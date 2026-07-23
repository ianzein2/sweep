import Foundation

/// Detects developer-machine compromise through the software supply chain:
/// compromised npm packages installed under a user's project directories,
/// artifacts of the Shai-Hulud npm worm (Sept/Nov 2025), and installed apps
/// signed by developer team IDs Apple has publicly revoked for malware abuse.
///
/// This scanner is bounded — it only walks a small set of common project roots
/// under `$HOME` (not the entire disk) and caps per-directory depth so a scan
/// of a Mac with dozens of Node projects still completes in a few seconds.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    /// Where we look for developer project directories. We deliberately do NOT
    /// walk the entire home directory — that would be prohibitively slow on
    /// developer machines and would balloon findings from harmless dev deps.
    private let projectRoots: [String] = [
        "Developer", "Projects", "Code", "src", "workspace",
        "Documents/GitHub", "Documents/Projects", "Documents/Code",
        "repos", "dev",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []
        let home = ShellRunner.realUserHome

        // 1. Compromised npm packages inside user project trees
        progress?.update("scanning node_modules for compromised packages")
        scanNpmPackages(home: home, findings: &findings, errors: &errors)

        // 2. Shai-Hulud worm markers
        progress?.update("scanning for Shai-Hulud worm markers")
        scanShaiHuludMarkers(home: home, findings: &findings, errors: &errors)

        // 3. Installed apps signed by revoked developer team IDs
        progress?.update("checking installed apps against revoked team IDs")
        scanRevokedTeamIds(findings: &findings, errors: &errors)

        // 4. Impersonation check for a small set of hand-picked apps
        progress?.update("checking impersonated app team IDs")
        scanImpersonatedApps(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Compromised npm packages

    private func scanNpmPackages(home: String, findings: inout [Finding], errors: inout [String]) {
        var scanned = 0
        let scanLimit = 500  // cap total node_modules dirs visited per scan

        // Names we care about (lowercased for cheap lookup)
        let watchNames = Set(SpywareSignature.compromisedNpmPackages.map { $0.name.lowercased() })

        for relRoot in projectRoots {
            let root = "\(home)/\(relRoot)"
            guard FileManager.default.fileExists(atPath: root) else { continue }

            guard let enumerator = FileManager.default.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if scanned >= scanLimit {
                    errors.append("Reached node_modules scan cap (\(scanLimit)); further trees skipped")
                    enumerator.skipDescendants()
                    break
                }
                // Depth cap — node_modules nesting can be quite deep, but the
                // interesting packages are always package.json files near the top.
                if enumerator.level > 6 {
                    enumerator.skipDescendants()
                    continue
                }
                let name = url.lastPathComponent
                if name == "node_modules" {
                    scanned += 1
                    inspectNodeModules(at: url.path, watchNames: watchNames, findings: &findings)
                    // Don't recurse into a node_modules again — deps of deps are
                    // already visible from the outer package.json check below.
                    enumerator.skipDescendants()
                }
            }
        }
    }

    private func inspectNodeModules(at path: String, watchNames: Set<String>, findings: inout [Finding]) {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: path) else { return }

        for entry in entries {
            if entry.hasPrefix(".") { continue }
            let entryPath = "\(path)/\(entry)"

            // @scope/name layout — recurse one level
            if entry.hasPrefix("@") {
                if let scoped = try? fm.contentsOfDirectory(atPath: entryPath) {
                    for scopedEntry in scoped {
                        checkPackage(at: "\(entryPath)/\(scopedEntry)",
                                     packageName: "\(entry)/\(scopedEntry)",
                                     watchNames: watchNames, findings: &findings)
                    }
                }
                continue
            }
            checkPackage(at: entryPath, packageName: entry,
                         watchNames: watchNames, findings: &findings)
        }
    }

    private func checkPackage(at path: String, packageName: String, watchNames: Set<String>, findings: inout [Finding]) {
        let lower = packageName.lowercased()
        // Fast reject on package name
        guard watchNames.contains(lower) else { return }

        // Read installed version from package.json
        let manifestPath = "\(path)/package.json"
        guard let data = FileManager.default.contents(atPath: manifestPath),
              let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        let installedVersion = (manifest["version"] as? String) ?? "unknown"

        for compromised in SpywareSignature.compromisedNpmPackages
            where compromised.name.lowercased() == lower {
            // If the entry has no specific bad versions, ANY installed copy is
            // suspect (the package itself is the campaign artifact — DPRK npm).
            if compromised.badVersions.isEmpty ||
               compromised.badVersions.contains(installedVersion) {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Compromised npm package installed: \(packageName)@\(installedVersion)",
                    detail: "\(compromised.campaign) — see: \(path)",
                    path: path,
                    remediation: "Remove: rm -rf \(path) — then audit your project's package-lock.json and rotate any credentials this project could reach"
                ))
            }
        }
    }

    // MARK: - Shai-Hulud worm

    private func scanShaiHuludMarkers(home: String, findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default
        var scanned = 0
        let cap = 400

        for relRoot in projectRoots {
            let root = "\(home)/\(relRoot)"
            guard fm.fileExists(atPath: root) else { continue }

            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if scanned >= cap {
                    enumerator.skipDescendants()
                    break
                }
                if enumerator.level > 6 {
                    enumerator.skipDescendants()
                    continue
                }
                scanned += 1
                let filename = url.lastPathComponent
                let relPath = url.path.replacingOccurrences(of: home, with: "~")

                for marker in SpywareSignature.shaiHuludMarkers {
                    // Path-shaped markers (containing "/") must match by full path suffix
                    // — otherwise a legitimate discussion.yaml or contents.json would false-fire.
                    let hit: Bool
                    if marker.contains("/") {
                        hit = url.path.hasSuffix("/" + marker)
                    } else {
                        // Bare-filename markers only fire near a package.json or repo root
                        // to keep false-positives low. We approximate this by requiring
                        // the immediate parent to contain a package.json.
                        let parent = url.deletingLastPathComponent().path
                        let hasManifest = FileManager.default.fileExists(atPath: "\(parent)/package.json")
                        hit = filename == marker && hasManifest
                    }
                    if hit {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "Shai-Hulud npm worm marker present",
                            detail: "File \(marker) found at \(relPath) — this file is dropped by the Shai-Hulud supply-chain worm",
                            path: url.path,
                            remediation: "Treat every project in this tree as potentially compromised. Rotate any npm, GitHub, and cloud tokens that this repo could see, and audit git remotes/workflows for attacker additions."
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Revoked / mismatched team IDs

    private func scanRevokedTeamIds(findings: inout [Finding], errors: inout [String]) {
        let appDirs = ["/Applications", "\(ShellRunner.realUserHome)/Applications"]
        for dir in appDirs {
            guard let apps = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for app in apps where app.hasSuffix(".app") {
                let appPath = "\(dir)/\(app)"
                guard let teamId = teamIdentifier(for: appPath) else { continue }
                if let reason = SpywareSignature.revokedMaliciousTeamIds[teamId] {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "App signed by a revoked malware team ID: \(app)",
                        detail: "TeamIdentifier: \(teamId) — \(reason)",
                        path: appPath,
                        remediation: "Uninstall this app: mv \"\(appPath)\" ~/.Trash — the developer certificate has been revoked for malware abuse"
                    ))
                }
            }
        }
    }

    private func scanImpersonatedApps(findings: inout [Finding], errors: inout [String]) {
        // For each hand-picked app, if its bundle ID is present on disk, verify
        // its team ID matches. A mismatch is high-confidence evidence of a trojan.
        let appDirs = ["/Applications", "\(ShellRunner.realUserHome)/Applications"]
        for dir in appDirs {
            guard let apps = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for app in apps where app.hasSuffix(".app") {
                let appPath = "\(dir)/\(app)"
                let infoPath = "\(appPath)/Contents/Info.plist"
                guard let data = FileManager.default.contents(atPath: infoPath),
                      let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                      let bundleId = plist["CFBundleIdentifier"] as? String,
                      let expected = SpywareSignature.legitimateVendorTeamIds[bundleId] else { continue }

                guard let actual = teamIdentifier(for: appPath) else { continue }
                if actual != expected.teamId {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Possible trojanized \(expected.appName): team ID mismatch",
                        detail: "\(bundleId) is signed by \(actual) — legitimate \(expected.appName) uses \(expected.teamId)",
                        path: appPath,
                        remediation: "Re-download \(expected.appName) from the vendor's official site and remove this copy: mv \"\(appPath)\" ~/.Trash"
                    ))
                }
            }
        }
    }

    /// Extract the Apple Developer TeamIdentifier from a signed bundle via `codesign`.
    /// Returns nil if the app is unsigned, ad-hoc-signed, or codesign errors out —
    /// we intentionally do not surface findings for those cases here (the Process
    /// scanner already flags unsigned binaries in unusual locations).
    private func teamIdentifier(for appPath: String) -> String? {
        let result = ShellRunner.run("/usr/bin/codesign",
                                     arguments: ["-dv", "--verbose=4", appPath],
                                     timeout: 5)
        // codesign writes machine-readable info to STDERR (yes, really).
        let combined = result.stdout + "\n" + result.stderr
        for line in combined.split(separator: "\n") {
            let s = String(line)
            if s.hasPrefix("TeamIdentifier=") {
                let value = String(s.dropFirst("TeamIdentifier=".count))
                    .trimmingCharacters(in: .whitespaces)
                if value.isEmpty || value == "not set" { return nil }
                return value
            }
        }
        return nil
    }
}
