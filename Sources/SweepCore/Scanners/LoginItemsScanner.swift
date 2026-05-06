import Foundation

/// Scans modern macOS login items registered via SMAppService / Background Task
/// Management (Ventura 13+).
///
/// These don't appear under `launchctl list` and aren't covered by the legacy
/// LaunchAgent/LaunchDaemon scanners. They include:
///
///   - "Login Items" surfaced in System Settings > General > Login Items
///   - "Allow in the Background" services registered by apps via SMAppService
///   - Helper bundles inside `Contents/Library/LoginItems/` of installed apps
///
/// macOS persists this state in the BackgroundTaskManagement DB
/// (`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm`),
/// which is the primary persistence surface attackers target after Apple
/// deprecated unsigned LaunchAgents in Ventura.
public final class LoginItemsScanner: Scanner {
    public let name = "Login Items Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("dumping BackgroundTaskManagement state")
        scanBTMState(findings: &findings, errors: &errors)

        progress?.update("scanning app-bundle login-item helpers")
        scanBundleLoginItems(findings: &findings, errors: &errors)

        progress?.update("checking ~/Library/Application Scripts for orphans")
        scanApplicationScripts(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - sfltool / BTM dump

    /// Reads the user's Background Task Management state via `sfltool dumpBTM`.
    /// On Ventura+ this lists every SMAppService-registered helper, login item,
    /// and "allow in background" entry — including those registered by apps that
    /// no longer exist on disk (a classic stale-malware indicator).
    private func scanBTMState(findings: inout [Finding], errors: inout [String]) {
        // sfltool requires the user's session — running as root via sudo can fail to
        // reach the user's BTM state, so we try both flavours and merge.
        var dumps: [String] = []

        let asUser = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpBTM"], timeout: 10)
        if asUser.success && !asUser.stdout.isEmpty { dumps.append(asUser.stdout) }

        // Some platforms emit the dump on stderr; try both
        if !asUser.stderr.isEmpty && asUser.stderr.contains("Type:") { dumps.append(asUser.stderr) }

        guard let dump = dumps.first else {
            // sfltool didn't run — record but don't crash. This is normal pre-Ventura.
            return
        }

        analyzeBTMDump(dump, findings: &findings)
    }

    private func analyzeBTMDump(_ dump: String, findings: inout [Finding]) {
        // sfltool dumpBTM outputs blocks like:
        //
        //   UUID: <uuid>
        //   Name: <human name>
        //   Developer Name: <signer>
        //   Type: legacy (...) | login item (...)
        //   Disposition: [enabled/disabled, allowed/disallowed, hidden/visible, notified]
        //   URL: file:///Library/LaunchAgents/com.example.helper.plist
        //   Bundle ID: com.example.helper
        //   Generation: 0
        //
        // Blocks are separated by blank lines. We parse each block into a dict.

        let blocks = dump.components(separatedBy: "\n\n")
        for block in blocks {
            var entry: [String: String] = [:]
            for line in block.split(separator: "\n") {
                let parts = line.split(separator: ":", maxSplits: 1).map { String($0).trimmingCharacters(in: .whitespaces) }
                if parts.count == 2 { entry[parts[0]] = parts[1] }
            }

            guard !entry.isEmpty else { continue }
            let name = entry["Name"] ?? entry["Bundle ID"] ?? "(unknown)"
            let bundleID = entry["Bundle ID"] ?? ""
            let developer = entry["Developer Name"] ?? ""
            let url = entry["URL"] ?? entry["Executable Path"] ?? ""
            let typeStr = entry["Type"] ?? ""
            let dispositionRaw = entry["Disposition"] ?? ""
            let dispositionLC = dispositionRaw.lowercased()
            let isEnabled = dispositionLC.contains("enabled")
            let isAllowed = dispositionLC.contains("allowed")
            let isHidden = dispositionLC.contains("hidden")

            // Strip the file:// prefix for nicer paths.
            let cleanPath: String? = {
                guard !url.isEmpty else { return nil }
                if let parsed = URL(string: url), parsed.isFileURL { return parsed.path }
                if url.hasPrefix("file://") { return String(url.dropFirst(7)) }
                return url
            }()

            // 1. Known spyware match — by name, bundle ID, or label.
            if let sig = SpywareSignature.match(processName: name)
                ?? SpywareSignature.match(bundleId: bundleID)
                ?? SpywareSignature.match(label: bundleID) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Known spyware registered as login item: \(sig.name)",
                    detail: "Name: \(name), Bundle: \(bundleID), Type: \(typeStr)",
                    path: cleanPath,
                    remediation: "Disable in System Settings > General > Login Items, then remove the app: \(sig.name)"
                ))
                continue
            }

            // 2. Fake Apple / vendor impersonation
            if !bundleID.isEmpty && SpywareSignature.isFakeAppleBundleId(bundleID) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Fake Apple bundle ID registered as login item",
                    detail: "Bundle: \(bundleID), Name: \(name) — disposition: \(dispositionRaw)",
                    path: cleanPath,
                    remediation: "Disable: System Settings > General > Login Items, then investigate the source app"
                ))
                continue
            }
            if !bundleID.isEmpty && SpywareSignature.isFakeVendorBundleId(bundleID) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Vendor-impersonation login item",
                    detail: "Bundle: \(bundleID), Name: \(name) — mimics a legitimate vendor",
                    path: cleanPath,
                    remediation: "Disable in Login Items; if you didn't install \(name) from the genuine vendor, remove it"
                ))
                continue
            }

            // 3. Login item from a temp / hidden / non-standard location
            if let path = cleanPath {
                let isHiddenPath = path.contains("/.") || path.split(separator: "/").contains(where: { $0.hasPrefix(".") })
                let isTempPath = path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") || path.hasPrefix("/var/tmp/")

                if isTempPath {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Login item registered from a temp directory",
                        detail: "Name: \(name), Path: \(path)",
                        path: path,
                        remediation: "Remove via Login Items; legitimate apps don't run from /tmp"
                    ))
                    continue
                }
                if isHiddenPath {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Login item points at a hidden path",
                        detail: "Name: \(name), Path: \(path)",
                        path: path,
                        remediation: "Investigate the path before removing — hidden persistence is a strong spyware indicator"
                    ))
                    continue
                }

                // 4. Pointer to a non-existent app — stale malware leftover.
                if !FileManager.default.fileExists(atPath: path) {
                    findings.append(Finding(
                        severity: .medium, category: .persistence,
                        title: "Login item references missing target",
                        detail: "Name: \(name), Path: \(path) — app no longer on disk but BTM still tracks it",
                        path: path,
                        remediation: "Disable in Login Items; if you didn't expect \(name), this is leftover malware state"
                    ))
                    continue
                }
            }

            // 5. "Hidden" + "enabled" + non-Apple developer is the AMOS / Banshee signature
            if isEnabled && isAllowed && isHidden &&
               !developer.lowercased().contains("apple") &&
               !bundleID.hasPrefix("com.apple.") {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Hidden-but-enabled login item",
                    detail: "Name: \(name), Developer: \(developer.isEmpty ? "(none)" : developer), Bundle: \(bundleID)",
                    path: cleanPath,
                    remediation: "Verify in System Settings > General > Login Items — hidden helpers should belong to apps you recognise"
                ))
                continue
            }

            // 6. Unsigned developer — sfltool reports an empty Developer Name when the helper
            // is ad-hoc / unsigned. Many real apps (open-source, dev builds) hit this, so it's
            // only LOW unless other signals fire.
            if isEnabled && (developer.isEmpty || developer == "Unknown") &&
               !bundleID.hasPrefix("com.apple.") {
                findings.append(Finding(
                    severity: .low, category: .persistence,
                    title: "Unsigned login item",
                    detail: "Name: \(name), Bundle: \(bundleID.isEmpty ? "(none)" : bundleID), Path: \(cleanPath ?? "(unknown)")",
                    path: cleanPath,
                    remediation: "Verify the source — unsigned helpers shouldn't normally appear in Login Items"
                ))
            }
        }
    }

    // MARK: - Bundle login-item helpers

    /// Apps can ship an embedded helper at
    /// `MyApp.app/Contents/Library/LoginItems/MyHelper.app`
    /// which they then register via SMAppService. Spyware mimicking a real app
    /// will plant a helper here so the parent app's signature gives it cover —
    /// we sanity-check the helpers against their parent's signing team.
    private func scanBundleLoginItems(findings: inout [Finding], errors: inout [String]) {
        let appDirs = ["/Applications", "\(ShellRunner.realUserHome)/Applications"]
        let fm = FileManager.default

        for dir in appDirs {
            guard fm.fileExists(atPath: dir),
                  let apps = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for app in apps where app.hasSuffix(".app") {
                let appPath = "\(dir)/\(app)"
                let helpersDir = "\(appPath)/Contents/Library/LoginItems"
                guard fm.fileExists(atPath: helpersDir),
                      let helpers = try? fm.contentsOfDirectory(atPath: helpersDir) else { continue }

                for helper in helpers where helper.hasSuffix(".app") {
                    let helperPath = "\(helpersDir)/\(helper)"
                    let helperPlist = "\(helperPath)/Contents/Info.plist"
                    guard let data = fm.contents(atPath: helperPlist),
                          let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { continue }

                    let helperBundleID = plist["CFBundleIdentifier"] as? String ?? ""
                    let helperName = plist["CFBundleName"] as? String ?? helper

                    // Known spyware
                    if let sig = SpywareSignature.match(bundleId: helperBundleID) {
                        findings.append(Finding(
                            severity: .high, category: .persistence,
                            title: "Spyware shipped as a bundled login-item helper: \(sig.name)",
                            detail: "Helper: \(helperName), Bundle: \(helperBundleID), Parent app: \(app)",
                            path: helperPath,
                            remediation: "Remove the parent app: rm -rf \"\(appPath)\""
                        ))
                        continue
                    }

                    // Vendor / Apple impersonation in a third-party bundle
                    if SpywareSignature.isFakeAppleBundleId(helperBundleID) ||
                       SpywareSignature.isFakeVendorBundleId(helperBundleID) {
                        findings.append(Finding(
                            severity: .high, category: .persistence,
                            title: "Bundled login-item helper uses an impersonating bundle ID",
                            detail: "Helper: \(helperName), Bundle: \(helperBundleID), Parent app: \(app)",
                            path: helperPath,
                            remediation: "Investigate \(app) — its login-item helper is mimicking another vendor"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Application Scripts

    /// `~/Library/Application Scripts/<bundle-id>/` is where apps can drop AppleScript /
    /// shell-script payloads that get run by their own helpers. XCSSET famously dropped
    /// scripts under `com.apple.systempreferences` here; modern stealers have followed
    /// suit. We flag unknown scripts and any whose parent bundle ID is fake-Apple.
    private func scanApplicationScripts(findings: inout [Finding], errors: inout [String]) {
        let dir = "\(ShellRunner.realUserHome)/Library/Application Scripts"
        let fm = FileManager.default
        guard fm.fileExists(atPath: dir),
              let entries = try? fm.contentsOfDirectory(atPath: dir) else { return }

        for entry in entries {
            // Each subdirectory is a bundle ID
            if SpywareSignature.isFakeAppleBundleId(entry) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Application Scripts directory under fake-Apple bundle ID",
                    detail: "Directory: \(entry) — only the matching app should populate this folder",
                    path: "\(dir)/\(entry)",
                    remediation: "Remove if you don't recognise the parent app: rm -rf \"\(dir)/\(entry)\""
                ))
                continue
            }
            if SpywareSignature.isFakeVendorBundleId(entry) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Application Scripts directory under vendor-impersonation bundle ID",
                    detail: "Directory: \(entry)",
                    path: "\(dir)/\(entry)",
                    remediation: "Remove if you don't recognise the parent app: rm -rf \"\(dir)/\(entry)\""
                ))
            }
        }
    }
}
