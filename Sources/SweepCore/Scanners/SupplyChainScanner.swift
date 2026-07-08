import Foundation

/// Detects known-malicious packages installed via developer package managers.
/// Focuses on the North Korean "Contagious Interview" / BeaverTail npm campaign (2023-2025),
/// which specifically targets macOS developers with typosquatted or lure npm packages that
/// download InvisibleFerret as a second-stage macOS persistence payload.
///
/// This scanner is intentionally narrow: it flags packages by *name*, not by full content
/// analysis. A name-match is not proof of compromise on its own, but the packages listed here
/// are documented in vendor IOCs (Palo Alto Unit 42, Socket, Datadog, Phylum, Snyk) and have
/// no legitimate reason to appear on a normal developer's machine.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    /// Names of npm packages publicly identified as North Korean Contagious Interview
    /// droppers or their known typosquats. Match is exact against the package.json `name`
    /// field (or the containing directory name inside node_modules).
    private let maliciousNpmPackages: Set<String> = [
        // Unit 42 (Palo Alto) — Contagious Interview campaign
        "ns-icon-set",
        "warbeast2000",
        "kodiak2k",
        "pretty-slice",
        "chalk-node",
        "node-request",
        "helmet-validate",
        // Phylum / Socket disclosures — BeaverTail dropper family
        "@ttk/react-native-styled-tocken",
        "ttk-react-native-styled-tocken",
        "airchat-nearby-widget",
        "dxb-payments",
        "pinkie-swear",  // typosquat of pinkie-promise
        "array-empty-validator",
        "array-empty-validators",
        "call-limit-tokenizer",
        "n2-nabla-token",
        "core-nabla-tokens",
        "next-form-step",
        // 2024-2025 additional wallet-stealer packages flagged by Socket
        "ethers-signer-utils",
        "solana-wallet-adaptor",
        "eth-provider-wallet",
        "@solana/web3.js-tokens",
        "web3-tokens-utils",
        // Wormhole/USDT drainers uploaded during 2024-2025
        "walletconnect-provider-utils",
        "wormhole-token-utils",
    ]

    /// PyPI packages tied to the same campaign or to macOS-targeted supply-chain attacks.
    private let maliciousPyPiPackages: Set<String> = [
        // Contagious Interview PyPI second-stage droppers (2024)
        "pyyaml-envtag",
        "pyyaml-tag",
        "yaml-envtag",
        "requests-darwin-lite",
        // Known crypto-drainer PyPI packages (2024-2025)
        "solana-py-utils",
        "eth-wallet-utils",
        "walletconnect-py",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("scanning globally installed npm packages")
        scanGlobalNpm(findings: &findings, errors: &errors)

        progress?.update("scanning ~/.npm cache")
        scanNpmCache(findings: &findings, errors: &errors)

        progress?.update("scanning common project locations")
        scanCommonProjectRoots(findings: &findings, errors: &errors)

        progress?.update("scanning globally installed Python packages")
        scanPyPi(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Global npm

    private func scanGlobalNpm(findings: inout [Finding], errors: inout [String]) {
        // Common global-install prefixes on macOS.
        let globalRoots = [
            "/opt/homebrew/lib/node_modules",
            "/usr/local/lib/node_modules",
            "\(ShellRunner.realUserHome)/.npm-global/lib/node_modules",
            "\(ShellRunner.realUserHome)/.nvm/versions/node",  // per-version, one level deeper
        ]

        for root in globalRoots {
            checkNodeModules(root: root, findings: &findings)
        }
    }

    // MARK: - npm cache (may retain a dropper even after the package is uninstalled)

    private func scanNpmCache(findings: inout [Finding], errors: inout [String]) {
        let cacheDir = "\(ShellRunner.realUserHome)/.npm/_cacache/content-v2"
        let fm = FileManager.default
        guard fm.fileExists(atPath: cacheDir) else { return }

        // The cache uses content-addressed storage — we can't inspect names cheaply. Instead
        // scan the index for tarballs whose filename references a known-bad package.
        let indexRoot = "\(ShellRunner.realUserHome)/.npm/_cacache/index-v5"
        guard fm.fileExists(atPath: indexRoot) else { return }

        let result = ShellRunner.run("/usr/bin/find", arguments: [
            indexRoot, "-type", "f", "-name", "*"
        ], timeout: 15)
        guard result.success else { return }

        for badPkg in maliciousNpmPackages {
            if result.stdout.contains("\"\(badPkg)\"") || result.stdout.contains("/\(badPkg)/") {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Malicious npm package in local cache: \(badPkg)",
                    detail: "\(badPkg) — flagged by public IOC feeds as a Contagious Interview / BeaverTail-family dropper",
                    path: cacheDir,
                    remediation: "Purge npm cache: npm cache clean --force"
                ))
            }
        }
    }

    // MARK: - Common project roots

    /// Walk a few well-known developer directories one level deep and check each project's
    /// package.json + top-level node_modules for a malicious dependency. We stop after 200
    /// candidate projects so this scan stays bounded even on large dev machines.
    private func scanCommonProjectRoots(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let projectRoots = [
            "\(home)/Projects", "\(home)/projects",
            "\(home)/Development", "\(home)/dev",
            "\(home)/Code", "\(home)/code",
            "\(home)/src", "\(home)/Sites",
            "\(home)/repos", "\(home)/Repositories",
            "\(home)/workspace", "\(home)/Documents/GitHub",
            "\(home)/Downloads",  // for coding-test drop-ins from social-engineering campaigns
        ]

        let fm = FileManager.default
        var checked = 0
        let maxChecked = 200

        for root in projectRoots {
            guard fm.fileExists(atPath: root),
                  let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for entry in entries {
                if checked >= maxChecked { break }
                let projectDir = "\(root)/\(entry)"
                checkNodeModules(root: "\(projectDir)/node_modules", findings: &findings)
                checkPackageJsonDeps(projectDir: projectDir, findings: &findings)
                checked += 1
            }
        }
    }

    /// Inspect a node_modules directory (top level + one @scope level) for known-bad packages.
    private func checkNodeModules(root: String, findings: inout [Finding]) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: root),
              let entries = try? fm.contentsOfDirectory(atPath: root) else { return }

        for entry in entries {
            if entry.hasPrefix("@") {
                // Scoped packages live one level deeper.
                let scopedDir = "\(root)/\(entry)"
                if let scoped = try? fm.contentsOfDirectory(atPath: scopedDir) {
                    for name in scoped {
                        let fullName = "\(entry)/\(name)"
                        if maliciousNpmPackages.contains(fullName) {
                            report(package: fullName, at: "\(scopedDir)/\(name)", findings: &findings)
                        }
                    }
                }
            } else if maliciousNpmPackages.contains(entry) {
                report(package: entry, at: "\(root)/\(entry)", findings: &findings)
            }
        }
    }

    /// Read a project's package.json dependency list. Catches malicious packages declared but
    /// not yet installed (e.g., a fresh clone of a booby-trapped coding-test repo).
    private func checkPackageJsonDeps(projectDir: String, findings: inout [Finding]) {
        let pkg = "\(projectDir)/package.json"
        guard let data = FileManager.default.contents(atPath: pkg),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        let dependencyKeys = ["dependencies", "devDependencies", "peerDependencies",
                              "optionalDependencies"]
        for key in dependencyKeys {
            guard let deps = json[key] as? [String: Any] else { continue }
            for depName in deps.keys where maliciousNpmPackages.contains(depName) {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "package.json declares malicious dependency: \(depName)",
                    detail: "Project \(projectDir) requires \(depName) in \(key). This is a documented Contagious Interview / npm-drainer IOC.",
                    path: pkg,
                    remediation: "Remove the dependency and delete node_modules + lockfile before running `npm install` again. If this repo came from a job-interview coding test, treat this Mac as compromised."
                ))
            }
        }
    }

    private func report(package: String, at path: String, findings: inout [Finding]) {
        findings.append(Finding(
            severity: .high, category: .suspiciousFile,
            title: "Installed malicious npm package: \(package)",
            detail: "\(package) is on public IOC lists (Palo Alto Unit 42 / Socket / Phylum) as a macOS-targeted supply-chain dropper — commonly the loader for BeaverTail → InvisibleFerret persistence.",
            path: path,
            remediation: "Remove: rm -rf \"\(path)\"; then investigate ~/.n2/, /tmp/, LaunchAgents, and rotate credentials this machine has touched."
        ))
    }

    // MARK: - PyPI

    private func scanPyPi(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Common site-packages roots on macOS
        let sitePackagesRoots = [
            "/opt/homebrew/lib/python3.11/site-packages",
            "/opt/homebrew/lib/python3.12/site-packages",
            "/opt/homebrew/lib/python3.13/site-packages",
            "/usr/local/lib/python3.11/site-packages",
            "/usr/local/lib/python3.12/site-packages",
            "\(home)/Library/Python/3.11/lib/python/site-packages",
            "\(home)/Library/Python/3.12/lib/python/site-packages",
            "\(home)/.pyenv/versions",
        ]

        let fm = FileManager.default
        for root in sitePackagesRoots {
            guard fm.fileExists(atPath: root),
                  let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for entry in entries {
                // A PyPI package installs both `foo` and `foo-<version>.dist-info` directories.
                // Normalize by stripping the -version suffix on dist-info dirs.
                var normalized = entry
                if entry.hasSuffix(".dist-info") {
                    let base = String(entry.dropLast(".dist-info".count))
                    // Drop the last `-` segment (the version).
                    let parts = base.split(separator: "-").map(String.init).dropLast()
                    normalized = parts.joined(separator: "-")
                }
                if maliciousPyPiPackages.contains(normalized) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Installed malicious PyPI package: \(normalized)",
                        detail: "\(normalized) is flagged by public IOC feeds as a Contagious Interview / macOS-targeted dropper.",
                        path: "\(root)/\(entry)",
                        remediation: "Uninstall: pip uninstall \(normalized) — and audit which project pulled it in."
                    ))
                }
            }
        }
    }
}
