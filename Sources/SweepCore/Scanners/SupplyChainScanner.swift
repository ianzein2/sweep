import Foundation

/// Detects on-disk indicators of supply-chain compromise: malicious npm / pip packages
/// from active threat campaigns, and unexpected developer-tool artifacts. Designed to
/// surface threats that ride in through `npm install`, `pip install`, or `brew install`
/// rather than through the user's browser or downloads.
///
/// Coverage:
///  - DPRK "Contagious Interview" campaign npm package names (BeaverTail / InvisibleFerret
///    loaders observed Nov 2023 – 2025).
///  - DPRK PondRAT / VMConnect typosquatted PyPI packages.
///  - Loose stage-2 droppers commonly written to /tmp/.npl, /tmp/.n2, /Users/Shared.
///  - Recently modified `node_modules` postinstall scripts that fetch+execute remote code.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    /// npm packages associated with the DPRK "Contagious Interview" / BeaverTail campaign.
    /// These are typosquats published to the public npm registry as part of fake
    /// recruiter / coding-interview lures. Sources: Phylum, Unit 42, Mandiant 2024-2025.
    private let maliciousNpmPackages: Set<String> = [
        // BeaverTail loader family
        "beavertail", "react-icons-fake", "node-discord-extra",
        "node-helper-ws", "node-helpers-async", "node-fetch-async-helper",
        "discordjs-buttons", "react-modal-helper", "node-events-helpers",
        // 2024 typosquats targeting devs (Phylum, Sonatype)
        "etherscan-tools", "ether-balance", "ethereum-cryptography-fake",
        "solana-rpc-helper", "solana-tools-fake", "web3-tools-helper",
        "trufflehog-fake", "noobaa-core-fake", "nestjs-google-recaptcha",
        // Late-2024 "harmless-helper" series (Lazarus)
        "harmlesssolution", "redux-helpers-async", "react-router-async-helper",
        "core-pino-loader", "vite-meta-env", "vite-meta-test",
    ]

    /// PyPI packages associated with DPRK PondRAT / VMConnect / hacker-aware (2023-2025).
    private let maliciousPyPIPackages: Set<String> = [
        "pyperclips", "pyper-async", "pyrate-limiters",
        "ethermine-pool-checker", "py-numpy-helper",
        "tablediter", "request-plus", "requests-darwin-lite",
        "minimal-async", "real-ip-utils", "lib-pep-helper",
    ]

    /// Known IOC paths for stage-2 droppers used by the Contagious Interview campaign.
    private let droppedPayloadPaths: [String] = [
        "/private/tmp/.npl",
        "/private/tmp/.n2",
        "/private/tmp/.brick",
        "/private/tmp/.pyp",
        "/private/tmp/.py.bak",
        "/Users/Shared/Library/.ferret",
        "/Users/Shared/.pyp",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("scanning npm packages")
        scanNpmPackages(findings: &findings, errors: &errors)

        progress?.update("scanning pip packages")
        scanPipPackages(findings: &findings, errors: &errors)

        progress?.update("checking stage-2 dropper paths")
        scanDroppedPayloads(findings: &findings, errors: &errors)

        progress?.update("scanning postinstall hooks for remote-exec")
        scanPostinstallHooks(findings: &findings, errors: &errors)

        progress?.update("checking Homebrew taps")
        scanHomebrewTaps(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - npm

    private func scanNpmPackages(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Global node_modules and a few common project locations
        let roots = [
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
            "\(home)/.nvm/versions/node",
            "\(home)/.npm-global/lib/node_modules",
            "\(home)/node_modules",
        ]

        for root in roots {
            guard fm.fileExists(atPath: root) else { continue }

            // For nvm we have to descend into version dirs
            var moduleRoots = [root]
            if root.contains(".nvm/versions/node"),
               let versions = try? fm.contentsOfDirectory(atPath: root) {
                moduleRoots = versions.map { "\(root)/\($0)/lib/node_modules" }
                    .filter { fm.fileExists(atPath: $0) }
            }

            for modRoot in moduleRoots {
                guard let entries = try? fm.contentsOfDirectory(atPath: modRoot) else { continue }
                for entry in entries {
                    let lower = entry.lowercased()
                    if maliciousNpmPackages.contains(lower) {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "Malicious npm package installed: \(entry)",
                            detail: "Package \(entry) matches IOCs from the DPRK \"Contagious Interview\" / BeaverTail campaign",
                            path: "\(modRoot)/\(entry)",
                            remediation: "Uninstall: npm uninstall -g \(entry) — and audit the keychain / browser cookies, the loader exfiltrates both"
                        ))
                    }
                }
            }
        }

        // Also scan recently modified project node_modules in the user's working directories
        let workspaceRoots = ["\(home)/Documents", "\(home)/Desktop", "\(home)/Developer",
                              "\(home)/code", "\(home)/projects", "\(home)/src"]
        for ws in workspaceRoots {
            guard fm.fileExists(atPath: ws) else { continue }
            let result = ShellRunner.run("/usr/bin/find", arguments: [
                ws, "-maxdepth", "3", "-type", "d", "-name", "node_modules",
            ], timeout: 15)
            guard result.success else { continue }
            for nodeMods in result.stdout.split(separator: "\n").prefix(40) {
                let nmPath = String(nodeMods).trimmingCharacters(in: .whitespaces)
                guard let entries = try? fm.contentsOfDirectory(atPath: nmPath) else { continue }
                for entry in entries {
                    let lower = entry.lowercased()
                    if maliciousNpmPackages.contains(lower) {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "Malicious npm dependency in project: \(entry)",
                            detail: "Package \(entry) is a DPRK Contagious Interview IOC. Project: \(nmPath)",
                            path: "\(nmPath)/\(entry)",
                            remediation: "Delete node_modules and audit package.json. Rotate any credentials this project handled."
                        ))
                    }
                }
            }
        }
    }

    // MARK: - PyPI

    private func scanPipPackages(findings: inout [Finding], errors: inout [String]) {
        // Walk standard site-packages locations rather than calling `pip` (which is slow and
        // requires the right interpreter).
        let home = ShellRunner.realUserHome
        let fm = FileManager.default
        let pipRoots = [
            "/usr/local/lib/python3.11/site-packages",
            "/usr/local/lib/python3.12/site-packages",
            "/usr/local/lib/python3.13/site-packages",
            "/opt/homebrew/lib/python3.11/site-packages",
            "/opt/homebrew/lib/python3.12/site-packages",
            "/opt/homebrew/lib/python3.13/site-packages",
            "\(home)/Library/Python/3.11/lib/python/site-packages",
            "\(home)/Library/Python/3.12/lib/python/site-packages",
            "\(home)/Library/Python/3.13/lib/python/site-packages",
            "\(home)/.local/lib/python3.11/site-packages",
            "\(home)/.local/lib/python3.12/site-packages",
            "\(home)/.local/lib/python3.13/site-packages",
        ]

        for root in pipRoots {
            guard let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for entry in entries {
                let bareName = entry
                    .replacingOccurrences(of: ".dist-info", with: "")
                    .replacingOccurrences(of: ".egg-info", with: "")
                    .lowercased()
                // dist-info dirs encode the version as pkgname-1.2.3.dist-info
                let normalized = bareName.split(separator: "-").first.map(String.init) ?? bareName
                if maliciousPyPIPackages.contains(normalized) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Malicious PyPI package installed: \(normalized)",
                        detail: "\(normalized) matches DPRK PondRAT / VMConnect typosquat IOCs",
                        path: "\(root)/\(entry)",
                        remediation: "Uninstall: pip uninstall \(normalized) — then audit recent activity"
                    ))
                }
            }
        }
    }

    // MARK: - Dropped payloads

    private func scanDroppedPayloads(findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default
        for path in droppedPayloadPaths {
            guard fm.fileExists(atPath: path) else { continue }
            findings.append(Finding(
                severity: .high, category: .suspiciousFile,
                title: "Known stage-2 dropper path exists on disk",
                detail: "\(path) — IOC for DPRK Contagious Interview / BeaverTail / InvisibleFerret",
                path: path,
                remediation: "Quarantine and remove: sudo rm -rf \"\(path)\" — then audit recent npm/pip installs"
            ))
        }
    }

    // MARK: - postinstall hook abuse

    /// Many supply-chain compromises hide in package.json `postinstall` (or `preinstall`)
    /// scripts that fetch a remote loader the first time `npm install` runs. We scan a
    /// shallow window of project package.json files for the canonical patterns.
    private func scanPostinstallHooks(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let workspaceRoots = ["\(home)/Documents", "\(home)/Desktop", "\(home)/Developer",
                              "\(home)/code", "\(home)/projects", "\(home)/src"]
        let fm = FileManager.default

        // Find recently modified node_modules/<pkg>/package.json — supply-chain loaders are usually fresh
        for ws in workspaceRoots {
            guard fm.fileExists(atPath: ws) else { continue }
            let result = ShellRunner.run("/usr/bin/find", arguments: [
                ws, "-maxdepth", "5", "-name", "package.json",
                "-path", "*/node_modules/*", "-mtime", "-30",
            ], timeout: 20)
            guard result.success else { continue }

            for pkgLine in result.stdout.split(separator: "\n").prefix(200) {
                let pkgPath = String(pkgLine).trimmingCharacters(in: .whitespaces)
                guard let data = fm.contents(atPath: pkgPath),
                      let pkg = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
                guard let scripts = pkg["scripts"] as? [String: String] else { continue }

                let hookKeys = ["preinstall", "postinstall", "prepare", "install"]
                for hook in hookKeys {
                    guard let cmd = scripts[hook] else { continue }
                    let lower = cmd.lowercased()
                    let isRemoteFetch = (lower.contains("curl ") || lower.contains("wget ") ||
                                         lower.contains("axios") || lower.contains("https://"))
                    let isExec = lower.contains("eval") || lower.contains("exec(") ||
                                 lower.contains("| sh") || lower.contains("| bash") ||
                                 lower.contains("child_process") || lower.contains("spawn")
                    let isBase64 = lower.contains("base64") || lower.contains("atob(")

                    if (isRemoteFetch && isExec) || isBase64 {
                        let pkgName = (pkg["name"] as? String) ?? "unknown"
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "npm package \(hook) hook fetches and executes remote code",
                            detail: "Package: \(pkgName), Hook: \(hook): \(String(cmd.prefix(120)))",
                            path: pkgPath,
                            remediation: "Audit this dependency. If suspicious: delete node_modules, rotate credentials, run `npm audit`."
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Homebrew taps

    /// Third-party Homebrew taps install formulae outside Apple's notarization. A malicious
    /// tap can ship anything. The default taps are homebrew-core, homebrew-cask, and
    /// homebrew-services. We surface anything else for user review.
    private func scanHomebrewTaps(findings: inout [Finding], errors: inout [String]) {
        let brewPaths = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        let brewPath = brewPaths.first(where: { FileManager.default.fileExists(atPath: $0) })
        guard let brew = brewPath else { return }

        let result = ShellRunner.run(brew, arguments: ["tap"], timeout: 10)
        guard result.success else { return }

        let defaultTaps: Set<String> = [
            "homebrew/core", "homebrew/cask", "homebrew/services",
            "homebrew/bundle", "homebrew/cask-fonts", "homebrew/cask-versions",
        ]
        let installedTaps = result.stdout.split(separator: "\n")
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        let thirdPartyTaps = installedTaps.filter { !defaultTaps.contains($0.lowercased()) }

        for tap in thirdPartyTaps {
            findings.append(Finding(
                severity: .low, category: .suspiciousFile,
                title: "Third-party Homebrew tap installed",
                detail: "Tap: \(tap) — formulae here are not reviewed by Homebrew core. Verify the source.",
                path: nil,
                remediation: "Inspect: brew tap-info \(tap). If unwanted: brew untap \(tap)"
            ))
        }
    }
}
