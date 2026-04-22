import Foundation

/// Detects developer-environment supply-chain attacks.
///
/// Over 2023-2025 a wave of macOS campaigns has moved away from classic malware installers
/// and toward developer tooling — malicious npm packages with postinstall scripts, poisoned
/// pip index URLs, weaponized git hooks, and DPRK "Contagious Interview" payloads delivered
/// via fake coding tests. These IOCs aren't caught by process/persistence scans because they
/// live inside an engineer's package manager config, not as LaunchAgents.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking npm configuration")
        scanNpmConfig(findings: &findings, errors: &errors)

        progress?.update("checking globally installed npm packages")
        scanGlobalNpmPackages(findings: &findings, errors: &errors)

        progress?.update("checking pip configuration")
        scanPipConfig(findings: &findings, errors: &errors)

        progress?.update("checking git hooks configuration")
        scanGitHooksConfig(findings: &findings, errors: &errors)

        progress?.update("checking Homebrew taps")
        scanHomebrewTaps(findings: &findings, errors: &errors)

        progress?.update("checking SSH config for ProxyCommand")
        scanSSHConfig(findings: &findings, errors: &errors)

        progress?.update("checking for DPRK interview-dropped payloads")
        scanDPRKDropperPaths(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - npm

    /// Known typosquat / confused-deputy packages distributed via the Shai-Hulud-style
    /// npm supply-chain attacks (exfiltrated tokens, wallet theft) observed in 2024-2025.
    /// Lowercased. Exact-match against `npm list -g --depth=0` output.
    private let knownMaliciousNpmPackages: Set<String> = [
        // Crypto wallet drainers distributed via typosquats
        "ethers-wallet-sdk", "ethers-provider-sdk",
        "solana-web3-js-sdk", "web3-sdk-core",
        // DPRK "ContagiousInterview" npm droppers
        "node-rtsp-server-rtsp", "node-ts-logs", "log-mongodb",
        "auth0-logger", "node-eventlog", "swap-ethers",
        // Shai-Hulud-style token stealers (Sept 2025 wave)
        "rand-user-agent", "rand-ua-agent", "axios-file-upload",
        "crx-eval", "ethereum-cryptography-util",
    ]

    private func scanNpmConfig(findings: inout [Finding], errors: inout [String]) {
        // ~/.npmrc tokens, custom registries, or install-side-effect scripts
        let home = ShellRunner.realUserHome
        let npmrcPaths = ["\(home)/.npmrc", "/etc/npmrc"]

        for path in npmrcPaths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            let lines = content.split(separator: "\n")
            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix(";") || trimmed.hasPrefix("#") { continue }

                // registry = http://... over plain HTTP is a trivial MITM vector.
                if trimmed.lowercased().contains("registry=") &&
                   trimmed.lowercased().contains("http://") {
                    findings.append(Finding(
                        severity: .high, category: .supplyChain,
                        title: "npm configured with plain-HTTP registry",
                        detail: "Line in \(path): \(String(trimmed.prefix(120))) — registry responses can be replaced in transit",
                        path: path,
                        remediation: "Replace http:// with https:// in \(path), or remove the line to use the default registry"
                    ))
                }

                // Non-standard registry host
                if trimmed.lowercased().hasPrefix("registry=") &&
                   !trimmed.contains("registry.npmjs.org") &&
                   !trimmed.contains("registry.yarnpkg.com") &&
                   !trimmed.contains("registry.npmmirror.com") {
                    findings.append(Finding(
                        severity: .medium, category: .supplyChain,
                        title: "npm using non-standard registry",
                        detail: "Line in \(path): \(String(trimmed.prefix(120))) — confirm this is a trusted mirror or your company's internal registry",
                        path: path,
                        remediation: "Review \(path) and ensure the registry is expected"
                    ))
                }

                // Auth token present in world-readable .npmrc is a credential-leak risk.
                if trimmed.contains("_authToken=") || trimmed.contains("_auth=") {
                    if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                       let perm = attrs[.posixPermissions] as? NSNumber,
                       (perm.intValue & 0o044) != 0 {
                        findings.append(Finding(
                            severity: .high, category: .supplyChain,
                            title: "npm auth token in world-readable .npmrc",
                            detail: "\(path) contains an auth token but is readable by group/other (mode: \(String(perm.intValue, radix: 8)))",
                            path: path,
                            remediation: "Tighten permissions: chmod 600 \(path)"
                        ))
                    }
                }
            }
        }
    }

    private func scanGlobalNpmPackages(findings: inout [Finding], errors: inout [String]) {
        // Only run if npm is installed. `which` is in PATH for root+user.
        guard ShellRunner.which("npm") != nil else { return }

        let result = ShellRunner.run("/bin/sh", arguments: [
            "-c", "npm list -g --depth=0 --parseable 2>/dev/null"
        ], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        for rawLine in result.stdout.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }

            // Parseable output lists package paths; the package name is the last directory.
            let pkgName = URL(fileURLWithPath: line).lastPathComponent.lowercased()

            if knownMaliciousNpmPackages.contains(pkgName) {
                findings.append(Finding(
                    severity: .high, category: .supplyChain,
                    title: "Known malicious npm package installed globally: \(pkgName)",
                    detail: "Installed at \(line) — this package is on the public npm compromise lists",
                    path: line,
                    remediation: "Uninstall: npm uninstall -g \(pkgName) — then rotate any tokens exposed during install"
                ))
            }
        }
    }

    // MARK: - pip

    private func scanPipConfig(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let pipConfigs = [
            "\(home)/.pip/pip.conf",
            "\(home)/.config/pip/pip.conf",
            "/etc/pip.conf",
            "\(home)/Library/Application Support/pip/pip.conf",
        ]

        for path in pipConfigs {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            // index-url / extra-index-url pointing outside of pypi.org is how dependency confusion
            // attacks hijack internal package names with public, malicious replacements.
            for rawLine in content.split(separator: "\n") {
                let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
                let lower = trimmed.lowercased()
                guard lower.hasPrefix("index-url") || lower.hasPrefix("extra-index-url") else { continue }

                if lower.contains("http://") {
                    findings.append(Finding(
                        severity: .high, category: .supplyChain,
                        title: "pip configured with plain-HTTP index URL",
                        detail: "Line in \(path): \(String(trimmed.prefix(120))) — index responses can be replaced in transit",
                        path: path,
                        remediation: "Replace http:// with https:// in \(path)"
                    ))
                    continue
                }

                // Flag non-pypi.org indexes for review
                if !lower.contains("pypi.org") && !lower.contains("pypi.python.org") &&
                   !lower.contains("pythonhosted.org") {
                    findings.append(Finding(
                        severity: .medium, category: .supplyChain,
                        title: "pip using non-PyPI package index",
                        detail: "Line in \(path): \(String(trimmed.prefix(120))) — confirm this is your internal index, not a dependency-confusion trap",
                        path: path,
                        remediation: "Review \(path) — an attacker can hijack internal package names via a public mirror"
                    ))
                }
            }
        }
    }

    // MARK: - Git hooks

    private func scanGitHooksConfig(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let gitConfig = "\(home)/.gitconfig"
        guard let content = try? String(contentsOfFile: gitConfig, encoding: .utf8) else { return }

        // `git config --global core.hooksPath /path/that/runs/on/every/commit`
        // is a published supply-chain persistence primitive: the same directory is used by
        // every repo the user operates on, so any `git commit` triggers the attacker's payload.
        if let match = content.range(of: #"hooksPath\s*=\s*(\S+)"#, options: .regularExpression) {
            let setting = String(content[match])
            // Extract the path portion of the setting for context
            let pathPart = setting.split(separator: "=").last.map {
                String($0).trimmingCharacters(in: .whitespaces)
            } ?? "?"

            // core.hooksPath under /tmp, under a hidden dir, or outside user's home/projects is suspicious.
            let isSuspicious = pathPart.hasPrefix("/tmp") ||
                pathPart.hasPrefix("/var/tmp") ||
                pathPart.contains("/.") ||
                !pathPart.hasPrefix("/")  // relative — resolves per-cwd, dangerous

            findings.append(Finding(
                severity: isSuspicious ? .high : .medium,
                category: .supplyChain,
                title: isSuspicious
                    ? "Git core.hooksPath points to suspicious location"
                    : "Git core.hooksPath is overridden globally",
                detail: "Global core.hooksPath = \(pathPart) — every `git commit` in every repo runs scripts from this directory",
                path: gitConfig,
                remediation: isSuspicious
                    ? "Remove the override: git config --global --unset core.hooksPath — and inspect \(pathPart) for malicious scripts"
                    : "Verify this is your own hook directory, or remove with: git config --global --unset core.hooksPath"
            ))
        }

        // Also scan the current-user's ~/.config/git/hooks if it exists — a common choice
        // for honest users but also where malware plants payloads.
        let userHooksDir = "\(home)/.config/git/hooks"
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: userHooksDir) {
            for entry in entries where !entry.hasPrefix(".") {
                let hookPath = "\(userHooksDir)/\(entry)"
                guard let hookContent = try? String(contentsOfFile: hookPath, encoding: .utf8) else { continue }
                if hookHasRemoteExecution(hookContent) {
                    findings.append(Finding(
                        severity: .high, category: .supplyChain,
                        title: "Global git hook downloads and executes remote code",
                        detail: "Hook \(entry) in \(userHooksDir) contains curl|bash or similar — runs on every git command",
                        path: hookPath,
                        remediation: "Inspect \(hookPath) and remove if unexpected"
                    ))
                }
            }
        }
    }

    private func hookHasRemoteExecution(_ content: String) -> Bool {
        let lower = content.lowercased()
        // curl ... | sh / bash   or   wget ... | sh / bash
        let patterns = [
            "curl ",
            "wget ",
        ]
        for p in patterns where lower.contains(p) {
            if lower.contains("| sh") || lower.contains("| bash") ||
               lower.contains("|sh") || lower.contains("|bash") {
                return true
            }
        }
        // eval "$(curl ..." is the other classic form
        if lower.contains("eval ") && (lower.contains("curl") || lower.contains("wget")) {
            return true
        }
        return false
    }

    // MARK: - Homebrew

    private func scanHomebrewTaps(findings: inout [Finding], errors: inout [String]) {
        // `brew tap` points Homebrew at an additional GitHub repo as a formula source. A
        // compromised third-party tap can ship formulae that run arbitrary install scripts.
        // Only Apple-signed / well-known taps are safe by default.
        let knownSafeTapOwners: Set<String> = [
            "homebrew", "Homebrew",
            "hashicorp", "mongodb", "cloudflare", "github",
            "microsoft", "googlecloudplatform", "awslabs",
            "oven-sh", "python", "php",
        ]

        guard ShellRunner.which("brew") != nil else { return }

        let result = ShellRunner.run("/bin/sh", arguments: ["-c", "brew tap 2>/dev/null"], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        for rawLine in result.stdout.split(separator: "\n") {
            let tap = String(rawLine).trimmingCharacters(in: .whitespaces)
            guard !tap.isEmpty else { continue }

            // Taps are "owner/name". Owner is what we care about.
            let parts = tap.split(separator: "/")
            guard parts.count == 2 else { continue }
            let owner = String(parts[0])

            // homebrew/core and homebrew/cask are always present
            if owner.lowercased() == "homebrew" { continue }
            if knownSafeTapOwners.contains(owner) { continue }

            findings.append(Finding(
                severity: .low, category: .supplyChain,
                title: "Third-party Homebrew tap: \(tap)",
                detail: "Tap \(tap) is configured — formulae from this tap can run arbitrary install scripts as your user",
                path: nil,
                remediation: "Remove if unexpected: brew untap \(tap)"
            ))
        }
    }

    // MARK: - SSH

    private func scanSSHConfig(findings: inout [Finding], errors: inout [String]) {
        // `ProxyCommand curl | sh` or `Match exec ...` inside ~/.ssh/config is a published
        // persistence and exfiltration trick — every `ssh somehost` executes the shell pipeline.
        let home = ShellRunner.realUserHome
        let configPath = "\(home)/.ssh/config"
        guard let content = try? String(contentsOfFile: configPath, encoding: .utf8) else { return }

        for (idx, rawLine) in content.split(separator: "\n").enumerated() {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            let lower = line.lowercased()
            if lower.hasPrefix("#") || lower.isEmpty { continue }

            // ProxyCommand that pipes curl/wget output into a shell
            if lower.hasPrefix("proxycommand") {
                if lower.contains("curl") || lower.contains("wget") ||
                   lower.contains("bash") || lower.contains("/bin/sh") {
                    findings.append(Finding(
                        severity: .high, category: .supplyChain,
                        title: "Suspicious ProxyCommand in ~/.ssh/config",
                        detail: "Line \(idx + 1): \(String(line.prefix(160))) — ProxyCommand executes on every ssh invocation",
                        path: configPath,
                        remediation: "Inspect \(configPath) and remove if unexpected"
                    ))
                }
            }

            // `Match exec "curl ... | sh"` — rare in legitimate setups, abused by droppers.
            if lower.hasPrefix("match exec") &&
               (lower.contains("curl") || lower.contains("wget") || lower.contains("bash ")) {
                findings.append(Finding(
                    severity: .high, category: .supplyChain,
                    title: "Match exec directive in ~/.ssh/config downloads code",
                    detail: "Line \(idx + 1): \(String(line.prefix(160))) — runs on every ssh connection",
                    path: configPath,
                    remediation: "Inspect \(configPath) and remove if unexpected"
                ))
            }
        }
    }

    // MARK: - DPRK Contagious Interview droppers

    /// The DPRK "Contagious Interview" campaign (aka BeaverTail/InvisibleFerret/Ferret family)
    /// drops Python/Node payloads into a small set of fixed hidden paths after the victim runs
    /// a coding challenge from a fake recruiter. Flag these paths even without a matching
    /// process — the dropper may have exited after staging.
    private func scanDPRKDropperPaths(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let iocPaths: [String] = [
            "\(home)/.n2/pay",
            "\(home)/.n2/pay.zip",
            "\(home)/.npl/logs.txt",
            "\(home)/.npl/pay",
            "\(home)/.pyp/pay",
            "\(home)/.pyp/pay.zip",
            "\(home)/Library/Caches/com.apple.ferret",
            "/private/tmp/.frostyferret",
            "/private/tmp/.flexferret",
        ]

        let fm = FileManager.default
        for p in iocPaths where fm.fileExists(atPath: p) {
            findings.append(Finding(
                severity: .high, category: .supplyChain,
                title: "DPRK ContagiousInterview dropper artifact present",
                detail: "File \(p) matches an IOC for BeaverTail/InvisibleFerret/Ferret — you may have run a fake coding-challenge payload",
                path: p,
                remediation: "Disconnect from network, rotate all credentials (npm/pip/ssh/browser), and remove: rm -rf \"\(p)\""
            ))
        }
    }
}
