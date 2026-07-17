import Foundation

/// Detects developer-toolchain compromises: malicious npm postinstall scripts, tampered git
/// hooks, hijacked package registries, and ClickFix-style social-engineering payloads left in
/// shell history. These channels have become the dominant vector for 2024-2026 macOS
/// infostealers (NPM shrinkwrap poisoning, "install and run this" fake CAPTCHAs).
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("scanning global npm packages")
        scanGlobalNpmPackages(findings: &findings, errors: &errors)

        progress?.update("checking package manager configs")
        scanPackageManagerConfigs(findings: &findings, errors: &errors)

        progress?.update("scanning git hooks in known repos")
        scanGitHooks(findings: &findings, errors: &errors)

        progress?.update("scanning Homebrew tap integrity")
        scanHomebrewTaps(findings: &findings, errors: &errors)

        progress?.update("scanning shell history for ClickFix payloads")
        scanShellHistoryForClickFix(findings: &findings, errors: &errors)

        progress?.update("scanning for SUID/SGID binaries outside system paths")
        scanUnexpectedSUIDBinaries(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - npm global packages

    /// Directories where globally-installed npm packages live. postinstall / preinstall / prepare
    /// scripts in these packages run whenever the package is installed or the tree is rebuilt —
    /// a common landing zone for typo-squatted or later-compromised packages.
    private var npmGlobalPrefixes: [String] {
        let home = ShellRunner.realUserHome
        return [
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
            "\(home)/.npm-global/lib/node_modules",
            "\(home)/.nvm/versions/node",  // walked one level deeper
            "\(home)/.volta/tools/image/packages",
        ]
    }

    private let suspiciousScriptPatterns: [(needle: String, why: String)] = [
        ("curl ", "downloads content over HTTP(S)"),
        ("wget ", "downloads content over HTTP(S)"),
        ("| sh", "pipes downloaded content into shell"),
        ("|sh\n", "pipes downloaded content into shell"),
        ("| bash", "pipes downloaded content into shell"),
        ("|bash\n", "pipes downloaded content into shell"),
        ("eval(", "evaluates dynamic code"),
        ("child_process", "spawns external processes"),
        ("base64 -d", "decodes obfuscated payload"),
        ("base64 --decode", "decodes obfuscated payload"),
        (".onion", "connects to a Tor hidden service"),
        ("/tmp/", "writes to /tmp"),
        ("chmod +x", "makes a downloaded file executable"),
    ]

    private func scanGlobalNpmPackages(findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default

        var packageDirs: [String] = []
        for prefix in npmGlobalPrefixes {
            guard fm.fileExists(atPath: prefix) else { continue }
            if prefix.hasSuffix("/versions/node") {
                // Walk one level to reach node_modules under each installed Node version
                if let versions = try? fm.contentsOfDirectory(atPath: prefix) {
                    for version in versions {
                        let nested = "\(prefix)/\(version)/lib/node_modules"
                        if fm.fileExists(atPath: nested) { packageDirs.append(nested) }
                    }
                }
            } else {
                packageDirs.append(prefix)
            }
        }

        for root in packageDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for entry in entries where !entry.hasPrefix(".") {
                let entryPath = "\(root)/\(entry)"

                if entry.hasPrefix("@") {
                    // Scoped packages: one directory deeper (@scope/name)
                    if let inner = try? fm.contentsOfDirectory(atPath: entryPath) {
                        for name in inner where !name.hasPrefix(".") {
                            checkNpmPackage(at: "\(entryPath)/\(name)",
                                           displayName: "\(entry)/\(name)",
                                           findings: &findings)
                        }
                    }
                } else {
                    checkNpmPackage(at: entryPath, displayName: entry, findings: &findings)
                }
            }
        }
    }

    private func checkNpmPackage(at path: String, displayName: String, findings: inout [Finding]) {
        let packageJson = "\(path)/package.json"
        guard let data = FileManager.default.contents(atPath: packageJson),
              let pkg = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let scripts = pkg["scripts"] as? [String: String] else { return }

        // The lifecycle hooks that run on `npm install` — the danger zone.
        let dangerousHooks = ["preinstall", "install", "postinstall", "prepare", "prepublish"]

        for hook in dangerousHooks {
            guard let script = scripts[hook] else { continue }
            let matches = suspiciousScriptPatterns.filter { script.lowercased().contains($0.needle) }
            if matches.isEmpty { continue }

            let reasons = matches.map { $0.why }.joined(separator: "; ")
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "Malicious-looking npm \(hook) script: \(displayName)",
                detail: "Package's \(hook) hook \(reasons). Script: \(String(script.prefix(160)))",
                path: packageJson,
                remediation: "Inspect the package; if unfamiliar remove it: npm uninstall -g \(displayName)"
            ))
        }
    }

    // MARK: - Package manager configs (registry hijack)

    private func scanPackageManagerConfigs(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome

        // .npmrc — the registry= key controls where npm fetches packages. A malicious registry
        // that mirrors public packages but replaces select ones with typosquats/payloads is a
        // classic "shadow registry" attack.
        if let content = try? String(contentsOfFile: "\(home)/.npmrc", encoding: .utf8) {
            let lines = content.split(separator: "\n")
            for line in lines {
                let trimmed = String(line).trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("#") || trimmed.isEmpty { continue }
                if trimmed.lowercased().hasPrefix("registry=") ||
                   trimmed.lowercased().hasPrefix("registry =") {
                    let value = trimmed.split(separator: "=", maxSplits: 1).last
                        .map { String($0).trimmingCharacters(in: .whitespaces) } ?? ""
                    let officialHosts = ["registry.npmjs.org", "registry.yarnpkg.com",
                                         "npm.pkg.github.com", "registry.npmmirror.com",
                                         "npm.cloudsmith.io", "artifactory."]
                    let isOfficialish = officialHosts.contains(where: { value.contains($0) })
                    if !isOfficialish && !value.isEmpty {
                        findings.append(Finding(
                            severity: .high, category: .networkActivity,
                            title: "npm registry redirected to non-standard host",
                            detail: "~/.npmrc contains: \(String(trimmed.prefix(120)))",
                            path: "\(home)/.npmrc",
                            remediation: "Verify this registry — a hijacked registry can serve trojaned packages. Reset with: npm config delete registry"
                        ))
                    }
                }
            }
        }

        // pip.conf / .pypirc — analogous for Python.
        let pyConfigs = [
            "\(home)/Library/Application Support/pip/pip.conf",
            "\(home)/.pip/pip.conf",
            "\(home)/.config/pip/pip.conf",
        ]
        for cfg in pyConfigs {
            guard let content = try? String(contentsOfFile: cfg, encoding: .utf8) else { continue }
            for line in content.split(separator: "\n") {
                let trimmed = String(line).trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("#") { continue }
                let low = trimmed.lowercased()
                if low.hasPrefix("index-url") || low.hasPrefix("extra-index-url") {
                    let value = trimmed.split(separator: "=", maxSplits: 1).last
                        .map { String($0).trimmingCharacters(in: .whitespaces) } ?? ""
                    let official = ["pypi.org", "pythonhosted.org", "artifactory.",
                                    "pypi.python.org", "test.pypi.org"]
                    let isOfficialish = official.contains(where: { value.contains($0) })
                    if !isOfficialish && !value.isEmpty {
                        findings.append(Finding(
                            severity: .high, category: .networkActivity,
                            title: "pip index redirected to non-standard host",
                            detail: "\(cfg): \(String(trimmed.prefix(120)))",
                            path: cfg,
                            remediation: "Verify this Python index; malicious mirrors serve trojaned wheels"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Git hooks

    private func scanGitHooks(findings: inout [Finding], errors: inout [String]) {
        // Only inspect the user's global git hooks path and a few likely-cloned locations.
        // A full-disk walk is too expensive; we're looking for the common cases attackers use.
        let home = ShellRunner.realUserHome
        let candidateRoots = [
            "\(home)/Projects",
            "\(home)/Developer",
            "\(home)/Code",
            "\(home)/src",
            "\(home)/repos",
            "\(home)/GitHub",
            "\(home)/Documents/GitHub",
        ]

        // Global core.hooksPath (git config) is checked first.
        let globalHooks = ShellRunner.run("/usr/bin/git",
                                          arguments: ["config", "--global", "--get", "core.hooksPath"],
                                          timeout: 5)
        if globalHooks.success {
            let hookDir = globalHooks.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !hookDir.isEmpty {
                scanHooksIn(directory: expand(hookDir), origin: "global core.hooksPath",
                            findings: &findings)
            }
        }

        // Repo hooks — walk one level of each candidate root, look for .git/hooks
        let fm = FileManager.default
        for root in candidateRoots {
            guard let repos = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for repo in repos.prefix(50) where !repo.hasPrefix(".") {
                let hooksDir = "\(root)/\(repo)/.git/hooks"
                if fm.fileExists(atPath: hooksDir) {
                    scanHooksIn(directory: hooksDir, origin: "\(repo)/.git/hooks", findings: &findings)
                }
            }
        }
    }

    private func expand(_ path: String) -> String {
        if path.hasPrefix("~/") {
            return ShellRunner.realUserHome + String(path.dropFirst(1))
        }
        return path
    }

    private func scanHooksIn(directory: String, origin: String, findings: inout [Finding]) {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: directory) else { return }
        // Git's shipped .sample files are inert; ignore them.
        for file in files where !file.hasSuffix(".sample") && !file.hasPrefix(".") {
            let hookPath = "\(directory)/\(file)"
            var isDir: ObjCBool = false
            fm.fileExists(atPath: hookPath, isDirectory: &isDir)
            if isDir.boolValue { continue }
            guard let content = try? String(contentsOfFile: hookPath, encoding: .utf8) else { continue }

            let matches = suspiciousScriptPatterns.filter { content.lowercased().contains($0.needle) }
            // A hook that only prints/greps is fine. Two or more IOC hits = worth surfacing.
            if matches.count >= 2 {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Suspicious git hook: \(file)",
                    detail: "Location: \(origin); hook \(matches.map { $0.why }.joined(separator: "; ")). Runs on git actions.",
                    path: hookPath,
                    remediation: "Inspect: cat \"\(hookPath)\" — remove if not authored by you"
                ))
            }
        }
    }

    // MARK: - Homebrew tap integrity

    private func scanHomebrewTaps(findings: inout [Finding], errors: inout [String]) {
        // Non-core, non-cask-provider taps that have been pinned point to unofficial formula
        // sources. Some are safe (e.g., mongodb/brew), but attackers have been observed
        // publishing typosquat taps.
        let tapDirs = [
            "/opt/homebrew/Library/Taps",
            "/usr/local/Homebrew/Library/Taps",
        ]
        let fm = FileManager.default

        let officialOwners: Set<String> = [
            "homebrew", "linuxbrew",
        ]

        for tapDir in tapDirs {
            guard let orgs = try? fm.contentsOfDirectory(atPath: tapDir) else { continue }
            for org in orgs where !org.hasPrefix(".") {
                if officialOwners.contains(org.lowercased()) { continue }

                let orgPath = "\(tapDir)/\(org)"
                guard let taps = try? fm.contentsOfDirectory(atPath: orgPath) else { continue }
                for tap in taps where !tap.hasPrefix(".") {
                    // Widely used and reputable taps we don't flag.
                    let trusted: Set<String> = [
                        "homebrew-core", "homebrew-cask", "homebrew-services",
                        "homebrew-bundle",
                    ]
                    if trusted.contains(tap.lowercased()) { continue }

                    findings.append(Finding(
                        severity: .low, category: .suspiciousFile,
                        title: "Non-official Homebrew tap installed: \(org)/\(tap.replacingOccurrences(of: "homebrew-", with: ""))",
                        detail: "Formulae from this tap are outside the Homebrew audit process — a compromised tap can install trojaned software",
                        path: "\(orgPath)/\(tap)",
                        remediation: "Verify you trust the maintainer; otherwise: brew untap \(org)/\(tap.replacingOccurrences(of: "homebrew-", with: ""))"
                    ))
                }
            }
        }
    }

    // MARK: - ClickFix pattern in shell history

    private func scanShellHistoryForClickFix(findings: inout [Finding], errors: inout [String]) {
        // ClickFix / "paste this to fix your Mac" is the dominant 2024-2026 infection vector:
        // a fake-CAPTCHA or fake-update page uses JavaScript to place a shell command on the
        // clipboard and instructs the victim to paste it. The pasted command is captured in
        // the shell's history. We look for the canonical IOCs.
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
        ]

        let hardHits: [String] = [
            "curl -s http", "curl -sSL http", "curl -fsSL http",
            "wget -q http",
            "osascript -e",
        ]
        let payloadIndicators: [String] = [
            "| sh", "|sh", "| bash", "|bash",
            "base64 --decode | ", "eval \"$(",
        ]

        for path in historyFiles {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let lines = content.split(separator: "\n")
            for (idx, line) in lines.enumerated() {
                let raw = String(line)
                // zsh history entries look like ": 1712345678:0;curl -sSL http://... | sh"
                let cmd = raw.split(separator: ";", maxSplits: 1).last.map(String.init) ?? raw
                let low = cmd.lowercased()
                let hitsFetch = hardHits.contains(where: { low.contains($0) })
                let hitsPipe  = payloadIndicators.contains(where: { low.contains($0) })
                if hitsFetch && hitsPipe {
                    // Extra credit: known ClickFix domains show up here often — but we don't
                    // maintain that list here; the pattern alone is enough for a finding.
                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "Shell history contains ClickFix-style payload",
                        detail: "\(URL(fileURLWithPath: path).lastPathComponent) line \(idx + 1): \(String(cmd.prefix(160)))",
                        path: path,
                        remediation: "If you pasted this from a fake CAPTCHA / update page, treat your Mac as compromised. Rotate credentials, run a full sweep, and remove any downloaded payload from /tmp and /private/tmp."
                    ))
                }
            }
        }
    }

    // MARK: - Unexpected SUID / SGID binaries

    private func scanUnexpectedSUIDBinaries(findings: inout [Finding], errors: inout [String]) {
        // SUID / SGID binaries outside /usr, /bin, /sbin, /System are a classic
        // privilege-escalation staging technique — the attacker plants a small binary that
        // runs as root when invoked. We check the two spots users most commonly write to.
        let searchRoots = [
            "/tmp", "/private/tmp", "/var/tmp",
            "\(ShellRunner.realUserHome)/Downloads",
            "\(ShellRunner.realUserHome)/Library/Application Support",
        ]

        let fm = FileManager.default
        for root in searchRoots where fm.fileExists(atPath: root) {
            let result = ShellRunner.run("/usr/bin/find", arguments: [
                root,
                "-xdev",
                "-maxdepth", "4",
                "-type", "f",
                "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
                "-not", "-path", "*/com.apple.*",
            ], timeout: 15)

            guard result.success else { continue }
            let paths = result.stdout.split(separator: "\n").prefix(20)
            for path in paths {
                let p = String(path).trimmingCharacters(in: .whitespaces)
                guard !p.isEmpty else { continue }
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "SUID/SGID binary in unusual location",
                    detail: "File runs with elevated privileges when invoked — very rare outside /usr and /System",
                    path: p,
                    remediation: "Inspect ownership / signature; if not part of a package you installed, remove: sudo rm \"\(p)\""
                ))
            }
        }
    }
}
