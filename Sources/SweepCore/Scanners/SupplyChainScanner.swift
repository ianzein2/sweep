import Foundation

/// Detects developer-targeted supply-chain threats: malicious npm/pnpm/yarn packages,
/// hijacked package.json scripts, and droppers that recent campaigns
/// (BeaverTail / ContagiousInterview, OtterCookie, FlexibleFerret) install on developers' Macs
/// via fake job-interview "coding challenges" or compromised packages.
///
/// This scanner is read-only and fast — it walks shallow user project directories and
/// looks at known stealer caches and recent npm install logs.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    // Known-bad npm package names from the DPRK BeaverTail / ContagiousInterview campaigns,
    // published research lists, and recent npm/pnpm advisories. Public, IOC-level data only.
    private let knownMaliciousPackages: Set<String> = [
        // BeaverTail / ContagiousInterview family
        "node-helper-utils",
        "node-system-tools",
        "node-process-helper",
        "node-ipc-helper",
        "node-cache-helper",
        "fccall",
        "fcc-call",
        "fcc-tools",
        "javascriptgo",
        "asw-test",
        // 2024-2025 typosquats observed on npm
        "noblox.js-proxy",
        "noblox.js-proxies",
        "noblox-proxy",
        "discord-selfbot-v14",
        "@solana/web3.js-proxy",
        "ethers-proxy",
        "web3-proxy",
        // ContagiousInterview "interview" droppers
        "iconv-string",
        "iconv-test",
        "icon-converter-test",
        // Known crypto-targeting backdoors from supply chain (2024-2025)
        "harthat-api",
        "harthat-hash",
        "@blockxlabs/ethers",
    ]

    // Filenames that BeaverTail / InvisibleFerret reliably drop to the user's home directory.
    // These are documented public IOCs.
    private let beavertailDropPaths: [String] = [
        "~/.n2/p.exe",
        "~/.n2/p",
        "~/.n2/pay",
        "~/.n2/payload",
        "~/.n2/.config",
        "~/.npl",
        "~/.n3",
        "~/.npmrc.bak",
    ]

    // Script substrings that are common in malicious npm "postinstall" hooks.
    // Any one alone is not damning — `curl ... | sh` may be legitimate. We require
    // a combination (network + shell or network + base64) before flagging.
    private struct PostInstallRedFlags {
        let network: Bool
        let pipeToShell: Bool
        let base64Decode: Bool
        let evalRemote: Bool
        let writesToHome: Bool
        let fingerprintsHost: Bool

        var score: Int {
            var s = 0
            if network { s += 1 }
            if pipeToShell { s += 2 }
            if base64Decode { s += 2 }
            if evalRemote { s += 3 }
            if writesToHome { s += 1 }
            if fingerprintsHost { s += 1 }
            return s
        }
    }

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking known stealer drop paths")
        scanKnownDropPaths(findings: &findings)

        progress?.update("scanning npm/pnpm/yarn caches")
        scanPackageManagerCaches(findings: &findings, errors: &errors)

        progress?.update("scanning recent project package.json files")
        scanProjectPackageJSON(findings: &findings, errors: &errors)

        progress?.update("checking Python pip install footprints")
        scanPipInstallHistory(findings: &findings, errors: &errors)

        progress?.update("checking Homebrew untrusted taps")
        scanHomebrewTaps(findings: &findings, errors: &errors)

        progress?.update("scanning developer shell history for risky installs")
        scanShellHistoryForCurlPipeSh(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Known stealer drop paths

    private func scanKnownDropPaths(findings: inout [Finding]) {
        let fm = FileManager.default
        for raw in beavertailDropPaths {
            let path = SpywareSignature.expandPath(raw)
            guard fm.fileExists(atPath: path) else { continue }
            let attrs = try? fm.attributesOfItem(atPath: path)
            let size = (attrs?[.size] as? Int) ?? 0
            findings.append(Finding(
                severity: .high, category: .suspiciousFile,
                title: "BeaverTail / InvisibleFerret drop file present",
                detail: "Path: \(path) (\(size) bytes) — published IOC for the DPRK \"Contagious Interview\" campaign",
                path: path,
                remediation: "Quarantine and delete: mv \"\(path)\" \"\(path).quarantine\" — then investigate which npm package or interview test created it"
            ))
        }
    }

    // MARK: - Package manager caches

    private func scanPackageManagerCaches(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let cacheRoots = [
            "\(home)/.npm/_cacache",
            "\(home)/.pnpm-store",
            "\(home)/Library/pnpm/store",
            "\(home)/.yarn/cache",
            "\(home)/.bun/install/cache",
        ]
        let fm = FileManager.default

        for root in cacheRoots {
            guard fm.fileExists(atPath: root) else { continue }
            // Walk only shallowly — package names appear in path components, no need to read every blob
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) else { continue }

            // Track findings per package to avoid noise (a single bad package = one finding)
            var reported = Set<String>()

            for case let url as URL in enumerator {
                if enumerator.level > 5 {
                    enumerator.skipDescendants()
                    continue
                }
                // The package name appears as a path component. We check every component
                // against our known-bad list — including scoped packages like @foo/bar.
                let components = url.pathComponents
                for pkg in knownMaliciousPackages {
                    if components.contains(pkg) && !reported.contains(pkg) {
                        reported.insert(pkg)
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "Known malicious package in cache: \(pkg)",
                            detail: "Package found under: \(url.path) — this matches a published IOC for DPRK or crypto-targeting npm campaigns",
                            path: url.path,
                            remediation: "Clear the cache and audit projects: npm cache clean --force; grep -R \"\(pkg)\" ~/projects"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Project package.json scanning

    private func scanProjectPackageJSON(findings: inout [Finding], errors: inout [String]) {
        // We don't want to walk every directory under $HOME — that's too slow. Instead, look at
        // the common code roots developers use, and only inspect package.json files that are
        // not buried in node_modules.
        let home = ShellRunner.realUserHome
        let codeRoots = [
            "\(home)/Documents",
            "\(home)/Projects",
            "\(home)/projects",
            "\(home)/Developer",
            "\(home)/dev",
            "\(home)/src",
            "\(home)/code",
            "\(home)/Code",
            "\(home)/Workspaces",
            "\(home)/Desktop",
            "\(home)/Downloads",
        ]

        let fm = FileManager.default
        var inspectedFiles = 0
        let maxFiles = 200  // bound the work so we don't pin a slow disk

        for root in codeRoots {
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) else { continue }

            // Components we never descend into — they contain other people's package.json files
            let skippedComponents: Set<String> = [
                "node_modules", ".git", ".next", "dist", "build",
                ".turbo", ".cache", ".pnpm", ".yarn", ".venv", "vendor",
            ]
            for case let url as URL in enumerator {
                if inspectedFiles >= maxFiles { break }
                let last = url.lastPathComponent
                if skippedComponents.contains(last) {
                    enumerator.skipDescendants()
                    continue
                }
                if enumerator.level > 4 {
                    enumerator.skipDescendants()
                    continue
                }
                guard last == "package.json" else { continue }
                inspectedFiles += 1
                inspectPackageJSON(at: url.path, findings: &findings)
            }
        }
    }

    private func inspectPackageJSON(at path: String, findings: inout [Finding]) {
        guard let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return }

        // 1. Check declared dependencies against known-bad packages.
        let depKeys = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
        for key in depKeys {
            guard let deps = json[key] as? [String: Any] else { continue }
            for pkgName in deps.keys {
                if knownMaliciousPackages.contains(pkgName) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Known malicious npm package referenced: \(pkgName)",
                        detail: "package.json at \(path) lists \(pkgName) in \(key) — published IOC",
                        path: path,
                        remediation: "Remove this dependency immediately: npm uninstall \(pkgName), then rotate any secrets the project touched"
                    ))
                }
            }
        }

        // 2. Inspect lifecycle scripts (postinstall, preinstall, install) for downloader / loader patterns.
        guard let scripts = json["scripts"] as? [String: Any] else { return }
        let riskyScriptNames = ["preinstall", "install", "postinstall", "prepare", "prepublish"]
        for scriptName in riskyScriptNames {
            guard let body = scripts[scriptName] as? String, !body.isEmpty else { continue }
            let flags = scoreInstallScript(body)
            // Score of 3+ combined indicators is a strong signal. Below that we treat as informational
            // — many legitimate packages run `node script.js` in postinstall.
            if flags.score >= 3 {
                let truncated = String(body.prefix(160))
                findings.append(Finding(
                    severity: flags.score >= 5 ? .high : .medium,
                    category: .suspiciousFile,
                    title: "Suspicious \(scriptName) script in package.json",
                    detail: "File: \(path) — \(scriptName): \(truncated)",
                    path: path,
                    remediation: "Inspect the script. Run installs with `npm install --ignore-scripts` for untrusted packages"
                ))
            }
        }
    }

    private func scoreInstallScript(_ body: String) -> PostInstallRedFlags {
        let lower = body.lowercased()
        let network = lower.contains("curl ") || lower.contains("curl http") ||
                      lower.contains("wget ") || lower.contains("fetch(") ||
                      lower.contains("https.get") || lower.contains("http.get") ||
                      lower.contains("axios")
        let pipeToShell = (lower.contains("| sh") || lower.contains("| bash") ||
                           lower.contains("|sh") || lower.contains("|bash") ||
                           lower.contains("| zsh"))
        let base64Decode = (lower.contains("base64") &&
                            (lower.contains("--decode") || lower.contains(" -d") || lower.contains("decode(")))
        let evalRemote = (lower.contains("eval") &&
                          (lower.contains("require(") || lower.contains("function(") || lower.contains("function (")))
        let writesToHome = lower.contains("~/.") || lower.contains("$home/.") ||
                           lower.contains("/users/") && lower.contains("/.")
        // Host fingerprinting commands used by BeaverTail to decide whether to deliver second stage
        let fingerprintsHost = lower.contains("os.platform") || lower.contains("os.hostname") ||
                               lower.contains("os.userinfo") || lower.contains("uname -")
        return PostInstallRedFlags(
            network: network,
            pipeToShell: pipeToShell,
            base64Decode: base64Decode,
            evalRemote: evalRemote,
            writesToHome: writesToHome,
            fingerprintsHost: fingerprintsHost
        )
    }

    // MARK: - pip install footprints

    private func scanPipInstallHistory(findings: inout [Finding], errors: inout [String]) {
        // pip leaves a pyproject.toml or requirements.txt; we don't have a great IOC list for
        // Python packages, but we can flag the dangerous pattern of `pip install` from a raw
        // GitHub URL or an unsigned tarball in the user's history.
        let home = ShellRunner.realUserHome
        let histories = [
            "\(home)/.python_history",
            "\(home)/.ipython/profile_default/history.sqlite",
        ]

        for path in histories {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let lines = content.split(separator: "\n")
            for line in lines {
                let lower = String(line).lowercased()
                guard lower.contains("pip install") || lower.contains("pip3 install") else { continue }
                let usesUrl = lower.contains("http://") || lower.contains("https://")
                let usesUnsignedTarball = lower.contains(".tar.gz") || lower.contains(".zip") ||
                                          lower.contains(".whl")
                let usesGitHub = lower.contains("github.com")
                let usesIndex = lower.contains("--index-url") || lower.contains("--extra-index-url")
                if (usesUrl && usesUnsignedTarball) || usesGitHub || usesIndex {
                    findings.append(Finding(
                        severity: .low, category: .suspiciousFile,
                        title: "Risky pip install pattern in shell history",
                        detail: "From \(path): \(String(line).prefix(160))",
                        path: path,
                        remediation: "If the package isn't from a trusted index, audit it. `pip install --index-url` and direct URL installs can ship arbitrary code via setup.py"
                    ))
                    break  // one finding per history file is enough
                }
            }
        }
    }

    // MARK: - Homebrew untrusted taps

    private func scanHomebrewTaps(findings: inout [Finding], errors: inout [String]) {
        // Homebrew "taps" outside of homebrew-core/homebrew-cask can publish any code as a
        // formula or cask. Random taps are a common pattern in social-engineered installs.
        let tapsRoots = [
            "/opt/homebrew/Library/Taps",
            "/usr/local/Homebrew/Library/Taps",
        ]
        let fm = FileManager.default
        let trustedOrgs: Set<String> = [
            "homebrew", "Homebrew",
        ]

        for root in tapsRoots {
            guard fm.fileExists(atPath: root),
                  let orgs = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for org in orgs where !org.hasPrefix(".") {
                if trustedOrgs.contains(org) { continue }
                let orgPath = "\(root)/\(org)"
                guard let taps = try? fm.contentsOfDirectory(atPath: orgPath) else { continue }
                for tap in taps where !tap.hasPrefix(".") {
                    findings.append(Finding(
                        severity: .low, category: .suspiciousFile,
                        title: "Third-party Homebrew tap: \(org)/\(tap.replacingOccurrences(of: "homebrew-", with: ""))",
                        detail: "Tap installed at \(orgPath)/\(tap) — third-party taps can ship any code; verify you trust the publisher",
                        path: "\(orgPath)/\(tap)",
                        remediation: "Audit installed formulas: brew list --full-name | grep \(org)/ — remove with: brew untap \(org)/\(tap.replacingOccurrences(of: "homebrew-", with: ""))"
                    ))
                }
            }
        }
    }

    // MARK: - Shell history risky install patterns

    private func scanShellHistoryForCurlPipeSh(findings: inout [Finding], errors: inout [String]) {
        // `curl example.com/install.sh | sh` and similar are how many real installers work
        // (rust-up, deno, bun, brew). They're also how stealers land. We flag instances that
        // *don't* point at a known-good host so the user can review.
        let home = ShellRunner.realUserHome
        let trustedHosts = [
            "sh.rustup.rs", "raw.githubusercontent.com/Homebrew",
            "deno.land", "bun.sh", "get.docker.com", "ohmyz.sh",
            "raw.githubusercontent.com/nvm-sh", "fnm.vercel.app",
            "starship.rs", "install.python-poetry.org", "pyenv.run",
            "raw.githubusercontent.com/asdf-vm",
        ]
        let historyFiles = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.fish_history",
        ]

        for hf in historyFiles {
            guard FileManager.default.fileExists(atPath: hf),
                  let content = try? String(contentsOfFile: hf, encoding: .utf8) else { continue }
            // Walk lines and look for "curl ... | sh/bash" pattern
            for line in content.split(separator: "\n") {
                let raw = String(line)
                let lower = raw.lowercased()
                // Quick exclusion: must mention curl/wget AND pipe to a shell
                guard (lower.contains("curl ") || lower.contains("wget ")) &&
                      (lower.contains("| sh") || lower.contains("| bash") || lower.contains("|sh") || lower.contains("|bash")) else {
                    continue
                }
                // Skip if the URL is a known-trusted installer host
                if trustedHosts.contains(where: { lower.contains($0) }) { continue }
                // Take only the part after "curl" or "wget" to keep the finding compact
                let snippet = String(raw.prefix(160))
                findings.append(Finding(
                    severity: .low, category: .suspiciousFile,
                    title: "Risky 'curl | sh' install in shell history",
                    detail: "From \(URL(fileURLWithPath: hf).lastPathComponent): \(snippet)",
                    path: hf,
                    remediation: "Audit the URL. Stealers commonly land via pasted one-liners from interview \"coding challenges\" or fake browser-update prompts."
                ))
                // One finding per history file is enough — multiple lines would be repetitive
                break
            }
        }
    }
}
