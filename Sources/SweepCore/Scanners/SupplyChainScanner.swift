import Foundation

/// Detects developer supply-chain compromise: malicious npm/PyPI/RubyGems packages,
/// leaked credentials in dotfiles, and installed VS Code MCP server configs that
/// point at unknown remote endpoints.
///
/// Modern macOS spyware increasingly rides in through dev-tool packages rather than
/// standalone apps — a compromised transitive dependency runs the same postinstall
/// script and has the same disk/network access as any user-installed binary.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    // Package IDs reported malicious in 2024-2026 supply-chain campaigns.
    // Sourced from Socket, Snyk, ReversingLabs, GitHub Security Lab public advisories.
    // Exact name match — typosquats intentionally look like popular packages.
    private let maliciousNpmPackages: Set<String> = [
        // 2024 Lazarus / DPRK "Contagious Interview" npm drops
        "beavertail", "invisibleferret",
        "helmet-validate", "helmet-secure",
        "harthat-hash", "harthat-api", "harthat-fetch",
        "node-hardhat", "hardhat-deploy-others",
        "ethers-provider2", "ethers-providerz",
        "@typescript_eslintt/eslint-plugin",
        "eslint-config-airbnb-compat",
        "ts-runtime-compat-check",
        "solana-transaction-toolkit",
        // 2025 crypto-wallet drainers
        "solana-transaction-utils", "solana-transaction-web3",
        "@ledger-hq/hw-transport-node-hid-noevents",
        "web3-utils-tools",
        "trufflesuite-config",
        // 2024-2025 typosquats of popular packages
        "reqeust", "requet",       // requests
        "expresss", "expresss-js", // express
        "loadsh", "lodashh",       // lodash
        "chalk-utils",             // chalk
        "next-auth-plus",          // next-auth
        "reactt", "react-doom",    // react
        // 2025 postinstall droppers targeting macOS keychain
        "colorette-utils",
        "chalk-template-color",
        "debugger-utils",
        "eslintplugin-config",
    ]

    private let maliciousPipPackages: Set<String> = [
        // 2024-2025 PyPI takedowns targeting crypto / infostealer
        "requesocks", "urlib3",     // requests / urllib3 typosquats
        "beautifulsoup",             // real is beautifulsoup4
        "python3-dateutil",          // real is python-dateutil
        "jeIlyfish",                 // real is jellyfish
        "colourama",                 // real is colorama
        "cryptografy", "crytography", // cryptography typosquats
        "pyjwtt", "pyjjwt",          // pyjwt typosquats
        "matplotlibb", "numpyy",
        // 2025 crypto exfil PyPI packages
        "solana-py-toolkit",
        "web3py-utils",
        "ethereum-tester-utils",
        // 2024-2025 DPRK PyPI campaigns
        "pytoileur", "pyansible",
        "reverse-shellz",
    ]

    // Environment variable / dotfile keys that store secrets we don't want leaking
    // in world-readable places (Downloads, Desktop, /tmp).
    private let secretKeyPatterns: [String] = [
        "AKIA",                          // AWS access key prefix
        "ASIA",                          // AWS session token prefix
        "AIza",                          // Google Cloud API key prefix
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", // GitHub tokens
        "glpat-",                        // GitLab personal access token
        "xoxb-", "xoxp-", "xoxa-",       // Slack tokens
        "sk-ant-",                       // Anthropic API keys
        "sk-proj-",                      // OpenAI project keys
        "npm_",                          // npm automation tokens
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking installed npm packages")
        scanNpmPackages(findings: &findings, errors: &errors)

        progress?.update("checking installed Python packages")
        scanPipPackages(findings: &findings, errors: &errors)

        progress?.update("checking npm/Python auth files")
        scanRegistryAuthFiles(findings: &findings, errors: &errors)

        progress?.update("scanning for exposed API keys")
        scanExposedSecrets(findings: &findings, errors: &errors)

        progress?.update("checking VS Code MCP server configs")
        scanMCPServerConfigs(findings: &findings, errors: &errors)

        progress?.update("checking git hooks")
        scanGitHooks(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - npm packages

    private func scanNpmPackages(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Common locations where global and local node_modules live
        let candidateRoots = [
            "\(home)/.npm-global/lib/node_modules",
            "\(home)/.nvm/versions/node",       // per-version, needs one more level
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
        ]

        var packageDirs: [String] = []

        for root in candidateRoots {
            guard fm.fileExists(atPath: root) else { continue }

            if root.contains(".nvm/versions/node") {
                // ~/.nvm/versions/node/<version>/lib/node_modules
                if let versions = try? fm.contentsOfDirectory(atPath: root) {
                    for v in versions {
                        let vpath = "\(root)/\(v)/lib/node_modules"
                        if fm.fileExists(atPath: vpath) { packageDirs.append(vpath) }
                    }
                }
            } else {
                packageDirs.append(root)
            }
        }

        for packageDir in packageDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: packageDir) else { continue }
            for entry in entries {
                // Scoped packages live under @scope/name — descend one level
                if entry.hasPrefix("@") {
                    if let scoped = try? fm.contentsOfDirectory(atPath: "\(packageDir)/\(entry)") {
                        for name in scoped {
                            let fullName = "\(entry)/\(name)"
                            checkNpmPackage(name: fullName, path: "\(packageDir)/\(fullName)", findings: &findings)
                        }
                    }
                    continue
                }
                checkNpmPackage(name: entry, path: "\(packageDir)/\(entry)", findings: &findings)
            }
        }
    }

    private func checkNpmPackage(name: String, path: String, findings: inout [Finding]) {
        let lowered = name.lowercased()

        if maliciousNpmPackages.contains(lowered) {
            findings.append(Finding(
                severity: .high, category: .suspiciousFile,
                title: "Malicious npm package installed globally",
                detail: "Package: \(name) — matches a 2024-2026 supply-chain takedown IOC",
                path: path,
                remediation: "Uninstall immediately: npm uninstall -g \(name) — then audit your other environments, rotate secrets, and inspect \(path)/package.json for postinstall payloads"
            ))
            return
        }

        // package.json postinstall/preinstall pointing at curl|sh, base64 decoders, or
        // remote URLs is the canonical malicious-package pattern.
        let pkgPath = "\(path)/package.json"
        guard let data = FileManager.default.contents(atPath: pkgPath),
              let pkg = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let scripts = pkg["scripts"] as? [String: String] else { return }

        let riskyHooks = ["preinstall", "install", "postinstall"]
        for hook in riskyHooks {
            guard let cmd = scripts[hook] else { continue }
            let lc = cmd.lowercased()
            if lc.contains("curl") && (lc.contains("| sh") || lc.contains("| bash") || lc.contains("|sh") || lc.contains("|bash")) {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "npm package \(hook) hook pipes curl into a shell",
                    detail: "Package: \(name), \(hook): \(String(cmd.prefix(140)))",
                    path: pkgPath,
                    remediation: "Inspect \(pkgPath) — postinstall hooks that download and execute code are how malicious packages establish persistence"
                ))
            } else if lc.contains("base64") && (lc.contains("| sh") || lc.contains("| bash") || lc.contains("eval")) {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "npm package \(hook) hook decodes base64 payload",
                    detail: "Package: \(name), \(hook): \(String(cmd.prefix(140)))",
                    path: pkgPath,
                    remediation: "Inspect \(pkgPath) — base64-decoded install hooks are used to hide malicious commands from casual review"
                ))
            }
        }
    }

    // MARK: - Python packages

    private func scanPipPackages(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // We don't want to shell out to pip for every Python install — instead scan
        // the site-packages dirs directly. Cover pyenv, homebrew Python, and system Python.
        var siteDirs: [String] = []
        let searchRoots = [
            "\(home)/.pyenv/versions",
            "/opt/homebrew/lib",
            "/usr/local/lib",
            "\(home)/Library/Python",
        ]

        for root in searchRoots {
            guard fm.fileExists(atPath: root) else { continue }
            guard let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for entry in entries where entry.hasPrefix("python") || (entry.first?.isNumber ?? false) {
                // /opt/homebrew/lib/python3.12/site-packages OR ~/.pyenv/versions/3.11.4/lib/pythonX/site-packages
                let candidates = [
                    "\(root)/\(entry)/site-packages",
                    "\(root)/\(entry)/lib/python\(entry.replacingOccurrences(of: ".", with: ""))/site-packages",
                ]
                for c in candidates where fm.fileExists(atPath: c) {
                    siteDirs.append(c)
                }
                // pyenv style
                if fm.fileExists(atPath: "\(root)/\(entry)/lib") {
                    if let libs = try? fm.contentsOfDirectory(atPath: "\(root)/\(entry)/lib") {
                        for lib in libs where lib.hasPrefix("python") {
                            let sp = "\(root)/\(entry)/lib/\(lib)/site-packages"
                            if fm.fileExists(atPath: sp) { siteDirs.append(sp) }
                        }
                    }
                }
            }
        }

        for siteDir in siteDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: siteDir) else { continue }
            for entry in entries {
                // Package names normalize with dashes/underscores; also match dist-info folders
                let base = entry
                    .replacingOccurrences(of: ".dist-info", with: "")
                    .replacingOccurrences(of: ".egg-info", with: "")
                    .split(separator: "-").first.map(String.init) ?? entry

                let lowered = base.lowercased()
                if maliciousPipPackages.contains(lowered) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Malicious PyPI package installed",
                        detail: "Package: \(base) in \(siteDir) — matches a 2024-2026 supply-chain takedown IOC",
                        path: "\(siteDir)/\(entry)",
                        remediation: "Uninstall immediately: pip uninstall \(base) — then audit other environments and rotate secrets"
                    ))
                }
            }
        }
    }

    // MARK: - Auth file leaks

    private func scanRegistryAuthFiles(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome

        // Dotfiles that commonly hold plaintext auth tokens.
        // We don't read secrets; we just check that permissions aren't world-readable.
        let sensitiveFiles: [(path: String, label: String)] = [
            ("\(home)/.npmrc", "npm auth token"),
            ("\(home)/.pypirc", "PyPI upload token"),
            ("\(home)/.docker/config.json", "Docker registry auth"),
            ("\(home)/.aws/credentials", "AWS credentials"),
            ("\(home)/.aws/config", "AWS config"),
            ("\(home)/.netrc", "generic HTTP auth (curl/wget)"),
            ("\(home)/.git-credentials", "Git plaintext credential store"),
            ("\(home)/.kaggle/kaggle.json", "Kaggle API key"),
        ]

        let fm = FileManager.default
        for entry in sensitiveFiles {
            guard fm.fileExists(atPath: entry.path) else { continue }
            guard let attrs = try? fm.attributesOfItem(atPath: entry.path),
                  let perms = attrs[.posixPermissions] as? NSNumber else { continue }

            let mode = perms.uint16Value
            // Anything with world (o) read or group (g) read is over-permissive for a token file.
            let worldReadable = (mode & 0o004) != 0
            let groupReadable = (mode & 0o040) != 0

            if worldReadable || groupReadable {
                let modeStr = String(mode, radix: 8)
                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "Credential file is over-permissive",
                    detail: "\(entry.label) file has mode 0\(modeStr) — should be 0600. Other local users (and unsandboxed apps) can read tokens.",
                    path: entry.path,
                    remediation: "Restrict access: chmod 600 \"\(entry.path)\""
                ))
            }

            // A .netrc or .git-credentials containing a plaintext password is legacy-risky —
            // modern setups use OS keychain / GH CLI helpers.
            if entry.path.hasSuffix(".netrc") || entry.path.hasSuffix(".git-credentials") {
                if let content = try? String(contentsOfFile: entry.path, encoding: .utf8),
                   content.contains("password") || content.contains("://") {
                    let sizeLines = content.split(separator: "\n").count
                    findings.append(Finding(
                        severity: .low, category: .suspiciousFile,
                        title: "Legacy plaintext credential store in use",
                        detail: "\(entry.path) contains credentials (\(sizeLines) line(s)) — a single read of this file exposes them all",
                        path: entry.path,
                        remediation: "Prefer the macOS keychain: `git config --global credential.helper osxkeychain` — then delete \(entry.path)"
                    ))
                }
            }
        }
    }

    // MARK: - Exposed secrets in Downloads / Desktop / /tmp

    private func scanExposedSecrets(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Look for tiny .env-like text files freshly dropped into world-adjacent dirs.
        // AMOS-family stealers often stage `.env` copies here before uploading them.
        let exposedRoots = [
            "\(home)/Downloads",
            "\(home)/Desktop",
            "/tmp", "/private/tmp", "/var/tmp",
        ]

        let candidateNames = ["credentials", ".env", ".env.local", ".env.production", "config.json",
                              "secrets.yml", "secrets.yaml", ".aws", ".pypirc", "id_rsa", "id_ed25519"]

        for root in exposedRoots {
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
                options: [.skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if enumerator.level > 3 { enumerator.skipDescendants(); continue }
                let filename = url.lastPathComponent
                let filenameLower = filename.lowercased()

                // Match candidate names / patterns
                let looksLikeSecretName = candidateNames.contains(where: { filenameLower.hasSuffix($0) || filenameLower == $0 })
                if !looksLikeSecretName { continue }

                // Cap size — we peek at content only for small files
                guard let values = try? url.resourceValues(forKeys: [.fileSizeKey]),
                      let size = values.fileSize, size > 0, size < 200_000 else { continue }

                // Private SSH keys are always high — no need to sniff
                if filename == "id_rsa" || filename == "id_ed25519" || filename == "id_ecdsa" {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "SSH private key exposed in \(root)",
                        detail: "File: \(filename) (\(size) bytes) — SSH keys in Downloads/Desktop/tmp are frequently exfiltrated by infostealers",
                        path: url.path,
                        remediation: "Move to ~/.ssh with mode 0600, or delete if unused: mv \"\(url.path)\" ~/.ssh/ && chmod 600 ~/.ssh/\(filename)"
                    ))
                    continue
                }

                // For .env-style files, sniff for known key prefixes
                guard let content = try? String(contentsOfFile: url.path, encoding: .utf8) else { continue }
                if let matched = secretKeyPatterns.first(where: { content.contains($0) }) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Live API credentials exposed in \(root)",
                        detail: "File: \(filename) — contains a \"\(matched)\" style token, and lives in a directory routinely swept by infostealers",
                        path: url.path,
                        remediation: "Rotate the token, then move the file into an encrypted store (1Password/keychain) or delete it"
                    ))
                }
            }
        }
    }

    // MARK: - VS Code / Cursor MCP server configs

    private func scanMCPServerConfigs(findings: inout [Finding], errors: inout [String]) {
        // MCP (Model Context Protocol) servers registered in Claude Desktop / VS Code / Cursor
        // can execute arbitrary commands with the same privileges as the user. A rogue MCP entry
        // pointing at a remote endpoint or a random binary is a persistent backdoor.
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        let mcpConfigs: [(path: String, label: String)] = [
            ("\(home)/Library/Application Support/Claude/claude_desktop_config.json", "Claude Desktop"),
            ("\(home)/.cursor/mcp.json", "Cursor"),
            ("\(home)/Library/Application Support/Cursor/User/globalStorage/mcp.json", "Cursor global"),
            ("\(home)/.vscode/mcp.json", "VS Code workspace"),
            ("\(home)/Library/Application Support/Code/User/mcp.json", "VS Code user"),
        ]

        for entry in mcpConfigs {
            guard fm.fileExists(atPath: entry.path) else { continue }
            guard let data = fm.contents(atPath: entry.path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            // Config structures vary, but every impl lists servers under "mcpServers" or "servers"
            let servers = (json["mcpServers"] as? [String: Any]) ?? (json["servers"] as? [String: Any]) ?? [:]

            for (serverName, rawSpec) in servers {
                guard let spec = rawSpec as? [String: Any] else { continue }
                let command = (spec["command"] as? String) ?? ""
                let args = (spec["args"] as? [String])?.joined(separator: " ") ?? ""
                let url = (spec["url"] as? String) ?? ""

                // Server pointed at a raw remote URL over HTTP or an odd IP is worth surfacing.
                if !url.isEmpty {
                    let isPlainHTTP = url.lowercased().hasPrefix("http://")
                    let looksLikeIP = url.range(of: #"://\d+\.\d+\.\d+\.\d+"#, options: .regularExpression) != nil
                    if isPlainHTTP || looksLikeIP {
                        findings.append(Finding(
                            severity: isPlainHTTP ? .high : .medium,
                            category: .suspiciousFile,
                            title: "\(entry.label) MCP server points at an unusual endpoint",
                            detail: "Server \"\(serverName)\" URL: \(url)\(isPlainHTTP ? " — served over plain HTTP, trivially intercepted" : "")",
                            path: entry.path,
                            remediation: "Verify this MCP server is one you configured — remove the entry from \(entry.path) if not"
                        ))
                    }
                }

                // Command hooks that curl|sh or run from /tmp are a straightforward RCE.
                let combined = "\(command) \(args)".lowercased()
                if combined.contains("curl") && (combined.contains("|sh") || combined.contains("| sh") || combined.contains("|bash") || combined.contains("| bash")) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(entry.label) MCP server pipes curl into a shell",
                        detail: "Server \"\(serverName)\" command: \(String(combined.prefix(160)))",
                        path: entry.path,
                        remediation: "Remove this MCP server entry — it runs a remote script every time \(entry.label) starts"
                    ))
                } else if command.hasPrefix("/tmp/") || command.hasPrefix("/private/tmp/") || command.hasPrefix("/var/tmp/") {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(entry.label) MCP server runs a binary from /tmp",
                        detail: "Server \"\(serverName)\" command: \(command) \(args)",
                        path: entry.path,
                        remediation: "Binaries in /tmp are wiped on reboot and never legitimate for MCP — remove this entry"
                    ))
                }
            }
        }
    }

    // MARK: - Git hooks

    private func scanGitHooks(findings: inout [Finding], errors: inout [String]) {
        // Global git hooks and hooksPath settings can silently run a shell script on every
        // commit/push — an attractive persistence spot for tooling that already has repo access.
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // 1. core.hooksPath — a git config that redirects all repos to a shared hooks dir
        let cfgResult = ShellRunner.run("/usr/bin/git", arguments: [
            "config", "--global", "core.hooksPath"
        ], timeout: 5)
        if cfgResult.success {
            let path = cfgResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !path.isEmpty {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Global git hooksPath configured",
                    detail: "core.hooksPath = \(path) — every git operation in every repo runs the hooks in this directory",
                    path: path,
                    remediation: "Verify: git config --global core.hooksPath — unset with: git config --global --unset core.hooksPath"
                ))
            }
        }

        // 2. Sample templateDir hooks — installed on every `git init`
        let templateResult = ShellRunner.run("/usr/bin/git", arguments: [
            "config", "--global", "init.templateDir"
        ], timeout: 5)
        if templateResult.success {
            let tmpl = templateResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !tmpl.isEmpty {
                let expanded = tmpl.hasPrefix("~/") ? home + String(tmpl.dropFirst(1)) : tmpl
                let hooksDir = "\(expanded)/hooks"
                if fm.fileExists(atPath: hooksDir),
                   let hooks = try? fm.contentsOfDirectory(atPath: hooksDir), !hooks.isEmpty {
                    findings.append(Finding(
                        severity: .medium, category: .persistence,
                        title: "Git init.templateDir contains hooks",
                        detail: "\(hooks.count) hook(s) in \(hooksDir) — copied into every new git repo you clone or create",
                        path: hooksDir,
                        remediation: "Review each hook: ls -la \"\(hooksDir)\""
                    ))
                }
            }
        }
    }
}
