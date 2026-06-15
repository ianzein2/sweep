import Foundation

/// Hunts for credential-grade material lying around in cleartext: SSH keys without a
/// passphrase, API tokens in dot-env files, crypto wallet seed phrases / private keys,
/// suspicious AI / MCP / Cursor configurations that pipe data to remote endpoints.
///
/// Rationale: the AMOS / Banshee / Poseidon stealer families that dominated 2024-2025 do
/// almost none of their work as kernel-level malware — they're ordinary user-space processes
/// that scoop up files in well-known locations and POST them out. The single biggest thing a
/// user can do to neutralise that class of threat is to NOT leave plaintext secrets on disk.
/// This scanner finds those files so the user can encrypt, vault, or delete them before the
/// next infostealer drops.
public final class SecretsScanner: Scanner {
    public let name = "Secrets & Credentials Exposure Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking SSH private keys")
        scanSSHPrivateKeys(findings: &findings, errors: &errors)

        progress?.update("scanning dotenv / cloud credentials")
        scanCloudCredentials(findings: &findings, errors: &errors)

        progress?.update("looking for exposed crypto seed phrases")
        scanCryptoSeedFiles(findings: &findings, errors: &errors)

        progress?.update("auditing AI / MCP configurations")
        scanAIConfigs(findings: &findings, errors: &errors)

        progress?.update("checking shell history for secrets")
        scanShellHistorySecrets(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - SSH private keys without passphrase

    private func scanSSHPrivateKeys(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let sshDir = "\(home)/.ssh"
        let fm = FileManager.default

        guard fm.fileExists(atPath: sshDir),
              let entries = try? fm.contentsOfDirectory(atPath: sshDir) else { return }

        for entry in entries {
            // Public keys, known_hosts, config — skip
            if entry.hasSuffix(".pub") || entry == "known_hosts" || entry == "config" ||
               entry == "authorized_keys" || entry == "authorized_keys2" ||
               entry == "environment" || entry == "rc" { continue }

            let path = "\(sshDir)/\(entry)"

            // Only inspect regular files
            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  (attrs[.type] as? FileAttributeType) == .typeRegular else { continue }

            // Cap read size — private keys are small (a few KB at most)
            guard let attrs2 = try? fm.attributesOfItem(atPath: path),
                  let size = attrs2[.size] as? Int, size < 20_000 else { continue }

            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            // Recognize the PEM/OpenSSH headers for each private-key flavour.
            let isPrivateKey =
                content.contains("-----BEGIN OPENSSH PRIVATE KEY-----") ||
                content.contains("-----BEGIN RSA PRIVATE KEY-----") ||
                content.contains("-----BEGIN EC PRIVATE KEY-----") ||
                content.contains("-----BEGIN DSA PRIVATE KEY-----") ||
                content.contains("-----BEGIN PRIVATE KEY-----") ||
                content.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            guard isPrivateKey else { continue }

            // Detect encryption:
            //  * Modern OpenSSH keys: "Proc-Type" line not present, but an unencrypted key has
            //    the literal "none" cipher right after the magic header in base64. The easiest
            //    OpenSSH heuristic that survives newlines: an unencrypted OpenSSH private key's
            //    base64 body starts with "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU" (the literal "openssh-key-v1\0\0\0\0\0\0\0\0none"
            //    encoded). We don't need to decode — just detect the marker.
            //  * Legacy PEM keys: "Proc-Type: 4,ENCRYPTED" or "ENCRYPTED" header means there's a passphrase.
            let isEncrypted = content.contains("Proc-Type: 4,ENCRYPTED") ||
                              content.contains("DEK-Info:") ||
                              content.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
                              isEncryptedOpenSSHKey(content)

            // File mode — owner-only is correct (0600). Anything broader is a separate issue.
            let permissions = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0o600
            let worldOrGroupReadable = (permissions & 0o077) != 0

            if !isEncrypted {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "SSH private key has no passphrase",
                    detail: "\(entry) — anyone who reads this file (or any process running as you) gains every SSH access this key has.",
                    path: path,
                    remediation: "Add a passphrase: ssh-keygen -p -f \"\(path)\""
                ))
            }
            if worldOrGroupReadable {
                let perm = String(format: "%o", permissions)
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "SSH private key has loose permissions (\(perm))",
                    detail: "\(entry) is readable beyond your user account — sshd will refuse the key in this state, but a stealer running as you will gladly read it.",
                    path: path,
                    remediation: "Tighten: chmod 600 \"\(path)\""
                ))
            }
        }
    }

    private func isEncryptedOpenSSHKey(_ content: String) -> Bool {
        // OpenSSH-format keys carry the cipher name inside the base64 blob. An unencrypted key
        // contains the byte sequence for "none" as the kdfname; an encrypted key uses bcrypt or
        // aes256-ctr. Decoding the full blob is overkill — we check for the well-known prefixes
        // of unencrypted vs encrypted keys in the first 200 bytes of the body.
        let body = content
            .replacingOccurrences(of: "-----BEGIN OPENSSH PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END OPENSSH PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .trimmingCharacters(in: .whitespaces)
        // Unencrypted keys start with this base64 prefix (header + cipher "none" + kdf "none")
        // Encrypted keys carry "aes256-ctr" or similar — the base64 of "aes" is "YWVz".
        if body.hasPrefix("b3BlbnNzaC1rZXktdjEAAAAABG5vbmU") { return false }
        // Heuristic: if base64 of "aes" or "bcrypt" appears in first ~80 chars, treat as encrypted.
        let head = String(body.prefix(80))
        return head.contains("YWVz") || head.contains("YmNyeXB0")
    }

    // MARK: - Cloud credentials / dotenv

    private struct CredentialPattern {
        let name: String
        let regex: NSRegularExpression
        let severity: Severity
    }

    private static let credentialPatterns: [CredentialPattern] = {
        let raw: [(String, String, Severity)] = [
            ("AWS access key", #"AKIA[0-9A-Z]{16}"#, .high),
            ("AWS secret key", #"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{30,}"#, .high),
            ("Google API key", #"AIza[0-9A-Za-z\-_]{35}"#, .high),
            ("Slack token", #"xox[abprs]-[A-Za-z0-9\-]{10,}"#, .high),
            ("GitHub PAT", #"gh[pousr]_[A-Za-z0-9]{30,}"#, .high),
            ("GitHub App token", #"ghs_[A-Za-z0-9]{30,}"#, .high),
            ("Stripe key", #"sk_live_[A-Za-z0-9]{20,}"#, .high),
            ("OpenAI key", #"sk-[A-Za-z0-9]{20,}"#, .high),
            ("Anthropic key", #"sk-ant-[A-Za-z0-9\-_]{30,}"#, .high),
            ("HuggingFace token", #"hf_[A-Za-z0-9]{30,}"#, .medium),
            ("Twilio SID", #"AC[a-f0-9]{32}"#, .medium),
            ("SendGrid key", #"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{30,}"#, .high),
            ("Generic password assignment", #"(?i)(password|passwd|pwd)\s*=\s*['"][^'"]{8,}['"]"#, .low),
        ]
        return raw.compactMap { (name, pattern, sev) -> CredentialPattern? in
            guard let r = try? NSRegularExpression(pattern: pattern) else { return nil }
            return CredentialPattern(name: name, regex: r, severity: sev)
        }
    }()

    private func scanCloudCredentials(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Specific well-known credential files first. We surface them whether or not the contents
        // are populated — they're high-value targets and the user should know they exist.
        let knownFiles: [(path: String, label: String, severity: Severity)] = [
            ("\(home)/.aws/credentials", "AWS shared credentials file", .high),
            ("\(home)/.aws/config", "AWS config (may contain SSO sessions)", .low),
            ("\(home)/.config/gcloud/credentials.db", "gcloud credentials DB", .high),
            ("\(home)/.config/gcloud/access_tokens.db", "gcloud access tokens", .high),
            ("\(home)/.azure/accessTokens.json", "Azure access tokens", .high),
            ("\(home)/.docker/config.json", "Docker registry credentials", .medium),
            ("\(home)/.netrc", ".netrc (HTTP credentials)", .medium),
            ("\(home)/.npmrc", "npm registry tokens", .medium),
            ("\(home)/.pypirc", "PyPI upload tokens", .medium),
            ("\(home)/.kube/config", "Kubernetes cluster credentials", .medium),
            ("\(home)/.git-credentials", "Git plaintext credentials", .high),
        ]
        for entry in knownFiles {
            guard fm.fileExists(atPath: entry.path) else { continue }
            // Check permissions — 0600 is OK, anything broader is a stealer-ready file.
            let attrs = try? fm.attributesOfItem(atPath: entry.path)
            let perms = (attrs?[.posixPermissions] as? NSNumber)?.uint16Value ?? 0o600
            let isLoose = (perms & 0o077) != 0
            let permStr = String(format: "%o", perms)

            findings.append(Finding(
                severity: isLoose ? .high : entry.severity,
                category: .suspiciousFile,
                title: isLoose
                    ? "\(entry.label) is world/group readable (\(permStr))"
                    : "\(entry.label) present (cleartext on disk)",
                detail: "Stealer families read this file by default — leaving it unencrypted gives them every cloud/registry credential it holds.",
                path: entry.path,
                remediation: isLoose
                    ? "Tighten: chmod 600 \"\(entry.path)\" — then consider migrating to a secret manager"
                    : "Move secrets into a vault (1Password CLI, AWS SSO, gcloud auth login --update-adc) instead of cleartext files"
            ))
        }

        // Generic dotenv files anywhere under the home directory (capped depth, capped size).
        // Cap the walk so this scanner doesn't dominate the run.
        let walkRoots = [
            home,
            "\(home)/Documents",
            "\(home)/Developer",
            "\(home)/code",
            "\(home)/projects",
        ]
        var visited = Set<String>()
        var dotenvHits = 0
        let maxHits = 25  // don't spam — the goal is to alert, not enumerate

        for root in walkRoots {
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if enumerator.level > 4 { enumerator.skipDescendants(); continue }
                // Skip large directories that won't contain .env files but slow us down
                let dirName = url.deletingLastPathComponent().lastPathComponent
                if ["node_modules", "DerivedData", ".build", "build", "Pods",
                    ".venv", "venv", ".tox", "vendor", ".cargo", ".gradle"].contains(dirName) {
                    enumerator.skipDescendants()
                    continue
                }

                let filename = url.lastPathComponent
                // Match .env, .env.local, .env.production, etc., plus credentials.{yaml,yml,json}
                let isDotenv = filename == ".env" || filename.hasPrefix(".env.") ||
                               filename == ".envrc" || filename == "credentials.json" ||
                               filename == "credentials.yaml" || filename == "secrets.json" ||
                               filename == "secrets.yaml" || filename == "secrets.yml"
                guard isDotenv else { continue }
                if visited.contains(url.path) { continue }
                visited.insert(url.path)

                // Skip if huge — real .env files are small.
                guard let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize,
                      size > 0, size < 200_000 else { continue }

                guard let content = try? String(contentsOf: url, encoding: .utf8) else { continue }

                // Look for any credential pattern. If none hit, only report when filename is
                // explicitly .env (cap the noise) — the .env.example world is full of placeholders.
                var matchedPatterns: [String] = []
                let nsContent = content as NSString
                let range = NSRange(location: 0, length: nsContent.length)
                for pattern in Self.credentialPatterns {
                    if pattern.regex.firstMatch(in: content, options: [], range: range) != nil {
                        matchedPatterns.append(pattern.name)
                    }
                }

                if !matchedPatterns.isEmpty {
                    dotenvHits += 1
                    if dotenvHits > maxHits { break }
                    let preview = matchedPatterns.prefix(3).joined(separator: ", ")
                    let more = matchedPatterns.count > 3 ? " (+\(matchedPatterns.count - 3) more)" : ""
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Cleartext secrets in \(filename)",
                        detail: "Detected: \(preview)\(more) — infostealers grep these patterns directly.",
                        path: url.path,
                        remediation: "Rotate the leaked credentials, then move them into a secrets manager (e.g. 1Password Connect, AWS SSO, doppler) instead of a flat file."
                    ))
                }
            }
        }
    }

    // MARK: - Crypto wallet seed / mnemonic files

    private func scanCryptoSeedFiles(findings: inout [Finding], errors: inout [String]) {
        // Look for files whose name implies a BIP-39 seed and whose content has 12/24-word patterns.
        let home = ShellRunner.realUserHome
        let candidates = [
            "\(home)/Documents", "\(home)/Desktop", "\(home)/Downloads",
            "\(home)/iCloud Drive", "\(home)/Library/Mobile Documents",
        ]
        let fm = FileManager.default

        // Tiny BIP-39 wordlist sample — looking for 12+ common mnemonic words on a single line.
        // We don't need the full 2048-word list; the false-positive rate stays low even with this.
        let bip39Hint: Set<String> = [
            "abandon", "ability", "able", "account", "achieve", "across", "act", "action",
            "actor", "actual", "adapt", "add", "address", "adjust", "admit", "adult",
            "advance", "advice", "afford", "afraid", "again", "age", "agent", "agree",
            "ahead", "aim", "air", "alarm", "album", "alert", "alien", "alone",
            "alpha", "already", "amazing", "among", "amount", "anchor", "ancient", "anger",
            "angle", "animal", "another", "answer", "ant", "apart", "apple", "approve",
            "area", "argue", "arm", "army", "around", "arrive", "arrow", "art",
            "artist", "ask", "assist", "atom", "attack", "audit", "author", "auto",
            "average", "avoid", "awake", "award", "aware", "away", "baby", "back",
            "bag", "balance", "ball", "bamboo", "banana", "banner", "bar", "basic",
            "basket", "battle", "beach", "bean", "bear", "become", "begin", "behind",
            "below", "between", "blue", "boat", "book", "born", "boy", "brave",
            "bread", "bring", "brother", "build", "bus", "business", "busy", "butter",
            "cake", "call", "camp", "candy", "car", "card", "care", "carry",
        ]

        for root in candidates {
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
                options: [.skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if enumerator.level > 3 { enumerator.skipDescendants(); continue }

                let filename = url.lastPathComponent.lowercased()
                let nameHints = ["seed", "mnemonic", "phrase", "recovery", "wallet", "keystore"]
                let nameMatches = nameHints.contains(where: { filename.contains($0) })

                // Only inspect smallish text-ish files
                guard let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize,
                      size > 0, size < 50_000 else { continue }

                let ext = url.pathExtension.lowercased()
                let textExts: Set<String> = ["txt", "md", "rtf", "json", "yaml", "yml", "log", ""]
                guard textExts.contains(ext) else { continue }

                guard let content = try? String(contentsOf: url, encoding: .utf8) else { continue }

                // Look for 12+ contiguous BIP-39-looking words on a single line
                var seedLikely = false
                for rawLine in content.split(separator: "\n") {
                    let line = String(rawLine).lowercased()
                    let words = line.split(whereSeparator: { !$0.isLetter }).map { String($0) }
                    if words.count < 12 || words.count > 30 { continue }
                    let hits = words.filter { bip39Hint.contains($0) }.count
                    // Need many BIP-39 hits in short order to be confident
                    if hits >= 6 { seedLikely = true; break }
                }

                if seedLikely {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Possible crypto wallet seed phrase in plaintext",
                        detail: "File contains a 12-24 word sequence that looks like a BIP-39 mnemonic. Stealers grep these patterns and post them to attacker servers within seconds.",
                        path: url.path,
                        remediation: "Move funds to a new wallet immediately, then store the new seed offline (hardware wallet, paper in a safe). Never keep seed phrases in plaintext on disk."
                    ))
                } else if nameMatches && (ext == "txt" || ext == "md" || ext == "") {
                    findings.append(Finding(
                        severity: .medium, category: .suspiciousFile,
                        title: "File name suggests crypto recovery material",
                        detail: "\(url.lastPathComponent) — name contains a wallet/seed/recovery keyword.",
                        path: url.path,
                        remediation: "Inspect — if this file holds wallet recovery info, move funds and store the secret offline."
                    ))
                }
            }
        }
    }

    // MARK: - AI / MCP configurations

    private func scanAIConfigs(findings: inout [Finding], errors: inout [String]) {
        // Model Context Protocol (MCP) is a 2024-2025 standard for letting LLM-powered IDEs
        // (Cursor, Claude Desktop, Windsurf) call external tools. A malicious MCP server can
        // exfiltrate every file the user reads, edits, or has the IDE open. Compromised
        // configurations have shipped via npm typosquats and copy-pasted README "setup" blocks.
        let home = ShellRunner.realUserHome
        let configPaths: [(path: String, label: String)] = [
            ("\(home)/Library/Application Support/Claude/claude_desktop_config.json", "Claude Desktop"),
            ("\(home)/.cursor/mcp.json", "Cursor"),
            ("\(home)/Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", "Cline (Cursor)"),
            ("\(home)/.codeium/windsurf/mcp_config.json", "Windsurf"),
            ("\(home)/.config/Continue/config.json", "Continue.dev"),
        ]

        let fm = FileManager.default
        for entry in configPaths {
            guard fm.fileExists(atPath: entry.path),
                  let data = fm.contents(atPath: entry.path) else { continue }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            // Both formats wrap servers under "mcpServers" — Cursor and Claude agree on this key.
            // Continue.dev wraps under "mcpServers" or "models". We just look for any inner dict
            // with a "command" or "url" key and inspect that.
            let servers = (json["mcpServers"] as? [String: Any]) ??
                          (json["servers"] as? [String: Any]) ??
                          [:]

            for (serverName, value) in servers {
                guard let server = value as? [String: Any] else { continue }

                // STDIO-launched server: run an arbitrary executable. The user should know which.
                if let command = server["command"] as? String {
                    let args = (server["args"] as? [String]) ?? []
                    // Auto-running npx/uvx packages from the public registry is the typical
                    // typosquat vector — flag those at MEDIUM.
                    let untrustedRunners = ["npx", "uvx", "pipx", "bun", "deno"]
                    if untrustedRunners.contains(command) {
                        findings.append(Finding(
                            severity: .medium, category: .suspiciousFile,
                            title: "\(entry.label) MCP server runs untrusted package: \(serverName)",
                            detail: "Command: \(command) \(args.joined(separator: " ")) — this fetches and runs a public package on every IDE launch. Typosquats and package-takeover are common entry points.",
                            path: entry.path,
                            remediation: "Pin the package version (use a specific @x.y.z) or install it manually and reference the local path; review what data the IDE exposes to it."
                        ))
                    } else if command.contains("/tmp/") || command.contains("/var/tmp/") {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "\(entry.label) MCP server launches from temp directory",
                            detail: "Command: \(command) — running binaries from temp is a classic dropper pattern.",
                            path: entry.path,
                            remediation: "Remove this MCP server entry and audit how it got installed."
                        ))
                    }
                }

                // HTTP/SSE-mounted servers: an upstream URL receives every tool call. Surface the URL
                // so the user can verify the destination.
                if let urlStr = (server["url"] as? String) ?? (server["endpoint"] as? String),
                   !urlStr.isEmpty {
                    // Trust localhost — most MCP server templates use it.
                    let lower = urlStr.lowercased()
                    let isLocal = lower.contains("://localhost") || lower.contains("://127.0.0.1") ||
                                  lower.contains("://[::1]") || lower.contains("://0.0.0.0")
                    if !isLocal {
                        findings.append(Finding(
                            severity: .medium, category: .networkActivity,
                            title: "\(entry.label) MCP server posts tool calls to remote host: \(serverName)",
                            detail: "URL: \(urlStr) — every tool invocation routes through this endpoint. Make sure you control it.",
                            path: entry.path,
                            remediation: "Confirm the URL belongs to your own infrastructure or a vendor you trust before leaving this configured."
                        ))
                    }
                }

                // env entries carrying API keys in plaintext — the file ends up in cloud-sync'd
                // user folders (Application Support is iCloud-synced for many users).
                if let env = server["env"] as? [String: String] {
                    for (key, val) in env {
                        let kLower = key.lowercased()
                        if kLower.contains("token") || kLower.contains("key") || kLower.contains("secret") {
                            if val.count > 16 && !val.hasPrefix("$") {
                                findings.append(Finding(
                                    severity: .medium, category: .suspiciousFile,
                                    title: "\(entry.label) MCP config has cleartext credential: \(serverName).\(key)",
                                    detail: "MCP env carries a literal token. Anyone who reads the config (backup, cloud-sync, stealer) gets it.",
                                    path: entry.path,
                                    remediation: "Switch to ${ENV_VAR} interpolation and load the secret from your shell or a secrets manager."
                                ))
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: - Shell history

    private func scanShellHistorySecrets(findings: inout [Finding], errors: inout [String]) {
        // History files are written by every interactive shell and are a common source of secret
        // leakage (people paste env vars, `export FOO=bar`, curl with -u user:pass, etc.). We scan
        // for the same credential patterns used in the dotenv check, plus passworded curl URIs.
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history", "\(home)/.zhistory",
            "\(home)/.bash_history", "\(home)/.history",
            "\(home)/.python_history", "\(home)/.node_repl_history",
            "\(home)/.psql_history", "\(home)/.mysql_history",
            "\(home)/.irb_history",
        ]

        for path in historyFiles {
            guard FileManager.default.fileExists(atPath: path),
                  let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            // Cap analysis to the last 200 KB — older history is unlikely to contain still-valid keys.
            let tail = String(content.suffix(200_000))
            let ns = tail as NSString
            let range = NSRange(location: 0, length: ns.length)

            var hits: [String] = []
            for pattern in Self.credentialPatterns {
                if pattern.regex.firstMatch(in: tail, options: [], range: range) != nil {
                    hits.append(pattern.name)
                }
            }

            // Special-case: curl/wget with embedded user:pass@ URLs.
            if let urlAuth = try? NSRegularExpression(pattern: #"(curl|wget).+https?://[^\s'"]*:[^@\s'"]+@"#),
               urlAuth.firstMatch(in: tail, options: [], range: range) != nil {
                hits.append("HTTP URL with embedded credentials")
            }

            if !hits.isEmpty {
                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "Shell history contains credential-like strings",
                    detail: "\(URL(fileURLWithPath: path).lastPathComponent) — detected: \(hits.prefix(3).joined(separator: ", "))",
                    path: path,
                    remediation: "Rotate any exposed secrets, then either purge with: cat /dev/null > \"\(path)\" or scrub specific lines. Going forward, prefix sensitive commands with a leading space (HISTCONTROL=ignorespace)."
                ))
            }
        }
    }
}
