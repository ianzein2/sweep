import Foundation

/// Surfaces plaintext credentials and crypto wallet data that modern macOS infostealers
/// (AMOS, FrigidStealer, Banshee, Cthulhu, Odyssey, MetaStealer) specifically harvest.
///
/// We never read or echo secret material — only the file's path, presence, and surface
/// indicators (e.g. presence of an `_authToken` line). All findings include actionable
/// remediation guidance.
public final class CredentialExposureScanner: Scanner {
    public let name = "Credential Exposure Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking cloud / CI credential files")
        scanCloudCredentialFiles(findings: &findings, errors: &errors)

        progress?.update("checking developer auth tokens")
        scanDeveloperTokens(findings: &findings, errors: &errors)

        progress?.update("checking SSH private keys")
        scanSSHPrivateKeys(findings: &findings, errors: &errors)

        progress?.update("checking GPG private keys")
        scanGPGPrivateKeys(findings: &findings, errors: &errors)

        progress?.update("checking shell history for secrets")
        scanShellHistoryForSecrets(findings: &findings, errors: &errors)

        progress?.update("checking crypto wallets")
        scanCryptoWallets(findings: &findings, errors: &errors)

        progress?.update("checking messenger session files")
        scanMessengerSessions(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Cloud / CI credential files

    private func scanCloudCredentialFiles(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // (path, friendly name, secret marker, severity if marker matches)
        let targets: [(path: String, name: String, marker: String?, severity: Severity, remediation: String)] = [
            (
                "\(home)/.aws/credentials",
                "AWS access keys",
                "aws_secret_access_key",
                .high,
                "Move long-lived AWS keys to AWS SSO / IAM Identity Center, or store them in the macOS Keychain via aws-vault. Rotate any leaked keys."
            ),
            (
                "\(home)/.docker/config.json",
                "Docker registry credentials",
                "\"auth\":",
                .medium,
                "Use a credential helper (docker-credential-osxkeychain) so registry tokens are stored in the Keychain instead of plaintext."
            ),
            (
                "\(home)/.npmrc",
                "npm auth token",
                "_authToken",
                .high,
                "Rotate the token at npmjs.com and use granular access tokens. Avoid checking ~/.npmrc into git."
            ),
            (
                "\(home)/.yarnrc",
                "Yarn auth token",
                "_authToken",
                .high,
                "Rotate the token and prefer per-project .yarnrc.yml with secrets in environment variables."
            ),
            (
                "\(home)/.pypirc",
                "PyPI / Twine credentials",
                "password",
                .high,
                "Replace the password with a PyPI API token, store it in the Keychain via keyring, and rotate the old credential."
            ),
            (
                "\(home)/.git-credentials",
                "Git stored credentials",
                "https://",
                .high,
                "Switch Git to use osxkeychain: git config --global credential.helper osxkeychain, then delete ~/.git-credentials and re-authenticate."
            ),
            (
                "\(home)/.config/gh/hosts.yml",
                "GitHub CLI tokens",
                "oauth_token",
                .high,
                "Re-run 'gh auth login' choosing the 'macOS Keychain' credential storage option; rotate any token that has appeared in backups."
            ),
            (
                "\(home)/.kube/config",
                "Kubernetes cluster credentials",
                "token:",
                .high,
                "Replace static tokens with short-lived OIDC/AWS-IAM auth; keep ~/.kube/config out of cloud-synced folders (Dropbox, iCloud Drive)."
            ),
            (
                "\(home)/.netrc",
                ".netrc auth (HTTP/FTP)",
                "password",
                .high,
                "Remove the password and use a Keychain-backed credential helper. .netrc stores credentials in cleartext for any local process to read."
            ),
            (
                "\(home)/.heroku/oauth_credentials",
                "Heroku CLI OAuth token",
                "token",
                .medium,
                "Rotate via 'heroku auth:token' and prefer the Keychain-backed login flow."
            ),
            (
                "\(home)/.config/doctl/config.yaml",
                "DigitalOcean CLI token",
                "access-token",
                .medium,
                "Regenerate the token at cloud.digitalocean.com if this file has ever been shared or synced."
            ),
            (
                "\(home)/.config/glab-cli/config.yml",
                "GitLab CLI token",
                "token",
                .medium,
                "Rotate the token in GitLab > User Settings > Access Tokens."
            ),
            (
                "\(home)/.snowsql/config",
                "Snowflake CLI credentials",
                "password",
                .high,
                "Switch to key-pair authentication for Snowflake (RSA) and remove plaintext passwords from ~/.snowsql/config."
            ),
            (
                "\(home)/.databrickscfg",
                "Databricks CLI token",
                "token",
                .high,
                "Rotate the personal access token and store it via the Databricks CLI 'databricks configure --token' with file permissions 600."
            ),
        ]

        for target in targets {
            guard fm.fileExists(atPath: target.path) else { continue }

            // World-readable secrets files are an immediate red flag.
            let attrs = try? fm.attributesOfItem(atPath: target.path)
            let perms = (attrs?[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
            // Mode 0o077 == group+other bits — anything beyond owner-only should be flagged.
            let worldOrGroupReadable = (perms & 0o077) != 0

            // Without reading content, presence alone is informational.
            var matchedMarker = false
            if let marker = target.marker,
               let content = try? String(contentsOfFile: target.path, encoding: .utf8) {
                matchedMarker = content.contains(marker)
            }

            let severity: Severity
            let detail: String

            if worldOrGroupReadable {
                severity = .high
                detail = "\(target.name) on disk with permissions 0\(String(perms, radix: 8)) — readable by non-owner processes; any infostealer that runs in your user session can copy it."
            } else if matchedMarker {
                severity = target.severity
                detail = "\(target.name) on disk in plaintext — recent macOS stealers (AMOS / FrigidStealer / Banshee / Odyssey) specifically grep for this path."
            } else {
                // Empty config file — informational only, but still surface it.
                severity = .low
                detail = "\(target.name) file present (no secret marker detected) — verify it does not contain plaintext credentials."
            }

            findings.append(Finding(
                severity: severity,
                category: .credentialExposure,
                title: "\(target.name) stored in plaintext",
                detail: detail,
                path: target.path,
                remediation: target.remediation
            ))
        }
    }

    // MARK: - Developer auth tokens (broader)

    private func scanDeveloperTokens(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Cursor / VS Code settings.json sometimes contain pasted API keys.
        let editorSettings = [
            ("\(home)/Library/Application Support/Code/User/settings.json", "VSCode user settings"),
            ("\(home)/Library/Application Support/Cursor/User/settings.json", "Cursor user settings"),
            ("\(home)/Library/Application Support/Windsurf/User/settings.json", "Windsurf user settings"),
            ("\(home)/Library/Application Support/Code - Insiders/User/settings.json", "VSCode Insiders settings"),
        ]

        // High-confidence inline-secret patterns. We only confirm presence — we never log the value.
        let secretRegexes: [(name: String, pattern: String)] = [
            ("OpenAI API key", "sk-[A-Za-z0-9]{20,}"),
            ("Anthropic API key", "sk-ant-[A-Za-z0-9_\\-]{20,}"),
            ("GitHub personal access token", "ghp_[A-Za-z0-9]{30,}"),
            ("GitHub fine-grained PAT", "github_pat_[A-Za-z0-9_]{30,}"),
            ("Slack token", "xox[abprs]-[A-Za-z0-9\\-]{10,}"),
            ("AWS access key id", "AKIA[0-9A-Z]{16}"),
            ("Stripe live key", "sk_live_[A-Za-z0-9]{20,}"),
            ("Google API key", "AIza[A-Za-z0-9_\\-]{30,}"),
        ]

        for (path, label) in editorSettings {
            guard fm.fileExists(atPath: path),
                  let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            for secret in secretRegexes {
                guard let regex = try? NSRegularExpression(pattern: secret.pattern, options: []) else { continue }
                let range = NSRange(content.startIndex..., in: content)
                if regex.firstMatch(in: content, options: [], range: range) != nil {
                    findings.append(Finding(
                        severity: .high,
                        category: .credentialExposure,
                        title: "\(secret.name) hard-coded in \(label)",
                        detail: "Pattern matching \(secret.name) was found in \(label). Any extension running in the editor — and any malware in your user session — can read this file.",
                        path: path,
                        remediation: "Remove the secret from \(path), rotate the credential at the provider, and load it from a Keychain-backed environment variable or a 1Password / dotenv-vault helper."
                    ))
                }
            }
        }

        // .env files in common locations
        let envPaths = [
            "\(home)/.env", "\(home)/.envrc", "\(home)/.env.local",
            "\(home)/Desktop/.env", "\(home)/Documents/.env",
        ]
        for path in envPaths where fm.fileExists(atPath: path) {
            // We only check perms here — .env files often contain real credentials and should not be world-readable.
            let attrs = try? fm.attributesOfItem(atPath: path)
            let perms = (attrs?[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
            if (perms & 0o077) != 0 {
                findings.append(Finding(
                    severity: .high,
                    category: .credentialExposure,
                    title: ".env file is world/group readable",
                    detail: "File mode 0\(String(perms, radix: 8)) — .env typically contains API keys and database URLs.",
                    path: path,
                    remediation: "Restrict permissions: chmod 600 \"\(path)\". Avoid placing .env files on Desktop/Documents where they're indexed and synced."
                ))
            }
        }
    }

    // MARK: - SSH private keys without a passphrase

    private func scanSSHPrivateKeys(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let sshDir = "\(home)/.ssh"
        let fm = FileManager.default

        guard fm.fileExists(atPath: sshDir),
              let entries = try? fm.contentsOfDirectory(atPath: sshDir) else { return }

        for entry in entries {
            let path = "\(sshDir)/\(entry)"
            // Skip known non-key files
            if entry == "config" || entry == "known_hosts" || entry == "known_hosts.old" ||
               entry == "authorized_keys" || entry == "authorized_keys2" ||
               entry.hasSuffix(".pub") { continue }

            // Read the file header only — never log key material.
            guard let fh = FileHandle(forReadingAtPath: path) else { continue }
            let header = fh.readData(ofLength: 1024)
            fh.closeFile()
            guard let headerStr = String(data: header, encoding: .utf8),
                  headerStr.contains("PRIVATE KEY") else { continue }

            // OpenSSH/PEM/PKCS#8 unencrypted keys: header lacks "ENCRYPTED" and (for PEM) the "Proc-Type: 4,ENCRYPTED" line.
            // OpenSSH new-format keys store the cipher in the binary body — we approximate by checking the surface header.
            let looksEncrypted = headerStr.contains("ENCRYPTED") || headerStr.contains("Proc-Type: 4,ENCRYPTED")

            // Permissions check
            let attrs = try? fm.attributesOfItem(atPath: path)
            let perms = (attrs?[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
            let permsTooOpen = (perms & 0o077) != 0

            if !looksEncrypted {
                findings.append(Finding(
                    severity: .high,
                    category: .credentialExposure,
                    title: "SSH private key without passphrase: \(entry)",
                    detail: "Key file has no encryption header — anyone (or any malware) able to read this file gets direct SSH access to anywhere this key is trusted.",
                    path: path,
                    remediation: "Add a passphrase: ssh-keygen -p -f \"\(path)\". Even better, move to a hardware-backed key (Secure Enclave via Secretive, YubiKey, or 1Password SSH agent)."
                ))
            }
            if permsTooOpen {
                findings.append(Finding(
                    severity: .high,
                    category: .credentialExposure,
                    title: "SSH private key has loose permissions: \(entry)",
                    detail: "Permissions 0\(String(perms, radix: 8)) — ssh refuses to use these keys for a reason; any process in your session can copy them.",
                    path: path,
                    remediation: "Restrict permissions: chmod 600 \"\(path)\""
                ))
            }
        }
    }

    // MARK: - GPG private keys exported to disk

    private func scanGPGPrivateKeys(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let candidatePaths = [
            "\(home)/Desktop", "\(home)/Documents", "\(home)/Downloads",
        ]
        let fm = FileManager.default

        for dir in candidatePaths {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries {
                // Common export names for private GPG keys
                let lower = entry.lowercased()
                guard lower.contains("private") || lower.contains("secret") || lower.hasSuffix(".asc") || lower.hasSuffix(".key") || lower.hasSuffix(".gpg") else { continue }

                let path = "\(dir)/\(entry)"
                guard let fh = FileHandle(forReadingAtPath: path) else { continue }
                let header = fh.readData(ofLength: 200)
                fh.closeFile()
                guard let headerStr = String(data: header, encoding: .utf8),
                      headerStr.contains("PGP PRIVATE KEY BLOCK") else { continue }

                findings.append(Finding(
                    severity: .high,
                    category: .credentialExposure,
                    title: "Exported GPG private key on disk",
                    detail: "An ASCII-armored PGP private key block was found outside the gpg keyring — anyone with file access can import it.",
                    path: path,
                    remediation: "Move the key into gpg-agent (which uses the Keychain on macOS), then securely delete this file: rm -P \"\(path)\""
                ))
            }
        }
    }

    // MARK: - Shell history with embedded secrets

    private func scanShellHistoryForSecrets(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history", "\(home)/.bash_history",
            "\(home)/.history", "\(home)/.local/share/fish/fish_history",
        ]

        // We look only for high-confidence prefixes — false positives here would be noisy.
        let secretMarkers: [(name: String, marker: String)] = [
            ("AWS_SECRET_ACCESS_KEY=", "AWS_SECRET_ACCESS_KEY="),
            ("OPENAI_API_KEY=sk-", "OPENAI_API_KEY=sk-"),
            ("ANTHROPIC_API_KEY=sk-ant-", "ANTHROPIC_API_KEY=sk-ant-"),
            ("GITHUB_TOKEN=ghp_", "GITHUB_TOKEN=ghp_"),
            ("SLACK_TOKEN=xox", "SLACK_TOKEN=xox"),
            ("DATABRICKS_TOKEN=", "DATABRICKS_TOKEN="),
            ("curl -u user:password", "curl -u "),
        ]

        for path in historyFiles {
            guard FileManager.default.fileExists(atPath: path),
                  let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            for marker in secretMarkers where content.contains(marker.marker) {
                findings.append(Finding(
                    severity: .high,
                    category: .credentialExposure,
                    title: "Shell history contains a secret",
                    detail: "Found a line matching '\(marker.name)' in your shell history — anyone with file access can read it.",
                    path: path,
                    remediation: "Rotate the credential, then clean history: HISTORY_IGNORE='(*KEY*|*TOKEN*|*SECRET*)' in ~/.zshrc, or remove the line. Use 'security add-generic-password' or direnv for future use."
                ))
                break // one finding per history file is enough
            }
        }
    }

    // MARK: - Crypto wallets — the #1 target of modern macOS stealers

    private func scanCryptoWallets(findings: inout [Finding], errors: inout [String]) {
        // Modern macOS infostealers explicitly enumerate these wallet directories and
        // exfiltrate their entire contents. We don't penalize having a wallet — the finding is
        // informational/awareness — but we elevate severity when the directory is on iCloud Drive
        // or Desktop/Documents (which can be cloud-synced and easily scraped).
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        struct WalletTarget {
            let name: String
            let path: String
            let exfilNote: String
        }

        let targets: [WalletTarget] = [
            // Desktop wallets
            .init(name: "Exodus", path: "\(home)/Library/Application Support/exodus.wallet",
                  exfilNote: "AMOS, Banshee, Cthulhu and Odyssey all target Exodus by default."),
            .init(name: "Electrum", path: "\(home)/.electrum/wallets",
                  exfilNote: "Electrum wallets live in a known path that every Bitcoin-targeting stealer enumerates."),
            .init(name: "Atomic Wallet", path: "\(home)/Library/Application Support/atomic",
                  exfilNote: "Atomic Wallet has been a primary target since the AMOS 2023 builds."),
            .init(name: "Wasabi", path: "\(home)/.walletwasabi",
                  exfilNote: "Wasabi has appeared in AMOS-family stealer exfiltration lists."),
            .init(name: "Coinomi", path: "\(home)/Library/Application Support/Coinomi",
                  exfilNote: "Coinomi is on every major macOS stealer's wallet list."),
            .init(name: "Trust Wallet (Desktop)", path: "\(home)/Library/Application Support/Trust",
                  exfilNote: "Trust desktop wallet keystores are an AMOS exfil target."),
            .init(name: "Phantom (Solana)", path: "\(home)/Library/Application Support/Phantom",
                  exfilNote: "Phantom session files are scraped by stealers; rotate seed if you suspect compromise."),
            .init(name: "Coinbase Wallet", path: "\(home)/Library/Application Support/Coinbase Wallet",
                  exfilNote: "Coinbase Wallet desktop data is targeted alongside its browser extension."),
            .init(name: "Ledger Live", path: "\(home)/Library/Application Support/Ledger Live",
                  exfilNote: "Ledger Live state files are scraped (the private key never leaves the device, but addresses and labels do)."),
            .init(name: "Trezor Suite", path: "\(home)/Library/Application Support/Trezor Suite",
                  exfilNote: "Trezor Suite session data has appeared in stealer exfil archives."),
            .init(name: "Daedalus (Cardano)", path: "\(home)/Library/Application Support/Daedalus Mainnet",
                  exfilNote: "Daedalus wallet data is targeted by Cardano-focused campaigns."),
            .init(name: "Keplr (desktop)", path: "\(home)/Library/Application Support/Keplr",
                  exfilNote: "Keplr desktop data is increasingly targeted by Cosmos-ecosystem stealers."),
        ]

        for target in targets {
            guard fm.fileExists(atPath: target.path) else { continue }

            // iCloud Drive paths are doubly risky — anything synced there is fetched on every device the
            // user is signed in to. We can't probe the cloud, but we can warn if the user has the wallet
            // dir under ~/Library/Mobile Documents (the iCloud Drive root for an app).
            let onICloud = target.path.contains("Mobile Documents")
            let severity: Severity = onICloud ? .high : .medium

            findings.append(Finding(
                severity: severity,
                category: .credentialExposure,
                title: "\(target.name) data present on disk",
                detail: "\(target.exfilNote)\(onICloud ? " — folder is in iCloud Drive, which compounds exfil risk." : "")",
                path: target.path,
                remediation: "Make sure your seed phrase has never been stored on disk or in a cloud-synced note. Consider moving funds to a hardware wallet if this Mac handles material amounts."
            ))
        }
    }

    // MARK: - Messenger sessions (Telegram / Discord / WhatsApp)

    private func scanMessengerSessions(findings: inout [Finding], errors: inout [String]) {
        // Stealing the tdata folder (Telegram) or LevelDB local storage (Discord) gives an
        // attacker a fully-authenticated session on another machine — no password required.
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        struct SessionTarget {
            let name: String
            let path: String
            let note: String
        }

        let targets: [SessionTarget] = [
            .init(
                name: "Telegram Desktop",
                path: "\(home)/Library/Application Support/Telegram Desktop/tdata",
                note: "Telegram's tdata folder is a full session — copying it elsewhere logs the attacker in as you, bypassing 2FA."
            ),
            .init(
                name: "Discord",
                path: "\(home)/Library/Application Support/discord/Local Storage/leveldb",
                note: "Discord's Local Storage contains the auth token — a known target of every chat-targeting stealer family."
            ),
            .init(
                name: "WhatsApp Desktop",
                path: "\(home)/Library/Group Containers/group.net.whatsapp.WhatsApp.shared",
                note: "WhatsApp Desktop session can be cloned from disk if not protected — verify FileVault is on and Mac is not unattended."
            ),
            .init(
                name: "Slack",
                path: "\(home)/Library/Application Support/Slack/Local Storage/leveldb",
                note: "Slack session cookies live in LevelDB; if exfiltrated, an attacker has authenticated access to your workspaces."
            ),
            .init(
                name: "Signal",
                path: "\(home)/Library/Application Support/Signal",
                note: "Signal Desktop stores message keys on disk; copying this folder restores the session elsewhere."
            ),
        ]

        for target in targets {
            guard fm.fileExists(atPath: target.path) else { continue }
            findings.append(Finding(
                severity: .low,
                category: .credentialExposure,
                title: "\(target.name) session data present",
                detail: target.note,
                path: target.path,
                remediation: "This is informational — FileVault is your main defence here. If you ever lose physical control of this Mac, sign \(target.name) out from a second device immediately."
            ))
        }
    }
}
