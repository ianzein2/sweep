import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Audits the permissions and locations of developer / cloud credential files.
///
/// 2024-2025 macOS stealers (AMOS, Atomic, Banshee, FrigidStealer) specifically harvest
/// these files because they unlock cloud accounts, source-code repos, and crypto wallets
/// without needing further interaction. A loose POSIX mode here can also let any non-root
/// process — including a freshly-installed unsigned app — read the secret.
public final class CredentialExposureScanner: Scanner {
    public let name = "Credential Exposure Scan"
    public init() {}

    /// A credential file we expect to find on disk for many users.
    /// `tightMode` is the POSIX mode this file *should* be at if it exists. We flag anything
    /// looser than that (group- or world-readable, world-writable, etc.).
    private struct CredFile {
        let relativePath: String   // relative to ~
        let tightMode: mode_t      // expected mode bits (typically 0o600 / 0o400)
        let label: String
        let why: String            // user-facing reason
    }

    private let credentialFiles: [CredFile] = [
        // SSH — id_rsa et al. are the single highest-value targets on a dev machine.
        CredFile(relativePath: ".ssh/id_rsa", tightMode: 0o600,
                 label: "SSH private key (RSA)",
                 why: "Anyone who reads this key can SSH into every host where the public key is authorized"),
        CredFile(relativePath: ".ssh/id_ed25519", tightMode: 0o600,
                 label: "SSH private key (Ed25519)",
                 why: "Anyone who reads this key can SSH into every host where the public key is authorized"),
        CredFile(relativePath: ".ssh/id_ecdsa", tightMode: 0o600,
                 label: "SSH private key (ECDSA)",
                 why: "Anyone who reads this key can SSH into every host where the public key is authorized"),
        CredFile(relativePath: ".ssh/id_dsa", tightMode: 0o600,
                 label: "SSH private key (DSA)",
                 why: "Anyone who reads this key can SSH into every host where the public key is authorized"),
        // Cloud CLIs — bearer tokens to your cloud account
        CredFile(relativePath: ".aws/credentials", tightMode: 0o600,
                 label: "AWS credentials",
                 why: "Contains long-lived AWS access keys — any process that reads this can act as you in AWS"),
        CredFile(relativePath: ".aws/config", tightMode: 0o644,
                 label: "AWS config",
                 why: "Usually harmless but can leak SSO start URLs / role ARNs"),
        // Kubernetes
        CredFile(relativePath: ".kube/config", tightMode: 0o600,
                 label: "kubeconfig",
                 why: "Contains cluster credentials — readers can run kubectl as you"),
        // GitHub / Git
        CredFile(relativePath: ".git-credentials", tightMode: 0o600,
                 label: "Git credentials",
                 why: "Plain-text Git HTTPS passwords / personal access tokens"),
        CredFile(relativePath: ".gitconfig", tightMode: 0o644,
                 label: "Git config",
                 why: "May contain [url] insteadOf rules with embedded tokens"),
        // npm / yarn / pypi / docker
        CredFile(relativePath: ".npmrc", tightMode: 0o600,
                 label: "npm config (.npmrc)",
                 why: "Often contains _authToken values for npm / GitHub Packages"),
        CredFile(relativePath: ".yarnrc", tightMode: 0o600,
                 label: "yarn config (.yarnrc)",
                 why: "Often contains registry auth tokens"),
        CredFile(relativePath: ".yarnrc.yml", tightMode: 0o600,
                 label: "yarn 3+ config (.yarnrc.yml)",
                 why: "Often contains npmAuthToken values"),
        CredFile(relativePath: ".pypirc", tightMode: 0o600,
                 label: "PyPI credentials (.pypirc)",
                 why: "Contains your PyPI upload token in plaintext"),
        CredFile(relativePath: ".docker/config.json", tightMode: 0o600,
                 label: "Docker config",
                 why: "Contains base64-encoded registry credentials"),
        // netrc — historic ftp/http credential file, still used by curl, git, hg
        CredFile(relativePath: ".netrc", tightMode: 0o600,
                 label: ".netrc",
                 why: "Plain-text usernames + passwords for any host you've curled to"),
        // SOPS / age
        CredFile(relativePath: ".config/sops/age/keys.txt", tightMode: 0o600,
                 label: "age / SOPS keys",
                 why: "Anyone with this file can decrypt every SOPS-encrypted secret you have"),
        // Chrome/Brave master state files appear elsewhere in EvidenceScanner — skipped here.
    ]

    /// Directories whose contents must not be world-readable (search permission only).
    private let credentialDirs: [(path: String, label: String)] = [
        (".ssh", "SSH directory"),
        (".gnupg", "GnuPG directory"),
        (".aws", "AWS CLI directory"),
        (".kube", "kubeconfig directory"),
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        progress?.update("checking credential file permissions")
        for cred in credentialFiles {
            let fullPath = "\(home)/\(cred.relativePath)"
            guard fm.fileExists(atPath: fullPath) else { continue }
            checkFileMode(path: fullPath, expected: cred.tightMode,
                          label: cred.label, why: cred.why,
                          findings: &findings, errors: &errors)
            // Specific content checks for files known to leak secrets in cleartext
            switch cred.relativePath {
            case ".npmrc", ".yarnrc", ".yarnrc.yml":
                checkForAuthTokens(path: fullPath, label: cred.label, findings: &findings)
            case ".netrc":
                checkForCleartextPasswords(path: fullPath, label: cred.label, findings: &findings)
            case ".git-credentials":
                checkForGitTokens(path: fullPath, findings: &findings)
            default:
                break
            }
        }

        progress?.update("checking credential directory permissions")
        for dir in credentialDirs {
            let fullPath = "\(home)/\(dir.path)"
            guard fm.fileExists(atPath: fullPath) else { continue }
            checkDirMode(path: fullPath, label: dir.label, findings: &findings)
        }

        progress?.update("scanning for credentials in unusual locations")
        scanForCredentialsInTempLocations(findings: &findings)

        progress?.update("scanning shell history for plaintext secrets")
        scanShellHistoryForLeaks(home: home, findings: &findings)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - File mode check

    /// Pull POSIX mode bits via stat — Foundation's attributesOfItem rounds these into
    /// NSFilePosixPermissions but we keep raw `mode_t` semantics here for clarity.
    private func checkFileMode(path: String, expected: mode_t,
                               label: String, why: String,
                               findings: inout [Finding], errors: inout [String]) {
        var st = stat()
        guard stat(path, &st) == 0 else {
            errors.append("Could not stat \(path)")
            return
        }
        let mode = st.st_mode & 0o777
        let groupReadable = (mode & 0o040) != 0
        let worldReadable = (mode & 0o004) != 0
        let worldWritable = (mode & 0o002) != 0

        // Files like ~/.aws/config are usually fine at 0644; we only escalate when
        // the actual mode is looser than the expected mode for that file.
        let isLooser = (mode & ~expected) != 0

        if !isLooser { return }

        let severity: Severity
        let titleSuffix: String
        if worldReadable || worldWritable {
            severity = .high
            titleSuffix = worldWritable ? "world-writable" : "world-readable"
        } else if groupReadable && expected == 0o600 {
            severity = .medium
            titleSuffix = "group-readable"
        } else {
            severity = .low
            titleSuffix = "mode \(formatOctal(mode)) (expected ≤ \(formatOctal(expected)))"
        }

        findings.append(Finding(
            severity: severity, category: .permission,
            title: "\(label) is \(titleSuffix)",
            detail: "\(path) — \(why)",
            path: path,
            remediation: "Tighten permissions: chmod \(formatOctal(expected)) \"\(path)\""
        ))
    }

    /// Render a `mode_t` as a three-digit octal string ("600", "644", "755", ...).
    /// Built explicitly to avoid CVarArg width ambiguity around mode_t (UInt16).
    private func formatOctal(_ mode: mode_t) -> String {
        let value = UInt32(mode) & 0o777
        var out = String(value, radix: 8)
        while out.count < 3 { out = "0" + out }
        return out
    }

    private func checkDirMode(path: String, label: String, findings: inout [Finding]) {
        var st = stat()
        guard stat(path, &st) == 0 else { return }
        let mode = st.st_mode & 0o777
        // SSH refuses to use keys if ~/.ssh is loose — same principle for GPG / AWS.
        if (mode & 0o077) != 0 {
            // group or other has any bit set
            findings.append(Finding(
                severity: .medium, category: .permission,
                title: "\(label) has loose permissions",
                detail: "\(path) — mode \(formatOctal(mode)) (should be 700)",
                path: path,
                remediation: "Tighten permissions: chmod 700 \"\(path)\""
            ))
        }
    }

    // MARK: - Content checks

    private func checkForAuthTokens(path: String, label: String, findings: inout [Finding]) {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        let hasAuth = content.range(of: #"_authToken\s*=\s*\S"#, options: .regularExpression) != nil ||
                      content.range(of: #"npmAuthToken:\s*\S"#, options: .regularExpression) != nil
        if hasAuth {
            findings.append(Finding(
                severity: .low, category: .permission,
                title: "\(label) contains a plaintext auth token",
                detail: "\(path) stores an npm/yarn auth token in cleartext — any process that reads this file can publish packages as you",
                path: path,
                remediation: "Replace with an environment-variable reference or a credential helper if your CI / package manager supports it"
            ))
        }
    }

    private func checkForCleartextPasswords(path: String, label: String, findings: inout [Finding]) {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        if content.contains("password ") || content.contains("password\t") {
            findings.append(Finding(
                severity: .medium, category: .permission,
                title: "\(label) contains cleartext passwords",
                detail: "\(path) lists `password` fields in plaintext — readable by anything running as your user",
                path: path,
                remediation: "Use the macOS keychain via security(1) or a credential helper instead"
            ))
        }
    }

    private func checkForGitTokens(path: String, findings: inout [Finding]) {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        // .git-credentials stores entries as https://user:token@host — that token is the secret.
        if content.contains("@github.com") || content.contains("@gitlab.com") || content.contains("@bitbucket.org") {
            findings.append(Finding(
                severity: .low, category: .permission,
                title: ".git-credentials contains personal access tokens",
                detail: "\(path) stores PATs in cleartext — keep this file at 0600 and rotate any leaked tokens",
                path: path,
                remediation: "Switch to the osxkeychain credential helper: git config --global credential.helper osxkeychain"
            ))
        }
    }

    // MARK: - Stealer staging locations

    /// Stealers stage credential files in /tmp before exfiltration. A copy of `id_rsa`,
    /// `credentials`, or `config.json` outside the user's home (or inside a hidden dir
    /// within /tmp) is high-confidence active-stealer evidence.
    private func scanForCredentialsInTempLocations(findings: inout [Finding]) {
        let fm = FileManager.default
        let watchedNames: Set<String> = [
            "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
            "credentials", "config.json", "kubeconfig",
            ".npmrc", ".pypirc", ".netrc", ".git-credentials",
            "login.keychain-db", "login.keychain",
        ]
        let roots = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp"]
        for root in roots {
            guard fm.fileExists(atPath: root),
                  let enumerator = fm.enumerator(atPath: root) else { continue }
            // /tmp can be huge; cap traversal so this stays fast.
            var visited = 0
            while let relativeStr = enumerator.nextObject() as? String, visited < 5_000 {
                visited += 1
                let name = (relativeStr as NSString).lastPathComponent
                guard watchedNames.contains(name) else { continue }
                let fullPath = "\(root)/\(relativeStr)"
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Credential file staged in \(root)",
                    detail: "Found \(name) at \(fullPath) — modern macOS stealers stage these files in /tmp before exfiltration",
                    path: fullPath,
                    remediation: "Identify the creating process and rotate the leaked credential (SSH key, cloud token, etc.)"
                ))
            }
        }
    }

    // MARK: - Shell history secret leaks

    /// Looks for common secret-shaped tokens inline in shell history. We try to be
    /// conservative — a single false positive here is a chore for the user to dismiss
    /// every scan.
    private func scanShellHistoryForLeaks(home: String, findings: inout [Finding]) {
        let historyFiles = ["\(home)/.zsh_history", "\(home)/.bash_history"]

        // Anchored patterns. Each regex includes context so it doesn't fire on hex strings.
        let regexes: [(pattern: String, label: String)] = [
            (#"AKIA[0-9A-Z]{16}"#, "AWS access key ID"),
            (#"ghp_[A-Za-z0-9]{36,}"#, "GitHub personal access token"),
            (#"gho_[A-Za-z0-9]{36,}"#, "GitHub OAuth token"),
            (#"github_pat_[A-Za-z0-9_]{60,}"#, "GitHub fine-grained PAT"),
            (#"glpat-[A-Za-z0-9\-]{20,}"#, "GitLab personal access token"),
            (#"xox[baprs]-[A-Za-z0-9\-]{10,}"#, "Slack token"),
            (#"sk-[A-Za-z0-9]{20,}"#, "OpenAI / Stripe-shaped secret key"),
        ]

        for path in historyFiles {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            for entry in regexes {
                guard let _ = content.range(of: entry.pattern, options: .regularExpression) else { continue }
                findings.append(Finding(
                    severity: .medium, category: .permission,
                    title: "\(entry.label) found inline in shell history",
                    detail: "\(path) contains what looks like a \(entry.label). Even short-lived tokens here are recoverable by anything that reads this file (including stealers).",
                    path: path,
                    remediation: "Rotate the leaked credential, then trim the line out: history -d <num> (zsh) or edit \(path) directly"
                ))
            }
        }
    }
}
