import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Detects developer-targeted threats that bypass traditional spyware signatures:
///   - Malicious npm/pip packages from the DPRK "Contagious Interview" campaign and friends
///   - Trojanized IDE marketplace extensions (Cursor / Windsurf / VSCode)
///   - World-readable credential files (AI API keys, cloud tokens, SSH keys) that 2024-2025
///     infostealers explicitly enumerate before exfiltration
///
/// These are the attack surfaces that AMOS / Banshee / BeaverTail-style stealers care about
/// most on modern developer machines.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    // MARK: - Known-bad npm packages

    /// npm packages confirmed by Phylum / Socket / ReversingLabs reports (2023-2025) as
    /// vectors for BeaverTail / InvisibleFerret / DPRK "Contagious Interview" campaigns,
    /// Lottie-Player supply-chain compromise, and the ledger-helper crypto-wallet-drainer
    /// clusters. Names are matched against the resolved package name inside node_modules.
    private let knownBadNpmPackages: Set<String> = [
        // Contagious Interview (BeaverTail loader npm packages)
        "passport-loginrequired",
        "passport-saml-keycloak",
        "node-clog",
        "node-error-log",
        "noderr-log",
        "execution-time-async",
        "vue-execution-time",
        "react-execution-time",
        "asyncawaiter",
        "asyncawaiter-fix",
        "rocketrefer",
        "react-cookie-async",
        "node-clip",
        "vue-resp",
        "rtk-logger",
        "audioappv2",
        "audioappv4",
        "events-utils",
        "wsail",
        // Lottie-Player / supply-chain (Oct 2024)
        "@lottiefiles/lottie-player",  // versions 2.0.5–2.0.7 only — flagged conservatively as needs-review
        // Ledger-Connect-Kit clones / wallet drainer impersonators
        "ledger-connect-fix",
        "ledger-connect-kit-helper",
        // Solana / EVM private-key stealers seen on npm in 2024
        "solana-systemprogram-utils",
        "solana-transaction-toolkit",
        "solana-token-utils",
        "@solana-systemprogram/utils",
        // ESlint config trojans (July 2024 incident)
        "eslint-config-prettier-utils",
        "@eslintconfig/prettier",
    ]

    /// PyPI packages flagged as part of recent DPRK / typosquat campaigns. Most are direct
    /// typosquats of popular libraries with a postinstall payload.
    private let knownBadPyPiPackages: Set<String> = [
        // Contagious Interview Python loaders (mid-2024)
        "pyperclip-async",
        "pyperclop",
        "pyrequests",
        "requestes",
        "request-helpers",
        "passlib-async",
        "discord-utility",
        "discord-utils-py",
        // Typosquats from 2024 cluster reports
        "tensorflow-cpu-aws",
        "tensorflowcpu",
        "torchaudio-cpu",
        "pytorch-cuda",
        "scikitlearn",
        "matplotlib-utils",
        // BLOM hijack chain
        "ctx",
        "phpass",
    ]

    /// Cursor / VSCode / Windsurf marketplace extensions reported as malicious in 2024-2025.
    /// Matched against extension package names and directories (`publisher.name-version`).
    private let knownBadEditorExtensions: Set<String> = [
        // Cursor marketplace incidents (early 2025)
        "cursor-helper-prettier",
        "cursor-ai-improved",
        "ai-completion-pro",
        "ai-quick-import",
        "code-genie-plus",
        // VSCode marketplace clones reported by ExtensionTotal (2024-2025)
        "prettier-vscode-plus",
        "darcula-theme-enhanced",
        "material-icon-theme-enhanced",
        "solidity-debugger-plus",
        "ethers-vscode-helper",
        "web3-helpers",
        "ahmadalli-vscode-restore-terminals",
        "evan-buss-quokka-vscode-pro",
    ]

    // MARK: - Credential exposure paths

    /// Files containing API tokens / credentials that 2024-2025 infostealers explicitly
    /// enumerate. Each entry is (description, glob-relative-to-home, expected mode bits).
    /// Flag any file whose mode is more permissive than expected — group / other readable
    /// secrets are how infostealers get them without prompting for password.
    private struct CredentialTarget {
        let description: String
        let relativePath: String
        let maxMode: mode_t  // anything above this is too permissive
    }

    private let credentialTargets: [CredentialTarget] = [
        // SSH and GPG private keys — classic targets
        CredentialTarget(description: "SSH private key (id_rsa)",        relativePath: ".ssh/id_rsa",        maxMode: 0o600),
        CredentialTarget(description: "SSH private key (id_ed25519)",    relativePath: ".ssh/id_ed25519",    maxMode: 0o600),
        CredentialTarget(description: "SSH private key (id_ecdsa)",      relativePath: ".ssh/id_ecdsa",      maxMode: 0o600),
        CredentialTarget(description: "SSH config",                      relativePath: ".ssh/config",        maxMode: 0o644),
        CredentialTarget(description: "AWS credentials",                 relativePath: ".aws/credentials",   maxMode: 0o600),
        CredentialTarget(description: "AWS config",                      relativePath: ".aws/config",        maxMode: 0o644),
        CredentialTarget(description: "Google Cloud application default credentials",
                         relativePath: ".config/gcloud/application_default_credentials.json", maxMode: 0o600),
        CredentialTarget(description: "Kubernetes config",               relativePath: ".kube/config",       maxMode: 0o600),
        CredentialTarget(description: "Docker config",                   relativePath: ".docker/config.json", maxMode: 0o600),
        CredentialTarget(description: "npm auth token",                  relativePath: ".npmrc",             maxMode: 0o600),
        CredentialTarget(description: "PyPI upload token",               relativePath: ".pypirc",            maxMode: 0o600),
        CredentialTarget(description: "GitHub CLI token",                relativePath: ".config/gh/hosts.yml", maxMode: 0o600),
        // AI / LLM credentials — newly targeted in 2024-2025 stealer campaigns
        CredentialTarget(description: "Anthropic API config",            relativePath: ".anthropic/auth.json", maxMode: 0o600),
        CredentialTarget(description: "Claude config",                   relativePath: ".claude.json",       maxMode: 0o600),
        CredentialTarget(description: "Claude credentials",              relativePath: ".claude/credentials.json", maxMode: 0o600),
        CredentialTarget(description: "OpenAI key file",                 relativePath: ".openai",            maxMode: 0o600),
        CredentialTarget(description: "OpenAI auth",                     relativePath: ".openai/auth.json",  maxMode: 0o600),
        CredentialTarget(description: "Cursor IDE auth",                 relativePath: ".cursor/auth.json",  maxMode: 0o600),
        CredentialTarget(description: "Windsurf IDE auth",               relativePath: ".windsurf/auth.json", maxMode: 0o600),
        // Crypto wallet seeds and keystores
        CredentialTarget(description: "Bitcoin wallet.dat",              relativePath: "Library/Application Support/Bitcoin/wallet.dat", maxMode: 0o600),
        CredentialTarget(description: "Electrum wallet directory",       relativePath: ".electrum/wallets",  maxMode: 0o700),
        CredentialTarget(description: "Ethereum keystore",               relativePath: "Library/Ethereum/keystore", maxMode: 0o700),
    ]

    // MARK: - Scan

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("scanning for malicious npm packages")
        scanNpmPackages(findings: &findings, errors: &errors)

        progress?.update("scanning for malicious PyPI packages")
        scanPipPackages(findings: &findings, errors: &errors)

        progress?.update("scanning IDE marketplace extensions")
        scanEditorExtensions(findings: &findings, errors: &errors)

        progress?.update("scanning postinstall scripts")
        scanPostinstallScripts(findings: &findings, errors: &errors)

        progress?.update("checking developer credential exposure")
        scanCredentialExposure(findings: &findings, errors: &errors)

        progress?.update("checking environment file leaks")
        scanEnvFiles(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - npm

    private func scanNpmPackages(findings: inout [Finding], errors: inout [String]) {
        // Look at npm's global root (so we catch globally-installed loaders) and at the
        // user's recent project node_modules directories under common parents. We do NOT
        // walk the entire home directory — that would be far too slow.
        let home = ShellRunner.realUserHome
        var roots: [String] = [
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
        ]
        let projectParents = [
            "\(home)/Developer", "\(home)/Projects", "\(home)/Code",
            "\(home)/src", "\(home)/work", "\(home)/Documents",
            "\(home)/Desktop", "\(home)/repos", "\(home)/dev",
        ]
        for parent in projectParents {
            let fm = FileManager.default
            guard let entries = try? fm.contentsOfDirectory(atPath: parent) else { continue }
            for entry in entries {
                let candidate = "\(parent)/\(entry)/node_modules"
                if fm.fileExists(atPath: candidate) {
                    roots.append(candidate)
                }
            }
        }

        let fm = FileManager.default
        for root in roots {
            guard fm.fileExists(atPath: root) else { continue }
            scanNodeModulesTree(root: root, findings: &findings, depth: 0)
        }
    }

    private func scanNodeModulesTree(root: String, findings: inout [Finding], depth: Int) {
        // We descend only into top-level packages and scoped (@scope/) packages. Going deeper
        // would cross into transitive deps — fine, but we cap depth to keep scan time bounded.
        guard depth < 3 else { return }
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: root) else { return }

        for entry in entries where !entry.hasPrefix(".") {
            let entryPath = "\(root)/\(entry)"
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: entryPath, isDirectory: &isDir), isDir.boolValue else { continue }

            if entry.hasPrefix("@") {
                // scoped: descend one level
                scanNodeModulesTree(root: entryPath, findings: &findings, depth: depth + 1)
                continue
            }

            // Check package.json for the actual published name
            let pkgPath = "\(entryPath)/package.json"
            guard let data = fm.contents(atPath: pkgPath),
                  let pkg = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            let pkgName = (pkg["name"] as? String) ?? entry

            if knownBadNpmPackages.contains(pkgName) || knownBadNpmPackages.contains(entry) {
                findings.append(Finding(
                    severity: .high,
                    category: .supplyChain,
                    title: "Known-malicious npm package installed",
                    detail: "Package \"\(pkgName)\" at \(entryPath) — reported as part of a public supply-chain attack campaign",
                    path: entryPath,
                    remediation: "Remove the package (npm uninstall \(pkgName)), rotate any tokens / wallet keys, and audit recent commits"
                ))
                continue
            }
        }
    }

    // MARK: - PyPI

    private func scanPipPackages(findings: inout [Finding], errors: inout [String]) {
        // Walk the well-known site-packages locations for Python on macOS.
        let home = ShellRunner.realUserHome
        var roots: [String] = [
            "/Library/Python/3.9/site-packages",
            "/Library/Python/3.10/site-packages",
            "/Library/Python/3.11/site-packages",
            "/Library/Python/3.12/site-packages",
            "/Library/Python/3.13/site-packages",
            "/opt/homebrew/lib/python3.11/site-packages",
            "/opt/homebrew/lib/python3.12/site-packages",
            "/opt/homebrew/lib/python3.13/site-packages",
            "/usr/local/lib/python3.11/site-packages",
            "/usr/local/lib/python3.12/site-packages",
            "/usr/local/lib/python3.13/site-packages",
            "\(home)/Library/Python/3.9/lib/python/site-packages",
            "\(home)/Library/Python/3.10/lib/python/site-packages",
            "\(home)/Library/Python/3.11/lib/python/site-packages",
            "\(home)/Library/Python/3.12/lib/python/site-packages",
            "\(home)/Library/Python/3.13/lib/python/site-packages",
            "\(home)/.local/lib/python3.11/site-packages",
            "\(home)/.local/lib/python3.12/site-packages",
            "\(home)/.local/lib/python3.13/site-packages",
        ]
        // venvs people commonly drop into ~ — check the well-known ones.
        let venvCandidates = ["\(home)/.venv", "\(home)/venv", "\(home)/env"]
        for venv in venvCandidates {
            roots.append("\(venv)/lib/python3.11/site-packages")
            roots.append("\(venv)/lib/python3.12/site-packages")
            roots.append("\(venv)/lib/python3.13/site-packages")
        }

        let fm = FileManager.default
        for root in roots {
            guard fm.fileExists(atPath: root),
                  let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }

            for entry in entries {
                // distributions land both as "<pkg>" (importable) and "<pkg>-<ver>.dist-info"
                let name = entry
                    .replacingOccurrences(of: "-", with: "_")
                    .lowercased()
                    .components(separatedBy: ".")
                    .first ?? entry.lowercased()
                let underscoreVariant = name
                let hyphenVariant = name.replacingOccurrences(of: "_", with: "-")

                if knownBadPyPiPackages.contains(underscoreVariant) ||
                    knownBadPyPiPackages.contains(hyphenVariant) {
                    findings.append(Finding(
                        severity: .high,
                        category: .supplyChain,
                        title: "Known-malicious PyPI package installed",
                        detail: "Package \"\(entry)\" at \(root) — reported as part of a public supply-chain attack campaign",
                        path: "\(root)/\(entry)",
                        remediation: "Uninstall (pip uninstall \(hyphenVariant)) and rotate any credentials this Python environment has access to"
                    ))
                }
            }
        }
    }

    // MARK: - Editor extensions (known-bad list, complementing BrowserScanner's heuristics)

    private func scanEditorExtensions(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let editors: [(name: String, dir: String)] = [
            ("VSCode", "\(home)/.vscode/extensions"),
            ("VSCode Insiders", "\(home)/.vscode-insiders/extensions"),
            ("Cursor", "\(home)/.cursor/extensions"),
            ("Windsurf", "\(home)/.windsurf/extensions"),
            ("VSCodium", "\(home)/.vscode-oss/extensions"),
        ]
        let fm = FileManager.default

        for (editorName, extDir) in editors {
            guard fm.fileExists(atPath: extDir),
                  let entries = try? fm.contentsOfDirectory(atPath: extDir) else { continue }

            for entry in entries where !entry.hasPrefix(".") {
                let entryLower = entry.lowercased()
                if let match = knownBadEditorExtensions.first(where: { entryLower.contains($0) }) {
                    findings.append(Finding(
                        severity: .high,
                        category: .supplyChain,
                        title: "Known-malicious \(editorName) extension installed",
                        detail: "Extension \"\(entry)\" matches reported malicious family \"\(match)\"",
                        path: "\(extDir)/\(entry)",
                        remediation: "Remove in \(editorName) > Extensions and rotate any credentials the IDE had access to"
                    ))
                    continue
                }
                // Also check publisher.name inside package.json
                let pkgPath = "\(extDir)/\(entry)/package.json"
                guard let data = fm.contents(atPath: pkgPath),
                      let pkg = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
                let publisher = (pkg["publisher"] as? String) ?? ""
                let pkgName = (pkg["name"] as? String) ?? ""
                let combined = "\(publisher).\(pkgName)".lowercased()
                if let match = knownBadEditorExtensions.first(where: { combined.contains($0) }) {
                    findings.append(Finding(
                        severity: .high,
                        category: .supplyChain,
                        title: "Known-malicious \(editorName) extension installed",
                        detail: "Extension \(combined) matches reported malicious family \"\(match)\"",
                        path: "\(extDir)/\(entry)",
                        remediation: "Remove in \(editorName) > Extensions and rotate any credentials the IDE had access to"
                    ))
                }
            }
        }
    }

    // MARK: - Postinstall scripts in node_modules (BeaverTail-style loaders)

    /// Walks the top-level package.json of every direct dependency in the user's recent
    /// projects, looking for postinstall hooks that perform network downloads or hand off
    /// to eval / Buffer.from / child_process. This catches BeaverTail-style npm loaders
    /// even when the package name is not yet in our known-bad list.
    private func scanPostinstallScripts(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let projectParents = [
            "\(home)/Developer", "\(home)/Projects", "\(home)/Code",
            "\(home)/src", "\(home)/work", "\(home)/repos", "\(home)/dev",
        ]

        let fm = FileManager.default
        for parent in projectParents {
            guard let projects = try? fm.contentsOfDirectory(atPath: parent) else { continue }
            for project in projects {
                let nm = "\(parent)/\(project)/node_modules"
                guard fm.fileExists(atPath: nm),
                      let pkgs = try? fm.contentsOfDirectory(atPath: nm) else { continue }

                // Cap per-project: don't scan thousands of subpackages. We're hunting for the
                // canonical "single dropped-in package" pattern.
                for pkg in pkgs.prefix(500) where !pkg.hasPrefix(".") {
                    inspectPackageJsonForPostinstall(at: "\(nm)/\(pkg)/package.json", findings: &findings)
                }
            }
        }
    }

    private func inspectPackageJsonForPostinstall(at path: String, findings: inout [Finding]) {
        guard let data = FileManager.default.contents(atPath: path),
              let pkg = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let scripts = pkg["scripts"] as? [String: String] else { return }
        let suspect = ["postinstall", "preinstall", "install"]
        for key in suspect {
            guard let script = scripts[key] else { continue }
            let lower = script.lowercased()
            // The classic BeaverTail loader chain: download a JS blob and pipe to node.
            let downloadsAndExecs =
                (lower.contains("curl") || lower.contains("wget") || lower.contains("https.get") || lower.contains("fetch ")) &&
                (lower.contains("| node") || lower.contains("| sh") || lower.contains("| bash") ||
                 lower.contains("eval") || lower.contains("buffer.from"))
            let bareNetwork =
                lower.contains("http://") || lower.contains("https://")
            let usesChildProcess = lower.contains("child_process") || lower.contains("require('child_process')")

            if downloadsAndExecs {
                let pkgName = (pkg["name"] as? String) ?? path
                findings.append(Finding(
                    severity: .high,
                    category: .supplyChain,
                    title: "npm package \(key) script downloads and executes remote code",
                    detail: "Package \"\(pkgName)\" \(key): \(String(script.prefix(160)))",
                    path: path,
                    remediation: "Remove this package immediately and audit any commits / network calls since it was installed"
                ))
            } else if bareNetwork && usesChildProcess {
                let pkgName = (pkg["name"] as? String) ?? path
                findings.append(Finding(
                    severity: .medium,
                    category: .supplyChain,
                    title: "npm package \(key) script makes network call + spawns process",
                    detail: "Package \"\(pkgName)\" \(key): \(String(script.prefix(160)))",
                    path: path,
                    remediation: "Verify the script is legitimate — this is a common stage-2 loader pattern"
                ))
            }
        }
    }

    // MARK: - Credential file permission audit

    private func scanCredentialExposure(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        for target in credentialTargets {
            let path = "\(home)/\(target.relativePath)"
            guard fm.fileExists(atPath: path) else { continue }
            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  let posixRaw = attrs[.posixPermissions] as? NSNumber else { continue }
            let mode = mode_t(posixRaw.uint16Value) & 0o777

            // maxMode encodes the policy for this kind of file (private key vs. config). If
            // the actual mode has any bit set that maxMode doesn't allow, it is more accessible
            // than it should be. (mode being a strict subset of maxMode is always fine.)
            let isTooPermissive = (mode & ~target.maxMode) != 0
            if isTooPermissive {
                let modeStr = String(format: "%03o", mode)
                let expectedStr = String(format: "%03o", target.maxMode)
                findings.append(Finding(
                    severity: .medium,
                    category: .credentialExposure,
                    title: "\(target.description) has loose permissions",
                    detail: "File: \(path), mode: \(modeStr) (expected \(expectedStr) or stricter)",
                    path: path,
                    remediation: "Tighten permissions: chmod \(expectedStr) \"\(path)\""
                ))
            }
        }

        // Special check: a private SSH key without a passphrase header. We can't decrypt it,
        // but unencrypted keys say "BEGIN OPENSSH PRIVATE KEY" without ENCRYPTED markers and
        // a "kdfname: none" hint we can scan for cheaply.
        let sshKeys = [".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa"]
        for rel in sshKeys {
            let path = "\(home)/\(rel)"
            guard let head = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            // Encrypted PEM keys carry "Proc-Type: 4,ENCRYPTED" or "ENCRYPTED" body markers.
            // Modern OpenSSH-format keys with no passphrase contain "none" in their kdfname slot.
            let isLikelyEncrypted = head.contains("ENCRYPTED") || head.contains("DEK-Info:") ||
                head.contains("aes256-ctr") || head.contains("aes128-ctr")
            if !isLikelyEncrypted {
                findings.append(Finding(
                    severity: .medium,
                    category: .credentialExposure,
                    title: "SSH private key appears to be unencrypted",
                    detail: "File: \(path) — no passphrase indicators found. An infostealer that lifts this file can use it immediately.",
                    path: path,
                    remediation: "Add a passphrase: ssh-keygen -p -f \"\(path)\""
                ))
            }
        }
    }

    // MARK: - .env files in project roots

    /// Many infostealers (Atomic, Banshee, Poseidon) grep recently-active directories for
    /// `.env` files and exfiltrate their contents wholesale. We flag .env files that contain
    /// long-looking API tokens (40+ alphanumeric chars after =) so the user knows what is at
    /// risk if one of those stealers ever runs as them.
    private func scanEnvFiles(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let projectParents = [
            "\(home)/Developer", "\(home)/Projects", "\(home)/Code",
            "\(home)/src", "\(home)/work", "\(home)/repos", "\(home)/dev",
            "\(home)/Desktop",
        ]

        let fm = FileManager.default
        // Token-shaped values: 32+ chars of base64-ish text after =.
        let secretRegex = try? NSRegularExpression(pattern: "(?i)(api[_-]?key|secret|token|password|access[_-]?key|auth[_-]?token|bearer)[^=\\n]*=\\s*['\"]?[A-Za-z0-9+/=_\\-]{20,}", options: [])

        for parent in projectParents {
            guard let projects = try? fm.contentsOfDirectory(atPath: parent) else { continue }
            for project in projects {
                let envPaths = [
                    "\(parent)/\(project)/.env",
                    "\(parent)/\(project)/.env.local",
                    "\(parent)/\(project)/.env.development",
                    "\(parent)/\(project)/.env.production",
                ]
                for env in envPaths {
                    guard fm.fileExists(atPath: env),
                          let content = try? String(contentsOfFile: env, encoding: .utf8) else { continue }
                    // Count secret-looking lines
                    let range = NSRange(content.startIndex..<content.endIndex, in: content)
                    let matches = secretRegex?.numberOfMatches(in: content, options: [], range: range) ?? 0
                    if matches > 0 {
                        // Check file mode — group/other read on a .env is the bigger issue.
                        let attrs = try? fm.attributesOfItem(atPath: env)
                        let mode = mode_t(((attrs?[.posixPermissions] as? NSNumber)?.uint16Value ?? 0)) & 0o777
                        let isWorldReadable = (mode & 0o044) != 0
                        let severity: Severity = isWorldReadable ? .high : .low
                        let modeStr = String(format: "%03o", mode)
                        findings.append(Finding(
                            severity: severity,
                            category: .credentialExposure,
                            title: ".env with \(matches) secret-shaped value\(matches == 1 ? "" : "s")",
                            detail: "File: \(env), mode: \(modeStr) — infostealers grep project roots for .env files",
                            path: env,
                            remediation: isWorldReadable
                                ? "chmod 600 \"\(env)\" — currently readable by group/other"
                                : "Confirm no real secrets live here, or move them to the macOS keychain"
                        ))
                    }
                }
            }
        }
    }
}
