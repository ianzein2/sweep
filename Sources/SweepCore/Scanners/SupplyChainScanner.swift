import Foundation

/// Detects compromised developer toolchains and malicious package-manager hooks.
/// Supply-chain attacks via npm/pip/cargo/brew have become a primary delivery vector
/// for macOS infostealers (BeaverTail, InvisibleFerret, ContagiousInterview) since late 2024:
/// the dropper rarely arrives as a signed app — it arrives as a "lifecycle script" or
/// "build script" that runs the moment a developer installs an innocuous-looking package.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []
        let home = ShellRunner.realUserHome

        progress?.update("scanning npm postinstall hooks")
        scanNpmLifecycleScripts(home: home, findings: &findings, errors: &errors)

        progress?.update("scanning Python entry points / pip caches")
        scanPythonPackages(home: home, findings: &findings, errors: &errors)

        progress?.update("scanning Cargo build scripts")
        scanCargoBuildScripts(home: home, findings: &findings, errors: &errors)

        progress?.update("scanning Homebrew taps")
        scanHomebrewTaps(home: home, findings: &findings, errors: &errors)

        progress?.update("scanning .npmrc / .pypirc credential leakage")
        scanPackageManagerConfig(home: home, findings: &findings, errors: &errors)

        progress?.update("scanning shell history for ClickFix patterns")
        scanShellHistoryForClickFix(home: home, findings: &findings, errors: &errors)

        progress?.update("scanning ~/.docker config / credential helpers")
        scanDockerConfig(home: home, findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - npm / pnpm / yarn lifecycle hooks
    //
    // The dominant pattern across BeaverTail, InvisibleFerret, and recent typosquats is a
    // `package.json` lifecycle script (`postinstall`, `preinstall`, `prepare`) that pipes a
    // curl/wget into a shell or `node -e`. The package itself is innocuous; the hook does the work.

    private let npmLifecycleKeys: [String] = [
        "preinstall", "install", "postinstall", "prepare", "prepublish", "postpublish",
    ]

    private let npmSuspiciousPatterns: [(needle: String, why: String)] = [
        ("curl ", "downloads code at install time"),
        ("wget ", "downloads code at install time"),
        ("| sh", "pipes downloaded data into a shell"),
        ("| bash", "pipes downloaded data into a shell"),
        ("| zsh", "pipes downloaded data into a shell"),
        ("eval(", "evaluates dynamic code at install time"),
        ("Function(", "evaluates dynamic code at install time"),
        ("Buffer.from(", "Base64 / hex payload decoding"),
        ("require('child_process')", "spawns external commands at install"),
        ("child_process", "spawns external commands at install"),
        ("\\x", "hex-encoded payload (obfuscation)"),
        ("atob(", "Base64-decoded payload"),
        ("/tmp/", "drops files to a world-writable temp directory"),
        ("base64 -d", "decodes a hidden payload at install"),
        ("base64 --decode", "decodes a hidden payload at install"),
        ("nslookup", "DNS-based exfiltration / C2 lookup"),
    ]

    private func scanNpmLifecycleScripts(home: String, findings: inout [Finding], errors: inout [String]) {
        // Look in the project node_modules trees most commonly hit by attacks. We deliberately
        // do not walk arbitrary user code — there's no quick way to know which `package.json` files
        // were just installed vs. authored by the user.
        let roots = [
            "\(home)/node_modules",
            "\(home)/.npm",                 // npm cache (includes _cacache and _logs)
            "\(home)/.pnpm-store",
            "\(home)/Library/Caches/Yarn",
        ]

        let fm = FileManager.default
        var inspected = 0
        let cap = 4_000   // bound the scan so the worst case stays under a few seconds

        for root in roots {
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if inspected >= cap { break }
                if enumerator.level > 6 { continue }
                guard url.lastPathComponent == "package.json" else { continue }
                guard let attrs = try? url.resourceValues(forKeys: [.fileSizeKey]),
                      let size = attrs.fileSize, size < 500_000 else { continue }
                guard let data = try? Data(contentsOf: url),
                      let pkg = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
                inspected += 1

                guard let scripts = pkg["scripts"] as? [String: String] else { continue }
                let name = (pkg["name"] as? String) ?? url.deletingLastPathComponent().lastPathComponent
                let version = (pkg["version"] as? String) ?? "?"

                for key in npmLifecycleKeys {
                    guard let script = scripts[key] else { continue }
                    for pattern in npmSuspiciousPatterns where script.contains(pattern.needle) {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "Suspicious npm \"\(key)\" hook in \(name)@\(version)",
                            detail: "Script: \(truncate(script, 160)) — \(pattern.why)",
                            path: url.path,
                            remediation: "Pin or remove this dependency, then `npm cache clean --force`. Investigate what the hook ran."
                        ))
                        break  // one finding per hook is enough
                    }
                }
            }
            if inspected >= cap { break }
        }
    }

    // MARK: - Python / pip
    //
    // pip packages can run arbitrary code via `setup.py`, `setup.cfg` `cmdclass`, or PEP-517
    // `pyproject.toml` build backends. We can't safely import them, but we can grep the cached
    // artifacts for the same obvious IOCs we look for in npm.

    private func scanPythonPackages(home: String, findings: inout [Finding], errors: inout [String]) {
        let roots = [
            "\(home)/Library/Caches/pip",
            "\(home)/.cache/pip",
            "\(home)/.local/lib",         // pip --user installs
        ]
        let fm = FileManager.default
        var inspected = 0
        let cap = 2_000

        for root in roots {
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.fileSizeKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if inspected >= cap { break }
                if enumerator.level > 8 { continue }
                let last = url.lastPathComponent
                guard last == "setup.py" || last == "setup.cfg" || last == "pyproject.toml" else { continue }
                guard let attrs = try? url.resourceValues(forKeys: [.fileSizeKey]),
                      let size = attrs.fileSize, size < 300_000 else { continue }
                guard let content = try? String(contentsOf: url, encoding: .utf8) else { continue }
                inspected += 1

                let lower = content.lowercased()
                let bad: [(needle: String, why: String)] = [
                    ("urllib.request.urlopen", "fetches a URL at install time"),
                    ("requests.get(", "fetches a URL at install time"),
                    ("os.system(", "shells out at install time"),
                    ("subprocess.popen", "shells out at install time"),
                    ("subprocess.call", "shells out at install time"),
                    ("subprocess.run", "shells out at install time"),
                    ("exec(", "executes dynamically-generated code"),
                    ("eval(", "executes dynamically-generated code"),
                    ("base64.b64decode", "Base64 payload decoding"),
                    ("codecs.decode", "encoded payload decoding"),
                ]
                for pattern in bad where lower.contains(pattern.needle) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Suspicious code in Python package install script",
                        detail: "\(last) — \(pattern.why)",
                        path: url.path,
                        remediation: "Audit the dependency. Consider `pip cache purge` and reinstalling from a vetted index."
                    ))
                    break
                }
            }
            if inspected >= cap { break }
        }
    }

    // MARK: - Cargo build scripts
    //
    // Rust crates can include a `build.rs` that runs at compile time. A handful of supply-chain
    // attacks in 2024-2025 used this to drop stage-2 binaries on developer machines.

    private func scanCargoBuildScripts(home: String, findings: inout [Finding], errors: inout [String]) {
        let registry = "\(home)/.cargo/registry/src"
        let fm = FileManager.default
        guard fm.fileExists(atPath: registry) else { return }
        guard let enumerator = fm.enumerator(
            at: URL(fileURLWithPath: registry),
            includingPropertiesForKeys: [.fileSizeKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else { return }

        var inspected = 0
        let cap = 1_500
        for case let url as URL in enumerator {
            if inspected >= cap { break }
            if enumerator.level > 5 { continue }
            guard url.lastPathComponent == "build.rs" else { continue }
            guard let attrs = try? url.resourceValues(forKeys: [.fileSizeKey]),
                  let size = attrs.fileSize, size < 200_000 else { continue }
            guard let content = try? String(contentsOf: url, encoding: .utf8) else { continue }
            inspected += 1

            let suspicious = [
                ("Command::new(\"/bin/sh\"", "spawns a shell at build time"),
                ("Command::new(\"/bin/bash\"", "spawns a shell at build time"),
                ("Command::new(\"curl\"", "downloads at build time"),
                ("Command::new(\"wget\"", "downloads at build time"),
                ("reqwest::", "downloads at build time"),
                ("std::process::Command", "spawns a child process at build time"),
                ("Base64", "Base64 payload decoding"),
            ]
            for pattern in suspicious where content.contains(pattern.0) {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Suspicious Cargo build.rs",
                    detail: "Crate path: \(url.deletingLastPathComponent().lastPathComponent) — \(pattern.1)",
                    path: url.path,
                    remediation: "Pin / remove the crate, then `cargo clean` and rebuild from a vetted source."
                ))
                break
            }
        }
    }

    // MARK: - Homebrew taps
    //
    // A "tap" is essentially a third-party formula repository. A malicious tap can ship a
    // formula whose `install` block runs arbitrary code as the user. The legitimate Homebrew
    // namespace is `homebrew/*` — anything else is third-party.

    private func scanHomebrewTaps(home: String, findings: inout [Finding], errors: inout [String]) {
        // Modern Homebrew stores taps under <prefix>/Library/Taps/<user>/homebrew-<name>
        let prefixes = [
            "/opt/homebrew/Library/Taps",          // Apple Silicon default
            "/usr/local/Homebrew/Library/Taps",    // Intel default
        ]
        let fm = FileManager.default
        for prefix in prefixes {
            guard fm.fileExists(atPath: prefix),
                  let users = try? fm.contentsOfDirectory(atPath: prefix) else { continue }
            for user in users where !user.hasPrefix(".") && user != "homebrew" {
                // Any non-`homebrew` directory is a third-party tap owner — list them.
                let userDir = "\(prefix)/\(user)"
                guard let taps = try? fm.contentsOfDirectory(atPath: userDir) else { continue }
                for tap in taps where tap.hasPrefix("homebrew-") {
                    let tapDir = "\(userDir)/\(tap)"
                    let tapName = "\(user)/\(tap.replacingOccurrences(of: "homebrew-", with: ""))"

                    // Surface that the tap exists at a low severity so the user sees it,
                    // then escalate to high if any formula looks malicious.
                    var formulaIssues: [String] = []
                    if let enumerator = fm.enumerator(atPath: tapDir) {
                        for case let entry as String in enumerator {
                            guard entry.hasSuffix(".rb") else { continue }
                            let full = "\(tapDir)/\(entry)"
                            guard let body = try? String(contentsOfFile: full, encoding: .utf8) else { continue }
                            let lower = body.lowercased()
                            if lower.contains("curl ") && (lower.contains("| sh") || lower.contains("| bash")) {
                                formulaIssues.append("\(entry): curl piped into shell")
                            } else if lower.contains("eval(") {
                                formulaIssues.append("\(entry): eval()")
                            } else if lower.contains("base64 -d") || lower.contains("base64 --decode") {
                                formulaIssues.append("\(entry): base64 decoded payload")
                            }
                        }
                    }

                    if !formulaIssues.isEmpty {
                        let preview = formulaIssues.prefix(3).joined(separator: "; ")
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "Homebrew tap with suspicious formula(e): \(tapName)",
                            detail: preview,
                            path: tapDir,
                            remediation: "Untap if unrecognized: brew untap \(tapName)"
                        ))
                    } else {
                        findings.append(Finding(
                            severity: .low, category: .suspiciousFile,
                            title: "Third-party Homebrew tap installed: \(tapName)",
                            detail: "Third-party taps run arbitrary code at install time. Make sure you trust this source.",
                            path: tapDir,
                            remediation: "Untap if unused: brew untap \(tapName)"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Package manager config

    private func scanPackageManagerConfig(home: String, findings: inout [Finding], errors: inout [String]) {
        // .npmrc tokens / .pypirc passwords kept in plaintext are a classic post-stealer
        // target: if a stealer ran here, it'll have copied these files verbatim. Warn the user
        // so they can rotate, and warn if a non-default registry is configured (typosquat vector).
        let creds: [(path: String, label: String, tokenIndicators: [String])] = [
            ("\(home)/.npmrc", ".npmrc", ["_authToken", "_auth=", "_password"]),
            ("\(home)/.yarnrc", ".yarnrc", ["_authToken", "npmAuthToken"]),
            ("\(home)/.yarnrc.yml", ".yarnrc.yml", ["npmAuthToken"]),
            ("\(home)/.pypirc", ".pypirc", ["password"]),
            ("\(home)/.netrc", ".netrc", ["password"]),
        ]
        for entry in creds {
            guard let content = try? String(contentsOfFile: entry.path, encoding: .utf8) else { continue }
            let lower = content.lowercased()
            for indicator in entry.tokenIndicators where lower.contains(indicator.lowercased()) {
                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "Plaintext credentials in \(entry.label)",
                    detail: "\(entry.label) contains a \(indicator) entry — anything that read this file has your registry token.",
                    path: entry.path,
                    remediation: "Rotate the token at the registry and prefer keychain-backed credential helpers."
                ))
                break
            }
            // Custom registry can be the dropper's typosquat trick (e.g. registry pointing to attacker host).
            if entry.label == ".npmrc" {
                for line in content.split(separator: "\n") {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    if trimmed.hasPrefix("registry=") || trimmed.contains("registry =") {
                        let value = trimmed.split(separator: "=", maxSplits: 1).last.map(String.init) ?? ""
                        let v = value.trimmingCharacters(in: .whitespaces)
                        if !v.contains("registry.npmjs.org") && !v.contains("registry.yarnpkg.com") &&
                           !v.contains("npm.pkg.github.com") && !v.isEmpty {
                            findings.append(Finding(
                                severity: .medium, category: .networkActivity,
                                title: "Non-standard npm registry configured",
                                detail: "registry: \(v) — a malicious mirror can replace any package you install.",
                                path: entry.path,
                                remediation: "Verify you intentionally set this registry. If not, remove the line."
                            ))
                            break
                        }
                    }
                }
            }
        }
    }

    // MARK: - "ClickFix" pattern in shell history
    //
    // The 2024-2025 ClickFix campaigns trick users into pasting a "fix" command into Terminal —
    // typically a curl|bash one-liner. Detecting these in shell history is one of the few
    // post-hoc indicators after the script has run and cleaned up.

    private let clickFixPatterns: [(needle: String, why: String)] = [
        ("curl -s ", "curl -s | sh dropper pattern"),
        ("curl -sL ", "curl -sL | sh dropper pattern"),
        ("curl -fsSL ", "curl -fsSL | sh dropper pattern"),
        ("wget -q ", "wget -q | sh dropper pattern"),
        ("osascript -e ", "AppleScript invoked from terminal (often password-stealing)"),
        ("echo \"$(curl", "shell substitution + curl (obfuscated dropper)"),
        ("bash <(curl", "process substitution dropper"),
        ("sudo -k && sudo ", "force re-auth then sudo — typical ClickFix pattern"),
    ]

    private func scanShellHistoryForClickFix(home: String, findings: inout [Finding], errors: inout [String]) {
        // We check the last ~2000 lines of common history files. Older entries are less actionable
        // and history files can grow large.
        let histories = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.history",
            "\(home)/.local/share/fish/fish_history",
        ]
        let fm = FileManager.default
        for path in histories {
            // Skip absurdly large history files — read at most ~2MB which holds tens of
            // thousands of commands.
            if let attrs = try? fm.attributesOfItem(atPath: path),
               let size = attrs[.size] as? Int, size > 2_000_000 { continue }
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let lines = content.split(separator: "\n").suffix(2000)
            var seen = Set<String>()
            for raw in lines {
                let line = String(raw)
                // zsh extended history starts each line with `: <ts>:0;<cmd>` — strip the prefix.
                let cmd: String = {
                    if line.hasPrefix(": "), let semi = line.firstIndex(of: ";") {
                        return String(line[line.index(after: semi)...])
                    }
                    return line
                }()
                for pattern in clickFixPatterns where cmd.contains(pattern.needle) {
                    let key = "\(pattern.needle)|\(cmd.prefix(80))"
                    if seen.contains(key) { continue }
                    seen.insert(key)

                    // Pipe-into-shell is the strong signal; plain `curl -s` is informational.
                    let pipedToShell = cmd.contains("| sh") || cmd.contains("|sh") ||
                                       cmd.contains("| bash") || cmd.contains("|bash") ||
                                       cmd.contains("| zsh") || cmd.contains("|zsh")
                    let severity: Severity = pipedToShell ? .high : .medium

                    findings.append(Finding(
                        severity: severity, category: .suspiciousProcess,
                        title: pipedToShell
                            ? "Pipe-to-shell command in \(URL(fileURLWithPath: path).lastPathComponent)"
                            : "Suspicious one-liner in \(URL(fileURLWithPath: path).lastPathComponent)",
                        detail: "Command: \(truncate(cmd, 140)) — \(pattern.why)",
                        path: path,
                        remediation: pipedToShell
                            ? "If you don't remember running this, treat the Mac as potentially compromised: rotate credentials and inspect Persistence and Process scans."
                            : "Review this command. ClickFix campaigns trick users into running these via 'paste this to fix your browser' prompts."
                    ))
                    break
                }
            }
        }
    }

    // MARK: - Docker credential helpers
    //
    // ~/.docker/config.json can pin a `credsStore` to an arbitrary binary that's invoked
    // every time `docker login` runs — a low-noise persistence/credential-theft vector.

    private func scanDockerConfig(home: String, findings: inout [Finding], errors: inout [String]) {
        let path = "\(home)/.docker/config.json"
        guard let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        let credsStore = json["credsStore"] as? String
        let credHelpers = json["credHelpers"] as? [String: String] ?? [:]

        // The Docker docs only list a small set of legitimate built-ins.
        let trustedHelpers: Set<String> = ["osxkeychain", "desktop", "secretservice", "wincred", "pass"]

        if let store = credsStore, !trustedHelpers.contains(store) {
            findings.append(Finding(
                severity: .high, category: .suspiciousFile,
                title: "Docker credsStore points to a non-standard helper",
                detail: "credsStore: \(store) — Docker runs `docker-credential-\(store)` every login.",
                path: path,
                remediation: "Set credsStore to \"osxkeychain\" in ~/.docker/config.json, then investigate the docker-credential-\(store) binary."
            ))
        }
        for (registry, helper) in credHelpers where !trustedHelpers.contains(helper) {
            findings.append(Finding(
                severity: .medium, category: .suspiciousFile,
                title: "Docker credHelpers entry uses non-standard binary",
                detail: "\(registry) → docker-credential-\(helper)",
                path: path,
                remediation: "Remove the entry if not expected: edit ~/.docker/config.json"
            ))
        }
    }

    // MARK: - Helpers

    private func truncate(_ s: String, _ max: Int) -> String {
        if s.count <= max { return s }
        return String(s.prefix(max)) + "…"
    }
}
