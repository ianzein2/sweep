import Foundation

/// Detects 2024-2025 threats that don't fit cleanly into the older signature-based scanners:
///   - DPRK "Contagious Interview" indicators (BeaverTail / InvisibleFerret artifacts)
///   - Reverse tunnels / dev tunnels left running (ngrok, cloudflared, localtunnel, frp, chisel)
///   - Crypto wallet exposure: unencrypted wallet files in default user paths
///   - macOS that no longer receives security updates
///   - Known-malicious npm packages installed under the user's home
public final class ModernThreatScanner: Scanner {
    public let name = "Modern Threats Scan"
    public init() {}

    // Subset of the npm "Contagious Interview" / Lazarus packages flagged by security researchers
    // throughout 2024-2025. We match on package directory names under node_modules.
    private let malicousNpmPackages: Set<String> = [
        // 2023-2024 Lazarus npm wave
        "ip-checker", "is-window-open", "is-window-busy",
        "node-ifconfig", "node-clean-html", "tslib-dom",
        "react-html-table", "node-temp-folder",
        // 2024 "Contagious Interview" expansion (selected)
        "execution-time-async", "node-stream-zip-fixed", "react-icon-package",
        "test-execution-sdk", "snyk-node-fetch", "node-lifecycle-async",
        "ws-paginator", "react-dnd-text", "node-html-zip",
        // 2024-2025 npm token-grabbing / BeaverTail-style droppers
        "qcloud-sso", "harthat-api", "harthat-hash",
        "rtk-logger", "config-cors-helper",
    ]

    // Long-running tunnels / reverse proxies. Legitimate for developers, but worth surfacing —
    // attackers regularly install these to maintain off-band access to compromised Macs.
    private let tunnelBinaries: [(name: String, label: String, severity: Severity)] = [
        ("ngrok",       "ngrok tunnel",        .medium),
        ("cloudflared", "Cloudflare Tunnel",   .medium),
        ("lt",          "localtunnel",         .medium),
        ("localtunnel", "localtunnel",         .medium),
        ("frpc",        "frp client (reverse proxy)", .medium),
        ("frps",        "frp server",          .medium),
        ("chisel",      "chisel tunnel",       .high),     // rarely legitimate
        ("gost",        "GOST tunnel",         .high),     // commonly abused
        ("serveo",      "serveo tunnel",       .medium),
        ("rsockstun",   "rsockstun",           .high),     // pentest reverse SOCKS
    ]

    // Best-known macOS releases that still receive security updates. macOS gives ~3 years of
    // patches for the current and previous two major versions. Anything older is essentially
    // unpatched against modern CVEs and should be called out.
    //
    // Update this table when a new major macOS ships. Currently: Sequoia (15), Sonoma (14),
    // Ventura (13) are supported; Monterey (12) and below are not.
    private let supportedMajorVersions: Set<Int> = [13, 14, 15, 26]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking macOS version")
        checkMacOSVersion(findings: &findings)

        progress?.update("checking for Contagious Interview artifacts")
        checkContagiousInterviewIndicators(findings: &findings)

        progress?.update("scanning node_modules for malicious npm packages")
        checkMaliciousNpmPackages(findings: &findings)

        progress?.update("checking for active reverse tunnels")
        checkRunningTunnels(findings: &findings, errors: &errors)

        progress?.update("scanning crypto wallet directories")
        checkCryptoWalletExposure(findings: &findings)

        progress?.update("checking AI assistant credential paths")
        checkAIAssistantCredentials(findings: &findings)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - macOS version

    private func checkMacOSVersion(findings: inout [Finding]) {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let major = version.majorVersion

        if !supportedMajorVersions.contains(major) && major < 26 {
            findings.append(Finding(
                severity: .high, category: .systemIntegrity,
                title: "macOS \(major).\(version.minorVersion) is no longer receiving security updates",
                detail: "Apple typically patches only the current and previous two major macOS releases. macOS \(major) is outside that window — unpatched kernel and Safari CVEs will accumulate.",
                path: nil,
                remediation: "Upgrade macOS: System Settings > General > Software Update"
            ))
        }
    }

    // MARK: - DPRK "Contagious Interview" indicators (BeaverTail / InvisibleFerret)

    private func checkContagiousInterviewIndicators(findings: inout [Finding]) {
        // Researchers (Palo Alto Unit 42, Group-IB) document recurring paths used by the
        // BeaverTail JS dropper and the Python InvisibleFerret stage-2 backdoor.
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Stage-1 / stage-2 staging directories — these names recur across campaigns.
        let stagingPaths = [
            "\(home)/.n2",
            "\(home)/.npl",
            "\(home)/.bus",
            "\(home)/.sysenv",
            "\(home)/.pyp",
            "\(home)/.pay",
            "\(home)/.cl",
            "\(home)/.fonts/.fontconfig",
        ]
        for path in stagingPaths where fm.fileExists(atPath: path) {
            findings.append(Finding(
                severity: .high, category: .suspiciousFile,
                title: "DPRK 'Contagious Interview' staging directory present",
                detail: "Path \(path) matches the BeaverTail / InvisibleFerret malware family used in fake-interview campaigns targeting developers",
                path: path,
                remediation: "Inspect contents, then remove: rm -rf \"\(path)\" — and rotate browser, npm, and wallet credentials"
            ))
        }

        // Python interpreter dropped under user home (used to run InvisibleFerret offline)
        let pythonDrop = "\(home)/.pyp/python3"
        if fm.fileExists(atPath: pythonDrop) {
            findings.append(Finding(
                severity: .high, category: .suspiciousFile,
                title: "Standalone Python interpreter under ~/.pyp",
                detail: "Self-contained python3 in ~/.pyp is the documented InvisibleFerret execution path",
                path: pythonDrop,
                remediation: "Inspect and remove if not deliberately installed: rm -rf \"\(home)/.pyp\""
            ))
        }
    }

    // MARK: - Malicious npm packages

    private func checkMaliciousNpmPackages(findings: inout [Finding]) {
        // We don't try to walk every node_modules in every project — that's unbounded.
        // We do check well-known global locations and the user's npm cache, which is where
        // most "I tested a job-interview project" infections land.
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        var rootsToCheck: [String] = [
            "\(home)/node_modules",
            "\(home)/.npm-global/lib/node_modules",
            "\(home)/.npm/_cacache/content-v2",
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
        ]

        // Also include the top-level node_modules of dev project directories that commonly
        // appear in interview-prep scenarios (Desktop / Downloads / Documents).
        for parent in ["Desktop", "Downloads", "Documents", "Developer", "Projects", "work"] {
            let parentPath = "\(home)/\(parent)"
            guard let entries = try? fm.contentsOfDirectory(atPath: parentPath) else { continue }
            for entry in entries.prefix(50) {
                let nm = "\(parentPath)/\(entry)/node_modules"
                if fm.fileExists(atPath: nm) {
                    rootsToCheck.append(nm)
                }
            }
        }

        for root in rootsToCheck {
            guard fm.fileExists(atPath: root),
                  let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for entry in entries {
                if malicousNpmPackages.contains(entry) {
                    let fullPath = "\(root)/\(entry)"
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Known-malicious npm package installed: \(entry)",
                        detail: "Package \"\(entry)\" was flagged by researchers as part of the 2024-2025 npm supply-chain wave (Lazarus / Contagious Interview)",
                        path: fullPath,
                        remediation: "Remove the package, audit the parent project, rotate any tokens that may have been exfiltrated: rm -rf \"\(fullPath)\""
                    ))
                }
            }
        }
    }

    // MARK: - Reverse tunnels / dev tunnels

    private func checkRunningTunnels(findings: inout [Finding], errors: inout [String]) {
        // We use a single ps invocation — listing every command is much cheaper than per-tool greps.
        let ps = ShellRunner.run("/bin/ps", arguments: ["-axo", "pid,comm"], timeout: 5)
        guard ps.success else {
            errors.append("ps failed: \(ps.stderr)")
            return
        }

        // Build a list of (pid, basename) tuples. Apple's "comm" column is just the executable
        // basename, which is exactly what we want for matching tunnel binary names.
        let rows: [(pid: String, comm: String)] = ps.stdout.split(separator: "\n").compactMap { line in
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 2 else { return nil }
            return (pid: String(parts[0]), comm: String(parts[1]))
        }

        for tool in tunnelBinaries {
            // Match the basename of the executable, case-insensitively. Avoid substring matches
            // like "ngrok" inside "gongrokunsky" by anchoring on equality.
            let matches = rows.filter { row in
                let base = (row.comm as NSString).lastPathComponent.lowercased()
                return base == tool.name || base.hasPrefix(tool.name + ".")
            }
            if matches.isEmpty { continue }

            let pids = matches.map { $0.pid }.prefix(3).joined(separator: ", ")
            findings.append(Finding(
                severity: tool.severity, category: .networkActivity,
                title: "\(tool.label) is running on this Mac",
                detail: "Process: \(tool.name), PID(s): \(pids). Reverse tunnels keep an inbound channel open to this Mac — verify the tunnel is yours.",
                path: nil,
                remediation: "If you didn't start this tunnel, kill it: kill \(matches.first!.pid) — and investigate how it was installed"
            ))
        }

        // SSH reverse tunnels: ssh -R or autossh holding a remote-forwarded port open
        let sshTunnels = ShellRunner.run("/bin/ps", arguments: ["-axo", "pid,command"], timeout: 5)
        if sshTunnels.success {
            for line in sshTunnels.stdout.split(separator: "\n") {
                let s = String(line)
                if (s.contains(" ssh ") || s.contains(" autossh ")) &&
                   (s.contains(" -R ") || s.contains(" -fNR") || s.contains(" -NR")) {
                    let pid = s.split(separator: " ", omittingEmptySubsequences: true).first.map { String($0) } ?? "?"
                    findings.append(Finding(
                        severity: .medium, category: .networkActivity,
                        title: "SSH reverse tunnel is active",
                        detail: "ssh -R forwards a port from a remote server back into this Mac. Command: \(String(s.prefix(160)))",
                        path: nil,
                        remediation: "If unexpected, kill it: kill \(pid). Reverse SSH tunnels are a classic remote-access backdoor."
                    ))
                    // One finding per ssh -R is enough — keep the list short
                    break
                }
            }
        }
    }

    // MARK: - Crypto wallet exposure

    private func checkCryptoWalletExposure(findings: inout [Finding]) {
        // We don't read the wallets — we just note the standard paths so the user knows what
        // attackers will look for. Stealers in 2024-2025 specifically target these directories.
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        let wallets: [(name: String, paths: [String])] = [
            ("Electrum",              ["\(home)/.electrum/wallets"]),
            ("Exodus",                ["\(home)/Library/Application Support/Exodus"]),
            ("Atomic Wallet",         ["\(home)/Library/Application Support/atomic"]),
            ("Bitcoin Core",          ["\(home)/Library/Application Support/Bitcoin"]),
            ("Litecoin Core",         ["\(home)/Library/Application Support/Litecoin"]),
            ("Ledger Live",           ["\(home)/Library/Application Support/Ledger Live"]),
            ("Coinomi",               ["\(home)/Library/Application Support/Coinomi"]),
            ("Wasabi",                ["\(home)/Library/Application Support/WalletWasabi"]),
            ("Daedalus / Yoroi",      ["\(home)/Library/Application Support/Daedalus Mainnet"]),
            ("MetaMask (browser)",    [
                "\(home)/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
                "\(home)/Library/Application Support/Brave Software/Brave-Browser/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
            ]),
        ]

        var presentWallets: [String] = []
        for wallet in wallets {
            for path in wallet.paths where fm.fileExists(atPath: path) {
                presentWallets.append(wallet.name)
                break
            }
        }

        if !presentWallets.isEmpty {
            findings.append(Finding(
                severity: .low, category: .suspiciousFile,
                title: "Crypto wallet data present on this Mac",
                detail: "Detected: \(presentWallets.joined(separator: ", ")). 2024-2025 macOS stealers (Atomic, Banshee, Cthulhu, BeaverTail) specifically target these paths.",
                path: nil,
                remediation: "Ensure FileVault is on, never paste seed phrases anywhere, and consider moving long-term holdings to a hardware wallet."
            ))
        }
    }

    // MARK: - AI assistant credential exposure

    private func checkAIAssistantCredentials(findings: inout [Finding]) {
        // 2024-2025 stealers have started shipping with parsers for the local config files of
        // popular LLM and dev tools. These store live API tokens in plaintext; an attacker who
        // reads them gets straight-line access to the user's accounts and billing.
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        let credentialFiles: [(label: String, path: String)] = [
            ("Anthropic / Claude Code config",    "\(home)/.claude/config.json"),
            ("Anthropic / Claude Code credentials", "\(home)/.claude/credentials.json"),
            ("OpenAI CLI config",                 "\(home)/.config/openai/auth.json"),
            ("OpenAI ChatGPT key file",           "\(home)/.openai_api_key"),
            ("Cursor IDE auth",                   "\(home)/Library/Application Support/Cursor/User/globalStorage/auth.json"),
            ("GitHub Copilot host token",         "\(home)/.config/github-copilot/hosts.json"),
            ("Hugging Face token",                "\(home)/.cache/huggingface/token"),
            ("Replicate API key",                 "\(home)/.replicate"),
            ("AWS shared credentials",            "\(home)/.aws/credentials"),
            ("Google Cloud ADC",                  "\(home)/.config/gcloud/application_default_credentials.json"),
            ("npm auth token",                    "\(home)/.npmrc"),
            ("PyPI / twine credentials",          "\(home)/.pypirc"),
        ]

        var exposed: [String] = []
        for entry in credentialFiles {
            guard fm.fileExists(atPath: entry.path) else { continue }
            // Flag anything that's group/world readable — those are the easy wins for a stealer.
            if let attrs = try? fm.attributesOfItem(atPath: entry.path),
               let perms = attrs[.posixPermissions] as? Int,
               (perms & 0o077) != 0 {
                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "Credential file readable by other users: \(entry.label)",
                    detail: "Permissions \(String(perms, radix: 8)) on \(entry.path) — any local process can read this token",
                    path: entry.path,
                    remediation: "Tighten: chmod 600 \"\(entry.path)\""
                ))
            }
            exposed.append(entry.label)
        }

        if exposed.count >= 4 {
            // A lot of plaintext credentials in one place is the perfect target for an infostealer.
            findings.append(Finding(
                severity: .low, category: .suspiciousFile,
                title: "Multiple plaintext credential files in home directory (\(exposed.count) found)",
                detail: "Sweep located \(exposed.prefix(6).joined(separator: ", "))\(exposed.count > 6 ? ", …" : ""). 2024-2025 macOS stealers iterate these paths to grab live tokens.",
                path: nil,
                remediation: "Consider moving long-lived keys into the macOS Keychain or 1Password, and use short-lived tokens where the tool supports them."
            ))
        }
    }
}
