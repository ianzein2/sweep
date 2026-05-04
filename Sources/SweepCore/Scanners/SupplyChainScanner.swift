import Foundation

/// Detects supply-chain risks introduced by package managers and AI-tooling configurations.
/// Recent campaigns (2024-2025) increasingly arrive via:
///   - Malicious npm / pnpm / pip / RubyGems packages (Phylum, ReversingLabs, Aikido, GitGuardian)
///   - Compromised Homebrew formulas / non-official taps
///   - MCP (Model Context Protocol) server configs that launch arbitrary commands at AI-tool
///     startup (Cursor, Claude Desktop, Windsurf) — equivalent in blast radius to a LaunchAgent.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    /// npm packages publicly disclosed as malicious in 2024-2025 (Phylum, Socket, ReversingLabs,
    /// Aikido, GitGuardian, Snyk). Most have been removed from npm, but copies stay installed
    /// locally until the user runs `npm uninstall`.
    private let knownMaliciousNpm: Set<String> = [
        // Lazarus Contagious Interview campaign (Phylum 2023-2025) — fake interview projects
        // ship with these and they pull BeaverTail / InvisibleFerret.
        "passportjs-mock-strategy",
        "@types-deno",
        "json-pretty-format",
        "json-format-pretty",
        "node-hide-console-windows",
        "node-fetch-mock",
        "auth0-js-public",
        "express-fileupload-modal",
        // Solana / web3 wallet drainers
        "@solana/web3-helpers",
        "solana-transaction-toolkit",
        "anchor-spl-utils",
        "@solana-program/wallet-adapter-react",
        // Ethereum drainers
        "ethers-helper",
        "@ethereum/web3-helper",
        "web3-utils-helper",
        // Generic stealers / RATs distributed via npm
        "rspack-core-helper",
        "vue3-auto-import-helper",
        "ts-node-helper",
        "node-discord-rpc-extra",
        "discord-token-stealer",
    ]

    /// PyPI packages from recent typosquat / supply-chain reports.
    private let knownMaliciousPypi: Set<String> = [
        "colourama",                 // typosquat of "colorama"
        "djanga",                    // typosquat of "django"
        "request-helper",
        "requesys",
        "py-helpers-core",
        "pythonkafka",               // typosquat of kafka-python
        "snowflake-connector-python-helper",
        "dpython",
        "tensorflowy",               // typosquat of tensorflow
    ]

    /// Officially-blessed Homebrew taps. Anything else is third-party and worth surfacing.
    private let officialHomebrewTaps: Set<String> = [
        "homebrew/core",
        "homebrew/cask",
        "homebrew/bundle",
        "homebrew/services",
        "homebrew/command-not-found",
        "homebrew/test-bot",
        "homebrew/cask-fonts",
        "homebrew/cask-versions",
        "homebrew/cask-drivers",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking Homebrew taps")
        scanHomebrewTaps(findings: &findings, errors: &errors)

        progress?.update("checking global npm packages")
        scanGlobalNpm(findings: &findings, errors: &errors)

        progress?.update("checking installed pip packages")
        scanGlobalPip(findings: &findings, errors: &errors)

        progress?.update("checking AI tool MCP configurations")
        scanMCPConfigs(findings: &findings, errors: &errors)

        progress?.update("checking Cursor / VSCode workspace trust")
        scanWorkspaceTrust(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Homebrew Taps

    private func scanHomebrewTaps(findings: inout [Finding], errors: inout [String]) {
        // `brew tap` lists configured taps. A non-official tap can ship arbitrary formulas that
        // execute on `brew install`. Cracked-software / piracy taps are an established malware
        // distribution channel for macOS.
        let brewPaths = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        guard let brew = brewPaths.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            return
        }
        let result = ShellRunner.run(brew, arguments: ["tap"], timeout: 10)
        guard result.success else { return }

        let taps = result.stdout.split(separator: "\n")
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        for tap in taps {
            if officialHomebrewTaps.contains(tap) { continue }
            // Mark cracked-software / piracy taps as high — these are the most common vector for
            // bundled stealer DMGs.
            let lower = tap.lowercased()
            let looksPirated = ["crack", "warez", "nullsoft", "free-pro", "pirate", "appked"]
                .contains(where: { lower.contains($0) })
            findings.append(Finding(
                severity: looksPirated ? .high : .low,
                category: .suspiciousFile,
                title: looksPirated
                    ? "Homebrew tap matches known piracy / cracked-software pattern"
                    : "Third-party Homebrew tap installed",
                detail: "Tap: \(tap) — formulas in non-official taps run with the user's privileges and can install anything",
                path: nil,
                remediation: looksPirated
                    ? "Remove immediately: brew untap \(tap) — and audit anything installed from it"
                    : "Verify you trust the maintainer of this tap. Remove if unneeded: brew untap \(tap)"
            ))
        }
    }

    // MARK: - Global npm Packages

    private func scanGlobalNpm(findings: inout [Finding], errors: inout [String]) {
        // `npm ls -g --depth=0 --json` is the most reliable way to list global packages.
        // We check against a curated set of disclosed-malicious packages. Local node_modules
        // are out of scope (per-project) — globally-installed packages run anywhere on the system.
        let candidates = [
            "/opt/homebrew/bin/npm",
            "/usr/local/bin/npm",
            "/usr/bin/npm",
        ]
        guard let npm = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            return
        }
        let result = ShellRunner.run(npm, arguments: ["ls", "-g", "--depth=0", "--json"], timeout: 15)
        guard result.success || !result.stdout.isEmpty else { return }

        guard let data = result.stdout.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let deps = root["dependencies"] as? [String: Any] else {
            return
        }

        for (pkg, _) in deps {
            if knownMaliciousNpm.contains(pkg) {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Globally-installed npm package matches known-malicious list",
                    detail: "Package: \(pkg) — published research has identified this as malicious / typosquat",
                    path: nil,
                    remediation: "Uninstall immediately: npm uninstall -g \(pkg) — then audit your shell history for any code it ran"
                ))
            }
        }
    }

    // MARK: - Global pip Packages

    private func scanGlobalPip(findings: inout [Finding], errors: inout [String]) {
        // `pip3 list --format=json` works for the active Python. We also check pipx + Homebrew
        // Python installations because each has its own site-packages.
        let pipPaths = [
            "/opt/homebrew/bin/pip3",
            "/usr/local/bin/pip3",
            "/usr/bin/pip3",
        ]
        var checked = Set<String>()
        for pip in pipPaths where FileManager.default.fileExists(atPath: pip) {
            if checked.contains(pip) { continue }
            checked.insert(pip)
            let result = ShellRunner.run(pip, arguments: ["list", "--format=json", "--disable-pip-version-check"], timeout: 15)
            guard result.success else { continue }
            guard let data = result.stdout.data(using: .utf8),
                  let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { continue }

            for entry in arr {
                guard let name = entry["name"] as? String else { continue }
                if knownMaliciousPypi.contains(name.lowercased()) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Installed pip package matches known-malicious typosquat",
                        detail: "Package: \(name) (via \(pip)) — typosquat / supply-chain attack",
                        path: nil,
                        remediation: "Uninstall immediately: \(pip) uninstall -y \(name)"
                    ))
                }
            }
        }
    }

    // MARK: - MCP Server Configurations

    private func scanMCPConfigs(findings: inout [Finding], errors: inout [String]) {
        // Cursor, Claude Desktop, and Windsurf load MCP servers from JSON configs. Each entry can
        // run arbitrary commands at AI-tool startup. A malicious or compromised MCP entry is
        // effectively a LaunchAgent scoped to that AI tool. Surface entries that pipe shell
        // commands or fetch remote scripts.
        let home = ShellRunner.realUserHome
        let configPaths: [(String, String)] = [
            ("Cursor",         "\(home)/.cursor/mcp.json"),
            ("Cursor (legacy)", "\(home)/Library/Application Support/Cursor/User/mcp.json"),
            ("Claude Desktop", "\(home)/Library/Application Support/Claude/claude_desktop_config.json"),
            ("Windsurf",       "\(home)/.codeium/windsurf/mcp_config.json"),
            ("Zed",            "\(home)/.config/zed/settings.json"),
        ]

        let dangerousCommandFragments = [
            "curl ", "wget ", "| sh", "| bash", "/bin/sh", "base64 -d", "base64 --decode",
            "eval ", "python -c", "python3 -c", "node -e",
        ]

        for (tool, path) in configPaths {
            guard let data = FileManager.default.contents(atPath: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            // MCP configs put servers under `mcpServers` for Claude Desktop / Cursor.
            guard let servers = (json["mcpServers"] as? [String: Any]) ?? (json["mcp_servers"] as? [String: Any]) else {
                continue
            }

            for (serverName, raw) in servers {
                guard let entry = raw as? [String: Any] else { continue }
                let command = (entry["command"] as? String) ?? ""
                let args = (entry["args"] as? [String]) ?? []
                let combined = ([command] + args).joined(separator: " ")
                let lower = combined.lowercased()

                // Inline shell payloads embedded in MCP configs are the canonical malicious shape.
                if let badFragment = dangerousCommandFragments.first(where: { lower.contains($0) }) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "\(tool) MCP server runs an inline shell payload",
                        detail: "Server \"\(serverName)\" — command contains \"\(badFragment)\": \(String(combined.prefix(200)))",
                        path: path,
                        remediation: "Open \(path) and remove this MCP server entry. MCP servers run with your full user privileges every time the AI tool starts."
                    ))
                    continue
                }

                // Anything pointing at /tmp / hidden directories is suspicious as well.
                if command.hasPrefix("/tmp") || command.contains("/.") || command.hasPrefix("/private/tmp") ||
                   command.hasPrefix("/var/tmp") {
                    findings.append(Finding(
                        severity: .medium, category: .persistence,
                        title: "\(tool) MCP server runs from a temporary / hidden path",
                        detail: "Server \"\(serverName)\" — command: \(command)",
                        path: path,
                        remediation: "Verify this MCP server entry is intentional; remove if unrecognized"
                    ))
                }
            }
        }
    }

    // MARK: - Workspace Trust

    private func scanWorkspaceTrust(findings: inout [Finding], errors: inout [String]) {
        // VSCode / Cursor "workspace trust" gates whether an opened repository can run tasks
        // / debug configurations / extensions on open. Disabling it is convenient but means any
        // cloned repo (including malicious ones from cloned npm-script attacks) gets to execute.
        let home = ShellRunner.realUserHome
        let candidates: [(String, String)] = [
            ("VSCode",          "\(home)/Library/Application Support/Code/User/settings.json"),
            ("VSCode Insiders", "\(home)/Library/Application Support/Code - Insiders/User/settings.json"),
            ("Cursor",          "\(home)/Library/Application Support/Cursor/User/settings.json"),
            ("VSCodium",        "\(home)/Library/Application Support/VSCodium/User/settings.json"),
        ]

        for (editor, path) in candidates {
            guard let data = FileManager.default.contents(atPath: path) else { continue }
            // settings.json may contain comments / trailing commas — Foundation can't parse those.
            // Skip strict JSON parsing and look for the literal disabled flag instead.
            guard let raw = String(data: data, encoding: .utf8) else { continue }
            let normalized = raw.replacingOccurrences(of: " ", with: "")
                .replacingOccurrences(of: "\t", with: "")
                .replacingOccurrences(of: "\n", with: "")

            if normalized.contains("\"security.workspace.trust.enabled\":false") {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "\(editor) Workspace Trust is disabled",
                    detail: "security.workspace.trust.enabled = false — opening any folder will run its tasks/extensions automatically",
                    path: path,
                    remediation: "Re-enable: set \"security.workspace.trust.enabled\": true in \(path)"
                ))
            }
            if normalized.contains("\"security.workspace.trust.startupPrompt\":\"never\"") {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "\(editor) suppresses Workspace Trust prompt",
                    detail: "startupPrompt = never — you no longer see the trust dialog when opening unfamiliar folders",
                    path: path,
                    remediation: "Restore the prompt: remove \"security.workspace.trust.startupPrompt\" from settings.json"
                ))
            }
        }
    }
}
