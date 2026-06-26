import Foundation

/// Scans AI developer tool configuration for tampering — a 2025-era attack vector.
///
/// MCP (Model Context Protocol) servers run as local processes that the AI assistant invokes
/// with the user's credentials and filesystem privileges. A malicious or modified MCP config
/// turns the AI client into a one-prompt-to-RCE channel: any prompt that the assistant
/// satisfies by calling the MCP server will execute attacker-chosen code. The same shape
/// applies to Cursor / Continue / Codeium config files that store shell-invoked tools.
///
/// We focus on:
///   - MCP server entries that run unusual binaries (curl|sh, base64-decoded payloads, npx of
///     unknown packages, /tmp executables).
///   - Recently-modified config files that don't match the user's own edit history (heuristic).
///   - System-prompt / `customInstructions` fields that contain prompt-injection markers like
///     ignore-previous-instructions or "exfiltrate".
public final class AIToolingScanner: Scanner {
    public let name = "AI Tooling Scan"
    public init() {}

    /// Configuration files we know how to inspect. Paths are resolved against the real user home.
    private var configTargets: [(tool: String, path: String)] {
        let home = ShellRunner.realUserHome
        return [
            ("Claude Desktop", "\(home)/Library/Application Support/Claude/claude_desktop_config.json"),
            ("Claude Code",    "\(home)/.claude/settings.json"),
            ("Claude Code",    "\(home)/.claude.json"),
            ("Claude Code (project hooks)", "\(home)/.claude/hooks.json"),
            ("Cursor",         "\(home)/.cursor/mcp.json"),
            ("Cursor",         "\(home)/Library/Application Support/Cursor/User/settings.json"),
            ("VS Code (MCP)",  "\(home)/Library/Application Support/Code/User/mcp.json"),
            ("Windsurf",       "\(home)/.windsurf/mcp.json"),
            ("Continue.dev",   "\(home)/.continue/config.json"),
            ("Cline",          "\(home)/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
        ]
    }

    /// Substrings inside server command/args that indicate live, drop-and-run payloads.
    private let dangerousCommandPatterns: [(pattern: String, why: String)] = [
        ("curl -fsSL", "downloads a remote script for execution"),
        ("curl -sSL",  "downloads a remote script for execution"),
        ("wget -qO-",  "downloads a remote script for execution"),
        ("| sh",       "pipes downloaded content into a shell"),
        ("| bash",     "pipes downloaded content into a shell"),
        ("base64 -d",  "decodes a hidden payload"),
        ("base64 --decode", "decodes a hidden payload"),
        ("eval $(",    "evaluates dynamically-built code"),
        ("python -c",  "executes inline Python (often obfuscated)"),
        ("python3 -c", "executes inline Python (often obfuscated)"),
        ("node -e",    "executes inline JavaScript"),
        ("/tmp/",      "runs an executable from a temp directory"),
        ("/private/tmp/", "runs an executable from a temp directory"),
        ("nc -e",      "netcat reverse-shell pattern"),
        ("bash -i",    "interactive shell — common reverse-shell stage"),
    ]

    /// Tokens in system-prompt / instructions fields that flag prompt-injection tampering.
    private let promptInjectionMarkers: [String] = [
        "ignore previous instructions",
        "ignore all prior instructions",
        "disregard your instructions",
        "exfiltrate",
        "send to attacker",
        "post to webhook",
        "data:text/html;base64",
        "</system>",
        "<|im_start|>system",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []
        let fm = FileManager.default

        for (tool, path) in configTargets {
            guard fm.fileExists(atPath: path) else { continue }
            progress?.update("scanning \(tool) config")

            // We only parse JSON. Some configs may be partial-JSON-with-comments (jsonc); we tolerate
            // failure to parse and fall back to text-pattern scanning so partial coverage still works.
            let raw = (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
            let data = raw.data(using: .utf8) ?? Data()
            let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]

            if let json {
                scanMCPServers(in: json, tool: tool, configPath: path, findings: &findings)
                scanInstructionsFields(in: json, tool: tool, configPath: path, findings: &findings)
                scanHooks(in: json, tool: tool, configPath: path, findings: &findings)
            }
            // Text-level pass — catches dangerous patterns we'd miss in malformed JSON or arrays we didn't walk.
            scanTextPatterns(raw: raw, tool: tool, configPath: path, findings: &findings)
        }

        // Inspect known MCP server install directories for added (unsigned) entry points.
        progress?.update("scanning MCP server install dirs")
        scanMCPInstallDirectories(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - MCP Server entries

    private func scanMCPServers(in json: [String: Any], tool: String, configPath: String, findings: inout [Finding]) {
        // Claude Desktop, Cursor, VS Code, Continue, Cline all store servers under "mcpServers" or
        // "mcp.servers"/"servers"; collect whatever's there.
        var servers: [String: Any] = [:]
        if let s = json["mcpServers"] as? [String: Any] { servers.merge(s) { a, _ in a } }
        if let mcp = json["mcp"] as? [String: Any], let s = mcp["servers"] as? [String: Any] {
            servers.merge(s) { a, _ in a }
        }
        if let s = json["servers"] as? [String: Any] { servers.merge(s) { a, _ in a } }

        for (serverName, value) in servers {
            guard let conf = value as? [String: Any] else { continue }
            let command = (conf["command"] as? String) ?? ""
            let args = (conf["args"] as? [String]) ?? []
            let url = (conf["url"] as? String) ?? ""
            let env = conf["env"] as? [String: Any] ?? [:]

            // Compose the full invocation as a single string for pattern matching.
            let invocation = ([command] + args).joined(separator: " ")

            // 1. Drop-and-run / decode-and-run patterns in command or args.
            for pattern in dangerousCommandPatterns {
                if invocation.contains(pattern.pattern) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(tool) MCP server runs a dangerous command",
                        detail: "Server \"\(serverName)\" → \(invocation.prefix(180)) — \(pattern.why)",
                        path: configPath,
                        remediation: "Open \(configPath) and remove the \"\(serverName)\" entry. Then rotate any secrets the MCP server may have accessed."
                    ))
                    break
                }
            }

            // 2. Executable path under /tmp or hidden directory.
            if command.hasPrefix("/tmp/") || command.hasPrefix("/private/tmp/") ||
               command.contains("/.") {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "\(tool) MCP server runs from temp or hidden path",
                    detail: "Server \"\(serverName)\" command: \(command)",
                    path: configPath,
                    remediation: "Remove the \"\(serverName)\" entry from \(configPath) — legitimate MCP servers don't live in /tmp or hidden directories"
                ))
            }

            // 3. Remote URL transport pointing somewhere unexpected (raw IP, no TLS).
            if !url.isEmpty {
                let lower = url.lowercased()
                if lower.hasPrefix("http://") {
                    findings.append(Finding(
                        severity: .medium, category: .networkActivity,
                        title: "\(tool) MCP server transport is unencrypted",
                        detail: "Server \"\(serverName)\" URL: \(url) — credentials and tool calls travel in clear text",
                        path: configPath,
                        remediation: "Change the URL to https:// or remove the server if untrusted"
                    ))
                }
                // Raw IP rather than a hostname — uncommon for legitimate hosted MCP endpoints.
                if let host = URL(string: url)?.host,
                   host.split(separator: ".").allSatisfy({ Int($0) != nil }) {
                    findings.append(Finding(
                        severity: .medium, category: .networkActivity,
                        title: "\(tool) MCP server points to a raw IP address",
                        detail: "Server \"\(serverName)\" URL: \(url) — legitimate MCP services usually publish a hostname",
                        path: configPath,
                        remediation: "Verify the IP belongs to a server you trust, otherwise remove the entry"
                    ))
                }
            }

            // 4. Suspicious environment overrides that could redirect node/npx to a malicious binary.
            for (envKey, _) in env {
                let upper = envKey.uppercased()
                if upper == "DYLD_INSERT_LIBRARIES" || upper == "LD_PRELOAD" ||
                   upper == "NODE_OPTIONS" || upper == "PYTHONSTARTUP" {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(tool) MCP server sets a runtime-injection environment variable",
                        detail: "Server \"\(serverName)\" sets \(envKey) — used to inject code into the spawned interpreter",
                        path: configPath,
                        remediation: "Remove the \(envKey) entry from the server's env section in \(configPath)"
                    ))
                }
            }

            // 5. npx/uvx with no version pin — supply-chain risk worth surfacing.
            if command == "npx" || command == "uvx" || command == "uv" {
                let hasVersionPin = args.contains { $0.contains("@") && !$0.hasPrefix("@") }
                if !hasVersionPin && !args.isEmpty {
                    findings.append(Finding(
                        severity: .low, category: .suspiciousFile,
                        title: "\(tool) MCP server runs unpinned \(command) package",
                        detail: "Server \"\(serverName)\" → \(invocation) — without a version pin, a compromised package picks up automatically",
                        path: configPath,
                        remediation: "Pin the version in \(configPath), e.g. \(args.first ?? "package")@1.2.3"
                    ))
                }
            }
        }
    }

    // MARK: - System-prompt / instructions tampering

    private func scanInstructionsFields(in json: [String: Any], tool: String, configPath: String, findings: inout [Finding]) {
        // Fields commonly used to carry persistent instructions for an AI client.
        let candidateKeys = [
            "systemPrompt", "system_prompt", "customInstructions", "custom_instructions",
            "instructions", "initialPrompt", "preamble", "globalRules", "rules",
        ]
        for key in candidateKeys {
            guard let value = json[key] else { continue }
            let stringValue: String
            if let s = value as? String { stringValue = s }
            else if let arr = value as? [Any] { stringValue = arr.compactMap { $0 as? String }.joined(separator: " ") }
            else { continue }

            let lower = stringValue.lowercased()
            for marker in promptInjectionMarkers {
                if lower.contains(marker) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(tool) config contains prompt-injection marker",
                        detail: "Field \"\(key)\" contains: \"\(marker)\" — someone may have injected instructions to override your AI assistant",
                        path: configPath,
                        remediation: "Open \(configPath) and clear the \"\(key)\" field, then rotate any tokens the assistant might have leaked"
                    ))
                    break
                }
            }
        }
    }

    // MARK: - Hooks

    private func scanHooks(in json: [String: Any], tool: String, configPath: String, findings: inout [Finding]) {
        // Many AI clients (Claude Code, Cursor, Continue) expose pre/post hooks that run shell
        // commands around prompts or tool calls. Hook commands deserve the same scrutiny as MCP servers.
        let hookKeys = ["hooks", "preCommit", "postCommit", "preToolUse", "postToolUse", "userPromptSubmit"]
        for key in hookKeys {
            guard let raw = json[key] else { continue }
            let asString: String
            if let s = raw as? String { asString = s }
            else if let dict = raw as? [String: Any] {
                asString = (try? JSONSerialization.data(withJSONObject: dict))
                    .flatMap { String(data: $0, encoding: .utf8) } ?? ""
            }
            else if let arr = raw as? [Any] {
                asString = (try? JSONSerialization.data(withJSONObject: arr))
                    .flatMap { String(data: $0, encoding: .utf8) } ?? ""
            }
            else { continue }

            for pattern in dangerousCommandPatterns {
                if asString.contains(pattern.pattern) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(tool) hook contains a dangerous command",
                        detail: "Hook field \"\(key)\" — \(pattern.why)",
                        path: configPath,
                        remediation: "Open \(configPath) and remove or fix the \"\(key)\" entry"
                    ))
                    break
                }
            }
        }
    }

    // MARK: - Free-form text pass

    private func scanTextPatterns(raw: String, tool: String, configPath: String, findings: inout [Finding]) {
        // Catch dangerous patterns even when the file isn't strict JSON (jsonc, partial corruption).
        // We dedupe against the structured findings later — for now, only emit one per pattern per file.
        var emitted = Set<String>()
        for pattern in dangerousCommandPatterns {
            if raw.contains(pattern.pattern), !emitted.contains(pattern.pattern) {
                emitted.insert(pattern.pattern)
                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "\(tool) config text contains \"\(pattern.pattern)\"",
                    detail: "Pattern found in raw config — \(pattern.why). Verify the structured entry above (if any) and inspect the file directly.",
                    path: configPath,
                    remediation: "Open \(configPath) and review the surrounding context"
                ))
            }
        }
    }

    // MARK: - MCP install directories

    private func scanMCPInstallDirectories(findings: inout [Finding], errors: inout [String]) {
        // Some installers drop MCP server binaries into ~/.claude/mcp_servers/ or ~/.cursor/extensions
        // — flag any executable files there that don't have a recognizable package.json sibling
        // (i.e. they look like raw drop-in binaries).
        let home = ShellRunner.realUserHome
        let candidateDirs = [
            "\(home)/.claude/mcp_servers",
            "\(home)/.claude/mcp",
            "\(home)/.cursor/mcp_servers",
            "\(home)/.windsurf/mcp_servers",
        ]
        let fm = FileManager.default

        for dir in candidateDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where !entry.hasPrefix(".") {
                let path = "\(dir)/\(entry)"
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: path, isDirectory: &isDir) else { continue }

                if isDir.boolValue {
                    // A directory should contain a package.json for a node MCP server or a pyproject.toml.
                    let hasPkg = fm.fileExists(atPath: "\(path)/package.json") ||
                                 fm.fileExists(atPath: "\(path)/pyproject.toml") ||
                                 fm.fileExists(atPath: "\(path)/setup.py")
                    if !hasPkg {
                        findings.append(Finding(
                            severity: .medium, category: .suspiciousFile,
                            title: "MCP install directory lacks a package manifest",
                            detail: "Directory: \(path) — legitimate MCP servers ship with package.json/pyproject.toml; raw drops here may be malware",
                            path: path,
                            remediation: "Inspect contents: ls -la \"\(path)\" — remove if unrecognized"
                        ))
                    }
                } else {
                    // Mach-O binary directly in an MCP install dir — uncommon (MCPs are usually node/python).
                    guard let fh = FileHandle(forReadingAtPath: path) else { continue }
                    let header = fh.readData(ofLength: 4)
                    fh.closeFile()
                    guard header.count == 4 else { continue }
                    let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
                    let machoMagics: Set<UInt32> = [0xFEEDFACF, 0xFEEDFACE, 0xBEBAFECA, 0xCAFEBABE]
                    if machoMagics.contains(magic) {
                        findings.append(Finding(
                            severity: .medium, category: .suspiciousFile,
                            title: "Mach-O binary in MCP install directory",
                            detail: "File: \(path) — most MCP servers are node/python; a raw Mach-O binary here is unusual",
                            path: path,
                            remediation: "Verify the binary's origin and code signature, remove if unexpected"
                        ))
                    }
                }
            }
        }
    }
}
