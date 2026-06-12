import Foundation

public final class BrowserScanner: Scanner {
    public let name = "Browser Extension Scan"
    public init() {}

    // Recent campaigns (late 2024 / 2025) have weaponized VSCode/Cursor marketplace extensions
    // to steal credentials, drain crypto wallets, and inject backdoors. Keywords mirror
    // reported malicious extension families and IOCs.
    private let suspiciousEditorExtKeywords: [String] = [
        "crypto-wallet-stealer", "solidity-debugger-plus", "prettier-vscode-plus",
        "ethers-vscode-helper", "web3-helpers", "solana-wallet-helper",
        "discord-token-grabber", "chrome-cookie-stealer", "browser-data-sync",
    ]

    private let dangerousEditorExtPatterns: [String] = [
        "keylog", "stealer", "grabber", "exfil", "payload", "reverse-shell",
    ]

    // Extensions that are well-known and safe
    private let trustedExtensionIds: Set<String> = [
        // Password managers
        "aeblfdkhhhdcdjpifhhbdiojplfjncoa", // 1Password
        "aomjjhallfgjeglblehebfpbcfeobpgk", // 1Password (legacy)
        "nngceckbapebfimnlniiiahkandclblb", // Bitwarden
        "hdokiejnpimakedhajhdlcegeplioahd", // LastPass
        "oboonakemofpalcgghocfoadofidjkkk", // KeePassXC
        // Ad blockers
        "cjpalhdlnbpafiamejdnhcphjbkeiagm", // uBlock Origin
        "gighmmpiobklfepjocnamgkkbiglidom", // AdBlock
        "pkehgijcmpdhfbdbbnkijodmdjhbjlgp", // Privacy Badger
        // AI assistants
        "fcoeoabgfenejglbffodgkkbkcdhcgfn", // Claude
        // Productivity
        "liecbddmkiiihnedobmlmillhodjkdmb", // Loom
        "aapbdbdomjkkjkaonfhkkikfgjllcleb", // Google Translate
        "efaidnbmnnnibpcajpcglclefindmkaj", // Adobe Acrobat
        // Dev tools
        "fmkadmapgofadopljbjfkapdkoienihi", // React DevTools
        "nhdogjmejiglipccpnnnanhbledajbpd", // Vue DevTools
        "bfnaelmomeimhlpmgjnjophhpkkoljpa", // Angular DevTools
        "lmhkpmbekcpmknklioeibfkpmmfibljd", // Redux DevTools
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        // 1. Chrome extensions
        progress?.update("scanning Chrome extensions")
        scanChromeExtensions(findings: &findings, errors: &errors)

        // 2. Safari extensions (via pluginkit)
        progress?.update("scanning Safari extensions")
        scanSafariExtensions(findings: &findings, errors: &errors)

        // 3. Firefox extensions
        progress?.update("scanning Firefox extensions")
        scanFirefoxExtensions(findings: &findings, errors: &errors)

        // 4. Code editor extensions (VSCode / Cursor / Windsurf) — recently targeted by
        //    malicious marketplace extensions that steal cookies, keychains, and wallets.
        progress?.update("scanning code editor extensions")
        scanEditorExtensions(findings: &findings, errors: &errors)

        // 5. MCP (Model Context Protocol) server configs — a 2025 attack surface for AI tools
        //    (Claude Desktop, Cursor, Windsurf, Continue, etc.). A malicious MCP server runs on
        //    every AI launch with full user privileges.
        progress?.update("scanning MCP server configs")
        scanMCPServers(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Chrome Extensions

    private struct ChromeExtensionInfo {
        let extId: String
        let name: String
        let permStrings: [String]
        let hasDangerousPerms: Bool
        let hasAllUrls: Bool
        let hasKeyboardInput: Bool
        let isSpyLike: Bool
        var profiles: [String]
        let browserName: String
        let extDir: String
    }

    private func resolveExtensionName(_ name: String, extVersionDir: String) -> String {
        // If name is a localization placeholder like __MSG_extName__, resolve it
        guard name.hasPrefix("__MSG_") && name.hasSuffix("__") else { return name }
        let key = String(name.dropFirst(6).dropLast(2))
        let fm = FileManager.default
        // Try en, en_US, then first available locale
        for locale in ["en", "en_US"] {
            let messagesPath = "\(extVersionDir)/_locales/\(locale)/messages.json"
            if let data = fm.contents(atPath: messagesPath),
               let messages = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let entry = messages[key] as? [String: Any],
               let message = entry["message"] as? String {
                return message
            }
        }
        // Try first available locale
        let localesDir = "\(extVersionDir)/_locales"
        if let locales = try? fm.contentsOfDirectory(atPath: localesDir),
           let first = locales.first {
            let messagesPath = "\(localesDir)/\(first)/messages.json"
            if let data = fm.contents(atPath: messagesPath),
               let messages = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let entry = messages[key] as? [String: Any],
               let message = entry["message"] as? String {
                return message
            }
        }
        return name
    }

    private func scanChromeExtensions(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let chromePaths = [
            "\(home)/Library/Application Support/Google/Chrome",
            "\(home)/Library/Application Support/Brave Software/Brave-Browser",
            "\(home)/Library/Application Support/Microsoft Edge",
        ]

        // Collect extensions across all profiles, deduplicate by (browser, extId)
        var seenExtensions: [String: ChromeExtensionInfo] = [:] // key: "browserName:extId"

        for browserPath in chromePaths {
            let browserName = browserPath.contains("Chrome") ? "Chrome" :
                              browserPath.contains("Brave") ? "Brave" : "Edge"

            let fm = FileManager.default
            guard fm.fileExists(atPath: browserPath),
                  let profiles = try? fm.contentsOfDirectory(atPath: browserPath) else { continue }

            for profile in profiles {
                let extPath = "\(browserPath)/\(profile)/Extensions"
                guard fm.fileExists(atPath: extPath),
                      let extensions = try? fm.contentsOfDirectory(atPath: extPath) else { continue }

                for extId in extensions {
                    if trustedExtensionIds.contains(extId) { continue }

                    let dedupeKey = "\(browserName):\(extId)"

                    // If already seen, just add the profile name
                    if seenExtensions[dedupeKey] != nil {
                        seenExtensions[dedupeKey]!.profiles.append(profile)
                        continue
                    }

                    let extDir = "\(extPath)/\(extId)"
                    guard let versions = try? fm.contentsOfDirectory(atPath: extDir),
                          let latest = versions.sorted().last else { continue }

                    let extVersionDir = "\(extDir)/\(latest)"
                    let manifestPath = "\(extVersionDir)/manifest.json"
                    guard let data = fm.contents(atPath: manifestPath),
                          let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

                    var name = manifest["name"] as? String ?? "Unknown"
                    name = resolveExtensionName(name, extVersionDir: extVersionDir)

                    let permissions = (manifest["permissions"] as? [Any]) ?? []
                    let hostPermissions = (manifest["host_permissions"] as? [String]) ?? []

                    let permStrings = permissions.compactMap { $0 as? String }

                    let hasDangerousPerms = permStrings.contains(where: { perm in
                        ["webRequest", "webRequestBlocking", "debugger", "nativeMessaging",
                         "desktopCapture", "tabCapture", "pageCapture"].contains(perm)
                    })
                    let hasAllUrls = permStrings.contains("<all_urls>") ||
                        hostPermissions.contains("<all_urls>") ||
                        hostPermissions.contains("*://*/*")
                    let hasKeyboardInput = permStrings.contains("input")

                    let nameLC = name.lowercased()
                    let isSpyLike = ["spy", "keylog", "monitor", "track", "surveillance", "stealth"]
                        .contains(where: { nameLC.contains($0) })

                    seenExtensions[dedupeKey] = ChromeExtensionInfo(
                        extId: extId, name: name, permStrings: permStrings,
                        hasDangerousPerms: hasDangerousPerms, hasAllUrls: hasAllUrls,
                        hasKeyboardInput: hasKeyboardInput, isSpyLike: isSpyLike,
                        profiles: [profile], browserName: browserName, extDir: extDir
                    )
                }
            }
        }

        // Now emit one finding per unique extension
        for (_, ext) in seenExtensions {
            let profileNote = ext.profiles.count > 1
                ? " (in \(ext.profiles.count) profiles)"
                : ""

            if ext.isSpyLike || ext.hasKeyboardInput {
                findings.append(Finding(
                    severity: .high, category: .keylogging,
                    title: "\(ext.browserName) extension with spy-like name/permissions",
                    detail: "Extension: \(ext.name), ID: \(ext.extId)\(profileNote), Permissions: \(ext.permStrings.joined(separator: ", "))",
                    path: ext.extDir,
                    remediation: "Remove in \(ext.browserName) > Extensions (chrome://extensions)"
                ))
            } else if ext.hasDangerousPerms && ext.hasAllUrls {
                findings.append(Finding(
                    severity: .medium, category: .permission,
                    title: "\(ext.browserName) extension with broad permissions",
                    detail: "Extension: \(ext.name), ID: \(ext.extId)\(profileNote) — can intercept all web traffic",
                    path: ext.extDir,
                    remediation: "Verify this extension is legitimate in \(ext.browserName) > Extensions"
                ))
            }
        }
    }

    // MARK: - Safari Extensions

    private func scanSafariExtensions(findings: inout [Finding], errors: inout [String]) {
        // Use pluginkit to list Safari extensions
        let result = ShellRunner.run("/usr/bin/pluginkit", arguments: [
            "-mAp", "-vvv", "-p", "com.apple.Safari.extension"
        ], timeout: 10)

        guard result.success && !result.stdout.isEmpty else { return }

        let lines = result.stdout.split(separator: "\n")
        for line in lines {
            let lineStr = String(line).trimmingCharacters(in: .whitespaces)
            guard !lineStr.isEmpty else { continue }

            // Skip Apple extensions
            if lineStr.contains("com.apple.") { continue }

            let nameLC = lineStr.lowercased()
            let isSpyLike = ["spy", "keylog", "monitor", "surveillance", "stealth"]
                .contains(where: { nameLC.contains($0) })

            if isSpyLike {
                findings.append(Finding(
                    severity: .high, category: .keylogging,
                    title: "Safari extension with suspicious name",
                    detail: "Extension: \(lineStr)",
                    path: nil,
                    remediation: "Review in Safari > Settings > Extensions"
                ))
            }
        }
    }

    // MARK: - Firefox Extensions

    private func scanFirefoxExtensions(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let firefoxPath = "\(home)/Library/Application Support/Firefox/Profiles"
        let fm = FileManager.default

        guard fm.fileExists(atPath: firefoxPath),
              let profiles = try? fm.contentsOfDirectory(atPath: firefoxPath) else { return }

        for profile in profiles {
            let addonsPath = "\(firefoxPath)/\(profile)/extensions.json"
            guard let data = fm.contents(atPath: addonsPath),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let addons = json["addons"] as? [[String: Any]] else { continue }

            for addon in addons {
                let name = addon["defaultLocale"] as? [String: Any]
                let addonName = (name?["name"] as? String) ?? (addon["id"] as? String) ?? "Unknown"
                let id = addon["id"] as? String ?? ""
                let permissions = addon["userPermissions"] as? [String: Any]
                let perms = permissions?["permissions"] as? [String] ?? []
                let origins = permissions?["origins"] as? [String] ?? []

                // Skip Mozilla's own
                if id.hasSuffix("@mozilla.org") || id.hasSuffix("@mozilla.com") { continue }

                let nameLC = addonName.lowercased()
                let isSpyLike = ["spy", "keylog", "monitor", "track", "surveillance", "stealth"]
                    .contains(where: { nameLC.contains($0) })
                let hasAllUrls = origins.contains("<all_urls>") || origins.contains("*://*/*")

                if isSpyLike {
                    findings.append(Finding(
                        severity: .high, category: .keylogging,
                        title: "Firefox extension with suspicious name",
                        detail: "Extension: \(addonName), ID: \(id)",
                        path: addonsPath,
                        remediation: "Remove in Firefox > Add-ons (about:addons)"
                    ))
                } else if hasAllUrls && perms.contains(where: { ["webRequest", "webRequestBlocking"].contains($0) }) {
                    findings.append(Finding(
                        severity: .medium, category: .permission,
                        title: "Firefox extension with broad permissions",
                        detail: "Extension: \(addonName), ID: \(id) — can intercept all web traffic",
                        path: addonsPath,
                        remediation: "Verify this extension in Firefox > Add-ons"
                    ))
                }
            }
        }
    }

    // MARK: - Code Editor Extensions (VSCode, Cursor, Windsurf, etc.)

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

            for entry in entries {
                // VSCode-style extensions live in "publisher.name-version" directories
                guard !entry.hasPrefix(".") else { continue }
                let extPath = "\(extDir)/\(entry)"
                let packagePath = "\(extPath)/package.json"

                guard let data = fm.contents(atPath: packagePath),
                      let pkg = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

                let publisher = (pkg["publisher"] as? String) ?? "unknown"
                let displayName = (pkg["displayName"] as? String) ?? (pkg["name"] as? String) ?? entry
                let extId = "\(publisher).\(pkg["name"] as? String ?? "")"
                let combined = "\(displayName) \(extId) \(entry)".lowercased()

                // Direct keyword match against known malicious families
                if let kw = suspiciousEditorExtKeywords.first(where: { combined.contains($0) }) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(editorName) extension matches known malicious family",
                        detail: "Extension: \(displayName) (\(extId)) — matched pattern \"\(kw)\"",
                        path: extPath,
                        remediation: "Remove this extension in \(editorName) and investigate your keychain/wallet activity"
                    ))
                    continue
                }

                // Name-based heuristic
                if let kw = dangerousEditorExtPatterns.first(where: { combined.contains($0) }) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(editorName) extension with spy-like name",
                        detail: "Extension: \(displayName) (\(extId)) — name contains \"\(kw)\"",
                        path: extPath,
                        remediation: "Remove in \(editorName) > Extensions"
                    ))
                    continue
                }

                // Scan for suspicious runtime behaviors in the extension bundle
                let scriptResult = scanExtensionScripts(extPath: extPath)
                if scriptResult.hasRemoteExec || scriptResult.hasShellExec {
                    findings.append(Finding(
                        severity: scriptResult.hasRemoteExec ? .high : .medium,
                        category: .suspiciousFile,
                        title: "\(editorName) extension runs shell commands / remote code",
                        detail: "Extension: \(displayName) (\(extId))" +
                            (scriptResult.hasRemoteExec ? " — downloads and executes remote code" : "") +
                            (scriptResult.hasShellExec ? " — spawns child_process commands" : ""),
                        path: extPath,
                        remediation: "Review \(packagePath) and the extension's JS files. Remove if unexpected."
                    ))
                }
            }
        }
    }

    // MARK: - MCP Server Config Inspection

    /// MCP (Model Context Protocol) lets AI tools spawn local servers — a 2025-era attack vector
    /// where a malicious config makes the AI tool launch attacker-controlled binaries with the
    /// user's privileges on every startup. We inspect the JSON configs that all major AI tools share.
    private func scanMCPServers(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let configs: [(tool: String, path: String)] = [
            ("Claude Desktop",
             "\(home)/Library/Application Support/Claude/claude_desktop_config.json"),
            ("Cursor (user)", "\(home)/.cursor/mcp.json"),
            ("Cursor (global)", "\(home)/Library/Application Support/Cursor/User/mcp.json"),
            ("Windsurf", "\(home)/.codeium/windsurf/mcp_config.json"),
            ("Continue", "\(home)/.continue/config.json"),
            ("Cline", "\(home)/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
            ("Zed", "\(home)/.config/zed/settings.json"),
            ("Codex CLI", "\(home)/.codex/config.json"),
        ]

        let fm = FileManager.default
        for (tool, path) in configs {
            guard fm.fileExists(atPath: path),
                  let data = fm.contents(atPath: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            // Most configs nest servers under "mcpServers"; Continue uses "mcpServers" / "models";
            // Codex uses "mcp_servers"; Zed uses "context_servers".
            let serverContainers: [[String: Any]] = [
                json["mcpServers"] as? [String: Any],
                json["mcp_servers"] as? [String: Any],
                json["context_servers"] as? [String: Any],
            ].compactMap { $0 }

            for servers in serverContainers {
                for (serverName, rawDef) in servers {
                    guard let def = rawDef as? [String: Any] else { continue }
                    inspectMCPServer(tool: tool, configPath: path, serverName: serverName,
                                     def: def, findings: &findings)
                }
            }
        }
    }

    private func inspectMCPServer(tool: String, configPath: String, serverName: String,
                                  def: [String: Any], findings: inout [Finding]) {
        let command = (def["command"] as? String) ?? ""
        let args = (def["args"] as? [String])?.joined(separator: " ") ?? ""
        let url = (def["url"] as? String) ?? ""
        let env = def["env"] as? [String: Any] ?? [:]
        let combined = "\(command) \(args)".lowercased()

        // 1. Commands from temp / hidden paths — these should never be where a legitimate MCP server lives.
        let suspiciousPathPrefixes = ["/tmp/", "/private/tmp/", "/var/tmp/", "/dev/shm/"]
        let isFromTempDir = suspiciousPathPrefixes.contains { command.hasPrefix($0) }
        if isFromTempDir {
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "\(tool) MCP server runs binary from temp directory",
                detail: "Server: \"\(serverName)\" runs: \(command) \(args.prefix(80))",
                path: configPath,
                remediation: "Remove this entry from \(configPath) — legitimate MCP servers don't live in /tmp"
            ))
            return
        }

        if command.contains("/.") && !command.hasPrefix(".") {
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "\(tool) MCP server runs binary from hidden directory",
                detail: "Server: \"\(serverName)\" runs: \(command)",
                path: configPath,
                remediation: "Remove this entry from \(configPath) — binaries in hidden dirs are a strong spyware indicator"
            ))
            return
        }

        // 2. Stage-1 loader patterns: curl|bash, wget|sh, base64 decode + exec.
        // Pair-required to fire: token must appear and the line must also contain a shell
        // chain operator (|, ;, &&). That filters out benign args that happen to contain "curl".
        let loaderPatterns: [(String, String)] = [
            ("curl ", "downloads and executes remote code on every AI tool launch"),
            ("wget ", "downloads and executes remote code on every AI tool launch"),
            ("base64 -d", "decodes a hidden payload"),
            ("base64 --decode", "decodes a hidden payload"),
            ("eval(", "evaluates dynamic code"),
            ("exec(base64", "decodes and executes a hidden payload"),
        ]
        for (pattern, reason) in loaderPatterns {
            // For inherently dangerous patterns (eval(/exec(base64), the chain operator isn't required.
            let alwaysFire = pattern == "eval(" || pattern == "exec(base64"
            let hasChainOp = combined.contains("|") || combined.contains(";") || combined.contains("&&")
            if combined.contains(pattern) && (alwaysFire || hasChainOp) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "\(tool) MCP server contains stage-1 loader command",
                    detail: "Server: \"\(serverName)\" — \(reason) (\(String(combined.prefix(120))))",
                    path: configPath,
                    remediation: "Remove this entry from \(configPath) — review what was added to your AI tool config"
                ))
                return
            }
        }

        // 3. HTTP MCP transport pointing at a non-HTTPS or unfamiliar host — a malicious remote MCP
        //    server can return prompt-injection payloads that the AI then acts on with user privileges.
        if !url.isEmpty {
            let isPlainHTTP = url.lowercased().hasPrefix("http://")
            let lower = url.lowercased()
            let isLocalhost = lower.contains("://localhost") || lower.contains("://127.0.0.1") || lower.contains("://[::1]")
            if isPlainHTTP && !isLocalhost {
                findings.append(Finding(
                    severity: .high, category: .networkActivity,
                    title: "\(tool) MCP server uses plain HTTP transport",
                    detail: "Server: \"\(serverName)\" → \(url) — traffic and prompt-injection content can be tampered with in transit",
                    path: configPath,
                    remediation: "Switch to https:// or remove this entry from \(configPath)"
                ))
            }
        }

        // 4. Match the server's command against the known spyware database — a low-effort
        //    way to catch an attacker who pasted a stealer binary into the AI config.
        if let sig = SpywareSignature.match(processName: command) {
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "\(tool) MCP server matches known spyware: \(sig.name)",
                detail: "Server: \"\(serverName)\" runs: \(command)",
                path: configPath,
                remediation: "Remove from \(configPath) and remove \(sig.name)"
            ))
            return
        }

        // 5. Environment-variable exfil: storing real API keys/tokens in plaintext under env
        //    means a leaked config = leaked secrets. Surface this so users know to rotate.
        for (key, value) in env {
            guard let strVal = value as? String, !strVal.isEmpty else { continue }
            let keyUpper = key.uppercased()
            let isSecret = keyUpper.contains("KEY") || keyUpper.contains("TOKEN") ||
                           keyUpper.contains("SECRET") || keyUpper.contains("PASSWORD") ||
                           keyUpper.contains("API")
            // Heuristic: 20+ char alphanumeric-with-dashes string = a likely secret, not a placeholder.
            let looksLikeRealSecret = strVal.count >= 20 &&
                !strVal.contains("YOUR_") && !strVal.contains("<") && !strVal.contains("xxxxx")
            if isSecret && looksLikeRealSecret {
                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "\(tool) MCP config stores secret in plaintext",
                    detail: "Server: \"\(serverName)\" has env var \(key) — anyone with read access to this config can exfiltrate the secret",
                    path: configPath,
                    remediation: "Use a secrets manager or reference an environment variable instead of pasting the value"
                ))
                break  // one finding per server is enough
            }
        }
    }

    private struct EditorScriptScan {
        let hasRemoteExec: Bool
        let hasShellExec: Bool
    }

    private func scanExtensionScripts(extPath: String) -> EditorScriptScan {
        // Walk the top-level JS files for obvious IOCs. We intentionally cap depth/size so this
        // stays fast — we're looking for unobfuscated malicious patterns, not deep analysis.
        let fm = FileManager.default
        var hasRemoteExec = false
        var hasShellExec = false

        let candidatePaths = [
            "\(extPath)/extension.js",
            "\(extPath)/out/extension.js",
            "\(extPath)/dist/extension.js",
            "\(extPath)/src/extension.js",
        ]

        for path in candidatePaths {
            guard fm.fileExists(atPath: path) else { continue }
            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  let size = attrs[.size] as? Int, size < 5_000_000 else { continue }  // skip 5MB+ bundles
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            let lower = content.lowercased()
            // child_process.exec / execSync with a variable is a common stage-2 loader pattern.
            if lower.contains("child_process") &&
               (lower.contains(".exec(") || lower.contains(".execsync(") || lower.contains(".spawn(")) {
                hasShellExec = true
            }
            // http(s) GET + eval / execFile — the canonical drop-and-run.
            if (lower.contains("https.get") || lower.contains("http.get") || lower.contains("fetch(")) &&
               (lower.contains("eval(") || lower.contains("new function(") || lower.contains("vm.runin")) {
                hasRemoteExec = true
            }
        }

        return EditorScriptScan(hasRemoteExec: hasRemoteExec, hasShellExec: hasShellExec)
    }
}
