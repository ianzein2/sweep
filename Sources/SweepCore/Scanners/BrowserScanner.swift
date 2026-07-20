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
        // DPRK "Contagious Interview" / BeaverTail lures — reported by Palo Alto Unit 42,
        // ReversingLabs, and Snyk through 2024-2025. Delivered inside coding-test repos as
        // trojanized npm packages, often loaded by malicious VSCode/Cursor extensions.
        "beavertail", "invisibleferret", "n2-agent",
        "colors-fun-cli", "js-cookie-cli", "chalk-hex", "chalk-npm-helper",
        "eslint-config-airbnb-security", "solidity-lint-fix",
        "web3-testing-plus", "solana-scaffold-tools",
        // Solidity / crypto-focused fake extensions from late-2025 Cursor marketplace campaign
        "ethereum-security-linter", "hardhat-helper-plus", "foundry-vscode-tools",
        // Fake AI-assistant impersonators seen mid-2025 (typosquats of legitimate names)
        "claude-code-helper", "cursor-ai-tools-plus", "copilot-plus-helper",
    ]

    private let dangerousEditorExtPatterns: [String] = [
        "keylog", "stealer", "grabber", "exfil", "payload", "reverse-shell",
        // Additions mirroring 2025-era malicious extension naming conventions
        "clipper", "seedphrase", "cookiegrab", "tokenstealer",
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

        // 5. Native messaging hosts — Chrome/Chromium/Firefox extensions can invoke arbitrary
        //    native binaries through JSON manifests registered in NativeMessagingHosts directories.
        //    A rogue manifest is a stealth persistence + exfil channel that leaves no LaunchAgent trace.
        progress?.update("scanning browser native messaging hosts")
        scanNativeMessagingHosts(findings: &findings, errors: &errors)

        // 6. Model-Context-Protocol servers — Cursor/Claude Desktop auto-start MCP server
        //    binaries on launch, effectively giving an editor extension a stable command channel
        //    into the user's environment. Malicious mcp.json entries are a 2025-era persistence vector.
        progress?.update("scanning MCP server configurations")
        scanMCPConfigurations(findings: &findings, errors: &errors)

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

    private struct EditorScriptScan {
        let hasRemoteExec: Bool
        let hasShellExec: Bool
    }

    // MARK: - Native Messaging Hosts (Chrome / Chromium / Firefox)

    /// Directories a browser will read a NativeMessagingHost manifest from. Each manifest is a
    /// JSON file whose `path` key points at an executable the browser will launch on demand from
    /// an extension. A rogue entry survives without any LaunchAgent trace.
    private var nativeMessagingHostDirs: [(browser: String, path: String)] {
        let home = ShellRunner.realUserHome
        return [
            ("Chrome",      "\(home)/Library/Application Support/Google/Chrome/NativeMessagingHosts"),
            ("Chrome (system)", "/Library/Google/Chrome/NativeMessagingHosts"),
            ("Chromium",    "\(home)/Library/Application Support/Chromium/NativeMessagingHosts"),
            ("Brave",       "\(home)/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            ("Edge",        "\(home)/Library/Application Support/Microsoft Edge/NativeMessagingHosts"),
            ("Edge (system)", "/Library/Microsoft/Edge/NativeMessagingHosts"),
            ("Arc",         "\(home)/Library/Application Support/Arc/User Data/NativeMessagingHosts"),
            ("Firefox",     "\(home)/Library/Application Support/Mozilla/NativeMessagingHosts"),
            ("Firefox (system)", "/Library/Application Support/Mozilla/NativeMessagingHosts"),
        ]
    }

    /// Common, well-known native messaging hosts published by trusted vendors.
    /// A manifest matching one of these names is left alone.
    private let trustedNativeHostNames: Set<String> = [
        "com.1password.1password",
        "com.1password.browser_support",
        "com.google.chrome.browsercloudmanagement",
        "com.google.chrome.messaging.autofill_private_api",
        "com.google.chrome_remote_desktop",
        "com.dashlane.dashlanephonefinderapp",
        "com.microsoft.browsercore",
        "com.microsoft.autoupdate.helper",
        "com.bitwarden.desktop",
        "com.grammarly.desktopintegrations",
        "org.keepassxc.keepassxc_browser",
        "org.dropbox.crx",
        "com.plasmohq.mv3.notify",
    ]

    private func scanNativeMessagingHosts(findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default

        for (browser, dir) in nativeMessagingHostDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where entry.hasSuffix(".json") {
                let manifestPath = "\(dir)/\(entry)"
                guard let data = fm.contents(atPath: manifestPath),
                      let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

                let hostName = (manifest["name"] as? String)
                    ?? String(entry.dropLast(".json".count))
                let execPath = manifest["path"] as? String
                let allowedExts = (manifest["allowed_extensions"] as? [String]) ?? []
                let allowedOrigins = (manifest["allowed_origins"] as? [String]) ?? []

                // A trusted vendor's host is fine — just skip.
                if trustedNativeHostNames.contains(hostName) { continue }

                // Flag: the executable path is missing or unresolvable.
                guard let exec = execPath, !exec.isEmpty else {
                    findings.append(Finding(
                        severity: .low, category: .suspiciousFile,
                        title: "\(browser) native messaging host with no executable path",
                        detail: "Host: \(hostName)",
                        path: manifestPath,
                        remediation: "Inspect \(manifestPath); orphaned host manifests are safe to remove"
                    ))
                    continue
                }

                // Absolute-path check + hidden-path check + tmp check
                let inTemp = exec.hasPrefix("/tmp/") || exec.hasPrefix("/private/tmp/") || exec.hasPrefix("/var/tmp/")
                let isHidden = exec.split(separator: "/").contains { $0.hasPrefix(".") }
                let execExists = fm.fileExists(atPath: exec)

                let trustedPrefixes = [
                    "/System/", "/usr/", "/Applications/",
                    "/Library/Application Support/",
                    "/opt/homebrew/", "/usr/local/",
                    "\(ShellRunner.realUserHome)/Applications/",
                    "\(ShellRunner.realUserHome)/Library/Application Support/",
                ]
                let isTrustedPath = trustedPrefixes.contains { exec.hasPrefix($0) }

                if inTemp || isHidden {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(browser) native messaging host points to hidden or temp path",
                        detail: "Host \(hostName) → \(exec) — extensions can invoke this binary at will",
                        path: manifestPath,
                        remediation: "Remove: rm \"\(manifestPath)\" (and inspect the referenced binary)"
                    ))
                    continue
                }

                if execExists && !isTrustedPath {
                    findings.append(Finding(
                        severity: .medium, category: .suspiciousFile,
                        title: "\(browser) native messaging host in unusual location",
                        detail: "Host \(hostName) → \(exec)" +
                            (allowedExts.isEmpty && allowedOrigins.isEmpty
                                ? " (no allowed_extensions restriction — any extension may invoke it)"
                                : ""),
                        path: manifestPath,
                        remediation: "Verify \(exec) is legitimate; remove the manifest if unexpected: rm \"\(manifestPath)\""
                    ))
                } else if !execExists {
                    findings.append(Finding(
                        severity: .low, category: .suspiciousFile,
                        title: "\(browser) native messaging host references missing binary",
                        detail: "Host \(hostName) → \(exec) (does not exist)",
                        path: manifestPath,
                        remediation: "Orphaned host manifest — safe to remove: rm \"\(manifestPath)\""
                    ))
                }
            }
        }
    }

    // MARK: - MCP server configurations (Claude Desktop, Cursor, Windsurf, etc.)

    /// MCP (Model Context Protocol) config files. Each entry launches a command with args on
    /// editor/app startup — effectively a per-app LaunchAgent that a malicious extension or a
    /// social-engineered config commit can weaponize.
    private var mcpConfigLocations: [(app: String, path: String)] {
        let home = ShellRunner.realUserHome
        return [
            ("Claude Desktop", "\(home)/Library/Application Support/Claude/claude_desktop_config.json"),
            ("Cursor",         "\(home)/.cursor/mcp.json"),
            ("Cursor (workspace defaults)", "\(home)/Library/Application Support/Cursor/User/mcp.json"),
            ("Windsurf",       "\(home)/.codeium/windsurf/mcp_config.json"),
            ("VS Code (Continue)", "\(home)/.continue/config.json"),
            ("Zed",            "\(home)/.config/zed/settings.json"),
        ]
    }

    private func scanMCPConfigurations(findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default

        for (app, path) in mcpConfigLocations {
            guard fm.fileExists(atPath: path),
                  let data = fm.contents(atPath: path),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            // Normalize: some clients store MCP entries under "mcpServers", others under "mcp.servers".
            var servers: [String: Any] = (root["mcpServers"] as? [String: Any]) ?? [:]
            if servers.isEmpty, let mcp = root["mcp"] as? [String: Any],
               let s = mcp["servers"] as? [String: Any] {
                servers = s
            }
            if servers.isEmpty { continue }

            for (name, rawEntry) in servers {
                guard let entry = rawEntry as? [String: Any] else { continue }
                let command = entry["command"] as? String ?? ""
                let args = (entry["args"] as? [String])?.joined(separator: " ") ?? ""
                let env = entry["env"] as? [String: String] ?? [:]
                let url = entry["url"] as? String

                // A remote MCP server URL is worth noting but not by itself dangerous.
                if let remote = url, !remote.isEmpty {
                    let isPlainHTTP = remote.lowercased().hasPrefix("http://") &&
                                      !remote.contains("127.0.0.1") && !remote.contains("localhost")
                    if isPlainHTTP {
                        findings.append(Finding(
                            severity: .medium, category: .networkActivity,
                            title: "\(app) MCP server \"\(name)\" is loaded over plain HTTP",
                            detail: "URL: \(remote) — traffic is trivially interceptable",
                            path: path,
                            remediation: "Switch to HTTPS or remove this MCP entry from \(path)"
                        ))
                    }
                    continue
                }

                // Local command entries: the real risk. Flag runners that execute remote code on start.
                let combined = "\(command) \(args)".lowercased()
                let executesRemoteCode =
                    combined.contains("curl ") || combined.contains("wget ") ||
                    combined.contains("| sh") || combined.contains("| bash") ||
                    combined.contains("|sh") || combined.contains("|bash") ||
                    combined.contains("iex ") || combined.contains("$(curl") ||
                    combined.contains("eval ")

                if executesRemoteCode {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "\(app) MCP server \"\(name)\" runs remote code on launch",
                        detail: "Command: \(command) \(args)".trimmingCharacters(in: .whitespaces),
                        path: path,
                        remediation: "Remove this MCP entry from \(path); it fetches and executes remote code every time the app starts"
                    ))
                    continue
                }

                // npx/uvx entries pinned to "@latest" (or unversioned bare package names) will
                // silently pick up the newest upstream release on every launch — an upstream
                // package hijack runs immediately.
                let npxLike = command == "npx" || command == "uvx" || command == "pnpx"
                if npxLike && args.contains("@latest") {
                    findings.append(Finding(
                        severity: .low, category: .suspiciousFile,
                        title: "\(app) MCP server \"\(name)\" pinned to @latest",
                        detail: "Args: \(args) — every launch pulls whatever is on the registry",
                        path: path,
                        remediation: "Pin an explicit version (e.g. @1.2.3) in \(path)"
                    ))
                }

                // Executable in /tmp, /var/tmp, or a hidden path is a red flag.
                let inTemp = command.hasPrefix("/tmp/") || command.hasPrefix("/private/tmp/") || command.hasPrefix("/var/tmp/")
                let isHidden = command.split(separator: "/").contains { $0.hasPrefix(".") && $0 != ".cargo" && $0 != ".rustup" && $0 != ".local" }
                if inTemp || isHidden {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "\(app) MCP server \"\(name)\" launches a binary from a hidden/temp path",
                        detail: "Command: \(command) \(args)".trimmingCharacters(in: .whitespaces),
                        path: path,
                        remediation: "Remove this MCP entry from \(path) and inspect the referenced binary"
                    ))
                }

                // Environment blocks that carry secrets (API keys, tokens) are common but worth surfacing
                // once — a compromised MCP server would exfiltrate whatever is passed in env.
                let secretishKeys = env.keys.filter { key in
                    let k = key.uppercased()
                    return k.contains("KEY") || k.contains("TOKEN") || k.contains("SECRET") ||
                           k.contains("PASSWORD") || k.contains("APIKEY")
                }
                if !secretishKeys.isEmpty && !executesRemoteCode {
                    findings.append(Finding(
                        severity: .low, category: .suspiciousFile,
                        title: "\(app) MCP server \"\(name)\" is handed secret-like env vars",
                        detail: "env keys: \(secretishKeys.joined(separator: ", ")) — a compromised server sees these",
                        path: path,
                        remediation: "Confirm you trust the MCP server binary and its supply chain"
                    ))
                }
            }
        }
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
