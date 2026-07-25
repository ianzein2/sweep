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

    // Known-malicious Chrome/Chromium extension IDs from published supply-chain
    // compromises. Extensions in this list are ALWAYS reported, regardless of
    // permissions, because the extension itself is the compromise indicator.
    //
    // Sources: Cyberhaven Dec-2024 disclosure and follow-on analyses that identified
    // ~35 additional extensions signed with the same attacker infrastructure. Users
    // running any of these — even weeks or months after removal from the store —
    // still have the compromised code on disk and should investigate.
    private let knownMaliciousExtensionIds: [(id: String, name: String, campaign: String)] = [
        ("nnpnnpemnckcfdebeekibpiijlicmpom", "Cyberhaven",                "Cyberhaven Dec-2024 supply-chain compromise"),
        ("kkodiihpgodmdankclfibbiphjkfdenh", "Reader Mode",               "Cyberhaven Dec-2024 supply-chain compromise"),
        ("oaikpkmjciadfpddlpjjdapglcihgdle", "Parrot Talks",              "Cyberhaven Dec-2024 supply-chain compromise"),
        ("bibjgkidgpfbblifamdlkdlhgihmfohh", "Uvoice",                    "Cyberhaven Dec-2024 supply-chain compromise"),
        ("acmfnomgphggonodopogfbmkneepfgnh", "Internxt VPN",              "Cyberhaven Dec-2024 supply-chain compromise"),
        ("mnhffkhmpnefgklngfmlndmkimimbphc", "VPNCity",                   "Cyberhaven Dec-2024 supply-chain compromise"),
        ("cplhlgabfijoiabgkigdafklbhhdkahj", "Bookmark Favicon Changer",  "Cyberhaven Dec-2024 supply-chain compromise"),
        ("miglaibdlgminlepgeifekifakochlka", "Castorus",                  "Cyberhaven Dec-2024 supply-chain compromise"),
        ("gbbagbjbanbnpoklgomodhagcbkpckld", "Wayin AI",                  "Cyberhaven Dec-2024 supply-chain compromise"),
        ("dpggmcodlahmljkhlmpgpdcffdaoccni", "Search Copilot AI",         "Cyberhaven Dec-2024 supply-chain compromise"),
        ("acbiaofoeebeinacmcknopaikmecdehl", "VidHelper",                 "Cyberhaven Dec-2024 supply-chain compromise"),
        ("mbindhfolmpijhodmgkloeeppmkhpmhc", "Hi AI Prompt",              "Cyberhaven Dec-2024 supply-chain compromise"),
        ("njdkgjbjmdceoibefpjmdcmneejmoble", "Sort by Oldest",            "Cyberhaven Dec-2024 supply-chain compromise"),
        ("bbdnohkpnbkdkmnkddobeafboooinpla", "Rewards Search Automator",  "Cyberhaven Dec-2024 supply-chain compromise"),
        ("bahogceckgcanpcoabcdgmoidngedmfo", "Visual Effects for Google Meet", "Cyberhaven Dec-2024 supply-chain compromise"),
        ("hcalclcinlihfmdblpcegmehidfkpndn", "Vidnoz Flex",               "Cyberhaven Dec-2024 supply-chain compromise"),
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

        // 5. Native Messaging Hosts — the bridge an installed browser extension uses to
        //    execute native binaries. Malware registers a NativeMessagingHost so a benign-looking
        //    extension can shell out to arbitrary code. Rarely used by legitimate software.
        progress?.update("scanning browser native messaging hosts")
        scanNativeMessagingHosts(findings: &findings, errors: &errors)

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
                    // Known-malicious extensions must be reported even if they'd otherwise be
                    // trusted / benign-looking. Check this list FIRST.
                    if let bad = knownMaliciousExtensionIds.first(where: { $0.id == extId }) {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "\(browserName) extension from known supply-chain compromise",
                            detail: "Extension: \(bad.name) (\(extId)), profile: \(profile) — \(bad.campaign)",
                            path: "\(extPath)/\(extId)",
                            remediation: "Remove immediately in \(browserName) > Extensions. Rotate any credentials entered while this extension was installed."
                        ))
                        continue
                    }

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

    // MARK: - Native Messaging Hosts

    /// Names of publishers whose Native Messaging hosts are widely-installed and legitimate.
    /// Anything OUTSIDE this list gets reported so the user can decide.
    private static let knownGoodNativeMessagingHosts: Set<String> = [
        // Password managers
        "com.1password.1password", "com.1password.browser_support",
        "com.bitwarden.desktop", "com.dashlane.dashlanephoneextension.launcher",
        "com.lastpass.nativehost", "com.keepassxc.keepassxc",
        "com.keeperlogin.nativemessaging",
        "org.keepassxc.keepassxc_browser",
        "com.enpass.enpass",
        // Communication / desktop apps
        "com.google.chrome.remote_desktop",
        "com.google.chrome.remote_assistance",
        "com.zoom.pluginhost",
        "com.microsoft.teams.launcher",
        "com.cisco.webex.startpage",
        "com.getdropbox.dropboxsigners",
        "com.docker.desktop",
        // Media / DRM
        "com.widevine.wvcdm",
        // Common browser tooling
        "com.honey.browser.helper",
        "com.grammarly.desktop",
        "com.rewind.native",
        "com.notion.notionwebclipperextension",
    ]

    private func scanNativeMessagingHosts(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome

        // Chromium-family: JSON manifests live under each browser's NativeMessagingHosts directory
        let chromiumHostDirs: [(browser: String, path: String)] = [
            ("Chrome",  "\(home)/Library/Application Support/Google/Chrome/NativeMessagingHosts"),
            ("Chrome",  "/Library/Google/Chrome/NativeMessagingHosts"),
            ("Chromium","\(home)/Library/Application Support/Chromium/NativeMessagingHosts"),
            ("Brave",   "\(home)/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            ("Edge",    "\(home)/Library/Application Support/Microsoft Edge/NativeMessagingHosts"),
            ("Edge",    "/Library/Microsoft/Edge/NativeMessagingHosts"),
            ("Arc",     "\(home)/Library/Application Support/Arc/User Data/NativeMessagingHosts"),
            ("Vivaldi", "\(home)/Library/Application Support/Vivaldi/NativeMessagingHosts"),
            ("Opera",   "\(home)/Library/Application Support/com.operasoftware.Opera/NativeMessagingHosts"),
        ]

        let fm = FileManager.default
        for entry in chromiumHostDirs {
            guard fm.fileExists(atPath: entry.path),
                  let manifests = try? fm.contentsOfDirectory(atPath: entry.path) else { continue }

            for file in manifests where file.hasSuffix(".json") {
                let manifestPath = "\(entry.path)/\(file)"
                inspectNativeMessagingHost(
                    manifestPath: manifestPath,
                    browser: entry.browser,
                    findings: &findings
                )
            }
        }

        // Firefox: manifests live under a different directory, one per app
        let firefoxHostDirs = [
            "\(home)/Library/Application Support/Mozilla/NativeMessagingHosts",
            "/Library/Application Support/Mozilla/NativeMessagingHosts",
        ]
        for dir in firefoxHostDirs {
            guard fm.fileExists(atPath: dir),
                  let manifests = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in manifests where file.hasSuffix(".json") {
                let manifestPath = "\(dir)/\(file)"
                inspectNativeMessagingHost(
                    manifestPath: manifestPath,
                    browser: "Firefox",
                    findings: &findings
                )
            }
        }
    }

    private func inspectNativeMessagingHost(manifestPath: String, browser: String, findings: inout [Finding]) {
        let fm = FileManager.default
        guard let data = fm.contents(atPath: manifestPath),
              let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        let hostName = (manifest["name"] as? String) ?? URL(fileURLWithPath: manifestPath).deletingPathExtension().lastPathComponent
        let binaryPath = (manifest["path"] as? String) ?? ""

        // Trusted publisher — skip
        if BrowserScanner.knownGoodNativeMessagingHosts.contains(hostName) { return }

        // A Native Messaging Host binary that lives in /tmp or a hidden directory is
        // effectively never legitimate — legitimate installers place binaries in
        // /Applications or /Library/Application Support.
        let expandedBinary = binaryPath.hasPrefix("~/")
            ? ShellRunner.realUserHome + String(binaryPath.dropFirst(1))
            : binaryPath
        let isTempPath = expandedBinary.hasPrefix("/tmp/") ||
                         expandedBinary.hasPrefix("/private/tmp/") ||
                         expandedBinary.hasPrefix("/var/tmp/")
        let isHiddenPath = expandedBinary.split(separator: "/").contains { $0.hasPrefix(".") }
        let binaryExists = !expandedBinary.isEmpty && fm.fileExists(atPath: expandedBinary)

        if isTempPath || isHiddenPath {
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "\(browser) Native Messaging Host points to temp/hidden binary",
                detail: "Host: \(hostName), binary: \(binaryPath)",
                path: manifestPath,
                remediation: "Remove the manifest and inspect the binary: sudo rm \"\(manifestPath)\""
            ))
            return
        }

        // A registered Host with no binary at all is a broken/leftover install — informational.
        if !binaryExists && !binaryPath.isEmpty {
            findings.append(Finding(
                severity: .low, category: .persistence,
                title: "\(browser) Native Messaging Host references missing binary",
                detail: "Host: \(hostName), missing: \(binaryPath)",
                path: manifestPath,
                remediation: "Orphaned host — safe to remove: rm \"\(manifestPath)\""
            ))
            return
        }

        // Every remaining host is unknown to sweep but registered with a browser — surface
        // as medium so the user can eyeball it. Native Messaging is the standard way a
        // browser extension escapes the sandbox and shells out to native code.
        findings.append(Finding(
            severity: .medium, category: .persistence,
            title: "\(browser) Native Messaging Host registered",
            detail: "Host: \(hostName), binary: \(binaryPath) — grants a browser extension the ability to invoke this binary",
            path: manifestPath,
            remediation: "Confirm you installed the companion app that registered this host, otherwise remove: rm \"\(manifestPath)\""
        ))
    }
}
