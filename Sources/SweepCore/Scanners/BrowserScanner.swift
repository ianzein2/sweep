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

    // Known malicious / compromised VSCode/Cursor extension IDs reported 2024-2026.
    // Match is case-insensitive against the `publisher.name` slug at the package root.
    // Sources cited inline; ReversingLabs ahban cluster, Datadog MUT-9332, Checkmarx
    // juanblan281, Koi WhiteCobra, Socket/Koi GlassWorm, Nx Console v18.95.0 incident.
    private let knownMaliciousEditorExtIds: [(id: String, family: String, source: String)] = [
        // ReversingLabs ahban cluster (Nov 2024 -> Mar 2025)
        ("ahban.cychelloworld", "ahban ransomware downloader",
         "https://www.reversinglabs.com/blog/malware-vs-code-extension-names"),
        ("ahban.shiba", "ahban ransomware downloader",
         "https://www.reversinglabs.com/blog/malware-vs-code-extension-names"),
        ("ahbanc.shiba", "ahban (republished)",
         "https://thehackernews.com/2025/08/researchers-find-vs-code-flaw-allowing.html"),
        // Datadog MUT-9332 Solidity-themed stealers (May 2025)
        ("smartcontractai.solaibot", "MUT-9332 Solidity stealer",
         "https://securitylabs.datadoghq.com/articles/mut-9332-malicious-solidity-vscode-extensions/"),
        ("ethcompiler.among-eth", "MUT-9332 Solidity stealer",
         "https://securitylabs.datadoghq.com/articles/mut-9332-malicious-solidity-vscode-extensions/"),
        ("johngaffney.blankebesxstnion", "MUT-9332 Solidity stealer",
         "https://securitylabs.datadoghq.com/articles/mut-9332-malicious-solidity-vscode-extensions/"),
        // Checkmarx juanblan281 (Jan 2026)
        ("juanblan281.solid281", "Solidity typosquat ScreenConnect RAT",
         "https://checkmarx.com/zero-post/solidity-devs-targeted-again-malicious-vs-code-extension-drops-screenconnect-based-remote-access-trojan-rat/"),
        // Solidity Language impersonations (the $500k Cursor crypto-heist family)
        ("showsnowcrypto.snowshono", "Solidity Language impersonation",
         "https://www.scworld.com/news/fake-visual-studio-code-extension-for-cursor-led-to-500k-theft"),
        // Koi WhiteCobra (Sept 2025)
        ("contractshark.solidity-lang", "WhiteCobra Solidity stealer",
         "https://www.koi.ai/blog/whitecobra-vscode-cursor-extensions-malware"),
        // Nx Console v18.95.0 supply-chain compromise (May 2026)
        // ONLY v18.95.0 is malicious; >=18.100.0 is safe. We match on the version dir
        // in the heuristic below rather than blanket-banning the publisher.
        ("nrwl.angular-console-18.95.0", "Nx Console v18.95.0 hijack (CVE-2026-48027)",
         "https://nx.dev/blog/nx-console-v18-95-0-postmortem"),
        // Socket/Koi GlassWorm Open VSX cluster (Oct 2025 / Mar 2026)
        ("twilkbilk.color-highlight-css", "GlassWorm",
         "https://socket.dev/blog/open-vsx-transitive-glassworm-campaign"),
        ("otoboss.autoimport-extension", "GlassWorm",
         "https://socket.dev/blog/open-vsx-transitive-glassworm-campaign"),
        ("oigotm.my-command-palette-extension", "GlassWorm",
         "https://socket.dev/blog/open-vsx-transitive-glassworm-campaign"),
        ("federicanc.dotenv-syntax-highlighting", "GlassWorm",
         "https://socket.dev/blog/open-vsx-transitive-glassworm-campaign"),
        ("crotoapp.vscode-xml-extension", "GlassWorm",
         "https://socket.dev/blog/open-vsx-transitive-glassworm-campaign"),
        ("daeumer-web.es-linter-for-vs-code", "GlassWorm (dbaeumer typosquat)",
         "https://socket.dev/blog/open-vsx-transitive-glassworm-campaign"),
    ]

    // Known malicious / compromised Chrome extension IDs reported 2024-2026.
    // The Cyberhaven supply-chain wave (Dec 2024 / Jan 2025) hijacked legitimate
    // extensions to exfiltrate cookies and session tokens. The IDs below survived
    // takedown windows and may still be installed on Macs that never updated.
    private let knownMaliciousChromeExtIds: [(id: String, family: String, source: String)] = [
        // Cyberhaven cluster (Dec 2024 supply-chain incident)
        ("pajkjnmeojmbapicmbpliphjmcekeaac", "Cyberhaven hijack",
         "https://www.cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident-and-what-were-doing-about-it"),
        ("nnpnnpemnckcfdebeekibpiijlicmpom", "Internxt VPN hijack (Cyberhaven cluster)",
         "https://www.bleepingcomputer.com/news/security/cybersecurity-firms-chrome-extension-hijacked-to-steal-users-data/"),
        ("lbneaaedflankmgmfbmaplggbmjjmbae", "VPNCity hijack (Cyberhaven cluster)",
         "https://cyberinsider.com/multiple-chrome-vpn-extensions-compromised-in-coordinated-attack/"),
        ("fbmlcbhdmilaggedifpihjgkkmdgeljh", "ParrotTalks hijack (Cyberhaven cluster)",
         "https://isc.sans.edu/diary/31574"),
        ("oaikpkmjciadfpddlpjjdapglcihgdle", "Uvoice hijack (Cyberhaven cluster)",
         "https://isc.sans.edu/diary/31574"),
        ("jiofmdifioeejeilfkpegipdjiopiekl", "YesCaptcha Assistant hijack (Cyberhaven cluster)",
         "https://isc.sans.edu/diary/31574"),
        ("epikoohpebngmakjinphfiagogjcnddm", "AI Shop Buddy hijack (Cyberhaven cluster)",
         "https://isc.sans.edu/diary/31574"),
        ("ekpkdmohpdnebfedjjfklhpefgpgaaji", "Tackker Keylogger (Cyberhaven cluster)",
         "https://isc.sans.edu/diary/31574"),
        ("pdkmmfdfggfpibdjbbghggcllhhainjo", "Web3 Password Manager hijack (Cyberhaven cluster)",
         "https://isc.sans.edu/diary/31574"),
        // Standalone malicious extensions
        ("fnmihdojmnkclgjpcoonokmkhjpjechg", "AI chat tab/URL exfiltrator (Jan 2026)",
         "https://thehackernews.com/2026/01/two-chrome-extensions-caught-stealing.html"),
        ("inhcgfpbfdjbjogdfjbclgolkmhnooop", "AI Sidebar tab/URL exfiltrator (Jan 2026)",
         "https://thehackernews.com/2026/01/two-chrome-extensions-caught-stealing.html"),
        ("jkphinfhmfkckkcnifhjiplhfoiefffl", "CL Suite Meta Business 2FA stealer",
         "https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html"),
        ("jcbiifklmgnkppebelchllpdbnibihel", "FreeVPN.One / SpyVPN screen-capture exfiltrator",
         "https://www.koi.ai/blog/spyvpn-the-vpn-that-secretly-captures-your-screen"),
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

                    // Hard-match against the known-malicious ID list before any heuristic
                    // work — these get a HIGH finding regardless of permissions. We do this
                    // per-profile (not deduped) so the user sees which profile is affected.
                    if let hit = knownMaliciousChromeExtIds.first(where: { $0.id == extId }) {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "\(browserName) has a known malicious extension installed",
                            detail: "Extension ID: \(extId) (profile: \(profile)) — \(hit.family). " +
                                    "Source: \(hit.source)",
                            path: "\(extPath)/\(extId)",
                            remediation: "Remove immediately in \(browserName) > Extensions and rotate " +
                                         "any cookies/sessions or wallet credentials accessed in this profile."
                        ))
                        continue
                    }

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

                // Hard match against the known-malicious ID list. We match either the
                // publisher.name slug OR the full publisher.name-version directory so we
                // can flag the single-version Nx Console hijack without warning on safe
                // versions of the same extension.
                let extIdLower = extId.lowercased()
                let entryLower = entry.lowercased()
                if let hit = knownMaliciousEditorExtIds.first(where: {
                    extIdLower == $0.id || entryLower.hasPrefix($0.id)
                }) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(editorName) has a known malicious extension installed",
                        detail: "Extension: \(displayName) (\(extId)) — \(hit.family). Source: \(hit.source)",
                        path: extPath,
                        remediation: "Remove immediately in \(editorName) > Extensions and rotate any " +
                                     "secrets, wallet credentials, or git/npm tokens this editor had access to."
                    ))
                    continue
                }

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

                // Invisible Unicode in the display name is a known GlassWorm / typosquat
                // disguise — variation selectors (U+FE00–FE0F), tag characters (U+E0100–E01EF),
                // zero-width joiners, and other PUA glyphs let a malicious extension look
                // identical to a legitimate one in the marketplace listing.
                if displayName.unicodeScalars.contains(where: isInvisibleSpoofingScalar) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "\(editorName) extension uses invisible Unicode in its name",
                        detail: "Extension: \(displayName) (\(extId)) — invisible glyphs are a known " +
                                "GlassWorm / typosquat technique to impersonate trusted publishers",
                        path: extPath,
                        remediation: "Remove this extension and re-install the genuine one from the publisher's site"
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

    /// Detect glyphs commonly used to hide payloads inside marketplace listings.
    /// Variation selectors and tag characters render to nothing, letting an extension
    /// display as e.g. "Solidity Language" while having a different underlying slug.
    private func isInvisibleSpoofingScalar(_ scalar: Unicode.Scalar) -> Bool {
        let v = scalar.value
        // Variation Selectors (FE00–FE0F) and Variation Selectors Supplement (E0100–E01EF)
        if (0xFE00...0xFE0F).contains(v) { return true }
        if (0xE0100...0xE01EF).contains(v) { return true }
        // Tag characters (E0000–E007F) — used in some spoofs to encode hidden strings
        if (0xE0000...0xE007F).contains(v) { return true }
        // Zero-width characters frequently abused in typosquats
        if v == 0x200B || v == 0x200C || v == 0x200D || v == 0xFEFF { return true }
        return false
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
