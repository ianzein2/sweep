import Foundation

public final class BrowserScanner: Scanner {
    public let name = "Browser Extension Scan"
    public init() {}

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
}
