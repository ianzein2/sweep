import Foundation

/// Scans macOS 13+ Background Tasks Management (BTM) — the modern replacement for legacy
/// LaunchAgents. Apps can register persistent background items via SMAppService, login items,
/// or as launch helpers; the consolidated list appears via `sfltool dumpbtm`. Detecting
/// disabled-but-installed items is important because malware often registers itself, gets
/// disabled by the user in System Settings, then re-enables itself silently — the registration
/// itself is the persistence.
public final class BackgroundItemsScanner: Scanner {
    public let name = "Background Items Scan"
    public init() {}

    // Apple's own background items — registered by system services that ship with macOS.
    private let trustedPrefixes: [String] = [
        "com.apple.",
        "/System/", "/usr/", "/Library/Apple/",
    ]

    // Known reputable third-party developers (notarized macOS apps that legitimately use BTM).
    private let benignDeveloperHints: [String] = [
        "Adobe", "Microsoft", "Google", "Mozilla", "Docker", "JetBrains",
        "1Password", "Bitwarden", "Slack", "Zoom", "Dropbox", "Box",
        "GitHub", "Logi Options", "Logitech", "OBSProject",
        "Spotify", "Discord", "Notion", "Linear", "Figma", "Loom",
        "Tailscale", "ProtonVPN", "Mullvad", "Cloudflare",
        "Rogue Amoeba", "Bartender", "Alfred", "Raycast", "Karabiner",
        "Homebrew", "iTerm", "Sublime", "Visual Studio Code",
        "Apple",  // Developer name on Apple-signed third-party items
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("dumping Background Items database")
        // `sfltool dumpbtm` requires root for the full system view, but a user run still
        // returns user-scope items. We try once, treating non-zero as a soft error.
        let result = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 15)
        if !result.success {
            // On older macOS or when sfltool isn't installed, just skip silently.
            if result.exitCode == -1 || result.stderr.contains("not found") || result.exitCode == 127 {
                return ScanResult(scannerName: name, findings: [], errors: [], duration: Date().timeIntervalSince(start))
            }
            errors.append("sfltool dumpbtm failed: \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
            return ScanResult(scannerName: name, findings: findings, errors: errors, duration: Date().timeIntervalSince(start))
        }

        progress?.update("parsing Background Items")
        let items = parseBTMDump(result.stdout)

        // Per macOS conventions, types we care about: type 1 = legacy LaunchAgent, type 2 = legacy LaunchDaemon,
        // type 4 = login item, type 6 = SMAppService daemon, type 7 = SMAppService agent, type 8 = login extension.
        // We don't strictly require the type field, but we keep it for the human-readable label.
        for item in items {
            // Filter out Apple-shipped entries — they explode the count and aren't actionable.
            if trustedPrefixes.contains(where: { item.identifier.hasPrefix($0) }) { continue }
            if trustedPrefixes.contains(where: { item.executablePath.hasPrefix($0) }) {
                // Exec lives under a system path — still surface if the bundle ID is suspicious,
                // otherwise skip.
                if !SpywareSignature.isFakeAppleBundleId(item.identifier) { continue }
            }

            // Known spyware match → high severity, always
            if let sig = SpywareSignature.match(bundleId: item.identifier) ??
                         SpywareSignature.match(label: item.identifier) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Known spyware registered as background item: \(sig.name)",
                    detail: "Identifier: \(item.identifier), Path: \(item.executablePath), Enabled: \(item.enabled)",
                    path: item.executablePath.isEmpty ? nil : item.executablePath,
                    remediation: "Remove the app and revoke its background item: System Settings > General > Login Items > Allow in the Background"
                ))
                continue
            }

            // Fake Apple bundle ID → high
            if SpywareSignature.isFakeAppleBundleId(item.identifier) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Background item uses fake Apple identifier",
                    detail: "Identifier: \(item.identifier) — Apple-signed background items don't use this naming convention",
                    path: item.executablePath.isEmpty ? nil : item.executablePath,
                    remediation: "Open System Settings > General > Login Items > Allow in the Background and remove this entry"
                ))
                continue
            }

            // Hidden path in executable
            let execPath = item.executablePath
            if execPath.contains("/.") ||
                execPath.split(separator: "/").contains(where: { $0.hasPrefix(".") && $0 != "." }) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Background item runs a hidden executable",
                    detail: "Identifier: \(item.identifier), Path: \(execPath)",
                    path: execPath,
                    remediation: "Inspect, then remove the registering app and revoke in System Settings > General > Login Items"
                ))
                continue
            }

            // Items under /tmp, /private/tmp, /var/tmp are never legitimate persistence targets.
            let tmpPrefixes = ["/tmp/", "/private/tmp/", "/var/tmp/"]
            if tmpPrefixes.contains(where: { execPath.hasPrefix($0) }) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Background item runs from a temp directory",
                    detail: "Identifier: \(item.identifier), Path: \(execPath) — persistence pointing to /tmp is unusual and is a common malware pattern",
                    path: execPath,
                    remediation: "Inspect contents, then revoke in System Settings > General > Login Items"
                ))
                continue
            }

            // Disabled-but-installed background items are an interesting signal: the user
            // turned it off in Settings, but the item is still registered and could be
            // re-enabled silently by the parent app. Report as low/informational.
            if !item.enabled && !item.identifier.isEmpty {
                let lookedReputable = benignDeveloperHints.contains { item.developerName.localizedCaseInsensitiveContains($0) }
                if !lookedReputable {
                    findings.append(Finding(
                        severity: .low, category: .persistence,
                        title: "Disabled background item still registered",
                        detail: "Identifier: \(item.identifier), Developer: \(item.developerName.isEmpty ? "unknown" : item.developerName), Path: \(execPath)",
                        path: execPath.isEmpty ? nil : execPath,
                        remediation: "If you uninstalled the parent app, run: sfltool resetbtm — otherwise leave as-is"
                    ))
                }
                continue
            }

            // Enabled, non-Apple, non-reputable background item — surface so the user can audit.
            let lookedReputable = benignDeveloperHints.contains { item.developerName.localizedCaseInsensitiveContains($0) }
            if !lookedReputable && !item.identifier.isEmpty {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Unknown background item registered",
                    detail: "Identifier: \(item.identifier), Developer: \(item.developerName.isEmpty ? "unknown" : item.developerName), Path: \(execPath)",
                    path: execPath.isEmpty ? nil : execPath,
                    remediation: "Review in System Settings > General > Login Items > Allow in the Background — remove if you don't recognize the developer"
                ))
            }
        }

        return ScanResult(scannerName: name, findings: findings, errors: errors, duration: Date().timeIntervalSince(start))
    }

    // MARK: - Parser

    /// One row from `sfltool dumpbtm`. The tool's output is human-readable rather than a stable
    /// machine format, so we parse defensively: each "Item record:" block becomes one entry,
    /// and we extract a handful of fields we care about. Missing fields default to empty strings.
    private struct BTMItem {
        var identifier: String = ""
        var executablePath: String = ""
        var developerName: String = ""
        var enabled: Bool = false
        var typeLabel: String = ""
    }

    private func parseBTMDump(_ text: String) -> [BTMItem] {
        var items: [BTMItem] = []
        var current: BTMItem?

        // The dump groups records separated by lines like "Item record:" or "UUID: ...".
        // We treat any line that starts a new "Item record:" or "UUID:" header as a new record.
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.hasPrefix("Item record:") || (trimmed.hasPrefix("UUID:") && current?.identifier.isEmpty == false) {
                if let c = current { items.append(c) }
                current = BTMItem()
                continue
            }
            if current == nil { current = BTMItem() }

            // Field: value parsing — split on the first colon.
            guard let colon = trimmed.firstIndex(of: ":") else { continue }
            let key = String(trimmed[..<colon]).trimmingCharacters(in: .whitespaces).lowercased()
            let value = String(trimmed[trimmed.index(after: colon)...]).trimmingCharacters(in: .whitespaces)

            switch key {
            case "identifier", "bundle id", "bundle identifier", "id":
                if current?.identifier.isEmpty == true { current?.identifier = value }
            case "executable path", "exec path", "url":
                if current?.executablePath.isEmpty == true {
                    // URLs are sometimes prefixed with `file:///` — strip it.
                    var v = value
                    if v.hasPrefix("file://") { v = String(v.dropFirst("file://".count)) }
                    current?.executablePath = v
                }
            case "developer name", "team identifier", "developer":
                if current?.developerName.isEmpty == true { current?.developerName = value }
            case "disposition":
                // sfltool prints e.g. "disposition: [enabled, allowed, visible, notified]"
                current?.enabled = value.lowercased().contains("enabled")
            case "type":
                current?.typeLabel = value
            default:
                break
            }
        }
        if let c = current, !c.identifier.isEmpty || !c.executablePath.isEmpty {
            items.append(c)
        }
        return items
    }
}
