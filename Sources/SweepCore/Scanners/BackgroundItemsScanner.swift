import Foundation
import Security

/// Scans modern macOS Ventura+ background-item persistence.
///
/// Starting with macOS 13, third-party launch agents, login items, and helper tools register
/// with `backgroundtaskmanagementd` (BTM) and the Service Management framework
/// (`SMAppService`). This is a different surface from the classic LaunchAgent plist scan:
///
/// - apps install login items via `SMAppService.loginItem(identifier:)`
/// - launch agents/daemons can be registered programmatically via `SMAppService.agent(...)` /
///   `SMAppService.daemon(...)` instead of dropping a plist file
/// - all of these show up in `sfltool dump-btm` and the BTM database at
///   `/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm`
///
/// Recent malware families (DeerStealer, ReaderUpdate, ObjCShellz, FrigidStealer) abuse the
/// background-item surface because it dodges old plist-based scanners and the BTM database is
/// only readable with admin privileges.
public final class BackgroundItemsScanner: Scanner {
    public let name = "Background Items Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("dumping background items (sfltool)")
        scanBTMItems(findings: &findings, errors: &errors)

        progress?.update("checking modern login items")
        scanLegacyLoginItems(findings: &findings, errors: &errors)

        progress?.update("checking PrivilegedHelperTools")
        scanPrivilegedHelperTools(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - BTM dump via sfltool

    private struct BTMItem {
        var identifier: String = ""
        var name: String = ""
        var url: String = ""
        var type: String = ""
        var disposition: String = ""
        var teamID: String = ""
        var developer: String = ""
    }

    private func scanBTMItems(findings: inout [Finding], errors: inout [String]) {
        // `sfltool dump-btm` requires root. On non-root we get an error — that's fine, the
        // classic persistence scanner already covers plist-based items. We just skip silently.
        let result = ShellRunner.run("/usr/bin/sfltool", arguments: ["dump-btm"], timeout: 15)
        guard result.success, !result.stdout.isEmpty else {
            if !result.stderr.isEmpty && !result.stderr.lowercased().contains("permission") {
                errors.append("sfltool dump-btm failed: \(result.stderr.prefix(200))")
            }
            return
        }

        let items = parseBTM(result.stdout)
        for item in items {
            evaluateBTMItem(item, findings: &findings)
        }
    }

    /// Parse the sfltool dump-btm text output. Each item is a multi-line block, separated by blank
    /// lines. We rely on prefixes like "Identifier:", "URL:", "Team Identifier:" rather than a
    /// strict grammar — the tool's output has shifted across macOS versions but the keys are stable.
    private func parseBTM(_ output: String) -> [BTMItem] {
        var items: [BTMItem] = []
        var current = BTMItem()
        var inItem = false

        for rawLine in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)

            // Blank line ends the current block
            if line.isEmpty {
                if inItem && !current.identifier.isEmpty {
                    items.append(current)
                }
                current = BTMItem()
                inItem = false
                continue
            }

            // The "Records:" / "Container:" headers don't start a record themselves — we wait for the
            // next "Identifier:" line.
            if line.hasPrefix("Identifier:") {
                if inItem && !current.identifier.isEmpty {
                    items.append(current)
                    current = BTMItem()
                }
                current.identifier = stripKey(line, key: "Identifier:")
                inItem = true
                continue
            }
            guard inItem else { continue }

            if line.hasPrefix("Name:") {
                current.name = stripKey(line, key: "Name:")
            } else if line.hasPrefix("URL:") {
                current.url = stripKey(line, key: "URL:")
            } else if line.hasPrefix("Executable Path:") {
                if current.url.isEmpty { current.url = stripKey(line, key: "Executable Path:") }
            } else if line.hasPrefix("Type:") {
                current.type = stripKey(line, key: "Type:")
            } else if line.hasPrefix("Disposition:") {
                current.disposition = stripKey(line, key: "Disposition:")
            } else if line.hasPrefix("Team Identifier:") {
                current.teamID = stripKey(line, key: "Team Identifier:")
            } else if line.hasPrefix("Developer Name:") {
                current.developer = stripKey(line, key: "Developer Name:")
            }
        }
        if inItem && !current.identifier.isEmpty { items.append(current) }
        return items
    }

    private func stripKey(_ line: String, key: String) -> String {
        guard let range = line.range(of: key) else { return line }
        return String(line[range.upperBound...]).trimmingCharacters(in: .whitespaces)
    }

    private func evaluateBTMItem(_ item: BTMItem, findings: inout [Finding]) {
        let identifier = item.identifier
        let detailURL = item.url.isEmpty ? "n/a" : item.url

        // 1. Known spyware bundle ID
        if let sig = SpywareSignature.match(bundleId: identifier) ??
                     SpywareSignature.match(label: identifier) {
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "Known spyware registered as background item: \(sig.name)",
                detail: "Identifier: \(identifier), URL: \(detailURL), Type: \(item.type)",
                path: filePath(from: item.url),
                remediation: "Disable in System Settings > General > Login Items & Extensions, then remove \(sig.name)"
            ))
            return
        }

        // 2. Fake-Apple bundle ID (e.g. `com.apple.softwareupdate.agent`)
        if SpywareSignature.isFakeAppleBundleId(identifier) {
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "Background item with fake Apple bundle ID",
                detail: "Identifier: \(identifier), URL: \(detailURL) — legitimate Apple background items don't use this naming pattern",
                path: filePath(from: item.url),
                remediation: "Disable in System Settings > General > Login Items & Extensions and investigate the source"
            ))
            return
        }

        // 3. Skip Apple's own items entirely
        if identifier.hasPrefix("com.apple.") { return }

        // 4. Items whose backing binary lives in a tmp directory — never legitimate
        if let path = filePath(from: item.url) {
            let tmpPrefixes = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/"]
            if tmpPrefixes.contains(where: { path.hasPrefix($0) }) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Background item runs binary from temp directory",
                    detail: "Identifier: \(identifier), URL: \(detailURL)",
                    path: path,
                    remediation: "This is a strong malware indicator — disable in System Settings > General > Login Items & Extensions and remove the binary"
                ))
                return
            }
            // Hidden path components
            if path.split(separator: "/").contains(where: { $0.hasPrefix(".") && $0 != "." && $0 != ".." }) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Background item runs binary from hidden path",
                    detail: "Identifier: \(identifier), URL: \(detailURL)",
                    path: path,
                    remediation: "Hidden executables on persistence are a strong spyware indicator — investigate \(path)"
                ))
                return
            }
        }

        // 5. Ad-hoc / unsigned (no Team Identifier) third-party background items.
        // BTM normally records the developer team ID; entries with no team ID and no Apple identifier
        // are usually unsigned helper tools — rare in legitimate apps shipped from the App Store.
        if item.teamID.isEmpty || item.teamID.lowercased() == "none" || item.teamID == "(null)" {
            let isDisabled = item.disposition.lowercased().contains("disabled")
            findings.append(Finding(
                severity: isDisabled ? .low : .medium,
                category: .persistence,
                title: "Background item without developer Team ID",
                detail: "Identifier: \(identifier), URL: \(detailURL), Disposition: \(item.disposition)",
                path: filePath(from: item.url),
                remediation: "Verify this background item is legitimate in System Settings > General > Login Items & Extensions"
            ))
        }
    }

    /// `URL:` lines in the dump come as `file:///...` URLs — convert to a filesystem path.
    private func filePath(from url: String) -> String? {
        if url.isEmpty { return nil }
        if url.hasPrefix("file://") {
            if let u = URL(string: url) { return u.path }
        }
        if url.hasPrefix("/") { return url }
        return nil
    }

    // MARK: - Legacy login items (~/Library/Application Support/com.apple.backgroundtaskmanagementagent)

    /// Even when sfltool isn't available (no root), we can still find some persistence by walking
    /// the legacy login-items directory and System Preferences login items list.
    private func scanLegacyLoginItems(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let candidates = [
            "\(home)/Library/Application Support/com.apple.backgroundtaskmanagementagent",
        ]

        let fm = FileManager.default
        for dir in candidates {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where !entry.hasPrefix(".") {
                let entryPath = "\(dir)/\(entry)"
                // Match the file name against known spyware bundle IDs
                if let sig = SpywareSignature.match(bundleId: entry) ??
                             SpywareSignature.match(label: entry) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Known spyware in background-task DB: \(sig.name)",
                        detail: "Entry: \(entry)",
                        path: entryPath,
                        remediation: "Disable in System Settings > General > Login Items & Extensions, then remove the app"
                    ))
                }
            }
        }
    }

    // MARK: - PrivilegedHelperTools

    /// Apps that need privileged operations install an XPC helper in
    /// `/Library/PrivilegedHelperTools/` and register it with launchd via `SMJobBless` (now
    /// deprecated) or `SMAppService.daemon(...)`. Stale or unsigned helpers in this directory
    /// are a privilege-escalation surface — `Smjobless` helpers run as root and can be hijacked.
    private func scanPrivilegedHelperTools(findings: inout [Finding], errors: inout [String]) {
        let dir = "/Library/PrivilegedHelperTools"
        let fm = FileManager.default
        guard fm.fileExists(atPath: dir),
              let entries = try? fm.contentsOfDirectory(atPath: dir) else { return }

        for entry in entries where !entry.hasPrefix(".") {
            let path = "\(dir)/\(entry)"

            // Known spyware?
            if let sig = SpywareSignature.match(processName: entry) ??
                         SpywareSignature.match(bundleId: entry) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Known spyware helper tool: \(sig.name)",
                    detail: "Privileged helper: \(entry)",
                    path: path,
                    remediation: "Remove: sudo rm \"\(path)\" — then uninstall \(sig.name)"
                ))
                continue
            }

            // Fake-Apple-looking helper
            if SpywareSignature.isFakeAppleBundleId(entry) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Privileged helper with fake Apple bundle ID",
                    detail: "Helper: \(entry) — legitimate Apple helpers don't use this naming pattern",
                    path: path,
                    remediation: "Inspect and remove if unexpected: sudo rm \"\(path)\""
                ))
                continue
            }

            // Unsigned privileged helper — runs as root, must be signed by a known developer.
            if !checkIsSigned(path: path) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Unsigned privileged helper tool",
                    detail: "Helper: \(entry) runs with root privileges but has no valid signature",
                    path: path,
                    remediation: "Inspect, then remove if not expected: sudo rm \"\(path)\""
                ))
                continue
            }

            // Orphaned helper: no matching launchd plist references it. Indicates the parent app
            // was uninstalled but left the helper behind — a residual privesc surface.
            let isReferenced = launchdPlistsReference(entry)
            if !isReferenced {
                findings.append(Finding(
                    severity: .low, category: .persistence,
                    title: "Orphaned privileged helper tool",
                    detail: "Helper: \(entry) — no matching launchd plist found",
                    path: path,
                    remediation: "Remove if the installing app is gone: sudo rm \"\(path)\""
                ))
            }
        }
    }

    private func launchdPlistsReference(_ helperName: String) -> Bool {
        // Cheap check — look for the helper name in /Library/LaunchDaemons and ~/Library/LaunchAgents.
        let dirs = [
            "/Library/LaunchDaemons",
            "\(ShellRunner.realUserHome)/Library/LaunchAgents",
            "/Library/LaunchAgents",
        ]
        let fm = FileManager.default
        for dir in dirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where entry.hasSuffix(".plist") {
                guard let content = try? String(contentsOfFile: "\(dir)/\(entry)", encoding: .utf8) else { continue }
                if content.contains(helperName) { return true }
            }
        }
        return false
    }

    private func checkIsSigned(path: String) -> Bool {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return false }
        return SecStaticCodeCheckValidityWithErrors(code, SecCSFlags(rawValue: 0), nil, nil) == errSecSuccess
    }
}
