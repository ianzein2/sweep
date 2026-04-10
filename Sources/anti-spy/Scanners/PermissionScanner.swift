import Foundation
import Security

final class PermissionScanner: Scanner {
    let name = "Permission Scan"

    private let tccServices: [(service: String, label: String)] = [
        ("kTCCServiceScreenCapture", "Screen Capture"),
        ("kTCCServiceListenEvent", "Input Monitoring"),
        ("kTCCServiceAccessibility", "Accessibility"),
        ("kTCCServicePostEvent", "Synthetic Input"),
        ("kTCCServiceMicrophone", "Microphone"),
        ("kTCCServiceCamera", "Camera"),
    ]

    private let whitelistedClients: Set<String> = [
        "com.apple.Terminal", "com.apple.dt.Xcode", "com.apple.Safari",
        "com.apple.systempreferences", "com.apple.accessibility.universalaccess",
        "com.apple.screencaptureui", "com.apple.screensharing",
        "us.zoom.xos", "com.microsoft.teams", "com.microsoft.teams2",
        "com.skype.skype", "com.google.Chrome", "com.brave.Browser",
        "org.mozilla.firefox", "com.slack.Slack", "com.discord.Discord",
        "com.1password.1password", "com.agilebits.onepassword7",
        "com.loom.desktop", "com.obsproject.obs-studio",
        "com.getdropbox.dropbox", "com.google.drivefs",
        "com.microsoft.VSCode", "com.sublimetext.4", "com.sublimetext.3",
        "com.googlecode.iterm2", "net.kovidgoyal.kitty",
        "com.jetbrains.intellij", "com.jetbrains.CLion",
        "com.hegenberg.BetterTouchTool", "org.pqrs.Karabiner-Elements.Grabber",
        "org.pqrs.Karabiner-EventViewer", "com.manytricks.Moom",
        "com.contextsformac.Contexts", "com.runningwithcrayons.Alfred",
        "com.raycast.macos", "com.stairways.keyboardmaestro.engine",
        "com.stairways.keyboardmaestro",
        "com.elgato.StreamDeck", "com.telestream.screenflow10",
        "com.techsmith.snagit", "com.krill.screenium",
        "com.crowdcafe.windowmagnet", "org.rectangleapp.Rectangle",
        "com.lwouis.alt-tab-macos", "org.hammerspoon.Hammerspoon",
    ]

    private let knownAccessibilityApps: Set<String> = [
        "com.hegenberg.BetterTouchTool", "org.pqrs.Karabiner-Elements.Grabber",
        "org.pqrs.Karabiner-EventViewer", "com.runningwithcrayons.Alfred",
        "com.raycast.macos", "com.stairways.keyboardmaestro.engine",
        "com.stairways.keyboardmaestro", "com.lwouis.alt-tab-macos",
        "com.contextsformac.Contexts", "org.hammerspoon.Hammerspoon",
        "com.manytricks.Moom", "org.rectangleapp.Rectangle",
        "com.crowdcafe.windowmagnet", "com.knollsoft.Rectangle",
        "com.apple.voiceover", "com.apple.accessibility.universalaccess",
        "com.elgato.StreamDeck", "com.1password.1password",
        "com.agilebits.onepassword7", "com.bitwarden.desktop",
        "com.lastpass.lastpassdesktop",
    ]

    func scan(progress: Spinner? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        // 1. Try TCC database
        progress?.update("querying TCC database")
        let userHome = ShellRunner.realUserHome
        let userTCCPath = "\(userHome)/Library/Application Support/com.apple.TCC/TCC.db"
        let systemTCCPath = "/Library/Application Support/com.apple.TCC/TCC.db"

        let userGrants = queryTCC(dbPath: userTCCPath, errors: &errors, label: "User TCC")
        let systemGrants = queryTCC(dbPath: systemTCCPath, errors: &errors, label: "System TCC")
        let allGrants = userGrants + systemGrants

        if !allGrants.isEmpty {
            analyzeTCCGrants(allGrants, findings: &findings)

            // Batch check which apps exist on disk (single mdfind call)
            progress?.update("checking app existence")
            let clientIds = Set(allGrants.map { $0.client }
                .filter { !$0.hasPrefix("/") && !$0.hasPrefix("com.apple.") && !whitelistedClients.contains($0) })
            let installedApps = batchCheckAppsExist(clientIds)

            analyzeAccessibilityGrants(allGrants, installedApps: installedApps, findings: &findings)

            // 1.5 Check TCC database integrity
            progress?.update("checking TCC integrity")
            checkTCCIntegrity(grants: allGrants, installedApps: installedApps, findings: &findings, errors: &errors)
        }

        // 2. Check TCC log for spyware access attempts
        progress?.update("checking TCC access log")
        scanTCCLog(findings: &findings, errors: &errors)

        // 3. Check login items (sneaky persistence)
        progress?.update("checking login items")
        scanLoginItems(findings: &findings, errors: &errors)

        // 4. Check for DYLIB injection (used by advanced spyware)
        progress?.update("checking for DYLIB injection")
        scanDylibInjection(findings: &findings, errors: &errors)

        // 5. Check cron jobs
        progress?.update("checking cron jobs")
        scanCronJobs(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - TCC Database Analysis

    private func analyzeTCCGrants(_ allGrants: [TCCGrant], findings: inout [Finding]) {
        var clientPermissions: [String: [(service: String, label: String, modified: String)]] = [:]
        for grant in allGrants {
            clientPermissions[grant.client, default: []].append(
                (service: grant.service, label: grant.serviceLabel, modified: grant.lastModified)
            )
        }

        for (client, permissions) in clientPermissions {
            if whitelistedClients.contains(client) { continue }
            if client.hasPrefix("com.apple.") { continue }

            let permLabels = permissions.map { $0.label }

            if let sig = SpywareSignature.match(bundleId: client) {
                findings.append(Finding(
                    severity: .high, category: .permission,
                    title: "Known spyware has system permissions: \(sig.name)",
                    detail: "Client: \(client), Permissions: \(permLabels.joined(separator: ", "))",
                    path: nil,
                    remediation: "Revoke all permissions and remove \(sig.name)"
                ))
                continue
            }

            let hasScreenCapture = permLabels.contains("Screen Capture")
            let hasInputMonitoring = permLabels.contains("Input Monitoring")
            let hasMic = permLabels.contains("Microphone")
            let hasCamera = permLabels.contains("Camera")

            if hasScreenCapture && hasInputMonitoring {
                findings.append(Finding(
                    severity: .high, category: .permission,
                    title: "App has Screen Capture + Input Monitoring",
                    detail: "Client: \(client) — strong spyware indicator",
                    path: nil,
                    remediation: "Revoke in System Settings > Privacy & Security"
                ))
            } else if hasMic && hasCamera && hasScreenCapture {
                findings.append(Finding(
                    severity: .high, category: .permission,
                    title: "App has Camera + Mic + Screen Capture",
                    detail: "Client: \(client) — full surveillance capability",
                    path: nil,
                    remediation: "Revoke in System Settings > Privacy & Security"
                ))
            } else if hasScreenCapture {
                findings.append(Finding(
                    severity: .medium, category: .permission,
                    title: "Non-standard app has Screen Capture permission",
                    detail: "Client: \(client), Granted: \(permissions.first?.modified ?? "unknown")",
                    path: nil, remediation: "Check System Settings > Privacy & Security > Screen Recording"
                ))
            } else if hasInputMonitoring {
                findings.append(Finding(
                    severity: .medium, category: .permission,
                    title: "Non-standard app has Input Monitoring",
                    detail: "Client: \(client), Granted: \(permissions.first?.modified ?? "unknown")",
                    path: nil, remediation: "Check System Settings > Privacy & Security > Input Monitoring"
                ))
            }
        }
    }

    // MARK: - Batch App Existence Check (single mdfind call)

    private func batchCheckAppsExist(_ bundleIds: Set<String>) -> Set<String> {
        // Use a single mdfind to get all installed app bundle IDs, much faster than per-app queries
        let result = ShellRunner.run("/usr/bin/mdfind", arguments: [
            "kMDItemContentType == 'com.apple.application-bundle'"
        ], timeout: 10)
        guard result.success else { return [] }

        // For each found app, try to read its bundle identifier
        var installedIds = Set<String>()
        let paths = result.stdout.split(separator: "\n").map { String($0) }
        for path in paths {
            let plistPath = "\(path)/Contents/Info.plist"
            guard let data = FileManager.default.contents(atPath: plistPath),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let bundleId = plist["CFBundleIdentifier"] as? String else { continue }
            if bundleIds.contains(bundleId) {
                installedIds.insert(bundleId)
            }
        }
        return installedIds
    }

    // MARK: - Accessibility API Abuse Detection

    private func analyzeAccessibilityGrants(_ allGrants: [TCCGrant], installedApps: Set<String>, findings: inout [Finding]) {
        let accessibilityGrants = allGrants.filter { $0.service == "kTCCServiceAccessibility" }
        let syntheticInputClients = Set(
            allGrants.filter { $0.service == "kTCCServicePostEvent" }.map { $0.client }
        )

        for grant in accessibilityGrants {
            let client = grant.client
            if whitelistedClients.contains(client) { continue }
            if knownAccessibilityApps.contains(client) { continue }
            if client.hasPrefix("com.apple.") { continue }

            if syntheticInputClients.contains(client) {
                findings.append(Finding(
                    severity: .high, category: .permission,
                    title: "App has Accessibility + Synthetic Input (click injection risk)",
                    detail: "Client: \(client) — can simulate clicks to grant itself more permissions",
                    path: nil,
                    remediation: "Revoke both permissions in System Settings > Privacy & Security"
                ))
                continue
            }

            let appExists = client.hasPrefix("/") || installedApps.contains(client)
            if !appExists {
                findings.append(Finding(
                    severity: .high, category: .permission,
                    title: "Accessibility granted to app not found on disk",
                    detail: "Client: \(client), Granted: \(grant.lastModified)",
                    path: nil,
                    remediation: "Revoke in System Settings > Privacy & Security > Accessibility"
                ))
            } else {
                findings.append(Finding(
                    severity: .medium, category: .permission,
                    title: "Non-standard app has Accessibility permission",
                    detail: "Client: \(client), Granted: \(grant.lastModified)",
                    path: nil,
                    remediation: "Verify this app needs Accessibility in System Settings > Privacy & Security"
                ))
            }
        }
    }

    // MARK: - TCC Database Integrity

    private func checkTCCIntegrity(grants: [TCCGrant], installedApps: Set<String>, findings: inout [Finding], errors: inout [String]) {
        let now = Date()
        let sipEra = Date(timeIntervalSince1970: 1577836800) // 2020-01-01

        for grant in grants {
            guard let epoch = grant.rawEpoch else { continue }
            let grantDate = Date(timeIntervalSince1970: epoch)

            if grantDate > now {
                findings.append(Finding(
                    severity: .medium, category: .permission,
                    title: "TCC grant has future timestamp",
                    detail: "Client: \(grant.client), Service: \(grant.serviceLabel), Date: \(grant.lastModified)",
                    path: nil,
                    remediation: "This may indicate TCC database tampering"
                ))
            } else if grantDate < sipEra {
                findings.append(Finding(
                    severity: .medium, category: .permission,
                    title: "TCC grant predates modern TCC enforcement",
                    detail: "Client: \(grant.client), Service: \(grant.serviceLabel), Date: \(grant.lastModified)",
                    path: nil,
                    remediation: "Old grant — verify this app still needs \(grant.serviceLabel) permission"
                ))
            }
        }

        // Check for grants to apps not on disk
        var checkedClients = Set<String>()
        for grant in grants {
            let client = grant.client
            if client.hasPrefix("/") || client.hasPrefix("com.apple.") { continue }
            if whitelistedClients.contains(client) { continue }
            if checkedClients.contains(client) { continue }
            checkedClients.insert(client)

            if !installedApps.contains(client) {
                findings.append(Finding(
                    severity: .medium, category: .permission,
                    title: "TCC grant to app not found on disk",
                    detail: "Client: \(client) has \(grant.serviceLabel) permission but app is not installed",
                    path: nil,
                    remediation: "Revoke stale permission or investigate if app was removed"
                ))
            }
        }
    }

    // MARK: - Login Items (sneaky persistence, doesn't require LaunchAgent)

    private func scanLoginItems(findings: inout [Finding], errors: inout [String]) {
        // Check SMAppService-registered login items via sfltool
        let result = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 10)
        if result.success && !result.stdout.isEmpty {
            let lines = result.stdout.split(separator: "\n")
            for line in lines {
                let lineStr = String(line)
                for sig in SpywareSignature.known {
                    for name in sig.processNames {
                        // Require word boundary match — short names like "bh" would match too broadly
                        let lowerLine = lineStr.lowercased()
                        let lowerName = name.lowercased()
                        // Use word boundary check: name must be preceded/followed by non-alphanumeric
                        if let range = lowerLine.range(of: lowerName) {
                            let before = range.lowerBound == lowerLine.startIndex ||
                                !lowerLine[lowerLine.index(before: range.lowerBound)].isLetter
                            let after = range.upperBound == lowerLine.endIndex ||
                                !lowerLine[range.upperBound].isLetter
                            if before && after {
                                findings.append(Finding(
                                    severity: .high, category: .persistence,
                                    title: "Known spyware registered as login item: \(sig.name)",
                                    detail: "Found \"\(name)\" in Background Task Management",
                                    path: nil,
                                    remediation: "Remove in System Settings > General > Login Items"
                                ))
                            }
                        }
                    }
                    for bundleId in sig.bundleIdentifiers where !bundleId.isEmpty {
                        if lineStr.contains(bundleId) {
                            findings.append(Finding(
                                severity: .high, category: .persistence,
                                title: "Known spyware registered as login item: \(sig.name)",
                                detail: "Bundle: \(bundleId)",
                                path: nil,
                                remediation: "Remove in System Settings > General > Login Items"
                            ))
                        }
                    }
                }
            }
        }

        // Check legacy login items via osascript
        let legacyResult = ShellRunner.run("/usr/bin/osascript", arguments: [
            "-e", "tell application \"System Events\" to get the name of every login item"
        ], timeout: 10)
        if legacyResult.success && !legacyResult.stdout.isEmpty {
            let items = legacyResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
                .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            for item in items {
                if let sig = SpywareSignature.match(processName: item) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Known spyware in legacy login items: \(sig.name)",
                        detail: "Login item: \(item)",
                        path: nil,
                        remediation: "Remove in System Settings > General > Login Items"
                    ))
                }
            }
        }
    }

    // MARK: - DYLIB Injection Detection

    private func scanDylibInjection(findings: inout [Finding], errors: inout [String]) {
        // Check for DYLD environment variables (used to inject libraries)
        let envVars = ["DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE", "DYLD_LIBRARY_PATH"]
        for envVar in envVars {
            if let value = ProcessInfo.processInfo.environment[envVar] {
                findings.append(Finding(
                    severity: .high, category: .suspiciousProcess,
                    title: "DYLD injection environment variable set: \(envVar)",
                    detail: "Value: \(value) — this is used to inject code into running processes",
                    path: nil,
                    remediation: "Check your shell profile (~/.zshrc, ~/.bash_profile) for this variable"
                ))
            }
        }

        // Check shell profiles for DYLD injection
        let home = ShellRunner.realUserHome
        let profileFiles = [
            "\(home)/.zshrc", "\(home)/.zshenv", "\(home)/.zprofile",
            "\(home)/.bashrc", "\(home)/.bash_profile", "\(home)/.profile",
            "/etc/zshrc", "/etc/profile",
        ]
        for profilePath in profileFiles {
            guard let content = try? String(contentsOfFile: profilePath, encoding: .utf8) else { continue }
            for envVar in envVars {
                if content.contains(envVar) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "DYLD injection found in shell profile",
                        detail: "\(envVar) is set in \(profilePath)",
                        path: profilePath,
                        remediation: "Inspect and remove the DYLD line from this file"
                    ))
                }
            }
        }
    }

    // MARK: - Cron Jobs

    private func scanCronJobs(findings: inout [Finding], errors: inout [String]) {
        // Check user crontab
        let result = ShellRunner.run("/usr/bin/crontab", arguments: ["-l"], timeout: 5)
        if result.success && !result.stdout.isEmpty {
            let lines = result.stdout.split(separator: "\n").filter { !$0.hasPrefix("#") && !$0.isEmpty }
            for line in lines {
                let lineStr = String(line)
                // Check for known spyware in cron entries
                for sig in SpywareSignature.known {
                    for name in sig.processNames {
                        if lineStr.lowercased().contains(name.lowercased()) {
                            findings.append(Finding(
                                severity: .high, category: .persistence,
                                title: "Known spyware in cron job: \(sig.name)",
                                detail: "Cron entry: \(lineStr)",
                                path: nil,
                                remediation: "Remove with: crontab -e"
                            ))
                        }
                    }
                }
                // Flag cron jobs that touch screenshots/keylog-like paths
                let suspicious = ["screenshot", "keylog", "capture", "record", "screen"]
                for keyword in suspicious {
                    if lineStr.lowercased().contains(keyword) {
                        findings.append(Finding(
                            severity: .medium, category: .persistence,
                            title: "Suspicious cron job",
                            detail: "Entry contains \"\(keyword)\": \(lineStr)",
                            path: nil,
                            remediation: "Review with: crontab -l"
                        ))
                    }
                }
            }
        }

        // Check /etc/crontab and /var/at/tabs/
        for cronPath in ["/etc/crontab", "/var/at/tabs/root"] {
            guard let content = try? String(contentsOfFile: cronPath, encoding: .utf8) else { continue }
            for sig in SpywareSignature.known {
                for name in sig.processNames {
                    if content.lowercased().contains(name.lowercased()) {
                        findings.append(Finding(
                            severity: .high, category: .persistence,
                            title: "Known spyware in system cron: \(sig.name)",
                            detail: "Found in \(cronPath)",
                            path: cronPath,
                            remediation: "Inspect and clean \(cronPath)"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - TCC Log Analysis

    private func scanTCCLog(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/log", arguments: [
            "show", "--predicate",
            "subsystem == \"com.apple.TCC\" AND category == \"access\"",
            "--style", "compact",
            "--last", "1h",
            "--info"
        ], timeout: 15)

        guard result.success && !result.stdout.isEmpty else { return }

        let lines = result.stdout.split(separator: "\n")
        var accessCounts: [String: Int] = [:]
        for line in lines {
            let lineStr = String(line)
            if lineStr.contains("kTCCServiceScreenCapture") || lineStr.contains("kTCCServiceListenEvent") ||
               lineStr.contains("kTCCServiceCamera") || lineStr.contains("kTCCServiceMicrophone") {
                for sig in SpywareSignature.known {
                    for processName in sig.processNames {
                        if lineStr.lowercased().contains(processName.lowercased()) {
                            accessCounts[sig.name, default: 0] += 1
                        }
                    }
                    for bundleId in sig.bundleIdentifiers {
                        if lineStr.contains(bundleId) {
                            accessCounts[sig.name, default: 0] += 1
                        }
                    }
                }
            }
        }

        for (spywareName, count) in accessCounts where count > 0 {
            findings.append(Finding(
                severity: .high, category: .permission,
                title: "Known spyware in TCC access log: \(spywareName)",
                detail: "\(count) TCC access event(s) in the last hour",
                path: nil,
                remediation: "This spyware has been actively requesting privacy permissions"
            ))
        }
    }

    // MARK: - TCC Database Query

    private struct TCCGrant {
        let client: String
        let service: String
        let serviceLabel: String
        let lastModified: String
        let rawEpoch: Double?
    }

    private func queryTCC(dbPath: String, errors: inout [String], label: String) -> [TCCGrant] {
        guard FileManager.default.fileExists(atPath: dbPath) else { return [] }

        let tempPath = "/tmp/anti-spy-tcc-\(UUID().uuidString).db"
        let copyResult = ShellRunner.run("/bin/cp", arguments: [dbPath, tempPath])
        let queryPath = copyResult.success ? tempPath : dbPath
        defer { try? FileManager.default.removeItem(atPath: tempPath) }

        var grants: [TCCGrant] = []

        for (service, serviceLabel) in tccServices {
            let query = "SELECT client, auth_value, last_modified FROM access WHERE service = '\(service)' AND auth_value = 2;"
            let result = ShellRunner.run("/usr/bin/sqlite3", arguments: ["-separator", "|", queryPath, query])

            if !result.success {
                if result.stderr.contains("not authorized") || result.stderr.contains("unable to open") ||
                   result.stderr.contains("Operation not permitted") {
                    errors.append("\(label): TCC database locked (grant Terminal Full Disk Access)")
                    return grants
                }
                continue
            }

            for line in result.stdout.split(separator: "\n") {
                let parts = line.split(separator: "|", maxSplits: 2)
                guard parts.count >= 2 else { continue }
                let rawTs = parts.count > 2 ? String(parts[2]).trimmingCharacters(in: .whitespaces) : nil
                let epoch = rawTs.flatMap { Double($0) }
                grants.append(TCCGrant(
                    client: String(parts[0]),
                    service: service,
                    serviceLabel: serviceLabel,
                    lastModified: parts.count > 2 ? formatTimestamp(String(parts[2])) : "unknown",
                    rawEpoch: epoch
                ))
            }
        }

        return grants
    }

    private func formatTimestamp(_ ts: String) -> String {
        guard let epoch = Double(ts.trimmingCharacters(in: .whitespaces)) else { return ts }
        let date = Date(timeIntervalSince1970: epoch)
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd"
        return fmt.string(from: date)
    }
}
