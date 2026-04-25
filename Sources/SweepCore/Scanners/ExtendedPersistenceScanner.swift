import Foundation
import Security

/// Audits macOS-specific persistence vectors that fall outside the LaunchAgent /
/// LaunchDaemon / cron / shell-init paths covered by `PersistenceScanner`.
///
/// These mechanisms are documented as legitimate macOS extension points but are
/// also reused by post-2023 stalkerware, infostealers, and APT-grade implants
/// (e.g. AdLoad's SMAppService persistence, BlueNoroff authorization plug-ins,
/// LightSpy folder-action droppers). Any unsigned or non-Apple bundle in these
/// directories runs code with the privileges of whichever process loads them —
/// `mds`, `quicklookd`, `coreaudiod`, `SecurityAgent`, etc.
public final class ExtendedPersistenceScanner: Scanner {
    public let name = "Extended Persistence Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking Spotlight importers")
        scanBundleDirs(
            paths: ["/Library/Spotlight", "~/Library/Spotlight"],
            ext: ".mdimporter",
            kind: "Spotlight importer",
            loader: "mds / mdworker",
            severity: .medium,
            findings: &findings
        )

        progress?.update("checking Quick Look generators")
        scanBundleDirs(
            paths: ["/Library/QuickLook", "~/Library/QuickLook"],
            ext: ".qlgenerator",
            kind: "Quick Look generator",
            loader: "quicklookd",
            severity: .medium,
            findings: &findings
        )

        progress?.update("checking color picker plug-ins")
        scanBundleDirs(
            paths: ["/Library/ColorPickers", "~/Library/ColorPickers"],
            ext: ".colorPicker",
            kind: "Color picker plug-in",
            loader: "any app showing the system color panel",
            severity: .low,
            findings: &findings
        )

        progress?.update("checking authorization plug-ins")
        checkAuthorizationPlugins(findings: &findings, errors: &errors)

        progress?.update("checking Folder Action scripts")
        checkFolderActionScripts(findings: &findings, errors: &errors)

        progress?.update("checking Core Audio HAL plug-ins")
        scanBundleDirs(
            paths: ["/Library/Audio/Plug-Ins/HAL", "~/Library/Audio/Plug-Ins/HAL"],
            ext: ".driver",
            kind: "Core Audio HAL plug-in",
            loader: "coreaudiod",
            severity: .medium,
            findings: &findings
        )

        progress?.update("checking screen savers")
        scanBundleDirs(
            paths: ["/Library/Screen Savers", "~/Library/Screen Savers"],
            ext: ".saver",
            kind: "Screen saver bundle",
            loader: "legacyScreenSaver / ScreenSaverEngine",
            severity: .low,
            findings: &findings
        )

        progress?.update("checking system extensions")
        checkSystemExtensions(findings: &findings, errors: &errors)

        progress?.update("checking Background Task Management items")
        checkBackgroundTaskManagement(findings: &findings, errors: &errors)

        progress?.update("checking at(1) jobs")
        checkAtJobs(findings: &findings, errors: &errors)

        progress?.update("checking AppleScript handlers")
        checkApplicationScripts(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Generic plug-in bundle scan

    /// Walks each `path` for top-level entries ending with `ext`. Apple-signed
    /// bundles are silently skipped — all other entries are reported, with
    /// severity escalated if the bundle is unsigned.
    private func scanBundleDirs(
        paths: [String],
        ext: String,
        kind: String,
        loader: String,
        severity: Severity,
        findings: inout [Finding]
    ) {
        for rawPath in paths {
            let dir = SpywareSignature.expandPath(rawPath)
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            let isUserScope = rawPath.hasPrefix("~/")

            for entry in entries where entry.hasSuffix(ext) {
                let full = "\(dir)/\(entry)"
                if isAppleSigned(path: full) { continue }

                let signed = isCodesignValid(path: full)
                let scopeNote = isUserScope ? "user" : "system"
                let signNote = signed ? "signed by a third party" : "code signature missing or invalid"
                let effective: Severity = signed ? severity : .high

                findings.append(Finding(
                    severity: effective,
                    category: .persistence,
                    title: "\(kind) installed (\(scopeNote))",
                    detail: "\(entry) is loaded automatically by \(loader); \(signNote)",
                    path: full,
                    remediation: "Verify the publisher. To remove: \(isUserScope ? "" : "sudo ")rm -rf '\(full)'"
                ))
            }
        }
    }

    // MARK: - Authorization plug-ins

    /// `/Library/Security/SecurityAgentPlugins` is loaded by SecurityAgent at every
    /// authentication prompt — including login window, sudo, and Touch ID dialogs.
    /// A rogue plug-in here can harvest passwords or silently approve auth requests
    /// (the technique used by APT/BlueNoroff implants like NokNok).
    private func checkAuthorizationPlugins(findings: inout [Finding], errors: inout [String]) {
        let pluginDir = "/Library/Security/SecurityAgentPlugins"
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: pluginDir) else { return }

        for entry in entries where entry.hasSuffix(".bundle") {
            let full = "\(pluginDir)/\(entry)"
            if isAppleSigned(path: full) { continue }

            let signed = isCodesignValid(path: full)
            findings.append(Finding(
                severity: .high,
                category: .persistence,
                title: "Non-Apple authorization plug-in present",
                detail: "Bundle '\(entry)' loads inside SecurityAgent at every authentication prompt — capable of capturing or silently approving credentials\(signed ? "" : " (unsigned)")",
                path: full,
                remediation: "Inspect with: codesign -dvvv '\(full)'. Remove with: sudo rm -rf '\(full)' (Apple's Smart Card token bundle is the only legitimate non-vendor entry)."
            ))
        }
    }

    // MARK: - Folder Action scripts

    /// Folder Actions attach AppleScript handlers to filesystem events on a
    /// directory (created/added/removed). Modern stalkerware uses them to
    /// trigger uploads of new screenshots or downloads.
    private func checkFolderActionScripts(findings: inout [Finding], errors: inout [String]) {
        let dir = SpywareSignature.expandPath("~/Library/Scripts/Folder Action Scripts")
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
        for entry in entries where !entry.hasPrefix(".") {
            let full = "\(dir)/\(entry)"
            findings.append(Finding(
                severity: .medium,
                category: .persistence,
                title: "Folder Action script present",
                detail: "AppleScript '\(entry)' runs automatically when an attached folder changes — common exfiltration trigger",
                path: full,
                remediation: "Inspect with: cat '\(full)'. Detach via Automator > Folder Actions Setup, or remove with: rm '\(full)'"
            ))
        }
    }

    // MARK: - Application Scripts (sandbox-escape persistence)

    /// `~/Library/Application Scripts/<bundle-id>` is the only writable directory a
    /// sandboxed app shares with another app's NSUserScriptTask handler. XCSSET and
    /// several stealers drop AppleScript here to be invoked by another app
    /// (often `com.apple.systempreferences`).
    private func checkApplicationScripts(findings: inout [Finding], errors: inout [String]) {
        let baseDir = SpywareSignature.expandPath("~/Library/Application Scripts")
        guard let bundles = try? FileManager.default.contentsOfDirectory(atPath: baseDir) else { return }

        for bundle in bundles where !bundle.hasPrefix(".") {
            let bundleDir = "\(baseDir)/\(bundle)"
            guard let scripts = try? FileManager.default.contentsOfDirectory(atPath: bundleDir) else { continue }
            for script in scripts where script.hasSuffix(".scpt") || script.hasSuffix(".applescript") {
                let full = "\(bundleDir)/\(script)"
                let suspicious = bundle.hasPrefix("com.apple.")
                findings.append(Finding(
                    severity: suspicious ? .high : .low,
                    category: .persistence,
                    title: suspicious
                        ? "AppleScript handler installed under Apple bundle ID"
                        : "AppleScript handler installed under '\(bundle)'",
                    detail: "\(script) can be invoked by '\(bundle)' via NSUserScriptTask — XCSSET-style sandbox escape vector",
                    path: full,
                    remediation: "Inspect: osadecompile '\(full)'. Remove if unexpected: rm '\(full)'"
                ))
            }
        }
    }

    // MARK: - System extensions (modern replacement for kexts)

    /// `systemextensionsctl list` enumerates DriverKit and EndpointSecurity
    /// extensions. Apple-signed entries are skipped; everything else is surfaced
    /// because system extensions run with high privilege and survive reboot.
    private func checkSystemExtensions(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/systemextensionsctl", arguments: ["list"], timeout: 10)
        guard result.success else {
            if !result.stderr.isEmpty {
                errors.append("systemextensionsctl: \(result.stderr.prefix(200))")
            }
            return
        }

        for raw in result.stdout.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            // Activated rows start with a star/check marker followed by team-id and bundle-id columns.
            guard line.contains("[activated") || line.contains("activated enabled") else { continue }
            // Skip Apple system bundles
            let lower = line.lowercased()
            if lower.contains("com.apple.") || lower.contains("apple inc") { continue }

            findings.append(Finding(
                severity: .medium,
                category: .kernelExtension,
                title: "Non-Apple system extension active",
                detail: line,
                path: nil,
                remediation: "Audit with: systemextensionsctl list. Remove via the providing app, or boot to recovery and run: systemextensionsctl uninstall <teamID> <bundleID>"
            ))
        }
    }

    // MARK: - Background Task Management (Ventura+)

    /// `sfltool dumpbtm` is the unified database backing the new Login Items pane.
    /// It records every SMAppService-registered helper, agent, daemon, and login
    /// item — the persistence vector now used by AdLoad, modern adware bundles,
    /// and several 2024 infostealers because BTM entries don't appear in the
    /// classic LaunchAgents directories.
    private func checkBackgroundTaskManagement(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 20)
        guard result.success else {
            // sfltool requires root for the system-scope dump. The user-scope dump usually works.
            if !result.stderr.isEmpty {
                errors.append("sfltool dumpbtm: \(result.stderr.prefix(200))")
            }
            return
        }

        var name = ""
        var dev = ""
        var path = ""
        var type = ""
        var dispo = ""
        var pending = false

        func flush() {
            defer { pending = false; name = ""; dev = ""; path = ""; type = ""; dispo = "" }
            guard pending, !name.isEmpty else { return }

            let lowerDev = dev.lowercased()
            let lowerPath = path.lowercased()
            // Drop Apple's own entries — there are dozens and none are interesting.
            if lowerDev.contains("apple inc") || lowerDev == "apple" { return }
            if lowerPath.hasPrefix("/system/") || lowerPath.hasPrefix("/library/apple/") { return }

            // Spyware signature match against the recorded name or executable path.
            let lowerName = name.lowercased()
            let knownHit = SpywareSignature.allProcessNames.first { hit in
                lowerName.contains(hit) || lowerPath.contains(hit)
            }
            let isKnown = knownHit != nil

            findings.append(Finding(
                severity: isKnown ? .high : .low,
                category: .persistence,
                title: isKnown
                    ? "Background Task Management entry matches known spyware: \(name)"
                    : "Background Task Management entry: \(name)",
                detail: "type=\(type.isEmpty ? "?" : type), developer=\(dev.isEmpty ? "?" : dev), disposition=\(dispo.isEmpty ? "?" : dispo)",
                path: path.isEmpty ? nil : path,
                remediation: "Review: System Settings > General > Login Items & Extensions. Remove by uninstalling the providing app or via: sfltool resetbtm (resets all entries)."
            ))
        }

        for raw in result.stdout.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("name:") {
                flush()
                name = String(line.dropFirst("name:".count)).trimmingCharacters(in: .whitespaces)
                pending = true
            } else if line.hasPrefix("developer name:") {
                dev = String(line.dropFirst("developer name:".count)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("developerName:") {
                dev = String(line.dropFirst("developerName:".count)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("executable path:") {
                path = String(line.dropFirst("executable path:".count)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("executablePath:") {
                path = String(line.dropFirst("executablePath:".count)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("type:") {
                type = String(line.dropFirst("type:".count)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("disposition:") {
                dispo = String(line.dropFirst("disposition:".count)).trimmingCharacters(in: .whitespaces)
            }
        }
        flush()
    }

    // MARK: - at(1) jobs

    /// `at` schedules one-shot commands via `atrun(8)`. `at` is disabled by default
    /// on modern macOS but the queue directory survives — any file under it is
    /// executed when the queue is enabled, making it a stealthy scheduler few
    /// users (or scanners) inspect.
    private func checkAtJobs(findings: inout [Finding], errors: inout [String]) {
        let dir = "/var/at/jobs"
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
        let jobs = entries.filter { $0 != ".SEQ" && !$0.hasPrefix(".") }
        guard !jobs.isEmpty else { return }
        findings.append(Finding(
            severity: .medium,
            category: .persistence,
            title: "Scheduled at(1) job(s) present (\(jobs.count))",
            detail: "Files in /var/at/jobs run via atrun on a schedule — uncommon on macOS and a stealth scheduler often used by malware to survive reboots without a LaunchAgent",
            path: dir,
            remediation: "List with: atq. Remove individual jobs with: atrm <job-id>. Disable atrun: sudo launchctl disable system/com.apple.atrun"
        ))
    }

    // MARK: - Code-signing helpers

    private func isCodesignValid(path: String) -> Bool {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return false }
        return SecStaticCodeCheckValidityWithErrors(code, SecCSFlags(rawValue: 0), nil, nil) == errSecSuccess
    }

    private func isAppleSigned(path: String) -> Bool {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return false }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
              let req = requirement else { return false }
        return SecStaticCodeCheckValidityWithErrors(code, [], req, nil) == errSecSuccess
    }
}
