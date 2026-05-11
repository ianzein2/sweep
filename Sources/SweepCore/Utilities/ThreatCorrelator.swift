import Foundation

/// Cross-scanner threat correlation.
/// After all scanners run, this looks for patterns that individually might be LOW/MEDIUM
/// but together indicate HIGH-confidence spyware.
public enum ThreatCorrelator {
    public static func correlate(_ results: [ScanResult]) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []

        // Extract paths and identifiers mentioned across scanners
        var pathsBySeverity: [String: Severity] = [:]
        var processFindings: [String: [(scanner: String, finding: Finding)]] = [:]

        for result in results {
            for finding in result.findings {
                if let path = finding.path {
                    if let existing = pathsBySeverity[path] {
                        if finding.severity > existing { pathsBySeverity[path] = finding.severity }
                    } else {
                        pathsBySeverity[path] = finding.severity
                    }
                }

                let identifiers = extractIdentifiers(from: finding)
                for id in identifiers {
                    processFindings[id, default: []].append((scanner: result.scannerName, finding: finding))
                }
            }
        }

        // Pattern 1: Same entity flagged by multiple scanners
        for (identifier, scannerFindings) in processFindings {
            let uniqueScanners = Set(scannerFindings.map { $0.scanner })
            if uniqueScanners.count >= 3 {
                // Flagged by 3+ different scanners — very suspicious
                let scannerList = uniqueScanners.sorted().joined(separator: ", ")
                let maxSeverity = scannerFindings.map { $0.finding.severity }.max() ?? .medium

                // Only escalate if not already HIGH
                if maxSeverity < .high {
                    findings.append(Finding(
                        severity: .high,
                        category: .suspiciousProcess,
                        title: "Multi-scanner threat: \(identifier)",
                        detail: "Flagged by \(uniqueScanners.count) independent scanners: \(scannerList)",
                        path: scannerFindings.first?.finding.path,
                        remediation: "This entity was flagged by multiple detection methods — investigate immediately"
                    ))
                }
            }
        }

        // Pattern 2: Unsigned process + network connection + persistence = spyware
        let processFlags = Set(
            results.first(where: { $0.scannerName == "Process Scan" })?
                .findings.compactMap { $0.path } ?? []
        )
        let networkFlags = Set(
            results.first(where: { $0.scannerName == "Network Scan" })?
                .findings.compactMap { $0.path } ?? []
        )
        let persistenceFlags = Set(
            results.first(where: { $0.scannerName == "Persistence Scan" })?
                .findings.compactMap { extractExecutablePath(from: $0) } ?? []
        )

        let processAndNetwork = processFlags.intersection(networkFlags)
        for path in processAndNetwork {
            if persistenceFlags.contains(path) {
                findings.append(Finding(
                    severity: .high,
                    category: .suspiciousProcess,
                    title: "Suspicious trifecta: unsigned + network + persistence",
                    detail: "Binary is unsigned, makes network connections, and has persistence — classic spyware pattern",
                    path: path,
                    remediation: "Investigate this binary immediately — it exhibits all three hallmarks of spyware"
                ))
            }
        }

        // Pattern 3: Event tap + hidden persistence = keylogger
        let eventTapFindings = results.first(where: { $0.scannerName == "Event Tap Scan" })?.findings ?? []
        let hiddenPersistence = results.first(where: { $0.scannerName == "Persistence Scan" })?
            .findings.filter { $0.title.contains("hidden") } ?? []

        if !eventTapFindings.isEmpty && !hiddenPersistence.isEmpty {
            findings.append(Finding(
                severity: .high,
                category: .keylogging,
                title: "Keyboard interception + hidden persistence detected",
                detail: "An active keyboard event tap combined with hidden launch persistence is a strong keylogger indicator",
                path: nil,
                remediation: "Check Event Tap and Persistence findings above — these likely belong to the same keylogger"
            ))
        }

        // Pattern 4: Evidence of stored data + active network = exfiltration in progress
        let evidenceFindings = results.first(where: { $0.scannerName == "Evidence Scan" })?.findings ?? []
        let hasStoredScreenshots = evidenceFindings.contains { $0.category == .screenCapture }
        let hasStoredKeylogs = evidenceFindings.contains { $0.category == .keylogging }
        let hasActiveNetwork = !(results.first(where: { $0.scannerName == "Network Scan" })?.findings.isEmpty ?? true)

        if (hasStoredScreenshots || hasStoredKeylogs) && hasActiveNetwork {
            findings.append(Finding(
                severity: .high,
                category: .suspiciousProcess,
                title: "Stored spy artifacts + active network connections",
                detail: "Found \(hasStoredScreenshots ? "stored screenshots" : "keystroke logs") combined with suspicious network activity — possible data exfiltration",
                path: nil,
                remediation: "Disconnect from network and investigate the Evidence Scan and Network Scan findings"
            ))
        }

        // Pattern 5: SIP disabled + unsigned processes = wide open
        let sipDisabled = results.first(where: { $0.scannerName == "System Integrity Scan" })?
            .findings.contains { $0.title.contains("SIP") && $0.severity == .high } ?? false
        let unsignedProcessCount = results.first(where: { $0.scannerName == "Process Scan" })?
            .findings.filter { $0.title.contains("Unsigned") }.count ?? 0

        if sipDisabled && unsignedProcessCount > 0 {
            findings.append(Finding(
                severity: .high,
                category: .systemIntegrity,
                title: "SIP disabled with \(unsignedProcessCount) unsigned process(es) running",
                detail: "System Integrity Protection is off and unsigned code is running — system may be compromised",
                path: nil,
                remediation: "Re-enable SIP in Recovery Mode, then investigate unsigned processes"
            ))
        }

        // Pattern 6: Apple Events automation + Accessibility = AppleScript-based
        // backdoor. The 2024-2025 wave of macOS stalkerware (BeaverTail/ZuRu kin)
        // relies on osascript and Apple Events to drive other apps invisibly.
        let permissionFindings = results.first(where: { $0.scannerName == "Permission Scan" })?.findings ?? []
        let hasAutomationPlus = permissionFindings.contains {
            $0.title.contains("Automation + Accessibility") ||
            $0.title.contains("Automation (Apple Events)")
        }
        let hasSuspiciousAppleScriptPersistence = (results.first(where: { $0.scannerName == "Persistence Scan" })?.findings ?? [])
            .contains { f in
                let lower = (f.path ?? "").lowercased() + " " + f.detail.lowercased()
                return lower.contains("osascript") || lower.contains(".scpt") || lower.contains("applescript")
            }
        if hasAutomationPlus && hasSuspiciousAppleScriptPersistence {
            findings.append(Finding(
                severity: .high,
                category: .keylogging,
                title: "AppleScript automation backdoor pattern detected",
                detail: "An app holds Automation + Accessibility while a LaunchAgent invokes osascript — classic macOS AppleScript-based RAT footprint",
                path: nil,
                remediation: "Revoke Automation in System Settings > Privacy & Security and remove the AppleScript persistence"
            ))
        }

        // Pattern 7: Supply-chain compromise. A redirected npm/pip registry combined
        // with a suspicious shell-config command means every dev build can pull
        // tampered packages and the shell is set up to run their payload.
        let persistenceFindings = results.first(where: { $0.scannerName == "Persistence Scan" })?.findings ?? []
        let hasRegistryHijack = persistenceFindings.contains { $0.title.contains("registry redirected") || $0.title.contains("package index redirected") }
        let hasShellHijack = persistenceFindings.contains { $0.title.contains("Suspicious command in") || $0.title.contains("Malicious git alias") }
        if hasRegistryHijack && hasShellHijack {
            findings.append(Finding(
                severity: .high,
                category: .suspiciousProcess,
                title: "Developer supply-chain compromise pattern",
                detail: "Package manager is pointed at a non-default host AND your shell/git config runs external code — your next build could install attacker code",
                path: nil,
                remediation: "Restore the default registries, audit ~/.gitconfig and shell profiles, then `npm cache clean --force` before building again"
            ))
        }

        // Pattern 8: Recent risky download still on disk + active unsigned process.
        // The quarantine DB sees the download moment; the process scanner sees the
        // result of opening it.
        let deepFindings = results.first(where: { $0.scannerName == "Deep Inspection Scan" })?.findings ?? []
        let hasRiskyDownload = deepFindings.contains {
            $0.title.contains("download from suspicious host") ||
            $0.title.contains("missing quarantine attribute")
        }
        let hasUnsignedRunning = (results.first(where: { $0.scannerName == "Process Scan" })?.findings ?? [])
            .contains { $0.title.contains("Unsigned") || $0.title.contains("Ad-hoc signed") }
        if hasRiskyDownload && hasUnsignedRunning {
            findings.append(Finding(
                severity: .high,
                category: .suspiciousProcess,
                title: "Risky recent download is likely the unsigned process running now",
                detail: "A file was downloaded from a known malware-staging host and an unsigned process is currently running — the two are probably the same payload",
                path: nil,
                remediation: "Identify the unsigned process, terminate it, then remove the matching download from ~/Downloads"
            ))
        }

        return ScanResult(
            scannerName: "Threat Correlation",
            findings: findings,
            errors: [],
            duration: Date().timeIntervalSince(start)
        )
    }

    private static func extractIdentifiers(from finding: Finding) -> [String] {
        var ids: [String] = []

        // Extract from path
        if let path = finding.path {
            let filename = URL(fileURLWithPath: path).lastPathComponent
            if !filename.isEmpty { ids.append(filename) }
        }

        // Extract "Process: X" or "Client: X" from detail
        let detail = finding.detail
        if let range = detail.range(of: "Process: ") {
            let rest = detail[range.upperBound...]
            let name = String(rest.prefix(while: { $0 != "," && $0 != " " && $0 != "(" }))
            if !name.isEmpty { ids.append(name) }
        }
        if let range = detail.range(of: "Client: ") {
            let rest = detail[range.upperBound...]
            let name = String(rest.prefix(while: { $0 != "," && $0 != " " }))
            if !name.isEmpty { ids.append(name) }
        }

        return ids
    }

    private static func extractExecutablePath(from finding: Finding) -> String? {
        let detail = finding.detail
        // Look for executable paths in persistence findings
        if let range = detail.range(of: "Missing: ") {
            return String(detail[range.upperBound...]).trimmingCharacters(in: .whitespaces)
        }
        return finding.path
    }
}
