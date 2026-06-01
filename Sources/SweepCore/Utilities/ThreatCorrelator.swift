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

        // Pattern 6: AppleScript dropper + recent persistence = active staging
        // 2024-2025 macOS stealers (AMOS, Banshee, Poseidon, BeaverTail) commonly stage as
        // .scpt/.applescript files in /tmp that then install a persistent LaunchAgent. Seeing
        // both in the same scan is high-confidence evidence of an in-flight infection.
        let persistenceResult = results.first(where: { $0.scannerName == "Persistence Scan" })
        let appleScriptDropper = persistenceResult?.findings
            .first(where: { $0.title.contains("AppleScript file staged in temp") })
        let recentLaunchAgent = persistenceResult?.findings
            .first(where: { $0.title.contains("Unsigned executable set to run at login") ||
                            $0.title.contains("hidden path") ||
                            $0.title.contains("Fake Apple bundle ID") })

        if appleScriptDropper != nil && recentLaunchAgent != nil {
            findings.append(Finding(
                severity: .high,
                category: .suspiciousFile,
                title: "AppleScript dropper + suspicious LaunchAgent",
                detail: "An AppleScript was staged in /tmp and a suspicious LaunchAgent was installed — classic AMOS/Banshee/Poseidon installation pattern",
                path: appleScriptDropper?.path,
                remediation: "Treat as an active stealer infection: kill suspicious processes, remove the LaunchAgent, rotate browser passwords and any wallet seed phrases."
            ))
        }

        // Pattern 7: Credential staging + active network = exfiltration in progress
        // Distinct from pattern 4 — this looks specifically for browser-credential-store theft
        // (the AMOS-family signature payload) combined with outbound connections.
        let credentialStaging = (results.first(where: { $0.scannerName == "Evidence Scan" })?.findings ?? [])
            .filter { $0.title.contains("credential store copied") || $0.title.contains("Crypto wallet files staged") }
        if !credentialStaging.isEmpty && hasActiveNetwork {
            findings.append(Finding(
                severity: .high,
                category: .suspiciousFile,
                title: "Credential / wallet files staged with active network",
                detail: "\(credentialStaging.count) credential or wallet artifact(s) staged outside their legitimate location while suspicious network activity is present — likely exfiltration in progress",
                path: credentialStaging.first?.path,
                remediation: "Disconnect from network immediately. Rotate all browser passwords and move crypto funds to fresh wallets."
            ))
        }

        // Pattern 8: Tor anonymizer + persistence = covert C2
        // A process routing through Tor that also has a persistence mechanism is a hallmark
        // of modern macOS RATs that want stealthy survival.
        let networkResult = results.first(where: { $0.scannerName == "Network Scan" })
        let usesTorProxy = networkResult?.findings.contains(where: { $0.title.contains("Tor") }) ?? false
        let hasPersistence = !(persistenceResult?.findings.isEmpty ?? true)
        if usesTorProxy && hasPersistence {
            findings.append(Finding(
                severity: .high,
                category: .networkActivity,
                title: "Anonymized network traffic + persistence",
                detail: "A process is routing through Tor and persistence is installed — classic covert C2 setup",
                path: nil,
                remediation: "Investigate Network and Persistence findings together — treat the persistence entry as malicious"
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
