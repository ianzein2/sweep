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

        // Pattern 6: Hidden user account + SSH key + sudo NOPASSWD = persistent backdoor
        let persistenceResults = results.first(where: { $0.scannerName == "Persistence Scan" })
        let hasHiddenUser = persistenceResults?.findings.contains {
            $0.title.contains("Hidden") && ($0.title.contains("admin user") || $0.title.contains("user account"))
        } ?? false
        let hasSSHKey = persistenceResults?.findings.contains {
            $0.title.contains("SSH authorized key")
        } ?? false
        let hasNopasswd = persistenceResults?.findings.contains {
            $0.title.contains("Passwordless sudo")
        } ?? false

        let backdoorIndicators = [hasHiddenUser, hasSSHKey, hasNopasswd].filter { $0 }.count
        if backdoorIndicators >= 2 {
            findings.append(Finding(
                severity: .high,
                category: .persistence,
                title: "Multiple remote-access backdoor indicators",
                detail: "Combination present: " +
                    (hasHiddenUser ? "hidden user account, " : "") +
                    (hasSSHKey ? "SSH authorized key, " : "") +
                    (hasNopasswd ? "passwordless sudo entry, " : "") +
                    "— individually unusual, together a classic post-compromise backdoor pattern",
                path: nil,
                remediation: "Review each finding in the Persistence Scan above — these often belong to the same backdoor"
            ))
        }

        // Pattern 7: Recent suspicious package install + unsigned process + persistence = post-install compromise
        let deepResults = results.first(where: { $0.scannerName == "Deep Inspection Scan" })
        let hasRecentPkg = deepResults?.findings.contains {
            $0.title.contains("Recent non-Apple package install")
        } ?? false
        let hasUnsignedPersistence = persistenceResults?.findings.contains {
            $0.title.lowercased().contains("unsigned") && $0.severity >= .medium
        } ?? false
        if hasRecentPkg && hasUnsignedPersistence {
            findings.append(Finding(
                severity: .high,
                category: .persistence,
                title: "Recent installer + new unsigned persistence",
                detail: "A non-Apple package was installed recently and an unsigned LaunchAgent/Daemon was added — packages can run preinstall/postinstall scripts as root",
                path: nil,
                remediation: "Cross-reference the install date with the persistence file's creation time"
            ))
        }

        // Pattern 8: Plug-in surface persistence (QuickLook/Spotlight/Mail/Screen Saver) + network = covert payload
        let pluginPersistence = persistenceResults?.findings.contains {
            $0.title.contains("QuickLook plugin") ||
            $0.title.contains("Spotlight importer") ||
            $0.title.contains("Mail bundle") ||
            $0.title.contains("screen saver is unsigned")
        } ?? false
        let networkFindings = results.first(where: { $0.scannerName == "Network Scan" })?.findings ?? []
        let hasUnsignedNetwork = networkFindings.contains { $0.title.contains("Unsigned process with network") }

        if pluginPersistence && hasUnsignedNetwork {
            findings.append(Finding(
                severity: .high,
                category: .persistence,
                title: "Plug-in persistence + unsigned network activity",
                detail: "An unsigned plug-in (QuickLook / Spotlight / Mail / screen saver) is installed and an unsigned process is making network calls — likely related",
                path: nil,
                remediation: "Inspect both findings together; plug-ins are a stealth alternative to LaunchAgents"
            ))
        }

        // Pattern 9: Browser native-messaging host + dangerous browser extension = sandbox escape vector
        let hasNativeHost = deepResults?.findings.contains {
            $0.title.contains("native messaging host")
        } ?? false
        let browserResults = results.first(where: { $0.scannerName == "Browser Extension Scan" })
        let hasBroadExtension = browserResults?.findings.contains {
            $0.title.contains("broad permissions") || $0.title.contains("spy-like")
        } ?? false
        if hasNativeHost && hasBroadExtension {
            findings.append(Finding(
                severity: .high,
                category: .suspiciousProcess,
                title: "Broad-permission browser extension + native messaging host",
                detail: "An extension with wide permissions has a registered native messaging host — combined, these can execute code outside the browser sandbox",
                path: nil,
                remediation: "Identify the extension and remove it, then delete the native host manifest"
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
