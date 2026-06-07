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

        // Pattern 6: Stealer fingerprint — browser credential copy + crypto wallet staging +
        // active outbound network = AMOS / Banshee / Poseidon / Atomic-family campaign in progress.
        let evidenceForCorrelation = results.first(where: { $0.scannerName == "Evidence Scan" })?.findings ?? []
        let stolenCreds = evidenceForCorrelation.contains { $0.title.contains("credential store") }
        let stolenWallet = evidenceForCorrelation.contains { $0.title.contains("wallet files staged") }
        let stolenCredsByDevEnv = (results.first(where: { $0.scannerName == "Dev Environment Scan" })?
            .findings.contains { $0.title.contains("credential-shaped file in temp") }) ?? false
        let networkActive = !(results.first(where: { $0.scannerName == "Network Scan" })?.findings.isEmpty ?? true)
        if (stolenCreds || stolenWallet || stolenCredsByDevEnv) && networkActive {
            findings.append(Finding(
                severity: .high,
                category: .suspiciousProcess,
                title: "Infostealer fingerprint: credentials staged + active network",
                detail: "AMOS-family stealers (Atomic, Banshee, Poseidon, Cthulhu, FrigidStealer) copy browser/wallet/cloud creds before exfiltrating them",
                path: nil,
                remediation: "Disconnect from the network, rotate every credential the stealer can read (browser saved passwords, AWS/GCP keys, wallet seed phrases), then investigate Evidence Scan + Network Scan findings"
            ))
        }

        // Pattern 7: DPRK "Contagious Interview" — Node/Python being asked to run staged code,
        // combined with a suspicious launch agent or recent SSH-config tampering. The campaign
        // baits crypto/Web3 devs into running malicious "take-home" projects.
        let devFindings = results.first(where: { $0.scannerName == "Dev Environment Scan" })?.findings ?? []
        let processFindings = results.first(where: { $0.scannerName == "Process Scan" })?.findings ?? []
        let npmTampered = devFindings.contains { $0.title.contains(".npmrc") }
        let sshTampered = devFindings.contains { $0.title.contains("SSH ProxyCommand") || $0.title.contains("SSH LocalCommand") }
        let nodeOrPythonSuspect = processFindings.contains {
            let lc = $0.detail.lowercased()
            return lc.contains("node") || lc.contains("python") || lc.contains("ferret") || lc.contains("beavertail")
        }
        if nodeOrPythonSuspect && (npmTampered || sshTampered) {
            findings.append(Finding(
                severity: .high,
                category: .suspiciousProcess,
                title: "Possible DPRK 'Contagious Interview' campaign pattern",
                detail: "Suspicious Node/Python process plus tampered dev-tool configuration — matches the BeaverTail / InvisibleFerret / FlexibleFerret kill chain",
                path: nil,
                remediation: "Disconnect, kill the suspect process, revert .npmrc / SSH config, and rotate any keys/wallets you touched recently"
            ))
        }

        // Pattern 8: Custom root CA + proxy/PAC enabled = TLS interception is live. Each alone is
        // a yellow flag; together they're a confirmed traffic-interception setup (corporate or hostile).
        let deepFindings = results.first(where: { $0.scannerName == "Deep Inspection Scan" })?.findings ?? []
        let networkFindings = results.first(where: { $0.scannerName == "Network Scan" })?.findings ?? []
        let customCA = deepFindings.contains { $0.title.contains("Custom root CA") }
        let proxyOn = networkFindings.contains {
            $0.title.contains("proxy") || $0.title.contains("PAC")
        }
        if customCA && proxyOn {
            findings.append(Finding(
                severity: .high,
                category: .networkActivity,
                title: "TLS interception is configured (custom CA + proxy)",
                detail: "A custom trusted root CA combined with an active proxy means HTTPS traffic can be silently inspected end-to-end",
                path: nil,
                remediation: "If this isn't your employer's MDM-managed setup, treat the machine as compromised — remove the CA in Keychain Access and disable the proxy"
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
