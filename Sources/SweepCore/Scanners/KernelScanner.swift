import Foundation

public final class KernelScanner: Scanner {
    public let name = "Kernel Extension Scan"
    public init() {}

    private let knownSecurityVendors: Set<String> = [
        "com.crowdstrike.", "com.sentinelone.", "com.malwarebytes.",
        "com.sophos.", "com.cisco.amp.", "com.vmware.carbonblack.",
        "com.jamf.protect.", "com.eset.", "com.avast.", "com.avg.",
        "com.kaspersky.", "com.trendmicro.", "com.mcafee.",
        "com.symantec.", "com.norton.", "com.bitdefender.",
        "com.paloaltonetworks.", "com.carbonblack.",
        "at.obdev.",  // Little Snitch, Micro Snitch
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        // 1. Check loaded kernel extensions
        progress?.update("listing kernel extensions")
        scanKernelExtensions(findings: &findings, errors: &errors)

        // 2. Check system extensions
        progress?.update("checking system extensions")
        scanSystemExtensions(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Kernel Extensions (kextstat)

    private func scanKernelExtensions(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/sbin/kextstat", arguments: ["-l"], timeout: 15)

        if !result.success {
            if result.stderr.contains("not found") || result.exitCode == 127 {
                // kextstat may not be available on newer macOS
                return
            }
            errors.append("kextstat failed: \(result.stderr)")
            return
        }

        let lines = result.stdout.split(separator: "\n")
        for line in lines {
            let lineStr = String(line).trimmingCharacters(in: .whitespaces)

            // Skip header line
            if lineStr.hasPrefix("Index") || lineStr.isEmpty { continue }

            // Extract bundle identifier — it's the 6th column typically
            // Format: Index Refs Address Size Wired Name (Version) UUID <Linked Against>
            let parts = lineStr.split(separator: " ", maxSplits: 6)
            guard parts.count >= 6 else { continue }
            let bundleId = String(parts[5]).replacingOccurrences(of: "(", with: "")

            // Skip Apple kexts
            if bundleId.hasPrefix("com.apple.") { continue }

            // Check against known spyware
            if let sig = SpywareSignature.match(bundleId: bundleId) {
                findings.append(Finding(
                    severity: .high, category: .kernelExtension,
                    title: "Known spyware kernel extension: \(sig.name)",
                    detail: "Bundle: \(bundleId)",
                    path: nil,
                    remediation: "Unload with: sudo kextunload -b \(bundleId)"
                ))
                continue
            }

            // Check if it's a known security vendor
            let isSecurityVendor = knownSecurityVendors.contains { bundleId.hasPrefix($0) }
            if isSecurityVendor {
                findings.append(Finding(
                    severity: .low, category: .kernelExtension,
                    title: "Security tool kernel extension loaded",
                    detail: "Bundle: \(bundleId)",
                    path: nil,
                    remediation: "Known security vendor — verify this is your security software"
                ))
                continue
            }

            // Unknown third-party kext
            findings.append(Finding(
                severity: .medium, category: .kernelExtension,
                title: "Third-party kernel extension loaded",
                detail: "Bundle: \(bundleId) — kexts are deprecated on modern macOS, third-party kexts are unusual",
                path: nil,
                remediation: "Investigate this kernel extension and remove if not needed"
            ))
        }
    }

    // MARK: - System Extensions

    private func scanSystemExtensions(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/systemextensionsctl", arguments: ["list"], timeout: 15)

        if !result.success {
            if result.stderr.contains("not permitted") || result.stderr.contains("requires root") {
                errors.append("systemextensionsctl requires root privileges")
            }
            return
        }

        let lines = result.stdout.split(separator: "\n")
        for line in lines {
            let lineStr = String(line).trimmingCharacters(in: .whitespaces)

            // Look for extension entries — they contain bundle identifiers
            // Format varies, but typically includes bundle ID and category
            guard lineStr.contains(".") && !lineStr.hasPrefix("---") && !lineStr.hasPrefix("#") else { continue }

            // Skip Apple system extensions
            if lineStr.contains("com.apple.") { continue }

            // Extract bundle ID — split by both tabs and spaces to handle systemextensionsctl's tab-separated format
            let tokens = lineStr.components(separatedBy: CharacterSet.whitespaces)
                .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "*()[]")) }
                .filter { !$0.isEmpty }
            guard let bundleToken = tokens.first(where: {
                $0.contains(".") && $0.filter({ $0 == "." }).count >= 2
                && !$0.hasPrefix("(") && !$0.hasPrefix("[")
                && $0.rangeOfCharacter(from: .letters) != nil
            }) else { continue }
            let bundleId = String(bundleToken)

            // Check against known spyware
            if let sig = SpywareSignature.match(bundleId: bundleId) {
                findings.append(Finding(
                    severity: .high, category: .kernelExtension,
                    title: "Known spyware system extension: \(sig.name)",
                    detail: "Bundle: \(bundleId)",
                    path: nil,
                    remediation: "Remove the associated app and its system extension"
                ))
                continue
            }

            // Known security vendor
            let isSecurityVendor = knownSecurityVendors.contains { bundleId.hasPrefix($0) }

            let isEndpointSecurity = lineStr.lowercased().contains("endpoint") || lineStr.lowercased().contains("endpointsecurity")
            let isNetworkExtension = lineStr.lowercased().contains("network")

            if isEndpointSecurity || isNetworkExtension {
                let extType = isEndpointSecurity ? "Endpoint Security" : "Network"
                findings.append(Finding(
                    severity: isSecurityVendor ? .low : .medium,
                    category: .kernelExtension,
                    title: isSecurityVendor
                        ? "Security tool \(extType) extension"
                        : "Third-party \(extType) extension",
                    detail: "Bundle: \(bundleId) — \(extType) extensions can monitor \(isEndpointSecurity ? "all process activity" : "all network traffic")",
                    path: nil,
                    remediation: isSecurityVendor
                        ? "Known security vendor — verify this is expected"
                        : "Investigate this \(extType) extension"
                ))
            }
        }
    }
}
