import Foundation

final class ProfileScanner: Scanner {
    let name = "Profile Scan"

    func scan(progress: Spinner? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        // 1. Check installed configuration profiles
        progress?.update("listing configuration profiles")
        scanConfigurationProfiles(findings: &findings, errors: &errors)

        // 2. Check for MDM enrollment
        progress?.update("checking MDM enrollment")
        checkMDMEnrollment(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Configuration Profiles

    private func scanConfigurationProfiles(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/profiles", arguments: ["list", "-output", "stdout-xml"], timeout: 10)

        if !result.success {
            // Try simpler output
            let simpleResult = ShellRunner.run("/usr/bin/profiles", arguments: ["list"], timeout: 10)
            if simpleResult.success && !simpleResult.stdout.isEmpty {
                parseProfilesText(simpleResult.stdout, findings: &findings)
            } else if simpleResult.stderr.contains("no profiles") || simpleResult.stdout.contains("no profiles") {
                return // No profiles installed — clean
            } else {
                errors.append("Could not list configuration profiles")
            }
            return
        }

        if result.stdout.contains("no profiles") { return }

        // Parse XML output
        guard let data = result.stdout.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            // Fall back to text parsing
            parseProfilesText(result.stdout, findings: &findings)
            return
        }

        // Look for profile payloads
        if let computedProfiles = plist["_computedLevel"] as? [[String: Any]] {
            for profile in computedProfiles {
                analyzeProfile(profile, findings: &findings)
            }
        }
    }

    private func parseProfilesText(_ text: String, findings: inout [Finding]) {
        let lines = text.split(separator: "\n")
        var currentProfile: String?
        var hasVPN = false
        var hasCert = false
        var hasRestrictions = false

        for line in lines {
            let lineStr = String(line).trimmingCharacters(in: .whitespaces)

            if lineStr.contains("profileIdentifier:") || lineStr.contains("ProfileIdentifier:") {
                if let current = currentProfile {
                    reportProfile(name: current, hasVPN: hasVPN, hasCert: hasCert,
                                  hasRestrictions: hasRestrictions, findings: &findings)
                }
                currentProfile = lineStr.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces)
                hasVPN = false
                hasCert = false
                hasRestrictions = false
            }

            if lineStr.lowercased().contains("vpn") { hasVPN = true }
            if lineStr.lowercased().contains("certificate") || lineStr.lowercased().contains("cert") { hasCert = true }
            if lineStr.lowercased().contains("restriction") { hasRestrictions = true }
        }

        if let current = currentProfile {
            reportProfile(name: current, hasVPN: hasVPN, hasCert: hasCert,
                          hasRestrictions: hasRestrictions, findings: &findings)
        }
    }

    private func analyzeProfile(_ profile: [String: Any], findings: inout [Finding]) {
        let identifier = profile["ProfileIdentifier"] as? String ?? "unknown"
        let displayName = profile["ProfileDisplayName"] as? String ?? identifier
        let organization = profile["ProfileOrganization"] as? String ?? "unknown"
        let payloads = profile["ProfileItems"] as? [[String: Any]] ?? []

        // Skip Apple's own profiles
        if identifier.hasPrefix("com.apple.") { return }

        var hasVPN = false
        var hasCert = false
        var hasRestrictions = false
        var hasDNS = false
        var hasProxy = false

        for payload in payloads {
            let payloadType = payload["PayloadType"] as? String ?? ""
            if payloadType.contains("vpn") { hasVPN = true }
            if payloadType.contains("certificate") || payloadType.contains("pkcs") { hasCert = true }
            if payloadType.contains("restrictions") { hasRestrictions = true }
            if payloadType.contains("dns") { hasDNS = true }
            if payloadType.contains("proxy") { hasProxy = true }
        }

        reportProfile(name: "\(displayName) (\(identifier))", organization: organization,
                       hasVPN: hasVPN, hasCert: hasCert, hasRestrictions: hasRestrictions,
                       hasDNS: hasDNS, hasProxy: hasProxy, findings: &findings)
    }

    private func reportProfile(name: String, organization: String = "", hasVPN: Bool,
                                hasCert: Bool, hasRestrictions: Bool,
                                hasDNS: Bool = false, hasProxy: Bool = false,
                                findings: inout [Finding]) {
        // VPN + Certificate + Restrictions = full MDM surveillance capability
        let surveillancePayloads = [hasVPN, hasCert, hasRestrictions, hasDNS, hasProxy].filter { $0 }.count

        if surveillancePayloads >= 3 {
            findings.append(Finding(
                severity: .high, category: .systemIntegrity,
                title: "Configuration profile with extensive control",
                detail: "Profile: \(name)" + (organization.isEmpty ? "" : " by \(organization)") +
                    " — has VPN, certificates, and restrictions (full device management)",
                path: nil,
                remediation: "If this is not your employer's MDM, remove in System Settings > General > Profiles"
            ))
        } else if hasVPN || hasCert {
            findings.append(Finding(
                severity: .medium, category: .systemIntegrity,
                title: "Configuration profile installed",
                detail: "Profile: \(name)" + (organization.isEmpty ? "" : " by \(organization)") +
                    (hasVPN ? " [VPN]" : "") + (hasCert ? " [Certificate]" : "") +
                    (hasDNS ? " [DNS]" : "") + (hasProxy ? " [Proxy]" : ""),
                path: nil,
                remediation: "Verify this profile is expected in System Settings > General > Profiles"
            ))
        } else {
            findings.append(Finding(
                severity: .low, category: .systemIntegrity,
                title: "Configuration profile installed",
                detail: "Profile: \(name)" + (organization.isEmpty ? "" : " by \(organization)"),
                path: nil,
                remediation: "Review in System Settings > General > Profiles"
            ))
        }
    }

    // MARK: - MDM Enrollment

    private func checkMDMEnrollment(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/profiles", arguments: ["status", "-type", "enrollment"], timeout: 5)
        let output = result.stdout + result.stderr

        if output.contains("MDM enrollment: Yes") || output.contains("Enrolled via DEP: Yes") {
            findings.append(Finding(
                severity: .low, category: .systemIntegrity,
                title: "Device is MDM enrolled",
                detail: "This Mac is enrolled in Mobile Device Management" +
                    (output.contains("DEP") ? " (via Device Enrollment Program)" : ""),
                path: nil,
                remediation: "MDM can install profiles, apps, and monitor device remotely. This is normal for work devices."
            ))
        }
    }
}
