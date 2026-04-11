import Foundation

public enum Severity: String, Comparable, CaseIterable, Codable {
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        let order: [Severity] = [.low, .medium, .high]
        return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
    }
}

public enum FindingCategory: String, Codable {
    case screenCapture = "Screen Capture"
    case keylogging = "Keylogging"
    case persistence = "Persistence"
    case suspiciousProcess = "Suspicious Process"
    case suspiciousFile = "Suspicious File"
    case permission = "Permission"
    case deviceAccess = "Device Access"
    case networkActivity = "Network Activity"
    case kernelExtension = "Kernel Extension"
    case systemIntegrity = "System Integrity"
    case hardening = "Hardening"
}

public struct Finding: Codable {
    public let severity: Severity
    public let category: FindingCategory
    public let title: String
    public let detail: String
    public let path: String?
    public let remediation: String?

    public init(severity: Severity, category: FindingCategory, title: String, detail: String, path: String?, remediation: String?) {
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.path = path
        self.remediation = remediation
    }
}

public struct ScanResult: Codable {
    public let scannerName: String
    public var findings: [Finding]
    public var errors: [String]
    public let duration: TimeInterval

    public init(scannerName: String, findings: [Finding], errors: [String], duration: TimeInterval) {
        self.scannerName = scannerName
        self.findings = findings
        self.errors = errors
        self.duration = duration
    }
}
