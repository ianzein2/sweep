import Foundation

enum Severity: String, Comparable, CaseIterable, Codable {
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"

    static func < (lhs: Severity, rhs: Severity) -> Bool {
        let order: [Severity] = [.low, .medium, .high]
        return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
    }
}

enum FindingCategory: String, Codable {
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
}

struct Finding: Codable {
    let severity: Severity
    let category: FindingCategory
    let title: String
    let detail: String
    let path: String?
    let remediation: String?
}

struct ScanResult: Codable {
    let scannerName: String
    var findings: [Finding]
    var errors: [String]
    let duration: TimeInterval
}
