import Foundation

public struct RemediationAction {
    public let title: String
    public let description: String
    public let executable: String
    public let arguments: [String]
    public let safe: Bool // Tier A (true) = auto-apply, Tier B (false) = skip unless confirmed
}
