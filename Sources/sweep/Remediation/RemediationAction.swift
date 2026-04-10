import Foundation

struct RemediationAction {
    let title: String
    let description: String
    let executable: String
    let arguments: [String]
    let safe: Bool // Tier A (true) = auto-apply, Tier B (false) = skip unless confirmed
}
