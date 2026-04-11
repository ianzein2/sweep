import Foundation

/// Progress reporting protocol used by scanners.
/// The CLI implements this with a terminal Spinner; the app implements it with SwiftUI bindings.
public protocol ScanProgress: AnyObject {
    func update(_ message: String)
}
