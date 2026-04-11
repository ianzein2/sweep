import Foundation

public protocol Scanner {
    var name: String { get }
    func scan(progress: ScanProgress?) -> ScanResult
}
