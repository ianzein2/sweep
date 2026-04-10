import Foundation

protocol Scanner {
    var name: String { get }
    func scan(progress: Spinner?) -> ScanResult
}
