import Foundation

public struct BaselineReport: Codable {
    public let date: Date
    public let macOSVersion: String
    public let isRoot: Bool
    public let scanResults: [ScanResult]

    public init(date: Date, macOSVersion: String, isRoot: Bool, scanResults: [ScanResult]) {
        self.date = date
        self.macOSVersion = macOSVersion
        self.isRoot = isRoot
        self.scanResults = scanResults
    }

    public static var defaultPath: String {
        let home = ShellRunner.realUserHome
        return "\(home)/.sweep/baseline.json"
    }

    public func save(to path: String) throws {
        let dir = URL(fileURLWithPath: path).deletingLastPathComponent().path
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)
        try data.write(to: URL(fileURLWithPath: path))
    }

    public static func load(from path: String) throws -> BaselineReport {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(BaselineReport.self, from: data)
    }
}

public struct BaselineDiff {
    public let newFindings: [Finding]
    public let resolvedFindings: [Finding]
    public let unchangedCount: Int

    public static func compare(baseline: [ScanResult], current: [ScanResult]) -> BaselineDiff {
        let baselineFindings = Set(baseline.flatMap { $0.findings }.map { FingerprintedFinding($0) })
        let currentFindings = Set(current.flatMap { $0.findings }.map { FingerprintedFinding($0) })

        let newOnes = currentFindings.subtracting(baselineFindings).map { $0.finding }
        let resolved = baselineFindings.subtracting(currentFindings).map { $0.finding }
        let unchanged = baselineFindings.intersection(currentFindings).count

        return BaselineDiff(newFindings: newOnes, resolvedFindings: resolved, unchangedCount: unchanged)
    }
}

struct FingerprintedFinding: Hashable {
    let finding: Finding

    init(_ finding: Finding) { self.finding = finding }

    func hash(into hasher: inout Hasher) {
        hasher.combine(finding.title)
        hasher.combine(finding.path)
        hasher.combine(finding.category.rawValue)
    }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.finding.title == rhs.finding.title &&
        lhs.finding.path == rhs.finding.path &&
        lhs.finding.category == rhs.finding.category
    }
}
