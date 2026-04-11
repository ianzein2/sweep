import Foundation
import SweepCore
#if canImport(Darwin)
import Darwin
#endif

enum ANSIColor: String {
    case red = "\u{001B}[31m"
    case yellow = "\u{001B}[33m"
    case cyan = "\u{001B}[36m"
    case green = "\u{001B}[32m"
    case bold = "\u{001B}[1m"
    case dim = "\u{001B}[2m"
    case reset = "\u{001B}[0m"
}

final class Spinner: ScanProgress {
    private let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    private var frameIndex = 0
    private var timer: DispatchSourceTimer?
    private let label: String
    private let progress: String
    private let isTTY: Bool
    private let startTime = Date()
    private let lock = NSLock()
    private var _substatus: String = ""

    init(label: String, step: Int, total: Int, isTTY: Bool) {
        self.label = label
        self.progress = "[\(step)/\(total)]"
        self.isTTY = isTTY
    }

    /// Update the substatus text shown after the scanner name (e.g. "checking 5/42 apps")
    func update(_ substatus: String) {
        lock.lock()
        _substatus = substatus
        lock.unlock()
    }

    func start() {
        guard isTTY else { return }
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .userInteractive))
        timer.schedule(deadline: .now(), repeating: .milliseconds(80))
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            let frame = self.frames[self.frameIndex % self.frames.count]
            let elapsed = Int(Date().timeIntervalSince(self.startTime))
            let timeStr = elapsed > 0 ? " \(elapsed)s" : ""
            self.lock.lock()
            let sub = self._substatus.isEmpty ? "" : " — \(self._substatus)"
            self.lock.unlock()
            print("\r\u{001B}[2K  \(frame) \(self.progress) \(self.label)\(sub)\(timeStr)", terminator: "")
            fflush(stdout)
            self.frameIndex += 1
        }
        self.timer = timer
        timer.resume()
    }

    func stop() {
        timer?.cancel()
        timer = nil
        guard isTTY else { return }
        print("\r\u{001B}[2K", terminator: "")
        fflush(stdout)
    }
}

final class Reporter {
    let jsonMode: Bool
    let verbose: Bool
    let isTTY: Bool
    private var allResults: [ScanResult] = []

    init(jsonMode: Bool, verbose: Bool) {
        self.jsonMode = jsonMode
        self.verbose = verbose
        self.isTTY = isatty(STDOUT_FILENO) != 0
    }

    private func color(_ text: String, _ color: ANSIColor) -> String {
        guard isTTY && !jsonMode else { return text }
        return "\(color.rawValue)\(text)\(ANSIColor.reset.rawValue)"
    }

    private func severityColor(_ severity: Severity) -> ANSIColor {
        switch severity {
        case .high: return .red
        case .medium: return .yellow
        case .low: return .cyan
        }
    }

    func printHeader() {
        guard !jsonMode else { return }
        let line = String(repeating: "=", count: 60)
        print(color(line, .bold))
        print(color("  SWEEP SCAN REPORT", .bold))
        print(color("  \(formattedDate())", .dim))
        print(color("  macOS \(ProcessInfo.processInfo.operatingSystemVersionString)", .dim))
        printPrivilegeLevel()
        print(color(line, .bold))
        print()
    }

    private func printPrivilegeLevel() {
        let uid = getuid()
        if uid == 0 {
            print(color("  Running as: root (full scan)", .green))
        } else {
            print(color("  Running as: user (some scans may be limited)", .yellow))
            print(color("  Tip: Run with sudo for deeper scanning", .dim))
        }
    }

    func printScannerStart(_ name: String, step: Int? = nil, total: Int? = nil) {
        guard !jsonMode else { return }
        if let step = step, let total = total {
            print(color("--- [\(step)/\(total)] \(name) ---", .bold))
        } else {
            print(color("--- \(name) ---", .bold))
        }
    }

    func printScannerResult(_ result: ScanResult) {
        guard !jsonMode else {
            allResults.append(result)
            return
        }

        if result.findings.isEmpty && result.errors.isEmpty {
            print(color("  No issues found.", .green))
        }

        for finding in result.findings.sorted(by: { $0.severity > $1.severity }) {
            let severityTag = color("[\(finding.severity.rawValue)]", severityColor(finding.severity))
            print("\(severityTag) \(finding.title)")
            print("       \(finding.detail)")
            if let path = finding.path {
                print("       Path: \(path)")
            }
            if let remediation = finding.remediation {
                print(color("       Action: \(remediation)", .dim))
            }
            print()
        }

        for error in result.errors {
            print(color("  ! \(error)", .dim))
        }

        if !result.errors.isEmpty || !result.findings.isEmpty {
            print()
        }
    }

    func printScore(_ score: SecurityScore) {
        guard !jsonMode else { return }

        let line = String(repeating: "=", count: 60)
        print(color(line, .bold))
        print(color("  SECURITY SCORE", .bold))
        print(color(line, .bold))

        // Visual bar (25 chars wide)
        let barWidth = 25
        let filled = Int(Double(score.total) / 100.0 * Double(barWidth))
        let empty = barWidth - filled
        let barColor: ANSIColor = score.total >= 80 ? .green : score.total >= 60 ? .yellow : .red
        let bar = color(String(repeating: "█", count: filled), barColor) +
                  color(String(repeating: "░", count: empty), .dim)
        print()
        print("       \(bar)  \(score.total)/100  [\(score.grade)]")
        print()

        // Top deductions (up to 5)
        if !score.deductions.isEmpty {
            print(color("  Deductions:", .dim))
            // Deduplicate by title, summing points
            var seen: [String: (points: Int, severity: Severity)] = [:]
            for d in score.deductions {
                if let existing = seen[d.title] {
                    seen[d.title] = (existing.points + d.points, d.severity)
                } else {
                    seen[d.title] = (d.points, d.severity)
                }
            }
            let sorted = seen.sorted { $0.value.points > $1.value.points }
            for entry in sorted.prefix(5) {
                let tag = color("-\(entry.value.points)", severityColor(entry.value.severity))
                print("    \(tag)  \(entry.key)")
            }
            if sorted.count > 5 {
                let remaining = sorted.dropFirst(5).reduce(0) { $0 + $1.value.points }
                print(color("    -\(remaining)  ... and \(sorted.count - 5) more", .dim))
            }
            print()
        }
    }

    func printSummary(_ results: [ScanResult], score: SecurityScore? = nil) {
        if jsonMode {
            printJSON(results, score: score)
            return
        }

        let allFindings = results.flatMap { $0.findings }
        let high = allFindings.filter { $0.severity == .high }.count
        let medium = allFindings.filter { $0.severity == .medium }.count
        let low = allFindings.filter { $0.severity == .low }.count
        let errorScanners = results.filter { !$0.errors.isEmpty }

        let line = String(repeating: "=", count: 60)
        print(color(line, .bold))
        print(color("  SUMMARY", .bold))
        print(color(line, .bold))

        if high > 0 {
            print(color("  HIGH findings:   \(high)", .red))
        } else {
            print("  HIGH findings:   0")
        }
        if medium > 0 {
            print(color("  MEDIUM findings: \(medium)", .yellow))
        } else {
            print("  MEDIUM findings: 0")
        }
        print("  LOW findings:    \(low)")
        print()

        let completedCount = results.count
        let errorCount = errorScanners.count
        print("  Scans completed: \(completedCount)")
        if errorCount > 0 {
            let names = errorScanners.map { $0.scannerName }.joined(separator: ", ")
            print(color("  Scans with errors: \(errorCount) (\(names))", .yellow))
        }

        if high == 0 && medium == 0 && low == 0 {
            print()
            print(color("  No spyware indicators detected.", .green))
        } else if high > 0 {
            print()
            print(color("  WARNING: High-severity findings require immediate attention!", .red))
        }

        print(color(line, .bold))
    }

    func printDiff(_ diff: BaselineDiff, baselineDate: Date) {
        guard !jsonMode else { return }

        let line = String(repeating: "=", count: 60)
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"

        print(color(line, .bold))
        print(color("  CHANGES SINCE BASELINE", .bold))
        print(color("  Baseline from: \(fmt.string(from: baselineDate))", .dim))
        print(color(line, .bold))

        if diff.newFindings.isEmpty && diff.resolvedFindings.isEmpty {
            print(color("  No changes detected.", .green))
        } else {
            if !diff.newFindings.isEmpty {
                print(color("  [+] \(diff.newFindings.count) NEW finding(s):", .red))
                for f in diff.newFindings.sorted(by: { $0.severity > $1.severity }) {
                    print(color("      [\(f.severity.rawValue)] \(f.title)", severityColor(f.severity)))
                }
                print()
            }
            if !diff.resolvedFindings.isEmpty {
                print(color("  [-] \(diff.resolvedFindings.count) RESOLVED finding(s):", .green))
                for f in diff.resolvedFindings {
                    print(color("      \(f.title)", .dim))
                }
                print()
            }
        }
        print(color("  [=] \(diff.unchangedCount) unchanged", .dim))
        print(color(line, .bold))
        print()
    }

    func printBaselineSaved(_ path: String) {
        guard !jsonMode else { return }
        print(color("  Baseline saved to \(path)", .green))
        print()
    }

    func printRemediation(_ results: [RemediationResult]) {
        guard !jsonMode else { return }
        guard !results.isEmpty else { return }

        let line = String(repeating: "=", count: 60)
        print(color(line, .bold))
        print(color("  REMEDIATION", .bold))
        print(color(line, .bold))

        var fixedCount = 0, skippedCount = 0, dryCount = 0, failedCount = 0

        for result in results {
            switch result {
            case .fixed(let title, _):
                print(color("  [FIXED]", .green), " \(title)")
                fixedCount += 1
            case .skipped(let title, let reason):
                print(color("  [SKIP]", .dim), "  \(title) — \(reason)")
                skippedCount += 1
            case .dryRun(let title, let detail):
                print(color("  [DRY]", .cyan), "   \(title)")
                print(color("          \(detail)", .dim))
                dryCount += 1
            case .failed(let title, let error):
                print(color("  [FAIL]", .red), "  \(title) — \(error)")
                failedCount += 1
            }
        }

        print()
        var summary: [String] = []
        if fixedCount > 0 { summary.append("\(fixedCount) fixed") }
        if skippedCount > 0 { summary.append("\(skippedCount) skipped") }
        if dryCount > 0 { summary.append("\(dryCount) dry-run") }
        if failedCount > 0 { summary.append("\(failedCount) failed") }
        print("  \(summary.joined(separator: ", "))")
        print(color(line, .bold))
        print()
    }

    private func printJSON(_ results: [ScanResult], score: SecurityScore? = nil) {
        var output: [String: Any] = [
            "date": formattedDate(),
            "macOS": ProcessInfo.processInfo.operatingSystemVersionString,
            "isRoot": getuid() == 0,
            "results": results.map { result in
                [
                    "scanner": result.scannerName,
                    "duration": result.duration,
                    "errors": result.errors,
                    "findings": result.findings.map { finding in
                        var dict: [String: String] = [
                            "severity": finding.severity.rawValue,
                            "category": finding.category.rawValue,
                            "title": finding.title,
                            "detail": finding.detail,
                        ]
                        if let path = finding.path { dict["path"] = path }
                        if let rem = finding.remediation { dict["remediation"] = rem }
                        return dict
                    }
                ] as [String: Any]
            }
        ]

        if let score = score {
            output["score"] = [
                "total": score.total,
                "grade": score.grade,
                "deductions": score.deductions.map { ["points": $0.points, "title": $0.title] as [String: Any] }
            ] as [String: Any]
        }

        if let data = try? JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys]),
           let json = String(data: data, encoding: .utf8) {
            print(json)
        }
    }

    private func formattedDate() -> String {
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return fmt.string(from: Date())
    }
}
