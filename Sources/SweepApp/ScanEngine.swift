import Foundation
import SweepCore

@MainActor
final class ScanEngine: ObservableObject {
    @Published var results: [ScanResult] = []
    @Published var score: SecurityScore?
    @Published var isScanning = false
    @Published var progress: Double = 0
    @Published var currentScanner: String = ""
    @Published var scanDate: Date?

    let isRoot = getuid() == 0

    func startScan() {
        guard !isScanning else { return }
        isScanning = true
        progress = 0
        results = []
        score = nil
        currentScanner = "Starting..."

        let scanners: [SweepCore.Scanner] = [
            ProcessScanner(),
            PermissionScanner(),
            PersistenceScanner(),
            EvidenceScanner(),
            EventTapScanner(),
            DeviceScanner(),
            KernelScanner(),
            SystemIntegrityScanner(),
            NetworkScanner(),
            ProfileScanner(),
            BrowserScanner(),
            DeepScanner(),
            HardeningScanner(),
        ]

        let total = scanners.count

        // Run scanners on background thread
        Task.detached { [weak self] in
            var scanResults: [ScanResult] = []

            let resultSlots = UnsafeMutableBufferPointer<ScanResult?>.allocate(capacity: total)
            resultSlots.initialize(repeating: nil as ScanResult?)
            defer { resultSlots.deallocate() }

            var completed = 0
            let lock = NSLock()
            let group = DispatchGroup()
            let queue = DispatchQueue(label: "sweep.scanners", attributes: .concurrent)

            for (index, scanner) in scanners.enumerated() {
                group.enter()
                queue.async {
                    let result = scanner.scan(progress: nil)
                    resultSlots[index] = result
                    lock.lock()
                    completed += 1
                    let pct = Double(completed) / Double(total)
                    let name = scanner.name
                    lock.unlock()
                    Task { @MainActor [weak self] in
                        self?.progress = pct
                        self?.currentScanner = name
                    }
                    group.leave()
                }
            }

            group.wait()

            for i in 0..<total {
                if let result = resultSlots[i] {
                    scanResults.append(result)
                }
            }

            // Threat correlation
            if scanResults.count > 1 {
                let correlated = ThreatCorrelator.correlate(scanResults)
                if !correlated.findings.isEmpty {
                    scanResults.append(correlated)
                }
            }

            let score = SecurityScore.calculate(from: scanResults)

            await MainActor.run { [weak self] in
                self?.results = scanResults
                self?.score = score
                self?.scanDate = Date()
                self?.isScanning = false
                self?.currentScanner = ""
            }
        }
    }

    /// Find the sweep CLI binary
    private func findCLIBinary() -> String? {
        // 1. Installed location
        if FileManager.default.fileExists(atPath: "/usr/local/bin/sweep") {
            return "/usr/local/bin/sweep"
        }
        // 2. Relative to app bundle (e.g. build/ directory)
        let appPath = CommandLine.arguments[0]
        if let appDir = URL(string: appPath)?.deletingLastPathComponent() {
            // build/Sweep.app/Contents/MacOS/ -> build/../../.build/release/sweep
            let relative = appDir
                .appendingPathComponent("../../../../.build/release/sweep")
                .standardized.path
            if FileManager.default.fileExists(atPath: relative) {
                return relative
            }
        }
        // 3. Common dev location
        let devPath = FileManager.default.currentDirectoryPath + "/.build/release/sweep"
        if FileManager.default.fileExists(atPath: devPath) {
            return devPath
        }
        return nil
    }

    func scanAsAdmin() {
        guard !isScanning else { return }

        guard let cliBinary = findCLIBinary() else {
            // No CLI binary found — fall back to regular scan
            startScan()
            return
        }

        isScanning = true
        progress = 0
        results = []
        score = nil
        currentScanner = "Requesting admin privileges..."

        Task.detached { [weak self] in
            let escaped = cliBinary.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")

            let result = ShellRunner.run("/usr/bin/osascript", arguments: [
                "-e", "do shell script \"\(escaped) --json\" with administrator privileges"
            ], timeout: 120)

            await MainActor.run { [weak self] in
                if result.success, let data = result.stdout.data(using: .utf8) {
                    self?.parseJSONResults(data)
                } else {
                    // Admin cancelled or failed — reset state
                    self?.isScanning = false
                    self?.currentScanner = ""
                }
            }
        }
    }

    private func parseJSONResults(_ data: Data) {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let resultsArray = json["results"] as? [[String: Any]] else {
            isScanning = false
            return
        }

        var scanResults: [ScanResult] = []
        for resultDict in resultsArray {
            let scannerName = resultDict["scanner"] as? String ?? "Unknown"
            let duration = resultDict["duration"] as? TimeInterval ?? 0
            let errors = resultDict["errors"] as? [String] ?? []
            let findingsArray = resultDict["findings"] as? [[String: String]] ?? []

            var findings: [Finding] = []
            for fDict in findingsArray {
                let severity = Severity(rawValue: fDict["severity"] ?? "LOW") ?? .low
                let category = FindingCategory(rawValue: fDict["category"] ?? "Suspicious Process") ?? .suspiciousProcess
                findings.append(Finding(
                    severity: severity,
                    category: category,
                    title: fDict["title"] ?? "",
                    detail: fDict["detail"] ?? "",
                    path: fDict["path"],
                    remediation: fDict["remediation"]
                ))
            }

            scanResults.append(ScanResult(
                scannerName: scannerName,
                findings: findings,
                errors: errors,
                duration: duration
            ))
        }

        self.results = scanResults
        self.score = SecurityScore.calculate(from: scanResults)
        self.scanDate = Date()
        self.isScanning = false
        self.currentScanner = ""
    }
}
