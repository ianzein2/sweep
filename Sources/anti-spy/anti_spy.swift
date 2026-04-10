import ArgumentParser
import Foundation

@main
struct AntiSpy: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "anti-spy",
        abstract: "Detect spyware, keyloggers, and surveillance software on macOS"
    )

    @Flag(name: .long, help: "Output results as JSON")
    var json = false

    @Flag(name: .long, help: "Verbose output")
    var verbose = false

    @Option(name: .long, help: "Run only a specific scanner (process, permission, persistence, evidence, eventtap, device, kernel, integrity, network, profile, browser, deep)")
    var only: String?

    func run() throws {
        let reporter = Reporter(jsonMode: json, verbose: verbose)
        reporter.printHeader()

        var scanners: [Scanner] = []

        if only == nil || only == "process" {
            scanners.append(ProcessScanner())
        }
        if only == nil || only == "permission" {
            scanners.append(PermissionScanner())
        }
        if only == nil || only == "persistence" {
            scanners.append(PersistenceScanner())
        }
        if only == nil || only == "evidence" {
            scanners.append(EvidenceScanner())
        }
        if only == nil || only == "eventtap" {
            scanners.append(EventTapScanner())
        }
        if only == nil || only == "device" {
            scanners.append(DeviceScanner())
        }
        if only == nil || only == "kernel" {
            scanners.append(KernelScanner())
        }
        if only == nil || only == "integrity" {
            scanners.append(SystemIntegrityScanner())
        }
        if only == nil || only == "network" {
            scanners.append(NetworkScanner())
        }
        if only == nil || only == "profile" {
            scanners.append(ProfileScanner())
        }
        if only == nil || only == "browser" {
            scanners.append(BrowserScanner())
        }
        if only == nil || only == "deep" {
            scanners.append(DeepScanner())
        }

        var results: [ScanResult] = []

        let totalScanners = scanners.count
        for (index, scanner) in scanners.enumerated() {
            let step = index + 1
            let spinner = Spinner(label: scanner.name, step: step, total: totalScanners, isTTY: reporter.isTTY)
            if !json { spinner.start() }
            let result = scanner.scan(progress: json ? nil : spinner)
            spinner.stop()
            reporter.printScannerStart(scanner.name, step: step, total: totalScanners)
            results.append(result)
            reporter.printScannerResult(result)
        }

        // Cross-scanner correlation (only when running full scan)
        if only == nil && results.count > 1 {
            let correlated = ThreatCorrelator.correlate(results)
            if !correlated.findings.isEmpty {
                reporter.printScannerStart(correlated.scannerName, step: totalScanners + 1, total: totalScanners + 1)
                reporter.printScannerResult(correlated)
                results.append(correlated)
            }
        }

        reporter.printSummary(results)

        // Exit code based on findings
        let hasHigh = results.flatMap { $0.findings }.contains { $0.severity == .high }
        let hasErrors = results.contains { !$0.errors.isEmpty }

        if hasHigh {
            throw ExitCode(1)
        }
        if hasErrors && results.flatMap({ $0.findings }).isEmpty {
            throw ExitCode(2)
        }
    }
}
