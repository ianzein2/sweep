import ArgumentParser
import Foundation
import SweepCore

@main
struct Sweep: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sweep",
        abstract: "Detect spyware, keyloggers, and surveillance software on macOS"
    )

    @Flag(name: .long, help: "Output results as JSON")
    var json = false

    @Flag(name: .long, help: "Verbose output")
    var verbose = false

    @Option(name: .long, help: "Run only a specific scanner (process, permission, persistence, extpersistence, evidence, eventtap, device, kernel, integrity, network, profile, browser, deep, hardening)")
    var only: String?

    @Flag(name: .long, help: "Save scan results as baseline for future comparison")
    var saveBaseline = false

    @Flag(name: .long, help: "Compare current scan against saved baseline")
    var diff = false

    @Option(name: .long, help: "Path for baseline file (default: ~/.sweep/baseline.json)")
    var baselinePath: String?

    @Flag(name: .long, help: "Auto-fix safe issues (enable firewall, remove orphaned plists, etc.)")
    var fix = false

    @Flag(name: .long, help: "Show what --fix would do without making changes")
    var dryRun = false

    func run() throws {
        let reporter = Reporter(jsonMode: json, verbose: verbose)
        reporter.printHeader()

        var scanners: [SweepCore.Scanner] = []

        if only == nil || only == "process" {
            scanners.append(ProcessScanner())
        }
        if only == nil || only == "permission" {
            scanners.append(PermissionScanner())
        }
        if only == nil || only == "persistence" {
            scanners.append(PersistenceScanner())
        }
        if only == nil || only == "extpersistence" {
            scanners.append(ExtendedPersistenceScanner())
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
        if only == nil || only == "hardening" {
            scanners.append(HardeningScanner())
        }

        var results: [ScanResult] = []
        let totalScanners = scanners.count

        if only != nil {
            // Sequential mode for single scanner (with per-scanner spinner)
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
        } else {
            // Parallel mode: run all scanners concurrently
            let resultSlots = UnsafeMutableBufferPointer<ScanResult?>.allocate(capacity: totalScanners)
            resultSlots.initialize(repeating: nil as ScanResult?)
            defer { resultSlots.deallocate() }

            let spinner = Spinner(label: "Scanning", step: 0, total: totalScanners, isTTY: reporter.isTTY)
            if !json { spinner.start() }

            var completedCount = 0
            let countLock = NSLock()
            let group = DispatchGroup()
            let queue = DispatchQueue(label: "sweep.scanners", attributes: .concurrent)

            for (index, scanner) in scanners.enumerated() {
                group.enter()
                queue.async {
                    let result = scanner.scan(progress: nil)
                    resultSlots[index] = result
                    countLock.lock()
                    completedCount += 1
                    spinner.update("completed \(completedCount)/\(totalScanners)")
                    countLock.unlock()
                    group.leave()
                }
            }

            group.wait()
            spinner.stop()

            // Print results in order
            for (index, scanner) in scanners.enumerated() {
                guard let result = resultSlots[index] else { continue }
                reporter.printScannerStart(scanner.name, step: index + 1, total: totalScanners)
                results.append(result)
                reporter.printScannerResult(result)
            }
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

        // Security score
        let score = SecurityScore.calculate(from: results)
        reporter.printScore(score)

        // Baseline diff
        let effectivePath = baselinePath ?? BaselineReport.defaultPath
        if diff {
            do {
                let baseline = try BaselineReport.load(from: effectivePath)
                let changes = BaselineDiff.compare(baseline: baseline.scanResults, current: results)
                reporter.printDiff(changes, baselineDate: baseline.date)
            } catch {
                if !json {
                    print("  No baseline found at \(effectivePath). Run with --save-baseline first.")
                    print()
                }
            }
        }

        reporter.printSummary(results, score: score)

        // Save baseline (after printing so user sees results first)
        if saveBaseline {
            let baseline = BaselineReport(
                date: Date(),
                macOSVersion: ProcessInfo.processInfo.operatingSystemVersionString,
                isRoot: getuid() == 0,
                scanResults: results
            )
            do {
                try baseline.save(to: effectivePath)
                reporter.printBaselineSaved(effectivePath)
            } catch {
                if !json { print("  Failed to save baseline: \(error.localizedDescription)") }
            }
        }

        // Remediation
        if fix || dryRun {
            if getuid() != 0 && fix {
                if !json { print("  --fix requires root. Run with sudo.") }
            } else {
                let allFindings = results.flatMap { $0.findings }
                let remediator = Remediator(dryRun: dryRun)
                let remResults = remediator.remediate(findings: allFindings)
                reporter.printRemediation(remResults)
            }
        }

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
