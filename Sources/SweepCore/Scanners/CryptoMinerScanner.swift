import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Detects cryptojackers — software that hijacks CPU/GPU for cryptocurrency mining.
/// Apple Silicon's performance-per-watt and weak default outbound filtering have made
/// Macs a viable target since 2024; XMRig-derived miners and stratum+tcp connections to
/// public pools are the typical pattern.
public final class CryptoMinerScanner: Scanner {
    public let name = "Crypto Miner Scan"
    public init() {}

    // Known mining tooling shipped under these binary names or argv tokens.
    // Lower-case for case-insensitive comparison.
    private let minerProcessNames: Set<String> = [
        "xmrig", "xmrig-mo", "xmr-stak", "xmrig-cuda",
        "minerd", "cpuminer", "cgminer", "bfgminer", "sgminer",
        "ethminer", "phoenixminer", "lolminer", "t-rex",
        "nbminer", "teamredminer", "nanominer", "claymore",
        "ccminer", "verthashminer", "miniz", "wildrig",
        "trex", "nicehash", "minerstat",
        // Recently-observed loaders that drop XMRig (2024-2025)
        "kdevtmpfsi", "kinsing", "kthrotlds", "perfctd", "watchdogs",
    ]

    // Mining-pool domains and stratum endpoints (lowercase) — matched as substrings.
    // Curated from MinerGate, NiceHash, MiningPoolStats listings and Cisco Talos IOCs (2024-2025).
    private let knownPoolDomains: [String] = [
        "pool.minexmr.com", "pool.supportxmr.com", "supportxmr.com",
        "minergate.com", "moneroocean.stream", "xmr.nanopool.org",
        "nanopool.org", "f2pool.com", "ethermine.org",
        "2miners.com", "hiveon.net", "viabtc.com",
        "ravenminer.com", "miningpoolhub.com", "minerstat.com",
        "nicehash.com", "antpool.com", "slushpool.com",
        "binance.pool", "okexpool",
        // Stratum endpoints often live on these well-known mining ports
        "stratum+tcp", "stratum2+tcp", "stratum+ssl",
    ]

    // Mining-pool ports — non-exhaustive but matches the most common stratum endpoints.
    private let miningPorts: Set<Int> = [
        3333, 4444, 5555, 7777, 8888, 9999,  // generic stratum
        14444, 14433, 17777, 19999,           // monero pools
        45700, 45560,                          // ethermine
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("scanning process names and argv")
        scanProcesses(findings: &findings, errors: &errors)

        progress?.update("scanning network connections for pool endpoints")
        scanPoolConnections(findings: &findings, errors: &errors)

        progress?.update("scanning common drop paths")
        scanDropPaths(findings: &findings)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Process inspection

    private func scanProcesses(findings: inout [Finding], errors: inout [String]) {
        // `ps -axww -o pid=,user=,command=` gives full argv per process, which is what we
        // need to catch miners renamed to innocuous binary names but still launched with
        // tell-tale stratum/wallet flags.
        let result = ShellRunner.run("/bin/ps",
                                     arguments: ["-axww", "-o", "pid=,user=,command="],
                                     timeout: 10)
        guard result.success else {
            errors.append("ps failed: \(result.stderr)")
            return
        }

        let myPid = "\(ProcessInfo.processInfo.processIdentifier)"
        let lines = result.stdout.split(separator: "\n")

        for raw in lines {
            let line = String(raw)
            let lower = line.lowercased()

            // Pull pid and the command path (first non-pid/user token) for context.
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 3 else { continue }
            let pid = String(parts[0])
            if pid == myPid { continue }
            let user = String(parts[1])
            let argv0 = String(parts[2])
            let commandName = (argv0 as NSString).lastPathComponent

            // 1. Binary name match
            if minerProcessNames.contains(commandName.lowercased()) {
                findings.append(Finding(
                    severity: .high, category: .suspiciousProcess,
                    title: "Crypto miner process running: \(commandName)",
                    detail: "PID \(pid), user \(user), argv: \(String(line.prefix(200)))",
                    path: argv0,
                    remediation: "Kill the process (kill \(pid)) and locate its persistence: launchctl list | grep -i \(commandName)"
                ))
                continue
            }

            // 2. Argv heuristics — XMRig-style flags identify a miner even when renamed.
            //    --donate-level / --cpu-priority / --rig-id are XMRig-specific.
            //    stratum+tcp:// and -o pool.* identify any stratum miner.
            let minerArgvSignals = [
                "stratum+tcp://", "stratum+ssl://", "stratum2+tcp://",
                "--donate-level", "--coin monero", "--coin xmr",
                "--cpu-priority", "--rig-id", "--randomx-mode",
                "--user-agent xmrig",
            ]
            for signal in minerArgvSignals {
                if lower.contains(signal) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "Process launched with miner argv (\(signal))",
                        detail: "PID \(pid), user \(user), argv: \(String(line.prefix(200)))",
                        path: argv0,
                        remediation: "Kill the process (kill \(pid)) and remove its persistence; the binary may be renamed but the argv reveals it"
                    ))
                    break
                }
            }
        }
    }

    // MARK: - Network connections

    private func scanPoolConnections(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/sbin/lsof",
                                     arguments: ["-i", "-n", "-P", "+c", "0", "-w"],
                                     timeout: 15)
        guard result.success else { return }

        for raw in result.stdout.split(separator: "\n").prefix(500) {
            let line = String(raw)
            if line.hasPrefix("COMMAND") { continue }
            let lower = line.lowercased()

            // Direct domain match (stratum hosts are often resolved and visible in lsof output)
            for pool in knownPoolDomains {
                if lower.contains(pool) {
                    let parts = line.split(separator: " ", omittingEmptySubsequences: true)
                    let command = parts.first.map(String.init) ?? "?"
                    let pid = parts.count > 1 ? String(parts[1]) : "?"
                    findings.append(Finding(
                        severity: .high, category: .networkActivity,
                        title: "Connection to known mining pool: \(pool)",
                        detail: "Process: \(command) (PID \(pid)) — \(String(line.prefix(180)))",
                        path: nil,
                        remediation: "Stop the process (kill \(pid)) and look for its persistence with launchctl list"
                    ))
                    break
                }
            }

            // Port-based heuristic — common stratum ports in ESTABLISHED state
            if !lower.contains("established") { continue }
            if let arrow = lower.range(of: "->") {
                let remote = String(lower[arrow.upperBound...])
                if let colon = remote.range(of: ":", options: .backwards) {
                    // The port is everything after the last colon, up to the first non-digit.
                    var portChars = ""
                    for ch in remote[colon.upperBound...] {
                        if ch.isNumber { portChars.append(ch) } else { break }
                    }
                    if let port = Int(portChars), miningPorts.contains(port) {
                        let parts = line.split(separator: " ", omittingEmptySubsequences: true)
                        let command = parts.first.map(String.init) ?? "?"
                        let pid = parts.count > 1 ? String(parts[1]) : "?"
                        findings.append(Finding(
                            severity: .medium, category: .networkActivity,
                            title: "Established connection on mining-pool port \(port)",
                            detail: "Process: \(command) (PID \(pid)) — common stratum port",
                            path: nil,
                            remediation: "Investigate: lsof -nP -p \(pid) — the remote endpoint may be a mining pool"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Common drop paths

    /// Several miner droppers (Kinsing, kdevtmpfsi, perfctd) consistently land in /tmp,
    /// /var/tmp, or ~/Library/Caches with the names below. Catching the file even when the
    /// process is briefly idle is cheap insurance.
    private func scanDropPaths(findings: inout [Finding]) {
        let home = ShellRunner.realUserHome
        let dirs = [
            "/tmp", "/private/tmp", "/var/tmp",
            "\(home)/Library/Caches",
            "\(home)/Library/LaunchAgents",
        ]

        let fm = FileManager.default
        for dir in dirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries {
                let lower = entry.lowercased()
                if minerProcessNames.contains(lower) ||
                   lower.contains("xmrig") || lower.contains("kdevtmpfsi") ||
                   lower.contains("kinsing") || lower.contains("perfctd") {
                    let path = "\(dir)/\(entry)"
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Crypto miner binary on disk: \(entry)",
                        detail: "Found in \(dir) — a known cryptojacker drop location",
                        path: path,
                        remediation: "Remove the file (rm \"\(path)\"), then re-run sweep to find any leftover persistence"
                    ))
                }
            }
        }
    }
}
