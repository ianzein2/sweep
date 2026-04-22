import Foundation
import Security
#if canImport(Darwin)
import Darwin
#endif

public final class ProcessScanner: Scanner {
    public let name = "Process Scan"
    public init() {}

    // Paths where legitimate system/app binaries live
    private let trustedPathPrefixes: [String] = {
        var paths = [
            "/System/",
            "/usr/",
            "/bin/",
            "/sbin/",
            "/Applications/",
            "/Library/Apple/",
            "/Library/Developer/",
            "/Library/Frameworks/",
            "/Library/PrivilegedHelperTools/",
            "/opt/homebrew/",
            "/usr/local/",
        ]
        // Also trust user dev tools and app directories
        let home = ShellRunner.realUserHome
        paths.append("\(home)/Applications/")
        paths.append("\(home)/.pyenv/")
        paths.append("\(home)/.nvm/")
        paths.append("\(home)/.rbenv/")
        paths.append("\(home)/.rustup/")
        paths.append("\(home)/.cargo/")
        return paths
    }()

    // Common legitimate processes that may appear unsigned or from odd paths
    private let whitelistedProcessNames: Set<String> = [
        "launchd", "kernel_task", "WindowServer", "loginwindow",
        "Finder", "Dock", "SystemUIServer", "Spotlight",
        "mds", "mds_stores", "mdworker", "distnoted",
        "cfprefsd", "lsd", "trustd", "secd", "securityd",
        "notifyd", "usermanagerd", "coreservicesd", "coreaudiod",
        "hidd", "bluetoothd", "airportd", "wifid",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        let errors: [String] = []
        progress?.update("listing processes")

        let processes = listProcesses()

        let myPid = ProcessInfo.processInfo.processIdentifier

        progress?.update("checking \(processes.count) processes")

        for proc in processes {
            // Skip kernel, launchd, and ourselves
            if proc.pid <= 1 || proc.pid == myPid { continue }

            // Check against known spyware names — but only if NOT from a system path
            // (many spyware names mimic real Apple process names like mdworker_shared)
            if let sig = SpywareSignature.match(processName: proc.name) {
                let isSystemPath = proc.path.map { path in
                    path.hasPrefix("/System/") || path.hasPrefix("/usr/") ||
                    path.hasPrefix("/bin/") || path.hasPrefix("/sbin/")
                } ?? false

                if !isSystemPath {
                    findings.append(Finding(
                        severity: .high,
                        category: .suspiciousProcess,
                        title: "Known spyware process detected: \"\(proc.name)\" (\(sig.name))",
                        detail: "PID \(proc.pid), running from: \(proc.path ?? "unknown path")",
                        path: proc.path,
                        remediation: "Terminate process (kill \(proc.pid)) and remove \(sig.name)"
                    ))
                    continue
                }
            }

            // Check for processes mimicking system names from non-system paths
            if SpywareSignature.isSuspiciousSystemName(proc.name) {
                if let path = proc.path, !path.hasPrefix("/System/") && !path.hasPrefix("/usr/") {
                    findings.append(Finding(
                        severity: .high,
                        category: .suspiciousProcess,
                        title: "Process mimicking system name: \"\(proc.name)\"",
                        detail: "PID \(proc.pid), running from non-system path",
                        path: proc.path,
                        remediation: "This process name is used by macOS but is running from an unusual location — investigate immediately"
                    ))
                    continue
                }
            }

            // Skip whitelisted process names
            if whitelistedProcessNames.contains(proc.name) { continue }

            guard let path = proc.path, !path.isEmpty else { continue }

            // Check if from a trusted path
            let isTrustedPath = trustedPathPrefixes.contains { path.hasPrefix($0) }
            if isTrustedPath { continue }

            // Process is from an unusual location — check code signature
            let sigInfo = checkCodeSignature(path: path)

            if !sigInfo.isSigned {
                findings.append(Finding(
                    severity: .medium,
                    category: .suspiciousProcess,
                    title: "Unsigned process from unusual location",
                    detail: "Name: \(proc.name), PID: \(proc.pid), UID: \(proc.uid)",
                    path: path,
                    remediation: "Investigate this process — unsigned binaries outside standard paths are suspicious"
                ))
            } else if sigInfo.isAdHoc {
                findings.append(Finding(
                    severity: .low,
                    category: .suspiciousProcess,
                    title: "Ad-hoc signed process from unusual location",
                    detail: "Name: \(proc.name), PID: \(proc.pid), Signer: \(sigInfo.identity ?? "ad-hoc")",
                    path: path,
                    remediation: "Verify this process is legitimate — ad-hoc signing is common in development but also used by malware"
                ))
            }
        }

        // Dylib enumeration for all non-system processes
        progress?.update("scanning loaded libraries")
        scanLoadedDylibs(processes: processes, findings: &findings)

        // Check for orphaned child processes (parent is launchd but not a daemon)
        progress?.update("checking process hierarchy")
        scanProcessHierarchy(processes: processes, findings: &findings)

        // Detect cryptominers — high-CPU background processes named like known miners
        progress?.update("checking for cryptominers")
        scanForCryptominers(processes: processes, findings: &findings)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    private let suspiciousDylibPrefixes = [
        "/tmp/", "/private/tmp/", "/var/tmp/",
    ]

    private func scanLoadedDylibs(processes: [ProcessEntry], findings: inout [Finding]) {
        let myPid = ProcessInfo.processInfo.processIdentifier
        let home = ShellRunner.realUserHome

        // Check all non-system, non-Apple processes
        for proc in processes {
            if proc.pid <= 1 || proc.pid == myPid { continue }
            guard let path = proc.path else { continue }

            // Only inspect non-system processes
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/") ||
               path.hasPrefix("/bin/") || path.hasPrefix("/sbin/") { continue }

            // Use vmmap to get loaded libraries
            let result = ShellRunner.run("/usr/bin/vmmap", arguments: ["\(proc.pid)"], timeout: 5)
            guard result.success else { continue }

            let lines = result.stdout.split(separator: "\n")
            for line in lines {
                let lineStr = String(line)
                guard lineStr.contains(".dylib") else { continue }

                // Extract path
                if let pathStart = lineStr.range(of: "/") {
                    let libPath = String(lineStr[pathStart.lowerBound...]).trimmingCharacters(in: .whitespaces)
                    guard libPath.contains(".dylib") else { continue }

                    // Check for dylibs from hidden directories
                    if libPath.contains("/.") {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousProcess,
                            title: "Hidden dylib loaded into \(proc.name)",
                            detail: "PID \(proc.pid), Library: \(libPath)",
                            path: libPath,
                            remediation: "Hidden libraries are a strong indicator of code injection"
                        ))
                    }
                    // Dylibs from temp directories
                    else if suspiciousDylibPrefixes.contains(where: { libPath.hasPrefix($0) }) {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousProcess,
                            title: "Dylib loaded from temp directory into \(proc.name)",
                            detail: "PID \(proc.pid), Library: \(libPath)",
                            path: libPath,
                            remediation: "Libraries in temp directories are highly suspicious"
                        ))
                    }
                    // Dylibs from user home (unusual unless frameworks)
                    else if libPath.hasPrefix(home) &&
                            !libPath.contains("/Library/Frameworks/") &&
                            !libPath.contains("/Applications/") &&
                            !libPath.contains("/.cargo/") &&
                            !libPath.contains("/.rustup/") {
                        findings.append(Finding(
                            severity: .medium, category: .suspiciousProcess,
                            title: "Dylib loaded from user directory into \(proc.name)",
                            detail: "PID \(proc.pid), Library: \(libPath)",
                            path: libPath,
                            remediation: "Verify this library is expected"
                        ))
                    }
                }
            }
        }
    }

    private func scanProcessHierarchy(processes: [ProcessEntry], findings: inout [Finding]) {
        let myPid = ProcessInfo.processInfo.processIdentifier

        for proc in processes {
            if proc.pid <= 1 || proc.pid == myPid { continue }
            guard let path = proc.path else { continue }

            // Skip system processes
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/") ||
               path.hasPrefix("/bin/") || path.hasPrefix("/sbin/") { continue }
            if whitelistedProcessNames.contains(proc.name) { continue }

            // Orphan detection: parent doesn't exist (was killed) but child persists
            // Parent PID 1 = adopted by launchd, which is normal for daemons
            // But if it's not from a standard daemon path and ppid is 1, it could be suspicious
            if proc.ppid == 1 && proc.uid != 0 {
                // User-owned process adopted by launchd from non-standard path
                let isTrusted = trustedPathPrefixes.contains { path.hasPrefix($0) }
                if !isTrusted {
                    let sigInfo = checkCodeSignature(path: path)
                    if !sigInfo.isSigned {
                        findings.append(Finding(
                            severity: .medium, category: .suspiciousProcess,
                            title: "Unsigned orphan process running as daemon",
                            detail: "Name: \(proc.name), PID: \(proc.pid), Parent: launchd (adopted)",
                            path: path,
                            remediation: "This unsigned process is running without a parent — investigate its origin"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Cryptominer detection

    /// Process-name fragments used by well-known cryptominer families. We match conservatively —
    /// full equality or a very specific substring — because names like "xmr" appear in legitimate
    /// processes too.
    private let cryptominerNames: Set<String> = [
        "xmrig", "xmrigdaemon", "xmr-stak", "xmr-stak-cpu", "xmr-stak-amd",
        "cpuminer", "cpuminer-multi", "minerd", "ethminer", "claymore",
        "nanominer", "nbminer", "phoenixminer", "t-rex", "trex",
        "lolminer", "teamredminer", "gminer", "bzminer",
        "kawpowminer", "rigelminer", "srbminer",
    ]

    /// Flags running cryptominers. Miners rarely hide behind a renamed binary on macOS because
    /// OpenCL/Metal initialization logs via the binary's own path; we match the process name only.
    private func scanForCryptominers(processes: [ProcessEntry], findings: inout [Finding]) {
        let myPid = ProcessInfo.processInfo.processIdentifier

        for proc in processes {
            if proc.pid <= 1 || proc.pid == myPid { continue }

            let nameLower = proc.name.lowercased()
            guard cryptominerNames.contains(nameLower) else { continue }

            findings.append(Finding(
                severity: .high,
                category: .cryptomining,
                title: "Cryptominer process running: \"\(proc.name)\"",
                detail: "PID \(proc.pid), Path: \(proc.path ?? "unknown") — known miner family",
                path: proc.path,
                remediation: "Terminate: kill \(proc.pid) — then hunt for the dropper via persistence/browser extensions"
            ))
        }
    }

    private struct ProcessEntry {
        let pid: Int32
        let ppid: Int32
        let name: String
        let path: String?
        let uid: UInt32
    }

    private func listProcesses() -> [ProcessEntry] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var bufferSize = 0

        guard sysctl(&mib, UInt32(mib.count), nil, &bufferSize, nil, 0) == 0 else {
            return []
        }

        let entryCount = bufferSize / MemoryLayout<kinfo_proc>.stride
        let buffer = UnsafeMutablePointer<kinfo_proc>.allocate(capacity: entryCount)
        defer { buffer.deallocate() }

        guard sysctl(&mib, UInt32(mib.count), buffer, &bufferSize, nil, 0) == 0 else {
            return []
        }

        let actualCount = bufferSize / MemoryLayout<kinfo_proc>.stride
        var results: [ProcessEntry] = []

        for i in 0..<actualCount {
            let proc = buffer[i]
            let pid = proc.kp_proc.p_pid

            // Extract process name from kinfo_proc
            let procName = withUnsafePointer(to: proc.kp_proc.p_comm) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN) + 1) { charPtr in
                    String(cString: charPtr)
                }
            }

            // Get full path via proc_pidpath
            var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let pathLen = proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
            let path = pathLen > 0 ? String(cString: pathBuffer) : nil

            let uid = proc.kp_eproc.e_ucred.cr_uid
            let ppid = proc.kp_eproc.e_ppid

            results.append(ProcessEntry(pid: pid, ppid: ppid, name: procName, path: path, uid: uid))
        }

        return results
    }

    private struct CodeSignInfo {
        let isSigned: Bool
        let isAppleSigned: Bool
        let isAdHoc: Bool
        let identity: String?
    }

    private func checkCodeSignature(path: String) -> CodeSignInfo {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?

        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return CodeSignInfo(isSigned: false, isAppleSigned: false, isAdHoc: false, identity: nil)
        }

        let checkResult = SecStaticCodeCheckValidityWithErrors(code, SecCSFlags(rawValue: 0), nil, nil)
        guard checkResult == errSecSuccess else {
            return CodeSignInfo(isSigned: false, isAppleSigned: false, isAdHoc: false, identity: nil)
        }

        // Get signing info
        var infoDict: CFDictionary?
        SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &infoDict)

        var identity: String?
        var isAdHoc = false
        var isApple = false

        if let info = infoDict as? [String: Any] {
            if let id = info[kSecCodeInfoIdentifier as String] as? String {
                identity = id
            }
            if let teamId = info[kSecCodeInfoTeamIdentifier as String] as? String {
                if teamId.isEmpty {
                    isAdHoc = true
                }
            } else {
                // No team identifier — could be ad-hoc or Apple-signed
                isAdHoc = identity != nil
            }
        }

        // Check if Apple-signed using anchor requirement
        var requirement: SecRequirement?
        if SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
           let req = requirement {
            isApple = SecStaticCodeCheckValidityWithErrors(code, [], req, nil) == errSecSuccess
        }

        if isApple { isAdHoc = false }

        return CodeSignInfo(isSigned: true, isAppleSigned: isApple, isAdHoc: isAdHoc, identity: identity)
    }
}
