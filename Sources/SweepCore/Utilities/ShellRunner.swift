import Foundation
#if canImport(Darwin)
import Darwin
#endif

public struct ShellResult {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public var success: Bool { exitCode == 0 }
}

// Shared proc_pidpath import — used by ProcessScanner, EventTapScanner, NetworkScanner
@_silgen_name("proc_pidpath")
func proc_pidpath(_ pid: Int32, _ buffer: UnsafeMutableRawPointer, _ bufferSize: UInt32) -> Int32

public enum ShellRunner {
    public static func run(_ executable: String, arguments: [String] = [], timeout: TimeInterval = 30) -> ShellResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        do {
            try process.run()
        } catch {
            return ShellResult(exitCode: -1, stdout: "", stderr: error.localizedDescription)
        }

        // Read stdout and stderr concurrently BEFORE waiting for termination.
        // Reading after wait causes deadlocks when pipe buffers fill (~64KB)
        // because the child blocks on write while we block on termination.
        var outData = Data()
        var errData = Data()
        let readGroup = DispatchGroup()

        readGroup.enter()
        DispatchQueue.global(qos: .utility).async {
            outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            readGroup.leave()
        }
        readGroup.enter()
        DispatchQueue.global(qos: .utility).async {
            errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            readGroup.leave()
        }

        let semaphore = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in semaphore.signal() }
        let waitResult = semaphore.wait(timeout: .now() + timeout)

        if waitResult == .timedOut {
            process.terminate()
            Thread.sleep(forTimeInterval: 1.0)
            if process.isRunning { process.interrupt() }
            // Drain remaining pipe data to avoid leaking file descriptors
            readGroup.wait()
            return ShellResult(exitCode: -2, stdout: "", stderr: "Process timed out")
        }

        readGroup.wait()

        return ShellResult(
            exitCode: process.terminationStatus,
            stdout: String(data: outData, encoding: .utf8) ?? "",
            stderr: String(data: errData, encoding: .utf8) ?? ""
        )
    }

    public static func which(_ command: String) -> String? {
        let result = run("/usr/bin/which", arguments: [command])
        let path = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return result.success && !path.isEmpty ? path : nil
    }

    /// Returns the real user's home directory, even when running under sudo.
    public static var realUserHome: String {
        if let sudoUser = ProcessInfo.processInfo.environment["SUDO_USER"] {
            // Sanitize: SUDO_USER must be a simple username (alphanumeric, hyphen, underscore, period).
            // Reject anything that could cause path traversal (e.g. "../../etc").
            let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
            let isValid = !sudoUser.isEmpty &&
                          sudoUser.unicodeScalars.allSatisfy({ allowed.contains($0) }) &&
                          !sudoUser.contains("..")
            if isValid {
                let home = "/Users/\(sudoUser)"
                // Double-check the resolved path is actually under /Users/
                if FileManager.default.fileExists(atPath: home) {
                    return home
                }
            }
        }
        return NSHomeDirectory()
    }

    /// Get process path by PID using proc_pidpath
    public static func processPath(for pid: Int32) -> String? {
        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let len = proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
        guard len > 0 else { return nil }
        return String(cString: pathBuffer)
    }
}
