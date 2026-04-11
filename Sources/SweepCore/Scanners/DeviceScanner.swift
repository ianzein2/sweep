import Foundation

public final class DeviceScanner: Scanner {
    public let name = "Device Access Scan"
    public init() {}

    // Known legitimate processes that access camera/mic
    private let whitelistedProcessNames: Set<String> = [
        "VDCAssistant", "AppleCameraAssistant", "avconferenced",
        "coreaudiod", "audioclocksyncd", "FaceTime",
        "Photo Booth", "QuickTime Player", "zoom.us",
        "Microsoft Teams", "Slack", "Discord", "Safari",
        "Google Chrome", "firefox", "Brave Browser",
        "OBS", "obs", "FaceTimeNotificationCenterService",
        "WindowServer", "loginwindow", "screencaptureui",
        "screensharingd", "ScreensharingAgent",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        // 1. Check for processes accessing camera device files
        progress?.update("checking camera access")
        checkCameraAccess(findings: &findings, errors: &errors)

        // 2. Check for processes accessing microphone / audio input
        progress?.update("checking microphone access")
        checkMicrophoneAccess(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    private func checkCameraAccess(findings: inout [Finding], errors: inout [String]) {
        // Check via lsof for processes with camera-related files open
        let cameraResult = ShellRunner.run("/usr/sbin/lsof", arguments: ["+c", "0", "-w"], timeout: 15)

        if cameraResult.success {
            let lines = cameraResult.stdout.split(separator: "\n")
            for line in lines {
                let lineStr = String(line)
                // Look for processes accessing camera-related paths
                if lineStr.contains("AppleCamera") || lineStr.contains("VDC") ||
                   lineStr.contains("IOUSB") || lineStr.contains("CoreMedia") {

                    let parts = lineStr.split(separator: " ", maxSplits: 1)
                    guard let processName = parts.first else { continue }
                    let name = String(processName)

                    if whitelistedProcessNames.contains(name) { continue }

                    // Check against known spyware
                    if let sig = SpywareSignature.match(processName: name) {
                        findings.append(Finding(
                            severity: .high,
                            category: .deviceAccess,
                            title: "Known spyware is accessing the camera: \(sig.name)",
                            detail: "Process: \(name)",
                            path: nil,
                            remediation: "Terminate this process immediately and remove \(sig.name)"
                        ))
                    }
                }
            }
        }

    }

    private func checkMicrophoneAccess(findings: inout [Finding], errors: inout [String]) {
        // Check for processes that have audio-related files open
        let audioResult = ShellRunner.run("/bin/sh", arguments: [
            "-c",
            "lsof -w 2>/dev/null | grep -i 'audioinput\\|microphone\\|audio.input\\|coreaudio' | head -20"
        ], timeout: 10)

        if audioResult.success && !audioResult.stdout.isEmpty {
            let lines = audioResult.stdout.split(separator: "\n")
            for line in lines {
                let parts = String(line).split(separator: " ", maxSplits: 1)
                guard let processName = parts.first else { continue }
                let name = String(processName)

                if whitelistedProcessNames.contains(name) { continue }
                if name == "lsof" || name == "grep" { continue }

                if let sig = SpywareSignature.match(processName: name) {
                    findings.append(Finding(
                        severity: .high,
                        category: .deviceAccess,
                        title: "Known spyware is accessing the microphone: \(sig.name)",
                        detail: "Process: \(name)",
                        path: nil,
                        remediation: "Terminate this process immediately and remove \(sig.name)"
                    ))
                }
            }
        }
    }
}
