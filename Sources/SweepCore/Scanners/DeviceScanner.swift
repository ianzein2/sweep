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

        // 3. Check for installed audio loopback / virtual driver plug-ins.
        //    Stealthy alternative to microphone-tap surveillance: these drivers route
        //    *system audio* (calls, meeting playback, music) into a virtual input that
        //    any process can record without triggering the Microphone TCC prompt.
        progress?.update("checking audio capture drivers")
        checkAudioCaptureDrivers(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Audio Loopback / Virtual Drivers

    /// Driver bundle name → (display name, severity).
    /// Severity captures how often the driver is used by malware vs. legitimately.
    /// `.medium` = legitimate but powerful; `.high` = strong indicator if user didn't install it.
    private let knownAudioDrivers: [(bundle: String, display: String, severity: Severity, note: String)] = [
        ("BlackHole2ch.driver",    "BlackHole (2ch)",    .medium,
         "free virtual loopback used to record system audio into apps like OBS or Audio Hijack"),
        ("BlackHole16ch.driver",   "BlackHole (16ch)",   .medium,
         "free virtual loopback used to record system audio into apps like OBS or Audio Hijack"),
        ("BlackHole64ch.driver",   "BlackHole (64ch)",   .medium,
         "free virtual loopback used to record system audio into apps like OBS or Audio Hijack"),
        ("Soundflower.driver",     "Soundflower",       .high,
         "abandonware loopback driver — frequently bundled with macOS surveillance kits"),
        ("Loopback.driver",        "Rogue Amoeba Loopback", .medium,
         "commercial multi-channel audio router — legitimate but powerful audio capture"),
        ("LoopbackAudio.driver",   "Rogue Amoeba Loopback", .medium,
         "commercial multi-channel audio router — legitimate but powerful audio capture"),
        ("ACE.driver",             "Rogue Amoeba ACE",   .medium,
         "Audio Capture Engine — Audio Hijack / Loopback / Piezo backend"),
        ("iShowU Audio Capture.driver", "iShowU Audio Capture", .medium,
         "screen-recorder audio loopback — legitimate but routes system audio"),
        ("WavTap.driver",          "WavTap",            .high,
         "abandoned audio capture driver — not from a current vendor"),
        ("EasyAudioOutput.driver", "EasyAudio",         .high,
         "obscure audio loopback driver — uncommon outside of malware"),
        ("VBCABLE_A.driver",       "VB-Audio Cable",    .medium,
         "free virtual audio cable from VB-Audio — legitimate but routes system audio"),
        ("VBCABLE_B.driver",       "VB-Audio Cable B",  .medium,
         "free virtual audio cable from VB-Audio — legitimate but routes system audio"),
        ("Hush.driver",            "Hush",              .high,
         "obscure capture driver — not from a current vendor"),
    ]

    private func checkAudioCaptureDrivers(findings: inout [Finding], errors: inout [String]) {
        // CoreAudio HAL plug-ins live in two well-known locations.
        let pluginDirs = [
            "/Library/Audio/Plug-Ins/HAL",
            "\(ShellRunner.realUserHome)/Library/Audio/Plug-Ins/HAL",
        ]
        let fm = FileManager.default

        for dir in pluginDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where entry.hasSuffix(".driver") {
                let path = "\(dir)/\(entry)"

                if let known = knownAudioDrivers.first(where: { $0.bundle == entry }) {
                    findings.append(Finding(
                        severity: known.severity,
                        category: .deviceAccess,
                        title: "Audio loopback driver installed: \(known.display)",
                        detail: "\(entry) — \(known.note). Loopback drivers let any app record system audio without triggering Microphone permission prompts.",
                        path: path,
                        remediation: "Verify you installed this. To remove: sudo rm -rf \"\(path)\" (then reboot)."
                    ))
                } else {
                    // Unknown HAL plug-in — not on Apple-or-named-vendor list.
                    findings.append(Finding(
                        severity: .medium,
                        category: .deviceAccess,
                        title: "Unknown audio driver plug-in",
                        detail: "\(entry) — third-party CoreAudio plug-in not from a recognized vendor. Plug-ins here can intercept or route system audio.",
                        path: path,
                        remediation: "Investigate: ls -la \"\(path)\" and inspect the bundle's Info.plist. Remove if unexpected."
                    ))
                }
            }
        }
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
