import Foundation
import CoreGraphics
#if canImport(Darwin)
import Darwin
#endif

public final class EventTapScanner: Scanner {
    public let name = "Event Tap Scan"
    public init() {}

    // Keyboard event types in CGEventType
    private let keyboardEventMask: CGEventMask = {
        (1 << CGEventType.keyDown.rawValue) |
        (1 << CGEventType.keyUp.rawValue) |
        (1 << CGEventType.flagsChanged.rawValue)
    }()

    // Known legitimate event tap creators
    private let whitelistedProcessNames: Set<String> = [
        "WindowServer", "loginwindow", "Dock", "SystemUIServer",
        // Keyboard remappers
        "Karabiner-Elements", "karabiner_grabber", "karabiner_observer",
        "Karabiner-EventViewer",
        // Automation tools
        "BetterTouchTool", "Hammerspoon", "skhd",
        "KeyboardMaestro Engine", "Alfred",
        // Accessibility
        "VoiceOver", "AssistiveControl",
        "universalaccessd", "universalAccessAuthWarn",
        // System UI
        "ViewBridgeAuxiliary", "SystemUIServer",
        "ControlCenter", "NotificationCenter",
        "Spotlight", "Finder",
        // Input methods
        "TextInputMenuAgent", "TextInputSwitcher",
        // Screen sharing
        "screensharingd", "ScreensharingAgent",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        // Get list of all event taps
        var tapCount: UInt32 = 0
        guard CGGetEventTapList(0, nil, &tapCount) == .success, tapCount > 0 else {
            errors.append("Could not enumerate event taps (may need Accessibility permission)")
            return ScanResult(scannerName: name, findings: findings, errors: errors,
                            duration: Date().timeIntervalSince(start))
        }

        var tapList = [CGEventTapInformation](repeating: CGEventTapInformation(), count: Int(tapCount))
        guard CGGetEventTapList(tapCount, &tapList, &tapCount) == .success else {
            errors.append("Failed to retrieve event tap list")
            return ScanResult(scannerName: name, findings: findings, errors: errors,
                            duration: Date().timeIntervalSince(start))
        }

        for tap in tapList.prefix(Int(tapCount)) {
            let interceptsKeyboard = (tap.eventsOfInterest & keyboardEventMask) != 0
            let isGlobal = tap.processBeingTapped == 0

            guard interceptsKeyboard else { continue }

            let pid = Int32(tap.tappingProcess)
            let processName = getProcessName(pid: pid)
            let processPath = getProcessPath(pid: pid)

            // Skip whitelisted processes
            if let name = processName, whitelistedProcessNames.contains(name) { continue }

            // Skip Apple system processes (from /System/ or /usr/)
            if let path = processPath,
               path.hasPrefix("/System/") || path.hasPrefix("/usr/") { continue }

            let tapType = tap.options == CGEventTapOptions.defaultTap ? "active (can modify)" : "listen-only"
            let scope = isGlobal ? "GLOBAL" : "targeted (PID \(tap.processBeingTapped))"

            if isGlobal {
                findings.append(Finding(
                    severity: .high,
                    category: .keylogging,
                    title: "Global keyboard event tap detected",
                    detail: "Process: \(processName ?? "PID \(pid)"), Type: \(tapType), Scope: \(scope)",
                    path: processPath,
                    remediation: "Investigate process \(processName ?? "PID \(pid)") — global keyboard taps are the primary keylogging mechanism on macOS"
                ))
            } else {
                findings.append(Finding(
                    severity: .medium,
                    category: .keylogging,
                    title: "Keyboard event tap detected",
                    detail: "Process: \(processName ?? "PID \(pid)"), Type: \(tapType), Scope: \(scope)",
                    path: processPath,
                    remediation: "Verify this process needs keyboard access"
                ))
            }
        }

        if findings.isEmpty && tapCount > 0 {
            // All taps were whitelisted — no suspicious ones found
        }

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    private func getProcessName(pid: Int32) -> String? {
        guard let path = ShellRunner.processPath(for: pid) else { return nil }
        return URL(fileURLWithPath: path).lastPathComponent
    }

    private func getProcessPath(pid: Int32) -> String? {
        return ShellRunner.processPath(for: pid)
    }
}
