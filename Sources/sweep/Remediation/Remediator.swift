import Foundation

enum RemediationResult {
    case fixed(title: String, detail: String)
    case skipped(title: String, reason: String)
    case dryRun(title: String, detail: String)
    case failed(title: String, error: String)
}

struct Remediator {
    let dryRun: Bool

    func remediate(findings: [Finding]) -> [RemediationResult] {
        var results: [RemediationResult] = []

        for finding in findings {
            guard let action = actionFor(finding) else { continue }

            if dryRun {
                results.append(.dryRun(title: action.title, detail: action.description))
                continue
            }

            if !action.safe {
                results.append(.skipped(title: action.title, reason: "requires manual confirmation"))
                continue
            }

            let success = execute(action)
            if success {
                results.append(.fixed(title: action.title, detail: action.description))
            } else {
                results.append(.failed(title: action.title, error: "command failed"))
            }
        }

        return results
    }

    private func actionFor(_ finding: Finding) -> RemediationAction? {
        // Match findings to safe remediation actions
        let title = finding.title.lowercased()

        // Hardening fixes (Tier A — safe)
        if title.contains("firewall is disabled") {
            return RemediationAction(
                title: "Enable macOS firewall",
                description: "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
                arguments: ["--setglobalstate", "on"],
                safe: true
            )
        }
        if title.contains("stealth mode is disabled") {
            return RemediationAction(
                title: "Enable firewall stealth mode",
                description: "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
                executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
                arguments: ["--setstealthmode", "on"],
                safe: true
            )
        }
        if title.contains("auto-login is enabled") {
            return RemediationAction(
                title: "Disable auto-login",
                description: "defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
                executable: "/usr/bin/defaults",
                arguments: ["delete", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"],
                safe: true
            )
        }
        if title.contains("guest account is enabled") {
            return RemediationAction(
                title: "Disable guest account",
                description: "defaults write com.apple.loginwindow GuestEnabled -bool false",
                executable: "/usr/bin/defaults",
                arguments: ["write", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled", "-bool", "false"],
                safe: true
            )
        }
        if title.contains("automatic software update checks are disabled") {
            return RemediationAction(
                title: "Enable automatic update checks",
                description: "defaults write com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true",
                executable: "/usr/bin/defaults",
                arguments: ["write", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled", "-bool", "true"],
                safe: true
            )
        }
        if title.contains("password hints are shown") {
            return RemediationAction(
                title: "Disable password hints at login",
                description: "defaults write com.apple.loginwindow RetriesUntilHint -int 0",
                executable: "/usr/bin/defaults",
                arguments: ["write", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint", "-int", "0"],
                safe: true
            )
        }

        // Orphaned plists (Tier A — safe, the executable doesn't exist)
        if title.contains("references missing executable"), let path = finding.path {
            return RemediationAction(
                title: "Remove orphaned plist",
                description: "rm \(path)",
                executable: "/bin/rm",
                arguments: [path],
                safe: true
            )
        }

        // Tier B — not auto-applied
        if title.contains("filevault") {
            return RemediationAction(
                title: "Enable FileVault encryption",
                description: "fdesetup enable (requires restart)",
                executable: "/usr/bin/fdesetup",
                arguments: ["enable"],
                safe: false
            )
        }
        if title.contains("remote login") {
            return RemediationAction(
                title: "Disable Remote Login (SSH)",
                description: "systemsetup -setremotelogin off",
                executable: "/usr/sbin/systemsetup",
                arguments: ["-setremotelogin", "off"],
                safe: false
            )
        }

        return nil
    }

    private func execute(_ action: RemediationAction) -> Bool {
        guard getuid() == 0 else { return false }
        let result = ShellRunner.run(action.executable, arguments: action.arguments, timeout: 10)
        return result.success
    }
}
