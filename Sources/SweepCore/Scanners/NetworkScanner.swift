import Foundation
import Security

public final class NetworkScanner: Scanner {
    public let name = "Network Scan"
    public init() {}

    private let trustedProcessNames: Set<String> = [
        // System daemons
        "mDNSResponder", "configd", "nsurlsessiond", "trustd",
        "networkd", "symptomsd", "apsd", "cloudd", "IMDPersistenceAgent",
        "CalendarAgent", "AddressBookSourceSync", "akd", "secd",
        "rapportd", "identityservicesd", "sharingd", "CommCenter",
        "WiFiAgent", "airportd", "bluetoothd", "wifid",
        "WindowServer", "loginwindow", "Dock", "SystemUIServer",
        "com.apple.WebKit.Networking", "nsurlstoraged",
        "softwareupdated", "commerce", "storeassetd", "storedownloadd",
        "biomed", "healthd", "remindd", "suggestd", "parsecd",
        "photolibraryd", "photoanalysisd", "mediaremoted",
        "amsaccountsd", "amsengagementd", "AMPDeviceDiscoveryAgent",
        "assistantd", "siriknowledged", "searchpartyd",
        "ReportCrash", "spindump", "diagnosticd",
        "translationd", "coreduetd", "knowledge-agent",
        "NotificationCenter", "UsageTrackingAgent",
        // User apps
        "Finder", "Safari", "Google Chrome", "firefox", "Brave Browser",
        "Mail", "Messages", "FaceTime", "Music", "Podcasts", "News",
        "Slack", "Discord", "Microsoft Teams", "zoom.us", "Telegram",
        "Spotify", "App Store",
        // Dev tools
        "Xcode", "git", "ssh", "curl", "wget", "node", "python3", "ruby",
        "Code Helper", "Electron", "Code Helper (Renderer)",
        "com.docker.backend", "docker", "kubectl",
        "brew", "npm", "yarn", "pnpm",
    ]

    private let suspiciousPorts: Set<Int> = [
        4444, 5555, 6666, 7777, 8888, 9999,  // Common RAT/C2 ports
        1337, 31337,                           // Hacker culture ports
        4443, 8443,                            // Alt HTTPS often used by C2
        6667, 6668, 6669, 6697,               // IRC (used by some botnets)
        3127, 12345, 65535,                    // Known trojan ports
    ]

    private let blockedAppleDomains: Set<String> = [
        "ocsp.apple.com", "mesu.apple.com", "updates.apple.com",
        "xp.apple.com", "gdmf.apple.com", "gs.apple.com",
        "ppq.apple.com", "albert.apple.com", "captive.apple.com",
        "gsa.apple.com", "gspe1-ssl.ls.apple.com",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        // 1. Active network connections
        progress?.update("checking active connections")
        scanActiveConnections(findings: &findings, errors: &errors)

        // 2. Check /etc/hosts
        progress?.update("checking /etc/hosts")
        scanHostsFile(findings: &findings, errors: &errors)

        // 3. Check for proxy / PAC URL hijacking — a common man-in-the-middle vector used by
        //    infostealers and enterprise monitoring tools that redirect browser traffic.
        progress?.update("checking proxy configuration")
        scanProxyConfiguration(findings: &findings, errors: &errors)

        // 4. Tunneling tools (ngrok, cloudflared, frp, chisel, gost) — increasingly used as
        //    lightweight C2 channels because they egress over 443 to legitimate cloud hosts.
        progress?.update("checking for tunneling tools")
        scanTunnelingTools(findings: &findings, errors: &errors)

        // 5. Browser remote-debugging port (CDP 9222) — when reachable, anything on the host
        //    can read cookies, session tokens, and saved logins from the live browser.
        progress?.update("checking browser debugging ports")
        scanRemoteDebuggingPorts(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Active Network Connections

    private func scanActiveConnections(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/sbin/lsof", arguments: [
            "-i", "-n", "-P", "+c", "0", "-w"
        ], timeout: 20)

        guard result.success && !result.stdout.isEmpty else {
            if !result.success {
                errors.append("lsof network scan failed: \(result.stderr)")
            }
            return
        }

        struct ConnectionInfo {
            let command: String
            let pid: String
            let user: String
            let connection: String
            let isEstablished: Bool
            let isListening: Bool
            let remotePort: Int?
        }

        var connectionsByProcess: [String: [ConnectionInfo]] = [:]
        let lines = result.stdout.split(separator: "\n")

        for line in lines.prefix(500) {  // Cap at 500 lines for performance
            let lineStr = String(line)
            if lineStr.hasPrefix("COMMAND") { continue }  // Skip header

            let parts = lineStr.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 9 else { continue }

            let command = String(parts[0])
            let pid = String(parts[1])
            let connectionName = String(parts.last ?? "")

            // Skip trusted processes
            if trustedProcessNames.contains(command) { continue }
            if command.hasPrefix("com.apple.") { continue }

            let isEstablished = connectionName.contains("ESTABLISHED") || lineStr.contains("ESTABLISHED")
            let isListening = connectionName.contains("LISTEN") || lineStr.contains("LISTEN")

            // Extract remote port from connection string like "host:port->remote:port"
            var remotePort: Int?
            if let arrowRange = connectionName.range(of: "->") {
                let remote = String(connectionName[arrowRange.upperBound...])
                if let colonRange = remote.range(of: ":", options: .backwards) {
                    let portStr = remote[colonRange.upperBound...].replacingOccurrences(of: " ", with: "")
                        .replacingOccurrences(of: "(ESTABLISHED)", with: "")
                    remotePort = Int(portStr)
                }
            }

            let conn = ConnectionInfo(
                command: command, pid: pid, user: String(parts[2]),
                connection: connectionName,
                isEstablished: isEstablished, isListening: isListening,
                remotePort: remotePort
            )
            connectionsByProcess["\(command):\(pid)", default: []].append(conn)
        }

        let myPid = "\(ProcessInfo.processInfo.processIdentifier)"

        for (key, connections) in connectionsByProcess {
            let parts = key.split(separator: ":", maxSplits: 1)
            let command = String(parts[0])
            let pid = String(parts[1])

            // Skip ourselves
            if pid == myPid { continue }

            // Check against known spyware
            if let sig = SpywareSignature.match(processName: command) {
                let established = connections.filter { $0.isEstablished }
                if !established.isEmpty {
                    findings.append(Finding(
                        severity: .high, category: .networkActivity,
                        title: "Known spyware with active network connection: \(sig.name)",
                        detail: "Process: \(command) (PID \(pid)), \(established.count) active connection(s)",
                        path: nil,
                        remediation: "Kill process: kill \(pid) — then remove \(sig.name)"
                    ))
                }
                continue
            }

            // Check for suspicious ports
            for conn in connections {
                if let port = conn.remotePort, suspiciousPorts.contains(port) {
                    findings.append(Finding(
                        severity: .medium, category: .networkActivity,
                        title: "Connection on suspicious port \(port)",
                        detail: "Process: \(command) (PID \(pid)), Connection: \(conn.connection)",
                        path: nil,
                        remediation: "Investigate this process: ps aux | grep \(pid)"
                    ))
                }
            }

            // Check for unsigned processes with outbound connections
            let establishedConns = connections.filter { $0.isEstablished }
            if !establishedConns.isEmpty {
                if let pidInt = Int32(pid),
                   let path = ShellRunner.processPath(for: pidInt) {
                    let trustedPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/",
                                           "/Applications/", "/Library/Apple/",
                                           "/opt/homebrew/"]
                    if !trustedPrefixes.contains(where: { path.hasPrefix($0) }) {
                        let sigInfo = checkCodeSignature(path: path)
                        if !sigInfo.isSigned {
                            findings.append(Finding(
                                severity: .high, category: .networkActivity,
                                title: "Unsigned process with network connections",
                                detail: "Process: \(command) (PID \(pid)), \(establishedConns.count) connection(s)",
                                path: path,
                                remediation: "Investigate this unsigned binary making network connections"
                            ))
                        }
                    }
                }
            }

            // Flag processes listening on non-standard ports
            let listening = connections.filter { $0.isListening }
            for conn in listening {
                // Extract local port
                let connStr = conn.connection
                if let colonRange = connStr.range(of: ":", options: .backwards) {
                    let portPart = connStr[colonRange.upperBound...]
                        .replacingOccurrences(of: " ", with: "")
                        .replacingOccurrences(of: "(LISTEN)", with: "")
                    if let port = Int(portPart), port > 0 {
                        let commonPorts: Set<Int> = [22, 80, 443, 3000, 3001, 4200, 5000, 5173, 5432,
                                                     8000, 8080, 8081, 9090, 27017, 6379, 11211]
                        if !commonPorts.contains(port) && suspiciousPorts.contains(port) {
                            findings.append(Finding(
                                severity: .medium, category: .networkActivity,
                                title: "Process listening on suspicious port \(port)",
                                detail: "Process: \(command) (PID \(pid))",
                                path: nil,
                                remediation: "Investigate: lsof -i :\(port)"
                            ))
                        }
                    }
                }
            }
        }
    }

    // MARK: - /etc/hosts Analysis

    private func scanHostsFile(findings: inout [Finding], errors: inout [String]) {
        guard let content = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8) else {
            return
        }

        let lines = content.split(separator: "\n")
        var customEntries = 0

        for line in lines {
            let lineStr = String(line).trimmingCharacters(in: .whitespaces)
            if lineStr.isEmpty || lineStr.hasPrefix("#") { continue }

            // Parse: IP hostname [aliases...] — handle both tabs and spaces
            let parts = lineStr.components(separatedBy: CharacterSet.whitespaces)
                .filter { !$0.isEmpty }
            guard parts.count >= 2 else { continue }

            let ip = parts[0]

            // Skip localhost entries
            if ip == "127.0.0.1" || ip == "::1" || ip == "255.255.255.255" {
                let hostname = parts[1].lowercased()
                if hostname == "localhost" || hostname == "broadcasthost" { continue }
            }

            customEntries += 1

            // Check if any Apple security domains are being redirected
            for domain in blockedAppleDomains {
                if lineStr.lowercased().contains(domain) {
                    findings.append(Finding(
                        severity: .high, category: .networkActivity,
                        title: "Apple security domain redirected in /etc/hosts",
                        detail: "Domain: \(domain) → \(ip) — blocks macOS security checks",
                        path: "/etc/hosts",
                        remediation: "Remove this line from /etc/hosts: sudo nano /etc/hosts"
                    ))
                }
            }
        }

        // Flag unusually large hosts file
        if customEntries > 200 {
            findings.append(Finding(
                severity: .low, category: .networkActivity,
                title: "Large number of custom /etc/hosts entries (\(customEntries))",
                detail: "Could be an ad-blocker or could indicate domain redirection by malware",
                path: "/etc/hosts",
                remediation: "Review /etc/hosts for unexpected entries"
            ))
        }
    }

    // MARK: - Proxy / PAC Hijack Detection

    private func scanProxyConfiguration(findings: inout [Finding], errors: inout [String]) {
        // `networksetup -listallnetworkservices` returns one per line, first line is a header.
        let servicesResult = ShellRunner.run("/usr/sbin/networksetup",
                                             arguments: ["-listallnetworkservices"], timeout: 5)
        guard servicesResult.success else { return }

        let services = servicesResult.stdout
            .split(separator: "\n")
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.contains("denoted") && !$0.hasPrefix("*") }

        let proxyKinds: [(flag: String, label: String)] = [
            ("-getwebproxy",        "HTTP proxy"),
            ("-getsecurewebproxy",  "HTTPS proxy"),
            ("-getsocksfirewallproxy", "SOCKS proxy"),
            ("-getftpproxy",        "FTP proxy"),
            ("-getstreamingproxy",  "Streaming proxy"),
            ("-getgopherproxy",     "Gopher proxy"),
        ]

        for service in services {
            // PAC URL first — a single malicious PAC file can reroute ALL traffic per-URL.
            let autoProxy = ShellRunner.run("/usr/sbin/networksetup",
                                            arguments: ["-getautoproxyurl", service], timeout: 5)
            if autoProxy.success {
                let lines = autoProxy.stdout.split(separator: "\n")
                    .map { String($0).trimmingCharacters(in: .whitespaces) }
                let enabled = lines.contains { $0.hasPrefix("Enabled:") && $0.contains("Yes") }
                let urlLine = lines.first { $0.hasPrefix("URL:") }
                let url = urlLine.map { $0.replacingOccurrences(of: "URL:", with: "").trimmingCharacters(in: .whitespaces) } ?? ""

                if enabled && !url.isEmpty && url != "(null)" {
                    // PAC URLs that use plain http:// are especially risky — the PAC file itself can be swapped in transit.
                    let isInsecure = url.lowercased().hasPrefix("http://")
                    findings.append(Finding(
                        severity: isInsecure ? .high : .medium,
                        category: .networkActivity,
                        title: "Automatic proxy configuration (PAC) is enabled",
                        detail: "Service \"\(service)\" is using PAC URL: \(url)" +
                            (isInsecure ? " — served over plain HTTP, trivially man-in-the-middle-able" : ""),
                        path: nil,
                        remediation: "Verify this is your employer's proxy, or disable: System Settings > Network > \(service) > Details > Proxies"
                    ))
                }
            }

            // Per-protocol proxies
            for kind in proxyKinds {
                let proxyResult = ShellRunner.run("/usr/sbin/networksetup",
                                                  arguments: [kind.flag, service], timeout: 5)
                guard proxyResult.success else { continue }

                let lines = proxyResult.stdout.split(separator: "\n")
                    .map { String($0).trimmingCharacters(in: .whitespaces) }
                let enabled = lines.contains { $0.hasPrefix("Enabled:") && $0.contains("Yes") }
                guard enabled else { continue }

                let server = lines.first { $0.hasPrefix("Server:") }
                    .map { $0.replacingOccurrences(of: "Server:", with: "").trimmingCharacters(in: .whitespaces) } ?? "?"
                let port = lines.first { $0.hasPrefix("Port:") }
                    .map { $0.replacingOccurrences(of: "Port:", with: "").trimmingCharacters(in: .whitespaces) } ?? "?"

                // Proxies pointing at loopback usually mean a local interception tool (Charles, Proxyman, mitmproxy)
                // — legitimate for developers, but worth noting.
                let isLoopback = server == "127.0.0.1" || server == "localhost" || server == "::1"
                findings.append(Finding(
                    severity: isLoopback ? .low : .medium,
                    category: .networkActivity,
                    title: "\(kind.label) is enabled",
                    detail: "Service \"\(service)\" routes \(kind.label.lowercased()) traffic via \(server):\(port)" +
                        (isLoopback ? " (local interception proxy)" : ""),
                    path: nil,
                    remediation: isLoopback
                        ? "Expected if you're using Proxyman/Charles/mitmproxy — otherwise disable in Network settings"
                        : "Verify this proxy is authorized, or disable: System Settings > Network > \(service) > Details > Proxies"
                ))
            }
        }
    }

    // MARK: - Tunneling Tools

    /// Process names belonging to popular tunneling tools. Each of these can punch a hole
    /// through NAT and forward arbitrary local traffic to a remote operator, which is exactly
    /// what modern C2 frameworks (and red-team kits) want.
    private let tunnelingProcessNames: [(name: String, label: String, severity: Severity)] = [
        ("ngrok",         "ngrok",         .medium),
        ("cloudflared",   "cloudflared",   .medium),
        ("frpc",          "frp client",    .high),
        ("frps",          "frp server",    .high),
        ("chisel",        "chisel tunnel", .high),
        ("gost",          "gost tunnel",   .high),
        ("localtunnel",   "localtunnel",   .medium),
        ("rathole",       "rathole tunnel",.high),
        ("wstunnel",      "wstunnel",      .high),
        ("revsocks",      "revsocks (reverse SOCKS)", .high),
        ("rsockstun",     "rsockstun (reverse SOCKS)", .high),
        // Mesh / remote-access tools — legitimate but visible: flag at .low so the user knows
        // they're running, since they're a common cover for unauthorized access.
        ("tailscaled",    "Tailscale",     .low),
        ("zerotier-one",  "ZeroTier",      .low),
    ]

    private func scanTunnelingTools(findings: inout [Finding], errors: inout [String]) {
        // ps -axo pid,comm,args gives us pid + the process basename (comm) + full argv.
        // We match on comm (exact) so a binary named "ngrok" matches but a log file path or
        // an unrelated command containing "ngrok" in argv does not.
        let psResult = ShellRunner.run("/bin/ps", arguments: ["-axo", "pid,comm,args"], timeout: 5)
        guard psResult.success else { return }

        let toolsByName = Dictionary(uniqueKeysWithValues: tunnelingProcessNames.map {
            ($0.name.lowercased(), ($0.label, $0.severity))
        })

        let lines = psResult.stdout.split(separator: "\n").dropFirst() // skip header
        var reported = Set<String>()

        for line in lines {
            let trimmed = String(line).trimmingCharacters(in: .whitespaces)
            // parts[0] = pid, parts[1] = comm, parts[2...] = args
            let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 2 else { continue }

            let pid = String(parts[0])
            let comm = String(parts[1])
            // Process basename may include a path (e.g. "ngrok" vs "/usr/local/bin/ngrok").
            let basename = (comm as NSString).lastPathComponent.lowercased()

            guard let tool = toolsByName[basename] else { continue }
            if reported.contains(basename) { continue }
            reported.insert(basename)

            let snippet = String(trimmed.prefix(160))
            let severity = tool.1
            let lowSeverityNote = severity == .low
                ? " (legitimate mesh/access tool — only investigate if unexpected)"
                : ""

            findings.append(Finding(
                severity: severity, category: .networkActivity,
                title: "Tunneling tool running: \(tool.0)",
                detail: "PID \(pid): \(snippet)\(lowSeverityNote)",
                path: nil,
                remediation: severity == .low
                    ? "Verify this tunnel is yours — these tools can also be used to exfiltrate data"
                    : "Tunneling clients are a common C2 channel — terminate if not expected: kill \(pid)"
            ))
        }
    }

    // MARK: - Browser Remote Debugging Ports

    /// Chromium-based browsers expose the DevTools protocol on TCP 9222 when started with
    /// --remote-debugging-port. Anything that can reach that port can read cookies, session
    /// tokens, and saved passwords from the live browser. Stealer campaigns increasingly
    /// abuse this rather than going after sqlite cookie databases at rest.
    private let remoteDebuggingPorts: Set<Int> = [9222, 9223, 9229, 9230]

    private func scanRemoteDebuggingPorts(findings: inout [Finding], errors: inout [String]) {
        // Build a quick port -> process map from lsof. We can't use the parsed connections from
        // scanActiveConnections because they were not retained.
        let result = ShellRunner.run("/usr/sbin/lsof", arguments: [
            "-iTCP", "-sTCP:LISTEN", "-n", "-P", "+c", "0"
        ], timeout: 10)
        guard result.success else { return }

        for line in result.stdout.split(separator: "\n") {
            let lineStr = String(line)
            if lineStr.hasPrefix("COMMAND") { continue }

            let parts = lineStr.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 9 else { continue }

            let command = String(parts[0])
            let pid = String(parts[1])
            let conn = String(parts.last ?? "")

            // Find the trailing :PORT in the NAME column. lsof prints things like "*:9222 (LISTEN)"
            // or "127.0.0.1:9222 (LISTEN)" — both work with rangeOfLast(":").
            guard let colon = conn.range(of: ":", options: .backwards) else { continue }
            let portStr = conn[colon.upperBound...]
                .replacingOccurrences(of: " ", with: "")
                .replacingOccurrences(of: "(LISTEN)", with: "")
            guard let port = Int(portStr), remoteDebuggingPorts.contains(port) else { continue }

            // Local-loopback bindings are slightly safer than wildcard ones, but a local stealer
            // can still talk to loopback, so we always surface this.
            let isLoopback = conn.hasPrefix("127.0.0.1:") || conn.hasPrefix("[::1]:") ||
                conn.hasPrefix("localhost:")
            let nodeJSPort = (port == 9229 || port == 9230)

            // Node Inspector ports get a slightly softer message — they're commonly opened by devs.
            let title = nodeJSPort
                ? "Node.js debugger port \(port) is open"
                : "Browser remote-debugging port \(port) is open"
            let detail = "\(command) (PID \(pid)) listening on \(isLoopback ? "loopback" : "all interfaces")" +
                (nodeJSPort
                    ? " — local processes can attach a debugger to this Node runtime"
                    : " — local processes can read cookies / session tokens via DevTools Protocol")

            findings.append(Finding(
                severity: nodeJSPort ? .low : .high,
                category: .networkActivity,
                title: title,
                detail: detail,
                path: nil,
                remediation: nodeJSPort
                    ? "Stop the debugger when not in use, or restrict access (--inspect=127.0.0.1)"
                    : "Quit \(command) and relaunch it without --remote-debugging-port"
            ))
        }
    }

    // MARK: - Code Signature Check

    private struct CodeSignInfo {
        let isSigned: Bool
    }

    private func checkCodeSignature(path: String) -> CodeSignInfo {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?

        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return CodeSignInfo(isSigned: false)
        }

        let checkResult = SecStaticCodeCheckValidityWithErrors(code, SecCSFlags(rawValue: 0), nil, nil)
        return CodeSignInfo(isSigned: checkResult == errSecSuccess)
    }
}
