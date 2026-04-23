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

        // 4. Check for local-AI inference servers bound to non-loopback interfaces.
        //    Ollama, LM Studio, llama.cpp servers etc. have become a common "oops" — users
        //    set OLLAMA_HOST=0.0.0.0 for convenience and end up exposing a model server
        //    (and in vulnerable versions a full RCE) to the local network.
        progress?.update("checking exposed AI inference servers")
        scanExposedAIServers(findings: &findings, errors: &errors)

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

    // MARK: - Exposed AI Inference Servers

    /// Local AI services that, if bound to 0.0.0.0 or a non-loopback IP, expose a model
    /// server (and sometimes the filesystem via tool-calling) to anyone on the LAN.
    /// Port / service catalogue reflects the mainstream 2024-2025 lineup.
    private let aiInferencePorts: [(port: Int, product: String, notes: String)] = [
        (11434, "Ollama",            "Ollama's HTTP API — full model pull/run control, prior CVEs allow path traversal"),
        (1234,  "LM Studio",         "LM Studio local server — browses local models and runs prompts"),
        (5000,  "AUTOMATIC1111 / Flask AI", "Commonly used by local Stable Diffusion and Flask-based AI tools"),
        (7860,  "Gradio / A1111 share", "Gradio / A1111 web UI — can expose uploaded files and model configs"),
        (8001,  "vLLM / OpenAI-compat", "vLLM OpenAI-compatible server"),
        (8080,  "llama.cpp server",  "llama.cpp's built-in HTTP server"),
        (8188,  "ComfyUI",           "ComfyUI — node-based workflow UI with filesystem access"),
        (3000,  "Open WebUI / ChatUI", "Open WebUI chat front-end — stores chat history and API keys"),
    ]

    private func scanExposedAIServers(findings: inout [Finding], errors: inout [String]) {
        // lsof -iTCP -sTCP:LISTEN gives just the listening sockets — cheap and precise.
        let result = ShellRunner.run("/usr/sbin/lsof", arguments: [
            "-nP", "-iTCP", "-sTCP:LISTEN", "+c", "0"
        ], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        let aiPortSet = Set(aiInferencePorts.map { $0.port })
        var alreadyReported = Set<Int>()  // one finding per port

        for line in result.stdout.split(separator: "\n") {
            let lineStr = String(line)
            if lineStr.hasPrefix("COMMAND") { continue }

            // lsof LISTEN line format:
            //   ollama    1234 user   3u  IPv4 ... TCP *:11434 (LISTEN)
            //   ollama    1234 user   3u  IPv4 ... TCP 127.0.0.1:11434 (LISTEN)
            //   ollama    1234 user   3u  IPv6 ... TCP [::1]:11434 (LISTEN)
            guard let nameRange = lineStr.range(of: "TCP ") else { continue }
            let addr = String(lineStr[nameRange.upperBound...])
                .replacingOccurrences(of: "(LISTEN)", with: "")
                .trimmingCharacters(in: .whitespaces)

            // Split address from port at the last colon (handles IPv6 brackets).
            guard let colon = addr.range(of: ":", options: .backwards) else { continue }
            let host = String(addr[..<colon.lowerBound])
                .trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
            let portStr = String(addr[colon.upperBound...])
            guard let port = Int(portStr), aiPortSet.contains(port),
                  !alreadyReported.contains(port) else { continue }

            // 127.0.0.1, ::1, localhost are safe — only flag when bound to * or a real interface.
            let isLoopback = host == "127.0.0.1" || host == "::1" || host == "localhost" ||
                             host.hasPrefix("127.")
            guard !isLoopback else { continue }

            let meta = aiInferencePorts.first { $0.port == port }!
            let parts = lineStr.split(separator: " ", omittingEmptySubsequences: true)
            let command = parts.first.map { String($0) } ?? "?"

            findings.append(Finding(
                severity: .high, category: .networkActivity,
                title: "AI server (\(meta.product)) exposed on the network",
                detail: "Process \(command) is listening on \(host):\(port). \(meta.notes).",
                path: nil,
                remediation: "Bind to 127.0.0.1 only. For Ollama: set OLLAMA_HOST=127.0.0.1; for LM Studio / Open WebUI disable \"Serve on local network\"."
            ))
            alreadyReported.insert(port)
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
