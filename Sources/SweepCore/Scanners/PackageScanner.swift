import Foundation

/// Scans globally installed npm and pip packages for indicators of the macOS
/// supply-chain campaigns that have been most active in 2023-2025:
///
///  - DPRK "Contagious Interview" / BeaverTail / InvisibleFerret — malicious
///    npm packages that fetch and execute Node-based stealers during a fake
///    job interview, typically via postinstall hooks.
///  - Commodity "left-pad-style" wallet/cookie stealers published to npm/PyPI.
///
/// We deliberately stick to behaviors visible from disk (no network calls):
/// known-bad package names, lifecycle scripts that fetch & exec remote code,
/// and tell-tale payload markers in JS/Python sources.
public final class PackageScanner: Scanner {
    public let name = "Package Scan"
    public init() {}

    // Globally installed packages from these campaigns share a small set of
    // recognizable name fragments. We match on substring (case-insensitive)
    // to catch typosquats like "ether-helpers" vs "ethers-helper".
    private let knownMaliciousNpmPatterns: [String] = [
        // BeaverTail / Contagious Interview clusters (Palo Alto Unit 42, JAMF,
        // SecureList, ReversingLabs reports, 2023-2025)
        "beavertail", "invisibleferret",
        "ether-provider-utils", "ethers-mainnet-deployment",
        "ethers-utils-helper", "ethers-helpers-utils",
        "solidity-event-helper", "decimal-event-helper",
        "node-clipboard-helper", "node-cookie-helper",
        "react-native-vector-icons-helper",
        "vue-css-helper", "lyft-style-helper",
        "discord-cors-helper", "discord-fetch-helper",
        "ethers-extension-helper",
        // Commodity stealers seen in 2024-2025
        "wallet-keystore-helper", "metamask-helper-utils",
        "cookie-grabber", "token-grabber",
    ]

    private let knownMaliciousPipPatterns: [String] = [
        // PyPI clusters tied to DPRK / Contagious Interview Python stagers
        "pyperclip-helper", "soljson-types", "klhttp-helper",
        "py-clipboard-helper", "py-cookie-helper",
        // Commodity Python crypto stealers
        "krypterm", "py-keylog", "wallet-grabber-py",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("scanning global npm packages")
        scanNpmGlobals(findings: &findings, errors: &errors)

        progress?.update("scanning Python user-site packages")
        scanPipUserSite(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - npm

    private func scanNpmGlobals(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Common global install roots across npm/pnpm/yarn/Volta.
        // We scan whatever exists — users typically have one or two.
        let roots = [
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
            "\(home)/.npm-global/lib/node_modules",
            "\(home)/.volta/tools/image/packages",
            "\(home)/Library/pnpm/global/5/node_modules",
            "\(home)/.yarn/global/node_modules",
        ]

        let fm = FileManager.default
        for root in roots {
            guard fm.fileExists(atPath: root),
                  let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }

            for entry in entries where !entry.hasPrefix(".") {
                let pkgRoot = "\(root)/\(entry)"
                // Scoped packages (@org/name) — recurse one level
                if entry.hasPrefix("@"),
                   let scoped = try? fm.contentsOfDirectory(atPath: pkgRoot) {
                    for scopedEntry in scoped where !scopedEntry.hasPrefix(".") {
                        analyzeNpmPackage(
                            name: "\(entry)/\(scopedEntry)",
                            path: "\(pkgRoot)/\(scopedEntry)",
                            findings: &findings
                        )
                    }
                } else {
                    analyzeNpmPackage(name: entry, path: pkgRoot, findings: &findings)
                }
            }
        }
    }

    private func analyzeNpmPackage(name: String, path: String, findings: inout [Finding]) {
        // 1. Direct name match against published IOC lists.
        let nameLC = name.lowercased()
        if let pattern = knownMaliciousNpmPatterns.first(where: { nameLC.contains($0) }) {
            findings.append(Finding(
                severity: .high, category: .maliciousPackage,
                title: "Globally installed npm package matches malicious campaign",
                detail: "Package: \(name) — matches pattern \"\(pattern)\" used by published macOS supply-chain attacks",
                path: path,
                remediation: "Uninstall: npm uninstall -g \(name) — then audit your shell history and rotate browser/wallet credentials"
            ))
            return
        }

        // 2. package.json lifecycle scripts that fetch and execute remote code.
        //    The BeaverTail dropper pattern is a postinstall script that runs
        //    `curl ... | node` or `node -e "<base64>"`.
        let pkgJson = "\(path)/package.json"
        guard let data = FileManager.default.contents(atPath: pkgJson),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return
        }

        // Plenty of legitimate npm packages publish lifecycle scripts too,
        // so we only flag the ones whose script body matches the loader pattern.
        if let scripts = json["scripts"] as? [String: Any] {
            for hook in ["preinstall", "install", "postinstall", "prepublish"] {
                guard let body = scripts[hook] as? String else { continue }
                let bodyLC = body.lowercased()

                // Network-fetch + execute is the canonical drop-and-run.
                let fetches = bodyLC.contains("curl ") || bodyLC.contains("wget ") ||
                              bodyLC.contains("https.get") || bodyLC.contains("http.get")
                let execs = bodyLC.contains("| sh") || bodyLC.contains("| bash") ||
                            bodyLC.contains("| node") || bodyLC.contains("| python") ||
                            bodyLC.contains("eval(") || bodyLC.contains("node -e ") ||
                            bodyLC.contains("child_process")

                if fetches && execs {
                    findings.append(Finding(
                        severity: .high, category: .maliciousPackage,
                        title: "npm package \(hook) hook fetches and executes remote code",
                        detail: "Package: \(name), hook: \(hook) — \(body.prefix(120))",
                        path: pkgJson,
                        remediation: "Uninstall: npm uninstall -g \(name) — and investigate any shells started since install"
                    ))
                    return
                }
            }
        }

        // 3. Common BeaverTail payload markers in entry-point JS.
        let entryCandidates = [
            "\(path)/index.js",
            "\(path)/main.js",
            "\(path)/dist/index.js",
            "\(path)/lib/index.js",
        ]
        for candidate in entryCandidates {
            guard FileManager.default.fileExists(atPath: candidate),
                  let attrs = try? FileManager.default.attributesOfItem(atPath: candidate),
                  let size = attrs[.size] as? Int, size < 2_000_000,
                  let content = try? String(contentsOfFile: candidate, encoding: .utf8) else { continue }

            let lower = content.lowercased()
            // The BeaverTail loader writes to /tmp/.cache or /private/tmp/.npl
            // and exfils browser data via short HTTP requests.
            let hasDropPath = lower.contains("/tmp/.cache") ||
                              lower.contains("/private/tmp/.npl") ||
                              lower.contains("/tmp/.n2/")
            let hasExfil = lower.contains("login data") ||
                           lower.contains("local state") ||
                           (lower.contains(".ldb") && lower.contains("metamask"))

            if hasDropPath || hasExfil {
                findings.append(Finding(
                    severity: .high, category: .maliciousPackage,
                    title: "npm package contains BeaverTail-family payload markers",
                    detail: "Package: \(name) — entry JS references stealer staging paths or browser credential stores",
                    path: candidate,
                    remediation: "Uninstall: npm uninstall -g \(name) — rotate browser/wallet credentials"
                ))
                return
            }
        }
    }

    // MARK: - pip / Python

    private func scanPipUserSite(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // User-level site-packages roots — we don't touch system Python.
        var roots: [String] = [
            "\(home)/.local/lib",
            "\(home)/Library/Python",
        ]
        if let pyenv = ProcessInfo.processInfo.environment["PYENV_ROOT"] {
            roots.append("\(pyenv)/versions")
        }

        let fm = FileManager.default
        for root in roots {
            guard fm.fileExists(atPath: root),
                  let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for entry in entries {
                // Two layouts we expect:
                //   .local/lib/python3.12/site-packages          (pip --user, modern)
                //   Library/Python/3.12/lib/python/site-packages (macOS framework Python)
                let candidates = [
                    "\(root)/\(entry)/site-packages",
                    "\(root)/\(entry)/lib/python/site-packages",
                ]
                for sp in candidates {
                    guard fm.fileExists(atPath: sp),
                          let packages = try? fm.contentsOfDirectory(atPath: sp) else { continue }
                    for pkg in packages where !pkg.hasPrefix(".") && !pkg.hasSuffix(".dist-info") {
                        let pkgLC = pkg.lowercased()
                        if let pattern = knownMaliciousPipPatterns.first(where: { pkgLC.contains($0) }) {
                            findings.append(Finding(
                                severity: .high, category: .maliciousPackage,
                                title: "Installed Python package matches malicious campaign",
                                detail: "Package: \(pkg) at \(sp) — matches pattern \"\(pattern)\" from published macOS supply-chain attacks",
                                path: "\(sp)/\(pkg)",
                                remediation: "Uninstall: pip uninstall \(pkg) — then audit shell history and rotate any credentials this user has touched"
                            ))
                        }
                    }
                }
            }
        }
    }
}
