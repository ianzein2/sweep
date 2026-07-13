import Foundation

/// Threat-intelligence indicators pulled from public 2025-2026 macOS malware research
/// (SentinelOne, Jamf, Microsoft, Kaspersky, Kandji, Unit 42, Objective-See, etc.).
///
/// Everything in this file is a static IOC list — no network fetch, no auto-update. The
/// project's stance is that a scanner should be reviewable at build time; each entry
/// below is attributable to a public report cited in the commit that introduced it.
public enum ThreatIntel {

    // MARK: - Command-and-control domains and hosts

    /// Domains observed as C2, malvertising, or lure infrastructure in 2025-2026 macOS
    /// campaigns. If a process is talking to one of these, it's a high-confidence hit
    /// regardless of what else the scanner sees.
    public static let knownC2Domains: Set<String> = [
        // XCSSET 2025 — all `.ru` C2 (Microsoft, Mar & Sep 2025)
        "cdntor.ru", "checkcdn.ru", "cdcache.ru", "applecdn.ru", "flowcdn.ru",
        "elasticdns.ru", "rublenet.ru", "figmastars.ru", "bulksec.ru", "adobetrix.ru",
        "figmacat.ru", "digichat.ru", "diggimax.ru", "cdnroute.ru", "sigmanow.ru",
        "fixmates.ru", "mdscache.ru", "trinitysol.ru", "verifysign.ru", "digitalcdn.ru",
        "windsecure.ru", "adobecdn.ru",
        // SHub Reaper / MacSync (SentinelOne, Microsoft, 2025-2026)
        "rapidfilevault4.sbs", "coco-fun2.com", "nitlebuf.com", "yablochnisok.com",
        "mentaorb.com", "0x666.info", "honestly.ink", "pla7ina.cfd", "play67.cc",
        "rvdownloads.com", "famiode.com", "woupp.com", "contatoplus.com",
        // ClickFix lure domains (Microsoft, May 2026)
        "cleanmymacos.org", "mac-storage-guide.squarespace.com",
        "macos-disk-space.medium.com", "macclean.craft.me", "domenpozh.net",
        // Odyssey Stealer (Jamf, PRODAFT, 2025)
        "poseidon.cool", "odyssey1.to", "odyssey-st.com", "download-cleanshot.cfd",
        // Sapphire Sleet (Microsoft, Apr 2026)
        "uw04webzoom.us", "check02id.com",
        // FrigidStealer (Proofpoint, Jan 2025)
        "askforupdate.org",
        // Cuckoo fake-Homebrew typosquats (Kandji, Koi, Hunt.io, Sep 2025)
        "brewe.sh", "homabrews.org", "brewsh.cx", "brrewsh.org", "brewshh.org",
        // AppleProcessHub (Kandji, May 2025)
        "appleprocesshub.com",
    ]

    /// Raw IPv4 addresses seen as active Odyssey / Cthulhu 2025 C2. Matched against
    /// remote endpoints from lsof output; presence is high-confidence.
    public static let knownC2IPs: Set<String> = [
        // Odyssey Stealer (Jamf, PRODAFT)
        "5.199.166.102", "185.147.124.212", "83.222.190.214", "88.214.50.3",
        "85.198.110.134",  // StealC pivot
        // Cthulhu Stealer 2025 repack (Darktrace)
        "89.208.103.185",
        // Sapphire Sleet (Microsoft, Apr 2026)
        "83.136.208.246", "188.227.196.252", "104.145.210.107",
    ]

    // MARK: - Apple Developer Team IDs seen signing malware

    /// Team IDs that have signed and (in some cases) notarized macOS malware. Apple
    /// eventually revokes these, but stealer authors keep re-registering under the same
    /// codename; a signed binary from one of these IDs should not be trusted just
    /// because notarization passed.
    public static let untrustedAppleTeamIDs: Set<String> = [
        "GNJLS3UYZ4",  // MacSync Stealer (Jamf, Dec 2025) — Swift/Go stealer distributed as a signed & notarized DMG
    ]

    // MARK: - Malicious browser extensions

    /// Chromium extension IDs that have been publicly attributed to credential-theft,
    /// crypto-clipping, or session-hijacking campaigns. These IDs may still be resident
    /// in user profiles after the Web Store yanks them; the scanner should flag them
    /// even if the extension no longer downloads updates.
    public static let maliciousChromiumExtensionIDs: Set<String> = [
        // RedDirection campaign — "Palette Creator" (SecurityAlliance, 2026; ~100k users at takedown)
        "iofmialeiddolmdlkbheakaefefkjokp",
        // "OmniBar AI Chat and Search" (Malwarebytes, Dec 2025 sleeper campaign)
        "ajfanjhcdgaohcbphpaceglgpgaaohod",
    ]

    // MARK: - Wallet extension IDs modern stealers explicitly target

    /// Chromium extension IDs that AMOS-family stealers (AMOS, Banshee, Poseidon,
    /// Cuckoo, Odyssey, SHub) walk directly to exfiltrate wallet state. Legitimate
    /// installations under `~/Library/Application Support/<browser>/…/Extensions/`
    /// aren't malicious on their own, but a *copy* of one of these directories staged
    /// under `/tmp` or a hidden folder is stealer evidence — EvidenceScanner uses this
    /// list to make that call.
    public static let cryptoWalletExtensionIDs: [(label: String, id: String)] = [
        ("MetaMask",         "nkbihfbeogaeaoehlefnkodbefgpgknn"),
        ("Phantom",          "bfnaelmomeimhlpmgjnjophhpkkoljpa"),
        ("Coinbase Wallet",  "hnfanknocfeofbddgcijnmhnfnkdnaad"),
        ("Ronin",            "fnjhmkhhmkbjkkabndcnnogagogbneec"),
        ("TronLink",         "ibnejdfjmmkpcnlpebklmnkoeoihofec"),
        ("Keplr",            "dmkamcknogkgcdfhhbddcghachkejeap"),
        // Additions from the 2026 Sapphire Sleet target list (Microsoft, Apr 2026)
        ("Solflare",         "bhhhlbepdkbapadjdnnojkbgioiodbic"),
        ("Rabby",            "acmacodkjbdgmoleebolmdjonilkdbch"),
        ("Backpack",         "aflkmfhebedbjioipglgcbcmnbpgliof"),
        ("OKX Wallet",       "mcohilncbfahbmgdjkbpemcciiolgcge"),
        ("Sui Wallet",       "opcgpfmipidbgpenhmajoajpbobppdil"),
    ]

    // MARK: - Contagious Interview npm packages (DPRK)

    /// npm packages published by DPRK "recruiter" actors delivering BeaverTail /
    /// InvisibleFerret / OtterCookie. Presence in `package.json` or in the npm cache
    /// (`~/.npm/_cacache`) is a strong indicator the developer was targeted.
    /// Sources: Unit 42, Socket, Panther, GitLab tech-note (2025-2026).
    public static let maliciousNpmPackages: Set<String> = [
        "passports-js",
        "bcrypts-js",
        "blockscan-api",
        "rollup-plugin-polyfill-route",
    ]

    // MARK: - Homebrew typosquat domains

    /// Domain strings that indicate a `curl … | bash` fake-Homebrew install ran on this
    /// machine. Grepped from shell history and shell rc files.
    public static let homebrewTyposquatDomains: [String] = [
        "brewe.sh", "brewsh.cx", "brrewsh.org", "brewshh.org", "homabrews.org",
    ]

    // MARK: - macOS version support thresholds

    /// Latest security-supported versions of each macOS train as of the last update to
    /// this file. Anything older is exposed to at least one publicly-disclosed critical
    /// CVE (kernel RCE, root privesc, Wi-Fi kernel bug, or CVE-2026-39118 EDR bypass).
    /// Bumping these numbers is the ONE thing a Sweep contributor needs to remember
    /// when Apple ships an update.
    public struct MacOSVersion {
        public let major: Int
        public let minor: Int
        public let patch: Int
        public init(_ major: Int, _ minor: Int, _ patch: Int) {
            self.major = major; self.minor = minor; self.patch = patch
        }
        /// Lexicographic (major, minor, patch) comparison.
        public func isOlderThan(_ other: MacOSVersion) -> Bool {
            if major != other.major { return major < other.major }
            if minor != other.minor { return minor < other.minor }
            return patch < other.patch
        }
    }

    /// (train name, minimum-safe version). If the running Mac's major matches the
    /// train and its full version is older, HardeningScanner emits a "patch me" finding.
    public static let macOSMinimumSafeVersions: [(train: String, minimum: MacOSVersion)] = [
        ("Tahoe",    MacOSVersion(26, 5, 0)),   // May 11 2026 rollup incl. kernel RCE, root privesc
        ("Sequoia",  MacOSVersion(15, 7, 7)),   // 45-CVE Wi-Fi kernel RCE rollup
        ("Sonoma",   MacOSVersion(14, 8, 7)),   // Legacy security update
    ]
}
