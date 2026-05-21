import Foundation

public struct SpywareSignature {
    public let name: String
    public let processNames: [String]
    public let bundleIdentifiers: [String]
    public let filePaths: [String]
    public let launchAgentLabels: [String]

    // MARK: - Known Spyware Database

    public static let known: [SpywareSignature] = [
        // Consumer keyloggers
        SpywareSignature(
            name: "Spyrix",
            processNames: ["skm", "SpyrixKeylogger", "Spyrix", "SpyrixFree"],
            bundleIdentifiers: ["com.spyrix.keylogger", "com.spyrix.skm"],
            filePaths: [
                "~/Library/Application Support/Spyrix",
                "~/Library/Application Support/.Spyrix",
            ],
            launchAgentLabels: ["com.spyrix.keylogger", "com.spyrix.skm"]
        ),
        SpywareSignature(
            name: "FlexiSpy",
            processNames: ["Sync Services", "FSXSS", "flexispy", "SyncManager", "FlexiSPY"],
            bundleIdentifiers: ["com.yourcompany.flexispy", "com.flexispy.app"],
            filePaths: [
                "/Library/Application Support/.FlexiSPY",
                "~/Library/Application Support/.FlexiSPY",
                "/usr/local/.flexispy",
            ],
            launchAgentLabels: ["com.flexispy.service", "com.sync.services"]
        ),
        SpywareSignature(
            name: "mSpy",
            processNames: ["mSpy", "BackupService", "mspyagent", "IphoneInternalService"],
            bundleIdentifiers: ["com.mspy.agent"],
            filePaths: [
                "~/Library/Application Support/mSpy",
                "~/Library/Application Support/.mSpy",
            ],
            launchAgentLabels: ["com.mspy.agent", "com.backup.service"]
        ),
        SpywareSignature(
            name: "Hoverwatch",
            processNames: ["HoverwatchService", "hoverwatch", "hwservice"],
            bundleIdentifiers: ["com.hoverwatch.service"],
            filePaths: [
                "~/Library/Application Support/Hoverwatch",
                "~/Library/Application Support/.Hoverwatch",
            ],
            launchAgentLabels: ["com.hoverwatch.service"]
        ),
        SpywareSignature(
            name: "Kidlogger",
            processNames: ["kidlogger", "KidLogger", "KidLogger Pro"],
            bundleIdentifiers: ["com.kidlogger.agent"],
            filePaths: [
                "~/Library/Application Support/Kidlogger",
                "~/Library/Application Support/KidLogger",
            ],
            launchAgentLabels: ["com.kidlogger.agent"]
        ),
        SpywareSignature(
            name: "Refog",
            processNames: ["refog", "RefogKMS", "mpkd", "refog_kms"],
            bundleIdentifiers: ["com.refog.keylogger"],
            filePaths: [
                "~/Library/Application Support/REFOG",
                "/Library/Application Support/REFOG",
                "~/Library/Application Support/mpk",
            ],
            launchAgentLabels: ["com.refog.keylogger", "com.refog.mpk"]
        ),
        SpywareSignature(
            name: "CocoaSpy",
            processNames: ["CocoaSpy", "cocoaspy"],
            bundleIdentifiers: ["com.cocoaspy.agent"],
            filePaths: [
                "~/Library/Application Support/CocoaSpy",
                "~/Library/Application Support/.CocoaSpy",
            ],
            launchAgentLabels: ["com.cocoaspy.agent"]
        ),
        SpywareSignature(
            name: "Spyera",
            processNames: ["SpyeraService", "spyera"],
            bundleIdentifiers: ["com.spyera.service"],
            filePaths: [
                "/Library/Application Support/.Spyera",
                "~/Library/Application Support/.Spyera",
            ],
            launchAgentLabels: ["com.spyera.service"]
        ),
        SpywareSignature(
            name: "Realtime-Spy",
            processNames: ["rtsd", "RealtimeSpy", "realtime-spy"],
            bundleIdentifiers: ["com.spytech.realtimespy"],
            filePaths: [
                "~/Library/Application Support/RealtimeSpy",
                "~/Library/Application Support/.RealtimeSpy",
            ],
            launchAgentLabels: ["com.spytech.realtimespy"]
        ),
        SpywareSignature(
            name: "Aobo Keylogger",
            processNames: ["aobo", "AoboKeylogger", "akl"],
            bundleIdentifiers: ["com.aobo.keylogger"],
            filePaths: [
                "~/Library/Application Support/.Aobo",
                "~/Library/Application Support/Aobo",
            ],
            launchAgentLabels: ["com.aobo.keylogger"]
        ),
        SpywareSignature(
            name: "Elite Keylogger",
            processNames: ["elitekeylogger", "ek_service"],
            bundleIdentifiers: ["com.widestep.elitekeylogger"],
            filePaths: [
                "~/Library/Application Support/.EliteKeylogger",
                "~/Library/Application Support/EliteKeylogger",
            ],
            launchAgentLabels: ["com.widestep.elitekeylogger"]
        ),
        SpywareSignature(
            name: "Revealer Keylogger",
            processNames: ["revealer", "rkl_service"],
            bundleIdentifiers: ["com.logixoft.revealer"],
            filePaths: [
                "~/Library/Application Support/Revealer",
                "~/Library/Application Support/.Revealer",
            ],
            launchAgentLabels: ["com.logixoft.revealer"]
        ),
        // Modern stalkerware
        SpywareSignature(
            name: "Spyic",
            processNames: ["spyic", "SpyicService"],
            bundleIdentifiers: ["com.spyic.app"],
            filePaths: ["~/Library/Application Support/.Spyic"],
            launchAgentLabels: ["com.spyic.service"]
        ),
        SpywareSignature(
            name: "Cocospy",
            processNames: ["cocospy", "CocospyAgent"],
            bundleIdentifiers: ["com.cocospy.app"],
            filePaths: ["~/Library/Application Support/.Cocospy"],
            launchAgentLabels: ["com.cocospy.service"]
        ),
        SpywareSignature(
            name: "pcTattletale",
            processNames: ["pcTattletale", "pctattletale", "tattletale"],
            bundleIdentifiers: ["com.pctattletale.agent"],
            filePaths: ["~/Library/Application Support/.pcTattletale"],
            launchAgentLabels: ["com.pctattletale.agent"]
        ),
        SpywareSignature(
            name: "SpyBubble",
            processNames: ["SpyBubble", "spybubble"],
            bundleIdentifiers: ["com.spybubble.agent"],
            filePaths: ["~/Library/Application Support/.SpyBubble"],
            launchAgentLabels: ["com.spybubble.service"]
        ),
        SpywareSignature(
            name: "Xnspy",
            processNames: ["xnspy", "XnspyService"],
            bundleIdentifiers: ["com.xnspy.agent"],
            filePaths: ["~/Library/Application Support/.Xnspy"],
            launchAgentLabels: ["com.xnspy.service"]
        ),
        SpywareSignature(
            name: "iKeyMonitor",
            processNames: ["ikeymonitor", "iKeyMonitor", "ikm_service"],
            bundleIdentifiers: ["com.ikeymonitor.agent"],
            filePaths: [
                "~/Library/Application Support/.iKeyMonitor",
                "~/Library/Application Support/iKeyMonitor",
            ],
            launchAgentLabels: ["com.ikeymonitor.agent"]
        ),
        SpywareSignature(
            name: "EyeZy",
            processNames: ["eyezy", "EyeZyAgent"],
            bundleIdentifiers: ["com.eyezy.agent"],
            filePaths: ["~/Library/Application Support/.EyeZy"],
            launchAgentLabels: ["com.eyezy.service"]
        ),
        // Enterprise/APT-style
        SpywareSignature(
            name: "OSX.Pegasus",
            processNames: ["pegasusagent", "rptd"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/.system_cache",
                "/private/var/tmp/.pegasus",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OSX.DazzleSpy",
            processNames: ["softwareupdate_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/LaunchDaemons/.com.apple.softwareupdate.plist",
                "~/Library/Safari/.webarchives",
            ],
            launchAgentLabels: ["com.apple.softwareupdate.agent"]
        ),
        SpywareSignature(
            name: "OSX.CloudMensis",
            processNames: ["WindowServer.app"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/WebKit/com.apple.Safari/WebKitCache",
                "~/Library/.cloudconfig",
            ],
            launchAgentLabels: ["com.apple.webkitproxy"]
        ),
        SpywareSignature(
            name: "XCSSET",
            processNames: ["XcodeSpy", "xcsset_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Scripts/com.apple.systempreferences",
                "~/Library/LaunchAgents/com.apple.appstore.agent.plist",
            ],
            launchAgentLabels: ["com.apple.appstore.agent"]
        ),
        SpywareSignature(
            name: "OSX.Predator",
            processNames: ["cytrox_agent", "predator"],
            bundleIdentifiers: [],
            filePaths: ["/private/var/tmp/.predator"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Chrysaor",
            processNames: ["chrysaor", "nsobject_agent"],
            bundleIdentifiers: [],
            filePaths: ["/Library/.chrysaor"],
            launchAgentLabels: []
        ),
        // Modern macOS infostealers (2023-2025)
        SpywareSignature(
            name: "Atomic macOS Stealer (AMOS)",
            processNames: ["Atomic", "AMOS", "atomic_stealer", "AMOSInstaller"],
            bundleIdentifiers: ["com.atomic.stealer", "com.amos.agent"],
            filePaths: [
                "/private/tmp/AppleScript-*.scpt",
                "/private/tmp/.atomic",
                "~/Library/Application Support/.amos",
            ],
            launchAgentLabels: ["com.atomic.agent", "com.amos.service"]
        ),
        SpywareSignature(
            name: "Banshee Stealer",
            processNames: ["Banshee", "banshee", "bnsh", "bansheeUI"],
            bundleIdentifiers: ["com.banshee.stealer"],
            filePaths: [
                "/private/tmp/.banshee",
                "~/Library/Application Support/.Banshee",
            ],
            launchAgentLabels: ["com.banshee.service"]
        ),
        SpywareSignature(
            name: "Cthulhu Stealer",
            processNames: ["Cthulhu", "cthulhu_mac", "CleanMyMac_Pro"],
            bundleIdentifiers: ["com.cthulhu.stealer"],
            filePaths: [
                "/private/tmp/.cthulhu",
                "~/Library/Application Support/.Cthulhu",
            ],
            launchAgentLabels: ["com.cthulhu.agent"]
        ),
        SpywareSignature(
            name: "Poseidon Stealer",
            processNames: ["Poseidon", "poseidon_stealer", "pstealer"],
            bundleIdentifiers: ["com.poseidon.stealer"],
            filePaths: [
                "/private/tmp/.poseidon",
                "~/Library/Application Support/.Poseidon",
            ],
            launchAgentLabels: ["com.poseidon.service"]
        ),
        SpywareSignature(
            name: "MetaStealer",
            processNames: ["MetaStealer", "metastealer", "msteal"],
            bundleIdentifiers: ["com.meta.stealer"],
            filePaths: [
                "/private/tmp/.metastealer",
                "~/Library/Application Support/.MetaStealer",
            ],
            launchAgentLabels: ["com.meta.stealer"]
        ),
        SpywareSignature(
            name: "Cuckoo Stealer",
            processNames: ["Cuckoo", "cuckoo_stealer", "DumpMediaSpotifyMusicConverter"],
            bundleIdentifiers: ["com.cuckoo.stealer"],
            filePaths: [
                "/private/tmp/.cuckoo",
                "~/Library/Application Support/.Cuckoo",
            ],
            launchAgentLabels: ["com.cuckoo.agent"]
        ),
        SpywareSignature(
            name: "Realst",
            processNames: ["realst", "Realst", "realst_installer"],
            bundleIdentifiers: ["com.realst.agent"],
            filePaths: [
                "/private/tmp/.realst",
                "~/Library/Application Support/.Realst",
            ],
            launchAgentLabels: ["com.realst.service"]
        ),
        SpywareSignature(
            name: "MacStealer",
            processNames: ["MacStealer", "macstealer", "mstealer"],
            bundleIdentifiers: ["com.macstealer.agent"],
            filePaths: [
                "/private/tmp/.macstealer",
                "~/Library/Application Support/.MacStealer",
            ],
            launchAgentLabels: ["com.macstealer.service"]
        ),
        SpywareSignature(
            name: "PureLand Stealer",
            processNames: ["PureLand", "pureland", "pure_stealer"],
            bundleIdentifiers: ["com.pureland.stealer"],
            filePaths: [
                "/private/tmp/.pureland",
                "~/Library/Application Support/.PureLand",
            ],
            launchAgentLabels: ["com.pureland.agent"]
        ),
        SpywareSignature(
            name: "Activator Backdoor",
            processNames: ["Activator", "activator_agent", "app_activator"],
            bundleIdentifiers: ["com.activator.macos"],
            filePaths: [
                "/private/tmp/.activator",
                "~/Library/Application Support/.Activator",
            ],
            launchAgentLabels: ["com.activator.service"]
        ),
        // North Korean / APT-linked macOS malware
        SpywareSignature(
            name: "RustBucket",
            processNames: ["RustBucket", "rustbucket", "InternalPDF", "DocSend", "SafariHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.rustbucket",
                "~/Library/Metadata/.system_update",
            ],
            launchAgentLabels: ["com.apple.systempreferences.helper"]
        ),
        SpywareSignature(
            name: "KandyKorn",
            processNames: ["KandyKorn", "kandykorn", "CryptoSwift", "FinderTools"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Group Containers/.kandy",
                "~/Library/Caches/com.apple.safari.updater",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "ObjCShellz",
            processNames: ["ObjCShellz", "objcshellz", "objc_helper"],
            bundleIdentifiers: [],
            filePaths: ["/private/var/tmp/.objcshell"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "SpectralBlur",
            processNames: ["SpectralBlur", "spectralblur", "macshare"],
            bundleIdentifiers: [],
            filePaths: ["/private/var/tmp/.spectral"],
            launchAgentLabels: ["com.apple.macshare.plist"]
        ),
        SpywareSignature(
            name: "SmoothOperator (3CX)",
            processNames: ["3CX Desktop App", "3cxdesktopapp", "ffmpeg-operator"],
            bundleIdentifiers: ["com.electron.3cxdesktopapp"],
            filePaths: [],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "NokNok (BlueNoroff)",
            processNames: ["noknok", "NokNok", "SysJSONRPC", "CryptoAssetCalc"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.noknok"],
            launchAgentLabels: []
        ),
        // Consumer stalkerware / monitoring (2023-2025 additions)
        SpywareSignature(
            name: "WebWatcher",
            processNames: ["WebWatcher", "webwatcher", "wwservice", "wwclient"],
            bundleIdentifiers: ["com.awarenesstech.webwatcher"],
            filePaths: [
                "~/Library/Application Support/WebWatcher",
                "/Library/Application Support/WebWatcher",
            ],
            launchAgentLabels: ["com.awarenesstech.webwatcher"]
        ),
        SpywareSignature(
            name: "TheTruthSpy",
            processNames: ["TheTruthSpy", "truthspy", "tts_service"],
            bundleIdentifiers: ["com.thetruthspy.agent"],
            filePaths: ["~/Library/Application Support/.TheTruthSpy"],
            launchAgentLabels: ["com.thetruthspy.service"]
        ),
        SpywareSignature(
            name: "ClevGuard / KidsGuard Pro",
            processNames: ["KidsGuard", "clevguard", "KidsGuardPro", "kgp_service"],
            bundleIdentifiers: ["com.clevguard.kidsguard"],
            filePaths: [
                "~/Library/Application Support/ClevGuard",
                "~/Library/Application Support/KidsGuard",
            ],
            launchAgentLabels: ["com.clevguard.service"]
        ),
        SpywareSignature(
            name: "Mobistealth",
            processNames: ["Mobistealth", "mobistealth", "msagent"],
            bundleIdentifiers: ["com.mobistealth.agent"],
            filePaths: ["~/Library/Application Support/.Mobistealth"],
            launchAgentLabels: ["com.mobistealth.service"]
        ),
        SpywareSignature(
            name: "Spyzie",
            processNames: ["Spyzie", "spyzie", "spzagent"],
            bundleIdentifiers: ["com.spyzie.agent"],
            filePaths: ["~/Library/Application Support/.Spyzie"],
            launchAgentLabels: ["com.spyzie.service"]
        ),
        // DPRK / North Korean campaigns (2024-2026)
        SpywareSignature(
            // BlueNoroff loader chain documented by SentinelOne in Aug 2024 — masquerades as
            // crypto/PDF documents and drops a stage-2 Mach-O written in Swift.
            name: "TodoSwift (BlueNoroff)",
            processNames: ["TodoSwift", "todoswift", "TodoForMac", "swift_pdf_helper"],
            bundleIdentifiers: ["com.todoswift.app", "com.app.todoswift"],
            filePaths: [
                "/private/var/tmp/.todoswift",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: ["com.todoswift.service"]
        ),
        SpywareSignature(
            // DPRK loader (Nov 2024, Group-IB / Jamf) — abuses extended attributes
            // (xattr "test") to hide a second-stage Rust/AppleScript payload.
            name: "RustyAttr (DPRK)",
            processNames: ["RustyAttr", "rustyattr", "rustdoor_loader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.rustyattr",
                "~/Library/Application Support/.RustyAttr",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // BlueNoroff "Hidden Risk" campaign (SentinelOne, Nov 2024) — fake crypto-news
            // PDFs that drop a stage-2 zsh + Swift backdoor.
            name: "Hidden Risk (BlueNoroff)",
            processNames: ["HiddenRisk", "growth", "growth_helper", "CryptoBoom"],
            bundleIdentifiers: ["com.growth.assistant", "com.cryptoboom.helper"],
            filePaths: [
                "~/Library/Caches/com.apple.softwareupdate.zshenv",
                "~/.zshenv.public",
                "/private/var/tmp/.hiddenrisk",
            ],
            launchAgentLabels: ["com.apple.softwareupdate.zshenv"]
        ),
        SpywareSignature(
            // DPRK Nim-based backdoor (Huntress / SentinelOne, mid-2025). Notable because
            // Nim binaries dodge most YARA rules and ship a custom in-memory C2 channel.
            name: "NimDoor (DPRK)",
            processNames: ["NimDoor", "nimdoor", "GoogIeDrive", "ZoomVideo_helper", "CoreKitAgent"],
            bundleIdentifiers: ["com.zoom.video.helper", "com.google.drive.helper"],
            filePaths: [
                "/private/var/tmp/.nimdoor",
                "~/Library/CoreKitAgent",
                "~/Library/Application Support/.nimdoor",
            ],
            launchAgentLabels: ["com.google.keystone.agent", "com.zoom.client.helper"]
        ),
        SpywareSignature(
            // DPRK "Contagious Interview" campaign — fake job-interview NPM packages drop
            // BeaverTail (JS infostealer) which fetches InvisibleFerret (Python RAT).
            name: "BeaverTail (DPRK)",
            processNames: ["BeaverTail", "beavertail", "qnodeservice", "p.js", "nvm_setup"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.beavertail",
                "~/.npl",
                "~/Library/Application Support/.BeaverTail",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Stage-2 Python RAT delivered by BeaverTail.
            name: "InvisibleFerret (DPRK)",
            processNames: ["invisible_ferret", "invferret", "pyp.py", "pay.py"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.n2/pay",
                "~/.n2/bow",
                "~/.n2/mlip",
                "/private/var/tmp/.invferret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // OtterCookie (NTT, late 2024) — DPRK Contagious Interview successor to BeaverTail,
            // adds clipboard hijacking and broader wallet coverage.
            name: "OtterCookie (DPRK)",
            processNames: ["OtterCookie", "ottercookie", "otter_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.ottercookie",
                "~/.ott",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // PylangGhost (Cisco Talos, mid-2025) — Famous Chollima / DPRK Python+CGo loader
            // distributed via fake Coinbase/Robinhood "skills tests".
            name: "PylangGhost (DPRK)",
            processNames: ["PylangGhost", "pylangghost", "nvidia_release.py", "ChromeWrapper"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.pyenv/versions/.pylang",
                "/private/var/tmp/.pylangghost",
            ],
            launchAgentLabels: ["com.nvidia.release.helper"]
        ),
        // 2024-2026 macOS infostealers / loaders
        SpywareSignature(
            // Proofpoint, Feb 2025 — TA569's macOS-targeted twin of "SmartApeSG" via fake
            // browser-update overlays ("Safari Update Required").
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "DiskAnalyzer", "SafariUpdate"],
            bundleIdentifiers: ["com.safari.update", "com.diskanalyzer.helper"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
            ],
            launchAgentLabels: ["com.safari.update.helper"]
        ),
        SpywareSignature(
            // Kaspersky GReAT, April 2025 — modular stealer distributed via cracked apps;
            // notable for using mach_inject-style task port abuse for Telegram/wallet theft.
            name: "PasivRobber",
            processNames: ["PasivRobber", "pasivrobber", "wsus", "macUpdater"],
            bundleIdentifiers: ["com.apple.macupdater", "com.wsus.daemon"],
            filePaths: [
                "/private/tmp/.pasiv",
                "/Library/Application Support/.PasivRobber",
                "~/Library/Application Support/.PasivRobber",
            ],
            launchAgentLabels: ["com.wsus.daemon", "com.apple.macupdater.agent"]
        ),
        SpywareSignature(
            // Kandji Threat Research, 2025 — Go-based stealer that fingerprints Apple Silicon
            // and exfils 1Password / iCloud Keychain copies.
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "ProcessHub", "applehubd"],
            bundleIdentifiers: ["com.apple.processhub", "com.apple.hub.agent"],
            filePaths: [
                "/private/tmp/.appleprocesshub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub.agent"]
        ),
        SpywareSignature(
            // macOS.ZuRu resurfaced in 2025 (Trend Micro / Patrick Wardle) — trojanized
            // Termius / iTerm2 installers, drops Khepri C2 framework.
            name: "macOS.ZuRu",
            processNames: ["zuru", "ZuRu", "Khepri", "khepri_macos", "iTerm2_helper"],
            bundleIdentifiers: ["com.googleusercontent.apps.zuru", "com.iterm2.helper"],
            filePaths: [
                "~/Library/.Trash/.fseventsd",
                "/private/tmp/.zuru",
                "~/Library/Application Support/.ZuRu",
            ],
            launchAgentLabels: ["com.iterm2.helper", "com.zuru.agent"]
        ),
        SpywareSignature(
            // ThreatFabric / BlackBerry, 2024 — macOS variant of the LightSpy iOS implant;
            // modular surveillance with audio, screenshot, and contact-stealing plugins.
            name: "LightSpy (macOS)",
            processNames: ["LightSpy", "lightspy", "macos_plugin", "lightSpyService", "macsync"],
            bundleIdentifiers: ["com.macsync.service"],
            filePaths: [
                "~/Library/Application Support/.LightSpy",
                "/private/var/tmp/.lightspy",
            ],
            launchAgentLabels: ["com.macsync.service"]
        ),
        SpywareSignature(
            // Crystal Stealer (a.k.a. CrystalRAT), 2024-2025 — Russian-language MaaS targeting
            // macOS browsers and crypto wallets, sold on dark-web forums.
            name: "Crystal Stealer",
            processNames: ["Crystal", "crystal_stealer", "crystalUI", "crystld"],
            bundleIdentifiers: ["com.crystal.stealer", "com.crystal.agent"],
            filePaths: [
                "/private/tmp/.crystal",
                "~/Library/Application Support/.Crystal",
            ],
            launchAgentLabels: ["com.crystal.agent"]
        ),
        SpywareSignature(
            // GhostStealer / Encore (2025) — Go-based stealer marketed alongside AMOS clones;
            // uses Apple Help Viewer abuse for execution on Sequoia+.
            name: "GhostStealer",
            processNames: ["GhostStealer", "ghoststealer", "ghst", "applehelp_runner"],
            bundleIdentifiers: ["com.ghost.stealer"],
            filePaths: [
                "/private/tmp/.ghoststealer",
                "~/Library/Application Support/.GhostStealer",
            ],
            launchAgentLabels: ["com.ghost.agent"]
        ),
        SpywareSignature(
            // ToyMaker / KeySteal (Sequoia-era, 2024) — abuses macOS Sequoia keychain
            // export prompt phishing to harvest credentials.
            name: "KeySteal",
            processNames: ["KeySteal", "keysteal", "ksUpdater", "keychain_helper"],
            bundleIdentifiers: ["com.keychain.helper"],
            filePaths: [
                "/private/tmp/.keysteal",
                "~/Library/Application Support/.KeySteal",
            ],
            launchAgentLabels: ["com.keychain.helper"]
        ),
        SpywareSignature(
            // Embargo (Rust-based ransomware crew, 2024-2025) — known macOS encryptor variant
            // delivered alongside AMOS-family stealers on cracked-software pages.
            name: "Embargo Ransomware",
            processNames: ["Embargo", "embargo_rs", "embargo_encryptor"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.embargo",
                "~/Library/Application Support/.Embargo",
            ],
            launchAgentLabels: []
        ),
    ]

    // MARK: - Heuristic Detection Patterns

    /// Fake Apple bundle ID patterns — real Apple IDs follow strict conventions
    public static let fakeAppleBundlePatterns: [String] = [
        "com.apple.softwareupdate.agent",
        "com.apple.system.update",
        "com.apple.systemd",
        "com.apple.updater",
        "com.apple.webkitproxy",
        "com.apple.appstore.agent",
        "com.apple.icloud.sync",
        "com.apple.security.agent",
        "com.apple.kernel.service",
        "com.apple.daemon.helper",
    ]

    /// Process names that look like system processes but aren't real Apple binaries.
    /// Real Apple equivalents noted in comments. Only flag if running from non-system paths.
    public static let suspiciousSystemNames: Set<String> = [
        "softwareupdate_agent",  // Real: softwareupdated
        "WindowServer.app",      // Real: WindowServer (no .app suffix)
        "loginwindow.app",       // Real: loginwindow (no .app suffix)
        "kernel_service",        // Real: kernel_task
        "systemd",               // Linux, not macOS
        "initd",                 // Linux, not macOS
        "update_agent",          // Not a real Apple process
        "securityd_helper",      // Real: securityd
        "trustd_agent",          // Real: trustd
        "cfprefsd_helper",       // Real: cfprefsd
        "launchd_helper",        // Real: launchd
        "notifyd_agent",         // Real: notifyd
        "iCloudHelper",          // Real: bird / cloudd
        "iCloudSyncAgent",       // Not a real Apple process
        "XProtectHelper",        // Real: XProtect (no Helper suffix)
        "SpotlightHelper",       // Real: mds / mdworker
        "AppleDockD",            // Real: Dock (not a daemon)
        "ApplePushService",      // Real: apsd
        "coreaudio_helper",      // Real: coreaudiod
    ]

    /// Checks if a bundle ID looks like a fake Apple ID
    public static func isFakeAppleBundleId(_ bundleId: String) -> Bool {
        if !bundleId.hasPrefix("com.apple.") { return false }
        // Known fake patterns
        if fakeAppleBundlePatterns.contains(bundleId) { return true }
        // Heuristics: Apple doesn't use these suffixes
        let suspiciousSuffixes = [".agent", ".service", ".daemon", ".helper", ".proxy", ".updater"]
        for suffix in suspiciousSuffixes {
            if bundleId.hasSuffix(suffix) {
                // This is suspicious — most Apple daemons don't use generic suffixes
                return true
            }
        }
        return false
    }

    /// Checks if a process name is mimicking a system process
    public static func isSuspiciousSystemName(_ name: String) -> Bool {
        return suspiciousSystemNames.contains(name)
    }

    // MARK: - Match Methods

    public static var allProcessNames: Set<String> {
        Set(known.flatMap { $0.processNames.map { $0.lowercased() } })
    }

    public static var allBundleIdentifiers: Set<String> {
        Set(known.flatMap { $0.bundleIdentifiers })
    }

    public static func match(processName: String) -> SpywareSignature? {
        let lower = processName.lowercased()
        return known.first { sig in
            sig.processNames.contains { $0.lowercased() == lower }
        }
    }

    public static func match(bundleId: String) -> SpywareSignature? {
        known.first { sig in
            sig.bundleIdentifiers.contains(bundleId)
        }
    }

    public static func match(label: String) -> SpywareSignature? {
        let lower = label.lowercased()
        return known.first { sig in
            sig.launchAgentLabels.contains { $0.lowercased() == lower }
        }
    }

    public static func expandPath(_ path: String) -> String {
        if path.hasPrefix("~/") {
            return ShellRunner.realUserHome + String(path.dropFirst(1))
        }
        return path
    }
}
