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
        // 2024–2026 additions — recent infostealers, DPRK/APT tooling, and trojanized apps
        SpywareSignature(
            // Feb 2025 infostealer distributed via fake Safari/Chrome update lures.
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "FrigidUpdater", "SafariUpdate"],
            bundleIdentifiers: ["com.frigid.stealer", "com.safari.updater"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.Frigid",
                "~/Downloads/SafariUpdate.dmg",
            ],
            launchAgentLabels: ["com.frigid.agent"]
        ),
        SpywareSignature(
            // Poseidon-family fork observed in 2025; sold on underground forums as Amos/Poseidon successor.
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey_stealer", "odysseyagent", "OdysseyInstaller"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        SpywareSignature(
            // OceanLotus/APT32 macOS backdoor active through 2024.
            name: "MacMa (OSX.CDDS)",
            processNames: ["MacMa", "macma", "cdds_agent", "airportpaird", "UserAgent"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Preferences/com.apple.softwareupdateagent.plist",
                "~/Library/.airportpaird",
                "/private/var/tmp/.macma",
            ],
            launchAgentLabels: ["com.apple.softwareupdateagent"]
        ),
        SpywareSignature(
            // ThreatFabric / Kaspersky-tracked cross-platform surveillanceware, macOS build seen 2024.
            name: "LightSpy (macOS)",
            processNames: ["lightspy", "LightSpy", "lspy", "macupdater_helper", "systeminfoservice"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.lightspy",
                "~/Library/Application Support/.lightspy",
                "~/Library/Group Containers/.lightspy",
            ],
            launchAgentLabels: ["com.apple.systeminfo.service"]
        ),
        SpywareSignature(
            // Chinese APT Gh0st RAT variant identified by Cisco Talos in Dec 2024.
            name: "PLAYFULGHOST",
            processNames: ["PlayfulGhost", "playfulghost", "ghostagent", "gh0st_darwin"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.playful",
                "~/Library/Caches/.ghostcache",
            ],
            launchAgentLabels: ["com.apple.ghost.helper"]
        ),
        SpywareSignature(
            // Bitdefender-tracked (Feb 2024) crypto-focused backdoor; drops GateDoor as loader.
            name: "RustDoor",
            processNames: ["RustDoor", "rustdoor", "iTerm2_helper", "zoom_sdk_helper"],
            bundleIdentifiers: ["com.rustdoor.helper"],
            filePaths: [
                "~/Library/Application Support/.rustdoor",
                "/private/var/tmp/.rustdoor",
                "/tmp/environmentService",
            ],
            launchAgentLabels: ["com.apple.rustdoor", "environmentService.plist"]
        ),
        SpywareSignature(
            // Go-based loader companion to RustDoor, targets Windows+macOS crypto teams.
            name: "GateDoor",
            processNames: ["GateDoor", "gatedoor", "GoogleChromeUpdater", "gate_helper"],
            bundleIdentifiers: ["com.gatedoor.helper"],
            filePaths: [
                "~/Library/Application Support/.gatedoor",
                "/private/var/tmp/.gatedoor",
            ],
            launchAgentLabels: ["com.google.chromeupdater"]
        ),
        SpywareSignature(
            // SentinelOne-tracked trojanized apps (Termius, iTerm2, Navicat) — Nov 2024.
            name: "macOS.ZuRu",
            processNames: ["zuru", "ZuRu", "libcrypto.2.dylib", "GoogleHelperUpdater",
                           "com.apple.xssooagent"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/GoogleHelperUpdater",
                "/private/tmp/.zuru",
                "~/Library/LaunchAgents/com.apple.xssooagent.plist",
                "~/Library/Application Support/Termius/.zuru",
            ],
            launchAgentLabels: ["com.apple.xssooagent"]
        ),
        SpywareSignature(
            // DPRK Lazarus Rust dropper, uses extended-attribute code-hiding trick (Nov 2024).
            name: "RustyAttr (Lazarus)",
            processNames: ["RustyAttr", "rustyattr", "test", "Job Interview PDF"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.rustyattr",
                "~/Library/Application Support/.rustyattr",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Huntress-tracked Nim-based DPRK backdoor family (2025).
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "zoom_sdk_support",
                           "GoogleMeetsSupport", "koi_stealer"],
            bundleIdentifiers: ["us.zoom.sdk-support"],
            filePaths: [
                "/private/var/tmp/.nimdoor",
                "~/Library/Application Support/.nimdoor",
                "~/Library/LaunchAgents/com.googleusercontent.plist",
            ],
            launchAgentLabels: ["com.googleusercontent", "us.zoom.sdksupport"]
        ),
        SpywareSignature(
            // Kaspersky report Aug 2024 — Chinese APT RAT ported to macOS.
            name: "HZ RAT (macOS)",
            processNames: ["hzrat", "HZRAT", "OpenVPN_Connect_Installer",
                           "iTunesHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.hzrat",
                "~/Library/Application Support/OpenVPN Connect/.hz",
            ],
            launchAgentLabels: ["com.openvpn.client.plist"]
        ),
        SpywareSignature(
            // DPRK "Contagious Interview" Node.js first-stage; delivered inside malicious test repos.
            name: "BeaverTail (Contagious Interview)",
            processNames: ["beavertail", "BeaverTail", "node_modules_helper",
                           "npm_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.n2",
                "~/.n2/pay",
                "~/Library/Application Support/.beavertail",
                "~/.npl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Python-based second-stage backdoor that BeaverTail pulls down.
            name: "InvisibleFerret",
            processNames: ["invisibleferret", "InvisibleFerret", "python3_helper",
                           "pay", "bow"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.n2/pay",
                "~/.n2/bow",
                "~/.n2/mlip",
                "~/.n2/adc",
                "/private/tmp/.if",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Kaspersky "SparkCat" family macOS variant — steals crypto seeds via screenshot OCR (Jun 2025).
            name: "SparkKitty",
            processNames: ["SparkKitty", "sparkkitty", "PhotoAnalysisHelper",
                           "iOSPhotoSync"],
            bundleIdentifiers: ["com.sparkkitty.agent"],
            filePaths: [
                "~/Library/Application Support/.sparkkitty",
                "/private/tmp/.sparkkitty",
            ],
            launchAgentLabels: ["com.sparkkitty.service"]
        ),
        SpywareSignature(
            // AMOS-family variant that ships as an "app installer" and uses AppleScript for TCC prompts (2025).
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "aph_agent",
                           "com.apple.mainhub"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "/private/tmp/.aph",
                "~/Library/Application Support/.appleprocesshub",
                "/tmp/main",
            ],
            launchAgentLabels: ["com.apple.mainhub", "com.apple.processhub"]
        ),
        SpywareSignature(
            // Check Point-tracked infostealer distributed via cracked-software funnels (2024).
            name: "XLoader (macOS)",
            processNames: ["XLoader", "xloader", "OfficeNote", "PostSaver"],
            bundleIdentifiers: ["com.xloader.agent"],
            filePaths: [
                "~/Library/Application Support/.xloader",
                "/private/tmp/.xloader",
            ],
            launchAgentLabels: ["com.xloader.service"]
        ),
        SpywareSignature(
            // "PACT" backdoor — 2024 macOS APT family reported by Volexity.
            name: "PACT Backdoor",
            processNames: ["pact", "PACT", "pact_helper", "com.apple.pact"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.pact",
                "~/Library/Application Support/.pact",
            ],
            launchAgentLabels: ["com.apple.pact.helper"]
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
        // Additions seen in 2024–2025 macOS campaigns (RustDoor, NimDoor, ZuRu, PACT, HZ RAT, etc.)
        "com.apple.softwareupdateagent",
        "com.apple.rustdoor",
        "com.apple.pact.helper",
        "com.apple.mainhub",
        "com.apple.processhub",
        "com.apple.xssooagent",
        "com.apple.ghost.helper",
        "com.apple.icloud.helper",
        "com.apple.bird.helper",
        "com.apple.mobileassetd.helper",
        "com.apple.spotlightd.helper",
        "com.apple.diskspaced",
        "com.apple.corebrightness.helper",
        "com.apple.systeminfo.service",
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
        // New in 2024–2025 campaigns. p_comm is truncated to 16 chars — keep entries at or below.
        "mdworkerd",             // Real: mdworker / mdworker_shared
        "keychainhelper",        // Real: securityd (used by AMOS variants)
        "SafariUpdate",          // FrigidStealer lure — real: SafariUpdated
        "SafariUpdater",         // FrigidStealer lure
        "iTunesHelper",          // HZ RAT lure — iTunes is deprecated
        "AppleAccountAgen",      // NimDoor lure (real: accountsd)
        "AppleCoreService",      // Real: coreservicesd
        "GoogleHelperUpda",      // macOS.ZuRu lure — no real Google process by this name
        "GoogleChromeUpda",      // GateDoor lure — real updater is "GoogleSoftwareUpdate"
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
