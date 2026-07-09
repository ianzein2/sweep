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
        // DPRK "Contagious Interview" / Ferret family (SentinelOne, Nov 2024 - 2025)
        // Fake-recruiter campaign that tricks developers into running installers during a "coding test".
        SpywareSignature(
            name: "FrostyFerret / FERRETPASSIVE",
            processNames: ["FrostyFerret_UI", "FROSTYFERRET_UI", "MULTI_FROSTYFERRET_CMDCODES",
                           "ChromeUpdate", "chromeupdate", "FERRETPASSIVE"],
            bundleIdentifiers: ["com.frostyferret.helper"],
            filePaths: [
                "/private/tmp/.chromeupdate",
                "/private/tmp/.frostyferret",
                "~/Library/Application Support/com.frostyferret",
            ],
            launchAgentLabels: ["com.google.chrome.update", "com.chrome.updater"]
        ),
        SpywareSignature(
            name: "FriendlyFerret",
            processNames: ["FriendlyFerret_secd", "friendlyferret", "FRIENDLYFERRET"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/WebKit/com.apple.WebKit.WebContent/friendly.ferret",
                "/private/tmp/.friendlyferret",
            ],
            launchAgentLabels: ["com.apple.secd"]
        ),
        SpywareSignature(
            name: "FlexibleFerret",
            processNames: ["FlexibleFerret", "flexibleferret", "FerretUpdater", "com.zoom.installer"],
            bundleIdentifiers: ["com.zoom.installer.helper", "com.flexible.ferret"],
            filePaths: [
                "/private/tmp/.zoom_installer",
                "/private/tmp/.flexibleferret",
                "~/Library/Group Containers/.ferret",
            ],
            launchAgentLabels: ["com.zoom.installer", "com.apple.zoom.update"]
        ),
        SpywareSignature(
            name: "BeaverTail",
            processNames: ["beavertail", "BeaverTail", "npmupdate", "node_module_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.beavertail",
                "~/Library/Application Support/.n2",
                "~/.npm-cache/.beaver",
            ],
            launchAgentLabels: ["com.node.helper", "com.npm.update"]
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["invisibleferret", "InvisibleFerret", "pyp", "adb.py", "brow.py"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.invisibleferret",
                "~/Library/Python/.if_agent",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OtterCookie",
            processNames: ["ottercookie", "OtterCookie", "socket-node", "node-socket-helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.ottercookie",
                "~/Library/Caches/.otter",
            ],
            launchAgentLabels: []
        ),
        // DPRK — NimDoor (July 2025, SentinelOne). Nim-based backdoor targeting Web3/crypto orgs;
        // hooks SIGINT/SIGTERM so it re-launches when the user tries to kill it.
        SpywareSignature(
            name: "NimDoor",
            processNames: ["nimdoor", "NimDoor", "GoogIe LLC", "zoom_sdk_support",
                           "installer_v", "coreks", "trojan_nim"],
            bundleIdentifiers: ["com.zoom.sdksupport", "com.googie.updater"],
            filePaths: [
                "/private/tmp/.nimdoor",
                "/private/tmp/zoom_sdk_support.scpt",
                "~/Library/Application Support/.nimdoor",
                "~/Library/Group Containers/.nim",
            ],
            launchAgentLabels: ["com.google.updater", "com.zoom.sdksupport"]
        ),
        // Lazarus — RustyAttr (Nov 2024, Group-IB). Uses extended attributes to hide shellcode
        // inside benign-looking macOS apps signed with stolen certificates.
        SpywareSignature(
            name: "RustyAttr",
            processNames: ["RustyAttr", "rustyattr", "TwoStepUpdater", "twostep_updater"],
            bundleIdentifiers: ["com.twostep.updater", "com.rusty.helper"],
            filePaths: [
                "/private/tmp/.rustyattr",
                "~/Library/Application Support/.rustyattr",
            ],
            launchAgentLabels: ["com.twostep.updater"]
        ),
        // BlueNoroff — Hidden Risk (Nov 2024, SentinelOne). Fake-PDF crypto lure with a
        // touchbar helper persistence trick via zshenv.
        SpywareSignature(
            name: "HiddenRisk (BlueNoroff)",
            processNames: ["HiddenRisk", "hidden_risk", "growth", "growth_extend", "growthhelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.hiddenrisk",
                "~/Library/.growth",
                "~/.zshenv",  // trojanized only — persistence signal handled elsewhere
            ],
            launchAgentLabels: []
        ),
        // 2024-2025 macOS infostealers
        SpywareSignature(
            name: "AMOS v2 (Atomic Stealer)",
            processNames: ["Update", "amos_v2", "atomic_v2", "SwiftBelt", "AmosLoader"],
            bundleIdentifiers: ["com.atomic.stealer.v2", "com.amos.v2"],
            filePaths: [
                "/private/tmp/.amos2",
                "/private/tmp/AppleScript*.scpt",
                "~/Library/Application Support/.amos2",
            ],
            launchAgentLabels: ["com.atomic.v2", "com.amos.persistence"]
        ),
        SpywareSignature(
            name: "PSW Stealer / Sushi",
            processNames: ["Sushi", "sushi", "sushi_stealer", "PSWStealer"],
            bundleIdentifiers: ["com.sushi.stealer"],
            filePaths: [
                "/private/tmp/.sushi",
                "~/Library/Application Support/.sushi",
            ],
            launchAgentLabels: ["com.sushi.helper"]
        ),
        SpywareSignature(
            name: "SparkCat / SparkKitty",
            processNames: ["SparkCat", "sparkcat", "SparkKitty", "sparkkitty", "GmailSparkKit"],
            bundleIdentifiers: ["com.sparkcat.agent", "com.sparkkitty.helper"],
            filePaths: [
                "/private/tmp/.sparkcat",
                "~/Library/Application Support/.sparkkitty",
            ],
            launchAgentLabels: ["com.sparkcat.helper"]
        ),
        SpywareSignature(
            name: "MacSync Stealer",
            processNames: ["MacSync", "macsync", "macsyncd", "macsync_daemon"],
            bundleIdentifiers: ["com.macsync.stealer"],
            filePaths: [
                "/private/tmp/.macsync",
                "~/Library/Application Support/.MacSync",
            ],
            launchAgentLabels: ["com.macsync.service"]
        ),
        SpywareSignature(
            name: "Realst v2",
            processNames: ["realst_v2", "RealstV2", "GameInstaller", "InstallHelper"],
            bundleIdentifiers: ["com.realst.v2", "com.game.installer"],
            filePaths: [
                "/private/tmp/.realst2",
                "~/Library/Application Support/.Realst2",
            ],
            launchAgentLabels: ["com.realst.updater", "com.game.installhelper"]
        ),
        SpywareSignature(
            name: "PurpleStealer",
            processNames: ["PurpleStealer", "purplestealer", "purple_agent"],
            bundleIdentifiers: ["com.purplestealer.agent"],
            filePaths: ["/private/tmp/.purple"],
            launchAgentLabels: ["com.purple.agent"]
        ),
        SpywareSignature(
            name: "TrickMo (macOS variant)",
            processNames: ["trickmo", "TrickMo", "trickmo_agent"],
            bundleIdentifiers: ["com.trickmo.agent"],
            filePaths: ["/private/tmp/.trickmo"],
            launchAgentLabels: ["com.trickmo.service"]
        ),
        // XCSSET refresh (Microsoft Threat Intelligence, Feb 2025) — updated payload with
        // new obfuscation, LaunchDaemon persistence, and clipboard-hijacking for crypto.
        SpywareSignature(
            name: "XCSSET v2025",
            processNames: ["xcsset2025", "XCSSETUpdater", "xcode_helper", "xchelperd",
                           "com.apple.macos.updater"],
            bundleIdentifiers: ["com.apple.macos.updater", "com.apple.xcodehelper"],
            filePaths: [
                "~/Library/Group Containers/.xcode2025",
                "~/Library/Caches/com.apple.xcode.helper",
                "/private/var/tmp/.xchelper",
            ],
            launchAgentLabels: ["com.apple.xcode.helper", "com.apple.macos.updater"]
        ),
        // 2024 — JokerSpy re-emergence
        SpywareSignature(
            name: "JokerSpy v2",
            processNames: ["xcc", "sh.py", "jokerspy", "swiftbelt"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/xcc",
                "/private/tmp/.jokerspy",
            ],
            launchAgentLabels: []
        ),
        // Charming Kitten / APT35 macOS extension (2025 activity)
        SpywareSignature(
            name: "CharmingKitten (APT35 macOS)",
            processNames: ["charming", "CharmingKitten", "kittenagent", "PhosphorusHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.charmingkitten",
                "~/Library/Application Support/.phosphorus",
            ],
            launchAgentLabels: []
        ),
        // TA453 / Mint Sandstorm macOS backdoor
        SpywareSignature(
            name: "MischiefTut (TA453)",
            processNames: ["mischieftut", "MischiefTut", "TutorialHelper"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.mischief"],
            launchAgentLabels: []
        ),
        // macMa v2 / CDDS (Daggerfly) — Symantec Aug 2024 report
        SpywareSignature(
            name: "macMa v2 / CDDS",
            processNames: ["macma", "MacMa", "cdds", "helperprocess", "systemUpdater"],
            bundleIdentifiers: ["com.apple.systemUpdater"],
            filePaths: [
                "/private/tmp/.cdds",
                "~/Library/Preferences/.macma",
            ],
            launchAgentLabels: ["com.apple.systemUpdater", "com.apple.helperprocess"]
        ),
        // Redline & similar Windows stealers ported to macOS (2024-2025 reports)
        SpywareSignature(
            name: "RedLine (macOS port)",
            processNames: ["redline", "RedLine", "redline_mac", "RLStealer"],
            bundleIdentifiers: ["com.redline.stealer"],
            filePaths: [
                "/private/tmp/.redline",
                "~/Library/Application Support/.redline",
            ],
            launchAgentLabels: ["com.redline.service"]
        ),
        // TodoSwift (Kandykorn variant, 2024)
        SpywareSignature(
            name: "TodoSwift (BlueNoroff)",
            processNames: ["TodoSwift", "todoswift", "todo_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Group Containers/.todoswift",
            ],
            launchAgentLabels: []
        ),
        // Adload / MaxOfferDeal (still active family, 2024-2025 variants)
        SpywareSignature(
            name: "Adload / MaxOfferDeal",
            processNames: ["MaxOfferDeal", "OperativeMachine", "SkilledObject",
                           "InitialProgram", "ElementaryTyped", "TypicalConfig"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/MaxOfferDeal",
                "~/Library/Application Support/.adload",
            ],
            launchAgentLabels: []
        ),
        // Shlayer & Bundlore (still current 2024-2025)
        SpywareSignature(
            name: "Shlayer",
            processNames: ["Player", "Flash Player", "Adobe Flash Player", "shlayer", "ShlayerAgent"],
            bundleIdentifiers: ["com.adobe.flashplayer.installer"],
            filePaths: [
                "/private/tmp/Player.app",
                "/private/tmp/.shlayer",
            ],
            launchAgentLabels: ["com.adobe.flashplayer"]
        ),
        SpywareSignature(
            name: "Bundlore",
            processNames: ["Bundlore", "bundlore", "installMac", "InstallerHelper"],
            bundleIdentifiers: ["com.bundlore.agent"],
            filePaths: [
                "~/Library/Application Support/.bundlore",
                "/private/tmp/.bundlore",
            ],
            launchAgentLabels: ["com.bundlore.helper"]
        ),
        // "TrollStealer" / SunSpin family (2025)
        SpywareSignature(
            name: "TrollStealer",
            processNames: ["TrollStealer", "trollstealer", "troll_agent"],
            bundleIdentifiers: ["com.trollstealer.agent"],
            filePaths: [
                "/private/tmp/.troll",
                "~/Library/Application Support/.TrollStealer",
            ],
            launchAgentLabels: ["com.troll.agent"]
        ),
        // "HZ RAT" macOS port (2024, Kaspersky)
        SpywareSignature(
            name: "HZ RAT (macOS)",
            processNames: ["hzrat", "HZRAT", "OpenVPNConnect", "openvpn_connect"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.openvpn-connect",
            ],
            launchAgentLabels: []
        ),
        // Cthulhu Stealer v2 (2024 refresh)
        SpywareSignature(
            name: "Cthulhu v2",
            processNames: ["Cthulhu2", "cthulhu_v2", "cthulhu_mac_v2"],
            bundleIdentifiers: ["com.cthulhu.v2"],
            filePaths: [
                "/private/tmp/.cthulhu2",
                "~/Library/Application Support/.Cthulhu2",
            ],
            launchAgentLabels: ["com.cthulhu.v2"]
        ),
        // Predator (Intellexa/Cytrox) refresh
        SpywareSignature(
            name: "Predator v2 (Intellexa)",
            processNames: ["predator_v2", "cytrox_v2", "IntellexaHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.predator2",
                "/private/var/tmp/.intellexa",
            ],
            launchAgentLabels: []
        ),
        // "Banshee 2.0" (Kaspersky Jan 2025, English-locale evasion removed)
        SpywareSignature(
            name: "Banshee 2.0",
            processNames: ["Banshee2", "banshee2", "banshee_v2", "BnshV2"],
            bundleIdentifiers: ["com.banshee.v2"],
            filePaths: [
                "/private/tmp/.banshee2",
                "~/Library/Application Support/.Banshee2",
            ],
            launchAgentLabels: ["com.banshee.v2"]
        ),
        // Poseidon Stealer (Rodrigo4) — active 2024
        SpywareSignature(
            name: "Poseidon v2",
            processNames: ["poseidon_v2", "PoseidonV2", "Rodrigo4"],
            bundleIdentifiers: ["com.poseidon.v2"],
            filePaths: [
                "/private/tmp/.poseidon2",
                "~/Library/Application Support/.Poseidon2",
            ],
            launchAgentLabels: ["com.poseidon.v2"]
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
        // Seen in 2024-2025 macOS malware (Ferret, NimDoor, XCSSET refresh, macMa v2)
        "com.apple.macos.updater",
        "com.apple.xcodehelper",
        "com.apple.systemUpdater",
        "com.apple.helperprocess",
        "com.apple.secd.helper",
        "com.apple.zoom.update",
        "com.google.chrome.update",  // real Google Chrome uses different label
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
        // Recent (2024-2025) impersonation patterns
        "ChromeUpdate",          // Real Chrome updater is GoogleUpdater / KeystoneAgent
        "chromeupdate",          // Ferret family lure
        "GoogIe LLC",            // NimDoor — capital-i-for-l typosquat
        "ZoomInstaller",         // Not the real Zoom binary
        "zoom_sdk_support",      // NimDoor lure
        "installer_v",           // NimDoor payload
        "TwoStepUpdater",        // RustyAttr lure
        "OpenVPNConnect",        // Real: openvpn (HZ RAT decoy name)
        "growthhelper",          // HiddenRisk / BlueNoroff
        "sysUpdater",            // Impersonates softwareupdated
        "MacOSUpdater",          // Not a real Apple process
        "SafariUpdate",          // Safari updates ride along with system updates
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
