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
        // 2024-2025 macOS infostealers and droppers
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid", "WindowsUpdate", "Chrome-update", "Safari-update"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
                "/private/var/tmp/.frigid",
            ],
            launchAgentLabels: ["com.frigid.agent", "com.update.helper"]
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "process_hub", "applehub", "AppleAccountHelper"],
            bundleIdentifiers: ["com.appleprocesshub.app"],
            filePaths: [
                "/private/tmp/.aph",
                "~/Library/Application Support/.AppleProcessHub",
                "/tmp/.aph_stage",
            ],
            launchAgentLabels: ["com.apple.processhub"]  // fake Apple label
        ),
        SpywareSignature(
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey_mac", "OdysseyStealer", "odst"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        SpywareSignature(
            name: "BeaverTail (DPRK ContagiousInterview)",
            processNames: ["BeaverTail", "beavertail", "node_helper", "npm_helper",
                           "ContagiousInterview", "fccall"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.beavertail",
                "~/.npm/_cacache/.beaver",
                "~/Library/Application Support/.BeaverTail",
                // BeaverTail commonly drops to a hidden home directory file
                "~/.n2/p.exe",
                "~/.n2/p",
                "~/.n2/pay",
            ],
            launchAgentLabels: ["com.node.helper", "com.npm.update"]
        ),
        SpywareSignature(
            name: "InvisibleFerret (DPRK)",
            processNames: ["InvisibleFerret", "invisibleferret", "npc_helper", "appletwm"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.n2/pay",
                "~/.n2/.config",
                "/private/tmp/.invisible",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OtterCookie (DPRK)",
            processNames: ["OtterCookie", "ottercookie", "node_otter", "fccall2"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.otter",
                "~/Library/Application Support/.OtterCookie",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FlexibleFerret (DPRK)",
            processNames: ["FlexibleFerret", "flexible_ferret", "FerretHelper",
                           "ChromeUpdate", "FrostyFerret"],
            bundleIdentifiers: ["com.flexible.ferret"],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/Application Support/.FlexibleFerret",
                "~/Library/LaunchAgents/com.apple.softwareupdate-agent.plist",
            ],
            launchAgentLabels: ["com.apple.softwareupdate-agent"]  // fake
        ),
        SpywareSignature(
            name: "HiddenRisk (DPRK)",
            processNames: ["HiddenRisk", "hiddenrisk", "RustDoor", "rust_door",
                           "GoSorry", "Hloader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.hiddenrisk",
                "/Library/Application Support/.HiddenRisk",
                "~/Library/Application Support/.HiddenRisk",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "RustDoor (Crypto Industry)",
            processNames: ["RustDoor", "rustdoor", "rd_helper", "VisualStudioUpdater",
                           "VisualStudioHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.rustdoor",
                "~/Library/Application Support/.RustDoor",
            ],
            launchAgentLabels: ["com.visualstudio.updater"]  // fake
        ),
        SpywareSignature(
            name: "Pearl Stealer",
            processNames: ["Pearl", "pearl_stealer", "PearlAgent", "pearlsh"],
            bundleIdentifiers: ["com.pearl.stealer"],
            filePaths: [
                "/private/tmp/.pearl",
                "~/Library/Application Support/.Pearl",
            ],
            launchAgentLabels: ["com.pearl.agent"]
        ),
        SpywareSignature(
            name: "Tiny FUD",
            processNames: ["TinyFUD", "tinyfud", "tfud", "fudagent"],
            bundleIdentifiers: ["com.tinyfud.app"],
            filePaths: [
                "/private/tmp/.tfud",
                "~/Library/Application Support/.TinyFUD",
            ],
            launchAgentLabels: ["com.tinyfud.service"]
        ),
        SpywareSignature(
            name: "MAS Stealer",
            processNames: ["MASStealer", "masstealer", "mas_stealer", "MacUpdater"],
            bundleIdentifiers: ["com.mas.stealer"],
            filePaths: [
                "/private/tmp/.mas",
                "~/Library/Application Support/.MAS",
            ],
            launchAgentLabels: ["com.mas.agent"]
        ),
        // 2024-2025 ClickFix / fake-CAPTCHA droppers
        SpywareSignature(
            name: "ClickFix Mac Dropper",
            processNames: ["ClickFix", "clickfix", "captcha_helper", "TerminalUpdater"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.clickfix",
                "/private/tmp/captcha.sh",
                "~/Library/Application Support/.ClickFix",
            ],
            launchAgentLabels: ["com.captcha.helper"]
        ),
        SpywareSignature(
            name: "FakeUpdates / SocGholish (Mac variant)",
            processNames: ["fakeupdate", "SocGholish", "browserUpdate",
                           "ChromeUpdater", "FirefoxUpdater", "SafariUpdater"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.update",
                "~/Library/Application Support/.BrowserUpdate",
            ],
            launchAgentLabels: ["com.browser.updater", "com.chrome.updater"]
        ),
        // Crystals — NSO-linked Mac targeted spyware (late 2024-2025)
        SpywareSignature(
            name: "Crystals (NSO)",
            processNames: ["crystalsd", "Crystals", "crystals_agent", "crpd"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.crystals",
                "/Library/.crystals",
            ],
            launchAgentLabels: []
        ),
        // Triangulation-style implants (iOS-derived techniques on macOS)
        SpywareSignature(
            name: "Operation Triangulation (Mac variant)",
            processNames: ["BackupAgent", "triangulationd", "imagentd"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/db/.triangulation",
                "~/Library/Caches/.triangulation",
            ],
            launchAgentLabels: []
        ),
        // Lumma Stealer Mac variant (emerged 2024-2025)
        SpywareSignature(
            name: "LummaC2 (Mac variant)",
            processNames: ["lumma", "LummaC2", "lummac", "lummahelper"],
            bundleIdentifiers: ["com.lumma.stealer"],
            filePaths: [
                "/private/tmp/.lumma",
                "~/Library/Application Support/.Lumma",
            ],
            launchAgentLabels: ["com.lumma.agent"]
        ),
        // Crypto-targeting variants
        SpywareSignature(
            name: "BlueNoroff Crypto Stealer (RustBucket v3)",
            processNames: ["CryptoSwift", "CryptoAssetCalc", "BlueNoroff", "ProcessReporter"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.bn",
                "~/Library/Application Support/.BlueNoroff",
            ],
            launchAgentLabels: []
        ),
        // Variants targeting cracked / pirated app installers (2024-2025)
        SpywareSignature(
            name: "TodoSwift",
            processNames: ["TodoSwift", "todoswift", "ts_helper"],
            bundleIdentifiers: ["com.todoswift.app"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: ["com.todoswift.agent"]
        ),
        // Recent crypto-drainer browser companions (early 2025)
        SpywareSignature(
            name: "AppleScript Wallet Drainer",
            processNames: ["wallet_drain", "WalletDrainer", "drainagent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/wallet.scpt",
                "/private/tmp/.drain.scpt",
                "~/Library/Application Support/.WalletDrainer",
            ],
            launchAgentLabels: []
        ),
    ]

    // MARK: - Heuristic Detection Patterns

    /// Fake Apple bundle ID patterns — real Apple IDs follow strict conventions
    public static let fakeAppleBundlePatterns: [String] = [
        "com.apple.softwareupdate.agent",
        "com.apple.softwareupdate-agent",
        "com.apple.system.update",
        "com.apple.systemd",
        "com.apple.updater",
        "com.apple.webkitproxy",
        "com.apple.appstore.agent",
        "com.apple.icloud.sync",
        "com.apple.security.agent",
        "com.apple.kernel.service",
        "com.apple.daemon.helper",
        // 2024-2025 fake Apple labels observed in BeaverTail/FlexibleFerret/RustDoor
        "com.apple.processhub",
        "com.apple.appleaccount.helper",
        "com.apple.spotlight.indexer",
        "com.apple.cloudd.helper",
        "com.apple.systemconfig.daemon",
        "com.apple.mediasharing.helper",
        "com.apple.update.installer",
        "com.apple.installer.daemon",
        "com.apple.mac.helper",
        "com.apple.icloud.helper",
        "com.apple.softwareupdate.installer",
        "com.apple.coreservices.helper",
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
        // Fake "browser updater" process names — Atomic / FrigidStealer / FakeUpdates use these
        "ChromeUpdate",          // Real Chrome updater is GoogleSoftwareUpdate
        "Chrome-update",
        "ChromeUpdater",
        "FirefoxUpdater",
        "SafariUpdater",         // Safari is updated via macOS itself
        "Safari-update",
        "BrowserUpdate",
        "WindowsUpdate",         // Windows process name on macOS = always malicious
        "VisualStudioUpdater",   // Used by RustDoor disguise; real one differs
        "VisualStudioHelper",
        "TerminalUpdater",       // Terminal.app does not have its own updater
        "MacUpdater",            // Mimics legitimate MacUpdater app
        // 2024-2025 stealer process names that pose as system services
        "AppleAccountHelper",    // No such Apple binary
        "AppleProcessHub",
        "ProcessReporter",       // Used by BlueNoroff/RustBucket v3
        "SystemConfigurationHelper",
        "iCloudHelperAgent",
        "MacOSSync",
        "MacOSAgent",
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
