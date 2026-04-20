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
        // Lazarus "Contagious Interview" campaign (2024-2025) — trojanized
        // Node.js modules and fake job-interview coding tasks drop these backdoors.
        SpywareSignature(
            name: "BeaverTail",
            processNames: ["beavertail", "BeaverTail", "p2pchat", "airdropserver"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.n2/",
                "/tmp/p2pchat",
                "/private/tmp/.beavertail",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["invisibleferret", "ssh-agent-helper", "node-updater"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.npl",
                "~/.n2/pay",
                "/private/tmp/.ferret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FlexibleFerret",
            processNames: ["FlexibleFerret", "flexibleferret", "ChromeUpdate"],
            bundleIdentifiers: ["com.flexibleferret.app"],
            filePaths: ["/private/tmp/.flexibleferret"],
            launchAgentLabels: ["com.apple.ChromeUpdate.plist"]
        ),
        SpywareSignature(
            name: "FrostyFerret",
            processNames: ["FrostyFerret", "frostyferret", "ChromeUpdateAlert"],
            bundleIdentifiers: ["com.frostyferret.agent"],
            filePaths: ["/private/tmp/.frostyferret"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FriendlyFerret",
            processNames: ["FriendlyFerret", "friendlyferret"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.friendlyferret"],
            launchAgentLabels: []
        ),
        // BlueNoroff (DPRK) 2024 campaigns
        SpywareSignature(
            name: "TodoSwift",
            processNames: ["TodoSwift", "todoswift", "AiApp"],
            bundleIdentifiers: ["com.todoswift.app"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.todoswift",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "RustyAttr",
            processNames: ["rustyattr", "RustyAttr", "xattrhelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.rustyattr",
                "~/Library/Caches/.rustyattr",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "HiddenRisk",
            processNames: ["HiddenRisk", "hiddenrisk", "CryptoArchive"],
            bundleIdentifiers: ["com.hiddenrisk.agent"],
            filePaths: [
                "/private/tmp/.hiddenrisk",
                "~/Library/Application Support/.hiddenrisk",
            ],
            launchAgentLabels: ["com.apple.hiddenrisk.plist"]
        ),
        SpywareSignature(
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "zoom_sdk_helper", "GoogleChromeUpdater"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/Application Support/.zoom_sdk",
                "/Users/Shared/.nimdoor",
            ],
            launchAgentLabels: ["com.google.chrome.updater.plist"]
        ),
        // 2024-2025 infostealers (new variants beyond AMOS/Poseidon family)
        SpywareSignature(
            name: "Mystic Stealer (macOS)",
            processNames: ["Mystic", "mystic_stealer", "msticstl"],
            bundleIdentifiers: ["com.mystic.stealer"],
            filePaths: [
                "/private/tmp/.mystic",
                "~/Library/Application Support/.Mystic",
            ],
            launchAgentLabels: ["com.mystic.service"]
        ),
        SpywareSignature(
            name: "ShadowVault Stealer",
            processNames: ["ShadowVault", "shadowvault", "svault"],
            bundleIdentifiers: ["com.shadowvault.stealer"],
            filePaths: [
                "/private/tmp/.shadowvault",
                "~/Library/Application Support/.ShadowVault",
            ],
            launchAgentLabels: ["com.shadowvault.agent"]
        ),
        SpywareSignature(
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey_stealer", "odysteal"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.service"]
        ),
        SpywareSignature(
            name: "Mac.c Stealer",
            processNames: ["macc_stealer", "mac.c", "maccstealer"],
            bundleIdentifiers: ["com.macc.stealer"],
            filePaths: [
                "/private/tmp/.macc",
                "~/Library/Application Support/.MacC",
            ],
            launchAgentLabels: ["com.macc.agent"]
        ),
        SpywareSignature(
            name: "DigitStealer",
            processNames: ["DigitStealer", "digitstealer", "dgstl"],
            bundleIdentifiers: ["com.digit.stealer"],
            filePaths: [
                "/private/tmp/.digit",
                "~/Library/Application Support/.Digit",
            ],
            launchAgentLabels: ["com.digit.stealer"]
        ),
        SpywareSignature(
            name: "Fuji Stealer",
            processNames: ["Fuji", "fujistealer", "fuji_mac"],
            bundleIdentifiers: ["com.fuji.stealer"],
            filePaths: [
                "/private/tmp/.fuji",
                "~/Library/Application Support/.Fuji",
            ],
            launchAgentLabels: ["com.fuji.service"]
        ),
        // HZ RAT (macOS port, 2024) — used against Chinese-speaking enterprise targets
        SpywareSignature(
            name: "HZ RAT (macOS)",
            processNames: ["hzrat", "HZRat", "OpenVPNConnect.helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/OpenVPNConnect/helper",
            ],
            launchAgentLabels: ["com.openvpn.client.helper.plist"]
        ),
        // LightSpy macOS implant (APT41-linked, 2024 variant)
        SpywareSignature(
            name: "LightSpy (macOS)",
            processNames: ["lightspy", "LightSpy", "macos_agent", "lsclient"],
            bundleIdentifiers: ["com.lightspy.agent"],
            filePaths: [
                "/private/var/tmp/.lightspy",
                "~/Library/Application Support/.lsclient",
            ],
            launchAgentLabels: ["com.lightspy.service"]
        ),
        // AdLoad — adware/PUP family still actively morphing through 2025
        SpywareSignature(
            name: "AdLoad",
            processNames: ["SearchPartyHelper", "SearchPartyd",
                           "PhotoShowAgent", "ResultsUncover", "LookingForChoice"],
            bundleIdentifiers: ["com.SearchPartyHelper.agent"],
            filePaths: [
                "~/Library/Application Support/.com.SearchPartyHelper.Service",
                "/Library/LaunchAgents/com.SearchPartyHelper.plist",
            ],
            launchAgentLabels: [
                "com.SearchPartyHelper.agent",
                "com.SearchPartyd.service",
                "com.adload.helper",
            ]
        ),
        // ReaderUpdate — long-running macOS adware/infostealer loader (Go/Crystal/Rust rewrites)
        SpywareSignature(
            name: "ReaderUpdate",
            processNames: ["ReaderUpdate", "readerupdate", "reader_update"],
            bundleIdentifiers: ["com.readerupdate.agent"],
            filePaths: [
                "~/Library/Application Support/ReaderUpdate",
                "~/.readerupdate",
            ],
            launchAgentLabels: ["com.readerupdate.agent", "com.readerupdate.helper"]
        ),
        // XCSSET v2 (2024-2025 evolved Xcode project infector)
        SpywareSignature(
            name: "XCSSET v2",
            processNames: ["xcode_helper", "xcodesetup", "SafariCloudSync"],
            bundleIdentifiers: ["com.apple.xcodesetup", "com.apple.SafariCloudSync"],
            filePaths: [
                "~/Library/Application Scripts/com.apple.xcodesync",
                "~/Library/Caches/com.apple.SafariCloudSync",
                "~/Library/Developer/Xcode/UserData/.xcsset",
            ],
            launchAgentLabels: [
                "com.apple.xcodesync.agent",
                "com.apple.SafariCloudSync.plist",
            ]
        ),
        // ToxicPanda (macOS variant, 2024-2025)
        SpywareSignature(
            name: "ToxicPanda",
            processNames: ["ToxicPanda", "toxicpanda", "tpagent"],
            bundleIdentifiers: ["com.toxicpanda.agent"],
            filePaths: [
                "/private/tmp/.toxicpanda",
                "~/Library/Application Support/.ToxicPanda",
            ],
            launchAgentLabels: ["com.toxicpanda.service"]
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
        // Newer (2024-2025) impersonation patterns
        "com.apple.hiddenrisk",
        "com.apple.SafariCloudSync",
        "com.apple.xcodesync",
        "com.apple.ChromeUpdate",
        "com.apple.xprotect.helper",
        "com.apple.notarization.agent",
        "com.apple.passwords.sync",
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
        "GoogleChromeUpdater",   // Real: GoogleSoftwareUpdateAgent (wrong name pattern)
        "ChromeUpdate",          // Real: GoogleSoftwareUpdate (abbreviated)
        "ChromeUpdateAlert",     // Not a real Chrome process — Lazarus FerretFamily lure
        "zoom_sdk_helper",       // Real: zoom.us / CptHost — used by NimDoor
        "SafariCloudSync",       // Not a real Safari process — XCSSET v2 lure
        "xcodesetup",            // Not a real Xcode binary
        "node-updater",          // Fake Node.js updater — Contagious Interview (InvisibleFerret)
        "ssh-agent-helper",      // Real: ssh-agent (no "helper" suffix)
        "OpenVPNConnect.helper", // Real: OpenVPN Connect (no dotted helper) — HZ RAT
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
