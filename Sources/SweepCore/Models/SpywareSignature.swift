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
        // 2024-2025 macOS malware families (Objective-See / SentinelLabs / Kaspersky / Huntress reports)
        SpywareSignature(
            name: "HZ RAT (macOS)",
            // Real OpenVPN Connect's process name is "OpenVPN Connect" (with a space) and the
            // bundle ID is "net.openvpn.connect.app". The dropper uses "OpenVPNConnect" (no space)
            // and a fake bundle ID — only those imposter names are listed here.
            processNames: ["hzrat", "HZ_RAT", "OpenVPNConnect"],
            bundleIdentifiers: ["com.openvpnconnect", "com.openvpn.OpenVPNConnect"],
            filePaths: [
                "/private/tmp/.OpenVPNConnect",
                "/private/var/tmp/.hzrat",
                "~/Library/Application Support/.openvpnconnect",
            ],
            launchAgentLabels: ["com.openvpnconnect.helper"]
        ),
        SpywareSignature(
            name: "NotLockBit (macOS ransomware)",
            processNames: ["NotLockBit", "notlockbit", "lockbit_macos"],
            bundleIdentifiers: ["com.notlockbit.agent"],
            filePaths: [
                "/private/tmp/.notlockbit",
                "~/Library/Application Support/.notlockbit",
            ],
            launchAgentLabels: ["com.notlockbit.service"]
        ),
        SpywareSignature(
            name: "FlexibleFerret (DPRK)",
            processNames: [
                "FlexibleFerret", "FrostyFerret_UI", "FrostyFerret",
                "FriendlyFerret_Secure", "ChromeUpdate", "ChromeUpdateAlert",
            ],
            bundleIdentifiers: ["com.zoom.us.updater", "com.flexibleferret"],
            filePaths: [
                "/private/var/tmp/.cf",
                "/private/tmp/.ChromeUpdate",
                "~/Library/Application Support/.FrostyFerret",
            ],
            launchAgentLabels: ["com.zoom.us.zoomupdate"]
        ),
        SpywareSignature(
            name: "TodoSwift (DPRK Lazarus)",
            processNames: ["TodoSwift", "todoswift", "ToDoTasks", "BDCalendar"],
            bundleIdentifiers: ["com.toplist.bdcalendar", "com.todoswift.app"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: ["com.toplist.bdcalendar.helper"]
        ),
        SpywareSignature(
            name: "NimDoor (DPRK Lazarus)",
            processNames: ["nimdoor", "NimDoor", "nimoper", "coreupdater", "CoreKitAgent"],
            bundleIdentifiers: ["com.nimdoor.agent"],
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/Application Support/.coreupdater",
                "~/Library/Application Support/.CoreKitAgent",
            ],
            launchAgentLabels: ["com.apple.coreupdater"]
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "aph_agent"],
            bundleIdentifiers: ["com.appleprocesshub.agent"],
            filePaths: [
                "/private/tmp/applescripts",
                "/private/tmp/.appleprocesshub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.appleprocesshub.service"]
        ),
        SpywareSignature(
            name: "Hidden Risk (DPRK Lazarus)",
            processNames: ["HiddenRisk", "hiddenrisk", "BitcoinPDFAgent", "bitcoin_pdf_agent"],
            bundleIdentifiers: ["com.hiddenrisk.agent", "com.bitcoinpdf.agent"],
            filePaths: [
                "/Users/Shared/.zsh_env",
                "/private/tmp/.NCC",
                "~/Library/Application Support/.HiddenRisk",
            ],
            launchAgentLabels: ["com.apple.zsh.env", "com.bitcoinpdf.helper"]
        ),
        SpywareSignature(
            name: "RustyAttr (Rust stealer)",
            processNames: ["RustyAttr", "rustyattr", "rustystealer"],
            bundleIdentifiers: ["com.rustyattr.app"],
            filePaths: [
                "/private/tmp/.rustyattr",
                "~/Library/Application Support/.RustyAttr",
            ],
            launchAgentLabels: ["com.rustyattr.service"]
        ),
        SpywareSignature(
            name: "JaskaGO (Go stealer)",
            processNames: ["JaskaGO", "jaskago", "jaska_agent", "jaska"],
            bundleIdentifiers: ["com.jaskago.agent"],
            filePaths: [
                "/private/tmp/.jaska",
                "/private/tmp/jaska",
                "~/Library/Application Support/.JaskaGO",
            ],
            launchAgentLabels: ["com.jaskago.service"]
        ),
        SpywareSignature(
            name: "FERRETTERMINATOR (DPRK Lazarus)",
            processNames: ["FerretTerminator", "ferretterminator", "ferret_term"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.ferret",
                "/Users/Shared/.ferret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OneClik (BlueNoroff)",
            processNames: ["OneClik", "oneclik", "OneClikUtility", "oneclikhelper"],
            bundleIdentifiers: ["com.oneclik.agent", "com.oneclik.utility"],
            filePaths: [
                "/private/tmp/.oneclik",
                "~/Library/Application Support/.OneClik",
            ],
            launchAgentLabels: ["com.oneclik.service"]
        ),
        SpywareSignature(
            name: "HollowRabbit",
            processNames: ["HollowRabbit", "hollowrabbit", "rabbit_agent"],
            bundleIdentifiers: ["com.hollowrabbit.agent"],
            filePaths: [
                "/private/tmp/.hollowrabbit",
                "~/Library/Application Support/.HollowRabbit",
            ],
            launchAgentLabels: ["com.hollowrabbit.service"]
        ),
        SpywareSignature(
            name: "OSX.SwiftBelt / SwiftFox",
            processNames: ["SwiftBelt", "swiftbelt", "SwiftFox", "swiftfox"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.swiftbelt", "/private/tmp/.swiftfox"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Crackonosh (macOS port)",
            processNames: ["Crackonosh", "crackonosh", "macspeed", "MacOptimize"],
            bundleIdentifiers: ["com.crackonosh.miner"],
            filePaths: [
                "/private/tmp/.crackonosh",
                "~/Library/Application Support/.macspeed",
            ],
            launchAgentLabels: ["com.macspeed.optimizer"]
        ),
        SpywareSignature(
            name: "RustyMiner / RustyKey (cryptominer)",
            processNames: ["RustyMiner", "rustyminer", "RustyKey", "rustykey", "xmrig-rs"],
            bundleIdentifiers: ["com.rustyminer.agent"],
            filePaths: [
                "/private/tmp/.rustyminer",
                "~/Library/Application Support/.rustyminer",
            ],
            launchAgentLabels: ["com.rustyminer.service"]
        ),
        SpywareSignature(
            name: "macOS XMRig (unauthorized cryptominer)",
            processNames: ["xmrig", "XMRig", "minerd", "cpuminer", "ccminer"],
            bundleIdentifiers: ["com.xmrig.miner"],
            filePaths: [
                "/private/tmp/.xmrig",
                "~/Library/Application Support/.xmrig",
            ],
            launchAgentLabels: ["com.xmrig.service"]
        ),
        SpywareSignature(
            name: "DPRK FullHouse / RustBucket family",
            processNames: ["FullHouse", "fullhouse", "fullhouse.doored", "FullHouse_Helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.fullhouse",
                "/Users/Shared/.fullhouse",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "PassiveTotal / OSX.ClickFix",
            processNames: ["ClickFix", "clickfix", "ClickFixHelper", "InstallCleanerPro"],
            bundleIdentifiers: ["com.clickfix.installer"],
            filePaths: ["/private/tmp/.clickfix"],
            launchAgentLabels: ["com.clickfix.helper"]
        ),
        SpywareSignature(
            name: "RealStealer / FixedAgent (2025)",
            processNames: ["RealStealer", "realstealer", "FixedAgent", "fixedagent"],
            bundleIdentifiers: ["com.realstealer.agent"],
            filePaths: ["/private/tmp/.realstealer"],
            launchAgentLabels: ["com.realstealer.service"]
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
        // 2024-2025 observed imposter bundle IDs
        "com.apple.coreupdater",
        "com.apple.zsh.env",
        "com.apple.systempreferences.helper",
        "com.apple.macshare.plist",
        "com.apple.appstore.updater",
        "com.apple.appcache.helper",
        "com.apple.crash.agent",
        "com.apple.spotlight.helper",
        "com.apple.update.daemon",
        "com.apple.system.helper",
        "com.apple.icloud.helper",
        "com.apple.iclouddrive.helper",
        "com.apple.notification.helper",
        "com.apple.network.helper",
        "com.apple.audio.helper",
        "com.apple.bluetooth.helper",
        "com.apple.print.helper",
        "com.apple.airdrop.helper",
        "com.apple.finder.helper",
        "com.apple.dock.helper",
        "com.apple.tcc.helper",
        "com.apple.softwareupdate.daemon",
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
        // Additional imposter names observed in 2024-2025 malware reports
        "coreupdater",           // Used by NimDoor
        "CoreKitAgent",          // Used by NimDoor variants
        "appcache",              // Not Apple
        "appcacheagent",         // Not Apple
        "macupdater",            // Not Apple
        "macupdate_helper",      // Not Apple
        "MacUpdater",            // Not Apple (mimics MacUpdate the app)
        "AppStoreUpdate",        // Real: storedownloadd/storeassetd
        "AirportHelper",         // Real: airportd
        "BluetoothHelper",       // Real: bluetoothd
        "tcc_helper",            // Real: tccd
        "tccd_helper",           // Real: tccd
        "Finder.app",            // Real: Finder (no .app suffix in `ps`)
        "Dock.app",              // Real: Dock (no .app suffix)
        "SystemUIServer.app",    // Real: SystemUIServer (no .app suffix)
        "mds_helper",            // Real: mds
        "diskutility",           // Real: diskutilityd
        "logind",                // Linux-style, macOS uses loginwindow
        "syslogd_helper",        // Real: syslogd
        "configd_helper",        // Real: configd
        "WebKitNetworkingHelper",// Real: com.apple.WebKit.Networking
        "WindowServer_helper",   // Real: WindowServer (no helper variant)
        "iTunesHelperAgent",     // Real: iTunesHelper (without "Agent")
        "PhotoLibraryHelper",    // Real: photolibraryd
        "AppleSpellAgent",       // Real: AppleSpell (without "Agent")
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
