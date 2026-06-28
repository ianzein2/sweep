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
        // 2024-2026 macOS threats. Reported by Jamf Threat Labs, SentinelOne, Kaspersky GReAT,
        // Sekoia, Volexity, and CrowdStrike. Process names and paths come from published
        // analyses and shared IOC feeds; see the per-entry comment for the lead reference.
        SpywareSignature(  // Lazarus, Aug 2024 (SentinelOne)
            name: "TodoSwift",
            processNames: ["TodoSwift", "todoswift", "SwiftUpdater", "CryptoTrade"],
            bundleIdentifiers: ["com.todoswift.agent"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.todoswift",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(  // BlueNoroff, Nov 2024 (SentinelOne — "HiddenRisk")
            name: "HiddenRisk / RustDoor",
            processNames: ["RustDoor", "rustdoor", "GoSorry", "growth", "ProxyAgent"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/.helper",
                "~/Library/Application Support/.RustDoor",
                "/private/var/tmp/.rustdoor",
            ],
            launchAgentLabels: ["com.apple.helper", "com.apple.bluetooth.helper"]
        ),
        SpywareSignature(  // BlueNoroff, June 2025 (Huntress / SentinelOne)
            name: "NimDoor / DurianBeacon",
            processNames: ["NimDoor", "nimdoor", "DurianBeacon", "GoogleChromeUpdater", "ZoomVideoSDK"],
            bundleIdentifiers: ["us.zoom.SDK", "com.google.update.helper"],
            filePaths: [
                "/private/var/tmp/.nimdoor",
                "~/Library/Application Support/.nimdoor",
                "/tmp/.zoom_sdk",
            ],
            launchAgentLabels: ["com.google.update.helper"]
        ),
        SpywareSignature(  // NK "Contagious Interview", late 2023+; npm supply-chain stages
            name: "BeaverTail",
            processNames: ["BeaverTail", "beavertail", "n2.exe", "lkdvd_macos"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.npl",
                "/private/tmp/.npl",
                "~/Library/Caches/.beavertail",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(  // Python backdoor paired with BeaverTail
            name: "InvisibleFerret",
            processNames: ["pay", "invisibleferret", "FlexibleFerret", "fcc-installer", "fjsc_installer"],
            bundleIdentifiers: ["com.apple.codequickfix", "com.flexible.installer"],
            filePaths: [
                "/tmp/.npl",
                "~/.npl",
                "~/Library/Caches/com.apple.codequickfix",
            ],
            launchAgentLabels: ["com.apple.codequickfix"]
        ),
        SpywareSignature(  // Proofpoint, Feb 2025 — TA569 fake-update lure delivers AMOS variant
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "FrigidApp", "DMG_Mounter"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
            ],
            launchAgentLabels: ["com.frigid.agent"]
        ),
        SpywareSignature(  // Kandji / Jamf, Apr 2025 — extends Atomic Stealer family
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey_stealer", "OdysseyHelper", "AppleScript-Odyssey"],
            bundleIdentifiers: ["com.odyssey.stealer", "com.odyssey.helper"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
                "/private/tmp/AppleScript-odyssey-*.scpt",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        SpywareSignature(  // Kaspersky GReAT, Jan 2025 — first OCR-based image stealer in App Store ecosystem
            name: "SparkCat",
            processNames: ["spark", "sparkcat", "SparkApp", "TextRecognizerHelper"],
            bundleIdentifiers: ["com.spark.ocr", "com.sparkcat.app"],
            filePaths: [
                "~/Library/Application Support/.SparkCat",
                "~/Library/Caches/com.spark.ocr",
            ],
            launchAgentLabels: ["com.spark.ocr.service"]
        ),
        SpywareSignature(  // Kandji, June 2025
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "aph_helper", "ProcessHubAgent"],
            bundleIdentifiers: ["com.apple.processhub", "com.appleprocesshub.agent"],
            filePaths: [
                "/private/tmp/.aph",
                "~/Library/Application Support/.AppleProcessHub",
                "/tmp/.aph_dropper",
            ],
            launchAgentLabels: ["com.apple.processhub.helper"]
        ),
        SpywareSignature(  // Jamf, May 2025 — Banshee fork with anti-VM tricks
            name: "DigitStealer",
            processNames: ["DigitStealer", "digitstealer", "DigitApp", "DigitInstaller"],
            bundleIdentifiers: ["com.digit.stealer"],
            filePaths: [
                "/private/tmp/.digit",
                "~/Library/Application Support/.Digit",
            ],
            launchAgentLabels: ["com.digit.stealer"]
        ),
        SpywareSignature(  // CrowdStrike SCATTERED SPIDER, Sept 2025 — browser-cookie focused
            name: "CookieSpider",
            processNames: ["CookieSpider", "cookiespider", "SHAMOS", "shamos", "CookieGrabber"],
            bundleIdentifiers: ["com.cookie.spider"],
            filePaths: [
                "/private/tmp/.cookies",
                "~/Library/Application Support/.CookieSpider",
                "/private/tmp/.shamos",
            ],
            launchAgentLabels: ["com.cookie.spider"]
        ),
        SpywareSignature(  // SentinelOne, Mar 2025 — Go-based loader for stage-two implants
            name: "GoStringer Loader",
            processNames: ["gostringer", "GoStringer", "go_loader", "macho_loader"],
            bundleIdentifiers: ["com.go.stringer"],
            filePaths: [
                "/private/tmp/.gostringer",
                "~/Library/Caches/.gostringer",
            ],
            launchAgentLabels: ["com.go.stringer"]
        ),
        SpywareSignature(  // PIRATE PANDA / TAG-100, 2025 (Recorded Future)
            name: "ShadowPad-macOS",
            processNames: ["shadowpad", "ShadowPad", "scrss", "scrss_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/PrivilegedHelperTools/.shadowpad",
                "/private/var/tmp/.shadowpad",
            ],
            launchAgentLabels: ["com.apple.scrss"]
        ),
        SpywareSignature(  // BlueNoroff, late 2024 (Volexity)
            name: "RustyAttr",
            processNames: ["RustyAttr", "rustyattr", "ToDoTasks", "TodoAtomic"],
            bundleIdentifiers: ["com.rustyattr.agent"],
            filePaths: [
                "~/Library/Application Support/.RustyAttr",
                "/private/tmp/.rustyattr",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(  // Volexity, 2025 (DPRK "Lightless Can" successor)
            name: "Lightless Can II",
            processNames: ["lightlessmcse", "LightlessCAN", "LightlessClient", "macse"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/.lightless",
                "~/Library/Application Support/.lightless",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(  // Microsoft Threat Intel, 2024 — "Storm-2077" stage two macOS implant
            name: "Storm2077 Backdoor",
            processNames: ["storm_agent", "storm2077", "stagetwo"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.storm2077",
                "~/Library/.s2077",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(  // ESET, May 2025 — "PassiveStealer" delivered through cracked apps
            name: "PassiveStealer",
            processNames: ["PassiveStealer", "passivestealer", "Passive_App", "PSAgent"],
            bundleIdentifiers: ["com.passive.stealer"],
            filePaths: [
                "/private/tmp/.passive",
                "~/Library/Application Support/.PassiveStealer",
            ],
            launchAgentLabels: ["com.passive.stealer"]
        ),
        SpywareSignature(  // RedotPay-themed stealer family, mid-2025
            name: "RedotPay Stealer",
            processNames: ["RedotPay", "redotpay", "RedotApp", "RedotInstaller"],
            bundleIdentifiers: ["com.redotpay.stealer"],
            filePaths: [
                "/private/tmp/.redotpay",
                "~/Library/Application Support/.RedotPay",
            ],
            launchAgentLabels: ["com.redotpay.agent"]
        ),
        // Commercial mercenary spyware (mobile-first, but Mac variants reported by Citizen Lab 2024-2025)
        SpywareSignature(
            name: "Reign / QuaDream (Citizen Lab)",
            processNames: ["reign", "qdr_agent", "kingsmen", "quadream"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.reign",
                "~/Library/.qdr",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(  // Intellexa, 2024-2025 — Predator desktop variant
            name: "Intellexa Alien (macOS)",
            processNames: ["alien_helper", "intellexa", "AlienAgent", "intelagent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.alien",
                "/Library/.intellexa",
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
        // 2024-2026 mimic patterns observed in macOS implants
        "com.apple.bluetooth.helper",     // RustDoor / HiddenRisk
        "com.apple.codequickfix",          // InvisibleFerret
        "com.apple.processhub",            // AppleProcessHub
        "com.apple.processhub.helper",
        "com.apple.scrss",                 // ShadowPad-macOS
        "com.apple.helper",
        "com.apple.softwareupdate.helper",
        "com.google.update.helper",        // NimDoor mimics Google updater
        "us.zoom.SDK",                     // NimDoor mimics Zoom SDK
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
