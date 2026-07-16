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
        // DPRK Contagious Interview campaign (2024-2025)
        // Fake job-interview lures targeting developers; Node.js/Python multi-stage
        SpywareSignature(
            name: "BeaverTail",
            processNames: ["beavertail", "BeaverTail", "n2n", "p2p", "car.node"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.npl",
                "/private/tmp/p2.py",
                "/private/tmp/beaver",
                "~/.n2/npm",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["invisibleferret", "invisible_ferret"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.pay",
                "/private/tmp/.bow",
                "~/.n2/pay",
                "/private/tmp/mlip",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OtterCookie",
            processNames: ["ottercookie", "otter_cookie", "cookie_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.ottercookie",
                "~/.n2/ottercookie",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FlexibleFerret",
            processNames: ["flexibleferret", "FlexibleFerret", "FerretUpdater", "ChromeUpdate", "ChromeUpdateAlert"],
            bundleIdentifiers: ["com.zoom.us.updater"],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/Application Support/.ferret",
            ],
            launchAgentLabels: ["com.apple.ChromeUpdateAlert"]
        ),
        // NimDoor — DPRK Nim-based backdoor, disclosed 2025
        // Signal-based persistence, masquerades as Google Keystone / CoreKit
        SpywareSignature(
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "GoogleKeystoneAgent", "googlekeystoneagent",
                          "CoreKitAgent", "corekitagent", "trojan_nim"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/LaunchAgents/com.google.keystone.agent.plist",
                "~/Library/Application Support/GoogleKeystone",
                "/private/tmp/.nimdoor",
            ],
            launchAgentLabels: ["com.google.keystone.agent", "com.apple.corekit.agent"]
        ),
        // FrigidStealer — 2025, distributed via SmartApeSG / TA569 fake browser updates
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid", "MacBrowserUpdate", "SafariUpdate"],
            bundleIdentifiers: ["com.macupdate.frigid", "com.safari.update.helper"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
            ],
            launchAgentLabels: ["com.macupdate.frigid"]
        ),
        // HZ Rat for macOS — Chinese-linked, disclosed Aug 2024 (Kaspersky)
        // Targets WeChat/DingTalk credentials
        SpywareSignature(
            name: "HZ Rat (macOS)",
            processNames: ["hzrat", "HZRat", "OpenVPNConnect.app", "hz_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/airportpaird",
                "/Users/Shared/.hzrat",
                "~/Library/Application Support/.hzrat",
            ],
            launchAgentLabels: ["com.hz.agent"]
        ),
        // LightSpy for macOS — modular surveillance framework, disclosed 2024
        SpywareSignature(
            name: "LightSpy (macOS)",
            processNames: ["lightspy", "LightSpy", "macircloader", "coredump_helper"],
            bundleIdentifiers: ["com.apple.macos.softwareupdate"],
            filePaths: [
                "/private/var/db/.lightspy",
                "~/Library/Caches/.lightspy",
                "/Library/LaunchDaemons/com.apple.softwareupdate.plist.helper",
            ],
            launchAgentLabels: ["com.apple.macos.softwareupdate"]
        ),
        // RustDoor / GateDoor — ALPHV-linked, disclosed Feb 2024
        SpywareSignature(
            name: "RustDoor",
            processNames: ["rustdoor", "RustDoor", "Visual Studio Updater", "zshrc_updater",
                          "VisualStudioUpdater"],
            bundleIdentifiers: ["com.microsoft.vs.updater"],
            filePaths: [
                "~/Library/Application Support/mysqlserver.plist",
                "~/Library/LaunchAgents/com.microsoft.vs.updater.plist",
                "/tmp/.test",
            ],
            launchAgentLabels: ["com.microsoft.vs.updater"]
        ),
        SpywareSignature(
            name: "GateDoor",
            processNames: ["gatedoor", "GateDoor", "go_helper"],
            bundleIdentifiers: [],
            filePaths: ["/tmp/.gatedoor"],
            launchAgentLabels: []
        ),
        // JokerSpy — Python-based RAT, disclosed 2023, active in 2024
        SpywareSignature(
            name: "JokerSpy",
            processNames: ["JokerSpy", "jokerspy", "xcc", "sh.py", "shared.dat"],
            bundleIdentifiers: ["com.apple.xcc", "com.apple.security.check"],
            filePaths: [
                "/Users/Shared/xcc",
                "/Users/Shared/shared.dat",
                "~/Public/Safari/sh.py",
            ],
            launchAgentLabels: []
        ),
        // TodoSwift / GreenDorm — DPRK BlueNoroff, disclosed Aug 2024
        SpywareSignature(
            name: "TodoSwift",
            processNames: ["TodoSwift", "todoswift", "todo_swift", "GreenDorm"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.todoswift",
            ],
            launchAgentLabels: []
        ),
        // BlueNoroff HiddenRisk — disclosed Nov 2024
        SpywareSignature(
            name: "HiddenRisk (BlueNoroff)",
            processNames: ["hiddenrisk", "HiddenRisk", "growth", "GrowthProxy"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/LaunchAgents/com.google.growth.plist",
                "~/.Growth",
            ],
            launchAgentLabels: ["com.google.growth"]
        ),
        // PondRAT — DPRK Citrine Sleet / Gleaming Pisces, Sep 2024 (Palo Alto Unit 42)
        // Poisoned Python packages (real-ip, jsonpickle-fastify, coloredlogs-jsonpickle)
        SpywareSignature(
            name: "PondRAT",
            processNames: ["pondrat", "PondRAT", "python_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.pond",
                "~/.pondrat",
            ],
            launchAgentLabels: []
        ),
        // KrustyLoader — DPRK Andariel, 2024, Ivanti Connect Secure delivery chain
        SpywareSignature(
            name: "KrustyLoader",
            processNames: ["krustyloader", "KrustyLoader", "rust_loader"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.k",
                "/tmp/.krusty",
            ],
            launchAgentLabels: []
        ),
        // NotLockBit — macOS ransomware, disclosed Oct 2024 (Trend Micro / SentinelOne)
        // Impersonates LockBit branding; Go-based, exfil to Amazon S3
        SpywareSignature(
            name: "NotLockBit",
            processNames: ["NotLockBit", "notlockbit", "not_lockbit", "lockbit_mac"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.notlockbit",
                "~/Desktop/NotLockBitReadMeForVictim.txt",
            ],
            launchAgentLabels: []
        ),
        // RustyAttr — 2024, DPRK, abuses extended attributes to hide payloads
        SpywareSignature(
            name: "RustyAttr",
            processNames: ["rustyattr", "RustyAttr", "xattr_loader"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.rustyattr",
                "~/Library/Application Support/.rustyattr",
            ],
            launchAgentLabels: []
        ),
        // CherryPie / FullHouse.Doored — Aug 2024, DPRK Citrine Sleet
        SpywareSignature(
            name: "FullHouse.Doored",
            processNames: ["FullHouse", "fullhouse", "cherrypie", "CherryPie", "FrostyFerret"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.fullhouse"],
            launchAgentLabels: []
        ),
        // CoreWarrior — 2024
        SpywareSignature(
            name: "CoreWarrior",
            processNames: ["corewarrior", "CoreWarrior", "core_warrior"],
            bundleIdentifiers: [],
            filePaths: ["/tmp/.corewarrior"],
            launchAgentLabels: []
        ),
        // MacMa (OSX.CDDS) — Chinese-linked, ongoing 2024-2025 updates
        SpywareSignature(
            name: "MacMa (OSX.CDDS)",
            processNames: ["macma", "MacMa", "CDDS", "UserAgent", "AudioComponentRegistrar"],
            bundleIdentifiers: ["com.apple.audiocomponent.registrar", "com.apple.UserAgent"],
            filePaths: [
                "~/Library/UserAgent",
                "~/Library/Preferences/com.apple.UserAgent.plist",
                "/tmp/.macma",
            ],
            launchAgentLabels: ["com.apple.UserAgent"]
        ),
        // XLoader for macOS — infostealer, 2023-2025 active variants
        SpywareSignature(
            name: "XLoader (macOS)",
            processNames: ["xloader", "XLoader", "OfficeNote", "OfficeNote.app"],
            bundleIdentifiers: ["com.microsoft.officenote"],
            filePaths: [
                "/Applications/OfficeNote.app",
                "~/Library/Application Support/.xloader",
            ],
            launchAgentLabels: []
        ),
        // Turtle ransomware — Nov 2023, Go-based, cross-platform
        SpywareSignature(
            name: "Turtle Ransomware",
            processNames: ["turtle", "Turtle", "turtle_ransomware"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.turtle",
                "~/Desktop/READ_ME_TURTLE.txt",
            ],
            launchAgentLabels: []
        ),
        // CrossLock ransomware — 2024, Rust-based
        SpywareSignature(
            name: "CrossLock",
            processNames: ["crosslock", "CrossLock", "cross_lock"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.crosslock",
                "~/Desktop/CrossLock_ReadMe.txt",
            ],
            launchAgentLabels: []
        ),
        // Adload — long-lived adware family with modern 2024-2025 variants (Podcastarter, Mainstresk, etc.)
        // Uses random 8-char lowercase names in ~/Library/Application Support/<name>/<name>
        SpywareSignature(
            name: "Adload",
            processNames: ["Podcastarter", "podcastarter", "Mainstresk", "mainstresk",
                          "CleanParameterD", "cleanparameterd", "Genieo", "genieo",
                          "PremierOpinion", "premieropinion"],
            bundleIdentifiers: ["com.Genieo.Genieo", "com.premieropinion"],
            filePaths: [
                "~/Library/Application Support/Genieo",
                "~/Library/LaunchAgents/com.Genieo.completer.download.plist",
                "~/Library/LaunchAgents/com.Genieo.engine.plist",
            ],
            launchAgentLabels: [
                "com.Genieo.completer.download",
                "com.Genieo.engine",
                "com.Genieo.macextension.client",
            ]
        ),
        // Shlayer — Apple's most detected macOS threat 2020-2024, still active
        SpywareSignature(
            name: "Shlayer",
            processNames: ["shlayer", "Shlayer", "Player.app", "AdobeFlashPlayer",
                          "installer.sh", "installer.dmg"],
            bundleIdentifiers: ["com.adobe.flashplayer.installer.fake"],
            filePaths: [
                "/private/tmp/Player.app",
                "/private/tmp/.shlayer",
                "~/Library/Application Support/.shlayer",
            ],
            launchAgentLabels: []
        ),
        // Fickle Stealer — Rust-based infostealer, 2024
        SpywareSignature(
            name: "Fickle Stealer",
            processNames: ["fickle", "Fickle", "FickleStealer", "fickle_stealer"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.fickle",
                "~/Library/Application Support/.Fickle",
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
        // Observed in 2024-2025 macOS malware masquerading as Apple services
        "com.apple.corekit.agent",              // NimDoor
        "com.apple.macos.softwareupdate",       // LightSpy for macOS
        "com.apple.systempreferences.helper",   // RustBucket JADESNOW/JADENEEDLE variants
        "com.apple.audiocomponent.registrar",   // MacMa / OSX.CDDS
        "com.apple.UserAgent",                  // MacMa
        "com.apple.macshare.plist",             // SpectralBlur
        "com.apple.ChromeUpdateAlert",          // FlexibleFerret
        "com.apple.xcc",                        // JokerSpy
        "com.apple.security.check",             // JokerSpy
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
        // Observed in 2024-2025 malware masquerading as Apple/vendor daemons
        "CoreKitAgent",          // NimDoor — no such Apple daemon exists
        "corekitagent",          // NimDoor (lowercase variant)
        "coredump_helper",       // LightSpy — no such Apple daemon
        "AudioComponentRegistrar", // MacMa — real is coreaudiod / audiocomponentd (helper)
        "macircloader",          // LightSpy loader
        "SafariUpdate",          // FrigidStealer — Safari updates via Software Update, not a standalone
        "MacBrowserUpdate",      // FrigidStealer
        "ChromeUpdateAlert",     // FlexibleFerret — real Chrome is GoogleUpdater/Keystone (no "Alert" suffix)
        "SafariHelper",          // RustBucket — real is com.apple.Safari.SafeBrowsing.Service
        "VisualStudioUpdater",   // RustDoor — real Microsoft VS auto-updates in-app
        "zshrc_updater",         // RustDoor — nothing legitimately named this
        "IphoneInternalService", // mSpy — not a real service
        "GrowthProxy",           // BlueNoroff HiddenRisk masquerade
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
