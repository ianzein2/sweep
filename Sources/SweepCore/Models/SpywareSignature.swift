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
        // DPRK "Contagious Interview" campaign (Lazarus / BlueNoroff, 2024-2025) —
        // delivered via fake job interviews and trojanized npm packages.
        SpywareSignature(
            name: "BeaverTail",
            processNames: ["BeaverTail", "beavertail", "p.js", "n2.js"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.npl",
                "/private/tmp/.pyp",
                "~/Library/Application Support/.beavertail",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["InvisibleFerret", "invisibleferret", "pay.py", "bow.py"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.n2",
                "~/Library/Application Support/.invisible",
                "/private/tmp/mp.py",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OtterCookie",
            processNames: ["OtterCookie", "ottercookie", "otter_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.ottercookie",
                "~/Library/Application Support/.otter",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FlexibleFerret",
            processNames: ["FlexibleFerret", "flexibleferret", "ChromeUpdate", "FrostyFerret"],
            bundleIdentifiers: ["com.zoom.zoomus.helper", "com.zoom.us.installer"],
            filePaths: [
                "/private/tmp/.flexibleferret",
                "~/Library/Application Support/.FrostyFerret",
                "~/Library/Caches/com.apple.helpd/.chromeupdate",
            ],
            launchAgentLabels: ["com.zoom.installer"]
        ),
        // BlueNoroff macOS toolset (2024-2025)
        SpywareSignature(
            name: "TodoSwift",
            processNames: ["TodoSwift", "todoswift", "todo_dropper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: []
        ),
        // NimDoor (BlueNoroff, April 2025) — Nim-language backdoor distributed via fake Zoom updates.
        SpywareSignature(
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "GoogIeHelper", "CoreKitAgent", "trojan_nim"],
            bundleIdentifiers: ["com.google.googIe.helper"],  // Note: capital I instead of l
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/Application Support/.GoogIe",
                "~/Library/LaunchAgents/com.google.googIe.plist",
            ],
            launchAgentLabels: ["com.google.googIe.helper"]
        ),
        // HZ Rat (China-aligned, mid-2024) — collects WeChat / DingTalk data on macOS.
        SpywareSignature(
            name: "HZ Rat",
            processNames: ["HZRat", "hzrat", "OpenVPNConnect", "openvpnchk"],
            bundleIdentifiers: ["com.openvpn.OpenVPN-Connect"],  // imposter
            filePaths: [
                "~/Library/Application Support/.hzrat",
                "/private/tmp/.openvpnchk",
            ],
            launchAgentLabels: ["com.openvpn.connect"]
        ),
        // JaskaGO (Go-based infostealer, late 2023 / 2024) — distributed via cracked installers.
        SpywareSignature(
            name: "JaskaGO",
            processNames: ["JaskaGO", "jaskago", "jas_agent"],
            bundleIdentifiers: ["com.jaska.agent"],
            filePaths: [
                "/private/tmp/.jaskago",
                "~/Library/Application Support/.JaskaGO",
            ],
            launchAgentLabels: ["com.jaska.service"]
        ),
        // RustDoor / Trojan.MAC.RustDoor (BlackCat-affiliated, 2024) — Rust backdoor.
        SpywareSignature(
            name: "RustDoor",
            processNames: ["RustDoor", "rustdoor", "VisualStudioUpdater", "zshrc_aliases"],
            bundleIdentifiers: ["com.visualstudio.code.updater"],
            filePaths: [
                "/private/tmp/.rustdoor",
                "~/Library/Application Support/.rustdoor",
                "~/Public/.rustdoor",
                "~/.config/.zshrc_aliases",
            ],
            launchAgentLabels: ["com.visualstudio.code.updater"]
        ),
        // CoreNote / KandyKorn relative (Lazarus, late 2024)
        SpywareSignature(
            name: "CoreNote",
            processNames: ["CoreNote", "corenote", "objc_helper", "core_note"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.corenote",
                "~/Library/Group Containers/.core",
            ],
            launchAgentLabels: []
        ),
        // OSAMiner — long-running AppleScript-based XMRig cryptominer.
        SpywareSignature(
            name: "OSAMiner",
            processNames: ["OSAMiner", "osaminer", "MaintenanceService", "xmrig"],
            bundleIdentifiers: ["com.apple.maintenance.service"],  // imposter
            filePaths: [
                "/Library/Caches/com.apple.audio.driver",
                "~/Library/Caches/com.apple.audio.driver",
                "~/Library/Application Support/.minertools",
            ],
            launchAgentLabels: ["com.apple.maintenance.service", "com.apple.audio.helper"]
        ),
        // AppleProcessHub (early-2024 modular stealer)
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "ProcessHubAgent"],
            bundleIdentifiers: ["com.apple.processhub"],  // imposter
            filePaths: [
                "/private/tmp/.applehub",
                "~/Library/Application Support/.ProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub.agent"]
        ),
        // CherryLoader / SnakeScript (mid-2024) — multi-stage downloader.
        SpywareSignature(
            name: "CherryLoader",
            processNames: ["CherryLoader", "cherryloader", "cherry_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.cherry",
                "~/Library/Application Support/.cherry_loader",
            ],
            launchAgentLabels: ["com.cherry.loader"]
        ),
        // Trojan-Proxy.OSX.Agent (Kaspersky, Dec-2023 / 2024) — distributed in cracked apps.
        // Note: the malware uses "WindowServers" (plural) as an imitation — real Apple process is "WindowServer".
        SpywareSignature(
            name: "Trojan-Proxy.OSX.Agent",
            processNames: ["WindowServers", "proxyhelper"],
            bundleIdentifiers: ["com.4starsoft.windowservers"],
            filePaths: [
                "/Library/Application Support/com.apple.WindowServer.plist",  // dropped plist using fake Apple label
            ],
            launchAgentLabels: ["GoogleHelperUpdater"]
        ),
        // AdLoad — long-running macOS adware family with many drop names (Apple XProtect-flagged).
        SpywareSignature(
            name: "AdLoad",
            processNames: [
                "PracticalCommander", "ElegantArchive", "ProductiveAnalysis",
                "AnalyzerExtensionHost", "SkilledObjectAgent", "RotationalAxisAgent",
                "QualityPlaceSearch", "ActivityElementSkill",
            ],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.PracticalCommander",
                "/Library/Application Support/com.PracticalCommander",
            ],
            launchAgentLabels: []
        ),
        // Pirrit / Bundlore — historical but still widely active adware/spyware hybrid.
        SpywareSignature(
            name: "Pirrit / Bundlore",
            processNames: ["pirrit", "bundlore", "InstallMac", "MyShopcoupon", "GenieoUpdater"],
            bundleIdentifiers: ["com.genieoinnovation.macextension", "com.genieo.completer"],
            filePaths: [
                "~/Library/Application Support/Genieo",
                "~/Library/Application Support/InstallMac",
                "~/Library/LaunchAgents/com.genieoinnovation.macextension.plist",
            ],
            launchAgentLabels: ["com.genieoinnovation.macextension", "com.genieo.completer.update"]
        ),
        // CrossBarking (Squarex, Oct-2024) — Arc browser extension exploiting boost feature.
        SpywareSignature(
            name: "CrossBarking",
            processNames: ["CrossBarking", "crossbarking", "arc_boost"],
            bundleIdentifiers: ["company.thebrowser.Browser.boost"],
            filePaths: [
                "~/Library/Application Support/Arc/User Data/.crossbarking",
            ],
            launchAgentLabels: []
        ),
        // OSX.PuzzleMaker / new infostealer chains (early 2025) — credential harvester.
        SpywareSignature(
            name: "OSX.PuzzleMaker",
            processNames: ["PuzzleMaker", "puzzlemaker", "puzzle_helper"],
            bundleIdentifiers: ["com.puzzlemaker.helper"],
            filePaths: [
                "/private/tmp/.puzzle",
                "~/Library/Application Support/.PuzzleMaker",
            ],
            launchAgentLabels: ["com.puzzlemaker.service"]
        ),
        // FrigidStealer (mid-2024) — JavaScript-staged macOS stealer via fake browser-update lures.
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "FrigidUpdate"],
            bundleIdentifiers: ["com.adobe.flashplayer.frigid"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
            ],
            launchAgentLabels: ["com.adobe.flash.update"]
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
        // Observed in 2024-2025 droppers
        "com.apple.maintenance.service",
        "com.apple.audio.helper",
        "com.apple.processhub",
        "com.apple.helpd.update",
        "com.apple.systempreferences.helper",
        "com.apple.protectedcloudstorage.daemon",
    ]

    /// Brand bundle-ID patterns impersonating well-known vendors.
    /// Real vendors don't sit in user-writable LaunchAgent paths with these names.
    public static let fakeBrandBundlePatterns: [String] = [
        "com.google.googIe.helper",         // capital I instead of l
        "com.google.chromeupdate.helper",   // real ID is com.google.keystone
        "com.zoom.zoomus.helper",            // real ID is us.zoom.xos
        "com.zoom.us.installer",
        "com.adobe.flashplayer.frigid",     // Flash Player is dead — any new entry is malicious
        "com.adobe.flash.update",
        "com.visualstudio.code.updater",    // VSCode auto-updates internally, not via separate plist
        "com.openvpn.OpenVPN-Connect",
        "com.4starsoft.windowservers",      // sounds-like-Apple imposter
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

    /// Checks if a bundle ID is impersonating a well-known non-Apple vendor.
    /// Catches mid-2024+ droppers that hide as "Google Helper", "Zoom Installer", etc.
    public static func isFakeBrandBundleId(_ bundleId: String) -> Bool {
        if fakeBrandBundlePatterns.contains(bundleId) { return true }

        // Per-segment look-alike check (so we don't false-positive on real Apple IDs that
        // legitimately contain capital I, like ".IconSizeService"). A segment whose
        // visually-normalized form equals a vendor name — but whose plain-lowercased form
        // doesn't — is a confusable.
        let vendors: Set<String> = ["google", "apple", "microsoft", "amazon", "zoom"]
        for seg in bundleId.split(separator: ".") {
            let plain = String(seg).lowercased()
            if vendors.contains(plain) { continue }  // genuine segment
            let normalized = plain
                .replacingOccurrences(of: "0", with: "o")
                .replacingOccurrences(of: "1", with: "l")
                .replacingOccurrences(of: "i", with: "l")  // catches googIe-style after lowercase
            if vendors.contains(normalized) && plain != normalized {
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
