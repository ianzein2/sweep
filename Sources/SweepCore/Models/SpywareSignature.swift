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
        // 2025-2026 macOS threats — DPRK and infostealer families
        // Reported by Objective-See, JAMF, Sentinel One, Volexity, Kandji.
        SpywareSignature(
            // NimDoor: DPRK Nim-language backdoor with signal-handler persistence,
            // installs via a malicious zsh helper. Uses fake "Zoom SDK update" lures.
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "GoogIe", "CoreKitAgent",
                           "InjectWithDyldArm64", "trojan_loader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/Application Support/.NimDoor",
                "~/.zshenv",  // NimDoor's persistence pivot — flagged additionally by shell-config scan
                "/private/tmp/installer.scpt",
            ],
            launchAgentLabels: ["com.google.update.agent"]
        ),
        SpywareSignature(
            // BeaverTail: JS/Node-based stealer dropped during DPRK "Contagious
            // Interview" recruiter scam. Pulled in InvisibleFerret as second stage.
            // We only list specific lure-app names — generic "node_helper" omitted
            // to avoid colliding with legitimate Node.js helpers.
            name: "BeaverTail (Contagious Interview)",
            processNames: ["BeaverTail", "beavertail",
                           "MiroTalk", "FCCCall", "FreeConference"],
            bundleIdentifiers: ["com.mirotalk.helper", "com.freeconference.app"],
            filePaths: [
                "/private/tmp/.npl",
                "~/Library/Application Support/.beaver",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // InvisibleFerret: Python-based DPRK backdoor delivered as second stage
            // by BeaverTail. Uses pip-install lures; persists via cron and zshenv.
            // Generic IOCs ("pay", "ssid") intentionally omitted — they collide with
            // legitimate dev binaries. We rely on file-path and label matches instead.
            name: "InvisibleFerret",
            processNames: ["InvisibleFerret", "invisibleferret"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.n2/pay",
                "~/.npl",
                "~/Library/Application Support/.iferret",
                "/private/tmp/.invisible",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // OtterCookie: DPRK JS/Node stealer, observed late-2024 through 2025.
            // Variants v2/v3 added crypto-wallet scraping and clipboard hijacking.
            name: "OtterCookie",
            processNames: ["OtterCookie", "ottercookie", "ottersvc"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.otter",
                "~/Library/Application Support/.OtterCookie",
            ],
            launchAgentLabels: ["com.otter.service"]
        ),
        SpywareSignature(
            // FrigidStealer: distributed via fake "browser update" SocGholish-style
            // landing pages in 2025. AppleScript-driven keychain/wallet scraper.
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "frigid",
                           "ChromeUpdater", "SafariUpdater"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.Frigid",
            ],
            launchAgentLabels: ["com.frigid.agent"]
        ),
        SpywareSignature(
            // AppleProcessHub Stealer: Feb 2025 stealer that disguised itself as
            // "AppleProcessHub" to look like a system service.
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "AppleProcHub"],
            bundleIdentifiers: ["com.apple.processhub"],  // fake Apple bundle ID
            filePaths: [
                "/private/tmp/.aph",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub.agent"]
        ),
        SpywareSignature(
            // Crystal Stealer (a.k.a. Crystal): 2025 macOS infostealer sold as MaaS,
            // targets browser cookies, Notes.app, Keychain export.
            name: "Crystal Stealer",
            processNames: ["Crystal", "crystal_stealer", "crystalmac"],
            bundleIdentifiers: ["com.crystal.stealer"],
            filePaths: [
                "/private/tmp/.crystal",
                "~/Library/Application Support/.Crystal",
            ],
            launchAgentLabels: ["com.crystal.service"]
        ),
        SpywareSignature(
            // Odyssey Stealer: 2025 Atomic-fork rebranded for crypto wallet draining.
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey_stealer", "odystealer"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        SpywareSignature(
            // TrollStealer: 2024-2025 Korean-language infostealer attributed to
            // Kimsuky / DPRK. Steals keychain, GPG keys, SSH config.
            name: "TrollStealer",
            processNames: ["TrollStealer", "trollstealer", "troll_mac"],
            bundleIdentifiers: ["com.troll.stealer"],
            filePaths: [
                "/private/tmp/.troll",
                "~/Library/Application Support/.TrollStealer",
            ],
            launchAgentLabels: ["com.troll.service"]
        ),
        SpywareSignature(
            // HZ RAT macOS: Tencent QQ-targeting RAT ported from Windows in 2024.
            name: "HZ RAT (macOS)",
            processNames: ["HZRat", "hzrat", "hz_helper", "qqhelper"],
            bundleIdentifiers: ["com.tencent.qqhelper.fake", "com.hzrat.agent"],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.hzrat",
            ],
            launchAgentLabels: ["com.tencent.qq.helper", "com.hzrat.service"]
        ),
        SpywareSignature(
            // NotLockBit: Oct 2024 LockBit-themed Mac ransomware (first
            // cross-platform LockBit variant). Encrypts and exfils to S3.
            name: "NotLockBit",
            processNames: ["NotLockBit", "notlockbit", "lockbit_mac"],
            bundleIdentifiers: ["com.lockbit.mac", "com.notlockbit.agent"],
            filePaths: [
                "/private/tmp/.lockbit",
                "/private/tmp/.notlockbit",
                "~/Library/Application Support/.lockbit",
            ],
            launchAgentLabels: ["com.lockbit.service"]
        ),
        SpywareSignature(
            // PasivRobber: 2025 DPRK-attributed Mac surveillance suite, exfiltrates
            // browser data, iMessage, WeChat. Disguises as "WeChat helper."
            name: "PasivRobber",
            processNames: ["PasivRobber", "pasivrobber", "WeChatHelper",
                           "ChatExtractor"],
            bundleIdentifiers: ["com.pasiv.agent", "com.wechat.helper.fake"],
            filePaths: [
                "/private/tmp/.pasiv",
                "~/Library/Application Support/.PasivRobber",
            ],
            launchAgentLabels: ["com.wechat.helper", "com.pasiv.service"]
        ),
        SpywareSignature(
            // ChillyHell (a.k.a. ChillBacon): 2025 modular backdoor distributed via
            // pirated app installers; persists via login items + zshenv.
            name: "ChillyHell",
            processNames: ["ChillyHell", "chillyhell", "ChillBacon", "chillbacon"],
            bundleIdentifiers: ["com.chilly.hell", "com.chill.bacon"],
            filePaths: [
                "/private/tmp/.chilly",
                "~/Library/Application Support/.ChillyHell",
            ],
            launchAgentLabels: ["com.chilly.service", "com.chillbacon.agent"]
        ),
        SpywareSignature(
            // FullHouse / TouchMove: DPRK 2025 cluster targeting macOS dev machines.
            name: "FullHouse (DPRK)",
            processNames: ["FullHouse", "fullhouse", "TouchMove", "touchmove"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.fullhouse",
                "~/Library/Caches/.touchmove",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Tylocker: 2025 macOS file-locker / wiper using rust-crypto.
            name: "Tylocker",
            processNames: ["Tylocker", "tylocker", "tycrypt"],
            bundleIdentifiers: ["com.tylocker.agent"],
            filePaths: ["/private/tmp/.tylocker"],
            launchAgentLabels: ["com.tylocker.service"]
        ),
        SpywareSignature(
            // GhostStealer: 2025 commodity stealer sold via Telegram, MaaS model.
            name: "GhostStealer",
            processNames: ["GhostStealer", "ghoststealer", "ghost_mac"],
            bundleIdentifiers: ["com.ghost.stealer"],
            filePaths: [
                "/private/tmp/.ghost",
                "~/Library/Application Support/.Ghost",
            ],
            launchAgentLabels: ["com.ghost.service"]
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
        // Observed 2024-2025 fake-Apple bundle IDs
        "com.apple.processhub",        // AppleProcessHub Stealer (2025)
        "com.apple.swcd.agent",        // NimDoor variants
        "com.apple.coregraphics.agent",
        "com.apple.iphone.sync",
        "com.apple.hidd.helper",
        "com.apple.cloudd.sync",
        "com.apple.activitymonitor.helper",
        "com.apple.notificationcenterui.helper",
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
