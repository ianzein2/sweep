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
        // 2024-2026 macOS malware families
        // "Contagious Interview" DPRK campaign — fake job offers target devs with malicious
        // npm packages and interview apps that drop BeaverTail, InvisibleFerret, and the
        // FERRET family (FROSTYFERRET, FRIENDLYFERRET, MULTIPEEK, etc.).
        SpywareSignature(
            name: "BeaverTail",
            processNames: ["BeaverTail", "beavertail", "pw.js", "main99"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.beavertail",
                "~/Library/Application Support/.beavertail",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["InvisibleFerret", "invisibleferret", "ordinaryMondogdb", "ordinaryMongods"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.ssl",
                "~/.ssl",
                "~/Library/Application Support/.n2",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FROSTYFERRET (Ferret family)",
            processNames: ["FROSTYFERRET", "FROSTYFERRET_UI", "ChromeUpdater", "chromeupdate",
                           "CameraAccess", "chromeupdate_ua"],
            bundleIdentifiers: ["com.google.chromeupdater"],
            filePaths: [
                "/private/tmp/.chromeupdate",
                "~/Library/Application Support/.ChromeUpdate",
            ],
            launchAgentLabels: ["com.google.chromeupdater", "com.google.chromeupdate"]
        ),
        SpywareSignature(
            name: "FRIENDLYFERRET (Ferret family)",
            processNames: ["FRIENDLYFERRET", "FRIENDLYFERRET_SECD", "secd_agent", "securityd_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.secd",
                "/private/var/tmp/.secd",
            ],
            launchAgentLabels: ["com.apple.secd.helper"]
        ),
        SpywareSignature(
            name: "MULTIPEEK (Ferret family)",
            processNames: ["MULTIPEEK", "multipeek", "videocallservice", "VirtualCam"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.multipeek"],
            launchAgentLabels: []
        ),
        // RustDoor / ThiefBucket (Nov 2023, active through 2024-2025) — Rust-based backdoor
        // often delivered as fake Visual Studio updates or crypto trading apps.
        SpywareSignature(
            name: "RustDoor",
            processNames: ["RustDoor", "rustdoor", "mypass", "mypass_helper",
                           "zshenv_helper", "zshrc_helper", "VisualStudioUpdater"],
            bundleIdentifiers: ["com.microsoft.VisualStudioUpdater"],
            filePaths: [
                "/private/tmp/.test",
                "~/Library/Application Support/.rustdoor",
                "~/.systemd",
                "/Users/Shared/.rustdoor",
            ],
            launchAgentLabels: ["com.apple.systemd", "com.microsoft.visualstudioupdater"]
        ),
        // Koi Stealer / NimDoor (Lazarus, 2024-2025) — Nim-compiled dropper that injects
        // an AppleScript payload chain and targets macOS crypto and messaging clients.
        SpywareSignature(
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "installer_helper", "GoogleCrashHelper",
                           "trojanized_zoom"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/Google/.helper",
            ],
            launchAgentLabels: ["com.google.crashhelper"]
        ),
        SpywareSignature(
            name: "Koi Stealer",
            processNames: ["KoiStealer", "koistealer", "koi_agent"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.koi", "~/Library/Application Support/.koi"],
            launchAgentLabels: []
        ),
        // TodoSwift / SwiftSpy (Lazarus variant, 2024) — Swift-based loader disguised
        // as a to-do list app, talks to attacker-controlled GitHub repos for payloads.
        SpywareSignature(
            name: "TodoSwift",
            processNames: ["TodoSwift", "todoswift", "SwiftUpdater", "swiftupdater"],
            bundleIdentifiers: ["com.todoswift.app", "com.swiftupdater.helper"],
            filePaths: ["~/Library/Application Support/.todoswift"],
            launchAgentLabels: ["com.apple.swiftupdater"]
        ),
        // HZ RAT (macOS variant, 2024) — ported from Windows, primarily targets WeChat
        // and DingTalk on Macs used by Chinese-speaking crypto and finance workers.
        SpywareSignature(
            name: "HZ RAT",
            processNames: ["HZ", "HZRat", "hz_rat", "rat_macos", "OpenVPNConnect_helper"],
            bundleIdentifiers: ["com.hz.rat", "com.openvpn.connecthelper"],
            filePaths: [
                "~/Library/Application Support/.hzrat",
                "/private/tmp/.hz",
            ],
            launchAgentLabels: ["com.openvpn.connect.helper"]
        ),
        // NotLockBit (Oct 2024) — first real macOS ransomware family after ThiefQuest,
        // Go-based, exfiltrates data to S3 then encrypts with AES + RSA.
        SpywareSignature(
            name: "NotLockBit (macOS ransomware)",
            processNames: ["NotLockBit", "notlockbit", "lockbit_mac", "mac_ransom"],
            bundleIdentifiers: ["com.notlockbit.payload"],
            filePaths: [
                "/private/tmp/.notlockbit",
                "~/Library/Application Support/.lockbit",
            ],
            launchAgentLabels: ["com.lockbit.agent"]
        ),
        // EvilQuest / ThiefQuest — ransomware + infostealer hybrid, still in the wild.
        SpywareSignature(
            name: "EvilQuest / ThiefQuest",
            processNames: ["EvilQuest", "thiefquest", "mixednkey", "toolroomd",
                           "com.apple.questd", "patch", "CrashReporter.tool"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/AppQuest",
                "/Library/AppQuest",
                "~/Library/mixednkey",
            ],
            launchAgentLabels: ["com.apple.questd", "com.apple.tooloom"]
        ),
        // LightSpy (macOS 2024) — modular implant first seen on iOS, ported to macOS
        // via watering-hole attacks against Hong Kong journalists and activists.
        SpywareSignature(
            name: "LightSpy (macOS)",
            processNames: ["LightSpy", "lightspy", "macload", "F_Warehouse",
                           "MacPluginsLoader", "irc_loader"],
            bundleIdentifiers: ["com.apple.lightspy", "com.light.spy"],
            filePaths: [
                "/private/tmp/.lightspy",
                "~/Library/Application Support/.lightspy",
            ],
            launchAgentLabels: []
        ),
        // RustyAttr (Nov 2024) — stores the actual malware payload inside extended
        // file attributes (xattr) to evade static scanners that only read file contents.
        SpywareSignature(
            name: "RustyAttr",
            processNames: ["RustyAttr", "rustyattr", "xattr_loader"],
            bundleIdentifiers: ["com.rusty.attr", "io.nwjs.app"],
            filePaths: ["/private/tmp/.rustyattr"],
            launchAgentLabels: []
        ),
        // XLoader (formerly FormBook) macOS port — commodity infostealer leased as MaaS.
        SpywareSignature(
            name: "XLoader (macOS)",
            processNames: ["XLoader", "xloader", "OfficeUpdate", "office_update"],
            bundleIdentifiers: ["com.microsoft.officeupdater"],
            filePaths: [
                "/private/tmp/.xloader",
                "~/Library/Application Support/.xloader",
            ],
            launchAgentLabels: ["com.microsoft.officeupdater"]
        ),
        // Shlayer / Bundlore — historically the top macOS adware loader, often drops
        // secondary stealers. Still widely distributed via fake Flash/codec updates in 2024.
        SpywareSignature(
            name: "Shlayer / Bundlore",
            processNames: ["Shlayer", "shlayer", "Bundlore", "bundlore", "MacSearch",
                           "Mughthesec", "Advanced Mac Cleaner", "MyCouponsmart"],
            bundleIdentifiers: ["com.Shlayer", "com.bundlore.installer"],
            filePaths: [
                "/private/tmp/.shlayer",
                "~/Library/Application Support/.bundlore",
            ],
            launchAgentLabels: ["com.shlayer.agent", "com.bundlore.agent"]
        ),
        // CloudChat (2024) — fake chat client delivered to targets in South Asia,
        // with backdoor and screen-capture capabilities.
        SpywareSignature(
            name: "CloudChat",
            processNames: ["CloudChat", "cloudchat", "CloudChatHelper"],
            bundleIdentifiers: ["com.cloudchat.mac", "com.cloudchat.helper"],
            filePaths: ["~/Library/Application Support/.CloudChat"],
            launchAgentLabels: ["com.cloudchat.helper"]
        ),
        // Vortax (Jun 2024) — Rhadamanthys-adjacent macOS stealer distributed as a fake
        // video-conferencing app on X and crypto Telegram channels.
        SpywareSignature(
            name: "Vortax",
            processNames: ["Vortax", "vortax", "VortaxMeeting", "VortaxHelper"],
            bundleIdentifiers: ["com.vortax.app", "com.vortax.helper"],
            filePaths: ["/private/tmp/.vortax", "~/Library/Application Support/.Vortax"],
            launchAgentLabels: ["com.vortax.helper"]
        ),
        // DeceptiveDeveloper / ClickFix (2024-2025) — social-engineered fake "fix"
        // pages that trick users into pasting malicious curl|bash commands in Terminal.
        SpywareSignature(
            name: "ClickFix loader",
            processNames: ["clickfix", "clickfix_mac", "update_terminal"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.clickfix", "~/Library/Application Support/.clickfix"],
            launchAgentLabels: []
        ),
        // Lumma Stealer (macOS port spotted 2025) — major Windows stealer with a Mach-O
        // build that targets browser logins and crypto wallets.
        SpywareSignature(
            name: "Lumma Stealer (macOS)",
            processNames: ["Lumma", "lumma", "lummac", "lummastealer"],
            bundleIdentifiers: ["com.lumma.stealer"],
            filePaths: ["/private/tmp/.lumma", "~/Library/Application Support/.lumma"],
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
