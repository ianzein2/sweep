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
        // 2024-2025 macOS threats
        SpywareSignature(
            name: "HZ RAT",
            processNames: ["hzrat", "hz_rat", "HzClient", "OpenVPNConnect"],
            bundleIdentifiers: ["com.openvpnconnect.helper"],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.hz",
            ],
            launchAgentLabels: ["com.openvpn.connect.helper"]
        ),
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid", "fr_helper", "InstallerHelper"],
            bundleIdentifiers: ["com.frigid.helper", "com.frigidstealer.agent"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.Frigid",
            ],
            launchAgentLabels: ["com.frigid.helper"]
        ),
        SpywareSignature(
            name: "BeaverTail (Lazarus)",
            processNames: ["beavertail", "BeaverTail", "p.js", "n2.js", "node_modules_handler"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.npl",
                "~/.n2/pay",
                "~/.tmpData",
                "/private/tmp/p2",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret (Lazarus)",
            processNames: ["invisibleferret", "ferret", "MicrosoftAutoUpdater", "pyp"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.npl",
                "~/.n2",
                "~/.bd",
                "/private/tmp/.pyp",
            ],
            launchAgentLabels: ["com.microsoft.autoupdater2"]
        ),
        SpywareSignature(
            name: "TodoSwift (DPRK)",
            processNames: ["TodoSwift", "todoswift", "todo_helper"],
            bundleIdentifiers: ["com.todoswift.app"],
            filePaths: ["/private/tmp/.todoswift"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "HiddenRisk (DPRK)",
            processNames: ["growth", "HiddenRisk", "macroshell", "ProcessRequest"],
            bundleIdentifiers: ["com.growthproject.agent"],
            filePaths: [
                "~/Library/Group Containers/.growth",
                "/private/tmp/.hiddenrisk",
            ],
            launchAgentLabels: ["com.growth.update"]
        ),
        SpywareSignature(
            name: "NimDoor (DPRK)",
            processNames: ["nimdoor", "NimDoor", "googlechromehelper", "GoogleVPNHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.nim",
                "~/Library/LaunchAgents/com.google.chrome.helper.plist",
            ],
            launchAgentLabels: ["com.google.chrome.helper", "com.google.vpn.helper"]
        ),
        SpywareSignature(
            name: "PondRAT (BlueNoroff)",
            processNames: ["pondrat", "PondRAT", "pyjpegg", "node-pyjp"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.pondrat", "~/.pyjp"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "aphub", "applehub"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "/private/tmp/.aphub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub"]
        ),
        SpywareSignature(
            name: "TinyFUD",
            processNames: ["tinyfud", "TinyFUD", "tfud_helper"],
            bundleIdentifiers: ["com.tinyfud.agent"],
            filePaths: ["/private/tmp/.tinyfud"],
            launchAgentLabels: ["com.tinyfud.service"]
        ),
        SpywareSignature(
            name: "macOS.NotLockBit",
            processNames: ["NotLockBit", "notlockbit", "NLBHelper"],
            bundleIdentifiers: ["com.notlockbit.ransom"],
            filePaths: [
                "/private/tmp/.notlockbit",
                "~/Library/Application Support/.NLB",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "SparkRAT",
            processNames: ["sparkrat", "SparkRAT", "sparkclient", "spark_client"],
            bundleIdentifiers: ["com.sparkrat.client"],
            filePaths: [
                "/private/tmp/.spark",
                "~/Library/Application Support/.SparkRAT",
            ],
            launchAgentLabels: ["com.sparkrat.client"]
        ),
        SpywareSignature(
            name: "MacMa (APT-Q-12)",
            processNames: ["macma", "MacMa", "UserAgent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.macma",
                "~/Library/Preferences/.UserAgent",
            ],
            launchAgentLabels: ["com.UserAgent.va"]
        ),
        SpywareSignature(
            name: "AlienFox Stealer",
            processNames: ["alienfox", "AlienFox", "alf_helper"],
            bundleIdentifiers: ["com.alienfox.toolkit"],
            filePaths: ["/private/tmp/.alienfox"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "ReaderUpdate Loader",
            processNames: ["ReaderUpdate", "readerupdate", "ru_helper"],
            bundleIdentifiers: ["com.reader.update", "com.adobe.readerupdate"],
            filePaths: [
                "/private/tmp/.readerupdate",
                "~/Library/Application Support/.ReaderUpdate",
            ],
            launchAgentLabels: ["com.reader.update"]
        ),
        SpywareSignature(
            name: "Crackonosh.macOS",
            processNames: ["crackonosh", "Crackonosh", "winlogui"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.crack", "~/Library/Application Support/.crackon"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "SoulSearcher.mac",
            processNames: ["soulsearcher", "SoulSearcher", "ssearch"],
            bundleIdentifiers: ["com.soulsearcher.agent"],
            filePaths: ["/private/tmp/.soul"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "AMOS (2025 variant)",
            processNames: ["amos2", "AMOS2", "atomicv2", "stealer_helper"],
            bundleIdentifiers: ["com.atomic.helper", "com.amos.helper2"],
            filePaths: [
                "/private/tmp/.amos2",
                "~/Library/Caches/.amos",
            ],
            launchAgentLabels: ["com.atomic.helper"]
        ),
        // Cryptominers — increasingly distributed via cracked apps and fake installers in 2024-2025
        SpywareSignature(
            name: "XMRig (cryptominer)",
            processNames: ["xmrig", "XMRig", "xmrigDaemon", "monerod", "minerd"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.xmrig",
                "/Library/Application Support/.xmrig",
                "~/Library/Application Support/.xmrig",
            ],
            launchAgentLabels: ["com.xmrig.daemon"]
        ),
        SpywareSignature(
            name: "SilverSparrow Miner",
            processNames: ["silversparrow", "ss_helper", "agent.sh"],
            bundleIdentifiers: ["com.silver.sparrow.helper"],
            filePaths: ["/tmp/agent.sh", "~/Library/._insu"],
            launchAgentLabels: ["com.silver.sparrow.agent"]
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
        // 2024-2025 fake-Apple labels used by DPRK / infostealer campaigns
        "com.apple.processhub",
        "com.apple.systempreferences.helper",
        "com.apple.chrome.helper",
        "com.apple.vpn.helper",
        "com.apple.installer.daemon",
        "com.apple.autoupdater2",
        "com.apple.timemachine.helper",
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

    /// Check whether any known-spyware file marker exists on disk. Returns the matching
    /// signature on the first hit so callers can present a single finding.
    public static func findInstalledOnDisk() -> [(signature: SpywareSignature, path: String)] {
        let fm = FileManager.default
        var hits: [(SpywareSignature, String)] = []
        for sig in known {
            for raw in sig.filePaths {
                // Wildcard patterns (e.g. "/private/tmp/AppleScript-*.scpt") need a glob walk.
                if raw.contains("*") {
                    if matchGlob(pattern: raw) { hits.append((sig, raw)); break }
                    continue
                }
                let expanded = expandPath(raw)
                if fm.fileExists(atPath: expanded) {
                    hits.append((sig, expanded))
                    break  // one finding per signature is enough
                }
            }
        }
        return hits
    }

    /// Tiny glob matcher — supports patterns with a single `*` in the basename. Sufficient
    /// for AMOS-style markers like `/private/tmp/AppleScript-*.scpt`. We deliberately don't
    /// pull in a regex engine for this.
    private static func matchGlob(pattern: String) -> Bool {
        let expanded = expandPath(pattern)
        let dir = (expanded as NSString).deletingLastPathComponent
        let basePattern = (expanded as NSString).lastPathComponent
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return false }
        guard let star = basePattern.firstIndex(of: "*") else {
            return entries.contains(basePattern)
        }
        let prefix = String(basePattern[..<star])
        let suffix = String(basePattern[basePattern.index(after: star)...])
        return entries.contains { entry in
            entry.hasPrefix(prefix) && entry.hasSuffix(suffix) && entry.count >= prefix.count + suffix.count
        }
    }
}
