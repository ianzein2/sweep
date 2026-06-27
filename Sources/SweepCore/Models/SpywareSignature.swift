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
        // 2025-2026 macOS threats — DPRK / Lazarus-linked
        SpywareSignature(
            name: "NimDoor",
            processNames: ["nimdoor", "NimDoor", "Zoom_Update", "zoom_sdk_helper",
                           "Telegram2", "Notion_Helper", "googlechrome_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.nimdoor",
                "~/Library/Application Support/.nimdoor",
                "~/Library/Trial/coral",
                "~/.zoom_sdk_helper",
            ],
            launchAgentLabels: ["com.zoom.update.agent", "com.googlechrome.helper"]
        ),
        SpywareSignature(
            name: "BeaverTail",
            processNames: ["BeaverTail", "beavertail", "p.js", "p2.js"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/p2.js",
                "/tmp/p.js",
                "~/Library/Application Support/.n2",
                "~/Library/Caches/.nca",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["InvisibleFerret", "invisibleferret", "pyp", "main.py",
                           "_pdf", "anyfile"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.npl",
                "~/.n2",
                "~/Library/Application Support/.invferret",
                "/private/tmp/.invferret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OtterCookie",
            processNames: ["OtterCookie", "ottercookie", "otter_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.ottercookie",
                "/private/tmp/.ottercookie",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "TodoSwift",
            processNames: ["TodoSwift", "todoswift", "todo_helper"],
            bundleIdentifiers: ["com.todoapp.swift"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: ["com.todoapp.swift"]
        ),
        SpywareSignature(
            name: "RustBucket v2 / KandyKorn v2",
            processNames: ["rustbucket2", "kandykorn2", "SafariUpdate", "SafariHelper2",
                           "BackgroundService"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.rustbucket2",
                "~/Library/Metadata/.system_update2",
            ],
            launchAgentLabels: ["com.apple.safariupdate", "com.apple.backgroundservice"]
        ),
        SpywareSignature(
            name: "PondRAT / POOLRAT",
            processNames: ["PondRAT", "pondrat", "POOLRAT", "poolrat", "node-pre-gyp",
                           "fccore", "_xpcservice"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.pondrat",
                "/Library/.poolrat",
                "~/Library/Application Support/.pondrat",
            ],
            launchAgentLabels: ["com.apple.xpcservice", "com.apple.fccore"]
        ),
        SpywareSignature(
            name: "ZuRu Backdoor",
            processNames: ["zuru", "ZuRu", "iTermService", "iterm_helper",
                           "GoogleHelperUpdater", "MicrosoftHelperUpdater"],
            bundleIdentifiers: ["com.iterm.helper", "com.googlechrome.helperupdater"],
            filePaths: [
                "/tmp/.test",
                "/tmp/GoogleUpdate",
                "/private/var/tmp/.zuru",
                "/Applications/iTerm.app/Contents/Frameworks/libcrypto.2.dylib",
            ],
            launchAgentLabels: ["com.iterm.helper", "com.googlechrome.helperupdater"]
        ),
        SpywareSignature(
            name: "HZ RAT",
            processNames: ["HZ", "hzrat", "hz_agent", "DingTalkHelper",
                           "WeChatHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.hzrat",
                "/private/tmp/.hzrat",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "macOS.RustDoor / ThiefBucket",
            processNames: ["RustDoor", "rustdoor", "ThiefBucket", "thiefbucket",
                           "VisualStudioUpdater", "vscode_updater"],
            bundleIdentifiers: ["com.visualstudio.updater"],
            filePaths: [
                "~/Public/.test",
                "/private/tmp/.rustdoor",
                "/Users/Shared/.rustdoor",
            ],
            launchAgentLabels: ["com.visualstudio.updater"]
        ),
        SpywareSignature(
            name: "LightSpy macOS / Macma",
            processNames: ["LightSpy", "lightspy", "Macma", "macma",
                           "WindowServerUpdate", "Updated"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.lightspy",
                "~/Library/Application Support/.macma",
                "/Library/PrivilegedHelperTools/.macma",
            ],
            launchAgentLabels: ["com.apple.windowserverupdate"]
        ),
        SpywareSignature(
            name: "BadCandy / SaltedRibbon",
            processNames: ["BadCandy", "badcandy", "SaltedRibbon", "saltedribbon"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.badcandy",
                "~/Library/Application Support/.saltedribbon",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "HellRAT",
            processNames: ["HellRAT", "hellrat", "hell_agent"],
            bundleIdentifiers: ["com.hellrat.agent"],
            filePaths: [
                "/private/tmp/.hellrat",
                "~/Library/Application Support/.HellRAT",
            ],
            launchAgentLabels: ["com.hellrat.service"]
        ),
        // 2025-2026 infostealers
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "frigid", "FrostUpdate",
                           "SafariUpdater", "WeChatBuilder"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
                "~/Library/Caches/.frigid",
            ],
            launchAgentLabels: ["com.frigid.agent", "com.safari.updater"]
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "aphub",
                           "applescript_hub"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "/private/tmp/.aphub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub.agent"]
        ),
        SpywareSignature(
            name: "SparkKitty",
            processNames: ["SparkKitty", "sparkkitty", "spark_kitty"],
            bundleIdentifiers: ["com.spark.kitty", "com.coinwallet.helper"],
            filePaths: [
                "/private/tmp/.sparkkitty",
                "~/Library/Application Support/.SparkKitty",
            ],
            launchAgentLabels: ["com.spark.kitty"]
        ),
        SpywareSignature(
            name: "SparkCat",
            processNames: ["SparkCat", "sparkcat", "spark_cat"],
            bundleIdentifiers: ["com.spark.cat"],
            filePaths: [
                "/private/tmp/.sparkcat",
                "~/Library/Application Support/.SparkCat",
            ],
            launchAgentLabels: ["com.spark.cat"]
        ),
        SpywareSignature(
            name: "NodeStealer macOS",
            processNames: ["NodeStealer", "nodestealer", "node_stealer", "fb_helper"],
            bundleIdentifiers: ["com.nodestealer.agent"],
            filePaths: [
                "/private/tmp/.nodestealer",
                "~/Library/Application Support/.NodeStealer",
            ],
            launchAgentLabels: ["com.nodestealer.service"]
        ),
        SpywareSignature(
            name: "Shlayer",
            processNames: ["Shlayer", "shlayer", "Player", "FlashPlayer",
                           "MacUpdater", "AdobeFlashUpdater"],
            bundleIdentifiers: ["com.adobe.flash.updater", "com.shlayer.installer"],
            filePaths: [
                "~/Library/Application Support/.shlayer",
                "/private/tmp/.shlayer",
                "/Applications/.FlashPlayer.app",
            ],
            launchAgentLabels: ["com.adobe.flash.updater"]
        ),
        SpywareSignature(
            name: "Bundlore",
            processNames: ["Bundlore", "bundlore", "InstallMac", "MacKeeper",
                           "AdvancedMacCleaner", "MacBooster"],
            bundleIdentifiers: ["com.bundlore.installer", "com.advancedmaccleaner.app"],
            filePaths: [
                "~/Library/Application Support/.bundlore",
                "/Applications/.AdvancedMacCleaner.app",
            ],
            launchAgentLabels: ["com.bundlore.service", "com.advancedmaccleaner.helper"]
        ),
        SpywareSignature(
            name: "Pirrit",
            processNames: ["Pirrit", "pirrit", "MyShopcoupon", "WebMail",
                           "OperatorMac", "FeedTheCat"],
            bundleIdentifiers: ["com.pirrit.app"],
            filePaths: [
                "~/Library/Application Support/.pirrit",
                "/Library/Application Support/.pirrit",
            ],
            launchAgentLabels: ["com.pirrit.service", "com.operatormac.daemon"]
        ),
        SpywareSignature(
            name: "Snake Keylogger macOS",
            processNames: ["snake_keylogger", "SnakeKL", "snakekeylogger",
                           "snake_helper"],
            bundleIdentifiers: ["com.snake.keylogger"],
            filePaths: [
                "~/Library/Application Support/.snake",
                "/private/tmp/.snake_kl",
            ],
            launchAgentLabels: ["com.snake.keylogger"]
        ),
        SpywareSignature(
            name: "StealC macOS",
            processNames: ["StealC", "stealc", "stealc_mac"],
            bundleIdentifiers: ["com.stealc.agent"],
            filePaths: [
                "/private/tmp/.stealc",
                "~/Library/Application Support/.StealC",
            ],
            launchAgentLabels: ["com.stealc.service"]
        ),
        SpywareSignature(
            name: "DigiStealer",
            processNames: ["DigiStealer", "digistealer", "dgs_agent"],
            bundleIdentifiers: ["com.digi.stealer"],
            filePaths: [
                "/private/tmp/.digistealer",
                "~/Library/Application Support/.DigiStealer",
            ],
            launchAgentLabels: ["com.digi.stealer"]
        ),
        SpywareSignature(
            name: "TriangleDB / Operation Triangulation",
            processNames: ["BackupAgent", "TriangleDB", "triangledb",
                           "popup", "popupd"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.triangledb",
                "~/Library/Application Support/.tdb",
            ],
            launchAgentLabels: ["com.apple.backupagent.helper"]
        ),
        SpywareSignature(
            name: "MoonShine macOS",
            processNames: ["MoonShine", "moonshine", "moon_helper"],
            bundleIdentifiers: ["com.moonshine.agent"],
            filePaths: [
                "/private/tmp/.moonshine",
                "~/Library/Application Support/.MoonShine",
            ],
            launchAgentLabels: ["com.moonshine.service"]
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
        // 2024-2026 mimicry patterns observed in active campaigns
        "com.apple.safariupdate",
        "com.apple.windowserverupdate",
        "com.apple.backgroundservice",
        "com.apple.backupagent.helper",
        "com.apple.xpcservice",            // ZuRu/PondRAT pattern; real ID is com.apple.xpc.<name>
        "com.apple.fccore",
        "com.apple.processhub.agent",
        "com.apple.icloud.helper",
        "com.apple.system.helper",
        "com.apple.systemupdate.helper",
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
        // 2024-2026 stealer mimicry patterns
        "WindowServerUpdate",    // Used by Macma / LightSpy
        "SafariUpdate",          // Used by RustBucket v2
        "SafariUpdater",         // FrigidStealer pattern
        "Zoom_Update",           // NimDoor pattern
        "zoom_sdk_helper",       // NimDoor pattern
        "GoogleHelperUpdater",   // ZuRu pattern
        "MicrosoftHelperUpdater",// ZuRu pattern
        "iTermService",          // ZuRu pattern
        "VisualStudioUpdater",   // RustDoor/ThiefBucket pattern
        "vscode_updater",        // RustDoor/ThiefBucket pattern
        "AdobeFlashUpdater",     // Shlayer pattern (Flash is dead — any such process is malware)
        "FlashPlayer",           // Shlayer pattern
        "Player",                // Shlayer pattern when unsigned
        "BackgroundService",     // RustBucket v2
        "BackupAgent",           // Operation Triangulation (TriangleDB)
        "fb_helper",             // NodeStealer pattern
        "DingTalkHelper",        // HZ RAT pattern
        "WeChatHelper",          // HZ RAT pattern (real WeChat doesn't ship this)
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
