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
        // 2024-2026 macOS threats
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid", "MacUpdater", "BrowserSafariUpdate"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
                "~/Library/LaunchAgents/com.safari.update.plist",
            ],
            launchAgentLabels: ["com.safari.update", "com.browser.updater"]
        ),
        SpywareSignature(
            name: "HZ RAT (macOS)",
            processNames: ["OpenVPNConnect", "hzhelper", "hzrat", "hz_rat", "DingTalk_helper"],
            bundleIdentifiers: ["com.hz.rat", "com.openvpn.connect.helper"],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.hz",
                "~/Library/LaunchAgents/com.openvpn.client.plist",
            ],
            launchAgentLabels: ["com.openvpn.client", "com.dingtalk.helper"]
        ),
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            processNames: ["BeaverTail", "beavertail", "node_modules_helper", "javascript_obfuscator"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.npl",
                "/private/tmp/.n2",
                "~/.npl",
                "~/Library/Application Support/.beaver",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret (Contagious Interview)",
            processNames: ["InvisibleFerret", "ferret", "pay", "p.py", "pay.py"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.ferret",
                "~/.ssh/.config-ferret",
                "~/Library/Application Support/.ferret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "NimDoor (DPRK)",
            processNames: ["nimdoor", "NimDoor", "GoogleVoiceHelper", "ZoomVideoSDK",
                           "Calendar+SyncHelper", "trojan1_arm64", "trojan2_arm64"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.nimdoor",
                "~/Library/Group Containers/.nimcache",
                "/tmp/.NimDoor",
            ],
            launchAgentLabels: ["com.google.voice.helper", "com.zoom.video.sdk"]
        ),
        SpywareSignature(
            name: "FullHouse.Doored (DPRK)",
            processNames: ["FullHouse", "fullhouse", "doored", "TaurusLauncher"],
            bundleIdentifiers: [],
            filePaths: ["/private/var/tmp/.fullhouse"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "RustyAttr (Lazarus)",
            processNames: ["RustyAttr", "rustyattr", "InternalPDFViewer"],
            bundleIdentifiers: ["com.test.app", "com.internal.pdf.viewer"],
            filePaths: [
                "/private/tmp/.rustyattr",
                "~/Library/Application Support/.rustyattr",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "macOS.MacMa / CDDS",
            processNames: ["MacMa", "macma", "UserAgent", "WindowServer.app", "cdds"],
            bundleIdentifiers: ["com.UserAgent.va"],
            filePaths: [
                "~/Library/Preferences/com.UserAgent.va.plist",
                "~/Library/LaunchAgents/com.UserAgent.va.plist",
                "/Library/LaunchAgents/com.UserAgent.va.plist",
            ],
            launchAgentLabels: ["com.UserAgent.va"]
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "ProcessHub", "AppleHub"],
            bundleIdentifiers: ["com.apple.processhub", "com.apple.process.hub"],
            filePaths: [
                "/private/tmp/.applehub",
                "~/Library/Application Support/.ProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub"]
        ),
        SpywareSignature(
            name: "NotLockBit (macOS ransomware)",
            processNames: ["notlockbit", "NotLockBit", "lockbit_mac", "lb_mac"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.notlockbit",
                "~/Library/Application Support/.notlockbit",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "TodoSwift / Lazarus DPRK",
            processNames: ["TodoSwift", "todoswift", "InvisibleSwift", "FinderSync"],
            bundleIdentifiers: ["com.tools.todoswift"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "macOS.Hyperion (FakeUpdates)",
            processNames: ["hyperion", "Hyperion", "SafariUpdate", "ChromeUpdate"],
            bundleIdentifiers: ["com.hyperion.agent"],
            filePaths: [
                "/private/tmp/.hyperion",
                "~/Library/Application Support/.Hyperion",
            ],
            launchAgentLabels: ["com.safari.softwareupdate", "com.chrome.softwareupdate"]
        ),
        SpywareSignature(
            name: "LightSpy (macOS)",
            processNames: ["lightspy", "LightSpy", "macma_core", "macmaplugin"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.lightspy",
                "~/Library/.lightspy",
                "~/Library/Application Support/.lightspy",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "MoonStone Sleet (DPRK)",
            processNames: ["moonstonesleet", "MoonStoneSleet", "FudModule", "Detourdog"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.moonstone"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Astaroth Stealer (macOS)",
            processNames: ["astaroth", "Astaroth", "astamac", "astaroth_mac"],
            bundleIdentifiers: ["com.astaroth.stealer"],
            filePaths: [
                "/private/tmp/.astaroth",
                "~/Library/Application Support/.Astaroth",
            ],
            launchAgentLabels: ["com.astaroth.service"]
        ),
        SpywareSignature(
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey_stealer", "odystealer", "OdysseyMacOS"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.service"]
        ),
        SpywareSignature(
            name: "AMOS NextGen (2025)",
            processNames: ["AMOSNext", "amos2", "AppleScript-Helper", "MacOSHelper",
                           "InstallerAssistant"],
            bundleIdentifiers: ["com.amos.next", "com.amos.installer"],
            filePaths: [
                "/private/tmp/.amos2",
                "/private/tmp/AppleScript-*.scpt",
                "/private/tmp/installer-*.sh",
                "~/Library/Application Support/.amos2",
            ],
            launchAgentLabels: ["com.amos.next", "com.amos.persistence"]
        ),
        SpywareSignature(
            name: "Tinexta Spyware",
            processNames: ["tinexta", "Tinexta", "TinextaAgent"],
            bundleIdentifiers: ["com.tinexta.agent"],
            filePaths: ["~/Library/Application Support/.Tinexta"],
            launchAgentLabels: ["com.tinexta.service"]
        ),
        SpywareSignature(
            name: "Bundlore / Adload",
            processNames: ["bundlore", "Bundlore", "Adload", "adload",
                           "SearchPartyHelper", "Player", "MMInstall"],
            bundleIdentifiers: ["com.bundlore.installer", "com.adload.agent"],
            filePaths: [
                "/private/tmp/.bundlore",
                "/Library/Application Support/.Adload",
            ],
            launchAgentLabels: ["com.bundlore.installer", "com.adload.service",
                                "com.SearchPartyHelper.agent"]
        ),
        SpywareSignature(
            name: "ClearFake / ClickFix Loader",
            processNames: ["clearfake", "ClearFake", "clickfix", "ClickFix",
                           "FakeUpdates", "ChromeUpdate.dmg"],
            bundleIdentifiers: ["com.clearfake.loader", "com.fakeupdate.loader"],
            filePaths: [
                "/private/tmp/.clearfake",
                "/private/tmp/.clickfix",
                "/private/tmp/update.sh",
            ],
            launchAgentLabels: ["com.clearfake.loader"]
        ),
        SpywareSignature(
            name: "CookieSpider / SeekStealer",
            processNames: ["seekstealer", "SeekStealer", "CookieSpider",
                           "cookiespider", "cks"],
            bundleIdentifiers: ["com.seek.stealer", "com.cookiespider.agent"],
            filePaths: [
                "/private/tmp/.seek",
                "~/Library/Application Support/.SeekStealer",
                "~/Library/Application Support/.CookieSpider",
            ],
            launchAgentLabels: ["com.seek.stealer", "com.cookiespider.service"]
        ),
        SpywareSignature(
            name: "JaskaGO (macOS)",
            processNames: ["jaskago", "JaskaGO", "GoStealerMac"],
            bundleIdentifiers: ["com.jaska.go"],
            filePaths: [
                "/private/tmp/.jaskago",
                "~/Library/Application Support/.JaskaGO",
            ],
            launchAgentLabels: ["com.jaska.go.service"]
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
        // Observed in 2024-2026 macOS malware persistence plists
        "com.apple.processhub",
        "com.apple.safari.softwareupdate",
        "com.apple.chrome.softwareupdate",
        "com.apple.spotlight.indexer",
        "com.apple.airport.helper",
        "com.apple.cloud.helper",
        "com.apple.notification.helper",
        "com.apple.iphone.helper",
        "com.apple.systempreferences.helper",
        "com.apple.terminalprefs",
        "com.apple.installer.helper",
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
