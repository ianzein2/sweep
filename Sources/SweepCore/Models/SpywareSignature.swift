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
        // Post-2024 macOS threats — publicly documented families we add to catch active campaigns
        SpywareSignature(
            name: "HZ RAT (macOS)",
            // Note: we deliberately skip "OpenVPNConnect" — the legitimate OpenVPN Connect
            // client uses the same process name. Detection is via the specific file paths and
            // launchd label below, which are unique to the HZ RAT install.
            processNames: ["HZBackdoor", "hzrat", "hz_rat"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.OpenVPN",
                "~/Library/Application Support/.HZ",
            ],
            launchAgentLabels: ["com.hz.backdoor"]
        ),
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            processNames: ["BeaverTail", "beavertail", "airport", "payload_native"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/pay",
                "/private/tmp/.npl",
                "~/Library/Preferences/.tmp",
                "/private/var/tmp/pay",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["InvisibleFerret", "invisibleferret", "pd.py", "bow.py"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.p2",
                "/private/tmp/.n2",
                "~/Public/pdown",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "frigid"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
            ],
            launchAgentLabels: ["com.frigid.stealer"]
        ),
        SpywareSignature(
            name: "NimDoor (DPRK)",
            processNames: ["NimDoor", "nimdoor", "zoom_sdk_helper", "GoogIe", "GoogleUpdate"],
            bundleIdentifiers: ["us.zoom.privileged.helper", "com.google.googleupdate"],
            filePaths: [
                "/private/tmp/.nimdoor",
                "/private/var/tmp/.nimdoor",
                "~/Library/Application Support/.nimdoor",
            ],
            launchAgentLabels: ["us.zoom.privileged.helper", "com.google.googleupdate"]
        ),
        SpywareSignature(
            name: "NotLockBit",
            processNames: ["NotLockBit", "notlockbit", "lockbit_go"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/notlockbit",
                "/private/tmp/.lockbit",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "RustyAttr (Lazarus)",
            processNames: ["RustyAttr", "rustyattr", "TestApp"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.rustyattr",
                "~/Library/Application Support/.RustyAttr",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "JokerSpy",
            processNames: ["xcc", "JokerSpy", "jokerspy", "sh.py"],
            bundleIdentifiers: ["com.apple.xcc", "eu.gsingh.xcc"],
            filePaths: [
                "/Users/Shared/xcc",
                "/Users/Shared/AppleAccount.tgz",
                "/Users/Shared/QuickTimeUpdater.app",
                "~/Public/xcc",
            ],
            launchAgentLabels: ["com.apple.xcc.plist"]
        ),
        SpywareSignature(
            name: "FROSTYFERRET / FRIENDLYFERRET (Contagious Interview)",
            processNames: ["FriendlyFerret", "FrostyFerret", "FlexibleFerret", "MultiFerret", "ChromeUpdater"],
            bundleIdentifiers: ["com.apple.helper", "com.google.chrome.updater", "com.zoom.updater"],
            filePaths: [
                "~/Library/LaunchAgents/com.apple.helper.plist",
                "/private/tmp/.ferret",
                "/private/tmp/ferret",
                "/Users/Shared/ChromeUpdate",
            ],
            launchAgentLabels: ["com.apple.helper", "com.google.chrome.updater", "com.zoom.updater"]
        ),
        SpywareSignature(
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey", "OdysseyStealer", "odysseystealer"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.stealer"]
        ),
        SpywareSignature(
            name: "SparkKitty / SparkCat",
            processNames: ["SparkKitty", "sparkkitty", "SparkCat", "sparkcat"],
            bundleIdentifiers: ["com.sparkkitty.agent", "com.sparkcat.agent"],
            filePaths: [
                "/private/tmp/.sparkcat",
                "~/Library/Application Support/.SparkCat",
                "~/Library/Application Support/.SparkKitty",
            ],
            launchAgentLabels: ["com.sparkcat.service", "com.sparkkitty.service"]
        ),
        SpywareSignature(
            name: "Silver Sparrow",
            processNames: ["agent.sh", "AutoUpdater", "silver_sparrow"],
            bundleIdentifiers: ["com.silversparrow.updater"],
            filePaths: [
                "~/Library/._insu",
                "~/Library/Application Support/agent_updater",
                "/tmp/agent.sh",
                "/tmp/version.json",
                "/tmp/version.plist",
            ],
            launchAgentLabels: ["init_agent", "verx_updater", "com.apple.appleaccount.plist"]
        ),
        SpywareSignature(
            name: "CookieMiner",
            processNames: ["CookieMiner", "cookieminer", "xmrig2", "xmrig"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.dscl.dat",
                "~/Library/xmrig",
                "/tmp/upfile",
                "/tmp/upfile.plist",
            ],
            launchAgentLabels: ["com.proxy.initialize"]
        ),
        SpywareSignature(
            name: "OSX.Bundlore",
            processNames: ["Bundlore", "bundlore", "mm-install-macos.sh"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.bundlore",
                "/private/tmp/.bundlore",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OSX.ZuRu",
            processNames: ["libcrypto.2.dylib", "iTerm2.updater", "zuru", "ZuRu"],
            bundleIdentifiers: ["com.iterm2.updater"],
            filePaths: [
                "/private/tmp/.iterm2",
                "~/Library/LaunchAgents/com.iterm2.updater.plist",
                "/Applications/iTerm.app/Contents/Frameworks/libcrypto.2.dylib",
            ],
            launchAgentLabels: ["com.iterm2.updater"]
        ),
        SpywareSignature(
            name: "OceanLotus (APT32)",
            processNames: ["flashupdate", "OceanLotus", "oceanlotus", "mdworker_shared_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/User Pictures/.tmp",
                "~/Library/User Pictures/.hdmi",
                "/private/tmp/.oceanlotus",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Turtle Ransomware",
            processNames: ["turtle", "Turtle", "turtle_encryptor"],
            bundleIdentifiers: ["com.turtle.ransom"],
            filePaths: [
                "/tmp/turtle_run",
                "/private/tmp/.turtle",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "KeySteal / iWebUpdate",
            processNames: ["iWebUpdate", "keysteal", "KeyStealer"],
            bundleIdentifiers: ["com.iwebupdate.agent"],
            filePaths: [
                "~/Library/Application Support/.iWebUpdate",
                "/private/tmp/.keysteal",
            ],
            launchAgentLabels: ["com.iwebupdate.agent"]
        ),
        SpywareSignature(
            name: "AMOS-Anaconda (Atomic 2.0)",
            processNames: ["AMOS-Anaconda", "amos_anaconda", "amos2", "amosgold", "AtomicPro"],
            bundleIdentifiers: ["com.amos.anaconda", "com.atomic.pro"],
            filePaths: [
                "/private/tmp/amos_anaconda",
                "/private/tmp/.amos2",
                "~/Library/Application Support/.AMOS2",
            ],
            launchAgentLabels: ["com.amos.anaconda", "com.atomic.pro"]
        ),
        SpywareSignature(
            name: "CherryPie",
            processNames: ["CherryPie", "cherrypie", "PostgresMacHelper"],
            bundleIdentifiers: ["com.cherrypie.agent"],
            filePaths: [
                "~/Library/Application Support/.CherryPie",
                "/private/tmp/.cherrypie",
            ],
            launchAgentLabels: ["com.postgres.machelper", "com.cherrypie.agent"]
        ),
        SpywareSignature(
            name: "MacMa (CDDS)",
            processNames: ["MacMa", "macma", "com.UserAgent", "UserAgent"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Preferences/UserAgent",
                "~/Library/LaunchAgents/com.UserAgent.va.plist",
                "/private/var/tmp/.macma",
            ],
            launchAgentLabels: ["com.UserAgent.va"]
        ),
        SpywareSignature(
            name: "Realst-2024 (BlockchainAppsDev)",
            processNames: ["BlockchainAppsDev", "chatgptmac", "AppleAccount", "MetaMaskUpdater"],
            bundleIdentifiers: ["com.metamask.updater"],
            filePaths: [
                "/private/tmp/.chatgptmac",
                "~/Library/Application Support/.blockchainappsdev",
            ],
            launchAgentLabels: ["com.metamask.updater"]
        ),
        SpywareSignature(
            name: "PoseidonV2 Loader",
            processNames: ["PoseidonV2", "poseidonv2", "poseidon2_loader"],
            bundleIdentifiers: ["com.poseidon.v2"],
            filePaths: [
                "/private/tmp/.poseidon2",
                "~/Library/Application Support/.PoseidonV2",
            ],
            launchAgentLabels: ["com.poseidon.v2"]
        ),
        SpywareSignature(
            name: "Ledger Live Impersonator",
            processNames: ["LedgerLiveUpdater", "ledger_updater", "LedgerHelperTool"],
            bundleIdentifiers: [
                "com.ledger.updater",
                "com.ledgerlive.helper",
            ],
            filePaths: [
                "~/Library/Application Support/.LedgerLive",
                "/private/tmp/.ledger",
            ],
            launchAgentLabels: ["com.ledger.updater", "com.ledgerlive.helper"]
        ),
        SpywareSignature(
            name: "GoSorry / macOS.SorryStealer",
            processNames: ["gosorry", "SorryStealer", "sorrystealer"],
            bundleIdentifiers: ["com.gosorry.stealer"],
            filePaths: [
                "/private/tmp/.sorry",
                "~/Library/Application Support/.SorryStealer",
            ],
            launchAgentLabels: ["com.gosorry.stealer"]
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
        // Post-2024 observed abuses — DPRK/APT campaigns favor these fakes
        "com.apple.helper",              // FROSTYFERRET / FRIENDLYFERRET (2025)
        "com.apple.systempreferences.helper",  // RustBucket
        "com.apple.xcc",                 // JokerSpy
        "com.apple.UserAgent",           // MacMa / CDDS
        "com.apple.finder.helper",       // Common APT fake
        "com.apple.telemetry",           // No such Apple service
        "com.apple.systemservice",       // No such Apple service
        "com.apple.dockutil",            // No such Apple service
        "com.apple.diagnostics.agent",   // No such Apple service
        "com.apple.appstore.updater",    // No such Apple service
        "com.apple.spotlight.agent",     // Real is mds/mdworker, no .agent
        "com.apple.airportd.helper",     // No such Apple service
        "com.apple.rapportd.updater",    // No such Apple service
        "com.apple.crashreporter.plist", // Real is com.apple.ReportCrash
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
        // Names observed in 2024-2025 DPRK / infostealer campaigns
        "GoogIe",                // BeaverTail — capital I, not lowercase l
        "GoogleUpdater",         // Google's real updater is GoogleSoftwareUpdate; used by NimDoor
        "ChromeUpdater",         // Real: GoogleUpdater / Google Chrome; used by Contagious Interview
        "ChromeHelper",          // Real: Google Chrome Helper (with space)
        "SafariHelper",          // Real: com.apple.Safari services, no plain SafariHelper
        "FinderTools",           // No such Apple binary — KandyKorn
        "mdworker_shared_helper",// Real: mdworker_shared; OceanLotus variant
        "com.UserAgent",         // MacMa
        "usermanagerd_helper",   // Real: usermanagerd
        "TrustAgentHelper",      // Not real
        "iCloudUpdater",         // Real: cloudd/bird handle iCloud
        "iMessageAgent",         // Real: imagent
        "DiagnosticReportHelper",// Real: ReportCrash
        "NotificationAgent",     // Real: usernoted
        "SystemUpdateAgent",     // Not real
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
