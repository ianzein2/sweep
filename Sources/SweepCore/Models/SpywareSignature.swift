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
        // 2025 macOS threat landscape — infostealers, DPRK APT, fake-update campaigns
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "MarsExecutable", "frigid", "SafariUpdate"],
            bundleIdentifiers: ["com.frigid.stealer", "com.wailord.installer"],
            filePaths: [
                "/private/tmp/.frigid",
                "/private/tmp/MarsExecutable",
                "~/Library/Application Support/.FrigidStealer",
                "~/Library/Application Support/SafariUpdate",
            ],
            launchAgentLabels: ["com.frigid.installer", "com.wailord.agent"]
        ),
        SpywareSignature(
            name: "FlexibleFerret (DPRK Contagious Interview)",
            processNames: ["FlexibleFerret", "flexibleferret", "FROSTYFERRET", "InvisibleFerret",
                           "ChromeUpdateAlert", "ChromeUpdate", "VCam", "CameraAccess"],
            bundleIdentifiers: ["com.flexibleferret.app", "com.chromeupdate.app"],
            filePaths: [
                "~/.chromeupdate",
                "~/Library/Application Support/.ferret",
                "/private/tmp/.ferret",
                "/private/var/tmp/.driftingferret",
            ],
            launchAgentLabels: ["com.apple.systemupdate", "com.chromeupdate.helper",
                                "com.google.chromeupdate", "com.zoom.startup"]
        ),
        SpywareSignature(
            name: "FrostyFerret",
            processNames: ["FrostyFerret", "frostyferret", "chromeupdate"],
            bundleIdentifiers: ["com.frostyferret.app"],
            filePaths: [
                "~/.chromeupdate",
                "~/Library/Application Support/.frostyferret",
                "/private/var/tmp/.frostyferret",
            ],
            launchAgentLabels: ["com.apple.frostyferret", "com.chromeupdate.helper"]
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["InvisibleFerret", "invisibleferret", "pyp"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.n2/pay",
                "~/.n2/bow",
                "~/.n2/mlip",
                "~/.npl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "BeaverTail (DPRK Contagious Interview)",
            processNames: ["BeaverTail", "beavertail", "MiroTalk"],
            bundleIdentifiers: ["io.mirotalk", "com.mirotalk.app"],
            filePaths: [
                "/private/tmp/.beaver",
                "~/Library/Application Support/.beavertail",
            ],
            launchAgentLabels: ["com.mirotalk.launcher"]
        ),
        SpywareSignature(
            name: "NimDoor (DPRK)",
            processNames: ["NimDoor", "nimdoor", "zoom_sdk_support",
                           "zoom_sdk_support_ver_1.6.9", "GoogIe", "trojan1_arm64", "trojan2_arm64"],
            bundleIdentifiers: ["us.zoom.support", "com.zoom.support.helper"],
            filePaths: [
                "/private/var/tmp/.nimdoor",
                "~/Library/Application Support/.nimdoor",
                "~/Library/Caches/.CFUserTextEncoding",
            ],
            launchAgentLabels: ["com.zoom.startup", "com.zoom.support.helper",
                                "com.google.update.helper"]
        ),
        SpywareSignature(
            name: "RustDoor (BlackCat/ALPHV)",
            processNames: ["RustDoor", "rustdoor", "VisualStudioUpdater",
                           "zshrc2", "VisualStudioUpdater_Patch", "ZoomVideo"],
            bundleIdentifiers: ["com.microsoft.vscode.updater", "com.visualstudio.updater"],
            filePaths: [
                "~/.zshrc2",
                "~/Library/Preferences/.zshrc2",
                "~/Library/Application Support/.rustdoor",
                "/private/tmp/.rustdoor",
            ],
            launchAgentLabels: ["com.microsoft.vscode.updater", "com.visualstudio.updater"]
        ),
        SpywareSignature(
            name: "Odyssey Stealer (AMOS variant)",
            processNames: ["Odyssey", "odyssey_stealer", "OdysseyInstaller",
                           "LedgerLive", "LedgerLiveInstaller"],
            bundleIdentifiers: ["com.odyssey.stealer", "com.ledger.live.fake"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
                "/private/tmp/AppleScript-*.scpt",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["appleprocesshub", "_appleprocesshub", "AppleProcessHub"],
            bundleIdentifiers: ["com.appleprocesshub.agent"],
            filePaths: [
                "/private/tmp/._appleprocesshub",
                "~/Library/Application Support/.appleprocesshub",
                "/tmp/.helper.sh",
            ],
            launchAgentLabels: ["com.apple.processhub", "com.appleprocesshub.helper"]
        ),
        SpywareSignature(
            name: "HZ Rat (China-nexus)",
            processNames: ["HZRat", "hzrat", "OpenVPN_Client_Setup",
                           "IPCC.MCA", "OpenVPNConnect_Setup"],
            bundleIdentifiers: ["com.hzrat.agent", "com.openvpn.client.setup"],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.hzrat",
                "~/Library/Application Support/OpenVPNSetup",
            ],
            launchAgentLabels: ["com.openvpn.client.helper", "com.hzrat.service"]
        ),
        SpywareSignature(
            name: "CoinLurker",
            processNames: ["CoinLurker", "coinlurker", "ChromeUpdate.app"],
            bundleIdentifiers: ["com.coinlurker.stealer", "com.chrome.update.helper"],
            filePaths: [
                "/private/tmp/.coinlurker",
                "~/Library/Application Support/.CoinLurker",
                "~/Library/Application Support/ChromeUpdate",
            ],
            launchAgentLabels: ["com.coinlurker.service", "com.google.chrome.updater"]
        ),
        SpywareSignature(
            name: "TodoSwift (DPRK)",
            processNames: ["TodoSwift", "todoswift", "todobear"],
            bundleIdentifiers: ["com.todoswift.app"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: ["com.todoswift.agent"]
        ),
        SpywareSignature(
            name: "TodoScramble",
            processNames: ["TodoScramble", "todoscramble", "swifty_todo"],
            bundleIdentifiers: ["com.todoscramble.app"],
            filePaths: [
                "/private/tmp/.todoscramble",
                "~/Library/Application Support/.TodoScramble",
            ],
            launchAgentLabels: ["com.todoscramble.agent"]
        ),
        SpywareSignature(
            name: "SparkKitty (iOS/macOS crypto stealer)",
            processNames: ["SparkKitty", "sparkkitty", "sparkkittyd"],
            bundleIdentifiers: ["com.sparkkitty.agent"],
            filePaths: [
                "/private/tmp/.sparkkitty",
                "~/Library/Application Support/.SparkKitty",
            ],
            launchAgentLabels: ["com.sparkkitty.service"]
        ),
        SpywareSignature(
            name: "SparkCat (crypto stealer)",
            processNames: ["SparkCat", "sparkcat", "sparkcatd"],
            bundleIdentifiers: ["com.sparkcat.agent"],
            filePaths: [
                "/private/tmp/.sparkcat",
                "~/Library/Application Support/.SparkCat",
            ],
            launchAgentLabels: ["com.sparkcat.service"]
        ),
        SpywareSignature(
            name: "PasivRobber (macOS commercial spy)",
            processNames: ["PasivRobber", "pasivrobber", "prsvc"],
            bundleIdentifiers: ["com.pasivrobber.agent"],
            filePaths: [
                "/private/var/tmp/.pasivrobber",
                "~/Library/Application Support/.PasivRobber",
            ],
            launchAgentLabels: ["com.pasivrobber.service"]
        ),
        SpywareSignature(
            name: "ReaderUpdate (loader)",
            processNames: ["ReaderUpdate", "readerupdate", "AdobeReaderUpdate", "readerupdate.arm64"],
            bundleIdentifiers: ["com.adobe.reader.update.helper"],
            filePaths: [
                "/private/tmp/.readerupdate",
                "~/Library/Application Support/.ReaderUpdate",
            ],
            launchAgentLabels: ["com.adobe.reader.update", "com.readerupdate.service"]
        ),
        SpywareSignature(
            name: "Crypter (macOS loader/anti-analysis)",
            processNames: ["Crypter", "crypter", "macCrypter"],
            bundleIdentifiers: ["com.crypter.loader"],
            filePaths: [
                "/private/tmp/.crypter",
                "~/Library/Application Support/.Crypter",
            ],
            launchAgentLabels: ["com.crypter.service"]
        ),
        SpywareSignature(
            name: "Zuru (poisoned installers)",
            processNames: ["Zuru", "zuru", "GoogleUpdater_", "iTerm.app"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.zuru",
                "~/Library/Application Support/.Zuru",
            ],
            launchAgentLabels: ["com.zuru.updater"]
        ),
        SpywareSignature(
            name: "OSX.LightSpy 2.0 (mobile+desktop)",
            processNames: ["lightspy", "LightSpy", "macnotifyd"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.lightspy",
                "~/Library/Application Support/.lightspy",
                "~/Library/Preferences/.LightSpy",
            ],
            launchAgentLabels: ["com.apple.macnotify"]
        ),
        SpywareSignature(
            name: "GhostGrab",
            processNames: ["GhostGrab", "ghostgrab", "ggrab"],
            bundleIdentifiers: ["com.ghostgrab.stealer"],
            filePaths: [
                "/private/tmp/.ghostgrab",
                "~/Library/Application Support/.GhostGrab",
            ],
            launchAgentLabels: ["com.ghostgrab.service"]
        ),
        SpywareSignature(
            name: "Tiny FUD (stager)",
            processNames: ["TinyFUD", "tinyfud", "tfud"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.tinyfud",
                "~/Library/Application Support/.tinyfud",
            ],
            launchAgentLabels: ["com.tinyfud.helper"]
        ),
        // Cryptominers commonly bundled with cracked macOS installers (2024-2025)
        SpywareSignature(
            name: "OSX.Miner (XMRig)",
            processNames: ["xmrig", "XMRig", "kmutex", "mshelper", "MinerHelper",
                           "com.apple.CoreDataProvider", "core_data_provider"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.xmrig",
                "/private/tmp/.xmrig",
                "~/Library/Application Support/.miner",
                "/Library/Application Support/.miner",
            ],
            launchAgentLabels: ["com.apple.coredataproviderd", "com.apple.miner"]
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
        // Additional 2025 stalkerware / DPRK impersonation labels
        "com.apple.systemupdate",         // FlexibleFerret persistence label
        "com.apple.processhub",           // AppleProcessHub Stealer
        "com.apple.frostyferret",         // FrostyFerret
        "com.apple.macnotify",            // LightSpy 2.0
        "com.apple.coredataproviderd",    // XMRig-based miners
        "com.apple.miner",
        "com.apple.CoreServices.helper",
        "com.apple.spotlight.helper",
        "com.apple.audio.driverd",
        "com.apple.wifi.helper",
        "com.apple.trustd.helper",
        "com.apple.system.helper",
        "com.apple.macos.helper",
        "com.apple.system.services",
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
        // Added to catch 2024-2025 impersonation seen in Ferret / RustDoor / AppleProcessHub etc.
        "macnotifyd",            // Not a real Apple daemon (LightSpy)
        "appleprocesshub",       // AppleProcessHub Stealer
        "chromeupdate",          // Ferret family; real: GoogleSoftwareUpdate
        "GoogIe",                // Homograph (capital-i for l) — DPRK NimDoor payload
        "GoogleUpdater_",        // Zuru variant naming
        "SafariUpdate",          // FrigidStealer impersonation; real: no "SafariUpdate" process
        "AdobeReaderUpdate",     // ReaderUpdate loader; real: none in modern macOS
        "VisualStudioUpdater",   // RustDoor mimic
        "spotlight_agent",       // Real: mds/mdworker
        "wifi_helper",           // Real: wifid
        "audio_driverd",         // Real: coreaudiod
        "kernel_helper",         // Real: kernel_task
        "trustd_service",        // Real: trustd
        "coreservices_helper",   // Real: coreservicesd
        "system_services",       // Not a real Apple process
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
