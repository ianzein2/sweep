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
        // 2024-2025 macOS threats (DPRK, China-linked APT, and new stealer families)
        SpywareSignature(
            name: "RustDoor / Trojan.MacOS.RustDoor",
            processNames: ["RustDoor", "rustdoor", "VisualStudioUpdater", "VisualStudioUpdater_Patch", "GoogleVoiceUtils"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.companyData",
                "~/Library/Application Support/.test",
                "/tmp/test.zip",
                "~/Library/VisualStudioUpdater",
            ],
            launchAgentLabels: ["com.apple.systemupdater.plist"]
        ),
        SpywareSignature(
            name: "HZ RAT (macOS)",
            processNames: ["hzr_agent", "hzrat", "hzr_service", "OpenVPNConnect.Helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.hzr",
                "~/Library/Application Support/.hzr",
            ],
            launchAgentLabels: ["com.openvpnconnect.helper"]
        ),
        SpywareSignature(
            name: "JaskaGO Stealer",
            processNames: ["jaskago", "JaskaGO", "Capcut_Installer", "AnyConnect", "GoogleDriveSync"],
            bundleIdentifiers: ["com.jaskago.stealer"],
            filePaths: [
                "/private/tmp/.jaskago",
                "~/Library/Application Support/.jaskago",
            ],
            launchAgentLabels: ["com.jaskago.service"]
        ),
        SpywareSignature(
            name: "BeaverTail (DPRK Contagious Interview)",
            processNames: ["BeaverTail", "beavertail", "node_module_v3"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.npl",
                "~/Library/Application Support/.npl",
                "~/.npl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret (DPRK Contagious Interview)",
            processNames: ["InvisibleFerret", "invisibleferret", "p.zi1", "pay", "ssh_agent_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/p.zi1",
                "~/.n2",
                "~/.npl",
                "~/.config/.n2",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FERRET family (DPRK FrostyFerret / ChromeFerret)",
            processNames: ["FrostyFerret", "ChromeUpdate.app", "chrome_update", "FerretService"],
            bundleIdentifiers: ["com.google.chromeupdate", "com.frosty.ferret"],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/Application Support/.ferret",
            ],
            launchAgentLabels: ["com.google.chromeupdate"]
        ),
        SpywareSignature(
            name: "Hidden Risk (BlueNoroff)",
            processNames: ["hidden_risk", "growth.agent", "InitUpdater"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Caches/com.apple.softwareupdater",
                "/private/var/tmp/.hr",
            ],
            launchAgentLabels: ["com.apple.softwareupdater"]
        ),
        SpywareSignature(
            name: "ZuRu (trojanized iTerm2 / Termius)",
            processNames: ["g.cache", "GoogleHelper", "iTerm2_helper", "TermiusUpdater"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.test",
                "/private/tmp/g.cache",
                "~/Library/Application Support/.zuru",
            ],
            launchAgentLabels: ["com.google.helper"]
        ),
        SpywareSignature(
            name: "GoBear / Gomir",
            processNames: ["gobear", "gomir", "GoBearService", "Troy", "TroyStealer"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.gobear",
                "~/Library/Application Support/.gobear",
            ],
            launchAgentLabels: ["com.gobear.service"]
        ),
        SpywareSignature(
            name: "DigitStealer",
            processNames: ["DigitStealer", "digitstealer", "ds_agent"],
            bundleIdentifiers: ["com.digit.stealer"],
            filePaths: [
                "/private/tmp/.digit",
                "~/Library/Application Support/.DigitStealer",
            ],
            launchAgentLabels: ["com.digit.stealer"]
        ),
        SpywareSignature(
            name: "PrivateLoader",
            processNames: ["privateloader", "PrivateLoader", "pld_agent"],
            bundleIdentifiers: ["com.private.loader"],
            filePaths: [
                "/private/tmp/.pld",
                "~/Library/Application Support/.PrivateLoader",
            ],
            launchAgentLabels: ["com.private.loader"]
        ),
        SpywareSignature(
            name: "ThiefQuest / EvilQuest",
            processNames: ["ThiefQuest", "EvilQuest", "CrashReporter", "abtpd", "AppQuest-Completer"],
            bundleIdentifiers: ["com.apple.questd", "com.google.softwareupdate"],
            filePaths: [
                "/Library/AppQuest/com.apple.questd",
                "~/Library/AppQuest/com.apple.questd",
                "/private/var/root/Library/Application Support/.apple_security",
            ],
            launchAgentLabels: ["com.apple.questd", "com.google.softwareupdate"]
        ),
        SpywareSignature(
            name: "MacMa / OSX.CDDS",
            processNames: ["UserAgent", "WindowServer", "cdds", "macma", "BackupAgent"],
            bundleIdentifiers: ["com.UserAgent.va", "com.apple.macma"],
            filePaths: [
                "~/Library/Preferences/com.UserAgent.va.plist",
                "~/Library/launchctl-user/com.UserAgent.va.plist",
            ],
            launchAgentLabels: ["com.UserAgent.va"]
        ),
        SpywareSignature(
            name: "NodeStealer (macOS variant)",
            processNames: ["NodeStealer", "node_stealer", "ns_agent", "MeetingHelper"],
            bundleIdentifiers: ["com.node.stealer"],
            filePaths: [
                "/private/tmp/.nodestealer",
                "~/Library/Application Support/.NodeStealer",
            ],
            launchAgentLabels: ["com.node.stealer"]
        ),
        SpywareSignature(
            name: "FullHouse.Doored (DPRK CryptoCore)",
            processNames: ["FullHouseDoored", "fullhouse", "doored", "AppleScriptHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.fullhouse",
                "~/Library/Application Support/.fullhouse",
            ],
            launchAgentLabels: ["com.apple.applescripthelper"]
        ),
        SpywareSignature(
            name: "Tachio Stealer",
            processNames: ["Tachio", "tachio_stealer", "tcio"],
            bundleIdentifiers: ["com.tachio.stealer"],
            filePaths: [
                "/private/tmp/.tachio",
                "~/Library/Application Support/.Tachio",
            ],
            launchAgentLabels: ["com.tachio.service"]
        ),
        SpywareSignature(
            name: "AppleSeed (Kimsuky)",
            processNames: ["appleseed", "AppleSeed", "as_agent", "Spider"],
            bundleIdentifiers: ["com.appleseed.agent"],
            filePaths: [
                "~/Library/Application Support/.AppleSeed",
                "/private/tmp/.appleseed",
            ],
            launchAgentLabels: ["com.apple.spider", "com.appleseed.agent"]
        ),
        SpywareSignature(
            name: "AppleProcessHub (2024)",
            processNames: ["AppleProcessHub", "applehub", "ProcessHub"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "/private/tmp/.processhub",
                "~/Library/Application Support/.ProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub"]
        ),
        SpywareSignature(
            name: "OSAMiner (mining via AppleScript)",
            processNames: ["osaminer", "OSAMiner", "Photo.scpt", "Image.scpt"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/k.plist",
                "~/Library/p.plist",
                "~/Library/.k.plist",
                "/private/var/tmp/.osaminer",
            ],
            launchAgentLabels: ["com.apple.kk", "com.apple.pp"]
        ),
        SpywareSignature(
            name: "DubRobber / XCSSET 2024",
            processNames: ["DubRobber", "dubrobber", "xcssetv2"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Scripts/com.apple.notes",
                "~/Library/Application Scripts/com.apple.mail",
                "~/Library/LaunchAgents/com.apple.suxinstaller.plist",
            ],
            launchAgentLabels: ["com.apple.suxinstaller"]
        ),
        SpywareSignature(
            name: "EmpireMonkey / SocGholish (macOS port)",
            processNames: ["socgholish", "monkey", "FakeUpdates"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.socgholish",
                "~/Library/Application Support/.fakeupdate",
            ],
            launchAgentLabels: []
        ),
        // Updates to existing major stealer families with newer IOCs
        SpywareSignature(
            name: "Atomic Stealer (AMOS v3+, 2024-2025)",
            processNames: ["AppleScript-Notarized", "amos_helper", "AMOSHelper", "Crack", "InstallerHelper"],
            bundleIdentifiers: ["com.amos.helper", "com.atomic.helper"],
            filePaths: [
                "/private/tmp/AppleScript-*.scpt",
                "/private/tmp/.amosv3",
                "~/Library/.amos_v3",
                "~/Library/Application Support/.amos_v3",
            ],
            launchAgentLabels: ["com.amos.helper", "com.atomic.helper"]
        ),
        SpywareSignature(
            name: "Banshee Stealer v2 (2024)",
            processNames: ["BansheeUI_v2", "BansheeAgent", "banshee_v2"],
            bundleIdentifiers: ["com.banshee.v2"],
            filePaths: [
                "/private/tmp/.bansheev2",
                "~/Library/Application Support/.bansheev2",
            ],
            launchAgentLabels: ["com.banshee.v2"]
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
        // 2024-2025 spyware impersonations
        "com.apple.softwareupdater",      // Hidden Risk (BlueNoroff) — note the trailing "r"
        "com.apple.systemupdater.plist",  // RustDoor
        "com.apple.applescripthelper",    // FullHouse.Doored
        "com.apple.suxinstaller",         // XCSSET 2024
        "com.apple.questd",               // ThiefQuest
        "com.apple.macma",                // MacMa
        "com.apple.processhub",           // AppleProcessHub
        "com.apple.spider",               // AppleSeed
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
        // 2024-2025 additions (observed in DPRK and stealer campaigns)
        "softwareupdater",       // Hidden Risk uses this — real is softwareupdated
        "AppleScriptHelper",     // FullHouse.Doored
        "VisualStudioUpdater",   // RustDoor
        "ChromeUpdate.app",      // FERRET — real Chrome doesn't run as a system process
        "TermiusUpdater",        // ZuRu
        "GoogleVoiceUtils",      // RustDoor — fake Google utility
        "GoogleDriveSync",       // JaskaGO impersonation
        "ssh_agent_helper",      // InvisibleFerret
        "MeetingHelper",         // NodeStealer
        "BackupAgent",           // MacMa
        "CryptoSwift",           // KandyKorn — masquerades as the Swift library
        "FinderTools",           // KandyKorn
        "AppQuest-Completer",    // ThiefQuest
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
