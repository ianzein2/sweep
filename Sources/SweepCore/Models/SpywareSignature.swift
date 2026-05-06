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
        // DPRK / Lazarus "Contagious Interview" campaign (active 2024-2025) — fake recruiters
        // trick devs into running poisoned npm packages or Zoom installers.
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            processNames: ["beavertail", "BeaverTail", "javascript_test", "ZoomVideoCommunications"],
            bundleIdentifiers: ["us.zoom.zoomupdater", "com.zoom.installer.helper"],
            filePaths: [
                "/private/tmp/.npl",
                "~/Library/Application Support/.npl",
                "~/Library/Application Support/.n2",
                "/private/tmp/p.zi",
            ],
            launchAgentLabels: ["com.zoom.video.helper", "com.video.zoom.update"]
        ),
        SpywareSignature(
            name: "InvisibleFerret (Contagious Interview)",
            processNames: ["InvisibleFerret", "invisibleferret", "pyp_main", "ferret_payload"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.npl",
                "~/.n2",
                "/private/tmp/pdown",
                "/private/tmp/InvisibleFerret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FrostyFerret (Contagious Interview)",
            processNames: ["FrostyFerret", "ChromeUpdateAlert", "ChromeUpdate"],
            bundleIdentifiers: ["com.google.chrome.updater"],
            filePaths: ["/private/tmp/ChromeUpdateAlert.app"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "TodoSwift (DPRK)",
            processNames: ["TodoSwift", "todoswift", "MacOS_Helper"],
            bundleIdentifiers: ["com.todoswift.helper"],
            filePaths: ["/private/tmp/.todoswift"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "PondRAT (DPRK)",
            processNames: ["PondRAT", "pondrat", "py_loader_mac"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.pondrat",
                "~/Library/Application Support/.pondrat",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FullHouse.Doored (DPRK)",
            processNames: ["FullHouseDoored", "fullhouse", "doored"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.fullhouse"],
            launchAgentLabels: []
        ),
        // 2024 macOS RATs and stealers
        SpywareSignature(
            name: "macOS.ZuRu (poisoned dev tools)",
            processNames: ["zuru", "ZuRu", "Termius_helper", "MicrosoftRemoteDesktopHelper", "RemoteDesktopHelper"],
            bundleIdentifiers: ["com.termius.mac.zuru", "com.microsoft.rdc.macos.helper2"],
            filePaths: [
                "/private/tmp/.zuru",
                "~/Library/Application Support/.zuru",
                "/Library/Application Support/.zuru",
            ],
            launchAgentLabels: ["com.zuru.agent", "com.termius.helper.update"]
        ),
        SpywareSignature(
            name: "HZ RAT (macOS variant)",
            processNames: ["hzrat", "HZRat", "OpenVPNConnect_helper", "DingTalkHelper"],
            bundleIdentifiers: ["com.openvpn.client.helper2"],
            filePaths: [
                "~/Library/Application Support/.hzrat",
                "/private/tmp/.hzrat",
            ],
            launchAgentLabels: ["com.openvpn.helper.update"]
        ),
        SpywareSignature(
            name: "RustDoor (Trellix)",
            processNames: ["rustdoor", "RustDoor", "VisualStudioUpdater", "zshrc_helper", "zsh_updater"],
            bundleIdentifiers: ["com.microsoft.visualstudio.updater"],
            filePaths: [
                "~/.cred",
                "~/Library/Preferences/.test",
                "/private/tmp/test.zip",
                "~/Public/.fseventsd",
            ],
            launchAgentLabels: ["com.microsoft.visualstudio.code.update", "com.apple.zshrc.helper"]
        ),
        SpywareSignature(
            name: "GoldDoor / GoldDigger (Lazarus)",
            processNames: ["GoldDoor", "GoldDigger", "golddigger_mac"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.golddoor"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "macOS.NotLockBit",
            processNames: ["NotLockBit", "notlockbit", "lbit_mac"],
            bundleIdentifiers: ["com.notlockbit.encrypt"],
            filePaths: [
                "/private/tmp/.notlockbit",
                "~/Library/Application Support/.notlockbit",
            ],
            launchAgentLabels: ["com.notlockbit.agent"]
        ),
        SpywareSignature(
            name: "Crystal Rans0m",
            processNames: ["CrystalRansom", "crystal_ransom", "crystal_lock"],
            bundleIdentifiers: ["com.crystal.ransom"],
            filePaths: ["/private/tmp/.crystal_ransom"],
            launchAgentLabels: []
        ),
        // 2024-2025 infostealers
        SpywareSignature(
            name: "Tusk Stealer",
            processNames: ["Tusk", "tusk_stealer", "Tusk_Installer", "tuskmac"],
            bundleIdentifiers: ["com.tusk.stealer"],
            filePaths: [
                "/private/tmp/.tusk",
                "~/Library/Application Support/.Tusk",
            ],
            launchAgentLabels: ["com.tusk.agent"]
        ),
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid_stealer", "frigid_mac", "FrigidInstaller"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
            ],
            launchAgentLabels: ["com.frigid.service"]
        ),
        SpywareSignature(
            name: "AMOS Pro / Atomic v2 (2025)",
            processNames: ["AMOSPro", "atomic_v2", "atomic2_installer", "AppleScriptHelper"],
            bundleIdentifiers: ["com.atomic.stealer.pro", "com.amos.pro"],
            filePaths: [
                "/private/tmp/.amos2",
                "/private/tmp/.amospro",
                "~/Library/Application Support/.AMOSPro",
            ],
            launchAgentLabels: ["com.amos.pro.agent"]
        ),
        SpywareSignature(
            name: "Lumma Stealer (macOS port)",
            processNames: ["LummaStealer", "lumma_mac", "lumma_helper"],
            bundleIdentifiers: ["com.lumma.stealer"],
            filePaths: ["/private/tmp/.lumma"],
            launchAgentLabels: ["com.lumma.service"]
        ),
        SpywareSignature(
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey_stealer", "odyssey_helper"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        SpywareSignature(
            name: "TrickMo (macOS)",
            processNames: ["TrickMo", "trickmo_mac", "trickmo_helper"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.trickmo"],
            launchAgentLabels: []
        ),
        // Cross-platform red-team frameworks frequently abused on macOS
        SpywareSignature(
            name: "Sliver implant",
            processNames: ["sliver", "Sliver", "sliver-implant", "SliverServer", "sliver-server"],
            bundleIdentifiers: ["com.sliver.implant"],
            filePaths: [
                "/private/tmp/.sliver",
                "~/Library/Application Support/.sliver",
            ],
            launchAgentLabels: ["com.sliver.agent"]
        ),
        SpywareSignature(
            name: "Mythic agent (Poseidon/Apfell)",
            processNames: ["mythic", "Mythic", "Apfell", "apfell_agent", "poseidon_mythic"],
            bundleIdentifiers: ["com.mythic.apfell", "com.mythic.poseidon"],
            filePaths: [
                "/private/tmp/.mythic",
                "~/Library/Application Support/.apfell",
            ],
            launchAgentLabels: ["com.mythic.agent"]
        ),
        SpywareSignature(
            name: "Empire Mac agent",
            processNames: ["empire_mac", "EmpireAgent", "empyre"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.empire"],
            launchAgentLabels: []
        ),
        // Crypto wallet drainers (2024-2025)
        SpywareSignature(
            name: "WalletGuard Drainer (impostor)",
            processNames: ["walletguard_helper", "WalletDrainer", "wallet_extract"],
            bundleIdentifiers: ["com.walletguard.helper"],
            filePaths: ["/private/tmp/.walletdrain"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Inferno Drainer (macOS module)",
            processNames: ["InfernoDrainer", "inferno_mac", "inferno_helper"],
            bundleIdentifiers: ["com.inferno.drain"],
            filePaths: ["/private/tmp/.inferno"],
            launchAgentLabels: []
        ),
        // Poisoned developer-tool installers
        SpywareSignature(
            name: "Poisoned Notion Installer (2024)",
            processNames: ["NotionUpdaterHelper", "notion_helper2"],
            bundleIdentifiers: ["notion.id.updater2"],
            filePaths: ["/private/tmp/.notionupdater"],
            launchAgentLabels: ["com.notion.updater.helper2"]
        ),
        SpywareSignature(
            name: "Poisoned Loom Installer (2024)",
            processNames: ["LoomHelperUpdate", "loom_helper2"],
            bundleIdentifiers: ["com.loom.desktop.updater2"],
            filePaths: ["/private/tmp/.loomupdater"],
            launchAgentLabels: ["com.loom.update.helper2"]
        ),
        // PyongRAT / SwiftSlicer follow-ons — DPRK Mac tooling
        SpywareSignature(
            name: "PyongRAT",
            processNames: ["pyongrat", "PyongRAT", "pyong_helper"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.pyongrat"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "SwiftSlicer (mac variant)",
            processNames: ["swiftslicer_mac", "SwiftSlicer", "slicer_helper"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.swiftslicer"],
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
        // Recent campaigns abuse these "looks-Apple" labels
        "com.apple.zshrc.helper",            // RustDoor 2024
        "com.apple.spotlight.helper",        // Multiple 2024 stealers
        "com.apple.macshare.plist",          // SpectralBlur
        "com.apple.timesync.helper",         // ZuRu / generic
        "com.apple.touchidd",                // Stealer mimic
        "com.apple.notarize.helper",         // Stealer mimic
    ]

    /// Fake "trusted vendor" bundle IDs that mimic legitimate developer tools
    public static let fakeVendorBundlePatterns: Set<String> = [
        "us.zoom.zoomupdater",                  // BeaverTail
        "com.zoom.installer.helper",            // BeaverTail
        "com.microsoft.visualstudio.updater",   // RustDoor
        "com.microsoft.rdc.macos.helper2",      // ZuRu
        "com.termius.mac.zuru",                 // ZuRu
        "com.openvpn.client.helper2",           // HZ RAT
        "com.google.chrome.updater",            // FrostyFerret (real ID is com.google.keystone.daemon)
        "com.loom.desktop.updater2",            // 2024 supply chain
        "notion.id.updater2",                   // 2024 supply chain
    ]

    /// Returns true when bundleId looks like a *vendor* impersonation (Microsoft, Zoom, Google, etc.)
    public static func isFakeVendorBundleId(_ bundleId: String) -> Bool {
        if fakeVendorBundlePatterns.contains(bundleId) { return true }
        // Heuristic: legitimate vendors don't ship a bundle ID with a numeric suffix
        // like "helper2"/"updater2" — this is a common impersonation tell.
        let suspiciousNumericSuffixes = ["helper2", "updater2", "helper3", "service2"]
        return suspiciousNumericSuffixes.contains { bundleId.hasSuffix(".\($0)") || bundleId.hasSuffix($0) }
    }

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
        // 2024-2025 campaign mimics
        "ChromeUpdate",          // FrostyFerret — real Chrome updater is GoogleSoftwareUpdateAgent
        "ChromeUpdateAlert",     // FrostyFerret
        "ZoomVideoCommunications", // BeaverTail-style alias for the user-facing Zoom binary
        "VisualStudioUpdater",   // RustDoor
        "MicrosoftRemoteDesktopHelper", // ZuRu
        "RemoteDesktopHelper",   // ZuRu (real path lives under /Applications/Microsoft Remote Desktop.app)
        "NotionUpdaterHelper",   // poisoned-installer mimic
        "LoomHelperUpdate",      // poisoned-installer mimic
        "DingTalkHelper",        // HZ RAT
        "OpenVPNConnect_helper", // HZ RAT
        "AppleScriptHelper",     // AMOS Pro family — legitimate Apple binary is `osascript`
        "TouchIDHelper",         // Stealer mimic — Apple's process is biometrickitd
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
