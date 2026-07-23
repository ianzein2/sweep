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
        // 2024-2026 infostealers and RATs
        SpywareSignature(
            name: "Odyssey Stealer (Poseidon rebrand)",
            processNames: ["Odyssey", "odyssey_stealer", "OdysseyLoader", "odyssey_helper"],
            bundleIdentifiers: ["com.odyssey.stealer", "com.odyssey.agent"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
                "~/Library/LaunchAgents/com.odyssey.plist",
            ],
            launchAgentLabels: ["com.odyssey.service", "com.odyssey.agent"]
        ),
        SpywareSignature(
            name: "AMOS 2025 backdoor (Atomic macOS Stealer)",
            processNames: ["rodrigo", "amos2", "AtomicStealer2", "amos_v2"],
            bundleIdentifiers: ["com.rodrigo.stealer", "com.atomic.v2", "com.finder.helper"],
            filePaths: [
                "/private/tmp/.rodrigo",
                "/private/tmp/InstallerHelper",
                "~/Library/Application Support/.rodrigo",
                // AMOS July 2025 backdoor drops hidden helpers into $HOME
                "~/.helper",
                "~/.agent",
                "/Library/LaunchDaemons/com.finder.helper.plist",
            ],
            launchAgentLabels: ["com.rodrigo.service", "com.atomic.v2", "com.finder.helper"]
        ),
        SpywareSignature(
            name: "macOS.ZuRu (Termius trojan 2025)",
            processNames: ["com.apple.xssooxxagent", "xssooxxagent", ".Termius Helper1"],
            bundleIdentifiers: [],
            filePaths: [
                "/Users/Shared/com.apple.xssooxxagent",
                "/tmp/.fseventsd",  // real .fseventsd is a directory at volume root
                "/Library/LaunchDaemons/com.apple.xssooxxagent.plist",
            ],
            launchAgentLabels: ["com.apple.xssooxxagent"]
        ),
        SpywareSignature(
            name: "MacSync Stealer (2025)",
            processNames: ["UserSyncWorker", "usersyncworker", "zk-call-messenger"],
            bundleIdentifiers: ["com.usersyncworker.helper"],
            filePaths: [
                "~/Library/Logs/UserSyncWorker.log",
                "~/Library/Application Support/UserSyncWorker/last_up",
                "~/Library/Application Support/UserSyncWorker",
            ],
            launchAgentLabels: ["com.usersyncworker.helper"]
        ),
        SpywareSignature(
            name: "XCSSET 2025 (Firefox/clipper variant)",
            processNames: ["vexyeqj", "xmyyeqjx", "iewmilh_cdyd", "neq_cdyd_ilvcmwx"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.root",
                "/tmp/ancr",
                "/tmp/xmyyeqjx",
                "/tmp/System Settings.app",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "SparkKitty",
            processNames: ["SparkKitty", "sparkkitty", "spkty_helper"],
            bundleIdentifiers: ["com.sparkkitty.helper"],
            filePaths: ["/private/tmp/.sparkkitty", "~/Library/Application Support/.SparkKitty"],
            launchAgentLabels: ["com.sparkkitty.service"]
        ),
        SpywareSignature(
            name: "BeaverTail (DPRK Contagious Interview)",
            processNames: ["beavertail", "BeaverTail", "n2.exe", "ffmpeg-helper", "coderchef"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.pnpm",
                "~/Library/Caches/com.apple.coderchef",
                "~/.n2",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret (DPRK)",
            processNames: ["invisibleferret", "InvisibleFerret", "python-helper", "iff_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.iff",
                "~/Library/Application Support/.invisible",
                "~/.npl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OtterCookie (DPRK)",
            processNames: ["OtterCookie", "ottercookie", "ottc_agent"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.ottc", "~/Library/Caches/.ottercookie"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FerretDPRK (FriendlyFerret / FlexibleFerret)",
            processNames: ["ChromeUpdate", "chrome_updater", "FriendlyFerret", "SafariHelper.app",
                           "InstallerAlert", "FlexibleFerret", "ferret_agent",
                           "CameraAccess.app", "VCam"],
            bundleIdentifiers: ["com.google.Chrome.updater", "com.apple.safari.helper.plist"],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/LaunchAgents/com.google.keystone.agent.plist",
                "~/Library/LaunchAgents/com.apple.system.d.plist",
                "~/Library/LaunchAgents/com.zoom.plist",   // FlexibleFerret masquerade
                "~/Library/LaunchAgents/com.apple.secd.plist",  // FlexibleFerret second stage
                "/private/var/tmp/logd",                    // second-stage backdoor
            ],
            launchAgentLabels: ["com.google.keystone.agent", "com.apple.system.d",
                                "com.zoom.plist", "com.apple.secd"]
        ),
        SpywareSignature(
            name: "RustyAttr (Lazarus 2024)",
            processNames: ["RustyAttr", "rustyattr", "xattr_loader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.rusty",
                "/private/var/tmp/.xattr_payload",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "HZ RAT (macOS)",
            processNames: ["OpenVPNConnect", "hzrat", "hz_agent", "openvpn_conn"],
            bundleIdentifiers: ["com.openvpn.connect.hz"],
            filePaths: [
                "~/Library/Application Support/OpenVPN Connect/hz",
                "/private/tmp/.hzrat",
            ],
            launchAgentLabels: ["com.openvpn.connect.helper"]
        ),
        SpywareSignature(
            name: "MacMa (CDDS)",
            processNames: ["macma", "MacMa", "UserAgent", "cdds_agent", "com.UserAgent.va"],
            bundleIdentifiers: ["com.UserAgent.va", "com.macma.helper"],
            filePaths: [
                "~/Library/Preferences/com.UserAgent.va.plist",
                "/Library/Preferences/com.UserAgent.va.plist",
                "~/Library/LaunchAgents/com.UserAgent.va.plist",
            ],
            launchAgentLabels: ["com.UserAgent.va"]
        ),
        SpywareSignature(
            name: "RustDoor (BlackCat/Alphv)",
            processNames: ["RustDoor", "rustdoor", "rd_agent", "zshrc_updater", "test_final"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.RustDoor",
                "/private/tmp/.rustdoor",
                "~/.zshrc_updater",
                "~/Library/LaunchAgents/com.apple.rustdoor.plist",
            ],
            launchAgentLabels: ["com.apple.rustdoor", "com.apple.zshrc.updater"]
        ),
        SpywareSignature(
            name: "NimDoor (DPRK Nim RAT)",
            processNames: ["NimDoor", "nimdoor", "n_service", "nim_agent", "zoom_sdk_support",
                           "GoogIe LLC",  // Cyrillic/Latin-I homoglyph — key DPRK marker
                           "CoreKitAgent"],
            bundleIdentifiers: ["com.zoom.sdk.support"],
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/Application Support/.NimDoor",
                "~/Library/LaunchAgents/com.apple.zoom.sdk.plist",
                "~/Library/LaunchAgents/com.google.update.plist",  // NimDoor 2025
            ],
            launchAgentLabels: ["com.apple.zoom.sdk", "com.zoom.helper", "com.google.update"]
        ),
        SpywareSignature(
            name: "Banshee 2.0 (Telegram trojan)",
            processNames: ["Setup.app", "setup_bnsh"],
            bundleIdentifiers: ["com.banshee.setup"],
            filePaths: [
                "/Volumes/Telegram/Setup.app",   // fake Telegram DMG staging
                "/private/tmp/.banshee2",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // PamStealer poses as Maccy; genuine Maccy team ID is M3ZDGVZ4RH.
            // We don't include the bare "Maccy" process name here to avoid false-positiving
            // legitimate installs — team-ID verification (SupplyChainScanner) is the discriminator.
            name: "PamStealer (fake Maccy clone 2025)",
            processNames: ["pamstealer", "PamStealer"],
            bundleIdentifiers: ["com.pamstealer.helper", "com.maccy.clone"],
            filePaths: [
                "/private/tmp/.pamstealer",
                "~/Library/Application Support/.PamStealer",
            ],
            launchAgentLabels: ["com.pamstealer.service"]
        ),
        SpywareSignature(
            name: "JokerSpy",
            processNames: ["xcc", "JokerSpy", "sh.py.app", "xcc_agent"],
            bundleIdentifiers: ["com.apple.xcc"],
            filePaths: [
                "/Applications/xcc.app",
                "/Users/Shared/xcc.app",
                "~/Library/Application Support/.xcc",
            ],
            launchAgentLabels: ["com.apple.xcc"]
        ),
        SpywareSignature(
            name: "SwiftBelt (post-exploit enum)",
            processNames: ["SwiftBelt", "swiftbelt", "sbelt"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/SwiftBelt", "/private/tmp/.swiftbelt"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "LightSpy for macOS",
            processNames: ["LightSpy", "lightspy", "macCore", "MacControlHelper"],
            bundleIdentifiers: ["com.lightspy.core", "com.mac.controlhelper"],
            filePaths: [
                "/private/tmp/.lightspy",
                "~/Library/Preferences/com.lightspy.plist",
            ],
            launchAgentLabels: ["com.lightspy.plist", "com.mac.controlhelper"]
        ),
        SpywareSignature(
            name: "TodoSwift / DPRK dropper",
            processNames: ["TodoSwift", "todoswift", "TodoTasksAgent", "coinswap_helper"],
            bundleIdentifiers: ["com.todo.swift", "com.coinswap.helper"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: ["com.todo.swift", "com.coinswap.helper"]
        ),
        SpywareSignature(
            name: "KEYPLUG for macOS",
            processNames: ["keyplug", "KEYPLUG", "keyplug_agent"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.keyplug", "~/Library/Caches/.keyplug"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "ZuRu (Trojanized dev tools)",
            processNames: ["G.d", "F.d", "zuru", "iTerm_helper", "iterm.d"],
            bundleIdentifiers: ["com.googleusercontent.download", "com.iterm2.helper.d"],
            filePaths: [
                "~/Library/LaunchAgents/com.googleusercontent.download.plist",
                "~/Library/LaunchAgents/com.iterm2.helper.plist",
                "/private/tmp/.zuru",
            ],
            launchAgentLabels: ["com.googleusercontent.download", "com.iterm2.helper.d"]
        ),
        SpywareSignature(
            name: "XCSSET 2024 (Notes/Keychain variant)",
            processNames: ["xcssettool", "notes_helper", "xcs_agent"],
            bundleIdentifiers: ["com.apple.notes.helper"],
            filePaths: [
                "~/Library/Application Scripts/com.apple.Notes",
                "~/.notes_helper",
                "~/Library/Preferences/com.apple.notes.helper.plist",
            ],
            launchAgentLabels: ["com.apple.notes.helper"]
        ),
        SpywareSignature(
            name: "Ledger Live Trojan (BlueNoroff)",
            processNames: ["LedgerLive.app", "LedgerHelper", "ledger_updater"],
            bundleIdentifiers: ["com.ledger.live.helper", "com.ledger.updater"],
            filePaths: [
                "/private/tmp/.ledger",
                "~/Library/Application Support/Ledger Live/.helper",
            ],
            launchAgentLabels: ["com.ledger.live.helper", "com.ledger.updater"]
        ),
        SpywareSignature(
            name: "Notorious / BlackDoor",
            processNames: ["notorious", "Notorious", "blackdoor", "bd_agent"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.notorious", "/private/var/tmp/.blackdoor"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "AppleProcessHub (RAT)",
            processNames: ["AppleProcessHub", "appleprocesshub", "processhub_agent"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "~/Library/LaunchAgents/com.apple.processhub.plist",
                "/private/tmp/.processhub",
            ],
            launchAgentLabels: ["com.apple.processhub"]
        ),
        SpywareSignature(
            name: "Cobalt Strike beacon (macOS)",
            processNames: ["beacon", "cobaltstrike", "artifact32", "artifact64", "cs_beacon"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.beacon", "/private/tmp/artifact"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Sliver C2 implant (macOS)",
            processNames: ["sliver", "sliverd", "SLIVER_IMPLANT", "shellcode_loader"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.sliver", "/private/var/tmp/sliver"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Mustang Panda macOS",
            processNames: ["mustangpanda", "MustangPanda", "mp_agent"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.mp"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "KandyKorn v2 / SwiftLoader",
            processNames: ["SwiftLoader", "swiftloader", "sload_agent", "arcadia_stealer"],
            bundleIdentifiers: ["com.swift.loader", "com.arcadia.stealer"],
            filePaths: [
                "/private/tmp/.arcadia",
                "~/Library/Application Support/.arcadia",
            ],
            launchAgentLabels: ["com.swift.loader", "com.arcadia.stealer"]
        ),
        SpywareSignature(
            name: "MacSync (2025)",
            processNames: ["MacSync", "macsync", "mac_sync_agent", "syncmanager_helper"],
            bundleIdentifiers: ["com.macsync.agent"],
            filePaths: [
                "~/Library/Application Support/.MacSync",
                "/private/tmp/.macsync",
            ],
            launchAgentLabels: ["com.macsync.service", "com.macsync.agent"]
        ),
        SpywareSignature(
            name: "GoStealer (macOS)",
            processNames: ["GoStealer", "gostealer", "gost_agent"],
            bundleIdentifiers: ["com.gostealer.agent"],
            filePaths: [
                "/private/tmp/.gostealer",
                "~/Library/Application Support/.GoStealer",
            ],
            launchAgentLabels: ["com.gostealer.service"]
        ),
        SpywareSignature(
            name: "Fake Ledger / Trezor installer",
            processNames: ["Ledger Live Installer", "Trezor Suite Setup",
                           "LedgerInstaller", "TrezorInstaller"],
            bundleIdentifiers: ["com.ledger.installer.helper", "com.trezor.setup.helper"],
            filePaths: [
                "/private/tmp/LedgerLive-installer",
                "/private/tmp/TrezorSetup",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "TinyTurla-NG (Turla)",
            processNames: ["tinyturla", "TinyTurla", "ttng_agent"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.tinyturla", "/private/var/tmp/.turla"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Cthulhu 2 / SapphireStealer",
            processNames: ["SapphireStealer", "sapphire_stealer", "sapph_agent"],
            bundleIdentifiers: ["com.sapphire.stealer"],
            filePaths: [
                "/private/tmp/.sapphire",
                "~/Library/Application Support/.Sapphire",
            ],
            launchAgentLabels: ["com.sapphire.service"]
        ),
        SpywareSignature(
            name: "PureStealer (macOS port)",
            processNames: ["PureStealer", "pure_mac", "pmac_agent"],
            bundleIdentifiers: ["com.purestealer.mac"],
            filePaths: [
                "/private/tmp/.purestealer",
                "~/Library/Application Support/.PureStealer",
            ],
            launchAgentLabels: ["com.purestealer.mac"]
        ),
        SpywareSignature(
            name: "AMOS-related \"install.sh\" dropper",
            processNames: ["install.sh", "installer.sh", "install_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/install.sh",
                "/tmp/install.sh",
            ],
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
        // 2024-2026 additions used by RustDoor, NimDoor, MacMa, XCSSET variants
        "com.apple.notes.helper",
        "com.apple.system.d",
        "com.apple.zoom.sdk",
        "com.apple.processhub",
        "com.apple.rustdoor",
        "com.apple.zshrc.updater",
        "com.apple.xcc",
        "com.apple.macshare.plist",
        "com.apple.family.sync",
        "com.apple.spotlightd.agent",
        "com.apple.icloud.helper",
        "com.apple.fanhelperd",
        "com.apple.dockhelper",
        "com.apple.airportd.helper",
        "com.apple.audio.d",
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
        // 2024-2026 additions — process names observed impersonating Apple binaries
        // (only names Apple does NOT ship; the ProcessScanner still gates these
        // to non-system paths so a real /usr/libexec/... binary is safe.)
        "mdworker_shared_helper",  // Real: mdworker_shared (no _helper)
        "AppleMobileDevice",       // Real: AppleMobileDeviceService (no truncation)
        "cloudkitd_helper",        // Real: cloudkitd
        "SafariHelper.app",        // FerretDPRK masquerade
        "ChromeUpdate",            // FerretDPRK / Ledger trojan
        "chrome_updater",          // FerretDPRK
        "InternalPDF",             // RustBucket dropper
        "InternalDocs",            // RustBucket dropper
        "PDFViewer_Update",        // Reported in Lazarus campaigns
        "AppleSecurityHub",        // Not a real Apple binary
        "AppleProcessHub",         // Not a real Apple binary
        "iTerm_helper",            // ZuRu masquerade
        "coreduetd_helper",        // Real: coreduetd
        "airportd_helper",         // Real: airportd
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

    // MARK: - Developer Team ID Reputation

    /// Apple developer team IDs revoked over public malware campaigns in 2024-2025.
    /// A signed binary whose TeamIdentifier is in this list should be treated as
    /// high-confidence malicious — Apple only revokes for confirmed abuse.
    /// Sources: Jamf Threat Labs, SentinelOne, Check Point.
    public static let revokedMaliciousTeamIds: [String: String] = [
        "GNJLS3UYZ4": "MacSync Stealer (2025) — Swift code-signed, revoked by Apple",
        // Placeholder entries — real IDs from advisories can be added over time.
        // Only entries backed by public reporting go here; this file must not
        // include unverified rumor IDs, or Sweep will misfire on legitimate apps.
    ]

    /// Legitimate developer team IDs for apps commonly impersonated by macOS malware.
    /// A binary claiming to be one of these apps but signed by a *different* team ID
    /// is strong evidence of a trojanized clone.
    ///
    /// Only entries with confirmed team IDs from vendor documentation or independent
    /// research go here — a wrong entry would cause false positives against every
    /// legitimate install of the impersonated app.
    public static let legitimateVendorTeamIds: [String: (appName: String, teamId: String)] = [
        // p0deje.Maccy — team ID from Jamf Threat Labs PamStealer writeup (2025)
        "com.p0deje.Maccy":       ("Maccy",          "M3ZDGVZ4RH"),
        // Additional entries should only be added when the team ID is confirmed
        // against Apple's developer directory or a public advisory.
    ]

    // MARK: - Compromised Supply-Chain Packages

    /// Specific npm package versions known to have shipped malicious code.
    /// Used by SupplyChainScanner to walk `node_modules` and flag installed copies.
    /// Sources: Wiz, Socket.dev, Microsoft, Unit 42 (2025).
    public static let compromisedNpmPackages: [(name: String, badVersions: Set<String>, campaign: String)] = [
        // CVE-2025-32965 — official xrpl.js compromise (Apr 2025)
        ("xrpl",              ["4.2.1", "4.2.2", "4.2.3", "4.2.4"], "xrpl.js supply-chain compromise (CVE-2025-32965)"),
        // DPRK "Contagious Interview" packages (Socket 2025) — small curated subset
        ("tailwind-magic",    [],                                    "DPRK Contagious Interview npm campaign"),
        ("node-tailwind",     [],                                    "DPRK Contagious Interview npm campaign"),
        ("react-modal-select",[],                                    "DPRK Contagious Interview npm campaign"),
        ("dev-log-core",      [],                                    "DPRK Contagious Interview npm campaign"),
        ("logger-base",       [],                                    "DPRK Contagious Interview npm campaign"),
        ("logkitx",           [],                                    "DPRK Contagious Interview npm campaign"),
        ("pino-debugger",     [],                                    "DPRK Contagious Interview npm campaign"),
        ("debug-fmt",         [],                                    "DPRK Contagious Interview npm campaign"),
        ("debug-glitz",       [],                                    "DPRK Contagious Interview npm campaign"),
    ]

    /// Filenames and directories dropped by the Shai-Hulud npm worm (Sept/Nov 2025).
    /// If Sweep finds any of these inside a `node_modules` or repo root, it is
    /// very likely the worm ran there.
    public static let shaiHuludMarkers: [String] = [
        "cloud.json",
        "contents.json",
        "environment.json",
        "truffleSecrets.json",
        ".github/workflows/discussion.yaml",
    ]

    /// Malicious VSCode/Cursor extension publishers and IDs, drawn from Koi,
    /// The Hacker News, and Socket 2025 reporting.
    public static let maliciousEditorExtensionIds: Set<String> = [
        // TigerJack (Koi Security, 2025) — 17k+ installs
        "ab-498.cpp-playground",
        "498.cpp-playground",
        "ab-498.http-format",
        "498.http-format",
        "498-00.pythonformat",
        "498.solidity-language",
        // Anivia loader → OctoRAT (Nov 2025)
        "publishingsofficial.prettier-vscode-plus",
    ]

    /// Publishers used by known-malicious extension families. Any extension published
    /// by these publishers is suspect regardless of the exact package name.
    public static let maliciousEditorPublishers: Set<String> = [
        "ab-498", "498", "498-00", "publishingsofficial",
    ]
}
