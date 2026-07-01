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
            name: "RustDoor",
            processNames: ["RustDoor", "rustdoor", "zshrc_helper", "Coreupdate", "GoogleUpdate.bin"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.rustdoor",
                "~/Library/Application Support/.rustdoor",
                "/tmp/coreupdated",
            ],
            launchAgentLabels: ["com.apple.rustdoor", "com.apple.updater.helper"]
        ),
        SpywareSignature(
            name: "HZ Rat (macOS)",
            processNames: ["OpenVPNConnect.app", "hzrat", "hzrat_agent", "OpenVPNConnectHelper"],
            bundleIdentifiers: ["net.openvpn.connect.helper"],
            filePaths: [
                "/private/var/tmp/.hzrat",
                "~/Library/Application Support/OpenVPN Connect",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            processNames: ["beavertail", "BeaverTail", "MiroTalk", "FCCCall", "chromeupdate", "chrome_update"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.n2/pnpm",
                "~/.n2",
                "~/Library/Application Support/.beavertail",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret (Contagious Interview)",
            processNames: ["invisibleferret", "InvisibleFerret", "npl", "python3_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.npl",
                "~/.n2/.npl",
                "/private/tmp/mp.zip",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "TrollStealer (Kimsuky)",
            processNames: ["TrollStealer", "trollstealer", "NxDooly", "InstallerHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.troll",
                "~/Library/Application Support/.trollstealer",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "NimStealer",
            processNames: ["NimStealer", "nimstealer", "nim_agent"],
            bundleIdentifiers: ["com.nimstealer.agent"],
            filePaths: [
                "/private/tmp/.nimstealer",
                "~/Library/Application Support/.NimStealer",
            ],
            launchAgentLabels: ["com.nimstealer.service"]
        ),
        SpywareSignature(
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey_stealer", "OdysseyInstaller"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["appleprocesshub", "AppleProcessHub", "processhub"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "/private/tmp/.appleprocesshub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub.agent"]
        ),
        SpywareSignature(
            name: "Vare Stealer",
            processNames: ["Vare", "vare_stealer", "vareUI"],
            bundleIdentifiers: ["com.vare.stealer"],
            filePaths: [
                "/private/tmp/.vare",
                "~/Library/Application Support/.Vare",
            ],
            launchAgentLabels: ["com.vare.service"]
        ),
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "DMGInstaller", "frigid_agent"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
            ],
            launchAgentLabels: ["com.frigid.service"]
        ),
        SpywareSignature(
            name: "AMOS Prime (2025 variant)",
            processNames: ["AMOSPrime", "amos_prime", "amosinstaller_v2", "AtomicPrime"],
            bundleIdentifiers: ["com.atomic.prime", "com.amos.prime"],
            filePaths: [
                "/private/tmp/.amos_prime",
                "~/Library/Application Support/.AMOSPrime",
            ],
            launchAgentLabels: ["com.atomic.prime.agent"]
        ),
        SpywareSignature(
            name: "Cthulhu 2.0 (RustyCthulhu)",
            processNames: ["CthulhuRust", "rustycthulhu", "cthulhu_v2", "CleanMyMacHelper_Pro"],
            bundleIdentifiers: ["com.cthulhu.rust"],
            filePaths: [
                "/private/tmp/.cthulhu2",
                "~/Library/Application Support/.CthulhuRust",
            ],
            launchAgentLabels: ["com.cthulhu.rust.agent"]
        ),
        SpywareSignature(
            name: "Banshee 3.0 (2025 rebuild)",
            processNames: ["Banshee3", "banshee_v3", "BansheePro", "bnsh3"],
            bundleIdentifiers: ["com.banshee.v3"],
            filePaths: [
                "/private/tmp/.banshee3",
                "~/Library/Application Support/.BansheeV3",
            ],
            launchAgentLabels: ["com.banshee.v3.service"]
        ),
        SpywareSignature(
            name: "LightSpy (macOS)",
            processNames: ["LightSpy", "lightspy_agent", "com.lightspy", "macmaster"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.lightspy",
                "~/Library/Application Support/.LightSpy",
                "/Library/.LightSpy",
            ],
            launchAgentLabels: ["com.apple.lightspy"]
        ),
        SpywareSignature(
            name: "SparkKitty / SparkCat (SDK stealer)",
            processNames: ["SparkKitty", "SparkCat", "sparkkitty_agent"],
            bundleIdentifiers: ["com.sparkkitty.sdk", "com.sparkcat.sdk"],
            filePaths: [
                "/private/tmp/.sparkkitty",
                "~/Library/Application Support/.SparkCat",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "PlushDaemon (macOS variant)",
            processNames: ["PlushDaemon", "plushd", "LittleDaemon"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.plushd",
                "/Library/.plushdaemon",
            ],
            launchAgentLabels: ["com.plush.daemon"]
        ),
        SpywareSignature(
            name: "MoonPeak (macOS)",
            processNames: ["MoonPeak", "moonpeak_agent", "peakloader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.moonpeak",
                "~/Library/Application Support/.MoonPeak",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Fickle Stealer (macOS port)",
            processNames: ["FickleStealer", "fickle_stealer", "fickle_agent"],
            bundleIdentifiers: ["com.fickle.stealer"],
            filePaths: [
                "/private/tmp/.fickle",
                "~/Library/Application Support/.Fickle",
            ],
            launchAgentLabels: ["com.fickle.service"]
        ),
        SpywareSignature(
            name: "GhostSpider (macOS backdoor)",
            processNames: ["GhostSpider", "ghostspider", "gspider_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.ghostspider",
                "~/Library/Application Support/.GhostSpider",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "macOS.CoinMiner (XMRig variants)",
            processNames: ["xmrig", "XMRigAgent", "mdworker_updated", "com.apple.mdworker_helper", "kernel_ext_helper", "systemcache_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.xmrig",
                "~/Library/Application Support/.miner",
                "/Library/.miner",
            ],
            launchAgentLabels: ["com.apple.mdworker.helper", "com.apple.kernel.helper"]
        ),
        SpywareSignature(
            name: "SnowLight (macOS APT loader)",
            processNames: ["SnowLight", "snowlight", "snowloader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.snowlight",
                "~/Library/Application Support/.SnowLight",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Ferret Family (2025)",
            processNames: ["FerretRAT", "ferret_agent", "FRPCagent", "chromiumUpdate"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/Application Support/.Ferret",
            ],
            launchAgentLabels: ["com.apple.chromium.updater"]
        ),
        SpywareSignature(
            name: "FlexibleFerret (2025)",
            processNames: ["FlexibleFerret", "flexferret", "ChromeUpdateService", "SafariUpdateService"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.flexferret",
                "~/Library/Application Support/.FlexibleFerret",
            ],
            launchAgentLabels: ["com.apple.chrome.updater", "com.apple.safari.updater"]
        ),
        // 2025-2026 stalkerware additions
        SpywareSignature(
            name: "Spynger",
            processNames: ["Spynger", "spynger", "spg_agent"],
            bundleIdentifiers: ["com.spynger.agent"],
            filePaths: ["~/Library/Application Support/.Spynger"],
            launchAgentLabels: ["com.spynger.service"]
        ),
        SpywareSignature(
            name: "uMobix",
            processNames: ["uMobix", "umobix", "umb_service"],
            bundleIdentifiers: ["com.umobix.agent"],
            filePaths: ["~/Library/Application Support/.uMobix"],
            launchAgentLabels: ["com.umobix.service"]
        ),
        SpywareSignature(
            name: "Phonsee",
            processNames: ["Phonsee", "phonsee", "phn_service"],
            bundleIdentifiers: ["com.phonsee.agent"],
            filePaths: ["~/Library/Application Support/.Phonsee"],
            launchAgentLabels: ["com.phonsee.service"]
        ),
        SpywareSignature(
            name: "Mobile Tracker Free",
            processNames: ["MobileTrackerFree", "mtracker", "mtf_agent"],
            bundleIdentifiers: ["com.mobiletrackerfree.agent"],
            filePaths: ["~/Library/Application Support/.MobileTracker"],
            launchAgentLabels: ["com.mobiletrackerfree.service"]
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
        // Additions seen in 2024-2026 DPRK, RustDoor, Ferret-family, and infostealer campaigns
        "com.apple.chrome.updater",
        "com.apple.chromium.updater",
        "com.apple.safari.updater",
        "com.apple.mdworker.helper",
        "com.apple.mdworker_helper",
        "com.apple.kernel.helper",
        "com.apple.kernel.ext.helper",
        "com.apple.rustdoor",
        "com.apple.processhub",
        "com.apple.processhub.agent",
        "com.apple.lightspy",
        "com.apple.updater.helper",
        "com.apple.terminal.helper",
        "com.apple.finder.helper",
        "com.apple.notes.helper",
        "com.apple.spotlight.helper",
        "com.apple.telemetry.agent",
        "com.apple.system.helper",
        "com.apple.systemservice",
        "com.apple.systempreferences.helper",
        "com.apple.webkit.helper",
        "com.apple.tcc.helper",
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
        // Additions from 2024-2026 malware campaigns (BeaverTail, Ferret, RustDoor, XMRig droppers)
        "chromeupdate",          // Not an Apple process; used by BeaverTail/Ferret family
        "chrome_update",
        "chromiumUpdate",
        "ChromeUpdateService",
        "SafariUpdateService",
        "mdworker_updated",      // Real: mdworker_shared
        "kernel_ext_helper",     // Not a real Apple process
        "systemcache_agent",     // Not a real Apple process
        "SysJSONRPC",            // Used by NokNok / BlueNoroff
        "Coreupdate",            // RustDoor variant
        "GoogleUpdate.bin",      // Mac Google Updater is Keystone, not GoogleUpdate.bin
        "OpenVPNConnectHelper",  // Real installer doesn't ship a helper daemon with this name
        "python3_helper",        // Not a real Apple/Python process; InvisibleFerret uses this
        "InstallerHelper",       // Not a real Apple process; TrollStealer uses this
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
