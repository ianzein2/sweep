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
        // 2024-2025 macOS malware families (newly observed in the wild)
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid", "FrigidUpdate", "MacUpdater"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
            ],
            launchAgentLabels: ["com.frigid.service"]
        ),
        SpywareSignature(
            name: "NimDoor (DPRK)",
            processNames: ["NimDoor", "nimdoor", "Telegram2", "ZoomFix", "ZoomUpdate", "macnotch"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/LaunchAgents/com.zoom.update.plist",
                "~/Library/Application Support/.nim",
            ],
            launchAgentLabels: ["com.zoom.update", "com.telegram2.service"]
        ),
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            processNames: ["BeaverTail", "beavertail", "n1.exe", "p.js", "FCCCall", "MiroTalk", "fccpackage"],
            bundleIdentifiers: ["com.miroai.cool", "com.fcccall.app"],
            filePaths: [
                "/private/tmp/.beavertail",
                "~/Library/Caches/com.miroai.cool",
                "/private/tmp/.npl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret (Contagious Interview)",
            processNames: ["InvisibleFerret", "ifsvc", "p.zip", "pdown", "ffpackage", "anydesk-client"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.npl",
                "/private/tmp/.n2",
                "~/Library/Application Support/.invisibleferret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FlexibleFerret",
            processNames: ["FlexibleFerret", "flexibleferret", "fcam.zip", "ChromeUpdate"],
            bundleIdentifiers: ["com.chromeupdate.installer"],
            filePaths: [
                "/private/tmp/.flexibleferret",
                "~/Library/Application Support/.flexible",
            ],
            launchAgentLabels: ["com.chromeupdate.helper"]
        ),
        SpywareSignature(
            name: "RustyAttr (DPRK)",
            processNames: ["RustyAttr", "rustyattr", "GitHubDesktop", "macUpgrader"],
            bundleIdentifiers: ["com.rustyattr.installer"],
            filePaths: [
                "/private/tmp/.rustyattr",
                "~/Library/Application Support/.rusty",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Hidden Risk (DPRK)",
            processNames: ["HiddenRisk", "hiddenrisk", "macOSUpdate", "BitcoinDocument"],
            bundleIdentifiers: ["com.bitcoinanalysis.app"],
            filePaths: [
                "/private/tmp/.hiddenrisk",
                "~/Library/Application Support/.hidden_risk",
                "/var/root/.zshenv",  // Hidden Risk modifies root's zshenv
            ],
            launchAgentLabels: ["com.apple.macos.update"]
        ),
        SpywareSignature(
            name: "ReaderUpdate (Go infostealer)",
            processNames: ["ReaderUpdate", "reader_update", "readerupdate", "ReadingHelper", "TVStreamReader"],
            bundleIdentifiers: ["com.readerupdate.helper", "com.reader.update"],
            filePaths: [
                "~/Library/Application Support/.reader",
                "/private/tmp/.readerupdate",
            ],
            launchAgentLabels: ["com.reader.update", "com.readingreader.helper"]
        ),
        SpywareSignature(
            name: "JOKERSPY",
            processNames: ["xcc", "xcc.plugin", "sh.py", "jokerspy", "JokerSpy"],
            bundleIdentifiers: ["com.apple.security.systempolicyd"],  // typo-squat
            filePaths: [
                "/Users/Shared/AppleAccount",
                "/Users/Shared/.xcc",
                "~/Library/Application Support/.jokerspy",
            ],
            launchAgentLabels: ["com.apple.security.systempolicyd"]
        ),
        SpywareSignature(
            name: "HZ RAT",
            processNames: ["HZ_RAT", "hzrat", "OpenVPNConnect", "DingTalkHelper", "WeChatHelper"],
            bundleIdentifiers: ["com.openvpn.client.tray"],  // impersonated
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.hz",
                "~/Library/Application Support/OpenVPN Connect/HZ",
            ],
            launchAgentLabels: ["com.openvpn.client.tray"]
        ),
        SpywareSignature(
            name: "macma (Operation In(ter)ception)",
            processNames: ["macma", "Macma", "InterceptionAgent", "kAgent"],
            bundleIdentifiers: ["com.apple.softwareupdate.daemon"],  // fake
            filePaths: [
                "~/Library/LaunchAgents/com.apple.softwareupdate.daemon.plist",
                "/Library/Application Support/.macma",
            ],
            launchAgentLabels: ["com.apple.softwareupdate.daemon"]
        ),
        SpywareSignature(
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey", "OdysseyStealer", "OdysseyMacOS"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.service"]
        ),
        SpywareSignature(
            name: "Crocodilus",
            processNames: ["Crocodilus", "crocodilus", "crocodile_stealer"],
            bundleIdentifiers: ["com.crocodilus.stealer"],
            filePaths: [
                "/private/tmp/.crocodilus",
                "~/Library/Application Support/.crocodilus",
            ],
            launchAgentLabels: ["com.crocodilus.service"]
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "process_hub"],
            bundleIdentifiers: ["com.apple.processhub"],  // fake
            filePaths: [
                "/private/tmp/.appleprocesshub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub.helper"]
        ),
        SpywareSignature(
            name: "DustyHammock",
            processNames: ["DustyHammock", "dustyhammock", "hammockd"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.dustyhammock",
                "~/Library/Application Support/.hammock",
            ],
            launchAgentLabels: ["com.apple.systemhammock"]
        ),
        SpywareSignature(
            name: "Banshee 2.0",
            processNames: ["Banshee2", "banshee2", "BansheeReborn", "bnsh2"],
            bundleIdentifiers: ["com.banshee.v2", "com.banshee.reborn"],
            filePaths: [
                "/private/tmp/.banshee2",
                "~/Library/Application Support/.Banshee2",
            ],
            launchAgentLabels: ["com.banshee.v2.service"]
        ),
        SpywareSignature(
            name: "Tiny FUD",
            processNames: ["TinyFUD", "tinyfud", "tinyfud_loader"],
            bundleIdentifiers: ["com.tinyfud.loader"],
            filePaths: [
                "/private/tmp/.tinyfud",
                "~/Library/Application Support/.TinyFUD",
            ],
            launchAgentLabels: ["com.tinyfud.service"]
        ),
        SpywareSignature(
            name: "PerfctlR",
            processNames: ["perfctl", "perfctlr", "perfctl-r"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.perfctl",
                "/var/tmp/.perfctl",
                "/usr/bin/perfctl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "macOS.SwiftBelt",
            processNames: ["SwiftBelt", "swiftbelt", "SwiftBeltCLI"],
            bundleIdentifiers: ["com.cedowens.swiftbelt"],
            filePaths: [
                "/private/tmp/.swiftbelt",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "AdLoad",
            processNames: ["adload", "AdLoad", "MainSystem", "BaseUpdater", "ConsoleHelper", "SearchSmart"],
            bundleIdentifiers: ["com.adload.helper", "com.search-smart.app"],
            filePaths: [
                "~/Library/Application Support/.AdLoad",
                "/Library/Application Support/.AdLoad",
            ],
            launchAgentLabels: ["com.AdLoad.helper", "com.MainSystem.helper"]
        ),
        SpywareSignature(
            name: "Shlayer",
            processNames: ["Shlayer", "shlayer", "AdobeFlashPlayerInstaller"],
            bundleIdentifiers: ["com.adobe.flashplayer.installer"],  // fake
            filePaths: [
                "/private/tmp/.shlayer",
                "~/Library/Application Support/.Shlayer",
            ],
            launchAgentLabels: ["com.shlayer.installer"]
        ),
        SpywareSignature(
            name: "Bundlore",
            processNames: ["Bundlore", "bundlore", "MyCouponSmart", "PriceFountain"],
            bundleIdentifiers: ["com.bundlore.helper", "com.mycouponsmart.app"],
            filePaths: [
                "~/Library/Application Support/.Bundlore",
                "/Library/Application Support/.Bundlore",
            ],
            launchAgentLabels: ["com.bundlore.helper"]
        ),
        SpywareSignature(
            name: "OSX.Genio",
            processNames: ["Genieo", "genieo", "Omnibar", "InstallMac"],
            bundleIdentifiers: ["com.genieo.installer", "com.installmac.AppRemoval"],
            filePaths: [
                "~/Library/Application Support/Genieo",
                "/Library/Application Support/Genieo",
            ],
            launchAgentLabels: ["com.genieo.completer.download", "com.genieoinnovation.macextension"]
        ),
        SpywareSignature(
            name: "FerretSync (DPRK loader)",
            processNames: ["FerretSync", "ferretsync", "FerretSyncHelper"],
            bundleIdentifiers: ["com.ferret.sync"],
            filePaths: [
                "/private/tmp/.ferretsync",
                "~/Library/Application Support/.FerretSync",
            ],
            launchAgentLabels: ["com.ferret.sync"]
        ),
        SpywareSignature(
            name: "SparkKitty Stealer",
            processNames: ["SparkKitty", "sparkkitty", "sparkkitty_agent"],
            bundleIdentifiers: ["com.sparkkitty.stealer"],
            filePaths: [
                "/private/tmp/.sparkkitty",
                "~/Library/Application Support/.SparkKitty",
            ],
            launchAgentLabels: ["com.sparkkitty.service"]
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
        // 2024-2025 IOCs from observed campaigns
        "com.apple.softwareupdate.daemon",   // macma/Operation In(ter)ception
        "com.apple.security.systempolicyd",  // JOKERSPY typo-squat (real: systempolicyd)
        "com.apple.processhub",              // AppleProcessHub stealer
        "com.apple.macos.update",            // Hidden Risk
        "com.apple.zoom.update",             // NimDoor
        "com.apple.telegram2",               // NimDoor
        "com.apple.installer.helper",        // generic dropper pattern
        "com.apple.tcc.helper",              // fake TCC daemon
        "com.apple.xprotect.helper",         // fake XProtect helper
        "com.apple.endpoint.security.helper",
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
        // 2024-2025 mimicry observed in DPRK/Lazarus and infostealer campaigns
        "softwareupdated_helper",   // Real: softwareupdated
        "TCCHelper",                // Real: tccd (no Helper suffix)
        "AppleTCC",                 // Real: tccd
        "endpointsecurityd",        // Real: endpointsecurityd is in /System only
        "MacUpdater",               // generic dropper name
        "ZoomUpdate",               // NimDoor mimicry — real Zoom uses com.zoom.ZoomAutoUpdater
        "ChromeUpdate",             // FlexibleFerret mimicry
        "GoogleSoftwareUpdate.app", // Real: GoogleSoftwareUpdate (no .app)
        "macnotch",                 // NimDoor
        "applefilebookmark",        // not real
        "AppleAccount",             // JOKERSPY
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
