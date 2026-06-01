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
        // 2024-2026 DPRK / APT-linked macOS malware
        SpywareSignature(
            // "Contagious Interview" — fake job interview lures targeting developers.
            // BeaverTail is the Node.js/Python stealer stage; InvisibleFerret is the Python RAT.
            name: "BeaverTail (Contagious Interview)",
            processNames: ["beavertail", "node_modules_helper", "ffmpeg-utils",
                           "VCam", "MiroTalk", "FreeConference", "ChromeUpdate"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.npl",
                "/private/tmp/.n2",
                "~/Library/Application Support/.npl",
                "~/.npl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret (Contagious Interview)",
            processNames: ["invisibleferret", "pyp", "p2", "ssh_client", "pay"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.n2",
                "~/.config/google-chrome/Default/Login Data.bak",
                "/private/tmp/.iferret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // North Korean RAT discovered in 2024 (Trend Micro / Aqua Nautilus).
            // Distributed via fake VPN / cracked apps. Persists as a Swift binary in /tmp.
            name: "RustDoor / Bandit",
            processNames: ["RustDoor", "rustdoor", "Bandit", "VMware-tools", "Visual_Studio_Updater"],
            bundleIdentifiers: ["com.visualstudio.updater", "com.vmware.toolsd"],
            filePaths: [
                "/private/tmp/test",
                "/private/tmp/.rustdoor",
                "~/Library/Application Support/.bandit",
                "~/Library/.system_updater",
            ],
            launchAgentLabels: ["com.apple.systemupdater", "com.visualstudio.updater"]
        ),
        SpywareSignature(
            name: "TODDLERSHARK / DURIANBEACON",
            processNames: ["toddlershark", "durianbeacon", "DustyEmu", "macOSPanel"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.toddler", "~/Library/Caches/.duri"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // BlueNoroff (DPRK) crypto-targeting cluster, 2024 update of NokNok.
            name: "HiddenRisk (BlueNoroff)",
            processNames: ["hiddenrisk", "growth.scpt", "growth", "ExchangeBitkozMonopoly",
                           "MacGorow", "ksearch"],
            bundleIdentifiers: ["com.apple.growth"],
            filePaths: [
                "/private/tmp/.growth",
                "~/Library/LaunchAgents/com.apple.growth.plist",
                "~/Library/Logs/.growth.log",
            ],
            launchAgentLabels: ["com.apple.growth"]
        ),
        SpywareSignature(
            // Lazarus / DPRK 2025 — distributed via npm and PyPI typo-squat packages.
            name: "FlexibleFerret",
            processNames: ["flexibleferret", "FlexibleFerret", "lib_ffmpeg", "ffmpeg_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.flex",
                "/private/tmp/.flex",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Originally iOS-only, full macOS variant documented late 2024.
            name: "LightSpy (macOS)",
            processNames: ["lightspy", "LightSpy", "macma", "Macma", "uploadtask", "soundrecord"],
            bundleIdentifiers: ["com.lightspy.agent"],
            filePaths: [
                "/private/var/db/.lightspy",
                "~/Library/Caches/.lightspy",
                "~/Library/Application Support/.macma",
            ],
            launchAgentLabels: ["com.apple.softwareupdater", "com.lightspy.daemon"]
        ),
        // 2024-2026 macOS infostealers
        SpywareSignature(
            // "ReaderUpdate" / "Crimson Stealer" — Mach-O Crimson Stealer family observed late 2024,
            // spread via fake Adobe Reader updaters and cracked Mac apps.
            name: "ReaderUpdate / Crimson Stealer",
            processNames: ["ReaderUpdate", "AdobeReaderUpdater", "crimson_stealer", "crimson",
                           "AdobeUpdaterHelper", "BlueExperienceUpdater"],
            bundleIdentifiers: ["com.adobe.ReaderUpdater", "com.crimson.stealer"],
            filePaths: [
                "/private/tmp/.readerupdate",
                "~/Library/Application Support/.crimson",
                "~/Library/LaunchAgents/com.adobe.ReaderUpdater.plist",
            ],
            launchAgentLabels: ["com.adobe.ReaderUpdater", "com.crimson.agent"]
        ),
        SpywareSignature(
            // 2025 macOS stealer — distributed via fake Chrome/Safari updates and cracked software.
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid", "frigid_stealer", "WindowServer.helper"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.frigid",
            ],
            launchAgentLabels: ["com.frigid.helper"]
        ),
        SpywareSignature(
            // Banshee Stealer 3.0 / Banshee XV — 2025 evolution with Apple-binary-mimicking persistence.
            name: "Banshee 3.0",
            processNames: ["banshee3", "banshee_xv", "bnsh3", "AppleSecureKey", "AppleSyncProxy"],
            bundleIdentifiers: ["com.banshee.v3", "com.apple.securekey"],
            filePaths: [
                "/private/tmp/.banshee3",
                "~/Library/Application Support/.banshee3",
            ],
            launchAgentLabels: ["com.banshee.v3", "com.apple.securekey"]
        ),
        SpywareSignature(
            // Lumma Stealer is primarily Windows but a macOS port appeared in 2025.
            name: "Lumma Stealer (macOS)",
            processNames: ["lumma", "Lumma", "lumma_mac", "lumc"],
            bundleIdentifiers: ["com.lumma.stealer"],
            filePaths: [
                "/private/tmp/.lumma",
                "~/Library/Application Support/.lumma",
            ],
            launchAgentLabels: ["com.lumma.agent"]
        ),
        SpywareSignature(
            // 2024 Russian-speaking actor; macOS RAT distributed via Telegram channels and cracked apps.
            name: "HZ Rat (macOS)",
            processNames: ["hzrat", "HZRat", "hz_rat", "OpenVPNConnect_Helper"],
            bundleIdentifiers: ["com.hzrat.agent"],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.hzrat",
            ],
            launchAgentLabels: ["com.openvpn.helper", "com.hzrat.daemon"]
        ),
        SpywareSignature(
            // "SwiftAttacker" / "SwiftBelt" malicious variant — Swift-based stealer, 2025.
            name: "SwiftAttacker",
            processNames: ["SwiftAttacker", "swiftattacker", "SwiftBeltMalicious", "swiftspy"],
            bundleIdentifiers: ["com.swift.attacker"],
            filePaths: [
                "/private/tmp/.swiftatk",
                "~/Library/Application Support/.swiftatk",
            ],
            launchAgentLabels: ["com.swift.attacker"]
        ),
        SpywareSignature(
            // OSX/Shlayer continues to be one of the most prevalent macOS threats (adware/installer dropper).
            name: "OSX.Shlayer",
            processNames: ["shlayer", "Shlayer", "Bundlore", "bundlore", "AdobeFlashPlayer_Installer",
                           "Player", "FlashUpdate", "MacDefender"],
            bundleIdentifiers: [
                "com.adobe.flashplayer.installmanager",
                "com.bundlore.agent",
            ],
            filePaths: [
                "/private/tmp/.shlayer",
                "~/Library/Application Support/.shlayer",
            ],
            launchAgentLabels: ["com.bundlore.agent", "com.shlayer.installer"]
        ),
        SpywareSignature(
            // 2025 adware-turned-stealer family delivered via SEO-poisoning macOS app cracks.
            name: "AdLoad (2025)",
            processNames: ["adload", "AdLoad", "search-defender", "ResultRunner",
                           "InstantSearch", "ProductSphere", "OmniBoxes"],
            bundleIdentifiers: [
                "com.adload.agent", "com.searchdefender.app",
                "com.resultrunner.helper", "com.instantsearch.helper",
            ],
            filePaths: [
                "~/Library/Application Support/com.AdLoad",
                "~/Library/Application Support/.AdLoad",
                "/Library/LaunchDaemons/com.adload.plist",
            ],
            launchAgentLabels: ["com.adload.agent", "com.searchdefender.daemon"]
        ),
        SpywareSignature(
            // 2025 commodity macOS RAT sold on Russian-language forums.
            name: "AuroraStealer (macOS)",
            processNames: ["aurora", "AuroraStealer", "aurora_mac", "audisrv"],
            bundleIdentifiers: ["com.aurora.stealer"],
            filePaths: [
                "/private/tmp/.aurora",
                "~/Library/Application Support/.aurora",
            ],
            launchAgentLabels: ["com.aurora.audisrv"]
        ),
        // 2024-2026 consumer stalkerware / monitoring
        SpywareSignature(
            name: "TheOneSpy",
            processNames: ["TheOneSpy", "theonespy", "tos_service", "tosagent"],
            bundleIdentifiers: ["com.theonespy.agent"],
            filePaths: [
                "~/Library/Application Support/TheOneSpy",
                "~/Library/Application Support/.TheOneSpy",
            ],
            launchAgentLabels: ["com.theonespy.agent"]
        ),
        SpywareSignature(
            name: "uMobix",
            processNames: ["uMobix", "umobix", "umobix_agent"],
            bundleIdentifiers: ["com.umobix.agent"],
            filePaths: ["~/Library/Application Support/.uMobix"],
            launchAgentLabels: ["com.umobix.service"]
        ),
        SpywareSignature(
            name: "Hoverwatch Plus",
            processNames: ["HoverwatchPlus", "hwplus", "hoverwatch_plus"],
            bundleIdentifiers: ["com.hoverwatch.plus"],
            filePaths: ["~/Library/Application Support/.HoverwatchPlus"],
            launchAgentLabels: ["com.hoverwatch.plus"]
        ),
        SpywareSignature(
            name: "FamiSafe",
            processNames: ["FamiSafe", "famisafe", "famisafe_agent"],
            bundleIdentifiers: ["com.wondershare.famisafe"],
            filePaths: ["~/Library/Application Support/FamiSafe"],
            launchAgentLabels: ["com.wondershare.famisafe"]
        ),
        SpywareSignature(
            // Family of stalkerware sold under shifting brands ("eyeZy", "EyeZy", "SafeSpy", etc.)
            // sharing the same code base. Added 2025 IOCs.
            name: "SafeSpy / EyeZy variants",
            processNames: ["safespy", "SafeSpy", "safespyagent", "eyezy_v2"],
            bundleIdentifiers: ["com.safespy.agent", "com.eyezy.v2"],
            filePaths: [
                "~/Library/Application Support/.SafeSpy",
                "~/Library/Application Support/.EyeZyV2",
            ],
            launchAgentLabels: ["com.safespy.service"]
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
        // 2024-2025 macOS malware impersonations observed in the wild
        "com.apple.growth",                 // BlueNoroff / HiddenRisk
        "com.apple.securekey",              // Banshee 3.0
        "com.apple.systemupdater",          // RustDoor / Bandit
        "com.apple.systempreferences.helper", // RustBucket
        "com.apple.macshare.plist",         // SpectralBlur
        "com.apple.crashreporter.agent",    // generic stealer drop name
        "com.apple.bluetooth.helper",       // observed in late-2024 droppers
        "com.apple.wifi.helper",            // observed in late-2024 droppers
        "com.apple.search.helper",          // AdLoad family
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
        // 2024-2025 process-name lookalikes used by macOS infostealers and droppers
        "AdobeReaderUpdater",    // ReaderUpdate / Crimson Stealer
        "AdobeFlashPlayer_Installer", // Shlayer/Bundlore
        "ChromeUpdate",          // BeaverTail variants
        "Visual_Studio_Updater", // RustDoor
        "VMware-tools",          // RustDoor
        "OpenVPNConnect_Helper", // HZ Rat
        "search-defender",       // AdLoad
        "InstantSearch",         // AdLoad
        "ResultRunner",          // AdLoad
        "WindowServer.helper",   // FrigidStealer (real: WindowServer, no .helper)
        "AppleSecureKey",        // Banshee 3.0 (no such Apple binary)
        "AppleSyncProxy",        // Banshee 3.0
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
