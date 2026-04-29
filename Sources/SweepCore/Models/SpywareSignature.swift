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
        // 2024-2025 macOS threats — APT, RAT, and stealer families documented by
        // Apple, Kaspersky, JAMF, SentinelOne, Bitdefender, Proofpoint, ESET.
        SpywareSignature(
            name: "RustDoor (BlackBasta-linked backdoor)",
            processNames: ["rustdoor", "RustDoor", "Visual Studio Updater", "vsupdate"],
            bundleIdentifiers: ["com.microsoft.vsupdate"],
            filePaths: [
                "/private/var/tmp/.rustdoor",
                "~/Library/Application Support/.rustdoor",
                "/private/tmp/zsh.hidden",
            ],
            launchAgentLabels: ["com.apple.systemkeychain", "com.microsoft.vsupdate"]
        ),
        SpywareSignature(
            name: "BeaverTail (DPRK Lazarus / Contagious Interview)",
            processNames: ["BeaverTail", "beavertail", "p.zip", "p2.zip", "node_modules_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/test.json",
                "/tmp/.npl",
                "~/Library/Application Support/.npl",
                "~/Library/Application Support/Programs/InvisibleFerret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret (DPRK follow-on backdoor)",
            processNames: ["InvisibleFerret", "invisibleferret", "pyp", "python_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.npl",
                "~/Library/Application Support/.n2",
                "/tmp/.n2",
            ],
            launchAgentLabels: ["com.python.helper"]
        ),
        SpywareSignature(
            name: "LightSpy (macOS variant)",
            processNames: ["LightSpy", "lightspy", "macircloader", "FrameworkLoader", "system_extension_helper"],
            bundleIdentifiers: ["com.apple.lightspy"],
            filePaths: [
                "/private/var/tmp/.lightspy",
                "~/Library/Caches/com.apple.cache.helper",
            ],
            launchAgentLabels: ["com.apple.cache.helper"]
        ),
        SpywareSignature(
            name: "Geacon (Go Cobalt Strike beacon)",
            processNames: ["geacon", "Geacon", "geacon_plus", "geacon_pro", "SecureLink", "SourceTreeUpdater"],
            bundleIdentifiers: ["com.atlassian.sourcetree.update"],
            filePaths: [
                "/private/tmp/.geacon",
                "~/Library/Application Support/.SecureLink",
            ],
            launchAgentLabels: ["com.atlassian.sourcetree.update"]
        ),
        SpywareSignature(
            name: "JaskaGO (Go infostealer)",
            processNames: ["JaskaGO", "jaskago", "CapCut_Installer"],
            bundleIdentifiers: ["com.jaskago.installer"],
            filePaths: [
                "/private/tmp/.jaska",
                "~/Library/Application Support/.JaskaGO",
            ],
            launchAgentLabels: ["com.jaskago.service"]
        ),
        SpywareSignature(
            name: "HZ RAT (macOS variant)",
            // Avoid OpenVPNConnect / WeChatHelper here — those collide with the real apps.
            // The real HZ RAT samples drop process names "hzrat" and a fake Tencent helper.
            processNames: ["hzrat", "HZRAT", "QQHelperHZ", "tencent_helper_hz"],
            bundleIdentifiers: ["com.tencent.qq.helperhz"],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.hzrat",
            ],
            launchAgentLabels: ["com.tencent.qq.helperhz"]
        ),
        SpywareSignature(
            name: "TodoSwift (DPRK BlueNoroff dropper)",
            processNames: ["TodoSwift", "todoswift", "Todo:1.app", "TodoTasks"],
            bundleIdentifiers: ["com.todoswift.app", "com.bluenoroff.todoswift"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.todoswift",
            ],
            launchAgentLabels: ["com.todoswift.helper"]
        ),
        SpywareSignature(
            name: "FrigidStealer (mac-targeted stealer)",
            processNames: ["FrigidStealer", "frigidstealer", "DesktopUtility", "MacUpdater"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
            ],
            launchAgentLabels: ["com.frigid.stealer"]
        ),
        SpywareSignature(
            name: "FERRET / FrostyFerret (DPRK)",
            processNames: ["FrostyFerret", "ferret", "ChromeUpdate", "ChromeUpdater_helper"],
            bundleIdentifiers: ["com.google.chrome.helper.updater"],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/Application Support/.ChromeUpdate",
            ],
            launchAgentLabels: ["com.google.chrome.helper.updater"]
        ),
        SpywareSignature(
            name: "Lazarus FullHouse.Doored / VanaModular",
            processNames: ["fullhouse", "FullHouse", "vanamodular", "VanaModular", "TableLoader", "TableSettings"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.tableSettings",
                "/private/tmp/.fullhouse",
            ],
            launchAgentLabels: ["com.apple.tablesettings"]
        ),
        SpywareSignature(
            name: "ToddyCat / Macma (Hacking Team-style RAT)",
            processNames: ["macma", "Macma", "toddycat", "WindowServerHelper", "client.app"],
            bundleIdentifiers: ["com.apple.windowserverhelper"],
            filePaths: [
                "/private/tmp/.macma",
                "~/Library/Application Support/.macma",
            ],
            launchAgentLabels: ["com.apple.windowserverhelper", "com.UserAgent.va.plist"]
        ),
        SpywareSignature(
            name: "ThiefQuest / EvilQuest (legacy ransomware/infostealer)",
            processNames: ["thiefquest", "ThiefQuest", "evilquest", "questd", "CrashReporter_helper"],
            bundleIdentifiers: ["com.apple.questd"],
            filePaths: [
                "~/Library/AppQuest",
                "/Library/AppQuest",
                "/private/var/root/Library/AppQuest",
            ],
            launchAgentLabels: ["com.apple.questd", "com.apple.questd.plist"]
        ),
        SpywareSignature(
            name: "OSX.Shlayer / Bundlore (adware-malware loader)",
            processNames: ["Shlayer", "shlayer", "bundlore", "Bundlore", "PlayerInstaller", "AdobeFlashPlayer.app"],
            bundleIdentifiers: ["com.adobe.flashplayer.installer"],
            filePaths: [
                "/private/tmp/Installer.app",
                "/private/tmp/.shlayer",
                "~/Library/LaunchAgents/com.adobe.flashplayer.plist",
            ],
            launchAgentLabels: ["com.adobe.flashplayer", "com.macsearch.helper"]
        ),
        SpywareSignature(
            name: "OSX.Pirrit (adware injector)",
            processNames: ["Pirrit", "pirrit", "wssync", "Mughthesec", "spigot_search"],
            bundleIdentifiers: ["com.pirrit.adware"],
            filePaths: [
                "~/Library/Application Support/.pirrit",
                "/Library/Application Support/Pirrit",
            ],
            launchAgentLabels: ["com.pirrit.helper"]
        ),
        SpywareSignature(
            name: "OSX.Adload (signed adware)",
            processNames: ["Adload", "adload", "ResultsExtension", "MainSearch", "AdEngine"],
            bundleIdentifiers: ["com.adload.installer"],
            filePaths: [
                "~/Library/Application Support/.Adload",
                "/Library/Application Support/Adload",
            ],
            launchAgentLabels: ["com.adload.update"]
        ),
        SpywareSignature(
            name: "OSX.KeRanger (ransomware)",
            processNames: ["keranger", "KeRanger", "kernel_service", "General.rtf"],
            bundleIdentifiers: ["com.apple.keranger"],
            filePaths: [
                "~/Library/kernel_service",
                "/Library/kernel_service",
                "/Applications/Transmission.app/Contents/Resources/General.rtf",
            ],
            launchAgentLabels: ["com.apple.keranger"]
        ),
        SpywareSignature(
            name: "OSX.Coldroot (legacy RAT)",
            processNames: ["coldroot", "Coldroot", "com.apple.audio.driver"],
            bundleIdentifiers: ["com.apple.audio.driver2"],
            filePaths: [
                "/private/etc/com.apple.audio.driver2.app",
                "/Library/LaunchDaemons/com.apple.audio.driver.plist",
            ],
            launchAgentLabels: ["com.apple.audio.driver2"]
        ),
        SpywareSignature(
            name: "OSX.Hydromac",
            processNames: ["hydromac", "Hydromac", "MacOSUpdater"],
            bundleIdentifiers: ["com.hydromac.updater"],
            filePaths: [
                "/private/tmp/.hydromac",
                "~/Library/Application Support/.Hydromac",
            ],
            launchAgentLabels: ["com.hydromac.service"]
        ),
        SpywareSignature(
            name: "Atomic Stealer 2025 variants (AMOS-Lite / Amos.Pro)",
            processNames: ["amos_lite", "Amos.Pro", "amospro", "AMOSLite", "atomicpro", "ledger_live_updater"],
            bundleIdentifiers: ["com.atomic.lite", "com.atomic.pro"],
            filePaths: [
                "/private/tmp/.amospro",
                "~/Library/Application Support/.AMOSLite",
            ],
            launchAgentLabels: ["com.atomic.lite", "com.atomic.pro"]
        ),
        SpywareSignature(
            name: "macOS.NimDoor (DPRK Nim-based backdoor)",
            processNames: ["nimdoor", "NimDoor", "GoogleChromeFramework_Helper", "ZoomBackgroundHelper"],
            bundleIdentifiers: ["com.zoom.background.helper"],
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/Application Support/.zoombackground",
            ],
            launchAgentLabels: ["com.zoom.background.helper"]
        ),
        SpywareSignature(
            name: "macOS.HiddenLotus (CryptoMiner-malware hybrid)",
            processNames: ["HiddenLotus", "hiddenlotus", "macupdater", "AppleSyncNotifier"],
            bundleIdentifiers: ["com.apple.syncnotifier"],
            filePaths: [
                "/Library/Application Support/.hiddenlotus",
                "~/Library/Application Support/.hiddenlotus",
            ],
            launchAgentLabels: ["com.apple.syncnotifier"]
        ),
        SpywareSignature(
            name: "OSX.XMRig CryptoJacker",
            processNames: ["xmrig", "XMRig", "minerd", "kdevtmpfsi", "kinsing", "minegate"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.xmrig",
                "/private/tmp/.xmrig",
                "~/Library/Application Support/.xmrig",
            ],
            launchAgentLabels: ["com.apple.miner", "com.miner.xmrig"]
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
