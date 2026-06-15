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
        // 2024-2026 macOS malware families documented by Objective-See, Mandiant,
        // SentinelOne, Jamf, Kaspersky, Sekoia, and Unit 42.
        SpywareSignature(
            name: "NimDoor (DPRK)",
            processNames: ["NimDoor", "nimdoor", "googkeyhelper", "GoogleSyncHelper", "CoreKitAgent"],
            bundleIdentifiers: ["com.google.update", "com.zoom.helper"],
            filePaths: [
                "~/.config/zoom/.helper",
                "/private/tmp/.nimdoor",
                "~/Library/LaunchAgents/com.google.update.plist",
            ],
            launchAgentLabels: ["com.google.update", "com.zoom.helper"]
        ),
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid", "SafariUpdater", "ChromeUpdate"],
            bundleIdentifiers: ["com.apple.safariupdate", "com.safari.update"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Downloads/Safari Update.dmg",
                "~/Library/Application Support/.frigid",
            ],
            launchAgentLabels: ["com.safari.updater"]
        ),
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            processNames: ["BeaverTail", "beavertail", "vid_install", "Visual Studio Code Helper"],
            bundleIdentifiers: ["com.beavertail.agent"],
            filePaths: [
                "/private/tmp/.beaver",
                "~/Library/Application Support/.beavertail",
                "~/.npm/_logs/.beaver",
            ],
            launchAgentLabels: ["com.beaver.service"]
        ),
        SpywareSignature(
            name: "InvisibleFerret (DPRK)",
            processNames: ["InvisibleFerret", "invisibleferret", "pyvenv-cfg", "tigerWalker"],
            bundleIdentifiers: ["com.invisible.ferret"],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/Application Support/.ferret",
                "~/.pylib/.ferret",
            ],
            launchAgentLabels: ["com.invisible.ferret"]
        ),
        SpywareSignature(
            name: "FlexibleFerret (DPRK)",
            processNames: ["FlexibleFerret", "flexibleferret", "FROSTYFERRET_UI", "ChromeUpdate",
                           "CameraAccess", "VirtualMeeting"],
            bundleIdentifiers: ["com.apple.ChromeUpdate"],
            filePaths: [
                "/private/tmp/.flexibleferret",
                "~/Library/.ferretcache",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "HZ RAT",
            processNames: ["HZ-RAT", "hzrat", "Helper Tool", "OpenVPN Helper"],
            bundleIdentifiers: ["com.openvpn.helper.tool"],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.HZRat",
            ],
            launchAgentLabels: ["com.openvpn.helpertool"]
        ),
        SpywareSignature(
            name: "OdysseyStealer (AMOS successor)",
            processNames: ["Odyssey", "odyssey_stealer", "OdysseyInstaller", "odyssey_payload"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
                "/private/tmp/AppleScript-*.scpt",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        SpywareSignature(
            name: "NotLockBit (macOS ransomware)",
            processNames: ["NotLockBit", "notlockbit", "lockbit_macos", "lbb_pass"],
            bundleIdentifiers: ["com.lockbit.macos"],
            filePaths: [
                "/private/tmp/.notlockbit",
                "/private/tmp/lbb_pass.txt",
                "~/Library/Application Support/.NotLockBit",
            ],
            launchAgentLabels: ["com.lockbit.service"]
        ),
        SpywareSignature(
            name: "JokerSpy",
            processNames: ["xcc", "JokerSpy", "sh.py", "shared.dat"],
            bundleIdentifiers: ["xyz.xcc.xcc"],
            filePaths: [
                "/Users/Shared/sh.py",
                "/Users/Shared/shared.dat",
                "/private/tmp/.xcc",
                "~/Library/LaunchAgents/com.apple.xcc.plist",
            ],
            launchAgentLabels: ["com.apple.xcc", "xyz.xcc"]
        ),
        SpywareSignature(
            name: "MystRodX (DPRK)",
            processNames: ["MystRodX", "mystrodx", "rodx", "PostgreSQLHelper"],
            bundleIdentifiers: ["com.postgresql.helper"],
            filePaths: [
                "/private/tmp/.mystrodx",
                "~/Library/PostgreSQL/.helper",
            ],
            launchAgentLabels: ["com.postgresql.helper"]
        ),
        SpywareSignature(
            name: "RustyAttr (Lazarus)",
            processNames: ["RustyAttr", "rustyattr", "Tauri", "Bonjour Service"],
            bundleIdentifiers: ["com.bonjour.helper"],
            filePaths: [
                "/private/tmp/.rusty",
                "~/Library/Application Support/.RustyAttr",
            ],
            launchAgentLabels: ["com.bonjour.helper"]
        ),
        SpywareSignature(
            name: "MoonPeak",
            processNames: ["MoonPeak", "moonpeak", "moonshell"],
            bundleIdentifiers: ["com.moonpeak.agent"],
            filePaths: [
                "/private/tmp/.moonpeak",
                "~/Library/Application Support/.moonpeak",
            ],
            launchAgentLabels: ["com.moonpeak.service"]
        ),
        SpywareSignature(
            name: "Cuckoo Stealer 2.0",
            processNames: ["Cuckoo2", "cuckoo2", "DumpMedia", "TuneSolo"],
            bundleIdentifiers: ["com.dumpmedia.helper", "com.tunesolo.helper"],
            filePaths: [
                "/private/tmp/.cuckoo2",
                "~/Library/Application Support/.Cuckoo2",
            ],
            launchAgentLabels: ["com.cuckoo2.service"]
        ),
        SpywareSignature(
            name: "Crystal Stealer",
            processNames: ["CrystalStealer", "crystal_stealer", "CrystalInstaller"],
            bundleIdentifiers: ["com.crystal.stealer"],
            filePaths: [
                "/private/tmp/.crystal",
                "~/Library/Application Support/.Crystal",
            ],
            launchAgentLabels: ["com.crystal.agent"]
        ),
        SpywareSignature(
            name: "Lumma macOS",
            processNames: ["Lumma", "lumma_mac", "LummaC2", "LummaCommander"],
            bundleIdentifiers: ["com.lumma.stealer"],
            filePaths: [
                "/private/tmp/.lumma",
                "~/Library/Application Support/.Lumma",
            ],
            launchAgentLabels: ["com.lumma.service"]
        ),
        SpywareSignature(
            name: "DigiStealer (DigitalPulse)",
            processNames: ["DigiStealer", "digistealer", "digitalpulse"],
            bundleIdentifiers: ["com.digistealer.agent"],
            filePaths: [
                "/private/tmp/.digi",
                "~/Library/Application Support/.DigiStealer",
            ],
            launchAgentLabels: ["com.digistealer.service"]
        ),
        SpywareSignature(
            name: "Apothic SSH (Lazarus)",
            processNames: ["ApothicSSH", "apothic", "sshd-helper"],
            bundleIdentifiers: ["com.openssh.helper"],
            filePaths: [
                "/private/tmp/.apothic",
                "~/Library/Application Support/.Apothic",
                "/Library/LaunchDaemons/com.openssh.helperd.plist",
            ],
            launchAgentLabels: ["com.openssh.helperd"]
        ),
        SpywareSignature(
            name: "MacMa (DazzleSpy v2)",
            processNames: ["MacMa", "macma", "UserAgent", "softwareupdated_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/LaunchDaemons/com.apple.softwareupdate.daemon.plist",
                "~/Library/Preferences/.UserAgent",
                "/private/tmp/.macma",
            ],
            launchAgentLabels: ["com.apple.softwareupdate.daemon", "com.apple.useragent"]
        ),
        SpywareSignature(
            name: "ObjCShellz v2",
            processNames: ["objcshellz2", "ObjCShellzHelper", "macshellz"],
            bundleIdentifiers: [],
            filePaths: ["/private/var/tmp/.objcshell2"],
            launchAgentLabels: ["com.apple.macshellz"]
        ),
        SpywareSignature(
            name: "Hidden Risk (PylotMcKenzie / DPRK)",
            processNames: ["HiddenRisk", "PylotMcKenzie", "pylot", "growth"],
            bundleIdentifiers: ["com.growth.helper"],
            filePaths: [
                "/Library/LaunchDaemons/com.growth.helper.plist",
                "/private/tmp/.hiddenrisk",
            ],
            launchAgentLabels: ["com.growth.helper"]
        ),
        SpywareSignature(
            name: "BlueNoroff RustyAttr",
            processNames: ["rustyattr", "BlueNoroffHelper", "ZoomClientPlugin"],
            bundleIdentifiers: ["us.zoom.clientplugin"],
            filePaths: [
                "/private/tmp/.bluenoroff",
                "~/Library/Application Support/.BlueNoroff",
            ],
            launchAgentLabels: ["us.zoom.clientplugin"]
        ),
        SpywareSignature(
            name: "TrollStealer (Kimsuky)",
            processNames: ["TrollStealer", "trollstealer", "AdobeARMHelper"],
            bundleIdentifiers: ["com.adobe.arm.helper"],
            filePaths: [
                "/private/tmp/.trollstealer",
                "~/Library/Application Support/.TrollStealer",
            ],
            launchAgentLabels: ["com.adobe.arm.helper"]
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "processhub", "applehub"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "/private/tmp/.processhub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub"]
        ),
        SpywareSignature(
            name: "PostalKitty",
            processNames: ["PostalKitty", "postalkitty", "PostalHelper", "MailLink"],
            bundleIdentifiers: ["com.postal.kitty"],
            filePaths: [
                "/private/tmp/.postalkitty",
                "~/Library/Application Support/.PostalKitty",
            ],
            launchAgentLabels: ["com.postal.kitty"]
        ),
        SpywareSignature(
            name: "RustBucket v2",
            processNames: ["RustBucket2", "rustbucket2", "PDFViewer", "AcrobatPDF"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.rustbucket2",
                "~/Library/Metadata/.system_pdf",
            ],
            launchAgentLabels: ["com.apple.pdfviewer.helper"]
        ),
        SpywareSignature(
            name: "FerretRAT (DPRK)",
            processNames: ["FerretRAT", "ferretrat", "Slack Helper Updater"],
            bundleIdentifiers: ["com.slack.helper.updater"],
            filePaths: [
                "/private/tmp/.ferret-rat",
                "~/Library/.ferretrat",
            ],
            launchAgentLabels: ["com.slack.helper.updater"]
        ),
        SpywareSignature(
            name: "TigerWalker (Sapphire Stealer macOS)",
            processNames: ["TigerWalker", "tigerwalker", "sapphire_mac"],
            bundleIdentifiers: ["com.sapphire.macos"],
            filePaths: [
                "/private/tmp/.tigerwalker",
                "~/Library/Application Support/.Sapphire",
            ],
            launchAgentLabels: ["com.sapphire.service"]
        ),
        // Commercial mercenary spyware
        SpywareSignature(
            name: "OSX.Triangulation",
            processNames: ["triangulation_agent", "BackupAgent2"],
            bundleIdentifiers: [],
            filePaths: ["/private/var/tmp/.triangulation"],
            launchAgentLabels: ["com.apple.backupagent"]
        ),
        SpywareSignature(
            name: "Reign (QuaDream)",
            processNames: ["reign", "QuaDream", "kingsfish", "Reign"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.reign",
                "/private/var/tmp/.kingsfish",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Hermit (RCS Lab)",
            processNames: ["hermit_agent", "rcs_helper"],
            bundleIdentifiers: [],
            filePaths: ["/private/var/tmp/.hermit"],
            launchAgentLabels: ["com.rcs.agent"]
        ),
        // Modern stalkerware (2024-2026)
        SpywareSignature(
            name: "Onemonitar / OneSpy",
            processNames: ["onemonitar", "OneMonitar", "OneSpy", "onespy"],
            bundleIdentifiers: ["com.onemonitar.agent", "com.onespy.agent"],
            filePaths: [
                "~/Library/Application Support/.OneMonitar",
                "~/Library/Application Support/OneSpy",
            ],
            launchAgentLabels: ["com.onemonitar.service", "com.onespy.service"]
        ),
        SpywareSignature(
            name: "Bark (parental/stalkerware variant)",
            processNames: ["BarkAgent", "bark_helper"],
            bundleIdentifiers: ["com.bark.agent"],
            filePaths: ["~/Library/Application Support/.Bark"],
            launchAgentLabels: ["com.bark.service"]
        ),
        SpywareSignature(
            name: "uMobix",
            processNames: ["umobix", "uMobix", "umagent"],
            bundleIdentifiers: ["com.umobix.agent"],
            filePaths: ["~/Library/Application Support/.uMobix"],
            launchAgentLabels: ["com.umobix.service"]
        ),
        SpywareSignature(
            name: "Cocospy 2.0 / Spynger",
            processNames: ["spynger", "Spynger", "cocospyAgent2"],
            bundleIdentifiers: ["com.spynger.agent"],
            filePaths: ["~/Library/Application Support/.Spynger"],
            launchAgentLabels: ["com.spynger.service"]
        ),
        SpywareSignature(
            name: "iSpyoo",
            processNames: ["ispyoo", "iSpyoo", "isp_agent"],
            bundleIdentifiers: ["com.ispyoo.agent"],
            filePaths: ["~/Library/Application Support/.iSpyoo"],
            launchAgentLabels: ["com.ispyoo.service"]
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
