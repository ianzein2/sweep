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
        // DPRK "Contagious Interview" cluster (2023-2025) — fake recruiter campaigns drop
        // Python/JS/Nim payloads disguised as coding assessments or video conferencing helpers.
        SpywareSignature(
            name: "BeaverTail",
            processNames: ["BeaverTail", "beavertail", "MiroTalk", "FCCCall", "FreeConference"],
            bundleIdentifiers: ["com.mirotalk.app", "com.fcccall.app"],
            filePaths: [
                "/private/tmp/.npl",
                "/private/tmp/.n2",
                "~/Library/Application Support/.BeaverTail",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["InvisibleFerret", "invisibleferret", "ssh_assistant", "ssh-config"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.npl",
                "~/.n2",
                "/private/tmp/.invisible",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FrostyFerret",
            processNames: ["FrostyFerret", "frostyferret", "ChromeUpdate", "ChromeUpdateAlert"],
            bundleIdentifiers: ["com.google.chrome.update"],
            filePaths: [
                "/private/tmp/.frostyferret",
                "~/Library/Application Support/.FrostyFerret",
            ],
            launchAgentLabels: ["com.google.chrome.update.agent"]
        ),
        SpywareSignature(
            name: "FriendlyFerret",
            processNames: ["FriendlyFerret", "friendlyferret", "set_path"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.friendlyferret"],
            launchAgentLabels: ["com.apple.set_path"]
        ),
        SpywareSignature(
            name: "FlexibleFerret",
            processNames: ["FlexibleFerret", "flexibleferret", "FerretInstaller", "ChromeUpdater"],
            bundleIdentifiers: ["com.apple.ChromeUpdater"],
            filePaths: [
                "/private/tmp/.flexibleferret",
                "~/Library/Application Support/.FlexibleFerret",
            ],
            launchAgentLabels: ["com.apple.chromeupdate"]
        ),
        SpywareSignature(
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "GoogIeHelper", "Trojan.NimDoor", "ZoomVideo"],
            bundleIdentifiers: ["com.google.helper", "us.zoom.video.update"],
            filePaths: [
                "/private/tmp/.NimDoor",
                "~/.Trash/NimDoor",
                "~/Library/Application Support/.nimdoor",
                "/tmp/coreaudiod",
            ],
            launchAgentLabels: ["com.google.helper", "com.zoom.video.helper"]
        ),
        SpywareSignature(
            name: "PylangGhost",
            processNames: ["PylangGhost", "pylangghost", "pyc_compiler", "PythonGhost"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.pylang",
                "~/Library/Application Support/.PylangGhost",
            ],
            launchAgentLabels: []
        ),
        // ZuRu trojan family — distributed via SEO-poisoned downloads (iTerm2, Termius, NetSpot etc.)
        SpywareSignature(
            name: "ZuRu",
            processNames: ["ZuRu", "zuru", "g.ssl", "GoogleUpdate", "libcrypto.2.dylib"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.zuru",
                "/Users/Shared/com.apple.softwareupdated",
                "/private/tmp/.fseventsd",
                "~/Library/Caches/.zuru",
            ],
            launchAgentLabels: ["com.apple.usbmuxd.plist", "com.google.softwareupdate"]
        ),
        // JOKERSPY / XCC (Mac.BackDoor.Jokerspy)
        SpywareSignature(
            name: "JOKERSPY",
            processNames: ["JOKERSPY", "jokerspy", "xcc", "XCC", "shared.dat"],
            bundleIdentifiers: ["com.apple.xcc", "com.xcc.service"],
            filePaths: [
                "/Users/Shared/bin/shared.dat",
                "/Users/Shared/.local",
                "/private/tmp/.jokerspy",
            ],
            launchAgentLabels: ["com.apple.xcc.plist"]
        ),
        // HZRat (Chinese-language backdoor, 2024)
        SpywareSignature(
            name: "HZRat",
            processNames: ["HZRat", "hzrat", "OpenVPNConnect", "openvpnhelper", "OpenVPN"],
            bundleIdentifiers: ["com.openvpn.connect.helper"],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.HZRat",
                "~/Library/LaunchAgents/com.openvpn.connect.daemon.plist",
            ],
            launchAgentLabels: ["com.openvpn.connect.daemon"]
        ),
        // Gimmick / CherryPie (Chinese APT, Storm Cloud)
        SpywareSignature(
            name: "Gimmick (Storm Cloud)",
            processNames: ["Gimmick", "gimmick", "CherryPie", "cherrypie", "PLIST"],
            bundleIdentifiers: ["com.apple.softwareupdateagent"],
            filePaths: [
                "/Library/PrivateFrameworks/.gimmick",
                "~/Library/Preferences/PlistBuddy",
            ],
            launchAgentLabels: ["com.apple.softwareupdateagent"]
        ),
        // Geacon / Geacon Pro (Cobalt Strike Beacon port to Go for macOS)
        SpywareSignature(
            name: "Geacon (Cobalt Strike)",
            processNames: ["geacon", "Geacon", "geacon_pro", "GeaconPro", "stage1", "beacon"],
            bundleIdentifiers: ["com.geacon.agent"],
            filePaths: [
                "/private/tmp/.geacon",
                "/tmp/stage1",
                "~/Library/Application Support/.beacon",
            ],
            launchAgentLabels: ["com.apple.cs.csloggingd"]
        ),
        // RustDoor (DPRK Rust backdoor, 2024)
        SpywareSignature(
            name: "RustDoor",
            processNames: ["RustDoor", "rustdoor", "rs_test", "ChromeUpdater.app"],
            bundleIdentifiers: ["com.google.chrome.updater"],
            filePaths: [
                "/private/tmp/.rustdoor",
                "/Users/Shared/.rustdoor",
                "~/.Trash/RustDoor",
                "/Library/PrivateFrameworks/RustDoor.framework",
            ],
            launchAgentLabels: ["com.google.chrome.updater"]
        ),
        // KEYPLUG.mac (APT41 / Earth Baku, 2024)
        SpywareSignature(
            name: "KEYPLUG.mac",
            processNames: ["KEYPLUG", "keyplug", "keyplug_mac", "k3yp1ug"],
            bundleIdentifiers: ["com.apple.keyplug"],
            filePaths: [
                "/private/var/tmp/.keyplug",
                "~/Library/Application Support/.keyplug",
            ],
            launchAgentLabels: []
        ),
        // PasivRobber (China-linked TLS-based exfil, 2025)
        SpywareSignature(
            name: "PasivRobber",
            processNames: ["PasivRobber", "pasivrobber", "wsus", "wsusd"],
            bundleIdentifiers: ["com.passivrobber.agent"],
            filePaths: [
                "/private/var/tmp/.pasivrobber",
                "/Library/.wsus",
            ],
            launchAgentLabels: ["com.apple.wsus.plist"]
        ),
        // SparkCat / SparkKitty (clipboard + OCR-based crypto stealer, 2024-2025)
        SpywareSignature(
            name: "SparkCat / SparkKitty",
            processNames: ["SparkCat", "sparkcat", "SparkKitty", "sparkkitty", "OCREngine"],
            bundleIdentifiers: ["com.sparkcat.agent", "com.sparkkitty.agent"],
            filePaths: [
                "/private/tmp/.sparkcat",
                "~/Library/Application Support/.SparkCat",
                "~/Library/Application Support/.SparkKitty",
            ],
            launchAgentLabels: ["com.sparkcat.service", "com.sparkkitty.service"]
        ),
        // ObjCShellz, NokNok already present — add MacMa (Mac.BackDoor.MacMa / DazzleSpy variant)
        SpywareSignature(
            name: "MacMa",
            processNames: ["MacMa", "macma", "UserAgent", "useragentd"],
            bundleIdentifiers: ["com.apple.UserAgent"],
            filePaths: [
                "/Library/.com.apple.UserAgent",
                "~/Library/Application Support/.UserAgent",
                "/Library/LaunchAgents/com.UserAgent.va.plist",
            ],
            launchAgentLabels: ["com.UserAgent.va", "com.apple.UserAgent"]
        ),
        // Adware / harvester families still active in 2025
        SpywareSignature(
            name: "AdLoad",
            processNames: ["AdLoad", "adload", "InitialSearch", "MyShopBot", "OperativeIngredient",
                          "ConnectionCachet", "PracticalDoor", "EnhancedDial"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/Application Support/com.AdLoad",
                "~/Library/Application Support/com.AdLoad",
                "/Library/LaunchAgents/com.AdLoad.plist",
            ],
            launchAgentLabels: ["com.AdLoad", "com.MyShopBot"]
        ),
        SpywareSignature(
            name: "Pirrit",
            processNames: ["Pirrit", "pirrit", "macpirrit", "PirritDesktop"],
            bundleIdentifiers: ["com.pirrit.desktop"],
            filePaths: [
                "/Library/Application Support/.pirrit",
                "~/Library/LaunchAgents/com.pirrit.plist",
            ],
            launchAgentLabels: ["com.pirrit"]
        ),
        SpywareSignature(
            name: "Shlayer",
            processNames: ["Shlayer", "shlayer", "Player.app", "AdobeFlashPlayer"],
            bundleIdentifiers: ["com.adobe.flashplayer.installmanager"],
            filePaths: [
                "/private/tmp/.shlayer",
                "/tmp/Player.app",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Bundlore",
            processNames: ["Bundlore", "bundlore", "InstallMac", "InstallCore"],
            bundleIdentifiers: ["com.bundlore.installer"],
            filePaths: [
                "/Library/Application Support/.bundlore",
                "~/Library/Application Support/.bundlore",
            ],
            launchAgentLabels: ["com.bundlore.installer"]
        ),
        // BadBazaar / SilkBean class stalkerware (originally Android, now cross-platform companion components)
        SpywareSignature(
            name: "BadBazaar Companion",
            processNames: ["BadBazaar", "badbazaar", "SilkBean", "silkbean"],
            bundleIdentifiers: ["com.badbazaar.companion"],
            filePaths: [
                "~/Library/Application Support/.BadBazaar",
                "/private/tmp/.silkbean",
            ],
            launchAgentLabels: ["com.badbazaar.service"]
        ),
        // CrazyEvil (Russian-speaking traffer crew — distributes AMOS/Lummac/Atomic-derived stealers,
        // 2024-2025). Drops a renamed Atomic binary via fake meeting/Web3 lures.
        SpywareSignature(
            name: "CrazyEvil Loader",
            processNames: ["CrazyEvil", "crazyevil", "Meeten", "ClickFix", "ClickFixer", "GatherUp"],
            bundleIdentifiers: ["com.meeten.app", "com.gatherup.app"],
            filePaths: [
                "/private/tmp/.crazyevil",
                "~/Downloads/Meeten.dmg",
                "~/Library/Application Support/.Meeten",
            ],
            launchAgentLabels: ["com.meeten.helper"]
        ),
        // RealtimeSpy variant already present. Add ZipLine (HermitCrab APT, 2025)
        SpywareSignature(
            name: "ZipLine",
            processNames: ["ZipLine", "zipline", "zlpd", "zl_agent"],
            bundleIdentifiers: [],
            filePaths: ["/private/var/tmp/.zipline", "/Library/.zipline"],
            launchAgentLabels: ["com.apple.ziplined"]
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
        // Labels seen in 2024-2025 macOS implants masquerading as Apple components
        "com.apple.set_path",
        "com.apple.chromeupdate",
        "com.apple.usbmuxd.plist",
        "com.apple.UserAgent",
        "com.apple.softwareupdateagent",
        "com.apple.softwareupdated.helper",
        "com.apple.cs.csloggingd",
        "com.apple.wsus.plist",
        "com.apple.xcc",
        "com.apple.xcc.plist",
        "com.apple.keyplug",
        "com.apple.ziplined",
        // Common camouflage patterns from open-source RAT templates
        "com.apple.system.helper",
        "com.apple.systemui.agent",
        "com.apple.timemachine.helper",
        "com.apple.spotlight.helper",
        "com.apple.airport.helper",
        "com.apple.terminal.helper",
        "com.apple.shortcuts.helper",
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
        // Names observed in 2024-2025 macOS malware mimicking Apple binaries
        "GoogIeHelper",          // Capital-i homoglyph for "GoogleHelper"
        "ChromeUpdater",         // Used by RustDoor, ZuRu, FlexibleFerret
        "ChromeUpdateAlert",     // FrostyFerret lure
        "GoogleUpdate",          // ZuRu, RustDoor (real Chrome updater is GoogleSoftwareUpdateAgent)
        "useragentd",            // MacMa
        "UserAgent",             // MacMa (when running from non-system paths)
        "fseventsd_helper",      // Real: fseventsd
        "wsusd",                 // Windows-update naming, never legitimate on macOS
        "appleupdated",          // Real: softwareupdated
        "mdworker_helper",       // Real: mdworker / mdworker_shared
        "bluetoothd_helper",     // Real: bluetoothd
        "syslogd_helper",        // Real: syslogd
        "opendirectoryd_helper", // Real: opendirectoryd
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
