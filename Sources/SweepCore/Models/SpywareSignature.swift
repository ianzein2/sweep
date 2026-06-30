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
        // 2024-2026 additions — DPRK / Lazarus / BlueNoroff "Contagious Interview" cluster
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            processNames: ["beavertail", "BeaverTail", "p.js", "test.js", "ssh-agent.js"],
            bundleIdentifiers: [],
            // BeaverTail is delivered as a JavaScript payload in trojanized npm packages,
            // typically writing its stage-2 (InvisibleFerret) to these paths.
            filePaths: [
                "~/.npl",
                "~/.n2",
                "~/Library/Application Support/.BeaverTail",
                "/private/tmp/.beavertail",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret (Contagious Interview)",
            processNames: ["invisibleferret", "InvisibleFerret", "pay.py", "payload.py"],
            bundleIdentifiers: [],
            // InvisibleFerret is a Python backdoor that BeaverTail drops; it persists in the
            // user's home directory and exfiltrates browser data, keychains, and crypto wallets.
            filePaths: [
                "~/.n2/pay",
                "~/.n2/bow",
                "~/.n2/mlip",
                "~/.n2/lap",
                "~/.n2/adc",
                "~/.npl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FlexibleFerret (Lazarus, 2025)",
            processNames: ["FlexibleFerret", "flexibleferret", "ChromeUpdate", "FROSTYFERRET_UI"],
            bundleIdentifiers: ["com.zoom.chromeupdate"],
            filePaths: [
                "~/Library/Application Support/com.zoom.us.update",
                "/private/tmp/.flexibleferret",
            ],
            launchAgentLabels: ["com.zoom.us.update", "com.zoom.chromeupdate"]
        ),
        SpywareSignature(
            name: "FerretMacOS (DPRK, 2025)",
            processNames: ["FROSTYFERRET", "FRIENDLYFERRET", "MULTI_FROSTYFERRET", "ChromeUpdater"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/com.apple.UpdateChecker",
                "~/Library/Caches/com.apple.UpdateChecker",
            ],
            launchAgentLabels: ["com.apple.updatechecker"]
        ),
        SpywareSignature(
            name: "TodoSwift (DPRK, 2024)",
            processNames: ["TodoSwift", "todoswift", "todo_helper"],
            bundleIdentifiers: ["com.todoswift.app"],
            filePaths: [
                "~/Library/Application Support/.TodoSwift",
                "/private/tmp/.todoswift",
            ],
            launchAgentLabels: ["com.todoswift.agent"]
        ),
        SpywareSignature(
            name: "RustyAttr (Lazarus, 2024)",
            processNames: ["rustyattr", "RustyAttr", "pdf_viewer", "JobDescription"],
            bundleIdentifiers: ["com.cybertool.pdf"],
            filePaths: [
                "~/Library/Application Support/.RustyAttr",
                "/private/tmp/.rustyattr",
            ],
            launchAgentLabels: ["com.cybertool.agent"]
        ),
        SpywareSignature(
            name: "HiddenRisk (BlueNoroff, 2024)",
            processNames: ["HiddenRisk", "hiddenrisk", "RustDoorAgent", "growth"],
            bundleIdentifiers: ["com.growth.app", "com.cryptosrv.app"],
            filePaths: [
                "~/Library/LaunchAgents/com.googl.update.plist",
                "~/.fseventsd",
                "~/Library/Application Support/.HiddenRisk",
                "/private/tmp/.hiddenrisk",
            ],
            // Note: dot before "googl" — typosquats Google's update label as a persistence trick.
            launchAgentLabels: ["com.googl.update", "com.apple.softwareupdater.helper"]
        ),
        SpywareSignature(
            name: "WaterPlum / OtterCookie (DPRK, 2025)",
            processNames: ["OtterCookie", "ottercookie", "waterplum", "Cookieserver"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.OtterCookie",
                "/private/tmp/.ottercookie",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "RustDoor / ThiefBucket (2024)",
            processNames: ["RustDoor", "rustdoor", "ThiefBucket", "thiefbucket"],
            bundleIdentifiers: ["com.apple.systempreferences.helper.rustdoor"],
            filePaths: [
                "/private/tmp/.test",
                "/private/tmp/.rustdoor",
                "~/Library/Application Support/.rustdoor",
            ],
            launchAgentLabels: ["com.apple.rustdoor", "com.apple.systempreferences.helper"]
        ),
        // 2024-2026 additions — modern infostealers and droppers
        SpywareSignature(
            name: "Banshee Reborn (Banshee 2.0, 2024-2025)",
            processNames: ["BansheeReborn", "banshee_2", "bsh2", "BansheeUI2"],
            bundleIdentifiers: ["com.banshee2.stealer", "com.bansheeReborn.app"],
            filePaths: [
                "/private/tmp/.banshee2",
                "/private/tmp/.bsh2",
                "~/Library/Application Support/.BansheeReborn",
            ],
            launchAgentLabels: ["com.banshee2.service", "com.bansheeReborn.agent"]
        ),
        SpywareSignature(
            name: "PSEUDOMANUSCRYPT macOS (2024)",
            processNames: ["pseudomanuscrypt", "PseudoManuscrypt", "winlogon_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.pmscript",
                "/private/tmp/.pmscript",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "HZ Rat macOS (2024)",
            processNames: ["hzrat", "HZRat", "OpenVPNConnect"],
            bundleIdentifiers: ["com.macos.openvpn-helper"],
            // HZ Rat for macOS was distributed inside a trojanized OpenVPN Connect installer.
            filePaths: [
                "~/Library/Application Support/.openvpn",
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.hzrat",
            ],
            launchAgentLabels: ["com.macos.openvpn-helper", "com.openvpn.update"]
        ),
        SpywareSignature(
            name: "Tonic Stealer (2024-2025)",
            processNames: ["Tonic", "tonic_stealer", "TonicHelper"],
            bundleIdentifiers: ["com.tonic.stealer", "com.tonic.agent"],
            filePaths: [
                "/private/tmp/.tonic",
                "~/Library/Application Support/.Tonic",
            ],
            launchAgentLabels: ["com.tonic.service"]
        ),
        SpywareSignature(
            name: "ReaderUpdate (2024-2025)",
            processNames: ["ReaderUpdate", "reader_update", "ReaderHelper"],
            bundleIdentifiers: ["com.reader.update.helper"],
            filePaths: [
                "~/Library/Application Support/.ReaderUpdate",
                "~/Library/Application Support/Reader",
            ],
            launchAgentLabels: ["com.reader.update", "com.reader.helper"]
        ),
        SpywareSignature(
            name: "Crystalray (2024)",
            processNames: ["crystalray", "Crystalray", "platypus_loader", "sliver_macos"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.crystal",
                "~/Library/Application Support/.crystalray",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "LightSpy macOS (2024)",
            processNames: ["lightspy", "LightSpy", "ircbot", "macos_audio"],
            bundleIdentifiers: [],
            // LightSpy on macOS uses a modular plugin architecture and stages plugins under hidden dirs.
            filePaths: [
                "~/Library/Application Support/.lightspy",
                "/private/var/tmp/.ircbot",
                "/private/var/tmp/.macos_plugins",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "PEAKLIGHT macOS variant (2024)",
            processNames: ["peaklight", "PEAKLIGHT", "shadowlogger"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.peaklight",
                "~/Library/Application Support/.peaklight",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "MISTPEN macOS (2024)",
            processNames: ["mistpen", "MISTPEN", "burnbook_loader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.mistpen",
                "~/Library/Application Support/.mistpen",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "HotPage Adware/Spyware (2024)",
            processNames: ["hotpage", "HotPage", "HotPageHelper"],
            bundleIdentifiers: ["com.hotpage.helper"],
            filePaths: [
                "~/Library/Application Support/.HotPage",
            ],
            launchAgentLabels: ["com.hotpage.helper"]
        ),
        SpywareSignature(
            name: "Salvador Stealer (2024)",
            processNames: ["salvador", "Salvador", "salvador_stealer"],
            bundleIdentifiers: ["com.salvador.stealer"],
            filePaths: [
                "/private/tmp/.salvador",
                "~/Library/Application Support/.Salvador",
            ],
            launchAgentLabels: ["com.salvador.agent"]
        ),
        SpywareSignature(
            name: "NodeStealer macOS port (2024)",
            processNames: ["nodestealer", "NodeStealer", "node_stealer_macos"],
            bundleIdentifiers: ["com.nodestealer.agent"],
            filePaths: [
                "/private/tmp/.nodestealer",
                "~/Library/Application Support/.NodeStealer",
            ],
            launchAgentLabels: ["com.nodestealer.service"]
        ),
        SpywareSignature(
            name: "Lumma Stealer macOS port (2024-2025)",
            processNames: ["lumma", "LummaC2", "lumma_stealer", "lumma_mac"],
            bundleIdentifiers: ["com.lumma.stealer"],
            filePaths: [
                "/private/tmp/.lumma",
                "~/Library/Application Support/.Lumma",
            ],
            launchAgentLabels: ["com.lumma.agent"]
        ),
        SpywareSignature(
            name: "FrigidStealer (2024-2025)",
            processNames: ["FrigidStealer", "frigid", "frigid_stealer", "DownloadApp"],
            bundleIdentifiers: ["com.frigid.stealer"],
            // Distributed through fake browser update lures (ClearFake / SmartApeSG).
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.Frigid",
                "~/Downloads/DownloadApp.app",
            ],
            launchAgentLabels: ["com.frigid.service"]
        ),
        SpywareSignature(
            name: "AMOS v2 / Atomic 2.0 (2024-2025)",
            processNames: ["amos2", "AMOSv2", "AtomicStealer2", "amos_v2", "AppleScript-helper"],
            bundleIdentifiers: ["com.amos.v2", "com.atomic.stealer.v2"],
            // AMOS v2 dropped the AppleScript-based password prompt and added persistence + a builder panel.
            filePaths: [
                "/private/tmp/AppleScript-helper",
                "/private/tmp/.amos2",
                "~/Library/Application Support/.amos2",
            ],
            launchAgentLabels: ["com.amos.v2.agent", "com.atomic.v2.service"]
        ),
        SpywareSignature(
            name: "Lazarus LinkPro (2024)",
            processNames: ["linkpro", "LinkPro", "link_pro_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.linkpro",
                "~/Library/Application Support/.LinkPro",
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
        // 2024-2025 stealer/loader campaigns observed in the wild
        "com.apple.softwareupdater.helper",  // HiddenRisk / BlueNoroff
        "com.apple.updatechecker",            // FerretMacOS
        "com.apple.rustdoor",                 // RustDoor
        "com.apple.xpcd",                     // not a real Apple daemon
        "com.apple.coreservicesd",            // mimics coreservicesd
        "com.apple.timed.helper",             // not real
        "com.apple.networkd.helper",          // not real
        "com.apple.cloudd.sync",              // not real
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
