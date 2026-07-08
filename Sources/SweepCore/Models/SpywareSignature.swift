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
        // 2024-2025 macOS threat additions
        //
        // North Korea "Contagious Interview" cluster: BlueNoroff / Lazarus subgroups target
        // developers via fake job interviews and coding tests. The dropper is usually an npm
        // package (BeaverTail) that fetches InvisibleFerret. Both persist on macOS.
        SpywareSignature(
            // BeaverTail runs inside node from an npm package; matching on generic names like n2n
            // would false-positive on the legitimate p2p VPN of that name. Rely on the file paths
            // instead — the drop directory ~/.n2/ is the specific IOC.
            name: "BeaverTail (Contagious Interview)",
            processNames: ["beavertail", "BeaverTail"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.n2/",
                "~/Library/Application Support/.n2",
                "/private/tmp/beavertail",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // The InvisibleFerret payloads execute under python3 so process-name matching is
            // rarely useful — the strong IOCs are the dropped script paths in ~/.n2/, ~/.npl, ~/.p2.
            name: "InvisibleFerret (Contagious Interview)",
            processNames: ["invisibleferret", "InvisibleFerret"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.n2/pay",
                "~/.n2/bow",
                "~/.n2/adc",
                "~/.npl",
                "~/.p2",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FlexibleFerret",
            processNames: ["flexibleferret", "FlexibleFerret", "cameraaccess", "chromeupdate"],
            bundleIdentifiers: ["com.apple.cameraaccess", "com.apple.chromeupdate"],
            filePaths: [
                "~/Library/Caches/com.apple.cameraaccess",
                "~/.n2/",
            ],
            launchAgentLabels: ["com.apple.cameraaccess", "com.apple.chromeupdate"]
        ),
        // HZ Rat — 2024 Chinese-linked backdoor targeting WeChat / DingTalk users.
        SpywareSignature(
            name: "HZ Rat",
            processNames: ["hzrat", "HZRat", "OpenVPNConnect", "SafariSync"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/OpenVPNConnect",
                "/tmp/.hzrat",
            ],
            launchAgentLabels: ["com.openvpn.client.plist"]
        ),
        // JokerSpy — 2023-2024 modular backdoor with SwiftBelt post-exploitation.
        SpywareSignature(
            name: "JokerSpy",
            processNames: ["jokerspy", "JokerSpy", "xcc", "sh.py", "shared.dat"],
            bundleIdentifiers: ["com.apple.PrivateAgent"],
            filePaths: [
                "/Users/Shared/sh.py",
                "/Users/Shared/xcc",
                "/private/var/tmp/.jokerspy",
                "~/Library/Preferences/com.apple.PrivateAgent.plist",
            ],
            launchAgentLabels: ["com.apple.PrivateAgent"]
        ),
        // LightSpy — modular surveillance framework; macOS variant surfaced 2024.
        SpywareSignature(
            name: "LightSpy (macOS)",
            processNames: ["lightspy", "LightSpy", "macircloader", "LightService"],
            bundleIdentifiers: ["com.apple.WebKit.LightService"],
            filePaths: [
                "/private/var/tmp/.lightspy",
                "~/Library/Application Support/.lightspy",
            ],
            launchAgentLabels: []
        ),
        // RustDoor / Trellix / ThieCrocs — 2024 Rust-written macOS backdoor tied to ransomware ops.
        SpywareSignature(
            name: "RustDoor",
            processNames: ["rustdoor", "RustDoor", "Testx86_64", "Testarm64", "zshrc2",
                           "coreloader", "rustdown"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.rustdoor",
                "/tmp/zshrc2",
                "/private/tmp/.rustdoor",
                "~/.rustdoor",
            ],
            launchAgentLabels: ["com.apple.finder.plist2", "com.apple.rustdown"]
        ),
        // Odyssey Stealer — 2024-2025 AMOS fork widely distributed via ClickFix pages.
        SpywareSignature(
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey", "odyssey_stealer", "OdysseyInstaller"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
                "/tmp/Odyssey_installer",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        // MacSync Stealer — 2024 stealer marketed on Russian-speaking forums.
        SpywareSignature(
            name: "MacSync Stealer",
            processNames: ["MacSync", "macsync", "MacSyncStealer"],
            bundleIdentifiers: ["com.macsync.stealer"],
            filePaths: [
                "/private/tmp/.macsync",
                "~/Library/Application Support/.MacSync",
            ],
            launchAgentLabels: ["com.macsync.agent"]
        ),
        // Nova Stealer — 2024 Go-based infostealer, uses `osascript` for password prompts.
        SpywareSignature(
            name: "Nova Stealer",
            processNames: ["NovaStealer", "novastealer", "NovaAgent"],
            bundleIdentifiers: ["com.nova.stealer"],
            filePaths: [
                "/private/tmp/.nova",
                "~/Library/Application Support/.Nova",
            ],
            launchAgentLabels: ["com.nova.agent"]
        ),
        // Ledger Stealer — 2025 wallet-focused stealer distributed via fake dApps.
        SpywareSignature(
            name: "Ledger Stealer",
            processNames: ["LedgerStealer", "ledger_stealer", "LedgerHelper"],
            bundleIdentifiers: ["com.ledger.stealer"],
            filePaths: [
                "/private/tmp/.ledger_stealer",
                "~/Library/Application Support/.LedgerHelper",
            ],
            launchAgentLabels: ["com.ledger.helper"]
        ),
        // Ferret family follow-ons — FrostyFerret / DriftingFerret / EggheadFerret (2024).
        SpywareSignature(
            name: "FrostyFerret",
            processNames: ["FrostyFerret", "frostyferret", "ChromeUpdateAlert"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/ChromeUpdateAlert",
                "/private/tmp/.frostyferret",
            ],
            launchAgentLabels: []
        ),
        // XMRig macOS cryptominer — distributed inside cracked apps (Adobe/Autodesk cracks).
        // Not surveillance but classic Mac malware; users deserve a heads-up.
        SpywareSignature(
            name: "XMRig Cryptominer",
            processNames: ["xmrig", "XMRig", "com.apple.rphelper", "spotlightd",
                           "com.apple.WindowsServer", "com.apple.rpcsvchost"],
            bundleIdentifiers: ["com.apple.rphelper", "com.apple.rpcsvchost"],
            filePaths: [
                "/Library/Application Support/com.apple.rphelper",
                "~/Library/Application Support/com.apple.WindowsServer",
                "/private/tmp/.xmrig",
                "/tmp/xmrig",
            ],
            launchAgentLabels: ["com.apple.rphelper", "com.apple.rpcsvchost",
                                "com.apple.WindowsServer.plist"]
        ),
        // TodoSwift — 2024 Lazarus dropper masquerading as todo-list PDF viewer.
        SpywareSignature(
            name: "TodoSwift (Lazarus)",
            processNames: ["TodoSwift", "todoswift", "com.hnetwork.MonolithicView"],
            bundleIdentifiers: ["com.hnetwork.MonolithicView"],
            filePaths: ["/private/tmp/.todoswift"],
            launchAgentLabels: []
        ),
        // BlueNoroff CryptoCore / RustBucket variants (2024) — targets crypto exchange staff.
        SpywareSignature(
            name: "CryptoCore (BlueNoroff)",
            processNames: ["CryptoCore", "cryptocore", "SwiftLoader", "CryptoAssetManagement"],
            bundleIdentifiers: ["com.apple.CryptoAssetManagement"],
            filePaths: [
                "~/Library/Application Support/.cryptocore",
                "/private/var/tmp/.cryptocore",
            ],
            launchAgentLabels: ["com.apple.CryptoAssetManagement"]
        ),
        // Amos / Poseidon "ClickFix" variant — dropped via clipboard-injection CAPTCHA pages.
        // Process names like "update" and "install" alone would false-positive on many legitimate
        // installers; we match only on the distinctive names and rely on file-path IOCs for the rest.
        SpywareSignature(
            name: "AMOS ClickFix Variant",
            processNames: ["installer_script", "system_update", "MacOSHelper", "macos-update"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/update",
                "/tmp/install",
                "/tmp/installer_script",
                "/tmp/system_update",
                "/tmp/MacOSHelper",
            ],
            launchAgentLabels: []
        ),
        // 2024 "Perfctl" / Perfmon cryptojacker seen on macOS after cracked-software installs.
        SpywareSignature(
            name: "Perfctl Cryptojacker",
            processNames: ["perfctl", "Perfctl", "perfmon", "sh1", "wizard"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/.perf.c/",
                "/var/tmp/.perf.c/",
                "/usr/bin/perfctl",
                "~/.config/cron/perfcc",
            ],
            launchAgentLabels: ["com.perf.plist"]
        ),
        // TrickMo / TrickBot macOS module (2024) — banking trojan sibling.
        SpywareSignature(
            name: "TrickMo (macOS)",
            processNames: ["trickmo", "TrickMo", "com.google.androidfilehelper"],
            bundleIdentifiers: ["com.google.androidfilehelper"],
            filePaths: ["/private/tmp/.trickmo"],
            launchAgentLabels: ["com.google.androidfilehelper"]
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
        // 2024-2025 IOCs observed in ClickFix / Ferret / RustDoor / cryptojacker campaigns
        "com.apple.PrivateAgent",
        "com.apple.cameraaccess",
        "com.apple.chromeupdate",
        "com.apple.rphelper",
        "com.apple.rpcsvchost",
        "com.apple.finder.plist2",
        "com.apple.rustdown",
        "com.apple.WebKit.LightService",
        "com.apple.CryptoAssetManagement",
        "com.apple.macshare.plist",
        "com.apple.WindowsServer",   // Note: real is WindowServer (no 's')
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
        // 2024-2025 additions — process names observed in current-day campaigns
        "spotlightd",            // Real: mds (used by XMRig cryptojacker)
        "WindowsServer",         // Real: WindowServer (used by cryptojackers)
        "cameraaccess",          // FlexibleFerret
        "chromeupdate",          // FlexibleFerret
        "OpenVPNConnect",        // HZ Rat, unless it's the real OpenVPN app in /Applications
        "SafariHelper",          // RustBucket / Lazarus
        "SafariSync",            // HZ Rat
        "MonolithicView",        // TodoSwift dropper
        "MacOSHelper",           // AMOS ClickFix
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
