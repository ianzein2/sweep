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
        // DPRK / APT-linked macOS malware (2024-2026)
        SpywareSignature(
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "GoogIe LLC", "GoogleDrive", "ZoomClient", "ZoomUpdate"],
            bundleIdentifiers: ["com.nimdoor.agent"],
            filePaths: [
                "/private/var/tmp/.nimdoor",
                "~/Library/Application Support/.nimdoor",
                "~/Library/LaunchAgents/com.google.keystone.agent.plist",
                "/tmp/.GoogIe",
            ],
            launchAgentLabels: ["com.google.keystone.agent", "com.zoom.zcsd"]
        ),
        SpywareSignature(
            name: "BeaverTail",
            processNames: ["BeaverTail", "beavertail", "node-win", "nvidiaGPUDetector"],
            bundleIdentifiers: ["com.beavertail.agent"],
            filePaths: [
                "/private/tmp/.npl",
                "/private/var/tmp/.beaver",
                "~/Library/Application Support/.beavertail",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            // "bow" / "pay" / "mclip" are the documented filenames for this DPRK dropper but
            // too short to match as process names without false positives; kept only as file IOCs.
            processNames: ["InvisibleFerret", "invisibleferret"],
            bundleIdentifiers: ["com.ferret.agent"],
            filePaths: [
                "/private/tmp/.ferret",
                "/private/tmp/p.py",
                "/private/tmp/pay",
                "/private/tmp/bow",
                "/private/tmp/mclip",
                "/private/var/tmp/.invisibleferret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "RustDoor / GateDoor",
            processNames: ["RustDoor", "rustdoor", "gatedoor", "zshrc_aliases", "zsh_updater", "zshrc2"],
            bundleIdentifiers: ["com.rustdoor.agent"],
            filePaths: [
                "~/.zshrc_aliases",
                "~/.zsh_updater",
                "/private/var/tmp/.rustdoor",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "ToDoSwift",
            processNames: ["ToDoSwift", "todoswift", "TodoTasks"],
            bundleIdentifiers: ["com.todoswift.agent"],
            filePaths: [
                "/private/var/tmp/.todoswift",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: ["com.todoswift.service"]
        ),
        SpywareSignature(
            name: "HiddenRisk (DPRK)",
            processNames: ["HiddenRisk", "hiddenrisk", "growth_hack", "Hidden Risk Behind New Surge"],
            bundleIdentifiers: ["com.hiddenrisk.agent"],
            filePaths: [
                "/private/var/tmp/.hiddenrisk",
                "~/Library/Application Support/.HiddenRisk",
            ],
            launchAgentLabels: ["com.apple.helper.plist"]
        ),
        SpywareSignature(
            name: "FERRET (DPRK)",
            processNames: ["FERRET", "ferret_installer", "ChromeUpdate", "FromChatGPT"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.ferret",
                "/tmp/.ChromeUpdate",
            ],
            launchAgentLabels: ["com.google.chrome.update"]
        ),
        // Commercial mercenary / govt spyware
        SpywareSignature(
            name: "Paragon Graphite",
            processNames: ["Graphite", "paragon_agent", "graphite_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.graphite",
                "~/Library/Caches/.graphite",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "QuaDream Reign",
            processNames: ["Reign", "quadream_agent"],
            bundleIdentifiers: [],
            filePaths: ["/private/var/tmp/.reign"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Candiru / DevilsTongue",
            processNames: ["DevilsTongue", "candiru_agent", "devilstongue"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.candiru",
                "/Library/.devilstongue",
            ],
            launchAgentLabels: []
        ),
        // Modern stealers (2024-2026)
        SpywareSignature(
            name: "ShadowVault",
            processNames: ["ShadowVault", "shadowvault", "shvault"],
            bundleIdentifiers: ["com.shadowvault.agent"],
            filePaths: [
                "/private/tmp/.shadowvault",
                "~/Library/Application Support/.ShadowVault",
            ],
            launchAgentLabels: ["com.shadowvault.service"]
        ),
        SpywareSignature(
            name: "Koi Stealer",
            processNames: ["KoiStealer", "koi_stealer", "koiloader"],
            bundleIdentifiers: ["com.koi.stealer"],
            filePaths: [
                "/private/tmp/.koi",
                "~/Library/Application Support/.Koi",
            ],
            launchAgentLabels: ["com.koi.service"]
        ),
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "WindowServerHelper", "ChromeUpdate.app"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
                "/Users/Shared/.update",
            ],
            launchAgentLabels: ["com.frigid.service"]
        ),
        SpywareSignature(
            name: "Crocodilus (macOS variant)",
            processNames: ["Crocodilus", "crocodilus", "croc_agent"],
            bundleIdentifiers: ["com.crocodilus.agent"],
            filePaths: [
                "/private/tmp/.crocodilus",
                "~/Library/Application Support/.Crocodilus",
            ],
            launchAgentLabels: ["com.crocodilus.service"]
        ),
        SpywareSignature(
            name: "CherryPie / Gh0stPie",
            processNames: ["CherryPie", "gh0stpie", "cherrypie_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.cherrypie",
                "~/Library/Application Support/.CherryPie",
            ],
            launchAgentLabels: []
        ),
        // Persistent adware/loaders still seen in 2024-2026 incident reports
        SpywareSignature(
            name: "AdLoad",
            processNames: ["AdLoad", "adload", "ProgressSnapshotSearch", "ElementarySignalSearch",
                           "MainActivitySearch", "RecordMapperSearch", "SkilledObjectSearch"],
            bundleIdentifiers: ["com.adload.agent"],
            filePaths: [
                "~/Library/Application Support/com.ProgressSnapshot",
                "~/Library/Application Support/com.ElementarySignal",
                "~/Library/Application Support/com.MainActivity",
                "~/Library/LaunchAgents/com.ProgressSnapshot.plist",
            ],
            launchAgentLabels: ["com.ProgressSnapshot", "com.ElementarySignal",
                                "com.MainActivity", "com.RecordMapper"]
        ),
        SpywareSignature(
            name: "Shlayer",
            // "Installer" alone would collide with Apple's Installer.app — we rely on Shlayer's
            // specific dropper names and file paths instead.
            processNames: ["Shlayer", "shlayer", "FlashPlayer_install"],
            bundleIdentifiers: ["com.shlayer.installer"],
            filePaths: [
                "/private/tmp/.shlayer",
                "/Users/Shared/.AdobePlayer",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Silver Sparrow",
            processNames: ["silver_sparrow", "verx", "agentupd"],
            bundleIdentifiers: ["com.silversparrow.agent"],
            filePaths: [
                "~/Library/._insu",
                "/tmp/agent.sh",
                "/tmp/version.json",
                "/tmp/version.plist",
            ],
            launchAgentLabels: ["init_verx", "agent.plist"]
        ),
        SpywareSignature(
            name: "UpdateAgent",
            processNames: ["UpdateAgent", "updateagent", "WizardUpdate"],
            bundleIdentifiers: ["com.adobe.fp.updater"],
            filePaths: [
                "~/Library/Application Support/.updateAgent",
                "/Library/Application Support/.wizardupdate",
            ],
            launchAgentLabels: ["com.adobe.fp.updater"]
        ),
        SpywareSignature(
            name: "JokerSpy",
            processNames: ["JokerSpy", "jokerspy", "xcc", "sh.py", "shared.dat"],
            bundleIdentifiers: ["com.apple.xcc"],
            filePaths: [
                "/Users/Shared/xcc",
                "/Users/Shared/sh.py",
                "/private/tmp/.jokerspy",
            ],
            launchAgentLabels: ["com.apple.xcc.plist"]
        ),
        // ClickFix / fake-captcha droppers (widespread 2024-2026 delivery vector)
        SpywareSignature(
            name: "ClickFix / FakeCaptcha dropper",
            processNames: ["clickfix", "FakeCaptcha", "captcha_helper", "VerifyHuman"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.clickfix",
                "/Users/Shared/.captcha",
            ],
            launchAgentLabels: []
        ),
    ]

    // MARK: - Cryptominer Database

    /// Known cryptomining process names. These are frequently dropped by compromised
    /// installers, pirated software, and drive-by downloads. They burn CPU/GPU and battery,
    /// and their presence almost always means the host has been tampered with.
    public static let cryptominerProcessNames: Set<String> = [
        // Monero (XMR) — most common on compromised Macs
        "xmrig", "xmrig-notls", "xmr-stak", "xmr-stak-cpu", "xmr-stak-rx",
        "minergate", "MinerGate", "minergate-cli", "minerd",
        // Generic CPU/GPU miners
        "cpuminer", "cpuminer-multi", "ccminer", "ethminer",
        "t-rex", "teamredminer", "lolminer", "nbminer",
        "phoenixminer", "claymore", "gminer", "srbminer",
        // NiceHash and pool agents
        "nicehash", "nicehash-miner", "excavator",
        // macOS-specific / hidden variants
        "mac-miner", "macminer", "osx_miner", "mdworker_miner",
        "com.apple.mdworker_shared_helper",  // Often used as cover by miners
        "kdevtmpfsi", "kinsing",  // Linux-origin but cross-compiled to macOS in some campaigns
        // Recent campaigns (2024-2026)
        "cpuhog", "minerbot", "xmrig2", "xmrigMiner", "hiddenminer",
    ]

    public static func isCryptominer(_ name: String) -> Bool {
        let lower = name.lowercased()
        return cryptominerProcessNames.contains(where: { $0.lowercased() == lower })
    }

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
        // Observed 2024-2026 campaigns — DPRK, AMOS, RustDoor, etc.
        "com.apple.xcc",                    // JokerSpy
        "com.apple.helper",                 // HiddenRisk
        "com.apple.WebKit.Networking.agent",
        "com.apple.systempreferences.helper",
        "com.apple.coreservices.helper",
        "com.apple.mdworker_shared_helper",
        "com.apple.launchd.helper",
        "com.apple.audio.coreaudiod.helper",
        "com.apple.spotlight.indexer",
        "com.apple.metadata.mdflagwriter",
        "com.apple.itunes.helper",          // Old iTunes is gone — any "helper" here is suspicious
        "com.apple.quicktime.helper",
        "com.apple.preferences.helper",
        "com.apple.google.keystone.agent",  // NimDoor disguise
        // Fake "Google" bundle IDs that malware uses (not Apple but same pattern)
        "com.google.chrome.update",         // Fake — Chrome updater is com.google.keystone
        "com.google.drive.helper",          // NimDoor style
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
        // Observed 2024-2026 process masquerading campaigns
        "mdworker_shared_helper", // AMOS/miners — real is mdworker_shared
        "WindowServerHelper",    // FrigidStealer — no such Apple process
        "WindowServerd",         // There's no WindowServer daemon with 'd' suffix
        "launchdd",              // Typo-squat of launchd
        "coreservicesd",         // Masquerade of coreservicesd (real is lsd/coreservicesd)
        "nsurld",                // Fake — real is nsurlsessiond
        "bluetoothed",           // Fake — real is bluetoothd
        "iCloudDrive",           // Not a real process (real is bird)
        "ZoomUpdate",            // NimDoor — no legitimate background Zoom updater
        "GoogIe LLC",            // Unicode homoglyph ("GoogIe" with capital-I not lower-l)
        "Google LLc",            // Case-mangled to evade checks
        "ChromeUpdate.app",      // Real Chrome updater is GoogleSoftwareUpdate
        "MicrosoftUpdate",       // Fake (real is Microsoft AutoUpdate)
        "AdobeUpdate",           // Fake (real is AdobeUpdater, etc.)
        "AdobePlayer",           // Flash Player is dead — any "AdobePlayer" today is malware
        "FlashPlayer_install",   // Shlayer family
        "FlashPlayer",           // Flash EOL 2020 — binaries named this are stealers
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
