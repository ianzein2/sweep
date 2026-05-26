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
        // ---- 2024–2026 additions ----
        // FrigidStealer — distributed via fake browser update prompts targeting macOS (Proofpoint, Feb 2025).
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid", "frigidstealer", "frigid_agent"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.Frigid",
                "/private/tmp/StealerMac",
            ],
            launchAgentLabels: ["com.frigid.service"]
        ),
        // Odyssey Stealer — AMOS rebrand reported by Cyble/Moonlock (2024–2025).
        SpywareSignature(
            name: "Odyssey Stealer",
            processNames: ["Odyssey", "odyssey_stealer", "odystealer", "OdysseyHelper"],
            bundleIdentifiers: ["com.odyssey.stealer", "com.odyssey.helper"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.service"]
        ),
        // BeaverTail — JavaScript stealer dropped by DPRK "Contagious Interview" job-lure campaign.
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            processNames: ["BeaverTail", "beavertail", "beaver_helper", "ChromeUpdate", "MicrosoftAutoUpdate2"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.npl",
                "~/Library/Caches/.npl",
                "~/Library/Application Support/.cache_npl",
            ],
            launchAgentLabels: []
        ),
        // InvisibleFerret — Python backdoor dropped as second stage by Contagious Interview.
        SpywareSignature(
            name: "InvisibleFerret (Contagious Interview)",
            processNames: ["InvisibleFerret", "invisible_ferret", "pay", "p.zi", "bow", "mlip"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.npl",
                "/private/tmp/.invisibleferret",
                "~/Library/Application Support/.ferret",
            ],
            launchAgentLabels: []
        ),
        // HZ RAT — Mac variant first reported by Kaspersky in 2024; long-running APT toolkit.
        SpywareSignature(
            name: "HZ RAT",
            processNames: ["HZRat", "hzrat", "hz_helper", "OpenVPNConnect.app"],
            bundleIdentifiers: ["com.hz.rat"],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.hz",
            ],
            launchAgentLabels: ["com.hz.openvpn.connect"]
        ),
        // LightSpy — modular surveillance framework with documented macOS implant (BlackBerry/ThreatFabric).
        SpywareSignature(
            name: "LightSpy",
            processNames: ["lightspy", "LightSpy", "macma", "MacOS_F", "macOS_F"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.lightspy",
                "~/Library/Caches/.lightspy",
            ],
            launchAgentLabels: ["com.apple.softwareupdate.lightspy"]
        ),
        // ShadowVault — infostealer/clipper for macOS (Guardz, 2023+) targeting wallets and keychain dumps.
        SpywareSignature(
            name: "ShadowVault",
            processNames: ["ShadowVault", "shadowvault", "shvault"],
            bundleIdentifiers: ["com.shadowvault.stealer"],
            filePaths: [
                "/private/tmp/.shadowvault",
                "~/Library/Application Support/.ShadowVault",
            ],
            launchAgentLabels: ["com.shadowvault.service"]
        ),
        // TraderTraitor — DPRK-attributed campaign behind multiple crypto-exchange compromises (CISA AA22-108A, AA24-…).
        SpywareSignature(
            name: "TraderTraitor (Lazarus)",
            processNames: ["CryptoAISbot", "TokenAIS", "TradeAtlas", "DAFOM", "CoinGoTrade"],
            bundleIdentifiers: [
                "com.cryptoaisbot.app", "com.tokenais.app", "com.tradeatlas.app",
                "com.dafom.app", "com.coingotrade.app",
            ],
            filePaths: ["~/Library/Application Support/.trader_traitor"],
            launchAgentLabels: []
        ),
        // KeySteal — keychain-targeted infostealer detected by Apple XProtect signatures.
        SpywareSignature(
            name: "KeySteal",
            processNames: ["KeySteal", "keysteal", "ksteal", "KeySigEx"],
            bundleIdentifiers: ["com.keysteal.agent"],
            filePaths: [
                "~/Library/Application Support/.KeySteal",
                "/private/tmp/.keysteal",
            ],
            launchAgentLabels: ["com.keysteal.service"]
        ),
        // JaskaGO — Go-based cross-platform stealer with mac builds (AT&T Alien Labs, 2023+).
        SpywareSignature(
            name: "JaskaGO",
            processNames: ["JaskaGO", "jaskago", "jgo_agent"],
            bundleIdentifiers: ["com.jaskago.agent"],
            filePaths: [
                "/private/tmp/.jaskago",
                "~/Library/Application Support/.JaskaGO",
            ],
            launchAgentLabels: ["com.jaskago.service"]
        ),
        // KandyKorn variant via DPRK BlueNoroff — extended IOCs observed in 2024.
        SpywareSignature(
            name: "RustyAttr (BlueNoroff)",
            processNames: ["RustyAttr", "rustyattr", "tauri_app", "Tauri"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Caches/.rustyattr",
                "/private/tmp/.rustyattr",
            ],
            launchAgentLabels: []
        ),
        // FerretApp / FlexibleFerret — DPRK-linked impersonation of Zoom/Chrome installers.
        SpywareSignature(
            name: "FlexibleFerret",
            processNames: ["FlexibleFerret", "flexible_ferret", "zoom_sdk_helper_x86_64"],
            bundleIdentifiers: ["com.zoom.sdk.helper.x86_64", "com.flexible.ferret"],
            filePaths: [
                "/private/tmp/.flexibleferret",
                "~/Library/Application Support/.FlexibleFerret",
            ],
            launchAgentLabels: ["com.zoom.sdk.helper"]
        ),
        // RustDoor — backdoor masquerading as Microsoft/Visual Studio updates (Bitdefender, 2024).
        SpywareSignature(
            name: "RustDoor",
            processNames: ["RustDoor", "rustdoor", "VisualStudioUpdater", "zshrc"],
            bundleIdentifiers: ["com.microsoft.visualstudio.updater"],
            filePaths: [
                "~/.systembk",
                "~/Public/.systembk",
                "/private/tmp/.rustdoor",
            ],
            launchAgentLabels: ["com.microsoft.visualstudio.updater"]
        ),
        // GoSorry / Boinas — Go-based macOS RAT documented in 2024.
        SpywareSignature(
            name: "GoSorry",
            processNames: ["gosorry", "GoSorry", "boinas", "Boinas"],
            bundleIdentifiers: ["com.boinas.agent"],
            filePaths: ["/private/tmp/.gosorry", "~/Library/Application Support/.Boinas"],
            launchAgentLabels: ["com.boinas.service"]
        ),
        // SpectralBlur extended — additional DPRK IOCs reported in 2024.
        SpywareSignature(
            name: "MISTPEN (DPRK)",
            processNames: ["mistpen", "MISTPEN", "BurnBookHelper", "VolatileMessenger"],
            bundleIdentifiers: [],
            filePaths: ["/private/var/tmp/.mistpen"],
            launchAgentLabels: []
        ),
        // PondRAT — Python implant by Lazarus group (Unit 42, 2024) delivered via poisoned PyPI packages.
        SpywareSignature(
            name: "PondRAT",
            processNames: ["PondRAT", "pondrat", "pondhelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.pondrat",
                "~/Library/Caches/.pond",
            ],
            launchAgentLabels: []
        ),
        // RokRAT macOS variant (APT37 / ScarCruft).
        SpywareSignature(
            name: "RokRAT",
            processNames: ["RokRAT", "rokrat", "rok_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.rokrat",
                "~/Library/Caches/.rok",
            ],
            launchAgentLabels: []
        ),
        // SilentTrinity — open-source C2 abused against macOS targets.
        SpywareSignature(
            name: "SilentTrinity",
            processNames: ["SilentTrinity", "silenttrinity", "st_agent", "boomerang"],
            bundleIdentifiers: ["com.silenttrinity.agent"],
            filePaths: ["/private/tmp/.silenttrinity"],
            launchAgentLabels: ["com.silenttrinity.service"]
        ),
        // SparkRAT macOS — Go-based open-source RAT seen in real-world intrusions.
        SpywareSignature(
            name: "SparkRAT",
            processNames: ["SparkRAT", "sparkrat", "spark_helper"],
            bundleIdentifiers: ["com.sparkrat.agent"],
            filePaths: [
                "/private/tmp/.sparkrat",
                "~/Library/Application Support/.SparkRAT",
            ],
            launchAgentLabels: ["com.sparkrat.service"]
        ),
        // Trojan-Proxy DNSChanger via cracked apps — Kaspersky, 2023+.
        SpywareSignature(
            name: "Trojan-Proxy (Cracked Apps)",
            processNames: ["GoogleHelperUpdater", "google_drive_helper2", "WindowServer.helper"],
            bundleIdentifiers: ["com.google.helperupdater"],
            filePaths: [
                "~/Library/Application Support/.GoogleHelper",
                "/private/tmp/.trojanproxy",
            ],
            launchAgentLabels: ["com.google.helperupdater"]
        ),
        // Cuckoo Spy variant / Cuckoo v2 IOCs reported in 2025.
        SpywareSignature(
            name: "Cuckoo v2 (DumpMedia variant)",
            processNames: ["DumpMediaMusicConverter", "FoneDogTool", "TuneFabSpotifyMusic", "Sidify"],
            bundleIdentifiers: [
                "com.dumpmedia.musicconverter",
                "com.fonedog.tool",
                "com.tunefab.spotifymusic",
            ],
            filePaths: ["~/Library/Application Support/.Cuckoo2"],
            launchAgentLabels: []
        ),
        // CHM Stealer / Crystal Stealer — 2024 stealers seen targeting macOS Web3 users.
        SpywareSignature(
            name: "Crystal Stealer",
            processNames: ["Crystal", "crystal_stealer", "CrystalAgent"],
            bundleIdentifiers: ["com.crystal.stealer"],
            filePaths: [
                "/private/tmp/.crystal",
                "~/Library/Application Support/.Crystal",
            ],
            launchAgentLabels: ["com.crystal.service"]
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
        // 2024–2026 stealer/RAT campaigns
        "com.apple.softwareupdate.lightspy",
        "com.apple.softwareupdate.plist",
        "com.apple.softwareupdated.helper",
        "com.apple.systempreferences.helper",
        "com.apple.macshare.plist",
        "com.apple.appstore.helper",
        "com.apple.installassistant.tool",
        "com.apple.coreservicesd.helper",
        "com.apple.commerce.helper",
        "com.apple.terminal.helper",
        "com.apple.finder.helper",
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
