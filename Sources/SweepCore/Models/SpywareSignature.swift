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
        SpywareSignature(
            // DPRK-attributed Nim-based loader/backdoor (SentinelOne, July 2024).
            // Often delivered via fake "Zoom meeting SDK" or job-interview installers.
            name: "NimDoor",
            processNames: ["nimdoor", "GoogIeHelper", "MicrosoftAUDaemon", "CoreKitAgent",
                           "ZoomVideoBackground"],
            bundleIdentifiers: ["com.zoom.update", "com.google.updater"],
            filePaths: [
                "/private/tmp/.nim",
                "~/Library/Application Support/.nimdoor",
                "~/Library/LaunchAgents/com.google.updater.plist",
            ],
            launchAgentLabels: ["com.google.updater", "com.zoom.update", "com.microsoft.audaemon"]
        ),
        SpywareSignature(
            // BeaverTail / InvisibleFerret — DPRK "Contagious Interview" campaign
            // delivered as fake coding-test packages (npm + Python).
            name: "BeaverTail / InvisibleFerret",
            processNames: ["beavertail", "invisibleferret", "ferret", "node_helper",
                           "miner.py", "iSecurityAgent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.npl",
                "/private/tmp/.n2",
                "~/Library/Application Support/.invisible",
                "~/Library/Application Support/.tinker",
            ],
            launchAgentLabels: ["com.apple.ttserver"]
        ),
        SpywareSignature(
            // Late 2024 / early 2025 — distributed via fake browser-update pop-ups (TDS).
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid", "Setup_safari", "WindowServers"],
            bundleIdentifiers: ["com.frigid.stealer", "marsoperator.frigid"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.Frigid",
            ],
            launchAgentLabels: ["com.frigid.service"]
        ),
        SpywareSignature(
            // Go-based stealer / RAT (AT&T Alien Labs, late 2023; macOS variant 2024).
            name: "JaskaGo",
            processNames: ["JaskaGo", "jaskago", "GoPanda", "AppleHelper.helper"],
            bundleIdentifiers: ["com.jaska.app"],
            filePaths: [
                "/private/tmp/.jaska",
                "~/Library/Application Support/.JaskaGo",
            ],
            launchAgentLabels: ["com.apple.systempref.helper"]
        ),
        SpywareSignature(
            // macOS port of LockBit ransomware seen in 2024.
            name: "NotLockBit",
            processNames: ["NotLockBit", "lockbit", "MyDocLocker", "MyEncryptor"],
            bundleIdentifiers: ["com.lockbit.macos"],
            filePaths: [
                "/private/tmp/.lockbit",
                "/private/tmp/encrypt.tmp",
            ],
            launchAgentLabels: ["com.apple.docs.encrypt"]
        ),
        SpywareSignature(
            // 2025 loader/dropper that delivers AMOS/Poseidon via fake PDF reader installers.
            name: "ReaderUpdate",
            processNames: ["ReaderUpdate", "readerupdate", "PDFReader_setup",
                           "Adobe_Acrobat_Update"],
            bundleIdentifiers: ["com.adobe.update", "com.pdfreader.update"],
            filePaths: [
                "/private/tmp/.reader",
                "~/Library/Application Support/.ReaderUpdate",
            ],
            launchAgentLabels: ["com.adobe.acrobat.update"]
        ),
        SpywareSignature(
            // DPRK-linked Swift backdoor (Aug 2024, Kandji & Phylum reports).
            name: "TodoSwift",
            processNames: ["TodoSwift", "todoswift", "ZoomCommunications.app", "GoogleEDU"],
            bundleIdentifiers: ["com.todo.swift"],
            filePaths: [
                "/private/tmp/.todo",
                "~/Library/Group Containers/.todoswift",
            ],
            launchAgentLabels: ["com.apple.todo.helper"]
        ),
        SpywareSignature(
            // DPRK "Hidden Risk" — fake crypto-news PDF dropper (SentinelOne, Nov 2024).
            // Persists via zshenv to survive shell launches without a LaunchAgent file.
            name: "HiddenRisk",
            processNames: ["HiddenRisk", "growth", "Hidden Risk Behind New Surge of Bitcoin Price",
                           "macnotes"],
            bundleIdentifiers: ["com.bohemian.cryptominer"],
            filePaths: [
                "/private/tmp/.zshenv",
                "~/Library/Application Support/.hiddenrisk",
                "~/Library/Application Support/.macnotes",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Active 2024-2025 RAT (BlackBerry/Lookout reporting); macOS variants used against
            // journalists and dissidents.
            name: "LightSpy",
            processNames: ["LightSpy", "lightspy", "macsysd", "macupdater_helper"],
            bundleIdentifiers: ["com.lookout.lightspy"],
            filePaths: [
                "/Library/.lightspy",
                "/private/var/tmp/.lightspy",
            ],
            launchAgentLabels: ["com.apple.macsysd"]
        ),
        SpywareSignature(
            // KrustyLoader (Volexity, Jan 2024) — Rust-based first-stage downloader.
            name: "KrustyLoader",
            processNames: ["krusty", "KrustyLoader", "rust_loader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.krusty",
                "/private/var/tmp/.krustyd",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Python-based stealer family active in 2024 — delivered via cracked apps and
            // fake productivity tools on warez sites.
            name: "PythonStealer (CryptoChameleon)",
            processNames: ["pythonstealer", "py_stealer", "ChromeUpdater", "wallet.py"],
            bundleIdentifiers: ["com.python.stealer"],
            filePaths: [
                "/private/tmp/.pystealer",
                "~/Library/Application Support/.PyStealer",
            ],
            launchAgentLabels: ["com.python.helper"]
        ),
        SpywareSignature(
            // AppleProcessHub (early 2025, MacPaw Moonlock) — fake Apple-branded loader.
            name: "AppleProcessHub",
            processNames: ["AppleProcessHub", "appleprocesshub", "applehub"],
            bundleIdentifiers: ["com.apple.process.hub"],
            filePaths: [
                "/private/tmp/.applehub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.process.hub"]
        ),
        SpywareSignature(
            // RustyAttr — BlueNoroff (DPRK), Nov 2024. Stores payload in macOS extended attrs.
            name: "RustyAttr",
            processNames: ["rustyattr", "RustyAttr", "xattr_loader"],
            bundleIdentifiers: ["com.rustyattr.loader"],
            filePaths: [
                "/private/tmp/.rustyattr",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // FlexibleFerret (Cisco Talos / Phylum, late 2024) — Electron-disguised stealer
            // distributed through fake video conferencing app installers.
            name: "FlexibleFerret",
            processNames: ["FlexibleFerret", "ferret", "FerretService",
                           "MicrosoftFerret"],
            bundleIdentifiers: ["com.flexible.ferret"],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/Application Support/.FlexibleFerret",
            ],
            launchAgentLabels: ["com.apple.ferret.helper"]
        ),
        SpywareSignature(
            // WizardUpdate / Adload — long-running adware that escalated in 2024 to drop
            // stealer payloads alongside ad injection.
            name: "WizardUpdate / Adload",
            processNames: ["WizardUpdate", "wizardupdate", "PostfixCacheService",
                           "ExtensionAgent", "AnalysisInjector"],
            bundleIdentifiers: ["com.WizardUpdate.helper", "com.adload.installer"],
            filePaths: [
                "/Library/Application Support/.WizardUpdate",
                "~/Library/Application Support/.WizardUpdate",
            ],
            launchAgentLabels: ["com.WizardUpdate.helper", "com.WizardUpdate.update"]
        ),
        SpywareSignature(
            // Mac.OSX.SpaceHopper / Pirrit successor — pop-up + tracking + stealer hybrid (2024).
            name: "SpaceHopper",
            processNames: ["SpaceHopper", "spacehopper", "spaceupdater"],
            bundleIdentifiers: ["com.spacehopper.agent"],
            filePaths: [
                "~/Library/Application Support/.spacehopper",
                "/private/tmp/.spacehopper",
            ],
            launchAgentLabels: ["com.spacehopper.helper"]
        ),
        SpywareSignature(
            // Crypter-installed clipboard-hijacker family (2024-2025) that swaps copied
            // crypto wallet addresses with attacker-controlled addresses.
            name: "ClipboardSwapper",
            processNames: ["ClipboardSwapper", "clipswap", "clipboarder",
                           "Pasteboard_helper", "CopyAgent"],
            bundleIdentifiers: ["com.clipboard.swapper", "com.copy.helper"],
            filePaths: [
                "/private/tmp/.clipswap",
                "~/Library/Application Support/.ClipboardSwapper",
            ],
            launchAgentLabels: ["com.copy.helper"]
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
        // 2024-2025 stealer/RAT IOCs disguising themselves as Apple services
        "com.apple.ttserver",
        "com.apple.macsysd",
        "com.apple.todo.helper",
        "com.apple.process.hub",
        "com.apple.ferret.helper",
        "com.apple.docs.encrypt",
        "com.apple.systempref.helper",
        "com.apple.macupdater.helper",
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
