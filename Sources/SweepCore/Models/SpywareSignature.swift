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
        // 2025-2026 macOS ClickFix / infostealer wave
        SpywareSignature(
            name: "ClickLock Stealer",
            processNames: ["clicklock", "ClickLock", "authirity", "chromer"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/LaunchAgents/com.authirity.plist",
                "~/Library/LaunchAgents/com.chromer.plist",
                "/private/tmp/.clicklock",
            ],
            // ClickLock spawns a 210ms process-kill loop until the victim types their password.
            // Persistence is two LaunchAgents dropped in the user's LaunchAgents directory.
            launchAgentLabels: ["com.authirity", "com.chromer"]
        ),
        SpywareSignature(
            name: "CrashStealer",
            processNames: ["veltod", "CrashReporter", "crashreporter_helper"],
            bundleIdentifiers: ["com.apple.crashreporter.helper"],
            filePaths: [
                "/private/tmp/CrashReporter.dmg",
                "/private/tmp/sys.cache",
                "~/Library/Application Support/.CrashReporter",
            ],
            // CrashStealer disguises itself as Apple's CrashReporter — the LaunchAgent label
            // com.apple.crashreporter.helper is a fake Apple bundle ID (real one is com.apple.CrashReporter).
            launchAgentLabels: ["com.apple.crashreporter.helper"]
        ),
        SpywareSignature(
            name: "SHub Reaper",
            processNames: ["SHub", "shub_reaper", "GoogleUpdater"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/GoogleUpdate.app",
                "~/Library/Application Support/GoogleUpdate",
            ],
            // Reaper impersonates Google Update via a fake GoogleUpdate.app in ~/Library. The
            // fake LaunchAgent label matches the legitimate Chrome updater — see the impersonated
            // vendor path check in PersistenceScanner for the disambiguating rule.
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "MacSync Stealer",
            processNames: ["MacSync", "macsync", "macsync_helper"],
            bundleIdentifiers: ["com.macsync.helper", "com.macsync.agent"],
            filePaths: [
                "~/Library/Application Support/.MacSync",
                "/private/tmp/.macsync",
            ],
            launchAgentLabels: ["com.macsync.helper", "com.macsync.agent"]
        ),
        // North-Korea Contagious Interview / DPRK campaign families
        SpywareSignature(
            name: "BeaverTail",
            processNames: ["beavertail", "BeaverTail", "n2_pdf", "node_pdf"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.n2",
                "/private/tmp/p.zi",
                "~/Library/Caches/.beavertail",
            ],
            // BeaverTail is a Node.js-based DPRK stealer dropped by fake npm packages and
            // .vscode/tasks.json auto-installers during "job interview" chains.
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["invisibleferret", "python_helper", "pyloader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.invisibleferret",
                "~/Library/Application Support/.pyp",
                "~/.npl",
            ],
            // Second-stage Python backdoor deployed by BeaverTail. Uses hidden ~/.npl staging.
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OtterCookie",
            processNames: ["ottercookie", "OtterCookie"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.ottercookie",
                "~/Library/Application Support/.ottercookie",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FRIENDLYFERRET",
            processNames: ["FRIENDLYFERRET", "friendlyferret", "secd_helper"],
            bundleIdentifiers: ["com.apple.secd"],
            filePaths: [
                "/private/tmp/.friendlyferret",
                "~/Library/Application Support/.secd",
            ],
            // FRIENDLYFERRET masquerades as com.apple.secd (the real Apple daemon has no LaunchAgent plist).
            launchAgentLabels: ["com.apple.secd"]
        ),
        SpywareSignature(
            name: "FlexibleFerret",
            processNames: ["FlexibleFerret", "flexibleferret", "ChromeUpdate", "FerretHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.ferret",
                "/private/tmp/.flexibleferret",
                "~/.chromeupdate",
            ],
            launchAgentLabels: ["com.apple.chromeupdate"]
        ),
        SpywareSignature(
            name: "BlueNoroff HiddenRisk",
            processNames: ["HiddenRisk", "hiddenrisk", "growth", "crypto_news"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.hiddenrisk",
                "/private/tmp/.hiddenrisk",
            ],
            // BlueNoroff HiddenRisk uses zshenv-based persistence — the zshenv modification is
            // detected separately by the shell-config scanner.
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "TanStack gh-token-monitor",
            processNames: ["gh-token-monitor", "gh_token_monitor"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/LaunchAgents/com.user.gh-token-monitor.plist",
            ],
            // Payload from the TanStack npm supply-chain compromise — a LaunchAgent that exfiltrates
            // GitHub tokens from the developer's keychain.
            launchAgentLabels: ["com.user.gh-token-monitor"]
        ),
        // Cryptojackers (2024-2025)
        SpywareSignature(
            name: "LoudMiner (XMRig)",
            processNames: ["LoudMiner", "loudminer", "xmrig", "coreaudiod-helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/Application Support/CoreAudioService",
                "~/Library/Application Support/CoreAudioService",
                "/Library/LaunchDaemons/com.apple.coreaudiod.plist.helper",
            ],
            launchAgentLabels: ["com.coreaudiod.helper"]
        ),
        SpywareSignature(
            name: "OSX.ppminer",
            processNames: ["ppminer", "com.pplauncher.plist"],
            bundleIdentifiers: [],
            filePaths: ["/Library/Application Support/pplauncher"],
            launchAgentLabels: ["com.pplauncher.plist"]
        ),
        SpywareSignature(
            name: "OSX.CpuMeaner",
            processNames: ["cpumeaner", "CpuMeaner", "com.osxext.gpumon"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/Application Support/com.osxext.gpumon",
                "/Library/LaunchDaemons/com.osxext.gpumon.plist",
            ],
            launchAgentLabels: ["com.osxext.gpumon"]
        ),
        // LightSpy — modular surveillance framework with a 2024 macOS build
        SpywareSignature(
            name: "LightSpy (macOS)",
            processNames: ["lightspy", "LightSpy", "SpyLight", "F_Warehouse"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.lightspy",
                "/private/var/tmp/.lightspy",
                "~/Library/Caches/.F_Warehouse",
            ],
            launchAgentLabels: []
        ),
        // XCSSET 2024/2025 variants that hide inside Xcode projects
        SpywareSignature(
            name: "XCSSET (2024 variant)",
            processNames: ["xcodebuild_helper", "xcode_installer", "safari_boot"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Caches/com.apple.dt.Xcode.installer",
                "~/Library/Developer/Xcode/UserData/xcuserdata/.xcsset",
            ],
            launchAgentLabels: ["com.apple.xcode.installer.helper"]
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
        // 2025-2026 additions — LaunchAgent labels observed in real infostealer campaigns.
        // The real Apple bundle IDs are com.apple.CrashReporter, com.apple.secd, com.apple.mdworker
        // (mixed case, no ".helper" / ".agent" suffix, and never installed as a user LaunchAgent).
        "com.apple.crashreporter.helper", // CrashStealer
        "com.apple.secd",                 // FRIENDLYFERRET (real secd has no user plist)
        "com.apple.chromeupdate",         // FlexibleFerret
        "com.apple.xcode.installer.helper", // XCSSET 2024
        "com.apple.mdworker.helper",
        "com.apple.mdworker.agent",
        "com.apple.spotlight.helper",
        "com.apple.icloud.helper",
        "com.apple.airport.helper",
    ]

    /// Fake bundle identifiers that impersonate other well-known vendors (Google, Microsoft, Adobe, etc.).
    /// Recent macOS stealers frequently pretend to be Google Update or Microsoft OneDrive.
    ///
    /// Note: labels that are ALSO used by legitimate vendor updaters (e.g. `com.google.keystone.agent`)
    /// are NOT listed here — that would misfire on every Chrome install. Those are disambiguated by
    /// their executable path in the vendor-impersonation heuristic (see PersistenceScanner).
    public static let fakeVendorBundlePatterns: [String] = [
        // SHub Reaper / stealer families that pick a plausible-but-not-real Google/Adobe/MS label
        "com.google.updater.helper",
        "com.adobe.updater.helper",
        "com.adobe.creativecloud.updater.plist",
        "com.microsoft.update.agent",
        "com.microsoft.onedrive.helper",
        // Node/npm supply-chain
        "com.user.gh-token-monitor",
    ]

    /// Legitimate vendor LaunchAgent labels paired with the executable-path prefix they
    /// SHOULD run from. If a plist uses one of these labels but its executable lives outside
    /// the expected prefix, it's very likely an impersonator (e.g. SHub Reaper spoofing Chrome's
    /// Keystone updater). Values are checked with `contains(where:)` on the executable path, so a
    /// match anywhere in the path suffices — accounts for user-home variance.
    public static let vendorLaunchAgentAllowedPaths: [String: [String]] = [
        "com.google.keystone.agent": [
            "/Library/Google/GoogleSoftwareUpdate/",
            "/Applications/Google Chrome.app/",
            "/Applications/Google Chrome Canary.app/",
            "/Applications/Google Chrome Beta.app/",
        ],
        "com.google.keystone.daemon": [
            "/Library/Google/GoogleSoftwareUpdate/",
        ],
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

    /// Checks if a bundle ID impersonates a well-known vendor (Google Update, Adobe, Microsoft, etc.)
    /// installed in a user or system LaunchAgents directory.
    /// Legitimate vendor updaters live in vendor-controlled application directories, not the
    /// user's LaunchAgents folder — so a match here is a strong compromise signal.
    public static func isFakeVendorBundleId(_ bundleId: String) -> Bool {
        return fakeVendorBundlePatterns.contains(bundleId)
    }

    /// If `label` is a known vendor LaunchAgent label AND `executablePath` sits outside every
    /// allowed prefix for that label, returns true — this is a strong signal of an impersonation
    /// campaign (e.g. SHub Reaper's fake `com.google.keystone.agent` pointing at ~/Library/GoogleUpdate.app).
    /// Returns false when the label is unknown or when the executable lives where it should.
    public static func isImpersonatedVendorLaunchAgent(label: String, executablePath: String) -> Bool {
        guard let allowedPrefixes = vendorLaunchAgentAllowedPaths[label], !allowedPrefixes.isEmpty else {
            return false
        }
        // The executable path is legitimate if it contains ANY of the allowed prefixes.
        for prefix in allowedPrefixes {
            if executablePath.contains(prefix) {
                return false
            }
        }
        return true
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
