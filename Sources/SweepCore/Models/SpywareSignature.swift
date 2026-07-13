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
        // Contemporary DPRK / APT (2025-2026)
        SpywareSignature(
            name: "NimDoor (DPRK)",
            // NimDoor's second stage is a Nim binary named "CoreKitAgent"; first-stage bash
            // droppers are dumped as short filenames in /private/var/tmp.
            processNames: ["CoreKitAgent", "netchk", "zoom_sdk_support"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/a",
                "/private/var/tmp/installer",
                "/private/var/tmp/netchk",
                "~/Library/Application Support/Google LLC/GoogIe LLC",  // lookalike I-vs-l
                "/private/tmp/zoom_sdk_support.scpt",
            ],
            // Real Google Chrome uses com.google.keystone.agent; NimDoor squats
            // com.google.update as a decoy label.
            launchAgentLabels: ["com.google.update"]
        ),
        SpywareSignature(
            name: "Sapphire Sleet (DPRK)",
            processNames: ["icloudz", "com.apple.cli"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/iCloud/icloudz",
            ],
            launchAgentLabels: ["com.apple.cli"]
        ),
        SpywareSignature(
            name: "SHub Reaper / SHub Stealer",
            processNames: ["shub_helper", "shub_update", "GoogleUpdate"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/helper",
                "/tmp/update",
                "/tmp/shub_",  // /tmp/shub_<random>/
                "~/Library/Application Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate",
            ],
            // Reaper mints per-victim random labels; the finder helper label is stable.
            launchAgentLabels: ["com.finder.helper", "com.google.keystone.agent.helper"]
        ),
        SpywareSignature(
            name: "MacSync Stealer (Mac.c rebrand)",
            processNames: ["UserSyncWorker", "runner"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/runner",
                "~/Library/Logs/UserSyncWorker.log",
                "~/Library/Application Support/UserSyncWorker",
                "~/Library/Application Support/UserSyncWorker/last_up",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Gaslight (DPRK)",
            // Rust binary that ships an AI prompt-injection blob to derail human-in-the-loop analysts.
            processNames: ["gaslight"],
            bundleIdentifiers: [],
            filePaths: [],
            launchAgentLabels: ["com.apple.system.services.activity"]
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["libsystd"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/libsystd.dylib",
                "/private/tmp/libsystd.dylib",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "DigitStealer",
            // Delivered as a fake "DynamicLake" menu-bar app; payload is JXA/osascript stages.
            processNames: ["DynamicLake"],
            bundleIdentifiers: [],
            filePaths: [
                "/Volumes/DynamicLake",
                "~/Downloads/DynamicLake.dmg",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FrigidStealer (TA2727)",
            processNames: ["FrigidStealer", "frigid"],
            bundleIdentifiers: [],
            // FrigidStealer arrives via fake-browser-update lures — the DMG typically has a
            // generic "update"/"install" name and asks for the login password via osascript.
            filePaths: [
                "~/Downloads/Update.dmg",
                "~/Downloads/BrowserUpdate.dmg",
                "~/Downloads/SafariUpdate.dmg",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Odyssey Stealer (ex-Poseidon)",
            // Poseidon was resold and rebranded to Odyssey; the on-disk state file is stable.
            processNames: ["odyssey", "Odyssey"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.botid",  // Odyssey's persistent bot-identifier file
                "/Users/Shared/NW",  // Cthulhu 2025 repack drop directory
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "CHILLYHELL",
            // Apple-notarized backdoor unnoticed since 2021; persists by appending to shell rc files.
            processNames: ["chillyhell", "ChillyHell"],
            bundleIdentifiers: [],
            filePaths: [],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Covid backdoor (Sliver + MacDriver)",
            processNames: ["covid"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.androids",  // hidden staging directory
            ],
            // Squats the Apple software-update label but drops into ~/Library/LaunchAgents
            // (the real com.apple.softwareupdate is a system-wide daemon under /System/Library).
            launchAgentLabels: ["com.apple.softwareupdate"]
        ),
        SpywareSignature(
            name: "Cuckoo Stealer (fake Homebrew)",
            processNames: ["cuckoo_helper"],
            bundleIdentifiers: [],
            filePaths: [],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Contagious Interview (BeaverTail / InvisibleFerret / OtterCookie)",
            // DPRK "recruiter" campaign delivered via npm packages; second-stage payload directories
            // are the strongest on-disk IOC — these paths should never exist on a clean Mac.
            processNames: ["beavertail", "invisibleferret", "ottercookie", "n2", "npl"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.npl",
                "~/.pyp",
                "~/.n2",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Shai-Hulud npm worm",
            // Worm that infects other npm packages and exfiltrates dev secrets via a GitHub Actions workflow it plants.
            processNames: [],
            bundleIdentifiers: [],
            filePaths: [],
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
        // Recent 2025-2026 stealer & DPRK LaunchAgent labels that collide with com.apple.*
        "com.apple.system.services.activity",  // Gaslight (DPRK, 2026)
        "com.apple.cli",                       // Sapphire Sleet (DPRK, 2026)
        "com.apple.qtop",                      // 2025 sample seen in wild
        "com.apple.softwareupdate",            // "covid" Sliver backdoor (2025) — real Apple label is com.apple.softwareupdated
        "com.apple.macshare",                  // SpectralBlur variant
        "com.apple.macshare.plist",
        "com.apple.systempreferences.helper",  // RustBucket (kept explicit here — heuristic below already covers .helper suffix but this is a known IOC)
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

    /// Canonical vendor / brand names that macOS malware routinely spoofs with visually
    /// similar characters — capital-I for lowercase-l, Cyrillic а/е/о, digit 0 for O, etc.
    /// Any Application Support / LaunchAgents folder that "looks like" one of these but
    /// isn't a byte-for-byte match is treated as impersonation.
    /// NimDoor (2025) used "GoogIe LLC" (capital-I) to shadow "Google LLC".
    public static let impersonatedBrandNames: [String] = [
        "Apple", "Google", "Google LLC", "Microsoft", "Microsoft Corporation",
        "iCloud", "Adobe", "Zoom", "Zoom Video Communications",
        "Dropbox", "Slack", "Telegram", "Discord",
    ]

    /// True when `candidate` visually resembles one of `impersonatedBrandNames` but
    /// isn't an exact match — the hallmark IOC of the 2025-2026 DPRK loaders.
    public static func isLookalikeBrandName(_ candidate: String) -> Bool {
        // Skip exact and case-insensitive-exact matches — those are the real names, not spoofs.
        for real in impersonatedBrandNames {
            if candidate == real { return false }
            if candidate.lowercased() == real.lowercased() { return false }
        }
        // Normalize the candidate: strip common lookalike substitutions and compare.
        for real in impersonatedBrandNames {
            if normalizeLookalike(candidate).lowercased() == real.lowercased() {
                return true
            }
        }
        // Any non-ASCII in what should be a plain ASCII vendor name is suspect
        // (Cyrillic а/е/о, Greek ο, fullwidth Latin, etc.).
        for real in impersonatedBrandNames {
            if candidate.count == real.count &&
               candidate.contains(where: { !$0.isASCII }) &&
               normalizeLookalike(candidate).lowercased() == real.lowercased() {
                return true
            }
        }
        return false
    }

    /// Fold visually similar characters to their ASCII counterparts so lookalikes collapse to the real name.
    private static func normalizeLookalike(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for ch in s {
            switch ch {
            // Capital-I / lowercase-L / digit-1 all render nearly identically in most fonts.
            case "I": out.append("l")
            case "1": out.append("l")
            // Common Cyrillic / Greek homoglyphs used in 2024-2026 lures.
            case "а", "α", "Α": out.append("a")
            case "е", "ε", "Ε": out.append("e")
            case "о", "ο", "Ο": out.append("o")
            case "р", "ρ", "Ρ": out.append("p")
            case "с", "ϲ": out.append("c")
            case "х", "χ": out.append("x")
            case "у": out.append("y")
            case "і": out.append("i")
            case "ѕ": out.append("s")
            case "К", "κ", "Κ": out.append("k")
            case "0": out.append("o")
            default: out.append(ch)
            }
        }
        return out
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
