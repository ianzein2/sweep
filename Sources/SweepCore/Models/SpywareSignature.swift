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
        // 2025 macOS infostealers / loaders
        SpywareSignature(
            name: "ModStealer",
            // ModStealer was disclosed by Mosyle in Sept 2025 — a Node.js-based stealer that
            // targets crypto wallet extensions, keychain entries, and browser data, distributed
            // through fake recruiter "coding test" lures (LinkedIn/Telegram).
            processNames: ["ModStealer", "modstealer", ".sysupdater", "node_helper",
                           "applesystem", "AppleSystemUpdater", "system_helper"],
            bundleIdentifiers: ["com.modstealer.agent", "com.system.updater.helper"],
            filePaths: [
                "/private/tmp/.modstealer",
                "~/Library/Application Support/.modstealer",
                "~/Library/LaunchAgents/com.apple.system.update.plist",
                "~/.npm/_cacache/.modstealer",
            ],
            launchAgentLabels: ["com.modstealer.agent", "com.apple.system.update"]
        ),
        SpywareSignature(
            name: "FrigidStealer (FROSTYFERRET)",
            // Fake browser-update lure that drops a notarized DMG installing an AppleScript
            // / Mach-O stealer dropping wallet and keychain data. Active 2024-2025.
            processNames: ["FrigidStealer", "frigid", "FrostyFerret", "marsx",
                           "frigid_helper"],
            bundleIdentifiers: ["com.frigid.stealer", "com.frostyferret.agent",
                                "com.macos.updater.helper"],
            filePaths: [
                "/private/tmp/.frigid",
                "/private/tmp/MacOSUpdater",
                "~/Library/Application Support/.FrigidStealer",
                "~/Library/Application Support/.frosty",
            ],
            launchAgentLabels: ["com.frigid.agent", "com.frostyferret.service"]
        ),
        SpywareSignature(
            name: "ReaderUpdate",
            // Long-running malware-as-a-service loader (Crystal, Nim, Rust variants)
            // distributed since 2020 and resurgent in 2025. Persists via LaunchAgent and
            // pulls follow-on payloads (often Genieo / Adload / Atomic).
            processNames: ["ReaderUpdate", "readerupdate", "reader_update",
                           "ReaderUpdater", "readerupdated"],
            bundleIdentifiers: ["com.readerupdate", "com.readerupdater.agent"],
            filePaths: [
                "~/Library/Application Support/com.ReaderUpdate",
                "~/Library/Application Support/.ReaderUpdate",
                "~/Library/LaunchAgents/com.ReaderUpdate.plist",
                "~/Library/LaunchAgents/com.ReaderUpdater.plist",
            ],
            launchAgentLabels: ["com.ReaderUpdate", "com.ReaderUpdater",
                                "com.readerupdate.daemon"]
        ),
        SpywareSignature(
            name: "Crystalsteel / NimDoor",
            // Nim/Crystal-language loaders from DPRK-aligned activity (BlueNoroff family),
            // dropped through fake Zoom/Teams meeting installers. 2025.
            processNames: ["NimDoor", "nimdoor", "Crystalsteel", "crystalsteel",
                           "ZoomMeetingHelper", "TeamsHelper", "trolagent"],
            bundleIdentifiers: ["com.zoom.helper.update", "com.microsoft.teams.helper"],
            filePaths: [
                "/private/tmp/.nimdoor",
                "/private/var/tmp/.crystal",
                "~/Library/Application Support/.nimdoor",
                "~/Library/Application Support/.crystal",
            ],
            launchAgentLabels: ["com.zoom.update.helper",
                                "com.microsoft.teams.update.helper"]
        ),
        // North Korea "Contagious Interview" (CL-STA-0240) campaign — 2024-2025
        SpywareSignature(
            name: "BeaverTail",
            // JavaScript stealer dropped through fake job-interview NPM packages and
            // electron apps. Steals browser data and crypto wallets, then loads InvisibleFerret.
            processNames: ["BeaverTail", "beavertail", "FCCCallTool", "FCCCall",
                           "MiroTalk", "Coder.exe", "node_modules_helper"],
            bundleIdentifiers: ["com.beavertail.agent", "com.fcc.call.tool",
                                "com.coder.helper"],
            filePaths: [
                "/private/tmp/.beavertail",
                "~/Library/Application Support/.beavertail",
                "~/Library/Caches/.npm-helper",
            ],
            launchAgentLabels: ["com.beavertail.service"]
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            // Python backdoor stage-2 of the Contagious Interview chain.
            // Provides remote shell, keylogging, and crypto-wallet exfil.
            processNames: ["InvisibleFerret", "invisibleferret", "pay", "bow",
                           "p.zi", "ssid.py", "pyp", "msu"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.n2/pay",
                "/private/tmp/.n2/bow",
                "~/.n2",
                "~/.npl",
                "~/Library/Application Support/.npl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "OtterCookie",
            // Newer Contagious Interview JS stealer (late 2024/2025) — replaces or
            // supplements BeaverTail. Steals clipboard, browser, and wallet data.
            processNames: ["OtterCookie", "ottercookie", "otter", "otter_helper"],
            bundleIdentifiers: ["com.ottercookie.agent"],
            filePaths: [
                "/private/tmp/.otter",
                "~/Library/Application Support/.ottercookie",
            ],
            launchAgentLabels: ["com.ottercookie.service"]
        ),
        SpywareSignature(
            name: "PylangGhost / GolangGhost (Lazarus)",
            // Cross-platform RAT (Python and Go variants) attributed to Famous Chollima /
            // Lazarus, distributed in fake job interview "skills test" packages in 2025.
            processNames: ["pylangghost", "PylangGhost", "golangghost", "GolangGhost",
                           "ghost", "py_helper", "go_helper"],
            bundleIdentifiers: ["com.pylangghost.agent", "com.golangghost.agent"],
            filePaths: [
                "/private/tmp/.pylangghost",
                "/private/tmp/.golangghost",
                "~/Library/Application Support/.ghost",
            ],
            launchAgentLabels: ["com.pylangghost.service",
                                "com.golangghost.service"]
        ),
        SpywareSignature(
            name: "Realst (cross-platform updates)",
            // Updated Realst variants seen 2024-2025 distributed as "blockchain games"
            // via fake Web3 startup pitches. Already covered above; this entry adds
            // new sample names and paths observed in the wild.
            processNames: ["Brawl Earth", "BrawlEarth", "SeaCraft", "JungleSwap",
                           "ChainShift", "Chain Shift", "PearlClub"],
            bundleIdentifiers: ["com.brawlearth.app", "com.seacraft.app",
                                "com.jungleswap.app", "com.chainshift.app"],
            filePaths: [
                "/private/tmp/.realst2",
                "~/Library/Application Support/.brawl",
                "~/Library/Application Support/.seacraft",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "RustyAttr",
            // RustyAttr (RustDoor lineage, late 2024) — uses extended attributes to
            // hide its second-stage payload. Distributed as PDF lures.
            processNames: ["RustyAttr", "rustyattr", "rustdoor", "rusty_helper"],
            bundleIdentifiers: ["com.rustyattr.agent"],
            filePaths: [
                "/private/tmp/.rustyattr",
                "~/Library/Application Support/.rustyattr",
            ],
            launchAgentLabels: ["com.rustyattr.service"]
        ),
        SpywareSignature(
            name: "HZ RAT (HZRat)",
            // Chinese-speaking actor RAT ported to macOS (mid-2024) — typically dropped
            // alongside fake DingTalk/WeChat installers. Receives commands over TCP/4444 family ports.
            processNames: ["hzrat", "HZRat", "HZRat-helper", "DingTalkHelper",
                           "WeChatHelper.bin"],
            bundleIdentifiers: ["com.hzrat.agent", "com.dingtalk.helper.update"],
            filePaths: [
                "/private/tmp/.hzrat",
                "~/Library/Application Support/.hzrat",
            ],
            launchAgentLabels: ["com.hzrat.service",
                                "com.dingtalk.update.helper"]
        ),
        SpywareSignature(
            name: "Cuckoo Stealer (2025 wave)",
            // Resurgent Cuckoo activity in 2025 disguised as cracked-app installers.
            // We list only the specific IOC sample names from public reports — generic
            // names like "OptimizerPro" overlap with legitimate (if pushy) commercial apps.
            processNames: ["DupeZap", "FoneTransHelper", "DumpMediaSpotifyConverter2",
                           "cuckoo_helper"],
            bundleIdentifiers: ["com.dupezap.app", "com.fonetrans.helper.app"],
            filePaths: [
                "/private/tmp/.cuckoo2",
                "~/Library/Application Support/.dupezap",
                "~/Library/Application Support/.fonetrans",
            ],
            launchAgentLabels: ["com.dupezap.service",
                                "com.fonetrans.helper"]
        ),
        SpywareSignature(
            name: "TodoSwift (BlueNoroff 2024-25)",
            // BlueNoroff macOS dropper masquerading as a Bitcoin price app. Pulls
            // a follow-on payload over HTTP and stores it under a fake .todo path.
            // Process names are constrained to the specific IOC samples reported by
            // Kandji / Jamf to avoid false positives on legitimate price-tracker apps.
            processNames: ["TodoSwift", "todoswift", "todoswift_helper"],
            bundleIdentifiers: ["com.todoswift.app", "com.todoswift.helper"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.todoswift",
            ],
            launchAgentLabels: ["com.todoswift.service",
                                "com.todoswift.helper"]
        ),
        SpywareSignature(
            name: "RustBucket (2024-25 variants)",
            // Lazarus / BlueNoroff RustBucket lineage with new dropper names. Already
            // covered above; this entry adds the newer SwiftLoader / FullHouse names.
            processNames: ["SwiftLoader", "FullHouse", "FullHouseDoor",
                           "InternalPDFViewer", "PDFViewerLite"],
            bundleIdentifiers: ["com.swiftloader.app", "com.fullhouse.app",
                                "com.internalpdf.viewer"],
            filePaths: [
                "/private/var/tmp/.swiftloader",
                "/private/var/tmp/.fullhouse",
                "~/Library/Caches/.pdfviewer",
            ],
            launchAgentLabels: ["com.swiftloader.service",
                                "com.fullhouse.helper"]
        ),
        // 2025 macOS adware/PUPs that frequently chain into stealers
        SpywareSignature(
            name: "Adload / Shlayer (2025 variants)",
            // Adload + Shlayer remain the most common macOS malware families. Frequently
            // delivers stealers as second-stage. New 2025 dropper names observed.
            processNames: ["mediadownloader", "MediaTab", "ChampionSearch",
                           "OperativeMachine", "ResultProcedure", "SearchUnit",
                           "ConfigType", "ConfigData", "ManagerAnalog"],
            bundleIdentifiers: ["com.mediadownloader.app", "com.mediatab.app",
                                "com.championsearch.app", "com.searchunit.app",
                                "com.configtype.app"],
            filePaths: [
                "~/Library/Application Support/com.MediaTab",
                "~/Library/Application Support/com.ChampionSearch",
                "~/Library/LaunchAgents/com.MediaTab.plist",
                "~/Library/LaunchAgents/com.SearchUnit.plist",
            ],
            launchAgentLabels: ["com.MediaTab", "com.SearchUnit",
                                "com.ChampionSearch", "com.OperativeMachine",
                                "com.ConfigType.helper", "com.ConfigData.helper"]
        ),
        // OSX.Trigona / OSX.LockBit variants (rare but real 2024-25 macOS ransomware activity)
        SpywareSignature(
            name: "OSX.LockBit (proof-of-concept)",
            // The LockBit gang published macOS-targeted ransomware POCs in 2023-24. Real
            // infections are rare but the binaries are signed and notarized in some samples.
            processNames: ["locker_Apple_M1_64", "locker_Apple_X86_64",
                           "lockbit_apple", "lockbit-arm"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/locker_Apple_M1_64",
                "/private/tmp/locker_Apple_X86_64",
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
