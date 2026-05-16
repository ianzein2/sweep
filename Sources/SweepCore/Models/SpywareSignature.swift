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
        // Modern macOS malware (2024-2026)
        SpywareSignature(
            // DPRK Lazarus subgroup BlueNoroff, Mar 2025. Delivered via fake Zoom invite
            // that drops a Nim-compiled binary. Persists via two LaunchAgents and stages
            // crypto-wallet theft via `/Users/Shared/.googl/coregkr`.
            name: "NimDoor",
            processNames: ["coregkr", "nimdoor", "GoogleHelper", "zoom_sdk_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/Users/Shared/.googl",
                "/Users/Shared/.googl/coregkr",
                "~/.zen_error",
                "~/Library/Application Support/.googl",
            ],
            launchAgentLabels: [
                "com.googl.host",
                "com.googl.coregkr",
                "com.google.zoomvideo",
            ]
        ),
        SpywareSignature(
            // DPRK "Contagious Interview" campaign; second-stage JavaScript dropper used
            // when developers run a poisoned npm package during a fake job interview.
            name: "BeaverTail",
            processNames: ["beavertail", "BeaverTail", "n2.js", "main.js"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.beavertail",
                "/private/tmp/p.zi",
                "~/.npl",
                "~/.n2/pay",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Companion Python implant dropped by BeaverTail; collects browser profiles,
            // crypto wallets, and SSH keys.
            name: "InvisibleFerret",
            processNames: ["invisibleferret", "InvisibleFerret", "pay", "python_loader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.invisibleferret",
                "~/.config/.npl",
                "~/.python_history.tmp",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // DPRK BlueNoroff (Oct 2024); disguised as a "Risk factors for Bitcoin price
            // decline" PDF. Installs an x86_64 backdoor inside `~/Library/Group Containers`.
            name: "OSX.HiddenRisk",
            processNames: ["hiddenrisk", "growth", "macnotifyd"],
            bundleIdentifiers: [],
            filePaths: [
                "/Users/Shared/.growth",
                "~/Library/Group Containers/.hiddenrisk",
            ],
            launchAgentLabels: ["com.apple.growth", "com.macnotifyd"]
        ),
        SpywareSignature(
            // ALPHV-linked Mach-O backdoor; persists as `/Library/Application Support/RustDoor`
            // and drops binaries in `/tmp/test` and `/var/tmp/lock`.
            name: "OSX.RustDoor",
            processNames: ["rustdoor", "RustDoor", "ARMv2", "Trembler", "thread"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/Application Support/RustDoor",
                "/tmp/test",
                "/var/tmp/lock",
                "~/Library/Application Support/.rustdoor",
            ],
            launchAgentLabels: ["com.apple.rustdoor", "com.apple.systempreferences.helper.rust"]
        ),
        SpywareSignature(
            // Aug 2025 SHAMOS campaign — AMOS variant distributed by COOKIE SPIDER via
            // ClickFix-style fake "macOS troubleshooting" pages that ask the user to paste
            // a malicious `curl … | bash` line into Terminal.
            name: "SHAMOS (AMOS variant)",
            processNames: ["shamos", "Shamos", "update.sh", "z.sh", "install.sh"],
            bundleIdentifiers: ["com.shamos.installer"],
            filePaths: [
                "/private/tmp/.shamos",
                "/private/tmp/update.sh",
                "/private/tmp/z.sh",
                "~/Library/Application Support/.shamos",
            ],
            launchAgentLabels: ["com.shamos.installer"]
        ),
        SpywareSignature(
            // Feb 2025; redirect-and-prompt campaign that pushes a fake Safari update; once
            // executed, drops Mach-O stealer modules in /tmp and exfiltrates wallets.
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid", "DOMAIN", "rd"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "/private/tmp/rd",
                "~/Library/Application Support/.Frigid",
            ],
            launchAgentLabels: ["com.frigid.agent"]
        ),
        SpywareSignature(
            // ClickFix loader — a social-engineering technique where a fake CAPTCHA tells the
            // user to paste a command. The dropper installs a persistence agent named to look
            // benign ("System Update Helper", "macOS Update Service").
            name: "ClickFix Loader",
            processNames: ["clickfix", "macupdate_helper", "update_helper", "systemupdater"],
            bundleIdentifiers: ["com.macos.update", "com.system.update.helper"],
            filePaths: [
                "/private/tmp/.clickfix",
                "/private/tmp/update_check",
                "~/Library/Application Support/.update_helper",
            ],
            launchAgentLabels: [
                "com.macos.update.helper",
                "com.systemupdater.daemon",
            ]
        ),
        SpywareSignature(
            // 2024-2025 macOS port of the Windows StealC family; pulls cookies, password
            // databases, and Apple Notes via a stealthy XPC helper.
            name: "StealC (macOS)",
            processNames: ["stealc", "StealC", "stc_macos", "AppleHelperXPC"],
            bundleIdentifiers: ["com.stealc.macos"],
            filePaths: [
                "/private/tmp/.stealc",
                "~/Library/Application Support/.stealc",
            ],
            launchAgentLabels: ["com.stealc.agent", "com.apple.helper.xpc"]
        ),
        SpywareSignature(
            // 2025; OCR-based screenshot scraper extracting seed phrases from saved images.
            // Variant of the SparkCat trojan ported from Android to Mac via fake AI image
            // apps and "wallet recovery" utilities.
            name: "SparkKitty",
            processNames: ["sparkkitty", "SparkKitty", "ImageDescribe", "spark_ocr"],
            bundleIdentifiers: [
                "com.sparkkitty.macos",
                "com.spark.imagedescribe",
            ],
            filePaths: [
                "~/Library/Application Support/.sparkkitty",
                "~/Library/Containers/.spark_ocr",
            ],
            launchAgentLabels: ["com.sparkkitty.service"]
        ),
        SpywareSignature(
            // Aug 2024 npm-borne backdoor disguised as a "DapiNet" or "Hyper-React" package.
            // Drops a Python loader and persists via crontab.
            name: "CherryPie",
            processNames: ["cherrypie", "CherryPie", "dapinet", "hyper_react"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.cherrypie",
                "~/.cherry_cron",
                "~/Library/Application Support/.cherrypie",
            ],
            launchAgentLabels: ["com.cherrypie.agent"]
        ),
        SpywareSignature(
            // Suspected DPRK-linked remote-access trojan deployed against crypto exchanges
            // (early 2025). Persists via a fake "TigerVNC" helper.
            name: "TigerRAT",
            processNames: ["TigerRAT", "tigerrat", "tigerhelper", "TigerVNCHelper"],
            bundleIdentifiers: ["com.tigervnc.helper"],
            filePaths: [
                "/private/tmp/.tiger",
                "~/Library/Application Support/.TigerRAT",
            ],
            launchAgentLabels: ["com.tigervnc.helper", "com.tiger.agent"]
        ),
        SpywareSignature(
            // Aug 2024 Mach-O backdoor used by Lazarus subgroup TraderTraitor in social
            // engineering aimed at crypto traders. Persists via a LaunchAgent disguised
            // as a Discord plugin.
            name: "TodoSwift",
            processNames: ["todoswift", "TodoSwift", "DiscordHelper", "todo_app"],
            bundleIdentifiers: ["com.discord.helper.todo"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.todoswift",
            ],
            launchAgentLabels: ["com.discord.helper", "com.todoswift.daemon"]
        ),
        SpywareSignature(
            // BlueNoroff 2024 "HappyDoor" — drops a XOR-encrypted dylib in
            // ~/Library/LaunchAgents and pivots to keychain exfiltration.
            name: "HappyDoor",
            processNames: ["happydoor", "HappyDoor", "happy_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.happydoor",
                "~/Library/Application Support/.happy",
            ],
            launchAgentLabels: ["com.happydoor.service", "com.apple.happyhelper"]
        ),
        SpywareSignature(
            // 2024 "Banshee 2.0" / source-leak variants distributed by the BANSHEE-affiliated
            // panel after the v1 leak; new process names and staging paths.
            name: "Banshee 2.0 (post-leak variants)",
            processNames: ["BansheeNext", "banshee_v2", "bn2", "MacOptimizer"],
            bundleIdentifiers: ["com.banshee.v2", "com.macoptimizer.agent"],
            filePaths: [
                "/private/tmp/.banshee2",
                "/private/tmp/.bn2",
                "~/Library/Application Support/.MacOptimizer",
            ],
            launchAgentLabels: ["com.banshee.v2", "com.macoptimizer.agent"]
        ),
        SpywareSignature(
            // 2024 AMOS spin-off marketed as "Crystal Stealer" on underground forums —
            // distributed through cracked-software lures (Final Cut Pro, Logic Pro keygens).
            name: "Crystal Stealer",
            processNames: ["crystal_stealer", "CrystalStealer", "crystal", "FCPHelper"],
            bundleIdentifiers: ["com.crystal.stealer"],
            filePaths: [
                "/private/tmp/.crystal",
                "~/Library/Application Support/.Crystal",
            ],
            launchAgentLabels: ["com.crystal.agent"]
        ),
        SpywareSignature(
            // 2024 PyInstaller-packaged stealer that ships its own Python runtime in a
            // hidden folder. Frequently signed ad-hoc and reuses the AMOS exfil endpoint.
            name: "MyDoom (macOS port)",
            processNames: ["mydoom_mac", "MyDoom", "macdoom", "pyinst_helper"],
            bundleIdentifiers: ["com.mydoom.mac"],
            filePaths: [
                "/private/tmp/.mydoom",
                "~/Library/Application Support/.mydoom",
            ],
            launchAgentLabels: ["com.mydoom.agent"]
        ),
        SpywareSignature(
            // 2025 multi-payload backdoor delivered via trojanized "GameInstaller" .pkg files
            // targeting macOS gaming forums; persists with a fake `gameservice` LaunchDaemon.
            name: "GamingDoor",
            processNames: ["gamingdoor", "GameService", "game_service", "macgame_agent"],
            bundleIdentifiers: ["com.gameservice.agent"],
            filePaths: [
                "/private/tmp/.gamingdoor",
                "/Library/Application Support/.gameservice",
            ],
            launchAgentLabels: ["com.gameservice.agent", "com.macgame.daemon"]
        ),
        SpywareSignature(
            // DPRK/Citrine Sleet 2024-2025 — uses the "FrostyFerret" macOS implant after
            // phishing victims with malicious browser extension installers.
            name: "FrostyFerret",
            processNames: ["frostyferret", "FrostyFerret", "FrostHelper", "browserUpdate"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.frosty",
                "~/Library/Application Support/.FrostyFerret",
            ],
            launchAgentLabels: ["com.browser.update.helper", "com.frosty.service"]
        ),
        SpywareSignature(
            // 2025 Russian-speaking actor distributed loader; common payload is the
            // open-source Mythic C2 "Poseidon" agent recompiled for macOS.
            name: "Mythic Poseidon Agent",
            processNames: ["mythic_poseidon", "PoseidonAgent", "mythicd", "c2_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.mythic",
                "~/Library/Application Support/.mythic",
            ],
            launchAgentLabels: ["com.mythic.poseidon", "com.c2.helper"]
        ),
        SpywareSignature(
            // 2025 dropper that abuses xattr quarantine clearing via osascript before
            // running an unsigned Mach-O. Often staged under a "Crypto Tools" lure.
            name: "Xattr Dropper",
            processNames: ["xattrdrop", "xattr_drop", "CryptoTools", "MacUtilities"],
            bundleIdentifiers: ["com.cryptotools.macos", "com.macutilities.app"],
            filePaths: [
                "/private/tmp/.xattrdrop",
                "/private/tmp/CryptoTools",
            ],
            launchAgentLabels: ["com.cryptotools.agent"]
        ),
        SpywareSignature(
            // 2024 "Coyote" macOS port — originally a Brazilian Windows banker; the macOS
            // build targets crypto-exchange web sessions via an Electron overlay.
            name: "Coyote (macOS)",
            processNames: ["coyote_mac", "Coyote", "coyote_agent", "BankerOverlay"],
            bundleIdentifiers: ["com.coyote.mac"],
            filePaths: [
                "/private/tmp/.coyote",
                "~/Library/Application Support/.Coyote",
            ],
            launchAgentLabels: ["com.coyote.agent"]
        ),
        SpywareSignature(
            // Sep 2024 GoSorry / GoCrypt — Go-based stealer distributed through fake
            // "DePIN node" installers targeting Helium / IO.net operators.
            name: "GoSorry / GoCrypt",
            processNames: ["gosorry", "GoCrypt", "depin_node", "ionet_helper"],
            bundleIdentifiers: ["com.depin.node", "com.ionet.helper"],
            filePaths: [
                "/private/tmp/.gosorry",
                "~/Library/Application Support/.gocrypt",
            ],
            launchAgentLabels: ["com.depin.node", "com.gocrypt.service"]
        ),
        SpywareSignature(
            // 2025 PhantomVPN — fake VPN client trojan with system-extension persistence
            // that captures network credentials and proxies traffic through C2.
            name: "PhantomVPN",
            processNames: ["phantomvpn", "PhantomVPN", "PhantomVPNHelper", "PhantomTunnel"],
            bundleIdentifiers: ["com.phantomvpn.macos", "com.phantomvpn.helper"],
            filePaths: [
                "/Applications/PhantomVPN.app",
                "~/Library/Application Support/PhantomVPN",
            ],
            launchAgentLabels: ["com.phantomvpn.helper", "com.phantomtunnel.daemon"]
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
        // Seen in 2024-2025 campaigns (NimDoor, HiddenRisk, ClickFix, FrostyFerret, etc.)
        "com.apple.growth",
        "com.apple.happyhelper",
        "com.apple.helper.xpc",
        "com.apple.rustdoor",
        "com.apple.systempreferences.helper.rust",
        "com.apple.systempreferences.helper",
        "com.apple.kernel_service",
        "com.apple.macshare.plist",
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
