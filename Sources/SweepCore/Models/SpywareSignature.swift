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
        // DPRK / Lazarus follow-on families (2024-2026)
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            // BeaverTail runs inside `node`, so the strongest single-name IOCs are the
            // second-stage drops; we keep process names distinctive to avoid false positives
            // (generic names like "p" or "pay" would flag countless legitimate binaries).
            processNames: ["beavertail", "BeaverTail", "beavertail_loader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/p.exe",
                "/private/tmp/.n2/pay",
                "/private/tmp/mainssz",
                "~/Library/Application Support/.beaver",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            // Python-based second stage dropped by BeaverTail on infected developer laptops.
            processNames: ["invisibleferret", "InvisibleFerret", "pyperclip_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/ssdd",
                "/private/tmp/mainssz",
                "~/Library/Application Support/.invferret",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "NimDoor",
            // Nim-compiled backdoor observed in 2025 campaigns against Web3 / crypto orgs.
            // Installers masquerade as Google/Zoom updater components; we can't use the real
            // "GoogleUpdater" / "ZoomUpdater" process names as IOCs since those are legitimate
            // vendor binaries. The file-path indicators below (drops in /tmp and hidden dirs)
            // are the actionable ones.
            processNames: ["NimDoor", "nimdoor"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.nimdoor",
                "/private/tmp/.GoogleUpdater",
                "~/Library/Application Support/.GoogleUpdater",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "RustDoor / SimpleTea",
            // Rust-compiled BlueNoroff backdoor first documented in 2024. Drops as generically-
            // named binaries in /tmp and installs a fake system-update LaunchAgent. We keep the
            // process names distinctive; the generic "test" name they sometimes use would false-
            // positive on countless CI and developer binaries.
            processNames: ["rustdoor", "RustDoor", "simpletea", "SimpleTea"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.rustdoor",
                "~/Library/SystemUpdate/.simpletea",
            ],
            launchAgentLabels: [
                "com.apple.systemupdate", "com.apple.rustupdate",
            ]
        ),
        SpywareSignature(
            name: "RokRAT (APT37)",
            processNames: ["RokRAT", "rokrat", "coreui_agent"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.rokrat"],
            launchAgentLabels: ["com.apple.coreui.agent"]
        ),
        // Chinese-language / APT41-linked
        SpywareSignature(
            name: "HZ RAT (macOS)",
            processNames: ["HZRAT", "hzrat", "hzagent"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.hz",
                "/private/tmp/.hzrat",
            ],
            launchAgentLabels: ["com.hz.agent"]
        ),
        SpywareSignature(
            name: "MacMa / CDDS (APT41)",
            // "UserAgent" as a process name is far too common (browsers, curl helpers, MDM tools);
            // we anchor the signature on the fake launch label and the drop paths instead.
            processNames: ["macma", "MacMa", "cdds_agent"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/UserAgent",
                "/Library/Preferences/com.apple.softwareupdate.plist.bak",
                "/private/tmp/.cdds",
            ],
            launchAgentLabels: ["com.apple.UserAgent"]
        ),
        SpywareSignature(
            name: "JokerSpy",
            // Python-based backdoor with a hidden helper installed under the QuickLook daemon
            // directory to survive across sessions.
            processNames: ["xcc", "jokerspy", "sh.py.py"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/QuickLookDaemon",
                "~/Library/JokerSpy",
                "/private/tmp/.joker",
            ],
            launchAgentLabels: ["com.apple.xccservice"]
        ),
        // 2025 stealer campaigns
        SpywareSignature(
            name: "FrigidStealer",
            // AMOS-family variant delivered by fake browser update lures (Feb 2025).
            processNames: ["FrigidStealer", "FrigidUpdate", "frigid"],
            bundleIdentifiers: ["com.frigid.updater", "com.frigid.stealer"],
            filePaths: [
                "/private/tmp/FrigidUpdate",
                "~/Library/Application Support/.FrigidUpdate",
            ],
            launchAgentLabels: ["com.frigid.updater"]
        ),
        SpywareSignature(
            name: "ShadowVault",
            processNames: ["ShadowVault", "shadowvault"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.shadowvault",
                "~/Library/Application Support/.ShadowVault",
            ],
            launchAgentLabels: ["com.shadowvault.agent"]
        ),
        SpywareSignature(
            name: "CherryPie (macOS)",
            processNames: ["CherryPie", "cherrypie", "cpstealer"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.cherrypie"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "JSCEAL",
            // Late 2025 AMOS spin-off; the loader runs JavaScript from a compiled bundle.
            processNames: ["jsceal", "JSCEAL", "jsceal_agent"],
            bundleIdentifiers: ["com.jsceal.agent"],
            filePaths: [
                "/private/tmp/.jsceal",
                "~/Library/Application Support/.jsceal",
            ],
            launchAgentLabels: ["com.jsceal.service"]
        ),
        SpywareSignature(
            name: "PylotAgent",
            processNames: ["PylotAgent", "pylotagent"],
            bundleIdentifiers: ["com.pylot.agent"],
            filePaths: ["~/Library/Application Support/.pylot"],
            launchAgentLabels: ["com.pylot.agent"]
        ),
        SpywareSignature(
            name: "XLoader (macOS)",
            // FormBook family port to macOS, still delivered via fake DMGs. We anchor on the
            // family name only; the "OfficeUpdate" label these drops sometimes use overlaps
            // with legitimate Microsoft AutoUpdate infrastructure.
            processNames: ["xloader", "XLoader"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.xloader",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "MicroBackdoor (macOS)",
            processNames: ["mbd", "microbackdoor", "MicroBackdoor"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.mbd"],
            launchAgentLabels: ["com.mbd.helper"]
        ),
        // Long-standing adware families with fresh droppers seen through 2025
        SpywareSignature(
            name: "AdLoad",
            // AdLoad droppers pick short generic names ("Player", "Extension", "Alerts"). Those
            // would false-positive too easily, so we key the signature on the family's own
            // distinctive bundle labels; the file paths under Application Support anchor it too.
            processNames: [
                "SafeFinder", "AdvancedSearch", "MacSaver",
                "com.PlayerHelper.HelperTool",
                "com.SearchDaemon.Daemon",
            ],
            bundleIdentifiers: [
                "com.PlayerHelper.HelperTool",
                "com.SearchDaemon.Daemon",
                "com.AdvancedSearch.Extension",
            ],
            filePaths: [
                "~/Library/Application Support/com.PlayerHelper.HelperTool",
                "~/Library/Application Support/com.SearchDaemon.Daemon",
                "~/Library/Application Support/com.AdvancedSearch.Extension",
            ],
            launchAgentLabels: [
                "com.PlayerHelper.HelperTool",
                "com.SearchDaemon.Daemon",
                "com.AdvancedSearch.Extension",
            ]
        ),
        SpywareSignature(
            name: "Bundlore",
            processNames: [
                "Bundlore", "bundlore", "IronMules", "mm-install-macos",
            ],
            bundleIdentifiers: ["com.bundlore.installer"],
            filePaths: [
                "/private/tmp/mm-install-macos",
                "~/Library/Application Support/.bundlore",
            ],
            launchAgentLabels: ["com.bundlore.installer"]
        ),
        SpywareSignature(
            name: "Silver Sparrow",
            // Anchored on the family's specific bundle IDs and drop-file names — "agent" alone
            // would false-positive on countless legitimate helper processes.
            processNames: ["silversparrow", "SilverSparrow", "agent_updater"],
            bundleIdentifiers: ["com.updater.mssse", "com.updater.mchtsser"],
            filePaths: [
                "/tmp/agent.sh",
                "/tmp/agent.plist",
                "/tmp/verx.sh",
                "/tmp/version.json",
                "/tmp/version.plist",
                "/Library/._insu",
                "~/Library/Application Support/agent_updater",
                "~/Library/._insu",
            ],
            launchAgentLabels: ["com.updater.mssse", "init_verx"]
        ),
        // Cryptojackers — dropped by other malware or bundled with cracked software.
        // Any of these running on a personal Mac usually means the user did not install it.
        SpywareSignature(
            name: "XMRig cryptominer",
            processNames: ["xmrig", "XMRig", "xmrig-mo", "xmrigMiner"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/xmrig",
                "~/Library/Application Support/.miner/xmrig",
                "/usr/local/bin/xmrig",
            ],
            launchAgentLabels: ["com.xmrig.miner", "com.system.miner"]
        ),
        SpywareSignature(
            name: "LoudMiner / BirdMiner",
            // LoudMiner shipped a QEMU-hosted Linux miner inside macOS Audio Unit packages.
            // "loop" is too common as a process name to use standalone; anchor on the fake
            // Application Support path (real Apple daemons never live under Application Support).
            processNames: ["loudminer", "LoudMiner", "birdminer"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/com.WindowServer",
                "~/Library/Application Support/.loop",
            ],
            launchAgentLabels: ["com.WindowServer.plist", "com.LoudMiner.helper"]
        ),
        SpywareSignature(
            name: "Generic cryptominer (cpuminer/minerd/T-Rex)",
            // Trimmed to unambiguous miner binary names. Legitimate cryptocurrency users on
            // macOS are rare, and even they typically wouldn't run these under a personal
            // login session.
            processNames: [
                "minerd", "cpuminer", "t-rex", "ethminer",
                "nicehash", "nicehashquickminer", "cgminer", "bfgminer",
                "coinminer",
            ],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/minerd",
                "/private/tmp/cpuminer",
                "~/Library/Application Support/.coinminer",
            ],
            launchAgentLabels: ["com.coinminer.helper"]
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
        // Observed 2024-2026 masquerades
        "com.apple.rustupdate",
        "com.apple.UserAgent",
        "com.apple.xccservice",
        "com.apple.coreui.agent",
        "com.apple.systempreferences.helper",
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
