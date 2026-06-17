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
        // 2024-2026 APT-linked macOS malware
        SpywareSignature(
            // Nim-based DPRK backdoor used in fake-recruiter campaigns (SentinelOne, Jul 2025)
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "GoogIeUpdater", "ZoomVideoSDK", "zoom_sdk_helper", "Trii"],
            bundleIdentifiers: ["com.zoomvideo.sdk.helper"],
            filePaths: [
                "/private/var/tmp/.nimdoor",
                "~/Library/Application Support/.nimdoor",
                "/private/tmp/Trii",
            ],
            launchAgentLabels: ["com.google.update.agent", "com.zoom.sdk.helper"]
        ),
        SpywareSignature(
            // Chinese-language surveillance toolkit (Kaspersky/Kandji, 2025)
            name: "PasivRobber",
            processNames: ["pasivrobber", "PasivRobber", "wpsbeta_helper", "wpsd"],
            bundleIdentifiers: ["com.wps.macos.officebeta.helper"],
            filePaths: [
                "/private/var/tmp/.pasiv",
                "~/Library/Application Support/.wpsbeta",
            ],
            launchAgentLabels: ["com.wpsoffice.beta.helper"]
        ),
        SpywareSignature(
            // Apple-themed infostealer surfaced mid-2025
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "AppleAccountHelper", "appleaccountd"],
            bundleIdentifiers: ["com.apple.process.hub", "com.apple.account.helper"],
            filePaths: [
                "/private/tmp/.applehub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.process.hub", "com.apple.account.helper"]
        ),
        SpywareSignature(
            // Browser-distributed stealer (Proofpoint, Feb 2025)
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigid_stealer", "ChromeUpdate", "SafariUpdate", "BrowserUpdate"],
            bundleIdentifiers: ["com.frigid.stealer", "com.browserupdate.helper"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
                "~/Library/Application Support/BrowserUpdate",
            ],
            launchAgentLabels: ["com.frigid.service", "com.browserupdate.agent"]
        ),
        SpywareSignature(
            // SwiftUI-based macOS dropper (Kaspersky, Aug 2024)
            name: "TodoSwift",
            processNames: ["TodoSwift", "todoswift", "TodoTasks", "todotasksd"],
            bundleIdentifiers: ["com.todoswift.app", "com.todo.tasks"],
            filePaths: [
                "/private/var/tmp/.todoswift",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: ["com.todo.tasks.agent"]
        ),
        SpywareSignature(
            // macOS variant of the Windows HZ RAT (Kaspersky, Sep 2024)
            name: "HZ RAT (macOS)",
            processNames: ["hzrat", "HZRat", "OpenVPNConnect_helper", "ovpn_helper"],
            bundleIdentifiers: ["com.hzrat.agent", "com.openvpn.helper.fake"],
            filePaths: [
                "/private/var/tmp/.hzrat",
                "~/Library/Application Support/.hzrat",
                "/private/tmp/OpenVPNConnect",
            ],
            launchAgentLabels: ["com.hzrat.agent"]
        ),
        SpywareSignature(
            // DPRK "Contagious Interview" Python backdoor with macOS variant
            name: "InvisibleFerret",
            processNames: ["invisibleferret", "InvisibleFerret", "npm_helper", "py_runtime"],
            bundleIdentifiers: ["com.invisibleferret.agent"],
            filePaths: [
                "/private/tmp/.npl",
                "~/Library/Application Support/.npm-cache-helper",
                "/private/var/tmp/.py_runtime",
            ],
            launchAgentLabels: ["com.npm.helper.agent"]
        ),
        SpywareSignature(
            // Lazarus JavaScript stage-1 with macOS payload (Unit 42, late 2024)
            name: "BeaverTail (macOS)",
            processNames: ["BeaverTail", "beavertail", "MiroTalk", "ZoomBrowser", "FCCCall", "DEXFLY"],
            bundleIdentifiers: ["com.mirotalk.agent", "com.fccall.app"],
            filePaths: [
                "/private/tmp/.beavertail",
                "~/Library/Application Support/.beavertail",
                "/private/tmp/MiroTalk",
            ],
            launchAgentLabels: ["com.mirotalk.agent", "com.dexfly.service"]
        ),
        SpywareSignature(
            // BlueNoroff macOS backdoor disguised as crypto tools (Bitdefender, Nov 2024)
            name: "HiddenRisk (BlueNoroff)",
            processNames: ["HiddenRisk", "hiddenrisk", "growthwriter", "EditorUI", "RustyAttr"],
            bundleIdentifiers: ["com.bluenoroff.editor", "com.growthwriter.app"],
            filePaths: [
                "/private/var/tmp/.hiddenrisk",
                "~/Library/Application Support/.RustyAttr",
            ],
            launchAgentLabels: ["com.growthwriter.agent"]
        ),
        SpywareSignature(
            // BlueNoroff-attributed Rust backdoor (SentinelOne, 2024)
            name: "RustyAttr",
            processNames: ["RustyAttr", "rustyattr", "attr_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.rustyattr",
                "~/Library/Application Support/.attr_helper",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // 2024 macOS dropper masquerading as a notes/todo utility (Jamf)
            name: "NotLockBit",
            processNames: ["NotLockBit", "notlockbit", "lockbit_macos"],
            bundleIdentifiers: ["com.notlockbit.app"],
            filePaths: [
                "/private/tmp/.notlockbit",
                "~/Library/Application Support/.NotLockBit",
            ],
            launchAgentLabels: ["com.notlockbit.service"]
        ),
        SpywareSignature(
            // 2024-2025 Java-loader campaign with macOS stage (BleepingComputer/Cisco Talos)
            name: "ClickFix Loader (macOS)",
            processNames: ["clickfix", "ClickFix", "captcha_helper", "verify_helper"],
            bundleIdentifiers: ["com.clickfix.installer", "com.captcha.helper"],
            filePaths: [
                "/private/tmp/.clickfix",
                "/private/var/tmp/.captcha_payload",
                "~/Library/Application Support/.clickfix",
            ],
            launchAgentLabels: ["com.captcha.helper.agent"]
        ),
        SpywareSignature(
            // Updated 3CX-style supply-chain stealer (Lazarus, 2024)
            name: "NokNok 2.0 (BlueNoroff)",
            processNames: ["noknok2", "NokNok2", "CryptoAssetCalc2", "BurgeonRMM"],
            bundleIdentifiers: ["com.burgeon.rmm"],
            filePaths: ["/private/tmp/.noknok2", "~/Library/Application Support/.BurgeonRMM"],
            launchAgentLabels: ["com.burgeon.rmm.agent"]
        ),
        SpywareSignature(
            // VSCode/Cursor extension supply-chain stealer family (2024-2025)
            name: "CursorJack / TigerJack (extension family)",
            processNames: ["cursorjack", "tigerjack", "vscode_helper_node"],
            bundleIdentifiers: ["com.cursorjack.helper"],
            filePaths: [
                "~/.cursor/extensions/.tigerjack",
                "~/.vscode/extensions/.tigerjack",
                "/private/tmp/.cursor_payload",
            ],
            launchAgentLabels: ["com.cursor.helper.agent", "com.vscode.helper.agent"]
        ),
        SpywareSignature(
            // 2025 evolution of AMOS family targeting macOS Sequoia/Tahoe (Moonlock/Kaspersky)
            name: "AMOS 2.0 / Tahoe Stealer",
            processNames: ["Tahoe", "tahoe_stealer", "AppleMusicAssist", "AppleArcadeHelper", "AMOSv2"],
            bundleIdentifiers: ["com.amos.v2", "com.applemusic.assist", "com.applearcade.helper"],
            filePaths: [
                "/private/tmp/AppleScript-tahoe-*.scpt",
                "/private/tmp/.amos2",
                "~/Library/Application Support/.tahoe",
            ],
            launchAgentLabels: ["com.applemusic.assist", "com.applearcade.helper"]
        ),
        SpywareSignature(
            // Drainer-family malware targeting browser extension wallets (2024-2025)
            name: "Inferno Drainer (macOS)",
            processNames: ["inferno", "InfernoDrainer", "wallet_inferno"],
            bundleIdentifiers: ["com.inferno.drainer"],
            filePaths: [
                "/private/tmp/.inferno",
                "~/Library/Application Support/.inferno",
            ],
            launchAgentLabels: ["com.inferno.drainer.service"]
        ),
        SpywareSignature(
            // 2024 Lazarus-linked dropper masquerading as PDF reader (Volexity)
            name: "RustBucket 2.0",
            processNames: ["RustBucket2", "InternalPDFv2", "DocPreviewer", "PDFReaderHelper"],
            bundleIdentifiers: ["com.docpreviewer.helper", "com.pdfreader.assist"],
            filePaths: [
                "/private/var/tmp/.rustbucket2",
                "~/Library/Metadata/.system_update_v2",
            ],
            launchAgentLabels: ["com.apple.systempreferences.helperv2", "com.docpreviewer.agent"]
        ),
        SpywareSignature(
            // 2025 fake-meeting RAT targeting researchers (Jamf, CISA AA25)
            name: "FakeUpdate RAT (macOS)",
            processNames: ["fakeupdate", "FakeUpdate", "SwUpdateHelper", "SoftwareUpdateAssist"],
            bundleIdentifiers: ["com.apple.swupdate.helper.fake"],
            filePaths: [
                "/private/tmp/.fakeupdate",
                "~/Library/Application Support/.SwUpdateHelper",
            ],
            launchAgentLabels: ["com.apple.swupdate.helper"]
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
        // 2024-2025 impersonation patterns seen in NimDoor / AMOS / FrigidStealer drops
        "com.apple.process.hub",
        "com.apple.account.helper",
        "com.apple.swupdate.helper.fake",
        "com.apple.swupdate.helper",
        "com.apple.systempreferences.helperv2",
        "com.apple.applemusic.assist",
        "com.apple.applearcade.helper",
        "com.apple.intelligence.helper",
        "com.apple.icloud.relay.helper",
        "com.apple.passwords.helper",
        "com.apple.notes.sync",
        "com.apple.shortcuts.runner",
        "com.apple.cloudkit.proxy",
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
        // 2024-2025 impersonation patterns: drop names mimicking macOS Sequoia/Tahoe daemons
        "appleintelligenced",    // No such Apple daemon — Apple Intelligence stack uses generativeexperiencesd / private_cloud_compute_proxyd etc.
        "AppleAccountHelper",    // Real: accountsd
        "appleaccountd",         // Real: accountsd
        "AppleMusicAssist",      // Real: musicd / MusicLibrary helpers
        "AppleArcadeHelper",     // Not a real daemon
        "iCloudKeychainHelper",  // Real: securityd / CloudKeychainProxy
        "iCloudRelayd",          // Real: privaterelayd  (no double "i")
        "iCloudSyncd",           // Not a real Apple daemon name
        "GenerativeAssistd",     // Real: generativeexperiencesd
        "SwUpdateHelper",        // Real: softwareupdated
        "SoftwareUpdateAssist",  // Not a real Apple process
        "PrivateCloudComputeHelper", // Real: private_cloud_compute_proxyd
        "BrowserUpdate",         // Common malware name, not Apple
        "ChromeUpdate",          // Common malware name (not signed by Google either)
        "SafariUpdate",          // Real Safari updates ship via softwareupdated
        "ZoomVideoSDK",          // Real Zoom installs to /Applications, not standalone agent
        "zoom_sdk_helper",       // NimDoor signature
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
