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
        // 2024-2025 stealers / APT activity
        SpywareSignature(
            name: "FrigidStealer",
            // ProofPoint TA2727: fake browser-update lure drops a DMG, runs an AppleScript loader,
            // executes a Mach-O Stealer in /private/tmp and exfils to Telegram-hosted C2.
            processNames: ["FrigidStealer", "frigidstealer", "frigid_stealer"],
            bundleIdentifiers: ["com.frigid.stealer"],
            filePaths: [
                "/private/tmp/.frigid",
                "/private/tmp/FrigidStealer",
                "~/Library/Application Support/.frigid",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "NimDoor (DPRK)",
            // BlueNoroff/Lazarus, Jul 2025. Nim-compiled Mach-O dropped via fake Zoom update.
            // Re-launches itself when the user kills it via SIGINT/SIGTERM trap handler.
            processNames: ["NimDoor", "nimdoor", "GoogIeSandboxHelper", "ZoomVideoSDK", "trojan_loader"],
            bundleIdentifiers: ["com.zoom.update.helper"],
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/LaunchAgents/com.google.update.plist",
                "~/Library/Application Support/.zoom_update",
            ],
            launchAgentLabels: ["com.google.update", "com.zoom.update.helper"]
        ),
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            // DPRK "ContagiousInterview" cluster — JS dropper hidden in fake job-interview NPM packages.
            // Loads InvisibleFerret as Python second stage; targets dev keychains and crypto wallets.
            processNames: ["BeaverTail", "beavertail", "main99_huzwh", "n2_call"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.npl",
                "/private/tmp/.n2/pay",
                "~/Library/Application Support/.beaver",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret (Contagious Interview)",
            // Python-based second-stage RAT in the same campaign — keylogger + exfil + wallet theft.
            processNames: ["InvisibleFerret", "invisibleferret", "ssh_aux", "pay_ord", "ssh_tcp"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.n2/.payload",
                "/private/tmp/.ssh_aux",
                "~/.npl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Odyssey Stealer",
            // 2024 fork of AMOS sold via Telegram. Same exfil pattern: keychain dump, browser
            // credential copy, Telegram session theft.
            processNames: ["OdysseyMacAgent", "OdysseyStealer", "odyssey_stealer"],
            bundleIdentifiers: ["com.odyssey.stealer", "com.odyssey.agent"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        SpywareSignature(
            name: "HZ RAT (macOS)",
            // Jul 2024 Kaspersky report — first macOS port of HZ RAT, targets Chinese users via
            // trojanized DingTalk/WeChat installers; long-running backdoor with shell + file exfil.
            processNames: ["HZRat", "hzrat", "OpenVPNHelper", "OpenVPNConnect-Helper"],
            bundleIdentifiers: ["com.openvpn.helper"],
            filePaths: [
                "~/Library/Application Support/.hzrat",
                "/Library/Application Support/.OpenVPN-Helper",
            ],
            launchAgentLabels: ["com.openvpn.helper"]
        ),
        SpywareSignature(
            name: "MacMa / CDDS",
            // Long-running APT toolkit (active through 2024). Variant names seen in the wild.
            processNames: ["macma", "MacMa", "UserAgent", "CDDS", "softwareupdated_helper"],
            bundleIdentifiers: ["com.apple.softwareupdate.helper"],
            filePaths: [
                "~/Library/Preferences/.com.apple.softwareupdate.plist",
                "~/Library/LaunchAgents/com.UserAgent.va.plist",
            ],
            launchAgentLabels: ["com.UserAgent.va", "com.apple.softwareupdate.helper"]
        ),
        SpywareSignature(
            name: "TodoSwift (DPRK)",
            // Aug 2024 Kandji — fake "stock-related PDF" lure delivers a Swift dropper that fetches
            // GoogleVPN-themed second stage. BlueNoroff cluster.
            processNames: ["TodoSwift", "todoswift", "GoogleVPN", "googlevpn"],
            bundleIdentifiers: ["com.google.vpn.helper"],
            filePaths: [
                "/private/tmp/.todo",
                "~/Library/Application Support/.googlevpn",
            ],
            launchAgentLabels: ["com.google.vpn.helper"]
        ),
        SpywareSignature(
            name: "RustyAttr (DPRK)",
            // Nov 2024 — DPRK Lazarus variant that hides its second-stage payload inside extended
            // attributes of a benign-looking .pdf decoy.
            processNames: ["RustyAttr", "rustyattr", "FullHouse.Doored", "fullhouse"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.rustyattr",
                "~/Library/.rustyattr",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Banshee 2.0",
            // Late-2024 update to the Banshee Stealer — adds Apple-XProtect string-decryption evasion,
            // expanded wallet/credential targeting (50+ Chromium wallet extensions).
            processNames: ["Banshee2", "BansheePro", "banshee_v2", "bnsh2"],
            bundleIdentifiers: ["com.banshee.pro", "com.banshee.v2"],
            filePaths: [
                "/private/tmp/.banshee2",
                "~/Library/Application Support/.BansheePro",
            ],
            launchAgentLabels: ["com.banshee.pro"]
        ),
        SpywareSignature(
            name: "Pearl Stealer",
            // 2024 Russian-speaking forum stealer — generic AMOS-clone, Telegram-based exfil.
            processNames: ["pearlstealer", "PearlMacAgent", "pearl_stealer"],
            bundleIdentifiers: ["com.pearl.stealer"],
            filePaths: [
                "/private/tmp/.pearl",
                "~/Library/Application Support/.Pearl",
            ],
            launchAgentLabels: ["com.pearl.agent"]
        ),
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            // 2024 — stealer dropped via Discord links and trojanized cracked apps. Mimics Apple
            // service names from non-system paths.
            processNames: ["AppleProcessHub", "appleprocesshub", "applemodulehub"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "/private/tmp/.processhub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub"]
        ),
        SpywareSignature(
            name: "ZuRu (Trojanized)",
            // Resurfaced 2024 — SEO-poisoned Trojanized macOS apps (Termius, iTerm2, Microsoft
            // Remote Desktop) include a `.ZuRu` payload that runs a Khepri C2 implant.
            processNames: [".ZuRu", "ZuRu", "GoogleHelperUpdater", "khepri"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.ZuRu",
                "/Users/Shared/.ZuRu",
                "~/Library/Application Support/.ZuRu",
            ],
            launchAgentLabels: ["com.apple.GoogleHelperUpdater"]
        ),
        SpywareSignature(
            name: "DigitStealer",
            // 2025 macOS infostealer — copies Chromium "Login Data", drains MetaMask/Phantom,
            // exfils via HTTP POST to attacker C2.
            processNames: ["DigitStealer", "digitstealer", "DigitLoader", "digit_main"],
            bundleIdentifiers: ["com.digit.stealer"],
            filePaths: [
                "/private/tmp/.digit",
                "~/Library/Application Support/.DigitStealer",
            ],
            launchAgentLabels: ["com.digit.agent"]
        ),
        SpywareSignature(
            name: "NodeStealer (macOS)",
            // 2024 macOS port of NodeStealer (Meta-credential focus). Grabs Facebook session cookies,
            // ad-account info; first cross-platform variant of the Vietnamese-origin family.
            processNames: ["NodeStealer", "nodestealer", "fb_grabber", "session_grab"],
            bundleIdentifiers: ["com.node.stealer"],
            filePaths: [
                "/private/tmp/.node_stealer",
                "~/Library/Application Support/.NodeStealer",
            ],
            launchAgentLabels: ["com.node.stealer"]
        ),
        SpywareSignature(
            name: "PrismXLite (ClickFix)",
            // 2024-2025 — fake-captcha "ClickFix" lure tells victims to paste a curl|sh command
            // into Terminal. The dropped Mach-O is a generic AMOS-style stealer.
            processNames: ["PrismXLite", "prismx", "clickfix_main", "prismx_agent"],
            bundleIdentifiers: ["com.prism.xlite"],
            filePaths: [
                "/private/tmp/.prismx",
                "/private/tmp/clickfix.sh",
                "~/Library/Application Support/.PrismXLite",
            ],
            launchAgentLabels: ["com.prism.xlite"]
        ),
        SpywareSignature(
            name: "macOS.LightSpy",
            // ThreatFabric — modular implant active through 2024, targets messaging app data,
            // browser history, and microphone capture. Macy/iOS variants share modules.
            processNames: ["LightSpy", "lightspy", "macma_helper", "ls_helper", "lspd"],
            bundleIdentifiers: ["com.lightspy.agent"],
            filePaths: [
                "/private/tmp/.lightspy",
                "~/Library/Application Support/.LightSpy",
            ],
            launchAgentLabels: ["com.lightspy.agent"]
        ),
        SpywareSignature(
            name: "Cuckoo 2 / FlipSwitch",
            // 2024-2025 — Cuckoo macOS stealer second wave delivered via fake free music-app
            // installers. Also seen as "FlipSwitch" variant.
            processNames: ["FlipSwitch", "flipswitch", "TuneFabSpotifyMusicConverter"],
            bundleIdentifiers: ["com.flipswitch.macos"],
            filePaths: [
                "/private/tmp/.flipswitch",
                "~/Library/Application Support/.FlipSwitch",
            ],
            launchAgentLabels: ["com.flipswitch.agent"]
        ),
        SpywareSignature(
            name: "BadBazaar (macOS)",
            // 2024 surveillance-ware tied to APT15/Vixen Panda. Targets Tibetan/Uyghur communities
            // — first macOS variant has audio recording + GPS/keychain exfil.
            processNames: ["BadBazaar", "badbazaar", "tibet_helper", "bb_main"],
            bundleIdentifiers: ["com.bad.bazaar"],
            filePaths: [
                "~/Library/Application Support/.BadBazaar",
                "/private/tmp/.bb",
            ],
            launchAgentLabels: ["com.bad.bazaar"]
        ),
    ]

    // MARK: - Heuristic Detection Patterns

    /// Fake Apple bundle ID patterns — real Apple IDs follow strict conventions
    public static let fakeAppleBundlePatterns: [String] = [
        "com.apple.softwareupdate.agent",
        "com.apple.softwareupdate.helper",
        "com.apple.system.update",
        "com.apple.systemd",
        "com.apple.updater",
        "com.apple.webkitproxy",
        "com.apple.appstore.agent",
        "com.apple.icloud.sync",
        "com.apple.security.agent",
        "com.apple.kernel.service",
        "com.apple.daemon.helper",
        "com.apple.processhub",
        "com.apple.GoogleHelperUpdater",
        // Common DPRK / stealer impostor labels seen 2024-2025
        "com.zoom.update.helper",
        "com.google.update",
        "com.google.vpn.helper",
        "com.openvpn.helper",
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
        // Names seen impersonating Apple binaries in 2024-2025 stealer/APT campaigns.
        "softwareupdated_helper", // Real: softwareupdated (no _helper)
        "GoogIeSandboxHelper",   // Capital "I" replaces "l" — homoglyph trick used by NimDoor
        "AppleHelper",           // Generic name used by AppleProcessHub and others
        "ZoomVideoSDK",          // Used by NimDoor as fake Zoom update payload
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
