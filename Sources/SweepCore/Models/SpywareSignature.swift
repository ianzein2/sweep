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
        // 2024-2025 macOS threat additions — based on public research
        // (Jamf, Kaspersky, SentinelOne, Phylum, Objective-See, Wiz, Mandiant, Volexity).
        SpywareSignature(
            name: "FrigidStealer",
            // FrigidStealer (Proofpoint, Feb 2025) — fake browser-update lure that drops a
            // signed AppleScript stealer. Operator personas: TA2726 / TA2727.
            processNames: ["FrigidStealer", "frigidstealer", "FrigidUpdate", "BrowserUpdater"],
            bundleIdentifiers: ["com.frigid.updater"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
                "~/Downloads/Update.dmg",
            ],
            launchAgentLabels: ["com.frigid.updater"]
        ),
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            // Lazarus / DPRK "Contagious Interview" campaign — JavaScript downloader bundled
            // into fake job-interview Node projects, deploys InvisibleFerret backdoor.
            processNames: ["BeaverTail", "beavertail", "n2.js", "node_modules_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/p.zi",
                "/private/tmp/p2.zip",
                "/private/tmp/.npl",
                "~/Library/Application Support/.n2",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            // Stage-2 of Contagious Interview: Python backdoor that exfiltrates browser data,
            // crypto wallets, and keychain.
            processNames: ["pyp", "InvisibleFerret", "ifferret", "pay.py"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.pyp",
                "~/Library/Application Support/.npl",
                "~/.npl",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "FlexibleFerret",
            // 2025 follow-on to BeaverTail (SentinelOne) — uses signed Apple Developer ID,
            // distributed via fake Chrome / VCam installers.
            processNames: ["FlexibleFerret", "flexibleferret", "FerretService", "ChromeUpdate"],
            bundleIdentifiers: ["com.flexible.ferret"],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/Application Support/.FlexibleFerret",
            ],
            launchAgentLabels: ["com.flexible.ferret"]
        ),
        SpywareSignature(
            name: "RustyAttr",
            // BlueNoroff / DPRK technique (Group-IB, Nov 2024) — stores Rust payload inside
            // extended attributes of an innocuous file; small launcher reads xattr and execs.
            processNames: ["RustyAttr", "rustyattr", "ChatGpt-Plus", "Apple-Updater"],
            bundleIdentifiers: ["com.rustyattr.app", "com.apple.updater.helper"],
            filePaths: [
                "/private/tmp/.rusty",
                "~/Library/Application Support/.RustyAttr",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "HZ RAT (macOS)",
            // Kaspersky disclosure (June 2024) — first macOS variant of the Windows HZ RAT.
            // Targets WeChat / DingTalk users. Persists via LaunchAgent.
            processNames: ["OpenVPNConnect", "OpenVPN_Connect", "hzrat", "hz_helper"],
            bundleIdentifiers: ["com.openvpn.client.helper"],
            filePaths: [
                "~/Library/Application Support/.hzrat",
                "/private/tmp/.hz",
            ],
            launchAgentLabels: ["com.openvpn.client.helper.plist"]
        ),
        SpywareSignature(
            name: "NotLockBit",
            // Trend Micro / SentinelOne — first macOS-targeted ransomware-style locker (Sept 2024)
            // that enumerates iCloud / Apple Account artifacts before encrypting.
            processNames: ["NotLockBit", "notlockbit", "darwin_x86_64", "notlockbit_arm64"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.notlockbit",
                "/private/var/folders/.notlockbit",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "JokerSpy",
            // Bitdefender / Elastic (mid-2023, expanded coverage 2024) — Python-based macOS
            // spyware. Signature binary is `xcc`; persists as a fake systemupdater plist.
            processNames: ["xcc", "shared.dat", "sh.py", "shared.py"],
            bundleIdentifiers: ["com.apple.systemupdater"],
            filePaths: [
                "/Users/Shared/.local/xcc",
                "/Users/Shared/AppleAccount.tmp",
                "~/Library/Application Support/com.apple.systemupdater",
            ],
            launchAgentLabels: ["com.apple.systemupdater.plist"]
        ),
        SpywareSignature(
            name: "TodoSwift (DPRK)",
            // Kandji (Aug 2024) — DPRK-linked dropper masquerading as a SwiftUI todo app,
            // pulls second-stage from attacker C2 in PDF form.
            processNames: ["TodoTasks", "todoswift", "TodoSwift", "TodoTasksHelper"],
            bundleIdentifiers: ["com.toptalshq.todotasks", "com.swiftui.todotasks"],
            filePaths: [
                "/private/tmp/.todotasks",
                "~/Library/Application Support/.TodoSwift",
            ],
            launchAgentLabels: ["com.swiftui.todotasks"]
        ),
        SpywareSignature(
            name: "ZuRu (HiddenRisk)",
            // 2024 resurgence of the OSX.ZuRu trojan (SentinelOne, Nov 2024). Distributed via
            // poisoned Termius / iTerm2 / Microsoft RDP packages from sponsored search ads.
            processNames: ["G-Helper", "g_helper", "zuru", "Termius_Helper"],
            bundleIdentifiers: ["com.termius.helper", "com.microsoft.rdc.helper"],
            filePaths: [
                "/Users/Shared/.fseventsd",
                "/Users/Shared/.Trash/.Helper",
                "~/Library/Application Support/.zuru",
            ],
            launchAgentLabels: ["com.zuru.helper"]
        ),
        SpywareSignature(
            name: "macOS.NokNok / RustBucket variant",
            // Continued BlueNoroff campaigns hitting crypto / VC sectors (Jamf, 2024).
            processNames: ["zoom_sdk_support", "zoom_us_helper", "noknok2", "RustBucket2"],
            bundleIdentifiers: ["us.zoom.SDKSupport.helper"],
            filePaths: [
                "/private/tmp/.zoom_helper",
                "~/Library/Application Support/.noknok2",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "macOS.AppleProcessHub",
            // 2024 backdoor disguised as Apple system component (Bitdefender Sep 2024).
            processNames: ["AppleProcessHub", "appleprocesshub", "ProcessHub"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "/private/tmp/.aphub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub.plist"]
        ),
        SpywareSignature(
            name: "Boltzmann / FrostyFerret",
            // 2025 stealer family (Phylum, Volexity) — drops fake "Apple ID" password prompt
            // via osascript, exfiltrates keychain & browser data.
            processNames: ["Boltzmann", "frostyferret", "FrostyFerret", "AppleID_Helper"],
            bundleIdentifiers: ["com.appleid.helper"],
            filePaths: [
                "/private/tmp/.boltzmann",
                "~/Library/Application Support/.FrostyFerret",
            ],
            launchAgentLabels: ["com.appleid.helper"]
        ),
        SpywareSignature(
            name: "Tiger Stealer (Lumma-mac)",
            // 2024 cross-platform port of the Lumma stealer / TigerCMS campaign, distributed
            // via cracked-software DMGs.
            processNames: ["TigerStealer", "tigerstealer", "tigerd", "Lumma"],
            bundleIdentifiers: ["com.tiger.stealer"],
            filePaths: [
                "/private/tmp/.tiger",
                "~/Library/Application Support/.Tiger",
            ],
            launchAgentLabels: ["com.tiger.stealer"]
        ),
        SpywareSignature(
            name: "Cuttlefish (macOS port)",
            // 2024 Lumen Black Lotus router-malware whose later samples included macOS staging
            // helpers for credential capture.
            processNames: ["cuttlefish", "Cuttlefish", "ctlfsh"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.cuttlefish"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "ShadowVault",
            // Guardz disclosure (June 2024) — MaaS macOS infostealer using a faked
            // "System Preferences" pw prompt to steal the login keychain.
            processNames: ["ShadowVault", "shadowvault", "PrefsAgent"],
            bundleIdentifiers: ["com.shadowvault.agent"],
            filePaths: [
                "/private/tmp/.shadowvault",
                "~/Library/Application Support/.ShadowVault",
            ],
            launchAgentLabels: ["com.shadowvault.agent"]
        ),
        SpywareSignature(
            name: "Crypt00r",
            // 2024 DPRK-adjacent malware that bundles a Python keychain dumper with
            // Cobalt-Strike beaconing.
            processNames: ["Crypt00r", "crypt00r", "cryptor_mac"],
            bundleIdentifiers: [],
            filePaths: ["/private/tmp/.crypt00r"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "Realst.B (2024 variant)",
            // Continued Realst infostealer activity (SentinelOne, Phylum) targeting Web3
            // game-development hires.
            processNames: ["Realst-B", "realst2", "GameInstaller", "PartyGameInstaller"],
            bundleIdentifiers: ["com.realst.installer", "com.partygame.installer"],
            filePaths: [
                "/private/tmp/.realst2",
                "~/Library/Application Support/.RealstB",
            ],
            launchAgentLabels: ["com.realst.installer"]
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
        // 2024-2025 impersonation patterns observed in the wild
        "com.apple.systemupdater",        // JokerSpy
        "com.apple.processhub",           // AppleProcessHub
        "com.apple.updater.helper",       // RustyAttr / BlueNoroff
        "com.apple.appleid.helper",       // Boltzmann / FrostyFerret
        "com.apple.sysmond",              // not a real Apple service
        "com.apple.coreservicesd",        // mis-suffixed
        "com.apple.softwareupdated.helper",
        "com.apple.aoshelper",            // observed in 2024 stealer campaigns
        "com.apple.timed.helper",
        "com.apple.cloud.sync.helper",
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
        // 2024-2025 stealer / RAT impersonation names
        "Apple-Updater",         // RustyAttr
        "AppleID_Helper",        // Boltzmann / FrostyFerret
        "ChatGpt-Plus",          // RustyAttr lure
        "BrowserUpdater",        // FrigidStealer / SocGholish-style fakes
        "ChromeUpdate",          // FlexibleFerret
        "PrefsAgent",            // ShadowVault
        "GameInstaller",         // Realst.B
        "Termius_Helper",        // ZuRu (HiddenRisk)
        "G-Helper",              // ZuRu (HiddenRisk)
        "zoom_sdk_support",      // BlueNoroff RustBucket variant
        "OpenVPN_Connect",       // HZ RAT (macOS) lure
        "AnyDeskHelper",         // 2024 fake support-tool stealers
        "CleanMyMac_Pro",        // Cthulhu / cracked-software bundles
        "Cracked-Helper",        // generic crack-bundle stealers
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
