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
        // 2024-2025 macOS threats — new campaigns and families reported by
        // XProtect, Sentinel, Kandji, JAMF, Objective-See, and Group-IB.
        SpywareSignature(
            // RustDoor / GateDoor — Rust-based backdoor first seen Feb 2024.
            // Distributed as fake Visual Studio updates, tied to ransomware affiliates.
            name: "RustDoor",
            processNames: ["rustdoor", "RustDoor", "GateDoor", "Visual Studio Updater", "vscodeupd"],
            bundleIdentifiers: ["com.visualstudio.updater", "com.rustdoor.agent"],
            filePaths: [
                "~/Library/Application Support/.rustdoor",
                "/private/tmp/.rustdoor",
                "~/Library/.rustdoor",
            ],
            launchAgentLabels: ["com.visualstudio.updater", "com.apple.vs.updater"]
        ),
        SpywareSignature(
            // HZ RAT for macOS — Kaspersky, Sept 2024. Backdoor targeting WeChat/DingTalk users.
            name: "HZ RAT",
            processNames: ["hzrat", "HZRat", "OpenVPNConnect_helper", "wechat_helper"],
            bundleIdentifiers: ["com.tencent.wechat.helper"],
            filePaths: [
                "/private/tmp/.hz",
                "~/Library/Application Support/.hzrat",
            ],
            launchAgentLabels: ["com.openvpn.client.helper", "com.tencent.wechathelper"]
        ),
        SpywareSignature(
            // LightSpy for macOS — ThreatFabric / Huntress, May 2024.
            // Modular surveillanceware with plugin-based capabilities.
            name: "LightSpy",
            processNames: ["lightspy", "LightSpy", "macircloader", "macmaild"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.lightspy",
                "~/Library/Application Support/.macmail",
                "~/Library/Caches/.macircloader",
            ],
            launchAgentLabels: ["com.apple.macmail.helper", "com.apple.softwareupdate.helper"]
        ),
        SpywareSignature(
            // BeaverTail — DPRK "Contagious Interview" campaign, Palo Alto Unit42, 2024.
            // NPM-package-borne JavaScript stealer that targets crypto wallets and keychains.
            name: "BeaverTail",
            processNames: ["beavertail", "BeaverTail", "npm_helper", "n2v", "p2v"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.n2",
                "/private/tmp/.p2",
                "~/Library/Application Support/.beavertail",
            ],
            launchAgentLabels: ["com.apple.npm.helper"]
        ),
        SpywareSignature(
            // InvisibleFerret — Python second-stage backdoor deployed by BeaverTail.
            // Same campaign, follow-on stage.
            name: "InvisibleFerret",
            processNames: ["invisibleferret", "InvisibleFerret", "pay", "pyp", "brow"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.pyp",
                "~/.brow",
                "/private/tmp/.pay",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // FlexibleFerret / FRIENDLYFERRET — SentinelLabs, Feb 2025. New macOS variants
            // of the Contagious Interview family; installer disguised as browser helpers.
            name: "FlexibleFerret",
            processNames: [
                "FlexibleFerret", "FriendlyFerret", "FrostyFerret",
                "com.zoom.us.helper", "ChromeUpdate", "zoomhelper",
            ],
            bundleIdentifiers: [
                "com.zoom.us.helper", "com.google.chrome.updater",
            ],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/Application Support/.ferret",
            ],
            launchAgentLabels: ["com.zoom.us.helper", "com.google.chrome.updater"]
        ),
        SpywareSignature(
            // TodoSwift — Kandji, August 2024. DPRK-linked, targets crypto industry with
            // fake PDF viewers that download a second-stage payload.
            name: "TodoSwift",
            processNames: ["TodoSwift", "todoswift", "SwiftUpdater", "PDFReader_helper"],
            bundleIdentifiers: ["com.todoswift.app", "com.pdfreader.helper"],
            filePaths: [
                "/private/tmp/.todoswift",
                "~/Library/Application Support/.PDFReader",
            ],
            launchAgentLabels: ["com.todoswift.helper"]
        ),
        SpywareSignature(
            // HiddenRisk — Sentinel/Kandji, Nov 2024. DPRK crypto stealer bundled inside
            // fake macOS-native "crypto news" PDF applications.
            name: "HiddenRisk",
            processNames: ["hiddenrisk", "HiddenRisk", "crypto_market_news"],
            bundleIdentifiers: ["com.crypto.marketnews", "com.hiddenrisk.helper"],
            filePaths: [
                "/private/tmp/.hiddenrisk",
                "~/Library/Group Containers/.hiddenrisk",
            ],
            launchAgentLabels: ["com.google.finder.helper", "com.apple.finder.updater"]
        ),
        SpywareSignature(
            // FrigidStealer — Proofpoint, Feb 2025. Fake-browser-update stealer targeting
            // browser cookies, autofill, and cryptocurrency wallets. AMOS/Poseidon-adjacent.
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "safariupdate", "SafariUpdate"],
            bundleIdentifiers: ["com.frigid.stealer", "com.apple.safari.update"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.frigid",
            ],
            launchAgentLabels: ["com.apple.safari.update"]
        ),
        SpywareSignature(
            // AppleProcessHub / MacStealerV2 — 2025 stealer distributed via GitHub-clone
            // pages posing as legitimate open-source software installers.
            name: "AppleProcessHub Stealer",
            processNames: ["AppleProcessHub", "appleprocesshub", "aph_stealer", "aphd"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "/private/tmp/.aph",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub.agent"]
        ),
        SpywareSignature(
            // NimDoor — DPRK, June 2025. Nim-language backdoor targeting web3/crypto firms;
            // steals keychains and browser data via chained Bash/AppleScript stagers.
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "nim_stager", "TrainingScheduler"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.nim",
                "~/Library/Application Support/.nimdoor",
            ],
            launchAgentLabels: ["com.apple.trainingd", "com.apple.trainingScheduler"]
        ),
        SpywareSignature(
            // XLoader for macOS — 2023 port of the Windows infostealer, seen active in 2024.
            // Distributed as a fake "OfficeNote" application.
            name: "XLoader (macOS)",
            processNames: ["XLoader", "xloader", "OfficeNote", "officenote"],
            bundleIdentifiers: ["com.officenote.app"],
            filePaths: [
                "/private/tmp/.xloader",
                "~/Library/Application Support/OfficeNote",
            ],
            launchAgentLabels: ["com.officenote.helper"]
        ),
        SpywareSignature(
            // Vidar for macOS — port of the Windows Vidar Stealer, active 2024.
            name: "Vidar Stealer (macOS)",
            processNames: ["vidar", "Vidar", "vstealer_mac"],
            bundleIdentifiers: ["com.vidar.stealer"],
            filePaths: [
                "/private/tmp/.vidar",
                "~/Library/Application Support/.Vidar",
            ],
            launchAgentLabels: ["com.vidar.agent"]
        ),
        SpywareSignature(
            // KeySteal — added to Apple XProtect signatures in 2023; keychain stealer distributed
            // via cracked-software downloads.
            name: "KeySteal",
            processNames: ["KeySteal", "keysteal", "ReSignTool", "ReSigner", "unpkg"],
            bundleIdentifiers: ["com.apple.ReSigner"],
            filePaths: [
                "/private/tmp/.keysteal",
                "~/Library/Application Support/.ReSigner",
            ],
            launchAgentLabels: ["com.apple.ReSigner.agent"]
        ),
        SpywareSignature(
            // JokerSpy — Bitdefender, 2023-2024. Python-based backdoor with an interactive
            // "sh.py" shell, distributed via fake Docker/Kubernetes plugins.
            name: "JokerSpy",
            processNames: ["JokerSpy", "jokerspy", "shared-networking", "sh.py", "xcc"],
            bundleIdentifiers: [],
            filePaths: [
                "/Users/Shared/.local/xcc",
                "/private/tmp/.jokerspy",
            ],
            launchAgentLabels: ["com.apple.shared.networking"]
        ),
        SpywareSignature(
            // Geacon (Cobalt Strike port for macOS) — active 2023-2025, seen in intrusions
            // impersonating SecureLink, AnyDesk, and other IT-support tooling.
            name: "Geacon",
            processNames: ["geacon", "Geacon", "SecureLink", "geacon_plus", "geacon_pro"],
            bundleIdentifiers: ["com.securelink.agent"],
            filePaths: [
                "/private/tmp/.geacon",
                "~/Library/Application Support/.geacon",
            ],
            launchAgentLabels: ["com.securelink.agent"]
        ),
        SpywareSignature(
            // Silver Sparrow — persistent adware/loader family; still surfacing on new Macs
            // even after XProtect signature updates.
            name: "Silver Sparrow",
            processNames: ["agent.sh", "verx.sh", "sparrow_agent"],
            bundleIdentifiers: ["com.pcv.updater"],
            filePaths: [
                "~/Library/Application Support/verx_updater",
                "~/Library/Application Support/agent_updater",
            ],
            launchAgentLabels: ["com.pcv.updater", "init_verx"]
        ),
        SpywareSignature(
            // XProtect payloads (Apple's XProtect blocks — MRT / XProtect Yara names,
            // 2024-2025 additions): OSAX.Trojan.SwipeLifter, Adload variants, ZuRu.
            name: "Adload",
            processNames: [
                "Adload", "adload", "SearchPartyUserAgent",
                "PDFOnline", "PDFCombo", "PDFhelper", "sysd", "MacTonic",
            ],
            bundleIdentifiers: [
                "com.pdfonline.agent", "com.mactonic.agent",
            ],
            filePaths: [
                "~/Library/Application Support/.Adload",
                "/Library/Application Support/.Adload",
                "~/Library/LaunchAgents/com.pdf.online.plist",
            ],
            launchAgentLabels: ["com.pdfonline.agent", "com.mactonic.agent"]
        ),
        SpywareSignature(
            // ZuRu (OSX.ZuRu) — trojanized versions of macOS utilities (iTerm2, Terminal,
            // MicrosoftWord, MSN Money) delivering a Sliver C2 beacon. New waves in 2024-2025.
            name: "OSX.ZuRu",
            processNames: ["ZuRu", "zuru", "libcrypto.2.dylib.bak", "GoogleUpdate"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.zuru",
                "/tmp/.test",
                "/Users/Shared/.pd",
            ],
            launchAgentLabels: ["com.google.keystone.system.agent"]
        ),
        SpywareSignature(
            // ClickFix / OyeMac — Nov 2024 social-engineering delivery: users are convinced
            // to paste a curl-piped shell into Terminal that fetches a macOS Odyssey stealer.
            name: "ClickFix (OyeMac)",
            processNames: ["OyeMac", "oyemac", "clickfix", "Terminal_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.oyemac",
                "~/Library/Application Support/.oyemac",
            ],
            launchAgentLabels: ["com.terminal.helper"]
        ),
        SpywareSignature(
            // MacSpy — commercial malware-as-a-service resurgent in 2024 dark-web listings.
            name: "MacSpy",
            processNames: ["macspy", "MacSpy", "macspyd"],
            bundleIdentifiers: ["com.macspy.agent"],
            filePaths: [
                "~/Library/Application Support/.MacSpy",
                "/private/tmp/.macspy",
            ],
            launchAgentLabels: ["com.macspy.agent"]
        ),
        SpywareSignature(
            // SwiftBelt / Osascape misuse — offensive-security tooling that has been observed
            // being deployed by threat actors on victim Macs for reconnaissance and lateral movement.
            name: "SwiftBelt (adversary use)",
            processNames: ["swiftbelt", "SwiftBelt", "osascape"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/swiftbelt",
                "/Users/Shared/swiftbelt",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Cthulhu variant "Ballast" / DPRK BlueNoroff crypto-drainer — active late 2024.
            name: "ObjCShellz variant / BALLAST",
            processNames: ["BallastAgent", "ballast", "objchelper2"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/.ballast",
                "/private/tmp/.ballast",
            ],
            launchAgentLabels: ["com.apple.finder.helper"]
        ),
        SpywareSignature(
            // NKAbuse — Kaspersky, 2024. Go-based cross-platform RAT that uses NKN
            // (New Kind of Network) blockchain protocol for stealthy C2. Confirmed macOS builds.
            name: "NKAbuse",
            processNames: ["nkabuse", "NKAbuse", "app_linux_arm64", "app_darwin"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.nkabuse",
                "~/.config/StoreService/nknmd",
            ],
            launchAgentLabels: ["com.Ubuntu.StoreService"]
        ),
        SpywareSignature(
            // MacSync / Odyssey Stealer — new AMOS-family stealer distributed via cracked apps
            // and "ClickFix"-style social engineering, active 2024-2025.
            name: "Odyssey Stealer",
            processNames: ["odyssey", "Odyssey", "OdysseyStealer", "AppleCleanUpTool"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.odyssey",
            ],
            launchAgentLabels: ["com.odyssey.agent", "com.applecleanup.agent"]
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
        // 2024-2025 impersonation labels observed in HiddenRisk, FlexibleFerret,
        // Ferret, RustDoor and Adload distribution chains.
        "com.apple.macmail.helper",
        "com.apple.softwareupdate.helper",
        "com.apple.trainingd",
        "com.apple.trainingScheduler",
        "com.apple.finder.updater",
        "com.apple.finder.helper",
        "com.apple.safari.update",
        "com.apple.processhub.agent",
        "com.apple.npm.helper",
        "com.apple.vs.updater",
        "com.apple.shared.networking",
        "com.apple.terminal.helper",
        "com.apple.ReSigner.agent",
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
