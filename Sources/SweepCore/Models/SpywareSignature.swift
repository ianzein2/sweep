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
        // 2025-2026: DPRK / Lazarus / Contagious Interview campaigns
        SpywareSignature(
            // Nim-based DPRK Web3 backdoor; CoreKitAgent revives the LaunchAgent on
            // SIGINT/SIGTERM. The "GoogIe LLC" directory uses a Latin capital I to
            // visually mimic Google.
            // https://www.sentinelone.com/labs/macos-nimdoor-dprk-threat-actors-target-web3-and-crypto-platforms-with-nim-based-malware/
            name: "NimDoor (DPRK)",
            processNames: ["CoreKitAgent", "GoogIe LLC"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/CoreKit",
                "~/Library/Application Support/GoogIe LLC",
                "/private/tmp/.config",
                "/private/tmp/cfg",
            ],
            launchAgentLabels: ["com.google.update"]
        ),
        SpywareSignature(
            // BlueNoroff "Hidden Risk" — first observed in-the-wild ~/.zshenv abuse
            // for non-interactive shell persistence that bypasses the Ventura+
            // Background Items notification.
            // https://www.sentinelone.com/labs/bluenoroff-hidden-risk-threat-actor-targets-macs-with-fake-crypto-news-and-novel-persistence/
            name: "BlueNoroff Hidden Risk (DPRK)",
            processNames: ["growth"],
            bundleIdentifiers: [],
            filePaths: ["/Users/Shared/growth"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // DPRK Contagious Interview backdoor masquerading as logd at a path the
            // real Apple logd binary never uses.
            // https://www.sentinelone.com/blog/macos-flexibleferret-further-variants-of-dprk-malware-family-unearthed/
            name: "FlexibleFerret / FriendlyFerret (DPRK)",
            processNames: ["com.apple.secd", "ChromeUpdate", "CameraAccess",
                           "drivfixer", "InstallerAlert"],
            bundleIdentifiers: ["Mac-Installer.InstallerAlert"],
            filePaths: [
                "/private/var/tmp/logd",
                "/var/tmp/macpatch.sh",
                "/var/tmp/CDrivers.zip",
                "/var/tmp/drivfixer.sh",
            ],
            launchAgentLabels: ["com.apple.secd"]
        ),
        SpywareSignature(
            // 2025 Contagious Interview JS stealer + Nuitka/PyInstaller delivery.
            // https://thehackernews.com/2025/09/dprk-hackers-use-clickfix-to-deliver.html
            name: "BeaverTail (DPRK)",
            processNames: ["WifiPreference"],
            bundleIdentifiers: [],
            filePaths: ["~/Library/Application Support/WifiPreference"],
            launchAgentLabels: [
                "com.avatar.update.wake",
                "com.wifianalyticsagent",
            ]
        ),
        SpywareSignature(
            // Famous Chollima / OtterCookie; npm + Vercel delivery.
            // https://thehackernews.com/2025/11/north-korean-hackers-deploy-197-npm.html
            name: "OtterCookie (DPRK)",
            processNames: ["ottercookie"],
            bundleIdentifiers: [],
            filePaths: [],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Lazarus Tauri/Rust trojan smuggling JS in extended attributes.
            // https://www.group-ib.com/blog/rustyattr-trojan/
            name: "RustyAttr (Lazarus)",
            processNames: ["rustyattr"],
            bundleIdentifiers: [],
            filePaths: [],
            launchAgentLabels: []
        ),
        // 2025-2026: New macOS infostealer families
        SpywareSignature(
            // Jamf-tracked stealer posing as DynamicLake utility; trojanizes Ledger Live's
            // app.asar. The hidden double-dot file ~/..txt is the persistent credential store.
            // https://www.jamf.com/blog/jtl-digitstealer-macos-infostealer-analysis/
            name: "DigitStealer",
            processNames: ["DynamicLake"],
            bundleIdentifiers: [],
            filePaths: [
                "~/..txt",
                "/Volumes/DynamicLake",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // MaaS evolution of Mac.c; swaps Ledger Live / Trezor Suite binaries.
            // https://www.jamf.com/blog/macsync-stealer-evolution-code-signed-swift-malware-analysis/
            name: "MacSync Stealer",
            processNames: ["UserSyncWorker", "devupdatesuite-helper"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/UserSyncWorker",
                "~/Library/Logs/UserSyncWorker.log",
                "/tmp/runner",
                "/tmp/osalogging.zip",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // SHub Reaper (SentinelOne, May 2026). Creates a fake Google Software Update
            // tree and registers a Keystone-mimicking LaunchAgent.
            // https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/
            name: "SHub Reaper",
            processNames: ["GoogleUpdate"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/Google/GoogleUpdate.app",
            ],
            launchAgentLabels: ["com.google.keystone.agent"]
        ),
        SpywareSignature(
            // Poseidon rebrand (Jamf). Random LaunchDaemon labels with hidden bot ID files.
            // https://www.jamf.com/blog/signed-and-stealing-uncovering-new-insights-on-odyssey-infostealer/
            name: "Odyssey Stealer (Poseidon)",
            processNames: ["odyssey"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.botid",
                "~/.pwd",
                "~/Library/Application Support/UserSyncWorker/last_up",
                "~/Library/Application Support/UserSyncWorker/gate",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Trend Micro / Microsoft MDR analysis (Sept 2025) — AMOS added a durable
            // root LaunchDaemon "com.finder.helper" with .helper/.agent in user home.
            // https://www.trendmicro.com/en_us/research/25/i/an-mdr-analysis-of-the-amos-stealer-campaign.html
            name: "AMOS 2025 (com.finder.helper)",
            processNames: [".helper", ".agent"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.helper",
                "~/.agent",
                "/tmp/starter",
                "/tmp/update",
            ],
            launchAgentLabels: ["com.finder.helper"]
        ),
        SpywareSignature(
            // Jamf ChillyHell — notarized modular backdoor masquerading as Apple's
            // qtop with three persistence fallbacks (LaunchAgent, LaunchDaemon, shell-RC).
            // https://www.jamf.com/blog/chillyhell-a-modular-macos-backdoor/
            name: "ChillyHell",
            processNames: ["qtop"],
            bundleIdentifiers: ["com.apple.qtop"],
            filePaths: [
                "~/Library/com.apple.qtop",
                "/usr/local/bin/qtop",
            ],
            launchAgentLabels: ["com.apple.qtop"]
        ),
        SpywareSignature(
            // ClickFix Script Editor variant (Jamf, Apr 2026); the .mainhelper file
            // and the stat /dev/console + sudo -u pattern in a LaunchAgent are the IOCs.
            // https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/
            name: "ClickFix Script Editor variant",
            processNames: ["mainhelper"],
            bundleIdentifiers: [],
            filePaths: ["~/.mainhelper"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Proofpoint TA2727 — Wails (Go) infostealer pushed via fake Safari/Chrome
            // browser updates; abuses AppleScript admin prompt.
            // https://www.proofpoint.com/us/blog/threat-insight/update-fake-updates-two-new-actors-and-new-mac-malware
            name: "FrigidStealer",
            processNames: ["ddaolimaki-daunito", "Safari Updater"],
            bundleIdentifiers: ["com.wails.ddaolimaki-daunito"],
            filePaths: [
                "/Volumes/Safari Updater/Safari Updater.app",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // SentinelOne — multi-runtime macOS loader; uses stable home paths.
            // https://www.sentinelone.com/blog/readerupdate-reforged-melting-pot-of-macos-malware-adds-go-to-crystal-nim-and-rust-variants/
            name: "ReaderUpdate",
            processNames: ["readerupdate"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/printers/printers",
                "~/Library/Application Support/etc/etc",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Malwarebytes — first documented Nuitka-compiled Python stealer on macOS.
            // https://www.malwarebytes.com/blog/threat-intel/2026/03/infiniti-stealer-a-new-macos-infostealer-using-clickfix-and-python-nuitka
            name: "Infiniti Stealer (NukeChain)",
            processNames: ["UpdateHelper.bin", "UpdateHelper"],
            bundleIdentifiers: [],
            filePaths: ["/tmp/UpdateHelper.bin"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Stage-1 dropper masquerades as a system dylib; AES-128-ECB obfuscated C2.
            // https://cybersecuritynews.com/researchers-dissected-macos-appleprocesshub-stealer/
            name: "AppleProcessHub Stealer",
            processNames: ["libsystd", "libsystd.dylib"],
            bundleIdentifiers: [],
            filePaths: ["/tmp/libsystd.dylib"],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Chinese-aligned multi-component spyware (Apr 2025). Masquerades as Apple's
            // geod via a daemon named "goed" plus per-app dylib stealers.
            // https://gbhackers.com/pasivrobber-malware-emerges-targeting-macos-to-steal-data/
            name: "PasivRobber",
            processNames: ["goed", "wsus", "center",
                           "libWXRobber", "libNTQQRobber", "libQQRobber"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/Application Support/.PasivRobber",
            ],
            launchAgentLabels: ["com.apple.geod.helper"]
        ),
        SpywareSignature(
            // FUD macOS backdoor with DYLD injection and ad-hoc resigning.
            // https://cybersecuritynews.com/new-tiny-fud-attacking-macos-users/
            name: "Tiny FUD",
            processNames: ["com.apple.Safari.helper", "com.apple.Webkit.Networking"],
            bundleIdentifiers: [],
            filePaths: [],
            launchAgentLabels: []
        ),
        SpywareSignature(
            // Nova / MioLab — replaces /Applications/Ledger Live.app and Trezor Suite.app
            // with unsigned Swift+WebKit clones to steal seed phrases.
            // https://cybersecuritynews.com/new-nova-stealer-attacking-macos-users/
            name: "Nova Stealer (MioLab)",
            processNames: ["mdrivers"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.mdrivers",
                "~/Library/LaunchAgents/LedgerLive.zip",
                "~/Library/LaunchAgents/TrezorSuite.zip",
            ],
            launchAgentLabels: ["application.com.artificialintelligence"]
        ),
        SpywareSignature(
            // Hunt.io Cuckoo Stealer ClickFix variant — Homebrew look-alike LaunchAgent.
            // https://hunt.io/blog/fake-homebrew-clickfix-cuckoo-stealer-macos
            name: "Cuckoo Stealer (ClickFix variant)",
            processNames: ["brewupdater", "upd"],
            bundleIdentifiers: [],
            filePaths: [],
            launchAgentLabels: [
                "com.homebrew.brewupdater",
                "com.user.loginscript",
                "com.dumpmedia.spotifymusicconverter",
                "com.immyac.videoconverter",
            ]
        ),
        SpywareSignature(
            // Shai-Hulud npm worm — Bun-runtime payload, GitHub Actions runner persistence,
            // destructive HOME wipe on exfil failure.
            // https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
            name: "Shai-Hulud npm worm",
            processNames: ["bun_environment"],
            bundleIdentifiers: [],
            filePaths: [
                "/tmp/bun_environment.js",
                "/tmp/setup_bun.js",
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
        // 2025-2026 IOCs
        "com.apple.qtop",                // ChillyHell modular backdoor
        "com.apple.secd",                // FlexibleFerret / FriendlyFerret
        "com.apple.geod.helper",         // PasivRobber masquerading as geod
        "com.apple.Webkit.Networking",   // Tiny FUD spoofed name (real binary is signed)
        "com.apple.Safari.helper",       // Tiny FUD spoofed name
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
        // 2025-2026: process names abused by DPRK / new infostealer families
        "com.apple.secd",        // FlexibleFerret / FriendlyFerret backdoor
        "com.apple.qtop",        // ChillyHell modular backdoor
        "GoogIe LLC",            // NimDoor (Latin capital I impersonating Google)
        "CoreKitAgent",          // NimDoor revival agent
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
