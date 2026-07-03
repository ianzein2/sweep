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
        // 2024 — Kaspersky-disclosed backdoor targeting Chinese-speaking users via
        // trojanized OpenVPN Connect and other apps. Uses DPRK-style beacon C2.
        SpywareSignature(
            name: "HZ-RAT",
            processNames: ["OpenVPNConnect_Updater", "hzrat", "hz-rat", "sysdiag"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/.hz",
                "/private/tmp/.hzrat",
                "~/Library/Caches/com.openvpn.helper",
            ],
            launchAgentLabels: ["com.openvpn.updater", "com.apple.sysdiag"]
        ),
        // 2024 — Bitdefender-disclosed. Delivered via fake job-interview PDFs
        // to crypto/DeFi engineers. Rust-based, drops multiple stage-2 loaders.
        SpywareSignature(
            name: "RustDoor",
            processNames: ["RustDoor", "rustdoor", "zshrc_updater", "zsh_env", "VisualStudioUpdater"],
            bundleIdentifiers: ["com.microsoft.vscode.updater", "com.apple.softwareupdate.updater"],
            filePaths: [
                "/private/tmp/.test",
                "~/Library/Application Support/.rustdoor",
                "~/Public/.test",
            ],
            launchAgentLabels: ["com.apple.softwareupdate.updater", "com.microsoft.vscode.updater"]
        ),
        // 2024–2025 — North Korean "Contagious Interview" campaign. BeaverTail is
        // an npm-package-borne infostealer; InvisibleFerret is its Python second stage.
        // Almost always dropped by fake recruiters via cloned GitHub repos.
        SpywareSignature(
            name: "BeaverTail",
            processNames: ["beavertail", "BeaverTail", "npm-run-script", "p.js"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.n2/pay",
                "/private/tmp/.p2/pay",
                "~/.npm/_cacache/.tmp/beaver",
                "/private/tmp/mdworker",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "InvisibleFerret",
            processNames: ["invisibleferret", "InvisibleFerret", "pay_p.zip", "bow", "mig", "pay"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.n2",
                "/private/tmp/.p2",
                "~/Library/.LaunchAgents/.pyp",
                "~/.n2",
                "~/.p2",
            ],
            launchAgentLabels: ["com.apple.python.updater", "com.apple.helper.pyp"]
        ),
        // 2025 — Cisco Talos-disclosed. North Korean, evolves from BeaverTail.
        // Delivered as a fake video-call app ("Willo/Chameleon"). Steals keychain + browsers.
        SpywareSignature(
            name: "PylangGhost",
            processNames: ["pylangghost", "PylangGhost", "GolangGhost", "nvidia_release", "AmazonQ"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.pylg",
                "~/Library/Application Support/.pylang",
                "/private/tmp/nvidia_release",
            ],
            launchAgentLabels: []
        ),
        // 2025 — Proofpoint-disclosed. TA569/SocGholish adapted for macOS.
        // Delivered via "your browser is out of date" popups on hacked sites.
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "frigidstealer", "MacUpdateAgent", "MacBrowserUpdate"],
            bundleIdentifiers: ["com.frigid.stealer", "com.browser.updater"],
            filePaths: [
                "/private/tmp/.frigid",
                "~/Library/Application Support/.FrigidStealer",
                "~/Downloads/Update.dmg",
            ],
            launchAgentLabels: ["com.browser.update.agent"]
        ),
        // 2025 — SentinelOne/Objective-See disclosed. North Korean "Ferret" family
        // (FROSTYFERRET, MULTIPLE FERRET) — first-stage installer for later loaders.
        SpywareSignature(
            name: "FrostyFerret",
            processNames: ["FROSTYFERRET_UI", "frosty_ui", "chromeupdater", "ChromeUpdate"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.ferret",
                "~/Library/Application Support/.frosty",
                "~/Library/WebKit/com.apple.WebKit/.ferret",
            ],
            launchAgentLabels: ["com.apple.chrome.updater", "com.google.keystone.helper"]
        ),
        SpywareSignature(
            name: "FlexibleFerret",
            processNames: ["FerretUI", "flexibleferret", "ChromeUpdate", "com.apple.dbupdate"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.flex",
                "~/Library/Preferences/.flexferret",
            ],
            launchAgentLabels: ["com.apple.dbupdate"]
        ),
        // 2024 — SentinelOne-disclosed. Chinese-linked backdoor delivered via
        // trojanized Homebrew/uTorrent installers to macOS creative-industry targets.
        SpywareSignature(
            name: "OSX.MacMa (CDDS)",
            processNames: ["macma", "MacMa", "cdds", "UserAgent", "at.obdev.sys"],
            bundleIdentifiers: ["at.obdev.launchhelper", "com.apple.launchhelper"],
            filePaths: [
                "~/Library/Preferences/com.apple.softwareupdate.updater.plist",
                "/private/tmp/.macma",
                "~/Library/LaunchAgents/at.obdev.launchhelper.plist",
            ],
            launchAgentLabels: ["at.obdev.launchhelper", "com.apple.launchhelper"]
        ),
        // Pirated-app loader (Objective-See 2021, revived 2024 via cracked Xcode kits)
        SpywareSignature(
            name: "OSX.Zuru",
            processNames: ["libcrypto.2.dylib.hzuru", "GoogleUpdate.zuru", "Baidu.zuru"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.info.zuru",
                "/private/tmp/GoogleUpdate",
                "/Users/Shared/mdworker",
            ],
            launchAgentLabels: []
        ),
        // 2024 — Group-IB disclosed. Kraken/GoBear — Kimsuky-linked Go-based backdoor
        // in fake job-application PDFs targeting crypto exchanges.
        SpywareSignature(
            name: "GoBear",
            processNames: ["gobear", "GoBear", "SwiftUpdate", "gsupdate"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.gobear",
                "~/Library/Application Support/.gobear",
            ],
            launchAgentLabels: ["com.apple.swiftupdate"]
        ),
        // 2024 — Elastic-disclosed. Prompts users to run scpt/shell in Terminal via
        // fake "click-fix" browser popups. Drops Atomic-family stealer.
        SpywareSignature(
            name: "ClickFix Loader",
            processNames: ["clickfix", "captcha_verify", "verify_human", "recaptcha_verify"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/verify.sh",
                "/private/tmp/captcha_verify",
                "~/Downloads/captcha_verify",
            ],
            launchAgentLabels: []
        ),
        // 2024 — Trend Micro-disclosed. "SwipeStealer" targeting macOS crypto users.
        SpywareSignature(
            name: "SwipeStealer",
            processNames: ["SwipeStealer", "swipestealer", "swipeagent"],
            bundleIdentifiers: ["com.swipe.stealer"],
            filePaths: [
                "/private/tmp/.swipe",
                "~/Library/Application Support/.SwipeStealer",
            ],
            launchAgentLabels: ["com.swipe.agent"]
        ),
        // 2024 — Moonlock-disclosed. Delivered as trojanized Notion / Loom clones.
        SpywareSignature(
            name: "Trigona macOS",
            processNames: ["trigona", "Trigona", "notionhelper", "loomupdater"],
            bundleIdentifiers: ["com.trigona.mac"],
            filePaths: [
                "/private/tmp/.trigona",
                "~/Library/Application Support/.trigona",
            ],
            launchAgentLabels: ["com.trigona.service"]
        ),
        // 2025 — Jamf/Objective-See-disclosed. "Airdry.pkg" pkg-based loader dropping
        // Atomic/Poseidon-style stealer via fake DMG apps of pirated productivity tools.
        SpywareSignature(
            name: "OSX.Airdry",
            processNames: ["airdry", "Airdry", "Airdry.pkg", "airdryhelper"],
            bundleIdentifiers: ["com.airdry.installer"],
            filePaths: [
                "/private/tmp/.airdry",
                "/private/var/tmp/.airdry",
                "~/Library/Application Support/.Airdry",
            ],
            launchAgentLabels: ["com.airdry.helper"]
        ),
        // 2024 — SentinelOne "Realst"-adjacent variant, disguised as "MetaMask" and
        // "TradingView" DMGs pushed via search-engine malvertising.
        SpywareSignature(
            name: "Realst (2024 variant)",
            processNames: ["metamaskhelper", "TradingViewHelper", "installer_helper", "InstallerHelper"],
            bundleIdentifiers: ["com.metamask.helper.installer", "com.tradingview.helper"],
            filePaths: [
                "/private/tmp/.metam",
                "/private/tmp/.tradingview",
            ],
            launchAgentLabels: []
        ),
        // 2024 — Kandji/Jamf-disclosed. Fake ChatGPT / Claude / Perplexity DMGs
        // in Google Ads carrying Atomic Stealer payloads.
        SpywareSignature(
            name: "Fake AI App Loader",
            processNames: ["chatgpt-installer", "ClaudeInstaller", "PerplexityHelper",
                           "openai-helper", "anthropic-helper", "AI_Install"],
            bundleIdentifiers: [
                "com.openai.installer",
                "com.anthropic.installer",
                "com.perplexity.installer",
            ],
            filePaths: [
                "/private/tmp/.chatgpt",
                "/private/tmp/.claudeinstall",
                "~/Downloads/ChatGPT.dmg",
                "~/Downloads/Claude.dmg",
            ],
            launchAgentLabels: []
        ),
        // 2024 — Malwarebytes-disclosed. Trojanized crypto trading tools carrying
        // "PSW.MacOS.Amos"-style payloads via Telegram groups.
        SpywareSignature(
            name: "TelegramSpy",
            processNames: ["TelegramSpy", "TgramHelper", "tgspyer", "tspy"],
            bundleIdentifiers: ["com.telegram.spyhelper"],
            filePaths: [
                "/private/tmp/.tgspy",
                "~/Library/Application Support/.TgSpy",
            ],
            launchAgentLabels: ["com.telegram.helper"]
        ),
        // 2025 — Objective-See's Patrick Wardle disclosed. "OSX.NimDoor" — Nim-based
        // North Korean-linked backdoor targeting crypto and Web3 developers.
        SpywareSignature(
            name: "NimDoor",
            processNames: ["nimdoor", "NimDoor", "nim_agent", "installer_helper2"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/Application Support/.nimd",
            ],
            launchAgentLabels: ["com.apple.nimhelper"]
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
        // 2024-2025 impostor labels observed in real DPRK/APT and stealer campaigns
        "com.apple.softwareupdate.updater",
        "com.apple.softwareupdate.helper",
        "com.apple.chrome.updater",
        "com.apple.launchhelper",
        "com.apple.sysdiag",
        "com.apple.dbupdate",
        "com.apple.helper.pyp",
        "com.apple.python.updater",
        "com.apple.swiftupdate",
        "com.apple.nimhelper",
        "com.apple.systempreferences.helper",
        "com.apple.macshare.plist",
        // Vendor impersonation
        "com.google.keystone.helper",
        "com.microsoft.vscode.updater",
        "com.microsoft.teams.updater",
        "com.zoom.updater",
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
        // 2024-2025 additions
        "softwareupdated_helper", // Real: softwareupdated
        "softwareupdate_helper",  // Not a real Apple process
        "syslogd_helper",         // Real: syslogd
        "sysdiagnose_agent",      // Real: sysdiagnose
        "bird_agent",             // Real: bird
        "cloudd_helper",          // Real: cloudd
        "spotlightd",             // Real: mds/mdworker
        "mds_helper",             // Real: mds_stores
        "mdworker_helper",        // Real: mdworker_shared
        "gatekeeperd",            // Not a real name; real is syspolicyd
        "xprotectd",              // Not a real name; real is XProtectRemediator daemon
        "com.apple.softwareupdate", // process name should never be a reverse-DNS label
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
