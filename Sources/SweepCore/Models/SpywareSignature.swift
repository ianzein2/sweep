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
        // 2025 macOS infostealers — newer AMOS forks and crack-bundle delivery
        // Odyssey Stealer — Poseidon rebrand by operator Rodrigo/Rodrigo4
        // (PRODAFT IOC repo, Jamf Threat Labs 2025-2026)
        SpywareSignature(
            name: "Odyssey Stealer (Poseidon rebrand)",
            processNames: ["Odyssey", "odyssey", "OdysseyInstaller", ".init"],
            bundleIdentifiers: ["com.odyssey.stealer"],
            filePaths: [
                "/private/tmp/.odyssey",
                "~/Library/Application Support/.Odyssey",
            ],
            launchAgentLabels: ["com.odyssey.agent"]
        ),
        SpywareSignature(
            name: "FrigidStealer",
            processNames: ["FrigidStealer", "Frigid", "frigid", "Safari Updater", "ddaolimaki-daunito"],
            bundleIdentifiers: ["com.wails.ddaolimaki-daunito", "com.frigid.stealer"],
            filePaths: [
                "/Volumes/Safari Updater/Safari Updater.app",
                "/private/tmp/.frigid",
                "~/Library/Application Support/.Frigid",
            ],
            launchAgentLabels: ["com.frigid.agent"]
        ),
        // SHAMOS / COOKIE SPIDER — AMOS variant delivered via fake Mac help / ClickFix lures
        // (CrowdStrike Falcon, Microsoft Security, BleepingComputer, 2025-2026)
        SpywareSignature(
            name: "SHAMOS (COOKIE SPIDER / AMOS variant)",
            processNames: [".mainhelper", ".agent", "mainhelper", "starter", "shamos"],
            bundleIdentifiers: ["com.finder.helper", "com.shamos.agent"],
            filePaths: [
                "/private/tmp/helper",
                "/private/tmp/starter",
                "/private/tmp/out.zip",
                "/private/tmp/.mainhelper",
                "/Library/LaunchDaemons/com.finder.helper.plist",
                "~/Library/LaunchDaemons/com.finder.helper.plist",
            ],
            launchAgentLabels: ["com.finder.helper"]
        ),
        // MacSync / Mac.c / SHub Stealer v2.0 — masquerades as Google Keystone (Datadog Security Labs, 2025)
        SpywareSignature(
            name: "MacSync / SHub Stealer (fake Google Keystone)",
            processNames: ["GoogleUpdate", "GoogleSoftwareUpdate", "shub", "macsync"],
            bundleIdentifiers: ["com.google.keystone.fake"],
            filePaths: [
                "/private/tmp/osalogging.zip",
                "/private/tmp/shub_log.zip",
                "/private/tmp/.c.sh",
                "/private/tmp/exodus_asar.zip",
                "/private/tmp/atomic_asar.zip",
                "/private/tmp/ledger_asar.zip",
                "/private/tmp/ledger_live_asar.zip",
                "/private/tmp/trezor_asar.zip",
                "~/Library/Application Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate",
            ],
            launchAgentLabels: ["com.google.keystone.agent"]
        ),
        // DPRK supply-chain stage-2 loaders (Axios npm attack, Mar 2026 — Google TI / The Hacker News)
        SpywareSignature(
            name: "WAVESHAPER.V2 (Axios npm supply chain)",
            processNames: ["ld.py", "plain-crypto-js"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/ld.py",
                "/tmp/ld.py",
            ],
            launchAgentLabels: []
        ),
        // SilentSync RAT — PyPI termncolor / sisaws / secmeasure (Zscaler, 2025)
        SpywareSignature(
            name: "SilentSync RAT (PyPI supply chain)",
            processNames: ["pyhelper", "silentsync"],
            bundleIdentifiers: ["com.apple.pyhelper"],
            filePaths: ["~/Library/LaunchAgents/com.apple.pyhelper.plist"],
            launchAgentLabels: ["com.apple.pyhelper"]
        ),
        // Hades / Shai-Hulud PyPI campaign (Orca Security / The Hacker News, Jun 2026)
        SpywareSignature(
            name: "Hades PyPI (gh-token-monitor)",
            processNames: ["gh-token-monitor", "gh-token", "bun-helper"],
            bundleIdentifiers: ["com.user.gh-token-monitor"],
            filePaths: ["~/Library/LaunchAgents/com.user.gh-token-monitor.plist"],
            launchAgentLabels: ["com.user.gh-token-monitor"]
        ),
        // Contagious Interview stage-4 (Socket.dev / Microsoft Defender, 2025)
        SpywareSignature(
            name: "VShell (Contagious Interview stage-4)",
            processNames: [".gp"],
            bundleIdentifiers: [],
            filePaths: ["~/.gp"],
            launchAgentLabels: []
        ),
        // Enterprise / "stealth mode" employee monitoring suites — flagged as monitoring tools
        // by Microsoft Defender and used in non-consensual deployments. Surfaced as LOW severity
        // so consensual users can dismiss while non-consensual surveillance becomes visible.
        SpywareSignature(
            name: "Teramind Stealth Agent",
            processNames: ["System Monitoring", "tmagent", "teramind"],
            bundleIdentifiers: ["com.teramind.tmagent", "com.teramind.systemextension.endpointsecurity"],
            filePaths: [
                "/usr/local/teramind/agent",
                "/usr/local/teramind/agent/etc/agent.conf",
            ],
            launchAgentLabels: ["com.teramind.tmagent", "com.teramind.agent"]
        ),
        SpywareSignature(
            name: "ActivTrak (covert agent)",
            processNames: ["scthost", "activtrak"],
            bundleIdentifiers: ["com.bgrove.scthost"],
            filePaths: [
                "/Library/LaunchAgents/com.bgrove.activtrak.agent.plist",
                "/Library/LaunchDaemons/com.bgrove.activtrak.daemon.plist",
                "/Library/PrivilegedHelperTools/com.bgrove.activtrak.helper",
            ],
            launchAgentLabels: ["com.bgrove.activtrak.agent", "com.bgrove.activtrak.daemon"]
        ),
        SpywareSignature(
            name: "Hubstaff Silent",
            processNames: ["HubstaffClient", "Hubstaff"],
            bundleIdentifiers: ["com.netsoft.Hubstaff"],
            filePaths: ["/Applications/Hubstaff.app"],
            launchAgentLabels: ["com.netsoft.Hubstaff"]
        ),
        SpywareSignature(
            name: "Time Doctor Automatic App",
            processNames: ["sfproc", "sfproc.sh", "updateschecker2"],
            bundleIdentifiers: ["com.timedoctorllc.SFProc"],
            filePaths: ["/opt/sfproc/updateschecker2.app"],
            launchAgentLabels: ["com.timedoctorllc.SFProc"]
        ),
        SpywareSignature(
            name: "Veriato Cerebral / Vision",
            processNames: ["Helpdesk", "vsage", "veriato"],
            bundleIdentifiers: ["com.veriato.helpdesk", "com.veriato.cerebral"],
            filePaths: [
                "/Applications/Helpdesk.app",
                "/Library/LaunchDaemons/com.veriato.cerebral.plist",
            ],
            launchAgentLabels: ["com.veriato.cerebral", "com.veriato.helpdesk"]
        ),
        // AppleProcessHub Stealer — Objective-C Mach-O disguised as a dylib (Kandji, May 2025)
        SpywareSignature(
            name: "AppleProcessHub Stealer",
            processNames: ["libsystd.dylib", "libsystd", "AppleProcessHub", "appleprocesshub"],
            bundleIdentifiers: ["com.apple.processhub"],
            filePaths: [
                "/private/tmp/libsystd.dylib",
                "/private/tmp/.appleprocesshub",
                "~/Library/Application Support/.AppleProcessHub",
            ],
            launchAgentLabels: ["com.apple.processhub.agent"]
        ),
        // MacSync signed Swift variant — UserSyncWorker (Jamf Threat Labs, Dec 2025)
        SpywareSignature(
            name: "MacSync Signed Swift Stealer",
            processNames: ["UserSyncWorker", "runtimectl"],
            bundleIdentifiers: ["com.usersyncworker", "com.zk-call.installer"],
            filePaths: [
                "/private/tmp/runner",
                "~/Library/Application Support/UserSyncWorker",
                "~/Library/Application Support/UserSyncWorker/last_up",
                "~/Library/Application Support/UserSyncWorker/gate",
                "~/Library/Logs/UserSyncWorker.log",
            ],
            launchAgentLabels: ["com.usersyncworker"]
        ),
        // Infiniti Stealer / NukeChain — Nuitka-compiled Python via ClickFix
        // (Malwarebytes, BleepingComputer, SecurityWeek, Mar 2026)
        SpywareSignature(
            name: "Infiniti Stealer (NukeChain)",
            processNames: ["UpdateHelper.bin", "UpdateHelper", "nukechain", "infiniti"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/UpdateHelper.bin",
                "/private/tmp/.infiniti",
            ],
            launchAgentLabels: []
        ),
        // SHub Reaper — fake Google Keystone with applescript:// abuse
        // (Malwarebytes, SentinelOne, Netskope, Mar-May 2026)
        SpywareSignature(
            name: "SHub Reaper (fake CleanMyMac)",
            processNames: ["GoogleUpdate", "shub_reaper", "reaper"],
            bundleIdentifiers: ["com.google.keystone.fake"],
            filePaths: [
                "~/Library/GoogleUpdate.app",
                "/private/tmp/.c.sh",
            ],
            launchAgentLabels: ["com.google.keystone.agent"]
        ),
        // Nova Stealer — wallet-replacement campaign (CybersecurityNews, GBHackers, Nov 2025)
        SpywareSignature(
            name: "Nova Stealer",
            processNames: ["mdriversmngr", "mdriversmngr.sh", "mdriversinstall", "mdriversswaps"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.mdrivers",
                "~/.mdrivers/scripts",
            ],
            launchAgentLabels: ["application.com.artificialintelligence"]
        ),
        // HyperHives — DPRK Contagious Interview Rust Mach-O (Apr 2026)
        SpywareSignature(
            name: "HyperHives (DPRK Contagious Interview)",
            processNames: ["hyperhives", "force"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Documents/temp_data/Application",
                "/private/tmp/hyperhives",
            ],
            launchAgentLabels: []
        ),
        // notnullOSX — Go-based hand-targeted stealer (Moonlock, GBHackers, Mar 2026)
        SpywareSignature(
            name: "notnullOSX",
            processNames: ["notnullosx", "WallSpace", "SystemInfo_grab", "iMessageGrab", "CryptoWalletsGrab"],
            bundleIdentifiers: ["com.wallspace.app"],
            filePaths: [
                "/private/tmp/notnullosx",
                "/private/tmp/.notnullosx",
            ],
            launchAgentLabels: ["com.wallspace.agent"]
        ),
        // DigitStealer — JXA fileless infostealer via fake DynamicLake (Jamf, Nov 2025)
        SpywareSignature(
            name: "DigitStealer",
            processNames: ["DynamicLake", "digitstealer", "dynamiclake"],
            bundleIdentifiers: ["com.dynamiclake.fake"],
            filePaths: [
                "/Volumes/DynamicLake/DynamicLake.dmg",
                "/private/tmp/.digit",
            ],
            launchAgentLabels: []
        ),
        // ClickFix NNApp DMG campaign (Unit42 timely-threat-intel, Jun 2026)
        SpywareSignature(
            name: "NNApp ClickFix DMG (Unit42 Jun 2026)",
            processNames: ["NNApp", "nnapp"],
            bundleIdentifiers: ["com.utils.nnapp"],
            filePaths: [
                "/Volumes/NNApp/NNApp.app",
                "/private/tmp/s.01M0td.dmg",
                "~/.hlpr",
                "~/.hlpr/User Name.txt",
                "~/.hlpr/System Information.txt",
                "~/Library/LaunchAgents/com.hlpr.agent.plist",
            ],
            launchAgentLabels: ["com.hlpr.agent", "com.utils.nnapp"]
        ),
        // Paradox Stealer — delivered via compromised Cursor/Open VSX extensions (Phorion, late 2025)
        SpywareSignature(
            name: "Paradox Stealer (Open VSX supply chain)",
            processNames: ["xoxoxoxxx", "paradox"],
            bundleIdentifiers: ["com.todesktop.230313mzl4w4u92"],  // abused Cursor signing ID
            filePaths: [
                "~/.cursor/extensions/ether.solidity-0.0.191-universal",
                "/private/tmp/xoxoxoxxx",
            ],
            launchAgentLabels: []
        ),
        // macOS.Gaslight — Rust backdoor with LLM-analyst prompt-injection payload
        // (SentinelLabs Jun 2026; Apple XProtect: MACOS_BONZAI_COBUCH)
        SpywareSignature(
            name: "macOS.Gaslight (BONZAI)",
            processNames: ["gaslight", "endpoint-macos-aarch64"],
            bundleIdentifiers: [],
            filePaths: [],
            launchAgentLabels: ["com.apple.system.services.activity"]
        ),
        // Sapphire Sleet macOS chain — Zoom/Teams "SDK update" lure (Microsoft, Apr 2026)
        SpywareSignature(
            name: "Sapphire Sleet macOS chain (BlueNoroff)",
            processNames: ["com.apple.cli", "icloudz", "services",
                           "com.microsoft.helper", "com.google.chromes.updaters",
                           ".google.docs", ".com.apple.helpers",
                           "systemupdate", "softwareupdate"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/Application Support/Authorization/auth.db",
                "~/Library/Application Support/iCloud/icloudz",
                "~/Library/Google/com.google.chromes.updaters",
                "~/Library/Services/services",
                "~/Library/Identification/.verify",
                "~/Library/LaunchAgents/com.apple.identification.plist",
                "/Library/LaunchDaemons/com.google.webkit.service.plist",
                "/private/tmp/SystemUpdate",
                "/private/tmp/SoftwareUpdate",
                "/private/tmp/lg4err",
                "/private/tmp/Zoom SDK Update.scpt",
                "/private/tmp/msteams sdk update.scpt",
            ],
            launchAgentLabels: ["com.google.webkit.service", "com.apple.identification"]
        ),
        // UNC1069 macOS chain — Mandiant Feb 2026 (WAVESHAPER + HYPERCALL + DEEPBREATH +
        // CHROMEPUSH + SUGARLOADER + SILENCELIFT)
        SpywareSignature(
            name: "UNC1069 macOS chain (Mandiant)",
            processNames: ["com.apple.mond", "com.apple.system.settings",
                           "com.apple.system.updater", "com.apple.logd",
                           "System Settings", "SystemUpdater", "chromeext"],
            bundleIdentifiers: [],
            filePaths: [
                "/Library/Caches/com.apple.mond",
                "/Library/SystemSettings/com.apple.system.settings",
                "/Library/SystemSettings/.CacheLogs.db",
                "/Library/Caches/System Settings",
                "/Library/Caches/chromeext",
                "/Library/Caches/.Logs.db",
                "/Library/Fonts/com.apple.logd",
                "/Library/OSRecovery/SystemUpdater",
                "/Library/OSRecovery/com.apple.os.config",
                "/Library/Group Containers/OSRecovery",
                "/Library/LaunchDaemons/com.apple.system.updater.plist",
                "~/Library/Application Support/com.apple.os.receipts",
                "~/Library/Application Support/com.apple.os.receipts/setting.db",
                "~/Library/Application Support/Google/Chrome/NativeMessagingHosts/Brave Browser Docs",
                "~/Library/Application Support/Google/Chrome/NativeMessagingHosts/Google Chrome Docs",
            ],
            launchAgentLabels: ["com.apple.system.updater"]
        ),
        // NimDoor — Nim macOS implant with SIGINT/SIGTERM self-resurrection
        // (SentinelLabs Jul 2025, BleepingComputer)
        SpywareSignature(
            name: "NimDoor (DPRK Stardust Chollima)",
            processNames: ["CoreKitAgent", "GoogIe LLC", "trojan1_arm64",
                           "zoom_sdk_support", "upl", "tlgrm", "netchk"],
            bundleIdentifiers: ["com.google.update"],
            filePaths: [
                "~/Library/Application Support/Google LLC/GoogIe LLC",
                "~/Library/Application Support/GoogIe LLC",
                "~/Library/CoreKit/CoreKitAgent",
                "~/Library/DnsService/a",
                "~/Library/DnsService/netchk",
                "~/Library/LaunchAgents/com.google.update.plist",
                "~/.ses",
                "/private/tmp/.config",
                "/private/tmp/cfg",
                "/private/tmp/zoom_sdk_support.scpt",
            ],
            launchAgentLabels: ["com.google.update"]
        ),
        // Mach-O Man — Lazarus Go-Mach-O kit, Telegram Bot API C2 (ANY.RUN, CertiK, Apr 2026)
        SpywareSignature(
            name: "Mach-O Man (Lazarus / TraderTraitor)",
            processNames: ["teamsSDK", "minst2", "macrasv2", "localencode", "OneDrive"],
            bundleIdentifiers: ["com.onedrive.launcher"],
            filePaths: [
                "~/Antivirus Service",
                "~/Antivirus Service/OneDrive",
                "~/Library/LaunchAgents/com.onedrive.launcher.plist",
                "/private/tmp/teamsSDK.bin",
                "/private/tmp/minst2.bin",
                "/private/tmp/macrasv2",
            ],
            launchAgentLabels: ["com.onedrive.launcher"]
        ),
        // macOS.ZuRu (Termius variant) — China-nexus, Khepri C2 (SentinelLabs Jul 2025)
        SpywareSignature(
            name: "macOS.ZuRu (Termius variant)",
            processNames: [".Termius Helper1", "Termius Helper", ".localized"],
            bundleIdentifiers: ["com.apple.xssooxxagent"],
            filePaths: [
                "/Library/LaunchDaemons/com.apple.xssooxxagent.plist",
                "/Users/Shared/com.apple.xssooxxagent",
                "/private/tmp/Termius",
                "/private/tmp/.fseventsd",
                "/private/tmp/apple-local-ipc.sock.lock",
            ],
            launchAgentLabels: ["com.apple.xssooxxagent"]
        ),
        // Macma / CDDS — China (Evasive Panda / Daggerfly / StormBamboo) 2024 variant
        SpywareSignature(
            name: "Macma / CDDS (Daggerfly / Evasive Panda)",
            processNames: ["UserAgent", "macma", "cdds"],
            bundleIdentifiers: ["com.UserAgent.va"],
            filePaths: [
                "~/Library/LaunchAgents/com.UserAgent.va.plist",
                "~/Library/Preferences/UserAgent/lib/UserAgent",
            ],
            launchAgentLabels: ["com.UserAgent.va"]
        ),
        // BlueNoroff GhostCall component family — Telegram-initiated fake Zoom/Teams,
        // multi-implant kit (Kaspersky Securelist GReAT, 2025-2026)
        SpywareSignature(
            name: "BlueNoroff GhostCall / GhostHire kit",
            processNames: ["CosmicDoor", "SilentSiphon", "RealTimeTroy", "RooTroy",
                           "ZoomClutch", "TeamsClutch", "GillyInjector", "InjectWithDyld",
                           "Nimcore", "DownTroy", "Root Troy V4", "XScreen"],
            bundleIdentifiers: [],
            filePaths: [
                "/Users/Shared/.pd",
                "/private/tmp/.growth",
                "/private/tmp/.zsh_init_success",
            ],
            launchAgentLabels: []
        ),
        // FlexibleFerret updated CDrivers chain (Jamf Threat Labs, late 2025)
        SpywareSignature(
            name: "FlexibleFerret CDrivers chain",
            processNames: ["CDrivers", "drivfixer"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/CDrivers.zip",
                "/private/var/tmp/CDrivers",
                "/private/var/tmp/CDrivers/drivfixer.sh",
                "~/Library/LaunchAgents/com.driver9990as7tpatch.plist",
            ],
            launchAgentLabels: ["com.driver9990as7tpatch"]
        ),
        // BlueNoroff Hidden Risk — zshenv persistence (the novel 2024 trick)
        // — caught also by the .zshenv shell-config scanner; we surface the marker file here
        SpywareSignature(
            name: "BlueNoroff Hidden Risk (zshenv abuse)",
            processNames: ["growth", "growth_trajectory"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.zsh_init_success",
                "~/.zshenv",  // benign by itself, but flagged when malware drops a sentinel
            ],
            launchAgentLabels: []
        ),
        // Axios npm supply chain → NukeSped Mach-O (Huntress / Microsoft, Mar 2026)
        SpywareSignature(
            name: "NukeSped via Axios npm chain (UNC1069 / BlueNoroff)",
            processNames: ["com.apple.act.mond", "act.mond"],
            bundleIdentifiers: ["com.apple.act.mond"],
            filePaths: [
                "/Library/Caches/com.apple.act.mond",
                "node_modules/plain-crypto-js",
            ],
            launchAgentLabels: ["com.apple.act.mond"]
        ),
        SpywareSignature(
            name: "DigiStealer (Lampion macOS)",
            processNames: ["DigiStealer", "digistealer", "lampion", "Lampion"],
            bundleIdentifiers: ["com.digistealer.agent", "com.lampion.stealer"],
            filePaths: [
                "/private/tmp/.digistealer",
                "/private/tmp/.lampion",
                "~/Library/Application Support/.DigiStealer",
            ],
            launchAgentLabels: ["com.digistealer.agent", "com.lampion.service"]
        ),
        SpywareSignature(
            name: "CloudChain Loader",
            processNames: ["CloudChain", "cloudchain", "cloudchaind", "CloudChainAgent"],
            bundleIdentifiers: ["com.cloudchain.loader"],
            filePaths: [
                "/private/tmp/.cloudchain",
                "~/Library/Application Support/.CloudChain",
            ],
            launchAgentLabels: ["com.cloudchain.service"]
        ),
        // 2024-2025 DPRK / Lazarus / BlueNoroff campaigns against macOS
        // BeaverTail — Contagious Interview (Microsoft TI Mar 2026, Datadog Security Labs,
        // GitLab Security, ESET deceptivedevelopment IOC repo, NVISO Nov 2025)
        SpywareSignature(
            name: "BeaverTail (Contagious Interview)",
            processNames: ["BeaverTail", "beavertail", "x64nvidia", "payuniversal2", "ChromeUpdate"],
            bundleIdentifiers: ["com.nvidia.hpc.pkg"],
            filePaths: [
                "~/.myvars",
                "~/.npc",
                "~/.linvidia",
                "/private/var/tmp/downx64.sh",
                "~/Library/LaunchAgents/com.avatar.update.wake.plist",
                "~/Library/Caches/.n2",
            ],
            launchAgentLabels: ["com.avatar.update.wake", "com.npl.update", "com.n2.update"]
        ),
        SpywareSignature(
            name: "InvisibleFerret (Contagious Interview)",
            processNames: ["InvisibleFerret", "ferret", "payuniversal2", "pythonw_helper"],
            bundleIdentifiers: [],
            filePaths: [
                "~/.npl",
                "~/.n2",
                "~/.pyp",
                "/private/tmp/p.zip",
                "/private/tmp/.n2/pay",
                "/private/tmp/.n2/bow",
                "/private/tmp/.n2/mlip",
                "/private/tmp/.npl",
            ],
            launchAgentLabels: []
        ),
        // FlexibleFerret — Ferret family (SentinelOne Feb 2025; Jamf Threat Labs)
        SpywareSignature(
            name: "FlexibleFerret (Ferret family)",
            processNames: ["FlexibleFerret", "versus", "InstallerAlert", "zoom", "postinstall"],
            bundleIdentifiers: ["Mac-Installer.AlertMsg", "Mac-Installer.InstallerAlert", "com.apple.ferret"],
            filePaths: [
                "/private/tmp/versus.app",
                "/private/var/tmp/logd",        // masquerades as the macOS logd binary
                "/Volumes/versus/versus.pkg",
                "~/Library/LaunchAgents/com.zoom.plist",
            ],
            launchAgentLabels: ["com.zoom"]
        ),
        // FrostyFerret / FriendlyFerret — XProtect-named DPRK macOS lures (SentinelOne, Jamf)
        SpywareSignature(
            name: "FrostyFerret / FriendlyFerret (DPRK)",
            processNames: ["ChromeUpdate", "CameraAccess", "VCam", "com.apple.secd"],
            bundleIdentifiers: [],
            filePaths: [
                "~/Library/LaunchAgents/com.zoom.plist",
                "/private/var/tmp/.frostyferret",
            ],
            launchAgentLabels: ["com.zoom"]
        ),
        // OtterCookie — including Nov 2025 npm wave with com.user.connector LaunchAgent
        // (Talos, Polyswarm, SafeDep, NTT Security)
        SpywareSignature(
            name: "OtterCookie",
            processNames: ["OtterCookie", "ottercookie", "otter_helper", "node-connector"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.ottercookie",
                "~/Library/Application Support/.OtterCookie",
                "~/Library/LaunchAgents/com.user.connector.plist",
            ],
            launchAgentLabels: ["com.user.connector"]
        ),
        // GolangGhost / WeaselStore — ClickFake Interview Go RAT chain (Sekoia, Talos, ESET)
        SpywareSignature(
            name: "GolangGhost / WeaselStore (DPRK Go RAT)",
            processNames: ["coremedia", "vcamservice", "ffmepg", "drivfixer", "DriverMinUpdate"],
            bundleIdentifiers: ["com.vcam"],
            filePaths: [
                "/private/var/tmp/VCam.zip",
                "/private/var/tmp/VCam",
                "/private/var/tmp/VCam/vcamservice.sh",
                "/Library/LaunchAgents/com.drive.plist",
                "/Library/LaunchAgents/com.vcam.plist",
            ],
            launchAgentLabels: ["com.drive", "com.vcam"]
        ),
        // AkdoorTea — shared chain artifacts on macOS (ESET deceptivedevelopment IOC repo)
        SpywareSignature(
            name: "AkdoorTea (DPRK)",
            processNames: ["DriverMinUpdate", "mac-v-j1722.fixer", "drivfixer", "akdoortea"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/var/tmp/driv.zip",
                "/private/var/tmp/drivfixer.sh",
                "/private/var/tmp/DriverMinUpdate",
                "/private/var/tmp/mac-v-j1722.fixer",
            ],
            launchAgentLabels: []
        ),
        SpywareSignature(
            name: "TodoSwift (Lazarus)",
            processNames: ["TodoSwift", "todoswift", "todoTasks", "todo_helper"],
            bundleIdentifiers: ["com.todo.swift", "com.todoswift.helper"],
            filePaths: ["/private/tmp/.todoswift"],
            launchAgentLabels: ["com.todoswift.agent"]
        ),
        SpywareSignature(
            name: "RustyAttr (Lazarus)",
            processNames: ["RustyAttr", "rustyattr", "tarball", "rust_helper"],
            bundleIdentifiers: ["com.rustyattr.helper"],
            filePaths: [
                "/private/tmp/.rustyattr",
                "~/Library/Application Support/.RustyAttr",
            ],
            launchAgentLabels: ["com.rustyattr.service"]
        ),
        SpywareSignature(
            name: "HiddenRisk (Lazarus)",
            processNames: ["HiddenRisk", "hiddenrisk", "growth_link", "BTCFavorable"],
            bundleIdentifiers: ["com.crypto.helper", "com.hiddenrisk.agent"],
            filePaths: [
                "/private/tmp/.hiddenrisk",
                "~/Library/Application Support/.HiddenRisk",
                "~/Library/Group Containers/.crypto",
            ],
            launchAgentLabels: ["com.apple.helper.crypto"]
        ),
        SpywareSignature(
            name: "PoisonNutCase (BlueNoroff)",
            processNames: ["PoisonNutCase", "poisonnut", "nutcase", "NutCaseHelper"],
            bundleIdentifiers: [],
            filePaths: [
                "/private/tmp/.poisonnut",
                "~/Library/Application Support/.NutCase",
            ],
            launchAgentLabels: ["com.apple.nutcase"]
        ),
        SpywareSignature(
            name: "NimDoor",
            processNames: ["NimDoor", "nimdoor", "nimagent", "trojan_nim"],
            bundleIdentifiers: ["com.nim.door", "com.nimdoor.agent"],
            filePaths: [
                "/private/tmp/.nimdoor",
                "~/Library/Application Support/.NimDoor",
            ],
            launchAgentLabels: ["com.nim.door.service"]
        ),
        // 2025 ClickFix / FakeCAPTCHA / FakeUpdate delivered stealers
        SpywareSignature(
            name: "ClickFix Payload (macOS)",
            processNames: ["update_helper", "browser_repair", "captcha_verify", "verify_helper"],
            bundleIdentifiers: ["com.clickfix.helper", "com.captcha.update"],
            filePaths: [
                "/private/tmp/.update_helper",
                "/private/tmp/.browser_repair",
                "/private/tmp/.captcha_verify",
            ],
            launchAgentLabels: ["com.clickfix.helper", "com.captcha.update"]
        ),
        // 2025 supply-chain / npm-pypi delivered macOS payloads
        SpywareSignature(
            name: "PondRAT (npm supply chain)",
            processNames: ["PondRAT", "pondrat", "pond_helper", "ponddaemon"],
            bundleIdentifiers: ["com.pondrat.agent"],
            filePaths: [
                "/private/tmp/.pondrat",
                "~/Library/Application Support/.PondRAT",
            ],
            launchAgentLabels: ["com.pondrat.service"]
        ),
        // 2025 ChatGPT / Cursor / Claude impersonators (trojan installers)
        SpywareSignature(
            name: "FakeChatGPT macOS",
            processNames: ["ChatGPT_Mac", "OpenAI_Helper", "chatgpt_updater"],
            bundleIdentifiers: ["com.chatgpt.mac.helper", "com.openai.unofficial"],
            filePaths: [
                "/private/tmp/.chatgpt_helper",
                "~/Library/Application Support/.ChatGPTHelper",
            ],
            launchAgentLabels: ["com.chatgpt.mac.helper", "com.openai.updater"]
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
        // 2024-2025 observed impersonations
        "com.apple.helper.crypto",
        "com.apple.processhub",
        "com.apple.ferret",
        "com.apple.ferret.helper",
        "com.apple.nutcase",
        "com.apple.icloudsync",
        "com.apple.spotlight.helper",
        "com.apple.systempreferences.helper",
        "com.apple.notificationcenter.helper",
        "com.apple.WindowManager.helper",
        "com.apple.controlcenter.agent",
        "com.apple.coreaudio.helper",
        "com.apple.networkextension.helper",
        "com.apple.endpointsecurity.helper",
        "com.apple.terminalhelper",
        "com.apple.finderagent",
        // 2025-2026 confirmed Apple-impersonating plist labels from primary reporting
        "com.apple.system.services.activity",  // macOS.Gaslight (SentinelLabs, Jun 2026)
        "com.apple.identification",            // Sapphire Sleet Teams variant (Microsoft, 2026)
        "com.apple.xssooxxagent",              // macOS.ZuRu Termius (SentinelLabs, 2025)
        "com.apple.act.mond",                  // BlueNoroff Axios npm chain (Huntress, 2026)
        "com.apple.mond",                      // UNC1069 WAVESHAPER (Mandiant, Feb 2026)
        "com.apple.system.settings",           // UNC1069 HYPERCALL (Mandiant)
        "com.apple.system.updater",            // UNC1069 SUGARLOADER (Mandiant)
        "com.apple.logd",                      // UNC1069 SILENCELIFT (Mandiant) — masquerades as logd
        "com.apple.secd",                      // FriendlyFerret (DPRK Ferret family)
        // Non-Apple but conspicuous LaunchAgent labels observed alongside the above
        "com.google.webkit.service",           // Sapphire Sleet (Microsoft, 2026)
        "com.google.chromes.updaters",         // Sapphire Sleet (note "chromes" plural — real Google uses singular)
        "com.google.update",                   // NimDoor (SentinelLabs, 2025)
        "com.onedrive.launcher",               // Mach-O Man / Lazarus (ANY.RUN, Apr 2026)
        "com.UserAgent.va",                    // Macma 2024 variant (Volexity, Daggerfly)
        // Common LLM/AI impersonations (2025 trojan installers)
        "com.openai.unofficial",
        "com.chatgpt.mac.helper",
        "com.anthropic.helper",
        "com.claude.helper",
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
        // 2025 stealer / RAT impersonations observed in the wild
        "WindowManager_helper",  // Real: WindowManager (no _helper suffix)
        "endpointsecurityd",     // Real: endpointsecurityd lives only in /usr/libexec
        "MRT_agent",             // Real: MRT (Malware Removal Tool, no agent)
        "amfid_helper",          // Real: amfid (no helper)
        "Finder_helper",         // Real: Finder (no helper, lives in /System/Library/CoreServices)
        "appstoredaemon",        // Real: appstoreagent / commerce
        "TimeMachineHelper",     // Real: backupd / com.apple.backupd
        "Photos_helper",         // Real: Photos / photoanalysisd
        "icloudpd",              // Real: cloudd / bird — not the open-source icloudpd
        "controlcenter_agent",   // Real: ControlCenter (no agent suffix)
        "ChatGPT_Mac",           // Apple does not ship a ChatGPT binary
        "OpenAI_Helper",         // Apple does not ship OpenAI binaries
        "Anthropic_Helper",      // Apple does not ship Anthropic binaries
        "Claude_Helper",         // Real Claude.app uses bundled Helper inside its app bundle
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
