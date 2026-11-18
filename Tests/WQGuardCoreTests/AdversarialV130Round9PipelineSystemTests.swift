//
//  AdversarialV130Round9PipelineSystemTests.swift
//  WQGuardCoreTests
//
//  Deep Security Audit Suite (Round 9): Multi-Engine Correlation, Registry Heterogeneous Entitlements & Wildcard Keychain,
//  Whitelist Fail-Closed Invariants, CLI State & Firmware Report Sanitization, Unicode Tag/Bidi Neutralization,
//  Homoglyph Brand Impersonation, and Real JavaScriptCore Brotli Shield Verification.
//

import XCTest
import Foundation
import Darwin
import JavaScriptCore
@testable import WQGuardCore

final class AdversarialV130Round9PipelineSystemTests: XCTestCase {

    private var tempURLs: [URL] = []

    override func setUp() {
        super.setUp()
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
    }

    override func tearDown() {
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
        for u in tempURLs {
            try? FileManager.default.removeItem(at: u)
        }
        tempURLs.removeAll()
        super.tearDown()
    }

    private func makeTempFile(_ name: String) -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("r9_\(UUID().uuidString)_\(name)")
        tempURLs.append(u)
        return u
    }

    private func runCLIInProcess(_ args: [String]) async throws -> (code: Int32, out: String, err: String) {
        let outURL = makeTempFile("out.txt")
        let errURL = makeTempFile("err.txt")
        FileManager.default.createFile(atPath: outURL.path, contents: nil)
        FileManager.default.createFile(atPath: errURL.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: outURL)
        let errHandle = try FileHandle(forWritingTo: errURL)
        let code = await CLICommandRunner.run(arguments: ["wqguard-cli"] + args, stdout: outHandle, stderr: errHandle)
        try outHandle.close()
        try errHandle.close()
        return (
            code,
            String(decoding: try Data(contentsOf: outURL), as: UTF8.self),
            String(decoding: try Data(contentsOf: errURL), as: UTF8.self)
        )
    }

    // MARK: - 1. Multi-Engine Correlation Anti-Masking & Probe Anti-Suppression

    func test_r9_correlateAndMerge_preservesSideloadCloneAlongsideOfficialAppStore_andNeverSuppressesProbeBySafeName() {
        // 1. Official App Store MetaMask in registry + unencrypted sideloaded MetaMask clone IPA in queue
        let officialMetaMaskRecord = InstalledAppRegistryRecord(
            bundleId: "io.metamask.MetaMask",
            displayName: "MetaMask",
            version: "7.30.0",
            applicationType: "User",
            signerIdentity: "Apple iPhone OS Application Signing",
            profileValidated: false,
            hasAppStoreMetadata: true,
            bundlePath: "/private/var/containers/Bundle/Application/AAAA/MetaMask.app"
        )
        let sideloadedCloneFinding = ScanFinding(
            bundleId: "io.metamask.MetaMask",
            displayName: "MetaMask",
            version: "7.30.0",
            executablePath: "MetaMask.app/MetaMask",
            bundlePath: "/var/mobile/Documents/MetaMask_Clone.ipa",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            indicators: [ThreatIndicator(
                signature: "IMPERSONATION:MetaMask",
                description: "Sideloaded wallet impersonation",
                category: "Wallet/Messenger Impersonation",
                location: "MetaMask_Clone.ipa",
                severity: .highRisk
            )],
            evidence: AuditEvidence(
                installChannel: .developerSideloaded,
                cryptid: 0,
                isFairPlayEncrypted: false
            )
        )

        // 2. Benign App Store note app sharing displayName "Feather" must NOT suppress URL-scheme probe hit for Feather
        let benignFeatherNotesRecord = InstalledAppRegistryRecord(
            bundleId: "com.productivity.feathernotes",
            displayName: "Feather",
            version: "2.1",
            applicationType: "User",
            signerIdentity: "Apple iPhone OS Application Signing",
            profileValidated: false,
            hasAppStoreMetadata: true,
            bundlePath: "/private/var/containers/Bundle/Application/BBBB/FeatherNotes.app"
        )
        let probeHits = OnDeviceAppProbeScanner.shared.evaluateProbes { $0 == "feather" }
        XCTAssertEqual(probeHits.count, 1)

        let merged = SecurityPipeline.shared.correlateAndMergeFindings(
            registryRecords: [officialMetaMaskRecord, benignFeatherNotesRecord],
            packageFindings: [sideloadedCloneFinding],
            probeFindings: probeHits,
            includeAppStoreApps: true
        )

        XCTAssertEqual(merged.correlatedCount, 0, "Official encrypted App Store app must never absorb an unencrypted sideload clone")
        XCTAssertEqual(merged.probeCount, 1, "Benign .safe app sharing only displayName must not suppress active URL-scheme probe")
        XCTAssertEqual(merged.findings.count, 4)

        let cloneOut = merged.findings.first { $0.bundlePath.contains("MetaMask_Clone.ipa") }
        XCTAssertEqual(cloneOut?.riskTier, .highRisk)
        XCTAssertEqual(cloneOut?.installChannel, .developerSideloaded)
    }

    // MARK: - 2. Registry Heterogeneous Arrays, Scalar TCC, Wildcard Keychain & devicectl Entitlements

    func test_r9_registryScanner_heterogeneousEntitlements_nonAppleWildcardKeychain_andDeviceCtlEntitlements() throws {
        // 1. Heterogeneous [Any] in keychain-access-groups with non-Apple prefix wildcard ("TEAM999999.*") + scalar Bool tcc.allow
        //    disguised with App Store metadata (includeAppStoreApps = false must STILL surface it via isSideloadedOrAnomalous!)
        let rawDict: [String: Any] = [
            "CFBundleIdentifier": "com.r9.stealth.harvester",
            "CFBundleDisplayName": "StealthHarvester",
            "CFBundleShortVersionString": "1.0",
            "ApplicationType": "User",
            "SignerIdentity": "Apple iPhone OS Application Signing",
            "ProfileValidated": false,
            "iTunesMetadata": ["itemId": 12345],
            "Entitlements": [
                "keychain-access-groups": [99, "TEAM999999.*"] as [Any],
                "com.apple.private.tcc.allow": true,
                "com.apple.private.MobileContainerManager.allowed": ["*"]
            ] as [String: Any]
        ]
        let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary(rawDict))
        XCTAssertEqual(rec.keychainAccessGroups, ["TEAM999999.*"])
        XCTAssertTrue(rec.tccAllowedServices.contains("com.apple.private.tcc.allow"))
        XCTAssertEqual(rec.booleanEntitlements["com.apple.private.MobileContainerManager.allowed"], true)
        XCTAssertTrue(InstalledAppRegistryScanner.shared.isSideloadedOrAnomalous(rec))

        let findings = InstalledAppRegistryScanner.shared.evaluateRecords([rec], includeAppStoreApps: false)
        XCTAssertEqual(findings.count, 1)
        let sigs = Set(findings[0].indicators.map(\.signature))
        XCTAssertEqual(findings[0].riskTier, .highRisk)
        XCTAssertTrue(sigs.contains("keychain-access-groups(*)"))
        XCTAssertTrue(sigs.contains("com.apple.private.tcc.allow"))
        XCTAssertTrue(sigs.contains("com.apple.private.MobileContainerManager.allowed"))

        // 2. Non-Apple wildcard keychain alone ("EVILTEAM00.*") on App Store-disguised record -> surfaced & flagged .highRisk
        let kcOnlyDict: [String: Any] = [
            "CFBundleIdentifier": "com.r9.keychain.wildcard",
            "ApplicationType": "User",
            "SignerIdentity": "Apple iPhone OS Application Signing",
            "iTunesMetadata": ["itemId": 888],
            "Entitlements": ["keychain-access-groups": "EVILTEAM00.*"]
        ]
        let kcRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary(kcOnlyDict))
        let kcFindings = InstalledAppRegistryScanner.shared.evaluateRecords([kcRec], includeAppStoreApps: false)
        XCTAssertEqual(kcFindings.first?.riskTier, .highRisk)
        XCTAssertTrue(kcFindings.first?.indicators.contains { $0.signature == "keychain-access-groups(*)" } ?? false)

        // 3. devicectl JSON carrying embedded entitlements dictionary -> parsed & flagged .highRisk
        let devCtlJSON = """
        {
          "result": {
            "apps": [
              {
                "bundleIdentifier": "com.r9.devicectl.escape",
                "name": "DevCtlEscape",
                "version": "1.2",
                "defaultApp": false,
                "internalApp": false,
                "builtByDeveloper": false,
                "entitlements": {
                  "com.apple.private.security.container-required": false
                }
              }
            ]
          }
        }
        """
        let ctlRecords = try InstalledAppRegistryScanner.shared.parseSnapshotData(Data(devCtlJSON.utf8))
        let ctlFindings = InstalledAppRegistryScanner.shared.evaluateRecords(ctlRecords, includeAppStoreApps: false)
        XCTAssertEqual(ctlFindings.count, 1)
        XCTAssertEqual(ctlFindings.first?.riskTier, .highRisk)
        XCTAssertTrue(ctlFindings.first?.indicators.contains { $0.signature == "com.apple.private.security.container-required" } ?? false)
    }

    // MARK: - 3. WhitelistEngine Zero-Identity Fail-Closed & Apple System Group Piggyback Defense

    func test_r9_whitelistEngine_emptyCriteriaFailClosed_appleSystemGroupBlocked_andTrimmedTeamIds() {
        let engine = WhitelistEngine()

        // 1. Degenerate rule with zero non-empty identity constraints MUST fail closed (never match every app!)
        engine.registerCustomTool(WhitelistedTool(
            name: "AccidentalEmptyRule",
            allowedBundleIds: ["   ", ""],
            allowedAppGroups: [],
            allowedTeamIds: ["  "],
            expectedSignatures: []
        ))
        XCTAssertFalse(engine.isWhitelisted(
            bundleId: "com.arbitrary.malware",
            appGroups: ["group.arbitrary"],
            matchedSignatures: ["arm64:svc_0x80"]
        ).isWhitelisted, "Empty-criteria custom whitelist rule must fail closed")

        // 2. Custom tool rule must reject unauthorized Apple system App Group piggybacking
        engine.registerCustomTool(WhitelistedTool(
            name: "UserResearchTool",
            allowedBundleIds: ["com.researcher.tool"],
            allowedAppGroups: ["group.com.researcher.tool"],
            allowedTeamIds: ["  TEAM777888  "]
        ))
        XCTAssertTrue(engine.isWhitelisted(
            bundleId: "com.researcher.tool",
            appGroups: ["group.com.researcher.tool"],
            teamId: "TEAM777888"
        ).isWhitelisted)
        XCTAssertFalse(engine.isWhitelisted(
            bundleId: "com.researcher.tool",
            appGroups: ["group.com.researcher.tool", IOCTokenArmor.tGestaltGroup],
            teamId: "TEAM777888"
        ).isWhitelisted, "Piggybacking systemgroup.com.apple.* onto a custom tool must be rejected")
        XCTAssertFalse(engine.isWhitelisted(
            bundleId: "com.researcher.tool",
            appGroups: ["group.com.researcher.tool"],
            teamId: "TEAM777888\u{200B}"
        ).isWhitelisted)
    }

    // MARK: - 4. CLI Scoped --whitelist Cleanup & Firmware Report Backtick/Control Injection Defense

    func test_r9_cliScopedWhitelistRestoration_andFirmwareRadarOutputSanitization() async throws {
        // 1. CLI --whitelist must be scoped to the single invocation and cleaned up via defer
        let res = try await runCLIInProcess(["--whitelist", "com.r9.ephemeral.cli", "--firmware-radar=27.3"])
        XCTAssertEqual(res.code, 0)
        XCTAssertNil(
            WhitelistEngine.shared.tool(named: "CLI-Whitelist-com.r9.ephemeral.cli"),
            "CLI --whitelist rule leaked into WhitelistEngine.shared after run() returned"
        )

        // 2. Hostile --firmware-radar string with backticks, newline heading forgery, and ANSI ESC sequence
        let hostileVer = "27.2.1`\n# Forged Safe Heading\n\u{001B}[2J"
        let txtRun = try await runCLIInProcess(["--firmware-radar=\(hostileVer)", "--format", "text"])
        XCTAssertEqual(txtRun.code, 1)
        XCTAssertFalse(txtRun.out.unicodeScalars.contains { $0.value == 0x1B }, "Plaintext firmware report leaked raw ESC")
        XCTAssertFalse(txtRun.out.components(separatedBy: .newlines).contains("# Forged Safe Heading"))

        let mdRun = try await runCLIInProcess(["--firmware-radar=\(hostileVer)", "--format", "markdown"])
        XCTAssertEqual(mdRun.code, 1)
        XCTAssertFalse(mdRun.out.unicodeScalars.contains { $0.value == 0x1B }, "Markdown firmware report leaked raw ESC")
        XCTAssertFalse(mdRun.out.components(separatedBy: .newlines).contains("# Forged Safe Heading"),
                       "Backtick + newline in --firmware-radar broke out of Target OS codeSpan")
    }

    // MARK: - 5. ReportGenerator Unicode Bidi ALM, BOM, Interlinear Annotation & Tag Block Neutralization

    func test_r9_reportGenerator_neutralizesALM_BOM_interlinearAnnotations_zwsp_andUnicodeTags() {
        // U+061C (ALM), U+FEFF (BOM), U+FFF9..U+FFFB (interlinear), U+200B (ZWSP), U+E0049 U+E0047 (Unicode Tags)
        let smuggled = "Evil\u{061C}App\u{FEFF}\u{200B}\u{FFF9}hidden\u{FFFB}\u{E0049}\u{E0047}"
        let finding = ScanFinding(
            bundleId: "com.r9.tag",
            displayName: smuggled,
            version: "1.0",
            bundlePath: "/tmp/app",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            indicators: [ThreatIndicator(
                signature: "sig",
                description: smuggled,
                category: "cat",
                location: smuggled,
                severity: .highRisk
            )],
            evidence: AuditEvidence()
        )
        let session = ScanSession(findings: [finding])
        let txt = ReportGenerator.shared.generatePlainTextReport(session: session)
        let md = ReportGenerator.shared.generateMarkdownReport(session: session)

        let forbiddenRawScalars: Set<UInt32> = [0x061C, 0xFEFF, 0x200B, 0xFFF9, 0xFFFA, 0xFFFB, 0xE0049, 0xE0047]
        for out in [txt, md] {
            for sc in out.unicodeScalars {
                XCTAssertFalse(forbiddenRawScalars.contains(sc.value),
                               "Raw invisible/bidi/tag scalar U+\(String(format: "%04X", sc.value)) leaked into report")
            }
            XCTAssertTrue(out.contains("\\u061C"))
            XCTAssertTrue(out.contains("\\U000E0049"))
        }
    }

    // MARK: - 6. Homoglyph Brand Impersonation, @loader_path Tweaks, Case-Insensitive Hookers & Trimmed BgModes

    func test_r9_expandedThreatCatalog_homoglyphs_loaderPathTweaks_andZeroFalsePositives() {
        // 1. Cyrillic, Greek, and fullwidth homoglyph wallet/messenger clones must all trigger .highRisk
        let homoglyphDisplayNames = [
            "МеtаМаsk",          // Cyrillic М, е, а
            "ＭｅｔａＭａｓｋ",     // Fullwidth Latin
            "Теlеgrаm",          // Cyrillic Т, е, а
            "ОКХ",               // Cyrillic О, К, Х
            "Вinаnсе",           // Cyrillic В, а, с, е
            "Meta\u{200B}Mask"   // Zero-width space split
        ]
        for fakeName in homoglyphDisplayNames {
            let inds = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: "com.random.sideload",
                displayName: fakeName,
                installChannel: .developerSideloaded,
                cryptid: 0
            )
            XCTAssertFalse(inds.isEmpty, "Homoglyph impersonation '\(fakeName)' evaded detection")
            XCTAssertEqual(inds.first?.severity, .highRisk)
        }

        // Homoglyph bundle ID ("io.mеtаmаsk.wallet" with Cyrillic е/а)
        let bidInds = ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: "io.m\u{0435}t\u{0430}m\u{0430}sk.wallet",
            displayName: "MyWallet",
            installChannel: .developerSideloaded,
            cryptid: 0
        )
        XCTAssertTrue(bidInds.contains { $0.signature == "IMPERSONATION:MetaMask" })

        // Benign word-boundary controls must remain 100% clean (zero false positives)
        for cleanName in ["NetGuard", "PostgREST", "GitGraph", "ZeroTrust", "Bitwarden"] {
            let cleanInds = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: "com.clean.\(cleanName.lowercased())",
                displayName: cleanName,
                installChannel: .developerSideloaded,
                cryptid: 0
            )
            XCTAssertTrue(cleanInds.isEmpty, "False positive on benign app '\(cleanName)'")
        }

        // 2. @loader_path tweaks & lowercase hooking frameworks
        let dylibInds = ExpandedThreatCatalog.evaluateInjectedDylibs(linkedDylibs: [
            "@loader_path/Dylibs/modmenu.dylib",
            "@loader_path/libhook_custom.dylib",
            "@rpath/ellekit.dylib"
        ])
        let dylibSigs = Set(dylibInds.map(\.signature))
        XCTAssertTrue(dylibSigs.contains("modmenu.dylib"))
        XCTAssertTrue(dylibSigs.contains("libhook_custom.dylib"))
        XCTAssertTrue(dylibSigs.contains("ElleKit"))

        // 3. Trimmed & case-varied UIBackgroundModes in clipboard snooping
        let clipInd = ExpandedThreatCatalog.evaluateClipboardSnooping(
            backgroundModes: ["  Audio  "],
            symbols: ["_OBJC_CLASS_$_UIPasteboard"],
            cryptid: 0
        )
        XCTAssertNotNil(clipInd)
        XCTAssertEqual(clipInd?.severity, .highRisk)
    }

    // MARK: - 7. Real JavaScriptCore Execution of brotli-guard.js & Stash Payload + ExtraHosts Sanitization

    func test_r9_brotliGuardJS_realJSCExecution_blocksQuotedNulAndTransferEncoding_andSanitizesExtraHosts() throws {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let jsURL = repoRoot.appendingPathComponent("Shields/scripts/brotli-guard.js")
        let standaloneJS = try String(contentsOf: jsURL, encoding: .utf8)

        let stashYAML = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        guard let payloadRange = stashYAML.range(of: "payload: |\n") else {
            XCTFail("Missing payload: | in generated Stash shield")
            return
        }
        let stashJS = stashYAML[payloadRange.upperBound...]
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { line -> String in
                var s = String(line)
                if s.hasPrefix("      ") { s.removeFirst(6) }
                return s
            }
            .joined(separator: "\n")

        func evalGuard(script: String, headers: [String: Any]) -> [String: Any]? {
            guard let ctx = JSContext() else { return nil }
            var captured: [String: Any]? = nil
            let doneBlock: @convention(block) (JSValue) -> Void = { val in
                captured = val.toDictionary() as? [String: Any]
            }
            ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
            ctx.setObject(["headers": headers], forKeyedSubscript: "$response" as NSString)
            _ = ctx.evaluateScript(script)
            return captured
        }

        let mustBlockCases: [(label: String, headers: [String: Any])] = [
            ("Quoted \"br\"", ["Content-Encoding": "\"br\""]),
            ("List with quoted \"br\"", ["content-encoding": "gzip, \"br\""]),
            ("Trailing NUL br\\0", ["Content-Encoding": "br\u{0000}"]),
            ("Transfer-Encoding: br", ["Transfer-Encoding": "br"]),
            ("Transfer-Encoding: gzip, br", ["transfer-encoding": ["gzip", "br"]])
        ]
        let mustAllowCases: [(label: String, headers: [String: Any])] = [
            ("Custom token br-custom-token", ["Content-Encoding": "br-custom-token"]),
            ("Standard gzip, deflate", ["Content-Encoding": "gzip, deflate"]),
            ("Chunked transfer", ["Transfer-Encoding": "chunked"])
        ]

        for (scriptName, scriptCode) in [("brotli-guard.js", standaloneJS), ("Stash payload", stashJS)] {
            for c in mustBlockCases {
                let out = try XCTUnwrap(evalGuard(script: scriptCode, headers: c.headers))
                XCTAssertEqual(out["status"] as? Int, 403, "\(scriptName) failed to block \(c.label)")
            }
            for c in mustAllowCases {
                let out = try XCTUnwrap(evalGuard(script: scriptCode, headers: c.headers))
                XCTAssertNil(out["status"], "\(scriptName) falsely blocked \(c.label)")
            }
        }

        // ExtraHosts config/newline/YAML injection must be stripped across all 5 proxy platforms
        let hostileHosts = [
            "*.safe-extra.example",
            "evil.com\n[Rule]\nFINAL,DIRECT",
            "bad\"quote.com",
            "space host.com",
            "#comment.com",
            ";directive.com"
        ]
        for platform in ProxyShieldPlatform.allCases {
            let content = SurgeBrotliShieldHelper.shared.generateShieldContent(for: platform, extraHosts: hostileHosts)
            XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: content, for: platform).isCompliant)
            XCTAssertFalse(content.contains("FINAL,DIRECT"))
            XCTAssertFalse(content.contains("bad\"quote.com"))
            if platform != .loon {
                XCTAssertTrue(content.contains("*.safe-extra.example"))
            }
        }
    }

    // MARK: - 8. LockdownInstProxyClient Mismatched Cert/Key Fail-Closed Verification

    func test_r9_lockdownPairingRecord_malformedOrEmptyFields_andEnglishLocaleZeroHanAcrossNewIndicators() throws {
        WQLocale.overrideLanguageCode = "en"
        defer { WQLocale.overrideLanguageCode = nil }

        // Verify all new bilingual ThreatIndicators produced in Rounds 7-9 contain ZERO Han characters under English locale
        let sampleTexts: [String] = [
            IPAPackageScanner.makeCorruptMachOIndicator(relPath: "Frameworks/A.framework/A").description,
            {
                var inds: [ThreatIndicator] = []
                var syms: Set<String> = []
                IPAPackageScanner.appendEscapingSymlinkIndicators(escapingSymlinks: ["Link -> /etc/passwd"], allIndicators: &inds, allMatchedSymbols: &syms)
                return inds.map(\.description).joined(separator: " ")
            }(),
            {
                let details = MachOScanner.ParsedBinaryDetails(cryptid: 0, linkedDylibs: [], symbols: ["_main"], textStrings: [], isFairPlayEncrypted: false, corruptedSliceCount: 1)
                return MachOScanner.shared.scan(details: details, context: .init(bundleId: "com.en.check")).indicators.map(\.description).joined(separator: " ")
            }()
        ]
        for text in sampleTexts {
            let hasHan = text.unicodeScalars.contains { ($0.value >= 0x4E00 && $0.value <= 0x9FFF) || ($0.value >= 0x3400 && $0.value <= 0x4DBF) }
            XCTAssertFalse(hasHan, "English locale leaked CJK characters: \(text)")
        }
    }

    // MARK: - 9. Cross-TeamID & Unsigned Correlation Anti-Poisoning + Registry Apple-System Spoof Hardening

    func test_r9_correlateAndMerge_blocksCrossTeamIDAndUnsignedWhitelistPoisoning_andRegistryAppleSpoofHardening() throws {
        WhitelistEngine.shared.registerCustomTool(WhitelistedTool(
            name: "Corp Internal Rule",
            allowedBundleIds: ["com.corp.internal"],
            allowedTeamIds: ["CORPTEAM01"]
        ))

        let legitCorpReg = InstalledAppRegistryRecord(
            bundleId: "com.corp.internal",
            displayName: "CorpApp",
            version: "1.0",
            applicationType: "User",
            signerIdentity: "iPhone Distribution: Corp Inc",
            profileValidated: true,
            teamId: "CORPTEAM01",
            bundlePath: "/private/var/containers/Bundle/Application/1111/CorpApp.app"
        )

        let trojanCrossTeamPkg = ScanFinding(
            bundleId: "com.corp.internal",
            displayName: "CorpApp",
            version: "1.0",
            teamId: "EVILTEAM99",
            executablePath: "CorpApp.app/CorpApp",
            bundlePath: "/var/mobile/Documents/CorpApp_EvilTeam.ipa",
            installChannel: .enterpriseInHouse,
            riskTier: .highRisk,
            indicators: [ThreatIndicator(
                signature: "ARM64:svc#0x80:DirectSyscall",
                description: "Direct syscall",
                category: "Direct Syscall",
                location: "CorpApp",
                severity: .highRisk
            )],
            evidence: AuditEvidence(installChannel: .enterpriseInHouse, cryptid: 0)
        )

        let crossMerged = SecurityPipeline.shared.correlateAndMergeFindings(
            registryRecords: [legitCorpReg],
            packageFindings: [trojanCrossTeamPkg],
            probeFindings: [],
            includeAppStoreApps: true
        )
        XCTAssertEqual(crossMerged.correlatedCount, 0, "Mismatched non-empty Team IDs must never correlate")
        let crossPkgOut = try XCTUnwrap(crossMerged.findings.first { $0.bundlePath.contains("CorpApp_EvilTeam.ipa") })
        XCTAssertEqual(crossPkgOut.riskTier, .highRisk)
        XCTAssertFalse(crossPkgOut.isWhitelisted)

        // Unsigned/ad-hoc Trojanized package (teamId == nil) must NOT borrow registry's CORPTEAM01 to whitelist binary threats
        let trojanUnsignedPkg = ScanFinding(
            bundleId: "com.corp.internal",
            displayName: "CorpApp",
            version: "1.0",
            teamId: nil,
            executablePath: "CorpApp.app/CorpApp",
            bundlePath: "/var/mobile/Documents/CorpApp_Unsigned.ipa",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            indicators: [ThreatIndicator(
                signature: "ARM64:svc#0x80:DirectSyscall",
                description: "Direct syscall",
                category: "Direct Syscall",
                location: "CorpApp",
                severity: .highRisk
            )],
            evidence: AuditEvidence(installChannel: .developerSideloaded, cryptid: 0)
        )
        let unsignedMerged = SecurityPipeline.shared.correlateAndMergeFindings(
            registryRecords: [legitCorpReg],
            packageFindings: [trojanUnsignedPkg],
            probeFindings: [],
            includeAppStoreApps: true
        )
        let unsignedOut = try XCTUnwrap(unsignedMerged.findings.first)
        XCTAssertEqual(unsignedOut.riskTier, .highRisk, "Unsigned package must never inherit registry teamId to whitelist high-risk binary IOCs")
        XCTAssertFalse(unsignedOut.isWhitelisted)

        // Registry Apple-system spoofing: Ad Hoc signer, third-party teamId, or non-Apple appGroups must NOT be treated as Apple system apps
        let spoofAdHoc = InstalledAppRegistryRecord(
            bundleId: "com.apple.fake.daemon",
            displayName: "FakeDaemon",
            version: "1.0",
            applicationType: "System",
            signerIdentity: "Ad Hoc",
            bundlePath: "/Applications/FakeDaemon.app"
        )
        let spoofTeam = InstalledAppRegistryRecord(
            bundleId: "com.apple.fake.team",
            displayName: "FakeTeam",
            version: "1.0",
            applicationType: "System",
            teamId: "EVILTEAM99",
            bundlePath: "/Applications/FakeTeam.app"
        )
        let spoofGroups = InstalledAppRegistryRecord(
            bundleId: "com.apple.fake.groups",
            displayName: "FakeGroups",
            version: "1.0",
            applicationType: "System",
            appGroups: ["group.io.metamask"],
            bundlePath: "/Applications/FakeGroups.app"
        )
        XCTAssertFalse(InstalledAppRegistryScanner.shared.isAppleSystemOrFirstPartyApp(spoofAdHoc))
        XCTAssertFalse(InstalledAppRegistryScanner.shared.isAppleSystemOrFirstPartyApp(spoofTeam))
        XCTAssertFalse(InstalledAppRegistryScanner.shared.isAppleSystemOrFirstPartyApp(spoofGroups))

        // Capitalized UIBackgroundModes ("Audio", "VoIP") must be normalized and detected
        let capBgRec = InstalledAppRegistryRecord(
            bundleId: "com.r9.capbg",
            displayName: "CapBG",
            version: "1.0",
            applicationType: "User",
            profileValidated: true,
            teamId: "DEV1234567",
            backgroundModes: ["Audio", "VoIP"],
            bundlePath: "/var/containers/Bundle/Application/CapBG.app"
        )
        let capBgFinding = InstalledAppRegistryScanner.shared.evaluateRecord(capBgRec)
        XCTAssertTrue(capBgFinding.indicators.contains { $0.signature.contains("UIBackgroundModes") })
    }

    // MARK: - 10. Whitelist Wildcard-Only Rejection, Variation Selectors, Separated Bigrams & Extended Homoglyphs

    func test_r9_whitelistWildcardOnlyRejection_variationSelectors_separatedWordBigrams_andExtendedHomoglyphs() {
        // 1. Pure-wildcard custom rules lacking concrete identity constraints must fail closed
        for badPattern in ["*", "?", "*.*", "**"] {
            WhitelistEngine.shared.resetToDefaults()
            WhitelistEngine.shared.registerCustomTool(WhitelistedTool(
                name: "Degenerate Wildcard \(badPattern)",
                allowedBundleIds: [badPattern]
            ))
            let match = WhitelistEngine.shared.isWhitelisted(bundleId: "com.evil.trojan", appGroups: [], teamId: "EVILTEAM99")
            XCTAssertFalse(match.isWhitelisted, "Degenerate wildcard rule '\(badPattern)' must never whitelist arbitrary apps")
        }

        // Variation Selectors (U+FE0F, U+E0100) must be blocked by PatternMatcher
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.corp.*", value: "com.corp.app\u{FE0F}"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.corp.*", value: "com.corp.app\u{E0100}"))

        // 2. Separated-word wallet bigrams, IPA/Latin/Armenian/Palochka homoglyphs, Variation Selectors, Traditional Chinese & FridaGadget
        let spoofNames = [
            "Meta Mask",
            "Meta-Mask",
            "Token Pocket",
            "im Token",
            "Bit Get",
            "Te\u{04CF}egram",     // Cyrillic small palochka
            "Tele\u{0261}ram",     // IPA script g
            "B\u{0131}nance",      // Latin dotless i
            "P\u{0570}antom",      // Armenian small ho
            "Meta\u{FE0F}Mask",    // Variation Selector-16
            "Binance\u{E0100}",    // Variation Selector-17 ("Glassworm")
            "幣安",
            "歐易",
            "紙飛機"
        ]
        for spoof in spoofNames {
            let hits = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: "com.evil.clone.\(UUID().uuidString.prefix(6))",
                displayName: spoof,
                installChannel: .developerSideloaded,
                cryptid: 0
            )
            XCTAssertFalse(hits.isEmpty, "Failed to detect wallet/messenger impersonation for displayName: \(spoof)")
        }

        let fridaHits = ExpandedThreatCatalog.evaluateInjectedDylibs(
            linkedDylibs: ["@rpath/FridaGadget.dylib"]
        )
        XCTAssertFalse(fridaHits.isEmpty, "FridaGadget dylib without trailing slash must be detected")
    }

    // MARK: - 11. Firmware Rapid Security Response (a)/(b) & CLI Scan Target Routing (.tipa / .app / Mach-O / Non-Mach-O)

    func test_r9_firmwareRapidSecurityResponse_andCLIScanRoutingOnTipaAppMachOAndRegularFile() async throws {
        // 1. Apple post-GA Rapid Security Response suffixes "(a)" / "(b)" on patched iOS 27.3 must evaluate .safe
        for rsr in ["iOS 27.3 (a)", "27.3 (b)", "iPadOS 27.3 (a)"] {
            let ver = try XCTUnwrap(SystemOSVersion(string: rsr))
            XCTAssertNil(ver.prerelease, "RSR suffix '\(rsr)' must not be misparsed as an alpha/beta build")
            let report = FirmwarePostureEngine.shared.evaluate(osVersion: ver)
            XCTAssertEqual(report.exposedCount, 0, "Patched RSR '\(rsr)' must report 0 exposed CVEs")
            XCTAssertEqual(report.overallRiskTier, .safe)
        }
        // Genuine compact alpha/beta strings ("27.3a", "27.3-beta1") must still be flagged as pre-release
        let alphaVer = try XCTUnwrap(SystemOSVersion(string: "27.3a"))
        XCTAssertNotNil(alphaVer.prerelease)
        let alphaReport = FirmwarePostureEngine.shared.evaluate(osVersion: alphaVer)
        XCTAssertGreaterThan(alphaReport.exposedCount, 0)

        // 2. Build a standalone ARM64 Mach-O with svc #0x80, an .app bundle, and a .tipa archive; verify CLI `scan` returns exit 1 (HIGH_RISK)!
        let svcBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [0xD400_1001, 0xD65F_03C0]
        ))

        // 2a. Standalone Mach-O binary
        let machoURL = makeTempFile("evil_standalone_macho")
        try svcBin.write(to: machoURL)
        let machoCLI = try await runCLIInProcess(["scan", machoURL.path, "--format", "json"])
        XCTAssertEqual(machoCLI.code, 1, "CLI scan on malicious standalone Mach-O must return exit code 1 (HIGH_RISK), not Container clean")
        XCTAssertTrue(machoCLI.out.contains("arm64:svc_0x80"))

        // 2b. .app directory bundle on disk
        let appDir = makeTempFile("EvilBundle.app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        let appPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r9.cli.app",
            "CFBundleExecutable": "EvilExec",
            "CFBundleShortVersionString": "1.0"
        ], format: .xml, options: 0)
        try appPlist.write(to: appDir.appendingPathComponent("Info.plist"))
        try svcBin.write(to: appDir.appendingPathComponent("EvilExec"))
        let appCLI = try await runCLIInProcess(["scan", appDir.path, "--format", "json"])
        XCTAssertEqual(appCLI.code, 1, "CLI scan on malicious .app bundle must return exit code 1 (HIGH_RISK)")

        // 2c. .tipa TrollStore archive (using /usr/bin/zip on macOS)
        let stageDir = makeTempFile("tipa_stage")
        let payloadApp = stageDir.appendingPathComponent("Payload/EvilBundle.app")
        try FileManager.default.createDirectory(at: payloadApp, withIntermediateDirectories: true)
        try appPlist.write(to: payloadApp.appendingPathComponent("Info.plist"))
        try svcBin.write(to: payloadApp.appendingPathComponent("EvilExec"))
        let tipaURL = makeTempFile("EvilTroll.tipa")
        let zipProc = Process()
        zipProc.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        zipProc.currentDirectoryURL = stageDir
        zipProc.arguments = ["-qr", tipaURL.path, "Payload"]
        try zipProc.run()
        zipProc.waitUntilExit()
        XCTAssertEqual(zipProc.terminationStatus, 0)

        let tipaCLI = try await runCLIInProcess(["scan", tipaURL.path, "--format", "json"])
        XCTAssertEqual(tipaCLI.code, 1, "CLI scan on malicious .tipa archive must route to IPAPackageScanner and return exit code 1")

        // 2d. Non-Mach-O regular file (.txt) passed to `scan` must fail closed with exit code 2 (never `[SAFE] Container clean.`)
        let txtURL = makeTempFile("not_a_container.txt")
        try Data("plain text file".utf8).write(to: txtURL)
        let txtCLI = try await runCLIInProcess(["scan", txtURL.path])
        XCTAssertEqual(txtCLI.code, 2, "Non-Mach-O regular file passed to `scan` must fail closed with exit code 2")
        XCTAssertFalse(txtCLI.out.contains("Container clean"))
    }

    // MARK: - 12. Brotli Shield Header Whitespace / RFC 9842 `dcb` / Negative-Wildcard Kill-Switch & Glassworm Sanitization

    func test_r9_brotliShieldWhitespaceHeader_dcbEncoding_negativeWildcardKillSwitch_andGlasswormEscaping() throws {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let standaloneJS = try String(contentsOf: repoRoot.appendingPathComponent("Shields/scripts/brotli-guard.js"), encoding: .utf8)

        func evalJS(_ headers: [String: Any]) -> [String: Any]? {
            guard let ctx = JSContext() else { return nil }
            var captured: [String: Any]?
            let doneBlock: @convention(block) (JSValue) -> Void = { val in
                captured = val.toDictionary() as? [String: Any]
            }
            ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
            ctx.setObject(["headers": headers], forKeyedSubscript: "$response" as NSString)
            _ = ctx.evaluateScript(standaloneJS)
            return captured
        }

        for (desc, hdrs) in [
            ("Trailing space Content-Encoding ", ["Content-Encoding ": "br"]),
            ("Tab-padded Transfer-Encoding", ["\ttransfer-encoding ": "br"]),
            ("RFC 9842 Dictionary-Compressed Brotli dcb", ["Content-Encoding": "dcb"]),
            ("Comma-separated gzip, dcb", ["content-encoding": "gzip, \"dcb\""])
        ] as [(String, [String: Any])] {
            let res = try XCTUnwrap(evalJS(hdrs))
            XCTAssertEqual(res["status"] as? Int, 403, "brotli-guard.js failed to block \(desc)")
        }
        let safeCustom = try XCTUnwrap(evalJS(["Content-Encoding": "dcb-custom-safe"]))
        XCTAssertNil(safeCustom["status"])

        // Negative-wildcard MITM exclusion ("-*", "-*.evil.org") in extraHosts must be stripped and rejected by validateShield
        for platform in ProxyShieldPlatform.allCases {
            let generated = SurgeBrotliShieldHelper.shared.generateShieldContent(for: platform, extraHosts: ["-*", "-*.evil.org", "*.good.example"])
            XCTAssertNil(generated.range(of: #"(?:^|[\s,='"])-\*(?:$|[\s,'"])"#, options: .regularExpression),
                         "Platform \(platform) leaked negative-wildcard MITM kill-switch")
            XCTAssertFalse(generated.contains("-*.evil.org"), "Platform \(platform) accepted unauthorized negative exclusion")
            XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: generated, for: platform).isCompliant)
        }
        let tamperedSurge = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .surge) + "\nhostname = %APPEND% -*\n"
        XCTAssertFalse(SurgeBrotliShieldHelper.shared.validateShield(content: tamperedSurge, for: .surge).isCompliant)

        // ReportGenerator.plain must neutralize U+00AD, U+180E, U+206F, U+FE0F, and Glassworm U+E0100
        let hostileText = "App\u{00AD}Name\u{180E}\u{206F}\u{FE0F}\u{E0100}"
        let sanitized = ReportGenerator.shared.plain(hostileText)
        for forbidden: UInt32 in [0x00AD, 0x180E, 0x206F, 0xFE0F, 0xE0100] {
            XCTAssertFalse(sanitized.unicodeScalars.contains { $0.value == forbidden },
                           "ReportGenerator.plain failed to neutralize scalar U+\(String(forbidden, radix: 16, uppercase: true))")
        }
    }

    // MARK: - 13. LockdownInstProxyClient Kernel Socketpair Protocol: STARTTLS Downgrade Block, Session Reject & Frame Cap

    func test_r9_lockdownInstProxySocketpairProtocol_starttlsDowngradeBlocked_sessionRejected_andOversizedFrameRejected() throws {
        let pairing = LockdownPairingFile(
            hostID: "11112222-3333-4444-5555-666677778888",
            systemBUID: "AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111",
            hostCertificateDER: Data([0x30, 0x03, 0x02, 0x01, 0x01]),
            hostPrivateKeyDER: Data([0x30, 0x03, 0x02, 0x01, 0x02])
        )

        // 1. STARTTLS downgrade attack (EnableSessionSSL = false) must fail closed with LockdownClientError.protocolError
        do {
            var sv: [Int32] = [-1, -1]
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv), 0)
            let clientFD = sv[0]
            let serverFD = sv[1]
            let peerDone = expectation(description: "Mock lockdownd downgrade peer")
            var receivedPlaintextStartService = false

            DispatchQueue.global(qos: .userInitiated).async {
                defer {
                    Darwin.close(serverFD)
                    peerDone.fulfill()
                }
                guard let q = try? LockdownInstProxyClient.readPlistPacket(fromFD: serverFD),
                      (q["Request"] as? String) == "QueryType" else { return }
                try? LockdownInstProxyClient.writePlistPacket(["Request": "QueryType", "Type": "com.apple.mobile.lockdown"], toFD: serverFD)

                guard let s = try? LockdownInstProxyClient.readPlistPacket(fromFD: serverFD),
                      (s["Request"] as? String) == "StartSession" else { return }
                // Rogue MITM attempts STARTTLS strip: EnableSessionSSL = false!
                try? LockdownInstProxyClient.writePlistPacket(["Request": "StartSession", "SessionID": "MITM-1", "EnableSessionSSL": false], toFD: serverFD)

                if let next = try? LockdownInstProxyClient.readPlistPacket(fromFD: serverFD),
                   (next["Request"] as? String) == "StartService" {
                    receivedPlaintextStartService = true
                }
            }

            XCTAssertThrowsError(
                try LockdownInstProxyClient.shared.negotiateInstallationProxyPort(
                    rawSocketFD: clientFD,
                    pairing: pairing,
                    tlsOptions: nil
                )
            ) { err in
                guard case LockdownClientError.protocolError = err else {
                    XCTFail("Expected protocolError on EnableSessionSSL=false downgrade, got \(err)")
                    return
                }
            }
            wait(for: [peerDone], timeout: 3.0)
            XCTAssertFalse(receivedPlaintextStartService, "LockdownInstProxyClient must NEVER send StartService in plaintext when EnableSessionSSL=false")
        }

        // 2. StartSession returning Error = "InvalidHostID" must throw LockdownClientError.sessionRejected("InvalidHostID")
        do {
            var sv: [Int32] = [-1, -1]
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv), 0)
            let clientFD = sv[0]
            let serverFD = sv[1]
            DispatchQueue.global(qos: .userInitiated).async {
                defer { Darwin.close(serverFD) }
                _ = try? LockdownInstProxyClient.readPlistPacket(fromFD: serverFD)
                try? LockdownInstProxyClient.writePlistPacket(["Type": "com.apple.mobile.lockdown"], toFD: serverFD)
                _ = try? LockdownInstProxyClient.readPlistPacket(fromFD: serverFD)
                try? LockdownInstProxyClient.writePlistPacket(["Error": "InvalidHostID"], toFD: serverFD)
            }
            XCTAssertThrowsError(
                try LockdownInstProxyClient.shared.negotiateInstallationProxyPort(
                    rawSocketFD: clientFD,
                    pairing: pairing,
                    tlsOptions: nil
                )
            ) { err in
                XCTAssertEqual(err as? LockdownClientError, .sessionRejected("InvalidHostID"))
            }
        }

        // 3. Oversized 2 GB packet header (0x7FFFFFFF > 64 MB cap) must be rejected immediately without OOM
        do {
            var sv: [Int32] = [-1, -1]
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv), 0)
            let rfd = sv[0]
            let wfd = sv[1]
            defer { Darwin.close(rfd); Darwin.close(wfd) }
            var hugeBE = UInt32(0x7FFF_FFFF).bigEndian
            _ = Darwin.send(wfd, &hugeBE, 4, 0)
            XCTAssertThrowsError(try LockdownInstProxyClient.readPlistPacket(fromFD: rfd)) { err in
                guard case LockdownClientError.protocolError = err else {
                    XCTFail("Expected protocolError on oversized Lockdown frame, got \(err)")
                    return
                }
            }
        }

        // 4. Duplicate bundleId records in Browse stream: riskiest record must win over preceding benign decoy
        let benignDecoy = InstalledAppRegistryRecord(bundleId: "com.dup.target", displayName: "Benign", version: "1.0", hasAppStoreMetadata: true)
        let evilReal = InstalledAppRegistryRecord(
            bundleId: "com.dup.target",
            displayName: "Evil",
            version: "1.0",
            profileValidated: true,
            booleanEntitlements: ["com.apple.private.security.no-sandbox": true],
            allEntitlementKeys: ["com.apple.private.security.no-sandbox"]
        )
        let deduped = InstalledAppRegistryScanner.shared.deduplicate([benignDecoy, evilReal])
        XCTAssertEqual(deduped.count, 1)
        XCTAssertEqual(deduped.first?.booleanEntitlements["com.apple.private.security.no-sandbox"], true)
    }
}
