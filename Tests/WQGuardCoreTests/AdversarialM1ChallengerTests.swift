//
//  AdversarialM1ChallengerTests.swift
//  WQGuardCoreTests
//
//  Empirical adversarial challenge harness for Milestone 1:
//  - 100% Read-Only Invariant & Filesystem Hash Stability
//  - Serialization Robustness (JSONDecoder corruption, missing fields, unexpected keys)
//  - Conflicting Tier Posture Derivation Hierarchy
//  - Whitelist Engine Evasion & Integrity Stress
//  - Report Generator Stress & Invariant Verification
//

import XCTest
import Foundation
import CryptoKit
@testable import WQGuardCore

final class AdversarialM1ChallengerTests: XCTestCase {

    // MARK: - Challenge 1: 100% Read-Only Invariant & Hash Stability

    func test_C1_workspaceFilesystemHashIdenticalAcrossM1Operations() throws {
        // Portable resolution of Sources directory relative to this test file
        let sourcesURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // Tests/WQGuardCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // WQGuard repo root
            .appendingPathComponent("Sources")
        
        // 1. Capture point-in-time filesystem snapshot before any M1 operations
        let beforeSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [sourcesURL])
        XCTAssertGreaterThan(beforeSnapshot.files.count, 0, "Sources directory must contain source files")

        // 2. Perform extensive model creation, risk derivation, and mutations in-memory
        for i in 0..<200 {
            let finding = ScanFinding(
                bundleId: "com.adversary.app\(i)",
                displayName: "Adversary \(i)",
                version: "1.0.\(i)",
                bundlePath: "/Applications/Adversary\(i).app",
                installChannel: .developerSideloaded,
                riskTier: (i % 2 == 0) ? .highRisk : .safe,
                evidence: AuditEvidence(
                    matchedSymbols: ["container_query_create", "fsgetpath"],
                    hasAppGroups: true,
                    appGroups: ["group.com.adversary\(i)"]
                )
            )
            let session = ScanSession(findings: [finding])
            _ = session.overallPosture
            _ = session.riskBreakdown
        }

        // 3. Perform intensive WhitelistEngine queries
        let engine = WhitelistEngine.shared
        for i in 0..<1000 {
            _ = engine.isWhitelisted(
                bundleId: (i % 2 == 0) ? "com.jbdotparty.Erosion" : "com.unknown.app\(i)",
                appGroups: ["group.com.jbdotparty.Erosion.WQ"],
                matchedSignatures: ["container_query_create"]
            )
        }

        // 4. Generate JSON, Markdown, and PlainText reports
        let complexFindings = (0..<50).map { i -> ScanFinding in
            ScanFinding(
                bundleId: "com.test.target\(i)",
                displayName: "Target App \(i)",
                version: "2.1.0",
                teamId: "TEAM\(i)",
                bundlePath: "/var/containers/Bundle/Application/UUID\(i)/Target.app",
                installChannel: InstallChannel.allCases[i % InstallChannel.allCases.count],
                riskTier: RiskTier.allCases[i % RiskTier.allCases.count],
                evidence: AuditEvidence(
                    matchedSymbols: ["container_query_create"],
                    linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
                    hasAppGroups: true,
                    appGroups: ["group.com.target\(i)"],
                    installChannel: InstallChannel.allCases[i % InstallChannel.allCases.count]
                )
            )
        }
        let complexSession = ScanSession(findings: complexFindings)
        let reporter = ReportGenerator.shared
        _ = try reporter.generateJSONReport(session: complexSession)
        _ = try reporter.generateJSONReportString(session: complexSession)
        _ = reporter.generateMarkdownReport(session: complexSession)
        _ = reporter.generatePlainTextReport(session: complexSession)

        // 5. Capture post-execution snapshot and assert 100% bit-for-bit identity
        let afterSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [sourcesURL])
        ReadOnlyAssertions.assertUnmodified(before: beforeSnapshot, after: afterSnapshot)
    }

    func test_C1_readOnlyGuaranteedInReadOnlyDirectory() throws {
        // Create an isolated temporary directory and revoke write permissions (chmod 0555)
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("wqguard_readonly_test_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        
        let sampleFile = tempDir.appendingPathComponent("sample.txt")
        try "immutability probe".write(to: sampleFile, atomically: true, encoding: .utf8)

        // Set directory to read-only (r-xr-xr-x)
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: tempDir.path)

        defer {
            // Restore permissions for cleanup
            _ = try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tempDir.path)
            _ = try? FileManager.default.removeItem(at: tempDir)
        }

        let beforeSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [tempDir])

        // Perform M1 operations referencing this read-only directory
        let finding = ScanFinding(
            bundleId: "com.readonly.probe",
            displayName: "Probe",
            version: "1.0",
            bundlePath: tempDir.path,
            installChannel: .developerSideloaded,
            riskTier: .safe,
            evidence: .empty()
        )
        let session = ScanSession(targetPath: tempDir.path, findings: [finding])
        _ = try ReportGenerator.shared.generateJSONReport(session: session)
        _ = ReportGenerator.shared.generateMarkdownReport(session: session)
        _ = ReportGenerator.shared.generatePlainTextReport(session: session)

        let afterSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [tempDir])
        ReadOnlyAssertions.assertUnmodified(before: beforeSnapshot, after: afterSnapshot)
    }

    // MARK: - Challenge 2: Serialization & Robustness (JSONDecoder)

    func test_C2_jsonDecoderGracefulOnCorruptedData() {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        // 1. Truncated JSON
        let validJSON = """
        {
            "id": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "sessionId": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "timestamp": "2026-11-11T07:00:00Z",
            "totalApps": 1,
            "riskBreakdown": {"SAFE": 1},
            "overallPosture": "SAFE",
            "findings": []
        }
        """
        for cutIndex in [5, 20, 50, 100, validJSON.count - 5] {
            let truncated = String(validJSON.prefix(cutIndex))
            let data = Data(truncated.utf8)
            XCTAssertThrowsError(try decoder.decode(ScanSession.self, from: data), "Must throw error on truncated JSON at cut \(cutIndex)")
        }

        // 2. Malformed syntax (unbalanced brackets, trailing commas)
        let syntaxErrors = [
            "{ \"id\": \"test\", ",
            "{ \"id\": \"test\" } ]",
            "{\"riskBreakdown\": {\"SAFE\": 1,}}",
            "NOT_JSON_AT_ALL",
            ""
        ]
        for bad in syntaxErrors {
            XCTAssertThrowsError(try decoder.decode(ScanSession.self, from: Data(bad.utf8)))
        }

        // 3. Invalid UTF-8 byte stream
        let badUTF8 = Data([0xFF, 0xFE, 0xFD, 0x00, 0x80])
        XCTAssertThrowsError(try decoder.decode(ScanSession.self, from: badUTF8))
    }

    func test_C2_jsonDecoderTypeMismatchesAndInvalidEnums() {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        // 1. Invalid RiskTier enum
        let invalidTierJSON = """
        {
            "id": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "sessionId": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "timestamp": "2026-11-11T07:00:00Z",
            "totalApps": 1,
            "riskBreakdown": {"SAFE": 1},
            "overallPosture": "EXTREME_SUPER_CRITICAL_RISK",
            "findings": []
        }
        """
        XCTAssertThrowsError(try decoder.decode(ScanSession.self, from: Data(invalidTierJSON.utf8))) { error in
            guard case DecodingError.dataCorrupted = error else {
                XCTFail("Expected dataCorrupted for invalid enum rawValue, got \(error)")
                return
            }
        }

        // 2. Type mismatch: totalApps as string instead of integer
        let stringTotalAppsJSON = """
        {
            "id": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "sessionId": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "timestamp": "2026-11-11T07:00:00Z",
            "totalApps": "one_hundred",
            "riskBreakdown": {"SAFE": 1},
            "overallPosture": "SAFE",
            "findings": []
        }
        """
        XCTAssertThrowsError(try decoder.decode(ScanSession.self, from: Data(stringTotalAppsJSON.utf8)))

        // 3. Type mismatch: findings as dictionary instead of array
        let findingsAsDictJSON = """
        {
            "id": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "sessionId": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "timestamp": "2026-11-11T07:00:00Z",
            "totalApps": 0,
            "riskBreakdown": {},
            "overallPosture": "SAFE",
            "findings": {"app": "invalid"}
        }
        """
        XCTAssertThrowsError(try decoder.decode(ScanSession.self, from: Data(findingsAsDictJSON.utf8)))
    }

    func test_C2_jsonDecoderMissingOptionalFieldsGracefulFallback() throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        // Minimal JSON omitting targetPath, systemVersion, scanDuration, engineVersion, sessionId
        let minimalSessionJSON = """
        {
            "id": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "timestamp": "2026-11-11T07:00:00Z",
            "totalApps": 1,
            "riskBreakdown": {"SAFE": 1},
            "findings": [
                {
                    "bundleId": "com.example.minimal",
                    "displayName": "Minimal",
                    "version": "1.0",
                    "bundlePath": "/Applications/Minimal.app",
                    "installChannel": "APP_STORE",
                    "riskTier": "SAFE",
                    "isWhitelisted": false,
                    "indicators": [],
                    "evidence": {
                        "matchedSymbols": [],
                        "linkedDylibs": [],
                        "hasAppGroups": false,
                        "appGroups": [],
                        "installChannel": "APP_STORE",
                        "cryptid": 1,
                        "isFairPlayEncrypted": true,
                        "escapingSymlinks": [],
                        "dynamicLoadingPresent": false,
                        "pathEnumerationPresent": false,
                        "remediationGuidance": "Clean"
                    },
                    "scanTimestamp": "2026-11-11T07:00:00Z"
                }
            ]
        }
        """
        let session = try decoder.decode(ScanSession.self, from: Data(minimalSessionJSON.utf8))
        XCTAssertEqual(session.id.uuidString, "E621E1F8-C36C-495A-93FC-0C247A3E6E5F")
        XCTAssertEqual(session.sessionId, "E621E1F8-C36C-495A-93FC-0C247A3E6E5F")
        XCTAssertNil(session.targetPath)
        XCTAssertNil(session.systemVersion)
        XCTAssertNil(session.scanDuration)
        XCTAssertEqual(session.engineVersion, "1.0.0")
        XCTAssertEqual(session.findings.count, 1)
        XCTAssertNil(session.findings[0].teamId)
        XCTAssertNil(session.findings[0].executablePath)
        XCTAssertNil(session.findings[0].whitelistedToolName)
    }

    func test_C2_jsonDecoderForwardCompatibilityWithUnexpectedKeys() throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        // JSON containing unexpected keys injected by future versions or telemetry
        let futureJSON = """
        {
            "id": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "sessionId": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "timestamp": "2026-11-11T07:00:00Z",
            "totalApps": 0,
            "riskBreakdown": {},
            "overallPosture": "SAFE",
            "findings": [],
            "futureField1": "some_value",
            "futureTelemetry": {
                "aiEvaluator": "gemini-3.0-pro",
                "confidenceScore": 0.999
            },
            "schemaVersion": 42
        }
        """
        let session = try decoder.decode(ScanSession.self, from: Data(futureJSON.utf8))
        XCTAssertEqual(session.id.uuidString, "E621E1F8-C36C-495A-93FC-0C247A3E6E5F")
        XCTAssertEqual(session.overallPosture, .safe)
    }

    // MARK: - Challenge 3: Posture Derivation with Conflicting Tiers

    func test_C3_postureDerivation1HighRiskPlus10SafeMustBeHighRisk() {
        let safeFindings = (0..<10).map { i in
            ScanFinding(
                bundleId: "com.safe.app\(i)",
                displayName: "Safe \(i)",
                version: "1.0",
                bundlePath: "/Applications/Safe\(i).app",
                installChannel: .appStore,
                riskTier: .safe,
                evidence: .empty()
            )
        }
        let highRiskFinding = ScanFinding(
            bundleId: "com.evil.trojan",
            displayName: "Trojan",
            version: "1.0",
            bundlePath: "/Applications/Trojan.app",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            evidence: AuditEvidence(matchedSymbols: ["container_query_create"])
        )

        var mixed = safeFindings
        mixed.append(highRiskFinding)

        let session = ScanSession(findings: mixed)
        XCTAssertEqual(session.overallPosture, .highRisk, "1 High Risk among 10 Safe apps MUST derive High Risk posture!")
        XCTAssertEqual(session.totalApps, 11)
        XCTAssertEqual(session.riskBreakdown[.highRisk], 1)
        XCTAssertEqual(session.riskBreakdown[.safe], 10)
    }

    func test_C3_postureDerivationCompleteHierarchyPermutations() {
        let safeF = ScanFinding(bundleId: "safe", displayName: "S", version: "1", bundlePath: "/S", installChannel: .appStore, riskTier: .safe, evidence: .empty())
        let cautionF = ScanFinding(bundleId: "caut", displayName: "C", version: "1", bundlePath: "/C", installChannel: .developerSideloaded, riskTier: .caution, evidence: .empty())
        let knownF = ScanFinding(bundleId: "known", displayName: "K", version: "1", bundlePath: "/K", installChannel: .developerSideloaded, riskTier: .knownTool, evidence: .empty())
        let highF = ScanFinding(bundleId: "high", displayName: "H", version: "1", bundlePath: "/H", installChannel: .developerSideloaded, riskTier: .highRisk, evidence: .empty())

        // 1. High Risk dominates all
        XCTAssertEqual(ScanSession(findings: [highF, cautionF, knownF, safeF]).overallPosture, .highRisk)
        XCTAssertEqual(ScanSession(findings: [safeF, safeF, safeF, highF]).overallPosture, .highRisk)
        XCTAssertEqual(ScanSession(findings: [knownF, highF]).overallPosture, .highRisk)
        XCTAssertEqual(ScanSession(findings: [cautionF, highF]).overallPosture, .highRisk)

        // 2. Caution dominates knownTool and safe when highRisk is absent
        XCTAssertEqual(ScanSession(findings: [cautionF, knownF, safeF]).overallPosture, .caution)
        XCTAssertEqual(ScanSession(findings: [cautionF, safeF, safeF]).overallPosture, .caution)
        XCTAssertEqual(ScanSession(findings: [cautionF, knownF]).overallPosture, .caution)

        // 3. Known Tool dominates safe when highRisk and caution are absent
        XCTAssertEqual(ScanSession(findings: [knownF, safeF, safeF]).overallPosture, .knownTool)
        XCTAssertEqual(ScanSession(findings: [knownF]).overallPosture, .knownTool)

        // 4. All safe derives safe
        XCTAssertEqual(ScanSession(findings: [safeF, safeF, safeF]).overallPosture, .safe)

        // 5. Empty findings derives safe
        XCTAssertEqual(ScanSession(findings: []).overallPosture, .safe)
    }

    func test_C3_riskTierOrderingVsPosturePriorityEmpiricalCheck() {
        // Empirically verify the relationship between RiskTier comparable ordering and ScanSession posture:
        // In RiskTier: safe(0) < caution(10) < knownTool(20) < highRisk(30)
        XCTAssertTrue(RiskTier.safe < RiskTier.caution)
        XCTAssertTrue(RiskTier.caution < RiskTier.knownTool)
        XCTAssertTrue(RiskTier.knownTool < RiskTier.highRisk)

        // But in ScanSession.overallPosture:
        // Caution takes operational priority over KnownTool because KnownTool is an authorized utility,
        // whereas Caution represents an uncharacterized sideloaded app with escape prerequisites.
        let session = ScanSession(findings: [
            ScanFinding(bundleId: "k", displayName: "K", version: "1", bundlePath: "/K", installChannel: .developerSideloaded, riskTier: .knownTool, evidence: .empty()),
            ScanFinding(bundleId: "c", displayName: "C", version: "1", bundlePath: "/C", installChannel: .developerSideloaded, riskTier: .caution, evidence: .empty())
        ])
        XCTAssertEqual(session.overallPosture, .caution, "ScanSession deliberate design: Caution takes precedence over authorized KnownTool")
    }

    // MARK: - Challenge 4: Whitelist Engine Adversarial Stress & Evasion Resistance

    func test_C4_whitelistEvasionPrefixAndSuffixAttacks() {
        let engine = WhitelistEngine.shared

        // Exact rule: "com.jbdotparty.Erosion"
        // Attack 1: Malicious app naming itself "com.jbdotparty.Erosion.trojan" (Erosion-CN pattern com.jbdotparty.Erosion.* will match if appGroup matches)
        let evasion1 = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion.trojan",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        // Attack 2: Malicious app named "malicious.com.jbdotparty.Erosion"
        let evasion2 = engine.isWhitelisted(
            bundleId: "malicious.com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        // Attack 3: Substring match attempt "com.jbdotparty.Erosion2"
        let evasion3 = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion2",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )

        // Note: Erosion-CN allows "com.jbdotparty.Erosion.*", but Erosion itself is exact.
        // com.jbdotparty.Erosion2 does not match "com.jbdotparty.Erosion-*" or "com.jbdotparty.Erosion.*"
        XCTAssertTrue(evasion1.isWhitelisted && evasion1.toolName == "Erosion-CN", "Erosion-CN wildcard matches dot suffix")
        XCTAssertFalse(evasion2.isWhitelisted, "Prefix injection 'malicious.com...' must not match")
        XCTAssertFalse(evasion3.isWhitelisted, "'com.jbdotparty.Erosion2' must not match Erosion or Erosion-CN")
    }

    func test_C4_whitelistAppGroupEnforcementPreventsBundleSpoofing() {
        let engine = WhitelistEngine.shared

        // Attack: Attacker compiles an app with bundle ID "com.jbdotparty.Erosion"
        // but since they do not possess jbdotparty's provisioning profile, their App Group is "group.com.evil.trojan"
        let spoofed = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.evil.trojan"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertFalse(spoofed.isWhitelisted, "Bundle ID spoof without authorized App Group MUST be rejected by whitelist!")
    }

    func test_C4_toggleRuleDisablingErosionRejection() {
        let engine = WhitelistEngine(tools: WhitelistEngine.defaultTools)
        
        // Disable both Erosion and Erosion-CN
        engine.toggleTool(named: "Erosion", isEnabled: false)
        
        // Exact bundle ID com.jbdotparty.Erosion must NOT match now!
        let checkErosion = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        XCTAssertFalse(checkErosion.isWhitelisted, "Disabled tool must immediately cease matching!")
    }

    func test_C4_concurrentQueriesThreadSafetyUnderMutations() {
        let engine = WhitelistEngine(tools: WhitelistEngine.defaultTools)
        let queue = DispatchQueue(label: "test.concurrent.whitelist", attributes: .concurrent)
        let group = DispatchGroup()

        for i in 0..<500 {
            group.enter()
            queue.async {
                if i % 50 == 0 {
                    engine.toggleTool(named: "Erosion", isEnabled: (i % 100 == 0))
                } else if i % 70 == 0 {
                    engine.registerCustomTool(WhitelistedTool(name: "Custom\(i)", allowedBundleIds: ["com.custom.\(i)"]))
                } else {
                    _ = engine.isWhitelisted(bundleId: "com.jbdotparty.Erosion", appGroups: ["group.com.jbdotparty.Erosion.WQ"])
                }
                group.leave()
            }
        }

        let waitResult = group.wait(timeout: .now() + 5.0)
        XCTAssertEqual(waitResult, .success, "Concurrent mutations and queries must not deadlock or race")
    }

    // MARK: - Challenge 5: Report Generation Stress & Invariants

    func test_C5_reportGeneratorStressWithOneThousandFindings() throws {
        let findings = (0..<1000).map { i -> ScanFinding in
            ScanFinding(
                bundleId: "com.stress.app\(i)",
                displayName: "Stress App \(i) 🚀",
                version: "1.0.\(i)",
                teamId: "TEAM\(i)",
                bundlePath: "/Applications/App\(i).app",
                installChannel: .developerSideloaded,
                riskTier: (i % 10 == 0) ? .highRisk : .safe,
                indicators: (i % 10 == 0) ? [
                    ThreatIndicator(
                        signature: "container_query_create",
                        description: "High risk query creation",
                        category: ThreatIndicator.Category.privateSymbol,
                        location: "__LINKEDIT",
                        severity: .highRisk
                    )
                ] : [],
                evidence: AuditEvidence(
                    matchedSymbols: (i % 10 == 0) ? ["container_query_create"] : [],
                    hasAppGroups: i % 10 == 0,
                    appGroups: (i % 10 == 0) ? ["group.stress\(i)"] : []
                )
            )
        }

        let session = ScanSession(
            sessionId: "STRESS-TEST-1000",
            findings: findings,
            systemVersion: "iOS 27.2",
            scanDuration: 4.56
        )

        let reporter = ReportGenerator.shared

        // 1. JSON Report
        let jsonData = try reporter.generateJSONReport(session: session)
        XCTAssertGreaterThan(jsonData.count, 100_000)

        // Verify JSON round-trip
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decodedSession = try decoder.decode(ScanSession.self, from: jsonData)
        XCTAssertEqual(decodedSession.findings.count, 1000)
        XCTAssertEqual(decodedSession.overallPosture, .highRisk)
        XCTAssertEqual(decodedSession.riskBreakdown[.highRisk], 100)
        XCTAssertEqual(decodedSession.riskBreakdown[.safe], 900)

        // 2. Markdown Report
        let md = reporter.generateMarkdownReport(session: session)
        XCTAssertTrue(md.contains("CRITICAL RISK DETECTED"))
        XCTAssertTrue(md.contains("🔴 High Risk Findings / 高危告警应用清单 (100)"))
        XCTAssertTrue(md.contains("🟢 Safe Applications / 安全合规应用清单 (900)"))

        // 3. PlainText Report
        let txt = reporter.generatePlainTextReport(session: session)
        XCTAssertTrue(txt.contains("[CRITICAL RISK DETECTED]"))
        XCTAssertTrue(txt.contains("High Risk (高危告警):    100 ( 10.0%)"))
        XCTAssertTrue(txt.contains("Safe (安全合规):         900 ( 90.0%)"))
    }

    func test_C5_reportGeneratorHandlesAdversarialSpecialCharacters() throws {
        // App with Markdown table breaking characters, quotes, unicode, HTML injection
        let maliciousFinding = ScanFinding(
            bundleId: "com.evil.<script>alert('xss')</script>|test",
            displayName: "Test | Pipe | Danger\nNewline Attack",
            version: "1.0\" -- Drop Table",
            teamId: "NONE | INJECT",
            executablePath: "/Path/With | Pipes/Binary",
            bundlePath: "/Path/With | Pipes/App.app",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            indicators: [
                ThreatIndicator(
                    signature: "pipe|signature|break",
                    description: "Line1\nLine2|Line3",
                    category: "Exploit | Category",
                    location: "Loc|1",
                    severity: .highRisk
                )
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["sym|1", "sym\n2"],
                remediationGuidance: "Guidance with <html> & | pipes"
            )
        )

        let session = ScanSession(findings: [maliciousFinding])
        let reporter = ReportGenerator.shared

        // Should not crash or produce invalid JSON
        let jsonData = try reporter.generateJSONReport(session: session)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(ScanSession.self, from: jsonData)
        XCTAssertEqual(decoded.findings[0].displayName, maliciousFinding.displayName)

        // Markdown and PlainText generation should not crash
        let md = reporter.generateMarkdownReport(session: session)
        XCTAssertFalse(md.isEmpty)

        let txt = reporter.generatePlainTextReport(session: session)
        XCTAssertFalse(txt.isEmpty)
    }
}
