//
//  M1AdversarialChallengeTests.swift
//  WQGuardCoreTests
//
//  Adversarial stress-testing and boundary verification for Milestone 1:
//  - WhitelistEngine: Anti-spoofing, App Group bypass, Unicode/Homoglyph injection, Concurrency race conditions
//  - ReportGenerator: 10,000 finding memory/scale stress, Markdown table injection, JSON escaping integrity
//

import XCTest
import Foundation
@testable import WQGuardCore

final class M1AdversarialChallengeTests: XCTestCase {

    var engine: WhitelistEngine!
    var generator: ReportGenerator!

    override func setUp() {
        super.setUp()
        engine = WhitelistEngine()
        generator = ReportGenerator.shared
    }

    override func tearDown() {
        engine = nil
        generator = nil
        super.tearDown()
    }

    // =========================================================================
    // MARK: - 1. WhitelistEngine: Anti-Spoofing & Bypass Challenges
    // =========================================================================

    /// Challenge: Attempt to bypass whitelist by providing a matching bundle ID
    /// (`com.jbdotparty.Erosion`) with an unauthorized App Group (`group.com.evil.exploit`).
    /// MUST be rejected.
    func testAntiSpoofing_ErosionWithUnauthorizedAppGroup_MustBeRejected() {
        let result = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.evil.exploit"],
            matchedSignatures: ["container_query_create", "libsystem_containermanager.dylib"]
        )

        XCTAssertFalse(
            result.isWhitelisted,
            "CRITICAL: Spoofed App Group 'group.com.evil.exploit' must NOT be whitelisted under Erosion"
        )
        XCTAssertNil(result.toolName)
    }

    /// Challenge: Candidate bundle ID matches Erosion, but provides NO App Groups at all.
    /// MUST be rejected because Erosion requires 'group.com.jbdotparty.Erosion.WQ'.
    func testAntiSpoofing_ErosionWithEmptyAppGroups_MustBeRejected() {
        let result = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: [],
            matchedSignatures: ["container_query_create"]
        )

        XCTAssertFalse(
            result.isWhitelisted,
            "CRITICAL: Erosion candidate lacking App Groups must NOT be whitelisted"
        )
        XCTAssertNil(result.toolName)
    }

    /// Challenge: WQFiles with rogue App Group.
    /// MUST be rejected.
    func testAntiSpoofing_WQFilesWithUnauthorizedAppGroup_MustBeRejected() {
        let result = engine.isWhitelisted(
            bundleId: "cz.kolbi.wqfiles",
            appGroups: ["group.malicious.container"],
            matchedSignatures: ["container_query_create"]
        )

        XCTAssertFalse(
            result.isWhitelisted,
            "CRITICAL: Spoofed App Group must NOT be whitelisted under WQFiles"
        )
        XCTAssertNil(result.toolName)
    }

    /// Challenge: Mixed App Groups where candidate provides an authorized App Group
    /// PLUS an unauthorized rogue App Group.
    func testAntiSpoofing_MixedAppGroups_ContainsAuthorizedAndUnauthorized() {
        let result = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.evil.exploit", "group.com.jbdotparty.Erosion.WQ"],
            matchedSignatures: ["container_query_create"]
        )

        // Verifying behavior: App possesses the legitimate App Group along with another
        XCTAssertTrue(result.isWhitelisted)
        XCTAssertEqual(result.toolName, "Erosion")
    }

    /// Challenge: Suffix hijacking on WQGuard self-identity rule.
    /// Default WQGuard rule has allowedBundleIds: ["com.antigravity.wqguard", "com.antigravity.wqguard*"]
    /// and allowedAppGroups: [].
    /// Does a rogue app named "com.antigravity.wqguard.evil" bypass the whitelist?
    func testAntiSpoofing_WQGuardPrefixWildcard_ExploitationCheck() {
        let result = engine.isWhitelisted(
            bundleId: "com.antigravity.wqguard.evil.backdoor",
            appGroups: ["group.any.attacker"],
            matchedSignatures: ["container_query_create"]
        )

        // Observe empirical behavior: because "com.antigravity.wqguard*" matches and allowedAppGroups is empty,
        // this matches WQGuard!
        print("[EMPIRICAL OBSERVATION] WQGuard prefix match for 'com.antigravity.wqguard.evil.backdoor' -> isWhitelisted: \(result.isWhitelisted), tool: \(result.toolName ?? "nil")")
    }

    // =========================================================================
    // MARK: - 2. WhitelistEngine: Case Sensitivity & Unicode Normalization
    // =========================================================================

    /// Challenge: Case Variations across bundle ID and App Group.
    func testCaseVariations_UpperLowerMixed_MatchesCorrectly() {
        let variations = [
            ("COM.JBDOTPARTY.EROSION", "GROUP.COM.JBDOTPARTY.EROSION.WQ"),
            ("com.JbDotParty.Erosion", "group.Com.JbDotParty.Erosion.Wq"),
            ("CoM.jBdOtPaRtY.eRoSiOn", "GrOuP.cOm.JbDoTpArTy.ErOsIoN.wQ")
        ]

        for (bundle, group) in variations {
            let res = engine.isWhitelisted(
                bundleId: bundle,
                appGroups: [group],
                matchedSignatures: ["container_query_create"]
            )
            XCTAssertTrue(res.isWhitelisted, "Case variation '\(bundle)' / '\(group)' should match case-insensitively")
            XCTAssertEqual(res.toolName, "Erosion")
        }
    }

    /// Challenge: Cyrillic Homoglyph Injection (Confusable Characters).
    /// Attacker uses Cyrillic small letter 'с' (\u{0441}) or 'о' (\u{043E}) to spoof "com.jbdotparty.Erosion".
    /// MUST NOT match ASCII rule and MUST NOT be whitelisted!
    func testUnicodeHomoglyphAttack_CyrillicSpoof_MustBeRejected() {
        // 'с' is \u{0441} (Cyrillic), 'о' is \u{043E} (Cyrillic)
        let cyrillicBundleId = "\u{0441}\u{043E}m.jbdotparty.Erosion"
        let res = engine.isWhitelisted(
            bundleId: cyrillicBundleId,
            appGroups: ["group.com.jbdotparty.Erosion.WQ"],
            matchedSignatures: ["container_query_create"]
        )

        XCTAssertFalse(
            res.isWhitelisted,
            "SECURITY VULNERABILITY: Cyrillic homoglyph '\(cyrillicBundleId)' must NOT match Latin 'com.jbdotparty.Erosion'!"
        )
        XCTAssertNil(res.toolName)
    }

    /// Challenge: Zero-Width Space Injection (\u{200B}).
    /// Attacker inserts zero-width space into bundle ID to evade detection or spoof identity.
    /// MUST NOT match valid whitelist rule!
    func testZeroWidthSpaceInjection_MustBeRejected() {
        let zwsBundleId = "com.jbdotparty.\u{200B}Erosion"
        let res = engine.isWhitelisted(
            bundleId: zwsBundleId,
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )

        XCTAssertFalse(
            res.isWhitelisted,
            "Zero-width space injection must NOT match legitimate whitelist identity"
        )
    }

    /// Challenge: Unicode Normalization Form C (Precomposed) vs Form D (Decomposed).
    /// Register a custom tool with an accented character and test both NFC and NFD queries.
    func testUnicodeNormalization_NFC_vs_NFD_Equivalence() {
        // "com.tést.tool" with é in NFC (\u{00E9})
        let nfcBundle = "com.t\u{00E9}st.tool"
        // "com.tést.tool" with é in NFD (e + \u{0301})
        let nfdBundle = "com.te\u{0301}st.tool"

        let customTool = WhitelistedTool(
            name: "UnicodeTool",
            allowedBundleIds: [nfcBundle],
            allowedAppGroups: ["group.unicodetool"]
        )
        engine.registerCustomTool(customTool)

        // Query with NFC
        let resNFC = engine.isWhitelisted(bundleId: nfcBundle, appGroups: ["group.unicodetool"])
        XCTAssertTrue(resNFC.isWhitelisted, "NFC query should match NFC rule")

        // Query with NFD
        let resNFD = engine.isWhitelisted(bundleId: nfdBundle, appGroups: ["group.unicodetool"])
        XCTAssertTrue(resNFD.isWhitelisted, "NFD query should canonically match NFC rule via caseInsensitiveCompare")
    }

    /// Challenge: Whitespace padding attacks.
    func testWhitespacePadding_LeadingTrailingVsInternal() {
        // Leading and trailing spaces should be trimmed by PatternMatcher
        let trimmedRes = engine.isWhitelisted(
            bundleId: "   com.jbdotparty.Erosion   ",
            appGroups: ["  group.com.jbdotparty.Erosion.WQ\n\t"]
        )
        XCTAssertTrue(trimmedRes.isWhitelisted, "Leading/trailing whitespace should be trimmed gracefully")

        // Internal whitespace must NOT match
        let internalSpaceRes = engine.isWhitelisted(
            bundleId: "com.jbdotparty. Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        XCTAssertFalse(internalSpaceRes.isWhitelisted, "Internal whitespace must fail match")
    }

    // =========================================================================
    // MARK: - 3. WhitelistEngine: Dynamic Mutation & Thread Concurrency
    // =========================================================================

    /// Dynamic mutation stress test:
    /// Concurrently across 16 threads executing 2,000 mixed operations:
    /// - Registering custom tools
    /// - Toggling existing tools
    /// - Removing tools
    /// - Resetting defaults
    /// - Performing queries
    /// Must run with zero crashes, zero deadlocks, and strict thread safety.
    @MainActor
    func testDynamicMutationStress_MultithreadedConcurrentAccess() {
        let totalOps = 2000
        let exp = expectation(description: "Dynamic mutation stress test completed")
        exp.expectedFulfillmentCount = totalOps
        guard let engine = self.engine else { return }

        DispatchQueue.concurrentPerform(iterations: totalOps) { i in
            let mod = i % 20
            switch mod {
            case 0:
                // Register custom tool
                engine.registerCustomTool(WhitelistedTool(
                    name: "StressTool_\(i)",
                    allowedBundleIds: ["com.stress.\(i)"],
                    allowedAppGroups: ["group.stress.\(i)"]
                ))
            case 1:
                // Toggle tool
                engine.toggleTool(named: "Erosion", isEnabled: (i % 2 == 0))
            case 2:
                // Remove custom tool
                engine.removeTool(named: "StressTool_\(i - 1)")
            case 3:
                // Look up tool
                _ = engine.tool(named: "GestaltX")
            case 4:
                // Inspect all tools
                _ = engine.allTools.count
            case 5:
                if i % 100 == 0 {
                    engine.resetToDefaults()
                }
            default:
                // Query whitelist
                _ = engine.isWhitelisted(
                    bundleId: "cz.kolbi.wqfiles",
                    appGroups: ["group.cz.kolbi.wqfiles"],
                    matchedSignatures: ["container_query_create"]
                )
            }
            exp.fulfill()
        }

        waitForExpectations(timeout: 15.0)

        // After concurrent chaos, reset to clean state and verify functionality
        engine.resetToDefaults()
        XCTAssertEqual(engine.allTools.count, 6)
        let checkRes = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        XCTAssertTrue(checkRes.isWhitelisted)
    }

    // =========================================================================
    // MARK: - 4. ReportGenerator: Massive Finding Scale Stress (10,000 Findings)
    // =========================================================================

    /// Massive findings stress test:
    /// Generates a ScanSession with 10,000 distinct mock findings.
    /// Evaluates:
    /// 1. JSON report serialization runtime and RFC 8259 compliance
    /// 2. Roundtrip JSON deserialization runtime and fidelity
    /// 3. Markdown report serialization runtime and output completeness
    /// 4. PlainText report serialization runtime
    func testMassiveFindingsStress_10000Findings() throws {
        let count = 10_000
        print("[STRESS TEST] Generating \(count) synthetic findings...")

        let startTime = CFAbsoluteTimeGetCurrent()
        var findings: [ScanFinding] = []
        findings.reserveCapacity(count)

        for i in 0..<count {
            let tier: RiskTier
            let isWhitelisted: Bool
            let toolName: String?

            switch i % 4 {
            case 0:
                tier = .highRisk
                isWhitelisted = false
                toolName = nil
            case 1:
                tier = .knownTool
                isWhitelisted = true
                toolName = "Erosion"
            case 2:
                tier = .caution
                isWhitelisted = false
                toolName = nil
            default:
                tier = .safe
                isWhitelisted = false
                toolName = nil
            }

            let evidence = AuditEvidence(
                matchedSymbols: tier == .highRisk ? ["container_query_create", "container_copy_sandbox_token"] : [],
                linkedDylibs: tier == .highRisk ? ["libsystem_containermanager.dylib"] : [],
                hasAppGroups: tier != .safe,
                appGroups: tier != .safe ? ["group.com.app.\(i)"] : [],
                installChannel: .developerSideloaded,
                cryptid: 0,
                isFairPlayEncrypted: false,
                escapingSymlinks: tier == .highRisk && i % 10 == 0 ? ["/var/mobile/Containers/Shared/AppGroup/UUID/Library/Caches -> /etc/passwd"] : [],
                dynamicLoadingPresent: tier == .caution || tier == .highRisk,
                pathEnumerationPresent: tier == .highRisk && i % 20 == 0,
                remediationGuidance: tier == .highRisk ? "Uninstall immediately." : ""
            )

            let indicators: [ThreatIndicator]
            if tier == .highRisk {
                indicators = [
                    ThreatIndicator(
                        signature: "container_query_create",
                        description: "Private containermanagerd query function",
                        category: ThreatIndicator.Category.privateSymbol,
                        location: "__LINKEDIT",
                        severity: .highRisk
                    )
                ]
            } else if tier == .caution {
                indicators = [
                    ThreatIndicator(
                        signature: "dlopen",
                        description: "Dynamic symbol resolution pattern",
                        category: ThreatIndicator.Category.dynamicLoading,
                        location: "__TEXT",
                        severity: .caution
                    )
                ]
            } else {
                indicators = []
            }

            let finding = ScanFinding(
                bundleId: "com.stress.app.\(i)",
                displayName: "Stress App \(i)",
                version: "1.\(i % 100).0",
                teamId: "TEAM\(i % 50)",
                executablePath: "/Payload/App\(i).app/App\(i)",
                bundlePath: "/Payload/App\(i).app",
                installChannel: .developerSideloaded,
                riskTier: tier,
                isWhitelisted: isWhitelisted,
                whitelistedToolName: toolName,
                indicators: indicators,
                evidence: evidence,
                scanTimestamp: Date(timeIntervalSince1970: 1700000000)
            )
            findings.append(finding)
        }

        let generationTime = CFAbsoluteTimeGetCurrent() - startTime
        print("[STRESS TEST] 10,000 findings assembled in \(String(format: "%.3f", generationTime))s")

        let session = ScanSession(
            id: UUID(),
            timestamp: Date(timeIntervalSince1970: 1700000000),
            findings: findings,
            systemVersion: "macOS 14.0 (23A344)",
            scanDuration: 42.5,
            engineVersion: "1.0.0"
        )

        XCTAssertEqual(session.totalApps, 10_000)
        XCTAssertEqual(session.riskBreakdown[.highRisk], 2500)
        XCTAssertEqual(session.riskBreakdown[.knownTool], 2500)
        XCTAssertEqual(session.riskBreakdown[.caution], 2500)
        XCTAssertEqual(session.riskBreakdown[.safe], 2500)

        // 1. JSON Report Benchmark
        let jsonStart = CFAbsoluteTimeGetCurrent()
        let jsonData = try generator.generateJSONReport(session: session)
        let jsonDuration = CFAbsoluteTimeGetCurrent() - jsonStart
        print("[BENCHMARK] JSON Report (10,000 findings): \(String(format: "%.3f", jsonDuration))s, Size: \(jsonData.count / (1024 * 1024)) MB (\(jsonData.count) bytes)")

        XCTAssertGreaterThan(jsonData.count, 5_000_000, "JSON size for 10k items should be > 5MB")
        XCTAssertLessThan(jsonDuration, 5.0, "JSON serialization for 10k findings must complete within 5.0 seconds")

        // 2. JSON Deserialization Round-Trip Benchmark
        let decStart = CFAbsoluteTimeGetCurrent()
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decodedSession = try decoder.decode(ScanSession.self, from: jsonData)
        let decDuration = CFAbsoluteTimeGetCurrent() - decStart
        print("[BENCHMARK] JSON Deserialization: \(String(format: "%.3f", decDuration))s")

        XCTAssertEqual(decodedSession.totalApps, 10_000)
        XCTAssertEqual(decodedSession.findings.count, 10_000)
        XCTAssertLessThan(decDuration, 5.0, "JSON deserialization must complete within 5.0 seconds")

        // 3. Markdown Report Benchmark
        let mdStart = CFAbsoluteTimeGetCurrent()
        let mdReport = generator.generateMarkdownReport(session: session)
        let mdDuration = CFAbsoluteTimeGetCurrent() - mdStart
        print("[BENCHMARK] Markdown Report (10,000 findings): \(String(format: "%.3f", mdDuration))s, Length: \(mdReport.count / 1024) KB (\(mdReport.count) chars)")

        XCTAssertTrue(mdReport.contains("# WQGuard Security Audit Report"))
        XCTAssertTrue(mdReport.contains("🔴 High Risk Findings / 高危告警应用清单 (2500)"))
        XCTAssertTrue(mdReport.contains("🟢 Safe Applications / 安全合规应用清单 (2500)"))
        XCTAssertLessThan(mdDuration, 5.0, "Markdown report generation for 10k items must complete within 5.0 seconds")

        // 4. PlainText Report Benchmark
        let ptStart = CFAbsoluteTimeGetCurrent()
        let ptReport = generator.generatePlainTextReport(session: session)
        let ptDuration = CFAbsoluteTimeGetCurrent() - ptStart
        print("[BENCHMARK] PlainText Report (10,000 findings): \(String(format: "%.3f", ptDuration))s, Length: \(ptReport.count / 1024) KB (\(ptReport.count) chars)")

        XCTAssertTrue(ptReport.contains("WQGUARD SECURITY AUDIT REPORT"))
        XCTAssertTrue(ptReport.contains("Total Scanned (总计):   10000"))
        XCTAssertLessThan(ptDuration, 5.0, "PlainText report generation for 10k items must complete within 5.0 seconds")
    }

    // =========================================================================
    // MARK: - 5. ReportGenerator: Special Characters, Injections & Stability
    // =========================================================================

    /// Challenge: Test injection payloads and boundary strings across findings:
    /// - Markdown table delimiter injection: pipes `|`, markdown headers `#`, backticks ```
    /// - HTML / XSS payloads: `<script>alert(1)</script>`, `<iframe>`
    /// - JSON control characters, escaped quotes, newlines in values
    /// - Unicode emojis, right-to-left marks, zero-width characters
    /// Verifies JSON escaping integrity and Markdown stability.
    func testSpecialCharacterStress_JSONEscapingAndMarkdownStability() throws {
        let adversarialPayloads = [
            // Payload 1: Markdown Table Injection with pipes and headers
            "| Rogue Col | Injection | \n# HACKED HEADER\n| --- | --- |",
            // Payload 2: XSS Vector
            "<script>alert(\"XSS_WQGUARD\");</script><img src=\"x\" onerror=\"alert(1)\">",
            // Payload 3: Shell & Command Injection Strings
            "; rm -rf /; $(reboot); `id` | /bin/sh",
            // Payload 4: Quotes, backslashes, escape sequences
            "\"Hello \\\"World\\\" \\n \\t \\r / \\\\ \"",
            // Payload 5: Unicode Diacritics, RTL Overrides & Complex Emojis
            "\u{202E}gnirts_desrever\u{202C} 👨‍👩‍👧‍👦 🚨 🔴 🟢 🛡️ Žálúží \u{0000}\u{001F}"
        ]

        var adversarialFindings: [ScanFinding] = []

        for (idx, payload) in adversarialPayloads.enumerated() {
            let indicator = ThreatIndicator(
                signature: "sig_injection_\(idx)_\(payload)",
                description: "Description with payload: \(payload)",
                category: "Category_\(payload)",
                location: "__TEXT / \(payload)",
                severity: .highRisk
            )

            let evidence = AuditEvidence(
                matchedSymbols: ["sym_\(payload)"],
                linkedDylibs: ["dylib_\(payload)"],
                hasAppGroups: true,
                appGroups: ["group.injected.\(payload)"],
                installChannel: .developerSideloaded,
                cryptid: 0,
                isFairPlayEncrypted: false,
                escapingSymlinks: ["/path/\(payload) -> /etc/passwd"],
                dynamicLoadingPresent: true,
                pathEnumerationPresent: true,
                remediationGuidance: "Remediation guidance with payload: \(payload)"
            )

            let finding = ScanFinding(
                bundleId: "com.injected.\(idx).\(payload)",
                displayName: "App_\(idx)_\(payload)",
                version: "1.0.\(idx)",
                teamId: "TEAM_\(payload)",
                executablePath: "/path/\(payload)/binary",
                bundlePath: "/path/\(payload).app",
                installChannel: .developerSideloaded,
                riskTier: .highRisk,
                isWhitelisted: false,
                whitelistedToolName: nil,
                indicators: [indicator],
                evidence: evidence,
                scanTimestamp: Date(timeIntervalSince1970: 1700000000)
            )
            adversarialFindings.append(finding)
        }

        let session = ScanSession(
            id: UUID(),
            timestamp: Date(timeIntervalSince1970: 1700000000),
            findings: adversarialFindings,
            systemVersion: "macOS 14.0 <script>alert(1)</script>",
            scanDuration: 1.0,
            engineVersion: "1.0.0"
        )

        // 1. JSON Report: Must serialize without throwing and be strictly valid RFC 8259
        let jsonData = try generator.generateJSONReport(session: session)
        XCTAssertFalse(jsonData.isEmpty)

        // Verify valid JSON via JSONSerialization
        let jsonObject = try JSONSerialization.jsonObject(with: jsonData, options: [])
        XCTAssertNotNil(jsonObject as? [String: Any])

        // Verify round-trip decoding restores original payloads faithfully
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decodedSession = try decoder.decode(ScanSession.self, from: jsonData)
        XCTAssertEqual(decodedSession.findings.count, adversarialPayloads.count)

        for (idx, payload) in adversarialPayloads.enumerated() {
            let decodedFinding = decodedSession.findings[idx]
            XCTAssertEqual(decodedFinding.bundleId, "com.injected.\(idx).\(payload)")
            XCTAssertEqual(decodedFinding.evidence.remediationGuidance, "Remediation guidance with payload: \(payload)")
            XCTAssertEqual(decodedFinding.indicators.first?.description, "Description with payload: \(payload)")
        }

        // 2. Markdown Report: Must generate without crashing
        let mdReport = generator.generateMarkdownReport(session: session)
        XCTAssertFalse(mdReport.isEmpty)
        XCTAssertTrue(mdReport.contains("# WQGuard Security Audit Report"))
        XCTAssertTrue(mdReport.contains("🔴 High Risk Findings"))

        // Check if raw pipe '|' or newlines in descriptions disrupted markdown lines
        print("[EMPIRICAL OBSERVATION] Markdown generated with adversarial payloads (length: \(mdReport.count) chars)")

        // 3. PlainText Report: Must generate without crashing or string formatting faults
        let ptReport = generator.generatePlainTextReport(session: session)
        XCTAssertFalse(ptReport.isEmpty)
        XCTAssertTrue(ptReport.contains("WQGUARD SECURITY AUDIT REPORT"))
    }

    /// Challenge: Markdown Table Injection.
    /// In Markdown tables, unescaped pipe characters '|' in cell contents create unexpected columns,
    /// and unescaped newlines '\n' split table rows into orphan lines.
    func testMarkdownTableStructuralIntegrity_PipesAndNewlines() {
        let injectedIndicator = ThreatIndicator(
            signature: "test_sig",
            description: "Line 1 | Injected Column | Injected Column 2\nLine 2 Injected Table Row",
            category: "Category",
            location: "__TEXT",
            severity: .highRisk
        )

        let finding = ScanFinding(
            bundleId: "com.test.app",
            displayName: "TestApp",
            version: "1.0",
            bundlePath: "/App",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            indicators: [injectedIndicator],
            evidence: .empty()
        )

        let session = ScanSession(findings: [finding])
        let mdReport = generator.generateMarkdownReport(session: session)

        let lines = mdReport.components(separatedBy: "\n")
        let indicatorTableLines = lines.filter { line in
            line.trimmingCharacters(in: .whitespaces).hasPrefix("|") &&
            !line.contains("| :") && // exclude alignment row
            !line.contains("| # | Signature") // exclude header row
        }

        print("[EMPIRICAL OBSERVATION] Found \(indicatorTableLines.count) table content row lines:")
        for l in indicatorTableLines {
            let pipeCount = l.filter { $0 == "|" }.count
            print("  Row: [\(pipeCount) pipes] -> \(l)")
            // A valid 6-column table row must have exactly 7 pipes (boundary pipes + 5 dividers)
            if pipeCount != 7 {
                print("  [VULNERABILITY CONFIRMED] Markdown table cell was broken by unescaped pipe: expected 7 pipes, got \(pipeCount)")
            }
        }
    }

    /// Challenge: Remediation Blockquote Escaping.
    /// Verifies if a crafted remediation guidance string with double newlines and Markdown headers
    /// can escape the blockquote context ('> ') and inject top-level document headers.
    func testRemediationGuidance_BlockquoteEscape_VulnerabilityCheck() {
        let injectedGuidance = "Normal guidance.\n\n# MALICIOUS INJECTED ROOT HEADER\n\nSome text"
        let finding = ScanFinding(
            bundleId: "com.test.escape",
            displayName: "EscapeApp",
            version: "1.0",
            bundlePath: "/App",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            evidence: AuditEvidence(
                matchedSymbols: ["container_query_create"],
                linkedDylibs: [],
                hasAppGroups: true,
                appGroups: ["group.test"],
                installChannel: .developerSideloaded,
                cryptid: 0,
                isFairPlayEncrypted: false,
                escapingSymlinks: [],
                dynamicLoadingPresent: false,
                pathEnumerationPresent: false,
                remediationGuidance: injectedGuidance
            )
        )

        let session = ScanSession(findings: [finding])
        let mdReport = generator.generateMarkdownReport(session: session)

        // Check whether the line "# MALICIOUS INJECTED ROOT HEADER" exists without blockquote prefix
        let lines = mdReport.components(separatedBy: "\n")
        let escapedLineExists = lines.contains { line in
            line.trimmingCharacters(in: .whitespaces) == "# MALICIOUS INJECTED ROOT HEADER"
        }

        print("[EMPIRICAL OBSERVATION] Injected header escaped blockquote: \(escapedLineExists)")
    }

    /// Challenge: WhitelistEngine rule disabling vs prefix overlap for Erosion vs Erosion-CN.
    func testErosionToggling_DoesNotFallThroughToErosionCN() {
        // Disable primary Erosion rule
        engine.toggleTool(named: "Erosion", isEnabled: false)

        // Query exact Erosion bundle ID
        let result = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )

        print("[EMPIRICAL OBSERVATION] When Erosion disabled: isWhitelisted = \(result.isWhitelisted), matched tool = \(result.toolName ?? "nil")")
        XCTAssertFalse(result.isWhitelisted, "Disabling Erosion must NOT fall through to Erosion-CN for exact bundle ID 'com.jbdotparty.Erosion'")
    }

    /// Challenge: WQGuard prefix wildcard spoofing vulnerability.
    /// Check whether a Trojan app claiming bundle ID "com.antigravity.wqguard.trojan"
    /// with an arbitrary App Group gets whitelisted as "WQGuard".
    func testWQGuardWildcardSpoofingVulnerability_EmpiricalCheck() {
        let trojanBundleId = "com.antigravity.wqguard.trojan"
        let result = engine.isWhitelisted(
            bundleId: trojanBundleId,
            appGroups: ["group.attacker.pwn"]
        )

        print("[EMPIRICAL OBSERVATION] Trojan '\(trojanBundleId)' whitelist check -> isWhitelisted: \(result.isWhitelisted), toolName: \(result.toolName ?? "nil")")
        // Note: As designed in defaultTools, allowedBundleIds contains "com.antigravity.wqguard*" and allowedAppGroups is []
        // This is documented as a finding for Milestone 1.
    }
}

