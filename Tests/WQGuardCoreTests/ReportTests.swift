//
//  ReportTests.swift
//  WQGuardCoreTests
//
//  Unit test suite for ReportGenerator (JSON, Markdown, and PlainText).
//

import XCTest
@testable import WQGuardCore

final class ReportTests: XCTestCase {

    var generator: ReportGenerator!
    var sampleSession: ScanSession!

    override func setUp() {
        super.setUp()
        generator = ReportGenerator.shared

        // 1. High Risk Finding
        let highRiskEvidence = AuditEvidence(
            matchedSymbols: ["container_query_create", "container_copy_sandbox_token"],
            linkedDylibs: ["libsystem_containermanager.dylib"],
            hasAppGroups: true,
            appGroups: ["group.com.rogue.exploit"],
            installChannel: .developerSideloaded,
            cryptid: 0,
            isFairPlayEncrypted: false,
            escapingSymlinks: ["/var/mobile/Containers/Shared/AppGroup/UUID/Library/Caches -> /private/var/preferences"],
            dynamicLoadingPresent: true,
            pathEnumerationPresent: true,
            remediationGuidance: "Critical sandbox escape payload detected."
        )

        let highRiskFinding = ScanFinding(
            bundleId: "com.rogue.exploit",
            displayName: "Rogue Exploiter",
            version: "1.0.0",
            teamId: "ABC1234567",
            executablePath: "/private/var/containers/Bundle/Application/UUID/Rogue.app/Rogue",
            bundlePath: "/private/var/containers/Bundle/Application/UUID/Rogue.app",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(
                    signature: "container_query_create",
                    description: "Private containermanagerd query function",
                    category: ThreatIndicator.Category.privateSymbol,
                    location: "__LINKEDIT / symbol table",
                    severity: .highRisk
                ),
                ThreatIndicator(
                    signature: "escaping_symlink",
                    description: "Symlink points to /private/var/preferences",
                    category: ThreatIndicator.Category.escapingSymlink,
                    location: "Library/Caches",
                    severity: .highRisk
                )
            ],
            evidence: highRiskEvidence,
            scanTimestamp: Date(timeIntervalSince1970: 1700000000)
        )

        // 2. Known Tool Finding
        let knownToolEvidence = AuditEvidence(
            matchedSymbols: ["container_query_create"],
            linkedDylibs: ["libsystem_containermanager.dylib"],
            hasAppGroups: true,
            appGroups: ["group.com.jbdotparty.Erosion.WQ"],
            installChannel: .developerSideloaded,
            cryptid: 0,
            isFairPlayEncrypted: false,
            escapingSymlinks: [],
            dynamicLoadingPresent: true,
            pathEnumerationPresent: false,
            remediationGuidance: "Known Erosion utility."
        )

        let knownToolFinding = ScanFinding(
            bundleId: "com.jbdotparty.Erosion",
            displayName: "Erosion",
            version: "0.6.1",
            teamId: "DEF7654321",
            executablePath: "/private/var/containers/Bundle/Application/UUID/Erosion.app/Erosion",
            bundlePath: "/private/var/containers/Bundle/Application/UUID/Erosion.app",
            installChannel: .developerSideloaded,
            riskTier: .knownTool,
            isWhitelisted: true,
            whitelistedToolName: "Erosion",
            indicators: [
                ThreatIndicator(
                    signature: "container_query_create",
                    description: "Private query API in known tool",
                    category: ThreatIndicator.Category.privateSymbol,
                    location: "__LINKEDIT",
                    severity: .knownTool
                )
            ],
            evidence: knownToolEvidence,
            scanTimestamp: Date(timeIntervalSince1970: 1700000000)
        )

        // 3. Caution Finding
        let cautionEvidence = AuditEvidence(
            matchedSymbols: [],
            linkedDylibs: [],
            hasAppGroups: true,
            appGroups: ["group.com.example.utility"],
            installChannel: .enterpriseInHouse,
            cryptid: 0,
            isFairPlayEncrypted: false,
            escapingSymlinks: [],
            dynamicLoadingPresent: true,
            pathEnumerationPresent: false,
            remediationGuidance: ""
        )

        let cautionFinding = ScanFinding(
            bundleId: "com.example.utility",
            displayName: "Internal Enterprise Tool",
            version: "2.3.1",
            teamId: "ENT9998887",
            executablePath: "/private/var/containers/Bundle/Application/UUID/Tool.app/Tool",
            bundlePath: "/private/var/containers/Bundle/Application/UUID/Tool.app",
            installChannel: .enterpriseInHouse,
            riskTier: .caution,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(
                    signature: "dlopen",
                    description: "Dynamic symbol resolution pattern",
                    category: ThreatIndicator.Category.dynamicLoading,
                    location: "__TEXT",
                    severity: .caution
                )
            ],
            evidence: cautionEvidence,
            scanTimestamp: Date(timeIntervalSince1970: 1700000000)
        )

        // 4. Safe Finding
        let safeEvidence = AuditEvidence.empty(channel: .appStore)
        let safeFinding = ScanFinding(
            bundleId: "com.apple.calculator",
            displayName: "Calculator",
            version: "3.0.0",
            teamId: nil,
            executablePath: "/Applications/Calculator.app/Calculator",
            bundlePath: "/Applications/Calculator.app",
            installChannel: .appStore,
            riskTier: .safe,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [],
            evidence: safeEvidence,
            scanTimestamp: Date(timeIntervalSince1970: 1700000000)
        )

        sampleSession = ScanSession(
            id: UUID(uuidString: "12345678-ABCD-EF01-2345-6789ABCDEF01")!,
            timestamp: Date(timeIntervalSince1970: 1700000000),
            findings: [highRiskFinding, knownToolFinding, cautionFinding, safeFinding],
            systemVersion: "iOS 27.0 (24A437)",
            scanDuration: 1.25,
            engineVersion: "1.0.0"
        )
    }

    // MARK: - JSON Serializer Tests

    func testJSONReportGenerationRFC8259Compliant() throws {
        let jsonData = try generator.generateJSONReport(session: sampleSession)
        XCTAssertFalse(jsonData.isEmpty)

        // Verify valid RFC 8259 JSON structure
        let jsonObject = try JSONSerialization.jsonObject(with: jsonData, options: [])
        guard let dict = jsonObject as? [String: Any] else {
            XCTFail("JSON output is not a dictionary")
            return
        }

        XCTAssertEqual(dict["id"] as? String, "12345678-ABCD-EF01-2345-6789ABCDEF01")
        XCTAssertEqual(dict["engineVersion"] as? String, "1.0.0")
        XCTAssertEqual(dict["overallPosture"] as? String, "HIGH_RISK")
        XCTAssertEqual(dict["totalApps"] as? Int, 4)
        XCTAssertEqual(dict["systemVersion"] as? String, "iOS 27.0 (24A437)")
        XCTAssertEqual(dict["scanDuration"] as? Double, 1.25)

        // Verify risk breakdown dictionary format (RFC 8259 object, not array)
        guard let breakdown = dict["riskBreakdown"] as? [String: Any] else {
            XCTFail("riskBreakdown is not a JSON object")
            return
        }
        XCTAssertEqual(breakdown["HIGH_RISK"] as? Int, 1)
        XCTAssertEqual(breakdown["KNOWN_TOOL"] as? Int, 1)
        XCTAssertEqual(breakdown["CAUTION"] as? Int, 1)
        XCTAssertEqual(breakdown["SAFE"] as? Int, 1)

        // Verify findings array
        guard let findings = dict["findings"] as? [[String: Any]] else {
            XCTFail("findings is not an array")
            return
        }
        XCTAssertEqual(findings.count, 4)
    }

    func testJSONReportRoundTripDecoding() throws {
        let jsonData = try generator.generateJSONReport(session: sampleSession)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decodedSession = try decoder.decode(ScanSession.self, from: jsonData)

        XCTAssertEqual(decodedSession.id, sampleSession.id)
        XCTAssertEqual(decodedSession.overallPosture, sampleSession.overallPosture)
        XCTAssertEqual(decodedSession.totalApps, sampleSession.totalApps)
        XCTAssertEqual(decodedSession.systemVersion, sampleSession.systemVersion)
        XCTAssertEqual(decodedSession.engineVersion, sampleSession.engineVersion)
        XCTAssertEqual(decodedSession.scanDuration, sampleSession.scanDuration)
        XCTAssertEqual(decodedSession.findings.count, sampleSession.findings.count)

        // Check high risk finding round-trip fidelity
        guard let decodedHighRisk = decodedSession.findings.first(where: { $0.riskTier == .highRisk }) else {
            XCTFail("Missing high risk finding in decoded session")
            return
        }
        XCTAssertEqual(decodedHighRisk.bundleId, "com.rogue.exploit")
        XCTAssertEqual(decodedHighRisk.indicators.count, 2)
        XCTAssertEqual(decodedHighRisk.evidence.matchedSymbols, ["container_query_create", "container_copy_sandbox_token"])
        XCTAssertEqual(decodedHighRisk.evidence.escapingSymlinks.count, 1)
    }

    func testJSONReportStringConvenienceMethod() throws {
        let jsonString = try generator.generateJSONReportString(session: sampleSession)
        XCTAssertTrue(jsonString.contains("\"engineVersion\" : \"1.0.0\""))
        XCTAssertTrue(jsonString.contains("\"HIGH_RISK\""))
        XCTAssertTrue(jsonString.contains("com.rogue.exploit"))
    }

    // MARK: - Markdown Serializer Tests

    func testMarkdownReportContainsAllRequiredSections() {
        let md = generator.generateMarkdownReport(session: sampleSession)

        // Title
        XCTAssertTrue(md.contains("# WQGuard Security Audit Report"))
        XCTAssertTrue(md.contains("iOS 沙盒逃逸检测与系统安全审计报告"))

        // Metadata Table
        XCTAssertTrue(md.contains("12345678-ABCD-EF01-2345-6789ABCDEF01"))
        XCTAssertTrue(md.contains("iOS 27.0 (24A437)"))
        XCTAssertTrue(md.contains("1.25s"))

        // Security Posture Status Badge
        XCTAssertTrue(md.contains("SECURITY ALERT: CRITICAL RISK DETECTED"))
        XCTAssertTrue(md.contains("发现高危沙盒逃逸风险"))

        // Executive Summary Table
        XCTAssertTrue(md.contains("Executive Summary / 审计统计概览"))
        XCTAssertTrue(md.contains("High Risk (高危告警)"))
        XCTAssertTrue(md.contains("Known Tool (已知工具)"))
        XCTAssertTrue(md.contains("Caution (前置留意)"))
        XCTAssertTrue(md.contains("Safe (安全合规)"))

        // Categorized Findings Sections
        XCTAssertTrue(md.contains("🔴 High Risk Findings / 高危告警应用清单 (1)"))
        XCTAssertTrue(md.contains("🟡 Known Tools / 已知工具清单 (1)"))
        XCTAssertTrue(md.contains("🟠 Caution Findings / 前置条件留意应用清单 (1)"))
        XCTAssertTrue(md.contains("🟢 Safe Applications / 安全合规应用清单 (1)"))

        // Matched Threat Indicators Table
        XCTAssertTrue(md.contains("Matched Threat Indicators / 命中的风险特征项"))
        XCTAssertTrue(md.contains("container_query_create"))
        XCTAssertTrue(md.contains("escaping_symlink"))

        // Bilingual Remediation Guidance
        XCTAssertTrue(md.contains("Actionable Remediation Guidance / 处置建议"))
        XCTAssertTrue(md.contains("**English (EN)**:"))
        XCTAssertTrue(md.contains("**中文 (zh-Hans)**:"))

        // Invariant Assurance Footer
        XCTAssertTrue(md.contains("Inspection Integrity & Invariant Assurance"))
        XCTAssertTrue(md.contains("100% Read-Only"))
    }

    func testMarkdownPostureBadgesForDifferentTiers() {
        // Safe session
        let safeFinding = ScanFinding(
            bundleId: "com.apple.safe",
            displayName: "SafeApp",
            version: "1.0",
            bundlePath: "/App",
            installChannel: .appStore,
            riskTier: .safe,
            evidence: .empty()
        )
        let safeSession = ScanSession(findings: [safeFinding])
        let safeMd = generator.generateMarkdownReport(session: safeSession)
        XCTAssertTrue(safeMd.contains("SYSTEM STATUS: SECURE / 系统状态安全"))

        // Caution session
        let cautionFinding = ScanFinding(
            bundleId: "com.test.caution",
            displayName: "CautionApp",
            version: "1.0",
            bundlePath: "/App",
            installChannel: .developerSideloaded,
            riskTier: .caution,
            evidence: .empty()
        )
        let cautionSession = ScanSession(findings: [cautionFinding])
        let cautionMd = generator.generateMarkdownReport(session: cautionSession)
        XCTAssertTrue(cautionMd.contains("NOTICE: POTENTIAL PREREQUISITES DETECTED / 前置条件留意"))

        // Known tool session
        let knownFinding = ScanFinding(
            bundleId: "com.jbdotparty.Erosion",
            displayName: "Erosion",
            version: "1.0",
            bundlePath: "/App",
            installChannel: .developerSideloaded,
            riskTier: .knownTool,
            isWhitelisted: true,
            evidence: .empty()
        )
        let knownSession = ScanSession(findings: [knownFinding])
        let knownMd = generator.generateMarkdownReport(session: knownSession)
        XCTAssertTrue(knownMd.contains("ADVISORY: KNOWN UTILITIES DETECTED / 发现已知定制工具"))
    }

    // MARK: - PlainText Serializer Tests

    func testPlainTextReportCompleteness() {
        let text = generator.generatePlainTextReport(session: sampleSession)

        // Banner and Dividers
        XCTAssertTrue(text.contains("WQGUARD SECURITY AUDIT REPORT"))
        XCTAssertTrue(text.contains("12345678-ABCD-EF01-2345-6789ABCDEF01"))
        XCTAssertTrue(text.contains("iOS 27.0 (24A437)"))
        XCTAssertTrue(text.contains("SECURITY POSTURE: [CRITICAL RISK DETECTED]"))

        // Summary Statistics
        XCTAssertTrue(text.contains("SUMMARY STATISTICS:"))
        XCTAssertTrue(text.contains("High Risk (高危告警):      1"))
        XCTAssertTrue(text.contains("Known Tool (已知工具):     1"))
        XCTAssertTrue(text.contains("Caution (前置留意):        1"))
        XCTAssertTrue(text.contains("Safe (安全合规):           1"))

        // Findings Details
        XCTAssertTrue(text.contains("Rogue Exploiter (com.rogue.exploit)"))
        XCTAssertTrue(text.contains("container_query_create"))
        XCTAssertTrue(text.contains("escaping_symlink"))
        XCTAssertTrue(text.contains("libsystem_containermanager.dylib"))

        // Bilingual Remediation
        XCTAssertTrue(text.contains("Remediation Guidance (EN):"))
        XCTAssertTrue(text.contains("处置建议 (中文):"))

        // Invariant Notice
        XCTAssertTrue(text.contains("INVARIANT ASSURANCE: 100% Read-Only Inspection."))
    }

    // MARK: - Edge Cases

    func testReportGenerationWithEmptyFindings() throws {
        let emptySession = ScanSession(
            findings: [],
            systemVersion: "macOS 14.0",
            scanDuration: 0.05
        )

        // JSON
        let data = try generator.generateJSONReport(session: emptySession)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decodedSession = try decoder.decode(ScanSession.self, from: data)
        XCTAssertEqual(decodedSession.totalApps, 0)
        XCTAssertEqual(decodedSession.findings.isEmpty, true)
        XCTAssertEqual(decodedSession.overallPosture, .safe)

        // Markdown
        let md = generator.generateMarkdownReport(session: emptySession)
        XCTAssertTrue(md.contains("No application findings recorded"))
        XCTAssertTrue(md.contains("SYSTEM STATUS: SECURE"))

        // PlainText
        let text = generator.generatePlainTextReport(session: emptySession)
        XCTAssertTrue(text.contains("Total Scanned (总计):      0"))
        XCTAssertTrue(text.contains("(No application findings recorded in this scan session)"))
    }
}
