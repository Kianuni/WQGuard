import XCTest
@testable import WQGuardCore

final class ModelTests: XCTestCase {

    // MARK: - RiskTier Tests

    func testRiskTierRawValues() {
        XCTAssertEqual(RiskTier.highRisk.rawValue, "HIGH_RISK")
        XCTAssertEqual(RiskTier.knownTool.rawValue, "KNOWN_TOOL")
        XCTAssertEqual(RiskTier.caution.rawValue, "CAUTION")
        XCTAssertEqual(RiskTier.safe.rawValue, "SAFE")
    }

    func testRiskTierLocalization() {
        XCTAssertEqual(RiskTier.highRisk.localizedNameZh, "高危告警")
        XCTAssertEqual(RiskTier.highRisk.localizedNameEn, "High Risk")
        XCTAssertEqual(RiskTier.knownTool.localizedNameZh, "已知工具提示")
        XCTAssertEqual(RiskTier.knownTool.localizedNameEn, "Known Tool")
        XCTAssertEqual(RiskTier.caution.localizedNameZh, "前置条件留意")
        XCTAssertEqual(RiskTier.caution.localizedNameEn, "Caution")
        XCTAssertEqual(RiskTier.safe.localizedNameZh, "安全")
        XCTAssertEqual(RiskTier.safe.localizedNameEn, "Safe")

        XCTAssertFalse(RiskTier.highRisk.localizedDescriptionZh.isEmpty)
        XCTAssertFalse(RiskTier.highRisk.localizedDescriptionEn.isEmpty)
    }

    func testRiskTierComparableOrdering() {
        XCTAssertLessThan(RiskTier.safe, RiskTier.caution)
        XCTAssertLessThan(RiskTier.caution, RiskTier.knownTool)
        XCTAssertLessThan(RiskTier.knownTool, RiskTier.highRisk)

        let unsorted: [RiskTier] = [.highRisk, .safe, .caution, .knownTool]
        let expectedSorted: [RiskTier] = [.safe, .caution, .knownTool, .highRisk]
        XCTAssertEqual(unsorted.sorted(), expectedSorted)
    }

    func testRiskTierCodableDictionaryKey() throws {
        let original: [RiskTier: Int] = [.highRisk: 2, .safe: 10]
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(original)
        let jsonString = String(data: data, encoding: .utf8)!
        XCTAssertTrue(jsonString.contains("\"HIGH_RISK\" : 2") || jsonString.contains("\"HIGH_RISK\":2"))

        let decoded = try JSONDecoder().decode([RiskTier: Int].self, from: data)
        XCTAssertEqual(decoded, original)
    }

    // MARK: - InstallChannel Tests

    func testInstallChannelRawValues() {
        XCTAssertEqual(InstallChannel.developerSideloaded.rawValue, "DEVELOPER_SIDELOADED")
        XCTAssertEqual(InstallChannel.enterpriseInHouse.rawValue, "ENTERPRISE_IN_HOUSE")
        XCTAssertEqual(InstallChannel.testFlight.rawValue, "TESTFLIGHT")
        XCTAssertEqual(InstallChannel.appStore.rawValue, "APP_STORE")
    }

    func testInstallChannelProperties() {
        XCTAssertTrue(InstallChannel.developerSideloaded.isSideloadedOrEnterprise)
        XCTAssertTrue(InstallChannel.enterpriseInHouse.isSideloadedOrEnterprise)
        XCTAssertFalse(InstallChannel.testFlight.isSideloadedOrEnterprise)
        XCTAssertFalse(InstallChannel.appStore.isSideloadedOrEnterprise)

        XCTAssertEqual(InstallChannel.developerSideloaded.expectedCryptid, 0)
        XCTAssertEqual(InstallChannel.enterpriseInHouse.expectedCryptid, 0)
        XCTAssertEqual(InstallChannel.testFlight.expectedCryptid, 1)
        XCTAssertEqual(InstallChannel.appStore.expectedCryptid, 1)

        XCTAssertEqual(InstallChannel.allCases.count, 4)
    }

    func testInstallChannelCodable() throws {
        let channel = InstallChannel.developerSideloaded
        let data = try JSONEncoder().encode(channel)
        let decoded = try JSONDecoder().decode(InstallChannel.self, from: data)
        XCTAssertEqual(decoded, channel)
    }

    // MARK: - ThreatIndicator Tests

    func testThreatIndicatorModel() throws {
        let indicator = ThreatIndicator(
            signature: "libsystem_containermanager.dylib",
            description: "Direct reference to private container manager",
            category: ThreatIndicator.Category.privateDylib,
            location: "LC_LOAD_DYLIB",
            severity: .highRisk
        )

        XCTAssertEqual(indicator.id, "private_dylib:libsystem_containermanager.dylib:LC_LOAD_DYLIB")
        XCTAssertEqual(indicator.severity, .highRisk)

        let data = try JSONEncoder().encode(indicator)
        let decoded = try JSONDecoder().decode(ThreatIndicator.self, from: data)
        XCTAssertEqual(decoded, indicator)
    }

    // MARK: - AuditEvidence Tests

    func testAuditEvidenceDefaultsAndEmpty() {
        let defaultEvidence = AuditEvidence()
        XCTAssertTrue(defaultEvidence.matchedSymbols.isEmpty)
        XCTAssertTrue(defaultEvidence.linkedDylibs.isEmpty)
        XCTAssertFalse(defaultEvidence.hasAppGroups)
        XCTAssertEqual(defaultEvidence.cryptid, 0)
        XCTAssertFalse(defaultEvidence.isFairPlayEncrypted)

        let emptyStore = AuditEvidence.empty(channel: .appStore)
        XCTAssertEqual(emptyStore.installChannel, .appStore)
        XCTAssertEqual(emptyStore.cryptid, 1)
        XCTAssertTrue(emptyStore.isFairPlayEncrypted)
    }

    func testAuditEvidenceCodable() throws {
        let evidence = AuditEvidence(
            matchedSymbols: ["container_query_create", "container_copy_sandbox_token"],
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            hasAppGroups: true,
            appGroups: ["group.com.evil.exploit"],
            installChannel: .developerSideloaded,
            cryptid: 0,
            isFairPlayEncrypted: false,
            escapingSymlinks: ["/etc/passwd"],
            dynamicLoadingPresent: true,
            pathEnumerationPresent: true,
            remediationGuidance: "Remove the application immediately."
        )

        let data = try JSONEncoder().encode(evidence)
        let decoded = try JSONDecoder().decode(AuditEvidence.self, from: data)
        XCTAssertEqual(decoded, evidence)
    }

    // MARK: - ScanFinding Tests

    func testScanFindingIdentifiableAndCodable() throws {
        let finding = ScanFinding(
            bundleId: "com.jbdotparty.Erosion",
            displayName: "Erosion",
            version: "1.0.2",
            teamId: "9XYZ12345",
            executablePath: "/var/containers/Bundle/Application/UUID/Erosion.app/Erosion",
            bundlePath: "/var/containers/Bundle/Application/UUID/Erosion.app",
            installChannel: .developerSideloaded,
            riskTier: .knownTool,
            isWhitelisted: true,
            whitelistedToolName: "Erosion",
            indicators: [
                ThreatIndicator(
                    signature: "container_query_create",
                    description: "Private symbol",
                    category: ThreatIndicator.Category.privateSymbol,
                    location: "__LINKEDIT",
                    severity: .highRisk
                )
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["container_query_create"],
                linkedDylibs: [],
                hasAppGroups: true,
                appGroups: ["group.com.jbdotparty.Erosion.WQ"],
                installChannel: .developerSideloaded,
                cryptid: 0,
                isFairPlayEncrypted: false,
                escapingSymlinks: [],
                dynamicLoadingPresent: true,
                pathEnumerationPresent: false,
                remediationGuidance: "Authorized known tool"
            ),
            scanTimestamp: Date(timeIntervalSince1970: 1700000000)
        )

        XCTAssertEqual(finding.id, "com.jbdotparty.Erosion:/var/containers/Bundle/Application/UUID/Erosion.app/Erosion")
        XCTAssertTrue(finding.isWhitelisted)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(finding)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(ScanFinding.self, from: data)
        XCTAssertEqual(decoded, finding)
        XCTAssertEqual(decoded.id, finding.id)
    }

    // MARK: - ScanSession Tests

    func testScanSessionPostureDerivation() throws {
        let safeFinding = ScanFinding(
            bundleId: "com.example.calculator",
            displayName: "Calculator",
            version: "1.0",
            bundlePath: "/Applications/Calculator.app",
            installChannel: .appStore,
            riskTier: .safe,
            evidence: .empty(channel: .appStore)
        )

        let cautionFinding = ScanFinding(
            bundleId: "com.example.tool",
            displayName: "Tool",
            version: "1.0",
            bundlePath: "/Applications/Tool.app",
            installChannel: .developerSideloaded,
            riskTier: .caution,
            evidence: AuditEvidence(hasAppGroups: true, dynamicLoadingPresent: true)
        )

        let highRiskFinding = ScanFinding(
            bundleId: "com.example.trojan",
            displayName: "Trojan",
            version: "1.0",
            bundlePath: "/Applications/Trojan.app",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            evidence: AuditEvidence(matchedSymbols: ["container_query_create"])
        )

        let sessionSafe = ScanSession(findings: [safeFinding])
        XCTAssertEqual(sessionSafe.overallPosture, .safe)
        XCTAssertEqual(sessionSafe.totalAppsScanned, 1)
        XCTAssertEqual(sessionSafe.riskBreakdown[.safe], 1)

        let sessionCaution = ScanSession(findings: [safeFinding, cautionFinding])
        XCTAssertEqual(sessionCaution.overallPosture, .caution)
        XCTAssertEqual(sessionCaution.riskBreakdown[.caution], 1)

        let sessionHighRisk = ScanSession(findings: [safeFinding, cautionFinding, highRiskFinding])
        XCTAssertEqual(sessionHighRisk.overallPosture, .highRisk)
        XCTAssertEqual(sessionHighRisk.highRiskFindings.count, 1)
        XCTAssertEqual(sessionHighRisk.cautionFindings.count, 1)
        XCTAssertEqual(sessionHighRisk.safeFindings.count, 1)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(sessionHighRisk)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(ScanSession.self, from: data)
        XCTAssertEqual(decoded.id, sessionHighRisk.id)
        XCTAssertEqual(decoded.overallPosture, .highRisk)
        XCTAssertEqual(decoded.findings.count, 3)
    }
}
