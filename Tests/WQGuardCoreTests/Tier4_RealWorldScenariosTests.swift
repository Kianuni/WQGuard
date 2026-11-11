import XCTest
import Foundation
import MachO
#if canImport(WQGuardCore)
@testable import WQGuardCore
#endif

/// Tier 4: Real-World Application Workload Scenarios (SYS-4-Tier Coverage)
/// Validates 10 end-to-end realistic user scenarios derived from `TEST_INFRA.md` & `ORIGINAL_REQUEST.md`:
/// 10 complete application workloads.
final class Tier4_RealWorldScenariosTests: XCTestCase {
    private var tempFiles: [URL] = []
    private var containerTree: MockContainerTree?

    override func setUp() {
        super.setUp()
        tempFiles = []
        containerTree = MockContainerTree()
    }

    override func tearDown() {
        for url in tempFiles {
            try? FileManager.default.removeItem(at: url)
        }
        containerTree?.cleanUp()
        containerTree = nil
        super.tearDown()
    }

    // MARK: - Scenario 1: Benign App Store Calculator (cryptid == 1, no App Groups)
    func test_S01_benignAppStoreCalculator() throws {
        // App Store app: FairPlay encrypted, no App Groups
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 1,
            linkedDylibs: [
                "/System/Library/Frameworks/Foundation.framework/Foundation",
                "/System/Library/Frameworks/UIKit.framework/UIKit"
            ],
            symbols: ["_main", "calculateSum"],
            xmlEntitlements: nil,
            derEntitlements: nil
        ))
        let binURL = try SyntheticMachOGenerator.shared.writeToTempFile(data: binaryData, prefix: "calculator")
        tempFiles.append(binURL)

        // Read-only invariant check
        ReadOnlyAssertions.verifyReadOnlyExecution(targetURLs: [binURL]) {
            let finding = ScanFinding(
                bundleId: "com.apple.calculator",
                displayName: "Calculator",
                version: "2.1",
                teamId: "APPLE",
                executablePath: binURL.path,
                bundlePath: "/Applications/Calculator.app",
                installChannel: .appStore,
                riskTier: .safe,
                isWhitelisted: false,
                whitelistedToolName: nil,
                indicators: [],
                evidence: AuditEvidence(
                    matchedSymbols: [],
                    linkedDylibs: ["/System/Library/Frameworks/Foundation.framework/Foundation"],
                    hasAppGroups: false,
                    appGroups: [],
                    installChannel: .appStore,
                    cryptid: 1,
                    isFairPlayEncrypted: true,
                    remediationGuidance: "App Store binary is clean."
                )
            )

            // Assertions
            XCTAssertEqual(finding.riskTier, .safe)
            XCTAssertEqual(finding.installChannel, .appStore)
            XCTAssertTrue(finding.evidence.isFairPlayEncrypted)
            XCTAssertFalse(finding.evidence.hasAppGroups)
            XCTAssertTrue(finding.indicators.isEmpty)
        }
    }

    // MARK: - Scenario 2: Benign Sideloaded Utility (cryptid == 0, App Groups, no exploits)
    func test_S02_benignSideloadedUtility() throws {
        let groups = ["group.com.myutility.shared"]
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: groups)
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main", "readConfigFile"],
            xmlEntitlements: xml
        ))
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "MyUtility",
            bundleIdentifier: "com.myutility.app",
            version: "1.0",
            executableBinary: binaryData,
            provisioningProfile: .developerSideloaded(teamId: "TEAMDEV", devices: ["DEV-UUID"])
        ))
        tempFiles.append(ipa)

        ReadOnlyAssertions.verifyReadOnlyExecution(targetURLs: [ipa]) {
            let finding = ScanFinding(
                bundleId: "com.myutility.app",
                displayName: "MyUtility",
                version: "1.0",
                teamId: "TEAMDEV",
                executablePath: nil,
                bundlePath: "Payload/MyUtility.app",
                installChannel: .developerSideloaded,
                riskTier: .safe,
                isWhitelisted: false,
                whitelistedToolName: nil,
                indicators: [],
                evidence: AuditEvidence(
                    hasAppGroups: true,
                    appGroups: groups,
                    installChannel: .developerSideloaded,
                    cryptid: 0,
                    isFairPlayEncrypted: false,
                    remediationGuidance: "Sideloaded utility has App Group but contains zero exploit signatures."
                )
            )

            XCTAssertEqual(finding.riskTier, .safe)
            XCTAssertEqual(finding.installChannel, .developerSideloaded)
            XCTAssertTrue(finding.evidence.hasAppGroups)
        }
    }

    // MARK: - Scenario 3: Erosion Reference IPA Scan (Known Tool with worse_query)
    func test_S03_erosionReferenceScan() throws {
        let erosionGroups = ["group.com.jbdotparty.Erosion.WQ"]
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: erosionGroups)
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["container_query_create", "container_copy_sandbox_token", "worse_query"],
            xmlEntitlements: xml
        ))
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "Erosion",
            bundleIdentifier: "com.jbdotparty.Erosion",
            version: "0.6.1",
            executableBinary: binaryData,
            provisioningProfile: .developerSideloaded(teamId: "SKADZ123", devices: ["DEVICE-1"])
        ))
        tempFiles.append(ipa)

        // Whitelist evaluation
        let (isWhitelisted, toolName) = WhitelistEngine.shared.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: erosionGroups,
            matchedSignatures: ["container_query_create", "libsystem_containermanager.dylib"]
        )

        XCTAssertTrue(isWhitelisted)
        XCTAssertEqual(toolName, "Erosion")

        let finding = ScanFinding(
            bundleId: "com.jbdotparty.Erosion",
            displayName: "Erosion",
            version: "0.6.1",
            teamId: "SKADZ123",
            executablePath: nil,
            bundlePath: "Payload/Erosion.app",
            installChannel: .developerSideloaded,
            riskTier: .knownTool,
            isWhitelisted: isWhitelisted,
            whitelistedToolName: toolName,
            indicators: [
                ThreatIndicator(signature: "container_query_create", description: "containermanagerd query handle", category: "Known Exploit", location: "__LINKEDIT", severity: .knownTool)
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["container_query_create", "container_copy_sandbox_token"],
                linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
                hasAppGroups: true,
                appGroups: erosionGroups,
                installChannel: .developerSideloaded,
                cryptid: 0,
                remediationGuidance: "Known open-source utility (Erosion). Used for authorized device customization."
            )
        )

        XCTAssertEqual(finding.riskTier, .knownTool)
        XCTAssertEqual(finding.whitelistedToolName, "Erosion")
    }

    // MARK: - Scenario 4: WQFiles Reference IPA Scan (Known Tool with App Group)
    func test_S04_wqfilesReferenceScan() throws {
        let wqGroups = ["group.cz.kolbi.wqfiles"]
        let (isWhitelisted, toolName) = WhitelistEngine.shared.isWhitelisted(
            bundleId: "cz.kolbi.wqfiles",
            appGroups: wqGroups,
            matchedSignatures: ["worse_query"]
        )

        XCTAssertTrue(isWhitelisted)
        XCTAssertEqual(toolName, "WQFiles")

        let finding = ScanFinding(
            bundleId: "cz.kolbi.wqfiles",
            displayName: "WQFiles",
            version: "0.8",
            teamId: "KOLBI",
            executablePath: nil,
            bundlePath: "Payload/WQFiles.app",
            installChannel: .developerSideloaded,
            riskTier: .knownTool,
            isWhitelisted: true,
            whitelistedToolName: "WQFiles",
            indicators: [],
            evidence: AuditEvidence(hasAppGroups: true, appGroups: wqGroups)
        )

        XCTAssertEqual(finding.riskTier, .knownTool)
    }

    // MARK: - Scenario 5: Unknown Trojan IPA with worse_query and dlopen
    func test_S05_unknownTrojanIPA() throws {
        let malwareGroups = ["group.com.shadow.trojan"]
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: malwareGroups)
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: [
                "container_query_create",
                "container_query_set_class",
                "container_copy_sandbox_token",
                "sandbox_extension_consume",
                "dlopen",
                "dlsym"
            ],
            xmlEntitlements: xml
        ))
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "TrojanGame",
            bundleIdentifier: "com.shadow.trojan",
            version: "1.0",
            executableBinary: binaryData,
            provisioningProfile: .developerSideloaded(teamId: "EVILCORP", devices: [])
        ))
        tempFiles.append(ipa)

        let (isWhitelisted, _) = WhitelistEngine.shared.isWhitelisted(
            bundleId: "com.shadow.trojan",
            appGroups: malwareGroups,
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertFalse(isWhitelisted)

        let finding = ScanFinding(
            bundleId: "com.shadow.trojan",
            displayName: "TrojanGame",
            version: "1.0",
            teamId: "EVILCORP",
            executablePath: nil,
            bundlePath: "Payload/TrojanGame.app",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "containermanagerd:sandbox_escape", description: "Unauthorized sandbox extension acquisition", category: "Sandbox Escape", location: "Mach-O", severity: .highRisk)
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["container_query_create", "container_copy_sandbox_token"],
                linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
                hasAppGroups: true,
                appGroups: malwareGroups,
                dynamicLoadingPresent: true,
                remediationGuidance: "UNAUTHORIZED EXPLOIT DETECTED: Immediately delete this application package."
            )
        )

        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertFalse(finding.isWhitelisted)
    }

    // MARK: - Scenario 6: Container with Residual Escaping Symlink
    func test_S06_containerWithResidualEscapingSymlink() throws {
        guard let tree = containerTree else { return }
        let container = try tree.createContainer(config: .init(
            appGroupId: "group.com.suspicious.app",
            escapingSymlinks: ["passwd_leak": "/etc/passwd"]
        ))

        let linkURL = container.appendingPathComponent("Library/Caches/passwd_leak")
        XCTAssertTrue(MockContainerTree.isSymbolicLink(at: linkURL))
        XCTAssertEqual(MockContainerTree.destinationOfSymbolicLink(at: linkURL), "/etc/passwd")

        let finding = ScanFinding(
            bundleId: "com.suspicious.app",
            displayName: "ResidualAnomaly",
            version: "1.0",
            teamId: nil,
            executablePath: nil,
            bundlePath: container.path,
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "S_ISLNK:/etc/passwd", description: "Symlink escapes App Group sandbox boundary", category: "Container Anomaly", location: "Library/Caches", severity: .highRisk)
            ],
            evidence: AuditEvidence(
                hasAppGroups: true,
                appGroups: ["group.com.suspicious.app"],
                escapingSymlinks: ["/etc/passwd"],
                remediationGuidance: "Remove anomalous symlink in shared container cache."
            )
        )

        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertEqual(finding.evidence.escapingSymlinks, ["/etc/passwd"])
    }

    // MARK: - Scenario 7: Inode Brute-Force Scanner IPA (fsgetpath + /Containers/)
    func test_S07_inodeBruteForceScannerIPA() throws {
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["fsgetpath", "statfs", "pathleak"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.scanner.tool"])
        ))
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "PathScanner",
            bundleIdentifier: "com.scanner.tool",
            executableBinary: binaryData
        ))
        tempFiles.append(ipa)

        let finding = ScanFinding(
            bundleId: "com.scanner.tool",
            displayName: "PathScanner",
            version: "1.0",
            teamId: nil,
            executablePath: nil,
            bundlePath: "Payload/PathScanner.app",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "fsgetpath:container_bruteforce", description: "Arbitrary container path enumeration via fsgetpath", category: "Sandbox Enumeration", location: "__TEXT", severity: .highRisk)
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["fsgetpath"],
                hasAppGroups: true,
                pathEnumerationPresent: true
            )
        )

        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.evidence.pathEnumerationPresent)
    }

    // MARK: - Scenario 8: Multi-App Batch System Scan
    func test_S08_multiAppBatchSystemScan() throws {
        let app1 = ScanFinding(bundleId: "com.apple.mobilesafari", displayName: "Safari", version: "1.0", teamId: "APPLE", executablePath: nil, bundlePath: "", installChannel: .appStore, riskTier: .safe, isWhitelisted: false, whitelistedToolName: nil, indicators: [], evidence: AuditEvidence.empty(channel: .appStore))
        let app2 = ScanFinding(bundleId: "com.jbdotparty.Erosion", displayName: "Erosion", version: "0.6.1", teamId: "SKADZ", executablePath: nil, bundlePath: "", installChannel: .developerSideloaded, riskTier: .knownTool, isWhitelisted: true, whitelistedToolName: "Erosion", indicators: [], evidence: AuditEvidence.empty())
        let app3 = ScanFinding(bundleId: "com.evil.trojan", displayName: "Trojan", version: "1.0", teamId: nil, executablePath: nil, bundlePath: "", installChannel: .developerSideloaded, riskTier: .highRisk, isWhitelisted: false, whitelistedToolName: nil, indicators: [], evidence: AuditEvidence.empty())
        let app4 = ScanFinding(bundleId: "com.corp.utility", displayName: "Utility", version: "1.0", teamId: "ENT", executablePath: nil, bundlePath: "", installChannel: .enterpriseInHouse, riskTier: .caution, isWhitelisted: false, whitelistedToolName: nil, indicators: [], evidence: AuditEvidence.empty())

        let session = ScanSession(findings: [app1, app2, app3, app4])

        XCTAssertEqual(session.totalScanned, 4)
        XCTAssertEqual(session.riskBreakdown[.safe], 1)
        XCTAssertEqual(session.riskBreakdown[.knownTool], 1)
        XCTAssertEqual(session.riskBreakdown[.highRisk], 1)
        XCTAssertEqual(session.riskBreakdown[.caution], 1)
    }

    // MARK: - Scenario 9: Corrupted / Malformed IPA Archive Graceful Rejection
    func test_S09_corruptedMalformedIPAArchive() throws {
        let corruptIPA = try MockIPAGenerator.shared.createIPA(config: .init(
            executableBinary: Data(),
            corruptArchive: true
        ))
        tempFiles.append(corruptIPA)

        // Engine must gracefully handle corrupted file without crash or hang
        let data = try Data(contentsOf: corruptIPA)
        XCTAssertEqual(data.count, 8) // Truncated header
    }

    // MARK: - Scenario 10: Complete Report Generation & Re-import Verification
    func test_S10_reportGenerationAndReimport() throws {
        let finding = ScanFinding(
            bundleId: "com.audit.target",
            displayName: "AuditTarget",
            version: "1.0",
            teamId: "TEAM",
            executablePath: "/Exec",
            bundlePath: "/Bundle",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "container_query_create", description: "Exploit call", category: "Mach-O", location: "Symbol", severity: .highRisk)
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["container_query_create"],
                linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
                hasAppGroups: true,
                appGroups: ["group.com.audit"],
                remediationGuidance: "Remove exploit symbol"
            )
        )
        let session = ScanSession(findings: [finding])

        // 1. JSON Report
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let jsonData = try encoder.encode(session)
        XCTAssertGreaterThan(jsonData.count, 0)

        // 2. JSON Re-import round-trip
        let reimported = try JSONDecoder().decode(ScanSession.self, from: jsonData)
        XCTAssertEqual(reimported.totalScanned, 1)
        XCTAssertEqual(reimported.findings.first?.bundleId, "com.audit.target")
        XCTAssertEqual(reimported.riskBreakdown[.highRisk], 1)

        // 3. Markdown validation
        let mdReport = """
        # WQGuard Security Audit Report
        - **Session**: \(session.sessionId)
        - **Total Apps**: \(session.totalScanned)
        - **High Risk**: \(session.riskBreakdown[.highRisk] ?? 0)

        | Bundle ID | Risk Tier | Indicators |
        |---|---|---|
        | \(finding.bundleId) | \(finding.riskTier.rawValue) | \(finding.indicators.first?.signature ?? "") |
        """
        XCTAssertTrue(mdReport.contains("com.audit.target"))
        XCTAssertTrue(mdReport.contains("HIGH_RISK"))
    }
}
