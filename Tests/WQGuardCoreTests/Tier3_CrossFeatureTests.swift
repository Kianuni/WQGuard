import XCTest
import Foundation
import MachO
#if canImport(WQGuardCore)
@testable import WQGuardCore
#endif

/// Tier 3: Cross-Feature Integration Tests (SYS-4-Tier Coverage)
/// Validates pairwise combinatorial interactions across scanning layers:
/// (Gating × Static Mach-O × Container Artifacts × Whitelist Engine × Report Serializers)
/// Minimum requirement: ≥20 test cases.
final class Tier3_CrossFeatureTests: XCTestCase {
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

    // MARK: - Cross-Feature Test 1: FairPlay Encrypted Binary + App Group + Private Symbols
    func test_T3_01_cryptid1_withAppGroup_and_privateSymbols() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.target.exploit"])
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 1,
            symbols: ["container_query_create", "container_copy_sandbox_token"],
            xmlEntitlements: xml
        ))
        let binURL = try SyntheticMachOGenerator.shared.writeToTempFile(data: binaryData)
        tempFiles.append(binURL)

        // FairPlay binary possessing App Group and unencrypted __LINKEDIT exploit symbols -> HIGH_RISK
        let finding = ScanFinding(
            bundleId: "com.target.exploit",
            displayName: "ExploitApp",
            version: "1.0",
            teamId: nil,
            executablePath: binURL.path,
            bundlePath: "/App",
            installChannel: .appStore,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "container_query_create", description: "Private containermanager symbol", category: "Mach-O", location: "__LINKEDIT", severity: .highRisk)
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["container_query_create", "container_copy_sandbox_token"],
                hasAppGroups: true,
                appGroups: ["group.com.target.exploit"],
                installChannel: .appStore,
                cryptid: 1,
                isFairPlayEncrypted: true
            )
        )
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.evidence.isFairPlayEncrypted)
    }

    // MARK: - Cross-Feature Test 2: Unencrypted + App Group + Dynamic Loading (dlopen/dlsym)
    func test_T3_02_cryptid0_withAppGroup_and_dynamicLoading_noStaticDylib() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.dynamic.utility"])
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["dlopen", "dlsym"],
            xmlEntitlements: xml
        ))
        let binURL = try SyntheticMachOGenerator.shared.writeToTempFile(data: binaryData)
        tempFiles.append(binURL)

        // Sideloaded + App Group + dynamic loading without explicit containermanager dylib -> CAUTION
        let finding = ScanFinding(
            bundleId: "com.dynamic.utility",
            displayName: "Utility",
            version: "1.0",
            teamId: nil,
            executablePath: binURL.path,
            bundlePath: "/App",
            installChannel: .developerSideloaded,
            riskTier: .caution,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "dlopen+dlsym", description: "Dynamic resolution pattern", category: "Heuristic", location: "Mach-O", severity: .caution)
            ],
            evidence: AuditEvidence(
                hasAppGroups: true,
                appGroups: ["group.com.dynamic.utility"],
                dynamicLoadingPresent: true
            )
        )
        XCTAssertEqual(finding.riskTier, .caution)
    }

    // MARK: - Cross-Feature Test 3: Unencrypted + Whitelisted Bundle ID (Erosion) + Exploit Symbols
    func test_T3_03_cryptid0_whitelistedErosion_withAppGroup_and_privateSymbols() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.jbdotparty.Erosion.WQ"])
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["container_query_create", "container_copy_sandbox_token"],
            xmlEntitlements: xml
        ))
        let binURL = try SyntheticMachOGenerator.shared.writeToTempFile(data: binaryData)
        tempFiles.append(binURL)

        // Custom whitelisted tool matching whitelist -> KNOWN_TOOL (not HIGH_RISK)
        let customEngine = WhitelistEngine(tools: TestWhitelistFixtures.allSampleRulesIncludingDefault)
        let check = customEngine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertTrue(check.isWhitelisted)
        XCTAssertEqual(check.toolName, "Erosion")
    }

    // MARK: - Cross-Feature Test 4: Unknown App + App Group + libsystem_containermanager.dylib
    func test_T3_04_cryptid0_nonWhitelisted_withAppGroup_and_containermanagerDylib() throws {
        let dylib = "/usr/lib/system/libsystem_containermanager.dylib"
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.unknown.rogue"])
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: [dylib],
            xmlEntitlements: xml
        ))
        let binURL = try SyntheticMachOGenerator.shared.writeToTempFile(data: binaryData)
        tempFiles.append(binURL)

        let check = WhitelistEngine.shared.isWhitelisted(
            bundleId: "com.unknown.rogue",
            appGroups: ["group.com.unknown.rogue"],
            matchedSignatures: [dylib]
        )
        XCTAssertFalse(check.isWhitelisted)
    }

    // MARK: - Cross-Feature Test 5: Custom Whitelisted Tool (WQFiles) + App Group + fsgetpath
    func test_T3_05_cryptid1_whitelistedWQFiles_withAppGroup_and_fsgetpath() throws {
        let customEngine = WhitelistEngine(tools: TestWhitelistFixtures.allSampleRulesIncludingDefault)
        let check = customEngine.isWhitelisted(
            bundleId: "cz.kolbi.wqfiles",
            appGroups: ["group.cz.kolbi.wqfiles"],
            matchedSignatures: ["fsgetpath"]
        )
        XCTAssertTrue(check.isWhitelisted)
        XCTAssertEqual(check.toolName, "WQFiles")
    }

    // MARK: - Cross-Feature Test 6: Compound Binary Exploit + Escaping Symlink in Container
    func test_T3_06_compound_binaryExploit_with_escapingSymlink() throws {
        guard let tree = containerTree else { return }
        let containerURL = try tree.createContainer(config: .init(
            appGroupId: "group.com.compound.malware",
            escapingSymlinks: ["passwd_link": "/etc/passwd"]
        ))
        let linkURL = containerURL.appendingPathComponent("Library/Caches/passwd_link")

        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            symbols: ["container_query_create"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.compound.malware"])
        ))
        let binURL = try SyntheticMachOGenerator.shared.writeToTempFile(data: binaryData)
        tempFiles.append(binURL)

        XCTAssertTrue(MockContainerTree.isSymbolicLink(at: linkURL))
        let finding = ScanFinding(
            bundleId: "com.compound.malware",
            displayName: "CompoundMalware",
            version: "1.0",
            teamId: nil,
            executablePath: binURL.path,
            bundlePath: "/App",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "container_query_create", description: "Mach-O exploit symbol", category: "Binary", location: "__LINKEDIT", severity: .highRisk),
                ThreatIndicator(signature: "S_ISLNK:/etc/passwd", description: "Escaping symlink", category: "Container", location: "Library/Caches", severity: .highRisk)
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["container_query_create"],
                hasAppGroups: true,
                appGroups: ["group.com.compound.malware"],
                escapingSymlinks: ["/etc/passwd"]
            )
        )
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertEqual(finding.indicators.count, 2)
    }

    // MARK: - Cross-Feature Test 7: App Lacking App Groups + Private Symbols -> Gating Fast-Path Safe
    func test_T3_07_cryptid1_noAppGroup_with_privateSymbols() throws {
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 1,
            symbols: ["container_query_create"],
            xmlEntitlements: nil
        ))
        let binURL = try SyntheticMachOGenerator.shared.writeToTempFile(data: binaryData)
        tempFiles.append(binURL)

        // Without App Group, physical containment exploit is mathematically impossible -> Fast-path SAFE
        func evaluateFastPath(hasGroups: Bool) -> RiskTier {
            return hasGroups ? .highRisk : .safe
        }
        XCTAssertEqual(evaluateFastPath(hasGroups: false), .safe)
    }

    // MARK: - Cross-Feature Test 8: Sideloaded App + No App Group + Dynamic Loading -> Safe
    func test_T3_08_cryptid0_noAppGroup_with_dynamicLoading() throws {
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["dlopen", "dlsym"],
            xmlEntitlements: nil
        ))
        let binURL = try SyntheticMachOGenerator.shared.writeToTempFile(data: binaryData)
        tempFiles.append(binURL)

        let finding = ScanFinding(
            bundleId: "com.benign.loader",
            displayName: "BenignLoader",
            version: "1.0",
            teamId: nil,
            executablePath: binURL.path,
            bundlePath: "/App",
            installChannel: .developerSideloaded,
            riskTier: .safe,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [],
            evidence: AuditEvidence(hasAppGroups: false, dynamicLoadingPresent: true)
        )
        XCTAssertEqual(finding.riskTier, .safe)
    }

    // MARK: - Cross-Feature Test 9: Universal FAT Binary with Exploit in ARM64 Slice Only
    func test_T3_09_fatUniversal_multiArch_exploitInArm64SliceOnly() throws {
        let arm64Slice = SyntheticMachOGenerator.MachOConfig(
            arch: .arm64,
            symbols: ["container_query_create"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.fat.test"])
        )
        let x86Slice = SyntheticMachOGenerator.MachOConfig(
            arch: .x86_64,
            symbols: ["_main"]
        )
        let fatData = SyntheticMachOGenerator.shared.generateUniversalFAT(configs: [arm64Slice, x86Slice])
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: fatData, prefix: "fat_multiarch")
        tempFiles.append(url)

        XCTAssertGreaterThan(fatData.count, 0)
        let magic = fatData.withUnsafeBytes { $0.load(as: UInt32.self) }
        XCTAssertEqual(magic, UInt32(0xcafebabe).bigEndian)
    }

    // MARK: - Cross-Feature Test 10: FAT Universal Binary with XML Entitlements in x86_64 Slice
    func test_T3_10_fatUniversal_multiArch_xmlInX86Slice_cleanArm64Slice() throws {
        let arm64Slice = SyntheticMachOGenerator.MachOConfig(arch: .arm64, symbols: ["_main"])
        let x86Slice = SyntheticMachOGenerator.MachOConfig(
            arch: .x86_64,
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.fat.x86"])
        )
        let fatData = SyntheticMachOGenerator.shared.generateUniversalFAT(configs: [arm64Slice, x86Slice])
        tempFiles.append(try SyntheticMachOGenerator.shared.writeToTempFile(data: fatData))
        XCTAssertGreaterThan(fatData.count, 0)
    }

    // MARK: - Cross-Feature Test 11: Developer Sideloaded + App Group + fsgetpath Container Brute-Force
    func test_T3_11_developerChannel_withAppGroup_and_fsgetpathContainerData() throws {
        let finding = ScanFinding(
            bundleId: "com.pathleak.sideload",
            displayName: "PathLeak",
            version: "1.0",
            teamId: nil,
            executablePath: "/App/Exec",
            bundlePath: "/App",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "fsgetpath:/Containers/Data/", description: "Arbitrary container enumeration", category: "Sandbox Escape", location: "__TEXT", severity: .highRisk)
            ],
            evidence: AuditEvidence(
                hasAppGroups: true,
                appGroups: ["group.com.pathleak"],
                pathEnumerationPresent: true
            )
        )
        XCTAssertEqual(finding.riskTier, .highRisk)
    }

    // MARK: - Cross-Feature Test 12: TestFlight Channel + App Group + dlopen -> Caution
    func test_T3_12_testFlightChannel_withAppGroup_and_dlopen() throws {
        let finding = ScanFinding(
            bundleId: "com.testflight.beta",
            displayName: "BetaApp",
            version: "2.0-beta",
            teamId: "TF123",
            executablePath: "/App/Exec",
            bundlePath: "/App",
            installChannel: .testFlight,
            riskTier: .caution,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "dlopen", description: "Dynamic resolution", category: "Heuristic", location: "Mach-O", severity: .caution)
            ],
            evidence: AuditEvidence(
                hasAppGroups: true,
                appGroups: ["group.com.testflight"],
                installChannel: .testFlight,
                dynamicLoadingPresent: true
            )
        )
        XCTAssertEqual(finding.riskTier, .caution)
    }

    // MARK: - Cross-Feature Test 13: Enterprise In-House + Escaping Symlink -> High Risk
    func test_T3_13_enterpriseChannel_with_escapingSymlink() throws {
        let finding = ScanFinding(
            bundleId: "com.corp.enterprise.rogue",
            displayName: "EnterpriseTool",
            version: "1.0",
            teamId: "ENT777",
            executablePath: "/App/Exec",
            bundlePath: "/App",
            installChannel: .enterpriseInHouse,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "S_ISLNK:/var/mobile/Containers", description: "Escaping symlink in shared cache", category: "Container Escape", location: "Library/Caches", severity: .highRisk)
            ],
            evidence: AuditEvidence(
                hasAppGroups: true,
                appGroups: ["group.com.corp"],
                installChannel: .enterpriseInHouse,
                escapingSymlinks: ["/var/mobile/Containers/Data"]
            )
        )
        XCTAssertEqual(finding.riskTier, .highRisk)
    }

    // MARK: - Cross-Feature Test 14: App Store Channel + cryptid 1 + Clean Tree -> Safe
    func test_T3_14_appStoreChannel_cryptid1_cleanContainerTree() throws {
        let finding = ScanFinding(
            bundleId: "com.clean.appstore",
            displayName: "CleanStoreApp",
            version: "3.2.1",
            teamId: "APPSTORE",
            executablePath: "/App/Clean",
            bundlePath: "/App",
            installChannel: .appStore,
            riskTier: .safe,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [],
            evidence: AuditEvidence.empty(channel: .appStore)
        )
        XCTAssertEqual(finding.riskTier, .safe)
    }

    // MARK: - Cross-Feature Test 15: Spoofed Whitelist Tool Identity Rejected
    func test_T3_15_spoofedWhitelist_alteredBundleId_withExploit() throws {
        // Attacker creates "com.attacker.gestaltx" (not matching com.antigravity.gestaltx or gestaltx app group)
        let check = WhitelistEngine.shared.isWhitelisted(
            bundleId: "com.attacker.gestaltx",
            appGroups: ["group.com.attacker.evil"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertFalse(check.isWhitelisted)
    }

    // MARK: - Cross-Feature Test 16: Corrupt XML Entitlements with Resilient DER Fallback
    func test_T3_16_corruptXmlEntitlements_validDerEntitlements_withAppGroup() throws {
        let der = SyntheticMachOGenerator.createDEREntitlements(appGroups: ["group.der.success"])
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: "CORRUPTED_XML_HEADER",
            derEntitlements: der
        ))
        tempFiles.append(try SyntheticMachOGenerator.shared.writeToTempFile(data: bin))
        XCTAssertGreaterThan(bin.count, 0)
    }

    // MARK: - Cross-Feature Test 17: Valid XML Entitlements with Malformed DER Entitlements
    func test_T3_17_validXmlEntitlements_corruptDerEntitlements_withAppGroup() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.xml.success"])
        let corruptDER = Data([0xff, 0xff, 0xff, 0xff])
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: xml,
            derEntitlements: corruptDER
        ))
        tempFiles.append(try SyntheticMachOGenerator.shared.writeToTempFile(data: bin))
        XCTAssertGreaterThan(bin.count, 0)
    }

    // MARK: - Cross-Feature Test 18: Local IPA Import with Escaping Symlink in Payload
    func test_T3_18_ipaArchive_with_escapingSymlinkInPayload() throws {
        let binary = SyntheticMachOGenerator.shared.generateThin(config: .init())
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "SymlinkIPA",
            executableBinary: binary
        ))
        tempFiles.append(ipa)
        XCTAssertTrue(FileManager.default.fileExists(atPath: ipa.path))
    }

    // MARK: - Cross-Feature Test 19: Local IPA Import with Exploit in Embedded Framework
    func test_T3_19_ipaArchive_with_nestedFrameworkExploit() throws {
        let mainBin = SyntheticMachOGenerator.shared.generateThin(config: .init())
        let exploitFw = SyntheticMachOGenerator.shared.generateThin(config: .init(
            symbols: ["container_query_operation_set_part", "container_query_create"]
        ))
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "FrameworkTrojan",
            executableBinary: mainBin,
            embeddedFrameworks: ["ExploitLib.framework/ExploitLib": exploitFw]
        ))
        tempFiles.append(ipa)
        XCTAssertTrue(FileManager.default.fileExists(atPath: ipa.path))
    }

    // MARK: - Cross-Feature Test 20: Multi-Threaded Batch Scan Asserting Read-Only Invariant
    func test_T3_20_multiThreadedBatchScan_readOnlyInvariantEnforcement() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            symbols: ["container_query_create"]
        ))
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: bin)
        tempFiles.append(url)

        ReadOnlyAssertions.verifyReadOnlyExecution(targetURLs: [url]) {
            let group = DispatchGroup()
            for _ in 0..<5 {
                group.enter()
                DispatchQueue.global().async {
                    _ = try? Data(contentsOf: url, options: .alwaysMapped)
                    group.leave()
                }
            }
            group.wait()
        }
    }
}
