//
//  StaticScannerTests.swift
//  WQGuardCoreTests
//
//  Unit test suite for ChannelClassifier, EntitlementGating,
//  SignatureCatalog, and MachOScanner.
//

import XCTest
import Foundation
import MachO
@testable import WQGuardCore

final class StaticScannerTests: XCTestCase {
    private var tempFiles: [URL] = []
    
    override func tearDown() {
        for url in tempFiles {
            try? FileManager.default.removeItem(at: url)
        }
        tempFiles.removeAll()
        super.tearDown()
    }
    
    // MARK: - ChannelClassifier Tests
    
    func testChannelClassification_DeveloperSideloaded_UnencryptedWithProvision() {
        let provDict: [String: Any] = [
            "TeamIdentifier": ["DEVTEAM123"],
            "TeamName": "Developer Personal",
            "Name": "iOS Team Provisioning Profile",
            "ProvisionedDevices": ["00008030-001234567890002E"]
        ]
        let provData = try! PropertyListSerialization.data(fromPropertyList: provDict, format: .xml, options: 0)
        let result = ChannelClassifier.classify(cryptid: 0, mobileprovisionData: provData)
        
        XCTAssertEqual(result.channel, .developerSideloaded)
        XCTAssertFalse(result.isEnterprise)
        XCTAssertEqual(result.teamIdentifier, "DEVTEAM123")
        XCTAssertTrue(result.hasMobileProvision)
    }
    
    func testChannelClassification_EnterpriseInHouse_ProvisionsAllDevices() {
        let provDict: [String: Any] = [
            "TeamIdentifier": ["ENTTEAM999"],
            "TeamName": "Global Enterprise",
            "Name": "Enterprise In-House Profile",
            "ProvisionsAllDevices": true
        ]
        let provData = try! PropertyListSerialization.data(fromPropertyList: provDict, format: .xml, options: 0)
        let result = ChannelClassifier.classify(cryptid: 0, mobileprovisionData: provData)
        
        XCTAssertEqual(result.channel, .enterpriseInHouse)
        XCTAssertTrue(result.isEnterprise)
        XCTAssertEqual(result.teamIdentifier, "ENTTEAM999")
    }
    
    func testChannelClassification_TestFlight_SandboxReceipt() {
        let result = ChannelClassifier.classify(cryptid: 1, hasSandboxReceipt: true)
        XCTAssertEqual(result.channel, .testFlight)
        XCTAssertTrue(result.isFairPlayEncrypted)
        XCTAssertTrue(result.hasReceipt)
    }
    
    func testChannelClassification_TestFlight_ReceiptMarker() {
        let mockReceiptData = "SANDBOX_TESTFLIGHT_RECEIPT_BLOB".data(using: .utf8)!
        let result = ChannelClassifier.classify(cryptid: 1, receiptData: mockReceiptData)
        XCTAssertEqual(result.channel, .testFlight)
    }
    
    func testChannelClassification_AppStore_FairPlayEncrypted() {
        let result = ChannelClassifier.classify(cryptid: 1, hasSandboxReceipt: false)
        XCTAssertEqual(result.channel, .appStore)
        XCTAssertTrue(result.isFairPlayEncrypted)
    }
    
    func testChannelClassification_AdHoc_WithoutProvision() {
        let result = ChannelClassifier.classify(cryptid: 0, mobileprovisionData: nil)
        XCTAssertEqual(result.channel, .developerSideloaded)
        XCTAssertFalse(result.hasMobileProvision)
    }
    
    // MARK: - EntitlementGating Tests
    
    func testEntitlementGating_NoAppGroups_FastPathsToSafe() {
        let result = EntitlementGating.evaluate(hasAppGroups: false, appGroups: [])
        XCTAssertTrue(result.isGatedOut)
        XCTAssertEqual(result.riskTier, .safe)
        XCTAssertFalse(result.shouldProceedToDeepScan)
        XCTAssertTrue(result.reason.contains("Layer 1 Fast-Path Gated"))
    }
    
    func testEntitlementGating_EmptyAppGroupsList_FastPathsToSafe() {
        let result = EntitlementGating.evaluate(hasAppGroups: true, appGroups: ["", "  "])
        XCTAssertTrue(result.isGatedOut)
        XCTAssertEqual(result.riskTier, .safe)
        XCTAssertFalse(result.shouldProceedToDeepScan)
    }
    
    func testEntitlementGating_ValidAppGroup_ProceedsToDeepScan() {
        let groups = ["group.com.example.shared"]
        let result = EntitlementGating.evaluate(hasAppGroups: true, appGroups: groups)
        XCTAssertFalse(result.isGatedOut)
        XCTAssertTrue(result.shouldProceedToDeepScan)
        XCTAssertEqual(result.appGroups, groups)
    }
    
    func testEntitlementGating_DictionaryWithGroups() {
        let dict: [String: Any] = [
            "com.apple.security.application-groups": ["group.corp.test1", "group.corp.test2"]
        ]
        let result = EntitlementGating.evaluate(entitlements: dict)
        XCTAssertFalse(result.isGatedOut)
        XCTAssertTrue(result.shouldProceedToDeepScan)
        XCTAssertEqual(result.appGroups.count, 2)
    }
    
    // MARK: - MachOScanner Tests
    
    func testMachOScanner_Dylib_libsystemContainermanager_FlaggedHighRisk() {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.evil.dylibapp",
            appGroups: ["group.com.evil.shared"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "libsystem_containermanager.dylib" })
    }
    
    func testMachOScanner_Dylib_WeakLinkedContainermanager_FlaggedHighRisk() {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            weakDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.evil.weakapp",
            appGroups: ["group.com.evil.shared"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "libsystem_containermanager.dylib" })
    }
    
    func testMachOScanner_PrivateSymbols_ContainerQueryCreate_FlaggedHighRisk() {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            symbols: ["container_query_create", "container_copy_sandbox_token"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.evil.symbols",
            appGroups: ["group.com.evil"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "container_query_create" })
        XCTAssertTrue(finding.indicators.contains { $0.signature == "container_copy_sandbox_token" })
    }
    
    func testMachOScanner_AllEightPrivateSymbolsDetected() {
        let allEight = [
            "container_query_create",
            "container_query_set_group_identifiers",
            "container_query_operation_set_part",
            "container_query_operation_set_flags",
            "container_copy_sandbox_token",
            "sandbox_extension_consume",
            "container_query_get_single_result",
            "container_query_iterate_results_sync"
        ]
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            symbols: allEight
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.evil.alleight",
            appGroups: ["group.com.evil"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .highRisk)
        for sym in allEight {
            XCTAssertTrue(finding.indicators.contains { $0.signature == sym }, "Missing signature for \(sym)")
        }
    }
    
    func testMachOScanner_DirectXPC_ContainermanagerdService_FlaggedHighRisk() {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            symbols: ["com.apple.containermanagerd"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.evil.xpc",
            appGroups: ["group.com.evil"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "com.apple.containermanagerd" })
    }
    
    func testMachOScanner_PathLeak_FsgetpathCombinedWithContainerData_FlaggedHighRisk() {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            symbols: ["fsgetpath", "/Containers/Data/"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.evil.pathleak",
            appGroups: ["group.com.evil"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature.contains("fsgetpath") })
        XCTAssertTrue(finding.evidence.pathEnumerationPresent)
    }
    
    func testMachOScanner_BehavioralTuple_ObfuscatedExploit_FlaggedHighRisk() {
        // Obfuscated: No literal container_query_create, but cryptid==0, App Group, dlopen+dlsym, and symlink
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            symbols: ["dlopen", "dlsym", "symlink"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.obfuscated.trojan",
            appGroups: ["group.com.obfuscated"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "cryptid0+AppGroups+dlopen/dlsym+Symlink/SandboxAPI" })
    }
    
    func testMachOScanner_DynamicLoadingHeuristic_WithAppGroup_FlaggedCaution() {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            symbols: ["dlopen", "dlsym"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.benign.dynamic",
            appGroups: ["group.com.benign"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .caution)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "dlopen+dlsym" })
    }
    
    func testMachOScanner_DynamicLoadingHeuristic_WithoutAppGroup_FastPathSafe() {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            symbols: ["dlopen", "dlsym"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.benign.dynamic",
            appGroups: []
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .safe)
        XCTAssertTrue(finding.indicators.isEmpty)
    }
    
    func testMachOScanner_FairPlayHandling_InspectsUnencryptedLoadCommands() {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 1,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.target.fairplay",
            installChannel: .appStore,
            appGroups: ["group.com.target"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.evidence.isFairPlayEncrypted)
        XCTAssertEqual(finding.evidence.cryptid, 1)
    }
    
    func testMachOScanner_WhitelistIntegration_ErosionDowngradedToKnownTool() {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["container_query_create", "container_copy_sandbox_token"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        // By default, Erosion is NOT built-in whitelisted -> High Risk
        let defaultFinding = MachOScanner.shared.scan(details: details, context: ctx)
        XCTAssertEqual(defaultFinding.riskTier, .highRisk)
        XCTAssertFalse(defaultFinding.isWhitelisted)

        // When user adds a custom rule, MachOScanner downgrades to Known Tool
        TestWhitelistFixtures.installSampleRulesIntoShared()
        defer { WhitelistEngine.shared.resetToDefaults() }
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .knownTool)
        XCTAssertTrue(finding.isWhitelisted)
        XCTAssertEqual(finding.whitelistedToolName, "Erosion")
    }
    
    func testMachOScanner_WhitelistIntegration_UnknownTrojanRemainsHighRisk() {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["container_query_create"]
        ))
        let details = try! MachOScanner.shared.parseMachO(data: binData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.unknown.trojan",
            appGroups: ["group.com.unknown.trojan"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertFalse(finding.isWhitelisted)
        XCTAssertNil(finding.whitelistedToolName)
    }
    
    func testMachOScanner_100PercentReadOnlyInvariant_TargetBinaryUntouched() throws {
        let synth = SyntheticMachOGenerator.shared
        let binData = synth.generateThin(config: .init(
            cryptid: 0,
            symbols: ["container_query_create"]
        ))
        let fileURL = try synth.writeToTempFile(data: binData)
        tempFiles.append(fileURL)
        
        let attrPre = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        let sizePre = attrPre[.size] as? UInt64
        let mtimePre = attrPre[.modificationDate] as? Date
        
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.test.readonly",
            appGroups: ["group.com.test"]
        )
        _ = try MachOScanner.shared.scan(binaryURL: fileURL, context: ctx)
        
        let attrPost = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        let sizePost = attrPost[.size] as? UInt64
        let mtimePost = attrPost[.modificationDate] as? Date
        
        XCTAssertEqual(sizePre, sizePost)
        XCTAssertEqual(mtimePre, mtimePost)
    }

    // MARK: - Universal FAT Binary Direct Scanning Tests
    
    func testMachOScanner_UniversalFatBinary_DirectScan_Arm64SliceSelectedAndFlaggedHighRisk() throws {
        let synth = SyntheticMachOGenerator.shared
        let arm64Config = SyntheticMachOGenerator.MachOConfig(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["container_query_create"]
        )
        let x86Config = SyntheticMachOGenerator.MachOConfig(
            arch: .x86_64,
            cryptid: 0,
            symbols: ["_clean_main"]
        )
        let fatData = synth.generateUniversalFAT(configs: [arm64Config, x86Config])
        
        // Direct parseMachO on Universal FAT binary
        let details = try MachOScanner.shared.parseMachO(data: fatData)
        XCTAssertEqual(details.cryptid, 0)
        XCTAssertFalse(details.isFairPlayEncrypted)
        XCTAssertTrue(details.linkedDylibs.contains("/usr/lib/system/libsystem_containermanager.dylib"))
        XCTAssertTrue(details.symbols.contains("container_query_create"))
        
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.test.fatbinary",
            appGroups: ["group.com.test.fatbinary"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        XCTAssertEqual(finding.riskTier, RiskTier.highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "container_query_create" })
        XCTAssertTrue(finding.indicators.contains { $0.signature == "libsystem_containermanager.dylib" })
    }

    func testMachOScanner_UniversalFatBinary_ScanBinaryURL_Succeeds() throws {
        let synth = SyntheticMachOGenerator.shared
        let arm64Config = SyntheticMachOGenerator.MachOConfig(
            arch: .arm64,
            cryptid: 0,
            symbols: ["container_query_set_group_identifiers"]
        )
        let x86Config = SyntheticMachOGenerator.MachOConfig(
            arch: .x86_64,
            cryptid: 0,
            symbols: ["_clean_main"]
        )
        let fatData = synth.generateUniversalFAT(configs: [arm64Config, x86Config])
        let tempURL = try synth.writeToTempFile(data: fatData)
        tempFiles.append(tempURL)
        
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.test.faturl",
            appGroups: ["group.com.test.faturl"]
        )
        let finding = try MachOScanner.shared.scan(binaryURL: tempURL, context: ctx)
        XCTAssertEqual(finding.riskTier, RiskTier.highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "container_query_set_group_identifiers" })
    }
}
