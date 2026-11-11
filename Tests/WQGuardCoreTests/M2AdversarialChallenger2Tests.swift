//
//  M2AdversarialChallenger2Tests.swift
//  WQGuardCoreTests
//
//  Milestone 2 Adversarial Challenge Suite:
//  1. Detection Precision:
//     - Target dylib (libsystem_containermanager.dylib in LC_LOAD_DYLIB & LC_LOAD_WEAK_DYLIB)
//     - 8 Private containermanager API symbols (container_query_create, etc.)
//     - Direct XPC service bypass strings (com.apple.containermanagerd[.system])
//     - APFS inode brute-force primitives (fsgetpath alone and with container prefixes)
//     - Dynamic loading alone (dlopen/dlsym -> Caution)
//     - Behavioral tuple (cryptid 0 + AppGroups + dlopen/dlsym + symlink/sandbox -> High Risk)
//     - Known tool whitelisting (Erosion, WQFiles -> Known Tool, spoofing rejection, disable rule)
//  2. Fast-Path Gating Invariant:
//     - Benign apps lacking App Groups MUST be gated out as Safe without flagging symbols
//  3. 100% Read-Only Safety:
//     - Bit-for-bit SHA256 checksums, st_mtimespec (sec & nsec), and read-only file permissions
//

import XCTest
import Foundation
import MachO
import CryptoKit
@testable import WQGuardCore

final class M2AdversarialChallenger2Tests: XCTestCase {

    private var tempFiles: [URL] = []

    override func setUp() {
        super.setUp()
        WhitelistEngine.shared.resetToDefaults()
    }

    override func tearDown() {
        for url in tempFiles {
            // Restore write permissions if modified during read-only tests so removeItem works
            chmod(url.path, 0o777)
            try? FileManager.default.removeItem(at: url)
        }
        tempFiles.removeAll()
        WhitelistEngine.shared.resetToDefaults()
        super.tearDown()
    }

    private func createTempFile(name: String, data: Data) throws -> URL {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("WQGuard_M2_Challenger_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        tempFiles.append(tempDir)
        let fileURL = tempDir.appendingPathComponent(name)
        try data.write(to: fileURL)
        return fileURL
    }

    // MARK: - Challenge 1: Detection Precision (Target Signatures)

    /// 1.1 Target Dylib Detection: LC_LOAD_DYLIB & LC_LOAD_WEAK_DYLIB
    func test_C1_targetDylib_LC_LOAD_DYLIB_and_WEAK_FlaggedHighRisk() throws {
        let dylibPath = "/usr/lib/system/libsystem_containermanager.dylib"

        // Case A: LC_LOAD_DYLIB
        let dataNormal = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: [dylibPath]
        ))
        let detailsNormal = try MachOScanner.shared.parseMachO(data: dataNormal)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.adversary.dylib.normal",
            appGroups: ["group.com.adversary.shared"]
        )
        let findingNormal = MachOScanner.shared.scan(details: detailsNormal, context: ctx)

        XCTAssertEqual(findingNormal.riskTier, .highRisk, "Direct linkage to libsystem_containermanager.dylib must trigger High Risk")
        XCTAssertTrue(findingNormal.indicators.contains { $0.signature == "libsystem_containermanager.dylib" })
        XCTAssertTrue(findingNormal.evidence.linkedDylibs.contains(dylibPath))

        // Case B: LC_LOAD_WEAK_DYLIB
        let dataWeak = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            weakDylibs: [dylibPath]
        ))
        let detailsWeak = try MachOScanner.shared.parseMachO(data: dataWeak)
        let findingWeak = MachOScanner.shared.scan(details: detailsWeak, context: ctx)

        XCTAssertEqual(findingWeak.riskTier, .highRisk, "Weak linkage to libsystem_containermanager.dylib must trigger High Risk")
        XCTAssertTrue(findingWeak.indicators.contains { $0.signature == "libsystem_containermanager.dylib" })

        // Case C: Benign Dylibs (UIKit, Foundation, libSystem.B.dylib)
        let dataBenign = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: [
                "/usr/lib/libSystem.B.dylib",
                "/System/Library/Frameworks/Foundation.framework/Foundation",
                "/System/Library/Frameworks/UIKit.framework/UIKit"
            ]
        ))
        let detailsBenign = try MachOScanner.shared.parseMachO(data: dataBenign)
        let findingBenign = MachOScanner.shared.scan(details: detailsBenign, context: ctx)

        XCTAssertEqual(findingBenign.riskTier, .safe, "Standard system frameworks must not trigger High Risk or Caution")
        XCTAssertTrue(findingBenign.indicators.isEmpty)
    }

    /// 1.2 The 8 Private Exploit Symbols: Individual Verification
    func test_C1_allEightPrivateSymbols_IndividuallyFlaggedHighRisk() throws {
        let eightSymbols = [
            "container_query_create",
            "container_query_set_group_identifiers",
            "container_query_operation_set_part",
            "container_query_operation_set_flags",
            "container_copy_sandbox_token",
            "sandbox_extension_consume",
            "container_query_get_single_result",
            "container_query_iterate_results_sync"
        ]

        let ctx = MachOScanner.ScanContext(
            bundleId: "com.adversary.exploit",
            appGroups: ["group.com.adversary.shared"]
        )

        for sym in eightSymbols {
            // Test without leading underscore
            let data1 = SyntheticMachOGenerator.shared.generateThin(config: .init(
                cryptid: 0,
                symbols: [sym]
            ))
            let details1 = try MachOScanner.shared.parseMachO(data: data1)
            let finding1 = MachOScanner.shared.scan(details: details1, context: ctx)

            XCTAssertEqual(finding1.riskTier, .highRisk, "Symbol '\(sym)' must trigger High Risk")
            XCTAssertTrue(finding1.indicators.contains { $0.signature == sym }, "Finding must contain indicator for '\(sym)'")
            XCTAssertTrue(finding1.evidence.matchedSymbols.contains(sym))

            // Test with leading underscore (as emitted by Darwin C compiler: _container_query_create)
            let mangledSym = "_\(sym)"
            let data2 = SyntheticMachOGenerator.shared.generateThin(config: .init(
                cryptid: 0,
                symbols: [mangledSym]
            ))
            let details2 = try MachOScanner.shared.parseMachO(data: data2)
            let finding2 = MachOScanner.shared.scan(details: details2, context: ctx)

            XCTAssertEqual(finding2.riskTier, .highRisk, "Mangled symbol '\(mangledSym)' must trigger High Risk")
            XCTAssertTrue(finding2.indicators.contains { $0.signature == sym }, "Finding must match canonical signature for '\(mangledSym)'")
        }
    }

    /// 1.3 Full Combination of all 8 Exploit Symbols
    func test_C1_combinedAllEightSymbols_AllDetectedSimultaneously() throws {
        let eightSymbols = [
            "container_query_create",
            "container_query_set_group_identifiers",
            "container_query_operation_set_part",
            "container_query_operation_set_flags",
            "container_copy_sandbox_token",
            "sandbox_extension_consume",
            "container_query_get_single_result",
            "container_query_iterate_results_sync"
        ]
        let data = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: eightSymbols
        ))
        let details = try MachOScanner.shared.parseMachO(data: data)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.adversary.fullworsequery",
            appGroups: ["group.com.adversary.shared"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)

        XCTAssertEqual(finding.riskTier, .highRisk)
        for sym in eightSymbols {
            XCTAssertTrue(finding.indicators.contains { $0.signature == sym }, "Missing detection of \(sym)")
        }
        XCTAssertEqual(finding.indicators.count, 8)
    }

    /// 1.4 Direct XPC Bypass Detection (com.apple.containermanagerd[.system])
    func test_C1_directXPCBypass_StringSignature_FlaggedHighRisk() throws {
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.adversary.xpc",
            appGroups: ["group.com.adversary.shared"]
        )

        // Case A: com.apple.containermanagerd
        let parsedA = MachOScanner.ParsedBinaryDetails(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textStrings: ["com.apple.containermanagerd"],
            isFairPlayEncrypted: false
        )
        let findingA = MachOScanner.shared.scan(details: parsedA, context: ctx)
        XCTAssertEqual(findingA.riskTier, .highRisk, "Direct XPC service com.apple.containermanagerd must trigger High Risk")
        XCTAssertTrue(findingA.indicators.contains { $0.signature == "com.apple.containermanagerd" })

        // Case B: com.apple.containermanagerd.system
        let parsedB = MachOScanner.ParsedBinaryDetails(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textStrings: ["com.apple.containermanagerd.system"],
            isFairPlayEncrypted: false
        )
        let findingB = MachOScanner.shared.scan(details: parsedB, context: ctx)
        XCTAssertEqual(findingB.riskTier, .highRisk, "Direct XPC service com.apple.containermanagerd.system must trigger High Risk")
        XCTAssertTrue(findingB.indicators.contains { $0.signature == "com.apple.containermanagerd.system" })
    }

    /// 1.5 APFS Inode Brute-Force Primitive (fsgetpath)
    func test_C1_fsgetpath_Alone_and_CombinedWithContainerPrefix() throws {
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.adversary.pathleak",
            appGroups: ["group.com.adversary.shared"]
        )

        // Case A: fsgetpath alone
        let dataAlone = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["fsgetpath"]
        ))
        let detailsAlone = try MachOScanner.shared.parseMachO(data: dataAlone)
        let findingAlone = MachOScanner.shared.scan(details: detailsAlone, context: ctx)

        XCTAssertEqual(findingAlone.riskTier, .highRisk)
        XCTAssertTrue(findingAlone.indicators.contains { $0.signature == "fsgetpath" })
        XCTAssertTrue(findingAlone.evidence.pathEnumerationPresent)

        // Case B: fsgetpath combined with /Containers/Data/ string
        let detailsCombined = MachOScanner.ParsedBinaryDetails(
            cryptid: 0,
            linkedDylibs: [],
            symbols: ["fsgetpath"],
            textStrings: ["/Containers/Data/"],
            isFairPlayEncrypted: false
        )
        let findingCombined = MachOScanner.shared.scan(details: detailsCombined, context: ctx)

        XCTAssertEqual(findingCombined.riskTier, .highRisk)
        XCTAssertTrue(findingCombined.indicators.contains { $0.signature.starts(with: "fsgetpath:") })
        XCTAssertTrue(findingCombined.evidence.pathEnumerationPresent)
    }

    /// 1.6 Dynamic Loading Alone (dlopen + dlsym) -> Caution
    func test_C1_dynamicLoadingAlone_TriggersCaution() throws {
        let data = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["dlopen", "dlsym", "_main"]
        ))
        let details = try MachOScanner.shared.parseMachO(data: data)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.example.pluginapp",
            appGroups: ["group.com.example.shared"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)

        XCTAssertEqual(finding.riskTier, .caution, "App Group + dynamic loading (dlopen/dlsym) without exploit symbols must trigger Caution")
        XCTAssertTrue(finding.indicators.contains { $0.signature == "dlopen+dlsym" })
        XCTAssertTrue(finding.evidence.dynamicLoadingPresent)
        XCTAssertFalse(finding.evidence.pathEnumerationPresent)
    }

    /// 1.7 Dynamic Loading Incomplete (dlopen alone or dlsym alone) -> Safe
    func test_C1_dynamicLoadingIncomplete_RemainsSafe() throws {
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.example.singleapp",
            appGroups: ["group.com.example.shared"]
        )

        // dlopen alone
        let data1 = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptid: 0, symbols: ["dlopen"]))
        let details1 = try MachOScanner.shared.parseMachO(data: data1)
        let finding1 = MachOScanner.shared.scan(details: details1, context: ctx)
        XCTAssertEqual(finding1.riskTier, .safe, "dlopen alone without dlsym must not trigger Caution")

        // dlsym alone
        let data2 = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptid: 0, symbols: ["dlsym"]))
        let details2 = try MachOScanner.shared.parseMachO(data: data2)
        let finding2 = MachOScanner.shared.scan(details: details2, context: ctx)
        XCTAssertEqual(finding2.riskTier, .safe, "dlsym alone without dlopen must not trigger Caution")
    }

    /// 1.8 Obfuscated Behavioral Tuple: AppGroups + dlopen/dlsym + symlink -> High Risk
    func test_C1_behavioralTuple_AppGroups_dlopen_symlink_TriggersHighRisk() throws {
        let data = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["dlopen", "dlsym", "symlink"]
        ))
        let details = try MachOScanner.shared.parseMachO(data: data)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.stealth.exploit",
            appGroups: ["group.com.stealth.shared"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)

        XCTAssertEqual(finding.riskTier, .highRisk, "Behavioral Tuple (App Groups + dlopen/dlsym + symlink) must trigger High Risk")
        XCTAssertTrue(finding.indicators.contains { $0.category == "Heuristic / Behavioral Tuple" })
    }

    /// 1.9 Whitelisted Tools (Erosion, WQFiles) vs Bundle ID Spoofing
    func test_C1_whitelistKnownTools_Erosion_and_WQFiles() throws {
        // Case A: Authentic Erosion with App Group
        let dataErosion = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["container_query_create", "container_copy_sandbox_token"]
        ))
        let detailsErosion = try MachOScanner.shared.parseMachO(data: dataErosion)
        let ctxErosion = MachOScanner.ScanContext(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        let findingErosion = MachOScanner.shared.scan(details: detailsErosion, context: ctxErosion)

        XCTAssertEqual(findingErosion.riskTier, .knownTool, "Authentic Erosion must be classified as Known Tool")
        XCTAssertTrue(findingErosion.isWhitelisted)
        XCTAssertEqual(findingErosion.whitelistedToolName, "Erosion")

        // Case B: Authentic WQFiles with App Group
        let ctxWQFiles = MachOScanner.ScanContext(
            bundleId: "cz.kolbi.wqfiles",
            appGroups: ["group.cz.kolbi.wqfiles"]
        )
        let findingWQFiles = MachOScanner.shared.scan(details: detailsErosion, context: ctxWQFiles)

        XCTAssertEqual(findingWQFiles.riskTier, .knownTool, "Authentic WQFiles must be classified as Known Tool")
        XCTAssertTrue(findingWQFiles.isWhitelisted)
        XCTAssertEqual(findingWQFiles.whitelistedToolName, "WQFiles")

        // Case C: Bundle ID Spoofing (Bundle ID matches Erosion, but App Group is unauthorized)
        let ctxSpoof = MachOScanner.ScanContext(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.attacker.evilgroup"]
        )
        let findingSpoof = MachOScanner.shared.scan(details: detailsErosion, context: ctxSpoof)

        XCTAssertEqual(findingSpoof.riskTier, .highRisk, "Spoofed Erosion bundle ID with wrong App Group MUST NOT be whitelisted!")
        XCTAssertFalse(findingSpoof.isWhitelisted)
        XCTAssertNil(findingSpoof.whitelistedToolName)

        // Case D: Whitelist Rule Toggled Off
        WhitelistEngine.shared.toggleTool(named: "Erosion", isEnabled: false)
        let findingDisabled = MachOScanner.shared.scan(details: detailsErosion, context: ctxErosion)

        XCTAssertEqual(findingDisabled.riskTier, .highRisk, "When Erosion whitelist rule is disabled, app must revert to High Risk")
        XCTAssertFalse(findingDisabled.isWhitelisted)
    }

    // MARK: - Challenge 2: Fast-Path Gating Invariant

    /// 2.1 Fast-Path Gating Invariant: Benign App Without App Group Entitlement
    func test_C2_fastPathGatingInvariant_NoAppGroups_MustBeGatedOutImmediatelyAsSafe() throws {
        // Construct binary containing ALL exploit signatures simultaneously:
        // - libsystem_containermanager.dylib
        // - all 8 exploit symbols
        // - com.apple.containermanagerd
        // - fsgetpath
        // - dlopen / dlsym
        let allSignatures = [
            "container_query_create",
            "container_query_set_group_identifiers",
            "container_query_operation_set_part",
            "container_query_operation_set_flags",
            "container_copy_sandbox_token",
            "sandbox_extension_consume",
            "container_query_get_single_result",
            "container_query_iterate_results_sync",
            "fsgetpath",
            "dlopen",
            "dlsym"
        ]
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: allSignatures
        ))

        // A: Application with no App Group entitlement (empty array)
        let ctxNoGroups = MachOScanner.ScanContext(
            bundleId: "com.example.calculator",
            displayName: "Calculator",
            appGroups: [] // NO APP GROUPS
        )

        let details = try MachOScanner.shared.parseMachO(data: binaryData)
        let finding = MachOScanner.shared.scan(details: details, context: ctxNoGroups)

        XCTAssertEqual(finding.riskTier, .safe, "CRITICAL INVARIANT: App without App Group entitlement MUST be gated out as Safe")
        XCTAssertTrue(finding.indicators.isEmpty, "Gated out app MUST have zero threat indicators")
        XCTAssertFalse(finding.isWhitelisted)
        XCTAssertFalse(finding.evidence.hasAppGroups)
        XCTAssertTrue(finding.evidence.remediationGuidance.contains("Layer 1 Fast-Path Gated"))

        // B: App with whitespace-only App Group
        let ctxWhitespace = MachOScanner.ScanContext(
            bundleId: "com.example.notes",
            appGroups: ["   ", "\t\n"]
        )
        let findingWhitespace = MachOScanner.shared.scan(details: details, context: ctxWhitespace)
        XCTAssertEqual(findingWhitespace.riskTier, .safe)
        XCTAssertTrue(findingWhitespace.indicators.isEmpty)

        // C: EntitlementGating direct evaluation
        let gatingDirect = EntitlementGating.evaluate(hasAppGroups: false, appGroups: [])
        XCTAssertTrue(gatingDirect.isGatedOut)
        XCTAssertEqual(gatingDirect.riskTier, .safe)
        XCTAssertFalse(gatingDirect.shouldProceedToDeepScan)
    }

    /// 2.2 CSBlob Entitlement Extraction Gating Test
    func test_C2_CSBlobParser_ExtractionGatingInvariant() throws {
        // Binary with valid XML entitlements declaring App Group
        let xmlWithGroup = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.acme.vault"])
        let machoWithGroup = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: xmlWithGroup
        ))
        let (hasGroup1, groups1) = CSBlobParser.shared.extractAppGroups(fromMachO: machoWithGroup)
        XCTAssertTrue(hasGroup1)
        XCTAssertEqual(groups1, ["group.com.acme.vault"])

        let gating1 = EntitlementGating.evaluate(hasAppGroups: hasGroup1, appGroups: groups1)
        XCTAssertFalse(gating1.isGatedOut)
        XCTAssertTrue(gating1.shouldProceedToDeepScan)

        // Binary with empty XML entitlements (no App Group)
        let xmlNoGroup = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>get-task-allow</key>
            <true/>
        </dict>
        </plist>
        """
        let machoNoGroup = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: xmlNoGroup
        ))
        let (hasGroup2, groups2) = CSBlobParser.shared.extractAppGroups(fromMachO: machoNoGroup)
        XCTAssertFalse(hasGroup2)
        XCTAssertTrue(groups2.isEmpty)

        let gating2 = EntitlementGating.evaluate(hasAppGroups: hasGroup2, appGroups: groups2)
        XCTAssertTrue(gating2.isGatedOut)
        XCTAssertEqual(gating2.riskTier, .safe)
        XCTAssertFalse(gating2.shouldProceedToDeepScan)
    }

    // MARK: - Challenge 3: 100% Read-Only Safety & Checksum Invariant

    /// 3.1 Bit-for-bit SHA256 checksum and nanosecond mtimespec stability across scans
    func test_C3_bitForBitSHA256AndMTimeInvariantAcrossScans() throws {
        // 1. Generate real synthetic Mach-O binary file on disk
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["container_query_create", "dlopen", "dlsym"]
        ))
        let binaryURL = try createTempFile(name: "TestTargetBinary", data: binaryData)

        // 2. Capture initial bit-for-bit state
        let initialData = try Data(contentsOf: binaryURL)
        let initialSHA256 = SHA256.hash(data: initialData).compactMap { String(format: "%02x", $0) }.joined()

        var initialStat = stat()
        XCTAssertEqual(lstat(binaryURL.path, &initialStat), 0)
        let initialMtimeSec = initialStat.st_mtimespec.tv_sec
        let initialMtimeNsec = initialStat.st_mtimespec.tv_nsec
        let initialSize = initialStat.st_size

        let beforeSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [binaryURL])

        // 3. Perform intensive repeated scans through all pipeline interfaces
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.test.readonly",
            appGroups: ["group.com.test.readonly"]
        )

        for _ in 0..<50 {
            // A. MachOParser
            let parsedFile = try MachOParser.parse(url: binaryURL)
            XCTAssertEqual(parsedFile.cryptid, 0)
            XCTAssertTrue(parsedFile.linksContainermanager)

            // B. CSBlobParser
            let fileData = try Data(contentsOf: binaryURL)
            _ = CSBlobParser.shared.extractAppGroups(fromMachO: fileData)

            // C. MachOScanner via file URL
            let finding = try MachOScanner.shared.scan(binaryURL: binaryURL, context: ctx)
            XCTAssertEqual(finding.riskTier, .highRisk)

            // D. EntitlementGating
            _ = EntitlementGating.evaluate(hasAppGroups: true, appGroups: ctx.appGroups)
        }

        // 4. Capture after snapshot and verify bit-for-bit invariants
        let afterSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [binaryURL])
        ReadOnlyAssertions.assertUnmodified(before: beforeSnapshot, after: afterSnapshot)

        // 5. Explicit SHA256 and nanosecond verification
        let finalData = try Data(contentsOf: binaryURL)
        let finalSHA256 = SHA256.hash(data: finalData).compactMap { String(format: "%02x", $0) }.joined()

        var finalStat = stat()
        XCTAssertEqual(lstat(binaryURL.path, &finalStat), 0)

        XCTAssertEqual(initialSHA256, finalSHA256, "Binary SHA256 hash mutated during scanning — violation of 100% read-only invariant!")
        XCTAssertEqual(initialSize, finalStat.st_size, "File size mutated")
        XCTAssertEqual(initialMtimeSec, finalStat.st_mtimespec.tv_sec, "Timestamp tv_sec mutated")
        XCTAssertEqual(initialMtimeNsec, finalStat.st_mtimespec.tv_nsec, "Timestamp tv_nsec mutated")
    }

    /// 3.2 Scanning on Read-Only Filesystem Objects (0444 file and 0555 directory permissions)
    func test_C3_scanSucceedsOnReadOnlyFilesystemObjects() throws {
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["container_query_create"]
        ))
        let binaryURL = try createTempFile(name: "ReadOnlyExecutable", data: binaryData)
        let parentDir = binaryURL.deletingLastPathComponent()

        // Make file strictly read-only: r--r--r-- (0444)
        XCTAssertEqual(chmod(binaryURL.path, 0o444), 0)
        // Make directory strictly read-only: r-xr-xr-x (0555 - cannot create/delete files inside)
        XCTAssertEqual(chmod(parentDir.path, 0o555), 0)

        // Verify that scanning succeeds completely without needing write privileges
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.test.readonlyperm",
            appGroups: ["group.com.test.readonlyperm"]
        )

        XCTAssertNoThrow(try {
            let parsed = try MachOParser.parse(url: binaryURL)
            XCTAssertTrue(parsed.containsSymbol("container_query_create"))

            let finding = try MachOScanner.shared.scan(binaryURL: binaryURL, context: ctx)
            XCTAssertEqual(finding.riskTier, .highRisk)
        }())
    }

    /// 3.3 Target Directory Integrity (Zero File Creation or Mutation)
    func test_C3_directoryTreeRemainsBitForBitIdentical() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("WQGuard_DirTree_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        tempFiles.append(tempDir)

        // Populate multiple files
        let bin1 = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptid: 0, symbols: ["container_query_create"]))
        let bin2 = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptid: 1, symbols: ["dlopen"]))
        let dummyInfo = "<plist><dict><key>CFBundleIdentifier</key><string>com.test.app</string></dict></plist>".data(using: .utf8)!

        let subDir = tempDir.appendingPathComponent("SubDir")
        try FileManager.default.createDirectory(at: subDir, withIntermediateDirectories: true)

        try bin1.write(to: tempDir.appendingPathComponent("App1"))
        try bin2.write(to: subDir.appendingPathComponent("App2"))
        try dummyInfo.write(to: tempDir.appendingPathComponent("Info.plist"))

        let beforeSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [tempDir])

        // Perform scans across files in directory
        let ctx = MachOScanner.ScanContext(bundleId: "com.test.app", appGroups: ["group.com.test.group"])
        _ = try MachOScanner.shared.scan(binaryURL: tempDir.appendingPathComponent("App1"), context: ctx)
        _ = try MachOScanner.shared.scan(binaryURL: subDir.appendingPathComponent("App2"), context: ctx)

        let afterSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [tempDir])
        ReadOnlyAssertions.assertUnmodified(before: beforeSnapshot, after: afterSnapshot)
    }

    /// 3.4 Multi-threaded Concurrent Scanning Read-Only Invariant
    func test_C3_concurrentMultiThreadedScanningBitForBitUnchanged() throws {
        let binaryData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["container_query_create", "dlopen", "dlsym"]
        ))
        let binaryURL = try createTempFile(name: "ConcurrentTestBinary", data: binaryData)
        let beforeSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [binaryURL])

        let ctx = MachOScanner.ScanContext(
            bundleId: "com.test.concurrent",
            appGroups: ["group.com.test.concurrent"]
        )

        let queue = DispatchQueue(label: "com.wqguard.test.concurrent", attributes: .concurrent)
        let group = DispatchGroup()

        for _ in 0..<30 {
            group.enter()
            queue.async {
                defer { group.leave() }
                do {
                    let finding = try MachOScanner.shared.scan(binaryURL: binaryURL, context: ctx)
                    XCTAssertEqual(finding.riskTier, .highRisk)
                } catch {
                    XCTFail("Concurrent scan failed with error: \(error)")
                }
            }
        }

        group.wait()

        let afterSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [binaryURL])
        ReadOnlyAssertions.assertUnmodified(before: beforeSnapshot, after: afterSnapshot)
    }

    // MARK: - Challenge 4: Behavioral Tuple Symlink Variants & Universal FAT

    /// 4.1 Behavioral Tuple: symlinkat and ObjC createSymbolicLinkAtPath variants
    func test_C4_behavioralTuple_SymlinkVariants_TriggerHighRisk() throws {
        let symlinkVariants = [
            "symlink",
            "symlinkat",
            "createSymbolicLinkAtPath:withDestinationPath:",
            "createSymbolicLinkAtPath"
        ]

        let ctx = MachOScanner.ScanContext(
            bundleId: "com.obfuscated.trojan",
            appGroups: ["group.com.obfuscated.group"]
        )

        for symlinkFunc in symlinkVariants {
            let data = SyntheticMachOGenerator.shared.generateThin(config: .init(
                cryptid: 0,
                symbols: ["dlopen", "dlsym", symlinkFunc]
            ))
            let details = try MachOScanner.shared.parseMachO(data: data)
            let finding = MachOScanner.shared.scan(details: details, context: ctx)

            XCTAssertEqual(
                finding.riskTier,
                .highRisk,
                "Behavioral tuple with symlink API '\(symlinkFunc)' must trigger High Risk"
            )
            XCTAssertTrue(
                finding.indicators.contains { $0.id == "TUPLE_OBFUSCATED_EXPLOIT" || $0.category == "Heuristic / Behavioral Tuple" },
                "Expected TUPLE_OBFUSCATED_EXPLOIT indicator for \(symlinkFunc)"
            )
        }
    }

    /// 4.2 Universal FAT Binary Slice Selection & Scanning
    func test_C4_universalFatBinary_SelectsArm64SliceAndFlagsHighRisk() throws {
        let arm64Config = SyntheticMachOGenerator.MachOConfig(
            arch: .arm64,
            cryptid: 0,
            symbols: ["container_query_create"]
        )
        let x86Config = SyntheticMachOGenerator.MachOConfig(
            arch: .x86_64,
            cryptid: 0,
            symbols: ["_clean_main"]
        )

        let fatData = SyntheticMachOGenerator.shared.generateUniversalFAT(configs: [arm64Config, x86Config])

        // 1. MachOParser correctly parses FAT binary, selects ARM64 primary slice, and locates symbol
        let parsedFat = try MachOParser.parse(data: fatData)
        XCTAssertEqual(parsedFat.architecture, MachOArchitecture.arm64, "On ARM64 host, primary slice must be arm64")
        XCTAssertTrue(parsedFat.containsSymbol("container_query_create"))

        // 2. Scan parsed slice data directly with MachOScanner
        let detailsFromSlice = try MachOScanner.shared.parseMachO(data: parsedFat.sliceData)
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.fat.test",
            appGroups: ["group.com.fat.test"]
        )
        let finding = MachOScanner.shared.scan(details: detailsFromSlice, context: ctx)

        XCTAssertEqual(finding.riskTier, RiskTier.highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "container_query_create" })

        // 3. Empirical check on MachOScanner.parseMachO direct FAT input:
        let directDetails = try MachOScanner.shared.parseMachO(data: fatData)
        let directFinding = MachOScanner.shared.scan(details: directDetails, context: ctx)
        XCTAssertEqual(directFinding.riskTier, RiskTier.highRisk)
        XCTAssertTrue(directFinding.indicators.contains { $0.signature == "container_query_create" })
    }

    /// 4.3 ASN.1 DER Entitlements Robustness & Malformed Recovery
    func test_C4_asn1DerEntitlements_ValidAndCorruptedHandledGracefully() throws {
        // Valid DER with multiple app groups
        let groups = ["group.corp.one", "group.corp.two"]
        let derData = SyntheticMachOGenerator.createDEREntitlements(appGroups: groups)
        let extracted = try CSBlobParser.shared.parseDERAppGroups(derData)
        XCTAssertEqual(Set(extracted), Set(groups))

        // Malformed DER 1: truncated byte stream throws malformedDER
        let truncatedDER = derData.prefix(6)
        XCTAssertThrowsError(try CSBlobParser.shared.parseDERAppGroups(truncatedDER)) { error in
            XCTAssertTrue(error is CSBlobError)
        }

        // Malformed DER 2: indefinite length 0x80 forbidden in DER
        var indefiniteDER = derData
        indefiniteDER[1] = 0x80
        XCTAssertThrowsError(try CSBlobParser.shared.parseDERAppGroups(indefiniteDER)) { error in
            XCTAssertTrue(error is CSBlobError)
        }

        // Malformed DER 3: length claims more octets than available
        var excessLengthDER = derData
        excessLengthDER[1] = 0x7f // claims 127 bytes, but buffer is much shorter
        XCTAssertThrowsError(try CSBlobParser.shared.parseDERAppGroups(excessLengthDER)) { error in
            XCTAssertTrue(error is CSBlobError)
        }

        // Unknown tag 0xff: ASN.1 parser handles gracefully as .other and extractAppGroups returns []
        var unknownTagDER = derData
        unknownTagDER[0] = 0xff
        let unknownTagGroups = (try? CSBlobParser.shared.parseDERAppGroups(unknownTagDER)) ?? []
        XCTAssertTrue(unknownTagGroups.isEmpty, "Unknown tags must gracefully yield empty App Groups without crash")
    }
}

