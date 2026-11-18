//
//  V130FeatureUnitTests.swift
//  WQGuardCoreTests
//
//  Comprehensive unit & integration tests for WQGuard v1.3.0:
//  - ARM64 inline `svc #0x80` direct syscall detection (`MachOParser` -> `MachOScanner` -> `IPAPackageScanner` / `SecurityPipeline`)
//  - App-Group-independent 2026 exploit primitives (AudioMxd CVE-2026-65339, BookRestore/bl_sbx, MobileGestalt tampering)
//  - AccessorySetupKit Bluetooth TCC bypass (CVE-2026-84493) on main bundles & embedded `.appex` extensions
//  - FairPlay partial-encryption bypass & FairPlay private-entitlement evaluation
//  - Cross-layer deduplication, `unencryptedTextStrings` propagation, anti-spoofing, and bilingual EN/ZH parity
//

import XCTest
import Foundation
import MachO
@testable import WQGuardCore

final class V130FeatureUnitTests: XCTestCase {

    private var tempFiles: [URL] = []

    override func setUp() {
        super.setUp()
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
    }

    override func tearDown() {
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
        for url in tempFiles {
            try? FileManager.default.removeItem(at: url)
        }
        tempFiles.removeAll()
        super.tearDown()
    }

    @discardableResult
    private func trackTempFile(_ url: URL) -> URL {
        tempFiles.append(url)
        return url
    }

    private func containsHanCharacters(_ text: String) -> Bool {
        text.unicodeScalars.contains { scalar in
            let v = scalar.value
            return (0x4E00...0x9FFF).contains(v)
                || (0x3400...0x4DBF).contains(v)
                || (0xF900...0xFAFF).contains(v)
                || (0x20000...0x2EBEF).contains(v)
        }
    }

    private func createTempDirectory(prefix: String = "v130_test") throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return trackTempFile(dir)
    }

    private func createAppBundle(
        in parentDir: URL,
        appName: String = "TestApp",
        bundleId: String = "com.example.v130",
        executableBinary: Data,
        extraInfoPlist: [String: Any] = [:],
        frameworks: [String: Data] = [:],
        dylibs: [String: Data] = [:],
        appExtensions: [(name: String, bundleId: String, binary: Data, extraInfoPlist: [String: Any], nestedFiles: [String: Data])] = [],
        isTestFlightReceipt: Bool = false
    ) throws -> URL {
        let appDir = parentDir.appendingPathComponent("\(appName).app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)

        var infoDict: [String: Any] = [
            "CFBundleIdentifier": bundleId,
            "CFBundleDisplayName": appName,
            "CFBundleName": appName,
            "CFBundleExecutable": appName,
            "CFBundleShortVersionString": "1.3.0",
            "CFBundleVersion": "17",
            "CFBundlePackageType": "APPL"
        ]
        for (k, v) in extraInfoPlist {
            infoDict[k] = v
        }
        let infoData = try PropertyListSerialization.data(fromPropertyList: infoDict, format: .xml, options: 0)
        try infoData.write(to: appDir.appendingPathComponent("Info.plist"))
        try executableBinary.write(to: appDir.appendingPathComponent(appName))

        if isTestFlightReceipt {
            let storeKitDir = appDir.appendingPathComponent("StoreKit")
            try FileManager.default.createDirectory(at: storeKitDir, withIntermediateDirectories: true)
            try Data("SANDBOX_RECEIPT".utf8).write(to: storeKitDir.appendingPathComponent("sandboxReceipt"))
        }

        for (relPath, data) in frameworks {
            let target = appDir.appendingPathComponent("Frameworks").appendingPathComponent(relPath)
            try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: target)
        }

        for (relPath, data) in dylibs {
            let target = appDir.appendingPathComponent("Dylibs").appendingPathComponent(relPath)
            try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: target)
        }

        for ext in appExtensions {
            let extDir = appDir.appendingPathComponent("PlugIns").appendingPathComponent("\(ext.name).appex")
            try FileManager.default.createDirectory(at: extDir, withIntermediateDirectories: true)
            var extInfo: [String: Any] = [
                "CFBundleIdentifier": ext.bundleId,
                "CFBundleDisplayName": ext.name,
                "CFBundleExecutable": ext.name,
                "CFBundlePackageType": "XPC!"
            ]
            for (k, v) in ext.extraInfoPlist {
                extInfo[k] = v
            }
            let extPlistData = try PropertyListSerialization.data(fromPropertyList: extInfo, format: .xml, options: 0)
            try extPlistData.write(to: extDir.appendingPathComponent("Info.plist"))
            try ext.binary.write(to: extDir.appendingPathComponent(ext.name))
            for (nestedRel, nestedData) in ext.nestedFiles {
                let nestedURL = extDir.appendingPathComponent(nestedRel)
                try FileManager.default.createDirectory(at: nestedURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                try nestedData.write(to: nestedURL)
            }
        }

        return appDir
    }

    private func zipAppBundle(_ appDir: URL, ipaName: String = "Package.ipa") throws -> URL {
        let stagingDir = try createTempDirectory(prefix: "v130_zip_stage")
        let payloadDir = stagingDir.appendingPathComponent("Payload")
        try FileManager.default.createDirectory(at: payloadDir, withIntermediateDirectories: true)
        let stagedApp = payloadDir.appendingPathComponent(appDir.lastPathComponent)
        try FileManager.default.copyItem(at: appDir, to: stagedApp)

        let outputIPA = trackTempFile(
            FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString)_\(ipaName)")
        )
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        process.currentDirectoryURL = stagingDir
        process.arguments = ["-q", "-r", outputIPA.path, "Payload"]
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0, "zip must succeed creating test IPA")
        return outputIPA
    }

    // MARK: - 1. MachOScanner: Direct Syscall (`svc #0x80`) & Backward Compatibility

    func test_machoScanner_parsedBinaryDetails_backwardCompatibleDefaults() {
        let details = MachOScanner.ParsedBinaryDetails(
            cryptid: 0,
            linkedDylibs: [],
            symbols: [],
            textStrings: [],
            isFairPlayEncrypted: false
        )
        XCTAssertEqual(details.directSyscallSites, [])
        XCTAssertEqual(details.directSyscallCount, 0)
    }

    func test_machoScanner_directSyscallSvc0x80_withoutAppGroups_cappedAt16Samples_flaggedHighRisk() throws {
        // 20 svc #0x80 instructions (0xD4001001) interspersed with benign nop/ret
        var instructions: [UInt32] = [0xD503201F] // nop
        instructions.append(contentsOf: Array(repeating: UInt32(0xD400_1001), count: 20))
        instructions.append(0xD65F03C0) // ret

        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: instructions
        ))
        let details = try MachOScanner.shared.parseMachO(data: bin)
        XCTAssertEqual(details.directSyscallCount, 20)
        XCTAssertEqual(details.directSyscallSites.count, 16, "Sample sites must be capped at 16")

        let finding = MachOScanner.shared.scan(
            details: details,
            context: .init(bundleId: "com.evil.directsvc", appGroups: [])
        )
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.evidence.matchedSymbols.contains("arm64:svc_0x80"))

        let site = try XCTUnwrap(details.directSyscallSites.first)
        let expectedLocation = "\(site.segmentName),\(site.sectionName) @ \(String(format: "0x%llx", site.virtualAddress)) (20x svc #0x80)"
        let indicator = try XCTUnwrap(finding.indicators.first { $0.signature == "arm64:svc_0x80" })
        XCTAssertEqual(indicator.location, expectedLocation)
        XCTAssertEqual(indicator.category, "Direct Syscall Evasion")
        XCTAssertEqual(indicator.severity, .highRisk)
    }

    func test_machoScanner_fakeCryptid1PartialEncryption_stillDetectsDirectSyscallOutsideEncryptedRange() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0x200,
            cryptsize: 0x100,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [0xD400_1001, 0xD65F03C0],
            extraCStringLiterals: [String(repeating: "A", count: 512)]
        ))
        let details = try MachOScanner.shared.parseMachO(data: bin)
        XCTAssertTrue(details.isFairPlayEncrypted)
        XCTAssertEqual(details.directSyscallCount, 1)

        let finding = MachOScanner.shared.scan(
            details: details,
            context: .init(bundleId: "com.spoof.fairplay", installChannel: .appStore, appGroups: [])
        )
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "arm64:svc_0x80" })
    }

    func test_machoScanner_benignInstructionsAndOtherSvcImmediate_remainSafe() throws {
        // svc #0x0 (0xD4000001), nop (0xD503201F), ret (0xD65F03C0) must NOT trigger svc #0x80
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"],
            textInstructions: [0xD503201F, 0xD400_0001, 0xD65F03C0]
        ))
        let details = try MachOScanner.shared.parseMachO(data: bin)
        XCTAssertEqual(details.directSyscallCount, 0)
        XCTAssertTrue(details.directSyscallSites.isEmpty)

        let finding = MachOScanner.shared.scan(
            details: details,
            context: .init(bundleId: "com.clean.instructions", appGroups: [])
        )
        XCTAssertEqual(finding.riskTier, .safe)
        XCTAssertTrue(finding.indicators.isEmpty)
    }

    // MARK: - 2. MachOScanner: App-Group-Independent 2026 Exploits & Anti-False-Positive Guards

    func test_machoScanner_standalone2026Exploits_bypassLayer1FastPathWithoutAppGroups() throws {
        // 1. Standalone Dylibs: MediaExperience.framework & BookLibraryPrivate.framework
        for (dylibPath, expectedSig) in [
            ("/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience", "CVE-2026-65339:MediaExperience.framework"),
            ("/System/Library/PrivateFrameworks/BookLibraryPrivate.framework/BookLibraryPrivate", "BookRestore:BookLibraryPrivate.framework")
        ] {
            let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: [dylibPath]
            ))
            let details = try MachOScanner.shared.parseMachO(data: bin)
            let finding = MachOScanner.shared.scan(details: details, context: .init(bundleId: "com.evil.dylib", appGroups: []))
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertTrue(finding.indicators.contains { $0.signature == expectedSig })
            XCTAssertTrue(finding.evidence.matchedSymbols.contains(expectedSig))
        }

        // 2. Standalone Symbols: _CMSessionSetProperty & AudioSessionSetCMProperty
        for (sym, expectedSig) in [
            ("_CMSessionSetProperty", "CVE-2026-65339:CMSessionSetProperty"),
            ("AudioSessionSetCMProperty", "CVE-2026-65339:AudioSessionSetCMProperty")
        ] {
            let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 0,
                symbols: [sym]
            ))
            let details = try MachOScanner.shared.parseMachO(data: bin)
            let finding = MachOScanner.shared.scan(details: details, context: .init(bundleId: "com.evil.sym", appGroups: []))
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertTrue(finding.indicators.contains { $0.signature == expectedSig })
            XCTAssertTrue(finding.evidence.matchedSymbols.contains(expectedSig))
        }

        // 3. All 8 Standalone String Rules via __TEXT,__cstring
        for (literal, rule) in SignatureCatalog.standaloneExploitStringRules {
            let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 0,
                extraCStringLiterals: [literal]
            ))
            let details = try MachOScanner.shared.parseMachO(data: bin)
            XCTAssertTrue(details.textStrings.contains(literal), "parseMachO must surface \(literal)")
            let finding = MachOScanner.shared.scan(details: details, context: .init(bundleId: "com.evil.str", appGroups: []))
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertTrue(finding.indicators.contains { $0.signature == rule.pattern && $0.location == "__TEXT: \(literal)" })
            XCTAssertTrue(finding.evidence.matchedSymbols.contains(rule.pattern))
        }
    }

    func test_machoScanner_legitimateEmulatorAudioFrameworks_remainSafe() throws {
        // Legitimate emulators (Delta, RetroArch, PPSSPP) link AudioToolbox/AVFAudio & call AudioOutputUnitStart/AURemoteIO
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: [
                "/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox",
                "/System/Library/Frameworks/AVFAudio.framework/AVFAudio"
            ],
            symbols: ["_AudioOutputUnitStart", "_AURemoteIO"]
        ))
        let details = try MachOScanner.shared.parseMachO(data: bin)
        let finding = MachOScanner.shared.scan(
            details: details,
            context: .init(bundleId: "com.rileytestut.Delta", displayName: "Delta", appGroups: [])
        )
        XCTAssertEqual(finding.riskTier, .safe)
        XCTAssertTrue(finding.indicators.isEmpty)
    }

    func test_machoScanner_fairPlayAppStoreMediaExperienceExempt_whileNonAppStoreFlagged() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            linkedDylibs: ["/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"]
        ))
        let details = try MachOScanner.shared.parseMachO(data: bin)

        let appStoreFinding = MachOScanner.shared.scan(
            details: details,
            context: .init(bundleId: "com.store.media", installChannel: .appStore, appGroups: [])
        )
        XCTAssertEqual(appStoreFinding.riskTier, .safe)

        let sideloadFinding = MachOScanner.shared.scan(
            details: details,
            context: .init(bundleId: "com.sideload.media", installChannel: .developerSideloaded, appGroups: [])
        )
        XCTAssertEqual(sideloadFinding.riskTier, .highRisk)
        XCTAssertTrue(sideloadFinding.indicators.contains { $0.signature == "CVE-2026-65339:MediaExperience.framework" })
    }

    func test_machoScanner_deduplicatesIdenticalSignatureAndLocation_andRejectsTrojanWQGuardSpoof() {
        let manualDetails = MachOScanner.ParsedBinaryDetails(
            cryptid: 0,
            linkedDylibs: [
                "/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience",
                "/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"
            ],
            symbols: ["_CMSessionSetProperty", "_CMSessionSetProperty"],
            textStrings: ["BLDatabaseManager.sqlite", "/var/tmp/BLDatabaseManager.sqlite"],
            isFairPlayEncrypted: false,
            directSyscallSites: [
                DirectSyscallSite(segmentName: "__TEXT", sectionName: "__text", fileOffset: 0x100, virtualAddress: 0x100000100, immediate: 0x80)
            ],
            directSyscallCount: 1
        )
        let finding = MachOScanner.shared.scan(
            details: manualDetails,
            context: .init(bundleId: "com.wqguard.app", displayName: "WQGuard", appGroups: ["group.com.wqguard.app"])
        )
        XCTAssertFalse(finding.isWhitelisted, "Trojanized com.wqguard.app carrying svc #0x80 / standalone exploits must NEVER be whitelisted")
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertEqual(finding.indicators.filter { $0.signature == "CVE-2026-65339:MediaExperience.framework" }.count, 1)
        XCTAssertEqual(finding.indicators.filter { $0.signature == "CVE-2026-65339:CMSessionSetProperty" }.count, 1)
        XCTAssertEqual(finding.indicators.filter { $0.signature == "BookRestore:BLDatabaseManager.sqlite" }.count, 1)
    }

    // MARK: - 3. ExpandedThreatCatalog Direct Unit Tests

    func test_expandedThreatCatalog_evaluateAudioMxdBypass_allVectorsAndFalsePositiveGuards() {
        // Explicit false placeholder ignored; non-matching audio APIs ignored
        let benign = ExpandedThreatCatalog.evaluateAudioMxdBypass(
            linkedDylibs: ["/System/Library/Frameworks/AVFAudio.framework/AVFAudio"],
            symbols: ["_AudioOutputUnitStart"],
            entitlements: ["com.apple.private.mediaexperience.allow": false],
            cryptid: 0
        )
        XCTAssertTrue(benign.isEmpty)

        // Entitlement still flagged when cryptid == 1, while binary dylib/symbol skipped
        let fairPlayEnt = ExpandedThreatCatalog.evaluateAudioMxdBypass(
            linkedDylibs: ["/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"],
            symbols: ["_CMSessionSetProperty"],
            entitlements: ["com.apple.private.cmsession.allow": true],
            cryptid: 1
        )
        XCTAssertEqual(fairPlayEnt.count, 1)
        XCTAssertEqual(fairPlayEnt.first?.signature, "CVE-2026-65339:com.apple.private.cmsession.allow")

        // Unencrypted detects entitlement + dylib + both symbols
        let full = ExpandedThreatCatalog.evaluateAudioMxdBypass(
            linkedDylibs: ["/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"],
            symbols: ["_CMSessionSetProperty", "_AudioSessionSetCMProperty"],
            entitlements: ["com.apple.private.mediaexperience.allow": true],
            cryptid: 0
        )
        XCTAssertEqual(full.count, 4)
        XCTAssertTrue(full.allSatisfy { $0.severity == .highRisk })
    }

    func test_expandedThreatCatalog_evaluateBookRestoreAndGestalt_allVectors() {
        let fairPlay = ExpandedThreatCatalog.evaluateBookRestoreAndGestalt(
            linkedDylibs: ["/System/Library/PrivateFrameworks/BookLibraryPrivate.framework/BookLibraryPrivate"],
            textStrings: ["BLDatabaseManager.sqlite", "com.apple.MobileGestalt.plist"],
            entitlements: [
                "com.apple.private.bookassetd.allow": true,
                "com.apple.private.MobileGestalt.allow": false,
                "com.apple.private.MobileGestalt.write": true
            ],
            cryptid: 1
        )
        XCTAssertEqual(Set(fairPlay.map(\.signature)), [
            "BookRestore:com.apple.private.bookassetd.allow",
            "MobileGestaltTamper:com.apple.private.MobileGestalt.write"
        ])

        let unencrypted = ExpandedThreatCatalog.evaluateBookRestoreAndGestalt(
            linkedDylibs: ["/System/Library/PrivateFrameworks/BookLibraryPrivate.framework/BookLibraryPrivate"],
            textStrings: ["downloads.28.sqlitedb", "systemgroup.com.apple.mobilegestaltcache"],
            entitlements: ["com.apple.itunesstored.private": true],
            cryptid: 0
        )
        XCTAssertEqual(Set(unencrypted.map(\.signature)), [
            "BookRestore:com.apple.itunesstored.private",
            "BookRestore:BookLibraryPrivate.framework",
            "BookRestore:downloads.28.sqlitedb",
            "MobileGestaltTamper:mobilegestaltcache"
        ])
    }

    func test_expandedThreatCatalog_evaluateAccessorySetupBypass_allBranches() {
        // App Store exempt
        let storeExempt = ExpandedThreatCatalog.evaluateAccessorySetupBypass(
            linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"],
            symbols: ["_OBJC_CLASS_$_ASAccessorySession"],
            infoPlist: [:],
            entitlements: ["com.apple.private.accessorysetupkit.allow": true],
            installChannel: .appStore,
            cryptid: 0
        )
        XCTAssertTrue(storeExempt.isEmpty)

        // Valid declarations -> clean
        let compliant = ExpandedThreatCatalog.evaluateAccessorySetupBypass(
            linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"],
            symbols: ["_OBJC_CLASS_$_ASAccessorySession"],
            infoPlist: [
                "NSBluetoothAlwaysUsageDescription": "Pair nearby hardware accessories",
                "NSAccessorySetupKitSupports": ["Bluetooth"]
            ],
            entitlements: ["com.apple.private.accessorysetupkit.allow": false],
            installChannel: .developerSideloaded,
            cryptid: 0
        )
        XCTAssertTrue(compliant.isEmpty)

        // Missing NSAccessorySetupKitSupports or whitespace NSBluetoothAlwaysUsageDescription -> flagged
        let bypass = ExpandedThreatCatalog.evaluateAccessorySetupBypass(
            linkedDylibs: [],
            symbols: ["_OBJC_CLASS_$_ASAccessorySession"],
            infoPlist: [
                "NSBluetoothAlwaysUsageDescription": "   ",
                "NSAccessorySetupKitSupports": []
            ],
            entitlements: ["com.apple.private.accessorysetupkit.bypass": true],
            installChannel: .developerSideloaded,
            cryptid: 0
        )
        XCTAssertEqual(Set(bypass.map(\.signature)), [
            "CVE-2026-84493:PrivateAccessoryEntitlement",
            "CVE-2026-84493:AccessorySetupKitBypass"
        ])
    }

    // MARK: - 4. SecurityPipeline.scanBundle & IPAPackageScanner.scan Integration

    func test_bundleAndIPA_nestedFrameworksAndAppex_propagateTextStrings_andDeduplicateCleanly() throws {
        let dir = try createTempDirectory(prefix: "v130_nested_dedup")

        let cleanMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"]
        ))
        // Nested framework carries BookRestore string + svc #0x80 (no App Groups)
        let evilFramework = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"],
            symbols: ["_CMSessionSetProperty"],
            textInstructions: [0xD400_1001],
            extraCStringLiterals: ["BLDatabaseManager.sqlite"]
        ))
        // Nested dylib inside PlugIns/Worker.appex carries MobileGestalt string
        let appexCleanExec = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"]
        ))
        let appexNestedDylib = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            extraCStringLiterals: ["com.apple.MobileGestalt.plist"]
        ))

        let appDir = try createAppBundle(
            in: dir,
            appName: "NestedHost",
            bundleId: "com.wqguard.app", // Also tests anti-spoofing against built-in WQGuard!
            executableBinary: cleanMain,
            frameworks: ["AudioBridge.framework/AudioBridge": evilFramework],
            appExtensions: [
                (
                    name: "Worker",
                    bundleId: "com.wqguard.app.worker",
                    binary: appexCleanExec,
                    extraInfoPlist: [:],
                    nestedFiles: ["Frameworks/GestaltHelper.dylib": appexNestedDylib]
                )
            ]
        )
        let ipaURL = try zipAppBundle(appDir, ipaName: "NestedHost.ipa")

        for finding in [try SecurityPipeline.shared.scanBundle(at: appDir), try IPAPackageScanner.shared.scan(ipaURL: ipaURL)] {
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertFalse(finding.isWhitelisted, "Trojanized com.wqguard.app with nested exploits must NEVER be whitelisted")

            let expectedSigs = [
                "arm64:svc_0x80",
                "CVE-2026-65339:MediaExperience.framework",
                "CVE-2026-65339:CMSessionSetProperty",
                "BookRestore:BLDatabaseManager.sqlite",
                "MobileGestaltTamper:com.apple.MobileGestalt.plist"
            ]
            for sig in expectedSigs {
                let matching = finding.indicators.filter { $0.signature == sig }
                XCTAssertEqual(matching.count, 1, "Expected exactly 1 deduplicated indicator for \(sig), got \(matching)")
                XCTAssertTrue(finding.evidence.matchedSymbols.contains(sig), "matchedSymbols must contain \(sig)")
            }

            let fwInd = try XCTUnwrap(finding.indicators.first { $0.signature == "BookRestore:BLDatabaseManager.sqlite" })
            XCTAssertTrue(fwInd.description.contains("[Frameworks/AudioBridge.framework/AudioBridge]"))
            XCTAssertTrue(fwInd.location.hasPrefix("Frameworks/AudioBridge.framework/AudioBridge:"))

            let appexDylibInd = try XCTUnwrap(finding.indicators.first { $0.signature == "MobileGestaltTamper:com.apple.MobileGestalt.plist" })
            XCTAssertTrue(appexDylibInd.description.contains("[PlugIns/Worker.appex/Frameworks/GestaltHelper.dylib]"))
        }
    }

    func test_bundleAndIPA_accessorySetupKit_mainAndAppex_isolationAndDetection() throws {
        let dir = try createTempDirectory(prefix: "v130_accessory")

        let cleanMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"]
        ))
        let accessoryBinary = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"],
            symbols: ["_OBJC_CLASS_$_ASAccessorySession"]
        ))

        // Case A: Main app uses AccessorySetupKit without Info.plist keys -> High Risk
        let mainBypassDir = try createAppBundle(
            in: dir,
            appName: "MainAccessoryBypass",
            bundleId: "com.wqguard.app",
            executableBinary: accessoryBinary
        )
        let mainBypassIPA = try zipAppBundle(mainBypassDir, ipaName: "MainAccessoryBypass.ipa")
        for finding in [try SecurityPipeline.shared.scanBundle(at: mainBypassDir), try IPAPackageScanner.shared.scan(ipaURL: mainBypassIPA)] {
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertFalse(finding.isWhitelisted)
            XCTAssertTrue(finding.indicators.contains { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" })
            XCTAssertTrue(finding.evidence.matchedSymbols.contains("CVE-2026-84493:AccessorySetupKitBypass"))
        }

        // Case B: Clean main app (no Bluetooth keys) + compliant .appex (HAS Bluetooth keys) -> Safe (no cross-contamination!)
        let compliantAppDir = try createAppBundle(
            in: dir,
            appName: "CompliantAppexHost",
            bundleId: "com.clean.accessory",
            executableBinary: cleanMain,
            appExtensions: [
                (
                    name: "PairExt",
                    bundleId: "com.clean.accessory.pair",
                    binary: accessoryBinary,
                    extraInfoPlist: [
                        "NSBluetoothAlwaysUsageDescription": "Pair supported hardware",
                        "NSAccessorySetupKitSupports": ["Bluetooth"]
                    ],
                    nestedFiles: [:]
                )
            ]
        )
        let compliantIPA = try zipAppBundle(compliantAppDir, ipaName: "CompliantAppexHost.ipa")
        for finding in [try SecurityPipeline.shared.scanBundle(at: compliantAppDir), try IPAPackageScanner.shared.scan(ipaURL: compliantIPA)] {
            XCTAssertEqual(finding.riskTier, .safe, "Compliant .appex must not cross-contaminate main bundle Info.plist check")
            XCTAssertTrue(finding.indicators.isEmpty)
        }

        // Case C: Main app has valid keys, while embedded .appex omits keys -> High Risk with [relPath]
        let sneakyDir = try createAppBundle(
            in: dir,
            appName: "SneakyAppexHost",
            bundleId: "com.sneaky.accessory",
            executableBinary: cleanMain,
            extraInfoPlist: [
                "NSBluetoothAlwaysUsageDescription": "Main app description",
                "NSAccessorySetupKitSupports": ["Bluetooth"]
            ],
            appExtensions: [
                (
                    name: "SneakyExt",
                    bundleId: "com.sneaky.accessory.ext",
                    binary: cleanMain,
                    extraInfoPlist: [:],
                    nestedFiles: ["Frameworks/BleKit.dylib": accessoryBinary]
                )
            ]
        )
        let sneakyIPA = try zipAppBundle(sneakyDir, ipaName: "SneakyAppexHost.ipa")
        for finding in [try SecurityPipeline.shared.scanBundle(at: sneakyDir), try IPAPackageScanner.shared.scan(ipaURL: sneakyIPA)] {
            XCTAssertEqual(finding.riskTier, .highRisk)
            let ind = try XCTUnwrap(finding.indicators.first { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" })
            XCTAssertTrue(ind.description.contains("[PlugIns/SneakyExt.appex/SneakyExt]"))
            XCTAssertTrue(ind.location.hasPrefix("PlugIns/SneakyExt.appex/SneakyExt:"))
        }
    }

    func test_bundleAndIPA_fairPlayEncryptedPrivateEntitlements_stillFlaggedHighRisk() throws {
        let dir = try createTempDirectory(prefix: "v130_fairplay_ent")
        let entXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.private.mediaexperience.allow</key>
            <true/>
            <key>com.apple.private.bookassetd.allow</key>
            <true/>
            <key>com.apple.private.MobileGestalt.allow</key>
            <true/>
            <key>com.apple.private.accessorysetupkit.allow</key>
            <true/>
        </dict>
        </plist>
        """
        let fairPlayBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            symbols: ["_main"],
            xmlEntitlements: entXML
        ))

        let appDir = try createAppBundle(
            in: dir,
            appName: "FairPlayPrivileged",
            bundleId: "com.testflight.privileged",
            executableBinary: fairPlayBin,
            isTestFlightReceipt: true
        )
        let ipaURL = try zipAppBundle(appDir, ipaName: "FairPlayPrivileged.ipa")

        for finding in [try SecurityPipeline.shared.scanBundle(at: appDir), try IPAPackageScanner.shared.scan(ipaURL: ipaURL)] {
            XCTAssertEqual(finding.installChannel, .testFlight)
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertTrue(finding.evidence.isFairPlayEncrypted)
            let sigs = Set(finding.indicators.map(\.signature))
            XCTAssertTrue(sigs.contains("CVE-2026-65339:com.apple.private.mediaexperience.allow"))
            XCTAssertTrue(sigs.contains("BookRestore:com.apple.private.bookassetd.allow"))
            XCTAssertTrue(sigs.contains("MobileGestaltTamper:com.apple.private.MobileGestalt.allow"))
            XCTAssertTrue(sigs.contains("CVE-2026-84493:PrivateAccessoryEntitlement"))
        }
    }

    // MARK: - 5. Bilingual EN/ZH Verification (Zero Han in English)

    func test_bilingualOutputs_englishZeroHan_and_chineseLocalized_acrossAllThreeEngines() throws {
        let dir = try createTempDirectory(prefix: "v130_bilingual")
        let svcBinary = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"],
            symbols: ["_CMSessionSetProperty"],
            textInstructions: [0xD400_1001],
            extraCStringLiterals: ["BLDatabaseManager.sqlite", "com.apple.MobileGestalt.plist"]
        ))
        let appDir = try createAppBundle(
            in: dir,
            appName: "BilingualExploit",
            bundleId: "com.test.bilingual",
            executableBinary: svcBinary
        )
        let ipaURL = try zipAppBundle(appDir, ipaName: "BilingualExploit.ipa")

        // 1. English Mode: zero Han leakage anywhere
        WQLocale.overrideLanguageCode = "en"
        let enMacho = try MachOScanner.shared.scan(binaryData: svcBinary, context: .init(bundleId: "com.test.bilingual"))
        let enBundle = try SecurityPipeline.shared.scanBundle(at: appDir)
        let enIPA = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        let enCatalog = ExpandedThreatCatalog.evaluateAccessorySetupBypass(
            linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"],
            symbols: [],
            infoPlist: [:],
            entitlements: ["com.apple.private.accessorysetupkit.allow": true],
            installChannel: .developerSideloaded,
            cryptid: 0
        )

        for finding in [enMacho, enBundle, enIPA] {
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertFalse(containsHanCharacters(finding.evidence.remediationGuidance), "English remediationGuidance contains Han: \(finding.evidence.remediationGuidance)")
            XCTAssertTrue(finding.evidence.remediationGuidance.contains("containermanagerd"))
            XCTAssertTrue(finding.evidence.remediationGuidance.contains("svc #0x80"))
            for ind in finding.indicators {
                XCTAssertFalse(containsHanCharacters(ind.description), "English indicator contains Han: \(ind.description)")
            }
        }
        for ind in enCatalog {
            XCTAssertFalse(containsHanCharacters(ind.description), "English catalog indicator contains Han: \(ind.description)")
        }

        // 2. Chinese Mode: Han localization present
        WQLocale.overrideLanguageCode = "zh-Hans"
        let zhMacho = try MachOScanner.shared.scan(binaryData: svcBinary, context: .init(bundleId: "com.test.bilingual"))
        let zhBundle = try SecurityPipeline.shared.scanBundle(at: appDir)
        let zhIPA = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        for finding in [zhMacho, zhBundle, zhIPA] {
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertTrue(containsHanCharacters(finding.evidence.remediationGuidance))
            XCTAssertTrue(finding.evidence.remediationGuidance.contains("containermanagerd"))
            XCTAssertTrue(finding.evidence.remediationGuidance.contains("svc #0x80"))
            for ind in finding.indicators {
                XCTAssertTrue(containsHanCharacters(ind.description), "Chinese indicator missing Han: \(ind.description)")
            }
        }
    }
}
