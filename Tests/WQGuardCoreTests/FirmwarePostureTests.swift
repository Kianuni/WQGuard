//
//  FirmwarePostureTests.swift
//  WQGuardCoreTests
//
//  Comprehensive test suite for FirmwarePostureEngine, SystemOSVersion parsing,
//  dual-branch version matrix evaluation, and actionable mitigations.
//

import XCTest
@testable import WQGuardCore

final class FirmwarePostureTests: XCTestCase {

    // MARK: - 1. Semantic Version Parsing & Comparison

    func testSemanticVersionParsing() {
        let v1 = SystemOSVersion(string: "26.2")
        XCTAssertNotNil(v1)
        XCTAssertEqual(v1?.major, 26)
        XCTAssertEqual(v1?.minor, 2)
        XCTAssertEqual(v1?.patch, 0)

        let v2 = SystemOSVersion(string: "26.7.2")
        XCTAssertNotNil(v2)
        XCTAssertEqual(v2?.major, 26)
        XCTAssertEqual(v2?.minor, 7)
        XCTAssertEqual(v2?.patch, 2)

        let v3 = SystemOSVersion(string: "iOS 27.2.1 (24C123)")
        XCTAssertNotNil(v3)
        XCTAssertEqual(v3?.major, 27)
        XCTAssertEqual(v3?.minor, 2)
        XCTAssertEqual(v3?.patch, 1)
        XCTAssertEqual(v3?.build, "24C123")

        let vInvalid = SystemOSVersion(string: "not_a_version")
        XCTAssertNil(vInvalid)
    }

    func testVersionComparisonOrder() {
        let v26_7_1 = SystemOSVersion(major: 26, minor: 7, patch: 1)
        let v26_7_2 = SystemOSVersion(major: 26, minor: 7, patch: 2)
        let v26_7_3 = SystemOSVersion(major: 26, minor: 7, patch: 3)
        let v27_0_0 = SystemOSVersion(major: 27, minor: 0, patch: 0)
        let v27_2_0 = SystemOSVersion(major: 27, minor: 2, patch: 0)
        let v27_2_1 = SystemOSVersion(major: 27, minor: 2, patch: 1)

        XCTAssertTrue(v26_7_1 < v26_7_2)
        XCTAssertTrue(v26_7_2 < v26_7_3)
        XCTAssertTrue(v26_7_3 < v27_0_0)
        XCTAssertTrue(v27_0_0 < v27_2_0)
        XCTAssertTrue(v27_2_0 < v27_2_1)
        XCTAssertFalse(v27_2_1 < v27_2_0)
        XCTAssertEqual(v26_7_2, SystemOSVersion(major: 26, minor: 7, patch: 2))
    }

    // MARK: - 2. Vulnerability Exposure Matrix

    func testWorseQuery0DayExposedUntilIOS27_3() {
        let engine = FirmwarePostureEngine.shared
        XCTAssertFalse(engine.isVulnerable(.worseQuery0day, in: SystemOSVersion(major: 25, minor: 9, patch: 9)))
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: SystemOSVersion(major: 26, minor: 0)))
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: SystemOSVersion(major: 26, minor: 7, patch: 3)))
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: SystemOSVersion(major: 27, minor: 0)))
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: SystemOSVersion(major: 27, minor: 2, patch: 1)))
        XCTAssertFalse(engine.isVulnerable(.worseQuery0day, in: SystemOSVersion(major: 27, minor: 3, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.worseQuery0day, in: SystemOSVersion(major: 28, minor: 0, patch: 0)))
    }

    func testBrotliVulnerabilityMatrix() {
        let engine = FirmwarePostureEngine.shared
        // Branch 26: Patched in 26.7.3
        XCTAssertTrue(engine.isVulnerable(.brotliOOB, in: SystemOSVersion(major: 26, minor: 7, patch: 2)))
        XCTAssertFalse(engine.isVulnerable(.brotliOOB, in: SystemOSVersion(major: 26, minor: 7, patch: 3)))

        // Branch 27: Patched in 27.2.1
        XCTAssertTrue(engine.isVulnerable(.brotliOOB, in: SystemOSVersion(major: 27, minor: 2, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.brotliOOB, in: SystemOSVersion(major: 27, minor: 2, patch: 1)))
    }

    func testPhotosBypassMatrix() {
        let engine = FirmwarePostureEngine.shared
        // Branch 26: Patched in 26.7.2
        XCTAssertTrue(engine.isVulnerable(.photosBypass, in: SystemOSVersion(major: 26, minor: 7, patch: 1)))
        XCTAssertFalse(engine.isVulnerable(.photosBypass, in: SystemOSVersion(major: 26, minor: 7, patch: 2)))

        // Branch 27: Patched in 27.2.0
        XCTAssertTrue(engine.isVulnerable(.photosBypass, in: SystemOSVersion(major: 27, minor: 1, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.photosBypass, in: SystemOSVersion(major: 27, minor: 2, patch: 0)))
    }

    func testCoreGraphics2DMatrix() {
        let engine = FirmwarePostureEngine.shared
        // Patched in iOS 27.0, iOS 26.7.1, and iOS 18.7.11
        XCTAssertTrue(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 18, minor: 7, patch: 10)))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 18, minor: 7, patch: 11)))
        XCTAssertTrue(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 26, minor: 7, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 26, minor: 7, patch: 1)))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 26, minor: 7, patch: 3)))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 27, minor: 0, patch: 0)))
    }

    func testCoreGraphicsPDFMatrix() {
        let engine = FirmwarePostureEngine.shared
        // Patched in 26.7.2 and 27.2.0
        XCTAssertTrue(engine.isVulnerable(.coreGraphicsPDF, in: SystemOSVersion(major: 26, minor: 7, patch: 1)))
        XCTAssertFalse(engine.isVulnerable(.coreGraphicsPDF, in: SystemOSVersion(major: 26, minor: 7, patch: 2)))
        XCTAssertTrue(engine.isVulnerable(.coreGraphicsPDF, in: SystemOSVersion(major: 27, minor: 1, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.coreGraphicsPDF, in: SystemOSVersion(major: 27, minor: 2, patch: 0)))
    }

    func testBluetoothAirPlayMatrix() {
        let engine = FirmwarePostureEngine.shared
        // Patched in 26.7.3 and 27.2.1
        XCTAssertTrue(engine.isVulnerable(.bluetoothAirPlay, in: SystemOSVersion(major: 26, minor: 7, patch: 2)))
        XCTAssertFalse(engine.isVulnerable(.bluetoothAirPlay, in: SystemOSVersion(major: 26, minor: 7, patch: 3)))
        XCTAssertTrue(engine.isVulnerable(.bluetoothAirPlay, in: SystemOSVersion(major: 27, minor: 2, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.bluetoothAirPlay, in: SystemOSVersion(major: 27, minor: 2, patch: 1)))
    }

    func testAudioMxdAndDyld2026Matrices() {
        let engine = FirmwarePostureEngine.shared
        // CVE-2026-65339 (AudioMxd): patched in 27.0, 26.6.1, 18.7.11
        XCTAssertTrue(engine.isVulnerable(.audioMxdBypass, in: SystemOSVersion(major: 18, minor: 7, patch: 10)))
        XCTAssertFalse(engine.isVulnerable(.audioMxdBypass, in: SystemOSVersion(major: 18, minor: 7, patch: 11)))
        XCTAssertTrue(engine.isVulnerable(.audioMxdBypass, in: SystemOSVersion(major: 26, minor: 6, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.audioMxdBypass, in: SystemOSVersion(major: 26, minor: 6, patch: 1)))
        XCTAssertFalse(engine.isVulnerable(.audioMxdBypass, in: SystemOSVersion(major: 27, minor: 0, patch: 0)))

        // CVE-2026-20700 (dyld): patched in 27.0, 26.3, 18.7.5
        XCTAssertTrue(engine.isVulnerable(.dyldZeroDay, in: SystemOSVersion(major: 18, minor: 7, patch: 4)))
        XCTAssertFalse(engine.isVulnerable(.dyldZeroDay, in: SystemOSVersion(major: 18, minor: 7, patch: 5)))
        XCTAssertTrue(engine.isVulnerable(.dyldZeroDay, in: SystemOSVersion(major: 26, minor: 2, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.dyldZeroDay, in: SystemOSVersion(major: 26, minor: 3, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.dyldZeroDay, in: SystemOSVersion(major: 27, minor: 0, patch: 0)))
    }

    func testWebKitAccessorySetupAndBookRestoreMatrices() {
        let engine = FirmwarePostureEngine.shared
        // CVE-2026-113897 (WebKit): patched in 27.2, 26.7.2
        XCTAssertTrue(engine.isVulnerable(.webkitSandboxEscape, in: SystemOSVersion(major: 26, minor: 7, patch: 1)))
        XCTAssertFalse(engine.isVulnerable(.webkitSandboxEscape, in: SystemOSVersion(major: 26, minor: 7, patch: 2)))
        XCTAssertTrue(engine.isVulnerable(.webkitSandboxEscape, in: SystemOSVersion(major: 27, minor: 1, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.webkitSandboxEscape, in: SystemOSVersion(major: 27, minor: 2, patch: 0)))

        // CVE-2026-84493 (AccessorySetupKit): patched in 27.2, 26.7.2 (iOS 18+ only)
        XCTAssertFalse(engine.isVulnerable(.accessorySetupBluetooth, in: SystemOSVersion(major: 17, minor: 6, patch: 0)))
        XCTAssertTrue(engine.isVulnerable(.accessorySetupBluetooth, in: SystemOSVersion(major: 18, minor: 0, patch: 0)))
        XCTAssertTrue(engine.isVulnerable(.accessorySetupBluetooth, in: SystemOSVersion(major: 26, minor: 7, patch: 1)))
        XCTAssertFalse(engine.isVulnerable(.accessorySetupBluetooth, in: SystemOSVersion(major: 26, minor: 7, patch: 2)))
        XCTAssertTrue(engine.isVulnerable(.accessorySetupBluetooth, in: SystemOSVersion(major: 27, minor: 1, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.accessorySetupBluetooth, in: SystemOSVersion(major: 27, minor: 2, patch: 0)))

        // PoC:BookRestore: patched in 27.0, 26.2 (iOS 18+ only)
        XCTAssertFalse(engine.isVulnerable(.bookRestoreEscape, in: SystemOSVersion(major: 17, minor: 6, patch: 0)))
        XCTAssertTrue(engine.isVulnerable(.bookRestoreEscape, in: SystemOSVersion(major: 18, minor: 0, patch: 0)))
        XCTAssertTrue(engine.isVulnerable(.bookRestoreEscape, in: SystemOSVersion(major: 26, minor: 1, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.bookRestoreEscape, in: SystemOSVersion(major: 26, minor: 2, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.bookRestoreEscape, in: SystemOSVersion(major: 27, minor: 0, patch: 0)))
    }

    // MARK: - 3. Actionable Mitigations & Report Posture

    func testActionableMitigationsPopulated() {
        let engine = FirmwarePostureEngine.shared
        let report = engine.evaluate(osVersion: SystemOSVersion(major: 26, minor: 2, patch: 0))

        XCTAssertEqual(report.overallRiskTier, .highRisk)
        XCTAssertFalse(report.exposedVulnerabilities.isEmpty)
        XCTAssertFalse(report.actionableMitigations.isEmpty)

        // Verify categories are present
        let categories = Set(report.actionableMitigations.map { $0.category })
        XCTAssertTrue(categories.contains(.networkProxy))
        XCTAssertTrue(categories.contains(.systemSettings))
        XCTAssertTrue(categories.contains(.appHygiene))
        XCTAssertTrue(categories.contains(.wqguardScan))

        // Verify specific Surge mitigation for Brotli
        let surgeMitigation = report.actionableMitigations.first { $0.category == .networkProxy }
        XCTAssertNotNil(surgeMitigation)
        XCTAssertTrue(surgeMitigation!.instructions.contains("Surge"))
        XCTAssertTrue(surgeMitigation!.relatedCVEs.contains("CVE-2026-111497"))
    }

    func testReportOverallRiskTierDerivation() {
        let engine = FirmwarePostureEngine.shared
        XCTAssertEqual(FirmwareCVEID.allCases.count, 13)
        XCTAssertEqual(FirmwarePostureEngine.allVulnerabilities.count, 13)

        // Fully evaluated count should match allVulnerabilities count (13)
        let report = engine.evaluate(osVersion: SystemOSVersion(major: 27, minor: 2, patch: 1))
        XCTAssertEqual(report.totalEvaluated, 13)
        // Only worse_query 0day remains exposed on 27.2.1
        XCTAssertEqual(report.exposedCount, 1)
        XCTAssertEqual(report.exposedVulnerabilities.first?.cveId, .worseQuery0day)
        XCTAssertEqual(report.overallRiskTier, .highRisk) // 0day has .highRisk severity

        // On iOS 27.3.0+, all 13 cataloged CVEs are patched -> .safe
        let report27_3 = engine.evaluate(osVersion: SystemOSVersion(major: 27, minor: 3, patch: 0))
        XCTAssertEqual(report27_3.totalEvaluated, 13)
        XCTAssertEqual(report27_3.exposedCount, 0)
        XCTAssertEqual(report27_3.overallRiskTier, .safe)
    }

    func testAll13CVEsBilingualZeroHanInEnglish() {
        let prev = WQLocale.overrideLanguageCode
        defer { WQLocale.overrideLanguageCode = prev }

        func hasHan(_ text: String) -> Bool {
            text.unicodeScalars.contains { scalar in
                let v = scalar.value
                return (0x4E00...0x9FFF).contains(v)
                    || (0x3400...0x4DBF).contains(v)
                    || (0xF900...0xFAFF).contains(v)
                    || (0x20000...0x2EBEF).contains(v)
            }
        }

        WQLocale.overrideLanguageCode = "en"
        let enCatalog = FirmwarePostureEngine.allVulnerabilities
        XCTAssertEqual(enCatalog.count, 13)
        for v in enCatalog {
            XCTAssertFalse(hasHan(v.name), "English name contains Han: \(v.name)")
            XCTAssertFalse(hasHan(v.subsystem), "English subsystem contains Han: \(v.subsystem)")
            XCTAssertFalse(hasHan(v.affectedDescription), "English affectedDescription contains Han: \(v.affectedDescription)")
            XCTAssertFalse(hasHan(v.patchedVersionDescription), "English patchedVersionDescription contains Han: \(v.patchedVersionDescription)")
            XCTAssertFalse(hasHan(v.details), "English details contains Han: \(v.details)")
            XCTAssertFalse(v.mitigations.isEmpty, "\(v.cveId.rawValue) must include actionable mitigations")
            for m in v.mitigations {
                XCTAssertFalse(hasHan(m.title), "English mitigation title contains Han: \(m.title)")
                XCTAssertFalse(hasHan(m.instructions), "English mitigation instructions contains Han: \(m.instructions)")
            }
        }

        WQLocale.overrideLanguageCode = "zh-Hans"
        let zhCatalog = FirmwarePostureEngine.allVulnerabilities
        XCTAssertEqual(zhCatalog.count, 13)
        for v in zhCatalog {
            XCTAssertTrue(hasHan(v.name), "Chinese name missing Han: \(v.name)")
            XCTAssertTrue(hasHan(v.details), "Chinese details missing Han: \(v.details)")
        }
    }
}
