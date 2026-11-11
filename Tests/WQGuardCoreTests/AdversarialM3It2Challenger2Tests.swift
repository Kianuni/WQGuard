//
//  AdversarialM3It2Challenger2Tests.swift
//  WQGuardCoreTests
//
//  Empirical Adversarial Stress-Test Suite by Challenger m3_2.
//  Rigorous testing of:
//  1. Dual-branch version boundaries (iOS 26.7.2 vs 26.7.3, iOS 27.2.0 vs 27.2.1) across all 8 cataloged CVEs.
//  2. All 16 negative MITM exclusions in Surge/WQGuard-Brotli-Shield.sgmodule and SurgeBrotliShieldHelper.
//  3. Sideloaded clone impersonation detection (cryptid == 0) vs App Store official app exemption (cryptid == 1).
//  4. Background clipboard snooping behavioral tuple (UIBackgroundModes + UIPasteboard).
//

import XCTest
@testable import WQGuardCore

final class AdversarialM3It2Challenger2Tests: XCTestCase {

    // MARK: - 1. Dual-Branch Version Boundaries Across All 8 Cataloged CVEs

    func testDualBranchBoundary_iOS26_7_2_vs_26_7_3() {
        let engine = FirmwarePostureEngine.shared
        let v26_7_2 = SystemOSVersion(major: 26, minor: 7, patch: 2)
        let v26_7_3 = SystemOSVersion(major: 26, minor: 7, patch: 3)

        // 1. worseQuery0day (unpatched 0day: vulnerable on both)
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: v26_7_2))
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: v26_7_3))

        // 2. photosBypass (patched in 26.7.2: false on both)
        XCTAssertFalse(engine.isVulnerable(.photosBypass, in: v26_7_2))
        XCTAssertFalse(engine.isVulnerable(.photosBypass, in: v26_7_3))

        // 3. brotliOOB (patched in 26.7.3: true on 26.7.2, false on 26.7.3)
        XCTAssertTrue(engine.isVulnerable(.brotliOOB, in: v26_7_2))
        XCTAssertFalse(engine.isVulnerable(.brotliOOB, in: v26_7_3))

        // 4. coreGraphicsPDF (patched in 26.7.2: false on both)
        XCTAssertFalse(engine.isVulnerable(.coreGraphicsPDF, in: v26_7_2))
        XCTAssertFalse(engine.isVulnerable(.coreGraphicsPDF, in: v26_7_3))

        // 5. coreGraphics2D (affects iOS < 27.0: true on both)
        XCTAssertTrue(engine.isVulnerable(.coreGraphics2D, in: v26_7_2))
        XCTAssertTrue(engine.isVulnerable(.coreGraphics2D, in: v26_7_3))

        // 6. appIntentsBypass (patched in 26.7.3: true on 26.7.2, false on 26.7.3)
        XCTAssertTrue(engine.isVulnerable(.appIntentsBypass, in: v26_7_2))
        XCTAssertFalse(engine.isVulnerable(.appIntentsBypass, in: v26_7_3))

        // 7. imessageGroup (patched in 26.7.3: true on 26.7.2, false on 26.7.3)
        XCTAssertTrue(engine.isVulnerable(.imessageGroup, in: v26_7_2))
        XCTAssertFalse(engine.isVulnerable(.imessageGroup, in: v26_7_3))

        // 8. bluetoothAirPlay (patched in 26.7.3: true on 26.7.2, false on 26.7.3)
        XCTAssertTrue(engine.isVulnerable(.bluetoothAirPlay, in: v26_7_2))
        XCTAssertFalse(engine.isVulnerable(.bluetoothAirPlay, in: v26_7_3))

        // Check aggregate counts
        let report_26_7_2 = engine.evaluate(osVersion: v26_7_2)
        XCTAssertEqual(report_26_7_2.totalEvaluated, 8)
        XCTAssertEqual(report_26_7_2.exposedCount, 6, "iOS 26.7.2 must have exactly 6 exposed CVEs")
        XCTAssertEqual(report_26_7_2.overallRiskTier, .highRisk)

        let report_26_7_3 = engine.evaluate(osVersion: v26_7_3)
        XCTAssertEqual(report_26_7_3.totalEvaluated, 8)
        XCTAssertEqual(report_26_7_3.exposedCount, 2, "iOS 26.7.3 must have exactly 2 exposed CVEs (0day + CoreGraphics2D)")
        XCTAssertEqual(report_26_7_3.overallRiskTier, .highRisk)
    }

    func testDualBranchBoundary_iOS27_2_0_vs_27_2_1() {
        let engine = FirmwarePostureEngine.shared
        let v27_2_0 = SystemOSVersion(major: 27, minor: 2, patch: 0)
        let v27_2_1 = SystemOSVersion(major: 27, minor: 2, patch: 1)

        // 1. worseQuery0day (unpatched 0day: vulnerable on both)
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: v27_2_0))
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: v27_2_1))

        // 2. photosBypass (patched in 27.2.0: false on both)
        XCTAssertFalse(engine.isVulnerable(.photosBypass, in: v27_2_0))
        XCTAssertFalse(engine.isVulnerable(.photosBypass, in: v27_2_1))

        // 3. brotliOOB (patched in 27.2.1: true on 27.2.0, false on 27.2.1)
        XCTAssertTrue(engine.isVulnerable(.brotliOOB, in: v27_2_0))
        XCTAssertFalse(engine.isVulnerable(.brotliOOB, in: v27_2_1))

        // 4. coreGraphicsPDF (patched in 27.2.0: false on both)
        XCTAssertFalse(engine.isVulnerable(.coreGraphicsPDF, in: v27_2_0))
        XCTAssertFalse(engine.isVulnerable(.coreGraphicsPDF, in: v27_2_1))

        // 5. coreGraphics2D (affects iOS < 27.0: false on both)
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: v27_2_0))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: v27_2_1))

        // 6. appIntentsBypass (patched in 27.2.1: true on 27.2.0, false on 27.2.1)
        XCTAssertTrue(engine.isVulnerable(.appIntentsBypass, in: v27_2_0))
        XCTAssertFalse(engine.isVulnerable(.appIntentsBypass, in: v27_2_1))

        // 7. imessageGroup (patched in 27.2.1: true on 27.2.0, false on 27.2.1)
        XCTAssertTrue(engine.isVulnerable(.imessageGroup, in: v27_2_0))
        XCTAssertFalse(engine.isVulnerable(.imessageGroup, in: v27_2_1))

        // 8. bluetoothAirPlay (patched in 27.2.1: true on 27.2.0, false on 27.2.1)
        XCTAssertTrue(engine.isVulnerable(.bluetoothAirPlay, in: v27_2_0))
        XCTAssertFalse(engine.isVulnerable(.bluetoothAirPlay, in: v27_2_1))

        // Check aggregate counts
        let report_27_2_0 = engine.evaluate(osVersion: v27_2_0)
        XCTAssertEqual(report_27_2_0.totalEvaluated, 8)
        XCTAssertEqual(report_27_2_0.exposedCount, 5, "iOS 27.2.0 must have exactly 5 exposed CVEs")
        XCTAssertEqual(report_27_2_0.overallRiskTier, .highRisk)

        let report_27_2_1 = engine.evaluate(osVersion: v27_2_1)
        XCTAssertEqual(report_27_2_1.totalEvaluated, 8)
        XCTAssertEqual(report_27_2_1.exposedCount, 1, "iOS 27.2.1 must have exactly 1 exposed CVE (0day only)")
        XCTAssertEqual(report_27_2_1.overallRiskTier, .highRisk)
    }

    func testPreReleaseAndLegacyFirmwareEvaluations() {
        let engine = FirmwarePostureEngine.shared

        // iOS 25.4 (legacy iOS prior to 26.0)
        let v25 = SystemOSVersion(major: 25, minor: 4, patch: 0)
        XCTAssertFalse(engine.isVulnerable(.worseQuery0day, in: v25), "worse_query 0day only applies to iOS 26+")
        XCTAssertTrue(engine.isVulnerable(.brotliOOB, in: v25), "Brotli OOB affects iOS < 26.7.3 / 27.2.1")
        XCTAssertTrue(engine.isVulnerable(.coreGraphics2D, in: v25), "CoreGraphics 2D affects iOS < 27.0")

        // iOS 28.0 (future iOS where all current CVEs are patched except possible future 0days)
        let v28 = SystemOSVersion(major: 28, minor: 0, patch: 0)
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: v28), "Unpatched 0day affects all versions >= 26")
        XCTAssertFalse(engine.isVulnerable(.photosBypass, in: v28))
        XCTAssertFalse(engine.isVulnerable(.brotliOOB, in: v28))
        XCTAssertFalse(engine.isVulnerable(.coreGraphicsPDF, in: v28))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: v28))
        XCTAssertFalse(engine.isVulnerable(.appIntentsBypass, in: v28))
        XCTAssertFalse(engine.isVulnerable(.imessageGroup, in: v28))
        XCTAssertFalse(engine.isVulnerable(.bluetoothAirPlay, in: v28))
    }

    // MARK: - 2. All 16 Negative MITM Exclusions in Surge Module

    func testAll16NegativeExclusionsStrictVerification() throws {
        let expected16: [String] = [
            "-*.apple.com",
            "-*.icloud.com",
            "-*.icloud-content.com",
            "-*.mzstatic.com",
            "-*.cdn-apple.com",
            "-guzzoni.apple.com",
            "-*.siri.apple.com",
            "-gspe1-ssl.ls.apple.com",
            "-apple-relay.*",
            "-cp4.cloudflare.com",
            "-*.openai.com",
            "-*.chatgpt.com",
            "-*.binance.com",
            "-*.okx.com",
            "-*.tenpay.com",
            "-*.alipay.com"
        ]

        XCTAssertEqual(expected16.count, 16, "Must define exactly 16 negative exclusion patterns")

        // 1. Verify helper constant matches
        XCTAssertEqual(SurgeBrotliShieldHelper.mandatoryNegativeExclusions, expected16)

        // 2. Verify physical file Surge/WQGuard-Brotli-Shield.sgmodule
        let repoRoot = URL(fileURLWithPath: #file)
            .deletingLastPathComponent() // WQGuardCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // WQGuard
        let fileURL = repoRoot.appendingPathComponent("Surge/WQGuard-Brotli-Shield.sgmodule")
        let fileContent = try String(contentsOf: fileURL, encoding: .utf8)

        for exc in expected16 {
            XCTAssertTrue(fileContent.contains(exc), "Physical .sgmodule file is missing mandatory negative exclusion: \(exc)")
        }

        // 3. Verify position: negative exclusions MUST be inside [MITM] hostname = %APPEND%
        guard let mitmRange = fileContent.range(of: "[MITM]") else {
            XCTFail("Missing [MITM] section")
            return
        }
        let mitmSection = String(fileContent[mitmRange.lowerBound...])
        XCTAssertTrue(mitmSection.contains("hostname = %APPEND%"))

        for exc in expected16 {
            XCTAssertTrue(mitmSection.contains(exc), "Exclusion \(exc) must be inside [MITM] section")
        }

        // 4. Verify Apple Intelligence / Siri / Banking critical domains
        XCTAssertTrue(mitmSection.contains("-guzzoni.apple.com"), "Mandarin Siri endpoint must be negatively excluded")
        XCTAssertTrue(mitmSection.contains("-gspe1-ssl.ls.apple.com"), "Apple Intelligence PCC / Siri endpoint must be negatively excluded")
        XCTAssertTrue(mitmSection.contains("-apple-relay.*"), "Apple Private Relay / PCC relay must be negatively excluded")
        XCTAssertTrue(mitmSection.contains("-*.openai.com"), "OpenAI Apple Intelligence integration must be negatively excluded")
        XCTAssertTrue(mitmSection.contains("-*.alipay.com"), "Alipay cert-pinned payment must be negatively excluded")
        XCTAssertTrue(mitmSection.contains("-*.tenpay.com"), "Tenpay cert-pinned payment must be negatively excluded")
        XCTAssertTrue(mitmSection.contains("-*.binance.com"), "Binance cert-pinned exchange must be negatively excluded")
        XCTAssertTrue(mitmSection.contains("-*.okx.com"), "OKX cert-pinned exchange must be negatively excluded")
    }

    func testSurgeModuleCustomExtraHostsWildcardSafety() {
        // Even when user passes "*", the negative exclusions come first in hostname = %APPEND%
        let generated = SurgeBrotliShieldHelper.shared.generateModuleContent(extraHosts: ["*"])
        XCTAssertTrue(generated.contains("{{{EXTRA_MITM_HOSTS}}}") == false)
        XCTAssertTrue(generated.contains(", *"))

        let validation = SurgeBrotliShieldHelper.shared.validateModule(content: generated)
        XCTAssertTrue(validation.isCompliant)
        XCTAssertTrue(validation.missingExclusions.isEmpty)
    }

    func testSurgeModuleValidationDetectsMissingExclusions() {
        var tampered = SurgeBrotliShieldHelper.rawModuleTemplate
        tampered = tampered.replacingOccurrences(of: "-guzzoni.apple.com,", with: "")
        tampered = tampered.replacingOccurrences(of: "-*.alipay.com,", with: "")

        let result = SurgeBrotliShieldHelper.shared.validateModule(content: tampered)
        XCTAssertFalse(result.isCompliant)
        XCTAssertEqual(result.missingExclusions.count, 2)
        XCTAssertTrue(result.missingExclusions.contains("-guzzoni.apple.com"))
        XCTAssertTrue(result.missingExclusions.contains("-*.alipay.com"))
    }

    // MARK: - 3. Impersonation Detection (cryptid == 0 vs cryptid == 1)

    func testAll9BrandsDetectedOnSideloadedClones() {
        // Test cases for each of the 9 brands:
        let testCases: [(brand: String, bundleId: String, name: String)] = [
            ("MetaMask", "io.metamask.modded", "MetaMask"),
            ("MetaMask", "com.evil.wallet", "小狐狸"),
            ("Trust Wallet", "com.sixdays.trust.fake", "Trust Wallet"),
            ("Phantom", "app.phantom.clone", "Phantom"),
            ("OKX", "com.okx.ios.phishing", "欧易"),
            ("Binance", "com.binance.ios.drainer", "币安"),
            ("TokenPocket", "vip.mytokenpocket.hack", "TP钱包"),
            ("imToken", "im.token.app.trojan", "imToken"),
            ("Bitget", "com.bitget.ios.bad", "Bitget"),
            ("Telegram", "org.telegram.messenger.spy", "纸飞机")
        ]

        for tc in testCases {
            // Sideloaded unencrypted (cryptid == 0)
            let indicatorsDev = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: tc.bundleId,
                displayName: tc.name,
                installChannel: .developerSideloaded,
                cryptid: 0
            )
            XCTAssertFalse(indicatorsDev.isEmpty, "Failed to flag sideloaded clone for brand: \(tc.brand), name: \(tc.name)")
            XCTAssertEqual(indicatorsDev.first?.severity, .highRisk)
            XCTAssertTrue(indicatorsDev.first?.signature.contains(tc.brand) ?? false)

            // Enterprise unencrypted (cryptid == 0)
            let indicatorsEnt = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: tc.bundleId,
                displayName: tc.name,
                installChannel: .enterpriseInHouse,
                cryptid: 0
            )
            XCTAssertFalse(indicatorsEnt.isEmpty, "Failed to flag enterprise clone for brand: \(tc.brand)")
            XCTAssertEqual(indicatorsEnt.first?.severity, .highRisk)
        }
    }

    func testOfficialAppStoreAndTestFlightExemption() {
        let brands: [(bundleId: String, name: String)] = [
            ("io.metamask.MetaMask", "MetaMask"),
            ("com.sixdays.trust", "Trust Wallet"),
            ("app.phantom", "Phantom"),
            ("com.okx.ios", "OKX"),
            ("com.binance.binance", "Binance"),
            ("vip.mytokenpocket", "TokenPocket"),
            ("im.token.app", "imToken"),
            ("com.bitget.ios", "Bitget"),
            ("org.telegram.messenger", "Telegram")
        ]

        for b in brands {
            // App Store with cryptid == 1
            let appStoreIndicators = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: b.bundleId,
                displayName: b.name,
                installChannel: .appStore,
                cryptid: 1
            )
            XCTAssertTrue(appStoreIndicators.isEmpty, "Official App Store app \(b.name) must be exempt from impersonation alerts")

            // TestFlight with cryptid == 1
            let tfIndicators = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: b.bundleId,
                displayName: b.name,
                installChannel: .testFlight,
                cryptid: 1
            )
            XCTAssertTrue(tfIndicators.isEmpty, "Official TestFlight app \(b.name) must be exempt from impersonation alerts")
        }
    }

    func testImpersonationExemptionWhenCryptidIs1EvenIfSideloaded() {
        // If a FairPlay-encrypted binary (cryptid == 1) is extracted, it is not an unencrypted clone
        let indicators = ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: "io.metamask.MetaMask",
            displayName: "MetaMask",
            installChannel: .developerSideloaded,
            cryptid: 1
        )
        XCTAssertTrue(indicators.isEmpty, "Encrypted binary (cryptid == 1) must be exempt from clone alerts")
    }

    func testImpersonationBenignNonMatchingApps() {
        let benignCases: [(bundleId: String, name: String)] = [
            ("com.apple.mobilesafari", "Safari"),
            ("com.example.calculator", "Calculator"),
            ("org.videolan.vlc", "VLC")
        ]

        for b in benignCases {
            let indicators = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: b.bundleId,
                displayName: b.name,
                installChannel: .developerSideloaded,
                cryptid: 0
            )
            XCTAssertTrue(indicators.isEmpty, "Benign app \(b.name) must not trigger impersonation alerts")
        }
    }

    func testImpersonationNilOrEmptyInputs() {
        let ind1 = ExpandedThreatCatalog.evaluateImpersonation(bundleId: nil, displayName: nil, installChannel: .developerSideloaded, cryptid: 0)
        XCTAssertTrue(ind1.isEmpty)

        let ind2 = ExpandedThreatCatalog.evaluateImpersonation(bundleId: "", displayName: "", installChannel: .developerSideloaded, cryptid: 0)
        XCTAssertTrue(ind2.isEmpty)
    }

    // MARK: - 4. Background Clipboard Snooping Tuple

    func testBackgroundClipboardSnoopingAllModes() {
        let persistentModes = ["audio", "location", "voip"]
        let targetSymbols = [
            "UIPasteboard",
            "generalPasteboard",
            "UIPasteboardNameGeneral",
            "_OBJC_CLASS_$_UIPasteboard",
            "-[UIPasteboard string]",
            "-[UIPasteboard strings]"
        ]

        for mode in persistentModes {
            for sym in targetSymbols {
                let indicator = ExpandedThreatCatalog.evaluateClipboardSnooping(
                    backgroundModes: [mode],
                    symbols: [sym],
                    cryptid: 0
                )
                XCTAssertNotNil(indicator, "Failed to flag mode: \(mode) with symbol: \(sym)")
                XCTAssertEqual(indicator?.severity, .highRisk)
                XCTAssertEqual(indicator?.signature, "UIBackgroundModes(\(mode))+UIPasteboard")
                XCTAssertEqual(indicator?.category, "Background Clipboard Snooping")
            }
        }
    }

    func testBackgroundClipboardSnoopingMultipleModes() {
        let indicator = ExpandedThreatCatalog.evaluateClipboardSnooping(
            backgroundModes: ["audio", "location", "fetch"],
            symbols: ["_UIPasteboard"],
            cryptid: 0
        )
        XCTAssertNotNil(indicator)
        XCTAssertEqual(indicator?.severity, .highRisk)
        XCTAssertEqual(indicator?.signature, "UIBackgroundModes(audio, location)+UIPasteboard")
    }

    func testBackgroundClipboardSnoopingExemptions() {
        // 1. App Store encrypted binary (cryptid == 1)
        let indEncrypted = ExpandedThreatCatalog.evaluateClipboardSnooping(
            backgroundModes: ["audio"],
            symbols: ["UIPasteboard"],
            cryptid: 1
        )
        XCTAssertNil(indEncrypted, "App Store encrypted apps must not be flagged by unencrypted snooping heuristic")

        // 2. Background audio without pasteboard (e.g. music player)
        let indAudioOnly = ExpandedThreatCatalog.evaluateClipboardSnooping(
            backgroundModes: ["audio"],
            symbols: ["_AVPlayer", "_AVAudioSession"],
            cryptid: 0
        )
        XCTAssertNil(indAudioOnly, "Normal audio player must not be flagged")

        // 3. Pasteboard without persistent background mode (e.g. normal utility with fetch)
        let indPasteboardOnly = ExpandedThreatCatalog.evaluateClipboardSnooping(
            backgroundModes: ["fetch", "remote-notification"],
            symbols: ["UIPasteboard"],
            cryptid: 0
        )
        XCTAssertNil(indPasteboardOnly, "App without persistent background mode (audio/location/voip) must not be flagged")

        // 4. No background modes at all
        let indNoModes = ExpandedThreatCatalog.evaluateClipboardSnooping(
            backgroundModes: [],
            symbols: ["UIPasteboard"],
            cryptid: 0
        )
        XCTAssertNil(indNoModes, "App with empty background modes must not be flagged")
    }
}
