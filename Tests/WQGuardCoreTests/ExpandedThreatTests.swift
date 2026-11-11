//
//  ExpandedThreatTests.swift
//  WQGuardCoreTests
//
//  Comprehensive test suite for ExpandedThreatCatalog:
//  Private Photos bypass, libbrotli CVE-2026-111497 notice,
//  wallet impersonation, injected tweaks, clipboard snooping, and fake supervision.
//

import XCTest
@testable import WQGuardCore

final class ExpandedThreatTests: XCTestCase {

    var mockTree: MockContainerTree!

    override func setUp() {
        super.setUp()
        mockTree = MockContainerTree()
    }

    override func tearDown() {
        mockTree?.cleanUp()
        mockTree = nil
        super.tearDown()
    }

    // MARK: - 1. Private Photos Bypass

    func testPhotosBypassFrameworkDetection() {
        let indicators = ExpandedThreatCatalog.evaluatePhotosBypass(
            linkedDylibs: ["/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/PhotoLibraryServices"],
            symbols: [],
            entitlements: [:],
            cryptid: 0
        )
        XCTAssertEqual(indicators.count, 1)
        XCTAssertEqual(indicators.first?.signature, "PhotoLibraryServices.framework")
        XCTAssertEqual(indicators.first?.severity, .highRisk)
    }

    func testPhotosBypassEntitlementDetection() {
        let entitlements: [String: Any] = [
            "com.apple.private.photos.access": true
        ]
        let indicators = ExpandedThreatCatalog.evaluatePhotosBypass(
            linkedDylibs: [],
            symbols: [],
            entitlements: entitlements,
            cryptid: 0
        )
        XCTAssertEqual(indicators.count, 1)
        XCTAssertEqual(indicators.first?.signature, "com.apple.private.photos.access")
        XCTAssertEqual(indicators.first?.severity, .highRisk)
    }

    func testPhotosBypassSymbolDetection() {
        let indicators = ExpandedThreatCatalog.evaluatePhotosBypass(
            linkedDylibs: [],
            symbols: ["-[PLPhotoLibrary openPhotoLibrary]"],
            entitlements: [:],
            cryptid: 0
        )
        XCTAssertEqual(indicators.count, 1)
        XCTAssertEqual(indicators.first?.severity, .highRisk)
    }

    // MARK: - 2. Bundled libbrotli Supply Chain Notice

    func testBrotliSupplyChainDetection() {
        let dylibIndicators = ExpandedThreatCatalog.evaluateBrotliSupplyChain(
            linkedDylibs: ["@rpath/libbrotlidec.dylib"],
            symbols: []
        )
        XCTAssertEqual(dylibIndicators.count, 1)
        XCTAssertEqual(dylibIndicators.first?.severity, .caution)

        let symbolIndicators = ExpandedThreatCatalog.evaluateBrotliSupplyChain(
            linkedDylibs: [],
            symbols: ["_BrotliDecoderDecompressStream"]
        )
        XCTAssertEqual(symbolIndicators.count, 1)
        XCTAssertEqual(symbolIndicators.first?.severity, .caution)
    }

    // MARK: - 3. Crypto Wallet & Messenger Impersonation

    func testCryptoWalletImpersonationDetection() {
        // Sideloaded unencrypted MetaMask clone
        let indicators = ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: "io.metamask.evilclone",
            displayName: "MetaMask",
            installChannel: .developerSideloaded,
            cryptid: 0
        )
        XCTAssertEqual(indicators.count, 1)
        XCTAssertEqual(indicators.first?.severity, .highRisk)
        XCTAssertTrue(indicators.first?.signature.contains("MetaMask") ?? false)

        // Telegram clone
        let tgIndicators = ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: "org.telegram.messenger.mod",
            displayName: "Telegram Mod",
            installChannel: .enterpriseInHouse,
            cryptid: 0
        )
        XCTAssertEqual(tgIndicators.count, 1)
        XCTAssertEqual(tgIndicators.first?.severity, .highRisk)
    }

    func testAppStoreLegitimateWalletExemption() {
        // Legitimate App Store binary (cryptid == 1)
        let indicators = ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: "io.metamask.MetaMask",
            displayName: "MetaMask",
            installChannel: .appStore,
            cryptid: 1
        )
        XCTAssertTrue(indicators.isEmpty, "Official App Store release must be exempt from impersonation alerts")
    }

    // MARK: - 4. Injected Tweaks & Modded Frameworks

    func testInjectedTweakDetection() {
        let indicators = ExpandedThreatCatalog.evaluateInjectedDylibs(
            linkedDylibs: [
                "/Library/MobileSubstrate/DynamicLibraries/ElleKit.dylib",
                "@executable_path/Frameworks/hook_speed.dylib"
            ]
        )
        XCTAssertEqual(indicators.count, 2)
        XCTAssertTrue(indicators.contains { $0.signature == "ElleKit" })
        XCTAssertTrue(indicators.contains { $0.signature == "hook_speed.dylib" })
    }

    // MARK: - 5. Clipboard Snooping Tuple

    func testBackgroundClipboardSnooping() {
        let indicator = ExpandedThreatCatalog.evaluateClipboardSnooping(
            backgroundModes: ["audio"],
            symbols: ["_OBJC_CLASS_$_UIPasteboard", "_generalPasteboard"],
            cryptid: 0
        )
        XCTAssertNotNil(indicator)
        XCTAssertEqual(indicator?.severity, .highRisk)
        XCTAssertEqual(indicator?.signature, "UIBackgroundModes(audio)+UIPasteboard")
    }

    func testBackgroundAudioWithoutPasteboardClean() {
        // Benign audio player like Spotify
        let indicator = ExpandedThreatCatalog.evaluateClipboardSnooping(
            backgroundModes: ["audio"],
            symbols: ["_AVPlayer", "_AVAudioSession"],
            cryptid: 0
        )
        XCTAssertNil(indicator, "Benign background audio app without pasteboard access must not be flagged")
    }

    // MARK: - 6. Fake Supervision & Rogue Profiles

    func testSupervisionProfileDetection() throws {
        let containerRoot = mockTree.rootDirectoryURL
        let profileDir = containerRoot
            .appendingPathComponent("systemgroup.com.apple.configurationprofiles")
            .appendingPathComponent("Library")
            .appendingPathComponent("ConfigurationProfiles")
        try FileManager.default.createDirectory(at: profileDir, withIntermediateDirectories: true)

        let cloudPlistURL = profileDir.appendingPathComponent("CloudConfigurationDetails.plist")
        let plistData = try PropertyListSerialization.data(fromPropertyList: ["IsSupervised": true], format: .xml, options: 0)
        try plistData.write(to: cloudPlistURL)

        let indicators = ExpandedThreatCatalog.evaluateSupervision(containerRoot: containerRoot)
        XCTAssertEqual(indicators.count, 1)
        XCTAssertEqual(indicators.first?.signature, "CloudConfigurationDetails.IsSupervised=true")
        XCTAssertEqual(indicators.first?.severity, .highRisk)
    }

    func testRetailCleanSupervisionExemption() {
        // Retail device has no CloudConfigurationDetails.plist
        let indicators = ExpandedThreatCatalog.evaluateSupervision(containerRoot: mockTree.rootDirectoryURL)
        XCTAssertTrue(indicators.isEmpty)
    }
}
