//
//  LocalizationBilingualTests.swift
//  WQGuardCoreTests
//
//  Empirical & invariant verification for full-stack English (`en`) and Simplified Chinese (`zh-Hans`)
//  localization across WQGuardCore engines, models, error types, and UI view files.
//

import XCTest
@testable import WQGuardCore

final class LocalizationBilingualTests: XCTestCase {

    override func setUp() {
        super.setUp()
        WQLocale.overrideLanguageCode = nil
    }

    override func tearDown() {
        WQLocale.overrideLanguageCode = nil
        super.tearDown()
    }

    private func containsHanCharacters(_ text: String) -> Bool {
        return text.unicodeScalars.contains { scalar in
            let v = scalar.value
            return (0x4E00...0x9FFF).contains(v)
                || (0x3400...0x4DBF).contains(v)
                || (0xF900...0xFAFF).contains(v)
                || (0x20000...0x2EBEF).contains(v)
        }
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    func testFirmwarePostureEngineFullyLocalizedInEnglishAndChinese() {
        // 1. English mode: zero Han leakage across all CVEs and mitigations
        WQLocale.overrideLanguageCode = "en"
        let enReport = FirmwarePostureEngine.shared.evaluate(osVersion: SystemOSVersion(major: 26, minor: 2, patch: 0))
        let enAllVulns = enReport.exposedVulnerabilities + enReport.patchedVulnerabilities
        XCTAssertEqual(enAllVulns.count, 8)
        for v in enAllVulns {
            XCTAssertFalse(containsHanCharacters(v.name), "English CVE name contains Han: \(v.name)")
            XCTAssertFalse(containsHanCharacters(v.affectedDescription), "English affectedDescription contains Han: \(v.affectedDescription)")
            XCTAssertFalse(containsHanCharacters(v.patchedVersionDescription), "English patchedVersionDescription contains Han: \(v.patchedVersionDescription)")
            XCTAssertFalse(containsHanCharacters(v.details), "English CVE details contains Han: \(v.details)")
            for m in v.mitigations {
                XCTAssertFalse(containsHanCharacters(m.title), "English mitigation title contains Han: \(m.title)")
                XCTAssertFalse(containsHanCharacters(m.instructions), "English mitigation instructions contains Han: \(m.instructions)")
            }
        }
        // Invariant expected by FirmwarePostureTests must remain satisfied in English too
        let enProxyMit = enReport.actionableMitigations.first { $0.category == .networkProxy }
        XCTAssertTrue(enProxyMit?.instructions.contains("Surge") ?? false)

        // 2. Chinese mode: localized Chinese emitted dynamically
        WQLocale.overrideLanguageCode = "zh-Hans"
        let zhReport = FirmwarePostureEngine.shared.evaluate(osVersion: SystemOSVersion(major: 26, minor: 2, patch: 0))
        let zhWorseQuery = zhReport.exposedVulnerabilities.first { $0.cveId == .worseQuery0day }
        XCTAssertTrue(containsHanCharacters(zhWorseQuery?.name ?? ""))
        XCTAssertTrue(containsHanCharacters(zhWorseQuery?.details ?? ""))
    }

    func testCoreEnginesAndErrorsLocalizedInEnglish() {
        WQLocale.overrideLanguageCode = "en"

        // AuditEvidence.empty
        let emptyEv = AuditEvidence.empty()
        XCTAssertFalse(containsHanCharacters(emptyEv.remediationGuidance))

        // EntitlementGating
        let gatedOut = EntitlementGating.evaluate(hasAppGroups: false, appGroups: [])
        XCTAssertTrue(gatedOut.reason.hasPrefix("Layer 1 Fast-Path Gated:"))
        XCTAssertFalse(containsHanCharacters(gatedOut.reason))

        let gatedIn = EntitlementGating.evaluate(hasAppGroups: true, appGroups: ["group.test.app"])
        XCTAssertTrue(gatedIn.reason.hasPrefix("Layer 1 Gating Proceed:"))
        XCTAssertFalse(containsHanCharacters(gatedIn.reason))

        // ExpandedThreatCatalog
        let photosInds = ExpandedThreatCatalog.evaluatePhotosBypass(
            linkedDylibs: ["/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/PhotoLibraryServices"],
            symbols: ["_OBJC_CLASS_$_PLPhotoLibrary"],
            entitlements: ["com.apple.private.photos.allow": true],
            cryptid: 0
        )
        XCTAssertEqual(photosInds.count, 3)
        for ind in photosInds {
            XCTAssertFalse(containsHanCharacters(ind.description), "English indicator contains Han: \(ind.description)")
        }

        let brotliInds = ExpandedThreatCatalog.evaluateBrotliSupplyChain(
            linkedDylibs: ["@rpath/libbrotli.dylib"],
            symbols: ["_BrotliDecoderDecompressStream"]
        )
        XCTAssertFalse(brotliInds.isEmpty)
        for ind in brotliInds {
            XCTAssertFalse(containsHanCharacters(ind.description))
        }

        let impersonationInds = ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: "io.metamask.clone",
            displayName: "MetaMask Pro",
            installChannel: .developerSideloaded,
            cryptid: 0
        )
        XCTAssertFalse(impersonationInds.isEmpty)
        for ind in impersonationInds {
            XCTAssertFalse(containsHanCharacters(ind.description))
        }

        // OnDeviceAppProbeScanner (ESign, Feather, TrollStore)
        let probeFindings = OnDeviceAppProbeScanner.shared.evaluateProbes { scheme in
            scheme == "esign" || scheme == "feather" || scheme == "trollstore"
        }
        XCTAssertEqual(probeFindings.count, 3)
        for f in probeFindings {
            XCTAssertFalse(containsHanCharacters(f.displayName), "English probe displayName contains Han: \(f.displayName)")
            XCTAssertFalse(containsHanCharacters(f.version))
            XCTAssertFalse(containsHanCharacters(f.bundlePath))
            XCTAssertFalse(containsHanCharacters(f.evidence.remediationGuidance))
            for ind in f.indicators {
                XCTAssertFalse(containsHanCharacters(ind.description), "English probe description contains Han: \(ind.description)")
            }
        }

        // InstalledAppRegistryScanner
        let esignRecord = InstalledAppRegistryRecord(
            bundleId: "p3.xyz.yyyue.esign",
            displayName: "ESign",
            version: "5.0",
            applicationType: "User",
            signerIdentity: "Apple Development: user@example.com (TEAM123456)",
            profileValidated: true,
            teamId: "TEAM123456",
            appGroups: ["group.esign.shared"],
            bundlePath: "/private/var/containers/Bundle/Application/UUID/ESign.app"
        )
        let esignFinding = InstalledAppRegistryScanner.shared.evaluateRecord(esignRecord)
        XCTAssertEqual(esignFinding.riskTier, .caution)
        XCTAssertFalse(containsHanCharacters(esignFinding.evidence.remediationGuidance))
        for ind in esignFinding.indicators {
            XCTAssertFalse(containsHanCharacters(ind.description))
        }

        // Errors
        let errors: [Error] = [
            IPAPackageScannerError.missingPayload,
            IPAPackageScannerError.zipSlipDetected("../evil"),
            InstalledAppRegistryError.emptyApplicationList,
            SecurityPipelineError.sandboxRestrictedNoAccessibleTargets,
            LockdownClientError.lockdownUnreachable("10.7.0.1"),
            LockdownClientError.invalidPairingFile("Detected RPPairing")
        ]
        for err in errors {
            let msg = err.localizedDescription
            XCTAssertFalse(containsHanCharacters(msg), "English error localizedDescription contains Han: \(msg)")
        }

        // SurgeBrotliShieldHelper hints & validation errors
        for platform in ProxyShieldPlatform.allCases {
            XCTAssertFalse(containsHanCharacters(platform.localizedUsageHint))
            let invalid = SurgeBrotliShieldHelper.shared.validateShield(content: "invalid", for: platform)
            XCTAssertFalse(invalid.isCompliant)
            for errMsg in invalid.errors {
                XCTAssertFalse(containsHanCharacters(errMsg), "English shield validation error contains Han: \(errMsg)")
            }
        }
    }

    func testUIViewsAndViewModelsContainZeroHardcodedChineseStrings() throws {
        let viewsDir = repositoryRoot.appendingPathComponent("WQGuard/App/Views")
        let vmDir = repositoryRoot.appendingPathComponent("WQGuard/App/ViewModels")

        for rootDir in [viewsDir, vmDir] {
            guard let enumerator = FileManager.default.enumerator(at: rootDir, includingPropertiesForKeys: nil) else {
                XCTFail("Failed to enumerate \(rootDir.path)")
                continue
            }
            for case let fileURL as URL in enumerator where fileURL.pathExtension == "swift" {
                let contents = try String(contentsOf: fileURL, encoding: .utf8)
                XCTAssertFalse(
                    containsHanCharacters(contents),
                    "Hardcoded Chinese characters found in \(fileURL.path); move strings to WQStrings.swift / Localizable.strings"
                )
            }
        }
    }

    func testLocalizationBundlesAndInfoPlistStringsPresent() throws {
        let enLocalizable = repositoryRoot.appendingPathComponent("WQGuard/App/Localization/en.lproj/Localizable.strings")
        let zhLocalizable = repositoryRoot.appendingPathComponent("WQGuard/App/Localization/zh-Hans.lproj/Localizable.strings")
        let enInfoPlist = repositoryRoot.appendingPathComponent("WQGuard/Resources/Localization/en.lproj/InfoPlist.strings")
        let zhInfoPlist = repositoryRoot.appendingPathComponent("WQGuard/Resources/Localization/zh-Hans.lproj/InfoPlist.strings")

        for url in [enLocalizable, zhLocalizable, enInfoPlist, zhInfoPlist] {
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.path), "Missing localization file: \(url.path)")
        }

        let enInfoStr = try String(contentsOf: enInfoPlist, encoding: .utf8)
        XCTAssertTrue(enInfoStr.contains("NSLocalNetworkUsageDescription"))
        XCTAssertFalse(containsHanCharacters(enInfoStr), "English InfoPlist.strings must not contain Han characters")
    }
}
