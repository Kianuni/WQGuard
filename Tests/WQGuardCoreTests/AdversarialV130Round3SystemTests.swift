//
//  AdversarialV130Round3SystemTests.swift
//  WQGuardCoreTests
//
//  Independent Adversarial Red-Team Challenger (Round 3):
//  1. Exhaustive 13-CVE multi-branch boundary matrix (iOS 17.7 - 28.0)
//  2. Full-stack bilingual (en / zh-Hans) & IOCTokenArmor integrity audit
//  3. Strict 100% read-only invariance torture (0444 + SHA-256 + st_mtimespec)
//  4. Empirical real-IPA self-armor & self-audit (build/WQGuard_v1.3.0.ipa)
//

import XCTest
import Foundation
import CryptoKit
import Darwin
import MachO
@testable import WQGuardCore

final class AdversarialV130Round3SystemTests: XCTestCase {

    private static let svc0x80: UInt32 = 0xD400_1001
    private static let nopInsn: UInt32 = 0xD503_201F
    private static let retInsn: UInt32 = 0xD65F_03C0

    private var tempURLs: [URL] = []
    private var readOnlyResetURLs: [URL] = []

    override func setUp() {
        super.setUp()
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
    }

    override func tearDown() {
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
        for url in readOnlyResetURLs.reversed() {
            restoreWritablePermissionsRecursively(at: url)
        }
        readOnlyResetURLs.removeAll()
        for url in tempURLs.reversed() {
            try? FileManager.default.removeItem(at: url)
        }
        tempURLs.removeAll()
        super.tearDown()
    }

    // MARK: - Helpers

    @discardableResult
    private func trackTemp(_ url: URL) -> URL {
        tempURLs.append(url)
        return url
    }

    private func markReadOnly(_ url: URL) throws {
        readOnlyResetURLs.append(url)
        XCTAssertEqual(chmod(url.path, 0o444), 0, "chmod 0o444 failed for \(url.path) (errno: \(errno))")
    }

    private func restoreWritablePermissionsRecursively(at url: URL) {
        var st = stat()
        guard lstat(url.path, &st) == 0 else { return }
        if (st.st_mode & S_IFMT) == S_IFDIR {
            _ = chmod(url.path, 0o777)
            if let enumerator = FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil) {
                for case let child as URL in enumerator {
                    var childStat = stat()
                    if lstat(child.path, &childStat) == 0 {
                        let mode: mode_t = (childStat.st_mode & S_IFMT) == S_IFDIR ? 0o777 : 0o666
                        _ = chmod(child.path, mode)
                    }
                }
            }
        } else {
            _ = chmod(url.path, 0o777)
        }
    }

    private func withLanguage(_ code: String, _ block: () throws -> Void) rethrows {
        let previous = WQLocale.overrideLanguageCode
        WQLocale.overrideLanguageCode = code
        defer { WQLocale.overrideLanguageCode = previous }
        try block()
    }

    /// Detects Han/CJK scalars across the four standard Unicode Han blocks.
    private func containsHanScalars(_ text: String) -> Bool {
        text.unicodeScalars.contains { scalar in
            let v = scalar.value
            return (0x4E00...0x9FFF).contains(v)
                || (0x3400...0x4DBF).contains(v)
                || (0xF900...0xFAFF).contains(v)
                || (0x20000...0x2EBEF).contains(v)
        }
    }

    /// Detects Han scalars as well as CJK Symbols/Punctuation and Halfwidth/Fullwidth forms for English leak checks.
    private func containsAnyCJKOrHanScalars(_ text: String) -> Bool {
        containsHanScalars(text) || text.unicodeScalars.contains { scalar in
            let v = scalar.value
            return (0x3000...0x303F).contains(v)
                || (0xFF00...0xFFEF).contains(v)
        }
    }

    private func wordsToLittleEndianData(_ words: [UInt32]) -> Data {
        var out = Data()
        out.reserveCapacity(words.count * 4)
        for word in words {
            var le = word.littleEndian
            withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
        }
        return out
    }

    private func makeEntitlementsXML(_ dict: [String: Any]) throws -> String {
        let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        return String(decoding: data, as: UTF8.self)
    }

    private func sha256Hex(of url: URL) throws -> String {
        let data = try Data(contentsOf: url, options: .alwaysMapped)
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func statInfo(of url: URL) throws -> (mtimeSec: Int, mtimeNsec: Int, mode: mode_t, size: off_t) {
        var st = stat()
        guard lstat(url.path, &st) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [
                NSLocalizedDescriptionKey: "lstat failed for \(url.path)"
            ])
        }
        return (Int(st.st_mtimespec.tv_sec), Int(st.st_mtimespec.tv_nsec), st.st_mode & 0o777, st.st_size)
    }

    private func assertFileStrictlyUnchanged(
        at url: URL,
        expectedSHA256: String,
        expectedStat: (mtimeSec: Int, mtimeNsec: Int, mode: mode_t, size: off_t),
        beforeSnapshot: ReadOnlyAssertions.FilesystemSnapshot,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let afterSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [url])
        ReadOnlyAssertions.assertUnmodified(before: beforeSnapshot, after: afterSnapshot, file: file, line: line)

        let actualSHA256 = try sha256Hex(of: url)
        let actualStat = try statInfo(of: url)
        XCTAssertEqual(actualSHA256, expectedSHA256, "SHA-256 changed for \(url.path)", file: file, line: line)
        XCTAssertEqual(actualStat.mtimeSec, expectedStat.mtimeSec, "st_mtimespec.tv_sec mutated for \(url.path)", file: file, line: line)
        XCTAssertEqual(actualStat.mtimeNsec, expectedStat.mtimeNsec, "st_mtimespec.tv_nsec mutated for \(url.path)", file: file, line: line)
        XCTAssertEqual(actualStat.mode, expectedStat.mode, "POSIX mode mutated for \(url.path)", file: file, line: line)
        XCTAssertEqual(actualStat.size, expectedStat.size, "File size mutated for \(url.path)", file: file, line: line)
    }

    private func createIPAFromBundle(
        appName: String,
        bundleId: String,
        mainBinary: Data,
        mainInfoExtras: [String: Any] = [:],
        appExtensions: [(name: String, bundleId: String, binary: Data, infoExtras: [String: Any])] = []
    ) throws -> URL {
        let stagingDir = trackTemp(
            FileManager.default.temporaryDirectory.appendingPathComponent("r3_ipa_stage_\(UUID().uuidString)")
        )
        let payloadDir = stagingDir.appendingPathComponent("Payload")
        let appDir = payloadDir.appendingPathComponent("\(appName).app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)

        var info: [String: Any] = [
            "CFBundleIdentifier": bundleId,
            "CFBundleDisplayName": appName,
            "CFBundleName": appName,
            "CFBundleExecutable": appName,
            "CFBundleShortVersionString": "1.3.0",
            "CFBundleVersion": "17",
            "CFBundlePackageType": "APPL"
        ]
        for (k, v) in mainInfoExtras {
            info[k] = v
        }
        let infoData = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        try infoData.write(to: appDir.appendingPathComponent("Info.plist"))

        let mainExecURL = appDir.appendingPathComponent(appName)
        try mainBinary.write(to: mainExecURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: mainExecURL.path)

        for ext in appExtensions {
            let extDir = appDir.appendingPathComponent("PlugIns").appendingPathComponent("\(ext.name).appex")
            try FileManager.default.createDirectory(at: extDir, withIntermediateDirectories: true)
            var extInfo: [String: Any] = [
                "CFBundleIdentifier": ext.bundleId,
                "CFBundleDisplayName": ext.name,
                "CFBundleExecutable": ext.name,
                "CFBundlePackageType": "XPC!"
            ]
            for (k, v) in ext.infoExtras {
                extInfo[k] = v
            }
            let extInfoData = try PropertyListSerialization.data(fromPropertyList: extInfo, format: .xml, options: 0)
            try extInfoData.write(to: extDir.appendingPathComponent("Info.plist"))

            let extExecURL = extDir.appendingPathComponent(ext.name)
            try ext.binary.write(to: extExecURL)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: extExecURL.path)
        }

        let ipaURL = trackTemp(
            FileManager.default.temporaryDirectory.appendingPathComponent("\(appName)_\(UUID().uuidString).ipa")
        )
        let zip = Process()
        zip.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        zip.currentDirectoryURL = stagingDir
        zip.arguments = ["-q", "-r", ipaURL.path, "Payload"]
        try zip.run()
        zip.waitUntilExit()
        XCTAssertEqual(zip.terminationStatus, 0, "zip must succeed creating test IPA")
        return ipaURL
    }

    // MARK: - 1. Exhaustive 13-CVE Multi-Branch Boundary Matrix (iOS 17.7 - 28.0)

    func test_round3_firmwarePosture_exhaustive13CVEMultiBranchBoundaryMatrix() {
        XCTAssertEqual(FirmwareCVEID.allCases.count, 13)
        XCTAssertEqual(FirmwarePostureEngine.allVulnerabilities.count, 13)
        XCTAssertEqual(
            Set(FirmwarePostureEngine.allVulnerabilities.map(\.cveId)),
            Set(FirmwareCVEID.allCases)
        )

        let engine = FirmwarePostureEngine.shared
        let all13 = Set(FirmwareCVEID.allCases)
        let validCategories = Set(MitigationCategory.allCases)

        struct VersionExpectation {
            let major: Int
            let minor: Int
            let patch: Int
            let expectedExposed: Set<FirmwareCVEID>
            let expectedTier: RiskTier
        }

        let fiveRemainingThrough27_2_0: Set<FirmwareCVEID> = [
            .worseQuery0day,
            .brotliOOB,
            .appIntentsBypass,
            .imessageGroup,
            .bluetoothAirPlay
        ]

        let matrix: [VersionExpectation] = [
            // Legacy iOS 17.7: excludes worseQuery0day (<26), accessorySetupBluetooth (<18), bookRestoreEscape (<18)
            .init(
                major: 17, minor: 7, patch: 0,
                expectedExposed: all13.subtracting([.worseQuery0day, .accessorySetupBluetooth, .bookRestoreEscape]),
                expectedTier: .highRisk
            ),
            // iOS 18 branch transitions
            .init(
                major: 18, minor: 0, patch: 0,
                expectedExposed: all13.subtracting([.worseQuery0day]),
                expectedTier: .highRisk
            ),
            .init(
                major: 18, minor: 7, patch: 4,
                expectedExposed: all13.subtracting([.worseQuery0day]),
                expectedTier: .highRisk
            ),
            .init(
                major: 18, minor: 7, patch: 5,
                expectedExposed: all13.subtracting([.worseQuery0day, .dyldZeroDay]),
                expectedTier: .highRisk
            ),
            .init(
                major: 18, minor: 7, patch: 10,
                expectedExposed: all13.subtracting([.worseQuery0day, .dyldZeroDay]),
                expectedTier: .highRisk
            ),
            .init(
                major: 18, minor: 7, patch: 11,
                expectedExposed: all13.subtracting([.worseQuery0day, .dyldZeroDay, .coreGraphics2D, .audioMxdBypass]),
                expectedTier: .highRisk
            ),
            // iOS 25.9.9: all except worseQuery0day (12)
            .init(
                major: 25, minor: 9, patch: 9,
                expectedExposed: all13.subtracting([.worseQuery0day]),
                expectedTier: .highRisk
            ),
            // iOS 26 branch transitions
            .init(major: 26, minor: 0, patch: 0, expectedExposed: all13, expectedTier: .highRisk),
            .init(major: 26, minor: 1, patch: 9, expectedExposed: all13, expectedTier: .highRisk),
            .init(
                major: 26, minor: 2, patch: 0,
                expectedExposed: all13.subtracting([.bookRestoreEscape]),
                expectedTier: .highRisk
            ),
            .init(
                major: 26, minor: 3, patch: 0,
                expectedExposed: all13.subtracting([.bookRestoreEscape, .dyldZeroDay]),
                expectedTier: .highRisk
            ),
            .init(
                major: 26, minor: 6, patch: 0,
                expectedExposed: all13.subtracting([.bookRestoreEscape, .dyldZeroDay]),
                expectedTier: .highRisk
            ),
            .init(
                major: 26, minor: 6, patch: 1,
                expectedExposed: all13.subtracting([.bookRestoreEscape, .dyldZeroDay, .audioMxdBypass]),
                expectedTier: .highRisk
            ),
            .init(
                major: 26, minor: 7, patch: 0,
                expectedExposed: all13.subtracting([.bookRestoreEscape, .dyldZeroDay, .audioMxdBypass]),
                expectedTier: .highRisk
            ),
            .init(
                major: 26, minor: 7, patch: 1,
                expectedExposed: all13.subtracting([.bookRestoreEscape, .dyldZeroDay, .audioMxdBypass, .coreGraphics2D]),
                expectedTier: .highRisk
            ),
            .init(
                major: 26, minor: 7, patch: 2,
                expectedExposed: fiveRemainingThrough27_2_0,
                expectedTier: .highRisk
            ),
            .init(
                major: 26, minor: 7, patch: 3,
                expectedExposed: [.worseQuery0day],
                expectedTier: .highRisk
            ),
            // iOS 27 & 28 branch transitions
            .init(
                major: 27, minor: 0, patch: 0,
                expectedExposed: all13.subtracting([.coreGraphics2D, .audioMxdBypass, .dyldZeroDay, .bookRestoreEscape]),
                expectedTier: .highRisk
            ),
            .init(
                major: 27, minor: 2, patch: 0,
                expectedExposed: fiveRemainingThrough27_2_0,
                expectedTier: .highRisk
            ),
            .init(major: 27, minor: 2, patch: 1, expectedExposed: [.worseQuery0day], expectedTier: .highRisk),
            .init(major: 27, minor: 2, patch: 9, expectedExposed: [.worseQuery0day], expectedTier: .highRisk),
            .init(major: 27, minor: 3, patch: 0, expectedExposed: [], expectedTier: .safe),
            .init(major: 28, minor: 0, patch: 0, expectedExposed: [], expectedTier: .safe)
        ]

        for entry in matrix {
            let ver = SystemOSVersion(major: entry.major, minor: entry.minor, patch: entry.patch)
            let label = "\(entry.major).\(entry.minor).\(entry.patch)"

            for cve in FirmwareCVEID.allCases {
                let expected = entry.expectedExposed.contains(cve)
                XCTAssertEqual(
                    engine.isVulnerable(cve, in: ver),
                    expected,
                    "iOS \(label): mismatch on \(cve.rawValue)"
                )
            }

            let report = engine.evaluate(osVersion: ver)
            XCTAssertEqual(report.totalEvaluated, 13, "iOS \(label): totalEvaluated must be 13")
            XCTAssertEqual(report.exposedCount, entry.expectedExposed.count, "iOS \(label): exposedCount mismatch")
            XCTAssertEqual(report.exposedVulnerabilities.count, entry.expectedExposed.count, "iOS \(label)")
            XCTAssertEqual(report.patchedVulnerabilities.count, 13 - entry.expectedExposed.count, "iOS \(label)")
            XCTAssertEqual(Set(report.exposedVulnerabilities.map(\.cveId)), entry.expectedExposed, "iOS \(label)")
            XCTAssertEqual(Set(report.patchedVulnerabilities.map(\.cveId)), all13.subtracting(entry.expectedExposed), "iOS \(label)")
            XCTAssertEqual(report.overallRiskTier, entry.expectedTier, "iOS \(label)")

            if entry.expectedExposed.isEmpty {
                XCTAssertTrue(report.actionableMitigations.isEmpty, "iOS \(label): safe build must have empty actionableMitigations")
            } else {
                XCTAssertFalse(report.actionableMitigations.isEmpty, "iOS \(label): vulnerable build must include mitigations")
                let ids = report.actionableMitigations.map(\.id)
                XCTAssertEqual(Set(ids).count, ids.count, "iOS \(label): duplicate mitigation IDs")
                for mitigation in report.actionableMitigations {
                    XCTAssertTrue(validCategories.contains(mitigation.category), "Invalid category on iOS \(label)")
                    XCTAssertFalse(mitigation.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    XCTAssertFalse(mitigation.instructions.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    XCTAssertFalse(mitigation.relatedCVEs.isEmpty)
                }
            }
        }

        // Verify string parsing across major transitions
        let parsedPairs: [(String, Int)] = [
            ("17.7", 10),
            ("iOS 18.7.11 (22H217)", 9),
            ("26.7.2", 5),
            ("26.7.3", 1),
            ("27.2.1-beta1", 1),
            ("iOS 27.3", 0),
            ("28.0", 0)
        ]
        for (raw, expectedExposed) in parsedPairs {
            guard let parsed = SystemOSVersion(string: raw) else {
                XCTFail("Failed to parse version string: \(raw)")
                continue
            }
            let report = engine.evaluate(osVersion: parsed)
            XCTAssertEqual(report.exposedCount, expectedExposed, "Parsed '\(raw)' expected \(expectedExposed) exposed")
        }
    }

    // MARK: - 2. Full-Stack Bilingual (en / zh-Hans) & IOCTokenArmor Integrity Audit

    func test_round3_iocTokenArmor_exactKeysAndPatterns() {
        let expectedPatternsByKey: [String: String] = [
            "com.apple.audio.audiomxd": "CVE-2026-65339:com.apple.audio.audiomxd",
            "com.apple.coremedia.audiomxd": "CVE-2026-65339:com.apple.coremedia.audiomxd",
            "com.apple.bookassetd": "BookRestore:com.apple.bookassetd",
            "com.apple.itunesstored": "BookRestore:com.apple.itunesstored",
            "BLDatabaseManager.sqlite": "BookRestore:BLDatabaseManager.sqlite",
            "downloads.28.sqlitedb": "BookRestore:downloads.28.sqlitedb",
            "com.apple.MobileGestalt.plist": "MobileGestaltTamper:com.apple.MobileGestalt.plist",
            "systemgroup.com.apple.mobilegestaltcache": "MobileGestaltTamper:mobilegestaltcache"
        ]

        let rules = SignatureCatalog.standaloneExploitStringRules
        XCTAssertEqual(rules.count, expectedPatternsByKey.count)
        XCTAssertEqual(Set(rules.keys), Set(expectedPatternsByKey.keys))
        XCTAssertEqual(Set(SignatureCatalog.standaloneExploitCandidateStrings), Set(expectedPatternsByKey.keys))

        for (key, expectedPattern) in expectedPatternsByKey {
            let rule = rules[key]
            XCTAssertNotNil(rule, "Missing standaloneExploitStringRules entry for \(key)")
            XCTAssertEqual(rule?.pattern, expectedPattern)
            XCTAssertEqual(rule?.severity, .highRisk)
        }

        XCTAssertEqual(IOCTokenArmor.tAudioDaemon, "com.apple.audio.audiomxd")
        XCTAssertEqual(IOCTokenArmor.tCoreMediaDaemon, "com.apple.coremedia.audiomxd")
        XCTAssertEqual(IOCTokenArmor.tBookDaemon, "com.apple.bookassetd")
        XCTAssertEqual(IOCTokenArmor.tStoreDaemon, "com.apple.itunesstored")
        XCTAssertEqual(IOCTokenArmor.tStorePrivPrefix, "com.apple.itunesstored.private")
        XCTAssertEqual(IOCTokenArmor.tBookSQLite, "BLDatabaseManager.sqlite")
        XCTAssertEqual(IOCTokenArmor.tDownloadsSQLite, "downloads.28.sqlitedb")
        XCTAssertEqual(IOCTokenArmor.tGestaltPlist, "com.apple.MobileGestalt.plist")
        XCTAssertEqual(IOCTokenArmor.tGestaltGroup, "systemgroup.com.apple.mobilegestaltcache")
    }

    func test_round3_bilingualFullStack_enZeroHanCJK_andZhHansLocalized() throws {
        let restrictedEnts: [String: Any] = [
            "com.apple.private.mediaexperience.allow": true,
            "com.apple.private.cmsession.allow": true,
            "com.apple.private.bookassetd.spi": true,
            "com.apple.itunesstored.private": true,
            "com.apple.private.MobileGestalt.allowed": true,
            "com.apple.private.accessorysetupkit.bypass": true
        ]
        let restrictedEntXML = try makeEntitlementsXML(restrictedEnts)

        let evilMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: [
                "/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience",
                "/System/Library/PrivateFrameworks/BookLibraryPrivate.framework/BookLibraryPrivate",
                "/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"
            ],
            symbols: [
                "_CMSessionSetProperty",
                "_AudioSessionSetCMProperty",
                "_OBJC_CLASS_$_ASAccessorySession"
            ],
            xmlEntitlements: restrictedEntXML,
            textInstructions: [Self.svc0x80, Self.retInsn],
            extraCStringLiterals: [
                "com.apple.audio.audiomxd",
                "com.apple.coremedia.audiomxd",
                "com.apple.bookassetd",
                "com.apple.itunesstored",
                "BLDatabaseManager.sqlite",
                "downloads.28.sqlitedb",
                "com.apple.MobileGestalt.plist",
                "systemgroup.com.apple.mobilegestaltcache"
            ]
        ))

        let evilIPA = try createIPAFromBundle(
            appName: "BilingualEvil",
            bundleId: "com.test.bilingual.evil",
            mainBinary: evilMachO
        )

        let cautionMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_dlopen", "_dlsym"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.test.caution"]),
            textInstructions: [Self.nopInsn, Self.retInsn]
        ))
        let cautionIPA = try createIPAFromBundle(
            appName: "BilingualCaution",
            bundleId: "com.test.bilingual.caution",
            mainBinary: cautionMachO
        )

        let safeMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"],
            textInstructions: [Self.nopInsn, Self.retInsn]
        ))
        let safeIPA = try createIPAFromBundle(
            appName: "BilingualSafe",
            bundleId: "com.test.bilingual.safe",
            mainBinary: safeMachO
        )

        let wqMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_container_query_create", "_dlopen", "_dlsym"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.wqguard.app"]),
            textInstructions: [Self.nopInsn, Self.retInsn]
        ))
        let wqIPA = try createIPAFromBundle(
            appName: "WQGuard",
            bundleId: "com.wqguard.app",
            mainBinary: wqMachO
        )

        let drmSafeMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            symbols: ["_main"],
            textInstructions: [Self.nopInsn, Self.retInsn]
        ))

        let regHighRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.test.reg.high",
            "CFBundleDisplayName": "RegHigh",
            "CFBundleShortVersionString": "1.0",
            "ApplicationType": "User",
            "SignerIdentity": "Apple Development: dev@test.com",
            "ProfileValidated": true,
            "Entitlements": restrictedEnts,
            "Path": "/private/var/containers/Bundle/Application/UUID-1/RegHigh.app"
        ]))
        let regCautionRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.test.reg.caution",
            "CFBundleDisplayName": "RegCaution",
            "CFBundleShortVersionString": "1.0",
            "ApplicationType": "User",
            "SignerIdentity": "Apple Development: dev@test.com",
            "ProfileValidated": true,
            "Entitlements": [
                "com.apple.security.application-groups": ["group.com.test.caution"]
            ],
            "Path": "/private/var/containers/Bundle/Application/UUID-2/RegCaution.app"
        ]))
        let regWQRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.wqguard.app",
            "CFBundleDisplayName": "WQGuard",
            "CFBundleShortVersionString": "1.3.0",
            "ApplicationType": "User",
            "SignerIdentity": "Apple Development: dev@test.com",
            "ProfileValidated": true,
            "Entitlements": [
                "com.apple.security.application-groups": ["group.com.wqguard.app"]
            ],
            "Path": "/private/var/containers/Bundle/Application/UUID-3/WQGuard.app"
        ]))
        let regSafeRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.test.reg.safe",
            "CFBundleDisplayName": "RegSafe",
            "CFBundleShortVersionString": "1.0",
            "ApplicationType": "User",
            "SignerIdentity": "Apple iPhone OS Application Signing",
            "ProfileValidated": false,
            "ApplicationDSID": 123456789,
            "Entitlements": [:],
            "Path": "/private/var/containers/Bundle/Application/UUID-4/RegSafe.app"
        ]))

        // --- Pass 1: English ("en") -> ZERO Han / CJK scalars anywhere ---
        try withLanguage("en") {
            // 1. FirmwarePostureEngine (all 13 CVEs + mitigations + report)
            let fwReport = FirmwarePostureEngine.shared.evaluate(osVersion: SystemOSVersion(major: 26, minor: 0))
            let allVulns = fwReport.exposedVulnerabilities + fwReport.patchedVulnerabilities
            XCTAssertEqual(allVulns.count, 13)
            for vuln in allVulns {
                XCTAssertFalse(containsAnyCJKOrHanScalars(vuln.name), "EN CVE name has CJK: \(vuln.name)")
                XCTAssertFalse(containsAnyCJKOrHanScalars(vuln.subsystem), "EN subsystem has CJK: \(vuln.subsystem)")
                XCTAssertFalse(containsAnyCJKOrHanScalars(vuln.affectedDescription), "EN affectedDescription has CJK: \(vuln.affectedDescription)")
                XCTAssertFalse(containsAnyCJKOrHanScalars(vuln.patchedVersionDescription), "EN patchedVersionDescription has CJK: \(vuln.patchedVersionDescription)")
                XCTAssertFalse(containsAnyCJKOrHanScalars(vuln.details), "EN details has CJK: \(vuln.details)")
                XCTAssertFalse(vuln.mitigations.isEmpty)
                for mit in vuln.mitigations {
                    XCTAssertFalse(containsAnyCJKOrHanScalars(mit.title), "EN mitigation title has CJK: \(mit.title)")
                    XCTAssertFalse(containsAnyCJKOrHanScalars(mit.instructions), "EN mitigation instructions has CJK: \(mit.instructions)")
                }
            }
            for mit in fwReport.actionableMitigations {
                XCTAssertFalse(containsAnyCJKOrHanScalars(mit.title))
                XCTAssertFalse(containsAnyCJKOrHanScalars(mit.instructions))
            }

            // 2. SignatureCatalog new rules
            let newRules = [SignatureCatalog.directSyscallRule]
                + Array(SignatureCatalog.standaloneExploitDylibRules.values)
                + Array(SignatureCatalog.standaloneExploitSymbolRules.values)
                + Array(SignatureCatalog.standaloneExploitStringRules.values)
            XCTAssertEqual(newRules.count, 13)
            for rule in newRules {
                let ind = rule.toIndicator()
                XCTAssertFalse(containsAnyCJKOrHanScalars(ind.description), "EN rule description has CJK (\(rule.id)): \(ind.description)")
                XCTAssertFalse(containsAnyCJKOrHanScalars(ind.category), "EN rule category has CJK (\(rule.id)): \(ind.category)")
                XCTAssertFalse(containsAnyCJKOrHanScalars(ind.location))
                XCTAssertFalse(containsAnyCJKOrHanScalars(ind.signature))
            }

            // 3. MachOScanner (svc #0x80 + standalone 2026 indicators + all 5 remediation tiers)
            let machoHigh = try MachOScanner.shared.scan(binaryData: evilMachO, context: .init(bundleId: "com.test.macho.high"))
            let machoCaution = try MachOScanner.shared.scan(binaryData: cautionMachO, context: .init(bundleId: "com.test.macho.caution", appGroups: ["group.com.test.caution"]))
            let machoWQ = try MachOScanner.shared.scan(binaryData: wqMachO, context: .init(bundleId: "com.wqguard.app", appGroups: ["group.com.wqguard.app"]))
            let machoSafe = try MachOScanner.shared.scan(binaryData: safeMachO, context: .init(bundleId: "com.test.macho.safe"))
            let machoDRM = try MachOScanner.shared.scan(binaryData: drmSafeMachO, context: .init(bundleId: "com.test.macho.drm", installChannel: .appStore))

            XCTAssertEqual(machoHigh.riskTier, .highRisk)
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "arm64:svc_0x80" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "CVE-2026-65339:MediaExperience.framework" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "CVE-2026-65339:CMSessionSetProperty" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "CVE-2026-65339:AudioSessionSetCMProperty" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "CVE-2026-65339:com.apple.audio.audiomxd" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "CVE-2026-65339:com.apple.coremedia.audiomxd" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "BookRestore:BookLibraryPrivate.framework" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "BookRestore:com.apple.bookassetd" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "BookRestore:com.apple.itunesstored" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "BookRestore:BLDatabaseManager.sqlite" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "BookRestore:downloads.28.sqlitedb" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "MobileGestaltTamper:com.apple.MobileGestalt.plist" })
            XCTAssertTrue(machoHigh.indicators.contains { $0.signature == "MobileGestaltTamper:mobilegestaltcache" })
            XCTAssertEqual(machoCaution.riskTier, .caution)
            XCTAssertEqual(machoWQ.riskTier, .knownTool)
            XCTAssertEqual(machoSafe.riskTier, .safe)
            XCTAssertEqual(machoDRM.riskTier, .safe)

            for f in [machoHigh, machoCaution, machoWQ, machoSafe, machoDRM] {
                XCTAssertFalse(containsAnyCJKOrHanScalars(f.evidence.remediationGuidance), "EN MachOScanner remediation has CJK: \(f.evidence.remediationGuidance)")
                for ind in f.indicators {
                    XCTAssertFalse(containsAnyCJKOrHanScalars(ind.description), "EN MachO indicator has CJK: \(ind.description)")
                    XCTAssertFalse(containsAnyCJKOrHanScalars(ind.category))
                    XCTAssertFalse(containsAnyCJKOrHanScalars(ind.location))
                }
            }

            // 4. ExpandedThreatCatalog new evaluators
            let audioInds = ExpandedThreatCatalog.evaluateAudioMxdBypass(
                linkedDylibs: ["/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"],
                symbols: ["_CMSessionSetProperty", "_AudioSessionSetCMProperty"],
                entitlements: restrictedEnts,
                cryptid: 0
            )
            XCTAssertEqual(audioInds.count, 5)
            let bookInds = ExpandedThreatCatalog.evaluateBookRestoreAndGestalt(
                linkedDylibs: ["/System/Library/PrivateFrameworks/BookLibraryPrivate.framework/BookLibraryPrivate"],
                textStrings: [
                    "com.apple.bookassetd",
                    "com.apple.itunesstored",
                    "BLDatabaseManager.sqlite",
                    "downloads.28.sqlitedb",
                    "com.apple.MobileGestalt.plist",
                    "systemgroup.com.apple.mobilegestaltcache"
                ],
                entitlements: restrictedEnts,
                cryptid: 0
            )
            XCTAssertEqual(bookInds.count, 10)
            let accInds = ExpandedThreatCatalog.evaluateAccessorySetupBypass(
                linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"],
                symbols: ["_OBJC_CLASS_$_ASAccessorySession"],
                infoPlist: [:],
                entitlements: restrictedEnts,
                installChannel: .developerSideloaded,
                cryptid: 0
            )
            XCTAssertEqual(accInds.count, 2)
            for ind in audioInds + bookInds + accInds {
                XCTAssertFalse(containsAnyCJKOrHanScalars(ind.description), "EN ExpandedThreatCatalog has CJK: \(ind.description)")
                XCTAssertFalse(containsAnyCJKOrHanScalars(ind.category))
                XCTAssertFalse(containsAnyCJKOrHanScalars(ind.location))
            }

            // 5. InstalledAppRegistryScanner (new 2026 entitlements + all 4 remediation tiers)
            let regFindings = InstalledAppRegistryScanner.shared.evaluateRecords(
                [regHighRec, regCautionRec, regWQRec, regSafeRec],
                includeAppStoreApps: true
            )
            XCTAssertEqual(regFindings.count, 4)
            XCTAssertEqual(regFindings[0].indicators.count, 6)
            for f in regFindings {
                XCTAssertFalse(containsAnyCJKOrHanScalars(f.evidence.remediationGuidance), "EN Registry remediation has CJK: \(f.evidence.remediationGuidance)")
                for ind in f.indicators {
                    XCTAssertFalse(containsAnyCJKOrHanScalars(ind.description), "EN Registry indicator has CJK: \(ind.description)")
                    XCTAssertFalse(containsAnyCJKOrHanScalars(ind.category))
                }
            }

            // 6. IPAPackageScanner (all 4 remediation tiers + indicators + errors)
            let ipaHigh = try IPAPackageScanner.shared.scan(ipaURL: evilIPA)
            let ipaCaution = try IPAPackageScanner.shared.scan(ipaURL: cautionIPA)
            let ipaWQ = try IPAPackageScanner.shared.scan(ipaURL: wqIPA)
            let ipaSafe = try IPAPackageScanner.shared.scan(ipaURL: safeIPA)

            XCTAssertEqual(ipaHigh.riskTier, .highRisk)
            XCTAssertTrue(ipaHigh.indicators.contains { $0.signature == "arm64:svc_0x80" })
            XCTAssertTrue(ipaHigh.indicators.contains { $0.signature == "CVE-2026-65339:com.apple.audio.audiomxd" })
            XCTAssertTrue(ipaHigh.indicators.contains { $0.signature == "BookRestore:BLDatabaseManager.sqlite" })
            XCTAssertTrue(ipaHigh.indicators.contains { $0.signature == "MobileGestaltTamper:com.apple.MobileGestalt.plist" })
            XCTAssertTrue(ipaHigh.indicators.contains { $0.signature == "CVE-2026-84493:PrivateAccessoryEntitlement" })
            XCTAssertEqual(ipaCaution.riskTier, .caution)
            XCTAssertEqual(ipaWQ.riskTier, .knownTool)
            XCTAssertEqual(ipaSafe.riskTier, .safe)

            for f in [ipaHigh, ipaCaution, ipaWQ, ipaSafe] {
                XCTAssertFalse(containsAnyCJKOrHanScalars(f.evidence.remediationGuidance), "EN IPA remediation has CJK: \(f.evidence.remediationGuidance)")
                for ind in f.indicators {
                    XCTAssertFalse(containsAnyCJKOrHanScalars(ind.description), "EN IPA indicator has CJK: \(ind.description)")
                    XCTAssertFalse(containsAnyCJKOrHanScalars(ind.category))
                }
            }
            for err in [
                IPAPackageScannerError.missingPayload,
                IPAPackageScannerError.zipSlipDetected("../evil"),
                IPAPackageScannerError.quotaExceeded("1GB"),
                IPAPackageScannerError.invalidInfoPlist("corrupt")
            ] {
                XCTAssertFalse(containsAnyCJKOrHanScalars(err.localizedDescription))
            }
        }

        // --- Pass 2: Simplified Chinese ("zh-Hans") -> Han scalars emitted across all components ---
        try withLanguage("zh-Hans") {
            // 1. FirmwarePostureEngine
            let fwReport = FirmwarePostureEngine.shared.evaluate(osVersion: SystemOSVersion(major: 26, minor: 0))
            let allVulns = fwReport.exposedVulnerabilities + fwReport.patchedVulnerabilities
            XCTAssertEqual(allVulns.count, 13)
            for vuln in allVulns {
                XCTAssertTrue(containsHanScalars(vuln.name), "ZH CVE name missing Han: \(vuln.name)")
                XCTAssertTrue(containsHanScalars(vuln.affectedDescription), "ZH affectedDescription missing Han: \(vuln.affectedDescription)")
                XCTAssertTrue(containsHanScalars(vuln.details), "ZH details missing Han: \(vuln.details)")
                for mit in vuln.mitigations {
                    XCTAssertTrue(containsHanScalars(mit.title), "ZH mitigation title missing Han: \(mit.title)")
                    XCTAssertTrue(containsHanScalars(mit.instructions), "ZH mitigation instructions missing Han: \(mit.instructions)")
                }
            }

            // 2. SignatureCatalog new rules
            let newRules = [SignatureCatalog.directSyscallRule]
                + Array(SignatureCatalog.standaloneExploitDylibRules.values)
                + Array(SignatureCatalog.standaloneExploitSymbolRules.values)
                + Array(SignatureCatalog.standaloneExploitStringRules.values)
            for rule in newRules {
                let desc = rule.toIndicator().description
                XCTAssertTrue(containsHanScalars(desc), "ZH rule description missing Han (\(rule.id)): \(desc)")
            }

            // 3. MachOScanner
            let machoHigh = try MachOScanner.shared.scan(binaryData: evilMachO, context: .init(bundleId: "com.test.macho.high"))
            let machoCaution = try MachOScanner.shared.scan(binaryData: cautionMachO, context: .init(bundleId: "com.test.macho.caution", appGroups: ["group.com.test.caution"]))
            let machoWQ = try MachOScanner.shared.scan(binaryData: wqMachO, context: .init(bundleId: "com.wqguard.app", appGroups: ["group.com.wqguard.app"]))
            let machoSafe = try MachOScanner.shared.scan(binaryData: safeMachO, context: .init(bundleId: "com.test.macho.safe"))
            let machoDRM = try MachOScanner.shared.scan(binaryData: drmSafeMachO, context: .init(bundleId: "com.test.macho.drm", installChannel: .appStore))

            for f in [machoHigh, machoCaution, machoWQ, machoSafe, machoDRM] {
                XCTAssertTrue(containsHanScalars(f.evidence.remediationGuidance), "ZH MachOScanner remediation missing Han: \(f.evidence.remediationGuidance)")
                for ind in f.indicators {
                    XCTAssertTrue(containsHanScalars(ind.description), "ZH MachO indicator missing Han: \(ind.description)")
                }
            }

            // 4. ExpandedThreatCatalog new evaluators
            let audioInds = ExpandedThreatCatalog.evaluateAudioMxdBypass(
                linkedDylibs: ["/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"],
                symbols: ["_CMSessionSetProperty", "_AudioSessionSetCMProperty"],
                entitlements: restrictedEnts,
                cryptid: 0
            )
            let bookInds = ExpandedThreatCatalog.evaluateBookRestoreAndGestalt(
                linkedDylibs: ["/System/Library/PrivateFrameworks/BookLibraryPrivate.framework/BookLibraryPrivate"],
                textStrings: [
                    "com.apple.bookassetd",
                    "com.apple.itunesstored",
                    "BLDatabaseManager.sqlite",
                    "downloads.28.sqlitedb",
                    "com.apple.MobileGestalt.plist",
                    "systemgroup.com.apple.mobilegestaltcache"
                ],
                entitlements: restrictedEnts,
                cryptid: 0
            )
            let accInds = ExpandedThreatCatalog.evaluateAccessorySetupBypass(
                linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"],
                symbols: ["_OBJC_CLASS_$_ASAccessorySession"],
                infoPlist: [:],
                entitlements: restrictedEnts,
                installChannel: .developerSideloaded,
                cryptid: 0
            )
            for ind in audioInds + bookInds + accInds {
                XCTAssertTrue(containsHanScalars(ind.description), "ZH ExpandedThreatCatalog missing Han: \(ind.description)")
            }

            // 5. InstalledAppRegistryScanner
            let regFindings = InstalledAppRegistryScanner.shared.evaluateRecords(
                [regHighRec, regCautionRec, regWQRec, regSafeRec],
                includeAppStoreApps: true
            )
            XCTAssertEqual(regFindings.count, 4)
            for f in regFindings {
                XCTAssertTrue(containsHanScalars(f.evidence.remediationGuidance), "ZH Registry remediation missing Han: \(f.evidence.remediationGuidance)")
                for ind in f.indicators {
                    XCTAssertTrue(containsHanScalars(ind.description), "ZH Registry indicator missing Han: \(ind.description)")
                }
            }

            // 6. IPAPackageScanner
            let ipaHigh = try IPAPackageScanner.shared.scan(ipaURL: evilIPA)
            let ipaCaution = try IPAPackageScanner.shared.scan(ipaURL: cautionIPA)
            let ipaWQ = try IPAPackageScanner.shared.scan(ipaURL: wqIPA)
            let ipaSafe = try IPAPackageScanner.shared.scan(ipaURL: safeIPA)

            for f in [ipaHigh, ipaCaution, ipaWQ, ipaSafe] {
                XCTAssertTrue(containsHanScalars(f.evidence.remediationGuidance), "ZH IPA remediation missing Han: \(f.evidence.remediationGuidance)")
                for ind in f.indicators {
                    XCTAssertTrue(containsHanScalars(ind.description), "ZH IPA indicator missing Han: \(ind.description)")
                }
            }
        }
    }

    // MARK: - 3. Strict 100% Read-Only Invariance Torture (0444 + SHA-256 + st_mtimespec)

    func test_round3_readOnlyInvariance_0444_macho_ipaWithAppex_andRegistrySnapshot() throws {
        let codePayload = wordsToLittleEndianData([Self.svc0x80, Self.retInsn])

        // 1. Mach-O with svc #0x80 in BOTH __TEXT,__text AND __EVIL,__code under chmod 0o444
        let machoData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.nopInsn, Self.svc0x80, Self.retInsn],
            customSections: [
                (segName: "__EVIL", sectName: "__code", flags: UInt32(S_REGULAR), payload: codePayload)
            ]
        ))
        let machoURL = trackTemp(
            FileManager.default.temporaryDirectory.appendingPathComponent("r3_ro_macho_\(UUID().uuidString)")
        )
        try machoData.write(to: machoURL)
        try markReadOnly(machoURL)

        let machoBeforeSHA = try sha256Hex(of: machoURL)
        let machoBeforeStat = try statInfo(of: machoURL)
        XCTAssertEqual(machoBeforeStat.mode, 0o444)
        let machoBeforeSnap = try ReadOnlyAssertions.captureSnapshot(of: [machoURL])

        let machoDirectFinding = try MachOScanner.shared.scan(
            binaryURL: machoURL,
            context: .init(bundleId: "com.ro.macho", executablePath: machoURL.path)
        )
        let machoPipelineFinding = try SecurityPipeline.shared.scanBinary(at: machoURL)

        let parsedSlices = try MachOParser.shared.parseAllSlices(data: try Data(contentsOf: machoURL, options: .mappedIfSafe))
        let parsedDetails = MachOScanner.shared.parseMachO(files: parsedSlices)
        XCTAssertEqual(parsedDetails.directSyscallCount, 2)
        XCTAssertTrue(parsedDetails.directSyscallSites.contains { $0.segmentName == "__TEXT" && $0.sectionName == "__text" })
        XCTAssertTrue(parsedDetails.directSyscallSites.contains { $0.segmentName == "__EVIL" && $0.sectionName == "__code" })

        for f in [machoDirectFinding, machoPipelineFinding] {
            XCTAssertEqual(f.riskTier, .highRisk)
            XCTAssertTrue(f.indicators.contains { $0.signature == "arm64:svc_0x80" })
        }

        try assertFileStrictlyUnchanged(
            at: machoURL,
            expectedSHA256: machoBeforeSHA,
            expectedStat: machoBeforeStat,
            beforeSnapshot: machoBeforeSnap
        )

        // 2. Combined .ipa under chmod 0o444: svc #0x80 + CVE-2026-65339 + BookRestore + AccessorySetupKit inside PlugIns/*.appex
        let mainEntXML = try makeEntitlementsXML([
            "com.apple.private.mediaexperience.allow": true,
            "com.apple.itunesstored.private": true
        ])
        let combinedMainBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: [
                "/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience",
                "/System/Library/PrivateFrameworks/BookLibraryPrivate.framework/BookLibraryPrivate"
            ],
            symbols: ["_CMSessionSetProperty"],
            xmlEntitlements: mainEntXML,
            textInstructions: [Self.svc0x80, Self.retInsn],
            customSections: [
                (segName: "__EVIL", sectName: "__code", flags: UInt32(S_REGULAR), payload: codePayload)
            ],
            extraCStringLiterals: [
                "com.apple.audio.audiomxd",
                "com.apple.bookassetd",
                "BLDatabaseManager.sqlite",
                "downloads.28.sqlitedb"
            ]
        ))
        let appexAccBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"],
            symbols: ["_OBJC_CLASS_$_ASAccessorySession"]
        ))
        let ipaURL = try createIPAFromBundle(
            appName: "CombinedReadOnly",
            bundleId: "com.ro.combined",
            mainBinary: combinedMainBin,
            appExtensions: [
                (
                    name: "AccPlugin",
                    bundleId: "com.ro.combined.accplugin",
                    binary: appexAccBin,
                    infoExtras: [:]
                )
            ]
        )
        try markReadOnly(ipaURL)

        let ipaBeforeSHA = try sha256Hex(of: ipaURL)
        let ipaBeforeStat = try statInfo(of: ipaURL)
        XCTAssertEqual(ipaBeforeStat.mode, 0o444)
        let ipaBeforeSnap = try ReadOnlyAssertions.captureSnapshot(of: [ipaURL])

        let ipaDirectFinding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        let ipaPipelineFinding = try SecurityPipeline.shared.scanIPA(at: ipaURL)

        for f in [ipaDirectFinding, ipaPipelineFinding] {
            XCTAssertEqual(f.riskTier, .highRisk)
            XCTAssertTrue(f.indicators.contains { $0.signature == "arm64:svc_0x80" })
            XCTAssertTrue(f.indicators.contains { $0.signature == "CVE-2026-65339:com.apple.audio.audiomxd" })
            XCTAssertTrue(f.indicators.contains { $0.signature == "CVE-2026-65339:MediaExperience.framework" })
            XCTAssertTrue(f.indicators.contains { $0.signature == "BookRestore:BLDatabaseManager.sqlite" })
            XCTAssertTrue(f.indicators.contains { $0.signature == "BookRestore:com.apple.itunesstored.private" })
            let accInd = f.indicators.first { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" }
            XCTAssertNotNil(accInd)
            XCTAssertTrue(accInd?.location.hasPrefix("PlugIns/AccPlugin.appex/AccPlugin:") ?? false)
        }

        try assertFileStrictlyUnchanged(
            at: ipaURL,
            expectedSHA256: ipaBeforeSHA,
            expectedStat: ipaBeforeStat,
            beforeSnapshot: ipaBeforeSnap
        )

        // 3. installation_proxy snapshot under chmod 0o444 carrying restricted 2026 entitlements
        let snapshotPlist: [[String: Any]] = [
            [
                "CFBundleIdentifier": "com.ro.registry.sideload",
                "CFBundleDisplayName": "ReadOnlySideload",
                "CFBundleShortVersionString": "1.0",
                "ApplicationType": "User",
                "SignerIdentity": "Apple Development: ro@evil.org",
                "ProfileValidated": true,
                "Entitlements": [
                    "com.apple.private.mediaexperience.allow": true,
                    "com.apple.private.cmsession.allow": true,
                    "com.apple.private.bookassetd.spi": true,
                    "com.apple.itunesstored.private": true,
                    "com.apple.private.MobileGestalt.allowed": true,
                    "com.apple.private.accessorysetupkit.bypass": true
                ],
                "Path": "/private/var/containers/Bundle/Application/UUID-RO1/ReadOnlySideload.app"
            ],
            [
                "CFBundleIdentifier": "com.ro.registry.disguised",
                "CFBundleDisplayName": "ReadOnlyDisguised",
                "CFBundleShortVersionString": "1.0",
                "ApplicationType": "User",
                "SignerIdentity": "Apple iPhone OS Application Signing",
                "ProfileValidated": false,
                "ApplicationDSID": 987654321,
                "Entitlements": [
                    "com.apple.private.accessorysetupkit.allow": true
                ],
                "Path": "/private/var/containers/Bundle/Application/UUID-RO2/ReadOnlyDisguised.app"
            ]
        ]
        let snapshotData = try PropertyListSerialization.data(fromPropertyList: snapshotPlist, format: .xml, options: 0)
        let snapshotURL = trackTemp(
            FileManager.default.temporaryDirectory.appendingPathComponent("r3_ro_snapshot_\(UUID().uuidString).plist")
        )
        try snapshotData.write(to: snapshotURL)
        try markReadOnly(snapshotURL)

        let snapBeforeSHA = try sha256Hex(of: snapshotURL)
        let snapBeforeStat = try statInfo(of: snapshotURL)
        XCTAssertEqual(snapBeforeStat.mode, 0o444)
        let snapBeforeReadOnly = try ReadOnlyAssertions.captureSnapshot(of: [snapshotURL])

        let parsedRecords = try InstalledAppRegistryScanner.shared.parseSnapshotFile(at: snapshotURL)
        let regFindings = InstalledAppRegistryScanner.shared.evaluateRecords(parsedRecords, includeAppStoreApps: false)
        let pipelineRegFindings = try SecurityPipeline.shared.scanRegistrySnapshot(at: snapshotURL, includeAppStoreApps: false)

        XCTAssertEqual(regFindings.count, 2)
        XCTAssertEqual(pipelineRegFindings.count, 2)
        for f in regFindings + pipelineRegFindings {
            XCTAssertEqual(f.riskTier, .highRisk)
        }
        XCTAssertEqual(regFindings[0].indicators.count, 6)
        XCTAssertTrue(regFindings[1].indicators.contains { $0.signature == "CVE-2026-84493:PrivateAccessoryEntitlement" })

        try assertFileStrictlyUnchanged(
            at: snapshotURL,
            expectedSHA256: snapBeforeSHA,
            expectedStat: snapBeforeStat,
            beforeSnapshot: snapBeforeReadOnly
        )
    }

    // MARK: - 4. Empirical Real-IPA Self-Armor & Self-Audit (build/WQGuard_v1.3.1.ipa)

    func test_round3_empiricalRealIPA_selfArmorZeroLeaksAndKnownToolSelfAudit() throws {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let ipaURL = repoRoot.appendingPathComponent("build/WQGuard_v1.3.1.ipa")
        guard FileManager.default.fileExists(atPath: ipaURL.path) else {
            throw XCTSkip("build/WQGuard_v1.3.1.ipa not present at \(ipaURL.path)")
        }

        // 1. Direct inspection of Payload/WQGuard.app/WQGuard via NativeZIPArchiveReader + MachOParser
        let ipaData = try Data(contentsOf: ipaURL, options: .mappedIfSafe)
        let zipReader = NativeZIPArchiveReader(data: ipaData)
        let entries = try zipReader.readCentralDirectory()

        let execEntry = try XCTUnwrap(
            entries.first { $0.path == "Payload/WQGuard.app/WQGuard" },
            "Payload/WQGuard.app/WQGuard entry missing from build/WQGuard_v1.3.1.ipa"
        )
        let execData = try zipReader.extract(entry: execEntry)
        XCTAssertGreaterThan(execData.count, 0)

        let all8ArmoredNeedles = [
            "com.apple.audio.audiomxd",
            "com.apple.coremedia.audiomxd",
            "com.apple.bookassetd",
            "com.apple.itunesstored",
            "BLDatabaseManager.sqlite",
            "downloads.28.sqlitedb",
            "com.apple.MobileGestalt.plist",
            "systemgroup.com.apple.mobilegestaltcache"
        ]
        for needle in all8ArmoredNeedles {
            XCTAssertNil(
                execData.range(of: Data(needle.utf8)),
                "IOCTokenArmor leak detected in compiled ARM64 binary Payload/WQGuard.app/WQGuard: raw UTF-8 bytes of '\(needle)' found"
            )
        }
        XCTAssertNil(
            execData.range(of: Data("com.apple.itunesstored.private".utf8)),
            "IOCTokenArmor leak detected: raw UTF-8 bytes of 'com.apple.itunesstored.private' found in Payload/WQGuard.app/WQGuard"
        )

        let slices = try MachOParser.shared.parseAllSlices(data: execData)
        XCTAssertFalse(slices.isEmpty, "Real WQGuard binary must contain at least one Mach-O slice")
        XCTAssertTrue(
            slices.contains { $0.architecture == .arm64 || $0.architecture == .arm64e },
            "Real WQGuard binary inside IPA must contain an ARM64/ARM64e slice"
        )
        for slice in slices {
            let syscallScan = slice.scanDirectSyscalls()
            XCTAssertEqual(
                syscallScan.totalCount,
                0,
                "Real WQGuard slice \(slice.architecture) unexpectedly triggered directSyscallCount = \(syscallScan.totalCount)"
            )
            XCTAssertTrue(syscallScan.sampleSites.isEmpty)
        }
        let parsedDetails = MachOScanner.shared.parseMachO(files: slices, rawData: execData)
        XCTAssertEqual(parsedDetails.directSyscallCount, 0)

        // 2. Full IPAPackageScanner self-audit under ReadOnlyAssertions invariance
        let beforeSHA = try sha256Hex(of: ipaURL)
        let beforeStat = try statInfo(of: ipaURL)
        let beforeSnap = try ReadOnlyAssertions.captureSnapshot(of: [ipaURL])

        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        let pipelineFinding = try SecurityPipeline.shared.scanIPA(at: ipaURL)
        XCTAssertEqual(pipelineFinding.riskTier, finding.riskTier)
        XCTAssertEqual(pipelineFinding.isWhitelisted, finding.isWhitelisted)
        XCTAssertEqual(pipelineFinding.whitelistedToolName, finding.whitelistedToolName)

        try assertFileStrictlyUnchanged(
            at: ipaURL,
            expectedSHA256: beforeSHA,
            expectedStat: beforeStat,
            beforeSnapshot: beforeSnap
        )

        XCTAssertEqual(finding.bundleId, "com.wqguard.app")
        XCTAssertEqual(finding.version, "1.3.1")
        XCTAssertEqual(finding.riskTier, .knownTool)
        XCTAssertTrue(finding.isWhitelisted)
        XCTAssertEqual(finding.whitelistedToolName, "WQGuard")

        let forbiddenPrefixes = [
            "arm64:svc_0x80",
            "CVE-2026-65339",
            "BookRestore",
            "MobileGestaltTamper",
            "CVE-2026-84493"
        ]
        for indicator in finding.indicators {
            for prefix in forbiddenPrefixes {
                XCTAssertFalse(
                    indicator.signature.hasPrefix(prefix),
                    "Real WQGuard_v1.3.1.ipa self-triggered indicator \(indicator.signature)"
                )
            }
        }
        for sym in finding.evidence.matchedSymbols {
            for prefix in forbiddenPrefixes {
                XCTAssertFalse(
                    sym.hasPrefix(prefix),
                    "Real WQGuard_v1.3.1.ipa matchedSymbols unexpectedly contains \(sym)"
                )
            }
        }
    }
}
