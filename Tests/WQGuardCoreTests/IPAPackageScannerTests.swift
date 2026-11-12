//
//  IPAPackageScannerTests.swift
//  WQGuardCoreTests
//
//  Comprehensive test suite for IPAPackageScanner, NativeZIPArchiveReader,
//  Layer 1/2/4 scanning of synthetic and real-world IPAs, Zip Slip and quota defenses.
//

import XCTest
@testable import WQGuardCore

final class IPAPackageScannerTests: XCTestCase {

    var tempFiles: [URL] = []

    override func tearDown() {
        for url in tempFiles {
            try? FileManager.default.removeItem(at: url)
        }
        tempFiles.removeAll()
        super.tearDown()
    }

    private func trackTempFile(_ url: URL) -> URL {
        tempFiles.append(url)
        return url
    }

    // MARK: - 1. Valid Synthetic Clean IPA Scan

    func test_IPA_validSyntheticArchive_scansCleanly() throws {
        let cleanBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
                symbols: ["_main"]
            )
        )

        let ipaConfig = MockIPAGenerator.IPAPackageConfig(
            appName: "CleanApp",
            bundleIdentifier: "com.example.cleanapp",
            executableBinary: cleanBinary,
            provisioningProfile: .developerSideloaded(teamId: "DEV12345", devices: ["UUID-1"])
        )

        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: ipaConfig))
        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        XCTAssertEqual(finding.bundleId, "com.example.cleanapp")
        XCTAssertEqual(finding.riskTier, .safe)
        XCTAssertEqual(finding.installChannel, .developerSideloaded)
        XCTAssertTrue(finding.indicators.isEmpty)
        XCTAssertFalse(finding.isWhitelisted)
    }

    // MARK: - 2. Real-World IPAs (WQFiles and Erosion)

    func test_IPA_realWorld_WQFilesIPA() throws {
        guard let wqfilesPath = SamplePathResolver.wqfilesIPA() else {
            throw XCTSkip("WQFiles.ipa not found (set WQFILES_IPA_PATH or place in sibling WQFiles-CN)")
        }

        let finding = try IPAPackageScanner.shared.scan(ipaURL: URL(fileURLWithPath: wqfilesPath))
        XCTAssertEqual(finding.bundleId, "cz.kolbi.wqfiles")
        XCTAssertFalse(finding.isWhitelisted, "WQFiles is no longer built-in whitelisted by default")
        XCTAssertEqual(finding.riskTier, .highRisk)
    }

    func test_IPA_realWorld_ErosionIPA() throws {
        guard let erosionPath = SamplePathResolver.erosionIPA() else {
            throw XCTSkip("Erosion.ipa not found (set EROSION_IPA_PATH or place in sibling Erosion-CN)")
        }

        let finding = try IPAPackageScanner.shared.scan(ipaURL: URL(fileURLWithPath: erosionPath))
        XCTAssertEqual(finding.bundleId, "com.jbdotparty.Erosion")
        XCTAssertFalse(finding.isWhitelisted, "Erosion is no longer built-in whitelisted by default")
        XCTAssertEqual(finding.riskTier, .highRisk)
    }

    // MARK: - 3. Synthetic Exploit Signature Detection (High Risk)

    func test_IPA_exploitSignature_flagsHighRisk() throws {
        let exploitEntitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.untrusted.exploit</string>
            </array>
        </dict>
        </plist>
        """

        let exploitBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
                symbols: ["_container_query_create", "_sandbox_extension_consume"],
                xmlEntitlements: exploitEntitlements
            )
        )

        let ipaConfig = MockIPAGenerator.IPAPackageConfig(
            appName: "ExploitApp",
            bundleIdentifier: "com.malicious.backdoor",
            executableBinary: exploitBinary,
            provisioningProfile: .developerSideloaded(teamId: "EVIL123", devices: ["UUID-EVIL"])
        )

        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: ipaConfig))
        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertFalse(finding.isWhitelisted)
        XCTAssertTrue(finding.indicators.contains { $0.severity == .highRisk })
    }

    // MARK: - 4. Zip Slip Traversal Defense

    func test_IPA_zipSlipTraversal_throwsZipSlipDetected() throws {
        // Construct mock ZIP with a path escaping via ../
        var zipData = Data()
        // Local header for ../../../../evil.txt
        let badPath = "../../../../evil.txt"
        let badPathBytes = Array(badPath.utf8)

        // Local header
        zipData.append(contentsOf: [0x50, 0x4b, 0x03, 0x04]) // sig
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 22)) // flags, method, crc, sizes
        zipData.append(UInt8(badPathBytes.count & 0xff))
        zipData.append(UInt8((badPathBytes.count >> 8) & 0xff))
        zipData.append(contentsOf: [0, 0]) // extra len
        zipData.append(contentsOf: badPathBytes)

        let cdOffset = zipData.count
        // Central Directory Header
        zipData.append(contentsOf: [0x50, 0x4b, 0x01, 0x02]) // sig
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 24))
        zipData.append(UInt8(badPathBytes.count & 0xff))
        zipData.append(UInt8((badPathBytes.count >> 8) & 0xff))
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 16)) // extra, comment, disk, attrs, local offset 0
        zipData.append(contentsOf: badPathBytes)
        let cdSize = zipData.count - cdOffset

        // EOCD
        zipData.append(contentsOf: [0x50, 0x4b, 0x05, 0x06]) // sig
        zipData.append(contentsOf: [0, 0, 0, 0]) // disk numbers
        zipData.append(contentsOf: [1, 0]) // total entries on disk: 1
        zipData.append(contentsOf: [1, 0]) // total entries: 1
        zipData.append(UInt8(cdSize & 0xff))
        zipData.append(UInt8((cdSize >> 8) & 0xff))
        zipData.append(UInt8((cdSize >> 16) & 0xff))
        zipData.append(UInt8((cdSize >> 24) & 0xff))
        zipData.append(UInt8(cdOffset & 0xff))
        zipData.append(UInt8((cdOffset >> 8) & 0xff))
        zipData.append(UInt8((cdOffset >> 16) & 0xff))
        zipData.append(UInt8((cdOffset >> 24) & 0xff))
        zipData.append(contentsOf: [0, 0]) // comment len

        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("slip_\(UUID().uuidString).ipa"))
        try zipData.write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.zipSlipDetected = error else {
                XCTFail("Expected zipSlipDetected, got \(error)")
                return
            }
        }
    }

    // MARK: - 5. Corrupt Header & Missing Payload Defenses

    func test_IPA_corruptArchive_throwsCorruptHeader() throws {
        let truncated = Data([0x50, 0x4b, 0x05, 0x06, 0x00, 0x00]) // Truncated EOCD
        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("trunc_\(UUID().uuidString).ipa"))
        try truncated.write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL))
    }

    func test_IPA_missingPayload_throwsMissingPayload() throws {
        // Valid ZIP containing only unrelated files, no Payload/ directory
        let binary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(arch: .arm64)
        )
        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "NoPayload",
            executableBinary: binary,
            includePayloadDirectory: false
        )
        let tempURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.missingPayload = error else {
                XCTFail("Expected missingPayload, got \(error)")
                return
            }
        }
    }

    // MARK: - 6. Embedded Frameworks & App Extensions Recursion

    func test_IPA_embeddedFramework_scansRecursively() throws {
        let fwBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                symbols: ["_fsgetpath"]
            )
        )

        let appEntitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.example.fw</string>
            </array>
        </dict>
        </plist>
        """

        let appBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                xmlEntitlements: appEntitlements
            )
        )

        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "FrameworkApp",
            executableBinary: appBinary,
            embeddedFrameworks: ["SecurityHelper.framework/SecurityHelper": fwBinary]
        )
        let tempURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))
        let finding = try IPAPackageScanner.shared.scan(ipaURL: tempURL)

        XCTAssertTrue(finding.evidence.matchedSymbols.contains("fsgetpath") || finding.evidence.matchedSymbols.contains("_fsgetpath"))
        XCTAssertTrue(finding.indicators.contains { $0.location.contains("Frameworks/SecurityHelper.framework") })
    }

    // MARK: - 7. Deterministic RAII Cleanup

    func test_IPA_deterministicRAIICleanup() throws {
        let appBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(arch: .arm64)
        )
        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "CleanupApp",
            executableBinary: appBinary
        )
        let tempURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))
        _ = try IPAPackageScanner.shared.scan(ipaURL: tempURL)

        // Verify no leftover wqguard_ipa_* folders in temporary directory
        let tempContents = try FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)
        let leftovers = tempContents.filter { $0.hasPrefix("wqguard_ipa_") }
        XCTAssertTrue(leftovers.isEmpty, "Found leftover temporary folders: \(leftovers)")
    }
}
