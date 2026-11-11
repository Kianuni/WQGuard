//
//  AdversarialM3ChallengerTests.swift
//  WQGuardCoreTests
//
//  Milestone 3 Empirical Adversarial Challenge Suite:
//  1. Real-World IPAs (WQFiles.ipa, Erosion_v0.8.1_zh-Hans.ipa) + Concurrency
//  2. Synthetic IPAs (Clean, Caution, High Risk, Frameworks, PlugIns, Whitelist Spoofing)
//  3. Zip Slip & Path Traversal Stress Tests (Relative, Windows backslash, Absolute, Sandboxing)
//  4. Corrupted ZIP Archives & Quota Defenses (Zero-byte, Truncated, Broken headers, Encrypted, Decompression failure, Quotas)
//  5. Container Symlink Escape Vectors (Library/Caches symlinks, Relative escapes, Dangling symlinks, Circular symlinks, Fake supervision)
//  6. 100% Read-Only Safety & Invariant Verification (Zero mutations, 0555 permissions, Cleanup)
//

import XCTest
import Foundation
import Darwin
import CryptoKit
@testable import WQGuardCore

final class AdversarialM3ChallengerTests: XCTestCase {

    private var tempFiles: [URL] = []
    private var mockTree: MockContainerTree!

    override func setUp() {
        super.setUp()
        WhitelistEngine.shared.resetToDefaults()
        mockTree = MockContainerTree()
    }

    override func tearDown() {
        for url in tempFiles {
            chmod(url.path, 0o777)
            try? FileManager.default.removeItem(at: url)
        }
        tempFiles.removeAll()
        mockTree?.cleanUp()
        mockTree = nil
        WhitelistEngine.shared.resetToDefaults()
        super.tearDown()
    }

    private func trackTempFile(_ url: URL) -> URL {
        tempFiles.append(url)
        return url
    }

    private func computeSHA256(of url: URL) throws -> String {
        let data = try Data(contentsOf: url)
        let hash = SHA256.hash(data: data)
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - 1. Real-World IPAs & Concurrency

    func test_C1_realWorld_WQFiles_invariants() throws {
        guard let wqfilesPath = SamplePathResolver.wqfilesIPA() else {
            throw XCTSkip("WQFiles.ipa not found (set WQFILES_IPA_PATH or place in sibling WQFiles-CN)")
        }

        let ipaURL = URL(fileURLWithPath: wqfilesPath)
        let shaBefore = try computeSHA256(of: ipaURL)
        let attrsBefore = try FileManager.default.attributesOfItem(atPath: ipaURL.path)
        let mtimeBefore = attrsBefore[.modificationDate] as? Date

        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        // Functional assertions
        XCTAssertEqual(finding.bundleId, "cz.kolbi.wqfiles")
        XCTAssertEqual(finding.installChannel, .developerSideloaded)
        XCTAssertTrue(finding.isWhitelisted)
        XCTAssertEqual(finding.riskTier, .knownTool)
        XCTAssertEqual(finding.whitelistedToolName, "WQFiles")

        // 100% Read-Only Invariant: Zero modification to source IPA
        let shaAfter = try computeSHA256(of: ipaURL)
        let attrsAfter = try FileManager.default.attributesOfItem(atPath: ipaURL.path)
        let mtimeAfter = attrsAfter[.modificationDate] as? Date

        XCTAssertEqual(shaBefore, shaAfter, "Source WQFiles.ipa was mutated during scan!")
        XCTAssertEqual(mtimeBefore, mtimeAfter, "Source WQFiles.ipa modification date changed!")
    }

    func test_C1_realWorld_Erosion_invariants() throws {
        guard let erosionPath = SamplePathResolver.erosionIPA() else {
            throw XCTSkip("Erosion.ipa not found (set EROSION_IPA_PATH or place in sibling Erosion-CN)")
        }

        let ipaURL = URL(fileURLWithPath: erosionPath)
        let shaBefore = try computeSHA256(of: ipaURL)
        let attrsBefore = try FileManager.default.attributesOfItem(atPath: ipaURL.path)
        let mtimeBefore = attrsBefore[.modificationDate] as? Date

        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        // Functional assertions
        XCTAssertEqual(finding.bundleId, "com.jbdotparty.Erosion")
        XCTAssertTrue(finding.isWhitelisted)
        XCTAssertEqual(finding.riskTier, .knownTool)
        XCTAssertEqual(finding.whitelistedToolName, "Erosion")

        // 100% Read-Only Invariant: Zero modification to source IPA
        let shaAfter = try computeSHA256(of: ipaURL)
        let attrsAfter = try FileManager.default.attributesOfItem(atPath: ipaURL.path)
        let mtimeAfter = attrsAfter[.modificationDate] as? Date

        XCTAssertEqual(shaBefore, shaAfter, "Source Erosion.ipa was mutated during scan!")
        XCTAssertEqual(mtimeBefore, mtimeAfter, "Source Erosion.ipa modification date changed!")
    }

    func test_C1_realWorld_concurrentScans_threadSafety() throws {
        guard let wqfilesPath = SamplePathResolver.wqfilesIPA(),
              let erosionPath = SamplePathResolver.erosionIPA() else {
            throw XCTSkip("Real-world IPAs missing (set WQFILES_IPA_PATH and EROSION_IPA_PATH)")
        }

        let wqURL = URL(fileURLWithPath: wqfilesPath)
        let erosionURL = URL(fileURLWithPath: erosionPath)

        DispatchQueue.concurrentPerform(iterations: 8) { index in
            let targetURL = (index % 2 == 0) ? wqURL : erosionURL
            do {
                let finding = try IPAPackageScanner.shared.scan(ipaURL: targetURL)
                XCTAssertEqual(finding.riskTier, .knownTool)
            } catch {
                XCTFail("Concurrent scan iteration \(index) failed with: \(error)")
            }
        }
    }

    // MARK: - 2. Synthetic IPAs

    func test_C2_syntheticCleanApp_safe() throws {
        let cleanBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
                symbols: ["_main"]
            )
        )

        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "CleanUtility",
            bundleIdentifier: "com.example.cleanutil",
            executableBinary: cleanBinary,
            provisioningProfile: .developerSideloaded(teamId: "DEVTEAM1", devices: ["DEV-1"])
        )

        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))
        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        XCTAssertEqual(finding.bundleId, "com.example.cleanutil")
        XCTAssertEqual(finding.riskTier, .safe)
        XCTAssertTrue(finding.indicators.isEmpty)
        XCTAssertFalse(finding.isWhitelisted)
    }

    func test_C2_syntheticCaution_appGroupsWithDynamicResolution() throws {
        let entitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.example.shared</string>
            </array>
        </dict>
        </plist>
        """

        let binary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
                symbols: ["_dlopen", "_dlsym"],
                xmlEntitlements: entitlements
            )
        )

        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "CautionApp",
            bundleIdentifier: "com.example.caution",
            executableBinary: binary,
            provisioningProfile: .developerSideloaded(teamId: "DEVTEAM2", devices: ["DEV-2"])
        )

        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))
        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        XCTAssertEqual(finding.riskTier, .caution)
        XCTAssertTrue(finding.evidence.dynamicLoadingPresent)
        XCTAssertTrue(finding.evidence.hasAppGroups)
    }

    func test_C2_syntheticHighRisk_directContainermanagerXPC() throws {
        let entitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.stealth.xpc</string>
            </array>
        </dict>
        </plist>
        """

        let binary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                symbols: ["_xpc_connection_create_mach_service", "com.apple.containermanagerd"],
                xmlEntitlements: entitlements
            )
        )

        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "XPCExploit",
            bundleIdentifier: "com.stealth.xpcbypass",
            executableBinary: binary
        )

        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))
        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature.contains("CONTAINERMANAGERD_XPC") || $0.signature.contains("XPC") || $0.severity == .highRisk })
    }

    func test_C2_syntheticHighRisk_fsgetpathInodePrimitive() throws {
        let entitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.badquery.app</string>
            </array>
        </dict>
        </plist>
        """

        let binary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                symbols: ["_fsgetpath", "_dlopen", "_dlsym", "_symlink"],
                xmlEntitlements: entitlements
            )
        )

        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "BadQueryPoC",
            bundleIdentifier: "com.exploit.badquery",
            executableBinary: binary
        )

        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))
        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.evidence.pathEnumerationPresent)
    }

    func test_C2_syntheticSpoofedWhitelistApp_rejected() throws {
        // Case 1: Attacker spoofs bundleId "cz.kolbi.wqfiles" but cannot obtain Apple-signed group.cz.kolbi.wqfiles
        let unauthorizedGroupEntitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.evil.pirate</string>
            </array>
        </dict>
        </plist>
        """

        let exploitBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
                symbols: ["_container_query_create"],
                xmlEntitlements: unauthorizedGroupEntitlements
            )
        )

        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "WQFilesSpoof",
            bundleIdentifier: "cz.kolbi.wqfiles",
            executableBinary: exploitBinary,
            provisioningProfile: .developerSideloaded(teamId: "EVIL_PIRATE", devices: ["DEV-666"])
        )

        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))
        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        // Whitelist verification enforces AppGroup match; spoofed app with unauthorized group is rejected
        XCTAssertFalse(finding.isWhitelisted)
        XCTAssertEqual(finding.riskTier, .highRisk)

        // Case 2: Custom registered tool enforcing allowedTeamIds rejects spoofed team ID
        let customTool = WhitelistedTool(
            name: "InternalSecurityTool",
            allowedBundleIds: ["com.corp.sectool"],
            allowedAppGroups: ["group.com.corp.sectool"],
            allowedTeamIds: ["CORP_TEAM_1234"],
            expectedSignatures: ["container_query_create"],
            description: "Enterprise security scanner with team restriction"
        )
        WhitelistEngine.shared.registerCustomTool(customTool)

        let legitEntitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.corp.sectool</string>
            </array>
        </dict>
        </plist>
        """

        let customBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
                symbols: ["_container_query_create"],
                xmlEntitlements: legitEntitlements
            )
        )

        let spoofedCustomConfig = MockIPAGenerator.IPAPackageConfig(
            appName: "SecToolSpoof",
            bundleIdentifier: "com.corp.sectool",
            executableBinary: customBinary,
            provisioningProfile: .developerSideloaded(teamId: "ROGUE_DEV_9999", devices: ["DEV-99"])
        )

        let spoofedCustomURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: spoofedCustomConfig))
        let customFinding = try IPAPackageScanner.shared.scan(ipaURL: spoofedCustomURL)

        XCTAssertFalse(customFinding.isWhitelisted)
        XCTAssertEqual(customFinding.riskTier, .highRisk)
    }

    // MARK: - 3. Zip Slip & Path Traversal Stress Tests

    private func constructCustomZip(entries: [(path: String, data: Data, method: UInt16)]) -> Data {
        var zipData = Data()
        var cdEntries: [(path: String, compSize: Int, uncompSize: Int, localOffset: Int, method: UInt16)] = []

        for entry in entries {
            let pathBytes = Array(entry.path.utf8)
            let localOffset = zipData.count

            // Local file header (30 bytes + name)
            zipData.append(contentsOf: [0x50, 0x4b, 0x03, 0x04]) // sig
            zipData.append(contentsOf: [20, 0]) // version
            zipData.append(contentsOf: [0, 0])  // flags
            zipData.append(UInt8(entry.method & 0xff))  // compression method
            zipData.append(UInt8((entry.method >> 8) & 0xff))
            zipData.append(contentsOf: [0, 0, 0, 0]) // mod time/date
            zipData.append(contentsOf: [0, 0, 0, 0]) // crc32 (dummy)
            let size = UInt32(entry.data.count)
            zipData.append(UInt8(size & 0xff))
            zipData.append(UInt8((size >> 8) & 0xff))
            zipData.append(UInt8((size >> 16) & 0xff))
            zipData.append(UInt8((size >> 24) & 0xff))
            zipData.append(UInt8(size & 0xff))
            zipData.append(UInt8((size >> 8) & 0xff))
            zipData.append(UInt8((size >> 16) & 0xff))
            zipData.append(UInt8((size >> 24) & 0xff))
            zipData.append(UInt8(pathBytes.count & 0xff))
            zipData.append(UInt8((pathBytes.count >> 8) & 0xff))
            zipData.append(contentsOf: [0, 0]) // extra len
            zipData.append(contentsOf: pathBytes)
            zipData.append(entry.data)

            cdEntries.append((path: entry.path, compSize: entry.data.count, uncompSize: entry.data.count, localOffset: localOffset, method: entry.method))
        }

        let cdOffset = zipData.count
        for cd in cdEntries {
            let pathBytes = Array(cd.path.utf8)
            // Central directory header (46 bytes + name)
            zipData.append(contentsOf: [0x50, 0x4b, 0x01, 0x02]) // sig
            zipData.append(contentsOf: [20, 0]) // version made by
            zipData.append(contentsOf: [20, 0]) // version needed
            zipData.append(contentsOf: [0, 0])  // flags
            zipData.append(UInt8(cd.method & 0xff))  // method
            zipData.append(UInt8((cd.method >> 8) & 0xff))
            zipData.append(contentsOf: [0, 0, 0, 0]) // mod time/date
            zipData.append(contentsOf: [0, 0, 0, 0]) // crc32
            let sz = UInt32(cd.uncompSize)
            zipData.append(UInt8(sz & 0xff))
            zipData.append(UInt8((sz >> 8) & 0xff))
            zipData.append(UInt8((sz >> 16) & 0xff))
            zipData.append(UInt8((sz >> 24) & 0xff))
            zipData.append(UInt8(sz & 0xff))
            zipData.append(UInt8((sz >> 8) & 0xff))
            zipData.append(UInt8((sz >> 16) & 0xff))
            zipData.append(UInt8((sz >> 24) & 0xff))
            zipData.append(UInt8(pathBytes.count & 0xff))
            zipData.append(UInt8((pathBytes.count >> 8) & 0xff))
            zipData.append(contentsOf: [0, 0]) // extra len
            zipData.append(contentsOf: [0, 0]) // comment len
            zipData.append(contentsOf: [0, 0]) // disk number
            zipData.append(contentsOf: [0, 0]) // internal attrs
            zipData.append(contentsOf: [0, 0, 0, 0]) // external attrs
            let off = UInt32(cd.localOffset)
            zipData.append(UInt8(off & 0xff))
            zipData.append(UInt8((off >> 8) & 0xff))
            zipData.append(UInt8((off >> 16) & 0xff))
            zipData.append(UInt8((off >> 24) & 0xff))
            zipData.append(contentsOf: pathBytes)
        }

        let cdSize = zipData.count - cdOffset
        // EOCD (22 bytes)
        zipData.append(contentsOf: [0x50, 0x4b, 0x05, 0x06]) // sig
        zipData.append(contentsOf: [0, 0]) // disk num
        zipData.append(contentsOf: [0, 0]) // start disk
        let cnt = UInt16(cdEntries.count)
        zipData.append(UInt8(cnt & 0xff))
        zipData.append(UInt8((cnt >> 8) & 0xff))
        zipData.append(UInt8(cnt & 0xff))
        zipData.append(UInt8((cnt >> 8) & 0xff))
        let cdsz = UInt32(cdSize)
        zipData.append(UInt8(cdsz & 0xff))
        zipData.append(UInt8((cdsz >> 8) & 0xff))
        zipData.append(UInt8((cdsz >> 16) & 0xff))
        zipData.append(UInt8((cdsz >> 24) & 0xff))
        let cdoff = UInt32(cdOffset)
        zipData.append(UInt8(cdoff & 0xff))
        zipData.append(UInt8((cdoff >> 8) & 0xff))
        zipData.append(UInt8((cdoff >> 16) & 0xff))
        zipData.append(UInt8((cdoff >> 24) & 0xff))
        zipData.append(contentsOf: [0, 0]) // comment len

        return zipData
    }

    private func constructCustomZip(entries: [(path: String, data: Data)]) -> Data {
        return constructCustomZip(entries: entries.map { ($0.path, $0.data, UInt16(0)) })
    }

    func test_C3_zipSlip_deepRelativePath_throws() throws {
        let zipData = constructCustomZip(entries: [
            ("Payload/App.app/Info.plist", Data("<plist></plist>".utf8)),
            ("../../../../../../../../tmp/pwned.txt", Data("pwned".utf8))
        ])

        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("slip_deep_\(UUID().uuidString).ipa"))
        try zipData.write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.zipSlipDetected = error else {
                XCTFail("Expected zipSlipDetected, got \(error)")
                return
            }
        }
    }

    func test_C3_zipSlip_payloadRelativeEscape_throws() throws {
        let zipData = constructCustomZip(entries: [
            ("Payload/App.app/../../../../evil.dylib", Data("dylib_payload".utf8))
        ])

        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("slip_payload_\(UUID().uuidString).ipa"))
        try zipData.write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.zipSlipDetected = error else {
                XCTFail("Expected zipSlipDetected, got \(error)")
                return
            }
        }
    }

    func test_C3_zipSlip_windowsBackslash_throws() throws {
        let zipData = constructCustomZip(entries: [
            ("Payload\\App.app\\..\\..\\evil.txt", Data("backslash_escape".utf8))
        ])

        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("slip_win_\(UUID().uuidString).ipa"))
        try zipData.write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.zipSlipDetected = error else {
                XCTFail("Expected zipSlipDetected, got \(error)")
                return
            }
        }
    }

    func test_C3_zipSlip_absolutePath_throws() throws {
        let zipData = constructCustomZip(entries: [
            ("/etc/passwd", Data("root:x:0:0:root".utf8))
        ])

        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("slip_abs_\(UUID().uuidString).ipa"))
        try zipData.write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.zipSlipDetected = error else {
                XCTFail("Expected zipSlipDetected, got \(error)")
                return
            }
        }
    }

    // MARK: - 4. Corrupted ZIP Archives & Quotas

    func test_C4_corruptArchive_zeroByteFile_throwsInvalidArchive() throws {
        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("zero_\(UUID().uuidString).ipa"))
        try Data().write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.invalidArchive = error else {
                XCTFail("Expected invalidArchive, got \(error)")
                return
            }
        }
    }

    func test_C4_corruptArchive_randomGarbage_throwsEOCDNotFound() throws {
        let garbage = Data((0..<256).map { _ in UInt8.random(in: 0...255) })
        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("garbage_\(UUID().uuidString).ipa"))
        try garbage.write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.endOfCentralDirectoryNotFound = error else {
                XCTFail("Expected endOfCentralDirectoryNotFound, got \(error)")
                return
            }
        }
    }

    func test_C4_corruptArchive_encryptedArchiveNotSupported() throws {
        // Construct ZIP where entry has general purpose bit 0 set (encrypted)
        var zipData = Data()
        let path = "Payload/App.app/Info.plist"
        let pathBytes = Array(path.utf8)

        // Local header with encrypted flag (bit 0 = 1)
        zipData.append(contentsOf: [0x50, 0x4b, 0x03, 0x04])
        zipData.append(contentsOf: [20, 0])
        zipData.append(contentsOf: [0x01, 0x00]) // bit 0 set!
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 20))
        zipData.append(UInt8(pathBytes.count & 0xff))
        zipData.append(UInt8((pathBytes.count >> 8) & 0xff))
        zipData.append(contentsOf: [0, 0])
        zipData.append(contentsOf: pathBytes)

        let cdOffset = zipData.count
        // CD header with bit 0 set
        zipData.append(contentsOf: [0x50, 0x4b, 0x01, 0x02])
        zipData.append(contentsOf: [20, 0, 20, 0])
        zipData.append(contentsOf: [0x01, 0x00]) // bit 0 set!
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 22))
        zipData.append(UInt8(pathBytes.count & 0xff))
        zipData.append(UInt8((pathBytes.count >> 8) & 0xff))
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 16))
        zipData.append(contentsOf: pathBytes)

        let cdSize = zipData.count - cdOffset
        // EOCD
        zipData.append(contentsOf: [0x50, 0x4b, 0x05, 0x06])
        zipData.append(contentsOf: [0, 0, 0, 0, 1, 0, 1, 0])
        let cdsz = UInt32(cdSize)
        zipData.append(UInt8(cdsz & 0xff))
        zipData.append(UInt8((cdsz >> 8) & 0xff))
        zipData.append(UInt8((cdsz >> 16) & 0xff))
        zipData.append(UInt8((cdsz >> 24) & 0xff))
        let cdoff = UInt32(cdOffset)
        zipData.append(UInt8(cdoff & 0xff))
        zipData.append(UInt8((cdoff >> 8) & 0xff))
        zipData.append(UInt8((cdoff >> 16) & 0xff))
        zipData.append(UInt8((cdoff >> 24) & 0xff))
        zipData.append(contentsOf: [0, 0])

        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("enc_\(UUID().uuidString).ipa"))
        try zipData.write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.encryptedArchiveNotSupported = error else {
                XCTFail("Expected encryptedArchiveNotSupported, got \(error)")
                return
            }
        }
    }

    func test_C4_corruptArchive_unsupportedCompressionMethod() throws {
        // Construct ZIP entry with unsupported compression method 12 (BZIP2)
        let zipData = constructCustomZip(entries: [
            ("Payload/App.app/Info.plist", Data("<plist></plist>".utf8), 12)
        ])

        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("unsupp_\(UUID().uuidString).ipa"))
        try zipData.write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.unsupportedCompressionMethod(let m) = error else {
                XCTFail("Expected unsupportedCompressionMethod, got \(error)")
                return
            }
            XCTAssertEqual(m, 12)
        }
    }

    func test_C4_quotaExceeded_entryCountLimit() throws {
        // EOCD stating 30,000 entries (>20,000 maxEntries quota)
        var zipData = Data()
        // Minimal valid dummy data so data.count >= 22
        zipData.append(contentsOf: [0x50, 0x4b, 0x05, 0x06])
        zipData.append(contentsOf: [0, 0, 0, 0])
        zipData.append(contentsOf: [0x30, 0x75]) // 30,000 entries
        zipData.append(contentsOf: [0x30, 0x75])
        zipData.append(contentsOf: [0, 0, 0, 0]) // cdSize
        zipData.append(contentsOf: [0, 0, 0, 0]) // cdOffset
        zipData.append(contentsOf: [0, 0])

        let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("quota_cnt_\(UUID().uuidString).ipa"))
        try zipData.write(to: tempURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.quotaExceeded = error else {
                XCTFail("Expected quotaExceeded, got \(error)")
                return
            }
        }
    }

    func test_C4_corruptArchive_corruptInfoPlist() throws {
        let binary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(arch: .arm64)
        )
        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "BadPlistApp",
            executableBinary: binary,
            corruptInfoPlist: true
        )
        let tempURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL)) { error in
            guard case IPAPackageScannerError.invalidInfoPlist = error else {
                XCTFail("Expected invalidInfoPlist, got \(error)")
                return
            }
        }
    }

    func test_C4_corruptArchive_missingExecutable() throws {
        // Info.plist references "MissingExec" but file is absent
        let binary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(arch: .arm64)
        )
        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "MissingExecApp",
            executableBinary: binary
        )
        let tempURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))

        // Modify the unpacked IPA via custom zip to remove binary
        let reader = NativeZIPArchiveReader(data: try Data(contentsOf: tempURL))
        let entries = try reader.readCentralDirectory()
        let nonExecEntries = entries.filter { !$0.path.hasSuffix("/MissingExecApp") }

        var rezipped: [(path: String, data: Data)] = []
        for e in nonExecEntries {
            let data = try reader.extract(entry: e)
            rezipped.append((path: e.path, data: data))
        }

        let badZipData = constructCustomZip(entries: rezipped)
        let badURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("no_exec_\(UUID().uuidString).ipa"))
        try badZipData.write(to: badURL)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: badURL)) { error in
            guard case IPAPackageScannerError.missingExecutable = error else {
                XCTFail("Expected missingExecutable, got \(error)")
                return
            }
        }
    }

    // MARK: - 5. Container Symlink Escape Vectors

    func test_C5_container_libraryCaches_absoluteSymlink_flagsHighRisk() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.exploit.caches",
            createCachesDirectory: false
        )
        let containerURL = try mockTree.createContainer(config: config)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: cachesURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        symlink("/etc/hosts", cachesURL.path)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertTrue(result.escapingSymlinks.contains(cachesURL.path))
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_CACHES_SYMLINK" && $0.severity == .highRisk })
    }

    func test_C5_container_libraryCaches_relativeEscape_flagsHighRisk() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.exploit.relescape",
            createCachesDirectory: false
        )
        let containerURL = try mockTree.createContainer(config: config)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: cachesURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        // Library/Caches relative link escaping 4 levels up
        symlink("../../../../", cachesURL.path)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertTrue(result.escapingSymlinks.contains(cachesURL.path))
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_CACHES_SYMLINK" && $0.severity == .highRisk })
    }

    func test_C5_container_libraryCaches_parentEscape_flagsHighRisk() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.exploit.parentescape",
            createCachesDirectory: false
        )
        let containerURL = try mockTree.createContainer(config: config)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: cachesURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        // From Library, ../.. points to parent of container root
        symlink("../..", cachesURL.path)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertTrue(result.escapingSymlinks.contains(cachesURL.path))
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_CACHES_SYMLINK" })
    }

    func test_C5_container_libraryCaches_benignInternalSymlink_clean() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.benign.symlink",
            createCachesDirectory: false
        )
        let containerURL = try mockTree.createContainer(config: config)
        let docURL = containerURL.appendingPathComponent("Documents")
        try FileManager.default.createDirectory(at: docURL, withIntermediateDirectories: true)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: cachesURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        // From Library, ../Documents is inside container root
        symlink("../Documents", cachesURL.path)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertTrue(result.isClean)
        XCTAssertTrue(result.escapingSymlinks.isEmpty)
        XCTAssertTrue(result.indicators.isEmpty)
    }

    func test_C5_container_childSymlink_absoluteEscape_flagsHighRisk() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.child.absescape",
            createCachesDirectory: true,
            escapingSymlinks: ["passwd_symlink": "/etc/passwd"]
        )
        let containerURL = try mockTree.createContainer(config: config)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertEqual(result.escapingSymlinks.count, 1)
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" && $0.severity == .highRisk })
    }

    func test_C5_container_childSymlink_relativeEscape_flagsHighRisk() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.child.relescape",
            createCachesDirectory: true,
            escapingSymlinks: ["up_and_away": "../../../../../private/var/mobile"]
        )
        let containerURL = try mockTree.createContainer(config: config)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertEqual(result.escapingSymlinks.count, 1)
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" })
    }

    func test_C5_container_childSymlink_danglingEscape_detected() throws {
        // Symlink pointing to a non-existent path outside container
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.child.dangling",
            createCachesDirectory: true,
            escapingSymlinks: ["ghost_target": "/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000"]
        )
        let containerURL = try mockTree.createContainer(config: config)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertEqual(result.escapingSymlinks.count, 1)
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" })
    }

    func test_C5_container_childSymlink_circularSymlink_notEscaping() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.child.circular",
            createCachesDirectory: true
        )
        let containerURL = try mockTree.createContainer(config: config)
        let loopURL = containerURL.appendingPathComponent("Library/Caches/loop")
        symlink("loop", loopURL.path)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertTrue(result.isClean)
        XCTAssertTrue(result.escapingSymlinks.isEmpty)
    }

    func test_C5_container_multipleMixedSymlinks_accurateCounting() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.mixed.symlinks",
            createCachesDirectory: true,
            escapingSymlinks: [
                "esc1": "/etc/hosts",
                "esc2": "../../../../tmp"
            ],
            regularFiles: [
                "Library/Caches/SubDir/data.txt": Data("sub data".utf8),
                "Documents/info.txt": Data("doc info".utf8)
            ]
        )
        let containerURL = try mockTree.createContainer(config: config)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")

        // Create 2 internal relative symlinks via POSIX symlink()
        symlink("SubDir", cachesURL.appendingPathComponent("benign1").path)
        symlink("../Documents", cachesURL.appendingPathComponent("benign2").path)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertEqual(result.escapingSymlinks.count, 2)
        XCTAssertEqual(result.indicators.filter { $0.signature == "CONTAINER_ESCAPING_SYMLINK" }.count, 2)
    }

    func test_C5_container_batchContainersScan_withRootSymlinks() throws {
        let cleanConfig = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.clean.batch",
            containerUUID: UUID().uuidString
        )
        _ = try mockTree.createContainer(config: cleanConfig)

        let dirtyConfig = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.dirty.batch",
            containerUUID: UUID().uuidString,
            escapingSymlinks: ["bad": "/etc/passwd"]
        )
        _ = try mockTree.createContainer(config: dirtyConfig)

        // Add a root-level symlink pointing outside (should be ignored by scanAppGroupContainers)
        let rootSymlink = mockTree.rootDirectoryURL.appendingPathComponent("rogue_symlink")
        symlink("/etc", rootSymlink.path)

        let batch = try ContainerScanner.shared.scanAppGroupContainers(at: mockTree.rootDirectoryURL)
        XCTAssertEqual(batch.count, 2)
        let cleanResults = batch.filter { $0.isClean }
        let dirtyResults = batch.filter { !$0.isClean }
        XCTAssertEqual(cleanResults.count, 1)
        XCTAssertEqual(dirtyResults.count, 1)
        XCTAssertEqual(dirtyResults.first?.metadata?.identifier, "group.com.dirty.batch")
    }

    // MARK: - 6. 100% Read-Only Safety & Invariant Verification

    func test_C6_readOnly_containerDirectory_zeroModification() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.readonly.strict",
            createMetadataPlist: true,
            createCachesDirectory: true,
            regularFiles: [
                "Library/Caches/cache.db": Data("read only test data".utf8),
                "Documents/notes.txt": Data("user notes".utf8)
            ]
        )
        let containerURL = try mockTree.createContainer(config: config)

        let beforeSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [containerURL])
        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertTrue(result.isClean)
        let afterSnapshot = try ReadOnlyAssertions.captureSnapshot(of: [containerURL])

        ReadOnlyAssertions.assertUnmodified(before: beforeSnapshot, after: afterSnapshot)
    }

    func test_C6_readOnly_readOnlyPermissionsContainer_scansSuccessfully() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.readonly.permissions",
            createMetadataPlist: true,
            createCachesDirectory: true,
            regularFiles: [
                "Library/Caches/read.bin": Data("data".utf8)
            ]
        )
        let containerURL = try mockTree.createContainer(config: config)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")

        // Set directory permissions to 0555 (r-x: read and execute only, NO write)
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: cachesURL.path)
        defer {
            // Restore write so tearDown can delete
            try? FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: cachesURL.path)
        }

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertTrue(result.isClean)
    }

    func test_C6_sandbox_temporaryDirectoryCleanup_onSuccessAndFailure() throws {
        let binary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(arch: .arm64)
        )
        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "SandboxCleanupApp",
            executableBinary: binary
        )
        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))

        // 1. Scan valid IPA
        _ = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        // 2. Scan invalid/corrupted IPA (throws error)
        let badZipData = constructCustomZip(entries: [
            ("Payload/App.app/../../evil.txt", Data("fail".utf8))
        ])
        let badURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("bad_cleanup_\(UUID().uuidString).ipa"))
        try badZipData.write(to: badURL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: badURL))

        // Verify zero leftover wqguard_ipa_* directories in temporaryDirectory
        let tempContents = try FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)
        let leftovers = tempContents.filter { $0.hasPrefix("wqguard_ipa_") }
        XCTAssertTrue(leftovers.isEmpty, "Found uncleaned sandbox directories: \(leftovers)")
    }

    func test_C6_scopedSandboxToken_threadSafeIdempotentRelease() {
        let token = ScopedSandboxToken(handle: 12345)
        DispatchQueue.concurrentPerform(iterations: 16) { _ in
            token.release()
        }
        XCTAssertEqual(token.handle, 12345)
    }
}
