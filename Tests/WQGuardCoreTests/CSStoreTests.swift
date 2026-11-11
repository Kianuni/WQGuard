//
//  CSStoreTests.swift
//  WQGuardCoreTests
//
//  Comprehensive test suite for CSStore2Parser and MCMReader.
//

import XCTest
import Darwin
@testable import WQGuardCore

final class CSStoreTests: XCTestCase {

    // MARK: - Helper: Synthetic CSStore2 Builder

    private func makeSyntheticCSStore(
        bundleSize: UInt32,
        bundleIDOffset: UInt32,
        containerOffset: UInt32,
        nameOffset: UInt32,
        displayNameOffset: UInt32,
        bundleId: String,
        containerPath: String,
        displayName: String,
        appGroupUUID: String? = nil
    ) -> Data {
        var data = Data(count: 8192)
        // Magic "bdsl"
        data[0] = 0x62
        data[1] = 0x64
        data[2] = 0x73
        data[3] = 0x6c

        // String heap marker "<string>" at offset 0x400
        let heapOffset = 0x400
        let marker = Data([0x3c, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3e])
        data.replaceSubrange(heapOffset..<(heapOffset + marker.count), with: marker)

        func appendLE32(_ val: UInt32, at offset: Int) {
            var v = val.littleEndian
            withUnsafeBytes(of: &v) { raw in
                data.replaceSubrange(offset..<(offset + 4), with: raw)
            }
        }

        // We will store strings starting at offset 0x500
        var strOffset = 0x500

        func writeString(sid: UInt32, str: String) -> UInt32 {
            appendLE32(sid, at: strOffset)
            let utf8 = Array(str.utf8)
            appendLE32(UInt32(utf8.count), at: strOffset + 4)
            data.replaceSubrange((strOffset + 8)..<(strOffset + 8 + utf8.count), with: utf8)
            data[strOffset + 8 + utf8.count] = 0 // null-terminate
            let entryLen = 8 + utf8.count + 4
            strOffset += (entryLen + 3) & ~3
            return sid << 2 // tagged ref (ref & 3 == 0)
        }

        let bidRef = writeString(sid: 10, str: bundleId)
        let contRef = writeString(sid: 11, str: containerPath)
        let nameRef = writeString(sid: 12, str: displayName)
        let dispRef = writeString(sid: 13, str: displayName)

        // Write unit record at offset 0x100
        let recOffset = 0x100
        appendLE32(0, at: recOffset) // some ID
        appendLE32(bundleSize, at: recOffset + 4) // size matching layout
        let uOffset = recOffset + 8

        appendLE32(bidRef, at: uOffset + Int(bundleIDOffset))
        appendLE32(nameRef, at: uOffset + Int(nameOffset))
        appendLE32(dispRef, at: uOffset + Int(displayNameOffset))
        appendLE32(contRef, at: uOffset + Int(containerOffset))

        // Optional App Group string
        if let gUUID = appGroupUUID {
            let groupStr = "/mobile/Containers/Shared/AppGroup/\(gUUID)"
            let groupBytes = Array(groupStr.utf8)
            data.replaceSubrange(strOffset..<(strOffset + groupBytes.count), with: groupBytes)
        }

        return data
    }

    // MARK: - 1. CSStore2 Multi-Layout Tests

    func testCSStore2_parseSynthetic_iOS26Layout_0x23c() throws {
        let uuid = "12345678-1234-1234-1234-123456789abc"
        let data = makeSyntheticCSStore(
            bundleSize: 0x23c,
            bundleIDOffset: 0x0c,
            containerOffset: 0x64,
            nameOffset: 0x68,
            displayNameOffset: 0x70,
            bundleId: "com.apple.mobilesafari",
            containerPath: "/var/mobile/Containers/Data/Application/\(uuid)",
            displayName: "Safari"
        )

        let snapshot = try CSStore2Parser.shared.parse(data: data)
        XCTAssertEqual(snapshot.layoutLabel, "26")
        XCTAssertEqual(snapshot.appContainers["/var/mobile/Containers/Data/Application/\(uuid)"], "com.apple.mobilesafari")
        XCTAssertEqual(snapshot.displayNames["com.apple.mobilesafari"], "Safari")
    }

    func testCSStore2_parseSynthetic_iOS27_0Layout_0x250() throws {
        let uuid = "A1B2C3D4-E5F6-7A8B-9C0D-1E2F3A4B5C6D"
        let data = makeSyntheticCSStore(
            bundleSize: 0x250,
            bundleIDOffset: 0x0c,
            containerOffset: 0x68,
            nameOffset: 0x6c,
            displayNameOffset: 0x74,
            bundleId: "org.telegram.Telegram-iOS",
            containerPath: "/var/mobile/Containers/Data/Application/\(uuid)",
            displayName: "Telegram"
        )

        let snapshot = try CSStore2Parser.shared.parse(data: data)
        XCTAssertEqual(snapshot.layoutLabel, "27.0")
        XCTAssertEqual(snapshot.appContainers["/var/mobile/Containers/Data/Application/\(uuid)"], "org.telegram.Telegram-iOS")
        XCTAssertEqual(snapshot.displayNames["org.telegram.Telegram-iOS"], "Telegram")
    }

    func testCSStore2_parseSynthetic_iOS27_2Layout_0x25c() throws {
        let uuid = "FEDCBA98-7654-3210-FEDC-BA9876543210"
        let data = makeSyntheticCSStore(
            bundleSize: 0x25c,
            bundleIDOffset: 0x0c,
            containerOffset: 0x6c,
            nameOffset: 0x70,
            displayNameOffset: 0x78,
            bundleId: "com.tencent.xin",
            containerPath: "/var/mobile/Containers/Data/Application/\(uuid)",
            displayName: "微信"
        )

        let snapshot = try CSStore2Parser.shared.parse(data: data)
        XCTAssertEqual(snapshot.layoutLabel, "27.2")
        XCTAssertEqual(snapshot.appContainers["/var/mobile/Containers/Data/Application/\(uuid)"], "com.tencent.xin")
        XCTAssertEqual(snapshot.displayNames["com.tencent.xin"], "微信")
    }

    // MARK: - 2. Unicode Sanitization Tests

    func testCSStore2_unicodeSanitization_replacesBiDiAndFormatScalars() {
        let parser = CSStore2Parser.shared

        // Soft hyphen \u00AD and zero-width joiner \u200D
        let hidden = "Test\u{00AD}App\u{200D}Name"
        let sanitized = parser.sanitizeUnicodeName(hidden)
        XCTAssertNotNil(sanitized)
        XCTAssertTrue(sanitized!.contains("\u{FFFD}"))

        // BiDi override character \u202E
        let bidi = "Photo\u{202E}txt.app"
        let bidiSanitized = parser.sanitizeUnicodeName(bidi)
        XCTAssertNotNil(bidiSanitized)
        XCTAssertTrue(bidiSanitized!.contains("\u{FFFD}"))

        // ASCII control character (e.g. \u0007 bell or \u0000 null)
        let control = "Bad\u{0007}App"
        XCTAssertNil(parser.sanitizeUnicodeName(control))

        // Path traversal attempts
        XCTAssertNil(parser.sanitizeUnicodeName("/var/mobile/payload.app"))
        XCTAssertNil(parser.sanitizeUnicodeName("Payload.app/"))
    }

    // MARK: - 3. AppGroup UUID Extraction

    func testCSStore2_appGroupUUID_extraction() throws {
        let uuid1 = "11111111-2222-3333-4444-555555555555"
        let data = makeSyntheticCSStore(
            bundleSize: 0x250,
            bundleIDOffset: 0x0c,
            containerOffset: 0x68,
            nameOffset: 0x6c,
            displayNameOffset: 0x74,
            bundleId: "com.example.app",
            containerPath: "/var/mobile/Containers/Data/Application/12345678-1234-1234-1234-123456789abc",
            displayName: "Test",
            appGroupUUID: uuid1
        )

        let snapshot = try CSStore2Parser.shared.parse(data: data)
        XCTAssertTrue(snapshot.appGroups.contains("/var/mobile/Containers/Shared/AppGroup/\(uuid1.uppercased())"))
    }

    // MARK: - 4. Bounds & Magic Rejection

    func testCSStore2_rejectionOfInvalidMagicOrSmallBuffer() {
        let parser = CSStore2Parser.shared

        // Too small (< 4096 bytes)
        XCTAssertThrowsError(try parser.parse(data: Data([0x62, 0x64, 0x73, 0x6c]))) { error in
            guard case CSStore2ParserError.dataTooSmall = error else {
                XCTFail("Expected dataTooSmall, got \(error)")
                return
            }
        }

        // Invalid magic
        var badMagic = Data(count: 8192)
        badMagic[0] = 0x58 // 'X'
        badMagic[1] = 0x58
        badMagic[2] = 0x58
        badMagic[3] = 0x58
        XCTAssertThrowsError(try parser.parse(data: badMagic)) { error in
            guard case CSStore2ParserError.invalidMagic = error else {
                XCTFail("Expected invalidMagic, got \(error)")
                return
            }
        }
    }

    func testCSStore2_builtInChineseNames_resolvesPopularApps() {
        let dict = CSStore2Parser.builtInChineseNames
        XCTAssertEqual(dict["com.apple.mobilesafari"], "Safari 浏览器")
        XCTAssertEqual(dict["com.apple.shortcuts"], "快捷指令")
        XCTAssertEqual(dict["com.tencent.xin"], "微信")
        XCTAssertEqual(dict["org.telegram.Telegram-iOS"], "Telegram")
        XCTAssertEqual(dict["com.NSSurge.inc.surge-ios"], "Surge")
    }

    // MARK: - 5. MCMReader Tests

    func testMCMReader_parseValidXMLPlist() throws {
        let uuid = UUID().uuidString
        let plistDict: [String: Any] = [
            "MCMMetadataIdentifier": "group.com.example.test",
            "MCMMetadataUUID": uuid,
            "MCMMetadataClass": 7,
            "MCMMetadataVersion": 1,
            "MCMMetadataUser": "mobile"
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plistDict, format: .xml, options: 0)

        let metadata = try MCMReader.shared.parseMetadata(data: data)
        XCTAssertEqual(metadata.identifier, "group.com.example.test")
        XCTAssertEqual(metadata.uuid, uuid)
        XCTAssertEqual(metadata.containerClass, .appGroup)
        XCTAssertEqual(metadata.version, 1)
        XCTAssertEqual(metadata.user, "mobile")
    }

    func testMCMReader_parseValidBinaryPlist() throws {
        let uuid = UUID().uuidString
        let plistDict: [String: Any] = [
            "MCMMetadataIdentifier": "com.example.app",
            "MCMMetadataUUID": uuid,
            "MCMMetadataClass": 1,
            "MCMMetadataVersion": 1
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plistDict, format: .binary, options: 0)

        let metadata = try MCMReader.shared.parseMetadata(data: data)
        XCTAssertEqual(metadata.identifier, "com.example.app")
        XCTAssertEqual(metadata.uuid, uuid)
        XCTAssertEqual(metadata.containerClass, .appData)
    }

    func testMCMReader_missingOrCorruptedFile_handledGracefully() {
        let fakeURL = URL(fileURLWithPath: "/nonexistent/path/\(UUID().uuidString)")
        XCTAssertThrowsError(try MCMReader.shared.readMetadata(inContainer: fakeURL)) { error in
            guard case MCMReaderError.metadataFileNotFound = error else {
                XCTFail("Expected metadataFileNotFound, got \(error)")
                return
            }
        }

        // Empty data
        XCTAssertThrowsError(try MCMReader.shared.parseMetadata(data: Data())) { error in
            guard case MCMReaderError.emptyData = error else {
                XCTFail("Expected emptyData, got \(error)")
                return
            }
        }

        // Corrupted plist data
        let corrupted = Data("corrupted not a plist".utf8)
        XCTAssertThrowsError(try MCMReader.shared.parseMetadata(data: corrupted)) { error in
            guard case MCMReaderError.corruptedPlist = error else {
                XCTFail("Expected corruptedPlist, got \(error)")
                return
            }
        }
    }

    func testMCMReader_symlinkMetadata_rejected() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("mcm_symlink_test_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let plistPath = tempDir.appendingPathComponent(MCMReader.metadataFilename).path
        // Create symlink pointing to /etc/hosts
        symlink("/etc/hosts", plistPath)

        XCTAssertThrowsError(try MCMReader.shared.readMetadata(inContainer: tempDir)) { error in
            guard case MCMReaderError.symlinkEncountered = error else {
                XCTFail("Expected symlinkEncountered, got \(error)")
                return
            }
        }
    }
}
