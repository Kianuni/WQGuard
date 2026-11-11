//
//  EntitlementTests.swift
//  WQGuardCoreTests
//
//  Unit tests covering CSBlobParser, SuperBlob validation,
//  dual XML Plist & ASN.1 DER entitlement extraction, and edge cases.
//

import XCTest
import Foundation
@testable import WQGuardCore

final class EntitlementTests: XCTestCase {

    private var tempFiles: [URL] = []

    override func tearDown() {
        for url in tempFiles {
            try? FileManager.default.removeItem(at: url)
        }
        tempFiles.removeAll()
        super.tearDown()
    }

    // MARK: - 1. SuperBlob Header Validation

    func testSuperBlob_validHeader_succeeds() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.test.alpha"])
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(xmlEntitlements: xml))
        let (hasGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertTrue(hasGroups)
        XCTAssertEqual(groups, ["group.com.test.alpha"])
    }

    func testSuperBlob_corruptMagic_throwsInvalidMagic() throws {
        var badData = Data(repeating: 0, count: 32)
        // Set bad magic 0xdeadbeef
        var badMagic = UInt32(0xdeadbeef).bigEndian
        badData.replaceSubrange(0..<4, with: Data(bytes: &badMagic, count: 4))
        var len = UInt32(32).bigEndian
        badData.replaceSubrange(4..<8, with: Data(bytes: &len, count: 4))

        XCTAssertThrowsError(try CSBlobParser.shared.parseSuperBlob(badData)) { error in
            guard let csError = error as? CSBlobError,
                  case .invalidSuperBlobMagic(let actual) = csError else {
                XCTFail("Expected invalidSuperBlobMagic, got \(error)")
                return
            }
            XCTAssertEqual(actual, 0xdeadbeef)
        }
    }

    func testSuperBlob_truncatedBuffer_throwsDataTooSmall() throws {
        let truncated = Data([0xfa, 0xde, 0x0c, 0xc0, 0x00, 0x00]) // Only 6 bytes
        XCTAssertThrowsError(try CSBlobParser.shared.parseSuperBlob(truncated)) { error in
            guard let csError = error as? CSBlobError,
                  case .dataTooSmall(let exp, let act) = csError else {
                XCTFail("Expected dataTooSmall, got \(error)")
                return
            }
            XCTAssertEqual(exp, 12)
            XCTAssertEqual(act, 6)
        }
    }

    func testSuperBlob_declaredLengthExceedsBuffer_throwsLengthOutOfBounds() throws {
        var data = Data()
        var magic = CSBlobConstants.superBlobMagic.bigEndian
        var declaredLength = UInt32(1024).bigEndian // Declared 1024 bytes, actual is 16 bytes
        var count = UInt32(0).bigEndian
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &declaredLength, count: 4))
        data.append(Data(bytes: &count, count: 4))
        data.append(Data(repeating: 0, count: 4))

        XCTAssertThrowsError(try CSBlobParser.shared.parseSuperBlob(data)) { error in
            guard let csError = error as? CSBlobError,
                  case .superBlobLengthOutOfBounds(let dec, let act) = csError else {
                XCTFail("Expected superBlobLengthOutOfBounds, got \(error)")
                return
            }
            XCTAssertEqual(dec, 1024)
            XCTAssertEqual(act, 16)
        }
    }

    func testSuperBlob_countOverflowClampedSafely() throws {
        var data = Data()
        var magic = CSBlobConstants.superBlobMagic.bigEndian
        var totalLength = UInt32(20).bigEndian
        var overflowCount = UInt32(0xffffffff).bigEndian // Huge count
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &totalLength, count: 4))
        data.append(Data(bytes: &overflowCount, count: 4))
        data.append(Data(repeating: 0, count: 8)) // 20 bytes total

        // Must not crash or OOM
        let parsed = try CSBlobParser.shared.parseSuperBlob(data)
        XCTAssertFalse(parsed.hasAppGroups)
        XCTAssertEqual(parsed.appGroups, [])
    }

    func testSuperBlob_zeroSlots_returnsEmpty() throws {
        var data = Data()
        var magic = CSBlobConstants.superBlobMagic.bigEndian
        var totalLength = UInt32(12).bigEndian
        var count = UInt32(0).bigEndian
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &totalLength, count: 4))
        data.append(Data(bytes: &count, count: 4))

        let parsed = try CSBlobParser.shared.parseSuperBlob(data)
        XCTAssertEqual(parsed, .empty)
    }

    // MARK: - 2. Slot 5 (XML Plist) Extraction

    func testSlot5_xmlSingleAppGroup_extracted() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.org.wqguard.core"])
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(xmlEntitlements: xml))
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertTrue(hasAppGroups)
        XCTAssertEqual(groups, ["group.org.wqguard.core"])
    }

    func testSlot5_xmlMultipleAppGroups_extracted() throws {
        let expected = ["group.com.apple.shared", "group.com.enterprise.vault", "group.com.dev.tunnel"]
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: expected)
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(xmlEntitlements: xml))
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertTrue(hasAppGroups)
        XCTAssertEqual(groups, expected)
    }

    func testSlot5_xmlEmptyArray_returnsFalse() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: [])
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(xmlEntitlements: xml))
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertFalse(hasAppGroups)
        XCTAssertTrue(groups.isEmpty)
    }

    func testSlot5_xmlMissingAppGroupsKey_returnsFalse() throws {
        let xmlWithoutGroups = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>get-task-allow</key>
            <true/>
            <key>keychain-access-groups</key>
            <array>
                <string>ABCDE.com.test.keychain</string>
            </array>
        </dict>
        </plist>
        """
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(xmlEntitlements: xmlWithoutGroups))
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertFalse(hasAppGroups)
        XCTAssertTrue(groups.isEmpty)
    }

    func testSlot5_xmlNullBytePaddingTrimming() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.padded.nulls"])
        var xmlBytes = Array(xml.utf8)
        // Add 32 null bytes at the end
        xmlBytes.append(contentsOf: [UInt8](repeating: 0, count: 32))
        let paddedData = Data(xmlBytes)

        let dict = try CSBlobParser.shared.parseXMLPlist(paddedData)
        let groups = CSBlobParser.shared.extractAppGroups(fromPlistDict: dict)
        XCTAssertEqual(groups, ["group.com.padded.nulls"])
    }

    func testSlot5_xmlMalformedTags_failsGracefully() throws {
        let malformed = "<dict><key>com.apple.security.application-groups</key><array><string>unclosed"
        let data = malformed.data(using: .utf8)!
        XCTAssertThrowsError(try CSBlobParser.shared.parseXMLPlist(data)) { error in
            guard case CSBlobError.malformedXMLPlist = error else {
                XCTFail("Expected malformedXMLPlist, got \(error)")
                return
            }
        }
    }

    // MARK: - 3. Slot 7 (ASN.1 DER) Extraction

    func testSlot7_derSingleAppGroup_extracted() throws {
        let der = SyntheticMachOGenerator.createDEREntitlements(appGroups: ["group.org.der.exclusive"])
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: nil,
            derEntitlements: der
        ))
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertTrue(hasAppGroups)
        XCTAssertEqual(groups, ["group.org.der.exclusive"])
    }

    func testSlot7_derMultipleAppGroups_extracted() throws {
        let expected = ["group.der.first", "group.der.second", "group.der.third"]
        let der = SyntheticMachOGenerator.createDEREntitlements(appGroups: expected)
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: nil,
            derEntitlements: der
        ))
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertTrue(hasAppGroups)
        XCTAssertEqual(groups, expected)
    }

    func testSlot7_derEmptySequence_returnsFalse() throws {
        let der = SyntheticMachOGenerator.createDEREntitlements(appGroups: [])
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: nil,
            derEntitlements: der
        ))
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertFalse(hasAppGroups)
        XCTAssertTrue(groups.isEmpty)
    }

    func testSlot7_derIndefiniteLength0x80_strictlyRejected() throws {
        let indefinite = Data([0x30, 0x80, 0x00, 0x00])
        XCTAssertThrowsError(try CSBlobParser.shared.parseDERAppGroups(indefinite)) { error in
            guard let csError = error as? CSBlobError,
                  case .malformedDER(let reason) = csError else {
                XCTFail("Expected malformedDER, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("0x80"))
        }
    }

    func testSlot7_derTruncatedStream_gracefulFailure() throws {
        let der = SyntheticMachOGenerator.createDEREntitlements(appGroups: ["group.trunc"])
        let truncated = der.prefix(12)
        XCTAssertThrowsError(try CSBlobParser.shared.parseDERAppGroups(Data(truncated))) { error in
            guard case CSBlobError.malformedDER = error else {
                XCTFail("Expected malformedDER, got \(error)")
                return
            }
        }
    }

    func testSlot7_derLongFormLengthOctets_supported() throws {
        // Construct string with length > 128 (requires 0x81 length octet)
        let largeGroup = "group." + String(repeating: "a", count: 150)
        let der = SyntheticMachOGenerator.createDEREntitlements(appGroups: [largeGroup])
        let groups = try CSBlobParser.shared.parseDERAppGroups(der)
        XCTAssertEqual(groups, [largeGroup])
    }

    func testSlot7_derDeeplyNestedSequence_safelyBounded() throws {
        var nested = Data([0x0c, 0x04, 0x74, 0x65, 0x73, 0x74]) // UTF8String "test"
        for _ in 0..<20 {
            nested = Data([0x30, UInt8(nested.count)]) + nested
        }
        // 20 levels must parse without stack overflow
        XCTAssertNoThrow(try ASN1DERDecoder.decode(nested, maxDepth: 32))

        // Exceeding maxDepth must throw malformedDER
        XCTAssertThrowsError(try ASN1DERDecoder.decode(nested, maxDepth: 10)) { error in
            guard case CSBlobError.malformedDER(let reason) = error else {
                XCTFail("Expected malformedDER, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("limit"))
        }
    }

    // MARK: - 4. Dual Slot Coexistence & Resilient Fallback

    func testDualSlots_bothPresent_mergedAndDeduplicated() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.common", "group.xml.only"])
        let der = SyntheticMachOGenerator.createDEREntitlements(appGroups: ["group.common", "group.der.only"])
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: xml,
            derEntitlements: der
        ))
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertTrue(hasAppGroups)
        XCTAssertEqual(Set(groups), Set(["group.common", "group.xml.only", "group.der.only"]))
    }

    func testDualSlots_slot5Corrupt_fallsBackToSlot7() throws {
        let der = SyntheticMachOGenerator.createDEREntitlements(appGroups: ["group.der.rescued"])
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: "CORRUPTED_XML_PLIST_NOT_XML",
            derEntitlements: der
        ))
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertTrue(hasAppGroups)
        XCTAssertEqual(groups, ["group.der.rescued"])
    }

    func testDualSlots_slot7Corrupt_fallsBackToSlot5() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.xml.rescued"])
        let macho = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: xml,
            derEntitlements: Data([0x30, 0x80, 0x00, 0x00]) // Malformed BER indefinite length
        ))
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(fromMachO: macho)
        XCTAssertTrue(hasAppGroups)
        XCTAssertEqual(groups, ["group.xml.rescued"])
    }

    // MARK: - 5. Non-aligned Memory Pointer Trap Immunity

    func testUnalignedMemorySafety_oddByteOffsets_doesNotTrap() throws {
        // Construct SuperBlob with sub-blobs placed at intentionally unaligned (odd) offsets
        var buffer = Data()
        var magic = CSBlobConstants.superBlobMagic.bigEndian
        var totalLen = UInt32(100).bigEndian
        var count = UInt32(1).bigEndian
        buffer.append(Data(bytes: &magic, count: 4))
        buffer.append(Data(bytes: &totalLen, count: 4))
        buffer.append(Data(bytes: &count, count: 4))

        // Slot 0 at unaligned offset 21 (odd address!)
        var slotType = UInt32(5).bigEndian
        var slotOff = UInt32(21).bigEndian
        buffer.append(Data(bytes: &slotType, count: 4))
        buffer.append(Data(bytes: &slotOff, count: 4))

        // Pad up to offset 21
        while buffer.count < 21 {
            buffer.append(0x00)
        }

        // Sub-blob header at offset 21
        var blobMagic = CSBlobConstants.entitlementXmlMagic.bigEndian
        var blobLen = UInt32(24).bigEndian
        buffer.append(Data(bytes: &blobMagic, count: 4))
        buffer.append(Data(bytes: &blobLen, count: 4))
        buffer.append(contentsOf: "<plist/>".utf8)

        // Pad to totalLen (100 bytes)
        while buffer.count < 100 {
            buffer.append(0x00)
        }

        // Must NOT crash with "load from misaligned raw pointer"
        XCTAssertNoThrow(try CSBlobParser.shared.parseSuperBlob(buffer))
    }

    // MARK: - 6. Missing Code Signature & Edge Cases

    func testMissingCodeSignature_returnsFalse() {
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(from: nil)
        XCTAssertFalse(hasAppGroups)
        XCTAssertTrue(groups.isEmpty)
    }

    func testEmptyCodeSignatureData_returnsFalse() {
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(from: Data())
        XCTAssertFalse(hasAppGroups)
        XCTAssertTrue(groups.isEmpty)
    }

    func testRandomGarbageBytes_returnsFalseWithoutCrash() {
        let garbage = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let (hasAppGroups, groups) = CSBlobParser.shared.extractAppGroups(from: garbage)
        XCTAssertFalse(hasAppGroups)
        XCTAssertTrue(groups.isEmpty)
    }
}
