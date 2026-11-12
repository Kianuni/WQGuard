//
//  CSBlobParser.swift
//  WQGuardCore
//
//  Standalone 100% read-only Mach-O Code Signature SuperBlob and
//  Dual Entitlements (XML Plist & ASN.1 DER) Parser.
//

import Foundation
import MachO

// MARK: - Constants

public enum CSBlobConstants {
    /// SuperBlob magic: 0xfade0cc0 (CSBLOB_EMBEDDED_SIGNATURE)
    public static let superBlobMagic: UInt32 = 0xfade0cc0

    /// Slot 5 Entitlements XML blob magic: 0xfade7171 (CSBLOB_ENTITLEMENTS)
    public static let entitlementXmlMagic: UInt32 = 0xfade7171

    /// Slot 7 Entitlements DER blob magic: 0xfade7172 (CSBLOB_DER_ENTITLEMENTS)
    public static let entitlementDerMagic: UInt32 = 0xfade7172

    // Slot Types
    public static let slotCodeDirectory: UInt32 = 0x0
    public static let slotInfoSlot: UInt32 = 0x1
    public static let slotRequirements: UInt32 = 0x2
    public static let slotResourceDir: UInt32 = 0x3
    public static let slotApplication: UInt32 = 0x4
    public static let slotEntitlements: UInt32 = 0x5            // CSSLOT_ENTITLEMENTS (XML Plist)
    public static let slotRepSpecific: UInt32 = 0x6
    public static let slotDerEntitlements: UInt32 = 0x7        // CSSLOT_DER_ENTITLEMENTS (ASN.1 DER)
    public static let slotAlternateCodeDirectories: UInt32 = 0x1000

    /// Key for App Groups entitlement
    public static let appGroupsKey = "com.apple.security.application-groups"
}

// MARK: - Errors

public enum CSBlobError: Error, LocalizedError, Equatable {
    case dataTooSmall(expected: Int, actual: Int)
    case invalidSuperBlobMagic(actual: UInt32)
    case superBlobLengthOutOfBounds(declared: Int, actual: Int)
    case blobIndexOutOfBounds(index: Int, offset: Int, count: Int)
    case malformedBlobHeader(offset: Int)
    case malformedXMLPlist(reason: String)
    case malformedDER(reason: String)
    case noEntitlementsSlotFound
    case noCodeSignatureFound

    public var errorDescription: String? {
        switch self {
        case .dataTooSmall(let exp, let act):
            return "CSBlob data too small: expected at least \(exp) bytes, got \(act)"
        case .invalidSuperBlobMagic(let actual):
            return "Invalid SuperBlob magic: 0x\(String(actual, radix: 16)) (expected 0xfade0cc0)"
        case .superBlobLengthOutOfBounds(let dec, let act):
            return "SuperBlob declared length \(dec) exceeds available buffer \(act)"
        case .blobIndexOutOfBounds(let idx, let off, let cnt):
            return "Blob index #\(idx) offset \(off) exceeds buffer count \(cnt)"
        case .malformedBlobHeader(let off):
            return "Malformed blob header at offset \(off)"
        case .malformedXMLPlist(let reason):
            return "Malformed XML Plist entitlements: \(reason)"
        case .malformedDER(let reason):
            return "Malformed ASN.1 DER entitlements: \(reason)"
        case .noEntitlementsSlotFound:
            return "No entitlements slot (slot 5 XML or slot 7 DER) found in SuperBlob"
        case .noCodeSignatureFound:
            return "No LC_CODE_SIGNATURE command found in binary"
        }
    }
}

// MARK: - Models

public enum EntitlementFormat: String, Sendable, Codable, Equatable {
    case xml = "XML_PLIST"
    case der = "ASN1_DER"
    case dual = "DUAL_XML_AND_DER"
    case none = "NONE"
}

public struct ParsedEntitlements: Sendable, Equatable {
    public let rawXML: String?
    public let rawDER: Data?
    public let hasAppGroups: Bool
    public let appGroups: [String]
    public let formatUsed: EntitlementFormat

    public init(
        rawXML: String? = nil,
        rawDER: Data? = nil,
        hasAppGroups: Bool,
        appGroups: [String],
        formatUsed: EntitlementFormat
    ) {
        self.rawXML = rawXML
        self.rawDER = rawDER
        self.hasAppGroups = hasAppGroups
        self.appGroups = appGroups
        self.formatUsed = formatUsed
    }

    public static let empty = ParsedEntitlements(
        rawXML: nil,
        rawDER: nil,
        hasAppGroups: false,
        appGroups: [],
        formatUsed: .none
    )
}

public struct CSBlobIndexEntry: Sendable, Equatable {
    public let type: UInt32
    public let offset: Int
    public let magic: UInt32
    public let length: Int
    public let payloadOffset: Int
    public let payloadLength: Int

    public init(type: UInt32, offset: Int, magic: UInt32, length: Int, payloadOffset: Int, payloadLength: Int) {
        self.type = type
        self.offset = offset
        self.magic = magic
        self.length = length
        self.payloadOffset = payloadOffset
        self.payloadLength = payloadLength
    }
}

// MARK: - Protocol

public protocol CSBlobParserProtocol: Sendable {
    func parseSuperBlob(_ data: Data) throws -> ParsedEntitlements
    func parseSuperBlob(buffer: UnsafeRawBufferPointer) throws -> ParsedEntitlements
    func extractAppGroups(from codeSignatureData: Data?) -> (hasAppGroups: Bool, appGroups: [String])
    func parseBlobIndices(from buffer: UnsafeRawBufferPointer) throws -> [CSBlobIndexEntry]
    func parseXMLPlist(_ data: Data) throws -> [String: Any]
    func parseDEREntitlements(_ data: Data) throws -> [String: Any]
}

// MARK: - Implementation

public final class CSBlobParser: CSBlobParserProtocol, @unchecked Sendable {
    public static let shared = CSBlobParser()

    public init() {}

    // MARK: - Unaligned Byte-Safe Big-Endian Reader (ARM64 Trap Proof)

    @inline(__always)
    public static func readUInt32BE(from buffer: UnsafeRawBufferPointer, at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= buffer.count else { return nil }
        let b0 = UInt32(buffer[offset])
        let b1 = UInt32(buffer[offset + 1])
        let b2 = UInt32(buffer[offset + 2])
        let b3 = UInt32(buffer[offset + 3])
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }

    // MARK: - Infallible Convenience API for Layer 1 Gating

    /// Extracts application groups from raw code signature SuperBlob data. Infallible: never throws.
    public func extractAppGroups(from codeSignatureData: Data?) -> (hasAppGroups: Bool, appGroups: [String]) {
        guard let data = codeSignatureData, !data.isEmpty else {
            return (false, [])
        }
        do {
            let parsed = try parseSuperBlob(data)
            return (parsed.hasAppGroups, parsed.appGroups)
        } catch {
            return (false, [])
        }
    }

    /// Merges two entitlement dictionaries without letting benign/empty placeholders shadow active privileges.
    /// - String arrays (including `com.apple.security.application-groups`, `keychain-access-groups`, `com.apple.private.tcc.allow`) are deduplicated unions.
    /// - Booleans merge conservatively so an active privilege (`true`, or `false` for `com.apple.private.security.container-required`) is never shadowed by a benign value in another slot/slice.
    /// - Non-boolean scalars prefer `incoming` (e.g. Slot 7 DER `CoreEntitlements`, which XNU/AMFI prioritizes over Slot 5 XML).
    public static func mergeEntitlementDictionaries(_ base: [String: Any], _ incoming: [String: Any]) -> [String: Any] {
        var result = base
        for (key, newVal) in incoming {
            if key == CSBlobConstants.appGroupsKey {
                let oldGroups = CSBlobParser.shared.extractAppGroups(fromPlistDict: result)
                let newGroups = CSBlobParser.shared.extractAppGroups(fromPlistDict: [key: newVal])
                var unionGroups = oldGroups
                for g in newGroups where !unionGroups.contains(g) {
                    unionGroups.append(g)
                }
                if !unionGroups.isEmpty {
                    result[key] = unionGroups
                }
                continue
            }

            if let newBool = newVal as? Bool {
                if let oldBool = result[key] as? Bool {
                    if key == "com.apple.private.security.container-required" {
                        result[key] = oldBool && newBool
                    } else {
                        result[key] = oldBool || newBool
                    }
                } else {
                    result[key] = newBool
                }
                continue
            }

            if let newArr = newVal as? [Any] {
                let newStrings = newArr.compactMap { $0 as? String }
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
                if let oldArr = result[key] as? [Any] {
                    var unionStrings = oldArr.compactMap { $0 as? String }
                        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                        .filter { !$0.isEmpty }
                    for s in newStrings where !unionStrings.contains(s) {
                        unionStrings.append(s)
                    }
                    result[key] = unionStrings
                } else {
                    result[key] = newStrings.isEmpty ? newArr : newStrings
                }
                continue
            }

            if let newStr = newVal as? String {
                if !newStr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || result[key] == nil {
                    result[key] = newStr
                }
                continue
            }

            result[key] = newVal
        }
        return result
    }

    /// Extracts and merges full entitlements dictionary across all Slot 5 (XML Plist) and Slot 7 (ASN.1 DER) blobs.
    /// Infallible: returns empty dictionary if no valid entitlements are present.
    public func parseMergedEntitlements(from codeSignatureData: Data?) -> [String: Any] {
        guard let data = codeSignatureData, data.count >= 12 else { return [:] }
        return data.withUnsafeBytes { buffer -> [String: Any] in
            guard let magic = Self.readUInt32BE(from: buffer, at: 0),
                  magic == CSBlobConstants.superBlobMagic,
                  let lengthU32 = Self.readUInt32BE(from: buffer, at: 4) else {
                return [:]
            }
            let totalLength = Int(lengthU32)
            guard totalLength >= 12, totalLength <= buffer.count,
                  let entries = try? parseBlobIndices(from: buffer, totalLength: totalLength) else {
                return [:]
            }

            var merged: [String: Any] = [:]

            // 1. Merge all Slot 5 (XML Plist) entries
            for entry in entries where entry.type == CSBlobConstants.slotEntitlements || entry.magic == CSBlobConstants.entitlementXmlMagic {
                let start = entry.payloadOffset
                let end = start + entry.payloadLength
                if start >= 0, end <= buffer.count, start <= end {
                    let payload = Data(buffer[start..<end])
                    if let dict = try? parseXMLPlist(payload) {
                        merged = Self.mergeEntitlementDictionaries(merged, dict)
                    }
                }
            }

            // 2. Merge all Slot 7 (ASN.1 DER CoreEntitlements) entries (authoritative over Slot 5 XML)
            for entry in entries where entry.type == CSBlobConstants.slotDerEntitlements || entry.magic == CSBlobConstants.entitlementDerMagic {
                let start = entry.payloadOffset
                let end = start + entry.payloadLength
                if start >= 0, end <= buffer.count, start <= end {
                    let payload = Data(buffer[start..<end])
                    if let dict = try? parseDEREntitlements(payload) {
                        merged = Self.mergeEntitlementDictionaries(merged, dict)
                    }
                    if let derGroups = try? parseDERAppGroups(payload), !derGroups.isEmpty {
                        merged = Self.mergeEntitlementDictionaries(merged, [CSBlobConstants.appGroupsKey: derGroups])
                    }
                }
            }

            return merged
        }
    }

    /// Automatically sniffs whether input data is a standalone SuperBlob or full Mach-O binary.
    /// Unions App Groups across all architecture slices when given a Universal/FAT binary.
    public func extractAppGroups(fromMachO data: Data) -> (hasAppGroups: Bool, appGroups: [String]) {
        guard data.count >= 12 else { return (false, []) }

        // Check if data is already a SuperBlob
        if let magic = data.withUnsafeBytes({ Self.readUInt32BE(from: $0, at: 0) }),
           magic == CSBlobConstants.superBlobMagic {
            return extractAppGroups(from: data)
        }

        // Union App Groups across all executable iOS ARM slices in FAT/Thin binaries
        if let allSlices = try? MachOParser.parseAllSlices(data: data), !allSlices.isEmpty {
            var combined: [String] = []
            for slice in MachOParser.selectAuditSlices(from: allSlices) {
                let (_, groups) = extractAppGroups(from: slice.codeSignatureData)
                for g in groups where !combined.contains(g) {
                    combined.append(g)
                }
            }
            if !combined.isEmpty {
                return (true, combined)
            }
        }

        // Fallback byte-safe Mach-O load command navigator
        guard let csData = extractCodeSignatureSlice(from: data) else {
            return (false, [])
        }
        return extractAppGroups(from: csData)
    }

    // MARK: - SuperBlob Parsing

    public func parseSuperBlob(_ data: Data) throws -> ParsedEntitlements {
        return try data.withUnsafeBytes { raw in
            try parseSuperBlob(buffer: raw)
        }
    }

    public func parseSuperBlob(buffer: UnsafeRawBufferPointer) throws -> ParsedEntitlements {
        guard buffer.count >= 12 else {
            throw CSBlobError.dataTooSmall(expected: 12, actual: buffer.count)
        }
        guard let magic = Self.readUInt32BE(from: buffer, at: 0) else {
            throw CSBlobError.dataTooSmall(expected: 4, actual: buffer.count)
        }
        guard magic == CSBlobConstants.superBlobMagic else {
            throw CSBlobError.invalidSuperBlobMagic(actual: magic)
        }
        guard let lengthU32 = Self.readUInt32BE(from: buffer, at: 4) else {
            throw CSBlobError.dataTooSmall(expected: 8, actual: buffer.count)
        }
        let totalLength = Int(lengthU32)
        guard totalLength >= 12, totalLength <= buffer.count else {
            throw CSBlobError.superBlobLengthOutOfBounds(declared: totalLength, actual: buffer.count)
        }

        let entries = try parseBlobIndices(from: buffer, totalLength: totalLength)
        if entries.isEmpty {
            return .empty
        }

        var xmlGroups: [String]? = nil
        var derGroups: [String]? = nil
        var rawXMLString: String? = nil
        var rawDERData: Data? = nil

        // 1. Process all Slot 5 (XML Plist) entries
        let xmlEntries = entries.filter { $0.type == CSBlobConstants.slotEntitlements || $0.magic == CSBlobConstants.entitlementXmlMagic }
        for xmlEntry in xmlEntries {
            let start = xmlEntry.payloadOffset
            let end = start + xmlEntry.payloadLength
            if start >= 0, end <= buffer.count, start <= end {
                let payloadData = Data(buffer[start..<end])
                if rawXMLString == nil, let str = String(data: payloadData, encoding: .utf8) {
                    rawXMLString = str
                }
                if let dict = try? parseXMLPlist(payloadData) {
                    let groups = extractAppGroups(fromPlistDict: dict)
                    var acc = xmlGroups ?? []
                    for g in groups where !acc.contains(g) { acc.append(g) }
                    xmlGroups = acc
                }
            }
        }

        // 2. Process all Slot 7 (ASN.1 DER) entries
        let derEntries = entries.filter { $0.type == CSBlobConstants.slotDerEntitlements || $0.magic == CSBlobConstants.entitlementDerMagic }
        for derEntry in derEntries {
            let start = derEntry.payloadOffset
            let end = start + derEntry.payloadLength
            if start >= 0, end <= buffer.count, start <= end {
                let payloadData = Data(buffer[start..<end])
                if rawDERData == nil { rawDERData = payloadData }
                if let groups = try? parseDERAppGroups(payloadData) {
                    var acc = derGroups ?? []
                    for g in groups where !acc.contains(g) { acc.append(g) }
                    derGroups = acc
                }
            }
        }

        // If neither slot could be decoded
        if xmlGroups == nil && derGroups == nil {
            return .empty
        }

        let finalFormat: EntitlementFormat
        let mergedGroups: [String]

        if let xg = xmlGroups, let dg = derGroups {
            finalFormat = .dual
            var combined = xg
            for item in dg where !combined.contains(item) {
                combined.append(item)
            }
            mergedGroups = combined
        } else if let xg = xmlGroups {
            finalFormat = .xml
            mergedGroups = xg
        } else if let dg = derGroups {
            finalFormat = .der
            mergedGroups = dg
        } else {
            finalFormat = .none
            mergedGroups = []
        }

        return ParsedEntitlements(
            rawXML: rawXMLString,
            rawDER: rawDERData,
            hasAppGroups: !mergedGroups.isEmpty,
            appGroups: mergedGroups,
            formatUsed: finalFormat
        )
    }

    public func parseBlobIndices(from buffer: UnsafeRawBufferPointer) throws -> [CSBlobIndexEntry] {
        guard buffer.count >= 12 else {
            throw CSBlobError.dataTooSmall(expected: 12, actual: buffer.count)
        }
        guard let magic = Self.readUInt32BE(from: buffer, at: 0), magic == CSBlobConstants.superBlobMagic else {
            throw CSBlobError.invalidSuperBlobMagic(actual: Self.readUInt32BE(from: buffer, at: 0) ?? 0)
        }
        guard let lengthU32 = Self.readUInt32BE(from: buffer, at: 4) else {
            throw CSBlobError.dataTooSmall(expected: 8, actual: buffer.count)
        }
        let totalLength = Int(lengthU32)
        guard totalLength >= 12, totalLength <= buffer.count else {
            throw CSBlobError.superBlobLengthOutOfBounds(declared: totalLength, actual: buffer.count)
        }
        return try parseBlobIndices(from: buffer, totalLength: totalLength)
    }

    private func parseBlobIndices(from buffer: UnsafeRawBufferPointer, totalLength: Int) throws -> [CSBlobIndexEntry] {
        guard let countU32 = Self.readUInt32BE(from: buffer, at: 8) else { return [] }
        let rawCount = Int(countU32)
        let maxSlots = (totalLength - 12) / 8
        let safeCount = min(max(0, rawCount), maxSlots)

        var entries: [CSBlobIndexEntry] = []
        for i in 0..<safeCount {
            let idxOff = 12 + i * 8
            guard let type = Self.readUInt32BE(from: buffer, at: idxOff),
                  let blobOffU32 = Self.readUInt32BE(from: buffer, at: idxOff + 4) else { continue }
            let blobOff = Int(blobOffU32)
            guard blobOff >= 12, blobOff + 8 <= totalLength else { continue }
            guard let blobMagic = Self.readUInt32BE(from: buffer, at: blobOff),
                  let blobLenU32 = Self.readUInt32BE(from: buffer, at: blobOff + 4) else { continue }
            let blobLen = Int(blobLenU32)
            guard blobLen >= 8, blobOff + blobLen <= totalLength else { continue }

            entries.append(CSBlobIndexEntry(
                type: type,
                offset: blobOff,
                magic: blobMagic,
                length: blobLen,
                payloadOffset: blobOff + 8,
                payloadLength: blobLen - 8
            ))
        }
        return entries
    }

    // MARK: - XML Plist Parser

    public func parseXMLPlist(_ data: Data) throws -> [String: Any] {
        guard !data.isEmpty else { return [:] }
        // Strip trailing null bytes padding (added by codesign/ldid)
        var clean = data
        while let last = clean.last, last == 0 {
            clean.removeLast()
        }
        do {
            let obj = try PropertyListSerialization.propertyList(from: clean, options: [], format: nil)
            guard let dict = obj as? [String: Any] else { return [:] }
            return dict
        } catch {
            throw CSBlobError.malformedXMLPlist(reason: error.localizedDescription)
        }
    }

    public func extractAppGroups(fromPlistDict dict: [String: Any]) -> [String] {
        if let array = dict[CSBlobConstants.appGroupsKey] as? [Any] {
            return array.compactMap { $0 as? String }
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        } else if let single = dict[CSBlobConstants.appGroupsKey] as? String {
            let trimmed = single.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? [] : [trimmed]
        }
        return []
    }

    // MARK: - ASN.1 DER Parser

    public func parseDERAppGroups(_ data: Data) throws -> [String] {
        guard !data.isEmpty else { return [] }
        let root = try ASN1DERDecoder.decode(data)
        return ASN1DERDecoder.extractAppGroups(from: root)
    }

    public func parseDEREntitlements(_ data: Data) throws -> [String: Any] {
        guard !data.isEmpty else { return [:] }
        let root = try ASN1DERDecoder.decode(data)
        return ASN1DERDecoder.toDictionary(root)
    }

    // MARK: - Internal Mach-O Slicer (Fallback)

    private func extractCodeSignatureSlice(from data: Data) -> Data? {
        // Fast-path: delegate to MachOParser if available
        if let macho = try? MachOParser.parse(data: data, preferredCpuType: CPU_TYPE_ARM64),
           let csData = macho.codeSignatureData {
            return csData
        }

        // Robust byte-safe fallback scanner
        return data.withUnsafeBytes { raw -> Data? in
            guard raw.count >= 32 else { return nil }
            let magic = raw.loadUnaligned(as: UInt32.self)

            // Check Universal FAT (32-bit: 0xcafebabe / 0xbebafeca, 64-bit: 0xcafebabf / 0xbfbafeca)
            let isFat32BE = (magic.byteSwapped == FAT_MAGIC)
            let isFat32LE = (magic == FAT_MAGIC)
            let isFat64BE = (magic.byteSwapped == FAT_MAGIC_64)
            let isFat64LE = (magic == FAT_MAGIC_64)
            let isFat32 = isFat32BE || isFat32LE || (magic == FAT_CIGAM) || (magic == UInt32(0xcafebabe).bigEndian)
            let isFat64 = isFat64BE || isFat64LE || (magic == FAT_CIGAM_64) || (magic == UInt32(0xcafebabf).bigEndian)
            let isFat = isFat32 || isFat64

            if isFat {
                guard raw.count >= 8 else { return nil }
                let isFatBe = isFat64 ? (isFat64BE || magic == FAT_MAGIC_64 || magic == UInt32(0xcafebabf).bigEndian)
                                      : (isFat32BE || magic == FAT_MAGIC || magic == UInt32(0xcafebabe).bigEndian)
                let rawNfat = raw.loadUnaligned(fromByteOffset: 4, as: UInt32.self)
                let nfat = Int(isFatBe ? UInt32(bigEndian: rawNfat) : UInt32(littleEndian: rawNfat))
                let safeNfat = min(max(0, nfat), 1024)
                let stride = isFat64 ? 32 : 20

                var fallbackSlice: (off: Int, size: Int)? = nil

                for i in 0..<safeNfat {
                    let archOff = 8 + i * stride
                    guard archOff + stride <= raw.count else { break }
                    let rawCpu = raw.loadUnaligned(fromByteOffset: archOff, as: UInt32.self)
                    let cputype = Int32(bitPattern: isFatBe ? UInt32(bigEndian: rawCpu) : UInt32(littleEndian: rawCpu))

                    let sliceOff: Int
                    let sliceSize: Int
                    if isFat64 {
                        let rawOff = raw.loadUnaligned(fromByteOffset: archOff + 8, as: UInt64.self)
                        let rawSz = raw.loadUnaligned(fromByteOffset: archOff + 16, as: UInt64.self)
                        sliceOff = Int(isFatBe ? UInt64(bigEndian: rawOff) : UInt64(littleEndian: rawOff))
                        sliceSize = Int(isFatBe ? UInt64(bigEndian: rawSz) : UInt64(littleEndian: rawSz))
                    } else {
                        let rawOff = raw.loadUnaligned(fromByteOffset: archOff + 8, as: UInt32.self)
                        let rawSz = raw.loadUnaligned(fromByteOffset: archOff + 12, as: UInt32.self)
                        sliceOff = Int(isFatBe ? UInt32(bigEndian: rawOff) : UInt32(littleEndian: rawOff))
                        sliceSize = Int(isFatBe ? UInt32(bigEndian: rawSz) : UInt32(littleEndian: rawSz))
                    }

                    if sliceOff >= 0, sliceSize >= 0, sliceOff + sliceSize <= raw.count {
                        if cputype == CPU_TYPE_ARM64 {
                            let sliceData = Data(raw[sliceOff..<(sliceOff + sliceSize)])
                            if let cs = sliceData.withUnsafeBytes({ findCodeSignature(inThin: $0) }) {
                                return cs
                            }
                        } else if fallbackSlice == nil {
                            fallbackSlice = (sliceOff, sliceSize)
                        }
                    }
                }

                if let (off, sz) = fallbackSlice {
                    let sliceData = Data(raw[off..<(off + sz)])
                    return sliceData.withUnsafeBytes { findCodeSignature(inThin: $0) }
                }
            }

            // Thin 64-bit / 32-bit Mach-O
            return findCodeSignature(inThin: raw)
        }
    }

    private func findCodeSignature(inThin buf: UnsafeRawBufferPointer) -> Data? {
        guard buf.count >= 32 else { return nil }
        let magic = buf.loadUnaligned(as: UInt32.self)
        guard magic == MH_MAGIC_64 || magic == MH_CIGAM_64 || magic == MH_MAGIC || magic == MH_CIGAM else { return nil }
        let is64 = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
        let isSwapped = (magic == MH_CIGAM_64 || magic == MH_CIGAM)
        let headerSize = is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size

        guard buf.count >= 20 else { return nil }
        let rawNcmds = buf.loadUnaligned(fromByteOffset: 16, as: UInt32.self)
        let ncmds = Int(isSwapped ? rawNcmds.byteSwapped : rawNcmds)
        var cursor = headerSize

        for _ in 0..<min(max(0, ncmds), 16384) {
            guard cursor + 8 <= buf.count else { break }
            let rawCmd = buf.loadUnaligned(fromByteOffset: cursor, as: UInt32.self)
            let cmd = isSwapped ? rawCmd.byteSwapped : rawCmd
            let rawCmdsize = buf.loadUnaligned(fromByteOffset: cursor + 4, as: UInt32.self)
            let cmdsize = Int(isSwapped ? rawCmdsize.byteSwapped : rawCmdsize)
            guard cmdsize >= 8, cursor + cmdsize <= buf.count else { break }

            if cmd == UInt32(LC_CODE_SIGNATURE) {
                guard cmdsize >= MemoryLayout<linkedit_data_command>.size else { break }
                let rawDataoff = buf.loadUnaligned(fromByteOffset: cursor + 8, as: UInt32.self)
                let dataoff = Int(isSwapped ? rawDataoff.byteSwapped : rawDataoff)
                let rawDatasize = buf.loadUnaligned(fromByteOffset: cursor + 12, as: UInt32.self)
                let datasize = Int(isSwapped ? rawDatasize.byteSwapped : rawDatasize)
                guard dataoff >= 0, datasize > 0, dataoff + datasize <= buf.count else { return nil }
                return Data(buf[dataoff..<(dataoff + datasize)])
            }
            cursor += cmdsize
        }
        return nil
    }
}

// MARK: - ASN.1 DER Decoder Subsystem

public enum ASN1DERDecoder {
    public indirect enum Node: Equatable {
        case boolean(Bool)
        case integer(Int64)
        case string(String)
        case data(Data)
        case sequence([Node])
        case set([Node])
        case constructed(tag: UInt8, children: [Node])
        case other(tag: UInt8, data: Data)
    }

    public static func decode(_ data: Data, maxDepth: Int = 32) throws -> Node {
        guard !data.isEmpty else {
            throw CSBlobError.malformedDER(reason: "Empty DER data")
        }
        return try data.withUnsafeBytes { raw in
            var offset = 0
            guard let node = try decodeNode(from: raw, offset: &offset, depth: 0, maxDepth: maxDepth) else {
                throw CSBlobError.malformedDER(reason: "No root DER element")
            }
            return node
        }
    }

    private static func decodeNode(
        from buf: UnsafeRawBufferPointer,
        offset: inout Int,
        depth: Int,
        maxDepth: Int
    ) throws -> Node? {
        guard offset < buf.count else { return nil }
        guard depth <= maxDepth else {
            throw CSBlobError.malformedDER(reason: "DER recursion depth exceeded limit of \(maxDepth)")
        }

        let tag = buf[offset]
        var cursor = offset + 1

        // Support ITU-T X.690 high-tag-number form ((tag & 0x1f) == 0x1f)
        if (tag & 0x1f) == 0x1f {
            var tagOctets = 0
            var foundTerminator = false
            while cursor < buf.count && tagOctets < 5 {
                let b = buf[cursor]
                cursor += 1
                tagOctets += 1
                if (b & 0x80) == 0 {
                    foundTerminator = true
                    break
                }
            }
            guard foundTerminator else {
                throw CSBlobError.malformedDER(reason: "Malformed or truncated high-tag-number DER tag at offset \(offset)")
            }
        }

        guard cursor < buf.count else {
            throw CSBlobError.malformedDER(reason: "Truncated DER stream at offset \(offset)")
        }

        let lengthByte = buf[cursor]
        cursor += 1

        let valueLength: Int
        if lengthByte == 0x80 {
            // Strictly forbidden in DER (ITU-T X.690 Section 10.1)
            throw CSBlobError.malformedDER(reason: "ASN.1 BER indefinite length (0x80) forbidden in DER")
        } else if (lengthByte & 0x80) == 0 {
            // Short form (0..127)
            valueLength = Int(lengthByte)
        } else {
            // Long form
            let numOctets = Int(lengthByte & 0x7f)
            if numOctets == 0 || numOctets > 4 {
                throw CSBlobError.malformedDER(reason: "Invalid DER length octets: \(numOctets)")
            }
            guard cursor + numOctets <= buf.count else {
                throw CSBlobError.malformedDER(reason: "Truncated DER length octets")
            }
            var len = 0
            for _ in 0..<numOctets {
                len = (len << 8) | Int(buf[cursor])
                cursor += 1
            }
            valueLength = len
        }

        guard cursor + valueLength <= buf.count else {
            throw CSBlobError.malformedDER(reason: "DER value length \(valueLength) exceeds buffer bound")
        }

        let valStart = cursor
        cursor += valueLength
        offset = cursor

        guard valStart >= 0, valStart + valueLength <= buf.count else {
            throw CSBlobError.malformedDER(reason: "DER value length \(valueLength) exceeds buffer bound")
        }
        let valSlice = UnsafeRawBufferPointer(rebasing: buf[valStart..<(valStart + valueLength)])
        let valData = Data(valSlice)

        func decodeChildren() throws -> [Node] {
            var children: [Node] = []
            var innerOffset = 0
            while innerOffset < valSlice.count {
                if let child = try decodeNode(from: valSlice, offset: &innerOffset, depth: depth + 1, maxDepth: maxDepth) {
                    children.append(child)
                } else {
                    break
                }
            }
            return children
        }

        switch tag {
        case 0x01: // BOOLEAN
            guard valueLength == 1 else {
                throw CSBlobError.malformedDER(reason: "Invalid boolean length \(valueLength)")
            }
            return .boolean(valSlice[0] != 0)

        case 0x02: // INTEGER
            var val: Int64 = 0
            for b in valSlice {
                val = (val << 8) | Int64(b)
            }
            return .integer(val)

        case 0x0c, 0x13, 0x16, 0x1a: // UTF8String, PrintableString, IA5String, VisibleString
            let str = String(decoding: valSlice, as: UTF8.self)
            return .string(str)

        case 0x04: // OCTET STRING
            return .data(valData)

        case 0x30: // SEQUENCE
            return .sequence(try decodeChildren())

        case 0x31: // SET
            return .set(try decodeChildren())

        default:
            // Any constructed ASN.1 container ((tag & 0x20) != 0), including Apple CoreEntitlements
            // [APPLICATION 16] (0x70) and [CONTEXT 16] (0xb0) wrappers.
            if (tag & 0x20) != 0 {
                return .constructed(tag: tag, children: try decodeChildren())
            }
            return .other(tag: tag, data: valData)
        }
    }

    public static func extractAppGroups(from node: Node) -> [String] {
        var groups: [String] = []

        func collectFromStringNode(_ n: Node) {
            switch n {
            case .string(let s):
                let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty && !groups.contains(trimmed) {
                    groups.append(trimmed)
                }
            case .sequence(let items), .set(let items), .constructed(_, let items):
                for item in items {
                    collectFromStringNode(item)
                }
            case .data(let d):
                if let s = String(data: d, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                   !s.isEmpty && !groups.contains(s) {
                    groups.append(s)
                }
            default:
                break
            }
        }

        func walk(_ n: Node) {
            switch n {
            case .sequence(let children), .set(let children), .constructed(_, let children):
                // Pair: [keyNode, valueNode]
                if children.count == 2,
                   case .string(let k) = children[0],
                   k == CSBlobConstants.appGroupsKey {
                    collectFromStringNode(children[1])
                    return
                }
                // Alternating sequence: [key1, val1, key2, val2, ...]
                if children.count >= 2 {
                    for i in stride(from: 0, to: children.count - 1, by: 2) {
                        if case .string(let k) = children[i], k == CSBlobConstants.appGroupsKey {
                            collectFromStringNode(children[i + 1])
                        }
                    }
                }
                for child in children {
                    walk(child)
                }
            default:
                break
            }
        }

        walk(node)
        return groups
    }

    public static func toDictionary(_ node: Node) -> [String: Any] {
        var dict: [String: Any] = [:]

        func asPair(_ n: Node) -> (String, Node)? {
            switch n {
            case .sequence(let pair), .set(let pair), .constructed(_, let pair):
                if pair.count == 2, case .string(let key) = pair[0] {
                    return (key, pair[1])
                }
                return nil
            default:
                return nil
            }
        }

        func convertVal(_ n: Node) -> Any {
            switch n {
            case .boolean(let b): return b
            case .integer(let i): return i
            case .string(let s): return s
            case .data(let d): return d
            case .sequence(let items), .set(let items), .constructed(_, let items):
                if !items.isEmpty {
                    let pairs = items.compactMap(asPair)
                    if pairs.count == items.count {
                        var sub: [String: Any] = [:]
                        for (k, v) in pairs {
                            sub[k] = convertVal(v)
                        }
                        return sub
                    }
                }
                return items.map(convertVal)
            case .other(_, let d): return d
            }
        }

        func walkDict(_ n: Node) {
            switch n {
            case .sequence(let children), .set(let children), .constructed(_, let children):
                if let (k, v) = asPair(n) {
                    dict[k] = convertVal(v)
                    return
                }
                for child in children {
                    if let (k, v) = asPair(child) {
                        dict[k] = convertVal(v)
                    } else {
                        walkDict(child)
                    }
                }
            default:
                break
            }
        }

        walkDict(node)
        return dict
    }
}
