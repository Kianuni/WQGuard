//
//  CSBlobParser.swift
//  WQGuardCore
//
//  Standalone 100% read-only Mach-O Code Signature SuperBlob and
//  Dual Entitlements (XML Plist & ASN.1 DER) Parser.
//

import CryptoKit
import Foundation
import MachO
import Security

// MARK: - Constants

public enum CSBlobConstants {
    /// SuperBlob magic: 0xfade0cc0 (CSBLOB_EMBEDDED_SIGNATURE)
    public static let superBlobMagic: UInt32 = 0xfade0cc0

    /// CodeDirectory magic: 0xfade0c02 (CSMAGIC_CODEDIRECTORY)
    public static let codeDirectoryMagic: UInt32 = 0xfade0c02

    /// Generic/CMS BlobWrapper magic: 0xfade0b01 (CSMAGIC_BLOBWRAPPER)
    public static let blobWrapperMagic: UInt32 = 0xfade0b01

    /// Slot 5 Entitlements XML blob magic: 0xfade7171 (CSBLOB_ENTITLEMENTS)
    public static let entitlementXmlMagic: UInt32 = 0xfade7171

    /// Slot 7 Entitlements DER blob magic: 0xfade7172 (CSBLOB_DER_ENTITLEMENTS)
    public static let entitlementDerMagic: UInt32 = 0xfade7172

    /// CodeDirectory ad-hoc signature flag: 0x00000002 (CS_ADHOC)
    public static let csAdhocFlag: UInt32 = 0x0000_0002

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
    public static let slotCMSSignature: UInt32 = 0x10000       // CSSLOT_CMS_SIGNATURE (PKCS#7 CMS)

    /// Key for App Groups entitlement
    public static let appGroupsKey = "com.apple.security.application-groups"
}

/// Cryptographic authenticity disposition of a Mach-O `LC_CODE_SIGNATURE` SuperBlob.
public enum CodeSignatureTrustDisposition: Sendable, Equatable {
    /// No `CodeDirectory` or `CSSLOT_CMS_SIGNATURE` present (e.g. synthetic test fixture or unsigned Mach-O).
    case absentOrSynthetic
    /// Cryptographically verified X.509 certificate chain anchored at `Apple Root CA` with an official
    /// `"Apple iPhone OS Application Signing"` or `"Software Signing"` leaf and zero `CS_ADHOC` flags.
    case appleAppStoreVerified
    /// `CS_ADHOC` (`0x2`) set in `CodeDirectory.flags` or `CodeDirectory` present with an empty/missing CMS signature (`codesign -s -` / `ldid`).
    case adHocOrUnsigned
    /// Non-empty CMS signature whose certificate chain either fails `Apple Root CA` cryptographic verification
    /// (e.g. self-signed spoof) or belongs to a non-App-Store identity (`Apple Development`, `iPhone Distribution`, etc.).
    case nonAppStoreSigner(subjectSummary: String?)

    public var isDisqualifiedFromAppStore: Bool {
        switch self {
        case .adHocOrUnsigned, .nonAppStoreSigner:
            return true
        case .absentOrSynthetic, .appleAppStoreVerified:
            return false
        }
    }
}

/// Verified Apple leaf signer identity category derived from CMS X.509 leaf subject summary.
public enum AppleVerifiedSignerKind: String, Sendable, Equatable {
    case none
    case appStore
    case testFlight
    case macSoftware
}

/// Full cryptographic code-signature evaluation combining disposition and verified Apple leaf signer provenance.
public struct CodeSignatureTrustEvaluation: Sendable, Equatable {
    public let disposition: CodeSignatureTrustDisposition
    public let signerKind: AppleVerifiedSignerKind
    public let leafSubjectSummary: String?

    public init(
        disposition: CodeSignatureTrustDisposition,
        signerKind: AppleVerifiedSignerKind,
        leafSubjectSummary: String? = nil
    ) {
        self.disposition = disposition
        self.signerKind = signerKind
        self.leafSubjectSummary = leafSubjectSummary
    }
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

    private static func scalarBoolValue(_ val: Any?) -> Bool? {
        guard let val else { return nil }
        if let b = val as? Bool { return b }
        if let i = val as? Int { return i != 0 }
        if let i64 = val as? Int64 { return i64 != 0 }
        if let u64 = val as? UInt64 { return u64 != 0 }
        if let i32 = val as? Int32 { return i32 != 0 }
        if let num = val as? NSNumber {
            return num.int64Value != 0 || num.doubleValue != 0.0
        }
        return nil
    }

    private static func isInactiveEntitlementPlaceholder(key: String, value: Any) -> Bool {
        if let b = scalarBoolValue(value) {
            return key == "com.apple.private.security.container-required" ? b : !b
        }
        if let s = value as? String {
            return s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        if let arr = value as? [Any] {
            if arr.isEmpty { return true }
            let strings = arr.compactMap { $0 as? String }
            if strings.count == arr.count {
                return strings.allSatisfy { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            }
            return false
        }
        return false
    }

    /// Merges two entitlement dictionaries without letting benign/empty/cross-type placeholders shadow active privileges.
    /// - String arrays (including `com.apple.security.application-groups`, `keychain-access-groups`, `com.apple.private.tcc.allow`) are deduplicated unions.
    /// - Boolean and numeric-boolean scalars (`Bool`, `Int64`, `NSNumber`) merge conservatively so an active privilege (`true`, or `false` for `com.apple.private.security.container-required`) is never shadowed by a benign value (`false`, `Int64(0)`, `[]`, `""`) in another slot/slice.
    /// - Non-boolean scalars prefer active `incoming` values (e.g. Slot 7 DER `CoreEntitlements`, which XNU/AMFI prioritizes over Slot 5 XML).
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

            if let oldVal = result[key],
               !isInactiveEntitlementPlaceholder(key: key, value: oldVal),
               isInactiveEntitlementPlaceholder(key: key, value: newVal) {
                continue
            }

            if let newBool = scalarBoolValue(newVal) {
                if let oldVal = result[key] {
                    if let oldBool = scalarBoolValue(oldVal) {
                        if key == "com.apple.private.security.container-required" {
                            result[key] = oldBool && newBool
                        } else {
                            result[key] = oldBool || newBool
                        }
                    } else if isInactiveEntitlementPlaceholder(key: key, value: oldVal) {
                        result[key] = newBool
                    }
                    // Otherwise oldVal is an active non-boolean collection/string (e.g. ["kTCCServiceMicrophone"]),
                    // keep it if newBool is false; if newBool is true and oldVal is active collection, keep collection.
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
                } else if let oldStr = result[key] as? String {
                    let trimmedOld = oldStr.trimmingCharacters(in: .whitespacesAndNewlines)
                    var unionStrings = trimmedOld.isEmpty ? [] : [trimmedOld]
                    for s in newStrings where !unionStrings.contains(s) {
                        unionStrings.append(s)
                    }
                    result[key] = unionStrings.isEmpty ? newArr : unionStrings
                } else {
                    result[key] = newStrings.isEmpty ? newArr : newStrings
                }
                continue
            }

            if let newStr = newVal as? String {
                let trimmedNew = newStr.trimmingCharacters(in: .whitespacesAndNewlines)
                if let oldArr = result[key] as? [Any] {
                    if !trimmedNew.isEmpty {
                        var unionStrings = oldArr.compactMap { $0 as? String }
                            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                            .filter { !$0.isEmpty }
                        if !unionStrings.contains(trimmedNew) {
                            unionStrings.append(trimmedNew)
                        }
                        result[key] = unionStrings
                    }
                } else if !trimmedNew.isEmpty || result[key] == nil {
                    result[key] = newStr
                }
                continue
            }

            result[key] = newVal
        }
        return result
    }

    /// Unions App Groups across ALL `LC_CODE_SIGNATURE` load commands in a single parsed `MachOFile`.
    public func extractAppGroups(fromSlice slice: MachOFile) -> (hasAppGroups: Bool, appGroups: [String]) {
        var combined: [String] = []
        let blobs = slice.allCodeSignatureData
        if blobs.isEmpty {
            return extractAppGroups(from: slice.codeSignatureData)
        }
        for blob in blobs {
            let (_, groups) = extractAppGroups(from: blob)
            for g in groups where !combined.contains(g) {
                combined.append(g)
            }
        }
        return (!combined.isEmpty, combined)
    }

    /// Unions merged Slot 5 + Slot 7 entitlement dictionaries across ALL `LC_CODE_SIGNATURE` load commands in a `MachOFile`.
    public func parseMergedEntitlements(fromSlice slice: MachOFile) -> [String: Any] {
        let blobs = slice.allCodeSignatureData
        if blobs.isEmpty {
            return parseMergedEntitlements(from: slice.codeSignatureData)
        }
        var merged: [String: Any] = [:]
        for blob in blobs {
            let dict = parseMergedEntitlements(from: blob)
            merged = Self.mergeEntitlementDictionaries(merged, dict)
        }
        return merged
    }

    /// Extracts and merges full entitlements dictionary across all Slot 5 (XML Plist) and Slot 7 (ASN.1 DER) blobs.
    /// Infallible: returns empty dictionary if no valid entitlements are present.
    public func parseMergedEntitlements(from codeSignatureData: Data?) -> [String: Any] {
        var merged: [String: Any] = [:]
        for dict in extractIndividualEntitlementDictionaries(from: codeSignatureData) {
            merged = Self.mergeEntitlementDictionaries(merged, dict)
        }
        return merged
    }

    /// Returns each individual Slot 5 (XML) and Slot 7 (DER) entitlement dictionary inside a `CS_SuperBlob` in evaluation order,
    /// without collapsing scalar string keys so callers can detect cross-slot or cross-slice identity shadowing.
    internal func extractIndividualEntitlementDictionaries(from codeSignatureData: Data?) -> [[String: Any]] {
        guard let data = codeSignatureData, data.count >= 12 else { return [] }
        return data.withUnsafeBytes { buffer -> [[String: Any]] in
            guard let magic = Self.readUInt32BE(from: buffer, at: 0),
                  magic == CSBlobConstants.superBlobMagic,
                  let lengthU32 = Self.readUInt32BE(from: buffer, at: 4) else {
                return []
            }
            let totalLength = Int(lengthU32)
            guard totalLength >= 12, totalLength <= buffer.count,
                  let entries = try? parseBlobIndices(from: buffer, totalLength: totalLength) else {
                return []
            }

            var dicts: [[String: Any]] = []

            // 1. All Slot 5 (XML Plist) entries
            for entry in entries where entry.type == CSBlobConstants.slotEntitlements || entry.magic == CSBlobConstants.entitlementXmlMagic {
                let start = entry.payloadOffset
                let end = start + entry.payloadLength
                if start >= 0, end <= buffer.count, start <= end {
                    let payload = Data(buffer[start..<end])
                    if let dict = try? parseXMLPlist(payload), !dict.isEmpty {
                        dicts.append(dict)
                    }
                }
            }

            // 2. All Slot 7 (ASN.1 DER CoreEntitlements) entries
            for entry in entries where entry.type == CSBlobConstants.slotDerEntitlements || entry.magic == CSBlobConstants.entitlementDerMagic {
                let start = entry.payloadOffset
                let end = start + entry.payloadLength
                if start >= 0, end <= buffer.count, start <= end {
                    let payload = Data(buffer[start..<end])
                    var combinedDer: [String: Any] = (try? parseDEREntitlements(payload)) ?? [:]
                    if let derGroups = try? parseDERAppGroups(payload), !derGroups.isEmpty {
                        combinedDer = Self.mergeEntitlementDictionaries(combinedDer, [CSBlobConstants.appGroupsKey: derGroups])
                    }
                    if !combinedDer.isEmpty {
                        dicts.append(combinedDer)
                    }
                }
            }

            return dicts
        }
    }

    /// Collects all distinct `application-identifier` and `com.apple.developer.team-identifier` values across all
    /// selected iOS audit slices (`MachOParser.selectAuditSlices`), all `LC_CODE_SIGNATURE` load commands, and
    /// both Slot 5 XML + Slot 7 DER blobs, defeating multi-slice and cross-slot identity shadowing.
    public func extractDistinctEntitlementIdentities(fromSlices slices: [MachOFile]) -> (appIdentifiers: [String], teamIdentifiers: [String]) {
        let auditSlices = MachOParser.selectAuditSlices(from: slices)
        var appIds: [String] = []
        var seenAppIdsLower: Set<String> = []
        var teamIds: [String] = []
        var seenTeamIdsLower: Set<String> = []

        func recordTeamId(_ raw: String) {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }
            if seenTeamIdsLower.insert(trimmed.lowercased()).inserted {
                teamIds.append(trimmed)
            }
        }

        for slice in auditSlices {
            let blobs = slice.allCodeSignatureData.isEmpty
                ? (slice.codeSignatureData.map { [$0] } ?? [])
                : slice.allCodeSignatureData
            for blob in blobs {
                for dict in extractIndividualEntitlementDictionaries(from: blob) {
                    if let rawTid = dict["com.apple.developer.team-identifier"] as? String {
                        recordTeamId(rawTid)
                    }
                    if let rawAppId = (dict["application-identifier"] as? String)?
                        .trimmingCharacters(in: .whitespacesAndNewlines),
                       !rawAppId.isEmpty {
                        if seenAppIdsLower.insert(rawAppId.lowercased()).inserted {
                            appIds.append(rawAppId)
                        }
                        if let dotIdx = rawAppId.firstIndex(of: ".") {
                            let prefix = String(rawAppId[..<dotIdx])
                            let rest = rawAppId[rawAppId.index(after: dotIdx)...]
                            let isTenCharTeam = prefix.count == 10 && !rest.isEmpty && prefix.utf8.allSatisfy {
                                ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x30 && $0 <= 0x39)
                            }
                            if isTenCharTeam {
                                recordTeamId(prefix)
                            }
                        }
                    }
                }
            }
        }

        return (appIds, teamIds)
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

        // Union App Groups across all executable iOS ARM slices and all LC_CODE_SIGNATURE commands in FAT/Thin binaries
        if let allSlices = try? MachOParser.parseAllSlices(data: data), !allSlices.isEmpty {
            var combined: [String] = []
            for slice in MachOParser.selectAuditSlices(from: allSlices) {
                let (_, groups) = extractAppGroups(fromSlice: slice)
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
        let maxSlots = min(max(0, (totalLength - 12) / 8), 4096)
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

    // MARK: - Cryptographic CMS & CodeDirectory Authenticity Inspection

    private struct ParsedCodeDirectory {
        let slotType: UInt32
        let rawBlob: Data
        let version: UInt32
        let flags: UInt32
        let hashOffset: Int
        let identOffset: Int
        let identifier: String?
        let nSpecialSlots: Int
        let nCodeSlots: Int
        let effectiveCodeLimit: Int
        let hashSize: Int
        let hashType: UInt8
        let effectivePageSize: Int
        let hasScatter: Bool

        func specialSlotHash(_ slotIndex: Int) -> Data? {
            guard slotIndex >= 1, slotIndex <= nSpecialSlots else { return nil }
            let start = hashOffset - slotIndex * hashSize
            let end = start + hashSize
            guard start >= 44, end <= rawBlob.count else { return nil }
            return rawBlob.subdata(in: start..<end)
        }

        func codeSlotHash(_ slotIndex: Int) -> Data? {
            guard slotIndex >= 0, slotIndex < nCodeSlots else { return nil }
            let start = hashOffset + slotIndex * hashSize
            let end = start + hashSize
            guard start >= 44, end <= rawBlob.count else { return nil }
            return rawBlob.subdata(in: start..<end)
        }
    }

    private struct BERElement {
        let tag: UInt8
        let isIndefinite: Bool
        let contentRange: Range<Int>
        let fullRange: Range<Int>
    }

    private enum CMSSignerIdentifier {
        case issuerAndSerial(issuerTLV: Data, serialBytes: Data)
        case subjectKeyIdentifier(Data)
    }

    private struct ParsedCMSSignerInfo {
        let sid: CMSSignerIdentifier
        let digestAlgorithmOID: Data
        let retaggedSignedAttrs: Data
        let contentTypeValues: [Data]
        let messageDigestValues: [Data]
        let appleCDHashesPlistBlobs: [Data]
        let appleCDHashesDEREntries: [(algOID: Data, hashes: [Data])]
        let signatureAlgorithmOID: Data
        let signatureBytes: Data
    }

    private struct ParsedCMSSignedData {
        let encapContentTypeOID: Data
        let encapContentBytes: Data?
        let certificateDERs: [Data]
        let signerInfos: [ParsedCMSSignerInfo]
    }

    /// Returns `true` when `slices` has no selected audit slices or any selected audit slice completely lacks an `LC_CODE_SIGNATURE` load command (`codeSignatures.isEmpty`).
    public static func hasMissingCodeSignature(inSlices slices: [MachOFile]) -> Bool {
        let auditSlices = MachOParser.selectAuditSlices(from: slices)
        return auditSlices.isEmpty || auditSlices.contains { $0.codeSignatures.isEmpty }
    }

    /// Evaluates cryptographic code-signature authenticity across all slices of a Mach-O image (100% read-only).
    /// Rejects ad-hoc (`CS_ADHOC` / empty CMS), grafted/transplanted CMS, unverified `CodeDirectory` Page-0 / code slots,
    /// unsigned `SuperBlob` Slot 5/7 injections, mixed signed+unsigned FAT slices, and developer/enterprise/self-signed X.509 chains
    /// claiming `cryptid != 0` App Store status, while preserving `.absentOrSynthetic` for minimal synthetic test fixtures
    /// lacking both `CodeDirectory` and `CSSLOT_CMS_SIGNATURE`.
    public func inspectCodeSignatureTrust(fromSlices slices: [MachOFile]) -> CodeSignatureTrustDisposition {
        inspectCodeSignatureTrustEvaluation(fromSlices: slices, customAnchorCertificates: nil).disposition
    }

    internal func inspectCodeSignatureTrust(
        fromSlices slices: [MachOFile],
        customAnchorCertificates: [SecCertificate]?
    ) -> CodeSignatureTrustDisposition {
        inspectCodeSignatureTrustEvaluation(fromSlices: slices, customAnchorCertificates: customAnchorCertificates).disposition
    }

    public func inspectCodeSignatureTrustEvaluation(fromSlices slices: [MachOFile]) -> CodeSignatureTrustEvaluation {
        inspectCodeSignatureTrustEvaluation(fromSlices: slices, customAnchorCertificates: nil)
    }

    internal func inspectCodeSignatureTrustEvaluation(
        fromSlices slices: [MachOFile],
        customAnchorCertificates: [SecCertificate]?
    ) -> CodeSignatureTrustEvaluation {
        let auditSlices = MachOParser.selectAuditSlices(from: slices)
        var sawAppleVerified = false
        var sawAbsent = false
        var verifiedKinds: [AppleVerifiedSignerKind] = []
        var verifiedSummary: String? = nil

        for slice in auditSlices {
            if !slice.codeSignatures.isEmpty {
                for cs in slice.codeSignatures {
                    if cs.datasize < 12 || UInt64(cs.dataoff) + UInt64(cs.datasize) > UInt64(slice.sliceData.count) {
                        return CodeSignatureTrustEvaluation(disposition: .adHocOrUnsigned, signerKind: .none, leafSubjectSummary: nil)
                    }
                }
            }
            let blobs = slice.allCodeSignatureData
            if blobs.isEmpty {
                let eval = inspectCodeSignatureTrustEvaluation(
                    from: slice.codeSignatureData,
                    sliceData: slice.sliceData,
                    customAnchorCertificates: customAnchorCertificates
                )
                switch eval.disposition {
                case .adHocOrUnsigned, .nonAppStoreSigner:
                    return eval
                case .appleAppStoreVerified:
                    sawAppleVerified = true
                    verifiedKinds.append(eval.signerKind)
                    if verifiedSummary == nil { verifiedSummary = eval.leafSubjectSummary }
                case .absentOrSynthetic:
                    sawAbsent = true
                }
            } else {
                for blob in blobs {
                    let eval = inspectCodeSignatureTrustEvaluation(
                        from: blob,
                        sliceData: slice.sliceData,
                        customAnchorCertificates: customAnchorCertificates
                    )
                    switch eval.disposition {
                    case .adHocOrUnsigned, .nonAppStoreSigner:
                        return eval
                    case .appleAppStoreVerified:
                        sawAppleVerified = true
                        verifiedKinds.append(eval.signerKind)
                        if verifiedSummary == nil { verifiedSummary = eval.leafSubjectSummary }
                    case .absentOrSynthetic:
                        sawAbsent = true
                    }
                }
            }
        }
        if sawAppleVerified && sawAbsent {
            return CodeSignatureTrustEvaluation(disposition: .adHocOrUnsigned, signerKind: .none, leafSubjectSummary: nil)
        }
        if sawAppleVerified {
            let aggregatedKind: AppleVerifiedSignerKind
            if verifiedKinds.contains(.testFlight) {
                aggregatedKind = .testFlight
            } else if verifiedKinds.contains(.appStore) {
                aggregatedKind = .appStore
            } else if verifiedKinds.contains(.macSoftware) {
                aggregatedKind = .macSoftware
            } else {
                aggregatedKind = .none
            }
            return CodeSignatureTrustEvaluation(
                disposition: .appleAppStoreVerified,
                signerKind: aggregatedKind,
                leafSubjectSummary: verifiedSummary
            )
        }
        return CodeSignatureTrustEvaluation(disposition: .absentOrSynthetic, signerKind: .none, leafSubjectSummary: nil)
    }

    public func inspectCodeSignatureTrust(from codeSignatureData: Data?) -> CodeSignatureTrustDisposition {
        inspectCodeSignatureTrustEvaluation(from: codeSignatureData, sliceData: nil, customAnchorCertificates: nil).disposition
    }

    public func inspectCodeSignatureTrustEvaluation(from codeSignatureData: Data?) -> CodeSignatureTrustEvaluation {
        inspectCodeSignatureTrustEvaluation(from: codeSignatureData, sliceData: nil, customAnchorCertificates: nil)
    }

    private func parseBlobIndicesStrict(from buffer: UnsafeRawBufferPointer, totalLength: Int) -> [CSBlobIndexEntry]? {
        guard let countU32 = Self.readUInt32BE(from: buffer, at: 8) else { return nil }
        let maxSlots = min(max(0, (totalLength - 12) / 8), 4096)
        guard UInt64(countU32) <= UInt64(maxSlots) else { return nil }
        let count = Int(countU32)

        var entries: [CSBlobIndexEntry] = []
        entries.reserveCapacity(count)
        for i in 0..<count {
            let idxOff = 12 + i * 8
            guard let type = Self.readUInt32BE(from: buffer, at: idxOff),
                  let blobOffU32 = Self.readUInt32BE(from: buffer, at: idxOff + 4) else {
                return nil
            }
            let blobOff = Int(blobOffU32)
            guard blobOff >= 12 + count * 8, blobOff + 8 <= totalLength,
                  let blobMagic = Self.readUInt32BE(from: buffer, at: blobOff),
                  let blobLenU32 = Self.readUInt32BE(from: buffer, at: blobOff + 4) else {
                return nil
            }
            let blobLen = Int(blobLenU32)
            guard blobLen >= 8, blobOff <= totalLength - blobLen else {
                return nil
            }
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

    internal func inspectCodeSignatureTrust(
        from codeSignatureData: Data?,
        sliceData: Data?,
        customAnchorCertificates: [SecCertificate]? = nil
    ) -> CodeSignatureTrustDisposition {
        inspectCodeSignatureTrustEvaluation(
            from: codeSignatureData,
            sliceData: sliceData,
            customAnchorCertificates: customAnchorCertificates
        ).disposition
    }

    internal func inspectCodeSignatureTrustEvaluation(
        from codeSignatureData: Data?,
        sliceData: Data?,
        customAnchorCertificates: [SecCertificate]? = nil
    ) -> CodeSignatureTrustEvaluation {
        guard let rawCSData = codeSignatureData, !rawCSData.isEmpty else {
            return CodeSignatureTrustEvaluation(disposition: .absentOrSynthetic, signerKind: .none, leafSubjectSummary: nil)
        }
        guard rawCSData.count >= 12 else {
            return CodeSignatureTrustEvaluation(disposition: .adHocOrUnsigned, signerKind: .none, leafSubjectSummary: nil)
        }
        let data = rawCSData.startIndex == 0 ? rawCSData : Data(rawCSData)
        return data.withUnsafeBytes { buffer -> CodeSignatureTrustEvaluation in
            guard let magic = Self.readUInt32BE(from: buffer, at: 0),
                  magic == CSBlobConstants.superBlobMagic,
                  let lengthU32 = Self.readUInt32BE(from: buffer, at: 4) else {
                return CodeSignatureTrustEvaluation(disposition: .adHocOrUnsigned, signerKind: .none, leafSubjectSummary: nil)
            }
            let totalLength = Int(lengthU32)
            guard totalLength >= 12, totalLength <= buffer.count,
                  let entries = parseBlobIndicesStrict(from: buffer, totalLength: totalLength) else {
                return CodeSignatureTrustEvaluation(disposition: .adHocOrUnsigned, signerKind: .none, leafSubjectSummary: nil)
            }

            var sawCodeDirectorySlot = false
            var codeDirectoryEntries: [(slotType: UInt32, blob: Data)] = []
            var xmlEntitlementBlobs: [Data] = []
            var derEntitlementBlobs: [Data] = []
            var cmsPayloads: [Data] = []
            var sawCMSWrapperSlot = false
            var sawNonEntitlementSlot = false

            for entry in entries {
                let isCodeDir = entry.type == CSBlobConstants.slotCodeDirectory
                    || (entry.type >= CSBlobConstants.slotAlternateCodeDirectories && entry.type <= CSBlobConstants.slotAlternateCodeDirectories + 5)
                    || entry.magic == CSBlobConstants.codeDirectoryMagic
                if isCodeDir {
                    sawCodeDirectorySlot = true
                    sawNonEntitlementSlot = true
                    if entry.length >= 16,
                       let flags = Self.readUInt32BE(from: buffer, at: entry.offset + 12),
                       (flags & CSBlobConstants.csAdhocFlag) != 0 {
                        return CodeSignatureTrustEvaluation(disposition: .adHocOrUnsigned, signerKind: .none, leafSubjectSummary: nil)
                    }
                    let blobStart = entry.offset
                    let blobEnd = entry.offset + entry.length
                    guard blobStart >= 12, blobEnd <= totalLength, blobStart < blobEnd else {
                        return CodeSignatureTrustEvaluation(disposition: .adHocOrUnsigned, signerKind: .none, leafSubjectSummary: nil)
                    }
                    codeDirectoryEntries.append((entry.type, Data(buffer[blobStart..<blobEnd])))
                }
                let isXmlEnt = entry.type == CSBlobConstants.slotEntitlements || entry.magic == CSBlobConstants.entitlementXmlMagic
                if isXmlEnt {
                    let blobStart = entry.offset
                    let blobEnd = entry.offset + entry.length
                    if blobStart >= 12, blobEnd <= totalLength, blobStart < blobEnd {
                        xmlEntitlementBlobs.append(Data(buffer[blobStart..<blobEnd]))
                    }
                }
                let isDerEnt = entry.type == CSBlobConstants.slotDerEntitlements || entry.magic == CSBlobConstants.entitlementDerMagic
                if isDerEnt {
                    let blobStart = entry.offset
                    let blobEnd = entry.offset + entry.length
                    if blobStart >= 12, blobEnd <= totalLength, blobStart < blobEnd {
                        derEntitlementBlobs.append(Data(buffer[blobStart..<blobEnd]))
                    }
                }
                let isCMS = entry.type == CSBlobConstants.slotCMSSignature || entry.magic == CSBlobConstants.blobWrapperMagic
                if isCMS {
                    sawCMSWrapperSlot = true
                    sawNonEntitlementSlot = true
                    if entry.payloadLength > 0 {
                        let start = entry.payloadOffset
                        let end = start + entry.payloadLength
                        if start >= 0, end <= buffer.count, start < end {
                            cmsPayloads.append(Data(buffer[start..<end]))
                        }
                    }
                }
                if !isCodeDir && !isXmlEnt && !isDerEnt && !isCMS {
                    sawNonEntitlementSlot = true
                }
            }

            if cmsPayloads.isEmpty {
                if sawCodeDirectorySlot || sawCMSWrapperSlot || sawNonEntitlementSlot || entries.isEmpty {
                    return CodeSignatureTrustEvaluation(disposition: .adHocOrUnsigned, signerKind: .none, leafSubjectSummary: nil)
                }
                return CodeSignatureTrustEvaluation(disposition: .absentOrSynthetic, signerKind: .none, leafSubjectSummary: nil)
            }

            var verifiedKinds: [AppleVerifiedSignerKind] = []
            var verifiedSummary: String? = nil
            for cmsData in cmsPayloads {
                let cmsEval = Self.verifyAppleAppStoreCMSSignature(
                    cmsData,
                    codeDirectoryEntries: codeDirectoryEntries,
                    xmlEntitlementBlobs: xmlEntitlementBlobs,
                    derEntitlementBlobs: derEntitlementBlobs,
                    sliceData: sliceData,
                    customAnchorCertificates: customAnchorCertificates
                )
                if cmsEval.disposition != .appleAppStoreVerified {
                    return cmsEval
                }
                verifiedKinds.append(cmsEval.signerKind)
                if verifiedSummary == nil {
                    verifiedSummary = cmsEval.leafSubjectSummary
                }
            }
            let aggregatedKind: AppleVerifiedSignerKind
            if verifiedKinds.contains(.testFlight) {
                aggregatedKind = .testFlight
            } else if verifiedKinds.contains(.appStore) {
                aggregatedKind = .appStore
            } else if verifiedKinds.contains(.macSoftware) {
                aggregatedKind = .macSoftware
            } else {
                aggregatedKind = .none
            }
            return CodeSignatureTrustEvaluation(
                disposition: .appleAppStoreVerified,
                signerKind: aggregatedKind,
                leafSubjectSummary: verifiedSummary
            )
        }
    }

    /// Verifies that an `.app` bundle's `Info.plist` matches the main binary's signed `CodeDirectory`
    /// (`identOffset` bundle identifier and Special Slot `-1` `CSSLOT_INFOSLOT` hash when populated),
    /// defeating whole-binary transplantation of a benign App Store Mach-O into a spoofed `Info.plist` bundle.
    /// Returns `nil` when no `CodeDirectory` with populated binding slots is present (e.g. minimal synthetic test fixtures) or when binding succeeds;
    /// returns `.nonAppStoreSigner` when `Info.plist` diverges from the signed `CodeDirectory`.
    public func verifyBundleInfoPlistBinding(
        fromSlices slices: [MachOFile],
        infoPlistData: Data?,
        plistBundleId: String?
    ) -> CodeSignatureTrustDisposition? {
        let auditSlices = MachOParser.selectAuditSlices(from: slices)
        let normalizedPlistBid = plistBundleId?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let rebasedInfoData = infoPlistData.map { $0.startIndex == 0 ? $0 : Data($0) }

        for slice in auditSlices {
            let blobs = slice.allCodeSignatureData.isEmpty
                ? (slice.codeSignatureData.map { [$0] } ?? [])
                : slice.allCodeSignatureData
            for rawBlob in blobs {
                let data = rawBlob.startIndex == 0 ? rawBlob : Data(rawBlob)
                let mismatch: Bool = data.withUnsafeBytes { buffer in
                    guard buffer.count >= 12,
                          let magic = Self.readUInt32BE(from: buffer, at: 0),
                          magic == CSBlobConstants.superBlobMagic,
                          let lengthU32 = Self.readUInt32BE(from: buffer, at: 4) else {
                        return false
                    }
                    let totalLength = Int(lengthU32)
                    guard totalLength >= 12, totalLength <= buffer.count,
                          let entries = try? parseBlobIndices(from: buffer, totalLength: totalLength) else {
                        return false
                    }
                    for entry in entries {
                        let isCodeDir = entry.type == CSBlobConstants.slotCodeDirectory
                            || (entry.type >= CSBlobConstants.slotAlternateCodeDirectories && entry.type <= CSBlobConstants.slotAlternateCodeDirectories + 5)
                            || entry.magic == CSBlobConstants.codeDirectoryMagic
                        guard isCodeDir else { continue }
                        let start = entry.offset
                        let end = entry.offset + entry.length
                        guard start >= 12, end <= totalLength, start < end else { return true }
                        let cdBytes = Data(buffer[start..<end])
                        guard let parsedCD = Self.parseCodeDirectory(slotType: entry.type, blobData: cdBytes, allowAdHoc: true) else {
                            continue
                        }
                        if let cdIdent = parsedCD.identifier?.trimmingCharacters(in: .whitespacesAndNewlines),
                           !cdIdent.isEmpty {
                            if normalizedPlistBid.isEmpty {
                                // An explicit bundle Info.plist omitting CFBundleIdentifier cannot match a signed CodeDirectory identifier
                                if rebasedInfoData != nil {
                                    return true
                                }
                            } else if cdIdent.caseInsensitiveCompare(normalizedPlistBid) != .orderedSame {
                                return true
                            }
                        }
                        if let infoSlotHash = parsedCD.specialSlotHash(1),
                           !infoSlotHash.allSatisfy({ $0 == 0 }) {
                            guard let plistBytes = rebasedInfoData,
                                  let actualHash = Self.computeCodeDirectorySlotDigest(plistBytes, hashType: parsedCD.hashType),
                                  actualHash == infoSlotHash else {
                                return true
                            }
                        }
                    }
                    return false
                }
                if mismatch {
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/Info.plist Mismatch")
                }
            }
        }
        return nil
    }

    private static let highPriorityResourceExtensions: Set<String> = [
        "jsbundle", "hbc", "js", "mjs", "cjs", "html", "htm", "wasm",
        "dylib", "so", "py", "lua", "sh", "plist", "json"
    ]

    private static let unsealedForbiddenActiveExtensions: Set<String> = [
        "jsbundle", "hbc", "js", "mjs", "cjs", "html", "htm", "wasm",
        "dylib", "so", "py", "lua", "sh"
    ]

    internal struct ArchiveSealedRegularFile: Sendable {
        let declaredSize: Int
        let readData: @Sendable (_ maxBytes: Int) -> Data?
    }

    internal enum ArchiveSealedResourceEntry: Sendable {
        case symlink(target: String)
        case regular(files: [ArchiveSealedRegularFile])
    }

    internal struct ArchiveBundleResourceLookup: Sendable {
        let resolveEntry: @Sendable (_ relativePath: String) -> ArchiveSealedResourceEntry?
        let unextractedRegularPaths: @Sendable () -> [String]
        let allSymlinks: @Sendable () -> [String: String]
        let allRegularPaths: @Sendable () -> [String]
    }

    /// Verifies `CodeDirectory` Special Slot `-3` (`CSSLOT_RESOURCEDIR` -> `_CodeSignature/CodeResources`)
    /// and sealed resource file digests (`files2` / `files`) when Special Slot `-3` is populated,
    /// defeating hybrid tampering of React Native / WebView / Capacitor bundle assets (e.g. `main.jsbundle`, `index.html`)
    /// or deletion of `_CodeSignature/CodeResources` inside an otherwise untouched Apple-signed bundle.
    /// Returns `nil` when no non-zero Special Slot `-3` is present (e.g. synthetic test fixtures) or when verification succeeds.
    public func verifyBundleCodeResourcesSeal(
        fromSlices slices: [MachOFile],
        bundleURL: URL
    ) -> CodeSignatureTrustDisposition? {
        verifyBundleCodeResourcesSeal(fromSlices: slices, bundleURL: bundleURL, archiveLookup: nil)
    }

    internal func verifyBundleCodeResourcesSeal(
        fromSlices slices: [MachOFile],
        bundleURL: URL,
        archiveLookup: ArchiveBundleResourceLookup?
    ) -> CodeSignatureTrustDisposition? {
        verifyBundleCodeResourcesSealInternal(
            fromSlices: slices,
            bundleURL: bundleURL,
            archiveLookup: archiveLookup,
            depth: 0
        )
    }

    private func verifyBundleCodeResourcesSealInternal(
        fromSlices slices: [MachOFile],
        bundleURL: URL,
        archiveLookup: ArchiveBundleResourceLookup?,
        depth: Int
    ) -> CodeSignatureTrustDisposition? {
        let auditSlices = MachOParser.selectAuditSlices(from: slices)
        var requiredSlot3Specs: [(hashType: UInt8, expectedDigest: Data)] = []

        for slice in auditSlices {
            let blobs = slice.allCodeSignatureData.isEmpty
                ? (slice.codeSignatureData.map { [$0] } ?? [])
                : slice.allCodeSignatureData
            for rawBlob in blobs {
                let data = rawBlob.startIndex == 0 ? rawBlob : Data(rawBlob)
                data.withUnsafeBytes { buffer in
                    guard buffer.count >= 12,
                          let magic = Self.readUInt32BE(from: buffer, at: 0),
                          magic == CSBlobConstants.superBlobMagic,
                          let lengthU32 = Self.readUInt32BE(from: buffer, at: 4) else {
                        return
                    }
                    let totalLength = Int(lengthU32)
                    guard totalLength >= 12, totalLength <= buffer.count,
                          let entries = try? parseBlobIndices(from: buffer, totalLength: totalLength) else {
                        return
                    }
                    for entry in entries {
                        let isCodeDir = entry.type == CSBlobConstants.slotCodeDirectory
                            || (entry.type >= CSBlobConstants.slotAlternateCodeDirectories && entry.type <= CSBlobConstants.slotAlternateCodeDirectories + 5)
                            || entry.magic == CSBlobConstants.codeDirectoryMagic
                        guard isCodeDir else { continue }
                        let start = entry.offset
                        let end = entry.offset + entry.length
                        guard start >= 12, end <= totalLength, start < end else { continue }
                        let cdBytes = Data(buffer[start..<end])
                        guard let parsedCD = Self.parseCodeDirectory(slotType: entry.type, blobData: cdBytes, allowAdHoc: true),
                              let slot3 = parsedCD.specialSlotHash(3),
                              !slot3.allSatisfy({ $0 == 0 }) else {
                            continue
                        }
                        requiredSlot3Specs.append((parsedCD.hashType, slot3))
                    }
                }
            }
        }

        guard !requiredSlot3Specs.isEmpty else {
            return nil
        }

        let resolvedBundlePath = IPAPackageScanner.lexicalStandardizedPath(bundleURL.resolvingSymlinksInPath().path)
        let resolvedBundleURL = URL(fileURLWithPath: resolvedBundlePath)
        let bundlePrefix = IPAPackageScanner.lexicalStandardizedPrefix(resolvedBundlePath)

        let layoutCandidates: [(codeResRel: String, resRootRel: String)] = [
            ("_CodeSignature/CodeResources", ""),
            ("Contents/_CodeSignature/CodeResources", "Contents"),
            ("Versions/Current/_CodeSignature/CodeResources", "Versions/Current"),
            ("Versions/A/_CodeSignature/CodeResources", "Versions/A")
        ]

        var matchedCodeResourcesData: Data? = nil
        var resourceRootURL: URL = resolvedBundleURL
        var matchedResRootRel = ""

        for cand in layoutCandidates {
            let candidateURL = resolvedBundleURL.appendingPathComponent(cand.codeResRel)
            var st = stat()
            if lstat(candidateURL.path, &st) == 0 {
                // Reject symlinked CodeResources files; allow Versions/Current directory symlink inside bundle
                if (st.st_mode & S_IFMT) == S_IFLNK {
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
                let resolvedCR = candidateURL.resolvingSymlinksInPath().standardizedFileURL
                let resolvedCRPath = IPAPackageScanner.lexicalStandardizedPath(resolvedCR.path)
                guard resolvedCRPath.hasPrefix(bundlePrefix),
                      let crData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: resolvedCR, maxBytes: 32 * 1024 * 1024) else {
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
                matchedCodeResourcesData = crData
                matchedResRootRel = cand.resRootRel
                let rawRootURL = cand.resRootRel.isEmpty
                    ? resolvedBundleURL
                    : resolvedBundleURL.appendingPathComponent(cand.resRootRel).resolvingSymlinksInPath().standardizedFileURL
                resourceRootURL = URL(fileURLWithPath: IPAPackageScanner.lexicalStandardizedPath(rawRootURL.path))
                break
            } else if let lookup = archiveLookup,
                      let archiveCR = lookup.resolveEntry(cand.codeResRel) {
                switch archiveCR {
                case .symlink:
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                case .regular(let files):
                    guard files.count == 1,
                          files[0].declaredSize <= 32 * 1024 * 1024,
                          let crData = files[0].readData(32 * 1024 * 1024) else {
                        return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                    }
                    matchedCodeResourcesData = crData
                    matchedResRootRel = cand.resRootRel
                    resourceRootURL = cand.resRootRel.isEmpty
                        ? resolvedBundleURL
                        : resolvedBundleURL.appendingPathComponent(cand.resRootRel)
                }
                if matchedCodeResourcesData != nil {
                    break
                }
            }
        }

        guard let codeResourcesData = matchedCodeResourcesData else {
            return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
        }

        for spec in requiredSlot3Specs {
            guard let actualDigest = Self.computeCodeDirectorySlotDigest(codeResourcesData, hashType: spec.hashType),
                  actualDigest == spec.expectedDigest else {
                return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
            }
        }

        guard let crPlist = (try? PropertyListSerialization.propertyList(from: codeResourcesData, options: [], format: nil)) as? [String: Any] else {
            return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
        }

        let resourceRootStd = IPAPackageScanner.lexicalStandardizedPath(resourceRootURL.path)
        guard resourceRootStd == resolvedBundlePath || resourceRootStd.hasPrefix(bundlePrefix) else {
            return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
        }
        let resourcePrefix = IPAPackageScanner.lexicalStandardizedPrefix(resourceRootStd)

        let files2Dict = crPlist["files2"] as? [String: Any]
        let files1Dict = crPlist["files"] as? [String: Any]
        guard files2Dict != nil || files1Dict != nil else {
            return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
        }

        let primaryMap: [String: Any]
        if let f2 = files2Dict, !f2.isEmpty {
            primaryMap = f2
        } else if let f1 = files1Dict, !f1.isEmpty {
            primaryMap = f1
        } else {
            primaryMap = files2Dict ?? files1Dict ?? [:]
        }
        let orderedKeys = primaryMap.keys.sorted { lhs, rhs in
            let lExt = (lhs as NSString).pathExtension.lowercased()
            let rExt = (rhs as NSString).pathExtension.lowercased()
            let lPrio = Self.highPriorityResourceExtensions.contains(lExt)
            let rPrio = Self.highPriorityResourceExtensions.contains(rExt)
            if lPrio != rPrio { return lPrio }
            return lhs < rhs
        }

        let maxSingleFileBytes = 32 * 1024 * 1024
        let maxTotalVerifyBytes = 64 * 1024 * 1024
        var totalVerifiedBytes = 0

        for relKey in orderedKeys {
            guard !relKey.isEmpty,
                  !relKey.hasPrefix("/"),
                  !relKey.split(separator: "/").contains(".."),
                  let rawEntry = primaryMap[relKey] else {
                continue
            }

            var isOptional = false
            var expectedSymlink: String? = nil
            var expectedSHA256: Data? = nil
            var expectedSHA1: Data? = nil

            if let rawData = rawEntry as? Data {
                if rawData.count == 32 {
                    expectedSHA256 = rawData
                } else if rawData.count == 20 {
                    expectedSHA1 = rawData
                } else {
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
            } else if let entryDict = rawEntry as? [String: Any] {
                // Nested Mach-O / sub-bundle entries (`cdhash` / `nested` / `omit`) are verified via Mach-O CodeDirectory inspection
                if (entryDict["nested"] as? Bool) == true
                    || (entryDict["omit"] as? Bool) == true
                    || entryDict["cdhash"] != nil {
                    continue
                }
                isOptional = (entryDict["optional"] as? Bool) == true
                expectedSymlink = entryDict["symlink"] as? String
                if let h2 = entryDict["hash2"] as? Data {
                    expectedSHA256 = h2
                }
                if let h1 = entryDict["hash"] as? Data {
                    expectedSHA1 = h1
                }
                if expectedSymlink == nil && expectedSHA256 == nil && expectedSHA1 == nil {
                    if isOptional { continue }
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
            } else {
                return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
            }

            let archiveRelKey = matchedResRootRel.isEmpty ? relKey : "\(matchedResRootRel)/\(relKey)"
            let targetURL = resourceRootURL.appendingPathComponent(relKey)
            var lst = stat()
            let diskExists = (lstat(targetURL.path, &lst) == 0)

            if let expLink = expectedSymlink {
                if diskExists && (lst.st_mode & S_IFMT) == S_IFLNK {
                    var linkBuf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
                    let linkLen = readlink(targetURL.path, &linkBuf, Int(PATH_MAX))
                    guard linkLen >= 0 else {
                        return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                    }
                    let actualLink = String(cString: linkBuf)
                    if actualLink != expLink {
                        return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                    }
                    continue
                } else if let lookup = archiveLookup,
                          case .symlink(let archiveTarget) = lookup.resolveEntry(archiveRelKey) {
                    if archiveTarget != expLink {
                        return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                    }
                    continue
                } else {
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
            }

            if diskExists {
                let mode = lst.st_mode & S_IFMT
                guard mode == S_IFREG else {
                    if isOptional { continue }
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
                let resolvedTarget = targetURL.resolvingSymlinksInPath().standardizedFileURL
                let resolvedTargetStd = IPAPackageScanner.lexicalStandardizedPath(resolvedTarget.path)
                guard resolvedTargetStd.hasPrefix(bundlePrefix) && resolvedTargetStd.hasPrefix(resourcePrefix) else {
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }

                let fileSize = Int(max(0, lst.st_size))
                guard fileSize <= maxSingleFileBytes, totalVerifiedBytes + fileSize <= maxTotalVerifyBytes else {
                    continue
                }
                guard let fileBytes = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: resolvedTarget, maxBytes: maxSingleFileBytes) else {
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
                totalVerifiedBytes += fileBytes.count

                if let sha256Expected = expectedSHA256 {
                    if Data(SHA256.hash(data: fileBytes)) != sha256Expected {
                        return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                    }
                } else if let sha1Expected = expectedSHA1 {
                    if Data(Insecure.SHA1.hash(data: fileBytes)) != sha1Expected {
                        return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                    }
                }
            } else if let lookup = archiveLookup {
                guard let resolvedArchive = lookup.resolveEntry(archiveRelKey) else {
                    if isOptional { continue }
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
                switch resolvedArchive {
                case .symlink:
                    if isOptional { continue }
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                case .regular(let fileCopies):
                    guard !fileCopies.isEmpty else {
                        if isOptional { continue }
                        return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                    }
                    for copy in fileCopies {
                        let fileSize = max(0, copy.declaredSize)
                        guard fileSize <= maxSingleFileBytes, totalVerifiedBytes + fileSize <= maxTotalVerifyBytes else {
                            continue
                        }
                        guard let fileBytes = copy.readData(maxSingleFileBytes) else {
                            return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                        }
                        totalVerifiedBytes += fileBytes.count
                        if let sha256Expected = expectedSHA256 {
                            if Data(SHA256.hash(data: fileBytes)) != sha256Expected {
                                return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                            }
                        } else if let sha1Expected = expectedSHA1 {
                            if Data(Insecure.SHA1.hash(data: fileBytes)) != sha1Expected {
                                return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                            }
                        }
                    }
                }
            } else {
                if isOptional { continue }
                return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
            }
        }

        // Reject unsealed script/web/dylib files injected into ANY bundle layout outside sealed CodeResources keys
        var rawSealedRelPaths = Set(files2Dict?.keys ?? [String: Any]().keys)
        if let f1 = files1Dict {
            rawSealedRelPaths.formUnion(f1.keys)
        }
        var verifiedVersionsTarget: String? = nil
        if let lookup = archiveLookup {
            if case .symlink(let rawTarget)? = lookup.resolveEntry("Versions/Current") {
                if lookup.unextractedRegularPaths().contains(where: { $0.hasPrefix("Versions/Current/") }) {
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
                let comps = rawTarget.split(separator: "/").filter { !$0.isEmpty && $0 != "." }.map(String.init)
                if !rawTarget.hasPrefix("/"),
                   !rawTarget.contains("\\"),
                   !rawTarget.contains("\0"),
                   comps.count == 1,
                   comps[0] != ".." {
                    verifiedVersionsTarget = "Versions/\(comps[0])"
                }
            }
        } else {
            let vcURL = resolvedBundleURL.appendingPathComponent("Versions/Current")
            var vcSt = stat()
            if lstat(vcURL.path, &vcSt) == 0, (vcSt.st_mode & S_IFMT) == S_IFLNK {
                let versionsPrefix = IPAPackageScanner.lexicalStandardizedPrefix(resolvedBundleURL.appendingPathComponent("Versions").path)
                let resolvedVC = vcURL.resolvingSymlinksInPath().standardizedFileURL
                let resolvedVCStd = IPAPackageScanner.lexicalStandardizedPath(resolvedVC.path)
                var targetSt = stat()
                if resolvedVCStd.hasPrefix(versionsPrefix),
                   lstat(resolvedVCStd, &targetSt) == 0,
                   (targetSt.st_mode & S_IFMT) == S_IFDIR,
                   IPAPackageScanner.lexicalStandardizedPath(resolvedVC.deletingLastPathComponent().path) == IPAPackageScanner.lexicalStandardizedPath(resolvedBundleURL.appendingPathComponent("Versions").path),
                   !resolvedVC.lastPathComponent.isEmpty {
                    verifiedVersionsTarget = "Versions/\(resolvedVC.lastPathComponent)"
                }
            }
        }

        var sealedPrefixes: [String] = [matchedResRootRel]
        if matchedResRootRel == "Versions/Current", let verTarget = verifiedVersionsTarget {
            if !sealedPrefixes.contains(verTarget) {
                sealedPrefixes.append(verTarget)
            }
        } else if matchedResRootRel.hasPrefix("Versions/"), let verTarget = verifiedVersionsTarget, verTarget == matchedResRootRel {
            if !sealedPrefixes.contains("Versions/Current") {
                sealedPrefixes.append("Versions/Current")
            }
        }

        var sealedRelPaths: Set<String> = []
        sealedRelPaths.reserveCapacity(rawSealedRelPaths.count * sealedPrefixes.count)
        for pfx in sealedPrefixes {
            if pfx.isEmpty {
                sealedRelPaths.formUnion(rawSealedRelPaths)
            } else {
                for key in rawSealedRelPaths {
                    sealedRelPaths.insert("\(pfx)/\(key)")
                }
            }
        }

        let isVersionedLayout = matchedResRootRel == "Versions/Current" || matchedResRootRel.hasPrefix("Versions/")
        var archiveDirSymlinkAliases: [String: String] = [:]
        if let lookup = archiveLookup {
            let allSymlinks = lookup.allSymlinks()
            let allRegulars = lookup.allRegularPaths()
            var regularExactSet: Set<String> = []
            var regularAncestorPrefixes: Set<String> = []
            regularExactSet.reserveCapacity(allRegulars.count)
            regularAncestorPrefixes.reserveCapacity(allRegulars.count * 2)
            for reg in allRegulars {
                regularExactSet.insert(reg)
                var slashIdx = reg.startIndex
                while let nextSlash = reg[slashIdx...].firstIndex(of: "/") {
                    regularAncestorPrefixes.insert(String(reg[..<nextSlash]))
                    slashIdx = reg.index(after: nextSlash)
                }
                regularAncestorPrefixes.insert(reg)
            }

            func resolveArchiveDirSymlink(_ startRel: String) -> String? {
                var comps = startRel.split(separator: "/").filter { !$0.isEmpty && $0 != "." }.map(String.init)
                guard !comps.isEmpty, !comps.contains("..") else { return nil }
                var visited: Set<String> = []
                var hops = 0
                while hops < 8 {
                    var matchedEndIdx: Int? = nil
                    var matchedTarget: String? = nil
                    for endIdx in stride(from: comps.count, through: 1, by: -1) {
                        let key = comps[0..<endIdx].joined(separator: "/")
                        if let t = allSymlinks[key] {
                            if regularAncestorPrefixes.contains(key) {
                                return nil
                            }
                            matchedEndIdx = endIdx
                            matchedTarget = t
                            break
                        }
                    }
                    guard let endIdx = matchedEndIdx, let rawTarget = matchedTarget else {
                        break
                    }
                    let key = comps[0..<endIdx].joined(separator: "/")
                    guard visited.insert(key).inserted else { return nil }
                    guard !rawTarget.isEmpty,
                          !rawTarget.hasPrefix("/"),
                          !rawTarget.contains("\\"),
                          !rawTarget.contains("\0") else {
                        return nil
                    }
                    var resolvedBase = Array(comps[0..<(endIdx - 1)])
                    for tc in rawTarget.split(separator: "/").map(String.init) {
                        if tc.isEmpty || tc == "." { continue }
                        if tc == ".." {
                            guard !resolvedBase.isEmpty else { return nil }
                            resolvedBase.removeLast()
                        } else {
                            resolvedBase.append(tc)
                        }
                    }
                    guard !resolvedBase.isEmpty else { return nil }
                    comps = resolvedBase + Array(comps[endIdx...])
                    hops += 1
                }
                for endIdx in stride(from: comps.count, through: 1, by: -1) {
                    let key = comps[0..<endIdx].joined(separator: "/")
                    if allSymlinks[key] != nil { return nil }
                }
                let finalRel = comps.joined(separator: "/")
                guard !regularExactSet.contains(finalRel) else { return nil }
                guard sealedPrefixes.contains(where: { finalRel == $0 || finalRel.hasPrefix($0 + "/") }) else {
                    return nil
                }
                return finalRel
            }

            for (linkRel, _) in allSymlinks {
                if regularAncestorPrefixes.contains(linkRel) {
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
                if isVersionedLayout, let resolvedTarget = resolveArchiveDirSymlink(linkRel) {
                    archiveDirSymlinkAliases[linkRel] = resolvedTarget
                }
            }
        }

        var diskDirSymlinkCache: [String: String] = [:]
        var diskDirSymlinkMisses: Set<String> = []
        func resolveVerifiedDiskDirSymlink(_ linkRel: String) -> String? {
            if let hit = diskDirSymlinkCache[linkRel] {
                return hit
            }
            if diskDirSymlinkMisses.contains(linkRel) {
                return nil
            }
            let startURL = resolvedBundleURL.appendingPathComponent(linkRel)
            var lst = stat()
            guard lstat(startURL.path, &lst) == 0, (lst.st_mode & S_IFMT) == S_IFLNK else {
                diskDirSymlinkMisses.insert(linkRel)
                return nil
            }
            var comps = linkRel.split(separator: "/").filter { !$0.isEmpty && $0 != "." }.map(String.init)
            guard !comps.isEmpty, !comps.contains("..") else {
                diskDirSymlinkMisses.insert(linkRel)
                return nil
            }
            var visited: Set<String> = []
            var hops = 0
            while hops < 8 {
                var foundSymlinkIdx: Int? = nil
                for endIdx in 1...comps.count {
                    let partialRel = comps[0..<endIdx].joined(separator: "/")
                    let partialURL = resolvedBundleURL.appendingPathComponent(partialRel)
                    var pst = stat()
                    guard lstat(partialURL.path, &pst) == 0 else {
                        diskDirSymlinkMisses.insert(linkRel)
                        return nil
                    }
                    if (pst.st_mode & S_IFMT) == S_IFLNK {
                        foundSymlinkIdx = endIdx
                        break
                    } else if endIdx < comps.count && (pst.st_mode & S_IFMT) != S_IFDIR {
                        diskDirSymlinkMisses.insert(linkRel)
                        return nil
                    }
                }
                guard let endIdx = foundSymlinkIdx else {
                    break
                }
                let partialRel = comps[0..<endIdx].joined(separator: "/")
                guard visited.insert(partialRel).inserted else {
                    diskDirSymlinkMisses.insert(linkRel)
                    return nil
                }
                let partialURL = resolvedBundleURL.appendingPathComponent(partialRel)
                var linkBuf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
                let linkLen = readlink(partialURL.path, &linkBuf, Int(PATH_MAX))
                guard linkLen > 0 else {
                    diskDirSymlinkMisses.insert(linkRel)
                    return nil
                }
                let rawTarget = String(cString: linkBuf)
                guard !rawTarget.isEmpty,
                      !rawTarget.hasPrefix("/"),
                      !rawTarget.contains("\\"),
                      !rawTarget.contains("\0") else {
                    diskDirSymlinkMisses.insert(linkRel)
                    return nil
                }
                var resolvedBase = Array(comps[0..<(endIdx - 1)])
                for tc in rawTarget.split(separator: "/").map(String.init) {
                    if tc.isEmpty || tc == "." { continue }
                    if tc == ".." {
                        guard !resolvedBase.isEmpty else {
                            diskDirSymlinkMisses.insert(linkRel)
                            return nil
                        }
                        resolvedBase.removeLast()
                    } else {
                        resolvedBase.append(tc)
                    }
                }
                guard !resolvedBase.isEmpty else {
                    diskDirSymlinkMisses.insert(linkRel)
                    return nil
                }
                comps = resolvedBase + Array(comps[endIdx...])
                hops += 1
            }
            for endIdx in 1...comps.count {
                let partialRel = comps[0..<endIdx].joined(separator: "/")
                let partialURL = resolvedBundleURL.appendingPathComponent(partialRel)
                var pst = stat()
                guard lstat(partialURL.path, &pst) == 0 else {
                    diskDirSymlinkMisses.insert(linkRel)
                    return nil
                }
                if (pst.st_mode & S_IFMT) == S_IFLNK {
                    diskDirSymlinkMisses.insert(linkRel)
                    return nil
                }
            }
            let finalRel = comps.joined(separator: "/")
            let finalURL = resolvedBundleURL.appendingPathComponent(finalRel)
            var fst = stat()
            guard lstat(finalURL.path, &fst) == 0, (fst.st_mode & S_IFMT) == S_IFDIR else {
                diskDirSymlinkMisses.insert(linkRel)
                return nil
            }
            let finalStd = IPAPackageScanner.lexicalStandardizedPath(finalURL.resolvingSymlinksInPath().standardizedFileURL.path)
            guard finalStd.hasPrefix(bundlePrefix),
                  sealedPrefixes.contains(where: { finalRel == $0 || finalRel.hasPrefix($0 + "/") }) else {
                diskDirSymlinkMisses.insert(linkRel)
                return nil
            }
            diskDirSymlinkCache[linkRel] = finalRel
            return finalRel
        }

        func resolveVersionedSymlinkAliasedRelPath(_ relPath: String, parts: [String]) -> String? {
            guard isVersionedLayout, parts.count >= 2 else { return nil }
            var prefix = ""
            for idx in 0..<(parts.count - 1) {
                prefix = prefix.isEmpty ? parts[idx] : "\(prefix)/\(parts[idx])"
                let targetBase: String?
                if archiveLookup != nil {
                    targetBase = archiveDirSymlinkAliases[prefix]
                } else {
                    targetBase = resolveVerifiedDiskDirSymlink(prefix)
                }
                if let resolvedBase = targetBase {
                    let subRel = parts[(idx + 1)...].joined(separator: "/")
                    return "\(resolvedBase)/\(subRel)"
                }
            }
            return nil
        }

        var dummyEscapes: [String] = []
        let candidates = IPAPackageScanner.enumerateCandidateFiles(
            in: resolvedBundleURL,
            bundleRootResolvedPrefix: bundlePrefix,
            escapingSymlinks: &dummyEscapes,
            bundleRootURL: resolvedBundleURL
        )
        if !dummyEscapes.isEmpty {
            return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
        }
        let nestedBundleExts: Set<String> = ["framework", "appex", "xpc", "app"]
        let systemExemptTopDirs: Set<String> = ["_codesignature", "sc_info", "_masreceipt", "storekit"]
        var nestedBundleSealCache: [String: Bool] = [:]

            func isNestedBundleSelfSealed(_ nestedRel: String) -> Bool {
                if let cached = nestedBundleSealCache[nestedRel] {
                    return cached
                }
                guard depth < 4 else {
                    nestedBundleSealCache[nestedRel] = false
                    return false
                }

                let nestedDiskURL = resolvedBundleURL.appendingPathComponent(nestedRel)
                let resolvedNestedURL: URL
                var nst = stat()
                let diskExists = (lstat(nestedDiskURL.path, &nst) == 0)
                if diskExists {
                    let mode = nst.st_mode & S_IFMT
                    guard mode == S_IFDIR || mode == S_IFLNK else {
                        nestedBundleSealCache[nestedRel] = false
                        return false
                    }
                    let candResolved = nestedDiskURL.resolvingSymlinksInPath().standardizedFileURL
                    let candStd = IPAPackageScanner.lexicalStandardizedPath(candResolved.path)
                    guard candStd.hasPrefix(bundlePrefix) else {
                        nestedBundleSealCache[nestedRel] = false
                        return false
                    }
                    var rnst = stat()
                    guard lstat(candResolved.path, &rnst) == 0,
                          (rnst.st_mode & S_IFMT) == S_IFDIR else {
                        nestedBundleSealCache[nestedRel] = false
                        return false
                    }
                    resolvedNestedURL = URL(fileURLWithPath: candStd)
                } else {
                    resolvedNestedURL = nestedDiskURL
                }
                let nestedDiskPrefix = IPAPackageScanner.lexicalStandardizedPrefix(resolvedNestedURL.path)

                let isArchiveSymlink: Bool
                if let lookup = archiveLookup,
                   case .symlink? = lookup.resolveEntry(nestedRel) {
                    isArchiveSymlink = true
                    if lookup.unextractedRegularPaths().contains(where: { $0.hasPrefix(nestedRel + "/") }) {
                        nestedBundleSealCache[nestedRel] = false
                        return false
                    }
                } else {
                    isArchiveSymlink = false
                }

                // 1. Nested bundle MUST actually possess its own CodeResources file (no-follow regular file or archive regular entry)
                var foundNestedCR: Data? = nil
                for cand in layoutCandidates {
                    if diskExists {
                        let crURL = resolvedNestedURL.appendingPathComponent(cand.codeResRel)
                        var crSt = stat()
                        if lstat(crURL.path, &crSt) == 0 {
                            if (crSt.st_mode & S_IFMT) == S_IFLNK {
                                nestedBundleSealCache[nestedRel] = false
                                return false
                            }
                            let resCR = crURL.resolvingSymlinksInPath().standardizedFileURL
                            let resCRStd = IPAPackageScanner.lexicalStandardizedPath(resCR.path)
                            if resCRStd.hasPrefix(nestedDiskPrefix),
                               let crBytes = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: resCR, maxBytes: 32 * 1024 * 1024) {
                                foundNestedCR = crBytes
                                break
                            }
                            nestedBundleSealCache[nestedRel] = false
                            return false
                        }
                    }
                    if let lookup = archiveLookup,
                       let archiveCR = lookup.resolveEntry("\(nestedRel)/\(cand.codeResRel)") {
                        switch archiveCR {
                        case .symlink:
                            nestedBundleSealCache[nestedRel] = false
                            return false
                        case .regular(let files):
                            if files.count == 1,
                               files[0].declaredSize <= 32 * 1024 * 1024,
                               let crBytes = files[0].readData(32 * 1024 * 1024) {
                                foundNestedCR = crBytes
                            } else {
                                nestedBundleSealCache[nestedRel] = false
                                return false
                            }
                        }
                        if foundNestedCR != nil {
                            break
                        }
                    }
                }

                guard let nestedCRData = foundNestedCR, diskExists else {
                    nestedBundleSealCache[nestedRel] = false
                    return false
                }

                // 2. Verify at least one Mach-O executable in the nested bundle has non-zero Special Slot -3 binding that CodeResources
                //    AND (when not an archive symlink) verify the nested bundle's own CodeResources seal recursively.
                let nestedArchivePrefix = nestedRel + "/"
                let nestedArchiveLookup: ArchiveBundleResourceLookup? = archiveLookup.map { parentLookup in
                    ArchiveBundleResourceLookup(
                        resolveEntry: { rel in
                            parentLookup.resolveEntry(nestedArchivePrefix + rel)
                        },
                        unextractedRegularPaths: {
                            parentLookup.unextractedRegularPaths().compactMap { p in
                                p.hasPrefix(nestedArchivePrefix) ? String(p.dropFirst(nestedArchivePrefix.count)) : nil
                            }
                        },
                        allSymlinks: {
                            var scoped: [String: String] = [:]
                            for (k, v) in parentLookup.allSymlinks() where k.hasPrefix(nestedArchivePrefix) {
                                let sub = String(k.dropFirst(nestedArchivePrefix.count))
                                if !sub.isEmpty { scoped[sub] = v }
                            }
                            return scoped
                        },
                        allRegularPaths: {
                            parentLookup.allRegularPaths().compactMap { p in
                                p.hasPrefix(nestedArchivePrefix) ? String(p.dropFirst(nestedArchivePrefix.count)) : nil
                            }
                        }
                    )
                }

                let binDirs = [
                    resolvedNestedURL,
                    resolvedNestedURL.appendingPathComponent("Contents/MacOS"),
                    resolvedNestedURL.appendingPathComponent("Versions/Current"),
                    resolvedNestedURL.appendingPathComponent("Versions/A")
                ]
                var checkedFiles = 0
                var probedRegularFiles = 0
                var visitedBinDirs: Set<String> = []
                for dirURL in binDirs where checkedFiles < 32 && probedRegularFiles < 4096 {
                    var dst = stat()
                    guard lstat(dirURL.path, &dst) == 0 else { continue }
                    let resolvedDir: URL
                    if (dst.st_mode & S_IFMT) == S_IFLNK {
                        let rd = dirURL.resolvingSymlinksInPath().standardizedFileURL
                        let rdStd = IPAPackageScanner.lexicalStandardizedPath(rd.path)
                        guard rdStd.hasPrefix(nestedDiskPrefix) else { continue }
                        var rdst = stat()
                        guard lstat(rd.path, &rdst) == 0, (rdst.st_mode & S_IFMT) == S_IFDIR else { continue }
                        resolvedDir = rd
                    } else if (dst.st_mode & S_IFMT) == S_IFDIR {
                        resolvedDir = dirURL
                    } else {
                        continue
                    }
                    let resolvedDirStd = IPAPackageScanner.lexicalStandardizedPath(resolvedDir.path)
                    guard visitedBinDirs.insert(resolvedDirStd).inserted else { continue }

                    guard let dp = opendir(resolvedDir.path) else { continue }
                    var fileNames: [String] = []
                    while let ent = readdir(dp) {
                        let name = withUnsafeBytes(of: ent.pointee.d_name) { raw -> String in
                            String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                        }
                        if name != "." && name != ".." && !name.hasPrefix("._") {
                            fileNames.append(name)
                        }
                    }
                    closedir(dp)
                    fileNames.sort()

                    for name in fileNames where checkedFiles < 32 && probedRegularFiles < 4096 {
                        let fileURL = resolvedDir.appendingPathComponent(name)
                        var fst = stat()
                        guard lstat(fileURL.path, &fst) == 0,
                              (fst.st_mode & S_IFMT) == S_IFREG else {
                            continue
                        }
                        probedRegularFiles += 1
                        let (pfx, fsz) = IPAPackageScanner.readMachOHeaderPrefix(of: fileURL)
                        guard IPAPackageScanner.isMachOOrFatMagic(pfx, fileSize: fsz) else {
                            continue
                        }
                        checkedFiles += 1
                        guard let binData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: fileURL, maxBytes: 128 * 1024 * 1024),
                              let binSlices = try? MachOParser.shared.parseAllSlices(data: binData),
                              !binSlices.isEmpty else {
                            continue
                        }

                        var hasMatchingSlot3 = false
                        for slice in MachOParser.selectAuditSlices(from: binSlices) {
                            let blobs = slice.allCodeSignatureData.isEmpty
                                ? (slice.codeSignatureData.map { [$0] } ?? [])
                                : slice.allCodeSignatureData
                            for rawBlob in blobs {
                                let bd = rawBlob.startIndex == 0 ? rawBlob : Data(rawBlob)
                                bd.withUnsafeBytes { buf in
                                    guard buf.count >= 12,
                                          let magic = Self.readUInt32BE(from: buf, at: 0),
                                          magic == CSBlobConstants.superBlobMagic,
                                          let len32 = Self.readUInt32BE(from: buf, at: 4) else { return }
                                    let tLen = Int(len32)
                                    guard tLen >= 12, tLen <= buf.count,
                                          let entries = try? parseBlobIndices(from: buf, totalLength: tLen) else { return }
                                    for entry in entries {
                                        let isCD = entry.type == CSBlobConstants.slotCodeDirectory
                                            || (entry.type >= CSBlobConstants.slotAlternateCodeDirectories && entry.type <= CSBlobConstants.slotAlternateCodeDirectories + 5)
                                            || entry.magic == CSBlobConstants.codeDirectoryMagic
                                        guard isCD, entry.offset >= 12, entry.offset + entry.length <= tLen, entry.length > 0 else { continue }
                                        if let parsedCD = Self.parseCodeDirectory(slotType: entry.type, blobData: Data(buf[entry.offset..<(entry.offset + entry.length)]), allowAdHoc: true),
                                           let slot3 = parsedCD.specialSlotHash(3),
                                           !slot3.allSatisfy({ $0 == 0 }),
                                           let digest = Self.computeCodeDirectorySlotDigest(nestedCRData, hashType: parsedCD.hashType),
                                           digest == slot3 {
                                            hasMatchingSlot3 = true
                                            return
                                        }
                                    }
                                }
                                if hasMatchingSlot3 { break }
                            }
                            if hasMatchingSlot3 { break }
                        }

                        if hasMatchingSlot3 {
                            if isArchiveSymlink {
                                nestedBundleSealCache[nestedRel] = true
                                return true
                            }
                            let subSealFailure = verifyBundleCodeResourcesSealInternal(
                                fromSlices: binSlices,
                                bundleURL: resolvedNestedURL,
                                archiveLookup: nestedArchiveLookup,
                                depth: depth + 1
                            )
                            let ok = (subSealFailure == nil)
                            nestedBundleSealCache[nestedRel] = ok
                            return ok
                        }
                    }
                }

                nestedBundleSealCache[nestedRel] = false
                return false
            }

            func isForbiddenUnsealed(relPath: String, pathExt: String) -> Bool {
                let parts = relPath.split(separator: "/").map(String.init)
                guard let firstComp = parts.first else { return false }
                if systemExemptTopDirs.contains(firstComp.lowercased()) {
                    return false
                }
                if let nestedIdx = parts.dropLast().indices.first(where: { nestedBundleExts.contains((parts[$0] as NSString).pathExtension.lowercased()) }) {
                    let nestedRel = parts[0...nestedIdx].joined(separator: "/")
                    if isNestedBundleSelfSealed(nestedRel) {
                        return false
                    }
                }
                guard Self.unsealedForbiddenActiveExtensions.contains(pathExt) else {
                    return false
                }
                if sealedRelPaths.contains(relPath) {
                    return false
                }
                if let aliasedRel = resolveVersionedSymlinkAliasedRelPath(relPath, parts: parts),
                   sealedRelPaths.contains(aliasedRel) {
                    return false
                }
                return true
            }

        for cand in candidates {
            let rel = IPAPackageScanner.bundleRelativePath(of: cand.logicalURL, in: resolvedBundleURL)
            let ext = cand.logicalURL.pathExtension.lowercased()
            if isForbiddenUnsealed(relPath: rel, pathExt: ext) {
                return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
            }
        }

        if let lookup = archiveLookup {
            for rel in lookup.unextractedRegularPaths() {
                let ext = (rel as NSString).pathExtension.lowercased()
                if isForbiddenUnsealed(relPath: rel, pathExt: ext) {
                    return .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
                }
            }
        }

        return nil
    }

    private static func parseCodeDirectory(slotType: UInt32, blobData rawData: Data, allowAdHoc: Bool = false) -> ParsedCodeDirectory? {
        let data = rawData.startIndex == 0 ? rawData : Data(rawData)
        guard data.count >= 44 else { return nil }
        return data.withUnsafeBytes { buf -> ParsedCodeDirectory? in
            guard let magic = readUInt32BE(from: buf, at: 0),
                  magic == CSBlobConstants.codeDirectoryMagic,
                  let lenU32 = readUInt32BE(from: buf, at: 4),
                  Int(lenU32) == data.count,
                  let version = readUInt32BE(from: buf, at: 8),
                  let flags = readUInt32BE(from: buf, at: 12),
                  (allowAdHoc || (flags & CSBlobConstants.csAdhocFlag) == 0),
                  let hashOffU32 = readUInt32BE(from: buf, at: 16),
                  let identOffU32 = readUInt32BE(from: buf, at: 20),
                  let nSpecU32 = readUInt32BE(from: buf, at: 24),
                  let nCodeU32 = readUInt32BE(from: buf, at: 28),
                  let codeLimitU32 = readUInt32BE(from: buf, at: 32) else {
                return nil
            }

            let hashSize = Int(buf[36])
            let hashType = buf[37]
            let pageSizeShift = buf[39]

            let expectedHashSize: Int
            switch hashType {
            case 1: expectedHashSize = 20 // CS_HASHTYPE_SHA1
            case 2: expectedHashSize = 32 // CS_HASHTYPE_SHA256
            case 3: expectedHashSize = 20 // CS_HASHTYPE_SHA256_TRUNCATED
            case 4: expectedHashSize = 48 // CS_HASHTYPE_SHA384
            case 5: expectedHashSize = 64 // CS_HASHTYPE_SHA512
            default: return nil
            }
            guard hashSize == expectedHashSize else { return nil }

            let hashOffset = Int(hashOffU32)
            let identOffset = Int(identOffU32)
            let nSpecialSlots = Int(nSpecU32)
            let nCodeSlots = Int(nCodeU32)
            guard nSpecialSlots >= 0, nSpecialSlots <= 64,
                  nCodeSlots >= 1, nCodeSlots <= 262_144 else {
                return nil
            }

            let specialBytes = nSpecialSlots * hashSize
            let codeBytes = nCodeSlots * hashSize
            guard hashOffset >= 44 + specialBytes,
                  hashOffset <= data.count - codeBytes else {
                return nil
            }

            var hasScatter = false
            if version >= 0x0002_0100, data.count >= 48,
               let scatterOff = readUInt32BE(from: buf, at: 44),
               scatterOff != 0 {
                hasScatter = true
            }

            let effectiveCodeLimit: Int
            if version >= 0x0002_0300, data.count >= 64,
               let clHi = readUInt32BE(from: buf, at: 56),
               let clLo = readUInt32BE(from: buf, at: 60) {
                let cl64 = (UInt64(clHi) << 32) | UInt64(clLo)
                if cl64 > 0 {
                    guard let exactLim = Int(exactly: cl64) else { return nil }
                    effectiveCodeLimit = exactLim
                } else {
                    effectiveCodeLimit = Int(codeLimitU32)
                }
            } else {
                effectiveCodeLimit = Int(codeLimitU32)
            }
            guard effectiveCodeLimit > 0 else { return nil }

            let effectivePageSize: Int
            if pageSizeShift == 0 {
                effectivePageSize = effectiveCodeLimit
            } else if pageSizeShift <= 24 {
                effectivePageSize = 1 << Int(pageSizeShift)
            } else {
                return nil
            }

            var identifier: String? = nil
            if identOffset >= 44 && identOffset < data.count {
                let maxIdentEnd = min(data.count, hashOffset - specialBytes >= identOffset ? (hashOffset - specialBytes) : data.count)
                var end = identOffset
                while end < maxIdentEnd && buf[end] != 0 {
                    end += 1
                }
                if end > identOffset {
                    identifier = String(data: data.subdata(in: identOffset..<end), encoding: .utf8)
                }
            }

            return ParsedCodeDirectory(
                slotType: slotType,
                rawBlob: data,
                version: version,
                flags: flags,
                hashOffset: hashOffset,
                identOffset: identOffset,
                identifier: identifier,
                nSpecialSlots: nSpecialSlots,
                nCodeSlots: nCodeSlots,
                effectiveCodeLimit: effectiveCodeLimit,
                hashSize: hashSize,
                hashType: hashType,
                effectivePageSize: effectivePageSize,
                hasScatter: hasScatter
            )
        }
    }

    private static func computeCodeDirectorySlotDigest<D: DataProtocol>(_ bytes: D, hashType: UInt8) -> Data? {
        switch hashType {
        case 1:
            return Data(Insecure.SHA1.hash(data: bytes))
        case 2:
            return Data(SHA256.hash(data: bytes))
        case 3:
            return Data(SHA256.hash(data: bytes).prefix(20))
        case 4:
            return Data(SHA384.hash(data: bytes))
        case 5:
            return Data(SHA512.hash(data: bytes))
        default:
            return nil
        }
    }

    private static func computeFullCodeDirectoryDigest(_ cdBlob: Data, hashType: UInt8) -> Data? {
        switch hashType {
        case 1:
            return Data(Insecure.SHA1.hash(data: cdBlob))
        case 2, 3:
            return Data(SHA256.hash(data: cdBlob))
        case 4:
            return Data(SHA384.hash(data: cdBlob))
        case 5:
            return Data(SHA512.hash(data: cdBlob))
        default:
            return nil
        }
    }

    // ASN.1 OID value payloads (excluding 0x06 tag and length byte)
    private static let oidSignedData = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])       // 1.2.840.113549.1.7.2
    private static let oidPKCS7Data = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])        // 1.2.840.113549.1.7.1
    private static let oidContentType = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03])      // 1.2.840.113549.1.9.3
    private static let oidMessageDigest = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04])    // 1.2.840.113549.1.9.4
    private static let oidAppleCDHashesPlist = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x09, 0x01]) // 1.2.840.113635.100.9.1
    private static let oidAppleCDHashesDER = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x09, 0x02]) // 1.2.840.113635.100.9.2

    private static let oidSHA1 = Data([0x2B, 0x0E, 0x03, 0x02, 0x1A])                                     // 1.3.14.3.2.26
    private static let oidSHA256 = Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])           // 2.16.840.1.101.3.4.2.1
    private static let oidSHA384 = Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02])           // 2.16.840.1.101.3.4.2.2
    private static let oidSHA512 = Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03])           // 2.16.840.1.101.3.4.2.3

    private static let oidRSAEncryption = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])    // 1.2.840.113549.1.1.1
    private static let oidSHA1WithRSA = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05])      // 1.2.840.113549.1.1.5
    private static let oidSHA256WithRSA = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])    // 1.2.840.113549.1.1.11
    private static let oidSHA384WithRSA = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C])    // 1.2.840.113549.1.1.12
    private static let oidSHA512WithRSA = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D])    // 1.2.840.113549.1.1.13

    private static let oidECPublicKey = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])                  // 1.2.840.10045.2.1
    private static let oidECDSASHA1 = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01])                    // 1.2.840.10045.4.1
    private static let oidECDSASHA256 = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])            // 1.2.840.10045.4.3.2
    private static let oidECDSASHA384 = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03])            // 1.2.840.10045.4.3.3
    private static let oidECDSASHA512 = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04])            // 1.2.840.10045.4.3.4

    private static func computeCMSDigest(_ data: Data, algorithmOID: Data) -> Data? {
        if algorithmOID == oidSHA256 {
            return Data(SHA256.hash(data: data))
        } else if algorithmOID == oidSHA384 {
            return Data(SHA384.hash(data: data))
        } else if algorithmOID == oidSHA512 {
            return Data(SHA512.hash(data: data))
        } else if algorithmOID == oidSHA1 {
            return Data(Insecure.SHA1.hash(data: data))
        }
        return nil
    }

    private static func resolveSecKeyAlgorithm(signatureAlgOID: Data, digestAlgOID: Data) -> SecKeyAlgorithm? {
        if signatureAlgOID == oidSHA256WithRSA {
            return digestAlgOID == oidSHA256 ? .rsaSignatureMessagePKCS1v15SHA256 : nil
        } else if signatureAlgOID == oidSHA384WithRSA {
            return digestAlgOID == oidSHA384 ? .rsaSignatureMessagePKCS1v15SHA384 : nil
        } else if signatureAlgOID == oidSHA512WithRSA {
            return digestAlgOID == oidSHA512 ? .rsaSignatureMessagePKCS1v15SHA512 : nil
        } else if signatureAlgOID == oidSHA1WithRSA {
            return digestAlgOID == oidSHA1 ? .rsaSignatureMessagePKCS1v15SHA1 : nil
        } else if signatureAlgOID == oidRSAEncryption {
            if digestAlgOID == oidSHA256 { return .rsaSignatureMessagePKCS1v15SHA256 }
            if digestAlgOID == oidSHA384 { return .rsaSignatureMessagePKCS1v15SHA384 }
            if digestAlgOID == oidSHA512 { return .rsaSignatureMessagePKCS1v15SHA512 }
            if digestAlgOID == oidSHA1 { return .rsaSignatureMessagePKCS1v15SHA1 }
            return nil
        } else if signatureAlgOID == oidECDSASHA256 {
            return digestAlgOID == oidSHA256 ? .ecdsaSignatureMessageX962SHA256 : nil
        } else if signatureAlgOID == oidECDSASHA384 {
            return digestAlgOID == oidSHA384 ? .ecdsaSignatureMessageX962SHA384 : nil
        } else if signatureAlgOID == oidECDSASHA512 {
            return digestAlgOID == oidSHA512 ? .ecdsaSignatureMessageX962SHA512 : nil
        } else if signatureAlgOID == oidECDSASHA1 {
            return digestAlgOID == oidSHA1 ? .ecdsaSignatureMessageX962SHA1 : nil
        } else if signatureAlgOID == oidECPublicKey {
            if digestAlgOID == oidSHA256 { return .ecdsaSignatureMessageX962SHA256 }
            if digestAlgOID == oidSHA384 { return .ecdsaSignatureMessageX962SHA384 }
            if digestAlgOID == oidSHA512 { return .ecdsaSignatureMessageX962SHA512 }
            if digestAlgOID == oidSHA1 { return .ecdsaSignatureMessageX962SHA1 }
            return nil
        }
        return nil
    }

    private static func machHeaderAndLoadCommandsEnd(of sliceData: Data) -> Int? {
        guard sliceData.count >= 28 else { return nil }
        return sliceData.withUnsafeBytes { raw -> Int? in
            let b0 = UInt32(raw[0]), b1 = UInt32(raw[1]), b2 = UInt32(raw[2]), b3 = UInt32(raw[3])
            let magicLE = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
            let is64: Bool
            let swapped: Bool
            switch magicLE {
            case MH_MAGIC_64: is64 = true; swapped = false
            case MH_CIGAM_64: is64 = true; swapped = true
            case MH_MAGIC:    is64 = false; swapped = false
            case MH_CIGAM:    is64 = false; swapped = true
            default: return nil
            }
            let headerSize = is64 ? 32 : 28
            guard sliceData.count >= headerSize else { return nil }
            let sb0 = UInt32(raw[20]), sb1 = UInt32(raw[21]), sb2 = UInt32(raw[22]), sb3 = UInt32(raw[23])
            let sizeofcmds = swapped
                ? ((sb0 << 24) | (sb1 << 16) | (sb2 << 8) | sb3)
                : (sb0 | (sb1 << 8) | (sb2 << 16) | (sb3 << 24))
            let end = headerSize + Int(sizeofcmds)
            guard end >= headerSize, end <= sliceData.count else { return nil }
            return end
        }
    }

    private static func verifyCodeDirectoryAgainstSliceAndSuperBlob(
        _ cd: ParsedCodeDirectory,
        sliceData rawSlice: Data,
        xmlEntitlementBlobs: [Data],
        derEntitlementBlobs: [Data]
    ) -> Bool {
        func isZeroSlot(_ slot: Data?) -> Bool {
            guard let slot else { return true }
            return slot.allSatisfy { $0 == 0 }
        }

        // 1. Enforce bidirectional seal between SuperBlob Slot 5 (XML entitlements) and CodeDirectory Special Slot -5
        let slotMinus5 = cd.specialSlotHash(5)
        if !xmlEntitlementBlobs.isEmpty {
            guard xmlEntitlementBlobs.count == 1,
                  let expected5 = slotMinus5,
                  !isZeroSlot(expected5),
                  let actual5 = computeCodeDirectorySlotDigest(xmlEntitlementBlobs[0], hashType: cd.hashType),
                  actual5 == expected5 else {
                return false
            }
        } else if !isZeroSlot(slotMinus5) {
            return false
        }

        // 2. Enforce bidirectional seal between SuperBlob Slot 7 (DER CoreEntitlements) and CodeDirectory Special Slot -7
        let slotMinus7 = cd.specialSlotHash(7)
        if !derEntitlementBlobs.isEmpty {
            guard derEntitlementBlobs.count == 1,
                  let expected7 = slotMinus7,
                  !isZeroSlot(expected7),
                  let actual7 = computeCodeDirectorySlotDigest(derEntitlementBlobs[0], hashType: cd.hashType),
                  actual7 == expected7 else {
                return false
            }
        } else if !isZeroSlot(slotMinus7) {
            return false
        }

        // 3. Reject scatter-list CodeDirectories on iOS/Mach-O App Store verification and enforce Mach-O header + load-command coverage
        guard !cd.hasScatter else { return false }
        let slice = rawSlice.startIndex == 0 ? rawSlice : Data(rawSlice)
        guard cd.effectiveCodeLimit <= slice.count,
              cd.effectiveCodeLimit <= 256 * 1024 * 1024,
              let commandsEnd = machHeaderAndLoadCommandsEnd(of: slice),
              cd.effectiveCodeLimit >= commandsEnd else {
            return false
        }

        let expectedSlots = (cd.effectiveCodeLimit + cd.effectivePageSize - 1) / cd.effectivePageSize
        guard expectedSlots == cd.nCodeSlots else {
            return false
        }

        // 4. Verify Page-0 (mach_header + load commands) and all remaining code pages up to codeLimit
        for slotIdx in 0..<cd.nCodeSlots {
            let pageStart = slotIdx * cd.effectivePageSize
            let pageEnd = min(pageStart + cd.effectivePageSize, cd.effectiveCodeLimit)
            guard pageStart < pageEnd,
                  let expectedPageHash = cd.codeSlotHash(slotIdx),
                  let actualPageHash = computeCodeDirectorySlotDigest(slice[pageStart..<pageEnd], hashType: cd.hashType),
                  actualPageHash == expectedPageHash else {
                return false
            }
        }

        return true
    }

    private static func verifyAppleAppStoreCMSSignature(
        _ cmsData: Data,
        codeDirectoryEntries: [(slotType: UInt32, blob: Data)],
        xmlEntitlementBlobs: [Data],
        derEntitlementBlobs: [Data],
        sliceData: Data?,
        customAnchorCertificates: [SecCertificate]?
    ) -> CodeSignatureTrustEvaluation {
        let parsedCMS = parseCMSSignedData(cmsData)
        let certDERs = parsedCMS?.certificateDERs ?? extractX509CertificatesFallback(cmsData)
        guard !certDERs.isEmpty else {
            return CodeSignatureTrustEvaluation(disposition: .nonAppStoreSigner(subjectSummary: nil), signerKind: .none, leafSubjectSummary: nil)
        }

        var certDERBySummary: [(cert: SecCertificate, der: Data, summary: String)] = []
        for der in certDERs {
            guard let cert = SecCertificateCreateWithData(nil, der as CFData) else { continue }
            let summary = (SecCertificateCopySubjectSummary(cert) as String?) ?? ""
            certDERBySummary.append((cert, der, summary))
        }
        guard !certDERBySummary.isEmpty else {
            return CodeSignatureTrustEvaluation(disposition: .nonAppStoreSigner(subjectSummary: nil), signerKind: .none, leafSubjectSummary: nil)
        }

        let appleLeafCandidates = certDERBySummary.filter { item in
            item.summary == "Apple iPhone OS Application Signing"
                || item.summary == "TestFlight Beta Distribution"
                || item.summary == "Apple TestFlight Beta Distribution"
                || item.summary == "Software Signing"
                || item.summary == "macOS Software Signing"
                || item.summary == "Apple Mac OS Application Signing"
        }
        guard !appleLeafCandidates.isEmpty else {
            let nonRootSummary = certDERBySummary.first { !$0.summary.hasPrefix("Apple Root CA") && !$0.summary.contains("Certification Authority") }?.summary
                ?? certDERBySummary.first?.summary
            return CodeSignatureTrustEvaluation(
                disposition: .nonAppStoreSigner(subjectSummary: nonRootSummary),
                signerKind: .none,
                leafSubjectSummary: nonRootSummary
            )
        }

        let fallbackSummary = appleLeafCandidates.first?.summary
        guard let signedData = parsedCMS,
              !signedData.signerInfos.isEmpty,
              signedData.encapContentTypeOID == oidPKCS7Data,
              !codeDirectoryEntries.isEmpty,
              let sliceBytes = sliceData else {
            return CodeSignatureTrustEvaluation(
                disposition: .nonAppStoreSigner(subjectSummary: fallbackSummary),
                signerKind: .none,
                leafSubjectSummary: fallbackSummary
            )
        }

        // Parse all CodeDirectory slots and require primary Slot 0 CodeDirectory
        var parsedCDs: [ParsedCodeDirectory] = []
        for cdEntry in codeDirectoryEntries {
            guard let parsed = parseCodeDirectory(slotType: cdEntry.slotType, blobData: cdEntry.blob) else {
                return CodeSignatureTrustEvaluation(
                    disposition: .nonAppStoreSigner(subjectSummary: fallbackSummary),
                    signerKind: .none,
                    leafSubjectSummary: fallbackSummary
                )
            }
            parsedCDs.append(parsed)
        }
        guard let primaryCD = parsedCDs.first(where: { $0.slotType == CSBlobConstants.slotCodeDirectory }) ?? parsedCDs.first else {
            return CodeSignatureTrustEvaluation(
                disposition: .nonAppStoreSigner(subjectSummary: fallbackSummary),
                signerKind: .none,
                leafSubjectSummary: fallbackSummary
            )
        }

        if let attachedContent = signedData.encapContentBytes, attachedContent != primaryCD.rawBlob {
            return CodeSignatureTrustEvaluation(
                disposition: .nonAppStoreSigner(subjectSummary: fallbackSummary),
                signerKind: .none,
                leafSubjectSummary: fallbackSummary
            )
        }

        // Verify every CodeDirectory slot against sliceData (Page-0 + code slots) and SuperBlob Slot 5/7
        for cd in parsedCDs {
            guard verifyCodeDirectoryAgainstSliceAndSuperBlob(
                cd,
                sliceData: sliceBytes,
                xmlEntitlementBlobs: xmlEntitlementBlobs,
                derEntitlementBlobs: derEntitlementBlobs
            ) else {
                return CodeSignatureTrustEvaluation(
                    disposition: .nonAppStoreSigner(subjectSummary: fallbackSummary),
                    signerKind: .none,
                    leafSubjectSummary: fallbackSummary
                )
            }
        }

        let policy = SecPolicyCreateBasicX509()
        for leafItem in appleLeafCandidates {
            var orderedCerts: [SecCertificate] = [leafItem.cert]
            for item in certDERBySummary where item.der != leafItem.der {
                orderedCerts.append(item.cert)
            }
            var trustOpt: SecTrust?
            guard SecTrustCreateWithCertificates(orderedCerts as CFArray, policy, &trustOpt) == errSecSuccess,
                  let trust = trustOpt else {
                continue
            }

            // Strictly disable any background AIA/OCSP network fetches during X.509 evaluation
            _ = SecTrustSetNetworkFetchAllowed(trust, false)

            if let customAnchors = customAnchorCertificates {
                guard SecTrustSetAnchorCertificates(trust, customAnchors as CFArray) == errSecSuccess,
                      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else {
                    continue
                }
            }

            // Evaluate against the OS built-in Root CA store (or explicit test anchor in unit tests):
            // try current wall-clock time first, then leaf X.509 Validity.notBefore + 60s for older archived App Store IPAs.
            var chainValid = SecTrustEvaluateWithError(trust, nil)
            if !chainValid, let notBefore = extractX509NotBeforeDate(from: leafItem.der) {
                _ = SecTrustSetVerifyDate(trust, notBefore.addingTimeInterval(60) as CFDate)
                chainValid = SecTrustEvaluateWithError(trust, nil)
            }
            guard chainValid,
                  let evaluatedChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  evaluatedChain.count >= 2,
                  (SecCertificateCopyData(evaluatedChain[0]) as Data) == leafItem.der,
                  let rootCert = evaluatedChain.last,
                  let rootSummary = SecCertificateCopySubjectSummary(rootCert) as String?,
                  rootSummary.hasPrefix("Apple Root CA"),
                  (customAnchorCertificates != nil || Self.isOfficialAppleRootCertificate(rootCert)),
                  let leafPublicKey = SecCertificateCopyKey(leafItem.cert) else {
                continue
            }

            let leafIssuerSerial = extractX509IssuerAndSerial(from: leafItem.der)
            let leafSubjectKeyIdentifier = extractX509SubjectKeyIdentifier(from: leafItem.der)

            // Require at least one SignerInfo bound to this Apple-anchored leaf certificate, primary CodeDirectory, and Apple CDHashes
            for signerInfo in signedData.signerInfos {
                switch signerInfo.sid {
                case .issuerAndSerial(let sidIssuer, let sidSerial):
                    guard let certIS = leafIssuerSerial,
                          certIS.issuerTLV == sidIssuer,
                          trimASN1IntegerLeadingZero(certIS.serialBytes) == trimASN1IntegerLeadingZero(sidSerial) else {
                        continue
                    }
                case .subjectKeyIdentifier(let sidSKI):
                    guard !sidSKI.isEmpty,
                          let leafSKI = leafSubjectKeyIdentifier,
                          leafSKI == sidSKI else {
                        continue
                    }
                }

                guard !signerInfo.retaggedSignedAttrs.isEmpty,
                      signerInfo.contentTypeValues.count == 1,
                      signerInfo.contentTypeValues[0] == oidPKCS7Data,
                      signerInfo.messageDigestValues.count == 1,
                      let expectedDigest = computeCMSDigest(primaryCD.rawBlob, algorithmOID: signerInfo.digestAlgorithmOID),
                      expectedDigest == signerInfo.messageDigestValues[0] else {
                    continue
                }

                if !verifyAppleCDHashesAttributes(signerInfo: signerInfo, codeDirectories: parsedCDs) {
                    continue
                }

                guard let secKeyAlg = resolveSecKeyAlgorithm(
                    signatureAlgOID: signerInfo.signatureAlgorithmOID,
                    digestAlgOID: signerInfo.digestAlgorithmOID
                ) else {
                    continue
                }

                if SecKeyVerifySignature(
                    leafPublicKey,
                    secKeyAlg,
                    signerInfo.retaggedSignedAttrs as CFData,
                    signerInfo.signatureBytes as CFData,
                    nil
                ) {
                    let kind: AppleVerifiedSignerKind
                    switch leafItem.summary {
                    case "TestFlight Beta Distribution", "Apple TestFlight Beta Distribution":
                        kind = .testFlight
                    case "Apple iPhone OS Application Signing":
                        kind = .appStore
                    case "Software Signing", "macOS Software Signing", "Apple Mac OS Application Signing":
                        kind = .macSoftware
                    default:
                        kind = .none
                    }
                    return CodeSignatureTrustEvaluation(
                        disposition: .appleAppStoreVerified,
                        signerKind: kind,
                        leafSubjectSummary: leafItem.summary
                    )
                }
            }
        }

        return CodeSignatureTrustEvaluation(
            disposition: .nonAppStoreSigner(subjectSummary: fallbackSummary),
            signerKind: .none,
            leafSubjectSummary: fallbackSummary
        )
    }

    private static let allowedProvisioningLeafSummaries: Set<String> = [
        "Apple iPhone OS Provisioning Profile Signing",
        "Apple Provisioning Profile Signing",
        "iPhone Provisioning Profile Signing",
        "Apple Mac OS Provisioning Profile Signing",
        "Mac OS Provisioning Profile Signing"
    ]

    public func verifyProvisioningProfileCMS(_ rawInput: Data) -> (isVerified: Bool, plist: [String: Any]?, leafSummary: String?) {
        verifyProvisioningProfileCMS(rawInput, customAnchorCertificates: nil)
    }

    internal func verifyProvisioningProfileCMS(
        _ rawInput: Data,
        customAnchorCertificates: [SecCertificate]? = nil
    ) -> (isVerified: Bool, plist: [String: Any]?, leafSummary: String?) {
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
        guard !data.isEmpty,
              let signedData = Self.parseCMSSignedData(data, requireSignedAttrs: false),
              signedData.encapContentTypeOID == Self.oidPKCS7Data,
              let encapBytes = signedData.encapContentBytes,
              !encapBytes.isEmpty,
              !signedData.signerInfos.isEmpty,
              !signedData.certificateDERs.isEmpty else {
            return (false, nil, nil)
        }

        guard let plist = (try? PropertyListSerialization.propertyList(from: encapBytes, options: [], format: nil)) as? [String: Any] else {
            return (false, nil, nil)
        }

        var certItems: [(cert: SecCertificate, der: Data, summary: String)] = []
        for der in signedData.certificateDERs {
            guard let cert = SecCertificateCreateWithData(nil, der as CFData) else { continue }
            let summary = (SecCertificateCopySubjectSummary(cert) as String?) ?? ""
            certItems.append((cert, der, summary))
        }
        let leafCandidates = certItems.filter { Self.allowedProvisioningLeafSummaries.contains($0.summary) }
        guard !leafCandidates.isEmpty else {
            return (false, nil, nil)
        }

        let policy = SecPolicyCreateBasicX509()
        for leafItem in leafCandidates {
            var orderedCerts: [SecCertificate] = [leafItem.cert]
            for item in certItems where item.der != leafItem.der {
                orderedCerts.append(item.cert)
            }
            var trustOpt: SecTrust?
            guard SecTrustCreateWithCertificates(orderedCerts as CFArray, policy, &trustOpt) == errSecSuccess,
                  let trust = trustOpt else {
                continue
            }
            _ = SecTrustSetNetworkFetchAllowed(trust, false)
            if let customAnchors = customAnchorCertificates {
                guard SecTrustSetAnchorCertificates(trust, customAnchors as CFArray) == errSecSuccess,
                      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else {
                    continue
                }
            }
            var chainValid = SecTrustEvaluateWithError(trust, nil)
            if !chainValid, let notBefore = Self.extractX509NotBeforeDate(from: leafItem.der) {
                _ = SecTrustSetVerifyDate(trust, notBefore.addingTimeInterval(60) as CFDate)
                chainValid = SecTrustEvaluateWithError(trust, nil)
            }
            guard chainValid,
                  let evaluatedChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  evaluatedChain.count >= 2,
                  (SecCertificateCopyData(evaluatedChain[0]) as Data) == leafItem.der,
                  let rootCert = evaluatedChain.last,
                  let rootSummary = SecCertificateCopySubjectSummary(rootCert) as String?,
                  rootSummary.hasPrefix("Apple Root CA"),
                  (customAnchorCertificates != nil || Self.isOfficialAppleRootCertificate(rootCert)),
                  let leafPublicKey = SecCertificateCopyKey(leafItem.cert) else {
                continue
            }

            let leafIssuerSerial = Self.extractX509IssuerAndSerial(from: leafItem.der)
            let leafSKI = Self.extractX509SubjectKeyIdentifier(from: leafItem.der)

            for signerInfo in signedData.signerInfos {
                switch signerInfo.sid {
                case .issuerAndSerial(let sidIssuer, let sidSerial):
                    guard let certIS = leafIssuerSerial,
                          certIS.issuerTLV == sidIssuer,
                          Self.trimASN1IntegerLeadingZero(certIS.serialBytes) == Self.trimASN1IntegerLeadingZero(sidSerial) else {
                        continue
                    }
                case .subjectKeyIdentifier(let sidSKI):
                    guard !sidSKI.isEmpty,
                          let lSKI = leafSKI,
                          lSKI == sidSKI else {
                        continue
                    }
                }

                let signedPayload: Data
                if !signerInfo.retaggedSignedAttrs.isEmpty {
                    guard signerInfo.contentTypeValues.count == 1,
                          signerInfo.contentTypeValues[0] == Self.oidPKCS7Data,
                          signerInfo.messageDigestValues.count == 1,
                          let expectedDigest = Self.computeCMSDigest(encapBytes, algorithmOID: signerInfo.digestAlgorithmOID),
                          expectedDigest == signerInfo.messageDigestValues[0] else {
                        continue
                    }
                    signedPayload = signerInfo.retaggedSignedAttrs
                } else {
                    signedPayload = encapBytes
                }

                guard let secKeyAlg = Self.resolveSecKeyAlgorithm(
                    signatureAlgOID: signerInfo.signatureAlgorithmOID,
                    digestAlgOID: signerInfo.digestAlgorithmOID
                ) else {
                    continue
                }

                if SecKeyVerifySignature(
                    leafPublicKey,
                    secKeyAlg,
                    signedPayload as CFData,
                    signerInfo.signatureBytes as CFData,
                    nil
                ) {
                    return (true, plist, leafItem.summary)
                }
            }
        }

        return (false, nil, nil)
    }

    public func verifyAppReceiptCMS(_ rawInput: Data) -> (isVerified: Bool, isSandbox: Bool) {
        verifyAppReceiptCMS(rawInput, customAnchorCertificates: nil)
    }

    internal func verifyAppReceiptCMS(
        _ rawInput: Data,
        customAnchorCertificates: [SecCertificate]? = nil
    ) -> (isVerified: Bool, isSandbox: Bool) {
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
        guard !data.isEmpty,
              let signedData = Self.parseCMSSignedData(data, requireSignedAttrs: false),
              signedData.encapContentTypeOID == Self.oidPKCS7Data,
              let encapBytes = signedData.encapContentBytes,
              !encapBytes.isEmpty,
              !signedData.signerInfos.isEmpty,
              !signedData.certificateDERs.isEmpty else {
            return (false, false)
        }

        guard let receiptRoot = try? ASN1DERDecoder.decode(encapBytes),
              case .set(let receiptAttrs) = receiptRoot,
              !receiptAttrs.isEmpty else {
            return (false, false)
        }

        var foundValidAttribute = false
        var isSandboxEnv = false
        for attrNode in receiptAttrs {
            guard case .sequence(let fields) = attrNode,
                  fields.count == 3,
                  case .integer(let attrType) = fields[0],
                  case .integer(_) = fields[1],
                  case .data(let attrBytes) = fields[2] else {
                continue
            }
            foundValidAttribute = true
            if attrType == 0,
               let envNode = try? ASN1DERDecoder.decode(attrBytes),
               case .string(let envValue) = envNode {
                let lowerEnv = envValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if lowerEnv == "productionsandbox" || lowerEnv == "sandbox" {
                    isSandboxEnv = true
                }
            }
        }
        guard foundValidAttribute else {
            return (false, false)
        }

        var certItems: [(cert: SecCertificate, der: Data, summary: String)] = []
        for der in signedData.certificateDERs {
            guard let cert = SecCertificateCreateWithData(nil, der as CFData) else { continue }
            let summary = (SecCertificateCopySubjectSummary(cert) as String?) ?? ""
            certItems.append((cert, der, summary))
        }
        let leafCandidates = certItems.filter { item in
            let s = item.summary
            return s.contains("Receipt Signing")
                || s == "Apple iPhone OS Application Signing"
                || s == "TestFlight Beta Distribution"
                || s == "Apple TestFlight Beta Distribution"
                || s == "Apple Inc. Application Integration"
        }
        guard !leafCandidates.isEmpty else {
            return (false, false)
        }

        let policy = SecPolicyCreateBasicX509()
        for leafItem in leafCandidates {
            var orderedCerts: [SecCertificate] = [leafItem.cert]
            for item in certItems where item.der != leafItem.der {
                orderedCerts.append(item.cert)
            }
            var trustOpt: SecTrust?
            guard SecTrustCreateWithCertificates(orderedCerts as CFArray, policy, &trustOpt) == errSecSuccess,
                  let trust = trustOpt else {
                continue
            }
            _ = SecTrustSetNetworkFetchAllowed(trust, false)
            if let customAnchors = customAnchorCertificates {
                guard SecTrustSetAnchorCertificates(trust, customAnchors as CFArray) == errSecSuccess,
                      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else {
                    continue
                }
            }
            var chainValid = SecTrustEvaluateWithError(trust, nil)
            if !chainValid, let notBefore = Self.extractX509NotBeforeDate(from: leafItem.der) {
                _ = SecTrustSetVerifyDate(trust, notBefore.addingTimeInterval(60) as CFDate)
                chainValid = SecTrustEvaluateWithError(trust, nil)
            }
            guard chainValid,
                  let evaluatedChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  evaluatedChain.count >= 2,
                  (SecCertificateCopyData(evaluatedChain[0]) as Data) == leafItem.der,
                  let rootCert = evaluatedChain.last,
                  let rootSummary = SecCertificateCopySubjectSummary(rootCert) as String?,
                  rootSummary.hasPrefix("Apple Root CA"),
                  (customAnchorCertificates != nil || Self.isOfficialAppleRootCertificate(rootCert)),
                  let leafPublicKey = SecCertificateCopyKey(leafItem.cert) else {
                continue
            }

            let leafIssuerSerial = Self.extractX509IssuerAndSerial(from: leafItem.der)
            let leafSKI = Self.extractX509SubjectKeyIdentifier(from: leafItem.der)

            for signerInfo in signedData.signerInfos {
                switch signerInfo.sid {
                case .issuerAndSerial(let sidIssuer, let sidSerial):
                    guard let certIS = leafIssuerSerial,
                          certIS.issuerTLV == sidIssuer,
                          Self.trimASN1IntegerLeadingZero(certIS.serialBytes) == Self.trimASN1IntegerLeadingZero(sidSerial) else {
                        continue
                    }
                case .subjectKeyIdentifier(let sidSKI):
                    guard !sidSKI.isEmpty,
                          let lSKI = leafSKI,
                          lSKI == sidSKI else {
                        continue
                    }
                }

                let signedPayload: Data
                if !signerInfo.retaggedSignedAttrs.isEmpty {
                    guard signerInfo.contentTypeValues.count == 1,
                          signerInfo.contentTypeValues[0] == Self.oidPKCS7Data,
                          signerInfo.messageDigestValues.count == 1,
                          let expectedDigest = Self.computeCMSDigest(encapBytes, algorithmOID: signerInfo.digestAlgorithmOID),
                          expectedDigest == signerInfo.messageDigestValues[0] else {
                        continue
                    }
                    signedPayload = signerInfo.retaggedSignedAttrs
                } else {
                    signedPayload = encapBytes
                }

                guard let secKeyAlg = Self.resolveSecKeyAlgorithm(
                    signatureAlgOID: signerInfo.signatureAlgorithmOID,
                    digestAlgOID: signerInfo.digestAlgorithmOID
                ) else {
                    continue
                }

                if SecKeyVerifySignature(
                    leafPublicKey,
                    secKeyAlg,
                    signedPayload as CFData,
                    signerInfo.signatureBytes as CFData,
                    nil
                ) {
                    return (true, isSandboxEnv)
                }
            }
        }

        return (false, false)
    }

    private static func verifyAppleCDHashesAttributes(
        signerInfo: ParsedCMSSignerInfo,
        codeDirectories: [ParsedCodeDirectory]
    ) -> Bool {
        // 1. Apple Plist CDHashes attribute (1.2.840.113635.100.9.1)
        for plistData in signerInfo.appleCDHashesPlistBlobs {
            guard let dict = try? CSBlobParser.shared.parseXMLPlist(plistData),
                  let rawHashes = dict["cdhashes"] as? [Any] else {
                return false
            }
            let plistHashes = rawHashes.compactMap { $0 as? Data }
            guard plistHashes.count == rawHashes.count, !plistHashes.isEmpty else {
                return false
            }
            for cd in codeDirectories {
                guard let fullDigest = computeFullCodeDirectoryDigest(cd.rawBlob, hashType: cd.hashType) else {
                    return false
                }
                let cdHash20 = Data(fullDigest.prefix(20))
                if !plistHashes.contains(cdHash20) && !plistHashes.contains(fullDigest) {
                    return false
                }
            }
        }

        // 2. Apple DER CDHashes attribute (1.2.840.113635.100.9.2)
        for derEntry in signerInfo.appleCDHashesDEREntries {
            guard !derEntry.hashes.isEmpty else { return false }
            for cd in codeDirectories {
                let matchesAlg: Bool
                switch cd.hashType {
                case 1: matchesAlg = (derEntry.algOID == oidSHA1)
                case 2, 3: matchesAlg = (derEntry.algOID == oidSHA256)
                case 4: matchesAlg = (derEntry.algOID == oidSHA384)
                case 5: matchesAlg = (derEntry.algOID == oidSHA512)
                default: matchesAlg = false
                }
                if matchesAlg {
                    guard let fullDigest = computeFullCodeDirectoryDigest(cd.rawBlob, hashType: cd.hashType) else {
                        return false
                    }
                    let cdHash20 = Data(fullDigest.prefix(20))
                    if !derEntry.hashes.contains(fullDigest) && !derEntry.hashes.contains(cdHash20) {
                        return false
                    }
                }
            }
        }

        return true
    }

    private static func trimASN1IntegerLeadingZero(_ bytes: Data) -> Data {
        var idx = bytes.startIndex
        while idx < bytes.endIndex && bytes[idx] == 0 && bytes.distance(from: idx, to: bytes.endIndex) > 1 {
            idx = bytes.index(after: idx)
        }
        return bytes.subdata(in: idx..<bytes.endIndex)
    }

    /// Official Apple Root CA X.509 DER SHA-256 digests (`Apple Root CA`, `Apple Root CA - G2`, `Apple Root CA - G3`),
    /// preventing rogue user/enterprise-installed roots with spoofed `"Apple Root CA*"` CNs from anchoring App Store trust.
    private static let officialAppleRootCASHA256Digests: Set<Data> = [
        Data([
            0xB0, 0xB1, 0x73, 0x0E, 0xCB, 0xC7, 0xFF, 0x45, 0x05, 0x14, 0x2C, 0x49, 0xF1, 0x29, 0x5E, 0x6E,
            0xDA, 0x6B, 0xCA, 0xED, 0x7E, 0x2C, 0x68, 0xC5, 0xBE, 0x91, 0xB5, 0xA1, 0x10, 0x01, 0xF0, 0x24
        ]),
        Data([
            0xC2, 0xB9, 0xB0, 0x42, 0xDD, 0x57, 0x83, 0x0E, 0x7D, 0x11, 0x7D, 0xAC, 0x55, 0xAC, 0x8A, 0xE1,
            0x94, 0x07, 0xD3, 0x8E, 0x41, 0xD8, 0x8F, 0x32, 0x15, 0xBC, 0x3A, 0x89, 0x04, 0x44, 0xA0, 0x50
        ]),
        Data([
            0x63, 0x34, 0x3A, 0xBF, 0xB8, 0x9A, 0x6A, 0x03, 0xEB, 0xB5, 0x7E, 0x9B, 0x3F, 0x5F, 0xA7, 0xBE,
            0x7C, 0x4F, 0x5C, 0x75, 0x6F, 0x30, 0x17, 0xB3, 0xA8, 0xC4, 0x88, 0xC3, 0x65, 0x3E, 0x91, 0x79
        ])
    ]

    private static func isOfficialAppleRootCertificate(_ cert: SecCertificate) -> Bool {
        let der = SecCertificateCopyData(cert) as Data
        let digest = Data(SHA256.hash(data: der))
        return officialAppleRootCASHA256Digests.contains(digest)
    }

    private static func encodeDefiniteDERTLV(tag: UInt8, content: Data) -> Data {
        var out = Data([tag])
        let len = content.count
        if len < 0x80 {
            out.append(UInt8(len))
        } else if len <= 0xFF {
            out.append(0x81)
            out.append(UInt8(len))
        } else if len <= 0xFFFF {
            out.append(0x82)
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        } else if len <= 0xFF_FFFF {
            out.append(0x83)
            out.append(UInt8((len >> 16) & 0xFF))
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        } else {
            out.append(0x84)
            out.append(UInt8((len >> 24) & 0xFF))
            out.append(UInt8((len >> 16) & 0xFF))
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        }
        out.append(content)
        return out
    }

    private static func readBERElement(in data: Data, at cur: inout Int, limit: Int, depth: Int = 0) -> BERElement? {
        guard cur < limit, depth <= 20 else { return nil }
        let elemStart = cur
        let tag = data[cur]
        cur += 1
        if (tag & 0x1F) == 0x1F {
            var octs = 0
            while cur < limit && octs < 5 {
                let tb = data[cur]
                cur += 1
                octs += 1
                if (tb & 0x80) == 0 { break }
            }
        }
        guard cur < limit else { return nil }
        let lenByte = data[cur]
        cur += 1
        if (lenByte & 0x80) == 0 {
            let len = Int(lenByte)
            guard cur + len <= limit else { return nil }
            let contentRange = cur..<(cur + len)
            cur += len
            return BERElement(tag: tag, isIndefinite: false, contentRange: contentRange, fullRange: elemStart..<cur)
        }
        let n = Int(lenByte & 0x7F)
        if n == 0 {
            // Indefinite-length constructed BER container: scan children until 0x00 0x00 EOC
            guard (tag & 0x20) != 0 else { return nil }
            let contentStart = cur
            while cur + 1 <= limit {
                if cur + 1 < limit && data[cur] == 0x00 && data[cur + 1] == 0x00 {
                    let contentEnd = cur
                    cur += 2
                    return BERElement(tag: tag, isIndefinite: true, contentRange: contentStart..<contentEnd, fullRange: elemStart..<cur)
                }
                if readBERElement(in: data, at: &cur, limit: limit, depth: depth + 1) == nil {
                    return nil
                }
            }
            return nil
        }
        guard n <= 4, cur + n <= limit else { return nil }
        var len = 0
        for _ in 0..<n {
            len = (len << 8) | Int(data[cur])
            cur += 1
        }
        guard len >= 0, cur + len <= limit else { return nil }
        let contentRange = cur..<(cur + len)
        cur += len
        return BERElement(tag: tag, isIndefinite: false, contentRange: contentRange, fullRange: elemStart..<cur)
    }

    private static func extractBEROctetStringBytes(
        in data: Data,
        element: BERElement,
        depth: Int = 0,
        maxBytes: Int = 16 * 1024 * 1024,
        into acc: inout Data
    ) -> Bool {
        guard depth <= 8 else { return false }
        if element.tag == 0x04 {
            let len = element.contentRange.count
            guard acc.count + len <= maxBytes else { return false }
            if len > 0 {
                acc.append(data.subdata(in: element.contentRange))
            }
            return true
        } else if element.tag == 0x24 {
            var cCur = element.contentRange.lowerBound
            let cLim = element.contentRange.upperBound
            while cCur < cLim {
                guard let part = readBERElement(in: data, at: &cCur, limit: cLim),
                      extractBEROctetStringBytes(in: data, element: part, depth: depth + 1, maxBytes: maxBytes, into: &acc) else {
                    return false
                }
            }
            return true
        }
        return false
    }

    private static func parseCMSSignedData(_ rawCMS: Data, requireSignedAttrs: Bool = true) -> ParsedCMSSignedData? {
        let data = rawCMS.startIndex == 0 ? rawCMS : Data(rawCMS)
        var topCur = 0
        guard let contentInfo = readBERElement(in: data, at: &topCur, limit: data.count),
              contentInfo.tag == 0x30 else {
            return nil
        }

        var ciCur = contentInfo.contentRange.lowerBound
        let ciLim = contentInfo.contentRange.upperBound
        guard let ciType = readBERElement(in: data, at: &ciCur, limit: ciLim),
              ciType.tag == 0x06,
              data.subdata(in: ciType.contentRange) == oidSignedData,
              let ciExp = readBERElement(in: data, at: &ciCur, limit: ciLim),
              ciExp.tag == 0xA0 else {
            return nil
        }

        var expCur = ciExp.contentRange.lowerBound
        guard let sdSeq = readBERElement(in: data, at: &expCur, limit: ciExp.contentRange.upperBound),
              sdSeq.tag == 0x30 else {
            return nil
        }

        var sdCur = sdSeq.contentRange.lowerBound
        let sdLim = sdSeq.contentRange.upperBound

        // 1. version (INTEGER 0x02), 2. digestAlgorithms (SET 0x31), 3. encapContentInfo (SEQUENCE 0x30)
        guard let verElem = readBERElement(in: data, at: &sdCur, limit: sdLim), verElem.tag == 0x02,
              let algSet = readBERElement(in: data, at: &sdCur, limit: sdLim), algSet.tag == 0x31,
              let encapSeq = readBERElement(in: data, at: &sdCur, limit: sdLim), encapSeq.tag == 0x30 else {
            return nil
        }

        var encCur = encapSeq.contentRange.lowerBound
        let encLim = encapSeq.contentRange.upperBound
        guard let eTypeElem = readBERElement(in: data, at: &encCur, limit: encLim), eTypeElem.tag == 0x06 else {
            return nil
        }
        let encapContentTypeOID = data.subdata(in: eTypeElem.contentRange)
        var encapContentBytes: Data? = nil
        if encCur < encLim,
           let eContentExp = readBERElement(in: data, at: &encCur, limit: encLim),
           eContentExp.tag == 0xA0 {
            var innerCur = eContentExp.contentRange.lowerBound
            guard let oct = readBERElement(in: data, at: &innerCur, limit: eContentExp.contentRange.upperBound) else {
                return nil
            }
            var acc = Data()
            guard extractBEROctetStringBytes(in: data, element: oct, depth: 0, maxBytes: 16 * 1024 * 1024, into: &acc) else {
                return nil
            }
            encapContentBytes = acc
        }

        var certs: [Data] = []
        var nextOpt = readBERElement(in: data, at: &sdCur, limit: sdLim)

        // Optional [0] IMPLICIT certificates (0xA0)
        if let certSet = nextOpt, certSet.tag == 0xA0 {
            var cCur = certSet.contentRange.lowerBound
            let cLim = certSet.contentRange.upperBound
            while cCur < cLim && certs.count < 32 {
                guard let certElem = readBERElement(in: data, at: &cCur, limit: cLim) else {
                    break
                }
                if certElem.tag == 0x30 {
                    certs.append(data.subdata(in: certElem.fullRange))
                }
            }
            nextOpt = readBERElement(in: data, at: &sdCur, limit: sdLim)
        }

        // Optional [1] IMPLICIT crls (0xA1)
        if let crlSet = nextOpt, crlSet.tag == 0xA1 {
            nextOpt = readBERElement(in: data, at: &sdCur, limit: sdLim)
        }

        // Required signerInfos SET OF SignerInfo (0x31)
        guard let signerInfosSet = nextOpt, signerInfosSet.tag == 0x31 else {
            return ParsedCMSSignedData(
                encapContentTypeOID: encapContentTypeOID,
                encapContentBytes: encapContentBytes,
                certificateDERs: certs,
                signerInfos: []
            )
        }

        var parsedSigners: [ParsedCMSSignerInfo] = []
        var siSetCur = signerInfosSet.contentRange.lowerBound
        let siSetLim = signerInfosSet.contentRange.upperBound
        while siSetCur < siSetLim && parsedSigners.count < 8 {
            guard let siElem = readBERElement(in: data, at: &siSetCur, limit: siSetLim),
                  siElem.tag == 0x30 else {
                break
            }
            if let parsedSI = parseSingleSignerInfo(in: data, range: siElem.contentRange, requireSignedAttrs: requireSignedAttrs) {
                parsedSigners.append(parsedSI)
            }
        }

        return ParsedCMSSignedData(
            encapContentTypeOID: encapContentTypeOID,
            encapContentBytes: encapContentBytes,
            certificateDERs: certs,
            signerInfos: parsedSigners
        )
    }

    private static func parseSingleSignerInfo(in data: Data, range: Range<Int>, requireSignedAttrs: Bool = true) -> ParsedCMSSignerInfo? {
        var cur = range.lowerBound
        let lim = range.upperBound

        // 1. version (INTEGER 0x02)
        guard let verElem = readBERElement(in: data, at: &cur, limit: lim), verElem.tag == 0x02 else {
            return nil
        }

        // 2. sid (IssuerAndSerialNumber 0x30 or [0] SubjectKeyIdentifier 0x80)
        guard let sidElem = readBERElement(in: data, at: &cur, limit: lim) else { return nil }
        let sid: CMSSignerIdentifier
        if sidElem.tag == 0x30 {
            var isCur = sidElem.contentRange.lowerBound
            let isLim = sidElem.contentRange.upperBound
            guard let issuerElem = readBERElement(in: data, at: &isCur, limit: isLim), issuerElem.tag == 0x30,
                  let serialElem = readBERElement(in: data, at: &isCur, limit: isLim), serialElem.tag == 0x02 else {
                return nil
            }
            sid = .issuerAndSerial(
                issuerTLV: data.subdata(in: issuerElem.fullRange),
                serialBytes: data.subdata(in: serialElem.contentRange)
            )
        } else if sidElem.tag == 0x80 {
            sid = .subjectKeyIdentifier(data.subdata(in: sidElem.contentRange))
        } else {
            return nil
        }

        // 3. digestAlgorithm (AlgorithmIdentifier SEQUENCE 0x30 -> OID 0x06)
        guard let digAlgSeq = readBERElement(in: data, at: &cur, limit: lim), digAlgSeq.tag == 0x30 else {
            return nil
        }
        var daCur = digAlgSeq.contentRange.lowerBound
        guard let digOID = readBERElement(in: data, at: &daCur, limit: digAlgSeq.contentRange.upperBound),
              digOID.tag == 0x06 else {
            return nil
        }
        let digestAlgorithmOID = data.subdata(in: digOID.contentRange)

        // 4. signedAttrs ([0] IMPLICIT SignedAttributes 0xA0) — mandatory when `requireSignedAttrs` is true
        guard let nextElem = readBERElement(in: data, at: &cur, limit: lim) else {
            return nil
        }

        let retaggedSignedAttrs: Data
        var contentTypeValues: [Data] = []
        var messageDigestValues: [Data] = []
        var appleCDHashesPlistBlobs: [Data] = []
        var appleCDHashesDEREntries: [(algOID: Data, hashes: [Data])] = []
        let sigAlgSeq: BERElement

        if nextElem.tag == 0xA0 {
            let signedAttrsElem = nextElem
            if signedAttrsElem.isIndefinite {
                retaggedSignedAttrs = encodeDefiniteDERTLV(tag: 0x31, content: data.subdata(in: signedAttrsElem.contentRange))
            } else {
                var copy = data.subdata(in: signedAttrsElem.fullRange)
                copy[0] = 0x31
                retaggedSignedAttrs = copy
            }

            var attrCur = signedAttrsElem.contentRange.lowerBound
            let attrLim = signedAttrsElem.contentRange.upperBound
            while attrCur < attrLim {
                guard let attrSeq = readBERElement(in: data, at: &attrCur, limit: attrLim),
                      attrSeq.tag == 0x30 else {
                    return nil
                }
                var aCur = attrSeq.contentRange.lowerBound
                let aLim = attrSeq.contentRange.upperBound
                guard let aType = readBERElement(in: data, at: &aCur, limit: aLim), aType.tag == 0x06,
                      let aVals = readBERElement(in: data, at: &aCur, limit: aLim), aVals.tag == 0x31 else {
                    return nil
                }
                let attrOID = data.subdata(in: aType.contentRange)
                var vCur = aVals.contentRange.lowerBound
                let vLim = aVals.contentRange.upperBound

                if attrOID == oidContentType {
                    while vCur < vLim {
                        guard let v = readBERElement(in: data, at: &vCur, limit: vLim), v.tag == 0x06 else { return nil }
                        contentTypeValues.append(data.subdata(in: v.contentRange))
                    }
                } else if attrOID == oidMessageDigest {
                    while vCur < vLim {
                        guard let v = readBERElement(in: data, at: &vCur, limit: vLim), v.tag == 0x04 else { return nil }
                        messageDigestValues.append(data.subdata(in: v.contentRange))
                    }
                } else if attrOID == oidAppleCDHashesPlist {
                    while vCur < vLim {
                        guard let v = readBERElement(in: data, at: &vCur, limit: vLim) else { return nil }
                        if v.tag == 0x04 || v.tag == 0x0C || v.tag == 0x16 {
                            appleCDHashesPlistBlobs.append(data.subdata(in: v.contentRange))
                        } else {
                            return nil
                        }
                    }
                } else if attrOID == oidAppleCDHashesDER {
                    while vCur < vLim {
                        guard let seq = readBERElement(in: data, at: &vCur, limit: vLim), seq.tag == 0x30 else { return nil }
                        var sCur = seq.contentRange.lowerBound
                        let sLim = seq.contentRange.upperBound
                        guard let hOIDElem = readBERElement(in: data, at: &sCur, limit: sLim), hOIDElem.tag == 0x06,
                              let hSetElem = readBERElement(in: data, at: &sCur, limit: sLim),
                              (hSetElem.tag == 0x30 || hSetElem.tag == 0x31 || hSetElem.tag == 0x04) else {
                            return nil
                        }
                        let hOID = data.subdata(in: hOIDElem.contentRange)
                        var hashes: [Data] = []
                        if hSetElem.tag == 0x04 {
                            hashes.append(data.subdata(in: hSetElem.contentRange))
                        } else {
                            var hsCur = hSetElem.contentRange.lowerBound
                            let hsLim = hSetElem.contentRange.upperBound
                            while hsCur < hsLim {
                                guard let hOct = readBERElement(in: data, at: &hsCur, limit: hsLim), hOct.tag == 0x04 else { return nil }
                                hashes.append(data.subdata(in: hOct.contentRange))
                            }
                        }
                        appleCDHashesDEREntries.append((hOID, hashes))
                    }
                }
            }

            guard let parsedSigAlg = readBERElement(in: data, at: &cur, limit: lim), parsedSigAlg.tag == 0x30 else {
                return nil
            }
            sigAlgSeq = parsedSigAlg
        } else if !requireSignedAttrs, nextElem.tag == 0x30 {
            retaggedSignedAttrs = Data()
            sigAlgSeq = nextElem
        } else {
            return nil
        }

        // 5. signatureAlgorithm (SEQUENCE 0x30 -> OID 0x06) & 6. signature (OCTET STRING 0x04)
        var saCur = sigAlgSeq.contentRange.lowerBound
        guard let sigOID = readBERElement(in: data, at: &saCur, limit: sigAlgSeq.contentRange.upperBound),
              sigOID.tag == 0x06,
              let sigOct = readBERElement(in: data, at: &cur, limit: lim),
              sigOct.tag == 0x04 else {
            return nil
        }

        return ParsedCMSSignerInfo(
            sid: sid,
            digestAlgorithmOID: digestAlgorithmOID,
            retaggedSignedAttrs: retaggedSignedAttrs,
            contentTypeValues: contentTypeValues,
            messageDigestValues: messageDigestValues,
            appleCDHashesPlistBlobs: appleCDHashesPlistBlobs,
            appleCDHashesDEREntries: appleCDHashesDEREntries,
            signatureAlgorithmOID: data.subdata(in: sigOID.contentRange),
            signatureBytes: data.subdata(in: sigOct.contentRange)
        )
    }

    /// Fallback certificate extractor used only to populate diagnostic `subjectSummary` on malformed CMS containers.
    private static func extractX509CertificatesFallback(_ rawCMS: Data) -> [Data] {
        let data = rawCMS.startIndex == 0 ? rawCMS : Data(rawCMS)
        let signedDataOIDTLV = Data([0x06, 0x09]) + oidSignedData
        guard let oidRange = data.range(of: signedDataOIDTLV) else { return [] }
        var cur = oidRange.upperBound
        guard let exp = readBERElement(in: data, at: &cur, limit: data.count), exp.tag == 0xA0 else { return [] }
        var expCur = exp.contentRange.lowerBound
        guard let sd = readBERElement(in: data, at: &expCur, limit: exp.contentRange.upperBound), sd.tag == 0x30 else { return [] }
        var sdCur = sd.contentRange.lowerBound
        let sdLim = sd.contentRange.upperBound
        guard readBERElement(in: data, at: &sdCur, limit: sdLim) != nil,
              readBERElement(in: data, at: &sdCur, limit: sdLim) != nil,
              readBERElement(in: data, at: &sdCur, limit: sdLim) != nil,
              let certSet = readBERElement(in: data, at: &sdCur, limit: sdLim),
              certSet.tag == 0xA0 else {
            return []
        }
        var cCur = certSet.contentRange.lowerBound
        let cLim = certSet.contentRange.upperBound
        var certs: [Data] = []
        while cCur < cLim && certs.count < 16 {
            guard let c = readBERElement(in: data, at: &cCur, limit: cLim), c.tag == 0x30 else { break }
            certs.append(data.subdata(in: c.fullRange))
        }
        return certs
    }

    private static func extractX509IssuerAndSerial(from certDER: Data) -> (issuerTLV: Data, serialBytes: Data)? {
        let data = certDER.startIndex == 0 ? certDER : Data(certDER)
        var cur = 0
        guard let outer = readBERElement(in: data, at: &cur, limit: data.count), outer.tag == 0x30 else { return nil }
        var tbsOuterCur = outer.contentRange.lowerBound
        guard let tbs = readBERElement(in: data, at: &tbsOuterCur, limit: outer.contentRange.upperBound), tbs.tag == 0x30 else { return nil }
        var tbsCur = tbs.contentRange.lowerBound
        let tbsLim = tbs.contentRange.upperBound
        guard var first = readBERElement(in: data, at: &tbsCur, limit: tbsLim) else { return nil }
        if first.tag == 0xA0 {
            guard let next = readBERElement(in: data, at: &tbsCur, limit: tbsLim) else { return nil }
            first = next
        }
        guard first.tag == 0x02,
              let sigAlg = readBERElement(in: data, at: &tbsCur, limit: tbsLim), sigAlg.tag == 0x30,
              let issuer = readBERElement(in: data, at: &tbsCur, limit: tbsLim), issuer.tag == 0x30 else {
            return nil
        }
        return (data.subdata(in: issuer.fullRange), data.subdata(in: first.contentRange))
    }

    private static func extractX509SubjectKeyIdentifier(from certDER: Data) -> Data? {
        let data = certDER.startIndex == 0 ? certDER : Data(certDER)
        var cur = 0
        guard let outer = readBERElement(in: data, at: &cur, limit: data.count), outer.tag == 0x30 else { return nil }
        var tbsOuterCur = outer.contentRange.lowerBound
        guard let tbs = readBERElement(in: data, at: &tbsOuterCur, limit: outer.contentRange.upperBound), tbs.tag == 0x30 else { return nil }
        var tbsCur = tbs.contentRange.lowerBound
        let tbsLim = tbs.contentRange.upperBound
        guard var first = readBERElement(in: data, at: &tbsCur, limit: tbsLim) else { return nil }
        if first.tag == 0xA0 {
            guard let next = readBERElement(in: data, at: &tbsCur, limit: tbsLim) else { return nil }
            first = next
        }
        guard first.tag == 0x02,
              let sigAlg = readBERElement(in: data, at: &tbsCur, limit: tbsLim), sigAlg.tag == 0x30,
              let issuer = readBERElement(in: data, at: &tbsCur, limit: tbsLim), issuer.tag == 0x30,
              let validity = readBERElement(in: data, at: &tbsCur, limit: tbsLim), validity.tag == 0x30,
              let subject = readBERElement(in: data, at: &tbsCur, limit: tbsLim), subject.tag == 0x30,
              let spki = readBERElement(in: data, at: &tbsCur, limit: tbsLim), spki.tag == 0x30 else {
            return nil
        }

        let oidSubjectKeyIdentifier = Data([0x55, 0x1D, 0x0E]) // 2.5.29.14
        while tbsCur < tbsLim {
            guard let elem = readBERElement(in: data, at: &tbsCur, limit: tbsLim) else { break }
            if elem.tag == 0xA3 {
                var extOuterCur = elem.contentRange.lowerBound
                guard let extSeq = readBERElement(in: data, at: &extOuterCur, limit: elem.contentRange.upperBound),
                      extSeq.tag == 0x30 else {
                    break
                }
                var extListCur = extSeq.contentRange.lowerBound
                let extListLim = extSeq.contentRange.upperBound
                while extListCur < extListLim {
                    guard let extItem = readBERElement(in: data, at: &extListCur, limit: extListLim),
                          extItem.tag == 0x30 else {
                        break
                    }
                    var eCur = extItem.contentRange.lowerBound
                    let eLim = extItem.contentRange.upperBound
                    guard let extOID = readBERElement(in: data, at: &eCur, limit: eLim),
                          extOID.tag == 0x06 else {
                        continue
                    }
                    guard data.subdata(in: extOID.contentRange) == oidSubjectKeyIdentifier else {
                        continue
                    }
                    guard var nextExtElem = readBERElement(in: data, at: &eCur, limit: eLim) else {
                        break
                    }
                    if nextExtElem.tag == 0x01 {
                        guard let valElem = readBERElement(in: data, at: &eCur, limit: eLim) else { break }
                        nextExtElem = valElem
                    }
                    if nextExtElem.tag == 0x04 {
                        var skiCur = nextExtElem.contentRange.lowerBound
                        if let skiOctet = readBERElement(in: data, at: &skiCur, limit: nextExtElem.contentRange.upperBound),
                           skiOctet.tag == 0x04,
                           !skiOctet.contentRange.isEmpty {
                            return data.subdata(in: skiOctet.contentRange)
                        }
                    }
                }
            }
        }

        // RFC 5280 §4.2.1.2 method 1 fallback when 2.5.29.14 extension is absent: SHA-1 of BIT STRING key bytes
        var spkiCur = spki.contentRange.lowerBound
        let spkiLim = spki.contentRange.upperBound
        if let _ = readBERElement(in: data, at: &spkiCur, limit: spkiLim),
           let bitStr = readBERElement(in: data, at: &spkiCur, limit: spkiLim),
           bitStr.tag == 0x03,
           bitStr.contentRange.count >= 2,
           data[bitStr.contentRange.lowerBound] == 0x00 {
            let keyBytes = data.subdata(in: (bitStr.contentRange.lowerBound + 1)..<bitStr.contentRange.upperBound)
            return Data(Insecure.SHA1.hash(data: keyBytes))
        }
        return nil
    }

    private static func extractX509NotBeforeDate(from certDER: Data) -> Date? {
        let data = certDER.startIndex == 0 ? certDER : Data(certDER)
        var cur = 0
        func readDERLen(_ pos: inout Int, _ lim: Int) -> Int? {
            guard pos < lim else { return nil }
            let b = data[pos]; pos += 1
            if (b & 0x80) == 0 { return Int(b) }
            let n = Int(b & 0x7F)
            guard n >= 1, n <= 4, pos + n <= lim else { return nil }
            var l = 0
            for _ in 0..<n { l = (l << 8) | Int(data[pos]); pos += 1 }
            return l
        }
        func skipDERTLV(_ pos: inout Int, _ lim: Int) -> Bool {
            guard pos < lim else { return false }
            pos += 1
            guard let l = readDERLen(&pos, lim), pos + l <= lim else { return false }
            pos += l
            return true
        }
        // Certificate SEQUENCE -> tbsCertificate SEQUENCE
        guard cur < data.count, data[cur] == 0x30 else { return nil }
        cur += 1
        guard let outerLen = readDERLen(&cur, data.count), cur + outerLen <= data.count else { return nil }
        let outerLim = cur + outerLen
        guard cur < outerLim, data[cur] == 0x30 else { return nil }
        cur += 1
        guard let tbsLen = readDERLen(&cur, outerLim), cur + tbsLen <= outerLim else { return nil }
        let tbsLim = cur + tbsLen
        // Optional [0] version
        if cur < tbsLim && data[cur] == 0xA0 {
            guard skipDERTLV(&cur, tbsLim) else { return nil }
        }
        // Skip serialNumber, signature, issuer
        guard skipDERTLV(&cur, tbsLim), skipDERTLV(&cur, tbsLim), skipDERTLV(&cur, tbsLim) else { return nil }
        // Validity SEQUENCE -> first element is notBefore (UTCTime 0x17 or GeneralizedTime 0x18)
        guard cur < tbsLim, data[cur] == 0x30 else { return nil }
        cur += 1
        guard let valLen = readDERLen(&cur, tbsLim), cur + valLen <= tbsLim else { return nil }
        let valLim = cur + valLen
        guard cur < valLim else { return nil }
        let timeTag = data[cur]
        cur += 1
        guard (timeTag == 0x17 || timeTag == 0x18),
              let tLen = readDERLen(&cur, valLim), cur + tLen <= valLim,
              let str = String(data: data.subdata(in: cur..<(cur + tLen)), encoding: .ascii) else {
            return nil
        }
        let digits = str.prefix { $0.isNumber }
        let year: Int
        let rest: Substring
        if timeTag == 0x17 && digits.count >= 10 {
            guard let yy = Int(digits.prefix(2)) else { return nil }
            year = yy >= 50 ? (1900 + yy) : (2000 + yy)
            rest = digits.dropFirst(2)
        } else if timeTag == 0x18 && digits.count >= 12 {
            guard let yyyy = Int(digits.prefix(4)) else { return nil }
            year = yyyy
            rest = digits.dropFirst(4)
        } else {
            return nil
        }
        guard rest.count >= 8,
              let month = Int(rest.prefix(2)),
              let day = Int(rest.dropFirst(2).prefix(2)),
              let hour = Int(rest.dropFirst(4).prefix(2)),
              let minute = Int(rest.dropFirst(6).prefix(2)) else {
            return nil
        }
        let sec = rest.count >= 10 ? (Int(rest.dropFirst(8).prefix(2)) ?? 0) : 0
        var comps = DateComponents()
        comps.calendar = Calendar(identifier: .gregorian)
        comps.timeZone = TimeZone(secondsFromGMT: 0)
        comps.year = year; comps.month = month; comps.day = day
        comps.hour = hour; comps.minute = minute; comps.second = sec
        return comps.date
    }

    // MARK: - XML Plist Parser

    private enum PlistLexicalOutcome {
        case matched(Int)
        case abortedAtNestedPlist(Int)
        case unclosedConstruct(Int)
        case reachedEOFWithoutClose
    }

    private struct PlistUnclosedMemo {
        var noCommentCloseFrom: Int = .max
        var noCDATACloseFrom: Int = .max
        var noPICloseFrom: Int = .max
        var noTagCloseFrom: Int = .max
    }

    private static func scanPlistLexical(
        base: UnsafePointer<UInt8>,
        count: Int,
        startOffset: Int,
        abortOnNestedPlist: Bool,
        memo: inout PlistUnclosedMemo
    ) -> PlistLexicalOutcome {
        var i = startOffset
        var inPlist = false

        @inline(__always)
        func isXMLSpace(_ b: UInt8) -> Bool {
            b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D
        }

        @inline(__always)
        func asciiLower(_ b: UInt8) -> UInt8 {
            (b >= 0x41 && b <= 0x5A) ? (b + 32) : b
        }

        @inline(__always)
        func matchesWordPlist(at pos: Int) -> Bool {
            guard pos + 5 <= count else { return false }
            return base[pos] == 0x70      // 'p'
                && base[pos + 1] == 0x6C  // 'l'
                && base[pos + 2] == 0x69  // 'i'
                && base[pos + 3] == 0x73  // 's'
                && base[pos + 4] == 0x74  // 't'
        }

        while i < count {
            if base[i] != 0x3C { // '<'
                i += 1
                continue
            }

            // 1. XML Comment: <!-- ... -->
            if i + 4 <= count,
               base[i + 1] == 0x21, base[i + 2] == 0x2D, base[i + 3] == 0x2D {
                let openPos = i
                if openPos >= memo.noCommentCloseFrom {
                    return .unclosedConstruct(openPos)
                }
                i += 4
                var closed = false
                while i + 3 <= count {
                    if base[i] == 0x2D && base[i + 1] == 0x2D && base[i + 2] == 0x3E {
                        i += 3
                        closed = true
                        break
                    }
                    i += 1
                }
                if !closed {
                    memo.noCommentCloseFrom = min(memo.noCommentCloseFrom, openPos)
                    return .unclosedConstruct(openPos)
                }
                continue
            }

            // 2. XML CDATA: <![CDATA[ ... ]]>
            if i + 9 <= count,
               base[i + 1] == 0x21, base[i + 2] == 0x5B,
               base[i + 3] == 0x43, base[i + 4] == 0x44, base[i + 5] == 0x41,
               base[i + 6] == 0x54, base[i + 7] == 0x41, base[i + 8] == 0x5B {
                let openPos = i
                if openPos >= memo.noCDATACloseFrom {
                    return .unclosedConstruct(openPos)
                }
                i += 9
                var closed = false
                while i + 3 <= count {
                    if base[i] == 0x5D && base[i + 1] == 0x5D && base[i + 2] == 0x3E {
                        i += 3
                        closed = true
                        break
                    }
                    i += 1
                }
                if !closed {
                    memo.noCDATACloseFrom = min(memo.noCDATACloseFrom, openPos)
                    return .unclosedConstruct(openPos)
                }
                continue
            }

            // 3. XML Processing Instruction: <? ... ?>
            if i + 2 <= count, base[i + 1] == 0x3F {
                let openPos = i
                if openPos >= memo.noPICloseFrom {
                    return .unclosedConstruct(openPos)
                }
                i += 2
                var closed = false
                while i + 2 <= count {
                    if base[i] == 0x3F && base[i + 1] == 0x3E {
                        i += 2
                        closed = true
                        break
                    }
                    i += 1
                }
                if !closed {
                    memo.noPICloseFrom = min(memo.noPICloseFrom, openPos)
                    return .unclosedConstruct(openPos)
                }
                continue
            }

            // 4. XML Declaration / DOCTYPE: <! ... > (supports internal subset [...] and nested comments/quotes)
            if i + 2 <= count, base[i + 1] == 0x21 {
                let openPos = i
                if i + 9 <= count,
                   asciiLower(base[i + 2]) == 0x64,
                   asciiLower(base[i + 3]) == 0x6F,
                   asciiLower(base[i + 4]) == 0x63,
                   asciiLower(base[i + 5]) == 0x74,
                   asciiLower(base[i + 6]) == 0x79,
                   asciiLower(base[i + 7]) == 0x70,
                   asciiLower(base[i + 8]) == 0x65
                {
                    i += 9
                } else {
                    i += 2
                }
                var bracketDepth = 0
                var quote: UInt8 = 0
                var closed = false
                while i < count {
                    let b = base[i]
                    if quote != 0 {
                        if b == quote { quote = 0 }
                        i += 1
                    } else if b == 0x22 || b == 0x27 {
                        quote = b
                        i += 1
                    } else if i + 4 <= count && b == 0x3C && base[i + 1] == 0x21 && base[i + 2] == 0x2D && base[i + 3] == 0x2D {
                        let cOpen = i
                        if cOpen >= memo.noCommentCloseFrom {
                            return .unclosedConstruct(cOpen)
                        }
                        i += 4
                        var cClosed = false
                        while i + 3 <= count {
                            if base[i] == 0x2D && base[i + 1] == 0x2D && base[i + 2] == 0x3E {
                                i += 3
                                cClosed = true
                                break
                            }
                            i += 1
                        }
                        if !cClosed {
                            memo.noCommentCloseFrom = min(memo.noCommentCloseFrom, cOpen)
                            return .unclosedConstruct(cOpen)
                        }
                    } else if b == 0x5B { // '['
                        bracketDepth += 1
                        i += 1
                    } else if b == 0x5D { // ']'
                        if bracketDepth > 0 { bracketDepth -= 1 }
                        i += 1
                    } else if b == 0x3E && bracketDepth == 0 { // '>'
                        i += 1
                        closed = true
                        break
                    } else {
                        i += 1
                    }
                }
                if !closed { return .unclosedConstruct(openPos) }
                continue
            }

            // 5. Closing </plist> tag
            if i + 7 <= count,
               base[i + 1] == 0x2F, // '/'
               matchesWordPlist(at: i + 2) {
                var j = i + 7
                while j < count && isXMLSpace(base[j]) {
                    j += 1
                }
                if j < count && base[j] == 0x3E { // '>'
                    if inPlist {
                        return .matched(j + 1)
                    }
                    i = j + 1
                    continue
                }
            }

            // 6. Opening <plist ...> tag
            if i + 6 <= count,
               matchesWordPlist(at: i + 1),
               (i + 6 < count && (base[i + 6] == 0x3E || base[i + 6] == 0x2F || isXMLSpace(base[i + 6]))) {
                if inPlist && abortOnNestedPlist {
                    return .abortedAtNestedPlist(i)
                }
                let openPos = i
                if openPos >= memo.noTagCloseFrom {
                    return .unclosedConstruct(openPos)
                }
                var j = i + 6
                var quote: UInt8 = 0
                var tagEnd: Int? = nil
                while j < count {
                    let b = base[j]
                    if quote != 0 {
                        if b == quote { quote = 0 }
                    } else if b == 0x22 || b == 0x27 {
                        quote = b
                    } else if b == 0x3E {
                        tagEnd = j
                        break
                    }
                    j += 1
                }
                guard let endIdx = tagEnd else {
                    memo.noTagCloseFrom = min(memo.noTagCloseFrom, openPos)
                    return .unclosedConstruct(openPos)
                }
                var back = endIdx - 1
                while back > i && isXMLSpace(base[back]) { back -= 1 }
                if base[back] == 0x2F {
                    if !inPlist {
                        return .matched(endIdx + 1)
                    }
                } else {
                    inPlist = true
                }
                i = endIdx + 1
                continue
            }

            // 7. Ordinary XML element tag <...>: skip quoted attributes up to '>'
            let openPos = i
            if openPos >= memo.noTagCloseFrom {
                return .unclosedConstruct(openPos)
            }
            i += 1
            var quote: UInt8 = 0
            var closed = false
            while i < count {
                let b = base[i]
                if quote != 0 {
                    if b == quote { quote = 0 }
                } else if b == 0x22 || b == 0x27 {
                    quote = b
                } else if b == 0x3E {
                    i += 1
                    closed = true
                    break
                }
                i += 1
            }
            if !closed {
                memo.noTagCloseFrom = min(memo.noTagCloseFrom, openPos)
                return .unclosedConstruct(openPos)
            }
        }
        return .reachedEOFWithoutClose
    }

    /// Scans `rawData` from `startOffset` using XML 1.0 lexical rules (skipping `<!--...-->` comments,
    /// `<![CDATA[...]]>` blocks, `<?...?>` processing instructions, `<!DOCTYPE ... [...]>` subsets,
    /// and quoted tag attributes) to return the byte offset immediately after the matching top-level `</plist>`
    /// (or self-closing `<plist.../>`). Runs in strict O(N) time with zero backtracking.
    public static func findMatchingPlistEnd(in rawData: Data, from startOffset: Int = 0) -> Int? {
        let data = rawData.startIndex == 0 ? rawData : Data(rawData)
        guard startOffset >= 0, startOffset < data.count else { return nil }
        return data.withUnsafeBytes { raw -> Int? in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            var memo = PlistUnclosedMemo()
            if case .matched(let endOff) = scanPlistLexical(
                base: base,
                count: raw.count,
                startOffset: startOffset,
                abortOnNestedPlist: true,
                memo: &memo
            ) {
                return endOff
            }
            return nil
        }
    }

    /// Locates top-level XML `<plist>...</plist>` document byte ranges inside `rawData`
    /// (including concatenated XML plist streams or CMS-wrapped provisioning data) in guaranteed O(N) worst-case time,
    /// ignoring literal `</plist>` tokens inside XML comments or CDATA sections and never re-scanning across unclosed `<plist>` runs.
    public static func scanXMLPlistDocumentRanges(in rawData: Data, maxDocuments: Int = 4096) -> [Range<Int>] {
        let data = rawData.startIndex == 0 ? rawData : Data(rawData)
        guard data.count >= 8, maxDocuments > 0 else { return [] }
        let xmlToken = Data("<?xml".utf8)
        let plistToken = Data("<plist".utf8)
        let closePlistToken = Data("</plist".utf8)
        let selfCloseToken = Data("/>".utf8)

        // O(N) fast-reject if neither `</plist` nor `/>` exists anywhere in the buffer
        guard data.range(of: closePlistToken) != nil || data.range(of: selfCloseToken) != nil else {
            return []
        }

        return data.withUnsafeBytes { raw -> [Range<Int>] in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return [] }
            let count = raw.count
            var memo = PlistUnclosedMemo()
            var ranges: [Range<Int>] = []
            var cursor = 0

            while cursor < count && ranges.count < maxDocuments {
                guard let plistRange = data.range(of: plistToken, options: [], in: cursor..<count) else {
                    break
                }
                let afterPlist = plistRange.upperBound
                guard afterPlist < count else { break }
                let nextByte = base[afterPlist]
                guard nextByte == 0x3E || nextByte == 0x2F || nextByte == 0x20 || nextByte == 0x09 || nextByte == 0x0A || nextByte == 0x0D else {
                    cursor = afterPlist
                    continue
                }

                // Skip top-level `<!-- ... -->` comment blocks that enclose `plistRange.lowerBound` without crossing `<?xml`
                let commentWindowStart = max(cursor, plistRange.lowerBound - 4096)
                if commentWindowStart < plistRange.lowerBound,
                   let cOpenRange = data.range(of: Data("<!--".utf8), options: .backwards, in: commentWindowStart..<plistRange.lowerBound),
                   data.range(of: Data("-->".utf8), options: [], in: cOpenRange.upperBound..<plistRange.lowerBound) == nil,
                   data.range(of: xmlToken, options: [], in: cOpenRange.upperBound..<plistRange.lowerBound) == nil,
                   cOpenRange.lowerBound < memo.noCommentCloseFrom,
                   let cCloseRange = data.range(of: Data("-->".utf8), options: [], in: afterPlist..<count) {
                    cursor = cCloseRange.upperBound
                    continue
                }

                let prologWindowStart = max(cursor, plistRange.lowerBound - 512)
                if prologWindowStart < plistRange.lowerBound,
                   let xmlRange = data.range(of: xmlToken, options: .backwards, in: prologWindowStart..<plistRange.lowerBound) {
                    let prologOutcome = scanPlistLexical(
                        base: base,
                        count: count,
                        startOffset: xmlRange.lowerBound,
                        abortOnNestedPlist: true,
                        memo: &memo
                    )
                    if case .matched(let endWithProlog) = prologOutcome, endWithProlog > afterPlist {
                        ranges.append(xmlRange.lowerBound..<endWithProlog)
                        cursor = endWithProlog
                        continue
                    }
                }

                let outcome = scanPlistLexical(
                    base: base,
                    count: count,
                    startOffset: plistRange.lowerBound,
                    abortOnNestedPlist: true,
                    memo: &memo
                )
                switch outcome {
                case .matched(let docEnd) where docEnd > plistRange.lowerBound:
                    ranges.append(plistRange.lowerBound..<docEnd)
                    cursor = docEnd
                case .abortedAtNestedPlist(let nextPlistOff):
                    cursor = max(afterPlist, nextPlistOff)
                case .unclosedConstruct(let unclosedPos):
                    cursor = max(afterPlist, unclosedPos + 2)
                case .reachedEOFWithoutClose, .matched:
                    // Clean lexical scan from `plistRange.lowerBound` reached EOF without encountering a nested `<plist>` or `</plist>`:
                    // zero valid `<plist>` documents can exist in `afterPlist..<count`.
                    return ranges
                }
            }
            return ranges
        }
    }

    /// Detects UTF-16LE / UTF-16BE encoded XML plists (with or without BOM) and transcodes to UTF-8 so
    /// trailing `0x00` bytes never corrupt UTF-16LE code units and O(N) lexical comment/CDATA scanning works uniformly.
    internal static func transcodeUTF16XMLToUTF8IfNeeded(_ rawInput: Data) -> Data? {
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
        guard data.count >= 4 else { return nil }
        let b0 = data[0], b1 = data[1], b2 = data[2], b3 = data[3]
        var isUTF16LE = (b0 == 0xFF && b1 == 0xFE)
            || (b0 == 0x3C && b1 == 0x00 && (b2 == 0x3F || b2 == 0x70 || b2 == 0x21) && b3 == 0x00)
        var isUTF16BE = (b0 == 0xFE && b1 == 0xFF)
            || (b0 == 0x00 && b1 == 0x3C && b2 == 0x00 && (b3 == 0x3F || b3 == 0x70 || b3 == 0x21))
        var startIdx = ((b0 == 0xFF && b1 == 0xFE) || (b0 == 0xFE && b1 == 0xFF)) ? 2 : 0
        if !isUTF16LE && !isUTF16BE {
            var off = 0
            while off + 4 <= data.count {
                let c0 = data[off], c1 = data[off + 1]
                let isBEWs = (c0 == 0x00) && (c1 == 0x20 || c1 == 0x09 || c1 == 0x0A || c1 == 0x0D || c1 == 0x00)
                let isLEWs = (c1 == 0x00) && (c0 == 0x20 || c0 == 0x09 || c0 == 0x0A || c0 == 0x0D || c0 == 0x00)
                if isBEWs || isLEWs {
                    off += 2
                    continue
                }
                break
            }
            if off + 4 <= data.count {
                let u0 = data[off], u1 = data[off + 1], u2 = data[off + 2], u3 = data[off + 3]
                if u0 == 0xFF && u1 == 0xFE {
                    var bodyOff = off + 2
                    while bodyOff + 4 <= data.count {
                        let c0 = data[bodyOff], c1 = data[bodyOff + 1]
                        if c1 == 0x00 && (c0 == 0x20 || c0 == 0x09 || c0 == 0x0A || c0 == 0x0D || c0 == 0x00) {
                            bodyOff += 2
                        } else {
                            break
                        }
                    }
                    if bodyOff + 4 <= data.count,
                       data[bodyOff] == 0x3C && data[bodyOff + 1] == 0x00
                        && (data[bodyOff + 2] == 0x3F || data[bodyOff + 2] == 0x70 || data[bodyOff + 2] == 0x21)
                        && data[bodyOff + 3] == 0x00 {
                        isUTF16LE = true
                        startIdx = bodyOff
                    }
                } else if u0 == 0xFE && u1 == 0xFF {
                    var bodyOff = off + 2
                    while bodyOff + 4 <= data.count {
                        let c0 = data[bodyOff], c1 = data[bodyOff + 1]
                        if c0 == 0x00 && (c1 == 0x20 || c1 == 0x09 || c1 == 0x0A || c1 == 0x0D || c1 == 0x00) {
                            bodyOff += 2
                        } else {
                            break
                        }
                    }
                    if bodyOff + 4 <= data.count,
                       data[bodyOff] == 0x00 && data[bodyOff + 1] == 0x3C && data[bodyOff + 2] == 0x00
                        && (data[bodyOff + 3] == 0x3F || data[bodyOff + 3] == 0x70 || data[bodyOff + 3] == 0x21) {
                        isUTF16BE = true
                        startIdx = bodyOff
                    }
                } else if u0 == 0x3C && u1 == 0x00 && (u2 == 0x3F || u2 == 0x70 || u2 == 0x21) && u3 == 0x00 {
                    isUTF16LE = true
                    startIdx = off
                } else if u0 == 0x00 && u1 == 0x3C && u2 == 0x00 && (u3 == 0x3F || u3 == 0x70 || u3 == 0x21) {
                    isUTF16BE = true
                    startIdx = off
                }
            }
        }
        guard isUTF16LE || isUTF16BE else { return nil }
        let evenCount = startIdx + ((data.count - startIdx) & ~1)
        guard evenCount - startIdx >= 4 else { return nil }
        let slice = evenCount == data.count ? data : data.prefix(evenCount)
        let encoding: String.Encoding = isUTF16LE ? .utf16LittleEndian : .utf16BigEndian
        guard startIdx < slice.count,
              let decoded = String(data: slice.subdata(in: startIdx..<slice.count), encoding: encoding) else {
            return nil
        }
        return Data(decoded.utf8)
    }

    private static func recoverFirstNonEmptyPlistDict(
        initialDict: [String: Any],
        utf8XMLData: Data
    ) -> [String: Any] {
        if !initialDict.isEmpty {
            return initialDict
        }
        let docRanges = scanXMLPlistDocumentRanges(in: utf8XMLData, maxDocuments: 4096)
        if docRanges.count <= 1 {
            return initialDict
        }
        for r in docRanges.dropFirst() {
            if let nextObj = try? PropertyListSerialization.propertyList(from: utf8XMLData.subdata(in: r), options: [], format: nil),
               let nextDict = nextObj as? [String: Any],
               !nextDict.isEmpty {
                return nextDict
            }
        }
        return initialDict
    }

    public func parseXMLPlist(_ data: Data) throws -> [String: Any] {
        guard !data.isEmpty else { return [:] }
        // 1. Lossless direct PropertyListSerialization first (preserves bplist00 32-byte trailers AND UTF-16LE trailing 0x00 code-unit bytes).
        //    If the first document parses to an empty dictionary `[:]` while additional `<plist>` documents follow in the same blob,
        //    inspect subsequent documents so a leading `<plist><dict/></plist>` decoy cannot shadow trailing entitlements.
        if let directObj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
           let directDict = directObj as? [String: Any] {
            if !directDict.isEmpty {
                return directDict
            }
            let utf8Probe = Self.transcodeUTF16XMLToUTF8IfNeeded(data) ?? (data.startIndex == 0 ? data : Data(data))
            return Self.recoverFirstNonEmptyPlistDict(initialDict: directDict, utf8XMLData: utf8Probe)
        }

        // 2. Transcode UTF-16LE / UTF-16BE XML plists (if padded with trailing nulls/bytes) into UTF-8 before byte-trimming & lexical scanning
        let workingData = Self.transcodeUTF16XMLToUTF8IfNeeded(data) ?? (data.startIndex == 0 ? data : Data(data))

        // 3. Strip trailing null bytes / ASCII whitespace padding (added by codesign/ldid)
        var trimEnd = workingData.count
        while trimEnd > 0 {
            let b = workingData[trimEnd - 1]
            if b == 0 || b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D {
                trimEnd -= 1
            } else {
                break
            }
        }
        let clean = trimEnd == workingData.count ? workingData : workingData.subdata(in: 0..<trimEnd)
        guard !clean.isEmpty else { return [:] }
        do {
            let obj = try PropertyListSerialization.propertyList(from: clean, options: [], format: nil)
            let dict = (obj as? [String: Any]) ?? [:]
            return Self.recoverFirstNonEmptyPlistDict(initialDict: dict, utf8XMLData: clean)
        } catch let primaryError {
            // XNU's libkern OSUnserializeXML stops parsing at the matching top-level closing `</plist>` tag and ignores
            // trailing padding/bytes, while valid XML may embed thousands of `</plist>` tokens inside `<!--...-->` comments
            // or `<![CDATA[...]]>` blocks. Use O(N) comment/CDATA-aware lexical scanning without truncation or quadratic retries.
            if let endOffset = Self.findMatchingPlistEnd(in: clean, from: 0), endOffset > 0, endOffset <= clean.count {
                let trimmedXML = clean.subdata(in: 0..<endOffset)
                if let obj = try? PropertyListSerialization.propertyList(from: trimmedXML, options: [], format: nil) {
                    let dict = (obj as? [String: Any]) ?? [:]
                    return Self.recoverFirstNonEmptyPlistDict(initialDict: dict, utf8XMLData: clean)
                }
            }
            var fallbackEmptyDict: [String: Any]? = nil
            for docRange in Self.scanXMLPlistDocumentRanges(in: clean, maxDocuments: 4096) {
                let slice = clean.subdata(in: docRange)
                if let obj = try? PropertyListSerialization.propertyList(from: slice, options: [], format: nil),
                   let dict = obj as? [String: Any] {
                    if !dict.isEmpty {
                        return dict
                    }
                    if fallbackEmptyDict == nil {
                        fallbackEmptyDict = dict
                    }
                }
            }
            if let empty = fallbackEmptyDict {
                return empty
            }
            throw CSBlobError.malformedXMLPlist(reason: primaryError.localizedDescription)
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
            guard valueLength >= 1 else {
                throw CSBlobError.malformedDER(reason: "Invalid zero-length DER INTEGER")
            }
            let isNegative = (valSlice[0] & 0x80) != 0
            var val: Int64 = isNegative ? -1 : 0
            var anyNonZero = false
            for b in valSlice {
                if b != 0 { anyNonZero = true }
                val = (val << 8) | Int64(b)
            }
            // Prevent >64-bit positive DER integers with trailing zero octets (e.g. 0x01 0x00 x 8 = 2^64)
            // from wrapping left-shift to Int64(0) and falsely appearing as explicit false/0 in entitlement checks.
            if val == 0 && anyNonZero {
                val = isNegative ? -1 : 1
            }
            return .integer(val)

        case 0x0c, 0x13, 0x14, 0x15, 0x16, 0x19, 0x1a, 0x1b: // UTF8String, PrintableString, T61, Videotex, IA5String, Graphic, VisibleString, GeneralString
            let str = String(decoding: valSlice, as: UTF8.self)
            return .string(str)

        case 0x1e: // BMPString (UTF-16BE)
            if let str = String(data: valData, encoding: .utf16BigEndian) {
                return .string(str)
            }
            return .data(valData)

        case 0x1c: // UniversalString (UTF-32BE)
            if let str = String(data: valData, encoding: .utf32BigEndian) {
                return .string(str)
            }
            return .data(valData)

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

        func isAlternatingKeyValueList(_ items: [Node], requireNonStringValue: Bool) -> Bool {
            guard items.count >= 4, items.count % 2 == 0 else { return false }
            var sawNonStringValue = false
            for i in stride(from: 0, to: items.count, by: 2) {
                guard case .string(let k) = items[i], !k.isEmpty else {
                    return false
                }
                if case .string = items[i + 1] {
                    continue
                }
                sawNonStringValue = true
            }
            return !requireNonStringValue || sawNonStringValue
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
                            sub = CSBlobParser.mergeEntitlementDictionaries(sub, [k: convertVal(v)])
                        }
                        return sub
                    }
                    if isAlternatingKeyValueList(items, requireNonStringValue: true) {
                        var sub: [String: Any] = [:]
                        for i in stride(from: 0, to: items.count, by: 2) {
                            if case .string(let k) = items[i] {
                                sub = CSBlobParser.mergeEntitlementDictionaries(sub, [k: convertVal(items[i + 1])])
                            }
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
                    dict = CSBlobParser.mergeEntitlementDictionaries(dict, [k: convertVal(v)])
                    return
                }
                let pairs = children.compactMap(asPair)
                if !children.isEmpty && pairs.count == children.count {
                    for (k, v) in pairs {
                        dict = CSBlobParser.mergeEntitlementDictionaries(dict, [k: convertVal(v)])
                    }
                    return
                }
                if isAlternatingKeyValueList(children, requireNonStringValue: false) {
                    for i in stride(from: 0, to: children.count, by: 2) {
                        if case .string(let k) = children[i] {
                            dict = CSBlobParser.mergeEntitlementDictionaries(dict, [k: convertVal(children[i + 1])])
                        }
                    }
                    return
                }
                for child in children {
                    if let (k, v) = asPair(child) {
                        dict = CSBlobParser.mergeEntitlementDictionaries(dict, [k: convertVal(v)])
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
