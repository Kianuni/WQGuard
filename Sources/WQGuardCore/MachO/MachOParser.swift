//
//  MachOParser.swift
//  WQGuardCore
//
//  Created by M2 MachO Parser Explorer.
//  100% Read-Only, Bounds-Checked Mach-O & Universal FAT Binary Parser.
//

import Foundation
import MachO

// MARK: - Mach-O Architecture & CPU Types

public enum MachOArchitecture: Hashable, Sendable, CustomStringConvertible {
    case arm64
    case arm64e
    case arm64_32
    case armv7
    case armv7s
    case x86_64
    case i386
    case unknown(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t)

    public var cpuType: cpu_type_t {
        switch self {
        case .arm64, .arm64e: return CPU_TYPE_ARM64
        case .arm64_32: return CPU_TYPE_ARM64_32
        case .armv7, .armv7s: return CPU_TYPE_ARM
        case .x86_64: return CPU_TYPE_X86_64
        case .i386: return CPU_TYPE_I386
        case .unknown(let type, _): return type
        }
    }

    public var is64Bit: Bool {
        switch self {
        case .arm64, .arm64e, .x86_64:
            return true
        case .arm64_32, .armv7, .armv7s, .i386:
            return false
        case .unknown(let type, _):
            return (type & CPU_ARCH_ABI64) != 0
        }
    }

    public var description: String {
        switch self {
        case .arm64: return "arm64"
        case .arm64e: return "arm64e"
        case .arm64_32: return "arm64_32"
        case .armv7: return "armv7"
        case .armv7s: return "armv7s"
        case .x86_64: return "x86_64"
        case .i386: return "i386"
        case .unknown(let type, let subtype): return "unknown(cpu: \(type), sub: \(subtype))"
        }
    }

    public static func from(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t) -> MachOArchitecture {
        let cleanSubtype = cpu_subtype_t(bitPattern: UInt32(bitPattern: cpuSubtype) & ~CPU_SUBTYPE_MASK)
        switch cpuType {
        case CPU_TYPE_ARM64:
            if cleanSubtype == CPU_SUBTYPE_ARM64E {
                return .arm64e
            }
            return .arm64
        case CPU_TYPE_ARM64_32:
            return .arm64_32
        case CPU_TYPE_ARM:
            if cleanSubtype == CPU_SUBTYPE_ARM_V7S {
                return .armv7s
            }
            return .armv7
        case CPU_TYPE_X86_64:
            return .x86_64
        case CPU_TYPE_I386:
            return .i386
        default:
            return .unknown(cpuType: cpuType, cpuSubtype: cpuSubtype)
        }
    }
}

// MARK: - Mach-O Parser Error

public enum MachOParserError: Error, CustomStringConvertible, Sendable, Equatable {
    case fileTooSmall(actual: Int, minimum: Int)
    case truncatedHeader(expected: Int, actual: Int)
    case invalidMagic(UInt32)
    case corruptedFatHeader(reason: String)
    case fatBinaryEmpty
    case sliceOutOfBounds(offset: UInt64, size: UInt64, total: Int)
    case architectureNotFound(preferred: String, available: [String])
    case loadCommandsOutOfBounds(expectedSize: Int, actualSize: Int)
    case invalidCommandCount(ncmds: UInt32, sizeofcmds: UInt32)
    case invalidCommandSize(cmd: UInt32, cmdsize: UInt32, offset: Int)
    case commandOutOfBounds(cmd: UInt32, cmdsize: UInt32, cursor: Int, totalCmdSize: Int)
    case malformedCommand(cmd: UInt32, reason: String)
    case symbolTableOutOfBounds(offset: UInt32, size: UInt64, total: Int)
    case stringTableOutOfBounds(offset: UInt32, size: UInt32, total: Int)
    case codeSignatureOutOfBounds(offset: UInt32, size: UInt32, total: Int)

    public var description: String {
        switch self {
        case .fileTooSmall(let actual, let min):
            return "File is too small (\(actual) bytes, minimum is \(min) bytes)"
        case .truncatedHeader(let exp, let act):
            return "Truncated Mach-O header: expected at least \(exp) bytes, got \(act) bytes"
        case .invalidMagic(let magic):
            return String(format: "Invalid Mach-O magic number: 0x%08x", magic)
        case .corruptedFatHeader(let reason):
            return "Corrupted Universal FAT header: \(reason)"
        case .fatBinaryEmpty:
            return "Universal FAT binary contains zero architecture slices"
        case .sliceOutOfBounds(let off, let sz, let total):
            return "Architecture slice at offset \(off) with size \(sz) extends beyond binary EOF (\(total) bytes)"
        case .architectureNotFound(let pref, let avail):
            return "Requested architecture '\(pref)' not found in binary (available: \(avail.joined(separator: ", ")))"
        case .loadCommandsOutOfBounds(let exp, let act):
            return "Mach-O load commands table requires \(exp) bytes, but binary slice has only \(act) bytes"
        case .invalidCommandCount(let ncmds, let sizeofcmds):
            return "Invalid Mach-O command count: ncmds=\(ncmds) exceeds capacity of sizeofcmds=\(sizeofcmds)"
        case .invalidCommandSize(let cmd, let cmdsize, let offset):
            return String(format: "Invalid load command size %u at offset %d (cmd: 0x%x); must be >= 8 and 4-byte aligned", cmdsize, offset, cmd)
        case .commandOutOfBounds(let cmd, let cmdsize, let cursor, let total):
            return String(format: "Load command 0x%x with size %u at offset %d exceeds load commands bounds (%d)", cmd, cmdsize, cursor, total)
        case .malformedCommand(let cmd, let reason):
            return String(format: "Malformed load command 0x%x: %@", cmd, reason)
        case .symbolTableOutOfBounds(let off, let sz, let total):
            return "Symbol table (symoff: \(off), size: \(sz)) extends beyond binary slice bounds (\(total))"
        case .stringTableOutOfBounds(let off, let sz, let total):
            return "String table (stroff: \(off), strsize: \(sz)) extends beyond binary slice bounds (\(total))"
        case .codeSignatureOutOfBounds(let off, let sz, let total):
            return "Code signature (dataoff: \(off), datasize: \(sz)) extends beyond binary slice bounds (\(total))"
        }
    }
}

// MARK: - Safe Binary Reader Utility

public struct BinaryReader: Sendable {
    public let data: Data

    public var count: Int { data.count }

    public init(data: Data) {
        self.data = data
    }

    @inlinable
    public func inRange(offset: Int, length: Int) -> Bool {
        guard offset >= 0, length >= 0 else { return false }
        guard offset <= data.count else { return false }
        return length <= data.count - offset
    }

    public func readUInt16(at offset: Int, swapped: Bool = false) -> UInt16? {
        guard inRange(offset: offset, length: 2) else { return nil }
        return data.withUnsafeBytes { raw in
            let val = raw.loadUnaligned(fromByteOffset: offset, as: UInt16.self)
            return swapped ? val.byteSwapped : val
        }
    }

    public func readUInt32(at offset: Int, swapped: Bool = false) -> UInt32? {
        guard inRange(offset: offset, length: 4) else { return nil }
        return data.withUnsafeBytes { raw in
            let val = raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
            return swapped ? val.byteSwapped : val
        }
    }

    public func readUInt64(at offset: Int, swapped: Bool = false) -> UInt64? {
        guard inRange(offset: offset, length: 8) else { return nil }
        return data.withUnsafeBytes { raw in
            let val = raw.loadUnaligned(fromByteOffset: offset, as: UInt64.self)
            return swapped ? val.byteSwapped : val
        }
    }

    public func readInt32(at offset: Int, swapped: Bool = false) -> Int32? {
        guard let u = readUInt32(at: offset, swapped: swapped) else { return nil }
        return Int32(bitPattern: u)
    }

    public func readFixedString(at offset: Int, maxLength: Int) -> String? {
        guard inRange(offset: offset, length: maxLength) else { return nil }
        return data.withUnsafeBytes { raw in
            guard let ptr = raw.baseAddress?.advanced(by: offset).assumingMemoryBound(to: CChar.self) else { return nil }
            var len = 0
            while len < maxLength && ptr[len] != 0 {
                len += 1
            }
            let sub = data.subdata(in: offset..<(offset + len))
            return String(data: sub, encoding: .utf8) ?? String(data: sub, encoding: .ascii)
        }
    }

    public func readNullTerminatedString(at offset: Int, maxScanLength: Int) -> String? {
        guard inRange(offset: offset, length: 1) else { return nil }
        let available = min(maxScanLength, data.count - offset)
        return data.withUnsafeBytes { raw in
            guard let ptr = raw.baseAddress?.advanced(by: offset).assumingMemoryBound(to: CChar.self) else { return nil }
            var len = 0
            while len < available && ptr[len] != 0 {
                len += 1
            }
            let sub = data.subdata(in: offset..<(offset + len))
            return String(data: sub, encoding: .utf8) ?? String(data: sub, encoding: .ascii)
        }
    }

    public func subdata(offset: Int, length: Int) -> Data? {
        guard inRange(offset: offset, length: length) else { return nil }
        return data.subdata(in: offset..<(offset + length))
    }
}

// MARK: - Mach-O Data Structures

public struct MachOSliceInfo: Sendable, Equatable {
    public let cpuType: cpu_type_t
    public let cpuSubtype: cpu_subtype_t
    public let offset: UInt64
    public let size: UInt64
    public let align: UInt32

    public var architecture: MachOArchitecture {
        MachOArchitecture.from(cpuType: cpuType, cpuSubtype: cpuSubtype)
    }

    public var is64Bit: Bool {
        (cpuType & CPU_ARCH_ABI64) != 0
    }

    public init(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t, offset: UInt64, size: UInt64, align: UInt32) {
        self.cpuType = cpuType
        self.cpuSubtype = cpuSubtype
        self.offset = offset
        self.size = size
        self.align = align
    }
}

public struct MachOSection: Sendable, Equatable {
    public let sectionName: String
    public let segmentName: String
    public let address: UInt64
    public let size: UInt64
    public let offset: UInt32
    public let align: UInt32
    public let reloff: UInt32
    public let nreloc: UInt32
    public let flags: UInt32

    public init(sectionName: String, segmentName: String, address: UInt64, size: UInt64, offset: UInt32, align: UInt32, reloff: UInt32, nreloc: UInt32, flags: UInt32) {
        self.sectionName = sectionName
        self.segmentName = segmentName
        self.address = address
        self.size = size
        self.offset = offset
        self.align = align
        self.reloff = reloff
        self.nreloc = nreloc
        self.flags = flags
    }
}

public struct MachOSegment: Sendable {
    public let name: String
    public let vmAddress: UInt64
    public let vmSize: UInt64
    public let fileOffset: UInt64
    public let fileSize: UInt64
    public let maxProtection: Int32
    public let initialProtection: Int32
    public let sectionCount: UInt32
    public let flags: UInt32
    public let sections: [MachOSection]

    public init(name: String, vmAddress: UInt64, vmSize: UInt64, fileOffset: UInt64, fileSize: UInt64, maxProtection: Int32, initialProtection: Int32, sectionCount: UInt32, flags: UInt32, sections: [MachOSection]) {
        self.name = name
        self.vmAddress = vmAddress
        self.vmSize = vmSize
        self.fileOffset = fileOffset
        self.fileSize = fileSize
        self.maxProtection = maxProtection
        self.initialProtection = initialProtection
        self.sectionCount = sectionCount
        self.flags = flags
        self.sections = sections
    }

    public var fileRange: Range<Int>? {
        guard fileSize > 0 else { return nil }
        guard let start = Int(exactly: fileOffset) else { return nil }
        let (endOffset, overflow) = fileOffset.addingReportingOverflow(fileSize)
        guard !overflow, let end = Int(exactly: endOffset) else { return nil }
        return start..<end
    }
}

public struct MachOEncryptionInfo: Sendable, Equatable {
    public let cryptoff: UInt32
    public let cryptsize: UInt32
    public let cryptid: UInt32
    public let is64Bit: Bool

    public init(cryptoff: UInt32, cryptsize: UInt32, cryptid: UInt32, is64Bit: Bool) {
        self.cryptoff = cryptoff
        self.cryptsize = cryptsize
        self.cryptid = cryptid
        self.is64Bit = is64Bit
    }

    public var isFairPlayEncrypted: Bool { cryptid != 0 }

    public var encryptedRange: Range<Int>? {
        guard isFairPlayEncrypted && cryptsize > 0 else { return nil }
        guard let start = Int(exactly: cryptoff) else { return nil }
        let (endOffset, overflow) = UInt64(cryptoff).addingReportingOverflow(UInt64(cryptsize))
        guard !overflow, let end = Int(exactly: endOffset) else { return nil }
        return start..<end
    }
}

public struct MachODylib: Sendable, Equatable {
    public let path: String
    public let isWeak: Bool
    public let timestamp: UInt32
    public let currentVersion: UInt32
    public let compatibilityVersion: UInt32

    public init(path: String, isWeak: Bool, timestamp: UInt32, currentVersion: UInt32, compatibilityVersion: UInt32) {
        self.path = path
        self.isWeak = isWeak
        self.timestamp = timestamp
        self.currentVersion = currentVersion
        self.compatibilityVersion = compatibilityVersion
    }

    public var formattedCurrentVersion: String {
        let major = (currentVersion >> 16) & 0xffff
        let minor = (currentVersion >> 8) & 0xff
        let patch = currentVersion & 0xff
        return "\(major).\(minor).\(patch)"
    }
}

public struct MachOSymtab: Sendable, Equatable {
    public let symoff: UInt32
    public let nsyms: UInt32
    public let stroff: UInt32
    public let strsize: UInt32

    public init(symoff: UInt32, nsyms: UInt32, stroff: UInt32, strsize: UInt32) {
        self.symoff = symoff
        self.nsyms = nsyms
        self.stroff = stroff
        self.strsize = strsize
    }

    public func parseSymbols(from data: Data, is64Bit: Bool, isSwapped: Bool) -> [String] {
        let reader = BinaryReader(data: data)
        let entrySize = is64Bit ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size
        let totalSymBytes = UInt64(nsyms) * UInt64(entrySize)
        guard UInt64(symoff) + totalSymBytes <= UInt64(data.count),
              UInt64(stroff) + UInt64(strsize) <= UInt64(data.count) else {
            return []
        }

        var results: [String] = []
        results.reserveCapacity(Int(min(nsyms, 8192)))

        for i in 0..<Int(nsyms) {
            let entryOffset = Int(symoff) + i * entrySize
            guard let strx = reader.readUInt32(at: entryOffset, swapped: isSwapped) else { continue }
            guard strx > 0, strx < strsize else { continue }
            let strOffset = Int(stroff) + Int(strx)
            let maxLen = Int(strsize) - Int(strx)
            if let name = reader.readNullTerminatedString(at: strOffset, maxScanLength: maxLen), !name.isEmpty {
                results.append(name)
            }
        }
        return results
    }
}

public struct MachOCodeSignature: Sendable, Equatable {
    public let dataoff: UInt32
    public let datasize: UInt32

    public init(dataoff: UInt32, datasize: UInt32) {
        self.dataoff = dataoff
        self.datasize = datasize
    }
}

// MARK: - Parsed Mach-O File Model

public struct MachOFile: Sendable {
    public let magic: UInt32
    public let cpuType: cpu_type_t
    public let cpuSubtype: cpu_subtype_t
    public let fileType: UInt32
    public let ncmds: UInt32
    public let sizeofcmds: UInt32
    public let flags: UInt32
    public let is64Bit: Bool
    public let isSwapped: Bool
    public let sliceData: Data
    public let slicesInContainer: [MachOSliceInfo]

    public let segments: [MachOSegment]
    public let encryptionInfo: MachOEncryptionInfo?
    public let linkedDylibs: [MachODylib]
    public let symtab: MachOSymtab?
    public let codeSignature: MachOCodeSignature?

    public init(
        magic: UInt32,
        cpuType: cpu_type_t,
        cpuSubtype: cpu_subtype_t,
        fileType: UInt32,
        ncmds: UInt32,
        sizeofcmds: UInt32,
        flags: UInt32,
        is64Bit: Bool,
        isSwapped: Bool,
        sliceData: Data,
        slicesInContainer: [MachOSliceInfo],
        segments: [MachOSegment],
        encryptionInfo: MachOEncryptionInfo?,
        linkedDylibs: [MachODylib],
        symtab: MachOSymtab?,
        codeSignature: MachOCodeSignature?
    ) {
        self.magic = magic
        self.cpuType = cpuType
        self.cpuSubtype = cpuSubtype
        self.fileType = fileType
        self.ncmds = ncmds
        self.sizeofcmds = sizeofcmds
        self.flags = flags
        self.is64Bit = is64Bit
        self.isSwapped = isSwapped
        self.sliceData = sliceData
        self.slicesInContainer = slicesInContainer
        self.segments = segments
        self.encryptionInfo = encryptionInfo
        self.linkedDylibs = linkedDylibs
        self.symtab = symtab
        self.codeSignature = codeSignature
    }

    public var architecture: MachOArchitecture {
        MachOArchitecture.from(cpuType: cpuType, cpuSubtype: cpuSubtype)
    }

    public var textSegment: MachOSegment? {
        segments.first { $0.name == "__TEXT" }
    }

    public var linkeditSegment: MachOSegment? {
        segments.first { $0.name == "__LINKEDIT" }
    }

    public var dataSegment: MachOSegment? {
        segments.first { $0.name == "__DATA" || $0.name == "__DATA_CONST" }
    }

    public var cryptid: UInt32 {
        encryptionInfo?.cryptid ?? 0
    }

    public var isFairPlayEncrypted: Bool {
        cryptid != 0
    }

    public var linkedDylibPaths: [String] {
        linkedDylibs.map { $0.path }
    }

    public var linksContainermanager: Bool {
        linksDylib(named: "libsystem_containermanager")
    }

    public func linksDylib(named name: String) -> Bool {
        let needle = name.lowercased()
        return linkedDylibs.contains { $0.path.lowercased().contains(needle) }
    }

    public var symbols: [String] {
        symtab?.parseSymbols(from: sliceData, is64Bit: is64Bit, isSwapped: isSwapped) ?? []
    }

    public func containsSymbol(_ symbolName: String) -> Bool {
        let allSyms = symbols
        if allSyms.contains(symbolName) {
            return true
        }
        let stripped = symbolName.hasPrefix("_") ? String(symbolName.dropFirst()) : symbolName
        let prefixed = "_" + stripped
        return allSyms.contains(stripped) || allSyms.contains(prefixed)
    }

    public func findSymbols(matching names: [String]) -> [String] {
        let allSet = Set(symbols)
        var matched: [String] = []
        for name in names {
            if allSet.contains(name) {
                matched.append(name)
                continue
            }
            let stripped = name.hasPrefix("_") ? String(name.dropFirst()) : name
            let prefixed = "_" + stripped
            if allSet.contains(stripped) || allSet.contains(prefixed) {
                matched.append(name)
            }
        }
        return matched
    }

    public var codeSignatureData: Data? {
        guard let cs = codeSignature else { return nil }
        guard UInt64(cs.dataoff) + UInt64(cs.datasize) <= UInt64(sliceData.count) else { return nil }
        return sliceData.subdata(in: Int(cs.dataoff)..<Int(cs.dataoff + cs.datasize))
    }
}

// MARK: - Mach-O Parser Engine

public final class MachOParser: Sendable {
    public static let shared = MachOParser()

    public init() {}

    /// Instance forwarding method for singleton delegation.
    public func parse(data: Data, preferredCpuType: cpu_type_t? = nil) throws -> MachOFile {
        try Self.parse(data: data, preferredCpuType: preferredCpuType)
    }

    /// Instance forwarding method for local filesystem URL parsing.
    public func parse(url: URL, preferredCpuType: cpu_type_t? = nil) throws -> MachOFile {
        try Self.parse(url: url, preferredCpuType: preferredCpuType)
    }

    /// Instance forwarding method for listing slices.
    public func listSlices(in data: Data) throws -> [MachOSliceInfo] {
        try Self.listSlices(in: data)
    }

    /// Instance forwarding method for slice extraction.
    public func extractSlice(from data: Data, slice: MachOSliceInfo) throws -> Data {
        try Self.extractSlice(from: data, slice: slice)
    }

    /// Parses a Mach-O file from a local filesystem URL in 100% read-only mode using memory mapping.
    public static func parse(url: URL, preferredCpuType: cpu_type_t? = nil) throws -> MachOFile {
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        return try parse(data: data, preferredCpuType: preferredCpuType)
    }

    /// Parses a Mach-O binary from raw Data (supports Thin 32-bit, Thin 64-bit, and Universal FAT).
    public static func parse(data: Data, preferredCpuType: cpu_type_t? = nil) throws -> MachOFile {
        guard data.count >= 4 else {
            throw MachOParserError.fileTooSmall(actual: data.count, minimum: 4)
        }

        let reader = BinaryReader(data: data)
        guard let rawMagic = reader.readUInt32(at: 0) else {
            throw MachOParserError.fileTooSmall(actual: data.count, minimum: 4)
        }

        // Detect Universal FAT binary (32-bit and 64-bit, Big-Endian or Little-Endian)
        let isFat32BE = (rawMagic.byteSwapped == FAT_MAGIC)
        let isFat32LE = (rawMagic == FAT_MAGIC)
        let isFat64BE = (rawMagic.byteSwapped == FAT_MAGIC_64)
        let isFat64LE = (rawMagic == FAT_MAGIC_64)

        if isFat32BE || isFat32LE || isFat64BE || isFat64LE {
            let isFat64 = isFat64BE || isFat64LE
            let fatSwapped = isFat32BE || isFat64BE
            let slices = try parseFatSlices(reader: reader, isFat64: isFat64, swapped: fatSwapped)
            guard !slices.isEmpty else {
                throw MachOParserError.fatBinaryEmpty
            }

            let chosenSlice = try selectPrimarySlice(from: slices, preferredCpuType: preferredCpuType)
            guard chosenSlice.offset <= UInt64(data.count),
                  chosenSlice.size <= UInt64(data.count) - chosenSlice.offset else {
                throw MachOParserError.sliceOutOfBounds(offset: chosenSlice.offset, size: chosenSlice.size, total: data.count)
            }

            let sliceSubdata = data.subdata(in: Int(chosenSlice.offset)..<Int(chosenSlice.offset + chosenSlice.size))
            return try parseThinSlice(sliceData: sliceSubdata, containerSlices: slices)
        }

        // Parse Thin Mach-O binary
        return try parseThinSlice(sliceData: data, containerSlices: [])
    }

    /// Lists all architecture slices embedded in a binary without decoding load commands.
    public static func listSlices(in data: Data) throws -> [MachOSliceInfo] {
        guard data.count >= 4 else {
            throw MachOParserError.fileTooSmall(actual: data.count, minimum: 4)
        }
        let reader = BinaryReader(data: data)
        guard let rawMagic = reader.readUInt32(at: 0) else {
            throw MachOParserError.fileTooSmall(actual: data.count, minimum: 4)
        }

        let isFat32BE = (rawMagic.byteSwapped == FAT_MAGIC)
        let isFat32LE = (rawMagic == FAT_MAGIC)
        let isFat64BE = (rawMagic.byteSwapped == FAT_MAGIC_64)
        let isFat64LE = (rawMagic == FAT_MAGIC_64)

        if isFat32BE || isFat32LE || isFat64BE || isFat64LE {
            let isFat64 = isFat64BE || isFat64LE
            let fatSwapped = isFat32BE || isFat64BE
            return try parseFatSlices(reader: reader, isFat64: isFat64, swapped: fatSwapped)
        }

        // Thin Mach-O binary: single slice
        guard data.count >= 28 else {
            throw MachOParserError.truncatedHeader(expected: 28, actual: data.count)
        }
        let is64 = (rawMagic == MH_MAGIC_64 || rawMagic == MH_CIGAM_64)
        let isSwapped = (rawMagic == MH_CIGAM_64 || rawMagic == MH_CIGAM)
        guard is64 || rawMagic == MH_MAGIC || rawMagic == MH_CIGAM else {
            throw MachOParserError.invalidMagic(rawMagic)
        }
        guard let cpuType = reader.readInt32(at: 4, swapped: isSwapped),
              let cpuSubtype = reader.readInt32(at: 8, swapped: isSwapped) else {
            throw MachOParserError.truncatedHeader(expected: 28, actual: data.count)
        }

        return [MachOSliceInfo(
            cpuType: cpuType,
            cpuSubtype: cpuSubtype,
            offset: 0,
            size: UInt64(data.count),
            align: 0
        )]
    }

    /// Extracts raw slice Data from a Universal FAT or Thin binary for a specified slice.
    public static func extractSlice(from data: Data, slice: MachOSliceInfo) throws -> Data {
        guard slice.offset <= UInt64(data.count),
              slice.size <= UInt64(data.count) - slice.offset else {
            throw MachOParserError.sliceOutOfBounds(offset: slice.offset, size: slice.size, total: data.count)
        }
        return data.subdata(in: Int(slice.offset)..<Int(slice.offset + slice.size))
    }

    // MARK: - Internal Helpers

    private static func parseFatSlices(reader: BinaryReader, isFat64: Bool, swapped: Bool) throws -> [MachOSliceInfo] {
        guard reader.count >= 8 else {
            throw MachOParserError.truncatedHeader(expected: 8, actual: reader.count)
        }
        guard let rawNfat = reader.readUInt32(at: 4, swapped: swapped) else {
            throw MachOParserError.truncatedHeader(expected: 8, actual: reader.count)
        }
        guard rawNfat > 0 else {
            throw MachOParserError.fatBinaryEmpty
        }
        guard rawNfat <= 1024 else {
            throw MachOParserError.corruptedFatHeader(reason: "Architecture slice count (\(rawNfat)) exceeds safety limit 1024")
        }

        let stride = isFat64 ? MemoryLayout<fat_arch_64>.size : MemoryLayout<fat_arch>.size
        let totalHeaderSize = 8 + Int(rawNfat) * stride
        guard totalHeaderSize <= reader.count else {
            throw MachOParserError.corruptedFatHeader(reason: "FAT header with \(rawNfat) entries requires \(totalHeaderSize) bytes, exceeds binary size \(reader.count)")
        }

        var slices: [MachOSliceInfo] = []
        slices.reserveCapacity(Int(rawNfat))

        for i in 0..<Int(rawNfat) {
            let entryOffset = 8 + i * stride
            let cpuType: cpu_type_t
            let cpuSubtype: cpu_subtype_t
            let offset: UInt64
            let size: UInt64
            let align: UInt32

            if isFat64 {
                guard let ct = reader.readInt32(at: entryOffset, swapped: swapped),
                      let cst = reader.readInt32(at: entryOffset + 4, swapped: swapped),
                      let off = reader.readUInt64(at: entryOffset + 8, swapped: swapped),
                      let sz = reader.readUInt64(at: entryOffset + 16, swapped: swapped),
                      let al = reader.readUInt32(at: entryOffset + 24, swapped: swapped) else {
                    throw MachOParserError.corruptedFatHeader(reason: "Failed reading fat_arch_64 entry \(i)")
                }
                cpuType = ct
                cpuSubtype = cst
                offset = off
                size = sz
                align = al
            } else {
                guard let ct = reader.readInt32(at: entryOffset, swapped: swapped),
                      let cst = reader.readInt32(at: entryOffset + 4, swapped: swapped),
                      let off = reader.readUInt32(at: entryOffset + 8, swapped: swapped),
                      let sz = reader.readUInt32(at: entryOffset + 12, swapped: swapped),
                      let al = reader.readUInt32(at: entryOffset + 16, swapped: swapped) else {
                    throw MachOParserError.corruptedFatHeader(reason: "Failed reading fat_arch entry \(i)")
                }
                cpuType = ct
                cpuSubtype = cst
                offset = UInt64(off)
                size = UInt64(sz)
                align = al
            }

            guard offset <= UInt64(reader.count), size <= UInt64(reader.count) - offset else {
                throw MachOParserError.sliceOutOfBounds(offset: offset, size: size, total: reader.count)
            }

            slices.append(MachOSliceInfo(
                cpuType: cpuType,
                cpuSubtype: cpuSubtype,
                offset: offset,
                size: size,
                align: align
            ))
        }

        return slices
    }

    private static func selectPrimarySlice(from slices: [MachOSliceInfo], preferredCpuType: cpu_type_t?) throws -> MachOSliceInfo {
        if let preferred = preferredCpuType {
            if let match = slices.first(where: { $0.cpuType == preferred }) {
                return match
            }
        }

        #if os(iOS)
        if let arm64 = slices.first(where: { $0.cpuType == CPU_TYPE_ARM64 }) {
            return arm64
        }
        if let arm32 = slices.first(where: { $0.cpuType == CPU_TYPE_ARM }) {
            return arm32
        }
        #elseif os(macOS)
        #if arch(arm64)
        let hostCpu = CPU_TYPE_ARM64
        let fallbackCpu = CPU_TYPE_X86_64
        #else
        let hostCpu = CPU_TYPE_X86_64
        let fallbackCpu = CPU_TYPE_ARM64
        #endif
        if let hostSlice = slices.first(where: { $0.cpuType == hostCpu }) {
            return hostSlice
        }
        if let arm64 = slices.first(where: { $0.cpuType == CPU_TYPE_ARM64 }) {
            return arm64
        }
        if let fallback = slices.first(where: { $0.cpuType == fallbackCpu }) {
            return fallback
        }
        #endif

        guard let first = slices.first else {
            throw MachOParserError.fatBinaryEmpty
        }
        return first
    }

    private static func parseThinSlice(sliceData: Data, containerSlices: [MachOSliceInfo]) throws -> MachOFile {
        guard sliceData.count >= 28 else {
            throw MachOParserError.truncatedHeader(expected: 28, actual: sliceData.count)
        }

        let reader = BinaryReader(data: sliceData)
        guard let magic = reader.readUInt32(at: 0) else {
            throw MachOParserError.fileTooSmall(actual: sliceData.count, minimum: 28)
        }

        let is64: Bool
        let isSwapped: Bool

        switch magic {
        case MH_MAGIC_64:
            is64 = true
            isSwapped = false
        case MH_CIGAM_64:
            is64 = true
            isSwapped = true
        case MH_MAGIC:
            is64 = false
            isSwapped = false
        case MH_CIGAM:
            is64 = false
            isSwapped = true
        default:
            throw MachOParserError.invalidMagic(magic)
        }

        let headerSize = is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        guard sliceData.count >= headerSize else {
            throw MachOParserError.truncatedHeader(expected: headerSize, actual: sliceData.count)
        }

        guard let cpuType = reader.readInt32(at: 4, swapped: isSwapped),
              let cpuSubtype = reader.readInt32(at: 8, swapped: isSwapped),
              let fileType = reader.readUInt32(at: 12, swapped: isSwapped),
              let ncmds = reader.readUInt32(at: 16, swapped: isSwapped),
              let sizeofcmds = reader.readUInt32(at: 20, swapped: isSwapped),
              let flags = reader.readUInt32(at: 24, swapped: isSwapped) else {
            throw MachOParserError.truncatedHeader(expected: headerSize, actual: sliceData.count)
        }

        let minCommandSize = MemoryLayout<load_command>.size
        let commandsEnd = headerSize + Int(sizeofcmds)
        guard reader.inRange(offset: headerSize, length: Int(sizeofcmds)) else {
            throw MachOParserError.loadCommandsOutOfBounds(expectedSize: commandsEnd, actualSize: reader.count)
        }

        let maxPossibleCmds = sizeofcmds / UInt32(minCommandSize)
        guard ncmds <= maxPossibleCmds, ncmds <= 16384 else {
            throw MachOParserError.invalidCommandCount(ncmds: ncmds, sizeofcmds: sizeofcmds)
        }

        var cursor = headerSize
        var segments: [MachOSegment] = []
        var encryptionInfo: MachOEncryptionInfo? = nil
        var linkedDylibs: [MachODylib] = []
        var symtab: MachOSymtab? = nil
        var codeSignature: MachOCodeSignature? = nil

        for _ in 0..<ncmds {
            guard cursor + minCommandSize <= commandsEnd else {
                throw MachOParserError.commandOutOfBounds(cmd: 0, cmdsize: 0, cursor: cursor, totalCmdSize: commandsEnd)
            }
            guard let cmd = reader.readUInt32(at: cursor, swapped: isSwapped),
                  let cmdsize = reader.readUInt32(at: cursor + 4, swapped: isSwapped) else {
                throw MachOParserError.commandOutOfBounds(cmd: 0, cmdsize: 0, cursor: cursor, totalCmdSize: commandsEnd)
            }

            guard cmdsize >= minCommandSize, (cmdsize % 4) == 0 else {
                throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cursor)
            }
            guard cursor + Int(cmdsize) <= commandsEnd else {
                throw MachOParserError.commandOutOfBounds(cmd: cmd, cmdsize: cmdsize, cursor: cursor, totalCmdSize: commandsEnd)
            }

            let cmdStart = cursor

            switch cmd {
            case UInt32(LC_SEGMENT_64):
                guard cmdsize >= MemoryLayout<segment_command_64>.size else {
                    throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cmdStart)
                }
                let segname = reader.readFixedString(at: cmdStart + 8, maxLength: 16) ?? ""
                let vmaddr = reader.readUInt64(at: cmdStart + 24, swapped: isSwapped) ?? 0
                let vmsize = reader.readUInt64(at: cmdStart + 32, swapped: isSwapped) ?? 0
                let fileoff = reader.readUInt64(at: cmdStart + 40, swapped: isSwapped) ?? 0
                let filesize = reader.readUInt64(at: cmdStart + 48, swapped: isSwapped) ?? 0
                let maxprot = reader.readInt32(at: cmdStart + 56, swapped: isSwapped) ?? 0
                let initprot = reader.readInt32(at: cmdStart + 60, swapped: isSwapped) ?? 0
                let nsects = reader.readUInt32(at: cmdStart + 64, swapped: isSwapped) ?? 0
                let segflags = reader.readUInt32(at: cmdStart + 68, swapped: isSwapped) ?? 0

                let sectionStride = MemoryLayout<section_64>.size
                var sections: [MachOSection] = []
                let requiredSectionBytes = UInt64(nsects) * UInt64(sectionStride)
                if nsects > 0 && UInt64(cmdsize) >= 72 + requiredSectionBytes {
                    for s in 0..<Int(nsects) {
                        let sectOffset = cmdStart + 72 + s * sectionStride
                        let sname = reader.readFixedString(at: sectOffset, maxLength: 16) ?? ""
                        let smname = reader.readFixedString(at: sectOffset + 16, maxLength: 16) ?? ""
                        let saddr = reader.readUInt64(at: sectOffset + 32, swapped: isSwapped) ?? 0
                        let ssize = reader.readUInt64(at: sectOffset + 40, swapped: isSwapped) ?? 0
                        let soff = reader.readUInt32(at: sectOffset + 48, swapped: isSwapped) ?? 0
                        let salign = reader.readUInt32(at: sectOffset + 52, swapped: isSwapped) ?? 0
                        let sreloff = reader.readUInt32(at: sectOffset + 56, swapped: isSwapped) ?? 0
                        let snreloc = reader.readUInt32(at: sectOffset + 60, swapped: isSwapped) ?? 0
                        let sflags = reader.readUInt32(at: sectOffset + 64, swapped: isSwapped) ?? 0

                        sections.append(MachOSection(
                            sectionName: sname,
                            segmentName: smname,
                            address: saddr,
                            size: ssize,
                            offset: soff,
                            align: salign,
                            reloff: sreloff,
                            nreloc: snreloc,
                            flags: sflags
                        ))
                    }
                }

                segments.append(MachOSegment(
                    name: segname,
                    vmAddress: vmaddr,
                    vmSize: vmsize,
                    fileOffset: fileoff,
                    fileSize: filesize,
                    maxProtection: maxprot,
                    initialProtection: initprot,
                    sectionCount: nsects,
                    flags: segflags,
                    sections: sections
                ))

            case UInt32(LC_SEGMENT):
                guard cmdsize >= MemoryLayout<segment_command>.size else {
                    throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cmdStart)
                }
                let segname = reader.readFixedString(at: cmdStart + 8, maxLength: 16) ?? ""
                let vmaddr = UInt64(reader.readUInt32(at: cmdStart + 24, swapped: isSwapped) ?? 0)
                let vmsize = UInt64(reader.readUInt32(at: cmdStart + 28, swapped: isSwapped) ?? 0)
                let fileoff = UInt64(reader.readUInt32(at: cmdStart + 32, swapped: isSwapped) ?? 0)
                let filesize = UInt64(reader.readUInt32(at: cmdStart + 36, swapped: isSwapped) ?? 0)
                let maxprot = reader.readInt32(at: cmdStart + 40, swapped: isSwapped) ?? 0
                let initprot = reader.readInt32(at: cmdStart + 44, swapped: isSwapped) ?? 0
                let nsects = reader.readUInt32(at: cmdStart + 48, swapped: isSwapped) ?? 0
                let segflags = reader.readUInt32(at: cmdStart + 52, swapped: isSwapped) ?? 0

                let sectionStride = MemoryLayout<section>.size
                var sections: [MachOSection] = []
                let requiredSectionBytes = UInt64(nsects) * UInt64(sectionStride)
                if nsects > 0 && UInt64(cmdsize) >= 56 + requiredSectionBytes {
                    for s in 0..<Int(nsects) {
                        let sectOffset = cmdStart + 56 + s * sectionStride
                        let sname = reader.readFixedString(at: sectOffset, maxLength: 16) ?? ""
                        let smname = reader.readFixedString(at: sectOffset + 16, maxLength: 16) ?? ""
                        let saddr = UInt64(reader.readUInt32(at: sectOffset + 32, swapped: isSwapped) ?? 0)
                        let ssize = UInt64(reader.readUInt32(at: sectOffset + 36, swapped: isSwapped) ?? 0)
                        let soff = reader.readUInt32(at: sectOffset + 40, swapped: isSwapped) ?? 0
                        let salign = reader.readUInt32(at: sectOffset + 44, swapped: isSwapped) ?? 0
                        let sreloff = reader.readUInt32(at: sectOffset + 48, swapped: isSwapped) ?? 0
                        let snreloc = reader.readUInt32(at: sectOffset + 52, swapped: isSwapped) ?? 0
                        let sflags = reader.readUInt32(at: sectOffset + 56, swapped: isSwapped) ?? 0

                        sections.append(MachOSection(
                            sectionName: sname,
                            segmentName: smname,
                            address: saddr,
                            size: ssize,
                            offset: soff,
                            align: salign,
                            reloff: sreloff,
                            nreloc: snreloc,
                            flags: sflags
                        ))
                    }
                }

                segments.append(MachOSegment(
                    name: segname,
                    vmAddress: vmaddr,
                    vmSize: vmsize,
                    fileOffset: fileoff,
                    fileSize: filesize,
                    maxProtection: maxprot,
                    initialProtection: initprot,
                    sectionCount: nsects,
                    flags: segflags,
                    sections: sections
                ))

            case UInt32(LC_ENCRYPTION_INFO_64):
                guard cmdsize >= MemoryLayout<encryption_info_command_64>.size else {
                    throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cmdStart)
                }
                let cryptoff = reader.readUInt32(at: cmdStart + 8, swapped: isSwapped) ?? 0
                let cryptsize = reader.readUInt32(at: cmdStart + 12, swapped: isSwapped) ?? 0
                let cryptid = reader.readUInt32(at: cmdStart + 16, swapped: isSwapped) ?? 0
                encryptionInfo = MachOEncryptionInfo(
                    cryptoff: cryptoff,
                    cryptsize: cryptsize,
                    cryptid: cryptid,
                    is64Bit: true
                )

            case UInt32(LC_ENCRYPTION_INFO):
                guard cmdsize >= MemoryLayout<encryption_info_command>.size else {
                    throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cmdStart)
                }
                let cryptoff = reader.readUInt32(at: cmdStart + 8, swapped: isSwapped) ?? 0
                let cryptsize = reader.readUInt32(at: cmdStart + 12, swapped: isSwapped) ?? 0
                let cryptid = reader.readUInt32(at: cmdStart + 16, swapped: isSwapped) ?? 0
                encryptionInfo = MachOEncryptionInfo(
                    cryptoff: cryptoff,
                    cryptsize: cryptsize,
                    cryptid: cryptid,
                    is64Bit: false
                )

            case UInt32(LC_LOAD_DYLIB), UInt32(LC_LOAD_WEAK_DYLIB), UInt32(LC_REEXPORT_DYLIB), UInt32(LC_LOAD_UPWARD_DYLIB):
                guard cmdsize >= MemoryLayout<dylib_command>.size else {
                    throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cmdStart)
                }
                let nameOffset = reader.readUInt32(at: cmdStart + 8, swapped: isSwapped) ?? 0
                let timestamp = reader.readUInt32(at: cmdStart + 12, swapped: isSwapped) ?? 0
                let curVer = reader.readUInt32(at: cmdStart + 16, swapped: isSwapped) ?? 0
                let compVer = reader.readUInt32(at: cmdStart + 20, swapped: isSwapped) ?? 0

                guard nameOffset >= 24, nameOffset < cmdsize else {
                    throw MachOParserError.malformedCommand(cmd: cmd, reason: "Dylib name offset \(nameOffset) is outside command bounds (cmdsize: \(cmdsize))")
                }
                let strStart = cmdStart + Int(nameOffset)
                let maxStrLen = Int(cmdsize) - Int(nameOffset)
                let path = reader.readNullTerminatedString(at: strStart, maxScanLength: maxStrLen) ?? ""

                linkedDylibs.append(MachODylib(
                    path: path,
                    isWeak: (cmd == UInt32(LC_LOAD_WEAK_DYLIB)),
                    timestamp: timestamp,
                    currentVersion: curVer,
                    compatibilityVersion: compVer
                ))

            case UInt32(LC_SYMTAB):
                guard cmdsize >= MemoryLayout<symtab_command>.size else {
                    throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cmdStart)
                }
                let symoff = reader.readUInt32(at: cmdStart + 8, swapped: isSwapped) ?? 0
                let nsyms = reader.readUInt32(at: cmdStart + 12, swapped: isSwapped) ?? 0
                let stroff = reader.readUInt32(at: cmdStart + 16, swapped: isSwapped) ?? 0
                let strsize = reader.readUInt32(at: cmdStart + 20, swapped: isSwapped) ?? 0

                let symEntrySize = is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size
                let totalSymBytes = UInt64(nsyms) * UInt64(symEntrySize)
                let (endOffset, overflow) = UInt64(symoff).addingReportingOverflow(totalSymBytes)
                guard !overflow, endOffset <= UInt64(reader.count) else {
                    throw MachOParserError.symbolTableOutOfBounds(offset: symoff, size: totalSymBytes, total: reader.count)
                }
                guard UInt64(stroff) + UInt64(strsize) <= UInt64(reader.count) else {
                    throw MachOParserError.stringTableOutOfBounds(offset: stroff, size: strsize, total: reader.count)
                }

                symtab = MachOSymtab(symoff: symoff, nsyms: nsyms, stroff: stroff, strsize: strsize)

            case UInt32(LC_CODE_SIGNATURE):
                guard cmdsize >= MemoryLayout<linkedit_data_command>.size else {
                    throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cmdStart)
                }
                let dataoff = reader.readUInt32(at: cmdStart + 8, swapped: isSwapped) ?? 0
                let datasize = reader.readUInt32(at: cmdStart + 12, swapped: isSwapped) ?? 0

                guard UInt64(dataoff) + UInt64(datasize) <= UInt64(reader.count) else {
                    throw MachOParserError.codeSignatureOutOfBounds(offset: dataoff, size: datasize, total: reader.count)
                }

                codeSignature = MachOCodeSignature(dataoff: dataoff, datasize: datasize)

            default:
                break
            }

            cursor += Int(cmdsize)
        }

        return MachOFile(
            magic: magic,
            cpuType: cpuType,
            cpuSubtype: cpuSubtype,
            fileType: fileType,
            ncmds: ncmds,
            sizeofcmds: sizeofcmds,
            flags: flags,
            is64Bit: is64,
            isSwapped: isSwapped,
            sliceData: sliceData,
            slicesInContainer: containerSlices,
            segments: segments,
            encryptionInfo: encryptionInfo,
            linkedDylibs: linkedDylibs,
            symtab: symtab,
            codeSignature: codeSignature
        )
    }
}
