//
//  MachOParser.swift
//  WQGuardCore
//
//  Created by M2 MachO Parser Explorer.
//  100% Read-Only, Bounds-Checked Mach-O & Universal FAT Binary Parser.
//

import Foundation
import MachO
import zlib

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
        self.data = data.startIndex == 0 ? data : Data(data)
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
            guard let base = raw.baseAddress?.advanced(by: offset).assumingMemoryBound(to: UInt8.self) else { return nil }
            var len = 0
            while len < maxLength && base[len] != 0 {
                len += 1
            }
            return String(decoding: UnsafeBufferPointer(start: base, count: len), as: UTF8.self)
        }
    }

    public func readNullTerminatedString(at offset: Int, maxScanLength: Int) -> String? {
        guard inRange(offset: offset, length: 1) else { return nil }
        let available = min(maxScanLength, data.count - offset)
        return data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress?.advanced(by: offset).assumingMemoryBound(to: UInt8.self) else { return nil }
            var len = 0
            while len < available && base[len] != 0 {
                len += 1
            }
            return String(decoding: UnsafeBufferPointer(start: base, count: len), as: UTF8.self)
        }
    }

    public func subdata(offset: Int, length: Int) -> Data? {
        guard inRange(offset: offset, length: length) else { return nil }
        let start = data.startIndex + offset
        return data.subdata(in: start..<(start + length))
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

public struct MachOSymtab: Sendable, Equatable, Hashable {
    public let symoff: UInt32
    public let nsyms: UInt32
    public let stroff: UInt32
    public let strsize: UInt32

    private static let maxSymbolsPerSymtab = 250_000
    private static let maxSymbolStringScanBytes = 512
    private static let maxTotalSymtabStringScanBytes = 16 * 1024 * 1024

    public init(symoff: UInt32, nsyms: UInt32, stroff: UInt32, strsize: UInt32) {
        self.symoff = symoff
        self.nsyms = nsyms
        self.stroff = stroff
        self.strsize = strsize
    }

    public func parseSymbols(from data: Data, is64Bit: Bool, isSwapped: Bool) -> [String] {
        var budget = Self.maxTotalSymtabStringScanBytes
        return parseSymbolsBounded(
            from: data,
            is64Bit: is64Bit,
            isSwapped: isSwapped,
            remainingStringScanBudget: &budget
        )
    }

    internal func parseSymbolsBounded(
        from data: Data,
        is64Bit: Bool,
        isSwapped: Bool,
        remainingStringScanBudget: inout Int,
        maxResults: Int = maxSymbolsPerSymtab
    ) -> [String] {
        guard nsyms > 0, strsize > 0, remainingStringScanBudget > 0, maxResults > 0 else { return [] }
        let entrySize = is64Bit ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size
        let totalSymBytes = UInt64(nsyms) * UInt64(entrySize)
        guard UInt64(symoff) + totalSymBytes <= UInt64(data.count),
              UInt64(stroff) + UInt64(strsize) <= UInt64(data.count),
              let symoffInt = Int(exactly: symoff),
              let stroffInt = Int(exactly: stroff),
              let strsizeInt = Int(exactly: strsize),
              let nsymsInt = Int(exactly: nsyms) else {
            return []
        }

        let cappedSyms = min(nsymsInt, Self.maxSymbolsPerSymtab)
        var results: [String] = []
        results.reserveCapacity(min(cappedSyms, min(maxResults, 8192)))
        var seenStrx: Set<UInt32> = []

        return data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return []
            }
            let totalBytes = raw.count
            for i in 0..<cappedSyms {
                if remainingStringScanBudget <= 0 || results.count >= maxResults { break }
                let entryOffset = symoffInt + i * entrySize
                guard entryOffset + entrySize <= totalBytes else { break }
                let rawStrx = UInt32(base[entryOffset])
                    | (UInt32(base[entryOffset + 1]) << 8)
                    | (UInt32(base[entryOffset + 2]) << 16)
                    | (UInt32(base[entryOffset + 3]) << 24)
                let strx = isSwapped ? rawStrx.byteSwapped : rawStrx
                guard strx > 0, strx < strsize,
                      seenStrx.insert(strx).inserted,
                      let strxInt = Int(exactly: strx) else { continue }
                let strOffset = stroffInt + strxInt
                guard strOffset < totalBytes else { continue }
                let maxLen = min(strsizeInt - strxInt, min(Self.maxSymbolStringScanBytes, totalBytes - strOffset))
                guard maxLen > 0 else { continue }
                var strLen = 0
                while strLen < maxLen && base[strOffset + strLen] != 0 {
                    strLen += 1
                }
                remainingStringScanBudget -= min(maxLen, strLen + 1)
                if strLen > 0 {
                    let s = String(decoding: UnsafeBufferPointer(start: base.advanced(by: strOffset), count: strLen), as: UTF8.self)
                    if !s.isEmpty {
                        results.append(s)
                    }
                }
            }
            return results
        }
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

public struct DirectSyscallSite: Sendable, Equatable, Hashable {
    public let segmentName: String
    public let sectionName: String
    public let fileOffset: Int
    public let virtualAddress: UInt64
    public let immediate: UInt16

    public init(
        segmentName: String,
        sectionName: String,
        fileOffset: Int,
        virtualAddress: UInt64,
        immediate: UInt16
    ) {
        self.segmentName = segmentName
        self.sectionName = sectionName
        self.fileOffset = fileOffset
        self.virtualAddress = virtualAddress
        self.immediate = immediate
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
    public let symtabs: [MachOSymtab]
    public let codeSignature: MachOCodeSignature?
    public let codeSignatures: [MachOCodeSignature]
    public let dynamicImportSymbols: [String]
    public let entryPointFileOffsets: [Int]
    private let symbolCache = SymbolCache()

    private final class SymbolCache: @unchecked Sendable {
        private let lock = NSLock()
        private var cachedOrdered: [String]?
        private var cachedSet: Set<String>?

        func resolve(
            symtabs: [MachOSymtab],
            sliceData: Data,
            is64Bit: Bool,
            isSwapped: Bool,
            dynamicImportSymbols: [String]
        ) -> (ordered: [String], set: Set<String>) {
            lock.lock()
            defer { lock.unlock() }
            if let cachedOrdered, let cachedSet {
                return (cachedOrdered, cachedSet)
            }
            let maxMergedSymbols = 250_000
            var remainingStringScanBudget = 16 * 1024 * 1024
            var result: [String] = []
            var seen: Set<String> = []
            for st in symtabs {
                if remainingStringScanBudget <= 0 || result.count >= maxMergedSymbols { break }
                for sym in st.parseSymbolsBounded(
                    from: sliceData,
                    is64Bit: is64Bit,
                    isSwapped: isSwapped,
                    remainingStringScanBudget: &remainingStringScanBudget,
                    maxResults: maxMergedSymbols - result.count
                ) {
                    if seen.insert(sym).inserted {
                        result.append(sym)
                        if result.count >= maxMergedSymbols { break }
                    }
                }
            }
            if result.count < maxMergedSymbols {
                for sym in dynamicImportSymbols {
                    if seen.insert(sym).inserted {
                        result.append(sym)
                        if result.count >= maxMergedSymbols { break }
                    }
                }
            }
            self.cachedOrdered = result
            self.cachedSet = seen
            return (result, seen)
        }
    }

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
        codeSignature: MachOCodeSignature?,
        symtabs: [MachOSymtab]? = nil,
        codeSignatures: [MachOCodeSignature]? = nil,
        dynamicImportSymbols: [String] = [],
        entryPointFileOffsets: [Int] = []
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
        self.sliceData = sliceData.startIndex == 0 ? sliceData : Data(sliceData)
        self.slicesInContainer = slicesInContainer
        self.segments = segments
        self.encryptionInfo = encryptionInfo
        self.linkedDylibs = linkedDylibs
        let resolvedSymtabs = symtabs ?? (symtab.map { [$0] } ?? [])
        self.symtabs = resolvedSymtabs
        self.symtab = symtab ?? resolvedSymtabs.first
        let resolvedCodeSigs = codeSignatures ?? (codeSignature.map { [$0] } ?? [])
        self.codeSignatures = resolvedCodeSigs
        self.codeSignature = resolvedCodeSigs.first(where: { $0.datasize > 0 }) ?? codeSignature ?? resolvedCodeSigs.first
        self.dynamicImportSymbols = dynamicImportSymbols
        self.entryPointFileOffsets = entryPointFileOffsets
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
        linksDylib(named: IOCTokenArmor.tContainerMgrPrefix)
    }

    public func linksDylib(named name: String) -> Bool {
        let needle = name.lowercased()
        return linkedDylibs.contains { $0.path.lowercased().contains(needle) }
    }

    public var symbols: [String] {
        symbolCache.resolve(
            symtabs: symtabs,
            sliceData: sliceData,
            is64Bit: is64Bit,
            isSwapped: isSwapped,
            dynamicImportSymbols: dynamicImportSymbols
        ).ordered
    }

    public func containsSymbol(_ symbolName: String) -> Bool {
        let allSet = symbolCache.resolve(
            symtabs: symtabs,
            sliceData: sliceData,
            is64Bit: is64Bit,
            isSwapped: isSwapped,
            dynamicImportSymbols: dynamicImportSymbols
        ).set
        if allSet.contains(symbolName) {
            return true
        }
        let stripped = symbolName.hasPrefix("_") ? String(symbolName.dropFirst()) : symbolName
        let prefixed = "_" + stripped
        return allSet.contains(stripped) || allSet.contains(prefixed)
    }

    public func findSymbols(matching names: [String]) -> [String] {
        let allSet = symbolCache.resolve(
            symtabs: symtabs,
            sliceData: sliceData,
            is64Bit: is64Bit,
            isSwapped: isSwapped,
            dynamicImportSymbols: dynamicImportSymbols
        ).set
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
        let start = sliceData.startIndex + Int(cs.dataoff)
        return sliceData.subdata(in: start..<(start + Int(cs.datasize)))
    }

    /// Returns raw SuperBlob slices across ALL `LC_CODE_SIGNATURE` load commands in the binary
    /// so appending a decoy/empty `LC_CODE_SIGNATURE` cannot shadow an earlier signature blob.
    public var allCodeSignatureData: [Data] {
        var blobs: [Data] = []
        for cs in codeSignatures where cs.datasize > 0 {
            guard UInt64(cs.dataoff) + UInt64(cs.datasize) <= UInt64(sliceData.count) else { continue }
            let start = sliceData.startIndex + Int(cs.dataoff)
            blobs.append(sliceData.subdata(in: start..<(start + Int(cs.datasize))))
        }
        return blobs
    }

    private static let fairPlay4KBEntropyTerms: [Double] = (0...4096).map { c in
        c == 0 ? 0.0 : -(Double(c) / 4096.0) * log2(Double(c) / 4096.0)
    }

    private static let fairPlay512BEntropyTerms: [Double] = (0...512).map { c in
        c == 0 ? 0.0 : -(Double(c) / 512.0) * log2(Double(c) / 512.0)
    }

    /// Detects `LC_ENCRYPTION_INFO` (`cryptid != 0`) paired with an ad-hoc or non-App-Store code signature
    /// whose `[cryptoff, cryptoff + cryptsize)` bytes contain unencrypted plaintext rather than FairPlay AES ciphertext.
    internal var hasForgedPlaintextFairPlayRange: Bool {
        guard isFairPlayEncrypted else { return false }
        let hasMalformedCSCmd = codeSignatures.contains { cs in
            cs.datasize < 12 || UInt64(cs.dataoff) + UInt64(cs.datasize) > UInt64(sliceData.count)
        }
        let blobs = allCodeSignatureData
        let sigDisqualified: Bool
        if hasMalformedCSCmd || codeSignatures.isEmpty || blobs.isEmpty {
            sigDisqualified = true
        } else {
            sigDisqualified = blobs.contains {
                CSBlobParser.shared.inspectCodeSignatureTrust(from: $0, sliceData: sliceData) != .appleAppStoreVerified
            }
        }
        guard sigDisqualified, let er = encryptionInfo?.encryptedRange else {
            return false
        }
        let lo = max(0, min(er.lowerBound, sliceData.count))
        let hi = max(lo, min(er.upperBound, sliceData.count))
        let totalLen = hi - lo
        guard totalLen >= 4 else { return false }
        if totalLen < 256 {
            return true
        }

        let isArm64 = (cpuType == CPU_TYPE_ARM64 || cpuType == CPU_TYPE_ARM64_32)
        let swapped = isSwapped

        return sliceData.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return false }
            var counts = [Int](repeating: 0, count: 256)

            return counts.withUnsafeMutableBufferPointer { cBuf -> Bool in
                guard let cPtr = cBuf.baseAddress else { return false }
                return Self.fairPlay4KBEntropyTerms.withUnsafeBufferPointer { terms4KBuf -> Bool in
                    return Self.fairPlay512BEntropyTerms.withUnsafeBufferPointer { terms512Buf -> Bool in
                        guard let terms4KPtr = terms4KBuf.baseAddress,
                              let terms512Ptr = terms512Buf.baseAddress else { return false }

                        @inline(__always)
                        func fairPlayEntropyThreshold(forLength len: Int) -> Double {
                            if len < 384 { return 6.4 }
                            if len < 512 { return 6.8 }
                            if len < 1024 { return 7.0 }
                            if len < 2048 { return 7.35 }
                            return 7.6
                        }

                        @inline(__always)
                        func windowEntropy(start: Int, length: Int) -> Double {
                            memset(cPtr, 0, 256 * MemoryLayout<Int>.size)
                            let end = start + length
                            var i = start
                            while i &+ 4 <= end {
                                cPtr[Int(base[i])] &+= 1
                                cPtr[Int(base[i &+ 1])] &+= 1
                                cPtr[Int(base[i &+ 2])] &+= 1
                                cPtr[Int(base[i &+ 3])] &+= 1
                                i &+= 4
                            }
                            while i < end {
                                cPtr[Int(base[i])] &+= 1
                                i &+= 1
                            }
                            var ent = 0.0
                            if length == 4096 {
                                for b in 0..<256 {
                                    let c = cPtr[b]
                                    if c > 0 { ent += terms4KPtr[c] }
                                }
                            } else if length == 512 {
                                for b in 0..<256 {
                                    let c = cPtr[b]
                                    if c > 0 { ent += terms512Ptr[c] }
                                }
                            } else {
                                let invN = 1.0 / Double(length)
                                for b in 0..<256 {
                                    let c = cPtr[b]
                                    if c > 0 {
                                        let p = Double(c) * invN
                                        ent -= p * log2(p)
                                    }
                                }
                            }
                            return ent
                        }

                        @inline(__always)
                        func hasASCIIRunAt(_ pos: Int, _ end: Int, _ prefix: StaticString) -> Bool {
                            let pLen = prefix.utf8CodeUnitCount
                            guard pos + pLen <= end else { return false }
                            return prefix.withUTF8Buffer { pBuf in
                                for k in 0..<pLen where base[pos + k] != pBuf[k] {
                                    return false
                                }
                                return true
                            }
                        }

                        @inline(__always)
                        func hasCaseInsensitiveASCIIRunAt(_ pos: Int, _ end: Int, _ lowerPrefix: StaticString) -> Bool {
                            let pLen = lowerPrefix.utf8CodeUnitCount
                            guard pos + pLen <= end else { return false }
                            return lowerPrefix.withUTF8Buffer { pBuf in
                                for k in 0..<pLen {
                                    let b = base[pos + k]
                                    let lower = (b >= 0x41 && b <= 0x5A) ? (b + 32) : b
                                    if lower != pBuf[k] { return false }
                                }
                                return true
                            }
                        }

                        func looksLikePlaintextPlistSpan(start: Int, length: Int) -> Bool {
                            guard length >= 8 else { return false }
                            let end = start + length
                            if length >= 7, hasASCIIRunAt(start, end, "bplist0") {
                                return true
                            }
                            // UTF-16LE / UTF-16BE XML check
                            if start + 4 <= end {
                                let b0 = base[start], b1 = base[start + 1], b2 = base[start + 2], b3 = base[start + 3]
                                if (b0 == 0xFF && b1 == 0xFE) || (b0 == 0xFE && b1 == 0xFF)
                                    || (b0 == 0x3C && b1 == 0x00 && (b2 == 0x3F || b2 == 0x70 || b2 == 0x21) && b3 == 0x00)
                                    || (b0 == 0x00 && b1 == 0x3C && b2 == 0x00 && (b3 == 0x3F || b3 == 0x70 || b3 == 0x21)) {
                                    return true
                                }
                            }
                            var pos = start
                            while pos < end {
                                let b = base[pos]
                                if b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D || b == 0x00
                                    || b == 0xEF || b == 0xBB || b == 0xBF || b == 0xFE || b == 0xFF {
                                    pos += 1
                                    continue
                                }
                                break
                            }
                            guard pos < end else { return false }
                            if base[pos] == 0x3C {
                                if hasASCIIRunAt(pos, end, "<?xml")
                                    || hasASCIIRunAt(pos, end, "<plist")
                                    || hasCaseInsensitiveASCIIRunAt(pos, end, "<!doctype")
                                    || hasASCIIRunAt(pos, end, "<!--") {
                                    return true
                                }
                                if pos + 3 < end && base[pos + 1] == 0x00 && (base[pos + 2] == 0x3F || base[pos + 2] == 0x70 || base[pos + 2] == 0x21) && base[pos + 3] == 0x00 {
                                    return true
                                }
                                if pos > start && base[pos - 1] == 0x00 && pos + 2 < end && base[pos + 1] == 0x00 && (base[pos + 2] == 0x3F || base[pos + 2] == 0x70 || base[pos + 2] == 0x21) {
                                    return true
                                }
                                return false
                            }
                            if base[pos] == 0x7B {
                                let sampleLen = min(end - pos, 64)
                                guard sampleLen >= 8 else { return false }
                                var printable = 0
                                for i in 0..<sampleLen {
                                    let b = base[pos + i]
                                    if (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D {
                                        printable += 1
                                    }
                                }
                                return Double(printable) / Double(sampleLen) >= 0.85
                            }
                            return false
                        }

                        let exactSelBuckets = Self.sensitiveSelectorBuckets
                        let fpExtraBuckets = Self.fairPlayExtraCStringBuckets
                        let minSubLen = Self.minSubNeedleLen
                        let headerSize = is64Bit ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
                        let commandsEnd = min(sliceData.count, headerSize + Int(sizeofcmds))

                        return Self.exactSelectorPairLenMaskTable.withUnsafeBufferPointer { exactPairBuf in
                            Self.fairPlayExtraPairLenMaskTable.withUnsafeBufferPointer { fpExtraPairBuf in
                                Self.substringAutomatonDFATable.withUnsafeBufferPointer { dfaBuf in
                                    guard let exactPairPtr = exactPairBuf.baseAddress,
                                          let fpExtraPairPtr = fpExtraPairBuf.baseAddress,
                                          let dfaPtr = dfaBuf.baseAddress else { return false }

                                    @inline(__always)
                                    func matchesSensitiveOrDangerousCString(strStart: Int, len: Int) -> Bool {
                                        guard len >= 5 && len <= 512 else { return false }
                                        let b0 = Int(base[strStart])
                                        let b1 = Int(base[strStart &+ 1])
                                        let firstPair = (b0 << 8) | b1
                                        let lenBit = len < 63 ? (UInt64(1) << len) : (UInt64(1) << 62)

                                        if (exactPairPtr[firstPair] & lenBit) != 0 {
                                            for needle in exactSelBuckets[b0] where needle.count == len && needle[1] == UInt8(b1) {
                                                var idx = 2
                                                while idx < len && base[strStart &+ idx] == needle[idx] {
                                                    idx &+= 1
                                                }
                                                if idx == len { return true }
                                            }
                                        }
                                        if (fpExtraPairPtr[firstPair] & lenBit) != 0 {
                                            for needle in fpExtraBuckets[b0] where needle.count == len && needle[1] == UInt8(b1) {
                                                var idx = 2
                                                while idx < len && base[strStart &+ idx] == needle[idx] {
                                                    idx &+= 1
                                                }
                                                if idx == len { return true }
                                            }
                                        }
                                        if len >= minSubLen {
                                            var state = 0
                                            var p = strStart
                                            let pEnd = strStart &+ len
                                            while p < pEnd {
                                                let nx = Int(dfaPtr[(state << 8) | Int(base[p])])
                                                if (nx & 0x8000) != 0 {
                                                    return true
                                                }
                                                state = nx
                                                p &+= 1
                                            }
                                        }
                                        return false
                                    }

                                    func hasPlaintextCStringSpan(start: Int, length: Int) -> Bool {
                                        let end = start + length
                                        var printableOrNul = 0
                                        var printableCount = 0
                                        var consecutiveASCII = 0
                                        var startedAtNulOrStart = true
                                        let minRunSingle = length <= 1_048_576 ? 14 : 16
                                        var i = start
                                        while i < end {
                                            let b = base[i]
                                            if b >= 0x20 && b <= 0x7E {
                                                if length < 256 {
                                                    printableOrNul &+= 1
                                                    printableCount &+= 1
                                                }
                                                consecutiveASCII &+= 1
                                            } else if b == 0x00 {
                                                if length < 256 {
                                                    printableOrNul &+= 1
                                                }
                                                if consecutiveASCII >= minRunSingle
                                                    || (startedAtNulOrStart && consecutiveASCII >= 14)
                                                    || (length <= 1_048_576 && startedAtNulOrStart && consecutiveASCII >= 12) {
                                                    return true
                                                }
                                                if (startedAtNulOrStart && consecutiveASCII >= 5) || (!startedAtNulOrStart && consecutiveASCII >= 8) {
                                                    if matchesSensitiveOrDangerousCString(strStart: i &- consecutiveASCII, len: consecutiveASCII) {
                                                        return true
                                                    }
                                                }
                                                consecutiveASCII = 0
                                                startedAtNulOrStart = true
                                            } else {
                                                consecutiveASCII = 0
                                                startedAtNulOrStart = false
                                            }
                                            i &+= 1
                                        }
                                        if (startedAtNulOrStart && consecutiveASCII >= 6) || (!startedAtNulOrStart && consecutiveASCII >= 8) {
                                            if matchesSensitiveOrDangerousCString(strStart: end &- consecutiveASCII, len: consecutiveASCII) {
                                                return true
                                            }
                                        }
                                        if length < 256 && length >= 4 && printableCount >= 2 {
                                            if Double(printableOrNul) / Double(length) >= 0.85 {
                                                return true
                                            }
                                        }
                                        if length >= 256 {
                                            let entLen = min(length, 4096)
                                            if windowEntropy(start: start, length: entLen) < fairPlayEntropyThreshold(forLength: entLen) {
                                                return true
                                            }
                                            var off = 0
                                            while off + 256 <= length {
                                                if windowEntropy(start: start + off, length: 256) < 6.3 {
                                                    return true
                                                }
                                                off += 256
                                            }
                                        }
                                        return false
                                    }

                                    @inline(__always)
                                    func arm64SyscallContextScore(_ w: UInt32) -> Int {
                                        if w == 0xD65F_03C0 || w == 0xD65F_0FFF || w == 0xD65F_0BFF
                                            || w == 0xD503_237F || w == 0xD503_233F || w == 0xD503_201F
                                            || (w & 0xFFFF_FF3F) == 0xD503_241F {
                                            return 20
                                        }
                                        let brMask = w & 0xFFFF_FC1F
                                        if brMask == 0xD65F_0000 || brMask == 0xD61F_0000 || brMask == 0xD63F_0000 {
                                            return 20
                                        }
                                        let fpLrMask = w & 0xFFC0_7FFF
                                        if fpLrMask == 0xA980_7BFD || fpLrMask == 0xA900_7BFD
                                            || fpLrMask == 0xA8C0_7BFD || fpLrMask == 0xA940_7BFD {
                                            return 20
                                        }
                                        let spMask = w & 0xFF80_03FF
                                        if spMask == 0xD100_03FF || spMask == 0x9100_03FF || spMask == 0x9100_03FD {
                                            return 20
                                        }
                                        let movRegMask = w & 0xFFE0_FFE0
                                        if (movRegMask == 0xAA00_03E0 || movRegMask == 0x2A00_03E0) && (w & 0x1F) != 31 {
                                            return 20
                                        }
                                        if (w & 0xFFE0_001F) == 0xD280_0010 || (w & 0xFFE0_001F) == 0x5280_0010
                                            || (w & 0xFFE0_001F) == 0x9280_0010 || (w & 0xFFE0_001F) == 0x1280_0010 {
                                            return 16 // movz/movn x16/w16, #imm16 (hw == 0)
                                        }
                                        let mov16Mask = w & 0xFF80_001F
                                        if mov16Mask == 0xD280_0010 || mov16Mask == 0x5280_0010
                                            || mov16Mask == 0x9280_0010 || mov16Mask == 0x1280_0010
                                            || mov16Mask == 0xF280_0010 || mov16Mask == 0x7280_0010 {
                                            return 8
                                        }
                                        let mov8Mask = w & 0xFFE0_001F
                                        if mov8Mask == 0xD280_0008 || mov8Mask == 0x5280_0008 {
                                            return 14
                                        }
                                        if (w & 0xFF00_0010) == 0x5400_0000 && (w & 0x0F) != 0x0F {
                                            let imm19 = (Int32(bitPattern: (w >> 5) & 0x7_FFFF) << 13) >> 13
                                            if abs(imm19) < 0x4000 { return 9 }
                                            if abs(imm19) < 0x10000 { return 5 }
                                            return 0 // b.cond
                                        }
                                        if (w & 0x3B80_0000) == 0x3900_0000 || (w & 0xFFC0_0000) == 0xB980_0000 {
                                            let imm12 = (w >> 10) & 0xFFF
                                            if imm12 < 0x100 { return 7 }
                                            if imm12 < 0x400 { return 4 }
                                            return 0 // ldr/str/ldrsw unsigned immediate
                                        }
                                        if (w & 0x3B20_0400) == 0x3800_0400 && (w & 0x00C0_0000) != 0x00C0_0000 {
                                            let imm9 = (Int32(bitPattern: (w >> 12) & 0x1FF) << 23) >> 23
                                            return abs(imm9) <= 64 ? 8 : 4 // ldr/str pre/post-index
                                        }
                                        if (w & 0x3B20_0C00) == 0x3820_0800 && (w & 0x00C0_0000) != 0x00C0_0000 {
                                            let opt = (w >> 13) & 0x7
                                            if opt == 2 || opt == 3 || opt == 6 || opt == 7 {
                                                return 8 // ldr/str register-offset
                                            }
                                            return 0
                                        }
                                        if (w & 0x3F00_0000) == 0x1800_0000 && (w & 0xC000_0000) != 0xC000_0000 {
                                            let imm19 = (Int32(bitPattern: (w >> 5) & 0x7_FFFF) << 13) >> 13
                                            return abs(imm19) < 0x4000 ? 6 : 0 // ldr literal
                                        }
                                        if (w & 0x3E00_0000) == 0x2800_0000 && (w & 0x0180_0000) != 0 && (w & 0xC000_0000) != 0xC000_0000 {
                                            let isLoad = (w & 0x0040_0000) != 0
                                            let rt = w & 0x1F
                                            let rt2 = (w >> 10) & 0x1F
                                            if isLoad && (rt == rt2 || rt == 31 || rt2 == 31) {
                                                return 0
                                            }
                                            let imm7 = (Int32(bitPattern: (w >> 15) & 0x7F) << 25) >> 25
                                            return abs(imm7) <= 32 ? 6 : 3 // ldp/stp
                                        }
                                        if (w & 0x7E00_0000) == 0x3400_0000 {
                                            let imm19 = (Int32(bitPattern: (w >> 5) & 0x7_FFFF) << 13) >> 13
                                            if abs(imm19) < 0x4000 { return 6 }
                                            if abs(imm19) < 0x10000 { return 3 }
                                            return 0 // cbz/cbnz
                                        }
                                        if (w & 0x7E00_0000) == 0x3600_0000 {
                                            let imm14 = (Int32(bitPattern: (w >> 5) & 0x3FFF) << 18) >> 18
                                            return abs(imm14) < 0x1000 ? 6 : 0 // tbz/tbnz
                                        }
                                        if (w & 0x1F80_0000) == 0x1280_0000
                                            && (w & 0x6000_0000) != 0x2000_0000
                                            && ((w & 0x8000_0000) != 0 || (w & 0x0040_0000) == 0)
                                            && (w & 0x1F) != 31 {
                                            let hw = (w >> 21) & 0x3
                                            return hw == 0 ? 6 : 3 // movz/movn/movk
                                        }
                                        if (w & 0x1F80_0000) == 0x1100_0000 {
                                            let sh = (w >> 22) & 1
                                            let imm12 = (w >> 10) & 0xFFF
                                            if sh == 0 && imm12 < 0x400 { return 6 }
                                            if sh == 0 { return 4 }
                                            return 2 // add/sub/cmp immediate
                                        }
                                        if (w & 0x7C00_0000) == 0x1400_0000 {
                                            let imm26 = (Int32(bitPattern: w & 0x03FF_FFFF) << 6) >> 6
                                            if abs(imm26) < 0x4_0000 { return 6 }
                                            if abs(imm26) < 0x20_0000 { return 3 }
                                            return 0 // b/bl
                                        }
                                        if (w & 0x1F00_0000) == 0x1000_0000 {
                                            let rawImm = (((w >> 5) & 0x7_FFFF) << 2) | ((w >> 29) & 0x3)
                                            let imm21 = (Int32(bitPattern: rawImm) << 11) >> 11
                                            if (w & 0x8000_0000) != 0 {
                                                return abs(imm21) < 0x4000 ? 5 : 0 // adrp
                                            } else {
                                                return abs(imm21) < 0x10000 ? 5 : 0 // adr
                                            }
                                        }
                                        // add/sub/cmp shifted register
                                        if (w & 0x1F20_0000) == 0x0B00_0000 && (w & 0x00C0_0000) != 0x00C0_0000 {
                                            let sf = (w >> 31) & 1
                                            let shift = (w >> 22) & 0x3
                                            let imm6 = (w >> 10) & 0x3F
                                            if sf == 1 || imm6 < 32 {
                                                if shift == 0 && imm6 == 0 { return 5 }
                                                if imm6 < 32 { return 3 }
                                            }
                                            return 0
                                        }
                                        // add/sub/cmp extended register
                                        if (w & 0x1FE0_0000) == 0x0B20_0000 && (w & 0x0000_1C00) <= 0x0000_1000 {
                                            return 4
                                        }
                                        // and/orr/eor/tst shifted register
                                        if (w & 0x1F00_0000) == 0x0A00_0000 {
                                            let sf = (w >> 31) & 1
                                            let shift = (w >> 22) & 0x3
                                            let imm6 = (w >> 10) & 0x3F
                                            if sf == 1 || imm6 < 32 {
                                                if shift == 0 && imm6 == 0 { return 5 }
                                                if imm6 < 32 { return 3 }
                                            }
                                            return 0
                                        }
                                        // and/orr/eor/tst bitmask immediate
                                        if (w & 0x1F80_0000) == 0x1200_0000 && ((w & 0x8000_0000) != 0 || (w & 0x0040_0000) == 0) {
                                            return 3
                                        }
                                        // sbfm/bfm/ubfm bitfield
                                        if (w & 0x1F80_0000) == 0x1300_0000
                                            && (w & 0x6000_0000) != 0x6000_0000
                                            && (((w >> 31) & 1) == ((w >> 22) & 1)) {
                                            return 4
                                        }
                                        // csel/csinc/csinv/csneg
                                        if (w & 0x3FE0_0800) == 0x1A80_0000 {
                                            return 5
                                        }
                                        // mul/madd/msub/smaddl/umaddl/smulh/umulh
                                        if (w & 0x7FE0_0000) == 0x1B00_0000
                                            || (w & 0xFF60_0000) == 0x9B20_0000
                                            || (w & 0xFF7F_FC00) == 0x9B40_7C00 {
                                            return 5
                                        }
                                        return 0
                                    }

                                    func hasPlaintextCodeSpan(start: Int, length: Int) -> Bool {
                                        if length < 256 {
                                            if isArm64 && length >= 4 {
                                                let endLimit = start + length - 3
                                                var p = start
                                                while p < endLimit {
                                                    let rawWord = UnsafeRawPointer(base.advanced(by: p)).loadUnaligned(as: UInt32.self)
                                                    let insn = swapped ? rawWord.byteSwapped : rawWord
                                                    if insn == 0xD400_1001 || insn == 0xD65F_03C0 || insn == 0xD503_201F || insn == 0xD503_237F {
                                                        return true
                                                    }
                                                    p &+= 1
                                                }
                                            }
                                            if length >= 64 && windowEntropy(start: start, length: length) < 4.5 {
                                                return true
                                            }
                                            if length >= 32 {
                                                var zeroCount = 0
                                                for i in start..<(start + length) where base[i] == 0 {
                                                    zeroCount += 1
                                                }
                                                if Double(zeroCount) / Double(length) >= 0.25 {
                                                    return true
                                                }
                                            }
                                            return false
                                        }
                                        if isArm64 {
                                            let end = start + length
                                            var svcOffsets: [Int] = []
                                            svcOffsets.reserveCapacity(4)
                                            let targetB0: UInt8 = swapped ? 0xD4 : 0x01
                                            let targetB1: UInt8 = swapped ? 0x00 : 0x10
                                            let targetB2: UInt8 = swapped ? 0x10 : 0x00
                                            let targetB3: UInt8 = swapped ? 0x01 : 0xD4
                                            let searchLimit = end - 3
                                            var p = start
                                            while p < searchLimit {
                                                guard let hitRaw = memchr(base.advanced(by: p), Int32(targetB0), searchLimit - p) else {
                                                    break
                                                }
                                                let hit = base.distance(to: hitRaw.assumingMemoryBound(to: UInt8.self))
                                                if base[hit &+ 1] == targetB1 && base[hit &+ 2] == targetB2 && base[hit &+ 3] == targetB3 {
                                                    svcOffsets.append(hit)
                                                    if svcOffsets.count >= 4 {
                                                        return true
                                                    }
                                                }
                                                p = hit &+ 1
                                            }
                                            var uniqueContextScores: [Int: Int] = [:]
                                            var qualifiedClusterRuns = 0
                                            for svcOff in svcOffsets {
                                                var runScore = 0
                                                var validInsnCount = 0
                                                var hasAdrpLdrPair = false
                                                var backWords: [UInt32] = []
                                                let minBackOff = max(start, svcOff - 32)
                                                var backGaps = 0
                                                var pendingBackGapPenalty = 0
                                                var preBackGapScore: Int? = nil
                                                var q = svcOff - 4
                                                while q >= minBackOff {
                                                    let rw = UnsafeRawPointer(base.advanced(by: q)).loadUnaligned(as: UInt32.self)
                                                    let w = swapped ? rw.byteSwapped : rw
                                                    if w == 0xD400_1001 {
                                                        q -= 4
                                                        continue
                                                    }
                                                    let sc = arm64SyscallContextScore(w)
                                                    if sc == 0 {
                                                        backGaps += 1
                                                        if backGaps > 1 { break }
                                                        if preBackGapScore == nil { preBackGapScore = runScore }
                                                        pendingBackGapPenalty += 4
                                                        q -= 4
                                                        continue
                                                    }
                                                    if pendingBackGapPenalty > 0 {
                                                        runScore -= pendingBackGapPenalty
                                                        pendingBackGapPenalty = 0
                                                    }
                                                    backWords.append(w)
                                                    validInsnCount += 1
                                                    let effective = (q == svcOff - 4 && sc >= 14) ? 20 : sc
                                                    runScore += effective
                                                    uniqueContextScores[q] = max(uniqueContextScores[q] ?? 0, effective)
                                                    q -= 4
                                                }
                                                if let preBackGapScore {
                                                    runScore = max(preBackGapScore, runScore)
                                                }
                                                let orderedBack = backWords.reversed()
                                                var prevAdrpRd: UInt32? = nil
                                                for w in orderedBack {
                                                    if (w & 0x9F00_0000) == 0x9000_0000 {
                                                        let rawImm = (((w >> 5) & 0x7_FFFF) << 2) | ((w >> 29) & 0x3)
                                                        let imm21 = (Int32(bitPattern: rawImm) << 11) >> 11
                                                        if abs(imm21) < 0x4000 {
                                                            prevAdrpRd = w & 0x1F
                                                            continue
                                                        }
                                                    }
                                                    if let rd = prevAdrpRd,
                                                       (w & 0x3B80_0000) == 0x3900_0000,
                                                       ((w >> 5) & 0x1F) == rd,
                                                       ((w >> 10) & 0xFFF) < 0x100 {
                                                        hasAdrpLdrPair = true
                                                    }
                                                    prevAdrpRd = nil
                                                }
                                                let maxFwdOff = min(searchLimit - 1, svcOff + 32)
                                                var fwdGaps = 0
                                                var pendingFwdGapPenalty = 0
                                                var preFwdGapScore: Int? = nil
                                                q = svcOff + 4
                                                while q <= maxFwdOff {
                                                    let rw = UnsafeRawPointer(base.advanced(by: q)).loadUnaligned(as: UInt32.self)
                                                    let w = swapped ? rw.byteSwapped : rw
                                                    if w == 0xD400_1001 {
                                                        q += 4
                                                        continue
                                                    }
                                                    let sc = arm64SyscallContextScore(w)
                                                    if sc == 0 {
                                                        fwdGaps += 1
                                                        if fwdGaps > 1 { break }
                                                        if preFwdGapScore == nil { preFwdGapScore = runScore }
                                                        pendingFwdGapPenalty += 4
                                                        q += 4
                                                        continue
                                                    }
                                                    if pendingFwdGapPenalty > 0 {
                                                        runScore -= pendingFwdGapPenalty
                                                        pendingFwdGapPenalty = 0
                                                    }
                                                    validInsnCount += 1
                                                    runScore += sc
                                                    uniqueContextScores[q] = max(uniqueContextScores[q] ?? 0, sc)
                                                    q += 4
                                                }
                                                if let preFwdGapScore {
                                                    runScore = max(preFwdGapScore, runScore)
                                                }
                                                if (validInsnCount >= 3 && runScore >= 17)
                                                    || (validInsnCount >= 2 && runScore >= 24)
                                                    || (hasAdrpLdrPair && validInsnCount >= 2 && runScore >= 12) {
                                                    return true
                                                }
                                                if validInsnCount >= 2 && runScore >= 12 {
                                                    qualifiedClusterRuns += 1
                                                }
                                                if length >= 64 {
                                                    let entStart = min(max(start, svcOff - 32), end - 64)
                                                    if windowEntropy(start: entStart, length: 64) < 4.8 {
                                                        return true
                                                    }
                                                }
                                            }
                                            if svcOffsets.count >= 2 && qualifiedClusterRuns >= 2 && uniqueContextScores.count >= 3 {
                                                let totalUniqueScore = uniqueContextScores.values.reduce(0, +)
                                                if totalUniqueScore >= 24 {
                                                    return true
                                                }
                                            }
                                            for ep in entryPointFileOffsets where ep >= start && ep + 64 <= end {
                                                if windowEntropy(start: ep, length: 64) < 4.8 {
                                                    return true
                                                }
                                                let epEnd = min(end - 3, ep + 61)
                                                var q = ep
                                                while q < epEnd {
                                                    let rw = UnsafeRawPointer(base.advanced(by: q)).loadUnaligned(as: UInt32.self)
                                                    let w = swapped ? rw.byteSwapped : rw
                                                    if w == 0xD400_1001 || w == 0xD65F_03C0 || w == 0xD65F_0FFF {
                                                        return true
                                                    }
                                                    q &+= 4
                                                }
                                            }
                                        }
                                        let entLen = min(length, 4096)
                                        if windowEntropy(start: start, length: entLen) < fairPlayEntropyThreshold(forLength: entLen) {
                                            return true
                                        }
                                        let subLimit = min(length, 1_048_576)
                                        var off = 0
                                        while off + 256 <= subLimit {
                                            if windowEntropy(start: start + off, length: 256) < 6.3 {
                                                return true
                                            }
                                            off += 256
                                        }
                                        return false
                                    }

                                    // Step A: Inspect each covered critical section's bounded byte span [sLo, sHi)
                                    // AND uncovered executable segment gaps [gapStart, gapEnd) intersecting [lo, hi)
                                    for seg in segments {
                                        for sect in seg.sections where sect.size > 0 {
                                            guard let sOff = Int(exactly: sect.offset),
                                                  let sSize = Int(exactly: sect.size),
                                                  sOff >= 0, sSize > 0, sOff < sliceData.count else {
                                                continue
                                            }
                                            let sEnd = min(sliceData.count, sOff + min(sSize, sliceData.count - sOff))
                                            let sLo = max(lo, sOff)
                                            let sHi = min(hi, sEnd)
                                            let sLen = sHi - sLo
                                            guard sLen > 0 else { continue }

                                            let sName = sect.sectionName
                                            let containsEntryPoint = entryPointFileOffsets.contains { $0 >= sOff && $0 < sEnd }
                                            if sName == "__info_plist" {
                                                if looksLikePlaintextPlistSpan(start: sLo, length: sLen) {
                                                    return true
                                                }
                                                if sLen >= 256 {
                                                    let entLen = min(sLen, 4096)
                                                    if windowEntropy(start: sLo, length: entLen) < fairPlayEntropyThreshold(forLength: entLen) {
                                                        return true
                                                    }
                                                }
                                            } else if sName == "__objc_methname" || sName == "__cstring" || sName == "__objc_classname" || sName == "__objc_methtype" {
                                                if hasPlaintextCStringSpan(start: sLo, length: sLen) {
                                                    return true
                                                }
                                            } else if containsEntryPoint || Self.shouldScanSectionForDirectSyscalls(sect, in: seg, sliceSize: sliceData.count) {
                                                if hasPlaintextCodeSpan(start: sLo, length: sLen) {
                                                    return true
                                                }
                                            }
                                        }

                                        let segStartCandidate = seg.fileOffset < UInt64(sliceData.count) ? Int(seg.fileOffset) : sliceData.count
                                        let (rawSegEnd, segOv) = seg.fileOffset.addingReportingOverflow(seg.fileSize)
                                        let clampedEnd64 = segOv ? UInt64(sliceData.count) : min(rawSegEnd, UInt64(sliceData.count))
                                        let segEndCandidate = Int(clampedEnd64)
                                        let hasEntryPointInSegment = segEndCandidate > segStartCandidate && entryPointFileOffsets.contains {
                                            $0 >= segStartCandidate && $0 < segEndCandidate
                                        }
                                        let isExecutableOrEntrySegment = ((seg.initialProtection & 0x04) != 0)
                                            || (((seg.maxProtection & 0x04) != 0) && hasEntryPointInSegment)

                                        if isExecutableOrEntrySegment && seg.fileSize > 0 && seg.fileOffset < UInt64(sliceData.count) {
                                            let segStart = segStartCandidate
                                            let segEnd = segEndCandidate
                                            guard segEnd - segStart >= 4, segEnd > lo, segStart < hi else { continue }

                                            var covered: [(Int, Int)] = []
                                            if segStart < commandsEnd {
                                                covered.append((segStart, min(segEnd, commandsEnd)))
                                            }
                                            for sect in seg.sections {
                                                let rawType = sect.flags & UInt32(SECTION_TYPE)
                                                let isZF = (rawType == UInt32(S_ZEROFILL) || rawType == UInt32(S_GB_ZEROFILL))
                                                if isZF && !Self.isZerofillInsideSegmentFilesize(sect, in: seg, sliceSize: sliceData.count) {
                                                    continue
                                                }
                                                guard sect.size > 0, UInt64(sect.offset) < UInt64(segEnd) else { continue }
                                                let (rawCEnd, cOv) = UInt64(sect.offset).addingReportingOverflow(sect.size)
                                                let isMetadataSection = !Self.shouldScanSectionForDirectSyscalls(sect, in: seg, sliceSize: sliceData.count)
                                                if isMetadataSection {
                                                    guard !cOv,
                                                          UInt64(sect.offset) >= UInt64(segStart),
                                                          rawCEnd <= UInt64(segEnd),
                                                          let cStart = Int(exactly: sect.offset),
                                                          let cEnd = Int(exactly: rawCEnd),
                                                          cEnd > cStart else { continue }
                                                    covered.append((cStart, cEnd))
                                                } else {
                                                    let clampedCEnd = cOv ? UInt64(segEnd) : min(rawCEnd, UInt64(segEnd))
                                                    let cStart = max(segStart, Int(sect.offset))
                                                    let cEnd = Int(clampedCEnd)
                                                    if cEnd > cStart {
                                                        covered.append((cStart, cEnd))
                                                    }
                                                }
                                            }
                                            covered.sort { $0.0 < $1.0 }

                                            var cursor = segStart
                                            for (ivStart, ivEnd) in covered {
                                                if ivStart > cursor {
                                                    let gLo = max(lo, cursor)
                                                    let gHi = min(hi, ivStart)
                                                    if gHi - gLo >= 4 && hasPlaintextCodeSpan(start: gLo, length: gHi - gLo) {
                                                        return true
                                                    }
                                                }
                                                if ivEnd > cursor {
                                                    cursor = ivEnd
                                                }
                                            }
                                            if cursor < segEnd {
                                                let gLo = max(lo, cursor)
                                                let gHi = min(hi, segEnd)
                                                if gHi - gLo >= 4 && hasPlaintextCodeSpan(start: gLo, length: gHi - gLo) {
                                                    return true
                                                }
                                            }
                                        }
                                    }

                                    // Step B: Verify every 4 KB page across [lo, hi) (including > 128 MB ranges without skipping [512, 4096))
                                    if totalLen < 4096 {
                                        return windowEntropy(start: lo, length: totalLen) < fairPlayEntropyThreshold(forLength: totalLen)
                                    }

                                    let winSize = 4096
                                    let maxStart = hi - winSize
                                    let totalWindows = totalLen / winSize
                                    for idx in 0..<totalWindows {
                                        if windowEntropy(start: lo + idx * winSize, length: winSize) < 7.6 {
                                            return true
                                        }
                                    }
                                    if lo + totalWindows * winSize != hi {
                                        if windowEntropy(start: maxStart, length: winSize) < 7.6 {
                                            return true
                                        }
                                    }

                                    for ep in entryPointFileOffsets where ep >= lo && ep < hi {
                                        let wStart = min(max(lo, ep & ~(winSize - 1)), maxStart)
                                        if windowEntropy(start: wStart, length: winSize) < 7.6 {
                                            return true
                                        }
                                        if ep + 256 <= hi && windowEntropy(start: ep, length: 256) < 6.3 {
                                            return true
                                        }
                                    }
                                    return false
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private static let sensitiveSelectorNeedles: [[UInt8]] = {
        var rawSet: Set<String> = [
            "bundleWithPath:", "bundleWithURL:", "initWithPath:", "initWithURL:",
            "NSClassFromString", "NSSelectorFromString", "sel_registerName", "load",
            IOCTokenArmor.tASAccSess, IOCTokenArmor.tSysPhotoLib,
            IOCTokenArmor.tGenPasteboard, IOCTokenArmor.tUIPasteboard,
            IOCTokenArmor.tPLPhotoLib, IOCTokenArmor.tPhotoLibSvc,
            IOCTokenArmor.tFsgetpath, IOCTokenArmor.tCqCreate
        ]
        for s in SignatureCatalog.privateContainerSymbols.keys { rawSet.insert(s) }
        for s in SignatureCatalog.pathEnumerationSymbols.keys { rawSet.insert(s) }
        for s in SignatureCatalog.standaloneExploitSymbolRules.keys { rawSet.insert(s) }
        for s in ExpandedThreatCatalog.photosSymbols { rawSet.insert(s) }
        for s in ExpandedThreatCatalog.pasteboardSymbols { rawSet.insert(s) }
        for s in ExpandedThreatCatalog.brotliSymbols { rawSet.insert(s) }
        var out: [[UInt8]] = []
        for s in rawSet where s.utf8.count >= 2 && s.utf8.count <= 512 {
            out.append(Array(s.utf8))
            if !s.hasPrefix("_") {
                out.append(Array(("_" + s).utf8))
            }
        }
        return out
    }()

    private static let sensitiveSelectorBuckets: [[[UInt8]]] = {
        var buckets = [[[UInt8]]](repeating: [], count: 256)
        for needle in sensitiveSelectorNeedles {
            if let first = needle.first {
                buckets[Int(first)].append(needle)
            }
        }
        return buckets
    }()

    private static let sensitiveSelectorSubstringNeedles: [[UInt8]] = [
        "bundleWithPath:", "bundleWithURL:", "initWithPath:", "initWithURL:",
        "NSClassFromString", "NSSelectorFromString", "sel_registerName",
        IOCTokenArmor.tASAccSess, IOCTokenArmor.tSysPhotoLib,
        IOCTokenArmor.tGenPasteboard, IOCTokenArmor.tUIPasteboard
    ].map { Array($0.utf8) }

    private static let minSubNeedleLen: Int = {
        sensitiveSelectorSubstringNeedles.map(\.count).min() ?? 12
    }()

    private static let exactSelectorPairLenMaskTable: [UInt64] = {
        var table = [UInt64](repeating: 0, count: 65_536)
        for needle in sensitiveSelectorNeedles where needle.count >= 2 {
            let key = (Int(needle[0]) << 8) | Int(needle[1])
            let bit = needle.count < 63 ? (UInt64(1) << needle.count) : (UInt64(1) << 62)
            table[key] |= bit
        }
        for needle in sensitiveSelectorSubstringNeedles where needle.count >= 2 {
            let key = (Int(needle[0]) << 8) | Int(needle[1])
            table[key] |= (UInt64(1) << 63)
        }
        return table
    }()

    private static let fairPlayExtraCStringNeedles: [[UInt8]] = {
        var rawSet: Set<String> = [
            "dlopen", "dlsym", "ptrace", "sysctl", "sysctlbyname", "task_for_pid",
            "objc_getClass", "objc_lookUpClass", "objc_getRequiredClass", "sel_getUid",
            "symlink", "symlinkat", "ElleKit", "FridaGadget", "libhooker",
            "CydiaSubstrate", "libsubstitute", "CFBundleLoadExecutable",
            "CFBundleLoadExecutableAndReturnError", "CFBundleGetFunctionPointerForName",
            SignatureCatalog.targetDylibName,
            IOCTokenArmor.tAudioDaemon, IOCTokenArmor.tCoreMediaDaemon,
            IOCTokenArmor.tBookDaemon, IOCTokenArmor.tStoreDaemon,
            IOCTokenArmor.tBookSQLite, IOCTokenArmor.tDownloadsSQLite,
            IOCTokenArmor.tGestaltPlist, IOCTokenArmor.tGestaltGroup,
            IOCTokenArmor.tMediaExpFw, IOCTokenArmor.tBookPrivFw,
            IOCTokenArmor.tPhotoLibFw, IOCTokenArmor.tAssetsLibFw,
            IOCTokenArmor.tAccSetupFw
        ]
        for s in SignatureCatalog.directXPCRules.keys { rawSet.insert(s) }
        for s in SignatureCatalog.standaloneExploitStringRules.keys { rawSet.insert(s) }
        var out: [[UInt8]] = []
        for s in rawSet where s.utf8.count >= 5 && s.utf8.count <= 512 {
            out.append(Array(s.utf8))
            if !s.hasPrefix("_") {
                out.append(Array(("_" + s).utf8))
            }
        }
        return out
    }()

    private static let fairPlayExtraCStringBuckets: [[[UInt8]]] = {
        var buckets = [[[UInt8]]](repeating: [], count: 256)
        for needle in fairPlayExtraCStringNeedles {
            if let first = needle.first {
                buckets[Int(first)].append(needle)
            }
        }
        return buckets
    }()

    private static let fairPlayExtraPairLenMaskTable: [UInt64] = {
        var table = [UInt64](repeating: 0, count: 65_536)
        for needle in fairPlayExtraCStringNeedles where needle.count >= 2 {
            let key = (Int(needle[0]) << 8) | Int(needle[1])
            let bit = needle.count < 63 ? (UInt64(1) << needle.count) : (UInt64(1) << 62)
            table[key] |= bit
        }
        return table
    }()

    private static let substringAutomatonDFATable: [UInt16] = {
        let needles = sensitiveSelectorSubstringNeedles
        var trieNext: [[Int]] = [[Int](repeating: -1, count: 256)]
        var isAccept: [Bool] = [false]

        for needle in needles where !needle.isEmpty {
            var state = 0
            for b in needle {
                let bi = Int(b)
                if trieNext[state][bi] == -1 {
                    let newState = trieNext.count
                    trieNext[state][bi] = newState
                    trieNext.append([Int](repeating: -1, count: 256))
                    isAccept.append(false)
                }
                state = trieNext[state][bi]
            }
            isAccept[state] = true
        }

        let stateCount = trieNext.count
        var fail = [Int](repeating: 0, count: stateCount)
        var dfa = [UInt16](repeating: 0, count: stateCount * 256)

        var queue: [Int] = []
        queue.reserveCapacity(stateCount)
        for b in 0..<256 {
            let nx = trieNext[0][b]
            if nx != -1 {
                fail[nx] = 0
                dfa[b] = isAccept[nx] ? (UInt16(nx) | 0x8000) : UInt16(nx)
                queue.append(nx)
            } else {
                dfa[b] = 0
            }
        }

        var head = 0
        while head < queue.count {
            let s = queue[head]
            head += 1
            let f = fail[s]
            let sBase = s * 256
            let fBase = f * 256
            for b in 0..<256 {
                let nx = trieNext[s][b]
                if nx != -1 {
                    let fTrans = Int(dfa[fBase + b] & 0x7FFF)
                    fail[nx] = fTrans
                    if isAccept[fTrans] {
                        isAccept[nx] = true
                    }
                    dfa[sBase + b] = isAccept[nx] ? (UInt16(nx) | 0x8000) : UInt16(nx)
                    queue.append(nx)
                } else {
                    dfa[sBase + b] = dfa[fBase + b]
                }
            }
        }

        return dfa
    }()

    /// Extracts Objective-C selector strings from unencrypted `__objc_methname` sections (or unencrypted sub-ranges
    /// when a partial `LC_ENCRYPTION_INFO_64` overlaps only part of `__objc_methname`)
    /// so stripped release binaries without `LC_SYMTAB` entries still surface private/sensitive selectors.
    public var objcMethodNames: [String] {
        let encRange: Range<Int>?
        if isFairPlayEncrypted && !hasForgedPlaintextFairPlayRange {
            guard let range = encryptionInfo?.encryptedRange else { return [] }
            encRange = range
        } else {
            encRange = nil
        }

        // Collect, sort, and merge all unencrypted `__objc_methname` subranges so overlapping headers never double-scan.
        var rawSubranges: [Range<Int>] = []
        for seg in segments {
            for sect in seg.sections where sect.sectionName == "__objc_methname" && sect.size > 0 {
                guard let start = Int(exactly: sect.offset),
                      let sizeInt = Int(exactly: sect.size),
                      start >= 0, sizeInt > 0,
                      start <= sliceData.count,
                      sizeInt <= sliceData.count - start else {
                    continue
                }
                let sectRange = start..<(start + sizeInt)
                if let er = encRange {
                    if er.lowerBound <= sectRange.lowerBound && er.upperBound >= sectRange.upperBound {
                        continue
                    }
                    if sectRange.lowerBound < er.lowerBound {
                        rawSubranges.append(sectRange.lowerBound..<min(sectRange.upperBound, er.lowerBound))
                    }
                    if er.upperBound < sectRange.upperBound {
                        rawSubranges.append(max(sectRange.lowerBound, er.upperBound)..<sectRange.upperBound)
                    }
                } else {
                    rawSubranges.append(sectRange)
                }
            }
        }
        guard !rawSubranges.isEmpty else { return [] }

        rawSubranges.sort { $0.lowerBound < $1.lowerBound }
        var mergedSubranges: [Range<Int>] = []
        for r in rawSubranges where !r.isEmpty {
            if let last = mergedSubranges.last, r.lowerBound <= last.upperBound {
                mergedSubranges[mergedSubranges.count - 1] = last.lowerBound..<max(last.upperBound, r.upperBound)
            } else {
                mergedSubranges.append(r)
            }
        }

        var selectors: [String] = []
        var seen: Set<String> = []
        let maxTotalScanBytes = 32 * 1024 * 1024
        let headScanBudget = 24 * 1024 * 1024
        let tailScanBudget = 8 * 1024 * 1024
        let maxMiddleGapScanBytes = 1024 * 1024 * 1024
        let maxHeadSelectors = 65_536
        let maxTotalSelectors = maxHeadSelectors + 32_768
        let maxGeneralBeforeTail = maxTotalSelectors - 16_384
        let tailRingCapacity = 8_192
        var tailRing = [(offset: Int, len: Int)](repeating: (0, 0), count: tailRingCapacity)
        var tailRingCount = 0
        var tailRingCursor = 0
        let buckets = Self.sensitiveSelectorBuckets
        let minSubLen = Self.minSubNeedleLen

        let totalMergedBytes = mergedSubranges.reduce(0) { $0 + $1.count }
        let isLargeScan = totalMergedBytes > maxTotalScanBytes
        let activeHeadLimit = isLargeScan ? headScanBudget : maxTotalScanBytes

        // Determine head subranges, optional tail subranges, and any skipped middle gap subranges
        var headSubranges: [Range<Int>] = []
        var remHead = activeHeadLimit
        var headStopOffset = mergedSubranges.first?.lowerBound ?? 0
        for r in mergedSubranges where remHead > 0 {
            let take = min(r.count, remHead)
            let part = r.lowerBound..<(r.lowerBound + take)
            headSubranges.append(part)
            headStopOffset = part.upperBound
            remHead -= take
        }

        var tailSubranges: [Range<Int>] = []
        var gapSubranges: [(range: Range<Int>, minBack: Int)] = []
        if isLargeScan {
            var remTail = tailScanBudget
            var tailStartOffset = mergedSubranges.last?.upperBound ?? headStopOffset
            for r in mergedSubranges.reversed() where remTail > 0 && r.upperBound > headStopOffset {
                let availLower = max(r.lowerBound, headStopOffset)
                let availCount = r.upperBound - availLower
                let take = min(availCount, remTail)
                let tailStart = r.upperBound - take
                tailSubranges.append(tailStart..<r.upperBound)
                tailStartOffset = tailStart
                remTail -= take
            }
            tailSubranges.reverse()

            var remGap = maxMiddleGapScanBytes
            for r in mergedSubranges where remGap > 0 {
                let lo = max(r.lowerBound, headStopOffset)
                let hi = min(r.upperBound, tailStartOffset)
                if lo < hi {
                    let take = min(hi - lo, remGap)
                    gapSubranges.append((range: lo..<(lo + take), minBack: r.lowerBound))
                    remGap -= take
                }
            }
        }

        var parallelScanRanges: [(range: Range<Int>, minBack: Int)] = []

        sliceData.withUnsafeBytes { raw in
            guard let sliceBase = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return
            }
            let totalSliceBytes = raw.count

            let sliceAddr = Int(bitPattern: sliceBase)

            Self.exactSelectorPairLenMaskTable.withUnsafeBufferPointer { exactPairBuf in
                Self.substringAutomatonDFATable.withUnsafeBufferPointer { dfaBuf in
                    guard let exactPairPtr = exactPairBuf.baseAddress,
                          let dfaPtr = dfaBuf.baseAddress else { return }
                    let exactAddr = Int(bitPattern: exactPairPtr)
                    let dfaAddr = Int(bitPattern: dfaPtr)

                    @Sendable
                    func scanSensitiveChunk(
                        _ chunkRange: Range<Int>,
                        minBack: Int,
                        outMatches: inout [(str: String, isExact: Bool)]
                    ) {
                        let cSliceBase = UnsafePointer<UInt8>(bitPattern: sliceAddr)!
                        let cExactPairPtr = UnsafePointer<UInt64>(bitPattern: exactAddr)!
                        let cDfaPtr = UnsafePointer<UInt16>(bitPattern: dfaAddr)!
                        var startOff = chunkRange.lowerBound
                        if startOff > minBack {
                            let backLimit = max(minBack, startOff - 512)
                            var s = startOff
                            while s > backLimit && cSliceBase[s - 1] != 0 {
                                s -= 1
                            }
                            if (s > 0 && cSliceBase[s - 1] == 0) || s == minBack {
                                startOff = s
                            }
                        }
                        let subLen = chunkRange.upperBound - startOff
                        guard subLen > 0 else { return }
                        let base = cSliceBase + startOff
                        let baseAddr = Int(bitPattern: base)
                        let overrunLimit = min(totalSliceBytes - startOff, subLen + 512)
                        var subMatchCount = 0
                        var cur = 0
                        while cur < subLen {
                            if base[cur] == 0 {
                                cur &+= 1
                                continue
                            }
                            let strStart = cur
                            let searchLim = (subLen &- strStart) <= 512 ? overrunLimit : subLen
                            let misalign = (baseAddr &+ cur) & 7
                            if misalign != 0 {
                                let alignLim = min(searchLim, cur &+ (8 &- misalign))
                                while cur < alignLim && base[cur] != 0 {
                                    cur &+= 1
                                }
                            }
                            if cur < searchLim && base[cur] != 0 && cur &+ 8 <= searchLim {
                                let u64Ptr = UnsafePointer<UInt64>(bitPattern: baseAddr &+ cur)!
                                let maxQ = (searchLim &- cur) >> 3
                                var qIdx = 0
                                while qIdx < maxQ {
                                    let w = u64Ptr[qIdx].littleEndian
                                    let z = (w &- 0x0101_0101_0101_0101) & ~w & 0x8080_8080_8080_8080
                                    if z != 0 {
                                        cur &+= (qIdx << 3) &+ (z.trailingZeroBitCount >> 3)
                                        break
                                    }
                                    qIdx &+= 1
                                }
                                if qIdx == maxQ {
                                    cur &+= (maxQ << 3)
                                    while cur < searchLim && base[cur] != 0 {
                                        cur &+= 1
                                    }
                                }
                            } else if cur < searchLim && base[cur] != 0 {
                                while cur < searchLim && base[cur] != 0 {
                                    cur &+= 1
                                }
                            }
                            let len = cur &- strStart
                            if len >= 2 && len <= 512 {
                                var exactMatched = false
                                var subMatched = false
                                let b0 = Int(base[strStart])
                                let b1 = Int(base[strStart &+ 1])
                                let firstPair = (b0 << 8) | b1
                                let pairMask = cExactPairPtr[firstPair]
                                let lenBit = len < 63 ? (UInt64(1) << len) : (UInt64(1) << 62)
                                if (pairMask & lenBit) != 0 {
                                    for needle in buckets[b0] where needle.count == len && needle[1] == UInt8(b1) {
                                        var idx = 2
                                        while idx < len && base[strStart &+ idx] == needle[idx] {
                                            idx &+= 1
                                        }
                                        if idx == len {
                                            exactMatched = true
                                            break
                                        }
                                    }
                                }
                                if !exactMatched && len >= minSubLen {
                                    var state = 0
                                    var p = strStart
                                    let pEnd = strStart &+ len
                                    while p < pEnd {
                                        let nx = Int(cDfaPtr[(state << 8) | Int(base[p])])
                                        if (nx & 0x8000) != 0 {
                                            subMatched = true
                                            break
                                        }
                                        state = nx
                                        p &+= 1
                                    }
                                }
                                if exactMatched {
                                    if outMatches.count < maxTotalSelectors + 1_024 {
                                        let s = String(decoding: UnsafeBufferPointer(start: base + strStart, count: len), as: UTF8.self)
                                        if !s.isEmpty {
                                            outMatches.append((s, true))
                                        }
                                    }
                                } else if subMatched && subMatchCount < maxTotalSelectors {
                                    let s = String(decoding: UnsafeBufferPointer(start: base + strStart, count: len), as: UTF8.self)
                                    if !s.isEmpty {
                                        outMatches.append((s, false))
                                        subMatchCount += 1
                                    }
                                }
                            }
                        }
                    }

                    func scanLinearRange(_ subRange: Range<Int>, collectTailRing: Bool, deferPhase2IfLarge: Bool, subMatchLimit: Int) {
                        let subLen = subRange.count
                        let base = sliceBase + subRange.lowerBound
                        let baseAddr = Int(bitPattern: base)
                        var cur = 0

                        // Phase 1: Collect up to `maxHeadSelectors` unique selectors
                        while cur < subLen && selectors.count < maxHeadSelectors {
                            if base[cur] == 0 {
                                cur &+= 1
                                continue
                            }
                            let strStart = cur
                            let misalign = (baseAddr &+ cur) & 7
                            if misalign != 0 {
                                let alignLim = min(subLen, cur &+ (8 &- misalign))
                                while cur < alignLim && base[cur] != 0 {
                                    cur &+= 1
                                }
                            }
                            if cur < subLen && base[cur] != 0 && cur &+ 8 <= subLen {
                                let u64Ptr = UnsafePointer<UInt64>(bitPattern: baseAddr &+ cur)!
                                let maxQ = (subLen &- cur) >> 3
                                var qIdx = 0
                                while qIdx < maxQ {
                                    let w = u64Ptr[qIdx].littleEndian
                                    let z = (w &- 0x0101_0101_0101_0101) & ~w & 0x8080_8080_8080_8080
                                    if z != 0 {
                                        cur &+= (qIdx << 3) &+ (z.trailingZeroBitCount >> 3)
                                        break
                                    }
                                    qIdx &+= 1
                                }
                                if qIdx == maxQ {
                                    cur &+= (maxQ << 3)
                                    while cur < subLen && base[cur] != 0 {
                                        cur &+= 1
                                    }
                                }
                            } else if cur < subLen && base[cur] != 0 {
                                while cur < subLen && base[cur] != 0 {
                                    cur &+= 1
                                }
                            }
                            let len = cur &- strStart
                            if len >= 2 && len <= 512 {
                                let s = String(decoding: UnsafeBufferPointer(start: base + strStart, count: len), as: UTF8.self)
                                if !s.isEmpty && seen.insert(s).inserted {
                                    selectors.append(s)
                                }
                            }
                        }

                        if deferPhase2IfLarge && (subLen - cur) >= 4 * 1024 * 1024 {
                            parallelScanRanges.append((range: (subRange.lowerBound + cur)..<subRange.upperBound, minBack: subRange.lowerBound))
                            return
                        }

                        // Phase 2: Zero-allocation middle needle matching + tail ring buffer if head cap was hit
                        while cur < subLen {
                            if base[cur] == 0 {
                                cur &+= 1
                                continue
                            }
                            let strStart = cur
                            let misalign = (baseAddr &+ cur) & 7
                            if misalign != 0 {
                                let alignLim = min(subLen, cur &+ (8 &- misalign))
                                while cur < alignLim && base[cur] != 0 {
                                    cur &+= 1
                                }
                            }
                            if cur < subLen && base[cur] != 0 && cur &+ 8 <= subLen {
                                let u64Ptr = UnsafePointer<UInt64>(bitPattern: baseAddr &+ cur)!
                                let maxQ = (subLen &- cur) >> 3
                                var qIdx = 0
                                while qIdx < maxQ {
                                    let w = u64Ptr[qIdx].littleEndian
                                    let z = (w &- 0x0101_0101_0101_0101) & ~w & 0x8080_8080_8080_8080
                                    if z != 0 {
                                        cur &+= (qIdx << 3) &+ (z.trailingZeroBitCount >> 3)
                                        break
                                    }
                                    qIdx &+= 1
                                }
                                if qIdx == maxQ {
                                    cur &+= (maxQ << 3)
                                    while cur < subLen && base[cur] != 0 {
                                        cur &+= 1
                                    }
                                }
                            } else if cur < subLen && base[cur] != 0 {
                                while cur < subLen && base[cur] != 0 {
                                    cur &+= 1
                                }
                            }
                            let len = cur &- strStart
                            if len >= 2 && len <= 512 {
                                var exactMatched = false
                                var subMatched = false
                                let b0 = Int(base[strStart])
                                let b1 = Int(base[strStart &+ 1])
                                let firstPair = (b0 << 8) | b1
                                let pairMask = exactPairPtr[firstPair]
                                let lenBit = len < 63 ? (UInt64(1) << len) : (UInt64(1) << 62)
                                if (pairMask & lenBit) != 0 {
                                    for needle in buckets[b0] where needle.count == len && needle[1] == UInt8(b1) {
                                        var idx = 2
                                        while idx < len && base[strStart &+ idx] == needle[idx] {
                                            idx &+= 1
                                        }
                                        if idx == len {
                                            exactMatched = true
                                            break
                                        }
                                    }
                                }
                                if !exactMatched && len >= minSubLen {
                                    var state = 0
                                    var p = strStart
                                    let pEnd = strStart &+ len
                                    while p < pEnd {
                                        let nx = Int(dfaPtr[(state << 8) | Int(base[p])])
                                        if (nx & 0x8000) != 0 {
                                            subMatched = true
                                            break
                                        }
                                        state = nx
                                        p &+= 1
                                    }
                                }

                                if exactMatched {
                                    if selectors.count < maxTotalSelectors + 1_024 {
                                        let s = String(decoding: UnsafeBufferPointer(start: base + strStart, count: len), as: UTF8.self)
                                        if !s.isEmpty && seen.insert(s).inserted {
                                            selectors.append(s)
                                        }
                                    }
                                } else if subMatched {
                                    if selectors.count < subMatchLimit {
                                        let s = String(decoding: UnsafeBufferPointer(start: base + strStart, count: len), as: UTF8.self)
                                        if !s.isEmpty && seen.insert(s).inserted {
                                            selectors.append(s)
                                        }
                                    }
                                } else if collectTailRing {
                                    tailRing[tailRingCursor] = (subRange.lowerBound + strStart, len)
                                    tailRingCursor = (tailRingCursor + 1) % tailRingCapacity
                                    if tailRingCount < tailRingCapacity {
                                        tailRingCount += 1
                                    }
                                }
                            }
                        }
                    }

                    for subRange in headSubranges where !subRange.isEmpty {
                        scanLinearRange(
                            subRange,
                            collectTailRing: !isLargeScan,
                            deferPhase2IfLarge: isLargeScan,
                            subMatchLimit: isLargeScan ? maxGeneralBeforeTail : maxTotalSelectors
                        )
                    }

                    for gap in gapSubranges where !gap.range.isEmpty {
                        parallelScanRanges.append((range: gap.range, minBack: gap.minBack))
                    }

                    if !parallelScanRanges.isEmpty {
                        let totalParallelBytes = parallelScanRanges.reduce(0) { $0 + $1.range.count }
                        if totalParallelBytes >= 8 * 1024 * 1024 {
                            let targetChunks = min(8, max(2, ProcessInfo.processInfo.activeProcessorCount))
                            let chunkSize = max(2 * 1024 * 1024, (totalParallelBytes + targetChunks - 1) / targetChunks)
                            var chunks: [(range: Range<Int>, minBack: Int)] = []
                            for item in parallelScanRanges {
                                var lo = item.range.lowerBound
                                while lo < item.range.upperBound {
                                    let hi = min(item.range.upperBound, lo + chunkSize)
                                    chunks.append((range: lo..<hi, minBack: item.minBack))
                                    lo = hi
                                }
                            }
                            let immutableChunks = chunks
                            let chunkCount = immutableChunks.count
                            final class ChunkResultsBox: @unchecked Sendable {
                                var items: [[(str: String, isExact: Bool)]]
                                init(count: Int) { self.items = Array(repeating: [], count: count) }
                            }
                            let resultsLock = NSLock()
                            let resultsBox = ChunkResultsBox(count: chunkCount)
                            DispatchQueue.concurrentPerform(iterations: chunkCount) { idx in
                                var localMatches: [(str: String, isExact: Bool)] = []
                                scanSensitiveChunk(immutableChunks[idx].range, minBack: immutableChunks[idx].minBack, outMatches: &localMatches)
                                if !localMatches.isEmpty {
                                    resultsLock.lock()
                                    resultsBox.items[idx] = localMatches
                                    resultsLock.unlock()
                                }
                            }
                            for localList in resultsBox.items {
                                for item in localList {
                                    if item.isExact {
                                        if selectors.count < maxTotalSelectors + 1_024 && seen.insert(item.str).inserted {
                                            selectors.append(item.str)
                                        }
                                    } else if selectors.count < maxGeneralBeforeTail && seen.insert(item.str).inserted {
                                        selectors.append(item.str)
                                    }
                                }
                            }
                        } else {
                            var localMatches: [(str: String, isExact: Bool)] = []
                            for item in parallelScanRanges {
                                scanSensitiveChunk(item.range, minBack: item.minBack, outMatches: &localMatches)
                            }
                            for item in localMatches {
                                if item.isExact {
                                    if selectors.count < maxTotalSelectors + 1_024 && seen.insert(item.str).inserted {
                                        selectors.append(item.str)
                                    }
                                } else if selectors.count < maxGeneralBeforeTail && seen.insert(item.str).inserted {
                                    selectors.append(item.str)
                                }
                            }
                        }
                    }

                    for (idx, subRange) in tailSubranges.enumerated() where !subRange.isEmpty {
                        var adjustedRange = subRange
                        if idx == 0 {
                            let containingMinBack = mergedSubranges.first {
                                adjustedRange.lowerBound >= $0.lowerBound && adjustedRange.lowerBound <= $0.upperBound
                            }?.lowerBound ?? headStopOffset
                            if adjustedRange.lowerBound > containingMinBack {
                                let backLimit = max(containingMinBack, adjustedRange.lowerBound - 512)
                                var s = adjustedRange.lowerBound
                                while s > backLimit && sliceBase[s - 1] != 0 {
                                    s -= 1
                                }
                                if (s > 0 && sliceBase[s - 1] == 0) || s == containingMinBack {
                                    adjustedRange = s..<adjustedRange.upperBound
                                }
                            }
                        }
                        scanLinearRange(adjustedRange, collectTailRing: true, deferPhase2IfLarge: false, subMatchLimit: maxTotalSelectors)
                    }

                    if tailRingCount > 0 {
                        let startRing = tailRingCount < tailRingCapacity ? 0 : tailRingCursor
                        for i in 0..<tailRingCount {
                            let span = tailRing[(startRing + i) % tailRingCapacity]
                            let s = String(
                                decoding: UnsafeBufferPointer(start: sliceBase.advanced(by: span.offset), count: span.len),
                                as: UTF8.self
                            )
                            if !s.isEmpty && seen.insert(s).inserted {
                                selectors.append(s)
                            }
                        }
                    }
                }
            }
        }
        return selectors
    }

    /// Extracts an embedded `__info_plist` section (`-sectcreate __TEXT __info_plist`) from unencrypted section bytes
    /// so standalone Mach-O executables/helpers/dylibs carry full `Info.plist` metadata into threat evaluation.
    public var embeddedInfoPlist: [String: Any]? {
        let encRange: Range<Int>?
        if isFairPlayEncrypted && !hasForgedPlaintextFairPlayRange {
            guard let range = encryptionInfo?.encryptedRange else { return nil }
            encRange = range
        } else {
            encRange = nil
        }

        struct PlistSliceKey: Hashable { let lower: Int; let upper: Int }
        var seenPlistSlices: Set<PlistSliceKey> = []
        var sectionChecks = 0
        let maxSectionChecks = 32_768

        let smallThreshold = 64 * 1024
        let mediumThreshold = 1024 * 1024

        var smallFailedAttempts = 0
        var smallFailedBytes = 0
        let maxSmallFailedAttempts = 16_384
        let maxSmallFailedBytes = 16 * 1024 * 1024

        var mediumFailedAttempts = 0
        var mediumFailedBytes = 0
        let maxMediumFailedAttempts = 512
        let maxMediumFailedBytes = 32 * 1024 * 1024

        var largeFailedAttempts = 0
        var largeFailedBytes = 0
        let maxLargeFailedAttempts = 16
        let maxLargeFailedBytes = 32 * 1024 * 1024

        var openStepFailedAttempts = 0
        var openStepFailedBytes = 0
        let maxOpenStepFailedAttempts = 256
        let maxOpenStepFailedBytes = 1024 * 1024
        let maxSingleOpenStepBytes = 1024 * 1024

        var smallStructuralScanBytes = 0
        let maxSmallStructuralScanBytes = 32 * 1024 * 1024
        var mediumStructuralScanBytes = 0
        let maxMediumStructuralScanBytes = 64 * 1024 * 1024
        var largeStructuralScanBytes = 0
        let maxLargeStructuralScanBytes = 64 * 1024 * 1024
        var openStepStructuralScanBytes = 0
        let maxOpenStepStructuralScanBytes = 2 * 1024 * 1024
        var largeLeadingWhitespaceBytes = 0
        let maxLargeLeadingWhitespaceBytes = 8 * 1024 * 1024
        var smallMediumLeadingWhitespaceBytes = 0
        let maxSmallMediumLeadingWhitespaceBytes = 16 * 1024 * 1024

        @inline(__always)
        func consumeStructuralScanBudget(_ bytes: Int, sectionSize: Int) -> Bool {
            if sectionSize <= smallThreshold {
                guard smallStructuralScanBytes + bytes <= maxSmallStructuralScanBytes else { return false }
                smallStructuralScanBytes += bytes
                return true
            } else if sectionSize <= mediumThreshold {
                guard mediumStructuralScanBytes + bytes <= maxMediumStructuralScanBytes else { return false }
                mediumStructuralScanBytes += bytes
                return true
            } else {
                guard largeStructuralScanBytes + bytes <= maxLargeStructuralScanBytes else { return false }
                largeStructuralScanBytes += bytes
                return true
            }
        }

        @inline(__always)
        func canAttemptParse(sectionSize: Int) -> Bool {
            if sectionSize <= smallThreshold {
                return smallFailedAttempts < maxSmallFailedAttempts && smallFailedBytes + sectionSize <= maxSmallFailedBytes
            } else if sectionSize <= mediumThreshold {
                return mediumFailedAttempts < maxMediumFailedAttempts && mediumFailedBytes + sectionSize <= maxMediumFailedBytes
            } else {
                return largeFailedAttempts < maxLargeFailedAttempts && largeFailedBytes + sectionSize <= maxLargeFailedBytes
            }
        }

        @inline(__always)
        func canAttemptOpenStepParse(sectionSize: Int) -> Bool {
            return sectionSize <= maxSingleOpenStepBytes
                && openStepFailedAttempts < maxOpenStepFailedAttempts
                && openStepFailedBytes + sectionSize <= maxOpenStepFailedBytes
        }

        @inline(__always)
        func recordFailedParse(sectionSize: Int) {
            if sectionSize <= smallThreshold {
                smallFailedAttempts += 1
                smallFailedBytes += sectionSize
            } else if sectionSize <= mediumThreshold {
                mediumFailedAttempts += 1
                mediumFailedBytes += sectionSize
            } else {
                largeFailedAttempts += 1
                largeFailedBytes += sectionSize
            }
        }

        @inline(__always)
        func recordFailedOpenStepParse(sectionSize: Int) {
            openStepFailedAttempts += 1
            openStepFailedBytes += sectionSize
        }

        enum CandidatePlistKind {
            case none
            case xmlOrBplist
            case openStep
        }

        var emptyPlistFallback: [String: Any]? = nil

        @inline(__always)
        func hasASCIIRun(_ base: UnsafePointer<UInt8>, at pos: Int, end: Int, _ prefix: StaticString) -> Bool {
            let pLen = prefix.utf8CodeUnitCount
            guard pos + pLen <= end else { return false }
            return prefix.withUTF8Buffer { pBuf in
                for k in 0..<pLen where base[pos + k] != pBuf[k] {
                    return false
                }
                return true
            }
        }

        @inline(__always)
        func hasCaseInsensitiveASCIIRun(_ base: UnsafePointer<UInt8>, at pos: Int, end: Int, _ lowerPrefix: StaticString) -> Bool {
            let pLen = lowerPrefix.utf8CodeUnitCount
            guard pos + pLen <= end else { return false }
            return lowerPrefix.withUTF8Buffer { pBuf in
                for k in 0..<pLen {
                    let b = base[pos + k]
                    let lower = (b >= 0x41 && b <= 0x5A) ? (b + 32) : b
                    if lower != pBuf[k] { return false }
                }
                return true
            }
        }

        @inline(__always)
        func containsByte(_ base: UnsafePointer<UInt8>, from start: Int, to end: Int, _ target: UInt8) -> Bool {
            guard start < end else { return false }
            return memchr(base.advanced(by: start), Int32(target), end - start) != nil
        }

        @inline(__always)
        func containsASCIIXMLPlistStructure(_ base: UnsafePointer<UInt8>, from start: Int, to end: Int) -> Bool {
            var sawPlistOpen = false
            var sawClosing = false
            var p = start
            while p < end {
                let b = base[p]
                if b == 0x3C { // '<'
                    if !sawPlistOpen && p + 6 <= end && hasCaseInsensitiveASCIIRun(base, at: p + 1, end: end, "plist") {
                        sawPlistOpen = true
                        if sawClosing { return true }
                    }
                    if !sawClosing && p + 2 <= end && base[p + 1] == 0x2F { // '</'
                        if (p + 8 <= end && hasCaseInsensitiveASCIIRun(base, at: p + 2, end: end, "plist>"))
                            || (p + 7 <= end && hasCaseInsensitiveASCIIRun(base, at: p + 2, end: end, "dict>")) {
                            sawClosing = true
                            if sawPlistOpen { return true }
                        }
                    }
                } else if b == 0x2F && !sawClosing && p + 1 < end && base[p + 1] == 0x3E { // '/>'
                    sawClosing = true
                    if sawPlistOpen { return true }
                }
                p &+= 1
            }
            return sawPlistOpen && sawClosing
        }

        @inline(__always)
        func containsUTF16XMLPlistStructure(_ base: UnsafePointer<UInt8>, from start: Int, to end: Int, littleEndian: Bool) -> Bool {
            // Check for UTF-16 `<plist` and (`</plist>` or `</dict>` or `/>`)
            let step = 2
            @inline(__always)
            func unit(_ idx: Int) -> UInt8? {
                guard idx + 1 < end else { return nil }
                if littleEndian {
                    return base[idx + 1] == 0x00 ? base[idx] : nil
                } else {
                    return base[idx] == 0x00 ? base[idx + 1] : nil
                }
            }
            @inline(__always)
            func matchesCI(_ idx: Int, _ lowerASCII: StaticString) -> Bool {
                let count = lowerASCII.utf8CodeUnitCount
                guard idx + count * 2 <= end else { return false }
                return lowerASCII.withUTF8Buffer { buf in
                    for k in 0..<count {
                        guard let u = unit(idx + k * 2) else { return false }
                        let lower = (u >= 0x41 && u <= 0x5A) ? (u + 32) : u
                        if lower != buf[k] { return false }
                    }
                    return true
                }
            }
            var sawPlistOpen = false
            var sawClosing = false
            var p = start
            while p + 1 < end {
                if let u = unit(p) {
                    if u == 0x3C {
                        if !sawPlistOpen && matchesCI(p + 2, "plist") {
                            sawPlistOpen = true
                            if sawClosing { return true }
                        }
                        if !sawClosing && unit(p + 2) == 0x2F {
                            if matchesCI(p + 4, "plist>") || matchesCI(p + 4, "dict>") {
                                sawClosing = true
                                if sawPlistOpen { return true }
                            }
                        }
                    } else if u == 0x2F && !sawClosing && unit(p + 2) == 0x3E {
                        sawClosing = true
                        if sawPlistOpen { return true }
                    }
                }
                p &+= step
            }
            return sawPlistOpen && sawClosing
        }

        @inline(__always)
        func looksLikeValidCandidatePlist(_ base: UnsafePointer<UInt8>, range r: Range<Int>) -> (kind: CandidatePlistKind, contentStart: Int) {
            let count = r.count
            guard count >= 4 else { return (.none, r.lowerBound) }
            let start = r.lowerBound
            let end = r.upperBound
            if count >= 8, hasASCIIRun(base, at: start, end: end, "bplist0") {
                guard canAttemptParse(sectionSize: count) else { return (.none, start) }
                guard count >= 40 else { return (.none, start) }
                let verDigit = base[start + 7]
                guard verDigit >= 0x30 && verDigit <= 0x39 else { return (.none, start) }
                let t = end - 32
                let offsetIntSize = base[t + 6]
                let objectRefSize = base[t + 7]
                guard (offsetIntSize == 1 || offsetIntSize == 2 || offsetIntSize == 4 || offsetIntSize == 8),
                      (objectRefSize == 1 || objectRefSize == 2 || objectRefSize == 4 || objectRefSize == 8) else {
                    return (.none, start)
                }
                @inline(__always)
                func readU64BE(_ off: Int) -> UInt64 {
                    var v: UInt64 = 0
                    for k in 0..<8 { v = (v << 8) | UInt64(base[off + k]) }
                    return v
                }
                let numObjects = readU64BE(t + 8)
                let topObject = readU64BE(t + 16)
                let offsetTableOffset = readU64BE(t + 24)
                let bodyLimit = UInt64(count - 32)
                guard numObjects > 0,
                      topObject < numObjects,
                      offsetTableOffset >= 8,
                      offsetTableOffset < bodyLimit else {
                    return (.none, start)
                }
                let (tableBytes, ov1) = numObjects.multipliedReportingOverflow(by: UInt64(offsetIntSize))
                guard !ov1 else { return (.none, start) }
                let (tableEnd, ov2) = offsetTableOffset.addingReportingOverflow(tableBytes)
                guard !ov2 && tableEnd <= bodyLimit else { return (.none, start) }
                guard let topEntryOff = Int(exactly: offsetTableOffset + topObject * UInt64(offsetIntSize)) else {
                    return (.none, start)
                }
                var topObjOffset: UInt64 = 0
                for k in 0..<Int(offsetIntSize) {
                    topObjOffset = (topObjOffset << 8) | UInt64(base[start + topEntryOff + k])
                }
                guard topObjOffset >= 8, topObjOffset < offsetTableOffset else { return (.none, start) }
                let topMarker = base[start + Int(topObjOffset)]
                return ((topMarker & 0xF0) == 0xD0 ? .xmlOrBplist : .none, start)
            }

            // UTF-16LE / UTF-16BE BOM or un-padded XML preamble
            if count >= 4 {
                let b0 = base[start], b1 = base[start + 1], b2 = base[start + 2], b3 = base[start + 3]
                if b0 == 0xFF && b1 == 0xFE {
                    guard canAttemptParse(sectionSize: count),
                          consumeStructuralScanBudget(count, sectionSize: count) else { return (.none, start) }
                    return (containsUTF16XMLPlistStructure(base, from: start + 2, to: end, littleEndian: true) ? .xmlOrBplist : .none, start)
                }
                if b0 == 0xFE && b1 == 0xFF {
                    guard canAttemptParse(sectionSize: count),
                          consumeStructuralScanBudget(count, sectionSize: count) else { return (.none, start) }
                    return (containsUTF16XMLPlistStructure(base, from: start + 2, to: end, littleEndian: false) ? .xmlOrBplist : .none, start)
                }
                if b0 == 0x3C && b1 == 0x00 && (b2 == 0x3F || b2 == 0x70 || b2 == 0x21) && b3 == 0x00 {
                    guard canAttemptParse(sectionSize: count),
                          consumeStructuralScanBudget(count, sectionSize: count) else { return (.none, start) }
                    return (containsUTF16XMLPlistStructure(base, from: start, to: end, littleEndian: true) ? .xmlOrBplist : .none, start)
                }
                if b0 == 0x00 && b1 == 0x3C && b2 == 0x00 && (b3 == 0x3F || b3 == 0x70 || b3 == 0x21) {
                    guard canAttemptParse(sectionSize: count),
                          consumeStructuralScanBudget(count, sectionSize: count) else { return (.none, start) }
                    return (containsUTF16XMLPlistStructure(base, from: start, to: end, littleEndian: false) ? .xmlOrBplist : .none, start)
                }
            }

            var pos = start
            var chargedWhitespaceBudget = false
            while pos < end {
                if !chargedWhitespaceBudget && (pos - start) >= 4096 {
                    if count > mediumThreshold {
                        guard largeLeadingWhitespaceBytes + count <= maxLargeLeadingWhitespaceBytes else { return (.none, start) }
                        largeLeadingWhitespaceBytes += count
                        chargedWhitespaceBudget = true
                    } else {
                        guard smallMediumLeadingWhitespaceBytes + count <= maxSmallMediumLeadingWhitespaceBytes else { return (.none, start) }
                        smallMediumLeadingWhitespaceBytes += count
                        chargedWhitespaceBudget = true
                    }
                }
                if pos + 8 <= end {
                    let w = UnsafeRawPointer(base.advanced(by: pos)).loadUnaligned(as: UInt64.self)
                    if w == 0x2020_2020_2020_2020 || w == 0
                        || w == 0x0020_0020_0020_0020 || w == 0x2000_2000_2000_2000 {
                        pos &+= 8
                        continue
                    }
                }
                let b = base[pos]
                if b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D || b == 0x00
                    || b == 0xEF || b == 0xBB || b == 0xBF || b == 0xFE || b == 0xFF {
                    pos &+= 1
                    continue
                }
                if b == 0x7B { // '{' (JSON / OpenStep dictionary plist)
                    guard canAttemptOpenStepParse(sectionSize: count) else { return (.none, start) }
                    let rem = end - pos
                    guard openStepStructuralScanBytes + rem <= maxOpenStepStructuralScanBytes else { return (.none, start) }
                    openStepStructuralScanBytes += rem
                    return (containsByte(base, from: pos + 1, to: end, 0x7D) ? .openStep : .none, pos)
                }
                if b == 0x3C { // '<'
                    guard canAttemptParse(sectionSize: count) else { return (.none, start) }
                    // UTF-16LE / UTF-16BE after leading whitespace:
                    // UTF-16BE `00 3C 00 3F 00 78` shares bytes `3C 00 3F 00 78` with UTF-16LE shifted by 1 byte,
                    // so disambiguate using 2-byte code-unit alignment relative to `start`.
                    let canBeLE = pos + 3 < end && base[pos + 1] == 0x00 && (base[pos + 2] == 0x3F || base[pos + 2] == 0x70 || base[pos + 2] == 0x21) && base[pos + 3] == 0x00
                    let canBeBE = pos > start && base[pos - 1] == 0x00 && pos + 2 < end && base[pos + 1] == 0x00 && (base[pos + 2] == 0x3F || base[pos + 2] == 0x70 || base[pos + 2] == 0x21)
                    if canBeBE && (((pos - 1 - start) & 1) == 0 || !canBeLE) {
                        let rem = end - (pos - 1)
                        guard consumeStructuralScanBudget(rem, sectionSize: count) else { return (.none, start) }
                        return (containsUTF16XMLPlistStructure(base, from: pos - 1, to: end, littleEndian: false) ? .xmlOrBplist : .none, pos - 1)
                    }
                    if canBeLE {
                        let rem = end - pos
                        guard consumeStructuralScanBudget(rem, sectionSize: count) else { return (.none, start) }
                        return (containsUTF16XMLPlistStructure(base, from: pos, to: end, littleEndian: true) ? .xmlOrBplist : .none, pos)
                    }
                    let isXMLStart = hasASCIIRun(base, at: pos, end: end, "<?xml")
                        || hasASCIIRun(base, at: pos, end: end, "<plist")
                        || hasCaseInsensitiveASCIIRun(base, at: pos, end: end, "<!doctype")
                        || hasASCIIRun(base, at: pos, end: end, "<!--")
                    guard isXMLStart else { return (.none, start) }
                    let rem = end - pos
                    guard consumeStructuralScanBudget(rem, sectionSize: count) else { return (.none, start) }
                    return (containsASCIIXMLPlistStructure(base, from: pos, to: end) ? .xmlOrBplist : .none, pos)
                }
                return (.none, start)
            }
            return (.none, start)
        }

        return sliceData.withUnsafeBytes { raw -> [String: Any]? in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            let sliceCount = raw.count

            for seg in segments {
                for sect in seg.sections where sect.sectionName == "__info_plist" && sect.size > 0 {
                    sectionChecks += 1
                    if sectionChecks > maxSectionChecks {
                        return emptyPlistFallback
                    }
                    if smallFailedAttempts >= maxSmallFailedAttempts
                        && mediumFailedAttempts >= maxMediumFailedAttempts
                        && largeFailedAttempts >= maxLargeFailedAttempts
                        && openStepFailedAttempts >= maxOpenStepFailedAttempts {
                        return emptyPlistFallback
                    }
                    guard let start = Int(exactly: sect.offset),
                          let sizeInt = Int(exactly: sect.size),
                          sizeInt <= 8 * 1024 * 1024,
                          start >= 0, sizeInt > 0,
                          start <= sliceCount,
                          sizeInt <= sliceCount - start else {
                        continue
                    }
                    let sectRange = start..<(start + sizeInt)
                    var candidateSlices: [Range<Int>] = []
                    if let er = encRange {
                        if er.lowerBound <= sectRange.lowerBound && er.upperBound >= sectRange.upperBound {
                            continue
                        }
                        if sectRange.lowerBound < er.lowerBound {
                            candidateSlices.append(sectRange.lowerBound..<min(sectRange.upperBound, er.lowerBound))
                        }
                        if er.upperBound < sectRange.upperBound {
                            candidateSlices.append(max(sectRange.lowerBound, er.upperBound)..<sectRange.upperBound)
                        }
                    } else {
                        candidateSlices.append(sectRange)
                    }

                    for r in candidateSlices where !r.isEmpty {
                        guard seenPlistSlices.insert(PlistSliceKey(lower: r.lowerBound, upper: r.upperBound)).inserted else {
                            continue
                        }
                        guard r.lowerBound >= 0, r.upperBound <= sliceCount else { continue }
                        let (candidateKind, contentStart) = looksLikeValidCandidatePlist(base, range: r)
                        guard candidateKind != .none, contentStart >= r.lowerBound, contentStart < r.upperBound else { continue }

                        let rawPlist = Data(bytes: base.advanced(by: contentStart), count: r.upperBound - contentStart)
                        if let dict = try? CSBlobParser.shared.parseXMLPlist(rawPlist) {
                            if !dict.isEmpty {
                                return dict
                            }
                            if emptyPlistFallback == nil {
                                emptyPlistFallback = dict
                            }
                        } else if candidateKind == .openStep {
                            recordFailedOpenStepParse(sectionSize: r.count)
                        } else {
                            recordFailedParse(sectionSize: r.count)
                        }
                    }
                }
            }
            return emptyPlistFallback
        }
    }

    private static let excludedCustomRXSectionPrefixes: [String] = [
        "__const", "__swift", "__objc_",
        "__cstring", "__ustring", "__oslogstring",
        "__unwind_info", "__eh_frame", "__gcc_except_tab",
        "__entitlements", "__info_plist", "__dof_"
    ]

    private static func isZerofillInsideSegmentFilesize(_ sect: MachOSection, in segment: MachOSegment, sliceSize: Int) -> Bool {
        guard sect.size > 0, segment.fileSize > 0 else { return false }
        let (segEnd, segOv) = segment.fileOffset.addingReportingOverflow(segment.fileSize)
        guard !segOv else { return false }
        let sectStart = UInt64(sect.offset)
        let (sectEnd, sectOv) = sectStart.addingReportingOverflow(sect.size)
        guard !sectOv else { return false }
        return sectStart >= segment.fileOffset && sectEnd <= segEnd && sectEnd <= UInt64(sliceSize)
    }

    private static func shouldScanSectionForDirectSyscalls(_ sect: MachOSection, in segment: MachOSegment, sliceSize: Int) -> Bool {
        let rawSectType = sect.flags & UInt32(SECTION_TYPE)
        let sectType: UInt32
        if rawSectType == UInt32(S_ZEROFILL) || rawSectType == UInt32(S_GB_ZEROFILL) {
            guard isZerofillInsideSegmentFilesize(sect, in: segment, sliceSize: sliceSize) else {
                return false
            }
            sectType = UInt32(S_REGULAR)
        } else {
            sectType = rawSectType
        }

        let instructionAttrsMask = UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS)
        if (sect.flags & instructionAttrsMask) != 0 {
            return true
        }

        let name = sect.sectionName
        if name == "__text" || name == "__stubs" {
            return true
        }

        let hasExecuteProt = (segment.initialProtection & 0x04) != 0
        guard hasExecuteProt else {
            return false
        }

        if segment.name == "__TEXT" {
            guard sectType == UInt32(S_REGULAR) else {
                return false
            }
            return !excludedCustomRXSectionPrefixes.contains { name.hasPrefix($0) }
        }
        return true
    }

    /// Scans unencrypted ARM64/ARM64_32 executable sections and uncovered executable segment bytes for inline `svc #0x80` (`0xD400_1001`) instructions.
    public func scanDirectSyscalls(maxSampleSites: Int = 16) -> (totalCount: Int, sampleSites: [DirectSyscallSite]) {
        guard cpuType == CPU_TYPE_ARM64 || cpuType == CPU_TYPE_ARM64_32 else {
            return (0, [])
        }

        let encRange: Range<Int>?
        if isFairPlayEncrypted && !hasForgedPlaintextFairPlayRange {
            guard let range = encryptionInfo?.encryptedRange else {
                return (0, [])
            }
            encRange = range
        } else {
            encRange = nil
        }

        let reader = BinaryReader(data: sliceData)
        let sampleLimit = max(0, maxSampleSites)
        var totalCount = 0
        var sampleSites: [DirectSyscallSite] = []
        var recordedOffsets: Set<Int> = []
        var scannedByPhase = [[(Int, Int)]](repeating: [], count: 4)
        let headerSize = is64Bit ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        let commandsEnd = min(sliceData.count, headerSize + Int(sizeofcmds))

        func scanWordRange(start: Int, sizeInt: Int, segName: String, sectName: String, baseVA: UInt64) {
            guard sizeInt >= 4 else { return }
            let alignedLen = sizeInt & ~3
            guard alignedLen >= 4 else { return }
            let end = start + alignedLen
            let phase = start & 3

            var fragments: [(Int, Int)] = [(start, end)]
            for (exStart, exEnd) in scannedByPhase[phase] {
                var nextFragments: [(Int, Int)] = []
                nextFragments.reserveCapacity(fragments.count)
                for (fStart, fEnd) in fragments {
                    if exEnd <= fStart || exStart >= fEnd {
                        nextFragments.append((fStart, fEnd))
                    } else {
                        if fStart < exStart {
                            nextFragments.append((fStart, exStart))
                        }
                        if exEnd < fEnd {
                            nextFragments.append((exEnd, fEnd))
                        }
                    }
                }
                fragments = nextFragments
                if fragments.isEmpty { return }
            }

            for (fragStart, fragEnd) in fragments {
                scannedByPhase[phase].append((fragStart, fragEnd))
                let fragLen = fragEnd - fragStart
                let fragBaseVA = baseVA &+ UInt64(fragStart - start)
                for relOff in stride(from: 0, through: fragLen - 4, by: 4) {
                    let wordOffset = fragStart + relOff
                    if let er = encRange {
                        let wordRange = wordOffset..<(wordOffset + 4)
                        if wordRange.overlaps(er) {
                            continue
                        }
                    }

                    guard let insn = reader.readUInt32(at: wordOffset, swapped: isSwapped) else {
                        continue
                    }

                    if insn == 0xD400_1001, recordedOffsets.insert(wordOffset).inserted {
                        totalCount += 1
                        if sampleSites.count < sampleLimit {
                            sampleSites.append(DirectSyscallSite(
                                segmentName: segName,
                                sectionName: sectName,
                                fileOffset: wordOffset,
                                virtualAddress: fragBaseVA &+ UInt64(relOff),
                                immediate: 0x0080
                            ))
                        }
                    }
                }
            }

            if scannedByPhase[phase].count > 32 {
                scannedByPhase[phase].sort { $0.0 < $1.0 }
                var merged: [(Int, Int)] = []
                for iv in scannedByPhase[phase] {
                    if let last = merged.last, iv.0 <= last.1 {
                        merged[merged.count - 1].1 = max(last.1, iv.1)
                    } else {
                        merged.append(iv)
                    }
                }
                scannedByPhase[phase] = merged
            }
        }

        for seg in segments {
            let segFileStart = seg.fileOffset <= UInt64(sliceData.count) ? Int(seg.fileOffset) : 0
            for sect in seg.sections {
                guard let start = Int(exactly: sect.offset),
                      let sizeInt = Int(exactly: sect.size),
                      sizeInt >= 4,
                      start >= 0,
                      start <= sliceData.count,
                      sizeInt <= sliceData.count - start else {
                    continue
                }
                let sectEnd = start + sizeInt
                let containsEntryPoint = entryPointFileOffsets.contains { $0 >= start && $0 < sectEnd }
                guard containsEntryPoint || Self.shouldScanSectionForDirectSyscalls(sect, in: seg, sliceSize: sliceData.count) else {
                    continue
                }
                scanWordRange(start: start, sizeInt: sizeInt, segName: seg.name, sectName: sect.sectionName, baseVA: sect.address)
                // Defeat unaligned section-header phase-shifting (e.g. sect.offset = 0x401 hiding 4-byte-aligned svc #0x80 at 0x404)
                if start >= segFileStart {
                    let rem = (start - segFileStart) % 4
                    if rem != 0 {
                        let alignedStart = start + (4 - rem)
                        if alignedStart <= sectEnd - 4 {
                            let alignedVA = seg.vmAddress &+ UInt64(alignedStart - segFileStart)
                            scanWordRange(
                                start: alignedStart,
                                sizeInt: sectEnd - alignedStart,
                                segName: seg.name,
                                sectName: sect.sectionName,
                                baseVA: alignedVA
                            )
                        }
                    }
                }
            }

            // Also scan executable segment file bytes [fileOffset, fileOffset + fileSize) not covered by any valid in-bounds section header
            // (defeating header-padding code caves, OOB fake section headers, and nsects=0 executable segments while respecting metadata sections).
            let segStartCandidate = seg.fileOffset < UInt64(sliceData.count) ? Int(seg.fileOffset) : sliceData.count
            let (rawSegEnd, segOv) = seg.fileOffset.addingReportingOverflow(seg.fileSize)
            let clampedEnd64 = segOv ? UInt64(sliceData.count) : min(rawSegEnd, UInt64(sliceData.count))
            let segEndCandidate = Int(clampedEnd64)
            let hasEntryPointInSegment = segEndCandidate > segStartCandidate && entryPointFileOffsets.contains {
                $0 >= segStartCandidate && $0 < segEndCandidate
            }
            let isExecutableOrEntrySegment = ((seg.initialProtection & 0x04) != 0)
                || (((seg.maxProtection & 0x04) != 0) && hasEntryPointInSegment)

            if isExecutableOrEntrySegment && seg.fileSize > 0 && seg.fileOffset < UInt64(sliceData.count) {
                let segStart = segStartCandidate
                let segEnd = segEndCandidate
                guard segEnd - segStart >= 4 else { continue }

                var covered: [(Int, Int)] = []
                if segStart < commandsEnd {
                    covered.append((segStart, min(segEnd, commandsEnd)))
                }
                for sect in seg.sections {
                    let rawType = sect.flags & UInt32(SECTION_TYPE)
                    let isZF = (rawType == UInt32(S_ZEROFILL) || rawType == UInt32(S_GB_ZEROFILL))
                    if isZF && !Self.isZerofillInsideSegmentFilesize(sect, in: seg, sliceSize: sliceData.count) {
                        continue
                    }
                    guard sect.size > 0, UInt64(sect.offset) < UInt64(segEnd) else { continue }
                    let (rawCEnd, cOv) = UInt64(sect.offset).addingReportingOverflow(sect.size)
                    let isMetadataSection = !Self.shouldScanSectionForDirectSyscalls(sect, in: seg, sliceSize: sliceData.count)
                    if isMetadataSection {
                        // Reject out-of-bounds fake metadata section headers so they cannot blind gap scanning
                        guard !cOv,
                              UInt64(sect.offset) >= UInt64(segStart),
                              rawCEnd <= UInt64(segEnd),
                              let cStart = Int(exactly: sect.offset),
                              let cEnd = Int(exactly: rawCEnd),
                              cEnd > cStart else { continue }
                        covered.append((cStart, cEnd))
                    } else {
                        let clampedCEnd = cOv ? UInt64(segEnd) : min(rawCEnd, UInt64(segEnd))
                        let cStart = max(segStart, Int(sect.offset))
                        let cEnd = Int(clampedCEnd)
                        if cEnd > cStart {
                            covered.append((cStart, cEnd))
                        }
                    }
                }
                covered.sort { $0.0 < $1.0 }

                func scanGap(_ gapStart: Int, _ gapEnd: Int) {
                    guard gapEnd - gapStart >= 4 else { return }
                    let rem = (gapStart - segStart) % 4
                    let alignedStart = rem == 0 ? gapStart : gapStart + (4 - rem)
                    guard alignedStart <= gapEnd - 4 else { return }
                    let gapVA = seg.vmAddress &+ UInt64(alignedStart - segStart)
                    scanWordRange(
                        start: alignedStart,
                        sizeInt: gapEnd - alignedStart,
                        segName: seg.name,
                        sectName: "__unsectioned",
                        baseVA: gapVA
                    )
                }

                var cursor = segStart
                for (ivStart, ivEnd) in covered {
                    if ivStart > cursor {
                        scanGap(cursor, ivStart)
                    }
                    if ivEnd > cursor {
                        cursor = ivEnd
                    }
                }
                if cursor < segEnd {
                    scanGap(cursor, segEnd)
                }
            }
        }

        return (totalCount, sampleSites)
    }

    public var directSyscallSites: [DirectSyscallSite] {
        scanDirectSyscalls().sampleSites
    }

    public var directSyscallCount: Int {
        scanDirectSyscalls().totalCount
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

    /// Instance forwarding method for parsing all slices in Thin or Universal/FAT binaries.
    public func parseAllSlices(data: Data) throws -> [MachOFile] {
        try Self.parseAllSlices(data: data)
    }

    /// Selects all iOS-executable ARM architecture slices (`arm64`, `arm64e`, `arm64_32`, `armv7`) when present,
    /// defeating `arm64` + `arm64e` multi-slice shadowing while avoiding dead `x86_64` simulator slice pollution.
    /// Falls back to all slices when no ARM slice exists (e.g. host macOS x86_64 test binaries).
    public static func selectAuditSlices(from files: [MachOFile]) -> [MachOFile] {
        let armSlices = files.filter { ($0.cpuType & 0x00ff_ffff) == CPU_TYPE_ARM }
        return armSlices.isEmpty ? files : armSlices
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

    /// Parses a Mach-O file from a local filesystem URL in 100% read-only mode with strict `O_NOFOLLOW` regular-file verification.
    public static func parse(url: URL, preferredCpuType: cpu_type_t? = nil) throws -> MachOFile {
        let data = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: url)
        return try parse(data: data, preferredCpuType: preferredCpuType)
    }

    /// Parses ALL architecture slices embedded in a Universal FAT or Thin Mach-O binary so secondary
    /// slices (e.g., `arm64e` shadowed behind a clean `arm64` slice) cannot evade static inspection.
    public static func parseAllSlices(data rawInput: Data) throws -> [MachOFile] {
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
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
            let slices = try parseFatSlices(reader: reader, isFat64: isFat64, swapped: fatSwapped, allowOutOfBoundsEntries: true)
            guard !slices.isEmpty else {
                throw MachOParserError.fatBinaryEmpty
            }

            var parsedFiles: [MachOFile] = []
            var firstError: Error?
            struct SliceDedupKey: Hashable {
                let cpuType: cpu_type_t
                let cpuSubtype: cpu_subtype_t
                let offset: UInt64
                let size: UInt64
            }
            struct ByteSpanKey: Hashable {
                let offset: UInt64
                let size: UInt64
            }
            var seenSliceKeys: Set<SliceDedupKey> = []
            var spanReuseCounts: [ByteSpanKey: Int] = [:]
            var offsetReuseCounts: [UInt64: Int] = [:]
            var totalDecodedSliceBytes: UInt64 = 0
            let maxParsedSlices = 16
            let maxTotalDecodedBytes = UInt64(min(256 * 1024 * 1024, max(data.count * 4, 16 * 1024 * 1024)))
            for slice in slices {
                if parsedFiles.count >= maxParsedSlices { break }
                let dedupKey = SliceDedupKey(
                    cpuType: slice.cpuType,
                    cpuSubtype: slice.cpuSubtype,
                    offset: slice.offset,
                    size: slice.size
                )
                guard seenSliceKeys.insert(dedupKey).inserted else { continue }
                let spanKey = ByteSpanKey(offset: slice.offset, size: slice.size)
                let reuseCount = spanReuseCounts[spanKey, default: 0]
                if reuseCount >= 4 || offsetReuseCounts[slice.offset, default: 0] >= 4 { continue }
                guard slice.offset <= UInt64(data.count),
                      slice.size <= UInt64(data.count) - slice.offset else {
                    if firstError == nil {
                        firstError = MachOParserError.sliceOutOfBounds(offset: slice.offset, size: slice.size, total: data.count)
                    }
                    continue
                }
                guard let startInt = Int(exactly: slice.offset),
                      let endInt = Int(exactly: slice.offset + slice.size) else {
                    continue
                }
                if slice.size < 28 {
                    if firstError == nil {
                        firstError = MachOParserError.truncatedHeader(expected: 28, actual: Int(slice.size))
                    }
                    continue
                }
                guard let sliceMagic = reader.readUInt32(at: startInt) else {
                    if firstError == nil {
                        firstError = MachOParserError.truncatedHeader(expected: 28, actual: Int(slice.size))
                    }
                    continue
                }
                let sliceIs64: Bool
                let sliceSwapped: Bool
                switch sliceMagic {
                case MH_MAGIC_64:
                    sliceIs64 = true
                    sliceSwapped = false
                case MH_CIGAM_64:
                    sliceIs64 = true
                    sliceSwapped = true
                case MH_MAGIC:
                    sliceIs64 = false
                    sliceSwapped = false
                case MH_CIGAM:
                    sliceIs64 = false
                    sliceSwapped = true
                default:
                    if firstError == nil {
                        firstError = MachOParserError.invalidMagic(sliceMagic)
                    }
                    continue
                }
                let sliceHeaderSize = sliceIs64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
                guard Int(slice.size) >= sliceHeaderSize,
                      let thinCpuType = reader.readInt32(at: startInt + 4, swapped: sliceSwapped) else {
                    if firstError == nil {
                        firstError = MachOParserError.truncatedHeader(expected: sliceHeaderSize, actual: Int(slice.size))
                    }
                    continue
                }
                guard thinCpuType == slice.cpuType else {
                    if firstError == nil {
                        firstError = MachOParserError.corruptedFatHeader(
                            reason: "FAT slice cpuType (\(slice.cpuType)) disagrees with thin Mach-O header cpuType (\(thinCpuType))"
                        )
                    }
                    continue
                }
                let (nextTotal, totalOv) = totalDecodedSliceBytes.addingReportingOverflow(slice.size)
                if totalOv || (totalDecodedSliceBytes > 0 && nextTotal > maxTotalDecodedBytes) {
                    break
                }
                spanReuseCounts[spanKey] = reuseCount + 1
                offsetReuseCounts[slice.offset, default: 0] += 1
                totalDecodedSliceBytes = nextTotal
                let sliceSubdata = data.subdata(in: startInt..<endInt)
                do {
                    let file = try parseThinSlice(sliceData: sliceSubdata, containerSlices: slices)
                    parsedFiles.append(file)
                } catch {
                    if firstError == nil { firstError = error }
                }
            }
            if parsedFiles.isEmpty {
                throw firstError ?? MachOParserError.fatBinaryEmpty
            }
            return parsedFiles
        }

        return [try parseThinSlice(sliceData: data, containerSlices: [])]
    }

    /// Parses a Mach-O binary from raw Data (supports Thin 32-bit, Thin 64-bit, and Universal FAT).
    public static func parse(data rawInput: Data, preferredCpuType: cpu_type_t? = nil) throws -> MachOFile {
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
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
            let file = try parseThinSlice(sliceData: sliceSubdata, containerSlices: slices)
            guard file.cpuType == chosenSlice.cpuType else {
                throw MachOParserError.corruptedFatHeader(
                    reason: "FAT slice cpuType (\(chosenSlice.cpuType)) disagrees with thin Mach-O header cpuType (\(file.cpuType))"
                )
            }
            return file
        }

        // Parse Thin Mach-O binary
        return try parseThinSlice(sliceData: data, containerSlices: [])
    }

    /// Lists all architecture slices embedded in a binary without decoding load commands.
    public static func listSlices(in rawInput: Data) throws -> [MachOSliceInfo] {
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
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
    public static func extractSlice(from rawInput: Data, slice: MachOSliceInfo) throws -> Data {
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
        guard slice.offset <= UInt64(data.count),
              slice.size <= UInt64(data.count) - slice.offset else {
            throw MachOParserError.sliceOutOfBounds(offset: slice.offset, size: slice.size, total: data.count)
        }
        let start = data.startIndex + Int(slice.offset)
        return data.subdata(in: start..<(start + Int(slice.size)))
    }

    // MARK: - Internal Helpers

    private static func parseFatSlices(
        reader: BinaryReader,
        isFat64: Bool,
        swapped: Bool,
        allowOutOfBoundsEntries: Bool = false
    ) throws -> [MachOSliceInfo] {
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

            if !allowOutOfBoundsEntries {
                guard offset <= UInt64(reader.count), size <= UInt64(reader.count) - offset else {
                    throw MachOParserError.sliceOutOfBounds(offset: offset, size: size, total: reader.count)
                }
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
        var encryptionInfos: [MachOEncryptionInfo] = []
        var linkedDylibs: [MachODylib] = []
        var symtabs: [MachOSymtab] = []
        var seenSymtabs: Set<MachOSymtab> = []
        var totalSymtabEntries: UInt64 = 0
        var codeSignatures: [MachOCodeSignature] = []
        var dynamicImportSymbols: [String] = []
        var dynamicSymSet: Set<String> = []
        struct DyldBindKey: Hashable { let offset: Int; let size: Int; let isLazy: Bool }
        var deferredDyldBinds: [(offset: Int, size: Int, isLazy: Bool)] = []
        var seenDyldBinds: Set<DyldBindKey> = []
        struct ChainedFixupKey: Hashable { let offset: UInt32; let size: UInt32 }
        var seenChainedFixups: Set<ChainedFixupKey> = []
        var chainedFixupsCommandCount = 0
        var remainingChainedZlibBytes = 32 * 1024 * 1024
        var remainingChainedImportsBudget = 262_144
        var lcMainEntryOffsets: [UInt64] = []
        var unixThreadEntryVAs: [UInt64] = []

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
                guard is64 else {
                    throw MachOParserError.malformedCommand(cmd: cmd, reason: "LC_SEGMENT_64 is invalid inside a 32-bit Mach-O header")
                }
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
                guard !is64 else {
                    throw MachOParserError.malformedCommand(cmd: cmd, reason: "LC_SEGMENT is invalid inside a 64-bit Mach-O header")
                }
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
                guard is64 else {
                    throw MachOParserError.malformedCommand(cmd: cmd, reason: "LC_ENCRYPTION_INFO_64 is invalid inside a 32-bit Mach-O header")
                }
                guard cmdsize >= MemoryLayout<encryption_info_command_64>.size else {
                    throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cmdStart)
                }
                let cryptoff = reader.readUInt32(at: cmdStart + 8, swapped: isSwapped) ?? 0
                let cryptsize = reader.readUInt32(at: cmdStart + 12, swapped: isSwapped) ?? 0
                let cryptid = reader.readUInt32(at: cmdStart + 16, swapped: isSwapped) ?? 0
                encryptionInfos.append(MachOEncryptionInfo(
                    cryptoff: cryptoff,
                    cryptsize: cryptsize,
                    cryptid: cryptid,
                    is64Bit: true
                ))

            case UInt32(LC_ENCRYPTION_INFO):
                guard !is64 else {
                    throw MachOParserError.malformedCommand(cmd: cmd, reason: "LC_ENCRYPTION_INFO is invalid inside a 64-bit Mach-O header")
                }
                guard cmdsize >= MemoryLayout<encryption_info_command>.size else {
                    throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cmdStart)
                }
                let cryptoff = reader.readUInt32(at: cmdStart + 8, swapped: isSwapped) ?? 0
                let cryptsize = reader.readUInt32(at: cmdStart + 12, swapped: isSwapped) ?? 0
                let cryptid = reader.readUInt32(at: cmdStart + 16, swapped: isSwapped) ?? 0
                encryptionInfos.append(MachOEncryptionInfo(
                    cryptoff: cryptoff,
                    cryptsize: cryptsize,
                    cryptid: cryptid,
                    is64Bit: false
                ))

            case UInt32(LC_LOAD_DYLIB), UInt32(LC_LOAD_WEAK_DYLIB), UInt32(LC_REEXPORT_DYLIB), UInt32(LC_LAZY_LOAD_DYLIB), UInt32(LC_LOAD_UPWARD_DYLIB):
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

                let st = MachOSymtab(symoff: symoff, nsyms: nsyms, stroff: stroff, strsize: strsize)
                if seenSymtabs.insert(st).inserted, symtabs.count < 8, totalSymtabEntries < 500_000 {
                    symtabs.append(st)
                    totalSymtabEntries = totalSymtabEntries &+ UInt64(nsyms)
                }

            case UInt32(LC_CODE_SIGNATURE):
                guard cmdsize >= MemoryLayout<linkedit_data_command>.size else {
                    throw MachOParserError.invalidCommandSize(cmd: cmd, cmdsize: cmdsize, offset: cmdStart)
                }
                let dataoff = reader.readUInt32(at: cmdStart + 8, swapped: isSwapped) ?? 0
                let datasize = reader.readUInt32(at: cmdStart + 12, swapped: isSwapped) ?? 0

                guard UInt64(dataoff) + UInt64(datasize) <= UInt64(reader.count) else {
                    throw MachOParserError.codeSignatureOutOfBounds(offset: dataoff, size: datasize, total: reader.count)
                }

                codeSignatures.append(MachOCodeSignature(dataoff: dataoff, datasize: datasize))

            case 0x8000_0034: // LC_DYLD_CHAINED_FIXUPS
                if cmdsize >= MemoryLayout<linkedit_data_command>.size,
                   let dataoff = reader.readUInt32(at: cmdStart + 8, swapped: isSwapped),
                   let datasize = reader.readUInt32(at: cmdStart + 12, swapped: isSwapped),
                   datasize >= 28,
                   UInt64(dataoff) + UInt64(datasize) <= UInt64(reader.count),
                   let dataoffInt = Int(exactly: dataoff),
                   let datasizeInt = Int(exactly: datasize),
                   seenChainedFixups.insert(ChainedFixupKey(offset: dataoff, size: datasize)).inserted,
                   chainedFixupsCommandCount < 8,
                   remainingChainedImportsBudget > 0 {
                    chainedFixupsCommandCount += 1
                    let (syms, zlibBytesUsed, entriesConsumed) = Self.parseChainedFixupImports(
                        reader: reader,
                        dataoff: dataoffInt,
                        datasize: datasizeInt,
                        isSwapped: isSwapped,
                        maxImportsBudget: remainingChainedImportsBudget,
                        maxZlibOutputBytes: min(16 * 1024 * 1024, remainingChainedZlibBytes)
                    )
                    remainingChainedZlibBytes = max(0, remainingChainedZlibBytes - zlibBytesUsed)
                    remainingChainedImportsBudget = max(0, remainingChainedImportsBudget - entriesConsumed)
                    for s in syms where dynamicSymSet.insert(s).inserted {
                        dynamicImportSymbols.append(s)
                    }
                }

            case 0x0000_0022, 0x8000_0022: // LC_DYLD_INFO, LC_DYLD_INFO_ONLY
                if cmdsize >= 48 {
                    let bindRanges: [(UInt32, UInt32, Bool)] = [
                        (reader.readUInt32(at: cmdStart + 16, swapped: isSwapped) ?? 0, reader.readUInt32(at: cmdStart + 20, swapped: isSwapped) ?? 0, false), // bind
                        (reader.readUInt32(at: cmdStart + 24, swapped: isSwapped) ?? 0, reader.readUInt32(at: cmdStart + 28, swapped: isSwapped) ?? 0, false), // weak_bind
                        (reader.readUInt32(at: cmdStart + 32, swapped: isSwapped) ?? 0, reader.readUInt32(at: cmdStart + 36, swapped: isSwapped) ?? 0, true)   // lazy_bind (random-access)
                    ]
                    for (off, sz, isLazy) in bindRanges where sz > 0 && UInt64(off) + UInt64(sz) <= UInt64(reader.count) {
                        if let offInt = Int(exactly: off),
                           let szInt = Int(exactly: sz),
                           seenDyldBinds.insert(DyldBindKey(offset: offInt, size: szInt, isLazy: isLazy)).inserted,
                           deferredDyldBinds.count < 24 {
                            deferredDyldBinds.append((offset: offInt, size: szInt, isLazy: isLazy))
                        }
                    }
                }

            case 0x8000_0028: // LC_MAIN
                if cmdsize >= 24, let entryoff = reader.readUInt64(at: cmdStart + 8, swapped: isSwapped) {
                    lcMainEntryOffsets.append(entryoff)
                }

            case 0x0000_0005: // LC_UNIXTHREAD
                // ARM_THREAD_STATE64: flavor = 6, count = 68 (u32 words), pc at offset +16 + 32*8 = +272
                if (cpuType == CPU_TYPE_ARM64 || cpuType == CPU_TYPE_ARM64_32),
                   cmdsize >= 280,
                   reader.readUInt32(at: cmdStart + 8, swapped: isSwapped) == 6,
                   let pc = reader.readUInt64(at: cmdStart + 272, swapped: isSwapped) {
                    unixThreadEntryVAs.append(pc)
                }

            default:
                break
            }

            cursor += Int(cmdsize)
        }

        if !deferredDyldBinds.isEmpty {
            let hasLazy = deferredDyldBinds.contains(where: { $0.isLazy })
            let stubOffsets: [Int] = hasLazy ? Self.extractStubHelperLazyBindOffsets(
                segments: segments,
                reader: reader,
                cpuType: cpuType,
                isSwapped: isSwapped
            ) : []
            for bindEntry in deferredDyldBinds {
                let syms = Self.parseDyldBindSymbols(
                    reader: reader,
                    offset: bindEntry.offset,
                    size: bindEntry.size,
                    isLazyBind: bindEntry.isLazy,
                    stubHelperOffsets: bindEntry.isLazy ? stubOffsets : []
                )
                for s in syms where dynamicSymSet.insert(s).inserted {
                    dynamicImportSymbols.append(s)
                }
            }
        }

        let resolvedEncryptionInfo = Self.resolveEncryptionInfo(from: encryptionInfos, is64Bit: is64)

        var entryPointFileOffsets: [Int] = []
        let textFileBase = segments.first(where: { $0.name == "__TEXT" })?.fileOffset ?? 0
        for relEntry in lcMainEntryOffsets {
            let (absOff, ov) = textFileBase.addingReportingOverflow(relEntry)
            if !ov, absOff < UInt64(sliceData.count), let intOff = Int(exactly: absOff) {
                entryPointFileOffsets.append(intOff)
            } else if relEntry < UInt64(sliceData.count), let intOff = Int(exactly: relEntry) {
                entryPointFileOffsets.append(intOff)
            }
        }
        for pc in unixThreadEntryVAs {
            for seg in segments where seg.vmSize > 0 && pc >= seg.vmAddress {
                let (vmEnd, ov) = seg.vmAddress.addingReportingOverflow(seg.vmSize)
                if !ov && pc < vmEnd {
                    let delta = pc - seg.vmAddress
                    let (fOff, fOv) = seg.fileOffset.addingReportingOverflow(delta)
                    if !fOv, fOff < UInt64(sliceData.count), let intOff = Int(exactly: fOff) {
                        entryPointFileOffsets.append(intOff)
                    }
                }
            }
        }

        let primarySymtab = symtabs.first(where: { $0.nsyms > 0 }) ?? symtabs.first
        let primaryCodeSig = codeSignatures.first(where: { $0.datasize > 0 }) ?? codeSignatures.first

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
            encryptionInfo: resolvedEncryptionInfo,
            linkedDylibs: linkedDylibs,
            symtab: primarySymtab,
            codeSignature: primaryCodeSig,
            symtabs: symtabs,
            codeSignatures: codeSignatures,
            dynamicImportSymbols: dynamicImportSymbols,
            entryPointFileOffsets: entryPointFileOffsets
        )
    }

    /// Resolves multiple `LC_ENCRYPTION_INFO[_64]` load commands conservatively:
    /// - Single command: preserved verbatim.
    /// - Multiple commands: if any command declares `cryptid == 0` (unencrypted), or if encrypted ranges are disjoint,
    ///   collapses to `cryptid = 0` so an appended fake `cryptid = 1` command can never blind static code/string inspection.
    private static func resolveEncryptionInfo(from infos: [MachOEncryptionInfo], is64Bit: Bool) -> MachOEncryptionInfo? {
        guard let first = infos.first else { return nil }
        if infos.count == 1 {
            return first
        }
        if infos.contains(where: { !$0.isFairPlayEncrypted }) {
            return MachOEncryptionInfo(cryptoff: 0, cryptsize: 0, cryptid: 0, is64Bit: is64Bit)
        }
        guard var overlap = first.encryptedRange else {
            return MachOEncryptionInfo(cryptoff: 0, cryptsize: 0, cryptid: 0, is64Bit: is64Bit)
        }
        for info in infos.dropFirst() {
            guard let r = info.encryptedRange else {
                return MachOEncryptionInfo(cryptoff: 0, cryptsize: 0, cryptid: 0, is64Bit: is64Bit)
            }
            let lo = max(overlap.lowerBound, r.lowerBound)
            let hi = min(overlap.upperBound, r.upperBound)
            if lo >= hi {
                return MachOEncryptionInfo(cryptoff: 0, cryptsize: 0, cryptid: 0, is64Bit: is64Bit)
            }
            overlap = lo..<hi
        }
        guard let off32 = UInt32(exactly: overlap.lowerBound),
              let sz32 = UInt32(exactly: overlap.count) else {
            return MachOEncryptionInfo(cryptoff: 0, cryptsize: 0, cryptid: 0, is64Bit: is64Bit)
        }
        return MachOEncryptionInfo(cryptoff: off32, cryptsize: sz32, cryptid: first.cryptid, is64Bit: is64Bit)
    }

    /// Parses external imported symbol names from `LC_DYLD_CHAINED_FIXUPS` (`dyld_chained_fixups_header`),
    /// defeating `strip` / zeroed-`LC_SYMTAB` evasion on modern iOS 15+–27 ARM64/ARM64e binaries.
    private static func parseChainedFixupImports(
        reader: BinaryReader,
        dataoff: Int,
        datasize: Int,
        isSwapped: Bool,
        maxImportsBudget: Int = 262_144,
        maxZlibOutputBytes: Int = 16 * 1024 * 1024
    ) -> (symbols: [String], zlibOutputBytesUsed: Int, entriesConsumed: Int) {
        guard datasize >= 28, reader.inRange(offset: dataoff, length: datasize) else { return ([], 0, 0) }
        guard let importsOffset = reader.readUInt32(at: dataoff + 8, swapped: isSwapped),
              let symbolsOffset = reader.readUInt32(at: dataoff + 12, swapped: isSwapped),
              let importsCount = reader.readUInt32(at: dataoff + 16, swapped: isSwapped),
              let importsFormat = reader.readUInt32(at: dataoff + 20, swapped: isSwapped),
              let symbolsFormat = reader.readUInt32(at: dataoff + 24, swapped: isSwapped) else {
            return ([], 0, 0)
        }

        guard UInt64(importsOffset) < UInt64(datasize),
              UInt64(symbolsOffset) < UInt64(datasize),
              let importsOffsetInt = Int(exactly: importsOffset),
              let symbolsOffsetInt = Int(exactly: symbolsOffset) else {
            return ([], 0, 0)
        }

        let entryStride: Int
        switch importsFormat {
        case 1: entryStride = 4   // DYLD_CHAINED_IMPORT
        case 2: entryStride = 8   // DYLD_CHAINED_IMPORT_ADDEND
        case 3: entryStride = 16  // DYLD_CHAINED_IMPORT_ADDEND64
        default: return ([], 0, 0)
        }

        let cappedCount = min(Int(importsCount), maxImportsBudget)
        guard cappedCount > 0 else { return ([], 0, 0) }
        let importsEndBound: Int
        if symbolsOffsetInt > importsOffsetInt && (symbolsOffsetInt - importsOffsetInt) >= entryStride {
            importsEndBound = symbolsOffsetInt
        } else {
            importsEndBound = datasize
        }
        let maxReadableEntries = (importsEndBound - importsOffsetInt) / entryStride
        let availableCount = min(cappedCount, maxReadableEntries)
        guard availableCount > 0 else { return ([], 0, 0) }

        let symPoolStart = dataoff + symbolsOffsetInt
        let symPoolSize = datasize - symbolsOffsetInt
        let symbolsPool: Data
        var zlibUsed = 0
        if symbolsFormat == 0 {
            guard let sub = reader.subdata(offset: symPoolStart, length: symPoolSize) else { return ([], 0, 0) }
            symbolsPool = sub
        } else if symbolsFormat == 1 {
            guard maxZlibOutputBytes > 0,
                  let comp = reader.subdata(offset: symPoolStart, length: symPoolSize),
                  let inflated = inflateZlibBounded(comp, maxOutputBytes: maxZlibOutputBytes) else {
                return ([], 0, 0)
            }
            symbolsPool = inflated
            zlibUsed = inflated.count
        } else {
            return ([], 0, 0)
        }

        let symReader = BinaryReader(data: symbolsPool)
        let importsBase = dataoff + importsOffsetInt
        var results: [String] = []
        results.reserveCapacity(min(availableCount, 4096))

        for i in 0..<availableCount {
            let entryOff = importsBase + i * entryStride
            let nameOff: Int
            if importsFormat == 3 {
                guard let raw64 = reader.readUInt64(at: entryOff, swapped: isSwapped) else { continue }
                nameOff = Int(UInt32(truncatingIfNeeded: raw64 >> 32))
            } else {
                guard let raw32 = reader.readUInt32(at: entryOff, swapped: isSwapped) else { continue }
                nameOff = Int(raw32 >> 9)
            }
            guard nameOff >= 0, nameOff < symReader.count else { continue }
            if let sym = symReader.readNullTerminatedString(at: nameOff, maxScanLength: min(512, symReader.count - nameOff)),
               !sym.isEmpty {
                results.append(sym)
            }
        }
        return (results, zlibUsed, availableCount)
    }

    private static func inflateZlibBounded(_ compressed: Data, maxOutputBytes: Int) -> Data? {
        guard !compressed.isEmpty else { return nil }
        var strm = z_stream()
        guard inflateInit_(&strm, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            return nil
        }
        defer { inflateEnd(&strm) }
        var out = Data()
        let chunkCap = 32_768
        var chunk = [UInt8](repeating: 0, count: chunkCap)
        let ok: Bool = compressed.withUnsafeBytes { inPtr in
            strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
            strm.avail_in = uInt(compressed.count)
            while true {
                let status: Int32 = chunk.withUnsafeMutableBufferPointer { buf in
                    strm.next_out = buf.baseAddress
                    strm.avail_out = uInt(chunkCap)
                    return inflate(&strm, Z_NO_FLUSH)
                }
                let produced = chunkCap - Int(strm.avail_out)
                if produced > 0 {
                    if out.count + produced >= maxOutputBytes {
                        let keep = max(0, maxOutputBytes - out.count)
                        if keep > 0 {
                            out.append(contentsOf: chunk[0..<keep])
                        }
                        // Return bounded prefix rather than discarding recovered symbols when trailing zlib padding exceeds cap
                        return true
                    }
                    out.append(contentsOf: chunk[0..<produced])
                }
                if status == Z_STREAM_END { return true }
                if status == Z_OK && strm.avail_in > 0 { continue }
                if status == Z_OK && produced > 0 { continue }
                return false
            }
        }
        return ok ? out : nil
    }

    /// Extracts exact `lazy_bind` stream offsets from `__TEXT,__stub_helper` trampolines
    /// (ARM64 `ldr w16, #8; b prologue; .long lazy_offset` and x86_64/i386 `push $lazy_offset; jmp helper`).
    private static func extractStubHelperLazyBindOffsets(
        segments: [MachOSegment],
        reader: BinaryReader,
        cpuType: cpu_type_t,
        isSwapped: Bool
    ) -> [Int] {
        var offsets: [Int] = []
        var seen: Set<Int> = []
        for seg in segments {
            for sect in seg.sections where sect.sectionName == "__stub_helper" && sect.size >= 10 {
                guard let start = Int(exactly: sect.offset),
                      let sizeInt = Int(exactly: sect.size),
                      sizeInt <= 4 * 1024 * 1024,
                      reader.inRange(offset: start, length: sizeInt) else {
                    continue
                }
                if cpuType == CPU_TYPE_ARM64 || cpuType == CPU_TYPE_ARM64_32 {
                    guard sizeInt >= 12 else { continue }
                    var pos = start
                    let limit = start + sizeInt - 12
                    while pos <= limit && offsets.count < 16_384 {
                        if let w0 = reader.readUInt32(at: pos, swapped: isSwapped),
                           w0 == 0x1800_0050,
                           let w1 = reader.readUInt32(at: pos + 4, swapped: isSwapped),
                           (w1 & 0xFC00_0000) == 0x1400_0000,
                           let lazyOff = reader.readUInt32(at: pos + 8, swapped: isSwapped),
                           let intOff = Int(exactly: lazyOff) {
                            if seen.insert(intOff).inserted {
                                offsets.append(intOff)
                            }
                            pos += 12
                            continue
                        }
                        pos += 4
                    }
                } else if cpuType == CPU_TYPE_X86_64 || cpuType == CPU_TYPE_I386 {
                    if let sub = reader.subdata(offset: start, length: sizeInt) {
                        sub.withUnsafeBytes { raw in
                            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                            var pos = 0
                            while pos + 10 <= raw.count && offsets.count < 16_384 {
                                if base[pos] == 0x68 && base[pos + 5] == 0xE9 {
                                    let imm = UInt32(base[pos + 1])
                                        | (UInt32(base[pos + 2]) << 8)
                                        | (UInt32(base[pos + 3]) << 16)
                                        | (UInt32(base[pos + 4]) << 24)
                                    let resolved = Int(isSwapped ? imm.byteSwapped : imm)
                                    if resolved >= 0 && seen.insert(resolved).inserted {
                                        offsets.append(resolved)
                                    }
                                    pos += 10
                                    continue
                                }
                                pos += 1
                            }
                        }
                    }
                }
            }
        }
        return offsets
    }

    /// Parses bound symbol names from `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` opcode streams (`bind`, `weak_bind`, `lazy_bind`).
    /// For `lazy_bind`, `dyld_stub_binder` jumps directly into per-symbol random-access offsets (`__stub_helper`), so dead
    /// invalid opcodes or desynchronizing prefix opcodes placed before active offsets must never abort symbol extraction.
    private static func parseDyldBindSymbols(
        reader: BinaryReader,
        offset: Int,
        size: Int,
        isLazyBind: Bool = false,
        stubHelperOffsets: [Int] = []
    ) -> [String] {
        guard size > 0, reader.inRange(offset: offset, length: size),
              let stream = reader.subdata(offset: offset, length: size) else {
            return []
        }
        var results: [String] = []
        var seen: Set<String> = []
        stream.withUnsafeBytes { raw in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            let end = raw.count

            func appendSymbol(_ s: String) {
                guard !s.isEmpty, results.count < 65_536 else { return }
                if seen.insert(s).inserted {
                    results.append(s)
                }
            }

            func skipLEB128(at cursor: inout Int) -> Bool {
                var count = 0
                while cursor < end && count < 16 {
                    let b = base[cursor]
                    cursor += 1
                    count += 1
                    if (b & 0x80) == 0 { return true }
                }
                return false
            }

            // 1. For random-access `lazy_bind`, execute exact `dyld_stub_binder` single-record interpreter from every `__stub_helper` target offset.
            if isLazyBind && !stubHelperOffsets.isEmpty {
                for startOff in stubHelperOffsets where startOff >= 0 && startOff < end {
                    var cur = startOff
                    var steps = 0
                    recordLoop: while cur < end && steps < 4096 {
                        steps += 1
                        let opByte = base[cur]
                        cur += 1
                        let op = opByte & 0xF0
                        let im = opByte & 0x0F
                        switch op {
                        case 0x00:
                            break recordLoop
                        case 0x90, 0xA0, 0xB0, 0xC0:
                            break recordLoop
                        case 0x10, 0x30, 0x50:
                            continue
                        case 0x20, 0x60, 0x70, 0x80:
                            if !skipLEB128(at: &cur) { break recordLoop }
                        case 0xD0:
                            if im == 0x00 {
                                if !skipLEB128(at: &cur) { break recordLoop }
                            } else if im != 0x01 {
                                break recordLoop
                            }
                        case 0x40:
                            let symStart = cur
                            while cur < end && base[cur] != 0 { cur += 1 }
                            let symLen = cur - symStart
                            if cur < end { cur += 1 }
                            if symLen > 0 && symLen <= 512 {
                                let s = String(decoding: UnsafeBufferPointer(start: base.advanced(by: symStart), count: symLen), as: UTF8.self)
                                appendSymbol(s)
                            }
                        default:
                            break recordLoop
                        }
                    }
                }
            }

            // 2. Sequential opcode stream pass from offset 0.
            var idx = 0
            func recoverLazyRecord() {
                while idx < end && base[idx] != 0x00 {
                    idx += 1
                }
                while idx < end && base[idx] == 0x00 {
                    idx += 1
                }
            }

            sequentialLoop: while idx < end && results.count < 65_536 {
                let byte = base[idx]
                idx += 1
                let opcode = byte & 0xF0
                let imm = byte & 0x0F

                switch opcode {
                case 0x00: // BIND_OPCODE_DONE
                    if !isLazyBind && imm != 0x00 {
                        break sequentialLoop
                    }
                    continue
                case 0x10, 0x30, 0x50, 0x90, 0xB0:
                    continue
                case 0x20, 0x60, 0x70, 0x80, 0xA0:
                    if !skipLEB128(at: &idx) {
                        if isLazyBind { recoverLazyRecord(); continue }
                        break sequentialLoop
                    }
                case 0xC0:
                    if !skipLEB128(at: &idx) || !skipLEB128(at: &idx) {
                        if isLazyBind { recoverLazyRecord(); continue }
                        break sequentialLoop
                    }
                case 0xD0:
                    if imm == 0x00 {
                        if !skipLEB128(at: &idx) {
                            if isLazyBind { recoverLazyRecord(); continue }
                            break sequentialLoop
                        }
                    } else if imm != 0x01 {
                        if isLazyBind { recoverLazyRecord(); continue }
                        break sequentialLoop
                    }
                case 0x40: // BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
                    let start = idx
                    while idx < end && base[idx] != 0 {
                        idx += 1
                    }
                    let len = idx - start
                    if idx < end { idx += 1 } // consume NUL
                    if len > 0 && len <= 512 {
                        let s = String(decoding: UnsafeBufferPointer(start: base.advanced(by: start), count: len), as: UTF8.self)
                        appendSymbol(s)
                    }
                default:
                    if isLazyBind {
                        recoverLazyRecord()
                        continue
                    }
                    break sequentialLoop
                }
            }

            // 3. Random-access resynchronization pass for `lazy_bind`:
            // Defeats desynchronizing prefix bytes (including dead ULEB128 operands taking values `0x40..0x4F` right before
            // a real `0x40..0x4F` `SET_SYMBOL` opcode, long >32-opcode padding before `DO_BIND`, or stripped `__stub_helper`).
            if isLazyBind {
                @inline(__always)
                func isValidSymbolStart(_ b: UInt8) -> Bool {
                    b == 0x5F || b == 0x24 || b == 0x2E || b == 0x3F
                        || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
                }

                @inline(__always)
                func isValidSymbolBody(_ b: UInt8) -> Bool {
                    b >= 0x21 && b <= 0x7E
                }

                // 2-bit memo per byte in [0, end): 0 = unvisited, 1 = false, 2 = true
                var memo = [UInt64](repeating: 0, count: (end + 31) >> 5)
                var trace: [Int] = []
                trace.reserveCapacity(64)

                @inline(__always)
                func getMemo(_ idx: Int) -> UInt64 {
                    (memo[idx >> 5] >> ((idx & 31) << 1)) & 0x3
                }

                @inline(__always)
                func setMemo(_ idx: Int, _ val: UInt64) {
                    let wordIdx = idx >> 5
                    let shift = (idx & 31) << 1
                    memo[wordIdx] = (memo[wordIdx] & ~(UInt64(0x3) << shift)) | (val << shift)
                }

                func reachesDoBind(from tailStart: Int) -> Bool {
                    guard tailStart >= 0, tailStart < end else { return false }
                    let cached = getMemo(tailStart)
                    if cached != 0 { return cached == 2 }

                    trace.removeAll(keepingCapacity: true)
                    var cur = tailStart
                    var outcome = false
                    while cur < end {
                        let cMemo = getMemo(cur)
                        if cMemo != 0 {
                            outcome = (cMemo == 2)
                            break
                        }
                        trace.append(cur)
                        let opByte = base[cur]
                        cur += 1
                        let op = opByte & 0xF0
                        let im = opByte & 0x0F
                        switch op {
                        case 0x90: // BIND_OPCODE_DO_BIND
                            outcome = true
                            cur = end
                        case 0xA0, 0xB0: // DO_BIND_ADD_ADDR_*
                            if op == 0xA0 && !skipLEB128(at: &cur) {
                                outcome = false
                            } else {
                                outcome = true
                            }
                            cur = end
                        case 0xC0: // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                            if !skipLEB128(at: &cur) || !skipLEB128(at: &cur) {
                                outcome = false
                            } else {
                                outcome = true
                            }
                            cur = end
                        case 0x00: // BIND_OPCODE_DONE before DO_BIND
                            outcome = false
                            cur = end
                        case 0x10, 0x30, 0x50:
                            continue
                        case 0x20, 0x60, 0x70, 0x80:
                            if !skipLEB128(at: &cur) {
                                outcome = false
                                cur = end
                            }
                        case 0xD0:
                            if im == 0x00 {
                                if !skipLEB128(at: &cur) {
                                    outcome = false
                                    cur = end
                                }
                            } else if im != 0x01 {
                                outcome = false
                                cur = end
                            }
                        case 0x40:
                            while cur < end && base[cur] != 0 { cur += 1 }
                            guard cur < end else {
                                outcome = false
                                cur = end
                                break
                            }
                            cur += 1
                        default:
                            outcome = false
                            cur = end
                        }
                    }

                    let mark: UInt64 = outcome ? 2 : 1
                    for idx in trace {
                        setMemo(idx, mark)
                    }
                    return outcome
                }

                // O(N) NUL-anchored backward scan
                var nulPos = 2
                while nulPos < end && results.count < 65_536 {
                    if base[nulPos] == 0, reachesDoBind(from: nulPos + 1) {
                        let minScan = max(0, nulPos - 513)
                        var runStart = nulPos
                        while runStart > minScan && isValidSymbolBody(base[runStart - 1]) {
                            runStart -= 1
                        }
                        if nulPos - runStart >= 2 {
                            var outerOpIdx: Int?
                            let limitOp = nulPos - 1
                            for idx in runStart..<limitOp {
                                if (base[idx] & 0xF0) == 0x40 && isValidSymbolStart(base[idx + 1]) {
                                    let symLen = nulPos - (idx + 1)
                                    if symLen >= 1 && symLen <= 512 {
                                        outerOpIdx = idx
                                        break
                                    }
                                }
                            }
                            if let firstOp = outerOpIdx {
                                let symLen = nulPos - (firstOp + 1)
                                let s = String(
                                    decoding: UnsafeBufferPointer(start: base.advanced(by: firstOp + 1), count: symLen),
                                    as: UTF8.self
                                )
                                appendSymbol(s)
                                // Also inspect any interior `0x40..0x4F` opcode immediately followed by `'_'` (`0x5F`) or `'$'` (`0x24`)
                                // inside `[firstOp + 1, limitOp)` so a dead `0x40..0x4F` prefix byte cannot swallow the real `SET_SYMBOL`.
                                if nulPos - (firstOp + 1) >= 2 {
                                    for innerPos in (firstOp + 1)..<limitOp {
                                        let ib = base[innerPos]
                                        let nextB = base[innerPos + 1]
                                        if (ib & 0xF0) == 0x40 && (nextB == 0x5F || nextB == 0x24) {
                                            let innerLen = nulPos - (innerPos + 1)
                                            if innerLen >= 1 && innerLen <= 512 {
                                                let innerSym = String(
                                                    decoding: UnsafeBufferPointer(start: base.advanced(by: innerPos + 1), count: innerLen),
                                                    as: UTF8.self
                                                )
                                                appendSymbol(innerSym)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    nulPos += 1
                }
            }
        }
        return results
    }
}
