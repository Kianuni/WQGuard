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
        var result: [String] = []
        var seen: Set<String> = []
        for st in symtabs {
            for sym in st.parseSymbols(from: sliceData, is64Bit: is64Bit, isSwapped: isSwapped) where seen.insert(sym).inserted {
                result.append(sym)
            }
        }
        for sym in dynamicImportSymbols where seen.insert(sym).inserted {
            result.append(sym)
        }
        return result
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

    /// Detects `LC_ENCRYPTION_INFO` (`cryptid != 0`) paired with an ad-hoc or non-App-Store code signature
    /// whose `[cryptoff, cryptoff + cryptsize)` bytes contain unencrypted plaintext rather than FairPlay AES ciphertext.
    internal var hasForgedPlaintextFairPlayRange: Bool {
        guard isFairPlayEncrypted else { return false }
        let hasMalformedCSCmd = codeSignatures.contains { cs in
            cs.datasize < 12 || UInt64(cs.dataoff) + UInt64(cs.datasize) > UInt64(sliceData.count)
        }
        let blobs = allCodeSignatureData
        let sigDisqualified: Bool
        if hasMalformedCSCmd {
            sigDisqualified = true
        } else if blobs.isEmpty {
            sigDisqualified = CSBlobParser.shared.inspectCodeSignatureTrust(from: codeSignatureData, sliceData: sliceData).isDisqualifiedFromAppStore
        } else {
            sigDisqualified = blobs.contains {
                CSBlobParser.shared.inspectCodeSignatureTrust(from: $0, sliceData: sliceData).isDisqualifiedFromAppStore
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

        return sliceData.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return false }

            func windowEntropy(start: Int, length: Int) -> Double {
                var counts = [Int](repeating: 0, count: 256)
                for i in start..<(start + length) {
                    counts[Int(base[i])] += 1
                }
                let invN = 1.0 / Double(length)
                var ent = 0.0
                for c in counts where c > 0 {
                    let p = Double(c) * invN
                    ent -= p * log2(p)
                }
                return ent
            }

            if totalLen < 4096 {
                let threshold = totalLen < 1024 ? 7.35 : 7.6
                return windowEntropy(start: lo, length: totalLen) < threshold
            }

            let winSize = 4096
            let maxStart = hi - winSize
            var candidateStarts: [Int] = []
            let totalWindows = totalLen / winSize
            let maxStrided = 256
            let step = max(1, totalWindows / maxStrided)
            var idx = 0
            while idx < totalWindows && candidateStarts.count < maxStrided {
                candidateStarts.append(lo + idx * winSize)
                idx += step
            }
            if candidateStarts.last != maxStart {
                candidateStarts.append(maxStart)
            }
            for ep in entryPointFileOffsets where ep >= lo && ep < hi {
                candidateStarts.append(min(max(lo, ep & ~(winSize - 1)), maxStart))
            }
            for seg in segments {
                for sect in seg.sections where sect.size > 0 {
                    let sName = sect.sectionName
                    if sName == "__text" || sName == "__cstring" || sName == "__objc_methname" {
                        if let sOff = Int(exactly: sect.offset), sOff < hi {
                            let clamped = min(max(lo, sOff), maxStart)
                            if clamped + winSize <= hi {
                                candidateStarts.append(clamped)
                            }
                        }
                    }
                }
            }

            var checked: Set<Int> = []
            for wStart in candidateStarts where checked.insert(wStart).inserted {
                if windowEntropy(start: wStart, length: winSize) < 7.6 {
                    return true
                }
            }
            return false
        }
    }

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
        var selectors: [String] = []

        for seg in segments {
            for sect in seg.sections where sect.sectionName == "__objc_methname" && sect.size > 0 {
                let start = Int(sect.offset)
                guard let sizeInt = Int(exactly: sect.size),
                      start >= 0, sizeInt > 0,
                      start <= sliceData.count,
                      sizeInt <= sliceData.count - start else {
                    continue
                }
                let sectRange = start..<(start + sizeInt)
                var unencryptedSubranges: [Range<Int>] = []
                if let er = encRange {
                    if er.lowerBound <= sectRange.lowerBound && er.upperBound >= sectRange.upperBound {
                        continue
                    }
                    if sectRange.lowerBound < er.lowerBound {
                        unencryptedSubranges.append(sectRange.lowerBound..<min(sectRange.upperBound, er.lowerBound))
                    }
                    if er.upperBound < sectRange.upperBound {
                        unencryptedSubranges.append(max(sectRange.lowerBound, er.upperBound)..<sectRange.upperBound)
                    }
                } else {
                    unencryptedSubranges.append(sectRange)
                }

                sliceData.withUnsafeBytes { raw in
                    for subRange in unencryptedSubranges where !subRange.isEmpty {
                        guard let base = raw.baseAddress?.advanced(by: subRange.lowerBound).assumingMemoryBound(to: UInt8.self) else {
                            continue
                        }
                        let subLen = subRange.count
                        var cur = 0
                        while cur < subLen && selectors.count < 65_536 {
                            while cur < subLen && base[cur] == 0 {
                                cur += 1
                            }
                            if cur >= subLen { break }
                            let strStart = cur
                            while cur < subLen && base[cur] != 0 {
                                cur += 1
                            }
                            let len = cur - strStart
                            if len >= 2 && len <= 512 {
                                let s = String(decoding: UnsafeBufferPointer(start: base.advanced(by: strStart), count: len), as: UTF8.self)
                                if !s.isEmpty {
                                    selectors.append(s)
                                }
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
        if isFairPlayEncrypted {
            guard let range = encryptionInfo?.encryptedRange else { return nil }
            encRange = range
        } else {
            encRange = nil
        }

        for seg in segments {
            for sect in seg.sections where sect.sectionName == "__info_plist" && sect.size > 0 {
                let start = Int(sect.offset)
                guard let sizeInt = Int(exactly: sect.size),
                      sizeInt <= 8 * 1024 * 1024,
                      start >= 0, sizeInt > 0,
                      start <= sliceData.count,
                      sizeInt <= sliceData.count - start else {
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
                    let rawPlist = sliceData.subdata(in: r)
                    if let dict = (try? PropertyListSerialization.propertyList(from: rawPlist, options: [], format: nil)) as? [String: Any] {
                        return dict
                    }
                    if let dict = try? CSBlobParser.shared.parseXMLPlist(rawPlist), !dict.isEmpty {
                        return dict
                    }
                }
            }
        }
        return nil
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
        let headerSize = is64Bit ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        let commandsEnd = min(sliceData.count, headerSize + Int(sizeofcmds))

        func scanWordRange(start: Int, sizeInt: Int, segName: String, sectName: String, baseVA: UInt64) {
            guard sizeInt >= 4 else { return }
            for relOff in stride(from: 0, through: sizeInt - 4, by: 4) {
                let wordOffset = start + relOff
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
                            virtualAddress: baseVA &+ UInt64(relOff),
                            immediate: 0x0080
                        ))
                    }
                }
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
                    let clampedCEnd = cOv ? UInt64(segEnd) : min(rawCEnd, UInt64(segEnd))
                    let cStart = max(segStart, Int(sect.offset))
                    let cEnd = Int(clampedCEnd)
                    if cEnd > cStart {
                        covered.append((cStart, cEnd))
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
            for slice in slices {
                guard slice.offset <= UInt64(data.count),
                      slice.size <= UInt64(data.count) - slice.offset else {
                    if firstError == nil {
                        firstError = MachOParserError.sliceOutOfBounds(offset: slice.offset, size: slice.size, total: data.count)
                    }
                    continue
                }
                let sliceSubdata = data.subdata(in: Int(slice.offset)..<Int(slice.offset + slice.size))
                do {
                    let file = try parseThinSlice(sliceData: sliceSubdata, containerSlices: slices)
                    guard file.cpuType == slice.cpuType else {
                        throw MachOParserError.corruptedFatHeader(
                            reason: "FAT slice cpuType (\(slice.cpuType)) disagrees with thin Mach-O header cpuType (\(file.cpuType))"
                        )
                    }
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
        var codeSignatures: [MachOCodeSignature] = []
        var dynamicImportSymbols: [String] = []
        var dynamicSymSet: Set<String> = []
        var deferredDyldBinds: [(offset: Int, size: Int, isLazy: Bool)] = []
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

                symtabs.append(MachOSymtab(symoff: symoff, nsyms: nsyms, stroff: stroff, strsize: strsize))

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
                   UInt64(dataoff) + UInt64(datasize) <= UInt64(reader.count) {
                    let syms = Self.parseChainedFixupImports(reader: reader, dataoff: Int(dataoff), datasize: Int(datasize), isSwapped: isSwapped)
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
                        deferredDyldBinds.append((offset: Int(off), size: Int(sz), isLazy: isLazy))
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
        isSwapped: Bool
    ) -> [String] {
        guard datasize >= 28, reader.inRange(offset: dataoff, length: datasize) else { return [] }
        guard let importsOffset = reader.readUInt32(at: dataoff + 8, swapped: isSwapped),
              let symbolsOffset = reader.readUInt32(at: dataoff + 12, swapped: isSwapped),
              let importsCount = reader.readUInt32(at: dataoff + 16, swapped: isSwapped),
              let importsFormat = reader.readUInt32(at: dataoff + 20, swapped: isSwapped),
              let symbolsFormat = reader.readUInt32(at: dataoff + 24, swapped: isSwapped) else {
            return []
        }

        guard UInt64(importsOffset) < UInt64(datasize),
              UInt64(symbolsOffset) < UInt64(datasize) else {
            return []
        }

        let entryStride: Int
        switch importsFormat {
        case 1: entryStride = 4   // DYLD_CHAINED_IMPORT
        case 2: entryStride = 8   // DYLD_CHAINED_IMPORT_ADDEND
        case 3: entryStride = 16  // DYLD_CHAINED_IMPORT_ADDEND64
        default: return []
        }

        let cappedCount = Int(min(importsCount, 262_144))
        guard cappedCount > 0 else { return [] }
        let importsEndBound: Int
        if symbolsOffset > importsOffset && (Int(symbolsOffset) - Int(importsOffset)) >= entryStride {
            importsEndBound = Int(symbolsOffset)
        } else {
            importsEndBound = datasize
        }
        let maxReadableEntries = (importsEndBound - Int(importsOffset)) / entryStride
        let availableCount = min(cappedCount, maxReadableEntries)
        guard availableCount > 0 else { return [] }

        let symPoolStart = dataoff + Int(symbolsOffset)
        let symPoolSize = datasize - Int(symbolsOffset)
        let symbolsPool: Data
        if symbolsFormat == 0 {
            guard let sub = reader.subdata(offset: symPoolStart, length: symPoolSize) else { return [] }
            symbolsPool = sub
        } else if symbolsFormat == 1 {
            guard let comp = reader.subdata(offset: symPoolStart, length: symPoolSize),
                  let inflated = inflateZlibBounded(comp, maxOutputBytes: 16 * 1024 * 1024) else {
                return []
            }
            symbolsPool = inflated
        } else {
            return []
        }

        let symReader = BinaryReader(data: symbolsPool)
        let importsBase = dataoff + Int(importsOffset)
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
        return results
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

                func reachesDoBind(from tailStart: Int) -> Bool {
                    var cur = tailStart
                    var steps = 0
                    while cur < end && steps < 4096 {
                        steps += 1
                        let opByte = base[cur]
                        cur += 1
                        let op = opByte & 0xF0
                        let im = opByte & 0x0F
                        switch op {
                        case 0x90: // BIND_OPCODE_DO_BIND
                            return true
                        case 0xA0, 0xB0: // DO_BIND_ADD_ADDR_*
                            if op == 0xA0 && !skipLEB128(at: &cur) { return false }
                            return true
                        case 0xC0: // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                            if !skipLEB128(at: &cur) || !skipLEB128(at: &cur) { return false }
                            return true
                        case 0x00: // BIND_OPCODE_DONE before DO_BIND
                            return false
                        case 0x10, 0x30, 0x50:
                            continue
                        case 0x20, 0x60, 0x70, 0x80:
                            if !skipLEB128(at: &cur) { return false }
                        case 0xD0:
                            if im == 0x00 {
                                if !skipLEB128(at: &cur) { return false }
                            } else if im != 0x01 {
                                return false
                            }
                        case 0x40:
                            while cur < end && base[cur] != 0 { cur += 1 }
                            guard cur < end else { return false }
                            cur += 1
                        default:
                            return false
                        }
                    }
                    return false
                }

                var pos = 0
                while pos + 3 <= end && results.count < 65_536 {
                    if (base[pos] & 0xF0) == 0x40, isValidSymbolStart(base[pos + 1]) {
                        var nulPos = pos + 1
                        var allPrintable = true
                        while nulPos < end && base[nulPos] != 0 && (nulPos - (pos + 1)) <= 512 {
                            if !isValidSymbolBody(base[nulPos]) {
                                allPrintable = false
                                break
                            }
                            nulPos += 1
                        }
                        let symLen = nulPos - (pos + 1)
                        if allPrintable, nulPos < end, base[nulPos] == 0, symLen >= 1, symLen <= 512,
                           reachesDoBind(from: nulPos + 1) {
                            let s = String(decoding: UnsafeBufferPointer(start: base.advanced(by: pos + 1), count: symLen), as: UTF8.self)
                            appendSymbol(s)
                            // Also inspect any interior `0x40..0x4F` opcode immediately followed by `'_'` (`0x5F`) or `'$'` (`0x24`)
                            // inside `[pos + 1, nulPos - 1)` so a dead `0x40..0x4F` prefix byte (e.g., `[0x72, 0x40, 0x41, "_fsgetpath\0"]`
                            // where `0x41` is `'A'`) cannot swallow the real `SET_SYMBOL` opcode via `pos = nulPos + 1`.
                            if nulPos - (pos + 1) >= 2 {
                                for innerPos in (pos + 1)..<(nulPos - 1) {
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
                            pos = nulPos + 1
                            continue
                        }
                    }
                    pos += 1
                }
            }
        }
        return results
    }
}
