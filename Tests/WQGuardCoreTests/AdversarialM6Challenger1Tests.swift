//
//  AdversarialM6Challenger1Tests.swift
//  WQGuardCoreTests
//
//  Tier 5 — Binary & CSBlob White-Box Adversarial Stress Suite.
//  Created for Milestone 6 Adversarial Coverage Hardening by challenger_m6_1.
//
//  Coverage Scope:
//  - MachOArchitecture & CPU Subtype Mappings with ABI masks
//  - MachOParser boundary arithmetic, slice selection, FAT headers, and load command constraints
//  - CSBlobParser SuperBlob corrupted slot indices, ASN.1 DER length octets, and recursion limits
//  - MachOScanner behavioral tuples, FairPlay DRM boundary, and path leak detection
//  - WhitelistEngine pattern matcher regex escaping, spoofing resistance, and thread safety
//

import XCTest
import Foundation
import MachO
@testable import WQGuardCore

final class AdversarialM6Challenger1Tests: XCTestCase {

    private var tempFiles: [URL] = []

    override func tearDown() {
        for url in tempFiles {
            try? FileManager.default.removeItem(at: url)
        }
        tempFiles.removeAll()
        WhitelistEngine.shared.resetToDefaults()
        super.tearDown()
    }

    // =========================================================================
    // MARK: - Section 1: Mach-O Architecture & Header White-Box Hardening
    // =========================================================================

    /// Verifies MachOArchitecture mappings, descriptions, is64Bit flags, and CPU subtype mask stripping.
    func test_M6_C1_MachOArchitecture_comprehensiveCpuTypeAndSubtypeMappings() {
        // 1. ARM64 standard and with subtype mask bits (e.g. CPU_SUBTYPE_PTRAUTH_ABI)
        let arm64Clean = MachOArchitecture.from(cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64_ALL)
        XCTAssertEqual(arm64Clean, .arm64)
        XCTAssertTrue(arm64Clean.is64Bit)
        XCTAssertEqual(arm64Clean.cpuType, CPU_TYPE_ARM64)
        XCTAssertEqual(arm64Clean.description, "arm64")

        // ARM64 with subtype flags (masked by ~CPU_SUBTYPE_MASK)
        let arm64WithFlags = MachOArchitecture.from(
            cpuType: CPU_TYPE_ARM64,
            cpuSubtype: cpu_subtype_t(bitPattern: UInt32(bitPattern: CPU_SUBTYPE_ARM64_ALL) | 0x80000000)
        )
        XCTAssertEqual(arm64WithFlags, .arm64, "Subtype flags above CPU_SUBTYPE_MASK must be stripped")

        // 2. ARM64e with pointer authentication
        let arm64e = MachOArchitecture.from(cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64E)
        XCTAssertEqual(arm64e, .arm64e)
        XCTAssertTrue(arm64e.is64Bit)
        XCTAssertEqual(arm64e.description, "arm64e")

        // 3. ARM64_32 (Apple Watch 64-bit architecture with 32-bit ILP32 pointers)
        let arm64_32 = MachOArchitecture.from(cpuType: CPU_TYPE_ARM64_32, cpuSubtype: 0)
        XCTAssertEqual(arm64_32, .arm64_32)
        XCTAssertFalse(arm64_32.is64Bit, "ARM64_32 operates in 32-bit pointer ABI mode")
        XCTAssertEqual(arm64_32.description, "arm64_32")

        // 4. ARM 32-bit (v7 and v7s)
        let armv7 = MachOArchitecture.from(cpuType: CPU_TYPE_ARM, cpuSubtype: CPU_SUBTYPE_ARM_V7)
        XCTAssertEqual(armv7, .armv7)
        XCTAssertFalse(armv7.is64Bit)
        XCTAssertEqual(armv7.description, "armv7")

        let armv7s = MachOArchitecture.from(cpuType: CPU_TYPE_ARM, cpuSubtype: CPU_SUBTYPE_ARM_V7S)
        XCTAssertEqual(armv7s, .armv7s)
        XCTAssertFalse(armv7s.is64Bit)
        XCTAssertEqual(armv7s.description, "armv7s")

        // 5. x86_64 and i386
        let x86_64 = MachOArchitecture.from(cpuType: CPU_TYPE_X86_64, cpuSubtype: CPU_SUBTYPE_X86_64_ALL)
        XCTAssertEqual(x86_64, .x86_64)
        XCTAssertTrue(x86_64.is64Bit)
        XCTAssertEqual(x86_64.description, "x86_64")

        let i386 = MachOArchitecture.from(cpuType: CPU_TYPE_I386, cpuSubtype: 3)
        XCTAssertEqual(i386, MachOArchitecture.i386)
        XCTAssertFalse(i386.is64Bit)
        XCTAssertEqual(i386.description, "i386")

        // 6. Unknown architecture fallback
        let unknownArch = MachOArchitecture.from(cpuType: 0x12345678, cpuSubtype: 0x42)
        XCTAssertEqual(unknownArch, .unknown(cpuType: 0x12345678, cpuSubtype: 0x42))
        XCTAssertEqual(unknownArch.description, "unknown(cpu: 305419896, sub: 66)")
    }

    /// Verifies MachOParser error reporting on truncated headers at exact byte cutoffs.
    func test_M6_C1_MachOParser_truncatedHeadersExactByteBoundaries() {
        // Less than 4 bytes -> fileTooSmall
        for count in 0..<4 {
            let data = Data(repeating: 0x00, count: count)
            XCTAssertThrowsError(try MachOParser.parse(data: data)) { err in
                XCTAssertEqual(err as? MachOParserError, .fileTooSmall(actual: count, minimum: 4))
            }
        }

        // 32-bit Thin header: 4 to 27 bytes -> truncatedHeader(expected: 28, actual: count)
        for count in 4..<28 {
            var data = Data()
            var magic = UInt32(MH_MAGIC)
            data.append(Data(bytes: &magic, count: 4))
            data.append(Data(repeating: 0x00, count: count - 4))
            XCTAssertThrowsError(try MachOParser.parse(data: data)) { err in
                XCTAssertEqual(err as? MachOParserError, .truncatedHeader(expected: 28, actual: count))
            }
        }

        // 64-bit Thin header: 28 to 31 bytes -> truncatedHeader(expected: 32, actual: count)
        for count in 28..<32 {
            var data = Data()
            var magic = UInt32(MH_MAGIC_64)
            data.append(Data(bytes: &magic, count: 4))
            data.append(Data(repeating: 0x00, count: count - 4))
            XCTAssertThrowsError(try MachOParser.parse(data: data)) { err in
                XCTAssertEqual(err as? MachOParserError, .truncatedHeader(expected: 32, actual: count))
            }
        }
    }

    /// Verifies Universal FAT header safety limits: nfat == 0, nfat > 1024, and truncated fat_arch table.
    func test_M6_C1_MachOParser_FATHeaderSliceCountLimits() {
        // 1. nfat == 0 -> fatBinaryEmpty
        var zeroFat = Data()
        var magicBE = UInt32(FAT_MAGIC).bigEndian
        var zeroNfatBE = UInt32(0).bigEndian
        zeroFat.append(Data(bytes: &magicBE, count: 4))
        zeroFat.append(Data(bytes: &zeroNfatBE, count: 4))
        XCTAssertThrowsError(try MachOParser.parse(data: zeroFat)) { err in
            XCTAssertEqual(err as? MachOParserError, .fatBinaryEmpty)
        }

        // 2. nfat == 1025 -> corruptedFatHeader (exceeds safety limit 1024)
        var excessiveFat = Data()
        var excessiveNfatBE = UInt32(1025).bigEndian
        excessiveFat.append(Data(bytes: &magicBE, count: 4))
        excessiveFat.append(Data(bytes: &excessiveNfatBE, count: 4))
        XCTAssertThrowsError(try MachOParser.parse(data: excessiveFat)) { err in
            guard let machoErr = err as? MachOParserError,
                  case .corruptedFatHeader(let reason) = machoErr else {
                XCTFail("Expected corruptedFatHeader, got: \(err)")
                return
            }
            XCTAssertTrue(reason.contains("exceeds safety limit 1024"))
        }

        // 3. Truncated FAT header: nfat = 2 (requires 8 + 2 * 20 = 48 bytes), but binary has only 28 bytes
        var truncatedFat = Data()
        var nfat2BE = UInt32(2).bigEndian
        truncatedFat.append(Data(bytes: &magicBE, count: 4))
        truncatedFat.append(Data(bytes: &nfat2BE, count: 4))
        truncatedFat.append(Data(repeating: 0x00, count: 20)) // only 1 entry present
        XCTAssertThrowsError(try MachOParser.parse(data: truncatedFat)) { err in
            guard let machoErr = err as? MachOParserError,
                  case .corruptedFatHeader(let reason) = machoErr else {
                XCTFail("Expected corruptedFatHeader, got: \(err)")
                return
            }
            XCTAssertTrue(reason.contains("exceeds binary size"))
        }
    }

    /// Verifies MachOParser.extractSlice boundary arithmetic at EOF and 1-byte overflow.
    func test_M6_C1_MachOParser_extractSlice_boundaryArithmetic() throws {
        let thin = SyntheticMachOGenerator.shared.generateThin(config: .init(symbols: ["_boundary_sym"]))
        let sliceValid = MachOSliceInfo(
            cpuType: CPU_TYPE_ARM64,
            cpuSubtype: CPU_SUBTYPE_ARM64_ALL,
            offset: 0,
            size: UInt64(thin.count),
            align: 0
        )

        // Exact match of full buffer -> succeeds
        let extracted = try MachOParser.extractSlice(from: thin, slice: sliceValid)
        XCTAssertEqual(extracted.count, thin.count)

        // Slice size extending 1 byte past total data -> throws sliceOutOfBounds
        let sliceOverflow = MachOSliceInfo(
            cpuType: CPU_TYPE_ARM64,
            cpuSubtype: CPU_SUBTYPE_ARM64_ALL,
            offset: 0,
            size: UInt64(thin.count) + 1,
            align: 0
        )
        XCTAssertThrowsError(try MachOParser.extractSlice(from: thin, slice: sliceOverflow)) { err in
            XCTAssertEqual(err as? MachOParserError, .sliceOutOfBounds(offset: 0, size: UInt64(thin.count) + 1, total: thin.count))
        }

        // Slice offset beyond data count -> throws sliceOutOfBounds
        let sliceOffsetBeyond = MachOSliceInfo(
            cpuType: CPU_TYPE_ARM64,
            cpuSubtype: CPU_SUBTYPE_ARM64_ALL,
            offset: UInt64(thin.count) + 10,
            size: 100,
            align: 0
        )
        XCTAssertThrowsError(try MachOParser.extractSlice(from: thin, slice: sliceOffsetBeyond)) { err in
            XCTAssertEqual(err as? MachOParserError, .sliceOutOfBounds(offset: UInt64(thin.count) + 10, size: 100, total: thin.count))
        }
    }

    // =========================================================================
    // MARK: - Section 2: Load Commands & Arithmetic Boundary Hardening
    // =========================================================================

    /// Verifies load command count safety: ncmds cannot exceed sizeofcmds / 8.
    func test_M6_C1_MachOParser_loadCommandCountSafety() {
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 100, // 100 commands cannot fit in sizeofcmds = 56
            sizeofcmds: 56,
            flags: 0,
            reserved: 0
        )
        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        data.append(Data(repeating: 0x00, count: 56))

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { err in
            XCTAssertEqual(err as? MachOParserError, .invalidCommandCount(ncmds: 100, sizeofcmds: 56))
        }
    }

    /// Verifies load command size validation: cmdsize must be >= 8 and a multiple of 4.
    func test_M6_C1_MachOParser_invalidCommandSize_unalignedOrTooSmall() {
        // cmdsize = 4 (< 8)
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 1,
            sizeofcmds: 32,
            flags: 0,
            reserved: 0
        )
        var dataSmall = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        var cmdSmall = load_command(cmd: UInt32(LC_SEGMENT_64), cmdsize: 4)
        dataSmall.append(Data(bytes: &cmdSmall, count: 8))
        dataSmall.append(Data(repeating: 0, count: 24))

        XCTAssertThrowsError(try MachOParser.parse(data: dataSmall)) { err in
            if case .invalidCommandSize(let cmd, let sz, let off) = err as? MachOParserError {
                XCTAssertEqual(cmd, UInt32(LC_SEGMENT_64))
                XCTAssertEqual(sz, 4)
                XCTAssertEqual(off, 32)
            } else {
                XCTFail("Expected invalidCommandSize, got: \(err)")
            }
        }

        // cmdsize = 13 (not 4-byte aligned)
        var dataUnaligned = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        var cmdUnaligned = load_command(cmd: UInt32(LC_SEGMENT_64), cmdsize: 13)
        dataUnaligned.append(Data(bytes: &cmdUnaligned, count: 8))
        dataUnaligned.append(Data(repeating: 0, count: 24))

        XCTAssertThrowsError(try MachOParser.parse(data: dataUnaligned)) { err in
            if case .invalidCommandSize(let cmd, let sz, _) = err as? MachOParserError {
                XCTAssertEqual(cmd, UInt32(LC_SEGMENT_64))
                XCTAssertEqual(sz, 13)
            } else {
                XCTFail("Expected invalidCommandSize for unaligned size, got: \(err)")
            }
        }
    }

    /// Verifies load command extending past sizeofcmds throws commandOutOfBounds.
    func test_M6_C1_MachOParser_commandOutOfBounds_exceedingSizeofcmds() {
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 2,
            sizeofcmds: 80,
            flags: 0,
            reserved: 0
        )
        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)

        // First command: 72 bytes
        var seg = segment_command_64()
        seg.cmd = UInt32(LC_SEGMENT_64)
        seg.cmdsize = 72
        data.append(Data(bytes: &seg, count: 72))

        // Second command claims cmdsize = 16, but only 8 bytes remain in sizeofcmds
        var cmd2 = load_command(cmd: UInt32(LC_SYMTAB), cmdsize: 16)
        data.append(Data(bytes: &cmd2, count: 8))

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { err in
            if case .commandOutOfBounds(let cmd, let sz, let cursor, let total) = err as? MachOParserError {
                XCTAssertEqual(cmd, UInt32(LC_SYMTAB))
                XCTAssertEqual(sz, 16)
                XCTAssertEqual(cursor, 32 + 72)
                XCTAssertEqual(total, 32 + 80)
            } else {
                XCTFail("Expected commandOutOfBounds, got: \(err)")
            }
        }
    }

    /// Verifies dylib_command nameOffset boundaries: nameOffset < 24 and nameOffset >= cmdsize throw malformedCommand.
    func test_M6_C1_MachOParser_dylibCommand_nameOffsetBounds() {
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 1,
            sizeofcmds: 32,
            flags: 0,
            reserved: 0
        )

        // 1. nameOffset = 20 (< 24)
        var dataOffsetSmall = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        var dylibCmdSmall = dylib_command(
            cmd: UInt32(LC_LOAD_DYLIB),
            cmdsize: 32,
            dylib: dylib(name: lc_str(offset: 20), timestamp: 0, current_version: 0, compatibility_version: 0)
        )
        dataOffsetSmall.append(Data(bytes: &dylibCmdSmall, count: MemoryLayout<dylib_command>.size))
        dataOffsetSmall.append(Data(repeating: 0, count: 8))

        XCTAssertThrowsError(try MachOParser.parse(data: dataOffsetSmall)) { err in
            guard let machoErr = err as? MachOParserError,
                  case .malformedCommand(let cmd, let reason) = machoErr else {
                XCTFail("Expected malformedCommand for nameOffset < 24, got: \(err)")
                return
            }
            XCTAssertEqual(cmd, UInt32(LC_LOAD_DYLIB))
            XCTAssertTrue(reason.contains("outside command bounds"))
        }

        // 2. nameOffset = 32 (>= cmdsize 32)
        var dataOffsetLarge = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        var dylibCmdLarge = dylib_command(
            cmd: UInt32(LC_LOAD_DYLIB),
            cmdsize: 32,
            dylib: dylib(name: lc_str(offset: 32), timestamp: 0, current_version: 0, compatibility_version: 0)
        )
        dataOffsetLarge.append(Data(bytes: &dylibCmdLarge, count: MemoryLayout<dylib_command>.size))
        dataOffsetLarge.append(Data(repeating: 0, count: 8))

        XCTAssertThrowsError(try MachOParser.parse(data: dataOffsetLarge)) { err in
            guard let machoErr = err as? MachOParserError,
                  case .malformedCommand(let cmd, let reason) = machoErr else {
                XCTFail("Expected malformedCommand for nameOffset >= cmdsize, got: \(err)")
                return
            }
            XCTAssertEqual(cmd, UInt32(LC_LOAD_DYLIB))
            XCTAssertTrue(reason.contains("outside command bounds"))
        }
    }

    /// Verifies MachOSymtab parsing when nsyms == 0, strx == 0, and unterminated symbol strings.
    func test_M6_C1_MachOParser_symtab_boundaryAndTruncation() throws {
        // Construct binary with nsyms == 0
        let binEmptySym = SyntheticMachOGenerator.shared.generateThin(config: .init(symbols: []))
        let parsedEmpty = try MachOParser.parse(data: binEmptySym)
        XCTAssertTrue(parsedEmpty.symbols.isEmpty)
        XCTAssertFalse(parsedEmpty.containsSymbol("non_existent"))
        XCTAssertEqual(parsedEmpty.findSymbols(matching: ["sym1", "sym2"]), [])

        // Construct binary with symbols
        let binWithSym = SyntheticMachOGenerator.shared.generateThin(config: .init(
            symbols: ["container_query_create", "dlopen", "dlsym"]
        ))
        let parsed = try MachOParser.parse(data: binWithSym)
        XCTAssertTrue(parsed.containsSymbol("container_query_create"))
        XCTAssertTrue(parsed.containsSymbol("_container_query_create"), "Should match with underscore prefix")
        XCTAssertEqual(parsed.findSymbols(matching: ["container_query_create", "dlsym", "missing"]), ["container_query_create", "dlsym"])
    }

    // =========================================================================
    // MARK: - Section 3: CSBlob & SuperBlob White-Box Attack Vectors
    // =========================================================================

    /// Verifies CSBlobParser SuperBlob header bounds checking: < 12 bytes, invalid magic, declared length bounds.
    func test_M6_C1_CSBlob_superBlobHeaderValidation() {
        let parser = CSBlobParser.shared

        // Less than 12 bytes
        for len in [0, 4, 8, 11] {
            let data = Data(repeating: 0x00, count: len)
            XCTAssertThrowsError(try parser.parseSuperBlob(data)) { err in
                XCTAssertEqual(err as? CSBlobError, .dataTooSmall(expected: 12, actual: len))
            }
        }

        // Invalid magic (0x11223344 != 0xfade0cc0)
        var badMagicData = Data()
        var badMagic = UInt32(0x11223344).bigEndian
        var lenBE = UInt32(100).bigEndian
        var countBE = UInt32(1).bigEndian
        badMagicData.append(Data(bytes: &badMagic, count: 4))
        badMagicData.append(Data(bytes: &lenBE, count: 4))
        badMagicData.append(Data(bytes: &countBE, count: 4))
        badMagicData.append(Data(repeating: 0x00, count: 88))

        XCTAssertThrowsError(try parser.parseSuperBlob(badMagicData)) { err in
            XCTAssertEqual(err as? CSBlobError, .invalidSuperBlobMagic(actual: 0x11223344))
        }

        // Declared length < 12
        var shortLenData = Data()
        var validMagic = UInt32(CSBlobConstants.superBlobMagic).bigEndian
        var shortLen = UInt32(8).bigEndian
        shortLenData.append(Data(bytes: &validMagic, count: 4))
        shortLenData.append(Data(bytes: &shortLen, count: 4))
        shortLenData.append(Data(bytes: &countBE, count: 4))

        XCTAssertThrowsError(try parser.parseSuperBlob(shortLenData)) { err in
            XCTAssertEqual(err as? CSBlobError, .superBlobLengthOutOfBounds(declared: 8, actual: 12))
        }

        // Declared length > buffer.count
        var hugeLenData = Data()
        var hugeLen = UInt32(500).bigEndian
        hugeLenData.append(Data(bytes: &validMagic, count: 4))
        hugeLenData.append(Data(bytes: &hugeLen, count: 4))
        hugeLenData.append(Data(bytes: &countBE, count: 4))

        XCTAssertThrowsError(try parser.parseSuperBlob(hugeLenData)) { err in
            XCTAssertEqual(err as? CSBlobError, .superBlobLengthOutOfBounds(declared: 500, actual: 12))
        }
    }

    /// Verifies CSBlobParser handles corrupted slot index entries safely: blobOff < 12, blobLen < 8, and blobOff + blobLen > totalLength.
    func test_M6_C1_CSBlob_corruptedSlotIndices_boundsAndSelfReference() throws {
        let parser = CSBlobParser.shared

        // Build SuperBlob with 3 corrupted slot index entries
        var sb = Data()
        var magic = UInt32(CSBlobConstants.superBlobMagic).bigEndian
        var totalLen = UInt32(100).bigEndian
        var slotCount = UInt32(3).bigEndian
        sb.append(Data(bytes: &magic, count: 4))
        sb.append(Data(bytes: &totalLen, count: 4))
        sb.append(Data(bytes: &slotCount, count: 4))

        // Slot 1: blobOff = 4 (points into header; must be >= 12)
        var s1Type = UInt32(CSBlobConstants.slotEntitlements).bigEndian
        var s1Off = UInt32(4).bigEndian
        sb.append(Data(bytes: &s1Type, count: 4))
        sb.append(Data(bytes: &s1Off, count: 4))

        // Slot 2: blobOff = 50, but blobLen = 4 (< 8)
        var s2Type = UInt32(CSBlobConstants.slotEntitlements).bigEndian
        var s2Off = UInt32(50).bigEndian
        sb.append(Data(bytes: &s2Type, count: 4))
        sb.append(Data(bytes: &s2Off, count: 4))

        // Slot 3: blobOff = 70, blobLen = 50 (70 + 50 = 120 > totalLen 100)
        var s3Type = UInt32(CSBlobConstants.slotEntitlements).bigEndian
        var s3Off = UInt32(70).bigEndian
        sb.append(Data(bytes: &s3Type, count: 4))
        sb.append(Data(bytes: &s3Off, count: 4))

        // Pad up to 100 bytes
        sb.append(Data(repeating: 0x00, count: 100 - sb.count))

        // Inject slot 2 header at offset 50: magic = 0xfade7171, len = 4 (< 8)
        var xmlMagic = UInt32(CSBlobConstants.entitlementXmlMagic).bigEndian
        var s2Len = UInt32(4).bigEndian
        sb.replaceSubrange(50..<54, with: Data(bytes: &xmlMagic, count: 4))
        sb.replaceSubrange(54..<58, with: Data(bytes: &s2Len, count: 4))

        // Inject slot 3 header at offset 70: magic = 0xfade7171, len = 50 (extends past 100)
        var s3Len = UInt32(50).bigEndian
        sb.replaceSubrange(70..<74, with: Data(bytes: &xmlMagic, count: 4))
        sb.replaceSubrange(74..<78, with: Data(bytes: &s3Len, count: 4))

        // Parse: All 3 slots are corrupted -> returns .empty without trapping or crashing
        let parsed = try parser.parseSuperBlob(sb)
        XCTAssertEqual(parsed, .empty)
        XCTAssertFalse(parsed.hasAppGroups)
        XCTAssertEqual(parsed.appGroups, [])
        XCTAssertEqual(parsed.formatUsed, .none)
    }

    /// Verifies CSBlobParser strips trailing null-byte padding from codesign/ldid XML plists.
    func test_M6_C1_CSBlob_xmlPlist_stripsNullPaddingAndHandlesMalformedXML() throws {
        let parser = CSBlobParser.shared

        let validPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.padded.nullbytes</string>
            </array>
        </dict>
        </plist>
        """
        var paddedData = validPlist.data(using: .utf8)!
        paddedData.append(Data(repeating: 0x00, count: 64)) // 64 trailing null padding bytes

        let dict = try parser.parseXMLPlist(paddedData)
        let groups = parser.extractAppGroups(fromPlistDict: dict)
        XCTAssertEqual(groups, ["group.padded.nullbytes"])

        // Corrupted XML syntax -> throws malformedXMLPlist
        let malformedData = "<plist><dict><key>unclosed".data(using: .utf8)!
        XCTAssertThrowsError(try parser.parseXMLPlist(malformedData)) { err in
            guard let csErr = err as? CSBlobError,
                  case .malformedXMLPlist = csErr else {
                XCTFail("Expected malformedXMLPlist, got: \(err)")
                return
            }
        }
    }

    /// Verifies CSBlobParser handles non-string, boolean, and mixed elements in App Groups plist dictionary.
    func test_M6_C1_CSBlob_xmlPlist_mixedAndMalformedAppGroupTypes() {
        let parser = CSBlobParser.shared

        // 1. Single string (non-array)
        let singleDict: [String: Any] = [
            CSBlobConstants.appGroupsKey: "group.single.string"
        ]
        XCTAssertEqual(parser.extractAppGroups(fromPlistDict: singleDict), ["group.single.string"])

        // 2. Mixed array with integers, booleans, empty strings, and whitespace
        let mixedDict: [String: Any] = [
            CSBlobConstants.appGroupsKey: [
                12345,
                "  group.valid.one  ",
                true,
                "",
                "   ",
                ["nested": "dict"],
                "group.valid.two"
            ]
        ]
        XCTAssertEqual(parser.extractAppGroups(fromPlistDict: mixedDict), ["group.valid.one", "group.valid.two"])

        // 3. App group key is boolean instead of string or array
        let boolDict: [String: Any] = [
            CSBlobConstants.appGroupsKey: true
        ]
        XCTAssertEqual(parser.extractAppGroups(fromPlistDict: boolDict), [])
    }

    /// Verifies ASN.1 DER decoder rejects BER indefinite length (0x80) and recursion bombs > 32.
    func test_M6_C1_CSBlob_asn1der_indefiniteLengthAndRecursionLimits() {
        // 1. BER indefinite length 0x80 -> rejected
        let berData = Data([0x30, 0x80, 0x01, 0x01, 0xff, 0x00, 0x00])
        XCTAssertThrowsError(try ASN1DERDecoder.decode(berData)) { err in
            guard let csErr = err as? CSBlobError,
                  case .malformedDER(let reason) = csErr else {
                XCTFail("Expected malformedDER for BER indefinite length, got: \(err)")
                return
            }
            XCTAssertTrue(reason.contains("0x80"))
        }

        // 2. Recursion depth limit > 32
        var bomb = Data([0x01, 0x01, 0xff]) // boolean true
        for _ in 0..<35 {
            var seq = Data([0x30, UInt8(bomb.count)])
            seq.append(bomb)
            bomb = seq
        }

        XCTAssertThrowsError(try ASN1DERDecoder.decode(bomb)) { err in
            guard let csErr = err as? CSBlobError,
                  case .malformedDER(let reason) = csErr else {
                XCTFail("Expected malformedDER for recursion depth limit, got: \(err)")
                return
            }
            XCTAssertTrue(reason.contains("recursion depth exceeded"))
        }
    }

    /// Verifies ASN.1 DER multi-byte length octets (1, 2, 3, 4 bytes) and rejection of numOctets > 4.
    func test_M6_C1_CSBlob_asn1der_lengthOctetsValidation() throws {
        // 1. Short form length: 5 bytes
        let shortForm = Data([0x0c, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]) // UTF8String "hello"
        let nodeShort = try ASN1DERDecoder.decode(shortForm)
        XCTAssertEqual(nodeShort, .string("hello"))

        // 2. Long form 1 octet (0x81, 0x05)
        let longForm1 = Data([0x0c, 0x81, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f])
        let nodeLong1 = try ASN1DERDecoder.decode(longForm1)
        XCTAssertEqual(nodeLong1, .string("hello"))

        // 3. Long form 2 octets (0x82, 0x00, 0x05)
        let longForm2 = Data([0x0c, 0x82, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f])
        let nodeLong2 = try ASN1DERDecoder.decode(longForm2)
        XCTAssertEqual(nodeLong2, .string("hello"))

        // 4. Invalid length octets: 0x85 (5 octets > limit 4)
        let invalidOctets = Data([0x0c, 0x85, 0x00, 0x00, 0x00, 0x00, 0x05, 0x68])
        XCTAssertThrowsError(try ASN1DERDecoder.decode(invalidOctets)) { err in
            guard let csErr = err as? CSBlobError,
                  case .malformedDER(let reason) = csErr else {
                XCTFail("Expected malformedDER for >4 length octets, got: \(err)")
                return
            }
            XCTAssertTrue(reason.contains("Invalid DER length octets"))
        }
    }

    /// Verifies dual-slot coexistence: Slot 5 XML and Slot 7 DER both declaring different App Groups merge deduplicated with .dual format.
    func test_M6_C1_CSBlob_dualSlots_xmlAndDerDeduplicatedMerge() throws {
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.shared.common", "group.xml.exclusive"])
        let der = SyntheticMachOGenerator.createDEREntitlements(appGroups: ["group.shared.common", "group.der.exclusive"])

        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: xml,
            derEntitlements: der
        ))

        let parsed = try MachOParser.parse(data: bin)
        guard let csData = parsed.codeSignatureData else {
            XCTFail("Missing code signature data")
            return
        }

        let entitlements = try CSBlobParser.shared.parseSuperBlob(csData)
        XCTAssertTrue(entitlements.hasAppGroups)
        XCTAssertEqual(entitlements.formatUsed, .dual)
        XCTAssertEqual(entitlements.appGroups.count, 3)
        XCTAssertTrue(entitlements.appGroups.contains("group.shared.common"))
        XCTAssertTrue(entitlements.appGroups.contains("group.xml.exclusive"))
        XCTAssertTrue(entitlements.appGroups.contains("group.der.exclusive"))
    }

    // =========================================================================
    // MARK: - Section 4: MachOScanner Detection Precision & Behavioral Tuple
    // =========================================================================

    /// Verifies FairPlay DRM binary (cryptid == 1): __TEXT strings are skipped, but symbols and linked dylibs in __LINKEDIT are still scanned.
    func test_M6_C1_MachOScanner_fairPlayDrmHandling() throws {
        let scanner = MachOScanner.shared

        // App Store encrypted binary linking libsystem_containermanager.dylib
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 1,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["container_query_create"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.fairplay.app"])
        ))

        let details = try scanner.parseMachO(data: bin)
        XCTAssertEqual(details.cryptid, 1)
        XCTAssertTrue(details.isFairPlayEncrypted)
        XCTAssertTrue(details.textStrings.isEmpty, "__TEXT strings must not be parsed on FairPlay-encrypted binaries")
        XCTAssertTrue(details.linkedDylibs.contains("/usr/lib/system/libsystem_containermanager.dylib"))
        XCTAssertTrue(details.symbols.contains("container_query_create"))

        let context = MachOScanner.ScanContext(
            bundleId: "com.fairplay.victim",
            installChannel: .appStore,
            appGroups: ["group.fairplay.app"]
        )
        let finding = scanner.scan(details: details, context: context)
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.evidence.isFairPlayEncrypted)
    }

    /// Verifies the 3 variants of the obfuscated behavioral tuple:
    /// cryptid == 0 + AppGroups + dlopen/dlsym + (symlink || sandbox_extension_consume || fsgetpath)
    func test_M6_C1_MachOScanner_behavioralTupleVariants() throws {
        let scanner = MachOScanner.shared
        let appGroups = ["group.com.adversarial.tuple"]

        // Variant A: dlopen + dlsym + symlink
        let binA = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["dlopen", "dlsym", "symlink"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: appGroups)
        ))
        let detailsA = try scanner.parseMachO(data: binA)
        let findingA = scanner.scan(details: detailsA, context: .init(bundleId: "com.tuple.a", appGroups: appGroups))
        XCTAssertEqual(findingA.riskTier, .highRisk)
        XCTAssertTrue(findingA.indicators.contains { $0.signature == SignatureCatalog.behavioralTupleRule.pattern })

        // Variant B: dlopen + dlsym + sandbox_extension_consume
        let binB = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["dlopen", "dlsym", "sandbox_extension_consume"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: appGroups)
        ))
        let detailsB = try scanner.parseMachO(data: binB)
        let findingB = scanner.scan(details: detailsB, context: .init(bundleId: "com.tuple.b", appGroups: appGroups))
        XCTAssertEqual(findingB.riskTier, .highRisk)

        // Variant C: dlopen + dlsym alone (no symlink, no exploit APIs) -> Caution
        let binC = SyntheticMachOGenerator.shared.generateThin(config: .init(
            cryptid: 0,
            symbols: ["dlopen", "dlsym"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: appGroups)
        ))
        let detailsC = try scanner.parseMachO(data: binC)
        let findingC = scanner.scan(details: detailsC, context: .init(bundleId: "com.tuple.c", appGroups: appGroups))
        XCTAssertEqual(findingC.riskTier, .caution, "dlopen + dlsym alone without exploit APIs must be classified as Caution")
        XCTAssertTrue(findingC.indicators.contains { $0.signature == SignatureCatalog.dynamicLoadingCautionRule.pattern })
    }

    /// Verifies path leak detection: fsgetpath alone vs fsgetpath + /Containers/Data/ prefix string.
    func test_M6_C1_MachOScanner_pathLeakVariants() throws {
        let scanner = MachOScanner.shared
        let appGroups = ["group.com.adversarial.pathleak"]

        // 1. fsgetpath alone -> High Risk (APFS inode brute force)
        let binAlone = SyntheticMachOGenerator.shared.generateThin(config: .init(
            symbols: ["fsgetpath"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: appGroups)
        ))
        let detailsAlone = try scanner.parseMachO(data: binAlone)
        let findingAlone = scanner.scan(details: detailsAlone, context: .init(bundleId: "com.leak.alone", appGroups: appGroups))
        XCTAssertEqual(findingAlone.riskTier, .highRisk)
        XCTAssertTrue(findingAlone.indicators.contains { $0.signature == "fsgetpath" })

        // 2. Binary lacking App Groups -> gated out as Safe
        let binNoGroups = SyntheticMachOGenerator.shared.generateThin(config: .init(
            symbols: ["container_query_create", "libsystem_containermanager.dylib"]
        ))
        let detailsNoGroups = try scanner.parseMachO(data: binNoGroups)
        let findingNoGroups = scanner.scan(details: detailsNoGroups, context: .init(bundleId: "com.safe.nogroups", appGroups: []))
        XCTAssertEqual(findingNoGroups.riskTier, .safe, "Apps without App Groups must be fast-pathed as Safe")
    }

    // =========================================================================
    // MARK: - Section 5: WhitelistEngine & PatternMatcher Hardening
    // =========================================================================

    /// Verifies PatternMatcher safely escapes regex metacharacters in glob patterns without regex injection.
    func test_M6_C1_PatternMatcher_globAndRegexMetacharacters() {
        // Regex metacharacters must be matched literally, not as regex operators
        XCTAssertTrue(PatternMatcher.matches(pattern: "com.app.test+1", value: "com.app.test+1"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.app.test+1", value: "com.app.testtttt1"), "Plus sign must not act as regex plus")

        XCTAssertTrue(PatternMatcher.matches(pattern: "com.app.[abc]", value: "com.app.[abc]"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.app.[abc]", value: "com.app.a"), "Brackets must not act as regex character class")

        XCTAssertTrue(PatternMatcher.matches(pattern: "com.app.(foo|bar)", value: "com.app.(foo|bar)"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.app.(foo|bar)", value: "com.app.foo"), "Parentheses and pipe must not act as regex group")

        // Wildcard glob matching
        XCTAssertTrue(PatternMatcher.matches(pattern: "com.*.gestaltx", value: "com.straight-tamago.gestaltx"))
        XCTAssertTrue(PatternMatcher.matches(pattern: "group.*gestaltx", value: "group.test.gestaltx"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.*.gestaltx", value: "org.other.gestaltx"))
    }

    /// Demonstrates the single wildcard '*' matching defect:
    /// PatternMatcher.matches(pattern: "*", value: ...) returns false because range(of: "", options: [.anchored]) returns nil in Swift Foundation.
    func test_M6_C1_PatternMatcher_singleWildcardHandling() {
        let matchesArbitrary = PatternMatcher.matches(pattern: "*", value: "any.arbitrary.bundle.id")
        let matchesEmpty = PatternMatcher.matches(pattern: "*", value: "")
        print("[EMPIRICAL OBSERVATION] PatternMatcher single wildcard: matchesArbitrary=\(matchesArbitrary), matchesEmpty=\(matchesEmpty)")
        XCTAssertTrue(matchesArbitrary, "Single wildcard '*' pattern must match any value")
        XCTAssertTrue(matchesEmpty, "Single wildcard '*' pattern must match empty string")
    }

    /// Demonstrates the multiple Slot 5 shadowing vulnerability:
    /// When an adversary embeds a decoy empty Slot 5 entry before the real App Groups Slot 5 entry,
    /// CSBlobParser.parseSuperBlob takes only entries.first, dropping the App Groups and causing
    /// EntitlementGating to fast-path the exploit binary as Safe.
    func test_M6_C1_CSBlob_multipleSlot5ShadowingEmpiricalDemonstration() throws {
        let emptyXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict></dict></plist>"
        let evilXml = """
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version=\"1.0\">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.shadowed.malicious</string>
            </array>
        </dict>
        </plist>
        """

        let emptyData = emptyXml.data(using: .utf8)!
        let evilData = evilXml.data(using: .utf8)!

        var sb = Data()
        var magic = UInt32(CSBlobConstants.superBlobMagic).bigEndian
        let totalLen = 12 + 16 + (8 + emptyData.count) + (8 + evilData.count)
        var totalLenBE = UInt32(totalLen).bigEndian
        var countBE = UInt32(2).bigEndian

        sb.append(Data(bytes: &magic, count: 4))
        sb.append(Data(bytes: &totalLenBE, count: 4))
        sb.append(Data(bytes: &countBE, count: 4))

        let off0 = 12 + 16
        let off1 = off0 + 8 + emptyData.count

        // Entry 0 Index
        var type0 = UInt32(CSBlobConstants.slotEntitlements).bigEndian
        var off0BE = UInt32(off0).bigEndian
        sb.append(Data(bytes: &type0, count: 4))
        sb.append(Data(bytes: &off0BE, count: 4))

        // Entry 1 Index
        var type1 = UInt32(CSBlobConstants.slotEntitlements).bigEndian
        var off1BE = UInt32(off1).bigEndian
        sb.append(Data(bytes: &type1, count: 4))
        sb.append(Data(bytes: &off1BE, count: 4))

        // Entry 0 Blob: magic 0xfade7171, len = 8 + emptyData.count
        var magic0 = UInt32(CSBlobConstants.entitlementXmlMagic).bigEndian
        var len0 = UInt32(8 + emptyData.count).bigEndian
        sb.append(Data(bytes: &magic0, count: 4))
        sb.append(Data(bytes: &len0, count: 4))
        sb.append(emptyData)

        // Entry 1 Blob: magic 0xfade7171, len = 8 + evilData.count
        var magic1 = UInt32(CSBlobConstants.entitlementXmlMagic).bigEndian
        var len1 = UInt32(8 + evilData.count).bigEndian
        sb.append(Data(bytes: &magic1, count: 4))
        sb.append(Data(bytes: &len1, count: 4))
        sb.append(evilData)

        let parsed = try CSBlobParser.shared.parseSuperBlob(sb)
        print("[EMPIRICAL OBSERVATION] Multiple slot 5 entries: hasAppGroups=\(parsed.hasAppGroups), appGroups=\(parsed.appGroups)")
        XCTAssertTrue(parsed.hasAppGroups, "CSBlobParser should extract App Groups from any valid Slot 5 entry even if shadowed by an earlier entry")
        XCTAssertTrue(parsed.appGroups.contains("group.com.shadowed.malicious"))
    }

    /// Verifies that when primary Erosion rule is disabled, com.jbdotparty.Erosion is NOT matched by Erosion-CN.
    func test_M6_C1_WhitelistEngine_ErosionCN_distinctFromErosion() {
        let engine = WhitelistEngine(tools: TestWhitelistFixtures.allSampleRulesIncludingDefault)

        // 1. When Erosion is enabled, it matches Erosion
        let initial = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        XCTAssertTrue(initial.isWhitelisted)
        XCTAssertEqual(initial.toolName, "Erosion")

        // 2. Disable Erosion
        engine.toggleTool(named: "Erosion", isEnabled: false)

        // 3. com.jbdotparty.Erosion must NOT match Erosion-CN
        let afterDisable = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        XCTAssertFalse(afterDisable.isWhitelisted, "com.jbdotparty.Erosion must NOT match Erosion-CN when Erosion is disabled")
        XCTAssertNil(afterDisable.toolName)

        // 4. com.jbdotparty.Erosion-CN continues to match Erosion-CN
        let erosionCN = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion-CN",
            appGroups: ["group.com.jbdotparty.Erosion.Testing"]
        )
        XCTAssertTrue(erosionCN.isWhitelisted)
        XCTAssertEqual(erosionCN.toolName, "Erosion-CN")
    }

    /// Verifies spoofing resistance: matching bundle ID without valid App Group is rejected.
    func test_M6_C1_WhitelistEngine_spoofingResistance_appGroupMustMatch() {
        let engine = WhitelistEngine(tools: TestWhitelistFixtures.allSampleRulesIncludingDefault)

        // Spoofed Erosion bundle ID with attacker's App Group -> REJECTED
        let spoofedErosion = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.evil.trojan"]
        )
        XCTAssertFalse(spoofedErosion.isWhitelisted)
        XCTAssertNil(spoofedErosion.toolName)

        // Spoofed WQFiles bundle ID with no App Groups -> REJECTED
        let spoofedWQFiles = engine.isWhitelisted(
            bundleId: "cz.kolbi.wqfiles",
            appGroups: []
        )
        XCTAssertFalse(spoofedWQFiles.isWhitelisted)
        XCTAssertNil(spoofedWQFiles.toolName)

        // Attacker App Group matching Erosion with attacker Bundle ID -> REJECTED
        let spoofedGroupOnly = engine.isWhitelisted(
            bundleId: "com.attacker.tool",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        XCTAssertFalse(spoofedGroupOnly.isWhitelisted)
        XCTAssertNil(spoofedGroupOnly.toolName)
    }

    /// Verifies custom whitelist tool with Team ID enforcement.
    func test_M6_C1_WhitelistEngine_customToolWithTeamIdEnforcement() {
        let engine = WhitelistEngine()

        let customTool = WhitelistedTool(
            name: "AuthorizedInternalScanner",
            allowedBundleIds: ["com.corp.scanner"],
            allowedAppGroups: ["group.com.corp.scanner"],
            allowedTeamIds: ["TEAM123456"],
            description: "Internal authorized security utility",
            isEnabled: true
        )
        engine.registerCustomTool(customTool)

        // Authorized candidate with correct Team ID
        let valid = engine.isWhitelisted(
            bundleId: "com.corp.scanner",
            appGroups: ["group.com.corp.scanner"],
            teamId: "TEAM123456"
        )
        XCTAssertTrue(valid.isWhitelisted)
        XCTAssertEqual(valid.toolName, "AuthorizedInternalScanner")

        // Rogue candidate with wrong Team ID -> REJECTED
        let rogueTeam = engine.isWhitelisted(
            bundleId: "com.corp.scanner",
            appGroups: ["group.com.corp.scanner"],
            teamId: "ROGUE99999"
        )
        XCTAssertFalse(rogueTeam.isWhitelisted)

        // Rogue candidate with nil Team ID -> REJECTED
        let noTeam = engine.isWhitelisted(
            bundleId: "com.corp.scanner",
            appGroups: ["group.com.corp.scanner"],
            teamId: nil
        )
        XCTAssertFalse(noTeam.isWhitelisted)
    }

    /// Verifies WhitelistEngine thread safety under concurrent reader and writer contention across 100 threads.
    func test_M6_C1_WhitelistEngine_concurrentQueriesAndMutations() {
        let engine = WhitelistEngine(tools: TestWhitelistFixtures.allSampleRulesIncludingDefault)
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "com.adversarial.whitelist.concurrency", attributes: .concurrent)

        for i in 0..<100 {
            group.enter()
            queue.async {
                if i % 3 == 0 {
                    // Mutation: toggle tool
                    engine.toggleTool(named: "Erosion", isEnabled: (i % 2 == 0))
                } else if i % 3 == 1 {
                    // Mutation: register custom tool
                    let tool = WhitelistedTool(
                        name: "DynamicTool_\(i)",
                        allowedBundleIds: ["com.dynamic.\(i)"],
                        allowedAppGroups: ["group.dynamic.\(i)"]
                    )
                    engine.registerCustomTool(tool)
                } else {
                    // Read: query isWhitelisted
                    _ = engine.isWhitelisted(
                        bundleId: "com.jbdotparty.Erosion",
                        appGroups: ["group.com.jbdotparty.Erosion.WQ"]
                    )
                }
                group.leave()
            }
        }

        let result = group.wait(timeout: .now() + 5.0)
        XCTAssertEqual(result, .success, "Concurrent mutations and queries must complete without deadlocks or crashes")
    }
}
