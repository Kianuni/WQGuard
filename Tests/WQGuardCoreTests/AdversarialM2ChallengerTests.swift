//
//  AdversarialM2ChallengerTests.swift
//  WQGuardCoreTests
//
//  Empirical Adversarial Stress Harness for Milestone 2:
//  1. MachOParser:
//     - Corrupt magic bytes, truncated headers, out-of-bounds load command offsets, ncmds integer overflows.
//     - FAT binaries with invalid cputype, overlapping slices, zero-length slices.
//  2. CSBlobParser:
//     - SuperBlob with invalid magic, truncated blob offsets, overlapping slot indices.
//     - ASN.1 DER parser with malformed length octets, indefinite length (0x80), recursion bombs (>32).
//     - Byte-safe reading at odd offsets (1023, 1091, 1527) verifying zero ARM64 unaligned pointer faults.
//

import XCTest
import MachO
import Foundation
@testable import WQGuardCore

final class AdversarialM2ChallengerTests: XCTestCase {

    // MARK: - Section 1: MachOParser Adversarial Challenges

    // 1.1 Corrupt Magic Bytes
    func testMachO_corruptMagicBytes_throwsInvalidMagicOrTooSmall() {
        let corruptMagics: [UInt32] = [
            0x00000000,
            0xdeadbeef,
            0xbaadf00d,
            0x12345678,
            0x7f454c46, // ELF magic "\x7fELF"
            0x00005a4d  // PE DOS header "MZ"
        ]

        for magic in corruptMagics {
            var data = Data()
            var m = magic
            data.append(Data(bytes: &m, count: 4))
            data.append(Data(repeating: 0x00, count: 28)) // pad to 32 bytes

            XCTAssertThrowsError(try MachOParser.parse(data: data), "Expected invalidMagic for 0x\(String(magic, radix: 16))") { error in
                guard let machoError = error as? MachOParserError else {
                    XCTFail("Unexpected error type: \(error)")
                    return
                }
                XCTAssertEqual(machoError, .invalidMagic(magic))
            }
        }
    }

    func testMachO_emptyAndSubFourBytes_throwsFileTooSmall() {
        let lengths = [0, 1, 2, 3]
        for len in lengths {
            let data = Data(repeating: 0xaa, count: len)
            XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
                guard let machoError = error as? MachOParserError else {
                    XCTFail("Unexpected error type: \(error)")
                    return
                }
                XCTAssertEqual(machoError, .fileTooSmall(actual: len, minimum: 4))
            }
        }
    }

    // 1.2 Truncated Headers
    func testMachO_truncatedHeaders_throwsTruncatedHeader() {
        // Thin 32-bit (requires at least 28 bytes)
        let thin32TruncatedLengths = [4, 8, 16, 27]
        for len in thin32TruncatedLengths {
            var data = Data()
            var magic = UInt32(MH_MAGIC)
            data.append(Data(bytes: &magic, count: 4))
            if len > 4 {
                data.append(Data(repeating: 0x00, count: len - 4))
            }
            XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
                guard let machoError = error as? MachOParserError else {
                    XCTFail("Unexpected error type: \(error)")
                    return
                }
                XCTAssertEqual(machoError, .truncatedHeader(expected: 28, actual: len))
            }
        }

        // Thin 64-bit (requires at least 32 bytes)
        let thin64TruncatedLengths = [28, 29, 30, 31]
        for len in thin64TruncatedLengths {
            var data = Data()
            var magic = UInt32(MH_MAGIC_64)
            data.append(Data(bytes: &magic, count: 4))
            data.append(Data(repeating: 0x00, count: len - 4))
            XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
                guard let machoError = error as? MachOParserError else {
                    XCTFail("Unexpected error type: \(error)")
                    return
                }
                XCTAssertEqual(machoError, .truncatedHeader(expected: 32, actual: len))
            }
        }
    }

    // 1.3 Out-of-Bounds Load Command Offsets
    func testMachO_sizeofcmdsOutOfBounds_throwsLoadCommandsOutOfBounds() {
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 1,
            sizeofcmds: 1000, // file has only 32 bytes
            flags: 0,
            reserved: 0
        )
        let data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            XCTAssertEqual(machoError, .loadCommandsOutOfBounds(expectedSize: 1032, actualSize: 32))
        }
    }

    func testMachO_cmdsizeZeroOrUnaligned_throwsInvalidCommandSize() {
        // cmdsize = 0
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 1,
            sizeofcmds: 16,
            flags: 0,
            reserved: 0
        )
        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        var lc = load_command(cmd: UInt32(LC_SEGMENT_64), cmdsize: 0)
        data.append(Data(bytes: &lc, count: MemoryLayout<load_command>.size))
        data.append(Data(repeating: 0, count: 8))

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            if case .invalidCommandSize(let cmd, let sz, _) = machoError {
                XCTAssertEqual(cmd, UInt32(LC_SEGMENT_64))
                XCTAssertEqual(sz, 0)
            } else {
                XCTFail("Expected invalidCommandSize, got \(machoError)")
            }
        }

        // cmdsize unaligned (e.g. 9 bytes, not multiple of 4)
        var dataUnaligned = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        var lcUnaligned = load_command(cmd: UInt32(LC_SEGMENT_64), cmdsize: 9)
        dataUnaligned.append(Data(bytes: &lcUnaligned, count: MemoryLayout<load_command>.size))
        dataUnaligned.append(Data(repeating: 0, count: 8))

        XCTAssertThrowsError(try MachOParser.parse(data: dataUnaligned)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            if case .invalidCommandSize(let cmd, let sz, _) = machoError {
                XCTAssertEqual(cmd, UInt32(LC_SEGMENT_64))
                XCTAssertEqual(sz, 9)
            } else {
                XCTFail("Expected invalidCommandSize, got \(machoError)")
            }
        }
    }

    func testMachO_cmdsizeExtendsBeyondSizeofcmds_throwsCommandOutOfBounds() {
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 1,
            sizeofcmds: 16,
            flags: 0,
            reserved: 0
        )
        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        // cmdsize declared as 32, but sizeofcmds is only 16
        var lc = load_command(cmd: UInt32(LC_SEGMENT_64), cmdsize: 32)
        data.append(Data(bytes: &lc, count: MemoryLayout<load_command>.size))
        data.append(Data(repeating: 0, count: 8))

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            if case .commandOutOfBounds(let cmd, let sz, let cur, let tot) = machoError {
                XCTAssertEqual(cmd, UInt32(LC_SEGMENT_64))
                XCTAssertEqual(sz, 32)
                XCTAssertEqual(cur, 32)
                XCTAssertEqual(tot, 48)
            } else {
                XCTFail("Expected commandOutOfBounds, got \(machoError)")
            }
        }
    }

    func testMachO_symtabOutOfBounds_throwsSymbolTableOutOfBounds() {
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 1,
            sizeofcmds: UInt32(MemoryLayout<symtab_command>.size),
            flags: 0,
            reserved: 0
        )
        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        // symoff = 0x80000000 (OOB)
        var symcmd = symtab_command(
            cmd: UInt32(LC_SYMTAB),
            cmdsize: UInt32(MemoryLayout<symtab_command>.size),
            symoff: 0x8000,
            nsyms: 10,
            stroff: 0x8100,
            strsize: 100
        )
        data.append(Data(bytes: &symcmd, count: MemoryLayout<symtab_command>.size))

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            if case .symbolTableOutOfBounds(let off, _, _) = machoError {
                XCTAssertEqual(off, 0x8000)
            } else {
                XCTFail("Expected symbolTableOutOfBounds, got \(machoError)")
            }
        }
    }

    func testMachO_codeSignatureOutOfBounds_throwsCodeSignatureOutOfBounds() {
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 1,
            sizeofcmds: UInt32(MemoryLayout<linkedit_data_command>.size),
            flags: 0,
            reserved: 0
        )
        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        var cscmd = linkedit_data_command(
            cmd: UInt32(LC_CODE_SIGNATURE),
            cmdsize: UInt32(MemoryLayout<linkedit_data_command>.size),
            dataoff: 0x10000,
            datasize: 0x200
        )
        data.append(Data(bytes: &cscmd, count: MemoryLayout<linkedit_data_command>.size))

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            if case .codeSignatureOutOfBounds(let off, let sz, _) = machoError {
                XCTAssertEqual(off, 0x10000)
                XCTAssertEqual(sz, 0x200)
            } else {
                XCTFail("Expected codeSignatureOutOfBounds, got \(machoError)")
            }
        }
    }

    // 1.4 ncmds Integer Overflows and Boundary Limits
    func testMachO_ncmdsIntegerOverflow_throwsInvalidCommandCount() {
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: UInt32.max, // Integer overflow attempt
            sizeofcmds: 100,
            flags: 0,
            reserved: 0
        )
        let data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size) + Data(repeating: 0, count: 100)

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            XCTAssertEqual(machoError, .invalidCommandCount(ncmds: UInt32.max, sizeofcmds: 100))
        }
    }

    func testMachO_ncmdsExceeds16384SafetyLimit_throwsInvalidCommandCount() {
        let excessiveNcmds: UInt32 = 16385
        let sizeofcmds = excessiveNcmds * 8
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: excessiveNcmds,
            sizeofcmds: sizeofcmds,
            flags: 0,
            reserved: 0
        )
        let data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size) + Data(repeating: 0, count: Int(sizeofcmds))

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            XCTAssertEqual(machoError, .invalidCommandCount(ncmds: excessiveNcmds, sizeofcmds: sizeofcmds))
        }
    }

    func testMachO_zeroCommands_parsesCleanly() throws {
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 0,
            sizeofcmds: 0,
            flags: 0,
            reserved: 0
        )
        let data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        let file = try MachOParser.parse(data: data)
        XCTAssertEqual(file.ncmds, 0)
        XCTAssertEqual(file.segments.count, 0)
        XCTAssertEqual(file.linkedDylibs.count, 0)
        XCTAssertNil(file.symtab)
        XCTAssertNil(file.codeSignature)
    }

    // 1.5 FAT Binaries Adversarial Cases
    func testFAT_zeroSlices_throwsFatBinaryEmpty() {
        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = 0
        var data = Data()
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &nfat, count: 4))

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            XCTAssertEqual(machoError, .fatBinaryEmpty)
        }
    }

    func testFAT_excessiveSliceCount_throwsCorruptedFatHeader() {
        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = UInt32(1025).bigEndian // Exceeds safety limit 1024
        var data = Data()
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &nfat, count: 4))

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            if case .corruptedFatHeader(let reason) = machoError {
                XCTAssertTrue(reason.contains("1024"))
            } else {
                XCTFail("Expected corruptedFatHeader, got \(machoError)")
            }
        }
    }

    func testFAT_sliceOutOfBounds_throwsSliceOutOfBounds() {
        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = UInt32(1).bigEndian
        var data = Data()
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &nfat, count: 4))

        // fat_arch entry: cputype, cpusubtype, offset, size, align
        var arch = fat_arch(
            cputype: CPU_TYPE_ARM64.bigEndian,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
            offset: UInt32(4096).bigEndian, // File is only ~100 bytes!
            size: UInt32(2048).bigEndian,
            align: UInt32(14).bigEndian
        )
        data.append(Data(bytes: &arch, count: MemoryLayout<fat_arch>.size))
        data.append(Data(repeating: 0, count: 50)) // total ~78 bytes

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            if case .sliceOutOfBounds(let off, let sz, let tot) = machoError {
                XCTAssertEqual(off, 4096)
                XCTAssertEqual(sz, 2048)
                XCTAssertEqual(tot, data.count)
            } else {
                XCTFail("Expected sliceOutOfBounds, got \(machoError)")
            }
        }
    }

    func testFAT_invalidCpuType_listsAsUnknownWithoutCrashing() throws {
        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = UInt32(1).bigEndian
        var data = Data()
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &nfat, count: 4))

        let customCpuType: cpu_type_t = 0x70001234
        let customCpuSubtype: cpu_subtype_t = 0x00000001
        var arch = fat_arch(
            cputype: customCpuType.bigEndian,
            cpusubtype: customCpuSubtype.bigEndian,
            offset: UInt32(28).bigEndian,
            size: UInt32(32).bigEndian,
            align: UInt32(2).bigEndian
        )
        data.append(Data(bytes: &arch, count: MemoryLayout<fat_arch>.size)) // 28 bytes header
        data.append(Data(repeating: 0x90, count: 32)) // dummy slice

        let slices = try MachOParser.listSlices(in: data)
        XCTAssertEqual(slices.count, 1)
        XCTAssertEqual(slices[0].cpuType, customCpuType)
        XCTAssertEqual(slices[0].architecture, .unknown(cpuType: customCpuType, cpuSubtype: customCpuSubtype))
    }

    func testFAT_overlappingSlices_handledSafely() throws {
        // Construct a FAT binary where Slice 0 and Slice 1 overlap in byte range
        // Thin Slice 1 (x86_64, 32 bytes) at offset 48, size 32
        // Thin Slice 2 (arm64, 32 bytes) at offset 56 (overlaps with slice 1 by 24 bytes!)
        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = UInt32(2).bigEndian
        var data = Data()
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &nfat, count: 4))

        var arch1 = fat_arch(
            cputype: CPU_TYPE_X86_64.bigEndian,
            cpusubtype: CPU_SUBTYPE_X86_64_ALL.bigEndian,
            offset: UInt32(48).bigEndian,
            size: UInt32(32).bigEndian,
            align: UInt32(2).bigEndian
        )
        var arch2 = fat_arch(
            cputype: CPU_TYPE_ARM64.bigEndian,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
            offset: UInt32(56).bigEndian, // Overlaps arch1 (48..<80 vs 56..<88)
            size: UInt32(32).bigEndian,
            align: UInt32(2).bigEndian
        )
        data.append(Data(bytes: &arch1, count: MemoryLayout<fat_arch>.size))
        data.append(Data(bytes: &arch2, count: MemoryLayout<fat_arch>.size)) // 48 bytes header

        // Add 50 bytes of payload
        var arm64Header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 0,
            sizeofcmds: 0,
            flags: 0,
            reserved: 0
        )
        // Pad 8 bytes then arm64Header
        data.append(Data(repeating: 0xaa, count: 8))
        data.append(Data(bytes: &arm64Header, count: MemoryLayout<mach_header_64>.size)) // at offset 56

        let slices = try MachOParser.listSlices(in: data)
        XCTAssertEqual(slices.count, 2)
        XCTAssertEqual(slices[0].offset, 48)
        XCTAssertEqual(slices[1].offset, 56)

        // Select arm64 slice
        let parsed = try MachOParser.parse(data: data, preferredCpuType: CPU_TYPE_ARM64)
        XCTAssertEqual(parsed.architecture, .arm64)
        XCTAssertEqual(parsed.ncmds, 0)
    }

    func testFAT_zeroLengthSlice_gracefulHandling() {
        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = UInt32(1).bigEndian
        var data = Data()
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &nfat, count: 4))

        var arch = fat_arch(
            cputype: CPU_TYPE_ARM64.bigEndian,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
            offset: UInt32(28).bigEndian,
            size: UInt32(0).bigEndian, // ZERO length
            align: UInt32(2).bigEndian
        )
        data.append(Data(bytes: &arch, count: MemoryLayout<fat_arch>.size))

        // listSlices should succeed and report size 0
        XCTAssertNoThrow(try {
            let slices = try MachOParser.listSlices(in: data)
            XCTAssertEqual(slices.count, 1)
            XCTAssertEqual(slices[0].size, 0)
        }())

        // parse should throw truncatedHeader(expected: 28, actual: 0) rather than crashing
        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
            XCTAssertEqual(machoError, .truncatedHeader(expected: 28, actual: 0))
        }
    }

    // MARK: - Section 2: CSBlobParser Adversarial Challenges

    // 2.1 SuperBlob Invalid Magic
    func testCSBlob_invalidMagic_throwsInvalidSuperBlobMagic() {
        var badMagic: UInt32 = UInt32(0x12345678).bigEndian
        var length: UInt32 = UInt32(32).bigEndian
        var count: UInt32 = UInt32(0).bigEndian
        var data = Data()
        data.append(Data(bytes: &badMagic, count: 4))
        data.append(Data(bytes: &length, count: 4))
        data.append(Data(bytes: &count, count: 4))
        data.append(Data(repeating: 0, count: 20))

        XCTAssertThrowsError(try CSBlobParser.shared.parseSuperBlob(data)) { error in
            guard let csError = error as? CSBlobError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(csError, .invalidSuperBlobMagic(actual: 0x12345678))
        }

        // extractAppGroups convenience API must return false without throwing
        let result = CSBlobParser.shared.extractAppGroups(from: data)
        XCTAssertFalse(result.hasAppGroups)
        XCTAssertTrue(result.appGroups.isEmpty)
    }

    // 2.2 Truncated Blob Offsets & Lengths
    func testCSBlob_superBlobLengthOutOfBounds_throwsSuperBlobLengthOutOfBounds() {
        var magic: UInt32 = CSBlobConstants.superBlobMagic.bigEndian
        var declaredLength: UInt32 = UInt32(5000).bigEndian // Only 16 bytes present
        var count: UInt32 = UInt32(0).bigEndian
        var data = Data()
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &declaredLength, count: 4))
        data.append(Data(bytes: &count, count: 4))
        data.append(Data(repeating: 0, count: 4))

        XCTAssertThrowsError(try CSBlobParser.shared.parseSuperBlob(data)) { error in
            guard let csError = error as? CSBlobError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(csError, .superBlobLengthOutOfBounds(declared: 5000, actual: 16))
        }
    }

    func testCSBlob_truncatedBlobOffset_skippedSafely() throws {
        // SuperBlob declaring 1 slot, but slot offset is beyond SuperBlob boundary
        var magic: UInt32 = CSBlobConstants.superBlobMagic.bigEndian
        var length: UInt32 = UInt32(20).bigEndian
        var count: UInt32 = UInt32(1).bigEndian
        var slotType: UInt32 = CSBlobConstants.slotEntitlements.bigEndian
        var slotOffset: UInt32 = UInt32(9999).bigEndian // OOB offset

        var data = Data()
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &length, count: 4))
        data.append(Data(bytes: &count, count: 4))
        data.append(Data(bytes: &slotType, count: 4))
        data.append(Data(bytes: &slotOffset, count: 4))

        let parsed = try CSBlobParser.shared.parseSuperBlob(data)
        XCTAssertEqual(parsed, .empty)
        XCTAssertFalse(parsed.hasAppGroups)
    }

    // 2.3 Overlapping Slot Indices
    func testCSBlob_overlappingSlotIndices_decodedSafely() throws {
        // Build a SuperBlob where slot 5 (XML) and slot 7 (DER) point to the same valid XML block
        // Parser should safely inspect slot 5, fail or skip slot 7 as non-DER, and successfully extract App Groups!
        let xmlStr = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.adversarial.overlap</string>
            </array>
        </dict>
        </plist>
        """
        let xmlData = xmlStr.data(using: .utf8)!
        let blobLen = 8 + xmlData.count

        var superBlob = Data()
        var sbMagic = CSBlobConstants.superBlobMagic.bigEndian
        let totalLen = 12 + 16 + blobLen
        var sbLen = UInt32(totalLen).bigEndian
        var sbCount = UInt32(2).bigEndian

        superBlob.append(Data(bytes: &sbMagic, count: 4))
        superBlob.append(Data(bytes: &sbLen, count: 4))
        superBlob.append(Data(bytes: &sbCount, count: 4))

        let blobOffset = 12 + 16
        // Slot 5 -> blobOffset
        var s5Type = CSBlobConstants.slotEntitlements.bigEndian
        var s5Off = UInt32(blobOffset).bigEndian
        superBlob.append(Data(bytes: &s5Type, count: 4))
        superBlob.append(Data(bytes: &s5Off, count: 4))

        // Slot 7 -> ALSO blobOffset (overlapping exactly!)
        var s7Type = CSBlobConstants.slotDerEntitlements.bigEndian
        var s7Off = UInt32(blobOffset).bigEndian
        superBlob.append(Data(bytes: &s7Type, count: 4))
        superBlob.append(Data(bytes: &s7Off, count: 4))

        // Entitlements Blob
        var entMagic = CSBlobConstants.entitlementXmlMagic.bigEndian
        var entLen = UInt32(blobLen).bigEndian
        superBlob.append(Data(bytes: &entMagic, count: 4))
        superBlob.append(Data(bytes: &entLen, count: 4))
        superBlob.append(xmlData)

        let parsed = try CSBlobParser.shared.parseSuperBlob(superBlob)
        XCTAssertTrue(parsed.hasAppGroups)
        XCTAssertEqual(parsed.appGroups, ["group.com.adversarial.overlap"])
        // Both slot 5 and slot 7 were processed without crashing; slot 7 decoded as non-empty DER structure with 0 groups, merging to dual
        XCTAssertTrue(parsed.formatUsed == .dual || parsed.formatUsed == .xml)
    }

    // 2.4 ASN.1 DER Parser Adversarial Challenges
    func testASN1_emptyData_throwsMalformedDER() {
        XCTAssertThrowsError(try ASN1DERDecoder.decode(Data())) { error in
            guard let csError = error as? CSBlobError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(csError, .malformedDER(reason: "Empty DER data"))
        }
    }

    func testASN1_indefiniteLength0x80_throwsMalformedDER() {
        // Tag 0x30 (SEQUENCE), Length 0x80 (BER Indefinite length - strictly forbidden in DER!)
        let berData = Data([0x30, 0x80, 0x01, 0x01, 0xff, 0x00, 0x00])

        XCTAssertThrowsError(try ASN1DERDecoder.decode(berData)) { error in
            guard let csError = error as? CSBlobError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            if case .malformedDER(let reason) = csError {
                XCTAssertTrue(reason.contains("indefinite length (0x80) forbidden"))
            } else {
                XCTFail("Expected malformedDER with indefinite length, got \(csError)")
            }
        }
    }

    func testASN1_malformedLengthOctets_throwsMalformedDER() {
        // Length byte 0x85 (5 octets, exceeds maximum 4 octets allowed)
        let badLengthOctets = Data([0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00])
        XCTAssertThrowsError(try ASN1DERDecoder.decode(badLengthOctets)) { error in
            guard let csError = error as? CSBlobError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            if case .malformedDER(let reason) = csError {
                XCTAssertTrue(reason.contains("Invalid DER length octets: 5"))
            } else {
                XCTFail("Expected invalid DER length octets, got \(csError)")
            }
        }

        // Truncated length octets: length byte 0x82 (expects 2 octets, only 1 provided)
        let truncatedLengthOctets = Data([0x30, 0x82, 0x01])
        XCTAssertThrowsError(try ASN1DERDecoder.decode(truncatedLengthOctets)) { error in
            guard let csError = error as? CSBlobError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            if case .malformedDER(let reason) = csError {
                XCTAssertTrue(reason.contains("Truncated DER length octets"))
            } else {
                XCTFail("Expected truncated DER length octets, got \(csError)")
            }
        }

        // Value length extends beyond buffer bound
        let oobValueLength = Data([0x04, 0x7f, 0xaa, 0xbb]) // Declares 127 bytes, only 2 provided
        XCTAssertThrowsError(try ASN1DERDecoder.decode(oobValueLength)) { error in
            guard let csError = error as? CSBlobError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            if case .malformedDER(let reason) = csError {
                XCTAssertTrue(reason.contains("exceeds buffer bound"))
            } else {
                XCTFail("Expected exceeds buffer bound, got \(csError)")
            }
        }
    }

    func testASN1_recursionBombExceeding32_throwsRecursionDepthExceeded() {
        // Construct nested sequences: SEQUENCE { SEQUENCE { ... } }
        // 34 nested sequences: root is depth 0, 33rd child is at depth 33 (> 32)
        var bomb = Data()
        let count = 34
        for d in 0..<count {
            let remaining = (count - d - 1) * 2
            bomb.append(contentsOf: [0x30, UInt8(remaining)])
        }

        XCTAssertThrowsError(try ASN1DERDecoder.decode(bomb, maxDepth: 32)) { error in
            guard let csError = error as? CSBlobError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            if case .malformedDER(let reason) = csError {
                XCTAssertTrue(reason.contains("recursion depth exceeded limit of 32"))
            } else {
                XCTFail("Expected recursion depth exceeded, got \(csError)")
            }
        }

        // Extreme stress: 100 nested sequences must fail gracefully without stack overflow
        var deepBomb = Data()
        for d in 0..<100 {
            let remaining = (100 - d - 1) * 2
            deepBomb.append(contentsOf: [0x30, UInt8(min(remaining, 127))])
        }
        XCTAssertThrowsError(try ASN1DERDecoder.decode(deepBomb, maxDepth: 32))
    }

    func testASN1_validSequenceAtDepth32_succeeds() throws {
        // Exact depth 32 should succeed
        var data = Data()
        let depth = 32
        for d in 0..<depth {
            let remaining = (depth - d - 1) * 2
            data.append(contentsOf: [0x30, UInt8(remaining)])
        }
        let node = try ASN1DERDecoder.decode(data, maxDepth: 32)
        XCTAssertNotNil(node)
    }

    // 2.5 ARM64 Unaligned Memory Access Stress (Odd Offsets 1023, 1091, 1527)
    func testUnalignedMemoryReads_oddOffsets_noFaults() {
        let oddOffsets = [1023, 1091, 1527]
        let bufferSize = 2048

        // Fill buffer with pseudo-random deterministic bytes
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        for i in 0..<bufferSize {
            buffer[i] = UInt8(i & 0xff)
        }

        // Test CSBlobParser.readUInt32BE at odd offsets
        buffer.withUnsafeBytes { raw in
            for offset in oddOffsets {
                let expectedB0 = UInt32(buffer[offset])
                let expectedB1 = UInt32(buffer[offset + 1])
                let expectedB2 = UInt32(buffer[offset + 2])
                let expectedB3 = UInt32(buffer[offset + 3])
                let expectedValue = (expectedB0 << 24) | (expectedB1 << 16) | (expectedB2 << 8) | expectedB3

                guard let readValue = CSBlobParser.readUInt32BE(from: raw, at: offset) else {
                    XCTFail("readUInt32BE returned nil at offset \(offset)")
                    continue
                }
                XCTAssertEqual(readValue, expectedValue, "Unaligned readUInt32BE failed at odd offset \(offset)")
            }
        }

        // Test BinaryReader.readUInt16, readUInt32, readUInt64 at odd offsets
        let reader = BinaryReader(data: Data(buffer))
        for offset in oddOffsets {
            guard let val16 = reader.readUInt16(at: offset),
                  let val32 = reader.readUInt32(at: offset),
                  let val64 = reader.readUInt64(at: offset) else {
                XCTFail("BinaryReader failed unaligned read at offset \(offset)")
                continue
            }
            // Verify byte swapping
            let swapped16 = reader.readUInt16(at: offset, swapped: true)
            let swapped32 = reader.readUInt32(at: offset, swapped: true)
            let swapped64 = reader.readUInt64(at: offset, swapped: true)
            XCTAssertEqual(swapped16, val16.byteSwapped)
            XCTAssertEqual(swapped32, val32.byteSwapped)
            XCTAssertEqual(swapped64, val64.byteSwapped)
        }
    }

    func testCSBlobParser_oddOffsetSubdataSlices_parsesWithoutTrapping() throws {
        let oddOffsets = [1023, 1091, 1527]

        // Create a valid SuperBlob with App Groups
        let xmlStr = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.adversarial.unaligned</string>
            </array>
        </dict>
        </plist>
        """
        let xmlData = xmlStr.data(using: .utf8)!
        let blobLen = 8 + xmlData.count

        var superBlob = Data()
        var sbMagic = CSBlobConstants.superBlobMagic.bigEndian
        let totalLen = 12 + 8 + blobLen
        var sbLen = UInt32(totalLen).bigEndian
        var sbCount = UInt32(1).bigEndian

        superBlob.append(Data(bytes: &sbMagic, count: 4))
        superBlob.append(Data(bytes: &sbLen, count: 4))
        superBlob.append(Data(bytes: &sbCount, count: 4))

        var s5Type = CSBlobConstants.slotEntitlements.bigEndian
        var s5Off = UInt32(12 + 8).bigEndian
        superBlob.append(Data(bytes: &s5Type, count: 4))
        superBlob.append(Data(bytes: &s5Off, count: 4))

        var entMagic = CSBlobConstants.entitlementXmlMagic.bigEndian
        var entLen = UInt32(blobLen).bigEndian
        superBlob.append(Data(bytes: &entMagic, count: 4))
        superBlob.append(Data(bytes: &entLen, count: 4))
        superBlob.append(xmlData)

        for offset in oddOffsets {
            let padding = Data(repeating: 0xcc, count: offset)
            let composite = padding + superBlob
            let oddSlice = composite.subdata(in: offset..<composite.count)

            // Direct parseSuperBlob
            let parsed = try CSBlobParser.shared.parseSuperBlob(oddSlice)
            XCTAssertTrue(parsed.hasAppGroups)
            XCTAssertEqual(parsed.appGroups, ["group.com.adversarial.unaligned"])

            // Infallible extractAppGroups
            let extracted = CSBlobParser.shared.extractAppGroups(from: oddSlice)
            XCTAssertTrue(extracted.hasAppGroups)
            XCTAssertEqual(extracted.appGroups, ["group.com.adversarial.unaligned"])
        }
    }

    func testMachOParser_oddOffsetSubdataSlices_parsesWithoutTrapping() throws {
        let oddOffsets = [1023, 1091, 1527]

        let validMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"]
        ))

        for offset in oddOffsets {
            let padding = Data(repeating: 0xbb, count: offset)
            let composite = padding + validMachO
            let oddSlice = composite.subdata(in: offset..<composite.count)

            let parsed = try MachOParser.parse(data: oddSlice)
            XCTAssertEqual(parsed.architecture, .arm64)
            XCTAssertEqual(parsed.cryptid, 0)
            XCTAssertTrue(parsed.containsSymbol("main"))
        }
    }

    func testCSBlobParser_extractAppGroupsFromMachO_oddOffset_handlesSafely() {
        let oddOffsets = [1023, 1091, 1527]
        let validMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.adversarial.macho.odd"])
        ))

        for offset in oddOffsets {
            let padding = Data(repeating: 0xee, count: offset)
            let composite = padding + validMachO
            let oddSlice = composite.subdata(in: offset..<composite.count)

            let result = CSBlobParser.shared.extractAppGroups(fromMachO: oddSlice)
            XCTAssertTrue(result.hasAppGroups)
            XCTAssertEqual(result.appGroups, ["group.com.adversarial.macho.odd"])
        }
    }

    func testFAT_oddSliceOffset_inMachOData_doesNotTrapOnUnalignedLoad() {
        // Construct FAT binary where ARM64 slice is at odd offset 1023
        var data = Data()
        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = UInt32(1).bigEndian
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &nfat, count: 4))

        let oddSliceOffset: UInt32 = 1023
        let validMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.adversarial.fat.odd"])
        ))

        var arch = fat_arch(
            cputype: CPU_TYPE_ARM64.bigEndian,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
            offset: oddSliceOffset.bigEndian,
            size: UInt32(validMachO.count).bigEndian,
            align: UInt32(0).bigEndian
        )
        data.append(Data(bytes: &arch, count: MemoryLayout<fat_arch>.size))

        // Pad up to 1023
        if data.count < Int(oddSliceOffset) {
            data.append(Data(repeating: 0x55, count: Int(oddSliceOffset) - data.count))
        }
        data.append(validMachO)

        // Now data is a single Data buffer where slice is at offset 1023
        // Test MachOParser: parses correctly using subdata + loadUnaligned
        let parsed = try? MachOParser.parse(data: data)
        XCTAssertNotNil(parsed, "MachOParser should parse FAT binary with slice at odd offset without faulting")
    }

    func testFAT_oddSliceOffset_inMachOData_extractAppGroupsDoesNotTrap() {
        // Construct Universal FAT binary where ARM64 slice is positioned at odd offset 1023
        var data = Data()
        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = UInt32(1).bigEndian
        data.append(Data(bytes: &magic, count: 4))
        data.append(Data(bytes: &nfat, count: 4))

        let oddSliceOffset: UInt32 = 1023
        let validMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.adversarial.fat.odd"])
        ))

        var arch = fat_arch(
            cputype: CPU_TYPE_ARM64.bigEndian,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
            offset: oddSliceOffset.bigEndian,
            size: UInt32(validMachO.count).bigEndian,
            align: UInt32(0).bigEndian
        )
        data.append(Data(bytes: &arch, count: MemoryLayout<fat_arch>.size))

        // Pad with arbitrary bytes up to odd offset 1023
        if data.count < Int(oddSliceOffset) {
            data.append(Data(repeating: 0x55, count: Int(oddSliceOffset) - data.count))
        }
        data.append(validMachO)

        // 1. Verify CSBlobParser.extractAppGroups(fromMachO:) handles odd slice offset without signal 5 SIGTRAP
        let result = CSBlobParser.shared.extractAppGroups(fromMachO: data)
        XCTAssertTrue(result.hasAppGroups, "Should extract app groups from FAT binary with odd slice offset")
        XCTAssertEqual(result.appGroups, ["group.com.adversarial.fat.odd"])

        // 2. Also stress-test multiple non-standard odd offsets: 1091, 1527
        for oddOff in [1091, 1527] {
            var multiData = Data()
            multiData.append(Data(bytes: &magic, count: 4))
            multiData.append(Data(bytes: &nfat, count: 4))
            var multiArch = fat_arch(
                cputype: CPU_TYPE_ARM64.bigEndian,
                cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
                offset: UInt32(oddOff).bigEndian,
                size: UInt32(validMachO.count).bigEndian,
                align: UInt32(0).bigEndian
            )
            multiData.append(Data(bytes: &multiArch, count: MemoryLayout<fat_arch>.size))
            if multiData.count < oddOff {
                multiData.append(Data(repeating: 0x77, count: oddOff - multiData.count))
            }
            multiData.append(validMachO)

            let multiResult = CSBlobParser.shared.extractAppGroups(fromMachO: multiData)
            XCTAssertTrue(multiResult.hasAppGroups)
            XCTAssertEqual(multiResult.appGroups, ["group.com.adversarial.fat.odd"])
        }
    }

    // MARK: - Section 4: Deep Adversarial Empirical Stress Tests for SEC-M2-01

    func testFAT_extremeOddSliceOffsets_extractAppGroupsEmpiricalStress() {
        let extremeOffsets = [31, 63, 127, 255, 511, 1023, 1091, 1527, 2049, 4095, 8191, 16383, 32767, 65535]
        let validMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.adversarial.extreme.odd"])
        ))

        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = UInt32(1).bigEndian

        for oddOff in extremeOffsets {
            var data = Data()
            data.append(Data(bytes: &magic, count: 4))
            data.append(Data(bytes: &nfat, count: 4))

            var arch = fat_arch(
                cputype: CPU_TYPE_ARM64.bigEndian,
                cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
                offset: UInt32(oddOff).bigEndian,
                size: UInt32(validMachO.count).bigEndian,
                align: UInt32(0).bigEndian
            )
            data.append(Data(bytes: &arch, count: MemoryLayout<fat_arch>.size))

            if data.count < oddOff {
                data.append(Data(repeating: 0x33, count: oddOff - data.count))
            }
            data.append(validMachO)

            let result = CSBlobParser.shared.extractAppGroups(fromMachO: data)
            XCTAssertTrue(result.hasAppGroups, "Should extract app groups at odd offset \(oddOff) without faulting")
            XCTAssertEqual(result.appGroups, ["group.com.adversarial.extreme.odd"])
        }
    }

    func testFAT_fallbackScannerPath_corruptLoadCommands_extractAppGroupsEmpiricalStress() {
        // Construct Mach-O where MachOParser.parse will FAIL (corruptSizeOfCmds: 99999),
        // forcing CSBlobParser.extractCodeSignatureSlice fallback scanner to run!
        let oddOffsets = [1023, 1091, 1527, 4095]
        let corruptMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.adversarial.fallback.odd"]),
            corruptSizeOfCmds: 99999
        ))

        // Verify that MachOParser.parse actually throws on this binary
        XCTAssertThrowsError(try MachOParser.parse(data: corruptMachO), "MachOParser should throw on corruptSizeOfCmds")

        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = UInt32(1).bigEndian

        for oddOff in oddOffsets {
            var data = Data()
            data.append(Data(bytes: &magic, count: 4))
            data.append(Data(bytes: &nfat, count: 4))
            var arch = fat_arch(
                cputype: CPU_TYPE_ARM64.bigEndian,
                cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
                offset: UInt32(oddOff).bigEndian,
                size: UInt32(corruptMachO.count).bigEndian,
                align: UInt32(0).bigEndian
            )
            data.append(Data(bytes: &arch, count: MemoryLayout<fat_arch>.size))
            if data.count < oddOff {
                data.append(Data(repeating: 0x66, count: oddOff - data.count))
            }
            data.append(corruptMachO)

            // Even when MachOParser throws, the fallback scanner in CSBlobParser must find LC_CODE_SIGNATURE
            // and extract the app groups without unaligned memory traps!
            let result = CSBlobParser.shared.extractAppGroups(fromMachO: data)
            XCTAssertTrue(result.hasAppGroups, "Fallback scanner should extract app groups at odd offset \(oddOff)")
            XCTAssertEqual(result.appGroups, ["group.com.adversarial.fallback.odd"])
        }
    }

    func testFAT_malformedOddSlices_neverTraps() {
        // Test malformed FAT binaries with odd slice offsets to verify zero traps
        var magic = UInt32(FAT_MAGIC).bigEndian
        var nfat: UInt32 = UInt32(1).bigEndian

        let oddOffsets: [UInt32] = [1023, 1091, 1527, 65535, UInt32.max - 1]

        for oddOff in oddOffsets {
            // Case 1: sliceOff points past EOF
            var data1 = Data()
            data1.append(Data(bytes: &magic, count: 4))
            data1.append(Data(bytes: &nfat, count: 4))
            var arch1 = fat_arch(
                cputype: CPU_TYPE_ARM64.bigEndian,
                cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
                offset: oddOff.bigEndian,
                size: UInt32(100).bigEndian,
                align: UInt32(0).bigEndian
            )
            data1.append(Data(bytes: &arch1, count: MemoryLayout<fat_arch>.size))
            let res1 = CSBlobParser.shared.extractAppGroups(fromMachO: data1)
            XCTAssertFalse(res1.hasAppGroups)
            XCTAssertTrue(res1.appGroups.isEmpty)

            // Case 2: sliceSize is 0
            var data2 = Data()
            data2.append(Data(bytes: &magic, count: 4))
            data2.append(Data(bytes: &nfat, count: 4))
            var arch2 = fat_arch(
                cputype: CPU_TYPE_ARM64.bigEndian,
                cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
                offset: oddOff.bigEndian,
                size: UInt32(0).bigEndian,
                align: UInt32(0).bigEndian
            )
            data2.append(Data(bytes: &arch2, count: MemoryLayout<fat_arch>.size))
            let res2 = CSBlobParser.shared.extractAppGroups(fromMachO: data2)
            XCTAssertFalse(res2.hasAppGroups)
            XCTAssertTrue(res2.appGroups.isEmpty)

            // Case 3: sliceSize is huge (integer overflow in offset + size)
            var data3 = Data()
            data3.append(Data(bytes: &magic, count: 4))
            data3.append(Data(bytes: &nfat, count: 4))
            var arch3 = fat_arch(
                cputype: CPU_TYPE_ARM64.bigEndian,
                cpusubtype: CPU_SUBTYPE_ARM64_ALL.bigEndian,
                offset: oddOff.bigEndian,
                size: (UInt32.max - 10).bigEndian,
                align: UInt32(0).bigEndian
            )
            data3.append(Data(bytes: &arch3, count: MemoryLayout<fat_arch>.size))
            let res3 = CSBlobParser.shared.extractAppGroups(fromMachO: data3)
            XCTAssertFalse(res3.hasAppGroups)
            XCTAssertTrue(res3.appGroups.isEmpty)
        }
    }
}

