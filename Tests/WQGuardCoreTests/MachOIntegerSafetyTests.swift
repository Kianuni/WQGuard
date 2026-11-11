import XCTest
import Foundation
import MachO
@testable import WQGuardCore

final class MachOIntegerSafetyTests: XCTestCase {

    // MARK: - 1. LC_SEGMENT_64 Multiplication Overflow Test
    func testMachOParser_segment64_hugeNsectsMultiplicationOverflow_doesNotTrap() throws {
        // Construct synthetic 64-bit Mach-O binary
        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 1,
            sizeofcmds: 72,
            flags: 0,
            reserved: 0
        )

        var seg = segment_command_64()
        seg.cmd = UInt32(LC_SEGMENT_64)
        seg.cmdsize = 72
        // nsects = 0x20000000 -> 0x20000000 * 80 = 42,949,672,960 > UInt32.max
        seg.nsects = 0x20000000

        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        data.append(Data(bytes: &seg, count: 72))

        // On unpatched code, this triggers SIGTRAP (exit code 133).
        // On patched code, parsing succeeds without crash; sections array is empty.
        let parsed = try MachOParser.parse(data: data)
        XCTAssertEqual(parsed.segments.count, 1)
        XCTAssertEqual(parsed.segments.first?.sectionCount, 0x20000000)
        XCTAssertTrue(parsed.segments.first?.sections.isEmpty == true)
    }

    // MARK: - 2. LC_SEGMENT 32-bit Multiplication Overflow Test
    func testMachOParser_segment32_hugeNsectsMultiplicationOverflow_doesNotTrap() throws {
        // Construct synthetic 32-bit Mach-O binary
        var header = mach_header(
            magic: UInt32(MH_MAGIC),
            cputype: CPU_TYPE_ARM,
            cpusubtype: CPU_SUBTYPE_ARM_V7,
            filetype: UInt32(MH_EXECUTE),
            ncmds: 1,
            sizeofcmds: 56,
            flags: 0
        )

        var seg = segment_command()
        seg.cmd = UInt32(LC_SEGMENT)
        seg.cmdsize = 56
        // nsects = 0x20000000 -> 0x20000000 * 68 = 36,507,222,016 > UInt32.max
        seg.nsects = 0x20000000

        var data = Data(bytes: &header, count: MemoryLayout<mach_header>.size)
        data.append(Data(bytes: &seg, count: 56))

        // On unpatched code, this triggers SIGTRAP (exit code 133).
        // On patched code, parsing succeeds without crash; sections array is empty.
        let parsed = try MachOParser.parse(data: data)
        XCTAssertEqual(parsed.segments.count, 1)
        XCTAssertEqual(parsed.segments.first?.sectionCount, 0x20000000)
        XCTAssertTrue(parsed.segments.first?.sections.isEmpty == true)
    }

    // MARK: - 3. Symbol Table Downcast Trap Test
    func testMachOParser_symbolTable_hugeNsyms_throwsOutOfBoundsWithoutDowncastTrap() throws {
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

        // nsyms = 0x20000000 -> totalSymBytes = 0x20000000 * 16 = 8,589,934,592 (> UInt32.max)
        var symcmd = symtab_command(
            cmd: UInt32(LC_SYMTAB),
            cmdsize: UInt32(MemoryLayout<symtab_command>.size),
            symoff: 0x1000,
            nsyms: 0x20000000,
            stroff: 0x2000,
            strsize: 0x100
        )

        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        data.append(Data(bytes: &symcmd, count: MemoryLayout<symtab_command>.size))

        // On unpatched code, downcast UInt32(totalSymBytes) traps with SIGTRAP.
        // On patched code, throws MachOParserError.symbolTableOutOfBounds with size: 8589934592.
        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Expected MachOParserError, got: \(error)")
                return
            }
            if case .symbolTableOutOfBounds(let off, let sz, _) = machoError {
                XCTAssertEqual(off, 0x1000)
                XCTAssertEqual(sz, 8_589_934_592)
            } else {
                XCTFail("Expected symbolTableOutOfBounds error, got: \(machoError)")
            }
        }
    }

    // MARK: - 4. MachOSegment.fileRange Addition Overflow Tests
    func testMachOSegment_fileRange_overflowSafety() {
        // UInt64 addition overflow
        let segOverflow = MachOSegment(
            name: "__TEXT",
            vmAddress: 0,
            vmSize: 0,
            fileOffset: UInt64.max - 10,
            fileSize: 100,
            maxProtection: 7,
            initialProtection: 5,
            sectionCount: 0,
            flags: 0,
            sections: []
        )
        XCTAssertNil(segOverflow.fileRange, "Must return nil safely when fileOffset + fileSize overflows UInt64")

        // Exceeds Int.max
        let segExceedsIntMax = MachOSegment(
            name: "__TEXT",
            vmAddress: 0,
            vmSize: 0,
            fileOffset: UInt64(Int.max) + 1,
            fileSize: 100,
            maxProtection: 7,
            initialProtection: 5,
            sectionCount: 0,
            flags: 0,
            sections: []
        )
        XCTAssertNil(segExceedsIntMax.fileRange, "Must return nil safely when fileOffset exceeds Int.max")

        // Zero fileSize
        let segZero = MachOSegment(
            name: "__TEXT",
            vmAddress: 0,
            vmSize: 0,
            fileOffset: 0x1000,
            fileSize: 0,
            maxProtection: 7,
            initialProtection: 5,
            sectionCount: 0,
            flags: 0,
            sections: []
        )
        XCTAssertNil(segZero.fileRange, "Must return nil when fileSize == 0")

        // Normal valid range
        let segValid = MachOSegment(
            name: "__TEXT",
            vmAddress: 0x1000,
            vmSize: 0x1000,
            fileOffset: 0x1000,
            fileSize: 0x2000,
            maxProtection: 7,
            initialProtection: 5,
            sectionCount: 0,
            flags: 0,
            sections: []
        )
        XCTAssertEqual(segValid.fileRange, 0x1000..<0x3000)
    }

    // MARK: - 5. MachOEncryptionInfo.encryptedRange Addition Overflow Tests
    func testMachOEncryptionInfo_encryptedRange_overflowSafety() {
        // UInt32 addition overflow (0x80000000 + 0x80000000 = 0x100000000)
        let encOverflow = MachOEncryptionInfo(
            cryptoff: 0x80000000,
            cryptsize: 0x80000000,
            cryptid: 1,
            is64Bit: true
        )
        #if arch(arm64) || arch(x86_64)
        // On 64-bit architecture, 4GB fits safely into 64-bit Int
        XCTAssertEqual(encOverflow.encryptedRange, 0x80000000..<0x100000000)
        #else
        // On 32-bit architecture, 4GB exceeds Int32.max -> returns nil safely
        XCTAssertNil(encOverflow.encryptedRange)
        #endif

        // Maximum UInt32 offset + 1 byte
        let encMax = MachOEncryptionInfo(
            cryptoff: UInt32.max,
            cryptsize: 1,
            cryptid: 1,
            is64Bit: true
        )
        #if arch(arm64) || arch(x86_64)
        XCTAssertEqual(encMax.encryptedRange, Int(UInt32.max)..<(Int(UInt32.max) + 1))
        #else
        XCTAssertNil(encMax.encryptedRange)
        #endif

        // Unencrypted (cryptid == 0)
        let encUnencrypted = MachOEncryptionInfo(
            cryptoff: 0x4000,
            cryptsize: 0x4000,
            cryptid: 0,
            is64Bit: true
        )
        XCTAssertNil(encUnencrypted.encryptedRange)

        // Normal valid encryption range
        let encValid = MachOEncryptionInfo(
            cryptoff: 0x4000,
            cryptsize: 0x8000,
            cryptid: 1,
            is64Bit: true
        )
        XCTAssertEqual(encValid.encryptedRange, 0x4000..<0xc000)
    }
}
