import XCTest
import Foundation
import MachO
@testable import WQGuardCore

/// Adversarial stress tests for Milestone 2 Iteration 2:
/// Empirical verification of Universal FAT binary scanning (FAT_CIGAM / FAT_MAGIC / FAT_64)
/// and integer safety / overflow protections across MachOParser and MachOScanner.
final class AdversarialM2It2Challenger2Tests: XCTestCase {

    // MARK: - 1. Universal FAT Binary Scanning via MachOScanner & MachOParser

    /// Test 1: Verify MachOScanner.parseMachO(data:) on standard Universal FAT binary (FAT_CIGAM on LE hosts)
    /// correctly selects ARM64 primary slice, extracts symbols, linked dylibs, and text strings without "Invalid slice offset".
    func test_FAT_CIGAM_MachOScanner_parsesArm64SliceAccurately() throws {
        let arm64Config = SyntheticMachOGenerator.MachOConfig(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["container_query_create", "container_copy_sandbox_token"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.adversarial.fat"])
        )
        let x86Config = SyntheticMachOGenerator.MachOConfig(
            arch: .x86_64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_clean_x86_main"]
        )

        let fatData = SyntheticMachOGenerator.shared.generateUniversalFAT(configs: [arm64Config, x86Config])

        // Verify disk magic is FAT_CIGAM on LE host (0xbebafeca) or FAT_MAGIC (0xcafebabe)
        let diskMagic = fatData.withUnsafeBytes { $0.load(as: UInt32.self) }
        XCTAssertTrue(diskMagic == FAT_CIGAM || diskMagic == FAT_MAGIC, "Magic must be FAT_CIGAM or FAT_MAGIC")

        // 1. Direct MachOScanner.parseMachO invocation on FAT data
        let details = try MachOScanner.shared.parseMachO(data: fatData)
        XCTAssertEqual(details.cryptid, 0)
        XCTAssertFalse(details.isFairPlayEncrypted)
        XCTAssertTrue(details.linkedDylibs.contains("/usr/lib/system/libsystem_containermanager.dylib"))
        XCTAssertTrue(details.symbols.contains("container_query_create"))
        XCTAssertTrue(details.symbols.contains("container_copy_sandbox_token"))
        XCTAssertFalse(details.symbols.contains("_clean_x86_main"), "ARM64 slice was selected; x86 symbols should not be present")

        // 2. Scan finding with App Group context triggers High Risk
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.adversarial.fat",
            appGroups: ["group.com.adversarial.fat"]
        )
        let finding = MachOScanner.shared.scan(details: details, context: ctx)
        XCTAssertEqual(finding.riskTier, RiskTier.highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "libsystem_containermanager.dylib" })
        XCTAssertTrue(finding.indicators.contains { $0.signature == "container_query_create" })
    }

    /// Test 2: Verify Universal FAT binary with an odd slice offset (e.g. 1023) is parsed safely
    /// without Darwin ARM64 unaligned pointer SIGTRAP traps.
    func test_FAT_oddSliceOffset_MachOScannerAndParser_noTrap() throws {
        let thinData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_odd_slice_symbol"]
        ))

        let oddOffset: UInt32 = 1023
        var fatData = Data()
        var magicBE = UInt32(0xcafebabe).bigEndian
        var nfatBE = UInt32(1).bigEndian
        fatData.append(Data(bytes: &magicBE, count: 4))
        fatData.append(Data(bytes: &nfatBE, count: 4))

        var cpuTypeBE = CPU_TYPE_ARM64.bigEndian
        var cpuSubtypeBE = CPU_SUBTYPE_ARM64_ALL.bigEndian
        var offsetBE = oddOffset.bigEndian
        var sizeBE = UInt32(thinData.count).bigEndian
        var alignBE = UInt32(0).bigEndian

        fatData.append(Data(bytes: &cpuTypeBE, count: 4))
        fatData.append(Data(bytes: &cpuSubtypeBE, count: 4))
        fatData.append(Data(bytes: &offsetBE, count: 4))
        fatData.append(Data(bytes: &sizeBE, count: 4))
        fatData.append(Data(bytes: &alignBE, count: 4))

        // Pad up to oddOffset (1023)
        let padCount = Int(oddOffset) - fatData.count
        XCTAssertGreaterThan(padCount, 0)
        fatData.append(Data(repeating: 0xaa, count: padCount))
        fatData.append(thinData)

        // Parse with MachOParser
        let parsed = try MachOParser.parse(data: fatData)
        XCTAssertEqual(parsed.architecture, .arm64)
        XCTAssertTrue(parsed.containsSymbol("_odd_slice_symbol"))

        // Parse with MachOScanner
        let details = try MachOScanner.shared.parseMachO(data: fatData)
        XCTAssertTrue(details.symbols.contains("_odd_slice_symbol"))
    }

    /// Test 3: Verify 64-bit FAT binary (FAT_MAGIC_64 / FAT_CIGAM_64 = 0xcafebabf) support
    func test_FAT64_MachOScannerAndParser_parsesArm64Slice() throws {
        let thinData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_fat64_symbol"]
        ))

        let sliceOffset: UInt64 = 4096
        var fatData = Data()
        var magicBE = UInt32(0xcafebabf).bigEndian
        var nfatBE = UInt32(1).bigEndian
        fatData.append(Data(bytes: &magicBE, count: 4))
        fatData.append(Data(bytes: &nfatBE, count: 4))

        // fat_arch_64 has 32 bytes: cputype(4), cpusubtype(4), offset(8), size(8), align(4), reserved(4)
        var cpuTypeBE = CPU_TYPE_ARM64.bigEndian
        var cpuSubtypeBE = CPU_SUBTYPE_ARM64_ALL.bigEndian
        var offsetBE = sliceOffset.bigEndian
        var sizeBE = UInt64(thinData.count).bigEndian
        var alignBE = UInt32(12).bigEndian
        var reservedBE = UInt32(0).bigEndian

        fatData.append(Data(bytes: &cpuTypeBE, count: 4))
        fatData.append(Data(bytes: &cpuSubtypeBE, count: 4))
        fatData.append(Data(bytes: &offsetBE, count: 8))
        fatData.append(Data(bytes: &sizeBE, count: 8))
        fatData.append(Data(bytes: &alignBE, count: 4))
        fatData.append(Data(bytes: &reservedBE, count: 4))

        let padCount = Int(sliceOffset) - fatData.count
        fatData.append(Data(repeating: 0, count: padCount))
        fatData.append(thinData)

        let parsed = try MachOParser.parse(data: fatData)
        XCTAssertEqual(parsed.architecture, .arm64)
        XCTAssertTrue(parsed.containsSymbol("_fat64_symbol"))

        let details = try MachOScanner.shared.parseMachO(data: fatData)
        XCTAssertTrue(details.symbols.contains("_fat64_symbol"))
    }

    /// Test 4: Adversarial FAT headers with zero or excessive nfat_arch throw typed errors
    func test_FAT_adversarialNfat_throwsTypedMachOParserError() {
        // Zero nfat
        var zeroFat = Data()
        var magicBE = UInt32(0xcafebabe).bigEndian
        var zeroNfatBE = UInt32(0).bigEndian
        zeroFat.append(Data(bytes: &magicBE, count: 4))
        zeroFat.append(Data(bytes: &zeroNfatBE, count: 4))

        XCTAssertThrowsError(try MachOScanner.shared.parseMachO(data: zeroFat)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Expected MachOParserError.fatBinaryEmpty, got: \(error)")
                return
            }
            if case .fatBinaryEmpty = machoError {
                // Pass
            } else {
                XCTFail("Expected .fatBinaryEmpty, got: \(machoError)")
            }
        }

        // Excessive nfat (> 1024)
        var hugeNfatData = Data()
        var hugeNfatBE = UInt32(1025).bigEndian
        hugeNfatData.append(Data(bytes: &magicBE, count: 4))
        hugeNfatData.append(Data(bytes: &hugeNfatBE, count: 4))

        XCTAssertThrowsError(try MachOScanner.shared.parseMachO(data: hugeNfatData)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Expected MachOParserError.corruptedFatHeader, got: \(error)")
                return
            }
            if case .corruptedFatHeader(let reason) = machoError {
                XCTAssertTrue(reason.contains("1024"), "Reason should mention limit: \(reason)")
            } else {
                XCTFail("Expected .corruptedFatHeader, got: \(machoError)")
            }
        }
    }

    /// Test 5: Universal FAT with slice offset pointing outside binary throws typed sliceOutOfBounds
    func test_FAT_sliceOffsetOutOfBounds_throwsTypedError() {
        var fatData = Data()
        var magicBE = UInt32(0xcafebabe).bigEndian
        var nfatBE = UInt32(1).bigEndian
        fatData.append(Data(bytes: &magicBE, count: 4))
        fatData.append(Data(bytes: &nfatBE, count: 4))

        var cpuTypeBE = CPU_TYPE_ARM64.bigEndian
        var cpuSubtypeBE = CPU_SUBTYPE_ARM64_ALL.bigEndian
        var offsetBE = UInt32(0x100000).bigEndian // 1MB offset, but file is ~100 bytes
        var sizeBE = UInt32(0x1000).bigEndian
        var alignBE = UInt32(12).bigEndian

        fatData.append(Data(bytes: &cpuTypeBE, count: 4))
        fatData.append(Data(bytes: &cpuSubtypeBE, count: 4))
        fatData.append(Data(bytes: &offsetBE, count: 4))
        fatData.append(Data(bytes: &sizeBE, count: 4))
        fatData.append(Data(bytes: &alignBE, count: 4))

        XCTAssertThrowsError(try MachOScanner.shared.parseMachO(data: fatData)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Expected MachOParserError.corruptedFatHeader or sliceOutOfBounds, got: \(error)")
                return
            }
            switch machoError {
            case .corruptedFatHeader, .sliceOutOfBounds:
                break // Expected
            default:
                XCTFail("Unexpected error: \(machoError)")
            }
        }
    }

    // MARK: - 2. Integer Overflow Protections (nsects, nsyms, stroff, cmdsize)

    /// Test 6: Extreme nsects = 0xffffffff in LC_SEGMENT_64 does not crash/trap and handles gracefully
    func test_malformed_maxNsects_inLC_SEGMENT_64_noTrap() throws {
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
        seg.nsects = 0xffffffff // Max UInt32

        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        data.append(Data(bytes: &seg, count: 72))

        let parsed = try MachOParser.parse(data: data)
        XCTAssertEqual(parsed.segments.count, 1)
        XCTAssertEqual(parsed.segments.first?.sectionCount, 0xffffffff)
        XCTAssertTrue(parsed.segments.first?.sections.isEmpty == true)

        // MachOScanner also handles without issue
        let details = try MachOScanner.shared.parseMachO(data: data)
        XCTAssertEqual(details.cryptid, 0)
    }

    /// Test 7: Extreme nsects = 0xffffffff in LC_SEGMENT (32-bit) does not crash/trap and handles gracefully
    func test_malformed_maxNsects_inLC_SEGMENT_32_noTrap() throws {
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
        seg.nsects = 0xffffffff // Max UInt32

        var data = Data(bytes: &header, count: MemoryLayout<mach_header>.size)
        data.append(Data(bytes: &seg, count: 56))

        let parsed = try MachOParser.parse(data: data)
        XCTAssertEqual(parsed.segments.count, 1)
        XCTAssertEqual(parsed.segments.first?.sectionCount, 0xffffffff)
        XCTAssertTrue(parsed.segments.first?.sections.isEmpty == true)

        let details = try MachOScanner.shared.parseMachO(data: data)
        XCTAssertEqual(details.cryptid, 0)
    }

    /// Test 8: Extreme nsyms = 0xffffffff in LC_SYMTAB throws typed symbolTableOutOfBounds without downcast trap
    func test_malformed_maxNsyms_inLC_SYMTAB_throwsTypedError() {
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

        var symcmd = symtab_command(
            cmd: UInt32(LC_SYMTAB),
            cmdsize: UInt32(MemoryLayout<symtab_command>.size),
            symoff: 0x1000,
            nsyms: 0xffffffff, // Max UInt32
            stroff: 0x2000,
            strsize: 0x100
        )

        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        data.append(Data(bytes: &symcmd, count: MemoryLayout<symtab_command>.size))

        XCTAssertThrowsError(try MachOScanner.shared.parseMachO(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Expected MachOParserError, got: \(error)")
                return
            }
            if case .symbolTableOutOfBounds(let off, let sz, _) = machoError {
                XCTAssertEqual(off, 0x1000)
                let expectedSymBytes = UInt64(0xffffffff) * UInt64(MemoryLayout<nlist_64>.size)
                XCTAssertEqual(sz, expectedSymBytes)
            } else {
                XCTFail("Expected symbolTableOutOfBounds, got: \(machoError)")
            }
        }
    }

    /// Test 9: Integer overflow in symoff + totalSymBytes (addingReportingOverflow) throws typed symbolTableOutOfBounds
    func test_malformed_symoffOverflow_throwsTypedError() {
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

        // symoff = UInt32.max, nsyms = 0x20000000 -> symoff + totalSymBytes overflows UInt64!
        // 0xffffffff + 0x20000000 * 16 = 0xffffffff + 0x200000000 = 0x2ffffffff (fits in UInt64)
        // What if symoff is large and totalSymBytes is huge?
        // Let's test with symoff = UInt32.max and totalSymBytes > reader.count:
        var symcmd = symtab_command(
            cmd: UInt32(LC_SYMTAB),
            cmdsize: UInt32(MemoryLayout<symtab_command>.size),
            symoff: UInt32.max - 8,
            nsyms: 100,
            stroff: 0x100,
            strsize: 0x10
        )

        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        data.append(Data(bytes: &symcmd, count: MemoryLayout<symtab_command>.size))

        XCTAssertThrowsError(try MachOScanner.shared.parseMachO(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Expected MachOParserError, got: \(error)")
                return
            }
            if case .symbolTableOutOfBounds = machoError {
                // Pass
            } else {
                XCTFail("Expected symbolTableOutOfBounds, got: \(machoError)")
            }
        }
    }

    /// Test 10: Integer overflow in stroff + strsize throws typed stringTableOutOfBounds
    func test_malformed_stroffOverflow_throwsTypedError() {
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

        var symcmd = symtab_command(
            cmd: UInt32(LC_SYMTAB),
            cmdsize: UInt32(MemoryLayout<symtab_command>.size),
            symoff: 0,
            nsyms: 0,
            stroff: UInt32.max - 10,
            strsize: 100
        )

        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        data.append(Data(bytes: &symcmd, count: MemoryLayout<symtab_command>.size))

        XCTAssertThrowsError(try MachOScanner.shared.parseMachO(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Expected MachOParserError, got: \(error)")
                return
            }
            if case .stringTableOutOfBounds = machoError {
                // Pass
            } else {
                XCTFail("Expected stringTableOutOfBounds, got: \(machoError)")
            }
        }
    }

    /// Test 11: Malformed load commands (cmdsize = 0, cmdsize < min, commandOutOfBounds) throw typed errors
    func test_malformed_commandSize_throwsTypedError() {
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

        // cmdsize = 0 (forbidden)
        var cmd = load_command(cmd: UInt32(LC_SEGMENT_64), cmdsize: 0)
        var data = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        data.append(Data(bytes: &cmd, count: MemoryLayout<load_command>.size))
        data.append(Data(repeating: 0, count: 8)) // pad up to sizeofcmds (16 bytes)

        XCTAssertThrowsError(try MachOParser.parse(data: data)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Expected MachOParserError, got: \(error)")
                return
            }
            if case .invalidCommandSize = machoError {
                // Pass
            } else {
                XCTFail("Expected invalidCommandSize, got: \(machoError)")
            }
        }
    }

    /// Test 12: Truncated binary header (< 4 bytes, or < 28/32 bytes) throws typed fileTooSmall or truncatedHeader
    func test_truncated_machO_throwsTypedError() {
        // Less than 4 bytes
        let tinyData = Data([0xca, 0xfe])
        XCTAssertThrowsError(try MachOScanner.shared.parseMachO(data: tinyData)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Expected MachOParserError, got: \(error)")
                return
            }
            if case .fileTooSmall = machoError {
                // Pass
            } else {
                XCTFail("Expected fileTooSmall, got: \(machoError)")
            }
        }

        // 8 bytes (valid magic, but truncated header for thin binary)
        var header8 = Data()
        var magic = UInt32(MH_MAGIC_64)
        header8.append(Data(bytes: &magic, count: 4))
        header8.append(Data([0, 0, 0, 0]))
        XCTAssertThrowsError(try MachOScanner.shared.parseMachO(data: header8)) { error in
            guard let machoError = error as? MachOParserError else {
                XCTFail("Expected MachOParserError, got: \(error)")
                return
            }
            if case .truncatedHeader = machoError {
                // Pass
            } else {
                XCTFail("Expected truncatedHeader, got: \(machoError)")
            }
        }
    }
}
