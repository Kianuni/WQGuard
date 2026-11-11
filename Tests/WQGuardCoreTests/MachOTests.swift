//
//  MachOTests.swift
//  WQGuardCoreTests
//
//  Comprehensive Unit & Boundary Tests for MachOParser.
//

import XCTest
import MachO
@testable import WQGuardCore

final class MachOTests: XCTestCase {
    private var tempFiles: [URL] = []

    override func tearDown() {
        for url in tempFiles {
            try? FileManager.default.removeItem(at: url)
        }
        tempFiles.removeAll()
        super.tearDown()
    }

    // MARK: - 1. Thin ARM64 Parsing Tests

    func testThinArm64ValidBinary() throws {
        let data = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            weakDylibs: ["/usr/lib/libobjc.A.dylib"],
            symbols: ["_container_query_create", "_sandbox_extension_consume", "_main"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.test.wqguard"])
        ))

        let parsed = try MachOParser.parse(data: data)

        XCTAssertTrue(parsed.is64Bit)
        XCTAssertFalse(parsed.isSwapped)
        XCTAssertEqual(parsed.architecture, .arm64)
        XCTAssertEqual(parsed.cpuType, CPU_TYPE_ARM64)
        XCTAssertEqual(parsed.cryptid, 0)
        XCTAssertFalse(parsed.isFairPlayEncrypted)

        // Segments
        XCTAssertNotNil(parsed.textSegment)
        XCTAssertEqual(parsed.textSegment?.name, "__TEXT")

        // Linked Dylibs
        XCTAssertTrue(parsed.linksContainermanager)
        XCTAssertTrue(parsed.linkedDylibPaths.contains("/usr/lib/system/libsystem_containermanager.dylib"))
        XCTAssertTrue(parsed.linkedDylibPaths.contains("/usr/lib/libobjc.A.dylib"))
        let weakDylib = parsed.linkedDylibs.first { $0.path == "/usr/lib/libobjc.A.dylib" }
        XCTAssertEqual(weakDylib?.isWeak, true)

        // Symbols
        XCTAssertTrue(parsed.containsSymbol("container_query_create"))
        XCTAssertTrue(parsed.containsSymbol("_container_query_create"))
        XCTAssertTrue(parsed.containsSymbol("sandbox_extension_consume"))
        XCTAssertFalse(parsed.containsSymbol("non_existent_symbol"))

        let matched = parsed.findSymbols(matching: ["container_query_create", "dlopen"])
        XCTAssertEqual(matched, ["container_query_create"])

        // Code Signature
        XCTAssertNotNil(parsed.codeSignature)
        XCTAssertGreaterThan(parsed.codeSignature?.datasize ?? 0, 0)
        XCTAssertNotNil(parsed.codeSignatureData)
    }

    func testMultipleSegmentsTextAndLinkedit() throws {
        var cmds = Data()
        var ncmds: UInt32 = 0

        var textSeg = segment_command_64()
        textSeg.cmd = UInt32(LC_SEGMENT_64)
        textSeg.cmdsize = UInt32(MemoryLayout<segment_command_64>.size)
        withUnsafeMutableBytes(of: &textSeg.segname) { ptr in
            _ = "__TEXT".withCString { strncpy(ptr.baseAddress!.assumingMemoryBound(to: CChar.self), $0, 16) }
        }
        textSeg.vmaddr = 0x100000000
        textSeg.vmsize = 0x4000
        textSeg.filesize = 0x4000
        cmds.append(Data(bytes: &textSeg, count: MemoryLayout<segment_command_64>.size))
        ncmds += 1

        var linkeditSeg = segment_command_64()
        linkeditSeg.cmd = UInt32(LC_SEGMENT_64)
        linkeditSeg.cmdsize = UInt32(MemoryLayout<segment_command_64>.size)
        withUnsafeMutableBytes(of: &linkeditSeg.segname) { ptr in
            _ = "__LINKEDIT".withCString { strncpy(ptr.baseAddress!.assumingMemoryBound(to: CChar.self), $0, 16) }
        }
        linkeditSeg.vmaddr = 0x100004000
        linkeditSeg.vmsize = 0x4000
        linkeditSeg.filesize = 0x4000
        cmds.append(Data(bytes: &linkeditSeg, count: MemoryLayout<segment_command_64>.size))
        ncmds += 1

        var header = mach_header_64(
            magic: UInt32(MH_MAGIC_64),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: UInt32(MH_EXECUTE),
            ncmds: ncmds,
            sizeofcmds: UInt32(cmds.count),
            flags: UInt32(MH_NOUNDEFS | MH_DYLDLINK),
            reserved: 0
        )
        var binary = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        binary.append(cmds)

        let parsed = try MachOParser.parse(data: binary)
        XCTAssertEqual(parsed.segments.count, 2)
        XCTAssertNotNil(parsed.textSegment)
        XCTAssertEqual(parsed.textSegment?.name, "__TEXT")
        XCTAssertNotNil(parsed.linkeditSegment)
        XCTAssertEqual(parsed.linkeditSegment?.name, "__LINKEDIT")
    }

    func testThinArm64FairPlayEncrypted() throws {
        let data = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            linkedDylibs: ["/System/Library/Frameworks/UIKit.framework/UIKit"]
        ))

        let parsed = try MachOParser.parse(data: data)

        XCTAssertEqual(parsed.cryptid, 1)
        XCTAssertTrue(parsed.isFairPlayEncrypted)
        XCTAssertNotNil(parsed.encryptionInfo?.encryptedRange)
    }

    // MARK: - 2. Thin 32-bit Architecture Parsing Tests

    private func createSynthetic32BitBinary(
        cpuType: cpu_type_t = CPU_TYPE_ARM,
        cpuSubtype: cpu_subtype_t = CPU_SUBTYPE_ARM_V7,
        dylibPath: String = "/usr/lib/libSystem.B.dylib",
        symbols: [String] = ["_NSLog"]
    ) -> Data {
        var cmds = Data()
        var ncmds: UInt32 = 0

        // 1. LC_SEGMENT (__TEXT)
        var textSeg = segment_command()
        textSeg.cmd = UInt32(LC_SEGMENT)
        textSeg.cmdsize = UInt32(MemoryLayout<segment_command>.size)
        withUnsafeMutableBytes(of: &textSeg.segname) { ptr in
            _ = "__TEXT".withCString { strncpy(ptr.baseAddress!.assumingMemoryBound(to: CChar.self), $0, 16) }
        }
        textSeg.vmaddr = 0x4000
        textSeg.vmsize = 0x4000
        textSeg.fileoff = 0
        textSeg.filesize = 0x4000
        textSeg.maxprot = 7
        textSeg.initprot = 5
        textSeg.nsects = 0
        textSeg.flags = 0
        cmds.append(Data(bytes: &textSeg, count: MemoryLayout<segment_command>.size))
        ncmds += 1

        // 2. LC_LOAD_DYLIB
        var dylibBytes = Array(dylibPath.utf8)
        dylibBytes.append(0)
        let dylibCmdOffset: UInt32 = 24
        let totalCmdSize = UInt32((Int(dylibCmdOffset) + dylibBytes.count + 3) & ~3)
        var dylibCmd = dylib_command(
            cmd: UInt32(LC_LOAD_DYLIB),
            cmdsize: totalCmdSize,
            dylib: dylib(
                name: lc_str(offset: dylibCmdOffset),
                timestamp: 0,
                current_version: 0x00010000,
                compatibility_version: 0x00010000
            )
        )
        var dylibData = Data(bytes: &dylibCmd, count: MemoryLayout<dylib_command>.size)
        dylibData.append(contentsOf: dylibBytes)
        while dylibData.count < Int(totalCmdSize) {
            dylibData.append(0)
        }
        cmds.append(dylibData)
        ncmds += 1

        // 3. LC_SYMTAB
        let symtabPos = cmds.count
        var symtabCmd = symtab_command()
        symtabCmd.cmd = UInt32(LC_SYMTAB)
        symtabCmd.cmdsize = UInt32(MemoryLayout<symtab_command>.size)
        cmds.append(Data(bytes: &symtabCmd, count: MemoryLayout<symtab_command>.size))
        ncmds += 1

        // Header (28 bytes)
        var header = mach_header(
            magic: UInt32(MH_MAGIC),
            cputype: cpuType,
            cpusubtype: cpuSubtype,
            filetype: UInt32(MH_EXECUTE),
            ncmds: ncmds,
            sizeofcmds: UInt32(cmds.count),
            flags: UInt32(MH_NOUNDEFS | MH_DYLDLINK)
        )

        var binary = Data(bytes: &header, count: MemoryLayout<mach_header>.size)
        binary.append(cmds)

        // Align to 4 bytes
        while binary.count % 4 != 0 {
            binary.append(0)
        }

        // Symbol table
        let symoff = UInt32(binary.count)
        var stringTable = Data([0])
        var nlists: [nlist] = []
        for sym in symbols {
            let strx = UInt32(stringTable.count)
            stringTable.append(contentsOf: sym.utf8)
            stringTable.append(0)
            var nl = nlist()
            nl.n_un.n_strx = strx
            nl.n_type = UInt8(N_EXT | N_SECT)
            nl.n_sect = 1
            nl.n_desc = 0
            nl.n_value = 0x4000
            nlists.append(nl)
        }

        for var nl in nlists {
            binary.append(Data(bytes: &nl, count: MemoryLayout<nlist>.size))
        }

        let stroff = UInt32(binary.count)
        binary.append(stringTable)

        // Update symtab_command in place
        let symtabFileOff = MemoryLayout<mach_header>.size + symtabPos
        var updatedSymtab = symtab_command(
            cmd: UInt32(LC_SYMTAB),
            cmdsize: UInt32(MemoryLayout<symtab_command>.size),
            symoff: symoff,
            nsyms: UInt32(symbols.count),
            stroff: stroff,
            strsize: UInt32(stringTable.count)
        )
        withUnsafeBytes(of: &updatedSymtab) { raw in
            binary.replaceSubrange(symtabFileOff..<symtabFileOff + MemoryLayout<symtab_command>.size, with: raw)
        }

        return binary
    }

    func testThin32BitArmv7Parsing() throws {
        let data = createSynthetic32BitBinary(
            cpuType: CPU_TYPE_ARM,
            cpuSubtype: CPU_SUBTYPE_ARM_V7,
            dylibPath: "/usr/lib/libSystem.B.dylib",
            symbols: ["_NSLog"]
        )

        let parsed = try MachOParser.parse(data: data)

        XCTAssertFalse(parsed.is64Bit)
        XCTAssertEqual(parsed.cpuType, CPU_TYPE_ARM)
        XCTAssertEqual(parsed.architecture, .armv7)
        XCTAssertEqual(parsed.cryptid, 0)
        XCTAssertTrue(parsed.containsSymbol("NSLog"))
    }

    // MARK: - 3. Universal FAT Binary Tests

    func testUniversalFATParsingMultipleSlices() throws {
        let fat = SyntheticMachOGenerator.shared.generateUniversalFAT(configs: [
            .init(arch: .arm64, cryptid: 0, linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"]),
            .init(arch: .x86_64, cryptid: 1, linkedDylibs: ["/usr/lib/libSystem.B.dylib"])
        ])

        let slices = try MachOParser.listSlices(in: fat)
        XCTAssertEqual(slices.count, 2)
        XCTAssertTrue(slices.contains { $0.cpuType == CPU_TYPE_ARM64 })
        XCTAssertTrue(slices.contains { $0.cpuType == CPU_TYPE_X86_64 })

        // Primary Slice Parsing
        let parsed = try MachOParser.parse(data: fat)
        XCTAssertEqual(parsed.slicesInContainer.count, 2)

        #if arch(arm64) || os(iOS)
        XCTAssertEqual(parsed.cpuType, CPU_TYPE_ARM64)
        XCTAssertTrue(parsed.linksContainermanager)
        #else
        XCTAssertEqual(parsed.cpuType, CPU_TYPE_X86_64)
        #endif
    }

    func testUniversalFATExplicitSliceSelection() throws {
        let fat = SyntheticMachOGenerator.shared.generateUniversalFAT(configs: [
            .init(arch: .arm64, cryptid: 0, symbols: ["_arm64_entry"]),
            .init(arch: .x86_64, cryptid: 1, symbols: ["_x86_64_entry"])
        ])

        let parsedArm64 = try MachOParser.parse(data: fat, preferredCpuType: CPU_TYPE_ARM64)
        XCTAssertEqual(parsedArm64.cpuType, CPU_TYPE_ARM64)
        XCTAssertTrue(parsedArm64.containsSymbol("arm64_entry"))

        let parsedX86 = try MachOParser.parse(data: fat, preferredCpuType: CPU_TYPE_X86_64)
        XCTAssertEqual(parsedX86.cpuType, CPU_TYPE_X86_64)
        XCTAssertTrue(parsedX86.containsSymbol("x86_64_entry"))
    }

    // MARK: - 4. URL-Based Parsing & Read-Only Invariants

    func testParseFromURLReadOnly() throws {
        let data = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_test_read_only"]
        ))
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: data, prefix: "ro_macho")
        tempFiles.append(url)

        let initialAttributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let initialModDate = initialAttributes[.modificationDate] as? Date

        let parsed = try MachOParser.parse(url: url)
        XCTAssertTrue(parsed.containsSymbol("test_read_only"))

        let postAttributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let postModDate = postAttributes[.modificationDate] as? Date
        XCTAssertEqual(initialModDate, postModDate, "MachOParser must not modify scanned file")
    }

    // MARK: - 5. Boundary & Error Handling Tests (Adversarial Hardening)

    func testErrorZeroByteBinary() {
        XCTAssertThrowsError(try MachOParser.parse(data: Data())) { error in
            guard case MachOParserError.fileTooSmall = error else {
                XCTFail("Expected fileTooSmall error, got \(error)")
                return
            }
        }
    }

    func testErrorTruncatedHeader() {
        let truncated = Data([0xcf, 0xfa, 0xed, 0xfe]) // 4 bytes only
        XCTAssertThrowsError(try MachOParser.parse(data: truncated)) { error in
            guard case MachOParserError.truncatedHeader = error else {
                XCTFail("Expected truncatedHeader error, got \(error)")
                return
            }
        }
    }

    func testErrorInvalidMagic() {
        var badData = Data([0xde, 0xad, 0xbe, 0xef])
        badData.append(Data(repeating: 0, count: 64))
        XCTAssertThrowsError(try MachOParser.parse(data: badData)) { error in
            guard case MachOParserError.invalidMagic(let magic) = error else {
                XCTFail("Expected invalidMagic error, got \(error)")
                return
            }
            XCTAssertEqual(magic, 0xefbeadde)
        }
    }

    func testErrorHugeNCmdsOverflow() {
        let corrupt = SyntheticMachOGenerator.shared.generateThin(config: .init(
            corruptNCmds: 0xffffffff
        ))
        XCTAssertThrowsError(try MachOParser.parse(data: corrupt)) { error in
            guard case MachOParserError.invalidCommandCount = error else {
                XCTFail("Expected invalidCommandCount error, got \(error)")
                return
            }
        }
    }

    func testErrorLoadCommandsExceedFileSize() {
        let corrupt = SyntheticMachOGenerator.shared.generateThin(config: .init(
            corruptSizeOfCmds: 0x00ffffff
        ))
        XCTAssertThrowsError(try MachOParser.parse(data: corrupt)) { error in
            guard case MachOParserError.loadCommandsOutOfBounds = error else {
                XCTFail("Expected loadCommandsOutOfBounds error, got \(error)")
                return
            }
        }
    }

    func testErrorCorruptedFatSliceCount() {
        var fatHeader = Data()
        var magicBE = UInt32(0xcafebabe).bigEndian
        var nfatBE = UInt32(0x00010000).bigEndian // 65,536 slices (exceeds safety limit 1024)
        fatHeader.append(Data(bytes: &magicBE, count: 4))
        fatHeader.append(Data(bytes: &nfatBE, count: 4))

        XCTAssertThrowsError(try MachOParser.parse(data: fatHeader)) { error in
            guard case MachOParserError.corruptedFatHeader = error else {
                XCTFail("Expected corruptedFatHeader error, got \(error)")
                return
            }
        }
    }

    func testErrorFatSlicePointsOutsideFile() {
        var fatData = Data()
        var magicBE = UInt32(0xcafebabe).bigEndian
        var nfatBE = UInt32(1).bigEndian
        fatData.append(Data(bytes: &magicBE, count: 4))
        fatData.append(Data(bytes: &nfatBE, count: 4))

        // Slice pointing at offset 0x100000 with size 0x1000 in a 32-byte file
        var cpuTypeBE = CPU_TYPE_ARM64.bigEndian
        var cpuSubBE = UInt32(0).bigEndian
        var offBE = UInt32(0x100000).bigEndian
        var szBE = UInt32(0x1000).bigEndian
        var alBE = UInt32(12).bigEndian

        fatData.append(Data(bytes: &cpuTypeBE, count: 4))
        fatData.append(Data(bytes: &cpuSubBE, count: 4))
        fatData.append(Data(bytes: &offBE, count: 4))
        fatData.append(Data(bytes: &szBE, count: 4))
        fatData.append(Data(bytes: &alBE, count: 4))

        XCTAssertThrowsError(try MachOParser.parse(data: fatData)) { error in
            guard case MachOParserError.sliceOutOfBounds = error else {
                XCTFail("Expected sliceOutOfBounds error, got \(error)")
                return
            }
        }
    }

    func testTrailingJunkBytesDoesNotBreakParser() throws {
        var data = SyntheticMachOGenerator.shared.generateThin(config: .init(
            symbols: ["_valid_symbol"]
        ))
        data.append(Data(repeating: 0xcc, count: 4096)) // Trailing padding/noise

        let parsed = try MachOParser.parse(data: data)
        XCTAssertTrue(parsed.containsSymbol("valid_symbol"))
    }
}
