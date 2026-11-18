//
//  AdversarialV130Round7BinaryCryptoTests.swift
//  WQGuardCoreTests
//
//  Deep Security Audit Suite (Round 7): Mach-O Loader, Dynamic Fixups, Syscall Phase Alignment & CSBlob DER/XML Hardening.
//

import XCTest
import Foundation
import MachO
import zlib
@testable import WQGuardCore

fileprivate extension Data {
    mutating func r7le16(_ v: UInt16) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r7le32(_ v: UInt32) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r7le64(_ v: UInt64) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r7be32(_ v: UInt32) { var x = v.bigEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
}

final class AdversarialV130Round7BinaryCryptoTests: XCTestCase {

    private static let svcWord: UInt32 = 0xD400_1001
    private static let nopWord: UInt32 = 0xD503_201F
    private static let retWord: UInt32 = 0xD65F_03C0

    private var tempURLs: [URL] = []

    override func setUp() {
        super.setUp()
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
    }

    override func tearDown() {
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
        for u in tempURLs {
            try? FileManager.default.removeItem(at: u)
        }
        tempURLs.removeAll()
        super.tearDown()
    }

    private func makeTempURL(_ name: String) -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("r7_\(UUID().uuidString)_\(name)")
        tempURLs.append(u)
        return u
    }

    private static func zlibCompress(_ raw: Data) -> Data {
        var strm = z_stream()
        guard deflateInit_(&strm, Z_DEFAULT_COMPRESSION, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            return Data()
        }
        defer { deflateEnd(&strm) }
        var out = [UInt8](repeating: 0, count: Int(deflateBound(&strm, uLong(raw.count))) + 32)
        let cap = out.count
        raw.withUnsafeBytes { inPtr in
            out.withUnsafeMutableBufferPointer { outPtr in
                strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
                strm.avail_in = uInt(raw.count)
                strm.next_out = outPtr.baseAddress
                strm.avail_out = uInt(cap)
                _ = deflate(&strm, Z_FINISH)
            }
        }
        return Data(out[0..<(cap - Int(strm.avail_out))])
    }

    // MARK: - 1. Real Clang ARM64 Binary with Zeroed LC_SYMTAB + LC_DYLD_CHAINED_FIXUPS

    func test_r7_realClangArm64Binary_zeroedSymtab_chainedFixupsStillDetectsPrivateImports() throws {
        let clangPath = "/usr/bin/clang"
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: clangPath), "clang not available")

        let cSource = """
        #include <dlfcn.h>
        extern void \(IOCTokenArmor.tCqCreate)(void);
        extern void \(IOCTokenArmor.tCqCopyToken)(void);
        __attribute__((used)) void *wq_test_entry(void) {
            \(IOCTokenArmor.tCqCreate)();
            \(IOCTokenArmor.tCqCopyToken)();
            return dlsym(RTLD_DEFAULT, "malloc");
        }
        """
        let srcURL = makeTempURL("chained_probe.c")
        let dylibURL = makeTempURL("libchained_probe.dylib")
        try cSource.write(to: srcURL, atomically: true, encoding: .utf8)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: clangPath)
        proc.arguments = [
            "-arch", "arm64",
            "-dynamiclib",
            "-O1",
            "-Wl,-fixup_chains",
            "-Wl,-U,_\(IOCTokenArmor.tCqCreate)",
            "-Wl,-U,_\(IOCTokenArmor.tCqCopyToken)",
            srcURL.path,
            "-o", dylibURL.path
        ]
        let errPipe = Pipe()
        proc.standardError = errPipe
        try proc.run()
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else {
            let errText = String(decoding: errPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            XCTFail("clang compilation failed: \(errText)")
            return
        }

        var machoBytes = try Data(contentsOf: dylibURL)
        let origParsed = try MachOParser.shared.parse(data: machoBytes)
        XCTAssertFalse(origParsed.dynamicImportSymbols.isEmpty, "Compiled ARM64 dylib must emit dynamic fixup/bind imports")

        // Wipe LC_SYMTAB completely (nsyms = 0, strsize = 0, and scrub traditional symtab/strtab payload bytes)
        let ncmds = Int(machoBytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self) })
        var cursor = 32
        var wipedSymtab = false
        for _ in 0..<ncmds {
            let cmd = machoBytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor, as: UInt32.self) }
            let cmdsize = Int(machoBytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 4, as: UInt32.self) })
            if cmd == UInt32(LC_SYMTAB) && cmdsize >= 24 {
                let symOff = Int(machoBytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 8, as: UInt32.self) })
                let nSyms = Int(machoBytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 12, as: UInt32.self) })
                let strOff = Int(machoBytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 16, as: UInt32.self) })
                let strSize = Int(machoBytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 20, as: UInt32.self) })
                if symOff > 0 && symOff + nSyms * 16 <= machoBytes.count {
                    machoBytes.resetBytes(in: symOff..<(symOff + nSyms * 16))
                }
                if strOff > 0 && strOff + strSize <= machoBytes.count {
                    machoBytes.resetBytes(in: strOff..<(strOff + strSize))
                }
                var zero: UInt32 = 0
                Swift.withUnsafeBytes(of: &zero) { z in
                    machoBytes.replaceSubrange((cursor + 8)..<(cursor + 12), with: z)
                    machoBytes.replaceSubrange((cursor + 12)..<(cursor + 16), with: z)
                    machoBytes.replaceSubrange((cursor + 16)..<(cursor + 20), with: z)
                    machoBytes.replaceSubrange((cursor + 20)..<(cursor + 24), with: z)
                }
                wipedSymtab = true
            }
            cursor += cmdsize
        }
        XCTAssertTrue(wipedSymtab, "Must locate and zero LC_SYMTAB")

        let strippedParsed = try MachOParser.shared.parse(data: machoBytes)
        XCTAssertEqual(strippedParsed.symtab?.nsyms, 0)
        XCTAssertTrue(strippedParsed.symbols.contains("_\(IOCTokenArmor.tCqCreate)"))
        XCTAssertTrue(strippedParsed.symbols.contains("_\(IOCTokenArmor.tCqCopyToken)"))

        let finding = try MachOScanner.shared.scan(
            binaryData: machoBytes,
            context: .init(bundleId: "com.r7.stripped.chained", appGroups: ["group.com.r7.test"])
        )
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == IOCTokenArmor.tCqCreate })
        XCTAssertTrue(finding.indicators.contains { $0.signature == IOCTokenArmor.tCqCopyToken })
    }

    // MARK: - 2. Chained Fixups Formats 1/2/3 + Zlib Symbol Pool + LC_DYLD_INFO_ONLY Opcode Stream

    private func buildCustomCommandMachO(loadCommands: [Data], payloadAt0x400: Data, totalSize: Int = 0x1000) -> Data {
        var cmdsBlob = Data()
        for lc in loadCommands { cmdsBlob.append(lc) }

        var bin = Data()
        bin.r7le32(MH_MAGIC_64)
        bin.r7le32(UInt32(bitPattern: CPU_TYPE_ARM64))
        bin.r7le32(UInt32(bitPattern: CPU_SUBTYPE_ARM64_ALL))
        bin.r7le32(UInt32(MH_EXECUTE))
        bin.r7le32(UInt32(loadCommands.count))
        bin.r7le32(UInt32(cmdsBlob.count))
        bin.r7le32(0)
        bin.r7le32(0)
        bin.append(cmdsBlob)
        if bin.count < totalSize {
            bin.append(Data(repeating: 0, count: totalSize - bin.count))
        }
        bin.replaceSubrange(0x400..<(0x400 + payloadAt0x400.count), with: payloadAt0x400)
        return bin
    }

    func test_r7_chainedFixupsFormats1_2_3_zlibSymbols_andMalformedBounds() throws {
        let sym1 = "_\(IOCTokenArmor.tFsgetpath)"
        let sym2 = "_\(IOCTokenArmor.tCMSessionSetProp)"
        var rawPool = Data([0])
        let off1 = UInt32(rawPool.count)
        rawPool.append(Data(sym1.utf8)); rawPool.append(0)
        let off2 = UInt32(rawPool.count)
        rawPool.append(Data(sym2.utf8)); rawPool.append(0)

        for format in [UInt32(1), UInt32(2), UInt32(3)] {
            for useZlib in [false, true] {
                var importsTable = Data()
                switch format {
                case 1:
                    importsTable.r7le32((off1 << 9) | 1)
                    importsTable.r7le32((off2 << 9) | 1)
                case 2:
                    importsTable.r7le32((off1 << 9) | 1); importsTable.r7le32(0)
                    importsTable.r7le32((off2 << 9) | 1); importsTable.r7le32(0)
                default:
                    importsTable.r7le64((UInt64(off1) << 32) | 1); importsTable.r7le64(0)
                    importsTable.r7le64((UInt64(off2) << 32) | 1); importsTable.r7le64(0)
                }

                let encodedPool = useZlib ? Self.zlibCompress(rawPool) : rawPool
                var fixupPayload = Data()
                let importsOff: UInt32 = 28
                let symbolsOff: UInt32 = importsOff + UInt32(importsTable.count)
                fixupPayload.r7le32(0) // fixups_version
                fixupPayload.r7le32(0) // starts_offset
                fixupPayload.r7le32(importsOff)
                fixupPayload.r7le32(symbolsOff)
                fixupPayload.r7le32(2) // imports_count
                fixupPayload.r7le32(format)
                fixupPayload.r7le32(useZlib ? 1 : 0)
                fixupPayload.append(importsTable)
                fixupPayload.append(encodedPool)

                var lcFixups = Data()
                lcFixups.r7le32(0x8000_0034) // LC_DYLD_CHAINED_FIXUPS
                lcFixups.r7le32(16)
                lcFixups.r7le32(0x400)
                lcFixups.r7le32(UInt32(fixupPayload.count))

                let bin = buildCustomCommandMachO(loadCommands: [lcFixups], payloadAt0x400: fixupPayload)
                let parsed = try MachOParser.shared.parse(data: bin)
                XCTAssertTrue(parsed.symbols.contains(sym1), "Format \(format) zlib=\(useZlib) missing \(sym1)")
                XCTAssertTrue(parsed.symbols.contains(sym2), "Format \(format) zlib=\(useZlib) missing \(sym2)")
                let finding = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.r7.fmt.\(format)"))
                XCTAssertEqual(finding.riskTier, .highRisk)
            }
        }

        // Malformed chained fixups with OOB imports_offset / huge imports_count must not trap or OOM
        var badFixup = Data()
        badFixup.r7le32(0); badFixup.r7le32(0); badFixup.r7le32(0xFFFF_FFF0); badFixup.r7le32(28)
        badFixup.r7le32(0x7FFF_FFFF); badFixup.r7le32(1); badFixup.r7le32(1)
        var lcBad = Data()
        lcBad.r7le32(0x8000_0034); lcBad.r7le32(16); lcBad.r7le32(0x400); lcBad.r7le32(UInt32(badFixup.count))
        let badBin = buildCustomCommandMachO(loadCommands: [lcBad], payloadAt0x400: badFixup)
        XCTAssertNoThrow(try MachOParser.shared.parse(data: badBin))
    }

    func test_r7_dyldInfoOnly_bindWeakLazyStreams_andOverflowingULEB128() throws {
        // bind stream: opcode 0x40 (SET_SYMBOL_TRAILING_FLAGS_IMM) + "_fsgetpath\0" + 0x90 (DO_BIND) + 0x00 (DONE)
        var bindStream = Data([0x40])
        bindStream.append(Data("_\(IOCTokenArmor.tFsgetpath)".utf8))
        bindStream.append(contentsOf: [0x00, 0x90, 0x00])

        // lazy_bind stream: opcode 0x72 (SET_SEGMENT_AND_OFFSET_ULEB) + 1-byte ULEB(0x10) + 0x40 + "_CMSessionSetProperty\0" + 0x90 + 0x00
        var lazyStream = Data([0x72, 0x10, 0x40])
        lazyStream.append(Data("_\(IOCTokenArmor.tCMSessionSetProp)".utf8))
        lazyStream.append(contentsOf: [0x00, 0x90, 0x00])

        // weak_bind stream with malformed 12-byte non-terminating ULEB128 after a valid symbol -> must extract valid symbol and stop cleanly
        var weakStream = Data([0x40])
        weakStream.append(Data("_\(IOCTokenArmor.tCqCopyToken)".utf8))
        weakStream.append(contentsOf: [0x00, 0x80]) // ADD_ADDR_ULEB followed by 12 continuation bytes
        weakStream.append(contentsOf: [UInt8](repeating: 0x81, count: 12))

        var payload = Data()
        let bindOff = UInt32(0x400)
        payload.append(bindStream)
        let weakOff = bindOff + UInt32(payload.count)
        payload.append(weakStream)
        let lazyOff = bindOff + UInt32(payload.count)
        payload.append(lazyStream)

        var lcDyld = Data()
        lcDyld.r7le32(0x8000_0022) // LC_DYLD_INFO_ONLY
        lcDyld.r7le32(48)
        lcDyld.r7le32(0); lcDyld.r7le32(0) // rebase
        lcDyld.r7le32(bindOff); lcDyld.r7le32(UInt32(bindStream.count))
        lcDyld.r7le32(weakOff); lcDyld.r7le32(UInt32(weakStream.count))
        lcDyld.r7le32(lazyOff); lcDyld.r7le32(UInt32(lazyStream.count))
        lcDyld.r7le32(0); lcDyld.r7le32(0) // export

        let bin = buildCustomCommandMachO(loadCommands: [lcDyld], payloadAt0x400: payload)
        let parsed = try MachOParser.shared.parse(data: bin)
        XCTAssertTrue(parsed.symbols.contains("_\(IOCTokenArmor.tFsgetpath)"))
        XCTAssertTrue(parsed.symbols.contains("_\(IOCTokenArmor.tCMSessionSetProp)"))
        XCTAssertTrue(parsed.symbols.contains("_\(IOCTokenArmor.tCqCopyToken)"))

        let finding = try MachOScanner.shared.scan(
            binaryData: bin,
            context: .init(bundleId: "com.r7.dyldinfo", appGroups: ["group.com.r7.dyld"])
        )
        XCTAssertEqual(finding.riskTier, .highRisk)
    }

    // MARK: - 3. Duplicate LC_SYMTAB / LC_CODE_SIGNATURE / LC_ENCRYPTION_INFO_64 & 32-in-64 Smuggling

    func test_r7_duplicateSymtab_duplicateCodeSignature_andMultiEncryptionRangeIntersection() throws {
        // 1. Two LC_SYMTAB commands: first has 0 symbols, second holds container_query_create
        var symPayload = Data([0])
        let strIdx = UInt32(symPayload.count)
        symPayload.append(Data("_\(IOCTokenArmor.tCqCreate)".utf8))
        symPayload.append(0)
        while symPayload.count % 8 != 0 { symPayload.append(0) }
        let nlistOff = 0x400 + symPayload.count
        // nlist_64: n_strx(4), n_type(1), n_sect(1), n_desc(2), n_value(8)
        symPayload.r7le32(strIdx)
        symPayload.append(contentsOf: [0x01, 0x00, 0x00, 0x00])
        symPayload.r7le64(0)

        var lcSymEmpty = Data()
        lcSymEmpty.r7le32(UInt32(LC_SYMTAB)); lcSymEmpty.r7le32(24)
        lcSymEmpty.r7le32(0); lcSymEmpty.r7le32(0); lcSymEmpty.r7le32(0); lcSymEmpty.r7le32(0)

        var lcSymReal = Data()
        lcSymReal.r7le32(UInt32(LC_SYMTAB)); lcSymReal.r7le32(24)
        lcSymReal.r7le32(UInt32(nlistOff)); lcSymReal.r7le32(1)
        lcSymReal.r7le32(0x400); lcSymReal.r7le32(UInt32(nlistOff - 0x400))

        let dualSymBin = buildCustomCommandMachO(loadCommands: [lcSymEmpty, lcSymReal], payloadAt0x400: symPayload)
        let dualSymParsed = try MachOParser.shared.parse(data: dualSymBin)
        XCTAssertEqual(dualSymParsed.symtabs.count, 2)
        XCTAssertTrue(dualSymParsed.symbols.contains("_\(IOCTokenArmor.tCqCreate)"))

        // 2. Two LC_ENCRYPTION_INFO_64 commands: [cryptid=0, cryptid=1 covering entire file 0..0x1000] + svc #0x80 at 0x400
        var lcSeg = Data()
        lcSeg.r7le32(UInt32(LC_SEGMENT_64)); lcSeg.r7le32(72)
        var segName = Array("__TEXT".utf8); segName += [UInt8](repeating: 0, count: 16 - segName.count)
        lcSeg.append(contentsOf: segName)
        lcSeg.r7le64(0x1_0000_0000); lcSeg.r7le64(0x1000)
        lcSeg.r7le64(0); lcSeg.r7le64(0x1000)
        lcSeg.r7le32(0x05); lcSeg.r7le32(0x05) // r-x
        lcSeg.r7le32(0); lcSeg.r7le32(0)

        var lcEnc0 = Data()
        lcEnc0.r7le32(UInt32(LC_ENCRYPTION_INFO_64)); lcEnc0.r7le32(24)
        lcEnc0.r7le32(0); lcEnc0.r7le32(0); lcEnc0.r7le32(0); lcEnc0.r7le32(0)

        var lcEncFull = Data()
        lcEncFull.r7le32(UInt32(LC_ENCRYPTION_INFO_64)); lcEncFull.r7le32(24)
        lcEncFull.r7le32(0); lcEncFull.r7le32(0x1000); lcEncFull.r7le32(1); lcEncFull.r7le32(0)

        var svcBytes = Data(); svcBytes.r7le32(Self.svcWord); svcBytes.r7le32(Self.retWord)
        let dualEncBin = buildCustomCommandMachO(loadCommands: [lcSeg, lcEnc0, lcEncFull], payloadAt0x400: svcBytes)
        let dualEncParsed = try MachOParser.shared.parse(data: dualEncBin)
        XCTAssertFalse(dualEncParsed.isFairPlayEncrypted, "cryptid=0 command alongside full-file cryptid=1 must resolve to unencrypted")
        XCTAssertEqual(dualEncParsed.directSyscallCount, 1)

        // Disjoint cryptid=1 commands ([0x100..0x200] and [0x300..0x900]) -> intersection is empty -> unencrypted, svc @ 0x400 caught
        var lcEncDisjointA = Data()
        lcEncDisjointA.r7le32(UInt32(LC_ENCRYPTION_INFO_64)); lcEncDisjointA.r7le32(24)
        lcEncDisjointA.r7le32(0x100); lcEncDisjointA.r7le32(0x100); lcEncDisjointA.r7le32(1); lcEncDisjointA.r7le32(0)
        var lcEncDisjointB = Data()
        lcEncDisjointB.r7le32(UInt32(LC_ENCRYPTION_INFO_64)); lcEncDisjointB.r7le32(24)
        lcEncDisjointB.r7le32(0x300); lcEncDisjointB.r7le32(0x600); lcEncDisjointB.r7le32(1); lcEncDisjointB.r7le32(0)
        let disjointEncBin = buildCustomCommandMachO(loadCommands: [lcSeg, lcEncDisjointA, lcEncDisjointB], payloadAt0x400: svcBytes)
        XCTAssertEqual(try MachOParser.shared.parse(data: disjointEncBin).directSyscallCount, 1)

        // 3. 32-bit LC_ENCRYPTION_INFO (0x21) inside 64-bit Mach-O must fail closed with malformedCommand
        var lcEnc32In64 = Data()
        lcEnc32In64.r7le32(UInt32(LC_ENCRYPTION_INFO)); lcEnc32In64.r7le32(20)
        lcEnc32In64.r7le32(0x400); lcEnc32In64.r7le32(0x400); lcEnc32In64.r7le32(1)
        let badBitnessBin = buildCustomCommandMachO(loadCommands: [lcEnc32In64], payloadAt0x400: svcBytes)
        XCTAssertThrowsError(try MachOParser.shared.parse(data: badBitnessBin)) { err in
            guard case MachOParserError.malformedCommand = err else {
                XCTFail("Expected malformedCommand for 32-bit LC_ENCRYPTION_INFO in 64-bit Mach-O, got \(err)")
                return
            }
        }
    }

    // MARK: - 4. FAT Header cpuType Lie & Corrupted Sibling Slice Detection

    func test_r7_fatHeaderCpuTypeMismatch_andCorruptSiblingSlice_flaggedHighRiskWithoutFalsePositives() throws {
        let cleanArm64 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [Self.nopWord, Self.retWord]
        ))
        let evilArm64 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [Self.svcWord, Self.retWord]
        ))

        // Build FAT container: Slice 0 is valid clean arm64; Slice 1 claims CPU_TYPE_X86_64 in fat_arch but contains ARM64 Mach-O with svc #0x80!
        var fat = Data()
        fat.r7be32(FAT_MAGIC)
        fat.r7be32(2)
        let off0: UInt32 = 0x1000
        let off1: UInt32 = UInt32(0x1000 + ((cleanArm64.count + 0xFFF) & ~0xFFF))
        // Entry 0: legitimate arm64
        fat.r7be32(UInt32(bitPattern: CPU_TYPE_ARM64))
        fat.r7be32(UInt32(bitPattern: CPU_SUBTYPE_ARM64_ALL))
        fat.r7be32(off0); fat.r7be32(UInt32(cleanArm64.count)); fat.r7be32(12)
        // Entry 1: lies as x86_64 while inner header is arm64
        fat.r7be32(UInt32(bitPattern: CPU_TYPE_X86_64))
        fat.r7be32(UInt32(bitPattern: CPU_SUBTYPE_X86_64_ALL))
        fat.r7be32(off1); fat.r7be32(UInt32(evilArm64.count)); fat.r7be32(12)

        let total = Int(off1) + evilArm64.count
        fat.append(Data(repeating: 0, count: total - fat.count))
        fat.replaceSubrange(Int(off0)..<(Int(off0) + cleanArm64.count), with: cleanArm64)
        fat.replaceSubrange(Int(off1)..<(Int(off1) + evilArm64.count), with: evilArm64)

        let details = try MachOScanner.shared.parseMachO(data: fat)
        XCTAssertEqual(details.corruptedSliceCount, 1)
        let finding = MachOScanner.shared.scan(details: details, context: .init(bundleId: "com.r7.fatlie"))
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "CorruptMachO:UnparseableSlice" })

        // Control: valid 2-slice Universal FAT (clean arm64 + clean x86_64) must have corruptedSliceCount == 0 and grade .safe,
        // including when inspecting a single parsed MachOFile slice via parseMachO(file:).
        let validFat = SyntheticMachOGenerator.shared.generateUniversalFAT(configs: [
            .init(arch: .arm64, symbols: ["_main"], textInstructions: [Self.nopWord, Self.retWord]),
            .init(arch: .x86_64, symbols: ["_main"])
        ])
        let validDetails = try MachOScanner.shared.parseMachO(data: validFat)
        XCTAssertEqual(validDetails.corruptedSliceCount, 0)
        XCTAssertEqual(MachOScanner.shared.scan(details: validDetails, context: .init(bundleId: "com.r7.validfat")).riskTier, .safe)

        let singleSlice = try MachOParser.shared.parse(data: validFat)
        let singleSliceDetails = MachOScanner.shared.parseMachO(file: singleSlice)
        XCTAssertEqual(singleSliceDetails.corruptedSliceCount, 0)
    }

    // MARK: - 5. Misaligned Section Offset Phase Shift & Entrypoint in Metadata-Named Section

    func test_r7_misalignedSectionOffsetPhaseShift_andEntryPointInConstSection_detected() throws {
        // 1. Misaligned section header offsets (+1, +2, +3) hiding 4-byte-aligned svc #0x80 at 0x404
        for delta in [1, 2, 3] {
            var lcSeg = Data()
            lcSeg.r7le32(UInt32(LC_SEGMENT_64)); lcSeg.r7le32(72 + 80)
            var segName = Array("__TEXT".utf8); segName += [UInt8](repeating: 0, count: 16 - segName.count)
            lcSeg.append(contentsOf: segName)
            lcSeg.r7le64(0x1_0000_0000); lcSeg.r7le64(0x1000)
            lcSeg.r7le64(0); lcSeg.r7le64(0x1000)
            lcSeg.r7le32(0x05); lcSeg.r7le32(0x05)
            lcSeg.r7le32(1); lcSeg.r7le32(0)

            var sectName = Array("__text".utf8); sectName += [UInt8](repeating: 0, count: 16 - sectName.count)
            lcSeg.append(contentsOf: sectName)
            lcSeg.append(contentsOf: segName)
            lcSeg.r7le64(0x1_0000_0400 &+ UInt64(delta))
            lcSeg.r7le64(16)
            lcSeg.r7le32(UInt32(0x400 + delta))
            lcSeg.r7le32(0)
            lcSeg.r7le32(0); lcSeg.r7le32(0)
            lcSeg.r7le32(UInt32(S_ATTR_PURE_INSTRUCTIONS))
            lcSeg.r7le32(0); lcSeg.r7le32(0); lcSeg.r7le32(0)

            var codeAt0x400 = Data()
            codeAt0x400.r7le32(Self.nopWord)
            codeAt0x400.r7le32(Self.svcWord) // 4-byte aligned at file offset 0x404!
            codeAt0x400.r7le32(Self.retWord)
            codeAt0x400.r7le32(Self.retWord)

            let bin = buildCustomCommandMachO(loadCommands: [lcSeg], payloadAt0x400: codeAt0x400)
            let parsed = try MachOParser.shared.parse(data: bin)
            XCTAssertGreaterThanOrEqual(parsed.directSyscallCount, 1, "Misaligned sect.offset +\(delta) hid aligned svc #0x80")
        }

        // 2. LC_MAIN pointing into __TEXT,__const (a normally-excluded metadata section without instruction attrs)
        var lcSegConst = Data()
        lcSegConst.r7le32(UInt32(LC_SEGMENT_64)); lcSegConst.r7le32(72 + 80)
        var textSeg = Array("__TEXT".utf8); textSeg += [UInt8](repeating: 0, count: 16 - textSeg.count)
        lcSegConst.append(contentsOf: textSeg)
        lcSegConst.r7le64(0x1_0000_0000); lcSegConst.r7le64(0x1000)
        lcSegConst.r7le64(0); lcSegConst.r7le64(0x1000)
        lcSegConst.r7le32(0x05); lcSegConst.r7le32(0x05)
        lcSegConst.r7le32(1); lcSegConst.r7le32(0)

        var constSect = Array("__const".utf8); constSect += [UInt8](repeating: 0, count: 16 - constSect.count)
        lcSegConst.append(contentsOf: constSect)
        lcSegConst.append(contentsOf: textSeg)
        lcSegConst.r7le64(0x1_0000_0400); lcSegConst.r7le64(16)
        lcSegConst.r7le32(0x400); lcSegConst.r7le32(2)
        lcSegConst.r7le32(0); lcSegConst.r7le32(0)
        lcSegConst.r7le32(UInt32(S_REGULAR)) // zero instruction flags!
        lcSegConst.r7le32(0); lcSegConst.r7le32(0); lcSegConst.r7le32(0)

        var lcMain = Data()
        lcMain.r7le32(0x8000_0028) // LC_MAIN
        lcMain.r7le32(24)
        lcMain.r7le64(0x400) // entryoff inside __TEXT,__const!
        lcMain.r7le64(0)

        var svcPayload = Data()
        svcPayload.r7le32(Self.svcWord)
        svcPayload.r7le32(Self.retWord)

        let mainInConstBin = buildCustomCommandMachO(loadCommands: [lcSegConst, lcMain], payloadAt0x400: svcPayload)
        let mainParsed = try MachOParser.shared.parse(data: mainInConstBin)
        XCTAssertEqual(mainParsed.entryPointFileOffsets, [0x400])
        XCTAssertEqual(mainParsed.directSyscallCount, 1, "LC_MAIN targeting __TEXT,__const must be scanned for svc #0x80")
    }

    // MARK: - 6. Single-Primitive Dynamic Symbol Resolution (dlsym RTLD_DEFAULT / CFBundle)

    func test_r7_singlePrimitiveDynamicResolution_caughtWithoutFalsePositives() throws {
        // 1. dlsym(RTLD_DEFAULT, "container_copy_sandbox_token") WITHOUT dlopen -> High Risk
        let dlsymContainerBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main", "_dlsym"],
            textInstructions: [Self.retWord],
            extraCStringLiterals: [IOCTokenArmor.tCqCopyToken]
        ))
        let f1 = try MachOScanner.shared.scan(
            binaryData: dlsymContainerBin,
            context: .init(bundleId: "com.r7.dlsym.container", appGroups: ["group.com.r7.c"])
        )
        XCTAssertEqual(f1.riskTier, .highRisk)
        XCTAssertTrue(f1.indicators.contains { $0.signature == IOCTokenArmor.tCqCopyToken })

        // 2. dlsym(RTLD_DEFAULT, "fsgetpath") with ZERO App Groups -> High Risk
        let dlsymFsgetpathBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main", "_dlsym"],
            textInstructions: [Self.retWord],
            extraCStringLiterals: [IOCTokenArmor.tFsgetpath]
        ))
        let f2 = try MachOScanner.shared.scan(
            binaryData: dlsymFsgetpathBin,
            context: .init(bundleId: "com.r7.dlsym.fsgetpath", appGroups: [])
        )
        XCTAssertEqual(f2.riskTier, .highRisk)
        XCTAssertTrue(f2.evidence.pathEnumerationPresent)

        // 3. Prose message mentioning "(fsgetpath)" alongside _dlsym -> MUST stay .safe (zero FP)
        let proseBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main", "_dlsym"],
            textInstructions: [Self.retWord],
            extraCStringLiterals: ["Status: Checked (\(IOCTokenArmor.tFsgetpath)) in report"]
        ))
        let f3 = try MachOScanner.shared.scan(
            binaryData: proseBin,
            context: .init(bundleId: "com.r7.prose.safe", appGroups: ["group.com.r7.prose"])
        )
        XCTAssertEqual(f3.riskTier, .safe)
        XCTAssertFalse(f3.evidence.pathEnumerationPresent)

        // 4. CFBundleLoadExecutable + private MediaExperience.framework string (0 App Groups, no dlopen/dlsym) -> High Risk
        let cfBundleBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main", "_CFBundleLoadExecutable"],
            textInstructions: [Self.retWord],
            extraCStringLiterals: ["/System/Library/PrivateFrameworks/\(IOCTokenArmor.tMediaExpFw)/MediaExperience"]
        ))
        let f4 = try MachOScanner.shared.scan(
            binaryData: cfBundleBin,
            context: .init(bundleId: "com.r7.cfbundle", appGroups: [])
        )
        XCTAssertEqual(f4.riskTier, .highRisk)

        // 5. XOR-obfuscated strings + _dlsym + _symlink + App Group (no _dlopen) -> Behavioral Tuple High Risk
        let dlsymTupleBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main", "_dlsym", "_symlink"],
            textInstructions: [Self.retWord]
        ))
        let f5 = try MachOScanner.shared.scan(
            binaryData: dlsymTupleBin,
            context: .init(bundleId: "com.r7.dlsym.tuple", appGroups: ["group.com.r7.tuple"])
        )
        XCTAssertEqual(f5.riskTier, .highRisk)
        XCTAssertTrue(f5.indicators.contains { $0.signature == SignatureCatalog.behavioralTupleRule.pattern })
    }

    // MARK: - 7. CSBlob ASN.1 DER 9-Byte Integer Overflow, Trailing-Junk XML & Cross-Type Shadowing

    private func buildDERKeyValue(key: String, valueDER: Data) -> Data {
        let keyBytes = Data(key.utf8)
        var keyTLV = Data([0x0C, UInt8(keyBytes.count)])
        keyTLV.append(keyBytes)
        let innerLen = keyTLV.count + valueDER.count
        var seq = Data([0x30, UInt8(innerLen)])
        seq.append(keyTLV)
        seq.append(valueDER)
        return seq
    }

    private func wrapDEREntitlementsDict(_ pairs: [Data]) -> Data {
        var setContent = Data()
        for p in pairs { setContent.append(p) }
        var setTLV = Data([0x31, UInt8(setContent.count)])
        setTLV.append(setContent)
        // Outer SEQUENCE { INTEGER 1, SET { pairs... } }
        var outerContent = Data([0x02, 0x01, 0x01])
        outerContent.append(setTLV)
        var outerSeq = Data([0x30, UInt8(outerContent.count)])
        outerSeq.append(outerContent)
        return outerSeq
    }

    func test_r7_csBlob_der9ByteInteger2Pow64_trailingNonNullXML_andCrossTypeShadowing() throws {
        // 1. 9-byte DER INTEGER = 2^64 (0x01 followed by eight 0x00 bytes) must NOT left-shift wrap to Int64(0)
        let int2Pow64 = Data([0x02, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let derPayload = wrapDEREntitlementsDict([
            buildDERKeyValue(key: "com.apple.private.security.no-sandbox", valueDER: int2Pow64)
        ])
        let parsedDER = try CSBlobParser.shared.parseDEREntitlements(derPayload)
        let dangerInds = ExpandedThreatCatalog.evaluateDangerousEntitlements(
            bundleId: "com.r7.der.bigint",
            installChannel: .developerSideloaded,
            entitlements: parsedDER,
            hasUnencryptedBinary: true
        )
        XCTAssertTrue(dangerInds.contains { $0.signature == "com.apple.private.security.no-sandbox" },
                      "9-byte DER INTEGER (2^64) wrapped to 0 and suppressed no-sandbox detection")

        // 0-length DER INTEGER (0x02 0x00) must throw malformedDER
        let zeroLenIntDER = wrapDEREntitlementsDict([
            buildDERKeyValue(key: "com.apple.private.security.no-sandbox", valueDER: Data([0x02, 0x00]))
        ])
        XCTAssertThrowsError(try CSBlobParser.shared.parseDEREntitlements(zeroLenIntDER))

        // 2. Slot 5 XML plist followed by non-NUL trailing garbage after </plist>
        let xmlText = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array><string>group.com.r7.trailing</string></array>
        </dict>
        </plist>TRAILING_NON_NUL_JUNK_BYTES
        """
        let xmlDict = try CSBlobParser.shared.parseXMLPlist(Data(xmlText.utf8))
        XCTAssertEqual(CSBlobParser.shared.extractAppGroups(fromPlistDict: xmlDict), ["group.com.r7.trailing"])

        // 3. Cross-type entitlement shadowing across slots/slices: active privileges must never be overwritten by false / 0 / [] / ""
        let baseEnts: [String: Any] = [
            "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"],
            "com.apple.private.security.no-sandbox": true,
            "com.apple.private.security.container-required": false,
            "keychain-access-groups": ["*"]
        ]
        let decoyIncoming: [String: Any] = [
            "com.apple.private.tcc.allow": false,
            "com.apple.private.security.no-sandbox": "",
            "com.apple.private.security.container-required": true,
            "keychain-access-groups": [String]()
        ]
        let merged = CSBlobParser.mergeEntitlementDictionaries(baseEnts, decoyIncoming)
        let eval = ExpandedThreatCatalog.evaluateDangerousEntitlements(
            bundleId: "com.r7.shadow",
            installChannel: .developerSideloaded,
            entitlements: merged,
            hasUnencryptedBinary: true
        )
        let sigs = Set(eval.map(\.signature))
        XCTAssertTrue(sigs.contains("com.apple.private.tcc.allow"))
        XCTAssertTrue(sigs.contains("com.apple.private.security.no-sandbox"))
        XCTAssertTrue(sigs.contains("com.apple.private.security.container-required"))
        XCTAssertTrue(sigs.contains("keychain-access-groups(*)"))
    }

    // MARK: - 8. Unsectioned Entry Segment (maxprot R-X), LC_LAZY_LOAD_DYLIB, Zlib Tail-Bomb & Single-Slice FAT cpuType

    func test_r7_unsectionedEntrySegmentMaxProt_lazyLoadDylib_zlibTailBomb_andSingleParseFatCpuMismatch() throws {
        // 1. Unsectioned __EVIL segment with initprot = VM_PROT_READ (0x01), maxprot = R-X (0x05), targeted by LC_MAIN @ 0x400
        var lcSeg = Data()
        lcSeg.r7le32(UInt32(LC_SEGMENT_64)); lcSeg.r7le32(72)
        var segName = Array("__EVIL".utf8); segName += [UInt8](repeating: 0, count: 16 - segName.count)
        lcSeg.append(contentsOf: segName)
        lcSeg.r7le64(0x1_0000_0000); lcSeg.r7le64(0x1000)
        lcSeg.r7le64(0); lcSeg.r7le64(0x1000)
        lcSeg.r7le32(0x05) // maxprot includes VM_PROT_EXECUTE
        lcSeg.r7le32(0x01) // initprot lacks VM_PROT_EXECUTE
        lcSeg.r7le32(0)    // nsects = 0 (unsectioned!)
        lcSeg.r7le32(0)

        var lcMain = Data()
        lcMain.r7le32(0x8000_0028) // LC_MAIN
        lcMain.r7le32(24)
        lcMain.r7le64(0x400)       // entryoff -> svc #0x80
        lcMain.r7le64(0)

        var svcPayload = Data()
        svcPayload.r7le32(Self.svcWord)
        svcPayload.r7le32(Self.retWord)
        let entryBin = buildCustomCommandMachO(loadCommands: [lcSeg, lcMain], payloadAt0x400: svcPayload)
        let entryParsed = try MachOParser.shared.parse(data: entryBin)
        XCTAssertEqual(entryParsed.directSyscallCount, 1, "Unsectioned segment targeted by LC_MAIN with maxprot R-X must be scanned for svc #0x80")

        // 2. LC_LAZY_LOAD_DYLIB (0x20) linking MediaExperience.framework
        let dylibPath = "/System/Library/PrivateFrameworks/\(IOCTokenArmor.tMediaExpFw)/MediaExperience"
        var dylibPathBytes = Data(dylibPath.utf8); dylibPathBytes.append(0)
        while (24 + dylibPathBytes.count) % 8 != 0 { dylibPathBytes.append(0) }
        var lcLazy = Data()
        lcLazy.r7le32(0x20) // LC_LAZY_LOAD_DYLIB
        lcLazy.r7le32(UInt32(24 + dylibPathBytes.count))
        lcLazy.r7le32(24)   // name.offset
        lcLazy.r7le32(0); lcLazy.r7le32(0x0001_0000); lcLazy.r7le32(0x0001_0000)
        lcLazy.append(dylibPathBytes)

        let lazyBin = buildCustomCommandMachO(loadCommands: [lcLazy], payloadAt0x400: Data([0]))
        let lazyParsed = try MachOParser.shared.parse(data: lazyBin)
        XCTAssertTrue(lazyParsed.linkedDylibs.contains(where: { $0.path == dylibPath }))
        let lazyScan = try MachOScanner.shared.scan(
            binaryData: lazyBin,
            context: .init(bundleId: "com.r7.lazydylib", appGroups: ["group.com.r7.lazy"])
        )
        XCTAssertTrue(lazyScan.indicators.contains { $0.signature.contains(IOCTokenArmor.tMediaExpFw) })

        // 3. LC_DYLD_CHAINED_FIXUPS zlib symbol pool with 18 MB zero-byte tail-bomb (> 16 MB cap) after valid import
        let sym = "_\(IOCTokenArmor.tFsgetpath)"
        var hugePool = Data([0])
        let symOff = UInt32(hugePool.count)
        hugePool.append(Data(sym.utf8)); hugePool.append(0)
        hugePool.append(Data(repeating: 0, count: 18 * 1024 * 1024))
        let compressedHugePool = Self.zlibCompress(hugePool)
        XCTAssertLessThan(compressedHugePool.count, 64 * 1024)

        var importsTable = Data()
        importsTable.r7le32((symOff << 9) | 1)
        var fixupBlob = Data()
        fixupBlob.r7le32(0); fixupBlob.r7le32(0); fixupBlob.r7le32(28); fixupBlob.r7le32(32)
        fixupBlob.r7le32(1); fixupBlob.r7le32(1); fixupBlob.r7le32(1)
        fixupBlob.append(importsTable)
        fixupBlob.append(compressedHugePool)

        var lcFix = Data()
        lcFix.r7le32(0x8000_0034); lcFix.r7le32(16); lcFix.r7le32(0x400); lcFix.r7le32(UInt32(fixupBlob.count))
        let tailBombBin = buildCustomCommandMachO(loadCommands: [lcFix], payloadAt0x400: fixupBlob, totalSize: 0x400 + fixupBlob.count + 64)
        let tailBombParsed = try MachOParser.shared.parse(data: tailBombBin)
        XCTAssertTrue(tailBombParsed.symbols.contains(sym), "Zlib zero-padding tail bomb must not discard prefix imports")

        // 4. MachOParser.parse(data:) single-slice API must enforce fat_arch.cputype == mach_header.cputype
        let x86Slice = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .x86_64,
            symbols: ["_main"],
            textInstructions: [Self.nopWord, Self.retWord]
        ))
        var lyingFat = Data()
        lyingFat.r7be32(0xCAFE_BABE)
        lyingFat.r7be32(1)
        lyingFat.r7be32(UInt32(bitPattern: CPU_TYPE_ARM64)) // claims ARM64 in fat_arch!
        lyingFat.r7be32(0)
        lyingFat.r7be32(0x100)
        lyingFat.r7be32(UInt32(x86Slice.count))
        lyingFat.r7be32(4)
        lyingFat.append(Data(repeating: 0, count: 0x100 - lyingFat.count))
        lyingFat.append(x86Slice)
        XCTAssertThrowsError(try MachOParser.shared.parse(data: lyingFat)) { err in
            guard case MachOParserError.corruptedFatHeader = err else {
                XCTFail("Expected corruptedFatHeader from single-slice parse(data:), got \(err)")
                return
            }
        }
    }

    // MARK: - 9. Partial FairPlay Header Evasion, ObjC NSBundle Dynamic Loader & Case-Insensitive Frameworks

    func test_r7_partialFairPlayHeader_nsBundleObjcDynamicLoader_andCaseInsensitiveFrameworkDetection() throws {
        // 1. Partial FairPlay header (cryptid = 1 covering only 32 bytes @ 0x40..<0x60) on .appStore channel
        //    must still inspect unencrypted __objc_methname, symbols, and C-strings outside encryptedRange!
        let partialBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0x40,
            cryptsize: 0x20,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_\(IOCTokenArmor.tCMSessionSetProp)"],
            textInstructions: [Self.nopWord, Self.retWord],
            customSections: [
                ("__TEXT", "__objc_methname", 0x02, Data("systemPhotoLibrary\0".utf8))
            ],
            extraCStringLiterals: [IOCTokenArmor.tBookDaemon]
        ))

        let partialParsed = try MachOParser.shared.parse(data: partialBin)
        XCTAssertTrue(partialParsed.isFairPlayEncrypted)
        XCTAssertTrue(partialParsed.objcMethodNames.contains("systemPhotoLibrary"),
                      "Unencrypted __objc_methname outside partial encryptedRange must still be extracted")
        let partialFinding = try MachOScanner.shared.scan(
            binaryData: partialBin,
            context: .init(bundleId: "com.r7.partial.fairplay", installChannel: .appStore, appGroups: ["group.com.r7.fp"])
        )
        XCTAssertEqual(partialFinding.riskTier, .highRisk, "Partial FairPlay header must not blind unencrypted IOC scanning")

        // 2. Objective-C NSBundle dynamic loader (bundleWithPath: + load) + dlsym + fsgetpath C-string (no dlopen/CFBundle!)
        //    plus lowercase mediaexperience.framework linkage
        let nsBundleBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/system/library/privateframeworks/\(IOCTokenArmor.tMediaExpFw.lowercased())/mediaexperience"],
            symbols: ["_dlsym", "_objc_msgSend"],
            textInstructions: [Self.nopWord, Self.retWord],
            customSections: [
                ("__TEXT", "__objc_methname", 0x02, Data("bundleWithPath:\0load\0".utf8))
            ],
            extraCStringLiterals: [IOCTokenArmor.tFsgetpath]
        ))
        let nsBundleScan = try MachOScanner.shared.scan(
            binaryData: nsBundleBin,
            context: .init(bundleId: "com.r7.nsbundle.dyn", appGroups: ["group.com.r7.nsb"])
        )
        XCTAssertEqual(nsBundleScan.riskTier, .highRisk)
        XCTAssertTrue(nsBundleScan.indicators.contains { $0.signature.contains(IOCTokenArmor.tFsgetpath) })
        XCTAssertTrue(nsBundleScan.indicators.contains { $0.signature.lowercased().contains("mediaexperience") })
    }

    // MARK: - 10. CSBlob Trailing Duplicate </plist>, Intra-Blob DER Key Shadowing & Heterogeneous EntitlementGating

    func test_r7_csBlob_trailingSecondClosePlist_intraBlobDuplicateDERKeys_andHeterogeneousGating() throws {
        // 1. Slot 5 XML plist followed by trailing garbage containing another literal </plist>
        let trickyXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
        <dict>
            <key>com.apple.private.security.no-sandbox</key>
            <true/>
            <key>com.apple.security.application-groups</key>
            <array><string>group.com.r7.multi.close</string></array>
        </dict>
        </plist>TRAILING_JUNK_WITH_SECOND_</plist>
        """
        let parsedXML = try CSBlobParser.shared.parseXMLPlist(Data(trickyXML.utf8))
        XCTAssertEqual(parsedXML["com.apple.private.security.no-sandbox"] as? Bool, true)
        XCTAssertEqual(CSBlobParser.shared.extractAppGroups(fromPlistDict: parsedXML), ["group.com.r7.multi.close"])

        // 2. Intra-blob duplicate keys inside a single Slot 7 DER SET: [no-sandbox: true, no-sandbox: false]
        let dupDER = wrapDEREntitlementsDict([
            buildDERKeyValue(key: "com.apple.private.security.no-sandbox", valueDER: Data([0x01, 0x01, 0xFF])),
            buildDERKeyValue(key: "com.apple.private.security.no-sandbox", valueDER: Data([0x01, 0x01, 0x00]))
        ])
        let parsedDupDER = try CSBlobParser.shared.parseDEREntitlements(dupDER)
        XCTAssertEqual(parsedDupDER["com.apple.private.security.no-sandbox"] as? Bool, true,
                       "Trailing false duplicate inside the same DER SET must never overwrite true")

        // 3. EntitlementGating.evaluate(entitlements:) with heterogeneous [Any] and scalar String application-groups
        let hetGate = EntitlementGating.evaluate(entitlements: [
            "com.apple.security.application-groups": [99, "group.com.r7.het"] as [Any]
        ])
        XCTAssertTrue(hetGate.shouldProceedToDeepScan)
        XCTAssertEqual(hetGate.appGroups, ["group.com.r7.het"])

        let scalarGate = EntitlementGating.evaluate(entitlements: [
            "com.apple.security.application-groups": "group.com.r7.scalar"
        ])
        XCTAssertTrue(scalarGate.shouldProceedToDeepScan)
        XCTAssertEqual(scalarGate.appGroups, ["group.com.r7.scalar"])
    }
}
