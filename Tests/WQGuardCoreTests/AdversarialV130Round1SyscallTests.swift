//
//  AdversarialV130Round1SyscallTests.swift
//  WQGuardCoreTests
//
//  Independent Adversarial Red-Team Challenger (Round 1):
//  ARM64 `svc #0x80` (`0xD4001001`) Direct Syscall Scanner torture suite covering:
//  1. Literal & metadata section false-positive torture + unaligned byte boundaries + other `svc` immediates
//  2. CPU architecture filtering (`x86_64`, `i386`, `armv7`, `armv7s` vs `arm64`, `arm64e`, `arm64_32`)
//  3. Universal FAT (`FAT_MAGIC` & `FAT_MAGIC_64`) multi-slice shadowing (`arm64` + `arm64e` vs `arm64` + `x86_64`)
//  4. Custom / anti-evasion executable sections & spoofed metadata prefixes with instruction attributes
//  5. Fake partial FairPlay encryption headers vs genuine DRM coverage vs zero/overflow `cryptsize`/`cryptoff`
//  6. DoS (50,000 instructions < 1s), 4GB `S_ZEROFILL`, and trailing-byte/truncated-section bounds stress
//  7. Layer 1 fast-path pre-gating bypass (0 App Groups) & `WhitelistEngine` anti-spoofing across all scanners
//

import XCTest
import Foundation
import MachO
@testable import WQGuardCore

final class AdversarialV130Round1SyscallTests: XCTestCase {

    private static let svc0x80: UInt32 = 0xD400_1001
    private static let svc0x80Bytes = Data([0x01, 0x10, 0x00, 0xD4])
    private static let nopInsn: UInt32 = 0xD503_201F
    private static let retInsn: UInt32 = 0xD65F_03C0

    private var tempURLs: [URL] = []

    override func setUp() {
        super.setUp()
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
    }

    override func tearDown() {
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
        for url in tempURLs {
            try? FileManager.default.removeItem(at: url)
        }
        tempURLs.removeAll()
        super.tearDown()
    }

    @discardableResult
    private func trackTemp(_ url: URL) -> URL {
        tempURLs.append(url)
        return url
    }

    // MARK: - Local Mach-O / FAT / Bundle / IPA Builders (Test-Only)

    private struct CustomSectionSpec {
        let segName: String
        let sectName: String
        let address: UInt64
        let sizeOverride: UInt64?
        let offsetOverride: UInt32?
        let flags: UInt32
        let payload: Data

        init(
            segName: String,
            sectName: String,
            address: UInt64 = 0,
            sizeOverride: UInt64? = nil,
            offsetOverride: UInt32? = nil,
            flags: UInt32,
            payload: Data
        ) {
            self.segName = segName
            self.sectName = sectName
            self.address = address
            self.sizeOverride = sizeOverride
            self.offsetOverride = offsetOverride
            self.flags = flags
            self.payload = payload
        }
    }

    private struct RawSegmentSpec {
        let name: String
        let initprot: Int32
        let maxprot: Int32
        let sections: [CustomSectionSpec]
    }

    private func copyFixed16(_ value: String, into buffer: UnsafeMutableRawBufferPointer) {
        buffer.initializeMemory(as: UInt8.self, repeating: 0)
        for (idx, byte) in value.utf8.prefix(16).enumerated() {
            buffer[idx] = byte
        }
    }

    private func align(_ data: inout Data, to alignment: Int) {
        let rem = data.count % alignment
        if rem != 0 {
            data.append(Data(repeating: 0, count: alignment - rem))
        }
    }

    private func patchStruct<T>(_ value: inout T, into data: inout Data, at offset: Int) {
        withUnsafeBytes(of: &value) { raw in
            data.replaceSubrange(offset..<(offset + MemoryLayout<T>.size), with: raw)
        }
    }

    private func wordsToLittleEndianData(_ words: [UInt32]) -> Data {
        var out = Data()
        out.reserveCapacity(words.count * 4)
        for w in words {
            var le = w.littleEndian
            withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
        }
        return out
    }

    /// Builds a Thin 64-bit Mach-O with full control over `cputype`, `cpusubtype`, segment protections,
    /// arbitrary section headers (`sizeOverride`, `offsetOverride`), and un-clamped `LC_ENCRYPTION_INFO_64`.
    private func buildThin64(
        cpuType: cpu_type_t = CPU_TYPE_ARM64,
        cpuSubtype: cpu_subtype_t = CPU_SUBTYPE_ARM64_ALL,
        segments: [RawSegmentSpec],
        encryption: (cryptid: UInt32, cryptoff: UInt32, cryptsize: UInt32)? = nil,
        extraTailBytes: Int = 0
    ) -> Data {
        let headerSize = MemoryLayout<mach_header_64>.size
        var loadCmds = Data()
        var ncmds: UInt32 = 0

        var segCmdOffsets: [Int] = []
        var sectHeaderOffsets: [[Int]] = []

        for segSpec in segments {
            segCmdOffsets.append(loadCmds.count)
            var seg = segment_command_64()
            seg.cmd = UInt32(LC_SEGMENT_64)
            seg.cmdsize = UInt32(MemoryLayout<segment_command_64>.size + segSpec.sections.count * MemoryLayout<section_64>.size)
            withUnsafeMutableBytes(of: &seg.segname) { copyFixed16(segSpec.name, into: $0) }
            seg.maxprot = segSpec.maxprot
            seg.initprot = segSpec.initprot
            seg.nsects = UInt32(segSpec.sections.count)
            loadCmds.append(Data(bytes: &seg, count: MemoryLayout<segment_command_64>.size))

            var sectOffsets: [Int] = []
            for _ in segSpec.sections {
                sectOffsets.append(loadCmds.count)
                var placeholder = section_64()
                loadCmds.append(Data(bytes: &placeholder, count: MemoryLayout<section_64>.size))
            }
            sectHeaderOffsets.append(sectOffsets)
            ncmds += 1
        }

        if let enc = encryption {
            var encCmd = encryption_info_command_64(
                cmd: UInt32(LC_ENCRYPTION_INFO_64),
                cmdsize: UInt32(MemoryLayout<encryption_info_command_64>.size),
                cryptoff: enc.cryptoff,
                cryptsize: enc.cryptsize,
                cryptid: enc.cryptid,
                pad: 0
            )
            loadCmds.append(Data(bytes: &encCmd, count: MemoryLayout<encryption_info_command_64>.size))
            ncmds += 1
        }

        var header = mach_header_64(
            magic: MH_MAGIC_64,
            cputype: cpuType,
            cpusubtype: cpuSubtype,
            filetype: UInt32(MH_EXECUTE),
            ncmds: ncmds,
            sizeofcmds: UInt32(loadCmds.count),
            flags: UInt32(MH_NOUNDEFS | MH_PIE),
            reserved: 0
        )

        var data = Data(bytes: &header, count: headerSize)
        data.append(loadCmds)
        align(&data, to: 16)

        var nextVmAddr: UInt64 = 0x1_0000_0000
        for (segIdx, segSpec) in segments.enumerated() {
            let segFileStart = (segSpec.name == "__TEXT") ? 0 : data.count
            let segVmStart = nextVmAddr

            for (sectIdx, sectSpec) in segSpec.sections.enumerated() {
                align(&data, to: 16)
                let naturalOffset = data.count
                let sectOffset = sectSpec.offsetOverride ?? UInt32(naturalOffset)
                let sectAddr = sectSpec.address != 0 ? sectSpec.address : (segVmStart &+ UInt64(naturalOffset - segFileStart))
                let sectSize = sectSpec.sizeOverride ?? UInt64(sectSpec.payload.count)
                data.append(sectSpec.payload)

                var sect = section_64()
                withUnsafeMutableBytes(of: &sect.sectname) { copyFixed16(sectSpec.sectName, into: $0) }
                withUnsafeMutableBytes(of: &sect.segname) { copyFixed16(sectSpec.segName, into: $0) }
                sect.addr = sectAddr
                sect.size = sectSize
                sect.offset = sectOffset
                sect.align = 2
                sect.flags = sectSpec.flags
                patchStruct(&sect, into: &data, at: headerSize + sectHeaderOffsets[segIdx][sectIdx])
            }

            align(&data, to: 16)
            let segFileSize = UInt64(data.count - segFileStart)
            var updatedSeg = segment_command_64()
            updatedSeg.cmd = UInt32(LC_SEGMENT_64)
            updatedSeg.cmdsize = UInt32(MemoryLayout<segment_command_64>.size + segSpec.sections.count * MemoryLayout<section_64>.size)
            withUnsafeMutableBytes(of: &updatedSeg.segname) { copyFixed16(segSpec.name, into: $0) }
            updatedSeg.vmaddr = segVmStart
            updatedSeg.vmsize = max(segFileSize, 0x4000)
            updatedSeg.fileoff = UInt64(segFileStart)
            updatedSeg.filesize = segFileSize
            updatedSeg.maxprot = segSpec.maxprot
            updatedSeg.initprot = segSpec.initprot
            updatedSeg.nsects = UInt32(segSpec.sections.count)
            patchStruct(&updatedSeg, into: &data, at: headerSize + segCmdOffsets[segIdx])

            nextVmAddr = (segVmStart + max(segFileSize, 0x4000) + 0x3FFF) & ~0x3FFF
        }

        if extraTailBytes > 0 {
            data.append(Data(repeating: 0, count: extraTailBytes))
        }
        return data
    }

    /// Builds a genuine 32-bit `MH_MAGIC` Mach-O binary (`LC_SEGMENT` + `section` + optional `LC_ENCRYPTION_INFO`).
    private func buildThin32(
        cpuType: cpu_type_t,
        cpuSubtype: cpu_subtype_t,
        segName: String = "__TEXT",
        sectName: String = "__text",
        flags: UInt32 = UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
        payload: Data,
        encryption: (cryptid: UInt32, cryptoff: UInt32, cryptsize: UInt32)? = nil
    ) -> Data {
        let headerSize = MemoryLayout<mach_header>.size
        var loadCmds = Data()
        var ncmds: UInt32 = 1

        let segCmdPos = loadCmds.count
        var seg = segment_command()
        seg.cmd = UInt32(LC_SEGMENT)
        seg.cmdsize = UInt32(MemoryLayout<segment_command>.size + MemoryLayout<section>.size)
        withUnsafeMutableBytes(of: &seg.segname) { copyFixed16(segName, into: $0) }
        seg.vmaddr = 0x4000
        seg.maxprot = 7
        seg.initprot = 5
        seg.nsects = 1
        loadCmds.append(Data(bytes: &seg, count: MemoryLayout<segment_command>.size))

        let sectPos = loadCmds.count
        var sectPlaceholder = section()
        loadCmds.append(Data(bytes: &sectPlaceholder, count: MemoryLayout<section>.size))

        if let enc = encryption {
            var encCmd = encryption_info_command(
                cmd: UInt32(LC_ENCRYPTION_INFO),
                cmdsize: UInt32(MemoryLayout<encryption_info_command>.size),
                cryptoff: enc.cryptoff,
                cryptsize: enc.cryptsize,
                cryptid: enc.cryptid
            )
            loadCmds.append(Data(bytes: &encCmd, count: MemoryLayout<encryption_info_command>.size))
            ncmds += 1
        }

        var header = mach_header(
            magic: MH_MAGIC,
            cputype: cpuType,
            cpusubtype: cpuSubtype,
            filetype: UInt32(MH_EXECUTE),
            ncmds: ncmds,
            sizeofcmds: UInt32(loadCmds.count),
            flags: UInt32(MH_NOUNDEFS)
        )

        var data = Data(bytes: &header, count: headerSize)
        data.append(loadCmds)
        align(&data, to: 16)

        let sectOff = UInt32(data.count)
        let sectAddr = UInt32(0x4000) + sectOff
        data.append(payload)
        align(&data, to: 16)

        var sect = section()
        withUnsafeMutableBytes(of: &sect.sectname) { copyFixed16(sectName, into: $0) }
        withUnsafeMutableBytes(of: &sect.segname) { copyFixed16(segName, into: $0) }
        sect.addr = sectAddr
        sect.size = UInt32(payload.count)
        sect.offset = sectOff
        sect.align = 2
        sect.flags = flags
        patchStruct(&sect, into: &data, at: headerSize + sectPos)

        seg.vmsize = UInt32(data.count)
        seg.filesize = UInt32(data.count)
        patchStruct(&seg, into: &data, at: headerSize + segCmdPos)

        return data
    }

    /// Wraps already-built Mach-O slices into a Universal FAT binary (`FAT_MAGIC` or `FAT_MAGIC_64`).
    private func buildUniversalFAT(
        slices: [(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t, data: Data)],
        useFat64: Bool = false
    ) -> Data {
        var fat = Data()
        var magicBE = (useFat64 ? FAT_MAGIC_64 : FAT_MAGIC).bigEndian
        var nfatBE = UInt32(slices.count).bigEndian
        fat.append(Data(bytes: &magicBE, count: 4))
        fat.append(Data(bytes: &nfatBE, count: 4))

        let entrySize = useFat64 ? MemoryLayout<fat_arch_64>.size : MemoryLayout<fat_arch>.size
        let headerTotal = 8 + slices.count * entrySize
        let alignment = 4096
        var currentOffset = (headerTotal + alignment - 1) & ~(alignment - 1)

        var archTable = Data()
        var payload = Data()
        for slice in slices {
            let pad = currentOffset - (headerTotal + payload.count)
            if pad > 0 {
                payload.append(Data(repeating: 0, count: pad))
            }
            var ctBE = slice.cpuType.bigEndian
            var cstBE = slice.cpuSubtype.bigEndian
            var alignBE = UInt32(12).bigEndian
            archTable.append(Data(bytes: &ctBE, count: 4))
            archTable.append(Data(bytes: &cstBE, count: 4))
            if useFat64 {
                var offBE = UInt64(currentOffset).bigEndian
                var szBE = UInt64(slice.data.count).bigEndian
                var resBE = UInt32(0).bigEndian
                archTable.append(Data(bytes: &offBE, count: 8))
                archTable.append(Data(bytes: &szBE, count: 8))
                archTable.append(Data(bytes: &alignBE, count: 4))
                archTable.append(Data(bytes: &resBE, count: 4))
            } else {
                var offBE = UInt32(currentOffset).bigEndian
                var szBE = UInt32(slice.data.count).bigEndian
                archTable.append(Data(bytes: &offBE, count: 4))
                archTable.append(Data(bytes: &szBE, count: 4))
                archTable.append(Data(bytes: &alignBE, count: 4))
            }
            payload.append(slice.data)
            currentOffset += (slice.data.count + alignment - 1) & ~(alignment - 1)
        }

        fat.append(archTable)
        fat.append(payload)
        return fat
    }

    private func makeBundleAndIPA(
        appName: String,
        bundleId: String = "com.redteam.syscall",
        executable: Data,
        frameworks: [String: Data] = [:],
        dylibs: [String: Data] = [:],
        appExtensions: [(name: String, bundleId: String, binary: Data, nestedFiles: [String: Data])] = []
    ) throws -> (bundleURL: URL, ipaURL: URL) {
        let rootDir = trackTemp(
            FileManager.default.temporaryDirectory.appendingPathComponent("rt_r1_\(UUID().uuidString)")
        )
        try FileManager.default.createDirectory(at: rootDir, withIntermediateDirectories: true)

        let appURL = rootDir.appendingPathComponent("\(appName).app")
        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)

        let info: [String: Any] = [
            "CFBundleIdentifier": bundleId,
            "CFBundleExecutable": appName,
            "CFBundleDisplayName": appName,
            "CFBundleName": appName,
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "CFBundlePackageType": "APPL"
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        try plistData.write(to: appURL.appendingPathComponent("Info.plist"))
        try executable.write(to: appURL.appendingPathComponent(appName))

        for (relPath, data) in frameworks {
            let dest = appURL.appendingPathComponent("Frameworks").appendingPathComponent(relPath)
            try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: dest)
        }
        for (relPath, data) in dylibs {
            let dest = appURL.appendingPathComponent("Dylibs").appendingPathComponent(relPath)
            try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: dest)
        }
        for ext in appExtensions {
            let extURL = appURL.appendingPathComponent("PlugIns").appendingPathComponent("\(ext.name).appex")
            try FileManager.default.createDirectory(at: extURL, withIntermediateDirectories: true)
            let extInfo: [String: Any] = [
                "CFBundleIdentifier": ext.bundleId,
                "CFBundleExecutable": ext.name,
                "CFBundlePackageType": "XPC!"
            ]
            let extPlist = try PropertyListSerialization.data(fromPropertyList: extInfo, format: .xml, options: 0)
            try extPlist.write(to: extURL.appendingPathComponent("Info.plist"))
            try ext.binary.write(to: extURL.appendingPathComponent(ext.name))
            for (nRel, nData) in ext.nestedFiles {
                let nDest = extURL.appendingPathComponent(nRel)
                try FileManager.default.createDirectory(at: nDest.deletingLastPathComponent(), withIntermediateDirectories: true)
                try nData.write(to: nDest)
            }
        }

        // Package the exact same bundle tree into an .ipa
        var extraFiles: [String: Data] = [:]
        for (relPath, data) in dylibs {
            extraFiles["Dylibs/\(relPath)"] = data
        }
        for ext in appExtensions {
            for (nRel, nData) in ext.nestedFiles {
                extraFiles["PlugIns/\(ext.name).appex/\(nRel)"] = nData
            }
        }
        let ipaExts = Dictionary(uniqueKeysWithValues: appExtensions.map { ($0.name, ($0.bundleId, $0.binary)) })
        let ipaURL = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
            appName: appName,
            bundleIdentifier: bundleId,
            executableBinary: executable,
            embeddedFrameworks: frameworks,
            appExtensions: ipaExts,
            additionalFiles: extraFiles
        )))

        return (appURL, ipaURL)
    }

    // MARK: - 1. Literal & Metadata False-Positive Torture

    func test_vector1_rawSvcBytesInAllMetadataSections_zeroDetectionsAndSafe() throws {
        // Repeat raw `01 10 00 D4` bytes (4-byte aligned!) across every metadata section under RX __TEXT.
        var svcBlob = Data()
        for _ in 0..<4 {
            svcBlob.append(Self.svc0x80Bytes)
        }
        var cstringBlob = svcBlob
        cstringBlob.append(0)

        let ehFrameFlags: UInt32 = UInt32(S_COALESCED) | UInt32(S_ATTR_NO_TOC) | UInt32(S_ATTR_STRIP_STATIC_SYMS) | UInt32(S_ATTR_LIVE_SUPPORT)
        let bin = buildThin64(segments: [
            RawSegmentSpec(
                name: "__TEXT",
                initprot: 5,
                maxprot: 7,
                sections: [
                    CustomSectionSpec(segName: "__TEXT", sectName: "__text", flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS), payload: wordsToLittleEndianData([Self.nopInsn, Self.retInsn])),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__cstring", flags: UInt32(S_CSTRING_LITERALS), payload: cstringBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__cstring_reg", flags: 0, payload: cstringBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__const", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__constg_swiftt", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__swift5_typeref", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__swift5_types", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: cstringBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__objc_meth_reg", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__unwind_info", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__eh_frame", flags: ehFrameFlags, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__eh_frame_reg", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__ustring", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__oslogstring", flags: UInt32(S_CSTRING_LITERALS), payload: cstringBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__gcc_except_tab", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__entitlements", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__dof_probe", flags: 0, payload: svcBlob),
                    CustomSectionSpec(segName: "__TEXT", sectName: "__literal4", flags: UInt32(S_4BYTE_LITERALS), payload: svcBlob)
                ]
            )
        ])

        let parsed = try MachOParser.shared.parse(data: bin)
        let scan = parsed.scanDirectSyscalls()
        XCTAssertEqual(scan.totalCount, 0, "Metadata sections must never produce direct syscall detections")
        XCTAssertTrue(scan.sampleSites.isEmpty)

        let details = try MachOScanner.shared.parseMachO(data: bin)
        XCTAssertEqual(details.directSyscallCount, 0)
        XCTAssertTrue(details.directSyscallSites.isEmpty)

        let machoFinding = MachOScanner.shared.scan(details: details, context: .init(bundleId: "com.clean.metadata", appGroups: []))
        XCTAssertEqual(machoFinding.riskTier, .safe)
        XCTAssertTrue(machoFinding.indicators.isEmpty)

        let (bundleURL, ipaURL) = try makeBundleAndIPA(appName: "MetadataTorture", executable: bin)
        let bundleFinding = try SecurityPipeline.shared.scanBundle(at: bundleURL)
        let ipaFinding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        XCTAssertEqual(bundleFinding.riskTier, .safe)
        XCTAssertEqual(ipaFinding.riskTier, .safe)
    }

    func test_vector1_unalignedSvcBytesInsideTextSection_offsetsPlus1Plus2Plus3_noFalsePositive() throws {
        // Craft adjacent 32-bit LE instructions in __TEXT,__text whose byte boundaries form `01 10 00 D4` at +1, +2, +3:
        // +1: [1F 01 10 00] [D4 03 5F D6] -> bytes 1..4 are 01 10 00 D4
        // +2: [1F 20 01 10] [00 D4 5F D6] -> bytes 2..5 are 01 10 00 D4
        // +3: [1F 20 03 01] [10 00 D4 D6] -> bytes 3..6 are 01 10 00 D4
        let instructions: [UInt32] = [
            Self.nopInsn,
            0x0010_011F, 0xD65F_03D4, // +1 unaligned
            Self.nopInsn,
            0x1001_201F, 0xD65F_D400, // +2 unaligned
            Self.retInsn,
            0x0103_201F, 0xD6D4_0010, // +3 unaligned
            Self.retInsn
        ]

        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            textInstructions: instructions
        ))

        let parsed = try MachOParser.shared.parse(data: bin)
        let textSect = try XCTUnwrap(parsed.textSegment?.sections.first { $0.sectionName == "__text" })
        let textBytes = parsed.sliceData.subdata(in: Int(textSect.offset)..<(Int(textSect.offset) + Int(textSect.size)))
        for offset in [5, 18, 31] {
            XCTAssertEqual(textBytes.subdata(in: offset..<(offset + 4)), Self.svc0x80Bytes, "Test setup must embed unaligned 01 10 00 D4 at byte +\(offset % 4)")
        }

        XCTAssertEqual(parsed.directSyscallCount, 0)
        XCTAssertTrue(parsed.directSyscallSites.isEmpty)

        let finding = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.clean.unaligned", appGroups: []))
        XCTAssertEqual(finding.riskTier, .safe)
        XCTAssertTrue(finding.indicators.isEmpty)
    }

    func test_vector1_otherSvcImmediatesAndExceptionInstructions_noFalsePositive() throws {
        let non0x80Instructions: [UInt32] = [
            Self.nopInsn,
            0xD400_0001, // svc #0
            0xD400_0021, // svc #0x1
            0xD400_0FE1, // svc #0x7f
            0xD400_1021, // svc #0x81
            0xD41F_FFE1, // svc #0xffff
            0xD400_1002, // hvc #0x80
            0xD400_1003, // smc #0x80
            0xD420_1000, // brk #0x80
            0xD440_1000, // hlt #0x80
            0x0110_00D4, // byte-swapped encoding
            Self.retInsn
        ]

        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            textInstructions: non0x80Instructions
        ))

        let parsed = try MachOParser.shared.parse(data: bin)
        XCTAssertEqual(parsed.directSyscallCount, 0)
        XCTAssertTrue(parsed.directSyscallSites.isEmpty)

        let finding = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.clean.othersvc", appGroups: []))
        XCTAssertEqual(finding.riskTier, .safe)
        XCTAssertTrue(finding.indicators.isEmpty)
    }

    // MARK: - 2. CPU Architecture Filtering

    func test_vector2_nonArm64Architectures_x86_64_i386_armv7_armv7s_mustNotDetect() throws {
        let x86_64Bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .x86_64,
            cryptid: 0,
            textInstructions: [Self.svc0x80, Self.svc0x80]
        ))
        let i386Bin = buildThin32(
            cpuType: CPU_TYPE_I386,
            cpuSubtype: cpu_subtype_t(3), // CPU_SUBTYPE_I386_ALL
            payload: wordsToLittleEndianData([Self.svc0x80, Self.svc0x80])
        )
        let armv7Bin32 = buildThin32(
            cpuType: CPU_TYPE_ARM,
            cpuSubtype: CPU_SUBTYPE_ARM_V7,
            payload: wordsToLittleEndianData([Self.svc0x80, Self.svc0x80])
        )
        let armv7sBin32 = buildThin32(
            cpuType: CPU_TYPE_ARM,
            cpuSubtype: CPU_SUBTYPE_ARM_V7S,
            payload: wordsToLittleEndianData([Self.svc0x80])
        )
        let armv7Synthetic = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .armv7,
            cryptid: 0,
            textInstructions: [Self.svc0x80]
        ))

        for (label, bin) in [
            ("x86_64", x86_64Bin),
            ("i386", i386Bin),
            ("armv7_32", armv7Bin32),
            ("armv7s_32", armv7sBin32),
            ("armv7_synthetic", armv7Synthetic)
        ] {
            let parsed = try MachOParser.shared.parse(data: bin)
            let scan = parsed.scanDirectSyscalls()
            XCTAssertEqual(scan.totalCount, 0, "\(label) must return 0 direct syscall sites")
            XCTAssertTrue(scan.sampleSites.isEmpty, "\(label) must return empty sample sites")

            let finding = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.clean.\(label)", appGroups: []))
            XCTAssertEqual(finding.riskTier, .safe, "\(label) must stay .safe")
            XCTAssertTrue(finding.indicators.isEmpty, "\(label) must emit zero indicators")
        }
    }

    func test_vector2_arm64_32_slice_detectedHighRisk() throws {
        let arm64_32Bin = buildThin32(
            cpuType: CPU_TYPE_ARM64_32,
            cpuSubtype: CPU_SUBTYPE_ARM64_32_V8,
            payload: wordsToLittleEndianData([Self.nopInsn, Self.svc0x80, Self.retInsn])
        )

        let parsed = try MachOParser.shared.parse(data: arm64_32Bin)
        XCTAssertEqual(parsed.architecture, .arm64_32)
        let scan = parsed.scanDirectSyscalls()
        XCTAssertEqual(scan.totalCount, 1)
        XCTAssertEqual(scan.sampleSites.count, 1)
        XCTAssertEqual(scan.sampleSites.first?.immediate, 0x0080)

        let finding = try MachOScanner.shared.scan(binaryData: arm64_32Bin, context: .init(bundleId: "com.evil.watch32", appGroups: []))
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "arm64:svc_0x80" })
        XCTAssertTrue(finding.evidence.matchedSymbols.contains("arm64:svc_0x80"))

        let (bundleURL, ipaURL) = try makeBundleAndIPA(appName: "Arm6432Evil", executable: arm64_32Bin)
        XCTAssertEqual(try SecurityPipeline.shared.scanBundle(at: bundleURL).riskTier, .highRisk)
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: ipaURL).riskTier, .highRisk)
    }

    // MARK: - 3. Universal FAT Multi-Slice Shadowing

    func test_vector3_fatShadowing_cleanArm64_maliciousArm64e_detectedInMachOAndIPA() throws {
        let cleanArm64 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            textInstructions: [Self.nopInsn, Self.retInsn]
        ))
        // arm64e slice carrying CPU_SUBTYPE_PTRAUTH_ABI flag (0x80000002) + svc #0x80
        let arm64eSubtype = cpu_subtype_t(bitPattern: 0x8000_0000 | UInt32(CPU_SUBTYPE_ARM64E))
        let evilArm64e = buildThin64(
            cpuType: CPU_TYPE_ARM64,
            cpuSubtype: arm64eSubtype,
            segments: [
                RawSegmentSpec(
                    name: "__TEXT",
                    initprot: 5,
                    maxprot: 7,
                    sections: [
                        CustomSectionSpec(
                            segName: "__TEXT",
                            sectName: "__text",
                            flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                            payload: wordsToLittleEndianData([Self.nopInsn, Self.svc0x80, Self.retInsn])
                        )
                    ]
                )
            ]
        )

        for useFat64 in [false, true] {
            let fatBin = buildUniversalFAT(
                slices: [
                    (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, cleanArm64),
                    (CPU_TYPE_ARM64, arm64eSubtype, evilArm64e)
                ],
                useFat64: useFat64
            )

            let parsedSlices = try MachOParser.shared.parseAllSlices(data: fatBin)
            XCTAssertEqual(parsedSlices.count, 2)
            XCTAssertEqual(parsedSlices[0].architecture, .arm64)
            XCTAssertEqual(parsedSlices[1].architecture, .arm64e)

            let machoFinding = try MachOScanner.shared.scan(binaryData: fatBin, context: .init(bundleId: "com.evil.fatshadow", appGroups: []))
            XCTAssertEqual(machoFinding.riskTier, .highRisk)
            XCTAssertTrue(machoFinding.evidence.matchedSymbols.contains("arm64:svc_0x80"))

            let (bundleURL, ipaURL) = try makeBundleAndIPA(appName: "FatShadow\(useFat64 ? "64" : "32")", executable: fatBin)
            let bundleFinding = try SecurityPipeline.shared.scanBundle(at: bundleURL)
            let ipaFinding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
            XCTAssertEqual(bundleFinding.riskTier, .highRisk)
            XCTAssertEqual(ipaFinding.riskTier, .highRisk)
            XCTAssertTrue(ipaFinding.indicators.contains { $0.signature == "arm64:svc_0x80" })
        }
    }

    func test_vector3_fatShadowing_encryptedCleanArm64_unencryptedMaliciousArm64e_stillDetected() throws {
        // Embed an encrypted svc #0x80 word inside 4096 bytes of high-entropy CSPRNG FairPlay ciphertext
        var csprngText = M1TestCMSFixtures.csprngBytes(count: 4096)
        csprngText.replaceSubrange(0..<4, with: Self.svc0x80Bytes)
        var encryptedCleanArm64 = buildThin64(
            cpuType: CPU_TYPE_ARM64,
            cpuSubtype: CPU_SUBTYPE_ARM64_ALL,
            segments: [
                RawSegmentSpec(
                    name: "__TEXT",
                    initprot: 5,
                    maxprot: 7,
                    sections: [
                        CustomSectionSpec(
                            segName: "__TEXT",
                            sectName: "__text",
                            flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                            payload: csprngText // inside encrypted ciphertext
                        )
                    ]
                )
            ],
            encryption: (cryptid: 1, cryptoff: 0, cryptsize: 0)
        )
        let encParsedPre = try MachOParser.shared.parse(data: encryptedCleanArm64)
        let encTextOff = try XCTUnwrap(encParsedPre.textSegment?.sections.first?.offset)
        var patchedCleanEnc = encryption_info_command_64(
            cmd: UInt32(LC_ENCRYPTION_INFO_64),
            cmdsize: UInt32(MemoryLayout<encryption_info_command_64>.size),
            cryptoff: encTextOff,
            cryptsize: UInt32(csprngText.count),
            cryptid: 1,
            pad: 0
        )
        patchStruct(&patchedCleanEnc, into: &encryptedCleanArm64, at: 32 + 72 + 80)

        let evilArm64e = buildThin64(
            cpuType: CPU_TYPE_ARM64,
            cpuSubtype: CPU_SUBTYPE_ARM64E,
            segments: [
                RawSegmentSpec(
                    name: "__TEXT",
                    initprot: 5,
                    maxprot: 7,
                    sections: [
                        CustomSectionSpec(
                            segName: "__TEXT",
                            sectName: "__text",
                            flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                            payload: wordsToLittleEndianData([Self.svc0x80, Self.retInsn])
                        )
                    ]
                )
            ]
        )

        let fatBin = buildUniversalFAT(slices: [
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, encryptedCleanArm64),
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, evilArm64e)
        ])

        let details = try MachOScanner.shared.parseMachO(data: fatBin)
        XCTAssertEqual(details.directSyscallCount, 1)
        let finding = MachOScanner.shared.scan(details: details, context: .init(bundleId: "com.evil.mixedencfat", appGroups: []))
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "arm64:svc_0x80" })
    }

    func test_vector3_fatShadowing_cleanArm64_maliciousFakeFairPlayArm64e_andMultiSliceSampleCap() throws {
        // Primary arm64 slice has 10 clean instructions + 10 svc #0x80; secondary arm64e has fake partial FairPlay + 10 svc #0x80
        let cleanArm64 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            textInstructions: [Self.nopInsn, Self.retInsn]
        ))
        let fakeFairPlayArm64e = buildThin64(
            cpuType: CPU_TYPE_ARM64,
            cpuSubtype: CPU_SUBTYPE_ARM64E,
            segments: [
                RawSegmentSpec(
                    name: "__TEXT",
                    initprot: 5,
                    maxprot: 7,
                    sections: [
                        CustomSectionSpec(
                            segName: "__TEXT",
                            sectName: "__text",
                            flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                            payload: wordsToLittleEndianData([Self.nopInsn, Self.svc0x80, Self.retInsn])
                        )
                    ]
                )
            ],
            encryption: (cryptid: 1, cryptoff: 0x40, cryptsize: 0x20)
        )
        let fatFakeFP = buildUniversalFAT(slices: [
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, cleanArm64),
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, fakeFairPlayArm64e)
        ])
        let fakeFPFinding = try MachOScanner.shared.scan(binaryData: fatFakeFP, context: .init(bundleId: "com.evil.fatfakefp", appGroups: []))
        XCTAssertEqual(fakeFPFinding.riskTier, .highRisk)
        XCTAssertTrue(fakeFPFinding.indicators.contains { $0.signature == "arm64:svc_0x80" })

        // Multi-slice sample capping: 10 in arm64 + 10 in arm64e -> totalCount == 20, sampleSites.count == 16
        let arm64Ten = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            textInstructions: [UInt32](repeating: Self.svc0x80, count: 10)
        ))
        let arm64eTen = buildThin64(
            cpuType: CPU_TYPE_ARM64,
            cpuSubtype: CPU_SUBTYPE_ARM64E,
            segments: [
                RawSegmentSpec(
                    name: "__TEXT",
                    initprot: 5,
                    maxprot: 7,
                    sections: [
                        CustomSectionSpec(
                            segName: "__TEXT",
                            sectName: "__text",
                            flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                            payload: wordsToLittleEndianData([UInt32](repeating: Self.svc0x80, count: 10))
                        )
                    ]
                )
            ]
        )
        let fat20 = buildUniversalFAT(slices: [
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, arm64Ten),
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, arm64eTen)
        ])
        let details20 = try MachOScanner.shared.parseMachO(data: fat20)
        XCTAssertEqual(details20.directSyscallCount, 20)
        XCTAssertEqual(details20.directSyscallSites.count, 16)
    }

    func test_vector3_fatShadowing_cleanArm64_maliciousX86_64_noFalsePositive() throws {
        let cleanArm64 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            textInstructions: [Self.nopInsn, Self.retInsn]
        ))
        let x86WithSvcBytes = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .x86_64,
            cryptid: 0,
            textInstructions: [Self.svc0x80, Self.svc0x80, Self.svc0x80]
        ))

        // Put x86_64 slice BOTH second and first to verify ordering doesn't matter
        for slices in [
            [(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, cleanArm64), (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, x86WithSvcBytes)],
            [(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, x86WithSvcBytes), (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, cleanArm64)]
        ] {
            let fatBin = buildUniversalFAT(slices: slices)
            let allSlices = try MachOParser.shared.parseAllSlices(data: fatBin)
            let selected = MachOParser.selectAuditSlices(from: allSlices)
            XCTAssertEqual(selected.count, 1)
            XCTAssertEqual(selected.first?.architecture, .arm64)

            let details = try MachOScanner.shared.parseMachO(data: fatBin)
            XCTAssertEqual(details.directSyscallCount, 0)
            let finding = MachOScanner.shared.scan(details: details, context: .init(bundleId: "com.clean.universal", appGroups: []))
            XCTAssertEqual(finding.riskTier, .safe)
            XCTAssertTrue(finding.indicators.isEmpty)

            let (_, ipaURL) = try makeBundleAndIPA(appName: "CleanFat", executable: fatBin)
            let ipaFinding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
            XCTAssertEqual(ipaFinding.riskTier, .safe)
        }
    }

    // MARK: - 4. Custom / Anti-Evasion Section Detection

    func test_vector4_customSection_textShellRegularRX_detectedHighRisk() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [
                (segName: "__TEXT", sectName: "__shell", flags: UInt32(S_REGULAR), payload: wordsToLittleEndianData([Self.nopInsn, Self.svc0x80, Self.retInsn]))
            ]
        ))

        let parsed = try MachOParser.shared.parse(data: bin)
        let scan = parsed.scanDirectSyscalls()
        XCTAssertEqual(scan.totalCount, 1)
        XCTAssertEqual(scan.sampleSites.first?.segmentName, "__TEXT")
        XCTAssertEqual(scan.sampleSites.first?.sectionName, "__shell")

        let machoFinding = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.evil.shell", appGroups: []))
        XCTAssertEqual(machoFinding.riskTier, .highRisk)
        XCTAssertTrue(machoFinding.indicators.contains { $0.signature == "arm64:svc_0x80" && $0.location.contains("__TEXT,__shell") })

        let (_, ipaURL) = try makeBundleAndIPA(appName: "ShellCode", executable: bin)
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: ipaURL).riskTier, .highRisk)
    }

    func test_vector4_customSection_evilCodeSomeInstructionsRWXAndRX_detectedHighRisk() throws {
        for initprot: Int32 in [5, 7] {
            let bin = buildThin64(segments: [
                RawSegmentSpec(
                    name: "__TEXT",
                    initprot: 5,
                    maxprot: 7,
                    sections: [
                        CustomSectionSpec(
                            segName: "__TEXT",
                            sectName: "__text",
                            flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                            payload: wordsToLittleEndianData([Self.nopInsn, Self.retInsn])
                        )
                    ]
                ),
                RawSegmentSpec(
                    name: "__EVIL",
                    initprot: initprot,
                    maxprot: 7,
                    sections: [
                        CustomSectionSpec(
                            segName: "__EVIL",
                            sectName: "__code",
                            flags: UInt32(S_ATTR_SOME_INSTRUCTIONS),
                            payload: wordsToLittleEndianData([Self.svc0x80, Self.retInsn])
                        )
                    ]
                )
            ])

            let parsed = try MachOParser.shared.parse(data: bin)
            let scan = parsed.scanDirectSyscalls()
            XCTAssertEqual(scan.totalCount, 1)
            XCTAssertEqual(scan.sampleSites.first?.segmentName, "__EVIL")
            XCTAssertEqual(scan.sampleSites.first?.sectionName, "__code")

            let finding = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.evil.rwx", appGroups: []))
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertTrue(finding.indicators.contains { $0.signature == "arm64:svc_0x80" && $0.location.contains("__EVIL,__code") })

            let (_, ipaURL) = try makeBundleAndIPA(appName: "EvilSeg\(initprot)", executable: bin)
            XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: ipaURL).riskTier, .highRisk)
        }
    }

    func test_vector4_spoofedMetadataPrefixNamesWithInstructionAttributes_stillDetectedHighRisk() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [
                (segName: "__TEXT", sectName: "__const_shell", flags: UInt32(S_ATTR_PURE_INSTRUCTIONS), payload: Self.svc0x80Bytes),
                (segName: "__TEXT", sectName: "__objc_tramp", flags: UInt32(S_ATTR_PURE_INSTRUCTIONS), payload: Self.svc0x80Bytes),
                (segName: "__EVIL", sectName: "__swift_hook", flags: UInt32(S_ATTR_SOME_INSTRUCTIONS), payload: Self.svc0x80Bytes)
            ]
        ))

        let parsed = try MachOParser.shared.parse(data: bin)
        let scan = parsed.scanDirectSyscalls()
        XCTAssertEqual(scan.totalCount, 3, "Instruction attributes must take precedence over excluded metadata prefixes")
        XCTAssertEqual(Set(scan.sampleSites.map(\.sectionName)), ["__const_shell", "__objc_tramp", "__swift_hook"])

        let machoFinding = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.evil.spoofsect", appGroups: []))
        XCTAssertEqual(machoFinding.riskTier, .highRisk)
        XCTAssertTrue(machoFinding.evidence.matchedSymbols.contains("arm64:svc_0x80"))

        let (_, ipaURL) = try makeBundleAndIPA(appName: "SpoofPrefix", executable: bin)
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: ipaURL).riskTier, .highRisk)
    }

    func test_vector4_standardReadWriteDataSegment_maxprot3_doesNotFalsePositive() throws {
        let bin = buildThin64(segments: [
            RawSegmentSpec(
                name: "__TEXT",
                initprot: 5,
                maxprot: 5,
                sections: [
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: "__text",
                        flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                        payload: wordsToLittleEndianData([Self.nopInsn, Self.retInsn])
                    )
                ]
            ),
            RawSegmentSpec(
                name: "__DATA",
                initprot: 3, // VM_PROT_READ | VM_PROT_WRITE
                maxprot: 3,  // VM_PROT_READ | VM_PROT_WRITE
                sections: [
                    CustomSectionSpec(
                        segName: "__DATA",
                        sectName: "__data",
                        flags: UInt32(S_REGULAR),
                        payload: Self.svc0x80Bytes
                    )
                ]
            )
        ])

        let parsed = try MachOParser.shared.parse(data: bin)
        XCTAssertEqual(parsed.directSyscallCount, 0)
        XCTAssertEqual(try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.clean.rwdata", appGroups: [])).riskTier, .safe)
    }

    func test_vector4_nonExecutableDataSegmentWithLegacyMaxprot7RWX_doesNotFalsePositiveOnDataBytes() throws {
        // Older iOS/macOS linkers or hand-crafted Mach-Os set __DATA initprot=3 (RW, non-executable)
        // with maxprot=7 (RWX). Raw 0xD4001001 constants inside __DATA,__data are non-executable data.
        let bin = buildThin64(segments: [
            RawSegmentSpec(
                name: "__TEXT",
                initprot: 5,
                maxprot: 5,
                sections: [
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: "__text",
                        flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                        payload: wordsToLittleEndianData([Self.nopInsn, Self.retInsn])
                    )
                ]
            ),
            RawSegmentSpec(
                name: "__DATA",
                initprot: 3, // RW only (NOT mapped executable by dyld)
                maxprot: 7,  // legacy maxprot=RWX
                sections: [
                    CustomSectionSpec(
                        segName: "__DATA",
                        sectName: "__data",
                        flags: UInt32(S_REGULAR),
                        payload: Self.svc0x80Bytes
                    )
                ]
            )
        ])

        let parsed = try MachOParser.shared.parse(data: bin)
        XCTAssertEqual(parsed.directSyscallCount, 0, "__DATA,__data with initprot=3 (RW) must not be scanned just because maxprot has 0x04")
    }

    func test_vector4_stubsTextWithoutAttrs_and_16CharNonNullSectionName_detectedHighRisk() throws {
        // Section names are fixed 16-byte buffers; `"__1234567890code"` fills all 16 bytes with zero NUL terminator.
        let sixteenCharName = "__1234567890code"
        XCTAssertEqual(sixteenCharName.utf8.count, 16)

        let bin = buildThin64(segments: [
            RawSegmentSpec(
                name: "__TEXT",
                initprot: 5,
                maxprot: 5,
                sections: [
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: "__text",
                        flags: UInt32(S_REGULAR), // no S_ATTR_*_INSTRUCTIONS
                        payload: Self.svc0x80Bytes
                    ),
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: "__stubs",
                        flags: UInt32(S_SYMBOL_STUBS), // no S_ATTR_*_INSTRUCTIONS
                        payload: Self.svc0x80Bytes
                    ),
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: sixteenCharName,
                        flags: UInt32(S_REGULAR),
                        payload: Self.svc0x80Bytes
                    )
                ]
            )
        ])

        let parsed = try MachOParser.shared.parse(data: bin)
        let scan = parsed.scanDirectSyscalls()
        XCTAssertEqual(scan.totalCount, 3)
        XCTAssertEqual(Set(scan.sampleSites.map(\.sectionName)), ["__text", "__stubs", sixteenCharName])
        XCTAssertEqual(parsed.scanDirectSyscalls(maxSampleSites: 0).totalCount, 3)
        XCTAssertTrue(parsed.scanDirectSyscalls(maxSampleSites: 0).sampleSites.isEmpty)
        XCTAssertEqual(parsed.scanDirectSyscalls(maxSampleSites: -5).totalCount, 3)
        XCTAssertTrue(parsed.scanDirectSyscalls(maxSampleSites: -5).sampleSites.isEmpty)
    }

    // MARK: - 5. FairPlay Partial/Fake Encryption Header Attack vs Genuine DRM

    func test_vector5_fakePartialFairPlayHeader_detectsUnencryptedSvc0x80InMachOAndIPA() throws {
        // cryptoff=0x40, cryptsize=0x20 covers only header bytes 0x40..<0x60; __TEXT,__text starts after load commands.
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0x40,
            cryptsize: 0x20,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.nopInsn, Self.svc0x80, Self.retInsn]
        ))

        let parsed = try MachOParser.shared.parse(data: bin)
        XCTAssertTrue(parsed.isFairPlayEncrypted)
        XCTAssertEqual(parsed.encryptionInfo?.encryptedRange, 0x40..<0x60)
        XCTAssertEqual(parsed.directSyscallCount, 1)

        // Verify MachOScanner catches it even under appStore channel and 0 App Groups
        let machoFinding = try MachOScanner.shared.scan(
            binaryData: bin,
            context: .init(bundleId: "com.fake.fairplay", installChannel: .appStore, appGroups: [])
        )
        XCTAssertEqual(machoFinding.riskTier, .highRisk)
        XCTAssertTrue(machoFinding.indicators.contains { $0.signature == "arm64:svc_0x80" })
        XCTAssertTrue(machoFinding.evidence.matchedSymbols.contains("arm64:svc_0x80"))

        // Verify SecurityPipeline.scanBundle and IPAPackageScanner.scan also catch it (0 App Groups)
        let (bundleURL, ipaURL) = try makeBundleAndIPA(appName: "FakeFairPlayApp", executable: bin)
        let bundleFinding = try SecurityPipeline.shared.scanBundle(at: bundleURL)
        let ipaFinding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        for finding in [bundleFinding, ipaFinding] {
            XCTAssertEqual(finding.installChannel, .developerSideloaded)
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertTrue(finding.indicators.contains { $0.signature == "arm64:svc_0x80" })
            XCTAssertTrue(finding.evidence.matchedSymbols.contains("arm64:svc_0x80"))
        }
    }

    func test_vector5_genuineFairPlayHeaderCoveringTextCiphertext_noFalsePositive_andExactBoundaryChecks() throws {
        // 1. Full coverage over __TEXT,__text containing 4096-byte CSPRNG ciphertext (including encrypted `0xD4001001` words)
        //    plus CMS-signed Option A App Store leaf control.
        var fullCiphertext = M1TestCMSFixtures.csprngBytes(count: 4096)
        fullCiphertext.replaceSubrange(0..<12, with: wordsToLittleEndianData([Self.svc0x80, Self.svc0x80, Self.svc0x80]))
        let (fullEncryptedBin, rootCert) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.apple.appstore.drm",
            cryptid: 1,
            extraSegmentPayload: fullCiphertext
        )

        let parsedFull = try MachOParser.shared.parse(data: fullEncryptedBin)
        XCTAssertFalse(parsedFull.hasForgedPlaintextFairPlayRange)
        XCTAssertEqual(parsedFull.directSyscallCount, 0, "Genuine FairPlay ciphertext inside cryptoff..+cryptsize must not false-positive")
        let machoFull = try MachOScanner.shared.scan(
            binaryData: fullEncryptedBin,
            context: .init(bundleId: "com.apple.appstore.drm", installChannel: .appStore, appGroups: [])
        )
        XCTAssertEqual(machoFull.riskTier, .safe)

        let (bundleURL, ipaURL) = try makeBundleAndIPA(appName: "GenuineDRM", executable: fullEncryptedBin)
        XCTAssertEqual(try SecurityPipeline.shared.scanBundle(at: bundleURL).riskTier, .safe)
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: ipaURL).riskTier, .safe)

        let state = try M1TestCMSFixtures.sharedState()
        let signedDir = trackTemp(FileManager.default.temporaryDirectory.appendingPathComponent("wq_v5_signed_\(UUID().uuidString)"))
        try FileManager.default.createDirectory(at: signedDir, withIntermediateDirectories: true)
        let (_, signedIPA, _) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: signedDir,
            appName: "GenuineSignedDRM",
            bundleId: "com.apple.appstore.drm",
            cryptid: 1,
            signerLeaf: state.appStoreLeaf
        )
        let signedIPAFinding = try IPAPackageScanner.shared.scan(ipaURL: signedIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(signedIPAFinding.installChannel, .appStore)
        XCTAssertEqual(signedIPAFinding.riskTier, .safe)

        // 2. Boundary precision: 4096-byte CSPRNG ciphertext core + 1 trailing unencrypted svc word (bytes 4096..<4100)
        var partialPayload = M1TestCMSFixtures.csprngBytes(count: 4096)
        partialPayload.replaceSubrange(0..<12, with: wordsToLittleEndianData([Self.svc0x80, Self.svc0x80, Self.svc0x80]))
        partialPayload.append(Self.svc0x80Bytes)
        let baseBin = buildThin64(
            segments: [
                RawSegmentSpec(
                    name: "__TEXT",
                    initprot: 5,
                    maxprot: 7,
                    sections: [
                        CustomSectionSpec(
                            segName: "__TEXT",
                            sectName: "__text",
                            flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                            payload: partialPayload
                        )
                    ]
                )
            ],
            encryption: (cryptid: 1, cryptoff: 0, cryptsize: 0)
        )
        let baseParsed = try MachOParser.shared.parse(data: baseBin)
        let textOff = try XCTUnwrap(baseParsed.textSegment?.sections.first?.offset)

        // Patch LC_ENCRYPTION_INFO_64 (starts right after mach_header_64 + segment_command_64 + section_64 = 32 + 72 + 80 = 184)
        let encCmdOffset = 32 + 72 + 80
        var partialBin = baseBin
        var patchedEnc = encryption_info_command_64(
            cmd: UInt32(LC_ENCRYPTION_INFO_64),
            cmdsize: UInt32(MemoryLayout<encryption_info_command_64>.size),
            cryptoff: textOff,
            cryptsize: 4096, // covers bytes 0..<4096, leaves trailing word (bytes 4096..<4100) unencrypted!
            cryptid: 1,
            pad: 0
        )
        patchStruct(&patchedEnc, into: &partialBin, at: encCmdOffset)

        let partialParsed = try MachOParser.shared.parse(data: partialBin)
        XCTAssertFalse(partialParsed.hasForgedPlaintextFairPlayRange)
        let partialScan = partialParsed.scanDirectSyscalls()
        XCTAssertEqual(partialScan.totalCount, 1)
        XCTAssertEqual(partialScan.sampleSites.first?.fileOffset, Int(textOff) + 4096)

        // 3. Split-range: svc word 0 (0..<4) + 4096-byte CSPRNG core (4..<4100) + trailing svc word (4100..<4104)
        var midPayload = Self.svc0x80Bytes
        midPayload.append(M1TestCMSFixtures.csprngBytes(count: 4096))
        midPayload.append(Self.svc0x80Bytes)
        var midBin = buildThin64(
            segments: [
                RawSegmentSpec(
                    name: "__TEXT",
                    initprot: 5,
                    maxprot: 7,
                    sections: [
                        CustomSectionSpec(
                            segName: "__TEXT",
                            sectName: "__text",
                            flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                            payload: midPayload
                        )
                    ]
                )
            ],
            encryption: (cryptid: 1, cryptoff: 0, cryptsize: 0)
        )
        let midTextOff = try XCTUnwrap(MachOParser.shared.parse(data: midBin).textSegment?.sections.first?.offset)
        var midEnc = encryption_info_command_64(
            cmd: UInt32(LC_ENCRYPTION_INFO_64),
            cmdsize: UInt32(MemoryLayout<encryption_info_command_64>.size),
            cryptoff: midTextOff + 4,
            cryptsize: 4096,
            cryptid: 1,
            pad: 0
        )
        patchStruct(&midEnc, into: &midBin, at: encCmdOffset)
        let midParsed = try MachOParser.shared.parse(data: midBin)
        XCTAssertFalse(midParsed.hasForgedPlaintextFairPlayRange)
        let midScan = midParsed.scanDirectSyscalls()
        XCTAssertEqual(midScan.totalCount, 2)
        XCTAssertEqual(midScan.sampleSites.map(\.fileOffset), [Int(midTextOff), Int(midTextOff) + 4100])

        // 4. Embedded framework with fake partial FairPlay + svc #0x80 inside an App-Store-encrypted main app (0 App Groups)
        let evilFramework = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0x40,
            cryptsize: 0x20,
            textInstructions: [Self.svc0x80, Self.retInsn]
        ))
        let (cleanEncryptedMain, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.cleanencryptedmain",
            cryptid: 1
        )
        let (fwBundle, fwIPA) = try makeBundleAndIPA(
            appName: "EncryptedMainFakeFw",
            executable: cleanEncryptedMain,
            frameworks: ["StealthDRM.framework/StealthDRM": evilFramework]
        )
        for finding in [try SecurityPipeline.shared.scanBundle(at: fwBundle), try IPAPackageScanner.shared.scan(ipaURL: fwIPA)] {
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertTrue(finding.indicators.contains { $0.signature == "arm64:svc_0x80" && $0.location.contains("Frameworks/StealthDRM.framework/StealthDRM") })
        }
    }

    func test_vector5_cryptid1WithZeroCryptsize_and_cryptoffPlusCryptsizeOverflow_safe() throws {
        let baseBin = buildThin64(
            segments: [
                RawSegmentSpec(
                    name: "__TEXT",
                    initprot: 5,
                    maxprot: 7,
                    sections: [
                        CustomSectionSpec(
                            segName: "__TEXT",
                            sectName: "__text",
                            flags: UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS),
                            payload: wordsToLittleEndianData([Self.svc0x80, Self.retInsn])
                        )
                    ]
                )
            ],
            encryption: (cryptid: 1, cryptoff: 0, cryptsize: 0)
        )
        let encCmdOffset = 32 + 72 + 80

        // Case A: cryptid = 1, cryptsize = 0 -> encryptedRange == nil -> returns (0, []) safely
        let parsedZeroSize = try MachOParser.shared.parse(data: baseBin)
        XCTAssertTrue(parsedZeroSize.isFairPlayEncrypted)
        XCTAssertNil(parsedZeroSize.encryptionInfo?.encryptedRange)
        let zeroScan = parsedZeroSize.scanDirectSyscalls()
        XCTAssertEqual(zeroScan.totalCount, 0)
        XCTAssertTrue(zeroScan.sampleSites.isEmpty)

        // Case B: cryptid = 1, cryptoff + cryptsize overflows UInt32 (0x8000_0000 + 0x8000_0000) -> no crash, no UInt32 wraparound
        var overflowBin = baseBin
        var overflowEnc = encryption_info_command_64(
            cmd: UInt32(LC_ENCRYPTION_INFO_64),
            cmdsize: UInt32(MemoryLayout<encryption_info_command_64>.size),
            cryptoff: 0x8000_0000,
            cryptsize: 0x8000_0000,
            cryptid: 1,
            pad: 0
        )
        patchStruct(&overflowEnc, into: &overflowBin, at: encCmdOffset)

        let parsedOverflow = try MachOParser.shared.parse(data: overflowBin)
        // On 64-bit, encryptedRange is 0x80000000..<0x100000000 (never wraps to 0..0);
        // on 32-bit, encryptedRange is nil and returns (0, []). Neither crashes or wraps around.
        #if arch(arm64) || arch(x86_64)
        XCTAssertEqual(parsedOverflow.encryptionInfo?.encryptedRange, 0x8000_0000..<0x1_0000_0000)
        XCTAssertEqual(parsedOverflow.scanDirectSyscalls().totalCount, 1)
        #else
        XCTAssertNil(parsedOverflow.encryptionInfo?.encryptedRange)
        XCTAssertEqual(parsedOverflow.scanDirectSyscalls().totalCount, 0)
        #endif
    }

    // MARK: - 6. DoS, Bounds & Trailing-Byte Stress

    func test_vector6_dos50000SvcInstructions_cappedAt16Samples_completesUnder1Second() throws {
        let count = 50_000
        let instructions = [UInt32](repeating: Self.svc0x80, count: count)
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            textInstructions: instructions
        ))

        let parsed = try MachOParser.shared.parse(data: bin)
        let start = CFAbsoluteTimeGetCurrent()
        let scan = parsed.scanDirectSyscalls()
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        XCTAssertEqual(scan.totalCount, count)
        XCTAssertEqual(scan.sampleSites.count, 16)
        XCTAssertLessThan(elapsed, 1.0, "Scanning 50,000 svc #0x80 instructions took \(elapsed)s (must be < 1.0s)")

        let finding = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.dos.50k", appGroups: []))
        XCTAssertEqual(finding.riskTier, .highRisk)
        let ind = try XCTUnwrap(finding.indicators.first { $0.signature == "arm64:svc_0x80" })
        XCTAssertTrue(ind.location.contains("(50000x svc #0x80)"))
    }

    func test_vector6_zerofill4GBSection_noCrashNoOOM() throws {
        let bin = buildThin64(segments: [
            RawSegmentSpec(
                name: "__TEXT",
                initprot: 5,
                maxprot: 7,
                sections: [
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: "__text",
                        sizeOverride: 0x1_0000_0000, // 4GB virtual size!
                        offsetOverride: 0,
                        flags: UInt32(S_ZEROFILL),
                        payload: Data()
                    ),
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: "__gb_zero",
                        sizeOverride: 0x1_0000_0000,
                        offsetOverride: 0,
                        flags: UInt32(S_GB_ZEROFILL),
                        payload: Data()
                    ),
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: "__zero_attr",
                        sizeOverride: 0x1_0000_0000,
                        offsetOverride: 0,
                        flags: UInt32(S_ZEROFILL) | UInt32(S_ATTR_PURE_INSTRUCTIONS),
                        payload: Data()
                    )
                ]
            )
        ])

        let parsed = try MachOParser.shared.parse(data: bin)
        let scan = parsed.scanDirectSyscalls()
        XCTAssertEqual(scan.totalCount, 0)
        XCTAssertTrue(scan.sampleSites.isEmpty)
        XCTAssertEqual(try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.dos.zerofill", appGroups: [])).riskTier, .safe)
    }

    func test_vector6_sectionSizes0_1_2_3_7_andTruncatedSections_zeroOOBCrash() throws {
        // Section sizes 0, 1, 2, 3 containing incomplete svc #0x80 prefixes MUST yield 0 and never crash.
        for size in [0, 1, 2, 3] {
            let payload = Self.svc0x80Bytes.prefix(size)
            let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 0,
                customSections: [
                    (segName: "__TEXT", sectName: "__tiny", flags: UInt32(S_ATTR_PURE_INSTRUCTIONS), payload: payload)
                ]
            ))
            let parsed = try MachOParser.shared.parse(data: bin)
            let scan = parsed.scanDirectSyscalls()
            XCTAssertEqual(scan.totalCount, 0, "Section size \(size) must yield 0 detections")
            XCTAssertTrue(scan.sampleSites.isEmpty)
        }

        // Section size 7: 1 full `svc #0x80` word (4 bytes) + 3 trailing incomplete bytes [01, 10, 00]
        var size7Payload = Data(Self.svc0x80Bytes)
        size7Payload.append(contentsOf: [0x01, 0x10, 0x00])
        XCTAssertEqual(size7Payload.count, 7)

        let bin7 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [
                (segName: "__TEXT", sectName: "__size7", flags: UInt32(S_ATTR_PURE_INSTRUCTIONS), payload: size7Payload)
            ]
        ))
        let parsed7 = try MachOParser.shared.parse(data: bin7)
        let scan7 = parsed7.scanDirectSyscalls()
        XCTAssertEqual(scan7.totalCount, 1)
        XCTAssertEqual(scan7.sampleSites.count, 1)

        // Truncated / out-of-bounds section headers (offset+size > sliceData.count, UInt64.max size, UInt32.max offset)
        let oobBin = buildThin64(segments: [
            RawSegmentSpec(
                name: "__TEXT",
                initprot: 5,
                maxprot: 7,
                sections: [
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: "__trunc",
                        sizeOverride: 0x1000,
                        offsetOverride: nil,
                        flags: UInt32(S_ATTR_PURE_INSTRUCTIONS),
                        payload: Self.svc0x80Bytes
                    ),
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: "__huge",
                        sizeOverride: UInt64.max,
                        offsetOverride: 0x100,
                        flags: UInt32(S_ATTR_PURE_INSTRUCTIONS),
                        payload: Data()
                    ),
                    CustomSectionSpec(
                        segName: "__TEXT",
                        sectName: "__faroff",
                        sizeOverride: 16,
                        offsetOverride: UInt32.max - 4,
                        flags: UInt32(S_ATTR_PURE_INSTRUCTIONS),
                        payload: Data()
                    )
                ]
            )
        ])
        let parsedOOB = try MachOParser.shared.parse(data: oobBin)
        let oobScan = parsedOOB.scanDirectSyscalls()
        XCTAssertEqual(oobScan.totalCount, 0)
        XCTAssertTrue(oobScan.sampleSites.isEmpty)
        XCTAssertEqual(parsedOOB.directSyscallCount, 0)
        XCTAssertTrue(parsedOOB.directSyscallSites.isEmpty)
    }

    // MARK: - 7. Layer 1 Fast-Path Pre-Gating Bypass & Anti-Spoofing

    func test_vector7_zeroAppGroups_standaloneMachO_bundle_andIPA_allHighRiskWithArm64Svc0x80() throws {
        let evilBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.nopInsn, Self.svc0x80, Self.retInsn]
        ))

        // 1. Standalone MachOScanner (0 App Groups)
        let machoFinding = try MachOScanner.shared.scan(
            binaryData: evilBin,
            context: .init(bundleId: "com.nogroup.standalone", appGroups: [])
        )
        XCTAssertEqual(machoFinding.riskTier, .highRisk)
        XCTAssertFalse(machoFinding.evidence.hasAppGroups)
        XCTAssertTrue(machoFinding.indicators.contains { $0.signature == "arm64:svc_0x80" && $0.severity == .highRisk })
        XCTAssertTrue(machoFinding.evidence.matchedSymbols.contains("arm64:svc_0x80"))

        // 2. SecurityPipeline.scanBinary (0 App Groups)
        let binURL = trackTemp(try SyntheticMachOGenerator.shared.writeToTempFile(data: evilBin, prefix: "rt_standalone"))
        let pipelineBinFinding = try SecurityPipeline.shared.scanBinary(at: binURL)
        XCTAssertEqual(pipelineBinFinding.riskTier, .highRisk)
        XCTAssertFalse(pipelineBinFinding.evidence.hasAppGroups)
        XCTAssertTrue(pipelineBinFinding.indicators.contains { $0.signature == "arm64:svc_0x80" })
        XCTAssertTrue(pipelineBinFinding.evidence.matchedSymbols.contains("arm64:svc_0x80"))

        // 3. SecurityPipeline.scanBundle & IPAPackageScanner.scan (0 App Groups, main binary)
        let (bundleURL, ipaURL) = try makeBundleAndIPA(appName: "NoGroupMain", bundleId: "com.nogroup.app", executable: evilBin)
        for finding in [try SecurityPipeline.shared.scanBundle(at: bundleURL), try IPAPackageScanner.shared.scan(ipaURL: ipaURL)] {
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertFalse(finding.evidence.hasAppGroups)
            XCTAssertTrue(finding.indicators.contains { $0.signature == "arm64:svc_0x80" && $0.severity == .highRisk })
            XCTAssertTrue(finding.evidence.matchedSymbols.contains("arm64:svc_0x80"))
        }

        // 4. Hidden inside nested .framework, .dylib, .appex, and nested .appex .dylib with 0 App Groups everywhere
        let cleanMain = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, symbols: ["_main"]))
        let (fwBundle, fwIPA) = try makeBundleAndIPA(
            appName: "NoGroupNested",
            bundleId: "com.nogroup.nested",
            executable: cleanMain,
            frameworks: ["StealthKit.framework/StealthKit": evilBin],
            dylibs: ["libstealth.dylib": evilBin],
            appExtensions: [
                (
                    name: "StealthExt",
                    bundleId: "com.nogroup.nested.ext",
                    binary: cleanMain,
                    nestedFiles: ["Frameworks/libexthelper.dylib": evilBin]
                )
            ]
        )
        for finding in [try SecurityPipeline.shared.scanBundle(at: fwBundle), try IPAPackageScanner.shared.scan(ipaURL: fwIPA)] {
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertFalse(finding.evidence.hasAppGroups)
            XCTAssertTrue(finding.evidence.matchedSymbols.contains("arm64:svc_0x80"))
            let svcLocations = finding.indicators.filter { $0.signature == "arm64:svc_0x80" }.map(\.location)
            XCTAssertEqual(svcLocations.count, 3, "Expected svc #0x80 from framework, dylib, and nested appex dylib; got \(svcLocations)")
        }
    }

    func test_vector7_trojanizedWQGuardIdentityWithSvc0x80_cannotSpoofWhitelist() throws {
        let trojanBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_container_query_create"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.wqguard.app"]),
            textInstructions: [Self.svc0x80, Self.retInsn]
        ))

        let machoFinding = try MachOScanner.shared.scan(
            binaryData: trojanBin,
            context: .init(bundleId: "com.wqguard.app", displayName: "WQGuard", appGroups: ["group.com.wqguard.app"])
        )
        XCTAssertEqual(machoFinding.riskTier, .highRisk)
        XCTAssertFalse(machoFinding.isWhitelisted)
        XCTAssertTrue(machoFinding.evidence.matchedSymbols.contains("arm64:svc_0x80"))

        let (bundleURL, ipaURL) = try makeBundleAndIPA(
            appName: "WQGuard",
            bundleId: "com.wqguard.app",
            executable: trojanBin
        )
        for finding in [try SecurityPipeline.shared.scanBundle(at: bundleURL), try IPAPackageScanner.shared.scan(ipaURL: ipaURL)] {
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertFalse(finding.isWhitelisted)
            XCTAssertTrue(finding.evidence.matchedSymbols.contains("arm64:svc_0x80"))
        }
    }
}
