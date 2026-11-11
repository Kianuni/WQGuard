import Foundation
import MachO

/// SyntheticMachOGenerator generates valid in-memory Mach-O Thin (ARM64, x86_64) and Universal FAT binaries
/// with customizable load commands, symbol tables, encryption info headers, and Code Signature SuperBlobs.
public final class SyntheticMachOGenerator: @unchecked Sendable {
    public static let shared = SyntheticMachOGenerator()

    public enum Architecture: Sendable {
        case arm64
        case x86_64
        case armv7

        public var cpuType: cpu_type_t {
            switch self {
            case .arm64: return CPU_TYPE_ARM64
            case .x86_64: return CPU_TYPE_X86_64
            case .armv7: return CPU_TYPE_ARM
            }
        }

        public var cpuSubtype: cpu_subtype_t {
            switch self {
            case .arm64: return CPU_SUBTYPE_ARM64_ALL
            case .x86_64: return CPU_SUBTYPE_X86_64_ALL
            case .armv7: return CPU_SUBTYPE_ARM_V7
            }
        }
    }

    public struct MachOConfig: Sendable {
        public var arch: Architecture
        public var cryptid: UInt32
        public var cryptoff: UInt32
        public var cryptsize: UInt32
        public var linkedDylibs: [String]
        public var weakDylibs: [String]
        public var symbols: [String]
        public var xmlEntitlements: String?
        public var derEntitlements: Data?
        public var rawCodeSignatureSlot: (slot: UInt32, magic: UInt32, data: Data)?
        public var includeCodeSignature: Bool
        public var corruptMagic: UInt32?
        public var corruptNCmds: UInt32?
        public var corruptSizeOfCmds: UInt32?

        public init(
            arch: Architecture = .arm64,
            cryptid: UInt32 = 0,
            cryptoff: UInt32 = 0x4000,
            cryptsize: UInt32 = 0x4000,
            linkedDylibs: [String] = [],
            weakDylibs: [String] = [],
            symbols: [String] = [],
            xmlEntitlements: String? = nil,
            derEntitlements: Data? = nil,
            rawCodeSignatureSlot: (slot: UInt32, magic: UInt32, data: Data)? = nil,
            includeCodeSignature: Bool = true,
            corruptMagic: UInt32? = nil,
            corruptNCmds: UInt32? = nil,
            corruptSizeOfCmds: UInt32? = nil
        ) {
            self.arch = arch
            self.cryptid = cryptid
            self.cryptoff = cryptoff
            self.cryptsize = cryptsize
            self.linkedDylibs = linkedDylibs
            self.weakDylibs = weakDylibs
            self.symbols = symbols
            self.xmlEntitlements = xmlEntitlements
            self.derEntitlements = derEntitlements
            self.rawCodeSignatureSlot = rawCodeSignatureSlot
            self.includeCodeSignature = includeCodeSignature
            self.corruptMagic = corruptMagic
            self.corruptNCmds = corruptNCmds
            self.corruptSizeOfCmds = corruptSizeOfCmds
        }
    }

    public init() {}

    // MARK: - Entitlements Helpers

    /// Builds a standard XML property list string containing application groups.
    public static func createXMLEntitlements(appGroups: [String]) -> String {
        let groupsXml = appGroups.map { "        <string>\($0)</string>" }.joined(separator: "\n")
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
        \(groupsXml)
            </array>
        </dict>
        </plist>
        """
    }

    /// Encodes an ASN.1 DER payload representing `{"com.apple.security.application-groups": [appGroups]}`.
    public static func createDEREntitlements(appGroups: [String]) -> Data {
        func encodeDERLength(_ length: Int) -> [UInt8] {
            if length < 128 {
                return [UInt8(length)]
            } else if length <= 0xff {
                return [0x81, UInt8(length)]
            } else if length <= 0xffff {
                return [0x82, UInt8(length >> 8), UInt8(length & 0xff)]
            } else {
                return [0x84, UInt8((length >> 24) & 0xff), UInt8((length >> 16) & 0xff), UInt8((length >> 8) & 0xff), UInt8(length & 0xff)]
            }
        }

        func encodeDERString(_ str: String, tag: UInt8 = 0x0c) -> [UInt8] {
            let bytes = Array(str.utf8)
            return [tag] + encodeDERLength(bytes.count) + bytes
        }

        func encodeDERSequence(_ items: [[UInt8]]) -> [UInt8] {
            let payload = items.flatMap { $0 }
            return [0x30] + encodeDERLength(payload.count) + payload
        }

        let keyBytes = encodeDERString("com.apple.security.application-groups")
        let valueSeq = encodeDERSequence(appGroups.map { encodeDERString($0) })
        let pairSeq = encodeDERSequence([keyBytes, valueSeq])
        let rootSeq = encodeDERSequence([pairSeq])
        return Data(rootSeq)
    }

    // MARK: - Mach-O Generation

    /// Generates a Thin 64-bit Mach-O binary Data matching the configuration.
    public func generateThin(config: MachOConfig) -> Data {
        var loadCommandsData = Data()
        var ncmds: UInt32 = 0

        // 1. LC_SEGMENT_64: __TEXT
        var textSeg = segment_command_64()
        textSeg.cmd = UInt32(LC_SEGMENT_64)
        textSeg.cmdsize = UInt32(MemoryLayout<segment_command_64>.size)
        withUnsafeMutableBytes(of: &textSeg.segname) { ptr in
            let name = "__TEXT"
            _ = name.withCString { cstr in
                strncpy(ptr.baseAddress!.assumingMemoryBound(to: CChar.self), cstr, 16)
            }
        }
        textSeg.vmaddr = 0x100000000
        textSeg.vmsize = 0x4000
        textSeg.fileoff = 0
        textSeg.filesize = 0x4000
        textSeg.maxprot = 7
        textSeg.initprot = 5
        textSeg.nsects = 0
        textSeg.flags = 0
        loadCommandsData.append(Data(bytes: &textSeg, count: MemoryLayout<segment_command_64>.size))
        ncmds += 1

        // 2. LC_ENCRYPTION_INFO_64
        var encCmd = encryption_info_command_64(
            cmd: UInt32(LC_ENCRYPTION_INFO_64),
            cmdsize: UInt32(MemoryLayout<encryption_info_command_64>.size),
            cryptoff: config.cryptoff,
            cryptsize: config.cryptsize,
            cryptid: config.cryptid,
            pad: 0
        )
        loadCommandsData.append(Data(bytes: &encCmd, count: MemoryLayout<encryption_info_command_64>.size))
        ncmds += 1

        // 3. LC_LOAD_DYLIB
        for dylibPath in config.linkedDylibs {
            let cmdBytes = buildDylibCommand(path: dylibPath, isWeak: false)
            loadCommandsData.append(cmdBytes)
            ncmds += 1
        }

        // 4. LC_LOAD_WEAK_DYLIB
        for dylibPath in config.weakDylibs {
            let cmdBytes = buildDylibCommand(path: dylibPath, isWeak: true)
            loadCommandsData.append(cmdBytes)
            ncmds += 1
        }

        // 5. LC_SYMTAB
        let symtabCmdPos = loadCommandsData.count
        var symtabCmd = symtab_command()
        symtabCmd.cmd = UInt32(LC_SYMTAB)
        symtabCmd.cmdsize = UInt32(MemoryLayout<symtab_command>.size)
        loadCommandsData.append(Data(bytes: &symtabCmd, count: MemoryLayout<symtab_command>.size))
        ncmds += 1

        // 6. LC_CODE_SIGNATURE (optional)
        var csCmdPos: Int? = nil
        if config.includeCodeSignature && (config.xmlEntitlements != nil || config.derEntitlements != nil || config.rawCodeSignatureSlot != nil) {
            csCmdPos = loadCommandsData.count
            var csCmd = linkedit_data_command()
            csCmd.cmd = UInt32(LC_CODE_SIGNATURE)
            csCmd.cmdsize = UInt32(MemoryLayout<linkedit_data_command>.size)
            loadCommandsData.append(Data(bytes: &csCmd, count: MemoryLayout<linkedit_data_command>.size))
            ncmds += 1
        }

        // Assemble Mach-O Header
        let magic = config.corruptMagic ?? MH_MAGIC_64
        let finalNcmds = config.corruptNCmds ?? ncmds
        let finalSizeofcmds = config.corruptSizeOfCmds ?? UInt32(loadCommandsData.count)

        var header = mach_header_64(
            magic: magic,
            cputype: config.arch.cpuType,
            cpusubtype: config.arch.cpuSubtype,
            filetype: UInt32(MH_EXECUTE),
            ncmds: finalNcmds,
            sizeofcmds: finalSizeofcmds,
            flags: UInt32(MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE),
            reserved: 0
        )

        var result = Data(bytes: &header, count: MemoryLayout<mach_header_64>.size)
        result.append(loadCommandsData)

        // Align to 16 bytes
        let pad16 = (16 - (result.count % 16)) % 16
        if pad16 > 0 {
            result.append(Data(repeating: 0, count: pad16))
        }

        // Build Symbol Table Data
        let symoff = UInt32(result.count)
        var stringTable = Data([0]) // first byte null
        var nlists: [nlist_64] = []
        for symbol in config.symbols {
            let strx = UInt32(stringTable.count)
            stringTable.append(contentsOf: symbol.utf8)
            stringTable.append(0)
            var nl = nlist_64()
            nl.n_un.n_strx = strx
            nl.n_type = UInt8(N_EXT | N_SECT)
            nl.n_sect = 1
            nl.n_desc = 0
            nl.n_value = 0x100001000
            nlists.append(nl)
        }

        for var nl in nlists {
            result.append(Data(bytes: &nl, count: MemoryLayout<nlist_64>.size))
        }
        let stroff = UInt32(result.count)
        let strsize = UInt32(stringTable.count)
        result.append(stringTable)

        // Patch symtab command in load commands
        let symtabFileOffset = MemoryLayout<mach_header_64>.size + symtabCmdPos
        var updatedSymtab = symtab_command(
            cmd: UInt32(LC_SYMTAB),
            cmdsize: UInt32(MemoryLayout<symtab_command>.size),
            symoff: symoff,
            nsyms: UInt32(config.symbols.count),
            stroff: stroff,
            strsize: strsize
        )
        withUnsafeBytes(of: &updatedSymtab) { raw in
            result.replaceSubrange(symtabFileOffset..<symtabFileOffset + MemoryLayout<symtab_command>.size, with: raw)
        }

        // Build Code Signature SuperBlob if requested
        if let csPos = csCmdPos {
            let csPad = (16 - (result.count % 16)) % 16
            if csPad > 0 {
                result.append(Data(repeating: 0, count: csPad))
            }
            let csOff = UInt32(result.count)

            let superBlob = buildSuperBlob(
                xml: config.xmlEntitlements,
                der: config.derEntitlements,
                rawSlot: config.rawCodeSignatureSlot
            )
            result.append(superBlob)
            let csSize = UInt32(superBlob.count)

            let csFileOffset = MemoryLayout<mach_header_64>.size + csPos
            var updatedCS = linkedit_data_command(
                cmd: UInt32(LC_CODE_SIGNATURE),
                cmdsize: UInt32(MemoryLayout<linkedit_data_command>.size),
                dataoff: csOff,
                datasize: csSize
            )
            withUnsafeBytes(of: &updatedCS) { raw in
                result.replaceSubrange(csFileOffset..<csFileOffset + MemoryLayout<linkedit_data_command>.size, with: raw)
            }
        }

        // Adjust TEXT segment filesize and encryption offsets to be valid within generated binary
        let segOffset = MemoryLayout<mach_header_64>.size
        var updatedTextSeg = textSeg
        updatedTextSeg.filesize = UInt64(result.count)
        updatedTextSeg.vmsize = UInt64(result.count)
        withUnsafeBytes(of: &updatedTextSeg) { raw in
            result.replaceSubrange(segOffset..<segOffset + MemoryLayout<segment_command_64>.size, with: raw)
        }

        let encOffset = MemoryLayout<mach_header_64>.size + MemoryLayout<segment_command_64>.size
        var updatedEnc = encCmd
        if config.cryptsize > UInt32(result.count) || config.cryptoff >= UInt32(result.count) {
            updatedEnc.cryptoff = 0
            updatedEnc.cryptsize = UInt32(result.count)
            withUnsafeBytes(of: &updatedEnc) { raw in
                result.replaceSubrange(encOffset..<encOffset + MemoryLayout<encryption_info_command_64>.size, with: raw)
            }
        }

        return result
    }

    /// Generates a Universal FAT Mach-O binary (`0xcafebabe`) containing slices for each config.
    public func generateUniversalFAT(configs: [MachOConfig]) -> Data {
        precondition(!configs.isEmpty, "FAT binary must contain at least one slice")
        var thinSlices: [(config: MachOConfig, data: Data)] = []
        for cfg in configs {
            let sliceData = generateThin(config: cfg)
            thinSlices.append((cfg, sliceData))
        }

        var fatData = Data()
        var magicBE = UInt32(0xcafebabe).bigEndian
        var nfatBE = UInt32(thinSlices.count).bigEndian
        fatData.append(Data(bytes: &magicBE, count: 4))
        fatData.append(Data(bytes: &nfatBE, count: 4))

        let headerSize = 8 + thinSlices.count * 20
        let alignment = 4096 // 4KB alignment
        var currentOffset = (headerSize + alignment - 1) & ~(alignment - 1)

        var archesData = Data()
        var slicesPayload = Data()

        for slice in thinSlices {
            let pad = currentOffset - (headerSize + slicesPayload.count)
            if pad > 0 {
                slicesPayload.append(Data(repeating: 0, count: pad))
            }

            var cpuTypeBE = slice.config.arch.cpuType.bigEndian
            var cpuSubtypeBE = slice.config.arch.cpuSubtype.bigEndian
            var offsetBE = UInt32(currentOffset).bigEndian
            var sizeBE = UInt32(slice.data.count).bigEndian
            var alignBE = UInt32(12).bigEndian // 2^12 = 4096

            archesData.append(Data(bytes: &cpuTypeBE, count: 4))
            archesData.append(Data(bytes: &cpuSubtypeBE, count: 4))
            archesData.append(Data(bytes: &offsetBE, count: 4))
            archesData.append(Data(bytes: &sizeBE, count: 4))
            archesData.append(Data(bytes: &alignBE, count: 4))

            slicesPayload.append(slice.data)
            currentOffset += (slice.data.count + alignment - 1) & ~(alignment - 1)
        }

        fatData.append(archesData)
        fatData.append(slicesPayload)
        return fatData
    }

    // MARK: - Private Helpers

    private func buildDylibCommand(path: String, isWeak: Bool) -> Data {
        var cPath = Array(path.utf8)
        cPath.append(0)
        let dylibCmdOffset: UInt32 = 24
        let totalCmdSize = UInt32((Int(dylibCmdOffset) + cPath.count + 7) & ~7)
        let cmdType: UInt32 = isWeak ? UInt32(LC_LOAD_WEAK_DYLIB) : UInt32(LC_LOAD_DYLIB)

        var dylibCmd = dylib_command(
            cmd: cmdType,
            cmdsize: totalCmdSize,
            dylib: dylib(
                name: lc_str(offset: dylibCmdOffset),
                timestamp: 2,
                current_version: 0x00010000,
                compatibility_version: 0x00010000
            )
        )
        var cmdBytes = Data(bytes: &dylibCmd, count: MemoryLayout<dylib_command>.size)
        cmdBytes.append(Data(cPath))
        if cmdBytes.count < totalCmdSize {
            cmdBytes.append(Data(repeating: 0, count: Int(totalCmdSize) - cmdBytes.count))
        }
        return cmdBytes
    }

    private func buildSuperBlob(
        xml: String?,
        der: Data?,
        rawSlot: (slot: UInt32, magic: UInt32, data: Data)?
    ) -> Data {
        var slots: [(slotType: UInt32, blobData: Data)] = []

        if let xml = xml {
            var xmlBlob = Data()
            var magic = UInt32(0xfade7171).bigEndian
            let xmlBytes = Array(xml.utf8)
            var len = UInt32(8 + xmlBytes.count).bigEndian
            xmlBlob.append(Data(bytes: &magic, count: 4))
            xmlBlob.append(Data(bytes: &len, count: 4))
            xmlBlob.append(Data(xmlBytes))
            slots.append((5, xmlBlob))
        }

        if let der = der {
            var derBlob = Data()
            var magic = UInt32(0xfade7172).bigEndian
            var len = UInt32(8 + der.count).bigEndian
            derBlob.append(Data(bytes: &magic, count: 4))
            derBlob.append(Data(bytes: &len, count: 4))
            derBlob.append(der)
            slots.append((7, derBlob))
        }

        if let raw = rawSlot {
            var rawBlob = Data()
            var magic = raw.magic.bigEndian
            var len = UInt32(8 + raw.data.count).bigEndian
            rawBlob.append(Data(bytes: &magic, count: 4))
            rawBlob.append(Data(bytes: &len, count: 4))
            rawBlob.append(raw.data)
            slots.append((raw.slot, rawBlob))
        }

        var blob = Data()
        var magic = UInt32(0xfade0cc0).bigEndian
        var count = UInt32(slots.count).bigEndian
        let headerSize = 12 + slots.count * 8
        var currentOffset = UInt32(headerSize)

        var indexData = Data()
        var payloadData = Data()
        for slot in slots {
            var typeBE = slot.slotType.bigEndian
            var offBE = currentOffset.bigEndian
            indexData.append(Data(bytes: &typeBE, count: 4))
            indexData.append(Data(bytes: &offBE, count: 4))
            payloadData.append(slot.blobData)
            currentOffset += UInt32(slot.blobData.count)
        }

        var totalLength = currentOffset.bigEndian
        blob.append(Data(bytes: &magic, count: 4))
        blob.append(Data(bytes: &totalLength, count: 4))
        blob.append(Data(bytes: &count, count: 4))
        blob.append(indexData)
        blob.append(payloadData)
        return blob
    }

    /// Writes data to a temporary file and returns its URL.
    public func writeToTempFile(data: Data, prefix: String = "synthetic_macho") throws -> URL {
        let tempDir = FileManager.default.temporaryDirectory
        let fileURL = tempDir.appendingPathComponent("\(prefix)_\(UUID().uuidString)")
        try data.write(to: fileURL)
        return fileURL
    }
}
