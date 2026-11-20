//
//  AdversarialV130Round10DeepAuditTests.swift
//  WQGuardCoreTests
//
//  Deep Security Audit Regression Suite (Round 10):
//  1. ChannelClassifier & CSBlobParser O(N) comment/CDATA XML scanner + malformed/symlinked mobileprovision fail-closed
//  2. MachOParser LC_DYLD_INFO_ONLY lazy_bind random-access opcode poisoning & desync resynchronization
//  3. MachOParser objcMethodNames & MachOScanner partial LC_ENCRYPTION_INFO_64 overlap inspection
//  4. IPAPackageScanner 3+ slice Universal FAT disguise in skipped asset extensions
//  5. scanEmbeddedAppex escaping symlink pre-validation, in-bundle symlinked .appex enumeration & corrupt primary continuation
//  6. Hybrid encrypted main + unencrypted framework/appex CVE-2026-84493, encrypted private Photos entitlements, com.apple.* cryptid=1 no-sandbox & standalone __TEXT,__info_plist
//  7. wqguard-cli .framework without Info.plist, extensionless ZIP/IPA magic & O_NOFOLLOW target/output symlink defense
//  8. WhitelistEngine custom allowedAppGroups allSatisfy anti-piggybacking
//  9. ContainerScanner step-by-step climb-above-root detection, tilde rejection & Caches truncation/depth fail-closed
//  10. InstalledAppRegistryScanner TrollStore iTunesMetadata spoofing, System-registration spoofing, TestFlight spoofing & CDATA stream splitting
//

import XCTest
import Foundation
import Darwin
import MachO
import zlib
import JavaScriptCore
@testable import WQGuardCore

fileprivate extension Data {
    mutating func r10le16(_ v: UInt16) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r10le32(_ v: UInt32) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r10be32(_ v: UInt32) { var x = v.bigEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
}

final class AdversarialV130Round10DeepAuditTests: XCTestCase {

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
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: u.path)
            try? FileManager.default.removeItem(at: u)
        }
        tempURLs.removeAll()
        super.tearDown()
    }

    private func makeTempURL(_ name: String) -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("r10_\(UUID().uuidString)_\(name)")
        tempURLs.append(u)
        return u
    }

    private static func crc32Of(_ d: Data) -> UInt32 {
        d.withUnsafeBytes { raw in
            UInt32(crc32(0, raw.bindMemory(to: Bytef.self).baseAddress, uInt(d.count)))
        }
    }

    private static func deflateRaw(_ input: Data) -> Data {
        var strm = z_stream()
        guard deflateInit2_(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            return input
        }
        defer { deflateEnd(&strm) }
        var out = Data()
        var chunk = [UInt8](repeating: 0, count: 16_384)
        input.withUnsafeBytes { inPtr in
            strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
            strm.avail_in = uInt(input.count)
            repeat {
                let cap = chunk.count
                chunk.withUnsafeMutableBufferPointer { buf in
                    strm.next_out = buf.baseAddress
                    strm.avail_out = uInt(cap)
                    _ = deflate(&strm, Z_FINISH)
                }
                let produced = cap - Int(strm.avail_out)
                if produced > 0 { out.append(contentsOf: chunk[0..<produced]) }
            } while strm.avail_out == 0
        }
        return out
    }

    private struct ZipSpec {
        var path: String
        var payload: Data
        var deflate: Bool = false
        var unixMode: UInt32 = 0o100644
    }

    private func buildZip(_ items: [ZipSpec]) -> Data {
        var archive = Data()
        var cd = Data()
        for item in items {
            let localOff = UInt32(archive.count)
            let nameUTF8 = Data(item.path.utf8)
            let crc = Self.crc32Of(item.payload)
            let compPayload = item.deflate ? Self.deflateRaw(item.payload) : item.payload
            let method: UInt16 = item.deflate ? 8 : 0

            archive.r10le32(0x0403_4B50)
            archive.r10le16(20)
            archive.r10le16(0)
            archive.r10le16(method)
            archive.r10le16(0)
            archive.r10le16(0)
            archive.r10le32(crc)
            archive.r10le32(UInt32(compPayload.count))
            archive.r10le32(UInt32(item.payload.count))
            archive.r10le16(UInt16(nameUTF8.count))
            archive.r10le16(0)
            archive.append(nameUTF8)
            archive.append(compPayload)

            cd.r10le32(0x0201_4B50)
            cd.r10le16(0x0314)
            cd.r10le16(20)
            cd.r10le16(0)
            cd.r10le16(method)
            cd.r10le16(0)
            cd.r10le16(0)
            cd.r10le32(crc)
            cd.r10le32(UInt32(compPayload.count))
            cd.r10le32(UInt32(item.payload.count))
            cd.r10le16(UInt16(nameUTF8.count))
            cd.r10le16(0)
            cd.r10le16(0)
            cd.r10le16(0)
            cd.r10le16(0)
            cd.r10le32(item.unixMode << 16)
            cd.r10le32(localOff)
            cd.append(nameUTF8)
        }
        let cdOff = UInt32(archive.count)
        archive.append(cd)
        archive.r10le32(0x0605_4B50)
        archive.r10le16(0)
        archive.r10le16(0)
        archive.r10le16(UInt16(items.count))
        archive.r10le16(UInt16(items.count))
        archive.r10le32(UInt32(cd.count))
        archive.r10le32(cdOff)
        archive.r10le16(0)
        return archive
    }

    private func runCLIInProcess(_ args: [String]) async throws -> (code: Int32, out: String, err: String) {
        let outURL = makeTempURL("cli_out.txt")
        let errURL = makeTempURL("cli_err.txt")
        FileManager.default.createFile(atPath: outURL.path, contents: Data())
        FileManager.default.createFile(atPath: errURL.path, contents: Data())
        let outFH = try FileHandle(forWritingTo: outURL)
        let errFH = try FileHandle(forWritingTo: errURL)
        let code = await CLICommandRunner.run(arguments: ["wqguard-cli"] + args, stdout: outFH, stderr: errFH)
        try? outFH.close()
        try? errFH.close()
        return (
            code,
            String(decoding: try Data(contentsOf: outURL), as: UTF8.self),
            String(decoding: try Data(contentsOf: errURL), as: UTF8.self)
        )
    }

    // MARK: - 1. ChannelClassifier & CSBlobParser Comment/CDATA Linear XML Scanner & Malformed Mobileprovision Fail-Closed

    func test_r10_01_xmlCommentCDATALinearScan_andMalformedProvisionNeverFallsThroughToAppStore() throws {
        // 1. CSBlobParser.parseXMLPlist with 3,000 literal </plist> tokens inside comments & CDATA + trailing garbage:
        //    must finish in O(N) without quadratic PropertyListSerialization retries.
        let manyCloseComments = Array(repeating: "</plist>", count: 1500).joined(separator: " ")
        let manyCloseCDATA = Array(repeating: "</plist>", count: 1500).joined(separator: " ")
        let heavyEntitlementXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!-- \(manyCloseComments) -->
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>note</key>
            <string><![CDATA[\(manyCloseCDATA)]]></string>
            <key>com.apple.security.application-groups</key>
            <array><string>group.com.r10.linear</string></array>
        </dict>
        </plist>TRAILING_GARBAGE_WITH_</plist>_AND_BYTES
        """
        let t0 = CFAbsoluteTimeGetCurrent()
        let parsedEnts = try CSBlobParser.shared.parseXMLPlist(Data(heavyEntitlementXML.utf8))
        let elapsed = CFAbsoluteTimeGetCurrent() - t0
        XCTAssertLessThan(elapsed, 1.0, "CSBlobParser.parseXMLPlist took \(elapsed)s — expected O(N) comment/CDATA scan")
        XCTAssertEqual(CSBlobParser.shared.extractAppGroups(fromPlistDict: parsedEnts), ["group.com.r10.linear"])

        // 2. ChannelClassifier.extractPlist with 100 literal </plist> tokens inside CDATA/comments AND adversarial <plist><!-- prefix
        let manyProfileClose = Array(repeating: "</plist>", count: 60).joined(separator: " ")
        let entProfileXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!-- \(manyProfileClose) -->
        <plist version="1.0">
        <dict>
            <key>Name</key><string><![CDATA[Enterprise \(manyProfileClose)]]></string>
            <key>TeamIdentifier</key><array><string>ENT1010101</string></array>
            <key>ProvisionsAllDevices</key><true/>
        </dict>
        </plist>
        """
        var adversarialCMS = Data("CMS_PREFIX_<plist><!--_FAKE_UNCLOSED_".utf8)
        adversarialCMS.append(Data(entProfileXML.utf8))
        adversarialCMS.append(Data("_CMS_SUFFIX_--></plist>".utf8))
        let entClass = ChannelClassifier.classify(cryptid: 1, mobileprovisionData: adversarialCMS)
        XCTAssertEqual(entClass.channel, .enterpriseInHouse)
        XCTAssertEqual(entClass.teamIdentifier, "ENT1010101")

        // 3. Malformed / truncated / 0-byte / symlinked embedded.mobileprovision with cryptid = 1 MUST NEVER fall through to .appStore
        for badProv in [Data("CORRUPT_CMS_WITHOUT_VALID_XML".utf8), Data()] {
            let res = ChannelClassifier.classify(cryptid: 1, mobileprovisionData: badProv, hasSandboxReceipt: true)
            XCTAssertEqual(res.channel, .developerSideloaded,
                           "Malformed or empty embedded.mobileprovision on cryptid=1 bundle must fail closed to .developerSideloaded")
            XCTAssertTrue(res.hasMobileProvision)
        }

        // End-to-end IPA check: cryptid = 1 MetaMask clone carrying corrupted embedded.mobileprovision must trigger IMPERSONATION:MetaMask
        let encBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.retWord]
        ))
        let walletPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "io.metamask.MetaMask",
            "CFBundleDisplayName": "MetaMask",
            "CFBundleExecutable": "MetaMask",
            "CFBundleShortVersionString": "7.30.0"
        ], format: .xml, options: 0)
        let corruptProvIPA = makeTempURL("corrupt_prov_wallet.ipa")
        try buildZip([
            .init(path: "Payload/MetaMask.app/Info.plist", payload: walletPlist),
            .init(path: "Payload/MetaMask.app/MetaMask", payload: encBin, unixMode: 0o100755),
            .init(path: "Payload/MetaMask.app/embedded.mobileprovision", payload: Data([0x30, 0x82, 0xFF, 0x00, 0xDE, 0xAD]))
        ]).write(to: corruptProvIPA)
        let ipaFinding = try IPAPackageScanner.shared.scan(ipaURL: corruptProvIPA)
        XCTAssertEqual(ipaFinding.installChannel, .developerSideloaded)
        XCTAssertEqual(ipaFinding.riskTier, .highRisk)
        XCTAssertTrue(ipaFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })

        // Escaping symlink embedded.mobileprovision on disk with cryptid = 1 -> never dereferenced AND never .appStore
        let outsideFile = makeTempURL("outside.mobileprovision")
        try Data(entProfileXML.utf8).write(to: outsideFile)
        let appDir = makeTempURL("SymProvEncrypted.app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        symlink(outsideFile.path, appDir.appendingPathComponent("embedded.mobileprovision").path)
        let symBundleClass = ChannelClassifier.classifyBundle(at: appDir, cryptid: 1)
        XCTAssertEqual(symBundleClass.channel, .developerSideloaded)
        XCTAssertNil(symBundleClass.teamIdentifier)

        // Option A control: unsigned synthetic cryptid = 1 without Apple CMS trust never becomes .appStore,
        // while Apple App Store verified cryptid = 1 without embedded.mobileprovision classifies as .appStore.
        XCTAssertEqual(ChannelClassifier.classify(cryptid: 1, mobileprovisionData: nil).channel, .developerSideloaded)
        XCTAssertEqual(ChannelClassifier.classify(cryptid: 1, mobileprovisionData: nil, codeSignatureTrust: .appleAppStoreVerified).channel, .appStore)
    }

    // MARK: - 2. MachOParser LC_DYLD_INFO_ONLY lazy_bind Random-Access Poisoning & Desync Defense

    func test_r10_02_dyldLazyBind_invalidLeadingOpcode_andDesyncPrefixResynchronization() throws {
        // Build a minimal 64-bit ARM64 Mach-O with empty LC_SYMTAB and LC_DYLD_INFO_ONLY whose lazy_bind stream has:
        // - Record 1: invalid opcode 0xE0 at byte 0, 0xD2 at byte 1, 0x00 separator, then valid lazy_bind for `_fsgetpath`
        // - Record 2: desynchronizing valid opcode 0x80 (ADD_ADDR_ULEB) immediately preceding 0x40 `_\(IOCTokenArmor.tCqCreate)\0` + 0x90 DO_BIND
        let fsSym = "_" + IOCTokenArmor.tFsgetpath
        let cqSym = "_" + IOCTokenArmor.tCqCreate

        var lazyStream = Data([0xE0, 0xD2, 0x00])
        // Standard lazy_bind entry 1: SET_SEGMENT_AND_OFFSET_ULEB(seg=1, off=0), SET_DYLIB_ORDINAL_IMM(1), SET_SYMBOL(fsSym), DO_BIND, DONE
        lazyStream.append(contentsOf: [0x71, 0x00, 0x11, 0x40])
        lazyStream.append(Data(fsSym.utf8))
        lazyStream.append(contentsOf: [0x00, 0x90, 0x00])
        // Desynchronizing prefix byte 0x80 right before `__stub_helper` jump target 0x40 <cqSym>\0 0x90 0x00
        lazyStream.append(0x80)
        lazyStream.append(0x40)
        lazyStream.append(Data(cqSym.utf8))
        lazyStream.append(contentsOf: [0x00, 0x11, 0x90, 0x00])
        while lazyStream.count % 8 != 0 { lazyStream.append(0x00) }

        // Construct Mach-O64: header (32) + LC_SEGMENT_64 __TEXT (72) + LC_SEGMENT_64 __LINKEDIT (72) + LC_DYLD_INFO_ONLY (48) = 224 bytes
        let textSize = 512
        let lazyOffset = textSize
        let totalSize = textSize + lazyStream.count
        var bin = Data()
        bin.r10le32(MH_MAGIC_64)
        bin.r10le32(UInt32(bitPattern: CPU_TYPE_ARM64))
        bin.r10le32(0)
        bin.r10le32(UInt32(MH_EXECUTE))
        bin.r10le32(3) // ncmds
        bin.r10le32(72 + 72 + 48) // sizeofcmds = 192
        bin.r10le32(0)
        bin.r10le32(0)

        func appendSeg64(name: String, vmaddr: UInt64, vmsize: UInt64, fileoff: UInt64, filesize: UInt64, prot: Int32) {
            bin.r10le32(UInt32(LC_SEGMENT_64))
            bin.r10le32(72)
            var nameBytes = Array(name.utf8.prefix(16))
            while nameBytes.count < 16 { nameBytes.append(0) }
            bin.append(contentsOf: nameBytes)
            var vma = vmaddr.littleEndian; Swift.withUnsafeBytes(of: &vma) { bin.append(contentsOf: $0) }
            var vms = vmsize.littleEndian; Swift.withUnsafeBytes(of: &vms) { bin.append(contentsOf: $0) }
            var foff = fileoff.littleEndian; Swift.withUnsafeBytes(of: &foff) { bin.append(contentsOf: $0) }
            var fsz = filesize.littleEndian; Swift.withUnsafeBytes(of: &fsz) { bin.append(contentsOf: $0) }
            bin.r10le32(UInt32(bitPattern: prot))
            bin.r10le32(UInt32(bitPattern: prot))
            bin.r10le32(0)
            bin.r10le32(0)
        }

        appendSeg64(name: "__TEXT", vmaddr: 0x100000000, vmsize: UInt64(textSize), fileoff: 0, filesize: UInt64(textSize), prot: 5)
        appendSeg64(name: "__LINKEDIT", vmaddr: 0x100004000, vmsize: 0x4000, fileoff: UInt64(lazyOffset), filesize: UInt64(lazyStream.count), prot: 1)

        // LC_DYLD_INFO_ONLY (0x80000022), cmdsize = 48
        bin.r10le32(0x8000_0022)
        bin.r10le32(48)
        bin.r10le32(0); bin.r10le32(0) // rebase
        bin.r10le32(0); bin.r10le32(0) // bind
        bin.r10le32(0); bin.r10le32(0) // weak_bind
        bin.r10le32(UInt32(lazyOffset))
        bin.r10le32(UInt32(lazyStream.count))
        bin.r10le32(0); bin.r10le32(0) // export

        while bin.count < textSize {
            var ret = Self.retWord.littleEndian
            Swift.withUnsafeBytes(of: &ret) { bin.append(contentsOf: $0) }
        }
        bin.append(lazyStream)
        XCTAssertEqual(bin.count, totalSize)

        let parsed = try MachOParser.parse(data: bin)
        XCTAssertTrue(parsed.containsSymbol(IOCTokenArmor.tFsgetpath), "Poisoned byte 0 in lazy_bind must not blind _fsgetpath")
        XCTAssertTrue(parsed.containsSymbol(IOCTokenArmor.tCqCreate), "Desynchronized prefix byte in lazy_bind must not blind container_query_create")

        let details = try MachOScanner.shared.parseMachO(data: bin)
        let finding = MachOScanner.shared.scan(
            details: details,
            context: .init(bundleId: "com.r10.lazybind", appGroups: ["group.com.r10.shared"])
        )
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.evidence.pathEnumerationPresent)
        XCTAssertTrue(finding.indicators.contains { $0.signature == IOCTokenArmor.tCqCreate })
    }

    // MARK: - 3. MachOParser objcMethodNames Partial LC_ENCRYPTION_INFO_64 Overlap

    private func buildMachOWithObjCMethnameAndInfoPlist(
        selectors: [String],
        infoPlistData: Data? = nil,
        cryptid: UInt32 = 0,
        cryptRangeInMethname: Range<Int>? = nil,
        fullyEncryptMethname: Bool = false
    ) -> Data {
        var methData = Data([0, 0, 0, 0]) // 4 leading pad bytes
        for sel in selectors {
            methData.append(Data(sel.utf8))
            methData.append(0)
        }
        while methData.count % 8 != 0 { methData.append(0) }

        var plistSectData = infoPlistData ?? Data()
        while plistSectData.count % 8 != 0 { plistSectData.append(0) }

        let hasPlistSect = !plistSectData.isEmpty
        let nsects: UInt32 = hasPlistSect ? 3 : 2
        let segCmdSize = 72 + Int(nsects) * 80
        let hasEnc = cryptid != 0
        let ncmds: UInt32 = hasEnc ? 2 : 1
        let sizeofcmds = segCmdSize + (hasEnc ? 24 : 0)

        let textSectOff = 512
        let textSectSize = 16
        let methSectOff = textSectOff + textSectSize
        let methSectSize = methData.count
        let plistSectOff = methSectOff + methSectSize
        let totalTextFileSize = plistSectOff + plistSectData.count

        let resolvedCryptOff: UInt32
        let resolvedCryptSize: UInt32
        if fullyEncryptMethname {
            resolvedCryptOff = UInt32(textSectOff)
            resolvedCryptSize = UInt32(totalTextFileSize - textSectOff)
        } else if let r = cryptRangeInMethname {
            resolvedCryptOff = UInt32(methSectOff + r.lowerBound)
            resolvedCryptSize = UInt32(r.count)
        } else {
            resolvedCryptOff = 0
            resolvedCryptSize = 0
        }

        var bin = Data()
        bin.r10le32(MH_MAGIC_64)
        bin.r10le32(UInt32(bitPattern: CPU_TYPE_ARM64))
        bin.r10le32(0)
        bin.r10le32(UInt32(MH_EXECUTE))
        bin.r10le32(ncmds)
        bin.r10le32(UInt32(sizeofcmds))
        bin.r10le32(0)
        bin.r10le32(0)

        // LC_SEGMENT_64 __TEXT
        bin.r10le32(UInt32(LC_SEGMENT_64))
        bin.r10le32(UInt32(segCmdSize))
        var segName = Array("__TEXT".utf8); while segName.count < 16 { segName.append(0) }
        bin.append(contentsOf: segName)
        var vma: UInt64 = 0x100000000; Swift.withUnsafeBytes(of: &vma) { bin.append(contentsOf: $0) }
        var vms = UInt64(totalTextFileSize).littleEndian; Swift.withUnsafeBytes(of: &vms) { bin.append(contentsOf: $0) }
        var foff: UInt64 = 0; Swift.withUnsafeBytes(of: &foff) { bin.append(contentsOf: $0) }
        var fsz = UInt64(totalTextFileSize).littleEndian; Swift.withUnsafeBytes(of: &fsz) { bin.append(contentsOf: $0) }
        bin.r10le32(5); bin.r10le32(5)
        bin.r10le32(nsects)
        bin.r10le32(0)

        func appendSect64(sectName: String, offset: Int, size: Int, flags: UInt32) {
            var sn = Array(sectName.utf8.prefix(16)); while sn.count < 16 { sn.append(0) }
            var sgn = Array("__TEXT".utf8); while sgn.count < 16 { sgn.append(0) }
            bin.append(contentsOf: sn)
            bin.append(contentsOf: sgn)
            var addr = (UInt64(0x100000000) + UInt64(offset)).littleEndian
            var sz = UInt64(size).littleEndian
            Swift.withUnsafeBytes(of: &addr) { bin.append(contentsOf: $0) }
            Swift.withUnsafeBytes(of: &sz) { bin.append(contentsOf: $0) }
            bin.r10le32(UInt32(offset))
            bin.r10le32(2)
            bin.r10le32(0)
            bin.r10le32(0)
            bin.r10le32(flags)
            bin.r10le32(0); bin.r10le32(0); bin.r10le32(0)
        }

        appendSect64(sectName: "__text", offset: textSectOff, size: textSectSize, flags: UInt32(S_ATTR_PURE_INSTRUCTIONS))
        appendSect64(sectName: "__objc_methname", offset: methSectOff, size: methSectSize, flags: 0x02)
        if hasPlistSect {
            appendSect64(sectName: "__info_plist", offset: plistSectOff, size: plistSectData.count, flags: 0)
        }

        if hasEnc {
            bin.r10le32(UInt32(LC_ENCRYPTION_INFO_64))
            bin.r10le32(24)
            bin.r10le32(resolvedCryptOff)
            bin.r10le32(resolvedCryptSize)
            bin.r10le32(cryptid)
            bin.r10le32(0)
        }

        while bin.count < textSectOff { bin.append(0) }
        for _ in 0..<(textSectSize / 4) {
            var ret = Self.retWord.littleEndian
            Swift.withUnsafeBytes(of: &ret) { bin.append(contentsOf: $0) }
        }
        bin.append(methData)
        if hasPlistSect { bin.append(plistSectData) }
        return bin
    }

    func test_r10_03_objcMethodNames_partialEncryptionOverlapExtractsUnencryptedSelectors() throws {
        // 4-byte overlap at bytes 0..<4 of __objc_methname must NOT blind selectors at bytes 4..<end
        let partialBin = buildMachOWithObjCMethnameAndInfoPlist(
            selectors: ["systemPhotoLibrary", "ASAccessorySession", "generalPasteboard"],
            cryptid: 1,
            cryptRangeInMethname: 0..<4
        )
        let parsedPartial = try MachOParser.parse(data: partialBin)
        let extractedSels = Set(parsedPartial.objcMethodNames)
        XCTAssertTrue(extractedSels.contains("systemPhotoLibrary"))
        XCTAssertTrue(extractedSels.contains("ASAccessorySession"))
        XCTAssertTrue(extractedSels.contains("generalPasteboard"))

        let binURL = makeTempURL("partial_methname_bin")
        try partialBin.write(to: binURL)
        let finding = try SecurityPipeline.shared.scanBinary(at: binURL)
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "systemPhotoLibrary" })

        // Negative control: 100% FairPlay-encrypted __objc_methname (high-entropy CSPRNG >= 4096 bytes) returns empty selectors and .safe
        var fullEncBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 0x4000,
            textInstructions: [Self.retWord],
            customSections: [
                (segName: "__TEXT", sectName: "__objc_methname", flags: 0x02, payload: M1TestCMSFixtures.csprngBytes(count: 4096))
            ]
        ))
        let preFullParsed = try MachOParser.parse(data: fullEncBin)
        let methSect = try XCTUnwrap(preFullParsed.segments.flatMap(\.sections).first { $0.sectionName == "__objc_methname" })
        let fullNcmds = fullEncBin.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self) }
        var fullLcCur = MemoryLayout<mach_header_64>.size
        for _ in 0..<fullNcmds {
            let cmd = fullEncBin.withUnsafeBytes { $0.load(fromByteOffset: fullLcCur, as: UInt32.self) }
            let csz = fullEncBin.withUnsafeBytes { $0.load(fromByteOffset: fullLcCur + 4, as: UInt32.self) }
            if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                var offLE = methSect.offset.littleEndian
                var szLE = UInt32(methSect.size).littleEndian
                withUnsafeBytes(of: &offLE) { fullEncBin.replaceSubrange((fullLcCur + 8)..<(fullLcCur + 12), with: $0) }
                withUnsafeBytes(of: &szLE) { fullEncBin.replaceSubrange((fullLcCur + 12)..<(fullLcCur + 16), with: $0) }
                break
            }
            fullLcCur += Int(csz)
        }
        let parsedFull = try MachOParser.parse(data: fullEncBin)
        XCTAssertFalse(parsedFull.hasForgedPlaintextFairPlayRange)
        XCTAssertTrue(parsedFull.objcMethodNames.isEmpty)
        let fullURL = makeTempURL("full_enc_methname_bin")
        try fullEncBin.write(to: fullURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: fullURL).riskTier, .safe)
    }

    // MARK: - 4. IPAPackageScanner 3+ Slice Universal FAT Disguise

    func test_r10_04_fourSliceFatDisguisedAsPng_withPerturbedLeadingSlices_detectedInIPAAndBundle() throws {
        let arm64Slice = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.svcWord, Self.retWord]
        ))

        // Build 4-slice 0xCAFEBABE FAT binary:
        // fat_arch[0..2] have perturbed invalid cputype (0x00010100) and size 0;
        // fat_arch[3] (beyond 64-byte prefix!) holds valid CPU_TYPE_ARM64 with inline svc #0x80.
        let nfat: UInt32 = 4
        let sliceOffset: UInt32 = 128 // >= 8 + 4*20 = 88
        var fat = Data()
        fat.r10be32(0xCAFE_BABE)
        fat.r10be32(nfat)
        for _ in 0..<3 {
            fat.r10be32(0x0001_0100) // invalid cputype (middle byte non-zero)
            fat.r10be32(0)
            fat.r10be32(0)
            fat.r10be32(0)
            fat.r10be32(0)
        }
        fat.r10be32(UInt32(bitPattern: CPU_TYPE_ARM64))
        fat.r10be32(0)
        fat.r10be32(sliceOffset)
        fat.r10be32(UInt32(arm64Slice.count))
        fat.r10be32(14)
        while fat.count < Int(sliceOffset) { fat.append(0) }
        fat.append(arm64Slice)

        let cleanMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [Self.nopWord, Self.retWord]
        ))
        let plist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.fat4.disguise",
            "CFBundleExecutable": "App",
            "CFBundleShortVersionString": "1.0"
        ], format: .xml, options: 0)

        // 1. DEFLATE-compressed .ipa with disguised Assets/bg.png
        let ipaURL = makeTempURL("fat4_disguised.ipa")
        try buildZip([
            .init(path: "Payload/App.app/Info.plist", payload: plist, deflate: true),
            .init(path: "Payload/App.app/App", payload: cleanMain, deflate: true, unixMode: 0o100755),
            .init(path: "Payload/App.app/Assets/bg.png", payload: fat, deflate: true)
        ]).write(to: ipaURL)

        let ipaFinding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        XCTAssertEqual(ipaFinding.riskTier, .highRisk)
        XCTAssertTrue(ipaFinding.indicators.contains { $0.signature == SignatureCatalog.directSyscallRule.pattern })

        // 2. On-disk .app bundle with disguised Assets/bg.png
        let bundleDir = makeTempURL("Fat4App.app")
        try FileManager.default.createDirectory(at: bundleDir.appendingPathComponent("Assets"), withIntermediateDirectories: true)
        try plist.write(to: bundleDir.appendingPathComponent("Info.plist"))
        try cleanMain.write(to: bundleDir.appendingPathComponent("App"))
        try fat.write(to: bundleDir.appendingPathComponent("Assets/bg.png"))

        let bundleFinding = try SecurityPipeline.shared.scanBundle(at: bundleDir)
        XCTAssertEqual(bundleFinding.riskTier, .highRisk)
        XCTAssertTrue(bundleFinding.indicators.contains { $0.signature == SignatureCatalog.directSyscallRule.pattern })

        // 3. Negative control: synthetic Java .class file (0xCAFEBABE, minor=0, major=61, constant_pool_count=10, tag=7)
        var javaClass = Data([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x3D, 0x00, 0x0A, 0x07, 0x00, 0x02])
        javaClass.append(Data(repeating: 0x01, count: 128))
        XCTAssertFalse(IPAPackageScanner.isMachOOrFatMagic(javaClass, fileSize: javaClass.count))
    }

    // MARK: - 5. scanEmbeddedAppex Escaping Symlink, In-Bundle Symlinked .appex & Corrupt Primary Continuation

    func test_r10_05_scanEmbeddedAppex_escapingSymlink_inBundleDirSymlink_andCorruptPrimaryContinuation() throws {
        let cleanMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [Self.nopWord, Self.retWord]
        ))
        let appPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.appex.host",
            "CFBundleExecutable": "HostApp"
        ], format: .xml, options: 0)

        // 1. Escaping symlink `PlugIns/Escape.appex -> <outsideDir>` must NOT read external Info.plist and must flag BUNDLE_ESCAPING_SYMLINK
        let outsideAppex = makeTempURL("OutsideEvil.appex")
        try FileManager.default.createDirectory(at: outsideAppex, withIntermediateDirectories: true)
        let extPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "io.metamask.MetaMask.ext",
            "CFBundleExecutable": "OutsideBin"
        ], format: .xml, options: 0)
        try extPlist.write(to: outsideAppex.appendingPathComponent("Info.plist"))

        let app1 = makeTempURL("EscapeAppexHost.app")
        try FileManager.default.createDirectory(at: app1.appendingPathComponent("PlugIns"), withIntermediateDirectories: true)
        try appPlist.write(to: app1.appendingPathComponent("Info.plist"))
        try cleanMain.write(to: app1.appendingPathComponent("HostApp"))
        symlink(outsideAppex.path, app1.appendingPathComponent("PlugIns/Escape.appex").path)

        let f1 = try SecurityPipeline.shared.scanBundle(at: app1)
        XCTAssertEqual(f1.riskTier, .highRisk)
        XCTAssertTrue(f1.indicators.contains { $0.signature == "BUNDLE_ESCAPING_SYMLINK" })

        // 2. In-bundle directory symlink `PlugIns/Hidden.appex -> ../HiddenStore/RealExt` + corrupt primary executable + sibling evil dylib
        let app2 = makeTempURL("InBundleSymAppex.app")
        let realExtDir = app2.appendingPathComponent("HiddenStore/RealExt")
        try FileManager.default.createDirectory(at: app2.appendingPathComponent("PlugIns"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: realExtDir.appendingPathComponent("Frameworks"), withIntermediateDirectories: true)
        try appPlist.write(to: app2.appendingPathComponent("Info.plist"))
        try cleanMain.write(to: app2.appendingPathComponent("HostApp"))

        let plugPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.appex.host.share",
            "CFBundleExecutable": "CorruptPrimary"
        ], format: .xml, options: 0)
        try plugPlist.write(to: realExtDir.appendingPathComponent("Info.plist"))
        // Corrupt primary executable inside RealExt
        try Data([0xCF, 0xFA, 0xED, 0xFE, 0xAA, 0xBB]).write(to: realExtDir.appendingPathComponent("CorruptPrimary"))

        // Sibling dylib inside the same .appex carrying App Group + container_query_create + svc #0x80
        let grpXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
            <key>com.apple.security.application-groups</key>
            <array><string>group.com.r10.extvictim</string></array>
        </dict></plist>
        """
        let siblingDylib = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_" + IOCTokenArmor.tCqCreate],
            xmlEntitlements: grpXML,
            textInstructions: [Self.svcWord, Self.retWord]
        ))
        try siblingDylib.write(to: realExtDir.appendingPathComponent("Frameworks/SiblingPayload.dylib"))
        symlink("../HiddenStore/RealExt", app2.appendingPathComponent("PlugIns/Hidden.appex").path)

        let f2 = try SecurityPipeline.shared.scanBundle(at: app2)
        XCTAssertEqual(f2.riskTier, .highRisk)
        let f2Sigs = Set(f2.indicators.map(\.signature))
        XCTAssertTrue(f2Sigs.contains("CorruptMachO:UnparseableBinary"))
        XCTAssertTrue(f2Sigs.contains(IOCTokenArmor.tCqCreate), "Corrupt primary .appex binary must not skip sibling dylibs")
        XCTAssertTrue(f2Sigs.contains(SignatureCatalog.directSyscallRule.pattern))
        XCTAssertTrue(f2.evidence.appGroups.contains("group.com.r10.extvictim"))
    }

    // MARK: - 6. Hybrid Encrypted Main + Unencrypted Framework/Appex CVE-2026-84493, Encrypted Photos Entitlement, com.apple.* no-sandbox & Standalone __info_plist

    func test_r10_06_hybridAccessorySetupBypass_encryptedPhotosEntitlement_comAppleNoSandbox_andStandaloneInfoPlist() throws {
        let encryptedMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.retWord]
        ))
        let unencryptedAccessoryDylib = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"],
            symbols: ["_OBJC_CLASS_$_ASAccessorySession"],
            textInstructions: [Self.retWord]
        ))

        // 1. cryptid=1 main binary (.appStore) + unencrypted embedded framework importing AccessorySetupKit while omitting required Info.plist keys -> CVE-2026-84493
        let btOmittedAppPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.hybrid.bt",
            "CFBundleExecutable": "MainApp"
        ], format: .xml, options: 0)
        let hybridIPA = makeTempURL("hybrid_accessory.ipa")
        try buildZip([
            .init(path: "Payload/MainApp.app/Info.plist", payload: btOmittedAppPlist),
            .init(path: "Payload/MainApp.app/MainApp", payload: encryptedMain, unixMode: 0o100755),
            .init(path: "Payload/MainApp.app/Frameworks/Helper.dylib", payload: unencryptedAccessoryDylib)
        ]).write(to: hybridIPA)
        let hybridFinding = try IPAPackageScanner.shared.scan(ipaURL: hybridIPA)
        XCTAssertEqual(hybridFinding.riskTier, .highRisk)
        XCTAssertTrue(hybridFinding.indicators.contains { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" })

        // Also verify cryptid=1 main binary + unencrypted .appex invoking AccessorySetupKit while omitting NSAccessorySetupKitSupports -> CVE-2026-84493
        let cleanPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.hybrid.appexhost",
            "CFBundleExecutable": "MainApp"
        ], format: .xml, options: 0)
        let extBtOmittedPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.hybrid.appexhost.ext",
            "CFBundleExecutable": "ExtBin"
        ], format: .xml, options: 0)
        let hybridAppexIPA = makeTempURL("hybrid_appex_accessory.ipa")
        try buildZip([
            .init(path: "Payload/MainApp.app/Info.plist", payload: cleanPlist),
            .init(path: "Payload/MainApp.app/MainApp", payload: encryptedMain, unixMode: 0o100755),
            .init(path: "Payload/MainApp.app/PlugIns/Ext.appex/Info.plist", payload: extBtOmittedPlist),
            .init(path: "Payload/MainApp.app/PlugIns/Ext.appex/ExtBin", payload: unencryptedAccessoryDylib, unixMode: 0o100755)
        ]).write(to: hybridAppexIPA)
        let hybridAppexFinding = try IPAPackageScanner.shared.scan(ipaURL: hybridAppexIPA)
        XCTAssertEqual(hybridAppexFinding.riskTier, .highRisk)
        XCTAssertTrue(hybridAppexFinding.indicators.contains { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" })

        // 2. Pure cryptid=1 bundle declaring restricted com.apple.photos.bourgeoisie = true AND com.apple.fake + no-sandbox = true
        let encPhotosAndFakeAppleXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
            <key>com.apple.photos.bourgeoisie</key><true/>
            <key>com.apple.private.security.no-sandbox</key><true/>
        </dict></plist>
        """
        let encPrivBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 0,
            symbols: ["_main"],
            xmlEntitlements: encPhotosAndFakeAppleXML,
            textInstructions: [Self.retWord]
        ))
        let fakeApplePlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.apple.fake.photos",
            "CFBundleExecutable": "FakePhotos"
        ], format: .xml, options: 0)
        let encPhotosIPA = makeTempURL("enc_photos_fake_apple.ipa")
        try buildZip([
            .init(path: "Payload/FakePhotos.app/Info.plist", payload: fakeApplePlist),
            .init(path: "Payload/FakePhotos.app/FakePhotos", payload: encPrivBin, unixMode: 0o100755)
        ]).write(to: encPhotosIPA)
        let encPhotosFinding = try IPAPackageScanner.shared.scan(ipaURL: encPhotosIPA)
        XCTAssertEqual(encPhotosFinding.riskTier, .highRisk)
        let encPhotosSigs = Set(encPhotosFinding.indicators.map(\.signature))
        XCTAssertTrue(encPhotosSigs.contains("com.apple.photos.bourgeoisie"))
        XCTAssertTrue(encPhotosSigs.contains("com.apple.private.security.no-sandbox"))

        // 3. Standalone Mach-O binary embedding __TEXT,__info_plist (impersonation + UIBackgroundModes clipboard snooping)
        let embeddedPlistBytes = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "io.metamask.MetaMask",
            "CFBundleDisplayName": "MetaMask",
            "CFBundleShortVersionString": "7.88.1",
            "UIBackgroundModes": ["audio"]
        ], format: .xml, options: 0)
        let standaloneBin = buildMachOWithObjCMethnameAndInfoPlist(
            selectors: ["generalPasteboard", "ASAccessorySession"],
            infoPlistData: embeddedPlistBytes
        )
        let standaloneURL = makeTempURL("standalone_helper_bin")
        try standaloneBin.write(to: standaloneURL)
        let standaloneFinding = try SecurityPipeline.shared.scanBinary(at: standaloneURL)
        XCTAssertEqual(standaloneFinding.bundleId, "io.metamask.MetaMask")
        XCTAssertEqual(standaloneFinding.displayName, "MetaMask")
        XCTAssertEqual(standaloneFinding.version, "7.88.1")
        XCTAssertEqual(standaloneFinding.riskTier, .highRisk)
        XCTAssertTrue(standaloneFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })
        XCTAssertTrue(standaloneFinding.indicators.contains { $0.category == "Background Clipboard Snooping" })
        XCTAssertTrue(standaloneFinding.indicators.contains { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" },
                      "Standalone Mach-O with __TEXT,__info_plist omitting Bluetooth keys must fire CVE-2026-84493")
    }

    // MARK: - 7. wqguard-cli .framework Without Info.plist, Extensionless ZIP/IPA & O_NOFOLLOW Symlink Protection

    func test_r10_07_cli_frameworkWithoutInfoPlist_extensionlessZipIPA_andNoFollowSymlinkProtection() async throws {
        let evilMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [Self.svcWord, Self.retWord]
        ))

        // 1. `wqguard-cli scan Evil.framework` WITHOUT Info.plist -> must detect svc #0x80 and exit 1 (never Container clean exit 0)
        let fwDir = makeTempURL("Evil.framework")
        try FileManager.default.createDirectory(at: fwDir, withIntermediateDirectories: true)
        try evilMachO.write(to: fwDir.appendingPathComponent("Evil"))

        let fwRes = try await runCLIInProcess(["scan", fwDir.path])
        XCTAssertEqual(fwRes.code, 1, "Evil.framework without Info.plist must exit 1, stderr=\(fwRes.err)")
        XCTAssertTrue(fwRes.out.contains(SignatureCatalog.directSyscallRule.pattern))

        // Empty framework directory without binary or Info.plist must fail closed (exit 2)
        let emptyFw = makeTempURL("Empty.framework")
        try FileManager.default.createDirectory(at: emptyFw, withIntermediateDirectories: true)
        let emptyFwRes = try await runCLIInProcess(["scan", emptyFw.path])
        XCTAssertEqual(emptyFwRes.code, 2)

        // 2. Extensionless ZIP/IPA file (`PK\x03\x04` magic) -> scanned as IPA and exits 1
        let plist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.noext.ipa",
            "CFBundleExecutable": "NoExt"
        ], format: .xml, options: 0)
        let noExtIPA = makeTempURL("disguised_package_without_extension")
        try buildZip([
            .init(path: "Payload/NoExt.app/Info.plist", payload: plist),
            .init(path: "Payload/NoExt.app/NoExt", payload: evilMachO, unixMode: 0o100755)
        ]).write(to: noExtIPA)
        let noExtRes = try await runCLIInProcess(["scan", noExtIPA.path])
        XCTAssertEqual(noExtRes.code, 1, "Extensionless ZIP/IPA must be scanned by IPAPackageScanner and exit 1")

        // 3. Symlinked CLI scan target & symlinked -o output target & readPrefixBytes symlink -> rejected with O_NOFOLLOW
        let symScan = makeTempURL("sym_target.ipa")
        symlink(noExtIPA.path, symScan.path)
        XCTAssertNil(IPAPackageScanner.readPrefixBytes(of: symScan))

        let symScanRes = try await runCLIInProcess(["scan", symScan.path])
        XCTAssertEqual(symScanRes.code, 2, "Symlinked CLI scan target must be refused (exit 2)")

        let victimFile = makeTempURL("victim_overwrite.txt")
        try Data("DO_NOT_TOUCH".utf8).write(to: victimFile)
        let symOut = makeTempURL("sym_report_out.txt")
        symlink(victimFile.path, symOut.path)
        let symOutRes = try await runCLIInProcess(["--firmware-radar", "26.2", "-o", symOut.path])
        XCTAssertEqual(symOutRes.code, 2, "Symlinked -o output path must be refused")
        XCTAssertEqual(String(decoding: try Data(contentsOf: victimFile), as: UTF8.self), "DO_NOT_TOUCH")
    }

    // MARK: - 8. WhitelistEngine Custom Rule allowedAppGroups allSatisfy Anti-Piggybacking

    func test_r10_08_whitelistEngine_customRuleAllowedAppGroupsEnforcesAllSatisfy() {
        let engine = WhitelistEngine()
        engine.registerCustomTool(WhitelistedTool(
            name: "CorpAuditTool",
            allowedBundleIds: ["com.corp.auditor*"],
            allowedAppGroups: ["group.com.corp.auditor*"],
            allowedTeamIds: ["CORP112233"],
            expectedSignatures: [IOCTokenArmor.tCqCreate]
        ))

        // Authorized App Group(s) only -> whitelisted
        let cleanMatch = engine.isWhitelisted(
            bundleId: "com.corp.auditor.ios",
            appGroups: ["group.com.corp.auditor.main", "group.com.corp.auditor.cache"],
            matchedSignatures: [IOCTokenArmor.tCqCreate],
            teamId: "CORP112233"
        )
        XCTAssertTrue(cleanMatch.isWhitelisted)
        XCTAssertEqual(cleanMatch.toolName, "CorpAuditTool")

        // Piggybacking victim wallet/messenger App Groups onto a custom rule -> MUST BE REJECTED
        for victimGroup in ["group.io.metamask", "group.org.telegram", "group.com.unrelated.victim"] {
            let piggybacked = engine.isWhitelisted(
                bundleId: "com.corp.auditor.ios",
                appGroups: ["group.com.corp.auditor.main", victimGroup],
                matchedSignatures: [IOCTokenArmor.tCqCreate],
                teamId: "CORP112233"
            )
            XCTAssertFalse(piggybacked.isWhitelisted,
                           "Custom whitelist rule must reject piggybacked third-party group '\(victimGroup)'")
        }

        // Empty allowedAppGroups rule (e.g. CLI --whitelist) must also block Apple system group piggybacking
        engine.registerCustomTool(WhitelistedTool(
            name: "CLIStyleRule",
            allowedBundleIds: ["com.corp.cliapp"],
            allowedAppGroups: []
        ))
        XCTAssertFalse(engine.isWhitelisted(
            bundleId: "com.corp.cliapp",
            appGroups: [IOCTokenArmor.tGestaltGroup]
        ).isWhitelisted)
    }

    // MARK: - 9. ContainerScanner Climb-Above-Root Symlinks, Tilde Rejection & Caches Truncation Fail-Closed

    func test_r10_09_containerScanner_climbAboveRootCollapse_tildeRejection_andTruncationIndicators() throws {
        let parentDir = makeTempURL("AppGroupsRoot")
        let myUUID = "11111111-2222-3333-4444-555555555555"
        let victimUUID = "99999999-8888-7777-6666-555555555555"
        let containerURL = parentDir.appendingPathComponent(myUUID)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")
        let docsURL = containerURL.appendingPathComponent("Documents")
        try FileManager.default.createDirectory(at: cachesURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: docsURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: parentDir.appendingPathComponent(victimUUID), withIntermediateDirectories: true)

        // 1. Relative climb-above-root that lexically collapses back into containerRoot MUST be flagged escaping!
        XCTAssertTrue(ContainerScanner.shared.isDestinationEscaping(
            destination: "../../../\(victimUUID)/../\(myUUID)/Documents",
            relativeTo: cachesURL,
            containerRoot: containerURL
        ))
        XCTAssertTrue(ContainerScanner.shared.isDestinationEscaping(
            destination: "../../../\(myUUID)/Library/Caches",
            relativeTo: cachesURL,
            containerRoot: containerURL
        ))
        // Absolute path traversing `..` through parent/victim before entering containerRoot -> escaping!
        XCTAssertTrue(ContainerScanner.shared.isDestinationEscaping(
            destination: "\(parentDir.path)/\(victimUUID)/../\(myUUID)/Documents",
            relativeTo: cachesURL,
            containerRoot: containerURL
        ))
        // Tilde path `~/Library/Caches` -> escaping!
        XCTAssertTrue(ContainerScanner.shared.isDestinationEscaping(
            destination: "~/Library/Caches",
            relativeTo: cachesURL,
            containerRoot: containerURL
        ))
        // Negative control: strictly internal relative symlink `../../Documents` -> NOT escaping!
        XCTAssertFalse(ContainerScanner.shared.isDestinationEscaping(
            destination: "../../Documents",
            relativeTo: cachesURL,
            containerRoot: containerURL
        ))

        // 2. Depth > maxDepth (8) inside Library/Caches hiding an escaping symlink at depth 10 -> CONTAINER_CACHES_SCAN_TRUNCATED (.highRisk)
        let deepContainer = makeTempURL("deep_truncated_container")
        var deepCursor = deepContainer.appendingPathComponent("Library/Caches")
        for level in 0...9 {
            deepCursor = deepCursor.appendingPathComponent("d\(level)")
        }
        try FileManager.default.createDirectory(at: deepCursor, withIntermediateDirectories: true)
        symlink("/private/var/mobile/Library/SMS/sms.db", deepCursor.appendingPathComponent("hidden_escape").path)

        let deepRes = try ContainerScanner.shared.scanContainer(at: deepContainer)
        XCTAssertFalse(deepRes.isClean, "Caches directory exceeding maxDepth must NEVER report isClean == true")
        XCTAssertTrue(deepRes.indicators.contains { $0.signature == "CONTAINER_CACHES_SCAN_TRUNCATED" && $0.severity == .highRisk })

        // Verify entry-cap truncation directly via inspectDirectoryChildren(maxEntries: 5)
        let capContainer = makeTempURL("entry_cap_container")
        let capCaches = capContainer.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: capCaches, withIntermediateDirectories: true)
        for idx in 0..<8 {
            try Data("x".utf8).write(to: capCaches.appendingPathComponent("f\(idx).dat"))
        }
        let outcome = ContainerScanner.shared.inspectDirectoryChildren(
            dirURL: capCaches,
            containerRootURL: capContainer,
            maxDepth: 8,
            maxEntries: 5
        )
        XCTAssertTrue(outcome.hitEntryLimit)
        XCTAssertEqual(outcome.inspectedEntries, 5)
    }

    // MARK: - 10. InstalledAppRegistryScanner TrollStore iTunesMetadata, System-Registration & TestFlight Spoofing

    func test_r10_10_registryScanner_trollStoreITunesMeta_systemRegistrationSpoof_testFlightSpoof_andCDATAStream() throws {
        let scanner = InstalledAppRegistryScanner.shared

        // 1. Repackaged MetaMask carrying ApplicationDSID / iTunesMetadata (`hasAppStoreMetadata == true`) signed by TrollStore/Ad-Hoc/Dev
        for spoofSigner in [nil, "Ad Hoc", "ldid", "Apple Development: attacker@evil.io (TEAM000000)"] as [String?] {
            var dict: [String: Any] = [
                "CFBundleIdentifier": "io.metamask.MetaMask",
                "CFBundleDisplayName": "MetaMask",
                "CFBundleShortVersionString": "7.30.0",
                "ApplicationType": "User",
                "ProfileValidated": false,
                "ApplicationDSID": 888777666,
                "iTunesMetadata": ["itemId": 1438144202],
                "Path": "/private/var/containers/Bundle/Application/UUID-FAKE/MetaMask.app"
            ]
            if let s = spoofSigner { dict["SignerIdentity"] = s }
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary(dict))
            let (ch, encrypted) = scanner.classifyChannel(for: rec)
            XCTAssertEqual(ch, .developerSideloaded, "Signer=\(spoofSigner ?? "nil") with iTunesMetadata must NOT classify as .appStore")
            XCTAssertFalse(encrypted)

            let defaultFindings = scanner.evaluateRecords([rec], includeAppStoreApps: false)
            XCTAssertEqual(defaultFindings.count, 1)
            XCTAssertEqual(defaultFindings.first?.riskTier, .highRisk)
            XCTAssertTrue(defaultFindings.first?.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" } ?? false)
        }

        // 2. TrollStore "Switch to System Registration" (`com.apple.troll.persistence` & `com.apple.Health` with no-sandbox) in /var/containers/Bundle/Application
        let trollSysFake = InstalledAppRegistryRecord(
            bundleId: "com.apple.troll.persistence",
            displayName: "PersistenceHelper",
            version: "2.0",
            applicationType: "System",
            signerIdentity: nil,
            profileValidated: false,
            booleanEntitlements: ["com.apple.private.security.no-sandbox": true],
            allEntitlementKeys: ["com.apple.private.security.no-sandbox"],
            bundlePath: "/var/containers/Bundle/Application/UUID-TROLL/PersistenceHelper.app"
        )
        let trollSysCleanArbitrary = InstalledAppRegistryRecord(
            bundleId: "com.apple.custom.backdoor",
            displayName: "SystemHelper",
            version: "1.0",
            applicationType: "System",
            signerIdentity: nil,
            profileValidated: false,
            appGroups: ["group.r10.backdoor"],
            bundlePath: "/private/var/containers/Bundle/Application/UUID-BD/Backdoor.app"
        )
        let trollHijackedHealth = InstalledAppRegistryRecord(
            bundleId: "com.apple.Health",
            displayName: "健康",
            version: "1.0",
            applicationType: "System",
            signerIdentity: nil,
            profileValidated: false,
            booleanEntitlements: ["com.apple.private.security.no-container": true],
            allEntitlementKeys: ["com.apple.private.security.no-container"],
            bundlePath: "/private/var/containers/Bundle/Application/UUID-H/Health.app"
        )
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(trollSysFake))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(trollSysCleanArbitrary))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(trollHijackedHealth))
        XCTAssertEqual(scanner.evaluateRecords([trollSysFake, trollHijackedHealth], includeAppStoreApps: false).count, 2)

        // 3. Fake SignerIdentity containing "testflight" WITHOUT beta-reports-active, and ad-hoc beta-reports-active WITHOUT Apple Distribution signer
        let fakeTFSigner = InstalledAppRegistryRecord(
            bundleId: "io.metamask.tfspoof",
            displayName: "MetaMask",
            version: "1.0",
            applicationType: "User",
            signerIdentity: "iPhone Distribution: TestFlight Spoof Enterprise",
            profileValidated: true,
            bundlePath: "/var/containers/Bundle/Application/UUID-TF1/MetaMask.app"
        )
        let adHocBetaEnt = InstalledAppRegistryRecord(
            bundleId: "org.telegram.messenger",
            displayName: "Telegram",
            version: "10.0",
            applicationType: "User",
            signerIdentity: nil,
            profileValidated: false,
            booleanEntitlements: ["beta-reports-active": true],
            allEntitlementKeys: ["beta-reports-active"],
            bundlePath: "/var/containers/Bundle/Application/UUID-TF2/Telegram.app"
        )
        XCTAssertEqual(scanner.classifyChannel(for: fakeTFSigner).channel, .enterpriseInHouse)
        XCTAssertEqual(scanner.classifyChannel(for: adHocBetaEnt).channel, .developerSideloaded)
        let tfSpoofFindings = scanner.evaluateRecords([fakeTFSigner, adHocBetaEnt], includeAppStoreApps: false)
        XCTAssertEqual(tfSpoofFindings.count, 2)
        XCTAssertTrue(tfSpoofFindings.allSatisfy { $0.riskTier == .highRisk })

        // 4. Concatenated XML plist stream where Packet 1 embeds <![CDATA[</plist>]]> and <!--</plist>-->
        let packet1 = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!-- </plist> -->
        <plist version="1.0"><dict>
            <key>CurrentList</key>
            <array><dict>
                <key>CFBundleIdentifier</key><string>com.r10.pkt1</string>
                <key>CFBundleDisplayName</key><string><![CDATA[AppOne </plist> Name]]></string>
                <key>ApplicationType</key><string>User</string>
                <key>ProfileValidated</key><true/>
            </dict></array>
        </dict></plist>
        """
        let packet2 = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
            <key>CurrentList</key>
            <array><dict>
                <key>CFBundleIdentifier</key><string>com.r10.pkt2</string>
                <key>CFBundleDisplayName</key><string>AppTwo</string>
                <key>ApplicationType</key><string>User</string>
                <key>ProfileValidated</key><true/>
            </dict></array>
        </dict></plist>
        """
        let streamRecords = try scanner.parseSnapshotData(Data((packet1 + packet2).utf8))
        XCTAssertEqual(Set(streamRecords.map(\.bundleId)), ["com.r10.pkt1", "com.r10.pkt2"])

        // 5. O_NOFOLLOW symlink rejection on parseSnapshotFile & LockdownPairingFile.parse(from:) + bilingual EN/zh-Hans verification
        let realSnap = makeTempURL("real_snap.xml")
        try Data(packet2.utf8).write(to: realSnap)
        let symSnap = makeTempURL("sym_snap.xml")
        symlink(realSnap.path, symSnap.path)
        XCTAssertThrowsError(try scanner.parseSnapshotFile(at: symSnap))
        XCTAssertThrowsError(try LockdownPairingFile.parse(from: symSnap))

        let truncContainer = makeTempURL("i18n_trunc_container")
        let truncCaches = truncContainer.appendingPathComponent("Library/Caches")
        var deep = truncCaches
        for idx in 0...9 { deep = deep.appendingPathComponent("l\(idx)") }
        try FileManager.default.createDirectory(at: deep, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: deep.appendingPathComponent("leaf"))

        WQLocale.overrideLanguageCode = "en"
        let enInd = try ContainerScanner.shared.scanContainer(at: truncContainer).indicators.first { $0.signature == "CONTAINER_CACHES_SCAN_TRUNCATED" }
        XCTAssertTrue(enInd?.description.contains("truncated") ?? false)

        WQLocale.overrideLanguageCode = "zh-Hans"
        let zhInd = try ContainerScanner.shared.scanContainer(at: truncContainer).indicators.first { $0.signature == "CONTAINER_CACHES_SCAN_TRUNCATED" }
        XCTAssertTrue(zhInd?.description.contains("截断") ?? false)
    }

    // MARK: - 11. O(N) Unclosed <plist> DoS, >16 Decoy Plists, UTF-16 XML & Forged cryptid=1 CodeSignature Spoofing

    func test_r10_11_unclosedPlistDoS_manyDecoys_utf16XML_andForgedCryptid1CodeSignSpoof() throws {
        // 1. 15,000 unclosed `<plist >` tokens in ~120 KB MUST complete in strict O(N) (< 0.5s), never O(N^2)
        let unclosedFlood = String(repeating: "<plist >", count: 15_000)
        let floodData = Data(unclosedFlood.utf8)
        let t0 = CFAbsoluteTimeGetCurrent()
        let floodRanges = CSBlobParser.scanXMLPlistDocumentRanges(in: floodData)
        let floodElapsed = CFAbsoluteTimeGetCurrent() - t0
        XCTAssertTrue(floodRanges.isEmpty)
        XCTAssertLessThan(floodElapsed, 0.5, "15,000 unclosed <plist > tokens took \(floodElapsed)s — expected O(N) memoized scan")

        // 2. 22 decoy `<plist><dict/></plist>` documents inside XML comments & before real entitlements / Enterprise mobileprovision
        let twentyTwoCommentDecoys = Array(repeating: "<!-- <plist version=\"1.0\"><dict><key>k</key><true/></dict></plist> -->", count: 22).joined(separator: "\n")
        let twentyTwoEmptyDictDecoys = Array(repeating: "<plist version=\"1.0\"><dict/></plist>", count: 22).joined(separator: "\n")
        let realEntXML = """
        \(twentyTwoCommentDecoys)
        \(twentyTwoEmptyDictDecoys)
        <plist version="1.0"><dict>
            <key>com.apple.security.application-groups</key>
            <array><string>group.com.r10.twenty.two</string></array>
        </dict></plist>
        """
        let parsedManyEnt = try CSBlobParser.shared.parseXMLPlist(Data(realEntXML.utf8))
        XCTAssertEqual(CSBlobParser.shared.extractAppGroups(fromPlistDict: parsedManyEnt), ["group.com.r10.twenty.two"])

        let entProfileAfterDecoys = """
        \(twentyTwoCommentDecoys)
        \(twentyTwoEmptyDictDecoys)
        <plist version="1.0"><dict>
            <key>TeamIdentifier</key><array><string>ENT9988776</string></array>
            <key>ProvisionsAllDevices</key><true/>
        </dict></plist>
        """
        // Wrap inside nested BER constructed 0x24 OCTET STRING following PKCS#7 id-data OID
        let entPayloadBytes = Data(entProfileAfterDecoys.utf8)
        var berCMS = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])
        berCMS.append(contentsOf: [0xA0, 0x80, 0x24, 0x80, 0x24, 0x80]) // nested indefinite constructed OCTET STRING
        let lenHi = UInt8((entPayloadBytes.count >> 8) & 0xFF)
        let lenLo = UInt8(entPayloadBytes.count & 0xFF)
        berCMS.append(contentsOf: [0x04, 0x82, lenHi, lenLo])
        berCMS.append(entPayloadBytes)
        berCMS.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let berClass = ChannelClassifier.classify(cryptid: 0, mobileprovisionData: berCMS)
        XCTAssertEqual(berClass.channel, .enterpriseInHouse)
        XCTAssertEqual(berClass.teamIdentifier, "ENT9988776")

        // 3. UTF-16LE and UTF-16BE XML Plists (UTF-16LE ends with `0x3E 0x00`, which previously got corrupted by trailing-0x00 strip)
        let xmlString = """
        <?xml version="1.0" encoding="UTF-16"?>
        <plist version="1.0"><dict>
            <key>com.apple.security.application-groups</key>
            <array><string>group.com.r10.utf16</string></array>
            <key>TeamIdentifier</key><array><string>UTF16TEAM1</string></array>
            <key>ProvisionsAllDevices</key><true/>
        </dict></plist>
        """
        var utf16LE = Data([0xFF, 0xFE])
        utf16LE.append(try XCTUnwrap(xmlString.data(using: .utf16LittleEndian)))
        var utf16BE = Data([0xFE, 0xFF])
        utf16BE.append(try XCTUnwrap(xmlString.data(using: .utf16BigEndian)))

        for encodedPlist in [utf16LE, utf16BE] {
            let d = try CSBlobParser.shared.parseXMLPlist(encodedPlist)
            XCTAssertEqual(CSBlobParser.shared.extractAppGroups(fromPlistDict: d), ["group.com.r10.utf16"])
            let c = ChannelClassifier.classify(cryptid: 0, mobileprovisionData: encodedPlist)
            XCTAssertEqual(c.channel, .enterpriseInHouse)
            XCTAssertEqual(c.teamIdentifier, "UTF16TEAM1")
        }

        // 4. Forged `cryptid = 1` WITHOUT `embedded.mobileprovision`:
        //    Build a Mach-O with `cryptid = 1` covering `__TEXT` and sign it ad-hoc (`CS_ADHOC` CodeDirectory + empty CMS Wrapper).
        var adHocSuperBlob = Data()
        var codeDir = Data()
        codeDir.r10be32(CSBlobConstants.codeDirectoryMagic)
        codeDir.r10be32(44) // length
        codeDir.r10be32(0x0002_0400) // version
        codeDir.r10be32(CSBlobConstants.csAdhocFlag) // flags = CS_ADHOC (0x2)
        while codeDir.count < 44 { codeDir.append(0) }

        var emptyCMS = Data()
        emptyCMS.r10be32(CSBlobConstants.blobWrapperMagic)
        emptyCMS.r10be32(8)

        let sbLen = 12 + 16 + codeDir.count + emptyCMS.count
        adHocSuperBlob.r10be32(CSBlobConstants.superBlobMagic)
        adHocSuperBlob.r10be32(UInt32(sbLen))
        adHocSuperBlob.r10be32(2)
        adHocSuperBlob.r10be32(CSBlobConstants.slotCodeDirectory)
        adHocSuperBlob.r10be32(28)
        adHocSuperBlob.r10be32(CSBlobConstants.slotCMSSignature)
        adHocSuperBlob.r10be32(UInt32(28 + codeDir.count))
        adHocSuperBlob.append(codeDir)
        adHocSuperBlob.append(emptyCMS)

        XCTAssertEqual(CSBlobParser.shared.inspectCodeSignatureTrust(from: adHocSuperBlob), .adHocOrUnsigned)

        var codeDirPayload = Data()
        codeDirPayload.r10be32(0x0002_0400) // version
        codeDirPayload.r10be32(CSBlobConstants.csAdhocFlag) // flags = CS_ADHOC (0x2)
        while codeDirPayload.count < 36 { codeDirPayload.append(0) }

        let forgedEncMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 4096,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            rawCodeSignatureSlot: (
                slot: CSBlobConstants.slotCodeDirectory,
                magic: CSBlobConstants.codeDirectoryMagic,
                data: codeDirPayload
            ),
            textInstructions: [Self.retWord]
        ))
        let walletPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "io.metamask.MetaMask",
            "CFBundleDisplayName": "MetaMask",
            "CFBundleExecutable": "MetaMask",
            "CFBundleShortVersionString": "7.30.0"
        ], format: .xml, options: 0)
        let forgedIPA = makeTempURL("forged_cryptid1_adhoc_metamask.ipa")
        try buildZip([
            .init(path: "Payload/MetaMask.app/Info.plist", payload: walletPlist),
            .init(path: "Payload/MetaMask.app/MetaMask", payload: forgedEncMachO, unixMode: 0o100755)
        ]).write(to: forgedIPA)

        let forgedFinding = try IPAPackageScanner.shared.scan(ipaURL: forgedIPA)
        XCTAssertEqual(forgedFinding.installChannel, .developerSideloaded, "Ad-hoc signed cryptid=1 binary without mobileprovision must NOT classify as .appStore")
        XCTAssertEqual(forgedFinding.riskTier, .highRisk)
        XCTAssertTrue(forgedFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })

        // 5. Self-signed X.509 PKCS#7 CMS signature spoofing `CN=Apple iPhone OS Application Signing` (CS_ADHOC == 0, cryptid == 1)
        //    MUST fail Apple Root CA verification in `CSBlobParser.inspectCodeSignatureTrust` and classify as `.developerSideloaded`!
        let certDir = makeTempURL("spoof_cms_cert")
        try FileManager.default.createDirectory(at: certDir, withIntermediateDirectories: true)
        let keyURL = certDir.appendingPathComponent("k.pem")
        let certURL = certDir.appendingPathComponent("c.pem")
        let cmsInputURL = certDir.appendingPathComponent("in.bin")
        let cmsDerURL = certDir.appendingPathComponent("cms.der")
        try Data("cdhash".utf8).write(to: cmsInputURL)

        let reqProc = Process()
        reqProc.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        reqProc.arguments = [
            "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", keyURL.path, "-out", certURL.path,
            "-days", "1", "-nodes", "-subj", "/CN=Apple iPhone OS Application Signing"
        ]
        reqProc.standardError = FileHandle.nullDevice
        try reqProc.run(); reqProc.waitUntilExit()
        XCTAssertEqual(reqProc.terminationStatus, 0)

        let signProc = Process()
        signProc.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        signProc.arguments = [
            "smime", "-sign", "-binary",
            "-in", cmsInputURL.path,
            "-signer", certURL.path, "-inkey", keyURL.path,
            "-outform", "DER", "-nodetach", "-out", cmsDerURL.path
        ]
        signProc.standardError = FileHandle.nullDevice
        try signProc.run(); signProc.waitUntilExit()
        XCTAssertEqual(signProc.terminationStatus, 0)

        let spoofCMSDer = try Data(contentsOf: cmsDerURL)
        var nonAdHocCodeDir = Data()
        nonAdHocCodeDir.r10be32(CSBlobConstants.codeDirectoryMagic)
        nonAdHocCodeDir.r10be32(44)
        nonAdHocCodeDir.r10be32(0x0002_0400)
        nonAdHocCodeDir.r10be32(0) // flags = 0 (CS_ADHOC NOT set!)
        while nonAdHocCodeDir.count < 44 { nonAdHocCodeDir.append(0) }

        var cmsWrapper = Data()
        cmsWrapper.r10be32(CSBlobConstants.blobWrapperMagic)
        cmsWrapper.r10be32(UInt32(8 + spoofCMSDer.count))
        cmsWrapper.append(spoofCMSDer)

        var spoofCMSSuperBlob = Data()
        spoofCMSSuperBlob.r10be32(CSBlobConstants.superBlobMagic)
        spoofCMSSuperBlob.r10be32(UInt32(28 + nonAdHocCodeDir.count + cmsWrapper.count))
        spoofCMSSuperBlob.r10be32(2)
        spoofCMSSuperBlob.r10be32(CSBlobConstants.slotCodeDirectory)
        spoofCMSSuperBlob.r10be32(28)
        spoofCMSSuperBlob.r10be32(CSBlobConstants.slotCMSSignature)
        spoofCMSSuperBlob.r10be32(UInt32(28 + nonAdHocCodeDir.count))
        spoofCMSSuperBlob.append(nonAdHocCodeDir)
        spoofCMSSuperBlob.append(cmsWrapper)

        let spoofTrust = CSBlobParser.shared.inspectCodeSignatureTrust(from: spoofCMSSuperBlob)
        XCTAssertEqual(spoofTrust, .nonAppStoreSigner(subjectSummary: "Apple iPhone OS Application Signing"))

        let forgedCMSMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 4096,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            rawCodeSignatureSlot: (
                slot: CSBlobConstants.slotCMSSignature,
                magic: CSBlobConstants.blobWrapperMagic,
                data: spoofCMSDer
            ),
            textInstructions: [Self.retWord]
        ))
        let forgedCMSIPA = makeTempURL("forged_cryptid1_spoofcms_metamask.ipa")
        try buildZip([
            .init(path: "Payload/MetaMask.app/Info.plist", payload: walletPlist),
            .init(path: "Payload/MetaMask.app/MetaMask", payload: forgedCMSMachO, unixMode: 0o100755)
        ]).write(to: forgedCMSIPA)
        let forgedCMSFinding = try IPAPackageScanner.shared.scan(ipaURL: forgedCMSIPA)
        XCTAssertEqual(forgedCMSFinding.installChannel, .developerSideloaded)
        XCTAssertEqual(forgedCMSFinding.riskTier, .highRisk)
        XCTAssertTrue(forgedCMSFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })
    }

    // MARK: - 12. MachOParser lazy_bind 0x40..0x4F Operand Swallow, >32 Steps, __stub_helper & Inflated Chained Fixups

    func test_r10_12_machoParser_lazyBind0x40Swallow_longDoBindSteps_stubHelper_andInflatedChainedFixups() throws {
        let fsSym = "_" + IOCTokenArmor.tFsgetpath
        let cmSym = "_" + IOCTokenArmor.tCMSessionSetProp
        let cqSym = "_" + IOCTokenArmor.tCqCreate

        // Build lazy_bind stream exercising all 4 previously missed edge cases:
        // (a) [0xE0, 0x11, 0x72, 0x40, 0x40, "_fsgetpath\0", 0x90, 0x00] (`0x40` ULEB operand before `0x40` SET_SYMBOL)
        // (b) [0xE0, 0x11, 0x72, 0x40, 0x41, "_CMSessionSetProperty\0", 0x90, 0x00] (`0x40` before `0x41` WEAK_IMPORT `'A'`)
        // (c) 45 `0x50` opcodes (> 32 old reachesDoBind limit) before `0x90` DO_BIND on `_container_query_create`
        var lazyStream = Data([0xE0, 0x11, 0x72, 0x40, 0x40])
        lazyStream.append(Data(fsSym.utf8))
        lazyStream.append(contentsOf: [0x00, 0x90, 0x00])

        let stubTargetOffset = UInt32(lazyStream.count + 4) // points directly at 0x41 below
        lazyStream.append(contentsOf: [0xE0, 0x11, 0x72, 0x40, 0x41])
        lazyStream.append(Data(cmSym.utf8))
        lazyStream.append(contentsOf: [0x00, 0x90, 0x00])

        lazyStream.append(contentsOf: [0xE0, 0x40])
        lazyStream.append(Data(cqSym.utf8))
        lazyStream.append(0x00)
        lazyStream.append(contentsOf: Array(repeating: UInt8(0x51), count: 45))
        lazyStream.append(contentsOf: [0x90, 0x00])
        while lazyStream.count % 8 != 0 { lazyStream.append(0x00) }

        // Build Mach-O64 with `__TEXT,__stub_helper` section jumping to `stubTargetOffset` AND `LC_DYLD_INFO_ONLY` BEFORE `LC_SEGMENT_64`
        let segCmdSize = 72 + 80 // 1 section: __stub_helper
        let sizeofcmds = 48 + segCmdSize + 72 // LC_DYLD_INFO_ONLY + __TEXT + __LINKEDIT = 272
        let textSize = 512
        let stubOff = 384
        let lazyOffset = textSize

        var bin = Data()
        bin.r10le32(MH_MAGIC_64)
        bin.r10le32(UInt32(bitPattern: CPU_TYPE_ARM64))
        bin.r10le32(0)
        bin.r10le32(UInt32(MH_EXECUTE))
        bin.r10le32(3)
        bin.r10le32(UInt32(sizeofcmds))
        bin.r10le32(0)
        bin.r10le32(0)

        // Put LC_DYLD_INFO_ONLY FIRST (tests deferred bind resolution independent of load command ordering)
        bin.r10le32(0x8000_0022)
        bin.r10le32(48)
        bin.r10le32(0); bin.r10le32(0)
        bin.r10le32(0); bin.r10le32(0)
        bin.r10le32(0); bin.r10le32(0)
        bin.r10le32(UInt32(lazyOffset))
        bin.r10le32(UInt32(lazyStream.count))
        bin.r10le32(0); bin.r10le32(0)

        // LC_SEGMENT_64 __TEXT with __stub_helper
        bin.r10le32(UInt32(LC_SEGMENT_64))
        bin.r10le32(UInt32(segCmdSize))
        var tName = Array("__TEXT".utf8); while tName.count < 16 { tName.append(0) }
        bin.append(contentsOf: tName)
        var tVma: UInt64 = 0x100000000; Swift.withUnsafeBytes(of: &tVma) { bin.append(contentsOf: $0) }
        var tVms = UInt64(textSize).littleEndian; Swift.withUnsafeBytes(of: &tVms) { bin.append(contentsOf: $0) }
        var tFoff: UInt64 = 0; Swift.withUnsafeBytes(of: &tFoff) { bin.append(contentsOf: $0) }
        var tFsz = UInt64(textSize).littleEndian; Swift.withUnsafeBytes(of: &tFsz) { bin.append(contentsOf: $0) }
        bin.r10le32(5); bin.r10le32(5)
        bin.r10le32(1) // nsects = 1
        bin.r10le32(0)

        var shName = Array("__stub_helper".utf8); while shName.count < 16 { shName.append(0) }
        bin.append(contentsOf: shName)
        bin.append(contentsOf: tName)
        var shAddr = UInt64(0x100000000 + stubOff).littleEndian; Swift.withUnsafeBytes(of: &shAddr) { bin.append(contentsOf: $0) }
        var shSz: UInt64 = 12; Swift.withUnsafeBytes(of: &shSz) { bin.append(contentsOf: $0) }
        bin.r10le32(UInt32(stubOff))
        bin.r10le32(2); bin.r10le32(0); bin.r10le32(0)
        bin.r10le32(0x8000_0400)
        bin.r10le32(0); bin.r10le32(0); bin.r10le32(0) // reserved1, reserved2, reserved3 (80-byte section_64)

        // LC_SEGMENT_64 __LINKEDIT
        bin.r10le32(UInt32(LC_SEGMENT_64))
        bin.r10le32(72)
        var lName = Array("__LINKEDIT".utf8); while lName.count < 16 { lName.append(0) }
        bin.append(contentsOf: lName)
        var lVma: UInt64 = 0x100004000; Swift.withUnsafeBytes(of: &lVma) { bin.append(contentsOf: $0) }
        var lVms: UInt64 = 0x4000; Swift.withUnsafeBytes(of: &lVms) { bin.append(contentsOf: $0) }
        var lFoff = UInt64(lazyOffset).littleEndian; Swift.withUnsafeBytes(of: &lFoff) { bin.append(contentsOf: $0) }
        var lFsz = UInt64(lazyStream.count).littleEndian; Swift.withUnsafeBytes(of: &lFsz) { bin.append(contentsOf: $0) }
        bin.r10le32(1); bin.r10le32(1); bin.r10le32(0); bin.r10le32(0)

        while bin.count < stubOff {
            bin.r10le32(Self.retWord)
        }
        // ARM64 __stub_helper entry: ldr w16, #8 (0x18000050); b #0 (0x14000000); .long stubTargetOffset
        bin.r10le32(0x1800_0050)
        bin.r10le32(0x1400_0000)
        bin.r10le32(stubTargetOffset)
        while bin.count < textSize {
            bin.r10le32(Self.retWord)
        }
        bin.append(lazyStream)

        let parsed = try MachOParser.parse(data: bin)
        XCTAssertTrue(parsed.containsSymbol(IOCTokenArmor.tFsgetpath))
        XCTAssertTrue(parsed.containsSymbol(IOCTokenArmor.tCMSessionSetProp))
        XCTAssertTrue(parsed.containsSymbol(IOCTokenArmor.tCqCreate))

        // (d) Inflated `LC_DYLD_CHAINED_FIXUPS` `imports_count = 50_000` (`importsOffset + 50_000*4 > datasize`)
        var fixups = Data()
        fixups.r10le32(0) // fixups_version
        fixups.r10le32(0) // starts_offset
        fixups.r10le32(28) // imports_offset
        fixups.r10le32(32) // symbols_offset (1 real 4-byte import at 28..<32)
        fixups.r10le32(50_000) // inflated imports_count!
        fixups.r10le32(1) // DYLD_CHAINED_IMPORT (stride = 4)
        fixups.r10le32(0) // uncompressed symbols
        // 1 DYLD_CHAINED_IMPORT: lib_ordinal=1, weak=0, name_offset=1 -> (1 << 9) | 1 = 0x201
        fixups.r10le32((1 << 9) | 1)
        fixups.append(0x00)
        fixups.append(Data(fsSym.utf8))
        fixups.append(0x00)
        while fixups.count % 8 != 0 { fixups.append(0x00) }

        var cfBin = Data()
        cfBin.r10le32(MH_MAGIC_64)
        cfBin.r10le32(UInt32(bitPattern: CPU_TYPE_ARM64))
        cfBin.r10le32(0)
        cfBin.r10le32(UInt32(MH_EXECUTE))
        cfBin.r10le32(2)
        cfBin.r10le32(72 + 16) // LC_SEGMENT_64 + LC_DYLD_CHAINED_FIXUPS
        cfBin.r10le32(0); cfBin.r10le32(0)

        cfBin.r10le32(UInt32(LC_SEGMENT_64))
        cfBin.r10le32(72)
        cfBin.append(contentsOf: tName)
        Swift.withUnsafeBytes(of: &tVma) { cfBin.append(contentsOf: $0) }
        var cfSz = UInt64(256 + fixups.count).littleEndian
        Swift.withUnsafeBytes(of: &cfSz) { cfBin.append(contentsOf: $0) }
        Swift.withUnsafeBytes(of: &tFoff) { cfBin.append(contentsOf: $0) }
        Swift.withUnsafeBytes(of: &cfSz) { cfBin.append(contentsOf: $0) }
        cfBin.r10le32(5); cfBin.r10le32(5); cfBin.r10le32(0); cfBin.r10le32(0)

        cfBin.r10le32(0x8000_0034) // LC_DYLD_CHAINED_FIXUPS
        cfBin.r10le32(16)
        cfBin.r10le32(256)
        cfBin.r10le32(UInt32(fixups.count))
        while cfBin.count < 256 { cfBin.r10le32(Self.retWord) }
        cfBin.append(fixups)

        let cfParsed = try MachOParser.parse(data: cfBin)
        XCTAssertTrue(cfParsed.containsSymbol(IOCTokenArmor.tFsgetpath), "Inflated imports_count must clamp instead of blinding chained imports")
    }

    // MARK: - 13. POSIX namei Chained-Symlink + `..` Escape & Pass-3 Materialization Order

    func test_r10_13_posixNameiChainedSymlinkDotDotEscape_andPass3FileBeforeDirOrdering() throws {
        // 1. ContainerScanner: `hop1 -> ../..` (points to containerRoot) + `escape -> hop1/../VictimUUID/Documents/wallet.dat`
        let rootDir = makeTempURL("NameiContainers")
        let myContainer = rootDir.appendingPathComponent("MyUUID")
        let victimDocs = rootDir.appendingPathComponent("VictimUUID/Documents")
        let caches = myContainer.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: caches, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: victimDocs, withIntermediateDirectories: true)
        symlink("../..", caches.appendingPathComponent("hop1").path)
        symlink("hop1/../VictimUUID/Documents/wallet.dat", caches.appendingPathComponent("escape").path)

        XCTAssertTrue(ContainerScanner.shared.isDestinationEscaping(
            destination: "hop1/../VictimUUID/Documents/wallet.dat",
            relativeTo: caches,
            containerRoot: myContainer
        ), "POSIX namei expands hop1 (../..) BEFORE '..', escaping containerRoot into VictimUUID")
        let cScan = try ContainerScanner.shared.scanContainer(at: myContainer)
        XCTAssertFalse(cScan.isClean)
        XCTAssertTrue(cScan.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" && $0.severity == .highRisk })

        // 2. IPAPackageScanner.resolveInBundleArchivePath: `PlugIns/Sub/hop1 -> ..` + `PlugIns/Sub/escape -> hop1/../../Outside`
        let symMap = [
            "PlugIns/Sub/hop1": "..",
            "PlugIns/Sub/escape": "hop1/../../Outside"
        ]
        XCTAssertNil(IPAPackageScanner.resolveInBundleArchivePath(from: "PlugIns/Sub/escape", symlinks: symMap),
                     "Archive symlink hop1/../../Outside escapes .app root under POSIX namei")

        // 3. IPAPackageScanner Pass-3 materialization ordering:
        //    `PlugIns/Hidden.appex -> ../ZStore/RealExtDir` (alphabetically before `ZStore/...`) +
        //    regular-file symlink `ZStore/RealExtDir/Hidden -> ../../Assets/AskPayload`
        let cleanMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [Self.retWord]
        ))
        let askExtBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/System/Library/Frameworks/\(IOCTokenArmor.tAccSetupFw)/AccessorySetupKit"],
            symbols: ["_OBJC_CLASS_$_\(IOCTokenArmor.tASAccSess)"],
            textInstructions: [Self.retWord]
        ))
        let mainPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.pass3.app",
            "CFBundleExecutable": "Main"
        ], format: .xml, options: 0)
        let extPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.pass3.app.ext",
            "CFBundleExecutable": "Hidden"
        ], format: .xml, options: 0)

        let pass3IPA = makeTempURL("pass3_symlink_order.ipa")
        try buildZip([
            .init(path: "Payload/App.app/Info.plist", payload: mainPlist),
            .init(path: "Payload/App.app/Main", payload: cleanMain, unixMode: 0o100755),
            .init(path: "Payload/App.app/Assets/AskPayload", payload: askExtBin, unixMode: 0o100755),
            .init(path: "Payload/App.app/ZStore/RealExtDir/Info.plist", payload: extPlist),
            .init(path: "Payload/App.app/ZStore/RealExtDir/Hidden", payload: Data("../../Assets/AskPayload".utf8), unixMode: 0o120755),
            .init(path: "Payload/App.app/PlugIns/Hidden.appex", payload: Data("../ZStore/RealExtDir".utf8), unixMode: 0o120755)
        ]).write(to: pass3IPA)

        let pass3Finding = try IPAPackageScanner.shared.scan(ipaURL: pass3IPA)
        XCTAssertEqual(pass3Finding.riskTier, .highRisk)
        XCTAssertTrue(pass3Finding.indicators.contains { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" },
                      "Pass 3 must materialize file symlinks before directory symlinks so Hidden.appex/Hidden is audited")
    }

    // MARK: - 14. Disguised 3-Slice FAT with OOB Sibling, .appex/embedded.mobileprovision & In-Bundle Dir Symlinks

    func test_r10_14_fatOOBSiblingDisguise_appexMobileprovision_andInBundleDirectorySymlinks() throws {
        let cleanMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 0,
            symbols: ["_main"],
            textInstructions: [Self.retWord]
        ))
        let svcSlice = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_payload"],
            textInstructions: [Self.svcWord, Self.retWord]
        ))

        // 1. 3-slice 0xCAFEBABE disguised as `Assets/bg.png`:
        //    slice 0: perturbed cputype 0x0001000C (looks like Java .class byte 10 != 0),
        //    slice 1: OOB offset+size > fileSize,
        //    slice 2: valid ARM64 slice with `svc #0x80`
        let slice2Off = 4096
        var fatDisguised = Data()
        fatDisguised.r10be32(0xCAFE_BABE)
        fatDisguised.r10be32(3)
        // fat_arch[0]: perturbed cputype
        fatDisguised.r10be32(0x0001_000C); fatDisguised.r10be32(0); fatDisguised.r10be32(256); fatDisguised.r10be32(64); fatDisguised.r10be32(12)
        // fat_arch[1]: OOB size 0x1000_0000 > fileSize!
        fatDisguised.r10be32(0x0001_0007); fatDisguised.r10be32(3); fatDisguised.r10be32(512); fatDisguised.r10be32(0x1000_0000); fatDisguised.r10be32(12)
        // fat_arch[2]: valid ARM64
        fatDisguised.r10be32(UInt32(bitPattern: CPU_TYPE_ARM64)); fatDisguised.r10be32(0)
        fatDisguised.r10be32(UInt32(slice2Off)); fatDisguised.r10be32(UInt32(svcSlice.count)); fatDisguised.r10be32(14)
        while fatDisguised.count < slice2Off { fatDisguised.append(0) }
        fatDisguised.append(svcSlice)

        XCTAssertTrue(IPAPackageScanner.isMachOOrFatMagic(fatDisguised.prefix(8 + 3 * 20), fileSize: fatDisguised.count))

        // 2. Also include `PlugIns/Evil.appex/embedded.mobileprovision` inside a main `.app` that has NO top-level mobileprovision
        let privAccEntBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 0,
            symbols: ["_ext"],
            xmlEntitlements: """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict><key>com.apple.private.accessorysetupkit.allow</key><true/></dict></plist>
            """,
            textInstructions: [Self.retWord]
        ))
        let mainPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.hybrid.store",
            "CFBundleExecutable": "Main"
        ], format: .xml, options: 0)
        let extPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.hybrid.store.ext",
            "CFBundleExecutable": "Evil"
        ], format: .xml, options: 0)
        let extProv = Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
            <key>TeamIdentifier</key><array><string>EXTTEAM123</string></array>
            <key>ProvisionedDevices</key><array><string>UDID-1</string></array>
        </dict></plist>
        """.utf8)

        let ipaURL = makeTempURL("fat_oob_and_appex_prov.ipa")
        try buildZip([
            .init(path: "Payload/App.app/Info.plist", payload: mainPlist),
            .init(path: "Payload/App.app/Main", payload: cleanMain, unixMode: 0o100755),
            .init(path: "Payload/App.app/Assets/bg.png", payload: fatDisguised, deflate: true),
            .init(path: "Payload/App.app/PlugIns/Evil.appex/Info.plist", payload: extPlist),
            .init(path: "Payload/App.app/PlugIns/Evil.appex/Evil", payload: privAccEntBin, unixMode: 0o100755),
            .init(path: "Payload/App.app/PlugIns/Evil.appex/embedded.mobileprovision", payload: extProv)
        ]).write(to: ipaURL)

        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == SignatureCatalog.directSyscallRule.pattern })
        XCTAssertTrue(finding.indicators.contains { $0.signature == "CorruptMachO:UnparseableSlice" })
        XCTAssertTrue(finding.indicators.contains { $0.signature == "CVE-2026-84493:PrivateAccessoryEntitlement" })

        // 3. On-disk `.app` with in-bundle directory symlinks `PlugIns -> Resources/ExtStore` and `Frameworks/Bad.framework -> ../Resources/FwDir`
        let diskApp = makeTempURL("DirSymlinkBundle.app")
        let extStore = diskApp.appendingPathComponent("Resources/ExtStore/Sub.appex")
        let fwStore = diskApp.appendingPathComponent("Resources/FwDir")
        try FileManager.default.createDirectory(at: extStore, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: fwStore, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: diskApp.appendingPathComponent("Frameworks"), withIntermediateDirectories: true)
        try mainPlist.write(to: diskApp.appendingPathComponent("Info.plist"))
        try cleanMain.write(to: diskApp.appendingPathComponent("Main"))
        try extPlist.write(to: extStore.appendingPathComponent("Info.plist"))
        try svcSlice.write(to: extStore.appendingPathComponent("Evil"))
        try Data("NOT_A_VALID_MACHO_HEADER".utf8).write(to: fwStore.appendingPathComponent("Bad"))
        symlink("Resources/ExtStore", diskApp.appendingPathComponent("PlugIns").path)
        symlink("../Resources/FwDir", diskApp.appendingPathComponent("Frameworks/Bad.framework").path)

        let diskFinding = try SecurityPipeline.shared.scanBundle(at: diskApp)
        XCTAssertEqual(diskFinding.riskTier, .highRisk)
        XCTAssertTrue(diskFinding.indicators.contains { $0.signature == SignatureCatalog.directSyscallRule.pattern })
        XCTAssertTrue(diskFinding.indicators.contains { $0.signature == "CorruptMachO:UnparseableBinary" })
    }

    // MARK: - 15. Filename Whitelist Spoofing, Conflicting Bundle Identity & Dynamic Reflection

    func test_r10_15_filenameWhitelistSpoof_conflictingBundleIdentity_andDynamicObjCReflection() throws {
        let spoofMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_" + IOCTokenArmor.tCqCreate],
            xmlEntitlements: """
            <?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
                <key>com.apple.security.application-groups</key>
                <array><string>group.com.wqguard.app</string></array>
            </dict></plist>
            """,
            textInstructions: [Self.retWord]
        ))

        // 1a. Standalone Mach-O named `/tmp/.../com.wqguard.app` (no application-identifier, no __info_plist) -> MUST NOT match whitelist!
        let spoofDir = makeTempURL("spoof_bin_dir")
        try FileManager.default.createDirectory(at: spoofDir, withIntermediateDirectories: true)
        let spoofBinURL = spoofDir.appendingPathComponent("com.wqguard.app")
        try spoofMachO.write(to: spoofBinURL)
        let binFinding = try SecurityPipeline.shared.scanBinary(at: spoofBinURL)
        XCTAssertFalse(binFinding.isWhitelisted, "Filename fallback url.lastPathComponent must NEVER grant WhitelistEngine trust")
        XCTAssertEqual(binFinding.riskTier, .highRisk)

        // 1b. Stripped `.framework` named `com.wqguard.app.framework` without Info.plist -> MUST NOT match whitelist!
        let spoofFwURL = spoofDir.appendingPathComponent("com.wqguard.app.framework")
        try FileManager.default.createDirectory(at: spoofFwURL, withIntermediateDirectories: true)
        try spoofMachO.write(to: spoofFwURL.appendingPathComponent("com.wqguard.app"))
        let fwFinding = try SecurityPipeline.shared.scanBundle(at: spoofFwURL)
        XCTAssertFalse(fwFinding.isWhitelisted, "Bundle stem fallback without Info.plist or application-identifier must NEVER match whitelist")
        XCTAssertEqual(fwFinding.riskTier, .highRisk)

        // 2. Conflicting `Info.plist` (`com.wqguard.app`) vs CSBlob `application-identifier` (`TEAM123456.io.metamask`) in IPA
        let conflictMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_" + IOCTokenArmor.tCqCreate],
            xmlEntitlements: """
            <?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
                <key>application-identifier</key><string>TEAM123456.io.metamask</string>
                <key>com.apple.security.application-groups</key><array><string>group.com.wqguard.app</string></array>
            </dict></plist>
            """,
            textInstructions: [Self.retWord]
        ))
        let wqgPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.wqguard.app",
            "CFBundleDisplayName": "WQGuard",
            "CFBundleExecutable": "WQGuard"
        ], format: .xml, options: 0)
        let conflictIPA = makeTempURL("conflict_id.ipa")
        try buildZip([
            .init(path: "Payload/WQGuard.app/Info.plist", payload: wqgPlist),
            .init(path: "Payload/WQGuard.app/WQGuard", payload: conflictMachO, unixMode: 0o100755)
        ]).write(to: conflictIPA)
        let conflictFinding = try IPAPackageScanner.shared.scan(ipaURL: conflictIPA)
        XCTAssertFalse(conflictFinding.isWhitelisted)
        XCTAssertEqual(conflictFinding.riskTier, .highRisk)
        XCTAssertTrue(conflictFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })

        // Positive control: wildcard `application-identifier = "TEAM123456.*"` with `CFBundleIdentifier = "com.wqguard.app"` IS valid!
        let wildcardMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_" + IOCTokenArmor.tCqCreate],
            xmlEntitlements: """
            <?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
                <key>application-identifier</key><string>TEAM123456.*</string>
                <key>com.apple.security.application-groups</key><array><string>group.com.wqguard.app</string></array>
            </dict></plist>
            """,
            textInstructions: [Self.retWord]
        ))
        let wildcardIPA = makeTempURL("wildcard_wqg.ipa")
        try buildZip([
            .init(path: "Payload/WQGuard.app/Info.plist", payload: wqgPlist),
            .init(path: "Payload/WQGuard.app/WQGuard", payload: wildcardMachO, unixMode: 0o100755)
        ]).write(to: wildcardIPA)
        let wildcardFinding = try IPAPackageScanner.shared.scan(ipaURL: wildcardIPA)
        XCTAssertTrue(wildcardFinding.isWhitelisted)
        XCTAssertEqual(wildcardFinding.riskTier, .knownTool)

        // 3. Dynamic `dlopen` + `NSClassFromString` + `NSSelectorFromString` C-string reflection (zero static framework/class symbols)
        let dynReflectMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib", "/usr/lib/libobjc.A.dylib"],
            symbols: ["_dlopen", "_NSClassFromString", "_NSSelectorFromString"],
            textInstructions: [Self.retWord],
            extraCStringLiterals: [
                "/System/Library/PrivateFrameworks/\(IOCTokenArmor.tPhotoLibFw)/\(IOCTokenArmor.tPhotoLibSvc)",
                IOCTokenArmor.tPLPhotoLib,
                IOCTokenArmor.tSysPhotoLib,
                "/System/Library/Frameworks/\(IOCTokenArmor.tAccSetupFw)/AccessorySetupKit",
                IOCTokenArmor.tASAccSess
            ]
        ))
        let dynPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.dyn.reflect",
            "CFBundleExecutable": "DynReflect"
        ], format: .xml, options: 0)
        let dynIPA = makeTempURL("dyn_reflect.ipa")
        try buildZip([
            .init(path: "Payload/DynReflect.app/Info.plist", payload: dynPlist),
            .init(path: "Payload/DynReflect.app/DynReflect", payload: dynReflectMachO, unixMode: 0o100755)
        ]).write(to: dynIPA)

        let dynFinding = try IPAPackageScanner.shared.scan(ipaURL: dynIPA)
        XCTAssertEqual(dynFinding.riskTier, .highRisk)
        XCTAssertTrue(dynFinding.indicators.contains { $0.category == "Private Photos Bypass" })
        XCTAssertTrue(dynFinding.indicators.contains { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" })
    }

    // MARK: - 16. CLI Unpacked Payload/, .xcframework, Info.plist-less .app & Trailing-Slash Symlink Rejection

    func test_r10_16_cli_unpackedPayload_xcframework_plistLessApp_andTrailingSlashSymlink() async throws {
        let evilBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [Self.svcWord, Self.retWord]
        ))

        // 1. Unpacked `Payload/Evil.app` directory scanned via `wqguard-cli scan Payload` -> must exit 1
        let payloadDir = makeTempURL("Payload")
        let unpackedApp = payloadDir.appendingPathComponent("Evil.app")
        try FileManager.default.createDirectory(at: unpackedApp, withIntermediateDirectories: true)
        let appPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.r10.unpacked.evil",
            "CFBundleExecutable": "Evil"
        ], format: .xml, options: 0)
        try appPlist.write(to: unpackedApp.appendingPathComponent("Info.plist"))
        try evilBin.write(to: unpackedApp.appendingPathComponent("Evil"))

        let payloadRes = try await runCLIInProcess(["scan", payloadDir.path])
        XCTAssertEqual(payloadRes.code, 1, "Unpacked Payload/ directory must scan nested Evil.app and exit 1")
        XCTAssertTrue(payloadRes.out.contains(SignatureCatalog.directSyscallRule.pattern))

        // 2. `.xcframework` with top-level `CFBundlePackageType = "XFWK"` Info.plist
        let xcfwDir = makeTempURL("EvilSDK.xcframework")
        let sliceFwDir = xcfwDir.appendingPathComponent("ios-arm64/EvilSDK.framework")
        try FileManager.default.createDirectory(at: sliceFwDir, withIntermediateDirectories: true)
        let xcfwPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundlePackageType": "XFWK",
            "XCFrameworkFormatVersion": "1.0",
            "AvailableLibraries": [["LibraryIdentifier": "ios-arm64", "LibraryPath": "EvilSDK.framework"]]
        ], format: .xml, options: 0)
        try xcfwPlist.write(to: xcfwDir.appendingPathComponent("Info.plist"))
        try evilBin.write(to: sliceFwDir.appendingPathComponent("EvilSDK"))

        let xcfwRes = try await runCLIInProcess(["scan", xcfwDir.path])
        XCTAssertEqual(xcfwRes.code, 1, ".xcframework must discover nested slice binaries and exit 1")

        // 3. `Info.plist`-less `.app` directory containing Mach-O binary -> exits 1
        let strippedApp = makeTempURL("Stripped.app")
        try FileManager.default.createDirectory(at: strippedApp, withIntermediateDirectories: true)
        try evilBin.write(to: strippedApp.appendingPathComponent("Stripped"))
        let strippedRes = try await runCLIInProcess(["scan", strippedApp.path])
        XCTAssertEqual(strippedRes.code, 1)

        // 4. Symlink directory passed with trailing slash `SymApp.app/` -> refused (exit 2), never followed via POSIX trailing slash
        let symDir = makeTempURL("SymApp.app")
        symlink(unpackedApp.path, symDir.path)
        let symSlashRes = try await runCLIInProcess(["scan", symDir.path + "/"])
        XCTAssertEqual(symSlashRes.code, 2, "Trailing slash on symlink directory must still be rejected by lstat")
    }

    // MARK: - 17. Registry devicectl Non-AppStore, UPP/Free Validated, com.apple.fake platform-application & Whitelist Apple Groups

    func test_r10_17_registryDeviceCtlSpoof_uppFreeValidated_comAppleFakePlatform_andWhitelistAppleGroup() throws {
        let scanner = InstalledAppRegistryScanner.shared

        // 1. `devicectl` JSON where `builtByDeveloper == false` AND explicit `signerIdentity: "Ad Hoc"` or `enterpriseApp: true`
        let deviceCtlJSON = """
        {
          "result": {
            "apps": [
              {
                "bundleIdentifier": "io.metamask.MetaMask",
                "name": "MetaMask",
                "version": "7.30.0",
                "defaultApp": false,
                "internalApp": false,
                "builtByDeveloper": false,
                "signerIdentity": "Ad Hoc",
                "url": "file:///private/var/containers/Bundle/Application/8888/MetaMask.app/"
              },
              {
                "bundleIdentifier": "org.telegram.messenger",
                "name": "Telegram",
                "version": "10.0",
                "defaultApp": false,
                "internalApp": false,
                "builtByDeveloper": false,
                "enterpriseApp": true,
                "url": "file:///private/var/containers/Bundle/Application/9999/Telegram.app/"
              }
            ]
          }
        }
        """
        let ctlRecords = try scanner.parseSnapshotData(Data(deviceCtlJSON.utf8))
        let ctlFindings = scanner.evaluateRecords(ctlRecords, includeAppStoreApps: false)
        XCTAssertEqual(ctlFindings.count, 2)
        XCTAssertTrue(ctlFindings.allSatisfy { $0.riskTier == .highRisk })

        // 2. `UPPValidated` and `FreeProfileValidated` honored in `fromDictionary`
        let freeRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.free.sideload",
            "FreeProfileValidated": true
        ]))
        let uppRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.upp.enterprise",
            "UPPValidated": true,
            "SignerIdentity": "iPhone Distribution: Corp"
        ]))
        XCTAssertTrue(freeRec.profileValidated)
        XCTAssertTrue(uppRec.profileValidated)
        XCTAssertEqual(scanner.classifyChannel(for: uppRec).channel, .enterpriseInHouse)

        // 3. Unverified `com.apple.fake` record with `platform-application: true` and uppercase `GROUP.COM.APPLE.mobilegestaltcache`
        let fakeApplePlatform = InstalledAppRegistryRecord(
            bundleId: "com.apple.fake.daemon",
            displayName: "FakeDaemon",
            version: "1.0",
            applicationType: "System",
            signerIdentity: "Ad Hoc",
            profileValidated: false,
            appGroups: ["GROUP.COM.APPLE.mobilegestaltcache"],
            booleanEntitlements: ["platform-application": true],
            allEntitlementKeys: ["platform-application"],
            bundlePath: "/var/containers/Bundle/Application/UUID-FAKE/FakeDaemon.app"
        )
        let evalFake = scanner.evaluateRecord(fakeApplePlatform)
        XCTAssertEqual(evalFake.riskTier, .highRisk)
        XCTAssertTrue(evalFake.indicators.contains { $0.signature == "platform-application" })
        XCTAssertTrue(evalFake.indicators.contains { $0.signature.hasPrefix("AppleSystemAppGroup(") })

        // 4. Custom WhitelistEngine rule with `com.apple.*` bundle pattern cannot silently authorize `group.com.apple.*`
        let wl = WhitelistEngine()
        wl.registerCustomTool(WhitelistedTool(
            name: "CustomApplePrefixRule",
            allowedBundleIds: ["com.apple.custom.research"],
            allowedAppGroups: []
        ))
        XCTAssertFalse(wl.isWhitelisted(
            bundleId: "com.apple.custom.research",
            appGroups: ["group.com.apple.private.system"]
        ).isWhitelisted)
    }

    // MARK: - 18. Brotli Shield RFC 9110 Delimiters, brotli/x-br Aliases & Loon/Surge $httpClient Disambiguation

    func test_r10_18_brotliShield_rfc9110TokenDelimiters_brotliAliases_andHttpClientDisambiguation() throws {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let standaloneJS = try String(contentsOf: repoRoot.appendingPathComponent("Shields/scripts/brotli-guard.js"), encoding: .utf8)
        let stashContent = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let payloadMarker = try XCTUnwrap(stashContent.range(of: "payload: |"))
        let stashJS = stashContent[payloadMarker.upperBound...]
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { line -> String in
                var s = String(line)
                if s.hasPrefix("                  ") { s.removeFirst(18) }
                return s
            }
            .joined(separator: "\n")

        func evalScript(_ script: String, encoding: String, setPrefs: Bool = false, setHttpClient: Bool = false) -> JSValue? {
            let ctx = JSContext()!
            var result: JSValue?
            let doneBlock: @convention(block) (JSValue) -> Void = { val in result = val }
            ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
            ctx.setObject(["status": 200, "headers": ["Content-Encoding": encoding]], forKeyedSubscript: "$response" as NSString)
            if setPrefs { ctx.setObject(["stub": 1], forKeyedSubscript: "$prefs" as NSString) }
            if setHttpClient { ctx.setObject(["get": 1], forKeyedSubscript: "$httpClient" as NSString) }
            _ = ctx.evaluateScript(script)
            XCTAssertNil(ctx.exception)
            return result
        }

        for script in [standaloneJS, stashJS] {
            for hostileEncoding in ["br()", "gzip/br", "br=1", "brotli", "x-br", "x-brotli", "dcb", "gzip, (br)"] {
                let res = try XCTUnwrap(evalScript(script, encoding: hostileEncoding))
                XCTAssertEqual(res.forProperty("status")?.toInt32(), 403, "Failed to block '\(hostileEncoding)'")
            }
            for safeEncoding in ["gzip", "deflate", "br-custom-safe", "dcb-custom-safe", "app.br.token"] {
                let res = try XCTUnwrap(evalScript(script, encoding: safeEncoding))
                XCTAssertTrue(res.forProperty("status")?.isUndefined == true, "False positive on '\(safeEncoding)'")
            }
        }

        // Loon/Surge compatibility environment defining BOTH `$prefs` shim and `$httpClient` must receive integer `403`,
        // while pure Quantumult X (`$prefs` without `$httpClient`/`$loon`) receives `"HTTP/1.1 403 Forbidden"`.
        let loonRes = try XCTUnwrap(evalScript(standaloneJS, encoding: "br", setPrefs: true, setHttpClient: true))
        XCTAssertTrue(loonRes.forProperty("status")?.isNumber == true)
        XCTAssertEqual(loonRes.forProperty("status")?.toInt32(), 403)

        let qxRes = try XCTUnwrap(evalScript(standaloneJS, encoding: "br", setPrefs: true, setHttpClient: false))
        XCTAssertEqual(qxRes.forProperty("status")?.toString(), "HTTP/1.1 403 Forbidden")
    }
}
