//
//  AdversarialV130Round11FinalAuditTests.swift
//  WQGuardCoreTests
//
//  Final Deep Security Audit Regression Suite (Round 11):
//  1. CSBlobParser full cryptographic chain binding: CMS SignerInfo (messageDigest, CDHashes, SecKeyVerifySignature),
//     CodeDirectory Page-0 & code slots, SuperBlob Special Slots (-1 Info.plist, -5 XML, -7 DER), mixed FAT slices,
//     and whole-binary + swapped Info.plist transplant defense
//  2. Forged cryptid=1 + CS_ADHOC embedded dylib/framework channel downgrade & plaintext FairPlay range unmasking
//  3. LockdownInstProxyClient zero-outbound-network numeric local host guard & EnableServiceSSL=false fail-closed
//  4. SecurityPipeline malformed/hostile package .highRisk emission & discoverAccessibleTargets / isSelfSignedOrSideloadedBundle O_NOFOLLOW
//  5. correlateAndMergeFindings & WhitelistEngine.evaluateFindingWhitelist prefix-whitelist & cross-source TeamID borrowing defense
//  6. CSStore2Parser O_NOFOLLOW/FIFO/size pre-checks, sliced Data rebasing, trailing record near EOF, OOB string guard, C1 & Variation Selectors
//  7. Bounded O_NOFOLLOW file staging/atomic write helpers, CLI symlinked bundle rejection, Shared Brotli `sbr` guard & English zero-Han check
//

import CryptoKit
import Darwin
import Foundation
import JavaScriptCore
import MachO
import Network
@preconcurrency import Security
import XCTest
import zlib
@testable import WQGuardCore

fileprivate extension Data {
    mutating func r11le16(_ v: UInt16) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r11le32(_ v: UInt32) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r11be32(_ v: UInt32) { var x = v.bigEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
}

final class AdversarialV130Round11FinalAuditTests: XCTestCase {

    private static let svcWord: UInt32 = 0xD400_1001
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
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("r11_\(UUID().uuidString)_\(name)")
        tempURLs.append(u)
        return u
    }

    private static func crc32Of(_ d: Data) -> UInt32 {
        d.withUnsafeBytes { raw in
            UInt32(crc32(0, raw.bindMemory(to: Bytef.self).baseAddress, uInt(d.count)))
        }
    }

    private struct ZipSpec {
        var path: String
        var payload: Data
        var unixMode: UInt32 = 0o100644
    }

    private func buildZip(_ items: [ZipSpec]) -> Data {
        var archive = Data()
        var cd = Data()
        for item in items {
            let localOff = UInt32(archive.count)
            let nameUTF8 = Data(item.path.utf8)
            let crc = Self.crc32Of(item.payload)

            archive.r11le32(0x0403_4B50)
            archive.r11le16(20)
            archive.r11le16(0)
            archive.r11le16(0)
            archive.r11le16(0)
            archive.r11le16(0)
            archive.r11le32(crc)
            archive.r11le32(UInt32(item.payload.count))
            archive.r11le32(UInt32(item.payload.count))
            archive.r11le16(UInt16(nameUTF8.count))
            archive.r11le16(0)
            archive.append(nameUTF8)
            archive.append(item.payload)

            cd.r11le32(0x0201_4B50)
            cd.r11le16((3 << 8) | 20)
            cd.r11le16(20)
            cd.r11le16(0)
            cd.r11le16(0)
            cd.r11le16(0)
            cd.r11le16(0)
            cd.r11le32(crc)
            cd.r11le32(UInt32(item.payload.count))
            cd.r11le32(UInt32(item.payload.count))
            cd.r11le16(UInt16(nameUTF8.count))
            cd.r11le16(0)
            cd.r11le16(0)
            cd.r11le16(0)
            cd.r11le16(0)
            cd.r11le32((item.unixMode & 0xFFFF) << 16)
            cd.r11le32(localOff)
            cd.append(nameUTF8)
        }
        let cdOffset = UInt32(archive.count)
        let cdSize = UInt32(cd.count)
        archive.append(cd)
        archive.r11le32(0x0605_4B50)
        archive.r11le16(0)
        archive.r11le16(0)
        archive.r11le16(UInt16(items.count))
        archive.r11le16(UInt16(items.count))
        archive.r11le32(cdSize)
        archive.r11le32(cdOffset)
        archive.r11le16(0)
        return archive
    }

    private func runOpenSSL(_ args: [String]) throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        proc.arguments = args
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        proc.waitUntilExit()
        XCTAssertEqual(proc.terminationStatus, 0, "openssl failed with args: \(args.joined(separator: " "))")
    }

    /// Builds a valid SHA-256 `CS_CodeDirectory` (v2.04.00, `flags = 0`, 4 KB pages) covering `slicePrefixBytes`,
    /// Special Slot `-1` (`infoPlistData`), and Special Slot `-5` (`slot5FullBlob`).
    private func buildSignedStyleCodeDirectory(
        identifier: String,
        slicePrefixBytes: Data,
        infoPlistData: Data?,
        slot5FullBlob: Data?,
        codeResourcesData: Data? = nil
    ) -> Data {
        let pageSizeShift: UInt8 = 12 // 4096
        let pageSize = 1 << Int(pageSizeShift)
        let codeLimit = slicePrefixBytes.count
        let nCodeSlots = (codeLimit + pageSize - 1) / pageSize
        let nSpecialSlots: Int
        if slot5FullBlob != nil {
            nSpecialSlots = 5
        } else if codeResourcesData != nil {
            nSpecialSlots = 3
        } else if infoPlistData != nil {
            nSpecialSlots = 1
        } else {
            nSpecialSlots = 0
        }
        let hashSize = 32
        let identBytes = Data(identifier.utf8) + Data([0x00])
        let identOffset = 88 // CS_CodeDirectory v2.04.00 header is 88 bytes (scatter/team/codeLimit64/execSeg at +44..+87)
        let hashOffset = identOffset + identBytes.count + nSpecialSlots * hashSize
        let totalLen = hashOffset + nCodeSlots * hashSize

        var cd = Data()
        cd.r11be32(CSBlobConstants.codeDirectoryMagic)
        cd.r11be32(UInt32(totalLen))
        cd.r11be32(0x0002_0400) // version
        cd.r11be32(0)           // flags = 0 (NOT ad-hoc)
        cd.r11be32(UInt32(hashOffset))
        cd.r11be32(UInt32(identOffset))
        cd.r11be32(UInt32(nSpecialSlots))
        cd.r11be32(UInt32(nCodeSlots))
        cd.r11be32(UInt32(codeLimit))
        cd.append(UInt8(hashSize))
        cd.append(2) // CS_HASHTYPE_SHA256
        cd.append(0) // platform
        cd.append(pageSizeShift)
        cd.r11be32(0) // spare2
        cd.append(contentsOf: [UInt8](repeating: 0, count: 44)) // scatterOffset..execSegFlags = 0
        cd.append(identBytes)

        // Special slots stored backwards from -nSpecialSlots .. -1
        if nSpecialSlots > 0 {
            for slotIdx in stride(from: nSpecialSlots, through: 1, by: -1) {
                if slotIdx == 5, let s5 = slot5FullBlob {
                    cd.append(contentsOf: SHA256.hash(data: s5))
                } else if slotIdx == 3, let cr = codeResourcesData {
                    cd.append(contentsOf: SHA256.hash(data: cr))
                } else if slotIdx == 1, let plist = infoPlistData {
                    cd.append(contentsOf: SHA256.hash(data: plist))
                } else {
                    cd.append(contentsOf: [UInt8](repeating: 0, count: hashSize))
                }
            }
        }

        // Code slots 0 ..< nCodeSlots
        for s in 0..<nCodeSlots {
            let pStart = s * pageSize
            let pEnd = min(pStart + pageSize, codeLimit)
            cd.append(contentsOf: SHA256.hash(data: slicePrefixBytes[pStart..<pEnd]))
        }
        return cd
    }

    private func buildSuperBlob(slots: [(type: UInt32, blob: Data)]) -> Data {
        let headerLen = 12 + slots.count * 8
        let totalLen = headerLen + slots.reduce(0) { $0 + $1.blob.count }
        var sb = Data()
        sb.r11be32(CSBlobConstants.superBlobMagic)
        sb.r11be32(UInt32(totalLen))
        sb.r11be32(UInt32(slots.count))
        var cursor = headerLen
        for s in slots {
            sb.r11be32(s.type)
            sb.r11be32(UInt32(cursor))
            cursor += s.blob.count
        }
        for s in slots {
            sb.append(s.blob)
        }
        return sb
    }

    private func preparePreSizedMachOSliceForSigning(_ rawSlice: Data, reservedSigBytes: Int = 16_384) -> (slice: Data, csOffset: Int)? {
        var slice = Data(rawSlice)
        let ncmds = slice.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
        var cur = 32
        var foundCSOff: Int? = nil
        for _ in 0..<ncmds {
            let cmd = slice.withUnsafeBytes { $0.load(fromByteOffset: cur, as: UInt32.self).littleEndian }
            let cmdsz = Int(slice.withUnsafeBytes { $0.load(fromByteOffset: cur + 4, as: UInt32.self).littleEndian })
            if cmd == UInt32(LC_CODE_SIGNATURE) {
                let csOff = Int(slice.withUnsafeBytes { $0.load(fromByteOffset: cur + 8, as: UInt32.self).littleEndian })
                foundCSOff = csOff
                slice.removeSubrange(csOff..<slice.count)
                var newSizeLE = UInt32(reservedSigBytes).littleEndian
                withUnsafeBytes(of: &newSizeLE) { slice.replaceSubrange((cur + 12)..<(cur + 16), with: $0) }
                slice.append(Data(count: reservedSigBytes))
                break
            }
            cur += cmdsz
        }
        guard let csOff = foundCSOff else { return nil }

        var segCur = 32
        for _ in 0..<ncmds {
            let sc = slice.withUnsafeBytes { $0.load(fromByteOffset: segCur, as: UInt32.self).littleEndian }
            let ssz = Int(slice.withUnsafeBytes { $0.load(fromByteOffset: segCur + 4, as: UInt32.self).littleEndian })
            if sc == UInt32(LC_SEGMENT_64) {
                let nm = String(decoding: slice.subdata(in: (segCur + 8)..<(segCur + 24)).prefix { $0 != 0 }, as: UTF8.self)
                if nm == "__LINKEDIT" {
                    let fOff = slice.withUnsafeBytes { $0.load(fromByteOffset: segCur + 40, as: UInt64.self).littleEndian }
                    let newFileSz = UInt64(slice.count) - fOff
                    let newVmSz = (newFileSz + 0x3FFF) & ~0x3FFF
                    var vmLE = newVmSz.littleEndian
                    var fsLE = newFileSz.littleEndian
                    withUnsafeBytes(of: &vmLE) { slice.replaceSubrange((segCur + 32)..<(segCur + 40), with: $0) }
                    withUnsafeBytes(of: &fsLE) { slice.replaceSubrange((segCur + 48)..<(segCur + 56), with: $0) }
                }
            }
            segCur += ssz
        }
        return (slice, csOff)
    }

    private func writeSuperBlobIntoPreSizedSlice(_ preSizedSlice: Data, csOffset: Int, superBlob: Data) -> Data {
        var out = Data(preSizedSlice)
        out.replaceSubrange(csOffset..<(csOffset + superBlob.count), with: superBlob)
        return out
    }

    // MARK: - 1. Gap 1 + Pass 1: Full Cryptographic CMS + CodeDirectory + Page-0 + Slot 5/7 + Info.plist + Mixed FAT Binding

    func test_r11_01_cmsFullChainBinding_realAppleBinary_graftedCMS_page0_slot57_swappedInfoPlist_andMixedFat() throws {
        // Part A: Empirical verification against real Apple-signed /Applications/Safari.app on macOS
        let safariExecURL = URL(fileURLWithPath: "/Applications/Safari.app/Contents/MacOS/Safari")
        let safariPlistURL = URL(fileURLWithPath: "/Applications/Safari.app/Contents/Info.plist")
        if FileManager.default.fileExists(atPath: safariExecURL.path),
           let safariData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: safariExecURL),
           let safariPlistData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: safariPlistURL),
           let safariSlices = try? MachOParser.parseAllSlices(data: safariData),
           let safariArmSlice = MachOParser.selectAuditSlices(from: safariSlices).first,
           let safariSuperBlob = safariArmSlice.codeSignatureData {

            // 1. Intact Apple-signed binary + matching Info.plist verifies as .appleAppStoreVerified
            XCTAssertEqual(CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: [safariArmSlice]), .appleAppStoreVerified)
            XCTAssertNil(CSBlobParser.shared.verifyBundleInfoPlistBinding(
                fromSlices: [safariArmSlice],
                infoPlistData: safariPlistData,
                plistBundleId: "com.apple.Safari"
            ))

            // 2. Standalone SuperBlob without sliceData MUST fail-closed (cannot verify Page-0 / code slots)
            let noSliceDisp = CSBlobParser.shared.inspectCodeSignatureTrust(from: safariSuperBlob)
            XCTAssertTrue(noSliceDisp.isDisqualifiedFromAppStore, "Standalone SuperBlob without sliceData must fail-closed")

            // 3. 1-byte Page-0 Mach-O header/load-command mutation MUST invalidate CodeDirectory slot 0
            var page0TamperedBytes = safariArmSlice.sliceData
            page0TamperedBytes[24] ^= 0x01 // flip 1 bit in mach_header_64.flags
            let page0TamperedDisp = CSBlobParser.shared.inspectCodeSignatureTrust(
                from: safariSuperBlob,
                sliceData: page0TamperedBytes
            )
            XCTAssertTrue(page0TamperedDisp.isDisqualifiedFromAppStore, "1-bit Page-0 mutation must invalidate Apple code signature")

            // 4. 1-byte mutation inside CMS SignerInfo.signature (at declared SuperBlob end - 16, before trailing linker NUL padding) MUST fail SecKeyVerifySignature
            var sigTamperedSB = Data(safariSuperBlob)
            let declaredSBLen = Int(sigTamperedSB.withUnsafeBytes { CSBlobParser.readUInt32BE(from: $0, at: 4) ?? 0 })
            XCTAssertGreaterThan(declaredSBLen, 64)
            sigTamperedSB[declaredSBLen - 16] ^= 0xFF
            let sigTamperedDisp = CSBlobParser.shared.inspectCodeSignatureTrust(
                from: sigTamperedSB,
                sliceData: safariArmSlice.sliceData
            )
            XCTAssertTrue(sigTamperedDisp.isDisqualifiedFromAppStore, "1-byte CMS signature mutation must fail SecKeyVerifySignature")

            // 5. Transplanting Safari's genuine CodeDirectory + CMS SuperBlob onto a forged cryptid=1 MetaMask Mach-O MUST fail
            let baseMetaMaskMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 4096,
                cryptsize: 4096,
                linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
                symbols: ["_main"],
                xmlEntitlements: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict/></plist>",
                textInstructions: [Self.retWord]
            ))
            let preSizedMM = try XCTUnwrap(preparePreSizedMachOSliceForSigning(baseMetaMaskMachO, reservedSigBytes: max(65_536, safariSuperBlob.count)))
            let graftedMetaMaskMachO = writeSuperBlobIntoPreSizedSlice(preSizedMM.slice, csOffset: preSizedMM.csOffset, superBlob: safariSuperBlob)
            let graftedSlices = try MachOParser.parseAllSlices(data: graftedMetaMaskMachO)
            XCTAssertTrue(CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: graftedSlices).isDisqualifiedFromAppStore)

            let walletPlist = try PropertyListSerialization.data(fromPropertyList: [
                "CFBundleIdentifier": "io.metamask.MetaMask",
                "CFBundleDisplayName": "MetaMask",
                "CFBundleExecutable": "MetaMask",
                "CFBundleShortVersionString": "7.30.0"
            ], format: .xml, options: 0)
            let graftedIPA = makeTempURL("grafted_safari_cms_metamask.ipa")
            try buildZip([
                .init(path: "Payload/MetaMask.app/Info.plist", payload: walletPlist),
                .init(path: "Payload/MetaMask.app/MetaMask", payload: graftedMetaMaskMachO, unixMode: 0o100755)
            ]).write(to: graftedIPA)
            let graftedFinding = try IPAPackageScanner.shared.scan(ipaURL: graftedIPA)
            XCTAssertEqual(graftedFinding.installChannel, .developerSideloaded)
            XCTAssertEqual(graftedFinding.riskTier, .highRisk)
            XCTAssertTrue(graftedFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })

            // 6. Whole-binary transplant: untouched Apple-signed Safari slice inside Payload/MetaMask.app/MetaMask with swapped Info.plist
            let swappedPlistIPA = makeTempURL("whole_safari_binary_swapped_metamask_plist.ipa")
            try buildZip([
                .init(path: "Payload/MetaMask.app/Info.plist", payload: walletPlist),
                .init(path: "Payload/MetaMask.app/MetaMask", payload: safariArmSlice.sliceData, unixMode: 0o100755)
            ]).write(to: swappedPlistIPA)
            let swappedFinding = try IPAPackageScanner.shared.scan(ipaURL: swappedPlistIPA)
            XCTAssertEqual(swappedFinding.installChannel, .developerSideloaded, "Whole-binary transplant with mismatched Info.plist must NOT stay .appStore")
            XCTAssertEqual(swappedFinding.riskTier, .highRisk)
            XCTAssertTrue(swappedFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })
        }

        // Part B: Deterministic 3-tier PKI (Root "Apple Root CA - Test" -> Intermediate -> Leaf "Apple iPhone OS Application Signing")
        let pkiDir = makeTempURL("pki_chain")
        try FileManager.default.createDirectory(at: pkiDir, withIntermediateDirectories: true)
        let extFile = pkiDir.appendingPathComponent("v3.ext")
        try """
        [req]
        distinguished_name = dn
        prompt = no

        [dn]
        C = US
        O = Apple Inc.
        CN = Apple Root CA - Test

        [ca_ext]
        basicConstraints = critical,CA:true
        keyUsage = critical,keyCertSign,cRLSign
        subjectKeyIdentifier = hash
        authorityKeyIdentifier = keyid:always

        [leaf_ext]
        basicConstraints = critical,CA:false
        keyUsage = critical,digitalSignature
        extendedKeyUsage = codeSigning
        subjectKeyIdentifier = hash
        authorityKeyIdentifier = keyid:always
        """.write(to: extFile, atomically: true, encoding: .utf8)

        let rootKey = pkiDir.appendingPathComponent("root.key")
        let rootPem = pkiDir.appendingPathComponent("root.pem")
        let rootDer = pkiDir.appendingPathComponent("root.der")
        let intKey = pkiDir.appendingPathComponent("int.key")
        let intCsr = pkiDir.appendingPathComponent("int.csr")
        let intPem = pkiDir.appendingPathComponent("int.pem")
        let leafKey = pkiDir.appendingPathComponent("leaf.key")
        let leafCsr = pkiDir.appendingPathComponent("leaf.csr")
        let leafPem = pkiDir.appendingPathComponent("leaf.pem")

        try runOpenSSL(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-keyout", rootKey.path, "-out", rootPem.path, "-subj", "/C=US/O=Apple Inc./CN=Apple Root CA - Test", "-extensions", "ca_ext", "-config", extFile.path])
        try runOpenSSL(["x509", "-in", rootPem.path, "-outform", "DER", "-out", rootDer.path])
        try runOpenSSL(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", intKey.path, "-out", intCsr.path, "-subj", "/C=US/O=Apple Inc./CN=Apple iPhone Certification Authority"])
        try runOpenSSL(["x509", "-req", "-in", intCsr.path, "-CA", rootPem.path, "-CAkey", rootKey.path, "-CAcreateserial", "-days", "2", "-out", intPem.path, "-extfile", extFile.path, "-extensions", "ca_ext"])
        try runOpenSSL(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", leafKey.path, "-out", leafCsr.path, "-subj", "/C=US/O=Apple Inc./CN=Apple iPhone OS Application Signing"])
        try runOpenSSL(["x509", "-req", "-in", leafCsr.path, "-CA", intPem.path, "-CAkey", intKey.path, "-CAcreateserial", "-days", "2", "-out", leafPem.path, "-extfile", extFile.path, "-extensions", "leaf_ext"])

        let rootCertDER = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: rootDer)
        let customRootCert = try XCTUnwrap(SecCertificateCreateWithData(nil, rootCertDER as CFData))

        let appPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.example.legitstore",
            "CFBundleDisplayName": "LegitStore",
            "CFBundleExecutable": "LegitStore"
        ], format: .xml, options: 0)
        let entXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>application-identifier</key><string>TEAM123456.com.example.legitstore</string></dict></plist>"
        var slot5Blob = Data()
        slot5Blob.r11be32(CSBlobConstants.entitlementXmlMagic)
        slot5Blob.r11be32(UInt32(8 + entXML.utf8.count))
        slot5Blob.append(Data(entXML.utf8))

        let rawTemplateMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 4096,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            xmlEntitlements: entXML,
            textInstructions: [Self.retWord]
        ))
        let preSized = try XCTUnwrap(preparePreSizedMachOSliceForSigning(rawTemplateMachO, reservedSigBytes: 16_384))
        let csOff = preSized.csOffset
        let codeBytesBeforeSig = preSized.slice.subdata(in: 0..<csOff)

        let validCD = buildSignedStyleCodeDirectory(
            identifier: "com.example.legitstore",
            slicePrefixBytes: codeBytesBeforeSig,
            infoPlistData: appPlist,
            slot5FullBlob: slot5Blob
        )
        let cdInputURL = pkiDir.appendingPathComponent("cd.bin")
        let cmsDerURL = pkiDir.appendingPathComponent("cms.der")
        try validCD.write(to: cdInputURL)
        try runOpenSSL(["smime", "-sign", "-binary", "-in", cdInputURL.path, "-signer", leafPem.path, "-inkey", leafKey.path, "-certfile", intPem.path, "-outform", "DER", "-md", "sha256", "-out", cmsDerURL.path])
        let validCMSDer = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: cmsDerURL)

        var cmsWrapper = Data()
        cmsWrapper.r11be32(CSBlobConstants.blobWrapperMagic)
        cmsWrapper.r11be32(UInt32(8 + validCMSDer.count))
        cmsWrapper.append(validCMSDer)

        let validSB = buildSuperBlob(slots: [
            (CSBlobConstants.slotCodeDirectory, validCD),
            (CSBlobConstants.slotEntitlements, slot5Blob),
            (CSBlobConstants.slotCMSSignature, cmsWrapper)
        ])
        let signedSliceData = writeSuperBlobIntoPreSizedSlice(preSized.slice, csOffset: csOff, superBlob: validSB)
        let signedSlices = try MachOParser.parseAllSlices(data: signedSliceData)

        // Positive control: genuine CMS + matching CodeDirectory + Page-0 + Slot 5 verifies!
        XCTAssertEqual(
            CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: signedSlices, customAnchorCertificates: [customRootCert]),
            .appleAppStoreVerified
        )

        // Attack B1: Graft validCMSDer onto a modified CodeDirectory (flags = 0, altered identifier) -> messageDigest mismatch!
        let forgedCD = buildSignedStyleCodeDirectory(
            identifier: "io.metamask.MetaMask",
            slicePrefixBytes: codeBytesBeforeSig,
            infoPlistData: nil,
            slot5FullBlob: slot5Blob
        )
        let graftedSB = buildSuperBlob(slots: [
            (CSBlobConstants.slotCodeDirectory, forgedCD),
            (CSBlobConstants.slotEntitlements, slot5Blob),
            (CSBlobConstants.slotCMSSignature, cmsWrapper)
        ])
        let graftedSliceData = writeSuperBlobIntoPreSizedSlice(preSized.slice, csOffset: csOff, superBlob: graftedSB)
        let graftedPKISlices = try MachOParser.parseAllSlices(data: graftedSliceData)
        XCTAssertTrue(
            CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: graftedPKISlices, customAnchorCertificates: [customRootCert]).isDisqualifiedFromAppStore,
            "Grafted CMS over modified CodeDirectory must fail messageDigest verification"
        )

        // Attack B2: Inject unsigned Slot 7 DER entitlements into SuperBlob while keeping validCD + validCMSDer untouched!
        var rogueSlot7 = Data()
        rogueSlot7.r11be32(CSBlobConstants.entitlementDerMagic)
        rogueSlot7.r11be32(10)
        rogueSlot7.append(contentsOf: [0x30, 0x00])
        let slot7InjectedSB = buildSuperBlob(slots: [
            (CSBlobConstants.slotCodeDirectory, validCD),
            (CSBlobConstants.slotEntitlements, slot5Blob),
            (CSBlobConstants.slotDerEntitlements, rogueSlot7),
            (CSBlobConstants.slotCMSSignature, cmsWrapper)
        ])
        let slot7InjectedSliceData = writeSuperBlobIntoPreSizedSlice(preSized.slice, csOffset: csOff, superBlob: slot7InjectedSB)
        let slot7InjectedSlices = try MachOParser.parseAllSlices(data: slot7InjectedSliceData)
        XCTAssertTrue(
            CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: slot7InjectedSlices, customAnchorCertificates: [customRootCert]).isDisqualifiedFromAppStore,
            "Unsigned Slot 7 injection in SuperBlob must fail Special Slot -7 seal"
        )

        // Attack B3: Mixed-slice Universal FAT (Slice 0 = .appleAppStoreVerified, Slice 1 = unsigned cryptid=1 .absentOrSynthetic)
        let unsignedArmSliceData = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 4096,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            includeCodeSignature: false,
            textInstructions: [Self.retWord]
        ))
        let unsignedArmSlices = try MachOParser.parseAllSlices(data: unsignedArmSliceData)
        let mixedDisposition: CodeSignatureTrustDisposition = CSBlobParser.shared.inspectCodeSignatureTrust(
            fromSlices: signedSlices + unsignedArmSlices,
            customAnchorCertificates: [customRootCert]
        )
        XCTAssertEqual(mixedDisposition, CodeSignatureTrustDisposition.adHocOrUnsigned, "Mixed signed + unsigned slices must never return .appleAppStoreVerified")
    }

    // MARK: - 2. Pass 1 + Pass 3: Embedded Ad-Hoc cryptid=1 Dylib Downgrade & Forged Plaintext FairPlay Unmasking

    func test_r11_02_forgedCryptid1EmbeddedAdHocDylib_andPlaintextFairPlayRange_detectedHighRisk() throws {
        var adHocCDPayload = Data()
        adHocCDPayload.r11be32(0x0002_0400)
        adHocCDPayload.r11be32(CSBlobConstants.csAdhocFlag)
        while adHocCDPayload.count < 36 { adHocCDPayload.append(0) }

        // A. App Store-looking main binary (cryptid=1) + injected Dylibs/ElleKit.dylib with forged cryptid=1 + CS_ADHOC
        let cleanMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 4096,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.retWord]
        ))
        let injectedElleKit = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 4096,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_init"],
            rawCodeSignatureSlot: (
                slot: CSBlobConstants.slotCodeDirectory,
                magic: CSBlobConstants.codeDirectoryMagic,
                data: adHocCDPayload
            ),
            textInstructions: [Self.retWord]
        ))
        let appPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.example.injectedapp",
            "CFBundleDisplayName": "InjectedApp",
            "CFBundleExecutable": "InjectedApp"
        ], format: .xml, options: 0)
        let injectedIPA = makeTempURL("forged_cryptid1_ellekit_dylib.ipa")
        try buildZip([
            .init(path: "Payload/InjectedApp.app/Info.plist", payload: appPlist),
            .init(path: "Payload/InjectedApp.app/InjectedApp", payload: cleanMain, unixMode: 0o100755),
            .init(path: "Payload/InjectedApp.app/Dylibs/ElleKit.dylib", payload: injectedElleKit, unixMode: 0o100755)
        ]).write(to: injectedIPA)

        let injectedFinding = try IPAPackageScanner.shared.scan(ipaURL: injectedIPA)
        XCTAssertEqual(injectedFinding.installChannel, .developerSideloaded, "Embedded ad-hoc dylib must downgrade channel from .appStore")
        XCTAssertEqual(injectedFinding.riskTier, .caution)
        XCTAssertTrue(injectedFinding.indicators.contains { $0.signature.lowercased().contains("ellekit") })

        // B. Forged cryptid=1 + CS_ADHOC main binary hiding inline svc #0x80 and XPC strings inside [cryptoff, cryptoff+cryptsize)
        let forgedPlaintextMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0x4000,
            cryptsize: 0x4000,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            xmlEntitlements: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>com.apple.security.application-groups</key><array><string>group.com.evil.escape</string></array></dict></plist>",
            rawCodeSignatureSlot: (
                slot: CSBlobConstants.slotCodeDirectory,
                magic: CSBlobConstants.codeDirectoryMagic,
                data: adHocCDPayload
            ),
            textInstructions: [Self.svcWord, Self.retWord],
            extraCStringLiterals: ["com.apple.containermanagerd.system"]
        ))
        let forgedSvcIPA = makeTempURL("forged_cryptid1_svc80_xpc.ipa")
        try buildZip([
            .init(path: "Payload/InjectedApp.app/Info.plist", payload: appPlist),
            .init(path: "Payload/InjectedApp.app/InjectedApp", payload: forgedPlaintextMain, unixMode: 0o100755)
        ]).write(to: forgedSvcIPA)

        let svcFinding = try IPAPackageScanner.shared.scan(ipaURL: forgedSvcIPA)
        XCTAssertEqual(svcFinding.riskTier, .highRisk)
        XCTAssertTrue(svcFinding.indicators.contains { $0.signature == SignatureCatalog.directSyscallRule.pattern }, "Plaintext svc #0x80 inside forged cryptid=1 + CS_ADHOC must be caught")
        XCTAssertTrue(svcFinding.indicators.contains { $0.signature == "com.apple.containermanagerd.system" }, "Plaintext XPC C-string inside forged cryptid=1 + CS_ADHOC must be caught")
    }

    // MARK: - 3. Gap 2 + Pass 2: Lockdown Zero-Outbound-Network Host Guard & EnableServiceSSL=false Fail-Closed

    func test_r11_03_lockdownZeroOutboundHostGuard_andEnableServiceSSLDowngradeRejected() async throws {
        // 1. Numeric local/private/CGNAT/link-local literals allowed
        let allowedHosts = [
            "127.0.0.1", "127.255.255.254", "10.7.0.1", "10.0.0.1", "172.16.0.1", "172.31.255.254",
            "192.168.1.251", "100.64.0.1", "100.127.255.254", "169.254.10.20",
            "::1", "[::1]", "fe80::1", "fe80::1%utun2", "[fe80::abcd%en0]", "fd00::1", "fc00::42"
        ]
        for h in allowedHosts {
            XCTAssertTrue(LockdownInstProxyClient.isAllowedLocalHost(h), "Expected local literal '\(h)' to be allowed")
            XCTAssertNoThrow(try LockdownInstProxyClient.makeNumericNWHost(h))
        }

        // 2. DNS domains, public internet IPs, non-RFC1918 172.32+, non-CGNAT 100.128+, octal/hex, and IPv4-mapped IPv6 MUST fail
        let forbiddenHosts = [
            "", "   ", "evil.example.com", "localhost", "10.7.0.1.nip.io",
            "8.8.8.8", "1.1.1.1", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1",
            "0.0.0.0", "255.255.255.255", "127.0.0.0", "127.255.255.255",
            "::ffff:8.8.8.8", "::ffff:127.0.0.1", "2001:4860:4860::8888",
            "fe80::1%bad/zone", "10.7.0.1:62078", "0x0a070001", "10.7.0.1/32"
        ]
        for bad in forbiddenHosts {
            XCTAssertFalse(LockdownInstProxyClient.isAllowedLocalHost(bad), "Expected non-local/DNS host '\(bad)' to be rejected")
            XCTAssertThrowsError(try LockdownInstProxyClient.validateAllowedLocalHost(bad))
        }

        // 3. fetchInstalledApps rejects DNS & public IPs immediately before touching Keychain or network
        let dummyPairing = LockdownPairingFile(
            hostID: "HOST-1",
            systemBUID: "BUID-1",
            hostCertificateDER: Data([0x30, 0x00]),
            hostPrivateKeyDER: Data([0x30, 0x00])
        )
        do {
            _ = try await LockdownInstProxyClient.shared.fetchInstalledApps(pairing: dummyPairing, preferredHost: "evil.example.com", allowInteractiveConsentWait: false)
            XCTFail("DNS host must throw protocolError")
        } catch let err as LockdownClientError {
            guard case .protocolError = err else {
                XCTFail("Expected protocolError for DNS host, got \(err)")
                return
            }
        }
        do {
            _ = try await LockdownInstProxyClient.shared.fetchInstalledApps(pairing: dummyPairing, preferredHost: "8.8.8.8", allowInteractiveConsentWait: false)
            XCTFail("Public IP must throw protocolError")
        } catch let err as LockdownClientError {
            guard case .protocolError = err else {
                XCTFail("Expected protocolError for public IP, got \(err)")
                return
            }
        }

        // 4. browseApplications enforces useTLS == true and non-nil tlsOptions fail-closed
        XCTAssertThrowsError(try LockdownInstProxyClient.shared.browseApplications(
            host: "127.0.0.1",
            port: 62078,
            useTLS: false,
            tlsOptions: NWProtocolTLS.Options()
        )) { err in
            guard case LockdownClientError.protocolError = err else {
                XCTFail("Expected protocolError when useTLS=false, got \(err)")
                return
            }
        }
        XCTAssertThrowsError(try LockdownInstProxyClient.shared.browseApplications(
            host: "127.0.0.1",
            port: 62078,
            useTLS: true,
            tlsOptions: nil
        )) { err in
            guard case LockdownClientError.protocolError = err else {
                XCTFail("Expected protocolError when tlsOptions=nil, got \(err)")
                return
            }
        }

        // 5. Full Step 2 STARTTLS mock server returning EnableServiceSSL = false MUST be rejected fail-closed!
        try verifyStep2EnableServiceSSLDowngradeRejected()
    }

    private func verifyStep2EnableServiceSSLDowngradeRejected() throws {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        let clientFD = fds[0]
        let serverFD = fds[1]

        let tlsDir = makeTempURL("lockdown_tls")
        try FileManager.default.createDirectory(at: tlsDir, withIntermediateDirectories: true)
        let srvKeyURL = tlsDir.appendingPathComponent("srv.key")
        let srvPemURL = tlsDir.appendingPathComponent("srv.pem")
        let srvDerURL = tlsDir.appendingPathComponent("srv.der")
        let srvP12URL = tlsDir.appendingPathComponent("srv.p12")
        try runOpenSSL(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", srvKeyURL.path, "-out", srvPemURL.path, "-subj", "/CN=MockLockdownDevice"])
        try runOpenSSL(["x509", "-in", srvPemURL.path, "-outform", "DER", "-out", srvDerURL.path])
        try runOpenSSL(["pkcs12", "-export", "-inkey", srvKeyURL.path, "-in", srvPemURL.path, "-passout", "pass:testpw", "-out", srvP12URL.path])

        let srvCertDER = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: srvDerURL)
        let p12Data = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: srvP12URL)
        var importItems: CFArray?
        let importStatus = SecPKCS12Import(p12Data as CFData, [kSecImportExportPassphrase as String: "testpw"] as CFDictionary, &importItems)
        if importStatus == errSecSuccess,
           let items = importItems as? [[String: Any]],
           let rawIdentity = items.first?[kSecImportItemIdentity as String] {
            let serverSecIdentity = unsafeBitCast(rawIdentity as AnyObject, to: SecIdentity.self)
            let serverTLS = NWProtocolTLS.Options()
            if let nwId = sec_identity_create(serverSecIdentity) {
                sec_protocol_options_set_local_identity(serverTLS.securityProtocolOptions, nwId)
            }

            let clientTLS = NWProtocolTLS.Options()
            let clientSecOpts = clientTLS.securityProtocolOptions
            sec_protocol_options_set_verify_block(clientSecOpts, { _, trust, completion in
                let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                if let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate],
                   let leaf = chain.first,
                   (SecCertificateCopyData(leaf) as Data) == srvCertDER {
                    completion(true)
                } else {
                    completion(false)
                }
            }, DispatchQueue(label: "r11.client.verify"))

            let serverDone = DispatchSemaphore(value: 0)
            DispatchQueue.global(qos: .userInitiated).async {
                defer { serverDone.signal() }
                guard let q = try? LockdownInstProxyClient.readPlistPacket(fromFD: serverFD),
                      (q["Request"] as? String) == "QueryType" else {
                    Darwin.close(serverFD); return
                }
                try? LockdownInstProxyClient.writePlistPacket(["Request": "QueryType", "Type": "com.apple.mobile.lockdown"], toFD: serverFD)
                guard let s = try? LockdownInstProxyClient.readPlistPacket(fromFD: serverFD),
                      (s["Request"] as? String) == "StartSession" else {
                    Darwin.close(serverFD); return
                }
                try? LockdownInstProxyClient.writePlistPacket(["Request": "StartSession", "SessionID": "S-1", "EnableSessionSSL": true], toFD: serverFD)

                var portAddr = sockaddr_in()
                portAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                portAddr.sin_family = sa_family_t(AF_INET)
                portAddr.sin_port = 0
                portAddr.sin_addr.s_addr = inet_addr("127.0.0.1")
                let lfd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
                guard lfd >= 0 else { Darwin.close(serverFD); return }
                let boundOk = withUnsafePointer(to: &portAddr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(lfd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0 }
                }
                guard boundOk else { Darwin.close(lfd); Darwin.close(serverFD); return }
                var actualAddr = sockaddr_in()
                var aLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                _ = withUnsafeMutablePointer(to: &actualAddr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(lfd, $0, &aLen) }
                }
                let tlsPort = UInt16(bigEndian: actualAddr.sin_port)
                Darwin.close(lfd)

                let params = NWParameters(tls: serverTLS, tcp: NWProtocolTCP.Options())
                params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: tlsPort)!)
                guard let listener = try? NWListener(using: params) else { Darwin.close(serverFD); return }
                let lReady = DispatchSemaphore(value: 0)
                listener.stateUpdateHandler = { st in if case .ready = st { lReady.signal() } }
                listener.newConnectionHandler = { nwConn in
                    nwConn.start(queue: DispatchQueue(label: "r11.srv.conn"))
                    nwConn.receive(minimumIncompleteLength: 4, maximumLength: 4096) { _, _, _, _ in
                        let downgradeResp: [String: Any] = [
                            "Request": "StartService",
                            "Service": "com.apple.mobile.installation_proxy",
                            "Port": 54321,
                            "EnableServiceSSL": false
                        ]
                        if let xml = try? PropertyListSerialization.data(fromPropertyList: downgradeResp, format: .xml, options: 0) {
                            var lenBE = UInt32(xml.count).bigEndian
                            var pkt = Data(bytes: &lenBE, count: 4)
                            pkt.append(xml)
                            nwConn.send(content: pkt, completion: .contentProcessed { _ in
                                nwConn.cancel()
                                listener.cancel()
                            })
                        }
                    }
                }
                listener.start(queue: DispatchQueue(label: "r11.srv.listener"))
                _ = lReady.wait(timeout: .now() + 2.0)

                let tfd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
                var dst = sockaddr_in()
                dst.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                dst.sin_family = sa_family_t(AF_INET)
                dst.sin_port = tlsPort.bigEndian
                dst.sin_addr.s_addr = inet_addr("127.0.0.1")
                let cRes = withUnsafePointer(to: &dst) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(tfd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                }
                guard cRes == 0 else { Darwin.close(tfd); Darwin.close(serverFD); listener.cancel(); return }
                let g = DispatchGroup()
                g.enter()
                DispatchQueue.global().async {
                    var b = [UInt8](repeating: 0, count: 4096)
                    while true {
                        let n = Darwin.recv(serverFD, &b, b.count, 0)
                        if n <= 0 { break }
                        _ = Darwin.send(tfd, b, n, 0)
                    }
                    Darwin.shutdown(tfd, SHUT_WR)
                    g.leave()
                }
                g.enter()
                DispatchQueue.global().async {
                    var b = [UInt8](repeating: 0, count: 4096)
                    while true {
                        let n = Darwin.recv(tfd, &b, b.count, 0)
                        if n <= 0 { break }
                        _ = Darwin.send(serverFD, b, n, 0)
                    }
                    Darwin.close(serverFD)
                    g.leave()
                }
                _ = g.wait(timeout: .now() + 4.0)
                Darwin.close(tfd)
            }

            XCTAssertThrowsError(try LockdownInstProxyClient.shared.negotiateInstallationProxyPort(
                rawSocketFD: clientFD,
                pairing: LockdownPairingFile(
                    hostID: "HOST-1",
                    systemBUID: "BUID-1",
                    hostCertificateDER: srvCertDER,
                    hostPrivateKeyDER: srvCertDER,
                    deviceCertificateDER: srvCertDER
                ),
                tlsOptions: clientTLS
            )) { err in
                guard case LockdownClientError.protocolError(let msg) = err else {
                    XCTFail("Expected protocolError refusing EnableServiceSSL=false, got \(err)")
                    return
                }
                XCTAssertTrue(msg.contains("EnableServiceSSL=false"), "Expected EnableServiceSSL=false diagnostic, got: \(msg)")
            }
            _ = serverDone.wait(timeout: .now() + 5.0)
        } else {
            Darwin.close(clientFD)
            Darwin.close(serverFD)
        }
    }

    // MARK: - 4. Gap 3: Malformed/Hostile Packages Emit .highRisk (Zero Silent try? Drops) & discoverAccessibleTargets Hardening

    func test_r11_04_securityPipeline_malformedPackagesEmitHighRisk_andInfoPlistLessAppAndFrameworkScanned() async throws {
        let scanRoot = makeTempURL("hostile_packages_dir")
        try FileManager.default.createDirectory(at: scanRoot, withIntermediateDirectories: true)

        // 1. Corrupt polyglot .ipa
        let polyglotIPA = scanRoot.appendingPathComponent("PolyglotCorrupt.ipa")
        try Data("NOT_A_VALID_ZIP_HEADER_PAYLOAD_1234567890".utf8).write(to: polyglotIPA)

        // 2. Zip-Slip .ipa
        let zipSlipIPA = scanRoot.appendingPathComponent("ZipSlipAttack.ipa")
        try buildZip([
            .init(path: "Payload/Slip.app/../../escaped.txt", payload: Data("pwn".utf8))
        ]).write(to: zipSlipIPA)

        // 3. Symlink .ipa & dangling symlink .ipa
        let symTarget = makeTempURL("outside_secret.txt")
        try Data("secret".utf8).write(to: symTarget)
        let symIPA = scanRoot.appendingPathComponent("SymlinkTrap.ipa")
        XCTAssertEqual(symlink(symTarget.path, symIPA.path), 0)
        let danglingSymIPA = scanRoot.appendingPathComponent("DanglingTrap.tipa")
        XCTAssertEqual(symlink("/nonexistent/wqguard_dangling_\(UUID().uuidString)", danglingSymIPA.path), 0)

        // 4. Multi-.app smuggled .ipa
        let p1 = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "com.a.one", "CFBundleExecutable": "One"], format: .xml, options: 0)
        let p2 = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "com.b.two", "CFBundleExecutable": "Two"], format: .xml, options: 0)
        let dummyBin = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, symbols: ["_main"], textInstructions: [Self.retWord]))
        let multiAppIPA = scanRoot.appendingPathComponent("MultiAppSmuggle.ipa")
        try buildZip([
            .init(path: "Payload/One.app/Info.plist", payload: p1),
            .init(path: "Payload/One.app/One", payload: dummyBin, unixMode: 0o100755),
            .init(path: "Payload/Two.app/Info.plist", payload: p2),
            .init(path: "Payload/Two.app/Two", payload: dummyBin, unixMode: 0o100755)
        ]).write(to: multiAppIPA)

        // 5. Info.plist-less .app directory carrying inline svc #0x80 exploit Mach-O
        let noPlistApp = scanRoot.appendingPathComponent("NoPlistExploit.app", isDirectory: true)
        try FileManager.default.createDirectory(at: noPlistApp, withIntermediateDirectories: true)
        let exploitMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_" + IOCTokenArmor.tFsgetpath],
            textInstructions: [Self.svcWord, Self.retWord]
        ))
        try exploitMachO.write(to: noPlistApp.appendingPathComponent("NoPlistExploit"))

        // 6. Standalone .framework directory carrying exploit Mach-O
        let standaloneFw = scanRoot.appendingPathComponent("RogueKit.framework", isDirectory: true)
        try FileManager.default.createDirectory(at: standaloneFw, withIntermediateDirectories: true)
        try exploitMachO.write(to: standaloneFw.appendingPathComponent("RogueKit"))

        let unified = try await SecurityPipeline.shared.scanUnifiedInstalledAppsAsync(
            additionalLocations: [scanRoot],
            enableOnDeviceProbe: false
        )
        let asyncFindings = try await SecurityPipeline.shared.scanInstalledAppsAsync(additionalLocations: [scanRoot])

        for list in [unified.findings, asyncFindings] {
            XCTAssertEqual(list.count, 7, "All 7 hostile/malformed/plist-less/framework targets must surface without any silent try? drop")
            for f in list {
                XCTAssertEqual(f.riskTier, .highRisk, "Target \(f.displayName) must be .highRisk, got \(f.riskTier)")
                XCTAssertFalse(f.evidence.isWhitelistEligible, "Malformed or unverified-identity target \(f.displayName) must NOT be whitelist-eligible")
            }
        }

        // Even if a user adds wildcard custom rules matching malformed.package.* or NoPlistExploit, evaluateFindingWhitelist MUST refuse!
        let wlEngine = WhitelistEngine(tools: [
            WhitelistedTool(name: "TryBypassMalformed", allowedBundleIds: ["malformed.package.*", "NoPlistExploit", "RogueKit"])
        ])
        for f in unified.findings {
            XCTAssertFalse(wlEngine.evaluateFindingWhitelist(f).isWhitelisted, "evaluateFindingWhitelist must reject ineligible finding \(f.bundleId)")
        }
    }

    // MARK: - 5. Gap 4 + Pass 2: Prefix-Whitelist & Cross-Source TeamID Borrowing Blocked

    func test_r11_05_correlateAndMergeFindings_blocksPrefixWhitelistAndTeamIdBorrowing() throws {
        let wlEngine = WhitelistEngine(tools: [
            WhitelistedTool(
                name: "ExactCorpTool",
                allowedBundleIds: ["com.corp.tool"],
                allowedAppGroups: ["group.corp.tool"]
            ),
            WhitelistedTool(
                name: "TeamRestrictedSuite",
                allowedBundleIds: ["com.team.suite*"],
                allowedAppGroups: ["group.team.suite"],
                allowedTeamIds: ["TEAM999999"]
            )
        ])
        let customPipeline = SecurityPipeline(whitelistEngine: wlEngine)

        // Case A: Registry has com.corp.tool; local IPA has com.corp.tool.evil_plugin (same displayName -> prefix correlation)
        let regRecord = InstalledAppRegistryRecord(
            bundleId: "com.corp.tool",
            displayName: "CorpTool",
            version: "1.0",
            applicationType: "User",
            signerIdentity: "Apple Development: Dev",
            profileValidated: true,
            hasAppStoreMetadata: false,
            teamId: "CORP123456",
            appGroups: ["group.corp.tool"],
            bundlePath: "/var/containers/Bundle/Application/UUID/CorpTool.app"
        )
        let evilPluginFinding = ScanFinding(
            bundleId: "com.corp.tool.evil_plugin",
            displayName: "CorpTool",
            version: "1.0",
            teamId: "CORP123456",
            executablePath: "CorpTool.app/CorpTool",
            bundlePath: "/Documents/EvilPlugin.ipa",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            indicators: [
                ThreatIndicator(
                    signature: IOCTokenArmor.tCqCreate,
                    description: "Containermanager query primitive",
                    category: "Private API Symbol",
                    location: "LC_SYMTAB",
                    severity: .highRisk
                )
            ],
            evidence: AuditEvidence(
                matchedSymbols: [IOCTokenArmor.tCqCreate],
                hasAppGroups: true,
                appGroups: ["group.corp.tool"],
                installChannel: .developerSideloaded,
                cryptid: 0,
                isFairPlayEncrypted: false
            )
        )

        let mergedExact = customPipeline.correlateAndMergeFindings(
            registryRecords: [regRecord],
            packageFindings: [evilPluginFinding]
        )
        XCTAssertEqual(mergedExact.correlatedCount, 1)
        let mergedFinding = try XCTUnwrap(mergedExact.findings.first)
        XCTAssertEqual(mergedFinding.riskTier, .highRisk, "Suffix package com.corp.tool.evil_plugin must NOT borrow exact whitelist rule on com.corp.tool")
        XCTAssertFalse(mergedFinding.isWhitelisted)
        XCTAssertEqual(mergedFinding.evidence.correlatedPackageBundleId, "com.corp.tool.evil_plugin")
        XCTAssertFalse(wlEngine.evaluateFindingWhitelist(mergedFinding).isWhitelisted)

        // Case B: Positive control — explicit prefix wildcard rule `com.team.suite*` + matching TeamID on BOTH sources succeeds
        let suiteReg = InstalledAppRegistryRecord(
            bundleId: "com.team.suite.SIDELOAD1",
            displayName: "TeamSuite",
            version: "2.0",
            applicationType: "User",
            signerIdentity: "Apple Development",
            profileValidated: true,
            hasAppStoreMetadata: false,
            teamId: "TEAM999999",
            appGroups: ["group.team.suite"],
            bundlePath: "/var/containers/Bundle/Application/UUID/TeamSuite.app"
        )
        let signedSuitePkg = ScanFinding(
            bundleId: "com.team.suite",
            displayName: "TeamSuite",
            version: "2.0",
            teamId: "TEAM999999",
            executablePath: "TeamSuite.app/TeamSuite",
            bundlePath: "/Documents/TeamSuite.ipa",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            indicators: evilPluginFinding.indicators,
            evidence: AuditEvidence(
                matchedSymbols: [IOCTokenArmor.tCqCreate],
                hasAppGroups: true,
                appGroups: ["group.team.suite"],
                installChannel: .developerSideloaded
            )
        )
        let mergedWildcard = customPipeline.correlateAndMergeFindings(
            registryRecords: [suiteReg],
            packageFindings: [signedSuitePkg]
        )
        let validMerged = try XCTUnwrap(mergedWildcard.findings.first)
        XCTAssertEqual(validMerged.riskTier, .knownTool)
        XCTAssertTrue(validMerged.isWhitelisted)
        XCTAssertTrue(wlEngine.evaluateFindingWhitelist(validMerged).isWhitelisted)

        // Case C: Unsigned Trojanized IPA (`teamId: nil`) correlated with signed `suiteReg` (`teamId: "TEAM999999"`) MUST fail both initial merge & evaluateFindingWhitelist
        let unsignedTrojanPkg = ScanFinding(
            bundleId: "com.team.suite",
            displayName: "TeamSuite",
            version: "2.0",
            teamId: nil,
            executablePath: "TeamSuite.app/TeamSuite",
            bundlePath: "/Documents/UnsignedTrojan.ipa",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            indicators: evilPluginFinding.indicators,
            evidence: AuditEvidence(
                matchedSymbols: [IOCTokenArmor.tCqCreate],
                hasAppGroups: true,
                appGroups: ["group.team.suite"],
                installChannel: .developerSideloaded
            )
        )
        let mergedUnsigned = customPipeline.correlateAndMergeFindings(
            registryRecords: [suiteReg],
            packageFindings: [unsignedTrojanPkg]
        )
        let unsignedMergedFinding = try XCTUnwrap(mergedUnsigned.findings.first)
        XCTAssertEqual(unsignedMergedFinding.riskTier, .highRisk)
        XCTAssertFalse(unsignedMergedFinding.evidence.isTeamIdWhitelistVerified)
        XCTAssertFalse(wlEngine.evaluateFindingWhitelist(unsignedMergedFinding).isWhitelisted, "Session recalculation must NOT lend registry.teamId to unsigned package")
    }

    // MARK: - 6. Gap 5: CSStore2Parser O_NOFOLLOW, FIFO, Sliced Data, Trailing Records Near EOF, OOB String & C1/Variation Selectors

    func test_r11_06_csStore2Parser_noFollow_fifo_slicedData_trailingPluginAndBundleNearEOF_andUnicodeHardening() throws {
        let appUUID = "12345678-1234-1234-1234-123456789ABC"
        let plugUUID = "ABCDEF12-3456-7890-ABCD-EF1234567890"
        let groupUUID = "11111111-2222-3333-4444-555555555555"
        let bundleUUID = "99999999-8888-7777-6666-555555555555"

        // Build a compact CSStore2 buffer where the ONLY plugin record (0x104) sits right at the very end of the file (within < 0x25c bytes of EOF!)
        var store = Data(count: 4600)
        store[0] = 0x62; store[1] = 0x64; store[2] = 0x73; store[3] = 0x6c // "bdsl"
        let marker = Data("<string>".utf8)
        store.replaceSubrange(0x80..<(0x80 + marker.count), with: marker)

        func putLE32(_ val: UInt32, at off: Int) {
            var v = val.littleEndian
            withUnsafeBytes(of: &v) { store.replaceSubrange(off..<(off + 4), with: $0) }
        }
        var sCur = 0x100
        func putStr(sid: UInt32, _ text: String) -> UInt32 {
            putLE32(sid, at: sCur)
            let bytes = Array(text.utf8)
            putLE32(UInt32(bytes.count), at: sCur + 4)
            store.replaceSubrange((sCur + 8)..<(sCur + 8 + bytes.count), with: bytes)
            store[sCur + 8 + bytes.count] = 0
            sCur = (sCur + 8 + bytes.count + 4 + 3) & ~3
            return sid << 2
        }

        let appBidRef = putStr(sid: 10, "com.example.trailingapp")
        let appContRef = putStr(sid: 11, "/var/mobile/Containers/Data/Application/\(appUUID)")
        let appDispRef = putStr(sid: 12, "TrailingApp")
        let plugBidRef = putStr(sid: 20, "com.example.trailingapp.widget")
        let plugContRef = putStr(sid: 21, "/var/mobile/Containers/Data/PluginKitPlugin/\(plugUUID)")

        let rawGroupBytes = Array("/mobile/Containers/Shared/AppGroup/\(groupUUID)".utf8)
        store.replaceSubrange(sCur..<(sCur + rawGroupBytes.count), with: rawGroupBytes)
        sCur += (rawGroupBytes.count + 3) & ~3

        let rawBundleBytes = Array("/containers/Bundle/Application/\(bundleUUID)/TrailingApp.app\0".utf8)
        store.replaceSubrange(sCur..<(sCur + rawBundleBytes.count), with: rawBundleBytes)
        sCur += (rawBundleBytes.count + 3) & ~3

        // Place 0x23c bundle record AND 0x104 plugin record right against exact EOF (within final 0x10c bytes!)
        let pluginRecOff = store.count - (8 + 0x104)
        let bundleRecOff = (pluginRecOff - (8 + 0x23c)) & ~3

        putLE32(1, at: bundleRecOff)
        putLE32(0x23c, at: bundleRecOff + 4)
        putLE32(appBidRef, at: bundleRecOff + 8 + 0x0c)
        putLE32(appContRef, at: bundleRecOff + 8 + 0x64)
        putLE32(appDispRef, at: bundleRecOff + 8 + 0x68)
        putLE32(appDispRef, at: bundleRecOff + 8 + 0x70)

        putLE32(2, at: pluginRecOff)
        putLE32(0x104, at: pluginRecOff + 4)
        putLE32(plugBidRef, at: pluginRecOff + 8 + 0x00)
        putLE32(plugContRef, at: pluginRecOff + 8 + 0x50)

        // 1. Trailing 0x23c bundle + 0x104 plugin records near EOF both parsed!
        let snap = try CSStore2Parser.shared.parse(data: store)
        XCTAssertEqual(snap.appContainers["/var/mobile/Containers/Data/Application/\(appUUID)"], "com.example.trailingapp")
        XCTAssertEqual(snap.pluginContainers["/var/mobile/Containers/Data/PluginKitPlugin/\(plugUUID)"], "com.example.trailingapp.widget")
        XCTAssertTrue(snap.appGroups.contains("/var/mobile/Containers/Shared/AppGroup/\(groupUUID)"))
        XCTAssertTrue(snap.discoveredAppBundles.contains("/var/containers/Bundle/Application/\(bundleUUID)/TrailingApp.app"))

        // 2. Sliced Data (`startIndex == 137`) MUST NOT crash and MUST produce identical results!
        var outerBuffer = Data(repeating: 0xAA, count: 137)
        outerBuffer.append(store)
        outerBuffer.append(Data(repeating: 0xBB, count: 64))
        let sliced = outerBuffer[137..<(137 + store.count)]
        XCTAssertEqual(sliced.startIndex, 137)
        let slicedSnap = try CSStore2Parser.shared.parse(data: sliced)
        XCTAssertEqual(slicedSnap.appContainers, snap.appContainers)
        XCTAssertEqual(slicedSnap.pluginContainers, snap.pluginContainers)
        XCTAssertEqual(slicedSnap.appGroups, snap.appGroups)
        XCTAssertEqual(slicedSnap.discoveredAppBundles, snap.discoveredAppBundles)

        // 3. Unterminated odd-length string ending at exact `totalCount` MUST NOT trigger 1-byte OOB over-read
        var eofStringStore = store
        let tailStrOff = 0x900
        var sid99 = UInt32(99).littleEndian
        withUnsafeBytes(of: &sid99) { eofStringStore.replaceSubrange(tailStrOff..<(tailStrOff + 4), with: $0) }
        // Place a fake string entry right at `store.count - 13` with len = 5 (`offset + 8 + 5 == totalCount`, `(5 % 4) != 0`)
        var edgeStore = store
        let edgeOff = edgeStore.count - 13
        var edgeSid = UInt32(12).littleEndian
        var edgeLen = UInt32(5).littleEndian
        withUnsafeBytes(of: &edgeSid) { edgeStore.replaceSubrange(edgeOff..<(edgeOff + 4), with: $0) }
        withUnsafeBytes(of: &edgeLen) { edgeStore.replaceSubrange((edgeOff + 4)..<(edgeOff + 8), with: $0) }
        edgeStore.replaceSubrange((edgeOff + 8)..<(edgeOff + 13), with: Array("hello".utf8))
        XCTAssertNoThrow(try CSStore2Parser.shared.parse(data: edgeStore))

        // 4. Symlink & FIFO `.csstore` rejected via O_NOFOLLOW | O_NONBLOCK
        let realStoreURL = makeTempURL("valid.csstore")
        try store.write(to: realStoreURL)
        XCTAssertEqual(try CSStore2Parser.shared.parse(at: realStoreURL).appContainers, snap.appContainers)

        let symStoreURL = makeTempURL("symlink.csstore")
        XCTAssertEqual(symlink(realStoreURL.path, symStoreURL.path), 0)
        XCTAssertThrowsError(try CSStore2Parser.shared.parse(at: symStoreURL)) { err in
            guard case CSStore2ParserError.fileReadFailed = err else {
                XCTFail("Expected fileReadFailed on symlink .csstore, got \(err)")
                return
            }
        }

        let fifoStoreURL = makeTempURL("fifo.csstore")
        XCTAssertEqual(mkfifo(fifoStoreURL.path, 0o600), 0)
        XCTAssertThrowsError(try CSStore2Parser.shared.parse(at: fifoStoreURL)) { err in
            guard case CSStore2ParserError.fileReadFailed = err else {
                XCTFail("Expected non-blocking fileReadFailed on FIFO .csstore, got \(err)")
                return
            }
        }

        // 5. C1 control characters rejected (`nil`) & Variation Selectors (`FE00..FE0F`, `E0100..E01EF`) replaced with U+FFFD
        XCTAssertNil(CSStore2Parser.shared.sanitizeUnicodeName("Wallet\u{0085}App"))
        XCTAssertNil(CSStore2Parser.shared.sanitizeUnicodeName("Wallet\u{009B}App"))
        let vsName = try XCTUnwrap(CSStore2Parser.shared.sanitizeUnicodeName("MetaMask\u{FE0F}Pro\u{E0100}"))
        XCTAssertTrue(vsName.contains("\u{FFFD}"))
        XCTAssertFalse(vsName.unicodeScalars.contains { $0.value == 0xFE0F || $0.value == 0xE0100 })
    }

    // MARK: - 7. Gap 6 + Pass 3: Bounded O_NOFOLLOW File Staging, CLI Symlink Bundle Reject, Shared Brotli `sbr` & Zero-Han Check

    func test_r11_07_boundedNoFollowStaging_cliSymlinkBundleReject_sbrBrotliGuard_andEnglishZeroHan() async throws {
        // 1. Bounded O_NOFOLLOW copy & atomic write helpers
        let stageDir = makeTempURL("stage_dir")
        try FileManager.default.createDirectory(at: stageDir, withIntermediateDirectories: true)

        let srcFile = makeTempURL("legit_payload.bin")
        let srcBytes = Data((0..<8192).map { UInt8($0 & 0xFF) })
        try srcBytes.write(to: srcFile)

        let dstFile = stageDir.appendingPathComponent("copied.bin")
        let copiedCount = try IPAPackageScanner.copyBoundedRegularFileNoFollow(from: srcFile, to: dstFile, maxBytes: 16_384)
        XCTAssertEqual(copiedCount, srcBytes.count)
        XCTAssertEqual(try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: dstFile), srcBytes)

        // Reject > maxBytes quota
        XCTAssertThrowsError(try IPAPackageScanner.copyBoundedRegularFileNoFollow(from: srcFile, to: stageDir.appendingPathComponent("quota.bin"), maxBytes: 4096)) { err in
            guard case IPAPackageScannerError.quotaExceeded = err else {
                XCTFail("Expected quotaExceeded, got \(err)")
                return
            }
        }

        // Reject source symlink
        let srcSym = makeTempURL("src_sym.bin")
        XCTAssertEqual(symlink(srcFile.path, srcSym.path), 0)
        XCTAssertThrowsError(try IPAPackageScanner.copyBoundedRegularFileNoFollow(from: srcSym, to: stageDir.appendingPathComponent("out_sym.bin"))) { err in
            guard case IPAPackageScannerError.zipSlipDetected = err else {
                XCTFail("Expected zipSlipDetected on source symlink, got \(err)")
                return
            }
        }

        // Reject source FIFO without blocking
        let srcFIFO = makeTempURL("src_fifo.bin")
        XCTAssertEqual(mkfifo(srcFIFO.path, 0o600), 0)
        XCTAssertThrowsError(try IPAPackageScanner.copyBoundedRegularFileNoFollow(from: srcFIFO, to: stageDir.appendingPathComponent("out_fifo.bin")))

        // Reject pre-planted destination symlink on both copy & atomic write
        let outsideVictim = makeTempURL("victim.txt")
        try Data("UNTAMPERED".utf8).write(to: outsideVictim)
        let dstSym = stageDir.appendingPathComponent("preplanted_sym.bin")
        XCTAssertEqual(symlink(outsideVictim.path, dstSym.path), 0)
        XCTAssertThrowsError(try IPAPackageScanner.copyBoundedRegularFileNoFollow(from: srcFile, to: dstSym))
        XCTAssertThrowsError(try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(Data("OVERWRITE".utf8), to: dstSym))
        XCTAssertEqual(try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: outsideVictim), Data("UNTAMPERED".utf8))

        // 2. CLI scan on directory containing symlinked `.app` (`Payload/SymApp.app -> /tmp/...`) MUST exit 2 (never 0 SAFE)
        let realApp = makeTempURL("RealTarget.app")
        try FileManager.default.createDirectory(at: realApp, withIntermediateDirectories: true)
        let cliDir = makeTempURL("cli_scan_dir")
        try FileManager.default.createDirectory(at: cliDir, withIntermediateDirectories: true)
        XCTAssertEqual(symlink(realApp.path, cliDir.appendingPathComponent("SymApp.app").path), 0)

        let exitCode = await CLICommandRunner.run(
            arguments: ["wqguard-cli", "scan", cliDir.path, "--no-color"],
            stdout: FileHandle.nullDevice,
            stderr: FileHandle.nullDevice
        )
        XCTAssertEqual(exitCode, 2, "CLI scan on directory containing symlinked .app must fail-closed with exit code 2, never exit 0")

        // 3. Shared Brotli (`sbr`) blocked in Shields/scripts/brotli-guard.js & Stash override
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let guardJSURL = repoRoot.appendingPathComponent("Shields/scripts/brotli-guard.js")
        let guardJS = try String(decoding: IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: guardJSURL), as: UTF8.self)

        func evalGuardJS(contentEncoding: String, isQX: Bool = false) -> [String: Any] {
            let ctx = JSContext()!
            var captured: [String: Any] = [:]
            let doneBlock: @convention(block) (JSValue) -> Void = { val in
                captured = (val.toDictionary() as? [String: Any]) ?? [:]
            }
            ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
            ctx.setObject(["headers": ["Content-Encoding": contentEncoding]], forKeyedSubscript: "$response" as NSString)
            if isQX {
                ctx.setObject([:], forKeyedSubscript: "$task" as NSString)
            } else {
                ctx.setObject([:], forKeyedSubscript: "$httpClient" as NSString)
            }
            _ = ctx.evaluateScript(guardJS)
            return captured
        }

        XCTAssertEqual(evalGuardJS(contentEncoding: "sbr")["status"] as? Int, 403)
        XCTAssertEqual(evalGuardJS(contentEncoding: "gzip, sbr")["status"] as? Int, 403)
        XCTAssertEqual(evalGuardJS(contentEncoding: "sbr", isQX: true)["status"] as? String, "HTTP/1.1 403 Forbidden")
        XCTAssertNil(evalGuardJS(contentEncoding: "sbr_custom")["status"])

        // 4. English locale zero-Han verification on newly added diagnostics
        WQLocale.overrideLanguageCode = "en"
        defer { WQLocale.overrideLanguageCode = nil }
        let malformed = SecurityPipeline.makeMalformedPackageFinding(
            for: URL(fileURLWithPath: "/tmp/Evil.ipa"),
            error: IPAPackageScannerError.zipSlipDetected("../etc/passwd")
        )
        let enTexts = [
            malformed.indicators.first?.description ?? "",
            malformed.evidence.remediationGuidance
        ]
        for t in enTexts {
            XCTAssertNil(t.range(of: #"\p{Han}"#, options: .regularExpression), "English diagnostic leaked Han chars: \(t)")
        }
        do {
            _ = try LockdownInstProxyClient.validateAllowedLocalHost("evil.example.com")
        } catch {
            XCTAssertNil(error.localizedDescription.range(of: #"\p{Han}"#, options: .regularExpression))
        }
    }

    // MARK: - 8. ECDSA P-256 + Indefinite BER + Apple CDHashes (.1 & .2) + Boundary Inputs + devicectl /var/jb/ + Shield Dir Symlink

    func test_r11_08_cmsECDSA_appleCDHashes_indefiniteBER_boundaryInputs_devicectlJailbreakPath_andShieldSymlinkDir() throws {
        func derTLV(_ tag: UInt8, _ content: Data) -> Data {
            var out = Data([tag])
            let n = content.count
            if n < 0x80 {
                out.append(UInt8(n))
            } else if n <= 0xFF {
                out.append(0x81); out.append(UInt8(n))
            } else {
                out.append(0x82); out.append(UInt8((n >> 8) & 0xFF)); out.append(UInt8(n & 0xFF))
            }
            out.append(content)
            return out
        }
        func berIndef(_ tag: UInt8, _ content: Data) -> Data {
            var out = Data([tag, 0x80])
            out.append(content)
            out.append(contentsOf: [0x00, 0x00])
            return out
        }

        // 1. Generate ECDSA P-256 Root CA + Leaf ("Apple iPhone OS Application Signing")
        let ecDir = makeTempURL("ec_pki")
        try FileManager.default.createDirectory(at: ecDir, withIntermediateDirectories: true)
        let extFile = ecDir.appendingPathComponent("ec.ext")
        try """
        [req]
        distinguished_name = dn
        prompt = no
        [dn]
        C = US
        O = Apple Inc.
        CN = Apple Root CA - ECDSA Test
        [ca_ext]
        basicConstraints = critical,CA:true
        keyUsage = critical,keyCertSign,cRLSign
        subjectKeyIdentifier = hash
        [leaf_ext]
        basicConstraints = critical,CA:false
        keyUsage = critical,digitalSignature
        subjectKeyIdentifier = hash
        """.write(to: extFile, atomically: true, encoding: .utf8)

        let rKey = ecDir.appendingPathComponent("r.key")
        let rPem = ecDir.appendingPathComponent("r.pem")
        let rDer = ecDir.appendingPathComponent("r.der")
        let lKey = ecDir.appendingPathComponent("l.key")
        let lCsr = ecDir.appendingPathComponent("l.csr")
        let lPem = ecDir.appendingPathComponent("l.pem")
        let lDer = ecDir.appendingPathComponent("l.der")
        let lPkcs8Der = ecDir.appendingPathComponent("l_key.der")

        try runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", rKey.path])
        try runOpenSSL(["req", "-new", "-x509", "-key", rKey.path, "-days", "2", "-out", rPem.path, "-extensions", "ca_ext", "-config", extFile.path])
        try runOpenSSL(["x509", "-in", rPem.path, "-outform", "DER", "-out", rDer.path])

        try runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", lKey.path])
        try runOpenSSL(["req", "-new", "-key", lKey.path, "-out", lCsr.path, "-subj", "/C=US/O=Apple Inc./CN=Apple iPhone OS Application Signing"])
        try runOpenSSL(["x509", "-req", "-in", lCsr.path, "-CA", rPem.path, "-CAkey", rKey.path, "-CAcreateserial", "-days", "2", "-out", lPem.path, "-extfile", extFile.path, "-extensions", "leaf_ext"])
        try runOpenSSL(["x509", "-in", lPem.path, "-outform", "DER", "-out", lDer.path])
        // Export raw EC private key X9.63 (04 || X || Y || D) via openssl ec -outform DER or sign directly via openssl dgst -sha256 -sign
        _ = lPkcs8Der

        let rootCertDER = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: rDer)
        let leafCertDER = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: lDer)
        let customRootCert = try XCTUnwrap(SecCertificateCreateWithData(nil, rootCertDER as CFData))

        let rawMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 4096,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            xmlEntitlements: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict/></plist>",
            textInstructions: [Self.retWord]
        ))
        let preSized = try XCTUnwrap(preparePreSizedMachOSliceForSigning(rawMachO, reservedSigBytes: 16_384))
        let codePrefix = preSized.slice.subdata(in: 0..<preSized.csOffset)

        // Build primary SHA-256 CodeDirectory (slot 0) + alternate SHA-1 CodeDirectory (slot 0x1000)
        var slot5 = Data()
        let emptyEnt = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict/></plist>"
        slot5.r11be32(CSBlobConstants.entitlementXmlMagic)
        slot5.r11be32(UInt32(8 + emptyEnt.utf8.count))
        slot5.append(Data(emptyEnt.utf8))

        let primaryCD = buildSignedStyleCodeDirectory(identifier: "com.example.ecdsa", slicePrefixBytes: codePrefix, infoPlistData: nil, slot5FullBlob: slot5)

        // Build SHA-1 alternate CodeDirectory (hashType = 1, hashSize = 20)
        let pageSize = 4096
        let nCodeSlots = (codePrefix.count + pageSize - 1) / pageSize
        let identBytes = Data("com.example.ecdsa\0".utf8)
        let sha1HashOff = 88 + identBytes.count + 5 * 20
        var altSHA1CD = Data()
        altSHA1CD.r11be32(CSBlobConstants.codeDirectoryMagic)
        altSHA1CD.r11be32(UInt32(sha1HashOff + nCodeSlots * 20))
        altSHA1CD.r11be32(0x0002_0400)
        altSHA1CD.r11be32(0)
        altSHA1CD.r11be32(UInt32(sha1HashOff))
        altSHA1CD.r11be32(88)
        altSHA1CD.r11be32(5)
        altSHA1CD.r11be32(UInt32(nCodeSlots))
        altSHA1CD.r11be32(UInt32(codePrefix.count))
        altSHA1CD.append(20) // hashSize = 20
        altSHA1CD.append(1)  // CS_HASHTYPE_SHA1
        altSHA1CD.append(0)
        altSHA1CD.append(12)
        altSHA1CD.r11be32(0)
        altSHA1CD.append(contentsOf: [UInt8](repeating: 0, count: 44))
        altSHA1CD.append(identBytes)
        altSHA1CD.append(contentsOf: Insecure.SHA1.hash(data: slot5))
        altSHA1CD.append(contentsOf: [UInt8](repeating: 0, count: 4 * 20))
        for s in 0..<nCodeSlots {
            let ps = s * pageSize
            let pe = min(ps + pageSize, codePrefix.count)
            altSHA1CD.append(contentsOf: Insecure.SHA1.hash(data: codePrefix[ps..<pe]))
        }

        let primaryCDHash20 = Data(SHA256.hash(data: primaryCD).prefix(20))
        let altCDHash20 = Data(Insecure.SHA1.hash(data: altSHA1CD).prefix(20))

        func buildCustomCMS(cdHashesPlist: [Data], derHash20: Data) throws -> Data {
            let oidSignedData = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]))
            let oidData = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]))
            let oidSHA256 = derTLV(0x06, Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]))
            let oidECDSASHA256 = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]))
            let oidContentType = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03]))
            let oidMsgDigest = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04]))
            let oidCDHashesPlist = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x09, 0x01]))
            let oidCDHashesDER = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x09, 0x02]))

            let plistBytes = try PropertyListSerialization.data(fromPropertyList: ["cdhashes": cdHashesPlist], format: .xml, options: 0)
            let attr1 = derTLV(0x30, oidContentType + derTLV(0x31, oidData))
            let attr2 = derTLV(0x30, oidMsgDigest + derTLV(0x31, derTLV(0x04, Data(SHA256.hash(data: primaryCD)))))
            let attr3 = derTLV(0x30, oidCDHashesPlist + derTLV(0x31, derTLV(0x0C, plistBytes)))
            let derCDHashSeq = derTLV(0x30, oidSHA256 + derTLV(0x30, derTLV(0x04, derHash20) + derTLV(0x04, altCDHash20)))
            let attr4 = derTLV(0x30, oidCDHashesDER + derTLV(0x31, derCDHashSeq))

            let attrsInner = attr1 + attr2 + attr3 + attr4
            let signedAttrsForSig = derTLV(0x31, attrsInner)
            let attrsInURL = ecDir.appendingPathComponent("attrs_\(UUID().uuidString).der")
            let sigOutURL = ecDir.appendingPathComponent("sig_\(UUID().uuidString).der")
            try signedAttrsForSig.write(to: attrsInURL)
            try runOpenSSL(["dgst", "-sha256", "-sign", lKey.path, "-out", sigOutURL.path, attrsInURL.path])
            let sigBytes = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: sigOutURL)

            // Use v3 SignerInfo with [0] SubjectKeyIdentifier (0x80) AND indefinite-length BER (0x80) outer SignedData
            let signerInfo = derTLV(0x30,
                derTLV(0x02, Data([0x03])) +
                derTLV(0x80, Data([0x01, 0x02, 0x03, 0x04])) +
                derTLV(0x30, oidSHA256) +
                berIndef(0xA0, attrsInner) +
                derTLV(0x30, oidECDSASHA256) +
                derTLV(0x04, sigBytes)
            )
            let signedData = berIndef(0x30,
                derTLV(0x02, Data([0x03])) +
                derTLV(0x31, derTLV(0x30, oidSHA256)) +
                derTLV(0x30, oidData) +
                berIndef(0xA0, leafCertDER + rootCertDER) +
                derTLV(0x31, signerInfo)
            )
            return berIndef(0x30, oidSignedData + berIndef(0xA0, signedData))
        }

        // Positive control: ECDSA P-256 + indefinite BER + dual CodeDirectories (SHA-256 + SHA-1) + valid CDHashes (.1 & .2)
        let validECDSACMS = try buildCustomCMS(cdHashesPlist: [primaryCDHash20, altCDHash20], derHash20: primaryCDHash20)
        var validECWrapper = Data()
        validECWrapper.r11be32(CSBlobConstants.blobWrapperMagic)
        validECWrapper.r11be32(UInt32(8 + validECDSACMS.count))
        validECWrapper.append(validECDSACMS)

        let dualValidSB = buildSuperBlob(slots: [
            (CSBlobConstants.slotCodeDirectory, primaryCD),
            (CSBlobConstants.slotAlternateCodeDirectories, altSHA1CD),
            (CSBlobConstants.slotEntitlements, slot5),
            (CSBlobConstants.slotCMSSignature, validECWrapper)
        ])
        let dualValidSlice = writeSuperBlobIntoPreSizedSlice(preSized.slice, csOffset: preSized.csOffset, superBlob: dualValidSB)
        let dualSlices = try MachOParser.parseAllSlices(data: dualValidSlice)
        XCTAssertEqual(
            CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: dualSlices, customAnchorCertificates: [customRootCert]),
            .appleAppStoreVerified
        )

        // Negative control 1: Omit alternate CodeDirectory from Apple CDHashes plist (1.2.840.113635.100.9.1) -> MUST fail!
        let missingAltCMS = try buildCustomCMS(cdHashesPlist: [primaryCDHash20], derHash20: primaryCDHash20)
        var missingAltWrapper = Data()
        missingAltWrapper.r11be32(CSBlobConstants.blobWrapperMagic)
        missingAltWrapper.r11be32(UInt32(8 + missingAltCMS.count))
        missingAltWrapper.append(missingAltCMS)
        let missingAltSB = buildSuperBlob(slots: [
            (CSBlobConstants.slotCodeDirectory, primaryCD),
            (CSBlobConstants.slotAlternateCodeDirectories, altSHA1CD),
            (CSBlobConstants.slotEntitlements, slot5),
            (CSBlobConstants.slotCMSSignature, missingAltWrapper)
        ])
        let missingAltSlice = writeSuperBlobIntoPreSizedSlice(preSized.slice, csOffset: preSized.csOffset, superBlob: missingAltSB)
        XCTAssertTrue(
            CSBlobParser.shared.inspectCodeSignatureTrust(
                fromSlices: try MachOParser.parseAllSlices(data: missingAltSlice),
                customAnchorCertificates: [customRootCert]
            ).isDisqualifiedFromAppStore,
            "Unlisted alternate CodeDirectory must fail Apple CDHashes plist verification"
        )

        // Negative control 2: Mismatched hash in Apple DER CDHashes (1.2.840.113635.100.9.2) -> MUST fail!
        let badDERCMS = try buildCustomCMS(cdHashesPlist: [primaryCDHash20, altCDHash20], derHash20: Data(repeating: 0xEE, count: 20))
        var badDERWrapper = Data()
        badDERWrapper.r11be32(CSBlobConstants.blobWrapperMagic)
        badDERWrapper.r11be32(UInt32(8 + badDERCMS.count))
        badDERWrapper.append(badDERCMS)
        let badDERSB = buildSuperBlob(slots: [
            (CSBlobConstants.slotCodeDirectory, primaryCD),
            (CSBlobConstants.slotAlternateCodeDirectories, altSHA1CD),
            (CSBlobConstants.slotEntitlements, slot5),
            (CSBlobConstants.slotCMSSignature, badDERWrapper)
        ])
        let badDERSlice = writeSuperBlobIntoPreSizedSlice(preSized.slice, csOffset: preSized.csOffset, superBlob: badDERSB)
        XCTAssertTrue(
            CSBlobParser.shared.inspectCodeSignatureTrust(
                fromSlices: try MachOParser.parseAllSlices(data: badDERSlice),
                customAnchorCertificates: [customRootCert]
            ).isDisqualifiedFromAppStore,
            "Mismatched Apple DER CDHashes attribute must fail verification"
        )

        // 2. Empty & boundary inputs across hardened APIs
        XCTAssertEqual(CSBlobParser.shared.inspectCodeSignatureTrust(from: nil), .absentOrSynthetic)
        XCTAssertEqual(CSBlobParser.shared.inspectCodeSignatureTrust(from: Data()), .absentOrSynthetic)
        XCTAssertEqual(CSBlobParser.shared.inspectCodeSignatureTrust(from: Data(repeating: 0xFF, count: 11)), .adHocOrUnsigned)
        XCTAssertFalse(WhitelistEngine.shared.isWhitelistedForBoth(primaryBundleId: "", secondaryBundleId: "").isWhitelisted)
        XCTAssertNil(CSStore2Parser.shared.sanitizeUnicodeName(""))

        // 3. InstalledAppRegistryScanner: non-ASCII 10-char team prefix & devicectl /var/jb/ + /Applications/ TrollStore paths
        let nonASCIITeamRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.example.nonascii",
            "Entitlements": ["application-identifier": "ＡＢＣＤＥＦＧＨＩＪ.com.example.nonascii"]
        ]))
        XCTAssertNil(nonASCIITeamRec.teamId, "Fullwidth non-ASCII 10-character prefix must NOT be accepted as Apple Team ID")

        let jbWalletRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
            "bundleIdentifier": "io.metamask.MetaMask",
            "name": "MetaMask",
            "url": "file:///var/jb/Applications/MetaMask.app"
        ]))
        XCTAssertFalse(jbWalletRec.hasAppStoreMetadata, "devicectl /var/jb/ path must never be treated as official App Store")
        let jbEvaluated = InstalledAppRegistryScanner.shared.evaluateRecords([jbWalletRec], includeAppStoreApps: false)
        XCTAssertEqual(jbEvaluated.first?.riskTier, .highRisk)

        // 4. SurgeBrotliShieldHelper: pre-planted symlink at WQGuardSurgeExports directory unlinked safely without following
        let victimDir = makeTempURL("shield_victim_dir")
        try FileManager.default.createDirectory(at: victimDir, withIntermediateDirectories: true)
        let surgeExportDir = FileManager.default.temporaryDirectory.appendingPathComponent("WQGuardSurgeExports", isDirectory: true)
        try? FileManager.default.removeItem(at: surgeExportDir)
        XCTAssertEqual(symlink(victimDir.path, IPAPackageScanner.stripTrailingSlashes(surgeExportDir.path)), 0)

        let exportedShield = try SurgeBrotliShieldHelper.shared.exportShieldToTemporaryFile(for: .stash)
        XCTAssertTrue(IPAPackageScanner.isNonSymlinkDirectory(at: surgeExportDir))
        let victimItems = try FileManager.default.contentsOfDirectory(atPath: victimDir.path)
        XCTAssertTrue(victimItems.isEmpty, "Shield export must never write through a pre-planted directory symlink into victimDir")
        let stashContent = try String(decoding: IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: exportedShield), as: UTF8.self)
        XCTAssertTrue(stashContent.contains("dcb|sbr"))
    }

    // MARK: - 9. Malformed SuperBlob / OOB BlobIndex / Missing-BundleID Transplant & 64KB Entropy Padding Unmasking

    func test_r11_09_malformedSuperBlobDisqualification_missingBundleIdTransplant_and64KBRandomPrefixUnmasking() throws {
        // 1. Corrupted SuperBlob magic, truncated <12B LC_CODE_SIGNATURE, OOB SuperBlob.length, and OOB CS_BlobIndex
        //    on a forged cryptid=1 MetaMask + ElleKit + svc #0x80 IPA MUST fail-closed to .adHocOrUnsigned (.developerSideloaded)
        let groupEntXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>com.apple.security.application-groups</key><array><string>group.com.evil.escape</string></array></dict></plist>"

        // (a) Corrupt SuperBlob magic (0xfade0cc1)
        var corruptMagicSB = Data()
        corruptMagicSB.r11be32(0xfade_0cc1)
        corruptMagicSB.r11be32(16)
        corruptMagicSB.r11be32(0)
        corruptMagicSB.r11be32(0)

        // (b) Valid SuperBlob header with OOB CS_BlobIndex offset (0x00FF_FF00 > totalLength)
        var oobIndexSB = Data()
        oobIndexSB.r11be32(CSBlobConstants.superBlobMagic)
        oobIndexSB.r11be32(28)
        oobIndexSB.r11be32(2)
        oobIndexSB.r11be32(CSBlobConstants.slotCodeDirectory)
        oobIndexSB.r11be32(0x00FF_FF00)
        oobIndexSB.r11be32(CSBlobConstants.slotCMSSignature)
        oobIndexSB.r11be32(0x00FF_FF00)

        // (c) SuperBlob declared length > buffer.count
        var oobLenSB = Data()
        oobLenSB.r11be32(CSBlobConstants.superBlobMagic)
        oobLenSB.r11be32(4096)
        oobLenSB.r11be32(0)

        for (label, rawSB) in [("corruptMagic", corruptMagicSB), ("oobIndex", oobIndexSB), ("oobLength", oobLenSB)] {
            XCTAssertEqual(
                CSBlobParser.shared.inspectCodeSignatureTrust(from: rawSB),
                .adHocOrUnsigned,
                "Malformed SuperBlob (\(label)) must fail closed to .adHocOrUnsigned, never .absentOrSynthetic"
            )
            let forgedBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 0x4000,
                cryptsize: 0x4000,
                linkedDylibs: [
                    "@rpath/ElleKit.dylib",
                    "/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"
                ],
                symbols: ["_main"],
                xmlEntitlements: groupEntXML,
                rawCodeSignatureSlot: (
                    slot: CSBlobConstants.slotCodeDirectory,
                    magic: CSBlobConstants.codeDirectoryMagic,
                    data: Data(repeating: 0, count: 36)
                ),
                textInstructions: [Self.svcWord, Self.retWord],
                extraCStringLiterals: ["com.apple.MobileGestalt.plist"]
            ))
            // Overwrite LC_CODE_SIGNATURE payload directly with `rawSB`
            var patchedBin = forgedBin
            let ncmds = patchedBin.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
            var cur = 32
            for _ in 0..<ncmds {
                let cmd = patchedBin.withUnsafeBytes { $0.load(fromByteOffset: cur, as: UInt32.self).littleEndian }
                let cmdsz = Int(patchedBin.withUnsafeBytes { $0.load(fromByteOffset: cur + 4, as: UInt32.self).littleEndian })
                if cmd == UInt32(LC_CODE_SIGNATURE) {
                    let csOff = Int(patchedBin.withUnsafeBytes { $0.load(fromByteOffset: cur + 8, as: UInt32.self).littleEndian })
                    patchedBin.removeSubrange(csOff..<patchedBin.count)
                    var szLE = UInt32(rawSB.count).littleEndian
                    withUnsafeBytes(of: &szLE) { patchedBin.replaceSubrange((cur + 12)..<(cur + 16), with: $0) }
                    patchedBin.append(rawSB)
                    break
                }
                cur += cmdsz
            }

            let plist = try PropertyListSerialization.data(fromPropertyList: [
                "CFBundleIdentifier": "io.metamask.MetaMask",
                "CFBundleDisplayName": "MetaMask",
                "CFBundleExecutable": "MetaMask",
                "CFBundleShortVersionString": "7.0"
            ], format: .xml, options: 0)
            let ipaURL = makeTempURL("malformed_sb_\(label).ipa")
            try buildZip([
                ZipSpec(path: "Payload/MetaMask.app/Info.plist", payload: plist),
                ZipSpec(path: "Payload/MetaMask.app/MetaMask", payload: patchedBin, unixMode: 0o100755)
            ]).write(to: ipaURL)

            let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
            XCTAssertEqual(finding.installChannel, .developerSideloaded, "Malformed SuperBlob (\(label)) must NOT classify as .appStore")
            XCTAssertEqual(finding.riskTier, .highRisk)
            XCTAssertTrue(finding.indicators.contains { $0.signature == SignatureCatalog.directSyscallRule.pattern })
            XCTAssertTrue(finding.indicators.contains { $0.signature.hasPrefix("MobileGestaltTamper:") })
            XCTAssertTrue(finding.indicators.contains { $0.signature.hasPrefix("IMPERSONATION:") })
            XCTAssertTrue(finding.indicators.contains { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" })
        }

        // 2. Whole-binary transplant of signed binary whose Info.plist omits CFBundleIdentifier while spoofing CFBundleDisplayName = "MetaMask"
        let safariExecURL = URL(fileURLWithPath: "/Applications/Safari.app/Contents/MacOS/Safari")
        if FileManager.default.isReadableFile(atPath: safariExecURL.path),
           let safariData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: safariExecURL),
           let safariSlices = try? MachOParser.parseAllSlices(data: safariData),
           let armSlice = safariSlices.first(where: { $0.cpuType == CPU_TYPE_ARM64 }) {
            let omittedBidPlist = try PropertyListSerialization.data(fromPropertyList: [
                "CFBundleDisplayName": "MetaMask",
                "CFBundleExecutable": "MetaMask",
                "CFBundleShortVersionString": "7.0"
            ], format: .xml, options: 0)
            let bindDisp = CSBlobParser.shared.verifyBundleInfoPlistBinding(
                fromSlices: [armSlice],
                infoPlistData: omittedBidPlist,
                plistBundleId: nil
            )
            XCTAssertNotNil(bindDisp, "Omitting CFBundleIdentifier in Info.plist must fail CodeDirectory identifier binding")
            XCTAssertEqual(bindDisp?.isDisqualifiedFromAppStore, true)
        }

        // 3. Forged cryptid=1 + CS_ADHOC with 64 KB CSPRNG high-entropy prefix followed by ARM64 svc #0x80 + XPC C-string at +64 KB
        //    AND __LINKEDIT Brotli symbol preservation even when 100% of __TEXT is high-entropy
        var randomWords: [UInt32] = []
        randomWords.reserveCapacity(16_384)
        var randomBytes = Data(count: 65_536)
        _ = randomBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 65_536, $0.baseAddress!) }
        for off in stride(from: 0, to: 65_536, by: 4) {
            var w = randomBytes.withUnsafeBytes { $0.load(fromByteOffset: off, as: UInt32.self).littleEndian }
            if w == Self.svcWord { w ^= 0xFF }
            randomWords.append(w)
        }
        // Append 1024 NOP instructions (4 KB low-entropy code page) + svc #0x80 + ret after the 64 KB CSPRNG prefix
        let nopWord: UInt32 = 0xD503_201F
        let textWords = randomWords + [UInt32](repeating: nopWord, count: 1024) + [Self.svcWord, Self.retWord]

        var adhocCDPayload = Data()
        adhocCDPayload.r11be32(0x0002_0400)
        adhocCDPayload.r11be32(CSBlobConstants.csAdhocFlag)
        adhocCDPayload.append(contentsOf: [UInt8](repeating: 0, count: 28))

        let padded64KBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0x4000,
            cryptsize: 0x20000,
            symbols: ["_main", "_BrotliDecoderDecompressStream"],
            xmlEntitlements: groupEntXML,
            rawCodeSignatureSlot: (
                slot: CSBlobConstants.slotCodeDirectory,
                magic: CSBlobConstants.codeDirectoryMagic,
                data: adhocCDPayload
            ),
            textInstructions: textWords,
            extraCStringLiterals: ["com.apple.containermanagerd.system"]
        ))
        let paddedPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.evil.padded64k",
            "CFBundleDisplayName": "Padded64K",
            "CFBundleExecutable": "Padded64K",
            "CFBundleShortVersionString": "1.0"
        ], format: .xml, options: 0)
        let paddedIPA = makeTempURL("padded_64k_random_svc80.ipa")
        try buildZip([
            ZipSpec(path: "Payload/Padded64K.app/Info.plist", payload: paddedPlist),
            ZipSpec(path: "Payload/Padded64K.app/Padded64K", payload: padded64KBin, unixMode: 0o100755)
        ]).write(to: paddedIPA)

        let paddedFinding = try IPAPackageScanner.shared.scan(ipaURL: paddedIPA)
        XCTAssertEqual(paddedFinding.installChannel, .developerSideloaded)
        XCTAssertEqual(paddedFinding.riskTier, .highRisk)
        XCTAssertTrue(paddedFinding.indicators.contains { $0.signature == SignatureCatalog.directSyscallRule.pattern }, "svc #0x80 after 64 KB CSPRNG prefix must be unmasked")
        XCTAssertTrue(paddedFinding.indicators.contains { $0.signature == "com.apple.containermanagerd.system" }, "Plaintext C-string after 64 KB CSPRNG prefix must be unmasked")
        XCTAssertTrue(paddedFinding.indicators.contains { $0.signature.contains("Brotli") || $0.description.contains("Brotli") }, "__LINKEDIT Brotli symbol must remain audited on disqualified cryptid=1 binary")
    }

    // MARK: - 10. Lockdown HostCertificate Reflection TLS Pinning & Port Truncation Guard

    func test_r11_10_lockdownHostCertReflectionPinning_andPortTruncationGuard() throws {
        let pkiDir = makeTempURL("lockdown_reflection_pki")
        try FileManager.default.createDirectory(at: pkiDir, withIntermediateDirectories: true)

        let rootKey = pkiDir.appendingPathComponent("root.key")
        let rootPem = pkiDir.appendingPathComponent("root.pem")
        let rootDer = pkiDir.appendingPathComponent("root.der")
        let hostKey = pkiDir.appendingPathComponent("host.key")
        let hostCsr = pkiDir.appendingPathComponent("host.csr")
        let hostPem = pkiDir.appendingPathComponent("host.pem")
        let hostDer = pkiDir.appendingPathComponent("host.der")
        let hostKeyDer = pkiDir.appendingPathComponent("host_key.der")
        let hostP12 = pkiDir.appendingPathComponent("host.p12")
        let devKey = pkiDir.appendingPathComponent("dev.key")
        let devCsr = pkiDir.appendingPathComponent("dev.csr")
        let devPem = pkiDir.appendingPathComponent("dev.pem")
        let devDer = pkiDir.appendingPathComponent("dev.der")

        let caExt = pkiDir.appendingPathComponent("ca.ext")
        try "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n".write(to: caExt, atomically: true, encoding: .utf8)

        try runOpenSSL(["genrsa", "-out", rootKey.path, "2048"])
        try runOpenSSL(["req", "-new", "-x509", "-key", rootKey.path, "-days", "365", "-subj", "/CN=Lockdown Pairing Root CA", "-addext", "basicConstraints=critical,CA:TRUE", "-out", rootPem.path])
        try runOpenSSL(["x509", "-in", rootPem.path, "-outform", "DER", "-out", rootDer.path])

        // Generate HostCertificate + HostPrivateKey (signed by RootCertificate — attacker possesses both from pairing file!)
        try runOpenSSL(["genrsa", "-out", hostKey.path, "2048"])
        try runOpenSSL(["rsa", "-in", hostKey.path, "-outform", "DER", "-out", hostKeyDer.path])
        try runOpenSSL(["req", "-new", "-key", hostKey.path, "-subj", "/CN=Lockdown Host", "-out", hostCsr.path])
        try runOpenSSL(["x509", "-req", "-in", hostCsr.path, "-CA", rootPem.path, "-CAkey", rootKey.path, "-CAcreateserial", "-days", "365", "-out", hostPem.path])
        try runOpenSSL(["x509", "-in", hostPem.path, "-outform", "DER", "-out", hostDer.path])
        try runOpenSSL(["pkcs12", "-export", "-inkey", hostKey.path, "-in", hostPem.path, "-passout", "pass:reflectpw", "-out", hostP12.path])

        // Generate genuine DeviceCertificate (signed by RootCertificate)
        try runOpenSSL(["genrsa", "-out", devKey.path, "2048"])
        try runOpenSSL(["req", "-new", "-key", devKey.path, "-subj", "/CN=Lockdown iOS Device", "-out", devCsr.path])
        try runOpenSSL(["x509", "-req", "-in", devCsr.path, "-CA", rootPem.path, "-CAkey", rootKey.path, "-CAcreateserial", "-days", "365", "-out", devPem.path])
        try runOpenSSL(["x509", "-in", devPem.path, "-outform", "DER", "-out", devDer.path])

        let rootDERBytes = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: rootDer)
        let hostDERBytes = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: hostDer)
        let hostKeyDERBytes = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: hostKeyDer)
        let devDERBytes = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: devDer)
        let hostP12Bytes = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: hostP12)

        var importItems: CFArray?
        let status = SecPKCS12Import(hostP12Bytes as CFData, [kSecImportExportPassphrase as String: "reflectpw"] as CFDictionary, &importItems)
        guard status == errSecSuccess,
              let items = importItems as? [[String: Any]],
              let rawId = items.first?[kSecImportItemIdentity as String] else {
            return
        }
        let reflectIdentity = unsafeBitCast(rawId as AnyObject, to: SecIdentity.self)
        let reflectServerTLS = NWProtocolTLS.Options()
        if let nwId = sec_identity_create(reflectIdentity) {
            sec_protocol_options_set_local_identity(reflectServerTLS.securityProtocolOptions, nwId)
        }

        // Test BOTH pairing configurations (with DeviceCertificate AND with DeviceCertificate omitted / RootCertificate-only):
        // A rogue server presenting HostCertificate + HostPrivateKey MUST be rejected by real `createTLSOptions(from:)`!
        let pairingWithDev = LockdownPairingFile(
            hostID: "H-REFLECT-1",
            systemBUID: "B-REFLECT-1",
            hostCertificateDER: hostDERBytes,
            hostPrivateKeyDER: hostKeyDERBytes,
            rootCertificateDER: rootDERBytes,
            deviceCertificateDER: devDERBytes
        )
        let pairingRootOnly = LockdownPairingFile(
            hostID: "H-REFLECT-2",
            systemBUID: "B-REFLECT-2",
            hostCertificateDER: hostDERBytes,
            hostPrivateKeyDER: hostKeyDERBytes,
            rootCertificateDER: rootDERBytes,
            deviceCertificateDER: nil
        )

        for pairing in [pairingWithDev, pairingRootOnly] {
            guard let realClientTLS = try? LockdownInstProxyClient.shared.createTLSOptions(from: pairing) else {
                continue
            }
            var portAddr = sockaddr_in()
            portAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            portAddr.sin_family = sa_family_t(AF_INET)
            portAddr.sin_port = 0
            portAddr.sin_addr.s_addr = inet_addr("127.0.0.1")
            let pfd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
            _ = withUnsafePointer(to: &portAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(pfd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
            var actual = sockaddr_in()
            var aLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = withUnsafeMutablePointer(to: &actual) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(pfd, $0, &aLen) }
            }
            let port = UInt16(bigEndian: actual.sin_port)
            Darwin.close(pfd)

            let srvParams = NWParameters(tls: reflectServerTLS, tcp: NWProtocolTCP.Options())
            srvParams.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port)!)
            let listener = try NWListener(using: srvParams)
            let readySema = DispatchSemaphore(value: 0)
            listener.stateUpdateHandler = { if case .ready = $0 { readySema.signal() } }
            listener.newConnectionHandler = { conn in conn.start(queue: DispatchQueue(label: "r11.reflect.srv")) }
            listener.start(queue: DispatchQueue(label: "r11.reflect.listen"))
            _ = readySema.wait(timeout: .now() + 2.0)

            XCTAssertThrowsError(
                try LockdownInstProxyClient.shared.browseApplications(
                    host: "127.0.0.1",
                    port: port,
                    useTLS: true,
                    tlsOptions: realClientTLS
                ),
                "HostCertificate + HostPrivateKey reflection server must be rejected by TLS pinning"
            )
            listener.cancel()
        }
    }

    // MARK: - 11. Decoy Info.plist / ._Malware.ipa / Probe Suppression / devicectl Spoofed com.apple.* Defense

    func test_r11_11_decoyInfoPlist_dotUnderscoreIPA_safeProbeSuppression_andDeviceCtlComAppleEscape() async throws {
        // 1. Decoy Info.plist in a user directory + non-AppleDouble `._Stealer.ipa` + genuine AppleDouble `._ benign.ipa`
        let userDir = makeTempURL("user_docs_decoy_plist")
        try FileManager.default.createDirectory(at: userDir, withIntermediateDirectories: true)

        let benignExec = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, symbols: ["_main"]))
        let decoyPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.benign.decoy",
            "CFBundleDisplayName": "Decoy",
            "CFBundleExecutable": "DecoyExec",
            "CFBundleShortVersionString": "1.0"
        ], format: .xml, options: 0)
        try decoyPlist.write(to: userDir.appendingPathComponent("Info.plist"))
        try benignExec.write(to: userDir.appendingPathComponent("DecoyExec"))

        // Malicious `._Stealer.ipa` disguised with `._` prefix (real PKZIP IPA, NOT 0x00051607 AppleDouble!)
        let evilBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"],
            textInstructions: [Self.svcWord, Self.retWord]
        ))
        let evilPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.evil.dotunderscore",
            "CFBundleDisplayName": "DotUnderscoreEvil",
            "CFBundleExecutable": "EvilExec",
            "CFBundleShortVersionString": "1.0"
        ], format: .xml, options: 0)
        let dotUnderscoreIPA = userDir.appendingPathComponent("._Stealer.ipa")
        try buildZip([
            ZipSpec(path: "Payload/Evil.app/Info.plist", payload: evilPlist),
            ZipSpec(path: "Payload/Evil.app/EvilExec", payload: evilBin, unixMode: 0o100755)
        ]).write(to: dotUnderscoreIPA)

        // Genuine macOS AppleDouble `._Meta.ipa` starting with `0x00 0x05 0x16 0x07` MUST be ignored without false positive
        let appleDoubleFile = userDir.appendingPathComponent("._Meta.ipa")
        try Data([0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00]).write(to: appleDoubleFile)

        let discoveredFindings = try await SecurityPipeline.shared.scanInstalledAppsAsync(additionalLocations: [userDir])
        XCTAssertTrue(
            discoveredFindings.contains { $0.bundleId == "com.evil.dotunderscore" && $0.riskTier == .highRisk },
            "Malicious ._Stealer.ipa alongside a decoy Info.plist must NOT be skipped"
        )
        XCTAssertFalse(
            discoveredFindings.contains { $0.displayName == "._Meta.ipa" },
            "Genuine 0x00051607 AppleDouble metadata file must be ignored cleanly"
        )

        // Also verify `wqguard-cli -c` catches `._Stealer.ipa` in a batch directory with exit code 1
        let cliBatchDir = makeTempURL("cli_dotunderscore_batch")
        try FileManager.default.createDirectory(at: cliBatchDir, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: dotUnderscoreIPA, to: cliBatchDir.appendingPathComponent("._Stealer.ipa"))
        try Data([0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00]).write(to: cliBatchDir.appendingPathComponent("._Meta.ipa"))
        let outPipe = Pipe(), errPipe = Pipe()
        let cliCode = await CLICommandRunner.run(arguments: ["wqguard-cli", "-c", cliBatchDir.path], stdout: outPipe.fileHandleForWriting, stderr: errPipe.fileHandleForWriting)
        outPipe.fileHandleForWriting.closeFile()
        errPipe.fileHandleForWriting.closeFile()
        XCTAssertEqual(cliCode, 1, "wqguard-cli must detect malicious ._Stealer.ipa and return exit code 1")

        // 2. `.safe` decoy package finding (`com.tigisoftware.Filza.theme`) must NEVER silence a `.highRisk` live URL-scheme probe (`com.tigisoftware.Filza`)
        let safeDecoyPkg = ScanFinding(
            bundleId: "com.tigisoftware.Filza.theme",
            displayName: "ThemePack",
            version: "1.0",
            bundlePath: "/Documents/DecoyTheme.ipa",
            installChannel: .developerSideloaded,
            riskTier: .safe,
            evidence: .empty(channel: .developerSideloaded)
        )
        let activeFilzaProbe = ScanFinding(
            bundleId: "com.tigisoftware.Filza",
            displayName: "Filza File Manager",
            version: "4.0",
            bundlePath: "url-scheme://filza",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            indicators: [ThreatIndicator(
                signature: "URLSchemeProbe:filza",
                description: "Active Filza URL scheme detected",
                category: "On-Device Probe",
                location: "LSApplicationWorkspace",
                severity: .highRisk
            )],
            evidence: .empty(channel: .developerSideloaded)
        )
        let mergedProbe = SecurityPipeline.shared.correlateAndMergeFindings(
            registryRecords: [],
            packageFindings: [safeDecoyPkg],
            probeFindings: [activeFilzaProbe]
        )
        XCTAssertEqual(mergedProbe.probeCount, 1, "A .safe decoy package must never suppress an active .highRisk URL-scheme probe")
        XCTAssertTrue(mergedProbe.findings.contains { $0.bundleId == "com.tigisoftware.Filza" && $0.riskTier == .highRisk })

        // 3. `devicectl` snapshot with spoofed `com.apple.fake_persistence_helper` + `no-sandbox: true` and omitted `signerIdentity`
        let spoofDeviceCtlJSON = """
        {
          "result": {
            "apps": [
              {
                "bundleIdentifier": "com.apple.fake_persistence_helper",
                "name": "PersistenceHelper",
                "version": "2.0",
                "defaultApp": false,
                "internalApp": false,
                "builtByDeveloper": false,
                "entitlements": {
                  "com.apple.private.security.no-sandbox": true
                },
                "url": "file:///private/var/containers/Bundle/Application/AAAA-BBBB/PersistenceHelper.app/"
              }
            ]
          }
        }
        """
        let ctlRecs = try InstalledAppRegistryScanner.shared.parseSnapshotData(Data(spoofDeviceCtlJSON.utf8))
        let ctlEvaluated = InstalledAppRegistryScanner.shared.evaluateRecords(ctlRecs, includeAppStoreApps: false)
        XCTAssertEqual(ctlEvaluated.count, 1, "Spoofed com.apple.* TrollStore persistence helper in devicectl JSON must NOT be filtered as Apple OS app")
        XCTAssertEqual(ctlEvaluated.first?.riskTier, .highRisk)
        XCTAssertTrue(ctlEvaluated.first?.indicators.contains { $0.signature == "com.apple.private.security.no-sandbox" } == true)
    }

    // MARK: - 12. CSStore2 Pre-Heap Collision Override, Whitelist Built-In Immunity, Symlink CLI Output & Dangling Exec

    func test_r11_12_csstorePreHeapCollisionOverride_whitelistBuiltInImmunity_cliSymlinkOut_andDanglingExec() async throws {
        // 1. CSStore2Parser: pre-heap unit table stringID collision MUST be overridden by authoritative `<string>` heap entry,
        //    and `..` traversal in `bundlePathOffset` MUST be rejected
        let layout = CSStore2Parser.supportedLayouts[0] // 27.0: bundleSize=0x250
        let sidBid: UInt32 = 10
        let sidCont: UInt32 = 11
        let sidTravPath: UInt32 = 12
        let validUUID = "11111111-2222-3333-4444-555555555555"

        func appendCSString(_ buf: inout Data, sid: UInt32, str: String) {
            while buf.count % 4 != 0 { buf.append(0) }
            let utf8 = Data(str.utf8)
            buf.r11le32(sid)
            buf.r11le32(UInt32(utf8.count))
            buf.append(utf8)
            buf.append(0)
            while buf.count % 4 != 0 { buf.append(0) }
        }

        var csData = Data("bdsl".utf8)
        csData.append(Data(count: 60))
        // Pre-heap decoy string collision BEFORE `<string>` marker!
        appendCSString(&csData, sid: sidBid, str: "com.safe.preheap_decoy")

        // Bundle unit record referencing sidBid, sidCont, sidTravPath
        var rec = Data(count: Int(layout.bundleSize))
        func writeRecU32(_ off: UInt32, _ val: UInt32) {
            var le = val.littleEndian
            withUnsafeBytes(of: &le) { rec.replaceSubrange(Int(off)..<(Int(off) + 4), with: $0) }
        }
        writeRecU32(layout.bundlePathOffset, sidTravPath << 2)
        writeRecU32(layout.bundleIDOffset, sidBid << 2)
        writeRecU32(layout.containerOffset, sidCont << 2)
        csData.r11le32(1)
        csData.r11le32(layout.bundleSize)
        csData.append(rec)

        // Authoritative `<string>` heap
        while csData.count % 4 != 0 { csData.append(0) }
        csData.append(Data("<string>".utf8))
        appendCSString(&csData, sid: sidBid, str: "com.evil.authoritative_heap")
        appendCSString(&csData, sid: sidCont, str: "/var/mobile/Containers/Data/Application/\(validUUID)")
        appendCSString(&csData, sid: sidTravPath, str: "/var/containers/Bundle/Application/../../../../tmp/Trap.app")
        if csData.count < CSStore2Parser.minStoreBytes {
            csData.append(Data(count: CSStore2Parser.minStoreBytes - csData.count))
        }

        let snap = try CSStore2Parser.shared.parse(data: csData)
        XCTAssertEqual(
            snap.appContainers["/var/mobile/Containers/Data/Application/\(validUUID)"],
            "com.evil.authoritative_heap",
            "Authoritative <string> heap entry must override pre-heap stringID collision"
        )
        XCTAssertTrue(snap.bundlePaths.isEmpty, "Traversal bundlePath escaping /var/containers/Bundle/Application must be rejected")

        // 2. MCMReader in-memory quota enforcement
        let oversizedMCM = Data(repeating: 0x41, count: Int(MCMReader.maxPlistBytes) + 1)
        XCTAssertThrowsError(try MCMReader.shared.parseMetadata(data: oversizedMCM)) { err in
            XCTAssertEqual(err as? MCMReaderError, .fileTooLarge(size: Int64(oversizedMCM.count), maxAllowed: MCMReader.maxPlistBytes))
        }

        // 3. WhitelistEngine built-in `WQGuard` overwrite/removal immunity & CorruptMachO/AppexExecutableTraversal non-downgrade
        let wl = WhitelistEngine()
        wl.registerCustomTool(WhitelistedTool(
            name: "wqguard",
            allowedBundleIds: ["com.evil.*"],
            allowedAppGroups: [],
            expectedSignatures: [],
            isEnabled: true,
            isBuiltIn: true
        ))
        wl.removeTool(named: "WQGuard")
        let builtInRule = try XCTUnwrap(wl.tool(named: "WQGuard"))
        XCTAssertTrue(builtInRule.isBuiltIn)
        XCTAssertFalse(builtInRule.allowedBundleIds.contains("com.evil.*"), "Built-in WQGuard rule must never be overwritten or removed")

        wl.registerCustomTool(WhitelistedTool(
            name: "CustomPermissive",
            allowedBundleIds: ["com.custom.perm"],
            allowedAppGroups: [],
            expectedSignatures: []
        ))
        XCTAssertFalse(
            wl.isWhitelisted(bundleId: "com.custom.perm", matchedSignatures: ["CorruptMachO:Frameworks/Bad.dylib"]).isWhitelisted,
            "CorruptMachO anomaly must never be downgraded by a permissive custom whitelist rule"
        )
        XCTAssertFalse(
            wl.isWhitelisted(bundleId: "com.custom.perm", matchedSignatures: ["AppexExecutableTraversal"]).isWhitelisted,
            "AppexExecutableTraversal must never be downgraded by a permissive custom whitelist rule"
        )

        // 4. Dangling escaping symlink at CFBundleExecutable in scanBundle -> throws zipSlipDetected (never missingExecutable or stat follow)
        let danglingBundle = makeTempURL("DanglingExec.app")
        try FileManager.default.createDirectory(at: danglingBundle, withIntermediateDirectories: true)
        let danglingPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.evil.dangling",
            "CFBundleExecutable": "DanglingBin"
        ], format: .xml, options: 0)
        try danglingPlist.write(to: danglingBundle.appendingPathComponent("Info.plist"))
        XCTAssertEqual(symlink("/nonexistent_outside_root/secret_bin", danglingBundle.appendingPathComponent("DanglingBin").path), 0)
        XCTAssertThrowsError(try SecurityPipeline.shared.scanBundle(at: danglingBundle)) { err in
            guard case IPAPackageScannerError.zipSlipDetected = err else {
                XCTFail("Expected zipSlipDetected on dangling escaping executable symlink, got \(err)")
                return
            }
        }

        // 5. CLI `--export-surge` / `--out` through a symlinked parent directory MUST fail with exit code 2 without writing into target dir
        let realTargetDir = makeTempURL("cli_real_victim_dir")
        try FileManager.default.createDirectory(at: realTargetDir, withIntermediateDirectories: true)
        let symlinkParent = makeTempURL("cli_symlink_parent")
        XCTAssertEqual(symlink(realTargetDir.path, symlinkParent.path), 0)
        let oPipe = Pipe(), ePipe = Pipe()
        let exportExit = await CLICommandRunner.run(
            arguments: ["wqguard-cli", "--export-surge", symlinkParent.appendingPathComponent("pwned.sgmodule").path],
            stdout: oPipe.fileHandleForWriting,
            stderr: ePipe.fileHandleForWriting
        )
        oPipe.fileHandleForWriting.closeFile()
        ePipe.fileHandleForWriting.closeFile()
        XCTAssertEqual(exportExit, 2, "CLI export through symlink parent directory must fail closed with exit code 2")
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: realTargetDir.path).isEmpty)

        // 6. Brotli JS guard also blocks `x-dcb` and `x-sbr`
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let jsSource = try String(decoding: IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: repoRoot.appendingPathComponent("Shields/scripts/brotli-guard.js")), as: UTF8.self)
        for enc in ["x-dcb", "x-sbr"] {
            let ctx = try XCTUnwrap(JSContext())
            var captured: JSValue?
            let doneBlock: @convention(block) (JSValue) -> Void = { val in captured = val }
            ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
            ctx.setObject(["headers": ["Content-Encoding": enc]], forKeyedSubscript: "$response" as NSString)
            ctx.evaluateScript(jsSource)
            XCTAssertEqual(captured?.forProperty("status")?.toInt32(), 403, "brotli-guard.js must block \(enc)")
        }
    }

    // MARK: - 15. LC_CODE_SIGNATURE-Stripped & Unverified cryptid=1 CSPRNG Pre-Sideload Bypass Regression

    func test_r11_15_unsignedAndUnverifiedCryptid1CSPRNGPreSideloadBypass_caughtAcrossIPAAppAppexAndStandalone() throws {
        // Build 8192 bytes (2048 UInt32 words) of deterministic SHA-256 counter-mode CSPRNG ciphertext (entropy > 7.95 bits/byte)
        var csprngWords: [UInt32] = []
        csprngWords.reserveCapacity(2048)
        for blockIdx in UInt64(0)..<256 {
            var counterLE = blockIdx.littleEndian
            let seed = withUnsafeBytes(of: &counterLE) { Data($0) } + Data("WQGuard-CSPRNG-FairPlay-Test".utf8)
            let digest = Array(SHA256.hash(data: seed))
            for w in stride(from: 0, to: 32, by: 4) {
                let word = UInt32(digest[w])
                    | (UInt32(digest[w + 1]) << 8)
                    | (UInt32(digest[w + 2]) << 16)
                    | (UInt32(digest[w + 3]) << 24)
                csprngWords.append(word)
            }
        }

        func makeCryptid1CSPRNGBinary(
            linkedDylibs: [String],
            symbols: [String] = ["_main"],
            xmlEntitlements: String? = nil,
            includeCodeSignature: Bool = false,
            embeddedInfoPlist: Data? = nil
        ) throws -> Data {
            var customSects: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
            if let plistPayload = embeddedInfoPlist {
                customSects.append(("__DATA_CONST", "__info_plist", 0, plistPayload))
            }
            var raw = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 0,
                cryptsize: 0x2000,
                linkedDylibs: linkedDylibs,
                symbols: symbols,
                xmlEntitlements: xmlEntitlements,
                includeCodeSignature: includeCodeSignature,
                textInstructions: csprngWords,
                customSections: customSects
            ))
            // Bound __TEXT.filesize to end of __text and set [cryptoff, cryptoff+cryptsize) = [postHeaderStart, textEnd)
            // so BOTH `hasUnencryptedSegments == false` AND `hasForgedPlaintextFairPlayRange == false` hold simultaneously!
            let parsedInitial = try MachOParser.shared.parse(data: raw)
            let postHeaderStart = UInt32(MemoryLayout<mach_header_64>.size) + parsedInitial.sizeofcmds
            let textSect = try XCTUnwrap(parsedInitial.textSegment?.sections.first { $0.sectionName == "__text" })
            let textEnd = textSect.offset + UInt32(textSect.size)
            let ncmds = raw.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
            var cur = MemoryLayout<mach_header_64>.size
            for _ in 0..<ncmds {
                let cmd = raw.withUnsafeBytes { $0.load(fromByteOffset: cur, as: UInt32.self).littleEndian }
                let cmdsize = Int(raw.withUnsafeBytes { $0.load(fromByteOffset: cur + 4, as: UInt32.self).littleEndian })
                if cmd == UInt32(LC_SEGMENT_64) {
                    let segNameData = raw.subdata(in: (cur + 8)..<(cur + 24))
                    let segName = String(decoding: segNameData.prefix { $0 != 0 }, as: UTF8.self)
                    if segName == "__TEXT" {
                        var fsLE = UInt64(textEnd).littleEndian
                        var vmLE = UInt64((Int(textEnd) + 0x3FFF) & ~0x3FFF).littleEndian
                        withUnsafeBytes(of: &vmLE) { raw.replaceSubrange((cur + 32)..<(cur + 40), with: $0) }
                        withUnsafeBytes(of: &fsLE) { raw.replaceSubrange((cur + 48)..<(cur + 56), with: $0) }
                    }
                } else if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                    var offLE = postHeaderStart.littleEndian
                    var szLE = (textEnd - postHeaderStart).littleEndian
                    withUnsafeBytes(of: &offLE) { raw.replaceSubrange((cur + 8)..<(cur + 12), with: $0) }
                    withUnsafeBytes(of: &szLE) { raw.replaceSubrange((cur + 12)..<(cur + 16), with: $0) }
                }
                cur += cmdsize
            }
            return raw
        }

        // 0. 12-byte 0-slot empty CS_SuperBlob must fail closed to .adHocOrUnsigned
        var zeroSlotSB = Data()
        zeroSlotSB.r11be32(CSBlobConstants.superBlobMagic)
        zeroSlotSB.r11be32(12)
        zeroSlotSB.r11be32(0)
        XCTAssertEqual(CSBlobParser.shared.inspectCodeSignatureTrust(from: zeroSlotSB), .adHocOrUnsigned)

        // 1. Combined LC_CODE_SIGNATURE-stripped cryptid=1 CSPRNG MetaMask + @rpath/ElleKit.dylib + AccessorySetupKit.framework (missing BT keys)
        let walletPlistDict: [String: Any] = [
            "CFBundleIdentifier": "io.metamask.MetaMask",
            "CFBundleDisplayName": "MetaMask",
            "CFBundleExecutable": "MetaMask",
            "CFBundleShortVersionString": "7.35.0"
        ]
        let walletPlistData = try PropertyListSerialization.data(fromPropertyList: walletPlistDict, format: .xml, options: 0)
        let combinedUnsignedBin = try makeCryptid1CSPRNGBinary(
            linkedDylibs: [
                "/usr/lib/libSystem.B.dylib",
                "@rpath/ElleKit.dylib",
                "/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"
            ]
        )

        // Prove binary has zero LC_CODE_SIGNATURE, high-entropy FairPlay range, zero unencrypted segments, and .absentOrSynthetic trust
        let parsedUnsigned = try MachOParser.shared.parse(data: combinedUnsignedBin)
        XCTAssertTrue(parsedUnsigned.codeSignatures.isEmpty)
        XCTAssertTrue(parsedUnsigned.isFairPlayEncrypted)
        XCTAssertFalse(parsedUnsigned.hasForgedPlaintextFairPlayRange)
        let parsedDetails = try MachOScanner.shared.parseMachO(data: combinedUnsignedBin)
        XCTAssertFalse(parsedDetails.hasUnencryptedSegments)
        XCTAssertEqual(CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: [parsedUnsigned]), .absentOrSynthetic)
        XCTAssertTrue(CSBlobParser.hasMissingCodeSignature(inSlices: [parsedUnsigned]))

        let combinedAppDir = makeTempURL("UnsignedCryptid1MetaMask.app")
        try FileManager.default.createDirectory(at: combinedAppDir, withIntermediateDirectories: true)
        try walletPlistData.write(to: combinedAppDir.appendingPathComponent("Info.plist"))
        try combinedUnsignedBin.write(to: combinedAppDir.appendingPathComponent("MetaMask"))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: combinedAppDir.appendingPathComponent("MetaMask").path)

        let combinedIPAURL = makeTempURL("UnsignedCryptid1MetaMask.ipa")
        try buildZip([
            .init(path: "Payload/MetaMask.app/Info.plist", payload: walletPlistData),
            .init(path: "Payload/MetaMask.app/MetaMask", payload: combinedUnsignedBin, unixMode: 0o100755)
        ]).write(to: combinedIPAURL)

        let ipaFinding = try IPAPackageScanner.shared.scan(ipaURL: combinedIPAURL)
        let appFinding = try SecurityPipeline.shared.scanBundle(at: combinedAppDir)
        for (label, finding) in [("IPA", ipaFinding), ("AppBundle", appFinding)] {
            XCTAssertEqual(finding.riskTier, .highRisk, "\(label) must detect unsigned cryptid=1 CSPRNG MetaMask trojan as .highRisk")
            let sigs = Set(finding.indicators.map(\.signature))
            XCTAssertTrue(sigs.contains("IMPERSONATION:MetaMask"), "\(label) missing IMPERSONATION:MetaMask: \(sigs)")
            XCTAssertTrue(sigs.contains { $0.lowercased().contains("ellekit") }, "\(label) missing ElleKit injected dylib: \(sigs)")
            XCTAssertTrue(sigs.contains("CVE-2026-84493:AccessorySetupKitBypass"), "\(label) missing CVE-2026-84493:AccessorySetupKitBypass: \(sigs)")
            XCTAssertTrue(finding.evidence.matchedSymbols.contains("IMPERSONATION:MetaMask"))
            XCTAssertTrue(finding.evidence.matchedSymbols.contains("CVE-2026-84493:AccessorySetupKitBypass"))
        }

        // Also verify standalone Mach-O binary (`SecurityPipeline.scanBinary`) with embedded __TEXT,__info_plist
        let standaloneBinData = try makeCryptid1CSPRNGBinary(
            linkedDylibs: [
                "@rpath/ElleKit.dylib",
                "/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit",
                "/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"
            ],
            embeddedInfoPlist: walletPlistData
        )
        let standaloneURL = makeTempURL("UnsignedCryptid1MetaMaskStandalone")
        try standaloneBinData.write(to: standaloneURL)
        let standaloneFinding = try SecurityPipeline.shared.scanBinary(at: standaloneURL)
        XCTAssertEqual(standaloneFinding.riskTier, .highRisk)
        let standaloneSigs = Set(standaloneFinding.indicators.map(\.signature))
        XCTAssertTrue(standaloneSigs.contains("IMPERSONATION:MetaMask"))
        XCTAssertTrue(standaloneSigs.contains { $0.lowercased().contains("ellekit") })
        XCTAssertTrue(standaloneSigs.contains("CVE-2026-84493:AccessorySetupKitBypass"))
        XCTAssertTrue(standaloneSigs.contains("CVE-2026-65339:MediaExperience.framework"))

        // 2. Verify each vector independently on unsigned cryptid=1 CSPRNG bundles (including StoreKit/sandboxReceipt TestFlight spoof & .appex)
        let btCompliantWalletPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "io.metamask.MetaMask",
            "CFBundleDisplayName": "MetaMask",
            "CFBundleExecutable": "MetaMask",
            "NSBluetoothAlwaysUsageDescription": "Bluetooth hardware wallet",
            "NSAccessorySetupKitSupports": ["Bluetooth"]
        ], format: .xml, options: 0)
        let cleanCryptid1Bin = try makeCryptid1CSPRNGBinary(linkedDylibs: ["/usr/lib/libSystem.B.dylib"])
        let tfSpoofWalletIPA = makeTempURL("UnsignedCryptid1MetaMaskTFSpoof.ipa")
        try buildZip([
            .init(path: "Payload/MetaMask.app/Info.plist", payload: btCompliantWalletPlist),
            .init(path: "Payload/MetaMask.app/MetaMask", payload: cleanCryptid1Bin, unixMode: 0o100755),
            .init(path: "Payload/MetaMask.app/StoreKit/sandboxReceipt", payload: Data("sandbox".utf8))
        ]).write(to: tfSpoofWalletIPA)
        let tfSpoofFinding = try IPAPackageScanner.shared.scan(ipaURL: tfSpoofWalletIPA)
        XCTAssertEqual(tfSpoofFinding.riskTier, .highRisk)
        XCTAssertTrue(tfSpoofFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })

        // Standalone AccessorySetupKit vector on non-brand app & embedded .appex
        let genericNoBtPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.example.bletool",
            "CFBundleDisplayName": "BleTool",
            "CFBundleExecutable": "BleTool"
        ], format: .xml, options: 0)
        let genericBtCompliantPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.example.blehost",
            "CFBundleDisplayName": "BleHost",
            "CFBundleExecutable": "BleHost",
            "NSBluetoothAlwaysUsageDescription": "Allowed",
            "NSAccessorySetupKitSupports": ["Bluetooth"]
        ], format: .xml, options: 0)
        let accOnlyBin = try makeCryptid1CSPRNGBinary(
            linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"]
        )
        let accOnlyIPA = makeTempURL("UnsignedCryptid1AccOnly.ipa")
        try buildZip([
            .init(path: "Payload/BleTool.app/Info.plist", payload: genericNoBtPlist),
            .init(path: "Payload/BleTool.app/BleTool", payload: accOnlyBin, unixMode: 0o100755)
        ]).write(to: accOnlyIPA)
        let accOnlyFinding = try IPAPackageScanner.shared.scan(ipaURL: accOnlyIPA)
        XCTAssertEqual(accOnlyFinding.riskTier, .highRisk)
        XCTAssertTrue(accOnlyFinding.indicators.contains { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" })

        let appexNoBtPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.example.blehost.ext",
            "CFBundleExecutable": "BleExt"
        ], format: .xml, options: 0)
        let appexAccIPA = makeTempURL("UnsignedCryptid1AppexAcc.ipa")
        try buildZip([
            .init(path: "Payload/BleHost.app/Info.plist", payload: genericBtCompliantPlist),
            .init(path: "Payload/BleHost.app/BleHost", payload: cleanCryptid1Bin, unixMode: 0o100755),
            .init(path: "Payload/BleHost.app/PlugIns/BleExt.appex/Info.plist", payload: appexNoBtPlist),
            .init(path: "Payload/BleHost.app/PlugIns/BleExt.appex/BleExt", payload: accOnlyBin, unixMode: 0o100755)
        ]).write(to: appexAccIPA)
        let appexAccFinding = try IPAPackageScanner.shared.scan(ipaURL: appexAccIPA)
        XCTAssertEqual(appexAccFinding.riskTier, .highRisk)
        XCTAssertTrue(appexAccFinding.indicators.contains { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" })

        // 3. Slot-5-only `<dict/>` SuperBlob (!codeSignatures.isEmpty, .absentOrSynthetic) must NOT evade Impersonation, ElleKit, AccessorySetupKitBypass, or MediaExperience
        let emptyEntXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict/></plist>"
        let slot5FakeBin = try makeCryptid1CSPRNGBinary(
            linkedDylibs: [
                "@rpath/ElleKit.dylib",
                "/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit",
                "/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"
            ],
            xmlEntitlements: emptyEntXML,
            includeCodeSignature: true
        )
        let parsedSlot5 = try MachOParser.shared.parse(data: slot5FakeBin)
        XCTAssertFalse(parsedSlot5.codeSignatures.isEmpty)
        XCTAssertEqual(CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: [parsedSlot5]), .absentOrSynthetic)

        let slot5AppDir = makeTempURL("Slot5OnlyCryptid1MetaMask.app")
        try FileManager.default.createDirectory(at: slot5AppDir, withIntermediateDirectories: true)
        try walletPlistData.write(to: slot5AppDir.appendingPathComponent("Info.plist"))
        try slot5FakeBin.write(to: slot5AppDir.appendingPathComponent("MetaMask"))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: slot5AppDir.appendingPathComponent("MetaMask").path)

        let slot5IPA = makeTempURL("Slot5OnlyCryptid1MetaMask.ipa")
        try buildZip([
            .init(path: "Payload/MetaMask.app/Info.plist", payload: walletPlistData),
            .init(path: "Payload/MetaMask.app/MetaMask", payload: slot5FakeBin, unixMode: 0o100755)
        ]).write(to: slot5IPA)

        for slot5Finding in [try IPAPackageScanner.shared.scan(ipaURL: slot5IPA), try SecurityPipeline.shared.scanBundle(at: slot5AppDir)] {
            XCTAssertEqual(slot5Finding.riskTier, .highRisk)
            let slot5Sigs = Set(slot5Finding.indicators.map(\.signature))
            XCTAssertTrue(slot5Sigs.contains("IMPERSONATION:MetaMask"))
            XCTAssertTrue(slot5Sigs.contains { $0.lowercased().contains("ellekit") })
            XCTAssertTrue(slot5Sigs.contains("CVE-2026-84493:AccessorySetupKitBypass"))
            XCTAssertTrue(slot5Sigs.contains("CVE-2026-65339:MediaExperience.framework"))
        }

        // 4. Hybrid TrollFools-style injection: genuine Apple-signed main binary (.appleAppStoreVerified + matching Info.plist)
        //    paired with an LC_CODE_SIGNATURE-stripped cryptid=1 CSPRNG embedded Dylibs/ElleKit.dylib importing AccessorySetupKit
        let safariExecURL = URL(fileURLWithPath: "/Applications/Safari.app/Contents/MacOS/Safari")
        let safariPlistURL = URL(fileURLWithPath: "/Applications/Safari.app/Contents/Info.plist")
        if FileManager.default.fileExists(atPath: safariExecURL.path),
           let safariData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: safariExecURL),
           let safariPlistData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: safariPlistURL),
           let safariSlices = try? MachOParser.parseAllSlices(data: safariData),
           let safariArmSlice = MachOParser.selectAuditSlices(from: safariSlices).first {
            XCTAssertEqual(CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: [safariArmSlice]), .appleAppStoreVerified)

            let hybridSafariIPA = makeTempURL("HybridAppleSignedMainUnsignedCryptid1Dylib.ipa")
            try buildZip([
                .init(path: "Payload/Safari.app/Info.plist", payload: safariPlistData),
                .init(path: "Payload/Safari.app/Safari", payload: safariArmSlice.sliceData, unixMode: 0o100755),
                .init(path: "Payload/Safari.app/Dylibs/ElleKit.dylib", payload: accOnlyBin, unixMode: 0o100755)
            ]).write(to: hybridSafariIPA)

            let hybridSafariFinding = try IPAPackageScanner.shared.scan(ipaURL: hybridSafariIPA)
            XCTAssertEqual(hybridSafariFinding.riskTier, .highRisk)
            let hybridSigs = Set(hybridSafariFinding.indicators.map(\.signature))
            XCTAssertTrue(hybridSigs.contains { $0.lowercased().contains("ellekit") })
            XCTAssertTrue(hybridSigs.contains("CVE-2026-84493:AccessorySetupKitBypass"))
        }
    }

    // MARK: - 16. Dead x86_64 Slice & Multi-Slice / Multi-Slot Entitlement Identity Shadowing Anti-Bypass

    func test_r11_16_deadX86SliceAndMultiSliceSlotIdentityShadowing_neverSpoofsWhitelistOrHidesImpersonation() throws {
        func packTwoSliceFAT(_ s0: (cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t, data: Data),
                             _ s1: (cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t, data: Data)) -> Data {
            var fat = Data()
            fat.r11be32(0xCAFE_BABE)
            fat.r11be32(2)
            let off0: UInt32 = 4096
            let off1: UInt32 = UInt32((Int(off0) + s0.data.count + 4095) & ~4095)
            fat.r11be32(UInt32(bitPattern: s0.cpuType))
            fat.r11be32(UInt32(bitPattern: s0.cpuSubtype))
            fat.r11be32(off0)
            fat.r11be32(UInt32(s0.data.count))
            fat.r11be32(12)
            fat.r11be32(UInt32(bitPattern: s1.cpuType))
            fat.r11be32(UInt32(bitPattern: s1.cpuSubtype))
            fat.r11be32(off1)
            fat.r11be32(UInt32(s1.data.count))
            fat.r11be32(12)
            while fat.count < Int(off0) { fat.append(0) }
            fat.append(s0.data)
            while fat.count < Int(off1) { fat.append(0) }
            fat.append(s1.data)
            return fat
        }

        // 1. Dead x86_64 simulator slice injecting `GOODTEAM99.com.wqguard.app` + `group.com.wqguard.app`
        //    behind a real iOS `arm64` exploit slice (`EVILTEAM01.io.metamask.MetaMask` + `container_query_create` + `group.io.metamask`)
        let armExploitXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>application-identifier</key><string>EVILTEAM01.io.metamask.MetaMask</string>
            <key>com.apple.developer.team-identifier</key><string>EVILTEAM01</string>
            <key>com.apple.security.application-groups</key><array><string>group.com.wqguard.app</string></array>
        </dict></plist>
        """
        let deadX86SpoofXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>application-identifier</key><string>GOODTEAM99.com.wqguard.app</string>
            <key>com.apple.developer.team-identifier</key><string>GOODTEAM99</string>
            <key>com.apple.security.application-groups</key><array><string>group.com.wqguard.app</string></array>
        </dict></plist>
        """
        let armExploitSlice = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_" + IOCTokenArmor.tCqCreate],
            xmlEntitlements: armExploitXML,
            textInstructions: [Self.retWord]
        ))
        let deadX86SpoofSlice = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .x86_64,
            symbols: ["_main"],
            xmlEntitlements: deadX86SpoofXML
        ))
        let fatArmX86 = packTwoSliceFAT(
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, armExploitSlice),
            (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, deadX86SpoofSlice)
        )

        // Standalone scanBinary
        let fatBinURL = makeTempURL("fat_arm64_dead_x86_spoof")
        try fatArmX86.write(to: fatBinURL)
        let binFinding = try SecurityPipeline.shared.scanBinary(at: fatBinURL)
        XCTAssertEqual(binFinding.riskTier, .highRisk, "Dead x86_64 simulator slice must NEVER overwrite arm64 identity or spoof WQGuard")
        XCTAssertFalse(binFinding.isWhitelisted)
        XCTAssertEqual(binFinding.bundleId, "io.metamask.MetaMask")
        XCTAssertTrue(binFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })

        // Bundle & IPA spoofing CFBundleIdentifier = "com.wqguard.app" in Info.plist
        let spoofWQGuardPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.wqguard.app",
            "CFBundleDisplayName": "WQGuard",
            "CFBundleExecutable": "WQGuard"
        ], format: .xml, options: 0)
        let fatAppDir = makeTempURL("FatDeadX86Spoof.app")
        try FileManager.default.createDirectory(at: fatAppDir, withIntermediateDirectories: true)
        try spoofWQGuardPlist.write(to: fatAppDir.appendingPathComponent("Info.plist"))
        try fatArmX86.write(to: fatAppDir.appendingPathComponent("WQGuard"))

        let fatIPAURL = makeTempURL("FatDeadX86Spoof.ipa")
        try buildZip([
            .init(path: "Payload/WQGuard.app/Info.plist", payload: spoofWQGuardPlist),
            .init(path: "Payload/WQGuard.app/WQGuard", payload: fatArmX86, unixMode: 0o100755)
        ]).write(to: fatIPAURL)

        for (lbl, f) in [("Bundle", try SecurityPipeline.shared.scanBundle(at: fatAppDir)),
                         ("IPA", try IPAPackageScanner.shared.scan(ipaURL: fatIPAURL))] {
            XCTAssertEqual(f.riskTier, .highRisk, "\(lbl) must reject dead x86_64 identity overwrite")
            XCTAssertFalse(f.isWhitelisted)
            XCTAssertFalse(f.evidence.isWhitelistEligible)
            XCTAssertTrue(f.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })
        }

        // 2. Multi-ARM-slice FAT (`arm64` + `arm64e` subtype 2):
        //    (a) Slice 0 (`arm64`) declares MetaMask, Slice 1 (`arm64e`) declares `com.wqguard.app` -> conflicting identities, NEVER whitelisted
        var arm64eSpoofSlice = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_" + IOCTokenArmor.tCqCreate],
            xmlEntitlements: deadX86SpoofXML,
            textInstructions: [Self.retWord]
        ))
        var subtype2LE = UInt32(2).littleEndian
        withUnsafeBytes(of: &subtype2LE) { arm64eSpoofSlice.replaceSubrange(8..<12, with: $0) }
        let fatArm64AndArm64e = packTwoSliceFAT(
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, armExploitSlice),
            (CPU_TYPE_ARM64, 2, arm64eSpoofSlice)
        )
        let dualArmIPA = makeTempURL("DualArmShadowSpoof.ipa")
        try buildZip([
            .init(path: "Payload/WQGuard.app/Info.plist", payload: spoofWQGuardPlist),
            .init(path: "Payload/WQGuard.app/WQGuard", payload: fatArm64AndArm64e, unixMode: 0o100755)
        ]).write(to: dualArmIPA)
        let dualArmFinding = try IPAPackageScanner.shared.scan(ipaURL: dualArmIPA)
        XCTAssertEqual(dualArmFinding.riskTier, .highRisk)
        XCTAssertFalse(dualArmFinding.isWhitelisted)
        XCTAssertFalse(dualArmFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(dualArmFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })

        //    (b) Mixed Universal FAT (`arm64` has Slot-5 PrivateAccessoryEntitlement, `arm64e` has `codeSignatures.isEmpty`, both `cryptid = 1`)
        let privAccXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>com.apple.private.accessorysetupkit.pair</key><true/></dict></plist>"
        let armSlot5Crypt1 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            symbols: ["_main"],
            xmlEntitlements: privAccXML,
            textInstructions: [Self.retWord]
        ))
        var arm64eUnsignedCrypt1 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            symbols: ["_main"],
            includeCodeSignature: false,
            textInstructions: [Self.retWord]
        ))
        withUnsafeBytes(of: &subtype2LE) { arm64eUnsignedCrypt1.replaceSubrange(8..<12, with: $0) }
        let mixedMissingCSFat = packTwoSliceFAT(
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, armSlot5Crypt1),
            (CPU_TYPE_ARM64, 2, arm64eUnsignedCrypt1)
        )
        let validBtPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.example.mixedfat",
            "CFBundleExecutable": "MixedFat",
            "NSBluetoothAlwaysUsageDescription": "BT",
            "NSAccessorySetupKitSupports": ["Bluetooth"]
        ], format: .xml, options: 0)
        let mixedMissingCSIPA = makeTempURL("MixedSlot5AndUnsignedCrypt1Fat.ipa")
        try buildZip([
            .init(path: "Payload/MixedFat.app/Info.plist", payload: validBtPlist),
            .init(path: "Payload/MixedFat.app/MixedFat", payload: mixedMissingCSFat, unixMode: 0o100755)
        ]).write(to: mixedMissingCSIPA)
        let mixedMissingFinding = try IPAPackageScanner.shared.scan(ipaURL: mixedMissingCSIPA)
        XCTAssertEqual(mixedMissingFinding.riskTier, .highRisk)
        XCTAssertTrue(mixedMissingFinding.indicators.contains { $0.signature == "CVE-2026-84493:PrivateAccessoryEntitlement" })
    }

    // MARK: - 17. Unverified / Ad-Hoc / Stolen-Mobileprovision TeamID Anti-Spoofing

    func test_r11_17_unverifiedAdHocAndStolenProvisionTeamId_blockedAcrossBinaryBundleIPARegistryAndMerge() throws {
        let wlEngine = WhitelistEngine(tools: WhitelistEngine.defaultTools + [
            WhitelistedTool(
                name: "CorpTeamLockedTool",
                allowedBundleIds: ["com.corp.locked*"],
                allowedAppGroups: ["group.corp.locked"],
                allowedTeamIds: ["CORP112233"],
                expectedSignatures: [IOCTokenArmor.tCqCreate]
            )
        ])
        WhitelistEngine.shared.registerCustomTool(WhitelistedTool(
            name: "CorpTeamLockedTool",
            allowedBundleIds: ["com.corp.locked*"],
            allowedAppGroups: ["group.corp.locked"],
            allowedTeamIds: ["CORP112233"],
            expectedSignatures: [IOCTokenArmor.tCqCreate]
        ))
        defer { WhitelistEngine.shared.resetToDefaults() }
        let pipeline = SecurityPipeline(whitelistEngine: wlEngine)

        let forgedTeamEntXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
            <key>application-identifier</key><string>CORP112233.com.corp.locked.trojan</string>
            <key>com.apple.developer.team-identifier</key><string>CORP112233</string>
            <key>com.apple.security.application-groups</key><array><string>group.corp.locked</string></array>
        </dict></plist>
        """
        let unsignedTrojanBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_" + IOCTokenArmor.tCqCreate],
            xmlEntitlements: forgedTeamEntXML,
            textInstructions: [Self.retWord]
        ))
        let corpPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.corp.locked.trojan",
            "CFBundleDisplayName": "CorpLocked",
            "CFBundleExecutable": "CorpLocked"
        ], format: .xml, options: 0)

        // 1. Standalone unsigned Mach-O, unsigned .app, and unsigned .ipa (no embedded.mobileprovision) forging CORP112233 in Slot 5
        let binURL = makeTempURL("forged_team_bin")
        try unsignedTrojanBin.write(to: binURL)
        let standaloneF = try pipeline.scanBinary(at: binURL)
        XCTAssertEqual(standaloneF.riskTier, .highRisk)
        XCTAssertFalse(standaloneF.isWhitelisted)
        XCTAssertEqual(standaloneF.teamId, "CORP112233")
        XCTAssertFalse(standaloneF.evidence.isTeamIdWhitelistVerified)

        let unsignedAppDir = makeTempURL("UnsignedForgedTeam.app")
        try FileManager.default.createDirectory(at: unsignedAppDir, withIntermediateDirectories: true)
        try corpPlist.write(to: unsignedAppDir.appendingPathComponent("Info.plist"))
        try unsignedTrojanBin.write(to: unsignedAppDir.appendingPathComponent("CorpLocked"))
        let unsignedBundleF = try pipeline.scanBundle(at: unsignedAppDir)
        XCTAssertEqual(unsignedBundleF.riskTier, .highRisk)
        XCTAssertFalse(unsignedBundleF.isWhitelisted)
        XCTAssertFalse(unsignedBundleF.evidence.isTeamIdWhitelistVerified)

        let unsignedIPAURL = makeTempURL("UnsignedForgedTeam.ipa")
        try buildZip([
            .init(path: "Payload/CorpLocked.app/Info.plist", payload: corpPlist),
            .init(path: "Payload/CorpLocked.app/CorpLocked", payload: unsignedTrojanBin, unixMode: 0o100755)
        ]).write(to: unsignedIPAURL)
        let unsignedIPAF = try IPAPackageScanner.shared.scan(ipaURL: unsignedIPAURL)
        XCTAssertEqual(unsignedIPAF.riskTier, .highRisk)
        XCTAssertFalse(unsignedIPAF.isWhitelisted)
        XCTAssertFalse(unsignedIPAF.evidence.isTeamIdWhitelistVerified)

        // 2. Stolen CORP112233 embedded.mobileprovision paired with (a) CS_ADHOC binary, and (b) EVIL999999 entitlement conflict
        let stolenProvisionPlist = try PropertyListSerialization.data(fromPropertyList: [
            "TeamIdentifier": ["CORP112233"],
            "ProvisionedDevices": ["UDID-1"]
        ], format: .xml, options: 0)

        var adHocCDPayload = Data()
        adHocCDPayload.r11be32(0x0002_0400)
        adHocCDPayload.r11be32(CSBlobConstants.csAdhocFlag)
        while adHocCDPayload.count < 36 { adHocCDPayload.append(0) }
        let adHocTrojanBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_" + IOCTokenArmor.tCqCreate],
            xmlEntitlements: forgedTeamEntXML,
            rawCodeSignatureSlot: (slot: CSBlobConstants.slotCodeDirectory, magic: CSBlobConstants.codeDirectoryMagic, data: adHocCDPayload),
            textInstructions: [Self.retWord]
        ))
        let adHocStolenProvIPA = makeTempURL("AdHocStolenProv.ipa")
        try buildZip([
            .init(path: "Payload/CorpLocked.app/Info.plist", payload: corpPlist),
            .init(path: "Payload/CorpLocked.app/embedded.mobileprovision", payload: stolenProvisionPlist),
            .init(path: "Payload/CorpLocked.app/CorpLocked", payload: adHocTrojanBin, unixMode: 0o100755)
        ]).write(to: adHocStolenProvIPA)
        let adHocStolenF = try IPAPackageScanner.shared.scan(ipaURL: adHocStolenProvIPA)
        XCTAssertEqual(adHocStolenF.riskTier, .highRisk, "CS_ADHOC binary with stolen mobileprovision must NOT pass allowedTeamIds")
        XCTAssertFalse(adHocStolenF.isWhitelisted)
        XCTAssertFalse(adHocStolenF.evidence.isTeamIdWhitelistVerified)

        let mismatchedTeamXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
            <key>application-identifier</key><string>EVIL999999.com.corp.locked.trojan</string>
            <key>com.apple.developer.team-identifier</key><string>EVIL999999</string>
            <key>com.apple.security.application-groups</key><array><string>group.corp.locked</string></array>
        </dict></plist>
        """
        let mismatchedTeamBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_" + IOCTokenArmor.tCqCreate],
            xmlEntitlements: mismatchedTeamXML,
            textInstructions: [Self.retWord]
        ))
        let mismatchedProvIPA = makeTempURL("MismatchedProvTeam.ipa")
        try buildZip([
            .init(path: "Payload/CorpLocked.app/Info.plist", payload: corpPlist),
            .init(path: "Payload/CorpLocked.app/embedded.mobileprovision", payload: stolenProvisionPlist),
            .init(path: "Payload/CorpLocked.app/CorpLocked", payload: mismatchedTeamBin, unixMode: 0o100755)
        ]).write(to: mismatchedProvIPA)
        let mismatchedProvF = try IPAPackageScanner.shared.scan(ipaURL: mismatchedProvIPA)
        XCTAssertEqual(mismatchedProvF.riskTier, .highRisk)
        XCTAssertFalse(mismatchedProvF.isWhitelisted)
        XCTAssertFalse(mismatchedProvF.evidence.isWhitelistEligible)
        XCTAssertFalse(mismatchedProvF.evidence.isTeamIdWhitelistVerified)

        // 3. Correlating `unsignedIPAF` (forged teamId == CORP112233, isTeamIdWhitelistVerified == false) with validated registry record
        let legitReg = InstalledAppRegistryRecord(
            bundleId: "com.corp.locked.trojan",
            displayName: "CorpLocked",
            version: "1.0",
            applicationType: "User",
            signerIdentity: "Apple Development: Corp",
            profileValidated: true,
            teamId: "CORP112233",
            appGroups: ["group.corp.locked"],
            bundlePath: "/var/containers/Bundle/Application/UUID/CorpLocked.app"
        )
        let merged = pipeline.correlateAndMergeFindings(registryRecords: [legitReg], packageFindings: [unsignedIPAF])
        let mergedF = try XCTUnwrap(merged.findings.first)
        XCTAssertEqual(mergedF.riskTier, .highRisk, "Unverified self-asserted package TeamID must NEVER match validated registry TeamID during merge")
        XCTAssertFalse(mergedF.isWhitelisted)
        XCTAssertFalse(mergedF.evidence.isTeamIdWhitelistVerified)
        XCTAssertFalse(wlEngine.evaluateFindingWhitelist(mergedF).isWhitelisted)

        // 4. Unvalidated Ad-Hoc registry record (`profileValidated == false`, `signerIdentity == "Ad Hoc"`) forging CORP112233
        let adHocReg = InstalledAppRegistryRecord(
            bundleId: "com.corp.locked.trojan",
            displayName: "CorpLocked",
            version: "1.0",
            applicationType: "User",
            signerIdentity: "Ad Hoc",
            profileValidated: false,
            teamId: "CORP112233",
            appGroups: ["group.corp.locked"],
            bundlePath: "/var/containers/Bundle/Application/UUID/CorpLocked.app"
        )
        let regScanner = InstalledAppRegistryScanner(whitelistEngine: wlEngine)
        let adHocRegF = regScanner.evaluateRecord(adHocReg)
        XCTAssertEqual(adHocRegF.riskTier, .caution)
        XCTAssertFalse(adHocRegF.isWhitelisted)
        XCTAssertFalse(adHocRegF.evidence.isTeamIdWhitelistVerified)
    }

    // MARK: - 18. CodeResources Special Slot -3 Seal, JSBundle Tamper, Unsealed Script & Verified Unencrypted Framework Exemption

    func test_r11_18_codeResourcesSlot3Seal_jsbundleTamper_unsealedScript_andVerifiedUnencryptedFrameworkExemption() throws {
        // 1. Empirical check on macOS `/Applications/Safari.app` (real Apple Contents/_CodeSignature/CodeResources bundle)
        let safariAppURL = URL(fileURLWithPath: "/Applications/Safari.app")
        let safariExecURL = safariAppURL.appendingPathComponent("Contents/MacOS/Safari")
        if FileManager.default.fileExists(atPath: safariExecURL.path),
           let safariData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: safariExecURL),
           let safariSlices = try? MachOParser.parseAllSlices(data: safariData) {
            XCTAssertNil(
                CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: safariSlices, bundleURL: safariAppURL),
                "Authentic Apple-signed /Applications/Safari.app must pass Special Slot -3 CodeResources seal"
            )
        }

        // 2. Deterministic Special Slot -3 (`_CodeSignature/CodeResources`) verification on a React Native wallet bundle (`main.jsbundle`)
        let walletPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "io.metamask.MetaMask",
            "CFBundleDisplayName": "MetaMask",
            "CFBundleExecutable": "MetaMask"
        ], format: .xml, options: 0)
        let cleanJSBundle = Data("console.log('official metamask bundle');".utf8)
        let cleanJSBundleSHA256 = Data(SHA256.hash(data: cleanJSBundle))
        let codeResourcesData = try PropertyListSerialization.data(fromPropertyList: [
            "files2": [
                "main.jsbundle": ["hash2": cleanJSBundleSHA256]
            ]
        ], format: .xml, options: 0)
        let emptyEntXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict/></plist>"
        var slot5Blob = Data()
        slot5Blob.r11be32(CSBlobConstants.entitlementXmlMagic)
        slot5Blob.r11be32(UInt32(8 + emptyEntXML.utf8.count))
        slot5Blob.append(Data(emptyEntXML.utf8))

        let templateBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 4096,
            symbols: ["_main"],
            xmlEntitlements: emptyEntXML,
            textInstructions: [Self.retWord]
        ))
        let preSized = try XCTUnwrap(preparePreSizedMachOSliceForSigning(templateBin, reservedSigBytes: 8192))
        let cdWithSlot3 = buildSignedStyleCodeDirectory(
            identifier: "io.metamask.MetaMask",
            slicePrefixBytes: preSized.slice.subdata(in: 0..<preSized.csOffset),
            infoPlistData: walletPlistData,
            slot5FullBlob: slot5Blob,
            codeResourcesData: codeResourcesData
        )
        let sbWithSlot3 = buildSuperBlob(slots: [
            (CSBlobConstants.slotCodeDirectory, cdWithSlot3),
            (CSBlobConstants.slotEntitlements, slot5Blob)
        ])
        let sealedBin = writeSuperBlobIntoPreSizedSlice(preSized.slice, csOffset: preSized.csOffset, superBlob: sbWithSlot3)
        let sealedSlices = try MachOParser.parseAllSlices(data: sealedBin)

        let sealedAppDir = makeTempURL("SealedWallet.app")
        try FileManager.default.createDirectory(at: sealedAppDir.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try walletPlistData.write(to: sealedAppDir.appendingPathComponent("Info.plist"))
        try sealedBin.write(to: sealedAppDir.appendingPathComponent("MetaMask"))
        try cleanJSBundle.write(to: sealedAppDir.appendingPathComponent("main.jsbundle"))
        try codeResourcesData.write(to: sealedAppDir.appendingPathComponent("_CodeSignature/CodeResources"))

        // (a) Intact CodeResources + intact main.jsbundle + FairPlay SC_Info file -> passes seal
        try FileManager.default.createDirectory(at: sealedAppDir.appendingPathComponent("SC_Info"), withIntermediateDirectories: true)
        try Data("fairplay-sinf".utf8).write(to: sealedAppDir.appendingPathComponent("SC_Info/MetaMask.sinf"))
        XCTAssertNil(CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: sealedSlices, bundleURL: sealedAppDir))

        // (b) 1-byte modification in `main.jsbundle` -> MUST fail CodeResources seal
        try Data("console.log('drainer! metamask bundle');".utf8).write(to: sealedAppDir.appendingPathComponent("main.jsbundle"))
        XCTAssertEqual(
            CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: sealedSlices, bundleURL: sealedAppDir)?.isDisqualifiedFromAppStore,
            true,
            "1-byte mutation in sealed main.jsbundle must invalidate CodeResources seal"
        )

        // Restore main.jsbundle, then (c) inject unsealed `drainer.js` -> MUST fail CodeResources seal
        try cleanJSBundle.write(to: sealedAppDir.appendingPathComponent("main.jsbundle"))
        let injectedScriptURL = sealedAppDir.appendingPathComponent("drainer.js")
        try Data("fetch('https://evil.invalid')".utf8).write(to: injectedScriptURL)
        XCTAssertEqual(
            CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: sealedSlices, bundleURL: sealedAppDir)?.isDisqualifiedFromAppStore,
            true,
            "Unsealed injected .js script in flat iOS bundle must invalidate CodeResources seal"
        )

        // Remove drainer.js, then (d) delete `_CodeSignature/CodeResources` -> MUST fail CodeResources seal
        try FileManager.default.removeItem(at: injectedScriptURL)
        try FileManager.default.removeItem(at: sealedAppDir.appendingPathComponent("_CodeSignature/CodeResources"))
        XCTAssertEqual(
            CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: sealedSlices, bundleURL: sealedAppDir)?.isDisqualifiedFromAppStore,
            true,
            "Deleting _CodeSignature/CodeResources must invalidate Special Slot -3 seal"
        )

        // 3. Positive control for App Store IPAs with Apple-signed `cryptid == 0` embedded dynamic frameworks (`hasUnencryptedBinary == true`):
        //    When main binary is FairPlay-encrypted (`mainIsFairPlayEncrypted && !mainHasUnencryptedSegments`) and aggregate
        //    `codeSignatureTrust == .appleAppStoreVerified` (`!hasMissingCodeSignature`), `IMPERSONATION:MetaMask` must NOT false-positive.
        var verifiedInds: [ThreatIndicator] = []
        var verifiedSyms: Set<String> = []
        IPAPackageScanner.appendExpandedThreatIndicators(
            bundleId: "io.metamask.MetaMask",
            displayName: "MetaMask",
            installChannel: .appStore,
            mainCryptid: 1,
            mainIsFairPlayEncrypted: true,
            mainHasUnencryptedSegments: false,
            mainBackgroundModes: [],
            infoDict: ["CFBundleIdentifier": "io.metamask.MetaMask", "CFBundleDisplayName": "MetaMask"],
            entitlementsDict: [:],
            allLinkedDylibs: ["@rpath/hermes.framework/hermes"],
            appLinkedDylibs: ["@rpath/hermes.framework/hermes"],
            unencryptedSymbols: ["_hermes_vm_init"],
            appUnencryptedSymbols: ["_hermes_vm_init"],
            unencryptedTextStrings: [],
            hasUnencryptedBinary: true,
            appHasUnencryptedBinary: true,
            codeSignatureTrust: .appleAppStoreVerified,
            hasMissingCodeSignature: false,
            appHasMissingCodeSignature: false,
            allIndicators: &verifiedInds,
            allMatchedSymbols: &verifiedSyms
        )
        XCTAssertTrue(verifiedInds.isEmpty, "Authentic Apple-signed App Store MetaMask with Apple-signed cryptid=0 framework must not false-positive: \(verifiedInds)")
    }

    // MARK: - 19. Nested AppClips/*.app, Extension Brand Impersonation & Sibling Clipboard Snooping, cryptid=1 Behavioral Tuple & Registry Conflict

    func test_r11_19_nestedAppClips_appexImpersonationAndSiblingClipboard_cryptid1BehavioralTuple_andRegistryConflict() throws {
        // 1. Benign outer Host.app (with valid BT keys) embedding `AppClips/PhishClip.app`:
        //    - PhishClip.app Info.plist impersonates MetaMask (`io.metamask.MetaMask.Clip` / `MetaMask`),
        //    - declares `UIBackgroundModes = ["audio"]` while sibling `AppClips/PhishClip.app/Frameworks/Snoop.dylib` imports `UIPasteboard`,
        //    - links `AccessorySetupKit.framework` while omitting Bluetooth Info.plist keys (`CVE-2026-84493`).
        let hostPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.benign.utilityhost",
            "CFBundleDisplayName": "UtilityHost",
            "CFBundleExecutable": "UtilityHost",
            "NSBluetoothAlwaysUsageDescription": "Host BT allowed",
            "NSAccessorySetupKitSupports": ["Bluetooth"]
        ], format: .xml, options: 0)
        let hostBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [Self.retWord]
        ))
        let clipPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "io.metamask.MetaMask.Clip",
            "CFBundleDisplayName": "MetaMask",
            "CFBundleExecutable": "PhishClip",
            "UIBackgroundModes": ["audio"]
        ], format: .xml, options: 0)
        let clipBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"],
            symbols: ["_main"],
            textInstructions: [Self.retWord]
        ))
        let clipSiblingSnooper = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_OBJC_CLASS_$_" + IOCTokenArmor.tUIPasteboard],
            textInstructions: [Self.retWord]
        ))

        let nestedClipIPA = makeTempURL("NestedAppClipTripleBypass.ipa")
        try buildZip([
            .init(path: "Payload/UtilityHost.app/Info.plist", payload: hostPlist),
            .init(path: "Payload/UtilityHost.app/UtilityHost", payload: hostBin, unixMode: 0o100755),
            .init(path: "Payload/UtilityHost.app/AppClips/PhishClip.app/Info.plist", payload: clipPlist),
            .init(path: "Payload/UtilityHost.app/AppClips/PhishClip.app/PhishClip", payload: clipBin, unixMode: 0o100755),
            .init(path: "Payload/UtilityHost.app/AppClips/PhishClip.app/Frameworks/Snoop.dylib", payload: clipSiblingSnooper, unixMode: 0o100755)
        ]).write(to: nestedClipIPA)

        let nestedClipAppDir = makeTempURL("UtilityHost.app")
        try FileManager.default.createDirectory(at: nestedClipAppDir.appendingPathComponent("AppClips/PhishClip.app/Frameworks"), withIntermediateDirectories: true)
        try hostPlist.write(to: nestedClipAppDir.appendingPathComponent("Info.plist"))
        try hostBin.write(to: nestedClipAppDir.appendingPathComponent("UtilityHost"))
        try clipPlist.write(to: nestedClipAppDir.appendingPathComponent("AppClips/PhishClip.app/Info.plist"))
        try clipBin.write(to: nestedClipAppDir.appendingPathComponent("AppClips/PhishClip.app/PhishClip"))
        try clipSiblingSnooper.write(to: nestedClipAppDir.appendingPathComponent("AppClips/PhishClip.app/Frameworks/Snoop.dylib"))

        for (lbl, f) in [("IPA", try IPAPackageScanner.shared.scan(ipaURL: nestedClipIPA)),
                         ("Bundle", try SecurityPipeline.shared.scanBundle(at: nestedClipAppDir))] {
            XCTAssertEqual(f.riskTier, .highRisk, "\(lbl) must catch threats inside nested AppClips/*.app")
            let sigs = Set(f.indicators.map(\.signature))
            XCTAssertTrue(sigs.contains("IMPERSONATION:MetaMask"), "\(lbl) missing IMPERSONATION:MetaMask: \(sigs)")
            XCTAssertTrue(sigs.contains("CVE-2026-84493:AccessorySetupKitBypass"), "\(lbl) missing AccessorySetupKitBypass: \(sigs)")
            XCTAssertTrue(sigs.contains("UIBackgroundModes(audio)+UIPasteboard"), "\(lbl) missing sibling-dylib clipboard snooping: \(sigs)")
        }

        // 2. Unverified cryptid=1 binary carrying AppGroups + dlopen + dlsym + symlink MUST trigger Behavioral Tuple (.highRisk)
        let tupleBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 4096,
            symbols: ["_dlopen", "_dlsym", "_symlink"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.victim.tuple"]),
            textInstructions: [Self.retWord]
        ))
        let tuplePlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.evil.crypt1tuple",
            "CFBundleExecutable": "TupleApp"
        ], format: .xml, options: 0)
        let tupleIPA = makeTempURL("Crypt1BehavioralTuple.ipa")
        try buildZip([
            .init(path: "Payload/TupleApp.app/Info.plist", payload: tuplePlist),
            .init(path: "Payload/TupleApp.app/TupleApp", payload: tupleBin, unixMode: 0o100755)
        ]).write(to: tupleIPA)
        let tupleFinding = try IPAPackageScanner.shared.scan(ipaURL: tupleIPA)
        XCTAssertEqual(tupleFinding.riskTier, .highRisk)
        XCTAssertTrue(tupleFinding.indicators.contains { $0.signature == SignatureCatalog.behavioralTupleRule.pattern })

        // 3. InstalledAppRegistryScanner conflicting Entitlements["application-identifier"] impersonating MetaMask
        let conflictReg = InstalledAppRegistryRecord(
            bundleId: "com.benign.shell",
            displayName: "HelperShell",
            version: "1.0",
            applicationType: "User",
            signerIdentity: "Apple Development: Attacker",
            profileValidated: true,
            teamId: "EVIL123456",
            stringEntitlements: ["application-identifier": "EVIL123456.io.metamask.MetaMask"],
            bundlePath: "/var/containers/Bundle/Application/UUID/HelperShell.app"
        )
        let conflictRegF = InstalledAppRegistryScanner.shared.evaluateRecord(conflictReg)
        XCTAssertEqual(conflictRegF.riskTier, .highRisk)
        XCTAssertTrue(conflictRegF.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })
        XCTAssertFalse(conflictRegF.evidence.isWhitelistEligible)
    }
}
