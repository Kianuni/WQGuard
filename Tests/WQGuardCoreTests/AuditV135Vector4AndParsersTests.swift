//
//  AuditV135Vector4AndParsersTests.swift
//  WQGuardCoreTests
//
//  Milestone M1 Option A Comprehensive Regression Suite:
//  - R1.4 / R2 / R4 Cryptographic Provenance (CMS CodeSignature, Provisioning Profile, App Receipt)
//  - SubjectKeyIdentifier SID binding, BER 0x24 nested indefinite encapContent, alternating DER dict
//  - ChannelClassifier Option A enforcement (.absentOrSynthetic / missing CS rejection, TestFlight stripped provision)
//  - IPAPackageScanner / NativeZIPArchiveReader (/private lexical path, archive CodeResources, S_IFDIR, bit-6, local/CD mismatch, Team ID shadowing)
//  - MachOParser DoS/bypass hardening (parseAllSlices, LC_DYLD_CHAINED_FIXUPS, LC_SYMTAB, lazy_bind O(N), FairPlay __info_plist, objcMethodNames, scanDirectSyscalls)
//

import XCTest
import Foundation
import Security
import CryptoKit
import MachO
import zlib
@testable import WQGuardCore

// MARK: - Shared Real ECDSA CMS & Signed Mach-O Fixture Generator (Option A)

internal enum M1TestCMSFixtures {
    struct CertPair {
        let certDER: Data
        let keyPath: String
        let ski: Data
        let summary: String
    }

    struct BundleState {
        let tempDir: URL
        let rootCertDER: Data
        let rootCert: SecCertificate
        let appStoreLeaf: CertPair
        let testFlightLeaf: CertPair
        let macSoftwareLeaf: CertPair
        let provisioningLeaf: CertPair
        let receiptLeaf: CertPair
        let rogueLeaf: CertPair
    }

    private static let lock = NSLock()
    private static var cachedState: BundleState?

    static func sharedState() throws -> BundleState {
        lock.lock()
        defer { lock.unlock() }
        if let existing = cachedState {
            return existing
        }

        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wq_m1_cms_fixtures_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let extFile = dir.appendingPathComponent("ext.cnf")
        try """
        [req]
        distinguished_name = dn
        prompt = no
        x509_extensions = ca_ext
        [dn]
        C = US
        O = Apple Inc.
        CN = Apple Root CA - M1Test
        [ca_ext]
        basicConstraints = critical,CA:true
        keyUsage = critical,keyCertSign,cRLSign
        subjectKeyIdentifier = hash
        [leaf_ext]
        basicConstraints = critical,CA:false
        keyUsage = critical,digitalSignature
        subjectKeyIdentifier = hash
        """.write(to: extFile, atomically: true, encoding: .utf8)

        let rKey = dir.appendingPathComponent("root.key")
        let rPem = dir.appendingPathComponent("root.pem")
        let rDer = dir.appendingPathComponent("root.der")
        try runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", rKey.path])
        try runOpenSSL(["req", "-new", "-x509", "-key", rKey.path, "-days", "30", "-out", rPem.path, "-extensions", "ca_ext", "-config", extFile.path])
        try runOpenSSL(["x509", "-in", rPem.path, "-outform", "DER", "-out", rDer.path])

        let rootDER = try Data(contentsOf: rDer)
        guard let rootCert = SecCertificateCreateWithData(nil, rootDER as CFData) else {
            throw NSError(domain: "M1TestCMSFixtures", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to create root SecCertificate"])
        }

        func issueLeaf(tag: String, commonName: String) throws -> CertPair {
            let lKey = dir.appendingPathComponent("\(tag).key")
            let lCsr = dir.appendingPathComponent("\(tag).csr")
            let lPem = dir.appendingPathComponent("\(tag).pem")
            let lDer = dir.appendingPathComponent("\(tag).der")
            try runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", lKey.path])
            try runOpenSSL(["req", "-new", "-key", lKey.path, "-out", lCsr.path, "-subj", "/C=US/O=Apple Inc./CN=\(commonName)"])
            try runOpenSSL(["x509", "-req", "-in", lCsr.path, "-CA", rPem.path, "-CAkey", rKey.path, "-CAcreateserial", "-days", "30", "-out", lPem.path, "-extfile", extFile.path, "-extensions", "leaf_ext"])
            try runOpenSSL(["x509", "-in", lPem.path, "-outform", "DER", "-out", lDer.path])
            let certDER = try Data(contentsOf: lDer)
            guard let secCert = SecCertificateCreateWithData(nil, certDER as CFData),
                  let pubKey = SecCertificateCopyKey(secCert),
                  let pubRaw = SecKeyCopyExternalRepresentation(pubKey, nil) as Data? else {
                throw NSError(domain: "M1TestCMSFixtures", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to extract leaf key/SKI for \(tag)"])
            }
            let ski = Data(Insecure.SHA1.hash(data: pubRaw))
            let summary = (SecCertificateCopySubjectSummary(secCert) as String?) ?? commonName
            return CertPair(certDER: certDER, keyPath: lKey.path, ski: ski, summary: summary)
        }

        let state = BundleState(
            tempDir: dir,
            rootCertDER: rootDER,
            rootCert: rootCert,
            appStoreLeaf: try issueLeaf(tag: "appstore", commonName: "Apple iPhone OS Application Signing"),
            testFlightLeaf: try issueLeaf(tag: "testflight", commonName: "TestFlight Beta Distribution"),
            macSoftwareLeaf: try issueLeaf(tag: "macsoftware", commonName: "Apple Mac OS Application Signing"),
            provisioningLeaf: try issueLeaf(tag: "provision", commonName: "Apple iPhone OS Provisioning Profile Signing"),
            receiptLeaf: try issueLeaf(tag: "receipt", commonName: "Apple Inc. Receipt Signing"),
            rogueLeaf: try issueLeaf(tag: "rogue", commonName: "Untrusted Custom Leaf")
        )
        cachedState = state
        return state
    }

    @discardableResult
    static func runOpenSSL(_ args: [String]) throws -> Data {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        proc.arguments = args
        let stdout = Pipe()
        let stderr = Pipe()
        proc.standardOutput = stdout
        proc.standardError = stderr
        try proc.run()
        let outData = stdout.fileHandleForReading.readDataToEndOfFile()
        let errData = stderr.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        if proc.terminationStatus != 0 {
            let errText = String(decoding: errData, as: UTF8.self)
            throw NSError(domain: "M1TestCMSFixtures.OpenSSL", code: Int(proc.terminationStatus), userInfo: [NSLocalizedDescriptionKey: errText])
        }
        return outData
    }

    // MARK: DER / BER Helpers

    static func derLength(_ count: Int) -> Data {
        if count < 0x80 {
            return Data([UInt8(count)])
        }
        var lenBytes: [UInt8] = []
        var rem = count
        while rem > 0 {
            lenBytes.insert(UInt8(rem & 0xFF), at: 0)
            rem >>= 8
        }
        return Data([UInt8(0x80 | lenBytes.count)] + lenBytes)
    }

    static func derTLV(_ tag: UInt8, _ value: Data) -> Data {
        var out = Data([tag])
        out.append(derLength(value.count))
        out.append(value)
        return out
    }

    static func berIndef(_ tag: UInt8, _ value: Data) -> Data {
        var out = Data([tag, 0x80])
        out.append(value)
        out.append(contentsOf: [0x00, 0x00])
        return out
    }

    static func derUTF8String(_ str: String) -> Data {
        derTLV(0x0C, Data(str.utf8))
    }

    static func derInteger(_ value: Int) -> Data {
        var v = value
        if v == 0 {
            return derTLV(0x02, Data([0x00]))
        }
        var bytes: [UInt8] = []
        while v > 0 {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        }
        if let first = bytes.first, (first & 0x80) != 0 {
            bytes.insert(0x00, at: 0)
        }
        return derTLV(0x02, Data(bytes))
    }

    static func appendBE32(_ out: inout Data, _ v: UInt32) {
        var be = v.bigEndian
        withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
    }

    static func signECDSASHA256(payload: Data, keyPath: String, tempDir: URL) throws -> Data {
        let inURL = tempDir.appendingPathComponent("in_\(UUID().uuidString).der")
        let sigURL = tempDir.appendingPathComponent("sig_\(UUID().uuidString).der")
        defer {
            try? FileManager.default.removeItem(at: inURL)
            try? FileManager.default.removeItem(at: sigURL)
        }
        try payload.write(to: inURL)
        try runOpenSSL(["dgst", "-sha256", "-sign", keyPath, "-out", sigURL.path, inURL.path])
        return try Data(contentsOf: sigURL)
    }

    // Standard OIDs (DER value bytes, without 0x06 tag/len)
    static let oidSignedData = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]))
    static let oidData = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]))
    static let oidSHA256 = derTLV(0x06, Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]))
    static let oidSHA1 = derTLV(0x06, Data([0x2B, 0x0E, 0x03, 0x02, 0x1A]))
    static let oidECDSASHA256 = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]))
    static let oidContentType = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03]))
    static let oidMsgDigest = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04]))
    static let oidCDHashesPlist = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x09, 0x01]))
    static let oidCDHashesDER = derTLV(0x06, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x09, 0x02]))

    static func buildSignedCMS(
        encapContentBytes: Data,
        leaf: CertPair,
        rootCertDER: Data,
        tempDir: URL,
        useBER0x24Depth: Int = 0,
        useIndefiniteOuter: Bool = false,
        overrideSKI: Data? = nil,
        extraSignedAttrs: Data = Data()
    ) throws -> Data {
        let digest = Data(SHA256.hash(data: encapContentBytes))
        let attr1 = derTLV(0x30, oidContentType + derTLV(0x31, oidData))
        let attr2 = derTLV(0x30, oidMsgDigest + derTLV(0x31, derTLV(0x04, digest)))
        let attrsInner = attr1 + attr2 + extraSignedAttrs
        let sigPayload = derTLV(0x31, attrsInner)
        let sigBytes = try signECDSASHA256(payload: sigPayload, keyPath: leaf.keyPath, tempDir: tempDir)

        var encapContentNode: Data
        if useBER0x24Depth > 0 {
            let half = max(1, encapContentBytes.count / 2)
            let p1 = derTLV(0x04, Data(encapContentBytes.prefix(half)))
            let p2 = derTLV(0x04, Data(encapContentBytes.dropFirst(half)))
            var inner = p1 + p2
            for _ in 0..<useBER0x24Depth {
                inner = berIndef(0x24, inner)
            }
            encapContentNode = berIndef(0xA0, inner)
        } else {
            encapContentNode = derTLV(0xA0, derTLV(0x04, encapContentBytes))
        }

        let encapContentInfo = useIndefiniteOuter
            ? berIndef(0x30, oidData + encapContentNode)
            : derTLV(0x30, oidData + encapContentNode)

        let ski = overrideSKI ?? leaf.ski
        let signerInfo = derTLV(0x30,
            derTLV(0x02, Data([0x03])) +
            derTLV(0x80, ski) +
            derTLV(0x30, oidSHA256) +
            (useIndefiniteOuter ? berIndef(0xA0, attrsInner) : derTLV(0xA0, attrsInner)) +
            derTLV(0x30, oidECDSASHA256) +
            derTLV(0x04, sigBytes)
        )

        let certsTLV = useIndefiniteOuter
            ? berIndef(0xA0, leaf.certDER + rootCertDER)
            : derTLV(0xA0, leaf.certDER + rootCertDER)

        let signedDataInner =
            derTLV(0x02, Data([0x03])) +
            derTLV(0x31, derTLV(0x30, oidSHA256)) +
            encapContentInfo +
            certsTLV +
            derTLV(0x31, signerInfo)

        if useIndefiniteOuter {
            let signedData = berIndef(0x30, signedDataInner)
            return berIndef(0x30, oidSignedData + berIndef(0xA0, signedData))
        } else {
            let signedData = derTLV(0x30, signedDataInner)
            return derTLV(0x30, oidSignedData + derTLV(0xA0, signedData))
        }
    }

    static func buildCMSProvisioningProfile(
        plistDict: [String: Any],
        leaf: CertPair? = nil,
        useBER0x24Depth: Int = 0,
        useIndefiniteOuter: Bool = false
    ) throws -> (cmsData: Data, rootCert: SecCertificate) {
        let state = try sharedState()
        let plistBytes = try PropertyListSerialization.data(fromPropertyList: plistDict, format: .xml, options: 0)
        let cms = try buildSignedCMS(
            encapContentBytes: plistBytes,
            leaf: leaf ?? state.provisioningLeaf,
            rootCertDER: state.rootCertDER,
            tempDir: state.tempDir,
            useBER0x24Depth: useBER0x24Depth,
            useIndefiniteOuter: useIndefiniteOuter
        )
        return (cms, state.rootCert)
    }

    static func buildCMSSandboxReceipt(
        environment: String = "ProductionSandbox",
        leaf: CertPair? = nil,
        useBER0x24Depth: Int = 0,
        useIndefiniteOuter: Bool = false
    ) throws -> (cmsData: Data, rootCert: SecCertificate) {
        let state = try sharedState()
        // Receipt ASN.1 SET of Attribute SEQUENCE { type(0=env), version(1), OCTET STRING(UTF8String(env)) }
        let envAttr = derTLV(0x30, derInteger(0) + derInteger(1) + derTLV(0x04, derUTF8String(environment)))
        let bidAttr = derTLV(0x30, derInteger(2) + derInteger(1) + derTLV(0x04, derUTF8String("com.example.testapp")))
        let receiptSet = derTLV(0x31, envAttr + bidAttr)
        let cms = try buildSignedCMS(
            encapContentBytes: receiptSet,
            leaf: leaf ?? state.receiptLeaf,
            rootCertDER: state.rootCertDER,
            tempDir: state.tempDir,
            useBER0x24Depth: useBER0x24Depth,
            useIndefiniteOuter: useIndefiniteOuter
        )
        return (cms, state.rootCert)
    }

    static func csprngBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }

    struct SplitMix64 {
        private var state: UInt64

        init(seed: UInt64) {
            self.state = seed
        }

        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }

        mutating func bytes(count: Int) -> Data {
            guard count > 0 else { return Data() }
            var out = Data()
            out.reserveCapacity(count)
            while out.count < count {
                var w = next().littleEndian
                let remaining = count - out.count
                withUnsafeBytes(of: &w) { raw in
                    out.append(contentsOf: raw.prefix(min(8, remaining)))
                }
            }
            return out
        }
    }

    static func buildCodeDirectory(
        identifier: String,
        codeLimit: Int,
        slicePrefixBytes: Data,
        infoPlistData: Data?,
        codeResourcesData: Data?,
        slot5Blob: Data?,
        teamIdentifier: String? = nil
    ) -> Data {
        let pageSize = 4096
        let identBytes = Data((identifier + "\0").utf8)
        let teamBytes = teamIdentifier.map { Data(($0 + "\0").utf8) } ?? Data()
        let nSpecialSlots = 5
        let nCodeSlots = (codeLimit + pageSize - 1) / pageSize
        let headerSize = 88
        let identOffset = headerSize
        let teamOffset = teamBytes.isEmpty ? 0 : (identOffset + identBytes.count)
        let specialStart = identOffset + identBytes.count + teamBytes.count
        let hashOffset = specialStart + nSpecialSlots * 32
        let totalLen = hashOffset + nCodeSlots * 32

        var cd = Data()
        appendBE32(&cd, CSBlobConstants.codeDirectoryMagic)
        appendBE32(&cd, UInt32(totalLen))
        appendBE32(&cd, 0x0002_0400)
        appendBE32(&cd, 0)
        appendBE32(&cd, UInt32(hashOffset))
        appendBE32(&cd, UInt32(identOffset))
        appendBE32(&cd, UInt32(nSpecialSlots))
        appendBE32(&cd, UInt32(nCodeSlots))
        appendBE32(&cd, UInt32(codeLimit))
        cd.append(32) // hashSize
        cd.append(2)  // CS_HASHTYPE_SHA256
        cd.append(0)  // platform
        cd.append(12) // pageSize = 2^12 = 4096
        appendBE32(&cd, 0) // spare2
        appendBE32(&cd, 0) // scatterOffset
        appendBE32(&cd, UInt32(teamOffset))
        cd.append(Data(repeating: 0, count: 36)) // spare3 + codeLimit64 + execSeg*
        assert(cd.count == headerSize)
        cd.append(identBytes)
        cd.append(teamBytes)

        // Special slots in reverse order: 5, 4, 3, 2, 1
        let zero32 = Data(repeating: 0, count: 32)
        cd.append(slot5Blob.map { Data(SHA256.hash(data: $0)) } ?? zero32) // slot 5: entitlements
        cd.append(zero32) // slot 4: application
        cd.append(codeResourcesData.map { Data(SHA256.hash(data: $0)) } ?? zero32) // slot 3: CodeResources
        cd.append(zero32) // slot 2: requirements
        cd.append(infoPlistData.map { Data(SHA256.hash(data: $0)) } ?? zero32) // slot 1: Info.plist

        for s in 0..<nCodeSlots {
            let ps = s * pageSize
            let pe = min(ps + pageSize, min(codeLimit, slicePrefixBytes.count))
            if ps < pe {
                cd.append(Data(SHA256.hash(data: slicePrefixBytes[ps..<pe])))
            } else {
                cd.append(zero32)
            }
        }
        assert(cd.count == totalLen)
        return cd
    }

    static func zlibCompress(_ input: Data) throws -> Data {
        var strm = z_stream()
        guard deflateInit_(&strm, Z_DEFAULT_COMPRESSION, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw NSError(domain: "M1TestCMSFixtures.zlib", code: 1, userInfo: nil)
        }
        defer { deflateEnd(&strm) }
        var out = Data()
        let chunkCap = 16_384
        var chunk = [UInt8](repeating: 0, count: chunkCap)
        input.withUnsafeBytes { inPtr in
            strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
            strm.avail_in = uInt(input.count)
            repeat {
                let status: Int32 = chunk.withUnsafeMutableBufferPointer { buf in
                    strm.next_out = buf.baseAddress
                    strm.avail_out = uInt(chunkCap)
                    return deflate(&strm, Z_FINISH)
                }
                let produced = chunkCap - Int(strm.avail_out)
                if produced > 0 { out.append(contentsOf: chunk[0..<produced]) }
                if status == Z_STREAM_END { break }
            } while true
        }
        return out
    }

    static func buildSuperBlob(slots: [(UInt32, Data)]) -> Data {
        let headerAndIndex = 12 + slots.count * 8
        var sb = Data()
        appendBE32(&sb, CSBlobConstants.superBlobMagic)
        let total = headerAndIndex + slots.reduce(0) { $0 + $1.1.count }
        appendBE32(&sb, UInt32(total))
        appendBE32(&sb, UInt32(slots.count))
        var offset = UInt32(headerAndIndex)
        for (slotType, payload) in slots {
            appendBE32(&sb, slotType)
            appendBE32(&sb, offset)
            offset += UInt32(payload.count)
        }
        for (_, payload) in slots {
            sb.append(payload)
        }
        return sb
    }

    /// Generates an ARM64 Mach-O binary signed by an Apple-like test chain anchored at `rootCert`.
    /// When `cryptid != 0`, fills `[cryptoff, cryptoff+cryptsize)` with CSPRNG high-entropy bytes
    /// so `hasForgedPlaintextFairPlayRange` is false and the binary mirrors authentic encrypted App Store/TestFlight binaries.
    static func buildSignedMachO(
        identifier: String,
        cryptid: UInt32 = 1,
        xmlEntitlements: String? = nil,
        infoPlistData: Data? = nil,
        codeResourcesData: Data? = nil,
        teamIdentifier: String? = nil,
        signerLeaf: CertPair? = nil,
        symbols: [String] = ["_main"],
        linkedDylibs: [String] = ["/usr/lib/libSystem.B.dylib"],
        textInstructions: [UInt32] = [0xD65F_03C0],
        overrideSKI: Data? = nil,
        extraSegmentPayload: Data? = nil
    ) throws -> (machOData: Data, rootCert: SecCertificate) {
        let state = try sharedState()
        let leaf = signerLeaf ?? state.appStoreLeaf
        let entXML = xmlEntitlements ?? "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict/></plist>"

        // Build clean 2-segment (__TEXT + __LINKEDIT) ARM64 Mach-O so FairPlay covers 100% of [postHeaderStart, textEnd)
        // with 4096-byte CSPRNG high-entropy ciphertext and __LINKEDIT holds symtab + LC_CODE_SIGNATURE.
        func copyFixed16(_ str: String, into ptr: UnsafeMutableRawBufferPointer) {
            ptr.initializeMemory(as: UInt8.self, repeating: 0)
            for (i, b) in str.utf8.prefix(16).enumerated() { ptr[i] = b }
        }
        func makeLoadDylib(_ path: String) -> Data {
            let strBytes = Array(path.utf8) + [0]
            let rawLen = MemoryLayout<dylib_command>.size + strBytes.count
            let cmdLen = (rawLen + 7) & ~7
            var cmd = dylib_command()
            cmd.cmd = UInt32(LC_LOAD_DYLIB)
            cmd.cmdsize = UInt32(cmdLen)
            cmd.dylib.name.offset = UInt32(MemoryLayout<dylib_command>.size)
            cmd.dylib.current_version = 0x0001_0000
            cmd.dylib.compatibility_version = 0x0001_0000
            var d = Data(bytes: &cmd, count: MemoryLayout<dylib_command>.size)
            d.append(contentsOf: strBytes)
            d.append(Data(repeating: 0, count: cmdLen - rawLen))
            return d
        }

        let textPayload: Data
        if cryptid != 0 {
            let targetCount = max(4096, textInstructions.count * 4)
            textPayload = extraSegmentPayload.flatMap { $0.count >= 4096 ? $0 : nil } ?? csprngBytes(count: targetCount)
        } else {
            var code = Data()
            for w in textInstructions {
                var le = w.littleEndian
                withUnsafeBytes(of: &le) { code.append(contentsOf: $0) }
            }
            if let extraSegmentPayload { code.append(extraSegmentPayload) }
            if code.isEmpty { code.append(Data(repeating: 0, count: 4)) }
            textPayload = code
        }

        var dylibCmdsData = Data()
        for p in linkedDylibs { dylibCmdsData.append(makeLoadDylib(p)) }

        let textSegCmdSize = MemoryLayout<segment_command_64>.size + MemoryLayout<section_64>.size
        let linkeditSegCmdSize = MemoryLayout<segment_command_64>.size
        let encCmdSize = MemoryLayout<encryption_info_command_64>.size
        let symtabCmdSize = MemoryLayout<symtab_command>.size
        let csCmdSize = MemoryLayout<linkedit_data_command>.size
        let ncmds = UInt32(5 + linkedDylibs.count)
        let sizeofcmds = UInt32(textSegCmdSize + linkeditSegCmdSize + encCmdSize + dylibCmdsData.count + symtabCmdSize + csCmdSize)
        let headerSize = MemoryLayout<mach_header_64>.size
        let textOffset = headerSize + Int(sizeofcmds)
        let textEnd = textOffset + textPayload.count
        let textSegVMSize = UInt64((textEnd + 0xFFF) & ~0xFFF)

        // Build symtab + strtab inside __LINKEDIT starting at textEnd
        var strtab = Data([0])
        var nlistData = Data()
        for sym in symbols {
            let off = UInt32(strtab.count)
            strtab.append(Data((sym + "\0").utf8))
            var nl = nlist_64()
            nl.n_un.n_strx = off
            nl.n_type = UInt8(N_EXT | N_SECT)
            nl.n_sect = 1
            nl.n_value = 0x1_0000_0000 + UInt64(textOffset)
            nlistData.append(Data(bytes: &nl, count: MemoryLayout<nlist_64>.size))
        }
        let symoff = UInt32(textEnd)
        let stroff = UInt32(textEnd + nlistData.count)
        let strsize = UInt32(strtab.count)
        var linkeditPrefix = Data()
        linkeditPrefix.append(nlistData)
        linkeditPrefix.append(strtab)
        while ((textEnd + linkeditPrefix.count) % 16) != 0 {
            linkeditPrefix.append(0)
        }
        let newCSDataOff = textEnd + linkeditPrefix.count
        let reservedCSSize = 16_384
        let finalFileSize = newCSDataOff + reservedCSSize
        let linkeditFileSize = UInt64(finalFileSize - textEnd)
        let linkeditVMSize = max(0x4000, (linkeditFileSize + 0xFFF) & ~0xFFF)

        var hdr = mach_header_64()
        hdr.magic = MH_MAGIC_64
        hdr.cputype = CPU_TYPE_ARM64
        hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        hdr.filetype = UInt32(MH_EXECUTE)
        hdr.ncmds = ncmds
        hdr.sizeofcmds = sizeofcmds
        hdr.flags = UInt32(MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE)

        var textSeg = segment_command_64()
        textSeg.cmd = UInt32(LC_SEGMENT_64)
        textSeg.cmdsize = UInt32(textSegCmdSize)
        withUnsafeMutableBytes(of: &textSeg.segname) { copyFixed16("__TEXT", into: $0) }
        textSeg.vmaddr = 0x1_0000_0000
        textSeg.vmsize = textSegVMSize
        textSeg.fileoff = 0
        textSeg.filesize = UInt64(textEnd)
        textSeg.maxprot = 7
        textSeg.initprot = 5
        textSeg.nsects = 1

        var textSect = section_64()
        withUnsafeMutableBytes(of: &textSect.sectname) { copyFixed16("__text", into: $0) }
        withUnsafeMutableBytes(of: &textSect.segname) { copyFixed16("__TEXT", into: $0) }
        textSect.addr = 0x1_0000_0000 + UInt64(textOffset)
        textSect.size = UInt64(textPayload.count)
        textSect.offset = UInt32(textOffset)
        textSect.align = 2
        textSect.flags = UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS)

        var linkeditSeg = segment_command_64()
        linkeditSeg.cmd = UInt32(LC_SEGMENT_64)
        linkeditSeg.cmdsize = UInt32(linkeditSegCmdSize)
        withUnsafeMutableBytes(of: &linkeditSeg.segname) { copyFixed16("__LINKEDIT", into: $0) }
        linkeditSeg.vmaddr = 0x1_0000_0000 + textSegVMSize
        linkeditSeg.vmsize = linkeditVMSize
        linkeditSeg.fileoff = UInt64(textEnd)
        linkeditSeg.filesize = linkeditFileSize
        linkeditSeg.maxprot = 1
        linkeditSeg.initprot = 1
        linkeditSeg.nsects = 0

        var encCmd = encryption_info_command_64()
        encCmd.cmd = UInt32(LC_ENCRYPTION_INFO_64)
        encCmd.cmdsize = UInt32(encCmdSize)
        encCmd.cryptoff = cryptid != 0 ? UInt32(textOffset) : 0
        encCmd.cryptsize = cryptid != 0 ? UInt32(textPayload.count) : 0
        encCmd.cryptid = cryptid

        var symCmd = symtab_command()
        symCmd.cmd = UInt32(LC_SYMTAB)
        symCmd.cmdsize = UInt32(symtabCmdSize)
        symCmd.symoff = symoff
        symCmd.nsyms = UInt32(symbols.count)
        symCmd.stroff = stroff
        symCmd.strsize = strsize

        var csCmd = linkedit_data_command()
        csCmd.cmd = UInt32(LC_CODE_SIGNATURE)
        csCmd.cmdsize = UInt32(csCmdSize)
        csCmd.dataoff = UInt32(newCSDataOff)
        csCmd.datasize = UInt32(reservedCSSize)

        var bin = Data()
        bin.append(Data(bytes: &hdr, count: headerSize))
        bin.append(Data(bytes: &textSeg, count: MemoryLayout<segment_command_64>.size))
        bin.append(Data(bytes: &textSect, count: MemoryLayout<section_64>.size))
        bin.append(Data(bytes: &linkeditSeg, count: linkeditSegCmdSize))
        bin.append(Data(bytes: &encCmd, count: encCmdSize))
        bin.append(dylibCmdsData)
        bin.append(Data(bytes: &symCmd, count: symtabCmdSize))
        bin.append(Data(bytes: &csCmd, count: csCmdSize))
        precondition(bin.count == textOffset)
        bin.append(textPayload)
        precondition(bin.count == textEnd)
        bin.append(linkeditPrefix)
        precondition(bin.count == newCSDataOff)
        bin.append(Data(repeating: 0, count: reservedCSSize))

        let codePrefix = bin.subdata(in: 0..<newCSDataOff)
        var slot5 = Data()
        appendBE32(&slot5, CSBlobConstants.entitlementXmlMagic)
        appendBE32(&slot5, UInt32(8 + entXML.utf8.count))
        slot5.append(Data(entXML.utf8))

        let cd = buildCodeDirectory(
            identifier: identifier,
            codeLimit: newCSDataOff,
            slicePrefixBytes: codePrefix,
            infoPlistData: infoPlistData,
            codeResourcesData: codeResourcesData,
            slot5Blob: slot5,
            teamIdentifier: teamIdentifier
        )

        let cdHash20 = Data(SHA256.hash(data: cd).prefix(20))
        let cdHash32 = Data(SHA256.hash(data: cd))
        let cdPlistBytes = try PropertyListSerialization.data(fromPropertyList: ["cdhashes": [cdHash20]], format: .xml, options: 0)
        let attr3 = derTLV(0x30, oidCDHashesPlist + derTLV(0x31, derTLV(0x0C, cdPlistBytes)))
        let derCDHashSeq = derTLV(0x30, oidSHA256 + derTLV(0x30, derTLV(0x04, cdHash20)))
        let attr4 = derTLV(0x30, oidCDHashesDER + derTLV(0x31, derCDHashSeq))

        let attr1 = derTLV(0x30, oidContentType + derTLV(0x31, oidData))
        let attr2 = derTLV(0x30, oidMsgDigest + derTLV(0x31, derTLV(0x04, cdHash32)))
        let attrsInner = attr1 + attr2 + attr3 + attr4
        let sigBytes = try signECDSASHA256(payload: derTLV(0x31, attrsInner), keyPath: leaf.keyPath, tempDir: state.tempDir)
        let ski = overrideSKI ?? leaf.ski
        let signerInfo = derTLV(0x30,
            derTLV(0x02, Data([0x03])) +
            derTLV(0x80, ski) +
            derTLV(0x30, oidSHA256) +
            derTLV(0xA0, attrsInner) +
            derTLV(0x30, oidECDSASHA256) +
            derTLV(0x04, sigBytes)
        )
        let signedData = derTLV(0x30,
            derTLV(0x02, Data([0x03])) +
            derTLV(0x31, derTLV(0x30, oidSHA256)) +
            derTLV(0x30, oidData) +
            derTLV(0xA0, leaf.certDER + state.rootCertDER) +
            derTLV(0x31, signerInfo)
        )
        let cmsDER = derTLV(0x30, oidSignedData + derTLV(0xA0, signedData))

        var wrapper = Data()
        appendBE32(&wrapper, CSBlobConstants.blobWrapperMagic)
        appendBE32(&wrapper, UInt32(8 + cmsDER.count))
        wrapper.append(cmsDER)

        let sb = buildSuperBlob(slots: [
            (CSBlobConstants.slotCodeDirectory, cd),
            (CSBlobConstants.slotEntitlements, slot5),
            (CSBlobConstants.slotCMSSignature, wrapper)
        ])
        precondition(sb.count <= reservedCSSize, "SuperBlob exceeded reserved space")
        bin.replaceSubrange(newCSDataOff..<(newCSDataOff + sb.count), with: sb)
        return (bin, state.rootCert)
    }

    /// Creates a signed `.app` bundle + `.ipa` archive with matching `Info.plist`, `_CodeSignature/CodeResources`,
    /// and optional signed `embedded.mobileprovision` or `StoreKit/sandboxReceipt`.
    static func buildSignedAppBundleAndIPA(
        in dir: URL,
        appName: String,
        bundleId: String,
        cryptid: UInt32 = 1,
        xmlEntitlements: String? = nil,
        signerLeaf: CertPair? = nil,
        teamIdentifier: String? = nil,
        extraInfoPlist: [String: Any] = [:],
        extraAssets: [String: Data] = [:],
        tamperSealedAssetAfterSigning: (relPath: String, replacement: Data)? = nil,
        unsealedExtraAssets: [String: Data] = [:],
        provisionDict: [String: Any]? = nil,
        sandboxReceiptEnvironment: String? = nil
    ) throws -> (bundleURL: URL, ipaURL: URL, rootCert: SecCertificate) {
        let fm = FileManager.default
        let appURL = dir.appendingPathComponent("\(appName).app")
        try fm.createDirectory(at: appURL, withIntermediateDirectories: true)

        var plistDict: [String: Any] = [
            "CFBundleIdentifier": bundleId,
            "CFBundleExecutable": appName,
            "CFBundleName": appName,
            "CFBundleVersion": "1.0",
            "CFBundleShortVersionString": "1.0"
        ]
        for (k, v) in extraInfoPlist { plistDict[k] = v }
        let infoPlistData = try PropertyListSerialization.data(fromPropertyList: plistDict, format: .xml, options: 0)
        try infoPlistData.write(to: appURL.appendingPathComponent("Info.plist"))

        var filesMap: [String: Any] = [:]
        for (relPath, assetData) in extraAssets {
            let assetURL = appURL.appendingPathComponent(relPath)
            try fm.createDirectory(at: assetURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try assetData.write(to: assetURL)
            let sha1 = Data(Insecure.SHA1.hash(data: assetData))
            let sha256 = Data(SHA256.hash(data: assetData))
            filesMap[relPath] = ["hash": sha1, "hash2": sha256]
        }
        let codeResourcesDict: [String: Any] = [
            "files": filesMap,
            "files2": filesMap,
            "rules": [String: Any]()
        ]
        let codeResourcesData = try PropertyListSerialization.data(fromPropertyList: codeResourcesDict, format: .xml, options: 0)
        let csDir = appURL.appendingPathComponent("_CodeSignature")
        try fm.createDirectory(at: csDir, withIntermediateDirectories: true)
        try codeResourcesData.write(to: csDir.appendingPathComponent("CodeResources"))

        let (signedBin, rootCert) = try buildSignedMachO(
            identifier: bundleId,
            cryptid: cryptid,
            xmlEntitlements: xmlEntitlements,
            infoPlistData: infoPlistData,
            codeResourcesData: codeResourcesData,
            teamIdentifier: teamIdentifier,
            signerLeaf: signerLeaf
        )
        try signedBin.write(to: appURL.appendingPathComponent(appName))

        if let prov = provisionDict {
            let (provCMS, _) = try buildCMSProvisioningProfile(plistDict: prov)
            try provCMS.write(to: appURL.appendingPathComponent("embedded.mobileprovision"))
        }
        if let env = sandboxReceiptEnvironment {
            let (recCMS, _) = try buildCMSSandboxReceipt(environment: env)
            let skDir = appURL.appendingPathComponent("StoreKit")
            try fm.createDirectory(at: skDir, withIntermediateDirectories: true)
            try recCMS.write(to: skDir.appendingPathComponent("sandboxReceipt"))
        }

        if let tamper = tamperSealedAssetAfterSigning {
            try tamper.replacement.write(to: appURL.appendingPathComponent(tamper.relPath))
        }
        for (relPath, extraData) in unsealedExtraAssets {
            let u = appURL.appendingPathComponent(relPath)
            try fm.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
            try extraData.write(to: u)
        }

        let payloadDir = dir.appendingPathComponent("Payload_\(UUID().uuidString)")
        try fm.createDirectory(at: payloadDir.appendingPathComponent("Payload"), withIntermediateDirectories: true)
        let payloadApp = payloadDir.appendingPathComponent("Payload/\(appName).app")
        try fm.copyItem(at: appURL, to: payloadApp)
        let ipaURL = dir.appendingPathComponent("\(appName).ipa")
        let zipProc = Process()
        zipProc.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        zipProc.currentDirectoryURL = payloadDir
        zipProc.arguments = ["-qr", ipaURL.path, "Payload"]
        try zipProc.run()
        zipProc.waitUntilExit()
        precondition(zipProc.terminationStatus == 0, "zip failed")
        return (appURL, ipaURL, rootCert)
    }
}

// MARK: - Minimal Raw ZIP Builder for Adversarial Archive Edge-Case Tests

private struct RawZIPItem {
    let name: String
    let data: Data
    let externalAttrs: UInt32
    let gpFlags: UInt16
    let localUncompressedOverride: UInt32?
    let localCompressedOverride: UInt32?

    init(
        name: String,
        data: Data = Data(),
        externalAttrs: UInt32 = 0,
        gpFlags: UInt16 = 0,
        localUncompressedOverride: UInt32? = nil,
        localCompressedOverride: UInt32? = nil
    ) {
        self.name = name
        self.data = data
        self.externalAttrs = externalAttrs
        self.gpFlags = gpFlags
        self.localUncompressedOverride = localUncompressedOverride
        self.localCompressedOverride = localCompressedOverride
    }
}

private func buildStoredRawZIP(_ items: [RawZIPItem]) -> Data {
    var out = Data()
    var centralDir = Data()

    func appendLE16(_ d: inout Data, _ v: UInt16) {
        var le = v.littleEndian
        withUnsafeBytes(of: &le) { d.append(contentsOf: $0) }
    }
    func appendLE32(_ d: inout Data, _ v: UInt32) {
        var le = v.littleEndian
        withUnsafeBytes(of: &le) { d.append(contentsOf: $0) }
    }

    for item in items {
        let nameData = Data(item.name.utf8)
        let localOffset = UInt32(out.count)
        let crc = item.data.withUnsafeBytes { ptr -> UInt32 in
            guard let base = ptr.bindMemory(to: Bytef.self).baseAddress else { return 0 }
            return UInt32(zlib.crc32(0, base, uInt(item.data.count)))
        }
        let uncompSize = UInt32(item.data.count)
        let compSize = UInt32(item.data.count)

        appendLE32(&out, 0x0403_4B50)
        appendLE16(&out, 20)
        appendLE16(&out, item.gpFlags)
        appendLE16(&out, 0) // stored
        appendLE16(&out, 0)
        appendLE16(&out, 0)
        appendLE32(&out, crc)
        appendLE32(&out, item.localCompressedOverride ?? compSize)
        appendLE32(&out, item.localUncompressedOverride ?? uncompSize)
        appendLE16(&out, UInt16(nameData.count))
        appendLE16(&out, 0)
        out.append(nameData)
        out.append(item.data)

        appendLE32(&centralDir, 0x0201_4B50)
        appendLE16(&centralDir, (3 << 8) | 20)
        appendLE16(&centralDir, 20)
        appendLE16(&centralDir, item.gpFlags)
        appendLE16(&centralDir, 0)
        appendLE16(&centralDir, 0)
        appendLE16(&centralDir, 0)
        appendLE32(&centralDir, crc)
        appendLE32(&centralDir, compSize)
        appendLE32(&centralDir, uncompSize)
        appendLE16(&centralDir, UInt16(nameData.count))
        appendLE16(&centralDir, 0)
        appendLE16(&centralDir, 0)
        appendLE16(&centralDir, 0)
        appendLE16(&centralDir, 0)
        appendLE32(&centralDir, item.externalAttrs)
        appendLE32(&centralDir, localOffset)
        centralDir.append(nameData)
    }

    let cdOffset = UInt32(out.count)
    let cdSize = UInt32(centralDir.count)
    out.append(centralDir)

    appendLE32(&out, 0x0605_4B50)
    appendLE16(&out, 0)
    appendLE16(&out, 0)
    appendLE16(&out, UInt16(items.count))
    appendLE16(&out, UInt16(items.count))
    appendLE32(&out, cdSize)
    appendLE32(&out, cdOffset)
    appendLE16(&out, 0)
    return out
}

// MARK: - M1 Regression Test Suite

final class AuditV135Vector4AndParsersTests: XCTestCase {
    private var tempDirs: [URL] = []

    override func tearDown() {
        for d in tempDirs {
            try? FileManager.default.removeItem(at: d)
        }
        tempDirs.removeAll()
        super.tearDown()
    }

    private func makeTempDir(prefix: String = "m1_r4") throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        tempDirs.append(url)
        return url
    }

    // MARK: 1. CSBlobParser — SKI Binding, Signer Kinds, BER 0x24, Alternating DER, Profile & Receipt CMS

    func test_csBlob_subjectKeyIdentifierMismatch_rejected_andMatchingVerified() throws {
        let state = try M1TestCMSFixtures.sharedState()

        // Valid SKI -> .appleAppStoreVerified + .appStore
        let (validBin, root) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.ski.valid",
            cryptid: 1,
            signerLeaf: state.appStoreLeaf
        )
        let validSlices = try MachOParser.parseAllSlices(data: validBin)
        let validEval = CSBlobParser.shared.inspectCodeSignatureTrustEvaluation(
            fromSlices: validSlices,
            customAnchorCertificates: [root]
        )
        XCTAssertEqual(validEval.disposition, .appleAppStoreVerified)
        XCTAssertEqual(validEval.signerKind, .appStore)

        // Forged/mismatched SKI `[0x01, 0x02, 0x03, 0x04]` -> strictly rejected
        let (mismatchBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.ski.mismatch",
            cryptid: 1,
            signerLeaf: state.appStoreLeaf,
            overrideSKI: Data([0x01, 0x02, 0x03, 0x04])
        )
        let mismatchSlices = try MachOParser.parseAllSlices(data: mismatchBin)
        let mismatchEval = CSBlobParser.shared.inspectCodeSignatureTrustEvaluation(
            fromSlices: mismatchSlices,
            customAnchorCertificates: [root]
        )
        XCTAssertNotEqual(mismatchEval.disposition, .appleAppStoreVerified)
        XCTAssertEqual(mismatchEval.signerKind, .none)
    }

    func test_csBlob_verifiedSignerKinds_appStore_testFlight_macSoftware() throws {
        let state = try M1TestCMSFixtures.sharedState()

        let (tfBin, root) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.signer.tf",
            cryptid: 1,
            signerLeaf: state.testFlightLeaf
        )
        let tfEval = CSBlobParser.shared.inspectCodeSignatureTrustEvaluation(
            fromSlices: try MachOParser.parseAllSlices(data: tfBin),
            customAnchorCertificates: [root]
        )
        XCTAssertEqual(tfEval.disposition, .appleAppStoreVerified)
        XCTAssertEqual(tfEval.signerKind, .testFlight)

        let (macBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.signer.mac",
            cryptid: 1,
            signerLeaf: state.macSoftwareLeaf
        )
        let macEval = CSBlobParser.shared.inspectCodeSignatureTrustEvaluation(
            fromSlices: try MachOParser.parseAllSlices(data: macBin),
            customAnchorCertificates: [root]
        )
        XCTAssertEqual(macEval.disposition, .appleAppStoreVerified)
        XCTAssertEqual(macEval.signerKind, .macSoftware)
    }

    func test_cms_ber0x24NestedIndefiniteEncapContent_andDepthCap() throws {
        let provDict: [String: Any] = [
            "TeamIdentifier": ["TFTEAM8888"],
            "BetaReportsActive": true
        ]
        // Depth 3 nested 0x24 constructed OCTET STRING -> verified
        let (cmsDepth3, root) = try M1TestCMSFixtures.buildCMSProvisioningProfile(
            plistDict: provDict,
            useBER0x24Depth: 3,
            useIndefiniteOuter: true
        )
        let ok = CSBlobParser.shared.verifyProvisioningProfileCMS(cmsDepth3, customAnchorCertificates: [root])
        XCTAssertTrue(ok.isVerified)
        XCTAssertEqual(ok.plist?["BetaReportsActive"] as? Bool, true)

        // Depth 11 (> cap 8) nested 0x24 -> safely rejected
        let (cmsDepth11, _) = try M1TestCMSFixtures.buildCMSProvisioningProfile(
            plistDict: provDict,
            useBER0x24Depth: 11,
            useIndefiniteOuter: true
        )
        let tooDeep = CSBlobParser.shared.verifyProvisioningProfileCMS(cmsDepth11, customAnchorCertificates: [root])
        XCTAssertFalse(tooDeep.isVerified)
        XCTAssertNil(tooDeep.plist)
    }

    func test_cms_provisioningProfileAndReceipt_rejectForgeriesAndWrongLeaves() throws {
        let state = try M1TestCMSFixtures.sharedState()

        // 1. Raw XML provisioning profile (not CMS) -> unverified
        let rawXML = try PropertyListSerialization.data(
            fromPropertyList: ["TeamIdentifier": ["FAKE123"], "BetaReportsActive": true],
            format: .xml,
            options: 0
        )
        let rawRes = CSBlobParser.shared.verifyProvisioningProfileCMS(rawXML, customAnchorCertificates: [state.rootCert])
        XCTAssertFalse(rawRes.isVerified)

        // 2. CMS signed by wrong/rogue leaf -> rejected
        let (rogueProv, _) = try M1TestCMSFixtures.buildCMSProvisioningProfile(
            plistDict: ["BetaReportsActive": true],
            leaf: state.rogueLeaf
        )
        XCTAssertFalse(CSBlobParser.shared.verifyProvisioningProfileCMS(rogueProv, customAnchorCertificates: [state.rootCert]).isVerified)

        // 3. Valid sandbox receipt vs Production receipt vs raw ASCII string
        let (sandboxCMS, _) = try M1TestCMSFixtures.buildCMSSandboxReceipt(environment: "ProductionSandbox", useBER0x24Depth: 2, useIndefiniteOuter: true)
        let sbCheck = CSBlobParser.shared.verifyAppReceiptCMS(sandboxCMS, customAnchorCertificates: [state.rootCert])
        XCTAssertTrue(sbCheck.isVerified)
        XCTAssertTrue(sbCheck.isSandbox)

        let (prodCMS, _) = try M1TestCMSFixtures.buildCMSSandboxReceipt(environment: "Production")
        let prodCheck = CSBlobParser.shared.verifyAppReceiptCMS(prodCMS, customAnchorCertificates: [state.rootCert])
        XCTAssertTrue(prodCheck.isVerified)
        XCTAssertFalse(prodCheck.isSandbox)

        let rawFakeReceipt = Data("ProductionSandbox".utf8)
        let fakeRecCheck = CSBlobParser.shared.verifyAppReceiptCMS(rawFakeReceipt, customAnchorCertificates: [state.rootCert])
        XCTAssertFalse(fakeRecCheck.isVerified)
        XCTAssertFalse(fakeRecCheck.isSandbox)
    }

    func test_asn1DERDecoder_alternatingKeyValueSequence_andEmptyFiles2Fallback() throws {
        // Alternating [UTF8String("keyA"), INTEGER(42), UTF8String("keyB"), UTF8String("valB"), UTF8String("sub"), SEQ(nestedInt, 42, nestedStr, "ok")]
        let nestedSeq = M1TestCMSFixtures.derTLV(0x30,
            M1TestCMSFixtures.derUTF8String("nestedInt") +
            M1TestCMSFixtures.derInteger(42) +
            M1TestCMSFixtures.derUTF8String("nestedStr") +
            M1TestCMSFixtures.derUTF8String("ok")
        )
        let altSeq = M1TestCMSFixtures.derTLV(0x30,
            M1TestCMSFixtures.derUTF8String("keyA") +
            M1TestCMSFixtures.derInteger(42) +
            M1TestCMSFixtures.derUTF8String("keyB") +
            M1TestCMSFixtures.derUTF8String("valB") +
            M1TestCMSFixtures.derUTF8String("sub") +
            nestedSeq
        )
        let decoded = try ASN1DERDecoder.decode(altSeq)
        let dict = ASN1DERDecoder.toDictionary(decoded)
        XCTAssertEqual(dict["keyA"] as? Bool, true)
        XCTAssertEqual(dict["keyB"] as? String, "valB")
        let subDict = try XCTUnwrap(dict["sub"] as? [String: Any])
        XCTAssertEqual(subDict["nestedInt"] as? Bool, true)
        XCTAssertEqual(subDict["nestedStr"] as? String, "ok")

        // CodeResources with empty files2 dict + valid files dict
        let dir = try makeTempDir(prefix: "cr_fallback")
        let appDir = dir.appendingPathComponent("FilesFallback.app")
        try FileManager.default.createDirectory(at: appDir.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        let assetData = Data("hello world".utf8)
        try assetData.write(to: appDir.appendingPathComponent("config.json"))
        let crDict: [String: Any] = [
            "files": ["config.json": Data(Insecure.SHA1.hash(data: assetData))],
            "files2": [String: Any]() // empty files2 must fall back to `files`!
        ]
        let crData = try PropertyListSerialization.data(fromPropertyList: crDict, format: .xml, options: 0)
        try crData.write(to: appDir.appendingPathComponent("_CodeSignature/CodeResources"))

        let infoData = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.test.filesfallback", "CFBundleExecutable": "FilesFallback"],
            format: .xml,
            options: 0
        )
        try infoData.write(to: appDir.appendingPathComponent("Info.plist"))
        let (signedBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.filesfallback",
            cryptid: 1,
            infoPlistData: infoData,
            codeResourcesData: crData
        )
        let slices = try MachOParser.parseAllSlices(data: signedBin)
        let trust = CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: slices, bundleURL: appDir, archiveLookup: nil)
        XCTAssertNil(trust, "Valid CodeResources falling back to `files` when `files2` is empty must pass")
    }

    // MARK: 2. ChannelClassifier Option A Enforcement

    func test_channelClassifier_optionA_provenanceAndBypassRejections() throws {
        let (signedBetaProv, root) = try M1TestCMSFixtures.buildCMSProvisioningProfile(plistDict: [
            "TeamIdentifier": ["BETA123456"],
            "BetaReportsActive": true
        ])
        let (signedSandboxRec, _) = try M1TestCMSFixtures.buildCMSSandboxReceipt(environment: "ProductionSandbox")

        // 1. .absentOrSynthetic NEVER yields .appStore or .testFlight even with cryptid=1 + valid signed Beta provision/receipt
        let synStore = ChannelClassifier.classify(cryptid: 1, codeSignatureTrust: .absentOrSynthetic, customAnchorCertificates: [root])
        XCTAssertEqual(synStore.channel, .developerSideloaded)

        let synTF = ChannelClassifier.classify(
            cryptid: 1,
            mobileprovisionData: signedBetaProv,
            receiptData: signedSandboxRec,
            hasSandboxReceipt: true,
            codeSignatureTrust: .absentOrSynthetic,
            sandboxReceiptData: signedSandboxRec,
            verifiedSignerKind: .testFlight,
            customAnchorCertificates: [root]
        )
        XCTAssertEqual(synTF.channel, .developerSideloaded)

        // 2. hasMissingCodeSignature == true NEVER yields .appStore or .testFlight
        let missCS = ChannelClassifier.classify(
            cryptid: 1,
            codeSignatureTrust: .appleAppStoreVerified,
            verifiedSignerKind: .appStore,
            hasMissingCodeSignature: true,
            customAnchorCertificates: [root]
        )
        XCTAssertEqual(missCS.channel, .developerSideloaded)

        // 3. verifiedSignerKind == .testFlight + cryptid=1 + .appleAppStoreVerified -> .testFlight even with stripped provision/receipt!
        let strippedTF = ChannelClassifier.classify(
            cryptid: 1,
            mobileprovisionData: nil,
            receiptData: nil,
            codeSignatureTrust: .appleAppStoreVerified,
            verifiedSignerKind: .testFlight,
            hasMissingCodeSignature: false,
            customAnchorCertificates: [root]
        )
        XCTAssertEqual(strippedTF.channel, .testFlight)

        // 4. Forged unsigned BetaReportsActive plist + .appleAppStoreVerified App Store signer must NOT become .testFlight
        let unsignedBetaPlist = try PropertyListSerialization.data(
            fromPropertyList: ["TeamIdentifier": ["FAKE"], "BetaReportsActive": true],
            format: .xml,
            options: 0
        )
        let forgedBeta = ChannelClassifier.classify(
            cryptid: 1,
            mobileprovisionData: unsignedBetaPlist,
            hasSandboxReceipt: true,
            codeSignatureTrust: .appleAppStoreVerified,
            verifiedSignerKind: .appStore,
            customAnchorCertificates: [root]
        )
        XCTAssertEqual(forgedBeta.channel, .developerSideloaded, "Tampered/unsigned embedded.mobileprovision must fail closed")

        let boolSandboxOnly = ChannelClassifier.classify(
            cryptid: 1,
            mobileprovisionData: nil,
            hasSandboxReceipt: true,
            codeSignatureTrust: .appleAppStoreVerified,
            verifiedSignerKind: .appStore,
            customAnchorCertificates: [root]
        )
        XCTAssertEqual(boolSandboxOnly.channel, .appStore, "Bool hasSandboxReceipt must not spoof TestFlight")

        // 5. Signed BetaReportsActive provision OR signed sandboxReceipt -> .testFlight
        let verifiedBetaProv = ChannelClassifier.classify(
            cryptid: 1,
            mobileprovisionData: signedBetaProv,
            codeSignatureTrust: .appleAppStoreVerified,
            verifiedSignerKind: .appStore,
            customAnchorCertificates: [root]
        )
        XCTAssertEqual(verifiedBetaProv.channel, .testFlight)
        XCTAssertEqual(verifiedBetaProv.teamIdentifier, "BETA123456")

        let verifiedRecTF = ChannelClassifier.classify(
            cryptid: 1,
            codeSignatureTrust: .appleAppStoreVerified,
            sandboxReceiptData: signedSandboxRec,
            verifiedSignerKind: .appStore,
            customAnchorCertificates: [root]
        )
        XCTAssertEqual(verifiedRecTF.channel, .testFlight)
        XCTAssertTrue(verifiedRecTF.hasReceipt)
    }

    // MARK: 3. IPAPackageScanner & NativeZIPArchiveReader

    func test_nativeZIPArchiveReader_sIfDir_bit6_localMismatch_andNegativeBounds() throws {
        // 1. S_IFDIR without trailing slash + 0 payload -> classified as directory
        //    S_IFDIR with non-zero payload -> throws unsupported / corrupted archive
        let dirExternalAttr = UInt32(0o040755) << 16
        let validDirZip = buildStoredRawZIP([
            RawZIPItem(name: "Payload/MyApp.app", data: Data(), externalAttrs: dirExternalAttr),
            RawZIPItem(name: "Payload/MyApp.app/Info.plist", data: Data("<plist/>".utf8))
        ])
        let validReader = NativeZIPArchiveReader(data: validDirZip)
        let validEntries = try validReader.readCentralDirectory()
        let dirEntry = try XCTUnwrap(validEntries.first { $0.path == "Payload/MyApp.app" })
        XCTAssertTrue(dirEntry.isDirectory)

        let payloadDirZip = buildStoredRawZIP([
            RawZIPItem(name: "Payload/MyApp.app", data: Data("BAD".utf8), externalAttrs: dirExternalAttr)
        ])
        let badDirReader = NativeZIPArchiveReader(data: payloadDirZip)
        XCTAssertThrowsError(try badDirReader.readCentralDirectory()) { err in
            guard case IPAPackageScannerError.corruptHeader = err else {
                XCTFail("Expected corruptHeader for non-zero directory payload, got \(err)")
                return
            }
        }

        // 2. Bit-6 strong encryption (0x0041) -> encryptedArchiveNotSupported
        let encZip = buildStoredRawZIP([
            RawZIPItem(name: "Payload/MyApp.app/secret", data: Data("1234".utf8), gpFlags: 0x0041)
        ])
        let encReader = NativeZIPArchiveReader(data: encZip)
        XCTAssertThrowsError(try encReader.readCentralDirectory()) { err in
            XCTAssertEqual(err as? IPAPackageScannerError, .encryptedArchiveNotSupported)
        }

        // 3. Local header size mismatch vs Central Directory -> rejected
        let mismatchZip = buildStoredRawZIP([
            RawZIPItem(name: "Payload/MyApp.app/bin", data: Data("ABCD".utf8), localUncompressedOverride: 99)
        ])
        let misReader = NativeZIPArchiveReader(data: mismatchZip)
        XCTAssertThrowsError(try misReader.readCentralDirectory()) { err in
            guard case IPAPackageScannerError.corruptHeader = err else {
                XCTFail("Expected corruptHeader for local/CD size mismatch, got \(err)")
                return
            }
        }

        // 4. Negative maxEntries / maxTotalUncompressedBytes clamped safely (no crash)
        let clampedReader = NativeZIPArchiveReader(data: validDirZip, maxEntries: -5, maxTotalUncompressedBytes: -100)
        XCTAssertThrowsError(try clampedReader.readCentralDirectory()) { err in
            guard case IPAPackageScannerError.quotaExceeded = err else {
                XCTFail("Expected quotaExceeded, got \(err)")
                return
            }
        }
    }

    func test_ipaScanner_archiveCodeResourcesSeal_strippedTestFlight_tamperAndUnsealedJS_andMixedSigned() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "ipa_seal")

        // 1. Valid TestFlight IPA with stripped provision & receipt + valid skipped assets (.png/.strings/.js) -> .testFlight & .safe
        let (_, tfIPA, root) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir,
            appName: "CleanTF",
            bundleId: "com.test.clean.tf",
            cryptid: 1,
            signerLeaf: state.testFlightLeaf,
            teamIdentifier: "TEAMTF1234",
            extraAssets: [
                "icon.png": Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
                "en.lproj/Localizable.strings": Data("\"ok\" = \"ok\";".utf8),
                "web/helper.js": Data("console.log('ok');".utf8)
            ]
        )
        let tfFinding = try IPAPackageScanner.shared.scan(ipaURL: tfIPA, customAnchorCertificates: [root])
        XCTAssertEqual(tfFinding.installChannel, .testFlight)
        XCTAssertEqual(tfFinding.riskTier, .safe)

        let privEntXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>com.apple.private.accessorysetupkit.allow</key><true/>
        </dict></plist>
        """

        // 2. Tampered sealed asset (`icon.png` modified after signing) -> seal breaks -> downgraded to .developerSideloaded & .highRisk
        let (_, tamperedIPA, _) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir,
            appName: "TamperedAsset",
            bundleId: "com.test.tampered.asset",
            cryptid: 1,
            xmlEntitlements: privEntXML,
            signerLeaf: state.appStoreLeaf,
            extraAssets: ["icon.png": Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])],
            tamperSealedAssetAfterSigning: (relPath: "icon.png", replacement: Data("TAMPERED_PNG_PAYLOAD".utf8))
        )
        let tamperedFinding = try IPAPackageScanner.shared.scan(ipaURL: tamperedIPA, customAnchorCertificates: [root])
        XCTAssertEqual(tamperedFinding.installChannel, .developerSideloaded)
        XCTAssertEqual(tamperedFinding.riskTier, .highRisk)

        // 3. Unsealed active .js script -> seal breaks -> downgraded to .developerSideloaded & .highRisk
        let (_, unsealedIPA, _) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir,
            appName: "UnsealedJS",
            bundleId: "com.test.unsealed.js",
            cryptid: 1,
            xmlEntitlements: privEntXML,
            signerLeaf: state.appStoreLeaf,
            unsealedExtraAssets: ["evil_unsealed.js": Data("fetch('https://evil.invalid');".utf8)]
        )
        let unsealedFinding = try IPAPackageScanner.shared.scan(ipaURL: unsealedIPA, customAnchorCertificates: [root])
        XCTAssertEqual(unsealedFinding.installChannel, .developerSideloaded)
        XCTAssertEqual(unsealedFinding.riskTier, .highRisk)

        // 4. Nested Frameworks/Foo.framework/embedded.mobileprovision does NOT make main app enterprise or testFlight
        //    AND mixed unsigned dylib inside .testFlight IPA downgrades .testFlight -> .developerSideloaded (and strips exemption -> .highRisk)
        let unsignedDylib = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"]
        ))
        let (_, mixedIPA, _) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir,
            appName: "MixedSignedTF",
            bundleId: "com.test.mixed.tf",
            cryptid: 1,
            xmlEntitlements: privEntXML,
            signerLeaf: state.testFlightLeaf,
            extraAssets: [
                "Frameworks/Sub.framework/Sub": unsignedDylib,
                "Frameworks/Sub.framework/embedded.mobileprovision": Data("fake".utf8)
            ]
        )
        let mixedFinding = try IPAPackageScanner.shared.scan(ipaURL: mixedIPA, customAnchorCertificates: [root])
        XCTAssertEqual(mixedFinding.installChannel, .developerSideloaded, "Unsigned sub-binary inside .testFlight IPA must downgrade to .developerSideloaded")
        XCTAssertEqual(mixedFinding.riskTier, .highRisk)
    }

    func test_ipaScanner_lexicalStandardizedPath_privatePrefix_andTeamIDShadowingDefense() throws {
        // Verify `/private/var/...` vs `/var/...` lexical helper behaves consistently without triggering false ZipSlip
        XCTAssertEqual(
            IPAPackageScanner.lexicalStandardizedPath("/private/var/mobile/Containers/Data/App/Payload/Foo.app"),
            IPAPackageScanner.lexicalStandardizedPath("/private/var/mobile/Containers/Data/App/Payload/../Payload/Foo.app")
        )
        XCTAssertEqual(
            IPAPackageScanner.lexicalStandardizedPrefix("/var/tmp/unpack"),
            "/var/tmp/unpack/"
        )

        // Team ID shadowing defense:
        // Main binary signed by OWNTEAM123 with matching keychain-access-groups "OWNTEAM123.*" -> safe
        // Sub-binary (.appex) claiming team ROGUE99999 + keychain-access-groups "ROGUE99999.*" must NOT poison own team OR pass unflagged
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "team_shadow")

        let mainEnt = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>com.apple.developer.team-identifier</key><string>OWNTEAM123</string>
            <key>keychain-access-groups</key><array><string>OWNTEAM123.*</string></array>
        </dict></plist>
        """
        let appexEnt = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>com.apple.developer.team-identifier</key><string>ROGUE99999</string>
            <key>keychain-access-groups</key><array><string>*</string></array>
        </dict></plist>
        """
        let (appexBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.teamshadow.ext",
            cryptid: 1,
            xmlEntitlements: appexEnt,
            teamIdentifier: "ROGUE99999",
            signerLeaf: state.appStoreLeaf
        )
        let appexPlist = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "com.test.teamshadow.ext",
                "CFBundleExecutable": "Ext",
                "NSExtension": ["NSExtensionPointIdentifier": "com.apple.widgetkit-extension"]
            ],
            format: .xml,
            options: 0
        )

        let (_, ipaURL, root) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir,
            appName: "TeamShadow",
            bundleId: "com.test.teamshadow",
            cryptid: 1,
            xmlEntitlements: mainEnt,
            signerLeaf: state.appStoreLeaf,
            teamIdentifier: "OWNTEAM123",
            extraAssets: [
                "PlugIns/Ext.appex/Ext": appexBin,
                "PlugIns/Ext.appex/Info.plist": appexPlist
            ]
        )
        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL, customAnchorCertificates: [root])
        XCTAssertTrue(
            finding.indicators.contains { $0.signature.lowercased().contains("keychain") },
            "Wildcard '*' keychain-access-groups on .appex must be evaluated per-binary and flagged"
        )
    }

    // MARK: 4. MachOParser 7 DoS & Bypass Vectors (Explorer 3)

    func test_machoParser_parseAllSlices_duplicateAndOverlappingDosBounded() throws {
        let thinSlice = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"],
            textInstructions: [0xD400_1001, 0xD65F_03C0]
        ))

        // Build FAT binary with 1,024 fat_arch entries pointing to the SAME single slice offset (amplification bomb)
        let nfat: UInt32 = 1024
        let fatHeaderAndArchs = 8 + Int(nfat) * MemoryLayout<fat_arch>.size
        let sliceOffset = (fatHeaderAndArchs + 4095) & ~4095
        var fat = Data()
        M1TestCMSFixtures.appendBE32(&fat, FAT_MAGIC)
        M1TestCMSFixtures.appendBE32(&fat, nfat)
        for i in 0..<Int(nfat) {
            M1TestCMSFixtures.appendBE32(&fat, UInt32(bitPattern: CPU_TYPE_ARM64))
            // Distinct cpuSubtype every entry to stress both dedup and overlap budget
            M1TestCMSFixtures.appendBE32(&fat, UInt32(i))
            M1TestCMSFixtures.appendBE32(&fat, UInt32(sliceOffset))
            M1TestCMSFixtures.appendBE32(&fat, UInt32(thinSlice.count))
            M1TestCMSFixtures.appendBE32(&fat, 12)
        }
        fat.append(Data(repeating: 0, count: sliceOffset - fat.count))
        fat.append(thinSlice)

        let t0 = Date()
        let parsed = try MachOParser.parseAllSlices(data: fat)
        let elapsed = Date().timeIntervalSince(t0)
        XCTAssertLessThan(elapsed, 0.5)
        XCTAssertLessThanOrEqual(parsed.count, 16)
        XCTAssertGreaterThanOrEqual(parsed.count, 1)
    }

    func test_machoParser_chainedFixups_cumulativeZlibBudget() throws {
        func appendLE32(_ d: inout Data, _ v: UInt32) {
            var le = v.littleEndian
            withUnsafeBytes(of: &le) { d.append(contentsOf: $0) }
        }

        // Sub-case A: 6 commands x 8 MB zlib payloads (48 MB > 32 MB cumulative cap, strictly < 8-command limit).
        // Commands 0..3 consume 32 MB; commands 4..5 exceed remainingChainedZlibBytes and must NOT inflate.
        var okPool = Data([0x00])
        okPool.append(Data("_ok_cmd0\0".utf8))
        okPool.append(Data(repeating: 0x00, count: 8 * 1024 * 1024))
        let compressedOkPool = try M1TestCMSFixtures.zlibCompress(okPool)

        var latePool = Data([0x00])
        latePool.append(Data("_\(IOCTokenArmor.tFsgetpath)\0".utf8))
        latePool.append(Data(repeating: 0x00, count: 8 * 1024 * 1024))
        let compressedLatePool = try M1TestCMSFixtures.zlibCompress(latePool)

        func makeChainedPayload(compressed: Data, importsCount: UInt32, nameOffset: UInt32) -> Data {
            var cf = Data()
            appendLE32(&cf, 0)  // fixups_version
            appendLE32(&cf, 0)  // starts_offset
            appendLE32(&cf, 28) // imports_offset
            appendLE32(&cf, 28 + importsCount * 4) // symbols_offset
            appendLE32(&cf, importsCount)
            appendLE32(&cf, 1)  // DYLD_CHAINED_IMPORT
            appendLE32(&cf, 1)  // zlib compressed
            for _ in 0..<importsCount {
                appendLE32(&cf, nameOffset << 9)
            }
            cf.append(compressed)
            return cf
        }

        let cmd0Payload = makeChainedPayload(compressed: compressedOkPool, importsCount: 1, nameOffset: 1)
        let fillerPayload = makeChainedPayload(compressed: compressedOkPool, importsCount: 1, nameOffset: 1)
        let cmd5Payload = makeChainedPayload(compressed: compressedLatePool, importsCount: 1, nameOffset: 1)
        let allZlibPayloads = [cmd0Payload, fillerPayload, fillerPayload, fillerPayload, fillerPayload, cmd5Payload]

        var hdr = mach_header_64()
        hdr.magic = MH_MAGIC_64
        hdr.cputype = CPU_TYPE_ARM64
        hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        hdr.filetype = UInt32(MH_EXECUTE)
        hdr.ncmds = UInt32(allZlibPayloads.count)
        hdr.sizeofcmds = UInt32(allZlibPayloads.count * MemoryLayout<linkedit_data_command>.size)
        var evilZlib = Data(bytes: &hdr, count: MemoryLayout<mach_header_64>.size)
        var curOff = MemoryLayout<mach_header_64>.size + Int(hdr.sizeofcmds)
        for p in allZlibPayloads {
            var lc = linkedit_data_command()
            lc.cmd = 0x8000_0034
            lc.cmdsize = UInt32(MemoryLayout<linkedit_data_command>.size)
            lc.dataoff = UInt32(curOff)
            lc.datasize = UInt32(p.count)
            evilZlib.append(Data(bytes: &lc, count: MemoryLayout<linkedit_data_command>.size))
            curOff += p.count
        }
        for p in allZlibPayloads { evilZlib.append(p) }

        let t0 = Date()
        let parsedZlib = try MachOParser.parse(data: evilZlib)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 1.0)
        XCTAssertTrue(parsedZlib.containsSymbol("_ok_cmd0"))
        XCTAssertFalse(
            parsedZlib.containsSymbol("_\(IOCTokenArmor.tFsgetpath)"),
            "Cumulative 32 MB zlib budget must stop command 5 (< 8 commands)"
        )

        // Sub-case B: 3 commands x 150,000 OOB/empty import entries (syms.count == 0 in commands 0..1)
        // proving `availableCount` (not `syms.count`) deducts from `remainingChainedImportsBudget = 262_144`.
        func makeUncompressedChainedPayload(importsCount: Int, oobEntries: Bool, validSym: String?) -> Data {
            var symPool = Data([0x00])
            if let validSym {
                symPool.append(Data((validSym + "\0").utf8))
            }
            var cf = Data()
            appendLE32(&cf, 0)
            appendLE32(&cf, 0)
            appendLE32(&cf, 28)
            appendLE32(&cf, UInt32(28 + importsCount * 4))
            appendLE32(&cf, UInt32(importsCount))
            appendLE32(&cf, 1) // DYLD_CHAINED_IMPORT
            appendLE32(&cf, 0) // uncompressed
            let rawEntry: UInt32 = oobEntries ? (0x003F_FFFF << 9) : (1 << 9)
            for _ in 0..<importsCount {
                appendLE32(&cf, rawEntry)
            }
            cf.append(symPool)
            return cf
        }

        let oobPayload0 = makeUncompressedChainedPayload(importsCount: 150_000, oobEntries: true, validSym: nil)
        let oobPayload1 = makeUncompressedChainedPayload(importsCount: 150_000, oobEntries: true, validSym: nil)
        let canaryPayload2 = makeUncompressedChainedPayload(importsCount: 1, oobEntries: false, validSym: "_cmd2_budget_canary")
        let importPayloads = [oobPayload0, oobPayload1, canaryPayload2]

        var hdr2 = mach_header_64()
        hdr2.magic = MH_MAGIC_64
        hdr2.cputype = CPU_TYPE_ARM64
        hdr2.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        hdr2.filetype = UInt32(MH_EXECUTE)
        hdr2.ncmds = 3
        hdr2.sizeofcmds = UInt32(3 * MemoryLayout<linkedit_data_command>.size)
        var evilImports = Data(bytes: &hdr2, count: MemoryLayout<mach_header_64>.size)
        var off2 = MemoryLayout<mach_header_64>.size + Int(hdr2.sizeofcmds)
        for p in importPayloads {
            var lc = linkedit_data_command()
            lc.cmd = 0x8000_0034
            lc.cmdsize = UInt32(MemoryLayout<linkedit_data_command>.size)
            lc.dataoff = UInt32(off2)
            lc.datasize = UInt32(p.count)
            evilImports.append(Data(bytes: &lc, count: MemoryLayout<linkedit_data_command>.size))
            off2 += p.count
        }
        for p in importPayloads { evilImports.append(p) }

        let t1 = Date()
        let parsedImports = try MachOParser.parse(data: evilImports)
        XCTAssertLessThan(Date().timeIntervalSince(t1), 0.5)
        XCTAssertFalse(
            parsedImports.containsSymbol("_cmd2_budget_canary"),
            "Empty/OOB import entries must deduct availableCount from 262,144 budget so command 2 is skipped"
        )
    }

    func test_machoParser_symtab_nsymsStrsizeDoS_andSymbolCacheSpeed() throws {
        // 100,000 nlist_64 entries pointing to strx = 1 in a 1 MB NUL-free string table + 32 duplicate LC_SYMTAB
        var hdr = mach_header_64()
        hdr.magic = MH_MAGIC_64
        hdr.cputype = CPU_TYPE_ARM64
        hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        hdr.filetype = UInt32(MH_EXECUTE)
        let cmdCount: UInt32 = 32
        hdr.ncmds = cmdCount
        hdr.sizeofcmds = cmdCount * UInt32(MemoryLayout<symtab_command>.size)

        var bin = Data(bytes: &hdr, count: MemoryLayout<mach_header_64>.size)
        let symOff = MemoryLayout<mach_header_64>.size + Int(hdr.sizeofcmds)
        let nsyms = 100_000
        let symTableSize = nsyms * MemoryLayout<nlist_64>.size
        let strOff = symOff + symTableSize
        let strSize = 1 * 1024 * 1024

        for _ in 0..<cmdCount {
            var st = symtab_command()
            st.cmd = UInt32(LC_SYMTAB)
            st.cmdsize = UInt32(MemoryLayout<symtab_command>.size)
            st.symoff = UInt32(symOff)
            st.nsyms = UInt32(nsyms)
            st.stroff = UInt32(strOff)
            st.strsize = UInt32(strSize)
            bin.append(Data(bytes: &st, count: MemoryLayout<symtab_command>.size))
        }

        // nlist_64 entries with n_strx = 1
        var entry = nlist_64()
        entry.n_un.n_strx = 1
        let oneEntry = Data(bytes: &entry, count: MemoryLayout<nlist_64>.size)
        for _ in 0..<nsyms {
            bin.append(oneEntry)
        }
        // NUL-free string table filled with 'A'
        bin.append(Data(repeating: 0x41, count: strSize))

        let t0 = Date()
        let parsed = try MachOParser.parse(data: bin)
        _ = parsed.symbols
        for _ in 0..<20 {
            _ = parsed.containsSymbol("_nonexistent")
        }
        let elapsed = Date().timeIntervalSince(t0)
        XCTAssertLessThan(elapsed, 0.5, "O(nsyms * strsize) + SymbolCache must complete in < 0.5s")
        XCTAssertEqual(parsed.symtabs.count, 1, "Duplicate LC_SYMTAB commands must be deduplicated")
    }

    func test_machoParser_lazyBind_quadraticResyncDoS_O_N_recovery() throws {
        // 1 MB filled with 'A' (0x41) + 500 KB of [0x40, 0x41, 0x00] + trailing valid [0x40, _fsgetpath, 0x00, 0x90, 0x00]
        var lazyStream = Data(repeating: 0x41, count: 1024 * 1024)
        for _ in 0..<150_000 {
            lazyStream.append(contentsOf: [0x40, 0x41, 0x00])
        }
        lazyStream.append(0x40)
        lazyStream.append(Data(("_" + IOCTokenArmor.tFsgetpath).utf8))
        lazyStream.append(contentsOf: [0x00, 0x90, 0x00])

        var hdr = mach_header_64()
        hdr.magic = MH_MAGIC_64
        hdr.cputype = CPU_TYPE_ARM64
        hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        hdr.filetype = UInt32(MH_EXECUTE)
        hdr.ncmds = 1
        hdr.sizeofcmds = 48
        var bin = Data(bytes: &hdr, count: MemoryLayout<mach_header_64>.size)
        var dyldInfo = dyld_info_command()
        dyldInfo.cmd = UInt32(LC_DYLD_INFO_ONLY)
        dyldInfo.cmdsize = 48
        dyldInfo.lazy_bind_off = UInt32(MemoryLayout<mach_header_64>.size + 48)
        dyldInfo.lazy_bind_size = UInt32(lazyStream.count)
        bin.append(Data(bytes: &dyldInfo, count: 48))
        bin.append(lazyStream)

        let t0 = Date()
        let parsed = try MachOParser.parse(data: bin)
        let syms = parsed.symbols
        let elapsed = Date().timeIntervalSince(t0)
        XCTAssertLessThan(elapsed, 0.5, "O(N) lazy_bind Pass 3 must process 1.5 MB adversarial stream in < 0.5s")
        XCTAssertTrue(syms.contains("_" + IOCTokenArmor.tFsgetpath))
    }

    func test_machoParser_forgedFairPlay_embeddedInfoPlist_and_objcMethnamePadding() throws {
        // 1. Ad-hoc signed (.adHocOrUnsigned) cryptid=1 binary with plaintext __info_plist + plaintext svc #0x80 -> detected!
        let plistData = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.evil.forgedfp", "UIBackgroundModes": ["voip", "audio"]],
            format: .xml,
            options: 0
        )
        let emptyEnt = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict/></plist>"
        let adHocCD = M1TestCMSFixtures.buildCodeDirectory(
            identifier: "com.evil.forgedfp",
            codeLimit: 4096,
            slicePrefixBytes: Data(repeating: 0, count: 4096),
            infoPlistData: nil,
            codeResourcesData: nil,
            slot5Blob: nil
        )
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 0x4000,
            xmlEntitlements: emptyEnt,
            rawCodeSignatureSlot: (slot: CSBlobConstants.slotCodeDirectory, magic: CSBlobConstants.codeDirectoryMagic, data: Data(adHocCD.dropFirst(8))),
            textInstructions: [0xD400_1001, 0xD65F_03C0],
            customSections: [
                (segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: plistData)
            ]
        ))
        let parsed = try MachOParser.parse(data: bin)
        XCTAssertTrue(parsed.hasForgedPlaintextFairPlayRange)
        XCTAssertEqual(parsed.embeddedInfoPlist?["CFBundleIdentifier"] as? String, "com.evil.forgedfp")

        let dir = try makeTempDir(prefix: "forged_fp")
        let binURL = dir.appendingPathComponent("forged_fp_bin")
        try bin.write(to: binURL)
        let finding = try SecurityPipeline.shared.scanBinary(at: binURL)
        XCTAssertEqual(finding.riskTier, .highRisk)

        // Negative control: ad-hoc cryptid=1 over >= 256-byte CSPRNG high-entropy payload -> NOT forged plaintext
        let csprngBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 0x4000,
            xmlEntitlements: emptyEnt,
            rawCodeSignatureSlot: (slot: CSBlobConstants.slotCodeDirectory, magic: CSBlobConstants.codeDirectoryMagic, data: Data(adHocCD.dropFirst(8))),
            customSections: [
                (segName: "__TEXT", sectName: "__csprng", flags: 0, payload: M1TestCMSFixtures.csprngBytes(count: 1024))
            ]
        ))
        // Patch LC_ENCRYPTION_INFO_64 to cover only the CSPRNG section
        let parsedCSPRNGPre = try MachOParser.parse(data: csprngBin)
        let csprngSect = try XCTUnwrap(parsedCSPRNGPre.segments.flatMap(\.sections).first { $0.sectionName == "__csprng" })
        var patchedCSPRNG = csprngBin
        let ncmdsCS = patchedCSPRNG.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self) }
        var lcCur = MemoryLayout<mach_header_64>.size
        for _ in 0..<ncmdsCS {
            let cmd = patchedCSPRNG.withUnsafeBytes { $0.load(fromByteOffset: lcCur, as: UInt32.self) }
            let csz = patchedCSPRNG.withUnsafeBytes { $0.load(fromByteOffset: lcCur + 4, as: UInt32.self) }
            if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                var offLE = csprngSect.offset.littleEndian
                var szLE = UInt32(csprngSect.size).littleEndian
                withUnsafeBytes(of: &offLE) { patchedCSPRNG.replaceSubrange((lcCur + 8)..<(lcCur + 12), with: $0) }
                withUnsafeBytes(of: &szLE) { patchedCSPRNG.replaceSubrange((lcCur + 12)..<(lcCur + 16), with: $0) }
                break
            }
            lcCur += Int(csz)
        }
        let parsedCSPRNG = try MachOParser.parse(data: patchedCSPRNG)
        XCTAssertFalse(parsedCSPRNG.hasForgedPlaintextFairPlayRange)

        // 2. Front-padded 70,000 dummy selectors before "systemPhotoLibrary" + "bundleWithPath:" in __objc_methname
        var methPayload = Data()
        for i in 0..<70_000 {
            methPayload.append(Data("m\(i)\0".utf8))
        }
        methPayload.append(Data("systemPhotoLibrary\0".utf8))
        methPayload.append(Data("bundleWithPath:\0".utf8))
        for i in 0..<100 {
            methPayload.append(Data("z\(i)\0".utf8))
        }
        let methBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [
                (segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: methPayload)
            ]
        ))
        let parsedMeth = try MachOParser.parse(data: methBin)
        let sels = Set(parsedMeth.objcMethodNames)
        XCTAssertTrue(sels.contains("systemPhotoLibrary"))
        XCTAssertTrue(sels.contains("bundleWithPath:"))
    }

    func test_machoParser_overlappingTextSections_andOOBMetadataGapBlindingFix() throws {
        // Executable __TEXT segment containing unsectioned `svc #0x80` + 500 overlapping `__text` headers + OOB `__const` (size = UInt64.max)
        let ncmds: UInt32 = 1
        let nsects: UInt32 = 501
        let cmdsize = UInt32(MemoryLayout<segment_command_64>.size + Int(nsects) * MemoryLayout<section_64>.size)
        var hdr = mach_header_64()
        hdr.magic = MH_MAGIC_64
        hdr.cputype = CPU_TYPE_ARM64
        hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        hdr.filetype = UInt32(MH_EXECUTE)
        hdr.ncmds = ncmds
        hdr.sizeofcmds = cmdsize

        var bin = Data(bytes: &hdr, count: MemoryLayout<mach_header_64>.size)
        let commandsEnd = MemoryLayout<mach_header_64>.size + Int(cmdsize)
        let textStart = commandsEnd
        let textSize = 16_384
        let caveOffset = textStart + textSize // unsectioned code cave containing svc #0x80
        let totalFileSize = caveOffset + 16

        var seg = segment_command_64()
        seg.cmd = UInt32(LC_SEGMENT_64)
        seg.cmdsize = cmdsize
        withUnsafeMutableBytes(of: &seg.segname) { buf in
            buf.initializeMemory(as: UInt8.self, repeating: 0)
            for (i, b) in "__TEXT".utf8.enumerated() { buf[i] = b }
        }
        seg.vmaddr = 0x1_0000_0000
        seg.vmsize = UInt64(totalFileSize)
        seg.fileoff = 0
        seg.filesize = UInt64(totalFileSize)
        seg.maxprot = 7
        seg.initprot = 5
        seg.nsects = nsects
        bin.append(Data(bytes: &seg, count: MemoryLayout<segment_command_64>.size))

        // 500 overlapping __text sections covering [textStart, textStart + textSize)
        for _ in 0..<500 {
            var sect = section_64()
            withUnsafeMutableBytes(of: &sect.sectname) { buf in
                buf.initializeMemory(as: UInt8.self, repeating: 0)
                for (i, b) in "__text".utf8.enumerated() { buf[i] = b }
            }
            withUnsafeMutableBytes(of: &sect.segname) { buf in
                buf.initializeMemory(as: UInt8.self, repeating: 0)
                for (i, b) in "__TEXT".utf8.enumerated() { buf[i] = b }
            }
            sect.addr = 0x1_0000_0000 + UInt64(textStart)
            sect.size = UInt64(textSize)
            sect.offset = UInt32(textStart)
            sect.flags = UInt32(S_ATTR_PURE_INSTRUCTIONS)
            bin.append(Data(bytes: &sect, count: MemoryLayout<section_64>.size))
        }

        // OOB fake __const metadata section claiming size = UInt64.max starting at textStart
        var fakeConst = section_64()
        withUnsafeMutableBytes(of: &fakeConst.sectname) { buf in
            buf.initializeMemory(as: UInt8.self, repeating: 0)
            for (i, b) in "__const".utf8.enumerated() { buf[i] = b }
        }
        withUnsafeMutableBytes(of: &fakeConst.segname) { buf in
            buf.initializeMemory(as: UInt8.self, repeating: 0)
            for (i, b) in "__TEXT".utf8.enumerated() { buf[i] = b }
        }
        fakeConst.addr = 0x1_0000_0000 + UInt64(textStart)
        fakeConst.size = UInt64.max
        fakeConst.offset = UInt32(textStart)
        fakeConst.flags = UInt32(S_REGULAR)
        bin.append(Data(bytes: &fakeConst, count: MemoryLayout<section_64>.size))

        // Fill __text with NOPs (`0xD503_201F`)
        var nopLE = UInt32(0xD503_201F).littleEndian
        let nopData = Data(bytes: &nopLE, count: 4)
        for _ in 0..<(textSize / 4) {
            bin.append(nopData)
        }
        // Unsectioned code cave holds `svc #0x80` (`0xD400_1001`) + `ret`
        var svcLE = UInt32(0xD400_1001).littleEndian
        var retLE = UInt32(0xD65F_03C0).littleEndian
        bin.append(Data(bytes: &svcLE, count: 4))
        bin.append(Data(bytes: &retLE, count: 4))
        bin.append(Data(repeating: 0, count: totalFileSize - bin.count))

        let t0 = Date()
        let parsed = try MachOParser.parse(data: bin)
        let scan = parsed.scanDirectSyscalls()
        let elapsed = Date().timeIntervalSince(t0)
        XCTAssertLessThan(elapsed, 0.5)
        XCTAssertEqual(scan.totalCount, 1, "OOB __const metadata section must NOT blind unsectioned svc #0x80 code cave")
        XCTAssertEqual(scan.sampleSites.first?.fileOffset, caveOffset)
    }

    // MARK: 6. Iteration 2 Remediation Regression Tests

    func test_machoParser_forgedFairPlay_unsignedAndSlot5OnlyPlaintextCryptid1_detected() throws {
        let plistData = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.evil.unsignedfp", "UIBackgroundModes": ["voip", "audio"]],
            format: .xml,
            options: 0
        )
        let methPayload = Data("systemPhotoLibrary\0".utf8)

        // 1. Unsigned (codeSignatures.isEmpty) cryptid = 1 binary over plaintext svc #0x80 + __objc_methname + __info_plist
        let unsignedBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 0x4000,
            textInstructions: [0xD400_1001, 0xD65F_03C0],
            customSections: [
                (segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: methPayload),
                (segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: plistData)
            ]
        ))
        let parsedUnsigned = try MachOParser.parse(data: unsignedBin)
        XCTAssertTrue(parsedUnsigned.codeSignatures.isEmpty)
        XCTAssertTrue(parsedUnsigned.hasForgedPlaintextFairPlayRange)
        XCTAssertEqual(parsedUnsigned.scanDirectSyscalls().totalCount, 1)
        XCTAssertTrue(parsedUnsigned.objcMethodNames.contains("systemPhotoLibrary"))
        XCTAssertEqual(parsedUnsigned.embeddedInfoPlist?["CFBundleIdentifier"] as? String, "com.evil.unsignedfp")

        let dir = try makeTempDir(prefix: "unsigned_fp")
        let unsignedURL = dir.appendingPathComponent("unsigned_fp_bin")
        try unsignedBin.write(to: unsignedURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: unsignedURL).riskTier, .highRisk)

        // 2. Slot-5-only (.absentOrSynthetic) cryptid = 1 binary over plaintext svc #0x80 + __objc_methname + __info_plist
        let emptyEnt = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict/></plist>"
        let slot5OnlyBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 0x4000,
            xmlEntitlements: emptyEnt,
            textInstructions: [0xD400_1001, 0xD65F_03C0],
            customSections: [
                (segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: methPayload),
                (segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: plistData)
            ]
        ))
        let parsedSlot5 = try MachOParser.parse(data: slot5OnlyBin)
        XCTAssertFalse(parsedSlot5.codeSignatures.isEmpty)
        XCTAssertTrue(parsedSlot5.hasForgedPlaintextFairPlayRange)
        XCTAssertEqual(parsedSlot5.scanDirectSyscalls().totalCount, 1)
        XCTAssertTrue(parsedSlot5.objcMethodNames.contains("systemPhotoLibrary"))
        XCTAssertEqual(parsedSlot5.embeddedInfoPlist?["CFBundleIdentifier"] as? String, "com.evil.unsignedfp")

        let slot5URL = dir.appendingPathComponent("slot5_fp_bin")
        try slot5OnlyBin.write(to: slot5URL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: slot5URL).riskTier, .highRisk)
    }

    func test_machoParser_embeddedInfoPlist_shifted4MBSectionsDoS_fastBounded() throws {
        func buildShiftedInfoPlistBinary(fillByte: UInt8) throws -> Data {
            let nsects: UInt32 = 1000
            let segCmdSize = MemoryLayout<segment_command_64>.size + Int(nsects) * MemoryLayout<section_64>.size
            var hdr = mach_header_64()
            hdr.magic = MH_MAGIC_64
            hdr.cputype = CPU_TYPE_ARM64
            hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
            hdr.filetype = UInt32(MH_EXECUTE)
            hdr.ncmds = 1
            hdr.sizeofcmds = UInt32(segCmdSize)

            let payloadOffset = MemoryLayout<mach_header_64>.size + segCmdSize
            let payloadSize = 4 * 1024 * 1024
            let totalSize = payloadOffset + payloadSize

            var seg = segment_command_64()
            seg.cmd = UInt32(LC_SEGMENT_64)
            seg.cmdsize = UInt32(segCmdSize)
            withUnsafeMutableBytes(of: &seg.segname) { buf in
                buf.initializeMemory(as: UInt8.self, repeating: 0)
                for (i, b) in "__TEXT".utf8.enumerated() { buf[i] = b }
            }
            seg.vmaddr = 0x1_0000_0000
            seg.vmsize = UInt64(totalSize)
            seg.fileoff = 0
            seg.filesize = UInt64(totalSize)
            seg.maxprot = 5
            seg.initprot = 5
            seg.nsects = nsects

            var bin = Data(bytes: &hdr, count: MemoryLayout<mach_header_64>.size)
            bin.append(Data(bytes: &seg, count: MemoryLayout<segment_command_64>.size))
            for i in 0..<Int(nsects) {
                var sect = section_64()
                withUnsafeMutableBytes(of: &sect.sectname) { buf in
                    buf.initializeMemory(as: UInt8.self, repeating: 0)
                    for (j, b) in "__info_plist".utf8.enumerated() { buf[j] = b }
                }
                withUnsafeMutableBytes(of: &sect.segname) { buf in
                    buf.initializeMemory(as: UInt8.self, repeating: 0)
                    for (j, b) in "__TEXT".utf8.enumerated() { buf[j] = b }
                }
                sect.addr = 0x1_0000_0000 + UInt64(payloadOffset + i)
                sect.size = UInt64(payloadSize - i)
                sect.offset = UInt32(payloadOffset + i)
                sect.flags = UInt32(S_REGULAR)
                bin.append(Data(bytes: &sect, count: MemoryLayout<section_64>.size))
            }
            bin.append(Data(repeating: fillByte, count: payloadSize))
            return bin
        }

        let binA = try buildShiftedInfoPlistBinary(fillByte: 0x41)
        let t0 = Date()
        let parsedA = try MachOParser.parse(data: binA)
        XCTAssertNil(parsedA.embeddedInfoPlist)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 0.5)

        let binLT = try buildShiftedInfoPlistBinary(fillByte: 0x3C) // '<'
        let t1 = Date()
        let parsedLT = try MachOParser.parse(data: binLT)
        XCTAssertNil(parsedLT.embeddedInfoPlist)
        XCTAssertLessThan(Date().timeIntervalSince(t1), 0.5)
    }

    func test_machoParser_parseAllSlices_1024ShiftedCpuMismatchEntriesDoS_fastBounded() throws {
        let sliceOffset = 32_768
        let thinSize = 64 * 1024 * 1024
        var fat = Data()
        M1TestCMSFixtures.appendBE32(&fat, FAT_MAGIC)
        M1TestCMSFixtures.appendBE32(&fat, 1024)
        for i in 0..<1024 {
            M1TestCMSFixtures.appendBE32(&fat, UInt32(bitPattern: CPU_TYPE_ARM)) // intentional mismatch against ARM64 thin header
            M1TestCMSFixtures.appendBE32(&fat, UInt32(i))
            M1TestCMSFixtures.appendBE32(&fat, UInt32(sliceOffset))
            M1TestCMSFixtures.appendBE32(&fat, UInt32(thinSize - i))
            M1TestCMSFixtures.appendBE32(&fat, 12)
        }
        fat.append(Data(repeating: 0, count: sliceOffset - fat.count))
        var thinHdr = mach_header_64()
        thinHdr.magic = MH_MAGIC_64
        thinHdr.cputype = CPU_TYPE_ARM64
        thinHdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        thinHdr.filetype = UInt32(MH_EXECUTE)
        fat.append(Data(bytes: &thinHdr, count: MemoryLayout<mach_header_64>.size))
        fat.append(Data(repeating: 0, count: thinSize - MemoryLayout<mach_header_64>.size))

        let t0 = Date()
        XCTAssertThrowsError(try MachOParser.parseAllSlices(data: fat))
        XCTAssertLessThan(Date().timeIntervalSince(t0), 0.5)
    }

    func test_machoParser_objcMethodNames_260ByteSandwichedSelector_and_34MBFrontPadding() throws {
        // 1. 260-byte sandwiched selector (`Vector 6d`)
        let sandwiched260 = String(repeating: "a", count: 120) + "systemPhotoLibrary" + String(repeating: "b", count: 122)
        XCTAssertGreaterThan(sandwiched260.utf8.count, 256)
        XCTAssertLessThanOrEqual(sandwiched260.utf8.count, 512)
        var meth260 = Data()
        for i in 0..<66_000 {
            meth260.append(Data("p\(i)\0".utf8))
        }
        meth260.append(Data((sandwiched260 + "\0").utf8))
        meth260.append(Data("tailMarker\0".utf8))
        let bin260 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [
                (segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: meth260)
            ]
        ))
        let parsed260 = try MachOParser.parse(data: bin260)
        XCTAssertTrue(parsed260.objcMethodNames.contains(sandwiched260))

        // 2. 34 MB front-padded __objc_methname (`Vector 6c`) with selectors in middle gap (~25 MB) and tail (~33.5 MB)
        var meth34 = Data()
        meth34.reserveCapacity(35 * 1024 * 1024)
        let padChunk = Data("padSelector_\0".utf8)
        while meth34.count < 25 * 1024 * 1024 {
            meth34.append(padChunk)
        }
        meth34.append(Data("systemPhotoLibrary\0".utf8))
        while meth34.count < 34 * 1024 * 1024 {
            meth34.append(padChunk)
        }
        meth34.append(Data("bundleWithPath:\0".utf8))
        let bin34 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [
                (segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: meth34)
            ]
        ))
        let t0 = Date()
        let parsed34 = try MachOParser.parse(data: bin34)
        let sels34 = Set(parsed34.objcMethodNames)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 2.0)
        XCTAssertTrue(sels34.contains("systemPhotoLibrary"))
        XCTAssertTrue(sels34.contains("bundleWithPath:"))
    }

    func test_machoParser_symtab_8Symtabs_62500DistinctRandomASCII_fastBounded() throws {
        let symtabCount = 8
        let symsPerTab = 62_500
        let strSize = 8 * 1024 * 1024

        var hdr = mach_header_64()
        hdr.magic = MH_MAGIC_64
        hdr.cputype = CPU_TYPE_ARM64
        hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        hdr.filetype = UInt32(MH_EXECUTE)
        hdr.ncmds = UInt32(symtabCount)
        hdr.sizeofcmds = UInt32(symtabCount * MemoryLayout<symtab_command>.size)

        var bin = Data(bytes: &hdr, count: MemoryLayout<mach_header_64>.size)
        let nlistStart = MemoryLayout<mach_header_64>.size + Int(hdr.sizeofcmds)
        let nlistPerTabBytes = symsPerTab * MemoryLayout<nlist_64>.size
        let strOff = nlistStart + symtabCount * nlistPerTabBytes

        for t in 0..<symtabCount {
            var st = symtab_command()
            st.cmd = UInt32(LC_SYMTAB)
            st.cmdsize = UInt32(MemoryLayout<symtab_command>.size)
            st.symoff = UInt32(nlistStart + t * nlistPerTabBytes)
            st.nsyms = UInt32(symsPerTab)
            st.stroff = UInt32(strOff)
            st.strsize = UInt32(strSize)
            bin.append(Data(bytes: &st, count: MemoryLayout<symtab_command>.size))
        }

        // Distinct n_strx entries across all 8 symtabs
        var nlistBuf = Data()
        nlistBuf.reserveCapacity(symtabCount * nlistPerTabBytes)
        for t in 0..<symtabCount {
            for i in 0..<symsPerTab {
                var nl = nlist_64()
                nl.n_un.n_strx = UInt32(1 + (t * symsPerTab + i) * 16)
                withUnsafeBytes(of: &nl) { nlistBuf.append(contentsOf: $0) }
            }
        }
        bin.append(nlistBuf)
        // 8 MB NUL-free ASCII string table
        bin.append(Data(repeating: 0x41, count: strSize))

        let t0 = Date()
        let parsed = try MachOParser.parse(data: bin)
        _ = parsed.symbols
        let elapsed = Date().timeIntervalSince(t0)
        XCTAssertLessThan(elapsed, 0.5)
        XCTAssertEqual(parsed.symtabs.count, 8)
    }

    func test_channelClassifierAndIPAScanner_unverifiedProvisionTeamIdSpoofing_ProbeA_and_ProbeA2() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let root = state.rootCert
        let dir = try makeTempDir(prefix: "probe_a")

        let victimKeychainXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>application-identifier</key><string>VICTIM1234.com.evil.probe</string>
            <key>com.apple.developer.team-identifier</key><string>VICTIM1234</string>
            <key>keychain-access-groups</key><array><string>VICTIM1234.*</string></array>
        </dict></plist>
        """
        let victimProvPlist: [String: Any] = [
            "Name": "Spoofed Provision",
            "TeamIdentifier": ["VICTIM1234"],
            "ApplicationIdentifierPrefix": ["VICTIM1234"],
            "ProvisionedDevices": ["00008110-0000000000000001"]
        ]
        let rawXMLProv = try PropertyListSerialization.data(fromPropertyList: victimProvPlist, format: .xml, options: 0)
        // Dev-leaf CMS-signed profile (not Provisioning Profile Signing leaf / not trusted without matching root or non-Apple leaf)
        let (rogueCMSProv, _) = try M1TestCMSFixtures.buildCMSProvisioningProfile(plistDict: victimProvPlist, leaf: state.rogueLeaf)

        func buildSpoofedIPA(tag: String, mainEntitlements: String?, appexEntitlements: String?, fwEntitlements: String?, provData: Data?, appexProvData: Data?, bundleId: String = "com.evil.probe", teamId: String? = "VICTIM1234") throws -> URL {
            let subDir = dir.appendingPathComponent(tag)
            try FileManager.default.createDirectory(at: subDir, withIntermediateDirectories: true)
            let (mainBin, _) = try M1TestCMSFixtures.buildSignedMachO(
                identifier: bundleId,
                cryptid: 0,
                xmlEntitlements: mainEntitlements,
                teamIdentifier: teamId,
                signerLeaf: state.rogueLeaf
            )
            var items: [RawZIPItem] = [
                RawZIPItem(name: "Payload/Probe.app/Info.plist", data: try PropertyListSerialization.data(fromPropertyList: [
                    "CFBundleIdentifier": bundleId,
                    "CFBundleExecutable": "Probe",
                    "CFBundleName": "Probe"
                ], format: .xml, options: 0)),
                RawZIPItem(name: "Payload/Probe.app/Probe", data: mainBin, externalAttrs: UInt32(0o100755) << 16)
            ]
            if let provData {
                items.append(RawZIPItem(name: "Payload/Probe.app/embedded.mobileprovision", data: provData))
            }
            if let appexEntitlements {
                let (extBin, _) = try M1TestCMSFixtures.buildSignedMachO(
                    identifier: "\(bundleId).ext",
                    cryptid: 0,
                    xmlEntitlements: appexEntitlements,
                    teamIdentifier: teamId,
                    signerLeaf: state.rogueLeaf
                )
                items.append(RawZIPItem(name: "Payload/Probe.app/PlugIns/Ext.appex/Info.plist", data: try PropertyListSerialization.data(fromPropertyList: [
                    "CFBundleIdentifier": "\(bundleId).ext",
                    "CFBundleExecutable": "Ext",
                    "CFBundleName": "Ext"
                ], format: .xml, options: 0)))
                items.append(RawZIPItem(name: "Payload/Probe.app/PlugIns/Ext.appex/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16))
                if let appexProvData {
                    items.append(RawZIPItem(name: "Payload/Probe.app/PlugIns/Ext.appex/embedded.mobileprovision", data: appexProvData))
                }
            }
            if let fwEntitlements {
                let (fwBin, _) = try M1TestCMSFixtures.buildSignedMachO(
                    identifier: "\(bundleId).fw",
                    cryptid: 0,
                    xmlEntitlements: fwEntitlements,
                    teamIdentifier: teamId,
                    signerLeaf: state.rogueLeaf
                )
                items.append(RawZIPItem(name: "Payload/Probe.app/Frameworks/Evil.framework/Evil", data: fwBin, externalAttrs: UInt32(0o100755) << 16))
            }
            let ipaURL = subDir.appendingPathComponent("\(tag).ipa")
            try buildStoredRawZIP(items).write(to: ipaURL)
            return ipaURL
        }

        // ProbeA (raw unsigned XML) & ProbeA2 (untrusted/rogue-leaf CMS) on main, .appex, and Frameworks/
        for (label, prov) in [("xml_main", rawXMLProv), ("rogue_cms_main", rogueCMSProv)] {
            let ipa = try buildSpoofedIPA(tag: label, mainEntitlements: victimKeychainXML, appexEntitlements: nil, fwEntitlements: nil, provData: prov, appexProvData: nil)
            let f = try IPAPackageScanner.shared.scan(ipaURL: ipa, customAnchorCertificates: [root])
            XCTAssertEqual(f.riskTier, .highRisk, "\(label) must flag spoofed VICTIM1234.* wildcard")
            XCTAssertTrue(f.indicators.contains { $0.signature == "keychain-access-groups(*)" })
            XCTAssertFalse(f.evidence.isTeamIdWhitelistVerified)
        }

        for (label, prov) in [("xml_appex", rawXMLProv), ("rogue_cms_appex", rogueCMSProv)] {
            let ipa = try buildSpoofedIPA(tag: label, mainEntitlements: nil, appexEntitlements: victimKeychainXML, fwEntitlements: nil, provData: prov, appexProvData: prov)
            let f = try IPAPackageScanner.shared.scan(ipaURL: ipa, customAnchorCertificates: [root])
            XCTAssertEqual(f.riskTier, .highRisk, "\(label) must flag spoofed VICTIM1234.* wildcard in .appex")
            XCTAssertTrue(f.indicators.contains { $0.signature == "keychain-access-groups(*)" })
        }

        let fwIpa = try buildSpoofedIPA(tag: "xml_fw", mainEntitlements: nil, appexEntitlements: nil, fwEntitlements: victimKeychainXML, provData: rawXMLProv, appexProvData: nil)
        let fwFinding = try IPAPackageScanner.shared.scan(ipaURL: fwIpa, customAnchorCertificates: [root])
        XCTAssertEqual(fwFinding.riskTier, .highRisk)
        XCTAssertTrue(fwFinding.indicators.contains { $0.signature == "keychain-access-groups(*)" })

        // Whitelist Team ID spoofing test: custom rule requiring Team ID "VICTIM1234" must NOT whitelist unverified XML/rogue provision
        WhitelistEngine.shared.registerCustomTool(WhitelistedTool(
            name: "SpoofTargetTool",
            allowedBundleIds: ["com.victim.tool"],
            allowedAppGroups: [],
            allowedTeamIds: ["VICTIM1234"],
            expectedSignatures: ["keychain-access-groups(*)"],
            isBuiltIn: false
        ))
        let wlIpa = try buildSpoofedIPA(tag: "wl_spoof", mainEntitlements: victimKeychainXML, appexEntitlements: nil, fwEntitlements: nil, provData: rawXMLProv, appexProvData: nil, bundleId: "com.victim.tool")
        let wlFinding = try IPAPackageScanner.shared.scan(ipaURL: wlIpa, customAnchorCertificates: [root])
        XCTAssertFalse(wlFinding.evidence.isTeamIdWhitelistVerified)
        XCTAssertEqual(wlFinding.riskTier, .highRisk)
        WhitelistEngine.shared.resetToDefaults()
    }

    func test_channelClassifierAndIPAScanner_legacyAppIDPrefix_2C_vb_AppStoreAndCMSProvisioned_noFalsePositive() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "legacy_prefix_2cvb")

        let legacyWeiboEnts = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>com.apple.developer.team-identifier</key><string>NEWTEAM123</string>
            <key>application-identifier</key><string>LEGACY5678.com.sina.weibo</string>
            <key>keychain-access-groups</key><array>
                <string>LEGACY5678.*</string>
                <string>NEWTEAM123.*</string>
            </array>
            <key>beta-reports-active</key><true/>
        </dict></plist>
        """
        let provDict: [String: Any] = [
            "Name": "Weibo Legacy Prefix Distribution",
            "TeamIdentifier": ["NEWTEAM123"],
            "ApplicationIdentifierPrefix": ["LEGACY5678"],
            "BetaReportsActive": true
        ]

        // 1. TestFlight / App Store leaf with cryptid=1 + CMS-verified provision
        let (_, tfIPA, rootCert) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir.appendingPathComponent("tf"),
            appName: "WeiboTF",
            bundleId: "com.sina.weibo",
            cryptid: 1,
            xmlEntitlements: legacyWeiboEnts,
            signerLeaf: state.appStoreLeaf,
            teamIdentifier: "NEWTEAM123",
            provisionDict: provDict
        )
        let tfFinding = try IPAPackageScanner.shared.scan(ipaURL: tfIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(tfFinding.installChannel, .testFlight)
        XCTAssertEqual(tfFinding.riskTier, .safe)
        XCTAssertFalse(tfFinding.indicators.contains { $0.signature == "keychain-access-groups(*)" })

        // 2. CMS-provisioned non-App-Store leaf (cryptid=0) with valid Provisioning Profile Signing CMS
        let (_, devIPA, _) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir.appendingPathComponent("dev"),
            appName: "WeiboDev",
            bundleId: "com.sina.weibo",
            cryptid: 0,
            xmlEntitlements: legacyWeiboEnts,
            signerLeaf: state.rogueLeaf,
            teamIdentifier: "NEWTEAM123",
            provisionDict: [
                "Name": "Weibo Dev Profile",
                "TeamIdentifier": ["NEWTEAM123"],
                "ApplicationIdentifierPrefix": ["LEGACY5678"],
                "ProvisionedDevices": ["00008110-0000000000000002"]
            ]
        )
        let devFinding = try IPAPackageScanner.shared.scan(ipaURL: devIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(devFinding.riskTier, .safe)
        XCTAssertFalse(devFinding.indicators.contains { $0.signature == "keychain-access-groups(*)" })

        // 3. Negative control: rogue cross-team wildcard `ROGUE99999.*` -> .highRisk
        let rogueWeiboEnts = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>com.apple.developer.team-identifier</key><string>NEWTEAM123</string>
            <key>application-identifier</key><string>LEGACY5678.com.sina.weibo</string>
            <key>keychain-access-groups</key><array>
                <string>ROGUE99999.*</string>
            </array>
            <key>beta-reports-active</key><true/>
        </dict></plist>
        """
        let (_, rogueIPA, _) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir.appendingPathComponent("rogue"),
            appName: "WeiboRogue",
            bundleId: "com.sina.weibo",
            cryptid: 1,
            xmlEntitlements: rogueWeiboEnts,
            signerLeaf: state.appStoreLeaf,
            teamIdentifier: "NEWTEAM123",
            provisionDict: provDict
        )
        let rogueFinding = try IPAPackageScanner.shared.scan(ipaURL: rogueIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(rogueFinding.riskTier, .highRisk)
        XCTAssertTrue(rogueFinding.indicators.contains { $0.signature == "keychain-access-groups(*)" })
    }

    func test_ipaScanner_symlinkedAppex_archiveCodeResourcesLookup_sealedAndTampered() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "symlink_appex")

        func buildSymlinkedAppexIPA(tag: String, iconDiskBytes: Data, unsealedEvilJS: Data?) throws -> (ipaURL: URL, rootCert: SecCertificate) {
            let iconSealedBytes = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x01, 0x02, 0x03, 0x04])
            let extFilesMap: [String: Any] = [
                "icon.png": [
                    "hash": Data(Insecure.SHA1.hash(data: iconSealedBytes)),
                    "hash2": Data(SHA256.hash(data: iconSealedBytes))
                ]
            ]
            let extCRData = try PropertyListSerialization.data(
                fromPropertyList: ["files": extFilesMap, "files2": extFilesMap, "rules": [String: Any]()],
                format: .xml,
                options: 0
            )
            let extPlistData = try PropertyListSerialization.data(fromPropertyList: [
                "CFBundleIdentifier": "com.test.symappex.ext",
                "CFBundleExecutable": "RealExt",
                "CFBundleName": "RealExt"
            ], format: .xml, options: 0)
            let (extBin, rootCert) = try M1TestCMSFixtures.buildSignedMachO(
                identifier: "com.test.symappex.ext",
                cryptid: 1,
                infoPlistData: extPlistData,
                codeResourcesData: extCRData,
                signerLeaf: state.appStoreLeaf
            )

            let mainCRData = try PropertyListSerialization.data(
                fromPropertyList: ["files": [String: Any](), "files2": [String: Any](), "rules": [String: Any]()],
                format: .xml,
                options: 0
            )
            let mainPlistData = try PropertyListSerialization.data(fromPropertyList: [
                "CFBundleIdentifier": "com.test.symappex",
                "CFBundleExecutable": "SymApp",
                "CFBundleName": "SymApp"
            ], format: .xml, options: 0)
            let (mainBin, _) = try M1TestCMSFixtures.buildSignedMachO(
                identifier: "com.test.symappex",
                cryptid: 1,
                infoPlistData: mainPlistData,
                codeResourcesData: mainCRData,
                signerLeaf: state.appStoreLeaf
            )

            var items: [RawZIPItem] = [
                RawZIPItem(name: "Payload/SymApp.app/Info.plist", data: mainPlistData),
                RawZIPItem(name: "Payload/SymApp.app/SymApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
                RawZIPItem(name: "Payload/SymApp.app/_CodeSignature/CodeResources", data: mainCRData),
                RawZIPItem(name: "Payload/SymApp.app/Hidden/Real.appex/Info.plist", data: extPlistData),
                RawZIPItem(name: "Payload/SymApp.app/Hidden/Real.appex/RealExt", data: extBin, externalAttrs: UInt32(0o100755) << 16),
                RawZIPItem(name: "Payload/SymApp.app/Hidden/Real.appex/_CodeSignature/CodeResources", data: extCRData),
                RawZIPItem(name: "Payload/SymApp.app/Hidden/Real.appex/icon.png", data: iconDiskBytes),
                RawZIPItem(name: "Payload/SymApp.app/PlugIns/Alias.appex", data: Data("../Hidden/Real.appex".utf8), externalAttrs: UInt32(0o120755) << 16)
            ]
            if let unsealedEvilJS {
                items.append(RawZIPItem(name: "Payload/SymApp.app/Hidden/Real.appex/evil.js", data: unsealedEvilJS))
            }
            let ipaURL = dir.appendingPathComponent("\(tag).ipa")
            try buildStoredRawZIP(items).write(to: ipaURL)
            return (ipaURL, rootCert)
        }

        let cleanIcon = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x01, 0x02, 0x03, 0x04])
        let (cleanIPA, root) = try buildSymlinkedAppexIPA(tag: "clean_sym_appex", iconDiskBytes: cleanIcon, unsealedEvilJS: nil)
        let cleanFinding = try IPAPackageScanner.shared.scan(ipaURL: cleanIPA, customAnchorCertificates: [root])
        XCTAssertEqual(cleanFinding.installChannel, .appStore)
        XCTAssertEqual(cleanFinding.riskTier, .safe)

        let tamperedIcon = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xEE, 0xDD, 0xCC])
        let (tamperedIPA, _) = try buildSymlinkedAppexIPA(tag: "tampered_sym_appex", iconDiskBytes: tamperedIcon, unsealedEvilJS: nil)
        let tamperedFinding = try IPAPackageScanner.shared.scan(ipaURL: tamperedIPA, customAnchorCertificates: [root])
        XCTAssertEqual(tamperedFinding.installChannel, .developerSideloaded)

        let (evilJSIPA, _) = try buildSymlinkedAppexIPA(tag: "eviljs_sym_appex", iconDiskBytes: cleanIcon, unsealedEvilJS: Data("alert(1);".utf8))
        let evilJSFinding = try IPAPackageScanner.shared.scan(ipaURL: evilJSIPA, customAnchorCertificates: [root])
        XCTAssertEqual(evilJSFinding.installChannel, .developerSideloaded)
    }

    func test_csBlob_bundleCodeResourcesSeal_unsealedAssetsBundleEvilJS_caughtAndSealedPasses() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "assets_bundle_seal")
        let cleanJS = Data("console.log('clean');".utf8)
        let evilJS = Data("console.log('pwned');".utf8)

        // 1. Sealed Assets.bundle/clean.js -> .appStore / .safe
        let (sealedBundle, sealedIPA, rootCert) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir.appendingPathComponent("sealed"),
            appName: "SealedBundleApp",
            bundleId: "com.test.sealedbundle",
            cryptid: 1,
            signerLeaf: state.appStoreLeaf,
            extraAssets: ["Assets.bundle/clean.js": cleanJS]
        )
        let sealedSlices = try MachOParser.parseAllSlices(data: try Data(contentsOf: sealedBundle.appendingPathComponent("SealedBundleApp")))
        XCTAssertNil(CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: sealedSlices, bundleURL: sealedBundle))
        let sealedIPAFinding = try IPAPackageScanner.shared.scan(ipaURL: sealedIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(sealedIPAFinding.installChannel, .appStore)
        XCTAssertEqual(sealedIPAFinding.riskTier, .safe)

        // 2. Unsealed Assets.bundle/evil.js -> caught (`CodeDirectory/CodeResources Mismatch` -> .developerSideloaded)
        let (unsealedBundle, unsealedIPA, _) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir.appendingPathComponent("unsealed"),
            appName: "UnsealedBundleApp",
            bundleId: "com.test.unsealedbundle",
            cryptid: 1,
            signerLeaf: state.appStoreLeaf,
            extraAssets: ["Assets.bundle/clean.js": cleanJS],
            unsealedExtraAssets: ["Assets.bundle/evil.js": evilJS]
        )
        let unsealedSlices = try MachOParser.parseAllSlices(data: try Data(contentsOf: unsealedBundle.appendingPathComponent("UnsealedBundleApp")))
        let sealFailure = CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: unsealedSlices, bundleURL: unsealedBundle)
        XCTAssertNotNil(sealFailure)
        let unsealedIPAFinding = try IPAPackageScanner.shared.scan(ipaURL: unsealedIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(unsealedIPAFinding.installChannel, .developerSideloaded)
    }

    // MARK: 7. Iteration 3 Remediation Regression Tests

    func test_machoParser_forgedFairPlay_V1e_singlePageMixedCSPRNG_and_2MBOddPagePlaintext_detected() throws {
        // 1. V1e-i: Single 4096-byte FairPlay range mixing small plaintext sections (__text, __objc_methname, __info_plist)
        //    with ~3.8 KB of CSPRNG bytes in __const.
        let plistData = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "com.evil.mixed",
                "UIBackgroundModes": ["voip"]
            ],
            format: .xml,
            options: 0
        )
        let methPayload = Data("systemPhotoLibrary\0bundleWithPath:\0".utf8)
        let csprngConst = M1TestCMSFixtures.csprngBytes(count: 3846)

        var v1eiBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 4096,
            textInstructions: [0xD400_1001, 0xD65F_03C0],
            customSections: [
                (segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: methPayload),
                (segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: plistData),
                (segName: "__TEXT", sectName: "__const", flags: 0, payload: csprngConst)
            ]
        ))
        // Patch LC_ENCRYPTION_INFO_64 to cover exactly [textOff, textOff + 4096) spanning all 4 sections
        let preV1ei = try MachOParser.parse(data: v1eiBin)
        let textOff1 = try XCTUnwrap(preV1ei.textSegment?.sections.first { $0.sectionName == "__text" }?.offset)
        let ncmds1 = v1eiBin.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
        var cur1 = MemoryLayout<mach_header_64>.size
        for _ in 0..<ncmds1 {
            let cmd = v1eiBin.withUnsafeBytes { $0.load(fromByteOffset: cur1, as: UInt32.self).littleEndian }
            let csz = v1eiBin.withUnsafeBytes { $0.load(fromByteOffset: cur1 + 4, as: UInt32.self).littleEndian }
            if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                var offLE = textOff1.littleEndian
                var szLE = UInt32(4096).littleEndian
                withUnsafeBytes(of: &offLE) { v1eiBin.replaceSubrange((cur1 + 8)..<(cur1 + 12), with: $0) }
                withUnsafeBytes(of: &szLE) { v1eiBin.replaceSubrange((cur1 + 12)..<(cur1 + 16), with: $0) }
                break
            }
            cur1 += Int(csz)
        }
        let parsedV1ei = try MachOParser.parse(data: v1eiBin)
        XCTAssertTrue(parsedV1ei.hasForgedPlaintextFairPlayRange, "V1e-i mixed 4KB page must be detected as forged plaintext")
        XCTAssertEqual(parsedV1ei.scanDirectSyscalls().totalCount, 1)
        XCTAssertTrue(parsedV1ei.objcMethodNames.contains("systemPhotoLibrary"))
        XCTAssertEqual(parsedV1ei.embeddedInfoPlist?["CFBundleIdentifier"] as? String, "com.evil.mixed")

        let dir = try makeTempDir(prefix: "v1e_regression")
        let v1eiURL = dir.appendingPathComponent("v1ei_bin")
        try v1eiBin.write(to: v1eiURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: v1eiURL).riskTier, .highRisk)

        // 2. V1e-ii: 2 MB (512 pages) FairPlay range with CSPRNG on even pages (0, 2, 4, ...)
        //    and plaintext svc #0x80 on odd page 1 (lo + 4096) + plaintext selector on odd page 3 (lo + 12288)
        let twoMB = 2 * 1024 * 1024
        var text2MB = M1TestCMSFixtures.csprngBytes(count: 16_384)
        var oddSvcPage = Data()
        oddSvcPage.reserveCapacity(4096)
        var svcLE = UInt32(0xD400_1001).littleEndian
        let svcWord = withUnsafeBytes(of: &svcLE) { Data($0) }
        for _ in 0..<1024 { oddSvcPage.append(svcWord) }
        text2MB.replaceSubrange(4096..<8192, with: oddSvcPage)

        var meth2MB = M1TestCMSFixtures.csprngBytes(count: twoMB - 16_384)
        // Odd page 3 relative to lo (= textOff2) starts at 12288 in total; inside meth2MB that's offset 0..4096 if text2MB is 16384?
        // Wait: text2MB is 16384 bytes (pages 0..3), so lo + 12288 is inside page 3 of text2MB, or put selector in page 1 of meth2MB (which is odd page 5 of [lo, hi)).
        // Let's put plaintext selector at an odd page offset inside meth2MB aligned to page boundary!
        let selBytes = Data("\0systemPhotoLibrary\0bundleWithPath:\0".utf8)
        meth2MB.replaceSubrange(4096..<(4096 + selBytes.count), with: selBytes)

        var textWords2MB: [UInt32] = []
        textWords2MB.reserveCapacity(text2MB.count / 4)
        text2MB.withUnsafeBytes { raw in
            for i in stride(from: 0, to: text2MB.count, by: 4) {
                textWords2MB.append(raw.loadUnaligned(fromByteOffset: i, as: UInt32.self).littleEndian)
            }
        }
        var v1eiiBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: UInt32(twoMB),
            textInstructions: textWords2MB,
            customSections: [
                (segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: meth2MB)
            ]
        ))
        let preV1eii = try MachOParser.parse(data: v1eiiBin)
        let textOff2 = try XCTUnwrap(preV1eii.textSegment?.sections.first { $0.sectionName == "__text" }?.offset)
        let ncmds2 = v1eiiBin.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
        var cur2 = MemoryLayout<mach_header_64>.size
        for _ in 0..<ncmds2 {
            let cmd = v1eiiBin.withUnsafeBytes { $0.load(fromByteOffset: cur2, as: UInt32.self).littleEndian }
            let csz = v1eiiBin.withUnsafeBytes { $0.load(fromByteOffset: cur2 + 4, as: UInt32.self).littleEndian }
            if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                var offLE = textOff2.littleEndian
                var szLE = UInt32(twoMB).littleEndian
                withUnsafeBytes(of: &offLE) { v1eiiBin.replaceSubrange((cur2 + 8)..<(cur2 + 12), with: $0) }
                withUnsafeBytes(of: &szLE) { v1eiiBin.replaceSubrange((cur2 + 12)..<(cur2 + 16), with: $0) }
                break
            }
            cur2 += Int(csz)
        }
        let parsedV1eii = try MachOParser.parse(data: v1eiiBin)
        XCTAssertTrue(parsedV1eii.hasForgedPlaintextFairPlayRange, "V1e-ii odd-page 2MB plaintext must be detected")
        XCTAssertEqual(parsedV1eii.scanDirectSyscalls().totalCount, 1024)
        XCTAssertTrue(parsedV1eii.objcMethodNames.contains("systemPhotoLibrary"))
        let v1eiiURL = dir.appendingPathComponent("v1eii_bin")
        try v1eiiBin.write(to: v1eiiURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: v1eiiURL).riskTier, .highRisk)

        // 3. Negative control: genuine 2 MB pure CSPRNG range -> hasForgedPlaintextFairPlayRange == false
        var clean2MB = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: UInt32(twoMB),
            customSections: [
                (segName: "__TEXT", sectName: "__csprng", flags: 0, payload: M1TestCMSFixtures.csprngBytes(count: twoMB))
            ]
        ))
        let preClean2MB = try MachOParser.parse(data: clean2MB)
        let csOff2 = try XCTUnwrap(preClean2MB.segments.flatMap(\.sections).first { $0.sectionName == "__csprng" }?.offset)
        var cur3 = MemoryLayout<mach_header_64>.size
        let ncmds3 = clean2MB.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
        for _ in 0..<ncmds3 {
            let cmd = clean2MB.withUnsafeBytes { $0.load(fromByteOffset: cur3, as: UInt32.self).littleEndian }
            let csz = clean2MB.withUnsafeBytes { $0.load(fromByteOffset: cur3 + 4, as: UInt32.self).littleEndian }
            if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                var offLE = csOff2.littleEndian
                var szLE = UInt32(twoMB).littleEndian
                withUnsafeBytes(of: &offLE) { clean2MB.replaceSubrange((cur3 + 8)..<(cur3 + 12), with: $0) }
                withUnsafeBytes(of: &szLE) { clean2MB.replaceSubrange((cur3 + 12)..<(cur3 + 16), with: $0) }
                break
            }
            cur3 += Int(csz)
        }
        let parsedClean2MB = try MachOParser.parse(data: clean2MB)
        XCTAssertFalse(parsedClean2MB.hasForgedPlaintextFairPlayRange)
    }

    func test_machoParser_embeddedInfoPlist_V6e2f_decoyPrefixesAndLargeDecoysDoNotBlindRealPlist() throws {
        let evilPlistData = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "io.metamask.fake",
                "UIBackgroundModes": ["voip", "audio"]
            ],
            format: .xml,
            options: 0
        )

        // 1. V6e2-f: 32 x "<bad0/>" + 32 x "<plist><bad/></plist>" before real malicious __info_plist
        var customF: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
        for i in 0..<32 {
            customF.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: Data("<bad\(i)/>".utf8)))
        }
        for i in 0..<32 {
            customF.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: Data("<plist><bad\(i)/></plist>".utf8)))
        }
        customF.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: evilPlistData))

        let binF = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: customF
        ))
        let parsedF = try MachOParser.parse(data: binF)
        XCTAssertEqual(parsedF.embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.fake")

        let dir = try makeTempDir(prefix: "v6e2f_regression")
        let binFURL = dir.appendingPathComponent("v6e2f_bin")
        try binF.write(to: binFURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: binFURL).riskTier, .highRisk)

        // 2. V6e2-f2: 4 x 4 MB '<'-filled and 4 x 4 MB '<plist>' + '<'-filled decoys before real malicious __info_plist
        let fourMB = 4 * 1024 * 1024
        let lt4MB = Data(repeating: 0x3C, count: fourMB)
        var plistLt4MB = Data("<plist>".utf8)
        plistLt4MB.append(Data(repeating: 0x3C, count: fourMB - plistLt4MB.count))

        var customF2: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
        for _ in 0..<4 {
            customF2.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: lt4MB))
        }
        for _ in 0..<4 {
            customF2.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: plistLt4MB))
        }
        customF2.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: evilPlistData))

        let binF2 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: customF2
        ))
        let t0 = Date()
        let parsedF2 = try MachOParser.parse(data: binF2)
        let extracted = parsedF2.embeddedInfoPlist
        XCTAssertLessThan(Date().timeIntervalSince(t0), 0.5)
        XCTAssertEqual(extracted?["CFBundleIdentifier"] as? String, "io.metamask.fake")

        // 3. V6e2-g: UTF-16BE, binary bplist00, leading NUL + whitespace XML
        let xmlString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.test.utf16</string></dict></plist>"
        let utf16BE = try XCTUnwrap(xmlString.data(using: .utf16BigEndian))
        let bplist = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "com.test.bplist"], format: .binary, options: 0)
        var wsNul = Data([0x00, 0x00, 0x20, 0x09, 0x0A])
        wsNul.append(evilPlistData)

        for (expectedBid, rawPlist) in [("com.test.utf16", utf16BE), ("com.test.bplist", bplist), ("io.metamask.fake", wsNul)] {
            let b = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 0,
                customSections: [(segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: rawPlist)]
            ))
            let p = try MachOParser.parse(data: b)
            XCTAssertEqual(p.embeddedInfoPlist?["CFBundleIdentifier"] as? String, expectedBid)
        }
    }

    func test_machoParser_objcMethodNames_V6c_middleGapDecoyShadowing_and_64MiB_140MiB_timing() throws {
        let padChunk = Data("padSelector_\0".utf8)

        // 1. V6c-c: 64 x 599-byte decoy strings containing "systemPhotoLibrary" at 25 MiB + real "systemPhotoLibrary\0"
        var meth64Decoy = Data()
        meth64Decoy.reserveCapacity(35 * 1024 * 1024)
        while meth64Decoy.count < 25 * 1024 * 1024 {
            meth64Decoy.append(padChunk)
        }
        let decoy599 = String(repeating: "x", count: 581) + "systemPhotoLibrary"
        XCTAssertEqual(decoy599.utf8.count, 599)
        for _ in 0..<64 {
            meth64Decoy.append(Data((decoy599 + "\0").utf8))
        }
        meth64Decoy.append(Data("systemPhotoLibrary\0".utf8))
        while meth64Decoy.count < 35 * 1024 * 1024 {
            meth64Decoy.append(padChunk)
        }
        let binC = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: meth64Decoy)]
        ))
        let parsedC = try MachOParser.parse(data: binC)
        XCTAssertTrue(parsedC.objcMethodNames.contains("systemPhotoLibrary"))

        // 2. V6c-c2: single 1,152-byte C-string "systemPhotoLibrary" * 64 + "\0" at 25 MiB + real "systemPhotoLibrary\0"
        var meth1152 = Data()
        meth1152.reserveCapacity(35 * 1024 * 1024)
        while meth1152.count < 25 * 1024 * 1024 {
            meth1152.append(padChunk)
        }
        meth1152.append(Data((String(repeating: "systemPhotoLibrary", count: 64) + "\0").utf8))
        meth1152.append(Data("systemPhotoLibrary\0".utf8))
        while meth1152.count < 35 * 1024 * 1024 {
            meth1152.append(padChunk)
        }
        let binC2 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: meth1152)]
        ))
        let parsedC2 = try MachOParser.parse(data: binC2)
        XCTAssertTrue(parsedC2.objcMethodNames.contains("systemPhotoLibrary"))

        // 3. V6c-d: 64 MiB and 140 MiB __objc_methname timing (< 1.5s each in -Onone)
        for (totalMiB, midOffsetMiB) in [(64, 40), (140, 80)] {
            var bigMeth = Data()
            bigMeth.reserveCapacity(totalMiB * 1024 * 1024 + 4096)
            while bigMeth.count < midOffsetMiB * 1024 * 1024 {
                bigMeth.append(padChunk)
            }
            bigMeth.append(Data("systemPhotoLibrary\0".utf8))
            while bigMeth.count < totalMiB * 1024 * 1024 - 4096 {
                bigMeth.append(padChunk)
            }
            bigMeth.append(Data("bundleWithPath:\0".utf8))

            let binBig = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 0,
                customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: bigMeth)]
            ))
            let parsedBig = try MachOParser.parse(data: binBig)
            let t0 = Date()
            let sels = Set(parsedBig.objcMethodNames)
            let elapsed = Date().timeIntervalSince(t0)
            XCTAssertLessThan(elapsed, 1.5, "\(totalMiB) MiB objcMethodNames took \(elapsed)s (must be < 1.5s)")
            XCTAssertTrue(sels.contains("systemPhotoLibrary"))
            XCTAssertTrue(sels.contains("bundleWithPath:"))
        }
    }

    func test_ipaScanner_nestedBundleCodeResources_RealSignedFramework_and_DecoyBundles_caught() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "nested_cr_bypass")
        let cleanJS = Data("console.log('clean');".utf8)
        let evilJS = Data("console.log('evil');".utf8)

        let mainCRData = try PropertyListSerialization.data(
            fromPropertyList: ["files": [String: Any](), "files2": [String: Any](), "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let mainPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.nestedcr",
            "CFBundleExecutable": "MainApp",
            "CFBundleName": "MainApp"
        ], format: .xml, options: 0)
        let (mainBin, rootCert) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.nestedcr",
            cryptid: 1,
            infoPlistData: mainPlistData,
            codeResourcesData: mainCRData,
            signerLeaf: state.appStoreLeaf
        )

        let fwFilesMap: [String: Any] = [
            "clean.js": [
                "hash": Data(Insecure.SHA1.hash(data: cleanJS)),
                "hash2": Data(SHA256.hash(data: cleanJS))
            ]
        ]
        let fwCRData = try PropertyListSerialization.data(
            fromPropertyList: ["files": fwFilesMap, "files2": fwFilesMap, "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let fwPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.realfw",
            "CFBundleExecutable": "Real",
            "CFBundleName": "Real"
        ], format: .xml, options: 0)
        let (fwBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.realfw",
            cryptid: 1,
            infoPlistData: fwPlistData,
            codeResourcesData: fwCRData,
            signerLeaf: state.appStoreLeaf
        )

        // 1. Clean RealSignedFramework passes as .appStore / .safe
        let cleanFwItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: mainCRData),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/Real.framework/Info.plist", data: fwPlistData),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/Real.framework/Real", data: fwBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/Real.framework/_CodeSignature/CodeResources", data: fwCRData),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/Real.framework/clean.js", data: cleanJS)
        ]
        let cleanFwIPA = dir.appendingPathComponent("clean_fw.ipa")
        try buildStoredRawZIP(cleanFwItems).write(to: cleanFwIPA)
        let cleanFwFinding = try IPAPackageScanner.shared.scan(ipaURL: cleanFwIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(cleanFwFinding.installChannel, .appStore)
        XCTAssertEqual(cleanFwFinding.riskTier, .safe)

        // 2. RealSignedFramework with unsealed evil.js MUST be caught (.developerSideloaded)
        var evilFwItems = cleanFwItems
        evilFwItems.append(RawZIPItem(name: "Payload/MainApp.app/Frameworks/Real.framework/evil.js", data: evilJS))
        let evilFwIPA = dir.appendingPathComponent("evil_fw.ipa")
        try buildStoredRawZIP(evilFwItems).write(to: evilFwIPA)
        let evilFwFinding = try IPAPackageScanner.shared.scan(ipaURL: evilFwIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(evilFwFinding.installChannel, .developerSideloaded)

        // 3. Decoy.{appex,xpc,app,framework}/evil.js without CodeResources MUST be caught
        for ext in ["appex", "xpc", "app", "framework"] {
            let decoyItems: [RawZIPItem] = [
                RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
                RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
                RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: mainCRData),
                RawZIPItem(name: "Payload/MainApp.app/Decoy.\(ext)/evil.js", data: evilJS)
            ]
            let decoyIPA = dir.appendingPathComponent("decoy_\(ext).ipa")
            try buildStoredRawZIP(decoyItems).write(to: decoyIPA)
            let decoyFinding = try IPAPackageScanner.shared.scan(ipaURL: decoyIPA, customAnchorCertificates: [rootCert])
            XCTAssertEqual(decoyFinding.installChannel, .developerSideloaded, "Decoy.\(ext)/evil.js must be caught")
        }

        // 4. Decoy.appex with fake CodeResources (no Mach-O sealing it) + evil.js MUST be caught
        let fakeDecoyItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: mainCRData),
            RawZIPItem(name: "Payload/MainApp.app/Decoy.appex/_CodeSignature/CodeResources", data: fwCRData),
            RawZIPItem(name: "Payload/MainApp.app/Decoy.appex/evil.js", data: evilJS)
        ]
        let fakeDecoyIPA = dir.appendingPathComponent("fake_cr_decoy.ipa")
        try buildStoredRawZIP(fakeDecoyItems).write(to: fakeDecoyIPA)
        let fakeDecoyFinding = try IPAPackageScanner.shared.scan(ipaURL: fakeDecoyIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(fakeDecoyFinding.installChannel, .developerSideloaded)

        // 5. Info.plist-less .appex with signed Mach-O + CodeResources + unsealed evil.js MUST be caught
        let (noPlistBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.noplist",
            cryptid: 1,
            codeResourcesData: fwCRData,
            signerLeaf: state.appStoreLeaf
        )
        let noPlistItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: mainCRData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/NoPlist.appex/NoPlist", data: noPlistBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/NoPlist.appex/_CodeSignature/CodeResources", data: fwCRData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/NoPlist.appex/clean.js", data: cleanJS),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/NoPlist.appex/evil.js", data: evilJS)
        ]
        let noPlistIPA = dir.appendingPathComponent("noplist_appex.ipa")
        try buildStoredRawZIP(noPlistItems).write(to: noPlistIPA)
        let noPlistFinding = try IPAPackageScanner.shared.scan(ipaURL: noPlistIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(noPlistFinding.installChannel, .developerSideloaded)
    }

    // MARK: 8. Iteration 4 Remediation Regression Tests

    func test_codeResources_contentsAndVersionsALayouts_unsealedEvilCaught_and_35NonMachOFiles_and_versionsCurrentSymlinkCleanPass() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "r4_layout_regression")
        let cleanJS = Data("console.log('clean');".utf8)
        let evilJS = Data("console.log('evil');".utf8)

        let emptyCR = try PropertyListSerialization.data(
            fromPropertyList: ["files": [String: Any](), "files2": [String: Any](), "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let mainPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r4layout",
            "CFBundleExecutable": "MainApp",
            "CFBundleName": "MainApp"
        ], format: .xml, options: 0)
        let (mainBin, rootCert) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r4layout",
            cryptid: 1,
            infoPlistData: mainPlistData,
            codeResourcesData: emptyCR,
            signerLeaf: state.appStoreLeaf
        )

        // 1. MainApp with Contents/_CodeSignature/CodeResources + unsealed evil.js MUST be caught (.developerSideloaded)
        let mainContentsItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/Contents/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/evil.js", data: evilJS)
        ]
        let mainContentsIPA = dir.appendingPathComponent("main_contents_evil.ipa")
        try buildStoredRawZIP(mainContentsItems).write(to: mainContentsIPA)
        let mainContentsFinding = try IPAPackageScanner.shared.scan(ipaURL: mainContentsIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(mainContentsFinding.installChannel, .developerSideloaded, "MainApp Contents/_CodeSignature/CodeResources must catch root evil.js")

        // 2. Nested .appex with Contents/_CodeSignature/CodeResources + evil.js (root or Contents/Resources/evil.js) MUST be caught
        let extCRFiles: [String: Any] = [
            "Resources/clean.js": [
                "hash": Data(Insecure.SHA1.hash(data: cleanJS)),
                "hash2": Data(SHA256.hash(data: cleanJS))
            ]
        ]
        let extCRData = try PropertyListSerialization.data(
            fromPropertyList: ["files": extCRFiles, "files2": extCRFiles, "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let extPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r4layout.macext",
            "CFBundleExecutable": "MacExt",
            "CFBundleName": "MacExt"
        ], format: .xml, options: 0)
        let (extBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r4layout.macext",
            cryptid: 1,
            infoPlistData: extPlistData,
            codeResourcesData: extCRData,
            signerLeaf: state.appStoreLeaf
        )
        for badRel in ["PlugIns/MacExt.appex/evil.js", "PlugIns/MacExt.appex/Contents/Resources/evil.js"] {
            let extEvilItems: [RawZIPItem] = [
                RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
                RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
                RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
                RawZIPItem(name: "Payload/MainApp.app/PlugIns/MacExt.appex/Contents/Info.plist", data: extPlistData),
                RawZIPItem(name: "Payload/MainApp.app/PlugIns/MacExt.appex/Contents/MacOS/MacExt", data: extBin, externalAttrs: UInt32(0o100755) << 16),
                RawZIPItem(name: "Payload/MainApp.app/PlugIns/MacExt.appex/Contents/_CodeSignature/CodeResources", data: extCRData),
                RawZIPItem(name: "Payload/MainApp.app/PlugIns/MacExt.appex/Contents/Resources/clean.js", data: cleanJS),
                RawZIPItem(name: "Payload/MainApp.app/\(badRel)", data: evilJS)
            ]
            let extEvilIPA = dir.appendingPathComponent("ext_\(badRel.replacingOccurrences(of: "/", with: "_")).ipa")
            try buildStoredRawZIP(extEvilItems).write(to: extEvilIPA)
            let extEvilFinding = try IPAPackageScanner.shared.scan(ipaURL: extEvilIPA, customAnchorCertificates: [rootCert])
            XCTAssertEqual(extEvilFinding.installChannel, .developerSideloaded, "Nested .appex Contents layout must catch \(badRel)")
        }

        // 3. Framework with Versions/A/_CodeSignature/CodeResources:
        //    (a) Clean Versions/A + Versions/Current -> A symlink + Resources/clean.js MUST pass (.appStore / .safe)
        let fwCRFiles: [String: Any] = [
            "Resources/clean.js": [
                "hash": Data(Insecure.SHA1.hash(data: cleanJS)),
                "hash2": Data(SHA256.hash(data: cleanJS))
            ]
        ]
        let fwCRData = try PropertyListSerialization.data(
            fromPropertyList: ["files": fwCRFiles, "files2": fwCRFiles, "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let fwPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r4layout.macfw",
            "CFBundleExecutable": "MacFw",
            "CFBundleName": "MacFw"
        ], format: .xml, options: 0)
        let (fwBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r4layout.macfw",
            cryptid: 1,
            infoPlistData: fwPlistData,
            codeResourcesData: fwCRData,
            signerLeaf: state.appStoreLeaf
        )
        let cleanVersionsItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/A/Resources/Info.plist", data: fwPlistData),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/A/MacFw", data: fwBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/A/_CodeSignature/CodeResources", data: fwCRData),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/A/Resources/clean.js", data: cleanJS),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/Current", data: Data("A".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/MacFw", data: Data("Versions/Current/MacFw".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let cleanVersionsIPA = dir.appendingPathComponent("clean_versions_current_fw.ipa")
        try buildStoredRawZIP(cleanVersionsItems).write(to: cleanVersionsIPA)
        let cleanVersionsFinding = try IPAPackageScanner.shared.scan(ipaURL: cleanVersionsIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(cleanVersionsFinding.installChannel, .appStore, "Clean Versions/A + Versions/Current -> A framework must pass")
        XCTAssertEqual(cleanVersionsFinding.riskTier, .safe)

        //    (b) Versions/A framework with unsealed evil.js at root or Versions/A/evil.js MUST be caught
        for badRel in [
            "Frameworks/MacFw.framework/evil.js",
            "Frameworks/MacFw.framework/Versions/A/evil.js"
        ] {
            var badVersionsItems = cleanVersionsItems
            badVersionsItems.append(RawZIPItem(name: "Payload/MainApp.app/\(badRel)", data: evilJS))
            let badVersionsIPA = dir.appendingPathComponent("bad_\(badRel.replacingOccurrences(of: "/", with: "_")).ipa")
            try buildStoredRawZIP(badVersionsItems).write(to: badVersionsIPA)
            let badVersionsFinding = try IPAPackageScanner.shared.scan(ipaURL: badVersionsIPA, customAnchorCertificates: [rootCert])
            XCTAssertEqual(badVersionsFinding.installChannel, .developerSideloaded, "Versions/A framework must catch \(badRel)")
        }

        // 4. Clean signed .framework with 35 alphabetically earlier non-Mach-O JSON files (00_cfg.json..34_cfg.json before Zebra) MUST pass
        var zebraMap: [String: Any] = [
            "Zebra.js": [
                "hash": Data(Insecure.SHA1.hash(data: cleanJS)),
                "hash2": Data(SHA256.hash(data: cleanJS))
            ]
        ]
        var zebraItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR)
        ]
        for idx in 0..<35 {
            let cfgName = String(format: "%02d_cfg.json", idx)
            let cfgData = Data("{\"id\":\(idx)}".utf8)
            zebraMap[cfgName] = [
                "hash": Data(Insecure.SHA1.hash(data: cfgData)),
                "hash2": Data(SHA256.hash(data: cfgData))
            ]
            zebraItems.append(RawZIPItem(name: "Payload/MainApp.app/Frameworks/Zebra.framework/\(cfgName)", data: cfgData))
        }
        let zebraCRData = try PropertyListSerialization.data(
            fromPropertyList: ["files": zebraMap, "files2": zebraMap, "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let zebraPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r4layout.zebra",
            "CFBundleExecutable": "Zebra",
            "CFBundleName": "Zebra"
        ], format: .xml, options: 0)
        let (zebraBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r4layout.zebra",
            cryptid: 1,
            infoPlistData: zebraPlistData,
            codeResourcesData: zebraCRData,
            signerLeaf: state.appStoreLeaf
        )
        zebraItems.append(RawZIPItem(name: "Payload/MainApp.app/Frameworks/Zebra.framework/Info.plist", data: zebraPlistData))
        zebraItems.append(RawZIPItem(name: "Payload/MainApp.app/Frameworks/Zebra.framework/Zebra", data: zebraBin, externalAttrs: UInt32(0o100755) << 16))
        zebraItems.append(RawZIPItem(name: "Payload/MainApp.app/Frameworks/Zebra.framework/_CodeSignature/CodeResources", data: zebraCRData))
        zebraItems.append(RawZIPItem(name: "Payload/MainApp.app/Frameworks/Zebra.framework/Zebra.js", data: cleanJS))

        let zebraIPA = dir.appendingPathComponent("zebra_35_json.ipa")
        try buildStoredRawZIP(zebraItems).write(to: zebraIPA)
        let zebraFinding = try IPAPackageScanner.shared.scan(ipaURL: zebraIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(zebraFinding.installChannel, .appStore, "Clean framework with 35+ non-Mach-O files sorting before executable must pass")
        XCTAssertEqual(zebraFinding.riskTier, .safe)
    }

    func test_machoParser_forgedFairPlay_R4_256BCSPRNG_negativeControl_and_B1_B2_B3_B4b_B5b_detected() throws {
        let dir = try makeTempDir(prefix: "r4_fairplay_regression")

        func patchEncryptionRange(_ bin: inout Data, offset: UInt32, size: UInt32) {
            let ncmds = bin.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
            var cur = MemoryLayout<mach_header_64>.size
            for _ in 0..<ncmds {
                let cmd = bin.withUnsafeBytes { $0.load(fromByteOffset: cur, as: UInt32.self).littleEndian }
                let csz = bin.withUnsafeBytes { $0.load(fromByteOffset: cur + 4, as: UInt32.self).littleEndian }
                if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                    var offLE = offset.littleEndian
                    var szLE = size.littleEndian
                    withUnsafeBytes(of: &offLE) { bin.replaceSubrange((cur + 8)..<(cur + 12), with: $0) }
                    withUnsafeBytes(of: &szLE) { bin.replaceSubrange((cur + 12)..<(cur + 16), with: $0) }
                    return
                }
                cur += Int(csz)
            }
        }

        // 1. FP-2a/c/d: 256B pure CSPRNG range and 4 KB range with 256B CSPRNG __stubs / __objc_methname (20 trials -> 0/20 forged)
        var fp2aForged = 0
        var fp2cForged = 0
        var fp2dForged = 0
        for _ in 0..<20 {
            var b256 = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 0,
                cryptsize: 256,
                customSections: [(segName: "__TEXT", sectName: "__csprng", flags: 0, payload: M1TestCMSFixtures.csprngBytes(count: 256))]
            ))
            let p256 = try MachOParser.parse(data: b256)
            let off256 = try XCTUnwrap(p256.segments.flatMap(\.sections).first { $0.sectionName == "__csprng" }?.offset)
            patchEncryptionRange(&b256, offset: off256, size: 256)
            if try MachOParser.parse(data: b256).hasForgedPlaintextFairPlayRange { fp2aForged += 1 }

            var bStubs = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 0,
                cryptsize: 4096,
                customSections: [
                    (segName: "__TEXT", sectName: "__stubs", flags: UInt32(S_ATTR_PURE_INSTRUCTIONS), payload: M1TestCMSFixtures.csprngBytes(count: 256)),
                    (segName: "__TEXT", sectName: "__const", flags: 0, payload: M1TestCMSFixtures.csprngBytes(count: 3840))
                ]
            ))
            let pStubs = try MachOParser.parse(data: bStubs)
            let offStubs = try XCTUnwrap(pStubs.segments.flatMap(\.sections).first { $0.sectionName == "__stubs" }?.offset)
            patchEncryptionRange(&bStubs, offset: offStubs, size: 4096)
            if try MachOParser.parse(data: bStubs).hasForgedPlaintextFairPlayRange { fp2cForged += 1 }

            var bMeth = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 0,
                cryptsize: 4096,
                customSections: [
                    (segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: M1TestCMSFixtures.csprngBytes(count: 256)),
                    (segName: "__TEXT", sectName: "__const", flags: 0, payload: M1TestCMSFixtures.csprngBytes(count: 3840))
                ]
            ))
            let pMeth = try MachOParser.parse(data: bMeth)
            let offMeth = try XCTUnwrap(pMeth.segments.flatMap(\.sections).first { $0.sectionName == "__objc_methname" }?.offset)
            patchEncryptionRange(&bMeth, offset: offMeth, size: 4096)
            if try MachOParser.parse(data: bMeth).hasForgedPlaintextFairPlayRange { fp2dForged += 1 }
        }
        XCTAssertEqual(fp2aForged, 0, "FP-2a: 256B pure CSPRNG must yield 0/20 forged")
        XCTAssertEqual(fp2cForged, 0, "FP-2c: 4KB with 256B CSPRNG __stubs must yield 0/20 forged")
        XCTAssertEqual(fp2dForged, 0, "FP-2d: 4KB with 256B CSPRNG __objc_methname must yield 0/20 forged")

        // 2. B-1: __TEXT,__myevil (flags = 0) with 16 x svc #0x80 + 4032B CSPRNG in 4 KB FairPlay range
        var myEvilPayload = Data()
        for _ in 0..<16 {
            var w = UInt32(0xD400_1001).littleEndian
            withUnsafeBytes(of: &w) { myEvilPayload.append(contentsOf: $0) }
        }
        var b1 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 4096,
            customSections: [
                (segName: "__TEXT", sectName: "__myevil", flags: 0, payload: myEvilPayload),
                (segName: "__TEXT", sectName: "__const", flags: 0, payload: M1TestCMSFixtures.csprngBytes(count: 4032))
            ]
        ))
        let offB1 = try XCTUnwrap(try MachOParser.parse(data: b1).segments.flatMap(\.sections).first { $0.sectionName == "__myevil" }?.offset)
        patchEncryptionRange(&b1, offset: offB1, size: 4096)
        let parsedB1 = try MachOParser.parse(data: b1)
        XCTAssertTrue(parsedB1.hasForgedPlaintextFairPlayRange, "B-1 custom RX section flags=0 must be detected")
        XCTAssertEqual(parsedB1.scanDirectSyscalls().totalCount, 16)
        let b1URL = dir.appendingPathComponent("b1_myevil")
        try b1.write(to: b1URL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: b1URL).riskTier, .highRisk)

        // 3. B-2 & B-2c: 4 KB and 1 KB __text mixing 16 x svc #0x80 + CSPRNG
        for (label, textSize, constSize) in [("B-2", 4096, 0), ("B-2c", 1024, 3072)] {
            var words = [UInt32](repeating: 0xD400_1001, count: 16)
            let csBytes = M1TestCMSFixtures.csprngBytes(count: textSize - 64)
            csBytes.withUnsafeBytes { raw in
                for i in stride(from: 0, to: csBytes.count, by: 4) {
                    words.append(raw.loadUnaligned(fromByteOffset: i, as: UInt32.self).littleEndian)
                }
            }
            var sects: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
            if constSize > 0 {
                sects.append((segName: "__TEXT", sectName: "__const", flags: 0, payload: M1TestCMSFixtures.csprngBytes(count: constSize)))
            }
            var b2 = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 0,
                cryptsize: 4096,
                textInstructions: words,
                customSections: sects
            ))
            let offB2 = try XCTUnwrap(try MachOParser.parse(data: b2).textSegment?.sections.first { $0.sectionName == "__text" }?.offset)
            patchEncryptionRange(&b2, offset: offB2, size: 4096)
            let parsedB2 = try MachOParser.parse(data: b2)
            XCTAssertTrue(parsedB2.hasForgedPlaintextFairPlayRange, "\(label) mixed __text must be detected")
            XCTAssertGreaterThanOrEqual(parsedB2.scanDirectSyscalls().totalCount, 16)
        }

        // 4. B-3: 8 KB __objc_methname with CSPRNG in page 0 and selector in page 1
        var b3Payload = M1TestCMSFixtures.csprngBytes(count: 8192)
        let b3Sel = Data("\0systemPhotoLibrary\0bundleWithPath:\0".utf8)
        b3Payload.replaceSubrange(4096..<(4096 + b3Sel.count), with: b3Sel)
        var b3 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 8192,
            customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: b3Payload)]
        ))
        let offB3 = try XCTUnwrap(try MachOParser.parse(data: b3).segments.flatMap(\.sections).first { $0.sectionName == "__objc_methname" }?.offset)
        patchEncryptionRange(&b3, offset: offB3, size: 8192)
        let parsedB3 = try MachOParser.parse(data: b3)
        XCTAssertTrue(parsedB3.hasForgedPlaintextFairPlayRange, "B-3 8KB page-1 selector must be detected")
        XCTAssertTrue(parsedB3.objcMethodNames.contains("systemPhotoLibrary"))

        // 5. B-4b: 132 MB FairPlay range with 896 x svc #0x80 at page 5 offset 512 (20992)
        let size132MB = 132 * 1024 * 1024
        var b4bWords = [UInt32]()
        b4bWords.reserveCapacity(size132MB / 4)
        let csBlock = M1TestCMSFixtures.csprngBytes(count: 4096)
        var csWords4K = [UInt32]()
        csBlock.withUnsafeBytes { raw in
            for i in stride(from: 0, to: 4096, by: 4) {
                csWords4K.append(raw.loadUnaligned(fromByteOffset: i, as: UInt32.self).littleEndian)
            }
        }
        let totalPages132 = size132MB / 4096
        for _ in 0..<totalPages132 {
            b4bWords.append(contentsOf: csWords4K)
        }
        let targetWordBase = (5 * 4096 + 512) / 4
        for k in 0..<896 {
            b4bWords[targetWordBase + k] = 0xD400_1001
        }
        var b4b = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: UInt32(size132MB),
            textInstructions: b4bWords
        ))
        let offB4b = try XCTUnwrap(try MachOParser.parse(data: b4b).textSegment?.sections.first { $0.sectionName == "__text" }?.offset)
        patchEncryptionRange(&b4b, offset: offB4b, size: UInt32(size132MB))
        let parsedB4b = try MachOParser.parse(data: b4b)
        XCTAssertTrue(parsedB4b.hasForgedPlaintextFairPlayRange, "B-4b 132MB page-5 offset-512 svc #0x80 must be detected")
        XCTAssertGreaterThanOrEqual(parsedB4b.scanDirectSyscalls().totalCount, 896)

        // 6. B-5b: 243B __info_plist with 65 leading spaces + 3853B CSPRNG __const in 4 KB FairPlay range
        let plist243 = Data((String(repeating: " ", count: 65) + "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>io.metamask.fake</string><key>UIBackgroundModes</key><array><string>voip</string></array></dict></plist>").utf8)
        var b5b = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 4096,
            customSections: [
                (segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: plist243),
                (segName: "__TEXT", sectName: "__const", flags: 0, payload: M1TestCMSFixtures.csprngBytes(count: 4096 - plist243.count))
            ]
        ))
        let offB5b = try XCTUnwrap(try MachOParser.parse(data: b5b).segments.flatMap(\.sections).first { $0.sectionName == "__info_plist" }?.offset)
        patchEncryptionRange(&b5b, offset: offB5b, size: 4096)
        let parsedB5b = try MachOParser.parse(data: b5b)
        XCTAssertTrue(parsedB5b.hasForgedPlaintextFairPlayRange, "B-5b 65-space __info_plist in 4KB range must be detected")
        XCTAssertEqual(parsedB5b.embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.fake")
        let b5bURL = dir.appendingPathComponent("b5b_ws65")
        try b5b.write(to: b5bURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: b5bURL).riskTier, .highRisk)
    }

    func test_machoParser_objcMethodNames_R4_ahoCorasickPrefixDoS_and_165MiBGap_detectedFast() throws {
        // 1. B-7c / B-7c3: 64 MiB of repeating selector-prefix decoys must finish in < 0.5s
        for (label, pattern) in [
            ("NSSelectorFromStrin_x26", String(repeating: "NSSelectorFromStrin", count: 26) + "\0"),
            ("NS_x255", String(repeating: "NS", count: 255) + "\0")
        ] {
            let chunk = Data(pattern.utf8)
            var payload = Data()
            payload.reserveCapacity(64 * 1024 * 1024 + 4096)
            while payload.count < 64 * 1024 * 1024 - 128 {
                payload.append(chunk)
            }
            payload.append(Data("systemPhotoLibrary\0".utf8))
            let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 0,
                customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: payload)]
            ))
            let parsed = try MachOParser.parse(data: bin)
            let t0 = Date()
            let sels = Set(parsed.objcMethodNames)
            let elapsed = Date().timeIntervalSince(t0)
            XCTAssertLessThan(elapsed, 0.5, "\(label) 64 MiB took \(elapsed)s (must be < 0.5s)")
            XCTAssertTrue(sels.contains("systemPhotoLibrary"), "\(label) must detect trailing selector")
        }

        // 2. B-7d: 165 MiB __objc_methname with "systemPhotoLibrary\0" at 154 MiB
        let padChunk = Data("padSelector_\0".utf8)
        var block1MiB = Data()
        block1MiB.reserveCapacity(1024 * 1024 + padChunk.count)
        while block1MiB.count < 1024 * 1024 {
            block1MiB.append(padChunk)
        }
        let block1MiBExact = block1MiB.prefix(1024 * 1024)
        var payload165 = Data()
        payload165.reserveCapacity(165 * 1024 * 1024 + 128)
        for mib in 0..<165 {
            if mib == 154 {
                payload165.append(Data("\0systemPhotoLibrary\0".utf8))
            }
            payload165.append(block1MiBExact)
        }
        let bin165 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: payload165)]
        ))
        let parsed165 = try MachOParser.parse(data: bin165)
        XCTAssertTrue(parsed165.objcMethodNames.contains("systemPhotoLibrary"), "B-7d 165 MiB gap selector at 154 MiB must be detected")
    }

    func test_machoParser_embeddedInfoPlist_R4_256Decoys_16LargeDecoys_and_65SpaceWhitespace_extracted() throws {
        let evilPlistData = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "io.metamask.fake",
                "UIBackgroundModes": ["voip"]
            ],
            format: .xml,
            options: 0
        )

        // 1. B-6a: 256 x "<?xml bad?>" before real __info_plist
        var sects6a: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
        for _ in 0..<256 {
            sects6a.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: Data("<?xml bad?>".utf8)))
        }
        sects6a.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: evilPlistData))
        let bin6a = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, customSections: sects6a))
        XCTAssertEqual(try MachOParser.parse(data: bin6a).embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.fake")

        // 2. B-6b: 256 x "bplist00bad" before real __info_plist
        var sects6b: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
        for _ in 0..<256 {
            sects6b.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: Data("bplist00bad".utf8)))
        }
        sects6b.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: evilPlistData))
        let bin6b = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, customSections: sects6b))
        XCTAssertEqual(try MachOParser.parse(data: bin6b).embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.fake")

        // 3. B-6c: 16 x 65 KB "<?xml bad?>" before 65 KB valid __info_plist
        var decoy65KB = Data("<?xml bad?>".utf8)
        decoy65KB.append(Data(repeating: 0x20, count: 65 * 1024 - decoy65KB.count))
        var real65KB = evilPlistData
        real65KB.append(Data(repeating: 0x20, count: 65 * 1024 - real65KB.count))
        var sects6c: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
        for _ in 0..<16 {
            sects6c.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: decoy65KB))
        }
        sects6c.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: real65KB))
        let bin6c = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, customSections: sects6c))
        XCTAssertEqual(try MachOParser.parse(data: bin6c).embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.fake")

        // 4. B-6d3: 65 leading spaces before <plist>
        var ws65 = Data(repeating: 0x20, count: 65)
        ws65.append(Data("<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>io.metamask.ws65</string></dict></plist>".utf8))
        let bin6d3 = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [(segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: ws65)]
        ))
        XCTAssertEqual(try MachOParser.parse(data: bin6d3).embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.ws65")
    }

    // MARK: 9. Iteration 5 Remediation Regression Tests

    func test_codeResources_versionedFramework_resourcesSymlinkAliasing_andNegativeControls() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "r5_versioned_resources_symlink")
        let fm = FileManager.default
        let cleanJS = Data("console.log('clean');".utf8)
        let evilJS = Data("console.log('evil');".utf8)
        let configBundle = Data("globalThis.__cfg = 1;".utf8)

        let emptyCR = try PropertyListSerialization.data(
            fromPropertyList: ["files": [String: Any](), "files2": [String: Any](), "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let mainPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r5symlink",
            "CFBundleExecutable": "MainApp",
            "CFBundleName": "MainApp"
        ], format: .xml, options: 0)
        let (mainBin, rootCert) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r5symlink",
            cryptid: 1,
            infoPlistData: mainPlistData,
            codeResourcesData: emptyCR,
            signerLeaf: state.appStoreLeaf
        )

        let fwCRFiles: [String: Any] = [
            "Resources/clean.js": [
                "hash": Data(Insecure.SHA1.hash(data: cleanJS)),
                "hash2": Data(SHA256.hash(data: cleanJS))
            ],
            "Resources/config.jsbundle": [
                "hash": Data(Insecure.SHA1.hash(data: configBundle)),
                "hash2": Data(SHA256.hash(data: configBundle))
            ]
        ]
        let fwCRData = try PropertyListSerialization.data(
            fromPropertyList: ["files": fwCRFiles, "files2": fwCRFiles, "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let fwPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r5symlink.macfw",
            "CFBundleExecutable": "MacFw",
            "CFBundleName": "MacFw"
        ], format: .xml, options: 0)
        let (fwBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r5symlink.macfw",
            cryptid: 1,
            infoPlistData: fwPlistData,
            codeResourcesData: fwCRData,
            signerLeaf: state.appStoreLeaf
        )
        let fwSlices = try MachOParser.shared.parseAllSlices(data: fwBin)

        // 1. R4_9b: Clean IPA with Resources -> Versions/Current/Resources + non-skipped config.jsbundle MUST pass (.appStore / .safe)
        let baseIPAItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/A/Resources/Info.plist", data: fwPlistData),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/A/MacFw", data: fwBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/A/_CodeSignature/CodeResources", data: fwCRData),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/A/Resources/clean.js", data: cleanJS),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/A/Resources/config.jsbundle", data: configBundle),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/Current", data: Data("A".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/MacFw", data: Data("Versions/Current/MacFw".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Resources", data: Data("Versions/Current/Resources".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let cleanIPA = dir.appendingPathComponent("r4_9b_clean.ipa")
        try buildStoredRawZIP(baseIPAItems).write(to: cleanIPA)
        let cleanIPAFinding = try IPAPackageScanner.shared.scan(ipaURL: cleanIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(cleanIPAFinding.installChannel, .appStore, "R4_9b: Clean Resources -> Versions/Current/Resources IPA with .jsbundle must pass")
        XCTAssertEqual(cleanIPAFinding.riskTier, .safe)

        // 2. Negative controls in IPA:
        //    (a) unsealed Versions/A/Resources/evil.js
        var unsealedIPAItems = baseIPAItems
        unsealedIPAItems.append(RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Versions/A/Resources/evil.js", data: evilJS))
        let unsealedIPA = dir.appendingPathComponent("r4_9b_unsealed_evil.ipa")
        try buildStoredRawZIP(unsealedIPAItems).write(to: unsealedIPA)
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: unsealedIPA, customAnchorCertificates: [rootCert]).installChannel, .developerSideloaded)

        //    (b) colliding archive regular entry Resources/evil.js AND colliding Resources/config.jsbundle
        for (label, collidingName, collidingData) in [
            ("colliding_evil_js", "Resources/evil.js", evilJS),
            ("colliding_jsbundle", "Resources/config.jsbundle", evilJS)
        ] {
            var collidingItems = baseIPAItems
            collidingItems.append(RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/\(collidingName)", data: collidingData))
            let collidingIPA = dir.appendingPathComponent("r4_9b_\(label).ipa")
            try buildStoredRawZIP(collidingItems).write(to: collidingIPA)
            XCTAssertEqual(
                try IPAPackageScanner.shared.scan(ipaURL: collidingIPA, customAnchorCertificates: [rootCert]).installChannel,
                .developerSideloaded,
                "Colliding archive regular entry \(collidingName) alongside Resources symlink must be rejected"
            )
        }

        // 3. R4_9c: Clean on-disk Versions/B + Resources -> Versions/Current/Resources MUST return nil
        let diskFwB = dir.appendingPathComponent("MacFwB.framework")
        let verB = diskFwB.appendingPathComponent("Versions/B")
        try fm.createDirectory(at: verB.appendingPathComponent("Resources"), withIntermediateDirectories: true)
        try fm.createDirectory(at: verB.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try fwBin.write(to: verB.appendingPathComponent("MacFw"))
        try fwCRData.write(to: verB.appendingPathComponent("_CodeSignature/CodeResources"))
        try fwPlistData.write(to: verB.appendingPathComponent("Resources/Info.plist"))
        try cleanJS.write(to: verB.appendingPathComponent("Resources/clean.js"))
        try configBundle.write(to: verB.appendingPathComponent("Resources/config.jsbundle"))
        try fm.createSymbolicLink(atPath: diskFwB.appendingPathComponent("Versions/Current").path, withDestinationPath: "B")
        try fm.createSymbolicLink(atPath: diskFwB.appendingPathComponent("MacFw").path, withDestinationPath: "Versions/Current/MacFw")
        try fm.createSymbolicLink(atPath: diskFwB.appendingPathComponent("Resources").path, withDestinationPath: "Versions/Current/Resources")
        XCTAssertNil(CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: fwSlices, bundleURL: diskFwB), "R4_9c: Clean on-disk Versions/B + Resources symlink must return nil")

        // 4. R4_Safari_nested_MacFw_Resources_symlink_OnDisk: SafariNested.app/Contents/Frameworks/MacFw.framework on disk
        let safariApp = dir.appendingPathComponent("SafariNested.app")
        let safariMacOS = safariApp.appendingPathComponent("Contents/MacOS")
        let safariCRDir = safariApp.appendingPathComponent("Contents/_CodeSignature")
        let nestedFw = safariApp.appendingPathComponent("Contents/Frameworks/MacFw.framework")
        let nestedVerA = nestedFw.appendingPathComponent("Versions/A")
        try fm.createDirectory(at: safariMacOS, withIntermediateDirectories: true)
        try fm.createDirectory(at: safariCRDir, withIntermediateDirectories: true)
        try fm.createDirectory(at: nestedVerA.appendingPathComponent("Resources"), withIntermediateDirectories: true)
        try fm.createDirectory(at: nestedVerA.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        let (safariBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r5.safarinested",
            cryptid: 1,
            infoPlistData: mainPlistData,
            codeResourcesData: emptyCR,
            signerLeaf: state.appStoreLeaf
        )
        let safariSlices = try MachOParser.shared.parseAllSlices(data: safariBin)
        try safariBin.write(to: safariMacOS.appendingPathComponent("SafariNested"))
        try mainPlistData.write(to: safariApp.appendingPathComponent("Contents/Info.plist"))
        try emptyCR.write(to: safariCRDir.appendingPathComponent("CodeResources"))
        try fwBin.write(to: nestedVerA.appendingPathComponent("MacFw"))
        try fwCRData.write(to: nestedVerA.appendingPathComponent("_CodeSignature/CodeResources"))
        try fwPlistData.write(to: nestedVerA.appendingPathComponent("Resources/Info.plist"))
        try cleanJS.write(to: nestedVerA.appendingPathComponent("Resources/clean.js"))
        try configBundle.write(to: nestedVerA.appendingPathComponent("Resources/config.jsbundle"))
        try fm.createSymbolicLink(atPath: nestedFw.appendingPathComponent("Versions/Current").path, withDestinationPath: "A")
        try fm.createSymbolicLink(atPath: nestedFw.appendingPathComponent("MacFw").path, withDestinationPath: "Versions/Current/MacFw")
        try fm.createSymbolicLink(atPath: nestedFw.appendingPathComponent("Resources").path, withDestinationPath: "Versions/Current/Resources")
        XCTAssertNil(CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: safariSlices, bundleURL: safariApp), "Nested Safari Contents/Frameworks/MacFw.framework with Resources symlink must return nil")

        // 5. Negative control on disk: non-symlink regular Resources/ directory containing evil.js (or even clean.js) MUST fail
        let nonSymlinkFw = dir.appendingPathComponent("NonSymlinkResources.framework")
        let nsVerA = nonSymlinkFw.appendingPathComponent("Versions/A")
        try fm.createDirectory(at: nsVerA.appendingPathComponent("Resources"), withIntermediateDirectories: true)
        try fm.createDirectory(at: nsVerA.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try fm.createDirectory(at: nonSymlinkFw.appendingPathComponent("Resources"), withIntermediateDirectories: true)
        try fwBin.write(to: nsVerA.appendingPathComponent("MacFw"))
        try fwCRData.write(to: nsVerA.appendingPathComponent("_CodeSignature/CodeResources"))
        try fwPlistData.write(to: nsVerA.appendingPathComponent("Resources/Info.plist"))
        try cleanJS.write(to: nsVerA.appendingPathComponent("Resources/clean.js"))
        try configBundle.write(to: nsVerA.appendingPathComponent("Resources/config.jsbundle"))
        try evilJS.write(to: nonSymlinkFw.appendingPathComponent("Resources/evil.js"))
        try fm.createSymbolicLink(atPath: nonSymlinkFw.appendingPathComponent("Versions/Current").path, withDestinationPath: "A")
        try fm.createSymbolicLink(atPath: nonSymlinkFw.appendingPathComponent("MacFw").path, withDestinationPath: "Versions/Current/MacFw")
        XCTAssertNotNil(CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: fwSlices, bundleURL: nonSymlinkFw), "Regular directory Resources/evil.js must fail CodeResources check")
    }

    func test_machoParser_forgedFairPlay_R5_C1a_C1b_C1c_C1d_C1d2_detected() throws {
        let dir = try makeTempDir(prefix: "r5_fairplay_regression")

        func patchEncryptionRange(_ bin: inout Data, offset: UInt32, size: UInt32) {
            let ncmds = bin.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
            var cur = MemoryLayout<mach_header_64>.size
            for _ in 0..<ncmds {
                let cmd = bin.withUnsafeBytes { $0.load(fromByteOffset: cur, as: UInt32.self).littleEndian }
                let csz = bin.withUnsafeBytes { $0.load(fromByteOffset: cur + 4, as: UInt32.self).littleEndian }
                if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                    var offLE = offset.littleEndian
                    var szLE = size.littleEndian
                    withUnsafeBytes(of: &offLE) { bin.replaceSubrange((cur + 8)..<(cur + 12), with: $0) }
                    withUnsafeBytes(of: &szLE) { bin.replaceSubrange((cur + 12)..<(cur + 16), with: $0) }
                    return
                }
                cur += Int(csz)
            }
        }

        // 1. C1a: 7 x svc #0x80 with stp/mov x16,x8/ldp/blr/br + CSPRNG in 4 KB FairPlay range
        var c1aWords: [UInt32] = [
            0xA9BF_7BFD, // stp x29, x30, [sp, #-16]!
            0xAA08_03F0, // mov x16, x8
            0xD400_1001, // svc #0x80
            0xD400_1001,
            0xD400_1001,
            0xD400_1001,
            0xD400_1001,
            0xD400_1001,
            0xD400_1001,
            0xA8C1_7BFD, // ldp x29, x30, [sp], #16
            0xD63F_0120, // blr x9
            0xD61F_03C0  // br x30
        ]
        let c1aPad = M1TestCMSFixtures.csprngBytes(count: 4096 - c1aWords.count * 4)
        c1aPad.withUnsafeBytes { raw in
            for i in stride(from: 0, to: c1aPad.count, by: 4) {
                c1aWords.append(raw.loadUnaligned(fromByteOffset: i, as: UInt32.self).littleEndian)
            }
        }
        var c1aBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 4096,
            textInstructions: c1aWords
        ))
        let offC1a = try XCTUnwrap(try MachOParser.parse(data: c1aBin).textSegment?.sections.first?.offset)
        patchEncryptionRange(&c1aBin, offset: offC1a, size: 4096)
        let parsedC1a = try MachOParser.parse(data: c1aBin)
        XCTAssertTrue(parsedC1a.hasForgedPlaintextFairPlayRange, "C1a 7x svc stub must be detected")
        XCTAssertGreaterThanOrEqual(parsedC1a.scanDirectSyscalls().totalCount, 7)
        let c1aURL = dir.appendingPathComponent("c1a_bin")
        try c1aBin.write(to: c1aURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: c1aURL).riskTier, .highRisk)

        // 2. C1b: Unaligned cryptoff = off + 1 AND phase-shifted sect.offset = off + 1 with 16 x svc #0x80 at off + 4
        var c1bWords: [UInt32] = [0xAA00_03E0] // 4 bytes before +4
        c1bWords.append(contentsOf: [UInt32](repeating: 0xD400_1001, count: 16))
        let c1bPad = M1TestCMSFixtures.csprngBytes(count: 4096 - c1bWords.count * 4)
        c1bPad.withUnsafeBytes { raw in
            for i in stride(from: 0, to: c1bPad.count, by: 4) {
                c1bWords.append(raw.loadUnaligned(fromByteOffset: i, as: UInt32.self).littleEndian)
            }
        }
        let baseC1b = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 4096,
            textInstructions: c1bWords
        ))
        let offC1b = try XCTUnwrap(try MachOParser.parse(data: baseC1b).textSegment?.sections.first?.offset)

        // 2a. Unaligned cryptoff = offC1b + 1, cryptsize = 4095
        var c1bCryptBin = baseC1b
        patchEncryptionRange(&c1bCryptBin, offset: offC1b + 1, size: 4095)
        let parsedC1bCrypt = try MachOParser.parse(data: c1bCryptBin)
        XCTAssertTrue(parsedC1bCrypt.hasForgedPlaintextFairPlayRange, "C1b unaligned cryptoff+1 must be detected")
        XCTAssertGreaterThanOrEqual(parsedC1bCrypt.scanDirectSyscalls().totalCount, 16)
        let c1bCryptURL = dir.appendingPathComponent("c1b_cryptoff")
        try c1bCryptBin.write(to: c1bCryptURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: c1bCryptURL).riskTier, .highRisk)

        // 2b. Phase-shifted sect.offset = offC1b + 1, sect.size = 4095, cryptoff = offC1b, cryptsize = 4096
        var c1bSectBin = baseC1b
        patchEncryptionRange(&c1bSectBin, offset: offC1b, size: 4096)
        // section_64 for __text is immediately after mach_header_64 (32) + segment_command_64 (72) = 104
        // section_64.size is at +40 (8 bytes), section_64.offset is at +48 (4 bytes)
        let sectCmdOff = MemoryLayout<mach_header_64>.size + MemoryLayout<segment_command_64>.size
        var shiftedSizeLE = UInt64(4095).littleEndian
        var shiftedOffLE = (offC1b + 1).littleEndian
        withUnsafeBytes(of: &shiftedSizeLE) { c1bSectBin.replaceSubrange((sectCmdOff + 40)..<(sectCmdOff + 48), with: $0) }
        withUnsafeBytes(of: &shiftedOffLE) { c1bSectBin.replaceSubrange((sectCmdOff + 48)..<(sectCmdOff + 52), with: $0) }
        let parsedC1bSect = try MachOParser.parse(data: c1bSectBin)
        XCTAssertTrue(parsedC1bSect.hasForgedPlaintextFairPlayRange, "C1b phase-shifted sect.offset+1 must be detected")
        XCTAssertGreaterThanOrEqual(parsedC1bSect.scanDirectSyscalls().totalCount, 16)
        let c1bSectURL = dir.appendingPathComponent("c1b_sectoff")
        try c1bSectBin.write(to: c1bSectURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: c1bSectURL).riskTier, .highRisk)

        // 3. C1c: nsects = 0 RX __TEXT with 16 x svc #0x80 + ret inside 4 KB FairPlay range (and CSPRNG negative control)
        func buildZeroSectionRXBinary(includeSyscalls: Bool) -> Data {
            let segCmdSize = MemoryLayout<segment_command_64>.size
            let encCmdSize = MemoryLayout<encryption_info_command_64>.size
            var hdr = mach_header_64()
            hdr.magic = MH_MAGIC_64
            hdr.cputype = CPU_TYPE_ARM64
            hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
            hdr.filetype = UInt32(MH_EXECUTE)
            hdr.ncmds = 2
            hdr.sizeofcmds = UInt32(segCmdSize + encCmdSize)

            let cryptoff = 4096
            let cryptsize = 4096
            let totalSize = cryptoff + cryptsize

            var seg = segment_command_64()
            seg.cmd = UInt32(LC_SEGMENT_64)
            seg.cmdsize = UInt32(segCmdSize)
            withUnsafeMutableBytes(of: &seg.segname) { buf in
                buf.initializeMemory(as: UInt8.self, repeating: 0)
                for (i, b) in "__TEXT".utf8.enumerated() { buf[i] = b }
            }
            seg.vmaddr = 0x1_0000_0000
            seg.vmsize = UInt64(totalSize)
            seg.fileoff = 0
            seg.filesize = UInt64(totalSize)
            seg.maxprot = 7
            seg.initprot = 5
            seg.nsects = 0

            var enc = encryption_info_command_64()
            enc.cmd = UInt32(LC_ENCRYPTION_INFO_64)
            enc.cmdsize = UInt32(encCmdSize)
            enc.cryptoff = UInt32(cryptoff)
            enc.cryptsize = UInt32(cryptsize)
            enc.cryptid = 1

            var bin = Data(bytes: &hdr, count: MemoryLayout<mach_header_64>.size)
            bin.append(Data(bytes: &seg, count: segCmdSize))
            bin.append(Data(bytes: &enc, count: encCmdSize))
            if bin.count < cryptoff {
                bin.append(Data(repeating: 0, count: cryptoff - bin.count))
            }
            var payload = M1TestCMSFixtures.csprngBytes(count: cryptsize)
            if includeSyscalls {
                var stub = Data()
                for _ in 0..<16 {
                    var w = UInt32(0xD400_1001).littleEndian
                    withUnsafeBytes(of: &w) { stub.append(contentsOf: $0) }
                }
                var retW = UInt32(0xD65F_03C0).littleEndian
                withUnsafeBytes(of: &retW) { stub.append(contentsOf: $0) }
                payload.replaceSubrange(0..<stub.count, with: stub)
            }
            bin.append(payload)
            return bin
        }
        let c1cEvil = buildZeroSectionRXBinary(includeSyscalls: true)
        let parsedC1c = try MachOParser.parse(data: c1cEvil)
        XCTAssertTrue(parsedC1c.hasForgedPlaintextFairPlayRange, "C1c nsects=0 RX __TEXT with svc #0x80 must be detected")
        XCTAssertGreaterThanOrEqual(parsedC1c.scanDirectSyscalls().totalCount, 16)
        let c1cURL = dir.appendingPathComponent("c1c_nsects0")
        try c1cEvil.write(to: c1cURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: c1cURL).riskTier, .highRisk)

        let c1cClean = buildZeroSectionRXBinary(includeSyscalls: false)
        XCTAssertFalse(try MachOParser.parse(data: c1cClean).hasForgedPlaintextFairPlayRange, "nsects=0 RX __TEXT with pure CSPRNG must not false-positive")

        // 4. C1d: 2 MB __objc_methname with "\0initWithURL:\0_fsgetpath\0" at 1.5 MB + CSPRNG in FairPlay range
        var c1dPayload = M1TestCMSFixtures.csprngBytes(count: 2 * 1024 * 1024)
        let c1dInjection = Data("\0initWithURL:\0_fsgetpath\0".utf8)
        let c1dPos = 1536 * 1024
        c1dPayload.replaceSubrange(c1dPos..<(c1dPos + c1dInjection.count), with: c1dInjection)
        var c1dBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: UInt32(c1dPayload.count),
            customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: c1dPayload)]
        ))
        let offC1d = try XCTUnwrap(try MachOParser.parse(data: c1dBin).segments.flatMap(\.sections).first { $0.sectionName == "__objc_methname" }?.offset)
        patchEncryptionRange(&c1dBin, offset: offC1d, size: UInt32(c1dPayload.count))
        let parsedC1d = try MachOParser.parse(data: c1dBin)
        XCTAssertTrue(parsedC1d.hasForgedPlaintextFairPlayRange, "C1d 2MB __objc_methname short symbol/selector at 1.5MB must be detected")
        XCTAssertTrue(parsedC1d.objcMethodNames.contains("_fsgetpath"))
        let c1dURL = dir.appendingPathComponent("c1d_2mb")
        try c1dBin.write(to: c1dURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: c1dURL).riskTier, .highRisk)

        // 5. C1d2: 4 KB __objc_methname with "\0_fsgetpath\0" + CSPRNG in FairPlay range
        var c1d2Payload = M1TestCMSFixtures.csprngBytes(count: 4096)
        let c1d2Injection = Data("\0_fsgetpath\0".utf8)
        c1d2Payload.replaceSubrange(1024..<(1024 + c1d2Injection.count), with: c1d2Injection)
        var c1d2Bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 4096,
            customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: c1d2Payload)]
        ))
        let offC1d2 = try XCTUnwrap(try MachOParser.parse(data: c1d2Bin).segments.flatMap(\.sections).first { $0.sectionName == "__objc_methname" }?.offset)
        patchEncryptionRange(&c1d2Bin, offset: offC1d2, size: 4096)
        let parsedC1d2 = try MachOParser.parse(data: c1d2Bin)
        XCTAssertTrue(parsedC1d2.hasForgedPlaintextFairPlayRange, "C1d2 4KB __objc_methname _fsgetpath must be detected")
        XCTAssertTrue(parsedC1d2.objcMethodNames.contains("_fsgetpath"))
    }

    func test_machoParser_embeddedInfoPlist_R5_C2a_C2b_C2c_C2d_C2f_extracted() throws {
        let evilPlistData = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "io.metamask.fake",
                "UIBackgroundModes": ["voip"]
            ],
            format: .xml,
            options: 0
        )

        // 1. C2a: 2048 small malformed "</plist>" XML decoys before valid __info_plist
        var sects2a: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
        let tinyBadXML = Data("<plist><dict><key>k</bad></dict></plist>".utf8)
        for _ in 0..<2048 {
            sects2a.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: tinyBadXML))
        }
        sects2a.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: evilPlistData))
        let bin2a = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, customSections: sects2a))
        XCTAssertEqual(try MachOParser.parse(data: bin2a).embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.fake", "C2a: 2048 tiny malformed XML decoys must not blind trailing plist")

        // 2. C2b: 64 x 65 KB malformed "</plist>" XML decoys before 65 KB valid __info_plist
        var decoy65KB = Data("<plist><dict><key>k</bad></dict>".utf8)
        decoy65KB.append(Data(repeating: 0x20, count: 65 * 1024 - decoy65KB.count - 8))
        decoy65KB.append(Data("</plist>".utf8))
        var real65KB = evilPlistData
        real65KB.append(Data(repeating: 0x20, count: 65 * 1024 - real65KB.count))
        var sects2b: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
        for _ in 0..<64 {
            sects2b.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: decoy65KB))
        }
        sects2b.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: real65KB))
        let bin2b = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, customSections: sects2b))
        XCTAssertEqual(try MachOParser.parse(data: bin2b).embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.fake", "C2b: 64 x 65KB malformed XML decoys must not blind trailing plist")

        // 3. C2c: 2048 x 41B corrupt bplist00 (valid 32-byte trailer, topObject points to 0xFF) before valid __info_plist
        var badBplist = Data("bplist00".utf8)
        badBplist.append(0xFF) // corrupt object byte at offset 8
        var trailer = Data(repeating: 0, count: 32)
        trailer[6] = 1 // offsetIntSize = 1
        trailer[7] = 1 // objectRefSize = 1
        trailer[15] = 1 // numObjects = 1
        trailer[23] = 0 // topObject = 0
        trailer[31] = 8 // offsetTableOffset = 8 (Wait: 8 + 1 = 9 <= 9? Let's place offsetTable at 9 -> 42B total)
        // Rebuild valid 42B bplist with offsetTableOffset = 9 pointing to byte 8 (0xFF):
        var badBplist42 = Data("bplist00".utf8)
        badBplist42.append(0xFF) // byte 8: object 0 (invalid marker 0xFF)
        badBplist42.append(0x08) // byte 9: offsetTable[0] = 8
        trailer[31] = 9 // offsetTableOffset = 9, bodyLimit = 10
        badBplist42.append(trailer)
        var sects2c: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
        for _ in 0..<2048 {
            sects2c.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: badBplist42))
        }
        sects2c.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: evilPlistData))
        let bin2c = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, customSections: sects2c))
        XCTAssertEqual(try MachOParser.parse(data: bin2c).embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.fake", "C2c: 2048 corrupt bplist00 decoys must not blind trailing plist")

        // 4. C2d: 16 x 4 MB "<plist>" decoys before 65 KB valid __info_plist
        var decoy4MB = Data("<plist>".utf8)
        decoy4MB.append(Data(repeating: 0x20, count: 4 * 1024 * 1024 - decoy4MB.count - 8))
        decoy4MB.append(Data("</plist>".utf8))
        var sects2d: [(segName: String, sectName: String, flags: UInt32, payload: Data)] = []
        for _ in 0..<16 {
            sects2d.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: decoy4MB))
        }
        sects2d.append((segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: real65KB))
        let bin2d = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, customSections: sects2d))
        XCTAssertEqual(try MachOParser.parse(data: bin2d).embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.fake", "C2d: 16 x 4MB decoys must not starve trailing 65KB plist")

        // 5. C2f: 4097 leading spaces before <plist>
        var ws4097 = Data(repeating: 0x20, count: 4097)
        ws4097.append(Data("<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>io.metamask.fake</string></dict></plist>".utf8))
        let bin2f = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [(segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: ws4097)]
        ))
        XCTAssertEqual(try MachOParser.parse(data: bin2f).embeddedInfoPlist?["CFBundleIdentifier"] as? String, "io.metamask.fake", "C2f: 4097 leading spaces before <plist> must still be extracted")
    }

    func test_machoParser_objcMethodNames_R5_C3a_24MiBStraddle_and_C3b_gapStarvation() throws {
        // 1. C3a: "systemPhotoLibrary\0" straddling 24 MiB (headStopOffset) in 40 MiB __objc_methname (< 65,536 selectors)
        let boundary24 = 24 * 1024 * 1024
        var payload3a = Data(repeating: 0x00, count: 40 * 1024 * 1024)
        // Put 100 unique selectors at start, then NUL padding up to 24 MiB - 8, then "systemPhotoLibrary\0"
        let headSel = Data("selInitA\0selInitB\0".utf8)
        payload3a.replaceSubrange(0..<headSel.count, with: headSel)
        let straddleBytes = Data("\0systemPhotoLibrary\0".utf8)
        let straddleStart = boundary24 - 9 // '\0' at -9, "systemPh" before 24 MiB, "otoLibrary\0" across 24 MiB
        payload3a.replaceSubrange(straddleStart..<(straddleStart + straddleBytes.count), with: straddleBytes)
        let bin3a = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: payload3a)]
        ))
        let parsed3a = try MachOParser.parse(data: bin3a)
        XCTAssertTrue(parsed3a.objcMethodNames.contains("systemPhotoLibrary"), "C3a: Selector straddling 24 MiB headStopOffset must be detected")

        // 2. C3b: 65,536 head selectors + 32,768 unique "initWithPath:_i" in gap before trailing "systemPhotoLibrary"
        var payload3b = Data()
        payload3b.reserveCapacity(40 * 1024 * 1024)
        for i in 0..<65_536 {
            payload3b.append(Data("headSel_\(i)\0".utf8))
        }
        // Pad to 24 MiB so gapSubranges starts at 24 MiB
        if payload3b.count < boundary24 {
            payload3b.append(Data(repeating: 0x00, count: boundary24 - payload3b.count))
        }
        for i in 0..<32_768 {
            payload3b.append(Data("initWithPath:_\(i)\0".utf8))
        }
        // Pad up to 33 MiB so tailSubranges starts after gap, then append "systemPhotoLibrary\0"
        if payload3b.count < 33 * 1024 * 1024 {
            payload3b.append(Data(repeating: 0x00, count: 33 * 1024 * 1024 - payload3b.count))
        }
        payload3b.append(Data("\0systemPhotoLibrary\0".utf8))
        let bin3b = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: payload3b)]
        ))
        let parsed3b = try MachOParser.parse(data: bin3b)
        XCTAssertTrue(parsed3b.objcMethodNames.contains("systemPhotoLibrary"), "C3b: 32,768 gap matches must not starve tail selector")
    }

    // MARK: 10. Iteration 6 Remediation Regression Tests

    func test_appex_symlinkedFramework_R5_6a_clean_and_R5_6c_collision_caught() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "r6_appex_symlink_fw")
        let cleanJS = Data("console.log('clean');".utf8)
        let evilPNG = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF])
        let configBundle = Data("globalThis.__cfg = 1;".utf8)

        let emptyCR = try PropertyListSerialization.data(
            fromPropertyList: ["files": [String: Any](), "files2": [String: Any](), "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let mainPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r6appexfw",
            "CFBundleExecutable": "MainApp",
            "CFBundleName": "MainApp"
        ], format: .xml, options: 0)
        let (mainBin, rootCert) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r6appexfw",
            cryptid: 1,
            infoPlistData: mainPlistData,
            codeResourcesData: emptyCR,
            signerLeaf: state.appStoreLeaf
        )

        let extPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r6appexfw.ext",
            "CFBundleExecutable": "Ext",
            "CFBundleName": "Ext",
            "NSExtension": ["NSExtensionPointIdentifier": "com.apple.widgetkit-extension"]
        ], format: .xml, options: 0)
        let (extBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r6appexfw.ext",
            cryptid: 1,
            infoPlistData: extPlistData,
            codeResourcesData: emptyCR,
            signerLeaf: state.appStoreLeaf
        )

        let fwCRFiles: [String: Any] = [
            "Resources/clean.js": [
                "hash": Data(Insecure.SHA1.hash(data: cleanJS)),
                "hash2": Data(SHA256.hash(data: cleanJS))
            ],
            "Resources/config.jsbundle": [
                "hash": Data(Insecure.SHA1.hash(data: configBundle)),
                "hash2": Data(SHA256.hash(data: configBundle))
            ]
        ]
        let fwCRData = try PropertyListSerialization.data(
            fromPropertyList: ["files": fwCRFiles, "files2": fwCRFiles, "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let fwPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r6appexfw.macfw",
            "CFBundleExecutable": "MacFw",
            "CFBundleName": "MacFw"
        ], format: .xml, options: 0)
        let (fwBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r6appexfw.macfw",
            cryptid: 1,
            infoPlistData: fwPlistData,
            codeResourcesData: fwCRData,
            signerLeaf: state.appStoreLeaf
        )

        // 1. R5_6a: Clean symlinked versioned .framework inside .appex (both in-appex and escaping .appex into .app) -> .appStore, .safe
        let inAppexBase: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Info.plist", data: extPlistData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/A/Resources/Info.plist", data: fwPlistData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/A/MacFw", data: fwBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/A/_CodeSignature/CodeResources", data: fwCRData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/A/Resources/clean.js", data: cleanJS),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/A/Resources/config.jsbundle", data: configBundle),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/Current", data: Data("A".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/MacFw", data: Data("Versions/Current/MacFw".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Resources", data: Data("Versions/Current/Resources".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Frameworks/MacFw.framework", data: Data("../AltFw/MacFw.framework".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let cleanInAppexIPA = dir.appendingPathComponent("r5_6a_clean_in_appex.ipa")
        try buildStoredRawZIP(inAppexBase).write(to: cleanInAppexIPA)
        let f6aIn = try IPAPackageScanner.shared.scan(ipaURL: cleanInAppexIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(f6aIn.installChannel, .appStore, "R5_6a in-appex symlinked versioned .framework must remain .appStore")
        XCTAssertEqual(f6aIn.riskTier, .safe)

        let escapingAppexClean: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Info.plist", data: extPlistData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/ZStore/RealFw.framework/Versions/A/Resources/Info.plist", data: fwPlistData),
            RawZIPItem(name: "Payload/MainApp.app/ZStore/RealFw.framework/Versions/A/MacFw", data: fwBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/ZStore/RealFw.framework/Versions/A/_CodeSignature/CodeResources", data: fwCRData),
            RawZIPItem(name: "Payload/MainApp.app/ZStore/RealFw.framework/Versions/A/Resources/clean.js", data: cleanJS),
            RawZIPItem(name: "Payload/MainApp.app/ZStore/RealFw.framework/Versions/A/Resources/config.jsbundle", data: configBundle),
            RawZIPItem(name: "Payload/MainApp.app/ZStore/RealFw.framework/Versions/Current", data: Data("A".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/ZStore/RealFw.framework/MacFw", data: Data("Versions/Current/MacFw".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/ZStore/RealFw.framework/Resources", data: Data("Versions/Current/Resources".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Frameworks/MacFw.framework", data: Data("../../ZStore/RealFw.framework".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let cleanEscapingIPA = dir.appendingPathComponent("r5_6a_clean_zstore.ipa")
        try buildStoredRawZIP(escapingAppexClean).write(to: cleanEscapingIPA)
        let f6aZ = try IPAPackageScanner.shared.scan(ipaURL: cleanEscapingIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(f6aZ.installChannel, .appStore, "R5_6a escaping-appex -> ZStore symlinked versioned .framework must remain .appStore")
        XCTAssertEqual(f6aZ.riskTier, .safe)

        // 2. R5_6c: Colliding regular entry Resources/evil.png inside symlinked framework inside .appex -> .developerSideloaded
        var collidingInAppex = inAppexBase
        collidingInAppex.append(RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Resources/evil.png", data: evilPNG))
        let collidingInAppexIPA = dir.appendingPathComponent("r5_6c_colliding_in_appex.ipa")
        try buildStoredRawZIP(collidingInAppex).write(to: collidingInAppexIPA)
        XCTAssertEqual(
            try IPAPackageScanner.shared.scan(ipaURL: collidingInAppexIPA, customAnchorCertificates: [rootCert]).installChannel,
            .developerSideloaded,
            "R5_6c colliding Resources/evil.png in in-appex symlinked framework must disqualify .appStore"
        )

        var collidingZStore = escapingAppexClean
        collidingZStore.append(RawZIPItem(name: "Payload/MainApp.app/ZStore/RealFw.framework/Resources/evil.png", data: evilPNG))
        let collidingZStoreIPA = dir.appendingPathComponent("r5_6c_colliding_zstore.ipa")
        try buildStoredRawZIP(collidingZStore).write(to: collidingZStoreIPA)
        XCTAssertEqual(
            try IPAPackageScanner.shared.scan(ipaURL: collidingZStoreIPA, customAnchorCertificates: [rootCert]).installChannel,
            .developerSideloaded,
            "R5_6c colliding Resources/evil.png in ZStore symlinked framework must disqualify .appStore"
        )

        // 3. R5_6c non-.framework target name (`AltStore/RealFw`) with colliding `Resources/evil.png`
        let nonFwTargetCRFiles: [String: Any] = [
            "Resources/clean.png": [
                "hash": Data(Insecure.SHA1.hash(data: evilPNG)),
                "hash2": Data(SHA256.hash(data: evilPNG))
            ]
        ]
        let nonFwTargetCRData = try PropertyListSerialization.data(
            fromPropertyList: ["files": nonFwTargetCRFiles, "files2": nonFwTargetCRFiles, "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let (nonFwBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r6appexfw.realfw",
            cryptid: 1,
            infoPlistData: fwPlistData,
            codeResourcesData: nonFwTargetCRData,
            signerLeaf: state.appStoreLeaf
        )
        let collidingAltStoreNonFw: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Info.plist", data: extPlistData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltStore/RealFw/Versions/A/Resources/Info.plist", data: fwPlistData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltStore/RealFw/Versions/A/MacFw", data: nonFwBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltStore/RealFw/Versions/A/_CodeSignature/CodeResources", data: nonFwTargetCRData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltStore/RealFw/Versions/A/Resources/clean.png", data: evilPNG),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltStore/RealFw/Versions/Current", data: Data("A".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltStore/RealFw/MacFw", data: Data("Versions/Current/MacFw".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltStore/RealFw/Resources", data: Data("Versions/Current/Resources".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltStore/RealFw/Resources/evil.png", data: evilPNG),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Frameworks/MacFw.framework", data: Data("../AltStore/RealFw".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let collidingAltStoreIPA = dir.appendingPathComponent("r5_6c_colliding_altstore_realfw.ipa")
        try buildStoredRawZIP(collidingAltStoreNonFw).write(to: collidingAltStoreIPA)
        XCTAssertEqual(
            try IPAPackageScanner.shared.scan(ipaURL: collidingAltStoreIPA, customAnchorCertificates: [rootCert]).installChannel,
            .developerSideloaded,
            "R5_6c colliding Resources/evil.png in AltStore/RealFw must disqualify .appStore"
        )
    }

    func test_machoParser_forgedFairPlay_R6_altContext_1svc_3svc_and_CSPRNG_controls() throws {
        let dir = try makeTempDir(prefix: "r6_fairplay_alt_ctx")

        func patchEncryptionRange(_ bin: inout Data, offset: UInt32, size: UInt32) {
            let ncmds = bin.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
            var cur = MemoryLayout<mach_header_64>.size
            for _ in 0..<ncmds {
                let cmd = bin.withUnsafeBytes { $0.load(fromByteOffset: cur, as: UInt32.self).littleEndian }
                let csz = bin.withUnsafeBytes { $0.load(fromByteOffset: cur + 4, as: UInt32.self).littleEndian }
                if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                    var offLE = offset.littleEndian
                    var szLE = size.littleEndian
                    withUnsafeBytes(of: &offLE) { bin.replaceSubrange((cur + 8)..<(cur + 12), with: $0) }
                    withUnsafeBytes(of: &szLE) { bin.replaceSubrange((cur + 12)..<(cur + 16), with: $0) }
                    return
                }
                cur += Int(csz)
            }
        }

        func build4KFairPlayTextBinary(leadingWords: [UInt32], customPad: Data? = nil) -> Data {
            var words = leadingWords
            let pad = customPad ?? M1TestCMSFixtures.csprngBytes(count: 4096 - words.count * 4)
            pad.withUnsafeBytes { raw in
                for i in stride(from: 0, to: pad.count, by: 4) {
                    words.append(raw.loadUnaligned(fromByteOffset: i, as: UInt32.self).littleEndian)
                }
            }
            var bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 0,
                cryptsize: 4096,
                textInstructions: words
            ))
            if let off = try? MachOParser.parse(data: bin).textSegment?.sections.first?.offset {
                patchEncryptionRange(&bin, offset: off, size: 4096)
            }
            return bin
        }

        // 1. alt_ctx_1svc_adrp_ldr_cbz_beq: adrp x0,#0; ldr x0,[x0]; cbz x0,#8; svc #0x80; b.eq #8; bl #16
        let alt1Bin = build4KFairPlayTextBinary(leadingWords: [
            0x9000_0000, // adrp x0, #0
            0xF940_0000, // ldr x0, [x0]
            0xB400_0040, // cbz x0, #8
            0xD400_1001, // svc #0x80
            0x5400_0040, // b.eq #8
            0x9400_0004  // bl #16
        ])
        let parsedAlt1 = try MachOParser.parse(data: alt1Bin)
        XCTAssertTrue(parsedAlt1.hasForgedPlaintextFairPlayRange, "alt_ctx_1svc_adrp_ldr_cbz_beq must be detected as forged plaintext")
        XCTAssertGreaterThanOrEqual(parsedAlt1.scanDirectSyscalls().totalCount, 1)
        let alt1URL = dir.appendingPathComponent("alt1_bin")
        try alt1Bin.write(to: alt1URL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: alt1URL).riskTier, .highRisk)

        // 2. alt_ctx_3svc_adrp_ldr_beq: adrp x0,#0; ldr x0,[x0]; 3x svc #0x80; b.eq #8; b #16
        let alt3Bin = build4KFairPlayTextBinary(leadingWords: [
            0x9000_0000, // adrp x0, #0
            0xF940_0000, // ldr x0, [x0]
            0xD400_1001, // svc #0x80
            0xD400_1001, // svc #0x80
            0xD400_1001, // svc #0x80
            0x5400_0040, // b.eq #8
            0x1400_0004  // b #16
        ])
        let parsedAlt3 = try MachOParser.parse(data: alt3Bin)
        XCTAssertTrue(parsedAlt3.hasForgedPlaintextFairPlayRange, "alt_ctx_3svc_adrp_ldr_beq must be detected as forged plaintext")
        XCTAssertGreaterThanOrEqual(parsedAlt3.scanDirectSyscalls().totalCount, 3)
        let alt3URL = dir.appendingPathComponent("alt3_bin")
        try alt3Bin.write(to: alt3URL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: alt3URL).riskTier, .highRisk)

        // 3. Negative controls: 20x 256B seeded SplitMix64 + 20x 4KB seeded SplitMix64 with 3 raw svc #0x80 words at bytes 0..<12 (test_vector5 pattern)
        var negRng = M1TestCMSFixtures.SplitMix64(seed: 0x5635_4088_0000_0001)
        var pureFp = 0
        var vec5Fp = 0
        for _ in 0..<20 {
            var b256 = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 0,
                cryptsize: 256,
                customSections: [(segName: "__TEXT", sectName: "__csprng", flags: 0, payload: negRng.bytes(count: 256))]
            ))
            let off256 = try XCTUnwrap(try MachOParser.parse(data: b256).segments.flatMap(\.sections).first { $0.sectionName == "__csprng" }?.offset)
            patchEncryptionRange(&b256, offset: off256, size: 256)
            if try MachOParser.parse(data: b256).hasForgedPlaintextFairPlayRange { pureFp += 1 }

            let bVec5 = build4KFairPlayTextBinary(
                leadingWords: [0xD400_1001, 0xD400_1001, 0xD400_1001],
                customPad: negRng.bytes(count: 4096 - 12)
            )
            if try MachOParser.parse(data: bVec5).hasForgedPlaintextFairPlayRange { vec5Fp += 1 }
        }
        XCTAssertEqual(pureFp, 0, "20x 256B pure CSPRNG must yield 0 false positives")
        XCTAssertEqual(vec5Fp, 0, "20x test_vector5 (3 raw svc #0x80 + CSPRNG) must yield 0 false positives")
    }

    func test_machoParser_objcMethodNames_R6_multiSectionHeadStop_prevNonNul_detected() throws {
        let dir = try makeTempDir(prefix: "r6_multisect_headstop")

        func copyFixed16(_ str: String, into ptr: UnsafeMutableRawBufferPointer) {
            ptr.initializeMemory(as: UInt8.self, repeating: 0)
            for (i, b) in str.utf8.prefix(16).enumerated() { ptr[i] = b }
        }

        let boundary24 = 24 * 1024 * 1024
        let s1Size = boundary24 - 10
        let gapSize = 16
        let s2Size = 16 * 1024 * 1024

        let headerSize = MemoryLayout<mach_header_64>.size
        let segSize = MemoryLayout<segment_command_64>.size
        let sectSize = MemoryLayout<section_64>.size
        let sizeofcmds = segSize + 2 * sectSize
        let s1Off = (headerSize + sizeofcmds + 15) & ~15
        let gapOff = s1Off + s1Size
        let s2Off = gapOff + gapSize
        let totalSize = s2Off + s2Size

        var hdr = mach_header_64()
        hdr.magic = MH_MAGIC_64
        hdr.cputype = CPU_TYPE_ARM64
        hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        hdr.filetype = UInt32(MH_EXECUTE)
        hdr.ncmds = 1
        hdr.sizeofcmds = UInt32(sizeofcmds)

        var seg = segment_command_64()
        seg.cmd = UInt32(LC_SEGMENT_64)
        seg.cmdsize = UInt32(sizeofcmds)
        withUnsafeMutableBytes(of: &seg.segname) { copyFixed16("__TEXT", into: $0) }
        seg.vmaddr = 0x1_0000_0000
        seg.vmsize = UInt64(totalSize)
        seg.fileoff = 0
        seg.filesize = UInt64(totalSize)
        seg.maxprot = 5
        seg.initprot = 5
        seg.nsects = 2

        var sect1 = section_64()
        withUnsafeMutableBytes(of: &sect1.sectname) { copyFixed16("__objc_methname", into: $0) }
        withUnsafeMutableBytes(of: &sect1.segname) { copyFixed16("__TEXT", into: $0) }
        sect1.addr = 0x1_0000_0000 + UInt64(s1Off)
        sect1.size = UInt64(s1Size)
        sect1.offset = UInt32(s1Off)
        sect1.flags = UInt32(S_CSTRING_LITERALS)

        var sect2 = section_64()
        withUnsafeMutableBytes(of: &sect2.sectname) { copyFixed16("__objc_methname", into: $0) }
        withUnsafeMutableBytes(of: &sect2.segname) { copyFixed16("__TEXT", into: $0) }
        sect2.addr = 0x1_0000_0000 + UInt64(s2Off)
        sect2.size = UInt64(s2Size)
        sect2.offset = UInt32(s2Off)
        sect2.flags = UInt32(S_CSTRING_LITERALS)

        var bin = Data(repeating: 0, count: totalSize)
        bin.replaceSubrange(0..<headerSize, with: Data(bytes: &hdr, count: headerSize))
        bin.replaceSubrange(headerSize..<(headerSize + segSize), with: Data(bytes: &seg, count: segSize))
        bin.replaceSubrange((headerSize + segSize)..<(headerSize + segSize + sectSize), with: Data(bytes: &sect1, count: sectSize))
        bin.replaceSubrange((headerSize + segSize + sectSize)..<(headerSize + sizeofcmds), with: Data(bytes: &sect2, count: sectSize))

        // Fill 16-byte gap with non-NUL 0x41 so base[s2Off - 1] == 0x41
        bin.replaceSubrange(gapOff..<s2Off, with: Data(repeating: 0x41, count: gapSize))
        // Start Section 2 with "systemPhotoLibrary\0" straddling headStopOffset (+10)
        let targetSel = Data("systemPhotoLibrary\0".utf8)
        bin.replaceSubrange(s2Off..<(s2Off + targetSel.count), with: targetSel)

        let parsed = try MachOParser.parse(data: bin)
        XCTAssertTrue(parsed.objcMethodNames.contains("systemPhotoLibrary"), "multiSect_headStop_prev=0x41 must detect selector starting at s2Off")
        let binURL = dir.appendingPathComponent("multisect_prev0x41")
        try bin.write(to: binURL)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: binURL).riskTier, .highRisk)
    }

    func test_machoParser_embeddedInfoPlist_R6_openStepLatency_whitespaceLatency_and_nonStarvation() throws {
        func makeMultiSectionInfoPlistMachO(sections: [(offsetFromData: Int, size: Int)], backingData: Data) -> Data {
            func copyFixed16(_ str: String, into ptr: UnsafeMutableRawBufferPointer) {
                ptr.initializeMemory(as: UInt8.self, repeating: 0)
                for (i, b) in str.utf8.prefix(16).enumerated() { ptr[i] = b }
            }
            let headerSize = MemoryLayout<mach_header_64>.size
            let segSize = MemoryLayout<segment_command_64>.size
            let sectSize = MemoryLayout<section_64>.size
            let sizeofcmds = segSize + sections.count * sectSize
            let dataStart = (headerSize + sizeofcmds + 15) & ~15
            let totalSize = dataStart + backingData.count

            var hdr = mach_header_64()
            hdr.magic = MH_MAGIC_64
            hdr.cputype = CPU_TYPE_ARM64
            hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
            hdr.filetype = UInt32(MH_EXECUTE)
            hdr.ncmds = 1
            hdr.sizeofcmds = UInt32(sizeofcmds)

            var seg = segment_command_64()
            seg.cmd = UInt32(LC_SEGMENT_64)
            seg.cmdsize = UInt32(sizeofcmds)
            withUnsafeMutableBytes(of: &seg.segname) { copyFixed16("__TEXT", into: $0) }
            seg.vmaddr = 0x1_0000_0000
            seg.vmsize = UInt64(totalSize)
            seg.fileoff = 0
            seg.filesize = UInt64(totalSize)
            seg.maxprot = 5
            seg.initprot = 5
            seg.nsects = UInt32(sections.count)

            var bin = Data()
            bin.reserveCapacity(totalSize)
            bin.append(Data(bytes: &hdr, count: headerSize))
            bin.append(Data(bytes: &seg, count: segSize))
            for s in sections {
                let off = dataStart + s.offsetFromData
                var sect = section_64()
                withUnsafeMutableBytes(of: &sect.sectname) { copyFixed16("__info_plist", into: $0) }
                withUnsafeMutableBytes(of: &sect.segname) { copyFixed16("__TEXT", into: $0) }
                sect.addr = 0x1_0000_0000 + UInt64(off)
                sect.size = UInt64(s.size)
                sect.offset = UInt32(off)
                bin.append(Data(bytes: &sect, count: sectSize))
            }
            if bin.count < dataStart {
                bin.append(Data(repeating: 0, count: dataStart - bin.count))
            }
            bin.append(backingData)
            return bin
        }

        // 1. OpenStep_64x512KB_flat_keys (< 0.5s in debug)
        var openFlat = Data("{ ".utf8)
        var keyIdx = 0
        while openFlat.count < 512 * 1024 - 16 {
            openFlat.append(Data("k\(keyIdx)=v\(keyIdx);".utf8))
            keyIdx += 1
        }
        openFlat.append(Data("bad=*; }".utf8))
        var flatBacking = Data()
        flatBacking.reserveCapacity(openFlat.count + 64)
        flatBacking.append(Data(repeating: 0x20, count: 64))
        flatBacking.append(openFlat)
        let flatSections = (0..<64).map { i in (offsetFromData: 64 - i, size: openFlat.count) }
        let binFlat = makeMultiSectionInfoPlistMachO(sections: flatSections, backingData: flatBacking)
        let parsedFlat = try MachOParser.parse(data: binFlat)
        let t0 = Date()
        let plistFlat = parsedFlat.embeddedInfoPlist
        let flatElapsed = Date().timeIntervalSince(t0)
        XCTAssertNil(plistFlat)
        XCTAssertLessThan(flatElapsed, 0.5, "OpenStep_64x512KB_flat_keys took \(flatElapsed)s (must be < 0.5s)")

        // 1b. OpenStep_64x512KB_nest120 (< 0.5s in debug)
        var nestOpen = Data()
        let nestDepth = 120
        for d in 0..<nestDepth {
            nestOpen.append(Data("{ k\(d) = ".utf8))
        }
        nestOpen.append(Data("1".utf8))
        for _ in 0..<nestDepth {
            nestOpen.append(Data("; }".utf8))
        }
        // Pad to ~512 KB inside outer { ... } with flat keys + bad tail
        var nest512 = Data("{ ".utf8)
        while nest512.count < 512 * 1024 - nestOpen.count - 32 {
            nest512.append(Data("p=1;".utf8))
        }
        nest512.append(Data("n=".utf8))
        nest512.append(nestOpen)
        nest512.append(Data("; bad=*; }".utf8))
        var nestBacking = Data(repeating: 0x20, count: 64)
        nestBacking.append(nest512)
        let nestSections = (0..<64).map { i in (offsetFromData: 64 - i, size: nest512.count + i) }
        let binNest = makeMultiSectionInfoPlistMachO(sections: nestSections, backingData: nestBacking)
        let parsedNest = try MachOParser.parse(data: binNest)
        let tNest = Date()
        let plistNest = parsedNest.embeddedInfoPlist
        let nestElapsed = Date().timeIntervalSince(tNest)
        XCTAssertNil(plistNest)
        XCTAssertLessThan(nestElapsed, 0.5, "OpenStep_64x512KB_nest120 took \(nestElapsed)s (must be < 0.5s)")

        // 2. 1000x4MB_spaces_bad & 1000x4MB_spaces_plist_tag (< 0.5s in debug)
        let size4MB = 4 * 1024 * 1024
        for suffix in ["bad", "<plist>"] {
            var wsBacking = Data(repeating: 0x20, count: size4MB + 1024)
            let tail = Data(suffix.utf8)
            wsBacking.replaceSubrange((wsBacking.count - tail.count)..<wsBacking.count, with: tail)
            let wsSections = (0..<1000).map { i in (offsetFromData: i, size: size4MB + 1024 - i) }
            let binWS = makeMultiSectionInfoPlistMachO(sections: wsSections, backingData: wsBacking)
            let parsedWS = try MachOParser.parse(data: binWS)
            let tWS = Date()
            let plistWS = parsedWS.embeddedInfoPlist
            let wsElapsed = Date().timeIntervalSince(tWS)
            XCTAssertNil(plistWS)
            XCTAssertLessThan(wsElapsed, 0.5, "1000x4MB_spaces_\(suffix) took \(wsElapsed)s (must be < 0.5s)")
        }

        // 3. OpenStep_257x64KB_bad_then_valid & 2048x8KB_bad_then_valid (extracts trailing XML __info_plist)
        let validXML = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.example.sample"],
            format: .xml,
            options: 0
        )

        var badOpen64 = Data("{ ".utf8)
        while badOpen64.count < 64 * 1024 - 16 {
            badOpen64.append(Data("k=\"v\"; ".utf8))
        }
        badOpen64.append(Data("*}".utf8))
        var backing257 = Data(repeating: 0x20, count: 260)
        let open64Off = backing257.count
        backing257.append(badOpen64)
        let xml257Off = backing257.count
        backing257.append(validXML)
        var sects257 = (0..<257).map { i in (offsetFromData: open64Off - i, size: badOpen64.count) }
        sects257.append((offsetFromData: xml257Off, size: validXML.count))
        let bin257 = makeMultiSectionInfoPlistMachO(sections: sects257, backingData: backing257)
        XCTAssertEqual(
            try MachOParser.parse(data: bin257).embeddedInfoPlist?["CFBundleIdentifier"] as? String,
            "com.example.sample",
            "OpenStep_257x64KB malformed decoys must not starve trailing XML __info_plist"
        )

        var badOpen8 = Data("{ ".utf8)
        while badOpen8.count < 8 * 1024 - 16 {
            badOpen8.append(Data("k=\"v\"; ".utf8))
        }
        badOpen8.append(Data("*}".utf8))
        var backing2048 = Data(repeating: 0x20, count: 2050)
        let open8Off = backing2048.count
        backing2048.append(badOpen8)
        let xml2048Off = backing2048.count
        backing2048.append(validXML)
        var sects2048 = (0..<2048).map { i in (offsetFromData: open8Off - i, size: badOpen8.count) }
        sects2048.append((offsetFromData: xml2048Off, size: validXML.count))
        let bin2048 = makeMultiSectionInfoPlistMachO(sections: sects2048, backingData: backing2048)
        XCTAssertEqual(
            try MachOParser.parse(data: bin2048).embeddedInfoPlist?["CFBundleIdentifier"] as? String,
            "com.example.sample",
            "OpenStep_2048x8KB malformed decoys must not starve trailing XML __info_plist"
        )
    }

    // MARK: 11. Iteration 7 Remediation Regression Tests (C7, C9, C1..C4, PROBE_1A..1D, CSPRNG 500, R6_2b)

    func test_ipaScanner_C7_symAppexDecoyJson_and_C9_PBeforeZContents_detectedHighRisk() throws {
        let dir = try makeTempDir(prefix: "r7_c7_c9_pass3")

        let mainPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r7.host",
            "CFBundleExecutable": "MainApp",
            "CFBundleName": "MainApp"
        ], format: .xml, options: 0)
        let mainBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [0xD65F_03C0]
        ))

        let extPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r7.host.ext",
            "CFBundleExecutable": "Ext",
            "CFBundleName": "Ext",
            "NSExtension": ["NSExtensionPointIdentifier": "com.apple.widgetkit-extension"],
            "UIBackgroundModes": ["audio"]
        ], format: .xml, options: 0)
        let extBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main", "_OBJC_CLASS_$_" + IOCTokenArmor.tUIPasteboard],
            textInstructions: [0xD65F_03C0]
        ))

        // 1. C7a: PlugIns/Ext.appex -> ../AltStore/RealExt with colliding PlugIns/Ext.appex/decoy.json
        let c7aItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlist),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/AltStore/RealExt/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/MainApp.app/AltStore/RealExt/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/decoy.json", data: Data("{\"decoy\":true}".utf8)),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex", data: Data("../AltStore/RealExt".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let c7aIPA = dir.appendingPathComponent("c7a_decoy_json.ipa")
        try buildStoredRawZIP(c7aItems).write(to: c7aIPA)
        let f7a = try IPAPackageScanner.shared.scan(ipaURL: c7aIPA)
        XCTAssertEqual(f7a.riskTier, .highRisk, "C7a colliding decoy.json must not hide AltStore/RealExt .appex clip snooper")
        let sigs7a = Set(f7a.indicators.map(\.signature))
        XCTAssertTrue(sigs7a.contains("UIBackgroundModes(audio)+UIPasteboard"), "C7a missing UIBackgroundModes(audio)+UIPasteboard: \(sigs7a)")
        XCTAssertTrue(sigs7a.contains("ArchiveSymlinkCollision"), "C7a missing ArchiveSymlinkCollision: \(sigs7a)")

        // 2. C7b: Regular file colliding directly at PlugIns/Ext.appex alongside symlink PlugIns/Ext.appex -> ../AltStore/RealExt
        let c7bItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlist),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/AltStore/RealExt/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/MainApp.app/AltStore/RealExt/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex", data: Data("decoy".utf8)),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex", data: Data("../AltStore/RealExt".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let c7bIPA = dir.appendingPathComponent("c7b_regfile_collision.ipa")
        try buildStoredRawZIP(c7bItems).write(to: c7bIPA)
        let f7b = try IPAPackageScanner.shared.scan(ipaURL: c7bIPA)
        XCTAssertEqual(f7b.riskTier, .highRisk, "C7b regular file collision at PlugIns/Ext.appex must not hide AltStore/RealExt")
        let sigs7b = Set(f7b.indicators.map(\.signature))
        XCTAssertTrue(sigs7b.contains("UIBackgroundModes(audio)+UIPasteboard"), "C7b missing UIBackgroundModes(audio)+UIPasteboard: \(sigs7b)")
        XCTAssertTrue(sigs7b.contains("ArchiveSymlinkCollision"), "C7b missing ArchiveSymlinkCollision: \(sigs7b)")

        // 3. C9: PlugIns/Ext.appex -> ../ZExt/RealExt ('P' < 'Z') + ZExt/RealExt/Contents -> Versions/A/Contents
        let c9Items: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlist),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/ZExt/RealExt/Versions/A/Contents/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/MainApp.app/ZExt/RealExt/Versions/A/Contents/MacOS/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/ZExt/RealExt/Contents", data: Data("Versions/A/Contents".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex", data: Data("../ZExt/RealExt".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let c9IPA = dir.appendingPathComponent("c9_p_before_z.ipa")
        try buildStoredRawZIP(c9Items).write(to: c9IPA)
        let f9 = try IPAPackageScanner.shared.scan(ipaURL: c9IPA)
        XCTAssertEqual(f9.riskTier, .highRisk, "C9 P-before-Z nested directory symlink must materialize Contents/ cleanly")
        let sigs9 = Set(f9.indicators.map(\.signature))
        XCTAssertTrue(sigs9.contains("UIBackgroundModes(audio)+UIPasteboard"), "C9 missing UIBackgroundModes(audio)+UIPasteboard: \(sigs9)")
    }

    func test_csBlob_C1_C2_C3_C4_R6_5b_nonVersionedArchiveSymlinkCollisions_disqualified() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "r7_c1_c4_nonversioned_collision")
        let evilPNG = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF])
        let cleanPNG = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x01, 0x02, 0x03, 0x04])
        let tamperedPNG = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFE, 0xED, 0xFA, 0xCE])

        let emptyCR = try PropertyListSerialization.data(
            fromPropertyList: ["files": [String: Any](), "files2": [String: Any](), "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let mainPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r7.nonver",
            "CFBundleExecutable": "MainApp",
            "CFBundleName": "MainApp"
        ], format: .xml, options: 0)
        let (mainBin, rootCert) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r7.nonver",
            cryptid: 1,
            infoPlistData: mainPlistData,
            codeResourcesData: emptyCR,
            signerLeaf: state.appStoreLeaf
        )

        let extPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r7.nonver.ext",
            "CFBundleExecutable": "Ext",
            "CFBundleName": "Ext",
            "NSExtension": ["NSExtensionPointIdentifier": "com.apple.widgetkit-extension"]
        ], format: .xml, options: 0)
        let (extBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r7.nonver.ext",
            cryptid: 1,
            infoPlistData: extPlistData,
            codeResourcesData: emptyCR,
            signerLeaf: state.appStoreLeaf
        )

        let fwCRFiles: [String: Any] = [
            "Resources/clean.png": [
                "hash": Data(Insecure.SHA1.hash(data: cleanPNG)),
                "hash2": Data(SHA256.hash(data: cleanPNG))
            ]
        ]
        let fwCRData = try PropertyListSerialization.data(
            fromPropertyList: ["files": fwCRFiles, "files2": fwCRFiles, "rules": [String: Any]()],
            format: .xml,
            options: 0
        )
        let fwPlistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r7.nonver.macfw",
            "CFBundleExecutable": "MacFw",
            "CFBundleName": "MacFw"
        ], format: .xml, options: 0)
        let (fwBin, _) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: "com.test.r7.nonver.macfw",
            cryptid: 1,
            infoPlistData: fwPlistData,
            codeResourcesData: fwCRData,
            signerLeaf: state.appStoreLeaf
        )

        // Clean control: symlinked framework inside .appex with no colliding regular entries -> .appStore, .safe
        let cleanControlItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Info.plist", data: extPlistData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/A/Resources/Info.plist", data: fwPlistData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/A/MacFw", data: fwBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/A/_CodeSignature/CodeResources", data: fwCRData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/A/Resources/clean.png", data: cleanPNG),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Versions/Current", data: Data("A".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/MacFw", data: Data("Versions/Current/MacFw".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/AltFw/MacFw.framework/Resources", data: Data("Versions/Current/Resources".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Frameworks/MacFw.framework", data: Data("../AltFw/MacFw.framework".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let cleanIPA = dir.appendingPathComponent("c_clean_control.ipa")
        try buildStoredRawZIP(cleanControlItems).write(to: cleanIPA)
        let fClean = try IPAPackageScanner.shared.scan(ipaURL: cleanIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(fClean.installChannel, .appStore)
        XCTAssertEqual(fClean.riskTier, .safe)

        // C1: Unresolved symlinked .framework inside .appex + colliding Resources/evil.png
        let c1Items: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Info.plist", data: extPlistData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Frameworks/MacFw.framework", data: Data("../AltFw/MacFw.framework".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Frameworks/MacFw.framework/Resources/evil.png", data: evilPNG)
        ]
        let c1IPA = dir.appendingPathComponent("c1_appex_unres_evil_png.ipa")
        try buildStoredRawZIP(c1Items).write(to: c1IPA)
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: c1IPA, customAnchorCertificates: [rootCert]).installChannel, .developerSideloaded, "C1 must disqualify .appStore")

        // C2: Unresolved symlinked .framework inside .appex + colliding tampered Versions/A/Resources/clean.png
        let c2Items: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Info.plist", data: extPlistData),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Frameworks/MacFw.framework", data: Data("../AltFw/MacFw.framework".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Frameworks/MacFw.framework/Versions/A/Resources/clean.png", data: tamperedPNG)
        ]
        let c2IPA = dir.appendingPathComponent("c2_appex_unres_tampered_clean_png.ipa")
        try buildStoredRawZIP(c2Items).write(to: c2IPA)
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: c2IPA, customAnchorCertificates: [rootCert]).installChannel, .developerSideloaded, "C2 must disqualify .appStore")

        // C3: Unresolved symlinked .framework inside MainApp.app + colliding Resources/evil.png
        let c3Items: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework", data: Data("../AltFw/MacFw.framework".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/Frameworks/MacFw.framework/Resources/evil.png", data: evilPNG)
        ]
        let c3IPA = dir.appendingPathComponent("c3_mainapp_unres_evil_png.ipa")
        try buildStoredRawZIP(c3Items).write(to: c3IPA)
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: c3IPA, customAnchorCertificates: [rootCert]).installChannel, .developerSideloaded, "C3 must disqualify .appStore")

        // C4: Symlinked PlugIns/Ext.appex + colliding PlugIns/Ext.appex/evil.png
        let c4Items: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlistData),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/AltExt/Ext.appex/Info.plist", data: extPlistData),
            RawZIPItem(name: "Payload/MainApp.app/AltExt/Ext.appex/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/AltExt/Ext.appex/_CodeSignature/CodeResources", data: emptyCR),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex", data: Data("../AltExt/Ext.appex".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/evil.png", data: evilPNG)
        ]
        let c4IPA = dir.appendingPathComponent("c4_sym_appex_evil_png.ipa")
        try buildStoredRawZIP(c4Items).write(to: c4IPA)
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: c4IPA, customAnchorCertificates: [rootCert]).installChannel, .developerSideloaded, "C4 must disqualify .appStore")
    }

    func test_machoParser_forgedFairPlay_R7_PROBE_1A_to_1D_minimalWrappers_and_500TrialCSPRNG() throws {
        let dir = try makeTempDir(prefix: "r7_fairplay_probes")

        func patchEncryptionRange(_ bin: inout Data, offset: UInt32, size: UInt32) {
            let ncmds = bin.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
            var cur = MemoryLayout<mach_header_64>.size
            for _ in 0..<ncmds {
                let cmd = bin.withUnsafeBytes { $0.load(fromByteOffset: cur, as: UInt32.self).littleEndian }
                let csz = bin.withUnsafeBytes { $0.load(fromByteOffset: cur + 4, as: UInt32.self).littleEndian }
                if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                    var offLE = offset.littleEndian
                    var szLE = size.littleEndian
                    withUnsafeBytes(of: &offLE) { bin.replaceSubrange((cur + 8)..<(cur + 12), with: $0) }
                    withUnsafeBytes(of: &szLE) { bin.replaceSubrange((cur + 12)..<(cur + 16), with: $0) }
                    return
                }
                cur += Int(csz)
            }
        }

        func build4KFairPlayText(words leading: [UInt32], customPad: Data? = nil) -> Data {
            var allWords = leading
            let pad = customPad ?? M1TestCMSFixtures.csprngBytes(count: 4096 - allWords.count * 4)
            pad.withUnsafeBytes { raw in
                for i in stride(from: 0, to: pad.count, by: 4) {
                    allWords.append(raw.loadUnaligned(fromByteOffset: i, as: UInt32.self).littleEndian)
                }
            }
            var bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 0,
                cryptsize: 4096,
                textInstructions: allWords
            ))
            if let off = try? MachOParser.parse(data: bin).textSegment?.sections.first?.offset {
                patchEncryptionRange(&bin, offset: off, size: 4096)
            }
            return bin
        }

        let probeCases: [(name: String, words: [UInt32], minSyscalls: Int)] = [
            // PROBE_1A: adrp x2,#0; ldr x3,[x2]; cbz x3,#8; add x3,x4,x5; svc #0x80; cmp x6,x7; b.eq #8; bl #16
            ("PROBE_1A", [0x9000_0002, 0xF940_0043, 0xB400_0043, 0x8B05_0083, 0xD400_1001, 0xEB07_00DF, 0x5400_0040, 0x9400_0004], 1),
            // PROBE_1C: movz x16,#1; add x3,x4,x5; svc #0x80; eor x6,x7,x8; ret
            ("PROBE_1C", [0xD280_0030, 0x8B05_0083, 0xD400_1001, 0xCA08_00E6, 0xD65F_03C0], 1),
            // PROBE_1D: add x0,x0,x1; sub x1,x1,x2; eor x2,x2,x3; svc #0x80; csel x3,x3,x4,eq; mul x4,x4,x5
            ("PROBE_1D", [0x8B01_0000, 0xCB02_0021, 0xCA03_0042, 0xD400_1001, 0x9A84_0063, 0x9B05_7C84], 1),
            // Minimal 3-insn wrapper: [adrpX0, ldrX0, svc]
            ("WRAP_ADRP_LDR_SVC", [0x9000_0000, 0xF940_0000, 0xD400_1001], 1),
            // Minimal 4-insn wrapper: [movzX0, adrpX0, svc, ldpInsn]
            ("WRAP_MOVZ_ADRP_SVC_LDP", [0xD280_0020, 0x9000_0000, 0xD400_1001, 0xA940_07E0], 1),
            // 1-gap flankers on each side of svc #0x80
            ("GAP_FLANK", [0x9000_0000, 0xF940_0000, 0x0000_0000, 0xD400_1001, 0x0000_0000, 0x5400_0040, 0xD65F_03C0], 1)
        ]
        for (name, words, minSvc) in probeCases {
            let bin = build4KFairPlayText(words: words)
            let parsed = try MachOParser.parse(data: bin)
            XCTAssertTrue(parsed.hasForgedPlaintextFairPlayRange, "\(name) must detect forged plaintext FairPlay range")
            XCTAssertGreaterThanOrEqual(parsed.scanDirectSyscalls().totalCount, minSvc, "\(name) must detect syscalls")
            let url = dir.appendingPathComponent(name)
            try bin.write(to: url)
            XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: url).riskTier, .highRisk, "\(name) scanBinary must be .highRisk")
        }

        // PROBE_1B: 3 stubs at word offsets 10, 100, 200 inside 4 KB CSPRNG __text
        var b1Words = [UInt32](repeating: 0, count: 1024)
        M1TestCMSFixtures.csprngBytes(count: 4096).withUnsafeBytes { raw in
            for i in 0..<1024 { b1Words[i] = raw.loadUnaligned(fromByteOffset: i * 4, as: UInt32.self).littleEndian }
        }
        let stub1B: [UInt32] = [0x9000_0002, 0xF940_0043, 0x8B05_0083, 0xD400_1001, 0xCB08_00E6, 0x5400_0040, 0x9400_0004]
        for off in [10, 100, 200] {
            for (i, w) in stub1B.enumerated() { b1Words[off + i] = w }
        }
        var bin1B = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 1,
            cryptoff: 0,
            cryptsize: 4096,
            textInstructions: b1Words
        ))
        let off1B = try XCTUnwrap(try MachOParser.parse(data: bin1B).textSegment?.sections.first?.offset)
        patchEncryptionRange(&bin1B, offset: off1B, size: 4096)
        let parsed1B = try MachOParser.parse(data: bin1B)
        XCTAssertTrue(parsed1B.hasForgedPlaintextFairPlayRange, "PROBE_1B must detect 3 mixed-ARM64 stubs")
        XCTAssertGreaterThanOrEqual(parsed1B.scanDirectSyscalls().totalCount, 3)
        let url1B = dir.appendingPathComponent("PROBE_1B")
        try bin1B.write(to: url1B)
        XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: url1B).riskTier, .highRisk)

        // 500-trial negative controls: deterministic fixed-seed SplitMix64 for test_vector5 + live CSPRNG for pure 4 KB
        var vec5Rng = M1TestCMSFixtures.SplitMix64(seed: 0x5635_5237_0000_0001)
        var vec5Fp = 0
        var pure4KFp = 0
        for _ in 0..<500 {
            let vec5Bin = build4KFairPlayText(
                words: [0xD400_1001, 0xD400_1001, 0xD400_1001],
                customPad: vec5Rng.bytes(count: 4084)
            )
            if try MachOParser.parse(data: vec5Bin).hasForgedPlaintextFairPlayRange {
                vec5Fp += 1
            }
            if try MachOParser.parse(data: build4KFairPlayText(words: [])).hasForgedPlaintextFairPlayRange {
                pure4KFp += 1
            }
        }
        XCTAssertEqual(vec5Fp, 0, "500x test_vector5 (3 raw svc #0x80 + 4KB CSPRNG) must yield 0 false positives")
        XCTAssertEqual(pure4KFp, 0, "500x pure 4KB CSPRNG must yield 0 false positives")
    }

    func test_machoParser_embeddedInfoPlist_R6_2b_2048x32KBUnclosedOpenStep_nonStarvation() throws {
        func copyFixed16(_ str: String, into ptr: UnsafeMutableRawBufferPointer) {
            ptr.initializeMemory(as: UInt8.self, repeating: 0)
            for (i, b) in str.utf8.prefix(16).enumerated() { ptr[i] = b }
        }
        let validXML = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.example.r6_2b"],
            format: .xml,
            options: 0
        )
        var unclosedOpen32K = Data("{a=1;".utf8)
        unclosedOpen32K.append(Data(repeating: 0x20, count: 32 * 1024 - unclosedOpen32K.count))

        var backing = Data(repeating: 0x20, count: 2050)
        let openOff = backing.count
        backing.append(unclosedOpen32K)
        let xmlOff = backing.count
        backing.append(validXML)

        var sections: [(offsetFromData: Int, size: Int)] = (0..<2048).map { i in
            (offsetFromData: openOff - i, size: unclosedOpen32K.count)
        }
        sections.append((offsetFromData: xmlOff, size: validXML.count))

        let headerSize = MemoryLayout<mach_header_64>.size
        let segSize = MemoryLayout<segment_command_64>.size
        let sectSize = MemoryLayout<section_64>.size
        let sizeofcmds = segSize + sections.count * sectSize
        let dataStart = (headerSize + sizeofcmds + 15) & ~15
        let totalSize = dataStart + backing.count

        var hdr = mach_header_64()
        hdr.magic = MH_MAGIC_64
        hdr.cputype = CPU_TYPE_ARM64
        hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        hdr.filetype = UInt32(MH_EXECUTE)
        hdr.ncmds = 1
        hdr.sizeofcmds = UInt32(sizeofcmds)

        var seg = segment_command_64()
        seg.cmd = UInt32(LC_SEGMENT_64)
        seg.cmdsize = UInt32(sizeofcmds)
        withUnsafeMutableBytes(of: &seg.segname) { copyFixed16("__TEXT", into: $0) }
        seg.vmaddr = 0x1_0000_0000
        seg.vmsize = UInt64(totalSize)
        seg.fileoff = 0
        seg.filesize = UInt64(totalSize)
        seg.maxprot = 5
        seg.initprot = 5
        seg.nsects = UInt32(sections.count)

        var bin = Data()
        bin.reserveCapacity(totalSize)
        bin.append(Data(bytes: &hdr, count: headerSize))
        bin.append(Data(bytes: &seg, count: segSize))
        for s in sections {
            let off = dataStart + s.offsetFromData
            var sect = section_64()
            withUnsafeMutableBytes(of: &sect.sectname) { copyFixed16("__info_plist", into: $0) }
            withUnsafeMutableBytes(of: &sect.segname) { copyFixed16("__TEXT", into: $0) }
            sect.addr = 0x1_0000_0000 + UInt64(off)
            sect.size = UInt64(s.size)
            sect.offset = UInt32(off)
            bin.append(Data(bytes: &sect, count: sectSize))
        }
        if bin.count < dataStart {
            bin.append(Data(repeating: 0, count: dataStart - bin.count))
        }
        bin.append(backing)

        let parsed = try MachOParser.parse(data: bin)
        let t0 = Date()
        let plist = parsed.embeddedInfoPlist
        let elapsed = Date().timeIntervalSince(t0)
        XCTAssertEqual(plist?["CFBundleIdentifier"] as? String, "com.example.r6_2b", "2048x32KB unclosed OpenStep decoys must not starve trailing XML __info_plist")
        XCTAssertLessThan(elapsed, 0.2, "2048x32KB unclosed OpenStep scan took \(elapsed)s (must be < 0.2s)")
    }

    // MARK: 12. Iteration 8 Remediation Regression Tests (E3, E4, E5, E8, UTF-16BE leading-space, B1 inline Phase 2)

    func test_ipaScanner_R8_E3_E4_Pass3QuotaStarvation_and_E5_E8_FileVsDirCollisions() throws {
        let dir = try makeTempDir(prefix: "r8_pass3_e3_e4_e5_e8")

        let mainPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r8.host",
            "CFBundleExecutable": "MainApp",
            "CFBundleName": "MainApp"
        ], format: .xml, options: 0)
        let mainBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [0xD65F_03C0]
        ))

        let extPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.test.r8.host.ext",
            "CFBundleExecutable": "Ext",
            "CFBundleName": "Ext",
            "NSExtension": ["NSExtensionPointIdentifier": "com.apple.widgetkit-extension"],
            "UIBackgroundModes": ["audio"]
        ], format: .xml, options: 0)
        let extBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main", "_OBJC_CLASS_$_" + IOCTokenArmor.tUIPasteboard],
            textInstructions: [0xD65F_03C0]
        ))

        // 1. E3: Watch/W.app/PlugIns/Ext.appex (depth 4) -> ../../../ZExt/RealExt + 2048 .dat + ZExt/RealExt/Contents -> Versions/A/Contents
        var e3Items: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlist),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/ZExt/RealExt/Versions/A/Contents/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/MainApp.app/ZExt/RealExt/Versions/A/Contents/MacOS/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/ZExt/RealExt/Contents", data: Data("Versions/A/Contents".utf8), externalAttrs: UInt32(0o120777) << 16),
            RawZIPItem(name: "Payload/MainApp.app/Watch/W.app/PlugIns/Ext.appex", data: Data("../../../ZExt/RealExt".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        for i in 0..<2048 {
            e3Items.append(RawZIPItem(name: String(format: "Payload/MainApp.app/ZExt/RealExt/00_%04d.dat", i), data: Data([0x41])))
        }
        let e3IPA = dir.appendingPathComponent("e3_watch_depth4_2048.ipa")
        try buildStoredRawZIP(e3Items).write(to: e3IPA)
        let fE3 = try IPAPackageScanner.shared.scan(ipaURL: e3IPA)
        XCTAssertEqual(fE3.riskTier, .highRisk, "E3 must NOT drop to .safe when Pass 1+ resyncs newly materialized Contents/")
        XCTAssertTrue(
            fE3.indicators.contains { $0.signature == "UIBackgroundModes(audio)+UIPasteboard" },
            "E3 must detect UIBackgroundModes(audio)+UIPasteboard inside Watch/W.app/PlugIns/Ext.appex: \(fE3.indicators.map(\.signature))"
        )

        // 2. E4: 8 PadLinks -> SharedPad (2048 .dat) + PlugIns/Ext.appex -> ../ZExt/RealExt
        var e4Items: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlist),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/ZExt/RealExt/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/MainApp.app/ZExt/RealExt/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex", data: Data("../ZExt/RealExt".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        for i in 0..<2048 {
            e4Items.append(RawZIPItem(name: String(format: "Payload/MainApp.app/SharedPad/00_%04d.dat", i), data: Data([0x42])))
        }
        for k in 0..<8 {
            e4Items.append(RawZIPItem(
                name: "Payload/MainApp.app/PadLinks/D\(k)/L\(k)",
                data: Data("../../SharedPad".utf8),
                externalAttrs: UInt32(0o120777) << 16
            ))
        }
        let e4IPA = dir.appendingPathComponent("e4_16384_starvation.ipa")
        try buildStoredRawZIP(e4Items).write(to: e4IPA)
        let fE4 = try IPAPackageScanner.shared.scan(ipaURL: e4IPA)
        XCTAssertEqual(fE4.riskTier, .highRisk, "E4 must NOT return .safe when 8 PadLinks hit 16384 cap")
        let sigsE4 = Set(fE4.indicators.map(\.signature))
        XCTAssertTrue(sigsE4.contains("UIBackgroundModes(audio)+UIPasteboard"), "E4 missing extension detection: \(sigsE4)")
        XCTAssertTrue(sigsE4.contains("ArchiveSymlinkQuotaExceeded"), "E4 missing fail-closed quota truncation indicator: \(sigsE4)")

        // 2b. E4b: 8 PlugIns/A{0..7}.appex -> ../SharedPad (priority .appex) saturating 16384 before PlugIns/ZExt.appex
        var e4bItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlist),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/ZExt/RealExt/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/MainApp.app/ZExt/RealExt/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/ZExt.appex", data: Data("../ZExt/RealExt".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        for i in 0..<2048 {
            e4bItems.append(RawZIPItem(name: String(format: "Payload/MainApp.app/SharedPad/00_%04d.dat", i), data: Data([0x43])))
        }
        for k in 0..<8 {
            e4bItems.append(RawZIPItem(
                name: "Payload/MainApp.app/PlugIns/A\(k).appex",
                data: Data("../SharedPad".utf8),
                externalAttrs: UInt32(0o120777) << 16
            ))
        }
        let e4bIPA = dir.appendingPathComponent("e4b_appex_16384_failclosed.ipa")
        try buildStoredRawZIP(e4bItems).write(to: e4bIPA)
        let fE4b = try IPAPackageScanner.shared.scan(ipaURL: e4bIPA)
        XCTAssertEqual(fE4b.riskTier, .highRisk, "E4b must fail closed with .highRisk when 16384 cap truncates PlugIns/ZExt.appex")
        XCTAssertTrue(fE4b.indicators.contains { $0.signature == "ArchiveSymlinkQuotaExceeded" })

        // 3. E5: Regular file PlugIns/Ext.appex/Sub colliding with AltStore/RealExt/Sub/Payload directory
        let e5Items: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlist),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/AltStore/RealExt/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/MainApp.app/AltStore/RealExt/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/AltStore/RealExt/Sub/Payload", data: Data("payload".utf8)),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex/Sub", data: Data("decoy-file".utf8)),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex", data: Data("../AltStore/RealExt".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let e5IPA = dir.appendingPathComponent("e5_regfile_vs_subdir.ipa")
        try buildStoredRawZIP(e5Items).write(to: e5IPA)
        let fE5 = try IPAPackageScanner.shared.scan(ipaURL: e5IPA)
        XCTAssertEqual(fE5.riskTier, .highRisk, "E5 file-vs-dir collision inside target must not crash and must stay .highRisk")
        let sigsE5 = Set(fE5.indicators.map(\.signature))
        XCTAssertTrue(sigsE5.contains("ArchiveSymlinkCollision"), "E5 missing ArchiveSymlinkCollision: \(sigsE5)")
        XCTAssertTrue(sigsE5.contains("UIBackgroundModes(audio)+UIPasteboard"), "E5 missing .appex finding: \(sigsE5)")

        // 4. E8: Regular file PlugIns colliding with symlink PlugIns/Ext.appex -> ../AltStore/RealExt
        let e8Items: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlist),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/AltStore/RealExt/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/MainApp.app/AltStore/RealExt/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns", data: Data("decoy-parent".utf8)),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex", data: Data("../AltStore/RealExt".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        let e8IPA = dir.appendingPathComponent("e8_regfile_at_plugins_parent.ipa")
        try buildStoredRawZIP(e8Items).write(to: e8IPA)
        let fE8 = try IPAPackageScanner.shared.scan(ipaURL: e8IPA)
        XCTAssertEqual(fE8.riskTier, .highRisk, "E8 file-vs-dir collision at PlugIns parent must not crash and must stay .highRisk")
        let sigsE8 = Set(fE8.indicators.map(\.signature))
        XCTAssertTrue(sigsE8.contains("ArchiveSymlinkCollision"), "E8 missing ArchiveSymlinkCollision: \(sigsE8)")
        XCTAssertTrue(sigsE8.contains("UIBackgroundModes(audio)+UIPasteboard"), "E8 missing .appex finding: \(sigsE8)")

        // 5. E1 (9-hop >8-pass convergence overflow via nested directory materialization: Z/A0/D -> ../A1 ... Z/A8/D -> ../A9)
        var e1Items: [RawZIPItem] = [
            RawZIPItem(name: "Payload/MainApp.app/Info.plist", data: mainPlist),
            RawZIPItem(name: "Payload/MainApp.app/MainApp", data: mainBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/Z/A9/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/MainApp.app/Z/A9/Ext", data: extBin, externalAttrs: UInt32(0o100755) << 16),
            RawZIPItem(name: "Payload/MainApp.app/PlugIns/Ext.appex", data: Data("../Z/A0".utf8), externalAttrs: UInt32(0o120777) << 16)
        ]
        for idx in 0...8 {
            e1Items.append(RawZIPItem(
                name: "Payload/MainApp.app/Z/A\(idx)/D",
                data: Data("../A\(idx + 1)".utf8),
                externalAttrs: UInt32(0o120777) << 16
            ))
        }
        let e1IPA = dir.appendingPathComponent("e1_9hop_8pass_overflow.ipa")
        try buildStoredRawZIP(e1Items).write(to: e1IPA)
        let fE1 = try IPAPackageScanner.shared.scan(ipaURL: e1IPA)
        XCTAssertEqual(fE1.riskTier, .highRisk, "E1 >8-pass symlink convergence overflow must fail closed with .highRisk")
        XCTAssertTrue(
            fE1.indicators.contains { $0.signature == "ArchiveSymlinkQuotaExceeded" },
            "E1 must emit ArchiveSymlinkQuotaExceeded when 8 passes truncate unmaterialized entries: \(fE1.indicators.map(\.signature))"
        )
    }

    func test_machoParser_R8_utf16beLeadingWhitespace_embeddedInfoPlist_and_scanBinary() throws {
        let dir = try makeTempDir(prefix: "r8_utf16be_leadingspace")
        let xmlString = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.utf16.be</string>
            <key>UIBackgroundModes</key>
            <array>
                <string>audio</string>
            </array>
        </dict>
        </plist>
        """
        let utf16beBody = Data(xmlString.data(using: .utf16BigEndian)!)

        for (tag, prefixBytes) in [
            ("be1", [UInt8]([0x00, 0x20])),
            ("be5000", Array(repeating: [UInt8]([0x00, 0x20]), count: 5000).flatMap { $0 }),
            ("beTabNL", [UInt8]([0x00, 0x09, 0x00, 0x0A, 0x00, 0x0D]))
        ] {
            var plistSection = Data(prefixBytes)
            plistSection.append(utf16beBody)

            // Direct CSBlobParser.parseXMLPlist check
            let directDict = try CSBlobParser.shared.parseXMLPlist(plistSection)
            XCTAssertEqual(directDict["CFBundleIdentifier"] as? String, "com.utf16.be", "\(tag) direct parseXMLPlist failed")

            // MachOParser.embeddedInfoPlist + SecurityPipeline.scanBinary check
            let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                symbols: ["_main", "_OBJC_CLASS_$_" + IOCTokenArmor.tUIPasteboard],
                textInstructions: [0xD65F_03C0],
                customSections: [(segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: plistSection)]
            ))
            let parsed = try MachOParser.parse(data: bin)
            XCTAssertEqual(parsed.embeddedInfoPlist?["CFBundleIdentifier"] as? String, "com.utf16.be", "\(tag) embeddedInfoPlist must succeed")
            XCTAssertEqual(parsed.embeddedInfoPlist?["UIBackgroundModes"] as? [String], ["audio"], "\(tag) UIBackgroundModes missing")

            let binURL = dir.appendingPathComponent("bin_\(tag)")
            try bin.write(to: binURL)
            let finding = try SecurityPipeline.shared.scanBinary(at: binURL)
            XCTAssertEqual(finding.riskTier, .highRisk, "\(tag) scanBinary must detect .highRisk")
            XCTAssertTrue(
                finding.indicators.contains { $0.signature == "UIBackgroundModes(audio)+UIPasteboard" },
                "\(tag) missing UIBackgroundModes(audio)+UIPasteboard: \(finding.indicators.map(\.signature))"
            )
        }
    }

    func test_machoParser_R8_B1_headInlinePhase2_vs_tail_nonStarvation() throws {
        func copyFixed16(_ str: String, into ptr: UnsafeMutableRawBufferPointer) {
            ptr.initializeMemory(as: UInt8.self, repeating: 0)
            for (i, b) in str.utf8.prefix(16).enumerated() { ptr[i] = b }
        }

        let sectSize = 34 * 1024 * 1024
        let headerSize = MemoryLayout<mach_header_64>.size
        let segSize = MemoryLayout<segment_command_64>.size
        let sectCmdSize = MemoryLayout<section_64>.size
        let sizeofcmds = segSize + sectCmdSize
        let sectOff = (headerSize + sizeofcmds + 15) & ~15
        let totalSize = sectOff + sectSize

        var hdr = mach_header_64()
        hdr.magic = MH_MAGIC_64
        hdr.cputype = CPU_TYPE_ARM64
        hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL
        hdr.filetype = UInt32(MH_EXECUTE)
        hdr.ncmds = 1
        hdr.sizeofcmds = UInt32(sizeofcmds)

        var seg = segment_command_64()
        seg.cmd = UInt32(LC_SEGMENT_64)
        seg.cmdsize = UInt32(sizeofcmds)
        withUnsafeMutableBytes(of: &seg.segname) { copyFixed16("__TEXT", into: $0) }
        seg.vmaddr = 0x1_0000_0000
        seg.vmsize = UInt64(totalSize)
        seg.fileoff = 0
        seg.filesize = UInt64(totalSize)
        seg.maxprot = 5
        seg.initprot = 5
        seg.nsects = 1

        var sect = section_64()
        withUnsafeMutableBytes(of: &sect.sectname) { copyFixed16("__objc_methname", into: $0) }
        withUnsafeMutableBytes(of: &sect.segname) { copyFixed16("__TEXT", into: $0) }
        sect.addr = 0x1_0000_0000 + UInt64(sectOff)
        sect.size = UInt64(sectSize)
        sect.offset = UInt32(sectOff)
        sect.flags = UInt32(S_CSTRING_LITERALS)

        var bin = Data(repeating: 0, count: totalSize)
        bin.replaceSubrange(0..<headerSize, with: Data(bytes: &hdr, count: headerSize))
        bin.replaceSubrange(headerSize..<(headerSize + segSize), with: Data(bytes: &seg, count: segSize))
        bin.replaceSubrange((headerSize + segSize)..<(headerSize + sizeofcmds), with: Data(bytes: &sect, count: sectCmdSize))

        // Place 65,536 head selectors near offset 20.5 MB followed by 32,768 substring-matching selectors before 24 MB
        // so inline Phase 2 executes (< 4 MB remaining in headSubranges) and must respect maxGeneralBeforeTail.
        var cursor = sectOff + 20 * 1024 * 1024 + 512 * 1024
        for i in 0..<65_536 {
            let s = "h_\(i)\0"
            let bytes = Array(s.utf8)
            bin.replaceSubrange(cursor..<(cursor + bytes.count), with: bytes)
            cursor += bytes.count
        }
        for i in 0..<32_768 {
            let s = "initWithPath:_\(i)\0"
            let bytes = Array(s.utf8)
            bin.replaceSubrange(cursor..<(cursor + bytes.count), with: bytes)
            cursor += bytes.count
        }
        XCTAssertLessThan(cursor - sectOff, 24 * 1024 * 1024, "Head + inline Phase 2 test payload must finish before 24 MB headStopOffset")

        let tailProbe = "custom_NSClassFromString_probe\0"
        let tailOffset = sectOff + 27 * 1024 * 1024
        bin.replaceSubrange(tailOffset..<(tailOffset + tailProbe.utf8.count), with: Array(tailProbe.utf8))

        let parsed = try MachOParser.parse(data: bin)
        let names = parsed.objcMethodNames
        XCTAssertTrue(
            names.contains("custom_NSClassFromString_probe"),
            "Inline Phase 2 in headSubranges must respect maxGeneralBeforeTail and not starve tailSubranges substring matches"
        )
    }

    // MARK: 13. Iteration 9 Remediation Regression Tests (FairPlay 1-Gap Penalty & parseXMLPlist Empty Decoy Step 2/3)

    func test_machoParser_R9_forgedFairPlay_C1_gapPenaltyRegression_WRAP200_and_500CSPRNG() throws {
        let dir = try makeTempDir(prefix: "r9_fairplay_gap_penalty")

        func patchEncryptionRange(_ bin: inout Data, offset: UInt32, size: UInt32) {
            let ncmds = bin.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self).littleEndian }
            var cur = MemoryLayout<mach_header_64>.size
            for _ in 0..<ncmds {
                let cmd = bin.withUnsafeBytes { $0.load(fromByteOffset: cur, as: UInt32.self).littleEndian }
                let csz = bin.withUnsafeBytes { $0.load(fromByteOffset: cur + 4, as: UInt32.self).littleEndian }
                if cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                    var offLE = offset.littleEndian
                    var szLE = size.littleEndian
                    withUnsafeBytes(of: &offLE) { bin.replaceSubrange((cur + 8)..<(cur + 12), with: $0) }
                    withUnsafeBytes(of: &szLE) { bin.replaceSubrange((cur + 12)..<(cur + 16), with: $0) }
                    return
                }
                cur += Int(csz)
            }
        }

        func build4KFairPlayText(words leading: [UInt32], customPad: Data? = nil) -> Data {
            var allWords = leading
            let pad = customPad ?? M1TestCMSFixtures.csprngBytes(count: 4096 - allWords.count * 4)
            pad.withUnsafeBytes { raw in
                for i in stride(from: 0, to: pad.count, by: 4) {
                    allWords.append(raw.loadUnaligned(fromByteOffset: i, as: UInt32.self).littleEndian)
                }
            }
            var bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 1,
                cryptoff: 0,
                cryptsize: 4096,
                textInstructions: allWords
            ))
            if let off = try? MachOParser.parse(data: bin).textSegment?.sections.first?.offset {
                patchEncryptionRange(&bin, offset: off, size: 4096)
            }
            return bin
        }

        // 1. Deterministic C1_det_gap_penalty_ADRP_LDR_SVC (fwd gap + sc=2 must not drop runScore 12 -> 10)
        //    and symmetric backward gap variant
        let detCases: [(name: String, words: [UInt32])] = [
            ("C1_det_gap_penalty_ADRP_LDR_SVC", [0x9000_0000, 0xF940_0000, 0xD400_1001, 0xFFFF_FFFF, 0x9140_0000, 0xFFFF_FFFF]),
            ("C1_det_back_gap_penalty_ADRP_LDR_SVC", [0xFFFF_FFFF, 0x9140_0000, 0xFFFF_FFFF, 0x9000_0000, 0xF940_0000, 0xD400_1001])
        ]
        for (name, words) in detCases {
            let bin = build4KFairPlayText(words: words)
            let parsed = try MachOParser.parse(data: bin)
            XCTAssertTrue(parsed.hasForgedPlaintextFairPlayRange, "\(name) must detect forged plaintext FairPlay range")
            XCTAssertGreaterThanOrEqual(parsed.scanDirectSyscalls().totalCount, 1, "\(name) must report direct syscall")
            let url = dir.appendingPathComponent(name)
            try bin.write(to: url)
            XCTAssertEqual(try SecurityPipeline.shared.scanBinary(at: url).riskTier, .highRisk, "\(name) scanBinary must be .highRisk")
        }

        // 2. 200-trial WRAP_ADRP_LDR_SVC with CSPRNG trailing bytes (must hit 200/200)
        var wrapHits = 0
        for _ in 0..<200 {
            let bin = build4KFairPlayText(words: [0x9000_0000, 0xF940_0000, 0xD400_1001])
            let parsed = try MachOParser.parse(data: bin)
            if parsed.hasForgedPlaintextFairPlayRange && parsed.scanDirectSyscalls().totalCount >= 1 {
                wrapHits += 1
            }
        }
        XCTAssertEqual(wrapHits, 200, "WRAP_ADRP_LDR_SVC must hit 200/200 CSPRNG trailing-byte trials")

        // 3. 500-trial negative controls: deterministic fixed-seed SplitMix64 for test_vector5 + live CSPRNG for pure 4 KB
        var vec5Rng = M1TestCMSFixtures.SplitMix64(seed: 0x5635_5239_0000_0001)
        var vec5Fp = 0
        var pure4KFp = 0
        for _ in 0..<500 {
            let vec5Bin = build4KFairPlayText(
                words: [0xD400_1001, 0xD400_1001, 0xD400_1001],
                customPad: vec5Rng.bytes(count: 4084)
            )
            if try MachOParser.parse(data: vec5Bin).hasForgedPlaintextFairPlayRange {
                vec5Fp += 1
            }
            if try MachOParser.parse(data: build4KFairPlayText(words: [])).hasForgedPlaintextFairPlayRange {
                pure4KFp += 1
            }
        }
        XCTAssertEqual(vec5Fp, 0, "500x test_vector5 CSPRNG must yield 0 false positives")
        XCTAssertEqual(pure4KFp, 0, "500x pure 4KB CSPRNG must yield 0 false positives")
    }

    func test_csBlob_R9_A_emptyDecoy2_be_sp_utf8TrailingNul_and_wsThenBeBOM() throws {
        let decoyXML = "<plist version=\"1.0\"><dict/></plist><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.r8.decoy2</string></dict></plist>"
        let utf16beBody = Data(decoyXML.data(using: .utf16BigEndian)!)

        var beWithLeadSpace = Data([0x00, 0x20])
        beWithLeadSpace.append(utf16beBody)

        var utf8WithTrailingNul = Data(decoyXML.utf8)
        utf8WithTrailingNul.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        var utf8WithTrailingGarbage = Data(decoyXML.utf8)
        utf8WithTrailingGarbage.append(Data("<TRAILING_GARBAGE".utf8))

        for (tag, payload) in [
            ("A_emptyDecoy2_be_sp", beWithLeadSpace),
            ("A_emptyDecoy2_be_noSp", utf16beBody),
            ("A_emptyDecoy2_utf8_nul", utf8WithTrailingNul)
        ] {
            let csDict = try CSBlobParser.shared.parseXMLPlist(payload)
            XCTAssertEqual(csDict["CFBundleIdentifier"] as? String, "com.r8.decoy2", "\(tag) CSBlobParser.parseXMLPlist failed")

            let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                symbols: ["_main"],
                textInstructions: [0xD65F_03C0],
                customSections: [(segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: payload)]
            ))
            let parsed = try MachOParser.parse(data: bin)
            XCTAssertEqual(parsed.embeddedInfoPlist?["CFBundleIdentifier"] as? String, "com.r8.decoy2", "\(tag) MachOParser.embeddedInfoPlist failed")
        }

        // findMatchingPlistEnd fallback path (Step 3 catch branch) must also skip leading empty <plist><dict/></plist>
        let trimmedFallbackDict = try CSBlobParser.shared.parseXMLPlist(utf8WithTrailingGarbage)
        XCTAssertEqual(trimmedFallbackDict["CFBundleIdentifier"] as? String, "com.r8.decoy2")

        // A_ws_then_beBOM: leading UTF-16BE whitespace followed by UTF-16BE BOM (0xFE 0xFF)
        let bomXML = "<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.r9.wsbom</string></dict></plist>"
        var wsThenBeBOM = Data([0x00, 0x20, 0xFE, 0xFF])
        wsThenBeBOM.append(Data(bomXML.data(using: .utf16BigEndian)!))
        let wsBomDict = try CSBlobParser.shared.parseXMLPlist(wsThenBeBOM)
        XCTAssertEqual(wsBomDict["CFBundleIdentifier"] as? String, "com.r9.wsbom")

        let bomBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [0xD65F_03C0],
            customSections: [(segName: "__TEXT", sectName: "__info_plist", flags: 0, payload: wsThenBeBOM)]
        ))
        let parsedBomBin = try MachOParser.parse(data: bomBin)
        XCTAssertEqual(parsedBomBin.embeddedInfoPlist?["CFBundleIdentifier"] as? String, "com.r9.wsbom")
    }

    // MARK: - Issue #2 Real-World IPA ZIP Edge Cases (GPFlag 0x0008 Without DD, Deflated Dirs, Zero Padding, Uncompacted Orphans)

    func test_issue2_realWorldIPA_gpFlagBit3WithoutDD_deflatedDir_zeroPad_andUncompactedAppex_scansCleanlyWhileCatchingOrphanMachO() throws {
        let dir = try makeTempDir(prefix: "issue2_zip")
        let cleanMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [0xD65F_03C0]
        ))
        let cleanExtExec = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_NSExtensionMain"],
            textInstructions: [0xD65F_03C0]
        ))
        let evilExtExec = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            textInstructions: [0xD400_1001, 0xD65F_03C0]
        ))

        let mainPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.picsart.studio",
            "CFBundleExecutable": "Picsart",
            "CFBundleShortVersionString": "1.0"
        ], format: .xml, options: 0)
        let extPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.picsart.studio.CommentPushExtension",
            "CFBundleExecutable": "CommentPushExtension",
            "CFBundleShortVersionString": "1.0"
        ], format: .xml, options: 0)

        struct Issue2ZipItem {
            var path: String
            var payload: Data
            var method: UInt16 = 0
            var gpFlags: UInt16 = 0
            var unixMode: UInt32 = 0o100644
            var localZeroFields: Bool = false
            var localCompOverride: UInt32? = nil
            var trailingGap: Data = Data()
            var omitFromCD: Bool = false
        }

        func crc32(_ data: Data) -> UInt32 {
            data.withUnsafeBytes { raw in
                guard let base = raw.bindMemory(to: Bytef.self).baseAddress else { return 0 }
                return UInt32(truncatingIfNeeded: zlib.crc32(0, base, uInt(data.count)))
            }
        }

        func appendLe16(_ d: inout Data, _ v: UInt16) {
            var le = v.littleEndian
            d.append(Data(bytes: &le, count: 2))
        }
        func appendLe32(_ d: inout Data, _ v: UInt32) {
            var le = v.littleEndian
            d.append(Data(bytes: &le, count: 4))
        }

        func assembleZip(_ items: [Issue2ZipItem]) -> Data {
            var archive = Data()
            var cd = Data()
            var cdCount: UInt16 = 0
            for item in items {
                let off = UInt32(archive.count)
                let nameData = Data(item.path.utf8)
                let itemCRC = crc32(item.payload)
                let lComp = item.localCompOverride ?? (item.localZeroFields ? 0 : UInt32(item.payload.count))
                let lUncomp = item.localZeroFields ? 0 : UInt32(item.method == 8 && item.path.hasSuffix("/") ? 0 : item.payload.count)
                let lCRC = item.localZeroFields ? 0 : itemCRC

                var lh = Data()
                appendLe32(&lh, 0x0403_4b50)
                appendLe16(&lh, 20)
                appendLe16(&lh, item.gpFlags)
                appendLe16(&lh, item.method)
                appendLe16(&lh, 0); appendLe16(&lh, 0)
                appendLe32(&lh, lCRC)
                appendLe32(&lh, lComp)
                appendLe32(&lh, lUncomp)
                appendLe16(&lh, UInt16(nameData.count))
                appendLe16(&lh, 0)
                archive.append(lh)
                archive.append(nameData)
                archive.append(item.payload)
                archive.append(item.trailingGap)

                guard !item.omitFromCD else { continue }
                cdCount &+= 1
                var cdr = Data()
                appendLe32(&cdr, 0x0201_4b50)
                appendLe16(&cdr, 0x0314); appendLe16(&cdr, 20)
                appendLe16(&cdr, item.gpFlags)
                appendLe16(&cdr, item.method)
                appendLe16(&cdr, 0); appendLe16(&cdr, 0)
                appendLe32(&cdr, itemCRC)
                appendLe32(&cdr, UInt32(item.payload.count))
                appendLe32(&cdr, UInt32(item.method == 8 && item.path.hasSuffix("/") ? 0 : item.payload.count))
                appendLe16(&cdr, UInt16(nameData.count))
                appendLe16(&cdr, 0); appendLe16(&cdr, 0); appendLe16(&cdr, 0); appendLe16(&cdr, 0)
                appendLe32(&cdr, item.unixMode << 16)
                appendLe32(&cdr, off)
                cd.append(cdr)
                cd.append(nameData)
            }
            let cdOff = UInt32(archive.count)
            archive.append(cd)
            appendLe32(&archive, 0x0605_4b50)
            appendLe16(&archive, 0); appendLe16(&archive, 0)
            appendLe16(&archive, cdCount); appendLe16(&archive, cdCount)
            appendLe32(&archive, UInt32(cd.count))
            appendLe32(&archive, cdOff)
            appendLe16(&archive, 0)
            return archive
        }

        // 1. Real-world `.appex` entries with GPFlag 0x0808 (bit 3 set, descLen == 0), deflated empty directory (`0x03 0x00`),
        //    16-byte Data Descriptor + NUL alignment padding, and an uncompacted superseded Info.plist orphan header.
        let extPlistCRC = crc32(extPlist)
        var ddAndZeroPad = Data()
        appendLe32(&ddAndZeroPad, 0x0807_4b50)
        appendLe32(&ddAndZeroPad, extPlistCRC)
        appendLe32(&ddAndZeroPad, UInt32(extPlist.count))
        appendLe32(&ddAndZeroPad, UInt32(extPlist.count))
        ddAndZeroPad.append(Data(repeating: 0x00, count: 8))

        let compatZip = assembleZip([
            Issue2ZipItem(path: "Payload/Picsart.app/PlugIns/CommentPushExtension.appex/Info.plist", payload: extPlist, omitFromCD: true),
            Issue2ZipItem(path: "Payload/", payload: Data(), unixMode: 0o040755),
            Issue2ZipItem(path: "Payload/Picsart.app/", payload: Data(), unixMode: 0o040755),
            Issue2ZipItem(path: "Payload/Picsart.app/PlugIns/", payload: Data(), unixMode: 0o040755),
            Issue2ZipItem(
                path: "Payload/Picsart.app/PlugIns/CommentPushExtension.appex/",
                payload: Data([0x03, 0x00]),
                method: 8,
                gpFlags: 0x0808,
                unixMode: 0o040755
            ),
            Issue2ZipItem(
                path: "Payload/Picsart.app/PlugIns/CommentPushExtension.appex/Info.plist",
                payload: extPlist,
                gpFlags: 0x0808,
                localZeroFields: true,
                trailingGap: ddAndZeroPad
            ),
            Issue2ZipItem(
                path: "Payload/Picsart.app/PlugIns/CommentPushExtension.appex/CommentPushExtension",
                payload: cleanExtExec,
                gpFlags: 0x0808,
                unixMode: 0o100755,
                trailingGap: Data(repeating: 0x00, count: 4)
            ),
            Issue2ZipItem(path: "Payload/Picsart.app/Info.plist", payload: mainPlist, gpFlags: 0x0008),
            Issue2ZipItem(path: "Payload/Picsart.app/Picsart", payload: cleanMain, unixMode: 0o100755)
        ])
        let compatURL = dir.appendingPathComponent("compat_picsart.ipa")
        try compatZip.write(to: compatURL)
        let compatFinding = try IPAPackageScanner.shared.scan(ipaURL: compatURL)
        XCTAssertEqual(compatFinding.bundleId, "com.picsart.studio")
        XCTAssertEqual(compatFinding.riskTier, .safe)

        // 2. Uncompacted archive smuggling an unreferenced orphan Mach-O carrying `svc #0x80` MUST still be caught `.highRisk`
        let orphanMachOZip = assembleZip([
            Issue2ZipItem(path: "Payload/Picsart.app/Info.plist", payload: mainPlist),
            Issue2ZipItem(path: "Payload/Picsart.app/Picsart", payload: cleanMain, unixMode: 0o100755),
            Issue2ZipItem(
                path: "Payload/Picsart.app/PlugIns/CommentPushExtension.appex/HiddenEvil",
                payload: evilExtExec,
                unixMode: 0o100755,
                omitFromCD: true
            )
        ])
        let orphanMachOURL = dir.appendingPathComponent("orphan_evil_macho.ipa")
        try orphanMachOZip.write(to: orphanMachOURL)
        let orphanFinding = try IPAPackageScanner.shared.scan(ipaURL: orphanMachOURL)
        XCTAssertEqual(orphanFinding.riskTier, .highRisk)
        XCTAssertTrue(orphanFinding.indicators.contains { $0.signature == "arm64:svc_0x80" })

        // 3. Conflicting non-zero Local Header compressedSize when GPFlag 0x0008 is set and DD omitted -> still rejected as corruptHeader
        let conflictBit3Zip = assembleZip([
            Issue2ZipItem(path: "Payload/Picsart.app/Info.plist", payload: mainPlist, gpFlags: 0x0008, localCompOverride: 1),
            Issue2ZipItem(path: "Payload/Picsart.app/Picsart", payload: cleanMain, unixMode: 0o100755)
        ])
        let conflictBit3URL = dir.appendingPathComponent("conflict_bit3.ipa")
        try conflictBit3Zip.write(to: conflictBit3URL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: conflictBit3URL)) { err in
            guard case IPAPackageScannerError.corruptHeader = err else {
                XCTFail("Expected corruptHeader on conflicting bit-3 local size, got \(err)")
                return
            }
        }
    }
}
