//
//  AdversarialV130Round4ParserFuzzTests.swift
//  WQGuardCoreTests
//
//  Independent Adversarial Red-Team Challenger (Round 4): Parser & Archive Robustness / Fuzzing.
//
//  NEW vectors only (Rounds 1-3 covered svc literal/metadata FP torture, arch filtering, FAT arm64/arm64e
//  shadowing, custom RX sections, fake partial FairPlay, DoS caps, 2026 exploit catalog, firmware posture,
//  bilingual output and read-only invariance). This round attacks the *container parsers* themselves:
//
//  A. ZIP/IPA scanner-vs-installer differentials: duplicate entry names, case-folding collisions,
//     multiple .app bundles, CFBundleExecutable path traversal, Mach-O files hidden behind non-.dylib
//     extensions / archive symlinks, central-directory vs local-header name & method mismatch, orphan local
//     headers, fake EOCD inside the archive comment, understated EOCD entry count / CD size, data
//     descriptors, ZIP64 sentinel abuse, 20,000-entry boundary, Info.plist format variants, Payload case.
//  B. Mach-O: svc #0x80 in executable segment bytes not covered by any section header (header-padding code
//     cave, nsects=0 segment, S_ZEROFILL-typed section inside filesize), nsects/cmdsize mismatch, section
//     offset/size integer overflow, FAT topology abuse (overlap, zero-size, self-referential, nested FAT,
//     FAT64 overflow, nfat cap), MH_CIGAM_64, duplicate LC_ENCRYPTION_INFO_64 ordering, LC_SYMTAB strx abuse,
//     malformed/self-referential CS SuperBlob indices and DER depth bombs, Data-slice (startIndex != 0) API.
//  C. Deterministic seeded mini-fuzzers (SplitMix64): Mach-O/FAT mutation (900 iterations), ZIP reader
//     mutation (1000 iterations), full IPA scan mutation (300 iterations) with per-iteration time bounds and
//     byte-identical read-only invariant on every scanned input file.
//
//  Every assertion encodes the SECURE expectation: detect the malicious payload OR fail closed with a typed
//  error; never silently grade a malicious payload `.safe`; never crash. Tests tagged "[R4 DEFECT]" in their
//  failure messages expose real defects and are intentionally left failing until Sources/ are fixed.
//

import XCTest
import Foundation
import MachO
import zlib
@testable import WQGuardCore

// MARK: - Little/Big-Endian Data Writers (file-private to avoid cross-file symbol clashes)

fileprivate extension Data {
    mutating func r4le16(_ v: UInt16) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r4le32(_ v: UInt32) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r4le64(_ v: UInt64) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r4be32(_ v: UInt32) { var x = v.bigEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r4be64(_ v: UInt64) { var x = v.bigEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
}

/// Deterministic, seedable PRNG so every fuzz failure is reproducible from its seed + iteration index.
fileprivate struct R4SplitMix64 {
    var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
    mutating func int(_ upperExclusive: Int) -> Int {
        guard upperExclusive > 1 else { return 0 }
        return Int(next() % UInt64(upperExclusive))
    }
}

final class AdversarialV130Round4ParserFuzzTests: XCTestCase {

    private static let svc: UInt32 = 0xD400_1001
    private static let nop: UInt32 = 0xD503_201F
    private static let ret: UInt32 = 0xD65F_03C0
    private static let svcSig = "arm64:svc_0x80"
    private static let instrFlags = UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS)

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
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
            try? FileManager.default.removeItem(at: url)
        }
        tempURLs.removeAll()
        super.tearDown()
    }

    // MARK: - Binary Fixtures

    private static func le(_ words: [UInt32]) -> Data {
        var d = Data()
        for w in words { d.r4le32(w) }
        return d
    }

    private func maliciousBinary() -> Data {
        SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.nop, Self.svc, Self.ret]
        ))
    }

    private func cleanBinary() -> Data {
        SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.nop, Self.nop, Self.ret]
        ))
    }

    private func infoPlist(
        exec: Any,
        bundleId: String = "com.redteam.r4.parser",
        format: PropertyListSerialization.PropertyListFormat = .xml
    ) -> Data {
        let dict: [String: Any] = [
            "CFBundleIdentifier": bundleId,
            "CFBundleExecutable": exec,
            "CFBundleName": "R4App",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "CFBundlePackageType": "APPL"
        ]
        return (try? PropertyListSerialization.data(fromPropertyList: dict, format: format, options: 0)) ?? Data()
    }

    // MARK: - Raw zlib helpers

    private static func rawDeflate(_ input: Data) -> Data {
        var strm = z_stream()
        guard deflateInit2_(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY,
                            ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else { return Data() }
        defer { deflateEnd(&strm) }
        var out = [UInt8](repeating: 0, count: Int(deflateBound(&strm, uLong(input.count))) + 64)
        let outCount = out.count
        input.withUnsafeBytes { inPtr in
            out.withUnsafeMutableBufferPointer { outPtr in
                strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
                strm.avail_in = uInt(input.count)
                strm.next_out = outPtr.baseAddress
                strm.avail_out = uInt(outCount)
                _ = deflate(&strm, Z_FINISH)
            }
        }
        return Data(out[0..<(outCount - Int(strm.avail_out))])
    }

    private static func crc(_ input: Data) -> UInt32 {
        input.withUnsafeBytes { raw in
            UInt32(crc32(0, raw.bindMemory(to: Bytef.self).baseAddress, uInt(input.count)))
        }
    }

    // MARK: - Hand-rolled ZIP builder with full control over CD / local header / EOCD fields

    private struct ZipEntry {
        var name: String
        var data: Data
        var method: UInt16 = 0
        var cdName: String? = nil
        var cdMethod: UInt16? = nil
        var unixMode: UInt32 = 0o100644
        var dataDescriptor = false
        var cdExtra = Data()
        var cdCompRaw: UInt32? = nil
        var cdUncompRaw: UInt32? = nil
        var cdOffsetRaw: UInt32? = nil
        var omitFromCD = false
        var inDecoyCD = true
    }

    private struct BuiltZip {
        var data: Data
        var localOffsets: [Int]
        var cdOffset: Int
    }

    private func buildZip(
        _ entries: [ZipEntry],
        eocdCountOverride: UInt16? = nil,
        cdSizeOverride: UInt32? = nil,
        fakeEOCDDecoy: Bool = false
    ) -> BuiltZip {
        var out = Data()
        var records: [Data] = []
        var decoyRecords: [Data] = []
        var offsets: [Int] = []

        for e in entries {
            let payload = e.method == 8 ? Self.rawDeflate(e.data) : e.data
            let crc = Self.crc(e.data)
            let localOffset = out.count
            offsets.append(localOffset)
            let nameBytes = Data(e.name.utf8)
            let flags: UInt16 = e.dataDescriptor ? 0x0008 : 0

            out.r4le32(0x0403_4b50); out.r4le16(20); out.r4le16(flags); out.r4le16(e.method)
            out.r4le16(0); out.r4le16(0x21)
            out.r4le32(e.dataDescriptor ? 0 : crc)
            out.r4le32(e.dataDescriptor ? 0 : UInt32(payload.count))
            out.r4le32(e.dataDescriptor ? 0 : UInt32(e.data.count))
            out.r4le16(UInt16(nameBytes.count)); out.r4le16(0)
            out.append(nameBytes)
            out.append(payload)
            if e.dataDescriptor {
                out.r4le32(0x0807_4b50); out.r4le32(crc); out.r4le32(UInt32(payload.count)); out.r4le32(UInt32(e.data.count))
            }
            if e.omitFromCD { continue }

            var rec = Data()
            let cdNameBytes = Data((e.cdName ?? e.name).utf8)
            rec.r4le32(0x0201_4b50); rec.r4le16(0x0314); rec.r4le16(20); rec.r4le16(flags)
            rec.r4le16(e.cdMethod ?? e.method); rec.r4le16(0); rec.r4le16(0x21)
            rec.r4le32(crc)
            rec.r4le32(e.cdCompRaw ?? UInt32(payload.count))
            rec.r4le32(e.cdUncompRaw ?? UInt32(e.data.count))
            rec.r4le16(UInt16(cdNameBytes.count)); rec.r4le16(UInt16(e.cdExtra.count)); rec.r4le16(0)
            rec.r4le16(0); rec.r4le16(0)
            rec.r4le32(e.unixMode << 16)
            rec.r4le32(e.cdOffsetRaw ?? UInt32(localOffset))
            rec.append(cdNameBytes)
            rec.append(e.cdExtra)
            records.append(rec)
            if e.inDecoyCD { decoyRecords.append(rec) }
        }

        let cdOffset = out.count
        var cd = Data()
        for r in records { cd.append(r) }
        out.append(cd)

        var comment = Data()
        if fakeEOCDDecoy {
            let decoyOffset = out.count
            var decoy = Data()
            for r in decoyRecords { decoy.append(r) }
            out.append(decoy)
            comment.r4le32(0x0605_4b50); comment.r4le16(0); comment.r4le16(0)
            comment.r4le16(UInt16(decoyRecords.count)); comment.r4le16(UInt16(decoyRecords.count))
            comment.r4le32(UInt32(decoy.count)); comment.r4le32(UInt32(decoyOffset)); comment.r4le16(0)
        }

        let count = eocdCountOverride ?? UInt16(truncatingIfNeeded: records.count)
        out.r4le32(0x0605_4b50); out.r4le16(0); out.r4le16(0)
        out.r4le16(count); out.r4le16(count)
        out.r4le32(cdSizeOverride ?? UInt32(cd.count)); out.r4le32(UInt32(cdOffset))
        out.r4le16(UInt16(comment.count))
        out.append(comment)
        return BuiltZip(data: out, localOffsets: offsets, cdOffset: cdOffset)
    }

    private func appEntries(
        root: String = "Payload/R4App.app/",
        exec: Data,
        execName: String = "R4App",
        plist: Data? = nil
    ) -> [ZipEntry] {
        [
            ZipEntry(name: root + "Info.plist", data: plist ?? infoPlist(exec: execName)),
            ZipEntry(name: root + execName, data: exec, unixMode: 0o100755)
        ]
    }

    private func writeIPA(_ data: Data, _ tag: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("r4_\(tag)_\(UUID().uuidString).ipa")
        try data.write(to: url)
        tempURLs.append(url)
        return url
    }

    /// SECURE expectation for an IPA that ships a svc #0x80 payload the device will install/execute:
    /// either `.highRisk` with the `arm64:svc_0x80` indicator, or fail closed with a thrown error.
    private func assertNotSilentlySafe(_ zip: Data, _ label: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let url = try writeIPA(zip, "evasion")
        do {
            let finding = try IPAPackageScanner.shared.scan(ipaURL: url)
            XCTAssertEqual(finding.riskTier, .highRisk,
                           "[R4 DEFECT] \(label): IPA shipping a svc #0x80 payload was graded \(finding.riskTier) instead of failing closed or .highRisk",
                           file: file, line: line)
            XCTAssertTrue(finding.indicators.contains { $0.signature == Self.svcSig },
                          "[R4 DEFECT] \(label): no \(Self.svcSig) indicator emitted", file: file, line: line)
        } catch {
            // Fail-closed with a typed error is an acceptable secure outcome.
        }
    }

    private func assertDetects(_ zip: Data, _ label: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let url = try writeIPA(zip, "detect")
        let finding = try IPAPackageScanner.shared.scan(ipaURL: url)
        XCTAssertEqual(finding.riskTier, .highRisk, "\(label): expected .highRisk, got \(finding.riskTier)", file: file, line: line)
        XCTAssertTrue(finding.indicators.contains { $0.signature == Self.svcSig }, "\(label): missing \(Self.svcSig)", file: file, line: line)
    }

    private static func caseName(_ error: Error) -> String {
        if let label = Mirror(reflecting: error).children.first?.label { return label }
        return String(describing: error).components(separatedBy: "(").first ?? ""
    }

    // MARK: - A0. Harness controls (builder sanity)

    func test_zip_harnessControl_cleanSafe_maliciousHighRisk_dataDescriptorAndDeflateDetected() throws {
        let cleanURL = try writeIPA(buildZip(appEntries(exec: cleanBinary())).data, "clean")
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: cleanURL).riskTier, .safe, "Hand-rolled ZIP builder control: clean IPA must be .safe")

        try assertDetects(buildZip(appEntries(exec: maliciousBinary())).data, "STORE control")

        var deflated = appEntries(exec: maliciousBinary())
        deflated[1].method = 8
        try assertDetects(buildZip(deflated).data, "DEFLATE control")

        // Data-descriptor (general purpose flag bit 3) entries: local header sizes/CRC are zero; CD is authoritative.
        var dd = appEntries(exec: maliciousBinary())
        for i in dd.indices { dd[i].dataDescriptor = true; dd[i].method = 8 }
        try assertDetects(buildZip(dd).data, "Data-descriptor (flag bit 3) + DEFLATE")
    }

    // MARK: - A1. Duplicate entry names (scanner last-write-wins vs installer first-wins)

    func test_zip_duplicateEntryNames_maliciousFirstCleanLast_mustNotGradeSafe() throws {
        // Control: clean first, malicious last -> extracted file is the malicious one -> detected.
        var ctrl = appEntries(exec: cleanBinary())
        ctrl.append(ZipEntry(name: "Payload/R4App.app/R4App", data: maliciousBinary(), unixMode: 0o100755))
        try assertDetects(buildZip(ctrl).data, "Duplicate entry control (malicious last)")

        // Attack: malicious first, clean shadow last. The sandbox `.atomic` write keeps only the LAST copy, so the
        // scanner audits the clean shadow while any first-wins extractor installs the malicious executable.
        var attack = appEntries(exec: maliciousBinary())
        attack.append(ZipEntry(name: "Payload/R4App.app/R4App", data: cleanBinary(), unixMode: 0o100755))
        try assertNotSilentlySafe(buildZip(attack).data, "Duplicate ZIP entry names (malicious first, clean shadow last)")
    }

    // MARK: - A2. Case-folding collision on case-insensitive host volumes

    func test_zip_caseFoldingCollision_executableShadowedByLowercaseTwin_mustNotGradeSafe() throws {
        let probeDir = FileManager.default.temporaryDirectory.appendingPathComponent("r4_caseprobe_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: probeDir, withIntermediateDirectories: true)
        tempURLs.append(probeDir)
        try Data([1]).write(to: probeDir.appendingPathComponent("CaseProbe"))
        let caseInsensitive = FileManager.default.fileExists(atPath: probeDir.appendingPathComponent("caseprobe").path)
        try XCTSkipUnless(caseInsensitive, "Host temporary volume is case-sensitive; collision vector not applicable")

        // iOS data volumes are case-SENSITIVE: `R4App` (malicious, CFBundleExecutable) and `r4app` (clean) are two
        // distinct files on device. On a case-insensitive macOS sandbox the second write replaces the first.
        var entries = appEntries(exec: maliciousBinary())
        entries.append(ZipEntry(name: "Payload/R4App.app/r4app", data: cleanBinary(), unixMode: 0o100755))
        try assertNotSilentlySafe(buildZip(entries).data, "Case-folding collision R4App vs r4app on case-insensitive sandbox")
    }

    // MARK: - A3. Multiple .app bundles in Payload/

    func test_zip_multipleAppBundles_cleanDecoyFirst_maliciousSecond_mustNotGradeSafe() throws {
        var entries = appEntries(root: "Payload/Decoy.app/", exec: cleanBinary(), execName: "Decoy")
        entries += appEntries(root: "Payload/Evil.app/", exec: maliciousBinary(), execName: "Evil")
        try assertNotSilentlySafe(buildZip(entries).data, "Multiple .app bundles (only the first is audited)")
    }

    // MARK: - A4. CFBundleExecutable path traversal / directory / empty

    func test_zip_cfBundleExecutableTraversal_readsHostFileOutsideSandbox_mustFailClosed() throws {
        try XCTSkipUnless(FileManager.default.fileExists(atPath: "/bin/ls"), "/bin/ls not present on host")
        let traversal = String(repeating: "../", count: 32) + "bin/ls"
        let entries = appEntries(exec: maliciousBinary(), plist: infoPlist(exec: traversal))
        let url = try writeIPA(buildZip(entries).data, "traversal")
        do {
            let finding = try IPAPackageScanner.shared.scan(ipaURL: url)
            XCTAssertFalse(finding.executablePath?.contains("..") ?? false,
                           "[R4 DEFECT] CFBundleExecutable '\(traversal)' escaped the extraction sandbox: scanner parsed a HOST binary (\(finding.executablePath ?? "nil")) as the app's main executable")
            XCTAssertEqual(finding.riskTier, .highRisk,
                           "[R4 DEFECT] CFBundleExecutable traversal: real malicious R4App never audited; graded \(finding.riskTier)")
        } catch {
            // Fail closed (e.g. zipSlipDetected / invalidInfoPlist / missingExecutable) is the secure outcome.
        }

        // Empty CFBundleExecutable resolves to the bundle directory itself -> must fail closed, not crash.
        let emptyURL = try writeIPA(buildZip(appEntries(exec: maliciousBinary(), plist: infoPlist(exec: ""))).data, "emptyexec")
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: emptyURL))

        // Absolute CFBundleExecutable is re-rooted under the bundle (not the host) -> missingExecutable.
        let absURL = try writeIPA(buildZip(appEntries(exec: maliciousBinary(), plist: infoPlist(exec: "/bin/ls"))).data, "absexec")
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: absURL))
    }

    // MARK: - A5. Mach-O payloads hidden behind non-.dylib extensions / archive symlinks

    func test_zip_machOBehindNonDylibExtensionOrSymlink_neverAudited_mustNotGradeSafe() throws {
        let fwPlist = (try? PropertyListSerialization.data(
            fromPropertyList: ["CFBundleExecutable": "Evil.js", "CFBundleIdentifier": "com.r4.evil", "CFBundlePackageType": "FMWK"],
            format: .xml, options: 0)) ?? Data()

        // V1: dlopen()-able Mach-O shipped as Frameworks/libcore.so (no .dylib extension, not in a .framework).
        var v1 = appEntries(exec: cleanBinary())
        v1.append(ZipEntry(name: "Payload/R4App.app/Frameworks/libcore.so", data: maliciousBinary(), unixMode: 0o100755))
        try assertNotSilentlySafe(buildZip(v1).data, "Mach-O dylib named libcore.so (extension-based discovery)")

        // V2: framework whose CFBundleExecutable uses a skipped asset extension (.js) -> never even extracted.
        var v2 = appEntries(exec: cleanBinary())
        v2.append(ZipEntry(name: "Payload/R4App.app/Frameworks/Evil.framework/Info.plist", data: fwPlist))
        v2.append(ZipEntry(name: "Payload/R4App.app/Frameworks/Evil.framework/Evil.js", data: maliciousBinary(), unixMode: 0o100755))
        try assertNotSilentlySafe(buildZip(v2).data, "Framework executable named Evil.js (skipped asset extension)")

        // V3: framework binary is an archive symlink (stripped by the scanner) to an innocuously named blob.
        var v3 = appEntries(exec: cleanBinary())
        v3.append(ZipEntry(name: "Payload/R4App.app/Frameworks/Hidden.framework/Hidden", data: Data("../../blob.bin".utf8), unixMode: 0o120755))
        v3.append(ZipEntry(name: "Payload/R4App.app/blob.bin", data: maliciousBinary(), unixMode: 0o100755))
        try assertNotSilentlySafe(buildZip(v3).data, "Framework binary symlink -> blob.bin (symlink stripped, target never audited)")
    }

    // MARK: - A6. Central directory vs local header disagreement

    func test_zip_centralDirectoryVsLocalHeader_nameAndMethodMismatch_mustNotGradeSafe() throws {
        // Name mismatch: CD advertises a skipped asset; the local header (used by streaming extractors) carries the framework.
        var nameMismatch = appEntries(exec: cleanBinary())
        nameMismatch.append(ZipEntry(
            name: "Payload/R4App.app/Frameworks/Evil.framework/Evil",
            data: maliciousBinary(),
            cdName: "Payload/R4App.app/README.txt",
            unixMode: 0o100755
        ))
        try assertNotSilentlySafe(buildZip(nameMismatch).data, "CD name != local header name")

        // Method mismatch: data is DEFLATE (local method 8) but CD says STORE (0). Scanner writes the raw deflate stream
        // to disk, MachOParser rejects it, and the framework parse error is swallowed by `try?`.
        var methodMismatch = appEntries(exec: cleanBinary())
        methodMismatch.append(ZipEntry(
            name: "Payload/R4App.app/Frameworks/Evil.framework/Evil",
            data: maliciousBinary(),
            method: 8,
            cdMethod: 0,
            unixMode: 0o100755
        ))
        try assertNotSilentlySafe(buildZip(methodMismatch).data, "CD method STORE != local method DEFLATE")
    }

    // MARK: - A7. Orphan local headers & fake EOCD inside the archive comment

    func test_zip_orphanLocalHeaderAndFakeEOCDInComment_hiddenFramework_mustNotGradeSafe() throws {
        let evilFw = ZipEntry(name: "Payload/R4App.app/Frameworks/Evil.framework/Evil", data: maliciousBinary(), unixMode: 0o100755)

        var orphan = appEntries(exec: cleanBinary())
        var orphanFw = evilFw
        orphanFw.omitFromCD = true
        orphan.append(orphanFw)
        try assertNotSilentlySafe(buildZip(orphan).data, "Orphan local file header not referenced by the central directory")

        var decoy = appEntries(exec: cleanBinary())
        var decoyFw = evilFw
        decoyFw.inDecoyCD = false
        decoy.append(decoyFw)
        try assertNotSilentlySafe(buildZip(decoy, fakeEOCDDecoy: true).data, "Fake EOCD in archive comment pointing to a decoy CD")
    }

    // MARK: - A8. Understated EOCD entry count / central directory size

    func test_zip_understatedEOCDCountAndCDSize_silentlyTruncatesEntryList_mustNotGradeSafe() throws {
        var entries = appEntries(exec: cleanBinary())
        entries.append(ZipEntry(name: "Payload/R4App.app/Frameworks/Evil.framework/Evil", data: maliciousBinary(), unixMode: 0o100755))

        try assertNotSilentlySafe(buildZip(entries, eocdCountOverride: 2).data, "EOCD total entries (2) < CD records (3)")

        let full = buildZip(entries)
        // Size of the first two CD records only.
        let reader = NativeZIPArchiveReader(data: full.data)
        let parsed = try reader.readCentralDirectory()
        XCTAssertEqual(parsed.count, 3)
        let firstTwoSize = parsed.prefix(2).reduce(0) { $0 + 46 + $1.path.utf8.count }
        try assertNotSilentlySafe(buildZip(entries, cdSizeOverride: UInt32(firstTwoSize)).data, "EOCD CD size covers only 2 of 3 records")
    }

    // MARK: - A9. ZIP64 sentinel / extra-field abuse (reader level)

    func test_zip_zip64SentinelAndExtraFieldAbuse_failClosedWithTypedErrors() throws {
        let payload = Data(repeating: 0x41, count: 64)
        func z64(_ vals: [UInt64]) -> Data {
            var d = Data(); d.r4le16(0x0001); d.r4le16(UInt16(vals.count * 8))
            for v in vals { d.r4le64(v) }
            return d
        }
        var truncatedExtra = Data([0x01, 0x00, 0xFF, 0x00])
        truncatedExtra.r4le64(16)

        let cases: [(String, ZipEntry, String)] = [
            ("compSize sentinel without ZIP64 extra", ZipEntry(name: "a.bin", data: payload, cdCompRaw: 0xFFFF_FFFF), "corruptHeader"),
            ("ZIP64 local offset past EOF", ZipEntry(name: "a.bin", data: payload, cdExtra: z64([0xFFFF_FFFF_0000]), cdOffsetRaw: 0xFFFF_FFFF), "corruptHeader"),
            ("ZIP64 uncompressed size UInt64.max", ZipEntry(name: "a.bin", data: payload, cdExtra: z64([UInt64.max]), cdUncompRaw: 0xFFFF_FFFF), "quotaExceeded"),
            ("ZIP64 extra dataSize > extraLen", ZipEntry(name: "a.bin", data: payload, cdExtra: truncatedExtra, cdUncompRaw: 0xFFFF_FFFF), "quotaExceeded"),
            ("ZIP64 compressed size 2^63", ZipEntry(name: "a.bin", data: payload, cdExtra: z64([0x8000_0000_0000_0000]), cdCompRaw: 0xFFFF_FFFF), "corruptHeader")
        ]
        for (label, entry, expected) in cases {
            let reader = NativeZIPArchiveReader(data: buildZip([entry]).data)
            XCTAssertThrowsError(try reader.readCentralDirectory(), label) { err in
                XCTAssertTrue(err is IPAPackageScannerError, "\(label): untyped error \(err)")
                XCTAssertEqual(Self.caseName(err), expected, "\(label): \(err)")
            }
        }

        // EOCD 0xFFFF entry count (ZIP64 marker) is rejected by the 20,000 entry quota.
        let marker = NativeZIPArchiveReader(data: buildZip([ZipEntry(name: "a.bin", data: payload)], eocdCountOverride: 0xFFFF).data)
        XCTAssertThrowsError(try marker.readCentralDirectory()) { XCTAssertEqual(Self.caseName($0), "quotaExceeded") }
    }

    // MARK: - A10. Entry-count boundary (20,000)

    func test_zip_entryCountBoundary_20000Accepted_20001RejectedQuickly() throws {
        func make(_ n: Int) -> Data {
            buildZip((0..<n).map { ZipEntry(name: String(format: "Payload/R4App.app/d%05d/", $0), data: Data()) }).data
        }
        let atLimit = make(20_000)
        var t0 = Date()
        let entries = try NativeZIPArchiveReader(data: atLimit).readCentralDirectory()
        XCTAssertEqual(entries.count, 20_000)
        XCTAssertTrue(entries.allSatisfy(\.isDirectory))
        XCTAssertLessThan(Date().timeIntervalSince(t0), 5.0)

        t0 = Date()
        XCTAssertThrowsError(try NativeZIPArchiveReader(data: make(20_001)).readCentralDirectory()) {
            XCTAssertEqual(Self.caseName($0), "quotaExceeded")
        }
        XCTAssertLessThan(Date().timeIntervalSince(t0), 5.0)
    }

    // MARK: - A11. Info.plist format variants, Payload case, zero-length / truncated inputs

    func test_zip_infoPlistVariants_payloadCase_zeroLengthAndTruncated_secureOutcomes() throws {
        // Binary plist must be honoured identically to XML.
        try assertDetects(buildZip(appEntries(exec: maliciousBinary(), plist: infoPlist(exec: "R4App", format: .binary))).data, "Binary Info.plist")

        // Root-array / garbage / non-string CFBundleExecutable plists must not crash.
        let arrayPlist = (try? PropertyListSerialization.data(fromPropertyList: ["R4App"], format: .xml, options: 0)) ?? Data()
        let arrayURL = try writeIPA(buildZip(appEntries(exec: maliciousBinary(), plist: arrayPlist)).data, "arrayplist")
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: arrayURL)) { XCTAssertEqual(Self.caseName($0), "invalidInfoPlist") }
        let garbageURL = try writeIPA(buildZip(appEntries(exec: maliciousBinary(), plist: Data([0x62, 0x70, 0x6C, 0x69, 0x73, 0x74, 0x30, 0x30, 0xFF]))).data, "garbageplist")
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: garbageURL))
        try assertNotSilentlySafe(buildZip(appEntries(exec: maliciousBinary(), plist: infoPlist(exec: 42))).data, "Non-string CFBundleExecutable")

        // Lowercase `payload/` is accepted; uppercase `PAYLOAD/` fails closed.
        try assertDetects(buildZip(appEntries(root: "payload/R4App.app/", exec: maliciousBinary())).data, "lowercase payload/")
        let upperURL = try writeIPA(buildZip(appEntries(root: "PAYLOAD/R4App.app/", exec: maliciousBinary())).data, "upperpayload")
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: upperURL))

        // Zero-length main executable and a half-truncated archive fail closed.
        let zeroURL = try writeIPA(buildZip(appEntries(exec: Data())).data, "zeroexec")
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: zeroURL))
        let full = buildZip(appEntries(exec: maliciousBinary())).data
        let truncURL = try writeIPA(full.prefix(full.count / 2), "truncated")
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: truncURL))
    }

    // MARK: - Raw Mach-O builder (explicit offsets; optional byte-swapped header)

    private struct RSect {
        var name: String
        var seg: String = "__TEXT"
        var addr: UInt64
        var size: UInt64
        var offset: UInt32
        var flags: UInt32
    }

    private struct RSeg {
        var name: String
        var vmaddr: UInt64 = 0x1_0000_0000
        var vmsize: UInt64 = 0x1000
        var fileoff: UInt64 = 0
        var filesize: UInt64 = 0x1000
        var initprot: Int32 = 5
        var sects: [RSect] = []
        var nsectsOverride: UInt32? = nil
    }

    private func buildRawMachO(
        segs: [RSeg],
        enc: [(off: UInt32, size: UInt32, id: UInt32)] = [],
        symtab: (symoff: UInt32, nsyms: UInt32, stroff: UInt32, strsize: UInt32)? = nil,
        fileSize: Int = 0x1000,
        patches: [(Int, Data)] = [],
        swapped: Bool = false,
        cpu: cpu_type_t = CPU_TYPE_ARM64
    ) -> Data {
        func w32(_ d: inout Data, _ v: UInt32) { if swapped { d.r4be32(v) } else { d.r4le32(v) } }
        func w64(_ d: inout Data, _ v: UInt64) { if swapped { d.r4be64(v) } else { d.r4le64(v) } }
        func name16(_ d: inout Data, _ s: String) {
            var b = Array(s.utf8.prefix(16))
            b += [UInt8](repeating: 0, count: 16 - b.count)
            d.append(contentsOf: b)
        }
        var cmds = Data()
        var ncmds: UInt32 = 0
        for s in segs {
            w32(&cmds, UInt32(LC_SEGMENT_64)); w32(&cmds, UInt32(72 + 80 * s.sects.count)); name16(&cmds, s.name)
            w64(&cmds, s.vmaddr); w64(&cmds, s.vmsize); w64(&cmds, s.fileoff); w64(&cmds, s.filesize)
            w32(&cmds, 7); w32(&cmds, UInt32(bitPattern: s.initprot)); w32(&cmds, s.nsectsOverride ?? UInt32(s.sects.count)); w32(&cmds, 0)
            for x in s.sects {
                name16(&cmds, x.name); name16(&cmds, x.seg)
                w64(&cmds, x.addr); w64(&cmds, x.size)
                w32(&cmds, x.offset); w32(&cmds, 2); w32(&cmds, 0); w32(&cmds, 0)
                w32(&cmds, x.flags); w32(&cmds, 0); w32(&cmds, 0); w32(&cmds, 0)
            }
            ncmds += 1
        }
        for e in enc {
            w32(&cmds, UInt32(LC_ENCRYPTION_INFO_64)); w32(&cmds, 24)
            w32(&cmds, e.off); w32(&cmds, e.size); w32(&cmds, e.id); w32(&cmds, 0)
            ncmds += 1
        }
        if let st = symtab {
            w32(&cmds, UInt32(LC_SYMTAB)); w32(&cmds, 24)
            w32(&cmds, st.symoff); w32(&cmds, st.nsyms); w32(&cmds, st.stroff); w32(&cmds, st.strsize)
            ncmds += 1
        }
        var d = Data()
        w32(&d, MH_MAGIC_64); w32(&d, UInt32(bitPattern: cpu)); w32(&d, 0); w32(&d, UInt32(MH_EXECUTE))
        w32(&d, ncmds); w32(&d, UInt32(cmds.count)); w32(&d, 0x0020_0085); w32(&d, 0)
        d.append(cmds)
        if d.count < fileSize { d.append(Data(count: fileSize - d.count)) }
        for (off, bytes) in patches { d.replaceSubrange(off..<(off + bytes.count), with: bytes) }
        return d
    }

    private func textSect(offset: UInt32, size: UInt64, flags: UInt32 = AdversarialV130Round4ParserFuzzTests.instrFlags) -> RSect {
        RSect(name: "__text", addr: 0x1_0000_0000 + UInt64(offset), size: size, offset: offset, flags: flags)
    }

    // MARK: - B1. svc #0x80 in executable segment bytes not covered by a section header

    func test_macho_svcInExecutableSegmentBytesOutsideAnySection_mustBeDetected() throws {
        let cleanCode = Self.le([Self.nop, Self.ret])
        let svcCode = Self.le([Self.svc, Self.ret])
        let ctx = MachOScanner.ScanContext(bundleId: "com.redteam.r4.cave", installChannel: .developerSideloaded)

        // Controls: svc inside __text is detected; clean layout without svc has zero false positives.
        let inside = buildRawMachO(segs: [RSeg(name: "__TEXT", sects: [textSect(offset: 0x400, size: 8)])], patches: [(0x400, svcCode)])
        XCTAssertEqual(try MachOParser.shared.parse(data: inside).directSyscallCount, 1, "Builder control: svc inside __text")
        let cleanGap = buildRawMachO(segs: [RSeg(name: "__TEXT", sects: [textSect(offset: 0x800, size: 8)])], patches: [(0x800, cleanCode)])
        XCTAssertEqual(try MachOParser.shared.parse(data: cleanGap).directSyscallCount, 0, "FP control: zero header padding")
        XCTAssertEqual(try MachOScanner.shared.scan(binaryData: cleanGap, context: ctx).riskTier, .safe)

        // The kernel maps whole segments (fileoff..+filesize) with initprot; section headers are advisory metadata.
        let cases: [(String, Data)] = [
            ("svc in __TEXT header-padding code cave (bytes 0x400 not covered by __text @0x800)",
             buildRawMachO(segs: [RSeg(name: "__TEXT", sects: [textSect(offset: 0x800, size: 8)])],
                           patches: [(0x800, cleanCode), (0x400, svcCode)])),
            ("svc in R-X __TEXT segment with nsects = 0",
             buildRawMachO(segs: [RSeg(name: "__TEXT", sects: [])], patches: [(0x400, svcCode)])),
            ("svc in S_ZEROFILL-typed __text section lying inside the segment filesize (bytes are mapped R-X)",
             buildRawMachO(segs: [RSeg(name: "__TEXT", sects: [textSect(offset: 0x400, size: 8, flags: UInt32(S_ZEROFILL) | Self.instrFlags)])],
                           patches: [(0x400, svcCode)]))
        ]
        for (label, bin) in cases {
            let parsed = try MachOParser.shared.parse(data: bin)
            XCTAssertGreaterThan(parsed.directSyscallCount, 0, "[R4 DEFECT] \(label): inline svc #0x80 in executable mapped bytes not detected")
            XCTAssertEqual(try MachOScanner.shared.scan(binaryData: bin, context: ctx).riskTier, .highRisk,
                           "[R4 DEFECT] \(label): MachOScanner graded binary with executable svc #0x80 as non-high-risk")
        }
    }

    // MARK: - B2. nsects / cmdsize mismatch and section integer overflow

    func test_macho_nsectsCmdsizeMismatchAndSectionOffsetSizeOverflow_noCrashBounded() throws {
        let svcCode = Self.le([Self.svc, Self.ret])

        // nsects claims 2 / UInt32.max but cmdsize only holds 1 section header -> parser must not over-read.
        for override in [UInt32(2), UInt32(1000), UInt32.max] {
            let bin = buildRawMachO(segs: [RSeg(name: "__TEXT", sects: [textSect(offset: 0x400, size: 8)], nsectsOverride: override)],
                                    patches: [(0x400, svcCode)])
            do {
                let parsed = try MachOParser.shared.parse(data: bin)
                XCTAssertLessThanOrEqual(parsed.segments.first?.sections.count ?? 0, 1, "nsects=\(override) must never yield headers beyond cmdsize")
                _ = parsed.scanDirectSyscalls()
                _ = parsed.objcMethodNames
                print("[R4 INFO] nsects=\(override) with cmdsize for 1 section: parse accepted, sections=\(parsed.segments.first?.sections.count ?? -1), svc=\(parsed.directSyscallCount) (xnu rejects such commands with LOAD_BADMACHO)")
            } catch {
                XCTAssertTrue(error is MachOParserError)
            }
        }

        // Section offset/size overflow on UInt32/UInt64/Int boundaries; only the last sane section holds svc.
        let methFlags = UInt32(S_CSTRING_LITERALS)
        let sects: [RSect] = [
            textSect(offset: 0xFFFF_FFFF, size: UInt64.max),
            textSect(offset: 0xFFFF_FFF0, size: 0x20),
            textSect(offset: 0x0FF0, size: 0x8000_0000_0000_0000),
            textSect(offset: 0x0FF8, size: UInt64(Int.max)),
            RSect(name: "__objc_methname", addr: 0, size: UInt64.max, offset: 0x0F00, flags: methFlags),
            RSect(name: "__objc_methname", addr: 0, size: UInt64(Int.max), offset: 0x0F00, flags: methFlags),
            RSect(name: "__objc_methname", addr: 0, size: 0x200, offset: 0x0F00, flags: methFlags),
            textSect(offset: 0x0FFC, size: 4)
        ]
        let bin = buildRawMachO(segs: [RSeg(name: "__TEXT", sects: sects)], patches: [(0x0FFC, Self.le([Self.svc]))])
        let t0 = Date()
        let parsed = try MachOParser.shared.parse(data: bin)
        XCTAssertEqual(parsed.segments.first?.sections.count, sects.count)
        XCTAssertEqual(parsed.directSyscallCount, 1, "Only the in-bounds trailing 4-byte __text must be scanned")
        XCTAssertTrue(parsed.objcMethodNames.isEmpty)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 2.0)
    }

    // MARK: - B3. FAT topology abuse

    private func buildFat(
        _ archs: [(cpu: cpu_type_t, sub: cpu_subtype_t, offset: UInt64, size: UInt64)],
        payloads: [(offset: Int, data: Data)],
        totalSize: Int,
        fat64: Bool = false,
        nfatOverride: UInt32? = nil
    ) -> Data {
        var d = Data()
        d.r4be32(fat64 ? FAT_MAGIC_64 : FAT_MAGIC)
        d.r4be32(nfatOverride ?? UInt32(archs.count))
        for a in archs {
            d.r4be32(UInt32(bitPattern: a.cpu)); d.r4be32(UInt32(bitPattern: a.sub))
            if fat64 {
                d.r4be64(a.offset); d.r4be64(a.size); d.r4be32(14); d.r4be32(0)
            } else {
                d.r4be32(UInt32(truncatingIfNeeded: a.offset)); d.r4be32(UInt32(truncatingIfNeeded: a.size)); d.r4be32(14)
            }
        }
        if d.count < totalSize { d.append(Data(count: totalSize - d.count)) }
        for p in payloads { d.replaceSubrange(p.offset..<(p.offset + p.data.count), with: p.data) }
        return d
    }

    func test_macho_fatTopologyAbuse_overlapZeroSizeSelfRefNestedOverflow_secureOutcomes() throws {
        let mal = maliciousBinary()
        let s = UInt64(mal.count)
        let total = 0x1000 + mal.count
        let ctx = MachOScanner.ScanContext(bundleId: "com.redteam.r4.fat")
        let arm64e = CPU_SUBTYPE_ARM64E

        // Overlapping slices (arm64 + arm64e share bytes) -> both parsed, detected, counts summed.
        let overlap = buildFat([(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x1000, s), (CPU_TYPE_ARM64, arm64e, 0x1000, s)],
                               payloads: [(0x1000, mal)], totalSize: total)
        XCTAssertEqual(try MachOParser.shared.parseAllSlices(data: overlap).count, 2)
        XCTAssertEqual(try MachOScanner.shared.parseMachO(data: overlap).directSyscallCount, 2)
        XCTAssertEqual(try MachOScanner.shared.scan(binaryData: overlap, context: ctx).riskTier, .highRisk)

        // Zero-size slice + valid malicious slice.
        let zero = buildFat([(CPU_TYPE_ARM64, arm64e, 0x1000, 0), (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x1000, s)],
                            payloads: [(0x1000, mal)], totalSize: total)
        XCTAssertEqual(try MachOScanner.shared.scan(binaryData: zero, context: ctx).riskTier, .highRisk)

        // Slice pointing back at the FAT header itself (offset 0, whole file) -> no recursion, other slice detected.
        let selfRef = buildFat([(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0, UInt64(total)), (CPU_TYPE_ARM64, arm64e, 0x1000, s)],
                               payloads: [(0x1000, mal)], totalSize: total)
        XCTAssertEqual(try MachOScanner.shared.scan(binaryData: selfRef, context: ctx).riskTier, .highRisk)

        // Only slice is itself a FAT container -> typed failure (kernel does not support nested FAT either).
        let inner = buildFat([(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x1000, s)], payloads: [(0x1000, mal)], totalSize: total)
        let nested = buildFat([(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x1000, UInt64(inner.count))],
                              payloads: [(0x1000, inner)], totalSize: 0x1000 + inner.count)
        XCTAssertThrowsError(try MachOParser.shared.parseAllSlices(data: nested)) { XCTAssertTrue($0 is MachOParserError) }

        // FAT64 offset near UInt64.max (offset + size wraps) -> sliceOutOfBounds, never a trap.
        let wrap = buildFat([(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, UInt64.max - 8, 0x20)], payloads: [], totalSize: 0x100, fat64: true)
        XCTAssertThrowsError(try MachOParser.shared.parseAllSlices(data: wrap)) { XCTAssertEqual(Self.caseName($0), "sliceOutOfBounds") }
        XCTAssertThrowsError(try MachOParser.shared.parse(data: wrap))
        XCTAssertThrowsError(try MachOParser.shared.listSlices(in: wrap))

        // nfat_arch above the 1024 cap and nfat whose table exceeds the file -> corruptedFatHeader.
        let tooMany = buildFat([], payloads: [], totalSize: 8, nfatOverride: 1025)
        XCTAssertThrowsError(try MachOParser.shared.parseAllSlices(data: tooMany)) { XCTAssertEqual(Self.caseName($0), "corruptedFatHeader") }
        let tableOOB = buildFat([], payloads: [], totalSize: 16, nfatOverride: 64)
        XCTAssertThrowsError(try MachOParser.shared.parseAllSlices(data: tableOOB)) { XCTAssertEqual(Self.caseName($0), "corruptedFatHeader") }
    }

    // MARK: - B4. MH_CIGAM_64 byte-swapped slices & duplicate LC_ENCRYPTION_INFO_64 ordering

    func test_macho_cigam64SwappedSlices_andDuplicateEncryptionInfoOrdering() throws {
        // MH_CIGAM_64: every header/LC field big-endian. AArch64 instruction fetch is always little-endian, so the
        // architecturally-correct svc encoding stays 01 10 00 D4. Must parse without crash in both encodings.
        let swappedLE = buildRawMachO(segs: [RSeg(name: "__TEXT", sects: [textSect(offset: 0x400, size: 8)])],
                                      patches: [(0x400, Self.le([Self.svc, Self.ret]))], swapped: true)
        var beWords = Data(); beWords.r4be32(Self.svc); beWords.r4be32(Self.ret)
        let swappedBE = buildRawMachO(segs: [RSeg(name: "__TEXT", sects: [textSect(offset: 0x400, size: 8)])],
                                      patches: [(0x400, beWords)], swapped: true)
        let pLE = try MachOParser.shared.parse(data: swappedLE)
        let pBE = try MachOParser.shared.parse(data: swappedBE)
        XCTAssertTrue(pLE.isSwapped)
        XCTAssertEqual(pLE.cpuType, CPU_TYPE_ARM64)
        XCTAssertEqual(pLE.segments.first?.sections.first?.offset, 0x400)
        print("[R4 INFO] MH_CIGAM_64 arm64: svc count with LE instruction bytes = \(pLE.directSyscallCount), with BE-swapped bytes = \(pBE.directSyscallCount). Scanner byte-swaps instruction words for swapped headers (AArch64 code is always LE); iOS refuses to load MH_CIGAM_64 so this is informational only.")

        // Duplicate LC_ENCRYPTION_INFO_64 in both orders: a tiny fake cryptid=1 range over header bytes must never hide
        // the svc at 0x400, whichever command the parser keeps.
        let seg = RSeg(name: "__TEXT", sects: [textSect(offset: 0x400, size: 8)])
        let svcPatch = [(0x400, Self.le([Self.svc, Self.ret]))]
        let orders: [(String, [(off: UInt32, size: UInt32, id: UInt32)])] = [
            ("[cryptid=1 @0x40+0x20, cryptid=0]", [(0x40, 0x20, 1), (0, 0, 0)]),
            ("[cryptid=0, cryptid=1 @0x40+0x20]", [(0, 0, 0), (0x40, 0x20, 1)])
        ]
        for (label, enc) in orders {
            let bin = buildRawMachO(segs: [seg], enc: enc, patches: svcPatch)
            XCTAssertEqual(try MachOParser.shared.parse(data: bin).directSyscallCount, 1, "Duplicate LC_ENCRYPTION_INFO_64 \(label)")
            XCTAssertEqual(try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.r4.enc", installChannel: .appStore)).riskTier,
                           .highRisk, "Duplicate LC_ENCRYPTION_INFO_64 \(label)")
        }
    }

    // MARK: - B5. LC_SYMTAB strx abuse

    func test_macho_symtabStrxAbuse_pastTableUnterminatedAndOverflowingTables_bounded() throws {
        // symoff 0x800 (5 x nlist_64), stroff 0x900, strsize 0x20.
        var nlist = Data()
        for strx in [UInt32(1), 0x20, 0xFFFF_FFFF, 0x1C, 0] {
            nlist.r4le32(strx); nlist.append(contentsOf: [0x0F, 0x01, 0x00, 0x00]); nlist.r4le64(0x1_0000_0000)
        }
        var strtab = Data([0x00]) + Data("_ok".utf8) + Data([0x00])
        strtab.append(Data(repeating: 0x00, count: 0x1C - strtab.count))
        strtab.append(Data("ABCD".utf8))   // 0x1C..0x1F, no NUL inside the table
        let bin = buildRawMachO(segs: [RSeg(name: "__TEXT")],
                                symtab: (0x800, 5, 0x900, 0x20),
                                patches: [(0x800, nlist), (0x900, strtab), (0x920, Data("ZZZZ".utf8))])
        let syms = try MachOParser.shared.parse(data: bin).symbols
        XCTAssertEqual(syms, ["_ok", "ABCD"], "strx == strsize / 0xFFFFFFFF / 0 must be skipped and unterminated names bounded by strsize")
        XCTAssertFalse(syms.contains { $0.contains("Z") }, "String read leaked past the string table")

        // nsyms such that symoff + nsyms*16 overflows UInt32 / file; stroff + strsize overflows UInt32.
        let symOOB = buildRawMachO(segs: [RSeg(name: "__TEXT")], symtab: (0x800, 0x1000_0000, 0x900, 0x20))
        XCTAssertThrowsError(try MachOParser.shared.parse(data: symOOB)) { XCTAssertEqual(Self.caseName($0), "symbolTableOutOfBounds") }
        let strOOB = buildRawMachO(segs: [RSeg(name: "__TEXT")], symtab: (0x800, 0, 0xFFFF_FF00, 0x200))
        XCTAssertThrowsError(try MachOParser.shared.parse(data: strOOB)) { XCTAssertEqual(Self.caseName($0), "stringTableOutOfBounds") }
    }

    // MARK: - B6. Malformed / self-referential CS SuperBlob indices and DER depth bombs

    func test_csblob_malformedSelfReferentialIndicesAndDERDepthBomb_noCrash() throws {
        func superBlob(count: UInt32, index: [(UInt32, UInt32)], length: UInt32? = nil, blobs: [(Int, Data)], total: Int) -> Data {
            var d = Data()
            d.r4be32(CSBlobConstants.superBlobMagic)
            d.r4be32(length ?? UInt32(total))
            d.r4be32(count)
            for (t, o) in index { d.r4be32(t); d.r4be32(o) }
            if d.count < total { d.append(Data(count: total - d.count)) }
            for (o, b) in blobs { d.replaceSubrange(o..<(o + b.count), with: b) }
            return d
        }
        func blob(_ magic: UInt32, _ payload: Data, lengthOverride: UInt32? = nil) -> Data {
            var d = Data(); d.r4be32(magic); d.r4be32(lengthOverride ?? UInt32(8 + payload.count)); d.append(payload)
            return d
        }
        let xml = Data(SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.r4.dedupe"]).utf8)
        let xmlBlob = blob(CSBlobConstants.entitlementXmlMagic, xml)
        let total = 64 + xmlBlob.count + 64

        let cases: [(String, Data)] = [
            ("count=0xFFFFFFFF, length=12", superBlob(count: 0xFFFF_FFFF, index: [], blobs: [], total: 12)),
            ("indices pointing at header/index table (0,4,8,12,16)",
             superBlob(count: 5, index: [(5, 0), (5, 4), (5, 8), (5, 12), (7, 16)], blobs: [], total: 64)),
            ("blob lengths 0 / 7 / 0xFFFFFFFF",
             superBlob(count: 3, index: [(5, 40), (7, 48), (5, 56)],
                       blobs: [(40, blob(CSBlobConstants.entitlementXmlMagic, Data(), lengthOverride: 0)),
                               (48, blob(CSBlobConstants.entitlementDerMagic, Data(), lengthOverride: 7)),
                               (56, blob(CSBlobConstants.entitlementXmlMagic, Data(), lengthOverride: 0xFFFF_FFFF))],
                       total: 64)),
            ("nested SuperBlob as slot-5 payload",
             superBlob(count: 1, index: [(5, 32)],
                       blobs: [(32, superBlob(count: 1, index: [(5, 0)], blobs: [], total: 20))], total: 64)),
            ("SuperBlob length > buffer", superBlob(count: 1, index: [(5, 20)], length: 0x7FFF_FFFF, blobs: [], total: 32))
        ]
        for (label, data) in cases {
            _ = try? CSBlobParser.shared.parseSuperBlob(data)
            let groups = CSBlobParser.shared.extractAppGroups(from: data)
            XCTAssertFalse(groups.hasAppGroups, "\(label): malformed blob must not fabricate App Groups")
            _ = CSBlobParser.shared.parseMergedEntitlements(from: data)
            _ = CSBlobParser.shared.extractAppGroups(fromMachO: data)
        }

        // Two index entries (slot 5 + alternate slot) referencing the same XML blob -> deduplicated union.
        let dup = superBlob(count: 2, index: [(5, 64), (0x1000, 64)], blobs: [(64, xmlBlob)], total: total)
        XCTAssertEqual(CSBlobParser.shared.extractAppGroups(from: dup).appGroups, ["group.r4.dedupe"])

        // DER depth bomb: 4000 nested SEQUENCEs (long-form lengths) must throw / return, never overflow the stack.
        var der = Data([0x05, 0x00])
        for _ in 0..<4000 {
            let n = der.count
            var wrapped = Data([0x30, 0x84, UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)])
            wrapped.append(der)
            der = wrapped
        }
        let t0 = Date()
        _ = try? CSBlobParser.shared.parseDEREntitlements(der)
        _ = try? CSBlobParser.shared.parseDERAppGroups(der)
        let derSB = superBlob(count: 1, index: [(7, 20)], blobs: [(20, blob(CSBlobConstants.entitlementDerMagic, der))], total: 20 + 8 + der.count)
        XCTAssertFalse(CSBlobParser.shared.extractAppGroups(from: derSB).hasAppGroups)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 2.0)
    }

    // MARK: - B7. Public API: Data slices with non-zero startIndex

    func test_api_dataSliceWithNonZeroStartIndex_mustParseIdenticallyToRebasedCopy() throws {
        // Data slices keep their parent's indices. Readers use relative `withUnsafeBytes` offsets but extract with
        // absolute `subdata(in:)` ranges, so a slice silently yields bytes shifted by `startIndex` (or traps if the
        // range falls below startIndex).
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.r4.slice"])
        ))
        let baseline = try MachOParser.shared.parse(data: bin)
        let baseCS = try XCTUnwrap(baseline.codeSignatureData)
        XCTAssertEqual(CSBlobParser.shared.extractAppGroups(from: baseCS).appGroups, ["group.r4.slice"])

        let padded = Data(repeating: 0xEE, count: 7) + bin
        let slice = padded[7...]
        XCTAssertEqual(slice.startIndex, 7)
        XCTAssertEqual(Data(slice), bin)
        let sliced = try MachOParser.shared.parse(data: slice)
        XCTAssertEqual(sliced.codeSignatureData, baseCS,
                       "[R4 DEFECT] MachOFile.codeSignatureData on a Data slice (startIndex=7) returns shifted bytes")
        XCTAssertEqual(CSBlobParser.shared.extractAppGroups(from: sliced.codeSignatureData).appGroups, ["group.r4.slice"],
                       "[R4 DEFECT] Entitlements/App Groups silently lost when MachOParser is given a Data slice")

        let plist = infoPlist(exec: "R4App")
        let zip = buildZip(appEntries(exec: cleanBinary(), plist: plist)).data
        let zslice = (Data(repeating: 0xEE, count: 7) + zip)[7...]
        let reader = NativeZIPArchiveReader(data: zslice)
        do {
            let entries = try reader.readCentralDirectory()
            XCTAssertEqual(entries.map(\.path), ["Payload/R4App.app/Info.plist", "Payload/R4App.app/R4App"],
                           "[R4 DEFECT] NativeZIPArchiveReader on a Data slice decodes shifted entry names")
            if let first = entries.first {
                XCTAssertEqual(try? reader.extract(entry: first), plist,
                               "[R4 DEFECT] NativeZIPArchiveReader.extract on a Data slice returns shifted bytes")
            }
        } catch {
            XCTFail("[R4 DEFECT] NativeZIPArchiveReader on a valid Data slice threw \(error)")
        }
    }

    // MARK: - C. Deterministic mini-fuzzers

    private static let interesting32: [UInt32] = [
        0, 1, 0x7F, 0x80, 0xFF, 0x1000, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFF0, 0xFFFF_FFFF,
        0xD400_1001, 0xFADE_0CC0, 0xC00C_DEFA, 0x19, 0x2C, 0x0605_4b50, 0x0201_4b50, 0x0403_4b50
    ]

    private func mutate(_ base: Data, rng: inout R4SplitMix64, hotRanges: [Range<Int>]) -> Data {
        var d = base
        let ops = 1 + rng.int(6)
        for _ in 0..<ops {
            guard d.count > 4 else { break }
            func pickOffset(_ width: Int) -> Int {
                if !hotRanges.isEmpty && rng.int(10) < 7 {
                    let r = hotRanges[rng.int(hotRanges.count)]
                    let lo = min(max(r.lowerBound, 0), d.count - width)
                    let hi = min(max(r.upperBound, lo + 1), d.count - width + 1)
                    return lo + rng.int(max(hi - lo, 1))
                }
                return rng.int(d.count - width + 1)
            }
            switch rng.int(12) {
            case 0...3:
                let o = pickOffset(1)
                d[d.startIndex + o] ^= UInt8(1 << rng.int(8))
            case 4...7:
                let o = pickOffset(4) & ~1
                var v = Self.interesting32[rng.int(Self.interesting32.count)]
                if rng.int(2) == 0 { v = v.byteSwapped }
                if o + 4 <= d.count {
                    withUnsafeBytes(of: &v) { d.replaceSubrange((d.startIndex + o)..<(d.startIndex + o + 4), with: $0) }
                }
            case 8:
                d[d.startIndex + pickOffset(1)] = UInt8(truncatingIfNeeded: rng.next())
            case 9:
                if rng.int(3) == 0 { d = d.prefix(rng.int(d.count + 1)) }
            default:
                let len = min(16, d.count / 2)
                let src = rng.int(d.count - len + 1)
                let dst = rng.int(d.count - len + 1)
                let chunk = d.subdata(in: (d.startIndex + src)..<(d.startIndex + src + len))
                d.replaceSubrange((d.startIndex + dst)..<(d.startIndex + dst + len), with: chunk)
            }
        }
        return Data(d)
    }

    func test_fuzz_machOAndFatMutation_900Iterations_noCrashTypedErrorsTimeBoundedReadOnly() throws {
        let rich = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib", "/usr/lib/system/libsystem_containermanager.dylib"],
            weakDylibs: ["/System/Library/Frameworks/Photos.framework/Photos"],
            symbols: ["_main", "_dlopen", "_dlsym", "_fsgetpath", "_symlink"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.r4.fuzz"]),
            derEntitlements: SyntheticMachOGenerator.createDEREntitlements(appGroups: ["group.r4.fuzz.der"]),
            textInstructions: [Self.nop, Self.svc, Self.ret],
            customSections: [(segName: "__TEXT", sectName: "__objc_methname", flags: UInt32(S_CSTRING_LITERALS), payload: Data("setFoo:\0bar\0".utf8))],
            extraCStringLiterals: ["/var/mobile/Containers/Data/", "com.apple.containermanagerd"]
        ))
        let fat = SyntheticMachOGenerator.shared.generateUniversalFAT(configs: [
            .init(arch: .arm64, symbols: ["_main"], xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.r4.fat"]), textInstructions: [Self.svc]),
            .init(arch: .x86_64, symbols: ["_main"])
        ])
        var nl = Data()
        nl.r4le32(1); nl.append(contentsOf: [0x0F, 0x01, 0, 0]); nl.r4le64(0)
        let raw = buildRawMachO(
            segs: [RSeg(name: "__TEXT", sects: [textSect(offset: 0x400, size: 8)]), RSeg(name: "__LINKEDIT", vmaddr: 0x1_0000_1000, fileoff: 0x800, filesize: 0x800, initprot: 1)],
            enc: [(0x40, 0x20, 1), (0, 0, 0)],
            symtab: (0x800, 1, 0x900, 0x10),
            patches: [(0x400, Self.le([Self.svc, Self.ret])), (0x800, nl), (0x900, Data("\0_fsgetpath\0".utf8))]
        )

        // Read-only invariant on the on-disk seeds.
        let seedDir = FileManager.default.temporaryDirectory.appendingPathComponent("r4_macho_seeds_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: seedDir, withIntermediateDirectories: true)
        tempURLs.append(seedDir)
        let seeds: [(String, Data, UInt64)] = [("rich", rich, 0x5234_0001), ("fat", fat, 0x5234_0002), ("raw", raw, 0x5234_0003)]
        for (name, data, _) in seeds {
            let u = seedDir.appendingPathComponent(name)
            try data.write(to: u)
            try FileManager.default.setAttributes([.posixPermissions: 0o444], ofItemAtPath: u.path)
        }
        let before = try ReadOnlyAssertions.captureSnapshot(of: [seedDir])

        var parsedOK = 0, threw = 0, maxElapsed: TimeInterval = 0
        for (name, _, seed) in seeds {
            let seedURL = seedDir.appendingPathComponent(name)
            let base = try Data(contentsOf: seedURL, options: .mappedIfSafe)
            let hot: [Range<Int>] = [(0, 1536), (0x1000, 0x1600), (0x4000, 0x4600)].compactMap { lo, hi in
                lo < base.count ? lo..<min(base.count, hi) : nil
            }
            var rng = R4SplitMix64(seed: seed)
            for iter in 0..<300 {
                let m = mutate(base, rng: &rng, hotRanges: hot)
                let t0 = Date()
                _ = CSBlobParser.shared.extractAppGroups(fromMachO: m)
                _ = try? MachOParser.shared.parse(data: m)
                _ = try? MachOParser.shared.listSlices(in: m)
                do {
                    let files = try MachOParser.shared.parseAllSlices(data: m)
                    for f in files {
                        _ = f.symbols
                        _ = f.objcMethodNames
                        _ = f.scanDirectSyscalls()
                        _ = f.linkedDylibPaths
                        _ = f.textSegment?.fileRange
                        _ = f.encryptionInfo?.encryptedRange
                        let cs = f.codeSignatureData
                        _ = CSBlobParser.shared.extractAppGroups(from: cs)
                        _ = CSBlobParser.shared.parseMergedEntitlements(from: cs)
                    }
                    let details = MachOScanner.shared.parseMachO(files: files, rawData: m)
                    _ = MachOScanner.shared.scan(details: details, context: .init(bundleId: "com.redteam.r4.fuzz"))
                    parsedOK += 1
                } catch {
                    threw += 1
                    XCTAssertTrue(error is MachOParserError, "seed=\(name) iter=\(iter): untyped error \(error)")
                }
                let elapsed = Date().timeIntervalSince(t0)
                maxElapsed = max(maxElapsed, elapsed)
                XCTAssertLessThan(elapsed, 2.0, "seed=\(name) iter=\(iter): mutation took \(elapsed)s (possible algorithmic DoS)")
            }
            // A seed file scanned through the URL API must remain byte-identical.
            _ = try? MachOScanner.shared.scan(binaryURL: seedURL, context: .init(bundleId: "com.redteam.r4.fuzz"))
        }
        let after = try ReadOnlyAssertions.captureSnapshot(of: [seedDir])
        ReadOnlyAssertions.assertUnmodified(before: before, after: after)
        XCTAssertEqual(parsedOK + threw, 900)
        print("[R4 INFO] Mach-O fuzz: 900 iterations, parsed=\(parsedOK), typedErrors=\(threw), maxElapsed=\(String(format: "%.4f", maxElapsed))s")
    }

    private func fuzzIPABase() -> BuiltZip {
        let fwPlist = (try? PropertyListSerialization.data(
            fromPropertyList: ["CFBundleExecutable": "Core", "CFBundleIdentifier": "com.r4.core", "CFBundlePackageType": "FMWK"],
            format: .xml, options: 0)) ?? Data()
        let appexPlist = (try? PropertyListSerialization.data(
            fromPropertyList: ["CFBundleExecutable": "Widget", "CFBundleIdentifier": "com.redteam.r4.parser.widget", "CFBundlePackageType": "XPC!"],
            format: .xml, options: 0)) ?? Data()
        var entries = appEntries(exec: maliciousBinary())
        entries[1].method = 8
        entries += [
            ZipEntry(name: "Payload/R4App.app/Frameworks/Core.framework/Info.plist", data: fwPlist),
            ZipEntry(name: "Payload/R4App.app/Frameworks/Core.framework/Core", data: cleanBinary(), method: 8, unixMode: 0o100755),
            ZipEntry(name: "Payload/R4App.app/PlugIns/Widget.appex/Info.plist", data: appexPlist, method: 8),
            ZipEntry(name: "Payload/R4App.app/PlugIns/Widget.appex/Widget", data: cleanBinary(), unixMode: 0o100755),
            ZipEntry(name: "Payload/R4App.app/Assets.car", data: Data(repeating: 0x42, count: 512), method: 8)
        ]
        return buildZip(entries)
    }

    private func zipHotRanges(_ z: BuiltZip) -> [Range<Int>] {
        var hot = z.localOffsets.map { $0..<($0 + 30) }
        hot.append(z.cdOffset..<z.data.count)
        hot.append(max(0, z.data.count - 22)..<z.data.count)
        return hot
    }

    func test_fuzz_zipReaderMutation_1000Iterations_noCrashTypedErrorsTimeBounded() throws {
        let base = fuzzIPABase()
        let hot = zipHotRanges(base)
        var rng = R4SplitMix64(seed: 0x5234_2000)
        var ok = 0, threw = 0, extractErrors = 0, maxElapsed: TimeInterval = 0
        for iter in 0..<1000 {
            let m = mutate(base.data, rng: &rng, hotRanges: hot)
            let t0 = Date()
            let reader = NativeZIPArchiveReader(data: m, maxEntries: 20_000, maxTotalUncompressedBytes: 32 << 20)
            do {
                let entries = try reader.readCentralDirectory()
                for e in entries.prefix(64) {
                    do { _ = try reader.extract(entry: e) } catch {
                        extractErrors += 1
                        XCTAssertTrue(error is IPAPackageScannerError, "iter=\(iter): untyped extract error \(error)")
                    }
                }
                ok += 1
            } catch {
                threw += 1
                XCTAssertTrue(error is IPAPackageScannerError, "iter=\(iter): untyped CD error \(error)")
            }
            let elapsed = Date().timeIntervalSince(t0)
            maxElapsed = max(maxElapsed, elapsed)
            XCTAssertLessThan(elapsed, 2.0, "iter=\(iter): ZIP reader took \(elapsed)s")
        }
        XCTAssertEqual(ok + threw, 1000)
        print("[R4 INFO] ZIP reader fuzz: 1000 iterations, cdParsed=\(ok), cdTypedErrors=\(threw), extractTypedErrors=\(extractErrors), maxElapsed=\(String(format: "%.4f", maxElapsed))s")
    }

    func test_fuzz_fullIPAScanMutation_300Iterations_noCrashTimeBoundedSourceByteIdentical() throws {
        let base = fuzzIPABase()
        let baseURL = try writeIPA(base.data, "fuzzbase")
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: baseURL).riskTier, .highRisk, "Fuzz seed control must be .highRisk")

        let hot = zipHotRanges(base)
        let fuzzDir = FileManager.default.temporaryDirectory.appendingPathComponent("r4_ipa_fuzz_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: fuzzDir, withIntermediateDirectories: true)
        tempURLs.append(fuzzDir)

        var rng = R4SplitMix64(seed: 0x5234_3000)
        var findings: [RiskTier: Int] = [:]
        var errors: [String: Int] = [:]
        var maxElapsed: TimeInterval = 0
        for iter in 0..<300 {
            let m = mutate(base.data, rng: &rng, hotRanges: hot)
            let url = fuzzDir.appendingPathComponent("m\(iter).ipa")
            try m.write(to: url)
            try FileManager.default.setAttributes([.posixPermissions: 0o444], ofItemAtPath: url.path)
            let before = try ReadOnlyAssertions.captureSnapshot(of: [url])
            let t0 = Date()
            do {
                let f = try IPAPackageScanner.shared.scan(ipaURL: url)
                findings[f.riskTier, default: 0] += 1
            } catch {
                errors[Self.caseName(error), default: 0] += 1
            }
            let elapsed = Date().timeIntervalSince(t0)
            maxElapsed = max(maxElapsed, elapsed)
            XCTAssertLessThan(elapsed, 5.0, "iter=\(iter): IPA scan took \(elapsed)s")
            let after = try ReadOnlyAssertions.captureSnapshot(of: [url])
            ReadOnlyAssertions.assertUnmodified(before: before, after: after)
            XCTAssertEqual(try Data(contentsOf: url), m, "iter=\(iter): scanned IPA bytes changed")
            try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
            try? FileManager.default.removeItem(at: url)
        }
        XCTAssertEqual(findings.values.reduce(0, +) + errors.values.reduce(0, +), 300)
        print("[R4 INFO] Full IPA fuzz: findings=\(findings.map { "\($0.key)=\($0.value)" }.sorted()), errors=\(errors.sorted { $0.key < $1.key }), maxElapsed=\(String(format: "%.4f", maxElapsed))s")
    }
}
