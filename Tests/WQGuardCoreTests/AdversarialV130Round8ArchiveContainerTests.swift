//
//  AdversarialV130Round8ArchiveContainerTests.swift
//  WQGuardCoreTests
//
//  Deep Security Audit Suite (Round 8): ZIP Data Descriptors, Archive/Bundle Symlinks, .xpc & Versioned Frameworks,
//  ChannelClassifier Profile Consistency, Standalone Binary Parity, and Zero-Dereference Multi-Hop Container Inspection.
//

import XCTest
import Foundation
import Darwin
import MachO
import zlib
@testable import WQGuardCore

fileprivate extension Data {
    mutating func r8le16(_ v: UInt16) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r8le32(_ v: UInt32) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r8le64(_ v: UInt64) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r8be16(_ v: UInt16) { var x = v.bigEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func r8be32(_ v: UInt32) { var x = v.bigEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
}

final class AdversarialV130Round8ArchiveContainerTests: XCTestCase {

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
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("r8_\(UUID().uuidString)_\(name)")
        tempURLs.append(u)
        return u
    }

    private static func crc32Of(_ d: Data) -> UInt32 {
        d.withUnsafeBytes { raw in
            UInt32(crc32(0, raw.bindMemory(to: Bytef.self).baseAddress, uInt(d.count)))
        }
    }

    private func cleanMachO() -> Data {
        SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.nopWord, Self.retWord]
        ))
    }

    private func syscallMachO() -> Data {
        SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"],
            textInstructions: [Self.svcWord, Self.retWord]
        ))
    }

    private struct RawZipItem {
        var path: String
        var payload: Data
        var unixMode: UInt32 = 0o100644
        var dataDescriptor: Data? = nil
    }

    private func buildRawZip(_ items: [RawZipItem]) -> Data {
        var archive = Data()
        var cd = Data()
        for item in items {
            let localOff = UInt32(archive.count)
            let nameUTF8 = Data(item.path.utf8)
            let crc = Self.crc32Of(item.payload)
            let hasDD = item.dataDescriptor != nil
            let flags: UInt16 = hasDD ? 0x0008 : 0

            archive.r8le32(0x0403_4b50)
            archive.r8le16(20)
            archive.r8le16(flags)
            archive.r8le16(0) // STORE
            archive.r8le16(0); archive.r8le16(0x21)
            archive.r8le32(hasDD ? 0 : crc)
            archive.r8le32(hasDD ? 0 : UInt32(item.payload.count))
            archive.r8le32(hasDD ? 0 : UInt32(item.payload.count))
            archive.r8le16(UInt16(nameUTF8.count))
            archive.r8le16(0)
            archive.append(nameUTF8)
            archive.append(item.payload)
            if let dd = item.dataDescriptor {
                archive.append(dd)
            }

            cd.r8le32(0x0201_4b50)
            cd.r8le16(0x0314); cd.r8le16(20)
            cd.r8le16(flags)
            cd.r8le16(0)
            cd.r8le16(0); cd.r8le16(0x21)
            cd.r8le32(crc)
            cd.r8le32(UInt32(item.payload.count))
            cd.r8le32(UInt32(item.payload.count))
            cd.r8le16(UInt16(nameUTF8.count))
            cd.r8le16(0); cd.r8le16(0); cd.r8le16(0); cd.r8le16(0)
            cd.r8le32(item.unixMode << 16)
            cd.r8le32(localOff)
            cd.append(nameUTF8)
        }
        let cdOff = UInt32(archive.count)
        archive.append(cd)
        archive.r8le32(0x0605_4b50)
        archive.r8le16(0); archive.r8le16(0)
        archive.r8le16(UInt16(items.count)); archive.r8le16(UInt16(items.count))
        archive.r8le32(UInt32(cd.count))
        archive.r8le32(cdOff)
        archive.r8le16(0)
        return archive
    }

    private func makePlist(_ dict: [String: Any]) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    // MARK: - 1. PKZIP Data Descriptor Size/CRC Disagreement & Disguised Local Header Rejection

    func test_r8_zipDataDescriptor_crcOrSizeMismatch_andLocalHeaderMagicDisguise_rejected() throws {
        let plist = try makePlist([
            "CFBundleIdentifier": "com.r8.dd",
            "CFBundleExecutable": "R8App",
            "CFBundleShortVersionString": "1.0"
        ])
        let exec = cleanMachO()
        let crc = Self.crc32Of(exec)

        // Valid 16-byte Data Descriptor control -> must succeed and scan .safe
        var validDD = Data()
        validDD.r8le32(0x0807_4b50); validDD.r8le32(crc)
        validDD.r8le32(UInt32(exec.count)); validDD.r8le32(UInt32(exec.count))
        let validZip = buildRawZip([
            .init(path: "Payload/R8App.app/Info.plist", payload: plist),
            .init(path: "Payload/R8App.app/R8App", payload: exec, unixMode: 0o100755, dataDescriptor: validDD)
        ])
        let validURL = makeTempURL("valid_dd.ipa")
        try validZip.write(to: validURL)
        XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: validURL).riskTier, .safe)

        // 16-byte DD with forged compressedSize disagreeing with Central Directory -> must throw corruptHeader
        var badSizeDD = Data()
        badSizeDD.r8le32(0x0807_4b50); badSizeDD.r8le32(crc)
        badSizeDD.r8le32(UInt32(exec.count + 64)); badSizeDD.r8le32(UInt32(exec.count))
        let badSizeURL = makeTempURL("bad_dd_size.ipa")
        try buildRawZip([
            .init(path: "Payload/R8App.app/Info.plist", payload: plist),
            .init(path: "Payload/R8App.app/R8App", payload: exec, unixMode: 0o100755, dataDescriptor: badSizeDD)
        ]).write(to: badSizeURL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: badSizeURL))

        // 24-byte ZIP64 DD with forged CRC -> must throw corruptHeader
        var badZ64DD = Data()
        badZ64DD.r8le32(0x0807_4b50); badZ64DD.r8le32(crc ^ 0xDEAD_BEEF)
        badZ64DD.r8le64(UInt64(exec.count)); badZ64DD.r8le64(UInt64(exec.count))
        let badZ64URL = makeTempURL("bad_dd_z64.ipa")
        try buildRawZip([
            .init(path: "Payload/R8App.app/Info.plist", payload: plist),
            .init(path: "Payload/R8App.app/R8App", payload: exec, unixMode: 0o100755, dataDescriptor: badZ64DD)
        ]).write(to: badZ64URL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: badZ64URL))

        // 12-byte signatureless DD whose first 4 bytes equal 0x04034b50 (local header magic) -> must throw corruptHeader
        var disguisedLocalDD = Data()
        disguisedLocalDD.r8le32(0x0403_4b50)
        disguisedLocalDD.r8le32(UInt32(exec.count))
        disguisedLocalDD.r8le32(UInt32(exec.count))
        let disguisedURL = makeTempURL("disguised_dd.ipa")
        try buildRawZip([
            .init(path: "Payload/R8App.app/Info.plist", payload: plist),
            .init(path: "Payload/R8App.app/R8App", payload: exec, unixMode: 0o100755, dataDescriptor: disguisedLocalDD)
        ]).write(to: disguisedURL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: disguisedURL))
    }

    // MARK: - 2. 48-Slice FAT Binary Behind Skipped .png Asset vs Java .class Zero-FP

    func test_r8_fat48SlicesDisguisedAsPNG_extractedAndCaught_whileJavaClassIgnored() throws {
        let plist = try makePlist([
            "CFBundleIdentifier": "com.r8.fat48",
            "CFBundleExecutable": "R8FatApp",
            "CFBundleShortVersionString": "1.0"
        ])
        let clean = cleanMachO()
        let evil = syscallMachO()

        // Build valid 48-slice FAT binary: 47 overlapping clean arm64 entries + 1 arm64e entry with svc #0x80
        var fat48 = Data()
        fat48.r8be32(FAT_MAGIC)
        fat48.r8be32(48)
        let cleanOff: UInt32 = 0x1000
        let evilOff: UInt32 = UInt32(0x1000 + ((clean.count + 0xFFF) & ~0xFFF))
        for i in 0..<48 {
            fat48.r8be32(UInt32(bitPattern: CPU_TYPE_ARM64))
            if i == 47 {
                fat48.r8be32(UInt32(bitPattern: CPU_SUBTYPE_ARM64E))
                fat48.r8be32(evilOff); fat48.r8be32(UInt32(evil.count)); fat48.r8be32(12)
            } else {
                fat48.r8be32(UInt32(bitPattern: CPU_SUBTYPE_ARM64_ALL))
                fat48.r8be32(cleanOff); fat48.r8be32(UInt32(clean.count)); fat48.r8be32(12)
            }
        }
        let totalLen = Int(evilOff) + evil.count
        fat48.append(Data(repeating: 0, count: totalLen - fat48.count))
        fat48.replaceSubrange(Int(cleanOff)..<(Int(cleanOff) + clean.count), with: clean)
        fat48.replaceSubrange(Int(evilOff)..<(Int(evilOff) + evil.count), with: evil)

        XCTAssertTrue(IPAPackageScanner.isMachOOrFatMagic(Data(fat48.prefix(16))),
                      "48-slice Universal FAT header must be recognized as Mach-O")

        let disguisedIPA = makeTempURL("fat48_png.ipa")
        try buildRawZip([
            .init(path: "Payload/R8FatApp.app/Info.plist", payload: plist),
            .init(path: "Payload/R8FatApp.app/R8FatApp", payload: clean, unixMode: 0o100755),
            .init(path: "Payload/R8FatApp.app/Assets/splash.png", payload: fat48)
        ]).write(to: disguisedIPA)

        let fatFinding = try IPAPackageScanner.shared.scan(ipaURL: disguisedIPA)
        XCTAssertEqual(fatFinding.riskTier, .highRisk, "48-slice FAT binary disguised as splash.png must be extracted and caught")
        XCTAssertTrue(fatFinding.indicators.contains { $0.signature == "arm64:svc_0x80" })

        // Java .class file (0xCAFEBABE, minor=0, major=52 [Java 8] and 65 [Java 21], constant_pool_count=16, tag=0x0A Methodref)
        for majorVer: UInt16 in [45, 52, 61, 65] {
            var javaClass = Data()
            javaClass.r8be32(0xCAFE_BABE)
            javaClass.r8be16(0)
            javaClass.r8be16(majorVer)
            javaClass.r8be16(16) // constant_pool_count
            javaClass.append(contentsOf: [0x0A, 0x00, 0x03, 0x00, 0x0C, 0x07, 0x00, 0x0D])
            XCTAssertFalse(IPAPackageScanner.isMachOOrFatMagic(javaClass),
                           "Java .class (major=\(majorVer)) must NOT be misidentified as a FAT Mach-O")

            let javaIPA = makeTempURL("java_\(majorVer).ipa")
            try buildRawZip([
                .init(path: "Payload/R8FatApp.app/Info.plist", payload: plist),
                .init(path: "Payload/R8FatApp.app/R8FatApp", payload: clean, unixMode: 0o100755),
                .init(path: "Payload/R8FatApp.app/Assets/Embedded.png", payload: javaClass)
            ]).write(to: javaIPA)
            XCTAssertEqual(try IPAPackageScanner.shared.scan(ipaURL: javaIPA).riskTier, .safe)
        }
    }

    // MARK: - 3. Archive & Bundle Symlinks: Duplicate Case Collision, Oversized, and Escaping Symlink Detection

    func test_r8_archiveAndBundleSymlinks_duplicateCollisionOversizedAndEscaping_neverSilentlySafe() throws {
        let plist = try makePlist([
            "CFBundleIdentifier": "com.r8.symlink",
            "CFBundleExecutable": "R8SymApp",
            "CFBundleShortVersionString": "1.0"
        ])
        let clean = cleanMachO()
        let evil = syscallMachO()

        // 1. Case-colliding S_IFLNK entries (first points to evil.dat, second overwrites in lowercase to clean.dat) -> fail closed
        let dupSymURL = makeTempURL("dup_symlink.ipa")
        try buildRawZip([
            .init(path: "Payload/R8SymApp.app/Info.plist", payload: plist),
            .init(path: "Payload/R8SymApp.app/R8SymApp", payload: clean, unixMode: 0o100755),
            .init(path: "Payload/R8SymApp.app/evil.txt", payload: evil),
            .init(path: "Payload/R8SymApp.app/clean.txt", payload: clean),
            .init(path: "Payload/R8SymApp.app/Frameworks/Sub.framework/Sub", payload: Data("../../evil.txt".utf8), unixMode: 0o120755),
            .init(path: "Payload/R8SymApp.app/Frameworks/Sub.framework/sub", payload: Data("../../clean.txt".utf8), unixMode: 0o120755)
        ]).write(to: dupSymURL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: dupSymURL))

        // 2. Oversized S_IFLNK (> 4096 bytes) -> fail closed
        let bigSymURL = makeTempURL("oversized_symlink.ipa")
        try buildRawZip([
            .init(path: "Payload/R8SymApp.app/Info.plist", payload: plist),
            .init(path: "Payload/R8SymApp.app/R8SymApp", payload: clean, unixMode: 0o100755),
            .init(path: "Payload/R8SymApp.app/HugeLink", payload: Data(repeating: 0x41, count: 5000), unixMode: 0o120755)
        ]).write(to: bigSymURL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: bigSymURL))

        // 3. Escaping S_IFLNK inside .ipa archive -> stripped on disk AND flagged .highRisk (BUNDLE_ESCAPING_SYMLINK)
        let escapingIPA = makeTempURL("escaping_symlink.ipa")
        try buildRawZip([
            .init(path: "Payload/R8SymApp.app/Info.plist", payload: plist),
            .init(path: "Payload/R8SymApp.app/R8SymApp", payload: clean, unixMode: 0o100755),
            .init(path: "Payload/R8SymApp.app/CachesEscape", payload: Data("../../../../var/mobile/Containers/Data/Application/VICTIM".utf8), unixMode: 0o120755)
        ]).write(to: escapingIPA)
        let escFinding = try IPAPackageScanner.shared.scan(ipaURL: escapingIPA)
        XCTAssertEqual(escFinding.riskTier, .highRisk)
        XCTAssertFalse(escFinding.evidence.escapingSymlinks.isEmpty)
        XCTAssertTrue(escFinding.indicators.contains { $0.signature == "BUNDLE_ESCAPING_SYMLINK" })

        // 4. Escaping symlink inside on-disk .app bundle scanned via SecurityPipeline.scanBundle
        let appDir = makeTempURL("EscBundle.app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        try plist.write(to: appDir.appendingPathComponent("Info.plist"))
        try clean.write(to: appDir.appendingPathComponent("R8SymApp"))
        symlink("/private/etc/passwd", appDir.appendingPathComponent("EscapeOut").path)
        let bundleFinding = try SecurityPipeline.shared.scanBundle(at: appDir)
        XCTAssertEqual(bundleFinding.riskTier, .highRisk)
        XCTAssertTrue(bundleFinding.indicators.contains { $0.signature == "BUNDLE_ESCAPING_SYMLINK" })
    }

    // MARK: - 4. Embedded .xpc Bundles & Versioned Frameworks (Versions/A)

    func test_r8_embeddedXPCService_andVersionedFramework_detectedAcrossIPAAndBundle() throws {
        let appPlist = try makePlist([
            "CFBundleIdentifier": "com.r8.host",
            "CFBundleExecutable": "HostApp",
            "CFBundleShortVersionString": "1.0"
        ])
        let xpcPlist = try makePlist([
            "CFBundleIdentifier": "com.r8.host.worker",
            "CFBundleExecutable": "WorkerXPC",
            "CFBundlePackageType": "XPC!"
        ])
        let clean = cleanMachO()
        let evil = syscallMachO()

        // 1. .xpc carrying svc #0x80
        let xpcIPA = makeTempURL("with_xpc.ipa")
        try buildRawZip([
            .init(path: "Payload/HostApp.app/Info.plist", payload: appPlist),
            .init(path: "Payload/HostApp.app/HostApp", payload: clean, unixMode: 0o100755),
            .init(path: "Payload/HostApp.app/XPCServices/WorkerXPC.xpc/Info.plist", payload: xpcPlist),
            .init(path: "Payload/HostApp.app/XPCServices/WorkerXPC.xpc/WorkerXPC", payload: evil, unixMode: 0o100755)
        ]).write(to: xpcIPA)
        let xpcFinding = try IPAPackageScanner.shared.scan(ipaURL: xpcIPA)
        XCTAssertEqual(xpcFinding.riskTier, .highRisk)
        XCTAssertTrue(xpcFinding.indicators.contains { $0.signature == "arm64:svc_0x80" && $0.location.contains("WorkerXPC.xpc") })

        // 2. Truncated/corrupt Mach-O inside Frameworks/Legacy.framework/Versions/A/Legacy (must be recognized as expected binary role)
        let corruptVerIPA = makeTempURL("versioned_fw_corrupt.ipa")
        try buildRawZip([
            .init(path: "Payload/HostApp.app/Info.plist", payload: appPlist),
            .init(path: "Payload/HostApp.app/HostApp", payload: clean, unixMode: 0o100755),
            .init(path: "Payload/HostApp.app/Frameworks/Legacy.framework/Versions/A/Legacy", payload: Data([0xCF, 0xFA, 0xED, 0xFE, 0x01, 0x02]), unixMode: 0o100755)
        ]).write(to: corruptVerIPA)
        let verFinding = try IPAPackageScanner.shared.scan(ipaURL: corruptVerIPA)
        XCTAssertEqual(verFinding.riskTier, .highRisk)
        XCTAssertTrue(verFinding.indicators.contains { $0.signature == "CorruptMachO:UnparseableBinary" })
    }

    // MARK: - 5. SecurityPipeline.scanBinary Full ExpandedThreatCatalog Parity & Team ID Stripping

    func test_r8_scanBinary_dangerousEntitlements_impersonationAndTeamIdStripping() throws {
        // 1. Standalone binary with no-sandbox = true and 0 App Groups -> High Risk
        let noSandboxXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>application-identifier</key><string>TEAM99ABCD.com.r8.unsandboxed</string>
            <key>com.apple.private.security.no-sandbox</key><true/>
        </dict>
        </plist>
        """
        let noSbxBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            xmlEntitlements: noSandboxXML,
            textInstructions: [Self.retWord]
        ))
        let noSbxURL = makeTempURL("unsandboxed_bin")
        try noSbxBin.write(to: noSbxURL)
        let f1 = try SecurityPipeline.shared.scanBinary(at: noSbxURL)
        XCTAssertEqual(f1.riskTier, .highRisk)
        XCTAssertEqual(f1.teamId, "TEAM99ABCD")
        XCTAssertEqual(f1.bundleId, "com.r8.unsandboxed")
        XCTAssertTrue(f1.indicators.contains { $0.signature == "com.apple.private.security.no-sandbox" })

        // 2. Standalone binary impersonating MetaMask via application-identifier <TeamID>.io.metamask -> High Risk
        let metamaskXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>application-identifier</key><string>ABCDE12345.io.metamask.wallet</string>
        </dict>
        </plist>
        """
        let mmBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            symbols: ["_main"],
            xmlEntitlements: metamaskXML,
            textInstructions: [Self.retWord]
        ))
        let mmURL = makeTempURL("wallet_bin")
        try mmBin.write(to: mmURL)
        let f2 = try SecurityPipeline.shared.scanBinary(at: mmURL)
        XCTAssertEqual(f2.riskTier, .highRisk)
        XCTAssertEqual(f2.bundleId, "io.metamask.wallet")
        XCTAssertTrue(f2.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })
    }

    // MARK: - 6. ChannelClassifier Backwards </plist> & Re-Signed Encrypted Binary Detection

    func test_r8_channelClassifier_embeddedClosePlistLiteral_andResignedEncryptedProfileMismatch() throws {
        // 1. CMS wrapper whose XML plist contains a literal "</plist>" inside a string value
        let innerXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Name</key><string>Profile with literal &lt;/plist&gt; and <![CDATA[</plist>]]> token</string>
            <key>TeamIdentifier</key><array><string>ENT8889990</string></array>
            <key>ProvisionsAllDevices</key><true/>
        </dict>
        </plist>
        """
        var cmsWrapped = Data([0x30, 0x82, 0x02, 0x00, 0x06, 0x09])
        cmsWrapped.append(Data(innerXML.utf8))
        cmsWrapped.append(contentsOf: [0x31, 0x00, 0x00])

        let extracted = ChannelClassifier.extractPlist(from: cmsWrapped)
        XCTAssertEqual((extracted?["TeamIdentifier"] as? [String])?.first, "ENT8889990")

        // 2. Encrypted binary (cryptid = 1) re-signed with Enterprise or UDID-scoped Developer profile must NOT classify as .appStore
        let entRes = ChannelClassifier.classify(cryptid: 1, mobileprovisionData: cmsWrapped)
        XCTAssertEqual(entRes.channel, .enterpriseInHouse)
        XCTAssertTrue(entRes.isEnterprise)

        let devPlist = try makePlist([
            "TeamIdentifier": ["DEV7776665"],
            "ProvisionedDevices": ["00008130-0011223344556677"]
        ])
        let devRes = ChannelClassifier.classify(cryptid: 1, mobileprovisionData: devPlist)
        XCTAssertEqual(devRes.channel, .developerSideloaded)
    }

    // MARK: - 7. ContainerScanner: Library Symlink, 2-Hop Internal Pivot, and O_NOFOLLOW + FIFO Safety

    func test_r8_containerScanner_librarySymlink_twoHopPivot_andNoFollowSupervisionFIFO() throws {
        // 1. <Container>/Library replaced by an escaping symlink -> CONTAINER_LIBRARY_SYMLINK (.highRisk)
        let c1 = makeTempURL("container_libsym")
        try FileManager.default.createDirectory(at: c1, withIntermediateDirectories: true)
        symlink("/private/var/mobile", c1.appendingPathComponent("Library").path)
        let r1 = try ContainerScanner.shared.scanContainer(at: c1)
        XCTAssertFalse(r1.isClean)
        XCTAssertTrue(r1.indicators.contains { $0.signature == "CONTAINER_LIBRARY_SYMLINK" && $0.severity == .highRisk })

        // 2. Two-hop internal pivot: Library/Caches/hop1 -> ../../Documents/hop2, Documents/hop2 -> /etc/passwd
        let c2 = makeTempURL("container_twohop")
        let caches2 = c2.appendingPathComponent("Library/Caches")
        let docs2 = c2.appendingPathComponent("Documents")
        try FileManager.default.createDirectory(at: caches2, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: docs2, withIntermediateDirectories: true)
        symlink("/etc/passwd", docs2.appendingPathComponent("hop2").path)
        symlink("../../Documents/hop2", caches2.appendingPathComponent("hop1").path)
        let r2 = try ContainerScanner.shared.scanContainer(at: c2)
        XCTAssertFalse(r2.isClean)
        XCTAssertEqual(r2.escapingSymlinks.count, 1)
        XCTAssertTrue(r2.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" && $0.severity == .highRisk })

        // 3. Intermediate directory symlink pivot: Documents -> /private/var/mobile/Victim, Caches/entry -> ../../Documents/secret.db
        let c3 = makeTempURL("container_dirpivot")
        let caches3 = c3.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: caches3, withIntermediateDirectories: true)
        symlink("/private/var/mobile/Victim", c3.appendingPathComponent("Documents").path)
        symlink("../../Documents/secret.db", caches3.appendingPathComponent("entry").path)
        let r3 = try ContainerScanner.shared.scanContainer(at: c3)
        XCTAssertFalse(r3.isClean)
        XCTAssertTrue(r3.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" && $0.severity == .highRisk })

        // 4. Symlinked CloudConfigurationDetails.plist pointing outside container + FIFO CloudConfigurationDetails.plist (must NEVER block!)
        let outsideSupervised = makeTempURL("outside_supervised.plist")
        try makePlist(["IsSupervised": true]).write(to: outsideSupervised)

        let supRoot = makeTempURL("shared_groups_root")
        let sysGrp = supRoot.appendingPathComponent("systemgroup.com.apple.configurationprofiles")
        let cfgDir = sysGrp.appendingPathComponent("Library/ConfigurationProfiles")
        try FileManager.default.createDirectory(at: cfgDir, withIntermediateDirectories: true)
        let cloudPlistPath = cfgDir.appendingPathComponent("CloudConfigurationDetails.plist").path
        symlink(outsideSupervised.path, cloudPlistPath)

        let symContainerRes = try ContainerScanner.shared.scanContainer(at: sysGrp)
        XCTAssertTrue(symContainerRes.indicators.contains { $0.signature == "CONTAINER_SUPERVISION_SYMLINK" && $0.severity == .highRisk })
        let symCatalogRes = ExpandedThreatCatalog.evaluateSupervision(containerRoot: supRoot)
        XCTAssertTrue(symCatalogRes.contains { $0.signature == "CloudConfigurationDetails.SymlinkHazard" && $0.severity == .highRisk })

        // Replace symlink with a POSIX named pipe (FIFO): unguarded Data(contentsOf:) would block forever waiting for a writer!
        try FileManager.default.removeItem(atPath: cloudPlistPath)
        guard mkfifo(cloudPlistPath, 0o600) == 0 else {
            throw XCTSkip("mkfifo not permitted in current temporary directory")
        }
        let start = Date()
        let fifoContainerRes = try ContainerScanner.shared.scanContainer(at: sysGrp)
        let fifoCatalogRes = ExpandedThreatCatalog.evaluateSupervision(containerRoot: supRoot)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2.0, "FIFO at CloudConfigurationDetails.plist must never block")
        XCTAssertTrue(fifoContainerRes.indicators.contains { $0.signature == "CONTAINER_SUPERVISION_SPECIAL_FILE" })
        XCTAssertTrue(fifoCatalogRes.contains { $0.signature == "CloudConfigurationDetails.SpecialFileHazard" })
    }

    // MARK: - 8. ZIP64 EOCD Validation vs Dual-CD Polyglot & Gap Smuggling

    private func buildZip64Archive(items: [RawZipItem], classicTotalOverride: UInt16 = 0xFFFF, classicCDOffOverride: UInt32 = 0xFFFF_FFFF) -> Data {
        var archive = Data()
        var cd = Data()
        for item in items {
            let localOff = UInt32(archive.count)
            let nameUTF8 = Data(item.path.utf8)
            let crc = Self.crc32Of(item.payload)

            archive.r8le32(0x0403_4b50)
            archive.r8le16(45); archive.r8le16(0); archive.r8le16(0)
            archive.r8le16(0); archive.r8le16(0x21)
            archive.r8le32(crc)
            archive.r8le32(UInt32(item.payload.count))
            archive.r8le32(UInt32(item.payload.count))
            archive.r8le16(UInt16(nameUTF8.count)); archive.r8le16(0)
            archive.append(nameUTF8)
            archive.append(item.payload)

            cd.r8le32(0x0201_4b50)
            cd.r8le16(45); cd.r8le16(45); cd.r8le16(0); cd.r8le16(0)
            cd.r8le16(0); cd.r8le16(0x21)
            cd.r8le32(crc)
            cd.r8le32(UInt32(item.payload.count))
            cd.r8le32(UInt32(item.payload.count))
            cd.r8le16(UInt16(nameUTF8.count))
            cd.r8le16(0); cd.r8le16(0); cd.r8le16(0); cd.r8le16(0)
            cd.r8le32(item.unixMode << 16)
            cd.r8le32(localOff)
            cd.append(nameUTF8)
        }
        let cdOff = UInt64(archive.count)
        let cdSize = UInt64(cd.count)
        archive.append(cd)

        // ZIP64 EOCD Record (56 bytes)
        let zip64EOCDOff = UInt64(archive.count)
        archive.r8le32(0x0606_4b50)
        archive.r8le64(44) // size of remaining record
        archive.r8le16(45); archive.r8le16(45)
        archive.r8le32(0); archive.r8le32(0)
        archive.r8le64(UInt64(items.count))
        archive.r8le64(UInt64(items.count))
        archive.r8le64(cdSize)
        archive.r8le64(cdOff)

        // ZIP64 EOCD Locator (20 bytes)
        archive.r8le32(0x0706_4b50)
        archive.r8le32(0)
        archive.r8le64(zip64EOCDOff)
        archive.r8le32(1)

        // Classic EOCD (22 bytes)
        archive.r8le32(0x0605_4b50)
        archive.r8le16(0); archive.r8le16(0)
        archive.r8le16(classicTotalOverride)
        archive.r8le16(classicTotalOverride)
        archive.r8le32(0xFFFF_FFFF)
        archive.r8le32(classicCDOffOverride)
        archive.r8le16(0)
        return archive
    }

    func test_r8_zip64ValidArchive_vs_dualCentralDirectoryPolyglot_andGapSmuggling_rejected() throws {
        let plist = try makePlist([
            "CFBundleIdentifier": "com.r8.zip64",
            "CFBundleExecutable": "Z64App",
            "CFBundleShortVersionString": "1.0"
        ])
        let validZ64 = buildZip64Archive(items: [
            .init(path: "Payload/Z64App.app/Info.plist", payload: plist),
            .init(path: "Payload/Z64App.app/Z64App", payload: syscallMachO(), unixMode: 0o100755)
        ])
        let validURL = makeTempURL("valid_zip64.ipa")
        try validZ64.write(to: validURL)
        let validFinding = try IPAPackageScanner.shared.scan(ipaURL: validURL)
        XCTAssertEqual(validFinding.riskTier, .highRisk)

        // 1. Dual-CD polyglot disagreement: Classic EOCD claims non-sentinel totalEntries = 1 while ZIP64 EOCD has 2
        let mismatchZ64 = buildZip64Archive(items: [
            .init(path: "Payload/Z64App.app/Info.plist", payload: plist),
            .init(path: "Payload/Z64App.app/Z64App", payload: syscallMachO(), unixMode: 0o100755)
        ], classicTotalOverride: 1)
        let mismatchURL = makeTempURL("mismatch_zip64.ipa")
        try mismatchZ64.write(to: mismatchURL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: mismatchURL)) { err in
            guard case IPAPackageScannerError.corruptHeader = err else {
                XCTFail("Expected corruptHeader on ZIP64 vs Classic EOCD disagreement, got \(err)")
                return
            }
        }

        // 2. Fake 0x06064b50 gap smuggling between Classic CD and Classic EOCD without a valid 0x07064b50 locator
        var gapSmuggle = buildRawZip([
            .init(path: "Payload/Z64App.app/Info.plist", payload: plist),
            .init(path: "Payload/Z64App.app/Z64App", payload: cleanMachO(), unixMode: 0o100755)
        ])
        let eocdSlice = Data(gapSmuggle.suffix(22))
        gapSmuggle.removeLast(22)
        gapSmuggle.r8le32(0x0606_4b50) // fake ZIP64 EOCD magic without locator!
        gapSmuggle.append(Data(repeating: 0x41, count: 52))
        gapSmuggle.append(eocdSlice)
        let smuggleURL = makeTempURL("gap_smuggle.ipa")
        try gapSmuggle.write(to: smuggleURL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: smuggleURL)) { err in
            guard case IPAPackageScannerError.corruptHeader = err else {
                XCTFail("Expected corruptHeader on unlocated 0x06064b50 gap smuggling, got \(err)")
                return
            }
        }
    }

    // MARK: - 9. DEFLATE Empty-Block Padding (>512B), 2-Slice FAT cputype[1] Disguise & Directory Symlink .appex

    func test_r8_deflateEmptyBlockPadding_fatSecondSliceDisguise_andInBundleDirectorySymlinkAppex() throws {
        let appPlist = try makePlist([
            "CFBundleIdentifier": "com.r8.stealth.pkg",
            "CFBundleExecutable": "StealthApp",
            "CFBundleShortVersionString": "1.0"
        ])
        let extPlist = try makePlist([
            "CFBundleIdentifier": "com.r8.stealth.pkg.ext",
            "CFBundleExecutable": "HiddenExt",
            "CFBundleShortVersionString": "1.0",
            "NSAccessorySetupKitSupports": ["Bluetooth"]
        ])

        // 1. Build raw RFC 1951 DEFLATE stream: 120 non-final empty stored blocks (600 bytes > old 512B peek window)
        //    followed by a final stored block holding syscallMachO() disguised as Assets/logo.png
        let rawEvilMachO = syscallMachO()
        XCTAssertLessThan(rawEvilMachO.count, 65_535)
        var paddedDeflate = Data()
        for _ in 0..<120 {
            paddedDeflate.append(contentsOf: [0x00, 0x00, 0x00, 0xFF, 0xFF]) // BFINAL=0, BTYPE=00, LEN=0, NLEN=0xFFFF
        }
        paddedDeflate.append(0x01) // BFINAL=1, BTYPE=00
        let len16 = UInt16(rawEvilMachO.count)
        paddedDeflate.r8le16(len16)
        paddedDeflate.r8le16(~len16)
        paddedDeflate.append(rawEvilMachO)

        // Build custom ZIP with method=8 (DEFLATE) for Assets/logo.png, plus 2-slice FAT disguised as Assets/bg.jpg,
        // plus in-bundle directory symlink PlugIns/Hidden.appex -> ../Resources/RealExt
        var fatSecondArm64 = Data()
        let dummySlice = Data(repeating: 0xCC, count: 64)
        let off0: UInt32 = 0x100
        let off1: UInt32 = 0x200
        fatSecondArm64.r8be32(0xCAFE_BABE)
        fatSecondArm64.r8be32(2)
        // Slice 0: unknown cputype = 99 (evades naive fat_arch[0]-only check while byte 10 == 0 avoids Java .class)
        fatSecondArm64.r8be32(99); fatSecondArm64.r8be32(0); fatSecondArm64.r8be32(off0); fatSecondArm64.r8be32(UInt32(dummySlice.count)); fatSecondArm64.r8be32(4)
        // Slice 1: valid CPU_TYPE_ARM64 holding syscallMachO()
        fatSecondArm64.r8be32(UInt32(bitPattern: CPU_TYPE_ARM64)); fatSecondArm64.r8be32(0); fatSecondArm64.r8be32(off1); fatSecondArm64.r8be32(UInt32(rawEvilMachO.count)); fatSecondArm64.r8be32(4)
        fatSecondArm64.append(Data(repeating: 0, count: Int(off0) - fatSecondArm64.count))
        fatSecondArm64.append(dummySlice)
        fatSecondArm64.append(Data(repeating: 0, count: Int(off1) - fatSecondArm64.count))
        fatSecondArm64.append(rawEvilMachO)

        // Build archive manually so Assets/logo.png uses compression method 8
        struct CustomMethodItem {
            var path: String
            var rawPayload: Data
            var compressedPayload: Data
            var method: UInt16
            var unixMode: UInt32
        }
        let appexExec = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            linkedDylibs: ["/System/Library/Frameworks/AccessorySetupKit.framework/AccessorySetupKit"],
            symbols: ["_OBJC_CLASS_$_ASAccessorySession"],
            textInstructions: [Self.nopWord, Self.retWord]
        ))
        let entries: [CustomMethodItem] = [
            .init(path: "Payload/StealthApp.app/Info.plist", rawPayload: appPlist, compressedPayload: appPlist, method: 0, unixMode: 0o100644),
            .init(path: "Payload/StealthApp.app/StealthApp", rawPayload: cleanMachO(), compressedPayload: cleanMachO(), method: 0, unixMode: 0o100755),
            .init(path: "Payload/StealthApp.app/Assets/logo.png", rawPayload: rawEvilMachO, compressedPayload: paddedDeflate, method: 8, unixMode: 0o100644),
            .init(path: "Payload/StealthApp.app/Assets/bg.jpg", rawPayload: fatSecondArm64, compressedPayload: fatSecondArm64, method: 0, unixMode: 0o100644),
            .init(path: "Payload/StealthApp.app/Resources/RealExt/Info.plist", rawPayload: extPlist, compressedPayload: extPlist, method: 0, unixMode: 0o100644),
            .init(path: "Payload/StealthApp.app/Resources/RealExt/HiddenExt", rawPayload: appexExec, compressedPayload: appexExec, method: 0, unixMode: 0o100755),
            .init(path: "Payload/StealthApp.app/PlugIns/Hidden.appex", rawPayload: Data("../Resources/RealExt".utf8), compressedPayload: Data("../Resources/RealExt".utf8), method: 0, unixMode: 0o120777)
        ]

        var zip = Data()
        var cd = Data()
        for e in entries {
            let localOff = UInt32(zip.count)
            let nameUTF8 = Data(e.path.utf8)
            let crc = Self.crc32Of(e.rawPayload)
            zip.r8le32(0x0403_4b50); zip.r8le16(20); zip.r8le16(0); zip.r8le16(e.method)
            zip.r8le16(0); zip.r8le16(0x21); zip.r8le32(crc)
            zip.r8le32(UInt32(e.compressedPayload.count)); zip.r8le32(UInt32(e.rawPayload.count))
            zip.r8le16(UInt16(nameUTF8.count)); zip.r8le16(0)
            zip.append(nameUTF8); zip.append(e.compressedPayload)

            cd.r8le32(0x0201_4b50); cd.r8le16(0x0314); cd.r8le16(20); cd.r8le16(0); cd.r8le16(e.method)
            cd.r8le16(0); cd.r8le16(0x21); cd.r8le32(crc)
            cd.r8le32(UInt32(e.compressedPayload.count)); cd.r8le32(UInt32(e.rawPayload.count))
            cd.r8le16(UInt16(nameUTF8.count)); cd.r8le16(0); cd.r8le16(0); cd.r8le16(0); cd.r8le16(0)
            cd.r8le32(e.unixMode << 16); cd.r8le32(localOff); cd.append(nameUTF8)
        }
        let cdOff = UInt32(zip.count)
        zip.append(cd)
        zip.r8le32(0x0605_4b50); zip.r8le16(0); zip.r8le16(0)
        zip.r8le16(UInt16(entries.count)); zip.r8le16(UInt16(entries.count))
        zip.r8le32(UInt32(cd.count)); zip.r8le32(cdOff); zip.r8le16(0)

        let ipaURL = makeTempURL("deflate_fat_dirsym.ipa")
        try zip.write(to: ipaURL)
        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        XCTAssertEqual(finding.riskTier, .highRisk)

        let logoSyscalls = finding.indicators.filter { $0.signature == "arm64:svc_0x80" && $0.location.contains("logo.png") }
        XCTAssertFalse(logoSyscalls.isEmpty, "600B empty stored-block DEFLATE padding must not hide disguised Mach-O in logo.png")
        let bgCorrupt = finding.indicators.filter { $0.signature == "CorruptMachO:UnparseableSlice" && $0.location.contains("bg.jpg") }
        XCTAssertFalse(bgCorrupt.isEmpty, "2-slice FAT with cputype[1]=ARM64 disguised as bg.jpg must be detected")
        XCTAssertTrue(finding.indicators.contains { $0.signature == "CVE-2026-84493:AccessorySetupKitBypass" },
                      "In-bundle directory symlink PlugIns/Hidden.appex -> ../Resources/RealExt must be materialized and audited")
    }

    // MARK: - 10. ChannelClassifier Trailing </plist> in CMS, Symlinked Profile, Deep Caches Symlink & MCMReader FIFO

    func test_r8_channelClassifierTrailingClosePlist_symlinkedProfile_deepCachesEscape_andMCMReaderFIFOSafety() throws {
        // 1. Enterprise mobileprovision with cryptid=1 where trailing CMS unauthenticated attributes contain literal </plist>
        let entXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
        <dict>
            <key>TeamIdentifier</key><array><string>ENTCORP123</string></array>
            <key>ProvisionsAllDevices</key><true/>
        </dict>
        </plist>
        """
        var cmsWithTrailingTag = Data([0x30, 0x82, 0x02, 0x00])
        cmsWithTrailingTag.append(Data(entXML.utf8))
        cmsWithTrailingTag.append(Data("CMS_CERT_DER_BYTES_WITH_UNAUTHENTICATED_</plist>_TOKEN".utf8))

        let classified = ChannelClassifier.classify(cryptid: 1, mobileprovisionData: cmsWithTrailingTag)
        XCTAssertEqual(classified.channel, .enterpriseInHouse,
                       "Trailing </plist> in CMS bytes must never cause cryptid=1 Enterprise build to masquerade as .appStore")
        XCTAssertEqual(classified.teamIdentifier, "ENTCORP123")

        // 2. Bundle on disk with escaping symlink embedded.mobileprovision -> must NOT dereference external file
        let extProfile = makeTempURL("outside.mobileprovision")
        try cmsWithTrailingTag.write(to: extProfile)
        let appDir = makeTempURL("SymProfile.app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        symlink(extProfile.path, appDir.appendingPathComponent("embedded.mobileprovision").path)
        let bundleClass = ChannelClassifier.classifyBundle(at: appDir, cryptid: 0)
        XCTAssertNil(bundleClass.teamIdentifier, "ChannelClassifier.classifyBundle must never follow external symlinked mobileprovision")

        // 3. Deeply nested escaping symlink inside Library/Caches/com.apple.nsurlsessiond/Downloads/lvl3/escape
        let deepContainer = makeTempURL("deep_caches_container")
        let deepDir = deepContainer.appendingPathComponent("Library/Caches/com.apple.nsurlsessiond/Downloads/lvl3")
        try FileManager.default.createDirectory(at: deepDir, withIntermediateDirectories: true)
        symlink("/private/var/mobile/Library/SMS/sms.db", deepDir.appendingPathComponent("escape").path)
        let deepRes = try ContainerScanner.shared.scanContainer(at: deepContainer)
        XCTAssertFalse(deepRes.isClean)
        XCTAssertTrue(deepRes.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" && $0.severity == .highRisk })

        // 4. MCMReader FIFO safety: named pipe at .com.apple.mobile_container_manager.metadata.plist must never block
        let mcmDir = makeTempURL("mcm_fifo_container")
        try FileManager.default.createDirectory(at: mcmDir, withIntermediateDirectories: true)
        let mcmPlistPath = mcmDir.appendingPathComponent(".com.apple.mobile_container_manager.metadata.plist").path
        if mkfifo(mcmPlistPath, 0o600) == 0 {
            let t0 = Date()
            let mcmMeta = try? MCMReader.shared.readMetadata(inContainer: mcmDir)
            XCTAssertNil(mcmMeta)
            XCTAssertLessThan(Date().timeIntervalSince(t0), 2.0, "MCMReader must open metadata plist with O_NONBLOCK and reject FIFOs")
        }
    }
}
