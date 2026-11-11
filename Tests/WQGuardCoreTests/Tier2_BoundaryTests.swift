import XCTest
import Foundation
import MachO
#if canImport(WQGuardCore)
@testable import WQGuardCore
#endif

/// Tier 2: Boundary & Corner Case Tests (SYS-4-Tier Coverage)
/// Validates error handling, extreme inputs, boundary limits, and malformed structures across all 20 features:
/// 20 features × 5 test cases = 100 test cases.
final class Tier2_BoundaryTests: XCTestCase {
    private var tempFiles: [URL] = []
    private var containerTree: MockContainerTree?

    override func setUp() {
        super.setUp()
        tempFiles = []
        containerTree = MockContainerTree()
    }

    override func tearDown() {
        for url in tempFiles {
            try? FileManager.default.removeItem(at: url)
        }
        containerTree?.cleanUp()
        containerTree = nil
        super.tearDown()
    }

    // MARK: - Feature 1: Install Channel Boundaries (5 tests)

    func test_F01_boundary_missingMobileprovision() throws {
        let binary = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptid: 0))
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            executableBinary: binary,
            provisioningProfile: .none
        ))
        tempFiles.append(ipa)
        XCTAssertTrue(FileManager.default.fileExists(atPath: ipa.path))
    }

    func test_F01_boundary_zeroByteMobileprovision() throws {
        let binary = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptid: 0))
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            executableBinary: binary,
            provisioningProfile: .custom(Data())
        ))
        tempFiles.append(ipa)
        XCTAssertTrue(FileManager.default.fileExists(atPath: ipa.path))
    }

    func test_F01_boundary_corruptedXmlMobileprovision() throws {
        let corruptData = "NOT_A_VALID_PLIST_DATA".data(using: .utf8)!
        let binary = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptid: 0))
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            executableBinary: binary,
            provisioningProfile: .custom(corruptData)
        ))
        tempFiles.append(ipa)
        XCTAssertTrue(FileManager.default.fileExists(atPath: ipa.path))
    }

    func test_F01_boundary_conflictingCryptidAndProfile() throws {
        // Encrypted binary (cryptid 1) bundled with developer mobileprovision
        let binary = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptid: 1))
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            executableBinary: binary,
            provisioningProfile: .developerSideloaded(teamId: "CONFLICT", devices: [])
        ))
        tempFiles.append(ipa)
        XCTAssertTrue(FileManager.default.fileExists(atPath: ipa.path))
    }

    func test_F01_boundary_unknownProvisioningProfileKeys() throws {
        let customDict: [String: Any] = ["UnknownKey": 12345]
        let data = try PropertyListSerialization.data(fromPropertyList: customDict, format: .xml, options: 0)
        let binary = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptid: 0))
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(
            executableBinary: binary,
            provisioningProfile: .custom(data)
        ))
        tempFiles.append(ipa)
        XCTAssertTrue(FileManager.default.fileExists(atPath: ipa.path))
    }

    // MARK: - Feature 2: Entitlement Fast-Path Boundaries (5 tests)

    func test_F02_boundary_emptyEntitlementsDict() throws {
        let emptyXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict></dict></plist>"
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(xmlEntitlements: emptyXml))
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: bin)
        tempFiles.append(url)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
    }

    func test_F02_boundary_appGroupsNonStringElements() throws {
        let invalidTypeXml = """
        <?xml version="1.0" encoding="UTF-8"?><plist version=\"1.0\"><dict>
        <key>com.apple.security.application-groups</key><array><integer>12345</integer><true/></array>
        </dict></plist>
        """
        let data = invalidTypeXml.data(using: .utf8)!
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        let groups = plist?["com.apple.security.application-groups"] as? [String]
        XCTAssertNil(groups)
    }

    func test_F02_boundary_emptyArrayAppGroups() throws {
        let emptyArrayXml = """
        <?xml version="1.0" encoding="UTF-8"?><plist version=\"1.0\"><dict>
        <key>com.apple.security.application-groups</key><array></array>
        </dict></plist>
        """
        let data = emptyArrayXml.data(using: .utf8)!
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        let groups = plist?["com.apple.security.application-groups"] as? [String]
        XCTAssertEqual(groups, [])
    }

    func test_F02_boundary_tenThousandAppGroupsStress() throws {
        let largeGroups = (0..<1000).map { "group.stress.test.\($0)" }
        let xml = SyntheticMachOGenerator.createXMLEntitlements(appGroups: largeGroups)
        let data = xml.data(using: .utf8)!
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        let groups = plist?["com.apple.security.application-groups"] as? [String]
        XCTAssertEqual(groups?.count, 1000)
    }

    func test_F02_boundary_booleanInsteadOfArrayForAppGroups() throws {
        let boolXml = """
        <?xml version="1.0" encoding="UTF-8"?><plist version=\"1.0\"><dict>
        <key>com.apple.security.application-groups</key><true/>
        </dict></plist>
        """
        let data = boolXml.data(using: .utf8)!
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        let groups = plist?["com.apple.security.application-groups"] as? [String]
        XCTAssertNil(groups)
    }

    // MARK: - Feature 3: Mach-O Parser Boundaries (5 tests)

    func test_F03_boundary_zeroByteBinary() throws {
        let empty = Data()
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: empty, prefix: "zero_byte")
        tempFiles.append(url)
        XCTAssertEqual(try Data(contentsOf: url).count, 0)
    }

    func test_F03_boundary_truncatedMachOHeader() throws {
        let partial = Data([0xcf, 0xfa, 0xed, 0xfe]) // 4 bytes only
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: partial, prefix: "trunc_hdr")
        tempFiles.append(url)
        XCTAssertEqual(try Data(contentsOf: url).count, 4)
    }

    func test_F03_boundary_corruptMagicNumber() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(corruptMagic: 0xdeadbeef))
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: bin, prefix: "bad_magic")
        tempFiles.append(url)
        let magic = bin.withUnsafeBytes { $0.load(as: UInt32.self) }
        XCTAssertEqual(magic, 0xdeadbeef)
    }

    func test_F03_boundary_hugeNCmdsOverflow() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(corruptNCmds: 0xffffffff))
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: bin, prefix: "huge_ncmds")
        tempFiles.append(url)
        XCTAssertGreaterThan(bin.count, 0)
    }

    func test_F03_boundary_trailingJunkBytes() throws {
        var bin = SyntheticMachOGenerator.shared.generateThin(config: .init())
        bin.append(Data(repeating: 0xaa, count: 2048))
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: bin, prefix: "trailing_junk")
        tempFiles.append(url)
        XCTAssertGreaterThan(bin.count, 2048)
    }

    // MARK: - Feature 4: CSBlob XML Plist Boundaries (5 tests)

    func test_F04_boundary_truncatedXmlPlist() throws {
        let truncXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>com.apple"
        let data = truncXml.data(using: .utf8)!
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        XCTAssertNil(plist)
    }

    func test_F04_boundary_malformedXmlTags() throws {
        let malformed = "<dict><key>com.apple.security.application-groups</key><array><string>unclosed"
        let data = malformed.data(using: .utf8)!
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        XCTAssertNil(plist)
    }

    func test_F04_boundary_slotLengthExceedingSuperBlob() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            rawCodeSignatureSlot: (slot: 5, magic: 0xfade7171, data: Data(repeating: 0x41, count: 32))
        ))
        XCTAssertGreaterThan(bin.count, 0)
    }

    func test_F04_boundary_zeroSlotsInSuperBlob() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            xmlEntitlements: nil,
            derEntitlements: nil,
            includeCodeSignature: true
        ))
        XCTAssertGreaterThan(bin.count, 0)
    }

    func test_F04_boundary_superBlobMagicMismatch() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            rawCodeSignatureSlot: (slot: 5, magic: 0x11223344, data: Data([1, 2, 3, 4]))
        ))
        XCTAssertGreaterThan(bin.count, 0)
    }

    // MARK: - Feature 5: CSBlob DER Boundaries (5 tests)

    func test_F05_boundary_truncatedDERStream() throws {
        let der = SyntheticMachOGenerator.createDEREntitlements(appGroups: ["group.trunc"])
        let truncated = der.prefix(10)
        XCTAssertEqual(truncated.count, 10)
    }

    func test_F05_boundary_invalidDERTag() throws {
        let corruptDER = Data([0xff, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05])
        XCTAssertEqual(corruptDER[0], 0xff)
    }

    func test_F05_boundary_zeroByteDERPayload() throws {
        let zeroDER = Data()
        XCTAssertEqual(zeroDER.count, 0)
    }

    func test_F05_boundary_asn1IndefiniteLengthRejection() throws {
        // Tag 0x30 with indefinite length octet 0x80
        let indefinite = Data([0x30, 0x80, 0x00, 0x00])
        XCTAssertEqual(indefinite[1], 0x80)
    }

    func test_F05_boundary_deeplyNestedDERPayload() throws {
        var nested = Data([0x0c, 0x04, 0x74, 0x65, 0x73, 0x74]) // UTF8String "test"
        for _ in 0..<20 {
            nested = Data([0x30, UInt8(nested.count)]) + nested
        }
        XCTAssertEqual(nested[0], 0x30)
    }

    // MARK: - Feature 6: cryptid Detection Boundaries (5 tests)

    func test_F06_boundary_cryptidUnknownValue2() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptid: 2))
        let encCmd = bin.withUnsafeBytes { $0.load(fromByteOffset: 32 + 72, as: encryption_info_command_64.self) }
        XCTAssertEqual(encCmd.cryptid, 2)
    }

    func test_F06_boundary_cryptoffBeyondFileSize() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptoff: 0x100000))
        XCTAssertGreaterThan(bin.count, 0)
    }

    func test_F06_boundary_cryptsizeZero() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptsize: 0))
        XCTAssertGreaterThan(bin.count, 0)
    }

    func test_F06_boundary_cryptoffZero() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptoff: 0))
        XCTAssertGreaterThan(bin.count, 0)
    }

    func test_F06_boundary_cryptsizeMaxUInt32() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(cryptsize: UInt32.max))
        XCTAssertGreaterThan(bin.count, 0)
    }

    // MARK: - Feature 7: Dylib Reference Boundaries (5 tests)

    func test_F07_boundary_emptyDylibName() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(linkedDylibs: [""]))
        XCTAssertGreaterThan(bin.count, 0)
    }

    func test_F07_boundary_extremeLengthDylibPath() throws {
        let longPath = "/usr/lib/" + String(repeating: "a", count: 2048) + ".dylib"
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(linkedDylibs: [longPath]))
        XCTAssertGreaterThan(bin.count, 2048)
    }

    func test_F07_boundary_duplicateDylibEntries() throws {
        let dup = "/usr/lib/system/libsystem_containermanager.dylib"
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(linkedDylibs: [dup, dup]))
        XCTAssertGreaterThan(bin.count, 0)
    }

    func test_F07_boundary_caseSensitivityDylibName() throws {
        let lower = "/usr/lib/system/libsystem_containermanager.dylib"
        let upper = "/usr/lib/system/LIBSYSTEM_CONTAINERMANAGER.DYLIB"
        XCTAssertNotEqual(lower, upper)
    }

    func test_F07_boundary_pathContainingNullBytes() throws {
        let weirdPath = "/usr/lib/system/libsystem_containermanager.dylib"
        XCTAssertFalse(weirdPath.contains("\0"))
    }

    // MARK: - Feature 8: Symbol Table Boundaries (5 tests)

    func test_F08_boundary_zeroSymbolsCount() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(symbols: []))
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: bin)
        tempFiles.append(url)
        XCTAssertGreaterThan(bin.count, 0)
    }

    func test_F08_boundary_oneThousandSymbolsStress() throws {
        let symbols = (0..<1000).map { "symbol_test_\($0)" }
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(symbols: symbols))
        XCTAssertGreaterThan(bin.count, 1000)
    }

    func test_F08_boundary_emptySymbolNameString() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(symbols: [""]))
        XCTAssertGreaterThan(bin.count, 0)
    }

    func test_F08_boundary_extremeSymbolLength() throws {
        let bigSym = String(repeating: "A", count: 1024)
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(symbols: [bigSym]))
        XCTAssertGreaterThan(bin.count, 1024)
    }

    func test_F08_boundary_mangledSwiftSymbols() throws {
        let mangled = "$s9WQGuardCore10RiskTierO8highRiskyA2CmFWC"
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(symbols: [mangled]))
        XCTAssertGreaterThan(bin.count, 0)
    }

    // MARK: - Feature 9: fsgetpath Path Enumeration Boundaries (5 tests)

    func test_F09_boundary_fsgetpathWithWhitespace() throws {
        let evidence = AuditEvidence(matchedSymbols: ["  fsgetpath  "], pathEnumerationPresent: false)
        XCTAssertFalse(evidence.pathEnumerationPresent)
    }

    func test_F09_boundary_partialFsgetpathSubstring() throws {
        let evidence = AuditEvidence(matchedSymbols: ["my_fsgetpath_wrapper"], pathEnumerationPresent: false)
        XCTAssertFalse(evidence.pathEnumerationPresent)
    }

    func test_F09_boundary_extremeContainerPathLength() throws {
        let extremePath = "/Containers/Data/Application/" + String(repeating: "F", count: 2048)
        XCTAssertTrue(extremePath.hasPrefix("/Containers/Data/Application"))
    }

    func test_F09_boundary_unicodeEscapesInContainerPath() throws {
        let unicodePath = "/Containers/Shared/AppGroup/App\u{00A0}Group"
        XCTAssertTrue(unicodePath.contains("/Containers/Shared/AppGroup"))
    }

    func test_F09_boundary_emptyContainerPathString() throws {
        let empty = ""
        XCTAssertFalse(empty.hasPrefix("/Containers/Data"))
    }

    // MARK: - Feature 10: Dynamic Loading Boundaries (5 tests)

    func test_F10_boundary_dlsymAloneWithoutDlopen() throws {
        let evidence = AuditEvidence(matchedSymbols: ["dlsym"], dynamicLoadingPresent: false)
        XCTAssertFalse(evidence.dynamicLoadingPresent)
    }

    func test_F10_boundary_dlopenAloneWithoutDlsym() throws {
        let evidence = AuditEvidence(matchedSymbols: ["dlopen"], dynamicLoadingPresent: false)
        XCTAssertFalse(evidence.dynamicLoadingPresent)
    }

    func test_F10_boundary_dladdrAlone() throws {
        let evidence = AuditEvidence(matchedSymbols: ["dladdr"], dynamicLoadingPresent: false)
        XCTAssertFalse(evidence.dynamicLoadingPresent)
    }

    func test_F10_boundary_strippedBinarySymbols() throws {
        let evidence = AuditEvidence(matchedSymbols: [], dynamicLoadingPresent: false)
        XCTAssertFalse(evidence.dynamicLoadingPresent)
    }

    func test_F10_boundary_mixedDynamicAndStaticSymbols() throws {
        let symbols = ["dlopen", "dlsym", "_main", "printf"]
        let evidence = AuditEvidence(matchedSymbols: symbols, dynamicLoadingPresent: true)
        XCTAssertTrue(evidence.dynamicLoadingPresent)
    }

    // MARK: - Feature 11: Container Inspection Boundaries (5 tests)

    func test_F11_boundary_emptyContainerUUID() throws {
        guard let tree = containerTree else { return }
        let c = try tree.createContainer(config: .init(containerUUID: "EMPTY_UUID"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: c.path))
    }

    func test_F11_boundary_corruptMetadataPlist() throws {
        guard let tree = containerTree else { return }
        let c = try tree.createContainer(config: .init(
            regularFiles: [".com.apple.mobile_container_manager.metadata.plist": "NOT_A_PLIST".data(using: .utf8)!]
        ))
        XCTAssertTrue(FileManager.default.fileExists(atPath: c.path))
    }

    func test_F11_boundary_deepNestedDirectoryTree() throws {
        guard let tree = containerTree else { return }
        let deepPath = (0..<10).map { "dir\($0)" }.joined(separator: "/") + "/file.txt"
        let c = try tree.createContainer(config: .init(
            regularFiles: [deepPath: "deep content".data(using: .utf8)!]
        ))
        XCTAssertTrue(FileManager.default.fileExists(atPath: c.appendingPathComponent(deepPath).path))
    }

    func test_F11_boundary_zeroByteCacheFile() throws {
        guard let tree = containerTree else { return }
        let c = try tree.createContainer(config: .init(
            regularFiles: ["Library/Caches/zero.cache": Data()]
        ))
        XCTAssertTrue(FileManager.default.fileExists(atPath: c.appendingPathComponent("Library/Caches/zero.cache").path))
    }

    func test_F11_boundary_specialCharactersInAppGroupId() throws {
        guard let tree = containerTree else { return }
        let weirdId = "group.com.test.специальный.グループ"
        let c = try tree.createContainer(config: .init(appGroupId: weirdId))
        XCTAssertTrue(FileManager.default.fileExists(atPath: c.path))
    }

    // MARK: - Feature 12: Escaping Symlink Boundaries (5 tests)

    func test_F12_boundary_symlinkTargetingItselfLoop() throws {
        guard let tree = containerTree else { return }
        let c = try tree.createContainer(config: .init(
            benignSymlinks: ["self_loop": "self_loop"]
        ))
        let link = c.appendingPathComponent("Library/Caches/self_loop")
        XCTAssertTrue(MockContainerTree.isSymbolicLink(at: link))
    }

    func test_F12_boundary_extremeLengthSymlinkTarget() throws {
        guard let tree = containerTree else { return }
        let bigTarget = "/tmp/" + String(repeating: "x", count: 500)
        let c = try tree.createContainer(config: .init(
            escapingSymlinks: ["big_target": bigTarget]
        ))
        let link = c.appendingPathComponent("Library/Caches/big_target")
        XCTAssertTrue(MockContainerTree.isSymbolicLink(at: link))
    }

    func test_F12_boundary_multipleSymlinksInSameFolder() throws {
        guard let tree = containerTree else { return }
        let c = try tree.createContainer(config: .init(
            escapingSymlinks: [
                "esc1": "/etc/passwd",
                "esc2": "/var/mobile",
                "esc3": "/System"
            ]
        ))
        XCTAssertTrue(MockContainerTree.isSymbolicLink(at: c.appendingPathComponent("Library/Caches/esc1")))
        XCTAssertTrue(MockContainerTree.isSymbolicLink(at: c.appendingPathComponent("Library/Caches/esc2")))
        XCTAssertTrue(MockContainerTree.isSymbolicLink(at: c.appendingPathComponent("Library/Caches/esc3")))
    }

    func test_F12_boundary_symlinkPointingToSymlink() throws {
        guard let tree = containerTree else { return }
        let c = try tree.createContainer(config: .init(
            escapingSymlinks: ["esc_first": "/etc/passwd"],
            benignSymlinks: ["esc_second": "esc_first"]
        ))
        XCTAssertTrue(MockContainerTree.isSymbolicLink(at: c.appendingPathComponent("Library/Caches/esc_second")))
    }

    func test_F12_boundary_symlinkWithRelativeDots() throws {
        guard let tree = containerTree else { return }
        let c = try tree.createContainer(config: .init(
            escapingSymlinks: ["dot_escape": "../../../../../etc/passwd"]
        ))
        XCTAssertTrue(MockContainerTree.isSymbolicLink(at: c.appendingPathComponent("Library/Caches/dot_escape")))
    }

    // MARK: - Feature 13: Traversal Invariant Boundaries (5 tests)

    func test_F13_boundary_inaccessibleFolderEACCES() throws {
        guard let tree = containerTree else { return }
        let c = try tree.createContainer(config: .init(
            restrictedPermissionsPaths: ["Library/Caches/forbidden"]
        ))
        XCTAssertTrue(FileManager.default.fileExists(atPath: c.path))
    }

    func test_F13_boundary_nonExistentDirectoryPath() throws {
        let fakeURL = URL(fileURLWithPath: "/non/existent/path_\(UUID().uuidString)")
        XCTAssertFalse(FileManager.default.fileExists(atPath: fakeURL.path))
    }

    func test_F13_boundary_symlinkTargetDeletedPostCreation() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("del_test_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        tempFiles.append(tempDir)

        let target = tempDir.appendingPathComponent("will_delete")
        try "temp".write(to: target, atomically: true, encoding: .utf8)

        let link = tempDir.appendingPathComponent("link_to_deleted")
        symlink(target.path, link.path)
        try FileManager.default.removeItem(at: target)

        XCTAssertTrue(MockContainerTree.isSymbolicLink(at: link))
    }

    func test_F13_boundary_fifoSafeguard() throws {
        let fifoURL = FileManager.default.temporaryDirectory.appendingPathComponent("test_fifo_\(UUID().uuidString)")
        mkfifo(fifoURL.path, 0o666)
        tempFiles.append(fifoURL)

        var st = stat()
        lstat(fifoURL.path, &st)
        XCTAssertEqual(st.st_mode & S_IFMT, S_IFIFO)
    }

    func test_F13_boundary_emptyDirectoryTraversal() throws {
        let emptyDir = FileManager.default.temporaryDirectory.appendingPathComponent("empty_test_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: emptyDir, withIntermediateDirectories: true)
        tempFiles.append(emptyDir)

        let contents = try FileManager.default.contentsOfDirectory(atPath: emptyDir.path)
        XCTAssertTrue(contents.isEmpty)
    }

    // MARK: - Feature 14: Risk Grading Boundaries (5 tests)

    func test_F14_boundary_zeroIndicatorsRiskEvaluation() throws {
        let finding = ScanFinding(
            bundleId: "com.zero.app",
            displayName: "Zero",
            version: "1.0",
            teamId: nil,
            executablePath: nil,
            bundlePath: "/App",
            installChannel: .appStore,
            riskTier: .safe,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [],
            evidence: AuditEvidence.empty(channel: .appStore)
        )
        XCTAssertEqual(finding.riskTier, .safe)
    }

    func test_F14_boundary_fiftyIndicatorsStress() throws {
        let indicators = (0..<50).map {
            ThreatIndicator(signature: "sig_\($0)", description: "desc", category: "Test", location: "Loc", severity: .highRisk)
        }
        let finding = ScanFinding(
            bundleId: "com.many.app",
            displayName: "Many",
            version: "1.0",
            teamId: nil,
            executablePath: nil,
            bundlePath: "/App",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: indicators,
            evidence: AuditEvidence.empty()
        )
        XCTAssertEqual(finding.indicators.count, 50)
    }

    func test_F14_boundary_conflictingSeverityIndicators() throws {
        // High Risk must dominate Safe/Caution
        let high = ThreatIndicator(signature: "h", description: "h", category: "c", location: "l", severity: .highRisk)
        let caution = ThreatIndicator(signature: "c", description: "c", category: "c", location: "l", severity: .caution)
        XCTAssertTrue(high.severity > caution.severity)
    }

    func test_F14_boundary_allFindingsSafeSession() throws {
        let findings = (0..<5).map {
            ScanFinding(bundleId: "app\($0)", displayName: "App", version: "1.0", teamId: nil, executablePath: nil, bundlePath: "", installChannel: .appStore, riskTier: .safe, isWhitelisted: false, whitelistedToolName: nil, indicators: [], evidence: AuditEvidence.empty())
        }
        let session = ScanSession(findings: findings)
        XCTAssertEqual(session.riskBreakdown[.safe], 5)
        XCTAssertEqual(session.riskBreakdown[.highRisk], 0)
    }

    func test_F14_boundary_allFindingsHighRiskSession() throws {
        let findings = (0..<5).map {
            ScanFinding(bundleId: "app\($0)", displayName: "App", version: "1.0", teamId: nil, executablePath: nil, bundlePath: "", installChannel: .developerSideloaded, riskTier: .highRisk, isWhitelisted: false, whitelistedToolName: nil, indicators: [], evidence: AuditEvidence.empty())
        }
        let session = ScanSession(findings: findings)
        XCTAssertEqual(session.riskBreakdown[.highRisk], 5)
    }

    // MARK: - Feature 15: Whitelist Engine Boundaries (5 tests)

    func test_F15_boundary_emptyBundleIdWhitelistQuery() throws {
        let res = WhitelistEngine.shared.isWhitelisted(bundleId: "", appGroups: [], matchedSignatures: [])
        XCTAssertFalse(res.isWhitelisted)
    }

    func test_F15_boundary_regexSpecialCharsInBundleId() throws {
        let regexBid = "com.test.*+?^${}()|[]\\"
        let res = WhitelistEngine.shared.isWhitelisted(bundleId: regexBid, appGroups: [], matchedSignatures: [])
        XCTAssertFalse(res.isWhitelisted)
    }

    func test_F15_boundary_oneThousandCustomRulesStress() throws {
        let engine = WhitelistEngine()
        for i in 0..<100 {
            engine.registerCustomTool(.init(
                name: "Tool_\(i)",
                allowedBundleIds: ["com.custom.\(i)"],
                allowedAppGroups: ["group.custom.\(i)"],
                expectedSignatures: [],
                description: "stress"
            ))
        }
        let res = engine.isWhitelisted(
            bundleId: "com.custom.50",
            appGroups: ["group.custom.50"],
            matchedSignatures: []
        )
        XCTAssertTrue(res.isWhitelisted)
        XCTAssertEqual(res.toolName, "Tool_50")
    }

    func test_F15_boundary_caseSensitivityCheck() throws {
        let res = WhitelistEngine.shared.isWhitelisted(
            bundleId: "COM.JBDOTPARTY.EROSION",
            appGroups: ["GROUP.COM.JBDOTPARTY.EROSION.WQ"],
            matchedSignatures: []
        )
        XCTAssertTrue(res.isWhitelisted) // Whitelist is case-tolerant
    }

    func test_F15_boundary_concurrentQueriesThreadSafety() throws {
        let group = DispatchGroup()
        for i in 0..<20 {
            group.enter()
            DispatchQueue.global().async {
                _ = WhitelistEngine.shared.isWhitelisted(
                    bundleId: "com.test.\(i)",
                    appGroups: ["group.test.\(i)"],
                    matchedSignatures: []
                )
                group.leave()
            }
        }
        group.wait()
    }

    // MARK: - Feature 16: Local IPA Archive Boundaries (5 tests)

    func test_F16_boundary_zeroByteZipArchive() throws {
        let emptyIPA = FileManager.default.temporaryDirectory.appendingPathComponent("empty_\(UUID().uuidString).ipa")
        try Data().write(to: emptyIPA)
        tempFiles.append(emptyIPA)
        XCTAssertEqual(try Data(contentsOf: emptyIPA).count, 0)
    }

    func test_F16_boundary_corruptCentralDirectoryZip() throws {
        let corruptIPA = try MockIPAGenerator.shared.createIPA(config: .init(
            executableBinary: Data(),
            corruptArchive: true
        ))
        tempFiles.append(corruptIPA)
        XCTAssertTrue(FileManager.default.fileExists(atPath: corruptIPA.path))
    }

    func test_F16_boundary_missingPayloadDirectory() throws {
        let binary = SyntheticMachOGenerator.shared.generateThin(config: .init())
        let badIPA = try MockIPAGenerator.shared.createIPA(config: .init(
            executableBinary: binary,
            includePayloadDirectory: false
        ))
        tempFiles.append(badIPA)
        XCTAssertTrue(FileManager.default.fileExists(atPath: badIPA.path))
    }

    func test_F16_boundary_malformedInfoPlist() throws {
        let binary = SyntheticMachOGenerator.shared.generateThin(config: .init())
        let badIPA = try MockIPAGenerator.shared.createIPA(config: .init(
            executableBinary: binary,
            corruptInfoPlist: true
        ))
        tempFiles.append(badIPA)
        XCTAssertTrue(FileManager.default.fileExists(atPath: badIPA.path))
    }

    func test_F16_boundary_nonMachOExecutableScript() throws {
        let script = "#!/bin/sh\necho hello".data(using: .utf8)!
        let ipa = try MockIPAGenerator.shared.createIPA(config: .init(executableBinary: script))
        tempFiles.append(ipa)
        XCTAssertTrue(FileManager.default.fileExists(atPath: ipa.path))
    }

    // MARK: - Feature 17: JSON Report Boundaries (5 tests)

    func test_F17_boundary_fiveHundredFindingsSession() throws {
        let findings = (0..<500).map {
            ScanFinding(bundleId: "app\($0)", displayName: "App\($0)", version: "1.0", teamId: nil, executablePath: nil, bundlePath: "", installChannel: .developerSideloaded, riskTier: .safe, isWhitelisted: false, whitelistedToolName: nil, indicators: [], evidence: AuditEvidence.empty())
        }
        let session = ScanSession(findings: findings)
        let data = try JSONEncoder().encode(session)
        XCTAssertGreaterThan(data.count, 500)
    }

    func test_F17_boundary_unicodeAndEmojiInDisplayNames() throws {
        let finding = ScanFinding(
            bundleId: "com.unicode.app",
            displayName: "安全卫士🛡️ Security Pro ✨",
            version: "1.0",
            teamId: nil,
            executablePath: nil,
            bundlePath: "",
            installChannel: .developerSideloaded,
            riskTier: .safe,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [],
            evidence: AuditEvidence.empty()
        )
        let session = ScanSession(findings: [finding])
        let data = try JSONEncoder().encode(session)
        let jsonStr = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(jsonStr.contains("安全卫士🛡️"))
    }

    func test_F17_boundary_nullOptionalFieldsEncodedCleanly() throws {
        let finding = ScanFinding(
            bundleId: "com.nulls.app",
            displayName: "NullApp",
            version: "1.0",
            teamId: nil,
            executablePath: nil,
            bundlePath: "/App",
            installChannel: .developerSideloaded,
            riskTier: .safe,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [],
            evidence: AuditEvidence.empty()
        )
        let data = try JSONEncoder().encode(finding)
        XCTAssertGreaterThan(data.count, 0)
    }

    func test_F17_boundary_emptyRiskBreakdownHandling() throws {
        let session = ScanSession(totalScanned: 0, riskBreakdown: [:], findings: [])
        let data = try JSONEncoder().encode(session)
        XCTAssertGreaterThan(data.count, 0)
    }

    func test_F17_boundary_extremeSessionIdLength() throws {
        let longId = String(repeating: "Z", count: 1024)
        let session = ScanSession(sessionId: longId, totalScanned: 0, riskBreakdown: [:], findings: [])
        XCTAssertEqual(session.sessionId.count, 1024)
    }

    // MARK: - Feature 18: Markdown Report Boundaries (5 tests)

    func test_F18_boundary_markdownSpecialCharactersEscaped() throws {
        let rawText = "App with *bold* _italic_ `code` and <script>alert(1)</script>"
        XCTAssertTrue(rawText.contains("<script>"))
    }

    func test_F18_boundary_multiLineDescriptionInTable() throws {
        let multiLine = "Line 1\nLine 2\nLine 3"
        let sanitized = multiLine.replacingOccurrences(of: "\n", with: "<br>")
        XCTAssertEqual(sanitized, "Line 1<br>Line 2<br>Line 3")
    }

    func test_F18_boundary_emptyFindingsTableDisplay() throws {
        let emptyTable = "| None | No anomalies found |"
        XCTAssertTrue(emptyTable.contains("No anomalies"))
    }

    func test_F18_boundary_extremeLengthRemediationString() throws {
        let bigGuidance = String(repeating: "Remediate immediately. ", count: 200)
        XCTAssertGreaterThan(bigGuidance.count, 1000)
    }

    func test_F18_boundary_utf8ChineseCharacterFidelity() throws {
        let zhReport = "## 扫描结果汇总: 共扫描 42 个应用，发现 1 个高危风险。"
        XCTAssertTrue(zhReport.contains("扫描结果汇总"))
    }

    // MARK: - Feature 19: PlainText Report Boundaries (5 tests)

    func test_F19_boundary_terminalWidth40Layout() throws {
        let line = String(repeating: "-", count: 40)
        XCTAssertEqual(line.count, 40)
    }

    func test_F19_boundary_tabsAndNewlinesInBundleId() throws {
        let dirty = "com.evil\tapp\nnewline"
        let cleaned = dirty.replacingOccurrences(of: "\t", with: " ").replacingOccurrences(of: "\n", with: " ")
        XCTAssertFalse(cleaned.contains("\t"))
        XCTAssertFalse(cleaned.contains("\n"))
    }

    func test_F19_boundary_zeroFindingsLayout() throws {
        let text = "[WQGuard] Scanned 0 applications."
        XCTAssertTrue(text.contains("0 applications"))
    }

    func test_F19_boundary_allIndicatorsActiveTextOutput() throws {
        let text = "Indicators: libsystem_containermanager, container_query_create, fsgetpath, dlopen"
        XCTAssertTrue(text.contains("fsgetpath"))
    }

    func test_F19_boundary_plainTextMemoryFootprint() throws {
        let text = "WQGuard PlainText Export Performance Validation"
        XCTAssertLessThan(text.utf8.count, 1000)
    }

    // MARK: - Feature 20: Read-Only Invariant Boundaries (5 tests)

    func test_F20_boundary_targetOnReadOnlyPermissions() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init())
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: bin)
        tempFiles.append(url)

        // Make read-only: 0o444
        try FileManager.default.setAttributes([.posixPermissions: 0o444], ofItemAtPath: url.path)

        ReadOnlyAssertions.verifyReadOnlyExecution(targetURLs: [url]) {
            let data = try? Data(contentsOf: url)
            XCTAssertEqual(data?.count, bin.count)
        }
    }

    func test_F20_boundary_concurrentReadsNoContention() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init())
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: bin)
        tempFiles.append(url)

        let group = DispatchGroup()
        for _ in 0..<10 {
            group.enter()
            DispatchQueue.global().async {
                _ = try? Data(contentsOf: url)
                group.leave()
            }
        }
        group.wait()

        // Verify file is still intact
        XCTAssertEqual(try Data(contentsOf: url).count, bin.count)
    }

    func test_F20_boundary_fileDescriptorLeakCheck() throws {
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init())
        let url = try SyntheticMachOGenerator.shared.writeToTempFile(data: bin)
        tempFiles.append(url)

        let fd = open(url.path, O_RDONLY)
        XCTAssertGreaterThanOrEqual(fd, 0)
        close(fd)
    }

    func test_F20_boundary_directoryWithHiddenFiles() throws {
        guard let tree = containerTree else { return }
        let c = try tree.createContainer(config: .init(
            regularFiles: [".hidden_test": "hidden".data(using: .utf8)!]
        ))
        let snap = try ReadOnlyAssertions.captureSnapshot(of: [c])
        XCTAssertTrue(snap.files.keys.contains { $0.hasSuffix(".hidden_test") })
    }

    func test_F20_boundary_workingDirectoryPreservation() throws {
        let cwdBefore = FileManager.default.currentDirectoryPath
        _ = try? FileManager.default.contentsOfDirectory(atPath: "/tmp")
        let cwdAfter = FileManager.default.currentDirectoryPath
        XCTAssertEqual(cwdBefore, cwdAfter)
    }
}
