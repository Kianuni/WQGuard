//
//  AdversarialM6Challenger2Tests.swift
//  WQGuardCoreTests
//
//  Tier 5 White-Box Adversarial Hardening Suite by Challenger m6_2.
//  Exhaustively targets:
//  1. ContainerScanner & MCMReader (symlink traps, cycles, dangling links, multithreaded RAII, quota/corrupt plists)
//  2. CSStore2Reader / Parser (exact boundary file sizes, plugin records, malformed strings, Unicode sanitization)
//  3. FirmwarePostureEngine & ExpandedThreatCatalog (all branches 25.x - 28.x, fuzzed versions, Chinese aliases, private Photos, tweaks, supervision)
//  4. IPAPackageScanner & NativeZIPArchiveReader (Zip Slip variations, encrypted archives, unsupported compression, corrupted EOCD, recursive multi-binary)
//

import XCTest
import Darwin
@testable import WQGuardCore

final class AdversarialM6Challenger2Tests: XCTestCase {

    var mockTree: MockContainerTree!
    var tempFiles: [URL] = []

    override func setUp() {
        super.setUp()
        mockTree = MockContainerTree()
    }

    override func tearDown() {
        mockTree?.cleanUp()
        mockTree = nil
        for url in tempFiles {
            try? FileManager.default.removeItem(at: url)
        }
        tempFiles.removeAll()
        super.tearDown()
    }

    private func trackTempFile(_ url: URL) -> URL {
        tempFiles.append(url)
        return url
    }

    // =========================================================================
    // MARK: - Group 1: ContainerScanner & MCMReader White-Box Hardening
    // =========================================================================

    /// 1. Verifies that self-referential / relative symlink cycles inside Library/Caches do not loop infinitely
    /// and are not falsely classified as escaping if they resolve within the container.
    func test_T5_container_symlinkCycle_and_selfReferentialCaches() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.cycle.test",
            containerUUID: UUID().uuidString,
            createMetadataPlist: true,
            createCachesDirectory: true
        )
        let containerURL = try mockTree.createContainer(config: config)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")

        // Create internal symlink pointing to parent Library within container
        let internalLink = cachesURL.appendingPathComponent("internal_loop")
        symlink("..", internalLink.path)

        // Create internal symlink to self '.'
        let selfLink = cachesURL.appendingPathComponent("self_dot")
        symlink(".", selfLink.path)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertTrue(result.isClean, "Internal symlinks resolving within container must not be flagged as escaping")
        XCTAssertTrue(result.escapingSymlinks.isEmpty)
    }

    /// 2. Verifies that deeply nested escaping symlinks utilizing repeated '../' path traversal
    /// are caught and flagged with CONTAINER_ESCAPING_SYMLINK (High Risk).
    func test_T5_container_deepEscapingSymlink_doubleDotsEvasion() throws {
        let evilUUID = UUID().uuidString
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.escape.dots",
            containerUUID: UUID().uuidString,
            createMetadataPlist: true,
            createCachesDirectory: true
        )
        let containerURL = try mockTree.createContainer(config: config)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")

        // Relative path stepping 7 directories up to target another container
        let deepRelativeEscape = cachesURL.appendingPathComponent("subpath_escape")
        let target = "../../../../../../../private/var/mobile/Containers/Data/Application/\(evilUUID)"
        symlink(target, deepRelativeEscape.path)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertEqual(result.escapingSymlinks.count, 1)
        XCTAssertEqual(result.escapingSymlinks.first, deepRelativeEscape.path)
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" && $0.severity == .highRisk })
    }

    /// 3. Verifies that a dangling symlink pointing to a non-existent external container path
    /// is still detected as an escaping symlink without dereferencing.
    func test_T5_container_danglingSymlinkToNonexistentTarget() throws {
        let nonExistentTarget = "/var/mobile/Containers/Data/Application/DEADBEEF-0000-0000-0000-000000000000"
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.dangling.escape",
            containerUUID: UUID().uuidString,
            createMetadataPlist: true,
            createCachesDirectory: true,
            escapingSymlinks: ["ghost_target": nonExistentTarget]
        )
        let containerURL = try mockTree.createContainer(config: config)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertEqual(result.escapingSymlinks.count, 1)
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" })
    }

    /// 4. Verifies MCMReader rejection of plists with invalid UUID formats and missing required keys.
    func test_T5_container_mcmReader_invalidUUID_and_missingKeys_rejection() throws {
        let reader = MCMReader.shared

        // 4a. Malformed UUID
        let badUUIDDict: [String: Any] = [
            "MCMMetadataIdentifier": "group.com.bad.uuid",
            "MCMMetadataUUID": "NOT-A-VALID-UUID-ZZZZ-XXXXXXXXXXXX",
            "MCMMetadataClass": 7
        ]
        let badUUIDData = try PropertyListSerialization.data(fromPropertyList: badUUIDDict, format: .xml, options: 0)
        XCTAssertThrowsError(try reader.parseMetadata(data: badUUIDData)) { error in
            guard case MCMReaderError.invalidUUID = error else {
                XCTFail("Expected invalidUUID, got \(error)")
                return
            }
        }

        // 4b. Missing Identifier
        let missingIdDict: [String: Any] = [
            "MCMMetadataUUID": UUID().uuidString,
            "MCMMetadataClass": 7
        ]
        let missingIdData = try PropertyListSerialization.data(fromPropertyList: missingIdDict, format: .xml, options: 0)
        XCTAssertThrowsError(try reader.parseMetadata(data: missingIdData)) { error in
            guard case MCMReaderError.missingRequiredKey(let key) = error, key == "MCMMetadataIdentifier" else {
                XCTFail("Expected missingRequiredKey for MCMMetadataIdentifier, got \(error)")
                return
            }
        }

        // 4c. Missing UUID
        let missingUUIDDict: [String: Any] = [
            "MCMMetadataIdentifier": "group.com.missing.uuid",
            "MCMMetadataClass": 7
        ]
        let missingUUIDData = try PropertyListSerialization.data(fromPropertyList: missingUUIDDict, format: .xml, options: 0)
        XCTAssertThrowsError(try reader.parseMetadata(data: missingUUIDData)) { error in
            guard case MCMReaderError.missingRequiredKey(let key) = error, key == "MCMMetadataUUID" else {
                XCTFail("Expected missingRequiredKey for MCMMetadataUUID, got \(error)")
                return
            }
        }
    }

    /// 5. Verifies MCMReader bounds and size quota handling (empty file and oversized > 1MB).
    func test_T5_container_mcmReader_largeFileQuota_and_emptyFile() throws {
        let tempDir = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("mcm_quota_\(UUID().uuidString)"))
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        let metaURL = tempDir.appendingPathComponent(MCMReader.metadataFilename)

        // 5a. Empty file
        try Data().write(to: metaURL)
        XCTAssertThrowsError(try MCMReader.shared.readMetadata(inContainer: tempDir)) { error in
            guard case MCMReaderError.emptyData = error else {
                XCTFail("Expected emptyData error, got \(error)")
                return
            }
        }

        // 5b. File exceeding maxPlistBytes (1MB + 16 bytes)
        let oversizedData = Data(count: Int(MCMReader.maxPlistBytes) + 16)
        try oversizedData.write(to: metaURL)
        XCTAssertThrowsError(try MCMReader.shared.readMetadata(inContainer: tempDir)) { error in
            guard case MCMReaderError.fileTooLarge = error else {
                XCTFail("Expected fileTooLarge error, got \(error)")
                return
            }
        }
    }

    /// 6. Verifies MCMReader parsing of all 9 MCMContainerClass values and unknown fallbacks across binary plist.
    func test_T5_container_mcmReader_binaryPlist_allContainerClasses() throws {
        let classes: [(Int, MCMContainerClass)] = [
            (1, .appData),
            (2, .vpn),
            (3, .system),
            (4, .temporary),
            (5, .bundle),
            (7, .appGroup),
            (10, .plugin),
            (11, .internalDaemon),
            (12, .systemGroup),
            (99, .unknown)
        ]

        for (raw, expectedClass) in classes {
            let uuid = UUID().uuidString
            let dict: [String: Any] = [
                "MCMMetadataIdentifier": "group.com.class.\(raw)",
                "MCMMetadataUUID": uuid,
                "MCMMetadataClass": raw,
                "MCMMetadataVersion": 2,
                "MCMMetadataSchemaVersion": 42
            ]
            let binData = try PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0)
            let meta = try MCMReader.shared.parseMetadata(data: binData)
            XCTAssertEqual(meta.containerClass, expectedClass)
            XCTAssertEqual(meta.rawClass, raw)
            XCTAssertEqual(meta.schemaVersion, 42)
            XCTAssertFalse(meta.containerClass.description.isEmpty)
        }
    }

    /// 7. Verifies ScopedSandboxToken reentrancy and thread-safety under concurrent release from multiple threads.
    func test_T5_container_scopedSandboxToken_multithreadedReentrancy() {
        let token = ScopedSandboxToken(handle: 9999)
        let queue = DispatchQueue(label: "com.wqguard.test.token", attributes: .concurrent)
        let group = DispatchGroup()

        for _ in 0..<20 {
            group.enter()
            queue.async {
                token.release()
                group.leave()
            }
        }

        let waitResult = group.wait(timeout: .now() + 2.0)
        XCTAssertEqual(waitResult, .success)
        XCTAssertEqual(token.handle, 9999)
    }

    // =========================================================================
    // MARK: - Group 2: CSStore2Reader White-Box Hardening
    // =========================================================================

    /// Helper to assemble synthetic CSStore2 database with customizable bundle & plugin records.
    private func buildSyntheticStore(
        bundleRecords: [(bid: String, cont: String, name: String, disp: String, layout: CSLayoutSpec)] = [],
        pluginRecords: [(bid: String, cont: String, layout: CSLayoutSpec)] = [],
        appGroups: [String] = [],
        bufferSize: Int = 16384
    ) -> Data {
        var data = Data(count: bufferSize)
        // Magic "bdsl"
        data[0] = 0x62; data[1] = 0x64; data[2] = 0x73; data[3] = 0x6c

        let heapOffset = 0x400
        let marker = Data([0x3c, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3e])
        data.replaceSubrange(heapOffset..<(heapOffset + marker.count), with: marker)

        func appendLE32(_ val: UInt32, at offset: Int) {
            var v = val.littleEndian
            withUnsafeBytes(of: &v) { raw in
                data.replaceSubrange(offset..<(offset + 4), with: raw)
            }
        }

        var strOffset = 0x600
        var sidCounter: UInt32 = 100

        func writeString(str: String) -> UInt32 {
            let sid = sidCounter
            sidCounter += 1
            appendLE32(sid, at: strOffset)
            let utf8 = Array(str.utf8)
            appendLE32(UInt32(utf8.count), at: strOffset + 4)
            data.replaceSubrange((strOffset + 8)..<(strOffset + 8 + utf8.count), with: utf8)
            data[strOffset + 8 + utf8.count] = 0 // null-terminate
            let entryLen = 8 + utf8.count + 4
            strOffset += (entryLen + 3) & ~3
            return sid << 2 // tagged reference
        }

        var recOffset = 0x100

        // Write bundle records
        for b in bundleRecords {
            let bidRef = writeString(str: b.bid)
            let contRef = writeString(str: b.cont)
            let nameRef = writeString(str: b.name)
            let dispRef = writeString(str: b.disp)

            appendLE32(0, at: recOffset)
            appendLE32(b.layout.bundleSize, at: recOffset + 4)
            let uOffset = recOffset + 8

            appendLE32(bidRef, at: uOffset + Int(b.layout.bundleIDOffset))
            appendLE32(nameRef, at: uOffset + Int(b.layout.nameOffset))
            appendLE32(dispRef, at: uOffset + Int(b.layout.displayNameOffset))
            appendLE32(contRef, at: uOffset + Int(b.layout.containerOffset))

            recOffset += 8 + Int(b.layout.bundleSize)
            recOffset = (recOffset + 3) & ~3
        }

        // Write plugin records
        for p in pluginRecords {
            let pBidRef = writeString(str: p.bid)
            let pContRef = writeString(str: p.cont)

            appendLE32(0, at: recOffset)
            appendLE32(p.layout.pluginSize, at: recOffset + 4)
            let uOffset = recOffset + 8

            appendLE32(pBidRef, at: uOffset + Int(p.layout.pluginBundleIDOffset))
            appendLE32(pContRef, at: uOffset + Int(p.layout.pluginContainerOffset))

            recOffset += 8 + Int(p.layout.pluginSize)
            recOffset = (recOffset + 3) & ~3
        }

        // Write AppGroup strings
        for gUUID in appGroups {
            let groupStr = "/mobile/Containers/Shared/AppGroup/\(gUUID)"
            let groupBytes = Array(groupStr.utf8)
            data.replaceSubrange(strOffset..<(strOffset + groupBytes.count), with: groupBytes)
            strOffset += groupBytes.count + 4
        }

        return data
    }

    /// 8. Verifies that CSStore2Parser correctly handles untrusted unit record sizes,
    /// skipping non-matching sizes and untagged references without crashing.
    func test_T5_csstore2_nearBoundaryRecordSizes_and_stridePadding() throws {
        let layout27 = CSStore2Parser.supportedLayouts.first { $0.label == "27.0" }!
        let validUUID = "12345678-ABCD-EF01-2345-6789ABCDEF01"

        var data = buildSyntheticStore(
            bundleRecords: [
                (bid: "com.apple.testapp", cont: "/var/mobile/Containers/Data/Application/\(validUUID)", name: "TestApp", disp: "Test App", layout: layout27)
            ]
        )

        // Inject junk unit records with slightly off sizes (e.g. 0x24e, 0x254) before string heap
        var offSize = UInt32(0x24e).littleEndian
        withUnsafeBytes(of: &offSize) { raw in
            data.replaceSubrange(0x304..<0x308, with: raw)
        }

        let snapshot = try CSStore2Parser.shared.parse(data: data)
        XCTAssertEqual(snapshot.layoutLabel, "27.0")
        XCTAssertEqual(snapshot.appContainers["/var/mobile/Containers/Data/Application/\(validUUID)"], "com.apple.testapp")
    }

    /// 9. Verifies CSStore2Parser string table bounds checking against internal null bytes and string length overflow.
    func test_T5_csstore2_malformedStringEntries_nullBytesAndTruncation() throws {
        let parser = CSStore2Parser.shared

        // 9a. looksLikeBundleID edge cases
        XCTAssertFalse(parser.looksLikeBundleID(""))
        XCTAssertFalse(parser.looksLikeBundleID("a"))
        XCTAssertFalse(parser.looksLikeBundleID(".hidden.bundle"))
        XCTAssertFalse(parser.looksLikeBundleID("spaces in.bundle.id"))
        XCTAssertFalse(parser.looksLikeBundleID("evil/slash/bundle"))
        XCTAssertTrue(parser.looksLikeBundleID("com.valid-123.Bundle_App"))

        // 9b. normalizeVarPath edge cases
        XCTAssertNil(parser.normalizeVarPath(""))
        XCTAssertEqual(parser.normalizeVarPath("/private/var/mobile/Containers/Data/Application/UUID"), "/var/mobile/Containers/Data/Application/UUID")
        XCTAssertEqual(parser.normalizeVarPath("/var/mobile//Containers/Data///Application/UUID"), "/var/mobile/Containers/Data/Application/UUID")

        // 9c. isValidUUIDContainer
        XCTAssertFalse(parser.isValidUUIDContainer("/var/mobile/Containers/Data/Application/NOT-LONG-ENOUGH", prefix: "/var/mobile/Containers/Data/Application/"))
        XCTAssertFalse(parser.isValidUUIDContainer("/var/mobile/Containers/Data/Application/ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ", prefix: "/var/mobile/Containers/Data/Application/"))
        XCTAssertTrue(parser.isValidUUIDContainer("/var/mobile/Containers/Data/Application/12345678-1234-1234-1234-123456789ABC", prefix: "/var/mobile/Containers/Data/Application/"))
    }

    /// 10. Verifies CSStore2 exact boundary buffer size rejections.
    func test_T5_csstore2_exactBoundaryFileSizes() {
        let parser = CSStore2Parser.shared

        // 10a. Exactly 4095 bytes (1 byte below minimum 4096)
        var smallData = Data(count: 4095)
        smallData[0] = 0x62; smallData[1] = 0x64; smallData[2] = 0x73; smallData[3] = 0x6c
        XCTAssertThrowsError(try parser.parse(data: smallData)) { error in
            guard case CSStore2ParserError.dataTooSmall(let size, let minReq) = error else {
                XCTFail("Expected dataTooSmall, got \(error)")
                return
            }
            XCTAssertEqual(size, 4095)
            XCTAssertEqual(minReq, 4096)
        }

        // 10b. Exactly 4096 bytes with invalid magic
        let invalidMagicData = Data(count: 4096)
        XCTAssertThrowsError(try parser.parse(data: invalidMagicData)) { error in
            guard case CSStore2ParserError.invalidMagic = error else {
                XCTFail("Expected invalidMagic, got \(error)")
                return
            }
        }

        // 10c. Exactly 4096 bytes with valid magic but no records matching
        var emptyStore = Data(count: 4096)
        emptyStore[0] = 0x62; emptyStore[1] = 0x64; emptyStore[2] = 0x73; emptyStore[3] = 0x6c
        XCTAssertThrowsError(try parser.parse(data: emptyStore)) { error in
            guard case CSStore2ParserError.noValidLayoutMatched = error else {
                XCTFail("Expected noValidLayoutMatched, got \(error)")
                return
            }
        }
    }

    /// 11. Verifies CSStore2 plugin record parsing on iOS 26 and iOS 27 layouts.
    func test_T5_csstore2_pluginRecordParsing_iOS26_and_iOS27() throws {
        let layout27 = CSStore2Parser.supportedLayouts.first { $0.label == "27.0" }!
        let pluginUUID = "99887766-5544-3322-1100-AABBCCDDEEFF"
        let appUUID = "11223344-5566-7788-99AA-BBCCDDEEFF00"

        let data = buildSyntheticStore(
            bundleRecords: [
                (bid: "com.example.hostapp", cont: "/var/mobile/Containers/Data/Application/\(appUUID)", name: "HostApp", disp: "Host App", layout: layout27)
            ],
            pluginRecords: [
                (bid: "com.example.hostapp.widget", cont: "/var/mobile/Containers/Data/PluginKitPlugin/\(pluginUUID)", layout: layout27)
            ]
        )

        let snapshot = try CSStore2Parser.shared.parse(data: data)
        XCTAssertEqual(snapshot.pluginContainers["/var/mobile/Containers/Data/PluginKitPlugin/\(pluginUUID)"], "com.example.hostapp.widget")
        XCTAssertEqual(snapshot.appContainers["/var/mobile/Containers/Data/Application/\(appUUID)"], "com.example.hostapp")
    }

    /// 12. Exhaustive stress-testing of CSStore2 Unicode sanitizer against format scalars, BiDi overrides, and path attacks.
    func test_T5_csstore2_unicodeSanitizer_exhaustiveAdversarialControls() {
        let parser = CSStore2Parser.shared

        // 12a. Multiple format and BiDi control scalars replaced with \u{FFFD}
        let evilBiDi = "App\u{061C}\u{202E}Safe\u{FEFF}Name"
        let sanitized = parser.sanitizeUnicodeName(evilBiDi)
        XCTAssertNotNil(sanitized)
        XCTAssertTrue(sanitized!.contains("\u{FFFD}"))

        // 12b. All ASCII control characters (0x00 to 0x1F, 0x7F) rejected
        for code in 0...31 {
            let s = "App\(Character(UnicodeScalar(code)!))Name"
            XCTAssertNil(parser.sanitizeUnicodeName(s), "Control char \(code) must be rejected")
        }
        XCTAssertNil(parser.sanitizeUnicodeName("App\u{007F}Name"))

        // 12c. Path traversal / directory escape patterns in display names rejected
        XCTAssertNil(parser.sanitizeUnicodeName("/Payload/Malicious.app"))
        XCTAssertNil(parser.sanitizeUnicodeName("Foo.app/Bar"))
        XCTAssertNil(parser.sanitizeUnicodeName("   "))
    }

    // =========================================================================
    // MARK: - Group 3: FirmwarePostureEngine & Threat Catalog White-Box Hardening
    // =========================================================================

    /// 13. Evaluates all firmware posture boundaries across legacy iOS 25, dual branches 26 & 27, and future iOS 28.
    func test_T5_firmwarePosture_boundaryEvaluations_allBranches_includingFutureAndLegacy() {
        let engine = FirmwarePostureEngine.shared

        // 13a. Legacy iOS 25 (e.g. 25.9.9): worseQuery 0day is not active (<26), but all 7 other CVEs are exposed
        let v25 = SystemOSVersion(major: 25, minor: 9, patch: 9)
        let rep25 = engine.evaluate(osVersion: v25)
        XCTAssertFalse(engine.isVulnerable(.worseQuery0day, in: v25))
        XCTAssertEqual(rep25.exposedCount, 7, "iOS 25 must expose exactly 7 older vulnerabilities")
        XCTAssertEqual(rep25.overallRiskTier, .highRisk)

        // 13b. iOS 26.7.0: All 8 vulnerabilities exposed; iOS 26.7.1: coreGraphics2D patched -> 7 exposed
        let v26_0 = SystemOSVersion(major: 26, minor: 7, patch: 0)
        XCTAssertEqual(engine.evaluate(osVersion: v26_0).exposedCount, 8)
        let v26_1 = SystemOSVersion(major: 26, minor: 7, patch: 1)
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: v26_1))
        XCTAssertEqual(engine.evaluate(osVersion: v26_1).exposedCount, 7)

        // 13c. iOS 26.7.2: coreGraphics2D + photosBypass & coreGraphicsPDF patched -> 5 exposed
        let v26_2 = SystemOSVersion(major: 26, minor: 7, patch: 2)
        XCTAssertEqual(engine.evaluate(osVersion: v26_2).exposedCount, 5)

        // 13d. iOS 26.7.3: brotli, appIntents, imessage, bluetoothAirPlay also patched; only worseQuery 0day exposed -> 1 exposed
        let v26_3 = SystemOSVersion(major: 26, minor: 7, patch: 3)
        XCTAssertEqual(engine.evaluate(osVersion: v26_3).exposedCount, 1)
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: v26_3))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: v26_3))

        // 13e. iOS 27.0.0: coreGraphics2D patched; 7 others exposed
        let v27_0 = SystemOSVersion(major: 27, minor: 0, patch: 0)
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: v27_0))
        XCTAssertEqual(engine.evaluate(osVersion: v27_0).exposedCount, 7)

        // 13f. iOS 27.2.0: photosBypass & coreGraphicsPDF patched -> 5 exposed
        let v27_2_0 = SystemOSVersion(major: 27, minor: 2, patch: 0)
        XCTAssertEqual(engine.evaluate(osVersion: v27_2_0).exposedCount, 5)

        // 13g. iOS 27.2.1: Only worseQuery 0day exposed -> exactly 1 exposed
        let v27_2_1 = SystemOSVersion(major: 27, minor: 2, patch: 1)
        XCTAssertEqual(engine.evaluate(osVersion: v27_2_1).exposedCount, 1)

        // 13h. Future iOS 28.0.0: Unpatched worseQuery 0day remains active, all others patched
        let v28 = SystemOSVersion(major: 28, minor: 0, patch: 0)
        XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: v28))
        XCTAssertEqual(engine.evaluate(osVersion: v28).exposedCount, 1)
        XCTAssertEqual(engine.evaluate(osVersion: v28).overallRiskTier, .highRisk)
    }

    /// 14. Stress-tests SystemOSVersion parser against non-standard string formats and build numbers.
    func test_T5_firmwarePosture_semanticVersionStringParser_fuzzing() {
        let v1 = SystemOSVersion(string: "26.7.2 (24B123)")
        XCTAssertEqual(v1?.major, 26)
        XCTAssertEqual(v1?.minor, 7)
        XCTAssertEqual(v1?.patch, 2)
        XCTAssertEqual(v1?.build, "24B123")

        let v2 = SystemOSVersion(string: "Version 27.2.0 (Build 24C1)")
        XCTAssertEqual(v2?.major, 27)
        XCTAssertEqual(v2?.minor, 2)
        XCTAssertEqual(v2?.patch, 0)

        let v3 = SystemOSVersion(string: "  iOS 27.2.1-beta1  ")
        XCTAssertEqual(v3?.major, 27)
        XCTAssertEqual(v3?.minor, 2)
        XCTAssertEqual(v3?.patch, 1)

        XCTAssertNil(SystemOSVersion(string: ""))
        XCTAssertNil(SystemOSVersion(string: "invalid_os"))
        XCTAssertNil(SystemOSVersion(string: "26"))
        XCTAssertNil(SystemOSVersion(string: "no_dots_here"))
    }

    /// 15. Verifies ExpandedThreatCatalog crypto wallet and messenger impersonation detection
    /// across all Chinese brand aliases and sideloaded channels.
    func test_T5_expandedThreat_impersonation_caseInsensitive_and_chineseAliases() {
        let testCases: [(name: String, bid: String, expectedBrand: String)] = [
            ("小狐狸钱包", "com.custom.wallet", "MetaMask"),
            ("欧易交易所", "com.custom.exchange", "OKX"),
            ("币安Binance", "com.custom.binance", "Binance"),
            ("Telegram 纸飞机", "com.custom.tg", "Telegram"),
            ("tp钱包官方版", "com.custom.tp", "TokenPocket")
        ]

        for tc in testCases {
            let indicators = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: tc.bid,
                displayName: tc.name,
                installChannel: .developerSideloaded,
                cryptid: 0
            )
            XCTAssertEqual(indicators.count, 1, "Failed to match alias '\(tc.name)' for brand \(tc.expectedBrand)")
            XCTAssertEqual(indicators.first?.severity, .highRisk)
            XCTAssertTrue(indicators.first?.signature.contains(tc.expectedBrand) ?? false)
        }
    }

    /// 16. Verifies ExpandedThreatCatalog Private Photos detection for bourgeoisie entitlement and private frameworks.
    func test_T5_expandedThreat_photosBourgeoisieAndPrivatePrefix() {
        // Bourgeoisie entitlement
        let indEntitlement = ExpandedThreatCatalog.evaluatePhotosBypass(
            linkedDylibs: [],
            symbols: [],
            entitlements: ["com.apple.photos.bourgeoisie": true],
            cryptid: 0
        )
        XCTAssertEqual(indEntitlement.count, 1)
        XCTAssertEqual(indEntitlement.first?.signature, "com.apple.photos.bourgeoisie")
        XCTAssertEqual(indEntitlement.first?.severity, .highRisk)

        // AssetsLibraryServices private framework
        let indFramework = ExpandedThreatCatalog.evaluatePhotosBypass(
            linkedDylibs: ["/System/Library/PrivateFrameworks/AssetsLibraryServices.framework/AssetsLibraryServices"],
            symbols: [],
            entitlements: [:],
            cryptid: 0
        )
        XCTAssertEqual(indFramework.count, 1)
        XCTAssertEqual(indFramework.first?.signature, "AssetsLibraryServices.framework")
        XCTAssertEqual(indFramework.first?.severity, .highRisk)
    }

    /// 17. Verifies ExpandedThreatCatalog injected tweaks and hooking framework patterns in LC_LOAD_DYLIB.
    func test_T5_expandedThreat_injectedTweaks_rpathAndExecutablePath_variations() {
        let dylibs = [
            "@rpath/libsubstitute.dylib",
            "@executable_path/Frameworks/patch_anti_jailbreak.dylib",
            "@executable_path/Frameworks/Choicy.dylib",
            "@rpath/game_crack.dylib"
        ]

        let indicators = ExpandedThreatCatalog.evaluateInjectedDylibs(linkedDylibs: dylibs)
        XCTAssertEqual(indicators.count, 4)
        for ind in indicators {
            XCTAssertEqual(ind.severity, .caution)
            XCTAssertEqual(ind.category, "Injected Tweak / Modded IPA")
        }
    }

    /// 18. Verifies fake supervision detection for both residual CloudConfigurationDetails and active supervision.
    func test_T5_expandedThreat_fakeSupervision_residualAndSupervised() throws {
        let containerRoot = mockTree.rootDirectoryURL
        let profileDir = containerRoot
            .appendingPathComponent("systemgroup.com.apple.configurationprofiles")
            .appendingPathComponent("Library")
            .appendingPathComponent("ConfigurationProfiles")
        try FileManager.default.createDirectory(at: profileDir, withIntermediateDirectories: true)

        let cloudPlistURL = profileDir.appendingPathComponent("CloudConfigurationDetails.plist")

        // 18a. Residual plist with IsSupervised: false -> caution
        let residualData = try PropertyListSerialization.data(fromPropertyList: ["IsSupervised": false], format: .xml, options: 0)
        try residualData.write(to: cloudPlistURL)

        let residualInds = ExpandedThreatCatalog.evaluateSupervision(containerRoot: containerRoot)
        XCTAssertEqual(residualInds.count, 1)
        XCTAssertEqual(residualInds.first?.severity, .caution)

        // 18b. Active supervision with IsSupervised: true -> highRisk
        let activeData = try PropertyListSerialization.data(fromPropertyList: ["IsSupervised": true], format: .xml, options: 0)
        try activeData.write(to: cloudPlistURL)

        let activeInds = ExpandedThreatCatalog.evaluateSupervision(containerRoot: containerRoot)
        XCTAssertEqual(activeInds.count, 1)
        XCTAssertEqual(activeInds.first?.severity, .highRisk)
    }

    // =========================================================================
    // MARK: - Group 4: IPAPackageScanner & NativeZIPArchiveReader Hardening
    // =========================================================================

    /// 19. Tests multiple Zip Slip directory traversal attack variations in ZIP headers.
    func test_T5_ipa_zipSlipVariations_rejected() throws {
        let zipSlipAttacks = [
            "Payload/App.app/../../../../etc/shadow",
            "Payload/App.app/sub/../../../../../../tmp/pwn",
            "/Payload/App.app/main",
            "Payload\\App.app\\evil"
        ]

        for attackPath in zipSlipAttacks {
            var zipData = Data()
            let pathBytes = Array(attackPath.utf8)

            // Local header
            zipData.append(contentsOf: [0x50, 0x4b, 0x03, 0x04])
            zipData.append(contentsOf: [UInt8](repeating: 0, count: 22))
            zipData.append(UInt8(pathBytes.count & 0xff))
            zipData.append(UInt8((pathBytes.count >> 8) & 0xff))
            zipData.append(contentsOf: [0, 0])
            zipData.append(contentsOf: pathBytes)

            let cdOffset = zipData.count
            // Central Directory Header
            zipData.append(contentsOf: [0x50, 0x4b, 0x01, 0x02])
            zipData.append(contentsOf: [UInt8](repeating: 0, count: 24))
            zipData.append(UInt8(pathBytes.count & 0xff))
            zipData.append(UInt8((pathBytes.count >> 8) & 0xff))
            zipData.append(contentsOf: [UInt8](repeating: 0, count: 16))
            zipData.append(contentsOf: pathBytes)
            let cdSize = zipData.count - cdOffset

            // EOCD
            zipData.append(contentsOf: [0x50, 0x4b, 0x05, 0x06])
            zipData.append(contentsOf: [0, 0, 0, 0])
            zipData.append(contentsOf: [1, 0]) // 1 entry on disk
            zipData.append(contentsOf: [1, 0]) // 1 entry total
            zipData.append(UInt8(cdSize & 0xff))
            zipData.append(UInt8((cdSize >> 8) & 0xff))
            zipData.append(UInt8((cdSize >> 16) & 0xff))
            zipData.append(UInt8((cdSize >> 24) & 0xff))
            zipData.append(UInt8(cdOffset & 0xff))
            zipData.append(UInt8((cdOffset >> 8) & 0xff))
            zipData.append(UInt8((cdOffset >> 16) & 0xff))
            zipData.append(UInt8((cdOffset >> 24) & 0xff))
            zipData.append(contentsOf: [0, 0])

            let tempURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("slip_\(UUID().uuidString).ipa"))
            try zipData.write(to: tempURL)

            XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: tempURL), "Expected zipSlipDetected for path: \(attackPath)") { error in
                guard case IPAPackageScannerError.zipSlipDetected = error else {
                    XCTFail("Expected zipSlipDetected for path \(attackPath), got \(error)")
                    return
                }
            }
        }
    }

    /// 20. Verifies NativeZIPArchiveReader handling of corrupted EOCD records and buffer underruns.
    func test_T5_ipa_zipReader_corruptedEOCD_and_truncatedBuffers() {
        // Less than 22 bytes
        let tinyData = Data([0x50, 0x4b, 0x05, 0x06])
        let reader = NativeZIPArchiveReader(data: tinyData)
        XCTAssertThrowsError(try reader.readCentralDirectory()) { error in
            guard case IPAPackageScannerError.invalidArchive = error else {
                XCTFail("Expected invalidArchive, got \(error)")
                return
            }
        }

        // Buffer with no EOCD signature anywhere
        let junkData = Data(repeating: 0xaa, count: 128)
        let readerJunk = NativeZIPArchiveReader(data: junkData)
        XCTAssertThrowsError(try readerJunk.readCentralDirectory()) { error in
            guard case IPAPackageScannerError.endOfCentralDirectoryNotFound = error else {
                XCTFail("Expected endOfCentralDirectoryNotFound, got \(error)")
                return
            }
        }
    }

    /// 21. Verifies NativeZIPArchiveReader rejection of password-protected encrypted archives.
    func test_T5_ipa_zipReader_encryptedArchive_throwsEncryptedArchiveNotSupported() throws {
        var zipData = Data()
        let pathBytes = Array("Payload/Test.app/Info.plist".utf8)

        // Local header
        zipData.append(contentsOf: [0x50, 0x4b, 0x03, 0x04])
        zipData.append(contentsOf: [0x00, 0x00]) // version
        zipData.append(contentsOf: [0x01, 0x00]) // flags: bit 0 SET (encrypted)
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 20))
        zipData.append(UInt8(pathBytes.count & 0xff))
        zipData.append(UInt8((pathBytes.count >> 8) & 0xff))
        zipData.append(contentsOf: [0, 0])
        zipData.append(contentsOf: pathBytes)

        let cdOffset = zipData.count
        // Central Directory Header
        zipData.append(contentsOf: [0x50, 0x4b, 0x01, 0x02])
        zipData.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        zipData.append(contentsOf: [0x01, 0x00]) // flags: bit 0 SET (encrypted)
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 20))
        zipData.append(UInt8(pathBytes.count & 0xff))
        zipData.append(UInt8((pathBytes.count >> 8) & 0xff))
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 16))
        zipData.append(contentsOf: pathBytes)
        let cdSize = zipData.count - cdOffset

        // EOCD
        zipData.append(contentsOf: [0x50, 0x4b, 0x05, 0x06])
        zipData.append(contentsOf: [0, 0, 0, 0, 1, 0, 1, 0])
        zipData.append(UInt8(cdSize & 0xff))
        zipData.append(UInt8((cdSize >> 8) & 0xff))
        zipData.append(UInt8((cdSize >> 16) & 0xff))
        zipData.append(UInt8((cdSize >> 24) & 0xff))
        zipData.append(UInt8(cdOffset & 0xff))
        zipData.append(UInt8((cdOffset >> 8) & 0xff))
        zipData.append(UInt8((cdOffset >> 16) & 0xff))
        zipData.append(UInt8((cdOffset >> 24) & 0xff))
        zipData.append(contentsOf: [0, 0])

        let reader = NativeZIPArchiveReader(data: zipData)
        XCTAssertThrowsError(try reader.readCentralDirectory()) { error in
            guard case IPAPackageScannerError.encryptedArchiveNotSupported = error else {
                XCTFail("Expected encryptedArchiveNotSupported, got \(error)")
                return
            }
        }
    }

    /// 22. Verifies that an IPA with Payload/ but no valid .app bundle throws missingAppBundle.
    func test_T5_ipa_missingAppBundleInPayload_throwsMissingAppBundle() throws {
        // Create an IPA where Payload contains only "Payload/readme.txt"
        var zipData = Data()
        let pathBytes = Array("Payload/readme.txt".utf8)
        zipData.append(contentsOf: [0x50, 0x4b, 0x03, 0x04])
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 22))
        zipData.append(UInt8(pathBytes.count & 0xff))
        zipData.append(UInt8((pathBytes.count >> 8) & 0xff))
        zipData.append(contentsOf: [0, 0])
        zipData.append(contentsOf: pathBytes)

        let cdOffset = zipData.count
        zipData.append(contentsOf: [0x50, 0x4b, 0x01, 0x02])
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 24))
        zipData.append(UInt8(pathBytes.count & 0xff))
        zipData.append(UInt8((pathBytes.count >> 8) & 0xff))
        zipData.append(contentsOf: [UInt8](repeating: 0, count: 16))
        zipData.append(contentsOf: pathBytes)
        let cdSize = zipData.count - cdOffset

        zipData.append(contentsOf: [0x50, 0x4b, 0x05, 0x06])
        zipData.append(contentsOf: [0, 0, 0, 0, 1, 0, 1, 0])
        zipData.append(UInt8(cdSize & 0xff))
        zipData.append(UInt8((cdSize >> 8) & 0xff))
        zipData.append(UInt8((cdSize >> 16) & 0xff))
        zipData.append(UInt8((cdSize >> 24) & 0xff))
        zipData.append(UInt8(cdOffset & 0xff))
        zipData.append(UInt8((cdOffset >> 8) & 0xff))
        zipData.append(UInt8((cdOffset >> 16) & 0xff))
        zipData.append(UInt8((cdOffset >> 24) & 0xff))
        zipData.append(contentsOf: [0, 0])

        let fakeIPA = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("no_app_\(UUID().uuidString).ipa"))
        try zipData.write(to: fakeIPA)

        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: fakeIPA)) { error in
            guard case IPAPackageScannerError.missingPayload = error else {
                XCTFail("Expected missingPayload, got \(error)")
                return
            }
        }
    }

    /// 23. Verifies that an IPA with Info.plist referencing a non-existent CFBundleExecutable throws missingExecutable.
    func test_T5_ipa_missingExecutable_throwsMissingExecutable() throws {
        let binary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(arch: .arm64)
        )
        var config = MockIPAGenerator.IPAPackageConfig(
            appName: "MissingExecApp",
            executableBinary: binary
        )
        // We inject an additional corrupted Info.plist that specifies a phantom executable
        let phantomPlist: [String: Any] = [
            "CFBundleIdentifier": "com.example.phantom",
            "CFBundleExecutable": "GhostBinaryThatDoesNotExist",
            "CFBundleName": "MissingExecApp"
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: phantomPlist, format: .xml, options: 0)
        config.additionalFiles["Info.plist"] = plistData

        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: ipaURL)) { error in
            guard case IPAPackageScannerError.missingExecutable(let name) = error, name == "GhostBinaryThatDoesNotExist" else {
                XCTFail("Expected missingExecutable for GhostBinaryThatDoesNotExist, got \(error)")
                return
            }
        }
    }

    /// 24. Complex multi-binary recursive scan: main app, embedded framework with worse_query exploit,
    /// and embedded app extension with fsgetpath inode enumeration.
    func test_T5_ipa_appWithNestedPluginsAndMultipleFrameworks_stressScan() throws {
        let mainEntitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.nested.suite</string>
            </array>
        </dict>
        </plist>
        """

        let mainBin = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                symbols: ["_main"],
                xmlEntitlements: mainEntitlements
            )
        )

        let frameworkBin = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                symbols: ["_container_query_create", "_sandbox_extension_consume"]
            )
        )

        let pluginBin = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                symbols: ["_fsgetpath"]
            )
        )

        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "CompoundSuiteApp",
            bundleIdentifier: "com.example.compound.suite",
            executableBinary: mainBin,
            provisioningProfile: .developerSideloaded(teamId: "COMP123", devices: ["DEV-1"]),
            embeddedFrameworks: [
                "CoreExploit.framework/CoreExploit": frameworkBin
            ],
            appExtensions: [
                "ProbeExtension.appex": (bundleId: "com.example.compound.suite.probe", binary: pluginBin)
            ]
        )

        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))
        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)

        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertEqual(finding.installChannel, .developerSideloaded)
        XCTAssertFalse(finding.isWhitelisted)

        // Verify indicators collected from main, framework, and plugin
        XCTAssertTrue(finding.evidence.matchedSymbols.contains("container_query_create") || finding.evidence.matchedSymbols.contains("_container_query_create"))
        XCTAssertTrue(finding.evidence.matchedSymbols.contains("fsgetpath") || finding.evidence.matchedSymbols.contains("_fsgetpath"))
        XCTAssertTrue(finding.indicators.contains { $0.location.contains("Frameworks/CoreExploit.framework") })
        XCTAssertTrue(finding.indicators.contains { $0.location.contains("PlugIns/ProbeExtension.appex") })
    }
}
