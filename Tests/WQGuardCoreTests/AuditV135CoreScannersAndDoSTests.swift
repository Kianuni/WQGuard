//
//  AuditV135CoreScannersAndDoSTests.swift
//  WQGuardCoreTests
//
//  Milestone M3 Deterministic Regression & Boundary Test Suite:
//  1. LockdownInstProxyClient (PKCS#8 OOB crash, 64MB header EOF without 64MB alloc, 4MB pairing cap, PEM empty reject, ReturnAttributes)
//  2. ContainerScanner (root symlink, in-container symlink traversal, benign/cycle controls, unconditional supervision check, symlink parent rejection)
//  3. CSStore2Parser (fast-fail on garbage 16MB store, path/control-char/UUID validation, collision safety)
//  4. MCMReader (identifier/user sanitization, CFBoolean-as-Int rejection)
//  5. OnDeviceAppProbeScanner (AuditEvidence flags, scheme/bundle validation & deduplication, custom whitelist bilingual guidance, Task cancellation)
//  6. FirmwarePostureEngine (prerelease bypass fix, regex/length DoS, patch overflow fail-safe, Codable negative rejection)
//  7. ReportGenerator (engineVersion Markdown/PlainText injection, non-finite duration guard, control-char DoS perf, preserved "1.0.0")
//  8. CLICommandRunner (FD-pinned ancestor symlink defenses, isolated per-run --whitelist without .shared mutation, fail-closed container/input errors)
//

import XCTest
import Foundation
import Darwin
import Network
@testable import WQGuardCore

final class AuditV135CoreScannersAndDoSTests: XCTestCase {

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
            if let enumerator = FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.isSymbolicLinkKey]) {
                while let item = enumerator.nextObject() as? URL {
                    if let isSym = (try? item.resourceValues(forKeys: [.isSymbolicLinkKey]))?.isSymbolicLink, isSym {
                        continue
                    }
                    _ = try? FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: item.path)
                }
            }
            _ = try? FileManager.default.removeItem(at: url)
        }
        tempURLs.removeAll()
        super.tearDown()
    }

    @discardableResult
    private func trackTemp(_ url: URL) -> URL {
        tempURLs.append(url)
        return url
    }

    private func makeTempDir(prefix: String = "m3_test") throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return trackTemp(dir)
    }

    private func runCLIInProcess(_ args: [String]) async throws -> (code: Int32, out: String, err: String) {
        let dir = try makeTempDir(prefix: "m3_cli_io")
        let outURL = dir.appendingPathComponent("stdout.txt")
        let errURL = dir.appendingPathComponent("stderr.txt")
        FileManager.default.createFile(atPath: outURL.path, contents: nil)
        FileManager.default.createFile(atPath: errURL.path, contents: nil)
        let outH = try FileHandle(forWritingTo: outURL)
        let errH = try FileHandle(forWritingTo: errURL)
        let code = await CLICommandRunner.run(arguments: ["wqguard-cli"] + args, stdout: outH, stderr: errH)
        try outH.close()
        try errH.close()
        return (
            code,
            String(decoding: try Data(contentsOf: outURL), as: UTF8.self),
            String(decoding: try Data(contentsOf: errURL), as: UTF8.self)
        )
    }

    private func containsHanCharacters(_ text: String) -> Bool {
        text.unicodeScalars.contains { scalar in
            let v = scalar.value
            return (0x4E00...0x9FFF).contains(v)
                || (0x3400...0x4DBF).contains(v)
                || (0xF900...0xFAFF).contains(v)
                || (0x20000...0x2EBEF).contains(v)
        }
    }

    // MARK: - 1. LockdownInstProxyClient Hardening

    func test_lockdown_unwrapPKCS8_zeroLengthOctetStringAtEOF_neverCrashes() {
        let rsaOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

        // Crafted input where idx == bytes.count and payloadLen == 0 after multi-byte length 0x81 0x00
        let prefix = [UInt8](repeating: 0x30, count: 16)
        let eofCrashPayload = Data(prefix + rsaOID + [0x05, 0x00, 0x04, 0x81, 0x00])
        XCTAssertEqual(LockdownPairingFile.unwrapPKCS8PrivateKeyIfNeeded(eofCrashPayload), eofCrashPayload)

        // Short-form 0x04 0x00 followed by 0x30 (must not return empty Data)
        let zeroLenPayload = Data(prefix + rsaOID + [0x05, 0x00, 0x04, 0x00, 0x30, 0x01])
        XCTAssertEqual(LockdownPairingFile.unwrapPKCS8PrivateKeyIfNeeded(zeroLenPayload), zeroLenPayload)
    }

    func test_lockdown_parseData_4MBQuota_andEmptyPEMRejected() {
        let oversized = Data(repeating: 0x41, count: 4 * 1024 * 1024 + 1)
        XCTAssertThrowsError(try LockdownPairingFile.parse(data: oversized)) { err in
            guard case LockdownClientError.invalidPairingFile = err else {
                XCTFail("Expected invalidPairingFile for >4MB pairing data, got \(err)")
                return
            }
        }

        let emptyPEM = Data("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n".utf8)
        XCTAssertNil(LockdownPairingFile.decodePEMOrDER(emptyPEM))
    }

    func test_lockdown_readPlistPacket_64MBHeaderEOF_failsPromptly() throws {
        var sv: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv), 0)
        let clientFD = sv[0]
        let serverFD = sv[1]
        defer { Darwin.close(clientFD) }

        // Peer sends 64 MB packet length header (0x04000000) and immediately closes without sending payload
        var headerBE = UInt32(64 * 1024 * 1024).bigEndian
        let headerBytes = withUnsafeBytes(of: &headerBE) { Array($0) }
        _ = headerBytes.withUnsafeBytes { ptr in
            Darwin.send(serverFD, ptr.baseAddress, ptr.count, 0)
        }
        Darwin.close(serverFD)

        let start = Date()
        XCTAssertThrowsError(try LockdownInstProxyClient.readPlistPacket(fromFD: clientFD, step: "M3Test")) { err in
            guard case LockdownClientError.protocolError(let msg) = err else {
                XCTFail("Expected protocolError, got \(err)")
                return
            }
            XCTAssertTrue(msg.contains("EOF"))
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)
    }

    func test_lockdown_subnetDiagnosisAndRegistryTeamBundlePath() {
        let diag = LocalNetworkSubnetDiagnosis.inspect()
        XCTAssertEqual(diag.configuredHost, "10.7.0.1")

        let dict: [String: Any] = [
            "CFBundleIdentifier": "com.m3.attrs.app",
            "CFBundleDisplayName": "AttrsApp",
            "CFBundleShortVersionString": "1.0",
            "ApplicationType": "User",
            "TeamIdentifier": "TEAM987654",
            "BundlePath": "/private/var/containers/Bundle/Application/11111111-2222-3333-4444-555555555555/AttrsApp.app"
        ]
        let rec = InstalledAppRegistryRecord.fromDictionary(dict)
        XCTAssertEqual(rec?.teamId, "TEAM987654")
        XCTAssertEqual(rec?.bundlePath, "/private/var/containers/Bundle/Application/11111111-2222-3333-4444-555555555555/AttrsApp.app")
    }

    func test_lockdown_negotiateInstallationProxyPort_peerCloseDuringTLSRelay_noSigPipeCrash() throws {
        let pairing = LockdownPairingFile(
            hostID: "11112222-3333-4444-5555-666677778888",
            systemBUID: "AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111",
            hostCertificateDER: Data([0x30, 0x03, 0x02, 0x01, 0x01]),
            hostPrivateKeyDER: Data([0x30, 0x03, 0x02, 0x01, 0x02])
        )

        var sv: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv), 0)
        let clientFD = sv[0]
        let serverFD = sv[1]

        var preOpt: Int32 = -1
        var preLen = socklen_t(MemoryLayout<Int32>.size)
        XCTAssertEqual(getsockopt(clientFD, SOL_SOCKET, SO_NOSIGPIPE, &preOpt, &preLen), 0)
        XCTAssertEqual(preOpt, 0, "Caller must NOT pre-set SO_NOSIGPIPE for this regression test")

        let peerDone = expectation(description: "Mock lockdownd closes after EnableSessionSSL=true")
        DispatchQueue.global(qos: .userInitiated).async {
            defer {
                Darwin.close(serverFD)
                peerDone.fulfill()
            }
            guard let q = try? LockdownInstProxyClient.readPlistPacket(fromFD: serverFD),
                  (q["Request"] as? String) == "QueryType" else { return }
            try? LockdownInstProxyClient.writePlistPacket(
                ["Request": "QueryType", "Type": "com.apple.mobile.lockdown"],
                toFD: serverFD
            )

            guard let s = try? LockdownInstProxyClient.readPlistPacket(fromFD: serverFD),
                  (s["Request"] as? String) == "StartSession" else { return }
            try? LockdownInstProxyClient.writePlistPacket(
                ["Request": "StartSession", "SessionID": "M3-SIGPIPE-TEST", "EnableSessionSSL": true],
                toFD: serverFD
            )
            // Immediately close serverFD before TLS ClientHello relay completes
        }

        XCTAssertThrowsError(
            try LockdownInstProxyClient.shared.negotiateInstallationProxyPort(
                rawSocketFD: clientFD,
                pairing: pairing,
                tlsOptions: NWProtocolTLS.Options()
            )
        ) { err in
            guard case LockdownClientError.protocolError = err else {
                XCTFail("Expected LockdownClientError.protocolError without SIGPIPE crash, got \(err)")
                return
            }
        }
        wait(for: [peerDone], timeout: 5.0)
    }

    func test_lockdown_writePlistPacket_closedPeerWithoutCallerNoSigPipe_throwsProtocolError() throws {
        var sv: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv), 0)
        let clientFD = sv[0]
        let serverFD = sv[1]
        defer { Darwin.close(clientFD) }

        var preOpt: Int32 = -1
        var preLen = socklen_t(MemoryLayout<Int32>.size)
        XCTAssertEqual(getsockopt(clientFD, SOL_SOCKET, SO_NOSIGPIPE, &preOpt, &preLen), 0)
        XCTAssertEqual(preOpt, 0, "Caller must NOT pre-set SO_NOSIGPIPE for this regression test")

        Darwin.close(serverFD)

        XCTAssertThrowsError(
            try LockdownInstProxyClient.writePlistPacket(["Request": "QueryType"], toFD: clientFD, step: "test")
        ) { err in
            guard case LockdownClientError.protocolError(let msg) = err else {
                XCTFail("Expected LockdownClientError.protocolError without SIGPIPE crash, got \(err)")
                return
            }
            XCTAssertTrue(msg.contains("EPIPE") || msg.contains("ECONNRESET"), "Unexpected error message: \(msg)")
        }
    }

    // MARK: - 2. ContainerScanner Symlink Traversal & Unconditional Supervision

    func test_container_rootSymlink_flaggedHighRiskWithoutTraversal() throws {
        let base = try makeTempDir(prefix: "m3_cont_root")
        let realTarget = base.appendingPathComponent("RealOutside")
        try FileManager.default.createDirectory(at: realTarget, withIntermediateDirectories: true)

        let symContainer = base.appendingPathComponent("SymContainer")
        XCTAssertEqual(symlink(realTarget.path, symContainer.path), 0)

        let result = try ContainerScanner.shared.scanContainer(at: symContainer)
        XCTAssertFalse(result.isClean)
        XCTAssertTrue(result.escapingSymlinks.contains(symContainer.path))
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_ROOT_SYMLINK" && $0.severity == .highRisk })
    }

    func test_container_inContainerSymlinkTraversal_catchesHiddenEscapes() throws {
        // 1. Library/Caches -> ../OtherDir where OtherDir/escape -> /etc/passwd
        do {
            let c1 = try makeTempDir(prefix: "m3_caches_hop")
            try FileManager.default.createDirectory(at: c1.appendingPathComponent("Library"), withIntermediateDirectories: true)
            let otherDir = c1.appendingPathComponent("OtherDir")
            try FileManager.default.createDirectory(at: otherDir, withIntermediateDirectories: true)
            XCTAssertEqual(symlink("/etc/passwd", otherDir.appendingPathComponent("escape").path), 0)
            XCTAssertEqual(symlink("../OtherDir", c1.appendingPathComponent("Library/Caches").path), 0)

            let r1 = try ContainerScanner.shared.scanContainer(at: c1)
            XCTAssertFalse(r1.isClean)
            XCTAssertTrue(r1.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" && $0.severity == .highRisk })
        }

        // 2. Library -> RealLib where RealLib/Caches/escape -> /etc/passwd
        do {
            let c2 = try makeTempDir(prefix: "m3_lib_hop")
            let realLibCaches = c2.appendingPathComponent("RealLib/Caches")
            try FileManager.default.createDirectory(at: realLibCaches, withIntermediateDirectories: true)
            XCTAssertEqual(symlink("/etc/passwd", realLibCaches.appendingPathComponent("escape").path), 0)
            XCTAssertEqual(symlink("RealLib", c2.appendingPathComponent("Library").path), 0)

            let r2 = try ContainerScanner.shared.scanContainer(at: c2)
            XCTAssertFalse(r2.isClean)
            XCTAssertTrue(r2.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" && $0.severity == .highRisk })
        }

        // 3. Library/Caches/sub -> ../OtherDir where OtherDir/escape -> /etc/passwd
        do {
            let c3 = try makeTempDir(prefix: "m3_child_hop")
            let caches = c3.appendingPathComponent("Library/Caches")
            let otherDir = c3.appendingPathComponent("Library/OtherDir")
            try FileManager.default.createDirectory(at: caches, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: otherDir, withIntermediateDirectories: true)
            XCTAssertEqual(symlink("/etc/passwd", otherDir.appendingPathComponent("escape").path), 0)
            XCTAssertEqual(symlink("../OtherDir", caches.appendingPathComponent("sub").path), 0)

            let r3 = try ContainerScanner.shared.scanContainer(at: c3)
            XCTAssertFalse(r3.isClean)
            XCTAssertTrue(r3.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" && $0.severity == .highRisk })
        }
    }

    func test_container_benignInContainerSymlinks_andCycles_remainClean() throws {
        let container = try makeTempDir(prefix: "m3_benign_hop")
        let docs = container.appendingPathComponent("Documents")
        let lib = container.appendingPathComponent("Library")
        try FileManager.default.createDirectory(at: docs, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: lib, withIntermediateDirectories: true)
        try Data("clean".utf8).write(to: docs.appendingPathComponent("safe.txt"))
        XCTAssertEqual(symlink("../Documents", lib.appendingPathComponent("Caches").path), 0)
        XCTAssertEqual(symlink("loop", docs.appendingPathComponent("loop").path), 0)

        let result = try ContainerScanner.shared.scanContainer(at: container)
        XCTAssertTrue(result.isClean)
        XCTAssertTrue(result.escapingSymlinks.isEmpty)
    }

    func test_container_unconditionalSupervisionCheck_ignoresMissingOrCorruptMetadata() throws {
        // 1. UUID-named container with NO metadata plist
        let c1 = try makeTempDir(prefix: "m3_sup_nometa").appendingPathComponent(UUID().uuidString)
        let cfg1 = c1.appendingPathComponent("Library/ConfigurationProfiles")
        try FileManager.default.createDirectory(at: cfg1, withIntermediateDirectories: true)
        let supData = try PropertyListSerialization.data(fromPropertyList: ["IsSupervised": true], format: .xml, options: 0)
        try supData.write(to: cfg1.appendingPathComponent("CloudConfigurationDetails.plist"))

        let r1 = try ContainerScanner.shared.scanContainer(at: c1)
        XCTAssertTrue(r1.indicators.contains { $0.signature == "SYSTEMGROUP_SUPERVISION_DETECTED" && $0.severity == .highRisk })

        // 2. UUID-named container with corrupted metadata plist
        let c2 = try makeTempDir(prefix: "m3_sup_corrupt").appendingPathComponent(UUID().uuidString)
        let cfg2 = c2.appendingPathComponent("Library/ConfigurationProfiles")
        try FileManager.default.createDirectory(at: cfg2, withIntermediateDirectories: true)
        try Data("not-a-plist".utf8).write(to: c2.appendingPathComponent(MCMReader.metadataFilename))
        try supData.write(to: cfg2.appendingPathComponent("CloudConfigurationDetails.plist"))

        let r2 = try ContainerScanner.shared.scanContainer(at: c2)
        XCTAssertTrue(r2.indicators.contains { $0.signature == "SYSTEMGROUP_SUPERVISION_DETECTED" && $0.severity == .highRisk })

        // 3. Container with Library -> RealLib (internal symlink) + CloudConfigurationDetails.plist
        let c3 = try makeTempDir(prefix: "m3_sup_liblink").appendingPathComponent(UUID().uuidString)
        let cfg3 = c3.appendingPathComponent("RealLib/ConfigurationProfiles")
        try FileManager.default.createDirectory(at: cfg3, withIntermediateDirectories: true)
        XCTAssertEqual(symlink("RealLib", c3.appendingPathComponent("Library").path), 0)
        try supData.write(to: cfg3.appendingPathComponent("CloudConfigurationDetails.plist"))

        let r3 = try ContainerScanner.shared.scanContainer(at: c3)
        XCTAssertTrue(r3.indicators.contains { $0.signature == "SYSTEMGROUP_SUPERVISION_DETECTED" && $0.severity == .highRisk })
    }

    func test_container_scanAppGroupContainers_rejectsSymlinkedParent() throws {
        let base = try makeTempDir(prefix: "m3_parent_sym")
        let realDir = base.appendingPathComponent("RealParent")
        try FileManager.default.createDirectory(at: realDir, withIntermediateDirectories: true)
        let symParent = base.appendingPathComponent("SymParent")
        XCTAssertEqual(symlink(realDir.path, symParent.path), 0)

        XCTAssertThrowsError(try ContainerScanner.shared.scanAppGroupContainers(at: symParent)) { err in
            guard case ContainerScannerError.symlinkParentDirectory = err else {
                XCTFail("Expected symlinkParentDirectory error, got \(err)")
                return
            }
        }
    }

    // MARK: - 3. CSStore2Parser DoS & Path Validation

    func test_csstore2_16MBGarbageStore_failsFastUnder1Second() {
        var data = Data(count: 16 * 1024 * 1024)
        data[0] = 0x62 // 'b'
        data[1] = 0x64 // 'd'
        data[2] = 0x73 // 's'
        data[3] = 0x6c // 'l'

        let start = Date()
        XCTAssertThrowsError(try CSStore2Parser.shared.parse(data: data)) { err in
            guard case CSStore2ParserError.noValidLayoutMatched = err else {
                XCTFail("Expected noValidLayoutMatched, got \(err)")
                return
            }
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)

        // Adversarial 0x00000250-flooded 16MB buffer must also fail fast under 2.0s in debug (-Onone)
        var flooded = Data(count: 16 * 1024 * 1024)
        flooded.withUnsafeMutableBytes { raw in
            let u32 = raw.bindMemory(to: UInt32.self)
            for i in 0..<u32.count {
                u32[i] = UInt32(0x00000250).littleEndian
            }
        }
        flooded[0] = 0x62; flooded[1] = 0x64; flooded[2] = 0x73; flooded[3] = 0x6c
        let floodStart = Date()
        XCTAssertThrowsError(try CSStore2Parser.shared.parse(data: flooded)) { err in
            guard case CSStore2ParserError.noValidLayoutMatched = err else {
                XCTFail("Expected noValidLayoutMatched for flooded store, got \(err)")
                return
            }
        }
        XCTAssertLessThan(Date().timeIntervalSince(floodStart), 2.0)
    }

    func test_csstore2_sanitizesDiscoveredBundlePaths_andHandlesPathCollisions() throws {
        var data = Data(count: 16384)
        data[0] = 0x62; data[1] = 0x64; data[2] = 0x73; data[3] = 0x6c

        let marker = Data([0x3c, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3e])
        data.replaceSubrange(0x400..<(0x400 + marker.count), with: marker)

        func appendLE32(_ val: UInt32, at offset: Int) {
            var v = val.littleEndian
            withUnsafeBytes(of: &v) { data.replaceSubrange(offset..<(offset + 4), with: $0) }
        }

        var strOffset = 0x500
        func writeString(sid: UInt32, str: String) -> UInt32 {
            appendLE32(sid, at: strOffset)
            let utf8 = Array(str.utf8)
            appendLE32(UInt32(utf8.count), at: strOffset + 4)
            data.replaceSubrange((strOffset + 8)..<(strOffset + 8 + utf8.count), with: utf8)
            data[strOffset + 8 + utf8.count] = 0
            let entryLen = 8 + utf8.count + 4
            strOffset += (entryLen + 3) & ~3
            return sid << 2
        }

        let validUUID = "12345678-1234-1234-1234-123456789ABC"
        let bidRef = writeString(sid: 10, str: "com.m3.csstore.test")
        let contRef = writeString(sid: 11, str: "/var/mobile/Containers/Data/Application/\(validUUID)")
        let nameRef = writeString(sid: 12, str: "CSStoreTest")

        // Write colliding paths sharing sid 20
        _ = writeString(sid: 20, str: "/var/mobile/Containers/Data/Application/AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")
        _ = writeString(sid: 20, str: "/var/mobile/Containers/Data/Application/BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")
        let bidCollideRef = writeString(sid: 21, str: "com.m3.collide")

        // Layout 27.0 bundleSize = 0x250
        let rec1 = 0x100
        appendLE32(0x250, at: rec1 + 4)
        appendLE32(bidRef, at: rec1 + 8 + 0x0c)
        appendLE32(contRef, at: rec1 + 8 + 0x68)
        appendLE32(nameRef, at: rec1 + 8 + 0x6c)
        appendLE32(nameRef, at: rec1 + 8 + 0x74)

        let rec2 = 0x360
        appendLE32(0x250, at: rec2 + 4)
        appendLE32(bidCollideRef, at: rec2 + 8 + 0x0c)
        appendLE32(20 << 2, at: rec2 + 8 + 0x68)

        // Append hostile bundle path needles in data tail
        let uuid2 = "22222222-2222-2222-2222-222222222222"
        let uuid3 = "33333333-3333-3333-3333-333333333333"
        let uuid4 = "44444444-4444-4444-4444-444444444444"
        let tail = [
            "/var/containers/Bundle/Application/\(uuid2)/Evil\u{007F}.app\0",
            "/var/containers/Bundle/Application/\(uuid3)/Bidi\u{202E}App.app\0",
            "/var/containers/Bundle/Application/\(uuid4)/.app\0",
            "/var/containers/Bundle/Application/\(validUUID)/CleanApp.app\0"
        ].joined()
        let tailBytes = Array(tail.utf8)
        data.replaceSubrange(strOffset..<(strOffset + tailBytes.count), with: tailBytes)

        let snap = try CSStore2Parser.shared.parse(data: data)
        XCTAssertEqual(snap.appContainers.values.contains("com.m3.collide"), false, "Colliding container path must be dropped")
        XCTAssertTrue(snap.discoveredAppBundles.contains("/var/containers/Bundle/Application/\(validUUID)/CleanApp.app"))
        XCTAssertFalse(snap.discoveredAppBundles.contains { $0.contains("\u{007F}") || $0.contains("\u{202E}") || $0.hasSuffix("/.app") })
    }

    // MARK: - 4. MCMReader Identifier Sanitization & CFBoolean Rejection

    func test_mcmReader_sanitizesIdentifiers_andRejectsCFBooleanClass() throws {
        let validUUID = UUID().uuidString

        // 1. Whitespace-only identifier -> missingRequiredKey
        let wsData = try PropertyListSerialization.data(fromPropertyList: [
            "MCMMetadataIdentifier": "   \t\n ",
            "MCMMetadataUUID": validUUID
        ], format: .xml, options: 0)
        XCTAssertThrowsError(try MCMReader.shared.parseMetadata(data: wsData)) { err in
            guard case MCMReaderError.missingRequiredKey(let k) = err else {
                XCTFail("Expected missingRequiredKey, got \(err)")
                return
            }
            XCTAssertEqual(k, "MCMMetadataIdentifier")
        }

        // 2. Hostile identifier payloads (control chars, BiDi, path traversal, >512 bytes) -> corruptedPlist
        let hostileIds = [
            "group.evil\nInjected",
            "group.evil\u{001B}[31m",
            "group.evil\u{0000}nul",
            "group.evil\u{202E}bidi",
            "group/evil",
            "group\\evil",
            "group..evil",
            String(repeating: "a", count: 513)
        ]
        for badId in hostileIds {
            let fmt: PropertyListSerialization.PropertyListFormat = badId.contains("\0") ? .binary : .xml
            let d = try PropertyListSerialization.data(fromPropertyList: [
                "MCMMetadataIdentifier": badId,
                "MCMMetadataUUID": validUUID
            ], format: fmt, options: 0)
            XCTAssertThrowsError(try MCMReader.shared.parseMetadata(data: d), "Hostile identifier \(badId.debugDescription) must throw") { err in
                guard case MCMReaderError.corruptedPlist = err else {
                    XCTFail("Expected corruptedPlist, got \(err)")
                    return
                }
            }
        }

        // 3. CFBoolean for MCMMetadataClass / Version / SchemaVersion must NOT bridge as Int (e.g. true -> 1 == .appData)
        let boolData = try PropertyListSerialization.data(fromPropertyList: [
            "MCMMetadataIdentifier": "group.com.bool.test",
            "MCMMetadataUUID": validUUID,
            "MCMMetadataClass": true,
            "MCMMetadataVersion": true,
            "MCMMetadataSchemaVersion": false
        ], format: .xml, options: 0)
        let meta = try MCMReader.shared.parseMetadata(data: boolData)
        XCTAssertEqual(meta.rawClass, -1)
        XCTAssertEqual(meta.containerClass, .unknown)
        XCTAssertEqual(meta.version, 1)
        XCTAssertNil(meta.schemaVersion)

        // 4. Hostile MCMMetadataUser -> corruptedPlist
        for badUser in ["mobile/../../root", "mobile\u{202E}admin", String(repeating: "u", count: 257)] {
            let ud = try PropertyListSerialization.data(fromPropertyList: [
                "MCMMetadataIdentifier": "group.com.user.test",
                "MCMMetadataUUID": validUUID,
                "MCMMetadataUser": badUser
            ], format: .xml, options: 0)
            XCTAssertThrowsError(try MCMReader.shared.parseMetadata(data: ud)) { err in
                guard case MCMReaderError.corruptedPlist = err else {
                    XCTFail("Expected corruptedPlist for hostile MCMMetadataUser, got \(err)")
                    return
                }
            }
        }
    }

    // MARK: - 5. OnDeviceAppProbeScanner Validation, Evidence & Guidance

    func test_probeScanner_defaultCatalogEvidenceAndValidation() {
        let findings = OnDeviceAppProbeScanner.shared.evaluateProbes { _ in true }
        XCTAssertEqual(findings.count, OnDeviceAppProbeScanner.defaultCatalog.count)
        for f in findings {
            XCTAssertEqual(f.riskTier, .caution)
            XCTAssertFalse(f.isWhitelisted)
            XCTAssertNil(f.teamId)
            XCTAssertEqual(f.evidence.auditDepth, .onDeviceProbe)
            XCTAssertTrue(f.evidence.isWhitelistEligible)
            XCTAssertFalse(f.evidence.isTeamIdWhitelistVerified)
        }

        // Invalid schemes must never be passed to canOpenScheme; duplicate & bad canonicalBundleIds skipped
        var probedSchemes: [String] = []
        let customCatalog: [AppProbeDefinition] = [
            AppProbeDefinition(
                displayName: "BadSchemes",
                canonicalBundleId: "com.m3.badschemes",
                schemes: ["", "esign\n# Forged", "bad://scheme", "evil\u{0000}", "a/b?c=1", "1bad", String(repeating: "a", count: 65), "valid-scheme+1.0"],
                role: .sideloadSigner,
                summaryZh: "BadSchemes",
                summaryEn: "BadSchemes"
            ),
            AppProbeDefinition(
                displayName: "DupEntry",
                canonicalBundleId: "com.m3.badschemes",
                schemes: ["anothervalid"],
                role: .sideloadSigner,
                summaryZh: "DupEntry",
                summaryEn: "DupEntry"
            ),
            AppProbeDefinition(
                displayName: "BadBundle",
                canonicalBundleId: "com.m3.ctrl\u{001B}",
                schemes: ["cleanvalid"],
                role: .sideloadSigner,
                summaryZh: "BadBundle",
                summaryEn: "BadBundle"
            )
        ]
        let customFindings = OnDeviceAppProbeScanner.shared.evaluateProbes(catalog: customCatalog) { scheme in
            probedSchemes.append(scheme)
            return true
        }
        XCTAssertEqual(probedSchemes, ["valid-scheme+1.0"])
        XCTAssertEqual(customFindings.count, 1)
        XCTAssertEqual(customFindings[0].bundleId, "com.m3.badschemes")

        // Oversized catalog capped at 1024
        let hugeCatalog = (0..<1500).map { idx in
            AppProbeDefinition(
                displayName: "Tool \(idx)",
                canonicalBundleId: "com.m3.tool.\(idx)",
                schemes: ["scheme\(idx)"],
                role: .localDevDebugger,
                summaryZh: "Tool \(idx)",
                summaryEn: "Tool \(idx)"
            )
        }
        let hugeFindings = OnDeviceAppProbeScanner.shared.evaluateProbes(catalog: hugeCatalog) { _ in true }
        XCTAssertEqual(hugeFindings.count, 1024)
    }

    func test_probeScanner_customWhitelistUpdatesGuidanceBilingually_andBuiltInWQGuardBlocked() {
        let engine = WhitelistEngine()
        engine.registerCustomTool(WhitelistedTool(
            name: "CustomSideStore",
            allowedBundleIds: ["com.SideStore.SideStore"]
        ))
        let scanner = OnDeviceAppProbeScanner(whitelistEngine: engine)

        WQLocale.overrideLanguageCode = "en"
        let enFindings = scanner.evaluateProbes { $0 == "sidestore" }
        XCTAssertEqual(enFindings.count, 1)
        XCTAssertEqual(enFindings[0].riskTier, .knownTool)
        XCTAssertTrue(enFindings[0].isWhitelisted)
        XCTAssertTrue(enFindings[0].evidence.remediationGuidance.contains("CustomSideStore"))
        XCTAssertFalse(containsHanCharacters(enFindings[0].evidence.remediationGuidance))

        // Built-in WQGuard rule must NOT whitelist a spoofed com.wqguard.app on-device probe
        let spoofCatalog = [
            AppProbeDefinition(
                displayName: "WQGuard",
                canonicalBundleId: "com.wqguard.app",
                schemes: ["wqspoof"],
                role: .sideloadSigner,
                summaryZh: "Spoof",
                summaryEn: "Spoof"
            )
        ]
        let spoofFindings = scanner.evaluateProbes(catalog: spoofCatalog) { $0 == "wqspoof" }
        XCTAssertEqual(spoofFindings.count, 1)
        XCTAssertEqual(spoofFindings[0].riskTier, .caution)
        XCTAssertFalse(spoofFindings[0].isWhitelisted)
    }

    func test_probeScanner_cancelledTaskReturnsEmpty() async {
        let task = Task { () -> [ScanFinding] in
            await OnDeviceAppProbeScanner.shared.probeInstalledAppsAsync()
        }
        task.cancel()
        let result = await task.value
        XCTAssertTrue(result.isEmpty)
    }

    // MARK: - 6. FirmwarePostureEngine Hardening

    func test_firmware_prereleaseBypassFix_andRSRNegativeControls() throws {
        let engine = FirmwarePostureEngine.shared

        // Previously bypassed "27.3 A beta 1" / "27.3 b (beta 1)" must be detected as beta1 and exposed to worseQuery0day
        for s in ["27.3 A beta 1", "27.3 b (beta 1)", "27.3 b - Developer Beta 1", "27.3 a beta1"] {
            let v = try XCTUnwrap(SystemOSVersion(string: s), "\(s) must parse")
            XCTAssertEqual(v.prerelease, "beta1", "\(s) prerelease mismatch")
            XCTAssertEqual(v.betaOrdinal, 1)
            XCTAssertTrue(engine.isVulnerable(.worseQuery0day, in: v), "\(s) must be vulnerable to worseQuery0day")
        }

        // RSR post-GA "(a)" / "(b)" remain GA .safe
        for rsr in ["iOS 27.3 (a)", "27.3 (b)"] {
            let v = try XCTUnwrap(SystemOSVersion(string: rsr))
            XCTAssertNil(v.prerelease)
            XCTAssertFalse(engine.isVulnerable(.worseQuery0day, in: v))
        }

        // beta 2 variants with preceding " A" / " b" are patched
        for b2 in ["27.3 b beta 2", "27.3 A beta 2"] {
            let v = try XCTUnwrap(SystemOSVersion(string: b2))
            XCTAssertEqual(v.betaOrdinal, 2)
            XCTAssertFalse(engine.isVulnerable(.worseQuery0day, in: v))
        }
    }

    func test_firmware_regexAndLengthDoS_andOverflowFailSafe_andNegativeCodable() throws {
        let start = Date()
        XCTAssertNil(SystemOSVersion(string: "27.3" + String(repeating: " ", count: 100_000)))
        XCTAssertNil(SystemOSVersion(string: String(repeating: "9", count: 100_000)))
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.1)

        // Beta ordinal overflow stays fail-safe EXPOSED (betaOrdinal == 0)
        let overflowBeta = try XCTUnwrap(SystemOSVersion(string: "27.3-beta99999999999999999999"))
        XCTAssertEqual(overflowBeta.betaOrdinal, 0)
        XCTAssertTrue(FirmwarePostureEngine.shared.isVulnerable(.worseQuery0day, in: overflowBeta))

        // Patch overflow stays fail-safe 0 (EXPOSED for 26.7.<overflow> < 26.7.3)
        let overflowPatch = try XCTUnwrap(SystemOSVersion(string: "26.7.99999999999999999999"))
        XCTAssertEqual(overflowPatch.patch, 0)
        XCTAssertTrue(FirmwarePostureEngine.shared.isVulnerable(.brotliOOB, in: overflowPatch))
        XCTAssertTrue(FirmwarePostureEngine.shared.isVulnerable(.worseQuery0day, in: overflowPatch))

        // Negative Codable JSON throws DecodingError
        let negJSON = Data("{\"major\": -1, \"minor\": 0, \"patch\": 0}".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(SystemOSVersion.self, from: negJSON))

        // Directly constructed negative SystemOSVersion fails closed
        let negVer = SystemOSVersion(major: -1, minor: 0, patch: 0)
        XCTAssertTrue(FirmwarePostureEngine.shared.isVulnerable(.worseQuery0day, in: negVer))
    }

    // MARK: - 7. ReportGenerator Injection, Duration Guard, DoS & Constants

    func test_report_engineVersionSanitized_andDurationGuarded_andPlainFast() throws {
        let hostileVer = "1.0.0 |\n> ### 🟢 SYSTEM STATUS: SECURE\n# Forged\u{001B}[31m\u{202E}\u{E0041}"
        let sessionInf = ScanSession(
            findings: [],
            systemVersion: "iOS 27.3",
            scanDuration: .infinity,
            engineVersion: hostileVer
        )

        let md = ReportGenerator.shared.generateMarkdownReport(session: sessionInf)
        let mdLines = md.components(separatedBy: "\n")
        let engLines = mdLines.filter { $0.contains("Engine Version / 扫描引擎版本") }
        XCTAssertEqual(engLines.count, 1)
        XCTAssertFalse(mdLines.contains("# Forged"))
        XCTAssertFalse(md.unicodeScalars.contains { $0.value == 0x1B || $0.value == 0x202E || $0.value == 0xE0041 })
        XCTAssertTrue(md.contains("N/A"))

        let sessionNeg = ScanSession(
            findings: [],
            systemVersion: "iOS 27.3",
            scanDuration: -5.0,
            engineVersion: hostileVer
        )
        let txt = ReportGenerator.shared.generatePlainTextReport(session: sessionNeg)
        XCTAssertFalse(txt.unicodeScalars.contains { $0.value == 0x1B || $0.value == 0x202E || $0.value == 0xE0041 || $0.value == 0x0D })
        let txtEngLines = txt.components(separatedBy: "\n").filter { $0.contains("Engine Version") }
        XCTAssertEqual(txtEngLines.count, 1)
        XCTAssertTrue(txt.contains("Scan Duration: N/A") || txt.contains("Scan Duration         : N/A"))

        // Control-char DoS perf check (500 KB)
        let payload = String(repeating: "\u{001B}\u{202E}\u{E0100}", count: 60_000)
        let t0 = Date()
        let sanitized = ReportGenerator.shared.plain(payload)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 1.0)
        XCTAssertFalse(sanitized.unicodeScalars.contains { $0.value == 0x1B || $0.value == 0x202E || $0.value == 0xE0100 })

        // Preserved constants
        XCTAssertEqual(WQGuardCLIMetadata.version, "1.0.0")
        XCTAssertEqual(ScanSession(findings: []).engineVersion, "1.0.0")
    }

    // MARK: - 8. CLICommandRunner Ancestor Symlinks & Whitelist Isolation

    func test_cli_writeSafeCLIOutput_blocksAncestorSymlinksAndBadPaths() async throws {
        let base = try makeTempDir(prefix: "m3_cli_sym")
        let victimDir = base.appendingPathComponent("victim")
        let existingSub = victimDir.appendingPathComponent("existingSub")
        try FileManager.default.createDirectory(at: existingSub, withIntermediateDirectories: true)

        let symAncestor = base.appendingPathComponent("symAncestor")
        XCTAssertEqual(symlink(victimDir.path, symAncestor.path), 0)

        // 1. Existing symlinked ancestor + existing subdir
        let r1 = try await runCLIInProcess(["--firmware-radar", "26.2", "-o", symAncestor.appendingPathComponent("existingSub/out.json").path])
        XCTAssertEqual(r1.code, 2)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: existingSub.path).isEmpty)

        // 2. Surge export through symlinked ancestor
        let r2 = try await runCLIInProcess(["--export-surge", symAncestor.appendingPathComponent("existingSub/s.sgmodule").path])
        XCTAssertEqual(r2.code, 2)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: existingSub.path).isEmpty)

        // 3. Non-existent subdir under symlinked ancestor must fail and never create directory
        let r3 = try await runCLIInProcess(["--firmware-radar", "26.2", "-o", symAncestor.appendingPathComponent("new_sub/out.json").path])
        XCTAssertEqual(r3.code, 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: victimDir.appendingPathComponent("new_sub").path))

        // 4. `..` traversal through symlinked ancestor
        let r4 = try await runCLIInProcess(["--firmware-radar", "26.2", "-o", symAncestor.path + "/../other/out.json"])
        XCTAssertEqual(r4.code, 2)

        // 5. Trailing slash, empty path, NUL path, existing directory, pre-planted dest symlink
        let plantedSym = victimDir.appendingPathComponent("dest.json")
        XCTAssertEqual(symlink("/etc/hosts", plantedSym.path), 0)
        for badOut in ["", base.path + "/", existingSub.path, plantedSym.path, base.path + "/bad\0name.json"] {
            let rBad = try await runCLIInProcess(["--firmware-radar", "26.2", "-o", badOut])
            XCTAssertEqual(rBad.code, 2, "Bad output path \(badOut.debugDescription) must exit 2")
        }

        // 6. Regular temp dir overwrite succeeds
        let realOut = base.appendingPathComponent("valid_out.json")
        let ok1 = try await runCLIInProcess(["--firmware-radar", "27.3", "--format", "json", "-o", realOut.path])
        XCTAssertEqual(ok1.code, 0)
        let ok2 = try await runCLIInProcess(["--firmware-radar", "27.3", "--format", "json", "-o", realOut.path])
        XCTAssertEqual(ok2.code, 0)
        XCTAssertTrue(FileManager.default.fileExists(atPath: realOut.path))
    }

    func test_cli_isolatedWhitelist_neverMutatesShared_andBlocksMalformedIPA() async throws {
        let exploitEnts = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>com.apple.security.application-groups</key><array><string>group.com.m3.exploit</string></array>
        </dict></plist>
        """
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["_container_query_create"],
            xmlEntitlements: exploitEnts
        ))
        let ipaURL = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "M3ExploitApp",
            bundleIdentifier: "com.m3.exploit",
            executableBinary: bin,
            provisioningProfile: .developerSideloaded(teamId: "TEAM123456", devices: ["DEV1"])
        )))

        // 1. --whitelist downgrades exploit IPA in-run (exit 0) without mutating WhitelistEngine.shared
        let wlRes = try await runCLIInProcess(["--ipa", ipaURL.path, "--whitelist", "com.m3.exploit", "--format", "json"])
        XCTAssertEqual(wlRes.code, 0)
        XCTAssertNil(WhitelistEngine.shared.tool(named: "CLI-Whitelist-com.m3.exploit"))

        // 2. Without --whitelist, exploit IPA still exits 1
        let noWlRes = try await runCLIInProcess(["--ipa", ipaURL.path, "--format", "json"])
        XCTAssertEqual(noWlRes.code, 1)

        // 3. Zip-Slip / malformed IPA cannot be bypassed by --whitelist
        let badDir = try makeTempDir(prefix: "m3_zipslip")
        let badIPA = badDir.appendingPathComponent("slip.ipa")
        let zipData = constructSimpleZip(entries: [("Payload/App.app/../../evil.txt", Data("evil".utf8))])
        try zipData.write(to: badIPA)
        let badRes = try await runCLIInProcess(["--ipa", badIPA.path, "--whitelist", "com.m3.exploit"])
        XCTAssertNotEqual(badRes.code, 0)

        // 4. Symlink container target fails closed with exit code 2
        let symTarget = badDir.appendingPathComponent("sym_container")
        XCTAssertEqual(symlink("/etc", symTarget.path), 0)
        let symRes = try await runCLIInProcess(["--container", symTarget.path])
        XCTAssertEqual(symRes.code, 2)
    }

    private func constructSimpleZip(entries: [(String, Data)]) -> Data {
        var out = Data()
        var cd = Data()
        for (name, content) in entries {
            let nameData = Data(name.utf8)
            let offset = UInt32(out.count)
            // Local file header
            out.append(contentsOf: [0x50, 0x4b, 0x03, 0x04])
            out.append(contentsOf: [0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            out.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // CRC
            var sz = UInt32(content.count).littleEndian
            withUnsafeBytes(of: &sz) { out.append(contentsOf: $0); out.append(contentsOf: $0) }
            var nl = UInt16(nameData.count).littleEndian
            withUnsafeBytes(of: &nl) { out.append(contentsOf: $0) }
            out.append(contentsOf: [0x00, 0x00])
            out.append(nameData)
            out.append(content)

            // Central directory header
            cd.append(contentsOf: [0x50, 0x4b, 0x01, 0x02])
            cd.append(contentsOf: [0x14, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            cd.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
            withUnsafeBytes(of: &sz) { cd.append(contentsOf: $0); cd.append(contentsOf: $0) }
            withUnsafeBytes(of: &nl) { cd.append(contentsOf: $0) }
            cd.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            var offLE = offset.littleEndian
            withUnsafeBytes(of: &offLE) { cd.append(contentsOf: $0) }
            cd.append(nameData)
        }
        var cdOffset = UInt32(out.count).littleEndian
        var cdSize = UInt32(cd.count).littleEndian
        out.append(cd)
        out.append(contentsOf: [0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00])
        var cnt = UInt16(entries.count).littleEndian
        withUnsafeBytes(of: &cnt) { out.append(contentsOf: $0); out.append(contentsOf: $0) }
        withUnsafeBytes(of: &cdSize) { out.append(contentsOf: $0) }
        withUnsafeBytes(of: &cdOffset) { out.append(contentsOf: $0) }
        out.append(contentsOf: [0x00, 0x00])
        return out
    }
}
