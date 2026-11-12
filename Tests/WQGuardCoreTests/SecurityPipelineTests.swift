//
//  SecurityPipelineTests.swift
//  WQGuardCoreTests
//
//  Unit and integration tests for SecurityPipeline facade,
//  conformance to SecurityScannerEngineProtocol, asynchronous scanning,
//  and progress reporting.
//

import XCTest
@testable import WQGuardCore

final class SecurityPipelineTests: XCTestCase {

    var tempFiles: [URL] = []

    override func tearDown() {
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

    // MARK: - 1. Protocol Conformance

    func test_Pipeline_conformsToSecurityScannerEngineProtocol() {
        let pipeline: SecurityScannerEngineProtocol = SecurityPipeline.shared
        XCTAssertNotNil(pipeline)
    }

    // MARK: - 2. Scan Standalone Binary

    func test_Pipeline_scanBinary() throws {
        let binaryData = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
                symbols: ["_main"]
            )
        )
        let tempBinURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("test_bin_\(UUID().uuidString)"))
        try binaryData.write(to: tempBinURL)

        let finding = try SecurityPipeline.shared.scanBinary(at: tempBinURL)
        XCTAssertEqual(finding.riskTier, RiskTier.safe)
        XCTAssertEqual(finding.displayName, tempBinURL.lastPathComponent)
    }

    // MARK: - 3. Scan Application Bundle Directory

    func test_Pipeline_scanBundle() throws {
        let bundleURL = trackTempFile(FileManager.default.temporaryDirectory.appendingPathComponent("TestBundle_\(UUID().uuidString).app"))
        try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)

        let infoPlist: [String: Any] = [
            "CFBundleIdentifier": "com.test.bundleapp",
            "CFBundleDisplayName": "BundleApp",
            "CFBundleShortVersionString": "2.1.0",
            "CFBundleExecutable": "BundleApp"
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: infoPlist, format: .xml, options: 0)
        try plistData.write(to: bundleURL.appendingPathComponent("Info.plist"))

        let execBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                symbols: ["_main"]
            )
        )
        try execBinary.write(to: bundleURL.appendingPathComponent("BundleApp"))

        let finding = try SecurityPipeline.shared.scanBundle(at: bundleURL)
        XCTAssertEqual(finding.bundleId, "com.test.bundleapp")
        XCTAssertEqual(finding.displayName, "BundleApp")
        XCTAssertEqual(finding.version, "2.1.0")
        XCTAssertEqual(finding.riskTier, RiskTier.safe)
    }

    // MARK: - 4. Scan IPA Archive

    func test_Pipeline_scanIPA() throws {
        let appBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(arch: .arm64)
        )
        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "PipelineApp",
            bundleIdentifier: "com.pipeline.app",
            executableBinary: appBinary
        )
        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))

        let finding = try SecurityPipeline.shared.scanIPA(at: ipaURL)
        XCTAssertEqual(finding.bundleId, "com.pipeline.app")
        XCTAssertEqual(finding.riskTier, RiskTier.safe)
    }

    // MARK: - 5. Asynchronous Scanning & Progress Callbacks

    final class SafeEventCollector: @unchecked Sendable {
        private let lock = NSLock()
        var events: [ScanProgress] = []
        func append(_ p: ScanProgress) {
            lock.lock()
            defer { lock.unlock() }
            events.append(p)
        }
        func getEvents() -> [ScanProgress] {
            lock.lock()
            defer { lock.unlock() }
            return events
        }
    }

    func test_Pipeline_asyncProgressReporting() async throws {
        let appBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(arch: .arm64)
        )

        var ipaURLs: [URL] = []
        for i in 1...3 {
            let config = MockIPAGenerator.IPAPackageConfig(
                appName: "App\(i)",
                bundleIdentifier: "com.app.\(i)",
                executableBinary: appBinary
            )
            ipaURLs.append(trackTempFile(try MockIPAGenerator.shared.createIPA(config: config)))
        }

        let collector = SafeEventCollector()

        let session = try await SecurityPipeline.shared.createScanSessionAsync(targets: ipaURLs) { progress in
            collector.append(progress)
        }

        XCTAssertEqual(session.findings.count, 3)

        let events = collector.getEvents()
        XCTAssertEqual(events.count, 3)
        XCTAssertEqual(events.last?.completedCount, 3)
        XCTAssertEqual(events.last?.totalCount, 3)
        XCTAssertEqual(events.last?.fractionCompleted, 1.0)
    }

    // MARK: - 6. Thread Safety Under Concurrent Invocations

    func test_Pipeline_threadSafetyUnderConcurrentQueries() throws {
        let appBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(arch: .arm64)
        )
        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "ThreadApp",
            bundleIdentifier: "com.thread.app",
            executableBinary: appBinary
        )
        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))

        DispatchQueue.concurrentPerform(iterations: 20) { _ in
            do {
                let finding = try SecurityPipeline.shared.scanIPA(at: ipaURL)
                XCTAssertEqual(finding.bundleId, "com.thread.app")
            } catch {
                XCTFail("Concurrent scan failed with error: \(error)")
            }
        }
    }

    // MARK: - 7. Expanded Threat Catalog Wiring in IPA & Bundle Pipeline

    func test_Pipeline_impersonatedWalletIPA_flagsHighRisk() throws {
        let drainerBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
                symbols: ["_main", "_OBJC_CLASS_$_UIPasteboard"]
            )
        )
        let config = MockIPAGenerator.IPAPackageConfig(
            appName: "MetaMask",
            bundleIdentifier: "io.metamask.sideload.drainer",
            executableBinary: drainerBinary,
            provisioningProfile: .developerSideloaded(teamId: "SCAM999", devices: ["UUID-1"])
        )
        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: config))

        let finding = try SecurityPipeline.shared.scanIPA(at: ipaURL)
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })
    }

    func test_Pipeline_resignedErosionAppGroup_remainsKnownTool() throws {
        // Default shared engine does NOT built-in whitelist Erosion
        let defaultCheck = WhitelistEngine.shared.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion.XYZ987",
            appGroups: ["group.XYZ987.com.jbdotparty.Erosion"],
            matchedSignatures: ["container_query_create", "container_copy_sandbox_token"],
            teamId: "XYZ987"
        )
        XCTAssertFalse(defaultCheck.isWhitelisted)

        // Custom rule engine supports wildcard resigned App Groups
        let customEngine = WhitelistEngine(tools: TestWhitelistFixtures.allSampleRulesIncludingDefault)
        let wl = customEngine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion.XYZ987",
            appGroups: ["group.XYZ987.com.jbdotparty.Erosion"],
            matchedSignatures: ["container_query_create", "container_copy_sandbox_token"],
            teamId: "XYZ987"
        )
        XCTAssertTrue(wl.isWhitelisted)
        XCTAssertEqual(wl.toolName, "Erosion-CN")
    }
}
