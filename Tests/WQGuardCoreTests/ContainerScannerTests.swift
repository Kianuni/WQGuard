//
//  ContainerScannerTests.swift
//  WQGuardCoreTests
//
//  Unit tests for Layer 3 ContainerScanner, symlink escaping checks,
//  and ScopedSandboxToken RAII cleanup.
//

import XCTest
import Darwin
@testable import WQGuardCore

final class ContainerScannerTests: XCTestCase {

    var mockTree: MockContainerTree!

    override func setUp() {
        super.setUp()
        mockTree = MockContainerTree()
    }

    override func tearDown() {
        mockTree?.cleanUp()
        mockTree = nil
        super.tearDown()
    }

    // MARK: - 1. Escaping Caches Symlink

    func testContainerScanner_detectsLibraryCachesSymlink() throws {
        // Create container where Library/Caches itself is a symlink pointing outside (e.g. to /etc/hosts)
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.malicious.escape",
            containerUUID: UUID().uuidString,
            createMetadataPlist: true,
            createCachesDirectory: false
        )
        let containerURL = try mockTree.createContainer(config: config)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: cachesURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        symlink("/etc/hosts", cachesURL.path)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertEqual(result.escapingSymlinks.count, 1)
        XCTAssertEqual(result.escapingSymlinks.first, cachesURL.path)
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_CACHES_SYMLINK" })
        XCTAssertEqual(result.indicators.first?.severity, .highRisk)
    }

    // MARK: - 2. Escaping Symlink Inside Caches

    func testContainerScanner_detectsChildEscapingSymlink() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.child.escape",
            containerUUID: UUID().uuidString,
            createMetadataPlist: true,
            createCachesDirectory: true,
            escapingSymlinks: ["passwd_leak": "/etc/passwd"]
        )
        let containerURL = try mockTree.createContainer(config: config)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertFalse(result.isClean)
        XCTAssertEqual(result.escapingSymlinks.count, 1)
        XCTAssertTrue(result.indicators.contains { $0.signature == "CONTAINER_ESCAPING_SYMLINK" })
        XCTAssertEqual(result.indicators.first?.severity, .highRisk)
    }

    // MARK: - 3. Benign Internal Symlinks

    func testContainerScanner_benignInternalSymlink_clean() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.benign.app",
            containerUUID: UUID().uuidString,
            createMetadataPlist: true,
            createCachesDirectory: true,
            regularFiles: ["Library/Caches/SubCache/data.bin": Data("cached data".utf8)]
        )
        let containerURL = try mockTree.createContainer(config: config)
        let linkURL = containerURL.appendingPathComponent("Library/Caches/local_cache")
        symlink("SubCache", linkURL.path)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertTrue(result.isClean)
        XCTAssertTrue(result.escapingSymlinks.isEmpty)
        XCTAssertTrue(result.indicators.isEmpty)
    }

    // MARK: - 4. 100% Read-Only Assertion

    func testContainerScanner_readOnlyAssertion() throws {
        let config = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.readonly.app",
            containerUUID: UUID().uuidString,
            createMetadataPlist: true,
            createCachesDirectory: true,
            regularFiles: ["Library/Caches/cache.db": Data("read only verify".utf8)]
        )
        let containerURL = try mockTree.createContainer(config: config)

        try ReadOnlyAssertions.verifyReadOnlyExecution(targetURLs: [containerURL]) {
            let result = try ContainerScanner.shared.scanContainer(at: containerURL)
            XCTAssertTrue(result.isClean)
        }
    }

    // MARK: - 5. Batch App Group Containers Scanning

    func testContainerScanner_scanAppGroupContainers_multipleContainers() throws {
        let cleanConfig = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.clean.app",
            containerUUID: UUID().uuidString,
            createMetadataPlist: true,
            createCachesDirectory: true
        )
        _ = try mockTree.createContainer(config: cleanConfig)

        let exploitConfig = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.exploit.app",
            containerUUID: UUID().uuidString,
            createMetadataPlist: true,
            createCachesDirectory: true,
            escapingSymlinks: ["steal": "/var/mobile"]
        )
        _ = try mockTree.createContainer(config: exploitConfig)

        let batchResults = try ContainerScanner.shared.scanAppGroupContainers(at: mockTree.rootDirectoryURL)
        XCTAssertEqual(batchResults.count, 2)
        let dirty = batchResults.filter { !$0.isClean }
        XCTAssertEqual(dirty.count, 1)
        XCTAssertEqual(dirty.first?.metadata?.identifier, "group.com.exploit.app")
    }

    // MARK: - 6. Fake Supervision Detection

    func testContainerScanner_fakeSupervisionDetection() throws {
        let containerURL = mockTree.rootDirectoryURL.appendingPathComponent("systemgroup.com.apple.configurationprofiles")
        let cloudConfigDir = containerURL.appendingPathComponent("Library/ConfigurationProfiles")
        try FileManager.default.createDirectory(at: cloudConfigDir, withIntermediateDirectories: true)

        let metaURL = containerURL.appendingPathComponent(".com.apple.mobile_container_manager.metadata.plist")
        let metaDict: [String: Any] = [
            "MCMMetadataIdentifier": "systemgroup.com.apple.configurationprofiles",
            "MCMMetadataUUID": UUID().uuidString,
            "MCMMetadataClass": 12,
            "MCMMetadataVersion": 1
        ]
        let metaData = try PropertyListSerialization.data(fromPropertyList: metaDict, format: .xml, options: 0)
        try metaData.write(to: metaURL)

        let cloudConfigURL = cloudConfigDir.appendingPathComponent("CloudConfigurationDetails.plist")
        let cloudDict: [String: Any] = ["IsSupervised": true]
        let cloudData = try PropertyListSerialization.data(fromPropertyList: cloudDict, format: .xml, options: 0)
        try cloudData.write(to: cloudConfigURL)

        let result = try ContainerScanner.shared.scanContainer(at: containerURL)
        XCTAssertTrue(result.indicators.contains { $0.signature == "SYSTEMGROUP_SUPERVISION_DETECTED" })
        XCTAssertEqual(result.indicators.first?.severity, .highRisk)
    }

    // MARK: - 7. ScopedSandboxToken RAII Cleanup

    func testScopedSandboxToken_release() {
        let token = ScopedSandboxToken(handle: 42)
        XCTAssertEqual(token.handle, 42)
        token.release() // Should not crash
        token.release() // Idempotent
    }

    // MARK: - 8. Anomalous Metadata Diagnostics

    func testContainerScanner_anomalousMetadataDiagnostics() throws {
        // 1. Empty metadata file
        let emptyConfig = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.anomalous.empty",
            containerUUID: UUID().uuidString,
            createMetadataPlist: false,
            createCachesDirectory: true
        )
        let emptyContainer = try mockTree.createContainer(config: emptyConfig)
        let emptyMetaFile = emptyContainer.appendingPathComponent(MCMReader.metadataFilename)
        try Data().write(to: emptyMetaFile)

        let emptyResult = try ContainerScanner.shared.scanContainer(at: emptyContainer)
        XCTAssertTrue(emptyResult.indicators.contains { $0.signature == "CONTAINER_METADATA_EMPTY" && $0.severity == .caution })

        // 2. Invalid UUID metadata
        let badUUIDConfig = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.anomalous.baduuid",
            containerUUID: UUID().uuidString,
            createMetadataPlist: false,
            createCachesDirectory: true
        )
        let badUUIDContainer = try mockTree.createContainer(config: badUUIDConfig)
        let badUUIDMetaFile = badUUIDContainer.appendingPathComponent(MCMReader.metadataFilename)
        let badDict: [String: Any] = [
            "MCMMetadataIdentifier": "group.com.anomalous.baduuid",
            "MCMMetadataUUID": "NOT-A-REAL-UUID",
            "MCMMetadataClass": 7
        ]
        let badData = try PropertyListSerialization.data(fromPropertyList: badDict, format: .xml, options: 0)
        try badData.write(to: badUUIDMetaFile)

        let badUUIDResult = try ContainerScanner.shared.scanContainer(at: badUUIDContainer)
        XCTAssertTrue(badUUIDResult.indicators.contains { $0.signature == "CONTAINER_METADATA_INVALID_UUID" && $0.severity == .caution })

        // 3. Missing required key metadata
        let missingKeyConfig = MockContainerTree.ContainerConfig(
            appGroupId: "group.com.anomalous.missingkey",
            containerUUID: UUID().uuidString,
            createMetadataPlist: false,
            createCachesDirectory: true
        )
        let missingKeyContainer = try mockTree.createContainer(config: missingKeyConfig)
        let missingKeyMetaFile = missingKeyContainer.appendingPathComponent(MCMReader.metadataFilename)
        let missingDict: [String: Any] = [
            "MCMMetadataUUID": UUID().uuidString
            // Missing MCMMetadataIdentifier and MCMMetadataClass
        ]
        let missingData = try PropertyListSerialization.data(fromPropertyList: missingDict, format: .xml, options: 0)
        try missingData.write(to: missingKeyMetaFile)

        let missingKeyResult = try ContainerScanner.shared.scanContainer(at: missingKeyContainer)
        XCTAssertTrue(missingKeyResult.indicators.contains { $0.signature == "CONTAINER_METADATA_MISSING_KEY" && $0.severity == .caution })
    }
}

