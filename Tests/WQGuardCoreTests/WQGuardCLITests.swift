//
//  WQGuardCLITests.swift
//  WQGuardCoreTests
//
//  Unit and integration tests for wqguard-cli argument parser, error paths, and process execution.
//

import XCTest
import Foundation
@testable import WQGuardCore

final class WQGuardCLITests: XCTestCase {

    // MARK: - 1. Argument Parser Success Tests

    func testArgumentParser_HelpAndVersionFlags() throws {
        let helpShort = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-h"])
        XCTAssertTrue(helpShort.showHelp)

        let helpLong = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--help"])
        XCTAssertTrue(helpLong.showHelp)

        let verShort = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-v"])
        XCTAssertTrue(verShort.showVersion)

        let verLong = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--version"])
        XCTAssertTrue(verLong.showVersion)
    }

    func testArgumentParser_ScanSystemFlag() throws {
        let short = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-s"])
        XCTAssertTrue(short.scanSystem)

        let long = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--scan-system"])
        XCTAssertTrue(long.scanSystem)
    }

    func testArgumentParser_IPAPathVariations() throws {
        let spaceShort = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-i", "/path/to/app.ipa"])
        XCTAssertEqual(spaceShort.ipaPath, "/path/to/app.ipa")

        let spaceLong = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--ipa", "/path/to/app.ipa"])
        XCTAssertEqual(spaceLong.ipaPath, "/path/to/app.ipa")

        let eqShort = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-i=/path/to/app.ipa"])
        XCTAssertEqual(eqShort.ipaPath, "/path/to/app.ipa")

        let eqLong = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--ipa=/path/to/app.ipa"])
        XCTAssertEqual(eqLong.ipaPath, "/path/to/app.ipa")
    }

    func testArgumentParser_ContainerPathVariations() throws {
        let spaceShort = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-c", "/var/mobile/Containers/Shared/AppGroup/UUID"])
        XCTAssertEqual(spaceShort.containerPath, "/var/mobile/Containers/Shared/AppGroup/UUID")

        let spaceLong = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--container", "/var/mobile/Containers/Shared/AppGroup/UUID"])
        XCTAssertEqual(spaceLong.containerPath, "/var/mobile/Containers/Shared/AppGroup/UUID")

        let eqShort = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-c=/path/to/container"])
        XCTAssertEqual(eqShort.containerPath, "/path/to/container")

        let eqLong = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--container=/path/to/container"])
        XCTAssertEqual(eqLong.containerPath, "/path/to/container")
    }

    func testArgumentParser_FirmwareRadarVariations() throws {
        // Without version parameter
        let noVerShort = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-r"])
        XCTAssertTrue(noVerShort.firmwareRadar)
        XCTAssertNil(noVerShort.firmwareVersion)

        let noVerLong = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--firmware-radar"])
        XCTAssertTrue(noVerLong.firmwareRadar)
        XCTAssertNil(noVerLong.firmwareVersion)

        // Followed by another flag
        let followedByFlag = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-r", "-s"])
        XCTAssertTrue(followedByFlag.firmwareRadar)
        XCTAssertNil(followedByFlag.firmwareVersion)
        XCTAssertTrue(followedByFlag.scanSystem)

        // Space separated version
        let verShort = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-r", "26.2"])
        XCTAssertTrue(verShort.firmwareRadar)
        XCTAssertEqual(verShort.firmwareVersion, "26.2")

        let verLong = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--firmware-radar", "27.1"])
        XCTAssertTrue(verLong.firmwareRadar)
        XCTAssertEqual(verLong.firmwareVersion, "27.1")

        // Inline equals
        let eqShort = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-r=26.7.2"])
        XCTAssertTrue(eqShort.firmwareRadar)
        XCTAssertEqual(eqShort.firmwareVersion, "26.7.2")

        let eqLong = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--firmware-radar=27.2.1"])
        XCTAssertTrue(eqLong.firmwareRadar)
        XCTAssertEqual(eqLong.firmwareVersion, "27.2.1")
    }

    func testArgumentParser_ExportSurgeVariations() throws {
        let space = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--export-surge", "/tmp/shield.sgmodule"])
        XCTAssertEqual(space.exportSurgePath, "/tmp/shield.sgmodule")

        let eq = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--export-surge=/tmp/shield.sgmodule"])
        XCTAssertEqual(eq.exportSurgePath, "/tmp/shield.sgmodule")
    }

    func testArgumentParser_FormatAndOutAndWhitelist() throws {
        let parsed = try CLIArgumentParser.parse(arguments: [
            "wqguard-cli",
            "-s",
            "--format", "json",
            "-o", "/tmp/report.json",
            "--whitelist", "com.example.tool1",
            "--whitelist=com.example.tool2"
        ])

        XCTAssertTrue(parsed.scanSystem)
        XCTAssertEqual(parsed.format, .json)
        XCTAssertEqual(parsed.outPath, "/tmp/report.json")
        XCTAssertEqual(parsed.whitelistedBundleIDs, ["com.example.tool1", "com.example.tool2"])
    }

    func testArgumentParser_ScanSubcommandVariations() throws {
        let ipaScan = try CLIArgumentParser.parse(arguments: ["wqguard", "scan", "./build/WQGuard.ipa", "--format", "text"])
        XCTAssertEqual(ipaScan.ipaPath, "./build/WQGuard.ipa")
        XCTAssertEqual(ipaScan.format, .text)

        let systemScan = try CLIArgumentParser.parse(arguments: ["wqguard", "scan", "--format", "json"])
        XCTAssertTrue(systemScan.scanSystem)
        XCTAssertEqual(systemScan.format, .json)

        let containerScan = try CLIArgumentParser.parse(arguments: ["wqguard", "scan", "/var/mobile/Containers/Shared/AppGroup/UUID"])
        XCTAssertEqual(containerScan.containerPath, "/var/mobile/Containers/Shared/AppGroup/UUID")
    }

    // MARK: - 2. Argument Parser Error Tests

    func testArgumentParser_MissingActionThrows() {
        XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli"])) { error in
            XCTAssertEqual(error as? CLIError, CLIError.missingAction)
        }
    }

    func testArgumentParser_UnrecognizedOptionThrows() {
        XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--bogus-flag"])) { error in
            XCTAssertEqual(error as? CLIError, CLIError.unrecognizedOption("--bogus-flag"))
        }
    }

    func testArgumentParser_MissingArgumentThrows() {
        XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--ipa"])) { error in
            XCTAssertEqual(error as? CLIError, CLIError.missingArgument(option: "--ipa", expected: "<path>"))
        }

        XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-i"])) { error in
            XCTAssertEqual(error as? CLIError, CLIError.missingArgument(option: "-i", expected: "<path>"))
        }

        XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--format"])) { error in
            XCTAssertEqual(error as? CLIError, CLIError.missingArgument(option: "--format", expected: "<json|markdown|text>"))
        }
    }

    func testArgumentParser_InvalidFormatThrows() {
        XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-s", "--format", "yaml"])) { error in
            XCTAssertEqual(error as? CLIError, CLIError.invalidFormat("yaml"))
        }
    }

    // MARK: - 3. Process Execution Integration Tests

    private var cliBinaryURL: URL {
        let repoRoot = URL(fileURLWithPath: #file)
            .deletingLastPathComponent() // WQGuardCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repo root
        let bin = repoRoot.appendingPathComponent(".build/debug/wqguard-cli")
        if FileManager.default.fileExists(atPath: bin.path) {
            return bin
        }
        return repoRoot.appendingPathComponent(".build/out/Products/Debug/wqguard-cli")
    }

    private func runCLI(arguments: [String]) -> (output: String, error: String, exitCode: Int32) {
        let process = Process()
        process.executableURL = cliBinaryURL
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            process.waitUntilExit()

            let outData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            let errData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

            return (
                output: String(decoding: outData, as: UTF8.self),
                error: String(decoding: errData, as: UTF8.self),
                exitCode: process.terminationStatus
            )
        } catch {
            return ("", "Process launch failed: \(error)", -1)
        }
    }

    func testCLIProcess_VersionCheck() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let res = runCLI(arguments: ["--version"])
        XCTAssertEqual(res.exitCode, 0)
        XCTAssertTrue(res.output.contains("WQGuard v1.0.0"))
    }

    func testCLIProcess_HelpCheck() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let res = runCLI(arguments: ["--help"])
        XCTAssertEqual(res.exitCode, 0)
        XCTAssertTrue(res.output.contains("OVERVIEW: WQGuard CLI"))
        XCTAssertTrue(res.output.contains("EXIT CODES:"))
    }

    func testCLIProcess_InvalidFlagExitCode2() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let res = runCLI(arguments: ["--nonexistent-flag"])
        XCTAssertEqual(res.exitCode, 2)
        XCTAssertTrue(res.error.contains("unrecognized option"))
    }

    func testCLIProcess_ExportSurge() throws {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let tmpPath = NSTemporaryDirectory() + "cli-test-surge-\(UUID().uuidString).sgmodule"
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }

        let res = runCLI(arguments: ["--export-surge", tmpPath])
        XCTAssertEqual(res.exitCode, 0)
        XCTAssertTrue(res.error.contains("[+] Exported Surge shield"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: tmpPath))

        let content = try String(contentsOfFile: tmpPath, encoding: .utf8)
        let validation = SurgeBrotliShieldHelper.shared.validateModule(content: content)
        XCTAssertTrue(validation.isCompliant)
    }

    func testCLIProcess_FirmwareRadarEvaluation() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let res = runCLI(arguments: ["--firmware-radar", "26.2", "--format", "json"])
        // 26.2 is affected by worse_query 0day (HIGH_RISK), so exit code must be 1
        XCTAssertEqual(res.exitCode, 1)
        XCTAssertTrue(res.output.contains("\"overallRiskTier\" : \"HIGH_RISK\""))
        XCTAssertTrue(res.output.contains("0day:worse_query"))
    }
}
