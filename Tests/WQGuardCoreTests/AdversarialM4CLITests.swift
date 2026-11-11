//
//  AdversarialM4CLITests.swift
//  WQGuardCoreTests
//
//  Milestone 4 CLI Adversarial Challenger Test Suite:
//  1. Argument Fuzzing & Boundary Combinations (missing args, inline empty =, malformed flags, invalid formats)
//  2. Pipe Redirection & Stream Purity (JSON parseability, Markdown/Text cleanliness, zero ANSI leakage)
//  3. Exit Code Verification (0 for version/help/clean/whitelisted, 1 for 0day/exploit, 2 for syntax/IO errors)
//  4. Unicode, Spaces, and Special Characters in Paths
//  5. Terminal Styler & Non-TTY Suppression
//  6. Container Scanner Process & Direct Boundary Verification
//

import XCTest
import Foundation
import Darwin
@testable import WQGuardCore

final class AdversarialM4CLITests: XCTestCase {

    private var tempFiles: [URL] = []

    override func setUp() {
        super.setUp()
        WhitelistEngine.shared.resetToDefaults()
    }

    override func tearDown() {
        for url in tempFiles {
            _ = try? FileManager.default.removeItem(at: url)
        }
        tempFiles.removeAll()
        WhitelistEngine.shared.resetToDefaults()
        super.tearDown()
    }

    @discardableResult
    private func trackTempFile(_ url: URL) -> URL {
        tempFiles.append(url)
        return url
    }

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

    private func runCLI(arguments: [String], environment: [String: String]? = nil) -> (stdout: String, stderr: String, exitCode: Int32) {
        let process = Process()
        process.executableURL = cliBinaryURL
        process.arguments = arguments
        if let env = environment {
            var fullEnv = ProcessInfo.processInfo.environment
            for (k, v) in env {
                fullEnv[k] = v
            }
            process.environment = fullEnv
        }

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
                stdout: String(decoding: outData, as: UTF8.self),
                stderr: String(decoding: errData, as: UTF8.self),
                exitCode: process.terminationStatus
            )
        } catch {
            return ("", "Process launch failed: \(error)", -1)
        }
    }

    // MARK: - 1. Argument Fuzzing & Boundary Hardening

    func test_fuzz_missingActionThrows() {
        XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli"])) { error in
            XCTAssertEqual(error as? CLIError, CLIError.missingAction)
        }
    }

    func test_fuzz_missingArgumentsForOptions() {
        let missingCases: [([String], CLIError)] = [
            (["wqguard-cli", "--ipa"], .missingArgument(option: "--ipa", expected: "<path>")),
            (["wqguard-cli", "-i"], .missingArgument(option: "-i", expected: "<path>")),
            (["wqguard-cli", "--container"], .missingArgument(option: "--container", expected: "<path>")),
            (["wqguard-cli", "-c"], .missingArgument(option: "-c", expected: "<path>")),
            (["wqguard-cli", "--export-surge"], .missingArgument(option: "--export-surge", expected: "<path>")),
            (["wqguard-cli", "--format"], .missingArgument(option: "--format", expected: "<json|markdown|text>")),
            (["wqguard-cli", "-o"], .missingArgument(option: "-o", expected: "<path>")),
            (["wqguard-cli", "--out"], .missingArgument(option: "--out", expected: "<path>")),
            (["wqguard-cli", "--whitelist"], .missingArgument(option: "--whitelist", expected: "<bundleID>")),
        ]

        for (args, expectedErr) in missingCases {
            XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: args), "Args \(args) should throw \(expectedErr)") { err in
                XCTAssertEqual(err as? CLIError, expectedErr)
            }
        }
    }

    func test_fuzz_nextArgIsFlag_treatedAsMissingArgument() {
        // e.g. wqguard-cli --ipa --format json -> --ipa missing argument because next token is a flag
        XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli", "--ipa", "--format", "json"])) { err in
            XCTAssertEqual(err as? CLIError, CLIError.missingArgument(option: "--ipa", expected: "<path>"))
        }

        XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-c", "-s"])) { err in
            XCTAssertEqual(err as? CLIError, CLIError.missingArgument(option: "-c", expected: "<path>"))
        }

        XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-o", "-v"])) { err in
            XCTAssertEqual(err as? CLIError, CLIError.missingArgument(option: "-o", expected: "<path>"))
        }
    }

    func test_fuzz_inlineEmptyEquals() {
        let emptyCases: [([String], CLIError)] = [
            (["wqguard-cli", "--ipa="], .missingArgument(option: "--ipa", expected: "<path>")),
            (["wqguard-cli", "-i="], .missingArgument(option: "-i", expected: "<path>")),
            (["wqguard-cli", "--container="], .missingArgument(option: "--container", expected: "<path>")),
            (["wqguard-cli", "-c="], .missingArgument(option: "-c", expected: "<path>")),
            (["wqguard-cli", "--export-surge="], .missingArgument(option: "--export-surge", expected: "<path>")),
            (["wqguard-cli", "-o="], .missingArgument(option: "-o", expected: "<path>")),
            (["wqguard-cli", "--out="], .missingArgument(option: "--out", expected: "<path>")),
            (["wqguard-cli", "--whitelist="], .missingArgument(option: "--whitelist", expected: "<bundleID>")),
        ]

        for (args, expectedErr) in emptyCases {
            XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: args), "Args \(args) should throw \(expectedErr)") { err in
                XCTAssertEqual(err as? CLIError, expectedErr)
            }
        }
    }

    func test_fuzz_malformedAndUnknownFlags() {
        let malformed = [
            "--foo",
            "-xyz",
            "---help",
            "----version",
            "--scan_system",
            "--IPA",
            "--Surge",
            "-?",
            "/some/bare/path"
        ]

        for flag in malformed {
            XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli", flag])) { err in
                XCTAssertEqual(err as? CLIError, CLIError.unrecognizedOption(flag))
            }
        }
    }

    func test_fuzz_formatParsingCaseInsensitive() throws {
        let formats: [(String, OutputFormat)] = [
            ("json", .json),
            ("JSON", .json),
            ("Json", .json),
            ("markdown", .markdown),
            ("MARKDOWN", .markdown),
            ("md", .markdown),
            ("MD", .markdown),
            ("text", .text),
            ("TEXT", .text),
            ("txt", .text),
            ("TXT", .text)
        ]

        for (str, expectedFmt) in formats {
            let parsed = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-s", "--format", str])
            XCTAssertEqual(parsed.format, expectedFmt, "Format string '\(str)' should parse to \(expectedFmt)")

            let parsedEq = try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-s", "--format=\(str)"])
            XCTAssertEqual(parsedEq.format, expectedFmt, "Format string '--format=\(str)' should parse to \(expectedFmt)")
        }

        // Invalid formats
        let invalid = ["yaml", "xml", "csv", "html", "bin", ""]
        for bad in invalid {
            XCTAssertThrowsError(try CLIArgumentParser.parse(arguments: ["wqguard-cli", "-s", "--format", bad])) { err in
                XCTAssertEqual(err as? CLIError, CLIError.invalidFormat(bad))
            }
        }
    }

    func test_fuzz_multipleWhitelistAccumulation() throws {
        let parsed = try CLIArgumentParser.parse(arguments: [
            "wqguard-cli",
            "-s",
            "--whitelist", "com.tool.one",
            "--whitelist=com.tool.two",
            "--whitelist", "com.tool.three"
        ])
        XCTAssertEqual(parsed.whitelistedBundleIDs, ["com.tool.one", "com.tool.two", "com.tool.three"])
    }

    // MARK: - 2. Process Execution & Stream Purity

    func test_process_versionStreamPurity() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let res = runCLI(arguments: ["--version"])
        XCTAssertEqual(res.exitCode, 0)
        XCTAssertTrue(res.stdout.contains("WQGuard v1.0.0"))
        XCTAssertTrue(res.stderr.isEmpty, "Stderr should be empty on --version")
        XCTAssertFalse(res.stdout.contains("\u{001B}"), "Stdout must not contain ANSI escape codes")
    }

    func test_process_helpStreamPurity() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let res = runCLI(arguments: ["--help"])
        XCTAssertEqual(res.exitCode, 0)
        XCTAssertTrue(res.stdout.contains("OVERVIEW: WQGuard CLI"))
        XCTAssertTrue(res.stdout.contains("EXIT CODES:"))
        XCTAssertTrue(res.stderr.isEmpty, "Stderr should be empty on --help")
        XCTAssertFalse(res.stdout.contains("\u{001B}"), "Stdout must not contain ANSI escape codes when redirected to pipe")
    }

    func test_process_firmwareRadarJSONPurity() throws {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let res = runCLI(arguments: ["--firmware-radar", "26.2", "--format", "json"])
        XCTAssertEqual(res.exitCode, 1, "iOS 26.2 has worse_query 0day, exit code must be 1")
        XCTAssertTrue(res.stderr.isEmpty, "Stderr must be empty during firmware radar evaluation")
        XCTAssertFalse(res.stdout.contains("\u{001B}"), "JSON stdout must have no ANSI escape codes")

        // Parse JSON strictly to ensure pure parseability
        guard let data = res.stdout.data(using: .utf8) else {
            XCTFail("Stdout data could not be converted to UTF8")
            return
        }

        let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        XCTAssertNotNil(json)
        XCTAssertEqual(json?["overallRiskTier"] as? String, "HIGH_RISK")
        XCTAssertEqual(json?["totalEvaluated"] as? Int, 8)
        let exposed = json?["exposedVulnerabilities"] as? [[String: Any]]
        XCTAssertNotNil(exposed)
        XCTAssertTrue(exposed?.contains { ($0["cveId"] as? String) == "0day:worse_query" } == true)
    }

    func test_process_firmwareRadarMarkdownPurity() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let res = runCLI(arguments: ["--firmware-radar", "26.2", "--format", "markdown"])
        XCTAssertEqual(res.exitCode, 1)
        XCTAssertTrue(res.stdout.hasPrefix("# WQGuard Firmware CVE Exposure Radar Report"))
        XCTAssertTrue(res.stdout.contains("| CVE ID | Name | Subsystem | Severity | Status |"))
        XCTAssertTrue(res.stdout.contains("`0day:worse_query`"))
        XCTAssertFalse(res.stdout.contains("\u{001B}"), "Markdown stdout must have no ANSI escape codes")
    }

    func test_process_firmwareRadarTextPurity() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let res = runCLI(arguments: ["--firmware-radar", "26.2", "--format", "text"])
        XCTAssertEqual(res.exitCode, 1)
        XCTAssertTrue(res.stdout.contains("WQGuard Firmware CVE Exposure Radar"))
        XCTAssertTrue(res.stdout.contains("Target OS: 26.2"))
        XCTAssertFalse(res.stdout.contains("\u{001B}"), "Text stdout must have no ANSI escape codes when piped")
    }

    func test_process_firmwareRadarInvalidOSVersionExitCode2() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }
        let res = runCLI(arguments: ["--firmware-radar", "invalid-version-string"])
        XCTAssertEqual(res.exitCode, 2)
        XCTAssertTrue(res.stderr.contains("invalid OS version string"))
        XCTAssertTrue(res.stdout.isEmpty)
    }

    // MARK: - 3. Clean State & IPA Scanning Exit Codes

    func test_process_cleanIPAScanYieldsExitCode0AndPureJSON() throws {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }

        // Construct clean synthetic IPA
        let cleanBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
                symbols: ["_main"]
            )
        )
        let ipaConfig = MockIPAGenerator.IPAPackageConfig(
            appName: "AdversarialCleanApp",
            bundleIdentifier: "com.adversarial.clean",
            executableBinary: cleanBinary,
            provisioningProfile: .developerSideloaded(teamId: "TEAMCLEAN", devices: ["DEV1"])
        )
        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: ipaConfig))

        let res = runCLI(arguments: ["--ipa", ipaURL.path, "--format", "json"])
        XCTAssertEqual(res.exitCode, 0, "Clean IPA without high-risk indicators must yield exit code 0")
        XCTAssertFalse(res.stdout.contains("\u{001B}"))

        guard let data = res.stdout.data(using: .utf8) else {
            XCTFail("Clean IPA stdout could not be parsed as UTF8")
            return
        }
        let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        XCTAssertNotNil(json)
        XCTAssertEqual(json?["overallPosture"] as? String, "SAFE")
        let breakdown = json?["riskBreakdown"] as? [String: Any]
        XCTAssertEqual(breakdown?["HIGH_RISK"] as? Int, 0)
        XCTAssertEqual(breakdown?["SAFE"] as? Int, 1)
    }

    func test_process_exploitIPAScanYieldsExitCode1() throws {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }

        // Construct high-risk exploit IPA with App Group + containermanagerd symbols
        let exploitEntitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.adversarial.exploit</string>
            </array>
        </dict>
        </plist>
        """

        let exploitBinary = SyntheticMachOGenerator.shared.generateThin(
            config: SyntheticMachOGenerator.MachOConfig(
                arch: .arm64,
                cryptid: 0,
                linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
                symbols: ["_container_query_create", "_sandbox_extension_consume"],
                xmlEntitlements: exploitEntitlements
            )
        )
        let ipaConfig = MockIPAGenerator.IPAPackageConfig(
            appName: "ExploitApp",
            bundleIdentifier: "com.adversarial.exploit",
            executableBinary: exploitBinary,
            provisioningProfile: .developerSideloaded(teamId: "EVIL123", devices: ["DEV1"])
        )
        let ipaURL = trackTempFile(try MockIPAGenerator.shared.createIPA(config: ipaConfig))

        // 1. Without whitelist -> Exit code 1
        let resNoWhitelist = runCLI(arguments: ["--ipa", ipaURL.path, "--format", "json"])
        XCTAssertEqual(resNoWhitelist.exitCode, 1, "Unwhitelisted exploit IPA must exit with code 1")

        // 2. With whitelist -> Exit code 0
        let resWhitelisted = runCLI(arguments: [
            "--ipa", ipaURL.path,
            "--whitelist", "com.adversarial.exploit",
            "--format", "json"
        ])
        XCTAssertEqual(resWhitelisted.exitCode, 0, "Whitelisted tool must exit with code 0")
    }

    // MARK: - 4. Unicode, Spaces, and Special Characters in Paths

    func test_process_unicodeSpacesAndEmojiInPaths() throws {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }

        let tmpBase = FileManager.default.temporaryDirectory
            .appendingPathComponent("测试 目录 (Test & Dir) 🛡️ [M4]")
        try FileManager.default.createDirectory(at: tmpBase, withIntermediateDirectories: true)
        trackTempFile(tmpBase)

        let outReportURL = tmpBase.appendingPathComponent("审计 报告 · 2026.json")
        let surgeExportURL = tmpBase.appendingPathComponent("护盾 模块 · Brotli.sgmodule")

        // 1. Export Surge to Unicode path with spaces
        let surgeRes = runCLI(arguments: ["--export-surge", surgeExportURL.path])
        XCTAssertEqual(surgeRes.exitCode, 0)
        XCTAssertTrue(FileManager.default.fileExists(atPath: surgeExportURL.path))
        let surgeContent = try String(contentsOf: surgeExportURL, encoding: .utf8)
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateModule(content: surgeContent).isCompliant)

        // 2. Write JSON report to Unicode path with spaces via -o
        let outRes = runCLI(arguments: [
            "--firmware-radar", "26.2",
            "--format", "json",
            "-o", outReportURL.path
        ])
        XCTAssertEqual(outRes.exitCode, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: outReportURL.path))

        let reportData = try Data(contentsOf: outReportURL)
        let json = try JSONSerialization.jsonObject(with: reportData, options: []) as? [String: Any]
        XCTAssertNotNil(json)
        XCTAssertEqual(json?["overallRiskTier"] as? String, "HIGH_RISK")
    }

    // MARK: - 5. Terminal Styler Non-TTY & Environment Suppression

    func test_terminalStyler_nonTTYSuppressesColors() {
        // Create pipe file descriptor (isatty == 0)
        let pipe = Pipe()
        let styler = TerminalStyler(fileDescriptor: pipe.fileHandleForWriting.fileDescriptor)
        XCTAssertFalse(styler.isTTY)
        XCTAssertFalse(styler.supportsColor)

        let redText = styler.red("ERROR")
        XCTAssertEqual(redText, "ERROR", "When non-TTY, colors must not inject ANSI codes")
        let boldText = styler.bold("HEADER")
        XCTAssertEqual(boldText, "HEADER")
    }

    // MARK: - 6. Container Scanner Process & Direct Boundary Verification

    func test_process_containerEscapingSymlinkInParentDirectory() throws {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }

        let parentDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("m4_test_parent_containers_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
        trackTempFile(parentDir)

        let containerDir = parentDir.appendingPathComponent("UUID-CONTAINER-1")
        let cachesDir = containerDir.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: cachesDir, withIntermediateDirectories: true)

        let symlinkURL = cachesDir.appendingPathComponent("leak_passwd")
        symlink("/etc/passwd", symlinkURL.path)

        let res = runCLI(arguments: ["--container", parentDir.path, "--format", "json"])
        XCTAssertEqual(res.exitCode, 1, "Container with escaping symlink inside parent directory must exit with code 1")

        guard let data = res.stdout.data(using: .utf8) else {
            XCTFail("Container JSON output not UTF8")
            return
        }
        let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        XCTAssertNotNil(json)
        XCTAssertEqual(json?["overallPosture"] as? String, "HIGH_RISK")
    }

    func test_direct_containerScannerDirectScanIdentifiesEscapingSymlink() throws {
        // Direct engine verification of ContainerScanner.scanContainer(at:)
        let singleContainer = FileManager.default.temporaryDirectory
            .appendingPathComponent("m4_single_container_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: singleContainer, withIntermediateDirectories: true)
        trackTempFile(singleContainer)

        let cachesDir = singleContainer.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: cachesDir, withIntermediateDirectories: true)

        let symlinkURL = cachesDir.appendingPathComponent("leak_passwd")
        symlink("/etc/passwd", symlinkURL.path)

        let result = try ContainerScanner.shared.scanContainer(at: singleContainer)
        XCTAssertFalse(result.isClean)
        XCTAssertEqual(result.escapingSymlinks.count, 1)
        XCTAssertTrue(result.indicators.contains { $0.severity == .highRisk })
    }

    // MARK: - 7. Nonexistent & Unwritable Path Defenses

    func test_process_nonexistentFilesYieldExitCode2() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }

        let resIPA = runCLI(arguments: ["--ipa", "/nonexistent/path/to/missing.ipa"])
        XCTAssertEqual(resIPA.exitCode, 2)
        XCTAssertTrue(resIPA.stderr.contains("target file or directory not found"))

        let resContainer = runCLI(arguments: ["--container", "/nonexistent/missing/container"])
        XCTAssertEqual(resContainer.exitCode, 2)
        XCTAssertTrue(resContainer.stderr.contains("target file or directory not found"))
    }

    func test_process_unwritableOutputPathYieldExitCode2() {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }

        let resOut = runCLI(arguments: ["--firmware-radar", "26.2", "-o", "/dev/null/forbidden/report.txt"])
        XCTAssertEqual(resOut.exitCode, 2)
        XCTAssertTrue(resOut.stderr.contains("failed to write output file"))

        let resSurge = runCLI(arguments: ["--export-surge", "/dev/null/forbidden/shield.sgmodule"])
        XCTAssertEqual(resSurge.exitCode, 2)
        XCTAssertTrue(resSurge.stderr.contains("failed to export Surge shield"))
    }

    func test_process_containerEscapingSymlinkInDirectSingleContainerPath() throws {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }

        let singleContainer = FileManager.default.temporaryDirectory
            .appendingPathComponent("m4_test_single_container_\(UUID().uuidString)")
        let cachesDir = singleContainer.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: cachesDir, withIntermediateDirectories: true)
        trackTempFile(singleContainer)

        let symlinkURL = cachesDir.appendingPathComponent("leak_passwd")
        symlink("/etc/passwd", symlinkURL.path)

        // Passing the direct container URL (containing Library/Caches) must be recognized as a single container
        let res = runCLI(arguments: ["--container", singleContainer.path, "--format", "json"])
        XCTAssertEqual(res.exitCode, 1, "Direct single container path with escaping symlink must exit with code 1")

        guard let data = res.stdout.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
            XCTFail("Failed to parse container scan JSON")
            return
        }
        XCTAssertEqual(json["overallPosture"] as? String, "HIGH_RISK")
    }

    func test_process_cleanSingleContainerPath() throws {
        guard FileManager.default.fileExists(atPath: cliBinaryURL.path) else { return }

        let cleanContainer = FileManager.default.temporaryDirectory
            .appendingPathComponent("m4_test_clean_container_\(UUID().uuidString)")
        let cachesDir = cleanContainer.appendingPathComponent("Library/Caches")
        try FileManager.default.createDirectory(at: cachesDir, withIntermediateDirectories: true)
        trackTempFile(cleanContainer)

        let res = runCLI(arguments: ["--container", cleanContainer.path, "--format", "json"])
        XCTAssertEqual(res.exitCode, 0, "Clean single container path must exit with code 0")

        guard let data = res.stdout.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
            XCTFail("Failed to parse container scan JSON")
            return
        }
        XCTAssertEqual(json["overallPosture"] as? String, "SAFE")
    }
}
