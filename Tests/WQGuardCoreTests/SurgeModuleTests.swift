//
//  SurgeModuleTests.swift
//  WQGuardCoreTests
//
//  Unit tests for the 5-client Brotli Downgrade Shield Matrix (Surge, Shadowrocket,
//  Quantumult X, Loon, Stash), Shields/scripts/brotli-guard.js, SurgeBrotliShieldHelper,
//  and wqguard-cli --export-shield.
//

import XCTest
@testable import WQGuardCore

final class SurgeModuleTests: XCTestCase {

    private var repoRoot: URL {
        URL(fileURLWithPath: #file)
            .deletingLastPathComponent() // WQGuardCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // WQGuard
    }

    // MARK: - 1. Physical Repository Shield Files Compliance

    func testModuleFileContentCompliance() throws {
        let moduleURL = repoRoot.appendingPathComponent("Surge/WQGuard-Brotli-Shield.sgmodule")

        XCTAssertTrue(FileManager.default.fileExists(atPath: moduleURL.path), "Surge/WQGuard-Brotli-Shield.sgmodule must exist in repository root")

        let content = try String(contentsOf: moduleURL, encoding: .utf8)
        let validation = SurgeBrotliShieldHelper.shared.validateModule(content: content)

        XCTAssertTrue(validation.isCompliant, "Module must be 100% compliant: \(validation.errors)")
        XCTAssertTrue(validation.hasValidMetadata)
        XCTAssertTrue(validation.hasHeaderRewrite)
        XCTAssertTrue(validation.hasScriptGuard)
        XCTAssertTrue(validation.missingExclusions.isEmpty)

        // Ensure Shields/Surge/WQGuard-Brotli-Shield.sgmodule stays in sync with Surge/WQGuard-Brotli-Shield.sgmodule
        let shieldsSurgeURL = repoRoot.appendingPathComponent("Shields/Surge/WQGuard-Brotli-Shield.sgmodule")
        let shieldsSurgeContent = try String(contentsOf: shieldsSurgeURL, encoding: .utf8)
        XCTAssertEqual(
            content.trimmingCharacters(in: .whitespacesAndNewlines),
            shieldsSurgeContent.trimmingCharacters(in: .whitespacesAndNewlines),
            "Legacy Surge path and Shields/Surge path must remain identical"
        )
    }

    func testAllFivePhysicalShieldFilesAndGuardScriptCompliance() throws {
        let matrix: [(ProxyShieldPlatform, String)] = [
            (.surge, "Shields/Surge/WQGuard-Brotli-Shield.sgmodule"),
            (.shadowrocket, "Shields/Shadowrocket/WQGuard-Brotli-Shield.module"),
            (.quantumultX, "Shields/QuantumultX/WQGuard-Brotli-Shield.conf"),
            (.loon, "Shields/Loon/WQGuard-Brotli-Shield.plugin"),
            (.stash, "Shields/Stash/WQGuard-Brotli-Shield.stoverride")
        ]

        for (platform, relPath) in matrix {
            let fileURL = repoRoot.appendingPathComponent(relPath)
            XCTAssertTrue(FileManager.default.fileExists(atPath: fileURL.path), "Missing physical shield file: \(relPath)")
            let content = try String(contentsOf: fileURL, encoding: .utf8)
            let validation = SurgeBrotliShieldHelper.shared.validateShield(content: content, for: platform)
            XCTAssertTrue(validation.isCompliant, "\(platform.shortTitleEn) physical file failed compliance: \(validation.errors)")
            XCTAssertTrue(validation.missingExclusions.isEmpty)
        }

        let scriptURL = repoRoot.appendingPathComponent("Shields/scripts/brotli-guard.js")
        XCTAssertTrue(FileManager.default.fileExists(atPath: scriptURL.path), "Shields/scripts/brotli-guard.js must exist")
        let scriptContent = try String(contentsOf: scriptURL, encoding: .utf8)
        XCTAssertTrue(scriptContent.contains("Content-Encoding"))
        XCTAssertTrue(scriptContent.contains("HTTP/1.1 403 Forbidden"), "Guard script must support Quantumult X $task status format")
        XCTAssertTrue(scriptContent.contains("status: 403"), "Guard script must support Surge/Shadowrocket/Loon/Stash response status format")
    }

    // MARK: - 2. All 16 Negative MITM Exclusions Verified Across All 5 Generators

    func testAll16NegativeExclusionsPresent() {
        let expectedExclusions = [
            "-*.apple.com",
            "-*.icloud.com",
            "-*.icloud-content.com",
            "-*.mzstatic.com",
            "-*.cdn-apple.com",
            "-guzzoni.apple.com",
            "-*.siri.apple.com",
            "-gspe1-ssl.ls.apple.com",
            "-apple-relay.*",
            "-cp4.cloudflare.com",
            "-*.openai.com",
            "-*.chatgpt.com",
            "-*.binance.com",
            "-*.okx.com",
            "-*.tenpay.com",
            "-*.alipay.com"
        ]

        for platform in ProxyShieldPlatform.allCases {
            let generated = SurgeBrotliShieldHelper.shared.generateShieldContent(for: platform)
            let validation = SurgeBrotliShieldHelper.shared.validateShield(content: generated, for: platform)
            XCTAssertTrue(validation.isCompliant, "\(platform.shortTitleEn) generated shield must be compliant: \(validation.errors)")
            for exclusion in expectedExclusions {
                XCTAssertTrue(generated.contains(exclusion), "\(platform.shortTitleEn) must contain negative exclusion: \(exclusion)")
            }
        }
    }

    // MARK: - 3. Header Rewrite & Script Guard Rules

    func testHeaderRewriteRuleEnforcesGzipDeflate() {
        let template = SurgeBrotliShieldHelper.rawModuleTemplate
        XCTAssertTrue(template.contains("header-replace Accept-Encoding \"gzip, deflate\""))
    }

    func testResponseScriptBlocksUnsolicitedBrotli() {
        let template = SurgeBrotliShieldHelper.rawModuleTemplate
        XCTAssertTrue(template.contains("brotli-response-guard"))
        XCTAssertTrue(template.contains("requires-body=false"))
        XCTAssertTrue(template.contains("script-path=https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/scripts/brotli-guard.js"))
        XCTAssertFalse(template.contains("script-text="), "Surge .sgmodule [Script] must use script-path= instead of API-only script-text=")

        let stashShield = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        XCTAssertTrue(stashShield.contains("require-body: false"))
        guard let payloadRange = stashShield.range(of: "payload: |") else {
            XCTFail("Missing payload: | section in Stash shield")
            return
        }
        let jsPayload = String(stashShield[payloadRange.upperBound...])
        XCTAssertTrue(jsPayload.contains("status: 403"))
        XCTAssertTrue(jsPayload.contains("'Content-Length': '0'"))
        XCTAssertFalse(jsPayload.contains("response:"), "http-response script must use top-level status: 403, never nested response:")
        XCTAssertFalse(jsPayload.contains("body:"), "requires-body=false script must never pass body:")
    }

    // MARK: - 4. Platform Metadata, URL Schemes, Argument Substitution & File Export

    func testPlatformURLSchemesAndInference() {
        XCTAssertEqual(ProxyShieldPlatform(identifierOrPath: "/tmp/out.sgmodule"), .surge)
        XCTAssertEqual(ProxyShieldPlatform(identifierOrPath: "/tmp/out.module"), .shadowrocket)
        XCTAssertEqual(ProxyShieldPlatform(identifierOrPath: "/tmp/out.conf"), .quantumultX)
        XCTAssertEqual(ProxyShieldPlatform(identifierOrPath: "/tmp/out.plugin"), .loon)
        XCTAssertEqual(ProxyShieldPlatform(identifierOrPath: "/tmp/out.stoverride"), .stash)

        XCTAssertEqual(ProxyShieldPlatform.surge.oneTapInstallURL?.scheme, "surge")
        XCTAssertEqual(ProxyShieldPlatform.shadowrocket.oneTapInstallURL?.scheme, "shadowrocket")
        XCTAssertEqual(ProxyShieldPlatform.quantumultX.oneTapInstallURL?.scheme, "quantumult-x")
        XCTAssertEqual(ProxyShieldPlatform.loon.oneTapInstallURL?.scheme, "loon")
        XCTAssertEqual(ProxyShieldPlatform.stash.oneTapInstallURL?.scheme, "stash")
    }

    func testCustomArgumentSubstitution() {
        let customHosts = ["*.phishing.xyz", "*.bad.top"]
        for platform in ProxyShieldPlatform.allCases {
            let generated = SurgeBrotliShieldHelper.shared.generateShieldContent(for: platform, extraHosts: customHosts)
            XCTAssertTrue(generated.contains("*.phishing.xyz"), "\(platform) missing *.phishing.xyz")
            XCTAssertTrue(generated.contains("*.bad.top"), "\(platform) missing *.bad.top")
        }
    }

    func testTemporaryFileExportAcrossAllPlatforms() throws {
        for platform in ProxyShieldPlatform.allCases {
            let exportURL = try SurgeBrotliShieldHelper.shared.exportShieldToTemporaryFile(
                for: platform,
                extraHosts: ["*.custom.tld"]
            )
            defer { try? FileManager.default.removeItem(at: exportURL) }

            XCTAssertEqual(exportURL.pathExtension, platform.fileExtension)
            XCTAssertTrue(FileManager.default.fileExists(atPath: exportURL.path))
            let content = try String(contentsOf: exportURL, encoding: .utf8)
            XCTAssertTrue(content.contains("*.custom.tld"))
            XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: content, for: platform).isCompliant)
        }
    }

    func testValidationCatchesMissingExclusion() {
        let stripped = SurgeBrotliShieldHelper.rawModuleTemplate.replacingOccurrences(of: "-guzzoni.apple.com,", with: "")
        let result = SurgeBrotliShieldHelper.shared.validateModule(content: stripped)

        XCTAssertFalse(result.isCompliant)
        XCTAssertTrue(result.missingExclusions.contains("-guzzoni.apple.com"))
    }

    func testCLIExportShieldMultiFormat() async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("wqguard_cli_shields_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        for platform in ProxyShieldPlatform.allCases {
            let outURL = tempDir.appendingPathComponent("shield.\(platform.fileExtension)")
            let pipeOut = Pipe()
            let pipeErr = Pipe()
            let code = await CLICommandRunner.run(
                arguments: ["wqguard-cli", "--export-shield", outURL.path],
                stdout: pipeOut.fileHandleForWriting,
                stderr: pipeErr.fileHandleForWriting
            )
            pipeOut.fileHandleForWriting.closeFile()
            pipeErr.fileHandleForWriting.closeFile()

            XCTAssertEqual(code, 0, "CLI --export-shield failed for \(platform)")
            let written = try String(contentsOf: outURL, encoding: .utf8)
            XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: written, for: platform).isCompliant)
        }
    }
}
