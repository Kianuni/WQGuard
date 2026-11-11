//
//  SurgeModuleTests.swift
//  WQGuardCoreTests
//
//  Unit tests for Surge/WQGuard-Brotli-Shield.sgmodule and SurgeBrotliShieldHelper.
//  Verifies 16 mandatory negative MITM exclusions, header downgrade rules,
//  response script guard, and file export capabilities.
//

import XCTest
@testable import WQGuardCore

final class SurgeModuleTests: XCTestCase {

    // MARK: - 1. Physical .sgmodule File Validation

    func testModuleFileContentCompliance() throws {
        let repoRoot = URL(fileURLWithPath: #file)
            .deletingLastPathComponent() // WQGuardCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // WQGuard
        let moduleURL = repoRoot.appendingPathComponent("Surge/WQGuard-Brotli-Shield.sgmodule")

        XCTAssertTrue(FileManager.default.fileExists(atPath: moduleURL.path), "Surge/WQGuard-Brotli-Shield.sgmodule must exist in repository root")

        let content = try String(contentsOf: moduleURL, encoding: .utf8)
        let validation = SurgeBrotliShieldHelper.shared.validateModule(content: content)

        XCTAssertTrue(validation.isCompliant, "Module must be 100% compliant: \(validation.errors)")
        XCTAssertTrue(validation.hasValidMetadata)
        XCTAssertTrue(validation.hasHeaderRewrite)
        XCTAssertTrue(validation.hasScriptGuard)
        XCTAssertTrue(validation.missingExclusions.isEmpty)
    }

    // MARK: - 2. All 16 Negative MITM Exclusions Verified

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

        let template = SurgeBrotliShieldHelper.rawModuleTemplate
        for exclusion in expectedExclusions {
            XCTAssertTrue(template.contains(exclusion), "Template must contain negative exclusion: \(exclusion)")
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
        XCTAssertTrue(template.contains("status: 403"))
        XCTAssertTrue(template.contains("Blocked unsolicited Brotli response stream"))
    }

    // MARK: - 4. Argument Substitution & File Export

    func testCustomArgumentSubstitution() {
        let customHosts = ["*.phishing.xyz", "*.bad.top"]
        let generated = SurgeBrotliShieldHelper.shared.generateModuleContent(extraHosts: customHosts)

        XCTAssertTrue(generated.contains("*.phishing.xyz, *.bad.top"))
        XCTAssertFalse(generated.contains("{{{EXTRA_MITM_HOSTS}}}"))
    }

    func testTemporaryFileExport() throws {
        let exportURL = try SurgeBrotliShieldHelper.shared.exportToTemporaryFile(extraHosts: ["*.custom.tld"])
        defer { try? FileManager.default.removeItem(at: exportURL) }

        XCTAssertTrue(FileManager.default.fileExists(atPath: exportURL.path))
        let content = try String(contentsOf: exportURL, encoding: .utf8)
        XCTAssertTrue(content.contains("*.custom.tld"))
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateModule(content: content).isCompliant)
    }

    func testValidationCatchesMissingExclusion() {
        // Strip a critical exclusion like -guzzoni.apple.com
        let stripped = SurgeBrotliShieldHelper.rawModuleTemplate.replacingOccurrences(of: "-guzzoni.apple.com,", with: "")
        let result = SurgeBrotliShieldHelper.shared.validateModule(content: stripped)

        XCTAssertFalse(result.isCompliant)
        XCTAssertTrue(result.missingExclusions.contains("-guzzoni.apple.com"))
    }
}
