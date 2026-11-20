//
//  AuditV135ShieldsAndClientTests.swift
//  WQGuardCoreTests
//
//  Milestone M4 deterministic regression suite covering:
//  - SurgeBrotliShieldHelper comment/section/YAML scoping, duplicate hostname overrides,
//    port/wildcard negative MITM kill switches, Stash desc false positive vs JS response: bypass
//  - Quantumult X oneTapInstallURL encoding and multi-header Accept-Encoding regex rewrite
//  - JavaScriptCore resilience for brotli-guard.js and Stash inline JS (undeclared $response,
//    Object.create(null), throwing toString(), prototype pollution)
//  - v1.3.6 / Build 27 version sync & preserved "1.0.0" domain constants
//  - WhitelistEngine, LockdownPairingFile, and IPAPackageScanner UTF-8 filename boundary checks
//

import Darwin
import Foundation
import JavaScriptCore
import XCTest
@testable import WQGuardCore

final class AuditV135ShieldsAndClientTests: XCTestCase {

    private var repoRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // WQGuardCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // WQGuard
    }

    private func extractStashJS(from stashYAML: String) throws -> String {
        let range = try XCTUnwrap(stashYAML.range(of: "payload: |\n"))
        return stashYAML[range.upperBound...]
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { line -> String in
                var s = String(line)
                if s.hasPrefix("      ") { s.removeFirst(6) }
                return s
            }
            .joined(separator: "\n")
    }

    private func indentYAMLPayload(_ js: String, spaces: Int = 6) -> String {
        let pad = String(repeating: " ", count: spaces)
        var out = ""
        out.reserveCapacity(js.count + 64)
        var atLineStart = true
        for ch in js {
            if ch == "\r\n" || ch == "\r" || ch == "\n" {
                out.append(ch)
                atLineStart = true
            } else {
                if atLineStart {
                    out.append(pad)
                    atLineStart = false
                }
                out.append(ch)
            }
        }
        let normalized = out
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        for line in normalized.split(separator: "\n", omittingEmptySubsequences: false) {
            if !line.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                let leading = line.prefix(while: { $0 == " " }).count
                precondition(leading >= spaces, "YAML payload line under-indented (\(leading) < \(spaces)): \(line)")
            }
        }
        return out
    }

    private func stashHeaderBeforePayload(file: StaticString = #filePath, line: UInt = #line) throws -> String {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let range = try XCTUnwrap(validStash.range(of: "payload: |"), "Missing payload: | in generated Stash shield", file: file, line: line)
        return String(validStash[..<range.upperBound])
    }

    private func validateStashPayloadJS(_ js: String, headerPart: String) -> SurgeBrotliShieldHelper.ValidationResult {
        let yaml = headerPart + "\n" + indentYAMLPayload(js, spaces: 6) + "\n"
        return SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
    }

    // MARK: - 1. Commented Exclusions, Missing [MITM], Substring Collisions & Duplicate Hostname Overrides

    func testCommentedExclusionsAndMissingMITMSectionRejectedAcrossAllPlatforms() {
        let exclusions = SurgeBrotliShieldHelper.mandatoryNegativeExclusions.joined(separator: ", ")

        let fakeSurge = """
        #!name=WQGuard Fake
        #!desc=Includes \(exclusions) in desc only
        #!version=1.3.6
        #!category=Security
        [Header Rewrite]
        ^https?:// header-replace Accept-Encoding "gzip, deflate"
        [Script]
        brotli-response-guard = type=http-response,pattern=^https?://.+,requires-body=false,max-size=0,script-path=https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/scripts/brotli-guard.js
        # [MITM]
        # hostname = %APPEND% \(exclusions), *.xyz
        """
        let surgeRes = SurgeBrotliShieldHelper.shared.validateShield(content: fakeSurge, for: .surge)
        XCTAssertFalse(surgeRes.isCompliant)
        XCTAssertEqual(surgeRes.missingExclusions.count, 16)

        let fakeSR = """
        #!name=WQGuard Fake SR
        #!desc=Mentions \(exclusions)
        [Header Rewrite]
        ^https?://.+ header-replace Accept-Encoding gzip,deflate
        [Script]
        brotli-response-guard = type=http-response,pattern=^https?://.+,script-path=https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/scripts/brotli-guard.js,requires-body=0,max-size=0
        [MITM]
        # hostname = %APPEND% \(exclusions)
        hostname = %APPEND% *.xyz
        """
        let srRes = SurgeBrotliShieldHelper.shared.validateShield(content: fakeSR, for: .shadowrocket)
        XCTAssertFalse(srRes.isCompliant)
        XCTAssertEqual(srRes.missingExclusions.count, 16)

        let fakeQX = """
        ; Quantumult X CVE-2026-111497
        ; \(exclusions)
        [rewrite_local]
        ^https?://.+ url request-header (\\r\\n[Aa][Cc][Cc][Ee][Pp][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]:)[^\\r\\n]* request-header $1 gzip, deflate
        ^https?://.+ url script-response-header https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/scripts/brotli-guard.js
        [mitm]
        hostname = *.xyz
        """
        let qxRes = SurgeBrotliShieldHelper.shared.validateShield(content: fakeQX, for: .quantumultX)
        XCTAssertFalse(qxRes.isCompliant)
        XCTAssertEqual(qxRes.missingExclusions.count, 16)

        let fakeLoon = """
        #!name = WQGuard Fake Loon
        #!desc = \(exclusions)
        [Rewrite]
        ^https?://.+ header-replace Accept-Encoding gzip,deflate
        [Script]
        http-response ^https?://.+ script-path=https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/scripts/brotli-guard.js,requires-body=false,timeout=5
        [Mitm]
        hostname = *.xyz
        """
        let loonRes = SurgeBrotliShieldHelper.shared.validateShield(content: fakeLoon, for: .loon)
        XCTAssertFalse(loonRes.isCompliant)
        XCTAssertEqual(loonRes.missingExclusions.count, 16)

        let fakeStash = """
        #!version=1.3.6
        name: "Fake Stash"
        desc: "\(exclusions)"
        http:
          header-rewrite:
            - ^https?://.+ request-replace-regex Accept-Encoding "^.*$" "gzip, deflate"
          script:
            - name: brotli-response-guard
              match: ^https?://.+
              type: response
              require-body: false
        script-providers:
          brotli-response-guard:
            payload: |
              $done({ status: 403 });
        """
        let stashRes = SurgeBrotliShieldHelper.shared.validateShield(content: fakeStash, for: .stash)
        XCTAssertFalse(stashRes.isCompliant)
        XCTAssertEqual(stashRes.missingExclusions.count, 16)
        XCTAssertTrue(stashRes.hasHeaderRewrite)
        XCTAssertTrue(stashRes.hasScriptGuard)
    }

    func testCommentedRulesSubstringCollisionAndDuplicateHostnameOverrideRejected() {
        // 1. Substring collision: -*.apple.com.attacker.com must NOT satisfy -*.apple.com
        let baseSurge = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .surge)
        let collidedSurge = baseSurge.replacingOccurrences(of: "-*.apple.com,", with: "-*.apple.com.attacker.com,")
        let collidedRes = SurgeBrotliShieldHelper.shared.validateShield(content: collidedSurge, for: .surge)
        XCTAssertFalse(collidedRes.isCompliant)
        XCTAssertEqual(collidedRes.missingExclusions, ["-*.apple.com"])

        // 2. Duplicate hostname = override without %APPEND% wipes earlier exclusions
        let overriddenSurge = baseSurge + "\nhostname = *.xyz\n"
        let overriddenRes = SurgeBrotliShieldHelper.shared.validateShield(content: overriddenSurge, for: .surge)
        XCTAssertFalse(overriddenRes.isCompliant)
        XCTAssertEqual(overriddenRes.missingExclusions.count, 16)

        // 3. Commented header-rewrite rule in Surge must fail hasHeaderRewrite
        let commentedRewrite = baseSurge.replacingOccurrences(
            of: "^https?:// header-replace Accept-Encoding \"gzip, deflate\"",
            with: "# ^https?:// header-replace Accept-Encoding \"gzip, deflate\""
        )
        let commentedRewriteRes = SurgeBrotliShieldHelper.shared.validateShield(content: commentedRewrite, for: .surge)
        XCTAssertFalse(commentedRewriteRes.isCompliant)
        XCTAssertFalse(commentedRewriteRes.hasHeaderRewrite)
    }

    // MARK: - 2. Blanket Negative MITM Kill-Switch Variants

    func testBlanketNegativeMITMKillSwitchesRejectedAcrossAllPlatforms() {
        let killSwitches = ["-*", "-*:443", "-*:*", "-*.*", "-*.*:443", "-**", "-*."]

        for platform in ProxyShieldPlatform.allCases {
            let valid = SurgeBrotliShieldHelper.shared.generateShieldContent(for: platform)
            for ks in killSwitches {
                let tampered: String
                if platform == .stash {
                    tampered = valid.replacingOccurrences(of: "- \"*.xyz\"", with: "- \"\(ks)\"")
                } else {
                    tampered = valid.replacingOccurrences(of: "*.xyz", with: ks)
                }
                let res = SurgeBrotliShieldHelper.shared.validateShield(content: tampered, for: platform)
                XCTAssertFalse(res.isCompliant, "\(platform.shortTitleEn) must reject blanket kill switch \(ks)")
            }
        }

        // Positive wildcard "*" in extraHosts must remain compliant
        let surgeAllHosts = SurgeBrotliShieldHelper.shared.generateModuleContent(extraHosts: ["*"])
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateModule(content: surgeAllHosts).isCompliant)
    }

    // MARK: - 3. Stash "response:" False Positive & JS Wrapper Bypass Tests

    func testStashAllowsResponseColonInDescAndCommentsButRejectsJSNestedWrappers() {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let withDescResponse = validStash
            .replacingOccurrences(
                of: "desc: \"",
                with: "desc: \"Blocks response: br payload. "
            ) + "\n# response: guard comment\n"
        let validRes = SurgeBrotliShieldHelper.shared.validateShield(content: withDescResponse, for: .stash)
        XCTAssertTrue(validRes.isCompliant, "Stash desc/comment mentioning response: must pass: \(validRes.errors)")

        // Nested "response": or response : or body: in JS payload must fail
        let quotedWrapper = validStash.replacingOccurrences(
            of: "status: 403,",
            with: "\"response\": { status: 403 },"
        )
        let quotedWrapperRes = SurgeBrotliShieldHelper.shared.validateShield(content: quotedWrapper, for: .stash)
        XCTAssertFalse(quotedWrapperRes.isCompliant)
        XCTAssertFalse(quotedWrapperRes.hasScriptGuard)

        let spacedWrapper = validStash.replacingOccurrences(
            of: "status: 403,",
            with: "response : { status: 403 },"
        )
        let spacedWrapperRes = SurgeBrotliShieldHelper.shared.validateShield(content: spacedWrapper, for: .stash)
        XCTAssertFalse(spacedWrapperRes.isCompliant)
        XCTAssertFalse(spacedWrapperRes.hasScriptGuard)

        let bodyWrapper = validStash.replacingOccurrences(
            of: "status: 403,",
            with: "status: 403, body: \"blocked\","
        )
        let bodyWrapperRes = SurgeBrotliShieldHelper.shared.validateShield(content: bodyWrapper, for: .stash)
        XCTAssertFalse(bodyWrapperRes.isCompliant)
        XCTAssertFalse(bodyWrapperRes.hasScriptGuard)

        // Missing type: response in Stash script section must fail
        let missingType = validStash.replacingOccurrences(of: "type: response", with: "type: request")
        let missingTypeRes = SurgeBrotliShieldHelper.shared.validateShield(content: missingType, for: .stash)
        XCTAssertFalse(missingTypeRes.isCompliant)
        XCTAssertFalse(missingTypeRes.hasScriptGuard)
    }

    // MARK: - 4. Quantumult X oneTapInstallURL Encoding & Duplicate Accept-Encoding Header Regex

    func testQuantumultXOneTapInstallURLEncodesReservedQueryDelimiters() throws {
        let url = try XCTUnwrap(ProxyShieldPlatform.quantumultX.oneTapInstallURL)
        let abs = url.absoluteString
        XCTAssertTrue(abs.hasPrefix("quantumult-x:///add-resource?remote-resource="))
        let queryValue = String(abs.dropFirst("quantumult-x:///add-resource?remote-resource=".count))
        XCTAssertFalse(queryValue.contains("="), "Query value must percent-encode '=': \(queryValue)")
        XCTAssertFalse(queryValue.contains("&"), "Query value must percent-encode '&': \(queryValue)")
        XCTAssertTrue(queryValue.contains("%3D"))

        let comps = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let decodedParam = try XCTUnwrap(comps.queryItems?.first(where: { $0.name == "remote-resource" })?.value)
        let jsonData = try XCTUnwrap(decodedParam.data(using: .utf8))
        let parsed = try XCTUnwrap(JSONSerialization.jsonObject(with: jsonData) as? [String: Any])
        let rewriteRemote = try XCTUnwrap(parsed["rewrite_remote"] as? [String])
        XCTAssertTrue(rewriteRemote.first?.contains("WQGuard-Brotli-Shield.conf") == true)
    }

    func testQuantumultXRequestHeaderRegexRewritesAdjacentDuplicateAndEmptyAcceptEncoding() throws {
        let qxConf = try String(
            contentsOf: repoRoot.appendingPathComponent("Shields/QuantumultX/WQGuard-Brotli-Shield.conf"),
            encoding: .utf8
        )
        let ruleLine = try XCTUnwrap(
            qxConf.split(separator: "\n")
                .map(String.init)
                .first(where: { $0.contains("url request-header") })
        )
        // Extract regex pattern and replacement between "url request-header " and " request-header "
        let afterMarker = try XCTUnwrap(ruleLine.components(separatedBy: "url request-header ").last)
        let parts = afterMarker.components(separatedBy: " request-header ")
        XCTAssertEqual(parts.count, 2)
        let pattern = parts[0]
        let replacement = parts[1]

        let regex = try NSRegularExpression(pattern: pattern, options: [])
        let httpReq = "GET / HTTP/1.1\r\nHost: phishing.xyz\r\nAccept-Encoding: gzip\r\nAccept-Encoding: br\r\nAccept-Encoding:\r\nUser-Agent: Test\r\n\r\n"
        let rewritten = regex.stringByReplacingMatches(
            in: httpReq,
            options: [],
            range: NSRange(httpReq.startIndex..<httpReq.endIndex, in: httpReq),
            withTemplate: replacement
        )
        XCTAssertFalse(rewritten.contains("Accept-Encoding: br"), "Duplicate adjacent br header was not rewritten: \(rewritten)")
        XCTAssertEqual(rewritten.components(separatedBy: "gzip, deflate").count - 1, 3)
    }

    // MARK: - 5. JSContext Resilience for brotli-guard.js & Stash Inline JS

    func testBrotliGuardJSAndStashPayloadResilientAgainstHostileInputs() throws {
        let standaloneJS = try String(
            contentsOf: repoRoot.appendingPathComponent("Shields/scripts/brotli-guard.js"),
            encoding: .utf8
        )
        let stashJS = try extractStashJS(
            from: SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        )

        for (label, script) in [("brotli-guard.js", standaloneJS), ("Stash inline JS", stashJS)] {
            // 1. Undeclared $response must not throw ReferenceError and must invoke $done({})
            do {
                let ctx = try XCTUnwrap(JSContext())
                var captured: [String: Any]? = nil
                let doneBlock: @convention(block) (JSValue) -> Void = { val in
                    captured = val.toDictionary() as? [String: Any]
                }
                ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
                _ = ctx.evaluateScript(script)
                XCTAssertNil(ctx.exception, "\(label) threw exception on undeclared $response: \(String(describing: ctx.exception))")
                XCTAssertNotNil(captured)
                XCTAssertNil(captured?["status"])
            }

            // 2. Object.create(null) header value & headers map must not throw TypeError
            do {
                let ctx = try XCTUnwrap(JSContext())
                var captured: [String: Any]? = nil
                let doneBlock: @convention(block) (JSValue) -> Void = { val in
                    captured = val.toDictionary() as? [String: Any]
                }
                ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
                _ = ctx.evaluateScript("""
                var h = Object.create(null);
                h["Content-Encoding"] = Object.create(null);
                var $response = { status: 200, headers: h };
                """)
                _ = ctx.evaluateScript(script)
                XCTAssertNil(ctx.exception, "\(label) threw on Object.create(null): \(String(describing: ctx.exception))")
                XCTAssertNil(captured?["status"])
            }

            // 3. Array containing [Object.create(null), throwing-toString, "br"] must still block (status 403)
            do {
                let ctx = try XCTUnwrap(JSContext())
                var captured: [String: Any]? = nil
                let doneBlock: @convention(block) (JSValue) -> Void = { val in
                    captured = val.toDictionary() as? [String: Any]
                }
                ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
                _ = ctx.evaluateScript("""
                var poison = { toString: function () { throw new Error("boom"); } };
                var $response = { status: 200, headers: { "Content-Encoding": [Object.create(null), poison, "br"] } };
                """)
                _ = ctx.evaluateScript(script)
                XCTAssertNil(ctx.exception, "\(label) threw on [Object.create(null), poison, 'br']: \(String(describing: ctx.exception))")
                XCTAssertEqual(captured?["status"] as? Int, 403, "\(label) failed to block br alongside poison object")
            }

            // 4. Prototype pollution must not trigger false block on empty headers
            do {
                let ctx = try XCTUnwrap(JSContext())
                var captured: [String: Any]? = nil
                let doneBlock: @convention(block) (JSValue) -> Void = { val in
                    captured = val.toDictionary() as? [String: Any]
                }
                ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
                _ = ctx.evaluateScript("""
                Object.prototype["content-encoding"] = "br";
                var $response = { status: 200, headers: {} };
                """)
                _ = ctx.evaluateScript(script)
                XCTAssertNil(ctx.exception)
                XCTAssertNil(captured?["status"], "\(label) must ignore inherited prototype properties")
            }

            // 5. Safe tokens containing br/sbr substrings must not false-positive
            for safeToken in ["br-custom-token", "app.br.token", "sbr_custom"] {
                let ctx = try XCTUnwrap(JSContext())
                var captured: [String: Any]? = nil
                let doneBlock: @convention(block) (JSValue) -> Void = { val in
                    captured = val.toDictionary() as? [String: Any]
                }
                ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
                ctx.setObject(["status": 200, "headers": ["Content-Encoding": safeToken]], forKeyedSubscript: "$response" as NSString)
                _ = ctx.evaluateScript(script)
                XCTAssertNil(ctx.exception)
                XCTAssertNil(captured?["status"], "\(label) falsely blocked safe token \(safeToken)")
            }
        }
    }

    // MARK: - 6. Version 1.3.6 / Build 27 Sync, Byte-Equality & Preserved Constants

    func testVersionSyncAcrossAllShieldsAndPreservedDomainConstants() throws {
        let physicalMap: [(ProxyShieldPlatform, String)] = [
            (.surge, "Shields/Surge/WQGuard-Brotli-Shield.sgmodule"),
            (.shadowrocket, "Shields/Shadowrocket/WQGuard-Brotli-Shield.module"),
            (.quantumultX, "Shields/QuantumultX/WQGuard-Brotli-Shield.conf"),
            (.loon, "Shields/Loon/WQGuard-Brotli-Shield.plugin"),
            (.stash, "Shields/Stash/WQGuard-Brotli-Shield.stoverride")
        ]

        for (platform, relPath) in physicalMap {
            let generated = SurgeBrotliShieldHelper.shared.generateShieldContent(for: platform)
            let physical = try String(contentsOf: repoRoot.appendingPathComponent(relPath), encoding: .utf8)
            XCTAssertTrue(generated.contains("#!version=1.3.6"), "\(platform.shortTitleEn) generated must contain #!version=1.3.6")
            XCTAssertEqual(
                physical.trimmingCharacters(in: .whitespacesAndNewlines),
                generated.trimmingCharacters(in: .whitespacesAndNewlines),
                "\(relPath) must match generated output"
            )
            XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: physical, for: platform).isCompliant)
        }

        let legacySurge = try Data(contentsOf: repoRoot.appendingPathComponent("Surge/WQGuard-Brotli-Shield.sgmodule"))
        let shieldsSurge = try Data(contentsOf: repoRoot.appendingPathComponent("Shields/Surge/WQGuard-Brotli-Shield.sgmodule"))
        XCTAssertEqual(legacySurge, shieldsSurge, "Surge/ and Shields/Surge/ must be byte-identical")

        // Verify Info.plist carries 1.3.6 / Build 27
        let plistData = try Data(contentsOf: repoRoot.appendingPathComponent("WQGuard/Resources/Info.plist"))
        let plist = try XCTUnwrap(PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any])
        XCTAssertEqual(plist["CFBundleShortVersionString"] as? String, "1.3.6")
        XCTAssertEqual(plist["CFBundleVersion"] as? String, "27")

        // Preserved domain constants
        XCTAssertEqual(WQGuardCLIMetadata.version, "1.0.0")
        XCTAssertEqual(ScanSession(findings: []).engineVersion, "1.0.0")
    }

    // MARK: - 7. Whitelist, Pairing & UTF-8 Filename Boundary Contracts

    func testWhitelistRejectsHighRiskIneligibleEscapingAndProtectedGroups() {
        let highRiskHostFinding = ScanFinding(
            bundleId: "com.wqguard.app",
            displayName: "WQGuard",
            version: "1.3.6",
            teamId: "TEAM123456",
            executablePath: "/var/containers/Bundle/Application/1234/WQGuard.app/WQGuard",
            bundlePath: "/var/containers/Bundle/Application/1234/WQGuard.app",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [
                ThreatIndicator(signature: "arm64:svc_0x80", description: "Direct syscall", category: "Syscall", location: "Text", severity: .highRisk)
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["arm64:svc_0x80"],
                hasAppGroups: true,
                appGroups: ["group.com.wqguard.app"],
                auditDepth: .registryEntitlements,
                isWhitelistEligible: false,
                isTeamIdWhitelistVerified: true
            )
        )
        let engine = WhitelistEngine(tools: WhitelistEngine.defaultTools)
        XCTAssertFalse(engine.evaluateFindingWhitelist(highRiskHostFinding, runningSelfBundleId: "com.wqguard.app").isWhitelisted)

        // Escaping symlinks must never be whitelisted
        let escapingFinding = ScanFinding(
            bundleId: "com.wqguard.app",
            displayName: "WQGuard",
            version: "1.3.6",
            teamId: "TEAM123456",
            executablePath: "/tmp/WQGuard",
            bundlePath: "/tmp/WQGuard.app",
            installChannel: .developerSideloaded,
            riskTier: .caution,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [ThreatIndicator(signature: "dlopen", description: "Dynamic", category: "Dyn", location: "Mach-O", severity: .caution)],
            evidence: AuditEvidence(
                matchedSymbols: ["dlopen"],
                hasAppGroups: true,
                appGroups: ["group.com.wqguard.app"],
                escapingSymlinks: ["Library/Caches -> /etc/passwd"],
                auditDepth: .fullBinaryAndRegistry,
                isWhitelistEligible: true,
                isTeamIdWhitelistVerified: true
            )
        )
        XCTAssertFalse(engine.evaluateFindingWhitelist(escapingFinding, runningSelfBundleId: "com.wqguard.app").isWhitelisted)

        // Protected victim and Apple groups rejected
        XCTAssertTrue(ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup("group.io.metamask"))
        XCTAssertTrue(ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup("group.com.apple.reminders"))
        XCTAssertTrue(ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup("group.tvappservices.container"))
        XCTAssertFalse(ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup("group.com.example.customtool"))
    }

    func testIPAPackageScannerUTF8FilenameBoundAndLockdownPairingSizeCap() throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent("wqg_m4_utf8_\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let src = tmpDir.appendingPathComponent("source.ipa")
        try Data("PK\u{03}\u{04}dummy".utf8).write(to: src)

        // 1. 75 CJK characters = 225 UTF-8 bytes + ".ipa" (4 bytes) = 229 bytes (< 255 NAME_MAX) -> succeeds
        let safeCJKName = String(repeating: "测", count: 75) + ".ipa"
        let safeDst = tmpDir.appendingPathComponent(safeCJKName)
        try IPAPackageScanner.copyBoundedRegularFileNoFollow(from: src, to: safeDst, maxBytes: 1024 * 1024)
        XCTAssertTrue(FileManager.default.fileExists(atPath: safeDst.path))

        // 2. > 255 characters (both CJK and ASCII) -> fails with ENAMETOOLONG on APFS
        let overlongCJKName = String(repeating: "测", count: 252) + ".ipa"
        let overlongASCIIName = String(repeating: "a", count: 252) + ".ipa"
        XCTAssertThrowsError(try IPAPackageScanner.copyBoundedRegularFileNoFollow(from: src, to: tmpDir.appendingPathComponent(overlongCJKName), maxBytes: 1024 * 1024))
        XCTAssertThrowsError(try IPAPackageScanner.copyBoundedRegularFileNoFollow(from: src, to: tmpDir.appendingPathComponent(overlongASCIIName), maxBytes: 1024 * 1024))

        // 3. Symlink destination trap must fail
        let linkDst = tmpDir.appendingPathComponent("symlink_trap.ipa")
        XCTAssertEqual(Darwin.symlink(safeDst.path, linkDst.path), 0)
        XCTAssertThrowsError(try IPAPackageScanner.copyBoundedRegularFileNoFollow(from: src, to: linkDst, maxBytes: 1024 * 1024))

        // 4. LockdownPairingFile > 4 MB payload rejected
        let oversizedPairing = Data(repeating: 0x41, count: 4 * 1024 * 1024 + 1)
        XCTAssertThrowsError(try LockdownPairingFile.parse(data: oversizedPairing))

        // 5. InstalledAppRegistryScanner parses updated JSON snapshot cleanly
        let snap1 = Data("[{\"CFBundleIdentifier\":\"com.example.one\",\"CFBundleDisplayName\":\"One\",\"ApplicationType\":\"User\"}]".utf8)
        let snap2 = Data("[{\"CFBundleIdentifier\":\"com.example.one\",\"CFBundleDisplayName\":\"One\",\"ApplicationType\":\"User\"},{\"CFBundleIdentifier\":\"com.example.two\",\"CFBundleDisplayName\":\"Two\",\"ApplicationType\":\"User\"}]".utf8)
        XCTAssertEqual(try InstalledAppRegistryScanner.shared.parseSnapshotData(snap1).count, 1)
        XCTAssertEqual(try InstalledAppRegistryScanner.shared.parseSnapshotData(snap2).count, 2)
    }

    // MARK: - 8. Iteration 2 Challenger 1 Regressions (Accept-Encoding Smuggling, JS RegExp Literals, 4-Space YAML Sibling)

    func testAcceptEncodingBrotliSmugglingRejectedAcrossPlatforms() {
        // Shadowrocket & Loon: gzip,deflate,br and "gzip, deflate, br" must be rejected
        for platform in [ProxyShieldPlatform.shadowrocket, ProxyShieldPlatform.loon] {
            let valid = SurgeBrotliShieldHelper.shared.generateShieldContent(for: platform)
            let smuggledUnquoted = valid.replacingOccurrences(of: "Accept-Encoding gzip,deflate", with: "Accept-Encoding gzip,deflate,br")
            let res1 = SurgeBrotliShieldHelper.shared.validateShield(content: smuggledUnquoted, for: platform)
            XCTAssertFalse(res1.isCompliant, "\(platform.shortTitleEn) must reject gzip,deflate,br")
            XCTAssertFalse(res1.hasHeaderRewrite)

            let smuggledQuoted = valid.replacingOccurrences(of: "Accept-Encoding gzip,deflate", with: "Accept-Encoding \"gzip, deflate, br\"")
            let res2 = SurgeBrotliShieldHelper.shared.validateShield(content: smuggledQuoted, for: platform)
            XCTAssertFalse(res2.isCompliant, "\(platform.shortTitleEn) must reject \"gzip, deflate, br\"")
            XCTAssertFalse(res2.hasHeaderRewrite)
        }

        // Quantumult X: request-header $1 gzip, deflate, br and gzip,deflate,br must be rejected
        let validQX = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .quantumultX)
        for badReplacement in ["$1 gzip, deflate, br", "$1 gzip,deflate,br", "$1 \"gzip, deflate, br\""] {
            let tamperedQX = validQX.replacingOccurrences(of: "request-header $1 gzip, deflate", with: "request-header \(badReplacement)")
            let qxRes = SurgeBrotliShieldHelper.shared.validateShield(content: tamperedQX, for: .quantumultX)
            XCTAssertFalse(qxRes.isCompliant, "Quantumult X must reject \(badReplacement)")
            XCTAssertFalse(qxRes.hasHeaderRewrite)
        }

        // Stash: "gzip, deflate, br" and gzip,deflate,br must be rejected
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        for badReplacement in ["\"gzip, deflate, br\"", "gzip,deflate,br", "\"gzip, deflate\" br"] {
            let tamperedStash = validStash.replacingOccurrences(of: "\"^.*$\" \"gzip, deflate\"", with: "\"^.*$\" \(badReplacement)")
            let stashRes = SurgeBrotliShieldHelper.shared.validateShield(content: tamperedStash, for: .stash)
            XCTAssertFalse(stashRes.isCompliant, "Stash must reject \(badReplacement)")
            XCTAssertFalse(stashRes.hasHeaderRewrite)
        }

        // Surge: "gzip, deflate, br" must also be rejected
        let validSurge = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .surge)
        let tamperedSurge = validSurge.replacingOccurrences(of: "Accept-Encoding \"gzip, deflate\"", with: "Accept-Encoding \"gzip, deflate, br\"")
        let surgeRes = SurgeBrotliShieldHelper.shared.validateShield(content: tamperedSurge, for: .surge)
        XCTAssertFalse(surgeRes.isCompliant)
        XCTAssertFalse(surgeRes.hasHeaderRewrite)
    }

    func testStashJSCommentStrippingTracksRegExpLiterals() {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        guard let payloadIdx = validStash.range(of: "payload: |") else {
            XCTFail("Missing payload: | in generated Stash shield")
            return
        }
        let headerPart = String(validStash[..<payloadIdx.upperBound])

        // 1. Regex literal /https?:\/\// before nested response: wrapper must NOT hide response: as a comment
        let maliciousStash = headerPart + "\n      const re = /https?:\\/\\//; $done({ response: {\n        status: 403,\n        headers: {}\n      }});\n"
        let maliciousRes = SurgeBrotliShieldHelper.shared.validateShield(content: maliciousStash, for: .stash)
        XCTAssertFalse(maliciousRes.isCompliant, "RegExp literal // must not mask nested response: wrapper")
        XCTAssertFalse(maliciousRes.hasScriptGuard)

        // 2. Valid one-line JS with /^https?:\/\// followed by $done({ status: 403, headers: {} }) must be accepted
        let legitimateStash = headerPart + "\n      if (/^https?:\\/\\//.test('https://a.xyz')) $done({ status: 403, headers: {} });\n"
        let legitimateRes = SurgeBrotliShieldHelper.shared.validateShield(content: legitimateStash, for: .stash)
        XCTAssertTrue(legitimateRes.isCompliant, "Valid Stash JS with RegExp literal must pass: \(legitimateRes.errors)")
        XCTAssertTrue(legitimateRes.hasScriptGuard)
    }

    func testStashYAMLFourSpaceSiblingProviderCannotLeakStatus403() {
        let exclusions = SurgeBrotliShieldHelper.mandatoryNegativeExclusions
            .map { "        - \"\($0)\"" }
            .joined(separator: "\n")
        let fourSpaceTampered = """
        #!version=1.3.6
        name: "Stash 4-Space Sibling Probe"
        desc: "Test"
        http:
            mitm:
        \(exclusions)
                - "*.xyz"
            header-rewrite:
                - ^https?://.+ request-replace-regex Accept-Encoding "^.*$" "gzip, deflate"
            script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
        script-providers:
            brotli-response-guard:
                url: https://evil.example/disable.js
            other-provider:
                payload: |
                    $done({ status: 403 });
        """
        let res = SurgeBrotliShieldHelper.shared.validateShield(content: fourSpaceTampered, for: .stash)
        XCTAssertFalse(res.isCompliant, "4-space sibling other-provider must not leak status: 403 into brotli-response-guard")
        XCTAssertFalse(res.hasScriptGuard)
    }

    // MARK: - 9. Iteration 3 Regressions (Control-Header RegExp, ASI Division, Template Interpolation, Header-Target Anchoring)

    func testStashJSControlHeaderRegExpASIDivisionAndTemplateInterpolation() {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        guard let payloadIdx = validStash.range(of: "payload: |") else {
            XCTFail("Missing payload: | in generated Stash shield")
            return
        }
        let headerPart = String(validStash[..<payloadIdx.upperBound])

        // 1. Control-header if/while (...) followed by RegExp literal /a\/\// must NOT strip $done({ response: ... })
        let ifBypassJS = """
              if (1) /a\\/\\//; $done({ response: {
                status: 403,
                headers: {}
              }});
        """
        let ifBypassRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + ifBypassJS + "\n", for: .stash)
        XCTAssertFalse(ifBypassRes.isCompliant, "if (1) /a\\/\\// must parse as RegExp so response: is detected")
        XCTAssertFalse(ifBypassRes.hasScriptGuard)

        let whileBypassJS = """
              while (0) /a\\/\\//; $done({ response: {
                status: 403,
                headers: {}
              }});
        """
        let whileBypassRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + whileBypassJS + "\n", for: .stash)
        XCTAssertFalse(whileBypassRes.isCompliant, "while (0) /a\\/\\// must parse as RegExp so response: is detected")
        XCTAssertFalse(whileBypassRes.hasScriptGuard)

        // Legitimate if (1) /a\/\//.test('a//') followed by top-level $done({ status: 403 }) must be accepted
        let legitIfRegexJS = "      if (1) /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });"
        let legitIfRegexRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + legitIfRegexJS + "\n", for: .stash)
        XCTAssertTrue(legitIfRegexRes.isCompliant, "Legitimate if (1) /a\\/\\//.test('a//') must pass: \(legitIfRegexRes.errors)")
        XCTAssertTrue(legitIfRegexRes.hasScriptGuard)

        // Call expression foo() / 2 // response: fake must treat / as division and strip // comment
        let callDivisionJS = """
              const x = foo() / 2 // response: comment
              $done({ status: 403, headers: {} });
        """
        let callDivisionRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + callDivisionJS + "\n", for: .stash)
        XCTAssertTrue(callDivisionRes.isCompliant, "foo() / 2 // response: comment must strip comment: \(callDivisionRes.errors)")
        XCTAssertTrue(callDivisionRes.hasScriptGuard)

        // 2. ASI-division across newline before /* $done({ status: 403 }) */ must strip block comment and reject
        let asiDivisionJS = """
              var x = 10
              / 2 /*
              $done({ status: 403, headers: {} });
              */
        """
        let asiDivisionRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + asiDivisionJS + "\n", for: .stash)
        XCTAssertFalse(asiDivisionRes.isCompliant, "ASI division across newline must strip /* ... */ and reject")
        XCTAssertFalse(asiDivisionRes.hasScriptGuard)

        // Return ASI keyword followed by newline + RegExp literal must still parse RegExp and accept $done
        let returnRegexJS = """
              function check() {
                return
                /a\\/\\//.test('a//');
              }
              $done({ status: 403, headers: {} });
        """
        let returnRegexRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + returnRegexJS + "\n", for: .stash)
        XCTAssertTrue(returnRegexRes.isCompliant, "return\\n/a\\/\\// must parse RegExp cleanly: \(returnRegexRes.errors)")

        // 3. Template interpolation ${"`"} must NOT close outer template literal and mask /* ... */
        let templateInterpBypassJS = """
              const s = `hello ${"`"}`; /*
              $done({ status: 403, headers: {} });
              */
        """
        let templateInterpRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + templateInterpBypassJS + "\n", for: .stash)
        XCTAssertFalse(templateInterpRes.isCompliant, "Template interpolation ${\"`\"} must not mask /* ... */")
        XCTAssertFalse(templateInterpRes.hasScriptGuard)

        let nestedTemplateBypassJS = """
              const s = `outer ${`inner ${1}`}`; /*
              $done({ status: 403, headers: {} });
              */
        """
        let nestedTemplateRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + nestedTemplateBypassJS + "\n", for: .stash)
        XCTAssertFalse(nestedTemplateRes.isCompliant, "Nested template interpolation must not mask /* ... */")

        let legitTemplateJS = "      const s = `ok ${\"`\"}`; if (1) /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });"
        let legitTemplateRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + legitTemplateJS + "\n", for: .stash)
        XCTAssertTrue(legitTemplateRes.isCompliant, "Legitimate template interpolation + RegExp must pass: \(legitTemplateRes.errors)")
    }

    func testQuantumultXHeaderTargetMismatchRejected() {
        let validQX = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .quantumultX)
        let legitRule = "^https?://.+ url request-header (\\r\\n[Aa][Cc][Cc][Ee][Pp][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]:)[^\\r\\n]* request-header $1 gzip, deflate"
        XCTAssertTrue(validQX.contains(legitRule))
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: validQX, for: .quantumultX).isCompliant)

        let spoofedRules = [
            "^https?://.+ url request-header (\\r\\nAccept-Encoding-Extra:)[^\\r\\n]* request-header $1 gzip, deflate",
            "^https?://.+ url request-header (\\r\\nX-Accept-Encoding:)[^\\r\\n]* request-header $1 gzip, deflate",
            "^https?://accept-encoding.example.com/.+ url request-header (\\r\\nUser-Agent:)[^\\r\\n]* request-header $1 gzip, deflate",
            "^https?://.+ url request-header (\\r\\n[Aa][Cc][Cc][Ee][Pp][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]:)[^\\r\\n]* request-header gzip, deflate"
        ]
        for spoofed in spoofedRules {
            let tampered = validQX.replacingOccurrences(of: legitRule, with: spoofed)
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: tampered, for: .quantumultX)
            XCTAssertFalse(res.isCompliant, "QX must reject spoofed rule: \(spoofed)")
            XCTAssertFalse(res.hasHeaderRewrite, "QX hasHeaderRewrite must be false for: \(spoofed)")
        }

        // Valid alternative QX rule using Accept-Encoding: replacement
        let altValidRule = "^https?://.+ url request-header (?im)^Accept-Encoding:[^\\r\\n]* request-header Accept-Encoding: gzip, deflate"
        let altValidQX = validQX.replacingOccurrences(of: legitRule, with: altValidRule)
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: altValidQX, for: .quantumultX).isCompliant)
    }

    func testChainedUserAgentHeaderReplaceAndStashRequestReplaceRejected() {
        // Surge: chained User-Agent + header-replace Accept-Encoding must be rejected
        let validSurge = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .surge)
        let chainedSurge = validSurge.replacingOccurrences(
            of: "^https?:// header-replace Accept-Encoding \"gzip, deflate\"",
            with: "^https?://.+ header-replace User-Agent header-replace Accept-Encoding \"gzip, deflate\""
        )
        let surgeRes = SurgeBrotliShieldHelper.shared.validateShield(content: chainedSurge, for: .surge)
        XCTAssertFalse(surgeRes.isCompliant)
        XCTAssertFalse(surgeRes.hasHeaderRewrite)

        // Shadowrocket & Loon: chained User-Agent + header-replace Accept-Encoding must be rejected
        for platform in [ProxyShieldPlatform.shadowrocket, ProxyShieldPlatform.loon] {
            let valid = SurgeBrotliShieldHelper.shared.generateShieldContent(for: platform)
            let chained = valid.replacingOccurrences(
                of: "^https?://.+ header-replace Accept-Encoding gzip,deflate",
                with: "^https?://.+ header-replace User-Agent header-replace Accept-Encoding gzip,deflate"
            )
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: chained, for: platform)
            XCTAssertFalse(res.isCompliant, "\(platform.shortTitleEn) must reject chained User-Agent rule")
            XCTAssertFalse(res.hasHeaderRewrite)
        }

        // Stash: chained User-Agent + request-replace-regex Accept-Encoding must be rejected
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let origStashRule = "- ^https?://.+ request-replace-regex Accept-Encoding \"^.*$\" \"gzip, deflate\""
        let chainedStash = validStash.replacingOccurrences(
            of: origStashRule,
            with: "- ^https?://.+ request-replace-regex User-Agent request-replace-regex Accept-Encoding \"^.*$\" \"gzip, deflate\""
        )
        let stashRes = SurgeBrotliShieldHelper.shared.validateShield(content: chainedStash, for: .stash)
        XCTAssertFalse(stashRes.isCompliant)
        XCTAssertFalse(stashRes.hasHeaderRewrite)

        // Stash: legitimate request-replace (1-arg) and quoted URL regex variants must pass
        let requestReplaceStash = validStash.replacingOccurrences(
            of: origStashRule,
            with: "- ^https?://.+ request-replace Accept-Encoding \"gzip, deflate\""
        )
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: requestReplaceStash, for: .stash).isCompliant)

        let quotedURLStash = validStash.replacingOccurrences(
            of: origStashRule,
            with: "- '\"^https?://.+\" request-replace-regex Accept-Encoding \"^.*$\" \"gzip, deflate\"'"
        )
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: quotedURLStash, for: .stash).isCompliant)

        let invalidUnquotedTrailingStash = validStash.replacingOccurrences(
            of: origStashRule,
            with: "- \"^https?://.+\" request-replace-regex Accept-Encoding \"^.*$\" \"gzip, deflate\""
        )
        XCTAssertFalse(SurgeBrotliShieldHelper.shared.validateShield(content: invalidUnquotedTrailingStash, for: .stash).isCompliant)
    }

    // MARK: - 10. Iteration 4 Regressions (A1-A5 JS Lexer, Q1-Q2 QX Regex/Capture, S1-S2 Stash Regex/Cross-Entry)

    func testStashJSForAwaitMemberKeywordPostfixUpdateBraceExprAndUnicodeNewlines() {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        guard let payloadIdx = validStash.range(of: "payload: |") else {
            XCTFail("Missing payload: | in generated Stash shield")
            return
        }
        let headerPart = String(validStash[..<payloadIdx.upperBound])

        // A1: for await (...) followed by RegExp literal must NOT mask nested response:
        let forAwaitBypassJS = """
              async function run() {
                for await (const x of []) /a\\/\\//; $done({ response: {
                  status: 403,
                  headers: {}
                }});
              }
              run();
        """
        let forAwaitBypassRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + forAwaitBypassJS + "\n", for: .stash)
        XCTAssertFalse(forAwaitBypassRes.isCompliant, "for await (...) /a\\/\\// must parse as RegExp so response: is detected")
        XCTAssertFalse(forAwaitBypassRes.hasScriptGuard)

        let legitForAwaitJS = """
              async function run() {
                for await (const x of []) /a\\/\\//.test('a//');
                $done({ status: 403, headers: {} });
              }
              run();
        """
        let legitForAwaitRes = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + legitForAwaitJS + "\n", for: .stash)
        XCTAssertTrue(legitForAwaitRes.isCompliant, "Legitimate for await (...) /a\\/\\// must pass: \(legitForAwaitRes.errors)")

        // A2: Member keywords obj.return, obj.in, obj.of before division must strip /* ... */
        for memberKw in ["return", "in", "of"] {
            let memberBypassJS = """
                  const v = obj.\(memberKw) / 2 /*
                  $done({ status: 403, headers: {} });
                  */
            """
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + memberBypassJS + "\n", for: .stash)
            XCTAssertFalse(res.isCompliant, "obj.\(memberKw) / 2 /* ... */ must strip block comment and reject")
            XCTAssertFalse(res.hasScriptGuard)
        }

        // A3: Postfix ++ / -- before division must strip /* ... */ while spaced + + still allows RegExp
        for op in ["++", "--"] {
            let postfixBypassJS = """
                  let x = 10;
                  const v = x\(op) / 2 /*
                  $done({ status: 403, headers: {} });
                  */
            """
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + postfixBypassJS + "\n", for: .stash)
            XCTAssertFalse(res.isCompliant, "x\(op) / 2 /* ... */ must strip block comment and reject")
            XCTAssertFalse(res.hasScriptGuard)
        }
        let spacedUnaryRegexJS = "      const v = a + + /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });"
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + spacedUnaryRegexJS + "\n", for: .stash).isCompliant)

        // A4: Object literal / function expression closing '}' before division must strip /* ... */,
        // while statement block / function declaration closing '}' allows RegExp
        let objBraceDivJS = """
              const v = {} / 2 /*
              $done({ status: 403, headers: {} });
              */
        """
        XCTAssertFalse(SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + objBraceDivJS + "\n", for: .stash).isCompliant)

        let parenObjBraceDivJS = """
              const y = ({} / 2 /*
              $done({ status: 403, headers: {} });
              */);
        """
        XCTAssertFalse(SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + parenObjBraceDivJS + "\n", for: .stash).isCompliant)

        let fnExprBraceDivJS = """
              const f = function() {} / 2 /*
              $done({ status: 403, headers: {} });
              */
        """
        XCTAssertFalse(SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + fnExprBraceDivJS + "\n", for: .stash).isCompliant)

        let legitBlockRegexJS = "      if (1) {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });"
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + legitBlockRegexJS + "\n", for: .stash).isCompliant)

        let legitFnDeclRegexJS = "      function foo() {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });"
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: headerPart + "\n" + legitFnDeclRegexJS + "\n", for: .stash).isCompliant)

        // A5: Unicode line terminators U+2028 / U+2029 terminate // single-line comments
        let dqHeaderPart = headerPart.replacingOccurrences(of: "payload: |", with: "payload:")
        for (yamlEscape, label) in [("\\u2028", "U+2028"), ("\\u2029", "U+2029")] {
            let bypassYAML = dqHeaderPart + " \"// comment \(yamlEscape) $done({ response: {\\n  status: 403,\\n  headers: {}\\n}});\"\n"
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: bypassYAML, for: .stash)
            XCTAssertFalse(res.isCompliant, "Unicode line separator \(label) must terminate // comment so response: is detected")
            XCTAssertFalse(res.hasScriptGuard)

            let legitYAML = dqHeaderPart + " \"// comment \(yamlEscape) /a\\\\/\\\\//.test('a//'); $done({ status: 403, headers: {} });\"\n"
            let legitRes = SurgeBrotliShieldHelper.shared.validateShield(content: legitYAML, for: .stash)
            XCTAssertTrue(legitRes.isCompliant, "Unicode line separator \(label) must terminate // comment cleanly for valid regex: \(legitRes.errors)")
            XCTAssertTrue(legitRes.hasScriptGuard)
        }
    }

    func testQuantumultXAndStashRegexRewritesAndCrossScriptSpoofingRejected() {
        // Q1 & Q2: Dead regexes, missing capture group for $1, and $1 preserving br must be rejected
        let validQX = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .quantumultX)
        let legitQXRule = "^https?://.+ url request-header (\\r\\n[Aa][Cc][Cc][Ee][Pp][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]:)[^\\r\\n]* request-header $1 gzip, deflate"

        let badQXRules = [
            "^https?://.+ url request-header ^Accept-Encoding:NEVER_MATCHES$ request-header Accept-Encoding: gzip, deflate",
            "^https?://.+ url request-header ^Accept-Encoding:(?!br).* request-header Accept-Encoding: gzip, deflate",
            "^https?://.+ url request-header ^Accept-Encoding:.* request-header $1 gzip, deflate",
            "^https?://.+ url request-header (\\r\\nAccept-Encoding:[^\\r\\n]*) request-header $1 gzip, deflate",
            "^https?://.+ url request-header (\\r\\n[Aa][Cc][Cc][Ee][Pp][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]:[^\\r\\n]*) request-header $1 gzip, deflate"
        ]
        for badRule in badQXRules {
            let tampered = validQX.replacingOccurrences(of: legitQXRule, with: badRule)
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: tampered, for: .quantumultX)
            XCTAssertFalse(res.isCompliant, "QX must reject bad rule: \(badRule)")
            XCTAssertFalse(res.hasHeaderRewrite)
        }

        // S1: Stash dead request-replace-regex patterns rejected; broad matchers accepted
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let origStashRule = "- ^https?://.+ request-replace-regex Accept-Encoding \"^.*$\" \"gzip, deflate\""
        for deadPattern in ["\"^NEVER$\"", "\"^$\"", "\"^gzip$\"", "\"(?i).*br.*\""] {
            let tampered = validStash.replacingOccurrences(
                of: origStashRule,
                with: "- ^https?://.+ request-replace-regex Accept-Encoding \(deadPattern) \"gzip, deflate\""
            )
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: tampered, for: .stash)
            XCTAssertFalse(res.isCompliant, "Stash must reject dead/incomplete pattern \(deadPattern)")
            XCTAssertFalse(res.hasHeaderRewrite)
        }
        for validPattern in ["\"^.*$\"", "\".*\"", "\"(?i).*(?:br|dcb).*\""] {
            let updated = validStash.replacingOccurrences(
                of: origStashRule,
                with: "- ^https?://.+ request-replace-regex Accept-Encoding \(validPattern) \"gzip, deflate\""
            )
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: updated, for: .stash)
            XCTAssertTrue(res.isCompliant, "Stash should accept valid pattern \(validPattern): \(res.errors)")
            XCTAssertTrue(res.hasHeaderRewrite)
        }

        // S2: Stash multi-script cross-entry field spoofing must be rejected
        let spoofedMultiScript = validStash.replacingOccurrences(
            of: """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  timeout: 5
            """,
            with: """
              script:
                - name: decoy-script
                  match: ^https?://.+
                  type: response
                  require-body: false
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: request
                  require-body: true
            """
        )
        let spoofedRes = SurgeBrotliShieldHelper.shared.validateShield(content: spoofedMultiScript, for: .stash)
        XCTAssertFalse(spoofedRes.isCompliant, "Stash must reject cross-entry script: spoofing")
        XCTAssertFalse(spoofedRes.hasScriptGuard)
    }

    // MARK: - 11. Iteration 5 Regressions (Class Extends Heritage, Labeled/Switch Blocks, ASI Debugger/Break, Overfit Regexes, Nested MITM & Quoted YAML Keys)

    func testStashJSClassExtendsLabeledSwitchBlocksAndDebuggerBreakASI() throws {
        let headerPart = try stashHeaderBeforePayload()

        // Sanity check: parseStashYAML terminates payload: | at <= 4 spaces, while validateStashPayloadJS indents >= 6 spaces
        let validMultilineJS = "let a = 1;\nlet b = 2;\n$done({ status: 403, headers: {} });"
        let validMultilineRes = validateStashPayloadJS(validMultilineJS, headerPart: headerPart)
        XCTAssertTrue(validMultilineRes.isCompliant, "Properly 6-space indented multiline Stash JS must pass: \(validMultilineRes.errors)")
        XCTAssertTrue(validMultilineRes.hasScriptGuard)

        let truncatedMultilineYAML = headerPart + "\n      let a = 1;\n      let b = 2;\n    $done({ status: 403, headers: {} });\n"
        let truncatedMultilineRes = SurgeBrotliShieldHelper.shared.validateShield(content: truncatedMultilineYAML, for: .stash)
        XCTAssertFalse(truncatedMultilineRes.isCompliant)
        XCTAssertFalse(truncatedMultilineRes.hasScriptGuard)

        // 1. class ... extends <expr> {} must treat class body {} as statement container,
        //    while class expression const C = class extends <expr> {} treats / 2 as division
        let classDeclBypasses = [
            "class C extends ns.Base {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "class C extends a[0] {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "class C extends (function(){ return Array; }()) {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "class C extends getBase({}) {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "class C extends (A || B) {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});"
        ]
        for js in classDeclBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "class declaration extends expr must reject nested response: in \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let classExprDivJS = """
        const C = class extends ns.Base {} / 2 /*
        $done({ status: 403, headers: {} });
        */
        """
        let classExprDivRes = validateStashPayloadJS(classExprDivJS, headerPart: headerPart)
        XCTAssertFalse(classExprDivRes.isCompliant)
        XCTAssertFalse(classExprDivRes.hasScriptGuard)

        let legitClassDeclJS = "class C extends ns.Base {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });"
        let legitClassDeclRes = validateStashPayloadJS(legitClassDeclJS, headerPart: headerPart)
        XCTAssertTrue(legitClassDeclRes.isCompliant, "Legitimate class extends expr regex must pass: \(legitClassDeclRes.errors)")
        XCTAssertTrue(legitClassDeclRes.hasScriptGuard)

        // 2. Labeled statements & switch case:/default: blocks vs object literals & ternaries
        let colonBlockBypasses = [
            "lbl: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "switch (1) { case 1: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }",
            "switch (2) { default: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }",
            "switch (1) { case ns?.x: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }",
            "switch (1) { case c ? 1 : 2: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }",
            "class C { m() { lbl: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); } }"
        ]
        for js in colonBlockBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Labeled/switch block must not mask response: in \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let objLiteralColonDivJS = """
        const o = { k: {} / 2 /*
        $done({ status: 403, headers: {} });
        */ };
        """
        let objLiteralColonDivRes = validateStashPayloadJS(objLiteralColonDivJS, headerPart: headerPart)
        XCTAssertFalse(objLiteralColonDivRes.isCompliant)
        XCTAssertFalse(objLiteralColonDivRes.hasScriptGuard)

        let ternaryColonDivJS = """
        const t = c ? {} : {} / 2 /*
        $done({ status: 403, headers: {} });
        */;
        """
        let ternaryColonDivRes = validateStashPayloadJS(ternaryColonDivJS, headerPart: headerPart)
        XCTAssertFalse(ternaryColonDivRes.isCompliant)
        XCTAssertFalse(ternaryColonDivRes.hasScriptGuard)

        let legitLabeledBlockJS = "lbl: {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });"
        let legitLabeledBlockRes = validateStashPayloadJS(legitLabeledBlockJS, headerPart: headerPart)
        XCTAssertTrue(legitLabeledBlockRes.isCompliant, "Legitimate labeled block regex must pass: \(legitLabeledBlockRes.errors)")
        XCTAssertTrue(legitLabeledBlockRes.hasScriptGuard)

        let legitSwitchBlockJS = "switch (1) { case 1: {} /a\\/\\//.test('a//'); default: {} /b\\/\\//.test('b//'); } $done({ status: 403, headers: {} });"
        let legitSwitchBlockRes = validateStashPayloadJS(legitSwitchBlockJS, headerPart: headerPart)
        XCTAssertTrue(legitSwitchBlockRes.isCompliant, "Legitimate switch case/default regex must pass: \(legitSwitchBlockRes.errors)")
        XCTAssertTrue(legitSwitchBlockRes.hasScriptGuard)

        // 3. debugger & labeled break/continue ASI
        let asiBypasses = [
            "debugger\n/a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "lbl: { if (0) break lbl\n/a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }",
            "lbl: do { if (0) continue lbl\n/a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); } while (0);"
        ]
        for js in asiBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "debugger/labeled break/continue ASI must detect response: in \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let legitASICases = [
            "debugger\n/a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "lbl: { if (0) break lbl\n/a\\/\\//.test('a//'); } $done({ status: 403, headers: {} });",
            "lbl: do { if (0) continue lbl\n/a\\/\\//.test('a//'); } while (0); $done({ status: 403, headers: {} });"
        ]
        for js in legitASICases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate debugger/break/continue ASI regex must pass: \(res.errors)")
            XCTAssertTrue(res.hasScriptGuard)
        }

        // Plain identifier or member .debugger / .break across newline before / 2 /* ... */ still strips comment and rejects
        for divJS in [
            "let x = 1; x\n/ 2 /*\n$done({ status: 403, headers: {} });\n*/",
            "obj.debugger\n/ 2 /*\n$done({ status: 403, headers: {} });\n*/",
            "obj.break\n/ 2 /*\n$done({ status: 403, headers: {} });\n*/"
        ] {
            let res = validateStashPayloadJS(divJS, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Non-ASI division across newline must strip /* ... */ and reject: \(divJS)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        for legitMemberDivJS in [
            "const a = obj.debugger\n/ 2 // response: fake\n$done({ status: 403, headers: {} });",
            "const b = obj.break\n/ 2 // response: fake\n$done({ status: 403, headers: {} });"
        ] {
            let res = validateStashPayloadJS(legitMemberDivJS, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate member newline division must strip // comment and pass: \(res.errors)")
            XCTAssertTrue(res.hasScriptGuard)
        }
    }

    func testQuantumultXAndStashOverfitRegexesAndStashNestedMITMAndQuotedYAMLKeys() {
        // 1. QX overfit pattern rejecting gzip, br / br, gzip / zstd, br / BR / x-br must be rejected
        let validQX = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .quantumultX)
        let legitQXRule = "^https?://.+ url request-header (\\r\\n[Aa][Cc][Cc][Ee][Pp][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]:)[^\\r\\n]* request-header $1 gzip, deflate"
        let overfitQXRules = [
            "^https?://.+ url request-header (?im)^Accept-Encoding:\\s*(?:br|gzip,\\s*deflate,\\s*br)(?=\\r\\n) request-header Accept-Encoding: gzip, deflate",
            "^https?://.+ url request-header (?im)^Accept-Encoding:\\s*(?:br|gzip,\\s*deflate,\\s*br|gzip,\\s*br|br,\\s*gzip|zstd,\\s*br)(?=\\r\\n) request-header Accept-Encoding: gzip, deflate"
        ]
        for overfit in overfitQXRules {
            let tampered = validQX.replacingOccurrences(of: legitQXRule, with: overfit)
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: tampered, for: .quantumultX)
            XCTAssertFalse(res.isCompliant, "QX must reject overfit regex: \(overfit)")
            XCTAssertFalse(res.hasHeaderRewrite)
        }

        // 2. Stash overfit pattern rejecting gzip, br / br, gzip / zstd, br / BR / x-br must be rejected
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let origStashRule = "- ^https?://.+ request-replace-regex Accept-Encoding \"^.*$\" \"gzip, deflate\""
        let overfitStashPatterns = [
            "\"^(?:br|gzip, deflate, br)$\"",
            "\"^(?:br|gzip, deflate, br|gzip, br|br, gzip|zstd, br|BR)$\""
        ]
        for overfit in overfitStashPatterns {
            let tampered = validStash.replacingOccurrences(
                of: origStashRule,
                with: "- ^https?://.+ request-replace-regex Accept-Encoding \(overfit) \"gzip, deflate\""
            )
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: tampered, for: .stash)
            XCTAssertFalse(res.isCompliant, "Stash must reject overfit regex \(overfit)")
            XCTAssertFalse(res.hasHeaderRewrite)
        }

        // 3. Stash nested http.other.mitm: must NOT satisfy http.mitm:
        let exclusions = SurgeBrotliShieldHelper.mandatoryNegativeExclusions
            .map { "      - \"\($0)\"" }
            .joined(separator: "\n")
        let nestedMITMStash = """
        #!version=1.3.6
        name: "Nested MITM Probe"
        desc: "Test"
        http:
          other:
            mitm:
        \(exclusions)
              - "*.xyz"
          header-rewrite:
            - ^https?://.+ request-replace-regex Accept-Encoding "^.*$" "gzip, deflate"
          script:
            - name: brotli-response-guard
              match: ^https?://.+
              type: response
              require-body: false
        script-providers:
          brotli-response-guard:
            payload: |
              $done({ status: 403, headers: {} });
        """
        let nestedRes = SurgeBrotliShieldHelper.shared.validateShield(content: nestedMITMStash, for: .stash)
        XCTAssertFalse(nestedRes.isCompliant, "Nested http.other.mitm: must be rejected")
        XCTAssertEqual(nestedRes.missingExclusions.count, 16)
        XCTAssertTrue(nestedRes.hasHeaderRewrite)
        XCTAssertTrue(nestedRes.hasScriptGuard)

        // 4. Valid quoted YAML keys in Stash script: entry must be accepted
        let quotedKeysStash = validStash
            .replacingOccurrences(of: "- name: brotli-response-guard", with: "- \"name\": brotli-response-guard")
            .replacingOccurrences(of: "type: response", with: "'type': response")
            .replacingOccurrences(of: "require-body: false", with: "\"require-body\": false")
        let quotedRes = SurgeBrotliShieldHelper.shared.validateShield(content: quotedKeysStash, for: .stash)
        XCTAssertTrue(quotedRes.isCompliant, "Valid quoted YAML keys in Stash script: entry must pass: \(quotedRes.errors)")
        XCTAssertTrue(quotedRes.hasScriptGuard)
    }

    // MARK: - 12. Iteration 6 Regressions (Paren/IIFE Statement Containers, Multiline Block Comment ASI, Class Field `class`, `script-providers:` Nesting & Extended Accept-Encoding Samples)

    func testStashJSParenWrappedStatementContainersAndClassStaticBlocks() throws {
        let headerPart = try stashHeaderBeforePayload()

        // 1. Paren/bracket/template/method-wrapped statement containers must detect nested response:
        let bypassCases = [
            "(function(){ lbl: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();",
            "(function(){ switch (1) { case 1: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); } })();",
            "(function(){ switch (2) { default: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); } })();",
            "(function(){ switch (1) { case c ? a : b: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); } })();",
            "(function(){ const x = 1\n{} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();",
            "(function(){ const x = 1\nclass C {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();",
            "(function(){ const x = 1\nfunction f() {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();",
            "if (0) $done({ status: 403 });\n(function(){ lbl: {} /a\\/\\//; $done({ response: { status: 403, headers: {} } }); })();",
            "(() => { lbl: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();",
            "foo(function(){ lbl: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); });",
            "[function(){ lbl: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }][0]();",
            "`${(function(){ lbl: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })()}`;",
            "({ m() { lbl: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); } }).m();",
            "class C { m() {} static { lbl: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); } }",
            "(function(){ return\n{} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();",
            "(function*(){ yield\n{} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();"
        ]
        for js in bypassCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Paren/static container bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        // 2. Object literal, ternary, and expression-newline division inside paren/bracket containers must strip /* ... */
        let divisionCommentCases = [
            "(function(){ const o = { k: {} / 2 /*\n$done({ status: 403, headers: {} });\n*/ }; })();",
            "(function(){ const t = c ? {} : {} / 2 /*\n$done({ status: 403, headers: {} });\n*/; })();",
            "foo(x\n{ k: 1 } / 2 /*\n$done({ status: 403, headers: {} });\n*/);",
            "[a,\n{ k: 1 } / 2 /*\n$done({ status: 403, headers: {} });\n*/];"
        ]
        for js in divisionCommentCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Expression division dead comment must be stripped and rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        // 3. Legitimate wrapped statement containers + physical Stash shield must pass
        let legitCases = [
            "(function(){ lbl: {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} }); })();",
            "(function(){ switch (1) { case 1: {} /a\\/\\//.test('a//'); default: {} /b\\/\\//.test('b//'); } $done({ status: 403, headers: {} }); })();",
            "(() => { lbl: {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} }); })();",
            "foo(function(){ lbl: {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} }); });",
            "[function(){ lbl: {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} }); }][0]();",
            "`${(function(){ lbl: {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} }); })()}`;",
            "({ m() { lbl: {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} }); } }).m();",
            "class C { m() {} static { lbl: {} /a\\/\\//.test('a//'); } } $done({ status: 403, headers: {} });",
            "(function(){ if (1) return\n{} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} }); })();"
        ]
        for js in legitCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate wrapped container regex must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }

        let physicalStash = try String(
            contentsOf: repoRoot.appendingPathComponent("Shields/Stash/WQGuard-Brotli-Shield.stoverride"),
            encoding: .utf8
        )
        let physicalStashRes = SurgeBrotliShieldHelper.shared.validateShield(content: physicalStash, for: .stash)
        XCTAssertTrue(physicalStashRes.isCompliant, "Physical Stash shield must remain compliant: \(physicalStashRes.errors)")
        XCTAssertTrue(physicalStashRes.hasScriptGuard)
    }

    func testStashJSMultilineBlockCommentASIAndClassFieldNamedClass() throws {
        let headerPart = try stashHeaderBeforePayload()

        // 1. Multiline block comments (/*\n*/, /*\r\n*/, /*\r*/, /*\u{2028}*/, /*\u{2029}*/) act as LineTerminator for ASI
        for sep in ["\n", "\r\n", "\r"] {
            let bypassSnippets = [
                "debugger /*\(sep)*/ /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
                "const x = 1 /*\(sep)*/ {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
                "const x = 1 /*\(sep)*/ class C {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});"
            ]
            for js in bypassSnippets {
                let res = validateStashPayloadJS(js, headerPart: headerPart)
                XCTAssertFalse(res.isCompliant, "Multiline block comment ASI bypass must be rejected: \(js)")
                XCTAssertFalse(res.hasScriptGuard)
            }

            let legitJS = "debugger /*\(sep)*/ /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });"
            let legitRes = validateStashPayloadJS(legitJS, headerPart: headerPart)
            XCTAssertTrue(legitRes.isCompliant, "Legitimate multiline block comment ASI regex must pass: \(legitRes.errors)")
            XCTAssertTrue(legitRes.hasScriptGuard)
        }
        let dqHeaderPart = headerPart.replacingOccurrences(of: "payload: |", with: "payload:")
        for yamlEsc in ["\\u2028", "\\u2029"] {
            let bypassYAMLs = [
                dqHeaderPart + " \"debugger /*\(yamlEsc)*/ /a\\\\/\\\\//; $done({ response: {\\n  status: 403,\\n  headers: {}\\n}});\"\n",
                dqHeaderPart + " \"const x = 1 /*\(yamlEsc)*/ {} /a\\\\/\\\\//; $done({ response: {\\n  status: 403,\\n  headers: {}\\n}});\"\n",
                dqHeaderPart + " \"const x = 1 /*\(yamlEsc)*/ class C {} /a\\\\/\\\\//; $done({ response: {\\n  status: 403,\\n  headers: {}\\n}});\"\n"
            ]
            for yaml in bypassYAMLs {
                let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
                XCTAssertFalse(res.isCompliant, "Multiline block comment ASI bypass (\(yamlEsc)) must be rejected")
                XCTAssertFalse(res.hasScriptGuard)
            }

            let legitYAML = dqHeaderPart + " \"debugger /*\(yamlEsc)*/ /a\\\\/\\\\//.test('a//'); $done({ status: 403, headers: {} });\"\n"
            let legitRes = SurgeBrotliShieldHelper.shared.validateShield(content: legitYAML, for: .stash)
            XCTAssertTrue(legitRes.isCompliant, "Legitimate multiline block comment ASI regex (\(yamlEsc)) must pass: \(legitRes.errors)")
            XCTAssertTrue(legitRes.hasScriptGuard)
        }

        let extraMultilineASIBypasses = [
            "lbl: { if (0) break lbl /*\n*/ /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }",
            "(function(){ return /*\n*/ {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();",
            "(function*(){ yield /*\n*/ {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();"
        ]
        for js in extraMultilineASIBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Multiline block comment break/return/yield ASI bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let singleLineCommentDiv = "let x = 1 /* c */ / 2 / 1; $done({ status: 403, headers: {} });"
        let singleLineDivRes = validateStashPayloadJS(singleLineCommentDiv, headerPart: headerPart)
        XCTAssertTrue(singleLineDivRes.isCompliant, "Single-line block comment division must pass: \(singleLineDivRes.errors)")
        XCTAssertTrue(singleLineDivRes.hasScriptGuard)

        let memberMultilineDiv = "const v = obj.debugger /*\n*/ / 2 /*\n$done({ status: 403, headers: {} });\n*/"
        let memberMultilineDivRes = validateStashPayloadJS(memberMultilineDiv, headerPart: headerPart)
        XCTAssertFalse(memberMultilineDivRes.isCompliant)
        XCTAssertFalse(memberMultilineDivRes.hasScriptGuard)

        // 2. Class field named `class = {}` must prune pendingClassHeaders while preserving legitimate `extends (...)`
        let classFieldCommentBypasses = [
            "class C { static class = {} / 2 /*\n$done({ status: 403, headers: {} });\n*/ }",
            "class C { class = {} / 2 /*\n$done({ status: 403, headers: {} });\n*/ }",
            "class C { static class; x = {} / 2 /*\n$done({ status: 403, headers: {} });\n*/ }"
        ]
        for js in classFieldCommentBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Class field named class = {} dead comment must be stripped and rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let legitClassCases = [
            "class C { static class = {} / 2; m() { $done({ status: 403, headers: {} }); } }",
            "class C extends (x = y) {} $done({ status: 403, headers: {} });",
            "class C extends foo(a = b) {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "class C extends ns?.Base {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });"
        ]
        for js in legitClassCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate class field / extends expression must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }
    }

    func testStashYAMLScriptProvidersNestingAndExtraAcceptEncodingSamples() throws {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let providersMarker = try XCTUnwrap(validStash.range(of: "script-providers:"))
        let prefixBeforeProviders = String(validStash[..<providersMarker.lowerBound])

        // 1. Nested script-providers.other-provider.brotli-response-guard must be rejected
        let nestedProviderYAML = prefixBeforeProviders + """
        script-providers:
          other-provider:
            brotli-response-guard:
              payload: |
                $done({ status: 403, headers: {} });
        """
        let nestedProviderRes = SurgeBrotliShieldHelper.shared.validateShield(content: nestedProviderYAML, for: .stash)
        XCTAssertFalse(nestedProviderRes.isCompliant)
        XCTAssertFalse(nestedProviderRes.hasScriptGuard)
        XCTAssertTrue(nestedProviderRes.hasHeaderRewrite)

        // 2. Sequence-under-mapping (- decoy:) under script-providers: or http: must be rejected
        let decoySeqProviderYAML = prefixBeforeProviders + """
        script-providers:
          - decoy:
            brotli-response-guard:
              payload: |
                $done({ status: 403, headers: {} });
        """
        let decoySeqProviderRes = SurgeBrotliShieldHelper.shared.validateShield(content: decoySeqProviderYAML, for: .stash)
        XCTAssertFalse(decoySeqProviderRes.isCompliant)
        XCTAssertFalse(decoySeqProviderRes.hasScriptGuard)

        let exclusions = SurgeBrotliShieldHelper.mandatoryNegativeExclusions
            .map { "      - \"\($0)\"" }
            .joined(separator: "\n")
        let decoySeqHttpYAML = """
        #!version=1.3.6
        name: "Decoy HTTP Sequence"
        desc: "Test"
        http:
          - decoy:
            mitm:
        \(exclusions)
              - "*.xyz"
            header-rewrite:
              - ^https?://.+ request-replace-regex Accept-Encoding "^.*$" "gzip, deflate"
            script:
              - name: brotli-response-guard
                match: ^https?://.+
                type: response
                require-body: false
        script-providers:
          brotli-response-guard:
            payload: |
              $done({ status: 403, headers: {} });
        """
        let decoySeqHttpRes = SurgeBrotliShieldHelper.shared.validateShield(content: decoySeqHttpYAML, for: .stash)
        XCTAssertFalse(decoySeqHttpRes.isCompliant)

        // 3. Nested brotli-response-guard.meta.payload must be rejected
        let nestedPayloadYAML = prefixBeforeProviders + """
        script-providers:
          brotli-response-guard:
            meta:
              payload: |
                $done({ status: 403, headers: {} });
            url: https://evil.example/a.js
        """
        let nestedPayloadRes = SurgeBrotliShieldHelper.shared.validateShield(content: nestedPayloadYAML, for: .stash)
        XCTAssertFalse(nestedPayloadRes.isCompliant)
        XCTAssertFalse(nestedPayloadRes.hasScriptGuard)

        // 4. Valid sibling other-provider + brotli-response-guard + trailing-provider isolation must pass
        let isolatedSiblingsYAML = prefixBeforeProviders + """
        script-providers:
          other-provider:
            interval: 60
          brotli-response-guard:
            url: https://example.com/a.js
            payload: |
              $done({ status: 403, headers: {} });
          trailing-provider:
            payload: |
              $done({ response: { status: 403 } });
        """
        let isolatedSiblingsRes = SurgeBrotliShieldHelper.shared.validateShield(content: isolatedSiblingsYAML, for: .stash)
        XCTAssertTrue(isolatedSiblingsRes.isCompliant, "Valid sibling providers around brotli-response-guard must pass: \(isolatedSiblingsRes.errors)")
        XCTAssertTrue(isolatedSiblingsRes.hasScriptGuard)

        // 5. Duplicate brotli-response-guard where second omits payload: must be rejected (last-key-wins resets payloadLines)
        let duplicateGuardNoPayloadYAML = prefixBeforeProviders + """
        script-providers:
          brotli-response-guard:
            payload: |
              $done({ status: 403, headers: {} });
          brotli-response-guard:
            url: https://evil.example/a.js
        """
        let duplicateGuardRes = SurgeBrotliShieldHelper.shared.validateShield(content: duplicateGuardNoPayloadYAML, for: .stash)
        XCTAssertFalse(duplicateGuardRes.isCompliant)
        XCTAssertFalse(duplicateGuardRes.hasScriptGuard)

        // 6. Quoted script-providers keys pass; indented other.script-providers is rejected
        let quotedProvidersYAML = prefixBeforeProviders + """
        "script-providers":
          "brotli-response-guard":
            "payload": |
              $done({ status: 403, headers: {} });
        """
        let quotedProvidersRes = SurgeBrotliShieldHelper.shared.validateShield(content: quotedProvidersYAML, for: .stash)
        XCTAssertTrue(quotedProvidersRes.isCompliant, "Quoted script-providers keys must pass: \(quotedProvidersRes.errors)")
        XCTAssertTrue(quotedProvidersRes.hasScriptGuard)

        let indentedProvidersYAML = prefixBeforeProviders + """
        other:
          script-providers:
            brotli-response-guard:
              payload: |
                $done({ status: 403, headers: {} });
        """
        let indentedProvidersRes = SurgeBrotliShieldHelper.shared.validateShield(content: indentedProvidersYAML, for: .stash)
        XCTAssertFalse(indentedProvidersRes.isCompliant)
        XCTAssertFalse(indentedProvidersRes.hasScriptGuard)

        // 7. Extra QX & Stash Accept-Encoding samples ("deflate, br", "zstd, gzip, deflate, br")
        let validQX = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .quantumultX)
        let legitQXRule = "^https?://.+ url request-header (\\r\\n[Aa][Cc][Cc][Ee][Pp][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]:)[^\\r\\n]* request-header $1 gzip, deflate"
        let overfit8QXRule = "^https?://.+ url request-header (?im)^Accept-Encoding:\\s*(?:br|gzip,\\s*deflate,\\s*br|gzip,\\s*br|br,\\s*gzip|zstd,\\s*br|x-br)(?=\\r\\n) request-header Accept-Encoding: gzip, deflate"
        let overfitQXRes = SurgeBrotliShieldHelper.shared.validateShield(
            content: validQX.replacingOccurrences(of: legitQXRule, with: overfit8QXRule),
            for: .quantumultX
        )
        XCTAssertFalse(overfitQXRes.isCompliant)
        XCTAssertFalse(overfitQXRes.hasHeaderRewrite)

        let origStashRule = "- ^https?://.+ request-replace-regex Accept-Encoding \"^.*$\" \"gzip, deflate\""
        let overfit7StashPattern = "\"^(?:(?i)br|gzip, deflate, br|gzip, br|br, gzip|zstd, br|x-br)$\""
        let overfitStashRes = SurgeBrotliShieldHelper.shared.validateShield(
            content: validStash.replacingOccurrences(
                of: origStashRule,
                with: "- ^https?://.+ request-replace-regex Accept-Encoding \(overfit7StashPattern) \"gzip, deflate\""
            ),
            for: .stash
        )
        XCTAssertFalse(overfitStashRes.isCompliant)
        XCTAssertFalse(overfitStashRes.hasHeaderRewrite)

        // Physical QX & Stash shields remain compliant and QX rewrites "deflate, br" and "zstd, gzip, deflate, br"
        let physicalQX = try String(
            contentsOf: repoRoot.appendingPathComponent("Shields/QuantumultX/WQGuard-Brotli-Shield.conf"),
            encoding: .utf8
        )
        let physicalQXRes = SurgeBrotliShieldHelper.shared.validateShield(content: physicalQX, for: .quantumultX)
        XCTAssertTrue(physicalQXRes.isCompliant, "Physical QX shield must pass: \(physicalQXRes.errors)")
        XCTAssertTrue(physicalQXRes.hasHeaderRewrite)

        let ruleLine = try XCTUnwrap(
            physicalQX.split(separator: "\n").map(String.init).first(where: { $0.contains("url request-header") })
        )
        let afterMarker = try XCTUnwrap(ruleLine.components(separatedBy: "url request-header ").last)
        let parts = afterMarker.components(separatedBy: " request-header ")
        XCTAssertEqual(parts.count, 2)
        let qxRegex = try NSRegularExpression(pattern: parts[0], options: [])
        for headerVal in ["deflate, br", "zstd, gzip, deflate, br"] {
            let req = "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: \(headerVal)\r\n\r\n"
            let out = qxRegex.stringByReplacingMatches(
                in: req,
                options: [],
                range: NSRange(req.startIndex..<req.endIndex, in: req),
                withTemplate: parts[1]
            )
            XCTAssertTrue(out.contains("Accept-Encoding: gzip, deflate\r\n"), "QX regex must downgrade \(headerVal): \(out)")
            XCTAssertFalse(out.lowercased().contains("br\r\n"))
        }
    }

    // MARK: - 13. Iteration 7 Regressions (Object-Literal Class Heritage, Sloppy Function Named await/yield/of & Stash YAML Indentation/Duplicate-Key Hardening)

    func testStashJSObjectLiteralClassHeritageAndSloppyAwaitYieldOfFunctions() throws {
        let headerPart = try stashHeaderBeforePayload()

        // 1. Unparenthesized object-literal & function-expression class extends heritage must not break class body detection
        let heritageBypasses = [
            "class C extends { a: B }.a {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "class C extends { a: B }['a'] {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "class C extends { a: B }?.a {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "class C extends new { a: B }.a() {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "async function run() { class C extends await { a: B }.a {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }",
            "function F() { class C extends new.target {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }",
            "const await = class {}; class C extends await {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "class C extends function() { return B; }() {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "const C = class extends { a: B }.a {} / 2 /*\n$done({ status: 403, headers: {} });\n*/"
        ]
        for js in heritageBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Object/function extends heritage bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let legitHeritageCases = [
            "class C extends { a: B }.a {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "class C extends { a: B }['a'] {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "class C extends { a: B }?.a {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "class C extends new { a: B }.a() {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "async function run() { class C extends await { a: B }.a {} /a\\/\\//.test('a//'); } $done({ status: 403, headers: {} });",
            "class C extends (Base) {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "class C extends function() { return B; }() {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });"
        ]
        for js in legitHeritageCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate extends heritage regex must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }

        // 2. Sloppy-mode function / function* named await / yield / of (top-level & IIFE-wrapped)
        let sloppyFuncBypasses = [
            "function* await() {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "function* yield() {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "function await() {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "function yield() {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "function of() {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "(function() { function* await() {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();",
            "(function() { function* yield() {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); })();",
            "let f = function await() {} / 2 /*\n$done({ status: 403, headers: {} });\n*/",
            "let g = function* yield() {} / 2 /*\n$done({ status: 403, headers: {} });\n*/"
        ]
        for js in sloppyFuncBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Sloppy function/generator named await/yield/of bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let legitSloppyFuncs = [
            "function* await() {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "function* yield() {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "function await() {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "function yield() {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "function of() {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "(function() { function* await() {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} }); })();",
            "let f = function await() {} / 2; $done({ status: 403, headers: {} });"
        ]
        for js in legitSloppyFuncs {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate sloppy function/generator regex must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }
    }

    func testStashYAMLStrictScriptMitmIndentationAndDuplicateTopKeys() throws {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let exclusions = SurgeBrotliShieldHelper.mandatoryNegativeExclusions
            .map { "      - \"\($0)\"" }
            .joined(separator: "\n")

        // 1. http.script nested meta: hiding type/require-body must be rejected
        let nestedMetaScript = validStash.replacingOccurrences(
            of: """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  timeout: 5
            """,
            with: """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  meta:
                    type: response
                    require-body: false
            """
        )
        let nestedMetaRes = SurgeBrotliShieldHelper.shared.validateShield(content: nestedMetaScript, for: .stash)
        XCTAssertFalse(nestedMetaRes.isCompliant)
        XCTAssertFalse(nestedMetaRes.hasScriptGuard)

        // 2. http.script nested sub-list must be rejected
        let nestedListScript = validStash.replacingOccurrences(
            of: """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  timeout: 5
            """,
            with: """
              script:
                - other-key:
                    - name: brotli-response-guard
                      match: ^https?://.+
                      type: response
                      require-body: false
            """
        )
        let nestedListRes = SurgeBrotliShieldHelper.shared.validateShield(content: nestedListScript, for: .stash)
        XCTAssertFalse(nestedListRes.isCompliant)
        XCTAssertFalse(nestedListRes.hasScriptGuard)

        // 3. http.mitm nested mapping (bogus:\n      - ...) must be rejected
        let nestedMapMITM = """
        #!version=1.3.6
        name: "Nested MITM Map"
        desc: "Test"
        http:
          mitm:
            bogus:
        \(exclusions)
              - "*.xyz"
          header-rewrite:
            - ^https?://.+ request-replace-regex Accept-Encoding "^.*$" "gzip, deflate"
          script:
            - name: brotli-response-guard
              match: ^https?://.+
              type: response
              require-body: false
        script-providers:
          brotli-response-guard:
            payload: |
              $done({ status: 403, headers: {} });
        """
        let nestedMapMITMRes = SurgeBrotliShieldHelper.shared.validateShield(content: nestedMapMITM, for: .stash)
        XCTAssertFalse(nestedMapMITMRes.isCompliant)
        XCTAssertEqual(nestedMapMITMRes.missingExclusions.count, 16)

        // 4. Duplicate payload: | or payload: "" under brotli-response-guard: overrides earlier payload
        let providersMarker = try XCTUnwrap(validStash.range(of: "script-providers:"))
        let prefixBeforeProviders = String(validStash[..<providersMarker.lowerBound])

        let duplicatePayloadOverride = prefixBeforeProviders + """
        script-providers:
          brotli-response-guard:
            payload: |
              $done({ status: 403, headers: {} });
            payload: |
              // empty override
        """
        let dupPayloadRes = SurgeBrotliShieldHelper.shared.validateShield(content: duplicatePayloadOverride, for: .stash)
        XCTAssertFalse(dupPayloadRes.isCompliant)
        XCTAssertFalse(dupPayloadRes.hasScriptGuard)

        let duplicatePayloadEmptyString = prefixBeforeProviders + """
        script-providers:
          brotli-response-guard:
            payload: |
              $done({ status: 403, headers: {} });
            payload: ""
        """
        let dupPayloadEmptyRes = SurgeBrotliShieldHelper.shared.validateShield(content: duplicatePayloadEmptyString, for: .stash)
        XCTAssertFalse(dupPayloadEmptyRes.isCompliant)
        XCTAssertFalse(dupPayloadEmptyRes.hasScriptGuard)

        // 5. Duplicate top-level script-providers: or http: resets prior section state
        let duplicateTopProviders = validStash + """

        script-providers:
          other-provider:
            payload: |
              $done({ status: 403, headers: {} });
        """
        let dupTopProvidersRes = SurgeBrotliShieldHelper.shared.validateShield(content: duplicateTopProviders, for: .stash)
        XCTAssertFalse(dupTopProvidersRes.isCompliant)
        XCTAssertFalse(dupTopProvidersRes.hasScriptGuard)

        let duplicateTopHttp = validStash + """

        http:
          other: true
        """
        let dupTopHttpRes = SurgeBrotliShieldHelper.shared.validateShield(content: duplicateTopHttp, for: .stash)
        XCTAssertFalse(dupTopHttpRes.isCompliant)
        XCTAssertFalse(dupTopHttpRes.hasHeaderRewrite)
        XCTAssertFalse(dupTopHttpRes.hasScriptGuard)
        XCTAssertEqual(dupTopHttpRes.missingExclusions.count, 16)

        // 6. Positive counterparts: script entry with extra nested meta alongside valid direct keys, and duplicate valid payload: |
        let validExtraMetaScript = validStash.replacingOccurrences(
            of: """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  timeout: 5
            """,
            with: """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  meta:
                    extra: 1
                  timeout: 5
            """
        )
        let validExtraMetaRes = SurgeBrotliShieldHelper.shared.validateShield(content: validExtraMetaScript, for: .stash)
        XCTAssertTrue(validExtraMetaRes.isCompliant, "Valid script entry with sibling meta must pass: \(validExtraMetaRes.errors)")
        XCTAssertTrue(validExtraMetaRes.hasScriptGuard)

        let duplicatePayloadValid = prefixBeforeProviders + """
        script-providers:
          brotli-response-guard:
            payload: |
              // old
            payload: |
              $done({ status: 403, headers: {} });
        """
        let dupPayloadValidRes = SurgeBrotliShieldHelper.shared.validateShield(content: duplicatePayloadValid, for: .stash)
        XCTAssertTrue(dupPayloadValidRes.isCompliant, "Duplicate valid payload: | last-key-wins must pass: \(dupPayloadValidRes.errors)")
        XCTAssertTrue(dupPayloadValidRes.hasScriptGuard)
    }

    // MARK: - 14. Iteration 8 Regressions (Division Regex, Arrow ExpressionBody, Async/new.target Heritage, Header-Rewrite/Script YAML & Payload Key Masking)

    func testStashJSDivisionRegexArrowExpressionBodyAndAsyncAwaitHeritage() throws {
        let headerPart = try stashHeaderBeforePayload()

        // 1. Division `/` allows following RegExp literal (`1 / /a[/*]/`) while chained division (`1 / 2 / 1`) remains valid
        let divRegexBypass = "const r = 1 / /a[/*]/; $done({ response: {\n  status: 403,\n  headers: {}\n}}); return; /*/; $done({ status: 403, headers: {} }); /* */;"
        let divRegexBypassRes = validateStashPayloadJS(divRegexBypass, headerPart: headerPart)
        XCTAssertFalse(divRegexBypassRes.isCompliant)
        XCTAssertFalse(divRegexBypassRes.hasScriptGuard)

        let legitDivRegexCases = [
            "const x = 1 / 2 / 1; $done({ status: 403, headers: {} });",
            "const y = 1 / /a[/*]/.test('a/'); $done({ status: 403, headers: {} });",
            "let z = 1; z /= /a[/*]/.test('a/'); $done({ status: 403, headers: {} });"
        ]
        for js in legitDivRegexCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate division/regex must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }

        // 2. Arrow `=>` ExpressionBody (`function() {}`, `async function() {}`, `class {}`) vs BlockBody (`=> /* c */\n { ... }`)
        let arrowExprBypasses = [
            "const f = x => function() {} /a/*/; $done({ status: 403, headers: {} }); /*/;",
            "const g = x => async function() {} /a/*/; $done({ status: 403, headers: {} }); /*/;",
            "const h = x => class {} /a/*/; $done({ status: 403, headers: {} }); /*/;",
            "const f2 = x => /* c */\n function() {} /a/*/; $done({ status: 403, headers: {} }); /*/;",
            "const b2 = x => /* c */\n { lbl: {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); };"
        ]
        for js in arrowExprBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Arrow ExpressionBody/BlockBody bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let legitArrowCases = [
            "const b1 = x => /* c */\n { lbl: {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} }); };",
            "const b3 = x => function() {} / 2; $done({ status: 403, headers: {} });"
        ]
        for js in legitArrowCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate arrow body must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }

        // 3. `new.target`, `await.a`, `await?.a`, sloppy `extends await {}`, non-async shadowing, and async `extends await { a: B }.a`
        let heritageBypasses = [
            "function F() { class C extends new.target {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }",
            "const await = class {}; class C extends await {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "const await = { a: class {} }; class C extends await.a {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "const await = { a: class {} }; class C extends await?.a {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}});",
            "async function outer() { function inner() { const await = class {}; class C extends await {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); } }",
            "async function outer() { const o = { m() { const await = class {}; class C extends await {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); } }; }",
            "async function* gen() { class C extends await { a: B }.a {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); }",
            "const f = async () => { class C extends await { a: B }.a {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); };",
            "const o = { async m() { class C extends await { a: B }.a {} /a\\/\\//; $done({ response: {\n  status: 403,\n  headers: {}\n}}); } };"
        ]
        for js in heritageBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Heritage bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let legitHeritageCases = [
            "function F() { class C extends new.target {} /a\\/\\//.test('a//'); } $done({ status: 403, headers: {} });",
            "const await = class {}; class C extends await {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "const await = { a: class {} }; class C extends await.a {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "const await = { a: class {} }; class C extends await?.a {} /a\\/\\//.test('a//'); $done({ status: 403, headers: {} });",
            "async function outer() { function inner() { const await = class {}; class C extends await {} /a\\/\\//.test('a//'); } } $done({ status: 403, headers: {} });",
            "async function outer() { class X { m() { const await = class {}; class C extends await {} /a\\/\\//.test('a//'); } } } $done({ status: 403, headers: {} });",
            "const g = async x => { class C extends await { a: B }.a {} /a\\/\\//.test('a//'); }; $done({ status: 403, headers: {} });",
            "class X { async m() { class C extends await { a: B }.a {} /a\\/\\//.test('a//'); } } $done({ status: 403, headers: {} });"
        ]
        for js in legitHeritageCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate heritage regex must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }
    }

    func testStashYAMLStrictHeaderRewriteScriptAndPayloadHeuristicHardening() throws {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let headerPart = try stashHeaderBeforePayload()

        // 1. http.header-rewrite nested map, nested sub-list, and trailing non-list line must be rejected
        let validHeaderRewriteBlock = """
          header-rewrite:
            - ^https?://.+ request-replace-regex Accept-Encoding "^.*$" "gzip, deflate"
        """
        let invalidHeaderRewrites = [
            """
              header-rewrite:
                bogus:
                  - ^https?://.+ request-replace-regex Accept-Encoding "^.*$" "gzip, deflate"
            """,
            """
              header-rewrite:
                - other-key:
                    - ^https?://.+ request-replace-regex Accept-Encoding "^.*$" "gzip, deflate"
            """,
            """
              header-rewrite:
                - ^https?://.+ request-replace-regex Accept-Encoding "^.*$" "gzip, deflate"
                bogus: 1
            """
        ]
        for replacement in invalidHeaderRewrites {
            let yaml = validStash.replacingOccurrences(of: validHeaderRewriteBlock, with: replacement)
            XCTAssertNotEqual(yaml, validStash)
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertFalse(res.isCompliant, "Invalid header-rewrite YAML must be rejected")
            XCTAssertFalse(res.hasHeaderRewrite)
        }

        // 2. http.script `- other-key:\n        name: ...` and trailing `bogus: true` at scriptListIndent must be rejected; bare `-\n      name: ...` remains valid
        let validScriptBlock = """
          script:
            - name: brotli-response-guard
              match: ^https?://.+
              type: response
              require-body: false
              timeout: 5
        """
        let nestedFirstKeyScript = validStash.replacingOccurrences(
            of: validScriptBlock,
            with: """
              script:
                - other-key:
                    name: brotli-response-guard
                    match: ^https?://.+
                    type: response
                    require-body: false
            """
        )
        let nestedFirstKeyRes = SurgeBrotliShieldHelper.shared.validateShield(content: nestedFirstKeyScript, for: .stash)
        XCTAssertFalse(nestedFirstKeyRes.isCompliant)
        XCTAssertFalse(nestedFirstKeyRes.hasScriptGuard)

        let trailingBogusScript = validStash.replacingOccurrences(
            of: validScriptBlock,
            with: """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                bogus: true
            """
        )
        let trailingBogusScriptRes = SurgeBrotliShieldHelper.shared.validateShield(content: trailingBogusScript, for: .stash)
        XCTAssertFalse(trailingBogusScriptRes.isCompliant)
        XCTAssertFalse(trailingBogusScriptRes.hasScriptGuard)

        let bareDashScript = validStash.replacingOccurrences(
            of: validScriptBlock,
            with: """
              script:
                -
                  name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
            """
        )
        let bareDashRes = SurgeBrotliShieldHelper.shared.validateShield(content: bareDashScript, for: .stash)
        XCTAssertTrue(bareDashRes.isCompliant, "Bare `-` script entry must remain valid: \(bareDashRes.errors)")
        XCTAssertTrue(bareDashRes.hasScriptGuard)

        // 3. Computed wrapper keys (`['response']:`, `["body"]:`, `` [`response`]: ``) & string-literal `'status: 403'` must be rejected
        let payloadBypasses = [
            "$done({ ['response']: {\n  status: 403,\n  headers: {}\n}});",
            "$done({ [\"body\"]: {\n  status: 403,\n  headers: {}\n}});",
            "$done({ [`response`]: {\n  status: 403,\n  headers: {}\n}});",
            "const s = 'status: 403'; $done({});",
            "const s = \"status: 403\"; $done({});",
            "const s = `status: 403`; $done({});",
            "const s = `prefix ${1} status: 403`; $done({});"
        ]
        for js in payloadBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Computed wrapper / string-literal status:403 bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let legitPayloadKeys = [
            "$done({ \"status\": 403, headers: {} });",
            "$done({ 'status': 403, headers: {} });",
            "const re = /'/; $done({ status: 403, headers: {} });",
            "const s = 'response: 1'; $done({ status: 403, headers: {} });"
        ]
        for js in legitPayloadKeys {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate quoted status key / regex must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }
    }

    // MARK: - 15. Iteration 9 Regressions (Contextual of/await/yield, Async Private/Numeric/String/Class Methods, Surge/SR type=http-response, Strict Stash YAML & Obfuscated Keys)

    func testStashJSContextualOfAwaitYieldAndAsyncPrivateNumericStringClassMethods() throws {
        let headerPart = try stashHeaderBeforePayload()

        // 1. Contextual `of`, `await`, `yield` must NOT enable RegExp outside valid operator/async/generator contexts
        let contextualBypasses = [
            "const of = 10; const r = of / 2 /*/; $done({ status: 403, headers: {} }); /*/;",
            "const await = 10; const r = await / 2 /*/; $done({ status: 403, headers: {} }); /*/;",
            "const yield = 10; const r = yield / 2 /*/; $done({ status: 403, headers: {} }); /*/;",
            "const of = 10; for (of / 2 /*/; $done({ status: 403, headers: {} }); /*/;;) { break; }",
            "for (let of = 10; of / 2 /*/; $done({ status: 403, headers: {} }); /*/;) { break; }",
            "var yield = 10; function* g() { const f = () => yield / 2 /*/; $done({ status: 403, headers: {} }); /*/; return f(); }",
            "function* g() { function f() { const yield = 10; return yield / 2 /*/; $done({ status: 403, headers: {} }); /*/; } }",
            "async function f() { const g = () => await / 2 /*/; $done({ status: 403, headers: {} }); /*/; }"
        ]
        for js in contextualBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Contextual of/await/yield dead-comment bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let legitContextualCases = [
            "for (const x of /a[/*]/.source) { break; } $done({ status: 403, headers: {} });",
            "let x; for (x of /a[/*]/.source) { break; } $done({ status: 403, headers: {} });",
            "async function f() { for (await x of /a[/*]/.source) { break; } } $done({ status: 403, headers: {} });",
            "for (var of of /a[/*]/.source) { break; } $done({ status: 403, headers: {} });",
            "function* g() { yield /a[/*]/.test('a/'); } $done({ status: 403, headers: {} });",
            "const o = { *m() { yield /a[/*]/.test('a/'); } }; $done({ status: 403, headers: {} });",
            "class X { *m() {} *#n() { yield /a[/*]/.test('a/'); } } $done({ status: 403, headers: {} });",
            "async function* ag() { yield /a[/*]/.test('a/'); } $done({ status: 403, headers: {} });"
        ]
        for js in legitContextualCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate contextual for-of/await/yield regex must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }

        // 2. Async/generator private (#m), numeric (0), string ("m" / 'm'), and `class`-named methods
        let asyncMethodBypasses = [
            "class X { static async #m() { const B = class {}; class C extends await { a: B }.a {} /a[/*]/; $done({ response: {\n  status: 403,\n  headers: {}\n}}); /*/; $done({ status: 403, headers: {} }); /* */; } }",
            "class X { static async 0() { const B = class {}; class C extends await { a: B }.a {} /a[/*]/; $done({ response: {\n  status: 403,\n  headers: {}\n}}); /*/; $done({ status: 403, headers: {} }); /* */; } }",
            "const o = { async 'm'() { const B = class {}; class C extends await { a: B }.a {} /a[/*]/; $done({ response: {\n  status: 403,\n  headers: {}\n}}); /*/; $done({ status: 403, headers: {} }); /* */; } };",
            "const o = { async \"m\"() { const B = class {}; class C extends await { a: B }.a {} /a[/*]/; $done({ response: {\n  status: 403,\n  headers: {}\n}}); /*/; $done({ status: 403, headers: {} }); /* */; } };",
            "const o = { async class() { const B = class {}; class C extends await { a: B }.a {} /a[/*]/; $done({ response: {\n  status: 403,\n  headers: {}\n}}); /*/; $done({ status: 403, headers: {} }); /* */; } };",
            "class X { static async class() { const B = class {}; class C extends await { a: B }.a {} /a[/*]/; $done({ response: {\n  status: 403,\n  headers: {}\n}}); /*/; $done({ status: 403, headers: {} }); /* */; } }"
        ]
        for js in asyncMethodBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Async private/numeric/string/class method bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let legitAsyncAndGenMethods = [
            "class X { static async #m() { const B = class {}; class C extends await { a: B }.a {} /a\\/\\//.test('a//'); } } $done({ status: 403, headers: {} });",
            "class X { static async 0() { const B = class {}; class C extends await { a: B }.a {} /a\\/\\//.test('a//'); } } $done({ status: 403, headers: {} });",
            "const o = { async \"m\"() { const B = class {}; class C extends await { a: B }.a {} /a\\/\\//.test('a//'); } }; $done({ status: 403, headers: {} });",
            "const o = { async class() { const B = class {}; class C extends await { a: B }.a {} /a\\/\\//.test('a//'); } }; $done({ status: 403, headers: {} });",
            "class X { static *#m() { yield /a[/*]/.test('a/'); } } $done({ status: 403, headers: {} });",
            "const o = { *0() { yield /a[/*]/.test('a/'); } }; $done({ status: 403, headers: {} });",
            "const o = { *'m'() { yield /a[/*]/.test('a/'); } }; $done({ status: 403, headers: {} });",
            "const o = { *class() { yield /a[/*]/.test('a/'); } }; $done({ status: 403, headers: {} });",
            "class X { static async *#m() { const B = class {}; yield /a[/*]/.test('a/'); class C extends await { a: B }.a {} /a\\/\\//.test('a//'); } } $done({ status: 403, headers: {} });"
        ]
        for js in legitAsyncAndGenMethods {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate async/generator method must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }
    }

    func testSurgeShadowrocketTypeHttpResponseStashSamplesStrictYAMLAndObfuscatedKeys() throws {
        // 1. Surge & Shadowrocket must require type=http-response
        let validSurge = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .surge)
        let reqPhaseSurge = validSurge.replacingOccurrences(of: "type=http-response", with: "type=http-request")
        let reqSurgeRes = SurgeBrotliShieldHelper.shared.validateShield(content: reqPhaseSurge, for: .surge)
        XCTAssertFalse(reqSurgeRes.isCompliant)
        XCTAssertFalse(reqSurgeRes.hasScriptGuard)

        let validSR = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .shadowrocket)
        let reqPhaseSR = validSR.replacingOccurrences(of: "type=http-response", with: "type=http-request")
        let reqSRRes = SurgeBrotliShieldHelper.shared.validateShield(content: reqPhaseSR, for: .shadowrocket)
        XCTAssertFalse(reqSRRes.isCompliant)
        XCTAssertFalse(reqSRRes.hasScriptGuard)

        // 2. Stash header-rewrite regex must strip brotli, dcb, sbr, and identity, br
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let origStashRule = "- ^https?://.+ request-replace-regex Accept-Encoding \"^.*$\" \"gzip, deflate\""
        let incompleteStashRule = "- ^https?://.+ request-replace-regex Accept-Encoding \"^(?:br|gzip|zstd|BR|x-br|deflate).*$\" \"gzip, deflate\""
        let incompleteStashRes = SurgeBrotliShieldHelper.shared.validateShield(
            content: validStash.replacingOccurrences(of: origStashRule, with: incompleteStashRule),
            for: .stash
        )
        XCTAssertFalse(incompleteStashRes.isCompliant)
        XCTAssertFalse(incompleteStashRes.hasHeaderRewrite)

        let physicalStash = try String(
            contentsOf: repoRoot.appendingPathComponent("Shields/Stash/WQGuard-Brotli-Shield.stoverride"),
            encoding: .utf8
        )
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: physicalStash, for: .stash).isCompliant)

        // 3. Five YAML.safe_load-invalid Stash structures must be rejected
        let validScriptBlock = """
          script:
            - name: brotli-response-guard
              match: ^https?://.+
              type: response
              require-body: false
              timeout: 5
        """
        let scriptTrailingDash = validStash.replacingOccurrences(
            of: validScriptBlock,
            with: """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  - bogus
            """
        )
        XCTAssertFalse(SurgeBrotliShieldHelper.shared.validateShield(content: scriptTrailingDash, for: .stash).hasScriptGuard)

        let scriptMisaligned5Spaces = validStash.replacingOccurrences(
            of: validScriptBlock,
            with: """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                 bogus: 1
            """
        )
        XCTAssertFalse(SurgeBrotliShieldHelper.shared.validateShield(content: scriptMisaligned5Spaces, for: .stash).hasScriptGuard)

        let httpTrailingDash = validStash.replacingOccurrences(
            of: validScriptBlock,
            with: validScriptBlock + "\n  - bogus"
        )
        let httpTrailingDashRes = SurgeBrotliShieldHelper.shared.validateShield(content: httpTrailingDash, for: .stash)
        XCTAssertFalse(httpTrailingDashRes.isCompliant)
        XCTAssertFalse(httpTrailingDashRes.hasHeaderRewrite)

        let providersMarker = try XCTUnwrap(validStash.range(of: "script-providers:"))
        let prefixBeforeProviders = String(validStash[..<providersMarker.lowerBound])

        let providersTrailingDash = prefixBeforeProviders + """
        script-providers:
          brotli-response-guard:
            payload: |
              $done({ status: 403, headers: {} });
          - bogus
        """
        XCTAssertFalse(SurgeBrotliShieldHelper.shared.validateShield(content: providersTrailingDash, for: .stash).hasScriptGuard)

        let payloadUnderindented = prefixBeforeProviders + """
        script-providers:
          brotli-response-guard:
            payload: |
                  $done({ status: 403, headers: {} });
              bogus: 1
        """
        XCTAssertFalse(SurgeBrotliShieldHelper.shared.validateShield(content: payloadUnderindented, for: .stash).hasScriptGuard)

        // Valid sibling http.url-rewrite list remains accepted
        let validWithUrlRewrite = validStash.replacingOccurrences(
            of: "http:\n",
            with: "http:\n  url-rewrite:\n    - ^https?://example\\.com/a - reject\n"
        )
        let validUrlRewriteRes = SurgeBrotliShieldHelper.shared.validateShield(content: validWithUrlRewrite, for: .stash)
        XCTAssertTrue(validUrlRewriteRes.isCompliant, "Valid http.url-rewrite sibling list must pass: \(validUrlRewriteRes.errors)")

        // 4. Obfuscated wrapper keys, /status: 403/ RegExp, and ternary/switch 'status'
        let headerPart = try stashHeaderBeforePayload()
        let obfuscatedBypasses = [
            "const re = /status: 403/; $done({});",
            "const x = true ? 'status' : 403; $done({});",
            "switch('a') { case 'status': 403; } $done({});",
            "$done({ res\\u0070onse: {\n  status: 403,\n  headers: {}\n}});",
            "$done({ 'res\\x70onse': {\n  status: 403,\n  headers: {}\n}});",
            "$done({ \"b\\u{6f}dy\": {\n  status: 403,\n  headers: {}\n}});",
            "$done({ ['resp' + 'onse']: {\n  status: 403,\n  headers: {}\n}});",
            "$done({ [`${'response'}`]: {\n  status: 403,\n  headers: {}\n}});",
            "const r = { status: 403, headers: {} }; $done({ ['resp' + 'onse']: r });"
        ]
        for js in obfuscatedBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Obfuscated wrapper / regex / ternary-switch bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let legitDynamicKeys = [
            "const k = 'x'; $done({ [k]: 1, status: 403, headers: {} });",
            "const h = 'X-Test'; $done({ status: 403, headers: { [h]: '1' } });",
            "$done({ 'status': 403, headers: {} });",
            "const m = { [k]() { $done({ status: 403, headers: {} }); } };"
        ]
        for js in legitDynamicKeys {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate flat dynamic key / method must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }
    }

    // MARK: - 16. Iteration 10 Regressions (Template-Interpolation Folding, Class Field ASI Generator, Strict Stash Nested meta: & Block Scalar Header)

    func testGate9TemplateKeyFoldingClassFieldASIGeneratorAndStrictYAML() throws {
        let headerPart = try stashHeaderBeforePayload()

        // 1. Variable-bound template-interpolation computed keys must be folded and rejected
        let tmplRefBypasses = [
            "const r = { status: 403, headers: {} }; $done({ [`${'response'}`]: r });",
            "const r = { status: 403, headers: {} }; $done({ [`${'res' + 'ponse'}`]: r });",
            "const r = { status: 403, headers: {} }; $done({ [`res${`pon`}se`]: r });",
            "const r = { status: 403, headers: {} }; $done({ [`res${'p'}onse`]: r });",
            "const r = { status: 403, headers: {} }; $done({ ['resp' + `${'onse'}`]: r });",
            "const r = { status: 403, headers: {} }; $done({ [`${'bo' + `dy`}`]: r });"
        ]
        for js in tmplRefBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Variable-bound template-interpolation computed key must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let tmplBenignCases = [
            "const k = 'x'; $done({ [`${k}`]: 1, status: 403, headers: {} });",
            "$done({ [`${'k'}`]: 1, status: 403, headers: {} });",
            "const k = 'response'; $done({ [`${k}`]: 1, status: 403, headers: {} });"
        ]
        for js in tmplBenignCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Benign template-interpolation computed key must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }

        // 2. Uninitialized class field + newline ASI must preserve generator body tracking on *m() / *n(),
        //    while `a = 1 * 2` multiplication must NOT mark subsequent methods as generators
        let classFieldGenBypasses = [
            "class X { a\n *m() { yield /a[/*]/; $done({ response: {\n  status: 403,\n  headers: {}\n}}); /*/; $done({ status: 403, headers: {} }); /* */; } }",
            "class X { a\n *n() { yield /a[/*]/; $done({ response: {\n  status: 403,\n  headers: {}\n}}); /*/; $done({ status: 403, headers: {} }); /* */; } }",
            "function f() { const yield = 1; return yield / 2 /*/; $done({ status: 403, headers: {} }); /*/; }",
            "class X { a = 1 * 2; m() { const a = 1; return a / 2 /*/; $done({ status: 403, headers: {} }); /*/; } }"
        ]
        for js in classFieldGenBypasses {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertFalse(res.isCompliant, "Class field ASI generator / multiplication-method bypass must be rejected: \(js)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let classFieldGenLegitCases = [
            "class X { a\n *m() { yield /a[/*]/.test('a/'); } } $done({ status: 403, headers: {} });",
            "class X { a\n *n() { yield /a[/*]/.test('a/'); } } $done({ status: 403, headers: {} });",
            "class X { async\n *m() { yield /a[/*]/.test('a/'); } } $done({ status: 403, headers: {} });",
            "class X { a = 1 * 2; m() { return /a[/*]/.test('a/'); } } $done({ status: 403, headers: {} });"
        ]
        for js in classFieldGenLegitCases {
            let res = validateStashPayloadJS(js, headerPart: headerPart)
            XCTAssertTrue(res.isCompliant, "Legitimate class field ASI generator / multiplication must pass: \(res.errors) for \(js)")
            XCTAssertTrue(res.hasScriptGuard)
        }

        // 3. Strict Stash YAML: http.script & script-providers nested meta: sub-mappings and payload: block scalar headers
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let validScriptBlock = """
          script:
            - name: brotli-response-guard
              match: ^https?://.+
              type: response
              require-body: false
              timeout: 5
        """
        let invalidScriptMetaCases = [
            """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  meta:
                    extra: 1
                    - bogus
                  timeout: 5
            """,
            """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  meta:
                    extra: 1
                      bad: 2
                  timeout: 5
            """,
            """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  meta:
                    tags:
                      - a
                    - bogus
                  timeout: 5
            """
        ]
        for replacement in invalidScriptMetaCases {
            let yaml = validStash.replacingOccurrences(of: validScriptBlock, with: replacement)
            XCTAssertNotEqual(yaml, validStash)
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertFalse(res.isCompliant, "Invalid http.script nested meta: YAML must be rejected")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let validScriptMetaCases = [
            """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  meta:
                    tags:
                      - a
                  timeout: 5
            """,
            """
              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  meta:
                    extra: 1
                    tags:
                      - a
                    other: 2
                  timeout: 5
            """
        ]
        for replacement in validScriptMetaCases {
            let yaml = validStash.replacingOccurrences(of: validScriptBlock, with: replacement)
            XCTAssertNotEqual(yaml, validStash)
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertTrue(res.isCompliant, "Valid http.script nested meta: YAML must pass: \(res.errors)")
            XCTAssertTrue(res.hasScriptGuard)
        }

        let providersMarker = try XCTUnwrap(validStash.range(of: "script-providers:"))
        let prefixBeforeProviders = String(validStash[..<providersMarker.lowerBound])

        let invalidProviderCases = [
            prefixBeforeProviders + """
            script-providers:
              brotli-response-guard:
                payload: |
                  $done({ status: 403, headers: {} });
                meta:
                  extra: 1
                  - bogus
            """,
            prefixBeforeProviders + """
            script-providers:
              brotli-response-guard:
                payload: |
                  $done({ status: 403, headers: {} });
                meta:
                  extra: 1
                    bad: 2
            """,
            prefixBeforeProviders + """
            script-providers:
              brotli-response-guard:
                payload: | foo
                  $done({ status: 403, headers: {} });
            """,
            prefixBeforeProviders + """
            script-providers:
              brotli-response-guard:
                payload: |0
                  $done({ status: 403, headers: {} });
            """,
            prefixBeforeProviders + """
            script-providers:
              brotli-response-guard:
                payload: |10
                  $done({ status: 403, headers: {} });
            """
        ]
        for yaml in invalidProviderCases {
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertFalse(res.isCompliant, "Invalid script-providers YAML / block scalar header must be rejected:\n\(yaml)")
            XCTAssertFalse(res.hasScriptGuard)
        }

        let validProviderCases = [
            prefixBeforeProviders + """
            script-providers:
              brotli-response-guard:
                payload: |
                  $done({ status: 403, headers: {} });
                meta:
                  extra: 1
                  tags:
                    - a
                  other: 2
            """,
            prefixBeforeProviders + """
            script-providers:
              brotli-response-guard:
                payload: |- # ok
                  $done({ status: 403, headers: {} });
            """,
            prefixBeforeProviders + """
            script-providers:
              brotli-response-guard:
                payload: |+2 # ok
                  $done({ status: 403, headers: {} });
            """
        ]
        for yaml in validProviderCases {
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertTrue(res.isCompliant, "Valid script-providers nested meta: / block scalar header must pass: \(res.errors)")
            XCTAssertTrue(res.hasScriptGuard)
        }
    }

    // MARK: - 17. Iteration 11 Regressions (Explicit YAML Block Scalar Indentation |1-|9 and Blank-Line Semantics)

    func testGate10ExplicitBlockScalarIndentAndBlankLineYAML() throws {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let providersMarker = try XCTUnwrap(validStash.range(of: "script-providers:"))
        let prefixBeforeProviders = String(validStash[..<providersMarker.lowerBound])

        let invalidYAMLFixtures: [(String, String)] = [
            (
                "pipe4_at_indent4_with_6space_payload",
                prefixBeforeProviders + """
                script-providers:
                  brotli-response-guard:
                    payload: |4
                      $done({ status: 403, headers: {} });
                """
            ),
            (
                "pipe2_at_indent6_with_7space_payload",
                prefixBeforeProviders + """
                script-providers:
                    brotli-response-guard:
                      payload: |2
                       $done({ status: 403, headers: {} });
                """
            ),
            (
                "pipe2_at_indent4_line1_8_line2_5",
                prefixBeforeProviders + """
                script-providers:
                  brotli-response-guard:
                    payload: |2
                        const x = 1;
                     $done({ status: 403, headers: {} });
                """
            ),
            (
                "pipe_plus2_at_indent4_with_5space_payload",
                prefixBeforeProviders + """
                script-providers:
                  brotli-response-guard:
                    payload: |+2
                     $done({ status: 403, headers: {} });
                """
            ),
            (
                "pipe_2minus_at_indent4_with_5space_payload",
                prefixBeforeProviders + """
                script-providers:
                  brotli-response-guard:
                    payload: |2-
                     $done({ status: 403, headers: {} });
                """
            ),
            (
                "pipe_auto_leading_8space_blank_then_6space_payload",
                prefixBeforeProviders
                    + "script-providers:\n"
                    + "  brotli-response-guard:\n"
                    + "    payload: |\n"
                    + String(repeating: " ", count: 8) + "\n"
                    + "      $done({ status: 403, headers: {} });\n"
            ),
            (
                "pipe_auto_leading_spaces_plus_tab_blank_then_6space_payload",
                prefixBeforeProviders
                    + "script-providers:\n"
                    + "  brotli-response-guard:\n"
                    + "    payload: |\n"
                    + "     \t\n"
                    + "      $done({ status: 403, headers: {} });\n"
            ),
            (
                "pipe2_at_indent4_with_5space_comment_before_6space_payload",
                prefixBeforeProviders + """
                script-providers:
                  brotli-response-guard:
                    payload: |2
                     # comment ends empty block scalar
                      $done({ status: 403, headers: {} });
                """
            )
        ]

        for (name, yaml) in invalidYAMLFixtures {
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertFalse(res.isCompliant, "Invalid explicit-indent/blank-line Stash YAML must be rejected [\(name)]")
            XCTAssertFalse(res.hasScriptGuard, "hasScriptGuard must be false [\(name)]")
        }

        let validYAMLFixtures: [(String, String)] = [
            (
                "pipe4_at_indent4_with_8space_payload",
                prefixBeforeProviders + """
                script-providers:
                  brotli-response-guard:
                    payload: |4
                        $done({ status: 403, headers: {} });
                """
            ),
            (
                "pipe2_at_indent4_line1_8_line2_6",
                prefixBeforeProviders + """
                script-providers:
                  brotli-response-guard:
                    payload: |2
                        const x = 1;
                      $done({ status: 403, headers: {} });
                """
            ),
            (
                "pipe2_at_indent6_with_8space_payload",
                prefixBeforeProviders + """
                script-providers:
                    brotli-response-guard:
                      payload: |2
                        $done({ status: 403, headers: {} });
                """
            ),
            (
                "pipe_plus2_at_indent4_line1_8_line2_6",
                prefixBeforeProviders + """
                script-providers:
                  brotli-response-guard:
                    payload: |+2 # ok
                        const x = 1;
                      $done({ status: 403, headers: {} });
                """
            ),
            (
                "pipe_2minus_at_indent4_line1_8_line2_6",
                prefixBeforeProviders + """
                script-providers:
                  brotli-response-guard:
                    payload: |2- # ok
                        const x = 1;
                      $done({ status: 403, headers: {} });
                """
            ),
            (
                "pipe2_at_indent4_leading_10space_blank_then_6space_payload",
                prefixBeforeProviders
                    + "script-providers:\n"
                    + "  brotli-response-guard:\n"
                    + "    payload: |2\n"
                    + String(repeating: " ", count: 10) + "\n"
                    + "      $done({ status: 403, headers: {} });\n"
            ),
            (
                "pipe_auto_leading_5space_blank_then_6space_payload",
                prefixBeforeProviders
                    + "script-providers:\n"
                    + "  brotli-response-guard:\n"
                    + "    payload: |\n"
                    + String(repeating: " ", count: 5) + "\n"
                    + "      $done({ status: 403, headers: {} });\n"
            ),
            (
                "pipe2_at_indent4_6space_payload_then_5space_comment_then_meta",
                prefixBeforeProviders + """
                script-providers:
                  brotli-response-guard:
                    payload: |2
                      $done({ status: 403, headers: {} });
                     # trailing comment
                    meta:
                      a: 1
                """
            )
        ]

        for (name, yaml) in validYAMLFixtures {
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertTrue(res.isCompliant, "Valid explicit-indent/blank-line Stash YAML must pass [\(name)]: \(res.errors)")
            XCTAssertTrue(res.hasScriptGuard, "hasScriptGuard must be true [\(name)]")
        }
    }
}
