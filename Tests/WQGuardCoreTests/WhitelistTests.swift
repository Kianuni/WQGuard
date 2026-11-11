//
//  WhitelistTests.swift
//  WQGuardCoreTests
//
//  Unit tests covering exact matches, prefix matches, glob wildcards,
//  false-positive prevention, custom rule addition, and thread safety.
//

import XCTest
@testable import WQGuardCore

final class WhitelistTests: XCTestCase {

    var engine: WhitelistEngine!

    override func setUp() {
        super.setUp()
        // Instantiate fresh isolated engine for each test case
        engine = WhitelistEngine()
    }

    override func tearDown() {
        engine = nil
        super.tearDown()
    }

    // MARK: - 1. Default Built-in Tools Verification

    func testDefaultToolsCountAndIdentities() {
        let tools = engine.allTools
        XCTAssertEqual(tools.count, 6, "Expected exactly 6 default built-in tools")
        
        let toolNames = Set(tools.map { $0.name })
        let expectedNames: Set<String> = [
            "Erosion",
            "Erosion-CN",
            "GestaltX",
            "WQFiles",
            "WQFiles-CN",
            "WQGuard"
        ]
        XCTAssertEqual(toolNames, expectedNames)
        
        for tool in tools {
            XCTAssertTrue(tool.isEnabled, "\(tool.name) should be enabled by default")
            XCTAssertTrue(tool.isBuiltIn, "\(tool.name) should be marked as built-in")
        }
    }

    // MARK: - 2. Exact Match Tests

    func testExactMatchErosion() {
        let result = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"],
            matchedSignatures: ["container_query_create", "libsystem_containermanager.dylib"]
        )
        XCTAssertTrue(result.isWhitelisted)
        XCTAssertEqual(result.toolName, "Erosion")
    }

    func testExactMatchWQFiles() {
        let result = engine.isWhitelisted(
            bundleId: "cz.kolbi.wqfiles",
            appGroups: ["group.cz.kolbi.wqfiles"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertTrue(result.isWhitelisted)
        XCTAssertEqual(result.toolName, "WQFiles")
    }

    func testExactMatchWQGuard() {
        let result = engine.isWhitelisted(
            bundleId: "com.antigravity.wqguard",
            appGroups: ["group.com.wqguard.scanner"],
            matchedSignatures: []
        )
        XCTAssertTrue(result.isWhitelisted)
        XCTAssertEqual(result.toolName, "WQGuard")
    }

    // MARK: - 3. Prefix Match Tests

    func testPrefixMatchErosionCN() {
        let result1 = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion-CN",
            appGroups: ["group.com.jbdotparty.Erosion-CN"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertTrue(result1.isWhitelisted)
        XCTAssertEqual(result1.toolName, "Erosion-CN")

        let result2 = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion.LocalBuild",
            appGroups: ["group.com.jbdotparty.Erosion.Testing"],
            matchedSignatures: []
        )
        XCTAssertTrue(result2.isWhitelisted)
        XCTAssertEqual(result2.toolName, "Erosion-CN")
    }

    func testPrefixMatchWQFilesCN() {
        let result = engine.isWhitelisted(
            bundleId: "cz.kolbi.wqfiles.cn",
            appGroups: ["group.cz.kolbi.wqfiles.cn"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertTrue(result.isWhitelisted)
        XCTAssertEqual(result.toolName, "WQFiles-CN")
    }

    // MARK: - 4. Wildcard / Glob Matches

    func testWildcardMatchGestaltX() {
        let result1 = engine.isWhitelisted(
            bundleId: "com.straight-tamago.gestaltx",
            appGroups: ["group.straight-tamago.gestaltx"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertTrue(result1.isWhitelisted)
        XCTAssertEqual(result1.toolName, "GestaltX")

        let result2 = engine.isWhitelisted(
            bundleId: "com.randomdev.gestaltx",
            appGroups: ["group.randomdev.gestaltx"],
            matchedSignatures: []
        )
        XCTAssertTrue(result2.isWhitelisted)
        XCTAssertEqual(result2.toolName, "GestaltX")
    }

    // MARK: - 5. False-Positive & Impersonation Prevention Tests

    func testImpersonationBundleWithoutAppGroup() {
        // Attacker uses Erosion bundle ID but rogue App Group
        let result = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.attacker.malicious"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertFalse(result.isWhitelisted, "Spoofed App Group must NOT be whitelisted")
        XCTAssertNil(result.toolName)
    }

    func testImpersonationAppGroupWithoutBundle() {
        // Attacker uses Erosion App Group but rogue bundle ID
        let result = engine.isWhitelisted(
            bundleId: "com.attacker.evilapp",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertFalse(result.isWhitelisted, "Spoofed Bundle ID must NOT be whitelisted")
        XCTAssertNil(result.toolName)
    }

    func testMissingAppGroupWhenRequired() {
        // Candidate has WQFiles bundle ID but empty App Groups
        let result = engine.isWhitelisted(
            bundleId: "cz.kolbi.wqfiles",
            appGroups: [],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertFalse(result.isWhitelisted, "Missing App Group must fail match for tools requiring App Groups")
        XCTAssertNil(result.toolName)
    }

    func testUnrelatedBenignApp() {
        let result = engine.isWhitelisted(
            bundleId: "com.apple.mobilesafari",
            appGroups: ["group.com.apple.safari"],
            matchedSignatures: []
        )
        XCTAssertFalse(result.isWhitelisted)
        XCTAssertNil(result.toolName)
    }

    func testCaseInsensitiveNormalization() {
        let result = engine.isWhitelisted(
            bundleId: "COM.JBDOTPARTY.EROSION",
            appGroups: ["GROUP.COM.JBDOTPARTY.EROSION.WQ"],
            matchedSignatures: []
        )
        XCTAssertTrue(result.isWhitelisted, "Matching must be case-insensitive")
        XCTAssertEqual(result.toolName, "Erosion")
    }

    // MARK: - 6. Custom Tool Registration & Mutation

    func testRegisterCustomTool() {
        let customTool = WhitelistedTool(
            name: "InternalAuditUtility",
            allowedBundleIds: ["com.mycompany.audit*"],
            allowedAppGroups: ["group.mycompany.audit"],
            description: "Custom internal company scanner",
            isEnabled: true,
            isBuiltIn: false
        )
        engine.registerCustomTool(customTool)

        let result = engine.isWhitelisted(
            bundleId: "com.mycompany.audit.tool",
            appGroups: ["group.mycompany.audit"]
        )
        XCTAssertTrue(result.isWhitelisted)
        XCTAssertEqual(result.toolName, "InternalAuditUtility")
    }

    func testCustomToolTeamIdEnforcement() {
        let restrictedTool = WhitelistedTool(
            name: "EnterpriseRestrictedTool",
            allowedBundleIds: ["com.enterprise.sec"],
            allowedAppGroups: ["group.enterprise.sec"],
            allowedTeamIds: ["TEAM123456"],
            description: "Tool signed exclusively by authorized enterprise team"
        )
        engine.registerCustomTool(restrictedTool)

        // Matching Team ID
        let validResult = engine.isWhitelisted(
            bundleId: "com.enterprise.sec",
            appGroups: ["group.enterprise.sec"],
            teamId: "TEAM123456"
        )
        XCTAssertTrue(validResult.isWhitelisted)
        XCTAssertEqual(validResult.toolName, "EnterpriseRestrictedTool")

        // Rogue Team ID
        let invalidTeamResult = engine.isWhitelisted(
            bundleId: "com.enterprise.sec",
            appGroups: ["group.enterprise.sec"],
            teamId: "ROGUE99999"
        )
        XCTAssertFalse(invalidTeamResult.isWhitelisted)

        // Missing Team ID
        let missingTeamResult = engine.isWhitelisted(
            bundleId: "com.enterprise.sec",
            appGroups: ["group.enterprise.sec"],
            teamId: nil
        )
        XCTAssertFalse(missingTeamResult.isWhitelisted)
    }

    // MARK: - 7. Rule Toggling & Reset

    func testToggleRule() {
        // Disable Erosion
        engine.toggleTool(named: "Erosion", isEnabled: false)

        let disabledResult = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        XCTAssertFalse(disabledResult.isWhitelisted, "Disabled tool must not match")

        // Re-enable Erosion
        engine.toggleTool(named: "Erosion", isEnabled: true)

        let enabledResult = engine.isWhitelisted(
            bundleId: "com.jbdotparty.Erosion",
            appGroups: ["group.com.jbdotparty.Erosion.WQ"]
        )
        XCTAssertTrue(enabledResult.isWhitelisted)
        XCTAssertEqual(enabledResult.toolName, "Erosion")
    }

    func testRemoveTool() {
        engine.registerCustomTool(WhitelistedTool(
            name: "TemporaryTool",
            allowedBundleIds: ["com.temp.tool"]
        ))
        XCTAssertNotNil(engine.tool(named: "TemporaryTool"))

        engine.removeTool(named: "TemporaryTool")
        XCTAssertNil(engine.tool(named: "TemporaryTool"))
    }

    func testResetToDefaults() {
        // Mutate engine state
        engine.registerCustomTool(WhitelistedTool(name: "TempCustom", allowedBundleIds: ["com.temp"]))
        engine.toggleTool(named: "WQFiles", isEnabled: false)

        XCTAssertEqual(engine.allTools.count, 7)
        XCTAssertFalse(engine.tool(named: "WQFiles")!.isEnabled)

        // Reset
        engine.resetToDefaults()

        XCTAssertEqual(engine.allTools.count, 6)
        XCTAssertTrue(engine.tool(named: "WQFiles")!.isEnabled)
        XCTAssertNil(engine.tool(named: "TempCustom"))
    }

    // MARK: - 8. Thread-Safe Concurrency Test

    @MainActor
    func testThreadSafeConcurrentLookupsAndMutations() {
        let iterations = 1000
        let exp = expectation(description: "Concurrent lookups completed")
        exp.expectedFulfillmentCount = iterations
        guard let engine = self.engine else { return }

        DispatchQueue.concurrentPerform(iterations: iterations) { i in
            if i % 10 == 0 {
                engine.registerCustomTool(WhitelistedTool(
                    name: "ConcurrentTool_\(i)",
                    allowedBundleIds: ["com.concurrent.\(i)"],
                    allowedAppGroups: ["group.concurrent.\(i)"]
                ))
            } else if i % 15 == 0 {
                engine.toggleTool(named: "Erosion", isEnabled: (i % 2 == 0))
            } else if i % 50 == 0 {
                engine.resetToDefaults()
            } else {
                _ = engine.isWhitelisted(
                    bundleId: "cz.kolbi.wqfiles",
                    appGroups: ["group.cz.kolbi.wqfiles"],
                    matchedSignatures: ["container_query_create"]
                )
            }
            exp.fulfill()
        }

        waitForExpectations(timeout: 10.0)
    }

    // MARK: - 9. Codable Persistence Test

    func testWhitelistedToolCodableRoundTrip() throws {
        let original = WhitelistedTool(
            name: "TestTool",
            allowedBundleIds: ["com.test.*"],
            allowedAppGroups: ["group.test"],
            allowedTeamIds: ["TEAM1"],
            expectedSignatures: ["sig1", "sig2"],
            description: "Test description",
            isEnabled: true,
            isBuiltIn: false
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(original)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(WhitelistedTool.self, from: data)

        XCTAssertEqual(original, decoded)
    }

    // MARK: - 10. WQGuard Identity & Anti-Spoofing Tests

    func testWQGuard_cleanIdentity_matchesWhitelist() {
        let result = engine.isWhitelisted(
            bundleId: "com.wqguard.app",
            appGroups: ["group.com.wqguard.app"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertTrue(result.isWhitelisted)
        XCTAssertEqual(result.toolName, "WQGuard")
    }

    func testWQGuard_prefixWildcard_matchesDebugBuild() {
        let result = engine.isWhitelisted(
            bundleId: "com.wqguard.app.debug",
            appGroups: ["group.com.wqguard.app"],
            matchedSignatures: []
        )
        XCTAssertTrue(result.isWhitelisted)
        XCTAssertEqual(result.toolName, "WQGuard")
    }

    func testWQGuard_legacyAntigravity_matchesWhitelist() {
        let result = engine.isWhitelisted(
            bundleId: "com.antigravity.wqguard",
            appGroups: ["group.com.wqguard.scanner"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertTrue(result.isWhitelisted)
        XCTAssertEqual(result.toolName, "WQGuard")
    }

    func testWQGuard_spoofedBundleId_rejectedWithoutAppGroup() {
        let result = engine.isWhitelisted(
            bundleId: "com.wqguard.app",
            appGroups: ["group.attacker.evil"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertFalse(result.isWhitelisted, "Must reject spoofed bundle ID if App Group does not match")
        XCTAssertNil(result.toolName)
    }

    func testWQGuard_spoofedAppGroup_rejectedWithoutBundleId() {
        let result = engine.isWhitelisted(
            bundleId: "com.attacker.evil",
            appGroups: ["group.com.wqguard.app"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertFalse(result.isWhitelisted, "Must reject spoofed App Group if bundle ID does not match")
        XCTAssertNil(result.toolName)
    }
}
