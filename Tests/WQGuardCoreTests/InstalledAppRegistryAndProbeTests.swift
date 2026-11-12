//
//  InstalledAppRegistryAndProbeTests.swift
//  WQGuardCoreTests
//
//  Comprehensive unit tests for WQGuard v1.1.0 Installed App Security Scanner:
//  - Option 1: `installation_proxy` Plist/JSON Snapshot Parser & Registry Entitlements Evaluator
//  - Option 1 Direct: `.mobiledevicepairing` parser & PKCS#8 RSA key unwrapping
//  - Option 3: `OnDeviceAppProbeScanner` URL-scheme presence probe catalog
//  - Dual-Engine Correlation (`SecurityPipeline.correlateAndMergeFindings`)
//

import XCTest
@testable import WQGuardCore

final class InstalledAppRegistryAndProbeTests: XCTestCase {

    // MARK: - 1. installation_proxy XML Plist & JSON Snapshot Parsing

    func testParseInstProxyXMLPlistAndEvaluateThreats() throws {
        let rawApps: [[String: Any]] = [
            // 1. Official App Store MetaMask (must be skipped by default or marked Safe)
            [
                "CFBundleIdentifier": "io.metamask.MetaMask",
                "CFBundleDisplayName": "MetaMask",
                "CFBundleShortVersionString": "7.15.0",
                "ApplicationType": "User",
                "SignerIdentity": "Apple iPhone OS Application Signing",
                "ProfileValidated": false,
                "ApplicationDSID": 1234567890,
                "Entitlements": [
                    "application-identifier": "ABCD123456.io.metamask.MetaMask"
                ]
            ],
            // 2. Malicious Enterprise Repackaged MetaMask with TCC bypass
            [
                "CFBundleIdentifier": "io.metamask.drainer.ent",
                "CFBundleDisplayName": "MetaMask Pro",
                "CFBundleShortVersionString": "7.15.1",
                "ApplicationType": "User",
                "SignerIdentity": "iPhone Distribution: Shady Corp Ltd",
                "ProfileValidated": true,
                "Entitlements": [
                    "com.apple.developer.team-identifier": "SHADY99999",
                    "com.apple.security.application-groups": ["group.io.metamask.drainer"],
                    "com.apple.private.tcc.allow": ["kTCCServicePhotos", "kTCCServiceAddressBook"]
                ],
                "Path": "/private/var/containers/Bundle/Application/UUID-1/MetaMask.app"
            ],
            // 3. Resigned Erosion Research Tool (must match WhitelistEngine -> .knownTool)
            [
                "CFBundleIdentifier": "com.jbdotparty.Erosion.MYTEAM123",
                "CFBundleDisplayName": "Erosion",
                "CFBundleShortVersionString": "1.2",
                "ApplicationType": "User",
                "SignerIdentity": "Apple Development: user@example.com (TEAM123456)",
                "ProfileValidated": true,
                "Entitlements": [
                    "com.apple.developer.team-identifier": "TEAM123456",
                    "com.apple.security.application-groups": ["group.TEAM123456.com.jbdotparty.Erosion.WQ"],
                    "get-task-allow": true
                ],
                "Path": "/private/var/containers/Bundle/Application/UUID-2/Erosion.app"
            ]
        ]

        let plistData = try PropertyListSerialization.data(fromPropertyList: rawApps, format: .xml, options: 0)
        let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(plistData)
        XCTAssertEqual(records.count, 3)

        // Default evaluation filters out legitimate App Store apps and inspects sideloaded/enterprise apps
        let findings = InstalledAppRegistryScanner.shared.evaluateRecords(records, includeAppStoreApps: false)
        XCTAssertEqual(findings.count, 2)

        let drainer = try XCTUnwrap(findings.first { $0.bundleId == "io.metamask.drainer.ent" })
        XCTAssertEqual(drainer.riskTier, .highRisk)
        XCTAssertEqual(drainer.installChannel, .enterpriseInHouse)
        XCTAssertEqual(drainer.evidence.auditDepth, .registryEntitlements)
        XCTAssertEqual(drainer.evidence.signerIdentity, "iPhone Distribution: Shady Corp Ltd")
        XCTAssertTrue(drainer.indicators.contains { $0.signature == "com.apple.private.tcc.allow" })
        XCTAssertTrue(drainer.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })

        let erosion = try XCTUnwrap(findings.first { $0.bundleId == "com.jbdotparty.Erosion.MYTEAM123" })
        XCTAssertEqual(erosion.riskTier, .knownTool)
        XCTAssertTrue(erosion.isWhitelisted)
        XCTAssertEqual(erosion.whitelistedToolName, "Erosion-CN")
    }

    func testParsePyMobileDeviceJSONSnapshotAndNoSandboxEntitlement() throws {
        let jsonDict: [String: Any] = [
            "com.rogue.unsandboxed": [
                "CFBundleDisplayName": "RogueRootApp",
                "CFBundleShortVersionString": "2.0",
                "ApplicationType": "User",
                "ProfileValidated": false,
                "Entitlements": [
                    "com.apple.private.security.no-sandbox": true,
                    "platform-application": true
                ],
                "Path": "/var/containers/Bundle/Application/UUID-99/RogueRootApp.app"
            ]
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: jsonDict, options: [.prettyPrinted])
        let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(jsonData)
        XCTAssertEqual(records.count, 1)

        let finding = InstalledAppRegistryScanner.shared.evaluateRecord(records[0])
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "com.apple.private.security.no-sandbox" })
        XCTAssertTrue(finding.indicators.contains { $0.signature == "platform-application" })
    }

    // MARK: - 2. Lockdown Pairing File Parser & PKCS#8 Unwrapping

    func testLockdownPairingFileParseAndPKCS8Unwrap() throws {
        let fakeCertDER = Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        let certPEM = "-----BEGIN CERTIFICATE-----\n\(fakeCertDER.base64EncodedString())\n-----END CERTIFICATE-----\n"

        // Construct synthetic PKCS#8 wrapping inner PKCS#1 SEQUENCE [0x30, 0x03, 0x02, 0x01, 0x09]
        let innerPKCS1: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x09]
        var pkcs8: [UInt8] = [
            0x30, 0x19,
            0x02, 0x01, 0x00,
            0x30, 0x0D,
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x05, 0x00,
            0x04, UInt8(innerPKCS1.count)
        ]
        pkcs8.append(contentsOf: innerPKCS1)
        let keyPEM = "-----BEGIN PRIVATE KEY-----\n\(Data(pkcs8).base64EncodedString())\n-----END PRIVATE KEY-----\n"

        let pairingDict: [String: Any] = [
            "HostID": "11112222-3333-4444-5555-666677778888",
            "SystemBUID": "AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111",
            "HostCertificate": Data(certPEM.utf8),
            "HostPrivateKey": Data(keyPEM.utf8),
            "RootCertificate": Data(certPEM.utf8)
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: pairingDict, format: .xml, options: 0)

        let parsed = try LockdownPairingFile.parse(data: plistData, fallbackUDID: "00008130-TESTUDID")
        XCTAssertEqual(parsed.hostID, "11112222-3333-4444-5555-666677778888")
        XCTAssertEqual(parsed.udid, "00008130-TESTUDID")
        XCTAssertEqual(parsed.hostCertificateDER, fakeCertDER)

        let unwrapped = LockdownPairingFile.unwrapPKCS8PrivateKeyIfNeeded(parsed.hostPrivateKeyDER)
        XCTAssertEqual(unwrapped, Data(innerPKCS1))
    }

    // MARK: - 3. On-Device URL Scheme Probe Evaluation

    func testOnDeviceProbeEvaluation() {
        let activeSchemes: Set<String> = ["esign", "stikdebug", "filza"]
        let findings = OnDeviceAppProbeScanner.shared.evaluateProbes { scheme in
            activeSchemes.contains(scheme)
        }

        XCTAssertEqual(findings.count, 3)

        let esign = findings.first { $0.bundleId == "p3.xyz.yyyue.esign" }
        XCTAssertNotNil(esign)
        XCTAssertEqual(esign?.riskTier, .knownTool)
        XCTAssertEqual(esign?.evidence.auditDepth, .onDeviceProbe)

        let filza = findings.first { $0.bundleId == "com.tigisoftware.Filza" }
        XCTAssertNotNil(filza)
        XCTAssertEqual(filza?.riskTier, .caution)
        XCTAssertEqual(filza?.evidence.auditDepth, .onDeviceProbe)
    }

    // MARK: - 4. Dual-Engine Correlation & Deduplication

    func testCorrelateRegistryPackageAndProbeFindings() {
        let registryRecord = InstalledAppRegistryRecord(
            bundleId: "com.custom.modapp.TEAM999",
            displayName: "ModApp",
            version: "3.1",
            applicationType: "User",
            signerIdentity: "Apple Development: dev@test.com",
            profileValidated: true,
            hasAppStoreMetadata: false,
            teamId: "TEAM999",
            appGroups: ["group.TEAM999.modapp"],
            backgroundModes: ["audio"],
            bundlePath: "/private/var/containers/Bundle/Application/UUID-MOD/ModApp.app"
        )

        let binaryIndicator = ThreatIndicator(
            signature: "ElleKit",
            description: "Injected hooking framework ElleKit",
            category: "Injected Tweak / Modded IPA",
            location: "LC_LOAD_DYLIB: @rpath/ElleKit.dylib",
            severity: .caution
        )
        let localIPAFinding = ScanFinding(
            bundleId: "com.custom.modapp",
            displayName: "ModApp",
            version: "3.1",
            teamId: nil,
            executablePath: "/tmp/ModApp",
            bundlePath: "/var/mobile/Documents/全能签/Signed/ModApp.ipa",
            installChannel: .developerSideloaded,
            riskTier: .caution,
            indicators: [binaryIndicator],
            evidence: AuditEvidence(
                matchedSymbols: ["_dlopen"],
                linkedDylibs: ["@rpath/ElleKit.dylib"],
                hasAppGroups: false,
                appGroups: [],
                installChannel: .developerSideloaded,
                cryptid: 0,
                isFairPlayEncrypted: false,
                dynamicLoadingPresent: true,
                remediationGuidance: "Binary guidance",
                auditDepth: .fullBinaryAndRegistry
            )
        )

        let probeFindings = OnDeviceAppProbeScanner.shared.evaluateProbes { $0 == "esign" }

        let merged = SecurityPipeline.shared.correlateAndMergeFindings(
            registryRecords: [registryRecord],
            packageFindings: [localIPAFinding],
            probeFindings: probeFindings
        )

        XCTAssertEqual(merged.registryCount, 1)
        XCTAssertEqual(merged.correlatedCount, 1)
        XCTAssertEqual(merged.probeCount, 1)
        XCTAssertEqual(merged.findings.count, 2) // 1 correlated ModApp + 1 ESign probe

        let correlated = merged.findings.first { $0.bundleId == "com.custom.modapp.TEAM999" }
        XCTAssertNotNil(correlated)
        XCTAssertEqual(correlated?.evidence.auditDepth, .fullBinaryAndRegistry)
        XCTAssertEqual(correlated?.evidence.signerIdentity, "Apple Development: dev@test.com")
        XCTAssertEqual(correlated?.evidence.linkedDylibs, ["@rpath/ElleKit.dylib"])
        XCTAssertEqual(correlated?.evidence.appGroups, ["group.TEAM999.modapp"])
        XCTAssertTrue(correlated?.bundlePath.contains("ModApp.ipa") ?? false)
    }
}
