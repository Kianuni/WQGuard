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
        XCTAssertEqual(erosion.riskTier, .caution, "Erosion is no longer built-in whitelisted; registry App Group surfaces as Caution until binary correlation")
        XCTAssertFalse(erosion.isWhitelisted)
        XCTAssertNil(erosion.whitelistedToolName)
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

    func testDeviceCtlJSONSnapshotParsingAndClassification() throws {
        let jsonString = """
        {
          "info": {
            "commandType": "devicectl.device.info.apps",
            "jsonVersion": 5,
            "outcome": "success"
          },
          "result": {
            "apps": [
              {
                "bundleIdentifier": "com.apple.Preferences",
                "name": "Settings",
                "version": "1.0",
                "defaultApp": true,
                "internalApp": false,
                "builtByDeveloper": false,
                "url": "file:///Applications/Preferences.app/"
              },
              {
                "bundleIdentifier": "com.official.storeapp",
                "name": "StoreApp",
                "version": "4.2.0",
                "defaultApp": false,
                "internalApp": false,
                "builtByDeveloper": false,
                "url": "file:///private/var/containers/Bundle/Application/1111/StoreApp.app/"
              },
              {
                "bundleIdentifier": "com.tencent.xin.sideload",
                "name": "微信",
                "version": "8.0.50",
                "defaultApp": false,
                "internalApp": false,
                "builtByDeveloper": true,
                "appGroupIdentifiers": ["group.com.apple.PreviewShell"],
                "groupContainerPaths": {
                  "group.sideload.extra": "/private/var/mobile/Containers/Shared/AppGroup/2222"
                },
                "url": "file:///private/var/containers/Bundle/Application/3333/WeChat.app/"
              }
            ]
          }
        }
        """

        let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(Data(jsonString.utf8))
        XCTAssertEqual(records.count, 3)

        let findings = InstalledAppRegistryScanner.shared.evaluateRecords(records, includeAppStoreApps: false)
        // System app and App Store app excluded; sideloaded WeChat impersonator with system App Group flagged as highRisk
        XCTAssertEqual(findings.count, 1)
        let flagged = try XCTUnwrap(findings.first)
        XCTAssertEqual(flagged.bundleId, "com.tencent.xin.sideload")
        XCTAssertEqual(flagged.riskTier, .highRisk)
        XCTAssertTrue(flagged.evidence.appGroups.contains("group.com.apple.PreviewShell"))
        XCTAssertTrue(flagged.evidence.appGroups.contains("group.sideload.extra"))
    }

    func testLocalNetworkSubnetDiagnosisAndRPPairingDetection() throws {
        XCTAssertTrue(LocalNetworkSubnetDiagnosis.isIPv4("192.168.31.252", inSameSubnetAs: "192.168.31.88", netmask: "255.255.255.0"))
        XCTAssertFalse(LocalNetworkSubnetDiagnosis.isIPv4("10.7.0.1", inSameSubnetAs: "192.168.31.88", netmask: "255.255.255.0"))

        let wifiStandard = try XCTUnwrap(LocalNetworkSubnetDiagnosis.parseIPv4UInt32("192.168.31.88"))
        let mask24 = try XCTUnwrap(LocalNetworkSubnetDiagnosis.parseIPv4UInt32("255.255.255.0"))
        let pair1 = try XCTUnwrap(LocalNetworkSubnetDiagnosis.computeRecommendedPair(wifiIP: wifiStandard, netmask: mask24))
        XCTAssertEqual(LocalNetworkSubnetDiagnosis.formatIPv4UInt32(pair1.tunnel), "192.168.31.251")
        XCTAssertEqual(LocalNetworkSubnetDiagnosis.formatIPv4UInt32(pair1.device), "192.168.31.252")

        // Verify collision avoidance if phone itself already holds .251
        let wifiCollision = try XCTUnwrap(LocalNetworkSubnetDiagnosis.parseIPv4UInt32("192.168.31.251"))
        let pair2 = try XCTUnwrap(LocalNetworkSubnetDiagnosis.computeRecommendedPair(wifiIP: wifiCollision, netmask: mask24))
        XCTAssertNotEqual(LocalNetworkSubnetDiagnosis.formatIPv4UInt32(pair2.tunnel), "192.168.31.251")
        XCTAssertNotEqual(LocalNetworkSubnetDiagnosis.formatIPv4UInt32(pair2.device), "192.168.31.251")

        // Verify RPPairing plist is explicitly recognized with helpful message
        let rpPlist: [String: Any] = [
            "identifier": "12345678-ABCD",
            "public_key": Data([0x01, 0x02]),
            "private_key": Data([0x03, 0x04]),
            "remote_unlock_host_key": Data([0x05, 0x06])
        ]
        let rpData = try PropertyListSerialization.data(fromPropertyList: rpPlist, format: .xml, options: 0)
        XCTAssertThrowsError(try LockdownPairingFile.parse(data: rpData)) { error in
            XCTAssertTrue(error.localizedDescription.contains("RPPairing"))
        }
    }

    func testAppleSystemAppsExcludedWhileSpoofedComAppleAndFeatherAndModdedWeChatHandled() {
        let records: [InstalledAppRegistryRecord] = [
            // 1. Apple removable system app in /private/var/containers/Bundle/Application with TCC & no-container
            InstalledAppRegistryRecord(
                bundleId: "com.apple.shortcuts",
                displayName: "快捷指令",
                version: "7.0",
                applicationType: "User",
                signerIdentity: "Apple iPhone OS Application Signing",
                profileValidated: false,
                hasAppStoreMetadata: true,
                tccAllowedServices: ["kTCCServicePhotos"],
                booleanEntitlements: ["com.apple.private.security.no-container": true],
                bundlePath: "/private/var/containers/Bundle/Application/UUID-SHORTCUTS/Shortcuts.app"
            ),
            // 2. Apple Health app in /private/var/containers/Bundle/Application with nil SignerIdentity (CoreTrust static cache)
            InstalledAppRegistryRecord(
                bundleId: "com.apple.Health",
                displayName: "健康",
                version: "1.0",
                applicationType: "System",
                signerIdentity: nil,
                profileValidated: false,
                hasAppStoreMetadata: false,
                appGroups: ["group.com.apple.Health", "group.com.apple.ip.redirects"],
                backgroundModes: ["audio"],
                bundlePath: "/private/var/containers/Bundle/Application/UUID-HEALTH/Health.app"
            ),
            // 3. Apple internal WidgetRenderer daemon
            InstalledAppRegistryRecord(
                bundleId: "com.apple.chrono.WidgetRenderer-Snapshots",
                displayName: "WidgetRenderer_Default",
                version: "1.0",
                applicationType: "System",
                signerIdentity: "Software Signing",
                profileValidated: false,
                booleanEntitlements: ["com.apple.private.MobileContainerManager.allowed": true],
                bundlePath: "/System/Library/CoreServices/WidgetRenderer.app"
            ),
            // 4. Malicious developer-sideloaded app spoofing `com.apple.Health` -> MUST BE CAUGHT!
            InstalledAppRegistryRecord(
                bundleId: "com.apple.Health.spoof",
                displayName: "健康 Pro",
                version: "1.0",
                applicationType: "User",
                signerIdentity: "Apple Development: attacker@evil.org (EVIL123456)",
                profileValidated: true,
                teamId: "EVIL123456",
                appGroups: ["group.evil.shared"],
                booleanEntitlements: ["get-task-allow": true],
                bundlePath: "/private/var/containers/Bundle/Application/UUID-SPOOF/HealthSpoof.app"
            ),
            // 5. Legitimate Feather sideload manager -> MUST BE `.knownTool` (not Caution)
            InstalledAppRegistryRecord(
                bundleId: "kh.crysalis.feather.CERT999",
                displayName: "Feather",
                version: "2.1.0",
                applicationType: "User",
                signerIdentity: "iPhone Distribution: Enterprise Co",
                profileValidated: true,
                teamId: "ENT9999999",
                appGroups: ["group.kh.crysalis.feather.CERT999"],
                backgroundModes: ["audio"],
                bundlePath: "/private/var/containers/Bundle/Application/UUID-FEATHER/Feather.app"
            ),
            // 6. Modded enterprise WeChat (`com.tencent.wx`) -> MUST BE `.caution` with WeChat impersonation warning
            InstalledAppRegistryRecord(
                bundleId: "com.tencent.wx",
                displayName: "微信",
                version: "8.0.54",
                applicationType: "User",
                signerIdentity: "iPhone Distribution: ThirdParty Corp",
                profileValidated: true,
                teamId: "CORP888888",
                appGroups: ["group.com.tencent.wx"],
                backgroundModes: ["audio", "voip"],
                bundlePath: "/private/var/containers/Bundle/Application/UUID-WX/WeChat.app"
            )
        ]

        // Test BOTH `includeAppStoreApps: false` AND `includeAppStoreApps: true` — Apple OS system apps must NEVER appear!
        for includeStore in [false, true] {
            let findings = InstalledAppRegistryScanner.shared.evaluateRecords(records, includeAppStoreApps: includeStore)
            XCTAssertEqual(findings.count, 3, "includeStore=\(includeStore) must exclude all 3 genuine Apple OS apps")
            XCTAssertFalse(findings.contains { $0.bundleId == "com.apple.shortcuts" })
            XCTAssertFalse(findings.contains { $0.bundleId == "com.apple.Health" })
            XCTAssertFalse(findings.contains { $0.bundleId == "com.apple.chrono.WidgetRenderer-Snapshots" })

            let spoof = findings.first { $0.bundleId == "com.apple.Health.spoof" }
            XCTAssertNotNil(spoof)
            XCTAssertEqual(spoof?.installChannel, .developerSideloaded)
            XCTAssertEqual(spoof?.riskTier, .caution)

            let feather = findings.first { $0.bundleId == "kh.crysalis.feather.CERT999" }
            XCTAssertNotNil(feather)
            XCTAssertEqual(feather?.riskTier, .knownTool)
            XCTAssertTrue(feather?.isWhitelisted ?? false)
            XCTAssertEqual(feather?.whitelistedToolName, "Feather")

            let moddedWX = findings.first { $0.bundleId == "com.tencent.wx" }
            XCTAssertNotNil(moddedWX)
            XCTAssertEqual(moddedWX?.riskTier, .caution)
            XCTAssertTrue(moddedWX?.indicators.contains { $0.signature == "IMPERSONATION:WeChat (微信)" } ?? false)
        }
    }

    func testTestFlightAppsSurgeAndAPTVNotMisclassifiedAsEnterprise() throws {
        // Real-world TestFlight apps carry `ProfileValidated == true` (90-day TestFlight provisioning profile),
        // `SignerIdentity` containing "Apple Distribution: ..." or "Apple TestFlight Beta Distribution",
        // AND `Entitlements["beta-reports-active"] == true`.
        let rawApps: [String: Any] = [
            "com.nssurge.inc.surge-ios": [
                "CFBundleIdentifier": "com.nssurge.inc.surge-ios",
                "CFBundleDisplayName": "Surge",
                "CFBundleShortVersionString": "5.14.0",
                "ApplicationType": "User",
                "SignerIdentity": "Apple Distribution: Surge Networks Inc. (TEAM123456)",
                "ProfileValidated": true,
                "ApplicationDSID": 987654321,
                "UIBackgroundModes": ["network-authentication", "fetch"],
                "Entitlements": [
                    "application-identifier": "TEAM123456.com.nssurge.inc.surge-ios",
                    "com.apple.developer.team-identifier": "TEAM123456",
                    "beta-reports-active": true,
                    "com.apple.security.application-groups": ["group.com.nssurge.inc.surge-ios"]
                ],
                "Path": "/private/var/containers/Bundle/Application/UUID-SURGE/Surge-iOS.app"
            ],
            "com.kimen.aptvpro": [
                "CFBundleIdentifier": "com.kimen.aptvpro",
                "CFBundleDisplayName": "APTV",
                "CFBundleShortVersionString": "2.4.1",
                "ApplicationType": "User",
                "SignerIdentity": "Apple Distribution: Kimen Studio (APTV888888)",
                "ProfileValidated": true,
                "UIBackgroundModes": ["audio"],
                "Entitlements": [
                    "application-identifier": "APTV888888.com.kimen.aptvpro",
                    "com.apple.developer.team-identifier": "APTV888888",
                    "beta-reports-active": 1,
                    "com.apple.security.application-groups": ["group.com.kimen.aptvpro"]
                ],
                "Path": "/private/var/containers/Bundle/Application/UUID-APTV/APTV.app"
            ]
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: rawApps, options: [])
        let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(jsonData)
        XCTAssertEqual(records.count, 2)

        // 1. When `includeAppStoreApps: false`, TestFlight apps are trusted official builds and excluded
        let sideloadOnly = InstalledAppRegistryScanner.shared.evaluateRecords(records, includeAppStoreApps: false)
        XCTAssertTrue(sideloadOnly.isEmpty, "TestFlight apps Surge and APTV must not be treated as Enterprise/Sideloaded")

        // 2. When `includeAppStoreApps: true`, both are classified as `.testFlight` + `.safe` with FairPlay DRM
        let allFindings = InstalledAppRegistryScanner.shared.evaluateRecords(records, includeAppStoreApps: true)
        XCTAssertEqual(allFindings.count, 2)
        for finding in allFindings {
            XCTAssertEqual(finding.installChannel, .testFlight, "\(finding.displayName) must be .testFlight, not .enterpriseInHouse")
            XCTAssertEqual(finding.riskTier, .safe, "\(finding.displayName) must be .safe, not .caution")
            XCTAssertTrue(finding.evidence.isFairPlayEncrypted)
            XCTAssertEqual(finding.evidence.cryptid, 1)
            XCTAssertTrue(finding.indicators.isEmpty)
        }
    }
}
