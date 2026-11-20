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
        XCTAssertEqual(esign?.riskTier, .caution, "Strict zero trust: third-party sideload signers must NEVER be auto-whitelisted by default")
        XCTAssertFalse(esign?.isWhitelisted ?? true)
        XCTAssertNil(esign?.whitelistedToolName)
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
            // 5. Third-party Feather sideload manager -> Strict zero trust: MUST BE `.caution` (NEVER auto-whitelisted)
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
            XCTAssertEqual(feather?.riskTier, .caution)
            XCTAssertFalse(feather?.isWhitelisted ?? true)
            XCTAssertNil(feather?.whitelistedToolName)

            let moddedWX = findings.first { $0.bundleId == "com.tencent.wx" }
            XCTAssertNotNil(moddedWX)
            XCTAssertEqual(moddedWX?.riskTier, .caution)
            XCTAssertTrue(moddedWX?.indicators.contains { $0.signature == "IMPERSONATION:WeChat (微信)" } ?? false)
        }
    }

    func testTestFlightAppsSurgeAndAPTVNotMisclassifiedAsEnterprise() throws {
        // Real-world Apple TestFlight cloud-re-signed apps on iOS carry `SignerIdentity == "TestFlight Beta Distribution"`
        // (without an "Apple " prefix!) + `ProfileValidated == true`, as well as pre-upload `Apple Distribution:` builds with `beta-reports-active`.
        let rawApps: [String: Any] = [
            "com.nssurge.inc.surge-ios": [
                "CFBundleIdentifier": "com.nssurge.inc.surge-ios",
                "CFBundleDisplayName": "Surge",
                "CFBundleShortVersionString": "5.14.0",
                "ApplicationType": "User",
                "SignerIdentity": "TestFlight Beta Distribution",
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
                "SignerIdentity": "TestFlight Beta Distribution",
                "ProfileValidated": true,
                "UIBackgroundModes": ["audio"],
                "Entitlements": [
                    "application-identifier": "APTV888888.com.kimen.aptvpro",
                    "com.apple.developer.team-identifier": "APTV888888",
                    "com.apple.security.application-groups": ["group.com.kimen.aptvpro"]
                ],
                "Path": "/private/var/containers/Bundle/Application/UUID-APTV/APTV.app"
            ],
            "com.example.distbeta": [
                "CFBundleIdentifier": "com.example.distbeta",
                "CFBundleDisplayName": "DistBeta",
                "CFBundleShortVersionString": "1.0.0",
                "ApplicationType": "User",
                "SignerIdentity": "Apple Distribution: Example Studio (BETA999999)",
                "ProfileValidated": true,
                "UIBackgroundModes": ["audio"],
                "Entitlements": [
                    "application-identifier": "BETA999999.com.example.distbeta",
                    "com.apple.developer.team-identifier": "BETA999999",
                    "beta-reports-active": 1,
                    "com.apple.security.application-groups": ["group.com.example.distbeta"]
                ],
                "Path": "/private/var/containers/Bundle/Application/UUID-BETA/DistBeta.app"
            ]
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: rawApps, options: [])
        let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(jsonData)
        XCTAssertEqual(records.count, 3)

        // 1. When `includeAppStoreApps: false`, official TestFlight apps (`Surge`, `APTV`) are trusted and excluded,
        //    while third-party `"Apple Distribution:"` + `ProfileValidated` + `beta-reports-active` (`DistBeta`)
        //    must NOT spoof `.testFlight` offline and is surfaced as `.enterpriseInHouse`.
        let sideloadOnly = InstalledAppRegistryScanner.shared.evaluateRecords(records, includeAppStoreApps: false)
        XCTAssertEqual(sideloadOnly.count, 1)
        XCTAssertEqual(sideloadOnly.first?.bundleId, "com.example.distbeta")
        XCTAssertEqual(sideloadOnly.first?.installChannel, .enterpriseInHouse)
        XCTAssertEqual(sideloadOnly.first?.riskTier, .caution)

        // 2. When `includeAppStoreApps: true`, `Surge` and `APTV` are `.testFlight` + `.safe` with FairPlay DRM,
        //    whereas `DistBeta` remains `.enterpriseInHouse` (not `.testFlight`).
        let allFindings = InstalledAppRegistryScanner.shared.evaluateRecords(records, includeAppStoreApps: true)
        XCTAssertEqual(allFindings.count, 3)
        for tfId in ["com.nssurge.inc.surge-ios", "com.kimen.aptvpro"] {
            let finding = try XCTUnwrap(allFindings.first { $0.bundleId == tfId })
            XCTAssertEqual(finding.installChannel, .testFlight, "\(finding.displayName) must be .testFlight, not .enterpriseInHouse")
            XCTAssertEqual(finding.riskTier, .safe, "\(finding.displayName) must be .safe, not .caution")
            XCTAssertTrue(finding.evidence.isFairPlayEncrypted)
            XCTAssertEqual(finding.evidence.cryptid, 1)
            XCTAssertTrue(finding.indicators.isEmpty)
        }
        let distBeta = try XCTUnwrap(allFindings.first { $0.bundleId == "com.example.distbeta" })
        XCTAssertEqual(distBeta.installChannel, .enterpriseInHouse)
        XCTAssertFalse(distBeta.evidence.isFairPlayEncrypted)
        XCTAssertEqual(distBeta.evidence.cryptid, 0)
        XCTAssertEqual(distBeta.riskTier, .caution)
    }

    func testSSVSystemAppsWithPrivateEntitlementsAndNilSignerExcluded_WhileTrollStoreAndJailbreakSpoofsCaught() throws {
        // 1. Real iOS `installation_proxy` SSV Apple System App records (SignerIdentity == nil,
        //    legitimate platform-application / no-container / no-sandbox / tcc.allow / private 2026 entitlements)
        let ssvSystemAppsJSON: [String: Any] = [
            "com.apple.chrono.WidgetRenderer-Snapshots": [
                "CFBundleIdentifier": "com.apple.chrono.WidgetRenderer-Snapshots",
                "CFBundleDisplayName": "WidgetRenderer_Default",
                "ApplicationType": "System",
                "Path": "/System/Library/CoreServices/WidgetRenderer.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.security.no-container": true,
                    "com.apple.private.MobileContainerManager.allowed": true,
                    "com.apple.private.MobileGestalt.AllowedProtectedKeys": true
                ]
            ],
            "com.apple.AdaptiveMusicApp": [
                "CFBundleIdentifier": "com.apple.AdaptiveMusicApp",
                "CFBundleDisplayName": "环境音乐",
                "ApplicationType": "Internal",
                "Path": "/System/Applications/AdaptiveMusicApp.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.mediaexperience.allow": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"]
                ]
            ],
            "com.apple.mobiletimer": [
                "CFBundleIdentifier": "com.apple.mobiletimer",
                "CFBundleDisplayName": "时钟",
                "ApplicationType": "System",
                "BundlePath": "/Applications/MobileTimer.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.security.no-sandbox": true,
                    "com.apple.private.tcc.allow": ["kTCCServicePhotos"],
                    "com.apple.private.mediaexperience.allow": true
                ]
            ],
            "com.apple.StoreDemoViewService": [
                "CFBundleIdentifier": "com.apple.StoreDemoViewService",
                "CFBundleDisplayName": "StoreDemoViewService",
                "ApplicationType": "Hidden",
                "Path": "/private/preboot/Cryptexes/OS/System/Applications/StoreDemoViewService.app",
                "Entitlements": [
                    "platform-application": true
                ]
            ],
            "com.apple.ContinuitySingShieldUI": [
                "CFBundleIdentifier": "com.apple.ContinuitySingShieldUI",
                "CFBundleDisplayName": "唱歌",
                "ApplicationType": "System",
                "Path": "/private/var/staged_system_apps/ContinuitySingShieldUI.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.security.no-container": true,
                    "com.apple.private.mediaexperience.allow": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"]
                ]
            ],
            "com.apple.TVAccessViewService": [
                "CFBundleIdentifier": "com.apple.TVAccessViewService",
                "CFBundleDisplayName": "TVAccessViewService",
                "ApplicationType": "System",
                "Path": "/Applications/TVAccessViewService.app",
                "Entitlements": [
                    "platform-application": true
                ]
            ],
            "com.apple.SharingUIService": [
                "CFBundleIdentifier": "com.apple.SharingUIService",
                "CFBundleDisplayName": "SharingUIService",
                "ApplicationType": "System",
                "Path": "/System/Library/PrivateFrameworks/Sharing.framework/PlugIns/SharingUIService.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.security.no-container": true
                ]
            ]
        ]

        let ssvData = try JSONSerialization.data(withJSONObject: ssvSystemAppsJSON, options: [])
        let ssvRecords = try InstalledAppRegistryScanner.shared.parseSnapshotData(ssvData)
        XCTAssertEqual(ssvRecords.count, 7)

        for rec in ssvRecords {
            XCTAssertTrue(
                InstalledAppRegistryScanner.shared.isAppleSystemOrFirstPartyApp(rec),
                "SSV system app \(rec.bundleId) at \(rec.bundlePath) must be recognized as Apple system/first-party"
            )
        }
        XCTAssertTrue(
            InstalledAppRegistryScanner.shared.evaluateRecords(ssvRecords, includeAppStoreApps: false).isEmpty,
            "SSV system apps must produce 0 findings when includeAppStoreApps is false"
        )
        XCTAssertTrue(
            InstalledAppRegistryScanner.shared.evaluateRecords(ssvRecords, includeAppStoreApps: true).isEmpty,
            "SSV system apps must produce 0 findings when includeAppStoreApps is true"
        )

        // 2. Genuine Apple first-party App Store app signed by Apple iPhone OS Application Signing with Apple's Team ID
        let shortcutsFirstParty = InstalledAppRegistryRecord(
            bundleId: "com.apple.shortcuts",
            displayName: "快捷指令",
            version: "7.0",
            applicationType: "User",
            signerIdentity: "Apple iPhone OS Application Signing",
            profileValidated: false,
            hasAppStoreMetadata: true,
            teamId: "59GAB85EFG",
            tccAllowedServices: ["kTCCServicePhotos"],
            booleanEntitlements: ["com.apple.private.security.no-container": true],
            bundlePath: "/private/var/containers/Bundle/Application/UUID-SHORTCUTS/Shortcuts.app"
        )
        XCTAssertTrue(InstalledAppRegistryScanner.shared.isAppleSystemOrFirstPartyApp(shortcutsFirstParty))

        // 3. Negative controls MUST still be caught as .highRisk (isAppleSystemOrFirstPartyApp == false)
        let trollPersistence = InstalledAppRegistryRecord(
            bundleId: "com.apple.troll.persistence",
            displayName: "TrollHelper",
            version: "2.0",
            applicationType: "System",
            signerIdentity: nil,
            profileValidated: false,
            booleanEntitlements: ["com.apple.private.security.no-sandbox": true, "platform-application": true],
            allEntitlementKeys: ["com.apple.private.security.no-sandbox", "platform-application"],
            bundlePath: "/private/var/containers/Bundle/Application/UUID-TROLL/PersistenceHelper.app"
        )
        let trollTimerHijack = InstalledAppRegistryRecord(
            bundleId: "com.apple.mobiletimer",
            displayName: "时钟",
            version: "1.0",
            applicationType: "System",
            signerIdentity: nil,
            profileValidated: false,
            booleanEntitlements: ["com.apple.private.security.no-sandbox": true],
            allEntitlementKeys: ["com.apple.private.security.no-sandbox"],
            bundlePath: "/private/var/containers/Bundle/Application/UUID-HIJACK/MobileTimer.app"
        )
        let rootlessJBFake = InstalledAppRegistryRecord(
            bundleId: "com.apple.fake",
            displayName: "RootlessFake",
            version: "1.0",
            applicationType: "System",
            signerIdentity: nil,
            profileValidated: false,
            booleanEntitlements: ["com.apple.private.security.no-sandbox": true],
            allEntitlementKeys: ["com.apple.private.security.no-sandbox"],
            bundlePath: "/private/preboot/ABCD1234/jb-1234/Applications/Fake.app"
        )
        let adHocInApps = InstalledAppRegistryRecord(
            bundleId: "com.apple.fake",
            displayName: "AdHocFake",
            version: "1.0",
            applicationType: "System",
            signerIdentity: "Ad Hoc",
            profileValidated: false,
            booleanEntitlements: ["com.apple.private.security.no-sandbox": true],
            allEntitlementKeys: ["com.apple.private.security.no-sandbox"],
            bundlePath: "/Applications/Fake.app"
        )
        let thirdPartyTeamInApps = InstalledAppRegistryRecord(
            bundleId: "com.apple.fake",
            displayName: "TeamFake",
            version: "1.0",
            applicationType: "System",
            signerIdentity: nil,
            profileValidated: false,
            teamId: "EVILTEAM99",
            booleanEntitlements: ["com.apple.private.security.no-sandbox": true],
            allEntitlementKeys: ["com.apple.private.security.no-sandbox"],
            bundlePath: "/Applications/Fake.app"
        )
        let thirdPartyGroupInApps = InstalledAppRegistryRecord(
            bundleId: "com.apple.fake",
            displayName: "GroupFake",
            version: "1.0",
            applicationType: "System",
            signerIdentity: nil,
            profileValidated: false,
            appGroups: ["group.io.metamask"],
            booleanEntitlements: ["com.apple.private.security.no-sandbox": true],
            allEntitlementKeys: ["com.apple.private.security.no-sandbox"],
            bundlePath: "/Applications/Fake.app"
        )

        let negativeControls = [
            trollPersistence,
            trollTimerHijack,
            rootlessJBFake,
            adHocInApps,
            thirdPartyTeamInApps,
            thirdPartyGroupInApps
        ]
        for neg in negativeControls {
            XCTAssertFalse(
                InstalledAppRegistryScanner.shared.isAppleSystemOrFirstPartyApp(neg),
                "Negative control \(neg.bundleId) (\(neg.bundlePath)) MUST NOT be treated as Apple system app"
            )
        }
        let negFindings = InstalledAppRegistryScanner.shared.evaluateRecords(negativeControls, includeAppStoreApps: false)
        XCTAssertEqual(negFindings.count, negativeControls.count)
        XCTAssertTrue(negFindings.allSatisfy { $0.riskTier == .highRisk })

        // 4. DeviceCtl cryptex system path should NOT be marked as jailbreak / explicitNotAppStore
        let cryptexCtl: [String: Any] = [
            "bundleIdentifier": "com.apple.Safari",
            "name": "Safari",
            "defaultApp": true,
            "internalApp": false,
            "builtByDeveloper": false,
            "url": "file:///private/preboot/Cryptexes/OS/System/Applications/Safari.app/"
        ]
        let parsedCryptex = InstalledAppRegistryRecord.fromDeviceCtlDictionary(cryptexCtl)
        XCTAssertNotNil(parsedCryptex)
        if let pc = parsedCryptex {
            XCTAssertTrue(InstalledAppRegistryScanner.shared.isAppleSystemOrFirstPartyApp(pc))
        }
    }

    func testRealIOS26SystemAppsAndTeamScopedKeychainWildcards_NoFalsePositives_WhileAttacksStillCaught() throws {
        let scanner = InstalledAppRegistryScanner.shared

        // 1. Preinstalled removable Apple stock apps staged in `/private/var/containers/Bundle/Application/<UUID>/`
        //    (including exact `com.apple.mobiletimer` screenshot profile with `platform-application`, TCC, `BookRestore`, `group.com.apple.tipsnext`)
        let removableStockJSON: [String: Any] = [
            "com.apple.mobiletimer": [
                "CFBundleIdentifier": "com.apple.mobiletimer",
                "CFBundleDisplayName": "时钟",
                "CFBundleShortVersionString": "1.1",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/11111111-1111-1111-1111-111111111111/MobileTimer.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceMediaLibrary", "kTCCServiceMotion"],
                    "com.apple.itunesstored.private": true,
                    "com.apple.security.application-groups": ["group.com.apple.tipsnext"]
                ]
            ],
            "com.apple.shortcuts": [
                "CFBundleIdentifier": "com.apple.shortcuts",
                "CFBundleDisplayName": "快捷指令",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/22222222-2222-2222-2222-222222222222/Shortcuts.app",
                "Entitlements": [
                    "com.apple.developer.team-identifier": "59GAB85EFG",
                    "platform-application": true,
                    "com.apple.private.tcc.allow": ["kTCCServicePhotos", "kTCCServiceContacts"],
                    "com.apple.security.application-groups": ["group.is.workflow.my.app", "group.com.apple.siri.shortcuts"]
                ]
            ],
            "com.apple.DocumentsApp": [
                "CFBundleIdentifier": "com.apple.DocumentsApp",
                "CFBundleDisplayName": "文件",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/33333333-3333-3333-3333-333333333333/Files.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.security.application-groups": ["com.apple.DocumentsApp", "group.com.apple.FileProvider.LocalStorage"]
                ]
            ],
            "com.apple.Translate": [
                "CFBundleIdentifier": "com.apple.Translate",
                "CFBundleDisplayName": "翻译",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/44444444-4444-4444-4444-444444444444/Translate.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"]
                ]
            ],
            "com.apple.mobilecal": [
                "CFBundleIdentifier": "com.apple.mobilecal",
                "CFBundleDisplayName": "日历",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/55555555-5555-5555-5555-555555555555/MobileCal.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceCalendar"]
                ]
            ],
            "com.apple.mobilenotes": [
                "CFBundleIdentifier": "com.apple.mobilenotes",
                "CFBundleDisplayName": "备忘录",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/66666666-6666-6666-6666-666666666666/MobileNotes.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceAddressBook"],
                    "com.apple.security.application-groups": ["group.com.apple.notes"]
                ]
            ],
            "com.apple.FutureStock2026": [
                "CFBundleIdentifier": "com.apple.FutureStock2026",
                "CFBundleDisplayName": "FutureStock",
                "ApplicationType": "System",
                "IsAppStoreVendable": true,
                "Path": "/private/var/containers/Bundle/Application/77777777-7777-7777-7777-777777777777/FutureStock.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.tcc.allow": ["kTCCServicePhotos"]
                ]
            ]
        ]
        let removableData = try JSONSerialization.data(withJSONObject: removableStockJSON, options: [])
        let removableRecords = try scanner.parseSnapshotData(removableData)
        XCTAssertEqual(removableRecords.count, 7)
        for rec in removableRecords {
            XCTAssertTrue(
                scanner.isAppleSystemOrFirstPartyApp(rec),
                "Removable stock app \(rec.bundleId) must be recognized as Apple first-party system app"
            )
        }
        XCTAssertTrue(scanner.evaluateRecords(removableRecords, includeAppStoreApps: true).isEmpty)

        // 2. Core SSV Apple system apps carrying internal Apple Team IDs & non-`group.com.apple.*` Apple App Groups
        let ssvExtendedJSON: [String: Any] = [
            "com.apple.Preferences": [
                "CFBundleIdentifier": "com.apple.Preferences",
                "CFBundleDisplayName": "设置",
                "ApplicationType": "System",
                "Path": "/Applications/Preferences.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.developer.team-identifier": "AB12CD34EF",
                    "com.apple.security.application-groups": [
                        "243LU875E5.groups.com.apple.podcasts",
                        "group.is.workflow.my.app",
                        "com.apple.Preferences"
                    ],
                    "com.apple.private.security.no-container": true
                ]
            ],
            "com.apple.MobileSMS": [
                "CFBundleIdentifier": "com.apple.MobileSMS",
                "CFBundleDisplayName": "信息",
                "ApplicationType": "System",
                "Path": "/Applications/MobileSMS.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.security.no-container": true,
                    "com.apple.security.application-groups": ["com.apple.MobileSMS", "group.com.apple.messages"]
                ]
            ],
            "com.apple.siri": [
                "CFBundleIdentifier": "com.apple.siri",
                "CFBundleDisplayName": "Siri",
                "ApplicationType": "Hidden",
                "Path": "/Applications/Siri.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.security.no-container": true,
                    "com.apple.security.application-groups": ["group.com.apple.siri"]
                ]
            ],
            "com.apple.ContinuitySingShieldUI": [
                "CFBundleIdentifier": "com.apple.ContinuitySingShieldUI",
                "CFBundleDisplayName": "唱歌",
                "ApplicationType": "System",
                "Path": "/private/var/staged_system_apps/ContinuitySingShieldUI.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.developer.team-identifier": "243LU875E5",
                    "com.apple.security.application-groups": ["243LU875E5.groups.com.apple.music"],
                    "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"]
                ]
            ]
        ]
        let ssvExtData = try JSONSerialization.data(withJSONObject: ssvExtendedJSON, options: [])
        let ssvExtRecords = try scanner.parseSnapshotData(ssvExtData)
        XCTAssertEqual(ssvExtRecords.count, 4)
        for rec in ssvExtRecords {
            XCTAssertTrue(
                scanner.isAppleSystemOrFirstPartyApp(rec),
                "SSV system app \(rec.bundleId) with Apple internal Team ID / App Groups must not false-positive"
            )
        }
        XCTAssertTrue(scanner.evaluateRecords(ssvExtRecords, includeAppStoreApps: true).isEmpty)

        // 3. Own-Team / Legacy App ID prefix wildcards (`<OwnTeamID>.*`) in `keychain-access-groups`
        let erosionDict: [String: Any] = [
            "CFBundleIdentifier": "com.jbdotparty.Erosion",
            "CFBundleDisplayName": "Erosion",
            "ApplicationType": "User",
            "SignerIdentity": "iPhone Distribution: Example Corp",
            "ProfileValidated": true,
            "Entitlements": [
                "com.apple.developer.team-identifier": "9NZA6279KY",
                "application-identifier": "9NZA6279KY.*",
                "keychain-access-groups": ["9NZA6279KY.*", "com.apple.token"],
                "com.apple.security.application-groups": ["group.ca628877a97ac6a2.1"]
            ]
        ]
        let lokeyDict: [String: Any] = [
            "CFBundleIdentifier": "com.local.lokey.app",
            "CFBundleDisplayName": "Lokey",
            "ApplicationType": "User",
            "SignerIdentity": "iPhone Distribution: Example Corp",
            "ProfileValidated": true,
            "Entitlements": [
                "com.apple.developer.team-identifier": "9NZA6279KY",
                "application-identifier": "9NZA6279KY.*",
                "keychain-access-groups": ["9NZA6279KY.*", "com.apple.token"],
                "com.apple.security.application-groups": ["group.ca628877a97ac6a2.2"]
            ]
        ]
        for entAppDict in [erosionDict, lokeyDict] {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary(entAppDict))
            let finding = scanner.evaluateRecord(rec)
            XCTAssertEqual(finding.riskTier, .caution, "\(rec.bundleId) should drop from highRisk to caution when holding only own-team keychain wildcard + enterprise App Groups")
            XCTAssertFalse(finding.indicators.contains { $0.signature == "keychain-access-groups(*)" })
        }

        let weiboDict: [String: Any] = [
            "CFBundleIdentifier": "com.sina.weibo",
            "CFBundleDisplayName": "微博",
            "ApplicationType": "User",
            "SignerIdentity": "Apple iPhone OS Application Signing",
            "ProfileValidated": false,
            "ApplicationDSID": 350962683,
            "Entitlements": [
                "com.apple.developer.team-identifier": "NEWTEAM567",
                "application-identifier": "LEGACY1234.com.sina.weibo",
                "keychain-access-groups": ["LEGACY1234.*"]
            ]
        ]
        let weiboRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary(weiboDict))
        XCTAssertFalse(scanner.isSideloadedOrAnomalous(weiboRec))
        let weiboFinding = scanner.evaluateRecord(weiboRec)
        XCTAssertEqual(weiboFinding.riskTier, .safe)
        XCTAssertTrue(weiboFinding.indicators.isEmpty)

        // ExpandedThreatCatalog direct check: own-team safe, cross-team / global / apple / ad-hoc still caught
        let ownKCInds = ExpandedThreatCatalog.evaluateDangerousEntitlements(
            bundleId: "com.jbdotparty.Erosion",
            installChannel: .enterpriseInHouse,
            entitlements: [
                "com.apple.developer.team-identifier": "9NZA6279KY",
                "application-identifier": "9NZA6279KY.*",
                "keychain-access-groups": ["9NZA6279KY.*", "com.apple.token"]
            ]
        )
        XCTAssertFalse(ownKCInds.contains { $0.signature == "keychain-access-groups(*)" })

        for badKC in [["OTHERTEAM1.*"], ["*"], ["com.apple.*"]] {
            let badInds = ExpandedThreatCatalog.evaluateDangerousEntitlements(
                bundleId: "com.example.test",
                installChannel: .enterpriseInHouse,
                entitlements: [
                    "com.apple.developer.team-identifier": "9NZA6279KY",
                    "keychain-access-groups": badKC
                ]
            )
            XCTAssertTrue(badInds.contains { $0.signature == "keychain-access-groups(*)" }, "Expected dangerous wildcard detection for \(badKC)")
        }

        let forgedAdHocKC = ExpandedThreatCatalog.evaluateDangerousEntitlements(
            bundleId: "com.evil.adhoc",
            installChannel: .developerSideloaded,
            entitlements: [
                "com.apple.developer.team-identifier": "9NZA6279KY",
                "keychain-access-groups": ["9NZA6279KY.*"]
            ],
            allowedOwnTeamPrefixes: []
        )
        XCTAssertTrue(forgedAdHocKC.contains { $0.signature == "keychain-access-groups(*)" })

        // 4. Negative controls on registry scanner MUST stay .highRisk
        let crossTeamKC = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.evil.crossteam",
            "ApplicationType": "User",
            "SignerIdentity": "iPhone Distribution: Evil Corp",
            "ProfileValidated": true,
            "Entitlements": [
                "com.apple.developer.team-identifier": "9NZA6279KY",
                "keychain-access-groups": ["OTHERTEAM1.*"]
            ]
        ]))
        XCTAssertEqual(scanner.evaluateRecord(crossTeamKC).riskTier, .highRisk)
        XCTAssertTrue(scanner.evaluateRecord(crossTeamKC).indicators.contains { $0.signature == "keychain-access-groups(*)" })

        let adHocForgedKC = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.evil.forgedkc",
            "ApplicationType": "User",
            "ProfileValidated": false,
            "Entitlements": [
                "com.apple.developer.team-identifier": "EVILTEAM00",
                "keychain-access-groups": ["EVILTEAM00.*"]
            ]
        ]))
        XCTAssertEqual(scanner.evaluateRecord(adHocForgedKC).riskTier, .highRisk)
        XCTAssertTrue(scanner.evaluateRecord(adHocForgedKC).indicators.contains { $0.signature == "keychain-access-groups(*)" })

        let appleWildcardKC = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.evil.applekc",
            "ApplicationType": "User",
            "SignerIdentity": "iPhone Distribution: Evil Corp",
            "ProfileValidated": true,
            "Entitlements": [
                "com.apple.developer.team-identifier": "9NZA6279KY",
                "keychain-access-groups": ["com.apple.*"]
            ]
        ]))
        XCTAssertEqual(scanner.evaluateRecord(appleWildcardKC).riskTier, .highRisk)
        XCTAssertTrue(scanner.evaluateRecord(appleWildcardKC).indicators.contains { $0.signature == "keychain-access-groups(*)" })

        let trollTipsNoSandbox = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.tips",
            "CFBundleDisplayName": "Tips",
            "ApplicationType": "System",
            "IsAppStoreVendable": true,
            "Path": "/private/var/containers/Bundle/Application/UUID-TIPS/Tips.app",
            "Entitlements": [
                "com.apple.private.security.no-sandbox": true,
                "platform-application": true
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(trollTipsNoSandbox))
        XCTAssertEqual(scanner.evaluateRecord(trollTipsNoSandbox).riskTier, .highRisk)

        let trollTipsStarKC = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.tips",
            "CFBundleDisplayName": "Tips",
            "ApplicationType": "System",
            "IsAppStoreVendable": true,
            "Path": "/private/var/containers/Bundle/Application/UUID-TIPS/Tips.app",
            "Entitlements": [
                "keychain-access-groups": ["*"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(trollTipsStarKC))
        XCTAssertEqual(scanner.evaluateRecord(trollTipsStarKC).riskTier, .highRisk)

        // 5. Real iOS 26/27 Siri & modularized staged stock apps (`group.tvappservices.container`, Health without no-container, Campo, Spotlight, AppStore)
        let iOS26ExtendedSystemJSON: [String: Any] = [
            "com.apple.siri": [
                "CFBundleIdentifier": "com.apple.siri",
                "CFBundleDisplayName": "Siri",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-SIRI/Siri.app",
                "UIBackgroundModes": ["audio"],
                "Entitlements": [
                    "com.apple.private.MobileContainerManager.allowed": true,
                    "com.apple.private.tcc.allow": [
                        "kTCCServiceAddressBook", "kTCCServiceCalendar", "kTCCServiceCamera",
                        "kTCCServiceMediaLibrary", "kTCCServicePhotos", "kTCCServiceReminders"
                    ],
                    "com.apple.private.photos.service.internal.cloud": true,
                    "com.apple.itunesstored.private": true,
                    "com.apple.security.application-groups": [
                        "group.com.apple.Maps",
                        "group.com.apple.icloud.fm",
                        "group.com.apple.notes",
                        "group.com.apple.sports",
                        "group.tvappservices.container"
                    ]
                ]
            ],
            "com.apple.Preferences": [
                "CFBundleIdentifier": "com.apple.Preferences",
                "CFBundleDisplayName": "设置",
                "ApplicationType": "System",
                "Path": "/Applications/Preferences.app",
                "Entitlements": [
                    "com.apple.developer.team-identifier": "UNLISTED99",
                    "com.apple.security.application-groups": ["group.tvappservices.container", "group.com.apple.preferences"]
                ]
            ],
            "com.apple.campo": [
                "CFBundleIdentifier": "com.apple.campo",
                "CFBundleDisplayName": "Siri",
                "ApplicationType": "Hidden",
                "Path": "/private/var/containers/Bundle/Application/UUID-CAMPO/Campo.app",
                "Entitlements": [
                    "com.apple.security.application-groups": ["group.tvappservices.container"]
                ]
            ],
            "com.apple.Spotlight": [
                "CFBundleIdentifier": "com.apple.Spotlight",
                "CFBundleDisplayName": "聚焦",
                "ApplicationType": "Hidden",
                "Path": "/Applications/Spotlight.app",
                "Entitlements": [
                    "com.apple.security.application-groups": ["group.tvappservices.container", "group.com.apple.search"]
                ]
            ],
            "com.apple.Translate": [
                "CFBundleIdentifier": "com.apple.Translate",
                "CFBundleDisplayName": "翻译",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-TR/Translate.app",
                "Entitlements": [
                    "com.apple.developer.team-identifier": "UNLISTED88",
                    "application-identifier": "UNLISTED88.com.apple.Translate",
                    "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"]
                ]
            ],
            "com.apple.AppStore": [
                "CFBundleIdentifier": "com.apple.AppStore",
                "CFBundleDisplayName": "App Store",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-AS/AppStore.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.itunesstored.private": true
                ]
            ],
            "com.apple.Health.SSV": [
                "CFBundleIdentifier": "com.apple.Health",
                "CFBundleDisplayName": "健康",
                "ApplicationType": "System",
                "Path": "/Applications/Health.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.security.no-container": true
                ]
            ],
            "com.apple.Health.StagedClean": [
                "CFBundleIdentifier": "com.apple.Health",
                "CFBundleDisplayName": "健康",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-H2/Health.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceMotion"],
                    "com.apple.security.application-groups": ["group.com.apple.healthkit"]
                ]
            ]
        ]
        for (label, raw) in iOS26ExtendedSystemJSON {
            let dict = raw as! [String: Any]
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary(dict))
            XCTAssertTrue(
                scanner.isAppleSystemOrFirstPartyApp(rec),
                "Real iOS 26 system app case \(label) (\(rec.bundleId)) must be excluded"
            )
            XCTAssertTrue(scanner.evaluateRecords([rec], includeAppStoreApps: true).isEmpty)
        }

        // Negative controls for App Group classifier & staged Health no-container
        for badGroup in ["group.io.metamask", "group.r10.backdoor", "group.com.evil.wallet", "group.ca628877a97ac6a2.1"] {
            XCTAssertFalse(
                InstalledAppRegistryScanner.isAppleOwnedAppGroup(badGroup),
                "Third-party App Group '\(badGroup)' must NOT match Apple-owned App Groups"
            )
        }
        let stagedHijackedHealth = InstalledAppRegistryRecord(
            bundleId: "com.apple.Health",
            displayName: "健康",
            version: "1.0",
            applicationType: "System",
            signerIdentity: nil,
            profileValidated: false,
            booleanEntitlements: ["com.apple.private.security.no-container": true],
            allEntitlementKeys: ["com.apple.private.security.no-container"],
            bundlePath: "/private/var/containers/Bundle/Application/UUID-HIJACK-HEALTH/Health.app"
        )
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(stagedHijackedHealth))
        XCTAssertEqual(scanner.evaluateRecord(stagedHijackedHealth).riskTier, .highRisk)

        // 6. Final 3 real-iOS 26 system apps (`Translate` with Team 96VJNMX6ZP, `TVRemoteApp`, `reminders` v7.0 with `no-sandbox`)
        let finalThreeSystemJSON: [String: Any] = [
            "com.apple.Translate.96VJ": [
                "CFBundleIdentifier": "com.apple.Translate",
                "CFBundleDisplayName": "翻译",
                "CFBundleShortVersionString": "1.0",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-TRANS/Translate.app",
                "UIBackgroundModes": ["audio"],
                "Entitlements": [
                    "com.apple.developer.team-identifier": "96VJNMX6ZP",
                    "com.apple.private.tcc.allow": ["kTCCServiceCamera", "kTCCServiceMicrophone", "kTCCServicePhotos"],
                    "com.apple.security.application-groups": [
                        "group.com.apple.private.translation",
                        "group.com.apple.tipsnext"
                    ]
                ]
            ],
            "com.apple.TVRemoteApp": [
                "CFBundleIdentifier": "com.apple.TVRemoteApp",
                "CFBundleDisplayName": "遥控器",
                "CFBundleShortVersionString": "1.0",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-TVR/TVRemoteApp.app",
                "Entitlements": [
                    "com.apple.private.tcc.allow": ["kTCCServiceBluetoothAlways", "kTCCServiceMediaLibrary", "kTCCServiceMicrophone"],
                    "com.apple.itunesstored.private": true,
                    "com.apple.security.application-groups": [
                        "group.com.apple.tipsnext",
                        "group.com.apple.TVRemote"
                    ]
                ]
            ],
            "com.apple.reminders": [
                "CFBundleIdentifier": "com.apple.reminders",
                "CFBundleDisplayName": "提醒事项",
                "CFBundleShortVersionString": "7.0",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-REM/Reminders.app",
                "Entitlements": [
                    "com.apple.private.security.no-sandbox": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceCamera"],
                    "com.apple.security.application-groups": [
                        "group.com.apple.reminders",
                        "group.com.apple.assistant.shared"
                    ]
                ]
            ]
        ]
        for (label, raw) in finalThreeSystemJSON {
            let dict = raw as! [String: Any]
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary(dict))
            XCTAssertTrue(
                scanner.isAppleSystemOrFirstPartyApp(rec),
                "Real iOS 26 system app \(label) (\(rec.bundleId)) must not false-positive"
            )
            XCTAssertTrue(scanner.evaluateRecords([rec], includeAppStoreApps: true).isEmpty)
        }

        // Spoofed Reminders without `group.com.apple.reminders` or with `container-required=false` MUST still be rejected
        let spoofedRemindersNoGroup = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.reminders",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-SPOOF-REM/Reminders.app",
            "Entitlements": ["com.apple.private.security.no-sandbox": true]
        ]))
        let spoofedRemindersNoContainerReq = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.reminders",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-SPOOF-REM2/Reminders.app",
            "Entitlements": [
                "com.apple.private.security.no-sandbox": true,
                "com.apple.private.security.container-required": false,
                "com.apple.security.application-groups": ["group.com.apple.reminders"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(spoofedRemindersNoGroup))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(spoofedRemindersNoContainerReq))

        // 7. Enterprise-resigned WQGuard host self-whitelist verification (including explicit enterprise App ID conflict + cached snapshot UUID swap)
        let resignedSelfWQGuard = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.wqguard.app",
            "CFBundleDisplayName": "WQGuard",
            "ApplicationType": "User",
            "SignerIdentity": "iPhone Distribution: Example Enterprise",
            "ProfileValidated": true,
            "Path": "/private/var/containers/Bundle/Application/OLD-SNAPSHOT-UUID/WQGuard.app",
            "Entitlements": [
                "com.apple.developer.team-identifier": "9NZA6279KY",
                "application-identifier": "9NZA6279KY.signall.enterprise.cert",
                "keychain-access-groups": ["9NZA6279KY.*", "com.apple.token"],
                "com.apple.security.application-groups": ["group.ca628877a97ac6a2.1"]
            ]
        ]))
        let preSelfEvalFinding = scanner.evaluateRecord(resignedSelfWQGuard)
        XCTAssertFalse(preSelfEvalFinding.evidence.isWhitelistEligible, "Explicit enterprise application-identifier conflicts with com.wqguard.app")
        XCTAssertEqual(preSelfEvalFinding.indicators.count, 1)
        XCTAssertEqual(
            scanner.isEligibleSelfResignedWQGuard(
                resignedSelfWQGuard,
                provisionalRisk: .caution,
                matchedSignatures: [],
                selfBundleId: "com.wqguard.app"
            ),
            "WQGuard"
        )
        let postSelfWhitelistCheck = WhitelistEngine.shared.evaluateFindingWhitelist(
            preSelfEvalFinding,
            runningSelfBundleId: "com.wqguard.app"
        )
        XCTAssertTrue(postSelfWhitelistCheck.isWhitelisted)
        XCTAssertEqual(postSelfWhitelistCheck.toolName, "WQGuard")

        let disabledEngine = WhitelistEngine()
        disabledEngine.toggleTool(named: "WQGuard", isEnabled: false)
        XCTAssertFalse(
            disabledEngine.evaluateFindingWhitelist(preSelfEvalFinding, runningSelfBundleId: "com.wqguard.app").isWhitelisted
        )

        XCTAssertNil(
            scanner.isEligibleSelfResignedWQGuard(
                resignedSelfWQGuard,
                provisionalRisk: .highRisk,
                matchedSignatures: ["com.apple.private.security.no-sandbox"],
                selfBundleId: "com.wqguard.app"
            )
        )
        let squattingWQGuard = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.wqguard.app",
            "CFBundleDisplayName": "WQGuard",
            "ApplicationType": "User",
            "SignerIdentity": "iPhone Distribution: Example Enterprise",
            "ProfileValidated": true,
            "Path": "/private/var/containers/Bundle/Application/UUID-WQG/WQGuard.app",
            "Entitlements": [
                "com.apple.security.application-groups": ["group.io.metamask"]
            ]
        ]))
        XCTAssertNil(
            scanner.isEligibleSelfResignedWQGuard(
                squattingWQGuard,
                provisionalRisk: .caution,
                matchedSignatures: [],
                selfBundleId: "com.wqguard.app"
            )
        )
        let unrelatedEnterpriseApp = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "cz.kolbi.wqfiles",
            "CFBundleDisplayName": "WQ Files",
            "ApplicationType": "User",
            "SignerIdentity": "iPhone Distribution: Example Enterprise",
            "ProfileValidated": true,
            "Path": "/private/var/containers/Bundle/Application/UUID-WQF/WQFiles.app",
            "Entitlements": [
                "com.apple.security.application-groups": ["group.ca628877a97ac6a2.1"]
            ]
        ]))
        XCTAssertNil(
            scanner.isEligibleSelfResignedWQGuard(
                unrelatedEnterpriseApp,
                provisionalRisk: .caution,
                matchedSignatures: [],
                selfBundleId: "com.wqguard.app"
            )
        )

        // 8. Long-tail Apple first-party safeguards (Shazam App Store vs sideloaded spoof, GarageBand / Tamale)
        let genuineShazam = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.shazam.ShazamApp",
            "CFBundleDisplayName": "Shazam",
            "ApplicationType": "User",
            "SignerIdentity": "Apple iPhone OS Application Signing",
            "ProfileValidated": false,
            "Entitlements": [
                "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"],
                "com.apple.private.mediaexperience.allow": true
            ]
        ]))
        let sideloadedFakeShazam = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.shazam.ShazamApp",
            "CFBundleDisplayName": "Shazam",
            "ApplicationType": "User",
            "SignerIdentity": "iPhone Distribution: Evil Corp",
            "ProfileValidated": true,
            "Entitlements": [
                "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"]
            ]
        ]))
        let preinstalledGarageBand = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.mobilegarageband",
            "CFBundleDisplayName": "库乐队",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-GB/MobileGarageBand.app",
            "Entitlements": [
                "com.apple.private.tcc.allow": ["kTCCServiceMicrophone", "kTCCServiceMediaLibrary"],
                "com.apple.security.application-groups": ["group.com.apple.mobilegarageband"]
            ]
        ]))
        XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(genuineShazam))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(sideloadedFakeShazam))
        XCTAssertEqual(scanner.evaluateRecord(sideloadedFakeShazam).riskTier, .highRisk)
        XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(preinstalledGarageBand))
    }
}
