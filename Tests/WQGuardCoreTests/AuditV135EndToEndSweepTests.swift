//
//  AuditV135EndToEndSweepTests.swift
//  WQGuardCoreTests
//
//  Milestone M5 End-to-End Tier-5 Regression & Adversarial Sweep Suite:
//  - 104/104 SimRuntime App Groups dual-engine + registry highRisk + custom-rule rejection
//  - All 12 R4 stock apps + genuine TestFlight (Surge/APTV) + enterprise-resigned WQGuard matrix
//  - Cross-engine TestFlight Option A parity & tampered channel isolation
//  - Lokey-style S_IFDIR _CodeSignature/ ZIP directory entries & own-team/legacy keychain wildcards
//  - Unified 3-engine scanUnifiedInstalledAppsAsync -> ReportGenerator JSON/Markdown/PlainText round-trip
//  - CLICommandRunner E2E (--version, --firmware-radar, --export-surge, --export-shield, --ipa, --whitelist)
//  - On-disk Shields/* + brotli-guard.js live JavaScriptCore sweep
//  - Built build/WQGuard_v1.3.5.ipa manifest, Mach-O ARM64, self-armor & ReadOnlyAssertions audit
//  - Bilingual en / zh-Hans localization parity
//  - R3 repository hygiene, version 1.3.5 / Build 26 sync & preserved constants
//  - Deterministic regression tests for M5 Fixes 1, 2, and 3
//

import CryptoKit
import Darwin
import Foundation
import JavaScriptCore
import MachO
import Security
import XCTest
import zlib
@testable import WQGuardCore

final class AuditV135EndToEndSweepTests: XCTestCase {

    private var tempURLs: [URL] = []

    override func setUp() {
        super.setUp()
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
    }

    override func tearDown() {
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
        for url in tempURLs {
            _ = try? FileManager.default.removeItem(at: url)
        }
        tempURLs.removeAll()
        super.tearDown()
    }

    private var repoRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // WQGuardCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // WQGuard
    }

    @discardableResult
    private func trackTemp(_ url: URL) -> URL {
        tempURLs.append(url)
        return url
    }

    private func makeTempDir(prefix: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return trackTemp(dir)
    }

    private func runCLIInProcess(_ args: [String]) async throws -> (code: Int32, out: String, err: String) {
        let dir = try makeTempDir(prefix: "m5_cli_io")
        let outURL = dir.appendingPathComponent("stdout.txt")
        let errURL = dir.appendingPathComponent("stderr.txt")
        FileManager.default.createFile(atPath: outURL.path, contents: nil)
        FileManager.default.createFile(atPath: errURL.path, contents: nil)
        let outH = try FileHandle(forWritingTo: outURL)
        let errH = try FileHandle(forWritingTo: errURL)
        let code = await CLICommandRunner.run(arguments: ["wqguard-cli"] + args, stdout: outH, stderr: errH)
        try outH.close()
        try errH.close()
        return (
            code,
            String(decoding: try Data(contentsOf: outURL), as: UTF8.self),
            String(decoding: try Data(contentsOf: errURL), as: UTF8.self)
        )
    }

    private struct RawZIPItem {
        let name: String
        let data: Data
        let externalAttrs: UInt32
        init(name: String, data: Data = Data(), externalAttrs: UInt32 = 0) {
            self.name = name
            self.data = data
            self.externalAttrs = externalAttrs
        }
    }

    private func buildStoredRawZIP(_ items: [RawZIPItem]) -> Data {
        var out = Data()
        var centralDir = Data()

        func appendLE16(_ d: inout Data, _ v: UInt16) {
            var le = v.littleEndian
            withUnsafeBytes(of: &le) { d.append(contentsOf: $0) }
        }
        func appendLE32(_ d: inout Data, _ v: UInt32) {
            var le = v.littleEndian
            withUnsafeBytes(of: &le) { d.append(contentsOf: $0) }
        }

        for item in items {
            let nameBytes = Data(item.name.utf8)
            let localOffset = UInt32(out.count)
            let crc = item.data.withUnsafeBytes { ptr -> UInt32 in
                let base = ptr.bindMemory(to: Bytef.self).baseAddress
                return UInt32(zlib.crc32(0, base, uInt(item.data.count)))
            }
            let sz = UInt32(item.data.count)

            appendLE32(&out, 0x04034b50)
            appendLE16(&out, 20)
            appendLE16(&out, 0)
            appendLE16(&out, 0) // stored
            appendLE16(&out, 0)
            appendLE16(&out, 0)
            appendLE32(&out, crc)
            appendLE32(&out, sz)
            appendLE32(&out, sz)
            appendLE16(&out, UInt16(nameBytes.count))
            appendLE16(&out, 0)
            out.append(nameBytes)
            out.append(item.data)

            appendLE32(&centralDir, 0x02014b50)
            appendLE16(&centralDir, 0x031E) // Unix creator
            appendLE16(&centralDir, 20)
            appendLE16(&centralDir, 0)
            appendLE16(&centralDir, 0)
            appendLE16(&centralDir, 0)
            appendLE16(&centralDir, 0)
            appendLE32(&centralDir, crc)
            appendLE32(&centralDir, sz)
            appendLE32(&centralDir, sz)
            appendLE16(&centralDir, UInt16(nameBytes.count))
            appendLE16(&centralDir, 0)
            appendLE16(&centralDir, 0)
            appendLE16(&centralDir, 0)
            appendLE16(&centralDir, 0)
            appendLE32(&centralDir, item.externalAttrs)
            appendLE32(&centralDir, localOffset)
            centralDir.append(nameBytes)
        }

        let cdOffset = UInt32(out.count)
        let cdSize = UInt32(centralDir.count)
        out.append(centralDir)

        appendLE32(&out, 0x06054b50)
        appendLE16(&out, 0)
        appendLE16(&out, 0)
        appendLE16(&out, UInt16(items.count))
        appendLE16(&out, UInt16(items.count))
        appendLE32(&out, cdSize)
        appendLE32(&out, cdOffset)
        appendLE16(&out, 0)
        return out
    }

    private func buildMinimalMachOWithSeals(
        cstringPayload: Data = Data(),
        infoPlistData: Data? = nil,
        codeDirectoryIdentifier: String,
        teamIdentifier: String? = nil,
        xmlEntitlements: String? = nil,
        codeResourcesData: Data? = nil
    ) -> Data {
        func appendLE32(_ out: inout Data, _ v: UInt32) {
            var le = v.littleEndian
            withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
        }
        func appendLE64(_ out: inout Data, _ v: UInt64) {
            var le = v.littleEndian
            withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
        }
        func appendBE32(_ out: inout Data, _ v: UInt32) {
            var be = v.bigEndian
            withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
        }
        func fixed16(_ str: String) -> Data {
            var d = Data(repeating: 0, count: 16)
            for (i, b) in str.utf8.prefix(16).enumerated() { d[i] = b }
            return d
        }

        var textSections: [(seg: String, sect: String, data: Data)] = []
        if !cstringPayload.isEmpty {
            textSections.append(("__TEXT", "__cstring", cstringPayload))
        }
        if let infoPlistData {
            textSections.append(("__TEXT", "__info_plist", infoPlistData))
        }

        let headerSize = 32
        let textCmdSize = UInt32(72 + 80 * textSections.count)
        let csCmdSize: UInt32 = 16
        let linkeditCmdSize: UInt32 = 72
        let sizeofcmds = textCmdSize + csCmdSize + linkeditCmdSize
        let ncmds: UInt32 = 3

        let textStart = 4096
        var cursor = textStart
        var sectOffsets: [Int] = []
        for s in textSections {
            sectOffsets.append(cursor)
            cursor += s.data.count
        }
        let textEnd = max(textStart + 4096, ((cursor + 4095) / 4096) * 4096)
        var fileBytes = Data(repeating: 0, count: textEnd)
        for (idx, s) in textSections.enumerated() {
            fileBytes.replaceSubrange(sectOffsets[idx]..<(sectOffsets[idx] + s.data.count), with: s.data)
        }

        let linkeditOffset = fileBytes.count
        let entData = xmlEntitlements.map { Data($0.utf8) }
        let placeholderCD = M1TestCMSFixtures.buildCodeDirectory(
            identifier: codeDirectoryIdentifier,
            codeLimit: linkeditOffset,
            slicePrefixBytes: fileBytes,
            infoPlistData: infoPlistData,
            codeResourcesData: codeResourcesData,
            slot5Blob: entData,
            teamIdentifier: teamIdentifier
        )
        var placeholderSlots: [(UInt32, Data)] = [(CSBlobConstants.slotCodeDirectory, placeholderCD)]
        if let entData {
            var entBlob = Data()
            appendBE32(&entBlob, CSBlobConstants.entitlementXmlMagic)
            appendBE32(&entBlob, UInt32(8 + entData.count))
            entBlob.append(entData)
            placeholderSlots.append((CSBlobConstants.slotEntitlements, entBlob))
        }
        let placeholderSB = M1TestCMSFixtures.buildSuperBlob(slots: placeholderSlots)
        fileBytes.append(placeholderSB)
        let linkeditSize = fileBytes.count - linkeditOffset

        var hdr = Data()
        appendLE32(&hdr, MH_MAGIC_64)
        appendLE32(&hdr, UInt32(bitPattern: CPU_TYPE_ARM64))
        appendLE32(&hdr, UInt32(bitPattern: CPU_SUBTYPE_ARM64_ALL))
        appendLE32(&hdr, UInt32(MH_EXECUTE))
        appendLE32(&hdr, ncmds)
        appendLE32(&hdr, sizeofcmds)
        appendLE32(&hdr, 0x0020_0085)
        appendLE32(&hdr, 0)

        var cmds = Data()
        appendLE32(&cmds, UInt32(LC_SEGMENT_64))
        appendLE32(&cmds, textCmdSize)
        cmds.append(fixed16("__TEXT"))
        appendLE64(&cmds, 0x100000000)
        appendLE64(&cmds, UInt64(textEnd))
        appendLE64(&cmds, 0)
        appendLE64(&cmds, UInt64(textEnd))
        appendLE32(&cmds, 5)
        appendLE32(&cmds, 5)
        appendLE32(&cmds, UInt32(textSections.count))
        appendLE32(&cmds, 0)
        for (idx, s) in textSections.enumerated() {
            cmds.append(fixed16(s.sect))
            cmds.append(fixed16(s.seg))
            appendLE64(&cmds, 0x100000000 + UInt64(sectOffsets[idx]))
            appendLE64(&cmds, UInt64(s.data.count))
            appendLE32(&cmds, UInt32(sectOffsets[idx]))
            appendLE32(&cmds, 0)
            appendLE32(&cmds, 0)
            appendLE32(&cmds, 0)
            appendLE32(&cmds, 0)
            appendLE32(&cmds, 0)
            appendLE32(&cmds, 0)
            appendLE32(&cmds, 0)
        }

        appendLE32(&cmds, UInt32(LC_CODE_SIGNATURE))
        appendLE32(&cmds, 16)
        appendLE32(&cmds, UInt32(linkeditOffset))
        appendLE32(&cmds, UInt32(placeholderSB.count))

        appendLE32(&cmds, UInt32(LC_SEGMENT_64))
        appendLE32(&cmds, linkeditCmdSize)
        cmds.append(fixed16("__LINKEDIT"))
        appendLE64(&cmds, 0x100000000 + UInt64(textEnd))
        appendLE64(&cmds, UInt64(max(4096, linkeditSize)))
        appendLE64(&cmds, UInt64(linkeditOffset))
        appendLE64(&cmds, UInt64(linkeditSize))
        appendLE32(&cmds, 1)
        appendLE32(&cmds, 1)
        appendLE32(&cmds, 0)
        appendLE32(&cmds, 0)

        fileBytes.replaceSubrange(0..<headerSize, with: hdr)
        fileBytes.replaceSubrange(headerSize..<(headerSize + Int(sizeofcmds)), with: cmds)

        let cd = M1TestCMSFixtures.buildCodeDirectory(
            identifier: codeDirectoryIdentifier,
            codeLimit: linkeditOffset,
            slicePrefixBytes: Data(fileBytes[0..<linkeditOffset]),
            infoPlistData: infoPlistData,
            codeResourcesData: codeResourcesData,
            slot5Blob: entData,
            teamIdentifier: teamIdentifier
        )
        var slots: [(UInt32, Data)] = [(CSBlobConstants.slotCodeDirectory, cd)]
        if let entData {
            var entBlob = Data()
            appendBE32(&entBlob, CSBlobConstants.entitlementXmlMagic)
            appendBE32(&entBlob, UInt32(8 + entData.count))
            entBlob.append(entData)
            slots.append((CSBlobConstants.slotEntitlements, entBlob))
        }
        let finalSB = M1TestCMSFixtures.buildSuperBlob(slots: slots)
        fileBytes.replaceSubrange(linkeditOffset..<(linkeditOffset + finalSB.count), with: finalSB)
        return fileBytes
    }

    private func zipDirectory(_ payloadParentDir: URL, to ipaURL: URL) throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        proc.currentDirectoryURL = payloadParentDir
        proc.arguments = ["-qr", ipaURL.path, "Payload"]
        try proc.run()
        proc.waitUntilExit()
        XCTAssertEqual(proc.terminationStatus, 0, "zip failed creating \(ipaURL.lastPathComponent)")
    }

    // MARK: - E2E 01: 104/104 SimRuntime App Groups Dual-Engine + Registry + Whitelist Sweep

    func test_e2e_01_simRuntime104AppGroups_dualEngineAndThirdPartyHighRiskSweep() throws {
        let simRuntime104Groups: [String] = [
            "com.apple.CoreODI",
            "com.apple.Home.group",
            "com.apple.MailPersonaStorage",
            "com.apple.MusicUI.engagement",
            "com.apple.SafariSearchUploadWorker",
            "com.apple.SonicKit",
            "com.apple.bird",
            "com.apple.poirot.SearchAnalyticsWorker",
            "com.apple.poirot.poirot_tool",
            "com.apple.reminders",
            "group.com.apple.AdaptiveMusicApp",
            "group.com.apple.BlockMonitoring",
            "group.com.apple.BrowserKit",
            "group.com.apple.CloudDocs",
            "group.com.apple.CoreSpeech",
            "group.com.apple.DocumentManager",
            "group.com.apple.FaceTime",
            "group.com.apple.FileProvider.DomainCaching",
            "group.com.apple.FileProvider.LocalStorage",
            "group.com.apple.Fitness",
            "group.com.apple.GenerativePlayground",
            "group.com.apple.Health",
            "group.com.apple.Journal",
            "group.com.apple.ManagedSettings",
            "group.com.apple.Maps",
            "group.com.apple.Music",
            "group.com.apple.PegasusConfiguration",
            "group.com.apple.Photos.PhotosFileProvider",
            "group.com.apple.ScreenContinuityServices",
            "group.com.apple.ScreenTime",
            "group.com.apple.SiriTTS",
            "group.com.apple.SuggestedImage.SharedSecureContainer",
            "group.com.apple.TVRemote",
            "group.com.apple.UserNotifications",
            "group.com.apple.VoiceMemos.shared",
            "group.com.apple.accessibility.voicebanking",
            "group.com.apple.amsondevicestoraged",
            "group.com.apple.assistant.shared",
            "group.com.apple.assistant.shared.backedup",
            "group.com.apple.calendar",
            "group.com.apple.callintelligence",
            "group.com.apple.communicationtrustd",
            "group.com.apple.contacts.private-access",
            "group.com.apple.corehandwriting",
            "group.com.apple.coreservices.useractivityd",
            "group.com.apple.desktopservices.ArchiveService.AppGroupContainer",
            "group.com.apple.feedback",
            "group.com.apple.feedbacklogger",
            "group.com.apple.freeform",
            "group.com.apple.gamecenter",
            "group.com.apple.guestData",
            "group.com.apple.iBooks",
            "group.com.apple.iCloudDrive",
            "group.com.apple.icloud.findmydevice.shared-configuration",
            "group.com.apple.icloud.fm",
            "group.com.apple.intelligenceflow",
            "group.com.apple.jetpackassetd",
            "group.com.apple.liveactivitiesd",
            "group.com.apple.mail",
            "group.com.apple.mlhost",
            "group.com.apple.mobileslideshow.PhotosFileProvider",
            "group.com.apple.mobiletimerd",
            "group.com.apple.moments",
            "group.com.apple.musicd",
            "group.com.apple.musicrecognition",
            "group.com.apple.news",
            "group.com.apple.newsd",
            "group.com.apple.notes",
            "group.com.apple.notes.import",
            "group.com.apple.people",
            "group.com.apple.photolibraryd.private",
            "group.com.apple.poirot.MessagesAnalyticsWorker",
            "group.com.apple.pommes",
            "group.com.apple.private.translation",
            "group.com.apple.rapportd",
            "group.com.apple.reminders",
            "group.com.apple.replicatord",
            "group.com.apple.safari",
            "group.com.apple.servicesanalytics",
            "group.com.apple.servicesintelligenced",
            "group.com.apple.sharingd",
            "group.com.apple.shortcuts",
            "group.com.apple.siri.ASR.shared",
            "group.com.apple.siri.findmy",
            "group.com.apple.siri.inference",
            "group.com.apple.siri.referenceResolution",
            "group.com.apple.siri.sirisuggestions",
            "group.com.apple.siri.userfeedbacklearning",
            "group.com.apple.sports",
            "group.com.apple.stocks",
            "group.com.apple.stocks-news",
            "group.com.apple.storekit",
            "group.com.apple.suggestions.mail-intelligence",
            "group.com.apple.tips",
            "group.com.apple.tipsnext",
            "group.com.apple.tv.sharedcontainer",
            "group.com.apple.uiunderstanding",
            "group.com.apple.usernoted",
            "group.com.apple.weather",
            "group.com.apple.weather.internal",
            "group.is.workflow.my.app",
            "group.is.workflow.shortcuts",
            "group.tvappservices.container",
            "systemgroup.com.apple.accessorysetupkit"
        ]
        XCTAssertEqual(simRuntime104Groups.count, 104)

        let customWL = WhitelistEngine()
        customWL.registerCustomTool(WhitelistedTool(
            name: "AttackerEmptyGroupsRule",
            allowedBundleIds: ["com.attacker.app"],
            allowedAppGroups: [],
            expectedSignatures: [],
            isEnabled: true,
            isBuiltIn: false
        ))

        for group in simRuntime104Groups {
            XCTAssertTrue(
                InstalledAppRegistryScanner.isAppleOwnedAppGroup(group),
                "isAppleOwnedAppGroup must accept SimRuntime group '\(group)'"
            )
            XCTAssertTrue(
                ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup(group),
                "isProtectedVictimOrAppleSystemAppGroup must protect SimRuntime group '\(group)'"
            )

            let attackerRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.attacker.app",
                "CFBundleDisplayName": "Attacker",
                "ApplicationType": "User",
                "SignerIdentity": "iPhone Developer: Attacker",
                "ProfileValidated": true,
                "Path": "/private/var/containers/Bundle/Application/UUID-ATK/Attacker.app",
                "Entitlements": [
                    "com.apple.security.application-groups": [group]
                ]
            ]))
            let finding = InstalledAppRegistryScanner.shared.evaluateRecord(attackerRec)
            XCTAssertEqual(
                finding.riskTier,
                .highRisk,
                "Third-party app claiming SimRuntime group '\(group)' must be .highRisk"
            )

            let wlRes = customWL.isWhitelisted(
                bundleId: "com.attacker.app",
                appGroups: [group],
                matchedSignatures: ["com.apple.security.application-groups"]
            )
            XCTAssertFalse(
                wlRes.isWhitelisted,
                "Custom WhitelistEngine rule must reject SimRuntime group '\(group)'"
            )
        }
    }

    // MARK: - E2E 02: All 12 R4 Stock Apps + Surge/APTV TestFlight + Resigned Host WQGuard Matrix

    func test_e2e_02_r4All12StockAppsAndTestFlightAndResignedHostMatrix() throws {
        let rawApps: [String: Any] = [
            "com.apple.reminders": [
                "CFBundleIdentifier": "com.apple.reminders",
                "CFBundleShortVersionString": "7.0",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-REM/Reminders.app",
                "Entitlements": [
                    "com.apple.private.security.no-sandbox": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceCamera"],
                    "com.apple.security.application-groups": ["group.com.apple.reminders", "group.com.apple.assistant.shared"]
                ]
            ],
            "com.apple.Translate": [
                "CFBundleIdentifier": "com.apple.Translate",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-TR/Translate.app",
                "Entitlements": [
                    "com.apple.developer.team-identifier": "96VJNMX6ZP",
                    "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"]
                ]
            ],
            "com.apple.siri": [
                "CFBundleIdentifier": "com.apple.siri",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-SIRI/Siri.app",
                "Entitlements": ["com.apple.security.application-groups": ["group.tvappservices.container"]]
            ],
            "com.apple.Preferences": [
                "CFBundleIdentifier": "com.apple.Preferences",
                "ApplicationType": "System",
                "Path": "/Applications/Preferences.app",
                "Entitlements": ["com.apple.security.application-groups": ["group.tvappservices.container"]]
            ],
            "com.apple.campo": [
                "CFBundleIdentifier": "com.apple.campo",
                "ApplicationType": "Hidden",
                "Path": "/private/var/containers/Bundle/Application/UUID-CAMPO/Campo.app",
                "Entitlements": ["com.apple.security.application-groups": ["group.tvappservices.container"]]
            ],
            "com.apple.Spotlight": [
                "CFBundleIdentifier": "com.apple.Spotlight",
                "ApplicationType": "Hidden",
                "Path": "/Applications/Spotlight.app",
                "Entitlements": ["com.apple.security.application-groups": ["group.tvappservices.container"]]
            ],
            "com.apple.Health": [
                "CFBundleIdentifier": "com.apple.Health",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-HEALTH/Health.app",
                "Entitlements": ["platform-application": true]
            ],
            "com.apple.TVRemoteApp": [
                "CFBundleIdentifier": "com.apple.TVRemoteApp",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-TVR/TVRemoteApp.app",
                "Entitlements": ["com.apple.security.application-groups": ["group.com.apple.TVRemote"]]
            ],
            "com.apple.shortcuts": [
                "CFBundleIdentifier": "com.apple.shortcuts",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-SC/Shortcuts.app",
                "Entitlements": ["platform-application": true, "com.apple.security.application-groups": ["group.is.workflow.my.app"]]
            ],
            "com.apple.MobileSMS": [
                "CFBundleIdentifier": "com.apple.MobileSMS",
                "ApplicationType": "System",
                "Path": "/Applications/MobileSMS.app",
                "Entitlements": ["platform-application": true, "com.apple.private.security.no-container": true]
            ],
            "com.apple.DocumentsApp": [
                "CFBundleIdentifier": "com.apple.DocumentsApp",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-DOCS/Files.app",
                "Entitlements": ["platform-application": true]
            ],
            "com.shazam.ShazamApp": [
                "CFBundleIdentifier": "com.shazam.ShazamApp",
                "ApplicationType": "User",
                "SignerIdentity": "Apple iPhone OS Application Signing",
                "ProfileValidated": false,
                "Path": "/private/var/containers/Bundle/Application/UUID-SHAZAM/Shazam.app"
            ],
            "com.nssurge.inc.surge-ios": [
                "CFBundleIdentifier": "com.nssurge.inc.surge-ios",
                "CFBundleDisplayName": "Surge",
                "CFBundleShortVersionString": "5.14.0",
                "ApplicationType": "User",
                "SignerIdentity": "TestFlight Beta Distribution",
                "ProfileValidated": true,
                "ApplicationDSID": 987654321,
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
                "Entitlements": [
                    "application-identifier": "APTV888888.com.kimen.aptvpro",
                    "com.apple.developer.team-identifier": "APTV888888",
                    "com.apple.security.application-groups": ["group.com.kimen.aptvpro"]
                ],
                "Path": "/private/var/containers/Bundle/Application/UUID-APTV/APTV.app"
            ],
            "com.resigned.wqguard": [
                "CFBundleIdentifier": "com.resigned.wqguard",
                "CFBundleDisplayName": "WQGuard",
                "CFBundleShortVersionString": "1.3.5",
                "ApplicationType": "User",
                "SignerIdentity": "iPhone Distribution: Custom Enterprise",
                "ProfileValidated": true,
                "Entitlements": [
                    "application-identifier": "RESIGN9999.com.wqguard.app",
                    "com.apple.developer.team-identifier": "RESIGN9999",
                    "com.apple.security.application-groups": ["group.resigned.wqguard"]
                ],
                "Path": "/private/var/containers/Bundle/Application/STALE-UUID-WQ/WQGuard.app"
            ]
        ]

        let snapshotData = try JSONSerialization.data(withJSONObject: rawApps, options: [])
        let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(snapshotData)
        XCTAssertEqual(records.count, 15)

        let nonStoreFindings = InstalledAppRegistryScanner.shared.evaluateRecords(records, includeAppStoreApps: false)
        XCTAssertFalse(nonStoreFindings.contains(where: { $0.riskTier == .highRisk }), "Zero .highRisk expected in non-store matrix")
        XCTAssertEqual(nonStoreFindings.map(\.bundleId), ["com.resigned.wqguard"])

        let allFindings = InstalledAppRegistryScanner.shared.evaluateRecords(records, includeAppStoreApps: true)
        XCTAssertFalse(allFindings.contains(where: { $0.riskTier == .highRisk }), "Zero .highRisk expected across all 15 R4/TestFlight/host records")
        let surgeFinding = try XCTUnwrap(allFindings.first { $0.bundleId == "com.nssurge.inc.surge-ios" })
        let aptvFinding = try XCTUnwrap(allFindings.first { $0.bundleId == "com.kimen.aptvpro" })
        XCTAssertEqual(surgeFinding.installChannel, .testFlight)
        XCTAssertEqual(surgeFinding.riskTier, .safe)
        XCTAssertEqual(aptvFinding.installChannel, .testFlight)
        XCTAssertEqual(aptvFinding.riskTier, .safe)

        let wqFinding = try XCTUnwrap(allFindings.first { $0.bundleId == "com.resigned.wqguard" })
        let selfRes = WhitelistEngine.shared.evaluateFindingWhitelist(wqFinding, runningSelfBundleId: "com.resigned.wqguard")
        XCTAssertTrue(selfRes.isWhitelisted)
        XCTAssertEqual(selfRes.toolName, "WQGuard")

        let spoofedRes = WhitelistEngine.shared.isWhitelisted(
            bundleId: "com.wqguard.app",
            appGroups: ["group.attacker.evil"],
            matchedSignatures: ["container_query_create"]
        )
        XCTAssertFalse(spoofedRes.isWhitelisted)
        XCTAssertNil(spoofedRes.toolName)
    }

    // MARK: - E2E 03: Cross-Engine TestFlight Parity & Tampered Channel Isolation

    func test_e2e_03_crossEngineTestFlightParity_and_tamperedChannelIsolation() throws {
        let state = try M1TestCMSFixtures.sharedState()
        let dir = try makeTempDir(prefix: "e2e_tf")

        let (_, cleanTFIPA, rootCert) = try M1TestCMSFixtures.buildSignedAppBundleAndIPA(
            in: dir,
            appName: "CleanTF",
            bundleId: "com.test.e2e.tf",
            cryptid: 1,
            signerLeaf: state.testFlightLeaf,
            teamIdentifier: "TEAMTF1234"
        )
        let cleanFinding = try IPAPackageScanner.shared.scan(ipaURL: cleanTFIPA, customAnchorCertificates: [rootCert])
        XCTAssertEqual(cleanFinding.installChannel, .testFlight)
        XCTAssertEqual(cleanFinding.riskTier, .safe)

        let tfReg = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.test.e2e.tf",
            "CFBundleDisplayName": "CleanTF",
            "CFBundleShortVersionString": "1.0",
            "ApplicationType": "User",
            "SignerIdentity": "TestFlight Beta Distribution",
            "ProfileValidated": true,
            "Entitlements": [
                "application-identifier": "TEAMTF1234.com.test.e2e.tf",
                "com.apple.developer.team-identifier": "TEAMTF1234"
            ],
            "Path": "/private/var/containers/Bundle/Application/UUID-TF/CleanTF.app"
        ]))

        let mergedClean = SecurityPipeline.shared.correlateAndMergeFindings(
            registryRecords: [tfReg],
            packageFindings: [cleanFinding],
            includeAppStoreApps: true
        )
        XCTAssertEqual(mergedClean.correlatedCount, 1)
        XCTAssertEqual(mergedClean.findings.count, 1)
        XCTAssertEqual(mergedClean.findings.first?.installChannel, .testFlight)
        XCTAssertEqual(mergedClean.findings.first?.riskTier, .safe)

        // Tampered / sideloaded IPA with same bundleId + dangerous primitive must NOT merge with TestFlight registry record
        let tamperedBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.test.e2e.tf"]),
            extraCStringLiterals: ["com.apple.containermanagerd"]
        ))
        let tamperedIPA = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "TamperedTF",
            bundleIdentifier: "com.test.e2e.tf",
            executableBinary: tamperedBin,
            provisioningProfile: .developerSideloaded(teamId: "EVIL999999", devices: ["DEV1"])
        )))
        let tamperedFinding = try IPAPackageScanner.shared.scan(ipaURL: tamperedIPA)
        XCTAssertEqual(tamperedFinding.installChannel, .developerSideloaded)
        XCTAssertEqual(tamperedFinding.riskTier, .highRisk)

        let mergedTampered = SecurityPipeline.shared.correlateAndMergeFindings(
            registryRecords: [tfReg],
            packageFindings: [tamperedFinding],
            includeAppStoreApps: true
        )
        XCTAssertEqual(mergedTampered.correlatedCount, 0)
        XCTAssertTrue(mergedTampered.findings.contains(where: { $0.riskTier == .highRisk && $0.installChannel == .developerSideloaded }))

        // scanBinary / scanBundle on unsigned Mach-O & forged Apple Distribution BetaApp registry record never yield .testFlight
        let unsignedBinURL = dir.appendingPathComponent("unsigned_tf_spoof")
        try tamperedBin.write(to: unsignedBinURL)
        XCTAssertNotEqual(try SecurityPipeline.shared.scanBinary(at: unsignedBinURL).installChannel, .testFlight)

        let bundleURL = dir.appendingPathComponent("UnsignedTF.app")
        try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)
        try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.test.e2e.tf", "CFBundleExecutable": "UnsignedTF"],
            format: .xml,
            options: 0
        ).write(to: bundleURL.appendingPathComponent("Info.plist"))
        try tamperedBin.write(to: bundleURL.appendingPathComponent("UnsignedTF"))
        XCTAssertNotEqual(try SecurityPipeline.shared.scanBundle(at: bundleURL).installChannel, .testFlight)

        let forgedReg = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.forged.beta",
            "CFBundleDisplayName": "BetaApp",
            "ApplicationType": "User",
            "SignerIdentity": "Apple Distribution: Forged Corp (FORGED1234)",
            "ProfileValidated": true,
            "Entitlements": ["beta-reports-active": true],
            "Path": "/private/var/containers/Bundle/Application/UUID-FORGED/BetaApp.app"
        ]))
        XCTAssertNotEqual(InstalledAppRegistryScanner.shared.evaluateRecord(forgedReg).installChannel, .testFlight)
    }

    // MARK: - E2E 04: Lokey-Style _CodeSignature/ Directory Entries & Team-Owned Keychain Wildcards

    func test_e2e_04_lokeyStyleZipDirectoryEntries_and_teamOwnedKeychainWildcards() throws {
        let dir = try makeTempDir(prefix: "e2e_lokey")
        let teamId = "9NZA6279KY"
        let bundleId = "com.lokey.client"

        let compliantEnts = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>application-identifier</key><string>\(teamId).\(bundleId)</string>
            <key>com.apple.developer.team-identifier</key><string>\(teamId)</string>
            <key>keychain-access-groups</key><array>
                <string>\(teamId).*</string>
                <string>\(teamId).com.weibo.*</string>
            </array>
        </dict></plist>
        """
        let infoPlistData = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": bundleId,
                "CFBundleExecutable": "Lokey",
                "CFBundleDisplayName": "Lokey",
                "CFBundleShortVersionString": "1.0"
            ],
            format: .xml,
            options: 0
        )
        let (lokeyBin, rootCert) = try M1TestCMSFixtures.buildSignedMachO(
            identifier: bundleId,
            cryptid: 0,
            xmlEntitlements: compliantEnts,
            infoPlistData: infoPlistData,
            teamIdentifier: teamId
        )
        let (provCMS, _) = try M1TestCMSFixtures.buildCMSProvisioningProfile(plistDict: [
            "AppIDName": "Lokey",
            "ApplicationIdentifierPrefix": [teamId],
            "TeamIdentifier": [teamId],
            "Entitlements": [
                "application-identifier": "\(teamId).\(bundleId)",
                "com.apple.developer.team-identifier": teamId,
                "keychain-access-groups": ["\(teamId).*", "\(teamId).com.weibo.*"]
            ],
            "ProvisionedDevices": ["00008110-0011223344556677"]
        ])

        let dirAttrs = UInt32(0o040755) << 16
        let execAttrs = UInt32(0o100755) << 16
        let lokeyZIP = buildStoredRawZIP([
            RawZIPItem(name: "Payload/", data: Data(), externalAttrs: dirAttrs),
            RawZIPItem(name: "Payload/Lokey.app/", data: Data(), externalAttrs: dirAttrs),
            RawZIPItem(name: "Payload/Lokey.app/_CodeSignature/", data: Data(), externalAttrs: dirAttrs),
            RawZIPItem(name: "Payload/Lokey.app/Info.plist", data: infoPlistData),
            RawZIPItem(name: "Payload/Lokey.app/Lokey", data: lokeyBin, externalAttrs: execAttrs),
            RawZIPItem(name: "Payload/Lokey.app/embedded.mobileprovision", data: provCMS)
        ])
        let lokeyIPA = dir.appendingPathComponent("Lokey-unsigned (1).ipa")
        try lokeyZIP.write(to: lokeyIPA)

        let lokeyFinding = try IPAPackageScanner.shared.scan(ipaURL: lokeyIPA, customAnchorCertificates: [rootCert])
        XCTAssertFalse(
            lokeyFinding.indicators.contains { $0.signature.contains("MalformedPackage") },
            "Explicit _CodeSignature/ S_IFDIR directory entry must not trigger MalformedPackage"
        )
        XCTAssertFalse(
            lokeyFinding.indicators.contains { $0.signature.contains("keychain-access-groups") && $0.severity == .highRisk },
            "Team-owned & legacy prefix keychain wildcards must not trigger highRisk: \(lokeyFinding.indicators)"
        )
        XCTAssertNotEqual(lokeyFinding.riskTier, .highRisk)

        // Control: Ad-Hoc / "*" / "com.apple.*" / cross-team wildcards remain .highRisk
        let badWildcards = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>keychain-access-groups</key><array>
                <string>*</string>
                <string>com.apple.*</string>
                <string>OTHER99999.*</string>
            </array>
        </dict></plist>
        """
        let badBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            xmlEntitlements: badWildcards
        ))
        let badIPA = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "BadWildcard",
            bundleIdentifier: "com.evil.wildcard",
            executableBinary: badBin,
            provisioningProfile: .none
        )))
        let badFinding = try SecurityPipeline.shared.scanIPA(at: badIPA)
        XCTAssertEqual(badFinding.riskTier, .highRisk)
    }

    // MARK: - E2E 05: Unified 3-Engine Pipeline -> ReportGenerator JSON/Markdown/PlainText Round-Trip

    func test_e2e_05_unifiedThreeEnginePipeline_to_ReportGeneratorRoundTrip() async throws {
        let dir = try makeTempDir(prefix: "e2e_unified")

        let snapshotApps: [String: Any] = [
            "com.apple.reminders": [
                "CFBundleIdentifier": "com.apple.reminders",
                "CFBundleShortVersionString": "7.0",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-REM/Reminders.app",
                "Entitlements": [
                    "com.apple.private.security.no-sandbox": true,
                    "com.apple.security.application-groups": ["group.com.apple.reminders"]
                ]
            ],
            "com.nssurge.inc.surge-ios": [
                "CFBundleIdentifier": "com.nssurge.inc.surge-ios",
                "CFBundleDisplayName": "Surge",
                "ApplicationType": "User",
                "SignerIdentity": "TestFlight Beta Distribution",
                "ProfileValidated": true,
                "Path": "/private/var/containers/Bundle/Application/UUID-SURGE/Surge-iOS.app"
            ]
        ]
        let snapData = try JSONSerialization.data(withJSONObject: snapshotApps, options: [])

        // 1. Sideloaded benign utility
        let benignBin = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, symbols: ["_main"]))
        let benignIPA = try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "BenignUtil",
            bundleIdentifier: "com.example.benign",
            executableBinary: benignBin,
            provisioningProfile: .developerSideloaded(teamId: "BENIGN1234", devices: ["DEV1"])
        ))
        try FileManager.default.moveItem(at: benignIPA, to: dir.appendingPathComponent("BenignUtil.ipa"))

        // 2. Trojanized app with homoglyph victim group + exploit XPC + Unicode Bidi & ANSI escape displayName
        let trojanEnts = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.io.m\u{0435}tamask"])
        let trojanBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            xmlEntitlements: trojanEnts,
            extraCStringLiterals: ["com.apple.containermanagerd"]
        ))
        let trojanAppDir = dir.appendingPathComponent("Trojan.app")
        try FileManager.default.createDirectory(at: trojanAppDir, withIntermediateDirectories: true)
        try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "com.trojan.wallet",
                "CFBundleDisplayName": "SafeWallet\u{202E}txt.app\u{001B}[31m",
                "CFBundleExecutable": "Trojan",
                "CFBundleShortVersionString": "1.0"
            ],
            format: .xml,
            options: 0
        ).write(to: trojanAppDir.appendingPathComponent("Info.plist"))
        try trojanBin.write(to: trojanAppDir.appendingPathComponent("Trojan"))

        // 3. Clean WQGuard IPA
        let wqEnts = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>application-identifier</key><string>TEAMWQ0001.com.wqguard.app</string>
            <key>com.apple.developer.team-identifier</key><string>TEAMWQ0001</string>
            <key>com.apple.security.application-groups</key><array><string>group.com.wqguard.app</string></array>
        </dict></plist>
        """
        let wqBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            xmlEntitlements: wqEnts,
            extraCStringLiterals: ["com.apple.containermanagerd"]
        ))
        let wqIPA = try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "WQGuard",
            bundleIdentifier: "com.wqguard.app",
            executableBinary: wqBin,
            provisioningProfile: .developerSideloaded(teamId: "TEAMWQ0001", devices: ["DEV1"])
        ))
        try FileManager.default.moveItem(at: wqIPA, to: dir.appendingPathComponent("WQGuard.ipa"))

        let result = try await SecurityPipeline.shared.scanUnifiedInstalledAppsAsync(
            savedSnapshotData: snapData,
            additionalLocations: [dir],
            includeAppStoreApps: true,
            enableOnDeviceProbe: false
        )
        XCTAssertTrue(result.findings.contains(where: { $0.bundleId == "com.trojan.wallet" && $0.riskTier == .highRisk }))
        XCTAssertTrue(result.findings.contains(where: { $0.bundleId == "com.wqguard.app" && $0.riskTier == .knownTool && $0.isWhitelisted }))
        XCTAssertFalse(result.findings.contains(where: { $0.bundleId == "com.apple.reminders" }))
        XCTAssertTrue(result.findings.contains(where: { $0.bundleId == "com.nssurge.inc.surge-ios" && $0.installChannel == .testFlight && $0.riskTier == .safe }))

        let session = ScanSession(findings: result.findings, systemVersion: "iOS 27.1", scanDuration: 1.25)
        XCTAssertEqual(session.engineVersion, "1.0.0")

        let md = ReportGenerator.shared.generateMarkdownReport(session: session)
        let txt = ReportGenerator.shared.generatePlainTextReport(session: session)
        let jsonData = try ReportGenerator.shared.generateJSONReport(session: session)

        for output in [md, txt] {
            XCTAssertFalse(output.unicodeScalars.contains { $0.value == 0x202E || $0.value == 0x001B }, "Raw Bidi/ANSI escape leaked into report")
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(ScanSession.self, from: jsonData)
        XCTAssertEqual(decoded.engineVersion, "1.0.0")
        XCTAssertEqual(decoded.findings.count, result.findings.count)
    }

    // MARK: - E2E 06: CLI End-to-End Sweep

    func test_e2e_06_cliEndToEndSweep_ipa_firmwareRadar_exportShield_and_outputFormats() async throws {
        let dir = try makeTempDir(prefix: "e2e_cli")

        // 1. --version -> 1.0.0
        let verRes = try await runCLIInProcess(["--version"])
        XCTAssertEqual(verRes.code, 0)
        XCTAssertTrue(verRes.out.contains("1.0.0"))

        // 2. --firmware-radar 27.1 (json, exposed -> exit 1) & 27.2.1 (markdown, exposed -> exit 1)
        let fwJsonURL = dir.appendingPathComponent("fw_27_1.json")
        let fwJsonRes = try await runCLIInProcess(["--firmware-radar", "27.1", "--format", "json", "-o", fwJsonURL.path])
        XCTAssertEqual(fwJsonRes.code, 1)
        let fwReport = try JSONDecoder().decode(FirmwarePostureReport.self, from: try Data(contentsOf: fwJsonURL))
        XCTAssertEqual(fwReport.exposedCount, fwReport.exposedVulnerabilities.count)
        XCTAssertGreaterThan(fwReport.exposedCount, 0)

        let fwMdURL = dir.appendingPathComponent("fw_27_2_1.md")
        let fwMdRes = try await runCLIInProcess(["--firmware-radar", "27.2.1", "--format", "markdown", "-o", fwMdURL.path])
        XCTAssertEqual(fwMdRes.code, 1)
        let fwMdText = try String(contentsOf: fwMdURL, encoding: .utf8)
        XCTAssertTrue(fwMdText.contains("27.2.1"))

        // 3. --export-surge & --export-shield across all 5 platforms
        let surgeOut = dir.appendingPathComponent("surge.sgmodule")
        let surgeRes = try await runCLIInProcess(["--export-surge", surgeOut.path])
        XCTAssertEqual(surgeRes.code, 0)
        XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: try String(contentsOf: surgeOut, encoding: .utf8), for: .surge).isCompliant)

        let shieldExports: [(ProxyShieldPlatform, String)] = [
            (.surge, "shield.sgmodule"),
            (.shadowrocket, "shield.module"),
            (.quantumultX, "shield.conf"),
            (.loon, "shield.plugin"),
            (.stash, "shield.stoverride")
        ]
        for (platform, fileName) in shieldExports {
            let outURL = dir.appendingPathComponent(fileName)
            let res = try await runCLIInProcess(["--export-shield", outURL.path])
            XCTAssertEqual(res.code, 0, "--export-shield failed for \(fileName): \(res.err)")
            let content = try String(contentsOf: outURL, encoding: .utf8)
            XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateShield(content: content, for: platform).isCompliant)
        }

        // 4. --ipa <exploitIPA> without & with --whitelist (isolated from .shared)
        let exploitEnts = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>com.apple.security.application-groups</key><array><string>group.com.e2e.cli.benign</string></array>
        </dict></plist>
        """
        let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["_container_query_create"],
            xmlEntitlements: exploitEnts
        ))
        let ipaURL = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "E2ECLIApp",
            bundleIdentifier: "com.e2e.cli.app",
            executableBinary: bin,
            provisioningProfile: .developerSideloaded(teamId: "E2ETEAM123", devices: ["DEV1"])
        )))

        let ipaOutURL = dir.appendingPathComponent("ipa_scan.json")
        let failRes = try await runCLIInProcess(["--ipa", ipaURL.path, "--format", "json", "-o", ipaOutURL.path])
        XCTAssertEqual(failRes.code, 1)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decodedSession = try decoder.decode(ScanSession.self, from: try Data(contentsOf: ipaOutURL))
        XCTAssertEqual(decodedSession.findings.first?.riskTier, .highRisk)

        let wlRes = try await runCLIInProcess(["--ipa", ipaURL.path, "--whitelist", "com.e2e.cli.app", "--format", "text"])
        XCTAssertEqual(wlRes.code, 0)
        XCTAssertNil(WhitelistEngine.shared.tool(named: "CLI-Whitelist-com.e2e.cli.app"))
    }

    // MARK: - E2E 07: On-Disk Shields & brotli-guard.js Live JavaScriptCore Sweep

    func test_e2e_07_onDiskShieldsAndBrotliGuardJS_liveJavaScriptCoreSweep() throws {
        let physicalMap: [(ProxyShieldPlatform, String)] = [
            (.surge, "Shields/Surge/WQGuard-Brotli-Shield.sgmodule"),
            (.shadowrocket, "Shields/Shadowrocket/WQGuard-Brotli-Shield.module"),
            (.quantumultX, "Shields/QuantumultX/WQGuard-Brotli-Shield.conf"),
            (.loon, "Shields/Loon/WQGuard-Brotli-Shield.plugin"),
            (.stash, "Shields/Stash/WQGuard-Brotli-Shield.stoverride")
        ]
        for (platform, relPath) in physicalMap {
            let content = try String(contentsOf: repoRoot.appendingPathComponent(relPath), encoding: .utf8)
            XCTAssertTrue(content.contains("#!version=1.3.6"), "\(relPath) missing #!version=1.3.6")
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: content, for: platform)
            XCTAssertTrue(res.isCompliant, "\(relPath) failed validation: \(res.errors)")
            XCTAssertTrue(res.missingExclusions.isEmpty)
        }
        let surgeRoot = try String(contentsOf: repoRoot.appendingPathComponent("Surge/WQGuard-Brotli-Shield.sgmodule"), encoding: .utf8)
        let surgeShield = try String(contentsOf: repoRoot.appendingPathComponent("Shields/Surge/WQGuard-Brotli-Shield.sgmodule"), encoding: .utf8)
        XCTAssertEqual(surgeRoot, surgeShield)
        XCTAssertEqual(SurgeBrotliShieldHelper.mandatoryNegativeExclusions.count, 16)
        XCTAssertEqual(SurgeBrotliShieldHelper.defaultHighRiskTLDs.count, 21)

        let js = try String(contentsOf: repoRoot.appendingPathComponent("Shields/scripts/brotli-guard.js"), encoding: .utf8)
        func runJS(setup: String) throws -> [String: Any] {
            let ctx = try XCTUnwrap(JSContext())
            var captured: [String: Any] = [:]
            let doneBlock: @convention(block) (JSValue) -> Void = { val in
                captured = (val.toDictionary() as? [String: Any]) ?? [:]
            }
            ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)
            _ = ctx.evaluateScript(setup)
            _ = ctx.evaluateScript(js)
            XCTAssertNil(ctx.exception, "JS exception: \(String(describing: ctx.exception))")
            return captured
        }

        XCTAssertEqual(try runJS(setup: "var $response = { status: 200, headers: { 'Content-Encoding': 'br' } };")["status"] as? Int, 403)
        XCTAssertEqual(try runJS(setup: "var $response = { status: 200, headers: { 'content-encoding': 'Br' } };")["status"] as? Int, 403)
        XCTAssertEqual(try runJS(setup: "var $response = { status: 200, headers: { 'Content-Encoding': 'gzip, br' } };")["status"] as? Int, 403)
        XCTAssertNil(try runJS(setup: "var $response = { status: 200, headers: { 'Content-Encoding': 'gzip' } };")["status"])
        XCTAssertNil(try runJS(setup: "var h = Object.create(null); h['Content-Encoding'] = Object.create(null); var $response = { status: 200, headers: h };")["status"])
        XCTAssertNil(try runJS(setup: "")["status"])
    }

    // MARK: - E2E 08: Built build/WQGuard_v1.3.6.ipa Package & Manifest Audit

    func test_e2e_08_builtV135IPAPackageAndManifestAudit() throws {
        let ipaURL = repoRoot.appendingPathComponent("build/WQGuard_v1.3.6.ipa")
        guard FileManager.default.fileExists(atPath: ipaURL.path) else {
            throw XCTSkip("build/WQGuard_v1.3.6.ipa not present at \(ipaURL.path)")
        }

        let beforeSnap = try ReadOnlyAssertions.captureSnapshot(of: [ipaURL])

        let ipaData = try Data(contentsOf: ipaURL, options: .mappedIfSafe)
        let reader = NativeZIPArchiveReader(data: ipaData)
        let entries = try reader.readCentralDirectory()

        XCTAssertFalse(entries.contains(where: { $0.path.hasSuffix("/embedded.mobileprovision") || $0.path == "Payload/WQGuard.app/embedded.mobileprovision" }))

        let plistEntry = try XCTUnwrap(entries.first { $0.path == "Payload/WQGuard.app/Info.plist" })
        let plistData = try reader.extract(entry: plistEntry)
        let plist = try XCTUnwrap(try PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String: Any])
        XCTAssertEqual(plist["CFBundleShortVersionString"] as? String, "1.3.6")
        XCTAssertEqual(plist["CFBundleVersion"] as? String, "27")
        XCTAssertEqual(plist["CFBundleIdentifier"] as? String, "com.wqguard.app")

        let execEntry = try XCTUnwrap(entries.first { $0.path == "Payload/WQGuard.app/WQGuard" })
        let execData = try reader.extract(entry: execEntry)
        let slices = try MachOParser.shared.parseAllSlices(data: execData)
        XCTAssertTrue(slices.contains { $0.architecture == .arm64 || $0.architecture == .arm64e })
        for needle in ["com.apple.audio.audiomxd", "com.apple.bookassetd", "com.apple.MobileGestalt.plist"] {
            XCTAssertNil(execData.range(of: Data(needle.utf8)))
        }

        let finding = try SecurityPipeline.shared.scanIPA(at: ipaURL)
        XCTAssertEqual(finding.bundleId, "com.wqguard.app")
        XCTAssertEqual(finding.version, "1.3.6")
        XCTAssertEqual(finding.riskTier, .knownTool)
        XCTAssertTrue(finding.isWhitelisted)
        XCTAssertEqual(finding.whitelistedToolName, "WQGuard")
        XCTAssertTrue(finding.evidence.isWhitelistEligible)
        let forbiddenPrefixes = [
            "arm64:svc_0x80",
            "CVE-2026-65339",
            "BookRestore",
            "MobileGestaltTamper",
            "CVE-2026-84493",
            "CODE_SIGNATURE_SEAL_MISMATCH",
            "MalformedPackage"
        ]
        XCTAssertFalse(
            finding.indicators.contains { ind in
                forbiddenPrefixes.contains { ind.signature.hasPrefix($0) }
            },
            "Built WQGuard_v1.3.6.ipa unexpectedly triggered forbidden indicator: \(finding.indicators.map(\.signature))"
        )

        let afterSnap = try ReadOnlyAssertions.captureSnapshot(of: [ipaURL])
        ReadOnlyAssertions.assertUnmodified(before: beforeSnap, after: afterSnap)
    }

    // MARK: - E2E 09: Bilingual Localization Parity (en & zh-Hans)

    func test_e2e_09_bilingualLocalizationParity_enAndZhHans() throws {
        let testOS = try XCTUnwrap(SystemOSVersion(string: "27.1"))

        WQLocale.overrideLanguageCode = "en"
        let enFW = FirmwarePostureEngine.shared.evaluate(osVersion: testOS)
        let enProbeCatalog = OnDeviceAppProbeScanner.defaultCatalog
        let enSession = ScanSession(findings: [], systemVersion: "iOS 27.1")
        let enMD = ReportGenerator.shared.generateMarkdownReport(session: enSession)

        WQLocale.overrideLanguageCode = "zh-Hans"
        let zhFW = FirmwarePostureEngine.shared.evaluate(osVersion: testOS)
        let zhProbeCatalog = OnDeviceAppProbeScanner.defaultCatalog
        let zhSession = ScanSession(findings: [], systemVersion: "iOS 27.1")
        let zhMD = ReportGenerator.shared.generateMarkdownReport(session: zhSession)

        XCTAssertFalse(enMD.isEmpty)
        XCTAssertFalse(zhMD.isEmpty)
        XCTAssertNotEqual(enMD, zhMD)
        XCTAssertEqual(enFW.exposedCount, zhFW.exposedCount)
        XCTAssertFalse(enProbeCatalog.isEmpty)
        XCTAssertEqual(enProbeCatalog.count, zhProbeCatalog.count)
        XCTAssertNotEqual(enFW.actionableMitigations.first?.title, zhFW.actionableMitigations.first?.title)
    }

    // MARK: - E2E 10: R3 Repository Hygiene, Version Sync & Preserved Constants

    func test_e2e_10_r3RepositoryHygiene_versionSync_and_preservedConstants() throws {
        let infoData = try Data(contentsOf: repoRoot.appendingPathComponent("WQGuard/Resources/Info.plist"))
        let info = try XCTUnwrap(try PropertyListSerialization.propertyList(from: infoData, options: [], format: nil) as? [String: Any])
        XCTAssertEqual(info["CFBundleShortVersionString"] as? String, "1.3.6")
        XCTAssertEqual(info["CFBundleVersion"] as? String, "27")

        let pbx = try String(contentsOf: repoRoot.appendingPathComponent("WQGuard.xcodeproj/project.pbxproj"), encoding: .utf8)
        XCTAssertTrue(pbx.contains("MARKETING_VERSION = 1.3.6;"))
        XCTAssertTrue(pbx.contains("CURRENT_PROJECT_VERSION = 27;"))
        XCTAssertFalse(pbx.contains("MARKETING_VERSION = 1.3.5;"))

        let settings = try String(contentsOf: repoRoot.appendingPathComponent("WQGuard/App/Views/Settings/SettingsView.swift"), encoding: .utf8)
        XCTAssertTrue(settings.contains("1.3.6"))
        XCTAssertTrue(settings.contains("\"27\""))

        XCTAssertEqual(WQGuardCLIMetadata.version, "1.0.0")
        XCTAssertEqual(ScanSession(findings: []).engineVersion, "1.0.0")
        XCTAssertEqual(WhitelistEngine.defaultTools.map(\.name), ["WQGuard"])

        let usage = try String(contentsOf: repoRoot.appendingPathComponent("USAGE_GUIDE.md"), encoding: .utf8)
        XCTAssertTrue(usage.contains("1.2.1"))

        let docPaths = [
            "README.md",
            "SECURITY.md",
            "USAGE_GUIDE.md",
            "WQGuard/App/Localization/en.lproj/Localizable.strings",
            "WQGuard/App/Localization/zh-Hans.lproj/Localizable.strings"
        ]
        let roundRegex = try NSRegularExpression(pattern: "\\b\\d+\\s*rounds?\\b|红蓝|第.*轮", options: [.caseInsensitive])
        for rel in docPaths {
            let text = try String(contentsOf: repoRoot.appendingPathComponent(rel), encoding: .utf8)
            let range = NSRange(text.startIndex..<text.endIndex, in: text)
            XCTAssertNil(roundRegex.firstMatch(in: text, options: [], range: range), "Adversarial round-count mention found in \(rel)")
        }
    }

    // MARK: - Fix 1 Regression: WhitelistEngine Custom Rule Rejection on Protected Victim/Apple App Groups

    func test_fix1_whitelistEngine_customRulesRejectProtectedVictimAndAppleGroups_acrossDirectPipelineAndCLI() async throws {
        let protectedGroups = [
            "group.io.metamask",
            "group.com.tencent.xin",
            "group.org.telegram.messenger",
            "group.i\u{043E}.metamask",
            "group.io.meta\u{200B}mask",
            "group.com.apple.reminders",
            "group.tvappservices.container"
        ]

        // Custom rules with empty allowedAppGroups AND explicit victim/Apple group patterns must both be rejected
        let emptyGroupEngine = WhitelistEngine()
        emptyGroupEngine.registerCustomTool(WhitelistedTool(
            name: "CustomEmptyGroups",
            allowedBundleIds: ["com.custom.victimapp"],
            allowedAppGroups: [],
            expectedSignatures: [],
            isEnabled: true,
            isBuiltIn: false
        ))
        let explicitVictimEngine = WhitelistEngine()
        explicitVictimEngine.registerCustomTool(WhitelistedTool(
            name: "CustomExplicitVictim",
            allowedBundleIds: ["com.custom.victimapp"],
            allowedAppGroups: protectedGroups,
            expectedSignatures: [],
            isEnabled: true,
            isBuiltIn: false
        ))

        for grp in protectedGroups {
            XCTAssertFalse(
                emptyGroupEngine.isWhitelisted(
                    bundleId: "com.custom.victimapp",
                    appGroups: [grp],
                    matchedSignatures: ["com.apple.security.application-groups"]
                ).isWhitelisted,
                "Empty allowedAppGroups custom rule must reject protected group '\(grp.debugDescription)'"
            )
            XCTAssertFalse(
                explicitVictimEngine.isWhitelisted(
                    bundleId: "com.custom.victimapp",
                    appGroups: [grp],
                    matchedSignatures: ["com.apple.security.application-groups"]
                ).isWhitelisted,
                "Explicit protected group custom rule must reject '\(grp.debugDescription)'"
            )

            // Registry & SecurityPipeline parity with injected custom WhitelistEngine
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.custom.victimapp",
                "ApplicationType": "User",
                "SignerIdentity": "iPhone Developer: Custom",
                "ProfileValidated": true,
                "Path": "/private/var/containers/Bundle/Application/UUID-CUST/Cust.app",
                "Entitlements": ["com.apple.security.application-groups": [grp]]
            ]))
            let regFinding = InstalledAppRegistryScanner(whitelistEngine: emptyGroupEngine).evaluateRecord(rec)
            XCTAssertFalse(regFinding.isWhitelisted)
            XCTAssertNotEqual(regFinding.riskTier, .knownTool)
            XCTAssertTrue(regFinding.riskTier == .highRisk || regFinding.riskTier == .caution)
        }

        // CLI --whitelist against a .caution IPA carrying a protected victim group must NOT whitelist
        let victimEnts = SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.io.metamask"])
        let victimBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_dlopen", "_dlsym"],
            xmlEntitlements: victimEnts
        ))
        let victimIPA = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "VictimGroupApp",
            bundleIdentifier: "com.custom.victimapp",
            executableBinary: victimBin,
            provisioningProfile: .developerSideloaded(teamId: "VICTIM1234", devices: ["DEV1"])
        )))
        let cliRes = try await runCLIInProcess(["--ipa", victimIPA.path, "--whitelist", "com.custom.victimapp", "--format", "json"])
        XCTAssertEqual(cliRes.code, 0)
        let cliDecoder = JSONDecoder()
        cliDecoder.dateDecodingStrategy = .iso8601
        let cliSession = try cliDecoder.decode(ScanSession.self, from: Data(cliRes.out.utf8))
        let cliFinding = try XCTUnwrap(cliSession.findings.first)
        XCTAssertFalse(cliFinding.isWhitelisted, "CLI --whitelist must NOT downgrade protected victim App Group IPA")
        XCTAssertEqual(cliFinding.riskTier, .caution)

        // Positive preservation: benign non-protected group still matches custom rule
        let safeEngine = WhitelistEngine()
        safeEngine.registerCustomTool(WhitelistedTool(
            name: "BenignSuite",
            allowedBundleIds: ["com.team.suite"],
            allowedAppGroups: ["group.team.suite"],
            expectedSignatures: [],
            isEnabled: true,
            isBuiltIn: false
        ))
        XCTAssertTrue(
            safeEngine.isWhitelisted(
                bundleId: "com.team.suite",
                appGroups: ["group.team.suite"],
                matchedSignatures: ["com.apple.security.application-groups"]
            ).isWhitelisted
        )
    }

    // MARK: - Fix 2 Regression: IPAPackageScanner Special Slot -1/-3 Seal Tampering & Pipeline Injection

    func test_fix2_ipaPackageScanner_slot1AndSlot3SealTampering_andPipelineWhitelistInjection() throws {
        let dir = try makeTempDir(prefix: "fix2_ipa_seal")
        let wqEnts = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>application-identifier</key><string>TEAMWQ0001.com.wqguard.app</string>
            <key>com.apple.developer.team-identifier</key><string>TEAMWQ0001</string>
            <key>com.apple.security.application-groups</key><array><string>group.com.wqguard.app</string></array>
        </dict></plist>
        """

        // 1. Clean WQGuard.ipa baseline
        let cleanPlist = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "com.wqguard.app",
                "CFBundleExecutable": "WQGuard",
                "CFBundleShortVersionString": "1.0"
            ],
            format: .xml,
            options: 0
        )
        let expectedCR = Data("<plist><dict><key>files2</key><dict/></dict></plist>".utf8)
        let tamperedCR = Data("<plist><dict><key>tampered</key><true/></dict></plist>".utf8)
        let tamperedPlist = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "com.wqguard.app",
                "CFBundleExecutable": "WQGuard",
                "CFBundleShortVersionString": "9.9"
            ],
            format: .xml,
            options: 0
        )

        let cleanMainBin = buildMinimalMachOWithSeals(
            cstringPayload: Data("com.apple.containermanagerd\0".utf8),
            infoPlistData: cleanPlist,
            codeDirectoryIdentifier: "com.wqguard.app",
            xmlEntitlements: wqEnts,
            codeResourcesData: expectedCR
        )
        let cleanParent = dir.appendingPathComponent("CleanPack")
        let cleanApp = cleanParent.appendingPathComponent("Payload/WQGuard.app")
        try FileManager.default.createDirectory(at: cleanApp.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try cleanPlist.write(to: cleanApp.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: cleanApp.appendingPathComponent("_CodeSignature/CodeResources"))
        try cleanMainBin.write(to: cleanApp.appendingPathComponent("WQGuard"))
        let cleanIPA = dir.appendingPathComponent("CleanWQGuard.ipa")
        try zipDirectory(cleanParent, to: cleanIPA)

        let cleanFinding = try IPAPackageScanner.shared.scan(ipaURL: cleanIPA)
        XCTAssertEqual(cleanFinding.riskTier, .knownTool)
        XCTAssertTrue(cleanFinding.isWhitelisted)

        // 2. SecurityPipeline(whitelistEngine:) injection (disabled WQGuard + added custom rule)
        let disabledWL = WhitelistEngine()
        disabledWL.toggleTool(named: "WQGuard", isEnabled: false)
        let disabledPipeline = SecurityPipeline(whitelistEngine: disabledWL)
        let disabledFinding = try disabledPipeline.scanIPA(at: cleanIPA)
        XCTAssertFalse(disabledFinding.isWhitelisted, "SecurityPipeline(whitelistEngine:) must propagate disabled WQGuard rule to scanIPA")
        XCTAssertEqual(disabledFinding.riskTier, .highRisk)

        let customBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["_container_query_create"],
            xmlEntitlements: """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>
                <key>com.apple.security.application-groups</key><array><string>group.com.fix2.custom</string></array>
            </dict></plist>
            """
        ))
        let customIPA = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "CustomInjected",
            bundleIdentifier: "com.fix2.custom",
            executableBinary: customBin,
            provisioningProfile: .developerSideloaded(teamId: "FIX2TEAM99", devices: ["DEV1"])
        )))
        let customWL = WhitelistEngine()
        customWL.registerCustomTool(WhitelistedTool(
            name: "Fix2InjectedTool",
            allowedBundleIds: ["com.fix2.custom"],
            allowedAppGroups: ["group.com.fix2.custom"],
            expectedSignatures: [],
            isEnabled: true,
            isBuiltIn: false
        ))
        let customFinding = try SecurityPipeline(whitelistEngine: customWL).scanIPA(at: customIPA)
        XCTAssertTrue(customFinding.isWhitelisted)
        XCTAssertEqual(customFinding.whitelistedToolName, "Fix2InjectedTool")
        XCTAssertEqual(customFinding.riskTier, .knownTool)

        // 3. Main bundle Special Slot -1 tampered Info.plist inside IPA (keeping CFBundleIdentifier == com.wqguard.app)
        let slot1Parent = dir.appendingPathComponent("Slot1Pack")
        let slot1App = slot1Parent.appendingPathComponent("Payload/WQGuard.app")
        try FileManager.default.createDirectory(at: slot1App.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try tamperedPlist.write(to: slot1App.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: slot1App.appendingPathComponent("_CodeSignature/CodeResources"))
        try cleanMainBin.write(to: slot1App.appendingPathComponent("WQGuard"))
        let slot1IPA = dir.appendingPathComponent("Slot1Tampered.ipa")
        try zipDirectory(slot1Parent, to: slot1IPA)

        let slot1Finding = try IPAPackageScanner.shared.scan(ipaURL: slot1IPA)
        XCTAssertEqual(slot1Finding.riskTier, .highRisk)
        XCTAssertFalse(slot1Finding.isWhitelisted)
        XCTAssertFalse(slot1Finding.evidence.isWhitelistEligible)
        XCTAssertTrue(slot1Finding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })

        // 4. Main bundle Special Slot -3 tampered CodeResources + trailing non-seal-mismatch sub-binary (must not overwrite seal disposition)
        let slot3Parent = dir.appendingPathComponent("Slot3Pack")
        let slot3App = slot3Parent.appendingPathComponent("Payload/WQGuard.app")
        try FileManager.default.createDirectory(at: slot3App.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: slot3App.appendingPathComponent("Frameworks"), withIntermediateDirectories: true)
        try cleanPlist.write(to: slot3App.appendingPathComponent("Info.plist"))
        try tamperedCR.write(to: slot3App.appendingPathComponent("_CodeSignature/CodeResources"))
        try cleanMainBin.write(to: slot3App.appendingPathComponent("WQGuard"))
        let trailingDylib = SyntheticMachOGenerator.shared.generateThin(config: .init(arch: .arm64, cryptid: 0, symbols: ["_main"]))
        try trailingDylib.write(to: slot3App.appendingPathComponent("Frameworks/ZTrailing.dylib"))
        let slot3IPA = dir.appendingPathComponent("Slot3Tampered.ipa")
        try zipDirectory(slot3Parent, to: slot3IPA)

        let slot3Finding = try IPAPackageScanner.shared.scan(ipaURL: slot3IPA)
        XCTAssertEqual(slot3Finding.riskTier, .highRisk)
        XCTAssertFalse(slot3Finding.isWhitelisted)
        XCTAssertFalse(slot3Finding.evidence.isWhitelistEligible)
        XCTAssertTrue(slot3Finding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })

        // 5. Embedded .appex Special Slot -3 + embedded .framework Special Slot -1 inside IPA
        let appexParent = dir.appendingPathComponent("AppexSealPack")
        let appexApp = appexParent.appendingPathComponent("Payload/WQGuard.app")
        let extDir = appexApp.appendingPathComponent("PlugIns/Ext.appex")
        try FileManager.default.createDirectory(at: appexApp.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: extDir.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try cleanPlist.write(to: appexApp.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: appexApp.appendingPathComponent("_CodeSignature/CodeResources"))
        try cleanMainBin.write(to: appexApp.appendingPathComponent("WQGuard"))
        let extPlist = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.wqguard.app.ext", "CFBundleExecutable": "Ext", "CFBundleShortVersionString": "1.0"],
            format: .xml,
            options: 0
        )
        try extPlist.write(to: extDir.appendingPathComponent("Info.plist"))
        try tamperedCR.write(to: extDir.appendingPathComponent("_CodeSignature/CodeResources"))
        let extBin = buildMinimalMachOWithSeals(
            infoPlistData: extPlist,
            codeDirectoryIdentifier: "com.wqguard.app.ext",
            codeResourcesData: expectedCR
        )
        try extBin.write(to: extDir.appendingPathComponent("Ext"))
        let appexIPA = dir.appendingPathComponent("AppexSealTampered.ipa")
        try zipDirectory(appexParent, to: appexIPA)

        let appexFinding = try IPAPackageScanner.shared.scan(ipaURL: appexIPA)
        XCTAssertEqual(appexFinding.riskTier, .highRisk)
        XCTAssertFalse(appexFinding.isWhitelisted)
        XCTAssertFalse(appexFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(appexFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })

        let fwParent = dir.appendingPathComponent("FrameworkSealPack")
        let fwApp = fwParent.appendingPathComponent("Payload/WQGuard.app")
        let fwDir = fwApp.appendingPathComponent("Frameworks/Helper.framework")
        try FileManager.default.createDirectory(at: fwApp.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: fwDir, withIntermediateDirectories: true)
        try cleanPlist.write(to: fwApp.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: fwApp.appendingPathComponent("_CodeSignature/CodeResources"))
        try cleanMainBin.write(to: fwApp.appendingPathComponent("WQGuard"))
        let sealedFwPlist = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.wqguard.helper", "CFBundleExecutable": "Helper", "CFBundleShortVersionString": "1.0"],
            format: .xml,
            options: 0
        )
        let tamperedFwPlist = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.wqguard.helper", "CFBundleExecutable": "Helper", "CFBundleShortVersionString": "9.9"],
            format: .xml,
            options: 0
        )
        try tamperedFwPlist.write(to: fwDir.appendingPathComponent("Info.plist"))
        let fwBin = buildMinimalMachOWithSeals(
            infoPlistData: sealedFwPlist,
            codeDirectoryIdentifier: "com.wqguard.helper"
        )
        try fwBin.write(to: fwDir.appendingPathComponent("Helper"))
        let fwIPA = dir.appendingPathComponent("FrameworkSealTampered.ipa")
        try zipDirectory(fwParent, to: fwIPA)

        let fwFinding = try IPAPackageScanner.shared.scan(ipaURL: fwIPA)
        XCTAssertEqual(fwFinding.riskTier, .highRisk)
        XCTAssertFalse(fwFinding.isWhitelisted)
        XCTAssertFalse(fwFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(fwFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })

        // 6. Embedded .framework WITHOUT Special Slot -1 + CodeDirectory.identifier mismatch:
        //    must block whitelisting (hasBundleSealTampering) without falsely emitting CODE_SIGNATURE_SEAL_MISMATCH
        let fwNoSlot1Parent = dir.appendingPathComponent("FrameworkNoSlot1Pack")
        let fwNoSlot1App = fwNoSlot1Parent.appendingPathComponent("Payload/WQGuard.app")
        let fwNoSlot1Dir = fwNoSlot1App.appendingPathComponent("Frameworks/Helper.framework")
        try FileManager.default.createDirectory(at: fwNoSlot1App.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: fwNoSlot1Dir, withIntermediateDirectories: true)
        try cleanPlist.write(to: fwNoSlot1App.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: fwNoSlot1App.appendingPathComponent("_CodeSignature/CodeResources"))
        try cleanMainBin.write(to: fwNoSlot1App.appendingPathComponent("WQGuard"))
        try sealedFwPlist.write(to: fwNoSlot1Dir.appendingPathComponent("Info.plist"))
        let fwNoSlot1Bin = buildMinimalMachOWithSeals(
            infoPlistData: nil,
            codeDirectoryIdentifier: "com.wqguard.different.id"
        )
        try fwNoSlot1Bin.write(to: fwNoSlot1Dir.appendingPathComponent("Helper"))
        let fwNoSlot1IPA = dir.appendingPathComponent("FrameworkNoSlot1IdMismatch.ipa")
        try zipDirectory(fwNoSlot1Parent, to: fwNoSlot1IPA)

        let fwNoSlot1Finding = try IPAPackageScanner.shared.scan(ipaURL: fwNoSlot1IPA)
        XCTAssertFalse(fwNoSlot1Finding.isWhitelisted, "Framework identifier mismatch without Slot -1 must block WQGuard self-whitelist")
        XCTAssertFalse(fwNoSlot1Finding.evidence.isWhitelistEligible)
        XCTAssertFalse(
            fwNoSlot1Finding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" },
            "Framework without Special Slot -1 must not falsely emit CODE_SIGNATURE_SEAL_MISMATCH"
        )
        let fwNoSlot1BundleFinding = try SecurityPipeline().scanBundle(at: fwNoSlot1App)
        XCTAssertFalse(fwNoSlot1BundleFinding.isWhitelisted, "scanBundle top-level framework without Slot -1 must block WQGuard self-whitelist")
        XCTAssertFalse(fwNoSlot1BundleFinding.evidence.isWhitelistEligible)
        XCTAssertFalse(
            fwNoSlot1BundleFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" },
            "scanBundle top-level framework without Special Slot -1 must not falsely emit CODE_SIGNATURE_SEAL_MISMATCH"
        )

        // 6b. Main .app WITHOUT Special Slot -1 + CodeDirectory.identifier mismatch + clean .appex:
        //     both scan(ipaURL:) and scanBundle(at:) must block whitelisting without emitting CODE_SIGNATURE_SEAL_MISMATCH,
        //     while Special Slot -1 present DOES emit CODE_SIGNATURE_SEAL_MISMATCH.
        let mainNoSlot1Parent = dir.appendingPathComponent("MainNoSlot1WithAppexPack")
        let mainNoSlot1App = mainNoSlot1Parent.appendingPathComponent("Payload/WQGuard.app")
        let mainNoSlot1Ext = mainNoSlot1App.appendingPathComponent("PlugIns/Ext.appex")
        try FileManager.default.createDirectory(at: mainNoSlot1App.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: mainNoSlot1Ext.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try cleanPlist.write(to: mainNoSlot1App.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: mainNoSlot1App.appendingPathComponent("_CodeSignature/CodeResources"))
        let mainNoSlot1Bin = buildMinimalMachOWithSeals(
            cstringPayload: Data("com.apple.containermanagerd\0".utf8),
            infoPlistData: nil,
            codeDirectoryIdentifier: "com.wqguard.different.main",
            xmlEntitlements: wqEnts,
            codeResourcesData: expectedCR
        )
        try mainNoSlot1Bin.write(to: mainNoSlot1App.appendingPathComponent("WQGuard"))
        try extPlist.write(to: mainNoSlot1Ext.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: mainNoSlot1Ext.appendingPathComponent("_CodeSignature/CodeResources"))
        try extBin.write(to: mainNoSlot1Ext.appendingPathComponent("Ext"))
        let mainNoSlot1IPA = dir.appendingPathComponent("MainNoSlot1WithAppex.ipa")
        try zipDirectory(mainNoSlot1Parent, to: mainNoSlot1IPA)

        for finding in [
            try IPAPackageScanner.shared.scan(ipaURL: mainNoSlot1IPA),
            try SecurityPipeline().scanBundle(at: mainNoSlot1App)
        ] {
            XCTAssertFalse(finding.isWhitelisted)
            XCTAssertFalse(finding.evidence.isWhitelistEligible)
            XCTAssertFalse(
                finding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" },
                "Main .app without Special Slot -1 + clean .appex must not emit CODE_SIGNATURE_SEAL_MISMATCH"
            )
        }

        let mainSlot1App = dir.appendingPathComponent("MainSlot1WithAppex/WQGuard.app")
        try FileManager.default.createDirectory(at: mainSlot1App.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: mainSlot1App.appendingPathComponent("PlugIns/Ext.appex/_CodeSignature"), withIntermediateDirectories: true)
        try tamperedPlist.write(to: mainSlot1App.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: mainSlot1App.appendingPathComponent("_CodeSignature/CodeResources"))
        try cleanMainBin.write(to: mainSlot1App.appendingPathComponent("WQGuard"))
        try extPlist.write(to: mainSlot1App.appendingPathComponent("PlugIns/Ext.appex/Info.plist"))
        try expectedCR.write(to: mainSlot1App.appendingPathComponent("PlugIns/Ext.appex/_CodeSignature/CodeResources"))
        try extBin.write(to: mainSlot1App.appendingPathComponent("PlugIns/Ext.appex/Ext"))
        let mainSlot1Finding = try SecurityPipeline().scanBundle(at: mainSlot1App)
        XCTAssertFalse(mainSlot1Finding.isWhitelisted)
        XCTAssertTrue(mainSlot1Finding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })

        // 6c. .appex-nested .framework WITHOUT Special Slot -1 + CodeDirectory.identifier mismatch (and positive Slot -1 control)
        let nestedFwParent = dir.appendingPathComponent("NestedFwNoSlot1Pack")
        let nestedFwApp = nestedFwParent.appendingPathComponent("Payload/WQGuard.app")
        let nestedFwExt = nestedFwApp.appendingPathComponent("PlugIns/Ext.appex")
        let nestedFwDir = nestedFwExt.appendingPathComponent("Frameworks/Inner.framework")
        try FileManager.default.createDirectory(at: nestedFwApp.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: nestedFwExt.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: nestedFwDir, withIntermediateDirectories: true)
        try cleanPlist.write(to: nestedFwApp.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: nestedFwApp.appendingPathComponent("_CodeSignature/CodeResources"))
        try cleanMainBin.write(to: nestedFwApp.appendingPathComponent("WQGuard"))
        try extPlist.write(to: nestedFwExt.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: nestedFwExt.appendingPathComponent("_CodeSignature/CodeResources"))
        try extBin.write(to: nestedFwExt.appendingPathComponent("Ext"))
        let innerPlist = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.wqguard.inner", "CFBundleExecutable": "Inner", "CFBundleShortVersionString": "1.0"],
            format: .xml,
            options: 0
        )
        let tamperedInnerPlist = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleIdentifier": "com.wqguard.inner", "CFBundleExecutable": "Inner", "CFBundleShortVersionString": "9.9"],
            format: .xml,
            options: 0
        )
        try innerPlist.write(to: nestedFwDir.appendingPathComponent("Info.plist"))
        let innerNoSlot1Bin = buildMinimalMachOWithSeals(
            infoPlistData: nil,
            codeDirectoryIdentifier: "com.wqguard.different.inner"
        )
        try innerNoSlot1Bin.write(to: nestedFwDir.appendingPathComponent("Inner"))
        let nestedFwNoSlot1IPA = dir.appendingPathComponent("NestedFwNoSlot1.ipa")
        try zipDirectory(nestedFwParent, to: nestedFwNoSlot1IPA)

        for finding in [
            try IPAPackageScanner.shared.scan(ipaURL: nestedFwNoSlot1IPA),
            try SecurityPipeline().scanBundle(at: nestedFwApp)
        ] {
            XCTAssertFalse(finding.isWhitelisted)
            XCTAssertFalse(finding.evidence.isWhitelistEligible)
            XCTAssertFalse(
                finding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" },
                ".appex-nested .framework without Special Slot -1 must not emit CODE_SIGNATURE_SEAL_MISMATCH"
            )
        }

        // Positive Slot -1 control on .appex-nested .framework
        let innerWithSlot1Bin = buildMinimalMachOWithSeals(
            infoPlistData: innerPlist,
            codeDirectoryIdentifier: "com.wqguard.inner"
        )
        try tamperedInnerPlist.write(to: nestedFwDir.appendingPathComponent("Info.plist"))
        try innerWithSlot1Bin.write(to: nestedFwDir.appendingPathComponent("Inner"))
        let nestedFwSlot1IPA = dir.appendingPathComponent("NestedFwSlot1.ipa")
        try zipDirectory(nestedFwParent, to: nestedFwSlot1IPA)
        for finding in [
            try IPAPackageScanner.shared.scan(ipaURL: nestedFwSlot1IPA),
            try SecurityPipeline().scanBundle(at: nestedFwApp)
        ] {
            XCTAssertFalse(finding.isWhitelisted)
            XCTAssertTrue(finding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })
        }

        // 7. SecurityPipeline.scanBundle(at:) preserves main/framework seal-mismatch disposition against trailing ad-hoc dylib
        let trailingBundleApp = dir.appendingPathComponent("BundleSealTrailing/WQGuard.app")
        try FileManager.default.createDirectory(at: trailingBundleApp.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: trailingBundleApp.appendingPathComponent("Frameworks/Helper.framework"), withIntermediateDirectories: true)
        try cleanPlist.write(to: trailingBundleApp.appendingPathComponent("Info.plist"))
        try expectedCR.write(to: trailingBundleApp.appendingPathComponent("_CodeSignature/CodeResources"))
        try cleanMainBin.write(to: trailingBundleApp.appendingPathComponent("WQGuard"))
        try tamperedFwPlist.write(to: trailingBundleApp.appendingPathComponent("Frameworks/Helper.framework/Info.plist"))
        try fwBin.write(to: trailingBundleApp.appendingPathComponent("Frameworks/Helper.framework/Helper"))
        try trailingDylib.write(to: trailingBundleApp.appendingPathComponent("Frameworks/ZTrailing.dylib"))

        let bundleSealFinding = try SecurityPipeline().scanBundle(at: trailingBundleApp)
        XCTAssertEqual(bundleSealFinding.riskTier, .highRisk)
        XCTAssertFalse(bundleSealFinding.isWhitelisted)
        XCTAssertTrue(bundleSealFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })
    }

    // MARK: - Fix 3 Regression: parseStashYAML Tab Handling Parity vs YAML.safe_load

    func test_fix3_parseStashYAML_tabHandlingParity_withRubyYAML() throws {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let providersRange = try XCTUnwrap(validStash.range(of: "script-providers:"))
        let prefixBeforeProviders = String(validStash[..<providersRange.lowerBound])

        let invalidTabCases: [(String, String)] = [
            (
                "tab_after_hash_termination",
                validStash + "\n     # trailing comment\n\t\nname: trailing\n"
            ),
            (
                "tab_only_top_level",
                "name: \"Test\"\n\t\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "spaces_plus_tab_before_mitm",
                validStash.replacingOccurrences(of: "  mitm:", with: "  \tmitm:")
            ),
            (
                "spaces_plus_tab_before_dash",
                validStash.replacingOccurrences(of: "    - \"*.xyz\"", with: "    \t- \"*.xyz\"")
            ),
            (
                "spaces_plus_tab_before_script_prop",
                validStash.replacingOccurrences(of: "      type: response", with: "      \ttype: response")
            ),
            (
                "dash_tab_scalar",
                validStash.replacingOccurrences(of: "    - \"*.xyz\"", with: "    -\t\"*.xyz\"")
            ),
            (
                "dash_tab_mapping",
                validStash.replacingOccurrences(of: "    - name: brotli-response-guard", with: "    -\tname: brotli-response-guard")
            ),
            (
                "dash_space_tab_scalar",
                validStash.replacingOccurrences(of: "    - \"*.xyz\"", with: "    - \t\"*.xyz\"")
            ),
            (
                "space_tab_blank_after_quoted_scalar_category",
                validStash.replacingOccurrences(of: "http:", with: " \t\nhttp:")
            ),
            (
                "space_tab_comment_after_quoted_scalar_category",
                validStash.replacingOccurrences(of: "http:", with: "  \t# valid space-tab comment\nhttp:")
            ),
            (
                "space_tab_blank_inside_pending_http_block",
                validStash.replacingOccurrences(of: "  mitm:", with: " \t\n  mitm:")
            ),
            (
                "space_tab_comment_inside_pending_http_block",
                validStash.replacingOccurrences(of: "  mitm:", with: "  \t# comment inside http\n  mitm:")
            ),
            (
                "space_tab_blank_inside_pending_mitm_block",
                validStash.replacingOccurrences(of: "  mitm:\n", with: "  mitm:\n    \t\n")
            ),
            (
                "space_tab_comment_inside_pending_mitm_block",
                validStash.replacingOccurrences(of: "  mitm:\n", with: "  mitm:\n    \t# comment inside mitm\n")
            ),
            (
                "space_tab_blank_after_sequence_item",
                validStash.replacingOccurrences(of: "    - \"*.xyz\"\n", with: "    - \"*.xyz\"\n \t\n")
            ),
            (
                "space_tab_comment_after_sequence_item",
                validStash.replacingOccurrences(of: "    - \"*.xyz\"\n", with: "    - \"*.xyz\"\n  \t# comment after item\n")
            ),
            (
                "space_tab_underindented_after_plain_scalar_timeout5",
                validStash.replacingOccurrences(of: "script-providers:", with: " \t\nscript-providers:")
            ),
            (
                "space_tab_equal_indent_after_plain_scalar_timeout5",
                validStash.replacingOccurrences(of: "script-providers:", with: "      \t\nscript-providers:")
            ),
            (
                "space_tab_comment_equal_indent_after_plain_scalar_timeout5",
                validStash.replacingOccurrences(of: "script-providers:", with: "      \t# equal indent\nscript-providers:")
            ),
            (
                "space_tab_after_comment_terminating_plain_scalar",
                "name: plain_scalar\n  \t# valid space-tab comment\n \t\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "space_tab_after_inline_comment_plain_scalar",
                "name: plain_scalar # inline comment\n \t\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "multiline_dq_after_close_tab",
                "name: \"hello\n  world\"\n   \t\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "multiline_dq_after_close_colon_tab",
                "name: \"hello\n  foo: bar\"\n   \t\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "multiline_dq_after_close_comment_tab",
                "name: \"hello\n  world\"\n   \t# after close\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "multiline_sq_after_close_tab",
                "name: 'hello\n  world'\n   \t\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "single_quote_backslash_comment_tab",
                "name: 'foo\\'\n \t\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "flow_seq_after_close_tab",
                "extra: [\n  1,\n  2\n]\n \t\n" + validStash
            ),
            (
                "nospace_colon_top_key",
                "name:\"Test\"\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "nospace_colon_plain_top_key",
                "name:Test\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "nospace_colon_script_prop",
                validStash.replacingOccurrences(of: "      type: response", with: "      type:response")
            ),
            (
                "desc_literal_block_underindent_tab",
                validStash.replacingOccurrences(of: "desc: \"", with: "desc: |\n  line1\n \t\n  line2\nunused: \"")
            ),
            (
                "desc_literal_block_explicit2_underindent_tab",
                validStash.replacingOccurrences(of: "desc: \"", with: "desc: |2\n  line1\n \t\n  line2\nunused: \"")
            )
        ]

        for (label, yaml) in invalidTabCases {
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertFalse(res.isCompliant, "YAML.safe_load-invalid Stash YAML must be rejected [\(label)]")
        }

        let validTabCases: [(String, String)] = [
            (
                "tab_inside_block_scalar_at_6_spaces",
                prefixBeforeProviders
                    + "script-providers:\n"
                    + "  brotli-response-guard:\n"
                    + "    payload: |\n"
                    + "      const ok = 1;\n"
                    + "      \t\n"
                    + "      $done({ status: 403, headers: {} });\n"
            ),
            (
                "space_then_tab_blank_and_comment_lines",
                "name: plain_scalar\n \t\n  \t# valid space-tab comment\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "space_then_tab_more_indented_than_plain_scalar_timeout5",
                validStash.replacingOccurrences(of: "script-providers:", with: "       \t\nscript-providers:")
            ),
            (
                "space_then_tab_comment_more_indented_than_plain_scalar_timeout5",
                validStash.replacingOccurrences(of: "script-providers:", with: "       \t# valid indent 7 > 6\nscript-providers:")
            ),
            (
                "multiline_dq_inside_tab_blank",
                "name: \"hello\n \t\n  world\"\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "multiline_dq_inside_tab_comment",
                "name: \"hello\n \t# inside string\n  world\"\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "multiline_sq_inside_tab_blank",
                "name: 'hello\n \t\n  world'\n" + String(validStash[validStash.range(of: "desc:")!.lowerBound...])
            ),
            (
                "desc_literal_block_tab_same_indent",
                validStash.replacingOccurrences(of: "desc: \"", with: "desc: |\n  line1\n  \t\n  line2\nunused: \"")
            ),
            (
                "desc_folded_block_tab_same_indent",
                validStash.replacingOccurrences(of: "desc: \"", with: "desc: >\n  line1\n  \t\n  line2\nunused: \"")
            ),
            (
                "flow_seq_multiline_tab",
                "extra: [\n  1,\n \t# underindent comment\n  \t\n  2\n]\n" + validStash
            ),
            (
                "flow_map_multiline_tab",
                "extra: {\n  a: 1,\n \t# comment\n  b: 2\n}\n" + validStash
            )
        ]

        for (label, yaml) in validTabCases {
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertTrue(res.isCompliant, "YAML.safe_load-valid Stash YAML must pass [\(label)]: \(res.errors)")
            XCTAssertTrue(res.hasScriptGuard, "hasScriptGuard must be true [\(label)]")
        }
    }

    // MARK: - Fix 4 Regression: Gate 3 LibYAML Quote/Flow/Block/Script & Reviewer 2 Edges

    func test_fix4_parseStashYAML_gate3LibYAMLQuoteFlowBlockAndScriptParity() throws {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)
        let descRange = try XCTUnwrap(validStash.range(of: "desc:"))
        let tailFromDesc = String(validStash[descRange.lowerBound...])
        let providersRange = try XCTUnwrap(validStash.range(of: "script-providers:"))
        let prefixBeforeProviders = String(validStash[..<providersRange.lowerBound])
        let validScriptBlock = """
          script:
            - name: brotli-response-guard
              match: ^https?://.+
              type: response
              require-body: false
              timeout: 5
        """

        let invalidLibYAMLCases: [(String, String)] = [
            // Single-line quote trailing garbage (Challenger 2 #36, #57, #58; Reviewer 1; Reviewer 2)
            ("squote_backslash_trailing_bar", "extra: 'foo\\' bar\n" + validStash),
            ("singleline_dq_trailing_extra", "extra: \"hello\" extra\n" + validStash),
            ("singleline_sq_trailing_extra", "extra: 'hello' extra\n" + validStash),
            ("name_dq_trailing_extra", "name: \"Test\" extra\n" + tailFromDesc),
            ("name_sq_trailing_extra", "name: 'Test' extra\n" + tailFromDesc),
            (
                "mitm_dq_trailing_extra",
                validStash.replacingOccurrences(of: "    - \"*.xyz\"", with: "    - \"*.xyz\" extra")
            ),

            // Flow collections: missing commas, leading/double commas, trailing garbage (Challenger 2 #45-47; Reviewer 1; Reviewer 2)
            ("flow_seq_missing_comma_two_quotes", "extra: [\"a\" \"b\"]\n" + validStash),
            ("flow_seq_missing_comma_quote_number", "extra: [\"a\" 123]\n" + validStash),
            ("flow_seq_multiline_quote_no_comma", "extra: [\n  \"hello\n  world\" 123\n]\n" + validStash),
            ("flow_map_missing_comma", "extra: {a: 1 b: 2}\n" + validStash),
            ("flow_map_quotes_missing_colon", "extra: { \"a\" \"b\" }\n" + validStash),
            ("flow_seq_leading_comma", "extra: [, 1]\n" + validStash),
            ("flow_seq_double_comma", "extra: [1, , 2]\n" + validStash),
            ("flow_seq_trailing_garbage", "extra: [1, 2] extra\n" + validStash),
            ("flow_map_trailing_garbage", "extra: {a: 1} extra\n" + validStash),

            // Block scalar terminated by < contentIndent comment followed by indented line (Challenger 2 #63)
            ("block_2_comment_indent1_then_indent2", "extra: |2\n # comment\n  hello\n" + validStash),
            ("name_block_2_comment_indent1_then_indent2", "name: |2\n # comment\n  hello\n" + tailFromDesc),

            // Indented lines after non-http top-level scalars (Challenger 2 #71-74)
            ("indented_mapping_after_top_dq", "extra: \"Test\"\n  nested: 1\n" + validStash),
            ("indented_scalar_after_top_dq", "extra: \"Test\"\n  continuation\n" + validStash),
            ("indented_list_after_top_dq", "extra: \"Test\"\n  - item\n" + validStash),
            ("indented_mapping_after_top_plain", "extra: Test\n  nested: 1\n" + validStash),
            ("name_indented_mapping_after_top_dq", "name: \"Test\"\n  nested: 1\n" + tailFromDesc)
        ]

        for (label, yaml) in invalidLibYAMLCases {
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertFalse(res.isCompliant, "LibYAML-invalid Stash YAML must be rejected [\(label)]")
        }

        let validLibYAMLCases: [(String, String)] = [
            // Valid single-line quote/flow controls (Reviewer 1 & LibYAML controls)
            ("valid_name_dq_inline_comment", "name: \"hello\" # comment\n" + tailFromDesc),
            ("valid_name_dq_adjacent_hash", "name: \"hello\"#comment\n" + tailFromDesc),
            ("valid_quoted_key_space_before_colon", "\"name\" : \"Test\"\n" + tailFromDesc),
            ("valid_flow_seq_inline_comment", "extra: [1, 2] # comment\n" + validStash),
            ("valid_flow_seq_trailing_comma", "extra: [1, 2, ]\n" + validStash),
            ("valid_flow_map_trailing_comma", "extra: {a: 1, }\n" + validStash),
            ("valid_flow_key_mapping", "[1, 2]: 3\n" + validStash),
            ("valid_plain_scalar_multiline_dash", "extra: Test\n  - item\n" + validStash),

            // Valid nested http.script structures (Challenger 2 #64, #81, #82)
            (
                "valid_block_literal_in_http_script_list_item",
                validStash.replacingOccurrences(
                    of: validScriptBlock,
                    with: validScriptBlock + "\n      extra:\n        - |\n          line1\n          \tline2"
                )
            ),
            (
                "valid_plain_scalar_with_colon_under_script_pending_key",
                validStash.replacingOccurrences(
                    of: validScriptBlock,
                    with: validScriptBlock + "\n      extra:\n        foo:bar"
                )
            ),
            (
                "valid_nested_seq_of_maps_under_http_script",
                validStash.replacingOccurrences(
                    of: validScriptBlock,
                    with: validScriptBlock + "\n      extra:\n        - k1: v1\n          k2: v2"
                )
            )
        ]

        for (label, yaml) in validLibYAMLCases {
            XCTAssertNotEqual(yaml, prefixBeforeProviders, "Fixture replacement failed [\(label)]")
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertTrue(res.isCompliant, "LibYAML-valid Stash YAML must pass [\(label)]: \(res.errors)")
            XCTAssertTrue(res.hasScriptGuard, "hasScriptGuard must be true [\(label)]")
        }
    }

    // MARK: - Fix 5 Regression: Symlink/Collision/CorruptMachO/Container/Impersonation Custom Whitelist Rejection

    func test_fix5_symlinkAndCollision_customWhitelistAndCLIBypassBlocked() async throws {
        let dir = try makeTempDir(prefix: "fix5_sym_wl")
        let bundleId = "com.evil.symlink"
        let cleanPlist = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": bundleId,
                "CFBundleExecutable": "SymApp",
                "CFBundleDisplayName": "SymApp",
                "CFBundleShortVersionString": "1.0"
            ],
            format: .xml,
            options: 0
        )
        let extPlist = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "\(bundleId).ext",
                "CFBundleExecutable": "Ext",
                "CFBundleShortVersionString": "1.0"
            ],
            format: .xml,
            options: 0
        )
        let cleanBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_main"]
        ))
        let symlinkAttrs = UInt32(0o120777) << 16
        let execAttrs = UInt32(0o100755) << 16

        let customWL = WhitelistEngine()
        customWL.registerCustomTool(WhitelistedTool(
            name: "CustomNoSigRule",
            allowedBundleIds: [bundleId, "io.metamask.fake"],
            allowedAppGroups: [],
            expectedSignatures: [],
            isEnabled: true,
            isBuiltIn: false
        ))
        let explicitSigWL = WhitelistEngine()
        explicitSigWL.registerCustomTool(WhitelistedTool(
            name: "CustomExplicitSigRule",
            allowedBundleIds: [bundleId],
            allowedAppGroups: [],
            expectedSignatures: [
                "BUNDLE_ESCAPING_SYMLINK",
                "ArchiveSymlinkCollision",
                "ArchiveSymlinkQuotaExceeded",
                "AppexExecutableTraversal",
                "CorruptMachO:UnparseableBinary",
                "CorruptMachO:UnparseableSlice",
                "CONTAINER_ROOT_SYMLINK",
                "CONTAINER_CACHES_SCAN_TRUNCATED",
                "SYSTEMGROUP_SUPERVISION_DETECTED",
                "CloudConfigurationDetails.IsSupervised=true",
                "CloudConfigurationDetails.SymlinkHazard"
            ],
            isEnabled: true,
            isBuiltIn: false
        ))

        // 1. Direct WhitelistEngine check across structural, container, supervision & impersonation signatures
        let nonWhitelistableSigs = [
            "BUNDLE_ESCAPING_SYMLINK",
            "ArchiveSymlinkCollision",
            "ArchiveSymlinkQuotaExceeded",
            "AppexExecutableTraversal",
            "CorruptMachO:UnparseableBinary",
            "CorruptMachO:UnparseableSlice",
            "CONTAINER_ROOT_SYMLINK",
            "CONTAINER_LIBRARY_SYMLINK",
            "CONTAINER_CACHES_SYMLINK",
            "CONTAINER_ESCAPING_SYMLINK",
            "CONTAINER_CACHES_SCAN_TRUNCATED",
            "CONTAINER_CACHES_UNREADABLE_SUBDIR",
            "CONTAINER_SUPERVISION_SYMLINK",
            "SYSTEMGROUP_SUPERVISION_DETECTED",
            "CloudConfigurationDetails.IsSupervised=true",
            "CloudConfigurationDetails.SymlinkHazard"
        ]
        for sig in nonWhitelistableSigs {
            XCTAssertFalse(
                customWL.isWhitelisted(bundleId: bundleId, appGroups: [], matchedSignatures: [sig]).isWhitelisted,
                "Custom empty-sig rule must reject \(sig)"
            )
            XCTAssertFalse(
                explicitSigWL.isWhitelisted(bundleId: bundleId, appGroups: [], matchedSignatures: [sig]).isWhitelisted,
                "Custom explicit-sig rule must reject \(sig)"
            )
            let synthFinding = ScanFinding(
                bundleId: bundleId,
                displayName: "SymApp",
                version: "1.0",
                bundlePath: "/tmp/SymApp.app",
                installChannel: .developerSideloaded,
                riskTier: .caution,
                indicators: [ThreatIndicator(signature: sig, description: sig, category: "Structural Hazard", location: "Bundle", severity: .caution)],
                evidence: AuditEvidence(matchedSymbols: [sig], auditDepth: .fullBinaryAndRegistry, isWhitelistEligible: true)
            )
            XCTAssertFalse(
                customWL.evaluateFindingWhitelist(synthFinding).isWhitelisted,
                "evaluateFindingWhitelist must reject \(sig)"
            )
        }

        // 2. IPA with BUNDLE_ESCAPING_SYMLINK
        let escapingIPA = dir.appendingPathComponent("escaping_symlink.ipa")
        try buildStoredRawZIP([
            RawZIPItem(name: "Payload/SymApp.app/Info.plist", data: cleanPlist),
            RawZIPItem(name: "Payload/SymApp.app/SymApp", data: cleanBin, externalAttrs: execAttrs),
            RawZIPItem(name: "Payload/SymApp.app/CachesEscape", data: Data("../../../../var/mobile/Containers/Data/Application/VICTIM".utf8), externalAttrs: symlinkAttrs)
        ]).write(to: escapingIPA)

        // 3. IPA with ArchiveSymlinkCollision (regular file PlugIns colliding with PlugIns/Ext.appex symlink)
        let collisionIPA = dir.appendingPathComponent("symlink_collision.ipa")
        try buildStoredRawZIP([
            RawZIPItem(name: "Payload/SymApp.app/Info.plist", data: cleanPlist),
            RawZIPItem(name: "Payload/SymApp.app/SymApp", data: cleanBin, externalAttrs: execAttrs),
            RawZIPItem(name: "Payload/SymApp.app/AltStore/RealExt/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/SymApp.app/AltStore/RealExt/Ext", data: cleanBin, externalAttrs: execAttrs),
            RawZIPItem(name: "Payload/SymApp.app/PlugIns", data: Data("decoy-parent".utf8)),
            RawZIPItem(name: "Payload/SymApp.app/PlugIns/Ext.appex", data: Data("../AltStore/RealExt".utf8), externalAttrs: symlinkAttrs)
        ]).write(to: collisionIPA)

        // 4. IPA with ArchiveSymlinkQuotaExceeded (9-hop >8-pass convergence overflow)
        var quotaItems: [RawZIPItem] = [
            RawZIPItem(name: "Payload/SymApp.app/Info.plist", data: cleanPlist),
            RawZIPItem(name: "Payload/SymApp.app/SymApp", data: cleanBin, externalAttrs: execAttrs),
            RawZIPItem(name: "Payload/SymApp.app/Z/A9/Info.plist", data: extPlist),
            RawZIPItem(name: "Payload/SymApp.app/Z/A9/Ext", data: cleanBin, externalAttrs: execAttrs),
            RawZIPItem(name: "Payload/SymApp.app/PlugIns/Ext.appex", data: Data("../Z/A0".utf8), externalAttrs: symlinkAttrs)
        ]
        for idx in 0...8 {
            quotaItems.append(RawZIPItem(
                name: "Payload/SymApp.app/Z/A\(idx)/D",
                data: Data("../A\(idx + 1)".utf8),
                externalAttrs: symlinkAttrs
            ))
        }
        let quotaIPA = dir.appendingPathComponent("symlink_quota_exceeded.ipa")
        try buildStoredRawZIP(quotaItems).write(to: quotaIPA)

        // 5. IPA with AppexExecutableTraversal & IPA with CorruptMachO:UnparseableBinary
        let traversalExtPlist = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "\(bundleId).ext",
                "CFBundleExecutable": "../../Evil",
                "CFBundleShortVersionString": "1.0"
            ],
            format: .xml,
            options: 0
        )
        let traversalIPA = dir.appendingPathComponent("appex_traversal.ipa")
        try buildStoredRawZIP([
            RawZIPItem(name: "Payload/SymApp.app/Info.plist", data: cleanPlist),
            RawZIPItem(name: "Payload/SymApp.app/SymApp", data: cleanBin, externalAttrs: execAttrs),
            RawZIPItem(name: "Payload/SymApp.app/PlugIns/Ext.appex/Info.plist", data: traversalExtPlist)
        ]).write(to: traversalIPA)

        let corruptMachOIPA = dir.appendingPathComponent("corrupt_macho.ipa")
        try buildStoredRawZIP([
            RawZIPItem(name: "Payload/SymApp.app/Info.plist", data: cleanPlist),
            RawZIPItem(name: "Payload/SymApp.app/SymApp", data: cleanBin, externalAttrs: execAttrs),
            RawZIPItem(name: "Payload/SymApp.app/Frameworks/Bad.dylib", data: Data([0xCF, 0xFA, 0xED, 0xFE, 0x00, 0x00, 0x00, 0x00]))
        ]).write(to: corruptMachOIPA)

        let pipeline = SecurityPipeline(whitelistEngine: customWL)
        let cliDecoder = JSONDecoder()
        cliDecoder.dateDecodingStrategy = .iso8601

        for (expectedSig, ipaURL) in [
            ("BUNDLE_ESCAPING_SYMLINK", escapingIPA),
            ("ArchiveSymlinkCollision", collisionIPA),
            ("ArchiveSymlinkQuotaExceeded", quotaIPA),
            ("AppexExecutableTraversal", traversalIPA),
            ("CorruptMachO:UnparseableBinary", corruptMachOIPA)
        ] {
            let directFinding = try IPAPackageScanner(whitelistEngine: customWL).scan(ipaURL: ipaURL)
            XCTAssertEqual(directFinding.riskTier, .highRisk, "IPAPackageScanner must keep \(expectedSig) at .highRisk")
            XCTAssertFalse(directFinding.isWhitelisted, "IPAPackageScanner must not whitelist \(expectedSig)")
            XCTAssertFalse(directFinding.evidence.isWhitelistEligible, "isWhitelistEligible must be false for \(expectedSig)")
            XCTAssertTrue(directFinding.indicators.contains { $0.signature == expectedSig })

            let pipeFinding = try pipeline.scanIPA(at: ipaURL)
            XCTAssertEqual(pipeFinding.riskTier, .highRisk, "SecurityPipeline.scanIPA must keep \(expectedSig) at .highRisk")
            XCTAssertFalse(pipeFinding.isWhitelisted)
            XCTAssertFalse(pipeFinding.evidence.isWhitelistEligible)

            let cliRes = try await runCLIInProcess(["--ipa", ipaURL.path, "--whitelist", bundleId, "--format", "json"])
            XCTAssertEqual(cliRes.code, 1, "CLI --whitelist must exit 1 for \(expectedSig)")
            let cliSession = try cliDecoder.decode(ScanSession.self, from: Data(cliRes.out.utf8))
            let cliFinding = try XCTUnwrap(cliSession.findings.first)
            XCTAssertEqual(cliFinding.riskTier, .highRisk)
            XCTAssertFalse(cliFinding.isWhitelisted)
            XCTAssertFalse(cliFinding.evidence.isWhitelistEligible)
        }

        // 6. Standalone FAT binary with CorruptMachO:UnparseableSlice
        var fatData = Data()
        func appendBE32(_ d: inout Data, _ v: UInt32) {
            var be = v.bigEndian
            withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
        }
        let slice1Offset: UInt32 = 4096
        let slice1Size = UInt32(cleanBin.count)
        appendBE32(&fatData, 0xCAFE_BABE)
        appendBE32(&fatData, 2)
        // Arch 1: valid ARM64 slice
        appendBE32(&fatData, 0x0100_000C)
        appendBE32(&fatData, 0)
        appendBE32(&fatData, slice1Offset)
        appendBE32(&fatData, slice1Size)
        appendBE32(&fatData, 14)
        // Arch 2: corrupt out-of-bounds slice
        appendBE32(&fatData, 0x0100_000C)
        appendBE32(&fatData, 2)
        appendBE32(&fatData, 0x7FFF_0000)
        appendBE32(&fatData, 0x0001_0000)
        appendBE32(&fatData, 14)
        fatData.append(Data(repeating: 0, count: Int(slice1Offset) - fatData.count))
        fatData.append(cleanBin)
        let corruptFatURL = dir.appendingPathComponent("CorruptFatBin")
        try fatData.write(to: corruptFatURL)

        let fatFinding = try pipeline.scanBinary(at: corruptFatURL)
        XCTAssertEqual(fatFinding.riskTier, .highRisk)
        XCTAssertFalse(fatFinding.isWhitelisted)
        XCTAssertFalse(fatFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(fatFinding.indicators.contains { $0.signature == "CorruptMachO:UnparseableSlice" })

        // 7. On-disk .app bundle with escaping symlink via SecurityPipeline.scanBundle(at:)
        let appDir = dir.appendingPathComponent("EscapingSymBundle.app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        try cleanPlist.write(to: appDir.appendingPathComponent("Info.plist"))
        try cleanBin.write(to: appDir.appendingPathComponent("SymApp"))
        XCTAssertEqual(Darwin.symlink("/private/etc/passwd", appDir.appendingPathComponent("EscapeOut").path), 0)

        let bundleFinding = try pipeline.scanBundle(at: appDir)
        XCTAssertEqual(bundleFinding.riskTier, .highRisk)
        XCTAssertFalse(bundleFinding.isWhitelisted)
        XCTAssertFalse(bundleFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(bundleFinding.indicators.contains { $0.signature == "BUNDLE_ESCAPING_SYMLINK" })

        // 8. IMPERSONATION:MetaMask with empty appGroups must be blocked under custom empty-sig rule and CLI --whitelist
        let fakeMetaMaskIPA = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "MetaMask",
            bundleIdentifier: "io.metamask.fake",
            executableBinary: cleanBin,
            provisioningProfile: .developerSideloaded(teamId: "DRAINER999", devices: ["DEV1"])
        )))
        let mmPipeFinding = try pipeline.scanIPA(at: fakeMetaMaskIPA)
        XCTAssertEqual(mmPipeFinding.riskTier, .highRisk)
        XCTAssertFalse(mmPipeFinding.isWhitelisted)
        XCTAssertTrue(mmPipeFinding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })
        let mmCLI = try await runCLIInProcess(["--ipa", fakeMetaMaskIPA.path, "--whitelist", "io.metamask.fake", "--format", "json"])
        XCTAssertEqual(mmCLI.code, 1, "CLI --whitelist must exit 1 for IMPERSONATION:MetaMask")
        let mmCLISession = try cliDecoder.decode(ScanSession.self, from: Data(mmCLI.out.utf8))
        XCTAssertEqual(mmCLISession.findings.first?.riskTier, .highRisk)
        XCTAssertFalse(mmCLISession.findings.first?.isWhitelisted ?? true)

        XCTAssertNil(WhitelistEngine.shared.tool(named: "CLI-Whitelist-\(bundleId)"))
        XCTAssertNil(WhitelistEngine.shared.tool(named: "CLI-Whitelist-io.metamask.fake"))

        // 9. Positive control: clean .caution IPA (non-protected App Group + dlopen+dlsym) still whitelists under custom rule & CLI --whitelist
        let benignBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            symbols: ["_dlopen", "_dlsym"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.evil.benign"])
        ))
        let benignIPA = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "SymApp",
            bundleIdentifier: bundleId,
            executableBinary: benignBin,
            provisioningProfile: .developerSideloaded(teamId: "TEAMBENIGN", devices: ["DEV1"])
        )))
        let benignFinding = try pipeline.scanIPA(at: benignIPA)
        XCTAssertTrue(benignFinding.isWhitelisted)
        XCTAssertEqual(benignFinding.riskTier, .knownTool)
        let benignCLI = try await runCLIInProcess(["--ipa", benignIPA.path, "--whitelist", bundleId, "--format", "text"])
        XCTAssertEqual(benignCLI.code, 0)
    }

    // MARK: - Fix 6 Regression: Photos Bypass ObjC Symbols Deterministic & Non-Whitelistable

    func test_fix6_photosBypassObjCSymbols_deterministicAndNonWhitelistable() async throws {
        let objcVariants = [
            "_OBJC_CLASS_$_PLPhotoLibrary",
            "-[PLPhotoLibrary sharedPhotoLibrary]",
            "+[PLPhotoLibrary sharedPhotoLibrary]"
        ]

        // 1. Repeated determinism check on ExpandedThreatCatalog.evaluatePhotosBypass
        for _ in 0..<25 {
            for sym in objcVariants {
                let inds = ExpandedThreatCatalog.evaluatePhotosBypass(
                    linkedDylibs: [],
                    symbols: [sym],
                    entitlements: [:],
                    cryptid: 0
                )
                XCTAssertEqual(inds.count, 1, "Expected 1 Private Photos Bypass indicator for \(sym)")
                XCTAssertEqual(inds.first?.severity, .highRisk)
                XCTAssertEqual(
                    inds.first?.signature,
                    IOCTokenArmor.tPLPhotoLib,
                    "evaluatePhotosBypass must emit deterministic canonical signature for \(sym)"
                )
            }
        }

        // 2. Direct WhitelistEngine check with custom empty-signature rule across raw and token variants
        let bundleId = "com.evil.photodump"
        let customEmptyWL = WhitelistEngine()
        customEmptyWL.registerCustomTool(WhitelistedTool(
            name: "CustomNoSigPhotos",
            allowedBundleIds: [bundleId],
            allowedAppGroups: [],
            expectedSignatures: [],
            isEnabled: true,
            isBuiltIn: false
        ))

        let directBlockedSigs = objcVariants + [
            "-[PLPhotoLibrary",
            "+[PLPhotoLibrary",
            IOCTokenArmor.tPLPhotoLib
        ]
        for sig in directBlockedSigs {
            let wlRes = customEmptyWL.isWhitelisted(
                bundleId: bundleId,
                appGroups: [],
                matchedSignatures: [sig]
            )
            XCTAssertFalse(
                wlRes.isWhitelisted,
                "Custom empty-signature rule must reject Private Photos Bypass signature '\(sig)'"
            )
        }

        // 3. End-to-end IPAPackageScanner & CLICommandRunner --whitelist across all 3 ObjC symbol variants
        let cliDecoder = JSONDecoder()
        cliDecoder.dateDecodingStrategy = .iso8601

        for (idx, sym) in objcVariants.enumerated() {
            let bin = SyntheticMachOGenerator.shared.generateThin(config: .init(
                arch: .arm64,
                cryptid: 0,
                symbols: [sym]
            ))
            let ipa = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
                appName: "PhotoDump\(idx)",
                bundleIdentifier: bundleId,
                executableBinary: bin,
                provisioningProfile: .developerSideloaded(teamId: "EVILPHOTOS", devices: ["DEV1"])
            )))

            let ipaFinding = try IPAPackageScanner(whitelistEngine: customEmptyWL).scan(ipaURL: ipa)
            XCTAssertEqual(ipaFinding.riskTier, .highRisk, "IPAPackageScanner must keep \(sym) at .highRisk")
            XCTAssertFalse(ipaFinding.isWhitelisted, "IPAPackageScanner must never whitelist \(sym)")
            XCTAssertTrue(
                ipaFinding.indicators.contains {
                    $0.category == "Private Photos Bypass"
                        && $0.severity == .highRisk
                        && $0.signature == IOCTokenArmor.tPLPhotoLib
                },
                "Expected deterministic Private Photos Bypass indicator for \(sym)"
            )

            let cliRes = try await runCLIInProcess(["--ipa", ipa.path, "--whitelist", bundleId, "--format", "json"])
            XCTAssertEqual(cliRes.code, 1, "CLI --whitelist must exit 1 for \(sym)")
            let cliSession = try cliDecoder.decode(ScanSession.self, from: Data(cliRes.out.utf8))
            let cliFinding = try XCTUnwrap(cliSession.findings.first)
            XCTAssertEqual(cliFinding.riskTier, .highRisk)
            XCTAssertFalse(cliFinding.isWhitelisted)
        }

        XCTAssertNil(WhitelistEngine.shared.tool(named: "CLI-Whitelist-\(bundleId)"))
    }

    // MARK: - Fix 7 Regression: StashYAMLParser LibYAML Directives, Anchors, NEL & Flow URL Parity

    func test_fix7_stashYAMLParser_libYAMLDirectivesAnchorsNELAndFlowURLParity() throws {
        let validStash = SurgeBrotliShieldHelper.shared.generateShieldContent(for: .stash)

        let invalidCases: [(String, String)] = [
            ("yaml_1_2_rejected", "%YAML 1.2\n---\n" + validStash),
            ("yaml_1_0_rejected", "%YAML 1.0\n---\n" + validStash),
            ("yaml_1_3_rejected", "%YAML 1.3\n---\n" + validStash),
            ("duplicate_yaml_directive", "%YAML 1.1\n%YAML 1.1\n---\n" + validStash),
            ("duplicate_tag_directive", "%TAG !e! tag:a\n%TAG !e! tag:b\n---\n" + validStash),
            ("cross_doc_anchor_leak", "---\n" + validStash + "\na: &cross hello\n---\nb: *cross\n"),
            ("cross_doc_anchor_after_doc_end", "---\n" + validStash + "\na: &cross hello\n...\n---\nb: *cross\n"),
            ("nel_in_block_scalar_unindented", validStash + "\nextra: |\n  hello\u{0085}world\n"),
            ("ls_in_block_scalar_unindented", validStash + "\nextra: |\n  hello\u{2028}world\n"),
            ("ps_in_block_scalar_unindented", validStash + "\nextra: |\n  hello\u{2029}world\n"),
            ("flow_map_empty_val_without_space", "extra: {a:, b: 1}\n" + validStash),
            ("flow_seq_empty_val_without_space", "extra: [a:, b]\n" + validStash),
            ("flow_seq_trailing_colon", "extra: [a:]\n" + validStash),
            ("flow_map_trailing_colon", "extra: {a:}\n" + validStash),
            ("explicit_q_compact_seq_underindented", "? - a\n- b\n" + validStash),
            ("block_empty_key_without_anchor", ": 1\n" + validStash),
            ("flow_empty_key_without_anchor", "extra: { : 1 }\n" + validStash)
        ]

        for (label, yaml) in invalidCases {
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertFalse(res.isCompliant, "Invalid YAML must be rejected [\(label)]")
        }

        let validCases: [(String, String)] = [
            ("yaml_1_1_accepted", "%YAML 1.1\n---\n" + validStash),
            ("separate_docs_yaml_1_1_accepted", "%YAML 1.1\n---\n" + validStash + "\n...\n%YAML 1.1\n---\na: 1\n"),
            ("nel_in_block_scalar_indented", validStash + "\nextra: |\n  hello\u{0085}  world\n"),
            ("plain_scalar_leading_question_mark", "extra: ?foo\n" + validStash),
            ("explicit_q_compact_sequence", "? - a\n  - b\n: val\n" + validStash),
            ("explicit_q_compact_sequence_nested", "extra:\n  ? - a\n    - b\n  : val\n" + validStash),
            ("explicit_q_compact_mapping", "? k1: v1\n  k2: v2\n: val\n" + validStash),
            ("flow_anchor_empty_key_spaced", "extra: { &k : 1 }\n" + validStash),
            ("flow_anchor_empty_key_nospace", "extra: {&k: 1}\n" + validStash),
            ("block_anchor_empty_key", "&k: 1\n" + validStash),
            ("flow_seq_unquoted_url", "extra: [https://example.com]\n" + validStash),
            ("flow_map_unquoted_url", "extra: {u: https://example.com}\n" + validStash),
            ("flow_seq_colon_without_space", "extra: [a:b]\n" + validStash)
        ]

        for (label, yaml) in validCases {
            let res = SurgeBrotliShieldHelper.shared.validateShield(content: yaml, for: .stash)
            XCTAssertTrue(res.isCompliant, "Valid YAML must pass [\(label)]: \(res.errors)")
            XCTAssertTrue(res.hasScriptGuard, "hasScriptGuard must be true [\(label)]")
        }
    }

    // MARK: - Fix 8 Regression: Ad-Hoc CodeDirectory Bundle Seal Verification & Un-normalized Photos/AssetsLibrary Whitelist Rejection

    func test_fix8_adHocBundleSealVerification_detectsTamperedInfoPlistAndUnsealedFiles() async throws {
        let dir = try makeTempDir(prefix: "fix8_adhoc_seal")
        let bundleId = "com.example.adhocseal"

        func runTool(_ exe: String, args: [String]) throws {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: exe)
            proc.arguments = args
            let errPipe = Pipe()
            proc.standardError = errPipe
            try proc.run()
            proc.waitUntilExit()
            if proc.terminationStatus != 0 {
                let errText = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                XCTFail("\(exe) \(args.joined(separator: " ")) failed (\(proc.terminationStatus)): \(errText)")
            }
        }

        // Build real arm64 executable so /usr/bin/codesign -s - populates CS_ADHOC (0x2) + Special Slots -1/-3
        let cSrc = dir.appendingPathComponent("adhoc_app.c")
        try "#include <dlfcn.h>\nint main(void) { void *h = dlopen(0, 1); (void)dlsym(h, \"m\"); return 0; }\n".write(to: cSrc, atomically: true, encoding: .utf8)
        let builtExec = dir.appendingPathComponent("AdHocSealBin")
        try runTool("/usr/bin/clang", args: ["-arch", "arm64", "-Os", cSrc.path, "-o", builtExec.path])

        let payloadDir = dir.appendingPathComponent("Payload")
        let appDir = payloadDir.appendingPathComponent("AdHocSeal.app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)

        let cleanPlistDict: [String: Any] = [
            "CFBundleIdentifier": bundleId,
            "CFBundleName": "AdHocSeal",
            "CFBundleExecutable": "AdHocSeal",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1"
        ]
        let cleanPlistData = try PropertyListSerialization.data(fromPropertyList: cleanPlistDict, format: .xml, options: 0)
        let infoPlistURL = appDir.appendingPathComponent("Info.plist")
        try cleanPlistData.write(to: infoPlistURL)
        try FileManager.default.copyItem(at: builtExec, to: appDir.appendingPathComponent("AdHocSeal"))
        try Data("sealed asset\n".utf8).write(to: appDir.appendingPathComponent("asset.txt"))

        let entURL = dir.appendingPathComponent("adhoc_ent.plist")
        let entXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>com.apple.security.application-groups</key>
            <array><string>group.com.example.adhocseal</string></array>
        </dict></plist>
        """
        try entXML.write(to: entURL, atomically: true, encoding: .utf8)

        try runTool("/usr/bin/codesign", args: ["-f", "-s", "-", "-i", bundleId, "--entitlements", entURL.path, appDir.path])

        let customEmptyWL = WhitelistEngine()
        customEmptyWL.registerCustomTool(WhitelistedTool(
            name: "AdHocCustomEmpty",
            allowedBundleIds: [bundleId],
            allowedAppGroups: [],
            expectedSignatures: [],
            isEnabled: true,
            isBuiltIn: false
        ))
        let customPipeline = SecurityPipeline(whitelistEngine: customEmptyWL)
        let customIPAScanner = IPAPackageScanner(whitelistEngine: customEmptyWL)
        let cliDecoder = JSONDecoder()
        cliDecoder.dateDecodingStrategy = .iso8601

        // 1. Untampered ad-hoc bundle passes Special Slot -1 / -3 and CodeDirectory.identifier verification
        let untamperedBundleFinding = try customPipeline.scanBundle(at: appDir)
        XCTAssertFalse(
            untamperedBundleFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" },
            "Untampered ad-hoc bundle must not emit CODE_SIGNATURE_SEAL_MISMATCH: \(untamperedBundleFinding.indicators)"
        )
        XCTAssertTrue(untamperedBundleFinding.evidence.isWhitelistEligible)
        XCTAssertEqual(untamperedBundleFinding.riskTier, .knownTool)
        XCTAssertTrue(untamperedBundleFinding.isWhitelisted)

        let untamperedIPA = dir.appendingPathComponent("untampered_adhoc.ipa")
        try zipDirectory(dir, to: untamperedIPA)
        let untamperedIPAFinding = try customIPAScanner.scan(ipaURL: untamperedIPA)
        XCTAssertFalse(untamperedIPAFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" })
        XCTAssertTrue(untamperedIPAFinding.evidence.isWhitelistEligible)
        XCTAssertEqual(untamperedIPAFinding.riskTier, .knownTool)
        XCTAssertTrue(untamperedIPAFinding.isWhitelisted)

        let untamperedCLI = try await runCLIInProcess(["--ipa", untamperedIPA.path, "--whitelist", bundleId, "--format", "json"])
        XCTAssertEqual(untamperedCLI.code, 0)

        // 2. Tamper Info.plist (Special Slot -1 mismatch) -> CODE_SIGNATURE_SEAL_MISMATCH, .highRisk, isWhitelistEligible == false
        var tamperedPlistDict = cleanPlistDict
        tamperedPlistDict["CFBundleName"] = "TamperedAdHocSeal"
        let tamperedPlistData = try PropertyListSerialization.data(fromPropertyList: tamperedPlistDict, format: .xml, options: 0)
        try tamperedPlistData.write(to: infoPlistURL)

        let tamperedPlistBundleFinding = try customPipeline.scanBundle(at: appDir)
        XCTAssertEqual(tamperedPlistBundleFinding.riskTier, .highRisk)
        XCTAssertFalse(tamperedPlistBundleFinding.isWhitelisted)
        XCTAssertFalse(tamperedPlistBundleFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(tamperedPlistBundleFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" })

        let tamperedPlistIPA = dir.appendingPathComponent("tampered_plist_adhoc.ipa")
        try zipDirectory(dir, to: tamperedPlistIPA)
        let tamperedPlistIPAFinding = try customIPAScanner.scan(ipaURL: tamperedPlistIPA)
        XCTAssertEqual(tamperedPlistIPAFinding.riskTier, .highRisk)
        XCTAssertFalse(tamperedPlistIPAFinding.isWhitelisted)
        XCTAssertFalse(tamperedPlistIPAFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(tamperedPlistIPAFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" })

        let tamperedPlistCLI = try await runCLIInProcess(["--ipa", tamperedPlistIPA.path, "--whitelist", bundleId, "--format", "json"])
        XCTAssertEqual(tamperedPlistCLI.code, 1)
        let tamperedPlistCLIFinding = try XCTUnwrap(try cliDecoder.decode(ScanSession.self, from: Data(tamperedPlistCLI.out.utf8)).findings.first)
        XCTAssertEqual(tamperedPlistCLIFinding.riskTier, .highRisk)
        XCTAssertFalse(tamperedPlistCLIFinding.isWhitelisted)
        XCTAssertFalse(tamperedPlistCLIFinding.evidence.isWhitelistEligible)

        // Restore Info.plist and inject unsealed evil.js (Special Slot -3 mismatch)
        try cleanPlistData.write(to: infoPlistURL)
        let evilJSURL = appDir.appendingPathComponent("evil.js")
        try Data("evil_payload();\n".utf8).write(to: evilJSURL)

        let unsealedBundleFinding = try customPipeline.scanBundle(at: appDir)
        XCTAssertEqual(unsealedBundleFinding.riskTier, .highRisk)
        XCTAssertFalse(unsealedBundleFinding.isWhitelisted)
        XCTAssertFalse(unsealedBundleFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(unsealedBundleFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" })

        let unsealedIPA = dir.appendingPathComponent("unsealed_js_adhoc.ipa")
        try zipDirectory(dir, to: unsealedIPA)
        let unsealedIPAFinding = try customIPAScanner.scan(ipaURL: unsealedIPA)
        XCTAssertEqual(unsealedIPAFinding.riskTier, .highRisk)
        XCTAssertFalse(unsealedIPAFinding.isWhitelisted)
        XCTAssertFalse(unsealedIPAFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(unsealedIPAFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" })

        let unsealedCLI = try await runCLIInProcess(["--ipa", unsealedIPA.path, "--whitelist", bundleId, "--format", "json"])
        XCTAssertEqual(unsealedCLI.code, 1)
        let unsealedCLIFinding = try XCTUnwrap(try cliDecoder.decode(ScanSession.self, from: Data(unsealedCLI.out.utf8)).findings.first)
        XCTAssertEqual(unsealedCLIFinding.riskTier, .highRisk)
        XCTAssertFalse(unsealedCLIFinding.isWhitelisted)
        XCTAssertFalse(unsealedCLIFinding.evidence.isWhitelistEligible)

        // 3. Mismatched CodeDirectory.identifier (-i com.evil.malware vs CFBundleIdentifier = com.example.adhocseal)
        try FileManager.default.removeItem(at: evilJSURL)
        try runTool("/usr/bin/codesign", args: ["-f", "-s", "-", "-i", "com.evil.malware", "--entitlements", entURL.path, appDir.path])

        let mismatchBundleFinding = try customPipeline.scanBundle(at: appDir)
        XCTAssertEqual(mismatchBundleFinding.riskTier, .highRisk)
        XCTAssertFalse(mismatchBundleFinding.isWhitelisted)
        XCTAssertFalse(mismatchBundleFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(mismatchBundleFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" })

        let mismatchIPA = dir.appendingPathComponent("mismatch_ident_adhoc.ipa")
        try zipDirectory(dir, to: mismatchIPA)
        let mismatchIPAFinding = try customIPAScanner.scan(ipaURL: mismatchIPA)
        XCTAssertEqual(mismatchIPAFinding.riskTier, .highRisk)
        XCTAssertFalse(mismatchIPAFinding.isWhitelisted)
        XCTAssertFalse(mismatchIPAFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(mismatchIPAFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" })

        // 3b. Nested ad-hoc .framework Slot -3 seal verification (CSBlobParser.swift:1967)
        let fwRoot = appDir.appendingPathComponent("Frameworks/Sub.framework")
        try FileManager.default.createDirectory(at: fwRoot, withIntermediateDirectories: true)
        let fwCSrc = dir.appendingPathComponent("sub_fw.c")
        try "int sub_fn(void) { return 42; }\n".write(to: fwCSrc, atomically: true, encoding: .utf8)
        let fwDylib = fwRoot.appendingPathComponent("Sub")
        try runTool("/usr/bin/clang", args: ["-dynamiclib", "-arch", "arm64", "-Os", fwCSrc.path, "-o", fwDylib.path])
        try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleIdentifier": "com.example.adhocseal.sub",
                "CFBundleExecutable": "Sub",
                "CFBundleShortVersionString": "1.0"
            ],
            format: .xml,
            options: 0
        ).write(to: fwRoot.appendingPathComponent("Info.plist"))
        try Data("sealed fw resource\n".utf8).write(to: fwRoot.appendingPathComponent("fw.txt"))
        try runTool("/usr/bin/codesign", args: ["-f", "-s", "-", "-i", "com.example.adhocseal.sub", fwRoot.path])
        try runTool("/usr/bin/codesign", args: ["-f", "-s", "-", "-i", bundleId, "--entitlements", entURL.path, appDir.path])

        let untamperedNestedFinding = try customPipeline.scanBundle(at: appDir)
        XCTAssertFalse(untamperedNestedFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" })
        XCTAssertTrue(untamperedNestedFinding.evidence.isWhitelistEligible)

        try Data("evil_fw();\n".utf8).write(to: fwRoot.appendingPathComponent("evil.js"))
        let tamperedNestedFinding = try customPipeline.scanBundle(at: appDir)
        XCTAssertEqual(tamperedNestedFinding.riskTier, .highRisk)
        XCTAssertFalse(tamperedNestedFinding.isWhitelisted)
        XCTAssertFalse(tamperedNestedFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(tamperedNestedFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" })
        try FileManager.default.removeItem(at: fwRoot.appendingPathComponent("evil.js"))

        // Verify CS_ADHOC remains disqualified from Apple App Store / TestFlight CMS trust
        let execSlices = try MachOParser.shared.parseAllSlices(data: Data(contentsOf: appDir.appendingPathComponent("AdHocSeal")))
        let trustEval = CSBlobParser.shared.inspectCodeSignatureTrustEvaluation(fromSlices: execSlices)
        XCTAssertEqual(trustEval.disposition, .adHocOrUnsigned)
        XCTAssertEqual(trustEval.signerKind, .none)

        // 4. Positive control: minimal synthetic ad-hoc CodeDirectory (zeroed slots, nCodeSlots == 0) produces zero false positives
        var minAdHocCD = Data()
        func appendBE32(_ d: inout Data, _ v: UInt32) {
            var be = v.bigEndian
            withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
        }
        appendBE32(&minAdHocCD, 0x0002_0400)
        appendBE32(&minAdHocCD, CSBlobConstants.csAdhocFlag)
        minAdHocCD.append(Data(repeating: 0, count: 28))
        let synthBin = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            rawCodeSignatureSlot: (
                slot: CSBlobConstants.slotCodeDirectory,
                magic: CSBlobConstants.codeDirectoryMagic,
                data: minAdHocCD
            )
        ))
        let synthIPA = trackTemp(try MockIPAGenerator.shared.createIPA(config: .init(
            appName: "MinAdHocSynth",
            bundleIdentifier: bundleId,
            executableBinary: synthBin,
            provisioningProfile: .none
        )))
        let synthFinding = try customIPAScanner.scan(ipaURL: synthIPA)
        XCTAssertFalse(synthFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" })
        XCTAssertTrue(synthFinding.evidence.isWhitelistEligible)
        XCTAssertEqual(synthFinding.riskTier, .safe)

        // 5. Un-normalized Photos/AssetsLibrary signatures rejected by WhitelistEngine custom empty-sig rule
        let unnormalizedPhotoSigs = [
            "-[PHPhotoLibrary systemPhotoLibrary]",
            "/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/PhotoLibraryServices",
            "/System/Library/PrivateFrameworks/AssetsLibraryServices.framework/AssetsLibraryServices"
        ]
        for sig in unnormalizedPhotoSigs {
            let directWL = customEmptyWL.isWhitelisted(
                bundleId: bundleId,
                appGroups: [],
                matchedSignatures: [sig]
            )
            XCTAssertFalse(
                directWL.isWhitelisted,
                "WhitelistEngine must reject un-normalized Photos/AssetsLibrary signature '\(sig)'"
            )

            let fakeFinding = ScanFinding(
                bundleId: bundleId,
                displayName: "PhotoBypass",
                version: "1.0",
                bundlePath: "/tmp/PhotoBypass.app",
                installChannel: .developerSideloaded,
                riskTier: .highRisk,
                indicators: [
                    ThreatIndicator(
                        signature: sig,
                        description: "Un-normalized private photos signature",
                        category: "Private Photos Bypass",
                        location: "AdHocSeal",
                        severity: .highRisk
                    )
                ],
                evidence: AuditEvidence(
                    matchedSymbols: [sig],
                    isWhitelistEligible: true
                )
            )
            let evalWL = customEmptyWL.evaluateFindingWhitelist(fakeFinding)
            XCTAssertFalse(
                evalWL.isWhitelisted,
                "evaluateFindingWhitelist must reject un-normalized signature '\(sig)'"
            )
        }

        XCTAssertNil(WhitelistEngine.shared.tool(named: "CLI-Whitelist-\(bundleId)"))
    }
}
