//
//  AuditV135Vectors1To3Tests.swift
//  WQGuardCoreTests
//
//  Milestone M2 Comprehensive Deterministic Regression Suite (Vectors 1-3 & R2/R4):
//  - R1.1 Closed Apple App Group allowlist (all 104 SimRuntime unique_app_groups + bypass vectors)
//  - R1.2 isGenuineAppleNoSandboxStockApp & multi-privilege lockdown + R4 stock apps
//  - R1.4 Registry offline TestFlight forgery + InstalledAppRegistryScanner/SecurityPipeline parity
//  - R1.3 Unified host self-whitelisting, ExpandedThreatCatalog, WhitelistEngine, AuditEvidence
//  - R2 SecurityPipeline (scanBinary __info_plist, scanBundle .framework CodeResources seal,
//       correlateAndMergeFindings) & MachOScanner (cryptid=1, cryptsize=0 & ASCII search)
//

import XCTest
import Foundation
import CryptoKit
import MachO
@testable import WQGuardCore

final class AuditV135Vectors1To3Tests: XCTestCase {

    // MARK: - Helpers (Minimal ARM64 Mach-O & CodeSignature Builders)

    private static func appendLE32(_ out: inout Data, _ v: UInt32) {
        var le = v.littleEndian
        withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
    }

    private static func appendLE64(_ out: inout Data, _ v: UInt64) {
        var le = v.littleEndian
        withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
    }

    private static func appendBE32(_ out: inout Data, _ v: UInt32) {
        var be = v.bigEndian
        withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
    }

    private static func fixed16(_ str: String) -> Data {
        var d = Data(repeating: 0, count: 16)
        let bytes = Array(str.utf8.prefix(16))
        for (i, b) in bytes.enumerated() {
            d[i] = b
        }
        return d
    }

    /// Builds a minimal valid 64-bit ARM64 Mach-O with optional:
    /// - `LC_ENCRYPTION_INFO_64` (`cryptid`, `cryptoff`, `cryptsize`)
    /// - `__TEXT,__cstring` payload
    /// - `__TEXT,__info_plist` raw bytes
    /// - `LC_CODE_SIGNATURE` SuperBlob (`CodeDirectory` with optional Special Slots `-1`, `-3`, `-5` and optional XML entitlements)
    private static func buildMinimalARM64MachO(
        cryptid: UInt32 = 0,
        cryptoff: UInt32 = 0,
        cryptsize: UInt32 = 0,
        cstringPayload: Data = Data(),
        infoPlistData: Data? = nil,
        codeDirectoryIdentifier: String? = nil,
        teamIdentifier: String? = nil,
        xmlEntitlements: String? = nil,
        codeResourcesData: Data? = nil,
        includeCodeSignature: Bool = true
    ) -> Data {
        let headerSize = 32 // mach_header_64
        // Commands:
        // 1. LC_SEGMENT_64 __TEXT (72 + 80 * sectionCount)
        // 2. optional LC_ENCRYPTION_INFO_64 (24)
        // 3. optional LC_CODE_SIGNATURE (16)
        // 4. LC_SEGMENT_64 __LINKEDIT (72)
        var textSections: [(seg: String, sect: String, data: Data)] = []
        if !cstringPayload.isEmpty {
            textSections.append(("__TEXT", "__cstring", cstringPayload))
        }
        if let infoPlistData {
            textSections.append(("__TEXT", "__info_plist", infoPlistData))
        }

        let textCmdSize = UInt32(72 + 80 * textSections.count)
        let encCmdSize: UInt32 = (cryptid != 0 || cryptsize != 0 || cryptoff != 0) ? 24 : 0
        let csCmdSize: UInt32 = includeCodeSignature ? 16 : 0
        let linkeditCmdSize: UInt32 = 72
        let sizeofcmds = textCmdSize + encCmdSize + csCmdSize + linkeditCmdSize
        var ncmds: UInt32 = 2 // __TEXT + __LINKEDIT
        if encCmdSize > 0 { ncmds += 1 }
        if csCmdSize > 0 { ncmds += 1 }

        // Place __TEXT sections starting at offset 0x1000 (4096)
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
            let off = sectOffsets[idx]
            fileBytes.replaceSubrange(off..<(off + s.data.count), with: s.data)
        }

        let linkeditOffset = fileBytes.count
        var superBlob = Data()
        if includeCodeSignature {
            var slots: [(UInt32, Data)] = []
            let entData = xmlEntitlements.map { Data($0.utf8) }
            if let cdIdent = codeDirectoryIdentifier {
                let cd = M1TestCMSFixtures.buildCodeDirectory(
                    identifier: cdIdent,
                    codeLimit: linkeditOffset,
                    slicePrefixBytes: fileBytes,
                    infoPlistData: infoPlistData,
                    codeResourcesData: codeResourcesData,
                    slot5Blob: entData,
                    teamIdentifier: teamIdentifier
                )
                slots.append((CSBlobConstants.slotCodeDirectory, cd))
            }
            if let entData {
                var entBlob = Data()
                appendBE32(&entBlob, CSBlobConstants.entitlementXmlMagic)
                appendBE32(&entBlob, UInt32(8 + entData.count))
                entBlob.append(entData)
                slots.append((CSBlobConstants.slotEntitlements, entBlob))
            }
            if !slots.isEmpty {
                superBlob = M1TestCMSFixtures.buildSuperBlob(slots: slots)
            } else {
                // Minimal empty SuperBlob
                superBlob = M1TestCMSFixtures.buildSuperBlob(slots: [])
            }
            fileBytes.append(superBlob)
        }

        let linkeditSize = fileBytes.count - linkeditOffset

        // Write mach_header_64
        var hdr = Data()
        appendLE32(&hdr, MH_MAGIC_64)
        appendLE32(&hdr, UInt32(bitPattern: CPU_TYPE_ARM64))
        appendLE32(&hdr, UInt32(bitPattern: CPU_SUBTYPE_ARM64_ALL))
        appendLE32(&hdr, UInt32(MH_EXECUTE))
        appendLE32(&hdr, ncmds)
        appendLE32(&hdr, sizeofcmds)
        appendLE32(&hdr, 0x0020_0085) // MH_NOUNDEFS | MH_DYLDLINK | MH_PIE
        appendLE32(&hdr, 0) // reserved
        assert(hdr.count == headerSize)

        var cmds = Data()
        // LC_SEGMENT_64 __TEXT
        appendLE32(&cmds, UInt32(LC_SEGMENT_64))
        appendLE32(&cmds, textCmdSize)
        cmds.append(fixed16("__TEXT"))
        appendLE64(&cmds, 0x100000000)
        appendLE64(&cmds, UInt64(textEnd))
        appendLE64(&cmds, 0)
        appendLE64(&cmds, UInt64(textEnd))
        appendLE32(&cmds, 5) // maxprot r-x
        appendLE32(&cmds, 5) // initprot r-x
        appendLE32(&cmds, UInt32(textSections.count))
        appendLE32(&cmds, 0) // flags
        for (idx, s) in textSections.enumerated() {
            cmds.append(fixed16(s.sect))
            cmds.append(fixed16(s.seg))
            appendLE64(&cmds, 0x100000000 + UInt64(sectOffsets[idx]))
            appendLE64(&cmds, UInt64(s.data.count))
            appendLE32(&cmds, UInt32(sectOffsets[idx]))
            appendLE32(&cmds, 0) // align
            appendLE32(&cmds, 0) // reloff
            appendLE32(&cmds, 0) // nreloc
            appendLE32(&cmds, 0) // flags
            appendLE32(&cmds, 0) // reserved1
            appendLE32(&cmds, 0) // reserved2
            appendLE32(&cmds, 0) // reserved3
        }

        if encCmdSize > 0 {
            appendLE32(&cmds, UInt32(LC_ENCRYPTION_INFO_64))
            appendLE32(&cmds, 24)
            appendLE32(&cmds, cryptoff)
            appendLE32(&cmds, cryptsize)
            appendLE32(&cmds, cryptid)
            appendLE32(&cmds, 0)
        }

        if csCmdSize > 0 {
            appendLE32(&cmds, UInt32(LC_CODE_SIGNATURE))
            appendLE32(&cmds, 16)
            appendLE32(&cmds, UInt32(linkeditOffset))
            appendLE32(&cmds, UInt32(superBlob.count))
        }

        // LC_SEGMENT_64 __LINKEDIT
        appendLE32(&cmds, UInt32(LC_SEGMENT_64))
        appendLE32(&cmds, linkeditCmdSize)
        cmds.append(fixed16("__LINKEDIT"))
        appendLE64(&cmds, 0x100000000 + UInt64(textEnd))
        appendLE64(&cmds, UInt64(max(4096, linkeditSize)))
        appendLE64(&cmds, UInt64(linkeditOffset))
        appendLE64(&cmds, UInt64(linkeditSize))
        appendLE32(&cmds, 1) // maxprot r--
        appendLE32(&cmds, 1) // initprot r--
        appendLE32(&cmds, 0)
        appendLE32(&cmds, 0)

        assert(cmds.count == Int(sizeofcmds))
        fileBytes.replaceSubrange(0..<headerSize, with: hdr)
        fileBytes.replaceSubrange(headerSize..<(headerSize + Int(sizeofcmds)), with: cmds)

        // If CodeDirectory exists, re-compute page hashes now that header/load commands are written!
        if includeCodeSignature, let cdIdent = codeDirectoryIdentifier {
            let entData = xmlEntitlements.map { Data($0.utf8) }
            let cd = M1TestCMSFixtures.buildCodeDirectory(
                identifier: cdIdent,
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
            let updatedSB = M1TestCMSFixtures.buildSuperBlob(slots: slots)
            assert(updatedSB.count == superBlob.count)
            fileBytes.replaceSubrange(linkeditOffset..<(linkeditOffset + updatedSB.count), with: updatedSB)
        }

        return fileBytes
    }

    // MARK: - 1. R1.1 Closed Apple App Group Allowlist (All 104 SimRuntime Groups + Bypass Vectors)

    func test_r11_closedAppleAppGroupAllowlist_simRuntime104AndBypassVectors() {
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
        for grp in simRuntime104Groups {
            XCTAssertTrue(
                InstalledAppRegistryScanner.isAppleOwnedAppGroup(grp),
                "SimRuntime Apple App Group '\(grp)' must be accepted"
            )
        }

        // Additional verified Apple Team-ID-prefixed & acquired service groups
        let extraAppleGroups = [
            "243LU875E5.groups.com.apple.podcasts",
            "243LU875E5.groups.com.apple.music",
            "4GWDBCF5A4.com.apple.musicrecognition",
            "4WXS7A4F54.com.apple.familycontrols",
            "RD13622867.com.apple.CloudDocsUI",
            "RLRS9CRG76.com.apple.nanobackupd",
            "ZL6BUSYGB3.com.apple.newsd",
            "V568VXD5P8.com.apple.ShortcutsUI",
            "APPLE.com.apple.Preferences",
            "group.com.icloud.shared",
            "com.shazam.ShazamApp"
        ]
        for grp in extraAppleGroups {
            XCTAssertTrue(
                InstalledAppRegistryScanner.isAppleOwnedAppGroup(grp),
                "Verified Apple Team-ID / acquired group '\(grp)' must be accepted"
            )
        }

        // Closed-allowlist negative controls: empty, bare 'apple', heuristic 5+ letters, colliding short prefixes, unvalidated Team ID suffixes
        let rejectedGroups = [
            "",
            "   \n\t ",
            "apple",
            "group.customshare.exfil",
            "group.customcontainer.shared",
            "systemgroup.attacker.c2",
            "group.im.token.app",
            "group.tv.danmaku.bilianime",
            "group.maps.thirdparty",
            "group.mail.evil",
            "group.home.assistant",
            "group.tips.custom",
            "group.news.aggregator",
            "group.ams.custom",
            "group.sms.gateway",
            "group.gm.custom",
            "59GAB85EFG.evil.metamask",
            "4GWDBCF5A4.evil.app",
            "0000000000.io.metamask.drainer",
            "APPLE.evil.payload",
            "group.com.wqguard.app",
            "group.ca628877a97ac6a2.1",
            "group.mycompany.audit"
        ]
        for grp in rejectedGroups {
            XCTAssertFalse(
                InstalledAppRegistryScanner.isAppleOwnedAppGroup(grp),
                "Non-Apple / spoofed App Group '\(grp)' must be rejected by closed allowlist"
            )
        }
    }

    // MARK: - 2. R1.2 No-Sandbox Lockdown, Multi-Privilege Escalation & R4 Stock Apps

    func test_r12_noSandboxLockdown_multiPrivilegeAttacksBlocked_andR4StockAppsPreserved() throws {
        let scanner = InstalledAppRegistryScanner.shared

        // Positive R4: `com.apple.reminders` v7.0 (`no-sandbox = true` + `group.com.apple.reminders` + `group.com.apple.assistant.shared`)
        let genuineReminders = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
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
        ]))
        XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(genuineReminders))
        XCTAssertTrue(scanner.evaluateRecords([genuineReminders], includeAppStoreApps: true).isEmpty)

        // Genuine `com.apple.reminders` carrying first-party Apple entitlements (`MobileGestalt`, `Photos`,
        // `platform-application`, `com.apple.*` keychain, additional Apple stock groups) MUST remain accepted.
        let genuineExtendedReminders = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.reminders",
            "CFBundleDisplayName": "提醒事项",
            "CFBundleShortVersionString": "7.0",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-REM-EXT/Reminders.app",
            "Entitlements": [
                "com.apple.private.security.no-sandbox": true,
                "platform-application": true,
                "com.apple.private.MobileGestalt.AllowedProtectedKeys": true,
                "com.apple.photos.bourgeoisie": true,
                "keychain-access-groups": ["com.apple.*"],
                "com.apple.security.application-groups": ["group.com.apple.reminders", "group.com.apple.tipsnext"]
            ]
        ]))
        XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(genuineExtendedReminders))
        XCTAssertTrue(scanner.evaluateRecords([genuineExtendedReminders], includeAppStoreApps: true).isEmpty)

        // Attack 1: `com.apple.reminders` genuine platform-invariant violations MUST still fail closed
        let remindersAttacks: [(String, [String: Any])] = [
            ("no-container", [
                "com.apple.private.security.no-sandbox": true,
                "com.apple.private.security.no-container": true,
                "com.apple.security.application-groups": ["group.com.apple.reminders"]
            ]),
            ("container-required=false", [
                "com.apple.private.security.no-sandbox": true,
                "com.apple.private.security.container-required": false,
                "com.apple.security.application-groups": ["group.com.apple.reminders"]
            ]),
            ("keychain *", [
                "com.apple.private.security.no-sandbox": true,
                "keychain-access-groups": ["*"],
                "com.apple.security.application-groups": ["group.com.apple.reminders"]
            ]),
            ("keychain OTHERTEAM.*", [
                "com.apple.private.security.no-sandbox": true,
                "keychain-access-groups": ["OTHERTEAM.*"],
                "com.apple.security.application-groups": ["group.com.apple.reminders"]
            ]),
            ("EVILTEAM99 teamId", [
                "com.apple.developer.team-identifier": "EVILTEAM99",
                "com.apple.private.security.no-sandbox": true,
                "com.apple.security.application-groups": ["group.com.apple.reminders"]
            ]),
            ("non-Apple group.io.metamask", [
                "com.apple.private.security.no-sandbox": true,
                "com.apple.security.application-groups": ["group.com.apple.reminders", "group.io.metamask"]
            ]),
            ("empty appGroups", [
                "com.apple.private.security.no-sandbox": true
            ])
        ]
        for (label, ents) in remindersAttacks {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.apple.reminders",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-ATK/Reminders.app",
                "Entitlements": ents
            ]))
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "Reminders attack '\(label)' must be rejected")
            XCTAssertEqual(scanner.evaluateRecord(rec).riskTier, .highRisk, "Reminders attack '\(label)' must be .highRisk")
        }

        // Attack 2: Spoofed `Tips` holding only `group.com.apple.reminders` must stay rejected;
        // genuine staged `com.apple.Health` with MCM/MobileGestalt/tcc.allow must be accepted while hijacked Health is rejected
        let tipsNoSandbox = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.tips",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-TIPS/Tips.app",
            "Entitlements": [
                "com.apple.private.security.no-sandbox": true,
                "com.apple.security.application-groups": ["group.com.apple.reminders"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(tipsNoSandbox))
        XCTAssertEqual(scanner.evaluateRecord(tipsNoSandbox).riskTier, .highRisk)

        let genuineStagedHealth = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Health",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-HEALTH/Health.app",
            "Entitlements": [
                "com.apple.private.MobileContainerManager.allowed": true,
                "com.apple.private.MobileGestalt.allowed": true,
                "com.apple.private.tcc.allow": ["kTCCServiceMotion"]
            ]
        ]))
        XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(genuineStagedHealth))
        XCTAssertTrue(scanner.evaluateRecords([genuineStagedHealth], includeAppStoreApps: true).isEmpty)

        for (label, badDict) in [
            ("Health no-container", [
                "CFBundleIdentifier": "com.apple.Health",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-H-NOCONT/Health.app",
                "Entitlements": ["com.apple.private.security.no-container": true]
            ] as [String: Any]),
            ("Health wildcard keychain *", [
                "CFBundleIdentifier": "com.apple.Health",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-H-STAR/Health.app",
                "Entitlements": ["keychain-access-groups": ["*"]]
            ] as [String: Any]),
            ("Health AdHoc signer", [
                "CFBundleIdentifier": "com.apple.Health",
                "ApplicationType": "System",
                "SignerIdentity": "Ad Hoc",
                "Path": "/private/var/containers/Bundle/Application/UUID-H-ADHOC/Health.app",
                "Entitlements": ["platform-application": true]
            ] as [String: Any])
        ] {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary(badDict))
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "\(label) must be rejected")
            XCTAssertEqual(scanner.evaluateRecord(rec).riskTier, .highRisk, "\(label) must be .highRisk")
        }

        let vendableEvil = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.evil",
            "ApplicationType": "System",
            "IsAppStoreVendable": true,
            "Path": "/private/var/containers/Bundle/Application/UUID-EVIL/Evil.app",
            "Entitlements": [
                "com.apple.private.MobileGestalt.AllowedProtectedKeys": true,
                "com.apple.private.MobileContainerManager.allowed": true,
                "keychain-access-groups": ["com.apple.*"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(vendableEvil))
        XCTAssertEqual(scanner.evaluateRecord(vendableEvil).riskTier, .highRisk)

        // Attack 3: Unlisted Team ID (`EVILTEAM99`) without exact `application-identifier` match on staged `com.apple.Translate`
        let translateWrongAppId = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Translate",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-TR/Translate.app",
            "Entitlements": [
                "com.apple.developer.team-identifier": "EVILTEAM99",
                "application-identifier": "EVILTEAM99.com.apple.other",
                "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(translateWrongAppId))

        // Attack 4: SSV Preboot & Developer path tightening (`/private/preboot/evil/` & `/Developer/Applications/` rejected; `/private/preboot/Cryptexes/` accepted)
        let prebootEvil = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Preferences",
            "ApplicationType": "System",
            "Path": "/private/preboot/evil/Preferences.app",
            "Entitlements": ["com.apple.private.security.no-sandbox": true]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(prebootEvil))

        let devAppsEvil = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Preferences",
            "ApplicationType": "System",
            "Path": "/Developer/Applications/Preferences.app",
            "Entitlements": ["com.apple.private.security.no-sandbox": true]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(devAppsEvil))

        let prebootCryptex = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Preferences",
            "ApplicationType": "System",
            "Path": "/private/preboot/Cryptexes/OS/System/Applications/Preferences.app",
            "Entitlements": ["com.apple.private.security.no-sandbox": true]
        ]))
        XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(prebootCryptex))

        // Attack 5: `extraSideloadImpersonationTargets` display-name impersonation on `com.apple.*`
        let appleTipsWeChat = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.tips",
            "CFBundleDisplayName": "微信",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-WX/Tips.app",
            "Entitlements": ["com.apple.security.application-groups": ["group.com.apple.tips"]]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(appleTipsWeChat))
        XCTAssertEqual(scanner.evaluateRecord(appleTipsWeChat).riskTier, .highRisk)

        // Attack 6: `devicectl` traversal, non-cryptex preboot, `fromAppStore: true` on `com.apple.evil`, `testFlight: true` without signer, and 2026 entitlements
        let devicectlJSON: [String: Any] = [
            "result": [
                "apps": [
                    [
                        "bundleIdentifier": "com.evil.traversal",
                        "name": "Traversal",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "url": "file:///var/jb/../../Applications/Evil.app"
                    ],
                    [
                        "bundleIdentifier": "com.evil.containertraversal",
                        "name": "ContainerTraversal",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "bundleContainerPath": "/Applications/../var/jb/Evil.app"
                    ],
                    [
                        "bundleIdentifier": "com.evil.preboot",
                        "name": "PrebootEvil",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "url": "file:///private/preboot/evil-jb/Evil.app"
                    ],
                    [
                        "bundleIdentifier": "com.apple.evil",
                        "name": "FakeApple",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "fromAppStore": true,
                        "url": "file:///private/var/containers/Bundle/Application/1111/FakeApple.app"
                    ],
                    [
                        "bundleIdentifier": "com.evil.fakebeta",
                        "name": "FakeBeta",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "testFlight": true,
                        "appGroupIdentifiers": ["group.com.evil.fakebeta"],
                        "url": "file:///private/var/containers/Bundle/Application/2222/FakeBeta.app"
                    ],
                    [
                        "bundleIdentifier": "com.evil.gestalt",
                        "name": "GestaltEvil",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "entitlements": [
                            "com.apple.private.MobileGestalt.AllowedProtectedKeys": true,
                            "keychain-access-groups": ["*"]
                        ],
                        "url": "file:///private/var/containers/Bundle/Application/3333/GestaltEvil.app"
                    ]
                ]
            ]
        ]
        let ctlData = try JSONSerialization.data(withJSONObject: devicectlJSON, options: [])
        let ctlRecords = try scanner.parseSnapshotData(ctlData)
        XCTAssertEqual(ctlRecords.count, 6)
        for rec in ctlRecords {
            XCTAssertFalse(rec.hasAppStoreMetadata, "devicectl spoof \(rec.bundleId) must not fabricate App Store metadata")
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "\(rec.bundleId) must not be trusted as Apple OS")
        }
        let fakeBeta = try XCTUnwrap(ctlRecords.first { $0.bundleId == "com.evil.fakebeta" })
        XCTAssertEqual(scanner.classifyChannel(for: fakeBeta).channel, .developerSideloaded)
        XCTAssertEqual(scanner.evaluateRecord(fakeBeta).riskTier, .caution)
        let gestaltCtl = try XCTUnwrap(ctlRecords.first { $0.bundleId == "com.evil.gestalt" })
        XCTAssertEqual(scanner.evaluateRecord(gestaltCtl).riskTier, .highRisk)
    }

    // MARK: - 3. R1.4 Registry Offline TestFlight Forgery & App Group / Team Verification

    func test_r14_registryOfflineTestFlightForgery_blockedAndUnauthorizedAppleGroupsFlagged() throws {
        let scanner = InstalledAppRegistryScanner.shared

        // Forged offline TestFlight: `"Apple Distribution:"` + `ProfileValidated: true` + `BetaApp: true` + `betaExternalVersionIdentifier` + MetaMask impersonation
        let forgedDistBeta = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "io.metamask.repackaged",
            "CFBundleDisplayName": "MetaMask",
            "ApplicationType": "User",
            "SignerIdentity": "Apple Distribution: Evil Org (EVIL123456)",
            "ProfileValidated": true,
            "BetaApp": true,
            "IsTestFlight": true,
            "betaExternalVersionIdentifier": 12345,
            "iTunesMetadata": ["betaExternalVersionIdentifier": 12345],
            "Entitlements": [
                "application-identifier": "EVIL123456.io.metamask.repackaged",
                "com.apple.developer.team-identifier": "EVIL123456",
                "com.apple.security.application-groups": ["group.tvappservices.container"]
            ]
        ]))
        XCTAssertNil(forgedDistBeta.booleanEntitlements["beta-reports-active"], "Unverified BetaApp/IsTestFlight must not synthesize beta-reports-active")
        let (chan, isFP) = scanner.classifyChannel(for: forgedDistBeta)
        XCTAssertEqual(chan, .enterpriseInHouse)
        XCTAssertFalse(isFP)

        let finding = scanner.evaluateRecord(forgedDistBeta)
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "IMPERSONATION:MetaMask" })
        XCTAssertTrue(finding.indicators.contains { $0.signature == "AppleSystemAppGroup(group.tvappservices.container)" })

        // Unverified Apple TestFlight substring signer must not classify as `.testFlight`
        let spoofSigner = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.example.spoof",
            "ApplicationType": "User",
            "SignerIdentity": "Apple TestFlight Spoof",
            "ProfileValidated": true
        ]))
        XCTAssertNotEqual(scanner.classifyChannel(for: spoofSigner).channel, .testFlight)

        // Leftover `ApplicationDSID` without `SignerIdentity` or `ProfileValidated` must NOT set `isTeamIdWhitelistVerified = true`
        let unsignedWithDSID = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.wqguard.app",
            "ApplicationType": "User",
            "ApplicationDSID": 123456789,
            "Entitlements": [
                "com.apple.developer.team-identifier": "SPOOFTEAM1",
                "com.apple.security.application-groups": ["group.com.wqguard.app"]
            ]
        ]))
        let dsFinding = scanner.evaluateRecord(unsignedWithDSID)
        XCTAssertFalse(dsFinding.evidence.isTeamIdWhitelistVerified)
    }

    // MARK: - 4. R1.3 & R4 Unified Host Self-Whitelisting, ExpandedThreatCatalog, WhitelistEngine, AuditEvidence

    func test_r13_expandedThreatCatalog_whitelistEngine_and_auditEvidenceFailClosed() throws {
        // 1. Unified `isProtectedVictimOrAppleSystemAppGroup`
        let mustBlockGroups = [
            "",
            "   ",
            "group.com.sixdays.trust",
            "group.com.okex.ios",
            "group.com.okinc.okx",
            "group.im.token.app",
            "group.org.consenlabs.token",
            "group.com.tencent.xin",
            "group.com.tencent.wx",
            "group.com.alipay.iphoneclient",
            "group.vip.mytokenpocket",
            "group.com.coinbase.wallet",
            "group.com.bybit.app",
            "group.com.ledger.live",
            "group.so.onekey.app",
            "group.tvappservices.container",
            "group.is.workflow.myactions",
            "group.i\u{043E}.m\u{0435}t\u{0430}m\u{0430}sk", // Cyrillic homoglyphs
            "group.com.\u{0430}pple.keychain", // Cyrillic 'а'
            "group.io.meta\u{200B}mask" // zero-width space
        ]
        for grp in mustBlockGroups {
            XCTAssertTrue(
                ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup(grp),
                "Expected protected/Apple group '\(grp)' to return true"
            )
        }
        for safeGrp in ["group.com.wqguard.app", "group.com.wqguard.scanner", "group.ca628877a97ac6a2.1"] {
            XCTAssertFalse(
                ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup(safeGrp),
                "Legitimate group '\(safeGrp)' must return false"
            )
        }

        // 2. `dangerousWildcardKeychainGroups` preserves `com.pineapple.*` while flagging Apple/nested/homoglyph wildcards
        XCTAssertTrue(
            ExpandedThreatCatalog.dangerousWildcardKeychainGroups(
                ["9NZA6279KY.com.pineapple.*", "9NZA6279KY.*", "LEGACY1234.*"],
                allowedOwnTeamPrefixes: ["9NZA6279KY", "LEGACY1234"]
            ).isEmpty
        )
        let badWildcards = [
            "*",
            "com.apple.*",
            "com.\u{0430}pple.*",
            "*.com.apple.*",
            "9NZA6279KY.com.apple.*",
            "apple.*",
            "9NZA6279KY.apple.*",
            "9NZA6279KY.*.*",
            "9NZA6279KY.com.?.*",
            "OTHERTEAM1.*"
        ]
        for bad in badWildcards {
            XCTAssertEqual(
                ExpandedThreatCatalog.dangerousWildcardKeychainGroups([bad], allowedOwnTeamPrefixes: ["9NZA6279KY"]),
                [bad],
                "Wildcard '\(bad)' must be flagged"
            )
        }
        XCTAssertEqual(
            ExpandedThreatCatalog.dangerousWildcardKeychainGroups(["9NZA6279KY.com.pineapple.*"], allowedOwnTeamPrefixes: []),
            ["9NZA6279KY.com.pineapple.*"],
            "Without verified team prefixes, team wildcard must be flagged"
        )

        // 3. `WhitelistEngine.evaluateFindingWhitelist` rejects `.highRisk` across all depths, rejects ineligible `.fullBinaryAndRegistry`,
        //    rejects distinct `correlatedPackageBundleId`, and rejects `.onDeviceProbe`
        let highRiskFullFinding = ScanFinding(
            bundleId: "com.wqguard.app",
            displayName: "WQGuard",
            version: "1.0",
            teamId: nil,
            bundlePath: "",
            installChannel: .enterpriseInHouse,
            riskTier: .highRisk,
            indicators: [
                ThreatIndicator(signature: IOCTokenArmor.tCqCreate, description: "high", category: "Private API Symbol", location: "LC_SYMTAB", severity: .highRisk)
            ],
            evidence: AuditEvidence(
                matchedSymbols: [IOCTokenArmor.tCqCreate],
                hasAppGroups: true,
                appGroups: ["group.custom.resigned"],
                installChannel: .enterpriseInHouse,
                auditDepth: .fullBinaryAndRegistry,
                isWhitelistEligible: true,
                isTeamIdWhitelistVerified: true
            )
        )
        XCTAssertFalse(
            WhitelistEngine.shared.evaluateFindingWhitelist(highRiskFullFinding, runningSelfBundleId: "com.wqguard.app").isWhitelisted,
            ".highRisk indicator must block self-whitelisting even on .fullBinaryAndRegistry"
        )

        let ineligibleFullFinding = ScanFinding(
            bundleId: "com.wqguard.app",
            displayName: "WQGuard",
            version: "1.0",
            teamId: nil,
            bundlePath: "",
            installChannel: .enterpriseInHouse,
            riskTier: .caution,
            indicators: [
                ThreatIndicator(signature: "dlopen", description: "caution", category: "Dynamic Loading", location: "LC_SYMTAB", severity: .caution)
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["dlopen"],
                hasAppGroups: true,
                appGroups: ["group.custom.resigned"],
                installChannel: .enterpriseInHouse,
                auditDepth: .fullBinaryAndRegistry,
                isWhitelistEligible: false,
                isTeamIdWhitelistVerified: true
            )
        )
        XCTAssertFalse(
            WhitelistEngine.shared.evaluateFindingWhitelist(ineligibleFullFinding, runningSelfBundleId: "com.wqguard.app").isWhitelisted,
            "Standalone .fullBinaryAndRegistry with isWhitelistEligible == false must not self-whitelist"
        )

        let distinctCorrelatedFinding = ScanFinding(
            bundleId: "com.wqguard.app",
            displayName: "WQGuard",
            version: "1.0",
            teamId: nil,
            bundlePath: "",
            installChannel: .enterpriseInHouse,
            riskTier: .caution,
            indicators: [],
            evidence: AuditEvidence(
                matchedSymbols: ["dlopen"],
                hasAppGroups: true,
                appGroups: ["group.custom.resigned"],
                installChannel: .enterpriseInHouse,
                auditDepth: .registryEntitlements,
                correlatedPackageBundleId: "com.wqguard.app.evil",
                isWhitelistEligible: false,
                isTeamIdWhitelistVerified: true
            )
        )
        XCTAssertFalse(
            WhitelistEngine.shared.evaluateFindingWhitelist(distinctCorrelatedFinding, runningSelfBundleId: "com.wqguard.app").isWhitelisted
        )

        let probeDepthFinding = ScanFinding(
            bundleId: "com.wqguard.app",
            displayName: "WQGuard",
            version: "1.0",
            teamId: nil,
            bundlePath: "",
            installChannel: .developerSideloaded,
            riskTier: .caution,
            indicators: [],
            evidence: AuditEvidence(
                matchedSymbols: [],
                hasAppGroups: true,
                appGroups: ["group.custom.resigned"],
                installChannel: .developerSideloaded,
                auditDepth: .onDeviceProbe,
                isWhitelistEligible: false,
                isTeamIdWhitelistVerified: false
            )
        )
        XCTAssertFalse(
            WhitelistEngine.shared.evaluateFindingWhitelist(probeDepthFinding, runningSelfBundleId: "com.wqguard.app").isWhitelisted
        )

        // Custom rule non-Apple App Group check with homoglyphs & `group.tvappservices.container`
        let customWL = WhitelistEngine(tools: [
            WhitelistedTool(
                name: "CustomNoGroupList",
                allowedBundleIds: ["com.example.custom"],
                allowedAppGroups: [],
                isEnabled: true,
                isBuiltIn: false
            )
        ])
        XCTAssertFalse(customWL.isWhitelisted(bundleId: "com.example.custom", appGroups: ["group.tvappservices.container"]).isWhitelisted)
        XCTAssertFalse(customWL.isWhitelisted(bundleId: "com.example.custom", appGroups: ["group.com.\u{0430}pple.safari"]).isWhitelisted)
        XCTAssertTrue(customWL.isWhitelisted(bundleId: "com.example.custom", appGroups: ["group.mycompany.audit"]).isWhitelisted)

        // 4. `AuditEvidence` Codable fail-closed defaults when fields omitted
        let minimalEvidenceJSON = """
        {
          "matchedSymbols": ["dlopen"],
          "linkedDylibs": [],
          "hasAppGroups": true,
          "appGroups": ["group.custom.resigned"],
          "installChannel": "ENTERPRISE_IN_HOUSE",
          "cryptid": 0,
          "isFairPlayEncrypted": false,
          "escapingSymlinks": [],
          "dynamicLoadingPresent": false,
          "pathEnumerationPresent": false,
          "remediationGuidance": "ok"
        }
        """
        let decodedEvidence = try JSONDecoder().decode(AuditEvidence.self, from: Data(minimalEvidenceJSON.utf8))
        XCTAssertEqual(decodedEvidence.auditDepth, .onDeviceProbe)
        XCTAssertFalse(decodedEvidence.isWhitelistEligible)
        XCTAssertFalse(decodedEvidence.isTeamIdWhitelistVerified)
    }

    // MARK: - 5. R2 & R1.3/R1.4 SecurityPipeline & MachOScanner Fixes

    func test_r2_machoScanner_cryptsizeZero_caseInsensitiveFw_and_injectedWhitelist() throws {
        // 1. `cryptid=1, cryptsize=0` (`encryptedRange == nil`): must still inspect plaintext IOC C-strings!
        var cstrData = Data("/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience\0".utf8)
        cstrData.append(contentsOf: Data("com.apple.containermanagerd\0".utf8))
        let zeroCryptsizeMachO = Self.buildMinimalARM64MachO(
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 0,
            cstringPayload: cstrData,
            includeCodeSignature: false
        )
        let customWL = WhitelistEngine(tools: [
            WhitelistedTool(
                name: "InjectedScannerTool",
                allowedBundleIds: ["com.example.injected"],
                allowedAppGroups: ["group.example.injected"],
                expectedSignatures: ["com.apple.containermanagerd", "CVE-2026-65339:MediaExperience.framework"],
                isEnabled: true
            )
        ])
        let scannerDefault = MachOScanner()
        let details = try scannerDefault.parseMachO(data: zeroCryptsizeMachO)
        XCTAssertTrue(details.hasUnencryptedSegments, "cryptid=1, cryptsize=0 must expose plaintext slice buffers")
        XCTAssertTrue(details.textStrings.contains("com.apple.containermanagerd"))
        XCTAssertTrue(details.textStrings.contains("MediaExperience.framework"))

        // Case-insensitive framework matching via zero-allocation byte search (`mediaexperience.framework`)
        let lowerFwData = Data("mediaexperience.framework\0".utf8)
        let lowerFwMachO = Self.buildMinimalARM64MachO(
            cryptid: 0,
            cstringPayload: lowerFwData,
            includeCodeSignature: false
        )
        let lowerDetails = try scannerDefault.parseMachO(data: lowerFwMachO)
        XCTAssertTrue(lowerDetails.textStrings.contains("MediaExperience.framework"))

        // Custom WhitelistEngine injection on MachOScanner + remediation check on non-AppStore cryptid=1
        let ctx = MachOScanner.ScanContext(
            bundleId: "com.example.injected",
            displayName: "Injected",
            version: "1.0",
            installChannel: .developerSideloaded,
            appGroups: ["group.example.injected"]
        )
        let defaultFinding = scannerDefault.scan(details: details, context: ctx)
        XCTAssertEqual(defaultFinding.riskTier, .highRisk)

        let scannerCustom = MachOScanner(whitelistEngine: customWL)
        let customFinding = scannerCustom.scan(details: details, context: ctx)
        XCTAssertEqual(customFinding.riskTier, .knownTool)
        XCTAssertEqual(customFinding.whitelistedToolName, "InjectedScannerTool")

        // Sideloaded cryptid=1 with zero indicators must NOT say "Official App Store / TestFlight package"
        let cleanCryptid1 = Self.buildMinimalARM64MachO(cryptid: 1, cryptoff: 4096, cryptsize: 0, includeCodeSignature: false)
        let cleanDetails = try scannerDefault.parseMachO(data: cleanCryptid1)
        let cleanSideloadCtx = MachOScanner.ScanContext(bundleId: "com.example.clean", installChannel: .developerSideloaded)
        let cleanSideloadFinding = scannerDefault.scan(details: cleanDetails, context: cleanSideloadCtx)
        XCTAssertFalse(cleanSideloadFinding.evidence.remediationGuidance.contains("App Store / TestFlight"))
    }

    func test_r2_securityPipeline_scanBinary_infoPlistSlot1_missingCS_and_customWhitelist() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wq_m2_bin_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        // 1. Valid `__TEXT,__info_plist` matching Special Slot `-1` (without CFBundleIdentifier mismatch)
        let validPlistDict: [String: Any] = ["CFBundleIdentifier": "com.example.slot1ok", "CFBundleVersion": "1.0"]
        let validPlistData = try PropertyListSerialization.data(fromPropertyList: validPlistDict, format: .xml, options: 0)
        let entXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>com.apple.security.application-groups</key><array><string>group.example.slot1ok</string></array></dict></plist>"
        let validBin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            cstringPayload: Data("com.apple.containermanagerd\0".utf8),
            infoPlistData: validPlistData,
            codeDirectoryIdentifier: "com.example.slot1ok",
            xmlEntitlements: entXML,
            includeCodeSignature: true
        )
        let validURL = dir.appendingPathComponent("slot1ok")
        try validBin.write(to: validURL)

        let customWL = WhitelistEngine(tools: [
            WhitelistedTool(
                name: "Slot1Tool",
                allowedBundleIds: ["com.example.slot1ok"],
                allowedAppGroups: ["group.example.slot1ok"],
                expectedSignatures: ["com.apple.containermanagerd"],
                isEnabled: true
            )
        ])
        let customPipeline = SecurityPipeline(whitelistEngine: customWL)
        let validFinding = try customPipeline.scanBinary(at: validURL)
        // Custom whitelist works (not bypassed by WhitelistEngine.shared early return!)
        XCTAssertTrue(validFinding.isWhitelisted, "Custom WhitelistEngine must not be bypassed by early return in scanBinary")
        XCTAssertEqual(validFinding.riskTier, .knownTool)
        // And CodeDirectory/Info.plist Slot -1 passed (check with CSBlobParser directly using exact __info_plist bytes)
        let parsedSlices = try MachOParser.shared.parseAllSlices(data: validBin)
        XCTAssertNil(
            CSBlobParser.shared.verifyBundleInfoPlistBinding(fromSlices: parsedSlices, infoPlistData: validPlistData, plistBundleId: "com.example.slot1ok")
        )

        // 2. Stripped `CFBundleIdentifier` in `__TEXT,__info_plist` while `CodeDirectory.identifier` is set -> must fail binding (`isWhitelistEligible == false`)
        let strippedPlistDict: [String: Any] = ["CFBundleVersion": "1.0"]
        let strippedPlistData = try PropertyListSerialization.data(fromPropertyList: strippedPlistDict, format: .xml, options: 0)
        let strippedBin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            infoPlistData: strippedPlistData,
            codeDirectoryIdentifier: "com.example.slot1ok",
            xmlEntitlements: entXML,
            includeCodeSignature: true
        )
        let strippedURL = dir.appendingPathComponent("stripped")
        try strippedBin.write(to: strippedURL)
        let strippedFinding = try customPipeline.scanBinary(at: strippedURL)
        XCTAssertFalse(strippedFinding.evidence.isWhitelistEligible, "Stripped CFBundleIdentifier in __info_plist must fail binding")

        // 3. `cryptid=1` with missing `LC_CODE_SIGNATURE` must classify as `.developerSideloaded`
        let missingCSBin = Self.buildMinimalARM64MachO(
            cryptid: 1,
            cryptoff: 4096,
            cryptsize: 4096,
            includeCodeSignature: false
        )
        let missingCSURL = dir.appendingPathComponent("missingcs")
        try missingCSBin.write(to: missingCSURL)
        let missingCSFinding = try SecurityPipeline.shared.scanBinary(at: missingCSURL)
        XCTAssertEqual(missingCSFinding.installChannel, .developerSideloaded)
    }

    func test_r2_securityPipeline_scanBundle_frameworkCodeResourcesSeal_and_perBinaryKeychain() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wq_m2_bundle_\(UUID().uuidString)")
        let appURL = dir.appendingPathComponent("TestApp.app")
        let fwURL = appURL.appendingPathComponent("Frameworks/Sealed.framework")
        let fwCSDir = fwURL.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: fwCSDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        // Main app: NO Special Slot -3 (`codeResourcesData: nil`), clean Info.plist
        let appPlist: [String: Any] = [
            "CFBundleIdentifier": "com.example.bundleapp",
            "CFBundleExecutable": "TestApp",
            "CFBundleShortVersionString": "1.0"
        ]
        let appPlistData = try PropertyListSerialization.data(fromPropertyList: appPlist, format: .xml, options: 0)
        try appPlistData.write(to: appURL.appendingPathComponent("Info.plist"))

        let mainMachO = Self.buildMinimalARM64MachO(
            cryptid: 0,
            infoPlistData: appPlistData,
            codeDirectoryIdentifier: "com.example.bundleapp",
            teamIdentifier: "TEAM123456",
            xmlEntitlements: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>com.apple.developer.team-identifier</key><string>TEAM123456</string><key>application-identifier</key><string>TEAM123456.com.example.bundleapp</string></dict></plist>",
            codeResourcesData: nil,
            includeCodeSignature: true
        )
        try mainMachO.write(to: appURL.appendingPathComponent("TestApp"))

        // Embedded framework: HAS Special Slot `-3` sealing `CodeResources`, PLUS tampered `CodeResources` (missing on disk!)
        // and unverified wildcard keychain `TEAM123456.*` (since bundle is not CMS-verified).
        let fwExpectedCR = Data("<plist><dict><key>files2</key><dict/></dict></plist>".utf8)
        let fwEntXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>keychain-access-groups</key><array><string>OTHERTEAM9.*</string></array></dict></plist>"
        let fwMachO = Self.buildMinimalARM64MachO(
            cryptid: 0,
            codeDirectoryIdentifier: "com.example.Sealed",
            xmlEntitlements: fwEntXML,
            codeResourcesData: fwExpectedCR,
            includeCodeSignature: true
        )
        try fwMachO.write(to: fwURL.appendingPathComponent("Sealed"))
        // Write mismatched `CodeResources` bytes to trigger Special Slot -3 mismatch in `verifyBundleCodeResourcesSeal`
        try Data("<plist><dict><key>tampered</key><true/></dict></plist>".utf8).write(to: fwCSDir.appendingPathComponent("CodeResources"))

        let finding = try SecurityPipeline.shared.scanBundle(at: appURL)
        XCTAssertTrue(
            finding.indicators.contains { $0.signature == "keychain-access-groups(*)" && $0.location.contains("Sealed.framework") },
            "Embedded .framework cross-team keychain wildcard must be flagged with per-binary location"
        )
        // Verify directly that `verifyBundleCodeResourcesSeal` catches the tampered framework CodeResources
        let fwSlices = try MachOParser.shared.parseAllSlices(data: fwMachO)
        XCTAssertNotNil(
            CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: fwSlices, bundleURL: fwURL),
            "Tampered .framework CodeResources must fail Special Slot -3 verification"
        )
    }

    func test_r13_r2_correlateAndMerge_channelParity_probeSuppression_and_teamBorrowing() throws {
        // 1. Cross-channel `.appStore` vs `.testFlight` must NEVER merge
        let tfRecord = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.example.dual",
            "CFBundleDisplayName": "DualApp",
            "ApplicationType": "User",
            "SignerIdentity": "TestFlight Beta Distribution",
            "ProfileValidated": true
        ]))
        let appStorePkg = ScanFinding(
            bundleId: "com.example.dual",
            displayName: "DualApp",
            version: "1.0",
            bundlePath: "",
            installChannel: .appStore,
            riskTier: .safe,
            indicators: [],
            evidence: AuditEvidence(installChannel: .appStore, cryptid: 1, isFairPlayEncrypted: true)
        )
        let crossMerge = SecurityPipeline.shared.correlateAndMergeFindings(
            registryRecords: [tfRecord],
            packageFindings: [appStorePkg],
            includeAppStoreApps: true
        )
        XCTAssertEqual(crossMerge.correlatedCount, 0, ".testFlight registry and .appStore package must not cross-merge")
        XCTAssertEqual(crossMerge.findings.count, 2)

        // 2. `.caution` display-name decoy must NOT suppress an active URL-scheme probe hit
        let decoyCautionPkg = ScanFinding(
            bundleId: "com.evil.decoy",
            displayName: "TrollStore",
            version: "1.0",
            bundlePath: "",
            installChannel: .developerSideloaded,
            riskTier: .caution,
            indicators: [
                ThreatIndicator(signature: "dlopen", description: "caution", category: "Dynamic Loading", location: "LC_SYMTAB", severity: .caution)
            ],
            evidence: AuditEvidence(installChannel: .developerSideloaded)
        )
        let trollProbe = ScanFinding(
            bundleId: "com.opa334.TrollStore",
            displayName: "TrollStore",
            version: "Installed",
            bundlePath: "",
            installChannel: .developerSideloaded,
            riskTier: .caution,
            indicators: [
                ThreatIndicator(signature: "URLScheme(trollstore://)", description: "probe", category: "Privileged Environment Tool", location: "canOpenURL", severity: .caution)
            ],
            evidence: AuditEvidence(auditDepth: .onDeviceProbe)
        )
        let probeMerge = SecurityPipeline.shared.correlateAndMergeFindings(
            registryRecords: [],
            packageFindings: [decoyCautionPkg],
            probeFindings: [trollProbe]
        )
        XCTAssertEqual(probeMerge.probeCount, 1, ".caution decoy sharing display name must not silence probe")
        XCTAssertEqual(probeMerge.findings.count, 2)

        // 3. Unsigned/ad-hoc `registry.teamId == nil` must NEVER borrow `package.teamId` to satisfy `allowedTeamIds`
        let teamLockedWL = WhitelistEngine(tools: [
            WhitelistedTool(
                name: "StrictTeamTool",
                allowedBundleIds: ["com.example.strict"],
                allowedAppGroups: ["group.example.strict"],
                allowedTeamIds: ["TEAM123456"],
                expectedSignatures: ["dlopen"],
                isEnabled: true
            )
        ])
        let customPipeline = SecurityPipeline(whitelistEngine: teamLockedWL)
        let unsignedRegRecord = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.example.strict",
            "CFBundleDisplayName": "StrictTool",
            "ApplicationType": "User",
            "SignerIdentity": "Ad Hoc",
            "ProfileValidated": false,
            "Entitlements": [
                "com.apple.security.application-groups": ["group.example.strict"]
            ]
        ]))
        let signedPkg = ScanFinding(
            bundleId: "com.example.strict",
            displayName: "StrictTool",
            version: "1.0",
            teamId: "TEAM123456",
            bundlePath: "",
            installChannel: .enterpriseInHouse,
            riskTier: .caution,
            indicators: [
                ThreatIndicator(signature: "dlopen", description: "caution", category: "Dynamic Loading", location: "LC_SYMTAB", severity: .caution)
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["dlopen"],
                hasAppGroups: true,
                appGroups: ["group.example.strict"],
                installChannel: .enterpriseInHouse,
                isWhitelistEligible: true,
                isTeamIdWhitelistVerified: true
            )
        )
        let borrowMerge = customPipeline.correlateAndMergeFindings(
            registryRecords: [unsignedRegRecord],
            packageFindings: [signedPkg]
        )
        let mergedStrict = try XCTUnwrap(borrowMerge.findings.first)
        XCTAssertFalse(mergedStrict.isWhitelisted, "Ad-hoc/unsigned registry record with nil teamId must not borrow package.teamId")
        XCTAssertEqual(mergedStrict.riskTier, .caution)

        // 4. Merged `.highRisk` finding must not inherit a `.safe` remediation guidance from package
        let highRiskReg = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.example.remediation",
            "ApplicationType": "User",
            "Entitlements": [
                "com.apple.private.security.no-sandbox": true
            ]
        ]))
        let safePkg = ScanFinding(
            bundleId: "com.example.remediation",
            displayName: "Remediation",
            version: "1.0",
            bundlePath: "",
            installChannel: .developerSideloaded,
            riskTier: .safe,
            indicators: [],
            evidence: AuditEvidence(
                installChannel: .developerSideloaded,
                remediationGuidance: "No cross-container sandbox escape indicators detected; safe."
            )
        )
        let remMerge = SecurityPipeline.shared.correlateAndMergeFindings(
            registryRecords: [highRiskReg],
            packageFindings: [safePkg]
        )
        let remFinding = try XCTUnwrap(remMerge.findings.first)
        XCTAssertEqual(remFinding.riskTier, .highRisk)
        XCTAssertFalse(remFinding.evidence.remediationGuidance.contains("safe."))

        // 5. EntitlementGating whitespace trimming
        let trimmedGating = EntitlementGating.evaluate(hasAppGroups: true, appGroups: ["  group.example.trimmed \n", "   "])
        XCTAssertEqual(trimmedGating.appGroups, ["group.example.trimmed"])
        XCTAssertTrue(trimmedGating.shouldProceedToDeepScan)
    }

    // MARK: - 6. M2 Iteration 2 Regression Tests (4 Challenger Findings)

    func test_m2r2_challengerFinding1_nonStagedAndNonSSVPathsRejected_andR4Preserved() throws {
        let scanner = InstalledAppRegistryScanner.shared

        // 1. `/private/preboot/evil/App.app` with `platform-application` + `tcc.allow` (no `no-sandbox`) MUST be rejected
        let prebootEvilPlatform = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Preferences",
            "CFBundleDisplayName": "Settings",
            "ApplicationType": "System",
            "Path": "/private/preboot/evil/App.app",
            "Entitlements": [
                "platform-application": true,
                "com.apple.private.tcc.allow": ["kTCCServicePhotos"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(prebootEvilPlatform))
        let prebootPlatformFindings = scanner.evaluateRecords([prebootEvilPlatform], includeAppStoreApps: true)
        XCTAssertEqual(prebootPlatformFindings.count, 1)
        XCTAssertEqual(prebootPlatformFindings.first?.riskTier, .highRisk)

        // 2. `/private/preboot/evil/Reminders.app` with `no-sandbox` + `group.com.apple.reminders` MUST be rejected
        let prebootEvilReminders = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.reminders",
            "CFBundleDisplayName": "提醒事项",
            "CFBundleShortVersionString": "7.0",
            "ApplicationType": "System",
            "Path": "/private/preboot/evil/Reminders.app",
            "Entitlements": [
                "com.apple.private.security.no-sandbox": true,
                "com.apple.security.application-groups": ["group.com.apple.reminders"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(prebootEvilReminders))
        let prebootRemindersFindings = scanner.evaluateRecords([prebootEvilReminders], includeAppStoreApps: true)
        XCTAssertEqual(prebootRemindersFindings.count, 1)
        XCTAssertEqual(prebootRemindersFindings.first?.riskTier, .highRisk)

        // 3. `/Developer/Applications/Tips.app` & `/tmp/Tips.app` with `platform-application` + `tcc.allow` MUST be rejected
        for badTipsPath in ["/Developer/Applications/Tips.app", "/tmp/Tips.app"] {
            let badTips = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.apple.tips",
                "ApplicationType": "System",
                "Path": badTipsPath,
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.tcc.allow": ["kTCCServicePhotos"]
                ]
            ]))
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(badTips), "Path \(badTipsPath) must be rejected")
            let findings = scanner.evaluateRecords([badTips], includeAppStoreApps: true)
            XCTAssertEqual(findings.count, 1)
            XCTAssertEqual(findings.first?.riskTier, .highRisk)
        }

        // 4. `com.apple.reminders` in non-SSV `/tmp` or signed `Ad Hoc` MUST be rejected
        let remindersInTmpPath = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.reminders",
            "CFBundleShortVersionString": "7.0",
            "ApplicationType": "System",
            "Path": "/tmp/Reminders.app",
            "Entitlements": [
                "com.apple.private.security.no-sandbox": true,
                "platform-application": true,
                "com.apple.security.application-groups": ["group.com.apple.reminders"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(remindersInTmpPath))
        XCTAssertEqual(scanner.evaluateRecords([remindersInTmpPath], includeAppStoreApps: true).first?.riskTier, .highRisk)

        let remindersWithAdHocSigner = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.reminders",
            "CFBundleShortVersionString": "7.0",
            "ApplicationType": "System",
            "SignerIdentity": "Ad Hoc",
            "Path": "/private/var/containers/Bundle/Application/UUID-REM-ADHOC/Reminders.app",
            "Entitlements": [
                "com.apple.private.security.no-sandbox": true,
                "com.apple.security.application-groups": ["group.com.apple.reminders"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(remindersWithAdHocSigner))
        XCTAssertEqual(scanner.evaluateRecords([remindersWithAdHocSigner], includeAppStoreApps: true).first?.riskTier, .highRisk)

        // 5. `/private/preboot/evil/Evil.app` with `IsAppStoreVendable` + `platform-application` + `tcc.allow` MUST be rejected
        let prebootVendableEvil = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.evil",
            "ApplicationType": "System",
            "IsAppStoreVendable": true,
            "Path": "/private/preboot/evil/Evil.app",
            "Entitlements": [
                "platform-application": true,
                "com.apple.private.tcc.allow": ["kTCCServiceSystemPolicyAllFiles"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(prebootVendableEvil))
        XCTAssertEqual(scanner.evaluateRecords([prebootVendableEvil], includeAppStoreApps: true).first?.riskTier, .highRisk)

        // 6. Verify all R4 positive stock controls still pass with 0 findings
        let positiveRecords: [InstalledAppRegistryRecord] = try [
            [
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
            [
                "CFBundleIdentifier": "com.apple.Translate",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-TR/Translate.app",
                "Entitlements": [
                    "com.apple.developer.team-identifier": "96VJNMX6ZP",
                    "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.siri",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-SIRI/Siri.app",
                "Entitlements": ["com.apple.security.application-groups": ["group.tvappservices.container"]]
            ],
            [
                "CFBundleIdentifier": "com.apple.Preferences",
                "ApplicationType": "System",
                "Path": "/Applications/Preferences.app",
                "Entitlements": ["com.apple.security.application-groups": ["group.tvappservices.container"]]
            ],
            [
                "CFBundleIdentifier": "com.apple.campo",
                "ApplicationType": "Hidden",
                "Path": "/private/var/containers/Bundle/Application/UUID-CAMPO/Campo.app",
                "Entitlements": ["com.apple.security.application-groups": ["group.tvappservices.container"]]
            ],
            [
                "CFBundleIdentifier": "com.apple.Spotlight",
                "ApplicationType": "Hidden",
                "Path": "/Applications/Spotlight.app",
                "Entitlements": ["com.apple.security.application-groups": ["group.tvappservices.container"]]
            ],
            [
                "CFBundleIdentifier": "com.apple.Health",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-HEALTH/Health.app",
                "Entitlements": ["platform-application": true]
            ],
            [
                "CFBundleIdentifier": "com.apple.TVRemoteApp",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-TVR/TVRemoteApp.app",
                "Entitlements": ["com.apple.security.application-groups": ["group.com.apple.TVRemote"]]
            ],
            [
                "CFBundleIdentifier": "com.apple.shortcuts",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-SC/Shortcuts.app",
                "Entitlements": ["platform-application": true, "com.apple.security.application-groups": ["group.is.workflow.my.app"]]
            ],
            [
                "CFBundleIdentifier": "com.apple.MobileSMS",
                "ApplicationType": "System",
                "Path": "/Applications/MobileSMS.app",
                "Entitlements": ["platform-application": true, "com.apple.private.security.no-container": true]
            ],
            [
                "CFBundleIdentifier": "com.apple.DocumentsApp",
                "ApplicationType": "System",
                "Path": "/private/var/containers/Bundle/Application/UUID-DOCS/Files.app",
                "Entitlements": ["platform-application": true]
            ],
            [
                "CFBundleIdentifier": "com.shazam.ShazamApp",
                "ApplicationType": "User",
                "SignerIdentity": "Apple iPhone OS Application Signing",
                "ProfileValidated": false,
                "Path": "/private/var/containers/Bundle/Application/UUID-SHAZAM/Shazam.app"
            ],
            [
                "CFBundleIdentifier": "com.apple.FutureStock2026",
                "ApplicationType": "System",
                "IsAppStoreVendable": true,
                "Path": "/private/var/containers/Bundle/Application/UUID-FS26/FutureStock.app",
                "Entitlements": ["platform-application": true, "com.apple.private.tcc.allow": ["kTCCServicePhotos"]]
            ]
        ].map { try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary($0)) }

        for rec in positiveRecords {
            XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(rec), "R4 stock control \(rec.bundleId) must remain accepted")
        }
        XCTAssertTrue(scanner.evaluateRecords(positiveRecords, includeAppStoreApps: true).isEmpty)
    }

    func test_m2r2_challengerFinding2_devicectlTraversalWithDefaultAppFlagRejected() throws {
        let scanner = InstalledAppRegistryScanner.shared
        let devicectlJSON: [String: Any] = [
            "result": [
                "apps": [
                    [
                        "bundleIdentifier": "com.apple.Preferences",
                        "name": "Preferences",
                        "defaultApp": true,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "url": "file:///var/jb/../../Applications/Preferences.app",
                        "entitlements": [
                            "com.apple.private.security.no-sandbox": true
                        ]
                    ],
                    [
                        "bundleIdentifier": "com.apple.tips",
                        "name": "Tips",
                        "defaultApp": false,
                        "internalApp": true,
                        "builtByDeveloper": false,
                        "url": "file:///private/preboot/evil/../../Applications/Tips.app",
                        "entitlements": [
                            "platform-application": true
                        ]
                    ]
                ]
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: devicectlJSON, options: [])
        let records = try scanner.parseSnapshotData(data)
        XCTAssertEqual(records.count, 2)
        for rec in records {
            XCTAssertFalse(rec.hasAppStoreMetadata)
            XCTAssertEqual(rec.applicationType, "User")
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec))
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1)
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk)
        }
    }

    func test_m2r2_challengerFinding3_formatAndZeroWidthOnlyAppGroupsFailClosed() throws {
        let invisibleOnlyGroups = ["\u{FEFF}", "\u{00AD}", "\u{200B}\u{200D}", "\u{2060}", "\u{FEFF} \u{200B}", "\u{0301}"]
        for grp in invisibleOnlyGroups {
            XCTAssertTrue(
                ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup(grp),
                "Invisible/format-only App Group '\(grp.debugDescription)' must fail closed"
            )

            let finding = ScanFinding(
                bundleId: "com.wqguard.app",
                displayName: "WQGuard",
                version: "1.0",
                teamId: nil,
                bundlePath: "",
                installChannel: .enterpriseInHouse,
                riskTier: .caution,
                indicators: [
                    ThreatIndicator(
                        signature: "com.apple.security.application-groups",
                        description: "caution",
                        category: "Shared Container Surface",
                        location: "Entitlements",
                        severity: .caution
                    )
                ],
                evidence: AuditEvidence(
                    matchedSymbols: ["com.apple.security.application-groups"],
                    hasAppGroups: true,
                    appGroups: [grp],
                    installChannel: .enterpriseInHouse,
                    auditDepth: .registryEntitlements,
                    isWhitelistEligible: true,
                    isTeamIdWhitelistVerified: false
                )
            )
            XCTAssertFalse(
                WhitelistEngine.shared.evaluateFindingWhitelist(finding, runningSelfBundleId: "com.wqguard.app").isWhitelisted,
                "WhitelistEngine must reject invisible/format-only App Group"
            )

            let regRecord = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.wqguard.app",
                "CFBundleDisplayName": "WQGuard",
                "ApplicationType": "User",
                "SignerIdentity": "iPhone Distribution: Custom Enterprise",
                "ProfileValidated": true,
                "Entitlements": [
                    "com.apple.security.application-groups": [grp]
                ]
            ]))
            XCTAssertNil(
                InstalledAppRegistryScanner.shared.isEligibleSelfResignedWQGuard(
                    regRecord,
                    provisionalRisk: .caution,
                    matchedSignatures: ["com.apple.security.application-groups"],
                    selfBundleId: "com.wqguard.app"
                ),
                "InstalledAppRegistryScanner self-resigned fallback must reject invisible/format-only App Group"
            )
        }
    }

    func test_m2r2_challengerFinding4_specialSlot1And3TamperingClearsWhitelistEligibility() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wq_m2r2_seal_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let wqEntXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
        <key>application-identifier</key><string>TEAMWQ0001.com.wqguard.app</string>
        <key>com.apple.developer.team-identifier</key><string>TEAMWQ0001</string>
        <key>com.apple.security.application-groups</key><array><string>group.com.wqguard.app</string></array>
        </dict></plist>
        """

        // 1. `scanBinary`: untampered `com.wqguard.app` positive control vs Special Slot `-1` tampered `__TEXT,__info_plist`
        let cleanBinPlist = Data("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.wqguard.app</string><key>CFBundleVersion</key><string>1.0.0</string></dict></plist>".utf8)
        let cleanBin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            cstringPayload: Data("com.apple.containermanagerd\0".utf8),
            infoPlistData: cleanBinPlist,
            codeDirectoryIdentifier: "com.wqguard.app",
            xmlEntitlements: wqEntXML,
            includeCodeSignature: true
        )
        let cleanBinURL = dir.appendingPathComponent("wq_clean")
        try cleanBin.write(to: cleanBinURL)
        let cleanBinFinding = try SecurityPipeline.shared.scanBinary(at: cleanBinURL)
        XCTAssertTrue(cleanBinFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(cleanBinFinding.isWhitelisted)
        XCTAssertEqual(cleanBinFinding.riskTier, .knownTool)

        // Tamper `__TEXT,__info_plist` bytes in-place (`1.0.0` -> `9.9.9`) while keeping `CFBundleIdentifier == "com.wqguard.app"`
        var tamperedBin = cleanBin
        let needle = Data("1.0.0".utf8)
        let patchRange = try XCTUnwrap(tamperedBin.range(of: needle))
        tamperedBin.replaceSubrange(patchRange, with: Data("9.9.9".utf8))
        let tamperedBinURL = dir.appendingPathComponent("wq_tampered_slot1")
        try tamperedBin.write(to: tamperedBinURL)
        let tamperedBinFinding = try SecurityPipeline.shared.scanBinary(at: tamperedBinURL)
        XCTAssertFalse(tamperedBinFinding.evidence.isWhitelistEligible)
        XCTAssertFalse(tamperedBinFinding.isWhitelisted)
        XCTAssertEqual(tamperedBinFinding.riskTier, .highRisk)
        XCTAssertTrue(tamperedBinFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })
        XCTAssertFalse(
            WhitelistEngine.shared.evaluateFindingWhitelist(tamperedBinFinding, runningSelfBundleId: "com.wqguard.app").isWhitelisted
        )

        // 2. `scanBundle`: Special Slot `-1` (`Info.plist` tampered on disk) on `WQGuard.app`
        let slot1BundleURL = dir.appendingPathComponent("WQGuardSlot1.app")
        try FileManager.default.createDirectory(at: slot1BundleURL, withIntermediateDirectories: true)
        let sealedBundlePlist: [String: Any] = [
            "CFBundleIdentifier": "com.wqguard.app",
            "CFBundleExecutable": "WQGuard",
            "CFBundleShortVersionString": "1.0"
        ]
        let sealedBundlePlistData = try PropertyListSerialization.data(fromPropertyList: sealedBundlePlist, format: .xml, options: 0)
        let tamperedBundlePlist: [String: Any] = [
            "CFBundleIdentifier": "com.wqguard.app",
            "CFBundleExecutable": "WQGuard",
            "CFBundleShortVersionString": "9.9"
        ]
        let tamperedBundlePlistData = try PropertyListSerialization.data(fromPropertyList: tamperedBundlePlist, format: .xml, options: 0)
        try tamperedBundlePlistData.write(to: slot1BundleURL.appendingPathComponent("Info.plist"))
        let slot1MainBin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            cstringPayload: Data("com.apple.containermanagerd\0".utf8),
            infoPlistData: sealedBundlePlistData,
            codeDirectoryIdentifier: "com.wqguard.app",
            xmlEntitlements: wqEntXML,
            includeCodeSignature: true
        )
        try slot1MainBin.write(to: slot1BundleURL.appendingPathComponent("WQGuard"))

        let slot1BundleFinding = try SecurityPipeline.shared.scanBundle(at: slot1BundleURL)
        XCTAssertFalse(slot1BundleFinding.evidence.isWhitelistEligible)
        XCTAssertFalse(slot1BundleFinding.isWhitelisted)
        XCTAssertEqual(slot1BundleFinding.riskTier, .highRisk)
        XCTAssertTrue(slot1BundleFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })

        // 3. `scanBundle`: Special Slot `-3` (`_CodeSignature/CodeResources` tampered on disk) on `WQGuard.app`
        let slot3BundleURL = dir.appendingPathComponent("WQGuardSlot3.app")
        let slot3CSDir = slot3BundleURL.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: slot3CSDir, withIntermediateDirectories: true)
        try sealedBundlePlistData.write(to: slot3BundleURL.appendingPathComponent("Info.plist"))
        let expectedCR = Data("<plist><dict><key>files2</key><dict/></dict></plist>".utf8)
        let tamperedCR = Data("<plist><dict><key>tampered</key><true/></dict></plist>".utf8)
        try tamperedCR.write(to: slot3CSDir.appendingPathComponent("CodeResources"))
        let slot3MainBin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            cstringPayload: Data("com.apple.containermanagerd\0".utf8),
            infoPlistData: sealedBundlePlistData,
            codeDirectoryIdentifier: "com.wqguard.app",
            xmlEntitlements: wqEntXML,
            codeResourcesData: expectedCR,
            includeCodeSignature: true
        )
        try slot3MainBin.write(to: slot3BundleURL.appendingPathComponent("WQGuard"))

        let slot3BundleFinding = try SecurityPipeline.shared.scanBundle(at: slot3BundleURL)
        XCTAssertFalse(slot3BundleFinding.evidence.isWhitelistEligible)
        XCTAssertFalse(slot3BundleFinding.isWhitelisted)
        XCTAssertEqual(slot3BundleFinding.riskTier, .highRisk)
        XCTAssertTrue(slot3BundleFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })
        XCTAssertFalse(
            WhitelistEngine.shared.evaluateFindingWhitelist(slot3BundleFinding, runningSelfBundleId: "com.wqguard.app").isWhitelisted
        )
    }

    // MARK: - 7. M2 Iteration 3 Regression Tests (3 Reviewer 2 Findings)

    func test_m2r3_finding1_combiningMarksAndNonIdentifiersInAppGroupsFailClosed() throws {
        // 1. Decomposed combining marks, precomposed accented Latin vowels, enclosing marks, and control scalars must fail closed (`true`)
        let maliciousGroups = [
            "group.io.me\u{0301}tamask",
            "group.com.a\u{0301}pple.wallet",
            "group.io.m\u{00E9}tamask",
            "group.com.\u{00E1}pple.wallet",
            "\u{20DD}",
            "\u{0001}",
            "group.com.wqguard.\u{20DD}app",
            "group.com.wqguard.\u{0001}app"
        ]
        for grp in maliciousGroups {
            XCTAssertTrue(
                ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup(grp),
                "Combining-mark/control/enclosing App Group '\(grp.debugDescription)' must fail closed"
            )

            let regRecord = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.wqguard.app",
                "CFBundleDisplayName": "WQGuard",
                "ApplicationType": "User",
                "SignerIdentity": "iPhone Distribution: Custom Enterprise",
                "ProfileValidated": true,
                "Entitlements": [
                    "com.apple.security.application-groups": [grp]
                ]
            ]))
            XCTAssertNil(
                InstalledAppRegistryScanner.shared.isEligibleSelfResignedWQGuard(
                    regRecord,
                    provisionalRisk: .caution,
                    matchedSignatures: ["com.apple.security.application-groups"],
                    selfBundleId: "com.wqguard.app"
                ),
                "Self-resigned WQGuard must reject App Group '\(grp.debugDescription)'"
            )

            let finding = ScanFinding(
                bundleId: "com.wqguard.app",
                displayName: "WQGuard",
                version: "1.0",
                teamId: nil,
                bundlePath: "",
                installChannel: .enterpriseInHouse,
                riskTier: .caution,
                indicators: [
                    ThreatIndicator(
                        signature: "com.apple.security.application-groups",
                        description: "caution",
                        category: "Shared Container Surface",
                        location: "Entitlements",
                        severity: .caution
                    )
                ],
                evidence: AuditEvidence(
                    matchedSymbols: ["com.apple.security.application-groups"],
                    hasAppGroups: true,
                    appGroups: [grp],
                    installChannel: .enterpriseInHouse,
                    auditDepth: .registryEntitlements,
                    isWhitelistEligible: true,
                    isTeamIdWhitelistVerified: false
                )
            )
            XCTAssertFalse(
                WhitelistEngine.shared.evaluateFindingWhitelist(finding, runningSelfBundleId: "com.wqguard.app").isWhitelisted,
                "WhitelistEngine must reject App Group '\(grp.debugDescription)'"
            )
        }

        // 2. Legitimate WQGuard & non-victim groups remain allowed (`false`) and self-whitelisted
        for safeGrp in ["group.com.wqguard.app", "group.com.wqguard.scanner", "group.ca628877a97ac6a2.1"] {
            XCTAssertFalse(
                ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup(safeGrp),
                "Legitimate group '\(safeGrp)' must remain false"
            )
            let regRecord = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.wqguard.app",
                "CFBundleDisplayName": "WQGuard",
                "ApplicationType": "User",
                "SignerIdentity": "iPhone Distribution: Custom Enterprise",
                "ProfileValidated": true,
                "Entitlements": [
                    "com.apple.security.application-groups": [safeGrp]
                ]
            ]))
            XCTAssertEqual(
                InstalledAppRegistryScanner.shared.isEligibleSelfResignedWQGuard(
                    regRecord,
                    provisionalRisk: .caution,
                    matchedSignatures: ["com.apple.security.application-groups"],
                    selfBundleId: "com.wqguard.app"
                ),
                "WQGuard"
            )
        }

        // 3. CJK brand impersonation remains intact after NFKD + combining-mark folding
        XCTAssertFalse(
            ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: "com.fake.wallet",
                displayName: "欧易OKX多开",
                installChannel: .developerSideloaded,
                cryptid: 0
            ).isEmpty
        )
        XCTAssertTrue(ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup("group.com.微信.clone"))
    }

    func test_m2r3_finding2_scanBundle_appexMaskedSlot3_frameworkSlot1_and_mainZeroSlot1PlusSlot3() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wq_m2r3_seal_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let wqEntXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
        <key>application-identifier</key><string>TEAMWQ0001.com.wqguard.app</string>
        <key>com.apple.developer.team-identifier</key><string>TEAMWQ0001</string>
        <key>com.apple.security.application-groups</key><array><string>group.com.wqguard.app</string></array>
        </dict></plist>
        """
        let mainPlist: [String: Any] = [
            "CFBundleIdentifier": "com.wqguard.app",
            "CFBundleExecutable": "WQGuard",
            "CFBundleShortVersionString": "1.0"
        ]
        let mainPlistData = try PropertyListSerialization.data(fromPropertyList: mainPlist, format: .xml, options: 0)
        let mainCleanBin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            cstringPayload: Data("com.apple.containermanagerd\0".utf8),
            infoPlistData: mainPlistData,
            codeDirectoryIdentifier: "com.wqguard.app",
            xmlEntitlements: wqEntXML,
            includeCodeSignature: true
        )
        let expectedCR = Data("<plist><dict><key>files2</key><dict/></dict></plist>".utf8)
        let tamperedCR = Data("<plist><dict><key>tampered</key><true/></dict></plist>".utf8)

        // (a) Embedded `.appex` with tampered Special Slot `-3` + nested ad-hoc `.dylib` (masks `bundleSigTrust`)
        let appexCaseURL = dir.appendingPathComponent("AppexMaskedSeal.app")
        let appexURL = appexCaseURL.appendingPathComponent("PlugIns/Ext.appex")
        let appexCSDir = appexURL.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: appexCSDir, withIntermediateDirectories: true)
        try mainPlistData.write(to: appexCaseURL.appendingPathComponent("Info.plist"))
        try mainCleanBin.write(to: appexCaseURL.appendingPathComponent("WQGuard"))

        let extPlist: [String: Any] = [
            "CFBundleIdentifier": "com.wqguard.app.ext",
            "CFBundleExecutable": "Ext",
            "CFBundleShortVersionString": "1.0"
        ]
        let extPlistData = try PropertyListSerialization.data(fromPropertyList: extPlist, format: .xml, options: 0)
        try extPlistData.write(to: appexURL.appendingPathComponent("Info.plist"))
        try tamperedCR.write(to: appexCSDir.appendingPathComponent("CodeResources"))
        let extBin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            infoPlistData: extPlistData,
            codeDirectoryIdentifier: "com.wqguard.app.ext",
            codeResourcesData: expectedCR,
            includeCodeSignature: true
        )
        try extBin.write(to: appexURL.appendingPathComponent("Ext"))
        let nestedAdhocDylib = Self.buildMinimalARM64MachO(
            cryptid: 0,
            codeDirectoryIdentifier: "com.wqguard.app.ext.helper",
            includeCodeSignature: true
        )
        try nestedAdhocDylib.write(to: appexURL.appendingPathComponent("Helper.dylib"))

        let appexFinding = try SecurityPipeline.shared.scanBundle(at: appexCaseURL)
        XCTAssertEqual(appexFinding.riskTier, .highRisk)
        XCTAssertFalse(appexFinding.isWhitelisted)
        XCTAssertFalse(appexFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(appexFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })

        // (b) Embedded `.framework` with tampered Special Slot `-1` (`Info.plist`)
        let fwCaseURL = dir.appendingPathComponent("FrameworkSlot1.app")
        let fwURL = fwCaseURL.appendingPathComponent("Frameworks/Helper.framework")
        try FileManager.default.createDirectory(at: fwURL, withIntermediateDirectories: true)
        try mainPlistData.write(to: fwCaseURL.appendingPathComponent("Info.plist"))
        try mainCleanBin.write(to: fwCaseURL.appendingPathComponent("WQGuard"))

        let sealedFwPlist: [String: Any] = [
            "CFBundleIdentifier": "com.wqguard.helper",
            "CFBundleExecutable": "Helper",
            "CFBundleShortVersionString": "1.0"
        ]
        let tamperedFwPlist: [String: Any] = [
            "CFBundleIdentifier": "com.wqguard.helper",
            "CFBundleExecutable": "Helper",
            "CFBundleShortVersionString": "9.9"
        ]
        let sealedFwPlistData = try PropertyListSerialization.data(fromPropertyList: sealedFwPlist, format: .xml, options: 0)
        let tamperedFwPlistData = try PropertyListSerialization.data(fromPropertyList: tamperedFwPlist, format: .xml, options: 0)
        try tamperedFwPlistData.write(to: fwURL.appendingPathComponent("Info.plist"))
        let fwBin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            infoPlistData: sealedFwPlistData,
            codeDirectoryIdentifier: "com.wqguard.helper",
            includeCodeSignature: true
        )
        try fwBin.write(to: fwURL.appendingPathComponent("Helper"))

        let fwFinding = try SecurityPipeline.shared.scanBundle(at: fwCaseURL)
        XCTAssertEqual(fwFinding.riskTier, .highRisk)
        XCTAssertFalse(fwFinding.isWhitelisted)
        XCTAssertFalse(fwFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(fwFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })

        // (c) Main bundle with `cdIdent != Info.plist` + zeroed Special Slot `-1` + tampered Special Slot `-3`
        let mainZeroSlot1CaseURL = dir.appendingPathComponent("MainZeroSlot1AndSlot3.app")
        let mainCSDir = mainZeroSlot1CaseURL.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: mainCSDir, withIntermediateDirectories: true)
        let cleanAppPlist: [String: Any] = [
            "CFBundleIdentifier": "com.example.cleanapp",
            "CFBundleExecutable": "CleanApp",
            "CFBundleShortVersionString": "1.0"
        ]
        let cleanAppPlistData = try PropertyListSerialization.data(fromPropertyList: cleanAppPlist, format: .xml, options: 0)
        try cleanAppPlistData.write(to: mainZeroSlot1CaseURL.appendingPathComponent("Info.plist"))
        try tamperedCR.write(to: mainCSDir.appendingPathComponent("CodeResources"))
        let mainZeroSlot1Bin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            infoPlistData: nil, // leaves Special Slot -1 zeroed while CodeDirectory.identifier != Info.plist
            codeDirectoryIdentifier: "com.example.differentident",
            codeResourcesData: expectedCR,
            includeCodeSignature: true
        )
        try mainZeroSlot1Bin.write(to: mainZeroSlot1CaseURL.appendingPathComponent("CleanApp"))

        let mainZeroFinding = try SecurityPipeline.shared.scanBundle(at: mainZeroSlot1CaseURL)
        XCTAssertEqual(mainZeroFinding.riskTier, .highRisk)
        XCTAssertFalse(mainZeroFinding.isWhitelisted)
        XCTAssertFalse(mainZeroFinding.evidence.isWhitelistEligible)
        XCTAssertTrue(mainZeroFinding.indicators.contains { $0.signature == "CODE_SIGNATURE_SEAL_MISMATCH" && $0.severity == .highRisk })
    }

    func test_m2r3_finding3_lexicalDotAndSlashDeveloperTraversalRejected() throws {
        let scanner = InstalledAppRegistryScanner.shared
        let bypassCases: [(bid: String, url: String)] = [
            ("com.apple.Preferences", "file:///./Developer/../../Applications/Preferences.app"),
            ("com.apple.tips", "file://///Developer/../../Applications/Preferences.app"),
            ("com.apple.mobilesafari", "file:///var/./jb/../../Applications/Preferences.app"),
            ("com.apple.mobilemail", "file:///private/preboot/Cryptexes/../../../Applications/Preferences.app")
        ]
        let appsArray: [[String: Any]] = bypassCases.enumerated().map { idx, item in
            [
                "bundleIdentifier": item.bid,
                "name": "Stock\(idx)",
                "defaultApp": true,
                "internalApp": false,
                "builtByDeveloper": false,
                "url": item.url,
                "entitlements": [
                    "com.apple.private.security.no-sandbox": true
                ]
            ]
        }
        let devicectlJSON: [String: Any] = ["result": ["apps": appsArray]]
        let data = try JSONSerialization.data(withJSONObject: devicectlJSON, options: [])
        let records = try scanner.parseSnapshotData(data)
        XCTAssertEqual(records.count, bypassCases.count)
        for rec in records {
            XCTAssertFalse(rec.hasAppStoreMetadata, "Traversal path '\(rec.bundlePath)' must not inherit AppStore metadata")
            XCTAssertEqual(rec.applicationType, "User", "Traversal path '\(rec.bundlePath)' must downgrade to User")
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "Traversal path '\(rec.bundlePath)' must not be treated as Apple system")
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1)
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk)
        }

        // Direct `fromDictionary` with System ApplicationType & `/./Developer/...` / `///Developer/...` paths
        let dictPaths = [
            "/./Developer/../../Applications/Preferences.app",
            "///Developer/../../Applications/Preferences.app",
            "/var/./jb/../../Applications/Preferences.app",
            "/private/preboot/Cryptexes/../../../Applications/Preferences.app"
        ]
        for badPath in dictPaths {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.apple.Preferences",
                "ApplicationType": "System",
                "Path": badPath,
                "Entitlements": [
                    "com.apple.private.security.no-sandbox": true
                ]
            ]))
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "fromDictionary path '\(badPath)' must be rejected")
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1)
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk)
        }

        // Positive control: R4 stock app with trailing / double slashes remains accepted
        let cleanDoubleSlash = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Preferences",
            "ApplicationType": "System",
            "Path": "/private/var//containers/Bundle/Application/UUID-PREF/Preferences.app/",
            "Entitlements": [
                "com.apple.security.application-groups": ["group.tvappservices.container"]
            ]
        ]))
        XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(cleanDoubleSlash))
        XCTAssertTrue(scanner.evaluateRecords([cleanDoubleSlash], includeAppStoreApps: true).isEmpty)
    }

    // MARK: - 6. M2 Iteration 4 Remediation Regression Tests (Findings 1–4)

    func test_m2r4_finding1_devicectlOwnTeamKeychainWildcardsPreservedAndBadWildcardsFlagged() throws {
        let scanner = InstalledAppRegistryScanner.shared

        let devicectlJSON: [String: Any] = [
            "result": [
                "apps": [
                    // Genuine App Store Weibo (`fromAppStore: true`) with own-team & legacy prefix keychain wildcards
                    [
                        "bundleIdentifier": "com.sina.weibo",
                        "name": "Weibo",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "fromAppStore": true,
                        "teamIdentifier": "ABCDE12345",
                        "url": "file:///private/var/containers/Bundle/Application/UUID-WEIBO/Weibo.app",
                        "entitlements": [
                            "application-identifier": "LEGACY1234.com.sina.weibo",
                            "com.apple.developer.team-identifier": "ABCDE12345",
                            "keychain-access-groups": ["ABCDE12345.*", "ABCDE12345.com.sina.weibo.*", "LEGACY1234.*"]
                        ]
                    ],
                    // Genuine App Store Lokey (`fromAppStore` omitted) with own-team keychain wildcard
                    [
                        "bundleIdentifier": "com.lokey.app",
                        "name": "Lokey",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "teamIdentifier": "LOKEY12345",
                        "url": "file:///private/var/containers/Bundle/Application/UUID-LOKEY/Lokey.app",
                        "entitlements": [
                            "application-identifier": "LOKEY12345.com.lokey.app",
                            "com.apple.developer.team-identifier": "LOKEY12345",
                            "keychain-access-groups": ["LOKEY12345.*"]
                        ]
                    ],
                    // Developer-signed Erosion (`builtByDeveloper: true`) with own-team keychain wildcard
                    [
                        "bundleIdentifier": "com.erosion.tool",
                        "name": "Erosion",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": true,
                        "teamIdentifier": "EROSION123",
                        "url": "file:///private/var/containers/Bundle/Application/UUID-EROSION/Erosion.app",
                        "entitlements": [
                            "application-identifier": "EROSION123.com.erosion.tool",
                            "com.apple.developer.team-identifier": "EROSION123",
                            "keychain-access-groups": ["EROSION123.*"]
                        ]
                    ],
                    // Negative 1: Universal `"*"` wildcard
                    [
                        "bundleIdentifier": "com.evil.star",
                        "name": "EvilStar",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "fromAppStore": true,
                        "teamIdentifier": "ABCDE12345",
                        "url": "file:///private/var/containers/Bundle/Application/UUID-STAR/EvilStar.app",
                        "entitlements": [
                            "keychain-access-groups": ["*"]
                        ]
                    ],
                    // Negative 2: Apple-targeted `"com.apple.*"` wildcard
                    [
                        "bundleIdentifier": "com.evil.applekc",
                        "name": "EvilAppleKC",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "fromAppStore": true,
                        "teamIdentifier": "ABCDE12345",
                        "url": "file:///private/var/containers/Bundle/Application/UUID-APKC/EvilAppleKC.app",
                        "entitlements": [
                            "keychain-access-groups": ["com.apple.*"]
                        ]
                    ],
                    // Negative 3: Cross-team wildcard
                    [
                        "bundleIdentifier": "com.evil.crossteam",
                        "name": "EvilCrossTeam",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "fromAppStore": true,
                        "teamIdentifier": "ABCDE12345",
                        "url": "file:///private/var/containers/Bundle/Application/UUID-CROSS/EvilCross.app",
                        "entitlements": [
                            "keychain-access-groups": ["OTHER99999.*"]
                        ]
                    ],
                    // Negative 4: Ad-hoc flag with own-team wildcard
                    [
                        "bundleIdentifier": "com.evil.adhoc",
                        "name": "EvilAdHoc",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "adHoc": true,
                        "teamIdentifier": "ABCDE12345",
                        "url": "file:///private/var/containers/Bundle/Application/UUID-ADHOC/EvilAdHoc.app",
                        "entitlements": [
                            "keychain-access-groups": ["ABCDE12345.*"]
                        ]
                    ],
                    // Negative 5: Explicit ldid signer with own-team wildcard
                    [
                        "bundleIdentifier": "com.evil.ldid",
                        "name": "EvilLdid",
                        "defaultApp": false,
                        "internalApp": false,
                        "builtByDeveloper": false,
                        "signerIdentity": "ldid",
                        "teamIdentifier": "ABCDE12345",
                        "url": "file:///private/var/containers/Bundle/Application/UUID-LDID/EvilLdid.app",
                        "entitlements": [
                            "keychain-access-groups": ["ABCDE12345.*"]
                        ]
                    ]
                ]
            ]
        ]
        let ctlData = try JSONSerialization.data(withJSONObject: devicectlJSON, options: [])
        let records = try scanner.parseSnapshotData(ctlData)
        XCTAssertEqual(records.count, 8)

        let weibo = try XCTUnwrap(records.first { $0.bundleId == "com.sina.weibo" })
        XCTAssertTrue(weibo.hasAppStoreMetadata)
        XCTAssertEqual(scanner.classifyChannel(for: weibo).channel, .appStore)
        let weiboEval = scanner.evaluateRecord(weibo)
        XCTAssertEqual(weiboEval.riskTier, .safe)
        XCTAssertTrue(weiboEval.indicators.isEmpty, "App Store Weibo own-team KC wildcard must have 0 indicators")

        let lokey = try XCTUnwrap(records.first { $0.bundleId == "com.lokey.app" })
        XCTAssertTrue(lokey.hasAppStoreMetadata)
        XCTAssertEqual(scanner.classifyChannel(for: lokey).channel, .appStore)
        let lokeyEval = scanner.evaluateRecord(lokey)
        XCTAssertEqual(lokeyEval.riskTier, .safe)
        XCTAssertTrue(lokeyEval.indicators.isEmpty, "App Store Lokey own-team KC wildcard must have 0 indicators")

        let erosion = try XCTUnwrap(records.first { $0.bundleId == "com.erosion.tool" })
        XCTAssertEqual(scanner.classifyChannel(for: erosion).channel, .developerSideloaded)
        let erosionEval = scanner.evaluateRecord(erosion)
        XCTAssertEqual(erosionEval.riskTier, .safe)
        XCTAssertTrue(erosionEval.indicators.isEmpty, "Developer-signed Erosion own-team KC wildcard must have 0 indicators")

        for badBid in ["com.evil.star", "com.evil.applekc", "com.evil.crossteam", "com.evil.adhoc", "com.evil.ldid"] {
            let badRec = try XCTUnwrap(records.first { $0.bundleId == badBid })
            XCTAssertFalse(badRec.hasAppStoreMetadata, "\(badBid) must strip AppStore metadata")
            let badEval = scanner.evaluateRecord(badRec)
            XCTAssertEqual(badEval.riskTier, .highRisk, "\(badBid) must evaluate as .highRisk")
            XCTAssertTrue(
                badEval.indicators.contains { $0.signature == "keychain-access-groups(*)" && $0.severity == .highRisk },
                "\(badBid) must flag keychain-access-groups(*)"
            )
        }
    }

    func test_m2r4_finding2_separatorsFillersConfusablesAndStrictASCIIEnforcedInSelfWhitelist() throws {
        let scanner = InstalledAppRegistryScanner.shared
        let whitelist = WhitelistEngine.shared

        let hostileAppGroups = [
            "\u{3164}",
            "\u{2800}",
            "group.io.meta\u{3164}mask",
            "group.io.meta\u{FFA0}mask",
            "group.io.meta\u{180E}mask",
            "group.io.me\u{2028}tamask",
            "group.io.me\u{2029}tamask",
            "group.io.me\u{00A0}tamask",
            "group.io.me\u{3000}tamask",
            "group.io.me tamask",
            "group.com.a\u{2028}pple.wallet",
            "group.io.m\u{1D07}tamask",
            "group.io.\u{1D0D}etamask",
            "group.com.\u{1D00}pple.wallet",
            "group.io.\u{00B5}etamask",
            "group.com.\u{13AA}pple.wallet",
            "group.com.wqguard .app",
            "group.pua\u{E000}.app"
        ]

        for badGrp in hostileAppGroups {
            XCTAssertTrue(
                ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup(badGrp),
                "Expected separator/filler/confusable group '\(badGrp)' to fail closed"
            )
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.wqguard.app",
                "CFBundleDisplayName": "WQGuard",
                "ApplicationType": "User",
                "SignerIdentity": "iPhone Distribution: Third Party",
                "ProfileValidated": true,
                "Entitlements": [
                    "com.apple.security.application-groups": [badGrp]
                ]
            ]))
            XCTAssertNil(
                scanner.isEligibleSelfResignedWQGuard(
                    rec,
                    provisionalRisk: .caution,
                    matchedSignatures: ["com.apple.security.application-groups"],
                    selfBundleId: "com.wqguard.app"
                ),
                "isEligibleSelfResignedWQGuard must reject '\(badGrp)'"
            )
            let evaluated = scanner.evaluateRecord(rec)
            let wlRes = whitelist.evaluateFindingWhitelist(evaluated, runningSelfBundleId: "com.wqguard.app")
            XCTAssertFalse(wlRes.isWhitelisted, "evaluateFindingWhitelist must reject '\(badGrp)'")
            XCTAssertNil(wlRes.toolName)
        }

        // Unmapped benign-looking non-ASCII identifier must also fail self-whitelisting due to strict ASCII check
        let nonAsciiBenign = "group.com.中文.wqguard"
        let nonAsciiRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.wqguard.app",
            "CFBundleDisplayName": "WQGuard",
            "ApplicationType": "User",
            "SignerIdentity": "iPhone Distribution: Third Party",
            "ProfileValidated": true,
            "Entitlements": [
                "com.apple.security.application-groups": [nonAsciiBenign]
            ]
        ]))
        XCTAssertNil(
            scanner.isEligibleSelfResignedWQGuard(
                nonAsciiRec,
                provisionalRisk: .caution,
                matchedSignatures: ["com.apple.security.application-groups"],
                selfBundleId: "com.wqguard.app"
            )
        )
        let nonAsciiEval = scanner.evaluateRecord(nonAsciiRec)
        XCTAssertFalse(whitelist.evaluateFindingWhitelist(nonAsciiEval, runningSelfBundleId: "com.wqguard.app").isWhitelisted)

        // Positive CJK victim control
        XCTAssertTrue(ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup("group.com.微信.clone"))

        // Positive host controls
        for safeGrp in ["group.com.wqguard.app", "group.com.wqguard.scanner", "group.ca628877a97ac6a2.1"] {
            XCTAssertFalse(ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup(safeGrp))
            let okRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.wqguard.app",
                "CFBundleDisplayName": "WQGuard",
                "ApplicationType": "User",
                "SignerIdentity": "iPhone Distribution: Third Party",
                "ProfileValidated": true,
                "Entitlements": [
                    "com.apple.security.application-groups": [safeGrp]
                ]
            ]))
            XCTAssertEqual(
                scanner.isEligibleSelfResignedWQGuard(
                    okRec,
                    provisionalRisk: .caution,
                    matchedSignatures: ["com.apple.security.application-groups"],
                    selfBundleId: "com.wqguard.app"
                ),
                "WQGuard"
            )
            let okEval = scanner.evaluateRecord(okRec)
            let wlOk = whitelist.evaluateFindingWhitelist(okEval, runningSelfBundleId: "com.wqguard.app")
            XCTAssertTrue(wlOk.isWhitelisted, "Positive host control '\(safeGrp)' must remain self-whitelisted")
            XCTAssertEqual(wlOk.toolName, "WQGuard")
        }
    }

    func test_m2r4_finding3_nilTeamIdNonAdHocRegistryCannotBorrowPackageTeamId() throws {
        let customWL = WhitelistEngine(tools: [
            WhitelistedTool(
                name: "TeamLockedTool",
                allowedBundleIds: ["com.example.teamtool"],
                allowedAppGroups: [],
                allowedTeamIds: ["TEAM123456"],
                expectedSignatures: ["container_query_create"]
            )
        ])
        let customPipeline = SecurityPipeline(whitelistEngine: customWL)

        // Non-adhoc `SignerIdentity` ("iPhone Distribution: Evil Corp") with `teamId == nil`
        let evilDistNilTeamReg = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.example.teamtool",
            "CFBundleDisplayName": "TeamTool",
            "ApplicationType": "User",
            "SignerIdentity": "iPhone Distribution: Evil Corp",
            "ProfileValidated": true,
            "Entitlements": [
                "com.apple.security.application-groups": ["group.com.evil"]
            ]
        ]))
        XCTAssertNil(evilDistNilTeamReg.teamId)

        let signedPkg = ScanFinding(
            bundleId: "com.example.teamtool",
            displayName: "TeamTool",
            version: "1.0",
            teamId: "TEAM123456",
            bundlePath: "/tmp/TeamTool.ipa",
            installChannel: .enterpriseInHouse,
            riskTier: .caution,
            indicators: [
                ThreatIndicator(signature: "container_query_create", description: "caution", category: "Dynamic", location: "MachO", severity: .caution)
            ],
            evidence: AuditEvidence(
                matchedSymbols: ["container_query_create"],
                hasAppGroups: true,
                appGroups: ["group.com.evil"],
                installChannel: .enterpriseInHouse,
                isWhitelistEligible: true,
                isTeamIdWhitelistVerified: true
            )
        )

        let merged = customPipeline.correlateAndMergeFindings(
            registryRecords: [evilDistNilTeamReg],
            packageFindings: [signedPkg]
        )
        let finding = try XCTUnwrap(merged.findings.first)
        XCTAssertFalse(finding.isWhitelisted, "nil-teamId non-adhoc registry must not borrow package.teamId")
        XCTAssertFalse(finding.evidence.isTeamIdWhitelistVerified)
        XCTAssertEqual(finding.riskTier, .caution)
    }

    func test_m2r4_finding4_appexSymlinkEscapeSetsWhitelistIneligible() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wq_m2r4_symlink_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let outsidePlist = dir.appendingPathComponent("OutsideInfo.plist")
        let extPlist: [String: Any] = [
            "CFBundleIdentifier": "com.wqguard.app.ext",
            "CFBundleExecutable": "Ext",
            "CFBundleShortVersionString": "1.0"
        ]
        try PropertyListSerialization.data(fromPropertyList: extPlist, format: .xml, options: 0).write(to: outsidePlist)

        let appURL = dir.appendingPathComponent("Host.app")
        let appexURL = appURL.appendingPathComponent("PlugIns/Ext.appex")
        try FileManager.default.createDirectory(at: appexURL, withIntermediateDirectories: true)

        let mainPlist: [String: Any] = [
            "CFBundleIdentifier": "com.wqguard.app",
            "CFBundleExecutable": "WQGuard",
            "CFBundleShortVersionString": "1.0"
        ]
        let mainPlistData = try PropertyListSerialization.data(fromPropertyList: mainPlist, format: .xml, options: 0)
        try mainPlistData.write(to: appURL.appendingPathComponent("Info.plist"))
        let mainBin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            infoPlistData: mainPlistData,
            codeDirectoryIdentifier: "com.wqguard.app",
            includeCodeSignature: true
        )
        try mainBin.write(to: appURL.appendingPathComponent("WQGuard"))

        // Symlink PlugIns/Ext.appex/Info.plist -> ../../../OutsideInfo.plist (escapes Host.app)
        try FileManager.default.createSymbolicLink(
            at: appexURL.appendingPathComponent("Info.plist"),
            withDestinationURL: outsidePlist
        )
        let extBin = Self.buildMinimalARM64MachO(
            cryptid: 0,
            codeDirectoryIdentifier: "com.wqguard.app.ext",
            includeCodeSignature: true
        )
        try extBin.write(to: appexURL.appendingPathComponent("Ext"))

        let finding = try SecurityPipeline.shared.scanBundle(at: appURL)
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertFalse(finding.isWhitelisted)
        XCTAssertFalse(finding.evidence.isWhitelistEligible)
        XCTAssertFalse(finding.evidence.escapingSymlinks.isEmpty)
    }

    // MARK: - 7. M2 Iteration 5 Remediation Regression Tests (R1.2 Percent-Encoded Traversal & Low Note 1)

    func test_m2r5_percentEncodedPathTraversalBlockedAndBenignControlsPreserved() throws {
        let scanner = InstalledAppRegistryScanner.shared
        let highRiskEnts: [String: Any] = [
            "com.apple.private.security.no-sandbox": true,
            "platform-application": true,
            "com.apple.private.tcc.allow": ["kTCCServiceSystemPolicyAllFiles"]
        ]

        // 1. devicectl `url` payloads (including double-encoded `%252e%252e` and `%2e%2e%2f`)
        let urlPayloads: [(label: String, url: String)] = [
            ("pct-double-252e-url", "file:///Applications/%252e%252e/private/var/evil/Preferences.app"),
            ("pct-2e2e-url", "file:///Applications/%2e%2e/private/var/evil/Preferences.app"),
            ("pct-2E2E-slash-url", "file:///Applications/%2E%2E%2fprivate/var/evil/Preferences.app"),
            ("pct-mixed-dot2e-url", "file:///Applications/.%2e/private/var/evil/Preferences.app"),
            ("pct-2e-dot-url", "file:///Applications/%2e./private/var/evil/Preferences.app"),
            ("pct-double-var-jb-url", "file:///Applications/%252fvar%252fjb%252fevil/Preferences.app")
        ]

        for item in urlPayloads {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
                "bundleIdentifier": "com.apple.Preferences",
                "name": "Preferences",
                "defaultApp": true,
                "internalApp": false,
                "builtByDeveloper": false,
                "url": item.url,
                "entitlements": highRiskEnts
            ]))
            XCTAssertEqual(rec.applicationType, "User", "\(item.label) must demote applicationType to User")
            XCTAssertFalse(rec.hasAppStoreMetadata, "\(item.label) must not infer AppStore metadata")
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "\(item.label) must not classify as Apple OS")
            XCTAssertTrue(scanner.isSideloadedOrAnomalous(rec), "\(item.label) must be anomalous")
            XCTAssertNotEqual(scanner.classifyChannel(for: rec).channel, .appStore, "\(item.label) must not classify as .appStore")
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1, "\(item.label) must not be silently dropped by evaluateRecords")
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk, "\(item.label) must produce .highRisk")
        }

        // 2. devicectl `bundleContainerPath` payloads (including un-decoded `%2e%2e`, Cryptex escape, `%2fvar%2fjb%2f`, `%2fDeveloper%2f`)
        let containerPayloads: [(label: String, container: String)] = [
            ("pct-2e2e-container", "/Applications/%2e%2e/private/var/evil/Preferences.app"),
            ("pct-2e2e-cryptex-container", "/private/preboot/Cryptexes/%2e%2e/%2e%2e/evil/Preferences.app"),
            ("pct-2E2E-system-container", "/System/%2E%2E/private/var/evil/Preferences.app"),
            ("pct-mixed-dot2e-container", "/Applications/.%2e/private/var/evil/Preferences.app"),
            ("pct-2e-dot-container", "/Applications/%2e./private/var/evil/Preferences.app"),
            ("pct-2e2e2f-container", "/Applications/%2e%2e%2fprivate/var/evil/Preferences.app"),
            ("pct-double-252e-container", "/Applications/%252e%252e/private/var/evil/Preferences.app"),
            ("pct-2e2e-backslash-container", "/Applications/%2e%2e%5cprivate/var/evil/Preferences.app"),
            ("pct-var-jb-container", "/Applications/%2fvar%2fjb%2fevil/Preferences.app"),
            ("pct-developer-container", "/%2fDeveloper%2f/Applications/Preferences.app"),
            ("pct-2e2e-with-invalid-pct-container", "/Applications/%2e%2e/%ZZ/private/var/evil/Preferences.app")
        ]

        for item in containerPayloads {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
                "bundleIdentifier": "com.apple.Preferences",
                "name": "Preferences",
                "defaultApp": true,
                "internalApp": false,
                "builtByDeveloper": false,
                "bundleContainerPath": item.container,
                "entitlements": highRiskEnts
            ]))
            XCTAssertEqual(rec.applicationType, "User", "\(item.label) must demote applicationType to User")
            XCTAssertFalse(rec.hasAppStoreMetadata, "\(item.label) must not infer AppStore metadata")
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "\(item.label) must not classify as Apple OS")
            XCTAssertTrue(scanner.isSideloadedOrAnomalous(rec), "\(item.label) must be anomalous")
            XCTAssertNotEqual(scanner.classifyChannel(for: rec).channel, .appStore, "\(item.label) must not classify as .appStore")
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1, "\(item.label) must not be silently dropped by evaluateRecords")
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk, "\(item.label) must produce .highRisk")
        }

        // 3. `fromDictionary` `Path` payloads
        let dictPayloads: [(label: String, path: String)] = [
            ("dict-pct-2e2e-apps", "/Applications/%2e%2e/private/var/evil/Preferences.app"),
            ("dict-pct-2e2e-cryptex", "/private/preboot/Cryptexes/%2e%2e/evil/Preferences.app"),
            ("dict-pct-2e2e-system", "/System/%2e%2e/private/var/evil/Preferences.app"),
            ("dict-pct-2E2E-system", "/System/%2E%2E/private/var/evil/Preferences.app"),
            ("dict-pct-mixed-dot2e", "/Applications/.%2e/private/var/evil/Preferences.app"),
            ("dict-pct-2e-dot", "/Applications/%2e./private/var/evil/Preferences.app"),
            ("dict-pct-2e2e2f", "/Applications/%2e%2e%2fprivate/var/evil/Preferences.app"),
            ("dict-pct-252e252e", "/Applications/%252e%252e/private/var/evil/Preferences.app"),
            ("dict-pct-2e2e-backslash", "/Applications/%2e%2e%5cprivate/var/evil/Preferences.app"),
            ("dict-pct-var-jb", "/%2fvar%2fjb%2fevil/Preferences.app"),
            ("dict-pct-developer", "/%2fDeveloper%2f/Applications/Preferences.app")
        ]

        for item in dictPayloads {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.apple.Preferences",
                "ApplicationType": "System",
                "Path": item.path,
                "Entitlements": highRiskEnts
            ]))
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "\(item.label) must not classify as Apple OS")
            XCTAssertTrue(scanner.isSideloadedOrAnomalous(rec), "\(item.label) must be anomalous")
            XCTAssertNotEqual(scanner.classifyChannel(for: rec).channel, .appStore, "\(item.label) must not classify as .appStore")
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1, "\(item.label) must not be silently dropped by evaluateRecords")
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk, "\(item.label) must produce .highRisk")
        }

        // 4. Clean R4 controls (trailing `/.`, dotted bundle name, `%20` space, double slashes, Cryptexes)
        let benignControls: [(label: String, bid: String, path: String, groups: [String])] = [
            ("trailing-dot", "com.apple.Preferences", "/Applications/Preferences.app/.", ["group.tvappservices.container"]),
            ("dotted-app-name", "com.apple.Preferences", "/Applications/My.App.app", ["group.tvappservices.container"]),
            ("pct20-space-app-name", "com.apple.Preferences", "/Applications/My%20App.app", ["group.tvappservices.container"]),
            ("staged-double-slash", "com.apple.Preferences", "/private/var//containers/Bundle/Application/UUID-PREF/Preferences.app", ["group.tvappservices.container"]),
            ("cryptex-os-app", "com.apple.Preferences", "/private/preboot/Cryptexes/OS/System/Applications/Preferences.app", ["group.tvappservices.container"])
        ]

        for ctrl in benignControls {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": ctrl.bid,
                "ApplicationType": "System",
                "Path": ctrl.path,
                "Entitlements": [
                    "com.apple.security.application-groups": ctrl.groups
                ]
            ]))
            XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(rec), "Control '\(ctrl.label)' must remain Apple OS")
            XCTAssertFalse(scanner.isSideloadedOrAnomalous(rec), "Control '\(ctrl.label)' must not be anomalous")
            XCTAssertEqual(scanner.classifyChannel(for: rec).channel, .appStore)
            XCTAssertTrue(scanner.evaluateRecords([rec], includeAppStoreApps: true).isEmpty, "Control '\(ctrl.label)' must emit 0 findings")
        }
    }

    func test_m2r5_adHocSpaceSignerConsistency() throws {
        let teamLockedWL = WhitelistEngine(tools: [
            WhitelistedTool(
                name: "TeamLockedTool",
                allowedBundleIds: ["com.example.teamtool"],
                allowedAppGroups: [],
                allowedTeamIds: ["TEAM123456"],
                expectedSignatures: ["com.apple.security.application-groups"]
            )
        ])
        let scanner = InstalledAppRegistryScanner(whitelistEngine: teamLockedWL)

        for signer in ["Ad Hoc (Fugu)", "Ad-Hoc (Fugu)", "AdHoc (Fugu)"] {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.example.teamtool",
                "CFBundleDisplayName": "TeamTool",
                "ApplicationType": "User",
                "SignerIdentity": signer,
                "ProfileValidated": true,
                "TeamIdentifier": "TEAM123456",
                "Entitlements": [
                    "com.apple.developer.team-identifier": "TEAM123456",
                    "com.apple.security.application-groups": ["group.example.teamtool"]
                ]
            ]))
            XCTAssertEqual(scanner.classifyChannel(for: rec).channel, .developerSideloaded, "\(signer) must classify as .developerSideloaded")
            let finding = scanner.evaluateRecord(rec)
            XCTAssertFalse(finding.evidence.isTeamIdWhitelistVerified, "\(signer) must never mark teamId whitelist verified")
            XCTAssertFalse(finding.isWhitelisted, "\(signer) must not match team-locked whitelist")
            XCTAssertEqual(finding.riskTier, .caution, "\(signer) must remain .caution")
        }
    }

    // MARK: - 8. M2 Iteration 6 Remediation Regression Tests (R1.2 NUL/Control Chars, Non-Convergence, Un-Slashed /jb, Non-Local file://, AdHoc)

    func test_m2r6_nulAndControlCharTraversalAndUnSlashedJailbreakSuffixesBlocked() throws {
        let scanner = InstalledAppRegistryScanner.shared
        let highRiskEnts: [String: Any] = [
            "com.apple.private.security.no-sandbox": true,
            "platform-application": true,
            "com.apple.private.tcc.allow": ["kTCCServiceSystemPolicyAllFiles"]
        ]

        let dictPayloads: [(label: String, path: String)] = [
            ("dict-dotdot-pct00", "/Applications/..%00/private/var/evil/Preferences.app"),
            ("dict-pct2e2e-pct00", "/System/%2e%2e%00/private/var/evil/Preferences.app"),
            ("dict-literal-nul", "/Applications/..\0/private/var/evil/Preferences.app"),
            ("dict-control-0a", "/Applications/..%0a/private/var/evil/Preferences.app"),
            ("dict-control-7f", "/Applications/Preferences.app%7f"),
            ("dict-trailing-newline", "/Applications/Preferences.app\n"),
            ("dict-unslashed-pct2f-var-jb", "/Applications/%2fvar%2fjb"),
            ("dict-unslashed-var-jb", "/Applications/var/jb"),
            ("dict-unslashed-pct2f-jb", "/Applications/%2fjb"),
            ("dict-unslashed-jb", "/Applications/jb"),
            ("dict-root-var-jb", "/var/jb"),
            ("dict-root-jb", "/jb")
        ]

        for item in dictPayloads {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.apple.Preferences",
                "ApplicationType": "System",
                "Path": item.path,
                "Entitlements": highRiskEnts
            ]))
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "\(item.label) must not classify as Apple OS")
            XCTAssertNotEqual(scanner.classifyChannel(for: rec).channel, .appStore, "\(item.label) must not classify as .appStore")
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1, "\(item.label) must emit 1 finding")
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk, "\(item.label) must produce .highRisk")
        }

        let deviceCtlURLPayloads: [(label: String, url: String)] = [
            ("url-dotdot-pct00", "file:///Applications/..%00/private/var/evil/Preferences.app"),
            ("url-pct2e2e-pct00", "file:///Applications/%2e%2e%00/private/var/evil/Preferences.app"),
            ("url-cryptex-dotdot-pct00", "file:///private/preboot/Cryptexes/..%00/evil/Preferences.app"),
            ("url-trailing-pct00", "file:///Applications/Preferences.app%00"),
            ("url-control-0a", "file:///Applications/%0a/Preferences.app"),
            ("url-unslashed-pct2f-var-jb", "file:///Applications/%2fvar%2fjb"),
            ("url-unslashed-var-jb", "file:///Applications/var/jb")
        ]

        for item in deviceCtlURLPayloads {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
                "bundleIdentifier": "com.apple.Preferences",
                "name": "Preferences",
                "defaultApp": true,
                "internalApp": false,
                "builtByDeveloper": false,
                "url": item.url,
                "entitlements": highRiskEnts
            ]))
            XCTAssertEqual(rec.applicationType, "User", "\(item.label) must demote applicationType to User")
            XCTAssertFalse(rec.hasAppStoreMetadata, "\(item.label) must clear AppStore metadata")
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "\(item.label) must not classify as Apple OS")
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1, "\(item.label) must emit 1 finding")
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk, "\(item.label) must produce .highRisk")
        }

        let deviceCtlContainerPayloads: [(label: String, container: String)] = [
            ("container-dotdot-pct00", "/Applications/..%00/private/var/evil/Preferences.app"),
            ("container-pct2e2e-pct00", "/Applications/%2e%2e%00/private/var/evil/Preferences.app"),
            ("container-control-0a", "/Applications/..%0a/private/var/evil/Preferences.app"),
            ("container-trailing-newline", "/Applications/Preferences.app\n"),
            ("container-unslashed-pct2f-var-jb", "/Applications/%2fvar%2fjb"),
            ("container-unslashed-var-jb", "/Applications/var/jb")
        ]

        for item in deviceCtlContainerPayloads {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
                "bundleIdentifier": "com.apple.Preferences",
                "name": "Preferences",
                "defaultApp": true,
                "internalApp": false,
                "builtByDeveloper": false,
                "bundleContainerPath": item.container,
                "entitlements": highRiskEnts
            ]))
            XCTAssertEqual(rec.applicationType, "User", "\(item.label) must demote applicationType to User")
            XCTAssertFalse(rec.hasAppStoreMetadata, "\(item.label) must clear AppStore metadata")
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "\(item.label) must not classify as Apple OS")
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1, "\(item.label) must emit 1 finding")
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk, "\(item.label) must produce .highRisk")
        }
    }

    func test_m2r6_percentDecodeNonConvergenceFailClosedAndBoundedPerf() throws {
        let scanner = InstalledAppRegistryScanner.shared
        let highRiskEnts: [String: Any] = [
            "com.apple.private.security.no-sandbox": true,
            "platform-application": true,
            "com.apple.private.tcc.allow": ["kTCCServiceSystemPolicyAllFiles"]
        ]

        // 7x nested `%25...2e` in fromDictionary `Path` and devicectl `bundleContainerPath`
        let sevenLayerPath = "/Applications/%2525252525252e%2525252525252e/private/var/evil/Preferences.app"
        let dictRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Preferences",
            "ApplicationType": "System",
            "Path": sevenLayerPath,
            "Entitlements": highRiskEnts
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(dictRec), "7x encoded traversal in Path must fail closed")
        XCTAssertEqual(scanner.evaluateRecords([dictRec], includeAppStoreApps: true).first?.riskTier, .highRisk)

        let containerRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
            "bundleIdentifier": "com.apple.Preferences",
            "name": "Preferences",
            "defaultApp": true,
            "url": "file:///Applications/Preferences.app",
            "bundleContainerPath": sevenLayerPath,
            "entitlements": highRiskEnts
        ]))
        XCTAssertEqual(containerRec.applicationType, "User")
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(containerRec), "7x encoded traversal in bundleContainerPath must fail closed")
        XCTAssertEqual(scanner.evaluateRecords([containerRec], includeAppStoreApps: true).first?.riskTier, .highRisk)

        // 8x nested `%25...2e` in devicectl `url` (URL.path performs 1 pass -> 7x remaining)
        let eightLayerURL = "file:///Applications/%252525252525252e%252525252525252e/private/var/evil/Preferences.app"
        let urlRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
            "bundleIdentifier": "com.apple.Preferences",
            "name": "Preferences",
            "defaultApp": true,
            "url": eightLayerURL,
            "entitlements": highRiskEnts
        ]))
        XCTAssertEqual(urlRec.applicationType, "User")
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(urlRec), "8x encoded traversal in devicectl url must fail closed")
        XCTAssertEqual(scanner.evaluateRecords([urlRec], includeAppStoreApps: true).first?.riskTier, .highRisk)

        // Large 60KB nested `%25` chain + `2e%2e`: must fail closed and finish well under 1s (O(N) bounded)
        for largeChainPath in [
            "/Applications/%" + String(repeating: "25", count: 30_000) + "2e/evil/Preferences.app",
            "/Applications/%" + String(repeating: "25", count: 30_000) + "2e%2e/evil/Preferences.app",
            "/Applications/" + String(repeating: "%25", count: 20_000) + "/%2e%2e/evil/Preferences.app"
        ] {
            let start = CFAbsoluteTimeGetCurrent()
            let largeRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.apple.Preferences",
                "ApplicationType": "System",
                "Path": largeChainPath,
                "Entitlements": highRiskEnts
            ]))
            let isApple = scanner.isAppleSystemOrFirstPartyApp(largeRec)
            let evaluated = scanner.evaluateRecords([largeRec], includeAppStoreApps: true)
            let elapsed = CFAbsoluteTimeGetCurrent() - start
            XCTAssertLessThan(elapsed, 1.0, "60KB %25 chain must complete in < 1s (took \(elapsed)s)")
            XCTAssertFalse(isApple, "Non-converging/traversal 60KB %25 chain must fail closed")
            XCTAssertEqual(evaluated.count, 1)
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk)
        }
    }

    func test_m2r6_nonLocalFileURLRejectedAndBenignR4ControlsPreserved() throws {
        let scanner = InstalledAppRegistryScanner.shared
        let highRiskEnts: [String: Any] = [
            "com.apple.private.security.no-sandbox": true,
            "platform-application": true,
            "com.apple.private.tcc.allow": ["kTCCServiceSystemPolicyAllFiles"]
        ]

        // Non-local / authority-bearing file:// hosts must be rejected
        for remoteURL in [
            "file://evil.host/Applications/Preferences.app",
            "file://evil.host/Applications/My App/Preferences.app",
            "file://evil@localhost/Applications/Preferences.app",
            "file://localhost:8080/Applications/Preferences.app"
        ] {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
                "bundleIdentifier": "com.apple.Preferences",
                "name": "Preferences",
                "defaultApp": true,
                "internalApp": false,
                "builtByDeveloper": false,
                "url": remoteURL,
                "entitlements": highRiskEnts
            ]))
            XCTAssertEqual(rec.applicationType, "User", "Non-local \(remoteURL) must demote to User")
            XCTAssertFalse(rec.hasAppStoreMetadata, "Non-local \(remoteURL) must clear AppStore metadata")
            XCTAssertEqual(rec.bundlePath, remoteURL, "Non-local \(remoteURL) must preserve raw urlStr")
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "Non-local \(remoteURL) must not be Apple OS")
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1)
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk)
        }

        // Local file://localhost/... and file:///... remain valid
        for localURL in [
            "file://localhost/Applications/Preferences.app",
            "file:///Applications/Preferences.app",
            "file:///Applications/100%25Real.app",
            "file:///Applications/My%20App.app"
        ] {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
                "bundleIdentifier": "com.apple.Preferences",
                "name": "Preferences",
                "defaultApp": true,
                "url": localURL,
                "appGroupIdentifiers": ["group.tvappservices.container"]
            ]))
            XCTAssertEqual(rec.applicationType, "System", "Local \(localURL) must remain System")
            XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(rec), "Local \(localURL) must remain Apple OS")
            XCTAssertTrue(scanner.evaluateRecords([rec], includeAppStoreApps: true).isEmpty, "Local \(localURL) must emit 0 findings")
        }

        // Benign R4 dictionary controls (100%25Real.app, 100%Real.app, My%20App.app, /., My.App.app, App..Name.app, Cryptexes, stock apps)
        let benignDictControls: [(label: String, bid: String, path: String, groups: [String], boolEnts: [String: Bool])] = [
            ("100pct25-real", "com.apple.Preferences", "/Applications/100%25Real.app", ["group.tvappservices.container"], [:]),
            ("100pct-real", "com.apple.Preferences", "/Applications/100%Real.app", ["group.tvappservices.container"], [:]),
            ("my-pct20-app", "com.apple.Preferences", "/Applications/My%20App.app", ["group.tvappservices.container"], [:]),
            ("trailing-dot", "com.apple.Preferences", "/Applications/Preferences.app/.", ["group.tvappservices.container"], [:]),
            ("my-dot-app", "com.apple.Preferences", "/Applications/My.App.app", ["group.tvappservices.container"], [:]),
            ("app-double-dot-name", "com.apple.Preferences", "/Applications/App..Name.app", ["group.tvappservices.container"], [:]),
            ("cryptex-os", "com.apple.Preferences", "/private/preboot/Cryptexes/OS/System/Applications/Preferences.app", ["group.tvappservices.container"], [:]),
            ("reminders-v7-nosandbox", "com.apple.reminders", "/private/var/containers/Bundle/Application/UUID-REM/Reminders.app", ["group.com.apple.reminders"], ["com.apple.private.security.no-sandbox": true])
        ]

        for ctrl in benignDictControls {
            var entDict: [String: Any] = ["com.apple.security.application-groups": ctrl.groups]
            for (k, v) in ctrl.boolEnts { entDict[k] = v }
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": ctrl.bid,
                "ApplicationType": "System",
                "Path": ctrl.path,
                "Entitlements": entDict
            ]))
            XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(rec), "Benign R4 control '\(ctrl.label)' must remain Apple OS")
            XCTAssertTrue(scanner.evaluateRecords([rec], includeAppStoreApps: true).isEmpty, "Benign R4 control '\(ctrl.label)' must emit 0 findings")
        }
    }

    func test_m2r6_unspacedAdHocSignerConsistencyAcrossDictDevicectlAndMerge() throws {
        let teamLockedWL = WhitelistEngine(tools: [
            WhitelistedTool(
                name: "TeamLockedTool",
                allowedBundleIds: ["com.example.teamtool"],
                allowedAppGroups: [],
                allowedTeamIds: ["TEAM123456"],
                expectedSignatures: ["com.apple.security.application-groups"]
            )
        ])
        let scanner = InstalledAppRegistryScanner(whitelistEngine: teamLockedWL)
        let pipeline = SecurityPipeline(whitelistEngine: teamLockedWL)

        for signer in ["AdHoc (Fugu)", "Ad Hoc (Fugu)", "Ad-Hoc (Fugu)", "adhoc"] {
            // 1. fromDictionary + WhitelistEngine
            let dictRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
                "CFBundleIdentifier": "com.example.teamtool",
                "CFBundleDisplayName": "TeamTool",
                "ApplicationType": "User",
                "SignerIdentity": signer,
                "ProfileValidated": true,
                "TeamIdentifier": "TEAM123456",
                "Entitlements": [
                    "com.apple.developer.team-identifier": "TEAM123456",
                    "com.apple.security.application-groups": ["group.example.teamtool"]
                ]
            ]))
            XCTAssertEqual(scanner.classifyChannel(for: dictRec).channel, .developerSideloaded, "\(signer) dict channel")
            let dictFinding = scanner.evaluateRecord(dictRec)
            XCTAssertFalse(dictFinding.evidence.isTeamIdWhitelistVerified, "\(signer) dict must not verify teamId")
            XCTAssertFalse(dictFinding.isWhitelisted, "\(signer) dict must not whitelist")
            XCTAssertEqual(dictFinding.riskTier, .caution)
            let wlCheck = teamLockedWL.evaluateFindingWhitelist(dictFinding)
            XCTAssertFalse(wlCheck.isWhitelisted, "\(signer) WhitelistEngine must reject")

            // 2. fromDeviceCtlDictionary + own-team keychain wildcard must flag .highRisk (never bypass via deviceCtlOwnTeamPrefixes)
            let ctlRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
                "bundleIdentifier": "com.example.teamtool",
                "name": "TeamTool",
                "signerIdentity": signer,
                "profileValidated": true,
                "teamIdentifier": "TEAM123456",
                "entitlements": [
                    "com.apple.developer.team-identifier": "TEAM123456",
                    "keychain-access-groups": ["TEAM123456.*"],
                    "com.apple.security.application-groups": ["group.example.teamtool"]
                ]
            ]))
            XCTAssertFalse(ctlRec.hasAppStoreMetadata, "\(signer) devicectl must not have AppStore metadata")
            XCTAssertEqual(scanner.classifyChannel(for: ctlRec).channel, .developerSideloaded, "\(signer) devicectl channel")
            let ctlFinding = scanner.evaluateRecord(ctlRec)
            XCTAssertFalse(ctlFinding.evidence.isTeamIdWhitelistVerified, "\(signer) devicectl must not verify teamId")
            XCTAssertEqual(ctlFinding.riskTier, .highRisk, "\(signer) devicectl wildcard KC must flag .highRisk")
            XCTAssertTrue(ctlFinding.indicators.contains { $0.signature == "keychain-access-groups(*)" })

            // 3. mergeRegistryAndPackageFinding with valid signed package must stay unwhitelisted
            let signedPkg = ScanFinding(
                bundleId: "com.example.teamtool",
                displayName: "TeamTool",
                version: "1.0",
                teamId: "TEAM123456",
                bundlePath: "/tmp/TeamTool.ipa",
                installChannel: .developerSideloaded,
                riskTier: .caution,
                indicators: [
                    ThreatIndicator(
                        signature: "com.apple.security.application-groups",
                        description: "caution",
                        category: "Shared Container Surface",
                        location: "Entitlements",
                        severity: .caution
                    )
                ],
                evidence: AuditEvidence(
                    matchedSymbols: ["com.apple.security.application-groups"],
                    hasAppGroups: true,
                    appGroups: ["group.example.teamtool"],
                    installChannel: .developerSideloaded,
                    isWhitelistEligible: true,
                    isTeamIdWhitelistVerified: true
                )
            )
            let merged = pipeline.correlateAndMergeFindings(
                registryRecords: [dictRec],
                packageFindings: [signedPkg]
            )
            let mergedFinding = try XCTUnwrap(merged.findings.first)
            XCTAssertFalse(mergedFinding.isWhitelisted, "\(signer) merge must not whitelist")
            XCTAssertFalse(mergedFinding.evidence.isTeamIdWhitelistVerified, "\(signer) merge must not verify teamId")
            XCTAssertEqual(mergedFinding.riskTier, .caution)
        }
    }

    // MARK: - 9. M2 Iteration 7 Remediation Regression Tests (R1.2 devicectl Leading Control/Space & Non-file:// URL + Relative SSV Path)

    func test_m2r7_devicectlLeadingControlSpaceAndNonFileURLBlocked_andRelativePathRejected() throws {
        let scanner = InstalledAppRegistryScanner.shared
        let highRiskEnts: [String: Any] = [
            "com.apple.private.security.no-sandbox": true,
            "platform-application": true,
            "com.apple.private.tcc.allow": ["kTCCServiceSystemPolicyAllFiles"]
        ]

        // 1. All Challenger 1 [BYPASS-CHECK] & Reviewer 1 Finding 2 vectors (leading control/space, non-file://, raw path, whitespace-only, bare file://)
        let blockedURLPayloads: [(label: String, url: String)] = [
            ("leading-nul-traversal", "\0file:///Applications/%2e%2e/evil/Preferences.app"),
            ("leading-tab-traversal", "\tfile:///Applications/%2e%2e/evil/Preferences.app"),
            ("leading-newline-traversal", "\nfile:///Applications/%2e%2e/evil/Preferences.app"),
            ("leading-space-traversal", " file:///Applications/%2e%2e/evil/Preferences.app"),
            ("leading-space-var-jb", " file:///var/jb/Applications/Preferences.app"),
            ("leading-space-apps", " file:///Applications/Preferences.app"),
            ("trailing-space-apps", "file:///Applications/Preferences.app "),
            ("whitespace-only-url", "   "),
            ("nonfile-http-scheme", "http://evil.host/Applications/Preferences.app"),
            ("nonfile-https-scheme", "https://evil.host/Applications/Preferences.app"),
            ("nonfile-smb-scheme", "smb://evil.host/share/Preferences.app"),
            ("raw-nonfile-var-jb", "/var/jb/Applications/Preferences.app"),
            ("raw-nonfile-apps", "/Applications/Preferences.app"),
            ("relative-file-scheme", "file:Applications/Preferences.app"),
            ("bare-file-scheme", "file://"),
            ("bare-file-localhost", "file://localhost"),
            ("localhost-query-only", "file://localhost?x=1")
        ]

        for item in blockedURLPayloads {
            let rec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
                "bundleIdentifier": "com.apple.Preferences",
                "name": "Preferences",
                "defaultApp": true,
                "internalApp": false,
                "builtByDeveloper": false,
                "url": item.url,
                "entitlements": highRiskEnts
            ]))
            XCTAssertEqual(rec.applicationType, "User", "\(item.label) must demote applicationType to User")
            XCTAssertFalse(rec.hasAppStoreMetadata, "\(item.label) must clear hasAppStoreMetadata")
            XCTAssertEqual(rec.bundlePath, item.url, "\(item.label) must preserve raw url in bundlePath instead of falling back to /Applications/")
            XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(rec), "\(item.label) must not classify as Apple OS")
            XCTAssertNotEqual(scanner.classifyChannel(for: rec).channel, .appStore, "\(item.label) must not classify as .appStore")
            let evaluated = scanner.evaluateRecords([rec], includeAppStoreApps: true)
            XCTAssertEqual(evaluated.count, 1, "\(item.label) must emit 1 finding")
            XCTAssertEqual(evaluated.first?.riskTier, .highRisk, "\(item.label) must produce .highRisk")
        }

        // 2. Relative path without leading `/` must NOT be treated as an SSV System path (both fromDictionary Path & devicectl bundleContainerPath)
        let relativePathRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Preferences",
            "ApplicationType": "System",
            "Path": "Applications/Preferences.app",
            "Entitlements": highRiskEnts
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(relativePathRec), "Relative path without leading '/' must not match SSV system path")
        let relEval = scanner.evaluateRecords([relativePathRec], includeAppStoreApps: true)
        XCTAssertEqual(relEval.count, 1)
        XCTAssertEqual(relEval.first?.riskTier, .highRisk)

        let relativeContainerRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
            "bundleIdentifier": "com.apple.Preferences",
            "name": "Preferences",
            "defaultApp": true,
            "url": "",
            "bundleContainerPath": "Applications/Preferences.app",
            "entitlements": highRiskEnts
        ]))
        XCTAssertEqual(relativeContainerRec.applicationType, "User")
        XCTAssertFalse(relativeContainerRec.hasAppStoreMetadata)
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(relativeContainerRec), "Relative devicectl bundleContainerPath must not match SSV system path")
        let relCtlEval = scanner.evaluateRecords([relativeContainerRec], includeAppStoreApps: true)
        XCTAssertEqual(relCtlEval.count, 1)
        XCTAssertEqual(relCtlEval.first?.riskTier, .highRisk)

        // 3. Valid empty/absent `url` (`nil` and `""`) with `defaultApp: true` (and R4 benign controls) still emit 0 findings
        let absentURLRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
            "bundleIdentifier": "com.apple.Preferences",
            "name": "Preferences",
            "defaultApp": true,
            "appGroupIdentifiers": ["group.tvappservices.container"]
        ]))
        XCTAssertEqual(absentURLRec.applicationType, "System")
        XCTAssertEqual(absentURLRec.bundlePath, "/Applications/com.apple.Preferences.app")
        XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(absentURLRec))
        XCTAssertTrue(scanner.evaluateRecords([absentURLRec], includeAppStoreApps: true).isEmpty)

        let emptyURLRec = try XCTUnwrap(InstalledAppRegistryRecord.fromDeviceCtlDictionary([
            "bundleIdentifier": "com.apple.Preferences",
            "name": "Preferences",
            "defaultApp": true,
            "url": "",
            "appGroupIdentifiers": ["group.tvappservices.container"]
        ]))
        XCTAssertEqual(emptyURLRec.applicationType, "System")
        XCTAssertEqual(emptyURLRec.bundlePath, "/Applications/com.apple.Preferences.app")
        XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(emptyURLRec))
        XCTAssertTrue(scanner.evaluateRecords([emptyURLRec], includeAppStoreApps: true).isEmpty)
    }

    // MARK: - 10. Real iOS 26/27 Device Stock Apps (Unlisted Apple TeamIdentifier, Cryptex1 Boot Hash, Private Entitlements)

    func test_realDeviceIOS26_screenshotStockApps_zeroHighRiskFalsePositives() throws {
        let scanner = InstalledAppRegistryScanner.shared
        let pipeline = SecurityPipeline.shared

        let stockDicts: [[String: Any]] = [
            [
                "CFBundleIdentifier": "com.apple.MobileSMS",
                "CFBundleDisplayName": "信息",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPL1",
                "Path": "/private/var/containers/Bundle/Application/UUID-SMS/MobileSMS.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.security.no-container": true,
                    "com.apple.private.MobileContainerManager.allowed": true,
                    "com.apple.private.security.storage.AppDataContainers": true,
                    "com.apple.private.MobileGestalt.allowed": true,
                    "com.apple.private.photos.service.internal.cloud": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceCamera", "kTCCServiceMicrophone", "kTCCServiceContacts"],
                    "keychain-access-groups": ["com.apple.*", "UNLISTAPL1.*"],
                    "com.apple.security.application-groups": ["group.com.apple.Messages", "group.sms.shared", "group.im.shared"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.DocumentsApp",
                "CFBundleDisplayName": "文件",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPL2",
                "Path": "/private/var/containers/Bundle/Application/UUID-DOCS/DocumentsApp.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.MobileContainerManager.allowed": true,
                    "com.apple.private.security.storage.AppDataContainers": true,
                    "com.apple.private.MobileGestalt.allowed": true,
                    "com.apple.private.tcc.allow": ["kTCCServicePhotos"],
                    "com.apple.security.application-groups": ["group.com.apple.DocumentManager", "group.icloud.docs"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.mobilenotes",
                "CFBundleDisplayName": "备忘录",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPL3",
                "Path": "/private/var/containers/Bundle/Application/UUID-NOTES/MobileNotes.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.MobileGestalt.allowed": true,
                    "com.apple.private.photos.allow.internal": true,
                    "com.apple.private.mediaexperience.allow": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceCamera", "kTCCServiceMicrophone"],
                    "keychain-access-groups": ["com.apple.*"],
                    "com.apple.security.application-groups": ["group.com.apple.notes", "group.icloud.notes"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.Health",
                "CFBundleDisplayName": "健康",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPL4",
                "Path": "/private/preboot/0123456789ABCDEF0123456789ABCDEF/cryptex1/AppOS/Applications/Health.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.security.no-container": true,
                    "com.apple.private.MobileContainerManager.allowed": true,
                    "com.apple.private.MobileGestalt.allowed": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceMotion"],
                    "com.apple.security.application-groups": ["group.com.apple.Health", "group.health.shared"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.GenerativePlaygroundApp",
                "CFBundleDisplayName": "图乐园",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPL5",
                "Path": "/private/var/containers/Bundle/Application/UUID-GP/ImagePlayground.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.MobileGestalt.allowed": true,
                    "com.apple.photos.bourgeoisie": true,
                    "com.apple.private.mediaexperience.allow": true,
                    "com.apple.private.cmsession.allow": true,
                    "com.apple.itunesstored.private": true,
                    "com.apple.private.tcc.allow": ["kTCCServicePhotos"],
                    "keychain-access-groups": ["com.apple.*"],
                    "com.apple.security.application-groups": ["group.com.apple.GenerativePlayground", "group.gm.shared"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.Passwords",
                "CFBundleDisplayName": "密码",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPL6",
                "Path": "/private/var/containers/Bundle/Application/UUID-PASS/Passwords.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.MobileGestalt.allowed": true,
                    "keychain-access-groups": ["com.apple.*", "UNLISTAPL6.*"],
                    "com.apple.security.application-groups": ["group.passwords.shared"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.VoiceMemos",
                "CFBundleDisplayName": "语音备忘录",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPL7",
                "Path": "/private/var/containers/Bundle/Application/UUID-VM/VoiceMemos.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.mediaexperience.allow": true,
                    "com.apple.private.cmsession.allow": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"],
                    "com.apple.security.application-groups": ["group.com.apple.VoiceMemos.shared"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.AppStore",
                "CFBundleDisplayName": "App Store",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPL8",
                "Path": "/private/var/containers/Bundle/Application/UUID-AS/AppStore.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.itunesstored.private": true,
                    "com.apple.private.MobileGestalt.allowed": true,
                    "com.apple.security.application-groups": ["group.ams.store", "group.com.apple.appstore"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.reminders",
                "CFBundleDisplayName": "提醒事项",
                "CFBundleShortVersionString": "7.0",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPL9",
                "Path": "/private/var/containers/Bundle/Application/UUID-REM/Reminders.app",
                "Entitlements": [
                    "com.apple.private.security.no-sandbox": true,
                    "platform-application": true,
                    "com.apple.private.MobileGestalt.allowed": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceCamera"],
                    "com.apple.security.application-groups": ["group.com.apple.reminders", "group.com.apple.assistant.shared"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.Translate",
                "CFBundleDisplayName": "翻译",
                "ApplicationType": "System",
                "TeamIdentifier": "96VJNMX6ZP",
                "Path": "/private/var/containers/Bundle/Application/UUID-TR/Translate.app",
                "Entitlements": [
                    "com.apple.private.tcc.allow": ["kTCCServiceCamera", "kTCCServiceMicrophone", "kTCCServicePhotos"],
                    "com.apple.security.application-groups": ["group.com.apple.private.translation", "group.com.apple.tipsnext"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.TVRemoteApp",
                "CFBundleDisplayName": "遥控器",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPLA",
                "Path": "/private/var/containers/Bundle/Application/UUID-TVR/TVRemoteApp.app",
                "Entitlements": [
                    "com.apple.itunesstored.private": true,
                    "com.apple.private.tcc.allow": ["kTCCServiceBluetoothAlways", "kTCCServiceMicrophone"],
                    "com.apple.security.application-groups": ["group.com.apple.tipsnext", "group.com.apple.TVRemote"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.siri",
                "CFBundleDisplayName": "Siri",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPLB",
                "Path": "/private/preboot/A1B2C3D4E5F60718293A4B5C6D7E8F90/cryptexes/OS/Applications/Siri.app",
                "Entitlements": [
                    "com.apple.private.MobileContainerManager.allowed": true,
                    "com.apple.private.photos.service.internal.cloud": true,
                    "com.apple.itunesstored.private": true,
                    "com.apple.security.application-groups": ["group.tvappservices.container"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.Preferences",
                "CFBundleDisplayName": "设置",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPLC",
                "Path": "/Applications/Preferences.app",
                "Entitlements": [
                    "com.apple.security.application-groups": ["group.tvappservices.container", "UNLISTAPLC.com.apple.Preferences"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.campo",
                "CFBundleDisplayName": "Siri",
                "ApplicationType": "Hidden",
                "Path": "/private/var/containers/Bundle/Application/UUID-CAMPO/Campo.app",
                "Entitlements": [
                    "com.apple.security.application-groups": ["group.tvappservices.container"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.GameTrampoline",
                "CFBundleDisplayName": "Games",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPLD",
                "Path": "/private/var/containers/Bundle/Application/UUID-GT/GameTrampoline.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.tcc.allow": ["kTCCServicePhotos"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.SESUIServiceApp",
                "CFBundleDisplayName": "SESUIServiceApp",
                "ApplicationType": "System",
                "Path": "/Applications/SESUIServiceApp.app",
                "Entitlements": [
                    "application-identifier": "SESUIServiceApp",
                    "com.apple.runningboard.assertions.angeltarget": true,
                    "platform-application": true
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.SESUIServiceApp",
                "CFBundleDisplayName": "SESUIServiceApp",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPLE",
                "Path": "/private/var/containers/Bundle/Application/UUID-SES/SESUIServiceApp.app",
                "Entitlements": [
                    "application-identifier": "SESUIServiceApp",
                    "com.apple.runningboard.assertions.angeltarget": true,
                    "platform-application": true
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.purplebuddy",
                "CFBundleDisplayName": "Setup",
                "ApplicationType": "System",
                "Path": "/Applications/Setup.app",
                "Entitlements": [
                    "application-identifier": "Setup",
                    "platform-application": true
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.HDSViewService",
                "CFBundleDisplayName": "HomePod 设置",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPLF",
                "Path": "/private/var/containers/Bundle/Application/UUID-HDS/HDSViewService.app",
                "Entitlements": [
                    "platform-application": true,
                    "com.apple.private.tcc.allow": [
                        "kTCCServiceAddressBook",
                        "kTCCServiceBluetoothAlways",
                        "kTCCServiceCamera",
                        "kTCCServiceMediaLibrary",
                        "kTCCServiceMicrophone",
                        "kTCCServiceWillow"
                    ],
                    "com.apple.itunesstored.private": true,
                    "com.apple.private.MobileGestalt.AllowedProtectedKeys": true,
                    "com.apple.security.application-groups": ["group.homedevicesetup.diagnostics"]
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.FutureSecureHardwareUIService",
                "CFBundleDisplayName": "FutureHardwareUI",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPLG",
                "Path": "/private/var/containers/Bundle/Application/UUID-FHW/FutureHardwareUI.app",
                "Entitlements": [
                    "platform-application": true
                ]
            ],
            [
                "CFBundleIdentifier": "com.apple.SESUIServiceApp",
                "CFBundleDisplayName": "SESUIServiceApp",
                "ApplicationType": "System",
                "TeamIdentifier": "UNLISTAPLH",
                "Path": "/private/preboot/A1B2C3D4E5F60718293A4B5C6D7E8F90/proactive/System/Applications/SESUIServiceApp.app",
                "Entitlements": [
                    "platform-application": true
                ]
            ]
        ]

        let records = try stockDicts.map { try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary($0)) }
        for rec in records {
            XCTAssertTrue(scanner.isAppleSystemOrFirstPartyApp(rec), "Real stock app \(rec.bundleId) must be trusted")
        }
        XCTAssertTrue(scanner.evaluateRecords(records, includeAppStoreApps: true).isEmpty)
        let merged = pipeline.correlateAndMergeFindings(
            registryRecords: records,
            packageFindings: [],
            probeFindings: [],
            includeAppStoreApps: true
        )
        XCTAssertTrue(merged.findings.isEmpty)

        // Third-party App Group escalation surface (`isAppleOwnedAppGroup`) must remain strictly closed
        XCTAssertFalse(InstalledAppRegistryScanner.isAppleOwnedAppGroup("group.homedevicesetup.diagnostics"))
        XCTAssertFalse(InstalledAppRegistryScanner.isAppleOwnedAppGroup("group.customshare.exfil"))

        // Internal Apple service group helper accepts `group.homedevicesetup.diagnostics` while still rejecting hostile/custom groups
        XCTAssertTrue(InstalledAppRegistryScanner.isPermittedAppGroupForAppleSystemRecord("group.homedevicesetup.diagnostics"))
        XCTAssertFalse(InstalledAppRegistryScanner.isPermittedAppGroupForAppleSystemRecord("group.r10.backdoor"))
        XCTAssertFalse(InstalledAppRegistryScanner.isPermittedAppGroupForAppleSystemRecord("group.customshare.exfil"))

        // Negative controls for staged `*UIService` heuristic: disallowed privileges or explicit wrong `application-identifier` must stay .highRisk
        let spoofedHardwareNoCont = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.FutureSecureHardwareUIService",
            "ApplicationType": "System",
            "TeamIdentifier": "UNLISTAPLG",
            "Path": "/private/var/containers/Bundle/Application/UUID-FHW-NOCONT/FutureHardwareUI.app",
            "Entitlements": [
                "platform-application": true,
                "com.apple.private.security.no-container": true
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(spoofedHardwareNoCont))
        XCTAssertEqual(scanner.evaluateRecord(spoofedHardwareNoCont).riskTier, .highRisk)

        let spoofedHardwareEvilTeam = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.FutureSecureHardwareUIService",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-FHW-EVIL/FutureHardwareUI.app",
            "Entitlements": [
                "platform-application": true,
                "com.apple.developer.team-identifier": "EVILTEAM99",
                "application-identifier": "EVILTEAM99.com.apple.other"
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(spoofedHardwareEvilTeam))
        XCTAssertEqual(scanner.evaluateRecord(spoofedHardwareEvilTeam).riskTier, .highRisk)

        // Third-party reverse-DNS `application-identifier` on `com.apple.*` must fail closed even with `platform-application: true`
        let spoofedSESThirdPartyAppId = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.SESUIServiceApp",
            "ApplicationType": "System",
            "Path": "/Applications/SESUIServiceApp.app",
            "Entitlements": [
                "platform-application": true,
                "application-identifier": "EVIL123456.io.metamask.MetaMask"
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(spoofedSESThirdPartyAppId))
        XCTAssertEqual(scanner.evaluateRecord(spoofedSESThirdPartyAppId).riskTier, .highRisk)

        // Injecting an unlisted explicit `team-identifier` paired with bare `application-identifier` on staged `com.apple.Translate` + `no-sandbox` must stay rejected
        let spoofedTranslateBareAppId = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Translate",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-TR-BARE/Translate.app",
            "Entitlements": [
                "com.apple.developer.team-identifier": "EVILTEAM99",
                "application-identifier": "Translate",
                "com.apple.private.security.no-sandbox": true,
                "com.apple.security.application-groups": ["group.com.apple.private.translation"]
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(spoofedTranslateBareAppId))
        XCTAssertEqual(scanner.evaluateRecord(spoofedTranslateBareAppId).riskTier, .highRisk)

        let spoofedOtherBareAppId = try XCTUnwrap(InstalledAppRegistryRecord.fromDictionary([
            "CFBundleIdentifier": "com.apple.Translate",
            "ApplicationType": "System",
            "Path": "/private/var/containers/Bundle/Application/UUID-TR-OTHER/Translate.app",
            "Entitlements": [
                "com.apple.developer.team-identifier": "EVILTEAM99",
                "application-identifier": "OtherApp"
            ]
        ]))
        XCTAssertFalse(scanner.isAppleSystemOrFirstPartyApp(spoofedOtherBareAppId))
    }
}
