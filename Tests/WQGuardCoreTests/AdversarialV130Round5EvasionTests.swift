//
//  AdversarialV130Round5EvasionTests.swift
//  WQGuardCoreTests
//
//  Round 5 detection-coverage regression tests for the WQGuard static scanner.
//  Each test builds a synthetic Mach-O / bundle / IPA and asserts the scanner's
//  SECURE outcome (HIGH_RISK / not whitelisted). Out-of-scope notes are in the
//  coordinator report rather than encoded as tests.
//

import XCTest
import Foundation
import MachO
@testable import WQGuardCore

final class AdversarialV130Round5EvasionTests: XCTestCase {

    private static let svcInsn: UInt32 = 0xD400_1001
    private static let retInsn: UInt32 = 0xD65F_03C0
    private static let nopInsn: UInt32 = 0xD503_201F
    private static let mediaFwPath = "/System/Library/PrivateFrameworks/MediaExperience.framework/MediaExperience"
    private static let bookFwPath = "/System/Library/PrivateFrameworks/BookLibraryPrivate.framework/BookLibraryPrivate"

    private var tempURLs: [URL] = []

    override func setUp() {
        super.setUp()
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
    }

    override func tearDown() {
        WQLocale.overrideLanguageCode = nil
        WhitelistEngine.shared.resetToDefaults()
        for url in tempURLs { try? FileManager.default.removeItem(at: url) }
        tempURLs.removeAll()
        super.tearDown()
    }

    // MARK: - Helpers

    private struct AppexSpec {
        let name: String
        let bundleId: String
        let binary: Data
    }

    private func gen(_ config: SyntheticMachOGenerator.MachOConfig) -> Data {
        SyntheticMachOGenerator.shared.generateThin(config: config)
    }

    private static func entXML(groups: [String], extra: String = "") -> String {
        var body = ""
        if !groups.isEmpty {
            body += "<key>com.apple.security.application-groups</key><array>"
            body += groups.map { "<string>\($0)</string>" }.joined()
            body += "</array>"
        }
        body += extra
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>\(body)</dict></plist>
        """
    }

    private func makeBundleAndIPA(
        appName: String,
        bundleId: String,
        executable: Data,
        frameworks: [String: Data] = [:],
        appexes: [AppexSpec] = [],
        extraFiles: [String: Data] = [:]
    ) throws -> (bundleURL: URL, ipaURL: URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("rt_r5_\(UUID().uuidString)")
        tempURLs.append(root)
        let appURL = root.appendingPathComponent("\(appName).app")
        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        let info: [String: Any] = [
            "CFBundleIdentifier": bundleId,
            "CFBundleExecutable": appName,
            "CFBundleName": appName,
            "CFBundleDisplayName": appName,
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "CFBundlePackageType": "APPL"
        ]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
            .write(to: appURL.appendingPathComponent("Info.plist"))
        try executable.write(to: appURL.appendingPathComponent(appName))
        for (rel, data) in frameworks {
            let dest = appURL.appendingPathComponent("Frameworks").appendingPathComponent(rel)
            try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: dest)
        }
        for ext in appexes {
            let extURL = appURL.appendingPathComponent("PlugIns").appendingPathComponent("\(ext.name).appex")
            try FileManager.default.createDirectory(at: extURL, withIntermediateDirectories: true)
            let extInfo: [String: Any] = [
                "CFBundleIdentifier": ext.bundleId,
                "CFBundleExecutable": ext.name,
                "CFBundlePackageType": "XPC!",
                "NSExtension": ["NSExtensionPointIdentifier": "com.apple.widgetkit-extension"]
            ]
            try PropertyListSerialization.data(fromPropertyList: extInfo, format: .xml, options: 0)
                .write(to: extURL.appendingPathComponent("Info.plist"))
            try ext.binary.write(to: extURL.appendingPathComponent(ext.name))
        }
        for (rel, data) in extraFiles {
            let dest = appURL.appendingPathComponent(rel)
            try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: dest)
        }
        let ipaURL = try MockIPAGenerator.shared.createIPA(config: .init(
            appName: appName,
            bundleIdentifier: bundleId,
            executableBinary: executable,
            embeddedFrameworks: frameworks,
            appExtensions: Dictionary(uniqueKeysWithValues: appexes.map { ($0.name, ($0.bundleId, $0.binary)) }),
            additionalFiles: extraFiles
        ))
        tempURLs.append(ipaURL)
        return (appURL, ipaURL)
    }

    /// Changes the `cmd` field of the LC_LOAD_DYLIB whose install name equals `path` (thin LE 64-bit).
    private func retagDylibCommand(in data: Data, path: String, newCmd: UInt32) -> Data {
        var out = data
        func u32(_ off: Int) -> UInt32 {
            out.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: off, as: UInt32.self) }
        }
        let ncmds = Int(u32(16))
        var cursor = 32
        for _ in 0..<ncmds {
            let cmd = u32(cursor)
            let size = Int(u32(cursor + 4))
            guard size >= 8 else { break }
            if cmd == UInt32(LC_LOAD_DYLIB) {
                let start = cursor + Int(u32(cursor + 8))
                let end = cursor + size
                if start < end {
                    let name = String(decoding: out.subdata(in: start..<end).prefix { $0 != 0 }, as: UTF8.self)
                    if name == path {
                        var le = newCmd.littleEndian
                        withUnsafeBytes(of: &le) { out.replaceSubrange(cursor..<(cursor + 4), with: $0) }
                        return out
                    }
                }
            }
            cursor += size
        }
        XCTFail("LC_LOAD_DYLIB \(path) not found")
        return out
    }

    private func wordsLE(_ words: [UInt32]) -> Data {
        var d = Data()
        for w in words {
            var le = w.littleEndian
            withUnsafeBytes(of: &le) { d.append(contentsOf: $0) }
        }
        return d
    }

    private func cstrings(_ strings: [String]) -> Data {
        var d = Data()
        for s in strings {
            d.append(contentsOf: s.utf8)
            d.append(0)
        }
        return d
    }
}

// MARK: - Coverage: private framework / symbol references held only as C-strings

extension AdversarialV130Round5EvasionTests {

    func test_r5_v1_privateFrameworkPathAndSymbolNameAsCStringsOnly_flagged() throws {
        let cases: [(name: String, groups: [String], strings: [String])] = [
            ("MediaFwCString", [], [Self.mediaFwPath, "CMSessionSetProperty"]),
            ("MediaFwCStringAlt", [], [Self.mediaFwPath, "AudioSessionSetCMProperty"]),
            ("BookFwCString", [], [Self.bookFwPath]),
            ("ContainerMgrCString", ["group.com.r5.test"], [
                "/usr/lib/system/libsystem_containermanager.dylib",
                "container_query_create",
                "container_query_get_single_result",
                "container_copy_sandbox_token"
            ])
        ]
        for c in cases {
            let bin = gen(.init(
                arch: .arm64,
                symbols: ["_dlopen", "_dlsym"],
                xmlEntitlements: c.groups.isEmpty ? nil : Self.entXML(groups: c.groups),
                textInstructions: [Self.retInsn],
                extraCStringLiterals: c.strings
            ))
            let bid = "com.r5.\(c.name.lowercased())"
            let macho = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: bid, appGroups: c.groups))
            XCTAssertEqual(macho.riskTier, .highRisk, "[\(c.name)] MachOScanner got \(macho.riskTier) \(macho.indicators.map(\.signature))")
            let (bundleURL, ipaURL) = try makeBundleAndIPA(appName: c.name, bundleId: bid, executable: bin)
            let bundle = try SecurityPipeline.shared.scanBundle(at: bundleURL)
            let ipa = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
            XCTAssertEqual(bundle.riskTier, .highRisk, "[\(c.name)] bundle got \(bundle.riskTier) \(bundle.indicators.map(\.signature))")
            XCTAssertEqual(ipa.riskTier, .highRisk, "[\(c.name)] IPA got \(ipa.riskTier) \(ipa.indicators.map(\.signature))")
        }
    }

    // MARK: - Coverage: re-export / upward linkage and install-name variants

    func test_r5_v2_reexportUpwardAndPathVariants_andReexportingEmbeddedFramework_flagged() throws {
        let variants: [(name: String, path: String, cmd: UInt32?)] = [
            ("Reexport", Self.mediaFwPath, 0x8000_001F),
            ("Upward", Self.mediaFwPath, 0x8000_0023),
            ("VersionsA", "/System/Library/PrivateFrameworks/MediaExperience.framework/Versions/A/MediaExperience", nil),
            ("Rpath", "@rpath/MediaExperience.framework/MediaExperience", nil),
            ("DoubleSlash", "/System/Library/PrivateFrameworks//MediaExperience.framework/MediaExperience", nil),
            ("BookReexport", Self.bookFwPath, 0x8000_001F)
        ]
        for v in variants {
            var bin = gen(.init(arch: .arm64, linkedDylibs: [v.path], textInstructions: [Self.retInsn]))
            if let cmd = v.cmd { bin = retagDylibCommand(in: bin, path: v.path, newCmd: cmd) }
            let parsed = try MachOParser.shared.parse(data: bin)
            XCTAssertTrue(parsed.linkedDylibPaths.contains(v.path), "[\(v.name)] parser must surface install name")
            let macho = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.r5.link", appGroups: []))
            XCTAssertEqual(macho.riskTier, .highRisk, "[\(v.name)] got \(macho.riskTier)")
        }

        let reexporter = retagDylibCommand(
            in: gen(.init(arch: .arm64, linkedDylibs: [Self.mediaFwPath], textInstructions: [Self.retInsn])),
            path: Self.mediaFwPath,
            newCmd: 0x8000_001F
        )
        let mainBin = gen(.init(arch: .arm64, linkedDylibs: ["@rpath/AnalyticsKit.framework/AnalyticsKit"], textInstructions: [Self.retInsn]))
        let (bundleURL, ipaURL) = try makeBundleAndIPA(
            appName: "Reexporter",
            bundleId: "com.r5.reexporter",
            executable: mainBin,
            frameworks: ["AnalyticsKit.framework/AnalyticsKit": reexporter]
        )
        let bundle = try SecurityPipeline.shared.scanBundle(at: bundleURL)
        let ipa = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        XCTAssertEqual(bundle.riskTier, .highRisk, "bundle: \(bundle.indicators.map(\.signature))")
        XCTAssertEqual(ipa.riskTier, .highRisk, "ipa: \(ipa.indicators.map(\.signature))")
        XCTAssertTrue(ipa.evidence.matchedSymbols.contains("CVE-2026-65339:MediaExperience.framework"))
    }

    // MARK: - Coverage: IOC strings stored in data sections

    func test_r5_v3_iocStringsInDataConstCFStringAndDataSections_flagged() throws {
        let iocs: [(literal: String, sig: String)] = [
            (IOCTokenArmor.tAudioDaemon, "CVE-2026-65339:com.apple.audio.audiomxd"),
            (IOCTokenArmor.tBookSQLite, "BookRestore:BLDatabaseManager.sqlite"),
            (IOCTokenArmor.tGestaltPlist, "MobileGestaltTamper:com.apple.MobileGestalt.plist")
        ]
        for (seg, sect) in [("__DATA_CONST", "__const"), ("__DATA", "__cfstring"), ("__DATA", "__data")] {
            for ioc in iocs {
                let bin = gen(.init(
                    arch: .arm64,
                    textInstructions: [Self.retInsn],
                    customSections: [(segName: seg, sectName: sect, flags: 0, payload: cstrings(["pad", ioc.literal]))]
                ))
                let f = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.r5.data", appGroups: []))
                XCTAssertEqual(f.riskTier, .highRisk, "[\(seg),\(sect)] \(ioc.literal) got \(f.riskTier)")
                XCTAssertTrue(f.evidence.matchedSymbols.contains(ioc.sig), "[\(seg),\(sect)] missing \(ioc.sig)")
            }
        }
    }

    // MARK: - Coverage: svc #0x80 in metadata-named section of a non-__TEXT executable segment

    func test_r5_v4_svcInMetadataNamedSectionOfNonTextExecutableSegment_flagged() throws {
        let payload = wordsLE([Self.nopInsn, Self.svcInsn, Self.retInsn])
        for (seg, sect) in [("__MALX", "__const"), ("__TEXT_EXEC", "__const"), ("__CODE2", "__swift5_types"), ("__CODE3", "__cstring")] {
            let bin = gen(.init(
                arch: .arm64,
                textInstructions: [Self.retInsn],
                customSections: [(segName: seg, sectName: sect, flags: 0, payload: payload)]
            ))
            let parsed = try MachOParser.shared.parse(data: bin)
            guard let segment = parsed.segments.first(where: { $0.name == seg }) else {
                XCTFail("segment \(seg) missing"); continue
            }
            XCTAssertNotEqual(segment.initialProtection & 0x04, 0, "precondition: \(seg) is executable")
            let f = try MachOScanner.shared.scan(binaryData: bin, context: .init(bundleId: "com.r5.svc", appGroups: []))
            XCTAssertEqual(f.riskTier, .highRisk, "[\(seg),\(sect)] svc count=\(parsed.scanDirectSyscalls().totalCount)")
        }
    }
}

// MARK: - Coverage: gating context for shared frameworks, entitlements, whitelist identity

extension AdversarialV130Round5EvasionTests {

    func test_r5_v5_sharedFrameworkLoadedByGroupedAppex_mainHasNoGroups_flagged() throws {
        // Shared framework lives in the main app's Frameworks/ but is linked by an .appex that declares App Groups,
        // so its code executes in a process that satisfies the Layer-1 App Group precondition.
        let sharedFw = gen(.init(
            arch: .arm64,
            symbols: [
                "_container_query_create",
                "_container_query_set_group_identifiers",
                "_container_query_get_single_result",
                "_container_copy_sandbox_token",
                "_sandbox_extension_consume"
            ],
            textInstructions: [Self.retInsn]
        ))
        let fwLink = "@rpath/SharedCore.framework/SharedCore"
        let mainBin = gen(.init(arch: .arm64, linkedDylibs: [fwLink], textInstructions: [Self.retInsn]))
        let appexBin = gen(.init(
            arch: .arm64,
            linkedDylibs: [fwLink],
            xmlEntitlements: Self.entXML(groups: ["group.com.r5.widget"]),
            textInstructions: [Self.retInsn]
        ))
        let (bundleURL, ipaURL) = try makeBundleAndIPA(
            appName: "SharedFwHost",
            bundleId: "com.r5.sharedfw",
            executable: mainBin,
            frameworks: ["SharedCore.framework/SharedCore": sharedFw],
            appexes: [AppexSpec(name: "Widget", bundleId: "com.r5.sharedfw.widget", binary: appexBin)]
        )
        let bundle = try SecurityPipeline.shared.scanBundle(at: bundleURL)
        let ipa = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        XCTAssertTrue(bundle.evidence.hasAppGroups, "precondition: combined App Groups include the appex group")
        XCTAssertEqual(bundle.riskTier, .highRisk, "bundle got \(bundle.riskTier) \(bundle.indicators.map(\.signature))")
        XCTAssertEqual(ipa.riskTier, .highRisk, "IPA got \(ipa.riskTier) \(ipa.indicators.map(\.signature))")
    }

    private static let dangerousEntitlementsXML = """
    <key>com.apple.private.security.no-sandbox</key><true/>
    <key>platform-application</key><true/>
    <key>com.apple.private.tcc.allow</key><array><string>kTCCServiceMicrophone</string><string>kTCCServicePhotos</string></array>
    """

    private func wqguardIdentityBinary(extraEntitlements: String) -> Data {
        gen(.init(
            arch: .arm64,
            symbols: ["_container_query_create", "_dlopen", "_dlsym"],
            xmlEntitlements: Self.entXML(groups: ["group.com.wqguard.app"], extra: extraEntitlements),
            textInstructions: [Self.retInsn],
            extraCStringLiterals: ["com.apple.containermanagerd"]
        ))
    }

    func test_r5_v6_wqguardIdentity_expectedSignaturesOnly_plusDangerousEntitlements_notKnownTool() throws {
        // Baseline: genuine-looking WQGuard self-identity profile is KNOWN_TOOL.
        let baseline = try makeBundleAndIPA(appName: "WQGuard", bundleId: "com.wqguard.app",
                                            executable: wqguardIdentityBinary(extraEntitlements: ""))
        let baseBundle = try SecurityPipeline.shared.scanBundle(at: baseline.bundleURL)
        XCTAssertEqual(baseBundle.riskTier, .knownTool, "precondition: baseline self-identity must be KNOWN_TOOL")

        // Same identity + same signatures, but additionally declaring sandbox-removal / platform / TCC grants.
        let variant = try makeBundleAndIPA(appName: "WQGuard", bundleId: "com.wqguard.app",
                                           executable: wqguardIdentityBinary(extraEntitlements: Self.dangerousEntitlementsXML))
        let bundle = try SecurityPipeline.shared.scanBundle(at: variant.bundleURL)
        let ipa = try IPAPackageScanner.shared.scan(ipaURL: variant.ipaURL)
        for (label, f) in [("bundle", bundle), ("ipa", ipa)] {
            XCTAssertFalse(f.isWhitelisted, "[\(label)] must not be whitelisted with no-sandbox/platform/tcc entitlements")
            XCTAssertEqual(f.riskTier, .highRisk, "[\(label)] got \(f.riskTier) \(f.indicators.map(\.signature))")
        }
    }

    func test_r5_v7_thirdPartySideloadedIPA_withDangerousEntitlementsOnly_notSafe() throws {
        let bin = gen(.init(
            arch: .arm64,
            xmlEntitlements: Self.entXML(groups: [], extra: Self.dangerousEntitlementsXML),
            textInstructions: [Self.retInsn]
        ))
        let (bundleURL, ipaURL) = try makeBundleAndIPA(appName: "Flashlight", bundleId: "com.r5.flashlight", executable: bin)
        let bundle = try SecurityPipeline.shared.scanBundle(at: bundleURL)
        let ipa = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        XCTAssertNotEqual(bundle.riskTier, .safe, "bundle: no-sandbox + platform-application + tcc.allow rated SAFE")
        XCTAssertNotEqual(ipa.riskTier, .safe, "ipa: no-sandbox + platform-application + tcc.allow rated SAFE")
    }

    func test_r5_v8_whitelistEngine_identityMutationsAndSignatureValues_refused() {
        let engine = WhitelistEngine()
        let goodGroups = ["group.com.wqguard.app"]
        let goodSigs = ["container_query_create", "dlopen", "dlsym"]
        XCTAssertTrue(engine.isWhitelisted(bundleId: "com.wqguard.app", appGroups: goodGroups, matchedSignatures: goodSigs).isWhitelisted,
                      "precondition: exact identity is whitelisted")

        let badBundleIds = [
            "com.wqguаrd.app",            // Cyrillic a
            "ｃｏｍ.wqguard.app",          // fullwidth
            "com.wqguard.app\u{0}",
            "com.wq\u{200B}guard.app",    // zero-width space
            "com.wqguard.app\u{200B}",
            "com.wqguard.app.evil",
            "com.wqguard.appx",
            "evil.com.wqguard.app",
            ""
        ]
        for bid in badBundleIds {
            XCTAssertFalse(engine.isWhitelisted(bundleId: bid, appGroups: goodGroups, matchedSignatures: goodSigs).isWhitelisted,
                           "bundle id \(bid.debugDescription) must not match")
        }

        let badGroupSets: [[String]] = [
            [],
            ["group.com.wqguard.app", "group.com.victim.bank"],
            ["group.com.wqguаrd.app"],
            ["group.com.wqguard.app.extra"],
            [" "],
            ["group.com.wqguard.app\u{0}"]
        ]
        for groups in badGroupSets {
            XCTAssertFalse(engine.isWhitelisted(bundleId: "com.wqguard.app.debug", appGroups: groups, matchedSignatures: goodSigs).isWhitelisted,
                           "groups \(groups.map(\.debugDescription)) must not match")
        }

        let extraSigs = ["*", "dlopen*", "com.apple.containermanagerd*", ".csstore\u{0}x", "container_query_*",
                         "container_query_get_single_result", "arm64:svc_0x80", "?"]
        for sig in extraSigs {
            XCTAssertFalse(engine.isWhitelisted(bundleId: "com.wqguard.app", appGroups: goodGroups, matchedSignatures: goodSigs + [sig]).isWhitelisted,
                           "unexpected signature \(sig.debugDescription) must break the subset check")
        }
    }

    func test_r5_v9_wqguardIdentity_withInjectedDylibInFrameworksOrDylibs_notKnownTool() throws {
        let tweak = gen(.init(arch: .arm64, linkedDylibs: ["/usr/lib/libc++.1.dylib"], textInstructions: [Self.retInsn]))
        let layouts: [(name: String, link: String, frameworks: [String: Data], extra: [String: Data])] = [
            ("FwHooker", "@rpath/libhooker.dylib", ["libhooker.dylib": tweak], [:]),
            ("DylibsFolder", "@executable_path/Dylibs/libSupport.dylib", [:], ["Dylibs/libSupport.dylib": tweak]),
            ("RpathTweak", "@rpath/AppTweakLoader.framework/AppTweakLoader", ["AppTweakLoader.framework/AppTweakLoader": tweak], [:])
        ]
        for l in layouts {
            let bin = gen(.init(
                arch: .arm64,
                linkedDylibs: [l.link],
                symbols: ["_container_query_create", "_dlopen", "_dlsym"],
                xmlEntitlements: Self.entXML(groups: ["group.com.wqguard.app"]),
                textInstructions: [Self.retInsn]
            ))
            let (bundleURL, ipaURL) = try makeBundleAndIPA(appName: "WQGuard", bundleId: "com.wqguard.app", executable: bin,
                                                           frameworks: l.frameworks, extraFiles: l.extra)
            let bundle = try SecurityPipeline.shared.scanBundle(at: bundleURL)
            let ipa = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
            XCTAssertFalse(bundle.isWhitelisted, "[\(l.name)] bundle whitelisted: \(bundle.indicators.map(\.signature))")
            XCTAssertFalse(ipa.isWhitelisted, "[\(l.name)] ipa whitelisted: \(ipa.indicators.map(\.signature))")
            XCTAssertNotEqual(bundle.riskTier, .knownTool)
            XCTAssertNotEqual(ipa.riskTier, .knownTool)
        }
    }

    // MARK: - IOCTokenArmor concurrency

    private static let expectedTokens: [String] = [
        "com.apple.audio.audiomxd",
        "com.apple.coremedia.audiomxd",
        "com.apple.bookassetd",
        "com.apple.itunesstored",
        "com.apple.itunesstored.private",
        "BLDatabaseManager.sqlite",
        "downloads.28.sqlitedb",
        "com.apple.MobileGestalt.plist",
        "systemgroup.com.apple.mobilegestaltcache"
    ]

    private static func decodeAllTokens() -> [String] {
        [
            IOCTokenArmor.tAudioDaemon,
            IOCTokenArmor.tCoreMediaDaemon,
            IOCTokenArmor.tBookDaemon,
            IOCTokenArmor.tStoreDaemon,
            IOCTokenArmor.tStorePrivPrefix,
            IOCTokenArmor.tBookSQLite,
            IOCTokenArmor.tDownloadsSQLite,
            IOCTokenArmor.tGestaltPlist,
            IOCTokenArmor.tGestaltGroup
        ]
    }

    func test_r5_v10_iocTokenArmor_exactUnderConcurrentPerformAndTaskGroup() async {
        XCTAssertEqual(Self.decodeAllTokens(), Self.expectedTokens)

        let iterations = 1_000
        let mismatches = ManagedAtomicCounter()
        DispatchQueue.concurrentPerform(iterations: iterations) { _ in
            if Self.decodeAllTokens() != Self.expectedTokens { mismatches.increment() }
        }
        XCTAssertEqual(mismatches.value, 0, "concurrentPerform produced mismatching decodes")

        let taskMismatches = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
            for _ in 0..<iterations {
                group.addTask { Self.decodeAllTokens() == Self.expectedTokens }
            }
            var bad = 0
            for await ok in group where !ok { bad += 1 }
            return bad
        }
        XCTAssertEqual(taskMismatches, 0, "TaskGroup produced mismatching decodes")

        // Catalog keys derived from the armor must equal the plaintext needles.
        XCTAssertEqual(Set(SignatureCatalog.standaloneExploitStringRules.keys),
                       Set(Self.expectedTokens.filter { $0 != "com.apple.itunesstored.private" }))
    }
}

/// Minimal lock-based counter for concurrentPerform (Sendable under strict concurrency).
private final class ManagedAtomicCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.lock(); count += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
}
