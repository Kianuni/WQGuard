import XCTest
import Foundation
import Compression
import JavaScriptCore
@testable import WQGuardCore

/// Comprehensive empirical regression suite for WQGuard v1.2.1 covering all P0 & P1
/// findings from the pre-release red-team security audit, including real Apple `codesign`
/// CoreEntitlements DER (`0x70`/`0xb0`), real `JavaScriptCore` execution of `brotli-guard.js`,
/// real `clang`/`lipo`/`strip` `arm64`+`arm64e` + `__objc_methname` binaries, `.appex` isolation,
/// ZIP symlink/bomb/double-dot edge cases, and strict zero-trust sideload tool handling.
final class SecurityAuditV121RegressionTests: XCTestCase {

    private var repoRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // WQGuardCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // WQGuard
    }

    // MARK: - Helpers

    private func runProcess(_ executable: String, args: [String]) throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: executable)
        proc.arguments = args
        let errPipe = Pipe()
        proc.standardError = errPipe
        proc.standardOutput = Pipe()
        try proc.run()
        proc.waitUntilExit()
        if proc.terminationStatus != 0 {
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errText = String(data: errData, encoding: .utf8) ?? ""
            XCTFail("\(executable) exited with \(proc.terminationStatus): \(errText)")
        }
    }

    /// Builds a minimal SuperBlob (`0xfade0cc0`) containing custom `(slotType, blobData)` payloads
    /// (where each `blobData` already begins with its 8-byte `(magic, length)` blob header).
    private func buildSuperBlob(slots: [(type: UInt32, blob: Data)]) -> Data {
        let headerSize = 12 + slots.count * 8
        let totalLength = headerSize + slots.reduce(0) { $0 + $1.blob.count }
        var out = Data()
        func appendBE32(_ v: UInt32) {
            var be = v.bigEndian
            out.append(Data(bytes: &be, count: 4))
        }
        appendBE32(CSBlobConstants.superBlobMagic)
        appendBE32(UInt32(totalLength))
        appendBE32(UInt32(slots.count))

        var currentOffset = headerSize
        for s in slots {
            appendBE32(s.type)
            appendBE32(UInt32(currentOffset))
            currentOffset += s.blob.count
        }
        for s in slots {
            out.append(s.blob)
        }
        return out
    }

    private func wrapCSBlob(magic: UInt32, payload: Data) -> Data {
        var out = Data()
        var m = magic.bigEndian
        var l = UInt32(8 + payload.count).bigEndian
        out.append(Data(bytes: &m, count: 4))
        out.append(Data(bytes: &l, count: 4))
        out.append(payload)
        return out
    }

    /// Minimal ZIP builder supporting custom `externalFileAttributes`, `compressionMethod`, and spoofed `uncompressedSize`.
    private struct RawZipEntrySpec {
        var path: String
        var rawPayload: Data
        var compressionMethod: UInt16 = 0 // 0 = Store, 8 = Deflate
        var declaredUncompressedSize: UInt32? = nil
        var externalAttributes: UInt32 = (0o100644 << 16)
    }

    private func buildCustomZip(entries: [RawZipEntrySpec]) -> Data {
        var archive = Data()
        var cd = Data()

        func u16(_ v: UInt16) -> Data { var le = v.littleEndian; return Data(bytes: &le, count: 2) }
        func u32(_ v: UInt32) -> Data { var le = v.littleEndian; return Data(bytes: &le, count: 4) }

        for entry in entries {
            let localOffset = UInt32(archive.count)
            let pathBytes = Data(entry.path.utf8)
            let compSize = UInt32(entry.rawPayload.count)
            let uncompSize = entry.declaredUncompressedSize ?? compSize

            // Local File Header
            archive.append(u32(0x04034b50))
            archive.append(u16(20))
            archive.append(u16(0))
            archive.append(u16(entry.compressionMethod))
            archive.append(u16(0))
            archive.append(u16(0))
            archive.append(u32(0))
            archive.append(u32(compSize))
            archive.append(u32(uncompSize))
            archive.append(u16(UInt16(pathBytes.count)))
            archive.append(u16(0))
            archive.append(pathBytes)
            archive.append(entry.rawPayload)

            // Central Directory Header
            cd.append(u32(0x02014b50))
            cd.append(u16(0x031e)) // Unix creator
            cd.append(u16(20))
            cd.append(u16(0))
            cd.append(u16(entry.compressionMethod))
            cd.append(u16(0))
            cd.append(u16(0))
            cd.append(u32(0))
            cd.append(u32(compSize))
            cd.append(u32(uncompSize))
            cd.append(u16(UInt16(pathBytes.count)))
            cd.append(u16(0))
            cd.append(u16(0))
            cd.append(u16(0))
            cd.append(u16(0))
            cd.append(u32(entry.externalAttributes))
            cd.append(u32(localOffset))
            cd.append(pathBytes)
        }

        let cdOffset = UInt32(archive.count)
        let cdSize = UInt32(cd.count)
        archive.append(cd)

        // EOCD
        archive.append(u32(0x06054b50))
        archive.append(u16(0))
        archive.append(u16(0))
        archive.append(u16(UInt16(entries.count)))
        archive.append(u16(UInt16(entries.count)))
        archive.append(u32(cdSize))
        archive.append(u32(cdOffset))
        archive.append(u16(0))
        return archive
    }

    private func rawDeflate(_ input: Data) -> Data {
        let dstCap = max(input.count + 512, 4096)
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: dstCap)
        defer { dst.deallocate() }
        let written = input.withUnsafeBytes { src -> Int in
            guard let base = src.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return compression_encode_buffer(dst, dstCap, base, input.count, nil, COMPRESSION_ZLIB)
        }
        return Data(bytes: dst, count: written)
    }

    // MARK: - P0-1: Real Apple `codesign` CoreEntitlements DER (`0x70` / `0xb0`)

    func testP0_1_RealAppleCodesignDERSlot7Shadowing_EmptySlot5XML_ExtractsGroupsAndPrivateEntitlements() throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent("wqg_p0_1_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let cSource = tmpDir.appendingPathComponent("mini.c")
        try "int main(void) { return 0; }\n".write(to: cSource, atomically: true, encoding: .utf8)

        let binURL = tmpDir.appendingPathComponent("mini_arm64")
        try runProcess("/usr/bin/clang", args: ["-arch", "arm64", "-Os", cSource.path, "-o", binURL.path])

        let entPlistURL = tmpDir.appendingPathComponent("ent.plist")
        let entXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.com.wqguard.realcodesign.der</string>
                <string>group.com.wqguard.second.der</string>
            </array>
            <key>com.apple.private.photos.allow</key>
            <true/>
        </dict>
        </plist>
        """
        try entXML.write(to: entPlistURL, atomically: true, encoding: .utf8)

        try runProcess("/usr/bin/codesign", args: [
            "-f", "-s", "-",
            "--entitlements", entPlistURL.path,
            "--generate-entitlement-der",
            binURL.path
        ])

        let signedMachO = try Data(contentsOf: binURL)
        let parsedFile = try MachOParser.parse(data: signedMachO)
        guard let csData = parsedFile.codeSignatureData else {
            XCTFail("Expected LC_CODE_SIGNATURE in codesigned Mach-O")
            return
        }

        // Locate the real Apple-generated 0xfade7172 Slot 7 DER blob inside the SuperBlob
        let derMagicBE = Data([0xfa, 0xde, 0x71, 0x72])
        guard let derRange = csData.range(of: derMagicBE) else {
            XCTFail("Expected Slot 7 0xfade7172 DER blob generated by /usr/bin/codesign")
            return
        }
        let derStart = derRange.lowerBound
        let derLen: Int = csData.subdata(in: (derStart + 4)..<(derStart + 8)).withUnsafeBytes {
            Int($0.loadUnaligned(as: UInt32.self).bigEndian)
        }
        let fullDerBlob = csData.subdata(in: derStart..<(derStart + derLen))
        let derPayload = fullDerBlob.dropFirst(8)

        // Ground-truth verification: Apple CoreEntitlements v1 begins with 0x70 ([APPLICATION 16]) and contains 0xb0 ([CONTEXT 16])
        XCTAssertEqual(derPayload.first, 0x70, "Real Apple CoreEntitlements DER root tag must be 0x70 ([APPLICATION 16])")
        XCTAssertTrue(derPayload.contains(0xb0), "Real Apple CoreEntitlements DER must contain 0xb0 ([CONTEXT 16]) container")

        // Build an adversarial SuperBlob: Slot 5 has an EMPTY XML <dict/>, while Slot 7 has real Apple DER!
        let emptyXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict></dict></plist>
        """.data(using: .utf8)!
        let emptyXmlBlob = wrapCSBlob(magic: CSBlobConstants.entitlementXmlMagic, payload: emptyXML)
        let shadowedSuperBlob = buildSuperBlob(slots: [
            (type: CSBlobConstants.slotEntitlements, blob: emptyXmlBlob),
            (type: CSBlobConstants.slotDerEntitlements, blob: fullDerBlob)
        ])

        // 1. CSBlobParser SuperBlob extraction
        let superResult = try CSBlobParser.shared.parseSuperBlob(shadowedSuperBlob)
        XCTAssertTrue(superResult.hasAppGroups)
        XCTAssertEqual(Set(superResult.appGroups), Set(["group.com.wqguard.realcodesign.der", "group.com.wqguard.second.der"]))

        // 2. CSBlobParser merged entitlements dictionary includes DER boolean keys (e.g. private Photos TCC bypass)
        let mergedDict = CSBlobParser.shared.parseMergedEntitlements(from: shadowedSuperBlob)
        XCTAssertEqual(mergedDict["com.apple.private.photos.allow"] as? Bool, true)
        let dictGroups = mergedDict["com.apple.security.application-groups"] as? [String] ?? []
        XCTAssertTrue(dictGroups.contains("group.com.wqguard.realcodesign.der"))

        // 3. Full IPAPackageScanner end-to-end check with empty XML Slot 5 + real Apple DER Slot 7
        let machoShadowed = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["_container_copy_sandbox_token", "_sandbox_extension_consume"],
            xmlEntitlements: "<plist version=\"1.0\"><dict/></plist>",
            rawCodeSignatureSlot: (slot: CSBlobConstants.slotDerEntitlements, magic: CSBlobConstants.entitlementDerMagic, data: Data(derPayload))
        ))
        let infoPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.evil.dershadower",
            "CFBundleDisplayName": "DERShadower",
            "CFBundleExecutable": "DERShadower",
            "CFBundleShortVersionString": "1.0"
        ], format: .xml, options: 0)
        let ipaData = buildCustomZip(entries: [
            .init(path: "Payload/DERShadower.app/Info.plist", rawPayload: infoPlist),
            .init(path: "Payload/DERShadower.app/DERShadower", rawPayload: machoShadowed, externalAttributes: (0o100755 << 16))
        ])
        let ipaURL = tmpDir.appendingPathComponent("DERShadower.ipa")
        try ipaData.write(to: ipaURL)

        let finding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        XCTAssertEqual(finding.riskTier, .highRisk, "Empty XML Slot 5 + real Apple DER Slot 7 exploit IPA must be flagged High Risk")
        XCTAssertTrue(finding.evidence.appGroups.contains("group.com.wqguard.realcodesign.der"))
        XCTAssertTrue(finding.indicators.contains { $0.category == "Private Photos Bypass" })
    }

    // MARK: - P0-2: Real JavaScriptCore Execution of `brotli-guard.js` & Surge Module Syntax

    func testP0_2_BrotliGuardJS_RealJavaScriptCoreExecution_AllProxyLifecycles() throws {
        let scriptURL = repoRoot.appendingPathComponent("Shields/scripts/brotli-guard.js")
        let scriptSource = try String(contentsOf: scriptURL, encoding: .utf8)

        func runBrotliGuard(isQuanX: Bool, contentEncoding: String?, script: String = scriptSource) -> JSValue? {
            let ctx = JSContext()!
            var captured: JSValue?
            let doneBlock: @convention(block) (JSValue) -> Void = { val in
                captured = val
            }
            ctx.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)

            var headers: [String: String] = [:]
            if let ce = contentEncoding {
                headers["Content-Encoding"] = ce
            }
            ctx.setObject(["status": 200, "headers": headers], forKeyedSubscript: "$response" as NSString)
            if isQuanX {
                ctx.setObject(["valueForKey": "stub"], forKeyedSubscript: "$prefs" as NSString)
            }
            _ = ctx.evaluateScript(script)
            XCTAssertNil(ctx.exception, "JavaScript exception: \(String(describing: ctx.exception))")
            return captured
        }

        // 1. Surge / Shadowrocket / Loon / Stash http-response lifecycle with unsolicited `br`
        for maliciousCE in ["br", "gzip, br", "BR;q=1.0"] {
            guard let res = runBrotliGuard(isQuanX: false, contentEncoding: maliciousCE) else {
                XCTFail("Expected $done invocation for \(maliciousCE)")
                return
            }
            XCTAssertEqual(res.forProperty("status")?.toInt32(), 403, "Must return top-level status: 403 for \(maliciousCE)")
            XCTAssertTrue(res.forProperty("response")?.isUndefined == true, "Must NEVER wrap inside { response: ... } during http-response")
            XCTAssertTrue(res.forProperty("body")?.isUndefined == true, "Must NEVER pass body under requires-body=false")
            let hdrs = res.forProperty("headers")
            XCTAssertEqual(hdrs?.forProperty("Content-Length")?.toString(), "0")
            XCTAssertEqual(hdrs?.forProperty("Connection")?.toString(), "close")
        }

        // 2. Benign encodings pass through untouched ($done({}))
        for benignCE in [nil, "gzip", "deflate", "gzip, deflate", "br-custom-token"] {
            guard let res = runBrotliGuard(isQuanX: false, contentEncoding: benignCE) else {
                XCTFail("Expected $done({}) for benign encoding \(String(describing: benignCE))")
                return
            }
            XCTAssertTrue(res.forProperty("status")?.isUndefined == true, "Benign encoding \(String(describing: benignCE)) must pass through")
        }

        // 3. Quantumult X script-response-header lifecycle
        guard let qxRes = runBrotliGuard(isQuanX: true, contentEncoding: "br") else {
            XCTFail("Expected $done for Quantumult X")
            return
        }
        XCTAssertEqual(qxRes.forProperty("status")?.toString(), "HTTP/1.1 403 Forbidden")
        XCTAssertTrue(qxRes.forProperty("body")?.isUndefined == true)

        // 4. Execute embedded Stash YAML script-providers payload via JavaScriptCore too
        let stashFile = try String(contentsOf: repoRoot.appendingPathComponent("Shields/Stash/WQGuard-Brotli-Shield.stoverride"), encoding: .utf8)
        guard let range = stashFile.range(of: "payload: |") else {
            XCTFail("Missing payload: | in Stash stoverride")
            return
        }
        let stashJS = stashFile[range.upperBound...]
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { line -> String in
                var s = String(line)
                if s.hasPrefix("      ") { s.removeFirst(6) }
                return s
            }
            .joined(separator: "\n")
        guard let stashRes = runBrotliGuard(isQuanX: false, contentEncoding: "br", script: stashJS) else {
            XCTFail("Expected $done from Stash inline payload")
            return
        }
        XCTAssertEqual(stashRes.forProperty("status")?.toInt32(), 403)
        XCTAssertTrue(stashRes.forProperty("response")?.isUndefined == true)
        XCTAssertTrue(stashRes.forProperty("body")?.isUndefined == true)

        // 5. Verify both Surge .sgmodule files on disk match valid Surge syntax
        for relPath in ["Shields/Surge/WQGuard-Brotli-Shield.sgmodule", "Surge/WQGuard-Brotli-Shield.sgmodule"] {
            let sg = try String(contentsOf: repoRoot.appendingPathComponent(relPath), encoding: .utf8)
            XCTAssertTrue(sg.contains("#!version=1.2.1"), "\(relPath) must carry version 1.2.1")
            XCTAssertTrue(sg.contains("script-path=https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/scripts/brotli-guard.js"))
            XCTAssertFalse(sg.contains("script-text="), "\(relPath) must not use invalid script-text=")
            XCTAssertTrue(SurgeBrotliShieldHelper.shared.validateModule(content: sg).isCompliant)
        }
    }

    // MARK: - P0-3: `.appex` Independent `CSBlob` & Nested Dylib Escape Detection

    func testP0_3_AppexExtensionIndependentCSBlob_MainAppHasZeroAppGroups_CaughtHighRisk() throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent("wqg_p0_3_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        // Main app binary: completely clean, 0 App Groups, 0 exploit symbols
        let cleanMain = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"]
        ))
        let mainPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.innocent.weather",
            "CFBundleDisplayName": "SunnyWeather",
            "CFBundleExecutable": "SunnyWeather",
            "CFBundleShortVersionString": "2.0"
        ], format: .xml, options: 0)

        // Malicious Widget .appex: carries its OWN App Group entitlement + worse_query exploit symbols
        let evilAppexMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/system/libsystem_containermanager.dylib"],
            symbols: ["_container_query_create", "_container_copy_sandbox_token", "_sandbox_extension_consume"],
            xmlEntitlements: SyntheticMachOGenerator.createXMLEntitlements(appGroups: ["group.com.innocent.weather.widget"])
        ))
        let appexPlist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.innocent.weather.widget",
            "CFBundleDisplayName": "WeatherWidget",
            "CFBundleExecutable": "WeatherWidget"
        ], format: .xml, options: 0)

        // 1. Test via IPAPackageScanner
        let ipaData = buildCustomZip(entries: [
            .init(path: "Payload/SunnyWeather.app/Info.plist", rawPayload: mainPlist),
            .init(path: "Payload/SunnyWeather.app/SunnyWeather", rawPayload: cleanMain, externalAttributes: (0o100755 << 16)),
            .init(path: "Payload/SunnyWeather.app/PlugIns/WeatherWidget.appex/Info.plist", rawPayload: appexPlist),
            .init(path: "Payload/SunnyWeather.app/PlugIns/WeatherWidget.appex/WeatherWidget", rawPayload: evilAppexMachO, externalAttributes: (0o100755 << 16))
        ])
        let ipaURL = tmpDir.appendingPathComponent("AppexEscape.ipa")
        try ipaData.write(to: ipaURL)

        let ipaFinding = try IPAPackageScanner.shared.scan(ipaURL: ipaURL)
        XCTAssertEqual(ipaFinding.riskTier, .highRisk, ".appex with independent App Group + worse_query must be flagged High Risk even when main app has 0 App Groups")
        XCTAssertTrue(ipaFinding.evidence.appGroups.contains("group.com.innocent.weather.widget"))
        XCTAssertTrue(ipaFinding.indicators.contains { $0.signature == "container_copy_sandbox_token" })

        // 2. Test via SecurityPipeline.scanBundle on unpacked .app directory
        let appDir = tmpDir.appendingPathComponent("SunnyWeather.app")
        let plugDir = appDir.appendingPathComponent("PlugIns/WeatherWidget.appex")
        try FileManager.default.createDirectory(at: plugDir, withIntermediateDirectories: true)
        try mainPlist.write(to: appDir.appendingPathComponent("Info.plist"))
        try cleanMain.write(to: appDir.appendingPathComponent("SunnyWeather"))
        try appexPlist.write(to: plugDir.appendingPathComponent("Info.plist"))
        try evilAppexMachO.write(to: plugDir.appendingPathComponent("WeatherWidget"))

        let bundleFinding = try SecurityPipeline().scanBundle(at: appDir)
        XCTAssertEqual(bundleFinding.riskTier, .highRisk)
        XCTAssertTrue(bundleFinding.evidence.appGroups.contains("group.com.innocent.weather.widget"))
    }

    // MARK: - P0-4: `CVE-2026-86950` Backport Patches (`iOS 18.7.11` & `iOS 26.7.1` & `iOS 27.0`)

    func testP0_4_CVE2026_86950_OfficialAppleBackportPatches() {
        let engine = FirmwarePostureEngine.shared
        XCTAssertTrue(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 18, minor: 7, patch: 10)))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 18, minor: 7, patch: 11)))
        XCTAssertTrue(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 26, minor: 7, patch: 0)))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 26, minor: 7, patch: 1)))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 26, minor: 7, patch: 3)))
        XCTAssertFalse(engine.isVulnerable(.coreGraphics2D, in: SystemOSVersion(major: 27, minor: 0, patch: 0)))
    }

    // MARK: - P1-1: Strict Zero-Trust Whitelist & Sideloading Tool Policy

    func testP1_1_StrictZeroTrust_WhitelistSpoofingRejected_And_AllThirdPartySideloadToolsNeverWhitelisted() throws {
        let wl = WhitelistEngine()

        // 1. Wildcard suffix spoofing (`com.wqguard.app.pro`) MUST be rejected
        let wildcardSpoof = wl.isWhitelisted(
            bundleId: "com.wqguard.app.pro",
            appGroups: ["group.com.wqguard.app"],
            matchedSignatures: []
        )
        XCTAssertFalse(wildcardSpoof.isWhitelisted, "com.wqguard.app.pro must never match built-in WQGuard rule")

        // 2. Trojanized `com.wqguard.app` carrying actual exploit APIs MUST be rejected by Step 4 expectedSignatures
        for forbiddenSig in ["container_copy_sandbox_token", "sandbox_extension_consume", "libsystem_containermanager.dylib", "fsgetpath"] {
            let trojanSpoof = wl.isWhitelisted(
                bundleId: "com.wqguard.app",
                appGroups: ["group.com.wqguard.app"],
                matchedSignatures: [forbiddenSig]
            )
            XCTAssertFalse(trojanSpoof.isWhitelisted, "Trojanized com.wqguard.app carrying \(forbiddenSig) must NEVER be whitelisted")
        }

        // 3. Legitimate WQGuard self-scan with only read-only diagnostic string literals matches Known Tool
        let legitSelf = wl.isWhitelisted(
            bundleId: "com.wqguard.app",
            appGroups: ["group.com.wqguard.app"],
            matchedSignatures: ["com.apple.containermanagerd", ".csstore"]
        )
        XCTAssertTrue(legitSelf.isWhitelisted)
        XCTAssertEqual(legitSelf.toolName, "WQGuard")

        // 4. Third-party sideloading tools MUST NEVER be auto-whitelisted (Strict Zero Trust!)
        let thirdPartyTools: [(bundleId: String, name: String, group: String)] = [
            ("kh.crysalis.feather", "Feather", "group.kh.crysalis.feather"),
            ("com.esign.ios", "全能签", "group.com.esign.shared"),
            ("com.gbox.pub", "GBox", "group.com.gbox.shared"),
            ("com.usescarlet.scarlet", "Scarlet", "group.com.usescarlet"),
            ("com.SideStore.SideStore", "SideStore", "group.com.SideStore.SideStore"),
            ("com.rileytestut.AltStore", "AltStore", "group.com.rileytestut.AltStore"),
            ("com.SideStore.LocalDevVPN", "LocalDevVPN", "group.com.SideStore.LocalDevVPN"),
            ("com.stik.stikdebug", "StikDebug", "group.com.stik.stikdebug")
        ]

        let rawToolDicts: [[String: Any]] = thirdPartyTools.map { tool in
            [
                "CFBundleIdentifier": tool.bundleId,
                "CFBundleDisplayName": tool.name,
                "CFBundleShortVersionString": "1.0",
                "ApplicationType": "User",
                "SignerIdentity": "Apple Development: Test User",
                "ProfileValidated": true,
                "Entitlements": [
                    "com.apple.developer.team-identifier": "TEAM123456",
                    "com.apple.security.application-groups": [tool.group],
                    "get-task-allow": true
                ]
            ]
        }
        let plistData = try PropertyListSerialization.data(fromPropertyList: rawToolDicts, format: .xml, options: 0)
        let registryScanner = InstalledAppRegistryScanner(whitelistEngine: wl)
        let records = try registryScanner.parseSnapshotData(plistData)
        let registryFindings = registryScanner.evaluateRecords(records, includeAppStoreApps: false)
        XCTAssertEqual(registryFindings.count, thirdPartyTools.count)

        for finding in registryFindings {
            XCTAssertFalse(finding.isWhitelisted, "Strict zero trust: \(finding.displayName) (\(finding.bundleId)) must NEVER be auto-whitelisted")
            XCTAssertNotEqual(finding.riskTier, .knownTool, "Strict zero trust: \(finding.displayName) must NEVER default to .knownTool")
            XCTAssertEqual(finding.riskTier, .caution, "Third-party sideload tool \(finding.displayName) with App Groups must surface as .caution")
        }

        // 5. OnDeviceAppProbeScanner must also NEVER auto-whitelist third-party sideloading tools
        let probeScanner = OnDeviceAppProbeScanner(whitelistEngine: wl)
        let probeFindings = probeScanner.evaluateProbes { scheme in
            ["feather", "sidestore", "altstore", "esign", "gbox", "scarlet", "localdevvpn", "stikdebug"].contains(scheme.lowercased())
        }
        XCTAssertFalse(probeFindings.isEmpty)
        for pf in probeFindings {
            XCTAssertFalse(pf.isWhitelisted, "Probe finding \(pf.displayName) must never be auto-whitelisted")
            XCTAssertNotEqual(pf.riskTier, .knownTool, "Probe finding \(pf.displayName) must never default to .knownTool")
            XCTAssertEqual(pf.riskTier, .caution)
        }
    }

    // MARK: - P1-2: `fsgetpath` (`bad_query` CM-05) Without App Groups

    func testP1_2_StandaloneFsgetpathReconnaissance_ZeroAppGroups_FlaggedHighRisk() throws {
        let reconMachO = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_fsgetpath"]
        ))
        let details = try MachOScanner.shared.parseMachO(data: reconMachO)
        let finding = MachOScanner.shared.scan(
            details: details,
            context: .init(bundleId: "com.recon.pathleak", displayName: "PathLeak", appGroups: [])
        )
        XCTAssertEqual(finding.riskTier, .highRisk)
        XCTAssertTrue(finding.indicators.contains { $0.signature == "fsgetpath" && $0.severity == .highRisk })
    }

    // MARK: - P1-3: Word-Token Boundary Brand Impersonation (Zero `"tg"` / `"trust"` False Positives)

    func testP1_3_BrandImpersonation_WordTokenBoundaries_ZeroFalsePositivesOnNetGuardPostgRESTGitGraphZeroTrust() {
        let benignApps: [(bundleId: String, name: String)] = [
            ("eu.faircode.netguard", "NetGuard"),
            ("io.postgrest.studio", "PostgREST Client"),
            ("dev.gitgraph.ios", "GitGraph"),
            ("com.cloudflare.zerotrust", "ZeroTrust"),
            ("com.acme.zerotrust.agent", "Zero Trust Access"),
            ("org.PostgresApp.viewer", "PostgresGUI")
        ]

        for app in benignApps {
            let inds = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: app.bundleId,
                displayName: app.name,
                installChannel: .developerSideloaded,
                cryptid: 0
            )
            XCTAssertTrue(inds.isEmpty, "Benign app '\(app.name)' (\(app.bundleId)) must produce ZERO brand impersonation false positives, got: \(inds)")
        }

        let maliciousClones: [(bundleId: String, name: String)] = [
            ("com.evil.tgclient", "TG Pro"),
            ("org.telegram.mod.drainer", "Telegram"),
            ("com.fake.wallet", "Trust Wallet"),
            ("com.sixdays.trust.mod", "MyCrypto")
        ]

        for clone in maliciousClones {
            let inds = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: clone.bundleId,
                displayName: clone.name,
                installChannel: .developerSideloaded,
                cryptid: 0
            )
            XCTAssertEqual(inds.first?.severity, .highRisk, "Sideloaded clone '\(clone.name)' (\(clone.bundleId)) must be flagged High Risk")
        }
    }

    // MARK: - P1-4: `.app/Dylibs/`, FAT `arm64`+`arm64e` + `__objc_methname`, ZIP Hardening & `.tipa`

    func testP1_4_RealClangLipoStrippedFAT_Arm64Clean_Arm64eMaliciousWithObjcMethname_CaughtHighRisk() throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent("wqg_p1_4_fat_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        // Slice 1 (arm64): completely benign C binary
        let cleanC = tmpDir.appendingPathComponent("clean.c")
        try "int main(void) { return 0; }\n".write(to: cleanC, atomically: true, encoding: .utf8)
        let arm64URL = tmpDir.appendingPathComponent("slice_arm64")
        try runProcess("/usr/bin/clang", args: ["-arch", "arm64", "-Os", cleanC.path, "-o", arm64URL.path])

        // Slice 2 (arm64e): Objective-C binary using NSFileManager symlink selector + PHPhotoLibrary systemPhotoLibrary selector,
        // stripped with `/usr/bin/strip -x` so local symbols are gone and selectors live in `__objc_methname`!
        let evilObjC = tmpDir.appendingPathComponent("evil.m")
        let objcCode = """
        #import <Foundation/Foundation.h>
        #include <dlfcn.h>

        @interface FakePhotos : NSObject
        + (id)systemPhotoLibrary;
        @end

        int main(void) {
            void *h = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);
            void *s = dlsym(h, "printf");
            (void)s;
            [[NSFileManager defaultManager] createSymbolicLinkAtPath:@"/tmp/a" withDestinationPath:@"/tmp/b" error:nil];
            id p = [NSClassFromString(@"PHPhotoLibrary") performSelector:@selector(systemPhotoLibrary)];
            (void)p;
            return 0;
        }
        """
        try objcCode.write(to: evilObjC, atomically: true, encoding: .utf8)
        let arm64eURL = tmpDir.appendingPathComponent("slice_arm64e")
        try runProcess("/usr/bin/clang", args: ["-arch", "arm64e", "-Os", "-fobjc-arc", "-framework", "Foundation", evilObjC.path, "-o", arm64eURL.path])
        try runProcess("/usr/bin/strip", args: ["-x", arm64eURL.path])

        // Combine with lipo: clean arm64 FIRST, malicious stripped arm64e SECOND
        let fatURL = tmpDir.appendingPathComponent("UniversalShadow")
        try runProcess("/usr/bin/lipo", args: ["-create", arm64URL.path, arm64eURL.path, "-output", fatURL.path])

        let fatData = try Data(contentsOf: fatURL)
        let details = try MachOScanner.shared.parseMachO(data: fatData)
        XCTAssertTrue(details.symbols.contains("createSymbolicLinkAtPath:withDestinationPath:error:"), "Must extract ObjC symlink selector from __objc_methname in second arm64e slice")
        XCTAssertTrue(details.symbols.contains("systemPhotoLibrary"), "Must extract systemPhotoLibrary selector from __objc_methname in second arm64e slice")

        let finding = MachOScanner.shared.scan(
            details: details,
            context: .init(
                bundleId: "com.shadow.universal",
                displayName: "UniversalShadow",
                installChannel: .developerSideloaded,
                appGroups: ["group.com.shadow.universal"]
            )
        )
        XCTAssertEqual(finding.riskTier, .highRisk, "FAT arm64+arm64e binary with dlopen/dlsym + ObjC symlink selector + systemPhotoLibrary must be flagged High Risk")
        XCTAssertTrue(finding.indicators.contains { $0.category == "Heuristic / Behavioral Tuple" })

        let photosInds = ExpandedThreatCatalog.evaluatePhotosBypass(
            linkedDylibs: details.linkedDylibs,
            symbols: details.symbols,
            entitlements: [:],
            cryptid: details.cryptid
        )
        XCTAssertTrue(photosInds.contains { $0.category == "Private Photos Bypass" && $0.severity == .highRisk })
    }

    func testP1_4_UnreferencedDylibsFolder_DoubleDotAsset_ZipSlip_DeflateBomb_SymlinkStrip_And_TipaSupport() async throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent("wqg_p1_4_zip_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let cleanExec = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_main"]
        ))
        // Unreferenced injected dylib in `.app/Dylibs/AzuleTweak.dylib` carrying `fsgetpath`
        let injectedDylib = SyntheticMachOGenerator.shared.generateThin(config: .init(
            arch: .arm64,
            cryptid: 0,
            linkedDylibs: ["/usr/lib/libSystem.B.dylib"],
            symbols: ["_fsgetpath"]
        ))
        let plistData = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleIdentifier": "com.sideload.tweaked",
            "CFBundleDisplayName": "TweakedClient",
            "CFBundleExecutable": "TweakedClient",
            "CFBundleShortVersionString": "1.2.1"
        ], format: .xml, options: 0)

        // 1. Valid `.tipa` containing:
        //    - legitimate `icon..png` double-dot filename (must NOT trigger false-positive Zip-Slip)
        //    - `.app/Dylibs/AzuleTweak.dylib` unreferenced by LC_LOAD_DYLIB (must be scanned and flagged!)
        //    - POSIX symlink entry `Payload/TweakedClient.app/evil_link` (`0o120777 << 16`, must be stripped and never written to disk!)
        let tipaData = buildCustomZip(entries: [
            .init(path: "Payload/TweakedClient.app/Info.plist", rawPayload: plistData),
            .init(path: "Payload/TweakedClient.app/TweakedClient", rawPayload: cleanExec, externalAttributes: (0o100755 << 16)),
            .init(path: "Payload/TweakedClient.app/icon..png", rawPayload: Data([0x89, 0x50, 0x4e, 0x47])),
            .init(path: "Payload/TweakedClient.app/Dylibs/AzuleTweak.dylib", rawPayload: injectedDylib, externalAttributes: (0o100755 << 16)),
            .init(path: "Payload/TweakedClient.app/evil_link", rawPayload: Data("/etc/passwd".utf8), externalAttributes: (0o120777 << 16))
        ])
        let tipaURL = tmpDir.appendingPathComponent("TweakedClient.tipa")
        try tipaData.write(to: tipaURL)

        // Verify symlink entry is never materialized inside temporary unpack sandbox
        try IPAPackageScanner.shared.withTemporarySandbox(ipaURL: tipaURL) { bundleURL, _ in
            let linkPath = bundleURL.appendingPathComponent("evil_link").path
            var st = stat()
            XCTAssertNotEqual(lstat(linkPath, &st), 0, "ZIP S_IFLNK symlink entry must be stripped and never materialized on disk")
        }

        // Verify SecurityPipeline scans `.tipa` and detects `.app/Dylibs/AzuleTweak.dylib`
        let session = try await SecurityPipeline().createScanSessionAsync(targets: [tipaURL])
        XCTAssertEqual(session.findings.count, 1, "SecurityPipeline must discover and scan .tipa archives")
        let tipaFinding = session.findings[0]
        XCTAssertEqual(tipaFinding.riskTier, .highRisk)
        XCTAssertTrue(tipaFinding.indicators.contains { $0.signature == "fsgetpath" })
        XCTAssertTrue(tipaFinding.indicators.contains { $0.category == "Injected Tweak / Modded IPA" })

        // 2. Real `../` path traversal MUST still throw `.zipSlipDetected`
        let zipSlipData = buildCustomZip(entries: [
            .init(path: "Payload/TweakedClient.app/../../escape.txt", rawPayload: Data("boom".utf8))
        ])
        let zipSlipURL = tmpDir.appendingPathComponent("ZipSlip.ipa")
        try zipSlipData.write(to: zipSlipURL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: zipSlipURL)) { err in
            guard case IPAPackageScannerError.zipSlipDetected = err else {
                XCTFail("Expected zipSlipDetected, got \(err)")
                return
            }
        }

        // 3. Spoofed-header Deflate bomb (declares uncompressedSize = 32, inflates to 4096 bytes) MUST be rejected
        let inflated4K = Data(repeating: 0x41, count: 4096)
        let compressed4K = rawDeflate(inflated4K)
        let bombData = buildCustomZip(entries: [
            .init(
                path: "Payload/Bomb.app/Info.plist",
                rawPayload: compressed4K,
                compressionMethod: 8,
                declaredUncompressedSize: 32
            )
        ])
        let bombURL = tmpDir.appendingPathComponent("SpoofedBomb.ipa")
        try bombData.write(to: bombURL)
        XCTAssertThrowsError(try IPAPackageScanner.shared.scan(ipaURL: bombURL)) { err in
            guard case IPAPackageScannerError.quotaExceeded = err else {
                XCTFail("Expected quotaExceeded on spoofed uncompressedSize deflate stream, got \(err)")
                return
            }
        }
    }
}
