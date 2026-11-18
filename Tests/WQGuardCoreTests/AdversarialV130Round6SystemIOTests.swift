//
//  AdversarialV130Round6SystemIOTests.swift
//  WQGuardCoreTests
//
//  Independent Adversarial Red-Team Challenger (v1.3.0 Round 6 — System I/O):
//  1. Firmware version parsing (betas, RC, padded, overflow, Unicode digits, newlines) + CLI exit codes
//  2. Report / output injection (Markdown table & heading integrity, JSON round-trip, terminal control chars)
//  3. `installation_proxy` registry snapshot abuse (nesting depth, 50k records, odd entitlement value types,
//     duplicate shadowing, concatenated-stream chunk skipping, Apple first-party impersonation)
//  4. Concurrency (locale toggling + WhitelistEngine mutation while evaluating records concurrently)
//
//  Every assertion encodes the SECURE / CORRECT behavior. Failing tests in this file expose real defects
//  (see the `DEFECT` markers) and are intentionally kept.
//

import XCTest
import Foundation
@testable import WQGuardCore

final class AdversarialV130Round6SystemIOTests: XCTestCase {

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

    private func tempFile(_ name: String) -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("r6_\(UUID().uuidString)_\(name)")
        tempURLs.append(url)
        return url
    }

    /// Runs the CLI in-process with stdout/stderr redirected to regular files (non-TTY, no pipe back-pressure).
    private func runCLI(_ args: [String]) async throws -> (code: Int32, out: String, err: String) {
        let outURL = tempFile("stdout.txt")
        let errURL = tempFile("stderr.txt")
        FileManager.default.createFile(atPath: outURL.path, contents: nil)
        FileManager.default.createFile(atPath: errURL.path, contents: nil)
        let outH = try FileHandle(forWritingTo: outURL)
        let errH = try FileHandle(forWritingTo: errURL)
        let code = await CLICommandRunner.run(arguments: ["wqguard-cli"] + args, stdout: outH, stderr: errH)
        try outH.close()
        try errH.close()
        let out = String(decoding: try Data(contentsOf: outURL), as: UTF8.self)
        let err = String(decoding: try Data(contentsOf: errURL), as: UTF8.self)
        return (code, out, err)
    }

    private func isExposed(_ cve: FirmwareCVEID, _ report: FirmwarePostureReport) -> Bool {
        report.exposedVulnerabilities.contains { $0.cveId == cve }
    }

    private static var restricted2026Keys: [String] {
        [
            "com.apple.private.mediaexperience.r6",
            "com.apple.private.cmsession.r6",
            "com.apple.private.bookassetd.r6",
            IOCTokenArmor.tStorePrivPrefix + ".r6",
            "com.apple.private.MobileGestalt.r6",
            "com.apple.private.accessorysetupkit.r6"
        ]
    }

    /// A TrollStore-style ad-hoc registry entry: no SignerIdentity, no profile, no App Store metadata.
    private func adHocRecordDict(
        bundleId: String,
        path: String? = nil,
        appType: String = "User",
        entitlements: [String: Any]
    ) -> [String: Any] {
        [
            "CFBundleIdentifier": bundleId,
            "CFBundleDisplayName": "R6 \(bundleId)",
            "CFBundleShortVersionString": "1.0",
            "ApplicationType": appType,
            "Path": path ?? "/private/var/containers/Bundle/Application/\(UUID().uuidString)/R6.app",
            "Entitlements": entitlements
        ]
    }

    private func plistData(_ obj: Any) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: obj, format: .xml, options: 0)
    }

    private func makeFinding(
        bundleId: String = "com.r6.target",
        displayName: String = "R6 Target",
        version: String = "1.0",
        teamId: String? = "R6TEAM0001",
        bundlePath: String = "/var/containers/Bundle/Application/R6/R6.app",
        riskTier: RiskTier = .highRisk,
        indicators: [ThreatIndicator] = [],
        appGroups: [String] = [],
        remediation: String = ""
    ) -> ScanFinding {
        ScanFinding(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            teamId: teamId,
            executablePath: bundlePath + "/R6",
            bundlePath: bundlePath,
            installChannel: .developerSideloaded,
            riskTier: riskTier,
            indicators: indicators,
            evidence: AuditEvidence(
                matchedSymbols: ["container_query_create"],
                hasAppGroups: !appGroups.isEmpty,
                appGroups: appGroups,
                remediationGuidance: remediation
            )
        )
    }

    /// Splits a GFM table row into cells honoring backslash escapes (`\|`). Returns nil for non-table lines.
    private func gfmCellCount(_ row: String) -> Int? {
        guard row.hasPrefix("|") else { return nil }
        var count = 0
        var escaped = false
        // GFM: only `\|` escapes a pipe for cell splitting.
        for ch in row {
            if ch == "|" && !escaped { count += 1 }
            escaped = (ch == "\\")
        }
        return count - 1
    }

    /// CommonMark line endings are LF, CR, and CRLF.
    private func commonMarkLines(_ s: String) -> [String] {
        s.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .components(separatedBy: "\n")
    }

    // MARK: - 1. Firmware Version Parsing

    func test_r6_firmware_hostileVersionStrings_neverCrash_rejectGarbage_andNeverDowngradeVulnerableToSafe() {
        // Must be REJECTED (nil) — no silent guessing.
        let rejected = [
            "", "27", "27.", ".3", "iOS", "27\n.2", "27.\n2",
            "99999999999999999999.1", "27.99999999999999999999",
            "\u{FF12}\u{FF17}.\u{FF13}",            // full-width ２７.３
            "\u{0662}\u{0667}.\u{0663}",            // Arabic-Indic ٢٧.٣
            "\u{0968}\u{096D}.\u{0969}.\u{0967}"    // Devanagari २७.३.१
        ]
        for s in rejected {
            XCTAssertNil(SystemOSVersion(string: s), "Garbage firmware string \(s.debugDescription) must be rejected")
        }

        // Vulnerable 26.x / 27.0–27.2.x builds in every cosmetic form must stay HIGH RISK with worse_query exposed.
        let vulnerable = [
            "27.2.1", " 27.2.1 ", "\t27.2.1\n", "iOS 27.2.1", "iOS 27.2.1 (24C5034f)", "027.002.001",
            "27.2.1.4", "27.2.1-rc", "27.2.0-rc2", "27.2", "26.07.3", "26.7.3 (23H999)",
            "27.2.99999999999999999999", "26.7.\u{FF13}", "iPhone OS 27.0", "27.1.2\u{0000}"
        ]
        for s in vulnerable {
            guard let v = SystemOSVersion(string: s) else {
                XCTFail("Vulnerable firmware string \(s.debugDescription) must parse"); continue
            }
            let report = FirmwarePostureEngine.shared.evaluate(osVersion: v)
            XCTAssertEqual(report.overallRiskTier, .highRisk, "\(s.debugDescription) parsed as \(v) must be .highRisk")
            XCTAssertTrue(isExposed(.worseQuery0day, report), "\(s.debugDescription) must expose worse_query")
            XCTAssertEqual(report.totalEvaluated, 13)
        }

        // 27.3 beta 2 / RC / GM and later are patched for worse_query.
        for s in ["27.3", "27.3b2", "iOS 27.3 beta 2 (24D5034f)", "27.3.0-rc", "27.3.1", "28.0"] {
            guard let v = SystemOSVersion(string: s) else { XCTFail("\(s) must parse"); continue }
            XCTAssertFalse(isExposed(.worseQuery0day, FirmwarePostureEngine.shared.evaluate(osVersion: v)),
                           "\(s) is patched for worse_query")
        }
    }

    /// DEFECT (HIGH): docs + engine comments state worse_query is patched only in "iOS 27.3 beta 2+".
    /// The parser discards pre-release tags, so every iOS 27.3 *beta 1* string is evaluated as 27.3.0 GA
    /// and reported as PATCHED/.safe (CLI exit 0) while the device is still exploitable.
    func test_r6_firmware_27_3_beta1_mustRemainExposedToWorseQuery() async throws {
        let beta1Forms = ["27.3b1", "27.3 beta 1", "iOS 27.3 beta 1 (24D5001a)", "27.3.0-beta1"]
        for s in beta1Forms {
            guard let v = SystemOSVersion(string: s) else {
                // Rejecting the string (exit 2) would also be acceptable; claiming PATCHED is not.
                continue
            }
            let report = FirmwarePostureEngine.shared.evaluate(osVersion: v)
            XCTAssertTrue(isExposed(.worseQuery0day, report),
                          "DEFECT: \(s.debugDescription) (27.3 beta 1) parsed as \(v.major).\(v.minor).\(v.patch) and reported worse_query PATCHED")
            XCTAssertNotEqual(report.overallRiskTier, .safe, "DEFECT: \(s.debugDescription) reported .safe")
        }
        let cli = try await runCLI(["--firmware-radar=27.3b1", "--format", "json"])
        XCTAssertNotEqual(cli.code, 0, "DEFECT: `wqguard-cli --firmware-radar=27.3b1` exits 0 (safe) on a worse_query-exploitable beta")
    }

    /// DEFECT (LOW): `SystemOSVersion` is `Comparable` but its synthesized `==` also compares `build`/`rawString`,
    /// so `27.2` and `27.2.0` are neither `<` nor `>` each other yet are `!=` — violates Comparable's
    /// strict-total-order contract (breaks Set/Dictionary dedupe, `max()` ties, binary search).
    func test_r6_firmware_comparableEqualityConsistency() throws {
        let a = try XCTUnwrap(SystemOSVersion(string: "27.2"))
        let b = try XCTUnwrap(SystemOSVersion(string: "iOS 27.2.0 (24C101)"))
        XCTAssertFalse(a < b)
        XCTAssertFalse(b < a)
        XCTAssertEqual(a, b, "DEFECT: ordering says 27.2 ≡ 27.2.0 but == disagrees (Comparable contract violation)")
    }

    func test_r6_cli_firmwareRadarExitCodes_forHostileVersions() async throws {
        let cases: [(arg: String, expected: Int32)] = [
            ("--firmware-radar=27.2.1", 1),
            ("--firmware-radar= 27.2.1 ", 1),
            ("--firmware-radar=iOS 27.2.1 (24C5034f)", 1),
            ("--firmware-radar=027.002.001", 1),
            ("--firmware-radar=26.07.3", 1),
            ("--firmware-radar=27.2.1.4", 1),
            ("--firmware-radar=28.0", 0),
            ("--firmware-radar=27.3.1", 0),
            ("--firmware-radar=27", 2),
            ("--firmware-radar=27.", 2),
            ("--firmware-radar=\u{FF12}\u{FF17}.\u{FF13}", 2),
            ("--firmware-radar=\u{0662}\u{0667}.\u{0663}", 2),
            ("--firmware-radar=99999999999999999999.1", 2),
            ("--firmware-radar=27\n.2", 2)
        ]
        for c in cases {
            for fmt in ["json", "text", "markdown"] {
                let r = try await runCLI([c.arg, "--format", fmt])
                XCTAssertEqual(r.code, c.expected, "\(c.arg.debugDescription) --format \(fmt) exit code; stderr=\(r.err)")
                if c.expected == 2 {
                    XCTAssertTrue(r.out.isEmpty, "Invalid version must not print a report")
                } else if fmt == "json" {
                    XCTAssertNoThrow(try JSONSerialization.jsonObject(with: Data(r.out.utf8)), "stdout must be pure JSON")
                }
                XCTAssertFalse(r.out.contains("\u{1B}["), "No ANSI on non-TTY stdout")
            }
        }
        // Negative / dash-prefixed versions are treated as unknown flags, never evaluated.
        let neg = try await runCLI(["--firmware-radar", "-27.2"])
        XCTAssertEqual(neg.code, 2)
    }

    // MARK: - 2. Report / Output Injection

    private static let hostileStrings: [String] = [
        "a|b||c", "`code` ``x``", "<script>alert(1)</script>", "\u{1B}[31mRED\u{1B}[0m",
        "line1\r\nline2\rline3\nline4", "nul\u{0000}byte", "\u{2028}sep\u{2029}", "\u{202E}gpj.exe",
        "emoji 🔴🟢 中文", "\\|escaped\\", String(repeating: "A|", count: 50_000)
    ]

    func test_r6_report_jsonRoundTrip_withHostileAnd100kStrings() throws {
        var findings: [ScanFinding] = []
        for (i, s) in Self.hostileStrings.enumerated() {
            findings.append(makeFinding(
                bundleId: "com.r6.\(i).\(s.prefix(64))",
                displayName: s,
                version: s,
                teamId: s,
                bundlePath: "/tmp/\(s.prefix(200))",
                riskTier: i % 2 == 0 ? .highRisk : .caution,
                indicators: [ThreatIndicator(signature: s, description: s, category: s, location: s, severity: .highRisk)],
                appGroups: [s],
                remediation: s
            ))
        }
        let session = ScanSession(targetPath: "/tmp/\u{1B}[2J", findings: findings, systemVersion: "27.2.1\n# x")
        let start = Date()
        let data = try ReportGenerator.shared.generateJSONReport(session: session)
        let str = try ReportGenerator.shared.generateJSONReportString(session: session)
        XCTAssertLessThan(Date().timeIntervalSince(start), 10)
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: data))
        XCTAssertFalse(str.contains("\u{1B}"), "Raw ESC must be \\u001b-escaped inside JSON")
        XCTAssertFalse(str.contains("\u{0000}"))
        let decoded = try JSONDecoder.iso8601.decode(ScanSession.self, from: data)
        XCTAssertEqual(decoded.findings.count, findings.count)
        for (a, b) in zip(decoded.findings, findings) {
            XCTAssertEqual(a.displayName, b.displayName)
            XCTAssertEqual(a.bundleId, b.bundleId)
            XCTAssertEqual(a.indicators, b.indicators)
            XCTAssertEqual(a.riskTier, b.riskTier)
        }
        XCTAssertEqual(decoded.overallPosture, .highRisk)
    }

    /// DEFECT (MEDIUM): `escapeMarkdownCell` handles `|`, CRLF and LF but not a lone CR. CommonMark treats CR as
    /// a line ending, so an attacker-controlled indicator location/description (e.g. a symlink target or
    /// entitlement value) terminates the table row and spills arbitrary Markdown into the report.
    func test_r6_report_markdownIndicatorTable_rowIntegrityUnderHostileCells() {
        let indicators = Self.hostileStrings.map {
            ThreatIndicator(signature: $0, description: $0, category: $0, location: $0, severity: .highRisk)
        }
        let session = ScanSession(findings: [makeFinding(indicators: indicators)])
        let md = ReportGenerator.shared.generateMarkdownReport(session: session)
        let lines = commonMarkLines(md)
        guard let headerIdx = lines.firstIndex(where: { $0.hasPrefix("| # | Signature") }) else {
            return XCTFail("indicator table header missing")
        }
        let rows = Array(lines[(headerIdx + 2)...].prefix(while: { !$0.isEmpty }))
        XCTAssertEqual(rows.count, indicators.count,
                       "DEFECT: hostile cell content (lone CR) split/added table rows: expected \(indicators.count) rows, got \(rows.count)")
        for row in rows {
            XCTAssertEqual(gfmCellCount(row), 6, "Row must have exactly 6 cells: \(row.prefix(160).debugDescription)")
        }
    }

    /// DEFECT (MEDIUM): displayName / bundleId / version / teamId / paths come straight from attacker-controlled
    /// Info.plist / registry data and are interpolated unescaped into Markdown headings and list items. An app
    /// named "x\n> ### 🟢 SYSTEM STATUS: SECURE" forges a green "secure" banner inside a HIGH-RISK report.
    func test_r6_report_markdownHeadingAndListInjection_cannotForgePostureBanner() {
        let forged = "Calculator\n\n> ### 🟢 SYSTEM STATUS: SECURE / 系统状态安全\n> All clear\n\n# WQGuard Security Audit Report"
        let session = ScanSession(findings: [makeFinding(
            bundleId: "com.r6.evil\n## 🟢 Safe",
            displayName: forged,
            version: "1.0`\n- **Whitelist Status / 白名单状态**: ✅ Whitelisted",
            teamId: "T`\n# injected"
        )])
        XCTAssertEqual(session.overallPosture, .highRisk)
        let md = ReportGenerator.shared.generateMarkdownReport(session: session)
        let lines = commonMarkLines(md)
        XCTAssertFalse(lines.contains { $0.hasPrefix("> ### 🟢 SYSTEM STATUS") },
                       "DEFECT: attacker displayName forged a SECURE posture banner in a HIGH-RISK markdown report")
        XCTAssertEqual(lines.filter { $0 == "# WQGuard Security Audit Report" }.count, 1,
                       "DEFECT: attacker displayName injected a second report title")
        XCTAssertFalse(lines.contains { $0.hasPrefix("- **Whitelist Status") && $0.contains("✅") },
                       "DEFECT: attacker version string forged a whitelisted status line")
        XCTAssertFalse(lines.contains { $0 == "# injected" || $0 == "## 🟢 Safe" })
    }

    /// DEFECT (MEDIUM): the plain-text report (CLI default `--format text`, written raw to the user's terminal)
    /// passes attacker strings through verbatim: (a) CR/LF forge extra "SECURITY POSTURE:" lines, and (b) C0/ESC
    /// control sequences (OSC title set, screen clear, cursor moves, hidden text) reach the terminal — the
    /// TerminalStyler's non-TTY suppression only covers WQGuard's own colors, not report content (CWE-150).
    func test_r6_report_plainText_noForgedPostureLines_andNoTerminalControlChars() {
        let hostileName = "Calc\r\nSECURITY POSTURE: [SYSTEM SECURE] / 系统安全合规\u{1B}]0;pwned\u{07}\u{1B}[2J\u{1B}[8mhidden\u{1B}[0m"
        let session = ScanSession(findings: [makeFinding(
            bundleId: "com.r6.ansi\u{1B}[1A",
            displayName: hostileName,
            indicators: [ThreatIndicator(signature: "sig\u{1B}[31m", description: "d\u{08}\u{08}\u{08}SAFE",
                                         category: "c", location: "/tmp/\u{1B}[K", severity: .highRisk)]
        )])
        let text = ReportGenerator.shared.generatePlainTextReport(session: session)
        let postureLines = commonMarkLines(text).filter { $0.hasPrefix("SECURITY POSTURE:") }
        XCTAssertEqual(postureLines.count, 1, "DEFECT: attacker displayName forged extra SECURITY POSTURE lines: \(postureLines)")
        let controls = text.unicodeScalars.filter { ($0.value < 0x20 && $0 != "\n" && $0 != "\t") || $0.value == 0x7F }
        XCTAssertTrue(controls.isEmpty,
                      "DEFECT: plain-text report leaks \(controls.count) raw control chars (ESC/BEL/BS/CR) to the terminal")
    }

    func test_r6_report_100kCharFields_noCrash_boundedTime_allFormats() throws {
        let huge = String(repeating: "\u{4E2D}|`<b>", count: 25_000) // 100k scalars
        let findings = (0..<20).map { i in
            makeFinding(bundleId: "com.r6.huge.\(i)", displayName: huge, version: huge,
                        indicators: [ThreatIndicator(signature: huge, description: huge, category: "c", location: huge, severity: .caution)],
                        appGroups: [huge])
        }
        let session = ScanSession(findings: findings)
        let start = Date()
        let md = ReportGenerator.shared.generateMarkdownReport(session: session)
        let txt = ReportGenerator.shared.generatePlainTextReport(session: session)
        let json = try ReportGenerator.shared.generateJSONReport(session: session)
        XCTAssertLessThan(Date().timeIntervalSince(start), 30, "Report generation must stay bounded")
        XCTAssertGreaterThan(md.count, 2_000_000)
        XCTAssertGreaterThan(txt.count, 2_000_000)
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: json))
    }

    // MARK: - 3. Registry Snapshot Abuse

    func test_r6_registry_deeplyNestedSnapshots_throwCleanly_noStackOverflow() throws {
        let depth = 100_000
        let json = Data((String(repeating: "[", count: depth) + String(repeating: "]", count: depth)).utf8)
        let xml = Data(("<?xml version=\"1.0\"?><plist version=\"1.0\">" + String(repeating: "<array>", count: depth)
                        + String(repeating: "</array>", count: depth) + "</plist>").utf8)
        let dictJSON = Data((String(repeating: "{\"a\":", count: depth) + "1" + String(repeating: "}", count: depth)).utf8)
        for (label, data) in [("json", json), ("xml", xml), ("dictJSON", dictJSON)] {
            XCTAssertThrowsError(try InstalledAppRegistryScanner.shared.parseSnapshotData(data), label) { err in
                XCTAssertTrue(err is InstalledAppRegistryError, "\(label): \(err)")
            }
        }
        // A real record whose Entitlements carry a moderately deep (but parseable) nested value must still audit.
        var nested: Any = ["x": true]
        for _ in 0..<200 { nested = ["n": nested] }
        let rec = adHocRecordDict(bundleId: "com.r6.nested", entitlements: [
            "com.apple.private.security.no-sandbox": true,
            "com.apple.private.cmsession.deep": nested
        ])
        let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(try plistData([rec]))
        let findings = InstalledAppRegistryScanner.shared.evaluateRecords(records)
        XCTAssertEqual(findings.first?.riskTier, .highRisk)
    }

    func test_r6_registry_50kRecords_parseAndEvaluateWithinBound() throws {
        var apps: [[String: Any]] = []
        apps.reserveCapacity(50_000)
        for i in 0..<50_000 {
            var ents: [String: Any] = ["com.apple.security.application-groups": ["group.r6.\(i)"]]
            if i % 997 == 0 { ents["com.apple.private.security.no-container"] = true }
            apps.append(adHocRecordDict(bundleId: "com.r6.bulk.\(i)", path: "/private/var/containers/Bundle/Application/\(i)/A.app", entitlements: ents))
        }
        let data = try PropertyListSerialization.data(fromPropertyList: ["CurrentList": apps], format: .binary, options: 0)
        let start = Date()
        let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(data)
        let findings = InstalledAppRegistryScanner.shared.evaluateRecords(records)
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertEqual(records.count, 50_000)
        XCTAssertEqual(findings.count, 50_000)
        XCTAssertEqual(findings.filter { $0.riskTier == .highRisk }.count, (0..<50_000).filter { $0 % 997 == 0 }.count)
        XCTAssertLessThan(elapsed, 60, "50k-record snapshot took \(elapsed)s (debug build)")
    }

    func test_r6_registry_restrictedKeys_unexpectedValueTypes_stillFlagged() throws {
        // Plist-native exotic types.
        let plistValues: [(String, Any)] = [
            ("data", Data([0x01])), ("date", Date(timeIntervalSince1970: 0)), ("dict", ["k": "v"]),
            ("emptyArray", [Any]()), ("real", 0.5), ("emptyString", "")
        ]
        for key in Self.restricted2026Keys {
            for (label, value) in plistValues {
                let recs = try InstalledAppRegistryScanner.shared.parseSnapshotData(
                    try plistData([adHocRecordDict(bundleId: "com.r6.type.\(label)", entitlements: [key: value])]))
                let f = InstalledAppRegistryScanner.shared.evaluateRecords(recs)
                XCTAssertEqual(f.count, 1, "\(key)=\(label) must not be skipped")
                XCTAssertEqual(f.first?.riskTier, .highRisk, "\(key)=\(label) must be .highRisk")
            }
            // JSON null / nested.
            let json = """
            [{"CFBundleIdentifier":"com.r6.json.null","ApplicationType":"User","Entitlements":{"\(key)":null}},
             {"CFBundleIdentifier":"com.r6.json.obj","ApplicationType":"User","Entitlements":{"\(key)":{"a":[1,{"b":null}]}}}]
            """
            let recs = try InstalledAppRegistryScanner.shared.parseSnapshotData(Data(json.utf8))
            XCTAssertEqual(recs.count, 2)
            for f in InstalledAppRegistryScanner.shared.evaluateRecords(recs) {
                XCTAssertEqual(f.riskTier, .highRisk, "\(key) JSON exotic value for \(f.bundleId) must be .highRisk")
            }
            // Explicit false / 0 must remain clean (no over-correction).
            let off = try InstalledAppRegistryScanner.shared.parseSnapshotData(
                try plistData([adHocRecordDict(bundleId: "com.r6.off", entitlements: [key: false])]))
            XCTAssertTrue(InstalledAppRegistryScanner.shared.restricted2026BypassEntitlements(for: off[0]).isEmpty)
        }
    }

    /// DEFECT (MEDIUM): `deduplicate` keeps the FIRST record per bundle ID and silently discards the rest. When a
    /// snapshot (e.g. concatenated `instproxy Browse` dumps from before/after an update) lists a clean entry first
    /// and a malicious entry with the same bundle ID later, the malicious entitlements vanish from the audit.
    func test_r6_registry_duplicateBundleId_cleanFirstMustNotShadowMalicious() throws {
        let clean = adHocRecordDict(bundleId: "com.r6.dup", entitlements: [:])
        let evil = adHocRecordDict(bundleId: "com.r6.dup", entitlements: [
            "com.apple.private.security.no-sandbox": true,
            "com.apple.private.tcc.allow": ["kTCCServicePhotos"]
        ])
        for (label, data) in [
            ("array", try plistData([clean, evil])),
            ("currentList", try plistData(["CurrentList": [clean, evil]])),
            ("whitespaceVariant", try plistData([clean, adHocRecordDict(bundleId: " com.r6.dup\n", entitlements: evil["Entitlements"] as! [String: Any])]))
        ] {
            let recs = try InstalledAppRegistryScanner.shared.parseSnapshotData(data)
            let findings = InstalledAppRegistryScanner.shared.evaluateRecords(recs, includeAppStoreApps: true)
            XCTAssertTrue(findings.contains { $0.riskTier == .highRisk },
                          "DEFECT [\(label)]: clean duplicate shadowed malicious com.r6.dup (records=\(recs.count), tiers=\(findings.map(\.riskTier)))")
        }
        // Case-variant IDs are distinct records and must BOTH be audited (never merged into the clean one).
        let caseRecs = try InstalledAppRegistryScanner.shared.parseSnapshotData(try plistData([
            adHocRecordDict(bundleId: "com.r6.Case", entitlements: [:]),
            adHocRecordDict(bundleId: "COM.R6.CASE", entitlements: ["com.apple.private.security.no-container": true])
        ]))
        XCTAssertEqual(caseRecs.count, 2)
        XCTAssertTrue(InstalledAppRegistryScanner.shared.evaluateRecords(caseRecs).contains { $0.riskTier == .highRisk })
    }

    /// DEFECT (MEDIUM): concatenated `instproxy Browse` stream dumps (explicitly supported by step 3 of
    /// `parseSnapshotData`) never reach step 3 — `PropertyListSerialization` in step 1 happily parses the FIRST
    /// plist document and ignores trailing bytes, so every packet after the first is silently dropped
    /// (a malicious app in packet #2+ vanishes). Step 3 also prefers a later `<?xml` over an earlier `<plist`.
    func test_r6_registry_concatenatedBrowseStream_everyPacketAudited() throws {
        let evil = adHocRecordDict(bundleId: "com.r6.stream.evil", entitlements: ["com.apple.private.security.no-sandbox": true])
        let clean = adHocRecordDict(bundleId: "com.r6.stream.clean", entitlements: [:])
        let evilXML = String(decoding: try plistData(["CurrentList": [evil]]), as: UTF8.self)
        let cleanXML = String(decoding: try plistData(["CurrentList": [clean]]), as: UTF8.self)
        guard let plistStart = evilXML.range(of: "<plist") else { return XCTFail() }
        let headerless = String(evilXML[plistStart.lowerBound...])
        let streams: [(String, String)] = [
            ("clean+evil (both with <?xml>)", cleanXML + "\n" + evilXML),
            ("clean+evil (no separator)", cleanXML + evilXML),
            ("headerlessEvil+clean", headerless + "\n" + cleanXML)
        ]
        for (label, text) in streams {
            let recs = try InstalledAppRegistryScanner.shared.parseSnapshotData(Data(text.utf8))
            XCTAssertTrue(recs.contains { $0.bundleId == "com.r6.stream.clean" } && recs.contains { $0.bundleId == "com.r6.stream.evil" },
                          "DEFECT [\(label)]: concatenated Browse stream lost packets; got \(recs.map(\.bundleId))")
        }
    }

    /// DEFECT (HIGH): `isAppleSystemOrFirstPartyApp` trusts ANY `com.apple.*` bundle ID (case-insensitive) with no
    /// signer/profile, so a TrollStore/ad-hoc app (ApplicationType=User, no SignerIdentity, no App Store metadata,
    /// in /var/containers) simply named `com.apple.<anything>` is excluded from the audit entirely — even while
    /// holding no-sandbox / no-container / TCC-bypass / 2026 restricted entitlements.
    func test_r6_registry_adHocComAppleImpersonator_mustNotEscapeAudit() throws {
        for bid in ["com.apple.evil", "COM.APPLE.Evil", "com.apple.mobilesafari.helper"] {
            let dict = adHocRecordDict(bundleId: bid, entitlements: [
                "com.apple.private.security.no-sandbox": true,
                "com.apple.private.security.no-container": true,
                "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"],
                "com.apple.private.MobileGestalt.r6": true
            ])
            let recs = try InstalledAppRegistryScanner.shared.parseSnapshotData(try plistData([dict]))
            let rec = try XCTUnwrap(recs.first)
            XCTAssertFalse(InstalledAppRegistryScanner.shared.isAppleSystemOrFirstPartyApp(rec),
                           "DEFECT: ad-hoc User app \(bid) classified as Apple first-party")
            let findings = InstalledAppRegistryScanner.shared.evaluateRecords(recs, includeAppStoreApps: true)
            XCTAssertEqual(findings.first?.riskTier, .highRisk,
                           "DEFECT: unsandboxed ad-hoc \(bid) escaped auditing (findings=\(findings.count))")
        }
    }

    /// DEFECT (HIGH): path-prefix trust (`/Applications/`, `/Library/`, …) is unconditional and unnormalized. A
    /// non-Apple rootful-jailbreak app registered in /Applications (e.g. a Filza-style file manager with
    /// no-sandbox + platform-application), or a `..`-traversing path, is treated as Apple first-party and skipped.
    func test_r6_registry_nonAppleBundleInSystemPath_orTraversal_mustNotEscapeAudit() throws {
        let ents: [String: Any] = [
            "com.apple.private.security.no-sandbox": true,
            "platform-application": true
        ]
        let cases: [(bid: String, path: String, type: String)] = [
            ("com.tigisoftware.r6filza", "/Applications/R6Filza.app", "System"),
            ("com.r6.evil.traversal", "/Applications/../private/var/containers/Bundle/Application/X/Evil.app", "User"),
            ("com.r6.evil.library", "/Library/../var/mobile/Evil.app", "User")
        ]
        for c in cases {
            let recs = try InstalledAppRegistryScanner.shared.parseSnapshotData(
                try plistData([adHocRecordDict(bundleId: c.bid, path: c.path, appType: c.type, entitlements: ents)]))
            let findings = InstalledAppRegistryScanner.shared.evaluateRecords(recs, includeAppStoreApps: true)
            XCTAssertEqual(findings.first?.riskTier, .highRisk,
                           "DEFECT: non-Apple \(c.bid) at \(c.path) with no-sandbox+platform-application escaped auditing")
        }
    }

    // MARK: - 4. Concurrency

    func test_r6_concurrency_localeToggle_whitelistMutation_consistentDecisions_noCrash() {
        let scanner = InstalledAppRegistryScanner.shared
        let target = InstalledAppRegistryRecord(
            bundleId: "com.r6.wl.target", displayName: "WL", version: "1",
            booleanEntitlements: ["com.apple.private.security.no-sandbox": true],
            bundlePath: "/private/var/containers/Bundle/Application/T/T.app")
        let bystander = InstalledAppRegistryRecord(
            bundleId: "com.r6.bystander", displayName: "BY", version: "1",
            booleanEntitlements: ["com.apple.private.security.no-container": true],
            bundlePath: "/private/var/containers/Bundle/Application/B/B.app")
        let rule = WhitelistedTool(name: "R6-Target", allowedBundleIds: ["com.r6.wl.target"], isEnabled: true)

        final class Box: @unchecked Sendable {
            let lock = NSLock()
            var violations: [String] = []
            var stop = false
            func add(_ s: String) { lock.lock(); if violations.count < 20 { violations.append(s) }; lock.unlock() }
            var stopped: Bool { lock.lock(); defer { lock.unlock() }; return stop }
            func halt() { lock.lock(); stop = true; lock.unlock() }
        }
        let box = Box()
        let hanCheck: @Sendable (String) -> Bool = { s in s.unicodeScalars.contains { (0x4E00...0x9FFF).contains($0.value) } }

        let mutators = DispatchGroup()
        for m in 0..<3 {
            DispatchQueue.global().async(group: mutators) {
                var i = 0
                while !box.stopped {
                    switch (i + m) % 5 {
                    case 0: WQLocale.overrideLanguageCode = "en"
                    case 1: WQLocale.overrideLanguageCode = "zh-Hans"
                    case 2: WhitelistEngine.shared.registerCustomTool(rule)
                    case 3: WhitelistEngine.shared.toggleTool(named: "R6-Target", isEnabled: i % 2 == 0)
                    default: WhitelistEngine.shared.resetToDefaults()
                    }
                    i += 1
                }
            }
        }

        let start = Date()
        DispatchQueue.concurrentPerform(iterations: 4_000) { i in
            let rec = i % 2 == 0 ? target : bystander
            let f = scanner.evaluateRecord(rec)
            if rec.bundleId == "com.r6.bystander" {
                if f.isWhitelisted || f.riskTier != .highRisk {
                    box.add("bystander whitelisted/downgraded: \(f.riskTier)")
                }
            } else {
                // Target is either whitelisted (knownTool, named rule) or highRisk; nothing in between.
                if f.isWhitelisted {
                    if f.riskTier != .knownTool || f.whitelistedToolName != "R6-Target" { box.add("inconsistent wl: \(f.riskTier) \(String(describing: f.whitelistedToolName))") }
                } else if f.riskTier != .highRisk {
                    box.add("target downgraded without whitelist: \(f.riskTier)")
                }
            }
            // Each individual string is produced by one `pick` call: it must be wholly EN or wholly ZH.
            for ind in f.indicators where ind.description.isEmpty {
                box.add("empty description for \(ind.signature)")
            }
            _ = hanCheck(f.evidence.remediationGuidance)
            _ = ReportGenerator.shared.generatePlainTextReport(session: ScanSession(findings: [f]))
        }
        box.halt()
        XCTAssertEqual(mutators.wait(timeout: .now() + 30), .success, "Mutator threads deadlocked")
        XCTAssertLessThan(Date().timeIntervalSince(start), 120)
        XCTAssertTrue(box.violations.isEmpty, "Concurrency violations: \(box.violations)")
    }

    func test_r6_concurrency_parallelCLIFirmwareRuns_deterministicExitCodes() async throws {
        let versions: [(String, Int32)] = [("27.2.1", 1), ("28.1", 0), ("27", 2), ("26.7.3", 1), ("27.3.2", 0)]
        let results = try await withThrowingTaskGroup(of: (String, Int32, Int32).self) { group in
            for round in 0..<8 {
                for (v, expected) in versions {
                    group.addTask {
                        let r = try await Self.runCLIDetached(["--firmware-radar=\(v)", "--format", round % 2 == 0 ? "json" : "markdown"])
                        return (v, expected, r)
                    }
                }
            }
            var all: [(String, Int32, Int32)] = []
            for try await r in group { all.append(r) }
            return all
        }
        XCTAssertEqual(results.count, 40)
        for (v, expected, got) in results {
            XCTAssertEqual(got, expected, "Parallel CLI run for \(v)")
        }
    }

    private static func runCLIDetached(_ args: [String]) async throws -> Int32 {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("r6_par_\(UUID().uuidString)")
        let o = base.appendingPathExtension("out"), e = base.appendingPathExtension("err")
        FileManager.default.createFile(atPath: o.path, contents: nil)
        FileManager.default.createFile(atPath: e.path, contents: nil)
        defer { try? FileManager.default.removeItem(at: o); try? FileManager.default.removeItem(at: e) }
        let oh = try FileHandle(forWritingTo: o), eh = try FileHandle(forWritingTo: e)
        let code = await CLICommandRunner.run(arguments: ["wqguard-cli"] + args, stdout: oh, stderr: eh)
        try oh.close(); try eh.close()
        return code
    }
}

private extension JSONDecoder {
    static var iso8601: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}
