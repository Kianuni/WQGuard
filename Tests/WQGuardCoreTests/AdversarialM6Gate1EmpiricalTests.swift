import XCTest
import Foundation
@testable import WQGuardCore

/// Adversarial empirical tests for Milestone 6 Gate 1 verification:
/// 1. PatternMatcher wildcard matching (*, *suffix, prefix*, prefix*suffix, regex metacharacters)
/// 2. CSBlobParser multi-slot SuperBlob shadowing and deduplication
final class AdversarialM6Gate1EmpiricalTests: XCTestCase {

    // =========================================================================
    // MARK: - Task 1: PatternMatcher.matches Adversarial Empirical Verification
    // =========================================================================

    /// 1.1 Single wildcard '*' must match everything (empty, single char, bundle ID, UUID, emoji, whitespace).
    func test_M6_Gate1_PatternMatcher_singleWildcard_exhaustive() {
        let pattern = "*"

        let testValues = [
            "",
            "a",
            "Z",
            "0",
            "com.apple.SpringBoard",
            "group.com.jbdotparty.Erosion.WQ",
            "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
            "   ",
            "\t\n\r",
            "🚀.security.guard",
            String(repeating: "A", count: 5000),
            "weird!@#$%^&*()_+{}[]:;\"'<>?,./~`"
        ]

        for val in testValues {
            let matched = PatternMatcher.matches(pattern: pattern, value: val)
            XCTAssertTrue(matched, "Pattern '*' must match '\(val)'")
        }
    }

    /// 1.2 Suffix wildcard '*suffix' must match correctly and reject non-matching values.
    func test_M6_Gate1_PatternMatcher_suffixWildcard_exhaustive() {
        let pattern = "*suffix"

        // Positive matches
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "suffix"), "Exact suffix match")
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "mysuffix"), "Prefix with suffix")
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "LONG_PREFIX_suffix"), "Long prefix with suffix")
        XCTAssertTrue(PatternMatcher.matches(pattern: "*SUFFIX", value: "mysuffix"), "Case insensitivity in pattern")
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "mySUFFIX"), "Case insensitivity in value")

        // Negative matches
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "suffixExtra"), "Suffix followed by extra characters must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "suf"), "Partial suffix must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "prefix_suffix_tail"), "Suffix in middle must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: ""), "Empty value must not match non-empty suffix")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "other"), "Unrelated string must fail")

        // Dylib extension suffix
        let dylibPattern = "*.dylib"
        XCTAssertTrue(PatternMatcher.matches(pattern: dylibPattern, value: "libsystem_containermanager.dylib"))
        XCTAssertTrue(PatternMatcher.matches(pattern: dylibPattern, value: "/usr/lib/libsystem_containermanager.dylib"))
        XCTAssertFalse(PatternMatcher.matches(pattern: dylibPattern, value: "libsystem_containermanager.dylib.bak"))
        XCTAssertFalse(PatternMatcher.matches(pattern: dylibPattern, value: "dylib"))
    }

    /// 1.3 Prefix wildcard 'prefix*' must match correctly and reject non-matching values.
    func test_M6_Gate1_PatternMatcher_prefixWildcard_exhaustive() {
        let pattern = "com.apple.*"

        // Positive matches
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "com.apple."), "Exact prefix match")
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "com.apple.SpringBoard"), "Prefix match with component")
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "com.apple.foo.bar.baz"), "Deep hierarchical prefix match")
        XCTAssertTrue(PatternMatcher.matches(pattern: "COM.APPLE.*", value: "com.apple.MobileMail"), "Case insensitivity in pattern")
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "COM.APPLE.Safari"), "Case insensitivity in value")

        // Negative matches
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "com.google.chrome"), "Different vendor prefix must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "pre.com.apple.foo"), "Prefix appearing after start must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "com.apple"), "Missing dot separator must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: ""), "Empty string must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "com."), "Incomplete prefix must fail")

        // App Group prefix
        let groupPattern = "group.com.wqguard.*"
        XCTAssertTrue(PatternMatcher.matches(pattern: groupPattern, value: "group.com.wqguard.app"))
        XCTAssertTrue(PatternMatcher.matches(pattern: groupPattern, value: "group.com.wqguard.scanner"))
        XCTAssertFalse(PatternMatcher.matches(pattern: groupPattern, value: "group.cz.kolbi.wqfiles"))
    }

    /// 1.4 Prefix and suffix wildcard 'prefix*suffix' must match correctly and reject non-matching values.
    func test_M6_Gate1_PatternMatcher_prefixAndSuffixWildcard_exhaustive() {
        let pattern = "com.*.app"

        // Positive matches
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "com..app"), "Empty wildcard middle")
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "com.foo.app"), "Single word middle")
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "com.my-company.sec-tool.app"), "Hyphenated middle")
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "com.foo.bar.baz.qux.app"), "Multi-segment middle")
        XCTAssertTrue(PatternMatcher.matches(pattern: "COM.*.APP", value: "com.foo.app"), "Case insensitivity in pattern")
        XCTAssertTrue(PatternMatcher.matches(pattern: pattern, value: "COM.FOO.APP"), "Case insensitivity in value")

        // Negative matches
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "net.foo.app"), "Mismatched prefix must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "com.foo.tool"), "Mismatched suffix must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "com.foo.application"), "Suffix as prefix of another word must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "mycom.foo.app"), "Prefix as suffix of another word must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: "com.foo.app.extra"), "Trailing characters after suffix must fail")
        XCTAssertFalse(PatternMatcher.matches(pattern: pattern, value: ""), "Empty string must fail")
    }

    /// 1.5 Regex metacharacters must be treated literally without unintended regex injection or syntax errors.
    func test_M6_Gate1_PatternMatcher_regexMetacharactersAndInjection() {
        // Dot (.) must be literal, not regex wildcard
        XCTAssertTrue(PatternMatcher.matches(pattern: "com.app.test", value: "com.app.test"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.app.test", value: "comXappXtest"), "Dot must not match arbitrary character 'X'")

        // Plus (+) must be literal, not regex one-or-more
        XCTAssertTrue(PatternMatcher.matches(pattern: "com.app.test+1*", value: "com.app.test+1.demo"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.app.test+1*", value: "com.app.testtttt1.demo"), "Plus must not repeat preceding char")

        // Character class brackets [...] must be literal
        XCTAssertTrue(PatternMatcher.matches(pattern: "com.app.[abc]*", value: "com.app.[abc].release"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.app.[abc]*", value: "com.app.a.release"), "Brackets must not match character class")
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.app.[abc]*", value: "com.app.b.release"))

        // Parentheses and pipe (...) | (...) must be literal
        XCTAssertTrue(PatternMatcher.matches(pattern: "com.app.(a|b)*", value: "com.app.(a|b).tool"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.app.(a|b)*", value: "com.app.a.tool"), "Parens and pipe must not act as alternation")

        // Caret (^) and Dollar ($) must be literal
        XCTAssertTrue(PatternMatcher.matches(pattern: "^com.app.*$", value: "^com.app.test$"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "^com.app.*$", value: "com.app.test"), "Literal caret and dollar must be required")

        // Braces {m,n} must be literal
        XCTAssertTrue(PatternMatcher.matches(pattern: "com.app{1,3}*", value: "com.app{1,3}.tool"))
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.app{1,3}*", value: "com.appp.tool"), "Braces must not act as regex quantifier")

        // Question mark (?) is glob single-character match
        XCTAssertTrue(PatternMatcher.matches(pattern: "com.?.app", value: "com.a.app"), "Question mark matches single char 'a'")
        XCTAssertTrue(PatternMatcher.matches(pattern: "com.?.app", value: "com.1.app"), "Question mark matches single char '1'")
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.?.app", value: "com.ab.app"), "Question mark must not match multiple chars")
        XCTAssertFalse(PatternMatcher.matches(pattern: "com.?.app", value: "com..app"), "Question mark must not match empty char")

        // Complex combined glob with metacharacters
        let complexPattern = "com.*.sub[0-9]+*v?.0"
        XCTAssertTrue(PatternMatcher.matches(pattern: complexPattern, value: "com.corp.sub[0-9]+release-v1.0"))
        XCTAssertFalse(PatternMatcher.matches(pattern: complexPattern, value: "com.corp.sub5release-v1.0"), "Bracket must remain literal")
    }

    // =========================================================================
    // MARK: - Task 2: CSBlobParser Multi-Slot SuperBlob Shadowing & Deduplication
    // =========================================================================

    /// Helper to assemble a binary SuperBlob with arbitrary index entries and payloads.
    private func assembleSuperBlob(entries: [(type: UInt32, magic: UInt32, data: Data)]) -> Data {
        var sb = Data()
        var magic = UInt32(CSBlobConstants.superBlobMagic).bigEndian
        let headerSize = 12
        let indexTableSize = entries.count * 8
        var payloadOffset = headerSize + indexTableSize

        // Calculate total length
        var totalLength = payloadOffset
        for entry in entries {
            totalLength += 8 + entry.data.count // 8 bytes blob header (magic + length) + payload
        }

        var totalLenBE = UInt32(totalLength).bigEndian
        var countBE = UInt32(entries.count).bigEndian

        // 1. SuperBlob Header
        sb.append(Data(bytes: &magic, count: 4))
        sb.append(Data(bytes: &totalLenBE, count: 4))
        sb.append(Data(bytes: &countBE, count: 4))

        // 2. Index Table
        var currentOffset = payloadOffset
        for entry in entries {
            var typeBE = entry.type.bigEndian
            var offBE = UInt32(currentOffset).bigEndian
            sb.append(Data(bytes: &typeBE, count: 4))
            sb.append(Data(bytes: &offBE, count: 4))
            currentOffset += 8 + entry.data.count
        }

        // 3. Blob Payloads
        for entry in entries {
            var blobMagicBE = entry.magic.bigEndian
            var blobLenBE = UInt32(8 + entry.data.count).bigEndian
            sb.append(Data(bytes: &blobMagicBE, count: 4))
            sb.append(Data(bytes: &blobLenBE, count: 4))
            sb.append(entry.data)
        }

        return sb
    }

    /// 2.1 Decoy Empty Slot 5 preceding Malicious Slot 5:
    /// Malicious App Groups must NOT be shadowed; both entries parsed and extracted.
    func test_M6_Gate1_CSBlob_emptySlot5ShadowingMaliciousSlot5() throws {
        let emptyXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict></dict></plist>"
        let evilXml = """
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <plist version=\"1.0\">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.malicious.shadowed</string>
            </array>
        </dict>
        </plist>
        """

        let emptyData = emptyXml.data(using: .utf8)!
        let evilData = evilXml.data(using: .utf8)!

        let sb = assembleSuperBlob(entries: [
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: emptyData),
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: evilData)
        ])

        let parsed = try CSBlobParser.shared.parseSuperBlob(sb)
        print("[EMPIRICAL OBSERVATION] Empty Slot 5 shadowing: hasAppGroups=\(parsed.hasAppGroups), appGroups=\(parsed.appGroups)")

        XCTAssertTrue(parsed.hasAppGroups, "Must extract App Groups despite decoy empty Slot 5")
        XCTAssertEqual(parsed.appGroups, ["group.malicious.shadowed"])
        XCTAssertEqual(parsed.formatUsed, .xml)
    }

    /// 2.2 Malicious Slot 5 preceding Decoy Empty Slot 5:
    /// Empty Slot 5 arriving second must NOT clear or overwrite already extracted App Groups.
    func test_M6_Gate1_CSBlob_maliciousSlot5PrecedingEmptySlot5() throws {
        let evilXml = """
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <plist version=\"1.0\">
        <dict>
            <key>com.apple.security.application-groups</key>
            <array>
                <string>group.malicious.first</string>
            </array>
        </dict>
        </plist>
        """
        let emptyXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict></dict></plist>"

        let evilData = evilXml.data(using: .utf8)!
        let emptyData = emptyXml.data(using: .utf8)!

        let sb = assembleSuperBlob(entries: [
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: evilData),
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: emptyData)
        ])

        let parsed = try CSBlobParser.shared.parseSuperBlob(sb)
        print("[EMPIRICAL OBSERVATION] Reverse order Slot 5: hasAppGroups=\(parsed.hasAppGroups), appGroups=\(parsed.appGroups)")

        XCTAssertTrue(parsed.hasAppGroups)
        XCTAssertEqual(parsed.appGroups, ["group.malicious.first"])
    }

    /// 2.3 Multiple Slot 5s with overlapping App Groups:
    /// All entries must be aggregated and deduplicated into a clean unique list.
    func test_M6_Gate1_CSBlob_multipleSlot5_deduplication() throws {
        let xml1 = """
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <plist version=\"1.0\"><dict><key>com.apple.security.application-groups</key><array>
            <string>group.shared.common</string>
            <string>group.slot1.unique</string>
        </array></dict></plist>
        """
        let xml2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict></dict></plist>"
        let xml3 = """
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <plist version=\"1.0\"><dict><key>com.apple.security.application-groups</key><array>
            <string>group.shared.common</string>
            <string>group.slot3.unique</string>
        </array></dict></plist>
        """

        let sb = assembleSuperBlob(entries: [
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: xml1.data(using: .utf8)!),
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: xml2.data(using: .utf8)!),
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: xml3.data(using: .utf8)!)
        ])

        let parsed = try CSBlobParser.shared.parseSuperBlob(sb)
        print("[EMPIRICAL OBSERVATION] Triple Slot 5 deduplication: count=\(parsed.appGroups.count), groups=\(parsed.appGroups)")

        XCTAssertTrue(parsed.hasAppGroups)
        XCTAssertEqual(parsed.appGroups.count, 3, "Common group must be deduplicated across multiple Slot 5s")
        XCTAssertTrue(parsed.appGroups.contains("group.shared.common"))
        XCTAssertTrue(parsed.appGroups.contains("group.slot1.unique"))
        XCTAssertTrue(parsed.appGroups.contains("group.slot3.unique"))
    }

    /// 2.4 Multi-slot Dual Format with Shadowing in BOTH Slot 5 and Slot 7:
    /// Verifies dual extraction (.dual format) and cross-format deduplication.
    func test_M6_Gate1_CSBlob_dualSlots_shadowedXmlAndDer_deduplication() throws {
        let emptyXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict></dict></plist>"
        let evilXml = """
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <plist version=\"1.0\"><dict><key>com.apple.security.application-groups</key><array>
            <string>group.shared.both</string>
            <string>group.xml.exclusive</string>
        </array></dict></plist>
        """

        // Create empty DER dictionary
        let emptyDer = SyntheticMachOGenerator.createDEREntitlements(appGroups: [])
        // Create DER with app groups
        let evilDer = SyntheticMachOGenerator.createDEREntitlements(appGroups: ["group.shared.both", "group.der.exclusive"])

        let sb = assembleSuperBlob(entries: [
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: emptyXml.data(using: .utf8)!),
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: evilXml.data(using: .utf8)!),
            (type: UInt32(CSBlobConstants.slotDerEntitlements), magic: UInt32(CSBlobConstants.entitlementDerMagic), data: emptyDer),
            (type: UInt32(CSBlobConstants.slotDerEntitlements), magic: UInt32(CSBlobConstants.entitlementDerMagic), data: evilDer)
        ])

        let parsed = try CSBlobParser.shared.parseSuperBlob(sb)
        print("[EMPIRICAL OBSERVATION] Dual Slot 5 + Slot 7 shadowed: format=\(parsed.formatUsed), count=\(parsed.appGroups.count), groups=\(parsed.appGroups)")

        XCTAssertTrue(parsed.hasAppGroups)
        XCTAssertEqual(parsed.formatUsed, .dual, "Must be classified as .dual format when both XML and DER are parsed")
        XCTAssertEqual(parsed.appGroups.count, 3, "group.shared.both must be deduplicated across XML and DER")
        XCTAssertTrue(parsed.appGroups.contains("group.shared.both"))
        XCTAssertTrue(parsed.appGroups.contains("group.xml.exclusive"))
        XCTAssertTrue(parsed.appGroups.contains("group.der.exclusive"))
    }

    /// 2.5 Corrupted / Garbage Slot 5 preceding Valid Slot 5:
    /// Parser must gracefully tolerate malformed initial slot without throwing, recovering subsequent valid slot.
    func test_M6_Gate1_CSBlob_corruptedSlot5PrecedingValidSlot5() throws {
        let garbageBytes = Data([0xFF, 0xFE, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        let validXml = """
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <plist version=\"1.0\"><dict><key>com.apple.security.application-groups</key><array>
            <string>group.recovered.valid</string>
        </array></dict></plist>
        """

        let sb = assembleSuperBlob(entries: [
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: garbageBytes),
            (type: UInt32(CSBlobConstants.slotEntitlements), magic: UInt32(CSBlobConstants.entitlementXmlMagic), data: validXml.data(using: .utf8)!)
        ])

        let parsed = try CSBlobParser.shared.parseSuperBlob(sb)
        print("[EMPIRICAL OBSERVATION] Corrupted preceding slot: hasAppGroups=\(parsed.hasAppGroups), groups=\(parsed.appGroups)")

        XCTAssertTrue(parsed.hasAppGroups, "Must extract valid App Groups even if preceding slot contains corrupted data")
        XCTAssertEqual(parsed.appGroups, ["group.recovered.valid"])
    }
}
