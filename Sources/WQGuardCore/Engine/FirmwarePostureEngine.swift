//
//  FirmwarePostureEngine.swift
//  WQGuardCore
//
//  Feature 26: Firmware CVE Exposure Radar & Non-Upgrade Mitigation Advisor.
//  Evaluates device OS version against known 2026 iOS vulnerabilities and
//  provides actionable non-upgrade mitigations for users remaining on older firmware.
//

import Foundation

// MARK: - 1. System OS Version Model

/// Semantic OS version representation with branch-aware comparison.
///
/// Ordering and equality (`<`, `==`, `hash`) consider ONLY `major`/`minor`/`patch`, keeping the
/// `Comparable` contract consistent (`27.2` == `27.2.0 (24C101)`). Pre-release metadata (`prerelease`)
/// is evaluated separately at CVE boundaries where a fix landed mid-beta (e.g. worse_query in 27.3 beta 2).
public struct SystemOSVersion: Codable, Sendable, Equatable, Hashable, Comparable {
    public let major: Int
    public let minor: Int
    public let patch: Int
    public let build: String?
    public let rawString: String?
    /// Normalized pre-release tag: `"beta<N>"`, `"beta"` (unnumbered/unparseable), `"rc"`, `"rc<N>"`,
    /// `"alpha<N>"`, `"dev"`, or `nil` for GA builds.
    public let prerelease: String?

    enum CodingKeys: String, CodingKey {
        case major, minor, patch, build, rawString, prerelease
    }

    public init(major: Int, minor: Int, patch: Int = 0, build: String? = nil, rawString: String? = nil, prerelease: String? = nil) {
        self.major = major
        self.minor = minor
        self.patch = patch
        self.build = build
        self.rawString = rawString
        self.prerelease = prerelease
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let major = try container.decode(Int.self, forKey: .major)
        let minor = try container.decode(Int.self, forKey: .minor)
        let patch = try container.decode(Int.self, forKey: .patch)
        guard major >= 0, minor >= 0, patch >= 0 else {
            throw DecodingError.dataCorruptedError(
                forKey: .major,
                in: container,
                debugDescription: "OS version components must be non-negative"
            )
        }
        self.major = major
        self.minor = minor
        self.patch = patch
        self.build = try container.decodeIfPresent(String.self, forKey: .build)
        self.rawString = try container.decodeIfPresent(String.self, forKey: .rawString)
        self.prerelease = try container.decodeIfPresent(String.self, forKey: .prerelease)
    }

    public init(operatingSystemVersion: OperatingSystemVersion, build: String? = nil) {
        self.major = operatingSystemVersion.majorVersion
        self.minor = operatingSystemVersion.minorVersion
        self.patch = operatingSystemVersion.patchVersion
        self.build = build
        self.rawString = "\(operatingSystemVersion.majorVersion).\(operatingSystemVersion.minorVersion).\(operatingSystemVersion.patchVersion)"
        self.prerelease = nil
    }

    private static let versionCoreRegex: NSRegularExpression? = try? NSRegularExpression(
        pattern: #"(\d+)\.(\d+)(?:\.(\d+))?(?:[^\w]*\(([\w]+)\))?"#
    )
    private static let rsrSuffixRegex: NSRegularExpression? = try? NSRegularExpression(
        pattern: #"\(\s*[a-zA-Z]\s*\)"#
    )
    private static let prereleaseRegex: NSRegularExpression? = try? NSRegularExpression(
        pattern: #"(?:^|[\-_.(]\s*|\s+)(?:(?:developer|public)\s+)?(beta|seed|rc|alpha|dev|b|a)(?![A-Za-z])(?:\s*[-_.]?\s*([0-9]+))?"#,
        options: [.caseInsensitive]
    )

    /// Parses version strings such as "26.2", "iOS 27.1", "26.7.2 (24B123)", "27.2.1-beta1", "27.3b1",
    /// "27.3 beta 1 (24D5001a)", "27.3.0-rc".
    public init?(string: String) {
        guard !string.isEmpty, string.utf8.count <= 256 else {
            return nil
        }
        guard let regex = Self.versionCoreRegex,
              let match = regex.firstMatch(in: string, range: NSRange(string.startIndex..., in: string)) else {
            return nil
        }

        func extract(group: Int) -> String? {
            guard group < match.numberOfRanges, let r = Range(match.range(at: group), in: string) else { return nil }
            return String(string[r])
        }

        // Reject negative version numbers (e.g. "-27.3", " -27.3", "iOS -27.3", "27.-3.1", "−27.3")
        // while preserving hyphenated label prefixes such as "iOS-27.3".
        if let majorRange = Range(match.range(at: 1), in: string) {
            let prefix = string[..<majorRange.lowerBound]
            if prefix.hasSuffix("\u{2212}") {
                return nil
            }
            if prefix.hasSuffix("-") {
                let beforeMinus = prefix.dropLast().last
                let hasAlphaPrefix = beforeMinus.map { $0.isASCII && $0.isLetter } ?? false
                if !hasAlphaPrefix {
                    return nil
                }
            }
        }

        guard let majorStr = extract(group: 1), let major = Int(majorStr),
              let minorStr = extract(group: 2), let minor = Int(minorStr) else {
            return nil
        }

        // Fail-safe: on oversized/non-ASCII patch component, fall back to 0 (< patched threshold) so
        // vulnerable builds like "26.7.99999999999999999999" and "26.7.\u{FF13}" stay EXPOSED.
        let patch = extract(group: 3).flatMap { Int($0) } ?? 0
        let build = extract(group: 4)

        // Pre-release tag: inspect the text right after the numeric core (before any build parenthetical).
        let coreGroup = match.range(at: 3).location != NSNotFound ? 3 : 2
        var remainder = ""
        if let coreRange = Range(match.range(at: coreGroup), in: string) {
            remainder = String(string[coreRange.upperBound...])
        }
        if remainder.hasPrefix(".-") || remainder.hasPrefix(".\u{2212}") {
            return nil
        }

        self.major = major
        self.minor = minor
        self.patch = patch
        self.build = build
        self.rawString = string
        self.prerelease = SystemOSVersion.parsePrerelease(remainder)
    }

    /// Extracts a normalized pre-release tag from the text following the numeric version core.
    /// Unrecognized-but-present beta markers normalize to `"beta"` (unnumbered), which callers treat
    /// as the EARLIEST pre-release (fail-safe: never assumed to contain a mid-beta fix).
    static func parsePrerelease(_ remainder: String) -> String? {
        guard !remainder.isEmpty else { return nil }
        guard remainder.utf8.count <= 256 else { return "beta" }

        // Strip Apple Rapid Security Response / Background Security Improvement post-GA suffixes such as " (a)", " (b)", " (c)"
        // so "iOS 27.3 (a)" is never misclassified as an alpha/beta pre-release.
        let cleanedRemainder: String
        if let rsrRegex = Self.rsrSuffixRegex {
            let range = NSRange(remainder.startIndex..<remainder.endIndex, in: remainder)
            cleanedRemainder = rsrRegex.stringByReplacingMatches(in: remainder, range: range, withTemplate: " ")
        } else {
            cleanedRemainder = remainder
        }

        if let regex = Self.prereleaseRegex {
            let matches = regex.matches(
                in: cleanedRemainder,
                range: NSRange(cleanedRemainder.startIndex..., in: cleanedRemainder)
            )
            for m in matches {
                guard let tagRange = Range(m.range(at: 1), in: cleanedRemainder) else { continue }
                let tag = cleanedRemainder[tagRange].lowercased()
                var number: Int?
                if let numRange = Range(m.range(at: 2), in: cleanedRemainder) {
                    number = Int(cleanedRemainder[numRange])
                    if number == nil { return tag == "rc" ? "rc" : "beta" } // overflow => unclassifiable
                }
                // Single-letter "a"/"b" without an explicit number is only treated as alpha/beta when directly attached (e.g. "27.3b"),
                // avoiding false pre-release matches on standalone words/initials while continuing to scan later tokens (e.g. "27.3 A beta 1").
                if (tag == "a" || tag == "b") && number == nil {
                    guard let fullRange = Range(m.range(at: 0), in: cleanedRemainder) else { continue }
                    let matchedSlice = cleanedRemainder[fullRange]
                    if matchedSlice.first?.isWhitespace == true || matchedSlice.first == "(" {
                        continue
                    }
                }
                switch tag {
                case "beta", "b", "seed":
                    if let n = number { return "beta\(n)" }
                    return "beta"
                case "rc":
                    if let n = number { return "rc\(n)" }
                    return "rc"
                case "alpha", "a":
                    if let n = number { return "alpha\(n)" }
                    return "alpha"
                default:
                    return "dev"
                }
            }
        }

        // Any other mention of a pre-release keyword => unclassifiable beta (fail-safe).
        let lower = cleanedRemainder.lowercased()
        if lower.contains("beta") || lower.contains("seed") || lower.contains("alpha") {
            return "beta"
        }
        return nil
    }

    /// Beta ordinal for pre-release builds: `nil` for GA / RC builds, `0` for unclassifiable or
    /// pre-beta (alpha/dev) builds, `N` for "beta N".
    public var betaOrdinal: Int? {
        guard let tag = prerelease?.lowercased(), !tag.isEmpty else { return nil }
        if tag.hasPrefix("rc") { return nil }
        if tag.hasPrefix("beta") {
            return Int(tag.dropFirst(4)) ?? 0
        }
        return 0
    }

    public static func == (lhs: SystemOSVersion, rhs: SystemOSVersion) -> Bool {
        lhs.major == rhs.major && lhs.minor == rhs.minor && lhs.patch == rhs.patch
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(major)
        hasher.combine(minor)
        hasher.combine(patch)
    }

    public static func < (lhs: SystemOSVersion, rhs: SystemOSVersion) -> Bool {
        if lhs.major != rhs.major { return lhs.major < rhs.major }
        if lhs.minor != rhs.minor { return lhs.minor < rhs.minor }
        return lhs.patch < rhs.patch
    }

    public static var currentDevice: SystemOSVersion {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return SystemOSVersion(operatingSystemVersion: v)
    }

    public var displayString: String {
        if let raw = rawString, !raw.isEmpty {
            let sanitized = ReportGenerator.shared.plain(raw).trimmingCharacters(in: .whitespaces)
            if !sanitized.isEmpty {
                return sanitized
            }
        }
        var base = "\(major).\(minor).\(patch)"
        if let b = build { base += " (\(ReportGenerator.shared.plain(b)))" }
        return base
    }
}

// MARK: - 2. Actionable Mitigation Models

public enum MitigationCategory: String, Codable, Sendable, CaseIterable {
    case networkProxy = "NETWORK_PROXY"         // Surge / Proxy Header Rewrite
    case systemSettings = "SYSTEM_SETTINGS"     // iOS System Settings Toggle
    case appHygiene = "APP_HYGIENE"             // App Hygiene & Configuration
    case wqguardScan = "WQGUARD_SCAN"           // WQGuard Scan & Audit
}

public struct ActionableMitigation: Codable, Sendable, Identifiable, Equatable, Hashable {
    public var id: String { "\(category.rawValue):\(title)" }
    public let title: String
    public let instructions: String
    public let category: MitigationCategory
    public let actionUrl: String?
    public let relatedCVEs: [String]

    public init(
        title: String,
        instructions: String,
        category: MitigationCategory,
        actionUrl: String? = nil,
        relatedCVEs: [String] = []
    ) {
        self.title = title
        self.instructions = instructions
        self.category = category
        self.actionUrl = actionUrl
        self.relatedCVEs = relatedCVEs
    }
}

// MARK: - 3. Firmware Vulnerability Definition

public enum FirmwareCVEID: String, Codable, Sendable, CaseIterable {
    case worseQuery0day = "0day:worse_query"
    case photosBypass = "CVE-2026-112676"
    case brotliOOB = "CVE-2026-111497"
    case coreGraphicsPDF = "CVE-2026-112611"
    case coreGraphics2D = "CVE-2026-86950"
    case appIntentsBypass = "CVE-2026-113963"
    case imessageGroup = "CVE-2026-113960"
    case bluetoothAirPlay = "CVE-2026-113964-70"
    case audioMxdBypass = "CVE-2026-65339"
    case dyldZeroDay = "CVE-2026-20700"
    case webkitSandboxEscape = "CVE-2026-113897"
    case accessorySetupBluetooth = "CVE-2026-84493"
    case bookRestoreEscape = "PoC:BookRestore"
}

public struct FirmwareVulnerability: Codable, Sendable, Identifiable, Equatable {
    public var id: String { cveId.rawValue }
    public let cveId: FirmwareCVEID
    public let name: String
    public let subsystem: String
    public let cvssScore: Double?
    public let severity: RiskTier
    public let affectedDescription: String
    public let patchedVersionDescription: String
    public let details: String
    public let mitigations: [ActionableMitigation]

    public init(
        cveId: FirmwareCVEID,
        name: String,
        subsystem: String,
        cvssScore: Double?,
        severity: RiskTier,
        affectedDescription: String,
        patchedVersionDescription: String,
        details: String,
        mitigations: [ActionableMitigation]
    ) {
        self.cveId = cveId
        self.name = name
        self.subsystem = subsystem
        self.cvssScore = cvssScore
        self.severity = severity
        self.affectedDescription = affectedDescription
        self.patchedVersionDescription = patchedVersionDescription
        self.details = details
        self.mitigations = mitigations
    }
}

// MARK: - 4. Firmware Posture Report Model

public struct FirmwarePostureReport: Codable, Sendable, Equatable {
    public let osVersion: SystemOSVersion
    public let evaluatedAt: Date
    public let overallRiskTier: RiskTier
    public let exposedVulnerabilities: [FirmwareVulnerability]
    public let patchedVulnerabilities: [FirmwareVulnerability]
    public let actionableMitigations: [ActionableMitigation]
    public let totalEvaluated: Int
    public let exposedCount: Int

    public init(
        osVersion: SystemOSVersion,
        evaluatedAt: Date = Date(),
        exposedVulnerabilities: [FirmwareVulnerability],
        patchedVulnerabilities: [FirmwareVulnerability],
        actionableMitigations: [ActionableMitigation]
    ) {
        self.osVersion = osVersion
        self.evaluatedAt = evaluatedAt
        self.exposedVulnerabilities = exposedVulnerabilities
        self.patchedVulnerabilities = patchedVulnerabilities
        self.actionableMitigations = actionableMitigations
        self.totalEvaluated = exposedVulnerabilities.count + patchedVulnerabilities.count
        self.exposedCount = exposedVulnerabilities.count
        
        if exposedVulnerabilities.contains(where: { $0.severity == .highRisk }) {
            self.overallRiskTier = .highRisk
        } else if exposedVulnerabilities.contains(where: { $0.severity == .caution }) {
            self.overallRiskTier = .caution
        } else {
            self.overallRiskTier = .safe
        }
    }
}

// MARK: - 5. Firmware Posture Engine Evaluator

public final class FirmwarePostureEngine: Sendable {
    public static let shared = FirmwarePostureEngine()

    public init() {}

    /// Evaluates vulnerability exposure for a specific OS version.
    public func isVulnerable(_ cve: FirmwareCVEID, in version: SystemOSVersion) -> Bool {
        guard version.major >= 0, version.minor >= 0, version.patch >= 0 else {
            return true // Fail-closed on negative version components
        }
        switch cve {
        case .worseQuery0day:
            // Patched in iOS 27.3 beta 2+ / iOS 27.3; iOS 26.0 - 26.7.3 and 27.0 - 27.2.1 remain exposed
            if version.major < 26 {
                return false
            } else if version.major == 26 {
                return true
            } else if version.major == 27 {
                if version < SystemOSVersion(major: 27, minor: 3, patch: 0) { return true }
                // 27.3.0 pre-releases: only beta 2+ (and RC/GA) carry the fix. Beta 1 and any
                // unclassifiable pre-release tag fail safe as EXPOSED.
                if version.minor == 3, version.patch == 0, let beta = version.betaOrdinal, beta < 2 {
                    return true
                }
                return false
            } else {
                return false
            }

        case .photosBypass, .coreGraphicsPDF, .webkitSandboxEscape:
            // Patched in iOS 27.2 and iOS 26.7.2
            return isExposedBranchMatrix(
                version: version,
                ios26Patch: SystemOSVersion(major: 26, minor: 7, patch: 2),
                ios27Patch: SystemOSVersion(major: 27, minor: 2, patch: 0)
            )

        case .brotliOOB, .appIntentsBypass, .imessageGroup, .bluetoothAirPlay:
            // Patched in iOS 27.2.1 and iOS 26.7.3
            return isExposedBranchMatrix(
                version: version,
                ios26Patch: SystemOSVersion(major: 26, minor: 7, patch: 3),
                ios27Patch: SystemOSVersion(major: 27, minor: 2, patch: 1)
            )

        case .coreGraphics2D:
            // CVE-2026-86950: Patched in iOS 27.0, iOS 26.7.1, and iOS 18.7.11
            return isExposedBranchMatrix(
                version: version,
                ios18Patch: SystemOSVersion(major: 18, minor: 7, patch: 11),
                ios26Patch: SystemOSVersion(major: 26, minor: 7, patch: 1),
                ios27Patch: nil
            )

        case .audioMxdBypass:
            // CVE-2026-65339: Patched in iOS 27.0, iOS 26.6.1, and iOS 18.7.11
            return isExposedBranchMatrix(
                version: version,
                ios18Patch: SystemOSVersion(major: 18, minor: 7, patch: 11),
                ios26Patch: SystemOSVersion(major: 26, minor: 6, patch: 1),
                ios27Patch: nil
            )

        case .dyldZeroDay:
            // CVE-2026-20700: Patched in iOS 27.0, iOS 26.3, and iOS 18.7.5
            return isExposedBranchMatrix(
                version: version,
                ios18Patch: SystemOSVersion(major: 18, minor: 7, patch: 5),
                ios26Patch: SystemOSVersion(major: 26, minor: 3, patch: 0),
                ios27Patch: nil
            )

        case .accessorySetupBluetooth:
            // CVE-2026-84493: Patched in iOS 27.2 and iOS 26.7.2 (iOS 18+ only)
            return isExposedBranchMatrix(
                version: version,
                minMajor: 18,
                ios26Patch: SystemOSVersion(major: 26, minor: 7, patch: 2),
                ios27Patch: SystemOSVersion(major: 27, minor: 2, patch: 0)
            )

        case .bookRestoreEscape:
            // PoC:BookRestore / bl_sbx: Patched in iOS 27.0 and iOS 26.2 (iOS 18+ only)
            return isExposedBranchMatrix(
                version: version,
                minMajor: 18,
                ios26Patch: SystemOSVersion(major: 26, minor: 2, patch: 0),
                ios27Patch: nil
            )
        }
    }

    private func isExposedBranchMatrix(
        version: SystemOSVersion,
        minMajor: Int = 0,
        ios18Patch: SystemOSVersion? = nil,
        ios26Patch: SystemOSVersion,
        ios27Patch: SystemOSVersion?
    ) -> Bool {
        if version.major < minMajor {
            return false
        }
        if let p27 = ios27Patch {
            if version.major >= 28 {
                return false
            }
            if version.major == 27 {
                return version < p27
            }
        } else if version.major >= 27 {
            return false
        }

        if version.major == 26 {
            return version < ios26Patch
        }
        if let p18 = ios18Patch, version.major == 18 {
            return version < p18
        }
        return true
    }

    /// Evaluates firmware posture against all cataloged vulnerabilities.
    public func evaluate(osVersion: SystemOSVersion = .currentDevice) -> FirmwarePostureReport {
        let catalog = Self.allVulnerabilities

        var exposed: [FirmwareVulnerability] = []
        var patched: [FirmwareVulnerability] = []
        var mitigations: [ActionableMitigation] = []

        for vuln in catalog {
            if isVulnerable(vuln.cveId, in: osVersion) {
                exposed.append(vuln)
                mitigations.append(contentsOf: vuln.mitigations)
            } else {
                patched.append(vuln)
            }
        }

        // Deduplicate mitigations by ID while preserving order
        var seenIds = Set<String>()
        var uniqueMitigations: [ActionableMitigation] = []
        for m in mitigations {
            if !seenIds.contains(m.id) {
                seenIds.insert(m.id)
                uniqueMitigations.append(m)
            }
        }

        return FirmwarePostureReport(
            osVersion: osVersion,
            exposedVulnerabilities: exposed,
            patchedVulnerabilities: patched,
            actionableMitigations: uniqueMitigations
        )
    }

    // MARK: - Static Catalog Data
    public static var allVulnerabilities: [FirmwareVulnerability] {
        [
            FirmwareVulnerability(
                cveId: .worseQuery0day,
                name: WQLocale.pick(
                    en: "containermanagerd Cross-Sandbox Token Escape (worse_query / bad_query)",
                    zh: "containermanagerd 跨沙盒令牌签发逃逸 (worse_query / bad_query)"
                ),
                subsystem: "Darwin Sandbox / containermanagerd",
                cvssScore: 8.8,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS 26.0 – 26.7.3 and iOS 27.0 – 27.2.1",
                    zh: "iOS 26.0 – 26.7.3 及 iOS 27.0 – 27.2.1"
                ),
                patchedVersionDescription: WQLocale.pick(
                    en: "iOS 27.3 (patched in iOS 27.3 beta 2+)",
                    zh: "iOS 27.3（已于 iOS 27.3 beta 2+ 修复）"
                ),
                details: WQLocale.pick(
                    en: "Confused-deputy flaw in containermanagerd when handling class=7 (App Group) part=3 (Library/Caches) queries without prefix containment checks. Combined with escaping symlinks and fsgetpath inode enumeration, it tricks the kernel into issuing sandbox extension tokens for arbitrary app containers. Patched by Apple in iOS 27.3 beta 2+ / iOS 27.3, while iOS 26.0–26.7.3 and 27.0–27.2.1 remain exposed.",
                    zh: "利用 containermanagerd 在处理 class=7 (App Group) part=3 (Library/Caches) 查询时缺少路径前缀隔离校验的 Confused Deputy 漏洞，结合 escaping symlink 与 fsgetpath 诱导内核签发任意 App 容器的沙盒扩展令牌。Apple 已在 iOS 27.3 beta 2+ / iOS 27.3 修复，iOS 26.0–26.7.3 与 27.0–27.2.1 仍受影响。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Mandatory Pre-Install IPA Audit",
                            zh: "侧载应用安装前强制审计"
                        ),
                        instructions: WQLocale.pick(
                            en: "Before launching any third-party sideloaded or enterprise-signed IPA, run WQGuard static & sandbox analysis to catch App Group apps invoking containermanagerd IPC or symlink escape primitives.",
                            zh: "在启动任何外部侧载或企业证书签名的 IPA 之前，使用 WQGuard 运行静态与沙盒分析，拦截声明 App Group 并包含 containermanagerd IPC/逃逸特征的应用。"
                        ),
                        category: .wqguardScan,
                        relatedCVEs: ["0day:worse_query"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .photosBypass,
                name: WQLocale.pick(
                    en: "Apple Photos Private TCC Prompt & Access Bypass (CVE-2026-112676)",
                    zh: "Apple Photos 私有相册隐私提示与权限绕过 (CVE-2026-112676)"
                ),
                subsystem: "Photos / TCC Privacy",
                cvssScore: 7.5,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS < 27.2 and iOS 26 < 26.7.2",
                    zh: "iOS < 27.2 且 iOS 26 < 26.7.2"
                ),
                patchedVersionDescription: "iOS 27.2 / iOS 26.7.2",
                details: WQLocale.pick(
                    en: "Malicious local apps can link private \(IOCTokenArmor.tPhotoLibSvc) frameworks or spoof private entitlements to bypass iOS TCC photo authorization prompts and silently exfiltrate user photos and screenshots.",
                    zh: "恶意本地应用可调用私有框架 \(IOCTokenArmor.tPhotoLibSvc) 或利用私有 Entitlement 绕过 iOS TCC 相册访问授权提示，在后台静默读取用户相册与截图。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Remove Sensitive Credentials from Photos",
                            zh: "相册敏感凭证清退"
                        ),
                        instructions: WQLocale.pick(
                            en: "Never keep screenshots of crypto seed phrases, private keys, or identity documents in the system Photo Library; move sensitive images into a hardware-encrypted vault.",
                            zh: "切勿在系统相册中保存加密货币助记词/私钥截图或敏感身份证件；及时将机密照片移至硬件加密金库。"
                        ),
                        category: .appHygiene,
                        relatedCVEs: ["CVE-2026-112676"]
                    ),
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Scan IPAs for Private Photos Frameworks",
                            zh: "开启相册私有调用扫描"
                        ),
                        instructions: WQLocale.pick(
                            en: "Inspect local IPAs with WQGuard to catch unauthorized \(IOCTokenArmor.tPhotoLibSvc) / \(IOCTokenArmor.tPLPhotoLib) linkages.",
                            zh: "使用 WQGuard 扫描本地 IPA，排查非法引用 \(IOCTokenArmor.tPhotoLibSvc) / \(IOCTokenArmor.tPLPhotoLib) 的可疑软件包。"
                        ),
                        category: .wqguardScan,
                        relatedCVEs: ["CVE-2026-112676"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .brotliOOB,
                name: WQLocale.pick(
                    en: "Brotli Decoder Heap Out-of-Bounds Write / RCE (HTTP2Shell, CVE-2026-111497)",
                    zh: "Brotli 解码器堆越界写入 / 远程代码执行 (HTTP2Shell, CVE-2026-111497)"
                ),
                subsystem: "libbrotli / WebKit / CFNetwork",
                cvssScore: 9.2,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS < 27.2.1 and iOS 26 < 26.7.3",
                    zh: "iOS < 27.2.1 且 iOS 26 < 26.7.3"
                ),
                patchedVersionDescription: "iOS 27.2.1 / iOS 26.7.3",
                details: WQLocale.pick(
                    en: "Heap buffer out-of-bounds write in the libbrotli decoder. A malicious server returning a crafted Content-Encoding: br response can corrupt memory and achieve code execution in CFNetwork / WebKit.",
                    zh: "libbrotli 解码器中存在堆缓冲区越界写入缺陷。恶意服务端通过 HTTP/2 下发精心构造的 Content-Encoding: br 压缩流，可诱发 CFNetwork / WebKit 进程内存破坏与任意代码执行。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Enable Proxy Brotli Downgrade Shield (Surge / Shadowrocket / Quantumult X / Loon / Stash)",
                            zh: "启用代理工具 Brotli 降级护盾 (Surge / 小火箭 / 圈 X / Loon / Stash)"
                        ),
                        instructions: WQLocale.pick(
                            en: "Import WQGuard's Brotli Downgrade Shield into Surge, Shadowrocket, Quantumult X, Loon, or Stash to rewrite Accept-Encoding to 'gzip, deflate' and block unsolicited Content-Encoding: br responses.",
                            zh: "在 Surge、Shadowrocket、Quantumult X、Loon 或 Stash 中导入 WQGuard · 防 Brotli 溢出降级护盾规则，强制将 HTTP 请求头 Accept-Encoding 降级为 'gzip, deflate'，阻断网络传输层下发的恶意 Brotli 数据流。"
                        ),
                        category: .networkProxy,
                        actionUrl: "surge:///install-module",
                        relatedCVEs: ["CVE-2026-111497"]
                    ),
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Enable iOS Lockdown Mode",
                            zh: "开启 Safari 锁定模式 (Lockdown Mode)"
                        ),
                        instructions: WQLocale.pick(
                            en: "For untrusted links and WOFF2 web font hardening, enable strict protection under Settings -> Privacy & Security -> Lockdown Mode.",
                            zh: "对于访问不可信外部链接，在'设置 -> 隐私与安全性 -> 锁定模式'中针对特定网页启用严格防护。"
                        ),
                        category: .systemSettings,
                        actionUrl: "App-Prefs:root=Privacy&path=LOCKDOWN_MODE",
                        relatedCVEs: ["CVE-2026-111497"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .coreGraphicsPDF,
                name: WQLocale.pick(
                    en: "CoreGraphics Malicious PDF Font & Image OOB Write (CVE-2026-112611)",
                    zh: "CoreGraphics 恶意 PDF 字体与图像渲染越界写入 (CVE-2026-112611)"
                ),
                subsystem: "CoreGraphics / PDFKit",
                cvssScore: 8.8,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS < 27.2 and iOS 26 < 26.7.2",
                    zh: "iOS < 27.2 且 iOS 26 < 26.7.2"
                ),
                patchedVersionDescription: "iOS 27.2 / iOS 26.7.2",
                details: WQLocale.pick(
                    en: "Heap overflow in CoreGraphics while parsing crafted embedded PDF fonts and color spaces, enabling zero-click or one-click exploitation via malicious PDF files.",
                    zh: "CoreGraphics 解析特定格式嵌入式字体与色彩空间时发生堆溢出，可能被攻击者通过恶意 PDF 文件实施零点击或单点击攻击。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Disable Messenger Auto-Download",
                            zh: "关闭即时通讯软件自动下载"
                        ),
                        instructions: WQLocale.pick(
                            en: "Disable automatic media and file downloads in Telegram (Settings -> Data and Storage) and WeChat (Settings -> General -> Photos, Videos, Files & Calls).",
                            zh: "在 Telegram（设置 -> 数据与存储）和微信（设置 -> 通用 -> 照片、视频、文件和通话）中关闭'自动下载媒体与文件'。"
                        ),
                        category: .appHygiene,
                        relatedCVEs: ["CVE-2026-112611"]
                    ),
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Avoid QuickLook Previewing Untrusted PDFs",
                            zh: "避免本地快速预览未知 PDF"
                        ),
                        instructions: WQLocale.pick(
                            en: "Do not preview unknown PDF files directly in system QuickLook, Safari, or unisolated local document readers.",
                            zh: "切勿在系统 QuickLook、Safari 或未隔离的本地阅读器中直接预览来源不明的 PDF 文件。"
                        ),
                        category: .appHygiene,
                        relatedCVEs: ["CVE-2026-112611"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .coreGraphics2D,
                name: WQLocale.pick(
                    en: "CoreGraphics 2D Image Subsystem Memory Corruption 0-day (CVE-2026-86950)",
                    zh: "CoreGraphics 2D 图形引擎内存破坏 0day (CVE-2026-86950)"
                ),
                subsystem: "CoreGraphics / Quartz2D",
                cvssScore: 8.6,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS 26 < 26.7.1, iOS 18 < 18.7.11 (and unpatched legacy branches)",
                    zh: "iOS 26 < 26.7.1、iOS 18 < 18.7.11（及未获回移植补丁的旧分支）"
                ),
                patchedVersionDescription: "iOS 27.0 / iOS 26.7.1 / iOS 18.7.11",
                details: WQLocale.pick(
                    en: "Unbounded memory copy when parsing crafted ICC profiles (officially patched by Apple in iOS 27.0, iOS 26.7.1, and iOS 18.7.11). Devices below 26.7.1 or 18.7.11 remain vulnerable to crafted image payloads.",
                    zh: "图像子系统解析特定 ICC Profile 时存在无界内存复制缺陷（Apple 已在 iOS 27.0、iOS 26.7.1 与 iOS 18.7.11 发布官方安全补丁）；停留在低于 26.7.1 或 18.7.11 的设备易被恶意图像触发内存破坏。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Disable Automatic Image Rendering in Messengers",
                            zh: "禁用通讯软件图像自动渲染"
                        ),
                        instructions: WQLocale.pick(
                            en: "Disable automatic image prefetching and inline rendering in messaging apps to prevent silent processing of crafted image metadata.",
                            zh: "禁用即时通讯软件中的图片自动渲染与预加载功能，防止后台静默渲染恶意图像元数据。"
                        ),
                        category: .appHygiene,
                        relatedCVEs: ["CVE-2026-86950"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .appIntentsBypass,
                name: WQLocale.pick(
                    en: "App Intents & Shortcuts Privilege Authorization Bypass (CVE-2026-113963)",
                    zh: "App Intents 与快捷指令提权授权绕过 (CVE-2026-113963)"
                ),
                subsystem: "AppIntents / Shortcuts",
                cvssScore: 7.8,
                severity: .caution,
                affectedDescription: WQLocale.pick(
                    en: "iOS < 27.2.1 and iOS 26 < 26.7.3",
                    zh: "iOS < 27.2.1 且 iOS 26 < 26.7.3"
                ),
                patchedVersionDescription: "iOS 27.2.1 / iOS 26.7.3",
                details: WQLocale.pick(
                    en: "Crafted AppIntent metadata can bypass system authorization prompts to silently invoke privileged services and clipboard access.",
                    zh: "恶意应用可通过构造特定 AppIntent 元数据绕过系统权限确认对话框，自动触发具备高权限的系统服务与剪贴板访问。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Audit Shortcuts Automations Regularly",
                            zh: "定期审计快捷指令自动化"
                        ),
                        instructions: WQLocale.pick(
                            en: "Open the Apple Shortcuts app and remove unreviewed third-party shared shortcuts or automations.",
                            zh: "进入系统'快捷指令'应用，清理未经审核的第三方共享脚本与自动化流程。"
                        ),
                        category: .appHygiene,
                        actionUrl: "shortcuts://",
                        relatedCVEs: ["CVE-2026-113963"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .imessageGroup,
                name: WQLocale.pick(
                    en: "iMessage Blastdoor Unauthorized Group Join & History Leak (CVE-2026-113960/1)",
                    zh: "iMessage Blastdoor 群聊未授权加入与历史泄露 (CVE-2026-113960/1)"
                ),
                subsystem: "Messages / Blastdoor",
                cvssScore: 8.1,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS < 27.2.1 and iOS 26 < 26.7.3",
                    zh: "iOS < 27.2.1 且 iOS 26 < 26.7.3"
                ),
                patchedVersionDescription: "iOS 27.2.1 / iOS 26.7.3",
                details: WQLocale.pick(
                    en: "Logic flaw in iMessage protocol Group Action parsing that can expose participant lists and partial history metadata.",
                    zh: "iMessage 协议层在解析畸形 Group Action 消息时存在逻辑漏洞，攻击者可诱导客户端泄露群聊参与者列表及部分未解密历史摘要。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Enable Filter Unknown Senders",
                            zh: "开启未知发件人信息过滤"
                        ),
                        instructions: WQLocale.pick(
                            en: "Enable Settings -> Messages -> Filter Unknown Senders, and never share wallet seed phrases or credentials inside group chats.",
                            zh: "进入'设置 -> 信息'，启用'过滤未知发件人'；不要在多人群聊中传递钱包助记词或账户敏感凭据。"
                        ),
                        category: .systemSettings,
                        actionUrl: "App-Prefs:root=MESSAGES",
                        relatedCVEs: ["CVE-2026-113960"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .bluetoothAirPlay,
                name: WQLocale.pick(
                    en: "Bluetooth CoreUtils Zero-Click Pairing & AirPlay UAF (CVE-2026-113964–70)",
                    zh: "Bluetooth CoreUtils 零点击配对与 AirPlay 释放后使用 (CVE-2026-113964–70)"
                ),
                subsystem: "Bluetooth / AirPlay / rapportd",
                cvssScore: 8.8,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS < 27.2.1 and iOS 26 < 26.7.3",
                    zh: "iOS < 27.2.1 且 iOS 26 < 26.7.3"
                ),
                patchedVersionDescription: "iOS 27.2.1 / iOS 26.7.3",
                details: WQLocale.pick(
                    en: "Rate-limit bypass and use-after-free memory corruption in CoreUtils proximity pairing and AirPlay rapportd daemon, allowing nearby attackers to probe or exploit wireless services.",
                    zh: "CoreUtils 蓝牙邻近配对状态机及 AirPlay rapportd 守护进程中存在速率限制绕过与 UAF 内存破坏漏洞，附近恶意发射源可发起未授权配对嗅探。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Set Automatically AirPlay to Never",
                            zh: "将自动隔空播放设为从不"
                        ),
                        instructions: WQLocale.pick(
                            en: "Go to Settings -> General -> AirPlay & Continuity and set Automatically AirPlay to Never.",
                            zh: "进入'设置 -> 通用 -> 隔空播放与接力'，将'自动隔空播放到电视'调整为'从不'。"
                        ),
                        category: .systemSettings,
                        actionUrl: "App-Prefs:root=General&path=AIRPLAY",
                        relatedCVEs: ["CVE-2026-113964-70"]
                    ),
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Turn Off Bluetooth in Settings in Public",
                            zh: "公共场所彻底关闭蓝牙"
                        ),
                        instructions: WQLocale.pick(
                            en: "In airports, transit hubs, or untrusted public spaces, disable Bluetooth completely in Settings -> Bluetooth rather than only in Control Center.",
                            zh: "在机场、高铁站等不可信人员密集场所，前往'设置 -> 蓝牙'彻底关闭蓝牙开关（而非仅在控制中心临时断开）。"
                        ),
                        category: .systemSettings,
                        actionUrl: "App-Prefs:root=Bluetooth",
                        relatedCVEs: ["CVE-2026-113964-70"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .audioMxdBypass,
                name: WQLocale.pick(
                    en: "AudioMxd Microphone TCC & MediaExperience Bypass (CVE-2026-65339)",
                    zh: "AudioMxd 麦克风隐私权限与 MediaExperience 绕过 (CVE-2026-65339)"
                ),
                subsystem: "CoreMedia / audiomxd / MediaExperience",
                cvssScore: 7.8,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS < 27.0, iOS 26 < 26.6.1, iOS 18 < 18.7.11 (and unpatched legacy branches)",
                    zh: "iOS < 27.0、iOS 26 < 26.6.1、iOS 18 < 18.7.11（及未获补丁旧分支）"
                ),
                patchedVersionDescription: "iOS 27.0 / iOS 26.6.1 / iOS 18.7.11",
                details: WQLocale.pick(
                    en: "Privilege validation flaw in audiomxd and MediaExperience allows crafted apps to invoke private CMSession/AudioSession properties or spoof entitlements to bypass microphone TCC consent checks. Patched in iOS 27.0, 26.6.1, and 18.7.11.",
                    zh: "audiomxd 与 MediaExperience 进程存在权限校验缺陷，恶意应用可通过调用私有 CMSession/AudioSession 属性或伪造私有 Entitlement 绕过系统麦克风 TCC 授权提示。已于 iOS 27.0、26.6.1 及 18.7.11 修复。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Audit Microphone Permissions & Indicator",
                            zh: "核查麦克风权限与状态栏橙点"
                        ),
                        instructions: WQLocale.pick(
                            en: "Review Settings -> Privacy & Security -> Microphone and revoke access for untrusted sideloaded apps; watch for unexpected orange microphone indicators in Control Center.",
                            zh: "前往「设置 -> 隐私与安全性 -> 麦克风」撤回非必要应用的麦克风授权，并留意控制中心顶部的橙色麦克风调用指示灯。"
                        ),
                        category: .systemSettings,
                        actionUrl: "App-Prefs:root=Privacy&path=MICROPHONE",
                        relatedCVEs: ["CVE-2026-65339"]
                    ),
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Scan IPAs for AudioMxd Bypass Signatures",
                            zh: "扫描 IPA 中的 AudioMxd 越权特征"
                        ),
                        instructions: WQLocale.pick(
                            en: "Run WQGuard static IPA analysis to detect unauthorized \(IOCTokenArmor.tMediaExpFw) linkage, \(IOCTokenArmor.tCMSessionSetProp) symbols, or \(IOCTokenArmor.tAudioDaemon) XPC targeting.",
                            zh: "使用 WQGuard 扫描本地 IPA，排查非法引用 \(IOCTokenArmor.tMediaExpFw)、\(IOCTokenArmor.tCMSessionSetProp) 符号或访问 \(IOCTokenArmor.tAudioDaemon) 服务的可疑应用。"
                        ),
                        category: .wqguardScan,
                        relatedCVEs: ["CVE-2026-65339"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .dyldZeroDay,
                name: WQLocale.pick(
                    en: "dyld Dynamic Linker Arbitrary Memory Write 0-day (CVE-2026-20700)",
                    zh: "dyld 动态链接器任意内存写入 0day (CVE-2026-20700)"
                ),
                subsystem: "dyld / Mach-O Dynamic Linker",
                cvssScore: 7.8,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS < 27.0, iOS 26 < 26.3, iOS 18 < 18.7.5 (and unpatched legacy branches)",
                    zh: "iOS < 27.0、iOS 26 < 26.3、iOS 18 < 18.7.5（及未获补丁旧分支）"
                ),
                patchedVersionDescription: "iOS 27.0 / iOS 26.3 / iOS 18.7.5",
                details: WQLocale.pick(
                    en: "Memory corruption vulnerability in dyld dynamic linker image loading and Mach-O fixup parsing, exploited in the wild for arbitrary code execution via crafted binaries or web content chains. Patched in iOS 27.0, 26.3, and 18.7.5.",
                    zh: "dyld 动态链接器在解析 Mach-O 镜像加载与重定位数据时存在任意内存写入漏洞，可在恶意二进制或组合攻击链中触发越权代码执行。已于 iOS 27.0、26.3 及 18.7.5 修复。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Enable Lockdown Mode for High-Risk Targets",
                            zh: "高风险目标开启锁定模式 (Lockdown Mode)"
                        ),
                        instructions: WQLocale.pick(
                            en: "Enable Settings -> Privacy & Security -> Lockdown Mode to harden JIT/dyld attack surfaces against targeted exploit chains, and avoid installing unverified Mach-O binaries.",
                            zh: "前往「设置 -> 隐私与安全性 -> 锁定模式」启用严格防护以收紧 JIT 与动态加载攻击面，切勿安装来源不明的 Mach-O 应用。"
                        ),
                        category: .systemSettings,
                        actionUrl: "App-Prefs:root=Privacy&path=LOCKDOWN_MODE",
                        relatedCVEs: ["CVE-2026-20700"]
                    ),
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Audit Sideloaded Mach-O Binaries with WQGuard",
                            zh: "使用 WQGuard 审查侧载 Mach-O 二进制"
                        ),
                        instructions: WQLocale.pick(
                            en: "Inspect sideloaded IPAs with WQGuard prior to execution to catch anomalous dylibs, direct syscall evasion (svc #0x80), and unsigned executable payloads.",
                            zh: "在运行外部侧载 IPA 前使用 WQGuard 审查可疑动态库注入、内联直接系统调用 (svc #0x80) 与异常 Mach-O 载荷。"
                        ),
                        category: .wqguardScan,
                        relatedCVEs: ["CVE-2026-20700"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .webkitSandboxEscape,
                name: WQLocale.pick(
                    en: "WebKit GPU & WebContent Sandbox Escape Chain (CVE-2026-113897)",
                    zh: "WebKit 渲染与 GPU 进程沙盒逃逸链 (CVE-2026-113897)"
                ),
                subsystem: "WebKit / WebContent / GPU Process",
                cvssScore: 8.8,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS < 27.2 and iOS 26 < 26.7.2 (and unpatched legacy branches)",
                    zh: "iOS < 27.2 且 iOS 26 < 26.7.2（及未获补丁旧分支）"
                ),
                patchedVersionDescription: "iOS 27.2 / iOS 26.7.2",
                details: WQLocale.pick(
                    en: "Sandbox escape flaw in WebKit IPC and GPU process resource validation allowing compromised WebContent renderers to break out of the browser sandbox via malicious web pages. Patched in iOS 27.2 and 26.7.2.",
                    zh: "WebKit 进程间通信与 GPU 进程资源校验存在缺陷，受恶意网页攻破的 WebContent 渲染进程可借此突破浏览器沙盒隔离边界。已于 iOS 27.2 及 26.7.2 修复。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Harden Safari & WebView via Lockdown Mode",
                            zh: "通过锁定模式加固 Safari 与 WebView"
                        ),
                        instructions: WQLocale.pick(
                            en: "Enable Lockdown Mode (Settings -> Privacy & Security -> Lockdown Mode) or disable JavaScript for untrusted sites under Safari -> Settings -> Advanced.",
                            zh: "开启系统锁定模式（设置 -> 隐私与安全性 -> 锁定模式），或在「设置 -> Safari 浏览器 -> 高级」中对不可信站点限制 JavaScript 执行。"
                        ),
                        category: .systemSettings,
                        actionUrl: "App-Prefs:root=Privacy&path=LOCKDOWN_MODE",
                        relatedCVEs: ["CVE-2026-113897"]
                    ),
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Isolate Wallet & Untrusted Web Browsing",
                            zh: "隔离钱包操作与不可信网页浏览"
                        ),
                        instructions: WQLocale.pick(
                            en: "Avoid opening unverified DApp links or phishing URLs inside in-app WebViews alongside sensitive cryptocurrency wallets or signing sessions.",
                            zh: "避免在持有高价值加密钱包或登录会话的设备中使用 App 内置 WebView 打开不明 DApp 或可疑短链接。"
                        ),
                        category: .appHygiene,
                        relatedCVEs: ["CVE-2026-113897"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .accessorySetupBluetooth,
                name: WQLocale.pick(
                    en: "AccessorySetupKit Bluetooth Pairing & Privacy Bypass (CVE-2026-84493)",
                    zh: "AccessorySetupKit 蓝牙配对与隐私授权绕过 (CVE-2026-84493)"
                ),
                subsystem: "AccessorySetupKit / CoreBluetooth",
                cvssScore: 6.5,
                severity: .caution,
                affectedDescription: WQLocale.pick(
                    en: "iOS 18+ (< 27.2 and iOS 26 < 26.7.2)",
                    zh: "iOS 18+（< 27.2 且 iOS 26 < 26.7.2）"
                ),
                patchedVersionDescription: "iOS 27.2 / iOS 26.7.2",
                details: WQLocale.pick(
                    en: "Authorization validation bypass in AccessorySetupKit allows sideloaded apps lacking proper Bluetooth privacy usage declarations or AccessorySetupKitSupports entries to silently discover or interact with nearby Bluetooth accessories on iOS 18+. Patched in iOS 27.2 and 26.7.2.",
                    zh: "AccessorySetupKit 权限校验绕过缺陷允许缺少合规蓝牙隐私声明或 NSAccessorySetupKitSupports 配置的侧载应用，在 iOS 18+ 上静默发现或访问邻近蓝牙外设。已于 iOS 27.2 及 26.7.2 修复。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Restrict App Bluetooth & Accessory Permissions",
                            zh: "收紧应用蓝牙与外设访问权限"
                        ),
                        instructions: WQLocale.pick(
                            en: "Review Settings -> Privacy & Security -> Bluetooth and disable access for unknown or sideloaded apps that do not require hardware accessories.",
                            zh: "前往「设置 -> 隐私与安全性 -> 蓝牙」，关闭无需连接硬件外设的未知或侧载应用蓝牙权限。"
                        ),
                        category: .systemSettings,
                        actionUrl: "App-Prefs:root=Privacy&path=BT_PERIPHERAL",
                        relatedCVEs: ["CVE-2026-84493"]
                    ),
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Audit IPAs for AccessorySetupKit Info.plist Bypass",
                            zh: "排查 IPA 中的 AccessorySetupKit 声明绕过"
                        ),
                        instructions: WQLocale.pick(
                            en: "Scan sideloaded IPAs with WQGuard to flag apps linking \(IOCTokenArmor.tAccSetupFw) / \(IOCTokenArmor.tASAccSess) without required Info.plist privacy declarations.",
                            zh: "使用 WQGuard 扫描侧载 IPA，识别调用 \(IOCTokenArmor.tAccSetupFw) / \(IOCTokenArmor.tASAccSess) 却缺失合规 Info.plist 蓝牙声明的异常应用。"
                        ),
                        category: .wqguardScan,
                        relatedCVEs: ["CVE-2026-84493"]
                    )
                ]
            ),
            FirmwareVulnerability(
                cveId: .bookRestoreEscape,
                name: WQLocale.pick(
                    en: "BookRestore / bl_sbx Arbitrary System File Overwrite (PoC:BookRestore)",
                    zh: "BookRestore / bl_sbx 系统文件越权覆写逃逸 (PoC:BookRestore)"
                ),
                subsystem: "bookassetd / itunesstored / MobileGestalt",
                cvssScore: 7.8,
                severity: .highRisk,
                affectedDescription: WQLocale.pick(
                    en: "iOS 18+ (< 27.0 and iOS 26 < 26.2)",
                    zh: "iOS 18+（< 27.0 且 iOS 26 < 26.2）"
                ),
                patchedVersionDescription: "iOS 27.0 / iOS 26.2",
                details: WQLocale.pick(
                    en: "Path traversal and SQLite restoration abuse in bookassetd / itunesstored (\(IOCTokenArmor.tBookSQLite) / \(IOCTokenArmor.tDownloadsSQLite)), allowing unprivileged apps on iOS 18+ to overwrite protected system files such as MobileGestalt caches outside the app sandbox. Patched in iOS 27.0 and 26.2.",
                    zh: "bookassetd 与 itunesstored（\(IOCTokenArmor.tBookSQLite) / \(IOCTokenArmor.tDownloadsSQLite)）恢复流程存在路径穿越缺陷，可在 iOS 18+ 上越权覆写沙盒外的系统文件（如 MobileGestalt 缓存）。已于 iOS 27.0 及 26.2 修复。"
                ),
                mitigations: [
                    ActionableMitigation(
                        title: WQLocale.pick(
                            en: "Block BookRestore & MobileGestalt Tamper IPAs",
                            zh: "拦截 BookRestore 与 MobileGestalt 篡改应用"
                        ),
                        instructions: WQLocale.pick(
                            en: "Run WQGuard static IPA analysis before installing sideloaded packages to detect \(IOCTokenArmor.tBookPrivFw), bookassetd/itunesstored XPC targeting, \(IOCTokenArmor.tBookSQLite), or MobileGestalt cache strings.",
                            zh: "安装外部侧载包前通过 WQGuard 静态审查，拦截包含 \(IOCTokenArmor.tBookPrivFw)、bookassetd/itunesstored 交互、\(IOCTokenArmor.tBookSQLite) 或 MobileGestalt 缓存路径的越权包。"
                        ),
                        category: .wqguardScan,
                        relatedCVEs: ["PoC:BookRestore"]
                    )
                ]
            )
        ]
    }
}
