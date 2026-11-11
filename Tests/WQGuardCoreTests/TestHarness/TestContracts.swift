import Foundation

#if !canImport(WQGuardCore)
// MARK: - Interface Contracts from PROJECT.md (Active only when WQGuardCore is not yet compiled)

public enum RiskTier: String, Codable, Sendable, Comparable, CaseIterable {
    case highRisk = "HIGH_RISK"        // 高危告警
    case knownTool = "KNOWN_TOOL"      // 已知工具提示
    case caution = "CAUTION"            // 前置条件留意
    case safe = "SAFE"                  // 安全

    public var severityRank: Int {
        switch self {
        case .safe: return 0
        case .caution: return 10
        case .knownTool: return 20
        case .highRisk: return 30
        }
    }

    public static func < (lhs: RiskTier, rhs: RiskTier) -> Bool {
        return lhs.severityRank < rhs.severityRank
    }
}

public enum InstallChannel: String, Codable, Sendable, CaseIterable {
    case developerSideloaded = "DEVELOPER_SIDELOADED"
    case enterpriseInHouse = "ENTERPRISE_IN_HOUSE"
    case testFlight = "TESTFLIGHT"
    case appStore = "APP_STORE"
}

public struct ThreatIndicator: Codable, Sendable, Equatable {
    public let signature: String
    public let description: String
    public let category: String
    public let location: String
    public let severity: RiskTier

    public init(signature: String, description: String, category: String, location: String, severity: RiskTier) {
        self.signature = signature
        self.description = description
        self.category = category
        self.location = location
        self.severity = severity
    }
}

public struct AuditEvidence: Codable, Sendable, Equatable {
    public let matchedSymbols: [String]
    public let linkedDylibs: [String]
    public let hasAppGroups: Bool
    public let appGroups: [String]
    public let installChannel: InstallChannel
    public let cryptid: UInt32
    public let isFairPlayEncrypted: Bool
    public let escapingSymlinks: [String]
    public let dynamicLoadingPresent: Bool
    public let pathEnumerationPresent: Bool
    public let remediationGuidance: String

    public init(
        matchedSymbols: [String] = [],
        linkedDylibs: [String] = [],
        hasAppGroups: Bool = false,
        appGroups: [String] = [],
        installChannel: InstallChannel = .developerSideloaded,
        cryptid: UInt32 = 0,
        isFairPlayEncrypted: Bool = false,
        escapingSymlinks: [String] = [],
        dynamicLoadingPresent: Bool = false,
        pathEnumerationPresent: Bool = false,
        remediationGuidance: String = ""
    ) {
        self.matchedSymbols = matchedSymbols
        self.linkedDylibs = linkedDylibs
        self.hasAppGroups = hasAppGroups
        self.appGroups = appGroups
        self.installChannel = installChannel
        self.cryptid = cryptid
        self.isFairPlayEncrypted = isFairPlayEncrypted
        self.escapingSymlinks = escapingSymlinks
        self.dynamicLoadingPresent = dynamicLoadingPresent
        self.pathEnumerationPresent = pathEnumerationPresent
        self.remediationGuidance = remediationGuidance
    }

    public static func empty(channel: InstallChannel = .developerSideloaded) -> AuditEvidence {
        return AuditEvidence(installChannel: channel)
    }
}

public struct ScanFinding: Identifiable, Codable, Sendable, Equatable {
    public var id: String { bundleId + ":" + (executablePath ?? "") }
    public let bundleId: String
    public let displayName: String
    public let version: String
    public let teamId: String?
    public let executablePath: String?
    public let bundlePath: String
    public let installChannel: InstallChannel
    public let riskTier: RiskTier
    public let isWhitelisted: Bool
    public let whitelistedToolName: String?
    public let indicators: [ThreatIndicator]
    public let evidence: AuditEvidence
    public let scanTimestamp: Date

    public init(
        bundleId: String,
        displayName: String,
        version: String,
        teamId: String?,
        executablePath: String?,
        bundlePath: String,
        installChannel: InstallChannel,
        riskTier: RiskTier,
        isWhitelisted: Bool,
        whitelistedToolName: String?,
        indicators: [ThreatIndicator],
        evidence: AuditEvidence,
        scanTimestamp: Date = Date()
    ) {
        self.bundleId = bundleId
        self.displayName = displayName
        self.version = version
        self.teamId = teamId
        self.executablePath = executablePath
        self.bundlePath = bundlePath
        self.installChannel = installChannel
        self.riskTier = riskTier
        self.isWhitelisted = isWhitelisted
        self.whitelistedToolName = whitelistedToolName
        self.indicators = indicators
        self.evidence = evidence
        self.scanTimestamp = scanTimestamp
    }
}

public struct ScanSession: Codable, Sendable, Equatable {
    public let sessionId: String
    public let timestamp: Date
    public let targetPath: String
    public let totalScanned: Int
    public let riskBreakdown: [RiskTier: Int]
    public let findings: [ScanFinding]

    public init(
        sessionId: String = UUID().uuidString,
        timestamp: Date = Date(),
        targetPath: String = "/",
        totalScanned: Int,
        riskBreakdown: [RiskTier: Int],
        findings: [ScanFinding]
    ) {
        self.sessionId = sessionId
        self.timestamp = timestamp
        self.targetPath = targetPath
        self.totalScanned = totalScanned
        self.riskBreakdown = riskBreakdown
        self.findings = findings
    }

    public init(findings: [ScanFinding], targetPath: String = "/") {
        self.sessionId = UUID().uuidString
        self.timestamp = Date()
        self.targetPath = targetPath
        self.totalScanned = findings.count
        self.findings = findings

        var breakdown: [RiskTier: Int] = [
            .highRisk: 0,
            .knownTool: 0,
            .caution: 0,
            .safe: 0
        ]
        for f in findings {
            breakdown[f.riskTier, default: 0] += 1
        }
        self.riskBreakdown = breakdown
    }
}

public struct WhitelistedTool: Sendable {
    public let name: String
    public let allowedBundleIds: Set<String>
    public let allowedAppGroups: Set<String>
    public let expectedSignatures: Set<String>
    public let description: String

    public init(
        name: String,
        allowedBundleIds: Set<String>,
        allowedAppGroups: Set<String>,
        expectedSignatures: Set<String>,
        description: String
    ) {
        self.name = name
        self.allowedBundleIds = allowedBundleIds
        self.allowedAppGroups = allowedAppGroups
        self.expectedSignatures = expectedSignatures
        self.description = description
    }
}

public final class WhitelistEngine: @unchecked Sendable {
    public static let shared = WhitelistEngine()
    private var customTools: [WhitelistedTool] = []
    private let lock = NSLock()

    public init() {}

    public func isWhitelisted(
        bundleId: String,
        appGroups: [String],
        matchedSignatures: [String]
    ) -> (isWhitelisted: Bool, toolName: String?) {
        lock.lock()
        defer { lock.unlock() }

        // Default known tools
        let known = [
            ("Erosion", "com.jbdotparty.Erosion", "group.com.jbdotparty.Erosion"),
            ("Erosion-CN", "com.jbdotparty.Erosion-CN", "group.com.jbdotparty.Erosion"),
            ("GestaltX", "com.antigravity.gestaltx", "group.com.antigravity.gestaltx"),
            ("WQFiles", "cz.kolbi.wqfiles", "group.cz.kolbi.wqfiles"),
            ("WQFiles-CN", "cz.kolbi.wqfiles-cn", "group.cz.kolbi.wqfiles"),
            ("WQGuard", "com.antigravity.wqguard", "group.com.antigravity.wqguard")
        ]

        for (name, bid, grp) in known {
            if bundleId.lowercased().hasPrefix(bid.lowercased()) || bundleId == bid {
                return (true, name)
            }
            if appGroups.contains(where: { $0.hasPrefix(grp) }) {
                return (true, name)
            }
        }

        for custom in customTools {
            if custom.allowedBundleIds.contains(bundleId) {
                return (true, custom.name)
            }
            if !custom.allowedAppGroups.isDisjoint(with: Set(appGroups)) {
                return (true, custom.name)
            }
        }

        return (false, nil)
    }

    public func registerCustomTool(_ tool: WhitelistedTool) {
        lock.lock()
        defer { lock.unlock() }
        customTools.append(tool)
    }

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        customTools.removeAll()
    }
}

public protocol SecurityScannerEngineProtocol: Sendable {
    func scanBinary(at url: URL) throws -> ScanFinding
    func scanBundle(at url: URL) throws -> ScanFinding
    func scanIPA(at url: URL) throws -> ScanFinding
    func scanInstalledApps() throws -> [ScanFinding]
    func scanSharedContainers() throws -> [ThreatIndicator]
}

public protocol ReportGeneratorProtocol: Sendable {
    func generateJSONReport(session: ScanSession) throws -> Data
    func generateMarkdownReport(session: ScanSession) -> String
    func generatePlainTextReport(session: ScanSession) -> String
}

#endif

// MARK: - Portable Sample IPA Path Resolver

public enum SamplePathResolver: Sendable {
    /// Resolves path to a sample IPA from environment variables or sibling workspace folders.
    public static func resolveIPA(
        envVar: String,
        siblingDir: String,
        candidates: [String] = []
    ) -> String? {
        // 1. Explicit environment variable override
        if let envPath = ProcessInfo.processInfo.environment[envVar],
           FileManager.default.fileExists(atPath: envPath) {
            return envPath
        }

        // 2. Generic samples directory
        if let samplesDir = ProcessInfo.processInfo.environment["WQ_TEST_SAMPLES_DIR"] {
            for c in candidates {
                let p = URL(fileURLWithPath: samplesDir).appendingPathComponent(c).path
                if FileManager.default.fileExists(atPath: p) { return p }
            }
        }

        // 3. Portable sibling workspace directory relative to repo root
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // TestHarness
            .deletingLastPathComponent() // WQGuardCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // WQGuard repo root
        let siblingPath = repoRoot.deletingLastPathComponent().appendingPathComponent(siblingDir)

        for c in candidates {
            let p = siblingPath.appendingPathComponent(c).path
            if FileManager.default.fileExists(atPath: p) { return p }
        }

        // 4. Wildcard .ipa detection in sibling directory
        if let files = try? FileManager.default.contentsOfDirectory(atPath: siblingPath.path) {
            if let ipa = files.first(where: { $0.hasSuffix(".ipa") }) {
                return siblingPath.appendingPathComponent(ipa).path
            }
        }

        return nil
    }

    /// Resolves WQFiles sample IPA path
    public static func wqfilesIPA() -> String? {
        resolveIPA(
            envVar: "WQFILES_IPA_PATH",
            siblingDir: "WQFiles-CN",
            candidates: ["WQFiles.ipa"]
        )
    }

    /// Resolves Erosion sample IPA path
    public static func erosionIPA() -> String? {
        resolveIPA(
            envVar: "EROSION_IPA_PATH",
            siblingDir: "Erosion-CN",
            candidates: [
                "Erosion_v0.8.5_zh-Hans.ipa",
                "Erosion_v0.8.4_zh-Hans.ipa",
                "Erosion_v0.8.1_zh-Hans.ipa",
                "Erosion.ipa"
            ]
        )
    }
}
