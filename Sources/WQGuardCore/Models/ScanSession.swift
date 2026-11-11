import Foundation

/// Encapsulates the overall state, posture, and findings of a complete security scan session.
public struct ScanSession: Identifiable, Codable, Sendable, Equatable {
    public let id: UUID
    public let sessionId: String
    public let timestamp: Date
    public let targetPath: String?
    public let totalApps: Int
    public let riskBreakdown: [RiskTier: Int]
    public let overallPosture: RiskTier
    public let findings: [ScanFinding]
    public let systemVersion: String?
    public let scanDuration: TimeInterval?
    public let engineVersion: String

    public var totalScanned: Int { totalApps }
    public var totalAppsScanned: Int { totalApps }

    public var highRiskFindings: [ScanFinding] {
        findings.filter { $0.riskTier == .highRisk }
    }

    public var knownToolFindings: [ScanFinding] {
        findings.filter { $0.riskTier == .knownTool }
    }

    public var cautionFindings: [ScanFinding] {
        findings.filter { $0.riskTier == .caution }
    }

    public var safeFindings: [ScanFinding] {
        findings.filter { $0.riskTier == .safe }
    }

    public init(
        id: UUID = UUID(),
        sessionId: String? = nil,
        timestamp: Date = Date(),
        targetPath: String? = nil,
        totalScanned: Int? = nil,
        findings: [ScanFinding],
        systemVersion: String? = nil,
        scanDuration: TimeInterval? = nil,
        engineVersion: String = "1.0.0"
    ) {
        let resolvedId = id
        self.id = resolvedId
        self.sessionId = sessionId ?? resolvedId.uuidString
        self.timestamp = timestamp
        self.targetPath = targetPath
        self.findings = findings
        self.totalApps = totalScanned ?? findings.count
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

        if breakdown[.highRisk, default: 0] > 0 {
            self.overallPosture = .highRisk
        } else if breakdown[.caution, default: 0] > 0 {
            self.overallPosture = .caution
        } else if breakdown[.knownTool, default: 0] > 0 {
            self.overallPosture = .knownTool
        } else {
            self.overallPosture = .safe
        }

        self.systemVersion = systemVersion
        self.scanDuration = scanDuration
        self.engineVersion = engineVersion
    }

    public init(
        id: UUID = UUID(),
        sessionId: String? = nil,
        timestamp: Date = Date(),
        targetPath: String? = nil,
        totalApps: Int? = nil,
        totalScanned: Int? = nil,
        riskBreakdown: [RiskTier: Int],
        overallPosture: RiskTier? = nil,
        findings: [ScanFinding],
        systemVersion: String? = nil,
        scanDuration: TimeInterval? = nil,
        engineVersion: String = "1.0.0"
    ) {
        let resolvedId = id
        self.id = resolvedId
        self.sessionId = sessionId ?? resolvedId.uuidString
        self.timestamp = timestamp
        self.targetPath = targetPath
        self.totalApps = totalApps ?? totalScanned ?? findings.count
        self.riskBreakdown = riskBreakdown

        if let overallPosture = overallPosture {
            self.overallPosture = overallPosture
        } else {
            if riskBreakdown[.highRisk, default: 0] > 0 {
                self.overallPosture = .highRisk
            } else if riskBreakdown[.caution, default: 0] > 0 {
                self.overallPosture = .caution
            } else if riskBreakdown[.knownTool, default: 0] > 0 {
                self.overallPosture = .knownTool
            } else {
                self.overallPosture = .safe
            }
        }

        self.findings = findings
        self.systemVersion = systemVersion
        self.scanDuration = scanDuration
        self.engineVersion = engineVersion
    }

    enum CodingKeys: String, CodingKey {
        case id
        case sessionId
        case timestamp
        case targetPath
        case totalApps
        case totalScanned
        case riskBreakdown
        case overallPosture
        case findings
        case systemVersion
        case scanDuration
        case engineVersion
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedId = try container.decodeIfPresent(UUID.self, forKey: .id)
        let decodedSessionId = try container.decodeIfPresent(String.self, forKey: .sessionId)
        let resolvedId = decodedId ?? (decodedSessionId.flatMap { UUID(uuidString: $0) }) ?? UUID()
        self.id = resolvedId
        self.sessionId = decodedSessionId ?? resolvedId.uuidString
        self.timestamp = try container.decode(Date.self, forKey: .timestamp)
        self.targetPath = try container.decodeIfPresent(String.self, forKey: .targetPath)
        let total = try container.decodeIfPresent(Int.self, forKey: .totalApps)
            ?? container.decodeIfPresent(Int.self, forKey: .totalScanned)
            ?? 0
        self.totalApps = total
        self.riskBreakdown = try container.decode([RiskTier: Int].self, forKey: .riskBreakdown)
        self.overallPosture = try container.decodeIfPresent(RiskTier.self, forKey: .overallPosture) ?? .safe
        self.findings = try container.decode([ScanFinding].self, forKey: .findings)
        self.systemVersion = try container.decodeIfPresent(String.self, forKey: .systemVersion)
        self.scanDuration = try container.decodeIfPresent(TimeInterval.self, forKey: .scanDuration)
        self.engineVersion = try container.decodeIfPresent(String.self, forKey: .engineVersion) ?? "1.0.0"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(sessionId, forKey: .sessionId)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encodeIfPresent(targetPath, forKey: .targetPath)
        try container.encode(totalApps, forKey: .totalApps)
        try container.encode(totalApps, forKey: .totalScanned)
        try container.encode(riskBreakdown, forKey: .riskBreakdown)
        try container.encode(overallPosture, forKey: .overallPosture)
        try container.encode(findings, forKey: .findings)
        try container.encodeIfPresent(systemVersion, forKey: .systemVersion)
        try container.encodeIfPresent(scanDuration, forKey: .scanDuration)
        try container.encode(engineVersion, forKey: .engineVersion)
    }
}
