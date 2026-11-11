import Foundation

/// Represents the final evaluation and audit findings for a single scanned application or binary.
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
        teamId: String? = nil,
        executablePath: String? = nil,
        bundlePath: String,
        installChannel: InstallChannel,
        riskTier: RiskTier,
        isWhitelisted: Bool = false,
        whitelistedToolName: String? = nil,
        indicators: [ThreatIndicator] = [],
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
