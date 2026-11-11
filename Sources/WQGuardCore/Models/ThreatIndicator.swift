import Foundation

/// An individual security finding or threat indicator flagged during analysis.
public struct ThreatIndicator: Identifiable, Codable, Sendable, Equatable, Hashable {
    public var id: String { "\(category):\(signature):\(location)" }
    public let signature: String
    public let description: String
    public let category: String
    public let location: String
    public let severity: RiskTier

    public init(
        signature: String,
        description: String,
        category: String,
        location: String,
        severity: RiskTier
    ) {
        self.signature = signature
        self.description = description
        self.category = category
        self.location = location
        self.severity = severity
    }
}

public extension ThreatIndicator {
    enum Category {
        public static let privateDylib = "private_dylib"
        public static let privateSymbol = "private_symbol"
        public static let pathEnumeration = "path_enumeration"
        public static let escapingSymlink = "escaping_symlink"
        public static let dynamicLoading = "dynamic_loading"
        public static let entitlementMismatch = "entitlement_mismatch"
    }
}
