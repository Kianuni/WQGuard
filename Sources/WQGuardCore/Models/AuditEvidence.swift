import Foundation

/// Comprehensive audit evidence gathered across all scan layers for an analyzed binary or package.
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
    public let auditDepth: AuditDepth
    public let signerIdentity: String?

    enum CodingKeys: String, CodingKey {
        case matchedSymbols
        case linkedDylibs
        case hasAppGroups
        case appGroups
        case installChannel
        case cryptid
        case isFairPlayEncrypted
        case escapingSymlinks
        case dynamicLoadingPresent
        case pathEnumerationPresent
        case remediationGuidance
        case auditDepth
        case signerIdentity
    }

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
        remediationGuidance: String = "",
        auditDepth: AuditDepth = .fullBinaryAndRegistry,
        signerIdentity: String? = nil
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
        self.auditDepth = auditDepth
        self.signerIdentity = signerIdentity
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.matchedSymbols = try container.decode([String].self, forKey: .matchedSymbols)
        self.linkedDylibs = try container.decode([String].self, forKey: .linkedDylibs)
        self.hasAppGroups = try container.decode(Bool.self, forKey: .hasAppGroups)
        self.appGroups = try container.decode([String].self, forKey: .appGroups)
        self.installChannel = try container.decode(InstallChannel.self, forKey: .installChannel)
        self.cryptid = try container.decode(UInt32.self, forKey: .cryptid)
        self.isFairPlayEncrypted = try container.decode(Bool.self, forKey: .isFairPlayEncrypted)
        self.escapingSymlinks = try container.decode([String].self, forKey: .escapingSymlinks)
        self.dynamicLoadingPresent = try container.decode(Bool.self, forKey: .dynamicLoadingPresent)
        self.pathEnumerationPresent = try container.decode(Bool.self, forKey: .pathEnumerationPresent)
        self.remediationGuidance = try container.decode(String.self, forKey: .remediationGuidance)
        self.auditDepth = try container.decodeIfPresent(AuditDepth.self, forKey: .auditDepth) ?? .fullBinaryAndRegistry
        self.signerIdentity = try container.decodeIfPresent(String.self, forKey: .signerIdentity)
    }

    /// Generates an empty baseline evidence structure
    public static func empty(channel: InstallChannel = .appStore) -> AuditEvidence {
        return AuditEvidence(
            matchedSymbols: [],
            linkedDylibs: [],
            hasAppGroups: false,
            appGroups: [],
            installChannel: channel,
            cryptid: channel.expectedCryptid,
            isFairPlayEncrypted: channel.expectedCryptid != 0,
            escapingSymlinks: [],
            dynamicLoadingPresent: false,
            pathEnumerationPresent: false,
            remediationGuidance: "未发现威胁，保持系统更新。"
        )
    }
}
