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
