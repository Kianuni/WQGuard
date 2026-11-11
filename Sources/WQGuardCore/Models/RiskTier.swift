import Foundation

/// 4-tier security risk grading classification for applications and binaries.
public enum RiskTier: String, Codable, Sendable, Comparable, CaseIterable, CodingKeyRepresentable {
    /// High Risk (高危告警): Unknown apps matching containermanagerd sandbox token exploit signatures or anomalous escaping symlinks.
    case highRisk = "HIGH_RISK"
    /// Known Tool (已知工具提示): Apps matching a transparent, user-configurable whitelist of known open-source utilities.
    case knownTool = "KNOWN_TOOL"
    /// Caution (前置条件留意): Sideloaded/enterprise apps with App Groups and dynamic symbol resolution (dlopen/dlsym).
    case caution = "CAUTION"
    /// Safe (安全): Apps lacking App Group entitlement or clean across all scan layers.
    case safe = "SAFE"

    /// Numerical severity ranking (0 = safe, 10 = caution, 20 = knownTool, 30 = highRisk)
    public var severityRank: Int {
        switch self {
        case .safe: return 0
        case .caution: return 10
        case .knownTool: return 20
        case .highRisk: return 30
        }
    }

    /// Comparable implementation based on severity rank
    public static func < (lhs: RiskTier, rhs: RiskTier) -> Bool {
        return lhs.severityRank < rhs.severityRank
    }

    /// Localized display name in Simplified Chinese (zh-Hans)
    public var localizedNameZh: String {
        switch self {
        case .highRisk: return "高危告警"
        case .knownTool: return "已知工具提示"
        case .caution: return "前置条件留意"
        case .safe: return "安全"
        }
    }

    /// Localized display name in English (en)
    public var localizedNameEn: String {
        switch self {
        case .highRisk: return "High Risk"
        case .knownTool: return "Known Tool"
        case .caution: return "Caution"
        case .safe: return "Safe"
        }
    }

    /// Human-readable explanation in Simplified Chinese (zh-Hans)
    public var localizedDescriptionZh: String {
        switch self {
        case .highRisk:
            return "检测到越界沙盒访问特征或异常逃逸符号链接，存在越权风险。"
        case .knownTool:
            return "检测到已知越权测试工具（已授权白名单），符合已知特征。"
        case .caution:
            return "检测到 App Group 共享容器权限并伴随动态符号解析特征，建议留意。"
        case .safe:
            return "未发现可疑跨容器访问特征或无 App Group 权限，处于安全状态。"
        }
    }

    /// Human-readable explanation in English (en)
    public var localizedDescriptionEn: String {
        switch self {
        case .highRisk:
            return "Detected unauthorized sandbox escape signatures or escaping symlinks."
        case .knownTool:
            return "Matched known security utility in authorized whitelist."
        case .caution:
            return "Possesses App Group entitlements with dynamic symbol resolution (dlopen/dlsym)."
        case .safe:
            return "No suspicious cross-container access signatures or App Groups; safe."
        }
    }
}
