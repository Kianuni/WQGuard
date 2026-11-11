import Foundation

/// Distribution and installation channel classification for iOS applications.
public enum InstallChannel: String, Codable, Sendable, CaseIterable, CodingKeyRepresentable {
    /// Developer / Personal Sideloaded (cryptid == 0 + embedded.mobileprovision)
    case developerSideloaded = "DEVELOPER_SIDELOADED"
    /// Enterprise In-House (cryptid == 0 + enterprise provisioning)
    case enterpriseInHouse = "ENTERPRISE_IN_HOUSE"
    /// TestFlight (cryptid == 1 + beta profile/receipt)
    case testFlight = "TESTFLIGHT"
    /// App Store (cryptid == 1)
    case appStore = "APP_STORE"

    /// Localized display name in Simplified Chinese (zh-Hans)
    public var localizedNameZh: String {
        switch self {
        case .developerSideloaded: return "个人/开发者侧载 (Developer Sideloaded)"
        case .enterpriseInHouse: return "企业内部签名 (Enterprise In-House)"
        case .testFlight: return "TestFlight 测试版 (TestFlight Beta)"
        case .appStore: return "App Store 官方发布 (App Store)"
        }
    }

    /// Localized display name in English (en)
    public var localizedNameEn: String {
        switch self {
        case .developerSideloaded: return "Developer / Sideloaded"
        case .enterpriseInHouse: return "Enterprise In-House"
        case .testFlight: return "TestFlight Beta"
        case .appStore: return "App Store"
        }
    }

    /// Indicates whether the app was sideloaded (developer or enterprise certificate)
    public var isSideloadedOrEnterprise: Bool {
        switch self {
        case .developerSideloaded, .enterpriseInHouse:
            return true
        case .testFlight, .appStore:
            return false
        }
    }

    /// Expected FairPlay cryptid value for this channel
    public var expectedCryptid: UInt32 {
        switch self {
        case .developerSideloaded, .enterpriseInHouse:
            return 0
        case .testFlight, .appStore:
            return 1
        }
    }
}
