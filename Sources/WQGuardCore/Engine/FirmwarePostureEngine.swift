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
public struct SystemOSVersion: Codable, Sendable, Equatable, Hashable, Comparable {
    public let major: Int
    public let minor: Int
    public let patch: Int
    public let build: String?
    public let rawString: String?

    public init(major: Int, minor: Int, patch: Int = 0, build: String? = nil, rawString: String? = nil) {
        self.major = major
        self.minor = minor
        self.patch = patch
        self.build = build
        self.rawString = rawString
    }

    public init(operatingSystemVersion: OperatingSystemVersion, build: String? = nil) {
        self.major = operatingSystemVersion.majorVersion
        self.minor = operatingSystemVersion.minorVersion
        self.patch = operatingSystemVersion.patchVersion
        self.build = build
        self.rawString = "\(operatingSystemVersion.majorVersion).\(operatingSystemVersion.minorVersion).\(operatingSystemVersion.patchVersion)"
    }

    /// Parses version strings such as "26.2", "iOS 27.1", "26.7.2 (24B123)", "27.2.1-beta1"
    public init?(string: String) {
        let pattern = #"(\d+)\.(\d+)(?:\.(\d+))?(?:[^\w]*\(([\w]+)\))?"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: string, range: NSRange(string.startIndex..., in: string)) else {
            return nil
        }

        func extract(group: Int) -> String? {
            guard group < match.numberOfRanges, let r = Range(match.range(at: group), in: string) else { return nil }
            return String(string[r])
        }

        guard let majorStr = extract(group: 1), let major = Int(majorStr),
              let minorStr = extract(group: 2), let minor = Int(minorStr) else {
            return nil
        }

        let patch = extract(group: 3).flatMap { Int($0) } ?? 0
        let build = extract(group: 4)

        self.major = major
        self.minor = minor
        self.patch = patch
        self.build = build
        self.rawString = string
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
        if let raw = rawString, !raw.isEmpty { return raw }
        var base = "\(major).\(minor).\(patch)"
        if let b = build { base += " (\(b))" }
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
        switch cve {
        case .worseQuery0day:
            // Unpatched 0day: affects all iOS 26.x and 27.x versions currently known (26.0 - 27.2.1+)
            return version.major >= 26

        case .photosBypass:
            // CVE-2026-112676: Affects iOS < 27.2 and iOS 26 < 26.7.2
            if version.major == 26 {
                return version < SystemOSVersion(major: 26, minor: 7, patch: 2)
            } else if version.major == 27 {
                return version < SystemOSVersion(major: 27, minor: 2, patch: 0)
            } else {
                return version.major < 26
            }

        case .brotliOOB:
            // CVE-2026-111497 (HTTP2Shell): Affects iOS < 27.2.1 and iOS 26 < 26.7.3
            if version.major == 26 {
                return version < SystemOSVersion(major: 26, minor: 7, patch: 3)
            } else if version.major == 27 {
                return version < SystemOSVersion(major: 27, minor: 2, patch: 1)
            } else {
                return version.major < 26
            }

        case .coreGraphicsPDF:
            // CVE-2026-112611: Affects iOS < 27.2 and iOS 26 < 26.7.2
            if version.major == 26 {
                return version < SystemOSVersion(major: 26, minor: 7, patch: 2)
            } else if version.major == 27 {
                return version < SystemOSVersion(major: 27, minor: 2, patch: 0)
            } else {
                return version.major < 26
            }

        case .coreGraphics2D:
            // CVE-2026-86950: Affects iOS < 27.0
            return version.major < 27

        case .appIntentsBypass:
            // CVE-2026-113963: Affects iOS < 27.2.1 and iOS 26 < 26.7.3
            if version.major == 26 {
                return version < SystemOSVersion(major: 26, minor: 7, patch: 3)
            } else if version.major == 27 {
                return version < SystemOSVersion(major: 27, minor: 2, patch: 1)
            } else {
                return version.major < 26
            }

        case .imessageGroup:
            // CVE-2026-113960 & CVE-2026-113961: Affects iOS < 27.2.1 and iOS 26 < 26.7.3
            if version.major == 26 {
                return version < SystemOSVersion(major: 26, minor: 7, patch: 3)
            } else if version.major == 27 {
                return version < SystemOSVersion(major: 27, minor: 2, patch: 1)
            } else {
                return version.major < 26
            }

        case .bluetoothAirPlay:
            // CVE-2026-113964-70: Affects iOS < 27.2.1 and iOS 26 < 26.7.3
            if version.major == 26 {
                return version < SystemOSVersion(major: 26, minor: 7, patch: 3)
            } else if version.major == 27 {
                return version < SystemOSVersion(major: 27, minor: 2, patch: 1)
            } else {
                return version.major < 26
            }
        }
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
    public static let allVulnerabilities: [FirmwareVulnerability] = [
        FirmwareVulnerability(
            cveId: .worseQuery0day,
            name: "containermanagerd 跨沙盒令牌签发逃逸 (worse_query / bad_query)",
            subsystem: "Darwin Sandbox / containermanagerd",
            cvssScore: 8.8,
            severity: .highRisk,
            affectedDescription: "iOS 26.0 – 27.2.1+ (未修复 0day)",
            patchedVersionDescription: "暂无官方补丁 (未修复 0day)",
            details: "利用 containermanagerd 在处理 class=7 (App Group) part=3 (Library/Caches) 查询时，缺少路径前缀隔离校验的 Confused Deputy 漏洞，结合 escaping symlink 诱导内核签发任意 App 容器的沙盒扩展令牌。",
            mitigations: [
                ActionableMitigation(
                    title: "侧载应用安装前强制审计",
                    instructions: "在启动任何外部侧载或企业证书签名的 IPA 之前，使用 WQGuard 运行静态与沙盒分析，拦截声明 App Group 并包含 containermanagerd IPC/逃逸特征的应用。",
                    category: .wqguardScan,
                    relatedCVEs: ["0day:worse_query"]
                )
            ]
        ),
        FirmwareVulnerability(
            cveId: .photosBypass,
            name: "Apple Photos 私有相册隐私提示与权限绕过 (CVE-2026-112676)",
            subsystem: "Photos / TCC Privacy",
            cvssScore: 7.5,
            severity: .highRisk,
            affectedDescription: "iOS < 27.2 且 iOS 26 < 26.7.2",
            patchedVersionDescription: "iOS 27.2 / iOS 26.7.2",
            details: "恶意本地应用可调用私有框架 PhotoLibraryServices 或利用私有 Entitlement 绕过 iOS TCC 相册访问授权提示，在后台静默读取用户相册与截图。",
            mitigations: [
                ActionableMitigation(
                    title: "相册敏感凭证清退",
                    instructions: "切勿在系统相册中保存加密货币助记词/私钥截图或敏感身份证件；及时将机密照片移至硬件加密金库。",
                    category: .appHygiene,
                    relatedCVEs: ["CVE-2026-112676"]
                ),
                ActionableMitigation(
                    title: "开启相册私有调用扫描",
                    instructions: "使用 WQGuard 扫描本地 IPA，排查非法引用 PhotoLibraryServices / PLPhotoLibrary 的可疑软件包。",
                    category: .wqguardScan,
                    relatedCVEs: ["CVE-2026-112676"]
                )
            ]
        ),
        FirmwareVulnerability(
            cveId: .brotliOOB,
            name: "Brotli 解码器堆越界写入 / 远程代码执行 (HTTP2Shell, CVE-2026-111497)",
            subsystem: "libbrotli / WebKit / CFNetwork",
            cvssScore: 9.2,
            severity: .highRisk,
            affectedDescription: "iOS < 27.2.1 且 iOS 26 < 26.7.3",
            patchedVersionDescription: "iOS 27.2.1 / iOS 26.7.3",
            details: "libbrotli 解码器中存在堆缓冲区越界写入缺陷。恶意服务端通过 HTTP/2 下发精心构造的 Content-Encoding: br 压缩流，可诱发 CFNetwork / WebKit 进程内存破坏与任意代码执行。",
            mitigations: [
                ActionableMitigation(
                    title: "启用 Surge Brotli 降级护盾",
                    instructions: "在 Surge 中安装 WQGuard · 防 Brotli 溢出降级护盾模块，强制将 HTTP 请求头 Accept-Encoding 降级为 'gzip, deflate'，阻断网络传输层下发的恶意 Brotli 数据流。",
                    category: .networkProxy,
                    actionUrl: "surge:///install-module",
                    relatedCVEs: ["CVE-2026-111497"]
                ),
                ActionableMitigation(
                    title: "开启 Safari 锁定模式 (Lockdown Mode)",
                    instructions: "对于访问不可信外部链接，在'设置 -> 隐私与安全性 -> 锁定模式'中针对特定网页启用严格防护。",
                    category: .systemSettings,
                    actionUrl: "App-Prefs:root=Privacy&path=LOCKDOWN_MODE",
                    relatedCVEs: ["CVE-2026-111497"]
                )
            ]
        ),
        FirmwareVulnerability(
            cveId: .coreGraphicsPDF,
            name: "CoreGraphics 恶意 PDF 字体与图像渲染越界写入 (CVE-2026-112611)",
            subsystem: "CoreGraphics / PDFKit",
            cvssScore: 8.8,
            severity: .highRisk,
            affectedDescription: "iOS < 27.2 且 iOS 26 < 26.7.2",
            patchedVersionDescription: "iOS 27.2 / iOS 26.7.2",
            details: "CoreGraphics 解析特定格式嵌入式字体与色彩空间时发生堆溢出，可能被攻击者通过恶意 PDF 文件实施零点击或单点击攻击。",
            mitigations: [
                ActionableMitigation(
                    title: "关闭即时通讯软件自动下载",
                    instructions: "在 Telegram（设置 -> 数据与存储）和微信（设置 -> 通用 -> 照片、视频、文件和通话）中关闭'自动下载媒体与文件'。",
                    category: .appHygiene,
                    relatedCVEs: ["CVE-2026-112611"]
                ),
                ActionableMitigation(
                    title: "避免本地快速预览未知 PDF",
                    instructions: "切勿在系统 QuickLook、Safari 或未隔离的本地阅读器中直接预览来源不明的 PDF 文件。",
                    category: .appHygiene,
                    relatedCVEs: ["CVE-2026-112611"]
                )
            ]
        ),
        FirmwareVulnerability(
            cveId: .coreGraphics2D,
            name: "CoreGraphics 2D 图形引擎内存破坏 0day (CVE-2026-86950)",
            subsystem: "CoreGraphics / Quartz2D",
            cvssScore: 8.6,
            severity: .highRisk,
            affectedDescription: "iOS < 27.0",
            patchedVersionDescription: "iOS 27.0",
            details: "iOS 26.x 图像子系统解析特定 ICC Profile 时存在无界内存复制缺陷，在未升级至 iOS 27 时极易被图元触发崩溃或利用。",
            mitigations: [
                ActionableMitigation(
                    title: "禁用通讯软件图像自动渲染",
                    instructions: "禁用即时通讯软件中的图片自动渲染与预加载功能，防止后台静默渲染恶意图像元数据。",
                    category: .appHygiene,
                    relatedCVEs: ["CVE-2026-86950"]
                )
            ]
        ),
        FirmwareVulnerability(
            cveId: .appIntentsBypass,
            name: "App Intents 与快捷指令提权授权绕过 (CVE-2026-113963)",
            subsystem: "AppIntents / Shortcuts",
            cvssScore: 7.8,
            severity: .caution,
            affectedDescription: "iOS < 27.2.1 且 iOS 26 < 26.7.3",
            patchedVersionDescription: "iOS 27.2.1 / iOS 26.7.3",
            details: "恶意应用可通过构造特定 AppIntent 元数据绕过系统权限确认对话框，自动触发具备高权限的系统服务与剪贴板访问。",
            mitigations: [
                ActionableMitigation(
                    title: "定期审计快捷指令自动化",
                    instructions: "进入系统'快捷指令'应用，清理未经审核的第三方共享脚本与自动化流程。",
                    category: .appHygiene,
                    actionUrl: "shortcuts://",
                    relatedCVEs: ["CVE-2026-113963"]
                )
            ]
        ),
        FirmwareVulnerability(
            cveId: .imessageGroup,
            name: "iMessage Blastdoor 群聊未授权加入与历史泄露 (CVE-2026-113960/1)",
            subsystem: "Messages / Blastdoor",
            cvssScore: 8.1,
            severity: .highRisk,
            affectedDescription: "iOS < 27.2.1 且 iOS 26 < 26.7.3",
            patchedVersionDescription: "iOS 27.2.1 / iOS 26.7.3",
            details: "iMessage 协议层在解析畸形 Group Action 消息时存在逻辑漏洞，攻击者可诱导客户端泄露群聊参与者列表及部分未解密历史摘要。",
            mitigations: [
                ActionableMitigation(
                    title: "开启未知发件人信息过滤",
                    instructions: "进入'设置 -> 信息'，启用'过滤未知发件人'；不要在多人群聊中传递钱包助记词或账户敏感凭据。",
                    category: .systemSettings,
                    actionUrl: "App-Prefs:root=MESSAGES",
                    relatedCVEs: ["CVE-2026-113960"]
                )
            ]
        ),
        FirmwareVulnerability(
            cveId: .bluetoothAirPlay,
            name: "Bluetooth CoreUtils 零点击配对与 AirPlay 释放后使用 (CVE-2026-113964–70)",
            subsystem: "Bluetooth / AirPlay / rapportd",
            cvssScore: 8.8,
            severity: .highRisk,
            affectedDescription: "iOS < 27.2.1 且 iOS 26 < 26.7.3",
            patchedVersionDescription: "iOS 27.2.1 / iOS 26.7.3",
            details: "CoreUtils 蓝牙邻近配对状态机及 AirPlay rapportd 守护进程中存在速率限制绕过与 UAF 内存破坏漏洞，附近恶意发射源可发起未授权配对嗅探。",
            mitigations: [
                ActionableMitigation(
                    title: "将自动隔空播放设为从不",
                    instructions: "进入'设置 -> 通用 -> 隔空播放与接力'，将'自动隔空播放到电视'调整为'从不'。",
                    category: .systemSettings,
                    actionUrl: "App-Prefs:root=General&path=AIRPLAY",
                    relatedCVEs: ["CVE-2026-113964-70"]
                ),
                ActionableMitigation(
                    title: "公共场所彻底关闭蓝牙",
                    instructions: "在机场、高铁站等不可信人员密集场所，前往'设置 -> 蓝牙'彻底关闭蓝牙开关（而非仅在控制中心临时断开）。",
                    category: .systemSettings,
                    actionUrl: "App-Prefs:root=Bluetooth",
                    relatedCVEs: ["CVE-2026-113964-70"]
                )
            ]
        )
    ]
}
