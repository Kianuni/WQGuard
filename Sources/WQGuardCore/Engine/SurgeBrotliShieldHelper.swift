//
//  SurgeBrotliShieldHelper.swift
//  WQGuardCore
//
//  Multi-client Brotli Downgrade Shield generator, validator, and exporter supporting
//  Surge (.sgmodule), Shadowrocket (.module), Quantumult X (.conf), Loon (.plugin),
//  and Stash (.stoverride) to mitigate CVE-2026-111497 (HTTP2Shell).
//

import Foundation

public enum ProxyShieldPlatform: String, CaseIterable, Identifiable, Codable, Sendable {
    case surge = "surge"
    case shadowrocket = "shadowrocket"
    case quantumultX = "quantumultx"
    case loon = "loon"
    case stash = "stash"

    public var id: String { rawValue }

    public var shortTitleZh: String {
        switch self {
        case .surge: return "Surge"
        case .shadowrocket: return "小火箭"
        case .quantumultX: return "圈 X"
        case .loon: return "Loon"
        case .stash: return "Stash"
        }
    }

    public var shortTitleEn: String {
        switch self {
        case .surge: return "Surge"
        case .shadowrocket: return "Shadowrocket"
        case .quantumultX: return "Quantumult X"
        case .loon: return "Loon"
        case .stash: return "Stash"
        }
    }

    public var fileExtension: String {
        switch self {
        case .surge: return "sgmodule"
        case .shadowrocket: return "module"
        case .quantumultX: return "conf"
        case .loon: return "plugin"
        case .stash: return "stoverride"
        }
    }

    public var defaultFilename: String {
        "WQGuard-Brotli-Shield.\(fileExtension)"
    }

    public var remoteRawURLString: String {
        let base = "https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields"
        switch self {
        case .surge: return "\(base)/Surge/WQGuard-Brotli-Shield.sgmodule"
        case .shadowrocket: return "\(base)/Shadowrocket/WQGuard-Brotli-Shield.module"
        case .quantumultX: return "\(base)/QuantumultX/WQGuard-Brotli-Shield.conf"
        case .loon: return "\(base)/Loon/WQGuard-Brotli-Shield.plugin"
        case .stash: return "\(base)/Stash/WQGuard-Brotli-Shield.stoverride"
        }
    }

    public var oneTapInstallURL: URL? {
        guard let encoded = remoteRawURLString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)?
            .replacingOccurrences(of: "&", with: "%26")
            .replacingOccurrences(of: "=", with: "%3D") else {
            return nil
        }
        switch self {
        case .surge:
            return URL(string: "surge:///install-module?url=\(encoded)")
        case .shadowrocket:
            return URL(string: "shadowrocket://install?module=\(encoded)")
        case .loon:
            return URL(string: "loon://import?plugin=\(encoded)")
        case .stash:
            return URL(string: "stash://install-override?url=\(encoded)")
        case .quantumultX:
            let jsonParam = "{\"rewrite_remote\":[\"\(remoteRawURLString), tag=WQGuard Brotli 护盾, update-interval=86400, opt-parser=false, enabled=true\"]}"
            if let qxEncoded = jsonParam.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) {
                return URL(string: "quantumult-x:///add-resource?remote-resource=\(qxEncoded)")
            }
            return nil
        }
    }

    public var usageHintZh: String {
        switch self {
        case .surge:
            return "导入 Surge「模块」并开启 MitM 总开关与 CA 证书信任（日常保持默认高危后缀即可，零额外耗电）。"
        case .shadowrocket:
            return "导入小火箭「配置 → 模块」，并在「设置 → HTTPS 解密」中开启解密与证书信任。"
        case .quantumultX:
            return "在圈 X「重写 → 资源引用」中添加，并确保底部开启「重写」与「MitM」开关及证书信任。"
        case .loon:
            return "导入 Loon「配置 → 插件」，并开启「MITM」开关与系统 CA 根证书完全信任。"
        case .stash:
            return "导入 Stash「覆写 (Overrides)」启用，并在「MITM」中安装信任根证书。"
        }
    }

    public init?(identifierOrPath raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch trimmed {
        case "surge", "sgmodule":
            self = .surge
        case "shadowrocket", "sr", "module":
            self = .shadowrocket
        case "quantumultx", "quantumult-x", "qx", "conf":
            self = .quantumultX
        case "loon", "plugin", "lpx":
            self = .loon
        case "stash", "stoverride":
            self = .stash
        default:
            let ext = URL(fileURLWithPath: raw).pathExtension.lowercased()
            switch ext {
            case "sgmodule": self = .surge
            case "module": self = .shadowrocket
            case "conf": self = .quantumultX
            case "plugin", "lpx": self = .loon
            case "stoverride", "yaml", "yml": self = .stash
            default: return nil
            }
        }
    }
}

public final class SurgeBrotliShieldHelper: Sendable {
    public static let shared = SurgeBrotliShieldHelper()

    /// 16 mandatory negative exclusion patterns ensuring Apple Intelligence, Siri, and banking are never broken.
    public static let mandatoryNegativeExclusions: [String] = [
        "-*.apple.com",
        "-*.icloud.com",
        "-*.icloud-content.com",
        "-*.mzstatic.com",
        "-*.cdn-apple.com",
        "-guzzoni.apple.com",
        "-*.siri.apple.com",
        "-gspe1-ssl.ls.apple.com",
        "-apple-relay.*",
        "-cp4.cloudflare.com",
        "-*.openai.com",
        "-*.chatgpt.com",
        "-*.binance.com",
        "-*.okx.com",
        "-*.tenpay.com",
        "-*.alipay.com"
    ]

    /// Default 21 high-risk phishing / abuse TLDs targeted for MITM inspection without impacting mainstream apps.
    public static let defaultHighRiskTLDs: [String] = [
        "*.xyz", "*.top", "*.icu", "*.cyou", "*.sbs", "*.cfd", "*.buzz", "*.fun",
        "*.click", "*.link", "*.site", "*.online", "*.shop", "*.vip", "*.pw",
        "*.work", "*.rest", "*.monster", "*.quest", "*.zip", "*.mov"
    ]

    public static let remoteGuardScriptURL = "https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/scripts/brotli-guard.js"

    /// Raw verbatim template of the production Surge Brotli Shield module.
    public static let rawModuleTemplate: String = """
    #!name=WQGuard · 防 Brotli 溢出降级护盾 (CVE-2026-111497)
    #!desc=针对 iOS 26.x 与 iOS 27.0–27.2.0 系统未修复之 libbrotli 堆越界写高危漏洞 (CVE-2026-111497 / HTTP2Shell, CVSS 9.2)，在网络传输层剥离 Accept-Encoding 中的 br 算法强制降级为 gzip/deflate。内置 16 项严苛负向排除规则，确保 Apple Intelligence、Siri、iCloud 与网银支付绝对不被拦截。
    #!version=1.2.1
    #!category=安全防护
    #!arguments=EXTRA_MITM_HOSTS:*.example.invalid
    #!arguments-desc=可追加需要强制 Brotli 降级保护的高风险自定义域名（支持通配符如 *.example.com；如需保护全部 Safari/WebView 流量可填入 *，内置排除列表已保护 Apple 核心服务与金融应用）。

    [Header Rewrite]
    # 强制剥离客户端请求中的 br 压缩声明，降级至安全的 gzip 与 deflate 编码
    ^https?:// header-replace Accept-Encoding "gzip, deflate"

    [Script]
    # 零解压（requires-body=false）拦截不遵从客户端协商、强行回传 Content-Encoding: br 的恶意服务端响应
    brotli-response-guard = type=http-response,pattern=^https?://.+,requires-body=false,max-size=0,script-path=https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/scripts/brotli-guard.js

    [MITM]
    # 严苛负向排除规则保障：Apple Intelligence、普通话 Siri、PCC 中继、OpenAI 及银行绝对不走 MITM！
    hostname = %APPEND% -*.apple.com, -*.icloud.com, -*.icloud-content.com, -*.mzstatic.com, -*.cdn-apple.com, -guzzoni.apple.com, -*.siri.apple.com, -gspe1-ssl.ls.apple.com, -apple-relay.*, -cp4.cloudflare.com, -*.openai.com, -*.chatgpt.com, -*.binance.com, -*.okx.com, -*.tenpay.com, -*.alipay.com, *.xyz, *.top, *.icu, *.cyou, *.sbs, *.cfd, *.buzz, *.fun, *.click, *.link, *.site, *.online, *.shop, *.vip, *.pw, *.work, *.rest, *.monster, *.quest, *.zip, *.mov, {{{EXTRA_MITM_HOSTS}}}
    """

    public init() {}

    /// Generates the Surge module content (backward-compatible API).
    public func generateModuleContent(extraHosts: [String] = []) -> String {
        generateShieldContent(for: .surge, extraHosts: extraHosts)
    }

    /// Generates ready-to-import shield configuration for any of the 5 supported iOS proxy clients.
    public func generateShieldContent(for platform: ProxyShieldPlatform, extraHosts: [String] = []) -> String {
        let cleanExtra = extraHosts.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        let exclusionsCSV = Self.mandatoryNegativeExclusions.joined(separator: ", ")
        let tldsCSV = Self.defaultHighRiskTLDs.joined(separator: ", ")
        let appendedCSV = cleanExtra.isEmpty ? "" : ", \(cleanExtra.joined(separator: ", "))"

        switch platform {
        case .surge:
            if cleanExtra.isEmpty {
                return Self.rawModuleTemplate
            }
            let replacement = cleanExtra.joined(separator: ", ")
            return Self.rawModuleTemplate.replacingOccurrences(of: "{{{EXTRA_MITM_HOSTS}}}", with: replacement)

        case .shadowrocket:
            return """
            #!name=WQGuard · 防 Brotli 溢出降级护盾 (CVE-2026-111497)
            #!desc=针对 iOS 26.x 与 iOS 27.0–27.2.0 未修复之 libbrotli 堆越界写漏洞 (CVE-2026-111497 / HTTP2Shell)，剥离请求头 br 编码并阻断恶意强推响应。内置 16 项负向排除，不破坏 Apple Intelligence、Siri 与移动支付。
            #!category=安全防护

            [Header Rewrite]
            # 强制将请求头 Accept-Encoding 降级为安全的 gzip,deflate（无空格防解析歧义）
            ^https?://.+ header-replace Accept-Encoding gzip,deflate

            [Script]
            # 零解压（requires-body=0）拦截强行返回 Content-Encoding: br 的恶意响应
            brotli-response-guard = type=http-response,pattern=^https?://.+,script-path=\(Self.remoteGuardScriptURL),requires-body=0,max-size=0

            [MITM]
            hostname = %APPEND% \(exclusionsCSV), \(tldsCSV)\(appendedCSV)
            """

        case .quantumultX:
            return """
            ; WQGuard · 防 Brotli 溢出降级护盾 (CVE-2026-111497 / HTTP2Shell) — Quantumult X 重写资源
            ; 针对 iOS 26.x 与 iOS 27.0–27.2.0 未修复之 libbrotli 堆越界写漏洞，剥离请求头 br 编码并拦截强推的恶意响应。
            ; 使用方式：在 Quantumult X「重写 -> 资源引用」中添加本文件链接或本地导入，并确保开启 MitM 与证书信任。

            [rewrite_local]
            ; 1. 将客户端请求头中的 Accept-Encoding 强制降级为安全的 gzip, deflate
            ^https?://.+ url request-header (\\r\\n[Aa][Cc][Cc][Ee][Pp][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]:)[^\\r\\n]+(\\r\\n) request-header $1 gzip, deflate$2
            ; 2. 仅检查响应头（不解压响应体），阻断服务端强行返回的 Content-Encoding: br 数据流
            ^https?://.+ url script-response-header \(Self.remoteGuardScriptURL)

            [mitm]
            hostname = \(exclusionsCSV), \(tldsCSV)\(appendedCSV)
            """

        case .loon:
            let defaultArg = cleanExtra.isEmpty ? "*.example.invalid" : cleanExtra.joined(separator: ", ")
            return """
            #!name = WQGuard · 防 Brotli 溢出降级护盾 (CVE-2026-111497)
            #!desc = 针对 iOS 26.x 与 iOS 27.0–27.2.0 未修复之 libbrotli 堆越界写高危漏洞 (CVE-2026-111497 / HTTP2Shell)，强制降级 Accept-Encoding 为 gzip,deflate 并阻断恶意强推的 br 响应。内置 16 项负向排除，保障 Apple Intelligence、Siri 与支付正常使用。
            #!openUrl = https://github.com/Kianuni/WQGuard
            #!author = WQGuard Contributors
            #!tag = 安全防护
            #!system = iOS

            [Argument]
            EXTRA_MITM_HOSTS = input, "\(defaultArg)", tag = 附加防护域名, desc = 可选补充需要开启 Brotli 降级保护的自定义域名后缀（如 *.cc, *.me）

            [Rewrite]
            ^https?://.+ header-replace Accept-Encoding gzip,deflate

            [Script]
            http-response ^https?://.+ script-path=\(Self.remoteGuardScriptURL),requires-body=false,timeout=5,tag=WQGuard-Brotli-Guard

            [Mitm]
            hostname = \(exclusionsCSV), \(tldsCSV), {EXTRA_MITM_HOSTS}
            """

        case .stash:
            let allHosts = Self.mandatoryNegativeExclusions + Self.defaultHighRiskTLDs + cleanExtra
            let yamlMitmLines = allHosts.map { "    - \"\($0)\"" }.joined(separator: "\n")
            return """
            name: "WQGuard · 防 Brotli 溢出降级护盾 (CVE-2026-111497)"
            desc: "针对 iOS 26.x 与 iOS 27.0–27.2.0 未修复之 libbrotli 堆越界写漏洞 (HTTP2Shell)，剥离请求头 br 压缩声明并阻断强推响应。内置 16 项负向排除，不破坏 Apple Intelligence、Siri 与移动支付。"
            category: "安全防护"

            http:
              mitm:
            \(yamlMitmLines)

              header-rewrite:
                - ^https?://.+ request-replace-regex Accept-Encoding "^.*$" "gzip, deflate"

              script:
                - name: brotli-response-guard
                  match: ^https?://.+
                  type: response
                  require-body: false
                  timeout: 5

            script-providers:
              brotli-response-guard:
                payload: |
                  const headers = ($response && $response.headers) || {};
                  const ceParts = [];
                  for (const k of Object.keys(headers)) {
                    if (String(k).toLowerCase() === 'content-encoding') {
                      const v = headers[k];
                      ceParts.push(Array.isArray(v) ? v.join(', ') : String(v ?? ''));
                    }
                  }
                  const ce = ceParts.join(', ');
                  if (/(^|[,\\s])br($|[,\\s;])/i.test(ce)) {
                    $done({
                      status: 403,
                      headers: {
                        'Content-Type': 'text/plain; charset=utf-8',
                        'Content-Length': '0',
                        'Connection': 'close',
                        'X-WQGuard-Shield': 'Blocked-Unsolicited-Brotli'
                      }
                    });
                  } else {
                    $done({});
                  }
            """
        }
    }

    /// Validation result for module content.
    public struct ValidationResult: Sendable, Equatable {
        public let isCompliant: Bool
        public let missingExclusions: [String]
        public let hasHeaderRewrite: Bool
        public let hasScriptGuard: Bool
        public let hasValidMetadata: Bool
        public let errors: [String]

        public init(
            isCompliant: Bool,
            missingExclusions: [String],
            hasHeaderRewrite: Bool,
            hasScriptGuard: Bool,
            hasValidMetadata: Bool,
            errors: [String]
        ) {
            self.isCompliant = isCompliant
            self.missingExclusions = missingExclusions
            self.hasHeaderRewrite = hasHeaderRewrite
            self.hasScriptGuard = hasScriptGuard
            self.hasValidMetadata = hasValidMetadata
            self.errors = errors
        }
    }

    /// Validates that a Surge module content satisfies all security and compatibility invariants.
    public func validateModule(content: String) -> ValidationResult {
        validateShield(content: content, for: .surge)
    }

    /// Validates shield configuration content for any supported proxy client.
    public func validateShield(content: String, for platform: ProxyShieldPlatform) -> ValidationResult {
        var errors: [String] = []

        let hasValidMetadata: Bool
        let hasHeaderRewrite: Bool
        let hasScriptGuard: Bool

        switch platform {
        case .surge:
            hasValidMetadata = content.contains("#!name=") && content.contains("#!category=") && content.contains("#!arguments=")
            hasHeaderRewrite = content.contains("[Header Rewrite]") && content.contains("Accept-Encoding") && content.contains("\"gzip, deflate\"")
            hasScriptGuard = content.contains("[Script]")
                && content.contains("brotli-response-guard")
                && content.contains("requires-body=false")
                && content.contains("script-path=")
                && content.contains("brotli-guard.js")
                && !content.contains("script-text=")
        case .shadowrocket:
            hasValidMetadata = content.contains("#!name=") && content.contains("#!desc=")
            hasHeaderRewrite = content.contains("[Header Rewrite]") && content.contains("Accept-Encoding") && content.contains("gzip,deflate")
            hasScriptGuard = content.contains("[Script]") && content.contains("requires-body=0") && content.contains("brotli-guard.js")
        case .quantumultX:
            hasValidMetadata = content.contains("Quantumult X") && content.contains("CVE-2026-111497")
            hasHeaderRewrite = content.contains("[rewrite_local]") && content.contains("request-header") && content.contains("gzip, deflate")
            hasScriptGuard = content.contains("script-response-header") && content.contains("brotli-guard.js")
        case .loon:
            hasValidMetadata = content.contains("#!name") && content.contains("#!desc")
            hasHeaderRewrite = content.contains("[Rewrite]") && content.contains("Accept-Encoding") && content.contains("gzip,deflate")
            hasScriptGuard = content.contains("[Script]") && content.contains("http-response") && content.contains("requires-body=false")
        case .stash:
            hasValidMetadata = content.contains("name:") && content.contains("desc:")
            hasHeaderRewrite = content.contains("header-rewrite:") && content.contains("Accept-Encoding") && content.contains("gzip, deflate")
            hasScriptGuard = content.contains("script-providers:")
                && content.contains("brotli-response-guard")
                && content.contains("require-body: false")
                && content.contains("status: 403")
                && !content.contains("response:")
        }

        if !hasValidMetadata {
            errors.append("缺少合规的 \(platform.shortTitleEn) 元数据头部")
        }
        if !hasHeaderRewrite {
            errors.append("缺少 \(platform.shortTitleEn) Accept-Encoding 强制降级重写规则")
        }
        if !hasScriptGuard {
            errors.append("缺少 \(platform.shortTitleEn) 零解压响应拦截脚本规则")
        }

        var missing: [String] = []
        for exc in Self.mandatoryNegativeExclusions {
            if !content.contains(exc) {
                missing.append(exc)
            }
        }
        if !missing.isEmpty {
            errors.append("缺少关键负向排除规则: \(missing.joined(separator: ", "))")
        }

        let isCompliant = errors.isEmpty && missing.isEmpty
        return ValidationResult(
            isCompliant: isCompliant,
            missingExclusions: missing,
            hasHeaderRewrite: hasHeaderRewrite,
            hasScriptGuard: hasScriptGuard,
            hasValidMetadata: hasValidMetadata,
            errors: errors
        )
    }

    /// Exports the Surge module to a temporary file (backward-compatible API).
    public func exportToTemporaryFile(extraHosts: [String] = [], filename: String = "WQGuard-Brotli-Shield.sgmodule") throws -> URL {
        try exportShieldToTemporaryFile(for: .surge, extraHosts: extraHosts, customFilename: filename)
    }

    /// Exports any supported proxy client's shield configuration to a temporary file ready for Share Sheet.
    public func exportShieldToTemporaryFile(
        for platform: ProxyShieldPlatform,
        extraHosts: [String] = [],
        customFilename: String? = nil
    ) throws -> URL {
        let content = generateShieldContent(for: platform, extraHosts: extraHosts)
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("WQGuardSurgeExports", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent(customFilename ?? platform.defaultFilename)
        try content.write(to: fileURL, atomically: true, encoding: .utf8)
        return fileURL
    }
}
