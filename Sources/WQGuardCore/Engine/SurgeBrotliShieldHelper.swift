//
//  SurgeBrotliShieldHelper.swift
//  WQGuardCore
//
//  Multi-client Brotli Downgrade Shield generator, validator, and exporter supporting
//  Surge (.sgmodule), Shadowrocket (.module), Quantumult X (.conf), Loon (.plugin),
//  and Stash (.stoverride) to mitigate CVE-2026-111497 (HTTP2Shell).
//

import Darwin
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
            .replacingOccurrences(of: "=", with: "%3D")
            .replacingOccurrences(of: "+", with: "%2B") else {
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
            let qxTag = WQLocale.pick(en: "WQGuard Brotli Shield", zh: "WQGuard Brotli 护盾")
            let jsonParam = "{\"rewrite_remote\":[\"\(remoteRawURLString), tag=\(qxTag), update-interval=86400, opt-parser=false, enabled=true\"]}"
            if let qxEncoded = jsonParam.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)?
                .replacingOccurrences(of: "&", with: "%26")
                .replacingOccurrences(of: "=", with: "%3D")
                .replacingOccurrences(of: "+", with: "%2B") {
                return URL(string: "quantumult-x:///add-resource?remote-resource=\(qxEncoded)")
            }
            return nil
        }
    }

    public var usageHintEn: String {
        switch self {
        case .surge:
            return "Import into Surge Modules and enable MitM + CA certificate trust (keep default high-risk TLDs for zero battery overhead)."
        case .shadowrocket:
            return "Import into Shadowrocket Config -> Module, and enable HTTPS Decryption + CA trust."
        case .quantumultX:
            return "Add to Quantumult X Rewrite -> Resources, and enable both Rewrite and MitM with CA trust."
        case .loon:
            return "Import into Loon Plugins, and enable MITM + system root CA trust."
        case .stash:
            return "Import into Stash Overrides, and enable MITM + root CA certificate trust."
        }
    }

    public var localizedUsageHint: String {
        WQLocale.pick(en: usageHintEn, zh: usageHintZh)
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
    #!name=WQGuard · Brotli Downgrade Shield / 防溢出降级护盾 (CVE-2026-111497)
    #!desc=Mitigates unpatched iOS 26.x / 27.0–27.2.0 libbrotli heap OOB write (CVE-2026-111497 / HTTP2Shell, CVSS 9.2) by stripping br in Accept-Encoding & blocking unsolicited br responses; 16 Apple/banking exclusions. | 针对未修复 libbrotli 堆越界写漏洞，剥离 br 压缩声明并拦截强推响应；内置 16 项苹果与网银负向排除。
    #!version=1.3.6
    #!category=Security / 安全防护
    #!arguments=EXTRA_MITM_HOSTS:*.example.invalid
    #!arguments-desc=Extra hostnames/wildcards for Brotli downgrade protection (set * to cover all Safari/WebView domains; Apple & banking domains remain excluded). | 可追加高风险自定义域名（填 * 可覆盖全站流量，内置排除列表保障苹果与网银不受影响）。

    [Header Rewrite]
    # Strip br from client Accept-Encoding, downgrading safely to gzip & deflate / 强制剥离请求 br 声明
    ^https?:// header-replace Accept-Encoding "gzip, deflate"

    [Script]
    # Header-only (requires-body=false) block against unsolicited Content-Encoding: br / 零解压拦截强推 br 响应
    brotli-response-guard = type=http-response,pattern=^https?://.+,requires-body=false,max-size=0,script-path=https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/scripts/brotli-guard.js

    [MITM]
    # Strict 16 negative exclusions: never MITM Apple Intelligence, Siri, PCC relays, OpenAI, or banking apps
    hostname = %APPEND% -*.apple.com, -*.icloud.com, -*.icloud-content.com, -*.mzstatic.com, -*.cdn-apple.com, -guzzoni.apple.com, -*.siri.apple.com, -gspe1-ssl.ls.apple.com, -apple-relay.*, -cp4.cloudflare.com, -*.openai.com, -*.chatgpt.com, -*.binance.com, -*.okx.com, -*.tenpay.com, -*.alipay.com, *.xyz, *.top, *.icu, *.cyou, *.sbs, *.cfd, *.buzz, *.fun, *.click, *.link, *.site, *.online, *.shop, *.vip, *.pw, *.work, *.rest, *.monster, *.quest, *.zip, *.mov, {{{EXTRA_MITM_HOSTS}}}
    """

    public init() {}

    /// Generates the Surge module content (backward-compatible API).
    public func generateModuleContent(extraHosts: [String] = []) -> String {
        generateShieldContent(for: .surge, extraHosts: extraHosts)
    }

    /// Sanitizes user-supplied positive MITM hostnames/wildcards so newline/section/comment/YAML injection
    /// or leading-hyphen negative exclusions (`-*`) can never corrupt or disable generated shields.
    private static func sanitizeExtraHost(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 253, !trimmed.hasPrefix("-") else { return nil }
        let isValid = trimmed.utf8.allSatisfy { b in
            (b >= 0x41 && b <= 0x5A)
                || (b >= 0x61 && b <= 0x7A)
                || (b >= 0x30 && b <= 0x39)
                || b == 0x2E || b == 0x2D || b == 0x2A || b == 0x5F
        }
        return isValid ? trimmed : nil
    }

    /// Generates ready-to-import shield configuration for any of the 5 supported iOS proxy clients.
    public func generateShieldContent(for platform: ProxyShieldPlatform, extraHosts: [String] = []) -> String {
        let cleanExtra = extraHosts.compactMap(Self.sanitizeExtraHost)
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
            #!name=WQGuard · Brotli Downgrade Shield / 防溢出降级护盾 (CVE-2026-111497)
            #!desc=Mitigates iOS 26.x / 27.0–27.2.0 libbrotli OOB write (CVE-2026-111497 / HTTP2Shell) by downgrading Accept-Encoding & blocking unsolicited br responses; 16 Apple/banking exclusions. | 剥离 br 请求头并拦截恶意强推响应，内置 16 项苹果与网银负向排除。
            #!version=1.3.6
            #!category=Security / 安全防护

            [Header Rewrite]
            # Downgrade client Accept-Encoding to gzip,deflate / 强制降级客户端请求压缩协商
            ^https?://.+ header-replace Accept-Encoding gzip,deflate

            [Script]
            # Header-only guard (requires-body=0) blocking unsolicited Content-Encoding: br / 零解压拦截强推 br 响应
            brotli-response-guard = type=http-response,pattern=^https?://.+,script-path=\(Self.remoteGuardScriptURL),requires-body=0,max-size=0

            [MITM]
            hostname = %APPEND% \(exclusionsCSV), \(tldsCSV)\(appendedCSV)
            """

        case .quantumultX:
            return """
            ; WQGuard · Brotli Downgrade Shield / 防溢出降级护盾 (CVE-2026-111497 / HTTP2Shell) — Quantumult X Rewrite Resource
            ; #!version=1.3.6
            ; Mitigates unpatched iOS 26.x / 27.0–27.2.0 libbrotli heap OOB write by stripping br requests & blocking unsolicited br responses.
            ; Usage / 使用方式: Add under Quantumult X Rewrite -> Resources and enable Rewrite + MitM + CA certificate trust.

            [rewrite_local]
            ; 1. Downgrade Accept-Encoding to gzip, deflate / 将请求头 Accept-Encoding 降级为安全的 gzip, deflate
            ^https?://.+ url request-header (\\r\\n[Aa][Cc][Cc][Ee][Pp][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]:)[^\\r\\n]* request-header $1 gzip, deflate
            ; 2. Header-only response guard blocking unsolicited Content-Encoding: br / 仅检查响应头，拦截强推的 br 数据流
            ^https?://.+ url script-response-header \(Self.remoteGuardScriptURL)

            [mitm]
            hostname = \(exclusionsCSV), \(tldsCSV)\(appendedCSV)
            """

        case .loon:
            let defaultArg = cleanExtra.isEmpty ? "*.example.invalid" : cleanExtra.joined(separator: ", ")
            return """
            #!name = WQGuard · Brotli Downgrade Shield / 防溢出降级护盾 (CVE-2026-111497)
            #!desc = Mitigates iOS 26.x / 27.0–27.2.0 libbrotli OOB write (CVE-2026-111497 / HTTP2Shell) by downgrading Accept-Encoding to gzip,deflate & blocking unsolicited br responses; 16 Apple/banking exclusions. | 强制降级 Accept-Encoding 并阻断强推 br 响应，内置 16 项负向排除。
            #!version=1.3.6
            #!openUrl = https://github.com/Kianuni/WQGuard
            #!author = WQGuard Contributors
            #!tag = Security / 安全防护
            #!system = iOS

            [Argument]
            EXTRA_MITM_HOSTS = input, "\(defaultArg)", tag = Extra Domains / 附加域名, desc = Optional extra hostnames/wildcards for Brotli downgrade protection (e.g. *.cc, *.me) / 可选补充需强制降级的域名后缀

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
            #!version=1.3.6
            name: "WQGuard · Brotli Downgrade Shield / 防溢出降级护盾 (CVE-2026-111497)"
            desc: "Mitigates iOS 26.x / 27.0–27.2.0 libbrotli OOB write (HTTP2Shell) by stripping br in Accept-Encoding & blocking unsolicited br responses; 16 Apple/banking exclusions. | 剥离 br 请求声明并阻断强推响应，内置 16 项负向排除。"
            category: "Security / 安全防护"

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
                  (function () {
                    if (typeof $done !== 'function') { return; }
                    function coerceHdr(val, depth) {
                      if (val === undefined || val === null) { return ''; }
                      const t = typeof val;
                      if (t === 'string' || t === 'number' || t === 'boolean') { return String(val); }
                      if (Array.isArray(val)) {
                        if (depth > 4) { return ''; }
                        const items = [];
                        for (let j = 0; j < val.length; j++) {
                          const s = coerceHdr(val[j], depth + 1);
                          if (s) { items.push(s); }
                        }
                        return items.join(', ');
                      }
                      try { return String(val); } catch (_e) { return ''; }
                    }
                    const resp = typeof $response !== 'undefined' ? $response : null;
                    const headers = (resp && typeof resp.headers === 'object' && resp.headers !== null) ? resp.headers : {};
                    const encParts = [];
                    for (const k of Object.keys(headers)) {
                      const lk = String(k).trim().toLowerCase();
                      if (lk === 'content-encoding' || lk === 'transfer-encoding') {
                        const s = coerceHdr(headers[k], 0);
                        if (s) { encParts.push(s); }
                      }
                    }
                    const rawEnc = encParts.join(', ');
                    if (/(^|[^A-Za-z0-9_.-])((?:x-)?(?:br|brotli|dcb|sbr))($|[^A-Za-z0-9_.-])/i.test(rawEnc)) {
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
                  })();
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
        let hasMITMConfig: Bool
        let effectiveMitmTokens: Set<String>
        let allSeenMitmTokens: [String]
        let activeLinesForKillSwitch: [String]

        switch platform {
        case .surge, .shadowrocket, .quantumultX, .loon:
            let commentChars: Set<Character> = (platform == .quantumultX) ? ["#", ";"] : ["#"]
            let parsed = Self.parseINIConfig(content: content, commentChars: commentChars)
            let directivesJoined = parsed.directiveLines.joined(separator: "\n")
            let headerRewriteLines = parsed.sections[platform == .loon ? "rewrite" : (platform == .quantumultX ? "rewrite_local" : "header rewrite")] ?? []
            let scriptLines = parsed.sections[platform == .quantumultX ? "rewrite_local" : "script"] ?? []
            let mitmLines = parsed.sections["mitm"] ?? []

            switch platform {
            case .surge:
                hasValidMetadata = directivesJoined.contains("#!name=")
                    && directivesJoined.contains("#!category=")
                    && directivesJoined.contains("#!arguments=")
                hasHeaderRewrite = headerRewriteLines.contains { line in
                    Self.isCompliantHeaderReplaceAcceptEncoding(line, requireQuoted: true)
                }
                let hasScriptRule = scriptLines.contains { line in
                    line.contains("brotli-response-guard")
                        && line.contains("type=http-response")
                        && line.contains("requires-body=false")
                        && line.contains("script-path=")
                        && line.contains("brotli-guard.js")
                }
                let hasInlineScriptText = scriptLines.contains { $0.contains("script-text=") }
                hasScriptGuard = hasScriptRule && !hasInlineScriptText

            case .shadowrocket:
                hasValidMetadata = directivesJoined.contains("#!name=")
                    && directivesJoined.contains("#!desc=")
                hasHeaderRewrite = headerRewriteLines.contains { line in
                    Self.isCompliantHeaderReplaceAcceptEncoding(line)
                }
                hasScriptGuard = scriptLines.contains { line in
                    line.contains("type=http-response")
                        && line.contains("requires-body=0")
                        && line.contains("brotli-guard.js")
                }

            case .quantumultX:
                let bannerJoined = parsed.semicolonBannerLines.joined(separator: "\n")
                hasValidMetadata = bannerJoined.contains("Quantumult X") && bannerJoined.contains("CVE-2026-111497")
                hasHeaderRewrite = headerRewriteLines.contains { line in
                    Self.isCompliantQuantumultXHeaderRewrite(line)
                }
                hasScriptGuard = scriptLines.contains { line in
                    line.contains("url script-response-header") && line.contains("brotli-guard.js")
                }

            case .loon:
                hasValidMetadata = directivesJoined.contains("#!name")
                    && directivesJoined.contains("#!desc")
                hasHeaderRewrite = headerRewriteLines.contains { line in
                    Self.isCompliantHeaderReplaceAcceptEncoding(line)
                }
                hasScriptGuard = scriptLines.contains { line in
                    line.contains("http-response")
                        && line.contains("requires-body=false")
                        && line.contains("brotli-guard.js")
                }

            case .stash:
                hasValidMetadata = false
                hasHeaderRewrite = false
                hasScriptGuard = false
            }

            let mitmParsed = Self.parseMITMHostnameLines(mitmLines)
            hasMITMConfig = parsed.sections["mitm"] != nil && mitmParsed.hasHostnameLine
            effectiveMitmTokens = mitmParsed.effectiveTokens
            allSeenMitmTokens = mitmParsed.allTokens
            activeLinesForKillSwitch = parsed.activeLines

        case .stash:
            let parsed = Self.parseStashYAML(content: content)
            hasValidMetadata = parsed.hasTopLevelName && parsed.hasTopLevelDesc
            hasHeaderRewrite = parsed.headerRewriteLines.contains { line in
                Self.isCompliantStashHeaderRewrite(line)
            }
            let hasScriptEntry = parsed.scriptEntries.contains { entryLines in
                Self.isCompliantStashScriptEntry(entryLines)
            }
            let jsMasked = Self.stripJSComments(parsed.payloadJS, maskNonKeyLiterals: true)
            let hasStatus403 = jsMasked.range(
                of: #"(?<![A-Za-z0-9_$])(?:status|['"]status['"])\s*:\s*403(?![0-9])"#,
                options: .regularExpression
            ) != nil
            let hasNestedWrapper = jsMasked.range(
                of: #"(?<![A-Za-z0-9_$])(?:response|['"]response['"]|body|['"]body['"])\s*:|\[\s*['"`](?:response|body)['"`]\s*\]\s*:"#,
                options: .regularExpression
            ) != nil
            hasScriptGuard = parsed.hasScriptProviderGuard && hasScriptEntry && hasStatus403 && !hasNestedWrapper
            hasMITMConfig = parsed.hasMITMSection && !parsed.mitmTokens.isEmpty
            effectiveMitmTokens = Set(parsed.mitmTokens)
            allSeenMitmTokens = parsed.mitmTokens
            activeLinesForKillSwitch = parsed.activeLines
        }

        if !hasValidMetadata {
            errors.append(WQLocale.pick(
                en: "Missing compliant \(platform.shortTitleEn) metadata header",
                zh: "缺少合规的 \(platform.shortTitleEn) 元数据头部"
            ))
        }
        if !hasHeaderRewrite {
            errors.append(WQLocale.pick(
                en: "Missing \(platform.shortTitleEn) Accept-Encoding downgrade rewrite rule",
                zh: "缺少 \(platform.shortTitleEn) Accept-Encoding 强制降级重写规则"
            ))
        }
        if !hasScriptGuard {
            errors.append(WQLocale.pick(
                en: "Missing \(platform.shortTitleEn) header-only response guard script rule",
                zh: "缺少 \(platform.shortTitleEn) 零解压响应拦截脚本规则"
            ))
        }
        if !hasMITMConfig {
            errors.append(WQLocale.pick(
                en: "Missing \(platform.shortTitleEn) active [MITM] / mitm hostname configuration",
                zh: "缺少 \(platform.shortTitleEn) 有效的 [MITM] / mitm 域名配置段"
            ))
        }

        var missing: [String] = []
        for exc in Self.mandatoryNegativeExclusions {
            if !effectiveMitmTokens.contains(exc.lowercased()) {
                missing.append(exc)
            }
        }
        if !missing.isEmpty {
            errors.append(WQLocale.pick(
                en: "Missing mandatory negative exclusions: \(missing.joined(separator: ", "))",
                zh: "缺少关键负向排除规则: \(missing.joined(separator: ", "))"
            ))
        }

        let hasTokenKillSwitch = allSeenMitmTokens.contains(where: Self.isBlanketNegativeKillSwitchToken)
        let hasLineKillSwitch = activeLinesForKillSwitch.contains { line in
            line.range(
                of: #"(?:^|[\s,='"])-\*(?:[.*]*)(?::[^\s,'"]+)?(?=$|[\s,'"])"#,
                options: .regularExpression
            ) != nil
        }
        if hasTokenKillSwitch || hasLineKillSwitch {
            errors.append(WQLocale.pick(
                en: "Blanket negative MITM exclusion (-*) disables Brotli shield protection",
                zh: "存在全局负向排除 (-*)，会导致 Brotli 降级护盾失效"
            ))
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

    // MARK: - Private Shield Parsing Helpers

    private struct ParsedINIConfig {
        var directiveLines: [String] = []
        var semicolonBannerLines: [String] = []
        var sections: [String: [String]] = [:]
        var activeLines: [String] = []
    }

    private struct ParsedMITMHostnames {
        var hasHostnameLine: Bool = false
        var effectiveTokens: Set<String> = []
        var allTokens: [String] = []
    }

    private struct ParsedStashYAML {
        var hasTopLevelName: Bool = false
        var hasTopLevelDesc: Bool = false
        var hasMITMSection: Bool = false
        var mitmTokens: [String] = []
        var headerRewriteLines: [String] = []
        var scriptEntries: [[(key: String, value: String)]] = []
        var hasScriptProviderGuard: Bool = false
        var payloadJS: String = ""
        var activeLines: [String] = []
    }

    private static func isCompliantStashScriptEntry(_ entryPairs: [(key: String, value: String)]) -> Bool {
        var names: [String] = []
        var types: [String] = []
        var requireBodies: [String] = []
        var matches: [String] = []

        for (rawKey, rawVal) in entryPairs {
            let key = rawKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let val = rawVal.trimmingCharacters(in: .whitespacesAndNewlines)
            switch key {
            case "name":
                names.append(val.lowercased())
            case "type":
                types.append(val.lowercased())
            case "require-body":
                requireBodies.append(val.lowercased())
            case "match":
                if !val.isEmpty {
                    matches.append(val)
                }
            default:
                break
            }
        }

        return names == ["brotli-response-guard"]
            && types == ["response"]
            && requireBodies == ["false"]
            && !matches.isEmpty
            && !types.contains("request")
            && !requireBodies.contains("true")
    }

    private static func normalizedLines(_ content: String) -> [String] {
        content
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
    }

    private static func stripInlineCommentOutsideQuotes(_ line: String, commentChars: Set<Character>) -> String {
        var inSingle = false
        var inDouble = false
        var escaped = false
        var prevWasWhitespace = true
        var result = ""
        result.reserveCapacity(line.count)

        for ch in line {
            if escaped {
                result.append(ch)
                escaped = false
                prevWasWhitespace = false
                continue
            }
            if ch == "\\" && (inSingle || inDouble) {
                result.append(ch)
                escaped = true
                prevWasWhitespace = false
                continue
            }
            if ch == "\"" && !inSingle {
                inDouble.toggle()
                result.append(ch)
                prevWasWhitespace = false
                continue
            }
            if ch == "'" && !inDouble {
                inSingle.toggle()
                result.append(ch)
                prevWasWhitespace = false
                continue
            }
            if !inSingle && !inDouble && commentChars.contains(ch) && prevWasWhitespace {
                break
            }
            result.append(ch)
            prevWasWhitespace = ch.isWhitespace
        }
        return result.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func parseINIConfig(content: String, commentChars: Set<Character>) -> ParsedINIConfig {
        var parsed = ParsedINIConfig()
        var currentSection: String? = nil

        for rawLine in normalizedLines(content) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty { continue }

            if trimmed.hasPrefix("#!") {
                parsed.directiveLines.append(trimmed)
                continue
            }
            if commentChars.contains(";") && trimmed.hasPrefix(";") {
                parsed.semicolonBannerLines.append(trimmed)
                continue
            }
            if trimmed.hasPrefix("#") {
                continue
            }

            let cleaned = stripInlineCommentOutsideQuotes(trimmed, commentChars: commentChars)
            if cleaned.isEmpty { continue }

            if cleaned.hasPrefix("[") && cleaned.hasSuffix("]") && cleaned.count >= 2 {
                let secName = String(cleaned.dropFirst().dropLast())
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                    .lowercased()
                currentSection = secName
                if parsed.sections[secName] == nil {
                    parsed.sections[secName] = []
                }
                continue
            }

            if let sec = currentSection {
                parsed.sections[sec, default: []].append(cleaned)
            }
            parsed.activeLines.append(cleaned)
        }
        return parsed
    }

    private static func stripSurroundingQuotes(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if (s.hasPrefix("\"") && s.hasSuffix("\"")) || (s.hasPrefix("'") && s.hasSuffix("'")) {
            if s.count >= 2 {
                s = String(s.dropFirst().dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }
        return s
    }

    private static func parseMITMHostnameLines(_ lines: [String]) -> ParsedMITMHostnames {
        var out = ParsedMITMHostnames()
        for line in lines {
            guard let eqIdx = line.firstIndex(of: "=") else { continue }
            let lhs = line[..<eqIdx].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard lhs == "hostname" else { continue }
            out.hasHostnameLine = true

            var rhs = line[line.index(after: eqIdx)...].trimmingCharacters(in: .whitespacesAndNewlines)
            let upperRHS = rhs.uppercased()
            var isAppend = false
            if upperRHS.hasPrefix("%APPEND%") {
                isAppend = true
                rhs = String(rhs.dropFirst("%APPEND%".count)).trimmingCharacters(in: .whitespacesAndNewlines)
            } else if upperRHS.hasPrefix("%INSERT%") {
                isAppend = true
                rhs = String(rhs.dropFirst("%INSERT%".count)).trimmingCharacters(in: .whitespacesAndNewlines)
            }

            let tokens = rhs
                .split(separator: ",", omittingEmptySubsequences: false)
                .map { stripSurroundingQuotes(String($0)).lowercased() }
                .filter { !$0.isEmpty }

            out.allTokens.append(contentsOf: tokens)
            if isAppend {
                out.effectiveTokens.formUnion(tokens)
            } else {
                out.effectiveTokens = Set(tokens)
            }
        }
        return out
    }

    private static func isValidAcceptEncodingDowngradeValue(_ rawValue: String) -> Bool {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }

        let inner: String
        if trimmed.hasPrefix("\"") && trimmed.hasSuffix("\"") && trimmed.count >= 2 {
            let unquoted = String(trimmed.dropFirst().dropLast())
            guard !unquoted.contains("\"") else { return false }
            inner = unquoted
        } else if trimmed.hasPrefix("'") && trimmed.hasSuffix("'") && trimmed.count >= 2 {
            let unquoted = String(trimmed.dropFirst().dropLast())
            guard !unquoted.contains("'") else { return false }
            inner = unquoted
        } else {
            guard !trimmed.contains("\""), !trimmed.contains("'") else { return false }
            inner = trimmed
        }

        let tokens = inner
            .split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        guard tokens == ["gzip", "deflate"] else { return false }

        if inner.range(
            of: #"(?:^|[^A-Za-z0-9_.-])(?:x-)?(?:br|brotli|dcb|sbr)(?:$|[^A-Za-z0-9_.-])"#,
            options: [.regularExpression, .caseInsensitive]
        ) != nil {
            return false
        }
        return true
    }

    private static func isCompliantHeaderReplaceAcceptEncoding(_ line: String, requireQuoted: Bool = false) -> Bool {
        guard let regex = try? NSRegularExpression(
            pattern: #"^\S+\s+header-replace\s+Accept-Encoding\s+(.+)$"#,
            options: [.caseInsensitive]
        ) else {
            return false
        }
        let nsRange = NSRange(line.startIndex..<line.endIndex, in: line)
        guard let match = regex.firstMatch(in: line, range: nsRange),
              match.numberOfRanges >= 2,
              let valRange = Range(match.range(at: 1), in: line) else {
            return false
        }
        let rawVal = String(line[valRange]).trimmingCharacters(in: .whitespacesAndNewlines)
        if requireQuoted {
            guard rawVal == "\"gzip, deflate\"" || rawVal == "\"gzip,deflate\"" else {
                return false
            }
        }
        return isValidAcceptEncodingDowngradeValue(rawVal)
    }

    private static func foldSingleLetterCaseClasses(_ pattern: String) -> String {
        let chars = Array(pattern)
        var out = ""
        out.reserveCapacity(chars.count)
        var i = 0
        while i < chars.count {
            if chars[i] == "[", i + 3 < chars.count, chars[i + 3] == "]" {
                let c1 = chars[i + 1]
                let c2 = chars[i + 2]
                if c1.isASCII, c1.isLetter, c2.isASCII, c2.isLetter, c1.lowercased() == c2.lowercased() {
                    out.append(c1.lowercased())
                    i += 4
                    continue
                }
            }
            out.append(chars[i].lowercased())
            i += 1
        }
        return out
    }

    private static func isCompliantQuantumultXHeaderRewrite(_ line: String) -> Bool {
        guard let outerRegex = try? NSRegularExpression(
            pattern: #"^\S+\s+url\s+request-header\s+(\S+)\s+request-header\s+(.+)$"#,
            options: []
        ) else {
            return false
        }
        let nsRange = NSRange(line.startIndex..<line.endIndex, in: line)
        guard let outerMatch = outerRegex.firstMatch(in: line, range: nsRange),
              outerMatch.numberOfRanges == 3,
              let patternRange = Range(outerMatch.range(at: 1), in: line),
              let replacementRange = Range(outerMatch.range(at: 2), in: line) else {
            return false
        }
        let headerPattern = String(line[patternRange])
        guard headerPattern.count <= 2048 else {
            return false
        }
        let foldedPattern = foldSingleLetterCaseClasses(headerPattern)
        guard let targetRegex = try? NSRegularExpression(
            pattern: #"^(?:\(\?[imsx]+\))?(?:\(|(?:\(\?:(?:\^|\\r\\n|\\n)(?:\|(?:\^|\\r\\n|\\n))*\))|\^|\\r\\n|\\n)*accept-encoding(?:\s*|\\s[*?])?\)?:"#,
            options: []
        ) else {
            return false
        }
        let foldedNSRange = NSRange(foldedPattern.startIndex..<foldedPattern.endIndex, in: foldedPattern)
        guard targetRegex.firstMatch(in: foldedPattern, range: foldedNSRange) != nil else {
            return false
        }

        let rawReplacement = String(line[replacementRange]).trimmingCharacters(in: .whitespacesAndNewlines)
        let downgradeValue: String
        if rawReplacement.hasPrefix("$1") {
            let afterDollar1 = rawReplacement.dropFirst(2)
            if afterDollar1.hasPrefix(":") {
                downgradeValue = String(afterDollar1.dropFirst()).trimmingCharacters(in: .whitespacesAndNewlines)
            } else if let first = afterDollar1.first, first.isWhitespace {
                downgradeValue = String(afterDollar1).trimmingCharacters(in: .whitespacesAndNewlines)
            } else {
                return false
            }
        } else if let colonRange = rawReplacement.range(of: "accept-encoding:", options: [.caseInsensitive, .anchored]) {
            downgradeValue = String(rawReplacement[colonRange.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            return false
        }
        guard isValidAcceptEncodingDowngradeValue(downgradeValue) else {
            return false
        }

        guard let compiledPattern = try? NSRegularExpression(pattern: headerPattern, options: []) else {
            return false
        }
        if rawReplacement.hasPrefix("$1"), compiledPattern.numberOfCaptureGroups < 1 {
            return false
        }

        let samples = [
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: br\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\naccept-encoding: br\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: gzip, br\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: br, gzip\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: zstd, br\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: BR\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: x-br\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: deflate, br\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: zstd, gzip, deflate, br\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: gzip, deflate, br, zstd\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.xyz\r\nAccept-Encoding: br, deflate\r\n\r\n"
        ]
        for sample in samples {
            let sampleRange = NSRange(sample.startIndex..<sample.endIndex, in: sample)
            guard compiledPattern.numberOfMatches(in: sample, options: [], range: sampleRange) >= 1 else {
                return false
            }
            let rewritten = compiledPattern.stringByReplacingMatches(
                in: sample,
                options: [],
                range: sampleRange,
                withTemplate: rawReplacement
            )
            let lines = rewritten
                .replacingOccurrences(of: "\r\n", with: "\n")
                .split(separator: "\n", omittingEmptySubsequences: false)
                .map(String.init)
            let aeLines = lines.filter { $0.lowercased().hasPrefix("accept-encoding:") }
            guard lines.first == "GET / HTTP/1.1",
                  lines.contains("Host: a.xyz"),
                  aeLines.count == 1,
                  let rewrittenLine = aeLines.first else {
                return false
            }
            let rewrittenValue = String(rewrittenLine.dropFirst("accept-encoding:".count))
            guard isValidAcceptEncodingDowngradeValue(rewrittenValue) else {
                return false
            }
        }
        return true
    }

    private static func consumeStashToken(in text: String) -> (tokenEnd: String.Index, found: Bool) {
        var idx = text.startIndex
        guard idx < text.endIndex else { return (idx, false) }
        let firstChar = text[idx]
        if firstChar == "\"" || firstChar == "'" {
            idx = text.index(after: idx)
            let contentStart = idx
            var escaped = false
            var foundClose = false
            while idx < text.endIndex {
                let ch = text[idx]
                if escaped {
                    escaped = false
                } else if ch == "\\" {
                    escaped = true
                } else if ch == firstChar {
                    guard idx > contentStart else { return (idx, false) }
                    idx = text.index(after: idx)
                    foundClose = true
                    break
                }
                idx = text.index(after: idx)
            }
            return (idx, foundClose)
        } else {
            while idx < text.endIndex && !text[idx].isWhitespace {
                idx = text.index(after: idx)
            }
            return (idx, idx > text.startIndex)
        }
    }

    private static func isCompliantStashHeaderRewrite(_ line: String) -> Bool {
        var working = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if working.hasPrefix("-") {
            working = String(working.dropFirst()).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard !working.isEmpty else { return false }

        let (urlEnd, urlOK) = consumeStashToken(in: working)
        guard urlOK, urlEnd < working.endIndex, working[urlEnd].isWhitespace else {
            return false
        }
        let afterURL = String(working[urlEnd...]).trimmingCharacters(in: .whitespacesAndNewlines)

        guard let regex = try? NSRegularExpression(
            pattern: #"^request-replace(-regex)?\s+Accept-Encoding\s+(.+)$"#,
            options: [.caseInsensitive]
        ) else {
            return false
        }
        let nsRange = NSRange(afterURL.startIndex..<afterURL.endIndex, in: afterURL)
        guard let match = regex.firstMatch(in: afterURL, range: nsRange),
              match.numberOfRanges >= 3,
              let restRange = Range(match.range(at: 2), in: afterURL) else {
            return false
        }
        let isRegexMode = match.range(at: 1).location != NSNotFound
        let rest = String(afterURL[restRange]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !rest.isEmpty else { return false }

        if isRegexMode {
            let (patternEnd, patternOK) = consumeStashToken(in: rest)
            guard patternOK, patternEnd < rest.endIndex, rest[patternEnd].isWhitespace else {
                return false
            }
            let rawPattern = String(rest[..<patternEnd])
            let unquotedPattern = stripSurroundingQuotes(rawPattern)
            guard !unquotedPattern.isEmpty, unquotedPattern.count <= 2048 else {
                return false
            }
            let replacement = String(rest[patternEnd...]).trimmingCharacters(in: .whitespacesAndNewlines)
            guard isValidAcceptEncodingDowngradeValue(replacement) else {
                return false
            }
            guard let compiledRegex = try? NSRegularExpression(pattern: unquotedPattern, options: []) else {
                return false
            }
            let unquotedReplacement = stripSurroundingQuotes(replacement)
            let samples = [
                "br",
                "brotli",
                "dcb",
                "sbr",
                "identity, br",
                "gzip, deflate, br",
                "gzip, br",
                "br, gzip",
                "zstd, br",
                "BR",
                "x-br",
                "deflate, br",
                "zstd, gzip, deflate, br",
                "gzip, deflate, br, zstd",
                "br, deflate"
            ]
            for sample in samples {
                let sampleRange = NSRange(sample.startIndex..<sample.endIndex, in: sample)
                guard let match = compiledRegex.firstMatch(in: sample, options: [], range: sampleRange) else {
                    return false
                }
                let replacedText = compiledRegex.replacementString(
                    for: match,
                    in: sample,
                    offset: 0,
                    template: unquotedReplacement
                )
                let rewritten = (sample as NSString).replacingCharacters(in: match.range, with: replacedText)
                guard isValidAcceptEncodingDowngradeValue(rewritten) else {
                    return false
                }
            }
            return true
        } else {
            return isValidAcceptEncodingDowngradeValue(rest)
        }
    }

    private enum YAMLScalarStyle: Equatable {
        case plain
        case singleQuoted
        case doubleQuoted
        case literalBlock
        case foldedBlock
    }

    private indirect enum YAMLNode: Equatable {
        case null
        case scalar(String, style: YAMLScalarStyle)
        case sequence([YAMLNode])
        case mapping([(key: YAMLNode, value: YAMLNode)])

        static func == (lhs: YAMLNode, rhs: YAMLNode) -> Bool {
            switch (lhs, rhs) {
            case (.null, .null):
                return true
            case let (.scalar(a, sa), .scalar(b, sb)):
                return a == b && sa == sb
            case let (.sequence(a), .sequence(b)):
                return a == b
            case let (.mapping(a), .mapping(b)):
                guard a.count == b.count else { return false }
                return zip(a, b).allSatisfy { $0.key == $1.key && $0.value == $1.value }
            default:
                return false
            }
        }
    }

    private enum YAMLParseError: Error {
        case syntaxError
        case resourceLimitExceeded
    }

    private struct StashYAMLParser {
        private static let maxLines = 100_000
        private static let maxDepth = 128
        private static let maxTotalNodes = 100_000
        private static let maxAliasExpansions = 4096

        private let lines: [[Character]]
        private var line: Int = 0
        private var col: Int = 0
        private var depth: Int = 0
        private var totalNodes: Int = 0
        private var aliasExpansions: Int = 0
        private var anchors: [String: (node: YAMLNode, weight: Int)] = [:]
        private var parsedAnyDocument: Bool = false
        private var sawDocumentEndMarker: Bool = false

        init(content: String) throws {
            var scalars = content.unicodeScalars[...]
            if scalars.first == "\u{FEFF}" {
                scalars = scalars.dropFirst()
            }
            for scalar in scalars {
                let v = scalar.value
                let allowed = v == 0x09 || v == 0x0A || v == 0x0D || v == 0x85
                    || (v >= 0x20 && v != 0x7F && !(v >= 0x80 && v <= 0x9F))
                if !allowed {
                    throw YAMLParseError.syntaxError
                }
            }
            let normalized = String(scalars)
                .replacingOccurrences(of: "\r\n", with: "\n")
                .replacingOccurrences(of: "\r", with: "\n")
                .replacingOccurrences(of: "\u{0085}", with: "\n")
                .replacingOccurrences(of: "\u{2028}", with: "\n")
                .replacingOccurrences(of: "\u{2029}", with: "\n")
            let rawLines = normalized.split(separator: "\n", omittingEmptySubsequences: false)
            guard rawLines.count <= Self.maxLines else {
                throw YAMLParseError.resourceLimitExceeded
            }
            self.lines = rawLines.map(Array.init)
        }

        private var currentLine: [Character] { lines[line] }
        private var atEOF: Bool { line >= lines.count }
        private var atEOL: Bool { line >= lines.count || col >= lines[line].count }

        private func isAnchorChar(_ ch: Character) -> Bool {
            guard let ascii = ch.asciiValue else { return false }
            return (ascii >= 0x30 && ascii <= 0x39)
                || (ascii >= 0x41 && ascii <= 0x5A)
                || (ascii >= 0x61 && ascii <= 0x7A)
                || ch == "_" || ch == "-"
        }

        private func isHWS(_ ch: Character) -> Bool {
            ch == " " || ch == "\t"
        }

        private func isFlowIndicator(_ ch: Character) -> Bool {
            ch == "[" || ch == "]" || ch == "{" || ch == "}" || ch == ","
        }

        private func leadingSpaces(of lineIdx: Int) -> Int {
            let ln = lines[lineIdx]
            var i = 0
            while i < ln.count && ln[i] == " " {
                i += 1
            }
            return i
        }

        private func startsWithDocStart(at lineIdx: Int) -> Bool {
            guard lineIdx < lines.count else { return false }
            let ln = lines[lineIdx]
            guard ln.count >= 3 && ln[0] == "-" && ln[1] == "-" && ln[2] == "-" else {
                return false
            }
            return ln.count == 3 || isHWS(ln[3])
        }

        private func startsWithDocEnd(at lineIdx: Int) -> Bool {
            guard lineIdx < lines.count else { return false }
            let ln = lines[lineIdx]
            guard ln.count >= 3 && ln[0] == "." && ln[1] == "." && ln[2] == "." else {
                return false
            }
            return ln.count == 3 || isHWS(ln[3])
        }

        private mutating func skipHWS() {
            guard line < lines.count else { return }
            let ln = lines[line]
            while col < ln.count && isHWS(ln[col]) {
                col += 1
            }
        }

        private mutating func consumeTrailingCommentAndEOL(requireSpaceBeforeHash: Bool) throws {
            guard line < lines.count else { return }
            let ln = lines[line]
            let sawWS = col < ln.count && isHWS(ln[col])
            skipHWS()
            if col < ln.count {
                if ln[col] == "#" && (!requireSpaceBeforeHash || sawWS) {
                    // Valid inline comment extending to EOL
                } else {
                    throw YAMLParseError.syntaxError
                }
            }
            line += 1
            col = 0
        }

        private mutating func skipInterlineTrivia(activePlainParentIndent: Int?) throws -> Bool {
            var terminatedPlain = false
            while line < lines.count {
                let ln = lines[line]
                let sp = leadingSpaces(of: line)
                if sp == ln.count {
                    line += 1
                    col = 0
                    continue
                }
                if ln[sp] == "#" {
                    if activePlainParentIndent != nil {
                        terminatedPlain = true
                    }
                    line += 1
                    col = 0
                    continue
                }
                if ln[sp] == "\t" {
                    var j = sp
                    while j < ln.count && isHWS(ln[j]) { j += 1 }
                    let isBlankOrComment = (j == ln.count) || (ln[j] == "#")
                    if isBlankOrComment, let pIndent = activePlainParentIndent, !terminatedPlain, sp > pIndent {
                        if j < ln.count && ln[j] == "#" {
                            terminatedPlain = true
                        }
                        line += 1
                        col = 0
                        continue
                    }
                    throw YAMLParseError.syntaxError
                }
                break
            }
            return terminatedPlain
        }

        private mutating func recordNode(_ count: Int = 1) throws {
            totalNodes += count
            if totalNodes > Self.maxTotalNodes {
                throw YAMLParseError.resourceLimitExceeded
            }
        }

        private func nodeWeight(_ node: YAMLNode) -> Int {
            switch node {
            case .null, .scalar:
                return 1
            case .sequence(let items):
                return 1 + items.reduce(0) { $0 + nodeWeight($1) }
            case .mapping(let pairs):
                return 1 + pairs.reduce(0) { $0 + nodeWeight($1.key) + nodeWeight($1.value) }
            }
        }

        private mutating func enterDepth() throws {
            depth += 1
            if depth > Self.maxDepth {
                throw YAMLParseError.resourceLimitExceeded
            }
        }

        private mutating func exitDepth() {
            depth -= 1
        }

        mutating func parseStream() throws -> [YAMLNode] {
            var documents: [YAMLNode] = []

            while line < lines.count {
                anchors.removeAll()
                _ = try skipInterlineTrivia(activePlainParentIndent: nil)
                if line >= lines.count { break }

                var sawDirective = false
                var sawYAMLDirective = false
                var seenTagHandles: Set<String> = []
                while line < lines.count && !lines[line].isEmpty && lines[line][0] == "%" {
                    if parsedAnyDocument && !sawDocumentEndMarker {
                        throw YAMLParseError.syntaxError
                    }
                    try parseDirectiveLine(
                        sawYAMLDirective: &sawYAMLDirective,
                        seenTagHandles: &seenTagHandles
                    )
                    sawDirective = true
                    _ = try skipInterlineTrivia(activePlainParentIndent: nil)
                }

                if line >= lines.count {
                    if sawDirective {
                        throw YAMLParseError.syntaxError
                    }
                    break
                }

                if sawDirective && !startsWithDocStart(at: line) {
                    throw YAMLParseError.syntaxError
                }

                if sawDocumentEndMarker && !startsWithDocStart(at: line) {
                    throw YAMLParseError.syntaxError
                }

                if startsWithDocStart(at: line) {
                    anchors.removeAll()
                    sawDocumentEndMarker = false
                    parsedAnyDocument = true
                    col = 3
                    skipHWS()
                    if atEOL || currentLine[col] == "#" {
                        line += 1
                        col = 0
                        _ = try skipInterlineTrivia(activePlainParentIndent: nil)
                        if line >= lines.count || startsWithDocStart(at: line) || startsWithDocEnd(at: line) {
                            try recordNode()
                            documents.append(.null)
                        } else {
                            let doc = try parseBlockContentAtNewLine(parentIndent: -1, allowSameIndentSequence: true)
                            documents.append(doc)
                        }
                    } else {
                        let doc = try parseInlineDocumentStartContent()
                        documents.append(doc)
                    }
                } else {
                    if parsedAnyDocument {
                        throw YAMLParseError.syntaxError
                    }
                    parsedAnyDocument = true
                    let doc = try parseBlockContentAtNewLine(parentIndent: -1, allowSameIndentSequence: true)
                    documents.append(doc)
                }

                _ = try skipInterlineTrivia(activePlainParentIndent: nil)
                if line < lines.count {
                    if startsWithDocEnd(at: line) {
                        col = 3
                        try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: true)
                        sawDocumentEndMarker = true
                        anchors.removeAll()
                    } else if !startsWithDocStart(at: line) {
                        throw YAMLParseError.syntaxError
                    }
                }
            }

            return documents
        }

        private mutating func parseDirectiveLine(
            sawYAMLDirective: inout Bool,
            seenTagHandles: inout Set<String>
        ) throws {
            let ln = lines[line]
            var i = 1
            while i < ln.count && !isHWS(ln[i]) {
                i += 1
            }
            let dirName = String(ln[1..<i])
            guard dirName == "YAML" || dirName == "TAG" else {
                throw YAMLParseError.syntaxError
            }
            col = i
            skipHWS()
            if col >= ln.count || ln[col] == "#" {
                throw YAMLParseError.syntaxError
            }
            if dirName == "YAML" {
                guard !sawYAMLDirective else {
                    throw YAMLParseError.syntaxError
                }
                sawYAMLDirective = true
                var j = col
                while j < ln.count && !isHWS(ln[j]) && ln[j] != "#" {
                    j += 1
                }
                let ver = String(ln[col..<j])
                let parts = ver.split(separator: ".", omittingEmptySubsequences: false)
                guard parts.count == 2,
                      parts[0] == "1",
                      parts[1] == "1" else {
                    throw YAMLParseError.syntaxError
                }
                col = j
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: true)
            } else {
                // %TAG <handle> <prefix>
                var j = col
                while j < ln.count && !isHWS(ln[j]) { j += 1 }
                guard j > col else { throw YAMLParseError.syntaxError }
                let handle = String(ln[col..<j])
                guard handle.hasPrefix("!"), !seenTagHandles.contains(handle) else {
                    throw YAMLParseError.syntaxError
                }
                seenTagHandles.insert(handle)
                col = j
                skipHWS()
                var k = col
                while k < ln.count && !isHWS(ln[k]) { k += 1 }
                guard k > col else { throw YAMLParseError.syntaxError }
                col = k
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: true)
            }
        }

        private mutating func parseInlineDocumentStartContent() throws -> YAMLNode {
            let props = try parseSameLineProperties(inFlow: false)
            if atEOL || currentLine[col] == "#" {
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: true)
                _ = try skipInterlineTrivia(activePlainParentIndent: nil)
                if line >= lines.count || startsWithDocStart(at: line) || startsWithDocEnd(at: line) {
                    return registerAnchor(.null, anchor: props.anchor)
                }
                let child = try parseBlockNode(parentIndent: -1, allowSameIndentSequence: true)
                return registerAnchor(child, anchor: props.anchor)
            }

            let ch = currentLine[col]
            if ch == "-" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                throw YAMLParseError.syntaxError
            }
            if ch == "?" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                throw YAMLParseError.syntaxError
            }
            if ch == "*" {
                let node = try parseAlias(inFlow: false)
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: true)
                return registerAnchor(node, anchor: props.anchor)
            }
            if ch == "|" || ch == ">" {
                if props.anchor != nil || props.tag != nil {
                    // valid properties before block scalar
                }
                let node = try parseBlockScalar(baseIndent: 0)
                return registerAnchor(node, anchor: props.anchor)
            }
            if ch == "\"" || ch == "'" {
                let (val, _) = (ch == "\"") ? try parseDoubleQuotedScalar() : try parseSingleQuotedScalar()
                skipHWS()
                if col < currentLine.count && currentLine[col] == ":"
                    && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                    throw YAMLParseError.syntaxError
                }
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: false)
                try recordNode()
                let style: YAMLScalarStyle = (ch == "\"") ? .doubleQuoted : .singleQuoted
                return registerAnchor(.scalar(val, style: style), anchor: props.anchor)
            }
            if ch == "[" || ch == "{" {
                let node = (ch == "[") ? try parseFlowSequence() : try parseFlowMapping()
                skipHWS()
                if col < currentLine.count && currentLine[col] == ":"
                    && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                    throw YAMLParseError.syntaxError
                }
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: false)
                return registerAnchor(node, anchor: props.anchor)
            }
            if hasPlainMappingColonOnLine(from: col) {
                throw YAMLParseError.syntaxError
            }
            let node = try parsePlainScalar(parentIndent: -1)
            return registerAnchor(node, anchor: props.anchor)
        }

        private mutating func registerAnchor(_ node: YAMLNode, anchor: String?) -> YAMLNode {
            if let anchor = anchor {
                anchors[anchor] = (node: node, weight: nodeWeight(node))
            }
            return node
        }

        private mutating func parseSameLineProperties(inFlow: Bool) throws -> (anchor: String?, tag: String?) {
            var anchor: String? = nil
            var tag: String? = nil

            while line < lines.count {
                if inFlow {
                    try skipFlowTrivia()
                } else {
                    skipHWS()
                }
                guard line < lines.count && col < currentLine.count else { break }
                let ch = currentLine[col]
                if ch == "&" {
                    guard anchor == nil else { throw YAMLParseError.syntaxError }
                    col += 1
                    let start = col
                    while col < currentLine.count && isAnchorChar(currentLine[col]) {
                        col += 1
                    }
                    guard col > start else { throw YAMLParseError.syntaxError }
                    anchor = String(currentLine[start..<col])
                    if col < currentLine.count
                        && !isHWS(currentLine[col])
                        && currentLine[col] != ":"
                        && (!inFlow || !isFlowIndicator(currentLine[col])) {
                        throw YAMLParseError.syntaxError
                    }
                } else if ch == "!" {
                    guard tag == nil else { throw YAMLParseError.syntaxError }
                    col += 1
                    if col < currentLine.count && currentLine[col] == "<" {
                        col += 1
                        let start = col
                        while col < currentLine.count && currentLine[col] != ">" {
                            if isHWS(currentLine[col]) { throw YAMLParseError.syntaxError }
                            col += 1
                        }
                        guard col < currentLine.count && col > start else { throw YAMLParseError.syntaxError }
                        tag = String(currentLine[start..<col])
                        col += 1
                    } else {
                        let start = col
                        while col < currentLine.count && !isHWS(currentLine[col]) && !isFlowIndicator(currentLine[col]) {
                            col += 1
                        }
                        tag = "!" + String(currentLine[start..<col])
                    }
                } else {
                    break
                }
            }
            return (anchor, tag)
        }

        private mutating func parseAlias(inFlow: Bool) throws -> YAMLNode {
            guard col < currentLine.count && currentLine[col] == "*" else {
                throw YAMLParseError.syntaxError
            }
            col += 1
            let start = col
            while col < currentLine.count && isAnchorChar(currentLine[col]) {
                col += 1
            }
            guard col > start else {
                throw YAMLParseError.syntaxError
            }
            if col < currentLine.count
                && !isHWS(currentLine[col])
                && currentLine[col] != ":"
                && (!inFlow || !isFlowIndicator(currentLine[col])) {
                throw YAMLParseError.syntaxError
            }
            let name = String(currentLine[start..<col])
            guard let target = anchors[name] else {
                throw YAMLParseError.syntaxError
            }
            aliasExpansions += 1
            if aliasExpansions > Self.maxAliasExpansions {
                throw YAMLParseError.resourceLimitExceeded
            }
            try recordNode(target.weight)
            return target.node
        }

        private func hasPlainMappingColonOnLine(from startCol: Int) -> Bool {
            guard line < lines.count else { return false }
            let ln = lines[line]
            var i = startCol
            var prevWS = false
            while i < ln.count {
                let ch = ln[i]
                if ch == "#" && prevWS {
                    return false
                }
                if ch == ":" && (i + 1 == ln.count || isHWS(ln[i + 1])) {
                    return true
                }
                prevWS = isHWS(ch)
                i += 1
            }
            return false
        }

        private mutating func lookaheadIsQuotedOrFlowMappingKey() -> Bool {
            let savedLine = line
            let savedCol = col
            let savedTotalNodes = totalNodes
            let savedAliasExpansions = aliasExpansions
            let savedAnchors = anchors
            defer {
                line = savedLine
                col = savedCol
                totalNodes = savedTotalNodes
                aliasExpansions = savedAliasExpansions
                anchors = savedAnchors
            }

            let startLine = line
            guard line < lines.count && col < currentLine.count else { return false }
            let ch = currentLine[col]
            do {
                if ch == "\"" {
                    let (_, isMulti) = try parseDoubleQuotedScalar()
                    if isMulti || line != startLine { return false }
                } else if ch == "'" {
                    let (_, isMulti) = try parseSingleQuotedScalar()
                    if isMulti || line != startLine { return false }
                } else if ch == "[" {
                    _ = try parseFlowSequence()
                    if line != startLine { return false }
                } else if ch == "{" {
                    _ = try parseFlowMapping()
                    if line != startLine { return false }
                } else {
                    return false
                }
                skipHWS()
                return col < currentLine.count
                    && currentLine[col] == ":"
                    && (col + 1 == currentLine.count || isHWS(currentLine[col + 1]))
            } catch {
                return false
            }
        }

        private mutating func lookaheadLineHasBlockMappingKeyFromCurrentPos() -> Bool {
            let savedLine = line
            let savedCol = col
            let savedTotalNodes = totalNodes
            let savedAliasExpansions = aliasExpansions
            let savedAnchors = anchors
            defer {
                line = savedLine
                col = savedCol
                totalNodes = savedTotalNodes
                aliasExpansions = savedAliasExpansions
                anchors = savedAnchors
            }

            let props: (anchor: String?, tag: String?)
            do {
                props = try parseSameLineProperties(inFlow: false)
            } catch {
                return false
            }
            guard line < lines.count && col < currentLine.count else { return false }
            let ch = currentLine[col]
            if ch == "?" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                return true
            }
            if ch == "\"" || ch == "'" || ch == "[" || ch == "{" {
                return lookaheadIsQuotedOrFlowMappingKey()
            }
            if ch == "|" || ch == ">" || ch == "*" || ch == "#" {
                return false
            }
            if ch == "-" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                return false
            }
            if ch == ":" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                return props.anchor != nil || props.tag != nil
            }
            return hasPlainMappingColonOnLine(from: col)
        }

        private mutating func parseBlockContentAtNewLine(parentIndent: Int, allowSameIndentSequence: Bool) throws -> YAMLNode {
            try enterDepth()
            defer { exitDepth() }

            _ = try skipInterlineTrivia(activePlainParentIndent: nil)
            if line >= lines.count || startsWithDocStart(at: line) || startsWithDocEnd(at: line) {
                try recordNode()
                return .null
            }
            let indent = leadingSpaces(of: line)
            if indent < parentIndent {
                try recordNode()
                return .null
            }
            if indent == parentIndent {
                let ln = lines[line]
                if indent < ln.count && ln[indent] == "\t" {
                    throw YAMLParseError.syntaxError
                }
                if allowSameIndentSequence
                    && indent < ln.count
                    && ln[indent] == "-"
                    && (indent + 1 == ln.count || isHWS(ln[indent + 1])) {
                    return try parseBlockSequence(seqIndent: indent, parentIndent: parentIndent)
                }
                try recordNode()
                return .null
            }

            // indent > parentIndent
            let ln = lines[line]
            if indent < ln.count && ln[indent] == "\t" {
                throw YAMLParseError.syntaxError
            }
            col = indent
            if ln[col] == "-" && (col + 1 == ln.count || isHWS(ln[col + 1])) {
                return try parseBlockSequence(seqIndent: indent, parentIndent: parentIndent)
            }
            if lookaheadLineHasBlockMappingKeyFromCurrentPos() {
                return try parseBlockMapping(mapIndent: indent, startingAtCurrentLine: false)
            }
            let childProps = try parseSameLineProperties(inFlow: false)
            if atEOL || currentLine[col] == "#" {
                if !atEOL && currentLine[col] == "#" && col > 0 && !isHWS(currentLine[col - 1]) {
                    throw YAMLParseError.syntaxError
                }
                line += 1
                col = 0
                try recordNode()
                return registerAnchor(.null, anchor: childProps.anchor)
            }
            let c = currentLine[col]
            let node: YAMLNode
            if c == "|" || c == ">" {
                node = try parseBlockScalar(baseIndent: max(parentIndent, 0))
            } else if c == "[" || c == "{" {
                node = (c == "[") ? try parseFlowSequence() : try parseFlowMapping()
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: false)
            } else if c == "\"" || c == "'" {
                let (val, _) = (c == "\"") ? try parseDoubleQuotedScalar() : try parseSingleQuotedScalar()
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: false)
                try recordNode()
                node = .scalar(val, style: c == "\"" ? .doubleQuoted : .singleQuoted)
            } else if c == "*" {
                node = try parseAlias(inFlow: false)
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: true)
            } else {
                node = try parsePlainScalar(parentIndent: parentIndent)
            }
            return registerAnchor(node, anchor: childProps.anchor)
        }

        private mutating func parseBlockNode(
            parentIndent: Int,
            allowSameIndentSequence: Bool,
            allowCompactCollection: Bool = false
        ) throws -> YAMLNode {
            try enterDepth()
            defer { exitDepth() }

            let props = try parseSameLineProperties(inFlow: false)
            if atEOL || currentLine[col] == "#" {
                if !atEOL && currentLine[col] == "#" && col > 0 && !isHWS(currentLine[col - 1]) {
                    throw YAMLParseError.syntaxError
                }
                line += 1
                col = 0
                let child = try parseBlockContentAtNewLine(parentIndent: parentIndent, allowSameIndentSequence: allowSameIndentSequence)
                return registerAnchor(child, anchor: props.anchor)
            }

            // Same-line value after `key: ` or compact collection after `? `
            let ch = currentLine[col]
            if allowCompactCollection {
                if ch == "-" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                    if col + 1 < currentLine.count && currentLine[col + 1] == "\t" {
                        throw YAMLParseError.syntaxError
                    }
                    let seq = try parseBlockSequence(seqIndent: col, parentIndent: parentIndent, startingAtCurrentLine: true)
                    return registerAnchor(seq, anchor: props.anchor)
                }
                if lookaheadLineHasBlockMappingKeyFromCurrentPos() {
                    let map = try parseBlockMapping(mapIndent: col, startingAtCurrentLine: true)
                    return registerAnchor(map, anchor: props.anchor)
                }
            }
            if ch == "-" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                throw YAMLParseError.syntaxError
            }
            if ch == "?" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                throw YAMLParseError.syntaxError
            }
            if ch == ":" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                throw YAMLParseError.syntaxError
            }
            let node: YAMLNode
            if ch == "|" || ch == ">" {
                node = try parseBlockScalar(baseIndent: max(parentIndent, 0))
            } else if ch == "[" || ch == "{" {
                node = (ch == "[") ? try parseFlowSequence() : try parseFlowMapping()
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: false)
            } else if ch == "\"" || ch == "'" {
                let (val, _) = (ch == "\"") ? try parseDoubleQuotedScalar() : try parseSingleQuotedScalar()
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: false)
                try recordNode()
                node = .scalar(val, style: ch == "\"" ? .doubleQuoted : .singleQuoted)
            } else if ch == "*" {
                node = try parseAlias(inFlow: false)
                try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: true)
            } else {
                node = try parsePlainScalar(parentIndent: parentIndent)
            }
            return registerAnchor(node, anchor: props.anchor)
        }

        private mutating func parseBlockMapping(mapIndent: Int, startingAtCurrentLine: Bool) throws -> YAMLNode {
            try enterDepth()
            defer { exitDepth() }

            var pairs: [(key: YAMLNode, value: YAMLNode)] = []
            var first = startingAtCurrentLine

            while line < lines.count {
                if !first {
                    _ = try skipInterlineTrivia(activePlainParentIndent: nil)
                    if line >= lines.count { break }
                    if mapIndent == 0 && (startsWithDocStart(at: line) || startsWithDocEnd(at: line)) {
                        break
                    }
                    let sp = leadingSpaces(of: line)
                    if sp < mapIndent { break }
                    if sp > mapIndent { throw YAMLParseError.syntaxError }
                    col = sp
                    if col < currentLine.count && currentLine[col] == "\t" {
                        throw YAMLParseError.syntaxError
                    }
                    if col < currentLine.count && currentLine[col] == "-"
                        && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                        break
                    }
                }
                first = false

                let keyProps = try parseSameLineProperties(inFlow: false)
                guard line < lines.count && col < currentLine.count else {
                    throw YAMLParseError.syntaxError
                }

                if currentLine[col] == "?" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                    if col + 1 < currentLine.count && currentLine[col + 1] == "\t" {
                        throw YAMLParseError.syntaxError
                    }
                    col += 1
                    let keyNode = try parseBlockNode(parentIndent: mapIndent, allowSameIndentSequence: true, allowCompactCollection: true)
                    let registeredKey = registerAnchor(keyNode, anchor: keyProps.anchor)
                    _ = try skipInterlineTrivia(activePlainParentIndent: nil)
                    let valNode: YAMLNode
                    if line < lines.count && leadingSpaces(of: line) == mapIndent {
                        let ln = lines[line]
                        if mapIndent < ln.count && ln[mapIndent] == ":"
                            && (mapIndent + 1 == ln.count || isHWS(ln[mapIndent + 1])) {
                            if mapIndent + 1 < ln.count && ln[mapIndent + 1] == "\t" {
                                throw YAMLParseError.syntaxError
                            }
                            col = mapIndent + 1
                            valNode = try parseBlockNode(parentIndent: mapIndent, allowSameIndentSequence: true)
                        } else {
                            try recordNode()
                            valNode = .null
                        }
                    } else {
                        try recordNode()
                        valNode = .null
                    }
                    pairs.append((key: registeredKey, value: valNode))
                    continue
                }

                let keyStartLine = line
                let keyNode: YAMLNode
                let ch = currentLine[col]
                if (keyProps.anchor != nil || keyProps.tag != nil)
                    && ch == ":"
                    && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                    try recordNode()
                    keyNode = .null
                } else if ch == "\"" || ch == "'" {
                    let (keyStr, isMulti) = (ch == "\"") ? try parseDoubleQuotedScalar() : try parseSingleQuotedScalar()
                    guard !isMulti && line == keyStartLine else { throw YAMLParseError.syntaxError }
                    try recordNode()
                    keyNode = .scalar(keyStr, style: ch == "\"" ? .doubleQuoted : .singleQuoted)
                } else if ch == "[" || ch == "{" {
                    keyNode = (ch == "[") ? try parseFlowSequence() : try parseFlowMapping()
                    guard line == keyStartLine else { throw YAMLParseError.syntaxError }
                } else if ch == "*" {
                    keyNode = try parseAlias(inFlow: false)
                } else {
                    if ch == "|" || ch == ">" || ch == "]" || ch == "}" || ch == "," || ch == "@" || ch == "`" || ch == "#" {
                        throw YAMLParseError.syntaxError
                    }
                    if ch == "-" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                        throw YAMLParseError.syntaxError
                    }
                    if ch == ":" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                        throw YAMLParseError.syntaxError
                    }
                    var i = col
                    var prevWS = false
                    var colonIdx: Int? = nil
                    while i < currentLine.count {
                        let c = currentLine[i]
                        if c == "#" && prevWS {
                            break
                        }
                        if c == ":" && (i + 1 == currentLine.count || isHWS(currentLine[i + 1])) {
                            colonIdx = i
                            break
                        }
                        prevWS = isHWS(c)
                        i += 1
                    }
                    guard let foundColon = colonIdx else {
                        throw YAMLParseError.syntaxError
                    }
                    var end = foundColon
                    while end > col && isHWS(currentLine[end - 1]) {
                        end -= 1
                    }
                    guard end > col else { throw YAMLParseError.syntaxError }
                    let keyStr = String(currentLine[col..<end])
                    col = foundColon
                    try recordNode()
                    keyNode = .scalar(keyStr, style: .plain)
                }

                skipHWS()
                guard col < currentLine.count
                        && currentLine[col] == ":"
                        && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) else {
                    throw YAMLParseError.syntaxError
                }
                col += 1
                let registeredKey = registerAnchor(keyNode, anchor: keyProps.anchor)
                let valNode = try parseBlockNode(parentIndent: mapIndent, allowSameIndentSequence: true)
                pairs.append((key: registeredKey, value: valNode))
            }

            try recordNode()
            return .mapping(pairs)
        }

        private mutating func parseBlockSequence(
            seqIndent: Int,
            parentIndent: Int,
            startingAtCurrentLine: Bool = false
        ) throws -> YAMLNode {
            try enterDepth()
            defer { exitDepth() }

            var items: [YAMLNode] = []
            var first = startingAtCurrentLine

            while line < lines.count {
                let sp: Int
                if first {
                    first = false
                    sp = seqIndent
                } else {
                    _ = try skipInterlineTrivia(activePlainParentIndent: nil)
                    if line >= lines.count { break }
                    if seqIndent == 0 && (startsWithDocStart(at: line) || startsWithDocEnd(at: line)) {
                        break
                    }
                    let measured = leadingSpaces(of: line)
                    if measured < seqIndent { break }
                    if measured > seqIndent { throw YAMLParseError.syntaxError }
                    sp = measured
                }

                let ln = lines[line]
                if sp < ln.count && ln[sp] == "\t" {
                    throw YAMLParseError.syntaxError
                }
                guard sp < ln.count && ln[sp] == "-" else {
                    if seqIndent == parentIndent {
                        break
                    }
                    throw YAMLParseError.syntaxError
                }
                if sp + 1 < ln.count && ln[sp + 1] == "\t" {
                    throw YAMLParseError.syntaxError
                }
                guard sp + 1 == ln.count || ln[sp + 1] == " " else {
                    if seqIndent == parentIndent {
                        break
                    }
                    throw YAMLParseError.syntaxError
                }

                col = sp + 1
                var spacesAfterDash = 0
                while col < ln.count && ln[col] == " " {
                    spacesAfterDash += 1
                    col += 1
                }
                if col < ln.count && ln[col] == "\t" {
                    throw YAMLParseError.syntaxError
                }

                if col == ln.count || ln[col] == "#" {
                    line += 1
                    col = 0
                    let item = try parseBlockContentAtNewLine(parentIndent: seqIndent, allowSameIndentSequence: false)
                    items.append(item)
                    continue
                }

                let itemCol = seqIndent + 1 + spacesAfterDash
                if ln[col] == "-" && (col + 1 == ln.count || isHWS(ln[col + 1])) {
                    if col + 1 < ln.count && ln[col + 1] == "\t" {
                        throw YAMLParseError.syntaxError
                    }
                    let nested = try parseBlockSequence(seqIndent: itemCol, parentIndent: seqIndent, startingAtCurrentLine: true)
                    items.append(nested)
                    continue
                }

                if lookaheadLineHasBlockMappingKeyFromCurrentPos() {
                    let map = try parseBlockMapping(mapIndent: itemCol, startingAtCurrentLine: true)
                    items.append(map)
                    continue
                }

                let props = try parseSameLineProperties(inFlow: false)
                if atEOL || currentLine[col] == "#" {
                    if !atEOL && currentLine[col] == "#" && col > 0 && !isHWS(currentLine[col - 1]) {
                        throw YAMLParseError.syntaxError
                    }
                    line += 1
                    col = 0
                    let child = try parseBlockContentAtNewLine(parentIndent: seqIndent, allowSameIndentSequence: false)
                    items.append(registerAnchor(child, anchor: props.anchor))
                    continue
                }

                let c = currentLine[col]
                let itemNode: YAMLNode
                if c == "|" || c == ">" {
                    itemNode = try parseBlockScalar(baseIndent: seqIndent)
                } else if c == "[" || c == "{" {
                    itemNode = (c == "[") ? try parseFlowSequence() : try parseFlowMapping()
                    try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: false)
                } else if c == "\"" || c == "'" {
                    let (val, _) = (c == "\"") ? try parseDoubleQuotedScalar() : try parseSingleQuotedScalar()
                    try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: false)
                    try recordNode()
                    itemNode = .scalar(val, style: c == "\"" ? .doubleQuoted : .singleQuoted)
                } else if c == "*" {
                    itemNode = try parseAlias(inFlow: false)
                    try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: true)
                } else {
                    itemNode = try parsePlainScalar(parentIndent: seqIndent)
                }
                items.append(registerAnchor(itemNode, anchor: props.anchor))
            }

            try recordNode()
            return .sequence(items)
        }

        private mutating func parseDoubleQuotedScalar() throws -> (value: String, isMultiLine: Bool) {
            guard col < currentLine.count && currentLine[col] == "\"" else {
                throw YAMLParseError.syntaxError
            }
            col += 1
            var out = ""
            var isMultiLine = false
            var lineBuffer = ""

            while line < lines.count {
                let ln = lines[line]
                while col < ln.count {
                    let ch = ln[col]
                    if ch == "\"" {
                        col += 1
                        out.append(lineBuffer)
                        return (out, isMultiLine)
                    }
                    if ch == "\\" {
                        col += 1
                        if col == ln.count {
                            // Line continuation: backslash at EOL folds away newline and leading WS
                            isMultiLine = true
                            out.append(lineBuffer)
                            lineBuffer = ""
                            line += 1
                            col = 0
                            if line >= lines.count { throw YAMLParseError.syntaxError }
                            if startsWithDocStart(at: line) || startsWithDocEnd(at: line) {
                                throw YAMLParseError.syntaxError
                            }
                            let nextLn = lines[line]
                            while col < nextLn.count && isHWS(nextLn[col]) {
                                col += 1
                            }
                            break
                        }
                        let esc = ln[col]
                        col += 1
                        switch esc {
                        case "0": lineBuffer.append("\0")
                        case "a": lineBuffer.append("\u{07}")
                        case "b": lineBuffer.append("\u{08}")
                        case "t", "\t": lineBuffer.append("\t")
                        case "n": lineBuffer.append("\n")
                        case "v": lineBuffer.append("\u{0B}")
                        case "f": lineBuffer.append("\u{0C}")
                        case "r": lineBuffer.append("\r")
                        case "e": lineBuffer.append("\u{1B}")
                        case " ": lineBuffer.append(" ")
                        case "\"": lineBuffer.append("\"")
                        case "/": lineBuffer.append("/")
                        case "\\": lineBuffer.append("\\")
                        case "N": lineBuffer.append("\u{0085}")
                        case "_": lineBuffer.append("\u{00A0}")
                        case "L": lineBuffer.append("\u{2028}")
                        case "P": lineBuffer.append("\u{2029}")
                        case "x":
                            lineBuffer.append(try parseHexUnicodeEscape(digits: 2))
                        case "u":
                            lineBuffer.append(try parseHexUnicodeEscape(digits: 4))
                        case "U":
                            lineBuffer.append(try parseHexUnicodeEscape(digits: 8))
                        default:
                            throw YAMLParseError.syntaxError
                        }
                    } else {
                        lineBuffer.append(ch)
                        col += 1
                    }
                }
                if col == ln.count {
                    isMultiLine = true
                    while lineBuffer.last == " " || lineBuffer.last == "\t" {
                        lineBuffer.removeLast()
                    }
                    out.append(lineBuffer)
                    lineBuffer = ""
                    line += 1
                    col = 0
                    if line >= lines.count { throw YAMLParseError.syntaxError }
                    if startsWithDocStart(at: line) || startsWithDocEnd(at: line) {
                        throw YAMLParseError.syntaxError
                    }
                    var blankCount = 0
                    while line < lines.count {
                        if startsWithDocStart(at: line) || startsWithDocEnd(at: line) {
                            throw YAMLParseError.syntaxError
                        }
                        let nextLn = lines[line]
                        var j = 0
                        while j < nextLn.count && isHWS(nextLn[j]) { j += 1 }
                        if j == nextLn.count {
                            blankCount += 1
                            line += 1
                            continue
                        }
                        col = j
                        break
                    }
                    if line >= lines.count { throw YAMLParseError.syntaxError }
                    if blankCount > 0 {
                        out.append(String(repeating: "\n", count: blankCount))
                    } else {
                        out.append(" ")
                    }
                }
            }
            throw YAMLParseError.syntaxError
        }

        private mutating func parseHexUnicodeEscape(digits: Int) throws -> Character {
            let ln = lines[line]
            guard col + digits <= ln.count else {
                throw YAMLParseError.syntaxError
            }
            var value: UInt32 = 0
            for i in 0..<digits {
                let c = ln[col + i]
                guard let hex = c.hexDigitValue else {
                    throw YAMLParseError.syntaxError
                }
                value = (value << 4) | UInt32(hex)
            }
            guard let scalar = UnicodeScalar(value) else {
                throw YAMLParseError.syntaxError
            }
            col += digits
            return Character(scalar)
        }

        private mutating func parseSingleQuotedScalar() throws -> (value: String, isMultiLine: Bool) {
            guard col < currentLine.count && currentLine[col] == "'" else {
                throw YAMLParseError.syntaxError
            }
            col += 1
            var out = ""
            var isMultiLine = false
            var lineBuffer = ""

            while line < lines.count {
                let ln = lines[line]
                while col < ln.count {
                    let ch = ln[col]
                    if ch == "'" {
                        if col + 1 < ln.count && ln[col + 1] == "'" {
                            lineBuffer.append("'")
                            col += 2
                        } else {
                            col += 1
                            out.append(lineBuffer)
                            return (out, isMultiLine)
                        }
                    } else {
                        lineBuffer.append(ch)
                        col += 1
                    }
                }
                isMultiLine = true
                while lineBuffer.last == " " || lineBuffer.last == "\t" {
                    lineBuffer.removeLast()
                }
                out.append(lineBuffer)
                lineBuffer = ""
                line += 1
                col = 0
                if line >= lines.count { throw YAMLParseError.syntaxError }
                if startsWithDocStart(at: line) || startsWithDocEnd(at: line) {
                    throw YAMLParseError.syntaxError
                }
                var blankCount = 0
                while line < lines.count {
                    if startsWithDocStart(at: line) || startsWithDocEnd(at: line) {
                        throw YAMLParseError.syntaxError
                    }
                    let nextLn = lines[line]
                    var j = 0
                    while j < nextLn.count && isHWS(nextLn[j]) { j += 1 }
                    if j == nextLn.count {
                        blankCount += 1
                        line += 1
                        continue
                    }
                    col = j
                    break
                }
                if line >= lines.count { throw YAMLParseError.syntaxError }
                if blankCount > 0 {
                    out.append(String(repeating: "\n", count: blankCount))
                } else {
                    out.append(" ")
                }
            }
            throw YAMLParseError.syntaxError
        }

        private mutating func skipFlowTrivia() throws {
            while line < lines.count {
                let ln = lines[line]
                while col < ln.count && isHWS(ln[col]) {
                    col += 1
                }
                if col < ln.count && ln[col] == "#" {
                    line += 1
                    col = 0
                    if line < lines.count && (startsWithDocStart(at: line) || startsWithDocEnd(at: line)) {
                        throw YAMLParseError.syntaxError
                    }
                    continue
                }
                if col >= ln.count {
                    line += 1
                    col = 0
                    if line < lines.count && (startsWithDocStart(at: line) || startsWithDocEnd(at: line)) {
                        throw YAMLParseError.syntaxError
                    }
                    continue
                }
                break
            }
        }

        private mutating func parseFlowNode() throws -> (node: YAMLNode, isSingleLineKeyCandidate: Bool, isQuotedOrFlow: Bool) {
            try enterDepth()
            defer { exitDepth() }

            let startLine = line
            let props = try parseSameLineProperties(inFlow: true)
            try skipFlowTrivia()
            guard line < lines.count && col < currentLine.count else {
                throw YAMLParseError.syntaxError
            }
            let ch = currentLine[col]
            if props.anchor != nil || props.tag != nil {
                if ch == "," || ch == "]" || ch == "}"
                    || (ch == ":" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1]) || isFlowIndicator(currentLine[col + 1]))) {
                    try recordNode()
                    let node = registerAnchor(.null, anchor: props.anchor)
                    return (node, line == startLine, true)
                }
            }
            if ch == "," || ch == "]" || ch == "}" {
                throw YAMLParseError.syntaxError
            }
            if ch == "*" {
                let node = try parseAlias(inFlow: true)
                return (registerAnchor(node, anchor: props.anchor), line == startLine, false)
            }
            if ch == "[" {
                let node = try parseFlowSequence()
                return (registerAnchor(node, anchor: props.anchor), line == startLine, true)
            }
            if ch == "{" {
                let node = try parseFlowMapping()
                return (registerAnchor(node, anchor: props.anchor), line == startLine, true)
            }
            if ch == "\"" {
                let (val, isMulti) = try parseDoubleQuotedScalar()
                try recordNode()
                let node = registerAnchor(.scalar(val, style: .doubleQuoted), anchor: props.anchor)
                return (node, !isMulti && line == startLine, true)
            }
            if ch == "'" {
                let (val, isMulti) = try parseSingleQuotedScalar()
                try recordNode()
                let node = registerAnchor(.scalar(val, style: .singleQuoted), anchor: props.anchor)
                return (node, !isMulti && line == startLine, true)
            }
            if ch == "|" || ch == ">" || ch == "?" || ch == "%" || ch == "@" || ch == "`" {
                throw YAMLParseError.syntaxError
            }
            if (ch == "-" || ch == ":") && (col + 1 == currentLine.count || isHWS(currentLine[col + 1]) || isFlowIndicator(currentLine[col + 1])) {
                if ch == ":" {
                    throw YAMLParseError.syntaxError
                }
                if col + 1 == currentLine.count || isHWS(currentLine[col + 1]) {
                    throw YAMLParseError.syntaxError
                }
            }

            let (text, isMulti) = try parseFlowPlainScalar()
            try recordNode()
            let node = registerAnchor(.scalar(text, style: .plain), anchor: props.anchor)
            return (node, !isMulti && line == startLine, false)
        }

        private mutating func parseFlowPlainScalar() throws -> (value: String, isMultiLine: Bool) {
            let startLine = line
            var parts: [String] = []
            var pendingBlankLines = 0

            func scanFlowPlainLineSegment() throws -> (text: String, stoppedAtFlowDelimiterOrColon: Bool) {
                let ln = lines[line]
                var i = col
                var lastNonWS = col
                var prevWS = false
                while i < ln.count {
                    let ch = ln[i]
                    if isFlowIndicator(ch) {
                        break
                    }
                    if ch == "#" && prevWS {
                        break
                    }
                    if ch == ":" {
                        if i + 1 == ln.count || isHWS(ln[i + 1]) {
                            break
                        }
                        if isFlowIndicator(ln[i + 1]) {
                            throw YAMLParseError.syntaxError
                        }
                        lastNonWS = i + 1
                        prevWS = false
                        i += 1
                        continue
                    }
                    if !isHWS(ch) {
                        lastNonWS = i + 1
                        prevWS = false
                    } else {
                        prevWS = true
                    }
                    i += 1
                }
                let seg = String(ln[col..<lastNonWS])
                col = i
                let stoppedAtDelimiter = i < ln.count && (isFlowIndicator(ln[i]) || ln[i] == ":" || (ln[i] == "#" && prevWS))
                return (seg, stoppedAtDelimiter)
            }

            let (firstSeg, stoppedFirst) = try scanFlowPlainLineSegment()
            if firstSeg.isEmpty {
                throw YAMLParseError.syntaxError
            }
            parts.append(firstSeg)
            if stoppedFirst {
                return (parts.joined(), false)
            }

            // Continuation lines inside flow plain scalar
            while line < lines.count {
                let savedLine = line
                let savedCol = col
                if col >= currentLine.count {
                    line += 1
                    col = 0
                    if line >= lines.count {
                        throw YAMLParseError.syntaxError
                    }
                    if startsWithDocStart(at: line) || startsWithDocEnd(at: line) {
                        throw YAMLParseError.syntaxError
                    }
                } else {
                    break
                }

                let ln = lines[line]
                var j = 0
                while j < ln.count && isHWS(ln[j]) { j += 1 }
                if j == ln.count {
                    pendingBlankLines += 1
                    col = ln.count
                    continue
                }
                if ln[j] == "#" {
                    // Comment terminates flow plain scalar
                    line = savedLine
                    col = savedCol
                    break
                }
                if isFlowIndicator(ln[j]) {
                    col = j
                    break
                }
                if ln[j] == ":" {
                    if j + 1 == ln.count || isHWS(ln[j + 1]) {
                        col = j
                        break
                    }
                    if j + 1 < ln.count && isFlowIndicator(ln[j + 1]) {
                        throw YAMLParseError.syntaxError
                    }
                }
                if ln[j] == "\"" || ln[j] == "'" {
                    line = savedLine
                    col = savedCol
                    break
                }

                col = j
                let (seg, stopped) = try scanFlowPlainLineSegment()
                if pendingBlankLines > 0 {
                    parts.append(String(repeating: "\n", count: pendingBlankLines) + seg)
                    pendingBlankLines = 0
                } else {
                    parts.append(" " + seg)
                }
                if stopped {
                    break
                }
            }

            return (parts.joined(), line != startLine)
        }

        private mutating func parseFlowSequence() throws -> YAMLNode {
            try enterDepth()
            defer { exitDepth() }

            guard col < currentLine.count && currentLine[col] == "[" else {
                throw YAMLParseError.syntaxError
            }
            col += 1
            var items: [YAMLNode] = []
            var expectItemOrClose = true

            while true {
                try skipFlowTrivia()
                guard line < lines.count && col < currentLine.count else {
                    throw YAMLParseError.syntaxError
                }
                let ch = currentLine[col]
                if ch == "]" {
                    col += 1
                    try recordNode()
                    return .sequence(items)
                }
                if !expectItemOrClose {
                    guard ch == "," else {
                        throw YAMLParseError.syntaxError
                    }
                    col += 1
                    expectItemOrClose = true
                    continue
                }
                if ch == "," || ch == "}" {
                    throw YAMLParseError.syntaxError
                }
                if ch == "?" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                    col += 1
                    let (kNode, _, _) = try parseFlowNode()
                    try skipFlowTrivia()
                    let vNode: YAMLNode
                    if line < lines.count && col < currentLine.count && currentLine[col] == ":"
                        && (col + 1 == currentLine.count || isHWS(currentLine[col + 1]) || currentLine[col + 1] == "," || currentLine[col + 1] == "]") {
                        col += 1
                        try skipFlowTrivia()
                        if line < lines.count && col < currentLine.count && (currentLine[col] == "," || currentLine[col] == "]") {
                            try recordNode()
                            vNode = .null
                        } else {
                            vNode = try parseFlowNode().node
                        }
                    } else {
                        try recordNode()
                        vNode = .null
                    }
                    try recordNode()
                    items.append(.mapping([(key: kNode, value: vNode)]))
                    expectItemOrClose = false
                    continue
                }

                let (firstNode, isSingleLineKey, isQuotedOrFlow) = try parseFlowNode()
                let endLine = line
                while line == endLine && col < currentLine.count && isHWS(currentLine[col]) {
                    col += 1
                }
                if line == endLine && col < currentLine.count && currentLine[col] == ":" {
                    guard isSingleLineKey else { throw YAMLParseError.syntaxError }
                    if !isQuotedOrFlow {
                        guard col + 1 == currentLine.count || isHWS(currentLine[col + 1]) else {
                            throw YAMLParseError.syntaxError
                        }
                    }
                    col += 1
                    try skipFlowTrivia()
                    let valNode: YAMLNode
                    if line < lines.count && col < currentLine.count && (currentLine[col] == "," || currentLine[col] == "]") {
                        try recordNode()
                        valNode = .null
                    } else {
                        valNode = try parseFlowNode().node
                    }
                    try recordNode()
                    items.append(.mapping([(key: firstNode, value: valNode)]))
                } else {
                    items.append(firstNode)
                }
                expectItemOrClose = false
            }
        }

        private mutating func parseFlowMapping() throws -> YAMLNode {
            try enterDepth()
            defer { exitDepth() }

            guard col < currentLine.count && currentLine[col] == "{" else {
                throw YAMLParseError.syntaxError
            }
            col += 1
            var pairs: [(key: YAMLNode, value: YAMLNode)] = []
            var expectPairOrClose = true

            while true {
                try skipFlowTrivia()
                guard line < lines.count && col < currentLine.count else {
                    throw YAMLParseError.syntaxError
                }
                let ch = currentLine[col]
                if ch == "}" {
                    col += 1
                    try recordNode()
                    return .mapping(pairs)
                }
                if !expectPairOrClose {
                    guard ch == "," else {
                        throw YAMLParseError.syntaxError
                    }
                    col += 1
                    expectPairOrClose = true
                    continue
                }
                if ch == "," || ch == "]" {
                    throw YAMLParseError.syntaxError
                }

                if ch == "?" && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                    col += 1
                    let (kNode, _, _) = try parseFlowNode()
                    try skipFlowTrivia()
                    let vNode: YAMLNode
                    if line < lines.count && col < currentLine.count && currentLine[col] == ":" {
                        col += 1
                        try skipFlowTrivia()
                        if line < lines.count && col < currentLine.count && (currentLine[col] == "," || currentLine[col] == "}") {
                            try recordNode()
                            vNode = .null
                        } else {
                            vNode = try parseFlowNode().node
                        }
                    } else {
                        try recordNode()
                        vNode = .null
                    }
                    pairs.append((key: kNode, value: vNode))
                    expectPairOrClose = false
                    continue
                }

                let (keyNode, isSingleLineKey, isQuotedOrFlow) = try parseFlowNode()
                let keyEndLine = line
                while line == keyEndLine && col < currentLine.count && isHWS(currentLine[col]) {
                    col += 1
                }
                if line == keyEndLine && col < currentLine.count && currentLine[col] == ":" {
                    guard isSingleLineKey else { throw YAMLParseError.syntaxError }
                    if !isQuotedOrFlow {
                        guard col + 1 == currentLine.count || isHWS(currentLine[col + 1]) else {
                            throw YAMLParseError.syntaxError
                        }
                    }
                    col += 1
                    try skipFlowTrivia()
                    let valNode: YAMLNode
                    if line < lines.count && col < currentLine.count && (currentLine[col] == "," || currentLine[col] == "}") {
                        try recordNode()
                        valNode = .null
                    } else {
                        valNode = try parseFlowNode().node
                    }
                    pairs.append((key: keyNode, value: valNode))
                } else {
                    try skipFlowTrivia()
                    guard line < lines.count && col < currentLine.count && (currentLine[col] == "," || currentLine[col] == "}") else {
                        throw YAMLParseError.syntaxError
                    }
                    try recordNode()
                    pairs.append((key: keyNode, value: .null))
                }
                expectPairOrClose = false
            }
        }

        private mutating func parsePlainScalar(parentIndent: Int) throws -> YAMLNode {
            let startLine = line
            guard line < lines.count && col < currentLine.count else {
                throw YAMLParseError.syntaxError
            }
            let firstChar = currentLine[col]
            if firstChar == "\"" || firstChar == "'" || firstChar == "|" || firstChar == ">"
                || firstChar == "[" || firstChar == "{" || firstChar == "]" || firstChar == "}"
                || firstChar == "," || firstChar == "*" || firstChar == "%"
                || firstChar == "@" || firstChar == "`" || firstChar == "!" || firstChar == "&" || firstChar == "#" {
                throw YAMLParseError.syntaxError
            }
            if (firstChar == "-" || firstChar == ":" || firstChar == "?") && (col + 1 == currentLine.count || isHWS(currentLine[col + 1])) {
                throw YAMLParseError.syntaxError
            }

            func scanLineSegment(from startCol: Int) throws -> (text: String, hitComment: Bool) {
                let ln = lines[line]
                var i = startCol
                var lastNonWS = startCol
                var prevWS = false
                var hitComment = false
                while i < ln.count {
                    let ch = ln[i]
                    if ch == "#" && prevWS {
                        hitComment = true
                        break
                    }
                    if ch == ":" && (i + 1 == ln.count || isHWS(ln[i + 1])) {
                        throw YAMLParseError.syntaxError
                    }
                    if !isHWS(ch) {
                        lastNonWS = i + 1
                        prevWS = false
                    } else {
                        prevWS = true
                    }
                    i += 1
                }
                return (String(ln[startCol..<lastNonWS]), hitComment)
            }

            let (firstSeg, firstHitComment) = try scanLineSegment(from: col)
            var parts: [String] = [firstSeg]
            line += 1
            col = 0

            if !firstHitComment {
                var pendingBlankLines = 0
                while line < lines.count {
                    if startsWithDocStart(at: line) || startsWithDocEnd(at: line) {
                        break
                    }
                    let ln = lines[line]
                    let sp = leadingSpaces(of: line)
                    if sp == ln.count {
                        pendingBlankLines += 1
                        line += 1
                        col = 0
                        continue
                    }
                    if ln[sp] == "#" {
                        line += 1
                        col = 0
                        break
                    }
                    if ln[sp] == "\t" {
                        var j = sp
                        while j < ln.count && isHWS(ln[j]) { j += 1 }
                        if j == ln.count {
                            if sp > parentIndent {
                                pendingBlankLines += 1
                                line += 1
                                col = 0
                                continue
                            }
                            throw YAMLParseError.syntaxError
                        }
                        if ln[j] == "#" {
                            if sp > parentIndent {
                                line += 1
                                col = 0
                                break
                            }
                            throw YAMLParseError.syntaxError
                        }
                        if parentIndent >= 0 && sp > parentIndent {
                            let (seg, hitComment) = try scanLineSegment(from: j)
                            if pendingBlankLines > 0 {
                                parts.append(String(repeating: "\n", count: pendingBlankLines) + seg)
                                pendingBlankLines = 0
                            } else {
                                parts.append(" " + seg)
                            }
                            line += 1
                            col = 0
                            if hitComment { break }
                            continue
                        }
                        throw YAMLParseError.syntaxError
                    }
                    if sp <= parentIndent {
                        break
                    }
                    let (seg, hitComment) = try scanLineSegment(from: sp)
                    if pendingBlankLines > 0 {
                        parts.append(String(repeating: "\n", count: pendingBlankLines) + seg)
                        pendingBlankLines = 0
                    } else {
                        parts.append(" " + seg)
                    }
                    line += 1
                    col = 0
                    if hitComment { break }
                }
            }

            _ = startLine
            try recordNode()
            return .scalar(parts.joined(), style: .plain)
        }

        private mutating func parseBlockScalar(baseIndent: Int) throws -> YAMLNode {
            guard col < currentLine.count && (currentLine[col] == "|" || currentLine[col] == ">") else {
                throw YAMLParseError.syntaxError
            }
            let isLiteral = (currentLine[col] == "|")
            col += 1

            enum ChompMode { case clip, strip, keep }
            var chomp: ChompMode? = nil
            var explicitIndent: Int? = nil

            while col < currentLine.count {
                let c = currentLine[col]
                if c == "-" || c == "+" {
                    guard chomp == nil else { throw YAMLParseError.syntaxError }
                    chomp = (c == "-") ? .strip : .keep
                    col += 1
                } else if let ascii = c.asciiValue, ascii >= 0x31 && ascii <= 0x39 {
                    guard explicitIndent == nil else { throw YAMLParseError.syntaxError }
                    explicitIndent = Int(ascii - 0x30)
                    col += 1
                } else if isHWS(c) || c == "#" {
                    break
                } else {
                    throw YAMLParseError.syntaxError
                }
            }

            try consumeTrailingCommentAndEOL(requireSpaceBeforeHash: true)

            var contentIndent: Int? = explicitIndent.map { baseIndent + $0 }
            var maxBlankLeadingSpaces = 0
            var rawBodyLines: [(text: String, isBlank: Bool)] = []

            while line < lines.count {
                let ln = lines[line]
                let sp = leadingSpaces(of: line)

                if let cIndent = contentIndent {
                    if sp >= cIndent {
                        rawBodyLines.append((String(ln[cIndent...]), false))
                        line += 1
                        col = 0
                        continue
                    }
                    if sp == ln.count {
                        rawBodyLines.append(("", true))
                        line += 1
                        col = 0
                        continue
                    }
                    if ln[sp] == "\t" {
                        throw YAMLParseError.syntaxError
                    }
                    break
                } else {
                    if sp == ln.count {
                        maxBlankLeadingSpaces = max(maxBlankLeadingSpaces, sp)
                        rawBodyLines.append(("", true))
                        line += 1
                        col = 0
                        continue
                    }
                    if ln[sp] == "\t" {
                        throw YAMLParseError.syntaxError
                    }
                    if sp <= baseIndent {
                        break
                    }
                    if maxBlankLeadingSpaces > sp {
                        throw YAMLParseError.syntaxError
                    }
                    contentIndent = sp
                    rawBodyLines.append((String(ln[sp...]), false))
                    line += 1
                    col = 0
                }
            }

            var trailingBlankCount = 0
            while let last = rawBodyLines.last, last.isBlank {
                trailingBlankCount += 1
                rawBodyLines.removeLast()
            }

            let chompMode = chomp ?? .clip
            var result = ""
            if !rawBodyLines.isEmpty {
                if isLiteral {
                    result = rawBodyLines.map(\.text).joined(separator: "\n")
                } else {
                    var folded = ""
                    var prevWasNormal = false
                    for entry in rawBodyLines {
                        if entry.isBlank {
                            folded.append("\n")
                            prevWasNormal = false
                        } else {
                            let isMoreIndented = entry.text.first == " " || entry.text.first == "\t"
                            if prevWasNormal && !isMoreIndented {
                                folded.append(" ")
                            } else if !folded.isEmpty && !(prevWasNormal && !isMoreIndented) {
                                if folded.last != "\n" {
                                    folded.append("\n")
                                }
                            }
                            folded.append(entry.text)
                            prevWasNormal = !isMoreIndented
                        }
                    }
                    result = folded
                }
            }

            switch chompMode {
            case .strip:
                break
            case .clip:
                if !rawBodyLines.isEmpty {
                    result.append("\n")
                }
            case .keep:
                if !rawBodyLines.isEmpty {
                    result.append(String(repeating: "\n", count: 1 + trailingBlankCount))
                } else if trailingBlankCount > 0 {
                    result.append(String(repeating: "\n", count: trailingBlankCount))
                }
            }

            try recordNode()
            return .scalar(result, style: isLiteral ? .literalBlock : .foldedBlock)
        }
    }

    private static func collectYAMLScalarStrings(from node: YAMLNode, into output: inout [String]) {
        switch node {
        case .null:
            break
        case .scalar(let s, _):
            output.append(s)
        case .sequence(let items):
            for item in items {
                collectYAMLScalarStrings(from: item, into: &output)
            }
        case .mapping(let pairs):
            for (k, v) in pairs {
                collectYAMLScalarStrings(from: k, into: &output)
                collectYAMLScalarStrings(from: v, into: &output)
            }
        }
    }

    private static func extractStashYAML(from documents: [YAMLNode]) -> ParsedStashYAML {
        var out = ParsedStashYAML()
        guard let rootDoc = documents.first,
              case .mapping(let topEntries) = rootDoc else {
            return out
        }

        for (rawKeyNode, valNode) in topEntries {
            guard case .scalar(let rawKey, _) = rawKeyNode else { continue }
            let topKey = rawKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

            switch topKey {
            case "name":
                out.hasTopLevelName = true
            case "desc":
                out.hasTopLevelDesc = true
            case "http":
                out.hasMITMSection = false
                out.mitmTokens = []
                out.headerRewriteLines = []
                out.scriptEntries = []
                out.activeLines = []

                guard case .mapping(let httpEntries) = valNode else { continue }
                collectYAMLScalarStrings(from: valNode, into: &out.activeLines)

                for (httpKeyNode, httpValNode) in httpEntries {
                    guard case .scalar(let httpRawKey, _) = httpKeyNode else { continue }
                    let subKey = httpRawKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

                    switch subKey {
                    case "mitm":
                        out.hasMITMSection = false
                        out.mitmTokens = []
                        if case .sequence(let items) = httpValNode {
                            var tokens: [String] = []
                            var allScalars = true
                            for item in items {
                                if case .scalar(let tok, _) = item {
                                    let trimmed = tok.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                                    if !trimmed.isEmpty {
                                        tokens.append(trimmed)
                                    }
                                } else {
                                    allScalars = false
                                    break
                                }
                            }
                            if allScalars {
                                out.hasMITMSection = true
                                out.mitmTokens = tokens
                            }
                        }
                    case "header-rewrite":
                        out.headerRewriteLines = []
                        if case .sequence(let items) = httpValNode {
                            var lines: [String] = []
                            var allScalars = true
                            for item in items {
                                if case .scalar(let lineText, _) = item {
                                    lines.append(lineText.trimmingCharacters(in: .whitespacesAndNewlines))
                                } else {
                                    allScalars = false
                                    break
                                }
                            }
                            if allScalars {
                                out.headerRewriteLines = lines
                            }
                        }
                    case "script":
                        out.scriptEntries = []
                        if case .sequence(let items) = httpValNode {
                            var entries: [[(key: String, value: String)]] = []
                            for item in items {
                                if case .mapping(let props) = item {
                                    var pairs: [(key: String, value: String)] = []
                                    for (pk, pv) in props {
                                        guard case .scalar(let pkStr, _) = pk else { continue }
                                        switch pv {
                                        case .scalar(let pvStr, _):
                                            pairs.append((key: pkStr, value: pvStr))
                                        case .null:
                                            pairs.append((key: pkStr, value: ""))
                                        case .sequence, .mapping:
                                            pairs.append((key: pkStr, value: "<non-scalar>"))
                                        }
                                    }
                                    entries.append(pairs)
                                } else {
                                    entries.append([])
                                }
                            }
                            out.scriptEntries = entries
                        }
                    default:
                        break
                    }
                }
            case "script-providers":
                out.hasScriptProviderGuard = false
                out.payloadJS = ""

                guard case .mapping(let providers) = valNode else { continue }
                for (provKeyNode, provValNode) in providers {
                    guard case .scalar(let provRawKey, _) = provKeyNode else { continue }
                    let provName = provRawKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    guard provName == "brotli-response-guard" else { continue }

                    out.hasScriptProviderGuard = false
                    out.payloadJS = ""
                    guard case .mapping(let props) = provValNode else { continue }
                    out.hasScriptProviderGuard = true
                    for (pk, pv) in props {
                        guard case .scalar(let pkStr, _) = pk,
                              pkStr.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "payload" else {
                            continue
                        }
                        if case .scalar(let payloadStr, _) = pv {
                            out.payloadJS = payloadStr
                        } else {
                            out.payloadJS = ""
                        }
                    }
                }
            default:
                break
            }
        }

        return out
    }

    private static func parseStashYAML(content: String) -> ParsedStashYAML {
        do {
            var parser = try StashYAMLParser(content: content)
            let docs = try parser.parseStream()
            return extractStashYAML(from: docs)
        } catch {
            return ParsedStashYAML()
        }
    }

    private static func stripJSComments(_ js: String, maskNonKeyLiterals: Bool = false) -> String {
        struct NestingDepth: Equatable {
            let paren: Int
            let bracket: Int
            let brace: Int
            let template: Int
        }

        struct ParenState: Equatable {
            let allowsRegexAfterClose: Bool
            let nextBraceIsBlock: Bool
            let isFunctionParamList: Bool
            let functionIsAsync: Bool
            let functionIsGenerator: Bool
            let arrowIsAsync: Bool
            let methodIsAsync: Bool
            let methodIsGenerator: Bool
            let isForHeader: Bool
            var sawSemicolon: Bool
        }

        struct BracketState: Equatable {
            let methodIsAsync: Bool
            let methodIsGenerator: Bool
            let isComputedObjectKey: Bool
            var concatString: String?
            var concatExpectingPlus: Bool
        }

        struct BraceState: Equatable {
            let isStatementBody: Bool
            let isClassBody: Bool
            let allowsRegexAfterClose: Bool
            let isAsyncBody: Bool?
            let isGeneratorBody: Bool?
            var expectsObjectKey: Bool
            var propHasComputedKey: Bool
        }

        enum ContainerKind: Equatable {
            case paren
            case bracket
            case templateBrace
            case brace
        }

        struct PendingClassHeader {
            let isBlock: Bool
            let depth: NestingDepth
            var sawExtends: Bool = false
            var awaitingHeritageStart: Bool = false
        }

        let regexPrefixKeywords: Set<String> = [
            "return", "typeof", "void", "delete", "throw", "case",
            "in", "instanceof", "new", "else", "do"
        ]
        let asiRegexKeywords: Set<String> = [
            "return", "throw", "yield", "break", "continue", "debugger"
        ]
        let controlHeaderKeywords: Set<String> = [
            "if", "while", "for", "with"
        ]
        let blockHeaderKeywords: Set<String> = [
            "if", "while", "for", "with", "switch", "catch"
        ]
        let blockStatementKeywords: Set<String> = [
            "else", "do", "try", "finally", "catch", "static"
        ]
        let regexPrefixChars: Set<Character> = [
            ",", "=", "!", "&", "|", "~", "^", "+", "-", "*", "%", "<", ">"
        ]
        let isJSNewline: (Character) -> Bool = { ch in
            ch == "\n" || ch == "\r" || ch == "\r\n" || ch == "\u{2028}" || ch == "\u{2029}"
        }
        let isIdentStart: (Character) -> Bool = { ch in
            ch == "_" || ch == "$" || ch.isLetter
        }
        let isIdentPart: (Character) -> Bool = { ch in
            ch == "_" || ch == "$" || ch.isLetter || ch.isNumber
        }

        let chars = Array(js)

        func consumeJSUnicodeEscape(from index: Int) -> (scalar: UnicodeScalar?, nextIndex: Int)? {
            guard index + 1 < chars.count, chars[index] == "\\", chars[index + 1] == "u" else {
                return nil
            }
            var cur = index + 2
            if cur < chars.count, chars[cur] == "{" {
                cur += 1
                var value: UInt32 = 0
                var digits = 0
                while cur < chars.count, chars[cur] != "}" {
                    guard let d = chars[cur].hexDigitValue else { return nil }
                    value = value &* 16 &+ UInt32(d)
                    if value > 0x10FFFF { return nil }
                    digits += 1
                    cur += 1
                }
                guard digits > 0, cur < chars.count, chars[cur] == "}" else {
                    return nil
                }
                return (UnicodeScalar(value), cur + 1)
            } else {
                guard cur + 4 <= chars.count else { return nil }
                var value: UInt32 = 0
                for k in 0..<4 {
                    guard let d = chars[cur + k].hexDigitValue else { return nil }
                    value = (value << 4) | UInt32(d)
                }
                return (UnicodeScalar(value), cur + 4)
            }
        }

        func consumeDecodedStringEscape(from index: Int) -> (decoded: String, nextIndex: Int) {
            let nextIdx = index + 1
            guard nextIdx < chars.count else {
                return ("", chars.count)
            }
            let esc = chars[nextIdx]
            if isJSNewline(esc) {
                return ("", nextIdx + 1)
            }
            switch esc {
            case "x":
                if nextIdx + 2 < chars.count,
                   let hi = chars[nextIdx + 1].hexDigitValue,
                   let lo = chars[nextIdx + 2].hexDigitValue,
                   let scalar = UnicodeScalar((hi << 4) | lo) {
                    return (String(scalar), nextIdx + 3)
                }
                return ("x", nextIdx + 1)
            case "u":
                if let uEsc = consumeJSUnicodeEscape(from: index) {
                    if let scalar = uEsc.scalar {
                        return (String(scalar), uEsc.nextIndex)
                    }
                    return ("\u{FFFD}", uEsc.nextIndex)
                }
                return ("u", nextIdx + 1)
            case "n": return ("\n", nextIdx + 1)
            case "r": return ("\r", nextIdx + 1)
            case "t": return ("\t", nextIdx + 1)
            case "b": return ("\u{0008}", nextIdx + 1)
            case "f": return ("\u{000C}", nextIdx + 1)
            case "v": return ("\u{000B}", nextIdx + 1)
            case "0": return ("\0", nextIdx + 1)
            default: return (String(esc), nextIdx + 1)
            }
        }

        var out = ""
        out.reserveCapacity(chars.count)
        var i = 0
        var inSingle = false
        var inDouble = false
        var inTemplate = false
        var inRegex = false
        var inRegexCharClass = false
        var escaped = false
        var quotedLiteralBuffer = ""
        var templateBufferStack: [(buffer: String, hasInterpolation: Bool, concatString: String?, concatExpectingPlus: Bool)] = []
        var templateBraceConcatStack: [(concatString: String?, expectingPlus: Bool)] = []
        var canStartRegex = true
        var nextBraceIsBlock = true
        var pendingArrowBraceIsBlock = false
        var pendingArrowBodyIsAsync = false
        var pendingAsyncKeyword = false
        var pendingStarKeyword = false
        var pendingFunctionIsAsync = false
        var pendingFunctionIsGenerator = false
        var pendingMethodIsAsync = false
        var pendingMethodIsGenerator = false
        var pendingStringMethodIsAsync = false
        var pendingStringMethodIsGenerator = false
        var pendingArrowIdentIsAsync = false
        var pendingBraceFunctionIsAsync: Bool? = nil
        var pendingBraceFunctionIsGenerator: Bool? = nil
        var pendingBraceMethodIsAsync: Bool? = nil
        var pendingBraceMethodIsGenerator: Bool? = nil
        var pendingFunctionBraceIsBlock: Bool? = nil
        var pendingComputedKeyColon = false
        var pendingComputedKeyNormalizedName: String? = nil
        var pendingClassHeaders: [PendingClassHeader] = []
        var pendingTernaryDepths: [NestingDepth] = []
        var pendingBraceIsFunctionBody = false
        var pendingBreakOrContinueASI = false
        var prevTokenWasCloseParen = false
        var lastIdentBeforeWhitespace: String? = nil
        var prevWasDot = false
        var containerStack: [ContainerKind] = []
        var parenStack: [ParenState] = []
        var bracketStack: [BracketState] = []
        var braceStack: [BraceState] = []
        var conciseArrowAsyncScopes: [(depth: NestingDepth, isAsync: Bool)] = []
        var templateDepth = 0

        func currentDepth() -> NestingDepth {
            NestingDepth(
                paren: parenStack.count,
                bracket: bracketStack.count,
                brace: braceStack.count,
                template: templateDepth
            )
        }

        func isAtStatementBody() -> Bool {
            switch containerStack.last {
            case nil:
                return true
            case .brace:
                return braceStack.last?.isStatementBody ?? true
            case .paren, .bracket, .templateBrace:
                return false
            }
        }

        func isEnclosingMethodContainer() -> Bool {
            guard containerStack.last == .brace, let b = braceStack.last else {
                return false
            }
            return !b.isStatementBody || b.isClassBody
        }

        func isInsideAsyncFunction() -> Bool {
            var lastFuncBraceIdx = -1
            var lastFuncBraceAsync = false
            for (idx, b) in braceStack.enumerated() {
                if let isAsync = b.isAsyncBody {
                    lastFuncBraceIdx = idx + 1
                    lastFuncBraceAsync = isAsync
                }
            }
            if let concise = conciseArrowAsyncScopes.last,
               concise.depth.brace >= max(0, lastFuncBraceIdx) {
                return concise.isAsync
            }
            return lastFuncBraceIdx >= 0 ? lastFuncBraceAsync : false
        }

        func isInsideGeneratorFunction() -> Bool {
            var lastGenBraceIdx = -1
            var lastGenBraceGenerator = false
            for (idx, b) in braceStack.enumerated() {
                if let isGen = b.isGeneratorBody {
                    lastGenBraceIdx = idx + 1
                    lastGenBraceGenerator = isGen
                }
            }
            if let concise = conciseArrowAsyncScopes.last,
               concise.depth.brace >= max(0, lastGenBraceIdx) {
                return false
            }
            return lastGenBraceIdx >= 0 ? lastGenBraceGenerator : false
        }

        func isInsideComputedPropertyWrapper() -> Bool {
            for b in braceStack.reversed() {
                if b.isStatementBody {
                    return false
                }
                if b.propHasComputedKey {
                    return true
                }
            }
            return false
        }

        func clearObjectKeyExpectationOnToken() {
            if containerStack.last == .brace, !braceStack.isEmpty {
                braceStack[braceStack.count - 1].expectsObjectKey = false
            }
            pendingComputedKeyColon = false
            pendingComputedKeyNormalizedName = nil
        }

        func invalidateInnerConcatOnToken() {
            if containerStack.last == .bracket, !bracketStack.isEmpty {
                bracketStack[bracketStack.count - 1].concatString = nil
                bracketStack[bracketStack.count - 1].concatExpectingPlus = false
            } else if containerStack.last == .templateBrace, !templateBraceConcatStack.isEmpty {
                templateBraceConcatStack[templateBraceConcatStack.count - 1].concatString = nil
                templateBraceConcatStack[templateBraceConcatStack.count - 1].expectingPlus = false
            }
        }

        func recordStringInActiveConcat(_ val: String) {
            if containerStack.last == .bracket, !bracketStack.isEmpty {
                let idx = bracketStack.count - 1
                if !bracketStack[idx].concatExpectingPlus, let existing = bracketStack[idx].concatString {
                    bracketStack[idx].concatString = existing + val
                    bracketStack[idx].concatExpectingPlus = true
                } else {
                    bracketStack[idx].concatString = nil
                    bracketStack[idx].concatExpectingPlus = false
                }
            } else if containerStack.last == .templateBrace, !templateBraceConcatStack.isEmpty {
                let idx = templateBraceConcatStack.count - 1
                if !templateBraceConcatStack[idx].expectingPlus, let existing = templateBraceConcatStack[idx].concatString {
                    templateBraceConcatStack[idx].concatString = existing + val
                    templateBraceConcatStack[idx].expectingPlus = true
                } else {
                    templateBraceConcatStack[idx].concatString = nil
                    templateBraceConcatStack[idx].expectingPlus = false
                }
            }
        }

        func transitionArrowToConciseBodyIfNeeded(at depth: NestingDepth) {
            if pendingArrowBraceIsBlock {
                conciseArrowAsyncScopes.append((depth: depth, isAsync: pendingArrowBodyIsAsync))
                pendingArrowBraceIsBlock = false
                pendingArrowBodyIsAsync = false
            }
        }

        func clearAwaitingHeritageStart(at depth: NestingDepth) {
            if let lastIdx = pendingClassHeaders.indices.last,
               pendingClassHeaders[lastIdx].depth == depth,
               pendingClassHeaders[lastIdx].awaitingHeritageStart {
                pendingClassHeaders[lastIdx].awaitingHeritageStart = false
            }
        }

        func pruneClassHeaders(atOrDeeperThan depth: NestingDepth) {
            while let last = pendingClassHeaders.last,
                  last.depth.paren >= depth.paren
                      && last.depth.bracket >= depth.bracket
                      && last.depth.brace >= depth.brace
                      && last.depth.template >= depth.template {
                pendingClassHeaders.removeLast()
            }
        }

        func pruneStaleAtOrDeeper(than depth: NestingDepth) {
            pruneClassHeaders(atOrDeeperThan: depth)
            while let last = pendingTernaryDepths.last,
                  last.paren >= depth.paren
                      && last.bracket >= depth.bracket
                      && last.brace >= depth.brace
                      && last.template >= depth.template {
                pendingTernaryDepths.removeLast()
            }
            while let last = conciseArrowAsyncScopes.last,
                  last.depth.paren >= depth.paren
                      && last.depth.bracket >= depth.bracket
                      && last.depth.brace >= depth.brace
                      && last.depth.template >= depth.template {
                conciseArrowAsyncScopes.removeLast()
            }
        }

        func pruneDeeper(than depth: NestingDepth) {
            while let last = pendingClassHeaders.last,
                  last.depth.paren > depth.paren
                      || last.depth.bracket > depth.bracket
                      || last.depth.brace > depth.brace
                      || last.depth.template > depth.template {
                pendingClassHeaders.removeLast()
            }
            while let last = pendingTernaryDepths.last,
                  last.paren > depth.paren
                      || last.bracket > depth.bracket
                      || last.brace > depth.brace
                      || last.template > depth.template {
                pendingTernaryDepths.removeLast()
            }
            while let last = conciseArrowAsyncScopes.last,
                  last.depth.paren > depth.paren
                      || last.depth.bracket > depth.bracket
                      || last.depth.brace > depth.brace
                      || last.depth.template > depth.template {
                conciseArrowAsyncScopes.removeLast()
            }
        }

        func applyNewlineASI() {
            let lastIdent = lastIdentBeforeWhitespace ?? ""
            let isActiveASIKeyword: Bool
            if lastIdent == "yield" {
                isActiveASIKeyword = isInsideGeneratorFunction()
            } else {
                isActiveASIKeyword = asiRegexKeywords.contains(lastIdent)
            }
            let shouldPopConciseArrow = isActiveASIKeyword
                || pendingBreakOrContinueASI
                || !canStartRegex
            if isActiveASIKeyword || pendingBreakOrContinueASI {
                canStartRegex = true
                nextBraceIsBlock = true
            } else if !canStartRegex && isAtStatementBody() {
                nextBraceIsBlock = true
            }
            if shouldPopConciseArrow {
                let depth = currentDepth()
                while let last = conciseArrowAsyncScopes.last, last.depth == depth {
                    conciseArrowAsyncScopes.removeLast()
                }
            }
            pendingBreakOrContinueASI = false
            pendingAsyncKeyword = false
            pendingArrowIdentIsAsync = false
        }

        while i < chars.count {
            let ch = chars[i]
            if escaped {
                if maskNonKeyLiterals && inRegex {
                    // Masked RegExp literal interior
                } else if maskNonKeyLiterals && (inSingle || inDouble || inTemplate) {
                    if inTemplate {
                        if !templateBufferStack.isEmpty {
                            templateBufferStack[templateBufferStack.count - 1].buffer.append(ch)
                        }
                    } else {
                        quotedLiteralBuffer.append(ch)
                    }
                } else {
                    out.append(ch)
                }
                escaped = false
                i += 1
                continue
            }
            if (inSingle || inDouble || inTemplate || inRegex) && ch == "\\" {
                if maskNonKeyLiterals && inRegex {
                    escaped = true
                    i += 1
                    continue
                } else if maskNonKeyLiterals && (inSingle || inDouble || inTemplate) {
                    let (decoded, nextIdx) = consumeDecodedStringEscape(from: i)
                    if inTemplate {
                        if !templateBufferStack.isEmpty {
                            let idx = templateBufferStack.count - 1
                            templateBufferStack[idx].buffer.append(decoded)
                            if let existing = templateBufferStack[idx].concatString {
                                templateBufferStack[idx].concatString = existing + decoded
                            }
                        }
                    } else {
                        quotedLiteralBuffer.append(decoded)
                    }
                    i = nextIdx
                    continue
                } else {
                    out.append(ch)
                    escaped = true
                    i += 1
                    continue
                }
            }
            if inRegex {
                if ch == "[" {
                    inRegexCharClass = true
                } else if ch == "]" && inRegexCharClass {
                    inRegexCharClass = false
                } else if ch == "/" && !inRegexCharClass {
                    inRegex = false
                    canStartRegex = false
                    nextBraceIsBlock = false
                    pendingArrowBraceIsBlock = false
                    pendingArrowBodyIsAsync = false
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    if maskNonKeyLiterals {
                        out.append("/")
                    }
                } else if isJSNewline(ch) {
                    inRegex = false
                    inRegexCharClass = false
                    canStartRegex = true
                    nextBraceIsBlock = true
                    pendingArrowBraceIsBlock = false
                    pendingArrowBodyIsAsync = false
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    if maskNonKeyLiterals {
                        out.append(ch)
                    }
                }
                if !maskNonKeyLiterals {
                    out.append(ch)
                }
                i += 1
                continue
            }
            if !inDouble && !inTemplate && ch == "'" {
                if !inSingle {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearAwaitingHeritageStart(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    let inMethodContainer = isEnclosingMethodContainer()
                    pendingStringMethodIsAsync = inMethodContainer ? pendingAsyncKeyword : false
                    pendingStringMethodIsGenerator = inMethodContainer ? pendingStarKeyword : false
                    inSingle = true
                    if maskNonKeyLiterals {
                        quotedLiteralBuffer = ""
                    } else {
                        out.append(ch)
                    }
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                } else {
                    inSingle = false
                    canStartRegex = false
                    nextBraceIsBlock = false
                    if maskNonKeyLiterals {
                        recordStringInActiveConcat(quotedLiteralBuffer)
                        if quotedLiteralBuffer == "status" || quotedLiteralBuffer == "response" || quotedLiteralBuffer == "body" {
                            out.append("'")
                            out.append(quotedLiteralBuffer)
                            out.append("'")
                        } else {
                            out.append("\"\"")
                        }
                        quotedLiteralBuffer = ""
                    } else {
                        out.append(ch)
                    }
                    pendingMethodIsAsync = pendingStringMethodIsAsync
                    pendingMethodIsGenerator = pendingStringMethodIsGenerator
                    pendingStringMethodIsAsync = false
                    pendingStringMethodIsGenerator = false
                }
                lastIdentBeforeWhitespace = nil
                prevWasDot = false
                pendingFunctionBraceIsBlock = nil
                pendingBraceIsFunctionBody = false
                pendingBraceFunctionIsAsync = nil
                pendingBraceFunctionIsGenerator = nil
                pendingBraceMethodIsAsync = nil
                pendingBraceMethodIsGenerator = nil
                pendingAsyncKeyword = false
                pendingStarKeyword = false
                pendingFunctionIsAsync = false
                pendingFunctionIsGenerator = false
                pendingArrowIdentIsAsync = false
                pendingBreakOrContinueASI = false
                prevTokenWasCloseParen = false
                i += 1
                continue
            }
            if !inSingle && !inTemplate && ch == "\"" {
                if !inDouble {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearAwaitingHeritageStart(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    let inMethodContainer = isEnclosingMethodContainer()
                    pendingStringMethodIsAsync = inMethodContainer ? pendingAsyncKeyword : false
                    pendingStringMethodIsGenerator = inMethodContainer ? pendingStarKeyword : false
                    inDouble = true
                    if maskNonKeyLiterals {
                        quotedLiteralBuffer = ""
                    } else {
                        out.append(ch)
                    }
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                } else {
                    inDouble = false
                    canStartRegex = false
                    nextBraceIsBlock = false
                    if maskNonKeyLiterals {
                        recordStringInActiveConcat(quotedLiteralBuffer)
                        if quotedLiteralBuffer == "status" || quotedLiteralBuffer == "response" || quotedLiteralBuffer == "body" {
                            out.append("\"")
                            out.append(quotedLiteralBuffer)
                            out.append("\"")
                        } else {
                            out.append("\"\"")
                        }
                        quotedLiteralBuffer = ""
                    } else {
                        out.append(ch)
                    }
                    pendingMethodIsAsync = pendingStringMethodIsAsync
                    pendingMethodIsGenerator = pendingStringMethodIsGenerator
                    pendingStringMethodIsAsync = false
                    pendingStringMethodIsGenerator = false
                }
                lastIdentBeforeWhitespace = nil
                prevWasDot = false
                pendingFunctionBraceIsBlock = nil
                pendingBraceIsFunctionBody = false
                pendingBraceFunctionIsAsync = nil
                pendingBraceFunctionIsGenerator = nil
                pendingBraceMethodIsAsync = nil
                pendingBraceMethodIsGenerator = nil
                pendingAsyncKeyword = false
                pendingStarKeyword = false
                pendingFunctionIsAsync = false
                pendingFunctionIsGenerator = false
                pendingArrowIdentIsAsync = false
                pendingBreakOrContinueASI = false
                prevTokenWasCloseParen = false
                i += 1
                continue
            }
            if !inSingle && !inDouble && ch == "`" {
                if !inTemplate {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearAwaitingHeritageStart(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    inTemplate = true
                    if maskNonKeyLiterals {
                        let allowConcat = (containerStack.last == .bracket && bracketStack.last?.isComputedObjectKey == true && !(bracketStack.last?.concatExpectingPlus ?? true))
                            || (containerStack.last == .templateBrace && templateBraceConcatStack.last?.concatString != nil && !(templateBraceConcatStack.last?.expectingPlus ?? true))
                        templateBufferStack.append((buffer: "", hasInterpolation: false, concatString: allowConcat ? "" : nil, concatExpectingPlus: false))
                    } else {
                        out.append(ch)
                    }
                } else {
                    inTemplate = false
                    canStartRegex = false
                    nextBraceIsBlock = false
                    if maskNonKeyLiterals {
                        let entry = templateBufferStack.popLast() ?? (buffer: "", hasInterpolation: true, concatString: nil, concatExpectingPlus: false)
                        if !entry.hasInterpolation {
                            recordStringInActiveConcat(entry.buffer)
                        } else if !entry.concatExpectingPlus, let c = entry.concatString {
                            recordStringInActiveConcat(c)
                        } else {
                            invalidateInnerConcatOnToken()
                        }
                        if !entry.hasInterpolation && (entry.buffer == "status" || entry.buffer == "response" || entry.buffer == "body") {
                            out.append("`")
                            out.append(entry.buffer)
                            out.append("`")
                        } else {
                            out.append("\"\"")
                        }
                    } else {
                        out.append(ch)
                    }
                }
                lastIdentBeforeWhitespace = nil
                prevWasDot = false
                pendingFunctionBraceIsBlock = nil
                pendingBraceIsFunctionBody = false
                pendingBraceFunctionIsAsync = nil
                pendingBraceFunctionIsGenerator = nil
                pendingBraceMethodIsAsync = nil
                pendingBraceMethodIsGenerator = nil
                pendingAsyncKeyword = false
                pendingStarKeyword = false
                pendingFunctionIsAsync = false
                pendingFunctionIsGenerator = false
                pendingMethodIsAsync = false
                pendingMethodIsGenerator = false
                pendingArrowIdentIsAsync = false
                pendingBreakOrContinueASI = false
                prevTokenWasCloseParen = false
                i += 1
                continue
            }
            if inTemplate && ch == "$" && i + 1 < chars.count && chars[i + 1] == "{" {
                containerStack.append(.templateBrace)
                templateDepth += 1
                inTemplate = false
                canStartRegex = true
                nextBraceIsBlock = false
                pendingArrowBraceIsBlock = false
                pendingArrowBodyIsAsync = false
                pendingAsyncKeyword = false
                pendingStarKeyword = false
                pendingFunctionIsAsync = false
                pendingFunctionIsGenerator = false
                pendingMethodIsAsync = false
                pendingMethodIsGenerator = false
                pendingArrowIdentIsAsync = false
                pendingBraceFunctionIsAsync = nil
                pendingBraceFunctionIsGenerator = nil
                pendingBraceMethodIsAsync = nil
                pendingBraceMethodIsGenerator = nil
                lastIdentBeforeWhitespace = nil
                prevWasDot = false
                pendingFunctionBraceIsBlock = nil
                pendingBreakOrContinueASI = false
                prevTokenWasCloseParen = false
                if maskNonKeyLiterals {
                    let allowExprConcat: Bool
                    if !templateBufferStack.isEmpty {
                        templateBufferStack[templateBufferStack.count - 1].hasInterpolation = true
                        templateBufferStack[templateBufferStack.count - 1].buffer = ""
                        allowExprConcat = templateBufferStack[templateBufferStack.count - 1].concatString != nil
                    } else {
                        allowExprConcat = false
                    }
                    templateBraceConcatStack.append((concatString: allowExprConcat ? "" : nil, expectingPlus: false))
                    out.append("\"\" ${")
                } else {
                    templateBraceConcatStack.append((concatString: nil, expectingPlus: false))
                    out.append("${")
                }
                i += 2
                continue
            }
            if !inSingle && !inDouble && !inTemplate {
                if ch == "/" && i + 1 < chars.count {
                    let next = chars[i + 1]
                    if next == "/" {
                        i += 2
                        while i < chars.count && !isJSNewline(chars[i]) {
                            i += 1
                        }
                        continue
                    } else if next == "*" {
                        i += 2
                        var sawNewline = false
                        while i + 1 < chars.count && !(chars[i] == "*" && chars[i + 1] == "/") {
                            if isJSNewline(chars[i]) {
                                sawNewline = true
                            }
                            i += 1
                        }
                        if i + 1 < chars.count {
                            i += 2
                        } else {
                            if i < chars.count && isJSNewline(chars[i]) {
                                sawNewline = true
                            }
                            i = chars.count
                        }
                        if sawNewline {
                            applyNewlineASI()
                            out.append("\n")
                        } else {
                            out.append(" ")
                        }
                        continue
                    } else if canStartRegex && !isJSNewline(next) {
                        transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                        clearAwaitingHeritageStart(at: currentDepth())
                        clearObjectKeyExpectationOnToken()
                        invalidateInnerConcatOnToken()
                        inRegex = true
                        inRegexCharClass = false
                        lastIdentBeforeWhitespace = nil
                        prevWasDot = false
                        pendingFunctionBraceIsBlock = nil
                        pendingBraceIsFunctionBody = false
                        pendingBraceFunctionIsAsync = nil
                        pendingBraceFunctionIsGenerator = nil
                        pendingBraceMethodIsAsync = nil
                        pendingBraceMethodIsGenerator = nil
                        pendingAsyncKeyword = false
                        pendingStarKeyword = false
                        pendingFunctionIsAsync = false
                        pendingFunctionIsGenerator = false
                        pendingMethodIsAsync = false
                        pendingMethodIsGenerator = false
                        pendingArrowIdentIsAsync = false
                        pendingBreakOrContinueASI = false
                        prevTokenWasCloseParen = false
                        out.append(ch)
                        i += 1
                        continue
                    }
                }

                if (ch == "+" || ch == "-") && i + 1 < chars.count && chars[i + 1] == ch {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    out.append(ch)
                    out.append(ch)
                    canStartRegex = false
                    nextBraceIsBlock = false
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    pruneClassHeaders(atOrDeeperThan: currentDepth())
                    i += 2
                    continue
                }

                if ch == "=" && i + 1 < chars.count && chars[i + 1] == ">" {
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    out.append("=>")
                    canStartRegex = true
                    nextBraceIsBlock = false
                    pendingArrowBraceIsBlock = true
                    pendingArrowBodyIsAsync = pendingArrowIdentIsAsync
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingFunctionBraceIsBlock = nil
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    pruneClassHeaders(atOrDeeperThan: currentDepth())
                    i += 2
                    continue
                }

                if ch == "#" && i + 1 < chars.count {
                    var nextIsIdentStart = isIdentStart(chars[i + 1])
                    var privIdent = "#"
                    var rawPrivIdent = "#"
                    var scanIdx = i + 1
                    if !nextIsIdentStart,
                       chars[i + 1] == "\\",
                       let esc = consumeJSUnicodeEscape(from: i + 1),
                       let scalar = esc.scalar,
                       isIdentStart(Character(scalar)) {
                        nextIsIdentStart = true
                        privIdent.append(Character(scalar))
                        rawPrivIdent.append(contentsOf: chars[(i + 1)..<esc.nextIndex])
                        scanIdx = esc.nextIndex
                    } else if nextIsIdentStart {
                        privIdent.append(chars[i + 1])
                        rawPrivIdent.append(chars[i + 1])
                        scanIdx = i + 2
                    }
                    if nextIsIdentStart {
                        i = scanIdx
                        while i < chars.count {
                            if isIdentPart(chars[i]) {
                                privIdent.append(chars[i])
                                rawPrivIdent.append(chars[i])
                                i += 1
                            } else if chars[i] == "\\",
                                      let esc = consumeJSUnicodeEscape(from: i),
                                      let scalar = esc.scalar,
                                      isIdentPart(Character(scalar)) {
                                privIdent.append(Character(scalar))
                                rawPrivIdent.append(contentsOf: chars[i..<esc.nextIndex])
                                i = esc.nextIndex
                            } else {
                                break
                            }
                        }
                        transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                        clearAwaitingHeritageStart(at: currentDepth())
                        clearObjectKeyExpectationOnToken()
                        invalidateInnerConcatOnToken()
                        out.append(maskNonKeyLiterals ? privIdent : rawPrivIdent)
                        let inMethodContainer = isEnclosingMethodContainer()
                        let wasPendingAsync = pendingAsyncKeyword
                        let wasPendingStar = pendingStarKeyword
                        canStartRegex = false
                        nextBraceIsBlock = false
                        lastIdentBeforeWhitespace = nil
                        prevWasDot = false
                        pendingFunctionBraceIsBlock = nil
                        pendingBraceIsFunctionBody = false
                        pendingBraceFunctionIsAsync = nil
                        pendingBraceFunctionIsGenerator = nil
                        pendingBraceMethodIsAsync = nil
                        pendingBraceMethodIsGenerator = nil
                        pendingAsyncKeyword = false
                        pendingStarKeyword = false
                        pendingFunctionIsAsync = false
                        pendingFunctionIsGenerator = false
                        pendingMethodIsAsync = inMethodContainer ? wasPendingAsync : false
                        pendingMethodIsGenerator = inMethodContainer ? wasPendingStar : false
                        pendingArrowIdentIsAsync = false
                        pendingBreakOrContinueASI = false
                        prevTokenWasCloseParen = false
                        continue
                    }
                }

                var startsIdent = isIdentStart(ch)
                var ident = ""
                var rawIdent = ""
                var identNextIdx = i
                if startsIdent {
                    ident = String(ch)
                    rawIdent = String(ch)
                    identNextIdx = i + 1
                } else if ch == "\\",
                          let esc = consumeJSUnicodeEscape(from: i),
                          let scalar = esc.scalar,
                          isIdentStart(Character(scalar)) {
                    startsIdent = true
                    ident = String(Character(scalar))
                    rawIdent = String(chars[i..<esc.nextIndex])
                    identNextIdx = esc.nextIndex
                }
                if startsIdent {
                    i = identNextIdx
                    while i < chars.count {
                        if isIdentPart(chars[i]) {
                            ident.append(chars[i])
                            rawIdent.append(chars[i])
                            i += 1
                        } else if chars[i] == "\\",
                                  let esc = consumeJSUnicodeEscape(from: i),
                                  let scalar = esc.scalar,
                                  isIdentPart(Character(scalar)) {
                            ident.append(Character(scalar))
                            rawIdent.append(contentsOf: chars[i..<esc.nextIndex])
                            i = esc.nextIndex
                        } else {
                            break
                        }
                    }
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    out.append(maskNonKeyLiterals ? ident : rawIdent)
                    let wasDot = prevWasDot
                    prevWasDot = false
                    prevTokenWasCloseParen = false
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    let prevIdent = lastIdentBeforeWhitespace
                    let isForAwait = !wasDot && ident == "await" && prevIdent == "for"
                    let isBreakOrContinueLabel = !wasDot && pendingBreakOrContinueASI && (prevIdent == "break" || prevIdent == "continue")
                    lastIdentBeforeWhitespace = wasDot ? nil : (isForAwait ? "for" : ident)
                    if !wasDot {
                        let depth = currentDepth()
                        if pendingFunctionBraceIsBlock != nil {
                            canStartRegex = false
                            pendingBreakOrContinueASI = false
                            pendingAsyncKeyword = false
                            pendingStarKeyword = false
                            pendingMethodIsAsync = false
                            pendingMethodIsGenerator = false
                            pendingArrowIdentIsAsync = false
                            clearAwaitingHeritageStart(at: depth)
                        } else {
                            let isForOfOperator = ident == "of"
                                && containerStack.last == .paren
                                && (parenStack.last?.isForHeader ?? false)
                                && !(parenStack.last?.sawSemicolon ?? true)
                                && !canStartRegex
                                && prevIdent != "var"
                                && prevIdent != "let"
                                && prevIdent != "const"
                            let isContextualRegexPrefix = (ident == "await" && isInsideAsyncFunction())
                                || (ident == "yield" && isInsideGeneratorFunction())
                                || isForOfOperator
                            canStartRegex = regexPrefixKeywords.contains(ident) || isContextualRegexPrefix
                            if ident == "break" || ident == "continue" {
                                pendingBreakOrContinueASI = true
                            } else if !isBreakOrContinueLabel {
                                pendingBreakOrContinueASI = false
                            }
                            if ident == "function" {
                                pendingFunctionBraceIsBlock = nextBraceIsBlock
                                pendingFunctionIsAsync = pendingAsyncKeyword
                                pendingFunctionIsGenerator = false
                                pendingAsyncKeyword = false
                                pendingStarKeyword = false
                                pendingMethodIsAsync = false
                                pendingMethodIsGenerator = false
                                pendingArrowIdentIsAsync = false
                                clearAwaitingHeritageStart(at: depth)
                            } else if ident == "async" && !pendingAsyncKeyword && !pendingStarKeyword {
                                pendingAsyncKeyword = true
                                pendingMethodIsAsync = false
                                pendingMethodIsGenerator = false
                                pendingArrowIdentIsAsync = false
                                pendingFunctionIsAsync = false
                                pendingFunctionIsGenerator = false
                                clearAwaitingHeritageStart(at: depth)
                            } else {
                                let wasPendingAsync = pendingAsyncKeyword
                                let wasPendingStar = pendingStarKeyword
                                pendingAsyncKeyword = false
                                pendingStarKeyword = false
                                pendingFunctionIsAsync = false
                                pendingFunctionIsGenerator = false
                                if ident == "class" {
                                    if isEnclosingMethodContainer() && (wasPendingAsync || wasPendingStar) {
                                        pendingMethodIsAsync = wasPendingAsync
                                        pendingMethodIsGenerator = wasPendingStar
                                        pendingArrowIdentIsAsync = false
                                        clearAwaitingHeritageStart(at: depth)
                                        pendingFunctionBraceIsBlock = nil
                                    } else {
                                        pendingMethodIsAsync = false
                                        pendingMethodIsGenerator = false
                                        pendingArrowIdentIsAsync = false
                                        clearAwaitingHeritageStart(at: depth)
                                        pendingClassHeaders.append(PendingClassHeader(isBlock: nextBraceIsBlock, depth: depth))
                                        pendingFunctionBraceIsBlock = nil
                                    }
                                } else if ident == "extends",
                                          let lastIdx = pendingClassHeaders.indices.last,
                                          pendingClassHeaders[lastIdx].depth == depth,
                                          !pendingClassHeaders[lastIdx].sawExtends {
                                    pendingMethodIsAsync = false
                                    pendingMethodIsGenerator = false
                                    pendingArrowIdentIsAsync = false
                                    pendingClassHeaders[lastIdx].sawExtends = true
                                    pendingClassHeaders[lastIdx].awaitingHeritageStart = true
                                    canStartRegex = true
                                    nextBraceIsBlock = false
                                    pendingFunctionBraceIsBlock = nil
                                } else {
                                    pendingMethodIsAsync = wasPendingAsync
                                    pendingMethodIsGenerator = wasPendingStar
                                    pendingArrowIdentIsAsync = wasPendingAsync
                                    let canPrefixHeritageObject = ident == "new" || (ident == "await" && isInsideAsyncFunction())
                                    let isHeritagePrefixKeyword = canPrefixHeritageObject
                                        && pendingClassHeaders.last?.depth == depth
                                        && (pendingClassHeaders.last?.awaitingHeritageStart ?? false)
                                    if !isHeritagePrefixKeyword {
                                        clearAwaitingHeritageStart(at: depth)
                                    }
                                    if blockStatementKeywords.contains(ident) {
                                        nextBraceIsBlock = true
                                        pendingFunctionBraceIsBlock = nil
                                    } else if isForAwait {
                                        // Preserve nextBraceIsBlock across for await
                                    } else if regexPrefixKeywords.contains(ident) || isContextualRegexPrefix {
                                        nextBraceIsBlock = false
                                        pendingFunctionBraceIsBlock = nil
                                    }
                                }
                            }
                        }
                    } else {
                        clearAwaitingHeritageStart(at: currentDepth())
                        canStartRegex = false
                        pendingBreakOrContinueASI = false
                        pendingFunctionBraceIsBlock = nil
                        pendingAsyncKeyword = false
                        pendingStarKeyword = false
                        pendingFunctionIsAsync = false
                        pendingFunctionIsGenerator = false
                        pendingMethodIsAsync = false
                        pendingMethodIsGenerator = false
                        pendingArrowIdentIsAsync = false
                    }
                    continue
                }
                if ch.isNumber {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    out.append(ch)
                    i += 1
                    while i < chars.count && (chars[i].isNumber || chars[i] == "." || chars[i] == "x" || chars[i] == "X" || (chars[i] >= "a" && chars[i] <= "f") || (chars[i] >= "A" && chars[i] <= "F") || chars[i] == "_") {
                        out.append(chars[i])
                        i += 1
                    }
                    clearAwaitingHeritageStart(at: currentDepth())
                    let inMethodContainer = isEnclosingMethodContainer()
                    let methodAsync = inMethodContainer ? pendingAsyncKeyword : false
                    let methodGenerator = inMethodContainer ? pendingStarKeyword : false
                    canStartRegex = false
                    nextBraceIsBlock = false
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = methodAsync
                    pendingMethodIsGenerator = methodGenerator
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    continue
                }
                if isJSNewline(ch) {
                    applyNewlineASI()
                } else if ch == "(" {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearAwaitingHeritageStart(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    let prevIdent = lastIdentBeforeWhitespace ?? ""
                    if prevIdent == "class" {
                        pruneClassHeaders(atOrDeeperThan: currentDepth())
                    }
                    let arrowAsync = pendingAsyncKeyword
                    let methodAsync = pendingMethodIsAsync
                    let methodGen = pendingMethodIsGenerator
                    let fnAsync = pendingFunctionIsAsync
                    let fnGen = pendingFunctionIsGenerator
                    let isForHdr = prevIdent == "for"
                    containerStack.append(.paren)
                    if let fnIsBlock = pendingFunctionBraceIsBlock {
                        parenStack.append(ParenState(
                            allowsRegexAfterClose: controlHeaderKeywords.contains(prevIdent),
                            nextBraceIsBlock: fnIsBlock,
                            isFunctionParamList: true,
                            functionIsAsync: fnAsync,
                            functionIsGenerator: fnGen,
                            arrowIsAsync: arrowAsync,
                            methodIsAsync: methodAsync,
                            methodIsGenerator: methodGen,
                            isForHeader: false,
                            sawSemicolon: false
                        ))
                        pendingFunctionBraceIsBlock = nil
                    } else {
                        parenStack.append(ParenState(
                            allowsRegexAfterClose: controlHeaderKeywords.contains(prevIdent),
                            nextBraceIsBlock: blockHeaderKeywords.contains(prevIdent),
                            isFunctionParamList: false,
                            functionIsAsync: false,
                            functionIsGenerator: false,
                            arrowIsAsync: arrowAsync,
                            methodIsAsync: methodAsync,
                            methodIsGenerator: methodGen,
                            isForHeader: isForHdr,
                            sawSemicolon: false
                        ))
                    }
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    canStartRegex = true
                    nextBraceIsBlock = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                } else if ch == ")" {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    if containerStack.last == .paren {
                        containerStack.removeLast()
                        let p = parenStack.popLast()
                        canStartRegex = p?.allowsRegexAfterClose ?? false
                        nextBraceIsBlock = p?.nextBraceIsBlock ?? false
                        let isFnParam = p?.isFunctionParamList ?? false
                        pendingBraceIsFunctionBody = isFnParam
                        pendingBraceFunctionIsAsync = isFnParam ? (p?.functionIsAsync ?? false) : nil
                        pendingBraceFunctionIsGenerator = isFnParam ? (p?.functionIsGenerator ?? false) : nil
                        pendingArrowIdentIsAsync = p?.arrowIsAsync ?? false
                        pendingBraceMethodIsAsync = p?.methodIsAsync ?? false
                        pendingBraceMethodIsGenerator = p?.methodIsGenerator ?? false
                    } else {
                        canStartRegex = false
                        nextBraceIsBlock = false
                        pendingBraceIsFunctionBody = false
                        pendingBraceFunctionIsAsync = nil
                        pendingBraceFunctionIsGenerator = nil
                        pendingArrowIdentIsAsync = false
                        pendingBraceMethodIsAsync = nil
                        pendingBraceMethodIsGenerator = nil
                    }
                    invalidateInnerConcatOnToken()
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = true
                    pruneDeeper(than: currentDepth())
                } else if ch == "{" {
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    let depth = currentDepth()
                    let matchedClassBlock: Bool?
                    var isHeritageObjectLiteral = false
                    if !pendingBraceIsFunctionBody,
                       let lastIdx = pendingClassHeaders.indices.last,
                       pendingClassHeaders[lastIdx].depth == depth {
                        if pendingClassHeaders[lastIdx].awaitingHeritageStart {
                            pendingClassHeaders[lastIdx].awaitingHeritageStart = false
                            matchedClassBlock = nil
                            isHeritageObjectLiteral = true
                        } else {
                            let lastClass = pendingClassHeaders.removeLast()
                            matchedClassBlock = lastClass.isBlock
                        }
                    } else {
                        matchedClassBlock = nil
                    }
                    let isClassBody = matchedClassBlock != nil
                    let isArrowBlockBody = !isHeritageObjectLiteral && !isClassBody && !pendingBraceIsFunctionBody && pendingArrowBraceIsBlock
                    let effectiveNextBraceIsBlock = nextBraceIsBlock || pendingArrowBraceIsBlock
                    pendingArrowBraceIsBlock = false
                    let arrowIsAsync = pendingArrowBodyIsAsync
                    pendingArrowBodyIsAsync = false
                    let enclosingIsClassBody = (containerStack.last == .brace) && (braceStack.last?.isClassBody ?? false)
                    let isMethodBody = !isHeritageObjectLiteral && !isClassBody && !pendingBraceIsFunctionBody && !isArrowBlockBody && prevTokenWasCloseParen && isEnclosingMethodContainer()
                    let isClassMethod = isMethodBody && enclosingIsClassBody
                    let braceIsBlock = isHeritageObjectLiteral ? false : (isClassMethod ? true : (matchedClassBlock ?? effectiveNextBraceIsBlock))
                    let isStatementContainer = isHeritageObjectLiteral ? false : (isClassBody || pendingBraceIsFunctionBody || braceIsBlock || prevTokenWasCloseParen)
                    let braceIsAsyncBody: Bool?
                    let braceIsGeneratorBody: Bool?
                    if pendingBraceIsFunctionBody {
                        braceIsAsyncBody = pendingBraceFunctionIsAsync ?? false
                        braceIsGeneratorBody = pendingBraceFunctionIsGenerator ?? false
                    } else if isArrowBlockBody {
                        braceIsAsyncBody = arrowIsAsync
                        braceIsGeneratorBody = false
                    } else if isMethodBody {
                        braceIsAsyncBody = pendingBraceMethodIsAsync ?? false
                        braceIsGeneratorBody = pendingBraceMethodIsGenerator ?? false
                    } else {
                        braceIsAsyncBody = nil
                        braceIsGeneratorBody = nil
                    }
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    containerStack.append(.brace)
                    braceStack.append(BraceState(
                        isStatementBody: isStatementContainer,
                        isClassBody: isClassBody,
                        allowsRegexAfterClose: braceIsBlock,
                        isAsyncBody: braceIsAsyncBody,
                        isGeneratorBody: braceIsGeneratorBody,
                        expectsObjectKey: !isStatementContainer,
                        propHasComputedKey: false
                    ))
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    canStartRegex = true
                    nextBraceIsBlock = isStatementContainer
                } else if ch == "}" {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    pendingComputedKeyColon = false
                    pendingComputedKeyNormalizedName = nil
                    if containerStack.last == .templateBrace {
                        containerStack.removeLast()
                        if templateDepth > 0 { templateDepth -= 1 }
                        let exprConcat = templateBraceConcatStack.popLast()
                        if maskNonKeyLiterals, !templateBufferStack.isEmpty {
                            if let exprConcat, exprConcat.expectingPlus, let exprStr = exprConcat.concatString,
                               let existing = templateBufferStack[templateBufferStack.count - 1].concatString {
                                templateBufferStack[templateBufferStack.count - 1].concatString = existing + exprStr
                            } else {
                                templateBufferStack[templateBufferStack.count - 1].concatString = nil
                            }
                        }
                        inTemplate = true
                        canStartRegex = false
                        nextBraceIsBlock = false
                        out.append("}")
                        pruneDeeper(than: currentDepth())
                        i += 1
                        continue
                    } else if containerStack.last == .brace {
                        containerStack.removeLast()
                        let allowsRegex = braceStack.popLast()?.allowsRegexAfterClose ?? false
                        canStartRegex = allowsRegex
                        nextBraceIsBlock = allowsRegex
                        clearObjectKeyExpectationOnToken()
                        invalidateInnerConcatOnToken()
                    } else {
                        canStartRegex = false
                        nextBraceIsBlock = false
                    }
                    pruneDeeper(than: currentDepth())
                } else if ch == ";" {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    if containerStack.last == .paren, !parenStack.isEmpty {
                        parenStack[parenStack.count - 1].sawSemicolon = true
                    }
                    canStartRegex = true
                    nextBraceIsBlock = true
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    pruneStaleAtOrDeeper(than: currentDepth())
                } else if ch == "[" {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearAwaitingHeritageStart(at: currentDepth())
                    let isComputedObjKey = containerStack.last == .brace
                        && !(braceStack.last?.isStatementBody ?? true)
                        && (braceStack.last?.expectsObjectKey ?? false)
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    containerStack.append(.bracket)
                    bracketStack.append(BracketState(
                        methodIsAsync: pendingAsyncKeyword,
                        methodIsGenerator: pendingStarKeyword,
                        isComputedObjectKey: isComputedObjKey,
                        concatString: (maskNonKeyLiterals && isComputedObjKey) ? "" : nil,
                        concatExpectingPlus: false
                    ))
                    canStartRegex = true
                    nextBraceIsBlock = false
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                } else if ch == "]" {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    if containerStack.last == .bracket {
                        containerStack.removeLast()
                        let bState = bracketStack.popLast()
                        pendingMethodIsAsync = bState?.methodIsAsync ?? false
                        pendingMethodIsGenerator = bState?.methodIsGenerator ?? false
                        if let bState, bState.isComputedObjectKey {
                            pendingComputedKeyColon = true
                            if maskNonKeyLiterals,
                               bState.concatExpectingPlus,
                               let folded = bState.concatString,
                               (folded == "response" || folded == "body") {
                                pendingComputedKeyNormalizedName = folded
                            }
                        }
                    } else {
                        pendingMethodIsAsync = false
                        pendingMethodIsGenerator = false
                    }
                    invalidateInnerConcatOnToken()
                    canStartRegex = false
                    nextBraceIsBlock = false
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    pruneDeeper(than: currentDepth())
                } else if ch == "?" {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    if i + 1 < chars.count && chars[i + 1] == "?" {
                        out.append("??")
                        canStartRegex = true
                        nextBraceIsBlock = false
                        lastIdentBeforeWhitespace = nil
                        prevWasDot = false
                        pendingFunctionBraceIsBlock = nil
                        pendingBraceIsFunctionBody = false
                        pendingBraceFunctionIsAsync = nil
                        pendingBraceFunctionIsGenerator = nil
                        pendingBraceMethodIsAsync = nil
                        pendingBraceMethodIsGenerator = nil
                        pendingAsyncKeyword = false
                        pendingStarKeyword = false
                        pendingFunctionIsAsync = false
                        pendingFunctionIsGenerator = false
                        pendingMethodIsAsync = false
                        pendingMethodIsGenerator = false
                        pendingArrowIdentIsAsync = false
                        pendingBreakOrContinueASI = false
                        prevTokenWasCloseParen = false
                        pruneClassHeaders(atOrDeeperThan: currentDepth())
                        i += 2
                        continue
                    } else if i + 1 < chars.count && chars[i + 1] == "."
                        && !(i + 2 < chars.count && chars[i + 2] >= "0" && chars[i + 2] <= "9") {
                        clearAwaitingHeritageStart(at: currentDepth())
                        out.append("?.")
                        canStartRegex = false
                        nextBraceIsBlock = false
                        lastIdentBeforeWhitespace = nil
                        prevWasDot = true
                        pendingFunctionBraceIsBlock = nil
                        pendingBraceIsFunctionBody = false
                        pendingBraceFunctionIsAsync = nil
                        pendingBraceFunctionIsGenerator = nil
                        pendingBraceMethodIsAsync = nil
                        pendingBraceMethodIsGenerator = nil
                        pendingAsyncKeyword = false
                        pendingStarKeyword = false
                        pendingFunctionIsAsync = false
                        pendingFunctionIsGenerator = false
                        pendingMethodIsAsync = false
                        pendingMethodIsGenerator = false
                        pendingArrowIdentIsAsync = false
                        pendingBreakOrContinueASI = false
                        prevTokenWasCloseParen = false
                        i += 2
                        continue
                    } else {
                        let depth = currentDepth()
                        pruneClassHeaders(atOrDeeperThan: depth)
                        pendingTernaryDepths.append(depth)
                        canStartRegex = true
                        nextBraceIsBlock = false
                        lastIdentBeforeWhitespace = nil
                        prevWasDot = false
                        pendingFunctionBraceIsBlock = nil
                        pendingBraceIsFunctionBody = false
                        pendingBraceFunctionIsAsync = nil
                        pendingBraceFunctionIsGenerator = nil
                        pendingBraceMethodIsAsync = nil
                        pendingBraceMethodIsGenerator = nil
                        pendingAsyncKeyword = false
                        pendingStarKeyword = false
                        pendingFunctionIsAsync = false
                        pendingFunctionIsGenerator = false
                        pendingMethodIsAsync = false
                        pendingMethodIsGenerator = false
                        pendingArrowIdentIsAsync = false
                        pendingBreakOrContinueASI = false
                        prevTokenWasCloseParen = false
                    }
                } else if ch == ":" {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    invalidateInnerConcatOnToken()
                    let depth = currentDepth()
                    pruneClassHeaders(atOrDeeperThan: depth)
                    let isTernaryColon = pendingTernaryDepths.last == depth
                    let isStatementColon = !isTernaryColon && isAtStatementBody()
                    var suppressColonForMask = false
                    var normalizedComputedWrapper: String? = nil
                    if isTernaryColon {
                        pendingTernaryDepths.removeLast()
                        canStartRegex = true
                        nextBraceIsBlock = false
                        suppressColonForMask = true
                        clearObjectKeyExpectationOnToken()
                    } else {
                        while let last = conciseArrowAsyncScopes.last, last.depth == depth {
                            conciseArrowAsyncScopes.removeLast()
                        }
                        if isStatementColon {
                            canStartRegex = true
                            nextBraceIsBlock = true
                            suppressColonForMask = true
                            clearObjectKeyExpectationOnToken()
                        } else {
                            canStartRegex = true
                            nextBraceIsBlock = false
                            let isWrappedByOuterComputed = isInsideComputedPropertyWrapper()
                            if containerStack.last == .brace, !braceStack.isEmpty {
                                let bIdx = braceStack.count - 1
                                braceStack[bIdx].expectsObjectKey = false
                                if pendingComputedKeyColon {
                                    braceStack[bIdx].propHasComputedKey = true
                                    normalizedComputedWrapper = pendingComputedKeyNormalizedName
                                }
                            }
                            pendingComputedKeyColon = false
                            pendingComputedKeyNormalizedName = nil
                            if isWrappedByOuterComputed {
                                suppressColonForMask = true
                            }
                        }
                    }
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    if maskNonKeyLiterals {
                        if let normalized = normalizedComputedWrapper {
                            out.append(", \"\(normalized)\":")
                        } else if suppressColonForMask {
                            out.append(" /*:*/ ")
                        } else {
                            out.append(":")
                        }
                        i += 1
                        continue
                    }
                } else if regexPrefixChars.contains(ch) {
                    let prevCanStartRegex = canStartRegex
                    let prevNextBraceIsBlock = nextBraceIsBlock
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    if ch == "+" {
                        if containerStack.last == .bracket, !bracketStack.isEmpty, bracketStack.last?.concatExpectingPlus == true {
                            bracketStack[bracketStack.count - 1].concatExpectingPlus = false
                        } else if containerStack.last == .templateBrace, !templateBraceConcatStack.isEmpty, templateBraceConcatStack.last?.expectingPlus == true {
                            templateBraceConcatStack[templateBraceConcatStack.count - 1].expectingPlus = false
                        } else {
                            invalidateInnerConcatOnToken()
                        }
                    } else {
                        invalidateInnerConcatOnToken()
                    }
                    canStartRegex = true
                    nextBraceIsBlock = false
                    if ch == "*" {
                        if pendingFunctionBraceIsBlock != nil {
                            pendingFunctionIsGenerator = true
                        } else if isEnclosingMethodContainer() && (prevCanStartRegex || pendingAsyncKeyword || lastIdentBeforeWhitespace == "static" || (braceStack.last?.isClassBody == true && prevNextBraceIsBlock)) {
                            pendingStarKeyword = true
                        }
                    } else {
                        pendingFunctionBraceIsBlock = nil
                        pendingFunctionIsAsync = false
                        pendingFunctionIsGenerator = false
                        pendingAsyncKeyword = false
                        pendingStarKeyword = false
                    }
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    if ch == "," {
                        let depth = currentDepth()
                        while let last = conciseArrowAsyncScopes.last, last.depth == depth {
                            conciseArrowAsyncScopes.removeLast()
                        }
                        if containerStack.last == .brace, !braceStack.isEmpty {
                            braceStack[braceStack.count - 1].expectsObjectKey = true
                            braceStack[braceStack.count - 1].propHasComputedKey = false
                        }
                        pendingComputedKeyColon = false
                        pendingComputedKeyNormalizedName = nil
                    } else {
                        clearObjectKeyExpectationOnToken()
                    }
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    pruneClassHeaders(atOrDeeperThan: currentDepth())
                } else if ch == "." {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearAwaitingHeritageStart(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    canStartRegex = false
                    nextBraceIsBlock = false
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = true
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                } else if ch == "/" {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    canStartRegex = true
                    nextBraceIsBlock = false
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                    pruneClassHeaders(atOrDeeperThan: currentDepth())
                } else if !ch.isWhitespace {
                    transitionArrowToConciseBodyIfNeeded(at: currentDepth())
                    clearObjectKeyExpectationOnToken()
                    invalidateInnerConcatOnToken()
                    lastIdentBeforeWhitespace = nil
                    prevWasDot = false
                    pendingFunctionBraceIsBlock = nil
                    pendingBraceIsFunctionBody = false
                    pendingBraceFunctionIsAsync = nil
                    pendingBraceFunctionIsGenerator = nil
                    pendingBraceMethodIsAsync = nil
                    pendingBraceMethodIsGenerator = nil
                    pendingAsyncKeyword = false
                    pendingStarKeyword = false
                    pendingFunctionIsAsync = false
                    pendingFunctionIsGenerator = false
                    pendingMethodIsAsync = false
                    pendingMethodIsGenerator = false
                    pendingArrowIdentIsAsync = false
                    pendingBreakOrContinueASI = false
                    prevTokenWasCloseParen = false
                }
            }
            if maskNonKeyLiterals && (inSingle || inDouble || inTemplate) {
                if inTemplate {
                    if !templateBufferStack.isEmpty {
                        let idx = templateBufferStack.count - 1
                        templateBufferStack[idx].buffer.append(ch)
                        if let existing = templateBufferStack[idx].concatString {
                            templateBufferStack[idx].concatString = existing + String(ch)
                        }
                    }
                } else {
                    quotedLiteralBuffer.append(ch)
                }
            } else {
                out.append(ch)
            }
            i += 1
        }
        if maskNonKeyLiterals && (inSingle || inDouble || inTemplate) {
            out.append("\"\"")
        }
        return out
    }

    private static func isBlanketNegativeKillSwitchToken(_ rawToken: String) -> Bool {
        let token = stripSurroundingQuotes(rawToken).lowercased()
        guard token.hasPrefix("-") else { return false }
        var host = String(token.dropFirst())
        if let colonIdx = host.firstIndex(of: ":") {
            host = String(host[..<colonIdx])
        }
        guard !host.isEmpty else { return false }
        return host.allSatisfy { $0 == "*" || $0 == "." }
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
        var dirSt = stat()
        if lstat(IPAPackageScanner.stripTrailingSlashes(tempDir.path), &dirSt) == 0,
           (dirSt.st_mode & S_IFMT) == S_IFLNK {
            try FileManager.default.removeItem(at: tempDir)
        }
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let safeFilename: String = {
            guard let raw = customFilename?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !raw.isEmpty,
                  !raw.contains("/"),
                  !raw.contains("\\"),
                  !raw.contains("\0"),
                  raw != ".",
                  raw != ".." else {
                return platform.defaultFilename
            }
            return raw
        }()
        let fileURL = tempDir.appendingPathComponent(safeFilename)
        try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(Data(content.utf8), to: fileURL)
        return fileURL
    }
}
