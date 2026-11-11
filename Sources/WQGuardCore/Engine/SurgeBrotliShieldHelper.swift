//
//  SurgeBrotliShieldHelper.swift
//  WQGuardCore
//
//  Helper utility for previewing, exporting, and verifying Surge/WQGuard-Brotli-Shield.sgmodule.
//  Zero UIKit dependency: 100% compatible with macOS CLI, tests, and iOS SwiftUI targets.
//

import Foundation

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

    /// Raw verbatim template of the production Surge Brotli Shield module.
    public static let rawModuleTemplate: String = """
    #!name=WQGuard · 防 Brotli 溢出降级护盾 (CVE-2026-111497)
    #!desc=针对 iOS 26.x 与 iOS 27.0–27.2.0 系统未修复之 libbrotli 堆越界写高危漏洞 (CVE-2026-111497 / HTTP2Shell, CVSS 9.2)，在网络传输层剥离 Accept-Encoding 中的 br 算法强制降级为 gzip/deflate。内置 16 项严苛负向排除规则，确保 Apple Intelligence、Siri、iCloud 与网银支付绝对不被拦截。
    #!version=1.0.0
    #!category=安全防护
    #!arguments=EXTRA_MITM_HOSTS:*.example.invalid
    #!arguments-desc=可追加需要强制 Brotli 降级保护的高风险自定义域名（支持通配符如 *.example.com；如需保护全部 Safari/WebView 流量可填入 *，内置排除列表已保护 Apple 核心服务与金融应用）。

    [Header Rewrite]
    # 强制剥离客户端请求中的 br 压缩声明，降级至安全的 gzip 与 deflate 编码
    ^https?:// header-replace Accept-Encoding "gzip, deflate"

    [Script]
    # 防御不遵从客户端协商、强行回传 Content-Encoding: br 的恶意服务端响应
    brotli-response-guard = type=http-response,pattern=^https?://,requires-body=false,max-size=0,script-text="const ce = ($response.headers['Content-Encoding'] || $response.headers['content-encoding'] || '').toLowerCase(); if (ce.includes('br')) { $done({response: {status: 403, headers: {'Content-Type': 'text/plain; charset=utf-8'}, body: 'WQGuard Brotli Shield: Blocked unsolicited Brotli response stream to mitigate CVE-2026-111497.'}}); } else { $done({}); }"

    [MITM]
    # 严苛负向排除规则保障：Apple Intelligence、普通话 Siri、PCC 中继、OpenAI 及银行绝对不走 MITM！
    hostname = %APPEND% -*.apple.com, -*.icloud.com, -*.icloud-content.com, -*.mzstatic.com, -*.cdn-apple.com, -guzzoni.apple.com, -*.siri.apple.com, -gspe1-ssl.ls.apple.com, -apple-relay.*, -cp4.cloudflare.com, -*.openai.com, -*.chatgpt.com, -*.binance.com, -*.okx.com, -*.tenpay.com, -*.alipay.com, *.xyz, *.top, *.icu, *.cyou, *.sbs, *.cfd, *.buzz, *.fun, *.click, *.link, *.site, *.online, *.shop, *.vip, *.pw, *.work, *.rest, *.monster, *.quest, *.zip, *.mov, {{{EXTRA_MITM_HOSTS}}}
    """

    public init() {}

    /// Generates the Surge module content, substituting optional extra custom MITM host patterns.
    public func generateModuleContent(extraHosts: [String] = []) -> String {
        let replacement = extraHosts.isEmpty ? "*.example.invalid" : extraHosts.joined(separator: ", ")
        return Self.rawModuleTemplate.replacingOccurrences(of: "{{{EXTRA_MITM_HOSTS}}}", with: replacement)
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

    /// Validates that a given Surge module content satisfies all security and compatibility invariants.
    public func validateModule(content: String) -> ValidationResult {
        var errors: [String] = []

        let hasValidMetadata = content.contains("#!name=") && content.contains("#!category=") && content.contains("#!arguments=")
        if !hasValidMetadata {
            errors.append("缺少合规的 Surge 模块元数据指令 (#!name, #!category, #!arguments)")
        }

        let hasHeaderRewrite = content.contains("[Header Rewrite]") && content.contains("Accept-Encoding") && content.contains("\"gzip, deflate\"")
        if !hasHeaderRewrite {
            errors.append("缺少 [Header Rewrite] 或未正确配置 Accept-Encoding 强制降级规则")
        }

        let hasScriptGuard = content.contains("[Script]") && content.contains("brotli-response-guard")
        if !hasScriptGuard {
            errors.append("缺少 [Script] brotli-response-guard 响应拦截器")
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

    /// Exports the module to a temporary file ready for Share Sheet or document picker.
    public func exportToTemporaryFile(extraHosts: [String] = [], filename: String = "WQGuard-Brotli-Shield.sgmodule") throws -> URL {
        let content = generateModuleContent(extraHosts: extraHosts)
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("WQGuardSurgeExports", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent(filename)
        try content.write(to: fileURL, atomically: true, encoding: .utf8)
        return fileURL
    }
}
