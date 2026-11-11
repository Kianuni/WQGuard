//
//  ReportGenerator.swift
//  WQGuardCore
//
//  Multi-format security audit report serializer for WQGuard scan sessions.
//  Supports RFC 8259 JSON, bilingual Markdown, and terminal-friendly PlainText.
//

import Foundation

/// Contract defining multi-format security audit report generation.
public protocol ReportGeneratorProtocol: Sendable {
    /// Serializes a scan session into RFC 8259 compliant pretty-printed UTF-8 JSON data.
    /// - Parameter session: The completed scan session.
    /// - Returns: UTF-8 encoded JSON data.
    /// - Throws: An error if encoding fails.
    func generateJSONReport(session: ScanSession) throws -> Data

    /// Serializes a scan session into a human-readable Markdown report with status badges,
    /// summary tables, categorized findings, indicator tables, and bilingual remediation guidance.
    /// - Parameter session: The completed scan session.
    /// - Returns: Markdown formatted string.
    func generateMarkdownReport(session: ScanSession) -> String

    /// Serializes a scan session into clean formatted plain text suitable for terminal CLI output or .txt export.
    /// - Parameter session: The completed scan session.
    /// - Returns: Plain text formatted string.
    func generatePlainTextReport(session: ScanSession) -> String
}

/// Errors thrown during report generation.
public enum ReportGeneratorError: LocalizedError, Sendable {
    case invalidUTF8Data
    case encodingFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidUTF8Data:
            return "Failed to convert serialized JSON data to UTF-8 string."
        case .encodingFailed(let message):
            return "Failed to encode scan session to JSON: \(message)"
        }
    }
}

/// Production implementation of ReportGeneratorProtocol.
public final class ReportGenerator: ReportGeneratorProtocol, Sendable {

    /// Shared singleton instance.
    public static let shared = ReportGenerator()

    /// Initializes a new instance of ReportGenerator.
    public init() {}

    // MARK: - JSON Serializer

    /// Serializes a scan session into RFC 8259 compliant pretty-printed UTF-8 JSON data.
    public func generateJSONReport(session: ScanSession) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        do {
            return try encoder.encode(session)
        } catch {
            throw ReportGeneratorError.encodingFailed(error.localizedDescription)
        }
    }

    /// Convenience method to generate the JSON report directly as a UTF-8 string.
    public func generateJSONReportString(session: ScanSession) throws -> String {
        let data = try generateJSONReport(session: session)
        guard let jsonString = String(data: data, encoding: .utf8) else {
            throw ReportGeneratorError.invalidUTF8Data
        }
        return jsonString
    }

    // MARK: - Markdown Serializer

    /// Serializes a scan session into a human-readable Markdown report.
    public func generateMarkdownReport(session: ScanSession) -> String {
        var md = ""

        // 1. Header & Title
        md += "# WQGuard Security Audit Report\n"
        md += "### iOS 沙盒逃逸检测与系统安全审计报告\n\n"

        // 2. Metadata Table
        let timestampISO = ISO8601DateFormatter().string(from: session.timestamp)
        let resolvedSysVer = session.systemVersion ?? currentSystemVersionString()
        let durationStr = session.scanDuration.map { String(format: "%.2fs", $0) } ?? "N/A"

        md += "| Parameter / 属性 | Value / 详细取值 |\n"
        md += "| :--- | :--- |\n"
        md += "| **Scan Timestamp / 扫描时间** | `\(timestampISO)` |\n"
        md += "| **Session ID / 审计会话 ID** | `\(session.id.uuidString)` |\n"
        md += "| **System Version / 操作系统版本** | \(resolvedSysVer) |\n"
        md += "| **Engine Version / 扫描引擎版本** | WQGuardCore v\(session.engineVersion) |\n"
        md += "| **Scan Duration / 扫描耗时** | \(durationStr) |\n"
        md += "| **Total Scanned / 扫描应用总数** | \(session.totalApps) |\n\n"

        // 3. Security Posture Status Badge
        md += markdownPostureBadge(for: session.overallPosture)
        md += "\n\n"

        // 4. Executive Summary Statistics Table
        md += "## 📊 Executive Summary / 审计统计概览\n\n"
        md += "| Risk Tier / 风险等级 | Badge / 状态 | Count / 数量 | Percentage / 占比 | Scope & Definition / 风险定义 |\n"
        md += "| :--- | :---: | :---: | :---: | :--- |\n"

        let total = max(session.totalApps, 1)
        let highCount = session.riskBreakdown[.highRisk, default: 0]
        let knownCount = session.riskBreakdown[.knownTool, default: 0]
        let cautionCount = session.riskBreakdown[.caution, default: 0]
        let safeCount = session.riskBreakdown[.safe, default: 0]

        let highPct = String(format: "%.1f%%", Double(highCount) / Double(total) * 100.0)
        let knownPct = String(format: "%.1f%%", Double(knownCount) / Double(total) * 100.0)
        let cautionPct = String(format: "%.1f%%", Double(cautionCount) / Double(total) * 100.0)
        let safePct = String(format: "%.1f%%", Double(safeCount) / Double(total) * 100.0)

        md += "| **High Risk (高危告警)** | 🔴 | `\(highCount)` | `\(highPct)` | 包含 containermanagerd 逃逸调用、私有沙盒令牌或异常逃逸符号链接 |\n"
        md += "| **Known Tool (已知工具)** | 🟡 | `\(knownCount)` | `\(knownPct)` | 匹配白名单已知开源工具（Erosion、GestaltX、WQFiles、WQGuard 等） |\n"
        md += "| **Caution (前置留意)** | 🟠 | `\(cautionCount)` | `\(cautionPct)` | 声明 App Group 并具备动态符号解析（dlopen/dlsym）能力的侧载/企业应用 |\n"
        md += "| **Safe (安全合规)** | 🟢 | `\(safeCount)` | `\(safePct)` | 无 App Group 共享权限或经完整静态扫描未发现可疑特征的合规应用 |\n"
        md += "| **Total / 总计扫描** | 🛡️ | `\(session.totalApps)` | `100.0%` | 全部分发渠道扫描应用汇总 |\n\n"

        // 5. Categorized Findings
        md += "## 🔍 Detailed Audit Findings / 详细审计发现\n\n"

        if session.findings.isEmpty {
            md += "*No application findings recorded in this scan session (本次扫描未发现应用记录)。*\n\n"
        } else {
            // High Risk Section
            md += markdownCategorySection(
                title: "🔴 High Risk Findings / 高危告警应用清单",
                tier: .highRisk,
                findings: session.highRiskFindings
            )

            // Known Tool Section
            md += markdownCategorySection(
                title: "🟡 Known Tools / 已知工具清单",
                tier: .knownTool,
                findings: session.knownToolFindings
            )

            // Caution Section
            md += markdownCategorySection(
                title: "🟠 Caution Findings / 前置条件留意应用清单",
                tier: .caution,
                findings: session.cautionFindings
            )

            // Safe Section
            md += markdownCategorySection(
                title: "🟢 Safe Applications / 安全合规应用清单",
                tier: .safe,
                findings: session.safeFindings
            )
        }

        // 6. Footer & Integrity Assurance
        md += "---\n"
        md += "### 🔒 Inspection Integrity & Invariant Assurance / 审计完整性保证\n"
        md += "This report was generated automatically by **WQGuard** (100% Read-Only iOS Security Scanner).\n\n"
        md += "- **Read-Only Invariant**: WQGuard operates strictly using read-only file descriptors (`O_RDONLY`), `stat`/`lstat`, and memory-mapped buffers. No system, bundle, or App Group container files were modified, created, or deleted during this inspection.\n"
        md += "- **100% 只读保障声明**: WQGuard 严格使用只读描述符与内存映射运行，未在系统、应用包或共享容器目录中进行任何创建、写入、修改或删除操作。\n"

        return md
    }

    // MARK: - PlainText Serializer

    /// Serializes a scan session into clean formatted plain text suitable for terminal CLI output or .txt export.
    public func generatePlainTextReport(session: ScanSession) -> String {
        var text = ""

        let divider = String(repeating: "=", count: 80)
        let subDivider = String(repeating: "-", count: 80)

        // 1. Title Banner
        text += "\(divider)\n"
        text += "                      WQGUARD SECURITY AUDIT REPORT\n"
        text += "                       (iOS 沙盒逃逸检测与审计报告)\n"
        text += "\(divider)\n"

        let timestampISO = ISO8601DateFormatter().string(from: session.timestamp)
        let resolvedSysVer = session.systemVersion ?? currentSystemVersionString()
        let durationStr = session.scanDuration.map { String(format: "%.2fs", $0) } ?? "N/A"

        text += String(format: "%-22@: %@\n", "Scan Timestamp", timestampISO)
        text += String(format: "%-22@: %@\n", "Session ID", session.id.uuidString)
        text += String(format: "%-22@: %@\n", "System Version", resolvedSysVer)
        text += String(format: "%-22@: WQGuardCore v%@\n", "Engine Version", session.engineVersion)
        text += String(format: "%-22@: %@\n", "Scan Duration", durationStr)
        text += "\(divider)\n"

        // 2. Posture Banner
        text += "SECURITY POSTURE: \(plainTextPostureStatus(for: session.overallPosture))\n"
        text += "\(divider)\n"

        // 3. Summary Statistics
        let total = max(session.totalApps, 1)
        let highCount = session.riskBreakdown[.highRisk, default: 0]
        let knownCount = session.riskBreakdown[.knownTool, default: 0]
        let cautionCount = session.riskBreakdown[.caution, default: 0]
        let safeCount = session.riskBreakdown[.safe, default: 0]

        let highPct = String(format: "%5.1f%%", Double(highCount) / Double(total) * 100.0)
        let knownPct = String(format: "%5.1f%%", Double(knownCount) / Double(total) * 100.0)
        let cautionPct = String(format: "%5.1f%%", Double(cautionCount) / Double(total) * 100.0)
        let safePct = String(format: "%5.1f%%", Double(safeCount) / Double(total) * 100.0)

        text += "SUMMARY STATISTICS:\n"
        text += String(format: "  - [!] High Risk (高危告警):   %4d (%@)\n", highCount, highPct)
        text += String(format: "  - [*] Known Tool (已知工具):  %4d (%@)\n", knownCount, knownPct)
        text += String(format: "  - [?] Caution (前置留意):     %4d (%@)\n", cautionCount, cautionPct)
        text += String(format: "  - [+] Safe (安全合规):        %4d (%@)\n", safeCount, safePct)
        text += String(format: "  - [=] Total Scanned (总计):   %4d (100.0%%)\n", session.totalApps)
        text += "\(divider)\n\n"

        // 4. Findings List
        text += "DETAILED FINDINGS:\n"
        if session.findings.isEmpty {
            text += "  (No application findings recorded in this scan session)\n\n"
        } else {
            // Sort findings by severity (High Risk first)
            let sortedFindings = session.findings.sorted { $0.riskTier > $1.riskTier }
            for (idx, finding) in sortedFindings.enumerated() {
                text += "\(subDivider)\n"
                text += "[\(idx + 1)/\(session.findings.count)] [\(finding.riskTier.rawValue)] \(finding.displayName) (\(finding.bundleId))\n"
                text += "\(subDivider)\n"
                text += "  * Version:         \(finding.version)\n"
                text += "  * Team ID:         \(finding.teamId ?? "None (Ad-hoc / Unsigned)")\n"
                text += "  * Install Channel: \(finding.installChannel.localizedNameZh)\n"
                text += "  * Bundle Path:     \(finding.bundlePath)\n"
                text += "  * Executable Path: \(finding.executablePath ?? "N/A")\n"
                text += "  * DRM Status:      \(finding.evidence.isFairPlayEncrypted ? "FairPlay Encrypted (cryptid: 1)" : "Unencrypted Mach-O (cryptid: 0)")\n"
                text += "  * Whitelist:       \(finding.isWhitelisted ? "Whitelisted Tool: \(finding.whitelistedToolName ?? "Known Tool")" : "Not Whitelisted")\n"

                // Indicators
                if !finding.indicators.isEmpty {
                    text += "\n  [!] Threat Indicators (\(finding.indicators.count)):\n"
                    for (iIdx, ind) in finding.indicators.enumerated() {
                        text += "      \(iIdx + 1). [\(ind.severity.rawValue)] \(ind.signature)\n"
                        text += "         Category:    \(ind.category)\n"
                        text += "         Location:    \(ind.location)\n"
                        text += "         Description: \(ind.description)\n"
                    }
                }

                // Evidence Summary
                text += "\n  [*] Audit Evidence Summary:\n"
                if !finding.evidence.matchedSymbols.isEmpty {
                    text += "      - Matched Symbols: \(finding.evidence.matchedSymbols.joined(separator: ", "))\n"
                }
                if !finding.evidence.linkedDylibs.isEmpty {
                    text += "      - Linked Dylibs:   \(finding.evidence.linkedDylibs.joined(separator: ", "))\n"
                }
                if !finding.evidence.appGroups.isEmpty {
                    text += "      - App Groups:      \(finding.evidence.appGroups.joined(separator: ", "))\n"
                }
                if !finding.evidence.escapingSymlinks.isEmpty {
                    text += "      - Escaping Links:  \(finding.evidence.escapingSymlinks.joined(separator: ", "))\n"
                }
                text += "      - Dynamic Loading: \(finding.evidence.dynamicLoadingPresent ? "Present (dlopen/dlsym)" : "None")\n"
                text += "      - Path Enum:       \(finding.evidence.pathEnumerationPresent ? "Present (fsgetpath)" : "None")\n"

                // Remediation Guidance
                let (enGuidance, zhGuidance) = bilingualRemediation(for: finding)
                text += "\n  [+] Remediation Guidance (EN):\n"
                text += "      \(enGuidance)\n"
                text += "  [+] 处置建议 (中文):\n"
                text += "      \(zhGuidance)\n\n"
            }
        }

        // 5. Invariant Footer
        text += "\(divider)\n"
        text += "[i] INVARIANT ASSURANCE: 100% Read-Only Inspection.\n"
        text += "    No system, bundle, or App Group container files were modified or created.\n"
        text += "\(divider)\n"

        return text
    }

    // MARK: - Private Helpers

    private func currentSystemVersionString() -> String {
        #if os(macOS)
        return "macOS \(ProcessInfo.processInfo.operatingSystemVersionString)"
        #elseif os(iOS)
        return "iOS \(ProcessInfo.processInfo.operatingSystemVersionString)"
        #else
        return "Darwin \(ProcessInfo.processInfo.operatingSystemVersionString)"
        #endif
    }

    private func markdownPostureBadge(for posture: RiskTier) -> String {
        switch posture {
        case .highRisk:
            return """
            > ### 🔴 SECURITY ALERT: CRITICAL RISK DETECTED / 发现高危沙盒逃逸风险
            > **Posture / 安全态势**: Critical Sandbox Escape or Exploits Identified (检测到严重越权或沙盒逃逸行为)  
            > **Description / 说明**: One or more installed applications or inspected IPA packages contain active signatures targeting `containermanagerd` sandbox token acquisition or anomalous escaping symlinks (`S_ISLNK`). Immediate remediation is required.
            """
        case .knownTool:
            return """
            > ### 🟡 ADVISORY: KNOWN UTILITIES DETECTED / 发现已知定制工具
            > **Posture / 安全态势**: Authorized Known Tools Identified (检测到已知开源工具)  
            > **Description / 说明**: Applications matching the transparent whitelist of verified open-source utilities (e.g., Erosion, WQFiles, GestaltX) were detected. These tools utilize sandbox escape techniques for legitimate device customization.
            """
        case .caution:
            return """
            > ### 🟠 NOTICE: POTENTIAL PREREQUISITES DETECTED / 前置条件留意
            > **Posture / 安全态势**: Escape Prerequisites Present (存在潜在逃逸前置条件)  
            > **Description / 说明**: Applications possessing `com.apple.security.application-groups` combined with dynamic symbol loading (`dlopen`/`dlsym`) were found. While not matching exploit signatures, they possess technical prerequisites.
            """
        case .safe:
            return """
            > ### 🟢 SYSTEM STATUS: SECURE / 系统状态安全
            > **Posture / 安全态势**: Clean & Sandbox Compliant (未发现沙盒逃逸行为)  
            > **Description / 说明**: All inspected applications strictly respect iOS sandbox boundaries. No anomalous `containermanagerd` exploit signatures, private sandbox token calls, or rogue App Group symlinks were detected.
            """
        }
    }

    private func plainTextPostureStatus(for posture: RiskTier) -> String {
        switch posture {
        case .highRisk:
            return "[CRITICAL RISK DETECTED] / 发现高危沙盒逃逸利用"
        case .knownTool:
            return "[KNOWN UTILITIES DETECTED] / 发现已知定制工具"
        case .caution:
            return "[POTENTIAL PREREQUISITES] / 存在潜在逃逸前置条件"
        case .safe:
            return "[SYSTEM SECURE] / 系统安全合规"
        }
    }

    private func markdownCategorySection(
        title: String,
        tier: RiskTier,
        findings: [ScanFinding]
    ) -> String {
        var s = "### \(title) (\(findings.count))\n\n"

        if findings.isEmpty {
            s += "*No applications classified under \(tier.localizedNameEn) (\(tier.localizedNameZh)).*\n\n"
            return s
        }

        for (idx, finding) in findings.enumerated() {
            let badge = tierEmoji(for: finding.riskTier)
            s += "#### \(badge) \(idx + 1). \(finding.displayName) (`\(finding.bundleId)`)\n\n"
            s += "- **Display Name / 应用名称**: \(finding.displayName)\n"
            s += "- **Bundle Identifier / 标识符**: `\(finding.bundleId)`\n"
            s += "- **Version / 版本**: `\(finding.version)`\n"
            s += "- **Signing Team ID / 开发者团队**: `\(finding.teamId ?? "None (Ad-hoc / Unsigned)")`\n"
            s += "- **Install Channel / 分发渠道**: \(finding.installChannel.localizedNameZh)\n"
            s += "- **Executable Path / 可执行文件路径**: `\(finding.executablePath ?? "N/A")`\n"
            s += "- **Bundle Path / 安装包路径**: `\(finding.bundlePath)`\n"
            s += "- **FairPlay DRM / 加密状态**: \(finding.evidence.isFairPlayEncrypted ? "🔒 FairPlay Encrypted (cryptid: 1)" : "🔓 Unencrypted Mach-O (cryptid: 0)")\n"
            s += "- **Whitelist Status / 白名单状态**: \(finding.isWhitelisted ? "✅ Whitelisted (\(finding.whitelistedToolName ?? "Known Tool"))" : "❌ Not Whitelisted")\n\n"

            // Indicators Table
            if !finding.indicators.isEmpty {
                s += "##### 🚨 Matched Threat Indicators / 命中的风险特征项 (\(finding.indicators.count))\n\n"
                s += "| # | Signature / 特征标识 | Category / 威胁类别 | Severity / 等级 | Location / 检出位置 | Description / 详情说明 |\n"
                s += "| :-: | :--- | :--- | :---: | :--- | :--- |\n"
                for (iIdx, ind) in finding.indicators.enumerated() {
                    let sevBadge = "\(tierEmoji(for: ind.severity)) \(ind.severity.rawValue)"
                    let safeSig = escapeMarkdownCell(ind.signature)
                    let safeCat = escapeMarkdownCell(ind.category)
                    let safeLoc = escapeMarkdownCell(ind.location)
                    let safeDesc = escapeMarkdownCell(ind.description)
                    s += "| \(iIdx + 1) | `\(safeSig)` | \(safeCat) | \(sevBadge) | `\(safeLoc)` | \(safeDesc) |\n"
                }
                s += "\n"
            }

            // Evidence Breakdown
            s += "##### 🔬 Audit Evidence Breakdown / 详细审计取证信息\n\n"
            let symbols = finding.evidence.matchedSymbols.isEmpty ? "*None*" : finding.evidence.matchedSymbols.map { "`\($0)`" }.joined(separator: ", ")
            let dylibs = finding.evidence.linkedDylibs.isEmpty ? "*None*" : finding.evidence.linkedDylibs.map { "`\($0)`" }.joined(separator: ", ")
            let groups = finding.evidence.appGroups.isEmpty ? "*None*" : finding.evidence.appGroups.map { "`\($0)`" }.joined(separator: ", ")
            let symlinks = finding.evidence.escapingSymlinks.isEmpty ? "*None*" : finding.evidence.escapingSymlinks.map { "`\($0)`" }.joined(separator: ", ")

            s += "- **Matched Private Symbols / 私有符号**: \(symbols)\n"
            s += "- **Linked Dylibs / 动态链接库**: \(dylibs)\n"
            s += "- **Entitled App Groups / 共享群组**: \(groups)\n"
            s += "- **Escaping Symlinks (S_ISLNK) / 异常逃逸符号链接**: \(symlinks)\n"
            s += "- **Dynamic Resolution (`dlopen`/`dlsym`) / 动态加载**: \(finding.evidence.dynamicLoadingPresent ? "⚠️ Detected" : "Clean")\n"
            s += "- **Path Enumeration (`fsgetpath`) / 路径遍历**: \(finding.evidence.pathEnumerationPresent ? "⚠️ Detected" : "Clean")\n\n"

            // Bilingual Remediation Guidance
            let (enGuidance, zhGuidance) = bilingualRemediation(for: finding)
            s += "> #### 🛡️ Actionable Remediation Guidance / 处置建议\n"
            s += ">\n"
            s += "> **English (EN)**:\n"
            s += "> \(enGuidance)\n"
            s += ">\n"
            s += "> **中文 (zh-Hans)**:\n"
            s += "> \(zhGuidance)\n\n"
        }

        return s
    }

    private func tierEmoji(for tier: RiskTier) -> String {
        switch tier {
        case .highRisk: return "🔴"
        case .knownTool: return "🟡"
        case .caution: return "🟠"
        case .safe: return "🟢"
        }
    }

    private func bilingualRemediation(for finding: ScanFinding) -> (en: String, zh: String) {
        if !finding.evidence.remediationGuidance.isEmpty &&
           finding.evidence.remediationGuidance != "未发现威胁，保持系统更新。" {
            let customGuidance = finding.evidence.remediationGuidance
            switch finding.riskTier {
            case .highRisk:
                return (
                    en: "Immediate Action Required: Uninstall this application immediately. Revoke associated certificates and reboot device. Note: \(customGuidance)",
                    zh: "必须立即处置：请立即卸载此应用，在「设置-通用-VPN与设备管理」移除对应描述文件并重启设备。备注：\(customGuidance)"
                )
            case .knownTool:
                return (
                    en: "Known Customization Utility: Ensure this tool was obtained from official open-source releases. Note: \(customGuidance)",
                    zh: "已知定制工具：请确认该应用来源于官方开源渠道。如果您未主动安装，建议删除。备注：\(customGuidance)"
                )
            case .caution:
                return (
                    en: "Precondition Notice: App Group entitlement and dynamic loading detected. Verify developer identity. Note: \(customGuidance)",
                    zh: "前置条件提醒：检测到 App Group 权限与动态解析特征，请核实开发者来源。备注：\(customGuidance)"
                )
            case .safe:
                return (
                    en: "Clean Application: No action required.",
                    zh: "安全应用：未发现跨沙盒利用特征，无需操作。"
                )
            }
        }

        switch finding.riskTier {
        case .highRisk:
            return (
                en: "Immediate Action Required: 1. Delete this application from your device immediately. 2. Navigate to Settings > General > VPN & Device Management and remove any untrusted developer or enterprise profile. 3. Reboot the device to flush ephemeral system tokens and prevent container persistence.",
                zh: "高危处置建议：1. 立即从设备上卸载此应用。2. 进入「设置 > 通用 > VPN 与设备管理」移除对应未受信任的企业或个人开发者证书。3. 重启设备以清除临时内核沙盒令牌，杜绝残留持久化隐患。"
            )
        case .knownTool:
            let toolName = finding.whitelistedToolName ?? "Open-Source Utility"
            return (
                en: "Known Customization Utility (\(toolName)): This application matches the authorized open-source utility whitelist (e.g., Erosion, WQFiles, GestaltX) used for legitimate customization and diagnostics. If you did not intentionally install this tool, remove it from your device.",
                zh: "已知定制工具提示（\(toolName)）：该应用符合白名单授权开源工具特征（如 Erosion、WQFiles、GestaltX 等），通常用于系统诊断或个性化定制。若非本人主动安装，建议立即从设备中移除。"
            )
        case .caution:
            return (
                en: "Precondition Notice: This sideloaded application possesses App Group entitlements and dynamic symbol loading capabilities (dlopen/dlsym). While no active exploit was flagged, it possesses technical escape prerequisites. Verify the installation source before granting sensitive permissions.",
                zh: "前置条件留意：此侧载应用声明了 App Group 共享群组权限，并具备动态符号加载能力（dlopen/dlsym）。虽未直接触发已知逃逸利用，但具备技术前置条件。建议核查其安装包来源，谨慎授予权限。"
            )
        case .safe:
            return (
                en: "Safe Application: This application respects standard iOS sandbox boundaries. No containermanagerd exploit signatures or anomalous shared container symlinks detected. No user action is required.",
                zh: "安全合规应用：此应用严格遵守标准 iOS 沙盒规范，未检出 containermanagerd 逃逸调用或异常共享容器符号链接，无需任何用户处置。"
            )
        }
    }

    private func escapeMarkdownCell(_ text: String) -> String {
        return text
            .replacingOccurrences(of: "|", with: "\\|")
            .replacingOccurrences(of: "\r\n", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
    }
}
