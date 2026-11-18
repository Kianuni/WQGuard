//
//  WQStrings.swift
//  WQGuard
//
//  Consolidated type-safe bilingual string catalog supporting Simplified Chinese and English.
//

import Foundation
import WQGuardCore

public enum WQStrings {
    // MARK: - Localization Helpers
    public static var isEnglish: Bool {
        WQLocale.isEnglish
    }

    private static func localized(_ key: String, en: String, zh: String) -> String {
        let langFolder = isEnglish ? "en" : "zh-Hans"
        if let lprojPath = Bundle.main.path(forResource: langFolder, ofType: "lproj"),
           let langBundle = Bundle(path: lprojPath) {
            let val = langBundle.localizedString(forKey: key, value: "__WQ_MISSING__", table: "Localizable")
            if val != "__WQ_MISSING__" && val != key {
                return val
            }
        }
        return isEnglish ? en : zh
    }

    // MARK: - Tabs
    public static var tabDashboard: String { localized("tab_dashboard", en: "Dashboard", zh: "仪表盘") }
    public static var tabFindings: String { localized("tab_findings", en: "Findings", zh: "审计发现") }
    public static var tabIPAScan: String { localized("tab_ipa_scan", en: "IPA Scan", zh: "IPA 审查") }
    public static var tabFirmwareRadar: String { localized("tab_firmware_radar", en: "Firmware Radar", zh: "固件雷达") }
    public static var tabSettings: String { localized("tab_settings", en: "Settings", zh: "设置与规则") }

    // MARK: - Dashboard Overview
    public static var appTitle: String { localized("app_title", en: "WQGuard", zh: "WQGuard 容器守卫") }
    public static var startSystemScan: String { localized("start_system_scan", en: "Scan Installed Apps", zh: "开始全盘安全检测") }
    public static var startSystemScanSub: String { localized("start_system_scan_sub", en: "installation_proxy Registry + On-Device Probe + Queued IPA Correlation", zh: "系统注册表权限审计 + 本机探针 + 本地 IPA 二进制联动") }
    public static var configureInstalledScanButton: String { localized("configure_installed_scan_btn", en: "Scan Sources & Pairing", zh: "配置已安装扫描源") }
    public static func activeEnginesBadge(_ active: Int, total: Int = 3) -> String {
        localized("active_engines_badge", en: "\(active)/\(total) Engines On", zh: "已启用 \(active)/\(total) 引擎")
    }
    public static func queuedIPACountBadge(_ count: Int) -> String {
        localized("queued_ipa_count_badge", en: "\(count) Queued", zh: "已加入 \(count) 个")
    }
    public static func queuedIPAListSummary(_ namesCSV: String) -> String {
        localized("queued_ipa_list_summary", en: "Queued for scan: \(namesCSV)", zh: "已加入扫描列表: \(namesCSV)")
    }
    public static var inspectAuditResultsPrompt: String {
        localized("inspect_audit_results_prompt", en: "View Detailed Audit Findings", zh: "查看本次审计结果详情清单")
    }
    public static var selectIPAFileButton: String { localized("select_ipa_file_btn", en: "Select .ipa Files (Multi-Select)", zh: "选择 .ipa 文件加入扫描（支持多选）") }
    public static var batchImportIPAButton: String { localized("batch_import_ipa_button", en: "Select .ipa Files (Multi-Select)", zh: "选择 .ipa 文件加入扫描（支持多选）") }
    public static var scanningInProgress: String { localized("scanning_in_progress", en: "Deep analysis in progress...", zh: "正在深度分析...") }
    public static var cancelScan: String { localized("cancel_scan", en: "Cancel Scan", zh: "取消全盘扫描") }
    public static var metricsSummary: String { localized("metrics_summary", en: "Audit Summary", zh: "审计统计概览") }
    public static var scannedApps: String { localized("scanned_apps", en: "Scanned Apps", zh: "已扫描应用") }
    public static var highRiskAlerts: String { localized("high_risk_alerts", en: "High Risk", zh: "高危告警") }
    public static var knownTools: String { localized("known_tools", en: "Known Tools", zh: "已知工具") }
    public static var cautionAlerts: String { localized("caution_alerts", en: "Caution", zh: "前置留意") }
    public static var safeApps: String { localized("safe_apps", en: "Safe", zh: "安全合规") }

    // Quick Actions
    public static var viewDetailedFindings: String { localized("view_detailed_findings", en: "View Detailed Audit Findings", zh: "查看详细审计清单") }
    public static var viewDetailedFindingsSub: String { localized("view_detailed_findings_sub", en: "Inspect matched signatures, private symbols, and symlinks", zh: "检查所有命中特征、私有符号与逃逸链接") }
    public static var firmwareRadarTitle: String { localized("firmware_radar_title", en: "Firmware CVE Exposure Radar", zh: "固件 CVE 暴露雷达") }
    public static var firmwareRadarSub: String { localized("firmware_radar_sub", en: "Unpatched CVEs · Multi-Client Shield Export", zh: "项待防护系统漏洞 · 多平台护盾一键导入") }
    public static var exportAuditReport: String { localized("export_audit_report", en: "Export Audit Report", zh: "导出审计报告") }
    public static var exportAuditReportSub: String { localized("export_audit_report_sub", en: "Generate RFC 8259 JSON / Markdown / PlainText reports", zh: "生成 RFC 8259 JSON / Markdown / 纯文本审计报告") }

    // MARK: - Posture Hero Card
    public static var postureDeepAnalyzing: String { localized("posture_deep_analyzing", en: "Analyzing:", zh: "正在深度分析:") }
    public static var postureStatusScanningTitle: String { localized("posture_status_scanning_title", en: "Deep Audit in Progress...", zh: "深度审计进行中...") }
    public static var postureStatusHighRiskTitle: String { localized("posture_status_high_risk_title", en: "Scan Complete · High Risk Detected", zh: "检测完成 · 发现高危告警") }
    public static var postureStatusCautionTitle: String { localized("posture_status_caution_title", en: "Scan Complete · Review Advised", zh: "检测完成 · 发现需留意应用") }
    public static var postureStatusKnownToolTitle: String { localized("posture_status_known_tool_title", en: "Scan Complete · Known Tools", zh: "检测完成 · 检出已知定制工具") }
    public static var postureStatusSafeTitle: String { localized("posture_status_safe_title", en: "Scan Complete · System Safe", zh: "检测完成 · 系统状态安全合规") }

    public static var postureStatusScanningSub: String { localized("posture_status_scanning_sub", en: "Scanning Mach-O private symbols & shared container symlink traversals...", zh: "正在执行权限注册表核验与二进制特征排查") }
    public static var postureStatusHighRiskSub: String { localized("posture_status_high_risk_sub", en: "Detected unauthorized sandbox escape entitlements, private symbols, or impersonation!", zh: "检出高危越权特征或仿冒应用，点击卡片立即查看高危应用清单！") }
    public static var postureStatusCautionSub: String { localized("posture_status_caution_sub", en: "Sideloaded apps declare shared App Groups, persistent background modes, or mod traits. Tap to review.", zh: "部分侧载/企业签应用含共享容器、常驻后台或改版特征，点击查看详情。") }
    public static var postureStatusKnownToolSub: String { localized("posture_status_known_tool_sub", en: "Matched WQGuard self-identity or user-configured custom whitelist rules.", zh: "已匹配 WQGuard 自身身份或用户自定义信任白名单规则，点击查看清单。") }
    public static var postureStatusSafeSub: String { localized("posture_status_safe_sub", en: "All scanned targets strictly comply with iOS sandbox boundaries.", zh: "所有已扫描目标均符合 iOS 沙盒隔离边界，未检出越权风险。") }

    public static func posturePendingTitle(exposedCount: Int) -> String {
        if exposedCount > 0 {
            return localized("posture_pending_cve_title_\(exposedCount)", en: "Pending App Audit · \(exposedCount) Firmware CVEs", zh: "待执行应用审计 · \(exposedCount) 项固件漏洞")
        }
        return localized("posture_pending_clean_title", en: "Ready · Pending App Audit", zh: "就绪 · 待执行安全检测")
    }

    public static func posturePendingSubtitle(exposedCount: Int, isFullScanEnabled: Bool = false) -> String {
        if exposedCount > 0 {
            return localized("posture_pending_cve_sub", en: "Unpatched firmware CVEs detected. Tap below to scan installed apps or select local .ipa files.", zh: "当前 iOS 存在未修补系统漏洞。请点击下方扫描已安装应用或手动多选 .ipa 文件加入扫描。")
        }
        return localized("posture_pending_clean_sub", en: "Tap below to scan installed apps or select local .ipa packages.", zh: "请点击下方按钮扫描已安装应用或手动多选本地 .ipa 安装包。")
    }

    public static func postureTitle(for posture: RiskTier, isScanning: Bool) -> String {
        if isScanning { return postureStatusScanningTitle }
        switch posture {
        case .highRisk: return postureStatusHighRiskTitle
        case .caution: return postureStatusCautionTitle
        case .knownTool: return postureStatusKnownToolTitle
        case .safe: return postureStatusSafeTitle
        }
    }

    public static func postureSubtitle(for posture: RiskTier, isScanning: Bool) -> String {
        if isScanning { return postureStatusScanningSub }
        switch posture {
        case .highRisk: return postureStatusHighRiskSub
        case .caution: return postureStatusCautionSub
        case .knownTool: return postureStatusKnownToolSub
        case .safe: return postureStatusSafeSub
        }
    }

    // MARK: - Metric Grid / Progress
    public static var scanPreparing: String { localized("scan_preparing", en: "Preparing...", zh: "准备中...") }

    // MARK: - Findings View & Rows
    public static var filterAll: String { localized("filter_all", en: "All", zh: "全部") }
    public static var filterHighRisk: String { localized("filter_high_risk", en: "High Risk", zh: "高危") }
    public static var filterKnownTool: String { localized("filter_known_tool", en: "Known Tools", zh: "已知工具") }
    public static var filterCaution: String { localized("filter_caution", en: "Caution", zh: "前置留意") }
    public static var filterSafe: String { localized("filter_safe", en: "Safe", zh: "安全") }
    public static var searchPrompt: String { localized("search_prompt", en: "Search app name, Bundle ID, or Team ID...", zh: "搜索应用名、Bundle ID 或 Team ID...") }
    public static var noScanPerformed: String { localized("no_scan_performed", en: "No System Scan Performed Yet", zh: "尚未执行全盘扫描") }
    public static var noScanPerformedSub: String { localized("no_scan_performed_sub", en: "Tap 'Start System Audit' in Dashboard to initiate scan.", zh: "点击「仪表盘」中的「开始全盘检测」启动审计。") }
    public static var noFilteredFindings: String { localized("no_filtered_findings", en: "No Matching Applications Found", zh: "无符合筛选条件的应用") }
    public static var noFilteredFindingsSub: String { localized("no_filtered_findings_sub", en: "No security findings match the selected filter tier.", zh: "当前筛选等级下未发现任何风险记录。") }

    public static func indicatorCountBadge(_ count: Int) -> String {
        let enStr = count == 1 ? "1 Indicator" : "\(count) Indicators"
        return localized("indicator_count_\(count)", en: enStr, zh: "\(count) 项特征")
    }

    // MARK: - Finding Detail View
    public static var whitelistedBadge: String { localized("whitelisted_badge", en: "Whitelisted", zh: "已加入白名单") }
    public static func threatIndicatorsHeader(_ count: Int) -> String {
        return localized("threat_indicators_header_\(count)", en: "🚨 Matched Threat Indicators (\(count))", zh: "🚨 命中的威胁特征指标 (\(count))")
    }
    public static func indicatorLocation(_ location: String) -> String {
        return localized("indicator_location_prefix", en: "Location: \(location)", zh: "位置: \(location)")
    }
    public static var staticAuditEvidenceHeader: String { localized("static_audit_evidence_header", en: "🔬 Static Audit Evidence Details", zh: "🔬 静态审计取证详情") }
    public static var evidenceAuditDepth: String { localized("evidence_audit_depth", en: "Audit Depth", zh: "审计覆盖深度") }
    public static var evidenceSignerIdentity: String { localized("evidence_signer_identity", en: "Code Signer Identity", zh: "签名证书身份") }
    public static var evidenceVersion: String { localized("evidence_version", en: "Version", zh: "版本号") }
    public static var evidenceTeamId: String { localized("evidence_team_id", en: "Developer Team ID", zh: "开发者团队 ID") }
    public static var evidenceTeamIdUnsigned: String { localized("evidence_team_id_unsigned", en: "None (Ad-hoc / Unsigned)", zh: "无 (Ad-hoc / 未签名)") }
    public static var evidenceDrmStatus: String { localized("evidence_drm_status", en: "FairPlay DRM Status", zh: "FairPlay DRM 状态") }
    public static var evidenceDrmEncrypted: String { localized("evidence_drm_encrypted", en: "🔒 FairPlay Encrypted (cryptid: 1)", zh: "🔒 FairPlay 加密 (cryptid: 1)") }
    public static var evidenceDrmUnencrypted: String { localized("evidence_drm_unencrypted", en: "🔓 Unencrypted Mach-O (cryptid: 0)", zh: "🔓 未加密 Mach-O (cryptid: 0)") }
    public static var evidenceAppGroups: String { localized("evidence_app_groups", en: "App Groups", zh: "App Groups") }
    public static var evidenceAppGroupsNone: String { localized("evidence_app_groups_none", en: "None (Physically incapable of escape)", zh: "无 (物理无法触发逃逸)") }
    public static var evidencePrivateSymbols: String { localized("evidence_private_symbols", en: "Private Symbols", zh: "私有符号引用") }
    public static var evidenceNone: String { localized("evidence_none", en: "None", zh: "无") }
    public static var evidenceDynamicLoading: String { localized("evidence_dynamic_loading", en: "Dynamic Resolution", zh: "动态链接解析") }
    public static var evidenceDetectedDlopen: String { localized("evidence_detected_dlopen", en: "⚠️ Detected (dlopen/dlsym)", zh: "⚠️ 检出 (dlopen/dlsym)") }
    public static var evidencePathEnumeration: String { localized("evidence_path_enumeration", en: "Path Enumeration", zh: "路径爆破枚举") }
    public static var evidenceDetectedFsgetpath: String { localized("evidence_detected_fsgetpath", en: "⚠️ Detected (fsgetpath)", zh: "⚠️ 检出 (fsgetpath)") }
    public static var evidenceInstallPath: String { localized("evidence_install_path", en: "Install Path", zh: "安装路径") }
    public static var addToWhitelistButton: String { localized("add_to_whitelist_button", en: "Add App to Trusted Whitelist", zh: "将此应用加入信任白名单") }
    public static var whitelistAddedTitle: String { localized("whitelist_added_title", en: "Added to Whitelist", zh: "已加入白名单") }
    public static func whitelistAddedMessage(appName: String) -> String {
        return localized("whitelist_added_message", en: "App \"\(appName)\" has been added to local rules. Risk tier adjusted to Known Tool.", zh: "应用「\(appName)」已添加至本地规则，风险等级已调整为已知工具。")
    }

    // MARK: - Remediation Card View
    public static var remediationGuidanceTitle: String { localized("remediation_guidance_title", en: "Remediation Guidance", zh: "处置建议 (Remediation Guidance)") }
    public static var emergencyWorkflowTitle: String { localized("emergency_workflow_title", en: "Emergency Mitigation Workflow:", zh: "应急处置流程:") }
    public static var emergencyStep1: String { localized("emergency_step_1", en: "1. Immediately touch and hold the app icon to delete it. Do NOT launch.", zh: "1. 立即长按图标卸载此应用，切勿启动。") }
    public static var emergencyStep2: String { localized("emergency_step_2", en: "2. Go to Settings > General > VPN & Device Management to remove provisioning profile.", zh: "2. 前往「设置 -> 通用 -> VPN 与设备管理」注销签名描述文件。") }
    public static var emergencyStep3: String { localized("emergency_step_3", en: "3. Restart device to completely invalidate and reclaim untrusted kernel sandbox tokens.", zh: "3. 重启设备，彻底注销并回收未受信内核沙盒令牌。") }

    // MARK: - IPA Package Card & Injected Dylibs
    public static var ipaImportTitle: String { localized("ipa_import_title", en: "Import Local IPA Package", zh: "导入本地 IPA 安装包") }
    public static var ipaImportSub: String { localized("ipa_import_sub", en: "Pre-installation sandbox analysis for containermanagerd escape, private photos & dylib injection", zh: "安装前在沙盒内深度检测 containermanagerd 越权、私有相册调用与注入动态库") }
    public static var selectIPAButton: String { localized("select_ipa_button", en: "Select .ipa Files (Multi-Select)", zh: "选择 .ipa 文件加入扫描（支持多选）") }
    public static var batchIPANoValidTargets: String { localized("batch_ipa_no_targets", en: "Please select valid .ipa or .tipa package files (multiple selection supported).", zh: "请选择 .ipa 或 .tipa 格式的安装包文件（支持一次勾选多个文件加入扫描）。") }
    public static func batchIPACompletedBanner(_ count: Int) -> String {
        localized("batch_ipa_completed_\(count)", en: "Batch audit completed: \(count) packages inspected (see Findings tab for full list)", zh: "已完成批量审查：共检测 \(count) 个安装包（完整列表已同步至「仪表盘」与「审计发现」）")
    }
    public static var ipaAnalyzing: String { localized("ipa_analyzing", en: "Performing 4-layer sandbox analysis & Mach-O static binary audit...", zh: "正在进行 4 层沙盒解析与 Mach-O 静态二进制审计...") }
    public static var ipaAnalysisFailed: String { localized("ipa_analysis_failed", en: "IPA Analysis Failed", zh: "IPA 分析失败") }
    public static var preinstallAlertHighRisk: String { localized("preinstall_alert_high_risk", en: "Pre-install Warning: Detected sandbox escape exploit! Do NOT install!", zh: "安装前预警：检测到越界沙盒逃逸特征，切勿安装！") }
    public static var preinstallAlertSafe: String { localized("preinstall_alert_safe", en: "Pre-install Assessment: Clean. No exploit signatures detected.", zh: "安装前评估：未发现已知越权利用特征，处于安全状态。") }

    public static var ipaDistributionChannel: String { localized("ipa_distribution_channel", en: "Distribution Channel", zh: "分发渠道") }
    public static var ipaTeamIdSelfSigned: String { localized("ipa_team_id_self_signed", en: "None (Ad-hoc / Self-signed)", zh: "无 (Ad-hoc / 个人自签)") }
    public static var ipaDrmEncrypted: String { localized("ipa_drm_encrypted", en: "FairPlay Encrypted (cryptid: 1)", zh: "FairPlay 加密 (cryptid: 1)") }
    public static var ipaDrmUnencrypted: String { localized("ipa_drm_unencrypted", en: "Unencrypted (cryptid: 0, full static binary audit completed)", zh: "未加密 (cryptid: 0, 完整静态二进制审计已完成)") }
    public static var ipaDeclaredAppGroups: String { localized("ipa_declared_app_groups", en: "Declared App Groups", zh: "声明的 App Groups") }
    public static var ipaAppGroupsNone: String { localized("ipa_app_groups_none", en: "None (Physically incapable of escape)", zh: "无 (物理无法逃逸)") }
    public static var ipaDylibCountLabel: String { localized("ipa_dylib_count_label", en: "Dynamic Libraries Count", zh: "动态链接库数量") }
    public static func ipaDylibCountValue(_ count: Int) -> String {
        return localized("ipa_dylib_count_val_\(count)", en: "\(count) embedded/system dylibs", zh: "\(count) 个 embedded/system dylibs")
    }
    public static func ipaDetectedIndicatorsHeader(_ count: Int) -> String {
        return localized("ipa_detected_indicators_\(count)", en: "Detected Indicators (\(count)):", zh: "检出特征项 (\(count)):")
    }
    public static func injectedDylibsTitle(_ count: Int) -> String {
        return localized("injected_dylibs_title_\(count)", en: "Dynamic Libraries & Injection Audit (\(count))", zh: "动态库与注入审查 (\(count))")
    }
    public static var injectedDylibsEmpty: String { localized("injected_dylibs_empty", en: "No additional third-party embedded dynamic libraries detected.", zh: "未检出额外的第三方嵌入动态库。") }

    // MARK: - Firmware Radar & Mitigations
    public static func radarExposedCount(_ count: Int) -> String {
        let format = localized("radar_exposed_count", en: "%d Vulnerabilities Exposed", zh: "%d 项漏洞暴露")
        return String(format: format, count)
    }

    public static func radarPatchedCount(_ count: Int) -> String {
        let format = localized("radar_patched_count", en: "%d Patched", zh: "%d 项已打补丁")
        return String(format: format, count)
    }

    public static var surgeShieldTitle: String {
        localized("surge_shield_title", en: "Multi-Client · Brotli Downgrade Shield", zh: "多平台代理 · 防 Brotli 溢出降级护盾")
    }

    public static var surgeShieldDescription: String {
        localized("surge_shield_description",
                  en: "Strips br compression at the proxy layer for Surge, Shadowrocket, Quantumult X, Loon, and Stash to mitigate unpatched iOS 26/27 libbrotli heap overflow CVEs. Built-in 16 negative exclusions ensure Apple Intelligence, Siri, and banking are never intercepted.",
                  zh: "针对未修复 iOS 26/27 系统的 libbrotli 堆溢出高危漏洞，支持 Surge、小火箭、圈 X、Loon、Stash 五大代理工具在传输层剥离 br 压缩声明并阻断强推响应。内置 16 项负向排除，保障 Apple Intelligence、普通话 Siri 与网银支付绝对不被拦截。")
    }

    public static var surgeShieldPreview: String {
        localized("surge_shield_preview", en: "Preview & Import", zh: "预览与一键导入")
    }

    public static var surgeShieldExport: String {
        localized("surge_shield_export", en: "Export / Share File", zh: "分享规则文件")
    }

    public static func shieldExportButtonLabel(ext: String) -> String {
        isEnglish ? "Share .\(ext)" : "分享 .\(ext) 文件"
    }

    public static func shieldPlatformShortTitle(_ platform: ProxyShieldPlatform) -> String {
        isEnglish ? platform.shortTitleEn : platform.shortTitleZh
    }

    public static func shieldPlatformUsageHint(_ platform: ProxyShieldPlatform) -> String {
        platform.localizedUsageHint
    }

    public static func shieldOneTapInstallLabel(clientName: String) -> String {
        isEnglish ? "One-Tap Install in \(clientName)" : "一键唤起 \(clientName) 安装"
    }

    public static var shieldCopySubURLButton: String {
        isEnglish ? "Copy Subscription URL" : "复制在线订阅链接"
    }

    public static var shieldCopySourceButton: String {
        isEnglish ? "Copy Rule Source" : "复制配置源码"
    }

    public static var shieldCopiedSubURLToast: String {
        isEnglish ? "Subscription URL Copied" : "已复制在线订阅链接"
    }

    public static var shieldCopiedSourceToast: String {
        isEnglish ? "Rule Source Copied" : "已复制配置源码"
    }

    public static func shieldSheetCodeTitle(filename: String) -> String {
        isEnglish ? "Rule Source (\(filename))" : "配置源码预览 (\(filename))"
    }

    public static func radarKnownVulnerabilitiesHeader(count: Int) -> String {
        let format = localized("radar_known_vulns_header", en: "Firmware Known High-Risk CVE Assessment (%d items)", zh: "固件已知高危漏洞暴露评估 (%d 项)")
        return String(format: format, count)
    }

    public static var radarMitigationGuidanceHeader: String {
        localized("radar_mitigation_guidance_header", en: "🛡️ Non-Upgrade Mitigation Advisories", zh: "🛡️ 不升级固件下的缓解处置建议")
    }

    public static var radarBranchLTS: String {
        localized("radar_branch_lts", en: "iOS 26.x LTS Branch (Proxy Shield Recommended)", zh: "iOS 26.x 长期支持分支 (推荐开启代理护盾)")
    }

    public static var radarBranchCurrent: String {
        localized("radar_branch_current", en: "iOS 27.x Active Branch", zh: "iOS 27.x 现行分支")
    }

    public static func radarBranchOther(major: Int) -> String {
        let format = localized("radar_branch_other", en: "iOS %d.x Branch", zh: "iOS %d.x 分支")
        return String(format: format, major)
    }

    public static func radarBranchBadge(major: Int) -> String {
        if major == 26 {
            return radarBranchLTS
        } else if major == 27 {
            return radarBranchCurrent
        } else {
            return radarBranchOther(major: major)
        }
    }

    public static var cveStatusExposed: String {
        localized("cve_status_exposed", en: "⚠️ Exposed", zh: "⚠️ 暴露")
    }

    public static var cveStatusPatched: String {
        localized("cve_status_patched", en: "✅ Patched", zh: "✅ 已修补")
    }

    public static func cveAffectedVersions(_ versions: String) -> String {
        let format = localized("cve_affected_versions", en: "Affected: %@", zh: "影响版本: %@")
        return String(format: format, versions)
    }

    public static var mitigationConfigureButton: String {
        localized("mitigation_configure_button", en: "Configure Now", zh: "立即前往配置")
    }

    // MARK: - Multi-Client Shield Sheet
    public static var surgeSheetCodeTitle: String {
        localized("surge_sheet_code_title", en: "WQGuard · Brotli Shield Configuration", zh: "WQGuard · 防 Brotli 溢出降级护盾配置")
    }

    public static var surgeSheetNavTitle: String {
        localized("surge_sheet_nav_title", en: "Multi-Client Brotli Shield", zh: "多平台 Brotli 降级护盾")
    }

    // MARK: - Settings View & Custom Rules
    public static var settingsScanModeHeader: String { localized("settings_scan_mode_header", en: "Scan Scope & Risk Controls", zh: "扫描范围与高危权限开关") }
    public static var settingsScanModeFooter: String { localized("settings_scan_mode_footer", en: "By default, WQGuard operates in pure local IPA upload inspection mode. Enabling Full Installed-App Scan requires explicit risk acknowledgment.", zh: "WQGuard 默认仅开启最安全的「上传本地 IPA 安装包检测」模式。开启全盘已安装软件扫描需完整阅读安全须知并确认环境风险。") }
    public static var consentNavTitle: String { localized("consent_nav_title", en: "Security & Risk Notice", zh: "安全须知与风险告知") }
    public static var consentBannerTitle: String { localized("consent_banner_title", en: "Enable Full Installed-App Scan?", zh: "开启「全盘已安装软件扫描」高危提醒") }
    public static var consentBannerSubtitle: String { localized("consent_banner_subtitle", en: "Please carefully read all risk disclosures and operational boundaries below before enabling.", zh: "该模式涉及跨目录应用容器枚举，存在严格的系统环境边界与操作风险，请务必逐条阅读并确认：") }
    public static var consentClause1Title: String { localized("consent_clause1_title", en: "1. iOS Sandbox Boundary & Environment Limits", zh: "1. 系统沙盒边界与运行环境限制") }
    public static var consentClause1Body: String { localized("consent_clause1_body", en: "On standard personal/enterprise sideloaded iOS devices, Apple Seatbelt blocks cross-app directory enumeration (/var/containers/Bundle/Application). Full enumeration of other installed apps only succeeds in unsandboxed environments (e.g., TrollStore no-sandbox / jailbreak) or for bundles placed in WQGuard's shared Documents folder.", zh: "在普通个人自签/企业证书侧载环境下，iOS Seatbelt 沙盒会强制拦截跨应用读取 /var/containers/Bundle/Application。WQGuard 绝不内嵌主动沙盒逃逸攻击代码（Exploit），因此仅在具备全局读权限的环境（如 TrollStore 无沙盒环境）或针对放入 WQGuard 文件目录的应用包可完成枚举。") }
    public static var consentClause2Title: String { localized("consent_clause2_title", en: "2. Cross-Container Stability & Symlink Warnings", zh: "2. 跨容器操作风险与软链接残留警示") }
    public static var consentClause2Body: String { localized("consent_clause2_body", en: "WQGuard opens files strictly with O_RDONLY | O_NOFOLLOW. Never use unstable third-party container mutators concurrently during scanning, as interrupted symlink swaps in Library/Caches can destabilize containermanagerd or leave residual escaping symlinks.", zh: "WQGuard 全程严格采用 O_RDONLY | O_NOFOLLOW 只读不跟随模式。扫描期间请勿同时运行第三方容器写入/挂载工具，避免外部工具在共享容器 Library/Caches 中产生残留软链接或引发 containermanagerd 守护进程异常。") }
    public static var consentClause3Title: String { localized("consent_clause3_title", en: "3. FairPlay DRM Static Analysis Scope", zh: "3. FairPlay DRM 加密段的审计边界") }
    public static var consentClause3Body: String { localized("consent_clause3_body", en: "App Store apps have FairPlay-encrypted __TEXT segments (cryptid == 1); static scanning inspects Load Commands, symbol tables, and entitlements only. Pre-install .ipa upload inspection remains the primary defense against unencrypted sideloaded trojans.", zh: "App Store 官方应用的二进制正文段受苹果内核 FairPlay 加密（cryptid == 1），静态扫描仅可核验其未加密加载命令、符号表与签名权限；防范第三方篡改包、盗币木马的最有效手段仍为安装前上传 .ipa 检测。") }
    public static var consentClause4Title: String { localized("consent_clause4_title", en: "4. Local Privacy & Self-Audit Responsibility", zh: "4. 本机隐私数据保护与自用合规承诺") }
    public static var consentClause4Body: String { localized("consent_clause4_body", en: "Full scan reports contain installed Bundle IDs, versions, and signer Team IDs. Keep exported JSON/Markdown reports confidential and only audit devices you own or are authorized to inspect.", zh: "全盘扫描生成的报告包含本机应用清单、Bundle ID 及签名团队 ID 等敏感设备指纹信息。请确认仅在本人合法持有的设备上自用，并妥善保管导出的审计报告。") }
    public static var consentCheckboxLabel: String { localized("consent_checkbox_label", en: "I have read and understood the Security Notice and Risk Disclosures above, and confirm enabling Full Installed-App Scan.", zh: "我已完整阅读并理解上述《安全须知与风险告知》，知悉环境限制与相关风险，确认开启全盘已安装软件扫描。") }
    public static var consentConfirmButton: String { localized("consent_confirm_button", en: "Acknowledge Risks & Enable Full Scan", zh: "确认知悉风险并开启全盘扫描") }
    public static var consentKeepDefaultButton: String { localized("consent_keep_default_button", en: "Cancel (Keep Default IPA Upload Mode)", zh: "取消（保持默认上传 IPA 检测）") }

    public static var settingsBuiltinWhitelist: String { localized("settings_builtin_whitelist", en: "Built-in Research Tools Whitelist", zh: "内置已知研究工具白名单") }
    public static var settingsBuiltinWhitelistFooter: String { localized("settings_builtin_whitelist_footer", en: "When enabled, apps matching open-source research tools are classified as Known Tools rather than High Risk.", zh: "启用白名单后，匹配开源工具特征的应用将评级为「已知工具提示」而非「高危告警」。") }
    public static var settingsCustomRules: String { localized("settings_custom_rules", en: "Custom Whitelist Rules", zh: "自定义白名单规则") }
    public static var settingsNoCustomRules: String { localized("settings_no_custom_rules", en: "No custom rules configured", zh: "暂无自定义规则") }
    public static var settingsAddRule: String { localized("settings_add_rule", en: "Add Custom Bundle ID Rule", zh: "添加自定义 Bundle ID 规则") }
    public static var settingsResetButton: String { localized("settings_reset_button", en: "Reset Whitelist to Defaults", zh: "重置所有白名单为默认") }
    public static var settingsAboutHeader: String { localized("settings_about_header", en: "About WQGuard", zh: "关于 WQGuard") }
    public static var settingsAboutFooter: String { localized("settings_about_footer", en: "WQGuard is an open-source 100% read-only sandbox audit utility for iOS 26.2+ / 27.x.", zh: "WQGuard 是面向 iOS 26.2+ / iOS 27.x 的开源只读沙盒审计工具，保障设备免遭未授权跨容器提权渗透。") }
    public static var settingsEngineVersion: String { localized("settings_engine_version", en: "Engine Version", zh: "引擎版本") }
    public static var settingsAppBuild: String { localized("settings_app_build", en: "App Build", zh: "应用构建") }
    public static var settingsOperatingMode: String { localized("settings_operating_mode", en: "Operating Mode", zh: "工作模式") }
    public static var settingsReadOnlyMode: String { localized("settings_read_only_mode", en: "100% Read-Only (O_RDONLY)", zh: "100% 严格只读 (O_RDONLY)") }

    public static var settingsResetConfirmTitle: String {
        localized("settings_reset_confirm_title", en: "Reset Whitelist to Defaults?", zh: "确认重置白名单？")
    }

    public static var settingsResetConfirmAction: String {
        localized("settings_reset_confirm_action", en: "Reset to Defaults", zh: "确认重置为默认")
    }

    public static var settingsResetConfirmMessage: String {
        localized("settings_reset_confirm_message",
                  en: "This will remove all custom whitelist rules and restore only the built-in WQGuard self-identity rule.",
                  zh: "将清除所有自定义规则，并仅保留 WQGuard 自身默认白名单。")
    }

    public static var ruleSheetToolNamePlaceholder: String {
        localized("rule_sheet_tool_name_placeholder", en: "Tool / App Name (e.g. MyTool)", zh: "工具/应用名称 (例如: MyTool)")
    }

    public static var ruleSheetBundleIdPlaceholder: String {
        localized("rule_sheet_bundle_id_placeholder", en: "Bundle Identifier (e.g. com.example.tool*)", zh: "Bundle Identifier (例如: com.example.tool*)")
    }

    public static var ruleSheetAppGroupPlaceholder: String {
        localized("rule_sheet_app_group_placeholder", en: "App Group (Optional, e.g. group.com.example)", zh: "App Group (可选，例如: group.com.example)")
    }

    public static var ruleSheetSectionHeader: String {
        localized("rule_sheet_section_header", en: "Rule Attributes", zh: "规则属性")
    }

    public static var ruleSheetSectionFooter: String {
        localized("rule_sheet_section_footer", en: "Bundle ID and App Group support wildcard patterns (e.g. com.test.*).", zh: "Bundle ID 与 App Group 支持通配符匹配（如 com.test.*）。")
    }

    public static var ruleSheetNavTitle: String {
        localized("rule_sheet_nav_title", en: "Add Custom Rule", zh: "添加自定义规则")
    }

    // MARK: - Report Export View
    public static var exportFormatPicker: String {
        localized("export_format_picker", en: "Report Format", zh: "报告格式")
    }

    public static var exportCopyToClipboard: String {
        localized("export_copy_to_clipboard", en: "Copy to Clipboard", zh: "复制到剪贴板")
    }

    public static var exportShareFile: String {
        localized("export_share_file", en: "Share / Save File", zh: "分享 / 保存文件")
    }

    public static var exportNavTitle: String {
        localized("export_nav_title", en: "Export Security Audit Report", zh: "导出安全审计报告")
    }

    public static var exportCopiedNotice: String {
        localized("export_copied_notice", en: "Copied to Clipboard", zh: "已复制到剪贴板")
    }

    // MARK: - Common Buttons & Actions
    public static var alertScanTitle: String { localized("alert_scan_title", en: "Security Scan Notice", zh: "安全扫描提示") }
    public static var buttonOK: String { localized("button_ok", en: "OK", zh: "好") }
    public static var buttonAcknowledge: String { localized("button_ok", en: "OK", zh: "好") }
    public static var buttonCancel: String { localized("button_cancel", en: "Cancel", zh: "取消") }
    public static var buttonClose: String { localized("button_close", en: "Close", zh: "关闭") }
    public static var buttonSave: String { localized("button_save", en: "Save", zh: "保存") }
    public static var buttonDone: String { localized("button_done", en: "Done", zh: "完成") }

    // MARK: - ScanViewModel Auxiliary Strings
    public static var scanEngineInitializing: String {
        localized("scan_engine_initializing", en: "Initializing scan engine...", zh: "初始化扫描引擎...")
    }

    public static func scanFailedMessage(_ errorDescription: String) -> String {
        let format = localized("scan_failed_message", en: "System scan failed: %@", zh: "全盘扫描失败: %@")
        return String(format: format, errorDescription)
    }

    public static var customRuleDefaultDescription: String {
        localized("custom_rule_default_description", en: "User custom whitelist rule", zh: "用户自定义白名单规则")
    }

    public static var reportNoDataPlaceholder: String {
        localized("report_no_data_placeholder",
                  en: "No audit data available yet. Please perform a system scan or import an IPA package first.",
                  zh: "暂无扫描审计数据。请先执行全盘扫描或导入 IPA 安装包。")
    }

    public static func surgeGenerationFailedMessage(_ errorDescription: String) -> String {
        let format = localized("surge_generation_failed_message", en: "Failed to generate Surge shield module: %@", zh: "生成 Surge 护盾模块失败: %@")
        return String(format: format, errorDescription)
    }

    // MARK: - Risk Tiers & Distribution Channels
    public static func riskName(_ tier: RiskTier) -> String {
        return localized("risk_\(tier.rawValue.lowercased())", en: tier.localizedNameEn, zh: tier.localizedNameZh)
    }

    public static func riskDesc(_ tier: RiskTier) -> String {
        return localized("risk_desc_\(tier.rawValue.lowercased())", en: tier.localizedDescriptionEn, zh: tier.localizedDescriptionZh)
    }

    public static func channelName(_ channel: InstallChannel) -> String {
        switch channel {
        case .developerSideloaded:
            return localized("channel_sideloaded", en: "🛠️ Sideloaded", zh: "🛠️ 个人侧载")
        case .enterpriseInHouse:
            return localized("channel_enterprise", en: "🏢 Enterprise", zh: "🏢 企业签")
        case .testFlight:
            return localized("channel_testflight", en: "✈️ TestFlight", zh: "✈️ TestFlight")
        case .appStore:
            return localized("channel_appstore", en: "🍏 App Store", zh: "🍏 App Store")
        }
    }

    public static func auditDepthName(_ depth: AuditDepth) -> String {
        switch depth {
        case .fullBinaryAndRegistry:
            return localized("depth_full", en: "🔬 Full Binary", zh: "🔬 全量深扫")
        case .registryEntitlements:
            return localized("depth_registry", en: "📋 Registry Audit", zh: "📋 系统注册表")
        case .onDeviceProbe:
            return localized("depth_probe", en: "📡 On-Device Probe", zh: "📡 本机探针")
        }
    }

    public static func auditDepthFullDesc(_ depth: AuditDepth) -> String {
        return isEnglish ? depth.localizedNameEn : depth.localizedNameZh
    }

    public static var ipaMultiSelectHint: String {
        localized("ipa_multi_select_hint",
                  en: "💡 Select multiple .ipa / .tipa files at once in Files to queue them; for signed apps in Feather, tap Library → Signed → Export IPA to import.",
                  zh: "💡 支持在系统『文件』中一次勾选多个 .ipa / .tipa 文件加入扫描列表；Feather 已签名应用可在 Feather「库 → 已签名 → 导出 IPA」后导入。")
    }
    public static func ipaQueuedFilesHeader(_ count: Int) -> String {
        localized("ipa_queued_files_header", en: "Queued Files (\(count))", zh: "已加入扫描文件 (\(count))")
    }
    public static var ipaRescanAllButton: String { localized("ipa_rescan_all_btn", en: "Rescan All", zh: "全部重扫") }
    public static var ipaClearQueueButton: String { localized("ipa_clear_queue_btn", en: "Clear", zh: "清空") }

    public static var builtinWhitelistRuleDesc: String {
        localized("builtin_whitelist_rule_desc", en: "Self-identity whitelist for WQGuard security scanner", zh: "WQGuard 安全审计器自身身份白名单规则")
    }

    // MARK: - ScanViewModel Messages
    public static func pairingImportedSummary(hostPrefix: String) -> String {
        localized("pairing_imported_summary", en: "Pairing file imported (HostID: \(hostPrefix)…)", zh: "已导入配对文件 (HostID: \(hostPrefix)…)")
    }
    public static var clipboardNoValidPairing: String {
        localized("clipboard_no_valid_pairing",
                  en: "No valid pairing file found on clipboard. Long-press your .plist pairing file in Files → Copy, then tap here again.",
                  zh: "剪贴板中未检测到有效的配对文件。请在系统『文件』App 中长按你的配对 .plist 文件点击「拷贝」，再回来点此按钮。")
    }
    public static var clipboardUnsupportedPlatform: String {
        localized("clipboard_unsupported_platform", en: "Clipboard import is not supported on this platform.", zh: "当前平台不支持剪贴板导入")
    }
    public static func autoImportedPairingNotice(_ msg: String) -> String {
        localized("auto_imported_pairing_notice", en: "Auto-loaded pairing file: \(msg)", zh: "已自动加载配对文件：\(msg)")
    }
    public static func autoImportedSnapshotNotice(_ msg: String) -> String {
        localized("auto_imported_snapshot_notice", en: "Auto-loaded snapshot: \(msg)", zh: "已自动加载快照：\(msg)")
    }
    public static var autoImportedIPANotice: String {
        localized("auto_imported_ipa_notice", en: "Auto-queued IPA packages from Files → On My iPhone → WQGuard", zh: "已自动将「我的 iPhone → WQGuard」内的 IPA 加入扫描列表")
    }
    public static var autoImportNoticeSeparator: String {
        isEnglish ? "; " : "；"
    }
    public static func snapshotImportedSummary(count: Int) -> String {
        localized("snapshot_imported_summary", en: "Registry snapshot imported (\(count) installed apps)", zh: "已导入注册表快照（共 \(count) 款已安装应用）")
    }
    public static func incomingFileReadFailed(_ filename: String) -> String {
        localized("incoming_file_read_failed", en: "Unable to read incoming file (\(filename)).", zh: "无法读取传入文件 (\(filename))。")
    }
    public static var pairingFileRequiredAlert: String {
        localized("pairing_file_required_alert", en: "Please import a pairing file (.plist / .mobiledevicepairing) first.", zh: "请先导入配对文件 (.plist / .mobiledevicepairing)。")
    }
    public static func connectingViaLocalDevVPN(host: String) -> String {
        localized("connecting_localdevvpn", en: "Connecting to installation_proxy via LocalDevVPN (\(host))...", zh: "正在通过 LocalDevVPN (\(host)) 连接 installation_proxy...")
    }
    public static var localDevVPNCacheName: String {
        localized("localdevvpn_cache_name", en: "LocalDevVPN Live Cache", zh: "LocalDevVPN 直连缓存")
    }
    public static func liveConnectionFailedMessage(_ errorDescription: String) -> String {
        localized("live_connection_failed",
                  en: "Pairing file saved, but direct connection failed:\n\(errorDescription)",
                  zh: "配对文件已保存，但直连未成功：\n\(errorDescription)")
    }
    public static func liveRegistryReadNotice(count: Int) -> String {
        localized("live_registry_read_notice", en: "Fetched live registry for \(count) installed apps", zh: "已直连读取全机 \(count) 款应用注册表")
    }
    public static func summaryLiveRegistry(_ count: Int) -> String {
        localized("summary_live_registry", en: "🟢 Live Registry: \(count)", zh: "🟢 配对直连注册表: \(count) 款")
    }
    public static func summarySnapshotRegistry(_ count: Int) -> String {
        localized("summary_snapshot_registry", en: "📋 Snapshot Registry: \(count)", zh: "📋 注册表快照: \(count) 款")
    }
    public static func summaryCorrelatedBinary(_ count: Int) -> String {
        localized("summary_correlated_binary", en: "🔬 Correlated IPA Audits: \(count)", zh: "🔬 IPA 二进制深扫联动: \(count) 款")
    }
    public static func summaryProbeDetected(_ count: Int) -> String {
        localized("summary_probe_detected", en: "📡 On-Device Probes: \(count)", zh: "📡 本机探针: \(count) 款")
    }
    public static func summaryLocalIPAQueue(_ count: Int) -> String {
        localized("summary_local_ipa_queue", en: "📦 Local IPA Queue: \(count) audited", zh: "📦 本地 IPA 队列深扫: \(count) 款")
    }

    // MARK: - Scan Sources & Pairing Sheet + Step-by-Step Tutorial
    public static var scanConfigNavTitle: String { localized("scan_config_nav_title", en: "Scan Sources & Pairing", zh: "已安装应用扫描源") }
    public static var tutorialGroupTitle: String { localized("tutorial_group_title", en: "📖 Step-by-Step Setup & Export Guide (Mac · USB · Snapshot · VPN)", zh: "📖 保姆级图文步骤教程（Mac 软件安装 · 连线 · 导出）") }
    public static var tutorialSectionHeader: String { localized("tutorial_section_header", en: "Getting Started · Step-by-Step Guide", zh: "新手必读 · 详细操作指南") }
    public static var tutorialIntroHeadline: String { localized("tutorial_intro_headline", en: "💡 Choose EITHER Mode A OR Mode B (no need to enable both)", zh: "💡 方式 A 与 方式 B 二选一即可（无需同时开启）") }
    public static var tutorialIntroBullets: String {
        localized("tutorial_intro_bullets",
                  en: "• **Recommended for Beginners (Mode B)**: No on-device VPN or IP tweaks needed. Export `installed_apps.json` on your Mac in seconds and AirDrop it to your iPhone.\n• **Recommended for Power Users (Mode A)**: Import a pairing file once from your Mac, then scan wirelessly anytime anywhere using `LocalDevVPN`.",
                  zh: "• **新手最推荐「方式 B」**：不用在手机装 VPN、不用改 IP，连上 Mac 电脑几秒钟导出 `installed_apps.json` 隔空投送到手机即可扫全机应用。\n• **进阶推荐「方式 A」**：只需用 Mac 导出一次配对文件导入手机，以后出门在外无需电脑，打开 `LocalDevVPN` 就能随时无线直连扫描！")
    }
    public static var tutorialCategoryPicker: String { localized("tutorial_category_picker", en: "Guide Section", zh: "教程分类") }
    public static var tutorialTabModeB: String { localized("tutorial_tab_mode_b", en: "Mode B · Mac Export", zh: "方式 B · Mac导出") }
    public static var tutorialTabModeA: String { localized("tutorial_tab_mode_a", en: "Mode A · Wireless VPN", zh: "方式 A · 无线直连") }
    public static var tutorialTabEngine2: String { localized("tutorial_tab_engine2", en: "Engine 2 · Deep IPA", zh: "引擎 2 · IPA深扫") }

    public static var cliExportEchoText: String {
        localized("cli_export_echo_text", en: "✅ Exported to Desktop: ~/Desktop/installed_apps.json", zh: "✅ 已导出到桌面: ~/Desktop/installed_apps.json")
    }
    public static var cliDeviceCtlEchoText: String {
        localized("cli_devicectl_echo_text", en: "✅ Exported ~/Desktop/installed_apps.json", zh: "✅ 已导出 ~/Desktop/installed_apps.json")
    }

    // Engine 1A
    public static var engine1ATitle: String { localized("engine1a_title", en: "Mode A: LocalDevVPN Paired Live Registry", zh: "方式 A：LocalDevVPN 配对直连本机注册表") }
    public static var engine1ANoPairingPlaceholder: String { localized("engine1a_no_pairing", en: "No pairing file imported (.plist / .mobiledevicepairing)", zh: "未导入配对文件（支持 .plist / .mobiledevicepairing 配对文件）") }
    public static var engine1AGatewayLabel: String { localized("engine1a_gateway_label", en: "Loopback Gateway IP", zh: "环回网关地址") }
    public static func engine1ASubnetMismatchTitle(wifiIP: String) -> String {
        localized("engine1a_subnet_mismatch", en: "iOS 26.4+ / 27 Subnet Check (Wi-Fi: \(wifiIP))", zh: "iOS 26.4+ / 27 子网校验提示（当前 Wi-Fi: \(wifiIP)）")
    }
    public static func engine1ASubnetAlignedTitle(wifiIP: String) -> String {
        localized("engine1a_subnet_aligned", en: "Aligned with Current Wi-Fi Subnet (\(wifiIP))", zh: "已对齐当前 Wi-Fi 同网段（\(wifiIP)）")
    }
    public static var engine1ASubnetHint: String {
        localized("engine1a_subnet_hint",
                  en: "Recent iOS lockdownd drops 10.7.0.x tunnels outside your active Wi-Fi subnet (EOF). If direct connection closes, update LocalDevVPN to the matching subnet addresses below:",
                  zh: "新系统 lockdownd 会拦截不在当前 Wi-Fi 网段内的 10.7.0.x 隧道。若直连报 EOF 关闭，请将 LocalDevVPN 改为下方同网段地址并重连：")
    }
    public static var engine1ACopiedTunnel: String { localized("engine1a_copied_tunnel", en: "✅ Copied Tunnel", zh: "✅ 已复制 Tunnel") }
    public static func engine1ACopyTunnel(_ cidr: String) -> String { localized("engine1a_copy_tunnel", en: "Copy Tunnel: \(cidr)", zh: "复制 Tunnel: \(cidr)") }
    public static var engine1ACopiedDevice: String { localized("engine1a_copied_device", en: "✅ Copied & Applied", zh: "✅ 已复制并设为网关") }
    public static func engine1ACopyDevice(_ cidr: String) -> String { localized("engine1a_copy_device", en: "Copy Device: \(cidr)", zh: "复制 Device: \(cidr) 并填入") }
    public static var engine1AReplacePairing: String { localized("engine1a_replace_pairing", en: "Replace Pairing File from Files (.plist)", zh: "从文件选择更换配对文件 (.plist)") }
    public static var engine1APickPairing: String { localized("engine1a_pick_pairing", en: "Option 1: Select Pairing File from Files (.plist / .mobiledevicepairing)", zh: "方式 1：从「文件」选择配对文件 (.plist / .mobiledevicepairing)") }
    public static var engine1APastePairing: String { localized("engine1a_paste_pairing", en: "Option 2: Paste Pairing Record from Clipboard", zh: "方式 2：从剪贴板一键粘贴配对文件（在系统文件长按 .plist 点拷贝）") }
    public static var engine1AConnectAndScan: String { localized("engine1a_connect_and_scan", en: "Connect to installation_proxy & Scan All Apps", zh: "立即直连 installation_proxy 并扫描全机应用") }
    public static var engine1APairingRemoved: String { localized("engine1a_pairing_removed", en: "Saved pairing file removed", zh: "已移除配对文件") }
    public static var engine1ARemovePairing: String { localized("engine1a_remove_pairing", en: "Remove Saved Pairing File", zh: "移除已保存的配对文件") }
    public static var engine1AHeader: String { localized("engine1a_header", en: "Engine 1A · Live Pairing Direct (or use 1B)", zh: "引擎 1A · 本机配对直连（与 1B 二选一）") }
    public static var engine1AFooter: String {
        localized("engine1a_footer",
                  en: "💡 Besides the picker or clipboard, you can place a .plist / .mobiledevicepairing file into Files → On My iPhone → WQGuard for automatic detection.",
                  zh: "💡 除了点选或剪贴板导入外，你也可以在系统『文件』App 中直接把配对 .plist 移入『我的 iPhone → WQGuard』文件夹，返回本页即会自动识别！")
    }

    // Engine 1B
    public static var engine1BTitle: String { localized("engine1b_title", en: "Mode B: Import Installed-App Registry Snapshot", zh: "方式 B：导入已安装应用注册表快照") }
    public static func engine1BCachedSnapshot(filename: String, count: Int) -> String {
        localized("engine1b_cached_snapshot", en: "Cached snapshot: \(filename) (\(count) installed apps)", zh: "已缓存快照: \(filename)（共 \(count) 款已安装应用）")
    }
    public static var engine1BSupportedFormats: String { localized("engine1b_supported_formats", en: "Supports Xcode devicectl (.json), pymobiledevice3 (.json), or .plist", zh: "支持 Mac 原生 devicectl (.json)、pymobiledevice3 (.json) 或 .plist") }
    public static var engine1BSelectSnapshot: String { localized("engine1b_select_snapshot", en: "Select Registry Snapshot (.json / .plist / .xml)", zh: "选择注册表快照文件 (.json / .plist / .xml)") }
    public static var engine1BCopyPymobile: String { localized("engine1b_copy_pymobile", en: "Copy pymobiledevice3 Export Command (Full Entitlements)", zh: "复制 pymobiledevice3 导出到桌面命令（推荐·全量权限）") }
    public static var engine1BCopyDeviceCtl: String { localized("engine1b_copy_devicectl", en: "Copy Xcode devicectl Export Command (No extra tools)", zh: "复制 Xcode devicectl 导出命令（已装 Xcode 免插件）") }
    public static var commonCopiedLabel: String { localized("common_copied", en: "Copied", zh: "已复制") }
    public static var engine1BSnapshotCleared: String { localized("engine1b_snapshot_cleared", en: "Cached snapshot cleared", zh: "已清除快照缓存") }
    public static var engine1BClearSnapshot: String { localized("engine1b_clear_snapshot", en: "Clear Cached Snapshot Data", zh: "清除已缓存的快照数据") }
    public static var engine1BIncludeAppStoreToggle: String { localized("engine1b_include_appstore", en: "Also show third-party App Store / TestFlight apps (excludes Apple OS)", zh: "同时展示第三方 App Store / TestFlight 应用（已排除苹果系统服务）") }
    public static var engine1BHeader: String { localized("engine1b_header", en: "Engine 1B · Offline Registry Snapshot (No VPN, 100% iOS 27 Compatible)", zh: "引擎 1B · 离线注册表快照（无需 VPN，100% 兼容 iOS 27）") }
    public static var engine1BFooter: String {
        localized("engine1b_footer",
                  en: "pymobiledevice3 is recommended as it exports complete Entitlements, Team IDs, and Signer identities across sideloaded, enterprise, TestFlight, and App Store apps to ~/Desktop/installed_apps.json. AirDrop the file to your iPhone to audit.",
                  zh: "推荐优先使用 pymobiledevice3 导出命令（可读取企业签、个人侧载、TestFlight 与官方应用的完整 Entitlements 权限表并直接输出到 Mac 桌面 ~/Desktop/installed_apps.json），隔空投送到手机即可一键完成全盘审计。")
    }

    // Engine 2
    public static var engine2AddIPAButton: String { localized("engine2_add_ipa_btn", en: "Select .ipa Files to Queue (Multi-Select)", zh: "选择 .ipa 文件加入扫描列表（支持多选）") }
    public static var engine2EmptyQueue: String {
        localized("engine2_empty_queue",
                  en: "No local .ipa files queued yet. Tap above to pick multiple .ipa / .tipa files in the Files app.",
                  zh: "尚未加入本地 .ipa 安装包。可点击上方按钮在系统『文件』中一次勾选多个 .ipa / .tipa 文件加入扫描列表。")
    }
    public static func engine2QueuedSummary(_ count: Int) -> String {
        localized("engine2_queued_summary", en: "Queued for scan (\(count) IPA files)", zh: "已加入扫描列表（共 \(count) 个 IPA）")
    }
    public static var engine2ClearedBanner: String { localized("engine2_cleared_banner", en: "Cleared all queued IPA files", zh: "已清空全部已加入的 IPA 扫描文件") }
    public static var engine2ClearAllButton: String { localized("engine2_clear_all_btn", en: "Clear All Queued IPA Files", zh: "清空全部已加入的 IPA 文件") }
    public static var engine2Header: String { localized("engine2_header", en: "Engine 2 · Local IPA Scan Queue (Multi-Select)", zh: "引擎 2 · 本地 IPA 扫描列表（支持多选）") }
    public static var engine2Footer: String {
        localized("engine2_footer",
                  en: "Queued .ipa / .tipa files are cached and automatically correlated by Bundle ID with the installed registry for deep Mach-O private symbol and dylib audits. For signed apps in Feather, tap Library → Signed → Export IPA.",
                  zh: "加入列表的所有 .ipa / .tipa 文件会自动缓存，并在扫描时按 Bundle ID 与全机注册表联动合并，深度审计 Mach-O 私有符号与注入动态库。Feather 已签应用可在 Feather「库 → 已签名 → 导出 IPA」后导入。")
    }

    // Engine 3
    public static var engine3Toggle: String { localized("engine3_toggle", en: "Enable on-device signer & privileged tool probe", zh: "启用本机已安装签名器与高权限环境探针") }
    public static var engine3Header: String { localized("engine3_header", en: "Engine 3 · Zero-Config On-Device Presence Probe", zh: "引擎 3 · 本机零配置在位探针（方案三）") }
    public static var engine3Footer: String {
        localized("engine3_footer",
                  en: "Checks standard iOS URL schemes to detect installed signers and privileged tools such as ESign, Feather, SideStore, StikDebug, Filza, TrollStore, and Sileo.",
                  zh: "通过标准系统接口探测本机是否已安装全能签、Feather、SideStore、StikDebug 以及 Filza、TrollStore、Sileo 等高权限容器环境工具。")
    }

    // Tutorial Steps & Banners
    public static var tutStep1Badge: String { localized("tut_step1_badge", en: "Step 1", zh: "第 1 步") }
    public static var tutStep2Badge: String { localized("tut_step2_badge", en: "Step 2", zh: "第 2 步") }
    public static var tutStep3Badge: String { localized("tut_step3_badge", en: "Step 3", zh: "第 3 步") }
    public static var tutStep4Badge: String { localized("tut_step4_badge", en: "Step 4", zh: "第 4 步") }
    public static var tutOverviewBadge: String { localized("tut_overview_badge", en: "Overview", zh: "作用说明") }
    public static var tutMethod1Badge: String { localized("tut_method1_badge", en: "Method 1", zh: "方法 ①") }
    public static var tutMethod2Badge: String { localized("tut_method2_badge", en: "Method 2", zh: "方法 ②") }

    public static var tutModeBStep1Title: String { localized("tut_mb_s1_title", en: "Open Terminal on Mac & install pymobiledevice3", zh: "在 Mac 上打开「终端」并安装 pymobiledevice3") }
    public static var tutModeBStep1Detail: String {
        localized("tut_mb_s1_detail",
                  en: "1. Press Command ⌘ + Space on your Mac, type Terminal, and hit Return.\n2. Tap the button below to copy the install command, paste it into Terminal, and press Return (one-time setup; if macOS asks to install Command Line Tools click Install; if Xcode is already installed you can skip to the devicectl button below):",
                  zh: "1. 在 Mac 键盘同时按下 Command ⌘ + 空格，输入「终端」(Terminal) 回车打开。\n2. 点击下方按钮复制安装命令，粘贴到 Mac 终端窗口按回车运行（只需安装一次；若弹窗提示安装命令行工具点「安装」即可；若你电脑已安装苹果官方 Xcode 也可跳过此步用下方 Xcode 命令）：")
    }
    public static var tutModeBInstallCopied: String { localized("tut_mb_install_copied", en: "✅ Copied Mac install command", zh: "✅ 已复制 Mac 安装命令") }
    public static var tutModeBInstallCopyBtn: String { localized("tut_mb_install_btn", en: "📋 Copy Mac install command (brew / pip)", zh: "📋 复制 Mac 安装工具命令 (brew / pip)") }

    public static var tutModeBStep2Title: String { localized("tut_mb_s2_title", en: "Connect iPhone to Mac via USB & tap Trust", zh: "数据线连接 iPhone 与 Mac，点击「信任」") }
    public static var tutModeBStep2Detail: String {
        localized("tut_mb_s2_detail",
                  en: "1. Connect your iPhone to your Mac using a data-capable USB / USB-C cable and keep it unlocked on the Home Screen.\n2. When prompted with \"Trust This Computer?\" on iPhone, tap Trust and enter your passcode.\n3. Open Finder on your Mac, click your iPhone in the sidebar, and click Trust if shown.",
                  zh: "1. 用支持数据传输的 USB / Type-C 数据线将 iPhone 插入 Mac，解锁手机保持在桌面亮屏。\n2. 手机屏幕弹出「要信任此电脑吗？」时，点击「信任」并输入手机锁屏密码。\n3. 打开 Mac 左下角「访达」(Finder)，在左侧栏点一下你的 iPhone，若右侧也显示「信任」按钮请点一下。")
    }

    public static var tutModeBStep3Title: String { localized("tut_mb_s3_title", en: "Export snapshot to Mac Desktop in Terminal", zh: "在 Mac 终端一键导出快照文件到桌面") }
    public static var tutModeBStep3Detail: String {
        localized("tut_mb_s3_detail",
                  en: "Tap below to copy the export command, paste it via Universal Clipboard into Mac Terminal, and hit Return. Wait 3–8 seconds until \"✅ Exported\" prints — `installed_apps.json` will appear on your Mac Desktop:",
                  zh: "点击下方按钮复制导出命令，可通过微信/通用剪贴板发到 Mac，粘贴进「终端」按回车。等待约 3～8 秒看到“✅ 已导出到桌面”后，Mac 桌面就会出现 installed_apps.json 文件：")
    }
    public static var tutModeBExportCopied: String { localized("tut_mb_export_copied", en: "✅ Copied Desktop export command", zh: "✅ 已复制导出到桌面命令") }
    public static var tutModeBExportCopyBtn: String { localized("tut_mb_export_btn", en: "📋 Copy export command (saves to Mac Desktop)", zh: "📋 复制导出命令（自动存到 Mac 桌面）") }

    public static var tutModeBStep4Title: String { localized("tut_mb_s4_title", en: "AirDrop to iPhone & import into WQGuard", zh: "隔空投送到 iPhone 并导入 WQGuard") }
    public static var tutModeBStep4Detail: String {
        localized("tut_mb_s4_detail",
                  en: "1. Right-click `installed_apps.json` on your Mac Desktop → Share → AirDrop to your iPhone.\n2. Choose \"Open in WQGuard\" to scan immediately, or \"Save to Files\" and select it via Engine 1B below.",
                  zh: "1. 在 Mac 桌面上右键点击 installed_apps.json → 选择「共享」→「隔空投送 (AirDrop)」发给你的 iPhone（或通过微信文件传输助手发送）。\n2. 手机收到后直接选「用 WQGuard 打开」自动开扫；或者选「存储到“文件”」，再点本页下方引擎 1B 的「选择注册表快照文件」选中它即可！")
    }

    public static var tutModeAStep1Title: String { localized("tut_ma_s1_title", en: "iPhone Setup: Install free app LocalDevVPN", zh: "手机端下载什么？安装免费 App「LocalDevVPN」") }
    public static var tutModeAStep1Detail: String {
        localized("tut_ma_s1_detail",
                  en: "Search the App Store on your iPhone and install the free app LocalDevVPN (if you already have StikDebug or SideStore installed, you can also use their built-in loopback tunnel).",
                  zh: "打开 iPhone 的 App Store，搜索并免费下载安装「LocalDevVPN」（如果你手机上已经装有 StikDebug 或 SideStore，也可直接使用它们内置的隧道）。")
    }
    public static var tutModeAStep2Title: String { localized("tut_ma_s2_title", en: "Mac Setup: Generate pairing record with jitterbugpair", zh: "Mac 端下载什么？用 jitterbugpair 生成配对文件") }
    public static var tutModeAStep2Detail: String {
        localized("tut_ma_s2_detail",
                  en: "• Already have a `.mobiledevicepairing` or `.plist` from SideStore / StikDebug? Skip straight to Step 3 and reuse it!\n• First-time setup:\n  1. Download `jitterbugpair-macos.zip` from `github.com/osy/JitterBug/releases` and unzip `jitterbugpair`;\n  2. Connect iPhone to Mac via USB, unlock screen, and tap Trust;\n  3. Open Terminal on Mac, run `cd ~/Desktop`, then drag `jitterbugpair` into Terminal and press Return (if macOS blocks an unidentified developer, allow it in System Settings → Privacy & Security and run again);\n  4. `<Device-UDID>.mobiledevicepairing` will be created on your Mac Desktop.",
                  zh: "• 如果你以前给 SideStore / StikDebug 生成过 .mobiledevicepairing 或 .plist 配对文件，直接跳到第 3 步复用即可！\n• 首次生成操作：\n  1. 在 Mac 浏览器打开 github.com/osy/JitterBug/releases 下载 jitterbugpair-macos.zip 并双击解压出 jitterbugpair；\n  2. 数据线把 iPhone 连上 Mac，解锁手机亮屏点「信任」输密码；\n  3. 打开 Mac「终端」，先输入 cd ~/Desktop 回车，再把解压出的 jitterbugpair 拖进终端窗口按回车运行（若 Mac 拦截未验证开发者，前往 Mac「系统设置 → 隐私与安全性」底部点「仍要打开」后再运行一次）；\n  4. 运行成功后，Mac 桌面即会生成 <手机UDID>.mobiledevicepairing 配对文件！")
    }
    public static var tutModeACdCopied: String { localized("tut_ma_cd_copied", en: "✅ Copied cd ~/Desktop", zh: "✅ 已复制 cd ~/Desktop") }
    public static var tutModeACdCopyBtn: String { localized("tut_ma_cd_btn", en: "📋 Copy Desktop directory command (cd ~/Desktop)", zh: "📋 复制终端切换桌面目录命令 (cd ~/Desktop)") }

    public static var tutModeAStep3Title: String { localized("tut_ma_s3_title", en: "Transfer pairing record & import into Engine 1A", zh: "把配对文件传到手机并导入引擎 1A") }
    public static var tutModeAStep3Detail: String {
        localized("tut_ma_s3_detail",
                  en: "Right-click `<UDID>.mobiledevicepairing` on your Mac Desktop → Share → AirDrop to iPhone → Save to Files (e.g. On My iPhone → WQGuard), then import it under Engine 1A below.",
                  zh: "在 Mac 桌面右键该 .mobiledevicepairing 文件 →「共享 → 隔空投送」发到 iPhone → 选「存储到“文件”」（建议存到『我的 iPhone → WQGuard』目录），然后点本页下方引擎 1A 的「从文件选择配对文件」导入。")
    }
    public static var tutModeAStep4Title: String { localized("tut_ma_s4_title", en: "Enable VPN & Align Subnet (iOS 26.4+ / iOS 27)", zh: "开启 VPN 直连（iOS 26.4+ / iOS 27 子网对齐）") }
    public static var tutModeAStep4Detail: String {
        localized("tut_ma_s4_detail",
                  en: "• iOS 26.3 or earlier: Open LocalDevVPN, tap Connect, then tap \"Connect to installation_proxy & Scan\" below.\n• iOS 26.4+ / iOS 27 required: Apple requires the tunnel to match your active Wi-Fi subnet. While on Wi-Fi, tap Copy Tunnel & Copy Device in the orange notice below, paste them into LocalDevVPN ⚙️ Settings, reconnect VPN, then scan below (allow Local Network access if prompted).",
                  zh: "• iOS 26.3 及更早：打开 LocalDevVPN 点 Connect 连接，回本页点「立即直连扫描」即可。\n• iOS 26.4+ / iOS 27 必做：苹果要求隧道与当前 Wi-Fi 同网段。保持手机连 Wi-Fi，先点下方橙色提示框的「复制 Tunnel」，打开 LocalDevVPN 右上角 ⚙️ 设置粘贴到 Tunnel IP；再回本页点「复制 Device 并填入」粘贴到 LocalDevVPN 的 Device IP，保存并重连 VPN，回 WQGuard 点「立即直连扫描」（首次弹窗允许本地网络权限）即可 1 秒扫完全机！")
    }

    public static var tutEngine2OverviewTitle: String { localized("tut_e2_overview_title", en: "Why combine Engine 2 multi-select .ipa scanning?", zh: "为什么可以配合引擎 2 多选加入 .ipa 文件？") }
    public static var tutEngine2OverviewDetail: String {
        localized("tut_e2_overview_detail",
                  en: "Mode A / B audits signing identities, App Groups, and entitlements across all installed apps, while iOS sandbox isolation blocks reading other apps' Mach-O executables directly from disk. Adding `.ipa` files via Engine 2 automatically correlates them by Bundle ID with the registry, upgrading results to \"🔬 Full Binary Audit\" to catch containermanagerd exploit symbols and injected dylibs.",
                  zh: "方式 A / B 能查出全机所有应用的签名证书、App Groups 与越权权限表，而受 iOS 沙盒隔离限制无法直接拆包其他已安装应用的主程序。通过下方「引擎 2」将侧载应用的 .ipa 文件加入扫描列表后，WQGuard 会按 Bundle ID 自动将注册表与二进制合并升级为「🔬 全量深扫」，精准检出 containermanagerd 漏洞符号与注入动态库！")
    }
    public static var tutEngine2Method1Title: String { localized("tut_e2_m1_title", en: "Multi-select local .ipa files from Files", zh: "手动多选本地 .ipa 文件加入扫描列表") }
    public static var tutEngine2Method1Detail: String {
        localized("tut_e2_m1_detail",
                  en: "Tap \"Select .ipa Files to Queue\" under Engine 2 below, browse in Files (Downloads, Feather/Unsigned, etc.), select multiple `.ipa` / `.tipa` files at once, and tap Open.",
                  zh: "点击本页下方引擎 2 的「选择 .ipa 文件加入扫描列表（支持多选）」，进入系统『文件』App（例如「下载项」、『我的 iPhone → Feather → Unsigned』或任意保存安装包的目录），可一次勾选多个 .ipa / .tipa 文件点右上角「打开」批量加入扫描！")
    }
    public static var tutEngine2Method2Title: String { localized("tut_e2_m2_title", en: "Export signed IPA directly from Feather / ESign", zh: "在 Feather / 全能签内导出已签名 IPA") }
    public static var tutEngine2Method2Detail: String {
        localized("tut_e2_m2_detail",
                  en: "If tweaks (.dylib) were injected during signing, open Feather → Library → Signed → tap the app → Export IPA → Open in WQGuard (or Save to Files and multi-select below).",
                  zh: "如果某个应用在签名时额外注入了插件（dylib），可打开 Feather → 底部「库」→ 在「已签名」列表点击该应用 → 选择「导出 IPA」→ 直接选「WQGuard」（或先「存储到“文件”」再回 WQGuard 多选导入）。")
    }

    public static func bannerClipboardPairingScanning(_ summary: String) -> String {
        localized("banner_clipboard_pairing_scanning", en: "✅ Clipboard imported: \(summary) — connecting & scanning...", zh: "✅ 剪贴板导入成功：\(summary) — 正在直连扫描...")
    }
    public static func bannerFilePairingScanning(_ summary: String) -> String {
        localized("banner_file_pairing_scanning", en: "\(summary) — connecting via LocalDevVPN...", zh: "\(summary) — 正在通过 LocalDevVPN 直连扫描...")
    }
    public static func bannerQueuedIPAsScanning(_ count: Int) -> String {
        localized("banner_queued_ipas_scanning", en: "✅ Added \(count) IPA(s) to queue; scanning...", zh: "✅ 已加入 \(count) 个 IPA 至扫描列表，正在执行扫描...")
    }

    // Threat Indicators
    public static let indicatorMapZh: [String: String] = [
        IOCTokenArmor.tCqCreate: "私有容器查询创建调用 (containermanagerd 跨沙盒利用入口)",
        IOCTokenArmor.tCqCopyToken: "私有沙盒扩展令牌签发请求 (绕过系统访问控制)",
        IOCTokenArmor.tContainerMgrDylib: "引用私有容器管理器动态库",
        "com.apple.containermanagerd": "直接 XPC 访问容器管理守护进程",
        IOCTokenArmor.tFsgetpath: "底层 APFS Inode 路径暴力破解枚举调用",
        "escaping_symlink": "共享容器内异常逃逸符号链接 (S_ISLNK 指向外部路径)",
        "PhotoLibraryServices": "私有相册服务框架引用 (CVE-2026-112676 隐私绕过)",
        "BrotliDecoderDecompressStream": "嵌入第三方易受攻击的 libbrotli 解码库 (CVE-2026-111497)"
    ]
}
