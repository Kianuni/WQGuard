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
    private static var isEnglish: Bool {
        let pref = Locale.preferredLanguages.first?.lowercased() ?? "en"
        return !pref.hasPrefix("zh")
    }

    private static func localized(_ key: String, en: String, zh: String) -> String {
        let val = NSLocalizedString(key, tableName: "Localizable", bundle: .main, value: isEnglish ? en : zh, comment: "")
        if val == key {
            return isEnglish ? en : zh
        }
        return val
    }

    // MARK: - Tabs
    public static var tabDashboard: String { localized("tab_dashboard", en: "Dashboard", zh: "仪表盘") }
    public static var tabFindings: String { localized("tab_findings", en: "Findings", zh: "审计发现") }
    public static var tabIPAScan: String { localized("tab_ipa_scan", en: "IPA Scan", zh: "IPA 审查") }
    public static var tabFirmwareRadar: String { localized("tab_firmware_radar", en: "Firmware Radar", zh: "固件雷达") }
    public static var tabSettings: String { localized("tab_settings", en: "Settings", zh: "设置与规则") }

    // MARK: - Dashboard Overview
    public static var appTitle: String { localized("app_title", en: "WQGuard", zh: "WQGuard 容器守卫") }
    public static var startSystemScan: String { localized("start_system_scan", en: "Scan Self-Signed Apps", zh: "一键扫描自签应用") }
    public static var startSystemScanSub: String { localized("start_system_scan_sub", en: "Scans sideloaded/self-signed apps & bound signing directories", zh: "扫描已绑定的签名工具目录与本机自签包") }
    public static var bindSigningFolderButton: String { localized("bind_signing_folder_btn", en: "Bind Signer Folder", zh: "绑定签名工具目录") }
    public static var selectIPAFileButton: String { localized("select_ipa_file_btn", en: "Select .ipa Files", zh: "直接选择 .ipa 文件") }
    public static var batchImportIPAButton: String { localized("batch_import_ipa_button", en: "Select Signing Folder / Import IPAs", zh: "绑定自签工具目录 / 导入 IPA") }
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
    public static var firmwareRadarSub: String { localized("firmware_radar_sub", en: "Unpatched CVEs · Surge Shield export", zh: "项待防护系统漏洞 · Surge 护盾一键导出") }
    public static var exportAuditReport: String { localized("export_audit_report", en: "Export Audit Report", zh: "导出审计报告") }
    public static var exportAuditReportSub: String { localized("export_audit_report_sub", en: "Generate RFC 8259 JSON / Markdown / PlainText reports", zh: "生成 RFC 8259 JSON / Markdown / 纯文本审计报告") }

    // MARK: - Posture Hero Card
    public static var postureDeepAnalyzing: String { localized("posture_deep_analyzing", en: "Analyzing:", zh: "正在深度分析:") }
    public static var postureStatusScanningTitle: String { localized("posture_status_scanning_title", en: "Deep Audit in Progress...", zh: "深度审计进行中...") }
    public static var postureStatusHighRiskTitle: String { localized("posture_status_high_risk_title", en: "High Risk Warning", zh: "高危越权告警") }
    public static var postureStatusCautionTitle: String { localized("posture_status_caution_title", en: "Caution Advised", zh: "前置条件留意") }
    public static var postureStatusKnownToolTitle: String { localized("posture_status_known_tool_title", en: "Known Research Tools Detected", zh: "发现已知定制工具") }
    public static var postureStatusSafeTitle: String { localized("posture_status_safe_title", en: "System Posture Safe & Compliant", zh: "系统状态安全合规") }

    public static var postureStatusScanningSub: String { localized("posture_status_scanning_sub", en: "Scanning Mach-O private symbols & shared container symlink traversals...", zh: "正在执行 Mach-O 私有符号检索与共享容器逃逸符号链接排查") }
    public static var postureStatusHighRiskSub: String { localized("posture_status_high_risk_sub", en: "Detected unauthorized containermanagerd sandbox escape or escaping symlinks!", zh: "检测到未经授权的 containermanagerd 跨沙盒利用或异常逃逸符号链接！") }
    public static var postureStatusCautionSub: String { localized("posture_status_caution_sub", en: "App declares App Group shared containers with dynamic symbol resolution.", zh: "应用声明了 App Group 容器共享权限并伴随动态符号解析特征。") }
    public static var postureStatusKnownToolSub: String { localized("posture_status_known_tool_sub", en: "Matched authorized open-source research tools (Erosion, WQFiles, etc.).", zh: "匹配到白名单授权的开源定制工具（Erosion、WQFiles 等）。") }
    public static var postureStatusSafeSub: String { localized("posture_status_safe_sub", en: "All scanned targets strictly comply with iOS sandbox boundaries.", zh: "所有已扫描目标严格遵守 iOS 沙盒边界，未检出跨容器越权利用。") }

    public static func posturePendingTitle(exposedCount: Int) -> String {
        if exposedCount > 0 {
            return localized("posture_pending_cve_title_\(exposedCount)", en: "Pending App Audit · \(exposedCount) Firmware CVEs", zh: "待执行应用审计 · \(exposedCount) 项固件漏洞")
        }
        return localized("posture_pending_clean_title", en: "Ready · Pending App Audit", zh: "就绪 · 待执行安全检测")
    }

    public static func posturePendingSubtitle(exposedCount: Int, isFullScanEnabled: Bool = false) -> String {
        if exposedCount > 0 {
            return localized("posture_pending_cve_sub", en: "Unpatched firmware CVEs detected. Tap below to scan self-signed apps or import local IPAs.", zh: "当前 iOS 存在未修补系统漏洞。请点击下方扫描自签应用或绑定签名工具目录（Feather / SideStore / AltStore 等）。")
        }
        return localized("posture_pending_clean_sub", en: "Tap below to scan self-signed apps or import local IPA packages.", zh: "请点击下方按钮扫描自签应用或导入本地 IPA 安装包。")
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
    public static var selectIPAButton: String { localized("select_ipa_button", en: "Select .ipa Files or Folder", zh: "选择 .ipa 文件或文件夹（可多选）") }
    public static var batchIPANoValidTargets: String { localized("batch_ipa_no_targets", en: "No .ipa or .app packages found in the selected items.", zh: "所选文件或目录中未找到可审计的 .ipa 或 .app 安装包。") }
    public static func batchIPACompletedBanner(_ count: Int) -> String {
        localized("batch_ipa_completed_\(count)", en: "Batch audit completed: \(count) packages inspected (see Findings tab for full list)", zh: "已完成批量审查：共检测 \(count) 个安装包（完整列表已同步至「仪表盘」与「审计发现」）")
    }
    public static var ipaAnalyzing: String { localized("ipa_analyzing", en: "Performing 4-layer sandbox analysis & Mach-O static decompilation...", zh: "正在进行 4 层沙盒解析与 Mach-O 静态反编译...") }
    public static var ipaAnalysisFailed: String { localized("ipa_analysis_failed", en: "IPA Analysis Failed", zh: "IPA 分析失败") }
    public static var preinstallAlertHighRisk: String { localized("preinstall_alert_high_risk", en: "Pre-install Warning: Detected sandbox escape exploit! Do NOT install!", zh: "安装前预警：检测到越界沙盒逃逸特征，切勿安装！") }
    public static var preinstallAlertSafe: String { localized("preinstall_alert_safe", en: "Pre-install Assessment: Clean. No exploit signatures detected.", zh: "安装前评估：未发现已知越权利用特征，处于安全状态。") }

    public static var ipaDistributionChannel: String { localized("ipa_distribution_channel", en: "Distribution Channel", zh: "分发渠道") }
    public static var ipaTeamIdSelfSigned: String { localized("ipa_team_id_self_signed", en: "None (Ad-hoc / Self-signed)", zh: "无 (Ad-hoc / 个人自签)") }
    public static var ipaDrmEncrypted: String { localized("ipa_drm_encrypted", en: "FairPlay Encrypted (cryptid: 1)", zh: "FairPlay 加密 (cryptid: 1)") }
    public static var ipaDrmUnencrypted: String { localized("ipa_drm_unencrypted", en: "Unencrypted (cryptid: 0, full static decompilation completed)", zh: "未加密 (cryptid: 0, 完整静态反编译已完成)") }
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
        localized("surge_shield_title", en: "Surge · Brotli Downgrade Shield", zh: "Surge · 防 Brotli 溢出降级护盾")
    }

    public static var surgeShieldDescription: String {
        localized("surge_shield_description",
                  en: "Enforces stripping br compression at the network layer for unpatched iOS 26/27 libbrotli heap overflow vulnerabilities. Built-in 16 strict exclusion rules ensure Apple Intelligence, Siri, and banking payments are never intercepted.",
                  zh: "针对未修复 iOS 26/27 系统的 libbrotli 堆溢出高危漏洞，在网络传输层强制剥离 br 压缩声明。内置 16 项严苛负向排除规则，保障 Apple Intelligence、普通话 Siri 与网银支付绝对不被拦截。")
    }

    public static var surgeShieldPreview: String {
        localized("surge_shield_preview", en: "Preview Shield Rules", zh: "预览护盾规则")
    }

    public static var surgeShieldExport: String {
        localized("surge_shield_export", en: "Export / Share Module", zh: "一键导出 / 分享模块")
    }

    public static func radarKnownVulnerabilitiesHeader(count: Int) -> String {
        let format = localized("radar_known_vulns_header", en: "Firmware Known High-Risk CVE Assessment (%d items)", zh: "固件已知高危漏洞暴露评估 (%d 项)")
        return String(format: format, count)
    }

    public static var radarMitigationGuidanceHeader: String {
        localized("radar_mitigation_guidance_header", en: "🛡️ Non-Upgrade Mitigation Advisories", zh: "🛡️ 不升级固件下的缓解处置建议")
    }

    public static var radarBranchLTS: String {
        localized("radar_branch_lts", en: "iOS 26.x LTS Branch (Surge Shield Recommended)", zh: "iOS 26.x 长期支持分支 (推荐配置 Surge 护盾)")
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

    // MARK: - Surge Module Sheet
    public static var surgeSheetCodeTitle: String {
        localized("surge_sheet_code_title", en: "WQGuard · Brotli Shield Module Code", zh: "WQGuard · 防 Brotli 溢出降级护盾模块代码")
    }

    public static var surgeSheetNavTitle: String {
        localized("surge_sheet_nav_title", en: "Surge Shield Preview", zh: "Surge 护盾预览")
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
                  en: "This will remove all custom whitelist rules and restore the 6 built-in research tools to enabled state.",
                  zh: "将清除所有自定义规则，并将内置 6 款开源工具恢复为默认启用状态。")
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

    // Threat Indicators
    public static let indicatorMapZh: [String: String] = [
        "container_query_create": "私有容器查询创建调用 (containermanagerd 跨沙盒利用入口)",
        "container_copy_sandbox_token": "私有沙盒扩展令牌签发请求 (绕过系统访问控制)",
        "libsystem_containermanager.dylib": "引用私有容器管理器动态库",
        "com.apple.containermanagerd": "直接 XPC 访问容器管理守护进程",
        "fsgetpath": "底层 APFS Inode 路径暴力破解枚举调用",
        "escaping_symlink": "共享容器内异常逃逸符号链接 (S_ISLNK 指向外部路径)",
        "PhotoLibraryServices": "私有相册服务框架引用 (CVE-2026-112676 隐私绕过)",
        "BrotliDecoderDecompressStream": "嵌入第三方易受攻击的 libbrotli 解码库 (CVE-2026-111497)"
    ]
}
