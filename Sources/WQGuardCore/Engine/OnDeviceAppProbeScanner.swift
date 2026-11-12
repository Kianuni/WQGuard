//
//  OnDeviceAppProbeScanner.swift
//  WQGuardCore
//
//  Option 3 Engine: 100% standard iOS SDK URL-scheme presence probe (`canOpenURL` paired
//  with `LSApplicationQueriesSchemes`) that inventories installed sideloading signers,
//  LocalDevVPN debuggers, unsandboxed file managers, and bootstrap package managers
//  directly on device with zero configuration.
//

import Foundation
#if canImport(UIKit)
import UIKit
#endif

public struct AppProbeDefinition: Sendable, Equatable {
    public enum ProbeRole: String, Sendable, Equatable {
        case sideloadSigner
        case localDevDebugger
        case privilegedContainerTool
    }

    public let displayName: String
    public let canonicalBundleId: String
    public let schemes: [String]
    public let role: ProbeRole
    public let summaryZh: String

    public init(
        displayName: String,
        canonicalBundleId: String,
        schemes: [String],
        role: ProbeRole,
        summaryZh: String
    ) {
        self.displayName = displayName
        self.canonicalBundleId = canonicalBundleId
        self.schemes = schemes
        self.role = role
        self.summaryZh = summaryZh
    }
}

public final class OnDeviceAppProbeScanner: @unchecked Sendable {
    public static let shared = OnDeviceAppProbeScanner()

    public static let defaultCatalog: [AppProbeDefinition] = [
        AppProbeDefinition(
            displayName: "全能签 / ESign",
            canonicalBundleId: "p3.xyz.yyyue.esign",
            schemes: ["esign"],
            role: .sideloadSigner,
            summaryZh: "本机已安装侧载签名工具「全能签 / ESign」。可将其导出的 .ipa 文件多选加入扫描列表，对该工具签发的应用执行二进制深扫。"
        ),
        AppProbeDefinition(
            displayName: "Feather",
            canonicalBundleId: "kh.crysalis.feather",
            schemes: ["feather"],
            role: .sideloadSigner,
            summaryZh: "本机已安装开源侧载签名器 Feather。可在 Feather「库 → 已签名 → 导出 IPA」或手动多选本地 .ipa 文件加入扫描列表进行深扫。"
        ),
        AppProbeDefinition(
            displayName: "SideStore",
            canonicalBundleId: "com.SideStore.SideStore",
            schemes: ["sidestore"],
            role: .sideloadSigner,
            summaryZh: "本机已安装无线自签管理器 SideStore。可直接复用其配对文件 (.mobiledevicepairing) 开启全机已安装应用注册表审计。"
        ),
        AppProbeDefinition(
            displayName: "AltStore",
            canonicalBundleId: "com.rileytestut.AltStore",
            schemes: ["altstore"],
            role: .sideloadSigner,
            summaryZh: "本机已安装自签管理器 AltStore。"
        ),
        AppProbeDefinition(
            displayName: "GBox",
            canonicalBundleId: "com.gbox.pub",
            schemes: ["gbox"],
            role: .sideloadSigner,
            summaryZh: "本机已安装侧载签名工具 GBox。可手动多选其 .ipa 文件加入扫描列表进行二进制审计。"
        ),
        AppProbeDefinition(
            displayName: "Scarlet",
            canonicalBundleId: "com.DebianArch.Scarlet",
            schemes: ["scarlet"],
            role: .sideloadSigner,
            summaryZh: "本机已安装侧载安装器 Scarlet。"
        ),
        AppProbeDefinition(
            displayName: "StikDebug / LocalDevVPN",
            canonicalBundleId: "com.stik.stikdebug",
            schemes: ["stikdebug", "stikjit"],
            role: .localDevDebugger,
            summaryZh: "本机已安装 StikDebug 本地环回调试工具。开启其 VPN 后配合配对文件即可在 WQGuard 内直连本机 installation_proxy 读取全机已安装应用！"
        ),
        AppProbeDefinition(
            displayName: "LocalDevVPN",
            canonicalBundleId: "com.SideStore.LocalDevVPN",
            schemes: ["localdevvpn"],
            role: .localDevDebugger,
            summaryZh: "本机已安装 LocalDevVPN 本地环回隧道工具。连接 VPN 后配合配对文件即可在 WQGuard 内直连本机 installation_proxy 读取全机已安装应用。"
        ),
        AppProbeDefinition(
            displayName: "TrollStore",
            canonicalBundleId: "com.opa334.TrollStore",
            schemes: ["trollstore"],
            role: .privilegedContainerTool,
            summaryZh: "本机探针检出持久化安装器 TrollStore，环境支持任意无沙盒 (no-sandbox) 权限应用驻留，建议开启系统注册表全量权限审计。"
        ),
        AppProbeDefinition(
            displayName: "Filza File Manager",
            canonicalBundleId: "com.tigisoftware.Filza",
            schemes: ["filza"],
            role: .privilegedContainerTool,
            summaryZh: "本机探针检出无沙盒文件管理器 Filza，具备跨应用数据容器直接读写权限。"
        ),
        AppProbeDefinition(
            displayName: "Santander",
            canonicalBundleId: "com.serena.Santander",
            schemes: ["santander"],
            role: .privilegedContainerTool,
            summaryZh: "本机探针检出跨容器文件管理器 Santander。"
        ),
        AppProbeDefinition(
            displayName: "Sileo",
            canonicalBundleId: "org.coolstar.SileoStore",
            schemes: ["sileo"],
            role: .privilegedContainerTool,
            summaryZh: "本机探针检出越狱/Bootstrap 软件包管理器 Sileo，系统沙盒与动态库注入防护可能处于非标准状态。"
        ),
        AppProbeDefinition(
            displayName: "Zebra",
            canonicalBundleId: "xyz.willy.Zebra",
            schemes: ["zbra"],
            role: .privilegedContainerTool,
            summaryZh: "本机探针检出越狱软件包管理器 Zebra。"
        )
    ]

    private let whitelistEngine: WhitelistEngine

    public init(whitelistEngine: WhitelistEngine = .shared) {
        self.whitelistEngine = whitelistEngine
    }

    /// Runs the URL-scheme probe catalog on the current iOS device.
    public func probeInstalledAppsAsync() async -> [ScanFinding] {
        #if canImport(UIKit) && os(iOS)
        return await MainActor.run {
            self.evaluateProbes { scheme in
                guard let url = URL(string: "\(scheme)://") else { return false }
                return UIApplication.shared.canOpenURL(url)
            }
        }
        #else
        return []
        #endif
    }

    /// Deterministic evaluator accepting a scheme-checker closure (enables unit testing on macOS & iOS).
    public func evaluateProbes(
        catalog: [AppProbeDefinition] = OnDeviceAppProbeScanner.defaultCatalog,
        canOpenScheme: (String) -> Bool
    ) -> [ScanFinding] {
        var findings: [ScanFinding] = []

        for item in catalog {
            var matchedScheme: String?
            for scheme in item.schemes {
                if canOpenScheme(scheme) {
                    matchedScheme = scheme
                    break
                }
            }
            guard let activeScheme = matchedScheme else { continue }

            var indicators: [ThreatIndicator] = []
            var provisionalRisk: RiskTier = .knownTool

            switch item.role {
            case .sideloadSigner, .localDevDebugger:
                provisionalRisk = .knownTool
            case .privilegedContainerTool:
                provisionalRisk = .caution
                indicators.append(ThreatIndicator(
                    signature: "URLScheme(\(activeScheme)://)",
                    description: item.summaryZh,
                    category: "Privileged Environment Tool",
                    location: "UIApplication.canOpenURL(\(activeScheme)://)",
                    severity: .caution
                ))
            }

            let wl = whitelistEngine.isWhitelisted(
                bundleId: item.canonicalBundleId,
                appGroups: [],
                matchedSignatures: [],
                teamId: nil
            )
            let finalRisk: RiskTier = wl.isWhitelisted ? .knownTool : provisionalRisk

            let evidence = AuditEvidence(
                matchedSymbols: [],
                linkedDylibs: [],
                hasAppGroups: false,
                appGroups: [],
                installChannel: .developerSideloaded,
                cryptid: 0,
                isFairPlayEncrypted: false,
                escapingSymlinks: [],
                dynamicLoadingPresent: false,
                pathEnumerationPresent: false,
                remediationGuidance: item.summaryZh,
                auditDepth: .onDeviceProbe,
                signerIdentity: nil
            )

            findings.append(ScanFinding(
                bundleId: item.canonicalBundleId,
                displayName: item.displayName,
                version: "已安装 (本机探针)",
                teamId: nil,
                executablePath: nil,
                bundlePath: "\(activeScheme):// (本机在位)",
                installChannel: .developerSideloaded,
                riskTier: finalRisk,
                isWhitelisted: wl.isWhitelisted || item.role != .privilegedContainerTool,
                whitelistedToolName: wl.toolName ?? (item.role != .privilegedContainerTool ? item.displayName : nil),
                indicators: indicators,
                evidence: evidence,
                scanTimestamp: Date()
            ))
        }

        return findings
    }
}
