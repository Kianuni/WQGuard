//
//  EntitlementGating.swift
//  WQGuardCore
//
//  Layer 1 Gating Invariant: Fast-paths applications lacking `com.apple.security.application-groups`
//  as physically incapable of triggering containermanagerd sandbox escapes.
//

import Foundation

/// Result of evaluating Layer 1 Entitlement Fast-Path Gating.
public struct EntitlementGatingResult: Sendable, Equatable {
    /// True if the application was fast-pathed out at Layer 1.
    public let isGatedOut: Bool
    
    /// Resulting risk tier if gated out (.safe). If not gated out, represents baseline (.safe).
    public let riskTier: RiskTier
    
    /// Discovered App Group identifiers.
    public let appGroups: [String]
    
    /// Whether the scan pipeline must proceed to Layer 2 deep static inspection.
    public let shouldProceedToDeepScan: Bool
    
    /// Technical explanation and physical reasoning for this gating decision.
    public let reason: String
    
    public init(
        isGatedOut: Bool,
        riskTier: RiskTier,
        appGroups: [String],
        shouldProceedToDeepScan: Bool,
        reason: String
    ) {
        self.isGatedOut = isGatedOut
        self.riskTier = riskTier
        self.appGroups = appGroups
        self.shouldProceedToDeepScan = shouldProceedToDeepScan
        self.reason = reason
    }
}

/// Evaluates Layer 1 Gating Invariant:
/// An application lacking `com.apple.security.application-groups` is physically and mathematically
/// incapable of triggering or exploiting containermanagerd confused deputy cross-container sandbox escapes.
public enum EntitlementGating {
    
    /// Evaluates gating given an entitlement presence flag and list of application group identifiers.
    public static func evaluate(hasAppGroups: Bool, appGroups: [String]) -> EntitlementGatingResult {
        let validGroups = appGroups.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        if !hasAppGroups || validGroups.isEmpty {
            return EntitlementGatingResult(
                isGatedOut: true,
                riskTier: .safe,
                appGroups: [],
                shouldProceedToDeepScan: false,
                reason: "Layer 1 Fast-Path Gated: 应用未声明 com.apple.security.application-groups 共享容器权限。AMFI 与 Darwin 内核在物理上无法签发属于该进程的 App Group 跨容器沙盒令牌（containermanagerd 严格校验客户端凭证），亦无对应共享 Library/Caches 目录可供放置逃逸符号链接，物理上无法实施 containermanagerd 跨沙盒攻击。安全放行。"
            )
        } else {
            return EntitlementGatingResult(
                isGatedOut: false,
                riskTier: .safe,
                appGroups: validGroups,
                shouldProceedToDeepScan: true,
                reason: "Layer 1 Gating Proceed: 应用声明了 com.apple.security.application-groups 共享容器权限 (\(validGroups.joined(separator: ", ")))，满足与 containermanagerd 交互的前置条件，必须继续执行 Layer 2 Mach-O 静态深度扫描。"
            )
        }
    }
    
    /// Evaluates gating from a parsed entitlements dictionary (from XML or DER CSBlob).
    public static func evaluate(entitlements: [String: Any]) -> EntitlementGatingResult {
        if let rawGroups = entitlements["com.apple.security.application-groups"] as? [String], !rawGroups.isEmpty {
            return evaluate(hasAppGroups: true, appGroups: rawGroups)
        }
        return evaluate(hasAppGroups: false, appGroups: [])
    }
}
