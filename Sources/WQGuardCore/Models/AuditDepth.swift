//
//  AuditDepth.swift
//  WQGuardCore
//
//  Defines the inspection depth of a ScanFinding across WQGuard's dual-engine architecture.
//

import Foundation

/// Indicates which inspection engines contributed evidence to a `ScanFinding`.
public enum AuditDepth: String, Codable, Sendable, Equatable, CaseIterable {
    /// Full Mach-O binary static analysis + embedded/live entitlements & code signature inspection.
    case fullBinaryAndRegistry = "FULL_BINARY"

    /// System `installation_proxy` registry inspection (complete live Entitlements, App Groups,
    /// SignerIdentity, Info.plist attributes, and impersonation checks, without local Mach-O binary).
    case registryEntitlements = "REGISTRY_ENTITLEMENTS"

    /// Lightweight on-device presence probe (URL Scheme / environment tool discovery without entitlements or binary).
    case onDeviceProbe = "ON_DEVICE_PROBE"

    public var localizedNameZh: String {
        switch self {
        case .fullBinaryAndRegistry:
            return "全量深扫 (权限+二进制)"
        case .registryEntitlements:
            return "系统注册表 (权限+签名)"
        case .onDeviceProbe:
            return "本机探针盘点"
        }
    }

    public var localizedNameEn: String {
        switch self {
        case .fullBinaryAndRegistry:
            return "Full Audit (Binary + Entitlements)"
        case .registryEntitlements:
            return "System Registry (Entitlements + Signer)"
        case .onDeviceProbe:
            return "On-Device Probe"
        }
    }
}
