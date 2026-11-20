//
//  LockdownInstProxyClient.swift
//  WQGuardCore
//
//  Option 1 Direct Engine: Pure-Swift Apple `lockdownd` + `com.apple.mobile.installation_proxy`
//  client using a user-imported `.mobiledevicepairing` file over LocalDevVPN (e.g. 10.7.0.1:62078).
//  100% standard Apple Lockdown protocol (same mechanism used by Xcode, SideStore, and StikDebug),
//  using zero exploits and zero external dependencies.
//

import Foundation
import Darwin
import Security
import Network

public enum LockdownClientError: Error, LocalizedError, Sendable, Equatable {
    case invalidPairingFile(String)
    case identityImportFailed(OSStatus)
    case lockdownUnreachable(String)
    case protocolError(String)
    case sessionRejected(String)
    case serviceStartFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidPairingFile(let detail):
            return WQLocale.pick(
                en: "Invalid or incomplete pairing file (.mobiledevicepairing): \(detail)",
                zh: "配对文件 (.mobiledevicepairing) 无效或缺失关键字段: \(detail)"
            )
        case .identityImportFailed(let status):
            return WQLocale.pick(
                en: "Failed to load TLS client identity from pairing file (Keychain OSStatus: \(status)).",
                zh: "无法从配对文件加载 TLS 客户端证书身份 (Keychain OSStatus: \(status))。"
            )
        case .lockdownUnreachable(let host):
            return WQLocale.pick(
                en: "Cannot reach local lockdownd service (\(host):62078). Ensure LocalDevVPN (StikDebug / SideStore) is connected, or import a snapshot instead.",
                zh: "无法连接本机 lockdownd 服务 (\(host):62078)。请确认已开启 StikDebug / SideStore 的 LocalDevVPN（10.7.0.1），或改用「导入已安装应用快照」方式。"
            )
        case .protocolError(let msg):
            return WQLocale.pick(
                en: "lockdownd / installation_proxy protocol error: \(msg)",
                zh: "lockdownd / installation_proxy 协议交互异常: \(msg)"
            )
        case .sessionRejected(let err):
            return WQLocale.pick(
                en: "Pairing session rejected by device (\(err)). The pairing record may have expired (re-generate after resetting Trust This Computer).",
                zh: "配对会话被设备拒绝 (\(err))。该配对文件可能已过期（重置过信任电脑后需重新生成配对文件）。"
            )
        case .serviceStartFailed(let err):
            return WQLocale.pick(
                en: "Failed to start com.apple.mobile.installation_proxy service: \(err)",
                zh: "启动 com.apple.mobile.installation_proxy 服务失败: \(err)"
            )
        }
    }
}

/// Parsed representation of a standard `.mobiledevicepairing` / Lockdown pairing plist.
public struct LockdownPairingFile: Codable, Sendable, Equatable {
    public let hostID: String
    public let systemBUID: String
    public let hostCertificateDER: Data
    public let hostPrivateKeyDER: Data
    public let rootCertificateDER: Data?
    public let deviceCertificateDER: Data?
    public let udid: String?

    public init(
        hostID: String,
        systemBUID: String,
        hostCertificateDER: Data,
        hostPrivateKeyDER: Data,
        rootCertificateDER: Data? = nil,
        deviceCertificateDER: Data? = nil,
        udid: String? = nil
    ) {
        self.hostID = hostID
        self.systemBUID = systemBUID
        self.hostCertificateDER = hostCertificateDER
        self.hostPrivateKeyDER = hostPrivateKeyDER
        self.rootCertificateDER = rootCertificateDER
        self.deviceCertificateDER = deviceCertificateDER
        self.udid = udid
    }

    public static func parse(from url: URL) throws -> LockdownPairingFile {
        let data: Data
        do {
            data = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: url, maxBytes: 4 * 1024 * 1024)
        } catch {
            throw LockdownClientError.invalidPairingFile(error.localizedDescription)
        }
        let stem = url.deletingPathExtension().lastPathComponent
        return try parse(data: data, fallbackUDID: stem.isEmpty ? nil : stem)
    }

    public static func parse(data: Data, fallbackUDID: String? = nil) throws -> LockdownPairingFile {
        let maxPairingBytes = 4 * 1024 * 1024
        guard data.count <= maxPairingBytes else {
            throw LockdownClientError.invalidPairingFile(WQLocale.pick(
                en: "Pairing file exceeds maximum safe size (4 MB)",
                zh: "配对文件大小超过 4 MB 安全上限"
            ))
        }
        guard let outerPlist = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] else {
            throw LockdownClientError.invalidPairingFile(WQLocale.pick(
                en: "Not a valid XML or Binary Plist file",
                zh: "不是有效的 XML/Binary Plist 文件"
            ))
        }

        // Support both direct pairing plists and usbmuxd `{"PairRecord": {...}}` wrappers
        let plist: [String: Any]
        if let nested = outerPlist["PairRecord"] as? [String: Any] {
            plist = nested
        } else if let nested = outerPlist["PairRecordData"] as? Data,
                  let decodedNested = (try? PropertyListSerialization.propertyList(from: nested, options: [], format: nil)) as? [String: Any] {
            plist = decodedNested
        } else {
            plist = outerPlist
        }

        if plist["HostID"] == nil && plist["HostId"] == nil {
            if plist["remote_unlock_host_key"] != nil || (plist["public_key"] != nil && plist["private_key"] != nil) {
                throw LockdownClientError.invalidPairingFile(WQLocale.pick(
                    en: "Detected RPPairing (CoreDevice 49152) pairing record. On iOS 27, use Mode B (xcrun devicectl / pymobiledevice3) to export an installed-app JSON snapshot without VPN.",
                    zh: "检测到 RPPairing (CoreDevice 49152) 格式配对文件。iOS 27 推荐直接使用下方「方式 B：复制 Mac 原生 devicectl 命令一键导出快照」（无需配置 VPN）。"
                ))
            }
        }

        guard let hostID = (plist["HostID"] as? String) ?? (plist["HostId"] as? String), !hostID.isEmpty else {
            throw LockdownClientError.invalidPairingFile(WQLocale.pick(
                en: "Missing HostID (verify you selected a lockdown pairing record rather than an ordinary plist)",
                zh: "缺少 HostID（确认导入的是配对文件而非普通配置 plist）"
            ))
        }
        guard let systemBUID = (plist["SystemBUID"] as? String) ?? (plist["SystemBuid"] as? String), !systemBUID.isEmpty else {
            throw LockdownClientError.invalidPairingFile(WQLocale.pick(en: "Missing SystemBUID", zh: "缺少 SystemBUID"))
        }
        guard let hostCertRaw = Self.extractDataField(plist["HostCertificate"]),
              let hostCertDER = Self.decodePEMOrDER(hostCertRaw) else {
            throw LockdownClientError.invalidPairingFile(WQLocale.pick(en: "Missing or undecodable HostCertificate", zh: "缺少或无法解码 HostCertificate"))
        }
        guard let hostKeyRaw = Self.extractDataField(plist["HostPrivateKey"]),
              let hostKeyDER = Self.decodePEMOrDER(hostKeyRaw) else {
            throw LockdownClientError.invalidPairingFile(WQLocale.pick(en: "Missing or undecodable HostPrivateKey", zh: "缺少或无法解码 HostPrivateKey"))
        }

        let rootDER = Self.extractDataField(plist["RootCertificate"]).flatMap { Self.decodePEMOrDER($0) }
        let devDER = Self.extractDataField(plist["DeviceCertificate"]).flatMap { Self.decodePEMOrDER($0) }
        let udid = (plist["UDID"] as? String) ?? (outerPlist["UDID"] as? String) ?? fallbackUDID

        return LockdownPairingFile(
            hostID: hostID,
            systemBUID: systemBUID,
            hostCertificateDER: hostCertDER,
            hostPrivateKeyDER: hostKeyDER,
            rootCertificateDER: rootDER,
            deviceCertificateDER: devDER,
            udid: udid
        )
    }

    private static func extractDataField(_ value: Any?) -> Data? {
        if let d = value as? Data { return d }
        if let s = value as? String { return Data(s.utf8) }
        return nil
    }

    public static func decodePEMOrDER(_ raw: Data) -> Data? {
        guard !raw.isEmpty else { return nil }
        let trimmedRaw: Data = raw.last == 0 ? Data(raw.dropLast()) : raw
        let text = String(decoding: trimmedRaw, as: UTF8.self)
        if text.contains("-----BEGIN") {
            let lines = text.components(separatedBy: .newlines).filter { line in
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                return !trimmed.isEmpty && !trimmed.hasPrefix("-----BEGIN") && !trimmed.hasPrefix("-----END")
            }
            let base64Body = lines.joined()
            guard let decoded = Data(base64Encoded: base64Body, options: .ignoreUnknownCharacters), !decoded.isEmpty else {
                return nil
            }
            return decoded
        }
        // Raw DER ASN.1 SEQUENCE starts with 0x30
        if trimmedRaw.first == 0x30 {
            return trimmedRaw
        }
        guard let decoded = Data(base64Encoded: trimmedRaw, options: .ignoreUnknownCharacters), !decoded.isEmpty else {
            return nil
        }
        return decoded
    }

    /// Strips PKCS#8 PrivateKeyInfo wrapper around an inner PKCS#1 RSAPrivateKey if present,
    /// because Darwin `SecKeyCreateWithData` expects PKCS#1 DER for RSA private keys.
    public static func unwrapPKCS8PrivateKeyIfNeeded(_ der: Data) -> Data {
        let bytes = [UInt8](der)
        // Standard RSA OID: 06 09 2A 86 48 86 F7 0D 01 01 01
        let rsaOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        guard bytes.count > 20,
              let oidRange = bytes.firstRange(of: rsaOID) else {
            return der
        }
        // Look for OCTET STRING tag (0x04) right after `05 00` (NULL parameters) following the RSA OID
        var idx = oidRange.upperBound
        while idx < min(oidRange.upperBound + 8, bytes.count - 2) {
            if bytes[idx] == 0x04 {
                idx += 1
                let lenByte = bytes[idx]
                idx += 1
                var payloadLen = 0
                if (lenByte & 0x80) == 0 {
                    payloadLen = Int(lenByte)
                } else {
                    let numBytes = Int(lenByte & 0x7F)
                    guard numBytes > 0, numBytes <= 4, idx + numBytes <= bytes.count else { return der }
                    for _ in 0..<numBytes {
                        payloadLen = (payloadLen << 8) | Int(bytes[idx])
                        idx += 1
                    }
                }
                if payloadLen > 0, idx < bytes.count, payloadLen <= bytes.count - idx, bytes[idx] == 0x30 {
                    return Data(bytes[idx..<(idx + payloadLen)])
                }
                break
            }
            idx += 1
        }
        return der
    }
}

/// Pure-POSIX `getifaddrs()` inspector that detects iOS 26.4+ / iOS 27 `lockdownd` Wi-Fi subnet mismatches
/// and calculates collision-free `/32` addresses inside the current `en0` Wi-Fi netmask for `LocalDevVPN`.
public struct LocalNetworkSubnetDiagnosis: Sendable, Equatable {
    public let wifiInterface: String?
    public let wifiIP: String?
    public let wifiNetmask: String?
    public let wifiPrefixLength: Int?
    public let utunInterface: String?
    public let utunLocalIP: String?
    public let utunPeerIP: String?
    public let configuredHost: String
    public let recommendedTunnelIP: String?
    public let recommendedDeviceIP: String?
    public let hasSubnetMismatch: Bool

    public var recommendedTunnelCIDR: String? {
        recommendedTunnelIP.map { "\($0)/32" }
    }

    public var recommendedDeviceCIDR: String? {
        recommendedDeviceIP.map { "\($0)/32" }
    }

    public init(
        wifiInterface: String?,
        wifiIP: String?,
        wifiNetmask: String?,
        wifiPrefixLength: Int?,
        utunInterface: String?,
        utunLocalIP: String?,
        utunPeerIP: String?,
        configuredHost: String,
        recommendedTunnelIP: String?,
        recommendedDeviceIP: String?,
        hasSubnetMismatch: Bool
    ) {
        self.wifiInterface = wifiInterface
        self.wifiIP = wifiIP
        self.wifiNetmask = wifiNetmask
        self.wifiPrefixLength = wifiPrefixLength
        self.utunInterface = utunInterface
        self.utunLocalIP = utunLocalIP
        self.utunPeerIP = utunPeerIP
        self.configuredHost = configuredHost
        self.recommendedTunnelIP = recommendedTunnelIP
        self.recommendedDeviceIP = recommendedDeviceIP
        self.hasSubnetMismatch = hasSubnetMismatch
    }

    public static func inspect(configuredHost: String = "10.7.0.1") -> LocalNetworkSubnetDiagnosis {
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else {
            return LocalNetworkSubnetDiagnosis(
                wifiInterface: nil, wifiIP: nil, wifiNetmask: nil, wifiPrefixLength: nil,
                utunInterface: nil, utunLocalIP: nil, utunPeerIP: nil,
                configuredHost: configuredHost,
                recommendedTunnelIP: nil, recommendedDeviceIP: nil,
                hasSubnetMismatch: false
            )
        }
        defer { freeifaddrs(ifaddrPtr) }

        var foundWifiName: String?
        var foundWifiIP: String?
        var foundWifiMask: String?
        var foundUtunName: String?
        var foundUtunLocal: String?
        var foundUtunPeer: String?

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entryPtr = cursor {
            let entry = entryPtr.pointee
            cursor = entry.ifa_next

            let flags = Int32(entry.ifa_flags)
            guard (flags & IFF_UP) != 0,
                  let namePtr = entry.ifa_name,
                  let addr = entry.ifa_addr,
                  addr.pointee.sa_family == sa_family_t(AF_INET) else {
                continue
            }

            let name = String(cString: namePtr)
            guard let ipStr = ipv4String(from: addr) else { continue }

            if (name == "en0" || (foundWifiIP == nil && (name == "en1" || name == "bridge100"))),
               !ipStr.hasPrefix("169.254.") {
                foundWifiName = name
                foundWifiIP = ipStr
                foundWifiMask = entry.ifa_netmask.flatMap { ipv4String(from: $0) } ?? "255.255.255.0"
            } else if name.hasPrefix("utun") {
                // Only accept strictly local/private/CGNAT utun interfaces; never adopt a commercial VPN's public peer IP
                guard LockdownInstProxyClient.isAllowedLocalHost(ipStr) else { continue }
                let isLikelyLocalDevVPN = ipStr.hasPrefix("10.7.")
                    || ipStr.hasPrefix("192.168.")
                    || LockdownInstProxyClient.isRFC1918Block172(ipStr)
                    || foundUtunLocal == nil
                if isLikelyLocalDevVPN {
                    foundUtunName = name
                    foundUtunLocal = ipStr
                    if let dst = entry.ifa_dstaddr,
                       dst.pointee.sa_family == sa_family_t(AF_INET),
                       let peer = ipv4String(from: dst),
                       peer != ipStr && peer != "0.0.0.0",
                       LockdownInstProxyClient.isAllowedLocalHost(peer) {
                        foundUtunPeer = peer
                    }
                }
            }
        }

        var prefixLen: Int?
        var recTunnel: String?
        var recDevice: String?
        var mismatch = false

        if let wIP = foundWifiIP, let wMask = foundWifiMask,
           let ipVal = parseIPv4UInt32(wIP), let maskVal = parseIPv4UInt32(wMask) {
            prefixLen = maskVal.nonzeroBitCount
            if let pair = computeRecommendedPair(wifiIP: ipVal, netmask: maskVal) {
                recTunnel = formatIPv4UInt32(pair.tunnel)
                recDevice = formatIPv4UInt32(pair.device)
            }
            let cleanHost = configuredHost.trimmingCharacters(in: .whitespacesAndNewlines)
            let targetToCheck = cleanHost.isEmpty ? "10.7.0.1" : cleanHost
            if !isIPv4(targetToCheck, inSameSubnetAs: wIP, netmask: wMask) {
                mismatch = true
            } else if let uLocal = foundUtunLocal, !isIPv4(uLocal, inSameSubnetAs: wIP, netmask: wMask) {
                mismatch = true
            }
        }

        return LocalNetworkSubnetDiagnosis(
            wifiInterface: foundWifiName,
            wifiIP: foundWifiIP,
            wifiNetmask: foundWifiMask,
            wifiPrefixLength: prefixLen,
            utunInterface: foundUtunName,
            utunLocalIP: foundUtunLocal,
            utunPeerIP: foundUtunPeer,
            configuredHost: configuredHost,
            recommendedTunnelIP: recTunnel,
            recommendedDeviceIP: recDevice,
            hasSubnetMismatch: mismatch
        )
    }

    public static func isIPv4(_ candidate: String, inSameSubnetAs baseIP: String, netmask: String) -> Bool {
        guard let c = parseIPv4UInt32(candidate),
              let b = parseIPv4UInt32(baseIP),
              let m = parseIPv4UInt32(netmask) else {
            return false
        }
        return ((c ^ b) & m) == 0
    }

    public static func computeRecommendedPair(wifiIP: UInt32, netmask: UInt32) -> (tunnel: UInt32, device: UInt32)? {
        // Need at least a /29 (8 addresses) to safely pick two unused host addresses away from gateway & self
        guard netmask <= 0xFFFFFFF8 else { return nil }

        if netmask <= 0xFFFFFF00 {
            // Standard /24, /23, /22, /16: stay in the same /24 block as wifiIP so it always fits `netmask`
            let block24 = wifiIP & 0xFFFFFF00
            let candidates: [UInt32] = [251, 252, 249, 250, 247, 248].map { block24 | $0 }.filter { $0 != wifiIP }
            if candidates.count >= 2 {
                return (candidates[0], candidates[1])
            }
        } else {
            let network = wifiIP & netmask
            let broadcast = network | (~netmask)
            var candidates: [UInt32] = []
            var host = broadcast - 1
            while host > network + 1 {
                if host != wifiIP {
                    candidates.append(host)
                    if candidates.count == 2 {
                        return (candidates[1], candidates[0])
                    }
                }
                host -= 1
            }
        }
        return nil
    }

    private static func ipv4String(from sa: UnsafePointer<sockaddr>) -> String? {
        var addrIn = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &addrIn.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else {
            return nil
        }
        return String(cString: buf)
    }

    public static func parseIPv4UInt32(_ ip: String) -> UInt32? {
        let clean = ip.split(separator: "/", maxSplits: 1).first.map(String.init) ?? ip
        var inAddr = in_addr()
        guard inet_pton(AF_INET, clean, &inAddr) == 1 else { return nil }
        return UInt32(bigEndian: inAddr.s_addr)
    }

    public static func formatIPv4UInt32(_ value: UInt32) -> String {
        var inAddr = in_addr(s_addr: value.bigEndian)
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        _ = inet_ntop(AF_INET, &inAddr, &buf, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buf)
    }
}

/// Pure-Swift client speaking Apple's Lockdown + `com.apple.mobile.installation_proxy` plist protocol.
public final class LockdownInstProxyClient: @unchecked Sendable {
    public static let shared = LockdownInstProxyClient()
    public static let lockdownPort: UInt16 = 62078

    private let keychainLabel = "com.wqguard.lockdown.pairing.v1"

    public init() {}

    // MARK: - Zero-Outbound-Network Numeric Local Host Guard

    internal static func isRFC1918Block172(_ rawHost: String) -> Bool {
        var addr4 = in_addr()
        guard inet_pton(AF_INET, rawHost, &addr4) == 1 else { return false }
        let u32 = UInt32(bigEndian: addr4.s_addr)
        return (u32 & 0xFFF0_0000) == 0xAC10_0000
    }

    /// Enforces the strict zero-outbound-internet invariant (`SECURITY.md`):
    /// permits ONLY numeric loopback, RFC1918 private, link-local, CGNAT/LocalDevVPN, or IPv6 ULA literals
    /// (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`,
    /// `::1`, `fe80::/10`, `fc00::/7`), rejecting all DNS hostnames, public IPs, and IPv4-mapped IPv6 literals.
    public static func isAllowedLocalHost(_ rawHost: String) -> Bool {
        (try? validateAllowedLocalHost(rawHost)) != nil
    }

    public static func validateAllowedLocalHost(_ rawHost: String) throws -> String {
        let trimmed = rawHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !trimmed.contains(where: { $0.isWhitespace || $0 == "\0" || $0 == "/" }) else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Rejected non-local or malformed Lockdown host '\(rawHost)': only numeric local/private IP literals are permitted (zero outbound network / zero DNS).",
                zh: "已拦截非本地或格式非法的 Lockdown 地址 '\(rawHost)'：仅允许纯数字本地/私网 IP 字面量（零外发网络 / 零 DNS 查询）。"
            ))
        }

        let unbracketed: String
        if trimmed.hasPrefix("[") || trimmed.hasSuffix("]") {
            guard trimmed.hasPrefix("["), trimmed.hasSuffix("]"), trimmed.count > 2 else {
                throw LockdownClientError.protocolError(WQLocale.pick(
                    en: "Malformed bracketed IPv6 literal '\(rawHost)'.",
                    zh: "IPv6 括号字面量格式错误 '\(rawHost)'。"
                ))
            }
            unbracketed = String(trimmed.dropFirst().dropLast())
        } else {
            unbracketed = trimmed
        }

        // 1. Numeric IPv4 literal check (`inet_pton` strictly rejects octal/hex/short-form/DNS names)
        if !unbracketed.contains(":") {
            var addr4 = in_addr()
            guard inet_pton(AF_INET, unbracketed, &addr4) == 1 else {
                throw LockdownClientError.protocolError(WQLocale.pick(
                    en: "Rejected non-numeric or external host '\(rawHost)': DNS resolution and public IPs are forbidden.",
                    zh: "已拒绝非数字域名或外部主机 '\(rawHost)'：严禁发起 DNS 解析或连接公网 IP。"
                ))
            }
            let u32 = UInt32(bigEndian: addr4.s_addr)
            let isLoopback = (u32 & 0xFF00_0000) == 0x7F00_0000 && u32 != 0x7F00_0000 && u32 != 0x7FFF_FFFF
            let is10 = (u32 & 0xFF00_0000) == 0x0A00_0000
            let is172 = (u32 & 0xFFF0_0000) == 0xAC10_0000
            let is192 = (u32 & 0xFFFF_0000) == 0xC0A8_0000
            let isCGNAT = (u32 & 0xFFC0_0000) == 0x6440_0000
            let isLinkLocal = (u32 & 0xFFFF_0000) == 0xA9FE_0000
            guard isLoopback || is10 || is172 || is192 || isCGNAT || isLinkLocal else {
                throw LockdownClientError.protocolError(WQLocale.pick(
                    en: "Rejected public or reserved IPv4 host '\(rawHost)': only local/VPN/private subnets are permitted.",
                    zh: "已拒绝公网或保留网段 IPv4 地址 '\(rawHost)'：仅允许本机/本地 VPN/局域网私网地址。"
                ))
            }
            return unbracketed
        }

        // 2. Numeric IPv6 literal check (`::1`, `fe80::/10` with optional safe `%ifname`, `fc00::/7`)
        let parts = unbracketed.split(separator: "%", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Malformed IPv6 zone literal '\(rawHost)'.",
                zh: "IPv6 作用域字面量格式错误 '\(rawHost)'。"
            ))
        }
        let ipv6AddrPart = String(parts[0])
        let zonePart: String? = parts.count == 2 ? String(parts[1]) : nil
        if let zone = zonePart {
            let validZone = !zone.isEmpty && zone.count <= 16 && zone.utf8.allSatisfy { b in
                (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
                    || (b >= 0x30 && b <= 0x39) || b == 0x2E || b == 0x5F || b == 0x2D
            }
            guard validZone else {
                throw LockdownClientError.protocolError(WQLocale.pick(
                    en: "Invalid IPv6 interface zone in '\(rawHost)'.",
                    zh: "IPv6 网卡作用域标识符无效 '\(rawHost)'。"
                ))
            }
        }

        var addr6 = in6_addr()
        guard inet_pton(AF_INET6, ipv6AddrPart, &addr6) == 1 else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Rejected non-numeric IPv6 literal '\(rawHost)'.",
                zh: "已拒绝非法的 IPv6 字面量 '\(rawHost)'。"
            ))
        }
        let octets = withUnsafeBytes(of: addr6) { Array($0) }
        guard octets.count == 16 else {
            throw LockdownClientError.protocolError("Invalid IPv6 address buffer")
        }
        let isV6Loopback = octets[0..<15].allSatisfy({ $0 == 0 }) && octets[15] == 1 && zonePart == nil
        let isV6LinkLocal = octets[0] == 0xFE && (octets[1] & 0xC0) == 0x80
        let isV6ULA = (octets[0] & 0xFE) == 0xFC && zonePart == nil
        guard isV6Loopback || isV6LinkLocal || isV6ULA else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Rejected global or IPv4-mapped IPv6 host '\(rawHost)': only ::1, fe80::/10, and fc00::/7 are permitted.",
                zh: "已拒绝公网或映射型 IPv6 地址 '\(rawHost)'：仅允许 ::1、fe80::/10 与 fc00::/7。"
            ))
        }
        return unbracketed
    }

    internal static func makeNumericNWHost(_ rawHost: String) throws -> NWEndpoint.Host {
        let validated = try validateAllowedLocalHost(rawHost)
        if !validated.contains(":"), let v4 = IPv4Address(validated) {
            return .ipv4(v4)
        }
        if let v6 = IPv6Address(validated) {
            return .ipv6(v6)
        }
        throw LockdownClientError.protocolError(WQLocale.pick(
            en: "Failed to construct numeric network endpoint for '\(rawHost)'.",
            zh: "无法为 '\(rawHost)' 构建纯数字网络端点。"
        ))
    }

    // MARK: - Public Entry Point

    /// Connects to `lockdownd` over LocalDevVPN (default `10.7.0.1`, plus auto-detected Wi-Fi subnet / `utun` peer),
    /// starts `com.apple.mobile.installation_proxy`, and returns all installed app records.
    public func fetchInstalledApps(
        pairing: LockdownPairingFile,
        preferredHost: String = "10.7.0.1",
        allowInteractiveConsentWait: Bool = true
    ) async throws -> [InstalledAppRegistryRecord] {
        return try await Task.detached(priority: .userInitiated) { [self] in
            let cleanPreferred = preferredHost.trimmingCharacters(in: .whitespacesAndNewlines)
            let primaryHost = try Self.validateAllowedLocalHost(cleanPreferred.isEmpty ? "10.7.0.1" : cleanPreferred)
            let tlsOptions = try self.createTLSOptions(from: pairing)
            let diagnosis = LocalNetworkSubnetDiagnosis.inspect(configuredHost: primaryHost)

            // Fast-fail in <0.5s when no active `utun` VPN tunnel exists on the device, preventing
            // 15-25s UI freezes when the user runs an offline snapshot scan while LocalDevVPN is disconnected.
            if diagnosis.utunInterface == nil && primaryHost != "127.0.0.1" && primaryHost != "::1" {
                if let quickFD = try? Self.connectPOSIXSocket(host: primaryHost, port: Self.lockdownPort, timeoutMs: 450) {
                    Darwin.close(quickFD)
                } else {
                    throw LockdownClientError.lockdownUnreachable(primaryHost)
                }
            }

            let utunMatchesRecommended = (diagnosis.recommendedTunnelIP != nil && diagnosis.utunLocalIP == diagnosis.recommendedTunnelIP)
                || (diagnosis.recommendedDeviceIP != nil && diagnosis.utunPeerIP == diagnosis.recommendedDeviceIP)

            var candidateHosts: [String] = []
            let rawCandidates: [String?] = [
                primaryHost,
                diagnosis.utunPeerIP,
                utunMatchesRecommended ? diagnosis.recommendedDeviceIP : nil,
                "10.7.0.1",
                "10.7.0.2",
                "127.0.0.1"
            ]
            for maybeHost in rawCandidates {
                if let h = maybeHost?.trimmingCharacters(in: .whitespacesAndNewlines),
                   !h.isEmpty,
                   let canonical = try? Self.validateAllowedLocalHost(h),
                   !candidateHosts.contains(canonical) {
                    candidateHosts.append(canonical)
                }
            }

            // Trigger Network.framework Local Network consent prompt before raw BSD socket connects,
            // waking immediately (within 350ms) as soon as the user taps "Allow" on the iOS alert.
            Self.warmUpLocalNetworkPermission(
                host: primaryHost,
                port: Self.lockdownPort,
                allowConsentWait: allowInteractiveConsentWait
            )

            var connectedAtLeastOnce = false
            var lastAttemptError: Error?
            var sawImmediateEOF = false

            for (idx, host) in candidateHosts.enumerated() {
                let connectTimeout: Int32 = idx == 0 ? 1500 : 800
                guard let fd = try? Self.connectPOSIXSocket(host: host, port: Self.lockdownPort, timeoutMs: connectTimeout) else {
                    continue
                }
                connectedAtLeastOnce = true
                UserDefaults.standard.set(true, forKey: Self.localNetworkWarmedKey)

                do {
                    let (servicePort, enableServiceSSL) = try self.negotiateInstallationProxyPort(
                        rawSocketFD: fd,
                        pairing: pairing,
                        tlsOptions: tlsOptions
                    )
                    return try self.browseApplications(
                        host: host,
                        port: servicePort,
                        useTLS: enableServiceSSL,
                        tlsOptions: tlsOptions
                    )
                } catch let err as LockdownClientError {
                    lastAttemptError = err
                    if case .protocolError(let msg) = err, msg.contains("EOF") {
                        sawImmediateEOF = true
                        // Try next candidate host (e.g. if 10.7.0.1 hit utun subnet filter, try active utun peer)
                        continue
                    }
                    throw err
                } catch {
                    lastAttemptError = error
                    throw error
                }
            }

            guard connectedAtLeastOnce else {
                throw LockdownClientError.lockdownUnreachable(primaryHost)
            }

            if sawImmediateEOF {
                throw Self.buildEOFDiagnosticError(diagnosis: diagnosis)
            }

            throw lastAttemptError ?? LockdownClientError.lockdownUnreachable(primaryHost)
        }.value
    }

    private static func buildEOFDiagnosticError(diagnosis: LocalNetworkSubnetDiagnosis) -> LockdownClientError {
        if diagnosis.hasSubnetMismatch,
           let wifiIP = diagnosis.wifiIP,
           let recTunnel = diagnosis.recommendedTunnelCIDR,
           let recDevice = diagnosis.recommendedDeviceCIDR,
           let recHost = diagnosis.recommendedDeviceIP {
            return .protocolError(WQLocale.pick(
                en: "iOS 26.4+ / iOS 27 lockdownd enforces same-subnet VPN validation: Wi-Fi (\(wifiIP)) differs from LocalDevVPN (\(diagnosis.configuredHost)), closing the handshake (EOF).\n\nFix options:\n1️⃣ In LocalDevVPN settings, set Tunnel IP to \(recTunnel), Device IP to \(recDevice), reconnect the VPN, and set WQGuard gateway to \(recHost) (one-tap copy buttons are in Scan Sources & Pairing);\n2️⃣ Or use Mode B (Mac Snapshot Export) via Xcode devicectl / pymobiledevice3 without VPN.",
                zh: "iOS 26.4+ / iOS 27 系统 lockdownd 新增了 VPN 子网校验，检测到当前 Wi-Fi (\(wifiIP)) 与 LocalDevVPN (\(diagnosis.configuredHost)) 不在同一网段，握手被系统立即断开 (EOF)。\n\n解决方法（二选一）：\n1️⃣ 在 LocalDevVPN 设置中将 Tunnel IP 改为 \(recTunnel)、Device IP 改为 \(recDevice) 后重连 VPN，并在 WQGuard 将网关设为 \(recHost)（已在「已安装应用扫描源」页面提供一键复制）；\n2️⃣ 或者直接使用「方式 B：电脑端免装工具一键导出快照」（Xcode 原生 devicectl 走 iOS 27 CoreDevice 通道，无需 VPN 秒扫全机）。"
            ))
        }
        return .protocolError(WQLocale.pick(
            en: "Connection was closed (EOF) by local lockdownd (62078). iOS 26.4+ / iOS 27 restricts legacy port-62078 local VPN pairing sessions.\n\n👉 Recommended: Use Mode B in Scan Sources & Pairing to copy the Mac `xcrun devicectl` or `pymobiledevice3` command and AirDrop `installed_apps.json` to your iPhone.",
            zh: "连接建立后被本机 lockdownd (62078) 立即主动关闭 (EOF)。当前 iOS 26.4+ / iOS 27 系统限制了旧版 62078 端口本地 VPN 配对会话。\n\n👉 推荐改用「方式 B：电脑端免装工具一键导出快照」：在「已安装应用扫描源」复制 Mac 原生 xcrun devicectl 命令（无需安装第三方工具、无需开启 VPN），导出 installed_apps.json 发到手机即可完整扫描全机应用。"
        ))
    }

    private static let localNetworkWarmedKey = "wqguard_localnet_warmed_v1"

    /// Opens a brief `NWConnection` on first run so iOS NECP triggers the system Local Network permission prompt,
    /// polling every 350ms so execution resumes immediately the moment the user taps "Allow".
    private static func warmUpLocalNetworkPermission(host: String, port: UInt16, allowConsentWait: Bool) {
        guard host != "127.0.0.1",
              host != "::1",
              !UserDefaults.standard.bool(forKey: localNetworkWarmedKey),
              let nwHost = try? makeNumericNWHost(host),
              let nwPort = NWEndpoint.Port(rawValue: port) else {
            return
        }
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = 2
        let params = NWParameters(tls: nil, tcp: tcp)
        let queue = DispatchQueue(label: "com.wqguard.localnet.warmup")
        let conn = NWConnection(host: nwHost, port: nwPort, using: params)

        let readyOrFailSema = DispatchSemaphore(value: 0)
        let waitingFlag = LockedBox<Bool>(false)
        let finishedFlag = LockedBox<Bool>(false)

        conn.stateUpdateHandler = { state in
            switch state {
            case .waiting:
                waitingFlag.value = true
            case .ready:
                UserDefaults.standard.set(true, forKey: localNetworkWarmedKey)
                if !finishedFlag.value {
                    finishedFlag.value = true
                    readyOrFailSema.signal()
                }
            case .failed, .cancelled:
                if !finishedFlag.value {
                    finishedFlag.value = true
                    readyOrFailSema.signal()
                }
            default:
                break
            }
        }
        conn.start(queue: queue)

        // Wait 0.4s to detect either instant connection or NECP `.waiting` (Local Network system alert)
        if readyOrFailSema.wait(timeout: .now() + 0.4) == .timedOut, allowConsentWait, waitingFlag.value {
            for _ in 0..<28 {
                if readyOrFailSema.wait(timeout: .now() + 0.35) == .success {
                    break
                }
                if let probeFD = try? connectPOSIXSocket(host: host, port: port, timeoutMs: 220) {
                    Darwin.close(probeFD)
                    UserDefaults.standard.set(true, forKey: localNetworkWarmedKey)
                    break
                }
            }
        }
        conn.cancel()
    }

    // MARK: - Step 1 & 2: Lockdown Session & StartService

    func negotiateInstallationProxyPort(
        rawSocketFD: Int32,
        pairing: LockdownPairingFile,
        tlsOptions: NWProtocolTLS.Options?
    ) throws -> (port: UInt16, enableSSL: Bool) {
        setSocketNoSigPipe(rawSocketFD)
        var socketTransferredToRelay = false
        defer {
            if !socketTransferredToRelay && rawSocketFD >= 0 {
                Darwin.close(rawSocketFD)
            }
        }

        // 1. QueryType
        try Self.writePlistPacket(["Request": "QueryType", "Label": "WQGuard"], toFD: rawSocketFD, step: "QueryType")
        let queryResp = try Self.readPlistPacket(fromFD: rawSocketFD, step: "QueryType")
        guard (queryResp["Type"] as? String) == "com.apple.mobile.lockdown" else {
            throw LockdownClientError.protocolError(WQLocale.pick(en: "Unexpected QueryType response", zh: "非预期的 QueryType 响应"))
        }

        // 2. StartSession (mandatory STARTTLS: reject plaintext downgrade / MITM strip attacks)
        let startSessionReq: [String: Any] = [
            "Request": "StartSession",
            "HostID": pairing.hostID,
            "SystemBUID": pairing.systemBUID,
            "Label": "WQGuard"
        ]
        try Self.writePlistPacket(startSessionReq, toFD: rawSocketFD, step: "StartSession")
        let sessionResp = try Self.readPlistPacket(fromFD: rawSocketFD, step: "StartSession")
        if let err = sessionResp["Error"] as? String {
            throw LockdownClientError.sessionRejected(err)
        }

        let enableSessionSSL = (sessionResp["EnableSessionSSL"] as? Bool) ?? false
        guard enableSessionSSL else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Refused unencrypted StartSession (EnableSessionSSL=false): possible STARTTLS downgrade attack",
                zh: "拒绝未加密的 StartSession 会话 (EnableSessionSSL=false)：疑似 STARTTLS 降级攻击"
            ))
        }
        guard let tlsOptions else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Missing TLS client options for StartSession",
                zh: "缺少 StartSession TLS 客户端安全配置"
            ))
        }

        let startServiceReq: [String: Any] = [
            "Request": "StartService",
            "Service": "com.apple.mobile.installation_proxy",
            "Label": "WQGuard"
        ]

        // Extend socket timeout before handing over to TLS loopback relay
        var relayTV = timeval(tv_sec: 30, tv_usec: 0)
        setsockopt(rawSocketFD, SOL_SOCKET, SO_RCVTIMEO, &relayTV, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(rawSocketFD, SOL_SOCKET, SO_SNDTIMEO, &relayTV, socklen_t(MemoryLayout<timeval>.size))

        let relay = try LocalSocketTLSRelay(upstreamFD: rawSocketFD)
        socketTransferredToRelay = true
        defer { relay.stop() }

        let conn = try SyncNWChannel.connect(host: "127.0.0.1", port: relay.localPort, tlsOptions: tlsOptions)
        defer { conn.close() }

        try conn.sendPlist(startServiceReq)
        let serviceResp = try conn.receivePlist()

        if let err = serviceResp["Error"] as? String {
            throw LockdownClientError.serviceStartFailed(err)
        }
        guard let portNum = serviceResp["Port"] as? NSNumber else {
            throw LockdownClientError.serviceStartFailed(WQLocale.pick(en: "No valid service port returned", zh: "未返回有效的服务端口号"))
        }
        let portInt = portNum.int64Value
        guard portInt >= 1, portInt <= 65_535, Double(portInt) == portNum.doubleValue else {
            throw LockdownClientError.serviceStartFailed(WQLocale.pick(en: "No valid service port returned", zh: "未返回有效的服务端口号"))
        }
        let enableServiceSSL = (serviceResp["EnableServiceSSL"] as? Bool) ?? false
        guard enableServiceSSL else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Refused unencrypted installation_proxy service (EnableServiceSSL=false): possible TLS downgrade attack",
                zh: "拒绝未加密的 installation_proxy 服务通道 (EnableServiceSSL=false)：疑似 TLS 降级攻击"
            ))
        }
        return (UInt16(portInt), true)
    }

    // MARK: - Step 3: `com.apple.mobile.installation_proxy` Browse

    private static let maxBrowsePackets = 4_096
    private static let maxBrowseRecords = 32_768

    func browseApplications(
        host: String,
        port: UInt16,
        useTLS: Bool,
        tlsOptions: NWProtocolTLS.Options?
    ) throws -> [InstalledAppRegistryRecord] {
        guard useTLS, let verifiedTLSOptions = tlsOptions else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Refused unencrypted installation_proxy Browse session: TLS pinning is mandatory",
                zh: "拒绝未加密的 installation_proxy Browse 会话：强制要求 TLS 证书固定"
            ))
        }
        let conn = try SyncNWChannel.connect(
            host: host,
            port: port,
            tlsOptions: verifiedTLSOptions
        )
        defer { conn.close() }

        let browseReq: [String: Any] = [
            "Command": "Browse",
            "ClientOptions": [
                "ApplicationType": "Any",
                "ReturnAttributes": [
                    "CFBundleIdentifier",
                    "CFBundleDisplayName",
                    "CFBundleName",
                    "CFBundleExecutable",
                    "CFBundleShortVersionString",
                    "CFBundleVersion",
                    "ApplicationType",
                    "SignerIdentity",
                    "ProfileValidated",
                    "UPPValidated",
                    "FreeProfileValidated",
                    "ApplicationDSID",
                    "IsAppStoreVendable",
                    "HasMIDBasedSINF",
                    "BetaApp",
                    "Entitlements",
                    "UIBackgroundModes",
                    "TeamIdentifier",
                    "BundlePath",
                    "Path",
                    "Container"
                ]
            ]
        ]

        try conn.sendPlist(browseReq)

        var records: [InstalledAppRegistryRecord] = []
        var packetCount = 0
        while true {
            packetCount += 1
            guard packetCount <= Self.maxBrowsePackets else {
                throw LockdownClientError.protocolError(WQLocale.pick(
                    en: "instproxy Browse exceeded maximum packet quota (\(Self.maxBrowsePackets))",
                    zh: "instproxy Browse 响应包数量超出安全上限 (\(Self.maxBrowsePackets))"
                ))
            }
            let packet = try conn.receivePlist()
            if let err = packet["Error"] as? String {
                throw LockdownClientError.protocolError(WQLocale.pick(
                    en: "instproxy error: \(err)",
                    zh: "instproxy 错误: \(err)"
                ))
            }
            if let list = packet["CurrentList"] as? [[String: Any]] {
                for item in list {
                    if let rec = InstalledAppRegistryRecord.fromDictionary(item) {
                        guard records.count < Self.maxBrowseRecords else {
                            throw LockdownClientError.protocolError(WQLocale.pick(
                                en: "instproxy Browse exceeded maximum record quota (\(Self.maxBrowseRecords))",
                                zh: "instproxy Browse 应用记录数超出安全上限 (\(Self.maxBrowseRecords))"
                            ))
                        }
                        records.append(rec)
                    }
                }
            }
            let status = packet["Status"] as? String
            if status == "Complete" || (status == nil && packet["CurrentList"] == nil) {
                break
            }
        }
        return InstalledAppRegistryScanner.shared.deduplicate(records)
    }

    // MARK: - Security.framework TLS Identity Setup

    internal func createTLSOptions(from pairing: LockdownPairingFile) throws -> NWProtocolTLS.Options {
        guard let certRef = SecCertificateCreateWithData(nil, pairing.hostCertificateDER as CFData) else {
            throw LockdownClientError.invalidPairingFile(WQLocale.pick(
                en: "Invalid HostCertificate X.509 DER format",
                zh: "HostCertificate X.509 DER 格式无效"
            ))
        }

        let unwrappedKeyDER = LockdownPairingFile.unwrapPKCS8PrivateKeyIfNeeded(pairing.hostPrivateKeyDER)
        let rsaAttrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate
        ]
        let ecAttrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate
        ]

        guard let privKey = SecKeyCreateWithData(unwrappedKeyDER as CFData, rsaAttrs as CFDictionary, nil)
                ?? SecKeyCreateWithData(pairing.hostPrivateKeyDER as CFData, rsaAttrs as CFDictionary, nil)
                ?? SecKeyCreateWithData(pairing.hostPrivateKeyDER as CFData, ecAttrs as CFDictionary, nil) else {
            throw LockdownClientError.invalidPairingFile(WQLocale.pick(
                en: "HostPrivateKey format is not recognized by Security.framework",
                zh: "HostPrivateKey 私钥格式无法被系统 Security 框架识别"
            ))
        }

        let secIdentity = try importIdentityIntoKeychain(certificate: certRef, privateKey: privKey)
        guard let nwIdentity = sec_identity_create(secIdentity) else {
            throw LockdownClientError.identityImportFailed(errSecInternalError)
        }

        let tls = NWProtocolTLS.Options()
        let secOpts = tls.securityProtocolOptions
        sec_protocol_options_set_local_identity(secOpts, nwIdentity)
        sec_protocol_options_set_min_tls_protocol_version(secOpts, .TLSv12)

        let hostCertDER = SecCertificateCopyData(certRef) as Data
        let hostPubKeyData: Data? = SecCertificateCopyKey(certRef).flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? }
        let expectedDeviceDER = pairing.deviceCertificateDER
        let expectedRootCert: SecCertificate? = pairing.rootCertificateDER.flatMap {
            SecCertificateCreateWithData(nil, $0 as CFData)
        }

        let verifyQueue = DispatchQueue(label: "com.wqguard.lockdown.tlsverify")
        sec_protocol_options_set_verify_block(secOpts, { _, trust, completion in
            let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            guard let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate],
                  let leafCert = chain.first else {
                completion(false)
                return
            }

            let leafDER = SecCertificateCopyData(leafCert) as Data
            let leafPubKeyData: Data? = SecCertificateCopyKey(leafCert).flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? }

            // Block reflection / MITM impersonation using HostCertificate + HostPrivateKey from the pairing record itself
            if leafDER == hostCertDER || (hostPubKeyData != nil && leafPubKeyData == hostPubKeyData) {
                completion(false)
                return
            }

            // When DeviceCertificate is present in the pairing record, strictly pin chain[0] to exact DeviceCertificate DER bytes
            // (never falling through to RootCertificate, which also signed HostCertificate).
            if let devDER = expectedDeviceDER {
                completion(leafDER == devDER)
                return
            }

            // Fallback ONLY when DeviceCertificate is omitted and RootCertificate is present
            if let rootCert = expectedRootCert {
                _ = SecTrustSetNetworkFetchAllowed(secTrust, false)
                let x509Policy = SecPolicyCreateBasicX509()
                SecTrustSetPolicies(secTrust, x509Policy)
                SecTrustSetAnchorCertificates(secTrust, [rootCert] as CFArray)
                SecTrustSetAnchorCertificatesOnly(secTrust, true)
                if SecTrustEvaluateWithError(secTrust, nil) {
                    completion(true)
                    return
                }
            }

            // Fail-closed: never accept unverified STARTTLS peers when pinning certificates are missing or mismatched
            completion(false)
        }, verifyQueue)

        return tls
    }

    private static let keychainLock = NSLock()

    private func importIdentityIntoKeychain(certificate: SecCertificate, privateKey: SecKey) throws -> SecIdentity {
        Self.keychainLock.lock()
        defer { Self.keychainLock.unlock() }
        let targetCertDER = SecCertificateCopyData(certificate) as Data

        // Clean previous items under our isolated label
        SecItemDelete([
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: keychainLabel
        ] as CFDictionary)
        SecItemDelete([
            kSecClass: kSecClassKey,
            kSecAttrLabel: keychainLabel
        ] as CFDictionary)

        // 1. Add Certificate & retrieve Apple-computed kSecAttrApplicationLabel (public key SHA-1)
        var certAttrsResult: CFTypeRef?
        let addCertStatus = SecItemAdd([
            kSecClass: kSecClassCertificate,
            kSecValueRef: certificate,
            kSecAttrLabel: keychainLabel,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecReturnAttributes: true
        ] as CFDictionary, &certAttrsResult)

        guard addCertStatus == errSecSuccess || addCertStatus == errSecDuplicateItem else {
            throw LockdownClientError.identityImportFailed(addCertStatus)
        }

        var appLabelData: Data? = (certAttrsResult as? [CFString: Any])?[kSecAttrApplicationLabel] as? Data
        if appLabelData == nil {
            var fetchedAttrs: CFTypeRef?
            if SecItemCopyMatching([
                kSecClass: kSecClassCertificate,
                kSecAttrLabel: keychainLabel,
                kSecReturnAttributes: true,
                kSecMatchLimit: kSecMatchLimitOne
            ] as CFDictionary, &fetchedAttrs) == errSecSuccess {
                appLabelData = (fetchedAttrs as? [CFString: Any])?[kSecAttrApplicationLabel] as? Data
            }
        }

        // 2. Add Private Key paired via kSecAttrApplicationLabel (with fallback letting Keychain auto-compute)
        var addKeyQuery: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecValueRef: privateKey,
            kSecAttrLabel: keychainLabel,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        if let klbl = appLabelData {
            addKeyQuery[kSecAttrApplicationLabel] = klbl
        }
        var addKeyStatus = SecItemAdd(addKeyQuery as CFDictionary, nil)
        if addKeyStatus != errSecSuccess && addKeyStatus != errSecDuplicateItem && appLabelData != nil {
            addKeyQuery.removeValue(forKey: kSecAttrApplicationLabel)
            addKeyStatus = SecItemAdd(addKeyQuery as CFDictionary, nil)
        }
        guard addKeyStatus == errSecSuccess || addKeyStatus == errSecDuplicateItem else {
            throw LockdownClientError.identityImportFailed(addKeyStatus)
        }

        // 3. Fetch paired SecIdentity (first by ApplicationLabel, then by matching Certificate DER across app keychain)
        if let klbl = appLabelData {
            var identityRef: CFTypeRef?
            let idStatus = SecItemCopyMatching([
                kSecClass: kSecClassIdentity,
                kSecAttrApplicationLabel: klbl,
                kSecReturnRef: true,
                kSecMatchLimit: kSecMatchLimitOne
            ] as CFDictionary, &identityRef)
            if idStatus == errSecSuccess, let validRef = identityRef {
                return unsafeBitCast(validRef, to: SecIdentity.self)
            }
        }

        var allIdentitiesRef: CFTypeRef?
        let allStatus = SecItemCopyMatching([
            kSecClass: kSecClassIdentity,
            kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitAll
        ] as CFDictionary, &allIdentitiesRef)
        if allStatus == errSecSuccess, let array = allIdentitiesRef as? [Any] {
            for elem in array {
                let candidate = unsafeBitCast(elem as AnyObject, to: SecIdentity.self)
                var idCert: SecCertificate?
                if SecIdentityCopyCertificate(candidate, &idCert) == errSecSuccess,
                   let c = idCert,
                   (SecCertificateCopyData(c) as Data) == targetCertDER {
                    return candidate
                }
            }
        }

        throw LockdownClientError.identityImportFailed(allStatus == errSecSuccess ? errSecItemNotFound : allStatus)
    }

    // MARK: - Low-Level POSIX Socket Helpers (4-byte Big-Endian Length + XML Plist)

    private static func connectPOSIXSocket(host: String, port: UInt16, timeoutMs: Int32) throws -> Int32 {
        let validatedHost = try validateAllowedLocalHost(host)
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV

        var res: UnsafeMutablePointer<addrinfo>?
        let portStr = String(port)
        guard getaddrinfo(validatedHost, portStr, &hints, &res) == 0, let firstAddr = res else {
            throw LockdownClientError.lockdownUnreachable(validatedHost)
        }
        defer { freeaddrinfo(res) }

        let fd = Darwin.socket(firstAddr.pointee.ai_family, firstAddr.pointee.ai_socktype, firstAddr.pointee.ai_protocol)
        guard fd >= 0 else {
            throw LockdownClientError.lockdownUnreachable(host)
        }

        // Prevent SIGPIPE on closed peer sockets
        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        // Non-blocking connect with poll timeout
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        let rc = Darwin.connect(fd, firstAddr.pointee.ai_addr, firstAddr.pointee.ai_addrlen)
        if rc != 0 && errno != EINPROGRESS {
            Darwin.close(fd)
            throw LockdownClientError.lockdownUnreachable(host)
        }

        if rc != 0 {
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let pollRes = Darwin.poll(&pfd, 1, timeoutMs)
            if pollRes <= 0 {
                Darwin.close(fd)
                throw LockdownClientError.lockdownUnreachable(host)
            }
            var soErr: Int32 = 0
            var errLen = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &errLen)
            if soErr != 0 {
                Darwin.close(fd)
                throw LockdownClientError.lockdownUnreachable(host)
            }
        }

        // Restore blocking mode with 8s read/write timeout
        _ = fcntl(fd, F_SETFL, flags)
        var tv = timeval(tv_sec: 8, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        return fd
    }

    static func writePlistPacket(_ dict: [String: Any], toFD fd: Int32, step: String = "Lockdown") throws {
        setSocketNoSigPipe(fd)
        let plistData = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        var lengthBE = UInt32(plistData.count).bigEndian
        var packet = Data(bytes: &lengthBE, count: 4)
        packet.append(plistData)

        try packet.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return }
            var sent = 0
            while sent < rawBuf.count {
                let n = sendWithoutSigPipe(fd, base.advanced(by: sent), rawBuf.count - sent)
                if n < 0 && errno == EINTR {
                    continue
                }
                if n <= 0 {
                    let errCode = errno
                    if errCode == EPIPE || errCode == ECONNRESET {
                        throw LockdownClientError.protocolError(WQLocale.pick(
                            en: "Connection closed by peer during \(step) (EOF/EPIPE)",
                            zh: "\(step) 阶段连接被对端关闭 (EOF/EPIPE)"
                        ))
                    }
                    throw LockdownClientError.protocolError(WQLocale.pick(
                        en: "Socket write interrupted during \(step) (errno=\(errCode))",
                        zh: "\(step) 阶段 Socket 写入中断 (errno=\(errCode))"
                    ))
                }
                sent += n
            }
        }
    }

    private static let incrementalReadChunkBytes = 65_536
    private static let maxPacketDeadlineNs: UInt64 = 30 * 1_000_000_000

    static func readPlistPacket(fromFD fd: Int32, step: String = "Lockdown") throws -> [String: Any] {
        setSocketNoSigPipe(fd)
        let header = try readExactBytes(count: 4, fromFD: fd, step: step)
        let length = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        guard length > 0, length <= 64 * 1024 * 1024 else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Invalid \(step) packet length: \(length)",
                zh: "\(step) 非法数据包长度: \(length)"
            ))
        }
        let body = try readExactBytes(count: Int(length), fromFD: fd, step: step)
        guard let dict = (try? PropertyListSerialization.propertyList(from: body, options: [], format: nil)) as? [String: Any] else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "\(step) response payload is not a dictionary plist",
                zh: "\(step) 响应载荷不是有效的字典 Plist"
            ))
        }
        return dict
    }

    private static func readExactBytes(count: Int, fromFD fd: Int32, step: String) throws -> Data {
        guard count >= 0 else {
            throw LockdownClientError.protocolError("Negative read length")
        }
        if count == 0 {
            return Data()
        }
        var buffer = Data()
        buffer.reserveCapacity(min(count, incrementalReadChunkBytes))
        var chunk = [UInt8](repeating: 0, count: min(count, incrementalReadChunkBytes))
        let deadlineNs = DispatchTime.now().uptimeNanoseconds &+ maxPacketDeadlineNs

        while buffer.count < count {
            if DispatchTime.now().uptimeNanoseconds >= deadlineNs {
                throw LockdownClientError.protocolError(WQLocale.pick(
                    en: "Overall packet read deadline exceeded during \(step)",
                    zh: "\(step) 阶段数据包读取总超时"
                ))
            }
            let remaining = count - buffer.count
            let toRead = min(chunk.count, remaining)
            let n = chunk.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.recv(fd, base, toRead, 0)
            }
            if n < 0 && errno == EINTR {
                continue
            }
            if n == 0 {
                throw LockdownClientError.protocolError(WQLocale.pick(
                    en: "Peer closed connection during \(step) (EOF)",
                    zh: "\(step) 阶段对端主动关闭连接 (EOF)"
                ))
            }
            if n < 0 {
                let errCode = errno
                if errCode == ECONNRESET {
                    throw LockdownClientError.protocolError(WQLocale.pick(
                        en: "Connection reset by peer during \(step) (EOF/ECONNRESET)",
                        zh: "\(step) 阶段连接被对端重置 (EOF/ECONNRESET)"
                    ))
                }
                throw LockdownClientError.protocolError(WQLocale.pick(
                    en: "Socket read timeout during \(step) (errno=\(errCode))",
                    zh: "\(step) 阶段 Socket 读取超时 (errno=\(errCode))"
                ))
            }
            buffer.append(contentsOf: chunk[0..<n])
        }
        return buffer
    }
}

// MARK: - Ephemeral Loopback Relay for Clean STARTTLS Upgrade

@inline(__always)
@discardableResult
private func setSocketNoSigPipe(_ fd: Int32) -> Bool {
    #if canImport(Darwin)
    guard fd >= 0 else { return false }
    var noSigPipe: Int32 = 1
    if Darwin.setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size)) == 0 {
        return true
    }
    var current: Int32 = 0
    var len = socklen_t(MemoryLayout<Int32>.size)
    if Darwin.getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &current, &len) == 0, current == 1 {
        return true
    }
    return false
    #else
    return true
    #endif
}

private func sendWithoutSigPipe(_ fd: Int32, _ buf: UnsafeRawPointer, _ len: Int) -> Int {
    #if canImport(Darwin)
    if !setSocketNoSigPipe(fd) {
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        _ = Darwin.poll(&pfd, 1, 0)
        if (pfd.revents & Int16(POLLNVAL)) != 0 {
            errno = EBADF
        } else {
            errno = EPIPE
        }
        return -1
    }
    return Darwin.send(fd, buf, len, 0)
    #else
    return Darwin.send(fd, buf, len, 0)
    #endif
}

private final class LocalSocketTLSRelay: @unchecked Sendable {
    let localPort: UInt16
    private let listenFD: Int32
    private let upstreamFD: Int32
    private var clientFD: Int32 = -1
    private let lock = NSLock()
    private var isStopped = false
    private let acceptGroup = DispatchGroup()
    private let pumpGroup = DispatchGroup()

    init(upstreamFD: Int32) throws {
        setSocketNoSigPipe(upstreamFD)
        self.upstreamFD = upstreamFD
        let lfd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard lfd >= 0 else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Unable to create local TLS relay socket",
                zh: "无法创建本地 TLS 中继套接字"
            ))
        }
        var reuse: Int32 = 1
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let bindRes = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(lfd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindRes == 0, Darwin.listen(lfd, 1) == 0 else {
            Darwin.close(lfd)
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Unable to bind local loopback port",
                zh: "无法绑定本地回环端口"
            ))
        }

        let lFlags = fcntl(lfd, F_GETFL, 0)
        if lFlags >= 0 {
            _ = fcntl(lfd, F_SETFL, lFlags | O_NONBLOCK)
        }

        var boundAddr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &boundAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(lfd, $0, &addrLen)
            }
        }
        self.listenFD = lfd
        self.localPort = UInt16(bigEndian: boundAddr.sin_port)

        acceptGroup.enter()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            defer { self?.acceptGroup.leave() }
            self?.acceptAndPump()
        }
    }

    deinit {
        stop()
    }

    private func acceptAndPump() {
        var acceptedFD: Int32 = -1
        while true {
            lock.lock()
            let stopped = isStopped
            lock.unlock()
            if stopped { return }

            var pfd = pollfd(fd: listenFD, events: Int16(POLLIN), revents: 0)
            let pr = Darwin.poll(&pfd, 1, 50)
            if pr < 0 && errno == EINTR { continue }
            if pr < 0 { return }
            if pr == 0 { continue }

            var clientAddr = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let cfd = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.accept(listenFD, $0, &len)
                }
            }
            if cfd < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { continue }
                return
            }
            acceptedFD = cfd
            break
        }

        guard acceptedFD >= 0 else { return }
        var noSigPipe: Int32 = 1
        setsockopt(acceptedFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        let cFlags = fcntl(acceptedFD, F_GETFL, 0)
        if cFlags >= 0 {
            _ = fcntl(acceptedFD, F_SETFL, cFlags & ~O_NONBLOCK)
        }

        lock.lock()
        if isStopped {
            lock.unlock()
            Darwin.close(acceptedFD)
            return
        }
        self.clientFD = acceptedFD
        pumpGroup.enter()
        pumpGroup.enter()
        lock.unlock()

        let acceptedClientFD = acceptedFD
        let upFD = self.upstreamFD
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            defer { self?.pumpGroup.leave() }
            guard let self else { return }
            self.lock.lock()
            let stopped = self.isStopped
            self.lock.unlock()
            guard !stopped else { return }
            Self.pump(from: acceptedClientFD, to: upFD)
            Darwin.shutdown(upFD, SHUT_WR)
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            defer { self?.pumpGroup.leave() }
            guard let self else { return }
            self.lock.lock()
            let stopped = self.isStopped
            self.lock.unlock()
            guard !stopped else { return }
            Self.pump(from: upFD, to: acceptedClientFD)
            Darwin.shutdown(acceptedClientFD, SHUT_WR)
        }
    }

    private static func pump(from src: Int32, to dst: Int32) {
        var buf = [UInt8](repeating: 0, count: 16384)
        while true {
            let n = Darwin.recv(src, &buf, buf.count, 0)
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { break }
            var sent = 0
            while sent < n {
                let w = buf.withUnsafeBytes { ptr in
                    sendWithoutSigPipe(dst, ptr.baseAddress!.advanced(by: sent), n - sent)
                }
                if w < 0 && errno == EINTR { continue }
                if w <= 0 { return }
                sent += w
            }
        }
    }

    func stop() {
        lock.lock()
        let already = isStopped
        isStopped = true
        let cfd = clientFD
        lock.unlock()
        guard !already else { return }

        Darwin.shutdown(upstreamFD, SHUT_RDWR)
        if cfd >= 0 {
            Darwin.shutdown(cfd, SHUT_RDWR)
        }

        _ = acceptGroup.wait(timeout: .now() + 1.0)
        lock.lock()
        let finalClientFD = clientFD
        lock.unlock()
        if finalClientFD >= 0 && finalClientFD != cfd {
            Darwin.shutdown(finalClientFD, SHUT_RDWR)
        }
        _ = pumpGroup.wait(timeout: .now() + 1.0)

        Darwin.close(listenFD)
        if finalClientFD >= 0 {
            Darwin.close(finalClientFD)
        }
        Darwin.close(upstreamFD)
    }
}

// MARK: - Synchronous Wrapper over NWConnection for Framing Plist Streams

private final class SyncNWChannel: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.wqguard.nwchannel")

    private init(connection: NWConnection) {
        self.connection = connection
    }

    static func connect(host: String, port: UInt16, tlsOptions: NWProtocolTLS.Options?) throws -> SyncNWChannel {
        guard let verifiedTLS = tlsOptions else {
            throw LockdownClientError.protocolError(WQLocale.pick(
                en: "Refused unencrypted SyncNWChannel connection: TLS options are mandatory",
                zh: "拒绝未加密的 SyncNWChannel 连接：强制要求 TLS 安全选项"
            ))
        }
        let nwHost = try LockdownInstProxyClient.makeNumericNWHost(host)
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = 5
        let params = NWParameters(tls: verifiedTLS, tcp: tcp)
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw LockdownClientError.protocolError(WQLocale.pick(en: "Invalid port: \(port)", zh: "无效端口号: \(port)"))
        }
        let conn = NWConnection(host: nwHost, port: nwPort, using: params)
        let channel = SyncNWChannel(connection: conn)

        let sema = DispatchSemaphore(value: 0)
        let stateBox = LockedBox<Result<Void, Error>?>(nil)

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if stateBox.setIfNil(.success(())) {
                    sema.signal()
                }
            case .waiting(let err):
                switch err {
                case .tls:
                    if stateBox.setIfNil(.failure(LockdownClientError.protocolError(err.localizedDescription))) {
                        sema.signal()
                    }
                case .posix(let code) where code == .ECONNRESET || code == .EPIPE || code == .ECONNABORTED:
                    if stateBox.setIfNil(.failure(LockdownClientError.protocolError(err.localizedDescription))) {
                        sema.signal()
                    }
                default:
                    break
                }
            case .failed(let err):
                if stateBox.setIfNil(.failure(LockdownClientError.protocolError(err.localizedDescription))) {
                    sema.signal()
                }
            case .cancelled:
                if stateBox.setIfNil(.failure(LockdownClientError.protocolError(WQLocale.pick(en: "Connection cancelled", zh: "连接已取消")))) {
                    sema.signal()
                }
            default:
                break
            }
        }
        conn.start(queue: channel.queue)

        if sema.wait(timeout: .now() + 6.0) == .timedOut {
            conn.cancel()
            throw LockdownClientError.lockdownUnreachable(host)
        }
        if case .failure(let err) = stateBox.value {
            conn.cancel()
            throw err
        }
        return channel
    }

    func sendPlist(_ dict: [String: Any]) throws {
        let plistData = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        var lengthBE = UInt32(plistData.count).bigEndian
        var packet = Data(bytes: &lengthBE, count: 4)
        packet.append(plistData)

        let sema = DispatchSemaphore(value: 0)
        let errBox = LockedBox<Error?>(nil)
        connection.send(content: packet, completion: .contentProcessed { err in
            errBox.value = err
            sema.signal()
        })
        if sema.wait(timeout: .now() + 8.0) == .timedOut {
            throw LockdownClientError.protocolError(WQLocale.pick(en: "Request send timed out", zh: "发送请求超时"))
        }
        if let err = errBox.value {
            throw LockdownClientError.protocolError(err.localizedDescription)
        }
    }

    func receivePlist() throws -> [String: Any] {
        let header = try receiveExact(length: 4)
        let bodyLen = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        guard bodyLen > 0, bodyLen <= 64 * 1024 * 1024 else {
            throw LockdownClientError.protocolError(WQLocale.pick(en: "Invalid response packet length: \(bodyLen)", zh: "非法响应包长度: \(bodyLen)"))
        }
        let body = try receiveExact(length: Int(bodyLen))
        guard let dict = (try? PropertyListSerialization.propertyList(from: body, options: [], format: nil)) as? [String: Any] else {
            throw LockdownClientError.protocolError(WQLocale.pick(en: "Unable to parse installation_proxy response plist", zh: "无法解析 installation_proxy 响应 Plist"))
        }
        return dict
    }

    private static let incrementalReserveBytes = 65_536
    private static let maxPacketDeadlineNs: UInt64 = 30 * 1_000_000_000

    private func receiveExact(length: Int) throws -> Data {
        guard length >= 0 else {
            throw LockdownClientError.protocolError("Negative response packet length")
        }
        if length == 0 {
            return Data()
        }
        var accumulated = Data()
        accumulated.reserveCapacity(min(length, Self.incrementalReserveBytes))
        let deadlineNs = DispatchTime.now().uptimeNanoseconds &+ Self.maxPacketDeadlineNs

        while accumulated.count < length {
            let nowNs = DispatchTime.now().uptimeNanoseconds
            guard nowNs < deadlineNs else {
                throw LockdownClientError.protocolError(WQLocale.pick(
                    en: "Overall packet read deadline exceeded from installation_proxy",
                    zh: "读取 installation_proxy 数据包总超时"
                ))
            }
            let remainingNs = deadlineNs - nowNs
            let waitTimeoutSec = min(12.0, Double(remainingNs) / 1_000_000_000.0)
            let needed = min(Self.incrementalReserveBytes, length - accumulated.count)
            let sema = DispatchSemaphore(value: 0)
            let chunkBox = LockedBox<Result<Data, Error>?>(nil)
            connection.receive(minimumIncompleteLength: 1, maximumLength: needed) { data, _, isComplete, err in
                if let err = err {
                    chunkBox.value = .failure(LockdownClientError.protocolError(err.localizedDescription))
                } else if let data = data, !data.isEmpty {
                    chunkBox.value = .success(data)
                } else if isComplete {
                    chunkBox.value = .failure(LockdownClientError.protocolError(WQLocale.pick(en: "Connection closed prematurely", zh: "连接提前关闭")))
                } else {
                    chunkBox.value = .failure(LockdownClientError.protocolError(WQLocale.pick(en: "Unexpected empty read chunk from installation_proxy", zh: "installation_proxy 返回空数据分片")))
                }
                sema.signal()
            }
            if sema.wait(timeout: .now() + waitTimeoutSec) == .timedOut {
                throw LockdownClientError.protocolError(WQLocale.pick(en: "Timed out waiting for installation_proxy data", zh: "等待 installation_proxy 数据超时"))
            }
            switch chunkBox.value {
            case .success(let chunk):
                guard !chunk.isEmpty else {
                    throw LockdownClientError.protocolError(WQLocale.pick(en: "Unexpected empty read chunk from installation_proxy", zh: "installation_proxy 返回空数据分片"))
                }
                accumulated.append(chunk)
            case .failure(let err):
                throw err
            case .none:
                throw LockdownClientError.protocolError(WQLocale.pick(en: "Unknown read error", zh: "未知读取错误"))
            }
        }
        return accumulated
    }

    func close() {
        connection.cancel()
    }
}

private final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: T

    init(_ initial: T) {
        self.storage = initial
    }

    var value: T {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storage
        }
        set {
            lock.lock()
            storage = newValue
            lock.unlock()
        }
    }

    func setIfNil<Wrapped>(_ newVal: Wrapped) -> Bool where T == Optional<Wrapped> {
        lock.lock()
        defer { lock.unlock() }
        if storage == nil {
            storage = newVal
            return true
        }
        return false
    }
}
