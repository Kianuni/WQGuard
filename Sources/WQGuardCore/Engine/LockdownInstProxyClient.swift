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
            return "配对文件 (.mobiledevicepairing) 无效或缺失关键字段: \(detail)"
        case .identityImportFailed(let status):
            return "无法从配对文件加载 TLS 客户端证书身份 (Keychain OSStatus: \(status))。"
        case .lockdownUnreachable(let host):
            return "无法连接本机 lockdownd 服务 (\(host):62078)。请确认已开启 StikDebug / SideStore 的 LocalDevVPN（10.7.0.1），或改用「导入已安装应用快照」方式。"
        case .protocolError(let msg):
            return "lockdownd / installation_proxy 协议交互异常: \(msg)"
        case .sessionRejected(let err):
            return "配对会话被设备拒绝 (\(err))。该配对文件可能已过期（重置过信任电脑后需重新生成配对文件）。"
        case .serviceStartFailed(let err):
            return "启动 com.apple.mobile.installation_proxy 服务失败: \(err)"
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
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        let stem = url.deletingPathExtension().lastPathComponent
        return try parse(data: data, fallbackUDID: stem.isEmpty ? nil : stem)
    }

    public static func parse(data: Data, fallbackUDID: String? = nil) throws -> LockdownPairingFile {
        guard let outerPlist = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] else {
            throw LockdownClientError.invalidPairingFile("不是有效的 XML/Binary Plist 文件")
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

        guard let hostID = (plist["HostID"] as? String) ?? (plist["HostId"] as? String), !hostID.isEmpty else {
            throw LockdownClientError.invalidPairingFile("缺少 HostID（确认导入的是配对文件而非普通配置 plist）")
        }
        guard let systemBUID = (plist["SystemBUID"] as? String) ?? (plist["SystemBuid"] as? String), !systemBUID.isEmpty else {
            throw LockdownClientError.invalidPairingFile("缺少 SystemBUID")
        }
        guard let hostCertRaw = Self.extractDataField(plist["HostCertificate"]),
              let hostCertDER = Self.decodePEMOrDER(hostCertRaw) else {
            throw LockdownClientError.invalidPairingFile("缺少或无法解码 HostCertificate")
        }
        guard let hostKeyRaw = Self.extractDataField(plist["HostPrivateKey"]),
              let hostKeyDER = Self.decodePEMOrDER(hostKeyRaw) else {
            throw LockdownClientError.invalidPairingFile("缺少或无法解码 HostPrivateKey")
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
            return Data(base64Encoded: base64Body, options: .ignoreUnknownCharacters)
        }
        // Raw DER ASN.1 SEQUENCE starts with 0x30
        if trimmedRaw.first == 0x30 {
            return trimmedRaw
        }
        return Data(base64Encoded: trimmedRaw, options: .ignoreUnknownCharacters)
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
                if idx + payloadLen <= bytes.count && bytes[idx] == 0x30 {
                    return Data(bytes[idx..<(idx + payloadLen)])
                }
                break
            }
            idx += 1
        }
        return der
    }
}

/// Pure-Swift client speaking Apple's Lockdown + `com.apple.mobile.installation_proxy` plist protocol.
public final class LockdownInstProxyClient: @unchecked Sendable {
    public static let shared = LockdownInstProxyClient()
    public static let lockdownPort: UInt16 = 62078

    private let keychainLabel = "com.wqguard.lockdown.pairing.v1"

    public init() {}

    // MARK: - Public Entry Point

    /// Connects to `lockdownd` over LocalDevVPN (default `10.7.0.1`, fallback `127.0.0.1`),
    /// starts `com.apple.mobile.installation_proxy`, and returns all installed app records.
    public func fetchInstalledApps(
        pairing: LockdownPairingFile,
        preferredHost: String = "10.7.0.1"
    ) async throws -> [InstalledAppRegistryRecord] {
        return try await Task.detached(priority: .userInitiated) { [self] in
            let tlsOptions = try self.createTLSOptions(from: pairing)
            var candidateHosts: [String] = []
            for h in [preferredHost, "10.7.0.1", "10.7.0.2", "127.0.0.1"] where !h.isEmpty && !candidateHosts.contains(h) {
                candidateHosts.append(h)
            }

            var connectedFD: Int32 = -1
            var activeHost = preferredHost
            for host in candidateHosts {
                if let fd = try? Self.connectPOSIXSocket(host: host, port: Self.lockdownPort, timeoutMs: 2200) {
                    connectedFD = fd
                    activeHost = host
                    break
                }
            }

            guard connectedFD >= 0 else {
                throw LockdownClientError.lockdownUnreachable(preferredHost)
            }

            // Step 1 & 2: Plaintext `QueryType` and `StartSession` on `connectedFD`
            let (servicePort, enableServiceSSL) = try self.negotiateInstallationProxyPort(
                rawSocketFD: connectedFD,
                pairing: pairing,
                tlsOptions: tlsOptions
            )

            // Step 3: Connect to `com.apple.mobile.installation_proxy` on `activeHost:servicePort`
            return try self.browseApplications(
                host: activeHost,
                port: servicePort,
                useTLS: enableServiceSSL,
                tlsOptions: tlsOptions
            )
        }.value
    }

    // MARK: - Step 1 & 2: Lockdown Session & StartService

    private func negotiateInstallationProxyPort(
        rawSocketFD: Int32,
        pairing: LockdownPairingFile,
        tlsOptions: NWProtocolTLS.Options
    ) throws -> (port: UInt16, enableSSL: Bool) {
        var socketTransferredToRelay = false
        defer {
            if !socketTransferredToRelay && rawSocketFD >= 0 {
                Darwin.close(rawSocketFD)
            }
        }

        // 1. QueryType
        try Self.writePlistPacket(["Request": "QueryType", "Label": "WQGuard"], toFD: rawSocketFD)
        let queryResp = try Self.readPlistPacket(fromFD: rawSocketFD)
        guard (queryResp["Type"] as? String) == "com.apple.mobile.lockdown" else {
            throw LockdownClientError.protocolError("非预期的 QueryType 响应")
        }

        // 2. StartSession
        let startSessionReq: [String: Any] = [
            "Request": "StartSession",
            "HostID": pairing.hostID,
            "SystemBUID": pairing.systemBUID,
            "Label": "WQGuard"
        ]
        try Self.writePlistPacket(startSessionReq, toFD: rawSocketFD)
        let sessionResp = try Self.readPlistPacket(fromFD: rawSocketFD)
        if let err = sessionResp["Error"] as? String {
            throw LockdownClientError.sessionRejected(err)
        }

        let enableSessionSSL = (sessionResp["EnableSessionSSL"] as? Bool) ?? false
        let startServiceReq: [String: Any] = [
            "Request": "StartService",
            "Service": "com.apple.mobile.installation_proxy",
            "Label": "WQGuard"
        ]

        let serviceResp: [String: Any]
        if enableSessionSSL {
            // Upgrade the existing TCP socket to TLS via a local ephemeral loopback bridge
            let relay = try LocalSocketTLSRelay(upstreamFD: rawSocketFD)
            socketTransferredToRelay = true
            defer { relay.stop() }

            let conn = try SyncNWChannel.connect(host: "127.0.0.1", port: relay.localPort, tlsOptions: tlsOptions)
            defer { conn.close() }

            try conn.sendPlist(startServiceReq)
            serviceResp = try conn.receivePlist()
        } else {
            try Self.writePlistPacket(startServiceReq, toFD: rawSocketFD)
            serviceResp = try Self.readPlistPacket(fromFD: rawSocketFD)
        }

        if let err = serviceResp["Error"] as? String {
            throw LockdownClientError.serviceStartFailed(err)
        }
        guard let portNum = serviceResp["Port"] as? NSNumber, portNum.uint16Value > 0 else {
            throw LockdownClientError.serviceStartFailed("未返回有效的服务端口号")
        }
        let enableServiceSSL = (serviceResp["EnableServiceSSL"] as? Bool) ?? false
        return (portNum.uint16Value, enableServiceSSL)
    }

    // MARK: - Step 3: `com.apple.mobile.installation_proxy` Browse

    private func browseApplications(
        host: String,
        port: UInt16,
        useTLS: Bool,
        tlsOptions: NWProtocolTLS.Options
    ) throws -> [InstalledAppRegistryRecord] {
        let conn = try SyncNWChannel.connect(
            host: host,
            port: port,
            tlsOptions: useTLS ? tlsOptions : nil
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
                    "ApplicationDSID",
                    "Entitlements",
                    "UIBackgroundModes",
                    "Path",
                    "Container"
                ]
            ]
        ]

        try conn.sendPlist(browseReq)

        var records: [InstalledAppRegistryRecord] = []
        var seen: Set<String> = []
        while true {
            let packet = try conn.receivePlist()
            if let err = packet["Error"] as? String {
                throw LockdownClientError.protocolError("instproxy 错误: \(err)")
            }
            if let list = packet["CurrentList"] as? [[String: Any]] {
                for item in list {
                    if let rec = InstalledAppRegistryRecord.fromDictionary(item),
                       seen.insert(rec.bundleId).inserted {
                        records.append(rec)
                    }
                }
            }
            let status = packet["Status"] as? String
            if status == "Complete" || (status == nil && packet["CurrentList"] == nil) {
                break
            }
        }
        return records
    }

    // MARK: - Security.framework TLS Identity Setup

    private func createTLSOptions(from pairing: LockdownPairingFile) throws -> NWProtocolTLS.Options {
        guard let certRef = SecCertificateCreateWithData(nil, pairing.hostCertificateDER as CFData) else {
            throw LockdownClientError.invalidPairingFile("HostCertificate X.509 DER 格式无效")
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
            throw LockdownClientError.invalidPairingFile("HostPrivateKey 私钥格式无法被系统 Security 框架识别")
        }

        let secIdentity = try importIdentityIntoKeychain(certificate: certRef, privateKey: privKey)
        guard let nwIdentity = sec_identity_create(secIdentity) else {
            throw LockdownClientError.identityImportFailed(errSecInternalError)
        }

        let tls = NWProtocolTLS.Options()
        let secOpts = tls.securityProtocolOptions
        sec_protocol_options_set_local_identity(secOpts, nwIdentity)
        sec_protocol_options_set_min_tls_protocol_version(secOpts, .TLSv12)

        let expectedDeviceDER = pairing.deviceCertificateDER
        let expectedRootDER = pairing.rootCertificateDER
        let anchorCerts: [SecCertificate] = [expectedRootDER, expectedDeviceDER]
            .compactMap { $0 }
            .compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }

        let verifyQueue = DispatchQueue(label: "com.wqguard.lockdown.tlsverify")
        sec_protocol_options_set_verify_block(secOpts, { _, trust, completion in
            let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()

            // Pin directly against the pairing file's DeviceCertificate / RootCertificate DER bytes
            // because `lockdownd` generates long-lived device certificates that omit standard WebPKI
            // X.509v3 extensions and would otherwise be rejected by iOS WebPKI SecPolicy evaluation.
            if let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate], !chain.isEmpty {
                let presentedDERs = chain.map { SecCertificateCopyData($0) as Data }
                if let devDER = expectedDeviceDER, presentedDERs.contains(devDER) {
                    completion(true)
                    return
                }
                if let rootDER = expectedRootDER, presentedDERs.contains(rootDER) {
                    completion(true)
                    return
                }
            }

            if !anchorCerts.isEmpty {
                let x509Policy = SecPolicyCreateBasicX509()
                SecTrustSetPolicies(secTrust, x509Policy)
                SecTrustSetAnchorCertificates(secTrust, anchorCerts as CFArray)
                SecTrustSetAnchorCertificatesOnly(secTrust, true)
                if SecTrustEvaluateWithError(secTrust, nil) {
                    completion(true)
                    return
                }
            }

            // If pairing file omitted DeviceCertificate/RootCertificate, allow local loopback peer
            completion(expectedDeviceDER == nil && expectedRootDER == nil)
        }, verifyQueue)

        return tls
    }

    private func importIdentityIntoKeychain(certificate: SecCertificate, privateKey: SecKey) throws -> SecIdentity {
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
            if let first = array.first {
                return unsafeBitCast(first as AnyObject, to: SecIdentity.self)
            }
        }

        throw LockdownClientError.identityImportFailed(allStatus)
    }

    // MARK: - Low-Level POSIX Socket Helpers (4-byte Big-Endian Length + XML Plist)

    private static func connectPOSIXSocket(host: String, port: UInt16, timeoutMs: Int32) throws -> Int32 {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP

        var res: UnsafeMutablePointer<addrinfo>?
        let portStr = String(port)
        guard getaddrinfo(host, portStr, &hints, &res) == 0, let firstAddr = res else {
            throw LockdownClientError.lockdownUnreachable(host)
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

    fileprivate static func writePlistPacket(_ dict: [String: Any], toFD fd: Int32) throws {
        let plistData = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        var lengthBE = UInt32(plistData.count).bigEndian
        var packet = Data(bytes: &lengthBE, count: 4)
        packet.append(plistData)

        try packet.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return }
            var sent = 0
            while sent < rawBuf.count {
                let n = Darwin.send(fd, base.advanced(by: sent), rawBuf.count - sent, 0)
                if n <= 0 {
                    throw LockdownClientError.protocolError("Socket 写入中断")
                }
                sent += n
            }
        }
    }

    fileprivate static func readPlistPacket(fromFD fd: Int32) throws -> [String: Any] {
        let header = try readExactBytes(count: 4, fromFD: fd)
        let length = header.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard length > 0, length <= 64 * 1024 * 1024 else {
            throw LockdownClientError.protocolError("非法数据包长度: \(length)")
        }
        let body = try readExactBytes(count: Int(length), fromFD: fd)
        guard let dict = (try? PropertyListSerialization.propertyList(from: body, options: [], format: nil)) as? [String: Any] else {
            throw LockdownClientError.protocolError("响应载荷不是有效的字典 Plist")
        }
        return dict
    }

    private static func readExactBytes(count: Int, fromFD fd: Int32) throws -> Data {
        var buffer = Data(count: count)
        try buffer.withUnsafeMutableBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return }
            var offset = 0
            while offset < count {
                let n = Darwin.recv(fd, base.advanced(by: offset), count - offset, 0)
                if n <= 0 {
                    throw LockdownClientError.protocolError("Socket 读取超时或连接关闭")
                }
                offset += n
            }
        }
        return buffer
    }
}

// MARK: - Ephemeral Loopback Relay for Clean STARTTLS Upgrade

private final class LocalSocketTLSRelay: @unchecked Sendable {
    let localPort: UInt16
    private let listenFD: Int32
    private let upstreamFD: Int32
    private let lock = NSLock()
    private var isStopped = false

    init(upstreamFD: Int32) throws {
        self.upstreamFD = upstreamFD
        let lfd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard lfd >= 0 else {
            throw LockdownClientError.protocolError("无法创建本地 TLS 中继套接字")
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
            throw LockdownClientError.protocolError("无法绑定本地回环端口")
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

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.acceptAndPump()
        }
    }

    private func acceptAndPump() {
        var clientAddr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let clientFD = withUnsafeMutablePointer(to: &clientAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.accept(listenFD, $0, &len)
            }
        }
        guard clientFD >= 0 else { return }
        var noSigPipe: Int32 = 1
        setsockopt(clientFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        let upFD = self.upstreamFD
        DispatchQueue.global(qos: .userInitiated).async {
            Self.pump(from: clientFD, to: upFD)
            Darwin.shutdown(upFD, SHUT_WR)
        }
        DispatchQueue.global(qos: .userInitiated).async {
            Self.pump(from: upFD, to: clientFD)
            Darwin.close(clientFD)
        }
    }

    private static func pump(from src: Int32, to dst: Int32) {
        var buf = [UInt8](repeating: 0, count: 16384)
        while true {
            let n = Darwin.recv(src, &buf, buf.count, 0)
            if n <= 0 { break }
            var sent = 0
            while sent < n {
                let w = buf.withUnsafeBytes { ptr in
                    Darwin.send(dst, ptr.baseAddress!.advanced(by: sent), n - sent, 0)
                }
                if w <= 0 { return }
                sent += w
            }
        }
    }

    func stop() {
        lock.lock()
        let already = isStopped
        isStopped = true
        lock.unlock()
        guard !already else { return }
        Darwin.close(listenFD)
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
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = 5
        let params = NWParameters(tls: tlsOptions, tcp: tcp)
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw LockdownClientError.protocolError("无效端口号: \(port)")
        }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)
        let channel = SyncNWChannel(connection: conn)

        let sema = DispatchSemaphore(value: 0)
        let stateBox = LockedBox<Result<Void, Error>?>(nil)

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if stateBox.setIfNil(.success(())) {
                    sema.signal()
                }
            case .failed(let err):
                if stateBox.setIfNil(.failure(LockdownClientError.protocolError(err.localizedDescription))) {
                    sema.signal()
                }
            case .cancelled:
                if stateBox.setIfNil(.failure(LockdownClientError.protocolError("连接已取消"))) {
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
            throw LockdownClientError.protocolError("发送请求超时")
        }
        if let err = errBox.value {
            throw LockdownClientError.protocolError(err.localizedDescription)
        }
    }

    func receivePlist() throws -> [String: Any] {
        let header = try receiveExact(length: 4)
        let bodyLen = header.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard bodyLen > 0, bodyLen <= 64 * 1024 * 1024 else {
            throw LockdownClientError.protocolError("非法响应包长度: \(bodyLen)")
        }
        let body = try receiveExact(length: Int(bodyLen))
        guard let dict = (try? PropertyListSerialization.propertyList(from: body, options: [], format: nil)) as? [String: Any] else {
            throw LockdownClientError.protocolError("无法解析 installation_proxy 响应 Plist")
        }
        return dict
    }

    private func receiveExact(length: Int) throws -> Data {
        var accumulated = Data()
        accumulated.reserveCapacity(length)
        while accumulated.count < length {
            let needed = length - accumulated.count
            let sema = DispatchSemaphore(value: 0)
            let chunkBox = LockedBox<Result<Data, Error>?>(nil)
            connection.receive(minimumIncompleteLength: 1, maximumLength: needed) { data, _, isComplete, err in
                if let err = err {
                    chunkBox.value = .failure(LockdownClientError.protocolError(err.localizedDescription))
                } else if let data = data, !data.isEmpty {
                    chunkBox.value = .success(data)
                } else if isComplete {
                    chunkBox.value = .failure(LockdownClientError.protocolError("连接提前关闭"))
                } else {
                    chunkBox.value = .success(Data())
                }
                sema.signal()
            }
            if sema.wait(timeout: .now() + 12.0) == .timedOut {
                throw LockdownClientError.protocolError("等待 installation_proxy 数据超时")
            }
            switch chunkBox.value {
            case .success(let chunk):
                accumulated.append(chunk)
            case .failure(let err):
                throw err
            case .none:
                throw LockdownClientError.protocolError("未知读取错误")
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
