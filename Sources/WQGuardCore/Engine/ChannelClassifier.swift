//
//  ChannelClassifier.swift
//  WQGuardCore
//
//  100% read-only installation channel classifier for iOS applications.
//  Distinguishes between Developer Sideloaded, Enterprise In-House, TestFlight, and App Store.
//

import Darwin
import Foundation
import Security

/// Classifies application installation channels based on FairPlay DRM encryption (cryptid),
/// embedded mobileprovision profiles, and receipt metadata.
public enum ChannelClassifier {
    
    /// Structured result of install channel classification.
    public struct ClassificationResult: Sendable, Equatable {
        public let channel: InstallChannel
        public let teamIdentifier: String?
        public let teamName: String?
        public let profileName: String?
        public let isEnterprise: Bool
        public let hasMobileProvision: Bool
        public let hasReceipt: Bool
        public let isFairPlayEncrypted: Bool
        public let isProvisionCMSVerified: Bool
        public let verifiedProvisionTeamPrefixes: Set<String>
        public let details: String
        
        public init(
            channel: InstallChannel,
            teamIdentifier: String? = nil,
            teamName: String? = nil,
            profileName: String? = nil,
            isEnterprise: Bool = false,
            hasMobileProvision: Bool = false,
            hasReceipt: Bool = false,
            isFairPlayEncrypted: Bool = false,
            isProvisionCMSVerified: Bool = false,
            verifiedProvisionTeamPrefixes: Set<String> = [],
            details: String = ""
        ) {
            self.channel = channel
            self.teamIdentifier = teamIdentifier
            self.teamName = teamName
            self.profileName = profileName
            self.isEnterprise = isEnterprise
            self.hasMobileProvision = hasMobileProvision
            self.hasReceipt = hasReceipt
            self.isFairPlayEncrypted = isFairPlayEncrypted
            self.isProvisionCMSVerified = isProvisionCMSVerified
            self.verifiedProvisionTeamPrefixes = verifiedProvisionTeamPrefixes
            self.details = details
        }
    }

    private static let provisioningProfileMarkerKeys: Set<String> = [
        "ProvisionsAllDevices",
        "ProvisionedDevices",
        "TeamIdentifier",
        "ApplicationIdentifierPrefix",
        "Entitlements",
        "BetaReportsActive",
        "CreationDate",
        "ExpirationDate",
        "UUID"
    ]

    private static func looksLikeProvisioningPlist(_ dict: [String: Any]) -> Bool {
        dict.keys.contains { provisioningProfileMarkerKeys.contains($0) }
    }

    /// Extracts encapsulated PKCS#7 `id-data` (`1.2.840.113549.1.7.1`) OCTET STRING payloads from
    /// DER or indefinite-length BER CMS `SignedData` containers when present.
    private static func extractCMSDataPayloads(from rawInput: Data) -> [Data] {
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
        // OID 1.2.840.113549.1.7.1 (pkcs7-data): 06 09 2A 86 48 86 F7 0D 01 07 01
        let pkcs7DataOID = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])
        guard data.count > pkcs7DataOID.count + 4 else { return [] }

        func readBERLength(in buf: Data, at offset: inout Int) -> Int? {
            guard offset < buf.count else { return nil }
            let first = buf[offset]
            offset += 1
            if (first & 0x80) == 0 {
                return Int(first)
            }
            let numBytes = Int(first & 0x7F)
            if numBytes == 0 {
                return -1 // BER indefinite length
            }
            guard numBytes <= 4, offset + numBytes <= buf.count else { return nil }
            var length = 0
            for _ in 0..<numBytes {
                length = (length << 8) | Int(buf[offset])
                offset += 1
            }
            return length
        }

        func appendOctetStringPayload(in buf: Data, at cursor: inout Int, limit: Int, into out: inout Data, depth: Int) -> Bool {
            guard cursor < limit, depth <= 8, out.count < 16 * 1024 * 1024 else { return false }
            let tag = buf[cursor]
            cursor += 1
            if tag == 0x04 {
                guard let len = readBERLength(in: buf, at: &cursor), len >= 0, cursor + len <= limit else { return false }
                if len > 0 {
                    let take = min(len, 16 * 1024 * 1024 - out.count)
                    out.append(buf.subdata(in: cursor..<(cursor + take)))
                }
                cursor += len
                return true
            } else if tag == 0x24 {
                guard let outerLen = readBERLength(in: buf, at: &cursor) else { return false }
                let subLimit = outerLen >= 0 ? min(limit, cursor + outerLen) : limit
                while cursor < subLimit && out.count < 16 * 1024 * 1024 {
                    if outerLen < 0 && cursor + 1 < subLimit && buf[cursor] == 0x00 && buf[cursor + 1] == 0x00 {
                        cursor += 2
                        return true
                    }
                    if !appendOctetStringPayload(in: buf, at: &cursor, limit: subLimit, into: &out, depth: depth + 1) {
                        return false
                    }
                }
                return outerLen >= 0
            }
            return false
        }

        var payloads: [Data] = []
        var searchFrom = 0
        while searchFrom < data.count && payloads.count < 128,
              let oidRange = data.range(of: pkcs7DataOID, options: [], in: searchFrom..<data.count) {
            searchFrom = oidRange.upperBound
            var cursor = oidRange.upperBound
            // Expect [0] EXPLICIT (0xA0)
            guard cursor < data.count, data[cursor] == 0xA0 else { continue }
            cursor += 1
            guard let expLen = readBERLength(in: data, at: &cursor), cursor < data.count else { continue }
            let expLimit = expLen >= 0 ? min(data.count, cursor + expLen) : data.count

            var assembled = Data()
            if appendOctetStringPayload(in: data, at: &cursor, limit: expLimit, into: &assembled, depth: 0),
               !assembled.isEmpty {
                payloads.append(assembled)
            }
        }
        return payloads
    }
    
    /// Extracts an embedded XML property list from an Apple `.mobileprovision` CMS signedData blob.
    ///
    /// Real `.mobileprovision` files are DER/BER-encoded CMS containers wrapping an XML property list.
    /// Uses CMS `id-data` extraction followed by comment/CDATA-aware O(N) XML lexical scanning without
    /// arbitrary 16-candidate caps so neither multi-thousand `</plist>` tokens inside comments/CDATA nor
    /// decoy `<plist>` wrappers can blind profile extraction or trigger quadratic deserialization.
    public static func extractPlist(from rawInput: Data) -> [String: Any]? {
        let mobileprovisionData = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
        guard !mobileprovisionData.isEmpty else { return nil }

        // 1. Direct plist deserialization if already pure XML/UTF-16/binary plist
        if let plist = (try? PropertyListSerialization.propertyList(from: mobileprovisionData, options: [], format: nil)) as? [String: Any] {
            return plist
        }
        if let utf8Transcoded = CSBlobParser.transcodeUTF16XMLToUTF8IfNeeded(mobileprovisionData),
           let dict = try? CSBlobParser.shared.parseXMLPlist(utf8Transcoded), !dict.isEmpty {
            return dict
        }

        // 2. Authentic CMS PKCS#7 id-data OCTET STRING payload extraction (DER & nested BER constructed OCTET STRING)
        var fallbackDict: [String: Any]? = nil
        for cmsPayload in extractCMSDataPayloads(from: mobileprovisionData) {
            if let dict = (try? PropertyListSerialization.propertyList(from: cmsPayload, options: [], format: nil)) as? [String: Any] {
                if looksLikeProvisioningPlist(dict) { return dict }
                if fallbackDict == nil { fallbackDict = dict }
            } else if let dict = try? CSBlobParser.shared.parseXMLPlist(cmsPayload), !dict.isEmpty {
                if looksLikeProvisioningPlist(dict) { return dict }
                if fallbackDict == nil { fallbackDict = dict }
            }
        }

        // 3. Comment/CDATA-aware O(N) XML `<plist>...</plist>` scanner across arbitrary CMS/wrapper bytes (no 16-doc truncation)
        for docRange in CSBlobParser.scanXMLPlistDocumentRanges(in: mobileprovisionData, maxDocuments: 4096) {
            let xmlSlice = mobileprovisionData.subdata(in: docRange)
            if let dict = (try? PropertyListSerialization.propertyList(from: xmlSlice, options: [], format: nil)) as? [String: Any] {
                if looksLikeProvisioningPlist(dict) {
                    return dict
                }
                if fallbackDict == nil && !dict.isEmpty {
                    fallbackDict = dict
                }
            }
        }

        return fallbackDict
    }
    
    /// Classifies an application based on memory metadata.
    ///
    /// - Parameters:
    ///   - cryptid: The encryption identifier from Mach-O LC_ENCRYPTION_INFO_64 (0 = unencrypted, 1 = FairPlay encrypted).
    ///   - mobileprovisionData: Optional raw bytes of `embedded.mobileprovision`.
    ///   - receiptData: Optional raw bytes of `_MASReceipt/receipt` or `StoreKit/receipt`.
    ///   - hasSandboxReceipt: True if `StoreKit/sandboxReceipt` exists in the bundle.
    ///   - hasMobileProvisionArtifact: True if an `embedded.mobileprovision` entry/file exists in the bundle even when empty, oversized, symlinked, or unreadable.
    ///   - codeSignatureTrust: Optional cryptographic signature authenticity disposition from Mach-O `LC_CODE_SIGNATURE`.
    /// - Returns: A `ClassificationResult` containing the detected channel and signing metadata.
    public static func classify(
        cryptid: UInt32,
        mobileprovisionData: Data? = nil,
        receiptData: Data? = nil,
        hasSandboxReceipt: Bool = false,
        hasMobileProvisionArtifact: Bool = false,
        codeSignatureTrust: CodeSignatureTrustDisposition = .absentOrSynthetic,
        sandboxReceiptData: Data? = nil,
        verifiedSignerKind: AppleVerifiedSignerKind = .none,
        hasMissingCodeSignature: Bool = false
    ) -> ClassificationResult {
        classify(
            cryptid: cryptid,
            mobileprovisionData: mobileprovisionData,
            receiptData: receiptData,
            hasSandboxReceipt: hasSandboxReceipt,
            hasMobileProvisionArtifact: hasMobileProvisionArtifact,
            codeSignatureTrust: codeSignatureTrust,
            sandboxReceiptData: sandboxReceiptData,
            verifiedSignerKind: verifiedSignerKind,
            hasMissingCodeSignature: hasMissingCodeSignature,
            customAnchorCertificates: nil
        )
    }

    internal static func classify(
        cryptid: UInt32,
        mobileprovisionData: Data? = nil,
        receiptData: Data? = nil,
        hasSandboxReceipt: Bool = false,
        hasMobileProvisionArtifact: Bool = false,
        codeSignatureTrust: CodeSignatureTrustDisposition = .absentOrSynthetic,
        sandboxReceiptData: Data? = nil,
        verifiedSignerKind: AppleVerifiedSignerKind = .none,
        hasMissingCodeSignature: Bool = false,
        customAnchorCertificates: [SecCertificate]?
    ) -> ClassificationResult {
        _ = hasSandboxReceipt
        let isEncrypted = (cryptid != 0)
        let hasProvision = hasMobileProvisionArtifact || (mobileprovisionData != nil)

        var parsedPlist: [String: Any]? = nil
        var isProvisionCMSVerified = false
        if let data = mobileprovisionData, !data.isEmpty {
            let cmsEval = CSBlobParser.shared.verifyProvisioningProfileCMS(
                data,
                customAnchorCertificates: customAnchorCertificates
            )
            if cmsEval.isVerified, let verifiedPlist = cmsEval.plist {
                parsedPlist = verifiedPlist
                isProvisionCMSVerified = true
            } else {
                parsedPlist = extractPlist(from: data)
            }
        }

        var isEnterprise = false
        var hasProvisionedDevices = false
        var teamId: String? = nil
        var verifiedProvisionTeamPrefixes: Set<String> = []
        var teamName: String? = nil
        var profileName: String? = nil
        var hasBetaReportsActive = false

        if let plist = parsedPlist {
            if (plist["ProvisionsAllDevices"] as? Bool == true) || ((plist["ProvisionsAllDevices"] as? NSNumber)?.boolValue == true) {
                isEnterprise = true
            }
            if let devs = plist["ProvisionedDevices"] as? [Any], !devs.isEmpty {
                hasProvisionedDevices = true
            }
            let teamCandidates = (plist["TeamIdentifier"] as? [Any] ?? [])
                .compactMap { $0 as? String }
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            let prefixCandidates = (plist["ApplicationIdentifierPrefix"] as? [Any] ?? [])
                .compactMap { $0 as? String }
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            if let first = teamCandidates.first {
                teamId = first
            } else if let first = prefixCandidates.first {
                teamId = first
            }
            if isProvisionCMSVerified {
                for candidate in teamCandidates + prefixCandidates {
                    if ExpandedThreatCatalog.isStrictTenCharTeamId(candidate) {
                        verifiedProvisionTeamPrefixes.insert(candidate.lowercased())
                    }
                }
            }
            teamName = plist["TeamName"] as? String
            profileName = plist["Name"] as? String
            if (plist["BetaReportsActive"] as? Bool == true) || ((plist["BetaReportsActive"] as? NSNumber)?.boolValue == true) {
                hasBetaReportsActive = true
            }
            if let entDict = plist["Entitlements"] as? [String: Any],
               ((entDict["beta-reports-active"] as? Bool == true) || ((entDict["beta-reports-active"] as? NSNumber)?.boolValue == true)) {
                hasBetaReportsActive = true
            }
        }

        var hasVerifiedReceipt = false
        var hasVerifiedSandboxReceipt = false
        for candidateReceipt in [sandboxReceiptData, receiptData].compactMap({ $0 }) where !candidateReceipt.isEmpty {
            let receiptEval = CSBlobParser.shared.verifyAppReceiptCMS(
                candidateReceipt,
                customAnchorCertificates: customAnchorCertificates
            )
            if receiptEval.isVerified {
                hasVerifiedReceipt = true
                if receiptEval.isSandbox {
                    hasVerifiedSandboxReceipt = true
                }
            }
        }
        let hasReceipt = hasVerifiedReceipt

        // FairPlay Encrypted Binaries:
        // Official App Store releases NEVER ship an `embedded.mobileprovision` file.
        // Whenever `hasProvision` is true (including malformed/truncated CMS/XML, 0-byte files, profiles omitting
        // ProvisionedDevices, or escaping/oversized mobileprovision artifacts), fail closed and never classify as .appStore.
        if isEncrypted {
            if isEnterprise && !hasMissingCodeSignature && codeSignatureTrust != .adHocOrUnsigned {
                return ClassificationResult(
                    channel: .enterpriseInHouse,
                    teamIdentifier: teamId,
                    teamName: teamName,
                    profileName: profileName,
                    isEnterprise: true,
                    hasMobileProvision: true,
                    hasReceipt: hasReceipt,
                    isFairPlayEncrypted: true,
                    isProvisionCMSVerified: isProvisionCMSVerified,
                    verifiedProvisionTeamPrefixes: verifiedProvisionTeamPrefixes,
                    details: "Enterprise In-House: Encrypted binary re-signed with enterprise provisioning profile (ProvisionsAllDevices: true)."
                )
            }
            if hasProvision {
                if codeSignatureTrust == .appleAppStoreVerified
                    && !hasMissingCodeSignature
                    && isProvisionCMSVerified
                    && parsedPlist != nil
                    && hasBetaReportsActive
                    && !hasProvisionedDevices {
                    return ClassificationResult(
                        channel: .testFlight,
                        teamIdentifier: teamId,
                        teamName: teamName,
                        profileName: profileName,
                        isEnterprise: false,
                        hasMobileProvision: true,
                        hasReceipt: true,
                        isFairPlayEncrypted: true,
                        isProvisionCMSVerified: isProvisionCMSVerified,
                        verifiedProvisionTeamPrefixes: verifiedProvisionTeamPrefixes,
                        details: "TestFlight Beta: FairPlay DRM encrypted binary (cryptid=1) with CMS-verified beta-reports-active provisioning profile."
                    )
                }
                let reason: String
                if parsedPlist == nil {
                    reason = "Encrypted binary carries malformed, unreadable, or unparseable embedded.mobileprovision (rejected App Store trust)."
                } else if hasProvisionedDevices {
                    reason = "Encrypted binary re-signed with UDID-scoped developer provisioning profile (ProvisionedDevices)."
                } else if hasBetaReportsActive && !isProvisionCMSVerified {
                    reason = "Encrypted binary carries unverified BetaReportsActive embedded.mobileprovision (rejected TestFlight trust)."
                } else {
                    reason = "Encrypted binary carries non-TestFlight embedded.mobileprovision profile (re-signed or sideloaded bundle)."
                }
                return ClassificationResult(
                    channel: .developerSideloaded,
                    teamIdentifier: teamId,
                    teamName: teamName,
                    profileName: profileName,
                    isEnterprise: false,
                    hasMobileProvision: true,
                    hasReceipt: hasReceipt,
                    isFairPlayEncrypted: true,
                    isProvisionCMSVerified: isProvisionCMSVerified,
                    verifiedProvisionTeamPrefixes: verifiedProvisionTeamPrefixes,
                    details: "Developer Sideloaded: \(reason)"
                )
            }

            // Strictly enforce Apple-anchored CMS verification and non-missing LC_CODE_SIGNATURE for .appStore and .testFlight
            if hasMissingCodeSignature {
                return ClassificationResult(
                    channel: .developerSideloaded,
                    teamIdentifier: teamId,
                    teamName: teamName,
                    profileName: profileName,
                    isEnterprise: false,
                    hasMobileProvision: false,
                    hasReceipt: hasReceipt,
                    isFairPlayEncrypted: true,
                    details: "Developer Sideloaded: Binary header sets cryptid!=0 while LC_CODE_SIGNATURE is missing (rejected App Store/TestFlight trust)."
                )
            }
            switch codeSignatureTrust {
            case .adHocOrUnsigned:
                return ClassificationResult(
                    channel: .developerSideloaded,
                    teamIdentifier: teamId,
                    teamName: teamName,
                    profileName: profileName,
                    isEnterprise: false,
                    hasMobileProvision: false,
                    hasReceipt: hasReceipt,
                    isFairPlayEncrypted: true,
                    details: "Developer Sideloaded: Binary header sets cryptid!=0 while CodeDirectory/CMS is ad-hoc or unsigned (rejected App Store trust)."
                )
            case .nonAppStoreSigner(let subject):
                let signerDesc = subject ?? "untrusted X.509 certificate"
                return ClassificationResult(
                    channel: .developerSideloaded,
                    teamIdentifier: teamId,
                    teamName: teamName,
                    profileName: profileName,
                    isEnterprise: false,
                    hasMobileProvision: false,
                    hasReceipt: hasReceipt,
                    isFairPlayEncrypted: true,
                    details: "Developer Sideloaded: Binary header sets cryptid!=0 while CMS signature is '\(signerDesc)' rather than AppleRootCA-anchored Apple iPhone OS Application Signing."
                )
            case .absentOrSynthetic:
                return ClassificationResult(
                    channel: .developerSideloaded,
                    teamIdentifier: teamId,
                    teamName: teamName,
                    profileName: profileName,
                    isEnterprise: false,
                    hasMobileProvision: false,
                    hasReceipt: hasReceipt,
                    isFairPlayEncrypted: true,
                    details: "Developer Sideloaded: Binary header sets cryptid!=0 without a verified Apple CMS code signature (rejected App Store/TestFlight trust)."
                )
            case .appleAppStoreVerified:
                break
            }

            let isTestFlight = (verifiedSignerKind == .testFlight) || hasVerifiedSandboxReceipt
            if isTestFlight {
                return ClassificationResult(
                    channel: .testFlight,
                    teamIdentifier: teamId,
                    teamName: teamName,
                    profileName: profileName,
                    isEnterprise: false,
                    hasMobileProvision: false,
                    hasReceipt: hasVerifiedSandboxReceipt || hasReceipt,
                    isFairPlayEncrypted: true,
                    details: verifiedSignerKind == .testFlight
                        ? "TestFlight Beta: FairPlay DRM encrypted binary (cryptid=1) signed by verified Apple TestFlight Beta Distribution leaf certificate."
                        : "TestFlight Beta: FairPlay DRM encrypted binary (cryptid=1) with verified Apple sandbox receipt."
                )
            } else {
                return ClassificationResult(
                    channel: .appStore,
                    teamIdentifier: teamId,
                    teamName: teamName,
                    profileName: profileName,
                    isEnterprise: false,
                    hasMobileProvision: false,
                    hasReceipt: hasReceipt,
                    isFairPlayEncrypted: true,
                    details: "App Store: FairPlay DRM encrypted production binary (cryptid=1) released through Apple App Store."
                )
            }
        }

        // Unencrypted Binaries (Sideloaded or Enterprise)
        if isEnterprise && !hasMissingCodeSignature && codeSignatureTrust != .adHocOrUnsigned {
            return ClassificationResult(
                channel: .enterpriseInHouse,
                teamIdentifier: teamId,
                teamName: teamName,
                profileName: profileName,
                isEnterprise: true,
                hasMobileProvision: true,
                hasReceipt: hasReceipt,
                isFairPlayEncrypted: false,
                isProvisionCMSVerified: isProvisionCMSVerified,
                verifiedProvisionTeamPrefixes: verifiedProvisionTeamPrefixes,
                details: "Enterprise In-House: Unencrypted binary signed with enterprise provisioning profile (ProvisionsAllDevices: true)."
            )
        } else {
            let note = hasProvision ?
                "Unencrypted binary signed with developer/personal provisioning profile (ProvisionedDevices list)." :
                "Unencrypted binary without embedded provisioning profile (Ad-Hoc / TrollStore / ldid signed)."
            return ClassificationResult(
                channel: .developerSideloaded,
                teamIdentifier: teamId,
                teamName: teamName,
                profileName: profileName,
                isEnterprise: false,
                hasMobileProvision: hasProvision,
                hasReceipt: hasReceipt,
                isFairPlayEncrypted: false,
                isProvisionCMSVerified: isProvisionCMSVerified,
                verifiedProvisionTeamPrefixes: verifiedProvisionTeamPrefixes,
                details: "Developer Sideloaded: \(note)"
            )
        }
    }
    
    /// Classifies an installed or extracted bundle URL (100% read-only).
    ///
    /// - Parameters:
    ///   - bundleURL: The URL of the `.app` bundle directory.
    ///   - cryptid: The encryption identifier parsed from the main executable Mach-O header.
    ///   - codeSignatureTrust: Optional cryptographic signature authenticity disposition from Mach-O `LC_CODE_SIGNATURE`.
    ///   - verifiedSignerKind: Optional Apple leaf signer category from `CodeSignatureTrustEvaluation`.
    ///   - hasMissingCodeSignature: True if any selected audit slice lacks `LC_CODE_SIGNATURE`.
    /// - Returns: A `ClassificationResult`.
    public static func classifyBundle(
        at bundleURL: URL,
        cryptid: UInt32,
        codeSignatureTrust: CodeSignatureTrustDisposition = .absentOrSynthetic,
        verifiedSignerKind: AppleVerifiedSignerKind = .none,
        hasMissingCodeSignature: Bool = false
    ) -> ClassificationResult {
        classifyBundle(
            at: bundleURL,
            cryptid: cryptid,
            codeSignatureTrust: codeSignatureTrust,
            verifiedSignerKind: verifiedSignerKind,
            hasMissingCodeSignature: hasMissingCodeSignature,
            customAnchorCertificates: nil
        )
    }

    internal static func classifyBundle(
        at bundleURL: URL,
        cryptid: UInt32,
        codeSignatureTrust: CodeSignatureTrustDisposition = .absentOrSynthetic,
        verifiedSignerKind: AppleVerifiedSignerKind = .none,
        hasMissingCodeSignature: Bool = false,
        customAnchorCertificates: [SecCertificate]?
    ) -> ClassificationResult {
        let bundleResolved = IPAPackageScanner.lexicalStandardizedPath(bundleURL.resolvingSymlinksInPath().path)
        let bundleResolvedPrefix = IPAPackageScanner.lexicalStandardizedPrefix(bundleResolved)

        func hasEntryNoFollow(_ relativeSubpath: String) -> Bool {
            let fullPath = bundleURL.appendingPathComponent(relativeSubpath).path
            var st = stat()
            return lstat(fullPath, &st) == 0
        }

        func readInBundleFile(_ relativeSubpath: String, maxBytes: Int = 8 * 1024 * 1024) -> Data? {
            let comps = relativeSubpath.split(separator: "/").map(String.init)
            if case .success(let dataOpt) = ContainerScanner.readBoundedRegularFileNoFollow(
                rootURL: bundleURL,
                relativeComponents: comps,
                maxBytes: maxBytes
            ), let d = dataOpt {
                return d
            }
            // Allow strictly in-bundle symlinked regular files (e.g. versioned bundle layout), never external symlinks,
            // while still enforcing O_NOFOLLOW | O_NONBLOCK and `maxBytes` on the resolved target.
            let candidate = bundleURL.appendingPathComponent(relativeSubpath)
            let resolved = candidate.resolvingSymlinksInPath().standardizedFileURL
            let resolvedStd = IPAPackageScanner.lexicalStandardizedPath(resolved.path)
            guard resolvedStd.hasPrefix(bundleResolvedPrefix) else {
                return nil
            }
            if case .success(let dataOpt) = ContainerScanner.readBoundedRegularFileNoFollow(
                rootURL: resolved.deletingLastPathComponent(),
                relativeComponents: [resolved.lastPathComponent],
                maxBytes: maxBytes
            ) {
                return dataOpt
            }
            return nil
        }

        let hasProvArtifact = hasEntryNoFollow("embedded.mobileprovision")
        let provData = readInBundleFile("embedded.mobileprovision")
        let sandboxReceiptData = readInBundleFile("StoreKit/sandboxReceipt", maxBytes: 4 * 1024 * 1024)
        let receiptData = readInBundleFile("_MASReceipt/receipt") ?? readInBundleFile("StoreKit/receipt")

        return classify(
            cryptid: cryptid,
            mobileprovisionData: provData,
            receiptData: receiptData,
            hasSandboxReceipt: false,
            hasMobileProvisionArtifact: hasProvArtifact,
            codeSignatureTrust: codeSignatureTrust,
            sandboxReceiptData: sandboxReceiptData,
            verifiedSignerKind: verifiedSignerKind,
            hasMissingCodeSignature: hasMissingCodeSignature,
            customAnchorCertificates: customAnchorCertificates
        )
    }
}
