//
//  SecurityPipeline.swift
//  WQGuardCore
//
//  Feature 12: Top-level multi-layer scanner engine coordinating Layers 1-4.
//  Conforms to `SecurityScannerEngineProtocol: Sendable` with non-blocking
//  asynchronous scanning and progress reporting callbacks.
//

import Foundation
import Darwin

/// Errors specific to system-level scanning inside standard iOS Seatbelt sandboxes.
public enum SecurityPipelineError: Error, LocalizedError, Sendable, Equatable {
    case sandboxRestrictedNoAccessibleTargets

    public var errorDescription: String? {
        switch self {
        case .sandboxRestrictedNoAccessibleTargets:
            return WQLocale.pick(
                en: """
                This device is running inside the standard iOS Seatbelt sandbox (no unsandboxed TrollStore container access), so iOS blocks enumerating other installed apps directly.

                WQGuard operates strictly read-only with zero exploit payloads. Inspect your apps using either option:
                1. Tap "Scan Sources & Pairing" to import an installation_proxy snapshot or pair via LocalDevVPN;
                2. Tap "Select .ipa Files (Multi-Select)" or place .ipa packages into Files -> On My iPhone -> WQGuard.
                """,
                zh: """
                当前设备处于标准 iOS Seatbelt 沙盒隔离状态（非 TrollStore / 无全局容器读取权限），系统正常拦截了对其他已安装应用目录的枚举访问。

                WQGuard 坚持 100% 纯防御零漏洞利用原则，绝不调用系统漏洞越权突破沙盒。请通过以下任一方式完成审计：
                1. 点击下方「配置已安装扫描源」导入系统应用注册表或通过 LocalDevVPN 直连；
                2. 点击「选择 .ipa 文件加入扫描」或将 .ipa 放入「文件 App -> 我的 iPhone -> WQGuard」目录后再次检测。
                """
            )
        }
    }
}

/// Real-time progress snapshot emitted during asynchronous scanning sessions.
public struct ScanProgress: Sendable, Equatable {
    public let currentTarget: String
    public let completedCount: Int
    public let totalCount: Int
    public let currentFinding: ScanFinding?
    
    public var fractionCompleted: Double {
        totalCount > 0 ? Double(completedCount) / Double(totalCount) : 0.0
    }
    
    public var percentageString: String {
        String(format: "%.1f%%", fractionCompleted * 100.0)
    }
    
    public init(
        currentTarget: String,
        completedCount: Int,
        totalCount: Int,
        currentFinding: ScanFinding? = nil
    ) {
        self.currentTarget = currentTarget
        self.completedCount = completedCount
        self.totalCount = totalCount
        self.currentFinding = currentFinding
    }
}

/// Protocol defining the security scanner engine operations.
public protocol SecurityScannerEngineProtocol: Sendable {
    func scanBinary(at url: URL) throws -> ScanFinding
    func scanBundle(at url: URL) throws -> ScanFinding
    func scanIPA(at url: URL) throws -> ScanFinding
    func scanInstalledApps() throws -> [ScanFinding]
    func scanSharedContainers() throws -> [ThreatIndicator]
}

/// Top-level coordinator implementing progressive multi-layer security scanning (Layers 1-4).
/// Fully conforms to `SecurityScannerEngineProtocol: Sendable`.
public final class SecurityPipeline: SecurityScannerEngineProtocol, @unchecked Sendable {
    public static let shared = SecurityPipeline()
    
    private let machoScanner: MachOScanner
    private let ipaScanner: IPAPackageScanner
    private let whitelistEngine: WhitelistEngine
    private let containerScanner: ContainerScanner
    
    public init(
        machoScanner: MachOScanner = .shared,
        ipaScanner: IPAPackageScanner = .shared,
        whitelistEngine: WhitelistEngine = .shared,
        containerScanner: ContainerScanner = .shared
    ) {
        let resolvedMachoScanner: MachOScanner
        if machoScanner === MachOScanner.shared && whitelistEngine !== WhitelistEngine.shared {
            resolvedMachoScanner = MachOScanner(whitelistEngine: whitelistEngine)
        } else {
            resolvedMachoScanner = machoScanner
        }
        self.machoScanner = resolvedMachoScanner
        if ipaScanner === IPAPackageScanner.shared && whitelistEngine !== WhitelistEngine.shared {
            self.ipaScanner = IPAPackageScanner(whitelistEngine: whitelistEngine, machoScanner: resolvedMachoScanner)
        } else {
            self.ipaScanner = ipaScanner
        }
        self.whitelistEngine = whitelistEngine
        self.containerScanner = containerScanner
    }
    
    // MARK: - SecurityScannerEngineProtocol Conformance
    
    private static func isCodeSignatureSealMismatchDisposition(_ disposition: CodeSignatureTrustDisposition) -> Bool {
        disposition == .nonAppStoreSigner(subjectSummary: "CodeDirectory/Info.plist Mismatch")
            || disposition == .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
    }

    private static func hasNonZeroSpecialSlot1Hash(inSlices slices: [MachOFile]) -> Bool {
        func readBE32(_ data: Data, at offset: Int) -> UInt32? {
            guard offset >= 0, offset + 4 <= data.count else { return nil }
            let b0 = UInt32(data[data.startIndex + offset]) << 24
            let b1 = UInt32(data[data.startIndex + offset + 1]) << 16
            let b2 = UInt32(data[data.startIndex + offset + 2]) << 8
            let b3 = UInt32(data[data.startIndex + offset + 3])
            return b0 | b1 | b2 | b3
        }
        for slice in MachOParser.selectAuditSlices(from: slices) {
            let blobs = slice.allCodeSignatureData.isEmpty
                ? (slice.codeSignatureData.map { [$0] } ?? [])
                : slice.allCodeSignatureData
            for rawBlob in blobs {
                let data = rawBlob.startIndex == 0 ? rawBlob : Data(rawBlob)
                guard data.count >= 12,
                      readBE32(data, at: 0) == CSBlobConstants.superBlobMagic,
                      let totalLen = readBE32(data, at: 4),
                      totalLen >= 12, Int(totalLen) <= data.count,
                      let count = readBE32(data, at: 8) else { continue }
                let entryCount = min(Int(count), (Int(totalLen) - 12) / 8)
                for idx in 0..<entryCount {
                    let idxOff = 12 + idx * 8
                    guard let slotType = readBE32(data, at: idxOff),
                          let offsetU32 = readBE32(data, at: idxOff + 4) else { continue }
                    let isCodeDir = slotType == CSBlobConstants.slotCodeDirectory
                        || (slotType >= CSBlobConstants.slotAlternateCodeDirectories && slotType <= CSBlobConstants.slotAlternateCodeDirectories + 5)
                    let off = Int(offsetU32)
                    guard isCodeDir, off >= 12, off + 44 <= Int(totalLen),
                          readBE32(data, at: off) == CSBlobConstants.codeDirectoryMagic,
                          let hashOffsetU32 = readBE32(data, at: off + 16),
                          let nSpecialU32 = readBE32(data, at: off + 24) else { continue }
                    let hashSize = Int(data[off + 36])
                    let hashOffset = Int(hashOffsetU32)
                    let nSpecial = Int(nSpecialU32)
                    guard nSpecial >= 1, hashSize >= 16, hashSize <= 64 else { continue }
                    let slot1Start = off + hashOffset - hashSize
                    let slot1End = slot1Start + hashSize
                    guard slot1Start >= off + 44, slot1End <= Int(totalLen) else { continue }
                    if data[slot1Start..<slot1End].contains(where: { $0 != 0 }) {
                        return true
                    }
                }
            }
        }
        return false
    }

    private static func verifyFrameworkInfoPlistBinding(
        fromSlices fwSlices: [MachOFile],
        frameworkRootURL: URL,
        binaryParentURL: URL,
        bundleResolvedPrefix: String,
        escapingSymlinks: inout [String],
        rootBundleURL: URL
    ) -> (failure: CodeSignatureTrustDisposition?, hasNonZeroSlot1: Bool) {
        var plistCandidates: [URL] = [
            frameworkRootURL.appendingPathComponent("Info.plist"),
            frameworkRootURL.appendingPathComponent("Resources/Info.plist"),
            frameworkRootURL.appendingPathComponent("Versions/Current/Resources/Info.plist")
        ]
        if binaryParentURL != frameworkRootURL {
            plistCandidates.append(binaryParentURL.appendingPathComponent("Resources/Info.plist"))
        }
        var fwPlistData: Data? = nil
        var fwPlistBid: String? = nil
        for candidate in plistCandidates {
            var pStat = stat()
            guard lstat(candidate.path, &pStat) == 0 else { continue }
            let resolved = candidate.resolvingSymlinksInPath().standardizedFileURL
            let resolvedStd = IPAPackageScanner.lexicalStandardizedPath(resolved.path)
            guard resolvedStd.hasPrefix(bundleResolvedPrefix) else {
                let rel = IPAPackageScanner.bundleRelativePath(of: candidate, in: rootBundleURL)
                if !escapingSymlinks.contains(rel) {
                    escapingSymlinks.append(rel)
                }
                return (
                    .nonAppStoreSigner(subjectSummary: "CodeDirectory/Info.plist Mismatch"),
                    hasNonZeroSpecialSlot1Hash(inSlices: fwSlices)
                )
            }
            if let data = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: resolved, maxBytes: 8 * 1024 * 1024) {
                fwPlistData = data
                if let parsed = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any],
                   let rawBid = (parsed["CFBundleIdentifier"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                   !rawBid.isEmpty {
                    fwPlistBid = rawBid
                }
            }
            break
        }
        let failure = CSBlobParser.shared.verifyBundleInfoPlistBinding(
            fromSlices: fwSlices,
            infoPlistData: fwPlistData,
            plistBundleId: fwPlistBid
        )
        return (failure, hasNonZeroSpecialSlot1Hash(inSlices: fwSlices))
    }

    /// Extracts raw `__TEXT,__info_plist` bytes from a parsed `MachOFile` when unencrypted and valid XML plist.
    private static func extractRawEmbeddedInfoPlistData(from slice: MachOFile) -> Data? {
        let encryptedRange: Range<Int>? = (slice.isFairPlayEncrypted && !slice.hasForgedPlaintextFairPlayRange)
            ? slice.encryptionInfo?.encryptedRange
            : nil
        if slice.isFairPlayEncrypted && !slice.hasForgedPlaintextFairPlayRange && encryptedRange == nil {
            // cryptid != 0 with cryptsize == 0 -> zero encrypted bytes, so section bytes are plaintext
        }
        let maxPlistBytes = 8 * 1024 * 1024
        let base = slice.sliceData.startIndex
        var emptyFallback: Data? = nil
        for seg in slice.segments {
            for sect in seg.sections where sect.sectionName == "__info_plist" && sect.size > 0 {
                let start = Int(sect.offset)
                guard start >= 0,
                      start <= slice.sliceData.count,
                      let sizeInt = Int(exactly: sect.size),
                      sizeInt > 0,
                      sizeInt <= maxPlistBytes,
                      sizeInt <= slice.sliceData.count - start else {
                    continue
                }
                let end = start + sizeInt
                if let er = encryptedRange, start < er.upperBound && end > er.lowerBound {
                    continue
                }
                let raw = slice.sliceData.subdata(in: (base + start)..<(base + end))
                if let parsed = try? CSBlobParser.shared.parseXMLPlist(raw) {
                    if !parsed.isEmpty {
                        return raw
                    }
                    if emptyFallback == nil {
                        emptyFallback = raw
                    }
                }
            }
        }
        return emptyFallback
    }

    /// Scans a single Mach-O binary file at the specified URL.
    public func scanBinary(at url: URL) throws -> ScanFinding {
        let binaryData = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: url)
        let slices = try MachOParser.shared.parseAllSlices(data: binaryData)
        let details = machoScanner.parseMachO(
            files: slices,
            rawData: binaryData,
            expectedContainerSliceCount: slices.first?.slicesInContainer.count
        )
        
        var appGroups: [String] = []
        var entitlementsDict: [String: Any] = [:]
        var embeddedPlist: [String: Any] = [:]
        var hasEmbeddedInfoPlist = false
        var perSliceEmbeddedInfoPlists: [(slice: MachOFile, rawData: Data, bundleId: String?)] = []
        var primaryEmbeddedPlistData: Data? = nil
        for slice in MachOParser.selectAuditSlices(from: slices) {
            let (_, sliceGroups) = CSBlobParser.shared.extractAppGroups(fromSlice: slice)
            for g in sliceGroups where !appGroups.contains(g) {
                appGroups.append(g)
            }
            let sliceEnts = CSBlobParser.shared.parseMergedEntitlements(fromSlice: slice)
            entitlementsDict = CSBlobParser.mergeEntitlementDictionaries(entitlementsDict, sliceEnts)
            if let sPlist = slice.embeddedInfoPlist {
                hasEmbeddedInfoPlist = true
                for (k, v) in sPlist where embeddedPlist[k] == nil {
                    embeddedPlist[k] = v
                }
                if let rawBytes = Self.extractRawEmbeddedInfoPlistData(from: slice) {
                    let sBid = (sPlist["CFBundleIdentifier"] as? String)?
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    let cleanSliceBid = (sBid?.isEmpty == false) ? sBid : nil
                    perSliceEmbeddedInfoPlists.append((slice: slice, rawData: rawBytes, bundleId: cleanSliceBid))
                    if primaryEmbeddedPlistData == nil {
                        primaryEmbeddedPlistData = rawBytes
                    }
                }
            }
        }

        let identityResolution = IPAPackageScanner.resolveDistinctEntitlementIdentities(
            fromSlices: slices,
            explicitTeamId: nil
        )
        let teamId: String? = identityResolution.inferredTeamId

        let embeddedBundleId: String? = {
            guard let raw = (embeddedPlist["CFBundleIdentifier"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !raw.isEmpty else { return nil }
            return raw
        }()
        let embeddedDisplayName: String? = {
            let raw = (embeddedPlist["CFBundleDisplayName"] as? String) ?? (embeddedPlist["CFBundleName"] as? String)
            guard let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
            return trimmed
        }()
        let embeddedVersion: String? = {
            let raw = (embeddedPlist["CFBundleShortVersionString"] as? String) ?? (embeddedPlist["CFBundleVersion"] as? String)
            guard let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
            return trimmed
        }()
        let mainBackgroundModes = IPAPackageScanner.extractFlexibleStringList(embeddedPlist["UIBackgroundModes"])

        let hasEntitlementBundleId = !identityResolution.distinctBundleIds.isEmpty
        let bundleId = identityResolution.primaryBundleId ?? embeddedBundleId ?? url.lastPathComponent

        let trustEval = CSBlobParser.shared.inspectCodeSignatureTrustEvaluation(fromSlices: slices)
        var codeSigTrust = trustEval.disposition
        var verifiedSignerKind = trustEval.signerKind
        var hasBundleSealTampering = Self.isCodeSignatureSealMismatchDisposition(codeSigTrust)
        if hasEmbeddedInfoPlist {
            for (slice, rawPlistBytes, sliceBid) in perSliceEmbeddedInfoPlists {
                if let bindFail = CSBlobParser.shared.verifyBundleInfoPlistBinding(
                    fromSlices: [slice],
                    infoPlistData: rawPlistBytes,
                    plistBundleId: sliceBid
                ) {
                    codeSigTrust = bindFail
                    verifiedSignerKind = .none
                    hasBundleSealTampering = true
                    break
                }
            }
            if !Self.isCodeSignatureSealMismatchDisposition(codeSigTrust),
               let embeddedBindFailure = CSBlobParser.shared.verifyBundleInfoPlistBinding(
                   fromSlices: slices,
                   infoPlistData: primaryEmbeddedPlistData,
                   plistBundleId: embeddedBundleId
               ) {
                codeSigTrust = embeddedBindFailure
                verifiedSignerKind = .none
                hasBundleSealTampering = true
            }
        }
        let hasMissingCS = CSBlobParser.hasMissingCodeSignature(inSlices: slices)
        let installChannel = ChannelClassifier.classify(
            cryptid: details.cryptid,
            codeSignatureTrust: codeSigTrust,
            verifiedSignerKind: verifiedSignerKind,
            hasMissingCodeSignature: hasMissingCS
        ).channel
        let verifiedStandalonePrefixes = IPAPackageScanner.computeVerifiedTeamPrefixes(
            codeSignatureTrust: codeSigTrust,
            hasMissingCodeSignature: hasMissingCS,
            entitlements: entitlementsDict,
            provisionTeamId: nil,
            verifiedProvisionPrefixes: [],
            hasMultipleTeamIds: identityResolution.hasMultipleTeamIds,
            hasProvisionTeamConflict: identityResolution.hasProvisionTeamConflict
        )
        let displayName = embeddedDisplayName ?? url.lastPathComponent
        let version = embeddedVersion ?? "1.0"
        let gating = EntitlementGating.evaluate(hasAppGroups: !appGroups.isEmpty, appGroups: appGroups)
        let hasConflictingEmbeddedBundleId: Bool
        if identityResolution.hasMultipleBundleIds || identityResolution.hasMultipleTeamIds {
            hasConflictingEmbeddedBundleId = true
        } else if hasEntitlementBundleId, let embId = embeddedBundleId {
            hasConflictingEmbeddedBundleId = identityResolution.distinctBundleIds.contains {
                IPAPackageScanner.doesEntitlementBundleIdConflict(entBundleId: $0, withPlistBundleId: embId)
            }
        } else {
            hasConflictingEmbeddedBundleId = false
        }
        var hasVerifiedBundleIdentity = (hasEntitlementBundleId || embeddedBundleId != nil)
            && !hasConflictingEmbeddedBundleId
            && !hasBundleSealTampering
            && details.corruptedSliceCount == 0
        let isStandaloneTeamVerified: Bool = (teamId == nil) || (codeSigTrust == .appleAppStoreVerified && !hasMissingCS && !identityResolution.hasMultipleTeamIds)
        let whitelistTeamId: String? = isStandaloneTeamVerified ? teamId : nil

        let bundleContext = MachOScanner.ScanContext(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            teamId: whitelistTeamId,
            bundlePath: url.deletingLastPathComponent().path,
            executablePath: url.path,
            installChannel: installChannel,
            appGroups: gating.appGroups,
            disqualifyAppStoreExemption: details.cryptid != 0 && (hasMissingCS || codeSigTrust != .appleAppStoreVerified)
        )
        
        let baseFinding = machoScanner.scan(details: details, context: bundleContext)
        var allIndicators = baseFinding.indicators
        var allMatchedSymbols = Set(baseFinding.evidence.matchedSymbols)
        let linkedSet = Set(details.linkedDylibs)
        let binInspectable = !details.isFairPlayEncrypted || details.hasUnencryptedSegments || codeSigTrust.isDisqualifiedFromAppStore || hasMissingCS
        let binSymbolsInspectable = binInspectable || codeSigTrust != .appleAppStoreVerified
        let unencSyms: Set<String> = binSymbolsInspectable ? Set(details.symbols) : []
        let unencStrs: Set<String> = binInspectable ? Set(details.textStrings) : []
        let effectivePlist: [String: Any]
        if hasEmbeddedInfoPlist {
            effectivePlist = embeddedPlist
        } else {
            effectivePlist = [
                "NSBluetoothAlwaysUsageDescription": "standalone-macho",
                "NSAccessorySetupKitSupports": ["Bluetooth"]
            ]
        }

        IPAPackageScanner.appendExpandedThreatIndicators(
            bundleId: bundleId,
            displayName: displayName,
            installChannel: installChannel,
            mainCryptid: details.cryptid,
            mainIsFairPlayEncrypted: details.isFairPlayEncrypted,
            mainHasUnencryptedSegments: details.hasUnencryptedSegments,
            mainBackgroundModes: mainBackgroundModes,
            infoDict: effectivePlist,
            entitlementsDict: entitlementsDict,
            allLinkedDylibs: linkedSet,
            appLinkedDylibs: linkedSet,
            unencryptedSymbols: unencSyms,
            appUnencryptedSymbols: unencSyms,
            unencryptedTextStrings: unencStrs,
            hasUnencryptedBinary: binInspectable,
            appHasUnencryptedBinary: binInspectable,
            codeSignatureTrust: codeSigTrust,
            hasMissingCodeSignature: hasMissingCS,
            appHasMissingCodeSignature: hasMissingCS,
            verifiedOwnTeamPrefixes: verifiedStandalonePrefixes,
            allIndicators: &allIndicators,
            allMatchedSymbols: &allMatchedSymbols
        )

        // Evaluate impersonation and dangerous entitlements across ALL conflicting/secondary identities (across slices/slots and embedded __info_plist)
        var secondaryBids: [String] = []
        for candBid in identityResolution.distinctBundleIds where candBid.caseInsensitiveCompare(bundleId) != .orderedSame {
            secondaryBids.append(candBid)
        }
        if let embId = embeddedBundleId, embId.caseInsensitiveCompare(bundleId) != .orderedSame,
           !secondaryBids.contains(where: { $0.caseInsensitiveCompare(embId) == .orderedSame }) {
            secondaryBids.append(embId)
        }
        for conflictId in secondaryBids {
            IPAPackageScanner.appendConflictingIdentityIndicators(
                conflictingBundleId: conflictId,
                displayName: displayName,
                installChannel: installChannel,
                mainCryptid: details.cryptid,
                mainIsFairPlayEncrypted: details.isFairPlayEncrypted,
                mainHasUnencryptedSegments: details.hasUnencryptedSegments,
                hasUnencryptedBinary: binInspectable,
                codeSignatureTrust: codeSigTrust,
                hasMissingCodeSignature: hasMissingCS,
                entitlementsDict: entitlementsDict,
                verifiedOwnTeamPrefixes: verifiedStandalonePrefixes,
                allIndicators: &allIndicators,
                allMatchedSymbols: &allMatchedSymbols
            )
        }

        if hasBundleSealTampering && (codeSigTrust == .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch") || Self.hasNonZeroSpecialSlot1Hash(inSlices: slices)) {
            let sealInd = ThreatIndicator(
                signature: "CODE_SIGNATURE_SEAL_MISMATCH",
                description: WQLocale.pick(
                    en: "Code signature seal tampering detected: embedded Info.plist or signature binding no longer matches CodeDirectory Special Slot -1.",
                    zh: "检测到代码签名封印篡改：内嵌 Info.plist 或签名绑定与 CodeDirectory Special Slot -1 哈希不匹配。"
                ),
                category: "Code Signature Integrity",
                location: "LC_CODE_SIGNATURE (Special Slot -1)",
                severity: .highRisk
            )
            allIndicators.append(sealInd)
            allMatchedSymbols.insert(sealInd.signature)
        }
        if allMatchedSymbols.contains(where: WhitelistEngine.isNonWhitelistableStructuralSignature) {
            hasVerifiedBundleIdentity = false
        }

        if whitelistEngine === WhitelistEngine.shared
            && hasVerifiedBundleIdentity
            && isStandaloneTeamVerified
            && (baseFinding.teamId == teamId)
            && !hasConflictingEmbeddedBundleId
            && allIndicators.count == baseFinding.indicators.count
            && allMatchedSymbols == Set(baseFinding.evidence.matchedSymbols) {
            return baseFinding
        }

        var provisionalRisk: RiskTier = .safe
        if allIndicators.contains(where: { $0.severity == .highRisk }) {
            provisionalRisk = .highRisk
        } else if allIndicators.contains(where: { $0.severity == .caution }) {
            provisionalRisk = .caution
        }

        var isWhitelisted = false
        var whitelistedToolName: String? = nil
        var finalRisk = provisionalRisk
        if hasVerifiedBundleIdentity && (provisionalRisk == .highRisk || provisionalRisk == .caution) {
            let wlResult = whitelistEngine.isWhitelisted(
                bundleId: bundleId,
                appGroups: gating.appGroups,
                matchedSignatures: Array(allMatchedSymbols),
                teamId: whitelistTeamId
            )
            if wlResult.isWhitelisted {
                isWhitelisted = true
                whitelistedToolName = wlResult.toolName
                finalRisk = .knownTool
            }
        }

        let remediation: String
        switch finalRisk {
        case .highRisk:
            remediation = WQLocale.pick(
                en: "Unauthorized high-risk exploit indicators or privileged entitlements detected. Immediately isolate or delete this binary.",
                zh: "检测到未经授权的高危利用特征或越权私有 Entitlements，建议立即隔离或删除该二进制文件。"
            )
        case .knownTool:
            remediation = WQLocale.pick(
                en: "Matched trusted whitelist rule (\(whitelistedToolName ?? "Known Tool")).",
                zh: "匹配已知开源安全审计工具白名单（\(whitelistedToolName ?? "Known Tool")）。"
            )
        case .caution:
            remediation = WQLocale.pick(
                en: "Binary includes dynamic symbol resolution, injected libraries, or supply-chain advisories. Review source before trusting.",
                zh: "该二进制包含动态符号解析、注入动态库或供应链风险组件，建议复核来源。"
            )
        case .safe:
            remediation = baseFinding.evidence.remediationGuidance
        }

        let updatedEvidence = AuditEvidence(
            matchedSymbols: Array(allMatchedSymbols).sorted(),
            linkedDylibs: details.linkedDylibs,
            hasAppGroups: !gating.appGroups.isEmpty,
            appGroups: gating.appGroups,
            installChannel: installChannel,
            cryptid: details.cryptid,
            isFairPlayEncrypted: details.isFairPlayEncrypted,
            escapingSymlinks: [],
            dynamicLoadingPresent: baseFinding.evidence.dynamicLoadingPresent,
            pathEnumerationPresent: baseFinding.evidence.pathEnumerationPresent,
            remediationGuidance: remediation,
            isWhitelistEligible: hasVerifiedBundleIdentity,
            isTeamIdWhitelistVerified: isStandaloneTeamVerified
        )

        return ScanFinding(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            teamId: teamId,
            executablePath: url.path,
            bundlePath: url.deletingLastPathComponent().path,
            installChannel: installChannel,
            riskTier: finalRisk,
            isWhitelisted: isWhitelisted,
            whitelistedToolName: whitelistedToolName,
            indicators: allIndicators,
            evidence: updatedEvidence,
            scanTimestamp: Date()
        )
    }
    
    private static func stripTrailingSlashes(_ rawPath: String) -> String {
        guard rawPath.count > 1 else { return rawPath }
        var s = rawPath
        while s.count > 1 && s.hasSuffix("/") {
            s.removeLast()
        }
        return s
    }

    /// Scans an application `.app`, `.appex`, `.xpc`, `.framework`, `.xcframework`, or `.bundle` directory.
    public func scanBundle(at rawURL: URL) throws -> ScanFinding {
        let normalizedPath = Self.stripTrailingSlashes(rawURL.path)
        let url = URL(fileURLWithPath: normalizedPath)
        var topStat = stat()
        guard lstat(normalizedPath, &topStat) == 0 else {
            throw IPAPackageScannerError.fileNotFound(normalizedPath)
        }
        let topMode = topStat.st_mode & S_IFMT
        if topMode == S_IFLNK {
            throw IPAPackageScannerError.zipSlipDetected(url.lastPathComponent)
        }
        guard topMode == S_IFDIR else {
            throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                en: "Bundle target is not a directory: '\(normalizedPath)'",
                zh: "Bundle 目标不是目录: '\(normalizedPath)'"
            ))
        }
        
        let bundleResolvedPath = IPAPackageScanner.lexicalStandardizedPath(url.resolvingSymlinksInPath().path)
        let bundleResolvedPrefix = IPAPackageScanner.lexicalStandardizedPrefix(bundleResolvedPath)
        let bundleExt = url.pathExtension.lowercased()
        let isFrameworkOrGenericBundle = (bundleExt == "framework" || bundleExt == "xcframework" || bundleExt == "bundle")
        let bundleStem = url.deletingPathExtension().lastPathComponent

        let infoPlistCandidates: [URL] = [
            url.appendingPathComponent("Info.plist"),
            url.appendingPathComponent("Contents/Info.plist"),
            url.appendingPathComponent("Resources/Info.plist"),
            url.appendingPathComponent("Versions/Current/Resources/Info.plist"),
            url.appendingPathComponent("Versions/A/Resources/Info.plist")
        ]

        var matchedInfoPlistURL: URL? = nil
        for candidatePlist in infoPlistCandidates {
            var pStat = stat()
            if lstat(candidatePlist.path, &pStat) == 0 {
                matchedInfoPlistURL = candidatePlist
                break
            }
        }

        var infoDict: [String: Any] = [:]
        var rawInfoPlistData: Data? = nil
        var escapingSymlinks: [String] = []
        var resolvedExecPair: (logical: URL, read: URL)? = nil

        if let infoPlistURL = matchedInfoPlistURL {
            let resolvedInfoPlist = infoPlistURL.resolvingSymlinksInPath().standardizedFileURL
            let resolvedInfoPlistStd = IPAPackageScanner.lexicalStandardizedPath(resolvedInfoPlist.path)
            guard resolvedInfoPlistStd.hasPrefix(bundleResolvedPrefix) else {
                throw IPAPackageScannerError.zipSlipDetected("Info.plist")
            }
            guard let plistData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: resolvedInfoPlist, maxBytes: 8 * 1024 * 1024),
                  let parsedInfo = (try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil)) as? [String: Any] else {
                throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                    en: "Missing or invalid Info.plist",
                    zh: "缺少或无效的 Info.plist"
                ))
            }
            rawInfoPlistData = plistData
            infoDict = parsedInfo

            let pkgType = (infoDict["CFBundlePackageType"] as? String)?.uppercased()
            let isXCFrameworkPlist = (pkgType == "XFWK" || infoDict["AvailableLibraries"] != nil || bundleExt == "xcframework")

            if !isXCFrameworkPlist {
                let candidateExecRoots: [URL] = [
                    url,
                    url.appendingPathComponent("Contents/MacOS"),
                    url.appendingPathComponent("Versions/Current"),
                    url.appendingPathComponent("Versions/A")
                ]
                let fallbackName = infoDict["CFBundleDisplayName"] as? String
                    ?? infoDict["CFBundleName"] as? String
                    ?? bundleStem
                var resolvedPrimaryExec: URL? = nil
                var firstExecError: Error? = nil
                for rootCandidate in candidateExecRoots {
                    var rIsDir: ObjCBool = false
                    guard FileManager.default.fileExists(atPath: rootCandidate.path, isDirectory: &rIsDir), rIsDir.boolValue else {
                        continue
                    }
                    let rootResolved = rootCandidate.resolvingSymlinksInPath().standardizedFileURL
                    let rootResolvedStd = IPAPackageScanner.lexicalStandardizedPath(rootResolved.path)
                    guard rootResolvedStd == bundleResolvedPath || rootResolvedStd.hasPrefix(bundleResolvedPrefix) else {
                        throw IPAPackageScannerError.zipSlipDetected(rootCandidate.lastPathComponent)
                    }
                    do {
                        let (_, foundExec) = try IPAPackageScanner.resolveSafeBundleExecutableURL(
                            infoDict: infoDict,
                            bundleURL: rootResolved,
                            fallbackName: fallbackName
                        )
                        resolvedPrimaryExec = foundExec
                        break
                    } catch let err as IPAPackageScannerError {
                        if case .zipSlipDetected = err { throw err }
                        if case .invalidInfoPlist = err { throw err }
                        if firstExecError == nil { firstExecError = err }
                    } catch {
                        if firstExecError == nil { firstExecError = error }
                    }
                }
                if let chosenExec = resolvedPrimaryExec {
                    let resolvedChosen = chosenExec.resolvingSymlinksInPath().standardizedFileURL
                    let resolvedChosenStd = IPAPackageScanner.lexicalStandardizedPath(resolvedChosen.path)
                    guard resolvedChosenStd.hasPrefix(bundleResolvedPrefix) else {
                        throw IPAPackageScannerError.zipSlipDetected(chosenExec.lastPathComponent)
                    }
                    resolvedExecPair = (chosenExec, resolvedChosen)
                } else if !isFrameworkOrGenericBundle {
                    throw firstExecError ?? IPAPackageScannerError.missingExecutable(fallbackName)
                }
            }
        }

        if resolvedExecPair == nil {
            // Support `.xcframework`, `Info.plist`-less `.framework` / `.bundle`, and `Info.plist`-less `.app` / `.appex` / `.xpc` bundles containing binaries
            let stemCandidates: [URL] = [
                url.appendingPathComponent(bundleStem),
                url.appendingPathComponent("Versions/Current/\(bundleStem)"),
                url.appendingPathComponent("Versions/A/\(bundleStem)"),
                url.appendingPathComponent("Contents/MacOS/\(bundleStem)")
            ]
            for cand in stemCandidates {
                var cStat = stat()
                guard lstat(cand.path, &cStat) == 0 else { continue }
                let resolved = cand.resolvingSymlinksInPath().standardizedFileURL
                let resolvedStd = IPAPackageScanner.lexicalStandardizedPath(resolved.path)
                guard resolvedStd.hasPrefix(bundleResolvedPrefix) else {
                    throw IPAPackageScannerError.zipSlipDetected(cand.lastPathComponent)
                }
                var rStat = stat()
                if lstat(resolved.path, &rStat) == 0 && (rStat.st_mode & S_IFMT) == S_IFREG {
                    resolvedExecPair = (cand, resolved)
                    break
                }
            }
            if resolvedExecPair == nil {
                let discovered = IPAPackageScanner.enumerateCandidateFiles(
                    in: url,
                    bundleRootResolvedPrefix: bundleResolvedPrefix,
                    escapingSymlinks: &escapingSymlinks,
                    bundleRootURL: url
                )
                for item in discovered {
                    let isRole = IPAPackageScanner.isExpectedEmbeddedBinaryRole(
                        itemURL: item.logicalURL,
                        bundleRootResolvedPrefix: bundleResolvedPrefix
                    )
                    let (pfx, fsz) = IPAPackageScanner.readMachOHeaderPrefix(of: item.readURL)
                    if isRole || IPAPackageScanner.isMachOOrFatMagic(pfx, fileSize: fsz) {
                        resolvedExecPair = (item.logicalURL, item.readURL)
                        break
                    }
                }
            }
            if resolvedExecPair == nil {
                if !escapingSymlinks.isEmpty {
                    var symInds: [ThreatIndicator] = []
                    var symMatched: Set<String> = []
                    IPAPackageScanner.appendEscapingSymlinkIndicators(
                        escapingSymlinks: escapingSymlinks,
                        allIndicators: &symInds,
                        allMatchedSymbols: &symMatched
                    )
                    let symEvidence = AuditEvidence(
                        matchedSymbols: Array(symMatched).sorted(),
                        linkedDylibs: [],
                        hasAppGroups: false,
                        appGroups: [],
                        installChannel: .developerSideloaded,
                        cryptid: 0,
                        isFairPlayEncrypted: false,
                        escapingSymlinks: escapingSymlinks,
                        dynamicLoadingPresent: false,
                        pathEnumerationPresent: false,
                        remediationGuidance: WQLocale.pick(
                            en: "Bundle directory contains escaping symbolic links pointing outside bundle boundaries.",
                            zh: "Bundle 目录包含指向包边界之外的越界符号链接。"
                        ),
                        isWhitelistEligible: false,
                        isTeamIdWhitelistVerified: false
                    )
                    return ScanFinding(
                        bundleId: bundleStem,
                        displayName: bundleStem,
                        version: "1.0",
                        teamId: nil,
                        executablePath: nil,
                        bundlePath: url.path,
                        installChannel: .developerSideloaded,
                        riskTier: .highRisk,
                        isWhitelisted: false,
                        whitelistedToolName: nil,
                        indicators: symInds,
                        evidence: symEvidence,
                        scanTimestamp: Date()
                    )
                } else if isFrameworkOrGenericBundle || matchedInfoPlistURL != nil {
                    throw IPAPackageScannerError.missingExecutable(bundleStem)
                } else {
                    throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                        en: "Missing or invalid Info.plist",
                        zh: "缺少或无效的 Info.plist"
                    ))
                }
            }
        }

        let execURL = resolvedExecPair!.logical
        let execReadURL = resolvedExecPair!.read
        
        let execData = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: execReadURL)
        let mainSlices = try MachOParser.shared.parseAllSlices(data: execData)
        if infoDict.isEmpty {
            for slice in MachOParser.selectAuditSlices(from: mainSlices) {
                if let sPlist = slice.embeddedInfoPlist {
                    for (k, v) in sPlist where infoDict[k] == nil {
                        infoDict[k] = v
                    }
                    if rawInfoPlistData == nil {
                        rawInfoPlistData = Self.extractRawEmbeddedInfoPlistData(from: slice)
                    }
                }
            }
        }

        let pkgTypeUpper = (infoDict["CFBundlePackageType"] as? String)?.uppercased()
        let isTopLevelXCFramework = (pkgTypeUpper == "XFWK" || infoDict["AvailableLibraries"] != nil || bundleExt == "xcframework")
        let rawPlistBundleId: String? = isTopLevelXCFramework
            ? nil
            : (infoDict["CFBundleIdentifier"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasExplicitPlistBundleId = (rawPlistBundleId != nil && !rawPlistBundleId!.isEmpty)
        let bundleId = (hasExplicitPlistBundleId ? rawPlistBundleId! : nil) ?? bundleStem
        let displayName = infoDict["CFBundleDisplayName"] as? String ?? infoDict["CFBundleName"] as? String ?? bundleStem
        let version = infoDict["CFBundleShortVersionString"] as? String ?? infoDict["CFBundleVersion"] as? String ?? "1.0"
        let details = machoScanner.parseMachO(
            files: mainSlices,
            rawData: execData,
            expectedContainerSliceCount: mainSlices.first?.slicesInContainer.count
        )
        
        let mainTrustEval = CSBlobParser.shared.inspectCodeSignatureTrustEvaluation(fromSlices: mainSlices)
        var codeSigTrust = mainTrustEval.disposition
        var verifiedSignerKind = mainTrustEval.signerKind
        var hasBundleSealTampering = Self.isCodeSignatureSealMismatchDisposition(codeSigTrust)
        var hasExplicitSlotSealTampering = (codeSigTrust == .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch"))
        var sealTamperingLocations: [String] = hasBundleSealTampering ? [execURL.lastPathComponent] : []
        if !isTopLevelXCFramework,
           let plistBindingFailure = CSBlobParser.shared.verifyBundleInfoPlistBinding(
               fromSlices: mainSlices,
               infoPlistData: rawInfoPlistData,
               plistBundleId: hasExplicitPlistBundleId ? bundleId : nil
           ) {
            codeSigTrust = plistBindingFailure
            verifiedSignerKind = .none
            hasBundleSealTampering = true
            if Self.hasNonZeroSpecialSlot1Hash(inSlices: mainSlices) {
                hasExplicitSlotSealTampering = true
                sealTamperingLocations.append("Info.plist (Special Slot -1)")
            }
        }
        if !isTopLevelXCFramework,
           let crSealFailure = CSBlobParser.shared.verifyBundleCodeResourcesSeal(
               fromSlices: mainSlices,
               bundleURL: url
           ) {
            if !Self.isCodeSignatureSealMismatchDisposition(codeSigTrust) {
                codeSigTrust = crSealFailure
            }
            verifiedSignerKind = .none
            hasBundleSealTampering = true
            hasExplicitSlotSealTampering = true
            sealTamperingLocations.append("_CodeSignature/CodeResources (Special Slot -3)")
        }
        let mainHasMissingCS = CSBlobParser.hasMissingCodeSignature(inSlices: mainSlices)
        var bundleSigTrust = codeSigTrust
        var bundleHasMissingCS = mainHasMissingCS
        var embeddedHasMissingCS = false
        var appHasMissingCS = mainHasMissingCS
        var channelResult = ChannelClassifier.classifyBundle(
            at: url,
            cryptid: details.cryptid,
            codeSignatureTrust: codeSigTrust,
            verifiedSignerKind: verifiedSignerKind,
            hasMissingCodeSignature: mainHasMissingCS
        )
        var mainAppGroups: [String] = []
        var mainEntitlementsDict: [String: Any] = [:]
        var entitlementsDict: [String: Any] = [:]
        for slice in MachOParser.selectAuditSlices(from: mainSlices) {
            let (_, sliceGroups) = CSBlobParser.shared.extractAppGroups(fromSlice: slice)
            for g in sliceGroups where !mainAppGroups.contains(g) {
                mainAppGroups.append(g)
            }
            let sliceEnts = CSBlobParser.shared.parseMergedEntitlements(fromSlice: slice)
            mainEntitlementsDict = CSBlobParser.mergeEntitlementDictionaries(mainEntitlementsDict, sliceEnts)
            entitlementsDict = CSBlobParser.mergeEntitlementDictionaries(entitlementsDict, sliceEnts)
        }
        let identityResolution = IPAPackageScanner.resolveDistinctEntitlementIdentities(
            fromSlices: mainSlices,
            explicitTeamId: channelResult.teamIdentifier,
            allowedProvisionPrefixes: channelResult.verifiedProvisionTeamPrefixes
        )
        let mainEntBundleId = identityResolution.primaryBundleId
        let verifiedMainTeamPrefixes = IPAPackageScanner.computeVerifiedTeamPrefixes(
            codeSignatureTrust: codeSigTrust,
            hasMissingCodeSignature: mainHasMissingCS,
            entitlements: mainEntitlementsDict,
            provisionTeamId: channelResult.isProvisionCMSVerified ? channelResult.teamIdentifier : nil,
            verifiedProvisionPrefixes: channelResult.verifiedProvisionTeamPrefixes,
            hasMultipleTeamIds: identityResolution.hasMultipleTeamIds,
            hasProvisionTeamConflict: identityResolution.hasProvisionTeamConflict
        )
        let effectiveTeamId = channelResult.teamIdentifier ?? identityResolution.inferredTeamId
        let hasConflictingBundleIdentity = identityResolution.hasMultipleBundleIds
            || identityResolution.hasMultipleTeamIds
            || identityResolution.hasProvisionTeamConflict
            || (hasExplicitPlistBundleId && identityResolution.distinctBundleIds.contains {
                IPAPackageScanner.doesEntitlementBundleIdConflict(entBundleId: $0, withPlistBundleId: bundleId)
            })
        var hasVerifiedBundleIdentity = (hasExplicitPlistBundleId || mainEntBundleId != nil)
            && !hasConflictingBundleIdentity
            && !hasBundleSealTampering
        let gating = EntitlementGating.evaluate(hasAppGroups: !mainAppGroups.isEmpty, appGroups: mainAppGroups)
        var combinedAppGroups = gating.appGroups
        let mainBackgroundModes = IPAPackageScanner.extractFlexibleStringList(infoDict["UIBackgroundModes"])
        
        let context = MachOScanner.ScanContext(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            teamId: effectiveTeamId,
            bundlePath: url.path,
            executablePath: execURL.path,
            installChannel: channelResult.channel,
            appGroups: gating.appGroups,
            disqualifyAppStoreExemption: details.cryptid != 0 && (mainHasMissingCS || codeSigTrust != .appleAppStoreVerified)
        )
        
        var allIndicators: [ThreatIndicator] = []
        var allMatchedSymbols: Set<String> = []
        var allLinkedDylibs: Set<String> = Set(details.linkedDylibs)
        let mainInspectable = !details.isFairPlayEncrypted || details.hasUnencryptedSegments || codeSigTrust.isDisqualifiedFromAppStore || mainHasMissingCS
        let mainSymbolsInspectable = mainInspectable || codeSigTrust != .appleAppStoreVerified
        var unencryptedSymbols: Set<String> = mainSymbolsInspectable ? Set(details.symbols) : []
        var unencryptedTextStrings: Set<String> = mainInspectable ? Set(details.textStrings) : []
        var hasUnencryptedBinary = mainInspectable
        var appLinkedDylibs: Set<String> = Set(details.linkedDylibs)
        var appUnencryptedSymbols: Set<String> = mainSymbolsInspectable ? Set(details.symbols) : []
        var appHasUnencryptedBinary = mainInspectable
        var dynamicLoadingFound = false
        var pathEnumerationFound = false
        
        let mainFinding = machoScanner.scan(details: details, context: context)
        allIndicators.append(contentsOf: mainFinding.indicators)
        allMatchedSymbols.formUnion(mainFinding.evidence.matchedSymbols)
        if mainFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
        if mainFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
        
        // Discover and scan all embedded *.appex, *.xpc, and nested *.app bundles FIRST so combinedAppGroups includes extension App Groups
        // before evaluating shared Frameworks/* across the .app (R5 D3)
        var appexDiscoveryEscapes: [String] = []
        let appexURLs = IPAPackageScanner.discoverEmbeddedExtensions(
            in: url,
            bundleRootResolvedPrefix: bundleResolvedPrefix,
            escapingSymlinks: &appexDiscoveryEscapes,
            bundleRootURL: url
        )
        for esc in appexDiscoveryEscapes where !escapingSymlinks.contains(esc) {
            escapingSymlinks.append(esc)
        }
        let appexPrefixes = IPAPackageScanner.computeEmbeddedExtensionPrefixes(
            appexURLs: appexURLs,
            bundleRootResolvedPrefix: bundleResolvedPrefix
        )

        for itemURL in appexURLs {
            IPAPackageScanner.scanEmbeddedAppex(
                appexURL: itemURL,
                rootBundleURL: url,
                bundleResolvedPrefix: bundleResolvedPrefix,
                allEmbeddedExtensionPrefixes: appexPrefixes,
                parentBundleId: bundleId,
                version: version,
                teamId: effectiveTeamId,
                verifiedBundleProvisionTeamId: channelResult.isProvisionCMSVerified ? channelResult.teamIdentifier : nil,
                verifiedBundleProvisionPrefixes: channelResult.verifiedProvisionTeamPrefixes,
                installChannel: channelResult.channel,
                machoScanner: machoScanner,
                combinedAppGroups: &combinedAppGroups,
                entitlementsDict: &entitlementsDict,
                allIndicators: &allIndicators,
                allMatchedSymbols: &allMatchedSymbols,
                allLinkedDylibs: &allLinkedDylibs,
                unencryptedSymbols: &unencryptedSymbols,
                unencryptedTextStrings: &unencryptedTextStrings,
                hasUnencryptedBinary: &hasUnencryptedBinary,
                bundleCodeSignatureTrust: &bundleSigTrust,
                bundleHasMissingCodeSignature: &bundleHasMissingCS,
                embeddedHasMissingCodeSignature: &embeddedHasMissingCS,
                hasBundleSealTampering: &hasBundleSealTampering,
                hasExplicitSlotSealTampering: &hasExplicitSlotSealTampering,
                sealTamperingLocations: &sealTamperingLocations,
                dynamicLoadingFound: &dynamicLoadingFound,
                pathEnumerationFound: &pathEnumerationFound,
                escapingSymlinks: &escapingSymlinks
            )
            if Self.isCodeSignatureSealMismatchDisposition(bundleSigTrust) {
                hasBundleSealTampering = true
                if bundleSigTrust == .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch") {
                    hasExplicitSlotSealTampering = true
                }
            }
        }
        if (channelResult.channel == .appStore || channelResult.channel == .testFlight)
            && (bundleSigTrust.isDisqualifiedFromAppStore || embeddedHasMissingCS) {
            let downgradeTrust: CodeSignatureTrustDisposition = bundleSigTrust.isDisqualifiedFromAppStore
                ? bundleSigTrust
                : .adHocOrUnsigned
            channelResult = ChannelClassifier.classify(
                cryptid: details.cryptid,
                mobileprovisionData: nil,
                hasMobileProvisionArtifact: false,
                codeSignatureTrust: downgradeTrust,
                verifiedSignerKind: .none,
                hasMissingCodeSignature: mainHasMissingCS || embeddedHasMissingCS
            )
        }
        
        // Scan all remaining Mach-O binaries across the bundle (identified by magic or binary role, excluding mainExec and *.appex subtrees)
        // using combinedAppGroups so frameworks shared with grouped .appex extensions are properly gated
        let mainExecCanonical = IPAPackageScanner.lexicalStandardizedPath(execURL.path)
        let mainExecResolved = IPAPackageScanner.lexicalStandardizedPath(execReadURL.path)
        var enumerationEscapes: [String] = []
        let appCandidates = IPAPackageScanner.enumerateCandidateFiles(
            in: url,
            bundleRootResolvedPrefix: bundleResolvedPrefix,
            escapingSymlinks: &enumerationEscapes,
            bundleRootURL: url
        )
        for esc in enumerationEscapes where !escapingSymlinks.contains(esc) {
            escapingSymlinks.append(esc)
        }
        for candidate in appCandidates {
            let itemURL = candidate.logicalURL
            let readURL = candidate.readURL
            let itemCanonical = IPAPackageScanner.lexicalStandardizedPath(itemURL.path)
            if itemCanonical == mainExecCanonical ||
               itemCanonical == mainExecResolved ||
               IPAPackageScanner.lexicalStandardizedPath(readURL.path) == mainExecResolved ||
               appexPrefixes.contains(where: { itemCanonical.hasPrefix($0) }) {
                continue
            }
            let isDylib = itemURL.pathExtension.lowercased() == "dylib"
            let isExpectedRole = IPAPackageScanner.isExpectedEmbeddedBinaryRole(
                itemURL: itemURL,
                bundleRootResolvedPrefix: bundleResolvedPrefix
            )
            let (prefixBytes, readFileSize) = IPAPackageScanner.readMachOHeaderPrefix(of: readURL)
            let hasMachOMagic = IPAPackageScanner.isMachOOrFatMagic(prefixBytes, fileSize: readFileSize)
            guard isExpectedRole || hasMachOMagic else { continue }

            let relPath = IPAPackageScanner.bundleRelativePath(of: itemURL, in: url)
            if isDylib {
                allLinkedDylibs.insert("@executable_path/\(relPath)")
                appLinkedDylibs.insert("@executable_path/\(relPath)")
            }

            guard let dylibData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: readURL),
                  let fwSlices = try? MachOParser.shared.parseAllSlices(data: dylibData),
                  !fwSlices.isEmpty else {
                let corruptInd = IPAPackageScanner.makeCorruptMachOIndicator(relPath: relPath)
                allIndicators.append(corruptInd)
                allMatchedSymbols.insert(corruptInd.signature)
                continue
            }

            var fwSigTrust = CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: fwSlices)
            let candParentURL = itemURL.deletingLastPathComponent()
            let candGrandParentURL = candParentURL.deletingLastPathComponent()
            let frameworkRootURL: URL?
            if candParentURL.pathExtension.lowercased() == "framework" {
                frameworkRootURL = candParentURL
            } else if candGrandParentURL.lastPathComponent.lowercased() == "versions" &&
                      candGrandParentURL.deletingLastPathComponent().pathExtension.lowercased() == "framework" {
                frameworkRootURL = candGrandParentURL.deletingLastPathComponent()
            } else {
                frameworkRootURL = nil
            }
            if let fwRootURL = frameworkRootURL {
                let (fwPlistFailure, fwHasSlot1) = Self.verifyFrameworkInfoPlistBinding(
                    fromSlices: fwSlices,
                    frameworkRootURL: fwRootURL,
                    binaryParentURL: candParentURL,
                    bundleResolvedPrefix: bundleResolvedPrefix,
                    escapingSymlinks: &escapingSymlinks,
                    rootBundleURL: url
                )
                if let fwPlistFailure {
                    hasBundleSealTampering = true
                    if fwHasSlot1 {
                        hasExplicitSlotSealTampering = true
                        if !sealTamperingLocations.contains(relPath) {
                            sealTamperingLocations.append(relPath)
                        }
                    }
                    if !Self.isCodeSignatureSealMismatchDisposition(fwSigTrust)
                        && (fwSigTrust == .appleAppStoreVerified || fwPlistFailure.isDisqualifiedFromAppStore) {
                        fwSigTrust = fwPlistFailure
                    }
                }
                if let fwCRFailure = CSBlobParser.shared.verifyBundleCodeResourcesSeal(
                    fromSlices: fwSlices,
                    bundleURL: fwRootURL
                ) {
                    hasBundleSealTampering = true
                    hasExplicitSlotSealTampering = true
                    if !sealTamperingLocations.contains(relPath) {
                        sealTamperingLocations.append(relPath)
                    }
                    if !Self.isCodeSignatureSealMismatchDisposition(fwSigTrust)
                        && (fwSigTrust == .appleAppStoreVerified || fwCRFailure.isDisqualifiedFromAppStore) {
                        fwSigTrust = fwCRFailure
                    }
                }
            }
            if Self.isCodeSignatureSealMismatchDisposition(fwSigTrust) {
                hasBundleSealTampering = true
                if fwSigTrust == .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch") {
                    hasExplicitSlotSealTampering = true
                }
                if !sealTamperingLocations.contains(relPath) {
                    sealTamperingLocations.append(relPath)
                }
            }
            let fwHasMissingCS = CSBlobParser.hasMissingCodeSignature(inSlices: fwSlices)
            if fwHasMissingCS {
                embeddedHasMissingCS = true
                bundleHasMissingCS = true
                appHasMissingCS = true
            }
            if fwSigTrust != .appleAppStoreVerified {
                if !Self.isCodeSignatureSealMismatchDisposition(bundleSigTrust)
                    && (bundleSigTrust == .appleAppStoreVerified || fwSigTrust.isDisqualifiedFromAppStore) {
                    bundleSigTrust = fwSigTrust
                }
            }
            if (channelResult.channel == .appStore || channelResult.channel == .testFlight)
                && (fwSigTrust.isDisqualifiedFromAppStore || fwHasMissingCS) {
                let downgradeTrust: CodeSignatureTrustDisposition = fwSigTrust.isDisqualifiedFromAppStore
                    ? fwSigTrust
                    : .adHocOrUnsigned
                channelResult = ChannelClassifier.classify(
                    cryptid: details.cryptid,
                    mobileprovisionData: nil,
                    hasMobileProvisionArtifact: false,
                    codeSignatureTrust: downgradeTrust,
                    verifiedSignerKind: .none,
                    hasMissingCodeSignature: mainHasMissingCS || fwHasMissingCS
                )
            }

            let fwDetails = machoScanner.parseMachO(
                files: fwSlices,
                rawData: dylibData,
                expectedContainerSliceCount: fwSlices.first?.slicesInContainer.count
            )
            var fwGroups = combinedAppGroups
            var fwOwnEnts: [String: Any] = [:]
            for s in MachOParser.selectAuditSlices(from: fwSlices) {
                let (_, sg) = CSBlobParser.shared.extractAppGroups(fromSlice: s)
                for g in sg where !fwGroups.contains(g) { fwGroups.append(g) }
                for g in sg where !combinedAppGroups.contains(g) { combinedAppGroups.append(g) }
                let fwEnts = CSBlobParser.shared.parseMergedEntitlements(fromSlice: s)
                fwOwnEnts = CSBlobParser.mergeEntitlementDictionaries(fwOwnEnts, fwEnts)
                entitlementsDict = CSBlobParser.mergeEntitlementDictionaries(
                    entitlementsDict,
                    IPAPackageScanner.strippingBinaryScopedIdentityEntitlements(fwEnts)
                )
            }
            let fwIdRes = IPAPackageScanner.resolveDistinctEntitlementIdentities(
                fromSlices: fwSlices,
                explicitTeamId: channelResult.teamIdentifier,
                allowedProvisionPrefixes: channelResult.verifiedProvisionTeamPrefixes
            )
            let fwVerifiedPrefixes = IPAPackageScanner.computeVerifiedTeamPrefixes(
                codeSignatureTrust: fwSigTrust,
                hasMissingCodeSignature: fwHasMissingCS,
                entitlements: fwOwnEnts,
                provisionTeamId: channelResult.isProvisionCMSVerified ? channelResult.teamIdentifier : nil,
                verifiedProvisionPrefixes: channelResult.verifiedProvisionTeamPrefixes,
                hasMultipleTeamIds: fwIdRes.hasMultipleTeamIds,
                hasProvisionTeamConflict: fwIdRes.hasProvisionTeamConflict
            )
            IPAPackageScanner.appendPerBinaryWildcardKeychainIndicators(
                entitlements: fwOwnEnts,
                allowedOwnTeamPrefixes: fwVerifiedPrefixes,
                location: "\(relPath): CSBlob Entitlements",
                allIndicators: &allIndicators,
                allMatchedSymbols: &allMatchedSymbols
            )
            let fwContext = MachOScanner.ScanContext(
                bundleId: bundleId,
                displayName: displayName,
                version: version,
                teamId: effectiveTeamId,
                bundlePath: url.path,
                executablePath: itemURL.path,
                installChannel: channelResult.channel,
                appGroups: fwGroups,
                disqualifyAppStoreExemption: fwDetails.cryptid != 0 && (fwHasMissingCS || fwSigTrust != .appleAppStoreVerified)
            )
            let fwFinding = machoScanner.scan(details: fwDetails, context: fwContext)
            for ind in fwFinding.indicators {
                allIndicators.append(ThreatIndicator(
                    signature: ind.signature,
                    description: "\(ind.description) [\(relPath)]",
                    category: ind.category,
                    location: "\(relPath): \(ind.location)",
                    severity: ind.severity
                ))
            }
            allMatchedSymbols.formUnion(fwFinding.evidence.matchedSymbols)
            allLinkedDylibs.formUnion(fwDetails.linkedDylibs)
            appLinkedDylibs.formUnion(fwDetails.linkedDylibs)
            if !fwDetails.isFairPlayEncrypted || fwDetails.hasUnencryptedSegments || fwSigTrust.isDisqualifiedFromAppStore || fwHasMissingCS {
                hasUnencryptedBinary = true
                appHasUnencryptedBinary = true
                unencryptedSymbols.formUnion(fwDetails.symbols)
                appUnencryptedSymbols.formUnion(fwDetails.symbols)
                unencryptedTextStrings.formUnion(fwDetails.textStrings)
            } else if fwSigTrust != .appleAppStoreVerified {
                unencryptedSymbols.formUnion(fwDetails.symbols)
                appUnencryptedSymbols.formUnion(fwDetails.symbols)
            }
            if fwFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
            if fwFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
        }
        
        // Escaping Bundle Symlinks & Expanded Local Threat Signatures (propagate all matched threat signatures into allMatchedSymbols so Trojanized bundles can never spoof WhitelistEngine)
        IPAPackageScanner.appendEscapingSymlinkIndicators(
            escapingSymlinks: escapingSymlinks,
            allIndicators: &allIndicators,
            allMatchedSymbols: &allMatchedSymbols
        )
        if !escapingSymlinks.isEmpty && (channelResult.channel == .appStore || channelResult.channel == .testFlight) {
            bundleSigTrust = .nonAppStoreSigner(subjectSummary: "CodeDirectory/CodeResources Mismatch")
            channelResult = ChannelClassifier.classify(
                cryptid: details.cryptid,
                mobileprovisionData: nil,
                hasMobileProvisionArtifact: false,
                codeSignatureTrust: bundleSigTrust,
                verifiedSignerKind: .none,
                hasMissingCodeSignature: mainHasMissingCS || embeddedHasMissingCS
            )
        }
        IPAPackageScanner.appendExpandedThreatIndicators(
            bundleId: bundleId,
            displayName: displayName,
            installChannel: channelResult.channel,
            mainCryptid: details.cryptid,
            mainIsFairPlayEncrypted: details.isFairPlayEncrypted,
            mainHasUnencryptedSegments: details.hasUnencryptedSegments,
            mainBackgroundModes: mainBackgroundModes,
            infoDict: infoDict,
            entitlementsDict: entitlementsDict,
            allLinkedDylibs: allLinkedDylibs,
            appLinkedDylibs: appLinkedDylibs,
            unencryptedSymbols: unencryptedSymbols,
            appUnencryptedSymbols: appUnencryptedSymbols,
            unencryptedTextStrings: unencryptedTextStrings,
            hasUnencryptedBinary: hasUnencryptedBinary,
            appHasUnencryptedBinary: appHasUnencryptedBinary,
            codeSignatureTrust: bundleSigTrust,
            hasMissingCodeSignature: bundleHasMissingCS,
            appHasMissingCodeSignature: appHasMissingCS,
            verifiedOwnTeamPrefixes: verifiedMainTeamPrefixes,
            allIndicators: &allIndicators,
            allMatchedSymbols: &allMatchedSymbols
        )
        for candidateEntBid in identityResolution.distinctBundleIds where candidateEntBid.caseInsensitiveCompare(bundleId) != .orderedSame {
            IPAPackageScanner.appendConflictingIdentityIndicators(
                conflictingBundleId: candidateEntBid,
                displayName: displayName,
                installChannel: channelResult.channel,
                mainCryptid: details.cryptid,
                mainIsFairPlayEncrypted: details.isFairPlayEncrypted,
                mainHasUnencryptedSegments: details.hasUnencryptedSegments,
                hasUnencryptedBinary: hasUnencryptedBinary,
                codeSignatureTrust: bundleSigTrust,
                hasMissingCodeSignature: bundleHasMissingCS,
                entitlementsDict: entitlementsDict,
                verifiedOwnTeamPrefixes: verifiedMainTeamPrefixes,
                allIndicators: &allIndicators,
                allMatchedSymbols: &allMatchedSymbols
            )
        }
        
        if Self.isCodeSignatureSealMismatchDisposition(bundleSigTrust) {
            hasBundleSealTampering = true
        }
        let hasStructuralHostility = hasBundleSealTampering
            || !escapingSymlinks.isEmpty
            || details.corruptedSliceCount > 0
            || allMatchedSymbols.contains(where: WhitelistEngine.isNonWhitelistableStructuralSignature)
        if hasStructuralHostility {
            hasVerifiedBundleIdentity = false
        }
        if hasExplicitSlotSealTampering {
            let sealDetail = sealTamperingLocations.isEmpty
                ? "CodeDirectory Special Slot -1/-3 seal mismatch"
                : sealTamperingLocations.joined(separator: "; ")
            let sealInd = ThreatIndicator(
                signature: "CODE_SIGNATURE_SEAL_MISMATCH",
                description: WQLocale.pick(
                    en: "Code signature seal tampering detected (\(sealDetail)): Info.plist or _CodeSignature/CodeResources no longer matches CodeDirectory Special Slot hashes.",
                    zh: "检测到代码签名封印篡改（\(sealDetail)）：Info.plist 或 _CodeSignature/CodeResources 与 CodeDirectory 特殊槽位哈希不匹配。"
                ),
                category: "Code Signature Integrity",
                location: "LC_CODE_SIGNATURE (Special Slot -1/-3)",
                severity: .highRisk
            )
            allIndicators.append(sealInd)
            allMatchedSymbols.insert(sealInd.signature)
        }

        var provisionalRisk: RiskTier = .safe
        if allIndicators.contains(where: { $0.severity == .highRisk }) {
            provisionalRisk = .highRisk
        } else if allIndicators.contains(where: { $0.severity == .caution }) {
            provisionalRisk = .caution
        }

        let isTeamVerifiedForWhitelist: Bool
        if let effTeam = effectiveTeamId, !effTeam.isEmpty {
            let hasVerifiedAppStoreBundle = (bundleSigTrust == .appleAppStoreVerified && !bundleHasMissingCS && !channelResult.hasMobileProvision)
            isTeamVerifiedForWhitelist = (channelResult.isProvisionCMSVerified || hasVerifiedAppStoreBundle)
                && !identityResolution.hasMultipleTeamIds
                && !identityResolution.hasProvisionTeamConflict
                && !bundleHasMissingCS
                && (bundleSigTrust != .adHocOrUnsigned)
        } else {
            isTeamVerifiedForWhitelist = true
        }
        let whitelistTeamId: String? = isTeamVerifiedForWhitelist ? effectiveTeamId : nil
        
        var isWhitelisted = false
        var whitelistedToolName: String? = nil
        var finalRisk = provisionalRisk
        
        if hasVerifiedBundleIdentity && (provisionalRisk == .highRisk || provisionalRisk == .caution) {
            let wlResult = whitelistEngine.isWhitelisted(
                bundleId: hasExplicitPlistBundleId ? bundleId : (mainEntBundleId ?? bundleId),
                appGroups: combinedAppGroups,
                matchedSignatures: Array(allMatchedSymbols),
                teamId: whitelistTeamId
            )
            if wlResult.isWhitelisted {
                isWhitelisted = true
                whitelistedToolName = wlResult.toolName
                finalRisk = .knownTool
            }
        }
        
        let remediation: String
        switch finalRisk {
        case .highRisk:
            remediation = WQLocale.pick(
                en: "High-risk exploit or privilege escalation indicators detected (containermanagerd sandbox escape, inline svc #0x80 direct syscalls, local exploit primitives, impersonated wallet/messenger, or private privacy bypass). Uninstall immediately and remove its provisioning profile.",
                zh: "检测到高危越权或本地利用特征（containermanagerd 跨沙盒逃逸、内联 svc #0x80 直接系统调用、本地越权原语、伪造钱包/通讯软件或隐私绕过 API 引用），建议立即卸载并注销描述文件。"
            )
        case .knownTool:
            remediation = WQLocale.pick(
                en: "Matched trusted whitelist rule (\(whitelistedToolName ?? "Known Tool")).",
                zh: "匹配已知开源安全研究工具白名单（\(whitelistedToolName ?? "Known Tool")）。"
            )
        case .caution:
            remediation = WQLocale.pick(
                en: "Application declares shared containers or includes third-party dynamic libraries / supply-chain advisories. Review source before trusting.",
                zh: "应用声明了共享容器或包含第三方动态库/供应链风险组件，建议复核安装来源。"
            )
        case .safe:
            remediation = WQLocale.pick(
                en: "No cross-container sandbox escape or malicious exploit indicators detected; safe.",
                zh: "未发现跨沙盒越权或恶意利用特征，状态安全。"
            )
        }
        
        let evidence = AuditEvidence(
            matchedSymbols: Array(allMatchedSymbols).sorted(),
            linkedDylibs: Array(allLinkedDylibs).sorted(),
            hasAppGroups: !combinedAppGroups.isEmpty,
            appGroups: combinedAppGroups,
            installChannel: channelResult.channel,
            cryptid: details.cryptid,
            isFairPlayEncrypted: details.isFairPlayEncrypted,
            escapingSymlinks: escapingSymlinks,
            dynamicLoadingPresent: dynamicLoadingFound,
            pathEnumerationPresent: pathEnumerationFound,
            remediationGuidance: remediation,
            isWhitelistEligible: hasVerifiedBundleIdentity,
            isTeamIdWhitelistVerified: isTeamVerifiedForWhitelist
        )
        
        return ScanFinding(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            teamId: effectiveTeamId,
            executablePath: execURL.path,
            bundlePath: url.path,
            installChannel: channelResult.channel,
            riskTier: finalRisk,
            isWhitelisted: isWhitelisted,
            whitelistedToolName: whitelistedToolName,
            indicators: allIndicators,
            evidence: evidence,
            scanTimestamp: Date()
        )
    }
    
    /// Scans a local `.ipa` package archive.
    public func scanIPA(at url: URL) throws -> ScanFinding {
        return try ipaScanner.scan(ipaURL: url)
    }

    /// Scans an `installation_proxy` snapshot file (`.plist`, `.xml`, or `.json`).
    public func scanRegistrySnapshot(at url: URL, includeAppStoreApps: Bool = false) throws -> [ScanFinding] {
        let registryScanner = InstalledAppRegistryScanner(whitelistEngine: whitelistEngine)
        let records = try registryScanner.parseSnapshotFile(at: url)
        return registryScanner.evaluateRecords(records, includeAppStoreApps: includeAppStoreApps)
    }

    /// Summary metadata returned by unified multi-engine installed application scans.
    public struct UnifiedInstalledScanResult: Sendable, Equatable {
        public let findings: [ScanFinding]
        public let liveRegistryConnected: Bool
        public let registryEvaluatedCount: Int
        public let correlatedBinaryCount: Int
        public let probeDetectedCount: Int
        public let statusNotice: String?

        public init(
            findings: [ScanFinding],
            liveRegistryConnected: Bool,
            registryEvaluatedCount: Int,
            correlatedBinaryCount: Int,
            probeDetectedCount: Int,
            statusNotice: String? = nil
        ) {
            self.findings = findings
            self.liveRegistryConnected = liveRegistryConnected
            self.registryEvaluatedCount = registryEvaluatedCount
            self.correlatedBinaryCount = correlatedBinaryCount
            self.probeDetectedCount = probeDetectedCount
            self.statusNotice = statusNotice
        }
    }

    /// Correlates and deduplicates findings across:
    /// 1) `installation_proxy` system registry records (Option 1),
    /// 2) Local `.ipa` / `.app` packages from bound signing directories (Option 2),
    /// 3) On-device URL-scheme probes (Option 3).
    public func correlateAndMergeFindings(
        registryRecords: [InstalledAppRegistryRecord],
        packageFindings: [ScanFinding],
        probeFindings: [ScanFinding] = [],
        includeAppStoreApps: Bool = false
    ) -> (findings: [ScanFinding], registryCount: Int, correlatedCount: Int, probeCount: Int) {
        let registryScanner = InstalledAppRegistryScanner(whitelistEngine: whitelistEngine)
        let registryFindings = registryScanner.evaluateRecords(
            registryRecords,
            includeAppStoreApps: includeAppStoreApps
        )

        var remainingPackages = packageFindings
        var mergedResults: [ScanFinding] = []
        var correlatedCount = 0

        func canCorrelate(registry reg: ScanFinding, withPackage pkg: ScanFinding) -> Bool {
            // Never merge official App Store / TestFlight installations with sideloaded or cross-channel packages
            if reg.installChannel == .appStore || reg.installChannel == .testFlight {
                if pkg.installChannel != reg.installChannel
                    || !pkg.evidence.isFairPlayEncrypted
                    || !reg.evidence.isFairPlayEncrypted {
                    return false
                }
            }
            if pkg.installChannel == .appStore || pkg.installChannel == .testFlight {
                if reg.installChannel != pkg.installChannel
                    || !pkg.evidence.isFairPlayEncrypted
                    || !reg.evidence.isFairPlayEncrypted {
                    return false
                }
            }
            // Never correlate findings signed by different non-empty developer Team IDs
            if let rTeam = reg.teamId?.trimmingCharacters(in: .whitespacesAndNewlines),
               let pTeam = pkg.teamId?.trimmingCharacters(in: .whitespacesAndNewlines),
               !rTeam.isEmpty, !pTeam.isEmpty,
               rTeam.caseInsensitiveCompare(pTeam) != .orderedSame {
                return false
            }
            return true
        }

        func findMatchingPackageIndex(for reg: ScanFinding) -> Int? {
            if let exactIdx = remainingPackages.firstIndex(where: {
                $0.bundleId.caseInsensitiveCompare(reg.bundleId) == .orderedSame && canCorrelate(registry: reg, withPackage: $0)
            }) {
                return exactIdx
            }
            // Handle sideloaders appending personal Team/UDID suffix to original IPA bundleId (e.g. `com.foo.app` -> `com.foo.app.XYZ123`)
            return remainingPackages.firstIndex { pkg in
                guard canCorrelate(registry: reg, withPackage: pkg) else { return false }
                let regLower = reg.bundleId.lowercased()
                let pkgLower = pkg.bundleId.lowercased()
                let prefixMatch = regLower.hasPrefix(pkgLower + ".") || pkgLower.hasPrefix(regLower + ".")
                let nameMatch = reg.displayName.caseInsensitiveCompare(pkg.displayName) == .orderedSame
                return prefixMatch && nameMatch
            }
        }

        for reg in registryFindings {
            if let pkgIdx = findMatchingPackageIndex(for: reg) {
                let pkg = remainingPackages.remove(at: pkgIdx)
                correlatedCount += 1
                mergedResults.append(mergeRegistryAndPackageFinding(registry: reg, package: pkg))
            } else {
                mergedResults.append(reg)
            }
        }

        // Append remaining local signer packages (not yet installed or when registry snapshot was not loaded)
        mergedResults.append(contentsOf: remainingPackages)

        // Append on-device probe findings if not already covered by a non-safe Registry or Package finding
        // (a `.safe` decoy IPA or benign snapshot entry must NEVER silence an active `.highRisk`/`.caution` URL-scheme probe hit)
        var addedProbes = 0
        for probe in probeFindings {
            let alreadyCovered = mergedResults.contains { existing in
                guard existing.riskTier != .safe else { return false }
                let exLower = existing.bundleId.lowercased()
                let prLower = probe.bundleId.lowercased()
                if exLower == prLower || exLower.hasPrefix(prLower + ".") {
                    return true
                }
                return existing.riskTier == .highRisk
                    && existing.displayName.caseInsensitiveCompare(probe.displayName) == .orderedSame
            }
            if !alreadyCovered {
                mergedResults.append(probe)
                addedProbes += 1
            }
        }

        return (mergedResults, registryFindings.count, correlatedCount, addedProbes)
    }

    private func mergeRegistryAndPackageFinding(registry: ScanFinding, package: ScanFinding) -> ScanFinding {
        var combinedIndicators = package.indicators
        var seenIndKeys = Set(combinedIndicators.map { "\($0.category)|\($0.signature)" })

        for ind in registry.indicators {
            // Skip generic registry App Group caution if binary scan already evaluated full Layer 2 Mach-O
            if ind.signature == "com.apple.security.application-groups" && ind.severity == .caution {
                continue
            }
            let key = "\(ind.category)|\(ind.signature)"
            if seenIndKeys.insert(key).inserted {
                combinedIndicators.append(ind)
            }
        }

        let mergedAppGroups = Array(Set(registry.evidence.appGroups).union(package.evidence.appGroups)).sorted()
        var mergedSymbolSet = Set(registry.evidence.matchedSymbols).union(package.evidence.matchedSymbols)
        for ind in combinedIndicators {
            if ind.signature != "com.apple.security.application-groups"
                && ind.signature != SignatureCatalog.dynamicLoadingCautionRule.pattern {
                mergedSymbolSet.insert(ind.signature)
            }
        }
        let mergedSymbols = Array(mergedSymbolSet).sorted()
        let effectiveTeamId = registry.teamId ?? package.teamId

        // Prevent cross-source TeamID lending and unverified TeamID spoofing:
        // an unsigned/ad-hoc Trojanized IPA (`package.teamId == nil` or `!package.evidence.isTeamIdWhitelistVerified`)
        // must NEVER borrow or match `registry.teamId` to pass `allowedTeamIds`, nor may an unsigned/unvalidated
        // or `teamId == nil` registry record borrow `package.teamId`.
        let verifiedRegTeam = registry.evidence.isTeamIdWhitelistVerified ? registry.teamId : nil
        let verifiedPkgTeam = package.evidence.isTeamIdWhitelistVerified ? package.teamId : nil
        let whitelistCandidateTeamId: String?
        if let rTeam = verifiedRegTeam, let pTeam = verifiedPkgTeam,
           rTeam.caseInsensitiveCompare(pTeam) == .orderedSame {
            whitelistCandidateTeamId = rTeam
        } else {
            whitelistCandidateTeamId = nil
        }

        var provisionalRisk: RiskTier = .safe
        if combinedIndicators.contains(where: { $0.severity == .highRisk }) {
            provisionalRisk = .highRisk
        } else if combinedIndicators.contains(where: { $0.severity == .caution }) {
            provisionalRisk = .caution
        }

        let bothWhitelistEligible = registry.evidence.isWhitelistEligible
            && package.evidence.isWhitelistEligible
            && package.evidence.escapingSymlinks.isEmpty
            && !combinedIndicators.contains(where: { WhitelistEngine.isNonWhitelistableStructuralSignature($0.signature) })
            && !mergedSymbolSet.contains(where: WhitelistEngine.isNonWhitelistableStructuralSignature)
        let hasDistinctPackageBundleId = registry.bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
            .caseInsensitiveCompare(package.bundleId.trimmingCharacters(in: .whitespacesAndNewlines)) != .orderedSame

        var isKnown = false
        var resolvedToolName: String? = nil
        var finalRisk: RiskTier = provisionalRisk
        if bothWhitelistEligible && (provisionalRisk == .highRisk || provisionalRisk == .caution) {
            let wl: (isWhitelisted: Bool, toolName: String?)
            if hasDistinctPackageBundleId {
                wl = whitelistEngine.isWhitelistedForBoth(
                    primaryBundleId: registry.bundleId,
                    secondaryBundleId: package.bundleId,
                    appGroups: mergedAppGroups,
                    matchedSignatures: mergedSymbols,
                    teamId: whitelistCandidateTeamId
                )
            } else {
                wl = whitelistEngine.isWhitelisted(
                    bundleId: registry.bundleId,
                    appGroups: mergedAppGroups,
                    matchedSignatures: mergedSymbols,
                    teamId: whitelistCandidateTeamId
                )
            }
            if wl.isWhitelisted {
                isKnown = true
                resolvedToolName = wl.toolName
                finalRisk = .knownTool
            }
        }
        #if os(iOS)
        let runningSelfBid = (Bundle.main.bundleIdentifier ?? "com.wqguard.app")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanRegBid = registry.bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        let matchesSelfHost = !runningSelfBid.isEmpty
            && (cleanRegBid.caseInsensitiveCompare(runningSelfBid) == .orderedSame
                || (cleanRegBid.caseInsensitiveCompare("com.wqguard.app") == .orderedSame
                    && registry.displayName.trimmingCharacters(in: .whitespacesAndNewlines) == "WQGuard"))
        if !isKnown
            && provisionalRisk == .caution
            && !combinedIndicators.contains(where: { $0.severity == .highRisk })
            && !hasDistinctPackageBundleId
            && matchesSelfHost
            && registry.evidence.isWhitelistEligible
            && package.evidence.isWhitelistEligible
            && package.evidence.escapingSymlinks.isEmpty
            && registry.isWhitelisted && registry.whitelistedToolName == "WQGuard",
           let wqTool = whitelistEngine.tool(named: "WQGuard"), wqTool.isEnabled {
            let nonGroupSymbols = mergedSymbols.filter {
                $0 != "com.apple.security.application-groups"
                    && $0 != SignatureCatalog.dynamicLoadingCautionRule.pattern
            }
            let hasProtectedGroup = mergedAppGroups.contains {
                !PatternMatcher.isStrictIdentifierASCII($0)
                    || ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup($0)
            }
            let allExpected = !hasProtectedGroup && nonGroupSymbols.allSatisfy { sig in
                let cleanSig = sig.hasPrefix("_") ? String(sig.dropFirst()) : sig
                return wqTool.expectedSignatures.contains { pattern in
                    let cleanPat = pattern.hasPrefix("_") ? String(pattern.dropFirst()) : pattern
                    return PatternMatcher.matches(pattern: pattern, value: sig)
                        || PatternMatcher.matches(pattern: cleanPat, value: cleanSig)
                }
            }
            if allExpected {
                isKnown = true
                resolvedToolName = wqTool.name
                finalRisk = .knownTool
            }
        }
        #endif

        let pkgFileName = (package.bundlePath as NSString).lastPathComponent
        let mergedPath = "\(registry.bundlePath) " + WQLocale.pick(
            en: "[Linked IPA: \(pkgFileName)]",
            zh: "[已关联源包: \(pkgFileName)]"
        )

        let mergedRemediation: String
        switch finalRisk {
        case .highRisk:
            if package.riskTier == .highRisk && !package.evidence.remediationGuidance.isEmpty {
                mergedRemediation = package.evidence.remediationGuidance
            } else if !registry.evidence.remediationGuidance.isEmpty {
                mergedRemediation = registry.evidence.remediationGuidance
            } else {
                mergedRemediation = WQLocale.pick(
                    en: "High-risk exploit or privilege escalation indicators detected. Uninstall immediately and remove its provisioning profile.",
                    zh: "检测到高危越权或本地利用特征，建议立即卸载并注销描述文件。"
                )
            }
        case .knownTool:
            mergedRemediation = WQLocale.pick(
                en: "Matched trusted whitelist rule (\(resolvedToolName ?? "Known Tool")).",
                zh: "匹配已知开源安全研究工具白名单（\(resolvedToolName ?? "Known Tool")）。"
            )
        case .caution:
            if package.riskTier == .caution && !package.evidence.remediationGuidance.isEmpty {
                mergedRemediation = package.evidence.remediationGuidance
            } else {
                mergedRemediation = WQLocale.pick(
                    en: "Application declares shared containers or includes third-party dynamic libraries / supply-chain advisories. Review source before trusting.",
                    zh: "应用声明了共享容器或包含第三方动态库/供应链风险组件，建议复核安装来源。"
                )
            }
        case .safe:
            mergedRemediation = package.evidence.remediationGuidance
        }

        let mergedEvidence = AuditEvidence(
            matchedSymbols: mergedSymbols,
            linkedDylibs: package.evidence.linkedDylibs,
            hasAppGroups: !mergedAppGroups.isEmpty,
            appGroups: mergedAppGroups,
            installChannel: registry.installChannel,
            cryptid: package.evidence.cryptid,
            isFairPlayEncrypted: package.evidence.isFairPlayEncrypted,
            escapingSymlinks: package.evidence.escapingSymlinks,
            dynamicLoadingPresent: package.evidence.dynamicLoadingPresent,
            pathEnumerationPresent: package.evidence.pathEnumerationPresent,
            remediationGuidance: mergedRemediation,
            auditDepth: .fullBinaryAndRegistry,
            signerIdentity: registry.evidence.signerIdentity ?? package.evidence.signerIdentity,
            correlatedPackageBundleId: hasDistinctPackageBundleId ? package.bundleId : nil,
            isWhitelistEligible: bothWhitelistEligible,
            isTeamIdWhitelistVerified: (effectiveTeamId == nil) || (whitelistCandidateTeamId != nil)
        )

        return ScanFinding(
            bundleId: registry.bundleId,
            displayName: registry.displayName,
            version: registry.version,
            teamId: effectiveTeamId,
            executablePath: package.executablePath,
            bundlePath: mergedPath,
            installChannel: registry.installChannel,
            riskTier: finalRisk,
            isWhitelisted: isKnown,
            whitelistedToolName: resolvedToolName,
            indicators: combinedIndicators,
            evidence: mergedEvidence,
            scanTimestamp: Date()
        )
    }

    /// Unified asynchronous installed-app scan combining:
    /// - Option 1A: Live `lockdownd` / `installation_proxy` over LocalDevVPN (if `pairingFile` provided)
    /// - Option 1B: Saved/imported `installation_proxy` snapshot data (fallback or offline mode)
    /// - Option 2: Bound signing tool directories (`全能签` / `Feather` / `SideStore`) & `Documents`
    /// - Option 3: On-device URL-scheme probe catalog (`OnDeviceAppProbeScanner`)
    public func scanUnifiedInstalledAppsAsync(
        pairingFile: LockdownPairingFile? = nil,
        preferredLockdownHost: String = "10.7.0.1",
        savedSnapshotData: Data? = nil,
        additionalLocations: [URL] = [],
        includeAppStoreApps: Bool = false,
        enableOnDeviceProbe: Bool = true,
        progressHandler: (@Sendable (ScanProgress) -> Void)? = nil
    ) async throws -> UnifiedInstalledScanResult {
        var registryRecords: [InstalledAppRegistryRecord] = []
        var liveConnected = false
        var notices: [String] = []

        // Engine 1A: Live Lockdown installation_proxy via LocalDevVPN
        if let pairing = pairingFile {
            progressHandler?(ScanProgress(
                currentTarget: WQLocale.pick(
                    en: "Connecting to installation_proxy system registry...",
                    zh: "正在连接本机 installation_proxy 系统注册表..."
                ),
                completedCount: 0,
                totalCount: 1
            ))
            do {
                registryRecords = try await LockdownInstProxyClient.shared.fetchInstalledApps(
                    pairing: pairing,
                    preferredHost: preferredLockdownHost,
                    allowInteractiveConsentWait: savedSnapshotData == nil
                )
                liveConnected = true
                notices.append(WQLocale.pick(
                    en: "Loaded live registry of \(registryRecords.count) installed apps via pairing connection",
                    zh: "已通过配对直连读取全机 \(registryRecords.count) 款应用注册表"
                ))
            } catch {
                notices.append(WQLocale.pick(
                    en: "Live pairing connection unavailable (ensure LocalDevVPN is active); fell back to saved snapshot / local engines",
                    zh: "配对直连未就绪（请确认已开启 LocalDevVPN），已自动切换至快照/本地引擎"
                ))
            }
        }

        // Engine 1B: Fallback to imported/saved snapshot data if live connection wasn't active
        if registryRecords.isEmpty, let snapData = savedSnapshotData {
            do {
                let parsed = try InstalledAppRegistryScanner(whitelistEngine: whitelistEngine).parseSnapshotData(snapData)
                registryRecords = parsed
                notices.append(WQLocale.pick(
                    en: "Loaded installed-app snapshot (\(parsed.count) app records)",
                    zh: "已加载已安装应用快照（共 \(parsed.count) 款应用记录）"
                ))
            } catch {
                notices.append(WQLocale.pick(
                    en: "Saved snapshot failed validation (\(error.localizedDescription)); continued with local engines",
                    zh: "已保存的应用快照校验失败（\(error.localizedDescription)），已继续执行本地扫描引擎"
                ))
            }
        }

        // Engine 2: Bound Signer Directories & Local Packages
        let packageFindings: [ScanFinding] = try await Task.detached(priority: .userInitiated) { [self] in
            let discovery = self.discoverAccessibleTargets(additionalLocations: additionalLocations)
            let urls = discovery.targets
            guard !urls.isEmpty else { return [] }

            var items: [ScanFinding] = []
            let total = urls.count
            var completed = 0
            for url in urls {
                try Task.checkCancellation()
                progressHandler?(ScanProgress(
                    currentTarget: url.lastPathComponent,
                    completedCount: completed,
                    totalCount: total
                ))
                let f = self.scanTargetOrEmitMalformedFinding(at: url)
                if let valid = f {
                    items.append(valid)
                }
                completed += 1
                progressHandler?(ScanProgress(
                    currentTarget: url.lastPathComponent,
                    completedCount: completed,
                    totalCount: total,
                    currentFinding: f
                ))
            }
            return items
        }.value

        // Engine 3: On-Device URL Scheme Probe
        let probeFindings: [ScanFinding]
        if enableOnDeviceProbe {
            probeFindings = await OnDeviceAppProbeScanner(whitelistEngine: whitelistEngine).probeInstalledAppsAsync()
        } else {
            probeFindings = []
        }

        let merged = correlateAndMergeFindings(
            registryRecords: registryRecords,
            packageFindings: packageFindings,
            probeFindings: probeFindings,
            includeAppStoreApps: includeAppStoreApps
        )

        #if os(iOS)
        if merged.findings.isEmpty {
            throw SecurityPipelineError.sandboxRestrictedNoAccessibleTargets
        }
        #endif

        return UnifiedInstalledScanResult(
            findings: merged.findings,
            liveRegistryConnected: liveConnected,
            registryEvaluatedCount: merged.registryCount,
            correlatedBinaryCount: merged.correlatedCount,
            probeDetectedCount: merged.probeCount,
            statusNotice: notices.isEmpty ? nil : notices.joined(separator: " · ")
        )
    }

    /// Synthesizes a fail-closed `.highRisk` `ScanFinding` whenever a discovered or batch-imported `.ipa` / `.tipa` / bundle
    /// fails structural validation (polyglot/corrupt ZIP headers, Zip-Slip / symlink traps, zip bombs, hollowed bundles, or corrupt Mach-O).
    public static func makeMalformedPackageFinding(for url: URL, error: Error) -> ScanFinding {
        let cleanPath = IPAPackageScanner.stripTrailingSlashes(url.path)
        let fileName = (cleanPath as NSString).lastPathComponent
        let rawStem = ((fileName as NSString).deletingPathExtension)
        let sanitizedStem = rawStem.unicodeScalars.map { s -> Character in
            let v = s.value
            if (v >= 0x41 && v <= 0x5A) || (v >= 0x61 && v <= 0x7A)
                || (v >= 0x30 && v <= 0x39) || v == 0x2E || v == 0x2D {
                return Character(s)
            }
            return "-"
        }
        let stemStr = String(sanitizedStem).trimmingCharacters(in: CharacterSet(charactersIn: ".-"))
        let safeBundleId = "malformed.package.\(stemStr.isEmpty ? "unknown" : stemStr)"

        let signatureTag: String
        let reasonEn: String
        let reasonZh: String

        if let ipaErr = error as? IPAPackageScannerError {
            switch ipaErr {
            case .zipSlipDetected(let item):
                signatureTag = "MalformedPackage:ZipSlipOrSymlink"
                reasonEn = "Hostile path traversal or symbolic-link trap detected in package ('\(item)')."
                reasonZh = "安装包或目录中检测到恶意的路径穿越 (Zip-Slip) 或符号链接陷阱 ('\(item)')。"
            case .quotaExceeded(let detail):
                signatureTag = "MalformedPackage:DecompressionOrSizeBomb"
                reasonEn = "Package exceeded extraction or size safety quota (possible zip bomb: \(detail))."
                reasonZh = "安装包超出解压或体积安全配额（疑似压缩炸弹: \(detail)）。"
            case .corruptHeader(let detail):
                signatureTag = "MalformedPackage:CorruptArchiveHeader"
                reasonEn = "Corrupted or polyglot ZIP/IPA header detected (\(detail))."
                reasonZh = "检测到损坏或畸形拼接 (Polyglot) 的 ZIP/IPA 头部结构 (\(detail))。"
            case .endOfCentralDirectoryNotFound:
                signatureTag = "MalformedPackage:MissingOrTruncatedEOCD"
                reasonEn = "Archive is missing a valid ZIP End of Central Directory (truncated or non-ZIP payload)."
                reasonZh = "归档包缺失合法的 ZIP 核心目录结束标记 (EOCD)，文件已被截断或伪装后缀。"
            case .unsupportedCompressionMethod(let method):
                signatureTag = "MalformedPackage:UnsupportedCompressionMethod"
                reasonEn = "Archive uses non-standard compression method (ID: \(method)) to evade static extraction."
                reasonZh = "归档包使用了非标准压缩算法 (ID: \(method))，可能试图规避静态解压审查。"
            case .encryptedArchiveNotSupported:
                signatureTag = "MalformedPackage:PasswordEncryptedArchive"
                reasonEn = "Password-encrypted ZIP/IPA archive conceals payload contents from static inspection."
                reasonZh = "加密带密码的 ZIP/IPA 压缩包阻断了静态载荷审查。"
            case .decompressionFailed(let code):
                signatureTag = "MalformedPackage:DecompressionStreamCorrupt"
                reasonEn = "Deflate stream failed integrity verification during extraction (zlib code: \(code))."
                reasonZh = "解压流完整性校验失败（zlib 错误码: \(code)）。"
            case .invalidArchive(let detail):
                signatureTag = "MalformedPackage:InvalidOrTamperedArchive"
                reasonEn = "Structurally tampered or non-standard package archive (\(detail))."
                reasonZh = "检测到结构篡改或非标准的归档包（如多 .app 夹带或非普通文件: \(detail)）。"
            case .missingPayload, .missingAppBundle:
                signatureTag = "MalformedPackage:MissingPayload"
                reasonEn = "Archive is missing a valid Payload/*.app structure."
                reasonZh = "归档包缺失合法的 Payload/*.app 目录结构。"
            case .invalidInfoPlist(let detail):
                signatureTag = "MalformedPackage:InvalidInfoPlist"
                reasonEn = "Bundle Info.plist is missing, tampered, or unparseable (\(detail))."
                reasonZh = "应用包 Info.plist 缺失、被篡改或无法解析 (\(detail))。"
            case .missingExecutable(let detail):
                signatureTag = "MalformedPackage:MissingExecutable"
                reasonEn = "Declared bundle executable is missing or outside bundle bounds (\(detail))."
                reasonZh = "声明的主可执行文件缺失或越界 (\(detail))。"
            case .fileNotFound(let detail):
                signatureTag = "MalformedPackage:UnreadableTarget"
                reasonEn = "Target package could not be opened safely (\(detail))."
                reasonZh = "无法安全打开目标包文件 (\(detail))。"
            }
        } else if error is MachOParserError {
            signatureTag = "MalformedPackage:CorruptMachO"
            reasonEn = "Bundle executable contains a malformed or anti-analysis Mach-O header (\(error.localizedDescription))."
            reasonZh = "主可执行文件包含畸形或抗分析篡改的 Mach-O 头部结构 (\(error.localizedDescription))。"
        } else {
            signatureTag = "MalformedPackage:TamperedOrUnparseable"
            reasonEn = "Package failed static security verification (\(error.localizedDescription))."
            reasonZh = "目标包静态安全校验失败 (\(error.localizedDescription))。"
        }

        let indicator = ThreatIndicator(
            signature: signatureTag,
            description: WQLocale.pick(en: reasonEn, zh: reasonZh),
            category: "Malformed / Hostile Package",
            location: fileName,
            severity: .highRisk
        )

        let evidence = AuditEvidence(
            matchedSymbols: [signatureTag],
            linkedDylibs: [],
            hasAppGroups: false,
            appGroups: [],
            installChannel: .developerSideloaded,
            cryptid: 0,
            isFairPlayEncrypted: false,
            escapingSymlinks: signatureTag == "MalformedPackage:ZipSlipOrSymlink" ? [cleanPath] : [],
            dynamicLoadingPresent: false,
            pathEnumerationPresent: false,
            remediationGuidance: WQLocale.pick(
                en: "Malformed, tampered, or symlink-trapped packages frequently conceal exploit payloads or evade static parsers. Delete this file immediately and do NOT install it.",
                zh: "畸形、结构篡改或包含符号链接陷阱的安装包常被用于隐藏恶意载荷或绕过静态解析器，请立即删除该文件，严禁安装。"
            ),
            auditDepth: .fullBinaryAndRegistry,
            isWhitelistEligible: false,
            isTeamIdWhitelistVerified: false
        )

        return ScanFinding(
            bundleId: safeBundleId,
            displayName: fileName,
            version: "0.0",
            teamId: nil,
            executablePath: cleanPath,
            bundlePath: cleanPath,
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: [indicator],
            evidence: evidence,
            scanTimestamp: Date()
        )
    }

    private static func isSystemBundleContainerPath(_ path: String) -> Bool {
        path.hasPrefix("/var/containers/Bundle/Application/")
            || path.hasPrefix("/private/var/containers/Bundle/Application/")
            || path.hasPrefix("/var/mobile/Containers/Bundle/Application/")
    }

    private func scanTargetOrEmitMalformedFinding(at url: URL) -> ScanFinding? {
        let cleanPath = IPAPackageScanner.stripTrailingSlashes(url.path)
        let ext = url.pathExtension.lowercased()
        do {
            if ext == "ipa" || ext == "tipa" {
                return try self.scanIPA(at: url)
            } else {
                return try self.scanBundle(at: url)
            }
        } catch {
            // Skip ONLY if the entry genuinely disappeared (ENOENT/ENOTDIR on lstat) or hit OS sandbox EACCES/EPERM in system containers
            var lst = stat()
            if lstat(cleanPath, &lst) != 0 {
                let errCode = errno
                if errCode == ENOENT || errCode == ENOTDIR {
                    return nil
                }
                if (errCode == EACCES || errCode == EPERM) && Self.isSystemBundleContainerPath(cleanPath) {
                    return nil
                }
            } else if Self.isSystemBundleContainerPath(cleanPath) {
                let nsErr = error as NSError
                if nsErr.code == NSFileReadNoPermissionError || nsErr.code == Int(EACCES) || nsErr.code == Int(EPERM) {
                    return nil
                }
            }
            return Self.makeMalformedPackageFinding(for: url, error: error)
        }
    }
    
    /// Discovers readable self-signed/sideloaded `.app` bundles and `.ipa`/`.app` packages in Documents & bookmarked signing folders.
    private func discoverAccessibleTargets(additionalLocations: [URL] = []) -> (targets: [URL], permissionDeniedCount: Int) {
        var targets: [URL] = []
        var seenCanonicalPaths: Set<String> = []
        var permissionDeniedCount = 0
        let fm = FileManager.default
        
        #if os(iOS)
        let selfBundleCanonical = Bundle.main.bundleURL.resolvingSymlinksInPath().path
        #else
        let selfBundleCanonical = ""
        #endif
        
        func isSelfSignedOrSideloadedBundle(_ appURL: URL) -> Bool {
            let cleanAppPath = IPAPackageScanner.stripTrailingSlashes(appURL.path)
            var appLst = stat()
            guard lstat(cleanAppPath, &appLst) == 0 else {
                return false
            }
            let appMode = appLst.st_mode & S_IFMT
            if appMode == S_IFLNK {
                return true
            }
            guard appMode == S_IFDIR else {
                return false
            }

            // 1. Check embedded.mobileprovision via lstat (present on all developer/personal self-signed & enterprise apps)
            let provPath = (cleanAppPath as NSString).appendingPathComponent("embedded.mobileprovision")
            var provLst = stat()
            if lstat(provPath, &provLst) == 0 {
                return true
            }

            // 2. Read Info.plist strictly with O_NOFOLLOW; missing/symlink/corrupt Info.plist cannot be an official App Store bundle
            let infoURL = URL(fileURLWithPath: cleanAppPath, isDirectory: true).appendingPathComponent("Info.plist")
            guard let pData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: infoURL, maxBytes: 8 * 1024 * 1024),
                  let dict = (try? PropertyListSerialization.propertyList(from: pData, options: [], format: nil)) as? [String: Any] else {
                return true
            }

            // 3. Inspect ALL slices, partial FairPlay, and code-signature trust on the main executable with O_NOFOLLOW
            let fallbackName = (dict["CFBundleDisplayName"] as? String)
                ?? (dict["CFBundleName"] as? String)
                ?? appURL.deletingPathExtension().lastPathComponent
            guard let (_, execURL) = try? IPAPackageScanner.resolveSafeBundleExecutableURL(
                infoDict: dict,
                bundleURL: URL(fileURLWithPath: cleanAppPath, isDirectory: true),
                fallbackName: fallbackName
            ),
            let binData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: execURL),
            let slices = try? MachOParser.shared.parseAllSlices(data: binData),
            !slices.isEmpty else {
                return true
            }

            let details = self.machoScanner.parseMachO(
                files: slices,
                rawData: binData,
                expectedContainerSliceCount: slices.first?.slicesInContainer.count
            )
            if !details.isFairPlayEncrypted || details.hasUnencryptedSegments || details.corruptedSliceCount > 0 {
                return true
            }
            let auditSlices = MachOParser.selectAuditSlices(from: slices)
            if auditSlices.contains(where: { !$0.isFairPlayEncrypted || $0.hasForgedPlaintextFairPlayRange }) {
                return true
            }
            let sigTrust = CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: slices)
            if sigTrust != .appleAppStoreVerified || CSBlobParser.hasMissingCodeSignature(inSlices: slices) {
                return true
            }
            if CSBlobParser.shared.verifyBundleInfoPlistBinding(
                fromSlices: slices,
                infoPlistData: pData,
                plistBundleId: dict["CFBundleIdentifier"] as? String
            ) != nil {
                return true
            }

            let appRootURL = URL(fileURLWithPath: cleanAppPath, isDirectory: true)
            if CSBlobParser.shared.verifyBundleCodeResourcesSeal(
                fromSlices: slices,
                bundleURL: appRootURL
            ) != nil {
                return true
            }

            // 4. Inspect ALL candidate files across the entire bundle (including `Frameworks`, `Dylibs`, `DynamicLibraries`,
            //    `PlugIns`, `Extensions`, `XPCServices`, `AppClips`, `Watch`, root `*.dylib`, and disguised Mach-Os) so
            //    dylib-injection or plugin-hijack attacks on an otherwise untouched App Store main binary are never skipped
            let appResolved = IPAPackageScanner.lexicalStandardizedPath(appRootURL.resolvingSymlinksInPath().path)
            let appResolvedPrefix = IPAPackageScanner.lexicalStandardizedPrefix(appResolved)
            let mainExecCanonical = IPAPackageScanner.lexicalStandardizedPath(execURL.path)
            let mainExecResolved = IPAPackageScanner.lexicalStandardizedPath(execURL.resolvingSymlinksInPath().path)
            var subEscapes: [String] = []
            let candidates = IPAPackageScanner.enumerateCandidateFiles(
                in: appRootURL,
                bundleRootResolvedPrefix: appResolvedPrefix,
                escapingSymlinks: &subEscapes,
                bundleRootURL: appRootURL
            )
            if !subEscapes.isEmpty {
                return true
            }
            for cand in candidates {
                let itemCanonical = IPAPackageScanner.lexicalStandardizedPath(cand.logicalURL.path)
                if itemCanonical == mainExecCanonical
                    || itemCanonical == mainExecResolved
                    || IPAPackageScanner.lexicalStandardizedPath(cand.readURL.path) == mainExecResolved {
                    continue
                }
                if cand.logicalURL.lastPathComponent.lowercased() == "embedded.mobileprovision" {
                    return true
                }
                let isRole = IPAPackageScanner.isExpectedEmbeddedBinaryRole(
                    itemURL: cand.logicalURL,
                    bundleRootResolvedPrefix: appResolvedPrefix
                )
                let (pfx, fsz) = IPAPackageScanner.readMachOHeaderPrefix(of: cand.readURL)
                guard isRole || IPAPackageScanner.isMachOOrFatMagic(pfx, fileSize: fsz) else { continue }
                guard let subData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: cand.readURL),
                      let subSlices = try? MachOParser.shared.parseAllSlices(data: subData),
                      !subSlices.isEmpty else {
                    return true
                }
                let subAudit = MachOParser.selectAuditSlices(from: subSlices)
                if subAudit.contains(where: { $0.hasForgedPlaintextFairPlayRange }) {
                    return true
                }
                if CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: subSlices) != .appleAppStoreVerified
                    || CSBlobParser.hasMissingCodeSignature(inSlices: subSlices) {
                    return true
                }
                let subParent = cand.logicalURL.deletingLastPathComponent()
                let subGrandParent = subParent.deletingLastPathComponent()
                let fwRoot: URL?
                if subParent.pathExtension.lowercased() == "framework" {
                    fwRoot = subParent
                } else if subGrandParent.lastPathComponent.lowercased() == "versions" &&
                          subGrandParent.deletingLastPathComponent().pathExtension.lowercased() == "framework" {
                    fwRoot = subGrandParent.deletingLastPathComponent()
                } else {
                    fwRoot = nil
                }
                if let fwRoot,
                   CSBlobParser.shared.verifyBundleCodeResourcesSeal(fromSlices: subSlices, bundleURL: fwRoot) != nil {
                    return true
                }
            }
            return false
        }
        
        func appendUnique(_ url: URL, requireSelfSignedCheck: Bool = false) {
            let cleanPath = IPAPackageScanner.stripTrailingSlashes(url.path)
            guard !cleanPath.isEmpty else { return }
            var lst = stat()
            let isSymlink = (lstat(cleanPath, &lst) == 0) && ((lst.st_mode & S_IFMT) == S_IFLNK)
            let dedupKey = isSymlink ? "symlink:\(cleanPath)" : url.resolvingSymlinksInPath().path
            guard !dedupKey.isEmpty, dedupKey != selfBundleCanonical else { return }
            if requireSelfSignedCheck && url.pathExtension.lowercased() == "app" {
                guard isSelfSignedOrSideloadedBundle(url) else { return }
            }
            if seenCanonicalPaths.insert(dedupKey).inserted {
                targets.append(isSymlink ? URL(fileURLWithPath: cleanPath) : url)
            }
        }
        
        let searchRoots: [String] = [
            "/var/containers/Bundle/Application",
            "/private/var/containers/Bundle/Application",
            "/var/mobile/Containers/Bundle/Application"
        ]
        
        for root in searchRoots {
            let rootURL = URL(fileURLWithPath: root, isDirectory: true)
            do {
                let contents = try fm.contentsOfDirectory(at: rootURL, includingPropertiesForKeys: [.isDirectoryKey])
                for item in contents {
                    if item.pathExtension.lowercased() == "app" {
                        appendUnique(item, requireSelfSignedCheck: true)
                    } else if item.hasDirectoryPath {
                        if let subContents = try? fm.contentsOfDirectory(at: item, includingPropertiesForKeys: nil) {
                            for sub in subContents where sub.pathExtension.lowercased() == "app" {
                                appendUnique(sub, requireSelfSignedCheck: true)
                            }
                        }
                    }
                }
            } catch {
                let nsError = error as NSError
                if nsError.code == NSFileReadNoPermissionError ||
                   nsError.code == Int(EPERM) ||
                   nsError.code == Int(EACCES) {
                    permissionDeniedCount += 1
                }
            }
        }
        
        func scanUserDirectory(_ dirURL: URL) {
            let cleanDirPath = IPAPackageScanner.stripTrailingSlashes(dirURL.path)
            let ext = dirURL.pathExtension.lowercased()
            if ext == "ipa" || ext == "tipa" || ext == "app" || ext == "appex" || ext == "xpc" || ext == "framework" || ext == "xcframework" || ext == "bundle" {
                appendUnique(dirURL, requireSelfSignedCheck: false)
                return
            }
            var dirLst = stat()
            guard lstat(cleanDirPath, &dirLst) == 0, (dirLst.st_mode & S_IFMT) == S_IFDIR else {
                return
            }

            let rootInfoPath = (cleanDirPath as NSString).appendingPathComponent("Info.plist")
            var rootInfoLst = stat()
            let rootIsExtensionlessBundle = (lstat(rootInfoPath, &rootInfoLst) == 0)
            if rootIsExtensionlessBundle {
                appendUnique(dirURL, requireSelfSignedCheck: false)
                // Do NOT return early: continue walking with POSIX readdir so `.ipa`/`.tipa` archives in `Documents/`
                // or signer folders can never be hidden behind a decoy `Info.plist` or hidden from CFURLEnumerator as `._*`.
            }

            var visitedCount = 0
            let maxVisited = 20_000
            let maxDepth = 16

            func walkNoFollow(currentDirPath: String, depth: Int, insideExtensionlessBundle: Bool) {
                guard depth <= maxDepth, visitedCount < maxVisited, let dp = opendir(currentDirPath) else { return }
                defer { closedir(dp) }

                var entryNames: [String] = []
                while let ent = readdir(dp) {
                    let name = withUnsafeBytes(of: ent.pointee.d_name) { raw -> String in
                        String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                    }
                    if name != "." && name != ".." && name != ".DS_Store" {
                        entryNames.append(name)
                    }
                }
                entryNames.sort()

                for name in entryNames {
                    if visitedCount >= maxVisited { break }
                    visitedCount += 1
                    let childPath = (currentDirPath as NSString).appendingPathComponent(name)
                    let childURL = URL(fileURLWithPath: childPath)
                    var cst = stat()
                    guard lstat(childPath, &cst) == 0 else { continue }
                    let mode = cst.st_mode & S_IFMT
                    let fExt = childURL.pathExtension.lowercased()

                    if name == ".git" && mode == S_IFDIR {
                        var gitHeadLst = stat()
                        if lstat((childPath as NSString).appendingPathComponent("HEAD"), &gitHeadLst) == 0 {
                            continue
                        }
                    }
                    if name.hasPrefix("._") && mode == S_IFREG && IPAPackageScanner.isGenuineAppleDoubleMetadataFile(at: childURL) {
                        continue
                    }

                    let isArchiveExt = (fExt == "ipa" || fExt == "tipa")
                    let isBundleExt = (fExt == "app" || fExt == "appex" || fExt == "xpc" || fExt == "framework" || fExt == "xcframework")

                    if mode == S_IFLNK {
                        if isArchiveExt || (isBundleExt && !insideExtensionlessBundle) {
                            appendUnique(childURL, requireSelfSignedCheck: false)
                        }
                        continue
                    }

                    if isArchiveExt {
                        appendUnique(childURL, requireSelfSignedCheck: false)
                    } else if mode == S_IFDIR && isBundleExt {
                        if !insideExtensionlessBundle {
                            appendUnique(childURL, requireSelfSignedCheck: false)
                        }
                    } else if mode == S_IFDIR && fExt != "bundle" {
                        var childIsExtensionless = insideExtensionlessBundle
                        if !insideExtensionlessBundle {
                            let subInfo = (childPath as NSString).appendingPathComponent("Info.plist")
                            var subInfoLst = stat()
                            if lstat(subInfo, &subInfoLst) == 0 {
                                appendUnique(childURL, requireSelfSignedCheck: false)
                                childIsExtensionless = true
                            }
                        }
                        walkNoFollow(currentDirPath: childPath, depth: depth + 1, insideExtensionlessBundle: childIsExtensionless)
                    }
                }
            }

            walkNoFollow(currentDirPath: cleanDirPath, depth: 0, insideExtensionlessBundle: rootIsExtensionlessBundle)
        }
        
        #if os(iOS)
        // Inspect WQGuard's own Documents & Documents/Inbox folders
        if let docsURL = fm.urls(for: .documentDirectory, in: .userDomainMask).first {
            scanUserDirectory(docsURL)
        }
        #endif
        
        // Inspect any user-authorized signing tool directories (e.g. SideStore / AltStore / Feather / Downloads)
        for loc in additionalLocations {
            scanUserDirectory(loc)
        }
        
        return (targets, permissionDeniedCount)
    }
    
    /// Scans all installed self-signed applications across accessible directories.
    public func scanInstalledApps() throws -> [ScanFinding] {
        let discovery = discoverAccessibleTargets()
        #if os(iOS)
        if discovery.targets.isEmpty && discovery.permissionDeniedCount > 0 {
            throw SecurityPipelineError.sandboxRestrictedNoAccessibleTargets
        }
        #endif
        
        var findings: [ScanFinding] = []
        for targetURL in discovery.targets {
            if let finding = scanTargetOrEmitMalformedFinding(at: targetURL) {
                findings.append(finding)
            }
        }
        return findings
    }
    
    /// Scans shared App Group containers for escaping symlinks (Layer 3).
    public func scanSharedContainers() throws -> [ThreatIndicator] {
        var indicators: [ThreatIndicator] = []
        let sharedRoots = [
            "/var/mobile/Containers/Shared/AppGroup",
            "/private/var/mobile/Containers/Shared/AppGroup"
        ]
        
        let fm = FileManager.default
        for root in sharedRoots where fm.fileExists(atPath: root) {
            let rootURL = URL(fileURLWithPath: root)
            if let results = try? containerScanner.scanAppGroupContainers(at: rootURL) {
                for res in results {
                    indicators.append(contentsOf: res.indicators)
                }
            }
        }
        return indicators
    }
    
    // MARK: - Asynchronous Non-Blocking APIs with Progress Callbacks
    
    /// Asynchronously scans self-signed / sideloaded applications with live progress updates.
    public func scanInstalledAppsAsync(
        additionalLocations: [URL] = [],
        progressHandler: (@Sendable (ScanProgress) -> Void)? = nil
    ) async throws -> [ScanFinding] {
        return try await Task.detached(priority: .userInitiated) { [self] in
            let discovery = self.discoverAccessibleTargets(additionalLocations: additionalLocations)
            #if os(iOS)
            if discovery.targets.isEmpty && discovery.permissionDeniedCount > 0 {
                throw SecurityPipelineError.sandboxRestrictedNoAccessibleTargets
            }
            #endif
            
            let targetURLs = discovery.targets
            let total = targetURLs.count
            var completed = 0
            var results: [ScanFinding] = []
            
            for url in targetURLs {
                try Task.checkCancellation()
                progressHandler?(ScanProgress(
                    currentTarget: url.lastPathComponent,
                    completedCount: completed,
                    totalCount: total,
                    currentFinding: nil
                ))
                let finding = self.scanTargetOrEmitMalformedFinding(at: url)
                if let f = finding {
                    results.append(f)
                }
                completed += 1
                progressHandler?(ScanProgress(
                    currentTarget: url.lastPathComponent,
                    completedCount: completed,
                    totalCount: total,
                    currentFinding: finding
                ))
            }
            return results
        }.value
    }
    
    /// Creates a complete ScanSession asynchronously with progress reporting.
    public func createScanSessionAsync(
        targets: [URL]? = nil,
        progressHandler: (@Sendable (ScanProgress) -> Void)? = nil
    ) async throws -> ScanSession {
        let findings: [ScanFinding]
        if let specificTargets = targets {
            var items: [ScanFinding] = []
            var count = 0
            for url in specificTargets {
                let f: ScanFinding
                let ext = url.pathExtension.lowercased()
                if ext == "ipa" || ext == "tipa" {
                    f = try self.scanIPA(at: url)
                } else if ext == "app" || ext == "appex" || ext == "xpc" || ext == "framework" || ext == "xcframework" || ext == "bundle" {
                    f = try self.scanBundle(at: url)
                } else {
                    f = try self.scanBinary(at: url)
                }
                items.append(f)
                count += 1
                progressHandler?(ScanProgress(
                    currentTarget: url.lastPathComponent,
                    completedCount: count,
                    totalCount: specificTargets.count,
                    currentFinding: f
                ))
            }
            findings = items
        } else {
            findings = try await scanInstalledAppsAsync(progressHandler: progressHandler)
        }
        
        return ScanSession(findings: findings)
    }
}
