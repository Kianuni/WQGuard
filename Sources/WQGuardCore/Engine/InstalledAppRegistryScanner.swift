//
//  InstalledAppRegistryScanner.swift
//  WQGuardCore
//
//  Option 1 Engine: Parses iOS `com.apple.mobile.installation_proxy` installed application
//  registry records (from live Lockdown pairing connection or exported `.plist`/`.xml`/`.json`
//  snapshots) and performs full Entitlements, App Group, SignerIdentity, TCC bypass, and
//  Wallet/Messenger Impersonation security audits across all installed apps.
//

import Foundation

public enum InstalledAppRegistryError: Error, LocalizedError, Sendable, Equatable {
    case fileNotFound(String)
    case invalidSnapshotFormat(String)
    case emptyApplicationList

    public var errorDescription: String? {
        switch self {
        case .fileNotFound(let path):
            return WQLocale.pick(
                en: "Installed-app snapshot file not found: \(path)",
                zh: "未找到已安装应用快照文件: \(path)"
            )
        case .invalidSnapshotFormat(let detail):
            return WQLocale.pick(
                en: "Unable to parse installed-app snapshot format (\(detail)). Import a valid Xcode devicectl (.json), pymobiledevice3 (.json), or installation_proxy (.plist/.xml) file.",
                zh: "无法解析已安装应用快照格式 (\(detail))。请导入有效的 Xcode devicectl (.json)、pymobiledevice3 (.json) 或 installation_proxy (.plist/.xml) 文件。"
            )
        case .emptyApplicationList:
            return WQLocale.pick(
                en: "Installed application registry is empty; no app records found.",
                zh: "已安装应用注册表为空，未读取到任何应用记录。"
            )
        }
    }
}

/// Strongly-typed, `Sendable` representation of an installed iOS application from `installation_proxy`.
public struct InstalledAppRegistryRecord: Codable, Sendable, Equatable, Identifiable {
    public var id: String { bundleId }
    public let bundleId: String
    public let displayName: String
    public let version: String
    public let applicationType: String
    public let signerIdentity: String?
    public let profileValidated: Bool
    public let hasAppStoreMetadata: Bool
    public let teamId: String?
    public let appGroups: [String]
    public let keychainAccessGroups: [String]
    public let tccAllowedServices: [String]
    public let booleanEntitlements: [String: Bool]
    public let stringEntitlements: [String: String]
    public let allEntitlementKeys: [String]
    public let backgroundModes: [String]
    public let bundlePath: String
    public let containerPath: String?

    public init(
        bundleId: String,
        displayName: String,
        version: String,
        applicationType: String = "User",
        signerIdentity: String? = nil,
        profileValidated: Bool = false,
        hasAppStoreMetadata: Bool = false,
        teamId: String? = nil,
        appGroups: [String] = [],
        keychainAccessGroups: [String] = [],
        tccAllowedServices: [String] = [],
        booleanEntitlements: [String: Bool] = [:],
        stringEntitlements: [String: String] = [:],
        allEntitlementKeys: [String] = [],
        backgroundModes: [String] = [],
        bundlePath: String = "",
        containerPath: String? = nil
    ) {
        self.bundleId = bundleId
        self.displayName = displayName
        self.version = version
        self.applicationType = applicationType
        self.signerIdentity = signerIdentity
        self.profileValidated = profileValidated
        self.hasAppStoreMetadata = hasAppStoreMetadata
        self.teamId = teamId
        self.appGroups = appGroups
        self.keychainAccessGroups = keychainAccessGroups
        self.tccAllowedServices = tccAllowedServices
        self.booleanEntitlements = booleanEntitlements
        self.stringEntitlements = stringEntitlements
        self.allEntitlementKeys = allEntitlementKeys
        self.backgroundModes = backgroundModes
        self.bundlePath = bundlePath
        self.containerPath = containerPath
    }

    /// Parses a single dictionary emitted by `com.apple.mobile.installation_proxy` or `pymobiledevice3`.
    public static func fromDictionary(_ dict: [String: Any], fallbackBundleId: String? = nil) -> InstalledAppRegistryRecord? {
        let rawBid = (dict["CFBundleIdentifier"] as? String) ?? fallbackBundleId ?? ""
        let bundleId = rawBid.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !bundleId.isEmpty else { return nil }

        let displayName = (dict["CFBundleDisplayName"] as? String)
            ?? (dict["CFBundleName"] as? String)
            ?? (dict["CFBundleExecutable"] as? String)
            ?? bundleId

        let version = (dict["CFBundleShortVersionString"] as? String)
            ?? (dict["CFBundleVersion"] as? String)
            ?? "1.0"

        let appType = (dict["ApplicationType"] as? String) ?? "User"
        let signerIdentity = dict["SignerIdentity"] as? String
        let profileValidated = (dict["ProfileValidated"] as? Bool == true)
            || (dict["UPPValidated"] as? Bool == true)
            || (dict["FreeProfileValidated"] as? Bool == true)

        // App Store / TestFlight packages carry ApplicationDSID / iTunesMetadata or Apple App Store signing identity without provisioning profile
        let hasDSID: Bool = {
            if let dsidNum = dict["ApplicationDSID"] as? NSNumber {
                return dsidNum.int64Value > 0
            }
            if let dsidStr = dict["ApplicationDSID"] as? String, !dsidStr.isEmpty, dsidStr != "0" {
                return true
            }
            return false
        }()
        let hasITunesMeta = dict["iTunesMetadata"] != nil
            || (dict["IsAppStoreVendable"] as? Bool == true)
            || (dict["HasMIDBasedSINF"] as? Bool == true)
        let isAppleStoreSigner = (signerIdentity == "Apple iPhone OS Application Signing") && !profileValidated
        let hasAppStoreMetadata = hasDSID || hasITunesMeta || isAppleStoreSigner

        let entDict = (dict["Entitlements"] as? [String: Any]) ?? [:]
        let numericBoolKeys: Set<String> = [
            "beta-reports-active",
            "get-task-allow",
            "com.apple.private.security.no-container",
            "com.apple.private.security.no-sandbox",
            "com.apple.private.security.container-required",
            "com.apple.private.MobileContainerManager.allowed",
            "com.apple.private.security.storage.AppDataContainers",
            "platform-application"
        ]
        var boolEnts: [String: Bool] = [:]
        var strEnts: [String: String] = [:]
        func parseIntegerBool(_ value: Any) -> Bool? {
            if let i = value as? Int { return i != 0 }
            if let i64 = value as? Int64 { return i64 != 0 }
            if let u64 = value as? UInt64 { return u64 != 0 }
            if let i32 = value as? Int32 { return i32 != 0 }
            if let num = value as? NSNumber {
                return num.int64Value != 0 || num.doubleValue != 0.0
            }
            return nil
        }
        func extractTrimmedStrings(_ raw: Any?) -> [String] {
            guard let raw else { return [] }
            if let arr = raw as? [String] {
                return arr.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            }
            if let anyArr = raw as? [Any] {
                return anyArr.compactMap { $0 as? String }
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
            }
            if let single = raw as? String {
                let trimmed = single.trimmingCharacters(in: .whitespacesAndNewlines)
                return trimmed.isEmpty ? [] : [trimmed]
            }
            return []
        }

        let collectionCapableEscapeKeys: Set<String> = [
            "com.apple.private.MobileContainerManager.allowed",
            "com.apple.private.security.storage.AppDataContainers"
        ]
        for (k, v) in entDict {
            let isRestrictedNumericBool = numericBoolKeys.contains(k)
                || InstalledAppRegistryScanner.matchesRestricted2026PrivateEntitlementPrefix(k)
                || k.hasPrefix(ExpandedThreatCatalog.photosEntitlementPrefix)
                || k == ExpandedThreatCatalog.photosBourgeoisieEntitlement
            if let b = v as? Bool {
                boolEnts[k] = b
            } else if let num = v as? NSNumber, CFGetTypeID(num) == CFBooleanGetTypeID() {
                boolEnts[k] = num.boolValue
            } else if isRestrictedNumericBool, let parsed = parseIntegerBool(v) {
                boolEnts[k] = parsed
            } else if collectionCapableEscapeKeys.contains(k), !extractTrimmedStrings(v).isEmpty {
                boolEnts[k] = true
            } else if let s = v as? String {
                strEnts[k] = s
            }
        }

        let appGroups = extractTrimmedStrings(entDict["com.apple.security.application-groups"])
        let keychainGroups = extractTrimmedStrings(entDict["keychain-access-groups"])

        var tccServices: [String] = []
        for tccKey in ["com.apple.private.tcc.allow", "com.apple.private.tcc.allow-prompting"] {
            guard let rawTCC = entDict[tccKey] else { continue }
            let extracted = extractTrimmedStrings(rawTCC)
            if !extracted.isEmpty {
                tccServices.append(contentsOf: extracted)
            } else if (rawTCC as? Bool == true) || (parseIntegerBool(rawTCC) == true) {
                tccServices.append(tccKey)
            }
        }

        var teamId = strEnts["com.apple.developer.team-identifier"]
            ?? (dict["TeamIdentifier"] as? String)
        if teamId == nil, let appId = strEnts["application-identifier"],
           let dotIdx = appId.firstIndex(of: ".") {
            let prefix = String(appId[..<dotIdx])
            let isStrictASCIITeam = prefix.count == 10 && prefix.utf8.allSatisfy { b in
                (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39)
            }
            if isStrictASCIITeam {
                teamId = prefix.uppercased()
            }
        }

        let bgModes = extractTrimmedStrings(dict["UIBackgroundModes"])
        let nonEmptyPath: (Any?) -> String? = { raw in
            guard let s = raw as? String, !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
            return s
        }
        let bundlePath = nonEmptyPath(dict["Path"])
            ?? nonEmptyPath(dict["BundlePath"])
            ?? "/var/containers/Bundle/Application/\(bundleId)"
        let containerPath = dict["Container"] as? String

        return InstalledAppRegistryRecord(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            applicationType: appType,
            signerIdentity: signerIdentity,
            profileValidated: profileValidated,
            hasAppStoreMetadata: hasAppStoreMetadata,
            teamId: teamId,
            appGroups: appGroups,
            keychainAccessGroups: keychainGroups,
            tccAllowedServices: Array(Set(tccServices)).sorted(),
            booleanEntitlements: boolEnts,
            stringEntitlements: strEnts,
            allEntitlementKeys: Array(entDict.keys).sorted(),
            backgroundModes: bgModes,
            bundlePath: bundlePath,
            containerPath: containerPath
        )
    }

    /// Parses a single item from Apple Xcode `xcrun devicectl device info apps --json-output` (`result.apps[]`).
    public static func fromDeviceCtlDictionary(_ dict: [String: Any]) -> InstalledAppRegistryRecord? {
        guard let rawBid = dict["bundleIdentifier"] as? String else { return nil }
        let bundleId = rawBid.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !bundleId.isEmpty else { return nil }

        let displayName = (dict["name"] as? String) ?? bundleId
        let version = (dict["version"] as? String)
            ?? (dict["bundleVersion"] as? String)
            ?? "1.0"

        let isDefaultApp = (dict["defaultApp"] as? Bool) ?? false
        let isInternalApp = (dict["internalApp"] as? Bool) ?? false
        let builtByDeveloper = (dict["builtByDeveloper"] as? Bool) ?? false

        let explicitSignerRaw = (dict["signerIdentity"] as? String)
            ?? (dict["SignerIdentity"] as? String)
        let explicitProfileValidated: Bool? = {
            if let pv = dict["profileValidated"] as? Bool { return pv }
            if let pv = dict["ProfileValidated"] as? Bool { return pv }
            if dict["UPPValidated"] as? Bool == true || dict["FreeProfileValidated"] as? Bool == true { return true }
            if dict["provisioningProfile"] != nil { return true }
            return nil
        }()
        let rawURLString = dict["url"] as? String
        let rawContainerString = dict["bundleContainerPath"] as? String
        let containerPathCandidate = rawContainerString?.trimmingCharacters(in: .whitespacesAndNewlines)
        var hasNonLocalFileURL = false
        let rawBundlePath: String = {
            if let urlStr = rawURLString, !urlStr.isEmpty {
                let hasLeadingOrTrailingWhitespace = (urlStr.trimmingCharacters(in: .whitespacesAndNewlines) != urlStr)
                let hasLiteralControlChar = InstalledAppRegistryScanner.containsASCIIControlCharacter(urlStr)
                if !hasLeadingOrTrailingWhitespace && !hasLiteralControlChar {
                    if let u = URL(string: urlStr), u.isFileURL {
                        let host = u.host
                        let isLocalHost = (host == nil
                            || host?.isEmpty == true
                            || host?.caseInsensitiveCompare("localhost") == .orderedSame)
                            && u.user == nil
                            && u.password == nil
                            && u.port == nil
                        if !isLocalHost || u.path.isEmpty || !u.path.hasPrefix("/") {
                            hasNonLocalFileURL = true
                            return urlStr
                        }
                        return u.path
                    }
                    if urlStr.lowercased().hasPrefix("file://") {
                        let dropped = String(urlStr.dropFirst("file://".count))
                        if dropped.hasPrefix("/") {
                            return dropped
                        }
                        if dropped.lowercased().hasPrefix("localhost/") {
                            return String(dropped.dropFirst("localhost".count))
                        }
                    }
                }
                hasNonLocalFileURL = true
                return urlStr
            }
            if let container = containerPathCandidate, !container.isEmpty {
                return container
            }
            return isDefaultApp ? "/Applications/\(bundleId).app" : "/var/containers/Bundle/Application/\(bundleId)"
        }()
        let resolvedBundlePath = InstalledAppRegistryScanner.standardizedAbsolutePath(rawBundlePath)
        let lowerBundlePath = resolvedBundlePath.lowercased()

        let rawHazards = InstalledAppRegistryScanner.inspectPathHazards(rawBundlePath)
        let urlRawHazards: InstalledAppRegistryScanner.PathHazardFlags? = {
            guard let urlStr = rawURLString,
                  !urlStr.isEmpty else {
                return nil
            }
            if urlStr == rawBundlePath {
                return rawHazards
            }
            return InstalledAppRegistryScanner.inspectPathHazards(urlStr)
        }()
        let containerHazards = rawContainerString.flatMap { rawContainer -> InstalledAppRegistryScanner.PathHazardFlags? in
            let rawInspect = InstalledAppRegistryScanner.inspectPathHazards(rawContainer)
            if rawInspect.hasAny {
                return rawInspect
            }
            let trimmed = rawContainer.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed != rawBundlePath else { return nil }
            return InstalledAppRegistryScanner.inspectPathHazards(trimmed)
        }
        let isExplicitJailbreakMarker = rawHazards.hasJailbreakMarker
            || (urlRawHazards?.hasJailbreakMarker == true)
            || (containerHazards?.hasJailbreakMarker == true)
        let isPrebootJailbreak = rawHazards.isNonCryptexPreboot
            || (urlRawHazards?.isNonCryptexPreboot == true)
            || (containerHazards?.isNonCryptexPreboot == true)
        let isDeveloperMountPath = rawHazards.isDeveloperMount
            || (urlRawHazards?.isDeveloperMount == true)
            || (containerHazards?.isDeveloperMount == true)
        let hasTraversalSegment = rawHazards.hasTraversal
            || (urlRawHazards?.hasTraversal == true)
            || (containerHazards?.hasTraversal == true)
        let hasControlCharHazard = rawHazards.hasControlChar
            || (urlRawHazards?.hasControlChar == true)
            || (containerHazards?.hasControlChar == true)
        let hasInvalidContainerPath: Bool = {
            guard let rawContainer = rawContainerString, !rawContainer.isEmpty else { return false }
            let trimmed = rawContainer.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed != rawContainer
                || trimmed.isEmpty
                || !trimmed.hasPrefix("/")
                || InstalledAppRegistryScanner.containsASCIIControlCharacter(rawContainer)
        }()
        let isTrollStoreOrJailbreakPath = isExplicitJailbreakMarker
            || isPrebootJailbreak
            || isDeveloperMountPath
            || hasTraversalSegment
            || hasControlCharHazard
            || hasNonLocalFileURL
            || hasInvalidContainerPath
            || (!isDefaultApp && !isInternalApp
                && (lowerBundlePath.hasPrefix("/applications/")
                    || lowerBundlePath.hasPrefix("/private/applications/")
                    || lowerBundlePath.hasPrefix("/var/applications/")
                    || lowerBundlePath.hasPrefix("/private/var/applications/")))

        let isEnterpriseFlag = (dict["enterpriseApp"] as? Bool == true) || (dict["isEnterpriseApp"] as? Bool == true)
        let isAdHocFlag = (dict["adHoc"] as? Bool == true) || (dict["isAdHoc"] as? Bool == true)
        let explicitNotAppStore = (dict["fromAppStore"] as? Bool == false)
            || (dict["isAppStore"] as? Bool == false)
            || isEnterpriseFlag
            || isAdHocFlag
            || isTrollStoreOrJailbreakPath
            || (dict["provisioningProfile"] != nil)

        let appType = ((isDefaultApp || isInternalApp) && !isTrollStoreOrJailbreakPath) ? "System" : "User"
        let resolvedRawHazards = InstalledAppRegistryScanner.inspectDirectLowerPathHazards(lowerBundlePath)
        let rawLostDangerousMarker = (rawHazards.hasJailbreakMarker && !resolvedRawHazards.hasJailbreakMarker)
            || (rawHazards.isNonCryptexPreboot && !resolvedRawHazards.isNonCryptexPreboot)
            || (rawHazards.isDeveloperMount && !resolvedRawHazards.isDeveloperMount)
            || rawHazards.hasTraversal
            || rawHazards.hasControlChar
            || hasNonLocalFileURL
            || (hasInvalidContainerPath && rawBundlePath == containerPathCandidate)
        let containerHasHazard = (containerHazards?.hasAny == true) || hasInvalidContainerPath
        let storedBundlePath: String = {
            if rawLostDangerousMarker {
                return rawBundlePath
            }
            if urlRawHazards?.hasAny == true, let urlStr = rawURLString, !urlStr.isEmpty {
                return urlStr
            }
            if containerHasHazard && !rawHazards.hasAny, let rawContainer = rawContainerString, !rawContainer.isEmpty {
                return rawContainer
            }
            return resolvedBundlePath
        }()
        let profileValidated = explicitProfileValidated ?? (builtByDeveloper || isEnterpriseFlag)
        var groupSet: Set<String> = []
        if let arr = dict["appGroupIdentifiers"] as? [Any] {
            for case let g as String in arr {
                let trimmed = g.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty { groupSet.insert(trimmed) }
            }
        }
        if let map = dict["groupContainerPaths"] as? [String: Any] {
            for k in map.keys {
                let trimmed = k.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty { groupSet.insert(trimmed) }
            }
        }

        let containerPath = dict["dataContainerPath"] as? String
        var boolEnts: [String: Bool] = [:]
        var strEnts: [String: String] = [:]
        var keychainGroups: [String] = []
        var tccServices: [String] = []
        var allEntKeySet: Set<String> = []
        var teamId = dict["teamIdentifier"] as? String
        let rawEntDict = (dict["entitlements"] as? [String: Any]) ?? (dict["Entitlements"] as? [String: Any])

        if let rawEntDict,
           let parsedFromEnt = fromDictionary(["CFBundleIdentifier": bundleId, "Entitlements": rawEntDict]) {
            for g in parsedFromEnt.appGroups { groupSet.insert(g) }
            keychainGroups = parsedFromEnt.keychainAccessGroups
            tccServices = parsedFromEnt.tccAllowedServices
            boolEnts = parsedFromEnt.booleanEntitlements
            strEnts = parsedFromEnt.stringEntitlements
            allEntKeySet.formUnion(parsedFromEnt.allEntitlementKeys)
            if teamId == nil { teamId = parsedFromEnt.teamId }
        }

        let hasRestricted2026OrPhotos = allEntKeySet.contains { key in
            let isRestricted2026 = InstalledAppRegistryScanner.matchesRestricted2026PrivateEntitlementPrefix(key)
            let isPhotos = key.hasPrefix(ExpandedThreatCatalog.photosEntitlementPrefix)
                || key == ExpandedThreatCatalog.photosBourgeoisieEntitlement
            guard isRestricted2026 || isPhotos else { return false }
            return boolEnts[key] != false
        }
        let isExplicitAdHocOrLdidSigner = InstalledAppRegistryScanner.isAdHocOrLdidSigner(explicitSignerRaw)
        let deviceCtlOwnTeamPrefixes: Set<String> = (!isAdHocFlag && !isTrollStoreOrJailbreakPath && !isExplicitAdHocOrLdidSigner)
            ? ExpandedThreatCatalog.extractOwnTeamPrefixes(from: rawEntDict ?? [:], explicitTeamId: teamId)
            : []
        let hasWildcardKC = !ExpandedThreatCatalog.dangerousWildcardKeychainGroups(
            keychainGroups,
            allowedOwnTeamPrefixes: deviceCtlOwnTeamPrefixes
        ).isEmpty
        let hasEscapeOrPlatformEnt = boolEnts["get-task-allow"] == true
            || boolEnts["com.apple.private.security.no-sandbox"] == true
            || boolEnts["com.apple.private.security.no-container"] == true
            || boolEnts["com.apple.private.security.container-required"] == false
            || boolEnts["com.apple.private.MobileContainerManager.allowed"] == true
            || boolEnts["com.apple.private.security.storage.AppDataContainers"] == true
            || boolEnts["platform-application"] == true
            || !tccServices.isEmpty
            || hasRestricted2026OrPhotos
            || hasWildcardKC
        let isTestFlightFlag = (dict["isBeta"] as? Bool == true)
            || (dict["testFlight"] as? Bool == true)
            || (dict["betaReportsActive"] as? Bool == true)
        let lowerBid = bundleId.lowercased()

        let hasAppStoreMetadata: Bool
        let signerIdentity: String?

        if builtByDeveloper {
            hasAppStoreMetadata = false
            signerIdentity = explicitSignerRaw ?? "Apple Development (CoreDevice)"
        } else if isEnterpriseFlag {
            hasAppStoreMetadata = false
            signerIdentity = explicitSignerRaw ?? "iPhone Distribution (Enterprise)"
        } else if explicitNotAppStore || profileValidated || hasEscapeOrPlatformEnt {
            hasAppStoreMetadata = false
            signerIdentity = explicitSignerRaw ?? (isAdHocFlag ? "Ad Hoc" : nil)
        } else if let explicitSigner = explicitSignerRaw {
            let lowerSig = explicitSigner.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            hasAppStoreMetadata = !isDefaultApp && !isInternalApp && (lowerSig == "apple iphone os application signing")
            signerIdentity = explicitSigner
        } else if isTestFlightFlag {
            hasAppStoreMetadata = false
            signerIdentity = nil
        } else {
            let canInferAppStoreForComApple = !lowerBid.hasPrefix("com.apple.")
                || InstalledAppRegistryScanner.isCanonicalRemovableAppleStockBundleId(lowerBid)
            hasAppStoreMetadata = !isDefaultApp && !isInternalApp && canInferAppStoreForComApple
            signerIdentity = hasAppStoreMetadata ? "Apple iPhone OS Application Signing" : nil
        }

        let sortedGroups = Array(groupSet).sorted()
        if !sortedGroups.isEmpty {
            allEntKeySet.insert("com.apple.security.application-groups")
        }
        let bgModes = (dict["backgroundModes"] as? [Any] ?? dict["UIBackgroundModes"] as? [Any] ?? [])
            .compactMap { $0 as? String }
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        return InstalledAppRegistryRecord(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            applicationType: appType,
            signerIdentity: signerIdentity,
            profileValidated: profileValidated,
            hasAppStoreMetadata: hasAppStoreMetadata,
            teamId: teamId,
            appGroups: sortedGroups,
            keychainAccessGroups: keychainGroups,
            tccAllowedServices: tccServices,
            booleanEntitlements: boolEnts,
            stringEntitlements: strEnts,
            allEntitlementKeys: Array(allEntKeySet).sorted(),
            backgroundModes: bgModes,
            bundlePath: storedBundlePath,
            containerPath: containerPath
        )
    }
}

/// Evaluates installed application registry snapshots and live `installation_proxy` records.
public final class InstalledAppRegistryScanner: @unchecked Sendable {
    public static let shared = InstalledAppRegistryScanner()

    private let whitelistEngine: WhitelistEngine

    /// Additional major domestic / global messenger & payment apps frequently repackaged on sideload channels.
    private static var extraSideloadImpersonationTargets: [ExpandedThreatCatalog.ImpersonatedBrand] {
        ExpandedThreatCatalog.extraSideloadImpersonationTargets
    }

    private static func matchesExtraSideloadImpersonation(bundleIds: [String], displayName: String) -> [ExpandedThreatCatalog.ImpersonatedBrand] {
        let trimmedOrigName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let lowerName = trimmedOrigName.lowercased()
        let foldedLowerName = ExpandedThreatCatalog.foldConfusablesToASCII(trimmedOrigName).lowercased()
        let nameTokens = ExpandedThreatCatalog.extractBrandTokens(from: trimmedOrigName)
        let foldedCandBids = bundleIds.map { ExpandedThreatCatalog.foldConfusablesToASCII($0).lowercased() }
        var matched: [ExpandedThreatCatalog.ImpersonatedBrand] = []
        for extra in extraSideloadImpersonationTargets {
            let matchBid = foldedCandBids.contains { lowerBid in
                extra.bundleIdPatterns.contains { pat in
                    lowerBid == pat || lowerBid.hasPrefix(pat + ".") || lowerBid.contains("." + pat + ".") || lowerBid.hasSuffix("." + pat)
                }
            }
            let matchName = extra.displayNames.contains { pat in
                let isASCII = pat.unicodeScalars.allSatisfy { $0.isASCII }
                if isASCII && !pat.contains(" ") {
                    return lowerName == pat || foldedLowerName == pat || nameTokens.contains(pat)
                }
                return lowerName == pat || lowerName.contains(pat) || foldedLowerName == pat || foldedLowerName.contains(pat)
            }
            if matchBid || matchName {
                matched.append(extra)
            }
        }
        return matched
    }

    public init(whitelistEngine: WhitelistEngine = .shared) {
        self.whitelistEngine = whitelistEngine
    }

    // MARK: - Snapshot Parsing (Plist / XML / Binary Plist / JSON)

    public func parseSnapshotFile(at url: URL) throws -> [InstalledAppRegistryRecord] {
        let data: Data
        do {
            data = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: url, maxBytes: 128 * 1024 * 1024)
        } catch IPAPackageScannerError.fileNotFound {
            throw InstalledAppRegistryError.fileNotFound(url.path)
        } catch {
            throw InstalledAppRegistryError.invalidSnapshotFormat(error.localizedDescription)
        }
        return try parseSnapshotData(data)
    }

    public func parseSnapshotData(_ data: Data) throws -> [InstalledAppRegistryRecord] {
        guard !data.isEmpty else {
            throw InstalledAppRegistryError.emptyApplicationList
        }

        // 0. Concatenated XML plists (raw `instproxy Browse` stream dumps). `PropertyListSerialization`
        //    silently parses only the FIRST document and ignores trailing bytes, so any data holding more
        //    than one `</plist>` must take the chunked path, otherwise packets 2+ vanish from the audit.
        if Self.containsMultiplePlistTerminators(data),
           let chunked = parseConcatenatedPlistStream(data), !chunked.isEmpty {
            return chunked
        }

        // 1. Try PropertyList (XML or Binary)
        if let plistObj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) {
            let records = extractRecords(from: plistObj)
            if !records.isEmpty {
                return records
            }
        }

        // 2. Try strongly-typed cached JSON or `pymobiledevice3 apps list` JSON
        if let cached = try? JSONDecoder().decode([InstalledAppRegistryRecord].self, from: data), !cached.isEmpty {
            return deduplicate(cached)
        }
        if let jsonObj = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
            let records = extractRecords(from: jsonObj)
            if !records.isEmpty {
                return records
            }
        }

        // 3. Handle concatenated XML plists from raw `instproxy Browse` stream dumps
        if let chunked = parseConcatenatedPlistStream(data), !chunked.isEmpty {
            return chunked
        }

        throw InstalledAppRegistryError.invalidSnapshotFormat(
            WQLocale.pick(en: "Unrecognized snapshot data structure", zh: "未知的数据结构")
        )
    }

    /// `true` when the raw data contains at least two top-level XML `<plist>...</plist>` documents
    /// (ignoring literal `</plist>` tokens inside `<!--...-->` comments or `<![CDATA[...]]>` blocks).
    static func containsMultiplePlistTerminators(_ data: Data) -> Bool {
        CSBlobParser.scanXMLPlistDocumentRanges(in: data, maxDocuments: 2).count >= 2
    }

    /// Splits a concatenated XML plist stream into individual documents using comment/CDATA-aware O(N) lexical scanning,
    /// and aggregates the records of every chunk.
    private func parseConcatenatedPlistStream(_ data: Data) -> [InstalledAppRegistryRecord]? {
        let ranges = CSBlobParser.scanXMLPlistDocumentRanges(in: data, maxDocuments: 8192)
        guard !ranges.isEmpty else { return nil }
        let normalized = data.startIndex == 0 ? data : Data(data)
        var aggregated: [InstalledAppRegistryRecord] = []
        for docRange in ranges {
            let chunkData = normalized.subdata(in: docRange)
            if let plistObj = try? PropertyListSerialization.propertyList(from: chunkData, options: [], format: nil) {
                aggregated.append(contentsOf: extractRecords(from: plistObj))
            }
        }
        return aggregated.isEmpty ? nil : deduplicate(aggregated)
    }

    private func extractRecords(from rootObject: Any) -> [InstalledAppRegistryRecord] {
        var results: [InstalledAppRegistryRecord] = []

        if let array = rootObject as? [[String: Any]] {
            for item in array {
                // Could either be an app record directly, devicectl record, or a Browse packet containing `CurrentList`
                if let currentList = item["CurrentList"] as? [[String: Any]] {
                    for sub in currentList {
                        if let rec = InstalledAppRegistryRecord.fromDictionary(sub) {
                            results.append(rec)
                        }
                    }
                } else if let rec = InstalledAppRegistryRecord.fromDictionary(item)
                            ?? InstalledAppRegistryRecord.fromDeviceCtlDictionary(item) {
                    results.append(rec)
                }
            }
        } else if let dict = rootObject as? [String: Any] {
            if let resultObj = dict["result"] as? [String: Any],
               let ctlApps = resultObj["apps"] as? [[String: Any]] {
                for sub in ctlApps {
                    if let rec = InstalledAppRegistryRecord.fromDeviceCtlDictionary(sub)
                        ?? InstalledAppRegistryRecord.fromDictionary(sub) {
                        results.append(rec)
                    }
                }
            } else if let ctlApps = dict["apps"] as? [[String: Any]] {
                for sub in ctlApps {
                    if let rec = InstalledAppRegistryRecord.fromDeviceCtlDictionary(sub)
                        ?? InstalledAppRegistryRecord.fromDictionary(sub) {
                        results.append(rec)
                    }
                }
            } else if let currentList = dict["CurrentList"] as? [[String: Any]] {
                for sub in currentList {
                    if let rec = InstalledAppRegistryRecord.fromDictionary(sub) {
                        results.append(rec)
                    }
                }
            } else if let returnVal = dict["ReturnValue"] as? [[String: Any]] {
                for sub in returnVal {
                    if let rec = InstalledAppRegistryRecord.fromDictionary(sub) {
                        results.append(rec)
                    }
                }
            } else if dict["CFBundleIdentifier"] != nil, let single = InstalledAppRegistryRecord.fromDictionary(dict) {
                results.append(single)
            } else {
                // Keyed by Bundle ID (e.g. `pymobiledevice3 apps list`)
                for (key, value) in dict {
                    if let appDict = value as? [String: Any],
                       let rec = InstalledAppRegistryRecord.fromDictionary(appDict, fallbackBundleId: key) {
                        results.append(rec)
                    }
                }
            }
        }

        return deduplicate(results)
    }

    /// Collapses records sharing the same (whitespace-trimmed, case-sensitive) bundle ID.
    /// Secure-by-default: on a collision the RISKIEST record is kept (higher risk tier, then more
    /// indicators), so a clean duplicate can never shadow a malicious one.
    func deduplicate(_ records: [InstalledAppRegistryRecord]) -> [InstalledAppRegistryRecord] {
        var indexByBid: [String: Int] = [:]
        var unique: [InstalledAppRegistryRecord] = []
        unique.reserveCapacity(records.count)
        for rec in records {
            let key = rec.bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let existingIdx = indexByBid[key] else {
                indexByBid[key] = unique.count
                unique.append(rec)
                continue
            }
            let existing = unique[existingIdx]
            if existing == rec { continue }
            let a = evaluateRecord(existing)
            let b = evaluateRecord(rec)
            let aRank = a.riskTier.severityRank
            let bRank = b.riskTier.severityRank
            if bRank > aRank || (bRank == aRank && b.indicators.count > a.indicators.count) {
                unique[existingIdx] = rec
            }
        }
        return unique
    }

    // MARK: - Channel Classification & Security Audit

    /// Apple stock applications that are preinstalled as user-removable bundles under
    /// `/private/var/containers/Bundle/Application/<UUID>/` on iOS 15–27 and omit `SignerIdentity`
    /// in CoreTrust static-cache exports. Deliberately excludes SSV-only core apps such as `com.apple.health`.
    private static let removableAppleStockBundleIds: Set<String> = [
        "com.apple.mobiletimer",
        "com.apple.shortcuts",
        "com.apple.shortcutsviewservice",
        "com.apple.documentsapp",
        "com.apple.files",
        "com.apple.translate",
        "com.apple.sequoiatranslator",
        "com.apple.mobilecal",
        "com.apple.mobilenotes",
        "com.apple.mobilemail",
        "com.apple.maps",
        "com.apple.weather",
        "com.apple.calculator",
        "com.apple.stocks",
        "com.apple.voicememos",
        "com.apple.reminders",
        "com.apple.contacts",
        "com.apple.mobileaddressbook",
        "com.apple.facetime",
        "com.apple.podcasts",
        "com.apple.ibooks",
        "com.apple.tv",
        "com.apple.music",
        "com.apple.classical",
        "com.apple.news",
        "com.apple.home",
        "com.apple.findmy",
        "com.apple.mobileme.fmip1",
        "com.apple.mobileme.fmf1",
        "com.apple.tips",
        "com.apple.fitness",
        "com.apple.bridge",
        "com.apple.measure",
        "com.apple.magnifier",
        "com.apple.compass",
        "com.apple.journal",
        "com.apple.passwords",
        "com.apple.freeform",
        "com.apple.games",
        "com.apple.preview",
        "com.apple.previewshell",
        "com.apple.imageplayground",
        "com.apple.generativeplaygroundapp",
        "com.apple.continuitysingshieldui",
        "com.apple.invites",
        "com.apple.sports",
        "com.apple.store.jolly",
        "com.apple.supportapp",
        "com.apple.testflight",
        "com.apple.developer",
        "com.apple.applevisionproapp",
        "com.apple.aegirproxyapp",
        "com.apple.helloposter",
        "com.apple.printcenter",
        "com.apple.feedbackassistant",
        "com.apple.pages",
        "com.apple.keynote",
        "com.apple.numbers",
        "com.apple.imovie",
        "com.apple.garageband",
        "com.apple.clips",
        "com.apple.itunesu",
        "com.apple.finalcutcamera",
        "com.apple.appstore",
        "com.apple.camera",
        "com.apple.mobilesafari",
        "com.apple.mobileslideshow",
        "com.apple.photos",
        "com.apple.passbook",
        "com.apple.mobilephone",
        "com.apple.mobilesms",
        "com.apple.siri",
        "com.apple.campo",
        "com.apple.spotlight",
        "com.apple.preferences",
        "com.apple.datadetectors.ddactionsservice",
        "com.apple.tvremoteapp",
        "com.apple.tvremoteuiservice",
        "com.apple.appletv",
        "com.apple.books",
        "com.apple.musicrecognition",
        "com.apple.shazameventsapp",
        "com.apple.family",
        "com.apple.safetymonitorapp",
        "com.apple.sidecar",
        "com.apple.batteries",
        "com.apple.barcodescanner",
        "com.apple.hearingapp",
        "com.apple.mobilegarageband",
        "com.apple.playgrounds",
        "com.apple.photo-booth",
        "com.apple.tamale",
        "com.apple.writingtoolsuiservice",
        "com.apple.momentsuiservice",
        "com.apple.magnifierangel",
        "com.apple.continuitycaptureshieldui",
        "com.apple.findingui",
        "com.apple.movetoandroid",
        "com.apple.sosbuddy",
        "com.apple.simsetupuiservice",
        "com.apple.hdsviewservice",
        "com.apple.applesupport",
        "com.apple.store.jolly",
        "com.apple.wwdc-release",
        "com.apple.testflight",
        "com.apple.transporter",
        "com.apple.realitycomposer",
        "com.apple.musicmemos",
        "com.apple.remote",
        "com.apple.gametrampoline",
        "com.apple.adaptivemusicapp",
        "com.apple.icq",
        "com.apple.posterboard",
        "com.apple.posters.imageplaygroundposterapp",
        "com.apple.posters.weatherposterapp",
        "com.apple.posters.kaleidoscopeposterapp",
        "com.apple.posters.unityposterapp",
        "com.apple.health.sleep",
        "com.apple.healthprivacyservice",
        "com.apple.proximityreadersceneui",
        "com.apple.proximityreaderuiservice",
        "com.apple.cloudkit.sharebear",
        "com.apple.animoji.stickersapp",
        "com.apple.jellyfish",
        "com.apple.mobilesms.compose",
        "com.apple.messages.remotealerts",
        "com.apple.imessageappsviewservice",
        "com.apple.photos.photosuiservice",
        "com.apple.photosviewservice",
        "com.apple.musicuiservice",
        "com.apple.musickit.ui",
        "com.apple.passbooksecureuiservice",
        "com.apple.passbookuisceneservice",
        "com.apple.passbookuiservice",
        "com.apple.passbookstub",
        "com.apple.shortcutsui",
        "com.apple.shortcutsactions",
        "com.apple.safariviewservice",
        "com.apple.browserkitviewservice",
        "com.apple.businesschatviewservice",
        "com.apple.eventviewservice",
        "com.apple.home.homeuiservice",
        "com.apple.home.homecontrolservice",
        "com.apple.siri.parsec.hashtagimagesapp",
        "com.apple.clockangel",
        "com.apple.cameraoverlayangel",
        "com.apple.livetranscriptionui",
        "com.apple.accessibility.accessibilityreader",
        "com.apple.accessibilityuiserver",
        "com.apple.sesuiserviceapp",
        "com.apple.subcredentialuiservice",
        "com.apple.credentialsharinguiviewservice",
        "com.apple.coreidv.coreidvui",
        "com.apple.coreidv.idvsp",
        "com.apple.npkcompanionagent",
        "com.apple.ddactionsservice",
        "com.apple.storekituiservice",
        "com.apple.ios.storekituiservice",
        "com.apple.continuitykeyboards",
        "com.apple.continuityroutinguiservice",
        "com.apple.ctnotifyuiservice",
        "com.apple.setup",
        "com.apple.purplebuddy",
        "com.apple.diagnostics",
        "com.apple.diagnosticsservice",
        "com.apple.fieldtest",
        "com.apple.remoteicloudquotaui",
        "com.apple.askpermissionui",
        "com.apple.familycontrolsauthenticationui",
        "com.apple.screentimeunlock",
        "com.apple.stickers.usergenerated.messagesextension",
        "com.apple.usernotificationsuikit.thumbnailprovider"
    ]

    /// Official Apple-owned applications whose legacy bundle identifiers do not start with `com.apple.`,
    /// accepted ONLY when cryptographically signed by Apple App Store / Apple OS without a provisioning profile.
    private static let appleOwnedNonComAppleBundleIds: Set<String> = [
        "com.shazam.shazamapp",
        "com.shazam.encore.shazam",
        "is.workflow.my.app"
    ]

    /// Canonical lowercased bundle identifiers of Apple preinstalled removable stock apps that reside under
    /// `/private/var/containers/Bundle/Application/...` and may omit `SignerIdentity` in CoreTrust static-cache exports.
    private static let canonicalRemovableAppleStockBundleIds: Set<String> = {
        var ids = Set(
            CSStore2Parser.builtInChineseNames.keys
                .map { $0.lowercased() }
                .filter { $0.hasPrefix("com.apple.") }
        )
        let extras: [String] = [
            "com.apple.health",
            "com.apple.shortcuts",
            "com.apple.fitness",
            "com.apple.passbook",
            "com.apple.bridge",
            "com.apple.tips",
            "com.apple.translate",
            "com.apple.journal",
            "com.apple.passwords",
            "com.apple.freeform",
            "com.apple.measure",
            "com.apple.magnifier",
            "com.apple.compass",
            "com.apple.stocks",
            "com.apple.weather",
            "com.apple.voicememos",
            "com.apple.podcasts",
            "com.apple.ibooks",
            "com.apple.tv",
            "com.apple.music",
            "com.apple.news",
            "com.apple.home",
            "com.apple.findmy",
            "com.apple.contacts",
            "com.apple.facetime",
            "com.apple.files",
            "com.apple.documentsapp",
            "com.apple.reminders",
            "com.apple.mobilenotes",
            "com.apple.mobilecal",
            "com.apple.mobilemail",
            "com.apple.mobilesafari",
            "com.apple.mobileslideshow",
            "com.apple.mobiletimer",
            "com.apple.calculator",
            "com.apple.camera",
            "com.apple.appstore",
            "com.apple.preferences"
        ]
        for item in extras {
            ids.insert(item)
        }
        ids.formUnion(removableAppleStockBundleIds)
        return ids
    }()

    internal static func isCanonicalRemovableAppleStockBundleId(_ lowerBid: String) -> Bool {
        canonicalRemovableAppleStockBundleIds.contains(lowerBid)
    }

    private static let knownAppleFirstPartyTeamIds: Set<String> = [
        "0000000000",
        "APPLE",
        "59GAB85EFG",
        "243LU875E5",
        "K36BKF7T3D",
        "M8L2WTLA8W",
        "74J34U3R6X",
        "A85B27S937",
        "9Z356F7V79",
        "J5492B4V36",
        "F3LWYJ7GM7",
        "87G42F7594",
        "P3L35M8B69",
        "96VJNMX6ZP",
        "4GWDBCF5A4",
        "4WXS7A4F54",
        "RD13622867",
        "RLRS9CRG76",
        "ZL6BUSYGB3",
        "V568VXD5P8"
    ]

    private static let stagedAppleStorePrivateAllowedBundleIds: Set<String> = [
        "com.apple.mobiletimer",
        "com.apple.appstore",
        "com.apple.tvremoteapp",
        "com.apple.siri",
        "com.apple.music",
        "com.apple.podcasts",
        "com.apple.ibooks",
        "com.apple.books",
        "com.apple.appletv",
        "com.apple.tv"
    ]

    private static func rawPhotosPrivateEntitlementKeys(in record: InstalledAppRegistryRecord) -> [String] {
        let candidateKeys = Set(record.allEntitlementKeys)
            .union(record.booleanEntitlements.keys)
            .union(record.stringEntitlements.keys)
            .sorted()
        return candidateKeys.filter { key in
            guard key.hasPrefix(ExpandedThreatCatalog.photosEntitlementPrefix)
                || key == ExpandedThreatCatalog.photosBourgeoisieEntitlement else {
                return false
            }
            return record.booleanEntitlements[key] != false
        }
    }

    /// Returns `true` when an App Group identifier belongs to Apple's first-party system/stock namespaces
    /// (closed allowlist verified against iOS Simulator Runtime & SSV binaries, including bare `com.apple.*`,
    /// Team-ID-prefixed `*.groups.com.apple.*`, `group.tvappservices.container`, `group.is.workflow.*`,
    /// and verified Apple-acquired stock namespaces). Empty strings fail closed (`false`).
    internal static func isAppleOwnedAppGroup(_ rawGroup: String) -> Bool {
        let lg = rawGroup.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !lg.isEmpty else { return false }

        if lg == "group.com.apple"
            || lg == "systemgroup.com.apple"
            || lg == "group.tvappservices.container" {
            return true
        }

        let directPrefixes = [
            "group.com.apple.",
            "groups.com.apple.",
            "systemgroup.com.apple.",
            "com.apple.",
            "group.apple.",
            "groups.apple.",
            "systemgroup.apple.",
            "group.net.apple.",
            "group.org.apple.",
            "group.is.workflow.",
            "is.workflow.",
            "group.com.icloud.",
            "com.icloud.",
            "group.icloud.",
            "group.tvappservices.",
            "tvappservices.",
            "group.com.siri.",
            "group.siri.",
            "com.siri.",
            "group.com.itunes.",
            "group.itunes.",
            "com.itunes.",
            "group.com.me.",
            "group.com.mobileme.",
            "com.me.",
            "com.mobileme.",
            "group.com.shazam.",
            "com.shazam.",
            "group.com.darksky.",
            "com.darksky.",
            "group.com.beats.",
            "com.beats.",
            "group.com.primephonic.",
            "com.primephonic.",
            "group.com.texture.",
            "com.texture.",
            "group.com.beddit.",
            "com.beddit.",
            "group.com.nextvr.",
            "com.nextvr.",
            "group.com.filemaker.",
            "com.filemaker.",
            "group.com.claris.",
            "com.claris."
        ]
        if directPrefixes.contains(where: { lg.hasPrefix($0) }) {
            return true
        }

        if let dotIdx = lg.firstIndex(of: ".") {
            let prefix = String(lg[..<dotIdx])
            let rest = String(lg[lg.index(after: dotIdx)...])
            let isValidTeamPrefix = knownAppleFirstPartyTeamIds.contains(prefix.uppercased())
                || ExpandedThreatCatalog.isStrictTenCharTeamId(prefix)
                || prefix == "0000000000"
            if isValidTeamPrefix {
                if rest == "group.tvappservices.container" {
                    return true
                }
                let teamApplePrefixes = [
                    "com.apple.",
                    "group.com.apple.",
                    "groups.com.apple.",
                    "systemgroup.com.apple.",
                    "apple.",
                    "group.apple.",
                    "groups.apple.",
                    "systemgroup.apple.",
                    "group.net.apple.",
                    "group.org.apple.",
                    "is.workflow.",
                    "group.is.workflow.",
                    "group.com.icloud.",
                    "com.icloud.",
                    "group.icloud.",
                    "group.tvappservices.",
                    "tvappservices.",
                    "group.com.siri.",
                    "group.siri.",
                    "com.siri.",
                    "group.com.itunes.",
                    "group.itunes.",
                    "com.itunes.",
                    "group.com.me.",
                    "group.com.mobileme.",
                    "com.me.",
                    "com.mobileme.",
                    "com.shazam.",
                    "group.com.shazam.",
                    "group.com.darksky.",
                    "com.darksky.",
                    "group.com.beats.",
                    "com.beats.",
                    "group.com.primephonic.",
                    "com.primephonic.",
                    "group.com.texture.",
                    "com.texture.",
                    "group.com.beddit.",
                    "com.beddit.",
                    "group.com.nextvr.",
                    "com.nextvr.",
                    "group.com.filemaker.",
                    "com.filemaker.",
                    "group.com.claris.",
                    "com.claris."
                ]
                if teamApplePrefixes.contains(where: { rest.hasPrefix($0) }) {
                    return true
                }
            }
        }

        return false
    }

    private static let disallowedAppleRecordAppGroupMarkers: [String] = [
        "metamask", "telegram", "telegra", "whatsapp", "wechat", "tencent.xin", "tencent.wx",
        "alipay", "iphoneclient", "binance", "okx", "okex", "okinc", "trustwallet", "sixdays",
        "phantom", "imtoken", "im.token", "consenlabs", "tokenpocket", "mytokenpocket",
        "bitkeep", "bitget", "coinbase", "bybit", "ledger", "onekey", "wqguard",
        "trollstore", "backdoor", "evil", "attacker", "malware", "trojan", "drainer",
        "exfil", "danmaku"
    ]

    private static let internalAppleStockServiceAppGroupPrefixes: [String] = [
        "group.gm.", "group.ams.", "group.sms.", "group.im.", "group.tv.",
        "group.maps.", "group.mail.", "group.home.", "group.tips.", "group.news.",
        "group.notes.", "group.reminders.", "group.health.", "group.healthkit.",
        "group.passwords.", "group.voicememos.", "group.files.", "group.documents.",
        "group.photos.", "group.safari.", "group.weather.", "group.stocks.",
        "group.podcasts.", "group.books.", "group.music.", "group.fitness.",
        "group.journal.", "group.passbook.", "group.wallet.", "group.shortcuts.",
        "group.translate.", "group.translation.", "group.imageplayground.",
        "group.generativeplayground.", "group.freeform.", "group.findmy.",
        "group.facetime.", "group.contacts.", "group.calendar.", "group.clock.",
        "group.camera.", "group.magnifier.", "group.measure.", "group.sports.",
        "group.invites.", "group.games.", "group.preview.",
        "group.homedevicesetup.", "group.ses.", "group.sesuiservice.",
        "systemgroup.com.apple.", "systemgroup.apple."
    ]

    private static let rejectedStructuralAppleServiceSegments: Set<String> = [
        "local", "cloud", "store", "online", "world", "space", "email", "digital",
        "network", "agency", "center", "wallet", "crypto", "token", "finance",
        "global", "company", "solutions", "custom", "customshare", "customcontainer",
        "mycompany", "thirdparty", "example", "adversarial", "attacker", "spoof",
        "metamask", "telegram", "whatsapp", "wechat", "alipay", "binance", "trust",
        "phantom", "coinbase", "tokenpocket", "imtoken", "bitget", "bitkeep",
        "backdoor", "troll", "exploit", "hacker", "pwned", "trojan", "malware"
    ]

    private static func isStructuralInternalAppleServiceGroup(_ candidate: String) -> Bool {
        let remainder: Substring
        if candidate.hasPrefix("group.") {
            remainder = candidate.dropFirst(6)
        } else if candidate.hasPrefix("systemgroup.") {
            remainder = candidate.dropFirst(12)
        } else {
            return false
        }
        guard let dotIdx = remainder.firstIndex(of: ".") else { return false }
        let firstSeg = remainder[..<dotIdx]
        let afterDot = remainder[remainder.index(after: dotIdx)...]
        guard firstSeg.count >= 5,
              !afterDot.isEmpty,
              !afterDot.hasPrefix("."),
              !afterDot.hasSuffix(".") else {
            return false
        }
        guard firstSeg.utf8.allSatisfy({ $0 >= 0x61 && $0 <= 0x7A }) else {
            return false
        }
        return !rejectedStructuralAppleServiceSegments.contains(String(firstSeg))
    }

    private static let internalAppleStockServiceExactGroups: Set<String> = [
        "apple", "group.gm", "group.ams", "group.sms", "group.im", "group.tv",
        "group.notes", "group.reminders", "group.health", "group.passwords",
        "group.voicememos", "group.files"
    ]

    /// Evaluates whether an App Group entry declared by a `com.apple.*` OS/stock record is a
    /// legitimate Apple/internal-service container group, rejecting third-party, wallet, or
    /// obfuscated/malformed identifiers while preventing false positives on real iOS 26/27 stock apps.
    internal static func isPermittedAppGroupForAppleSystemRecord(_ rawGroup: String) -> Bool {
        let trimmed = rawGroup.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed == rawGroup else { return false }
        let hasForbiddenScalar = trimmed.unicodeScalars.contains { scalar in
            let v = scalar.value
            if v == 0x3164 || v == 0xFFA0 || v == 0x2800 || v == 0x180E || v == 0x115F || v == 0x1160 {
                return true
            }
            if scalar.properties.isWhitespace {
                return true
            }
            let cat = scalar.properties.generalCategory
            return cat == .control
                || cat == .format
                || cat == .enclosingMark
                || cat == .spaceSeparator
                || cat == .lineSeparator
                || cat == .paragraphSeparator
                || cat == .privateUse
                || cat == .surrogate
                || cat == .unassigned
        }
        guard !hasForbiddenScalar,
              !trimmed.contains("/"),
              !trimmed.contains("\\"),
              !trimmed.contains("..") else {
            return false
        }

        let folded = ExpandedThreatCatalog.foldConfusablesToASCII(trimmed).lowercased()
        guard !folded.isEmpty,
              !disallowedAppleRecordAppGroupMarkers.contains(where: { folded.contains($0) }) else {
            return false
        }

        if Self.isAppleOwnedAppGroup(trimmed)
            || Self.isAppleOwnedAppGroup(folded)
            || internalAppleStockServiceExactGroups.contains(folded) {
            return true
        }
        if internalAppleStockServiceAppGroupPrefixes.contains(where: { folded.hasPrefix($0) })
            || isStructuralInternalAppleServiceGroup(folded) {
            return true
        }

        if let dotIdx = folded.firstIndex(of: ".") {
            let prefix = String(folded[..<dotIdx])
            let rest = String(folded[folded.index(after: dotIdx)...])
            let isKnownApplePrefix = knownAppleFirstPartyTeamIds.contains(prefix.uppercased())
            let isTeamLikePrefix = isKnownApplePrefix
                || ExpandedThreatCatalog.isStrictTenCharTeamId(prefix)
                || prefix == "0000000000"
            if isTeamLikePrefix && !rest.isEmpty {
                if isKnownApplePrefix
                    && !rest.hasPrefix("io.")
                    && !rest.hasPrefix("org.")
                    && !rest.hasPrefix("net.")
                    && !rest.hasPrefix("com.") {
                    return true
                }
                if internalAppleStockServiceExactGroups.contains(rest)
                    || internalAppleStockServiceAppGroupPrefixes.contains(where: { rest.hasPrefix($0) })
                    || isStructuralInternalAppleServiceGroup(rest) {
                    return true
                }
            }
        }

        return false
    }

    /// Returns `true` when the record represents a genuine Apple OS daemon, CoreServices UI service,
    /// or Apple first-party system/removable application (never developer-sideloaded, TrollStore-registered, or enterprise-resigned).
    public func isAppleSystemOrFirstPartyApp(_ record: InstalledAppRegistryRecord) -> Bool {
        // Any bundle signed with a provisioning profile (Developer / Ad-Hoc / Enterprise sideload)
        // or carrying get-task-allow is NEVER a genuine Apple OS platform binary.
        if record.profileValidated || record.booleanEntitlements["get-task-allow"] == true {
            return false
        }

        let path = Self.standardizedAbsolutePath(record.bundlePath)
        let pathHazards = Self.inspectPathHazards(record.bundlePath)
        let isJailbreakSubpath = pathHazards.hasAny
        let hasLeadingSlash = record.bundlePath.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("/")

        let signer = record.signerIdentity?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        let lowerBid = record.bundleId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if Self.appleOwnedNonComAppleBundleIds.contains(lowerBid) {
            guard !isJailbreakSubpath, hasLeadingSlash else { return false }
            return signer == "apple iphone os application signing"
                || signer == "software signing"
                || signer == "apple code signing certification authority"
        }
        guard lowerBid.hasPrefix("com.apple.") else {
            return false
        }

        if let signer, !signer.isEmpty {
            // Cryptographic Apple OS platform signature or Apple App Store signature on a `com.apple.*` bundle without profileValidated
            if signer == "software signing"
                || signer == "apple iphone os application signing"
                || signer == "apple code signing certification authority" {
                return hasLeadingSlash && !isJailbreakSubpath
            }
            // Any other non-empty signer (e.g. "Ad Hoc", "ldid", "Apple Development", "iPhone Distribution") is NEVER Apple OS.
            return false
        }

        // Reject third-party App Groups, known sideload tool names, or wallet/messenger display-name impersonation.
        if record.appGroups.contains(where: { !Self.isPermittedAppGroupForAppleSystemRecord($0) }) {
            return false
        }
        if Self.matchKnownSideloadInfrastructure(bundleId: record.bundleId, displayName: record.displayName) != nil {
            return false
        }
        if !ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: record.bundleId,
            displayName: record.displayName,
            installChannel: .developerSideloaded,
            cryptid: 0
        ).isEmpty || !Self.matchesExtraSideloadImpersonation(
            bundleIds: [record.bundleId],
            displayName: record.displayName
        ).isEmpty {
            return false
        }

        // Real iOS SSV-sealed OS & Cryptex paths (`/System/`, `/Applications/`, `/private/preboot/Cryptexes/...`,
        // `/private/preboot/<BOOT_HASH>/cryptex1/...`, etc.): `installation_proxy` omits `SignerIdentity`
        // on stock OS daemons/apps while they legitimately hold `platform-application`, `no-container`, `no-sandbox`, `tcc.allow`, etc.
        let appType = record.applicationType.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let isSSVSystemPath = !isJailbreakSubpath && hasLeadingSlash && (
            path.hasPrefix("/System/")
            || path.hasPrefix("/private/System/")
            || path.hasPrefix("/Applications/")
            || path.hasPrefix("/private/Applications/")
            || path.hasPrefix("/private/preboot/")
            || path.hasPrefix("/preboot/")
            || path.hasPrefix("/private/var/Cryptexes/")
            || path.hasPrefix("/var/Cryptexes/")
            || path.hasPrefix("/private/var/staged_system_apps/")
            || path.hasPrefix("/var/staged_system_apps/")
            || path.hasPrefix("/private/var/MobileAsset/")
            || path.hasPrefix("/var/MobileAsset/")
        )
        let isStagedBundleContainerPath = !isJailbreakSubpath && hasLeadingSlash && (
            path.hasPrefix("/private/var/containers/Bundle/Application/")
            || path.hasPrefix("/var/containers/Bundle/Application/")
            || path.hasPrefix("/private/var/mobile/Containers/Bundle/Application/")
            || path.hasPrefix("/var/mobile/Containers/Bundle/Application/")
        )
        let isSystemAppType = (appType == "system" || appType == "internal" || appType == "hidden" || appType == "coreservices")
        let hasPlatformAppEnt = (record.booleanEntitlements["platform-application"] == true)
        let hasFullSandboxDisable = (record.booleanEntitlements["com.apple.private.security.no-sandbox"] == true
            || record.booleanEntitlements["com.apple.private.security.container-required"] == false)

        let rawPhotosKeys = Self.rawPhotosPrivateEntitlementKeys(in: record)
        let raw2026Keys = rawRestricted2026EntitlementKeys(in: record)
        let dangerousKC = ExpandedThreatCatalog.dangerousWildcardKeychainGroups(
            record.keychainAccessGroups,
            allowedOwnTeamPrefixes: []
        )

        // Check `application-identifier` when explicitly declared: must target Apple/first-party bundle namespace
        // and, off SSV, match a canonical Apple stock app or the record's own bundle ID.
        let rawAppIdEnt = record.stringEntitlements["application-identifier"]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        let entAppIdBidLower: String? = {
            guard let rawAppIdEnt, !rawAppIdEnt.isEmpty else { return nil }
            if let dotIdx = rawAppIdEnt.firstIndex(of: ".") {
                let prefix = String(rawAppIdEnt[..<dotIdx])
                if prefix == "0000000000"
                    || prefix == "apple"
                    || Self.knownAppleFirstPartyTeamIds.contains(prefix.uppercased())
                    || ExpandedThreatCatalog.isStrictTenCharTeamId(prefix) {
                    return String(rawAppIdEnt[rawAppIdEnt.index(after: dotIdx)...])
                }
            }
            return rawAppIdEnt
        }()
        var hasValidComAppleAppId = false
        var hasDotQualifiedValidComAppleAppId = false
        if let entAppIdBidLower {
            let isBareSingleSegmentId = !entAppIdBidLower.isEmpty
                && !entAppIdBidLower.contains(".")
                && !entAppIdBidLower.contains("*")
                && entAppIdBidLower.utf8.allSatisfy { b in
                    (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == 0x2D || b == 0x5F
                }
            let bareMatchesOwnAppleBundle = isBareSingleSegmentId && (
                lowerBid == "com.apple." + entAppIdBidLower
                || lowerBid.hasSuffix("." + entAppIdBidLower)
            )
            let isAppleEntBidPrefix = entAppIdBidLower.hasPrefix("com.apple.")
                || entAppIdBidLower.hasPrefix("is.workflow.")
                || entAppIdBidLower.hasPrefix("com.shazam.")
                || bareMatchesOwnAppleBundle
                || (isBareSingleSegmentId && isSSVSystemPath && isSystemAppType)
            guard isAppleEntBidPrefix else { return false }
            let matchesRecBid = (entAppIdBidLower == lowerBid)
                || bareMatchesOwnAppleBundle
                || (!isBareSingleSegmentId && (
                    Self.canonicalRemovableAppleStockBundleIds.contains(entAppIdBidLower)
                    || lowerBid.hasPrefix(entAppIdBidLower)
                    || entAppIdBidLower.hasPrefix(lowerBid)
                ))
            if !isSSVSystemPath && !matchesRecBid {
                return false
            }
            hasValidComAppleAppId = matchesRecBid || isSSVSystemPath
            hasDotQualifiedValidComAppleAppId = !isBareSingleSegmentId && hasValidComAppleAppId
        }

        // Permit global Apple keychain wildcards (`com.apple.*`, `apple.*`, `0000000000.*`, own/known Apple Team IDs)
        // on stock records while still catching bare `*` and third-party team wildcards (`OTHERTEAM.*`).
        let recordTeamLower = record.teamId?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let hasDisallowedNoSandboxKeychainWildcard = record.keychainAccessGroups.contains { rawGrp in
            let grp = rawGrp.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !grp.isEmpty else { return false }
            if grp == "*" { return true }
            guard grp.hasSuffix(".*") || grp.contains("*") else { return false }
            guard grp.hasSuffix(".*") else { return true }
            let foldedPrefix = ExpandedThreatCatalog.foldConfusablesToASCII(String(grp.dropLast(2))).lowercased()
            guard !foldedPrefix.isEmpty,
                  !foldedPrefix.contains("*"),
                  !foldedPrefix.contains("?") else {
                return true
            }
            if foldedPrefix == "com.apple"
                || foldedPrefix.hasPrefix("com.apple.")
                || foldedPrefix == "apple"
                || foldedPrefix.hasPrefix("apple.")
                || foldedPrefix == "0000000000"
                || Self.knownAppleFirstPartyTeamIds.contains(foldedPrefix.uppercased()) {
                return false
            }
            if let recordTeamLower, !recordTeamLower.isEmpty, foldedPrefix == recordTeamLower {
                return false
            }
            return true
        }

        let trimmedLowerGroups = record.appGroups.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
        let hasValidNoSandboxStockAppGroup: Bool = {
            guard !trimmedLowerGroups.isEmpty else { return false }
            let stockNoSandboxPrefixes = [
                "group.com.apple.", "systemgroup.com.apple.", "group.tvappservices.",
                "group.is.workflow.", "group.gm.", "group.sms.", "group.im.",
                "group.ams.", "group.icloud.", "com.apple."
            ]
            let hasAppleNS = trimmedLowerGroups.contains { grp in
                stockNoSandboxPrefixes.contains(where: { grp.hasPrefix($0) }) || grp == "group.tvappservices.container"
            }
            guard hasAppleNS else { return false }
            if lowerBid == "com.apple.reminders" {
                return trimmedLowerGroups.contains("group.com.apple.reminders")
            }
            // Prevent spoofed non-Reminders staged stock apps (e.g. `Tips` carrying only `group.com.apple.reminders`)
            let isOnlyRemindersGroup = trimmedLowerGroups.allSatisfy {
                $0 == "group.com.apple.reminders" || $0.hasPrefix("group.com.apple.reminders.")
            }
            return !isOnlyRemindersGroup
        }()

        // Genuine staged stock app with `no-sandbox = true` (e.g. iOS 26/27 Reminders v7.0+):
        // preserves real Apple groups/platform/Apple-keychain entitlements while still locking out
        // `container-required=false`, `no-container`, bare `*` / foreign keychain wildcards, and missing/foreign groups.
        let isGenuineAppleNoSandboxStockApp = Self.removableAppleStockBundleIds.contains(lowerBid)
            && isSystemAppType
            && (isSSVSystemPath || isStagedBundleContainerPath)
            && !isJailbreakSubpath
            && record.booleanEntitlements["com.apple.private.security.container-required"] != false
            && record.booleanEntitlements["com.apple.private.security.no-container"] != true
            && !hasDisallowedNoSandboxKeychainWildcard
            && hasValidNoSandboxStockAppGroup

        // Disallowed privileges for unknown/arbitrary `com.apple.*` staged bundles (never relaxes `com.apple.evil`)
        let hasDisallowedStagedPrivilegeForUnknownBundle =
            record.booleanEntitlements["com.apple.private.security.no-container"] == true
            || record.booleanEntitlements["com.apple.private.security.container-required"] == false
            || record.booleanEntitlements["com.apple.private.security.storage.AppDataContainers"] == true
            || (record.booleanEntitlements["com.apple.private.MobileContainerManager.allowed"] == true)
            || !dangerousKC.isEmpty
            || !raw2026Keys.isEmpty
            || !rawPhotosKeys.isEmpty

        let isAppleSystemUIServiceBundleId = lowerBid.hasPrefix("com.apple.") && (
            lowerBid.hasSuffix("uiservice")
            || lowerBid.hasSuffix("uiserviceapp")
            || lowerBid.hasSuffix("viewservice")
            || lowerBid.hasSuffix("viewserviceapp")
            || lowerBid.hasSuffix("angel")
        )

        // Genuine unsigned/CoreTrust-cached OS records may carry internal Apple Team IDs (often unlisted
        // in a static set when `installation_proxy` returns `TeamIdentifier`); reject unknown non-Apple
        // third-party bundles and explicitly conflicting non-Apple `no-sandbox` declarations.
        if let tid = record.teamId?.trimmingCharacters(in: .whitespacesAndNewlines), !tid.isEmpty {
            let upperTid = tid.uppercased()
            let isKnownAppleTeam = Self.knownAppleFirstPartyTeamIds.contains(upperTid)
            if !isKnownAppleTeam {
                let explicitEntTeam = record.stringEntitlements["com.apple.developer.team-identifier"]?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let hasUnlistedExplicitEntTeam = !explicitEntTeam.isEmpty
                    && !Self.knownAppleFirstPartyTeamIds.contains(explicitEntTeam.uppercased())
                let isApplePlatformTeamBound = (
                    isSSVSystemPath && isSystemAppType && (
                        hasPlatformAppEnt
                        || hasValidComAppleAppId
                        || Self.canonicalRemovableAppleStockBundleIds.contains(lowerBid)
                        || isAppleSystemUIServiceBundleId
                    )
                ) || (
                    isStagedBundleContainerPath
                        && isSystemAppType
                        && !isJailbreakSubpath
                        && (
                            (
                                Self.canonicalRemovableAppleStockBundleIds.contains(lowerBid)
                                && (!hasFullSandboxDisable || (isGenuineAppleNoSandboxStockApp && (!hasUnlistedExplicitEntTeam || hasDotQualifiedValidComAppleAppId)))
                            ) || (
                                !hasFullSandboxDisable
                                && !hasDisallowedStagedPrivilegeForUnknownBundle
                                && (!hasUnlistedExplicitEntTeam || hasDotQualifiedValidComAppleAppId)
                                && (isAppleSystemUIServiceBundleId || record.hasAppStoreMetadata)
                            )
                        )
                )
                if !isApplePlatformTeamBound {
                    return false
                }
            }
        }

        if isSSVSystemPath && isSystemAppType {
            return true
        }

        // Preinstalled removable Apple stock apps staged in `/private/var/containers/Bundle/Application/<UUID>/`:
        // genuine Apple stock apps may declare Apple private entitlements (`MobileGestalt`, `Photos`, `mediaexperience`,
        // `itunesstored.private`, `MCM`, `AppDataContainers`, `com.apple.*` keychain, `no-container` on MobileSMS, etc.).
        if isSystemAppType
            && (isSSVSystemPath || isStagedBundleContainerPath)
            && !isJailbreakSubpath
            && !hasFullSandboxDisable
            && !hasDisallowedNoSandboxKeychainWildcard {
            if Self.removableAppleStockBundleIds.contains(lowerBid) {
                return true
            }
            if Self.canonicalRemovableAppleStockBundleIds.contains(lowerBid)
                && record.booleanEntitlements["com.apple.private.security.no-container"] != true {
                return true
            }
            if (record.hasAppStoreMetadata || isAppleSystemUIServiceBundleId)
                && !hasDisallowedStagedPrivilegeForUnknownBundle {
                return true
            }
        }
        if isGenuineAppleNoSandboxStockApp {
            return true
        }

        // User-writable bundle container paths (`/var/containers/Bundle/Application/...`, where TrollStore "Switch to System
        // Registration" flips `ApplicationType` to `"System"`) NEVER trust unverified records with escape/private entitlements.
        if hasAnyDangerousRegistryEntitlement(record, assumingUnverifiedIdentity: true) || hasPlatformAppEnt {
            return false
        }

        if appType == "system"
            && (isSSVSystemPath || isStagedBundleContainerPath)
            && !isJailbreakSubpath
            && Self.canonicalRemovableAppleStockBundleIds.contains(lowerBid) {
            return true
        }

        return false
    }

    struct PathHazardFlags {
        let hasJailbreakMarker: Bool
        let isNonCryptexPreboot: Bool
        let isDeveloperMount: Bool
        let hasTraversal: Bool
        let hasControlChar: Bool

        var hasAny: Bool {
            hasJailbreakMarker || isNonCryptexPreboot || isDeveloperMount || hasTraversal || hasControlChar
        }
    }

    static func isAdHocOrLdidSigner(_ signer: String?) -> Bool {
        let lower = signer?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        guard !lower.isEmpty else { return false }
        return lower == "ad hoc"
            || lower.contains("ad hoc")
            || lower.contains("ad-hoc")
            || lower.contains("adhoc")
            || lower.contains("ldid")
            || lower.contains("trollstore")
    }

    static func containsASCIIControlCharacter(_ value: String) -> Bool {
        value.utf8.contains { $0 <= 0x1F || $0 == 0x7F }
    }

    @inline(__always)
    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        if byte >= 0x30 && byte <= 0x39 { return byte &- 0x30 }
        if byte >= 0x41 && byte <= 0x46 { return byte &- 0x37 }
        if byte >= 0x61 && byte <= 0x66 { return byte &- 0x57 }
        return nil
    }

    private static func withUTF8Buffer<R>(_ string: String, _ body: (UnsafeBufferPointer<UInt8>) -> R) -> R {
        if let result = string.utf8.withContiguousStorageIfAvailable(body) {
            return result
        }
        let copy = Array(string.utf8)
        return copy.withUnsafeBufferPointer(body)
    }

    private static func firstValidPercentIndex(in bytes: UnsafeBufferPointer<UInt8>) -> Int? {
        let count = bytes.count
        guard count >= 3 else { return nil }
        let limit = count &- 2
        var i = 0
        while i < limit {
            if bytes[i] == 0x25,
               hexNibble(bytes[i &+ 1]) != nil,
               hexNibble(bytes[i &+ 2]) != nil {
                return i
            }
            i &+= 1
        }
        return nil
    }

    private static func trimOuterWhitespace(_ raw: String) -> String {
        guard !raw.isEmpty else { return raw }
        let utf8 = raw.utf8
        let first = utf8[utf8.startIndex]
        let last = utf8[utf8.index(before: utf8.endIndex)]
        if first > 0x20 && first < 0x80 && last > 0x20 && last < 0x80 {
            return raw
        }
        return raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func containsDotDotPathSegment(_ value: String) -> Bool {
        let trimmed = trimOuterWhitespace(value)
        return withUTF8Buffer(trimmed) { bytes in
            let count = bytes.count
            guard count >= 2 else { return false }
            var hasConsecutiveDots = false
            var j = 0
            while j < count &- 1 {
                if bytes[j] == 0x2E && bytes[j &+ 1] == 0x2E {
                    hasConsecutiveDots = true
                    break
                }
                j &+= 1
            }
            guard hasConsecutiveDots else { return false }

            var segStart = 0
            var i = 0
            while i <= count {
                if i == count || bytes[i] == 0x2F || bytes[i] == 0x5C {
                    if i &- segStart == 2 && bytes[segStart] == 0x2E && bytes[segStart &+ 1] == 0x2E {
                        return true
                    }
                    segStart = i &+ 1
                }
                i &+= 1
            }
            return false
        }
    }

    @inline(__always)
    private static func lowerASCIIByte(_ b: UInt8, fold: Bool) -> UInt8 {
        if fold && b >= 0x41 && b <= 0x5A {
            return b &+ 0x20
        }
        return b
    }

    @inline(__always)
    private static func matchesASCIIPrefix(
        _ bytes: UnsafeBufferPointer<UInt8>,
        at index: Int,
        literal: StaticString,
        foldASCII: Bool
    ) -> Bool {
        let len = literal.utf8CodeUnitCount
        guard index &+ len <= bytes.count else { return false }
        let litPtr = literal.utf8Start
        var k = 0
        while k < len {
            if lowerASCIIByte(bytes[index &+ k], fold: foldASCII) != litPtr[k] {
                return false
            }
            k &+= 1
        }
        return true
    }

    private static func hasLegitimatePrebootMount(
        in bytes: UnsafeBufferPointer<UInt8>,
        atPrebootSlash index: Int,
        foldASCII: Bool
    ) -> Bool {
        let count = bytes.count
        let after = index &+ 9 // right after "/preboot/"
        let afterLen = count &- after
        guard afterLen > 0 else { return false }

        if afterLen >= 10 && matchesASCIIPrefix(bytes, at: after, literal: "cryptexes/", foldASCII: foldASCII) {
            return true
        }
        if afterLen == 9 && matchesASCIIPrefix(bytes, at: after, literal: "cryptexes", foldASCII: foldASCII) {
            return true
        }
        if afterLen >= 7 && matchesASCIIPrefix(bytes, at: after, literal: "active/", foldASCII: foldASCII) {
            return true
        }
        if afterLen == 6 && matchesASCIIPrefix(bytes, at: after, literal: "active", foldASCII: foldASCII) {
            return true
        }

        // Boot-manifest hash mount: `/private/preboot/<HEX_OR_UUID >= 16>/...`
        var segEnd = after
        while segEnd < count && bytes[segEnd] != 0x2F {
            let b = lowerASCIIByte(bytes[segEnd], fold: foldASCII)
            let isHexOrDash = (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x66) || b == 0x2D
            if !isHexOrDash {
                return false
            }
            segEnd &+= 1
        }
        return segEnd &- after >= 16 && (segEnd == count || bytes[segEnd] == 0x2F)
    }

    private static func inspectDirectUTF8Hazards(
        in bytes: UnsafeBufferPointer<UInt8>,
        foldASCII: Bool
    ) -> PathHazardFlags {
        let count = bytes.count
        var hasJailbreak = false
        var sawPreboot = false
        var sawLegitimatePrebootMount = false
        var isDeveloperMount = false

        if count >= 10 && matchesASCIIPrefix(bytes, at: 0, literal: "/developer", foldASCII: foldASCII) {
            if count == 10 || bytes[10] == 0x2F {
                isDeveloperMount = true
            }
        }

        var i = 0
        while i < count {
            if bytes[i] == 0x2F {
                let rem = count &- i
                if !hasJailbreak {
                    if rem >= 3 && matchesASCIIPrefix(bytes, at: i, literal: "/jb", foldASCII: foldASCII) {
                        if rem == 3 || bytes[i &+ 3] == 0x2F || bytes[i &+ 3] == 0x2D {
                            hasJailbreak = true
                        }
                    } else if rem >= 7 && matchesASCIIPrefix(bytes, at: i, literal: "/var/jb", foldASCII: foldASCII) {
                        if rem == 7 || bytes[i &+ 7] == 0x2F {
                            hasJailbreak = true
                        }
                    } else if rem >= 9 && matchesASCIIPrefix(bytes, at: i, literal: "/dopamine", foldASCII: foldASCII) {
                        hasJailbreak = true
                    } else if rem >= 10 && matchesASCIIPrefix(bytes, at: i, literal: "/procursus", foldASCII: foldASCII) {
                        hasJailbreak = true
                    }
                }
                if !sawLegitimatePrebootMount && rem >= 9 && matchesASCIIPrefix(bytes, at: i, literal: "/preboot/", foldASCII: foldASCII) {
                    sawPreboot = true
                    if hasLegitimatePrebootMount(in: bytes, atPrebootSlash: i, foldASCII: foldASCII) {
                        sawLegitimatePrebootMount = true
                    }
                }
                if hasJailbreak && sawLegitimatePrebootMount && isDeveloperMount {
                    break
                }
            }
            i &+= 1
        }

        return PathHazardFlags(
            hasJailbreakMarker: hasJailbreak,
            isNonCryptexPreboot: sawPreboot && !sawLegitimatePrebootMount,
            isDeveloperMount: isDeveloperMount,
            hasTraversal: false,
            hasControlChar: false
        )
    }

    private static func inspectDirectCandidatePathHazards(_ candidate: String) -> PathHazardFlags {
        let isAllASCII = candidate.utf8.allSatisfy { $0 < 0x80 }
        if isAllASCII {
            return withUTF8Buffer(candidate) { inspectDirectUTF8Hazards(in: $0, foldASCII: true) }
        }
        return inspectDirectLowerPathHazards(candidate.lowercased())
    }

    private static func mayDifferUnderCollapse(_ trimmed: String) -> Bool {
        withUTF8Buffer(trimmed) { bytes in
            let count = bytes.count
            guard count > 0 else { return true }
            if bytes[0] != 0x2F { return true }
            var i = 0
            while i < count {
                if bytes[i] == 0x2F {
                    if i &+ 1 < count {
                        let next = bytes[i &+ 1]
                        if next == 0x2F || next == 0x2E {
                            return true
                        }
                    } else if count > 1 {
                        return true
                    }
                }
                i &+= 1
            }
            return false
        }
    }

    private static func percentDecodeValidSequences(_ raw: String) -> String {
        guard raw.utf8.contains(0x25) else { return raw }
        return withUTF8Buffer(raw) { bytes in
            guard let firstPct = firstValidPercentIndex(in: bytes) else {
                return raw
            }
            let count = bytes.count
            var out: [UInt8] = []
            out.reserveCapacity(count)
            if firstPct > 0 {
                out.append(contentsOf: bytes[0..<firstPct])
            }
            var i = firstPct
            while i < count {
                if bytes[i] == 0x25, i &+ 2 < count,
                   let hi = hexNibble(bytes[i &+ 1]),
                   let lo = hexNibble(bytes[i &+ 2]) {
                    out.append((hi << 4) | lo)
                    i &+= 3
                } else {
                    out.append(bytes[i])
                    i &+= 1
                }
            }
            return String(decoding: out, as: UTF8.self)
        }
    }

    /// Iteratively percent-decodes `raw` up to `maxPasses` times until reaching a fixed point.
    /// Reports `didConverge == false` when decoding continues to mutate past `maxPasses` (fail-closed obfuscation signal).
    static func percentDecodedPathVariants(_ raw: String, maxPasses: Int = 6) -> (variants: [String], didConverge: Bool) {
        var variants: [String] = [raw]
        variants.reserveCapacity(maxPasses + 1)
        var current = raw
        var didConverge = false
        for _ in 0..<maxPasses {
            let decoded = percentDecodeValidSequences(current)
            if decoded == current {
                didConverge = true
                break
            }
            variants.append(decoded)
            current = decoded
        }
        if !didConverge {
            didConverge = !withUTF8Buffer(current) { firstValidPercentIndex(in: $0) != nil }
        }
        return (variants: variants, didConverge: didConverge)
    }

    static func inspectDirectLowerPathHazards(_ lowerPath: String) -> PathHazardFlags {
        withUTF8Buffer(lowerPath) { inspectDirectUTF8Hazards(in: $0, foldASCII: false) }
    }

    static func inspectPathHazards(_ raw: String) -> PathHazardFlags {
        var hasJailbreak = false
        var isNonCryptexPreboot = false
        var isDeveloperMount = false
        let (variants, didConverge) = percentDecodedPathVariants(raw)
        var hasTraversal = !didConverge
        var hasControlChar = false

        for variant in variants {
            if !hasControlChar && containsASCIIControlCharacter(variant) {
                hasControlChar = true
            }
            if !hasTraversal && containsDotDotPathSegment(variant) {
                hasTraversal = true
            }
            if hasControlChar && hasTraversal {
                break
            }
        }

        // When decoding fails to converge within `maxPasses`, `hasTraversal` is already `true`;
        // inspect only `raw` and the final decoded variant for direct path markers to avoid
        // repeating 60 KB normalizations across intermediate passes.
        let markerVariants: [String]
        if didConverge || variants.count <= 2 {
            markerVariants = variants
        } else {
            markerVariants = [variants[0], variants[variants.count - 1]]
        }

        var seen: Set<String> = []
        for variant in markerVariants {
            if hasJailbreak && isNonCryptexPreboot && isDeveloperMount {
                break
            }
            let hasBackslash = variant.utf8.contains(0x5C)
            let slashForms: [String] = hasBackslash
                ? [variant, variant.replacingOccurrences(of: "\\", with: "/")]
                : [variant]
            for form in slashForms {
                let trimmed = trimOuterWhitespace(form)
                let needsCollapse = mayDifferUnderCollapse(trimmed)
                let needsStandardize = (trimmed != form) || containsDotDotPathSegment(trimmed)

                @inline(__always)
                func checkCandidate(_ candidate: String) {
                    if markerVariants.count > 1 || needsCollapse || needsStandardize || hasBackslash {
                        guard seen.insert(candidate).inserted else { return }
                    }
                    let direct = inspectDirectCandidatePathHazards(candidate)
                    if direct.hasJailbreakMarker { hasJailbreak = true }
                    if direct.isNonCryptexPreboot { isNonCryptexPreboot = true }
                    if direct.isDeveloperMount { isDeveloperMount = true }
                }

                checkCandidate(trimmed)
                if needsCollapse {
                    let collapsed = collapsedDotSlashPath(trimmed)
                    if collapsed != trimmed {
                        checkCandidate(collapsed)
                    }
                }
                if needsStandardize {
                    let standardized = standardizedAbsolutePath(form)
                    if standardized != trimmed {
                        checkCandidate(standardized)
                    }
                }
            }
        }
        return PathHazardFlags(
            hasJailbreakMarker: hasJailbreak,
            isNonCryptexPreboot: isNonCryptexPreboot,
            isDeveloperMount: isDeveloperMount,
            hasTraversal: hasTraversal,
            hasControlChar: hasControlChar
        )
    }

    /// Lexically collapses empty (`//`) and current-directory (`/./`) segments WITHOUT resolving `..`,
    /// preserving intermediate path-prefix markers (e.g., `/./Developer/../../...`, `///Developer/...`).
    static func collapsedDotSlashPath(_ raw: String) -> String {
        let trimmed = trimOuterWhitespace(raw)
        guard !trimmed.isEmpty else { return "/" }
        var comps: [Substring] = []
        for slice in trimmed.utf8.split(separator: 0x2F, omittingEmptySubsequences: true) {
            if slice.count == 1 && slice[slice.startIndex] == 0x2E {
                continue
            }
            comps.append(trimmed[slice.startIndex..<slice.endIndex])
        }
        return "/" + comps.joined(separator: "/")
    }

    /// Returns `true` if `raw` (or any bounded iterative percent-decoding of `raw`) contains a `..` traversal segment,
    /// contains NUL/ASCII control characters (`0x00...0x1F`, `0x7F`), or fails to converge within `maxPasses`.
    static func hasDotDotSegment(_ raw: String) -> Bool {
        let (variants, didConverge) = percentDecodedPathVariants(raw)
        if !didConverge {
            return true
        }
        for variant in variants {
            if containsASCIIControlCharacter(variant) || containsDotDotPathSegment(variant) {
                return true
            }
        }
        return false
    }

    /// Lexically resolves `.` / `..` / duplicate separators WITHOUT touching the file system
    /// (unlike `NSString.standardizingPath`, whose `/private` handling depends on the host).
    static func standardizedAbsolutePath(_ raw: String) -> String {
        var stack: [Substring] = []
        for slice in raw.utf8.split(separator: 0x2F, omittingEmptySubsequences: true) {
            if slice.count == 1 && slice[slice.startIndex] == 0x2E {
                continue
            }
            if slice.count == 2 {
                let first = slice[slice.startIndex]
                let second = slice[slice.index(after: slice.startIndex)]
                if first == 0x2E && second == 0x2E {
                    if !stack.isEmpty { stack.removeLast() }
                    continue
                }
            }
            stack.append(raw[slice.startIndex..<slice.endIndex])
        }
        return "/" + stack.joined(separator: "/")
    }

    /// Identifies third-party sideloading signers/managers for zero-trust risk attribution (NEVER auto-whitelisted).
    public static func matchKnownSideloadInfrastructure(bundleId: String, displayName: String) -> String? {
        let lowerBid = bundleId.lowercased()
        let lowerName = displayName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        let rules: [(name: String, bidSubstrings: [String], exactNames: [String])] = [
            ("Feather", ["kh.crysalis.feather", "thewonderofyou.feather"], ["feather"]),
            ("LocalDevVPN", ["localdevvpn"], ["localdevvpn"]),
            ("StikDebug", ["stikdebug", "stikjit", "com.stik.sj"], ["stikdebug", "stikjit"]),
            ("SideStore", ["com.sidestore.sidestore", "sidestore"], ["sidestore"]),
            ("AltStore", ["com.rileytestut.altstore"], ["altstore"]),
            (WQLocale.pick(en: "ESign", zh: "全能签 / ESign"), ["yyyue.esign", "com.esign."], ["全能签", "esign"]),
            ("GBox", ["com.gbox.pub"], ["gbox"]),
            ("Scarlet", ["debianarch.scarlet", "usescarlet.scarlet"], ["scarlet"]),
            ("TrollStore", ["com.opa334.trollstore", "trollstore"], ["trollstore", "巨魔商店"])
        ]

        for rule in rules {
            if rule.bidSubstrings.contains(where: { lowerBid.contains($0) }) ||
               rule.exactNames.contains(lowerName) {
                return rule.name
            }
        }
        return nil
    }

    private static let restricted2026PrivateEntitlementPrefixes: [String] = [
        "com.apple.private.mediaexperience",
        "com.apple.private.cmsession",
        "com.apple.private.bookassetd",
        IOCTokenArmor.tStorePrivPrefix,
        "com.apple.private.MobileGestalt",
        "com.apple.private.accessorysetupkit"
    ]

    internal static func matchesRestricted2026PrivateEntitlementPrefix(_ key: String) -> Bool {
        restricted2026PrivateEntitlementPrefixes.contains { key.hasPrefix($0) }
    }

    private func rawRestricted2026EntitlementKeys(in record: InstalledAppRegistryRecord) -> [String] {
        let candidateKeys = Set(record.allEntitlementKeys)
            .union(record.booleanEntitlements.keys)
            .union(record.stringEntitlements.keys)
            .sorted()
        return candidateKeys.filter { key in
            guard Self.matchesRestricted2026PrivateEntitlementPrefix(key) else {
                return false
            }
            return record.booleanEntitlements[key] == true
                || (record.stringEntitlements[key] != nil)
                || (record.allEntitlementKeys.contains(key) && record.booleanEntitlements[key] != false)
        }
    }

    /// Returns restricted 2026 private bypass entitlement keys held by a non-Apple app record,
    /// ignoring explicit `false` / integer `0` values and genuine Apple system/first-party apps.
    public func restricted2026BypassEntitlements(for record: InstalledAppRegistryRecord) -> [String] {
        guard !isAppleSystemOrFirstPartyApp(record) else {
            return []
        }
        return rawRestricted2026EntitlementKeys(in: record)
    }

    /// Returns `true` when a non-Apple app record holds any restricted 2026 private bypass entitlement.
    public func hasRestricted2026PrivateEntitlements(_ record: InstalledAppRegistryRecord) -> Bool {
        !restricted2026BypassEntitlements(for: record).isEmpty
    }

    private func allowedOwnKeychainPrefixes(for record: InstalledAppRegistryRecord) -> Set<String> {
        let signerLower = record.signerIdentity?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        let isAdHocOrUnsigned = Self.isAdHocOrLdidSigner(record.signerIdentity)
        let hasProvisionedOrStoreIdentity = !isAdHocOrUnsigned && (
            record.profileValidated
            || signerLower == "apple iphone os application signing"
            || signerLower == "testflight beta distribution"
            || signerLower == "apple testflight beta distribution"
            || signerLower == "software signing"
        )
        guard hasProvisionedOrStoreIdentity else { return [] }
        var rawEnts: [String: Any] = [:]
        if let tid = record.stringEntitlements["com.apple.developer.team-identifier"] {
            rawEnts["com.apple.developer.team-identifier"] = tid
        }
        if let appId = record.stringEntitlements["application-identifier"] {
            rawEnts["application-identifier"] = appId
        }
        return ExpandedThreatCatalog.extractOwnTeamPrefixes(from: rawEnts, explicitTeamId: record.teamId)
    }

    private func hasAnyDangerousRegistryEntitlement(
        _ record: InstalledAppRegistryRecord,
        assumingUnverifiedIdentity: Bool = false,
        isTrustedAppleRecord: Bool? = nil
    ) -> Bool {
        let isTrustedApple = assumingUnverifiedIdentity
            ? false
            : (isTrustedAppleRecord ?? isAppleSystemOrFirstPartyApp(record))
        if record.booleanEntitlements["com.apple.private.security.no-container"] == true ||
           record.booleanEntitlements["com.apple.private.security.no-sandbox"] == true ||
           record.booleanEntitlements["com.apple.private.security.container-required"] == false ||
           record.booleanEntitlements["com.apple.private.MobileContainerManager.allowed"] == true ||
           record.booleanEntitlements["com.apple.private.security.storage.AppDataContainers"] == true ||
           (record.booleanEntitlements["platform-application"] == true && !isTrustedApple) ||
           !record.tccAllowedServices.isEmpty ||
           !rawRestricted2026EntitlementKeys(in: record).isEmpty {
            return true
        }
        let allowedKC = assumingUnverifiedIdentity ? Set<String>() : allowedOwnKeychainPrefixes(for: record)
        if !ExpandedThreatCatalog.dangerousWildcardKeychainGroups(record.keychainAccessGroups, allowedOwnTeamPrefixes: allowedKC).isEmpty {
            return true
        }
        let candidateKeys = Set(record.allEntitlementKeys)
            .union(record.booleanEntitlements.keys)
            .union(record.stringEntitlements.keys)
        for key in candidateKeys {
            if key.hasPrefix(ExpandedThreatCatalog.photosEntitlementPrefix) ||
               key == ExpandedThreatCatalog.photosBourgeoisieEntitlement {
                if record.booleanEntitlements[key] != false {
                    return true
                }
            }
        }
        return false
    }

    public func classifyChannel(for record: InstalledAppRegistryRecord) -> (channel: InstallChannel, isFairPlayEncrypted: Bool) {
        classifyChannel(for: record, isTrustedAppleRecord: isAppleSystemOrFirstPartyApp(record))
    }

    private func classifyChannel(
        for record: InstalledAppRegistryRecord,
        isTrustedAppleRecord: Bool
    ) -> (channel: InstallChannel, isFairPlayEncrypted: Bool) {
        if isTrustedAppleRecord {
            return (.appStore, true)
        }

        if record.booleanEntitlements["get-task-allow"] == true {
            return (.developerSideloaded, false)
        }

        let signerLower = record.signerIdentity?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() ?? ""

        // 1. Check explicit developer / ad-hoc signers FIRST so leftover `iTunesMetadata.plist` (`ApplicationDSID > 0`)
        //    on a repackaged wallet/messenger can never spoof `.appStore`.
        if signerLower.contains("apple development") || signerLower.contains("iphone developer") {
            return (.developerSideloaded, false)
        }
        if Self.isAdHocOrLdidSigner(record.signerIdentity) {
            return (.developerSideloaded, false)
        }

        // 2. TestFlight Beta builds:
        //    Official Apple TestFlight cloud-re-signed binaries carry `SignerIdentity == "TestFlight Beta Distribution"`
        //    (or `"Apple TestFlight Beta Distribution"`, or `"Apple iPhone OS Application Signing"` with `ProfileValidated == true`).
        //    Third-party `"Apple Distribution:"` / `"iPhone Distribution:"` / `"iOS Distribution:"` signers MUST NOT classify as `.testFlight`.
        let hasDangerousPrivateEscape = hasAnyDangerousRegistryEntitlement(
            record,
            isTrustedAppleRecord: false
        )
        if !hasDangerousPrivateEscape {
            let isOfficialAppleTestFlightSigner = (signerLower == "testflight beta distribution")
                || (signerLower == "apple testflight beta distribution")
                || (record.profileValidated && signerLower == "apple iphone os application signing")
            if isOfficialAppleTestFlightSigner {
                return (.testFlight, true)
            }
        }

        // 3. Enterprise / Distribution profile builds
        if record.profileValidated && (signerLower.contains("distribution") || signerLower.contains("enterprise")) {
            return (.enterpriseInHouse, false)
        }

        // 4. Genuine Apple App Store release: requires cryptographic Apple App Store signer without provisioning profile.
        //    Unvalidated TrollStore / ad-hoc records (`signerIdentity == nil`) carrying `iTunesMetadata.plist` fall through to `.developerSideloaded`.
        if signerLower == "apple iphone os application signing" && !record.profileValidated {
            return (.appStore, true)
        }

        // Unvalidated user bundle (e.g., TrollStore ad-hoc ldid signed, distribution-resigned without profileValidated, or custom sideload)
        return (.developerSideloaded, false)
    }

    /// Evaluates whether an installed app record belongs to the non-App-Store / sideloaded / anomalous inspection scope.
    public func isSideloadedOrAnomalous(_ record: InstalledAppRegistryRecord) -> Bool {
        isSideloadedOrAnomalous(record, isTrustedAppleRecord: isAppleSystemOrFirstPartyApp(record))
    }

    private func isSideloadedOrAnomalous(
        _ record: InstalledAppRegistryRecord,
        isTrustedAppleRecord: Bool
    ) -> Bool {
        if isTrustedAppleRecord {
            return false
        }
        let (channel, _) = classifyChannel(for: record, isTrustedAppleRecord: false)
        if channel.isSideloadedOrEnterprise {
            return true
        }
        // Even if marked App Store, inspect if carrying dangerous private sandbox-escape, TCC, Photos, keychain wildcard, or 2026 bypass entitlements
        if hasAnyDangerousRegistryEntitlement(record, isTrustedAppleRecord: false) {
            return true
        }
        return false
    }

    /// Checks whether `record` represents the currently executing WQGuard host app on iOS whose
    /// `com.apple.security.application-groups` or enterprise `application-identifier` was rewritten
    /// during sideload/enterprise signing (e.g. by 全能签 / ESign / Feather / AltStore / SideStore),
    /// including when scanning a previously cached `installation_proxy` snapshot whose bundle UUID
    /// path predates an in-place app update, while still rejecting any `.highRisk` indicator,
    /// victim App Group squatting, unexpected signature, or disabled built-in `WQGuard` rule.
    internal func isEligibleSelfResignedWQGuard(
        _ record: InstalledAppRegistryRecord,
        provisionalRisk: RiskTier,
        matchedSignatures: Set<String>,
        selfBundleId: String
    ) -> String? {
        let cleanSelfBid = selfBundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanRecBid = record.bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanSelfBid.isEmpty else { return nil }
        let isMatchingHostBundleId = cleanRecBid.caseInsensitiveCompare(cleanSelfBid) == .orderedSame
            || (cleanRecBid.caseInsensitiveCompare("com.wqguard.app") == .orderedSame
                && record.displayName.trimmingCharacters(in: .whitespacesAndNewlines) == "WQGuard")
        guard isMatchingHostBundleId, provisionalRisk == .caution else { return nil }
        let hasDisallowedGroup = record.appGroups.contains {
            !PatternMatcher.isStrictIdentifierASCII($0)
                || ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup($0)
        }
        guard !hasDisallowedGroup else { return nil }
        guard let wqTool = whitelistEngine.tool(named: "WQGuard"), wqTool.isEnabled else { return nil }
        let nonGroupSigs = matchedSignatures.filter { $0 != "com.apple.security.application-groups" }
        let allExpected = nonGroupSigs.allSatisfy { sig in
            let cleanSig = sig.hasPrefix("_") ? String(sig.dropFirst()) : sig
            return wqTool.expectedSignatures.contains { pattern in
                let cleanPat = pattern.hasPrefix("_") ? String(pattern.dropFirst()) : pattern
                return PatternMatcher.matches(pattern: pattern, value: sig)
                    || PatternMatcher.matches(pattern: cleanPat, value: cleanSig)
            }
        }
        return allExpected ? wqTool.name : nil
    }

    /// Evaluates all relevant installed app records into `ScanFinding` items.
    public func evaluateRecords(
        _ records: [InstalledAppRegistryRecord],
        includeAppStoreApps: Bool = false
    ) -> [ScanFinding] {
        var findings: [ScanFinding] = []
        for rec in records {
            // Always exclude genuine Apple OS daemons, CoreServices UI services, and Apple system apps
            // so `includeAppStoreApps` strictly audits user-installed third-party App Store applications.
            if isAppleSystemOrFirstPartyApp(rec) {
                continue
            }
            if !includeAppStoreApps && !isSideloadedOrAnomalous(rec, isTrustedAppleRecord: false) {
                continue
            }
            findings.append(evaluateRecord(rec, isTrustedAppleRecord: false))
        }
        return findings
    }

    /// Performs full registry-level security evaluation on a single installed application record.
    public func evaluateRecord(_ record: InstalledAppRegistryRecord) -> ScanFinding {
        evaluateRecord(record, isTrustedAppleRecord: isAppleSystemOrFirstPartyApp(record))
    }

    private func evaluateRecord(
        _ record: InstalledAppRegistryRecord,
        isTrustedAppleRecord: Bool
    ) -> ScanFinding {
        let (channel, isFairPlay) = classifyChannel(for: record, isTrustedAppleRecord: isTrustedAppleRecord)
        let cryptid: UInt32 = isFairPlay ? 1 : 0
        var indicators: [ThreatIndicator] = []
        var matchedSignatures: Set<String> = []

        // 1. Sandbox Escape & Unsandboxed Execution Entitlements
        let escapeEntitlements: [(key: String, expectedBool: Bool, desc: String)] = [
            ("com.apple.private.security.no-container", true, WQLocale.pick(
                en: "Declares no-container entitlement, permitting direct cross-sandbox read/write access to other apps' data.",
                zh: "声明了无容器隔离私有权限 (no-container)，该已安装应用可直接跨沙盒读写全机应用数据！"
            )),
            ("com.apple.private.security.no-sandbox", true, WQLocale.pick(
                en: "Declares no-sandbox entitlement, bypassing iOS Seatbelt sandbox confinement completely.",
                zh: "声明了关闭 Seatbelt 沙盒私有权限 (no-sandbox)，完全脱离 iOS 沙盒隔离控制！"
            )),
            ("com.apple.private.security.container-required", false, WQLocale.pick(
                en: "Explicitly disables container enforcement (container-required=false), enabling unsandboxed execution.",
                zh: "显式关闭了容器强制约束 (container-required=false)，具备沙盒逃逸执行能力！"
            )),
            ("com.apple.private.MobileContainerManager.allowed", true, WQLocale.pick(
                en: "Declares direct private MobileContainerManager daemon privilege for querying/manipulating containers across apps.",
                zh: "声明了 MobileContainerManager 私有守护进程直连特权，可跨应用查询或操作容器！"
            )),
            ("com.apple.private.security.storage.AppDataContainers", true, WQLocale.pick(
                en: "Declares internal Apple AppDataContainers cross-application filesystem access entitlement.",
                zh: "声明了 Apple 内部跨应用数据容器直接访问权限 (AppDataContainers)！"
            ))
        ]
        for rule in escapeEntitlements {
            if record.booleanEntitlements[rule.key] == rule.expectedBool {
                indicators.append(ThreatIndicator(
                    signature: rule.key,
                    description: rule.desc,
                    category: "Sandbox Escape Entitlement",
                    location: "installation_proxy Entitlements",
                    severity: .highRisk
                ))
                matchedSignatures.insert(rule.key)
            }
        }

        if record.booleanEntitlements["platform-application"] == true && !isTrustedAppleRecord {
            indicators.append(ThreatIndicator(
                signature: "platform-application",
                description: WQLocale.pick(
                    en: "Non-Apple or unverified installed app declares Apple system platform privilege (platform-application=true).",
                    zh: "非官方或未验证已安装应用伪造声明了 Apple 平台级系统应用特权 (platform-application=true)！"
                ),
                category: "Privilege Escalation Entitlement",
                location: "installation_proxy Entitlements",
                severity: .highRisk
            ))
            matchedSignatures.insert("platform-application")
        }

        // 2. TCC Silent Privacy Bypass Entitlements
        if !record.tccAllowedServices.isEmpty {
            let joined = record.tccAllowedServices.joined(separator: ", ")
            indicators.append(ThreatIndicator(
                signature: "com.apple.private.tcc.allow",
                description: WQLocale.pick(
                    en: "Holds silent TCC privacy bypass entitlements (\(joined)), allowing background reads of Photos, Contacts, Microphone, or Pasteboard without consent prompts.",
                    zh: "已安装应用持有 TCC 隐私免授权特权 (\(joined))，可在不弹出系统授权框的情况下静默读取相册、通讯录、麦克风或剪贴板！"
                ),
                category: "TCC Privacy Bypass",
                location: "installation_proxy Entitlements",
                severity: .highRisk
            ))
            matchedSignatures.insert("com.apple.private.tcc.allow")
        }

        // 3. Private Photos & Restricted 2026 Bypass Entitlements
        var rawEntMap: [String: Any] = [:]
        for k in record.allEntitlementKeys {
            rawEntMap[k] = record.booleanEntitlements[k] ?? record.stringEntitlements[k] ?? true
        }
        for (k, v) in record.booleanEntitlements {
            rawEntMap[k] = v
        }
        for (k, v) in record.stringEntitlements {
            if rawEntMap[k] == nil {
                rawEntMap[k] = v
            }
        }
        let photoInds = ExpandedThreatCatalog.evaluatePhotosBypass(
            linkedDylibs: [],
            symbols: [],
            entitlements: rawEntMap,
            cryptid: cryptid
        )
        for p in photoInds {
            indicators.append(p)
            matchedSignatures.insert(p.signature)
        }

        if !isTrustedAppleRecord {
            let audioMxdInds = ExpandedThreatCatalog.evaluateAudioMxdBypass(
                linkedDylibs: [],
                symbols: [],
                entitlements: rawEntMap,
                cryptid: cryptid
            )
            for ind in audioMxdInds {
                indicators.append(ind)
                matchedSignatures.insert(ind.signature)
            }

            let bookGestaltInds = ExpandedThreatCatalog.evaluateBookRestoreAndGestalt(
                linkedDylibs: [],
                textStrings: [],
                entitlements: rawEntMap,
                cryptid: cryptid
            )
            for ind in bookGestaltInds {
                indicators.append(ind)
                matchedSignatures.insert(ind.signature)
            }

            // Non-Apple records in installation_proxy holding restricted com.apple.private.accessorysetupkit*
            // (even when disguised with App Store metadata) must be flagged .highRisk; Info.plist usage checks
            // still do not fire here since linkedDylibs/symbols are empty.
            let accessoryInds = ExpandedThreatCatalog.evaluateAccessorySetupBypass(
                linkedDylibs: [],
                symbols: [],
                infoPlist: [:],
                entitlements: rawEntMap,
                installChannel: .developerSideloaded,
                cryptid: cryptid
            )
            for ind in accessoryInds {
                indicators.append(ind)
                matchedSignatures.insert(ind.signature)
            }
        }

        // 4. Keychain Wildcard Access
        let dangerousKCGroups = ExpandedThreatCatalog.dangerousWildcardKeychainGroups(
            record.keychainAccessGroups,
            allowedOwnTeamPrefixes: allowedOwnKeychainPrefixes(for: record)
        )
        if !dangerousKCGroups.isEmpty {
            let kcDisplay = dangerousKCGroups.joined(separator: ", ")
            indicators.append(ThreatIndicator(
                signature: "keychain-access-groups(*)",
                description: WQLocale.pick(
                    en: "Declares wildcard keychain access groups (\(kcDisplay)), exposing cross-app credentials and private keys.",
                    zh: "已安装应用声明了通配符钥匙串访问组 (\(kcDisplay))，可跨应用窃取 Keychain 敏感登录凭证与私钥！"
                ),
                category: "Keychain Credential Exposure",
                location: "installation_proxy Entitlements",
                severity: .highRisk
            ))
            matchedSignatures.insert("keychain-access-groups(*)")
        }

        // 5. App Groups Cross-Container Surface (Layer 1 Gating)
        let gating = EntitlementGating.evaluate(hasAppGroups: !record.appGroups.isEmpty, appGroups: record.appGroups)
        if !gating.appGroups.isEmpty && channel.isSideloadedOrEnterprise {
            let appleGroupAbuse = gating.appGroups.filter { grp in
                !isTrustedAppleRecord && Self.isAppleOwnedAppGroup(grp)
            }
            if !appleGroupAbuse.isEmpty {
                let gStr = appleGroupAbuse.joined(separator: ", ")
                indicators.append(ThreatIndicator(
                    signature: "AppleSystemAppGroup(\(gStr))",
                    description: WQLocale.pick(
                        en: "Third-party sideloaded app binds Apple internal system App Groups (\(gStr)), indicating high-risk system configuration tampering.",
                        zh: "第三方侧载应用越权绑定了 Apple 系统共享容器组 (\(gStr))，高危系统配置篡改特征！"
                    ),
                    category: "Unauthorized System App Group",
                    location: "installation_proxy Entitlements",
                    severity: .highRisk
                ))
                matchedSignatures.insert("AppleSystemAppGroup")
            } else {
                let gStr = gating.appGroups.joined(separator: ", ")
                indicators.append(ThreatIndicator(
                    signature: "com.apple.security.application-groups",
                    description: WQLocale.pick(
                        en: "Installed sideloaded app declares shared App Groups (\(gStr)), satisfying the prerequisite for containermanagerd cross-sandbox attacks. Import the source .ipa to run deep binary inspection.",
                        zh: "已安装侧载应用声明了共享容器权限 (\(gStr))，满足触发 containermanagerd 跨沙盒漏洞的前置条件。建议手动选择对应 .ipa 文件加入扫描做进一步二进制符号排查。"
                    ),
                    category: "Shared Container Surface",
                    location: "installation_proxy Entitlements",
                    severity: .caution
                ))
            }
        }

        // 6. Repackaged Crypto Wallet & Messenger Impersonation (check both CFBundleIdentifier and any conflicting Entitlements application-identifier)
        let rawEntAppId = record.stringEntitlements["application-identifier"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        let (entBundleId, inferredEntTeamId) = IPAPackageScanner.extractEntitlementBundleIdentity(
            entitlements: rawEntAppId.map { ["application-identifier": $0] } ?? [:],
            explicitTeamId: nil
        )
        let hasConflictingRegistryBundleId = IPAPackageScanner.doesEntitlementBundleIdConflict(
            entBundleId: entBundleId,
            withPlistBundleId: record.bundleId
        )
        let hasConflictingRegistryTeamId: Bool = {
            guard let recTeam = record.teamId?.trimmingCharacters(in: .whitespacesAndNewlines), !recTeam.isEmpty,
                  let entTeam = inferredEntTeamId?.trimmingCharacters(in: .whitespacesAndNewlines), !entTeam.isEmpty else {
                return false
            }
            return recTeam.caseInsensitiveCompare(entTeam) != .orderedSame
        }()

        var candidateBrandBundleIds: [String] = [record.bundleId]
        if let eBid = entBundleId, eBid.caseInsensitiveCompare(record.bundleId) != .orderedSame {
            candidateBrandBundleIds.append(eBid)
        }
        var seenBrandImpSigs: Set<String> = []
        for candBid in candidateBrandBundleIds {
            let brandInds = ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: candBid,
                displayName: record.displayName,
                installChannel: channel,
                cryptid: cryptid
            )
            for b in brandInds where seenBrandImpSigs.insert(b.signature).inserted {
                indicators.append(b)
                matchedSignatures.insert(b.signature)
            }
        }

        if cryptid == 0 && channel.isSideloadedOrEnterprise {
            let trimmedOrigName = record.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
            let lowerName = trimmedOrigName.lowercased()
            let foldedLowerName = ExpandedThreatCatalog.foldConfusablesToASCII(trimmedOrigName).lowercased()
            let nameTokens = ExpandedThreatCatalog.extractBrandTokens(from: trimmedOrigName)
            let foldedCandBids = candidateBrandBundleIds.map { ExpandedThreatCatalog.foldConfusablesToASCII($0).lowercased() }
            for extra in Self.extraSideloadImpersonationTargets {
                let matchBid = foldedCandBids.contains { lowerBid in
                    extra.bundleIdPatterns.contains { pat in
                        lowerBid == pat || lowerBid.hasPrefix(pat + ".") || lowerBid.contains("." + pat + ".") || lowerBid.hasSuffix("." + pat)
                    }
                }
                let matchName = extra.displayNames.contains { pat in
                    let isASCII = pat.unicodeScalars.allSatisfy { $0.isASCII }
                    if isASCII && !pat.contains(" ") {
                        return lowerName == pat || foldedLowerName == pat || nameTokens.contains(pat)
                    }
                    return lowerName == pat || lowerName.contains(pat) || foldedLowerName == pat || foldedLowerName.contains(pat)
                }
                if matchBid || matchName {
                    let sig = "IMPERSONATION:\(extra.name)"
                    if !matchedSignatures.contains(sig) {
                        indicators.append(ThreatIndicator(
                            signature: sig,
                            description: WQLocale.pick(
                                en: "Sideloaded/Enterprise Warning: Installed app '\(record.displayName)' matches high-risk tampered target \(extra.name). \(extra.localizedDescription). Verify any injected tweaks and never enter payment passwords or seed phrases into untrusted builds.",
                                zh: "侧载/企业签高危提醒：已安装应用「\(record.displayName)」匹配高频被篡改应用 \(extra.name)。\(extra.description)。请确认注入插件来源可靠，切勿在来历不明的改版包中输入支付密码或助记词！"
                            ),
                            category: "Modded Messenger / Payment Risk",
                            location: "BundleID: \(record.bundleId), Signer: \(record.signerIdentity ?? "Unknown")",
                            severity: extra.name.contains("Alipay") ? .highRisk : .caution
                        ))
                        matchedSignatures.insert(sig)
                    }
                }
            }
        }

        // 7. Persistent Background Execution Modes on Sideloaded Apps
        if channel.isSideloadedOrEnterprise {
            let persistent = record.backgroundModes
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                .filter { ExpandedThreatCatalog.backgroundModesRequiringInspection.contains($0) }
            if !persistent.isEmpty {
                let mStr = persistent.joined(separator: ", ")
                let bgSig = "UIBackgroundModes(\(mStr))"
                indicators.append(ThreatIndicator(
                    signature: bgSig,
                    description: WQLocale.pick(
                        en: "Sideloaded app declares persistent background execution modes (\(mStr)). Combined with UIPasteboard this can silently harvest copied credentials; correlate the .ipa for binary inspection.",
                        zh: "已安装侧载应用开启了常驻后台模式 (\(mStr))。若配合剪贴板接口可在后台静默窃取复制的助记词/密码，建议关联本地 IPA 核验二进制符号。"
                    ),
                    category: "Persistent Background Execution",
                    location: "installation_proxy Info.plist",
                    severity: .caution
                ))
                matchedSignatures.insert(bgSig)
            }
        }

        // 7b. Strict Zero Trust on Third-Party Sideloading & Developer Infrastructure
        // Even when a third-party signer/debugger (e.g. ESign, Scarlet, GBox, Feather, SideStore, AltStore, LocalDevVPN, StikDebug, TrollStore)
        // omits `application-groups`, it must surface as `.caution` rather than `.safe` and must never be auto-whitelisted.
        if channel.isSideloadedOrEnterprise,
           let sideloadInfraName = Self.matchKnownSideloadInfrastructure(bundleId: record.bundleId, displayName: record.displayName) {
            let infraSig = "SideloadTool(\(sideloadInfraName))"
            indicators.append(ThreatIndicator(
                signature: infraSig,
                description: WQLocale.pick(
                    en: "Detected third-party sideloading or debugging tool '\(sideloadInfraName)'. Under WQGuard's strict zero-trust policy, third-party sideload utilities are never auto-whitelisted; verify installer origin and re-signed packages.",
                    zh: "检测到第三方侧载签名/调试工具「\(sideloadInfraName)」。WQGuard 对所有第三方侧载工具严格执行零信任策略（绝不默认加白），请确认安装包来源可信并留意重签环境安全。"
                ),
                category: "Third-Party Sideload Infrastructure",
                location: "installation_proxy (\(record.bundleId))",
                severity: .caution
            ))
            matchedSignatures.insert(infraSig)
        }

        // 8. Risk Tier & Whitelist Resolution (Strict Zero Trust: ONLY explicit WhitelistEngine rules grant .knownTool)
        var provisionalRisk: RiskTier = .safe
        if indicators.contains(where: { $0.severity == .highRisk }) {
            provisionalRisk = .highRisk
        } else if indicators.contains(where: { $0.severity == .caution }) {
            provisionalRisk = .caution
        }

        let isRegistryWhitelistEligible = !hasConflictingRegistryBundleId && !hasConflictingRegistryTeamId
        let signerLowerForTeam = record.signerIdentity?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        let isAdHocOrUnsignedRegistrySigner = Self.isAdHocOrLdidSigner(record.signerIdentity)
        let isRegistryTeamVerified: Bool
        if let recTeam = record.teamId?.trimmingCharacters(in: .whitespacesAndNewlines), !recTeam.isEmpty {
            isRegistryTeamVerified = !hasConflictingRegistryTeamId
                && !isAdHocOrUnsignedRegistrySigner
                && (record.profileValidated
                    || signerLowerForTeam == "apple iphone os application signing"
                    || signerLowerForTeam == "testflight beta distribution"
                    || signerLowerForTeam == "apple testflight beta distribution"
                    || signerLowerForTeam == "software signing")
        } else {
            isRegistryTeamVerified = true
        }
        let whitelistCandidateTeam: String? = isRegistryTeamVerified ? record.teamId : nil

        var isWhitelisted = false
        var whitelistedToolName: String? = nil
        var finalRisk = provisionalRisk

        if isRegistryWhitelistEligible {
            let wlResult = whitelistEngine.isWhitelisted(
                bundleId: record.bundleId,
                appGroups: gating.appGroups,
                matchedSignatures: Array(matchedSignatures),
                teamId: whitelistCandidateTeam
            )
            if wlResult.isWhitelisted {
                isWhitelisted = true
                whitelistedToolName = wlResult.toolName
                finalRisk = .knownTool
            }
        }
        if !isWhitelisted {
            #if os(iOS)
            let runningSelfBid = Bundle.main.bundleIdentifier ?? "com.wqguard.app"
            #else
            let runningSelfBid = ""
            #endif
            if let selfToolName = isEligibleSelfResignedWQGuard(
                record,
                provisionalRisk: provisionalRisk,
                matchedSignatures: matchedSignatures,
                selfBundleId: runningSelfBid
            ) {
                isWhitelisted = true
                whitelistedToolName = selfToolName
                finalRisk = .knownTool
            }
        }

        let remediation: String
        switch finalRisk {
        case .highRisk:
            remediation = WQLocale.pick(
                en: "System registry audit detected high-risk privilege escalation (unsandboxed entitlements, TCC bypass, or wallet/payment impersonation). Delete immediately and remove the signing profile in Settings -> General -> VPN & Device Management.",
                zh: "系统注册表审计发现高危越权特征（无沙盒特权、TCC 免授权隐私绕过或高危仿冒客户端），建议立即在桌面长按卸载并前往「设置 -> 通用 -> VPN 与设备管理」移除对应证书/描述文件。"
            )
        case .knownTool:
            remediation = WQLocale.pick(
                en: "Installed application matches trusted whitelist rule (\(whitelistedToolName ?? "Known Tool")) at system registry audit depth.",
                zh: "已安装应用匹配受信任白名单规则（\(whitelistedToolName ?? "Known Tool")）。当前为系统注册表权限审计结果。"
            )
        case .caution:
            remediation = WQLocale.pick(
                en: "Installed sideloaded app declares shared App Group containers, background modes, or third-party sideload traits. Add the matching .ipa file to correlate full binary symbol inspection.",
                zh: "已安装侧载应用包含共享容器权限、常驻后台或改版特征。可手动选择对应 .ipa 安装包加入扫描列表自动按 Bundle ID 完成二进制深度复核。"
            )
        case .safe:
            remediation = WQLocale.pick(
                en: "Registry entitlements and signing chain verified: no App Groups or privileged sandbox-bypass entitlements declared (registry-level audit without local IPA binary).",
                zh: "系统注册表权限与签名链核验通过：未声明 App Group 共享容器或任何越权私有 Entitlements（当前为注册表级审计，无本地 IPA 二进制）。"
            )
        }

        let evidence = AuditEvidence(
            matchedSymbols: Array(matchedSignatures).sorted(),
            linkedDylibs: [],
            hasAppGroups: !gating.appGroups.isEmpty,
            appGroups: gating.appGroups,
            installChannel: channel,
            cryptid: cryptid,
            isFairPlayEncrypted: isFairPlay,
            escapingSymlinks: [],
            dynamicLoadingPresent: false,
            pathEnumerationPresent: false,
            remediationGuidance: remediation,
            auditDepth: .registryEntitlements,
            signerIdentity: record.signerIdentity,
            isWhitelistEligible: isRegistryWhitelistEligible,
            isTeamIdWhitelistVerified: isRegistryTeamVerified
        )

        return ScanFinding(
            bundleId: record.bundleId,
            displayName: record.displayName,
            version: record.version,
            teamId: record.teamId,
            executablePath: nil,
            bundlePath: record.bundlePath,
            installChannel: channel,
            riskTier: finalRisk,
            isWhitelisted: isWhitelisted,
            whitelistedToolName: whitelistedToolName,
            indicators: indicators,
            evidence: evidence,
            scanTimestamp: Date()
        )
    }
}
