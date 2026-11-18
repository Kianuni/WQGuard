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
        if (dict["BetaApp"] as? Bool == true) || (dict["IsTestFlight"] as? Bool == true) {
            boolEnts["beta-reports-active"] = true
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
        let bundlePath = (dict["Path"] as? String) ?? "/var/containers/Bundle/Application/\(bundleId)"
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
        let resolvedBundlePath: String = {
            if let urlStr = dict["url"] as? String, let u = URL(string: urlStr), u.isFileURL {
                return u.path
            }
            if let container = dict["bundleContainerPath"] as? String, !container.isEmpty {
                return container
            }
            return isDefaultApp ? "/Applications/\(bundleId).app" : "/var/containers/Bundle/Application/\(bundleId)"
        }()

        let lowerBundlePath = resolvedBundlePath.lowercased()
        let isTrollStoreOrJailbreakPath = lowerBundlePath.contains("/var/jb/")
            || lowerBundlePath.contains("/preboot/")
            || (!isDefaultApp && !isInternalApp && lowerBundlePath.hasPrefix("/applications/"))

        let isEnterpriseFlag = (dict["enterpriseApp"] as? Bool == true) || (dict["isEnterpriseApp"] as? Bool == true)
        let isAdHocFlag = (dict["adHoc"] as? Bool == true) || (dict["isAdHoc"] as? Bool == true)
        let explicitNotAppStore = (dict["fromAppStore"] as? Bool == false)
            || (dict["isAppStore"] as? Bool == false)
            || isEnterpriseFlag
            || isAdHocFlag
            || isTrollStoreOrJailbreakPath
            || (dict["provisioningProfile"] != nil)

        let appType = (isDefaultApp || isInternalApp) ? "System" : "User"
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

        if let rawEntDict = (dict["entitlements"] as? [String: Any]) ?? (dict["Entitlements"] as? [String: Any]),
           let parsedFromEnt = fromDictionary(["CFBundleIdentifier": bundleId, "Entitlements": rawEntDict]) {
            for g in parsedFromEnt.appGroups { groupSet.insert(g) }
            keychainGroups = parsedFromEnt.keychainAccessGroups
            tccServices = parsedFromEnt.tccAllowedServices
            boolEnts = parsedFromEnt.booleanEntitlements
            strEnts = parsedFromEnt.stringEntitlements
            allEntKeySet.formUnion(parsedFromEnt.allEntitlementKeys)
            if teamId == nil { teamId = parsedFromEnt.teamId }
        }

        let hasEscapeOrPlatformEnt = boolEnts["get-task-allow"] == true
            || boolEnts["com.apple.private.security.no-sandbox"] == true
            || boolEnts["com.apple.private.security.no-container"] == true
            || boolEnts["com.apple.private.security.container-required"] == false
            || boolEnts["com.apple.private.MobileContainerManager.allowed"] == true
            || boolEnts["com.apple.private.security.storage.AppDataContainers"] == true
            || boolEnts["platform-application"] == true
            || !tccServices.isEmpty
        let explicitFromAppStore = (dict["fromAppStore"] as? Bool == true) || (dict["isAppStore"] as? Bool == true)
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
        } else {
            let canInferAppStoreForComApple = !lowerBid.hasPrefix("com.apple.")
                || explicitFromAppStore
                || InstalledAppRegistryScanner.isCanonicalRemovableAppleStockBundleId(lowerBid)
            hasAppStoreMetadata = !isDefaultApp && !isInternalApp && canInferAppStoreForComApple
            signerIdentity = hasAppStoreMetadata ? "Apple iPhone OS Application Signing" : nil
        }

        let sortedGroups = Array(groupSet).sorted()
        if !sortedGroups.isEmpty {
            allEntKeySet.insert("com.apple.security.application-groups")
        }
        if (dict["isBeta"] as? Bool == true) ||
           (dict["testFlight"] as? Bool == true) ||
           (dict["betaReportsActive"] as? Bool == true) {
            boolEnts["beta-reports-active"] = true
            allEntKeySet.insert("beta-reports-active")
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
            bundlePath: resolvedBundlePath,
            containerPath: containerPath
        )
    }
}

/// Evaluates installed application registry snapshots and live `installation_proxy` records.
public final class InstalledAppRegistryScanner: @unchecked Sendable {
    public static let shared = InstalledAppRegistryScanner()

    private let whitelistEngine: WhitelistEngine

    /// Additional major domestic / global messenger & payment apps frequently repackaged on sideload channels.
    private static let extraSideloadImpersonationTargets: [ExpandedThreatCatalog.ImpersonatedBrand] = [
        .init(
            name: "WeChat (微信)",
            bundleIdPatterns: ["com.tencent.xin", "com.tencent.wx"],
            displayNames: ["微信", "wechat"],
            description: "国民级社交通讯与支付应用，第三方多开/防撤回重打包版本常见聊天记录与账密窃取插件",
            descriptionEn: "Major messaging & payment app; unofficial clone/tweak repackages frequently bundle credential or chat-history stealers"
        ),
        .init(
            name: "Alipay (支付宝)",
            bundleIdPatterns: ["com.alipay.iphoneclient"],
            displayNames: ["支付宝", "alipay"],
            description: "核心移动支付应用，严禁安装任何非 App Store 侧载篡改版本",
            descriptionEn: "Critical mobile payment app; never install any non-App Store sideloaded or modified build"
        ),
        .init(
            name: "WhatsApp",
            bundleIdPatterns: ["net.whatsapp.whatsapp"],
            displayNames: ["whatsapp"],
            description: "端到端加密通讯软件，非官方企业签/自签包常见会话劫持木马",
            descriptionEn: "End-to-end encrypted messenger; unofficial enterprise/sideloaded builds frequently carry session-hijacking trojans"
        )
    ]

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
        return ids
    }()

    internal static func isCanonicalRemovableAppleStockBundleId(_ lowerBid: String) -> Bool {
        canonicalRemovableAppleStockBundleIds.contains(lowerBid)
    }

    /// Returns `true` when the record represents a genuine Apple OS daemon, CoreServices UI service,
    /// or Apple first-party system/removable application (never developer-sideloaded, TrollStore-registered, or enterprise-resigned).
    public func isAppleSystemOrFirstPartyApp(_ record: InstalledAppRegistryRecord) -> Bool {
        // Any bundle signed with a provisioning profile (Developer / Ad-Hoc / Enterprise sideload)
        // or carrying get-task-allow is NEVER a genuine Apple OS platform binary.
        if record.profileValidated || record.booleanEntitlements["get-task-allow"] == true {
            return false
        }

        // Genuine Apple OS / first-party records do not carry a third-party developer Team ID.
        if let tid = record.teamId?.trimmingCharacters(in: .whitespacesAndNewlines), !tid.isEmpty {
            return false
        }

        let lowerBid = record.bundleId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard lowerBid.hasPrefix("com.apple.") else {
            return false
        }

        let signer = record.signerIdentity?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        if let signer, !signer.isEmpty {
            // Cryptographic Apple OS platform signature or Apple App Store signature on a `com.apple.*` bundle without profileValidated
            if signer == "software signing" || signer == "apple iphone os application signing" {
                return true
            }
            // Any other non-empty signer (e.g. "Ad Hoc", "ldid", "Apple Development", "iPhone Distribution") is NEVER Apple OS.
            return false
        }

        // Unsigned / nil-SignerIdentity path (CoreTrust static cache vs TrollStore "Switch to System Registration"):
        // 1. NEVER trust an unverified (`signer == nil`) record holding ANY sandbox-escape, platform-application, TCC,
        //    wildcard keychain, private Photos, or 2026 restricted bypass entitlement.
        if hasAnyDangerousRegistryEntitlement(record, assumingUnverifiedIdentity: true) || record.booleanEntitlements["platform-application"] == true {
            return false
        }

        // 2. Reject third-party App Groups, known sideload tool names, or wallet/messenger display-name impersonation.
        let hasThirdPartyGroup = record.appGroups.contains { grp in
            let lg = grp.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return !lg.isEmpty && !lg.hasPrefix("group.com.apple.") && !lg.hasPrefix("systemgroup.com.apple.")
        }
        if hasThirdPartyGroup {
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
        ).isEmpty {
            return false
        }

        // 3. Path-anchored system verification:
        //    - SSV-sealed OS paths (`/System/`, `/Applications/`, `/private/preboot/`) are trusted for clean `com.apple.*` bundles.
        //    - User-writable bundle container paths (`/var/containers/Bundle/Application/...`, where TrollStore "Switch to System
        //      Registration" flips `ApplicationType` to `"System"`) ONLY trust canonical preinstalled Apple stock bundle IDs.
        let path = Self.standardizedAbsolutePath(record.bundlePath)
        if path.hasPrefix("/System/") ||
           path.hasPrefix("/Applications/") ||
           path.hasPrefix("/private/preboot/") {
            return true
        }

        let appType = record.applicationType.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if appType == "system" && Self.canonicalRemovableAppleStockBundleIds.contains(lowerBid) {
            return true
        }

        return false
    }

    /// Lexically resolves `.` / `..` / duplicate separators WITHOUT touching the file system
    /// (unlike `NSString.standardizingPath`, whose `/private` handling depends on the host).
    static func standardizedAbsolutePath(_ raw: String) -> String {
        var stack: [Substring] = []
        for comp in raw.split(separator: "/", omittingEmptySubsequences: true) {
            switch comp {
            case ".": continue
            case "..": if !stack.isEmpty { stack.removeLast() }
            default: stack.append(comp)
            }
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

    private func hasAnyDangerousRegistryEntitlement(
        _ record: InstalledAppRegistryRecord,
        assumingUnverifiedIdentity: Bool = false
    ) -> Bool {
        let isTrustedApple = assumingUnverifiedIdentity ? false : isAppleSystemOrFirstPartyApp(record)
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
        if record.keychainAccessGroups.contains("*") ||
           record.keychainAccessGroups.contains(where: { $0.hasSuffix(".*") }) {
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
        if isAppleSystemOrFirstPartyApp(record) {
            return (.appStore, true)
        }

        if record.booleanEntitlements["get-task-allow"] == true {
            return (.developerSideloaded, false)
        }

        let signerLower = record.signerIdentity?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() ?? ""
        let hasDangerousPrivateEscape = hasAnyDangerousRegistryEntitlement(record)

        // 1. Check explicit developer / ad-hoc signers FIRST so leftover `iTunesMetadata.plist` (`ApplicationDSID > 0`)
        //    on a repackaged wallet/messenger can never spoof `.appStore`.
        if signerLower.contains("apple development") || signerLower.contains("iphone developer") {
            return (.developerSideloaded, false)
        }
        if signerLower == "ad hoc" || signerLower.contains("ad-hoc") || signerLower.contains("ldid") || signerLower.contains("trollstore") {
            return (.developerSideloaded, false)
        }

        // 2. TestFlight Beta builds:
        //    Require `beta-reports-active == true` paired with a validated Apple Distribution / App Store / TestFlight signature
        //    (never trusting arbitrary `"testflight"` substrings without `beta-reports-active`, nor ad-hoc/unsigned `beta-reports-active`).
        if !hasDangerousPrivateEscape {
            let isEligibleBetaSigner = (signerLower == "apple iphone os application signing")
                || (signerLower == "apple testflight beta distribution")
                || signerLower.hasPrefix("apple distribution:")
                || signerLower.hasPrefix("iphone distribution:")
            if (record.profileValidated && signerLower == "apple iphone os application signing") ||
               (record.booleanEntitlements["beta-reports-active"] == true && record.profileValidated && isEligibleBetaSigner) {
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
        if isAppleSystemOrFirstPartyApp(record) {
            return false
        }
        let (channel, _) = classifyChannel(for: record)
        if channel.isSideloadedOrEnterprise {
            return true
        }
        // Even if marked App Store, inspect if carrying dangerous private sandbox-escape, TCC, Photos, keychain wildcard, or 2026 bypass entitlements
        if hasAnyDangerousRegistryEntitlement(record) {
            return true
        }
        return false
    }

    /// Evaluates all relevant installed app records into `ScanFinding` items.
    public func evaluateRecords(
        _ records: [InstalledAppRegistryRecord],
        includeAppStoreApps: Bool = false
    ) -> [ScanFinding] {
        #if os(iOS)
        let selfBid = Bundle.main.bundleIdentifier ?? "com.wqguard.app"
        #else
        let selfBid = ""
        #endif

        var findings: [ScanFinding] = []
        for rec in records {
            if !selfBid.isEmpty && rec.bundleId == selfBid {
                // Only skip WQGuard's own bundle ID when it matches the built-in self-whitelist (.knownTool/.safe);
                // never skip a Trojanized sideloaded clone spoofing com.wqguard.app with high-risk entitlements.
                let selfEval = evaluateRecord(rec)
                if selfEval.riskTier == .knownTool || selfEval.riskTier == .safe {
                    continue
                }
            }
            // Always exclude genuine Apple OS daemons, CoreServices UI services, and Apple system apps
            // so `includeAppStoreApps` strictly audits user-installed third-party App Store applications.
            if isAppleSystemOrFirstPartyApp(rec) {
                continue
            }
            if !includeAppStoreApps && !isSideloadedOrAnomalous(rec) {
                continue
            }
            findings.append(evaluateRecord(rec))
        }
        return findings
    }

    /// Performs full registry-level security evaluation on a single installed application record.
    public func evaluateRecord(_ record: InstalledAppRegistryRecord) -> ScanFinding {
        let (channel, isFairPlay) = classifyChannel(for: record)
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

        let isTrustedAppleRecord = isAppleSystemOrFirstPartyApp(record)

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

        if !isAppleSystemOrFirstPartyApp(record) {
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
        if record.keychainAccessGroups.contains("*") || record.keychainAccessGroups.contains(where: { $0.hasSuffix(".*") }) {
            indicators.append(ThreatIndicator(
                signature: "keychain-access-groups(*)",
                description: WQLocale.pick(
                    en: "Declares wildcard keychain access groups (\(record.keychainAccessGroups.joined(separator: ", "))), exposing cross-app credentials and private keys.",
                    zh: "已安装应用声明了通配符钥匙串访问组 (\(record.keychainAccessGroups.joined(separator: ", ")))，可跨应用窃取 Keychain 敏感登录凭证与私钥！"
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
                let lowerG = grp.lowercased()
                return (lowerG.hasPrefix("group.com.apple.") || lowerG.hasPrefix("systemgroup.com.apple.")) && !isTrustedAppleRecord
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
        let isAdHocOrUnsignedRegistrySigner = signerLowerForTeam == "ad hoc"
            || signerLowerForTeam.contains("ad-hoc")
            || signerLowerForTeam.contains("ldid")
            || signerLowerForTeam.contains("trollstore")
        let isRegistryTeamVerified: Bool
        if let recTeam = record.teamId?.trimmingCharacters(in: .whitespacesAndNewlines), !recTeam.isEmpty {
            isRegistryTeamVerified = !hasConflictingRegistryTeamId
                && !isAdHocOrUnsignedRegistrySigner
                && (record.profileValidated || record.hasAppStoreMetadata || signerLowerForTeam == "apple iphone os application signing")
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
