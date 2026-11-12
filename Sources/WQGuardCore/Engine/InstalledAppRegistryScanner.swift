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
            return "未找到已安装应用快照文件: \(path)"
        case .invalidSnapshotFormat(let detail):
            return "无法解析已安装应用快照格式 (\(detail))。请导入有效的 Xcode devicectl (.json)、pymobiledevice3 (.json) 或 installation_proxy (.plist/.xml) 文件。"
        case .emptyApplicationList:
            return "已安装应用注册表为空，未读取到任何应用记录。"
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
        let profileValidated = (dict["ProfileValidated"] as? Bool) ?? false

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
        for (k, v) in entDict {
            if let b = v as? Bool {
                boolEnts[k] = b
            } else if let num = v as? NSNumber, CFGetTypeID(num) == CFBooleanGetTypeID() {
                boolEnts[k] = num.boolValue
            } else if let num = v as? NSNumber, numericBoolKeys.contains(k) {
                boolEnts[k] = (num.intValue != 0)
            } else if let s = v as? String {
                strEnts[k] = s
            }
        }
        if (dict["BetaApp"] as? Bool == true) || (dict["IsTestFlight"] as? Bool == true) {
            boolEnts["beta-reports-active"] = true
        }

        let appGroups = (entDict["com.apple.security.application-groups"] as? [String] ?? [])
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        let keychainGroups = (entDict["keychain-access-groups"] as? [String] ?? [])
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        var tccServices: [String] = []
        if let allowList = entDict["com.apple.private.tcc.allow"] as? [String] {
            tccServices.append(contentsOf: allowList)
        }
        if let promptList = entDict["com.apple.private.tcc.allow-prompting"] as? [String] {
            tccServices.append(contentsOf: promptList)
        }

        var teamId = strEnts["com.apple.developer.team-identifier"]
            ?? (dict["TeamIdentifier"] as? String)
        if teamId == nil, let appId = strEnts["application-identifier"],
           let dotIdx = appId.firstIndex(of: ".") {
            let prefix = String(appId[..<dotIdx])
            if prefix.count == 10 && prefix.allSatisfy({ $0.isLetter || $0.isNumber }) {
                teamId = prefix
            }
        }

        let bgModes = (dict["UIBackgroundModes"] as? [String]) ?? []
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

        let appType = (isDefaultApp || isInternalApp) ? "System" : "User"
        let profileValidated = builtByDeveloper
        let hasAppStoreMetadata = !isDefaultApp && !isInternalApp && !builtByDeveloper
        let signerIdentity: String? = builtByDeveloper
            ? "Apple Development (CoreDevice)"
            : (hasAppStoreMetadata ? "Apple iPhone OS Application Signing" : nil)

        var groupSet: Set<String> = []
        if let arr = dict["appGroupIdentifiers"] as? [String] {
            for g in arr {
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
        let sortedGroups = Array(groupSet).sorted()

        let resolvedBundlePath: String = {
            if let urlStr = dict["url"] as? String, let u = URL(string: urlStr), u.isFileURL {
                return u.path
            }
            if let container = dict["bundleContainerPath"] as? String, !container.isEmpty {
                return container
            }
            return isDefaultApp ? "/Applications/\(bundleId).app" : "/var/containers/Bundle/Application/\(bundleId)"
        }()

        let containerPath = dict["dataContainerPath"] as? String
        var boolEnts: [String: Bool] = [:]
        var allEntKeys: [String] = []
        if !sortedGroups.isEmpty {
            allEntKeys.append("com.apple.security.application-groups")
        }
        if (dict["isBeta"] as? Bool == true) ||
           (dict["testFlight"] as? Bool == true) ||
           (dict["betaReportsActive"] as? Bool == true) {
            boolEnts["beta-reports-active"] = true
            allEntKeys.append("beta-reports-active")
        }

        return InstalledAppRegistryRecord(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            applicationType: appType,
            signerIdentity: signerIdentity,
            profileValidated: profileValidated,
            hasAppStoreMetadata: hasAppStoreMetadata,
            teamId: nil,
            appGroups: sortedGroups,
            keychainAccessGroups: [],
            tccAllowedServices: [],
            booleanEntitlements: boolEnts,
            stringEntitlements: [:],
            allEntitlementKeys: allEntKeys,
            backgroundModes: [],
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
            description: "国民级社交通讯与支付应用，第三方多开/防撤回重打包版本常见聊天记录与账密窃取插件"
        ),
        .init(
            name: "Alipay (支付宝)",
            bundleIdPatterns: ["com.alipay.iphoneclient"],
            displayNames: ["支付宝", "alipay"],
            description: "核心移动支付应用，严禁安装任何非 App Store 侧载篡改版本"
        ),
        .init(
            name: "WhatsApp",
            bundleIdPatterns: ["net.whatsapp.whatsapp"],
            displayNames: ["whatsapp"],
            description: "端到端加密通讯软件，非官方企业签/自签包常见会话劫持木马"
        )
    ]

    public init(whitelistEngine: WhitelistEngine = .shared) {
        self.whitelistEngine = whitelistEngine
    }

    // MARK: - Snapshot Parsing (Plist / XML / Binary Plist / JSON)

    public func parseSnapshotFile(at url: URL) throws -> [InstalledAppRegistryRecord] {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw InstalledAppRegistryError.fileNotFound(url.path)
        }
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        return try parseSnapshotData(data)
    }

    public func parseSnapshotData(_ data: Data) throws -> [InstalledAppRegistryRecord] {
        guard !data.isEmpty else {
            throw InstalledAppRegistryError.emptyApplicationList
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
            return cached
        }
        if let jsonObj = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
            let records = extractRecords(from: jsonObj)
            if !records.isEmpty {
                return records
            }
        }

        // 3. Handle concatenated XML plists from raw `instproxy Browse` stream dumps
        if let text = String(data: data, encoding: .utf8), text.contains("<plist") {
            var aggregated: [InstalledAppRegistryRecord] = []
            var searchRange = text.startIndex..<text.endIndex
            while let startRange = text.range(of: "<?xml", range: searchRange) ?? text.range(of: "<plist", range: searchRange),
                  let endRange = text.range(of: "</plist>", range: startRange.lowerBound..<text.endIndex) {
                let chunk = String(text[startRange.lowerBound..<endRange.upperBound])
                if let chunkData = chunk.data(using: .utf8),
                   let plistObj = try? PropertyListSerialization.propertyList(from: chunkData, options: [], format: nil) {
                    aggregated.append(contentsOf: extractRecords(from: plistObj))
                }
                searchRange = endRange.upperBound..<text.endIndex
            }
            if !aggregated.isEmpty {
                return deduplicate(aggregated)
            }
        }

        throw InstalledAppRegistryError.invalidSnapshotFormat("未知的数据结构")
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

    private func deduplicate(_ records: [InstalledAppRegistryRecord]) -> [InstalledAppRegistryRecord] {
        var seen: Set<String> = []
        var unique: [InstalledAppRegistryRecord] = []
        for rec in records {
            if seen.insert(rec.bundleId).inserted {
                unique.append(rec)
            }
        }
        return unique
    }

    // MARK: - Channel Classification & Security Audit

    /// Returns `true` when the record represents a genuine Apple OS daemon, CoreServices UI service,
    /// or Apple first-party system/removable application (never developer-sideloaded or enterprise-resigned).
    public func isAppleSystemOrFirstPartyApp(_ record: InstalledAppRegistryRecord) -> Bool {
        // Any bundle signed with a provisioning profile (Developer / Ad-Hoc / Enterprise sideload)
        // or carrying get-task-allow is NEVER a genuine Apple OS platform binary.
        if record.profileValidated || record.booleanEntitlements["get-task-allow"] == true {
            return false
        }
        if let signer = record.signerIdentity?.lowercased() {
            if signer.contains("development") || signer.contains("developer") ||
               signer.contains("distribution") || signer.contains("enterprise") {
                return false
            }
            if signer == "software signing" {
                return true
            }
        }

        if record.bundlePath.hasPrefix("/Applications/") ||
           record.bundlePath.hasPrefix("/System/") ||
           record.bundlePath.hasPrefix("/Library/") ||
           record.bundlePath.hasPrefix("/private/preboot/") {
            return true
        }

        let lowerBid = record.bundleId.lowercased()
        if lowerBid.hasPrefix("com.apple.") {
            return true
        }

        let appType = record.applicationType.lowercased()
        if (appType == "internal" || appType == "hidden") && record.teamId == nil {
            return true
        }

        return false
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
            ("全能签 / ESign", ["yyyue.esign", "com.esign."], ["全能签", "esign"]),
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

    public func classifyChannel(for record: InstalledAppRegistryRecord) -> (channel: InstallChannel, isFairPlayEncrypted: Bool) {
        if isAppleSystemOrFirstPartyApp(record) {
            return (.appStore, true)
        }

        if record.booleanEntitlements["get-task-allow"] == true {
            return (.developerSideloaded, false)
        }

        let signerLower = record.signerIdentity?.lowercased() ?? ""
        let hasDangerousPrivateEscape =
            record.booleanEntitlements["com.apple.private.security.no-container"] == true ||
            record.booleanEntitlements["com.apple.private.security.no-sandbox"] == true ||
            !record.tccAllowedServices.isEmpty

        // TestFlight Beta builds:
        // On iOS, TestFlight apps embed a 90-day beta provisioning profile (`profileValidated == true`),
        // carry `Entitlements["beta-reports-active"] == true` (only issued on App Store Connect / TestFlight
        // distribution profiles and rejected by installd on sideloaded/enterprise IPAs), and are signed with
        // "Apple Distribution: ...", "iPhone Distribution: ...", "Apple TestFlight Beta Distribution",
        // or "Apple iPhone OS Application Signing".
        if !hasDangerousPrivateEscape {
            if record.booleanEntitlements["beta-reports-active"] == true ||
               signerLower.contains("testflight") ||
               (record.profileValidated && signerLower == "apple iphone os application signing") {
                return (.testFlight, true)
            }
        }

        if record.hasAppStoreMetadata && !record.profileValidated {
            return (.appStore, true)
        }

        if let signer = record.signerIdentity {
            let lower = signer.lowercased()
            if lower.contains("apple development") || lower.contains("iphone developer") {
                return (.developerSideloaded, false)
            }
            if record.profileValidated && (lower.contains("distribution") || lower.contains("enterprise")) {
                // Distinguish Ad-Hoc vs In-House Enterprise: Ad-Hoc usually has team-identifier and non-enterprise profile,
                // whereas Enterprise distribution lacks App Store metadata and distributes broadly.
                return (.enterpriseInHouse, false)
            }
            if signer == "Apple iPhone OS Application Signing" && !record.profileValidated {
                return (.appStore, true)
            }
        }

        // Unvalidated user bundle (e.g., TrollStore ad-hoc ldid signed or custom sideload)
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
        // Even if marked App Store, inspect if carrying dangerous private sandbox-escape entitlements
        if record.booleanEntitlements["com.apple.private.security.no-container"] == true ||
           record.booleanEntitlements["com.apple.private.security.no-sandbox"] == true ||
           !record.tccAllowedServices.isEmpty {
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
                continue
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
            ("com.apple.private.security.no-container", true, "声明了无容器隔离私有权限 (no-container)，该已安装应用可直接跨沙盒读写全机应用数据！"),
            ("com.apple.private.security.no-sandbox", true, "声明了关闭 Seatbelt 沙盒私有权限 (no-sandbox)，完全脱离 iOS 沙盒隔离控制！"),
            ("com.apple.private.security.container-required", false, "显式关闭了容器强制约束 (container-required=false)，具备沙盒逃逸执行能力！"),
            ("com.apple.private.MobileContainerManager.allowed", true, "声明了 MobileContainerManager 私有守护进程直连特权，可跨应用查询或操作容器！"),
            ("com.apple.private.security.storage.AppDataContainers", true, "声明了 Apple 内部跨应用数据容器直接访问权限 (AppDataContainers)！")
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

        if record.booleanEntitlements["platform-application"] == true && !record.bundleId.hasPrefix("com.apple.") {
            indicators.append(ThreatIndicator(
                signature: "platform-application",
                description: "第三方已安装应用伪造声明了 Apple 平台级系统应用特权 (platform-application=true)！",
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
                description: "已安装应用持有 TCC 隐私免授权特权 (\(joined))，可在不弹出系统授权框的情况下静默读取相册、通讯录、麦克风或剪贴板！",
                category: "TCC Privacy Bypass",
                location: "installation_proxy Entitlements",
                severity: .highRisk
            ))
            matchedSignatures.insert("com.apple.private.tcc.allow")
        }

        // 3. Private Photos Entitlements
        var rawEntMap: [String: Any] = [:]
        for k in record.allEntitlementKeys {
            rawEntMap[k] = record.booleanEntitlements[k] ?? true
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

        // 4. Keychain Wildcard Access
        if record.keychainAccessGroups.contains("*") || record.keychainAccessGroups.contains(where: { $0.hasSuffix(".*") && $0.contains("apple") }) {
            indicators.append(ThreatIndicator(
                signature: "keychain-access-groups(*)",
                description: "已安装应用声明了通配符钥匙串访问组 (\(record.keychainAccessGroups.joined(separator: ", ")))，可跨应用窃取 Keychain 敏感登录凭证与私钥！",
                category: "Keychain Credential Exposure",
                location: "installation_proxy Entitlements",
                severity: .highRisk
            ))
            matchedSignatures.insert("keychain-access-groups(*)")
        }

        // 5. App Groups Cross-Container Surface (Layer 1 Gating)
        let gating = EntitlementGating.evaluate(hasAppGroups: !record.appGroups.isEmpty, appGroups: record.appGroups)
        if !gating.appGroups.isEmpty && channel.isSideloadedOrEnterprise {
            let appleGroupAbuse = gating.appGroups.filter {
                ($0.hasPrefix("group.com.apple.") || $0.hasPrefix("systemgroup.com.apple.")) && !record.bundleId.hasPrefix("com.apple.")
            }
            if !appleGroupAbuse.isEmpty {
                let gStr = appleGroupAbuse.joined(separator: ", ")
                indicators.append(ThreatIndicator(
                    signature: "AppleSystemAppGroup(\(gStr))",
                    description: "第三方侧载应用越权绑定了 Apple 系统共享容器组 (\(gStr))，高危系统配置篡改特征！",
                    category: "Unauthorized System App Group",
                    location: "installation_proxy Entitlements",
                    severity: .highRisk
                ))
                matchedSignatures.insert("AppleSystemAppGroup")
            } else {
                let gStr = gating.appGroups.joined(separator: ", ")
                indicators.append(ThreatIndicator(
                    signature: "com.apple.security.application-groups",
                    description: "已安装侧载应用声明了共享容器权限 (\(gStr))，满足触发 containermanagerd 跨沙盒漏洞的前置条件。建议手动选择对应 .ipa 文件加入扫描做进一步二进制符号排查。",
                    category: "Shared Container Surface",
                    location: "installation_proxy Entitlements",
                    severity: .caution
                ))
            }
        }

        // 6. Repackaged Crypto Wallet & Messenger Impersonation
        let brandInds = ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: record.bundleId,
            displayName: record.displayName,
            installChannel: channel,
            cryptid: cryptid
        )
        for b in brandInds {
            indicators.append(b)
            matchedSignatures.insert(b.signature)
        }

        if cryptid == 0 && channel.isSideloadedOrEnterprise {
            let lowerBid = record.bundleId.lowercased()
            let trimmedOrigName = record.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
            let lowerName = trimmedOrigName.lowercased()
            let nameTokens = ExpandedThreatCatalog.extractBrandTokens(from: trimmedOrigName)
            for extra in Self.extraSideloadImpersonationTargets {
                let matchBid = extra.bundleIdPatterns.contains { pat in
                    lowerBid == pat || lowerBid.hasPrefix(pat + ".") || lowerBid.contains("." + pat + ".") || lowerBid.hasSuffix("." + pat)
                }
                let matchName = extra.displayNames.contains { pat in
                    let isASCII = pat.unicodeScalars.allSatisfy { $0.isASCII }
                    if isASCII && !pat.contains(" ") {
                        return lowerName == pat || nameTokens.contains(pat)
                    }
                    return lowerName == pat || lowerName.contains(pat)
                }
                if matchBid || matchName {
                    let sig = "IMPERSONATION:\(extra.name)"
                    if !matchedSignatures.contains(sig) {
                        indicators.append(ThreatIndicator(
                            signature: sig,
                            description: "侧载/企业签高危提醒：已安装应用「\(record.displayName)」匹配高频被篡改应用 \(extra.name)。\(extra.description)。请确认注入插件来源可靠，切勿在来历不明的改版包中输入支付密码或助记词！",
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
            let persistent = record.backgroundModes.filter {
                ExpandedThreatCatalog.backgroundModesRequiringInspection.contains($0)
            }
            if !persistent.isEmpty {
                let mStr = persistent.joined(separator: ", ")
                let bgSig = "UIBackgroundModes(\(mStr))"
                indicators.append(ThreatIndicator(
                    signature: bgSig,
                    description: "已安装侧载应用开启了常驻后台模式 (\(mStr))。若配合剪贴板接口可在后台静默窃取复制的助记词/密码，建议关联本地 IPA 核验二进制符号。",
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
                description: "检测到第三方侧载签名/调试工具「\(sideloadInfraName)」。WQGuard 对所有第三方侧载工具严格执行零信任策略（绝不默认加白），请确认安装包来源可信并留意重签环境安全。",
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

        var isWhitelisted = false
        var whitelistedToolName: String? = nil
        var finalRisk = provisionalRisk

        let wlResult = whitelistEngine.isWhitelisted(
            bundleId: record.bundleId,
            appGroups: gating.appGroups,
            matchedSignatures: Array(matchedSignatures),
            teamId: record.teamId
        )
        if wlResult.isWhitelisted {
            isWhitelisted = true
            whitelistedToolName = wlResult.toolName
            finalRisk = .knownTool
        }

        let remediation: String
        switch finalRisk {
        case .highRisk:
            remediation = "系统注册表审计发现高危越权特征（无沙盒特权、TCC 免授权隐私绕过或高危仿冒客户端），建议立即在桌面长按卸载并前往「设置 -> 通用 -> VPN 与设备管理」移除对应证书/描述文件。"
        case .knownTool:
            remediation = "已安装应用匹配受信任白名单规则（\(whitelistedToolName ?? "Known Tool")）。当前为系统注册表权限审计结果。"
        case .caution:
            remediation = "已安装侧载应用包含共享容器权限、常驻后台或改版特征。可手动选择对应 .ipa 安装包加入扫描列表自动按 Bundle ID 完成二进制深度复核。"
        case .safe:
            remediation = "系统注册表权限与签名链核验通过：未声明 App Group 共享容器或任何越权私有 Entitlements（当前为注册表级审计，无本地 IPA 二进制）。"
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
            signerIdentity: record.signerIdentity
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
