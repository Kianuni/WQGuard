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
            return """
            当前设备处于标准 iOS Seatbelt 沙盒隔离状态（非 TrollStore / 无全局容器读取权限），系统正常拦截了对其他已安装应用目录的枚举访问。

            WQGuard 坚持 100% 纯防御零漏洞利用原则，绝不调用系统漏洞越权突破沙盒。请通过以下任一方式完成审计：
            1. 点击下方「批量导入 IPA / 文件夹检测」直接选择本地侧载包；
            2. 将待检 .ipa 放入「文件 App -> 我的 iPhone -> WQGuard」目录后再次点击全盘检测。
            """
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
        self.machoScanner = machoScanner
        self.ipaScanner = ipaScanner
        self.whitelistEngine = whitelistEngine
        self.containerScanner = containerScanner
    }
    
    // MARK: - SecurityScannerEngineProtocol Conformance
    
    /// Scans a single Mach-O binary file at the specified URL.
    public func scanBinary(at url: URL) throws -> ScanFinding {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw IPAPackageScannerError.fileNotFound(url.path)
        }
        
        let binaryData = try Data(contentsOf: url, options: .mappedIfSafe)
        let machoFile = try MachOParser.shared.parse(data: binaryData)
        let details = machoScanner.parseMachO(file: machoFile, rawData: binaryData)
        let (_, appGroups) = CSBlobParser.shared.extractAppGroups(from: machoFile.codeSignatureData)
        
        var bundleId = url.lastPathComponent
        if let csData = machoFile.codeSignatureData,
           let parsed = try? CSBlobParser.shared.parseSuperBlob(csData),
           let rawXml = parsed.rawXML,
           let dict = try? CSBlobParser.shared.parseXMLPlist(Data(rawXml.utf8)),
           let appId = dict["application-identifier"] as? String {
            bundleId = appId
        }
        
        let bundleContext = MachOScanner.ScanContext(
            bundleId: bundleId,
            displayName: url.lastPathComponent,
            version: "1.0",
            teamId: nil,
            bundlePath: url.deletingLastPathComponent().path,
            executablePath: url.path,
            installChannel: details.cryptid != 0 ? .appStore : .developerSideloaded,
            appGroups: appGroups
        )
        
        return machoScanner.scan(details: details, context: bundleContext)
    }
    
    /// Scans an application `.app` bundle directory.
    public func scanBundle(at url: URL) throws -> ScanFinding {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw IPAPackageScannerError.fileNotFound(url.path)
        }
        
        let infoPlistURL = url.appendingPathComponent("Info.plist")
        guard FileManager.default.fileExists(atPath: infoPlistURL.path),
              let plistData = try? Data(contentsOf: infoPlistURL),
              let infoDict = (try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil)) as? [String: Any] else {
            throw IPAPackageScannerError.invalidInfoPlist("缺少或无效的 Info.plist")
        }
        
        let bundleId = infoDict["CFBundleIdentifier"] as? String ?? url.deletingPathExtension().lastPathComponent
        let displayName = infoDict["CFBundleDisplayName"] as? String ?? infoDict["CFBundleName"] as? String ?? url.deletingPathExtension().lastPathComponent
        let version = infoDict["CFBundleShortVersionString"] as? String ?? infoDict["CFBundleVersion"] as? String ?? "1.0"
        let execName = infoDict["CFBundleExecutable"] as? String ?? displayName
        
        let execURL = url.appendingPathComponent(execName)
        guard FileManager.default.fileExists(atPath: execURL.path) else {
            throw IPAPackageScannerError.missingExecutable(execName)
        }
        
        let execData = try Data(contentsOf: execURL, options: .mappedIfSafe)
        let machoFile = try MachOParser.shared.parse(data: execData)
        let details = machoScanner.parseMachO(file: machoFile, rawData: execData)
        
        let channelResult = ChannelClassifier.classifyBundle(at: url, cryptid: details.cryptid)
        let (hasGroups, appGroups) = CSBlobParser.shared.extractAppGroups(from: machoFile.codeSignatureData)
        let gating = EntitlementGating.evaluate(hasAppGroups: hasGroups, appGroups: appGroups)
        let backgroundModes = infoDict["UIBackgroundModes"] as? [String] ?? []
        var entitlementsDict: [String: Any] = [:]
        if let csData = machoFile.codeSignatureData,
           let parsed = try? CSBlobParser.shared.parseSuperBlob(csData),
           let rawXml = parsed.rawXML,
           let dict = try? CSBlobParser.shared.parseXMLPlist(Data(rawXml.utf8)) {
            entitlementsDict = dict
        }
        
        let context = MachOScanner.ScanContext(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            teamId: channelResult.teamIdentifier,
            bundlePath: url.path,
            executablePath: execURL.path,
            installChannel: channelResult.channel,
            appGroups: gating.appGroups
        )
        
        var allIndicators: [ThreatIndicator] = []
        var allMatchedSymbols: Set<String> = []
        var allLinkedDylibs: Set<String> = Set(details.linkedDylibs)
        var allSymbols: Set<String> = Set(details.symbols)
        var dynamicLoadingFound = false
        var pathEnumerationFound = false
        
        let mainFinding = machoScanner.scan(details: details, context: context)
        allIndicators.append(contentsOf: mainFinding.indicators)
        allMatchedSymbols.formUnion(mainFinding.evidence.matchedSymbols)
        if mainFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
        if mainFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
        
        // Scan Embedded Frameworks & Dynamic Libraries
        let frameworksURL = url.appendingPathComponent("Frameworks")
        if FileManager.default.fileExists(atPath: frameworksURL.path) {
            let fwEnumerator = FileManager.default.enumerator(at: frameworksURL, includingPropertiesForKeys: [.isRegularFileKey])
            while let itemURL = fwEnumerator?.nextObject() as? URL {
                let isDylib = itemURL.pathExtension.lowercased() == "dylib"
                let isFrameworkBinary = itemURL.deletingLastPathComponent().pathExtension.lowercased() == "framework" && itemURL.pathExtension.isEmpty
                if isDylib || isFrameworkBinary,
                   let dylibData = try? Data(contentsOf: itemURL, options: .mappedIfSafe),
                   let fwMachO = try? MachOParser.shared.parse(data: dylibData) {
                    let fwDetails = machoScanner.parseMachO(file: fwMachO, rawData: dylibData)
                    let fwFinding = machoScanner.scan(details: fwDetails, context: context)
                    let relPath = itemURL.path.replacingOccurrences(of: url.path + "/", with: "")
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
                    allSymbols.formUnion(fwDetails.symbols)
                    if fwFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
                    if fwFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
                }
            }
        }
        
        // Scan Embedded App Extensions (PlugIns)
        let pluginsURL = url.appendingPathComponent("PlugIns")
        if FileManager.default.fileExists(atPath: pluginsURL.path) {
            let plugEnumerator = FileManager.default.enumerator(at: pluginsURL, includingPropertiesForKeys: [.isDirectoryKey])
            while let itemURL = plugEnumerator?.nextObject() as? URL {
                if itemURL.pathExtension.lowercased() == "appex" {
                    let plugInfoPlistURL = itemURL.appendingPathComponent("Info.plist")
                    if let pData = try? Data(contentsOf: plugInfoPlistURL),
                       let pDict = (try? PropertyListSerialization.propertyList(from: pData, options: [], format: nil)) as? [String: Any],
                       let plugExec = pDict["CFBundleExecutable"] as? String {
                        let plugBinURL = itemURL.appendingPathComponent(plugExec)
                        if let binData = try? Data(contentsOf: plugBinURL, options: .mappedIfSafe),
                           let plugMachO = try? MachOParser.shared.parse(data: binData) {
                            let plugDetails = machoScanner.parseMachO(file: plugMachO, rawData: binData)
                            let plugFinding = machoScanner.scan(details: plugDetails, context: context)
                            let relPath = plugBinURL.path.replacingOccurrences(of: url.path + "/", with: "")
                            for ind in plugFinding.indicators {
                                allIndicators.append(ThreatIndicator(
                                    signature: ind.signature,
                                    description: "\(ind.description) [\(relPath)]",
                                    category: ind.category,
                                    location: "\(relPath): \(ind.location)",
                                    severity: ind.severity
                                ))
                            }
                            allMatchedSymbols.formUnion(plugFinding.evidence.matchedSymbols)
                            allLinkedDylibs.formUnion(plugDetails.linkedDylibs)
                            allSymbols.formUnion(plugDetails.symbols)
                            if plugFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
                            if plugFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
                        }
                    }
                }
            }
        }
        
        // Expanded Local Threat Signatures
        allIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: bundleId,
            displayName: displayName,
            installChannel: channelResult.channel,
            cryptid: details.cryptid
        ))
        
        if !details.isFairPlayEncrypted {
            let dylibList = Array(allLinkedDylibs)
            let symbolList = Array(allSymbols)
            allIndicators.append(contentsOf: ExpandedThreatCatalog.evaluatePhotosBypass(
                linkedDylibs: dylibList,
                symbols: symbolList,
                entitlements: entitlementsDict,
                cryptid: details.cryptid
            ))
            allIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateBrotliSupplyChain(
                linkedDylibs: dylibList,
                symbols: symbolList
            ))
            allIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateInjectedDylibs(
                linkedDylibs: dylibList
            ))
            if let clipboardInd = ExpandedThreatCatalog.evaluateClipboardSnooping(
                backgroundModes: backgroundModes,
                symbols: symbolList,
                cryptid: details.cryptid
            ) {
                allIndicators.append(clipboardInd)
            }
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
        
        if provisionalRisk == .highRisk || provisionalRisk == .caution {
            let wlResult = whitelistEngine.isWhitelisted(
                bundleId: bundleId,
                appGroups: gating.appGroups,
                matchedSignatures: Array(allMatchedSymbols),
                teamId: channelResult.teamIdentifier
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
            remediation = "检测到高危越权特征（未经授权的跨沙盒逃逸、伪造钱包/通讯软件或隐私绕过 API 引用），建议立即卸载并注销描述文件。"
        case .knownTool:
            remediation = "匹配已知开源安全研究工具白名单（\(whitelistedToolName ?? "Known Tool")）。"
        case .caution:
            remediation = "应用声明了共享容器或包含第三方动态库/供应链风险组件，建议复核安装来源。"
        case .safe:
            remediation = "未发现跨沙盒越权或恶意利用特征，状态安全。"
        }
        
        let evidence = AuditEvidence(
            matchedSymbols: Array(allMatchedSymbols).sorted(),
            linkedDylibs: Array(allLinkedDylibs).sorted(),
            hasAppGroups: !gating.appGroups.isEmpty,
            appGroups: gating.appGroups,
            installChannel: channelResult.channel,
            cryptid: details.cryptid,
            isFairPlayEncrypted: details.isFairPlayEncrypted,
            escapingSymlinks: [],
            dynamicLoadingPresent: dynamicLoadingFound,
            pathEnumerationPresent: pathEnumerationFound,
            remediationGuidance: remediation
        )
        
        return ScanFinding(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            teamId: channelResult.teamIdentifier,
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
    
    /// Discovers readable installed `.app` bundles and user-imported `.ipa`/`.app` packages in Documents.
    private func discoverAccessibleTargets() -> (targets: [URL], permissionDeniedCount: Int) {
        var targets: [URL] = []
        var seenCanonicalPaths: Set<String> = []
        var permissionDeniedCount = 0
        let fm = FileManager.default
        
        #if os(iOS)
        let selfBundleCanonical = Bundle.main.bundleURL.resolvingSymlinksInPath().path
        #else
        let selfBundleCanonical = ""
        #endif
        
        func appendUnique(_ url: URL) {
            let canonical = url.resolvingSymlinksInPath().path
            guard !canonical.isEmpty, canonical != selfBundleCanonical else { return }
            if seenCanonicalPaths.insert(canonical).inserted {
                targets.append(url)
            }
        }
        
        let searchRoots: [String] = [
            "/var/containers/Bundle/Application",
            "/private/var/containers/Bundle/Application",
            "/var/mobile/Containers/Bundle/Application",
            "/Applications",
            "/System/Applications"
        ]
        
        for root in searchRoots {
            let rootURL = URL(fileURLWithPath: root, isDirectory: true)
            do {
                let contents = try fm.contentsOfDirectory(at: rootURL, includingPropertiesForKeys: [.isDirectoryKey])
                for item in contents {
                    if item.pathExtension.lowercased() == "app" {
                        appendUnique(item)
                    } else if item.hasDirectoryPath {
                        if let subContents = try? fm.contentsOfDirectory(at: item, includingPropertiesForKeys: nil) {
                            for sub in subContents where sub.pathExtension.lowercased() == "app" {
                                appendUnique(sub)
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
        
        #if os(iOS)
        // Also inspect WQGuard's own Documents & Documents/Inbox folders (populated via Files app / AirDrop / Open-In)
        if let docsURL = fm.urls(for: .documentDirectory, in: .userDomainMask).first,
           let enumerator = fm.enumerator(at: docsURL, includingPropertiesForKeys: [.isDirectoryKey]) {
            while let fileURL = enumerator.nextObject() as? URL {
                let ext = fileURL.pathExtension.lowercased()
                if ext == "ipa" {
                    appendUnique(fileURL)
                } else if ext == "app" {
                    appendUnique(fileURL)
                    enumerator.skipDescendants()
                }
            }
        }
        #endif
        
        return (targets, permissionDeniedCount)
    }
    
    /// Scans all installed applications across accessible system directories.
    public func scanInstalledApps() throws -> [ScanFinding] {
        let discovery = discoverAccessibleTargets()
        #if os(iOS)
        if discovery.targets.isEmpty && discovery.permissionDeniedCount > 0 {
            throw SecurityPipelineError.sandboxRestrictedNoAccessibleTargets
        }
        #endif
        
        var findings: [ScanFinding] = []
        for targetURL in discovery.targets {
            let ext = targetURL.pathExtension.lowercased()
            if ext == "ipa", let finding = try? scanIPA(at: targetURL) {
                findings.append(finding)
            } else if let finding = try? scanBundle(at: targetURL) {
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
    
    /// Asynchronously scans installed applications with live progress updates.
    public func scanInstalledAppsAsync(
        progressHandler: (@Sendable (ScanProgress) -> Void)? = nil
    ) async throws -> [ScanFinding] {
        return try await Task.detached(priority: .userInitiated) { [self] in
            let discovery = self.discoverAccessibleTargets()
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
                let ext = url.pathExtension.lowercased()
                let finding: ScanFinding?
                if ext == "ipa" {
                    finding = try? self.scanIPA(at: url)
                } else {
                    finding = try? self.scanBundle(at: url)
                }
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
                if url.pathExtension.lowercased() == "ipa" {
                    f = try self.scanIPA(at: url)
                } else if url.pathExtension.lowercased() == "app" {
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
