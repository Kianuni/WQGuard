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
        let (_, appGroups) = CSBlobParser.shared.extractAppGroups(from: machoFile.codeSignatureData)
        
        let context = MachOScanner.ScanContext(
            bundleId: bundleId,
            displayName: displayName,
            version: version,
            teamId: channelResult.teamIdentifier,
            bundlePath: url.path,
            executablePath: execURL.path,
            installChannel: channelResult.channel,
            appGroups: appGroups
        )
        
        return machoScanner.scan(details: details, context: context)
    }
    
    /// Scans a local `.ipa` package archive.
    public func scanIPA(at url: URL) throws -> ScanFinding {
        return try ipaScanner.scan(ipaURL: url)
    }
    
    /// Scans all installed applications across system directories.
    public func scanInstalledApps() throws -> [ScanFinding] {
        var appURLs: [URL] = []
        let fm = FileManager.default
        
        // Scan standard search roots
        let searchRoots: [String] = [
            "/Applications",
            "/System/Applications",
            "/var/mobile/Containers/Bundle/Application"
        ]
        
        for root in searchRoots where fm.fileExists(atPath: root) {
            let rootURL = URL(fileURLWithPath: root)
            if let contents = try? fm.contentsOfDirectory(at: rootURL, includingPropertiesForKeys: [.isDirectoryKey]) {
                for item in contents {
                    if item.pathExtension.lowercased() == "app" {
                        appURLs.append(item)
                    } else if item.hasDirectoryPath {
                        // Check subdirectories (e.g. /var/mobile/Containers/Bundle/Application/<UUID>/<Name>.app)
                        if let subContents = try? fm.contentsOfDirectory(at: item, includingPropertiesForKeys: nil) {
                            for sub in subContents where sub.pathExtension.lowercased() == "app" {
                                appURLs.append(sub)
                            }
                        }
                    }
                }
            }
        }
        
        var findings: [ScanFinding] = []
        for appURL in appURLs {
            if let finding = try? scanBundle(at: appURL) {
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
            let searchRoots = ["/Applications", "/System/Applications", "/var/mobile/Containers/Bundle/Application"]
            var targetURLs: [URL] = []
            let fm = FileManager.default
            
            for root in searchRoots where fm.fileExists(atPath: root) {
                let rootURL = URL(fileURLWithPath: root)
                if let contents = try? fm.contentsOfDirectory(at: rootURL, includingPropertiesForKeys: nil) {
                    for item in contents {
                        if item.pathExtension.lowercased() == "app" {
                            targetURLs.append(item)
                        } else if item.hasDirectoryPath {
                            if let subContents = try? fm.contentsOfDirectory(at: item, includingPropertiesForKeys: nil) {
                                for sub in subContents where sub.pathExtension.lowercased() == "app" {
                                    targetURLs.append(sub)
                                }
                            }
                        }
                    }
                }
            }
            
            let total = targetURLs.count
            var completed = 0
            var results: [ScanFinding] = []
            
            for url in targetURLs {
                try Task.checkCancellation()
                let finding = try? self.scanBundle(at: url)
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
