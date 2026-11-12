//
//  ScanViewModel.swift
//  WQGuard
//
//  Central @MainActor state coordinator managing active scan sessions, real-time
//  progress reporting, findings filtering, firmware posture evaluation, and report export.
//

import SwiftUI
import Combine
import UniformTypeIdentifiers
import WQGuardCore

@MainActor
public final class ScanViewModel: ObservableObject {
    public static let shared = ScanViewModel()

    // MARK: - Published State
    @Published public var currentSession: ScanSession?
    @Published public var isScanning: Bool = false
    @Published public var scanProgress: ScanProgress?
    @Published public var selectedFinding: ScanFinding?
    @Published public var selectedRiskFilter: RiskTier? = nil
    @Published public var searchQuery: String = ""
    @Published public var installedAppsCount: Int = 0

    // Firmware CVE Radar State
    @Published public var firmwareReport: FirmwarePostureReport
    @Published public var selectedVulnerability: FirmwareVulnerability?

    // IPA Package Inspection State
    @Published public var inspectedIPAFinding: ScanFinding?
    @Published public var isInspectingIPA: Bool = false
    @Published public var ipaErrorMessage: String?

    // Whitelist State
    @Published public var whitelistedTools: [WhitelistedTool] = []
    @Published public var showAddRuleSheet: Bool = false

    // Report Export State
    public enum ExportFormat: String, CaseIterable, Identifiable {
        case markdown = "Markdown"
        case json = "JSON"
        case plainText = "PlainText"
        public var id: String { rawValue }
    }
    @Published public var exportFormat: ExportFormat = .markdown
    @Published public var exportedReportText: String = ""
    @Published public var exportedReportURL: URL?

    // Surge Brotli Shield Export State
    @Published public var surgeModuleContent: String = ""
    @Published public var surgeModuleExportURL: URL?
    @Published public var showSurgeSheet: Bool = false

    // Persistent Bookmarks for Self-Signed App Directories (Feather / SideStore / AltStore / Downloads)
    private static let bookmarkedDirsKey = "wqguard.bookmarked_sideload_dirs.v1"
    private static let lockdownHostKey = "wqguard.lockdown_host.v1"
    private static let includeAppStoreKey = "wqguard.include_appstore_registry.v1"
    private static let enableProbeKey = "wqguard.enable_ondevice_probe.v1"
    private static let snapshotNameKey = "wqguard.saved_snapshot_name.v1"

    @Published public var showSideloadPickerFromDashboard: Bool = false
    @Published public var showInstalledScanConfigSheet: Bool = false
    @Published public var bookmarkedFolderNames: [String] = []

    // Installed App Registry (Option 1) & On-Device Probe (Option 3) State
    @Published public var hasPairingFile: Bool = false
    @Published public var pairingHostIDSummary: String? = nil
    @Published public var lockdownHost: String = "10.7.0.1" {
        didSet { UserDefaults.standard.set(lockdownHost, forKey: Self.lockdownHostKey) }
    }
    @Published public var hasSavedSnapshot: Bool = false
    @Published public var savedSnapshotAppCount: Int = 0
    @Published public var savedSnapshotFilename: String? = nil
    @Published public var includeAppStoreAppsInRegistry: Bool = false {
        didSet { UserDefaults.standard.set(includeAppStoreAppsInRegistry, forKey: Self.includeAppStoreKey) }
    }
    @Published public var enableOnDeviceProbe: Bool = true {
        didSet { UserDefaults.standard.set(enableOnDeviceProbe, forKey: Self.enableProbeKey) }
    }
    @Published public var lastScanEngineSummary: String? = nil

    // Alert & Error Handling
    @Published public var activeAlertMessage: String?
    @Published public var showGlobalAlert: Bool = false

    // Background Tasks
    private var activeScanTask: Task<Void, Never>?

    // MARK: - Initialization
    public init() {
        self.firmwareReport = FirmwarePostureEngine.shared.evaluate()
        self.whitelistedTools = WhitelistEngine.shared.allTools
        self.surgeModuleContent = SurgeBrotliShieldHelper.shared.generateModuleContent()
        if let savedHost = UserDefaults.standard.string(forKey: Self.lockdownHostKey), !savedHost.isEmpty {
            self.lockdownHost = savedHost
        }
        self.includeAppStoreAppsInRegistry = UserDefaults.standard.bool(forKey: Self.includeAppStoreKey)
        if UserDefaults.standard.object(forKey: Self.enableProbeKey) != nil {
            self.enableOnDeviceProbe = UserDefaults.standard.bool(forKey: Self.enableProbeKey)
        }
        self.prepareSurgeExportURL()
        self.refreshBookmarkedFolderNames()
        self.refreshRegistrySourceState()
    }

    private var appSupportDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let dir = base.appendingPathComponent("WQGuardRegistry", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private var savedPairingURL: URL {
        appSupportDirectory.appendingPathComponent("active_device.mobiledevicepairing")
    }

    private var savedSnapshotURL: URL {
        appSupportDirectory.appendingPathComponent("installed_apps_snapshot.dat")
    }

    private func loadActivePairingFile() -> LockdownPairingFile? {
        guard FileManager.default.fileExists(atPath: savedPairingURL.path) else { return nil }
        return try? LockdownPairingFile.parse(from: savedPairingURL)
    }

    private func loadSavedSnapshotData() -> Data? {
        guard FileManager.default.fileExists(atPath: savedSnapshotURL.path) else { return nil }
        return try? Data(contentsOf: savedSnapshotURL, options: .mappedIfSafe)
    }

    public func refreshRegistrySourceState() {
        if let pairing = loadActivePairingFile() {
            hasPairingFile = true
            let prefix = String(pairing.hostID.prefix(8))
            pairingHostIDSummary = pairing.udid.map { "UDID: \($0.prefix(10))… (Host: \(prefix)…)" } ?? "HostID: \(prefix)…"
        } else {
            hasPairingFile = false
            pairingHostIDSummary = nil
        }

        if let snapData = loadSavedSnapshotData(),
           let records = try? InstalledAppRegistryScanner.shared.parseSnapshotData(snapData) {
            hasSavedSnapshot = true
            savedSnapshotAppCount = records.count
            savedSnapshotFilename = UserDefaults.standard.string(forKey: Self.snapshotNameKey) ?? "installed_apps.plist"
        } else {
            hasSavedSnapshot = false
            savedSnapshotAppCount = 0
            savedSnapshotFilename = nil
        }
    }

    public var activeEngineCount: Int {
        var count = 0
        if hasPairingFile || hasSavedSnapshot { count += 1 }
        if !bookmarkedFolderNames.isEmpty { count += 1 }
        if enableOnDeviceProbe { count += 1 }
        return count
    }

    public func importPairingFile(from url: URL) {
        if case .failure(let error) = importPairingFileWithResult(from: url) {
            activeAlertMessage = error.localizedDescription
            showGlobalAlert = true
        }
    }

    public func importPairingFileWithResult(from url: URL) -> Result<String, Error> {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }

        do {
            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            let stem = url.deletingPathExtension().lastPathComponent
            return importPairingDataWithResult(data, fallbackUDID: stem)
        } catch {
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            #endif
            return .failure(error)
        }
    }

    private func importPairingDataWithResult(_ data: Data, fallbackUDID: String?) -> Result<String, Error> {
        do {
            let pairing = try LockdownPairingFile.parse(data: data, fallbackUDID: fallbackUDID)
            try data.write(to: savedPairingURL, options: .atomic)
            refreshRegistrySourceState()
            let summary = "已导入配对文件 (HostID: \(pairing.hostID.prefix(8))…)"
            lastScanEngineSummary = summary
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            #endif
            return .success(summary)
        } catch {
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            #endif
            return .failure(error)
        }
    }

    public func clearPairingFile() {
        try? FileManager.default.removeItem(at: savedPairingURL)
        refreshRegistrySourceState()
    }

    public func importRegistrySnapshot(from url: URL, autoScan: Bool = true) {
        if case .failure(let error) = importRegistrySnapshotWithResult(from: url, autoScan: autoScan) {
            activeAlertMessage = error.localizedDescription
            showGlobalAlert = true
        }
    }

    public func importRegistrySnapshotWithResult(from url: URL, autoScan: Bool = true) -> Result<String, Error> {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }

        do {
            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            return importRegistrySnapshotDataWithResult(data, filename: url.lastPathComponent, autoScan: autoScan)
        } catch {
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            #endif
            return .failure(error)
        }
    }

    private func importRegistrySnapshotDataWithResult(_ data: Data, filename: String, autoScan: Bool = true) -> Result<String, Error> {
        do {
            let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(data)
            try data.write(to: savedSnapshotURL, options: .atomic)
            UserDefaults.standard.set(filename, forKey: Self.snapshotNameKey)
            refreshRegistrySourceState()
            let summary = "已导入注册表快照（共 \(records.count) 款已安装应用）"
            lastScanEngineSummary = summary
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            #endif
            if autoScan {
                showInstalledScanConfigSheet = false
                startSystemScan()
            }
            return .success(summary)
        } catch {
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            #endif
            return .failure(error)
        }
    }

    public func clearSavedSnapshot() {
        try? FileManager.default.removeItem(at: savedSnapshotURL)
        UserDefaults.standard.removeObject(forKey: Self.snapshotNameKey)
        refreshRegistrySourceState()
    }

    public func clearBoundSigningFolders() {
        UserDefaults.standard.removeObject(forKey: Self.bookmarkedDirsKey)
        refreshBookmarkedFolderNames()
    }

    public func handleIncomingURL(_ url: URL) {
        let ext = url.pathExtension.lowercased()
        if ext == "ipa" || ext == "tipa" || ext == "app" {
            scanIPAPackage(at: url)
            return
        }

        // Read security-scoped data ONCE inside a single start/stop pair so one-shot Open-In grants are never lost!
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }

        guard let rawData = try? Data(contentsOf: url, options: .mappedIfSafe) else {
            activeAlertMessage = "无法读取传入文件 (\(url.lastPathComponent))。"
            showGlobalAlert = true
            return
        }

        let stem = url.deletingPathExtension().lastPathComponent
        if ext == "mobiledevicepairing" || (try? LockdownPairingFile.parse(data: rawData, fallbackUDID: stem)) != nil {
            switch importPairingDataWithResult(rawData, fallbackUDID: stem) {
            case .success:
                testLiveLockdownConnectionAndScan()
            case .failure(let err):
                activeAlertMessage = err.localizedDescription
                showGlobalAlert = true
            }
        } else {
            switch importRegistrySnapshotDataWithResult(rawData, filename: url.lastPathComponent, autoScan: true) {
            case .success:
                break
            case .failure(let err):
                activeAlertMessage = err.localizedDescription
                showGlobalAlert = true
            }
        }
    }

    public func testLiveLockdownConnectionAndScan() {
        guard let pairing = loadActivePairingFile() else {
            activeAlertMessage = "请先导入配对文件 (.plist / .mobiledevicepairing)。"
            showGlobalAlert = true
            return
        }
        guard !isScanning else { return }
        showInstalledScanConfigSheet = false
        isScanning = true
        let host = lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "10.7.0.1" : lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines)
        scanProgress = ScanProgress(currentTarget: "正在通过 LocalDevVPN (\(host)) 连接 installation_proxy...", completedCount: 0, totalCount: 1)

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            do {
                let liveRecords = try await LockdownInstProxyClient.shared.fetchInstalledApps(
                    pairing: pairing,
                    preferredHost: host
                )
                // Cache live records to local snapshot store so future offline scans remain instant even when VPN is off
                if let encoded = try? JSONEncoder().encode(liveRecords) {
                    try? encoded.write(to: self.savedSnapshotURL, options: .atomic)
                    UserDefaults.standard.set("LocalDevVPN 直连缓存", forKey: Self.snapshotNameKey)
                    self.refreshRegistrySourceState()
                }
                self.isScanning = false
                self.scanProgress = nil
                self.runUnifiedScanWithPreloadedRegistry(liveRecords, liveConnected: true)
            } catch {
                self.isScanning = false
                self.scanProgress = nil
                self.activeAlertMessage = "配对文件已保存，但直连未成功：\n\(error.localizedDescription)"
                self.showGlobalAlert = true
                #if os(iOS)
                UINotificationFeedbackGenerator().notificationOccurred(.error)
                #endif
            }
        }
    }

    private func saveDirectoryBookmarkData(_ data: Data) {
        var existing = UserDefaults.standard.array(forKey: Self.bookmarkedDirsKey) as? [Data] ?? []
        if !existing.contains(data) {
            existing.append(data)
            UserDefaults.standard.set(existing, forKey: Self.bookmarkedDirsKey)
            refreshBookmarkedFolderNames()
        }
    }

    private func resolveBookmarkedDirectories() -> [URL] {
        let datas = UserDefaults.standard.array(forKey: Self.bookmarkedDirsKey) as? [Data] ?? []
        var urls: [URL] = []
        for data in datas {
            var isStale = false
            if let url = try? URL(resolvingBookmarkData: data, bookmarkDataIsStale: &isStale) {
                urls.append(url)
            }
        }
        return urls
    }

    private func refreshBookmarkedFolderNames() {
        let urls = resolveBookmarkedDirectories()
        let labels = urls.map { url -> String in
            let name = url.lastPathComponent
            let parent = url.deletingLastPathComponent().lastPathComponent
            if !parent.isEmpty && parent != "Documents" && parent != "File Provider Storage" && parent != "LocalStorage" && parent != "/" {
                return "\(parent)/\(name)"
            }
            return name
        }
        self.bookmarkedFolderNames = Array(Set(labels)).sorted()
    }

    // MARK: - Computed Properties
    public var hasScannedApps: Bool {
        guard let session = currentSession else { return false }
        return session.totalApps > 0
    }

    public var overallPosture: RiskTier {
        if let session = currentSession, session.totalApps > 0 {
            return session.overallPosture
        }
        return firmwareReport.overallRiskTier
    }

    public var filteredFindings: [ScanFinding] {
        guard let session = currentSession else { return [] }
        var list = session.findings

        if let filter = selectedRiskFilter {
            list = list.filter { $0.riskTier == filter }
        }

        if !searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let q = searchQuery.lowercased()
            list = list.filter {
                $0.displayName.lowercased().contains(q) ||
                $0.bundleId.lowercased().contains(q) ||
                ($0.teamId?.lowercased().contains(q) ?? false)
            }
        }

        return list.sorted { $0.riskTier > $1.riskTier }
    }

    public var highRiskCount: Int { currentSession?.riskBreakdown[.highRisk, default: 0] ?? 0 }
    public var knownToolCount: Int { currentSession?.riskBreakdown[.knownTool, default: 0] ?? 0 }
    public var cautionCount: Int { currentSession?.riskBreakdown[.caution, default: 0] ?? 0 }
    public var safeCount: Int { currentSession?.riskBreakdown[.safe, default: 0] ?? 0 }
    public var totalScannedCount: Int { currentSession?.totalApps ?? 0 }

    // MARK: - Unified Installed Application Scan Actions (Registry + Signer Folder + On-Device Probe)
    public func startSystemScan() {
        guard !isScanning else { return }
        isScanning = true
        scanProgress = ScanProgress(currentTarget: WQStrings.scanEngineInitializing, completedCount: 0, totalCount: 0)
        let savedDirs = resolveBookmarkedDirectories()
        let pairing = loadActivePairingFile()
        let snapData = loadSavedSnapshotData()
        let host = lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "10.7.0.1" : lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let includeStore = includeAppStoreAppsInRegistry
        let probeEnabled = enableOnDeviceProbe

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            let startTime = Date()
            let scopedBookmarks = savedDirs.map { ($0, $0.startAccessingSecurityScopedResource()) }
            defer {
                for (u, accessed) in scopedBookmarks where accessed {
                    u.stopAccessingSecurityScopedResource()
                }
            }

            do {
                let unified = try await SecurityPipeline.shared.scanUnifiedInstalledAppsAsync(
                    pairingFile: pairing,
                    preferredLockdownHost: host,
                    savedSnapshotData: snapData,
                    additionalLocations: savedDirs,
                    includeAppStoreApps: includeStore,
                    enableOnDeviceProbe: probeEnabled
                ) { [weak self] progress in
                    guard let strongSelf = self else { return }
                    Task { @MainActor in
                        strongSelf.scanProgress = progress
                    }
                }

                let duration = Date().timeIntervalSince(startTime)
                guard !unified.findings.isEmpty else {
                    self.isScanning = false
                    self.scanProgress = nil
                    try? await Task.sleep(nanoseconds: 150_000_000)
                    self.showInstalledScanConfigSheet = true
                    return
                }

                let session = ScanSession(
                    findings: unified.findings,
                    systemVersion: FirmwarePostureEngine.shared.evaluate().osVersion.displayString,
                    scanDuration: duration
                )

                self.currentSession = session
                self.installedAppsCount = session.totalApps
                self.lastScanEngineSummary = Self.formatEngineSummary(unified)
                self.isScanning = false
                self.scanProgress = nil
                self.updateExportedReport()
                #if os(iOS)
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                #endif
            } catch is SecurityPipelineError {
                self.isScanning = false
                self.scanProgress = nil
                try? await Task.sleep(nanoseconds: 150_000_000)
                self.showInstalledScanConfigSheet = true
            } catch {
                if Task.isCancelled {
                    self.isScanning = false
                    self.scanProgress = nil
                    return
                }
                self.isScanning = false
                self.scanProgress = nil
                self.activeAlertMessage = WQStrings.scanFailedMessage(error.localizedDescription)
                self.showGlobalAlert = true
                #if os(iOS)
                UINotificationFeedbackGenerator().notificationOccurred(.error)
                #endif
            }
        }
    }

    private func runUnifiedScanWithPreloadedRegistry(_ liveRecords: [InstalledAppRegistryRecord], liveConnected: Bool) {
        guard !isScanning else { return }
        isScanning = true
        let savedDirs = resolveBookmarkedDirectories()
        let includeStore = includeAppStoreAppsInRegistry
        let probeEnabled = enableOnDeviceProbe

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            let startTime = Date()
            let scopedBookmarks = savedDirs.map { ($0, $0.startAccessingSecurityScopedResource()) }
            defer {
                for (u, accessed) in scopedBookmarks where accessed {
                    u.stopAccessingSecurityScopedResource()
                }
            }

            let pkgFindings = (try? await SecurityPipeline.shared.scanInstalledAppsAsync(additionalLocations: savedDirs) { [weak self] progress in
                guard let strongSelf = self else { return }
                Task { @MainActor in strongSelf.scanProgress = progress }
            }) ?? []

            let probeFindings = probeEnabled ? await OnDeviceAppProbeScanner.shared.probeInstalledAppsAsync() : []
            let merged = SecurityPipeline.shared.correlateAndMergeFindings(
                registryRecords: liveRecords,
                packageFindings: pkgFindings,
                probeFindings: probeFindings,
                includeAppStoreApps: includeStore
            )

            let duration = Date().timeIntervalSince(startTime)
            let session = ScanSession(
                findings: merged.findings,
                systemVersion: FirmwarePostureEngine.shared.evaluate().osVersion.displayString,
                scanDuration: duration
            )

            let summaryResult = SecurityPipeline.UnifiedInstalledScanResult(
                findings: merged.findings,
                liveRegistryConnected: liveConnected,
                registryEvaluatedCount: merged.registryCount,
                correlatedBinaryCount: merged.correlatedCount,
                probeDetectedCount: merged.probeCount,
                statusNotice: "已直连读取全机 \(liveRecords.count) 款应用注册表"
            )

            self.currentSession = session
            self.installedAppsCount = session.totalApps
            self.lastScanEngineSummary = Self.formatEngineSummary(summaryResult)
            self.isScanning = false
            self.scanProgress = nil
            self.updateExportedReport()
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            #endif
        }
    }

    private static func formatEngineSummary(_ res: SecurityPipeline.UnifiedInstalledScanResult) -> String {
        var parts: [String] = []
        if res.liveRegistryConnected {
            parts.append("🟢 配对直连注册表: \(res.registryEvaluatedCount) 款")
        } else if res.registryEvaluatedCount > 0 {
            parts.append("📋 注册表快照: \(res.registryEvaluatedCount) 款")
        }
        if res.correlatedBinaryCount > 0 {
            parts.append("🔬 源包二进制深扫联动: \(res.correlatedBinaryCount) 款")
        }
        if res.probeDetectedCount > 0 {
            parts.append("📡 本机探针: \(res.probeDetectedCount) 款")
        }
        if parts.isEmpty {
            return "📦 本地源包深扫: \(res.findings.count) 款"
        }
        return parts.joined(separator: " · ")
    }

    public func cancelScan() {
        activeScanTask?.cancel()
        activeScanTask = nil
        isScanning = false
        scanProgress = nil
    }

    // MARK: - IPA Package Scan Actions (Single & Batch / Folder)
    public func scanIPAPackage(at url: URL) {
        scanMultipleIPAPackages(at: [url])
    }

    public func scanMultipleIPAPackages(at urls: [URL]) {
        guard !urls.isEmpty else { return }

        // Synchronously acquire security scope & persist directory bookmarks on MainActor immediately upon picker callback
        var preScopedPairs: [(URL, Bool)] = []
        var anyDirectoryBound = false
        let fmMain = FileManager.default
        for u in urls {
            let accessed = u.startAccessingSecurityScopedResource()
            preScopedPairs.append((u, accessed))
            var isDir: ObjCBool = false
            let ext = u.pathExtension.lowercased()
            if ext != "ipa" && ext != "tipa" && ext != "app",
               (u.hasDirectoryPath || (fmMain.fileExists(atPath: u.path, isDirectory: &isDir) && isDir.boolValue)) {
                if let bData = try? u.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil) {
                    saveDirectoryBookmarkData(bData)
                    anyDirectoryBound = true
                }
            }
        }

        isInspectingIPA = true
        isScanning = true
        ipaErrorMessage = nil
        scanProgress = ScanProgress(currentTarget: WQStrings.scanEngineInitializing, completedCount: 0, totalCount: urls.count)

        let capturedScopedPairs = preScopedPairs
        let boundFlag = anyDirectoryBound

        activeScanTask = Task { [weak self] in
            guard let self = self else {
                for (u, accessed) in capturedScopedPairs where accessed {
                    u.stopAccessingSecurityScopedResource()
                }
                return
            }
            defer {
                for (u, accessed) in capturedScopedPairs where accessed {
                    u.stopAccessingSecurityScopedResource()
                }
            }
            let startTime = Date()

            do {
                let findings: [ScanFinding] = try await Task.detached(priority: .userInitiated) { [weak self] in
                    // Expand directories into .ipa / .tipa / .app / unpacked bundle targets
                    var expandedTargets: [URL] = []
                    var seenPaths: Set<String> = []
                    let fm = FileManager.default

                    func addTarget(_ candidate: URL) {
                        let resolved = candidate.resolvingSymlinksInPath().path
                        if seenPaths.insert(resolved).inserted {
                            expandedTargets.append(candidate)
                        }
                    }

                    for itemURL in urls {
                        var isDir: ObjCBool = false
                        let ext = itemURL.pathExtension.lowercased()
                        if ext == "ipa" || ext == "tipa" || ext == "app" {
                            addTarget(itemURL)
                        } else if fm.fileExists(atPath: itemURL.path, isDirectory: &isDir), isDir.boolValue {
                            if fm.fileExists(atPath: itemURL.appendingPathComponent("Info.plist").path) {
                                addTarget(itemURL)
                            } else if let enumerator = fm.enumerator(at: itemURL, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) {
                                while let subURL = enumerator.nextObject() as? URL {
                                    let subExt = subURL.pathExtension.lowercased()
                                    if subExt == "ipa" || subExt == "tipa" {
                                        addTarget(subURL)
                                    } else if subExt == "app" {
                                        addTarget(subURL)
                                        enumerator.skipDescendants()
                                    } else if subExt != "framework" && subExt != "appex" && subExt != "bundle" {
                                        var subDir: ObjCBool = false
                                        if fm.fileExists(atPath: subURL.path, isDirectory: &subDir),
                                           subDir.boolValue,
                                           fm.fileExists(atPath: subURL.appendingPathComponent("Info.plist").path) {
                                            addTarget(subURL)
                                            enumerator.skipDescendants()
                                        }
                                    }
                                }
                            }
                        } else {
                            addTarget(itemURL)
                        }
                    }

                    guard !expandedTargets.isEmpty else {
                        throw IPAPackageScannerError.missingPayload
                    }

                    var results: [ScanFinding] = []
                    var lastError: Error?
                    let total = expandedTargets.count
                    var completed = 0

                    for target in expandedTargets {
                        try Task.checkCancellation()
                        let preProgress = ScanProgress(
                            currentTarget: target.lastPathComponent,
                            completedCount: completed,
                            totalCount: total,
                            currentFinding: nil
                        )
                        Task { @MainActor [weak self] in
                            self?.scanProgress = preProgress
                        }
                        do {
                            let finding: ScanFinding
                            var targetIsDir: ObjCBool = false
                            if fm.fileExists(atPath: target.path, isDirectory: &targetIsDir), targetIsDir.boolValue {
                                finding = try SecurityPipeline.shared.scanBundle(at: target)
                            } else {
                                finding = try SecurityPipeline.shared.scanIPA(at: target)
                            }
                            results.append(finding)
                            completed += 1
                            let progress = ScanProgress(
                                currentTarget: target.lastPathComponent,
                                completedCount: completed,
                                totalCount: total,
                                currentFinding: finding
                            )
                            Task { @MainActor [weak self] in
                                self?.scanProgress = progress
                            }
                        } catch {
                            lastError = error
                            completed += 1
                        }
                    }

                    if results.isEmpty, let err = lastError {
                        throw err
                    }
                    return results
                }.value

                guard !findings.isEmpty else {
                    self.handleIPAScanFailure(WQStrings.batchIPANoValidTargets)
                    return
                }

                let duration = Date().timeIntervalSince(startTime)
                let session = ScanSession(
                    findings: findings,
                    systemVersion: FirmwarePostureEngine.shared.evaluate().osVersion.displayString,
                    scanDuration: duration
                )

                self.currentSession = session
                self.installedAppsCount = session.totalApps
                self.inspectedIPAFinding = findings.sorted(by: { $0.riskTier > $1.riskTier }).first
                self.isInspectingIPA = false
                self.isScanning = false
                self.scanProgress = nil
                self.updateExportedReport()
                #if os(iOS)
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                #endif
            } catch {
                if Task.isCancelled {
                    self.isInspectingIPA = false
                    self.isScanning = false
                    self.scanProgress = nil
                    return
                }
                let message: String
                if case IPAPackageScannerError.missingPayload = error, boundFlag {
                    // Folder was successfully bound even if currently empty; run unified scan (probes + registry + bound dirs)
                    self.isInspectingIPA = false
                    self.isScanning = false
                    self.scanProgress = nil
                    self.startSystemScan()
                    return
                } else if case IPAPackageScannerError.missingPayload = error, urls.count > 1 || urls.first?.hasDirectoryPath == true {
                    message = WQStrings.batchIPANoValidTargets
                } else {
                    message = error.localizedDescription
                }
                self.handleIPAScanFailure(message)
            }
        }
    }

    private func handleIPAScanFailure(_ errorMessage: String) {
        self.ipaErrorMessage = errorMessage
        self.activeAlertMessage = errorMessage
        self.showGlobalAlert = true
        self.isInspectingIPA = false
        self.isScanning = false
        self.scanProgress = nil
        #if os(iOS)
        UINotificationFeedbackGenerator().notificationOccurred(.error)
        #endif
    }

    // MARK: - Whitelist Management
    public func toggleWhitelist(for tool: WhitelistedTool, isEnabled: Bool) {
        WhitelistEngine.shared.toggleTool(named: tool.name, isEnabled: isEnabled)
        self.whitelistedTools = WhitelistEngine.shared.allTools
        recalculateSessionTiers()
    }

    public func addCustomWhitelistRule(bundleId: String, name: String, appGroup: String = "") {
        guard !bundleId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? bundleId : name
        let groups = appGroup.isEmpty ? [] : [appGroup]

        let newTool = WhitelistedTool(
            name: cleanName,
            allowedBundleIds: [bundleId],
            allowedAppGroups: groups,
            description: WQStrings.customRuleDefaultDescription,
            isEnabled: true,
            isBuiltIn: false
        )
        WhitelistEngine.shared.registerCustomTool(newTool)
        self.whitelistedTools = WhitelistEngine.shared.allTools
        recalculateSessionTiers()
    }

    public func removeCustomWhitelistRule(named name: String) {
        WhitelistEngine.shared.removeTool(named: name)
        self.whitelistedTools = WhitelistEngine.shared.allTools
        recalculateSessionTiers()
    }

    public func resetWhitelistToDefaults() {
        WhitelistEngine.shared.resetToDefaults()
        self.whitelistedTools = WhitelistEngine.shared.allTools
        recalculateSessionTiers()
    }

    private func recalculateSessionTiers() {
        guard let session = currentSession else { return }
        var updatedFindings: [ScanFinding] = []

        for finding in session.findings {
            let wlResult = WhitelistEngine.shared.isWhitelisted(
                bundleId: finding.bundleId,
                appGroups: finding.evidence.appGroups,
                matchedSignatures: finding.evidence.matchedSymbols,
                teamId: finding.teamId
            )

            let newTier: RiskTier
            if wlResult.isWhitelisted {
                newTier = .knownTool
            } else if finding.indicators.contains(where: { $0.severity == .highRisk }) {
                newTier = .highRisk
            } else if finding.indicators.contains(where: { $0.severity == .caution }) {
                newTier = .caution
            } else {
                newTier = .safe
            }

            let updated = ScanFinding(
                bundleId: finding.bundleId,
                displayName: finding.displayName,
                version: finding.version,
                teamId: finding.teamId,
                executablePath: finding.executablePath,
                bundlePath: finding.bundlePath,
                installChannel: finding.installChannel,
                riskTier: newTier,
                isWhitelisted: wlResult.isWhitelisted,
                whitelistedToolName: wlResult.toolName,
                indicators: finding.indicators,
                evidence: finding.evidence,
                scanTimestamp: finding.scanTimestamp
            )
            updatedFindings.append(updated)
        }

        self.currentSession = ScanSession(
            id: session.id,
            sessionId: session.sessionId,
            timestamp: session.timestamp,
            targetPath: session.targetPath,
            findings: updatedFindings,
            systemVersion: session.systemVersion,
            scanDuration: session.scanDuration,
            engineVersion: session.engineVersion
        )
        updateExportedReport()
    }

    // MARK: - Report Export Serialization
    public func updateExportedReport() {
        guard let session = currentSession else {
            exportedReportText = WQStrings.reportNoDataPlaceholder
            exportedReportURL = nil
            return
        }

        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("WQGuardAuditReports", isDirectory: true)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        switch exportFormat {
        case .markdown:
            let md = ReportGenerator.shared.generateMarkdownReport(session: session)
            self.exportedReportText = md
            let url = tempDir.appendingPathComponent("WQGuard-Audit-Report-\(session.sessionId).md")
            try? md.write(to: url, atomically: true, encoding: .utf8)
            self.exportedReportURL = url

        case .json:
            if let data = try? ReportGenerator.shared.generateJSONReport(session: session),
               let jsonStr = String(data: data, encoding: .utf8) {
                self.exportedReportText = jsonStr
                let url = tempDir.appendingPathComponent("WQGuard-Audit-Report-\(session.sessionId).json")
                try? data.write(to: url, options: .atomic)
                self.exportedReportURL = url
            }

        case .plainText:
            let text = ReportGenerator.shared.generatePlainTextReport(session: session)
            self.exportedReportText = text
            let url = tempDir.appendingPathComponent("WQGuard-Audit-Report-\(session.sessionId).txt")
            try? text.write(to: url, atomically: true, encoding: .utf8)
            self.exportedReportURL = url
        }
    }

    // MARK: - Surge Brotli Shield Exporter
    public func prepareSurgeExportURL(extraHosts: [String] = []) {
        do {
            let url = try SurgeBrotliShieldHelper.shared.exportToTemporaryFile(extraHosts: extraHosts)
            self.surgeModuleExportURL = url
            self.surgeModuleContent = SurgeBrotliShieldHelper.shared.generateModuleContent(extraHosts: extraHosts)
        } catch {
            self.activeAlertMessage = WQStrings.surgeGenerationFailedMessage(error.localizedDescription)
            self.showGlobalAlert = true
        }
    }

    public func refreshFirmwarePosture() {
        self.firmwareReport = FirmwarePostureEngine.shared.evaluate()
    }
}
