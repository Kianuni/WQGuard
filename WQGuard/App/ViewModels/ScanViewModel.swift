//
//  ScanViewModel.swift
//  WQGuard
//
//  Central @MainActor state coordinator managing active scan sessions, real-time
//  progress reporting, findings filtering, firmware posture evaluation, and report export.
//

import Darwin
import SwiftUI
import Combine
import UniformTypeIdentifiers
import WQGuardCore

@MainActor
public final class ScanViewModel: ObservableObject {
    public static let shared = ScanViewModel()

    // MARK: - Published State
    @Published public var selectedTab: Int = 0
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

    // Multi-Client Brotli Shield Export State
    @Published public var selectedShieldPlatform: ProxyShieldPlatform = .surge {
        didSet {
            UserDefaults.standard.set(selectedShieldPlatform.rawValue, forKey: Self.shieldPlatformKey)
            prepareSurgeExportURL()
        }
    }
    @Published public var surgeModuleContent: String = ""
    @Published public var surgeModuleExportURL: URL?
    @Published public var showSurgeSheet: Bool = false

    // Persistent Settings Keys
    private static let legacyBookmarkedDirsKey = "wqguard.bookmarked_sideload_dirs.v1"
    private static let lockdownHostKey = "wqguard.lockdown_host.v1"
    private static let includeAppStoreKey = "wqguard.include_appstore_registry.v1"
    private static let enableProbeKey = "wqguard.enable_ondevice_probe.v1"
    private static let snapshotNameKey = "wqguard.saved_snapshot_name.v1"
    private static let shieldPlatformKey = "wqguard.shield_platform.v1"

    @Published public var showInstalledScanConfigSheet: Bool = false
    @Published public var syncedPackageNames: [String] = []

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
        if let savedPlatformRaw = UserDefaults.standard.string(forKey: Self.shieldPlatformKey),
           let savedPlatform = ProxyShieldPlatform(rawValue: savedPlatformRaw) {
            self.selectedShieldPlatform = savedPlatform
        }
        self.surgeModuleContent = SurgeBrotliShieldHelper.shared.generateShieldContent(for: self.selectedShieldPlatform)
        if let savedHost = UserDefaults.standard.string(forKey: Self.lockdownHostKey), !savedHost.isEmpty {
            self.lockdownHost = savedHost
        }
        self.includeAppStoreAppsInRegistry = UserDefaults.standard.bool(forKey: Self.includeAppStoreKey)
        if UserDefaults.standard.object(forKey: Self.enableProbeKey) != nil {
            self.enableOnDeviceProbe = UserDefaults.standard.bool(forKey: Self.enableProbeKey)
        }
        self.prepareSurgeExportURL()
        UserDefaults.standard.removeObject(forKey: Self.legacyBookmarkedDirsKey)
        self.refreshSyncedPackageNames()
        self.refreshRegistrySourceState()
    }

    public func navigateToFindings(filter: RiskTier? = nil) {
        self.selectedRiskFilter = filter
        self.selectedTab = 1
    }

    private static let maxPairingFileBytes = 4 * 1024 * 1024
    private static let maxSnapshotFileBytes = 128 * 1024 * 1024
    private static let maxPackageFileBytes = 1024 * 1024 * 1024

    private static func ensureSafeNonSymlinkDirectory(at dirURL: URL) -> URL {
        let clean = IPAPackageScanner.stripTrailingSlashes(dirURL.path)
        var st = stat()
        if lstat(clean, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK {
            try? FileManager.default.removeItem(at: dirURL)
        }
        try? FileManager.default.createDirectory(at: dirURL, withIntermediateDirectories: true)
        return dirURL
    }

    private var appSupportDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let dir = base.appendingPathComponent("WQGuardRegistry", isDirectory: true)
        return Self.ensureSafeNonSymlinkDirectory(at: dir)
    }

    private var syncedPackagesDirectory: URL {
        let dir = appSupportDirectory.appendingPathComponent("SyncedPackages", isDirectory: true)
        return Self.ensureSafeNonSymlinkDirectory(at: dir)
    }

    private var savedPairingURL: URL {
        appSupportDirectory.appendingPathComponent("active_device.mobiledevicepairing")
    }

    private var savedSnapshotURL: URL {
        appSupportDirectory.appendingPathComponent("installed_apps_snapshot.dat")
    }

    private func loadActivePairingFile() -> LockdownPairingFile? {
        return try? LockdownPairingFile.parse(from: savedPairingURL)
    }

    private func loadSavedSnapshotData() -> Data? {
        return try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(
            at: savedSnapshotURL,
            maxBytes: Self.maxSnapshotFileBytes
        )
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
        if !syncedPackageNames.isEmpty { count += 1 }
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
            let data = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(
                at: url,
                maxBytes: Self.maxPairingFileBytes
            )
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
            guard data.count <= Self.maxPairingFileBytes else {
                throw LockdownClientError.invalidPairingFile("Pairing payload exceeds \(Self.maxPairingFileBytes) bytes")
            }
            let pairing = try LockdownPairingFile.parse(data: data, fallbackUDID: fallbackUDID)
            try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(data, to: savedPairingURL)
            refreshRegistrySourceState()
            let summary = WQStrings.pairingImportedSummary(hostPrefix: String(pairing.hostID.prefix(8)))
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

    /// Reads a `.plist` / `.mobiledevicepairing` file or XML text directly from `UIPasteboard.general`
    /// (supports copying the `.plist` file in iOS Files App OR copying XML text via Universal Clipboard).
    public func importPairingFromClipboardWithResult() -> Result<String, Error> {
        #if canImport(UIKit)
        let pb = UIPasteboard.general

        // 1. Plain XML / Base64 string on clipboard
        if let str = pb.string?.trimmingCharacters(in: .whitespacesAndNewlines),
           !str.isEmpty,
           str.utf8.count <= Self.maxPairingFileBytes {
            let utf8Data = Data(str.utf8)
            if case .success(let msg) = importPairingDataWithResult(utf8Data, fallbackUDID: nil) {
                return .success(msg)
            }
            if let b64Data = Data(base64Encoded: str, options: .ignoreUnknownCharacters),
               case .success(let msg) = importPairingDataWithResult(b64Data, fallbackUDID: nil) {
                return .success(msg)
            }
        }

        // 2. Copied `.plist` / `.mobiledevicepairing` file item from iOS Files App (bounded to prevent clipboard DoS)
        var lastParseError: Error?
        for itemDict in pb.items.prefix(16) {
            for (_, rawVal) in itemDict.prefix(16) {
                if let d = rawVal as? Data {
                    switch importPairingDataWithResult(d, fallbackUDID: nil) {
                    case .success(let msg): return .success(msg)
                    case .failure(let err): lastParseError = err
                    }
                } else if let s = rawVal as? String {
                    if let fileURL = URL(string: s), fileURL.isFileURL,
                       let fileData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(
                           at: fileURL,
                           maxBytes: Self.maxPairingFileBytes
                       ) {
                        switch importPairingDataWithResult(fileData, fallbackUDID: fileURL.deletingPathExtension().lastPathComponent) {
                        case .success(let msg): return .success(msg)
                        case .failure(let err): lastParseError = err
                        }
                    } else if s.utf8.count <= Self.maxPairingFileBytes, let strData = s.data(using: .utf8) {
                        switch importPairingDataWithResult(strData, fallbackUDID: nil) {
                        case .success(let msg): return .success(msg)
                        case .failure(let err): lastParseError = err
                        }
                    }
                } else if let fileURL = rawVal as? URL,
                          fileURL.isFileURL,
                          let fileData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(
                              at: fileURL,
                              maxBytes: Self.maxPairingFileBytes
                          ) {
                    switch importPairingDataWithResult(fileData, fallbackUDID: fileURL.deletingPathExtension().lastPathComponent) {
                    case .success(let msg): return .success(msg)
                    case .failure(let err): lastParseError = err
                    }
                } else if let dictVal = rawVal as? [String: Any],
                          dictVal.count <= 64,
                          PropertyListSerialization.propertyList(dictVal, isValidFor: .xml),
                          let plistData = try? PropertyListSerialization.data(fromPropertyList: dictVal, format: .xml, options: 0),
                          plistData.count <= Self.maxPairingFileBytes {
                    switch importPairingDataWithResult(plistData, fallbackUDID: nil) {
                    case .success(let msg): return .success(msg)
                    case .failure(let err): lastParseError = err
                    }
                }
            }
        }

        return .failure(lastParseError ?? LockdownClientError.invalidPairingFile(WQStrings.clipboardNoValidPairing))
        #else
        return .failure(LockdownClientError.invalidPairingFile(WQStrings.clipboardUnsupportedPlatform))
        #endif
    }

    /// Automatically imports any `.mobiledevicepairing` / `.plist` / `.json` / `.ipa` / `.tipa` placed into
    /// `On My iPhone → WQGuard` (`Documents/` or `Documents/Inbox/`).
    @discardableResult
    public func autoImportFromDocumentsFolderIfNeeded() -> String? {
        let fm = FileManager.default
        guard let docsURL = fm.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return nil
        }

        let scanDirs = [docsURL, docsURL.appendingPathComponent("Inbox", isDirectory: true)]
        let currentHostID = loadActivePairingFile()?.hostID
        var autoImportedNotices: [String] = []
        var syncedNewIPA = false

        for dir in scanDirs {
            guard IPAPackageScanner.isNonSymlinkDirectory(at: dir),
                  let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
                continue
            }
            for item in items {
                let ext = item.pathExtension.lowercased()
                if ext == "ipa" || ext == "tipa" {
                    let targetName = item.lastPathComponent
                    if !syncedPackageNames.contains(targetName), stagePackageIntoSyncedFolder(item) != nil {
                        syncedNewIPA = true
                    }
                    continue
                }
                guard ext == "mobiledevicepairing" || ext == "plist" || ext == "xml" || ext == "json" else {
                    continue
                }
                let maxImportBytes = (ext == "mobiledevicepairing") ? Self.maxPairingFileBytes : Self.maxSnapshotFileBytes
                guard let data = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: item, maxBytes: maxImportBytes),
                      !data.isEmpty else {
                    continue
                }
                let stem = item.deletingPathExtension().lastPathComponent
                if let parsedPairing = try? LockdownPairingFile.parse(data: data, fallbackUDID: stem) {
                    if currentHostID != parsedPairing.hostID {
                        if case .success(let msg) = importPairingDataWithResult(data, fallbackUDID: stem) {
                            autoImportedNotices.append(WQStrings.autoImportedPairingNotice(msg))
                        }
                    }
                } else if !hasSavedSnapshot,
                          case .success(let msg) = importRegistrySnapshotDataWithResult(data, filename: item.lastPathComponent, autoScan: false) {
                    autoImportedNotices.append(WQStrings.autoImportedSnapshotNotice(msg))
                }
            }
        }

        if syncedNewIPA {
            refreshSyncedPackageNames()
            autoImportedNotices.append(WQStrings.autoImportedIPANotice)
        }

        return autoImportedNotices.isEmpty ? nil : autoImportedNotices.joined(separator: WQStrings.autoImportNoticeSeparator)
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
            let data = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(
                at: url,
                maxBytes: Self.maxSnapshotFileBytes
            )
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
            guard data.count <= Self.maxSnapshotFileBytes else {
                throw IPAPackageScannerError.quotaExceeded("Snapshot exceeds \(Self.maxSnapshotFileBytes) bytes")
            }
            let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(data)
            try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(data, to: savedSnapshotURL)
            UserDefaults.standard.set(filename, forKey: Self.snapshotNameKey)
            refreshRegistrySourceState()
            let summary = WQStrings.snapshotImportedSummary(count: records.count)
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

    public func removeSyncedPackage(named filename: String) {
        guard !filename.isEmpty,
              !filename.contains("/"),
              !filename.contains("\\"),
              !filename.contains("\0"),
              filename != ".",
              filename != ".." else {
            return
        }
        let target = syncedPackagesDirectory.appendingPathComponent(filename)
        try? FileManager.default.removeItem(at: target)
        refreshSyncedPackageNames()
    }

    public func clearSyncedPackages() {
        try? FileManager.default.removeItem(at: syncedPackagesDirectory)
        _ = syncedPackagesDirectory
        refreshSyncedPackageNames()
    }

    public func rescanAllSyncedPackages(correlateWithInstalled: Bool = false) {
        let urls = syncedPackageNames.map { syncedPackagesDirectory.appendingPathComponent($0) }
        guard !urls.isEmpty else { return }
        if correlateWithInstalled {
            startSystemScan()
        } else {
            scanMultipleIPAPackages(at: urls, correlateWithInstalled: false)
        }
    }

    private func refreshSyncedPackageNames() {
        let dir = syncedPackagesDirectory
        guard IPAPackageScanner.isNonSymlinkDirectory(at: dir) else {
            self.syncedPackageNames = []
            return
        }
        let items = (try? FileManager.default.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? []
        let names = items.compactMap { url -> String? in
            let ext = url.pathExtension.lowercased()
            guard ext == "ipa" || ext == "tipa" else { return nil }
            var lst = stat()
            guard lstat(IPAPackageScanner.stripTrailingSlashes(url.path), &lst) == 0,
                  (lst.st_mode & S_IFMT) == S_IFREG else {
                return nil
            }
            return url.lastPathComponent
        }
        self.syncedPackageNames = names.sorted()
    }

    @discardableResult
    private func stagePackageIntoSyncedFolder(_ src: URL) -> URL? {
        var emptyReserved: Set<String> = []
        return stagePackageIntoSyncedFolder(src, reservedBatchNames: &emptyReserved)
    }

    @discardableResult
    private func stagePackageIntoSyncedFolder(_ src: URL, reservedBatchNames: inout Set<String>) -> URL? {
        let ext = src.pathExtension.lowercased()
        guard ext == "ipa" || ext == "tipa" else { return nil }
        let rawName = src.lastPathComponent
        let isFromPickedStage = src.deletingLastPathComponent().lastPathComponent == "WQGuardPicked"
        // Strip temporary `<8 uppercase hex>_` prefix ONLY when staged by `SystemDocumentPicker.stageCopiedFilesIfNeeded`
        // (never stripping legitimate 8-letter app names such as `MetaMask_App.ipa` or `Telegram_App.ipa`).
        let baseName: String
        if isFromPickedStage,
           rawName.count > 9,
           let underscoreIdx = rawName.firstIndex(of: "_"),
           rawName.distance(from: rawName.startIndex, to: underscoreIdx) == 8,
           rawName[..<underscoreIdx].utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x46) }) {
            baseName = String(rawName[rawName.index(after: underscoreIdx)...])
        } else {
            baseName = rawName
        }
        guard !baseName.isEmpty,
              baseName.count <= 230,
              !baseName.contains("/"),
              !baseName.contains("\\"),
              !baseName.contains("\0"),
              baseName != ".",
              baseName != ".." else {
            return nil
        }

        // Disambiguate colliding filenames within the same multi-select batch so no selected IPA overwrites another
        var cleanName = baseName
        if reservedBatchNames.contains(cleanName.lowercased()) {
            let nsBase = baseName as NSString
            let stem = nsBase.deletingPathExtension
            let pathExt = nsBase.pathExtension
            var suffix = 2
            while suffix <= 999 {
                let candidate = pathExt.isEmpty ? "\(stem) (\(suffix))" : "\(stem) (\(suffix)).\(pathExt)"
                if !reservedBatchNames.contains(candidate.lowercased()) {
                    cleanName = candidate
                    break
                }
                suffix += 1
            }
        }

        let dst = syncedPackagesDirectory.appendingPathComponent(cleanName)
        let cleanSrcPath = IPAPackageScanner.stripTrailingSlashes(src.path)
        let cleanDstPath = IPAPackageScanner.stripTrailingSlashes(dst.path)
        if cleanSrcPath == cleanDstPath {
            var lst = stat()
            guard lstat(cleanDstPath, &lst) == 0, (lst.st_mode & S_IFMT) == S_IFREG else { return nil }
            reservedBatchNames.insert(cleanName.lowercased())
            return dst
        }
        if (try? IPAPackageScanner.copyBoundedRegularFileNoFollow(
            from: src,
            to: dst,
            maxBytes: Self.maxPackageFileBytes
        )) != nil {
            reservedBatchNames.insert(cleanName.lowercased())
            if isFromPickedStage {
                _ = Darwin.unlink(cleanSrcPath)
            }
            return dst
        }
        return nil
    }

    @discardableResult
    private func persistPackageToSyncedCacheIfApplicable(_ src: URL, reservedBatchNames: inout Set<String>) -> URL? {
        stagePackageIntoSyncedFolder(src, reservedBatchNames: &reservedBatchNames)
    }

    public func handleIncomingURL(_ url: URL) {
        guard url.isFileURL else { return }
        let ext = url.pathExtension.lowercased()
        if ext == "ipa" || ext == "tipa" {
            scanIPAPackage(at: url)
            return
        }

        // Read security-scoped data ONCE inside a single start/stop pair using O_NOFOLLOW + size cap
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }

        let maxBytes = (ext == "mobiledevicepairing") ? Self.maxPairingFileBytes : Self.maxSnapshotFileBytes
        guard let rawData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: url, maxBytes: maxBytes) else {
            activeAlertMessage = WQStrings.incomingFileReadFailed(url.lastPathComponent)
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
            activeAlertMessage = WQStrings.pairingFileRequiredAlert
            showGlobalAlert = true
            return
        }
        guard !isScanning else { return }
        showInstalledScanConfigSheet = false
        isScanning = true
        let host = lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "10.7.0.1" : lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines)
        scanProgress = ScanProgress(currentTarget: WQStrings.connectingViaLocalDevVPN(host: host), completedCount: 0, totalCount: 1)

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            do {
                let liveRecords = try await LockdownInstProxyClient.shared.fetchInstalledApps(
                    pairing: pairing,
                    preferredHost: host
                )
                // Cache live records to local snapshot store so future offline scans remain instant even when VPN is off
                if let encoded = try? JSONEncoder().encode(liveRecords), encoded.count <= Self.maxSnapshotFileBytes {
                    try? IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(encoded, to: self.savedSnapshotURL)
                    UserDefaults.standard.set(WQStrings.localDevVPNCacheName, forKey: Self.snapshotNameKey)
                    self.refreshRegistrySourceState()
                }
                self.isScanning = false
                self.scanProgress = nil
                self.runUnifiedScanWithPreloadedRegistry(liveRecords, liveConnected: true)
            } catch {
                self.isScanning = false
                self.scanProgress = nil
                self.activeAlertMessage = WQStrings.liveConnectionFailedMessage(error.localizedDescription)
                self.showGlobalAlert = true
                #if os(iOS)
                UINotificationFeedbackGenerator().notificationOccurred(.error)
                #endif
            }
        }
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

    // MARK: - Unified Installed Application Scan Actions (Registry + Synced IPA Queue + On-Device Probe)
    public func startSystemScan() {
        guard !isScanning else { return }
        _ = autoImportFromDocumentsFolderIfNeeded()
        isScanning = true
        scanProgress = ScanProgress(currentTarget: WQStrings.scanEngineInitializing, completedCount: 0, totalCount: 0)
        let extraScanDirs = [syncedPackagesDirectory]
        let pairing = loadActivePairingFile()
        let snapData = loadSavedSnapshotData()
        let host = lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "10.7.0.1" : lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let includeStore = includeAppStoreAppsInRegistry
        let probeEnabled = enableOnDeviceProbe

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            let startTime = Date()

            do {
                let unified = try await SecurityPipeline.shared.scanUnifiedInstalledAppsAsync(
                    pairingFile: pairing,
                    preferredLockdownHost: host,
                    savedSnapshotData: snapData,
                    additionalLocations: extraScanDirs,
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
        let extraScanDirs = [syncedPackagesDirectory]
        let includeStore = includeAppStoreAppsInRegistry
        let probeEnabled = enableOnDeviceProbe

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            let startTime = Date()

            let pkgFindings = (try? await SecurityPipeline.shared.scanInstalledAppsAsync(additionalLocations: extraScanDirs) { [weak self] progress in
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
                statusNotice: WQStrings.liveRegistryReadNotice(count: liveRecords.count)
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
            parts.append(WQStrings.summaryLiveRegistry(res.registryEvaluatedCount))
        } else if res.registryEvaluatedCount > 0 {
            parts.append(WQStrings.summarySnapshotRegistry(res.registryEvaluatedCount))
        }
        if res.correlatedBinaryCount > 0 {
            parts.append(WQStrings.summaryCorrelatedBinary(res.correlatedBinaryCount))
        }
        if res.probeDetectedCount > 0 {
            parts.append(WQStrings.summaryProbeDetected(res.probeDetectedCount))
        }
        if parts.isEmpty {
            return WQStrings.summaryLocalIPAQueue(res.findings.count)
        }
        return parts.joined(separator: " · ")
    }

    public func cancelScan() {
        activeScanTask?.cancel()
        activeScanTask = nil
        isScanning = false
        scanProgress = nil
    }

    // MARK: - Multi-Select IPA Package Scan Actions
    public func scanIPAPackage(at url: URL) {
        scanMultipleIPAPackages(at: [url], correlateWithInstalled: false)
    }

    public func scanMultipleIPAPackages(at urls: [URL], correlateWithInstalled: Bool = false) {
        guard !urls.isEmpty else { return }

        // Synchronously acquire security scope and persist all selected `.ipa` / `.tipa` files into `SyncedPackages`
        var preScopedPairs: [(URL, Bool)] = []
        var cachedTargets: [URL] = []
        var reservedBatchNames: Set<String> = []
        for u in urls {
            let accessed = u.startAccessingSecurityScopedResource()
            preScopedPairs.append((u, accessed))
            let ext = u.pathExtension.lowercased()
            if ext == "ipa" || ext == "tipa" {
                if let cached = persistPackageToSyncedCacheIfApplicable(u, reservedBatchNames: &reservedBatchNames) {
                    cachedTargets.append(cached)
                } else {
                    cachedTargets.append(u)
                }
            }
        }
        refreshSyncedPackageNames()

        guard !cachedTargets.isEmpty else {
            for (u, accessed) in preScopedPairs where accessed {
                u.stopAccessingSecurityScopedResource()
            }
            handleIPAScanFailure(WQStrings.batchIPANoValidTargets)
            return
        }

        // If invoked from Dashboard or Engine 2 Config Sheet, run unified scan across all queued IPAs + Registry!
        if correlateWithInstalled {
            for (u, accessed) in preScopedPairs where accessed {
                u.stopAccessingSecurityScopedResource()
            }
            showInstalledScanConfigSheet = false
            startSystemScan()
            return
        }

        isInspectingIPA = true
        isScanning = true
        ipaErrorMessage = nil
        scanProgress = ScanProgress(currentTarget: WQStrings.scanEngineInitializing, completedCount: 0, totalCount: cachedTargets.count)

        let capturedScopedPairs = preScopedPairs
        let scanTargets = cachedTargets

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
                    var results: [ScanFinding] = []
                    var lastError: Error?
                    let total = scanTargets.count
                    var completed = 0

                    for target in scanTargets {
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
                            let finding = try SecurityPipeline.shared.scanIPA(at: target)
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
                            if total > 1 {
                                let malformedFinding = SecurityPipeline.makeMalformedPackageFinding(for: target, error: error)
                                results.append(malformedFinding)
                                let progress = ScanProgress(
                                    currentTarget: target.lastPathComponent,
                                    completedCount: completed,
                                    totalCount: total,
                                    currentFinding: malformedFinding
                                )
                                Task { @MainActor [weak self] in
                                    self?.scanProgress = progress
                                }
                            }
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
                self.handleIPAScanFailure(error.localizedDescription)
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
        let trimmedBid = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedBid.isEmpty else { return }
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? trimmedBid : name.trimmingCharacters(in: .whitespacesAndNewlines)
        if let existing = WhitelistEngine.shared.tool(named: cleanName), existing.isBuiltIn {
            return
        }
        let groups = appGroup.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? []
            : [appGroup.trimmingCharacters(in: .whitespacesAndNewlines)]

        let newTool = WhitelistedTool(
            name: cleanName,
            allowedBundleIds: [trimmedBid],
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
        if let existing = WhitelistEngine.shared.tool(named: name), existing.isBuiltIn {
            return
        }
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
            let provisionalRisk: RiskTier
            if finding.indicators.contains(where: { $0.severity == .highRisk }) {
                provisionalRisk = .highRisk
            } else if finding.indicators.contains(where: { $0.severity == .caution }) {
                provisionalRisk = .caution
            } else {
                provisionalRisk = .safe
            }

            let wlResult: (isWhitelisted: Bool, toolName: String?)
            if provisionalRisk == .highRisk || provisionalRisk == .caution {
                wlResult = WhitelistEngine.shared.evaluateFindingWhitelist(finding)
            } else {
                wlResult = (false, nil)
            }

            let newTier: RiskTier = wlResult.isWhitelisted ? .knownTool : provisionalRisk

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

        let tempDir = Self.ensureSafeNonSymlinkDirectory(
            at: FileManager.default.temporaryDirectory.appendingPathComponent("WQGuardAuditReports", isDirectory: true)
        )

        switch exportFormat {
        case .markdown:
            let md = ReportGenerator.shared.generateMarkdownReport(session: session)
            self.exportedReportText = md
            let url = tempDir.appendingPathComponent("WQGuard-Audit-Report-\(session.sessionId).md")
            try? IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(Data(md.utf8), to: url)
            self.exportedReportURL = url

        case .json:
            if let data = try? ReportGenerator.shared.generateJSONReport(session: session),
               let jsonStr = String(data: data, encoding: .utf8) {
                self.exportedReportText = jsonStr
                let url = tempDir.appendingPathComponent("WQGuard-Audit-Report-\(session.sessionId).json")
                try? IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(data, to: url)
                self.exportedReportURL = url
            }

        case .plainText:
            let text = ReportGenerator.shared.generatePlainTextReport(session: session)
            self.exportedReportText = text
            let url = tempDir.appendingPathComponent("WQGuard-Audit-Report-\(session.sessionId).txt")
            try? IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(Data(text.utf8), to: url)
            self.exportedReportURL = url
        }
    }

    // MARK: - Multi-Client Brotli Shield Exporter
    public func prepareSurgeExportURL(extraHosts: [String] = []) {
        do {
            let url = try SurgeBrotliShieldHelper.shared.exportShieldToTemporaryFile(
                for: selectedShieldPlatform,
                extraHosts: extraHosts
            )
            self.surgeModuleExportURL = url
            self.surgeModuleContent = SurgeBrotliShieldHelper.shared.generateShieldContent(
                for: selectedShieldPlatform,
                extraHosts: extraHosts
            )
        } catch {
            self.activeAlertMessage = WQStrings.surgeGenerationFailedMessage(error.localizedDescription)
            self.showGlobalAlert = true
        }
    }

    public func refreshFirmwarePosture() {
        self.firmwareReport = FirmwarePostureEngine.shared.evaluate()
    }
}
