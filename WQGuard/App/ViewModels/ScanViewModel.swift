//
//  ScanViewModel.swift
//  WQGuard
//
//  Central @MainActor state coordinator managing active scan sessions, real-time
//  progress reporting, findings filtering, firmware posture evaluation, and report export.
//

import CryptoKit
import Darwin
import SwiftUI
import Combine
import UniformTypeIdentifiers
import WQGuardCore

private nonisolated final class ProgressSequenceBox: @unchecked Sendable {
    private let lock = NSLock()
    private var seq: UInt64 = 0

    func next() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        seq &+= 1
        return seq
    }
}

public nonisolated struct CustomRuleValidationResult: Sendable, Equatable {
    public let success: Bool
    public let errorMessage: String?

    public init(success: Bool, errorMessage: String? = nil) {
        self.success = success
        self.errorMessage = errorMessage
    }
}

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
    private static let snapshotCountKey = "wqguard.saved_snapshot_count.v1"
    private static let snapshotSHA256Key = "wqguard.saved_snapshot_sha256.v1"
    private static let autoImportFingerprintsKey = "wqguard.auto_import_fingerprints.v1"
    private static let customWhitelistRulesKey = "wqguard.custom_whitelist_rules.v1"
    private static let builtinWhitelistEnabledKey = "wqguard.builtin_whitelist_enabled.v1"
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

    // Background Tasks & Lifecycle Generation Guards
    private var activeScanTask: Task<Void, Never>?
    private var autoImportTask: Task<String?, Never>?
    private var scanGeneration: UInt64 = 0
    private var latestProgressSeq: UInt64 = 0
    private var registryStateGeneration: UInt64 = 0

    // MARK: - Initialization
    public init() {
        self.firmwareReport = FirmwarePostureEngine.shared.evaluate()
        Self.restorePersistedWhitelistState()
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
        self.loadLightweightRegistrySourceState()
        Task { [weak self] in
            await self?.refreshRegistrySourceStateAsync()
        }
    }

    public func navigateToFindings(filter: RiskTier? = nil) {
        self.selectedRiskFilter = filter
        self.selectedTab = 1
    }

    private nonisolated static let maxPairingFileBytes = 4 * 1024 * 1024
    private nonisolated static let maxSnapshotFileBytes = 128 * 1024 * 1024
    private nonisolated static let maxPackageFileBytes = 1024 * 1024 * 1024

    private nonisolated static func ensureSafeNonSymlinkDirectory(at dirURL: URL) -> URL {
        let clean = IPAPackageScanner.stripTrailingSlashes(dirURL.path)
        var st = stat()
        if lstat(clean, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK {
            try? FileManager.default.removeItem(at: dirURL)
        }
        try? FileManager.default.createDirectory(at: dirURL, withIntermediateDirectories: true)
        return dirURL
    }

    private nonisolated static func resolveAppSupportDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let dir = base.appendingPathComponent("WQGuardRegistry", isDirectory: true)
        return ensureSafeNonSymlinkDirectory(at: dir)
    }

    private nonisolated static func resolveSyncedPackagesDirectory() -> URL {
        let dir = resolveAppSupportDirectory().appendingPathComponent("SyncedPackages", isDirectory: true)
        return ensureSafeNonSymlinkDirectory(at: dir)
    }

    private var appSupportDirectory: URL {
        Self.resolveAppSupportDirectory()
    }

    private var syncedPackagesDirectory: URL {
        Self.resolveSyncedPackagesDirectory()
    }

    private var savedPairingURL: URL {
        appSupportDirectory.appendingPathComponent("active_device.mobiledevicepairing")
    }

    private var savedSnapshotURL: URL {
        appSupportDirectory.appendingPathComponent("installed_apps_snapshot.dat")
    }

    private nonisolated static func loadActivePairingFile(at url: URL) -> LockdownPairingFile? {
        return try? LockdownPairingFile.parse(from: url)
    }

    private func loadActivePairingFile() -> LockdownPairingFile? {
        return Self.loadActivePairingFile(at: savedPairingURL)
    }

    private nonisolated static func loadSavedSnapshotData(at url: URL) -> Data? {
        return try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(
            at: url,
            maxBytes: maxSnapshotFileBytes
        )
    }

    private func loadSavedSnapshotData() -> Data? {
        return Self.loadSavedSnapshotData(at: savedSnapshotURL)
    }

    private nonisolated static func sha256Hex(of data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func loadLightweightRegistrySourceState() {
        if let pairing = loadActivePairingFile() {
            hasPairingFile = true
            let prefix = String(pairing.hostID.prefix(8))
            pairingHostIDSummary = pairing.udid.map { "UDID: \($0.prefix(10))… (Host: \(prefix)…)" } ?? "HostID: \(prefix)…"
        } else {
            hasPairingFile = false
            pairingHostIDSummary = nil
        }

        var st = stat()
        let snapPath = IPAPackageScanner.stripTrailingSlashes(savedSnapshotURL.path)
        if lstat(snapPath, &st) == 0,
           (st.st_mode & S_IFMT) == S_IFREG,
           st.st_size > 0,
           st.st_size <= off_t(Self.maxSnapshotFileBytes) {
            hasSavedSnapshot = true
            savedSnapshotAppCount = UserDefaults.standard.integer(forKey: Self.snapshotCountKey)
            savedSnapshotFilename = UserDefaults.standard.string(forKey: Self.snapshotNameKey) ?? "installed_apps.plist"
        } else {
            hasSavedSnapshot = false
            savedSnapshotAppCount = 0
            savedSnapshotFilename = nil
        }
    }

    public func refreshRegistrySourceStateAsync() async {
        let gen = registryStateGeneration
        let pairingURL = savedPairingURL
        let snapURL = savedSnapshotURL
        let fallbackSnapName = UserDefaults.standard.string(forKey: Self.snapshotNameKey) ?? "installed_apps.plist"

        let result = await Task.detached(priority: .utility) { () -> (pairing: LockdownPairingFile?, snapCount: Int?, snapSHA: String?) in
            let pairing = Self.loadActivePairingFile(at: pairingURL)
            if let snapData = Self.loadSavedSnapshotData(at: snapURL),
               let records = try? InstalledAppRegistryScanner.shared.parseSnapshotData(snapData) {
                return (pairing, records.count, Self.sha256Hex(of: snapData))
            }
            return (pairing, nil, nil)
        }.value

        guard registryStateGeneration == gen else { return }
        applyRegistrySourceState(
            pairing: result.pairing,
            snapshotCount: result.snapCount,
            snapshotFilename: result.snapCount != nil ? fallbackSnapName : nil,
            snapshotSHA256: result.snapSHA
        )
    }

    public func refreshRegistrySourceState() {
        let pairing = loadActivePairingFile()
        if let snapData = loadSavedSnapshotData(),
           let records = try? InstalledAppRegistryScanner.shared.parseSnapshotData(snapData) {
            let name = UserDefaults.standard.string(forKey: Self.snapshotNameKey) ?? "installed_apps.plist"
            applyRegistrySourceState(
                pairing: pairing,
                snapshotCount: records.count,
                snapshotFilename: name,
                snapshotSHA256: Self.sha256Hex(of: snapData)
            )
        } else {
            applyRegistrySourceState(pairing: pairing, snapshotCount: nil, snapshotFilename: nil, snapshotSHA256: nil)
        }
    }

    private func applyRegistrySourceState(
        pairing: LockdownPairingFile?,
        snapshotCount: Int?,
        snapshotFilename: String?,
        snapshotSHA256: String?
    ) {
        registryStateGeneration &+= 1
        if let pairing = pairing {
            hasPairingFile = true
            let prefix = String(pairing.hostID.prefix(8))
            pairingHostIDSummary = pairing.udid.map { "UDID: \($0.prefix(10))… (Host: \(prefix)…)" } ?? "HostID: \(prefix)…"
        } else {
            hasPairingFile = false
            pairingHostIDSummary = nil
        }

        if let count = snapshotCount {
            hasSavedSnapshot = true
            savedSnapshotAppCount = count
            savedSnapshotFilename = snapshotFilename ?? UserDefaults.standard.string(forKey: Self.snapshotNameKey) ?? "installed_apps.plist"
            UserDefaults.standard.set(count, forKey: Self.snapshotCountKey)
            if let sha = snapshotSHA256 {
                UserDefaults.standard.set(sha, forKey: Self.snapshotSHA256Key)
            }
        } else {
            hasSavedSnapshot = false
            savedSnapshotAppCount = 0
            savedSnapshotFilename = nil
            UserDefaults.standard.removeObject(forKey: Self.snapshotCountKey)
            UserDefaults.standard.removeObject(forKey: Self.snapshotSHA256Key)
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
        defer {
            if accessed { url.stopAccessingSecurityScopedResource() }
            NativeDocumentPickerPresenter.cleanupPickedStagingFileIfApplicable(url)
        }

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

    public func importPairingFileAsync(from url: URL) async -> Result<String, Error> {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed { url.stopAccessingSecurityScopedResource() }
            NativeDocumentPickerPresenter.cleanupPickedStagingFileIfApplicable(url)
        }
        let stem = url.deletingPathExtension().lastPathComponent
        let targetPairingURL = savedPairingURL
        let maxBytes = Self.maxPairingFileBytes

        let outcome = await Task.detached(priority: .userInitiated) { () -> Result<(LockdownPairingFile, Data), Error> in
            do {
                let data = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: url, maxBytes: maxBytes)
                guard data.count <= maxBytes else {
                    throw LockdownClientError.invalidPairingFile("Pairing payload exceeds \(maxBytes) bytes")
                }
                let pairing = try LockdownPairingFile.parse(data: data, fallbackUDID: stem)
                try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(data, to: targetPairingURL)
                return .success((pairing, data))
            } catch {
                return .failure(error)
            }
        }.value

        switch outcome {
        case .success(let (pairing, _)):
            applyPairingImported(pairing)
            let summary = WQStrings.pairingImportedSummary(hostPrefix: String(pairing.hostID.prefix(8)))
            lastScanEngineSummary = summary
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            #endif
            return .success(summary)
        case .failure(let error):
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            #endif
            return .failure(error)
        }
    }

    private func applyPairingImported(_ pairing: LockdownPairingFile) {
        registryStateGeneration &+= 1
        hasPairingFile = true
        let prefix = String(pairing.hostID.prefix(8))
        pairingHostIDSummary = pairing.udid.map { "UDID: \($0.prefix(10))… (Host: \(prefix)…)" } ?? "HostID: \(prefix)…"
    }

    private func importPairingDataWithResult(_ data: Data, fallbackUDID: String?) -> Result<String, Error> {
        do {
            guard data.count <= Self.maxPairingFileBytes else {
                throw LockdownClientError.invalidPairingFile("Pairing payload exceeds \(Self.maxPairingFileBytes) bytes")
            }
            let pairing = try LockdownPairingFile.parse(data: data, fallbackUDID: fallbackUDID)
            try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(data, to: savedPairingURL)
            applyPairingImported(pairing)
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
        registryStateGeneration &+= 1
        try? FileManager.default.removeItem(at: savedPairingURL)
        hasPairingFile = false
        pairingHostIDSummary = nil
    }

    private nonisolated static func estimateBoundedXMLPlistSize(
        _ value: Any,
        depth: Int = 0,
        maxDepth: Int = 8,
        budgetRemaining: inout Int,
        nodesRemaining: inout Int
    ) -> Bool {
        guard depth <= maxDepth, nodesRemaining > 0, budgetRemaining >= 0 else {
            return false
        }
        nodesRemaining -= 1

        if let str = value as? String {
            budgetRemaining -= (str.utf8.count + 32)
            return budgetRemaining >= 0
        }
        if let data = value as? Data {
            budgetRemaining -= ((data.count * 4 / 3) + 64)
            return budgetRemaining >= 0
        }
        if value is NSNumber || value is Date {
            budgetRemaining -= 48
            return budgetRemaining >= 0
        }
        if let arr = value as? [Any] {
            budgetRemaining -= 32
            guard budgetRemaining >= 0 else { return false }
            for elem in arr {
                if !estimateBoundedXMLPlistSize(
                    elem,
                    depth: depth + 1,
                    maxDepth: maxDepth,
                    budgetRemaining: &budgetRemaining,
                    nodesRemaining: &nodesRemaining
                ) {
                    return false
                }
            }
            return true
        }
        if let dict = value as? [String: Any] {
            budgetRemaining -= 32
            guard budgetRemaining >= 0 else { return false }
            for (k, v) in dict {
                budgetRemaining -= (k.utf8.count + 32)
                guard budgetRemaining >= 0 else { return false }
                if !estimateBoundedXMLPlistSize(
                    v,
                    depth: depth + 1,
                    maxDepth: maxDepth,
                    budgetRemaining: &budgetRemaining,
                    nodesRemaining: &nodesRemaining
                ) {
                    return false
                }
            }
            return true
        }
        return false
    }

    private nonisolated static func isBoundedXMLPlist(_ value: Any, maxBytes: Int) -> Bool {
        var budget = maxBytes
        var nodes = 512
        return estimateBoundedXMLPlistSize(value, depth: 0, maxDepth: 8, budgetRemaining: &budget, nodesRemaining: &nodes)
    }

    private nonisolated static func readSecurityScopedBoundedPairingFile(at fileURL: URL) -> Data? {
        guard fileURL.isFileURL else { return nil }
        let accessed = fileURL.startAccessingSecurityScopedResource()
        defer { if accessed { fileURL.stopAccessingSecurityScopedResource() } }
        return try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(
            at: fileURL,
            maxBytes: maxPairingFileBytes
        )
    }

    /// Reads a `.plist` / `.mobiledevicepairing` file or XML text directly from `UIPasteboard.general`
    /// (supports copying the `.plist` file in iOS Files App OR copying XML text via Universal Clipboard).
    public func importPairingFromClipboardWithResult() -> Result<String, Error> {
        #if canImport(UIKit)
        let pb = UIPasteboard.general

        // 1. Plain XML / Base64 string on clipboard (pre-flight UTF-8 length check before trimming)
        if let rawStr = pb.string, rawStr.utf8.count <= Self.maxPairingFileBytes * 2 {
            let str = rawStr.trimmingCharacters(in: .whitespacesAndNewlines)
            if !str.isEmpty, str.utf8.count <= Self.maxPairingFileBytes {
                let utf8Data = Data(str.utf8)
                if case .success(let msg) = importPairingDataWithResult(utf8Data, fallbackUDID: nil) {
                    return .success(msg)
                }
                if let b64Data = Data(base64Encoded: str, options: .ignoreUnknownCharacters),
                   b64Data.count <= Self.maxPairingFileBytes,
                   case .success(let msg) = importPairingDataWithResult(b64Data, fallbackUDID: nil) {
                    return .success(msg)
                }
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
                    if let fileURL = URL(string: s),
                       let fileData = Self.readSecurityScopedBoundedPairingFile(at: fileURL) {
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
                          let fileData = Self.readSecurityScopedBoundedPairingFile(at: fileURL) {
                    switch importPairingDataWithResult(fileData, fallbackUDID: fileURL.deletingPathExtension().lastPathComponent) {
                    case .success(let msg): return .success(msg)
                    case .failure(let err): lastParseError = err
                    }
                } else if let dictVal = rawVal as? [String: Any],
                          dictVal.count <= 64,
                          Self.isBoundedXMLPlist(dictVal, maxBytes: Self.maxPairingFileBytes),
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

    private nonisolated struct AutoImportBackgroundOutcome: Sendable {
        var importedPairing: (pairing: LockdownPairingFile, data: Data, sourcePath: String, fingerprint: String)? = nil
        var importedSnapshot: (count: Int, filename: String, sha256: String, data: Data, sourcePath: String, fingerprint: String)? = nil
        var syncedNewIPA: Bool = false
        var updatedFingerprints: [String: String] = [:]
    }

    /// Coalesced async auto-import of `.mobiledevicepairing` / `.plist` / `.json` / `.ipa` / `.tipa`
    /// placed into `On My iPhone → WQGuard` (`Documents/` or `Documents/Inbox/`).
    @discardableResult
    public func autoImportFromDocumentsFolderIfNeededAsync() async -> String? {
        if let existing = autoImportTask {
            return await existing.value
        }
        let task = Task<String?, Never> { [weak self] in
            guard let self else { return nil }
            defer { self.autoImportTask = nil }
            return await self.performAutoImportFromDocumentsOffMainThread()
        }
        autoImportTask = task
        return await task.value
    }

    private func performAutoImportFromDocumentsOffMainThread() async -> String? {
        let initialRegistryGen = registryStateGeneration
        let pairingURL = savedPairingURL
        let snapshotURL = savedSnapshotURL
        let syncedDir = syncedPackagesDirectory
        let existingSyncedLowered = Set(syncedPackageNames.map { $0.lowercased() })
        let cachedFingerprints = (UserDefaults.standard.dictionary(forKey: Self.autoImportFingerprintsKey) as? [String: String]) ?? [:]
        let currentSnapSHA = UserDefaults.standard.string(forKey: Self.snapshotSHA256Key)
        let currentHostID = loadActivePairingFile()?.hostID

        let outcome = await Task.detached(priority: .utility) { () -> AutoImportBackgroundOutcome in
            var result = AutoImportBackgroundOutcome()
            result.updatedFingerprints = cachedFingerprints

            let fm = FileManager.default
            guard let docsURL = fm.urls(for: .documentDirectory, in: .userDomainMask).first else {
                return result
            }

            let scanDirs = [docsURL, docsURL.appendingPathComponent("Inbox", isDirectory: true)]
            var reservedBatchNames = existingSyncedLowered
            var activeHostID = currentHostID
            var activeSnapSHA = currentSnapSHA
            let maxDirEntries = 256

            for dir in scanDirs {
                guard IPAPackageScanner.isNonSymlinkDirectory(at: dir),
                      let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
                    continue
                }
                for item in items.prefix(maxDirEntries) {
                    let ext = item.pathExtension.lowercased()
                    guard ext == "ipa" || ext == "tipa" || ext == "mobiledevicepairing" || ext == "plist" || ext == "xml" || ext == "json" else {
                        continue
                    }

                    let cleanPath = IPAPackageScanner.stripTrailingSlashes(item.path)
                    let maxAllowedSize: Int64 = (ext == "ipa" || ext == "tipa")
                        ? Int64(Self.maxPackageFileBytes)
                        : Int64(ext == "mobiledevicepairing" ? Self.maxPairingFileBytes : Self.maxSnapshotFileBytes)

                    var st = stat()
                    guard lstat(cleanPath, &st) == 0,
                          (st.st_mode & S_IFMT) == S_IFREG,
                          st.st_size > 0,
                          st.st_size <= off_t(maxAllowedSize) else {
                        continue
                    }

                    let fp = "\(st.st_size):\(st.st_mtimespec.tv_sec):\(st.st_mtimespec.tv_nsec)"

                    if ext == "ipa" || ext == "tipa" {
                        let candidateSanitized = Self.sanitizeSyncedPackageFilename(item.lastPathComponent, stripPickedPrefix: false)?.lowercased()
                        if cachedFingerprints[cleanPath] == fp,
                           let cand = candidateSanitized,
                           reservedBatchNames.contains(cand) {
                            continue
                        }
                        if Self.stagePackageIntoSyncedFolderNonisolated(
                            item,
                            syncedDirectory: syncedDir,
                            reservedBatchNames: &reservedBatchNames
                        ) != nil {
                            result.syncedNewIPA = true
                            result.updatedFingerprints[cleanPath] = fp
                        }
                        continue
                    }

                    if cachedFingerprints[cleanPath] == fp {
                        continue
                    }

                    let maxImportBytes = (ext == "mobiledevicepairing") ? Self.maxPairingFileBytes : Self.maxSnapshotFileBytes
                    guard let data = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: item, maxBytes: maxImportBytes),
                          !data.isEmpty else {
                        continue
                    }

                    let stem = item.deletingPathExtension().lastPathComponent
                    if data.count <= Self.maxPairingFileBytes,
                       let parsedPairing = try? LockdownPairingFile.parse(data: data, fallbackUDID: stem) {
                        if activeHostID != parsedPairing.hostID {
                            activeHostID = parsedPairing.hostID
                            result.importedPairing = (parsedPairing, data, cleanPath, fp)
                        } else {
                            result.updatedFingerprints[cleanPath] = fp
                        }
                    } else if let records = try? InstalledAppRegistryScanner.shared.parseSnapshotData(data) {
                        let sha = Self.sha256Hex(of: data)
                        if activeSnapSHA != sha {
                            activeSnapSHA = sha
                            result.importedSnapshot = (records.count, item.lastPathComponent, sha, data, cleanPath, fp)
                        } else {
                            result.updatedFingerprints[cleanPath] = fp
                        }
                    }
                }
            }

            if result.updatedFingerprints.count > 512 {
                result.updatedFingerprints = Dictionary(result.updatedFingerprints.suffix(256), uniquingKeysWith: { _, latest in latest })
            }
            return result
        }.value

        var finalFingerprints = outcome.updatedFingerprints
        let registryUntouched = (self.registryStateGeneration == initialRegistryGen)

        var notices: [String] = []
        var appliedPairing: LockdownPairingFile? = nil
        if registryUntouched, let pairingInfo = outcome.importedPairing {
            if (try? IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(pairingInfo.data, to: pairingURL)) != nil {
                finalFingerprints[pairingInfo.sourcePath] = pairingInfo.fingerprint
                applyPairingImported(pairingInfo.pairing)
                appliedPairing = pairingInfo.pairing
                let summary = WQStrings.pairingImportedSummary(hostPrefix: String(pairingInfo.pairing.hostID.prefix(8)))
                lastScanEngineSummary = summary
                notices.append(WQStrings.autoImportedPairingNotice(summary))
            }
        }
        if registryUntouched, let snap = outcome.importedSnapshot {
            if (try? IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(snap.data, to: snapshotURL)) != nil {
                finalFingerprints[snap.sourcePath] = snap.fingerprint
                UserDefaults.standard.set(snap.filename, forKey: Self.snapshotNameKey)
                applyRegistrySourceState(
                    pairing: nil,
                    snapshotCount: snap.count,
                    snapshotFilename: snap.filename,
                    snapshotSHA256: snap.sha256
                )
                // Preserve pairing state updated just above if both arrived together
                if appliedPairing == nil, let existingPairing = loadActivePairingFile() {
                    applyPairingImported(existingPairing)
                } else if let pairing = appliedPairing {
                    applyPairingImported(pairing)
                }
                let summary = WQStrings.snapshotImportedSummary(count: snap.count)
                lastScanEngineSummary = summary
                notices.append(WQStrings.autoImportedSnapshotNotice(summary))
            }
        }
        if finalFingerprints.count > 512 {
            finalFingerprints = Dictionary(finalFingerprints.suffix(256), uniquingKeysWith: { _, latest in latest })
        }
        UserDefaults.standard.set(finalFingerprints, forKey: Self.autoImportFingerprintsKey)
        if outcome.syncedNewIPA {
            refreshSyncedPackageNames()
            notices.append(WQStrings.autoImportedIPANotice)
        }

        return notices.isEmpty ? nil : notices.joined(separator: WQStrings.autoImportNoticeSeparator)
    }

    public func importRegistrySnapshot(from url: URL, autoScan: Bool = true) {
        Task { [weak self] in
            guard let self else { return }
            if case .failure(let error) = await self.importRegistrySnapshotAsync(from: url, autoScan: autoScan) {
                self.activeAlertMessage = error.localizedDescription
                self.showGlobalAlert = true
            }
        }
    }

    public func importRegistrySnapshotAsync(from url: URL, autoScan: Bool = true) async -> Result<String, Error> {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed { url.stopAccessingSecurityScopedResource() }
            NativeDocumentPickerPresenter.cleanupPickedStagingFileIfApplicable(url)
        }

        let filename = url.lastPathComponent
        let targetSnapshotURL = savedSnapshotURL
        let maxBytes = Self.maxSnapshotFileBytes

        let outcome = await Task.detached(priority: .userInitiated) { () -> Result<(count: Int, sha256: String), Error> in
            do {
                let data = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: url, maxBytes: maxBytes)
                guard data.count <= maxBytes else {
                    throw IPAPackageScannerError.quotaExceeded("Snapshot exceeds \(maxBytes) bytes")
                }
                let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(data)
                try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(data, to: targetSnapshotURL)
                return .success((records.count, Self.sha256Hex(of: data)))
            } catch {
                return .failure(error)
            }
        }.value

        switch outcome {
        case .success(let (count, sha)):
            registryStateGeneration &+= 1
            UserDefaults.standard.set(filename, forKey: Self.snapshotNameKey)
            hasSavedSnapshot = true
            savedSnapshotAppCount = count
            savedSnapshotFilename = filename
            UserDefaults.standard.set(count, forKey: Self.snapshotCountKey)
            UserDefaults.standard.set(sha, forKey: Self.snapshotSHA256Key)

            let summary = WQStrings.snapshotImportedSummary(count: count)
            lastScanEngineSummary = summary
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            #endif
            if autoScan {
                showInstalledScanConfigSheet = false
                startSystemScan()
            }
            return .success(summary)
        case .failure(let error):
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            #endif
            return .failure(error)
        }
    }

    public func importRegistrySnapshotWithResult(from url: URL, autoScan: Bool = true) -> Result<String, Error> {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed { url.stopAccessingSecurityScopedResource() }
            NativeDocumentPickerPresenter.cleanupPickedStagingFileIfApplicable(url)
        }

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
            registryStateGeneration &+= 1
            UserDefaults.standard.set(filename, forKey: Self.snapshotNameKey)
            let sha = Self.sha256Hex(of: data)
            hasSavedSnapshot = true
            savedSnapshotAppCount = records.count
            savedSnapshotFilename = filename
            UserDefaults.standard.set(records.count, forKey: Self.snapshotCountKey)
            UserDefaults.standard.set(sha, forKey: Self.snapshotSHA256Key)

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
        registryStateGeneration &+= 1
        try? FileManager.default.removeItem(at: savedSnapshotURL)
        UserDefaults.standard.removeObject(forKey: Self.snapshotNameKey)
        UserDefaults.standard.removeObject(forKey: Self.snapshotCountKey)
        UserDefaults.standard.removeObject(forKey: Self.snapshotSHA256Key)
        hasSavedSnapshot = false
        savedSnapshotAppCount = 0
        savedSnapshotFilename = nil
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

    private nonisolated static func sanitizeSyncedPackageFilename(
        _ rawName: String,
        stripPickedPrefix: Bool
    ) -> String? {
        let strippedPicked: String
        if stripPickedPrefix,
           rawName.count > 9,
           let underscoreIdx = rawName.firstIndex(of: "_"),
           rawName.distance(from: rawName.startIndex, to: underscoreIdx) == 8,
           rawName[..<underscoreIdx].utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x46) }) {
            strippedPicked = String(rawName[rawName.index(after: underscoreIdx)...])
        } else {
            strippedPicked = rawName
        }

        var filteredScalars: [UnicodeScalar] = []
        filteredScalars.reserveCapacity(strippedPicked.unicodeScalars.count)
        for scalar in strippedPicked.unicodeScalars {
            let v = scalar.value
            if v <= 0x1F || v == 0x7F || v == 0x2F || v == 0x5C {
                continue
            }
            filteredScalars.append(scalar)
        }
        var clean = String(String.UnicodeScalarView(filteredScalars))
        while clean.hasPrefix(".") {
            clean.removeFirst()
        }
        guard !clean.isEmpty, clean != ".", clean != ".." else {
            return nil
        }

        let nsClean = clean as NSString
        let ext = nsClean.pathExtension.lowercased()
        guard ext == "ipa" || ext == "tipa" else {
            return nil
        }

        let maxBaseUTF8Bytes = 230
        if clean.utf8.count <= maxBaseUTF8Bytes {
            return clean
        }

        let extWithDot = ".\(nsClean.pathExtension)"
        let stem = nsClean.deletingPathExtension
        var fnv: UInt32 = 2166136261
        for byte in clean.utf8 {
            fnv ^= UInt32(byte)
            fnv = fnv &* 16777619
        }
        let hashTag = String(format: "_%08x", fnv)
        let maxStemBytes = max(1, maxBaseUTF8Bytes - extWithDot.utf8.count - hashTag.utf8.count)

        var truncatedStem = ""
        var usedBytes = 0
        for ch in stem {
            let chBytes = String(ch).utf8.count
            if usedBytes + chBytes > maxStemBytes { break }
            truncatedStem.append(ch)
            usedBytes += chBytes
        }
        let result = "\(truncatedStem)\(hashTag)\(extWithDot)"
        guard !result.isEmpty,
              result != ".",
              result != "..",
              result.utf8.count <= maxBaseUTF8Bytes else {
            return nil
        }
        return result
    }

    @discardableResult
    private nonisolated static func stagePackageIntoSyncedFolderNonisolated(
        _ src: URL,
        syncedDirectory: URL,
        reservedBatchNames: inout Set<String>
    ) -> URL? {
        let ext = src.pathExtension.lowercased()
        guard ext == "ipa" || ext == "tipa" else { return nil }

        let cleanSrcPath = IPAPackageScanner.stripTrailingSlashes(src.path)
        var srcSt = stat()
        guard lstat(cleanSrcPath, &srcSt) == 0, (srcSt.st_mode & S_IFMT) == S_IFREG else {
            return nil
        }

        // Check in-place rescanning BEFORE filename sanitization / collision disambiguation
        // so 231..236-byte `(2)` collided files already in SyncedPackages/ stay in-place.
        let resolvedSrcParent = IPAPackageScanner.stripTrailingSlashes(
            src.deletingLastPathComponent().resolvingSymlinksInPath().path
        )
        let resolvedSyncedDir = IPAPackageScanner.stripTrailingSlashes(
            syncedDirectory.resolvingSymlinksInPath().path
        )
        if !resolvedSyncedDir.isEmpty && resolvedSrcParent == resolvedSyncedDir {
            reservedBatchNames.insert(src.lastPathComponent.lowercased())
            return src
        }

        let isFromPickedStage = src.deletingLastPathComponent().lastPathComponent == "WQGuardPicked"
        guard let baseName = sanitizeSyncedPackageFilename(src.lastPathComponent, stripPickedPrefix: isFromPickedStage) else {
            return nil
        }

        let directDst = syncedDirectory.appendingPathComponent(baseName)
        let cleanDirectDstPath = IPAPackageScanner.stripTrailingSlashes(directDst.path)

        if cleanSrcPath == cleanDirectDstPath {
            var lst = stat()
            guard lstat(cleanDirectDstPath, &lst) == 0, (lst.st_mode & S_IFMT) == S_IFREG else { return nil }
            reservedBatchNames.insert(baseName.lowercased())
            return directDst
        }

        // Disambiguate colliding filenames (case-insensitive for APFS) across existing SyncedPackages and batch
        var cleanName = baseName
        if reservedBatchNames.contains(cleanName.lowercased()) {
            let nsBase = baseName as NSString
            let stem = nsBase.deletingPathExtension
            let pathExt = nsBase.pathExtension
            var foundSlot = false
            var suffix = 2
            while suffix <= 999 {
                let candidate = pathExt.isEmpty ? "\(stem) (\(suffix))" : "\(stem) (\(suffix)).\(pathExt)"
                if candidate.utf8.count <= 255 && !reservedBatchNames.contains(candidate.lowercased()) {
                    cleanName = candidate
                    foundSlot = true
                    break
                }
                suffix += 1
            }
            guard foundSlot else { return nil }
        }

        guard cleanName.utf8.count <= 255 else { return nil }
        let dst = syncedDirectory.appendingPathComponent(cleanName)
        if (try? IPAPackageScanner.copyBoundedRegularFileNoFollow(
            from: src,
            to: dst,
            maxBytes: maxPackageFileBytes
        )) != nil {
            reservedBatchNames.insert(cleanName.lowercased())
            if isFromPickedStage {
                _ = Darwin.unlink(cleanSrcPath)
            }
            return dst
        }
        return nil
    }

    public func handleIncomingURL(_ url: URL) {
        guard url.isFileURL else { return }
        let ext = url.pathExtension.lowercased()
        if ext == "ipa" || ext == "tipa" {
            scanIPAPackage(at: url)
            return
        }

        Task { @MainActor [weak self] in
            guard let self else { return }
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }

            let filename = url.lastPathComponent
            let stem = url.deletingPathExtension().lastPathComponent
            let maxBytes = (ext == "mobiledevicepairing") ? Self.maxPairingFileBytes : Self.maxSnapshotFileBytes

            enum IncomingParsed {
                case readFailed
                case pairing(Data, LockdownPairingFile)
                case pairingError(Error)
                case snapshot(Data, Int)
                case snapshotError(Error)
            }

            let parsed = await Task.detached(priority: .userInitiated) { () -> IncomingParsed in
                guard let rawData = try? IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: url, maxBytes: maxBytes) else {
                    return .readFailed
                }
                if ext == "mobiledevicepairing" {
                    do {
                        let p = try LockdownPairingFile.parse(data: rawData, fallbackUDID: stem)
                        return .pairing(rawData, p)
                    } catch {
                        return .pairingError(error)
                    }
                }
                if rawData.count <= Self.maxPairingFileBytes,
                   let p = try? LockdownPairingFile.parse(data: rawData, fallbackUDID: stem) {
                    return .pairing(rawData, p)
                }
                do {
                    let records = try InstalledAppRegistryScanner.shared.parseSnapshotData(rawData)
                    return .snapshot(rawData, records.count)
                } catch {
                    return .snapshotError(error)
                }
            }.value

            switch parsed {
            case .readFailed:
                self.activeAlertMessage = WQStrings.incomingFileReadFailed(filename)
                self.showGlobalAlert = true
            case .pairing(let rawData, _):
                switch self.importPairingDataWithResult(rawData, fallbackUDID: stem) {
                case .success:
                    self.testLiveLockdownConnectionAndScan()
                case .failure(let err):
                    self.activeAlertMessage = err.localizedDescription
                    self.showGlobalAlert = true
                }
            case .pairingError(let err):
                self.activeAlertMessage = err.localizedDescription
                self.showGlobalAlert = true
            case .snapshot(let rawData, let count):
                do {
                    try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(rawData, to: self.savedSnapshotURL)
                    self.registryStateGeneration &+= 1
                    UserDefaults.standard.set(filename, forKey: Self.snapshotNameKey)
                    let sha = Self.sha256Hex(of: rawData)
                    self.hasSavedSnapshot = true
                    self.savedSnapshotAppCount = count
                    self.savedSnapshotFilename = filename
                    UserDefaults.standard.set(count, forKey: Self.snapshotCountKey)
                    UserDefaults.standard.set(sha, forKey: Self.snapshotSHA256Key)
                    self.lastScanEngineSummary = WQStrings.snapshotImportedSummary(count: count)
                    self.showInstalledScanConfigSheet = false
                    self.startSystemScan()
                } catch {
                    self.activeAlertMessage = error.localizedDescription
                    self.showGlobalAlert = true
                }
            case .snapshotError(let err):
                self.activeAlertMessage = err.localizedDescription
                self.showGlobalAlert = true
            }
        }
    }

    // MARK: - Scan Lifecycle Generation & Progress Ordering
    private func beginScanSession(isIPAInspection: Bool) -> UInt64 {
        activeScanTask?.cancel()
        activeScanTask = nil
        scanGeneration &+= 1
        latestProgressSeq = 0
        isScanning = true
        isInspectingIPA = isIPAInspection
        return scanGeneration
    }

    private func isCurrentScanActive(_ generation: UInt64) -> Bool {
        !Task.isCancelled && scanGeneration == generation
    }

    private func postProgress(_ progress: ScanProgress, generation: UInt64, sequence: UInt64) {
        guard isScanning, scanGeneration == generation, sequence > latestProgressSeq else { return }
        latestProgressSeq = sequence
        scanProgress = progress
    }

    public func testLiveLockdownConnectionAndScan() {
        guard let pairing = loadActivePairingFile() else {
            activeAlertMessage = WQStrings.pairingFileRequiredAlert
            showGlobalAlert = true
            return
        }
        guard !isScanning else { return }
        showInstalledScanConfigSheet = false
        let gen = beginScanSession(isIPAInspection: false)
        let host = lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "10.7.0.1" : lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines)
        scanProgress = ScanProgress(currentTarget: WQStrings.connectingViaLocalDevVPN(host: host), completedCount: 0, totalCount: 1)
        let targetSnapshotURL = savedSnapshotURL

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            do {
                let liveRecords = try await LockdownInstProxyClient.shared.fetchInstalledApps(
                    pairing: pairing,
                    preferredHost: host
                )
                guard self.isCurrentScanActive(gen) else { return }

                // Encode and cache live records off @MainActor so future offline scans remain instant
                let cacheResult = await Task.detached(priority: .utility) { () -> String? in
                    guard let encoded = try? JSONEncoder().encode(liveRecords),
                          encoded.count <= Self.maxSnapshotFileBytes,
                          (try? IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(encoded, to: targetSnapshotURL)) != nil else {
                        return nil
                    }
                    return Self.sha256Hex(of: encoded)
                }.value

                guard self.isCurrentScanActive(gen) else { return }
                if let sha = cacheResult {
                    self.registryStateGeneration &+= 1
                    let cacheName = WQStrings.localDevVPNCacheName
                    UserDefaults.standard.set(cacheName, forKey: Self.snapshotNameKey)
                    self.hasSavedSnapshot = true
                    self.savedSnapshotAppCount = liveRecords.count
                    self.savedSnapshotFilename = cacheName
                    UserDefaults.standard.set(liveRecords.count, forKey: Self.snapshotCountKey)
                    UserDefaults.standard.set(sha, forKey: Self.snapshotSHA256Key)
                }

                self.runUnifiedScanWithPreloadedRegistry(liveRecords, liveConnected: true, reusingGeneration: gen)
            } catch is CancellationError {
                if self.scanGeneration == gen {
                    self.isScanning = false
                    self.scanProgress = nil
                }
            } catch {
                guard self.scanGeneration == gen else { return }
                self.isScanning = false
                self.scanProgress = nil
                if Task.isCancelled { return }
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
        let gen = beginScanSession(isIPAInspection: false)
        scanProgress = ScanProgress(currentTarget: WQStrings.scanEngineInitializing, completedCount: 0, totalCount: 0)

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            _ = await self.autoImportFromDocumentsFolderIfNeededAsync()
            guard self.isCurrentScanActive(gen) else { return }
            await self.executeSystemScanPipeline(generation: gen)
        }
    }

    private func executeSystemScanPipeline(generation gen: UInt64) async {
        guard isCurrentScanActive(gen) else { return }
        let startTime = Date()
        let extraScanDirs = [syncedPackagesDirectory]
        let pairingURL = savedPairingURL
        let snapURL = savedSnapshotURL
        let host = lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "10.7.0.1" : lockdownHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let includeStore = includeAppStoreAppsInRegistry
        let probeEnabled = enableOnDeviceProbe
        let seqBox = ProgressSequenceBox()

        let (pairing, snapData) = await Task.detached(priority: .userInitiated) {
            (Self.loadActivePairingFile(at: pairingURL), Self.loadSavedSnapshotData(at: snapURL))
        }.value

        guard isCurrentScanActive(gen) else { return }

        do {
            let unified = try await SecurityPipeline.shared.scanUnifiedInstalledAppsAsync(
                pairingFile: pairing,
                preferredLockdownHost: host,
                savedSnapshotData: snapData,
                additionalLocations: extraScanDirs,
                includeAppStoreApps: includeStore,
                enableOnDeviceProbe: probeEnabled
            ) { [weak self] progress in
                let seq = seqBox.next()
                let weakTarget = self
                Task { @MainActor in
                    weakTarget?.postProgress(progress, generation: gen, sequence: seq)
                }
            }

            guard self.isCurrentScanActive(gen) else { return }
            let duration = Date().timeIntervalSince(startTime)

            guard !unified.findings.isEmpty else {
                self.isScanning = false
                self.scanProgress = nil
                try? await Task.sleep(nanoseconds: 150_000_000)
                guard !Task.isCancelled, self.scanGeneration == gen else { return }
                self.showInstalledScanConfigSheet = true
                return
            }

            let guardedFindings = unified.findings.map(enforceProtectedGroupCustomRuleGuard(on:))
            let session = ScanSession(
                findings: guardedFindings,
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
        } catch is CancellationError {
            if self.scanGeneration == gen {
                self.isScanning = false
                self.scanProgress = nil
            }
        } catch is SecurityPipelineError {
            guard self.isCurrentScanActive(gen) else { return }
            self.isScanning = false
            self.scanProgress = nil
            try? await Task.sleep(nanoseconds: 150_000_000)
            guard !Task.isCancelled, self.scanGeneration == gen else { return }
            self.showInstalledScanConfigSheet = true
        } catch {
            guard self.scanGeneration == gen else { return }
            self.isScanning = false
            self.scanProgress = nil
            if Task.isCancelled { return }
            self.activeAlertMessage = WQStrings.scanFailedMessage(error.localizedDescription)
            self.showGlobalAlert = true
            #if os(iOS)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            #endif
        }
    }

    private func runUnifiedScanWithPreloadedRegistry(
        _ liveRecords: [InstalledAppRegistryRecord],
        liveConnected: Bool,
        reusingGeneration: UInt64? = nil
    ) {
        let gen: UInt64
        if let existing = reusingGeneration {
            guard scanGeneration == existing, !Task.isCancelled else { return }
            gen = existing
            isScanning = true
        } else {
            guard !isScanning else { return }
            gen = beginScanSession(isIPAInspection: false)
        }

        let extraScanDirs = [syncedPackagesDirectory]
        let includeStore = includeAppStoreAppsInRegistry
        let probeEnabled = enableOnDeviceProbe
        let seqBox = ProgressSequenceBox()

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            let startTime = Date()

            do {
                let pkgFindings: [ScanFinding]
                do {
                    pkgFindings = try await SecurityPipeline.shared.scanInstalledAppsAsync(additionalLocations: extraScanDirs) { [weak self] progress in
                        let seq = seqBox.next()
                        let weakTarget = self
                        Task { @MainActor in
                            weakTarget?.postProgress(progress, generation: gen, sequence: seq)
                        }
                    }
                } catch is CancellationError {
                    if self.scanGeneration == gen {
                        self.isScanning = false
                        self.scanProgress = nil
                    }
                    return
                } catch {
                    if Task.isCancelled || self.scanGeneration != gen { return }
                    pkgFindings = []
                }

                guard self.isCurrentScanActive(gen) else { return }
                let probeFindings = probeEnabled ? await OnDeviceAppProbeScanner.shared.probeInstalledAppsAsync() : []
                guard self.isCurrentScanActive(gen) else { return }

                let merged = await Task.detached(priority: .userInitiated) {
                    SecurityPipeline.shared.correlateAndMergeFindings(
                        registryRecords: liveRecords,
                        packageFindings: pkgFindings,
                        probeFindings: probeFindings,
                        includeAppStoreApps: includeStore
                    )
                }.value

                guard self.isCurrentScanActive(gen) else { return }

                let duration = Date().timeIntervalSince(startTime)
                let guardedFindings = merged.findings.map(enforceProtectedGroupCustomRuleGuard(on:))
                let session = ScanSession(
                    findings: guardedFindings,
                    systemVersion: FirmwarePostureEngine.shared.evaluate().osVersion.displayString,
                    scanDuration: duration
                )

                let summaryResult = SecurityPipeline.UnifiedInstalledScanResult(
                    findings: guardedFindings,
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
        scanGeneration &+= 1
        latestProgressSeq = 0
        activeScanTask?.cancel()
        activeScanTask = nil
        isScanning = false
        isInspectingIPA = false
        scanProgress = nil
    }

    // MARK: - Multi-Select IPA Package Scan Actions
    public func scanIPAPackage(at url: URL) {
        scanMultipleIPAPackages(at: [url], correlateWithInstalled: false)
    }

    public func scanMultipleIPAPackages(at urls: [URL], correlateWithInstalled: Bool = false) {
        guard !urls.isEmpty, !isScanning else { return }

        let gen = beginScanSession(isIPAInspection: !correlateWithInstalled)
        if !correlateWithInstalled {
            ipaErrorMessage = nil
        }
        scanProgress = ScanProgress(currentTarget: WQStrings.scanEngineInitializing, completedCount: 0, totalCount: urls.count)

        let syncedDir = syncedPackagesDirectory
        let existingSyncedLowered = Set(syncedPackageNames.map { $0.lowercased() })
        let seqBox = ProgressSequenceBox()

        // Acquire security scope for incoming URLs and release deterministically in defer
        var preScopedPairs: [(URL, Bool)] = []
        preScopedPairs.reserveCapacity(urls.count)
        for u in urls {
            preScopedPairs.append((u, u.startAccessingSecurityScopedResource()))
        }
        let capturedScopedPairs = preScopedPairs

        activeScanTask = Task { [weak self] in
            defer {
                for (u, accessed) in capturedScopedPairs where accessed {
                    u.stopAccessingSecurityScopedResource()
                }
            }
            guard let self = self else { return }

            // Offload potentially large (up to 1 GB per IPA) file staging off @MainActor with bridged cancellation
            let stagingWorker = Task.detached(priority: .userInitiated) { () -> [URL] in
                var cachedTargets: [URL] = []
                var reservedBatchNames = existingSyncedLowered
                for (u, _) in capturedScopedPairs {
                    if Task.isCancelled { break }
                    let ext = u.pathExtension.lowercased()
                    if ext == "ipa" || ext == "tipa" {
                        if let cached = Self.stagePackageIntoSyncedFolderNonisolated(
                            u,
                            syncedDirectory: syncedDir,
                            reservedBatchNames: &reservedBatchNames
                        ) {
                            cachedTargets.append(cached)
                        } else {
                            cachedTargets.append(u)
                        }
                    }
                }
                return cachedTargets
            }
            let scanTargets = await withTaskCancellationHandler {
                await stagingWorker.value
            } onCancel: {
                stagingWorker.cancel()
            }

            guard self.isCurrentScanActive(gen) else { return }
            self.refreshSyncedPackageNames()

            guard !scanTargets.isEmpty else {
                self.handleIPAScanFailure(WQStrings.batchIPANoValidTargets, generation: gen)
                return
            }

            if correlateWithInstalled {
                self.showInstalledScanConfigSheet = false
                await self.executeSystemScanPipeline(generation: gen)
                return
            }

            let startTime = Date()

            do {
                let scanWorker = Task.detached(priority: .userInitiated) { [weak self] () -> [ScanFinding] in
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
                        let preSeq = seqBox.next()
                        Task { @MainActor [weak self] in
                            self?.postProgress(preProgress, generation: gen, sequence: preSeq)
                        }
                        do {
                            let finding = try SecurityPipeline.shared.scanIPA(at: target)
                            try Task.checkCancellation()
                            results.append(finding)
                            completed += 1
                            let progress = ScanProgress(
                                currentTarget: target.lastPathComponent,
                                completedCount: completed,
                                totalCount: total,
                                currentFinding: finding
                            )
                            let postSeq = seqBox.next()
                            Task { @MainActor [weak self] in
                                self?.postProgress(progress, generation: gen, sequence: postSeq)
                            }
                        } catch is CancellationError {
                            throw CancellationError()
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
                                let errSeq = seqBox.next()
                                Task { @MainActor [weak self] in
                                    self?.postProgress(progress, generation: gen, sequence: errSeq)
                                }
                            }
                        }
                    }

                    if results.isEmpty, let err = lastError {
                        throw err
                    }
                    return results
                }
                let findings: [ScanFinding] = try await withTaskCancellationHandler {
                    try await scanWorker.value
                } onCancel: {
                    scanWorker.cancel()
                }

                guard self.isCurrentScanActive(gen) else { return }
                guard !findings.isEmpty else {
                    self.handleIPAScanFailure(WQStrings.batchIPANoValidTargets, generation: gen)
                    return
                }

                let duration = Date().timeIntervalSince(startTime)
                let guardedFindings = findings.map(enforceProtectedGroupCustomRuleGuard(on:))
                let session = ScanSession(
                    findings: guardedFindings,
                    systemVersion: FirmwarePostureEngine.shared.evaluate().osVersion.displayString,
                    scanDuration: duration
                )

                self.currentSession = session
                self.installedAppsCount = session.totalApps
                self.inspectedIPAFinding = guardedFindings.sorted(by: { $0.riskTier > $1.riskTier }).first
                self.isInspectingIPA = false
                self.isScanning = false
                self.scanProgress = nil
                self.updateExportedReport()
                #if os(iOS)
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                #endif
            } catch is CancellationError {
                if self.scanGeneration == gen {
                    self.isInspectingIPA = false
                    self.isScanning = false
                    self.scanProgress = nil
                }
            } catch {
                guard self.scanGeneration == gen else { return }
                if Task.isCancelled {
                    self.isInspectingIPA = false
                    self.isScanning = false
                    self.scanProgress = nil
                    return
                }
                self.handleIPAScanFailure(error.localizedDescription, generation: gen)
            }
        }
    }

    private func handleIPAScanFailure(_ errorMessage: String, generation: UInt64? = nil) {
        if let gen = generation, scanGeneration != gen { return }
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
    private nonisolated static func containsDisallowedRuleScalar(_ s: String) -> Bool {
        for scalar in s.unicodeScalars {
            let v = scalar.value
            if v <= 0x1F || (v >= 0x7F && v <= 0x9F) || v == 0x00AD
                || (v >= 0x200B && v <= 0x200F)
                || (v >= 0x2028 && v <= 0x202F)
                || (v >= 0x2060 && v <= 0x206F)
                || (v >= 0xFE00 && v <= 0xFE0F)
                || v == 0xFEFF
                || (v >= 0xE0100 && v <= 0xE01EF) {
                return true
            }
            if scalar.properties.isWhitespace {
                return true
            }
            let cat = scalar.properties.generalCategory
            if cat == .control || cat == .format || cat == .enclosingMark || cat == .privateUse || cat == .surrogate {
                return true
            }
        }
        return false
    }

    private nonisolated static func isValidConcreteIdentifierASCII(_ s: String) -> Bool {
        guard !s.isEmpty else { return false }
        return s.utf8.allSatisfy { b in
            (b >= 0x41 && b <= 0x5A)
                || (b >= 0x61 && b <= 0x7A)
                || (b >= 0x30 && b <= 0x39)
                || b == 0x2E || b == 0x2D || b == 0x5F
        }
    }

    private enum CustomBundleIdValidation {
        case valid(String)
        case invalidFormat
        case reservedApple
    }

    private nonisolated static func validateCustomBundleIdPattern(_ rawBid: String) -> CustomBundleIdValidation {
        let cleanBid = rawBid.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanBid.isEmpty,
              !containsDisallowedRuleScalar(cleanBid),
              !cleanBid.contains("?") else {
            return .invalidFormat
        }

        if cleanBid.contains("*") {
            // Allow `*` ONLY as a trailing `.*` after >= 2 concrete non-wildcard ASCII labels
            guard cleanBid.hasSuffix(".*") else { return .invalidFormat }
            let concretePrefix = String(cleanBid.dropLast(2))
            guard !concretePrefix.isEmpty,
                  !concretePrefix.contains("*"),
                  isValidConcreteIdentifierASCII(concretePrefix) else {
                return .invalidFormat
            }
            let labels = concretePrefix.split(separator: ".", omittingEmptySubsequences: false)
            guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty }) else {
                return .invalidFormat
            }
            let foldedPrefix = ExpandedThreatCatalog.foldConfusablesToASCII(concretePrefix).lowercased()
            if foldedPrefix == "com.apple"
                || foldedPrefix.hasPrefix("com.apple.")
                || "com.apple".hasPrefix(foldedPrefix + ".")
                || "com.apple".hasPrefix(foldedPrefix) {
                return .reservedApple
            }
            return .valid(cleanBid)
        }

        guard isValidConcreteIdentifierASCII(cleanBid) else { return .invalidFormat }
        let labels = cleanBid.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty, labels.allSatisfy({ !$0.isEmpty }) else {
            return .invalidFormat
        }
        let foldedBid = ExpandedThreatCatalog.foldConfusablesToASCII(cleanBid).lowercased()
        if foldedBid == "com.apple" || foldedBid.hasPrefix("com.apple.") {
            return .reservedApple
        }
        return .valid(cleanBid)
    }

    private static func validateCustomWhitelistInputs(
        bundleId: String,
        additionalBundleIds: [String] = [],
        name: String,
        allowedAppGroups: [String],
        allowedTeamIds: [String],
        checkExistingNameCollision: Bool
    ) -> Result<(cleanBundleIds: [String], cleanName: String, cleanGroups: [String], cleanTeams: [String]), Error> {
        var cleanBundleIds: [String] = []
        var seenLowerBids: Set<String> = []
        let allCandidateBids = [bundleId] + additionalBundleIds.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

        for candidateBid in allCandidateBids {
            switch validateCustomBundleIdPattern(candidateBid) {
            case .valid(let cleanBid):
                let lower = cleanBid.lowercased()
                if seenLowerBids.insert(lower).inserted {
                    cleanBundleIds.append(cleanBid)
                }
            case .invalidFormat:
                return .failure(NSError(domain: "WQWhitelist", code: 1, userInfo: [
                    NSLocalizedDescriptionKey: WQStrings.whitelistInvalidBundleId
                ]))
            case .reservedApple:
                return .failure(NSError(domain: "WQWhitelist", code: 2, userInfo: [
                    NSLocalizedDescriptionKey: WQStrings.whitelistReservedAppleBundleId
                ]))
            }
        }
        guard let primaryCleanBid = cleanBundleIds.first else {
            return .failure(NSError(domain: "WQWhitelist", code: 1, userInfo: [
                NSLocalizedDescriptionKey: WQStrings.whitelistInvalidBundleId
            ]))
        }

        let rawName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanName = rawName.isEmpty ? primaryCleanBid : rawName
        let nameHasControl = cleanName.unicodeScalars.contains { scalar in
            let v = scalar.value
            return v <= 0x1F || (v >= 0x7F && v <= 0x9F) || scalar.properties.generalCategory == .control || scalar.properties.generalCategory == .format
        }
        guard !cleanName.isEmpty, !nameHasControl else {
            return .failure(NSError(domain: "WQWhitelist", code: 3, userInfo: [
                NSLocalizedDescriptionKey: WQStrings.whitelistInvalidRuleName
            ]))
        }

        if checkExistingNameCollision, WhitelistEngine.shared.tool(named: cleanName) != nil {
            return .failure(NSError(domain: "WQWhitelist", code: 4, userInfo: [
                NSLocalizedDescriptionKey: WQStrings.whitelistDuplicateRuleName(cleanName)
            ]))
        }

        var cleanGroups: [String] = []
        for rawGroup in allowedAppGroups {
            let g = rawGroup.trimmingCharacters(in: .whitespacesAndNewlines)
            if g.isEmpty { continue }
            // Disallow all wildcards (* and ?) in custom allowedAppGroups; require exact concrete ASCII identifiers
            let groupLabels = g.split(separator: ".", omittingEmptySubsequences: false)
            guard !containsDisallowedRuleScalar(g),
                  !g.contains("*"),
                  !g.contains("?"),
                  isValidConcreteIdentifierASCII(g),
                  groupLabels.count >= 2,
                  groupLabels.allSatisfy({ !$0.isEmpty }) else {
                return .failure(NSError(domain: "WQWhitelist", code: 5, userInfo: [
                    NSLocalizedDescriptionKey: WQStrings.whitelistInvalidAppGroup(g)
                ]))
            }
            let foldedGroup = ExpandedThreatCatalog.foldConfusablesToASCII(g).lowercased()
            if ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup(g)
                || foldedGroup == "group.com.apple"
                || foldedGroup.hasPrefix("group.com.apple.")
                || foldedGroup == "systemgroup.com.apple"
                || foldedGroup.hasPrefix("systemgroup.com.apple.")
                || foldedGroup.hasPrefix("group.is.workflow")
                || foldedGroup.hasPrefix("group.tvappservices") {
                return .failure(NSError(domain: "WQWhitelist", code: 6, userInfo: [
                    NSLocalizedDescriptionKey: WQStrings.whitelistProtectedAppGroup(g)
                ]))
            }
            cleanGroups.append(g)
        }

        var cleanTeams: [String] = []
        for rawTeam in allowedTeamIds {
            let t = rawTeam.trimmingCharacters(in: .whitespacesAndNewlines)
            if t.isEmpty { continue }
            let validTeam = t.count <= 16 && t.utf8.allSatisfy { b in
                (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39)
            }
            guard validTeam else {
                return .failure(NSError(domain: "WQWhitelist", code: 7, userInfo: [
                    NSLocalizedDescriptionKey: WQStrings.whitelistInvalidTeamId(t)
                ]))
            }
            cleanTeams.append(t)
        }

        return .success((cleanBundleIds, cleanName, cleanGroups, cleanTeams))
    }

    private static func restorePersistedWhitelistState() {
        WhitelistEngine.shared.resetToDefaults()

        if UserDefaults.standard.object(forKey: builtinWhitelistEnabledKey) != nil {
            let builtInEnabled = UserDefaults.standard.bool(forKey: builtinWhitelistEnabledKey)
            WhitelistEngine.shared.toggleTool(named: "WQGuard", isEnabled: builtInEnabled)
        }

        guard let data = UserDefaults.standard.data(forKey: customWhitelistRulesKey),
              let decoded = try? JSONDecoder().decode([WhitelistedTool].self, from: data) else {
            return
        }

        for tool in decoded {
            guard let primaryBid = tool.allowedBundleIds.first else { continue }
            let additionalBids = Array(tool.allowedBundleIds.dropFirst())
            if case .success(let validated) = validateCustomWhitelistInputs(
                bundleId: primaryBid,
                additionalBundleIds: additionalBids,
                name: tool.name,
                allowedAppGroups: tool.allowedAppGroups,
                allowedTeamIds: tool.allowedTeamIds ?? [],
                checkExistingNameCollision: true
            ) {
                let safeTool = WhitelistedTool(
                    name: validated.cleanName,
                    allowedBundleIds: validated.cleanBundleIds,
                    allowedAppGroups: validated.cleanGroups,
                    allowedTeamIds: validated.cleanTeams.isEmpty ? nil : validated.cleanTeams,
                    expectedSignatures: tool.expectedSignatures,
                    description: tool.description.isEmpty ? WQStrings.customRuleDefaultDescription : tool.description,
                    isEnabled: tool.isEnabled,
                    isBuiltIn: false
                )
                WhitelistEngine.shared.registerCustomTool(safeTool)
            }
        }
    }

    private static func persistWhitelistState() {
        let all = WhitelistEngine.shared.allTools
        if let builtIn = all.first(where: { $0.isBuiltIn && $0.name == "WQGuard" }) {
            UserDefaults.standard.set(builtIn.isEnabled, forKey: builtinWhitelistEnabledKey)
        }
        let custom = all.filter { !$0.isBuiltIn }
        if let encoded = try? JSONEncoder().encode(custom) {
            UserDefaults.standard.set(encoded, forKey: customWhitelistRulesKey)
        }
    }

    public func toggleWhitelist(for tool: WhitelistedTool, isEnabled: Bool) {
        WhitelistEngine.shared.toggleTool(named: tool.name, isEnabled: isEnabled)
        Self.persistWhitelistState()
        self.whitelistedTools = WhitelistEngine.shared.allTools
        recalculateSessionTiers()
    }

    @discardableResult
    public func addCustomWhitelistRule(
        bundleId: String,
        additionalBundleIds: [String] = [],
        name: String,
        appGroup: String = "",
        allowedAppGroups: [String]? = nil,
        allowedTeamIds: [String]? = nil,
        expectedSignatures: [String] = [],
        requiringPromotionForFinding targetFinding: ScanFinding? = nil
    ) -> CustomRuleValidationResult {
        if let target = targetFinding,
           let protectedGroup = target.evidence.appGroups.first(where: { ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup($0) }) {
            return CustomRuleValidationResult(
                success: false,
                errorMessage: WQStrings.whitelistProtectedAppGroup(protectedGroup)
            )
        }

        let candidateGroups = allowedAppGroups ?? {
            let trimmed = appGroup.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? [] : [trimmed]
        }()

        switch Self.validateCustomWhitelistInputs(
            bundleId: bundleId,
            additionalBundleIds: additionalBundleIds,
            name: name,
            allowedAppGroups: candidateGroups,
            allowedTeamIds: allowedTeamIds ?? [],
            checkExistingNameCollision: true
        ) {
        case .failure(let err):
            return CustomRuleValidationResult(success: false, errorMessage: err.localizedDescription)

        case .success(let validated):
            let cleanSigs = expectedSignatures
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty && !Self.containsDisallowedRuleScalar($0) }

            let newTool = WhitelistedTool(
                name: validated.cleanName,
                allowedBundleIds: validated.cleanBundleIds,
                allowedAppGroups: validated.cleanGroups,
                allowedTeamIds: validated.cleanTeams.isEmpty ? nil : validated.cleanTeams,
                expectedSignatures: cleanSigs,
                description: WQStrings.customRuleDefaultDescription,
                isEnabled: true,
                isBuiltIn: false
            )
            WhitelistEngine.shared.registerCustomTool(newTool)

            if let target = targetFinding {
                recalculateSessionTiers()
                let promotedInSession = currentSession?.findings.first(where: { $0.id == target.id })?.isWhitelisted
                let promotedInInspected = (inspectedIPAFinding?.id == target.id) ? inspectedIPAFinding?.isWhitelisted : nil
                let fallbackAllowed = target.riskTier == .caution
                    && !target.indicators.contains(where: { $0.severity == .highRisk })
                    && evaluateSessionWhitelist(for: target).isWhitelisted
                let isPromoted = promotedInSession ?? promotedInInspected ?? fallbackAllowed
                guard isPromoted else {
                    WhitelistEngine.shared.removeTool(named: newTool.name)
                    recalculateSessionTiers()
                    self.whitelistedTools = WhitelistEngine.shared.allTools
                    return CustomRuleValidationResult(success: false, errorMessage: WQStrings.whitelistRejectedFallback)
                }
                Self.persistWhitelistState()
                self.whitelistedTools = WhitelistEngine.shared.allTools
                return CustomRuleValidationResult(success: true, errorMessage: nil)
            }

            Self.persistWhitelistState()
            self.whitelistedTools = WhitelistEngine.shared.allTools
            recalculateSessionTiers()
            return CustomRuleValidationResult(success: true, errorMessage: nil)
        }
    }

    public func removeCustomWhitelistRule(named name: String) {
        if let existing = WhitelistEngine.shared.tool(named: name), existing.isBuiltIn {
            return
        }
        WhitelistEngine.shared.removeTool(named: name)
        Self.persistWhitelistState()
        self.whitelistedTools = WhitelistEngine.shared.allTools
        recalculateSessionTiers()
    }

    public func resetWhitelistToDefaults() {
        WhitelistEngine.shared.resetToDefaults()
        UserDefaults.standard.removeObject(forKey: Self.customWhitelistRulesKey)
        UserDefaults.standard.set(true, forKey: Self.builtinWhitelistEnabledKey)
        self.whitelistedTools = WhitelistEngine.shared.allTools
        recalculateSessionTiers()
    }

    private func evaluateSessionWhitelist(for finding: ScanFinding) -> (isWhitelisted: Bool, toolName: String?) {
        let candidate = WhitelistEngine.shared.evaluateFindingWhitelist(finding)
        guard candidate.isWhitelisted else {
            return (false, nil)
        }
        let hasProtectedVictimOrAppleGroup = finding.evidence.appGroups.contains {
            ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup($0)
        }
        guard hasProtectedVictimOrAppleGroup else {
            return candidate
        }
        if let matchedName = candidate.toolName,
           let matchedTool = WhitelistEngine.shared.tool(named: matchedName),
           matchedTool.isBuiltIn {
            return candidate
        }
        let builtInTools = WhitelistEngine.shared.allTools.filter { $0.isBuiltIn }
        let builtInOnlyEngine = WhitelistEngine(tools: builtInTools)
        return builtInOnlyEngine.evaluateFindingWhitelist(finding)
    }

    private func enforceProtectedGroupCustomRuleGuard(on finding: ScanFinding) -> ScanFinding {
        guard finding.isWhitelisted || finding.riskTier == .knownTool else {
            return finding
        }
        let hasHighRiskIndicator = finding.indicators.contains(where: { $0.severity == .highRisk })
        let hasEscapingSymlink = !finding.evidence.escapingSymlinks.isEmpty
        let hasNonWhitelistableStructural = finding.indicators.contains(where: {
            WhitelistEngine.isNonWhitelistableStructuralSignature($0.signature)
        }) || finding.evidence.matchedSymbols.contains(where: WhitelistEngine.isNonWhitelistableStructuralSignature)
        let hasProtectedGroup = finding.evidence.appGroups.contains(where: { ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup($0) })
        let mustCheckBuiltInOnly = hasProtectedGroup || !finding.evidence.isWhitelistEligible
        let mustRevert: Bool
        if hasHighRiskIndicator || hasEscapingSymlink || hasNonWhitelistableStructural {
            mustRevert = true
        } else if mustCheckBuiltInOnly {
            let builtInTools = WhitelistEngine.shared.allTools.filter { $0.isBuiltIn }
            let builtInOnlyEngine = WhitelistEngine(tools: builtInTools)
            mustRevert = !builtInOnlyEngine.evaluateFindingWhitelist(finding).isWhitelisted
        } else {
            mustRevert = false
        }
        guard mustRevert else {
            return finding
        }
        let restoredTier: RiskTier = hasHighRiskIndicator ? .highRisk : .caution
        let restoredGuidance = (restoredTier == .highRisk) ? WQStrings.remediationHighRisk : WQStrings.remediationCaution
        let restoredEvidence = AuditEvidence(
            matchedSymbols: finding.evidence.matchedSymbols,
            linkedDylibs: finding.evidence.linkedDylibs,
            hasAppGroups: finding.evidence.hasAppGroups,
            appGroups: finding.evidence.appGroups,
            installChannel: finding.evidence.installChannel,
            cryptid: finding.evidence.cryptid,
            isFairPlayEncrypted: finding.evidence.isFairPlayEncrypted,
            escapingSymlinks: finding.evidence.escapingSymlinks,
            dynamicLoadingPresent: finding.evidence.dynamicLoadingPresent,
            pathEnumerationPresent: finding.evidence.pathEnumerationPresent,
            remediationGuidance: restoredGuidance,
            auditDepth: finding.evidence.auditDepth,
            signerIdentity: finding.evidence.signerIdentity,
            correlatedPackageBundleId: finding.evidence.correlatedPackageBundleId,
            isWhitelistEligible: finding.evidence.isWhitelistEligible,
            isTeamIdWhitelistVerified: finding.evidence.isTeamIdWhitelistVerified
        )
        return ScanFinding(
            bundleId: finding.bundleId,
            displayName: finding.displayName,
            version: finding.version,
            teamId: finding.teamId,
            executablePath: finding.executablePath,
            bundlePath: finding.bundlePath,
            installChannel: finding.installChannel,
            riskTier: restoredTier,
            isWhitelisted: false,
            whitelistedToolName: nil,
            indicators: finding.indicators,
            evidence: restoredEvidence,
            scanTimestamp: finding.scanTimestamp
        )
    }

    private func recalculateSessionTiers() {
        guard let session = currentSession else { return }
        var updatedFindings: [ScanFinding] = []
        updatedFindings.reserveCapacity(session.findings.count)

        for finding in session.findings {
            let provisionalRisk: RiskTier
            if finding.indicators.contains(where: { $0.severity == .highRisk }) {
                provisionalRisk = .highRisk
            } else if finding.indicators.contains(where: { $0.severity == .caution }) {
                provisionalRisk = .caution
            } else {
                provisionalRisk = .safe
            }

            // Align with M2: .highRisk findings are never downgraded by whitelist across any auditDepth,
            // and custom (!isBuiltIn) rules can never whitelist findings carrying protected victim/Apple App Groups.
            let wlResult: (isWhitelisted: Bool, toolName: String?)
            if provisionalRisk == .caution {
                wlResult = evaluateSessionWhitelist(for: finding)
            } else {
                wlResult = (false, nil)
            }

            let newTier: RiskTier = wlResult.isWhitelisted ? .knownTool : provisionalRisk
            let newGuidance: String
            if newTier == .knownTool {
                newGuidance = WQStrings.remediationMatchedWhitelist(wlResult.toolName ?? "Known Tool")
            } else if newTier != finding.riskTier || finding.isWhitelisted {
                switch newTier {
                case .highRisk:
                    newGuidance = WQStrings.remediationHighRisk
                case .caution:
                    newGuidance = WQStrings.remediationCaution
                case .safe:
                    newGuidance = WQStrings.remediationSafe
                case .knownTool:
                    newGuidance = finding.evidence.remediationGuidance
                }
            } else {
                newGuidance = finding.evidence.remediationGuidance
            }

            let updatedEvidence = AuditEvidence(
                matchedSymbols: finding.evidence.matchedSymbols,
                linkedDylibs: finding.evidence.linkedDylibs,
                hasAppGroups: finding.evidence.hasAppGroups,
                appGroups: finding.evidence.appGroups,
                installChannel: finding.evidence.installChannel,
                cryptid: finding.evidence.cryptid,
                isFairPlayEncrypted: finding.evidence.isFairPlayEncrypted,
                escapingSymlinks: finding.evidence.escapingSymlinks,
                dynamicLoadingPresent: finding.evidence.dynamicLoadingPresent,
                pathEnumerationPresent: finding.evidence.pathEnumerationPresent,
                remediationGuidance: newGuidance,
                auditDepth: finding.evidence.auditDepth,
                signerIdentity: finding.evidence.signerIdentity,
                correlatedPackageBundleId: finding.evidence.correlatedPackageBundleId,
                isWhitelistEligible: finding.evidence.isWhitelistEligible,
                isTeamIdWhitelistVerified: finding.evidence.isTeamIdWhitelistVerified
            )

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
                evidence: updatedEvidence,
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
        if let currentSelected = self.selectedFinding,
           let refreshedSelected = updatedFindings.first(where: { $0.id == currentSelected.id }) {
            self.selectedFinding = refreshedSelected
        }
        if let currentIPA = self.inspectedIPAFinding,
           let refreshedIPA = updatedFindings.first(where: { $0.id == currentIPA.id }) {
            self.inspectedIPAFinding = refreshedIPA
        }
        updateExportedReport()
    }

    // MARK: - Report Export Serialization
    private static func sanitizeExportSessionId(_ rawId: String) -> String {
        let allowed = rawId.unicodeScalars.map { scalar -> Character in
            let v = scalar.value
            if (v >= 0x41 && v <= 0x5A) || (v >= 0x61 && v <= 0x7A) || (v >= 0x30 && v <= 0x39)
                || v == 0x2D || v == 0x5F {
                return Character(scalar)
            }
            return "_"
        }
        let cleaned = String(allowed.prefix(64))
        return cleaned.isEmpty ? "session" : cleaned
    }

    public func updateExportedReport() {
        guard let session = currentSession else {
            exportedReportText = WQStrings.reportNoDataPlaceholder
            exportedReportURL = nil
            return
        }

        let tempDir = Self.ensureSafeNonSymlinkDirectory(
            at: FileManager.default.temporaryDirectory.appendingPathComponent("WQGuardAuditReports", isDirectory: true)
        )
        let safeSessionId = Self.sanitizeExportSessionId(session.sessionId)

        do {
            switch exportFormat {
            case .markdown:
                let md = ReportGenerator.shared.generateMarkdownReport(session: session)
                self.exportedReportText = md
                let url = tempDir.appendingPathComponent("WQGuard-Audit-Report-\(safeSessionId).md")
                try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(Data(md.utf8), to: url)
                self.exportedReportURL = url

            case .json:
                let data = try ReportGenerator.shared.generateJSONReport(session: session)
                guard let jsonStr = String(data: data, encoding: .utf8) else {
                    self.exportedReportText = WQStrings.reportNoDataPlaceholder
                    self.exportedReportURL = nil
                    return
                }
                self.exportedReportText = jsonStr
                let url = tempDir.appendingPathComponent("WQGuard-Audit-Report-\(safeSessionId).json")
                try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(data, to: url)
                self.exportedReportURL = url

            case .plainText:
                let text = ReportGenerator.shared.generatePlainTextReport(session: session)
                self.exportedReportText = text
                let url = tempDir.appendingPathComponent("WQGuard-Audit-Report-\(safeSessionId).txt")
                try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(Data(text.utf8), to: url)
                self.exportedReportURL = url
            }
        } catch {
            self.exportedReportURL = nil
            if exportFormat == .json {
                self.exportedReportText = error.localizedDescription
            }
            self.activeAlertMessage = error.localizedDescription
            self.showGlobalAlert = true
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
