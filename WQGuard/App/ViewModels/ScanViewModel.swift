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
    @Published public var showSideloadPickerFromDashboard: Bool = false
    @Published public var bookmarkedFolderNames: [String] = []

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
        self.prepareSurgeExportURL()
        self.refreshBookmarkedFolderNames()
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
        self.bookmarkedFolderNames = Array(Set(urls.map { $0.lastPathComponent })).sorted()
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

    // MARK: - Self-Signed Application Scan Actions
    public func startSystemScan() {
        guard !isScanning else { return }
        isScanning = true
        scanProgress = ScanProgress(currentTarget: WQStrings.scanEngineInitializing, completedCount: 0, totalCount: 0)
        let savedDirs = resolveBookmarkedDirectories()

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
                let findings = try await SecurityPipeline.shared.scanInstalledAppsAsync(additionalLocations: savedDirs) { [weak self] progress in
                    guard let strongSelf = self else { return }
                    Task { @MainActor in
                        strongSelf.scanProgress = progress
                    }
                }

                let duration = Date().timeIntervalSince(startTime)
                guard !findings.isEmpty else {
                    self.isScanning = false
                    self.scanProgress = nil
                    self.showSideloadPickerFromDashboard = true
                    return
                }
                let session = ScanSession(
                    findings: findings,
                    systemVersion: FirmwarePostureEngine.shared.evaluate().osVersion.displayString,
                    scanDuration: duration
                )

                self.currentSession = session
                self.installedAppsCount = session.totalApps
                self.isScanning = false
                self.scanProgress = nil
                self.updateExportedReport()
                #if os(iOS)
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                #endif
            } catch is SecurityPipelineError {
                // On standard sandboxed sideload with no bound signing folder yet, directly open picker
                self.isScanning = false
                self.scanProgress = nil
                self.showSideloadPickerFromDashboard = true
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
        isInspectingIPA = true
        isScanning = true
        ipaErrorMessage = nil
        scanProgress = ScanProgress(currentTarget: WQStrings.scanEngineInitializing, completedCount: 0, totalCount: urls.count)

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            let startTime = Date()

            do {
                let findings: [ScanFinding] = try await Task.detached(priority: .userInitiated) { [weak self] in
                    let scopedPairs = urls.map { ($0, $0.startAccessingSecurityScopedResource()) }
                    defer {
                        for (u, accessed) in scopedPairs where accessed {
                            u.stopAccessingSecurityScopedResource()
                        }
                    }

                    // Expand directories into .ipa / .app targets
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
                            if let bData = try? itemURL.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil) {
                                Task { @MainActor [weak self] in
                                    self?.saveDirectoryBookmarkData(bData)
                                }
                            }
                            if let enumerator = fm.enumerator(at: itemURL, includingPropertiesForKeys: [.isDirectoryKey]) {
                                while let subURL = enumerator.nextObject() as? URL {
                                    let subExt = subURL.pathExtension.lowercased()
                                    if subExt == "ipa" || subExt == "tipa" {
                                        addTarget(subURL)
                                    } else if subExt == "app" {
                                        addTarget(subURL)
                                        enumerator.skipDescendants()
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
                        do {
                            let finding: ScanFinding
                            if target.pathExtension.lowercased() == "app" {
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
                if case IPAPackageScannerError.missingPayload = error, urls.count > 1 || urls.first?.hasDirectoryPath == true {
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
