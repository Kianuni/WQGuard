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
    }

    // MARK: - Computed Properties
    public var overallPosture: RiskTier {
        if let session = currentSession {
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

    // MARK: - System Scan Actions
    public func startSystemScan() {
        guard !isScanning else { return }
        isScanning = true
        scanProgress = ScanProgress(currentTarget: WQStrings.scanEngineInitializing, completedCount: 0, totalCount: 0)

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }
            let startTime = Date()

            do {
                let findings = try await SecurityPipeline.shared.scanInstalledAppsAsync { [weak self] progress in
                    guard let strongSelf = self else { return }
                    Task { @MainActor in
                        strongSelf.scanProgress = progress
                    }
                }

                let duration = Date().timeIntervalSince(startTime)
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

    // MARK: - IPA Package Scan Actions
    public func scanIPAPackage(at url: URL) {
        isInspectingIPA = true
        ipaErrorMessage = nil

        Task.detached(priority: .userInitiated) { [weak self] in
            let isSecurityScoped = url.startAccessingSecurityScopedResource()
            defer {
                if isSecurityScoped {
                    url.stopAccessingSecurityScopedResource()
                }
            }

            do {
                let finding = try SecurityPipeline.shared.scanIPA(at: url)
                await self?.handleIPAScanSuccess(finding)
            } catch {
                await self?.handleIPAScanFailure(error.localizedDescription)
            }
        }
    }

    private func handleIPAScanSuccess(_ finding: ScanFinding) {
        self.inspectedIPAFinding = finding
        self.isInspectingIPA = false
        #if os(iOS)
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        #endif
    }

    private func handleIPAScanFailure(_ errorMessage: String) {
        self.ipaErrorMessage = errorMessage
        self.isInspectingIPA = false
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
