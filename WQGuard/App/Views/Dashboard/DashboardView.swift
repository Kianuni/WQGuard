//
//  DashboardView.swift
//  WQGuard
//
//  Main security dashboard providing posture hero card, one-tap scan, and metrics grid.
//

import SwiftUI
import UniformTypeIdentifiers
import WQGuardCore

public struct DashboardView: View {
    @EnvironmentObject var vm: ScanViewModel
    @State private var showExportSheet = false
    @State private var showBatchIPAPicker = false

    public init() {}

    public var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // 1. Dynamic Posture Hero Card
                PostureHeroCard(
                    posture: vm.overallPosture,
                    isScanning: vm.isScanning,
                    progress: vm.scanProgress,
                    hasScannedApps: vm.hasScannedApps,
                    exposedCVECount: vm.firmwareReport.exposedCount,
                    isFullScanEnabled: vm.isFullSystemScanEnabled
                )

                // 2. Primary Default Action (Upload IPA) + Opt-In Full System Scan Switch
                VStack(spacing: 12) {
                    if vm.isScanning {
                        ScanProgressBar(progress: vm.scanProgress)

                        Button(role: .destructive, action: { vm.cancelScan() }) {
                            Label(WQStrings.cancelScan, systemImage: "xmark.circle.fill")
                                .font(.headline)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 14)
                                .background(Color.red.opacity(0.15))
                                .foregroundColor(.red)
                                .clipShape(RoundedRectangle(cornerRadius: 14))
                        }
                    } else {
                        // Default Primary Mode: Upload / Import IPA Package(s)
                        Button(action: {
                            #if os(iOS)
                            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                            #endif
                            showBatchIPAPicker = true
                        }) {
                            VStack(spacing: 4) {
                                HStack(spacing: 8) {
                                    Image(systemName: "arrow.up.doc.on.clipboard")
                                        .font(.title3.bold())
                                    Text(WQStrings.defaultUploadIPAScan)
                                        .font(.headline.bold())
                                }
                                Text(WQStrings.defaultUploadIPAScanSub)
                                    .font(.caption2)
                                    .opacity(0.85)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 15)
                            .background(
                                LinearGradient(
                                    colors: [Color(red: 0.0, green: 0.78, blue: 0.65), Color(red: 0.0, green: 0.58, blue: 0.48)],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .foregroundColor(.black)
                            .clipShape(RoundedRectangle(cornerRadius: 16))
                            .shadow(color: Color(red: 0.0, green: 0.78, blue: 0.65).opacity(0.35), radius: 8, y: 4)
                        }

                        // Opt-In Switch Card for Full Installed-App Scan
                        VStack(spacing: 12) {
                            Toggle(isOn: Binding(
                                get: { vm.isFullSystemScanEnabled },
                                set: { vm.requestToggleFullSystemScan($0) }
                            )) {
                                VStack(alignment: .leading, spacing: 3) {
                                    HStack(spacing: 6) {
                                        Image(systemName: vm.isFullSystemScanEnabled ? "exclamationmark.shield.fill" : "lock.shield")
                                            .foregroundColor(vm.isFullSystemScanEnabled ? .orange : .gray)
                                        Text(WQStrings.fullScanToggleTitle)
                                            .font(.subheadline.bold())
                                            .foregroundColor(.white)
                                        Text(WQStrings.fullScanBadgeRisk)
                                            .font(.system(size: 10, weight: .bold))
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(Color.orange.opacity(0.2))
                                            .foregroundColor(.orange)
                                            .clipShape(Capsule())
                                    }
                                    Text(vm.isFullSystemScanEnabled ? WQStrings.fullScanToggleSubOn : WQStrings.fullScanToggleSubOff)
                                        .font(.caption2)
                                        .foregroundColor(.gray)
                                }
                            }
                            .tint(.orange)

                            if vm.isFullSystemScanEnabled {
                                Button(action: {
                                    #if os(iOS)
                                    UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                                    #endif
                                    vm.startSystemScan()
                                }) {
                                    HStack {
                                        Image(systemName: "play.shield.fill")
                                            .font(.headline)
                                        Text(WQStrings.startSystemScan)
                                            .font(.subheadline.bold())
                                    }
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 13)
                                    .background(Color.orange.opacity(0.18))
                                    .foregroundColor(.orange)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 12)
                                            .stroke(Color.orange.opacity(0.55), lineWidth: 1)
                                    )
                                    .clipShape(RoundedRectangle(cornerRadius: 12))
                                }
                            }
                        }
                        .padding(14)
                        .background(
                            RoundedRectangle(cornerRadius: 16)
                                .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                                .overlay(
                                    RoundedRectangle(cornerRadius: 16)
                                        .stroke(vm.isFullSystemScanEnabled ? Color.orange.opacity(0.45) : Color.white.opacity(0.1), lineWidth: 1)
                                )
                        )
                    }
                }
                .padding(.horizontal)

                // 3. Summary Metrics Grid
                VStack(alignment: .leading, spacing: 10) {
                    Text(WQStrings.metricsSummary)
                        .font(.title3.bold())
                        .foregroundColor(.primary)
                        .padding(.horizontal)

                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                        MetricGridCard(
                            title: WQStrings.scannedApps,
                            count: vm.totalScannedCount,
                            icon: "apps.iphone",
                            color: .blue
                        )
                        MetricGridCard(
                            title: WQStrings.highRiskAlerts,
                            count: vm.highRiskCount,
                            icon: "exclamationmark.shield.fill",
                            color: .red
                        )
                        MetricGridCard(
                            title: WQStrings.knownTools,
                            count: vm.knownToolCount,
                            icon: "wrench.and.screwdriver.fill",
                            color: .yellow
                        )
                        MetricGridCard(
                            title: WQStrings.cautionAlerts,
                            count: vm.cautionCount,
                            icon: "exclamationmark.triangle.fill",
                            color: .orange
                        )
                    }
                    .padding(.horizontal)
                }

                // 4. Quick Entry Actions
                VStack(spacing: 12) {
                    NavigationLink(destination: FindingsView()) {
                        QuickActionRow(
                            title: WQStrings.viewDetailedFindings,
                            subtitle: WQStrings.viewDetailedFindingsSub,
                            icon: "list.bullet.clipboard.fill",
                            color: .teal
                        )
                    }

                    NavigationLink(destination: FirmwareRadarView()) {
                        QuickActionRow(
                            title: WQStrings.firmwareRadarTitle,
                            subtitle: "\(vm.firmwareReport.exposedCount) \(WQStrings.firmwareRadarSub)",
                            icon: "antenna.radiowaves.left.and.right",
                            color: .purple
                        )
                    }

                    Button(action: {
                        vm.updateExportedReport()
                        showExportSheet = true
                    }) {
                        QuickActionRow(
                            title: WQStrings.exportAuditReport,
                            subtitle: WQStrings.exportAuditReportSub,
                            icon: "square.and.arrow.up.fill",
                            color: .indigo
                        )
                    }
                }
                .padding(.horizontal)
                .padding(.bottom, 24)
            }
            .padding(.top, 12)
        }
        .navigationTitle(WQStrings.appTitle)
        .sheet(isPresented: $showExportSheet) {
            ReportExportView()
        }
        .fileImporter(
            isPresented: $showBatchIPAPicker,
            allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .archive, .archive, .folder],
            allowsMultipleSelection: true
        ) { result in
            switch result {
            case .success(let urls):
                vm.scanMultipleIPAPackages(at: urls)
            case .failure(let err):
                vm.activeAlertMessage = err.localizedDescription
                vm.showGlobalAlert = true
            }
        }
    }
}
