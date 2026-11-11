//
//  DashboardView.swift
//  WQGuard
//
//  Main security dashboard providing posture hero card, one-tap scan, and metrics grid.
//

import SwiftUI
import WQGuardCore

public struct DashboardView: View {
    @EnvironmentObject var vm: ScanViewModel
    @State private var showExportSheet = false

    public init() {}

    public var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // 1. Dynamic Posture Hero Card
                PostureHeroCard(
                    posture: vm.overallPosture,
                    isScanning: vm.isScanning,
                    progress: vm.scanProgress
                )

                // 2. One-Tap System Scan Action Card
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
                        Button(action: {
                            #if os(iOS)
                            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                            #endif
                            vm.startSystemScan()
                        }) {
                            HStack {
                                Image(systemName: "play.shield.fill")
                                    .font(.title2)
                                Text(WQStrings.startSystemScan)
                                    .font(.headline)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 16)
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
    }
}
