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
    @State private var showFolderPicker = false
    @State private var showIPAFilePicker = false

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
                    exposedCVECount: vm.firmwareReport.exposedCount
                )

                // 2. Self-Signed Application Scan & Signing Folder Binding Actions
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
                            VStack(spacing: 4) {
                                HStack(spacing: 8) {
                                    Image(systemName: "play.shield.fill")
                                        .font(.title3.bold())
                                    Text(WQStrings.startSystemScan)
                                        .font(.headline.bold())
                                }
                                Text(WQStrings.startSystemScanSub)
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

                        HStack(spacing: 10) {
                            Button(action: {
                                #if os(iOS)
                                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                                #endif
                                showFolderPicker = true
                            }) {
                                HStack(spacing: 6) {
                                    Image(systemName: "folder.fill.badge.plus")
                                        .font(.subheadline)
                                    Text(WQStrings.bindSigningFolderButton)
                                        .font(.footnote.bold())
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 13)
                                .background(Color(red: 0.13, green: 0.15, blue: 0.20))
                                .foregroundColor(Color(red: 0.0, green: 0.85, blue: 0.72))
                                .overlay(
                                    RoundedRectangle(cornerRadius: 14)
                                        .stroke(Color(red: 0.0, green: 0.78, blue: 0.65).opacity(0.4), lineWidth: 1)
                                )
                                .clipShape(RoundedRectangle(cornerRadius: 14))
                            }

                            Button(action: {
                                #if os(iOS)
                                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                                #endif
                                showIPAFilePicker = true
                            }) {
                                HStack(spacing: 6) {
                                    Image(systemName: "doc.zipper")
                                        .font(.subheadline)
                                    Text(WQStrings.selectIPAFileButton)
                                        .font(.footnote.bold())
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 13)
                                .background(Color(red: 0.13, green: 0.15, blue: 0.20))
                                .foregroundColor(.white)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 14)
                                        .stroke(Color.white.opacity(0.2), lineWidth: 1)
                                )
                                .clipShape(RoundedRectangle(cornerRadius: 14))
                            }
                        }

                        if !vm.bookmarkedFolderNames.isEmpty {
                            Text("已绑定目录: \(vm.bookmarkedFolderNames.joined(separator: ", "))")
                                .font(.caption2)
                                .foregroundColor(.gray)
                                .lineLimit(1)
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
        .onChange(of: vm.showSideloadPickerFromDashboard) { newValue in
            if newValue {
                vm.showSideloadPickerFromDashboard = false
                showFolderPicker = true
            }
        }
        .background(
            EmptyView()
                .fileImporter(
                    isPresented: $showFolderPicker,
                    allowedContentTypes: [.folder],
                    allowsMultipleSelection: false
                ) { result in
                    switch result {
                    case .success(let urls):
                        vm.scanMultipleIPAPackages(at: urls)
                    case .failure(let err):
                        vm.activeAlertMessage = err.localizedDescription
                        vm.showGlobalAlert = true
                    }
                }
        )
        .background(
            EmptyView()
                .fileImporter(
                    isPresented: $showIPAFilePicker,
                    allowedContentTypes: [.data],
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
        )
    }
}
