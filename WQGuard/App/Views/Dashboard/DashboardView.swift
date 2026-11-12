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
                    onInspectFindings: vm.hasScannedApps ? {
                        vm.navigateToFindings(filter: vm.highRiskCount > 0 ? .highRisk : (vm.cautionCount > 0 ? .caution : nil))
                    } : nil
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

                        Button(action: {
                            #if os(iOS)
                            UIImpactFeedbackGenerator(style: .light).impactOccurred()
                            #endif
                            vm.showInstalledScanConfigSheet = true
                        }) {
                            HStack(spacing: 8) {
                                Image(systemName: "slider.horizontal.below.square.and.square.filled")
                                    .font(.subheadline)
                                Text(WQStrings.configureInstalledScanButton)
                                    .font(.footnote.bold())
                                Spacer()
                                Text("已启用 \(vm.activeEngineCount)/3 引擎")
                                    .font(.caption2.bold())
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 3)
                                    .background(Color.cyan.opacity(0.2))
                                    .foregroundColor(.cyan)
                                    .clipShape(Capsule())
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 12)
                            .background(Color(red: 0.11, green: 0.14, blue: 0.20))
                            .foregroundColor(.cyan)
                            .overlay(
                                RoundedRectangle(cornerRadius: 14)
                                    .stroke(Color.cyan.opacity(0.35), lineWidth: 1)
                            )
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                        }

                        Button(action: {
                            #if os(iOS)
                            UIImpactFeedbackGenerator(style: .light).impactOccurred()
                            #endif
                            presentPicker(.ipaFiles)
                        }) {
                            HStack(spacing: 8) {
                                Image(systemName: "doc.badge.plus")
                                    .font(.subheadline)
                                Text(WQStrings.selectIPAFileButton)
                                    .font(.footnote.bold())
                                Spacer()
                                if !vm.syncedPackageNames.isEmpty {
                                    Text("已加入 \(vm.syncedPackageNames.count) 个")
                                        .font(.caption2.bold())
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 3)
                                        .background(Color(red: 0.0, green: 0.78, blue: 0.65).opacity(0.2))
                                        .foregroundColor(Color(red: 0.0, green: 0.85, blue: 0.72))
                                        .clipShape(Capsule())
                                }
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 12)
                            .background(Color(red: 0.13, green: 0.15, blue: 0.20))
                            .foregroundColor(Color(red: 0.0, green: 0.85, blue: 0.72))
                            .overlay(
                                RoundedRectangle(cornerRadius: 14)
                                    .stroke(Color(red: 0.0, green: 0.78, blue: 0.65).opacity(0.4), lineWidth: 1)
                            )
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                        }

                        if let engineSummary = vm.lastScanEngineSummary {
                            Text(engineSummary)
                                .font(.caption2)
                                .foregroundColor(.cyan)
                                .lineLimit(1)
                        } else if !vm.syncedPackageNames.isEmpty {
                            Text("已加入扫描列表: \(vm.syncedPackageNames.joined(separator: ", "))")
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
                        Button(action: { if vm.hasScannedApps { vm.navigateToFindings(filter: nil) } }) {
                            MetricGridCard(
                                title: WQStrings.scannedApps,
                                count: vm.totalScannedCount,
                                icon: "apps.iphone",
                                color: .blue
                            )
                        }
                        .buttonStyle(.plain)

                        Button(action: { if vm.hasScannedApps { vm.navigateToFindings(filter: .highRisk) } }) {
                            MetricGridCard(
                                title: WQStrings.highRiskAlerts,
                                count: vm.highRiskCount,
                                icon: "exclamationmark.shield.fill",
                                color: .red
                            )
                        }
                        .buttonStyle(.plain)

                        Button(action: { if vm.hasScannedApps { vm.navigateToFindings(filter: .knownTool) } }) {
                            MetricGridCard(
                                title: WQStrings.knownTools,
                                count: vm.knownToolCount,
                                icon: "wrench.and.screwdriver.fill",
                                color: .yellow
                            )
                        }
                        .buttonStyle(.plain)

                        Button(action: { if vm.hasScannedApps { vm.navigateToFindings(filter: .caution) } }) {
                            MetricGridCard(
                                title: WQStrings.cautionAlerts,
                                count: vm.cautionCount,
                                icon: "exclamationmark.triangle.fill",
                                color: .orange
                            )
                        }
                        .buttonStyle(.plain)
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
        .sheet(isPresented: $vm.showInstalledScanConfigSheet) {
            InstalledScanConfigSheet()
        }
    }

    private func presentPicker(_ kind: DocumentPickerKind) {
        #if canImport(UIKit)
        NativeDocumentPickerPresenter.shared.present(kind: kind) { urls in
            vm.scanMultipleIPAPackages(at: urls, correlateWithInstalled: true)
        }
        #endif
    }
}
