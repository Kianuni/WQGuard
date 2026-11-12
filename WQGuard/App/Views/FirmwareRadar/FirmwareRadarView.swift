//
//  FirmwareRadarView.swift
//  WQGuard
//
//  Evaluates device firmware against 8 2026 iOS vulnerabilities and provides
//  actionable non-upgrade mitigations with Surge module export.
//

import SwiftUI
import WQGuardCore

public struct FirmwareRadarView: View {
    @EnvironmentObject var vm: ScanViewModel
    @State private var showSurgeSheet = false

    public init() {}

    public var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Firmware Version Header Card
                VStack(spacing: 12) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(vm.firmwareReport.osVersion.displayString)
                                .font(.title.bold())
                                .foregroundColor(.white)

                            Text(branchBadgeText)
                                .font(.caption.bold())
                                .foregroundColor(.teal)
                        }
                        Spacer()
                        ZStack {
                            Circle()
                                .fill(vm.firmwareReport.exposedCount > 0 ? Color.red.opacity(0.15) : Color.green.opacity(0.15))
                                .frame(width: 50, height: 50)
                            Image(systemName: vm.firmwareReport.exposedCount > 0 ? "exclamationmark.triangle.fill" : "checkmark.shield.fill")
                                .foregroundColor(vm.firmwareReport.exposedCount > 0 ? .red : .green)
                                .font(.title3.bold())
                        }
                    }

                    Divider().background(Color.white.opacity(0.15))

                    HStack {
                        Label(WQStrings.radarExposedCount(vm.firmwareReport.exposedCount), systemImage: "exclamationmark.circle")
                            .font(.caption.bold())
                            .foregroundColor(.red)
                        Spacer()
                        Label(WQStrings.radarPatchedCount(vm.firmwareReport.patchedVulnerabilities.count), systemImage: "checkmark.circle")
                            .font(.caption.bold())
                            .foregroundColor(.green)
                    }
                }
                .padding(18)
                .background(
                    RoundedRectangle(cornerRadius: 18)
                        .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                )
                .padding(.horizontal)

                // Multi-Client Brotli Shield Action Card
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Image(systemName: "shield.lefthalf.filled")
                            .foregroundColor(.teal)
                            .font(.title3)
                        Text(WQStrings.surgeShieldTitle)
                            .font(.headline)
                            .foregroundColor(.white)
                        Spacer()
                        Text("CVE-2026-111497")
                            .font(.system(size: 10, weight: .bold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.red.opacity(0.2))
                            .foregroundColor(.red)
                            .clipShape(Capsule())
                    }

                    Text(WQStrings.surgeShieldDescription)
                        .font(.caption)
                        .foregroundColor(.gray)

                    // 5-Client Selector Bar
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(ProxyShieldPlatform.allCases) { platform in
                                let isSelected = vm.selectedShieldPlatform == platform
                                Button(action: {
                                    vm.selectedShieldPlatform = platform
                                }) {
                                    HStack(spacing: 4) {
                                        Text(WQStrings.shieldPlatformShortTitle(platform))
                                            .font(.caption.bold())
                                        Text(".\(platform.fileExtension)")
                                            .font(.system(size: 10, design: .monospaced))
                                            .opacity(0.8)
                                    }
                                    .padding(.horizontal, 11)
                                    .padding(.vertical, 7)
                                    .background(isSelected ? Color.teal : Color.white.opacity(0.08))
                                    .foregroundColor(isSelected ? .black : .white)
                                    .clipShape(Capsule())
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }

                    Text(WQStrings.shieldPlatformUsageHint(vm.selectedShieldPlatform))
                        .font(.caption2)
                        .foregroundColor(.teal.opacity(0.9))
                        .fixedSize(horizontal: false, vertical: true)

                    HStack(spacing: 12) {
                        Button(action: { showSurgeSheet = true }) {
                            Label(WQStrings.surgeShieldPreview, systemImage: "bolt.shield.fill")
                                .font(.caption.bold())
                                .padding(.horizontal, 14)
                                .padding(.vertical, 10)
                                .background(Color.white.opacity(0.1))
                                .foregroundColor(.white)
                                .clipShape(RoundedRectangle(cornerRadius: 10))
                        }

                        if let url = vm.surgeModuleExportURL {
                            ShareLink(item: url) {
                                Label(WQStrings.shieldExportButtonLabel(ext: vm.selectedShieldPlatform.fileExtension), systemImage: "square.and.arrow.up.fill")
                                    .font(.caption.bold())
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 10)
                                    .background(Color.teal)
                                    .foregroundColor(.black)
                                    .clipShape(RoundedRectangle(cornerRadius: 10))
                            }
                        }
                    }
                }
                .padding(18)
                .background(
                    RoundedRectangle(cornerRadius: 18)
                        .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                )
                .padding(.horizontal)

                // 8 CVE Status Cards Grid
                VStack(alignment: .leading, spacing: 12) {
                    Text(WQStrings.radarKnownVulnerabilitiesHeader(count: FirmwarePostureEngine.allVulnerabilities.count))
                        .font(.headline)
                        .foregroundColor(.white)
                        .padding(.horizontal)

                    ForEach(FirmwarePostureEngine.allVulnerabilities) { vuln in
                        let isExposed = vm.firmwareReport.exposedVulnerabilities.contains(where: { $0.id == vuln.id })
                        CVECardView(vuln: vuln, isExposed: isExposed)
                            .padding(.horizontal)
                    }
                }

                // Actionable Mitigations
                if !vm.firmwareReport.actionableMitigations.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(WQStrings.radarMitigationGuidanceHeader)
                            .font(.headline)
                            .foregroundColor(.white)
                            .padding(.horizontal)

                        ForEach(vm.firmwareReport.actionableMitigations) { mit in
                            MitigationRowView(mitigation: mit)
                                .padding(.horizontal)
                        }
                    }
                }
            }
            .padding(.vertical, 16)
        }
        .navigationTitle(WQStrings.tabFirmwareRadar)
        .sheet(isPresented: $showSurgeSheet) {
            SurgeModuleSheet()
        }
    }

    private var branchBadgeText: String {
        let v = vm.firmwareReport.osVersion
        return WQStrings.radarBranchBadge(major: v.major)
    }
}
