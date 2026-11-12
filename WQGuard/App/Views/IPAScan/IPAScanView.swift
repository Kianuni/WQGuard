//
//  IPAScanView.swift
//  WQGuard
//
//  Pre-installation & batch multi-select security scanner for local .ipa / .tipa packages.
//

import SwiftUI
import UniformTypeIdentifiers
import WQGuardCore

public struct IPAScanView: View {
    @EnvironmentObject var vm: ScanViewModel

    public init() {}

    public var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Multi-Select IPA Import Card
                VStack(spacing: 16) {
                    ZStack {
                        Circle()
                            .fill(Color(red: 0.0, green: 0.78, blue: 0.65).opacity(0.15))
                            .frame(width: 72, height: 72)
                        Image(systemName: "doc.badge.plus")
                            .font(.system(size: 32))
                            .foregroundColor(Color(red: 0.0, green: 0.78, blue: 0.65))
                    }

                    VStack(spacing: 4) {
                        Text(WQStrings.ipaImportTitle)
                            .font(.title3.bold())
                            .foregroundColor(.white)
                        Text(WQStrings.ipaImportSub)
                            .font(.caption)
                            .foregroundColor(.gray)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 24)
                    }

                    Button(action: { presentPicker() }) {
                        Label(WQStrings.selectIPAFileButton, systemImage: "doc.badge.plus")
                            .font(.subheadline.bold())
                            .padding(.horizontal, 22)
                            .padding(.vertical, 14)
                            .background(Color(red: 0.0, green: 0.78, blue: 0.65))
                            .foregroundColor(.black)
                            .clipShape(Capsule())
                    }

                    Text("💡 支持在系统『文件』中一次勾选多个 .ipa / .tipa 文件加入扫描列表；Feather 已签名应用可在 Feather「库 → 已签名 → 导出 IPA」后导入。")
                        .font(.caption2)
                        .foregroundColor(.gray)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 20)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 32)
                .background(
                    RoundedRectangle(cornerRadius: 20)
                        .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                        .overlay(
                            RoundedRectangle(cornerRadius: 20)
                                .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [6]))
                                .foregroundColor(Color.white.opacity(0.2))
                        )
                )
                .padding(.horizontal)

                // Queued / Added IPA Scan List Card
                if !vm.syncedPackageNames.isEmpty {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Label("已加入扫描文件 (\(vm.syncedPackageNames.count))", systemImage: "tray.full.fill")
                                .font(.subheadline.bold())
                                .foregroundColor(Color(red: 0.0, green: 0.85, blue: 0.72))
                            Spacer()
                            Button(action: { vm.rescanAllSyncedPackages(correlateWithInstalled: false) }) {
                                Text("全部重扫")
                                    .font(.caption.bold())
                                    .foregroundColor(.cyan)
                            }
                            Text("·")
                                .foregroundColor(.gray)
                            Button(role: .destructive, action: { vm.clearSyncedPackages() }) {
                                Text("清空")
                                    .font(.caption.bold())
                                    .foregroundColor(.red)
                            }
                        }

                        ForEach(vm.syncedPackageNames, id: \.self) { pkgName in
                            HStack(spacing: 8) {
                                Image(systemName: "doc.zipper")
                                    .font(.caption)
                                    .foregroundColor(.teal)
                                Text(pkgName)
                                    .font(.caption.monospaced())
                                    .foregroundColor(.white)
                                    .lineLimit(1)
                                Spacer()
                                Button(action: { vm.removeSyncedPackage(named: pkgName) }) {
                                    Image(systemName: "xmark.circle.fill")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                }
                                .buttonStyle(.plain)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                    .padding(16)
                    .background(Color(red: 0.11, green: 0.13, blue: 0.18))
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    .padding(.horizontal)
                }

                // Inspection Status & Results
                if vm.isInspectingIPA {
                    VStack(spacing: 12) {
                        ProgressView()
                            .tint(Color(red: 0.0, green: 0.78, blue: 0.65))
                        Text(WQStrings.ipaAnalyzing)
                            .font(.caption.monospaced())
                            .foregroundColor(.gray)
                    }
                    .padding(24)
                } else if let error = vm.ipaErrorMessage {
                    VStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                            .font(.title)
                        Text(WQStrings.ipaAnalysisFailed)
                            .font(.headline.bold())
                            .foregroundColor(.white)
                        Text(error)
                            .font(.caption)
                            .foregroundColor(.gray)
                            .multilineTextAlignment(.center)
                    }
                    .padding(20)
                    .background(Color.red.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    .padding(.horizontal)
                } else if let finding = vm.inspectedIPAFinding {
                    if vm.totalScannedCount > 1 {
                        HStack(spacing: 10) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(Color(red: 0.0, green: 0.78, blue: 0.65))
                            Text(WQStrings.batchIPACompletedBanner(vm.totalScannedCount))
                                .font(.caption)
                                .foregroundColor(.white)
                            Spacer()
                        }
                        .padding(14)
                        .background(Color(red: 0.12, green: 0.16, blue: 0.18))
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .padding(.horizontal)
                    }
                    IPAPackageCard(finding: finding)
                        .padding(.horizontal)
                }
            }
            .padding(.top, 16)
            .padding(.bottom, 24)
        }
        .navigationTitle(WQStrings.tabIPAScan)
    }

    private func presentPicker() {
        #if canImport(UIKit)
        NativeDocumentPickerPresenter.shared.present(kind: .ipaFiles) { urls in
            vm.scanMultipleIPAPackages(at: urls, correlateWithInstalled: false)
        }
        #endif
    }
}
