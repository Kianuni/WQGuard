//
//  IPAScanView.swift
//  WQGuard
//
//  Pre-installation security scanner for local .ipa packages.
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
                // Drop / Import Card
                VStack(spacing: 16) {
                    ZStack {
                        Circle()
                            .fill(Color(red: 0.0, green: 0.78, blue: 0.65).opacity(0.15))
                            .frame(width: 72, height: 72)
                        Image(systemName: "arrow.up.doc.fill")
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

                    HStack(spacing: 12) {
                        Button(action: { presentPicker(.ipaFiles) }) {
                            Label(WQStrings.selectIPAFileButton, systemImage: "doc.zipper")
                                .font(.subheadline.bold())
                                .padding(.horizontal, 18)
                                .padding(.vertical, 13)
                                .background(Color(red: 0.0, green: 0.78, blue: 0.65))
                                .foregroundColor(.black)
                                .clipShape(Capsule())
                        }

                        Button(action: { presentPicker(.signingFolder) }) {
                            Label(WQStrings.bindSigningFolderButton, systemImage: "folder.fill.badge.plus")
                                .font(.subheadline.bold())
                                .padding(.horizontal, 18)
                                .padding(.vertical, 13)
                                .background(Color.white.opacity(0.1))
                                .foregroundColor(Color(red: 0.0, green: 0.85, blue: 0.72))
                                .clipShape(Capsule())
                        }
                    }

                    Text("💡 Feather 用户：点击左侧「导入源包」，进入『我的 iPhone → Feather → Signed → UUID文件夹』直接点选里面的 .app 包即可深扫（或在 Feather 内导出 IPA 用 WQGuard 打开）")
                        .font(.caption2)
                        .foregroundColor(.orange.opacity(0.9))
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
        }
        .navigationTitle(WQStrings.tabIPAScan)
    }

    private func presentPicker(_ kind: DocumentPickerKind) {
        #if canImport(UIKit)
        NativeDocumentPickerPresenter.shared.present(kind: kind) { urls in
            vm.scanMultipleIPAPackages(at: urls)
        }
        #endif
    }
}
