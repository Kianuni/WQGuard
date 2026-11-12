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
    @State private var showFilePicker = false
    @State private var showFolderPicker = false

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
                        Button(action: { showFilePicker = true }) {
                            Label(WQStrings.selectIPAFileButton, systemImage: "doc.zipper")
                                .font(.subheadline.bold())
                                .padding(.horizontal, 18)
                                .padding(.vertical, 13)
                                .background(Color(red: 0.0, green: 0.78, blue: 0.65))
                                .foregroundColor(.black)
                                .clipShape(Capsule())
                        }

                        Button(action: { showFolderPicker = true }) {
                            Label(WQStrings.bindSigningFolderButton, systemImage: "folder.fill.badge.plus")
                                .font(.subheadline.bold())
                                .padding(.horizontal, 18)
                                .padding(.vertical, 13)
                                .background(Color.white.opacity(0.1))
                                .foregroundColor(Color(red: 0.0, green: 0.85, blue: 0.72))
                                .clipShape(Capsule())
                        }
                    }
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
        .background(
            EmptyView()
                .fileImporter(
                    isPresented: $showFilePicker,
                    allowedContentTypes: [.data],
                    allowsMultipleSelection: true
                ) { result in
                    switch result {
                    case .success(let urls):
                        if !urls.isEmpty {
                            vm.scanMultipleIPAPackages(at: urls)
                        }
                    case .failure(let err):
                        vm.ipaErrorMessage = err.localizedDescription
                    }
                }
        )
        .background(
            EmptyView()
                .fileImporter(
                    isPresented: $showFolderPicker,
                    allowedContentTypes: [.folder],
                    allowsMultipleSelection: false
                ) { result in
                    switch result {
                    case .success(let urls):
                        if !urls.isEmpty {
                            vm.scanMultipleIPAPackages(at: urls)
                        }
                    case .failure(let err):
                        vm.ipaErrorMessage = err.localizedDescription
                    }
                }
        )
    }
}
