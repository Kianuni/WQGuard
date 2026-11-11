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

                    Button(action: { showFilePicker = true }) {
                        Label(WQStrings.selectIPAButton, systemImage: "folder.fill")
                            .font(.headline)
                            .padding(.horizontal, 24)
                            .padding(.vertical, 14)
                            .background(Color(red: 0.0, green: 0.78, blue: 0.65))
                            .foregroundColor(.black)
                            .clipShape(Capsule())
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
                    IPAPackageCard(finding: finding)
                        .padding(.horizontal)
                }
            }
            .padding(.top, 16)
        }
        .navigationTitle(WQStrings.tabIPAScan)
        .fileImporter(
            isPresented: $showFilePicker,
            allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .archive],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first {
                    vm.scanIPAPackage(at: url)
                }
            case .failure(let err):
                vm.ipaErrorMessage = err.localizedDescription
            }
        }
    }
}
