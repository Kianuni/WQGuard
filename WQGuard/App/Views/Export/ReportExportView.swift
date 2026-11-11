//
//  ReportExportView.swift
//  WQGuard
//
//  Multi-format security audit report export view with live preview.
//

import SwiftUI
import WQGuardCore

public struct ReportExportView: View {
    @EnvironmentObject var vm: ScanViewModel
    @Environment(\.dismiss) var dismiss
    @State private var showCopiedAlert = false

    public init() {}

    public var body: some View {
        NavigationStack {
            VStack(spacing: 14) {
                // Format Switcher
                Picker(WQStrings.exportFormatPicker, selection: $vm.exportFormat) {
                    ForEach(ScanViewModel.ExportFormat.allCases) { format in
                        Text(format.rawValue).tag(format)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)
                .onChange(of: vm.exportFormat) { _ in
                    vm.updateExportedReport()
                }

                // Monospace Preview
                TerminalCodeView(text: vm.exportedReportText)
                    .padding(.horizontal)

                // Actions Bar
                HStack(spacing: 12) {
                    Button(action: {
                        #if os(iOS)
                        UIPasteboard.general.string = vm.exportedReportText
                        UINotificationFeedbackGenerator().notificationOccurred(.success)
                        #endif
                        showCopiedAlert = true
                    }) {
                        Label(WQStrings.exportCopyToClipboard, systemImage: "doc.on.doc.fill")
                            .font(.subheadline.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(Color.white.opacity(0.1))
                            .foregroundColor(.white)
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                    }

                    if let url = vm.exportedReportURL {
                        ShareLink(item: url) {
                            Label(WQStrings.exportShareFile, systemImage: "square.and.arrow.up.fill")
                                .font(.subheadline.bold())
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 14)
                                .background(Color.teal)
                                .foregroundColor(.black)
                                .clipShape(RoundedRectangle(cornerRadius: 14))
                        }
                    }
                }
                .padding(.horizontal)
                .padding(.bottom, 8)
            }
            .navigationTitle(WQStrings.exportNavTitle)
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(WQStrings.buttonDone) { dismiss() }
                }
            }
            .alert(WQStrings.exportCopiedNotice, isPresented: $showCopiedAlert) {
                Button(WQStrings.buttonAcknowledge, role: .cancel) {}
            }
        }
    }
}
