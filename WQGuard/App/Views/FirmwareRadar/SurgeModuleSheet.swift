//
//  SurgeModuleSheet.swift
//  WQGuard
//
//  Multi-Client Brotli Shield preview, one-tap URL scheme installer,
//  subscription link copier, and Share Sheet file exporter.
//

import SwiftUI
import WQGuardCore
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

public struct SurgeModuleSheet: View {
    @EnvironmentObject var vm: ScanViewModel
    @Environment(\.dismiss) var dismiss
    @State private var copiedFeedbackText: String? = nil

    public init() {}

    public var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // 1. 5-Client Selector Pills
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(ProxyShieldPlatform.allCases) { platform in
                                let isSelected = vm.selectedShieldPlatform == platform
                                Button(action: {
                                    vm.selectedShieldPlatform = platform
                                    copiedFeedbackText = nil
                                }) {
                                    HStack(spacing: 4) {
                                        Text(WQStrings.shieldPlatformShortTitle(platform))
                                            .font(.caption.bold())
                                        Text(".\(platform.fileExtension)")
                                            .font(.system(size: 10, design: .monospaced))
                                            .opacity(0.8)
                                    }
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 8)
                                    .background(isSelected ? Color.teal : Color.white.opacity(0.08))
                                    .foregroundColor(isSelected ? .black : .white)
                                    .clipShape(Capsule())
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }

                    // 2. Quick Import & Copy Action Card
                    VStack(alignment: .leading, spacing: 10) {
                        Text(WQStrings.shieldPlatformUsageHint(vm.selectedShieldPlatform))
                            .font(.caption)
                            .foregroundColor(.gray)

                        if let installURL = vm.selectedShieldPlatform.oneTapInstallURL {
                            Link(destination: installURL) {
                                HStack {
                                    Image(systemName: "arrow.up.forward.app.fill")
                                    Text(WQStrings.shieldOneTapInstallLabel(clientName: WQStrings.shieldPlatformShortTitle(vm.selectedShieldPlatform)))
                                        .fontWeight(.bold)
                                    Spacer()
                                    Image(systemName: "chevron.right")
                                        .font(.caption.bold())
                                }
                                .font(.subheadline)
                                .padding(.horizontal, 14)
                                .padding(.vertical, 12)
                                .background(Color.teal)
                                .foregroundColor(.black)
                                .clipShape(RoundedRectangle(cornerRadius: 12))
                            }
                        }

                        HStack(spacing: 10) {
                            Button(action: {
                                copyToClipboard(vm.selectedShieldPlatform.remoteRawURLString)
                                showCopiedFeedback(WQStrings.shieldCopiedSubURLToast)
                            }) {
                                Label(WQStrings.shieldCopySubURLButton, systemImage: "link")
                                    .font(.caption.bold())
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 10)
                                    .background(Color.white.opacity(0.09))
                                    .foregroundColor(.white)
                                    .clipShape(RoundedRectangle(cornerRadius: 10))
                            }

                            Button(action: {
                                copyToClipboard(vm.surgeModuleContent)
                                showCopiedFeedback(WQStrings.shieldCopiedSourceToast)
                            }) {
                                Label(WQStrings.shieldCopySourceButton, systemImage: "doc.on.doc")
                                    .font(.caption.bold())
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 10)
                                    .background(Color.white.opacity(0.09))
                                    .foregroundColor(.white)
                                    .clipShape(RoundedRectangle(cornerRadius: 10))
                            }
                        }

                        if let feedback = copiedFeedbackText {
                            HStack(spacing: 6) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                Text(feedback)
                                    .foregroundColor(.green)
                            }
                            .font(.caption.bold())
                        }
                    }
                    .padding(14)
                    .background(
                        RoundedRectangle(cornerRadius: 14)
                            .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                    )

                    // 3. Code Preview
                    Text(WQStrings.shieldSheetCodeTitle(filename: vm.selectedShieldPlatform.defaultFilename))
                        .font(.subheadline.bold())
                        .foregroundColor(.white)

                    TerminalCodeView(text: vm.surgeModuleContent)
                }
                .padding()
            }
            .navigationTitle(WQStrings.surgeSheetNavTitle)
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(WQStrings.buttonClose) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if let url = vm.surgeModuleExportURL {
                        ShareLink(item: url) {
                            Image(systemName: "square.and.arrow.up")
                        }
                    }
                }
            }
        }
    }

    private func copyToClipboard(_ string: String) {
        #if canImport(UIKit)
        UIPasteboard.general.string = string
        #elseif canImport(AppKit)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
        #endif
    }

    private func showCopiedFeedback(_ message: String) {
        copiedFeedbackText = message
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
            if copiedFeedbackText == message {
                copiedFeedbackText = nil
            }
        }
    }
}
