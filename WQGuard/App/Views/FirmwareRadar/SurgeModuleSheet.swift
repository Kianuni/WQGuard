//
//  SurgeModuleSheet.swift
//  WQGuard
//
//  Surge Brotli Shield preview & Share Sheet exporter sheet.
//

import SwiftUI
import WQGuardCore

public struct SurgeModuleSheet: View {
    @EnvironmentObject var vm: ScanViewModel
    @Environment(\.dismiss) var dismiss

    public init() {}

    public var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text(WQStrings.surgeSheetCodeTitle)
                        .font(.headline)
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
}
