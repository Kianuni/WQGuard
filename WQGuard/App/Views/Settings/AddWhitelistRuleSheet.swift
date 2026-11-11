//
//  AddWhitelistRuleSheet.swift
//  WQGuard
//
//  Form sheet to add custom bundle ID rules to WhitelistEngine.
//

import SwiftUI
import WQGuardCore

public struct AddWhitelistRuleSheet: View {
    @EnvironmentObject var vm: ScanViewModel
    @Environment(\.dismiss) var dismiss

    @State private var toolName: String = ""
    @State private var bundleId: String = ""
    @State private var appGroup: String = ""

    public init() {}

    public var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(WQStrings.ruleSheetToolNamePlaceholder, text: $toolName)
                    TextField(WQStrings.ruleSheetBundleIdPlaceholder, text: $bundleId)
                        #if os(iOS)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        #endif
                    TextField(WQStrings.ruleSheetAppGroupPlaceholder, text: $appGroup)
                        #if os(iOS)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        #endif
                } header: {
                    Text(WQStrings.ruleSheetSectionHeader)
                } footer: {
                    Text(WQStrings.ruleSheetSectionFooter)
                }
            }
            .navigationTitle(WQStrings.ruleSheetNavTitle)
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(WQStrings.buttonCancel) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(WQStrings.buttonSave) {
                        vm.addCustomWhitelistRule(bundleId: bundleId, name: toolName, appGroup: appGroup)
                        dismiss()
                    }
                    .disabled(bundleId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}
