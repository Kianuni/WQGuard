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
    @State private var teamId: String = ""
    @State private var validationError: String? = nil

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
                    TextField(WQStrings.ruleSheetTeamIdPlaceholder, text: $teamId)
                        #if os(iOS)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        #endif
                } header: {
                    Text(WQStrings.ruleSheetSectionHeader)
                } footer: {
                    Text(WQStrings.ruleSheetSectionFooter)
                }

                if let err = validationError {
                    Section {
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.red)
                            Text(err)
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }
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
                        let cleanTeam = teamId.trimmingCharacters(in: .whitespacesAndNewlines)
                        let result = vm.addCustomWhitelistRule(
                            bundleId: bundleId,
                            name: toolName,
                            appGroup: appGroup,
                            allowedTeamIds: cleanTeam.isEmpty ? nil : [cleanTeam]
                        )
                        if result.success {
                            validationError = nil
                            dismiss()
                        } else {
                            validationError = result.errorMessage ?? WQStrings.whitelistRejectedFallback
                        }
                    }
                    .disabled(bundleId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}
