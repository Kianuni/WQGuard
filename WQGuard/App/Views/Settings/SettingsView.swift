//
//  SettingsView.swift
//  WQGuard
//
//  Settings screen to manage known tool whitelist and custom exclusions.
//

import SwiftUI
import WQGuardCore

public struct SettingsView: View {
    @EnvironmentObject var vm: ScanViewModel
    @State private var showResetConfirm = false

    public init() {}

    public var body: some View {
        List {
            // Built-in Known Tools Whitelist
            Section {
                ForEach(vm.whitelistedTools.filter { $0.isBuiltIn }) { tool in
                    Toggle(isOn: Binding(
                        get: { tool.isEnabled },
                        set: { vm.toggleWhitelist(for: tool, isEnabled: $0) }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(tool.name)
                                .font(.subheadline.bold())
                            Text(tool.description)
                                .font(.caption)
                                .foregroundColor(.gray)
                        }
                    }
                }
            } header: {
                Text(WQStrings.settingsBuiltinWhitelist)
            } footer: {
                Text(WQStrings.settingsBuiltinWhitelistFooter)
            }

            // Custom Whitelist Rules
            Section {
                let customTools = vm.whitelistedTools.filter { !$0.isBuiltIn }
                if customTools.isEmpty {
                    Text(WQStrings.settingsNoCustomRules)
                        .font(.caption)
                        .foregroundColor(.gray)
                } else {
                    ForEach(customTools) { tool in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(tool.name)
                                    .font(.subheadline.bold())
                                Text(tool.allowedBundleIds.joined(separator: ", "))
                                    .font(.caption.monospaced())
                                    .foregroundColor(.gray)
                            }
                            Spacer()
                        }
                    }
                    .onDelete { indexSet in
                        for idx in indexSet {
                            let tool = customTools[idx]
                            vm.removeCustomWhitelistRule(named: tool.name)
                        }
                    }
                }

                Button(action: { vm.showAddRuleSheet = true }) {
                    Label(WQStrings.settingsAddRule, systemImage: "plus.circle.fill")
                        .foregroundColor(.teal)
                }
            } header: {
                Text(WQStrings.settingsCustomRules)
            }

            // Reset Section
            Section {
                Button(role: .destructive, action: { showResetConfirm = true }) {
                    Text(WQStrings.settingsResetButton)
                }
            }

            // About WQGuard
            Section {
                HStack {
                    Text(WQStrings.settingsEngineVersion)
                    Spacer()
                    Text("WQGuardCore v1.1.3").foregroundColor(.gray)
                }
                HStack {
                    Text(WQStrings.settingsAppBuild)
                    Spacer()
                    let ver = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.1.3"
                    let bld = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "9"
                    Text("\(ver) (Build \(bld))").foregroundColor(.gray)
                }
                HStack {
                    Text(WQStrings.settingsOperatingMode)
                    Spacer()
                    Text(WQStrings.settingsReadOnlyMode).foregroundColor(.green)
                }
            } header: {
                Text(WQStrings.settingsAboutHeader)
            } footer: {
                Text(WQStrings.settingsAboutFooter)
            }
        }
        .navigationTitle(WQStrings.tabSettings)
        .sheet(isPresented: $vm.showAddRuleSheet) {
            AddWhitelistRuleSheet()
        }
        .confirmationDialog(
            WQStrings.settingsResetConfirmTitle,
            isPresented: $showResetConfirm,
            titleVisibility: .visible
        ) {
            Button(WQStrings.settingsResetConfirmAction, role: .destructive) {
                vm.resetWhitelistToDefaults()
            }
            Button(WQStrings.buttonCancel, role: .cancel) {}
        } message: {
            Text(WQStrings.settingsResetConfirmMessage)
        }
    }
}
