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
            // Scan Scope & High-Risk Full System Scan Opt-In Switch
            Section {
                Toggle(isOn: Binding(
                    get: { vm.isFullSystemScanEnabled },
                    set: { vm.requestToggleFullSystemScan($0) }
                )) {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text(WQStrings.fullScanToggleTitle)
                                .font(.subheadline.bold())
                            Text(WQStrings.fullScanBadgeRisk)
                                .font(.system(size: 10, weight: .bold))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.orange.opacity(0.2))
                                .foregroundColor(.orange)
                                .clipShape(Capsule())
                        }
                        Text(vm.isFullSystemScanEnabled ? WQStrings.fullScanToggleSubOn : WQStrings.fullScanToggleSubOff)
                            .font(.caption)
                            .foregroundColor(.gray)
                    }
                }
                .tint(.orange)
            } header: {
                Text(WQStrings.settingsScanModeHeader)
            } footer: {
                Text(WQStrings.settingsScanModeFooter)
            }

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
                    Text("WQGuardCore v1.0.2").foregroundColor(.gray)
                }
                HStack {
                    Text(WQStrings.settingsAppBuild)
                    Spacer()
                    let ver = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.2"
                    let bld = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "3"
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

// MARK: - Mandatory Risk Disclosure & Security Notice Consent Sheet

public struct FullScanConsentSheet: View {
    @EnvironmentObject var vm: ScanViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var hasReadAndAccepted: Bool = false

    public init() {}

    public var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // High-Visibility Warning Header Banner
                    HStack(alignment: .top, spacing: 14) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 30, weight: .bold))
                            .foregroundColor(.orange)
                        VStack(alignment: .leading, spacing: 6) {
                            Text(WQStrings.consentBannerTitle)
                                .font(.headline.bold())
                                .foregroundColor(.white)
                            Text(WQStrings.consentBannerSubtitle)
                                .font(.caption)
                                .foregroundColor(.orange.opacity(0.95))
                        }
                    }
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: 16)
                            .fill(Color.orange.opacity(0.14))
                            .overlay(
                                RoundedRectangle(cornerRadius: 16)
                                    .stroke(Color.orange.opacity(0.55), lineWidth: 1.5)
                            )
                    )

                    // 4 Security & Risk Clauses
                    clauseCard(icon: "lock.trianglebadge.exclamationmark.fill", title: WQStrings.consentClause1Title, detail: WQStrings.consentClause1Body)
                    clauseCard(icon: "link.badge.plus", title: WQStrings.consentClause2Title, detail: WQStrings.consentClause2Body)
                    clauseCard(icon: "cpu.fill", title: WQStrings.consentClause3Title, detail: WQStrings.consentClause3Body)
                    clauseCard(icon: "hand.raised.shield.fill", title: WQStrings.consentClause4Title, detail: WQStrings.consentClause4Body)

                    // Mandatory Explicit Checkbox Confirmation
                    Button(action: {
                        #if os(iOS)
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                        #endif
                        hasReadAndAccepted.toggle()
                    }) {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: hasReadAndAccepted ? "checkmark.square.fill" : "square")
                                .font(.title3.bold())
                                .foregroundColor(hasReadAndAccepted ? .orange : .gray)
                            Text(WQStrings.consentCheckboxLabel)
                                .font(.footnote.bold())
                                .foregroundColor(.white)
                                .multilineTextAlignment(.leading)
                        }
                        .padding(14)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(
                            RoundedRectangle(cornerRadius: 14)
                                .fill(Color(red: 0.12, green: 0.13, blue: 0.18))
                                .overlay(
                                    RoundedRectangle(cornerRadius: 14)
                                        .stroke(hasReadAndAccepted ? Color.orange.opacity(0.6) : Color.white.opacity(0.15), lineWidth: 1)
                                )
                        )
                    }
                    .buttonStyle(.plain)

                    // Confirm & Cancel Actions
                    VStack(spacing: 10) {
                        Button(action: {
                            vm.confirmEnableFullSystemScan()
                            dismiss()
                        }) {
                            HStack {
                                Image(systemName: "checkmark.shield.fill")
                                Text(WQStrings.consentConfirmButton)
                                    .font(.headline.bold())
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 15)
                            .background(hasReadAndAccepted ? Color.orange : Color.gray.opacity(0.25))
                            .foregroundColor(hasReadAndAccepted ? .black : .gray)
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                        }
                        .disabled(!hasReadAndAccepted)

                        Button(role: .cancel, action: {
                            dismiss()
                        }) {
                            Text(WQStrings.consentKeepDefaultButton)
                                .font(.subheadline.bold())
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 13)
                                .background(Color.white.opacity(0.08))
                                .foregroundColor(.white)
                                .clipShape(RoundedRectangle(cornerRadius: 14))
                        }
                    }
                    .padding(.top, 4)
                }
                .padding(18)
            }
            .background(Color(red: 0.06, green: 0.07, blue: 0.10).ignoresSafeArea())
            .navigationTitle(WQStrings.consentNavTitle)
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(WQStrings.buttonClose) { dismiss() }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private func clauseCard(icon: String, title: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .foregroundColor(.orange)
                Text(title)
                    .font(.subheadline.bold())
                    .foregroundColor(.white)
            }
            Text(detail)
                .font(.caption)
                .foregroundColor(.gray)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color.white.opacity(0.08), lineWidth: 1)
                )
        )
    }
}
