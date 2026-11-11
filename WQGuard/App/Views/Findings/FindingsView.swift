//
//  FindingsView.swift
//  WQGuard
//
//  Filterable list of security audit findings grouped by RiskTier.
//

import SwiftUI
import WQGuardCore

public struct FindingsView: View {
    @EnvironmentObject var vm: ScanViewModel

    public init() {}

    public var body: some View {
        VStack(spacing: 0) {
            // Filter Pills
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    FilterChip(
                        title: "\(WQStrings.filterAll) (\(vm.totalScannedCount))",
                        isSelected: vm.selectedRiskFilter == nil,
                        action: { vm.selectedRiskFilter = nil }
                    )
                    FilterChip(
                        title: "\(WQStrings.filterHighRisk) (\(vm.highRiskCount))",
                        isSelected: vm.selectedRiskFilter == .highRisk,
                        color: .red,
                        action: { vm.selectedRiskFilter = .highRisk }
                    )
                    FilterChip(
                        title: "\(WQStrings.filterKnownTool) (\(vm.knownToolCount))",
                        isSelected: vm.selectedRiskFilter == .knownTool,
                        color: .yellow,
                        action: { vm.selectedRiskFilter = .knownTool }
                    )
                    FilterChip(
                        title: "\(WQStrings.filterCaution) (\(vm.cautionCount))",
                        isSelected: vm.selectedRiskFilter == .caution,
                        color: .orange,
                        action: { vm.selectedRiskFilter = .caution }
                    )
                    FilterChip(
                        title: "\(WQStrings.filterSafe) (\(vm.safeCount))",
                        isSelected: vm.selectedRiskFilter == .safe,
                        color: .green,
                        action: { vm.selectedRiskFilter = .safe }
                    )
                }
                .padding(.horizontal)
                .padding(.vertical, 10)
            }
            .background(Color(red: 0.08, green: 0.09, blue: 0.12))

            // Findings List
            if vm.filteredFindings.isEmpty {
                VStack(spacing: 16) {
                    Spacer()
                    Image(systemName: "checkmark.seal.fill")
                        .font(.system(size: 54))
                        .foregroundColor(.green.opacity(0.8))
                    Text(vm.currentSession == nil ? WQStrings.noScanPerformed : WQStrings.noFilteredFindings)
                        .font(.headline)
                        .foregroundColor(.white)
                    Text(vm.currentSession == nil ? WQStrings.noScanPerformedSub : WQStrings.noFilteredFindingsSub)
                        .font(.caption)
                        .foregroundColor(.gray)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                    Spacer()
                }
            } else {
                List(vm.filteredFindings) { finding in
                    NavigationLink(destination: FindingDetailView(finding: finding)) {
                        FindingRowView(finding: finding)
                    }
                    .listRowBackground(Color(red: 0.10, green: 0.11, blue: 0.15))
                }
                .listStyle(.plain)
            }
        }
        .navigationTitle(WQStrings.tabFindings)
        .searchable(text: $vm.searchQuery, prompt: Text(WQStrings.searchPrompt))
    }
}

public struct FilterChip: View {
    public let title: String
    public let isSelected: Bool
    public var color: Color = Color(red: 0.0, green: 0.78, blue: 0.65)
    public let action: () -> Void

    public init(title: String, isSelected: Bool, color: Color = Color(red: 0.0, green: 0.78, blue: 0.65), action: @escaping () -> Void) {
        self.title = title
        self.isSelected = isSelected
        self.color = color
        self.action = action
    }

    public var body: some View {
        Button(action: {
            #if os(iOS)
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            #endif
            action()
        }) {
            Text(title)
                .font(.caption.bold())
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(isSelected ? color : Color.white.opacity(0.08))
                .foregroundColor(isSelected ? .black : .white)
                .clipShape(Capsule())
        }
    }
}
