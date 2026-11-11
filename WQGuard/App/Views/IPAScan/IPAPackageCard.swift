//
//  IPAPackageCard.swift
//  WQGuard
//
//  Inspected IPA metadata & pre-install risk card.
//

import SwiftUI
import WQGuardCore

public struct IPAPackageCard: View {
    public let finding: ScanFinding

    public init(finding: ScanFinding) {
        self.finding = finding
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(finding.displayName)
                        .font(.title2.bold())
                        .foregroundColor(.white)
                    Text(finding.bundleId)
                        .font(.caption.monospaced())
                        .foregroundColor(.gray)
                }
                Spacer()
                RiskBadge(tier: finding.riskTier)
            }

            Divider().background(Color.white.opacity(0.15))

            // Pre-install advisory banner
            HStack(spacing: 10) {
                Image(systemName: finding.riskTier == .highRisk ? "xmark.octagon.fill" : "checkmark.seal.fill")
                    .foregroundColor(finding.riskTier == .highRisk ? .red : .green)
                    .font(.title3)

                Text(finding.riskTier == .highRisk ? WQStrings.preinstallAlertHighRisk : WQStrings.preinstallAlertSafe)
                    .font(.subheadline.bold())
                    .foregroundColor(finding.riskTier == .highRisk ? .red : .green)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background((finding.riskTier == .highRisk ? Color.red : Color.green).opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 12))

            // Details Grid
            VStack(alignment: .leading, spacing: 10) {
                EvidenceRow(label: WQStrings.ipaDistributionChannel, value: WQStrings.channelName(finding.installChannel))
                EvidenceRow(label: WQStrings.evidenceTeamId, value: finding.teamId ?? WQStrings.ipaTeamIdSelfSigned)
                EvidenceRow(label: WQStrings.evidenceDrmStatus, value: finding.evidence.isFairPlayEncrypted ? WQStrings.ipaDrmEncrypted : WQStrings.ipaDrmUnencrypted)
                EvidenceRow(label: WQStrings.ipaDeclaredAppGroups, value: finding.evidence.appGroups.isEmpty ? WQStrings.ipaAppGroupsNone : finding.evidence.appGroups.joined(separator: ", "))
                if !finding.evidence.linkedDylibs.isEmpty {
                    EvidenceRow(label: WQStrings.ipaDylibCountLabel, value: WQStrings.ipaDylibCountValue(finding.evidence.linkedDylibs.count))
                }
            }

            // Injected Dylibs View
            if !finding.evidence.linkedDylibs.isEmpty {
                InjectedDylibsView(dylibs: finding.evidence.linkedDylibs)
            }

            // Indicators
            if !finding.indicators.isEmpty {
                Divider().background(Color.white.opacity(0.15))
                Text(WQStrings.ipaDetectedIndicatorsHeader(finding.indicators.count))
                    .font(.caption.bold())
                    .foregroundColor(.gray)

                ForEach(finding.indicators) { ind in
                    HStack {
                        Text("• [\(ind.severity.rawValue)] \(ind.signature)")
                            .font(.caption.bold().monospaced())
                            .foregroundColor(ind.severity == .highRisk ? .red : .orange)
                        Spacer()
                    }
                }
            }
        }
        .padding(18)
        .background(
            RoundedRectangle(cornerRadius: 18)
                .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
        )
    }
}
