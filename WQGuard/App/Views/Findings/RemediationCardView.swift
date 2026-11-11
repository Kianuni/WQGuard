//
//  RemediationCardView.swift
//  WQGuard
//
//  Displays actionable remediation guidance and emergency mitigation flows.
//

import SwiftUI
import WQGuardCore

public struct RemediationCardView: View {
    public let finding: ScanFinding

    public init(finding: ScanFinding) {
        self.finding = finding
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundColor(finding.riskTier == .highRisk ? .red : .teal)
                Text(WQStrings.remediationGuidanceTitle)
                    .font(.headline)
                    .foregroundColor(.white)
            }

            Text(finding.evidence.remediationGuidance.isEmpty ? WQStrings.riskDesc(finding.riskTier) : finding.evidence.remediationGuidance)
                .font(.subheadline)
                .foregroundColor(.white.opacity(0.9))

            if finding.riskTier == .highRisk {
                Divider().background(Color.white.opacity(0.15))
                VStack(alignment: .leading, spacing: 6) {
                    Text(WQStrings.emergencyWorkflowTitle)
                        .font(.caption.bold())
                        .foregroundColor(.red)
                    Text(WQStrings.emergencyStep1)
                        .font(.caption)
                    Text(WQStrings.emergencyStep2)
                        .font(.caption)
                    Text(WQStrings.emergencyStep3)
                        .font(.caption)
                }
                .foregroundColor(.white.opacity(0.8))
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(finding.riskTier == .highRisk ? Color.red.opacity(0.12) : Color.teal.opacity(0.12))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(finding.riskTier == .highRisk ? Color.red.opacity(0.3) : Color.teal.opacity(0.3), lineWidth: 1)
                )
        )
    }
}
