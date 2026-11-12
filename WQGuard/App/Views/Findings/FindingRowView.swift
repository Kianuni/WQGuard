//
//  FindingRowView.swift
//  WQGuard
//
//  Individual finding list row displaying app metadata and risk tier.
//

import SwiftUI
import WQGuardCore

public struct FindingRowView: View {
    public let finding: ScanFinding

    public init(finding: ScanFinding) {
        self.finding = finding
    }

    public var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(tierColor.opacity(0.15))
                    .frame(width: 44, height: 44)
                Text(finding.displayName.prefix(1))
                    .font(.title3.bold())
                    .foregroundColor(tierColor)
            }

            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(finding.displayName)
                        .font(.subheadline.bold())
                        .foregroundColor(.white)
                    Spacer()
                    RiskBadge(tier: finding.riskTier)
                }

                Text(finding.bundleId)
                    .font(.caption.monospaced())
                    .foregroundColor(.gray)
                    .lineLimit(1)

                HStack(spacing: 6) {
                    InstallChannelBadge(channel: finding.installChannel)
                    AuditDepthBadge(depth: finding.evidence.auditDepth)
                    if !finding.indicators.isEmpty {
                        Text(WQStrings.indicatorCountBadge(finding.indicators.count))
                            .font(.system(size: 10, weight: .bold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.red.opacity(0.2))
                            .foregroundColor(.red)
                            .clipShape(Capsule())
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }

    private var tierColor: Color {
        switch finding.riskTier {
        case .highRisk: return .red
        case .caution: return .orange
        case .knownTool: return .yellow
        case .safe: return .green
        }
    }
}
