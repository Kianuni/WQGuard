//
//  RiskBadge.swift
//  WQGuard
//
//  Color-coded pill badge displaying RiskTier severity.
//

import SwiftUI
import WQGuardCore

public struct RiskBadge: View {
    public let tier: RiskTier

    public init(tier: RiskTier) {
        self.tier = tier
    }

    public var body: some View {
        Text(WQStrings.riskName(tier))
            .font(.system(size: 11, weight: .bold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(badgeColor.opacity(0.2))
            .foregroundColor(badgeColor)
            .clipShape(Capsule())
    }

    private var badgeColor: Color {
        switch tier {
        case .highRisk: return .red
        case .caution: return .orange
        case .knownTool: return .yellow
        case .safe: return .green
        }
    }
}
