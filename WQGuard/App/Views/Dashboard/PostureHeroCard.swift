//
//  PostureHeroCard.swift
//  WQGuard
//
//  Dynamic color-coded status card displaying global device posture.
//

import SwiftUI
import WQGuardCore

public struct PostureHeroCard: View {
    public let posture: RiskTier
    public let isScanning: Bool
    public let progress: ScanProgress?

    public init(posture: RiskTier, isScanning: Bool, progress: ScanProgress?) {
        self.posture = posture
        self.isScanning = isScanning
        self.progress = progress
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                ZStack {
                    Circle()
                        .fill(cardColor.opacity(0.2))
                        .frame(width: 54, height: 54)

                    Image(systemName: iconName)
                        .font(.system(size: 26, weight: .bold))
                        .foregroundColor(cardColor)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text(titleText)
                        .font(.title2.bold())
                        .foregroundColor(.white)

                    Text(subtitleText)
                        .font(.caption)
                        .foregroundColor(.gray)
                        .lineLimit(2)
                }
                Spacer()
            }

            if isScanning, let p = progress {
                Divider().background(Color.white.opacity(0.15))
                HStack {
                    Text(WQStrings.postureDeepAnalyzing)
                        .font(.caption.bold())
                        .foregroundColor(.gray)
                    Text(p.currentTarget)
                        .font(.caption.monospaced())
                        .foregroundColor(.white)
                        .lineLimit(1)
                    Spacer()
                    Text(p.percentageString)
                        .font(.caption.bold())
                        .foregroundColor(Color(red: 0.0, green: 0.78, blue: 0.65))
                }
            }
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 22)
                .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                .overlay(
                    RoundedRectangle(cornerRadius: 22)
                        .stroke(cardColor.opacity(0.35), lineWidth: 1.5)
                )
        )
        .padding(.horizontal)
    }

    private var cardColor: Color {
        if isScanning { return Color(red: 0.0, green: 0.78, blue: 0.65) }
        switch posture {
        case .highRisk: return Color.red
        case .caution: return Color.orange
        case .knownTool: return Color.yellow
        case .safe: return Color.green
        }
    }

    private var iconName: String {
        if isScanning { return "rays" }
        switch posture {
        case .highRisk: return "exclamationmark.shield.fill"
        case .caution: return "shield.lefthalf.filled.badge.alert"
        case .knownTool: return "checkmark.shield.badge.questionmark.fill"
        case .safe: return "checkmark.shield.fill"
        }
    }

    private var titleText: String {
        WQStrings.postureTitle(for: posture, isScanning: isScanning)
    }

    private var subtitleText: String {
        WQStrings.postureSubtitle(for: posture, isScanning: isScanning)
    }
}
