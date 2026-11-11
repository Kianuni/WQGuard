//
//  MetricGridCard.swift
//  WQGuard
//
//  Grid tile displaying category counts with quick-filter navigation.
//

import SwiftUI
import WQGuardCore

public struct MetricGridCard: View {
    public let title: String
    public let count: Int
    public let icon: String
    public let color: Color

    public init(title: String, count: Int, icon: String, color: Color) {
        self.title = title
        self.count = count
        self.icon = icon
        self.color = color
    }

    public var body: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(color.opacity(0.15))
                    .frame(width: 44, height: 44)
                Image(systemName: icon)
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundColor(color)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text("\(count)")
                    .font(.title2.bold().monospacedDigit())
                    .foregroundColor(.white)
                Text(title)
                    .font(.caption)
                    .foregroundColor(.gray)
            }
            Spacer()
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
        )
    }
}

public struct QuickActionRow: View {
    public let title: String
    public let subtitle: String
    public let icon: String
    public let color: Color

    public init(title: String, subtitle: String, icon: String, color: Color) {
        self.title = title
        self.subtitle = subtitle
        self.icon = icon
        self.color = color
    }

    public var body: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle()
                    .fill(color.opacity(0.15))
                    .frame(width: 42, height: 42)
                Image(systemName: icon)
                    .foregroundColor(color)
                    .font(.system(size: 18, weight: .bold))
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.bold())
                    .foregroundColor(.white)
                Text(subtitle)
                    .font(.caption)
                    .foregroundColor(.gray)
                    .lineLimit(1)
            }

            Spacer()
            Image(systemName: "chevron.right")
                .font(.caption.bold())
                .foregroundColor(.gray)
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
        )
    }
}

public struct ScanProgressBar: View {
    public let progress: ScanProgress?

    public init(progress: ScanProgress?) {
        self.progress = progress
    }

    public var body: some View {
        VStack(spacing: 8) {
            ProgressView(value: progress?.fractionCompleted ?? 0.0)
                .tint(Color(red: 0.0, green: 0.78, blue: 0.65))

            HStack {
                Text(progress?.currentTarget ?? WQStrings.scanPreparing)
                    .font(.caption.monospaced())
                    .foregroundColor(.gray)
                    .lineLimit(1)
                Spacer()
                Text("\(progress?.completedCount ?? 0) / \(progress?.totalCount ?? 0)")
                    .font(.caption.bold().monospacedDigit())
                    .foregroundColor(.primary)
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
        )
    }
}
