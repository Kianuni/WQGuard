//
//  MitigationRowView.swift
//  WQGuard
//
//  Non-upgrade mitigation step card with configuration action button.
//

import SwiftUI
import WQGuardCore

public struct MitigationRowView: View {
    public let mitigation: ActionableMitigation

    public init(mitigation: ActionableMitigation) {
        self.mitigation = mitigation
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(categoryEmoji(mitigation.category))
                Text(mitigation.title)
                    .font(.subheadline.bold())
                    .foregroundColor(.white)
                Spacer()
                Text(mitigation.category.rawValue)
                    .font(.system(size: 9, weight: .bold))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.white.opacity(0.1))
                    .foregroundColor(.gray)
                    .clipShape(Capsule())
            }

            Text(mitigation.instructions)
                .font(.caption)
                .foregroundColor(.white.opacity(0.85))

            if let urlStr = mitigation.actionUrl, let url = URL(string: urlStr) {
                Button(action: {
                    #if os(iOS)
                    UIApplication.shared.open(url)
                    #endif
                }) {
                    Text(WQStrings.mitigationConfigureButton)
                        .font(.caption.bold())
                        .foregroundColor(.teal)
                }
                .padding(.top, 2)
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
        )
    }

    private func categoryEmoji(_ cat: MitigationCategory) -> String {
        switch cat {
        case .networkProxy: return "🌐"
        case .systemSettings: return "⚙️"
        case .appHygiene: return "🧹"
        case .wqguardScan: return "🛡️"
        }
    }
}
