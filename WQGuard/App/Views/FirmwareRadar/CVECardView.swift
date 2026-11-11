//
//  CVECardView.swift
//  WQGuard
//
//  Displays individual firmware vulnerability status, CVSS score, and affected versions.
//

import SwiftUI
import WQGuardCore

public struct CVECardView: View {
    public let vuln: FirmwareVulnerability
    public let isExposed: Bool

    public init(vuln: FirmwareVulnerability, isExposed: Bool) {
        self.vuln = vuln
        self.isExposed = isExposed
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(vuln.cveId.rawValue)
                    .font(.caption.bold().monospaced())
                    .foregroundColor(isExposed ? .red : .green)

                Spacer()
                Text(isExposed ? WQStrings.cveStatusExposed : WQStrings.cveStatusPatched)
                    .font(.caption2.bold())
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background((isExposed ? Color.red : Color.green).opacity(0.15))
                    .foregroundColor(isExposed ? .red : .green)
                    .clipShape(Capsule())
            }

            Text(vuln.name)
                .font(.subheadline.bold())
                .foregroundColor(.white)

            Text(vuln.details)
                .font(.caption)
                .foregroundColor(.gray)

            HStack {
                Text(WQStrings.cveAffectedVersions(vuln.affectedDescription))
                    .font(.caption2)
                    .foregroundColor(.gray)
                Spacer()
                if let score = vuln.cvssScore {
                    Text("CVSS \(String(format: "%.1f", score))")
                        .font(.caption2.bold())
                        .foregroundColor(score >= 9.0 ? .red : (score >= 7.0 ? .orange : .yellow))
                }
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
        )
    }
}
