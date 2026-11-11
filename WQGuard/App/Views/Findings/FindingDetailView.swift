//
//  FindingDetailView.swift
//  WQGuard
//
//  Detailed audit inspection view showing symbols, entitlements, and actionable remediation.
//

import SwiftUI
import WQGuardCore

public struct FindingDetailView: View {
    public let finding: ScanFinding
    @EnvironmentObject var vm: ScanViewModel
    @State private var showAddedToast = false

    public init(finding: ScanFinding) {
        self.finding = finding
    }

    public var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Header Card
                VStack(spacing: 8) {
                    ZStack {
                        Circle()
                            .fill(tierColor.opacity(0.15))
                            .frame(width: 64, height: 64)
                        Image(systemName: iconName)
                            .font(.system(size: 28, weight: .bold))
                            .foregroundColor(tierColor)
                    }

                    Text(finding.displayName)
                        .font(.title2.bold())
                        .foregroundColor(.white)

                    Text(finding.bundleId)
                        .font(.caption.monospaced())
                        .foregroundColor(.gray)

                    HStack(spacing: 8) {
                        RiskBadge(tier: finding.riskTier)
                        InstallChannelBadge(channel: finding.installChannel)
                        if finding.isWhitelisted {
                            Text(WQStrings.whitelistedBadge)
                                .font(.caption.bold())
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(Color.yellow.opacity(0.2))
                                .foregroundColor(.yellow)
                                .clipShape(Capsule())
                        }
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(
                    RoundedRectangle(cornerRadius: 18)
                        .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                )
                .padding(.horizontal)

                // Actionable Remediation Card
                RemediationCardView(finding: finding)
                    .padding(.horizontal)

                // Matched Threat Indicators
                if !finding.indicators.isEmpty {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(WQStrings.threatIndicatorsHeader(finding.indicators.count))
                            .font(.headline)
                            .foregroundColor(.white)
                            .padding(.horizontal)

                        ForEach(finding.indicators) { ind in
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text(ind.signature)
                                        .font(.subheadline.bold().monospaced())
                                        .foregroundColor(ind.severity == .highRisk ? .red : .orange)
                                    Spacer()
                                    Text(ind.category)
                                        .font(.caption.bold())
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.white.opacity(0.1))
                                        .clipShape(Capsule())
                                }

                                Text(ind.description)
                                    .font(.caption)
                                    .foregroundColor(.white.opacity(0.85))

                                Text(WQStrings.indicatorLocation(ind.location))
                                    .font(.caption2.monospaced())
                                    .foregroundColor(.gray)
                            }
                            .padding(14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(
                                RoundedRectangle(cornerRadius: 14)
                                    .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                            )
                            .padding(.horizontal)
                        }
                    }
                }

                // Audit Evidence Breakdown
                VStack(alignment: .leading, spacing: 10) {
                    Text(WQStrings.staticAuditEvidenceHeader)
                        .font(.headline)
                        .foregroundColor(.white)
                        .padding(.horizontal)

                    VStack(alignment: .leading, spacing: 12) {
                        EvidenceRow(label: WQStrings.evidenceVersion, value: finding.version)
                        EvidenceRow(label: WQStrings.evidenceTeamId, value: finding.teamId ?? WQStrings.evidenceTeamIdUnsigned)
                        EvidenceRow(label: WQStrings.evidenceDrmStatus, value: finding.evidence.isFairPlayEncrypted ? WQStrings.evidenceDrmEncrypted : WQStrings.evidenceDrmUnencrypted)
                        EvidenceRow(label: WQStrings.evidenceAppGroups, value: finding.evidence.appGroups.isEmpty ? WQStrings.evidenceAppGroupsNone : finding.evidence.appGroups.joined(separator: ", "))
                        EvidenceRow(label: WQStrings.evidencePrivateSymbols, value: finding.evidence.matchedSymbols.isEmpty ? WQStrings.evidenceNone : finding.evidence.matchedSymbols.joined(separator: ", "))
                        EvidenceRow(label: WQStrings.evidenceDynamicLoading, value: finding.evidence.dynamicLoadingPresent ? WQStrings.evidenceDetectedDlopen : WQStrings.evidenceNone)
                        EvidenceRow(label: WQStrings.evidencePathEnumeration, value: finding.evidence.pathEnumerationPresent ? WQStrings.evidenceDetectedFsgetpath : WQStrings.evidenceNone)
                        EvidenceRow(label: WQStrings.evidenceInstallPath, value: finding.bundlePath)
                    }
                    .padding(16)
                    .background(
                        RoundedRectangle(cornerRadius: 16)
                            .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                    )
                    .padding(.horizontal)
                }

                // Whitelist Action Button
                if !finding.isWhitelisted {
                    Button(action: {
                        vm.addCustomWhitelistRule(bundleId: finding.bundleId, name: finding.displayName)
                        showAddedToast = true
                    }) {
                        Label(WQStrings.addToWhitelistButton, systemImage: "checkmark.shield")
                            .font(.subheadline.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(Color.yellow.opacity(0.15))
                            .foregroundColor(.yellow)
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                    }
                    .padding(.horizontal)
                }
            }
            .padding(.vertical, 16)
        }
        .navigationTitle(finding.displayName)
        .alert(WQStrings.whitelistAddedTitle, isPresented: $showAddedToast) {
            Button(WQStrings.buttonOK, role: .cancel) {}
        } message: {
            Text(WQStrings.whitelistAddedMessage(appName: finding.displayName))
        }
    }

    private var tierColor: Color {
        switch finding.riskTier {
        case .highRisk: return .red
        case .caution: return .orange
        case .knownTool: return .yellow
        case .safe: return .green
        }
    }

    private var iconName: String {
        switch finding.riskTier {
        case .highRisk: return "exclamationmark.shield.fill"
        case .caution: return "shield.lefthalf.filled.badge.alert"
        case .knownTool: return "wrench.and.screwdriver.fill"
        case .safe: return "checkmark.shield.fill"
        }
    }
}

public struct EvidenceRow: View {
    public let label: String
    public let value: String

    public init(label: String, value: String) {
        self.label = label
        self.value = value
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundColor(.gray)
            Text(value)
                .font(.subheadline.monospaced())
                .foregroundColor(.white)
        }
    }
}
