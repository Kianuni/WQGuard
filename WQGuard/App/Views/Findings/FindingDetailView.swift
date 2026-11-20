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
    @State private var showRejectedAlert = false
    @State private var whitelistErrorMessage: String = ""

    public init(finding: ScanFinding) {
        self.finding = finding
    }

    private var activeFinding: ScanFinding {
        vm.currentSession?.findings.first(where: { $0.id == finding.id }) ?? finding
    }

    private var canOfferWhitelistAction: Bool {
        !activeFinding.isWhitelisted
            && activeFinding.riskTier == .caution
            && activeFinding.evidence.isWhitelistEligible
            && activeFinding.evidence.escapingSymlinks.isEmpty
            && activeFinding.evidence.auditDepth != .onDeviceProbe
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

                    Text(activeFinding.displayName)
                        .font(.title2.bold())
                        .foregroundColor(.white)

                    Text(activeFinding.bundleId)
                        .font(.caption.monospaced())
                        .foregroundColor(.gray)

                    HStack(spacing: 8) {
                        RiskBadge(tier: activeFinding.riskTier)
                        InstallChannelBadge(channel: activeFinding.installChannel)
                        AuditDepthBadge(depth: activeFinding.evidence.auditDepth)
                        if activeFinding.isWhitelisted {
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
                RemediationCardView(finding: activeFinding)
                    .padding(.horizontal)

                // Matched Threat Indicators
                if !activeFinding.indicators.isEmpty {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(WQStrings.threatIndicatorsHeader(activeFinding.indicators.count))
                            .font(.headline)
                            .foregroundColor(.white)
                            .padding(.horizontal)

                        ForEach(activeFinding.indicators) { ind in
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
                        EvidenceRow(label: WQStrings.evidenceAuditDepth, value: WQStrings.auditDepthFullDesc(activeFinding.evidence.auditDepth))
                        if let signer = activeFinding.evidence.signerIdentity, !signer.isEmpty {
                            EvidenceRow(label: WQStrings.evidenceSignerIdentity, value: signer)
                        }
                        EvidenceRow(label: WQStrings.evidenceVersion, value: activeFinding.version)
                        EvidenceRow(label: WQStrings.evidenceTeamId, value: activeFinding.teamId ?? WQStrings.evidenceTeamIdUnsigned)
                        EvidenceRow(label: WQStrings.evidenceDrmStatus, value: activeFinding.evidence.isFairPlayEncrypted ? WQStrings.evidenceDrmEncrypted : WQStrings.evidenceDrmUnencrypted)
                        EvidenceRow(label: WQStrings.evidenceAppGroups, value: activeFinding.evidence.appGroups.isEmpty ? WQStrings.evidenceAppGroupsNone : activeFinding.evidence.appGroups.joined(separator: ", "))
                        EvidenceRow(label: WQStrings.evidencePrivateSymbols, value: activeFinding.evidence.matchedSymbols.isEmpty ? WQStrings.evidenceNone : activeFinding.evidence.matchedSymbols.joined(separator: ", "))
                        EvidenceRow(label: WQStrings.evidenceDynamicLoading, value: activeFinding.evidence.dynamicLoadingPresent ? WQStrings.evidenceDetectedDlopen : WQStrings.evidenceNone)
                        EvidenceRow(label: WQStrings.evidencePathEnumeration, value: activeFinding.evidence.pathEnumerationPresent ? WQStrings.evidenceDetectedFsgetpath : WQStrings.evidenceNone)
                        EvidenceRow(label: WQStrings.evidenceInstallPath, value: activeFinding.bundlePath)
                    }
                    .padding(16)
                    .background(
                        RoundedRectangle(cornerRadius: 16)
                            .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
                    )
                    .padding(.horizontal)
                }

                // Anchored Whitelist Action Button (strictly hidden on .highRisk, ineligible, escaping symlink, or probe-only findings)
                if canOfferWhitelistAction {
                    Button(action: {
                        let verifiedTeamIds: [String]? = activeFinding.evidence.isTeamIdWhitelistVerified
                            ? activeFinding.teamId.map { [$0] }
                            : nil
                        let correlatedBids: [String] = {
                            guard let corr = activeFinding.evidence.correlatedPackageBundleId?
                                .trimmingCharacters(in: .whitespacesAndNewlines),
                                  !corr.isEmpty,
                                  corr.caseInsensitiveCompare(activeFinding.bundleId) != .orderedSame else {
                                return []
                            }
                            return [corr]
                        }()
                        let result = vm.addCustomWhitelistRule(
                            bundleId: activeFinding.bundleId,
                            additionalBundleIds: correlatedBids,
                            name: activeFinding.displayName,
                            allowedAppGroups: activeFinding.evidence.appGroups,
                            allowedTeamIds: verifiedTeamIds,
                            expectedSignatures: activeFinding.evidence.matchedSymbols,
                            requiringPromotionForFinding: activeFinding
                        )
                        if result.success, activeFinding.isWhitelisted {
                            showAddedToast = true
                        } else {
                            whitelistErrorMessage = result.errorMessage ?? WQStrings.whitelistRejectedFallback
                            showRejectedAlert = true
                        }
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
        .navigationTitle(activeFinding.displayName)
        .alert(WQStrings.whitelistAddedTitle, isPresented: $showAddedToast) {
            Button(WQStrings.buttonOK, role: .cancel) {}
        } message: {
            Text(WQStrings.whitelistAddedMessage(appName: activeFinding.displayName))
        }
        .alert(WQStrings.whitelistRejectedTitle, isPresented: $showRejectedAlert) {
            Button(WQStrings.buttonOK, role: .cancel) {}
        } message: {
            Text(whitelistErrorMessage)
        }
    }

    private var tierColor: Color {
        switch activeFinding.riskTier {
        case .highRisk: return .red
        case .caution: return .orange
        case .knownTool: return .yellow
        case .safe: return .green
        }
    }

    private var iconName: String {
        switch activeFinding.riskTier {
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
