//
//  InstalledScanConfigSheet.swift
//  WQGuard
//
//  Configuration center for WQGuard's 3-engine Installed App Security Scanner:
//  1) `installation_proxy` System Registry (LocalDevVPN Pairing Direct or Snapshot Import)
//  2) Multi-Select Local IPA Queue Correlation (Mach-O Binary + Embedded Dylibs + Extensions)
//  3) On-Device URL Scheme Presence Probe
//

import SwiftUI
import UniformTypeIdentifiers
import WQGuardCore

public struct InstalledScanConfigSheet: View {
    @EnvironmentObject var vm: ScanViewModel
    @Environment(\.dismiss) private var dismiss

    private enum TutorialTab: String, CaseIterable, Identifiable {
        case modeB
        case modeA
        case engine2
        var id: String { rawValue }

        var localizedTitle: String {
            switch self {
            case .modeB: return WQStrings.tutorialTabModeB
            case .modeA: return WQStrings.tutorialTabModeA
            case .engine2: return WQStrings.tutorialTabEngine2
            }
        }
    }

    @State private var copiedInstallPyToast = false
    @State private var copiedCommandToast = false
    @State private var copiedDeviceCtlToast = false
    @State private var copiedCdDesktopToast = false
    @State private var copiedTunnelToast = false
    @State private var copiedDeviceToast = false
    @State private var showTutorial = false
    @State private var selectedTutorialTab: TutorialTab = .modeB
    @State private var localBannerText: String? = nil
    @State private var localBannerIsError: Bool = false

    private let cliInstallPyCommand = #"command -v brew >/dev/null 2>&1 && brew install pymobiledevice3 || python3 -m pip install --user -U pymobiledevice3"#
    private var cliExportCommand: String {
        #"(command -v pymobiledevice3 >/dev/null 2>&1 && pymobiledevice3 apps list > ~/Desktop/installed_apps.json || python3 -m pymobiledevice3 apps list > ~/Desktop/installed_apps.json) && echo ""# + WQStrings.cliExportEchoText + #"""#
    }
    private var cliDeviceCtlCommand: String {
        #"ID=$(xcrun devicectl list devices -j - | python3 -c "import sys,json; devs=json.load(sys.stdin).get('result',{}).get('devices',[]); print(next((d['identifier'] for d in devs if 'Simulator' not in str(d)), ''))") && xcrun devicectl device info apps --device "$ID" --include-all-apps --include-app-group-identifiers --include-container-paths --json-output ~/Desktop/installed_apps.json && echo ""# + WQStrings.cliDeviceCtlEchoText + #"""#
    }

    private var subnetDiagnosis: LocalNetworkSubnetDiagnosis {
        LocalNetworkSubnetDiagnosis.inspect(configuredHost: vm.lockdownHost)
    }

    public init() {}

    public var body: some View {
        NavigationStack {
            List {
                if let banner = localBannerText {
                    Section {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: localBannerIsError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                                .foregroundColor(localBannerIsError ? .red : .green)
                            Text(banner)
                                .font(.caption)
                                .foregroundColor(localBannerIsError ? .red : .green)
                        }
                        .padding(.vertical, 4)
                    }
                }

                // Built-in Detailed Step-by-Step Setup & Export Tutorial
                Section {
                    DisclosureGroup(WQStrings.tutorialGroupTitle, isExpanded: $showTutorial) {
                        VStack(alignment: .leading, spacing: 12) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(WQStrings.tutorialIntroHeadline)
                                    .font(.caption.bold())
                                    .foregroundColor(.cyan)
                                Text(WQStrings.tutorialIntroBullets)
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }

                            Picker(WQStrings.tutorialCategoryPicker, selection: $selectedTutorialTab) {
                                ForEach(TutorialTab.allCases) { tab in
                                    Text(tab.localizedTitle).tag(tab)
                                }
                            }
                            .pickerStyle(.segmented)

                            switch selectedTutorialTab {
                            case .modeB:
                                modeBTutorialView
                            case .modeA:
                                modeATutorialView
                            case .engine2:
                                engine2TutorialView
                            }
                        }
                        .padding(.vertical, 6)
                    }
                    .font(.subheadline.bold())
                } header: {
                    Text(WQStrings.tutorialSectionHeader)
                }

                // Engine 1A: LocalDevVPN + Pairing File Direct Connection
                Section {
                    HStack {
                        Image(systemName: vm.hasPairingFile ? "checkmark.seal.fill" : "link.badge.plus")
                            .foregroundColor(vm.hasPairingFile ? .green : .cyan)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(WQStrings.engine1ATitle)
                                .font(.subheadline.bold())
                            Text(vm.pairingHostIDSummary ?? WQStrings.engine1ANoPairingPlaceholder)
                                .font(.caption)
                                .foregroundColor(vm.hasPairingFile ? .green : .gray)
                        }
                    }

                    HStack {
                        Text(WQStrings.engine1AGatewayLabel)
                            .font(.subheadline)
                        Spacer()
                        TextField("10.7.0.1", text: $vm.lockdownHost)
                            .multilineTextAlignment(.trailing)
                            .font(.subheadline.monospaced())
                            .foregroundColor(.teal)
                    }

                    if let wifiIP = subnetDiagnosis.wifiIP,
                       let recTunnel = subnetDiagnosis.recommendedTunnelCIDR,
                       let recDevice = subnetDiagnosis.recommendedDeviceCIDR,
                       let recHost = subnetDiagnosis.recommendedDeviceIP {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(spacing: 6) {
                                Image(systemName: subnetDiagnosis.hasSubnetMismatch ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
                                    .foregroundColor(subnetDiagnosis.hasSubnetMismatch ? .orange : .green)
                                Text(subnetDiagnosis.hasSubnetMismatch
                                     ? WQStrings.engine1ASubnetMismatchTitle(wifiIP: wifiIP)
                                     : WQStrings.engine1ASubnetAlignedTitle(wifiIP: wifiIP))
                                    .font(.caption.bold())
                                    .foregroundColor(subnetDiagnosis.hasSubnetMismatch ? .orange : .green)
                            }
                            Text(WQStrings.engine1ASubnetHint)
                                .font(.caption2)
                                .foregroundColor(.secondary)

                            HStack(spacing: 8) {
                                Button(action: {
                                    #if os(iOS)
                                    UIPasteboard.general.string = recTunnel
                                    #endif
                                    copiedTunnelToast = true
                                }) {
                                    Text(copiedTunnelToast ? WQStrings.engine1ACopiedTunnel : WQStrings.engine1ACopyTunnel(recTunnel))
                                        .font(.caption2.monospaced().bold())
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 5)
                                        .background(Color.cyan.opacity(0.15))
                                        .cornerRadius(6)
                                }
                                .buttonStyle(.plain)

                                Button(action: {
                                    #if os(iOS)
                                    UIPasteboard.general.string = recDevice
                                    #endif
                                    vm.lockdownHost = recHost
                                    copiedDeviceToast = true
                                }) {
                                    Text(copiedDeviceToast ? WQStrings.engine1ACopiedDevice : WQStrings.engine1ACopyDevice(recDevice))
                                        .font(.caption2.monospaced().bold())
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 5)
                                        .background(Color.teal.opacity(0.15))
                                        .cornerRadius(6)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                        .padding(.vertical, 4)
                    }

                    Button(action: { pickPairingFile() }) {
                        Label(
                            vm.hasPairingFile ? WQStrings.engine1AReplacePairing : WQStrings.engine1APickPairing,
                            systemImage: "folder.badge.plus"
                        )
                        .foregroundColor(.cyan)
                    }

                    Button(action: { pastePairingFromClipboard() }) {
                        Label(
                            WQStrings.engine1APastePairing,
                            systemImage: "doc.on.clipboard.fill"
                        )
                        .font(.footnote.bold())
                        .foregroundColor(.mint)
                    }

                    if vm.hasPairingFile {
                        Button(action: {
                            localBannerText = nil
                            vm.testLiveLockdownConnectionAndScan()
                        }) {
                            Label(WQStrings.engine1AConnectAndScan, systemImage: "bolt.shield.fill")
                                .font(.subheadline.bold())
                                .foregroundColor(.teal)
                        }

                        Button(role: .destructive, action: {
                            vm.clearPairingFile()
                            localBannerText = WQStrings.engine1APairingRemoved
                            localBannerIsError = false
                        }) {
                            Label(WQStrings.engine1ARemovePairing, systemImage: "trash")
                        }
                    }
                } header: {
                    Text(WQStrings.engine1AHeader)
                } footer: {
                    Text(WQStrings.engine1AFooter)
                }

                // Engine 1B: Offline Snapshot Import
                Section {
                    HStack {
                        Image(systemName: vm.hasSavedSnapshot ? "doc.badge.gearshape.fill" : "doc.text.magnifyingglass")
                            .foregroundColor(vm.hasSavedSnapshot ? .green : .orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(WQStrings.engine1BTitle)
                                .font(.subheadline.bold())
                            if vm.hasSavedSnapshot {
                                Text(WQStrings.engine1BCachedSnapshot(filename: vm.savedSnapshotFilename ?? "snapshot", count: vm.savedSnapshotAppCount))
                                    .font(.caption)
                                    .foregroundColor(.green)
                            } else {
                                Text(WQStrings.engine1BSupportedFormats)
                                    .font(.caption)
                                    .foregroundColor(.gray)
                            }
                        }
                    }

                    Button(action: { pickSnapshotFile() }) {
                        Label(WQStrings.engine1BSelectSnapshot, systemImage: "arrow.down.doc.fill")
                            .foregroundColor(.orange)
                    }

                    Button(action: {
                        #if os(iOS)
                        UIPasteboard.general.string = cliExportCommand
                        #endif
                        copiedCommandToast = true
                    }) {
                        HStack {
                            Label(WQStrings.engine1BCopyPymobile, systemImage: "terminal.fill")
                                .foregroundColor(.teal)
                            Spacer()
                            if copiedCommandToast {
                                Text(WQStrings.commonCopiedLabel)
                                    .font(.caption.bold())
                                    .foregroundColor(.green)
                            }
                        }
                    }

                    Button(action: {
                        #if os(iOS)
                        UIPasteboard.general.string = cliDeviceCtlCommand
                        #endif
                        copiedDeviceCtlToast = true
                    }) {
                        HStack {
                            Label(WQStrings.engine1BCopyDeviceCtl, systemImage: "apple.terminal.fill")
                            Spacer()
                            if copiedDeviceCtlToast {
                                Text(WQStrings.commonCopiedLabel)
                                    .font(.caption.bold())
                                    .foregroundColor(.green)
                            }
                        }
                    }

                    if vm.hasSavedSnapshot {
                        Button(role: .destructive, action: {
                            vm.clearSavedSnapshot()
                            localBannerText = WQStrings.engine1BSnapshotCleared
                            localBannerIsError = false
                        }) {
                            Label(WQStrings.engine1BClearSnapshot, systemImage: "trash")
                        }
                    }

                    Toggle(WQStrings.engine1BIncludeAppStoreToggle, isOn: $vm.includeAppStoreAppsInRegistry)
                        .font(.subheadline)
                } header: {
                    Text(WQStrings.engine1BHeader)
                } footer: {
                    Text(WQStrings.engine1BFooter)
                }

                // Engine 2: Multi-Select Local IPA Scan Queue & Registry Correlation
                Section {
                    Button(action: { pickSourcePackages() }) {
                        Label(WQStrings.engine2AddIPAButton, systemImage: "doc.badge.plus")
                            .font(.subheadline.bold())
                            .foregroundColor(.teal)
                    }

                    if vm.syncedPackageNames.isEmpty {
                        Text(WQStrings.engine2EmptyQueue)
                            .font(.caption)
                            .foregroundColor(.gray)
                    } else {
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark.seal.fill")
                                .foregroundColor(.green)
                            Text(WQStrings.engine2QueuedSummary(vm.syncedPackageNames.count))
                                .font(.caption.bold())
                                .foregroundColor(.green)
                        }

                        ForEach(vm.syncedPackageNames, id: \.self) { pkgName in
                            HStack(spacing: 10) {
                                Image(systemName: "doc.zipper")
                                    .foregroundColor(.teal)
                                    .font(.caption)
                                Text(pkgName)
                                    .font(.caption.monospaced())
                                    .lineLimit(1)
                                Spacer()
                                Button(action: {
                                    vm.removeSyncedPackage(named: pkgName)
                                }) {
                                    Image(systemName: "minus.circle.fill")
                                        .foregroundColor(.red.opacity(0.85))
                                }
                                .buttonStyle(.plain)
                            }
                        }
                        .onDelete { indexSet in
                            let currentNames = vm.syncedPackageNames
                            for idx in indexSet where idx < currentNames.count {
                                vm.removeSyncedPackage(named: currentNames[idx])
                            }
                        }

                        Button(role: .destructive, action: {
                            vm.clearSyncedPackages()
                            localBannerText = WQStrings.engine2ClearedBanner
                            localBannerIsError = false
                        }) {
                            Label(WQStrings.engine2ClearAllButton, systemImage: "trash")
                        }
                    }
                } header: {
                    Text(WQStrings.engine2Header)
                } footer: {
                    Text(WQStrings.engine2Footer)
                }

                // Engine 3: On-Device URL Scheme Probe
                Section {
                    Toggle(WQStrings.engine3Toggle, isOn: $vm.enableOnDeviceProbe)
                        .font(.subheadline)
                } header: {
                    Text(WQStrings.engine3Header)
                } footer: {
                    Text(WQStrings.engine3Footer)
                }
            }
            .navigationTitle(WQStrings.scanConfigNavTitle)
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(WQStrings.buttonDone) {
                        dismiss()
                    }
                }
            }
            .onAppear {
                if !vm.hasPairingFile && !vm.hasSavedSnapshot {
                    showTutorial = true
                }
                if let autoMsg = vm.autoImportFromDocumentsFolderIfNeeded() {
                    localBannerIsError = false
                    localBannerText = autoMsg
                }
            }
        }
    }

    // MARK: - Step-by-Step Tutorial Subviews

    private var modeBTutorialView: some View {
        VStack(alignment: .leading, spacing: 10) {
            tutorialStepCard(
                badge: WQStrings.tutStep1Badge,
                title: WQStrings.tutModeBStep1Title,
                color: .teal,
                detail: WQStrings.tutModeBStep1Detail
            )
            inlineCopyButton(
                title: copiedInstallPyToast ? WQStrings.tutModeBInstallCopied : WQStrings.tutModeBInstallCopyBtn,
                color: .teal
            ) {
                #if os(iOS)
                UIPasteboard.general.string = cliInstallPyCommand
                #endif
                copiedInstallPyToast = true
            }

            Divider()

            tutorialStepCard(
                badge: WQStrings.tutStep2Badge,
                title: WQStrings.tutModeBStep2Title,
                color: .cyan,
                detail: WQStrings.tutModeBStep2Detail
            )

            Divider()

            tutorialStepCard(
                badge: WQStrings.tutStep3Badge,
                title: WQStrings.tutModeBStep3Title,
                color: .orange,
                detail: WQStrings.tutModeBStep3Detail
            )
            inlineCopyButton(
                title: copiedCommandToast ? WQStrings.tutModeBExportCopied : WQStrings.tutModeBExportCopyBtn,
                color: .orange
            ) {
                #if os(iOS)
                UIPasteboard.general.string = cliExportCommand
                #endif
                copiedCommandToast = true
            }

            Divider()

            tutorialStepCard(
                badge: WQStrings.tutStep4Badge,
                title: WQStrings.tutModeBStep4Title,
                color: .green,
                detail: WQStrings.tutModeBStep4Detail
            )
        }
    }

    private var modeATutorialView: some View {
        VStack(alignment: .leading, spacing: 10) {
            tutorialStepCard(
                badge: WQStrings.tutStep1Badge,
                title: WQStrings.tutModeAStep1Title,
                color: .cyan,
                detail: WQStrings.tutModeAStep1Detail
            )

            Divider()

            tutorialStepCard(
                badge: WQStrings.tutStep2Badge,
                title: WQStrings.tutModeAStep2Title,
                color: .teal,
                detail: WQStrings.tutModeAStep2Detail
            )
            inlineCopyButton(
                title: copiedCdDesktopToast ? WQStrings.tutModeACdCopied : WQStrings.tutModeACdCopyBtn,
                color: .teal
            ) {
                #if os(iOS)
                UIPasteboard.general.string = "cd ~/Desktop"
                #endif
                copiedCdDesktopToast = true
            }

            Divider()

            tutorialStepCard(
                badge: WQStrings.tutStep3Badge,
                title: WQStrings.tutModeAStep3Title,
                color: .orange,
                detail: WQStrings.tutModeAStep3Detail
            )

            Divider()

            tutorialStepCard(
                badge: WQStrings.tutStep4Badge,
                title: WQStrings.tutModeAStep4Title,
                color: .green,
                detail: WQStrings.tutModeAStep4Detail
            )
        }
    }

    private var engine2TutorialView: some View {
        VStack(alignment: .leading, spacing: 10) {
            tutorialStepCard(
                badge: WQStrings.tutOverviewBadge,
                title: WQStrings.tutEngine2OverviewTitle,
                color: .cyan,
                detail: WQStrings.tutEngine2OverviewDetail
            )

            Divider()

            tutorialStepCard(
                badge: WQStrings.tutMethod1Badge,
                title: WQStrings.tutEngine2Method1Title,
                color: .teal,
                detail: WQStrings.tutEngine2Method1Detail
            )

            Divider()

            tutorialStepCard(
                badge: WQStrings.tutMethod2Badge,
                title: WQStrings.tutEngine2Method2Title,
                color: .orange,
                detail: WQStrings.tutEngine2Method2Detail
            )
        }
    }

    private func tutorialStepCard(badge: String, title: String, color: Color, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .center, spacing: 6) {
                Text(badge)
                    .font(.caption2.bold())
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(color)
                    .cornerRadius(4)
                Text(title)
                    .font(.caption.bold())
                    .foregroundColor(.primary)
            }
            Text(detail)
                .font(.caption2)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func inlineCopyButton(title: String, color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Text(title)
                    .font(.caption2.bold())
                    .foregroundColor(color)
                Spacer()
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(color.opacity(0.12))
            .cornerRadius(6)
        }
        .buttonStyle(.plain)
    }

    private func pastePairingFromClipboard() {
        switch vm.importPairingFromClipboardWithResult() {
        case .success(let summary):
            localBannerIsError = false
            localBannerText = WQStrings.bannerClipboardPairingScanning(summary)
            vm.testLiveLockdownConnectionAndScan()
        case .failure(let err):
            localBannerIsError = true
            localBannerText = err.localizedDescription
        }
    }

    private func pickPairingFile() {
        #if canImport(UIKit)
        NativeDocumentPickerPresenter.shared.present(kind: .pairingFile) { urls in
            guard let first = urls.first else { return }
            let result = vm.importPairingFileWithResult(from: first)
            switch result {
            case .success(let summary):
                localBannerIsError = false
                localBannerText = WQStrings.bannerFilePairingScanning(summary)
                vm.testLiveLockdownConnectionAndScan()
            case .failure(let err):
                localBannerIsError = true
                localBannerText = err.localizedDescription
            }
        }
        #endif
    }

    private func pickSnapshotFile() {
        #if canImport(UIKit)
        NativeDocumentPickerPresenter.shared.present(kind: .registrySnapshot) { urls in
            guard let first = urls.first else { return }
            let result = vm.importRegistrySnapshotWithResult(from: first, autoScan: true)
            switch result {
            case .success(let msg):
                localBannerIsError = false
                localBannerText = msg
            case .failure(let err):
                localBannerIsError = true
                localBannerText = err.localizedDescription
            }
        }
        #endif
    }

    private func pickSourcePackages() {
        #if canImport(UIKit)
        NativeDocumentPickerPresenter.shared.present(kind: .ipaFiles) { urls in
            vm.scanMultipleIPAPackages(at: urls, correlateWithInstalled: true)
            if !vm.syncedPackageNames.isEmpty {
                localBannerIsError = false
                localBannerText = WQStrings.bannerQueuedIPAsScanning(vm.syncedPackageNames.count)
            }
        }
        #endif
    }
}
