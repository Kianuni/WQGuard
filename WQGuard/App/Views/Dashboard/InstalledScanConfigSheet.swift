//
//  InstalledScanConfigSheet.swift
//  WQGuard
//
//  Configuration center for WQGuard's 3-engine Installed App Security Scanner:
//  1) `installation_proxy` System Registry (LocalDevVPN Pairing Direct or Snapshot Import)
//  2) Bound Signer Folder Correlation (Mach-O Binary + Embedded Dylibs)
//  3) On-Device URL Scheme Presence Probe
//

import SwiftUI
import UniformTypeIdentifiers
import WQGuardCore

public struct InstalledScanConfigSheet: View {
    @EnvironmentObject var vm: ScanViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var copiedCommandToast = false
    @State private var copiedDeviceCtlToast = false
    @State private var copiedTunnelToast = false
    @State private var copiedDeviceToast = false
    @State private var showTutorial = false
    @State private var localBannerText: String? = nil
    @State private var localBannerIsError: Bool = false

    private let cliDeviceCtlCommand = #"ID=$(xcrun devicectl list devices -j - | python3 -c "import sys,json; devs=json.load(sys.stdin).get('result',{}).get('devices',[]); print(next((d['identifier'] for d in devs if 'Simulator' not in str(d)), ''))") && xcrun devicectl device info apps --device "$ID" --include-all-apps --include-app-group-identifiers --include-container-paths --json-output ~/Desktop/installed_apps.json && echo "✅ 已导出 ~/Desktop/installed_apps.json""#
    private let cliExportCommand = "pymobiledevice3 apps list > installed_apps.json"

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

                // Built-in Quick Setup Guide
                Section {
                    DisclosureGroup("📖 开启教程：方式 A / 方式 B 二选一即可", isExpanded: $showTutorial) {
                        VStack(alignment: .leading, spacing: 10) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("① 方式 A 与 方式 B 需要同时开吗？")
                                    .font(.caption.bold())
                                    .foregroundColor(.cyan)
                                Text("**不需要，二选一即可！** 两者读取的都是 iOS 官方 `installation_proxy` 全机已安装应用注册表。推荐**方式 A**（导入配对 `.plist` / `.mobiledevicepairing` + 开启 **LocalDevVPN** 后，以后在手机上随时一键无线直连扫描全机）。")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }

                            Divider()

                            VStack(alignment: .leading, spacing: 3) {
                                Text("② 绑定 Feather / 全能签子目录（联动深扫二进制）")
                                    .font(.caption.bold())
                                    .foregroundColor(.orange)
                                Text("进入『我的 iPhone → Feather → Signed』（或全能签子文件夹），直接点击右上角「打开」即可绑定。")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }

                            Divider()

                            VStack(alignment: .leading, spacing: 3) {
                                Text("③ 方式 B（不想开 VPN 时：电脑导出离线快照）")
                                    .font(.caption.bold())
                                    .foregroundColor(.teal)
                                Text("手机连电脑执行 `pip3 install pymobiledevice3` 后运行下方复制的命令生成 `installed_apps.json`，发到手机导入即可。")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .font(.subheadline.bold())
                }

                // Engine 1A: LocalDevVPN + Pairing File Direct Connection
                Section {
                    HStack {
                        Image(systemName: vm.hasPairingFile ? "checkmark.seal.fill" : "link.badge.plus")
                            .foregroundColor(vm.hasPairingFile ? .green : .cyan)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("方式 A：LocalDevVPN 配对直连本机注册表")
                                .font(.subheadline.bold())
                            Text(vm.pairingHostIDSummary ?? "未导入配对文件（支持 .plist / .mobiledevicepairing 配对文件）")
                                .font(.caption)
                                .foregroundColor(vm.hasPairingFile ? .green : .gray)
                        }
                    }

                    HStack {
                        Text("环回网关地址")
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
                                     ? "iOS 26.4+ / 27 子网校验提示（当前 Wi-Fi: \(wifiIP)）"
                                     : "已对齐当前 Wi-Fi 同网段（\(wifiIP)）")
                                    .font(.caption.bold())
                                    .foregroundColor(subnetDiagnosis.hasSubnetMismatch ? .orange : .green)
                            }
                            Text("新系统 lockdownd 会拦截不在当前 Wi-Fi 网段内的 10.7.0.x 隧道。若直连报 EOF 关闭，请将 LocalDevVPN 改为下方同网段地址并重连：")
                                .font(.caption2)
                                .foregroundColor(.secondary)

                            HStack(spacing: 8) {
                                Button(action: {
                                    #if os(iOS)
                                    UIPasteboard.general.string = recTunnel
                                    #endif
                                    copiedTunnelToast = true
                                }) {
                                    Text(copiedTunnelToast ? "✅ 已复制 Tunnel" : "复制 Tunnel: \(recTunnel)")
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
                                    Text(copiedDeviceToast ? "✅ 已复制并设为网关" : "复制 Device: \(recDevice) 并填入")
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
                            vm.hasPairingFile ? "从文件选择更换配对文件 (.plist)" : "方式 1：从「文件」选择配对文件 (.plist / .mobiledevicepairing)",
                            systemImage: "folder.badge.plus"
                        )
                        .foregroundColor(.cyan)
                    }

                    Button(action: { pastePairingFromClipboard() }) {
                        Label(
                            "方式 2：从剪贴板一键粘贴配对文件（在系统文件长按 .plist 点拷贝）",
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
                            Label("立即直连 installation_proxy 并扫描全机应用", systemImage: "bolt.shield.fill")
                                .font(.subheadline.bold())
                                .foregroundColor(.teal)
                        }

                        Button(role: .destructive, action: {
                            vm.clearPairingFile()
                            localBannerText = "已移除配对文件"
                            localBannerIsError = false
                        }) {
                            Label("移除已保存的配对文件", systemImage: "trash")
                        }
                    }
                } header: {
                    Text("引擎 1A · 本机配对直连（与 1B 二选一）")
                } footer: {
                    Text("💡 除了点选或剪贴板导入外，你也可以在系统『文件』App 中直接把配对 .plist 移入『我的 iPhone → WQGuard』文件夹，返回本页即会自动识别！")
                }

                // Engine 1B: Offline Snapshot Import
                Section {
                    HStack {
                        Image(systemName: vm.hasSavedSnapshot ? "doc.badge.gearshape.fill" : "doc.text.magnifyingglass")
                            .foregroundColor(vm.hasSavedSnapshot ? .green : .orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("方式 B：导入已安装应用注册表快照")
                                .font(.subheadline.bold())
                            if vm.hasSavedSnapshot {
                                Text("已缓存快照: \(vm.savedSnapshotFilename ?? "snapshot")（共 \(vm.savedSnapshotAppCount) 款已安装应用）")
                                    .font(.caption)
                                    .foregroundColor(.green)
                            } else {
                                Text("支持 Mac 原生 devicectl (.json)、pymobiledevice3 (.json) 或 .plist")
                                    .font(.caption)
                                    .foregroundColor(.gray)
                            }
                        }
                    }

                    Button(action: { pickSnapshotFile() }) {
                        Label("选择注册表快照文件 (.json / .plist / .xml)", systemImage: "arrow.down.doc.fill")
                            .foregroundColor(.orange)
                    }

                    Button(action: {
                        #if os(iOS)
                        UIPasteboard.general.string = cliDeviceCtlCommand
                        #endif
                        copiedDeviceCtlToast = true
                    }) {
                        HStack {
                            Label("复制 Mac 免装插件一键导出命令（推荐 iOS 27）", systemImage: "apple.terminal.fill")
                                .foregroundColor(.teal)
                            Spacer()
                            if copiedDeviceCtlToast {
                                Text("已复制")
                                    .font(.caption.bold())
                                    .foregroundColor(.green)
                            }
                        }
                    }

                    Button(action: {
                        #if os(iOS)
                        UIPasteboard.general.string = cliExportCommand
                        #endif
                        copiedCommandToast = true
                    }) {
                        HStack {
                            Label("复制 pymobiledevice3 导出命令（跨平台）", systemImage: "terminal.fill")
                            Spacer()
                            if copiedCommandToast {
                                Text("已复制")
                                    .font(.caption.bold())
                                    .foregroundColor(.green)
                            }
                        }
                    }

                    if vm.hasSavedSnapshot {
                        Button(role: .destructive, action: {
                            vm.clearSavedSnapshot()
                            localBannerText = "已清除快照缓存"
                            localBannerIsError = false
                        }) {
                            Label("清除已缓存的快照数据", systemImage: "trash")
                        }
                    }

                    Toggle("同时纳入 App Store 官方应用审计", isOn: $vm.includeAppStoreAppsInRegistry)
                        .font(.subheadline)
                } header: {
                    Text("引擎 1B · 离线注册表快照（无需 VPN，100% 兼容 iOS 27）")
                } footer: {
                    Text("Mac 连接手机后直接在「终端」粘贴上方第一条命令（调用苹果 Xcode 原生 CoreDevice 通道，无需安装第三方工具），将桌面生成的 installed_apps.json 隔空投送至手机用 WQGuard 打开即可秒扫全机应用。")
                }

                // Engine 2: Bound Signer Folder Correlation
                Section {
                    if vm.bookmarkedFolderNames.isEmpty {
                        Text("尚未绑定子目录（进入 Feather 或全能签 → 点进 Signed 文件夹 → 点右上角打开）")
                            .font(.caption)
                            .foregroundColor(.orange)
                    } else {
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.green)
                            Text("已绑定: \(vm.bookmarkedFolderNames.joined(separator: ", "))")
                                .font(.subheadline.bold())
                                .foregroundColor(.green)
                        }
                    }

                    Button(action: { pickSigningFolder() }) {
                        Label("绑定签名器 Signed / Unsigned 子目录", systemImage: "folder.fill.badge.plus")
                            .foregroundColor(.teal)
                    }

                    if !vm.bookmarkedFolderNames.isEmpty {
                        Button(role: .destructive, action: {
                            vm.clearBoundSigningFolders()
                            localBannerText = "已解除签名器目录绑定"
                            localBannerIsError = false
                        }) {
                            Label("解除已绑定的签名目录", systemImage: "folder.badge.minus")
                        }
                    }
                } header: {
                    Text("引擎 2 · 签名器源包二进制深扫（Feather / 全能签）")
                } footer: {
                    Text("绑定后自动联动扫描 Signed / Unsigned 目录下的 .ipa 与解包后的 .app 二进制及 Frameworks/*.dylib 注入插件。")
                }

                // Engine 3: On-Device URL Scheme Probe
                Section {
                    Toggle("启用本机已安装签名器与高权限环境探针", isOn: $vm.enableOnDeviceProbe)
                        .font(.subheadline)
                } header: {
                    Text("引擎 3 · 本机零配置在位探针（方案三）")
                } footer: {
                    Text("通过标准系统接口探测本机是否已安装全能签、Feather、SideStore、StikDebug 以及 Filza、TrollStore、Sileo 等高权限容器环境工具。")
                }
            }
            .navigationTitle("已安装应用扫描源")
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
                if let autoMsg = vm.autoImportFromDocumentsFolderIfNeeded() {
                    localBannerIsError = false
                    localBannerText = autoMsg
                }
            }
        }
    }

    private func pastePairingFromClipboard() {
        switch vm.importPairingFromClipboardWithResult() {
        case .success(let summary):
            localBannerIsError = false
            localBannerText = "✅ 剪贴板导入成功：\(summary) — 正在直连扫描..."
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
                localBannerText = "\(summary) — 正在通过 LocalDevVPN 直连扫描..."
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

    private func pickSigningFolder() {
        #if canImport(UIKit)
        NativeDocumentPickerPresenter.shared.present(kind: .signingFolder) { urls in
            vm.scanMultipleIPAPackages(at: urls)
            localBannerIsError = false
            localBannerText = "已成功绑定目录（\(vm.bookmarkedFolderNames.joined(separator: ", "))），正在后台扫描源包..."
        }
        #endif
    }
}
