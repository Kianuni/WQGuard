//
//  InstalledScanConfigSheet.swift
//  WQGuard
//
//  Configuration center for WQGuard v1.1.0's 3-engine Installed App Security Scanner:
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

    @State private var showPairingPicker = false
    @State private var showSnapshotPicker = false
    @State private var showSignerFolderPicker = false
    @State private var copiedCommandToast = false

    private let cliExportCommand = "pymobiledevice3 apps list > installed_apps.json"

    public init() {}

    public var body: some View {
        NavigationStack {
            List {
                // Engine 1A: LocalDevVPN + Pairing File Direct Connection
                Section {
                    HStack {
                        Image(systemName: vm.hasPairingFile ? "checkmark.seal.fill" : "link.badge.plus")
                            .foregroundColor(vm.hasPairingFile ? .green : .cyan)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("方式 A：LocalDevVPN 配对直连本机注册表")
                                .font(.subheadline.bold())
                            Text(vm.pairingHostIDSummary ?? "未导入配对文件（支持复用 StikDebug / SideStore 配对文件）")
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

                    Button(action: { showPairingPicker = true }) {
                        Label(
                            vm.hasPairingFile ? "更换配对文件 (.mobiledevicepairing)" : "导入配对文件 (.mobiledevicepairing / .plist)",
                            systemImage: "key.radiowaves.forward.fill"
                        )
                        .foregroundColor(.cyan)
                    }

                    if vm.hasPairingFile {
                        Button(action: { vm.testLiveLockdownConnectionAndScan() }) {
                            Label("立即直连 installation_proxy 并扫描全机应用", systemImage: "bolt.shield.fill")
                                .font(.subheadline.bold())
                                .foregroundColor(.teal)
                        }

                        Button(role: .destructive, action: { vm.clearPairingFile() }) {
                            Label("移除已保存的配对文件", systemImage: "trash")
                        }
                    }
                } header: {
                    Text("引擎 1A · 本机配对直连（方案一）")
                } footer: {
                    Text("开启 StikDebug 或 SideStore 的 LocalDevVPN（10.7.0.1）后，WQGuard 可直接向 iOS 官方 installation_proxy 读取全机所有已安装应用的完整 Entitlements 权限表与签名身份，无需任何漏洞。")
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
                                Text("已加载 \(vm.savedSnapshotFilename ?? "snapshot")（共 \(vm.savedSnapshotAppCount) 款已安装应用）")
                                    .font(.caption)
                                    .foregroundColor(.green)
                            } else {
                                Text("支持 ideviceinstaller (.plist/.xml) 或 pymobiledevice3 (.json)")
                                    .font(.caption)
                                    .foregroundColor(.gray)
                            }
                        }
                    }

                    Button(action: { showSnapshotPicker = true }) {
                        Label("选择注册表快照文件 (.plist / .xml / .json)", systemImage: "arrow.down.doc.fill")
                            .foregroundColor(.orange)
                    }

                    Button(action: {
                        #if os(iOS)
                        UIPasteboard.general.string = cliExportCommand
                        #endif
                        copiedCommandToast = true
                    }) {
                        HStack {
                            Label("复制电脑端一键导出快照命令", systemImage: "terminal.fill")
                            Spacer()
                            if copiedCommandToast {
                                Text("已复制")
                                    .font(.caption.bold())
                                    .foregroundColor(.green)
                            }
                        }
                    }

                    if vm.hasSavedSnapshot {
                        Button(role: .destructive, action: { vm.clearSavedSnapshot() }) {
                            Label("清除已缓存的快照数据", systemImage: "trash")
                        }
                    }

                    Toggle("同时纳入 App Store 官方应用审计", isOn: $vm.includeAppStoreAppsInRegistry)
                        .font(.subheadline)
                } header: {
                    Text("引擎 1B · 离线注册表快照（无需 VPN）")
                } footer: {
                    Text("电脑连接手机执行 `\(cliExportCommand)` 或 `ideviceinstaller -l -o xml > apps.plist`，隔空投送至手机用 WQGuard 打开即可秒扫全机已安装应用。")
                }

                // Engine 2: Signer Directory Correlation
                Section {
                    if vm.bookmarkedFolderNames.isEmpty {
                        Text("尚未绑定签名器目录（建议绑定「全能签」或「Feather」目录）")
                            .font(.caption)
                            .foregroundColor(.gray)
                    } else {
                        HStack {
                            Image(systemName: "folder.fill.badge.gearshape")
                                .foregroundColor(.teal)
                            Text("已绑定: \(vm.bookmarkedFolderNames.joined(separator: ", "))")
                                .font(.subheadline)
                        }
                    }

                    Button(action: { showSignerFolderPicker = true }) {
                        Label("绑定签名工具目录（自动关联二进制深扫）", systemImage: "folder.fill.badge.plus")
                            .foregroundColor(.teal)
                    }

                    if !vm.bookmarkedFolderNames.isEmpty {
                        Button(role: .destructive, action: { vm.clearBoundSigningFolders() }) {
                            Label("解除已绑定的签名目录", systemImage: "folder.badge.minus")
                        }
                    }
                } header: {
                    Text("引擎 2 · 签名器源包二进制联动（方案二）")
                } footer: {
                    Text("当注册表检出已安装自签应用时，WQGuard 会按 Bundle ID 自动匹配签名目录中的源 .ipa 包，补齐 Mach-O 私有符号与 Frameworks/*.dylib 注入插件深扫。")
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
            .background(
                EmptyView()
                    .fileImporter(
                        isPresented: $showPairingPicker,
                        allowedContentTypes: [.data],
                        allowsMultipleSelection: false
                    ) { result in
                        if case .success(let urls) = result, let first = urls.first {
                            vm.importPairingFile(from: first)
                        }
                    }
            )
            .background(
                EmptyView()
                    .fileImporter(
                        isPresented: $showSnapshotPicker,
                        allowedContentTypes: [.data],
                        allowsMultipleSelection: false
                    ) { result in
                        if case .success(let urls) = result, let first = urls.first {
                            vm.importRegistrySnapshot(from: first, autoScan: true)
                        }
                    }
            )
            .background(
                EmptyView()
                    .fileImporter(
                        isPresented: $showSignerFolderPicker,
                        allowedContentTypes: [.folder],
                        allowsMultipleSelection: false
                    ) { result in
                        if case .success(let urls) = result {
                            dismiss()
                            vm.scanMultipleIPAPackages(at: urls)
                        }
                    }
            )
        }
    }
}
