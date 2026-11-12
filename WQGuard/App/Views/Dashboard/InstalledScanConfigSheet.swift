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

    @State private var activePicker: DocumentPickerKind? = nil
    @State private var copiedCommandToast = false
    @State private var showTutorial = true

    private let cliExportCommand = "pymobiledevice3 apps list > installed_apps.json"

    public init() {}

    public var body: some View {
        NavigationStack {
            List {
                // Built-in Quick Setup Guide
                Section {
                    DisclosureGroup("📖 开启教程：方式 A / 方式 B / Feather 怎么操作？", isExpanded: $showTutorial) {
                        VStack(alignment: .leading, spacing: 10) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("① 绑定 Feather / 全能签为什么点「打开」没反应？")
                                    .font(.caption.bold())
                                    .foregroundColor(.orange)
                                Text("iOS 系统禁止直接授权其他 App 的最外层根目录（如『我的 iPhone → Feather』）。请点进里面的 **Signed**（已签名）或 **Unsigned** 子文件夹后，再点右上角「打开」即可立即成功绑定！")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }

                            Divider()

                            VStack(alignment: .leading, spacing: 3) {
                                Text("② 方式 A（推荐：以后在手机上随时无线扫全机 App）")
                                    .font(.caption.bold())
                                    .foregroundColor(.cyan)
                                Text("1. 电脑下载开源工具 **idevice_pair**（Mac/Win 通用），手机插线点信任，点 Generate 生成 `.mobiledevicepairing` 配对文件发到手机导入下方（只需做一次）；\n2. 在手机 App Store 免费搜并安装 **LocalDevVPN**，打开开关；\n3. 回到 WQGuard 点击「一键扫描已安装应用」即可直连系统注册表！")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }

                            Divider()

                            VStack(alignment: .leading, spacing: 3) {
                                Text("③ 方式 B（无需装 VPN：电脑一行命令导出快照）")
                                    .font(.caption.bold())
                                    .foregroundColor(.teal)
                                Text("手机连电脑执行 `pip3 install pymobiledevice3` 后运行下方复制的命令生成 `installed_apps.json`，隔空投送到手机选择「用 WQGuard 打开」即可秒扫全机所有已安装应用。")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .font(.subheadline.bold())
                }

                // Engine 2 First if user came to bind Feather / Signer Directory!
                Section {
                    if vm.bookmarkedFolderNames.isEmpty {
                        Text("尚未绑定子目录（请进入 Feather 或全能签 → 点进 Signed 文件夹 → 点右上角打开）")
                            .font(.caption)
                            .foregroundColor(.orange)
                    } else {
                        HStack {
                            Image(systemName: "folder.fill.badge.gearshape")
                                .foregroundColor(.teal)
                            Text("已绑定: \(vm.bookmarkedFolderNames.joined(separator: ", "))")
                                .font(.subheadline)
                        }
                    }

                    Button(action: { activePicker = .signingFolder }) {
                        Label("绑定签名器 Signed / Unsigned 子目录", systemImage: "folder.fill.badge.plus")
                            .foregroundColor(.teal)
                    }

                    if !vm.bookmarkedFolderNames.isEmpty {
                        Button(role: .destructive, action: { vm.clearBoundSigningFolders() }) {
                            Label("解除已绑定的签名目录", systemImage: "folder.badge.minus")
                        }
                    }
                } header: {
                    Text("引擎 2 · 签名器源包二进制深扫（Feather / 全能签）")
                } footer: {
                    Text("自动扫描 Signed / Unsigned 目录下的 .ipa 与解包后的 .app 二进制及 Frameworks/*.dylib 注入插件。")
                }

                // Engine 1A: LocalDevVPN + Pairing File Direct Connection
                Section {
                    HStack {
                        Image(systemName: vm.hasPairingFile ? "checkmark.seal.fill" : "link.badge.plus")
                            .foregroundColor(vm.hasPairingFile ? .green : .cyan)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("方式 A：LocalDevVPN 配对直连本机注册表")
                                .font(.subheadline.bold())
                            Text(vm.pairingHostIDSummary ?? "未导入配对文件（支持 idevice_pair / StikDebug / SideStore 配对文件）")
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

                    Button(action: { activePicker = .pairingFile }) {
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
                    Text("开启 App Store 免费应用 LocalDevVPN（10.7.0.1）后，WQGuard 可直接向 iOS 官方 installation_proxy 读取全机所有已安装应用的完整 Entitlements 权限表与签名身份。")
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
                                Text("支持 pymobiledevice3 (.json) 或 ideviceinstaller (.plist/.xml)")
                                    .font(.caption)
                                    .foregroundColor(.gray)
                            }
                        }
                    }

                    Button(action: { activePicker = .registrySnapshot }) {
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
                    Text("电脑连接手机执行 `\(cliExportCommand)`，隔空投送至手机用 WQGuard 打开即可秒扫全机已安装应用。")
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
            #if canImport(UIKit)
            .sheet(item: $activePicker) { kind in
                SystemDocumentPicker(kind: kind) { urls in
                    activePicker = nil
                    switch kind {
                    case .pairingFile:
                        if let first = urls.first {
                            vm.importPairingFile(from: first)
                        }
                    case .registrySnapshot:
                        if let first = urls.first {
                            vm.importRegistrySnapshot(from: first, autoScan: true)
                        }
                    case .signingFolder, .ipaFiles:
                        dismiss()
                        vm.scanMultipleIPAPackages(at: urls)
                    }
                } onCancel: {
                    activePicker = nil
                }
            }
            #endif
        }
    }
}
