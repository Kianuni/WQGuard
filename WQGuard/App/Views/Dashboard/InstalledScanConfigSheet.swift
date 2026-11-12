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

    private enum TutorialTab: String, CaseIterable, Identifiable {
        case modeB = "方式 B · Mac导出"
        case modeA = "方式 A · 无线直连"
        case engine2 = "引擎 2 · IPA深扫"
        var id: String { rawValue }
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
    private let cliExportCommand = #"(command -v pymobiledevice3 >/dev/null 2>&1 && pymobiledevice3 apps list > ~/Desktop/installed_apps.json || python3 -m pymobiledevice3 apps list > ~/Desktop/installed_apps.json) && echo "✅ 已导出到桌面: ~/Desktop/installed_apps.json""#
    private let cliDeviceCtlCommand = #"ID=$(xcrun devicectl list devices -j - | python3 -c "import sys,json; devs=json.load(sys.stdin).get('result',{}).get('devices',[]); print(next((d['identifier'] for d in devs if 'Simulator' not in str(d)), ''))") && xcrun devicectl device info apps --device "$ID" --include-all-apps --include-app-group-identifiers --include-container-paths --json-output ~/Desktop/installed_apps.json && echo "✅ 已导出 ~/Desktop/installed_apps.json""#

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
                    DisclosureGroup("📖 保姆级图文步骤教程（Mac 软件安装 · 连线 · 导出）", isExpanded: $showTutorial) {
                        VStack(alignment: .leading, spacing: 12) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("💡 方式 A 与 方式 B 二选一即可（无需同时开启）")
                                    .font(.caption.bold())
                                    .foregroundColor(.cyan)
                                Text("• **新手最推荐「方式 B」**：不用在手机装 VPN、不用改 IP，连上 Mac 电脑几秒钟导出 `installed_apps.json` 隔空投送到手机即可扫全机应用。\n• **进阶推荐「方式 A」**：只需用 Mac 导出一次配对文件导入手机，以后出门在外无需电脑，打开 `LocalDevVPN` 就能随时无线直连扫描！")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }

                            Picker("教程分类", selection: $selectedTutorialTab) {
                                ForEach(TutorialTab.allCases) { tab in
                                    Text(tab.rawValue).tag(tab)
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
                    Text("新手必读 · 详细操作指南")
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
                        UIPasteboard.general.string = cliExportCommand
                        #endif
                        copiedCommandToast = true
                    }) {
                        HStack {
                            Label("复制 pymobiledevice3 导出到桌面命令（推荐·全量权限）", systemImage: "terminal.fill")
                                .foregroundColor(.teal)
                            Spacer()
                            if copiedCommandToast {
                                Text("已复制")
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
                            Label("复制 Xcode devicectl 导出命令（已装 Xcode 免插件）", systemImage: "apple.terminal.fill")
                            Spacer()
                            if copiedDeviceCtlToast {
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

                    Toggle("同时展示第三方 App Store / TestFlight 应用（已排除苹果系统服务）", isOn: $vm.includeAppStoreAppsInRegistry)
                        .font(.subheadline)
                } header: {
                    Text("引擎 1B · 离线注册表快照（无需 VPN，100% 兼容 iOS 27）")
                } footer: {
                    Text("推荐优先使用 pymobiledevice3 导出命令（可读取企业签、个人侧载、TestFlight 与官方应用的完整 Entitlements 权限表并直接输出到 Mac 桌面 ~/Desktop/installed_apps.json），隔空投送到手机即可一键完成全盘审计。")
                }

                // Engine 2: Multi-Select Local IPA Scan Queue & Registry Correlation
                Section {
                    Button(action: { pickSourcePackages() }) {
                        Label("选择 .ipa 文件加入扫描列表（支持多选）", systemImage: "doc.badge.plus")
                            .font(.subheadline.bold())
                            .foregroundColor(.teal)
                    }

                    if vm.syncedPackageNames.isEmpty {
                        Text("尚未加入本地 .ipa 安装包。可点击上方按钮在系统『文件』中一次勾选多个 .ipa / .tipa 文件加入扫描列表。")
                            .font(.caption)
                            .foregroundColor(.gray)
                    } else {
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark.seal.fill")
                                .foregroundColor(.green)
                            Text("已加入扫描列表（共 \(vm.syncedPackageNames.count) 个 IPA）")
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
                            localBannerText = "已清空全部已加入的 IPA 扫描文件"
                            localBannerIsError = false
                        }) {
                            Label("清空全部已加入的 IPA 文件", systemImage: "trash")
                        }
                    }
                } header: {
                    Text("引擎 2 · 本地 IPA 扫描列表（支持多选）")
                } footer: {
                    Text("加入列表的所有 .ipa / .tipa 文件会自动缓存，并在扫描时按 Bundle ID 与全机注册表联动合并，深度审计 Mach-O 私有符号与注入动态库。Feather 已签应用可在 Feather「库 → 已签名 → 导出 IPA」后导入。")
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
                badge: "第 1 步",
                title: "在 Mac 上打开「终端」并安装 pymobiledevice3",
                color: .teal,
                detail: "1. 在 Mac 键盘同时按下 Command ⌘ + 空格，输入「终端」(Terminal) 回车打开。\n2. 点击下方按钮复制安装命令，粘贴到 Mac 终端窗口按回车运行（只需安装一次；若弹窗提示安装命令行工具点「安装」即可；若你电脑已安装苹果官方 Xcode 也可跳过此步用下方 Xcode 命令）："
            )
            inlineCopyButton(
                title: copiedInstallPyToast ? "✅ 已复制 Mac 安装命令" : "📋 复制 Mac 安装工具命令 (brew / pip)",
                color: .teal
            ) {
                #if os(iOS)
                UIPasteboard.general.string = cliInstallPyCommand
                #endif
                copiedInstallPyToast = true
            }

            Divider()

            tutorialStepCard(
                badge: "第 2 步",
                title: "数据线连接 iPhone 与 Mac，点击「信任」",
                color: .cyan,
                detail: "1. 用支持数据传输的 USB / Type-C 数据线将 iPhone 插入 Mac，解锁手机保持在桌面亮屏。\n2. 手机屏幕弹出「要信任此电脑吗？」时，点击「信任」并输入手机锁屏密码。\n3. 打开 Mac 左下角「访达」(Finder)，在左侧栏点一下你的 iPhone，若右侧也显示「信任」按钮请点一下。"
            )

            Divider()

            tutorialStepCard(
                badge: "第 3 步",
                title: "在 Mac 终端一键导出快照文件到桌面",
                color: .orange,
                detail: "点击下方按钮复制导出命令，可通过微信/通用剪贴板发到 Mac，粘贴进「终端」按回车。等待约 3～8 秒看到“✅ 已导出到桌面”后，Mac 桌面就会出现 installed_apps.json 文件："
            )
            inlineCopyButton(
                title: copiedCommandToast ? "✅ 已复制导出到桌面命令" : "📋 复制导出命令（自动存到 Mac 桌面）",
                color: .orange
            ) {
                #if os(iOS)
                UIPasteboard.general.string = cliExportCommand
                #endif
                copiedCommandToast = true
            }

            Divider()

            tutorialStepCard(
                badge: "第 4 步",
                title: "隔空投送到 iPhone 并导入 WQGuard",
                color: .green,
                detail: "1. 在 Mac 桌面上右键点击 installed_apps.json → 选择「共享」→「隔空投送 (AirDrop)」发给你的 iPhone（或通过微信文件传输助手发送）。\n2. 手机收到后直接选「用 WQGuard 打开」自动开扫；或者选「存储到“文件”」，再点本页下方引擎 1B 的「选择注册表快照文件」选中它即可！"
            )
        }
    }

    private var modeATutorialView: some View {
        VStack(alignment: .leading, spacing: 10) {
            tutorialStepCard(
                badge: "第 1 步",
                title: "手机端下载什么？安装免费 App「LocalDevVPN」",
                color: .cyan,
                detail: "打开 iPhone 的 App Store，搜索并免费下载安装「LocalDevVPN」（如果你手机上已经装有 StikDebug 或 SideStore，也可直接使用它们内置的隧道）。"
            )

            Divider()

            tutorialStepCard(
                badge: "第 2 步",
                title: "Mac 端下载什么？用 jitterbugpair 生成配对文件",
                color: .teal,
                detail: "• 如果你以前给 SideStore / StikDebug 生成过 .mobiledevicepairing 或 .plist 配对文件，直接跳到第 3 步复用即可！\n• 首次生成操作：\n  1. 在 Mac 浏览器打开 github.com/osy/JitterBug/releases 下载 jitterbugpair-macos.zip 并双击解压出 jitterbugpair；\n  2. 数据线把 iPhone 连上 Mac，解锁手机亮屏点「信任」输密码；\n  3. 打开 Mac「终端」，先输入 cd ~/Desktop 回车，再把解压出的 jitterbugpair 拖进终端窗口按回车运行（若 Mac 拦截未验证开发者，前往 Mac「系统设置 → 隐私与安全性」底部点「仍要打开」后再运行一次）；\n  4. 运行成功后，Mac 桌面即会生成 <手机UDID>.mobiledevicepairing 配对文件！"
            )
            inlineCopyButton(
                title: copiedCdDesktopToast ? "✅ 已复制 cd ~/Desktop" : "📋 复制终端切换桌面目录命令 (cd ~/Desktop)",
                color: .teal
            ) {
                #if os(iOS)
                UIPasteboard.general.string = "cd ~/Desktop"
                #endif
                copiedCdDesktopToast = true
            }

            Divider()

            tutorialStepCard(
                badge: "第 3 步",
                title: "把配对文件传到手机并导入引擎 1A",
                color: .orange,
                detail: "在 Mac 桌面右键该 .mobiledevicepairing 文件 →「共享 → 隔空投送」发到 iPhone → 选「存储到“文件”」（建议存到『我的 iPhone → WQGuard』目录），然后点本页下方引擎 1A 的「从文件选择配对文件」导入。"
            )

            Divider()

            tutorialStepCard(
                badge: "第 4 步",
                title: "开启 VPN 直连（iOS 26.4+ / iOS 27 子网对齐）",
                color: .green,
                detail: "• iOS 26.3 及更早：打开 LocalDevVPN 点 Connect 连接，回本页点「立即直连扫描」即可。\n• iOS 26.4+ / iOS 27 必做：苹果要求隧道与当前 Wi-Fi 同网段。保持手机连 Wi-Fi，先点下方橙色提示框的「复制 Tunnel」，打开 LocalDevVPN 右上角 ⚙️ 设置粘贴到 Tunnel IP；再回本页点「复制 Device 并填入」粘贴到 LocalDevVPN 的 Device IP，保存并重连 VPN，回 WQGuard 点「立即直连扫描」（首次弹窗允许本地网络权限）即可 1 秒扫完全机！"
            )
        }
    }

    private var engine2TutorialView: some View {
        VStack(alignment: .leading, spacing: 10) {
            tutorialStepCard(
                badge: "作用说明",
                title: "为什么可以配合引擎 2 多选加入 .ipa 文件？",
                color: .cyan,
                detail: "方式 A / B 能查出全机所有应用的签名证书、App Groups 与越权权限表，而受 iOS 沙盒隔离限制无法直接拆包其他已安装应用的主程序。通过下方「引擎 2」将侧载应用的 .ipa 文件加入扫描列表后，WQGuard 会按 Bundle ID 自动将注册表与二进制合并升级为「🔬 全量深扫」，精准检出 containermanagerd 漏洞符号与注入动态库！"
            )

            Divider()

            tutorialStepCard(
                badge: "方法 ①",
                title: "手动多选本地 .ipa 文件加入扫描列表",
                color: .teal,
                detail: "点击本页下方引擎 2 的「选择 .ipa 文件加入扫描列表（支持多选）」，进入系统『文件』App（例如「下载项」、『我的 iPhone → Feather → Unsigned』或任意保存安装包的目录），可一次勾选多个 .ipa / .tipa 文件点右上角「打开」批量加入扫描！"
            )

            Divider()

            tutorialStepCard(
                badge: "方法 ②",
                title: "在 Feather / 全能签内导出已签名 IPA",
                color: .orange,
                detail: "如果某个应用在签名时额外注入了插件（dylib），可打开 Feather → 底部「库」→ 在「已签名」列表点击该应用 → 选择「导出 IPA」→ 直接选「WQGuard」（或先「存储到“文件”」再回 WQGuard 多选导入）。"
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

    private func pickSourcePackages() {
        #if canImport(UIKit)
        NativeDocumentPickerPresenter.shared.present(kind: .ipaFiles) { urls in
            vm.scanMultipleIPAPackages(at: urls, correlateWithInstalled: true)
            if !vm.syncedPackageNames.isEmpty {
                localBannerIsError = false
                localBannerText = "✅ 已加入 \(vm.syncedPackageNames.count) 个 IPA 至扫描列表，正在执行扫描..."
            }
        }
        #endif
    }
}
