# WQGuard 🛡️

**面向 iOS 26.2+ / iOS 27.x 的 100% 严格只读开源沙盒越权检测、侧载 IPA 审查与多平台固件 CVE 防护工具**  
**Standalone, 100% Read-Only Open-Source iOS Security Scanner, Sideloaded IPA Auditor & Multi-Client Firmware CVE Guard**

[![Latest Release](https://img.shields.io/github/v/release/Kianuni/WQGuard?label=Release&color=00c7a5)](https://github.com/Kianuni/WQGuard/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-iOS%2016.0%2B%20(Optimized%20for%20iOS%2026.2%2B%20%2F%2027.x)%20%7C%20macOS-lightgrey.svg)]()
[![Swift 6.0](https://img.shields.io/badge/Swift-6.0%20Strict%20Concurrency-orange.svg)]()
[![Unit Tests](https://img.shields.io/badge/Tests-664%20Passing-brightgreen.svg)]()
[![Read-Only Guaranteed](https://img.shields.io/badge/Security-100%25%20Read--Only%20(O__RDONLY)-success.svg)](SECURITY.md)

**[🇨🇳 简体中文](#简体中文) · [🇺🇸 English](#english) · [📥 下载最新安装包 / Download Latest IPA](https://github.com/Kianuni/WQGuard/releases/latest) · [📖 技术白皮书 / Technical Reference](USAGE_GUIDE.md) · [🔒 安全策略 / Security Policy](SECURITY.md)**

---

<a name="简体中文"></a>
## 🇨🇳 简体中文

### 1. 项目简介

**WQGuard（容器守卫）** 是一款专为 **iOS 26.2+ 与 iOS 27.x** 环境打造的生产级、零第三方依赖、**100% 严格只读**开源安全审计工具与固件风险防护系统。项目同时提供两大原生目标与一套独立多平台防护规则库：

1. **iOS 原生应用 (`WQGuard.app`)**：支持**全机已安装应用三引擎无越权扫描**、**本地多选 `.ipa` / `.tipa` 安装包深度静态反编译审查**、**2026 固件 CVE 漏洞暴露雷达**、**五大主流代理工具（Surge / 小火箭 / 圈 X / Loon / Stash）防 Brotli 溢出护盾一键导入/导出**，以及 RFC 8259 JSON / Markdown / 纯文本审计报告导出。
2. **macOS 终端命令行工具 (`wqguard-cli`)**：零外部依赖的原生 Darwin 终端工具，支持批量扫描 `.ipa` 安装包、共享容器目录、多格式代理护盾生成及 CI/CD 安全门禁自动化集成。
3. **独立多平台代理护盾规则库 ([`Shields/`](Shields/))**：无需安装 App 亦可直接通过订阅链接导入 Surge、Shadowrocket、Quantumult X、Loon 与 Stash，在网络传输层阻断 `CVE-2026-111497` (`HTTP2Shell`) 漏洞利用。

WQGuard 专注于在**绝对不调用任何私有越权漏洞（Zero-Exploit）**的前提下，精准检出跨容器沙盒逃逸攻击（`worse_query` / `bad_query` / `containermanagerd` 混淆替身漏洞）、二次打包盗币钱包木马（Web3 Drainer）、相册 TCC 隐私绕过（`CVE-2026-112676`）、注入外挂动态库（`Frameworks/*.dylib`）以及常驻后台剪贴板助记词窃取行为。

> **🔒 核心安全承诺：100% 物理只读不变量**  
> WQGuard 在任何情况下**绝不修改、创建、覆写或触碰**任何被检应用二进制、系统文件或容器元数据。全链路强制使用 `O_RDONLY | O_NOFOLLOW | O_CLOEXEC` 只读不跟随描述符、`lstat`/`readlink` 非递归软链接检查与 `.mappedIfSafe` 只读内存映射，并通过 **664 项自动化单元测试**与 SHA-256 前后一致性校验。

---

### 2. 核心功能亮点

#### 🛡️ 三引擎「全机已安装应用」合规审计架构
普通 iOS 侧载应用受限于 Apple Seatbelt 沙盒，无法直接枚举其他已安装应用目录。WQGuard 通过独创的**三引擎协同架构**，在不依赖越狱或内核漏洞的前提下实现全机安全盘点：

- **引擎 1A · 本机无线配对直连（`LocalDevVPN` + 配对文件）**：
  - 导入一次由 Mac `jitterbugpair`（或复用 SideStore / StikDebug）生成的 `.mobiledevicepairing` / `.plist` 配对文件（支持系统文件点选、剪贴板一键粘贴、或放入 `我的 iPhone → WQGuard` 自动加载）。
  - 配合 `LocalDevVPN` 在手机本地直连 iOS 官方 `installation_proxy` 服务，1 秒读取全机应用的完整 `Entitlements` 权限表、App Groups 共享容器与签名团队身份。
  - **iOS 26.4+ / iOS 27 子网对齐助手**：自动检测当前 Wi-Fi IP 并生成同网段 `Tunnel IP` 与 `Device IP` 一键复制按钮，完美解决新系统 `lockdownd` 拦截 `10.7.0.x` 隧道导致连接关闭的问题。
- **引擎 1B · 离线注册表快照导入（免 VPN · 100% 兼容 iOS 27）**：
  - 连接 Mac 执行一行 `pymobiledevice3` 或苹果官方 Xcode `xcrun devicectl` 命令导出 `installed_apps.json`，隔空投送至手机即可完成全盘审计。
  - **零系统误报 & 精准渠道识别**：内置双层系统路径（`/System/Library/`、`/Applications/`）与 Apple 平台二进制过滤，彻底排除苹果原生系统服务干扰；结合 `BetaReportsActive` / `get-task-allow` / `ProvisioningProfile` 精准区分 **`🛠️ 个人侧载`**、**`🏢 企业签`**、**`✈️ TestFlight`**（如 Surge、APTV 等 TestFlight 应用绝不误判为企业签）与 **`🍏 App Store`**。
- **引擎 2 · 多选本地 `.ipa` 扫描列表与二进制自动联动**：
  - 支持在系统「文件」App 中**一次勾选任意多个 `.ipa` / `.tipa` 文件**批量加入扫描列表（亦可从 Feather「库 → 已签名 → 导出 IPA」直接发送到 WQGuard），支持单个移除、侧滑删除、全部重扫与一键清空。
  - 全机扫描时自动按 `Bundle ID` 将注册表记录与本地 `.ipa` 主程序合并升级为 **`🔬 注册表 + 二进制全量深扫`**。
- **引擎 3 · 本机零配置在位探针**：
  - 基于标准 `UIApplication.canOpenURL` 探针清单，零配置识别本机在位的侧载签名工具（Feather、全能签、SideStore、AltStore、GBox、Scarlet）与高权限环境组件（TrollStore、Filza、Sileo 等）。

#### 🔬 4 层渐进式 Mach-O 静态深度解析引擎
```text
┌────────────────────────────────────────────────────────────────────────┐
│ 第 1 层：分发渠道识别与代码签名门禁                                    │
│ • 解析 LC_CODE_SIGNATURE 超块（XML 0xfade7171 + ASN.1 DER 0xfade7172） │
│ • 未声明 com.apple.security.application-groups 的包 O(1) 快速判定安全  │
├────────────────────────────────────────────────────────────────────────┤
│ 第 2 层：Mach-O 符号表、字符串段与抗混淆行为元组扫描                   │
│ • 扫描主二进制、Frameworks/*.dylib 与 PlugIns/*.appex 全部扩展组件     │
│ • 检索 libsystem_containermanager.dylib、container_query_*、fsgetpath  │
│ • 抗混淆行为元组：AppGroups ∧ (dlopen/dlsym) ∧ (symlink/token_consume) │
├────────────────────────────────────────────────────────────────────────┤
│ 第 3 层：共享容器逃逸软链接与恶意监管配置排查                          │
│ • 使用 lstat + readlink (O_NOFOLLOW) 排查 Library/Caches 越界软链接    │
│ • 检查 CloudConfigurationDetails.plist 防范伪造 MDM 监管锁机           │
├────────────────────────────────────────────────────────────────────────┤
│ 第 4 层：4 级风险裁决与极简可信白名单                                  │
│ • 输出：高危告警 / 已知工具 / 前置留意 / 安全合规                      │
│ • 默认白名单仅保留 WQGuard 自身，第三方越权工具一律据实检出绝不漏报    │
└────────────────────────────────────────────────────────────────────────┘
```

#### 🌐 固件 CVE 暴露雷达与多平台防 Brotli 溢出护盾矩阵 (`CVE-2026-111497`)
针对停留在未修补固件的 iOS 26.x 与 iOS 27.0–27.2 设备，实时评估 **8 项 2026 高危系统漏洞**，并为 iOS 五大主流网络代理客户端提供开箱即用的**防 Brotli 溢出降级护盾**（防御 `CVE-2026-111497` / `HTTP2Shell` `libbrotli` 堆溢出远程代码执行，CVSS 9.2）：

- **双层零解压拦截**：请求层将 `Accept-Encoding` 强制降级为 `gzip, deflate`；响应层采用**零响应体解压**（`requires-body=false` / `script-response-header`）直接阻断恶意服务端强行回传的 `Content-Encoding: br` 畸形流，避免代理进程或系统 `WebKit`/`CFNetwork` 触发漏洞。
- **零耗电、零断网默认策略**：全部 5 款客户端规则统一内置 `-*.apple.com`、`-guzzoni.apple.com`（普通话 Siri）、`-*.siri.apple.com`、`-apple-relay.*`、`-*.openai.com`、`-*.alipay.com`、`-*.tenpay.com` 等 **16 项严苛负向排除规则**，默认仅针对 `*.xyz`、`*.top`、`*.icu`、`*.click`、`*.zip` 等 **20 类黑产钓鱼高频后缀**开启 MITM，日常挂机零额外耗电、绝不影响银行与主流 App 正常联网（切勿在日常将附加域名设为全局 `*`）。

##### 📥 五大代理客户端一键订阅列表（也可在 WQGuard App「固件雷达」内一键唤起导入）

| 客户端 | 规则格式 | 仓库文件 | 在线订阅直链（复制填入客户端即可） | 启用要点 |
|---|---|---|---|---|
| **Surge** | `.sgmodule` | [`WQGuard-Brotli-Shield.sgmodule`](Shields/Surge/WQGuard-Brotli-Shield.sgmodule) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Surge/WQGuard-Brotli-Shield.sgmodule` | 导入「模块」，开启 `MitM` 与 CA 证书信任 |
| **Shadowrocket (小火箭)** | `.module` | [`WQGuard-Brotli-Shield.module`](Shields/Shadowrocket/WQGuard-Brotli-Shield.module) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Shadowrocket/WQGuard-Brotli-Shield.module` | 导入「配置 → 模块」，开启「HTTPS 解密」与证书信任 |
| **Quantumult X (圈 X)** | `.conf` | [`WQGuard-Brotli-Shield.conf`](Shields/QuantumultX/WQGuard-Brotli-Shield.conf) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/QuantumultX/WQGuard-Brotli-Shield.conf` | 添加至「重写 → 资源引用」，开启「重写」与「MitM」开关 |
| **Loon** | `.plugin` | [`WQGuard-Brotli-Shield.plugin`](Shields/Loon/WQGuard-Brotli-Shield.plugin) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Loon/WQGuard-Brotli-Shield.plugin` | 导入「配置 → 插件」，开启「MITM」与证书信任 |
| **Stash** | `.stoverride` | [`WQGuard-Brotli-Shield.stoverride`](Shields/Stash/WQGuard-Brotli-Shield.stoverride) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Stash/WQGuard-Brotli-Shield.stoverride` | 导入「覆写 (Overrides)」，开启「MITM」与根证书信任 |

##### 📊 8 项 2026 固件高危漏洞评估矩阵

| 漏洞编号 / 标识 | 受影响子系统 | 风险等级 | 受影响固件范围 | 免升级防护方案 |
|---|---|---|---|---|
| **0day:worse_query** | `containermanagerd` 沙盒逃逸 | 🔴 高危 (8.8) | iOS 26.0 – 27.2.1+ | 安装侧载应用前使用 WQGuard 审查 `.ipa`，拦截越权 App Group 利用 |
| **CVE-2026-111497** | `libbrotli` 堆越界写 (`HTTP2Shell`) | 🔴 高危 (9.2) | iOS < 27.2.1 / 26 < 26.7.3 | 导入上方 Surge / 小火箭 / 圈 X / Loon / Stash 防 Brotli 护盾（需开启 `MitM`） |
| **CVE-2026-112676** | Photos 相册 TCC 权限绕过 | 🔴 高危 (7.5) | iOS < 27.2 / 26 < 26.7.2 | 切勿在系统相册存放助记词截图；用 WQGuard 排查私有相册框架引用 |
| **CVE-2026-112611** | CoreGraphics PDF 越界写 | 🔴 高危 (8.8) | iOS < 27.2 / 26 < 26.7.2 | 关闭微信 / Telegram 文件自动下载，避免预览未知来源 PDF |
| **CVE-2026-86950** | CoreGraphics 2D 渲染引擎 | 🔴 高危 (8.6) | iOS < 27.0 | 关闭聊天软件自动加载图片与陌生群媒体预渲染 |
| **CVE-2026-113963** | App Intents 快捷指令提权 | 🟠 留意 (7.8) | iOS < 27.2.1 | 定期清理来源不明的第三方快捷指令与自动化规则 |
| **CVE-2026-113960/1** | iMessage Blastdoor 信息泄露 | 🔴 高危 (8.1) | iOS < 27.2.1 / 26 < 26.7.3 | 开启「设置 → 信息 → 过滤未知发件人」 |
| **CVE-2026-113964..70** | 蓝牙 CoreUtils 与 AirPlay | 🔴 高危 (8.8) | iOS < 27.2.1 / 26 < 26.7.3 | 将「隔空播放到电视」设为「从不」；公共场所从系统设置彻底关闭蓝牙 |

---

### 3. 快速上手指南

#### 第一步：下载与安装 iOS 应用
1. 前往 **[GitHub Releases](https://github.com/Kianuni/WQGuard/releases/latest)** 下载最新的 `WQGuard_v1.2.0.ipa`。
2. 使用任意主流工具安装至 iPhone / iPad：
   - **Feather / 全能签 / SideStore / AltStore / Sideloadly**：导入 `.ipa` 使用个人 Apple ID 或开发者证书签名安装；
   - **TrollStore**：直接用 TrollStore 打开安装；
   - **Xcode 源码运行**：在 Mac 上打开 `WQGuard.xcodeproj`，配置个人 Team 真机编译运行。

#### 第二步：扫描本机已安装应用（App 内置保姆级图文教程）
打开 WQGuard 点击首页 **「配置已安装扫描源」**，在 **方式 A** 与 **方式 B** 中任选其一即可：
- **新手最简 · 方式 B（Mac 导出离线快照，无需 VPN）**：
  1. iPhone 用数据线连接 Mac 并点击「信任」；
  2. 在 Mac「终端」运行：
     ```bash
     python3 -m pip install --user -U pymobiledevice3
     python3 -m pymobiledevice3 apps list > ~/Desktop/installed_apps.json
     ```
  3. 将桌面生成的 `installed_apps.json` 隔空投送（AirDrop）到手机，选择「用 WQGuard 打开」即刻完成全机扫描！
- **无线进阶 · 方式 A（LocalDevVPN 配对直连，后续脱离电脑随时扫）**：
  1. 手机从 App Store 免费安装 `LocalDevVPN`；
  2. 用 Mac `jitterbugpair` 生成一次 `<UDID>.mobiledevicepairing`（或复用已有的 SideStore / StikDebug 配对文件）传到手机导入引擎 1A；
  3. 若系统为 iOS 26.4+ / iOS 27，点击引擎 1A 内的橙色同网段按钮一键复制 `Tunnel IP` 与 `Device IP` 粘贴至 `LocalDevVPN` 重连，即可随时一键无线直连扫描全机。
- **多选 `.ipa` 深度联动（引擎 2 / IPA 审查页）**：
  - 点击 **「选择 .ipa 文件加入扫描（支持多选）」**，在系统「文件」中一次勾选一个或多个 `.ipa` / `.tipa` 安装包加入扫描列表，即可对主程序与嵌入动态库执行完整 4 层反编译审计。

---

### 4. macOS 命令行工具 (`wqguard-cli`) 与源码构建

#### 环境要求
- macOS 14.0+ / Xcode 16.0+ / Swift 6.0 工具链

#### 克隆与构建命令
```bash
git clone https://github.com/Kianuni/WQGuard.git
cd WQGuard

# 1. 运行全部 664 项单元测试
swift test

# 2. 编译 macOS 终端命令行工具 wqguard-cli
swift build -c release --product wqguard-cli

# 3. 免证书打包生成 iOS 安装包 (.ipa)
./scripts/ipabuild.sh --output build/WQGuard.ipa
```

#### `wqguard-cli` 常用示例
```bash
# 扫描本地未安装 IPA 并生成 Markdown 审计报告（发现高危时返回退出码 1，可用于 CI 门禁）
.build/release/wqguard-cli -i /path/to/suspicious.ipa --format markdown -o audit_report.md

# 评估指定 iOS 固件版本的 2026 CVE 暴露情况
.build/release/wqguard-cli -r 26.2

# 按文件后缀自动导出任意客户端的防 Brotli 护盾（支持 .sgmodule / .module / .conf / .plugin / .stoverride）
.build/release/wqguard-cli --export-shield ./WQGuard-Brotli-Shield.module
```

---

<a name="english"></a>
## 🇺🇸 English

### 1. Overview

**WQGuard** is a standalone, zero-dependency, **100% strictly read-only** open-source security scanner and firmware CVE posture advisor engineered for **iOS 26.2+ and iOS 27.x** devices (compatible with iOS 16.0+ and macOS Darwin hosts). It ships with two native targets and a standalone multi-client proxy shield collection:

1. **iOS Application (`WQGuard.app`)**: Native SwiftUI security scanner providing **3-engine exploit-free installed-app auditing**, **multi-select local `.ipa` / `.tipa` pre-install binary inspection**, **2026 Firmware CVE Exposure Radar**, **one-tap Multi-Client Brotli Shield import/export (`Surge`, `Shadowrocket`, `Quantumult X`, `Loon`, `Stash`)**, and RFC 8259 JSON / Markdown / PlainText report generation.
2. **macOS Host CLI (`wqguard-cli`)**: A standalone Darwin command-line binary for automated `.ipa` package inspection, container auditing, multi-format proxy shield export, and CI/CD security gating.
3. **Standalone Proxy Shield Collection ([`Shields/`](Shields/))**: Ready-to-subscribe MITM header-downgrade & zero-decompression response guards for all 5 major iOS proxy clients to mitigate `CVE-2026-111497` (`HTTP2Shell`).

WQGuard detects unauthorized cross-container sandbox escapes (`worse_query` / `bad_query` / `containermanagerd` confused-deputy exploits), repackaged Web3 crypto wallet drainers, private Photos TCC bypasses (`CVE-2026-112676`), injected tweak dylibs (`Frameworks/*.dylib`), and persistent background clipboard snooping — **without embedding or invoking any sandbox exploit itself**.

> **🔒 Core Security Guarantee: 100% Read-Only Physical Invariant**  
> Under no circumstances does WQGuard modify, create, rewrite, truncate, or touch any inspected binary, container metadata, or system file. Every inspection pass strictly uses `O_RDONLY | O_NOFOLLOW | O_CLOEXEC` descriptors, non-traversing `lstat` / `readlink` symlink checks, and read-only `.mappedIfSafe` memory mapping, continuously verified by **664 automated unit tests**.

---

### 2. Key Capabilities

#### 🛡️ 3-Engine Exploit-Free Installed-App Audit Architecture
Standard sideloaded iOS apps are blocked by Apple Seatbelt from enumerating `/var/containers/Bundle/Application`. WQGuard overcomes this cleanly via three standard, user-authorized engines:

- **Engine 1A · On-Device Wireless Pairing Direct (`LocalDevVPN` + Pairing File)**:
  - Import a `.mobiledevicepairing` / `.plist` pairing record generated once via `jitterbugpair` (or reused from SideStore / StikDebug) via the Files picker, one-tap Clipboard paste, or auto-discovery from `On My iPhone → WQGuard`.
  - Connects over `LocalDevVPN` directly to iOS's official `com.apple.mobile.installation_proxy` service to audit full `Entitlements`, `App Groups`, TCC bypass keys, and code-signing identities across all installed apps.
  - **Built-in iOS 26.4+ / iOS 27 Same-Subnet Helper**: Automatically inspects your active Wi-Fi subnet and provides one-tap copy buttons for aligned `Tunnel IP` and `Device IP` to satisfy modern `lockdownd` subnet validation.
- **Engine 1B · Offline Registry Snapshot Import (Zero VPN · 100% iOS 27 Compatible)**:
  - Export `installed_apps.json` from a Mac in seconds using `pymobiledevice3` or Apple's built-in `xcrun devicectl` and AirDrop it to WQGuard.
  - **Zero System-App False Positives & Accurate Channel Classification**: Filters out Apple system daemons/apps (`/System/Library/`, `/Applications/`, platform binaries) and accurately distinguishes **`🛠️ Sideloaded`**, **`🏢 Enterprise`**, **`✈️ TestFlight`** (`BetaReportsActive` / beta provisioning profiles), and **`🍏 App Store`** distributions.
- **Engine 2 · Multi-Select `.ipa` Scan Queue & Binary Correlation**:
  - Select multiple `.ipa` / `.tipa` packages at once in the iOS Files picker (or export signed IPAs from Feather via `Export IPA -> Open in WQGuard`) into a persistent local scan list supporting per-item removal, batch rescan, and automatic `Bundle ID` correlation with Engine 1 registry records (`🔬 Full Registry + Binary Audit`).
- **Engine 3 · Zero-Config On-Device Environment Probe**:
  - Uses standard `UIApplication.canOpenURL` probes to inventory installed sideload signers (Feather, ESign, SideStore, AltStore, GBox, Scarlet) and unsandboxed/bootstrap utilities (TrollStore, Filza, Sileo, etc.).

#### 🔬 4-Layer Progressive Static Mach-O Pipeline
1. **Layer 1 — Channel Classification & CSBlob Entitlement Gating**: Parses `LC_CODE_SIGNATURE` SuperBlobs in both XML (`0xfade7171`) and ASN.1 DER (`0xfade7172`) formats; apps without `com.apple.security.application-groups` are fast-pathed as `Safe` against `containermanagerd` escapes.
2. **Layer 2 — Mach-O Binary, Symbol & Behavioral Tuple Analysis**: Scans main executables, `Frameworks/*.dylib`, and `PlugIns/*.appex` for `libsystem_containermanager.dylib`, `container_query_*`, `com.apple.containermanagerd` XPC strings, `fsgetpath` inode brute-forcing, and XOR-resistant behavioral tuples (`cryptid == 0 ∧ AppGroups ∧ dlopen/dlsym ∧ symlink/sandbox_extension_consume`).
3. **Layer 3 — Escaping Symlink & Rogue Supervision Inspection**: Uses `lstat` + `readlink` (`O_NOFOLLOW`) to detect `Library/Caches` symlink traversals and unauthorized `CloudConfigurationDetails.plist` (`IsSupervised == true`).
4. **Layer 4 — 4-Tier Risk Grading & Minimal Whitelist**: Classifies findings into **High Risk**, **Known Tool**, **Caution**, or **Safe**. By default, **only `WQGuard` itself is whitelisted**, ensuring third-party exploit utilities are never silently exempted unless explicitly added by the user.

#### 🌐 Firmware CVE Exposure Radar & 5-Client Brotli Shield Matrix (`CVE-2026-111497`)
Evaluates **8 critical 2026 iOS CVEs** for devices remaining on iOS 26.x or iOS 27.0–27.2 and ships ready-to-import **Brotli Downgrade Shields** across all 5 major iOS MITM proxy clients to mitigate **`CVE-2026-111497` (`HTTP2Shell` `libbrotli` heap out-of-bounds write, CVSS 9.2)**:

- Rewrites outgoing `Accept-Encoding` headers to `gzip, deflate` and enforces a **zero-body-decompression** (`requires-body=false` / `script-response-header`) HTTP response guard that drops unsolicited `Content-Encoding: br` streams with `HTTP 403` before reaching WebKit/`CFNetwork`.
- Ships with **16 mandatory negative MITM exclusions** (`-*.apple.com`, `-guzzoni.apple.com`, `-*.siri.apple.com`, `-apple-relay.*`, `-*.openai.com`, `-*.binance.com`, `-*.alipay.com`, `-*.tenpay.com`, etc.) and targets 20 high-risk phishing TLDs by default for **zero battery drain and zero SSL-pinning breakage** on everyday apps.

| Proxy Client | Format | Repository File | Direct Subscription URL | Setup Note |
|---|---|---|---|---|
| **Surge** | `.sgmodule` | [`WQGuard-Brotli-Shield.sgmodule`](Shields/Surge/WQGuard-Brotli-Shield.sgmodule) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Surge/WQGuard-Brotli-Shield.sgmodule` | Import into **Modules**, enable **MitM** + CA trust |
| **Shadowrocket** | `.module` | [`WQGuard-Brotli-Shield.module`](Shields/Shadowrocket/WQGuard-Brotli-Shield.module) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Shadowrocket/WQGuard-Brotli-Shield.module` | Import into **Config → Module**, enable **HTTPS Decryption** + CA trust |
| **Quantumult X** | `.conf` | [`WQGuard-Brotli-Shield.conf`](Shields/QuantumultX/WQGuard-Brotli-Shield.conf) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/QuantumultX/WQGuard-Brotli-Shield.conf` | Add to **Rewrite → Resources**, enable **Rewrite** & **MitM** |
| **Loon** | `.plugin` | [`WQGuard-Brotli-Shield.plugin`](Shields/Loon/WQGuard-Brotli-Shield.plugin) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Loon/WQGuard-Brotli-Shield.plugin` | Import into **Plugins**, enable **MITM** + CA trust |
| **Stash** | `.stoverride` | [`WQGuard-Brotli-Shield.stoverride`](Shields/Stash/WQGuard-Brotli-Shield.stoverride) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Stash/WQGuard-Brotli-Shield.stoverride` | Import into **Overrides**, enable **MITM** + root CA trust |

---

### 3. Quick Start & Building from Source

#### Install Pre-Built IPA on iOS
Download the latest unsigned `WQGuard_v1.2.0.ipa` from **[GitHub Releases](https://github.com/Kianuni/WQGuard/releases/latest)** and install via **Feather**, **SideStore**, **AltStore**, **Sideloadly**, **TrollStore**, or build directly from `WQGuard.xcodeproj` in Xcode.

#### Build & Test on macOS
```bash
git clone https://github.com/Kianuni/WQGuard.git
cd WQGuard

# Run all 664 unit tests
swift test

# Build standalone macOS CLI
swift build -c release --product wqguard-cli

# Package unsigned iOS IPA (no Apple Developer certificate required)
./scripts/ipabuild.sh --output build/WQGuard.ipa
```

#### CLI Examples (`wqguard-cli`)
```bash
# Audit an uninstalled IPA and write a Markdown report (exits with code 1 on High Risk)
.build/release/wqguard-cli --ipa /path/to/app.ipa --format markdown -o report.md

# Evaluate iOS 26.2 firmware posture against 2026 CVEs
.build/release/wqguard-cli --firmware-radar 26.2

# Export Brotli Shield for any proxy client (.sgmodule / .module / .conf / .plugin / .stoverride)
.build/release/wqguard-cli --export-shield ./WQGuard-Brotli-Shield.stoverride
```

---

## 📄 License

Released under the **[MIT License](LICENSE)**.  
Copyright © 2026 WQGuard Contributors.
