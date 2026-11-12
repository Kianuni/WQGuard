# WQGuard 🛡️

**Standalone, Production-Grade, 100% Read-Only iOS Security Scanner & Firmware Posture Advisor**  
*Supporting iOS 26.2+ / iOS 27.x & macOS Darwin Hosts*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: iOS & macOS](https://img.shields.io/badge/Platform-iOS%2026.2%2B%20%7C%20iOS%2027.x%20%7C%20macOS-lightgrey.svg)]()
[![Swift: 6.0 Strict Concurrency](https://img.shields.io/badge/Swift-6.0%20Strict%20Concurrency-orange.svg)]()
[![Read-Only Invariant](https://img.shields.io/badge/Security-100%25%20Read--Only%20Guaranteed-success.svg)](SECURITY.md)

[English](#english) | [简体中文](#简体中文)

---

<a name="english"></a>
## English

### 1. Overview

**WQGuard** is an open-source, production-grade security scanner and firmware exposure analysis tool designed specifically for iOS 26.2+ and iOS 27.x environments. It operates across two targets:
1. **iOS Application (`WQGuard.app`)**: A modern SwiftUI dashboard with one-tap system scanning, local `.ipa` archive import via Document Picker / Share Sheet, interactive findings inspection, multi-format audit export, and Surge Brotli Shield export.
2. **macOS Host CLI (`wqguard-cli`)**: A zero-dependency Darwin command-line utility for automated batch auditing of `.ipa` packages, container directories, and firmware CVE exposure modeling.

WQGuard inspects installed applications across all distribution channels as well as uninstalled `.ipa` packages to detect unauthorized cross-container sandbox escapes (specifically `worse_query` / `bad_query` / `containermanagerd` exploits), 2026 firmware vulnerability exposures, repackaged cryptocurrency drainers, private photo framework theft, and injected dylib tweaks.

#### Core Security Guarantee: 100% Read-Only Invariant
WQGuard is engineered with a **zero-trust, 100% read-only invariant**. Under no circumstances does WQGuard modify, create, rewrite, truncate, or touch any inspected application binary, container metadata, or system file. All operations utilize strictly read-only file descriptors (`O_RDONLY | O_NOFOLLOW | O_CLOEXEC`), non-traversing `lstat` / `readlink` link inspections, memory-mapped buffers (`.mappedIfSafe`), and scoped RAII kernel sandbox token cleanup (`ScopedSandboxToken`).

---

### 2. Core Architecture: 4-Layer Progressive Pipeline

WQGuard implements a decoupled, high-performance 4-layer inspection pipeline:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        WQGuard Scanner Pipeline                        │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Install Channel & Entitlement Gating                          │
│ • Classifies: Sideloaded / Enterprise / TestFlight / App Store         │
│ • Parses LC_CODE_SIGNATURE CSBlob (XML 0xfade7171 & DER 0xfade7172)    │
│ • Fast-paths apps lacking com.apple.security.application-groups as Safe│
└────────────────────────────────────────────────────────────────────────┘
                                    │ (App Group Entitlement Present)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 2: Static Mach-O Binary, Symbol Table & String Scanner           │
│ • Inspects unencrypted (cryptid == 0) and FairPlay (cryptid == 1)      │
│ • Scans LC_LOAD_DYLIB for libsystem_containermanager.dylib             │
│ • Scans LC_SYMTAB for container_query_* and fsgetpath primitives       │
│ • Scans __cstring for direct XPC: com.apple.containermanagerd          │
│ • Evaluates Obfuscation-Resistant Behavioral Tuple                     │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 3: Shared App Group Container Artifact Inspector                 │
│ • Reads /var/mobile/Containers/Shared/AppGroup/<UUID>/ metadata       │
│ • Uses lstat & readlink with O_NOFOLLOW to detect escaping symlinks    │
│ • Scans Library/Caches (part = 3) for traversal targets outside root   │
│ • Inspects CloudConfigurationDetails.plist for Fake Supervision       │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 4: 4-Tier Risk Grading & Whitelist Engine                        │
│ • Evaluates evidence into: HIGH RISK, KNOWN TOOL, CAUTION, or SAFE     │
│ • Built-in transparent whitelist: Erosion, GestaltX, WQFiles, WQGuard  │
│ • Generates cryptographic AuditEvidence & multi-format reports         │
└────────────────────────────────────────────────────────────────────────┘
```

#### Detailed Layer Breakdown:
- **Layer 1: Channel Classification & Entitlement Gating**:
  - Classifies target into 4 install channels using Mach-O `cryptid` (`LC_ENCRYPTION_INFO_64`), `embedded.mobileprovision`, and App Store receipts.
  - Extracts embedded entitlements from `LC_CODE_SIGNATURE` SuperBlob (`0xfade0cc0`), supporting both XML plist (`0xfade7171` / slot 5) and ASN.1 DER (`0xfade7172` / slot 7).
  - Fast-path optimization: Applications lacking `com.apple.security.application-groups` are physically incapable of triggering the `containermanagerd` sandbox escape and are immediately classified as **Safe**.
- **Layer 2: Static Mach-O Binary & Symbol Scanning**:
  - Analyzes load commands (`LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`), symbol tables (`LC_SYMTAB`), and `__TEXT,__cstring`.
  - Target signatures: `libsystem_containermanager.dylib`, private C APIs (`container_query_create`, `container_query_set_group_identifiers`, `container_query_operation_set_part`, `container_query_operation_set_flags`, `container_copy_sandbox_token`, `sandbox_extension_consume`, `container_query_get_single_result`), direct XPC Mach services (`com.apple.containermanagerd`), and APFS inode brute-force primitives (`fsgetpath`).
  - **Obfuscation-Resistant Behavioral Tuple**: Catches XOR-encrypted or obfuscated PoCs by flagging unencrypted binaries (`cryptid == 0`) that combine: (a) `com.apple.security.application-groups` + (b) `dlopen`/`dlsym` + (c) symlink creation APIs (`symlink`, `symlinkat`) or `sandbox_extension_consume`/`fsgetpath`.
- **Layer 3: Shared Container Artifact Inspection**:
  - Performs 100% read-only bounds checking on `/var/mobile/Containers/Shared/AppGroup/<UUID>/` metadata and `LaunchServices` `CSStore2` caches.
  - Uses `lstat()` and `readlink()` to inspect `Library/Caches` (`part = 3`) for anomalous escaping symlinks pointing outside the container boundary without traversing into untrusted directories (`O_NOFOLLOW` invariant).
  - Inspects `systemgroup.com.apple.configurationprofiles` for unauthorized `CloudConfigurationDetails.plist` (`IsSupervised == true`).
- **Layer 4: 4-Tier Risk Grading & Whitelist Engine**:
  - **High Risk (高危告警)**: Unknown apps matching `containermanagerd` sandbox escape signatures, escaping symlinks, impersonated crypto wallets, or private photos framework bypasses.
  - **Known Tool (已知工具提示)**: Applications matching verified open-source utilities (`Erosion`, `Erosion-CN`, `GestaltX`, `WQFiles`, `WQFiles-CN`, `WQGuard`) with team ID and signature verification.
  - **Caution (前置条件留意)**: Sideloaded apps with App Group entitlement and dynamic loading (`dlopen`/`dlsym`), bundled `libbrotli` supply-chain notice, or injected tweak dylibs.
  - **Safe (安全)**: Clean apps lacking App Group entitlement or passing all scanning layers without indicators.

---

### 3. Surge Brotli Shield (`Surge/WQGuard-Brotli-Shield.sgmodule`)

To defend users on unpatched iOS 26.x and iOS 27.0–27.2 against **CVE-2026-111497** (`libbrotli` Heap Out-of-Bounds Write / `HTTP2Shell`, CVSS 9.2), WQGuard includes a battle-tested Surge protection module: `Surge/WQGuard-Brotli-Shield.sgmodule`.

#### Protection Mechanics:
1. **Network Header Downgrade (`[Header Rewrite]`)**:
   Strips `br` from outgoing HTTP/HTTPS `Accept-Encoding` request headers, forcing servers to negotiate safe `gzip` or `deflate` encoding:
   ```
   ^https?:// header-replace Accept-Encoding "gzip, deflate"
   ```
2. **Response Guard (`[Script]`)**:
   Blocks malicious non-compliant servers that attempt to force-send unsolicited `Content-Encoding: br` streams, dropping the stream with an HTTP 403 error before it reaches the vulnerable WebKit/CFNetwork Brotli decoder.
3. **16 Mandatory Negative MITM Exclusions (Zero Apple Intelligence or Banking Breakage)**:
   The module strictly exempts 16 mission-critical domains from MITM interception:
   - Apple Intelligence, Siri & Cloud: `-*.apple.com`, `-*.icloud.com`, `-*.icloud-content.com`, `-*.mzstatic.com`, `-*.cdn-apple.com`, `-guzzoni.apple.com` (Mandarin Siri), `-*.siri.apple.com`, `-gspe1-ssl.ls.apple.com`
   - Private Cloud Compute & Relay: `-apple-relay.*`, `-cp4.cloudflare.com`
   - OpenAI Integration: `-*.openai.com`, `-*.chatgpt.com`
   - Cert-Pinned Financial & Crypto Apps: `-*.binance.com`, `-*.okx.com`, `-*.tenpay.com` (WeChat Pay), `-*.alipay.com` (Alipay)
4. **In-App Helper & One-Tap Export**:
   `SurgeBrotliShieldHelper.swift` allows users to validate, customize extra MITM domains (`{{{EXTRA_MITM_HOSTS}}}`), preview, and export the `.sgmodule` directly into Surge via the iOS Share Sheet or CLI `--export-surge <path>`.

---

### 4. Firmware CVE Exposure Radar & Non-Upgrade Advisor

For security researchers and device owners intentionally staying on older iOS 26.x or iOS 27.0–27.2 builds (e.g. for TrollStore or research stability), WQGuard evaluates 8 tracked 2026 firmware vulnerabilities and delivers actionable, non-upgrade mitigations:

| CVE / Identifier | Subsystem | Severity | Affected Firmware | Non-Upgrade Mitigation |
|---|---|---|---|---|
| **0day:worse_query** | `containermanagerd` | High Risk (8.8) | iOS 26.0 – 27.2.1+ | Scan all sideloaded IPAs with WQGuard prior to launching; block App Group exploits. |
| **CVE-2026-112676** | Photos / TCC | High Risk (7.5) | iOS < 27.2 / 26 < 26.7.2 | Never store seed phrases/private keys in Photos; audit apps with WQGuard Photos rule. |
| **CVE-2026-111497** | `libbrotli` (HTTP2Shell) | High Risk (9.2) | iOS < 27.2.1 / 26 < 26.7.3 | Enable Surge Brotli Shield module; enable Lockdown Mode for untrusted links. |
| **CVE-2026-112611** | CoreGraphics PDF | High Risk (8.8) | iOS < 27.2 / 26 < 26.7.2 | Disable automatic file download in Telegram/WeChat; never preview untrusted PDFs locally. |
| **CVE-2026-86950** | CoreGraphics 2D | High Risk (8.6) | iOS < 27.0 | Disable image pre-rendering in chat apps; avoid rendering untrusted ICC profiles. |
| **CVE-2026-113963** | App Intents | Caution (7.8) | iOS < 27.2.1 | Periodically audit unfamiliar Shortcuts and App Intents automation rules. |
| **CVE-2026-113960/1** | iMessage Blastdoor | High Risk (8.1) | iOS < 27.2.1 / 26 < 26.7.3 | Enable "Filter Unknown Senders" in Messages; never share wallet secrets in group chats. |
| **CVE-2026-113964..70**| Bluetooth & AirPlay | High Risk (8.8) | iOS < 27.2.1 / 26 < 26.7.3 | Set AirPlay to "Never" in Settings; turn off Bluetooth from Settings (not Control Center). |

---

### 5. Expanded Threat Signatures

WQGuard detects modern real-world iOS threats beyond container escapes:
1. **Private Photos Framework Bypass (`CVE-2026-112676` Vector)**:
   Detects unencrypted binaries referencing Apple private photo frameworks (`PhotoLibraryServices`, `AssetsLibraryServices`, `PLPhotoLibrary`) or internal entitlements (`com.apple.private.photos.*`, `com.apple.photos.bourgeoisie`) used to bypass TCC privacy prompts.
2. **Bundled Vulnerable `libbrotli` Detection (`CVE-2026-111497`)**:
   Surfaces supply-chain caution notices when third-party apps embed `libbrotli*.dylib` or `BrotliDecoderDecompressStream` without verifying Brotli >= 1.2.1.
3. **Repackaged Crypto Wallet & Messenger Impersonation (High Risk Drainer Vector)**:
   Flags unencrypted sideloaded packages (`cryptid == 0`) whose display name or bundle ID impersonates major Web3 wallets or encrypted messengers: MetaMask, Trust Wallet, Phantom, OKX, Binance, TokenPocket, imToken, Bitget, and Telegram.
4. **Injected Dylibs & Modded IPA Tweaks**:
   Enumerates hooking frameworks (`CydiaSubstrate`, `libsubstitute`, `ElleKit`, `libhooker`, `Shadow`, `Choicy`) and suspicious tweaks in `@executable_path/Frameworks/` or `@rpath/`.
5. **Background Clipboard Snooping Tuple**:
   Detects unencrypted sideloaded apps combining persistent `UIBackgroundModes` (`audio`, `location`, `voip`) with `UIPasteboard` / `generalPasteboard` access (used to steal copied seed phrases).
6. **Fake Supervision / Rogue Configuration Profile**:
   Inspects `systemgroup.com.apple.configurationprofiles` read-only for unauthorized `CloudConfigurationDetails.plist` (`IsSupervised == true`) preventing setup assistant lockouts.

---

### 6. macOS Host CLI (`wqguard-cli`)

The `wqguard-cli` tool is a zero-dependency, standalone Darwin executable compiled directly via Swift Package Manager.

#### CLI Syntax & Options:
```bash
wqguard-cli [options]
```

| Option | Description |
|---|---|
| `-s, --scan-system` | Scan installed applications on current machine/target using `SecurityPipeline` and `CSStore2`. |
| `-i, --ipa <path>` | Inspect local uninstalled `.ipa` archive using `IPAPackageScanner`. |
| `-c, --container <path>` | Inspect App Group container directory using `ContainerScanner`. |
| `-r, --firmware-radar [os_ver]` | Evaluate OS version against 8 2026 CVEs using `FirmwarePostureEngine` (default: host OS). |
| `--export-surge <path>` | Export `WQGuard-Brotli-Shield.sgmodule` with 16 negative exclusions via `SurgeBrotliShieldHelper`. |
| `--format <text\|json\|markdown>`| Output report format (default: `text`). |
| `-o, --out <path>` | Write report to specified file path instead of stdout. |
| `--whitelist <bundleID>` | Temporarily whitelist specific bundle ID for this scan run (repeatable). |
| `-v, --version` | Print CLI engine version information. |
| `-h, --help` | Show usage manual and examples. |

#### Exit Codes:
- `0`: Scan completed successfully with no High Risk findings (clean, safe, caution, or whitelisted).
- `1`: High Risk findings detected (`RiskTier.highRisk`). Ideal for CI/CD gating!
- `2`: Usage error, invalid arguments, or missing target file.

#### CLI Usage Examples:
```bash
# 1. Audit an uninstalled IPA file and output Markdown report
wqguard-cli -i /path/to/suspicious.ipa --format markdown -o audit_report.md

# 2. Audit an uninstalled IPA file and output JSON for automated pipelines
wqguard-cli --ipa /path/to/app.ipa --format json

# 3. Evaluate iOS 26.2 firmware posture against 2026 CVEs
wqguard-cli -r 26.2

# 4. Export Surge Brotli Shield configuration module
wqguard-cli --export-surge ./WQGuard-Brotli-Shield.sgmodule

# 5. Scan a container directory with a temporary whitelist override
wqguard-cli -c /var/mobile/Containers/Shared/AppGroup/UUID --whitelist com.example.internal
```

---

### 7. Building & Installation Guide

#### Prerequisites:
- macOS 14.0+ (Sonoma) or macOS 15.0+ (Sequoia) / Darwin 27.x+
- Xcode 16.0+ with iOS 18+ SDK
- Swift 6.0 toolchain

#### 1. Building the macOS Host CLI (`wqguard-cli`):
```bash
# Clone the repository
git clone https://github.com/Kianuni/WQGuard.git
cd WQGuard

# Build release CLI executable
swift build -c release --product wqguard-cli

# Run host unit tests (580+ tests passing)
swift test
```

#### 2. Building the iOS Application & Packaging IPA:
WQGuard provides a standalone packaging script `./scripts/ipabuild.sh` that builds and pseudo-signs the iOS app without requiring a paid Apple Developer certificate:
```bash
# Make script executable
chmod +x ./scripts/ipabuild.sh

# Run standalone packaging pipeline
./scripts/ipabuild.sh --output WQGuard.ipa
```
The script automatically:
1. Runs host unit tests to prevent building broken packages.
2. Invokes headless `xcodebuild` targeting `generic/platform=iOS`.
3. Sanitizes code signatures and provisioning profiles.
4. Pseudo-signs the app bundle with entitlements (`WQGuard.entitlements`) using `ldid` or `codesign --generate-entitlement-der`.
5. Verifies IPA package integrity and signs payload into a clean `.ipa`.

#### 3. Installing on iOS:
- **TrollStore**: Share or transfer `WQGuard.ipa` to your device and open with TrollStore. TrollStore grants container access entitlements without revoking.
- **AltStore / Sideloadly**: Sideload `WQGuard.ipa` with personal developer certificate.
- **Direct Xcode Deployment**: Open `WQGuard.xcodeproj` in Xcode, select your personal signing team, and run on a connected iPhone or iPad.

---

### 8. Vendor Branding & Open-Source Governance

- **Clean Vendor Identifiers**:
  - Application Bundle Identifier: `com.wqguard.app`
  - Application Group Identifier: `group.com.wqguard.app`
  - Dedicated Scanner Group Identifier: `group.com.wqguard.scanner`
  - Zero personal usernames, machine paths, or third-party author identities are leaked in WQGuard's bundle metadata or source code.
- **Third-Party Whitelist Clarification**:
  - The domain `cz.kolbi.*` is exclusively recognized within `WhitelistEngine.swift` as the identity of the third-party open-source file utility `WQFiles` (developed by Kolbi). WQGuard is an independent project licensed under MIT.

---

<a name="简体中文"></a>
## 简体中文

### 1. 项目简介

**WQGuard** 是一款专为 iOS 26.2+ 与 iOS 27.x 系统打造的独立、生产级、**100% 只读**开源安全检测工具与固件风险评估系统。项目包含两大核心组件：
1. **iOS 原生应用 (`WQGuard.app`)**：现代化 SwiftUI 仪表盘，支持一键系统全盘扫描、通过系统文件选择器（Document Picker）或分享面板（Share Sheet）本地导入未安装 `.ipa` 文件审计、多维度风险证据深度溯源、多格式（JSON / Markdown / PlainText）合规报告导出，以及内置 Surge Brotli 降级护盾模块导出。
2. **macOS 终端 CLI 工具 (`wqguard-cli`)**：基于 Darwin 底层的零依赖静态命令行工具，专为终端用户与 CI/CD 自动化检测流水线设计。

WQGuard 能够全面扫描全渠道安装的应用与本地 `.ipa` 安装包，精准排查跨容器沙盒逃逸漏洞（`worse_query` / `bad_query` / `containermanagerd`）、2026 年最新系统固件 CVE 暴露风险、冒充 Web3 钱包的钓鱼盗币木马（Drainer）、利用私有相册框架窥探隐私、以及内嵌注入插件外挂。

#### 核心安全守则：100% 只读物理不变量
WQGuard 始终奉行**零信任、100% 绝对只读**原则。在任何场景下，WQGuard 绝不篡改、创建、覆写、截断或触碰任何被检测的目标二进制文件、容器元数据、系统配置或目录。所有检测动作均严格依托只读文件描述符（`O_RDONLY | O_NOFOLLOW | O_CLOEXEC`）、非递归符号链接检测（`lstat` / `readlink`）、只读内存映射（`.mappedIfSafe`）以及 RAII 作用域内核沙盒令牌自动释放机制（`ScopedSandboxToken`）。

---

### 2. 核心架构：4 层渐进式检测流水线

WQGuard 采用分层解耦的渐进式检测引擎：

```
┌────────────────────────────────────────────────────────────────────────┐
│                        WQGuard 核心检测流水线                          │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 第 1 层：安装渠道识别与 Entitlement 门禁过滤                           │
│ • 智能识别 4 大分发渠道：个人侧载 / 企业证书 / TestFlight / App Store  │
│ • 双模解析 LC_CODE_SIGNATURE CSBlob（XML 0xfade7171 与 DER 0xfade7172）│
│ • 无 com.apple.security.application-groups 权限的应用直接判定安全合规   │
└────────────────────────────────────────────────────────────────────────┘
                                    │ (具备 App Group 权限)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 第 2 层：静态 Mach-O 二进制、符号表与字符串深度扫描                    │
│ • 支持无加密（cryptid == 0）与 FairPlay 加密（cryptid == 1）二进制     │
│ • 检索 LC_LOAD_DYLIB 动态库引用：libsystem_containermanager.dylib      │
│ • 检索 LC_SYMTAB 符号表：container_query_* 与 fsgetpath 遍历原语       │
│ • 检索 __cstring 原生 XPC 绕过服务：com.apple.containermanagerd         │
│ • 评估抗混淆行为特征元组（Behavioral Tuple）                           │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 第 3 层：共享 App Group 容器痕迹与逃逸符号链接排查                     │
│ • 只读解析 /var/mobile/Containers/Shared/AppGroup/<UUID>/ 容器元数据   │
│ • 运用 lstat 与 readlink (O_NOFOLLOW) 探查 Library/Caches (part = 3)   │
│ • 精准检测指向容器边界外的逃逸符号链接，绝不向外递归遍历               │
│ • 探查 systemgroup 配置容器中伪造的 CloudConfigurationDetails.plist    │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 第 4 层：4 级风险裁决与已知开源工具白名单引擎                          │
│ • 裁决 4 级状态：高危告警、已知工具提示、前置条件留意、安全合规       │
│ • 内置透明已知工具白名单（Erosion、GestaltX、WQFiles、WQGuard 等）     │
│ • 生成具备可追溯链条的 AuditEvidence 审计报告与证据导出                │
└────────────────────────────────────────────────────────────────────────┘
```

#### 分层技术要点：
- **第 1 层：安装渠道识别与权限门禁**：
  - 结合 Mach-O `LC_ENCRYPTION_INFO_64` 中的 `cryptid`、`embedded.mobileprovision` 描述文件及应用收据，精准判定个人侧载、企业内部分发、TestFlight 测试版及 App Store 正式版。
  - 支持解析代码签名超块（`0xfade0cc0`）中的 XML plist（`0xfade7171`）及现代 Xcode 生成的 ASN.1 DER（`0xfade7172`）双格式。
  - **门禁快速通道**：未声明 `com.apple.security.application-groups` 的应用在物理层面无法触发 `containermanagerd` 跨容器提权，系统立即将其标记为**安全合规（Safe）**，大幅节约算力。
- **第 2 层：静态 Mach-O 符号与行为元组扫描**：
  - 全面扫描加载命令（`LC_LOAD_DYLIB`）、导出/导入符号表（`LC_SYMTAB`）及 `__cstring` 字符串段。
  - 核心特征库：私有容器管理动态库 `libsystem_containermanager.dylib`、C 包装函数（`container_query_create`、`container_query_set_group_identifiers`、`container_query_operation_set_part`、`container_query_operation_set_flags`、`container_copy_sandbox_token`、`sandbox_extension_consume`、`container_query_get_single_result`）、直接 XPC 通信 Mach 服务（`com.apple.containermanagerd`）、以及 APFS Inode 暴力枚举原语（`fsgetpath`）。
  - **抗混淆行为特征元组**：针对字符串异或加密的高级逃逸样本，只要未加密二进制（`cryptid == 0`）同时满足：(a) 包含 App Group 权限（AMFI 强制明文校验不可混淆）+ (b) 包含动态加载原语（`dlopen`/`dlsym`）+ (c) 包含符号链接创建接口（`symlink`/`symlinkat`）或沙盒扩展消费接口，即判定为高危行为元组！
- **第 3 层：共享容器逃逸符号链接排查**：
  - 只读分析 App Group 容器目录及 LaunchServices `CSStore2` 数据库。
  - 利用 POSIX `lstat` 与 `readlink` 检查 `Library/Caches`（`part = 3`）。若发现该路径被替换为指向容器外部的软链接（如指向 `/private/var/mobile/Containers/Data/Application` 或 `/etc/`），立即触发高危告警，并严格禁止向下递归，杜绝受骗替身风险。
  - 探查 `systemgroup.com.apple.configurationprofiles` 中是否存在非官方残留的 `CloudConfigurationDetails.plist`（`IsSupervised == true`）。
- **第 4 层：4 级风险裁决与白名单匹配**：
  - **高危告警 (HIGH_RISK)**：未知应用命中 `containermanagerd` 逃逸特征、容器内存在越界软链接、冒充加密钱包、或非法调用相册私有框架。
  - **已知工具提示 (KNOWN_TOOL)**：应用匹配经过安全社区公开审计的开源工具白名单（如 `Erosion`、`Erosion-CN`、`GestaltX`、`WQFiles`、`WQFiles-CN`、`WQGuard` 本身），提示为安全研究工具而非恶意攻击。
  - **前置留意 (CAUTION)**：侧载应用声明了 App Group 且具备动态调用能力、内嵌未确认版本的 `libbrotli`、或发现内嵌调试挂钩 dylib。
  - **安全合规 (SAFE)**：未声明共享权限或经检测完全合规的应用。

#### v1.1.0 三引擎「已安装应用」无漏洞全面审计架构：
- **引擎 1（`installation_proxy` 系统注册表审计）**：支持导入 `.mobiledevicepairing` 配对文件配合 LocalDevVPN（`10.7.0.1`）在手机本机直连 `lockdownd` / `com.apple.mobile.installation_proxy`，或离线导入 `.plist` / `.xml` / `.json` 注册表快照，读取全机所有已安装应用的完整 `Entitlements`、共享容器、TCC 隐私绕过权限、签名证书链与钱包/IM 仿冒特征。
- **引擎 2（签名器源包自动关联深扫）**：绑定全能签、Feather、SideStore 等目录后，按 `Bundle ID` 自动关联本地 `.ipa` 源包，补齐 Mach-O 私有符号与 `Frameworks/*.dylib` 注入库字节级深扫。
- **引擎 3（本机零配置在位探针）**：基于标准 `canOpenURL` 探针清单盘点本机已安装的侧载签名工具与高权限环境组件（如 Filza、TrollStore、Sileo 等），并在报告中以 `AuditDepth` 徽章透明标注每款应用的审计深度。

---

### 3. Surge Brotli 降级护盾 (`Surge/WQGuard-Brotli-Shield.sgmodule`)

针对驻留在老版本 iOS 26.x 与 iOS 27.0–27.2 系统上、未修复 **CVE-2026-111497**（`libbrotli` 堆越界写高危代码执行漏洞 / `HTTP2Shell`, CVSS 9.2）的用户，WQGuard 开源提供了经实战检验的 Surge 代理防护模块：`Surge/WQGuard-Brotli-Shield.sgmodule`。

#### 防护机制：
1. **传输层头部强制降级 (`[Header Rewrite]`)**：
   在客户端发起的 HTTP/HTTPS 请求中，实时剥离 `Accept-Encoding` 头中的 `br` 算法声明，强制服务端回落到成熟稳定的 `gzip, deflate` 压缩编码：
   ```
   ^https?:// header-replace Accept-Encoding "gzip, deflate"
   ```
2. **响应层非法回传防御 (`[Script]`)**：
   内置轻量级响应拦截脚本，拦截不遵循客户端协商、强行下发 `Content-Encoding: br` 的恶意服务端数据流，在触发 WebKit / CFNetwork 底层解码器前返回 HTTP 403 阻断。
3. **16 项严苛负向排除规则（保障 Apple Intelligence 与网银绝对不被破坏）**：
   严禁全流量盲目 MITM！内置必须排除的关键域名列表：
   - Apple 核心与 Siri：`-*.apple.com`, `-*.icloud.com`, `-*.icloud-content.com`, `-*.mzstatic.com`, `-*.cdn-apple.com`, `-guzzoni.apple.com`（普通话 Siri）, `-*.siri.apple.com`, `-gspe1-ssl.ls.apple.com`
   - 私有云计算与网络中继：`-apple-relay.*`, `-cp4.cloudflare.com`
   - OpenAI 深度整合：`-*.openai.com`, `-*.chatgpt.com`
   - 证书绑定之金融交易所：`-*.binance.com`, `-*.okx.com`, `-*.tenpay.com`（微信支付）, `-*.alipay.com`（支付宝）
4. **内置助手与一键导出**：
   通过 `SurgeBrotliShieldHelper.swift`，用户可在 iOS 应用仪表盘内直接预览配置、补充自定义防护域名（`{{{EXTRA_MITM_HOSTS}}}`）、并通过 iOS 分享面板一键导入 Surge；也可通过命令行 `wqguard-cli --export-surge` 导出。

---

### 4. 固件 CVE 暴露雷达与免升级防护建议

针对为保留特定系统特性（如 TrollStore 环境）而选择不升级固件的设备，WQGuard 内置固件姿态评估引擎，实时对比 8 项 2026 年度关键 CVE 并给出实操防护建议：

| 漏洞标识 / 别名 | 受影响子系统 | 风险等级 | 影响固件版本 | 免升级实操防护指引 |
|---|---|---|---|---|
| **0day:worse_query** | `containermanagerd` 沙盒逃逸 | 高危 (8.8) | iOS 26.0 – 27.2.1+ | 在安装并启动任何外部侧载或企业 IPA 前，必须通过 WQGuard 预检；阻断 App Group 提权。 |
| **CVE-2026-112676** | Photos 相册隐私授权绕过 | 高危 (7.5) | iOS < 27.2 / 26 < 26.7.2 | 切勿在系统相册保存助记词截图或机密证件；通过 WQGuard 排查调用私有相册接口的应用。 |
| **CVE-2026-111497** | `libbrotli` 堆越界写 (HTTP2Shell) | 高危 (9.2) | iOS < 27.2.1 / 26 < 26.7.3 | 开启 WQGuard Surge Brotli 降级护盾；在 Safari 中对不可信来源网址启用严格锁定模式。 |
| **CVE-2026-112611** | CoreGraphics 恶意 PDF 越界写 | 高危 (8.8) | iOS < 27.2 / 26 < 26.7.2 | 关闭 Telegram / 微信中文件的“自动下载媒体”选项；避免在系统快速预览中打开来源不明的 PDF。 |
| **CVE-2026-86950** | CoreGraphics 2D 引擎 0day | 高危 (8.6) | iOS < 27.0 | 关闭即时通讯软件中的图片自动渲染与预加载功能；避免解析非标准色彩配置图元。 |
| **CVE-2026-113963** | App Intents 快捷指令提权绕过 | 留意 (7.8) | iOS < 27.2.1 | 定期进入“快捷指令”应用，清理审计非官方共享的自动化流程与敏感权限。 |
| **CVE-2026-113960/1** | iMessage Blastdoor 群聊历史泄露 | 高危 (8.1) | iOS < 27.2.1 / 26 < 26.7.3 | 在系统“设置 -> 信息”中启用“过滤未知发件人”；切勿在多人 iMessage 群聊中传递敏感资产。 |
| **CVE-2026-113964..70**| 蓝牙 CoreUtils 零点击配对与 AirPlay | 高危 (8.8) | iOS < 27.2.1 / 26 < 26.7.3 | 将“隔空播放到电视”设为“从不”；在机场、车站等公共场所前往“设置 -> 蓝牙”彻底关闭蓝牙。 |

---

### 5. 扩展威胁特征库

除核心容器逃逸之外，WQGuard 深度覆盖了移动端实战常见威胁：
1. **相册私有框架非法调用 (`CVE-2026-112676` 攻击向量)**：
   检测未经授权链接 Apple 内部相册框架（`PhotoLibraryServices`、`AssetsLibraryServices`、`PLPhotoLibrary`）或声明内部相册私有权限（`com.apple.private.photos.*`、`com.apple.photos.bourgeoisie`）的恶意软件，防止其静默盗取相册照片。
2. **内嵌脆弱 `libbrotli` 供应链核验 (`CVE-2026-111497`)**：
   排查应用内嵌打包的 `libbrotli*.dylib` 动态库或相关解码符号，发出供应链提示以核验版本是否已升级至安全版本（>= 1.2.1）。
3. **冒充加密货币钱包与安全通讯软件（高危盗币木马 Drainer 向量）**：
   检测伪装成知名 Web3 钱包或加密通讯工具的未加密侧载包（`cryptid == 0`）：涵盖 MetaMask、Trust Wallet、Phantom、OKX、Binance、TokenPocket、imToken、Bitget 与 Telegram。官方应用均由 App Store 分发，此类二次打包安装包极大概率包含助记词嗅探后门！
4. **注入插件与外挂动态库枚举**：
   全面扫描 `LC_LOAD_DYLIB` 中加载的越狱挂钩框架（`CydiaSubstrate`、`libsubstitute`、`ElleKit`、`libhooker`、`Shadow`、`Choicy`）以及 `@executable_path/Frameworks/` 下的可疑补丁库。
5. **常驻后台剪贴板监听特征元组**：
   检测声明了常驻后台模式（`audio`、`location`、`voip`）并在二进制中引用 `UIPasteboard` 读取接口的应用，拦截暗中轮询复制板窃取私钥凭证的行为。
6. **伪造受监管状态与恶意描述文件排查**：
   以 100% 只读方式检查配置描述文件容器，检测异常激活的 `CloudConfigurationDetails.plist`（`IsSupervised == true`），预防零售设备因非授权 MDM 监管陷入无限设置死循环。

---

### 6. macOS 终端 CLI 工具 (`wqguard-cli`)

`wqguard-cli` 是基于 Swift 原生编译的轻量级 Darwin 终端工具，不依赖任何第三方动态库。

#### 命令行参数与选项：
```bash
wqguard-cli [选项]
```

| 参数选项 | 功能说明 |
|---|---|
| `-s, --scan-system` | 扫描当前设备/系统的已安装应用（结合 `SecurityPipeline` 与 `CSStore2` 数据库）。 |
| `-i, --ipa <路径>` | 扫描指定的未安装本地 `.ipa` 压缩归档包。 |
| `-c, --container <路径>` | 扫描指定的 App Group 共享数据容器目录。 |
| `-r, --firmware-radar [版本]`| 针对指定 iOS 版本（如 `26.2`）运行 2026 CVE 漏洞暴露雷达（省略参数时默认评估本机）。 |
| `--export-surge <路径>` | 导出包含 16 项负向排除规则的 `WQGuard-Brotli-Shield.sgmodule` Surge 模块文件。 |
| `--format <text\|json\|markdown>` | 设定报告输出格式（默认为 `text` 控制台着色文本）。 |
| `-o, --out <路径>` | 将扫描审计报告写入目标文件路径（取代默认的标准输出）。 |
| `--whitelist <BundleID>` | 针对本次运行临时将指定应用 Bundle ID 加入白名单（支持多次指定）。 |
| `-v, --version` | 输出 CLI 引擎的版本号与运行架构。 |
| `-h, --help` | 显示完整的命令行使用帮助手册。 |

#### 退出状态码 (Exit Codes)：
- `0`：检测完成，未发现高危告警（结果均为 Safe、Caution 或已知白名单工具）。
- `1`：**发现高危告警 (`RiskTier.highRisk`)**。非常适合作为 CI/CD 自动化构建的安全门禁！
- `2`：命令行参数错误、参数缺失或目标文件不存在。

#### 常用命令示例：
```bash
# 1. 扫描未安装的 IPA 文件，并将 Markdown 报告输出至文件
wqguard-cli -i ~/Downloads/test.ipa --format markdown -o report.md

# 2. 扫描 IPA 并输出结构化 JSON，便于自动化流水线处理
wqguard-cli --ipa /path/to/app.ipa --format json

# 3. 针对 iOS 26.2 系统评估 2026 年关键 CVE 固件风险
wqguard-cli -r 26.2

# 4. 导出 Surge 防 Brotli 溢出护盾模块
wqguard-cli --export-surge ./WQGuard-Brotli-Shield.sgmodule

# 5. 扫描容器目录并临时将内部测试包加入白名单
wqguard-cli -c /var/mobile/Containers/Shared/AppGroup/UUID --whitelist com.example.internal
```

---

### 7. 编译构建与安装指引

#### 构建环境要求：
- macOS 14.0+ (Sonoma) 或 macOS 15.0+ (Sequoia) / Darwin 27.x+
- Xcode 16.0+（包含 iOS 18+ SDK）
- Swift 6.0 编译工具链

#### 1. 编译 macOS CLI 工具：
```bash
# 克隆代码仓库
git clone https://github.com/Kianuni/WQGuard.git
cd WQGuard

# 编译 Release 版本命令行工具
swift build -c release --product wqguard-cli

# 运行自动化单元测试（580+ 测试用例全部通过）
swift test
```

#### 2. 构建 iOS 原生应用与打包 IPA：
WQGuard 提供了独立打包脚本 `./scripts/ipabuild.sh`，支持无需付费苹果开发者证书、采用 Ad-hoc / ldid 伪签名打包生产级 `.ipa`：
```bash
# 赋予执行权限
chmod +x ./scripts/ipabuild.sh

# 执行独立打包流水线
./scripts/ipabuild.sh --output WQGuard.ipa
```
该脚本将全自动完成：
1. 执行前置宿主单元测试，防止将包含回归缺陷的构建包打包。
2. 调用免签名 `xcodebuild` 命令编译 `generic/platform=iOS` 目标架构。
3. 清理残留签名文件并注入标准权限配置（`WQGuard.entitlements`）。
4. 运用 `ldid` 或 `codesign --generate-entitlement-der` 生成合规代码签名与 DER 证书。
5. 打包 Payload 结构并校验安装包完整性。

#### 3. iOS 设备安装方式：
- **TrollStore 安装**：将打包生成的 `WQGuard.ipa` 传送到 iOS 设备，在 TrollStore 中选择“Install”即可。TrollStore 将完整保留其 App Group 读取权限。
- **AltStore / Sideloadly 侧载**：使用个人免费 Apple ID 证书进行签名侧载。
- **Xcode 真机部署**：使用 Xcode 打开 `WQGuard.xcodeproj`，在 Signing & Capabilities 中配置您的个人证书，直接连接 iPhone / iPad 运行。

---

### 8. 品牌规范与开源声明

- **中立开源标识**：
  - 应用 Bundle Identifier：`com.wqguard.app`
  - 共享 App Group Identifier：`group.com.wqguard.app`
  - 专用沙盒扫描组：`group.com.wqguard.scanner`
  - WQGuard 绝不包含任何个人开发者机器本地路径或非中立作者标识。
- **第三方开源工具白名单说明**：
  - 代码库中出现的 `cz.kolbi.*` 标识严格且仅作为识别已知第三方文件管理工具 `WQFiles`（由 Kolbi 开发）的白名单判定规则。WQGuard 为全新独立的 MIT 开源项目。

---

## License

WQGuard is released under the **MIT License**.  
Copyright (c) 2026 WQGuard Contributors. See [LICENSE](LICENSE) for details.
