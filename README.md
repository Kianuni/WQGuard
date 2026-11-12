# WQGuard 🛡️

**面向 iOS 26.2+ / iOS 27.x 的 100% 严格只读开源沙盒越权检测、侧载 IPA 审查与多平台固件 CVE 防护工具**  
**Standalone, 100% Read-Only Open-Source iOS Security Scanner, Sideloaded IPA Auditor & Multi-Client Firmware CVE Guard**

[![Latest Release](https://img.shields.io/github/v/release/Kianuni/WQGuard?label=Release&color=00c7a5)](https://github.com/Kianuni/WQGuard/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-iOS%2016.0%2B%20(Optimized%20for%20iOS%2026.2%2B%20%2F%2027.x)%20%7C%20macOS-lightgrey.svg)]()
[![Swift 6.0](https://img.shields.io/badge/Swift-6.0%20Strict%20Concurrency-orange.svg)]()
[![Unit Tests](https://img.shields.io/badge/Tests-664%20Passing-brightgreen.svg)]()
[![Read-Only Guaranteed](https://img.shields.io/badge/Security-100%25%20Read--Only%20(O__RDONLY)-success.svg)](SECURITY.md)

**[🇨🇳 简体中文](#简体中文) · [🇺🇸 English](#english) · [📥 下载最新安装包 / Download Latest IPA](https://github.com/Kianuni/WQGuard/releases/latest) · [🔒 安全策略 / Security Policy](SECURITY.md) · [📖 技术白皮书 / Technical Reference](USAGE_GUIDE.md)**

---

<a name="简体中文"></a>
## 🇨🇳 简体中文

### 1. 项目简介

**WQGuard（容器守卫）** 是一款专为 **iOS 26.2+ 与 iOS 27.x** 环境打造的生产级、零第三方依赖、**100% 严格只读**开源安全审计工具与固件风险防护系统。项目同时提供两大原生目标与一套独立多平台防护规则库：

1. **iOS 原生应用 (`WQGuard.app`)**：支持**全机已安装应用三引擎无越权扫描**、**本地多选 `.ipa` / `.tipa` 安装包深度静态反编译审查**、**2026 固件 CVE 漏洞暴露雷达**、**五大主流代理工具（Surge / 小火箭 / 圈 X / Loon / Stash）防 Brotli 溢出护盾一键导入/导出**，以及 RFC 8259 JSON / Markdown / 纯文本审计报告导出。
2. **macOS 终端命令行工具 (`wqguard-cli`)**：零外部依赖的原生 Darwin 终端工具，支持批量扫描 `.ipa` 安装包、共享容器目录、多格式代理护盾生成及 CI/CD 安全门禁自动化集成。
3. **独立多平台代理护盾规则库 ([`Shields/`](Shields/))**：无需安装 App 亦可直接通过订阅链接导入 Surge、Shadowrocket、Quantumult X、Loon 与 Stash，在网络传输层阻断 `CVE-2026-111497` (`HTTP2Shell`) 漏洞利用。

WQGuard 专注于在**绝对不调用任何私有越权漏洞（Zero-Exploit）**的前提下，精准检出跨容器沙盒逃逸攻击（`worse_query` / `bad_query` / `containermanagerd` 混淆替身漏洞）、二次打包盗币钱包木马（Web3 Drainer）、相册 TCC 隐私绕过（`CVE-2026-112676`）、注入外挂动态库（`Frameworks/*.dylib`）以及常驻后台剪贴板助记词窃取行为。

---

### 2. 🔒 安全与隐私策略（三大底层铁律）

作为一款需要接触本机已安装应用列表、配对证书与可疑第三方安装包的审计工具，WQGuard 从架构底层严格执行**零信任安全策略**（详见 [SECURITY.md](SECURITY.md)）：

1. **100% 本机离线运行 · 零遥测零上传（Zero Telemetry & On-Device Only）**
   - **零外部依赖、零统计 SDK**：工程纯原生 Swift / Darwin 构建，不集成任何第三方分析、崩溃上报或广告库，**没有任何后台公网请求逻辑**。
   - **敏感凭证沙盒闭环**：导入的 `.mobiledevicepairing` 配对文件、`installed_apps.json` 快照与本地 `.ipa` 扫描队列仅存储在 WQGuard 自身沙盒私有目录内，支持随时在界面内一键彻底清除；引擎 1A 连接 `LocalDevVPN` 时仅与本机 `lockdownd` 服务建立本地虚拟环回 TLS 通道，流量绝不离开手机、绝不经过任何外部服务器。
2. **零漏洞利用原则（Zero-Exploit Guarantee）**
   - 市面上部分检测工具会内嵌 `worse_query` / `fsgetpath` 越权漏洞去强行枚举其他容器，极易造成 APFS 缓存抖动触发 iOS 看门狗强杀（`0x8badf00d`）、遗留危险软链接甚至导致系统 `containermanagerd` 守护进程崩溃。
   - WQGuard **坚决不内嵌、不调用任何沙盒逃逸攻击载荷**，100% 依托苹果官方 `com.apple.mobile.installation_proxy` 协议与用户显式授权的文件导入机制完成合规盘点。
3. **100% 物理只读不变量（Strict Physical Read-Only Invariant）**
   - **系统调用级只读锁死**：底层文件读取强制使用 `open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)`，内核级拒绝任何写操作，遇到符号链接立即返回 `ELOOP` 绝不跟随越界。
   - **非递归软链接取证与零残留拆包**：使用 `lstat()` + `readlink()` 在不解引用的前提下识别逃逸软链接并立即终止递归；通过 `.mappedIfSafe` (`PROT_READ`) 只读内存映射解析二进制；本地 `.ipa` 在随机隔离临时目录拆包审计后通过 `defer` 块强制销毁，零文件残留。
   - **664 项自动化回归验证**：每次测试均对被扫目录执行扫描前后 **SHA-256 逐字节一致性比对**、**纳秒级 `mtime` 时间戳零变动校验**以及 `0444/0555` 纯只读权限文件系统压力测试。

---

### 3. 🎯 扫描策略与四级风险裁决机制

#### 3.1 三引擎互补采集与自动升维联动
普通 iOS 侧载应用受限于 Apple Seatbelt 沙盒，无法直接读取 `/var/containers/Bundle/Application`。WQGuard 采用**三源互补 + 自动融合**策略：

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ 引擎 1 · 全机注册表权限审计（二选一）                                      │
│  ├─ 方式 A：LocalDevVPN + 配对文件无线直连 iOS 官方 installation_proxy     │
│  │         （内置 iOS 26.4+/27 同网段 IP 对齐助手，手机端随时 1 秒直扫）   │
│  └─ 方式 B：Mac pymobiledevice3 / devicectl 导出 installed_apps.json 快照  │
│  ▶ 采集能力：全机应用的完整 Entitlements 权限表、App Groups、证书与渠道身份│
├────────────────────────────────────────────────────────────────────────────┤
│ 引擎 2 · 本地多选 .ipa / .tipa 二进制深扫队列                              │
│  ▶ 支持在系统「文件」一次多选任意数量 .ipa 加入持久扫描列表（支持单独移除）│
│  ▶ 采集能力：拆包反编译主程序、Frameworks/*.dylib 与 PlugIns/*.appex 符号表│
├────────────────────────────────────────────────────────────────────────────┤
│ 引擎 3 · 本机零配置在位探针（UIApplication.canOpenURL）                    │
│  ▶ 采集能力：零配置识别 Feather / 全能签 / SideStore / TrollStore / Filza  │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     ▼
       【 按 Bundle ID 自动融合升级为 🔬 注册表 + 二进制全量深扫 】
```

#### 3.2 双层防误报门禁（为什么不乱报系统与正常 App？）
1. **第一道门禁：系统进程剔除与精准分发渠道识别**
   - **双层过滤系统应用**：自动剥离 `/System/Library/`、`/Applications/` 等系统目录及 Apple 平台内置服务，彻底消除「扫出一百多个系统高危应用」的误报噪音。
   - **四渠道精准定性**：结合 `ApplicationType`、`SignerIdentity`、`BetaReportsActive`、`get-task-allow` 与内嵌描述文件，精准区分 **`🍏 App Store`**、**`✈️ TestFlight`**（如 Surge、APTV 等测试版绝不误判为企业签）、**`🏢 企业签`** 与 **`🛠️ 个人侧载`**。
2. **第二道门禁：`App Groups` 密码学物理门禁（$O(1)$ 极速放行）**
   - **双槽防遮蔽解析**：同时解析 Mach-O `LC_CODE_SIGNATURE` 超块中的 **Slot 5 (XML `0xfade7171`)** 与 **Slot 7 (ASN.1 DER `0xfade7172`)** 权限字典并取并集，防止恶意包通过「空 XML + 隐藏 DER 槽」绕过审查。
   - **物理不可能定理**：`containermanagerd` 在内核侧强校验签名中的 `com.apple.security.application-groups`。未声明任何 App Group 的应用在物理上无法触发跨容器逃逸（请求会直接报错 `-1`），WQGuard 对此类无其他威胁特征的应用直接 $O(1)$ 判定安全。

#### 3.3 多维威胁检出与抗混淆行为元组
对于通过门禁进入深度分析的目标，扫描管线依次执行多向量交叉取证：
- **沙盒逃逸私有 API 与 XPC 特征**：扫描主程序、全部嵌入动态库与扩展组件的符号表及字符串段，捕获 `libsystem_containermanager.dylib`、`container_query_create`、`container_copy_sandbox_token`、`com.apple.containermanagerd` 与 `fsgetpath`（APFS Inode 路径爆破）。
- **抗 XOR 混淆行为元组启发式**：即便攻击者将私有函数名字符串全部加密隐藏，只要同时满足 **`未加密二进制 (cryptid == 0) ∧ 声明 App Groups ∧ 动态解析能力 (dlopen/dlsym) ∧ 软链接/令牌消费原语 (symlink/sandbox_extension_consume)`**，依然会被行为元组引擎精准锁定。
- **侧载高频黑产专项审计**：
  - **盗币假钱包 / 仿冒包识别**：比对主流加密钱包（MetaMask、Trust、Phantom、imToken、OKX、TokenPocket 等）与核心社交/支付软件的特征，拦截非官方证书重签仿冒应用。
  - **第三方注入动态库审查**：逐一枚举 `Frameworks/*.dylib` 与非系统加载路径（`@executable_path` / `@rpath`），揪出二次打包塞入的外挂或窃密插件。
  - **相册隐私绕过与伪造监管锁机**：检测非法引用 `PhotoLibraryServices`（`CVE-2026-112676` 静默读相册助记词截图）及容器内异常逃逸软链接、伪造 MDM 监管配置（`CloudConfigurationDetails.plist`）。

#### 3.4 四级风险透明裁决与极简白名单原则

| 风险等级 | 触发判定准则 | 处置建议 |
|---|---|---|
| **🔴 高危告警 (`High Risk`)** | 检出 `containermanagerd` 私有逃逸调用 / XPC 通信、`fsgetpath` 路径爆破、共享容器越界软链接、伪造 MDM 监管锁机、私有相册框架越权调用或仿冒知名钱包/金融应用签名 | **切勿启动，立即卸载**，并在系统设置中移除对应描述文件后重启设备回收内核沙盒令牌 |
| **🟡 已知工具 (`Known Tool`)** | 匹配用户显式启用的可信白名单规则，或引擎 3 识别到的公开侧载签名管理工具（如 WQGuard 自身、Feather、SideStore、LocalDevVPN 等） | 确认来源为本人主动安装的官方渠道包即可正常使用 |
| **🟠 前置留意 (`Caution`)** | 个人侧载或企业签应用声明了共享 `App Groups`、满足抗混淆动态加载行为元组、嵌入了第三方改版注入 `.dylib`、或开启高敏感常驻后台权限（如后台定位/音频保活伴随剪贴板访问风险） | 点进详情页核查其「注入动态库清单」与「声明权限」，仅保留信任来源的改版包 |
| **🟢 安全合规 (`Safe`)** | 官方 App Store / TestFlight 合规分发应用，或未声明越权敏感权限、未检出任何可疑私有符号与注入特征的干净侧载应用 | 符合 iOS 沙盒隔离边界，可放心使用 |

> **⚖️ 极简白名单原则**：WQGuard 出厂内置白名单**仅保留 `WQGuard` 自身**，默认不暗中豁免任何第三方越权研究工具（如 Erosion、WQFiles 等均会据实检出），把是否信任的知情权与开关权 100% 交给用户。

---

### 4. 🌐 固件 CVE 暴露雷达与多平台防 Brotli 溢出护盾矩阵 (`CVE-2026-111497`)

针对停留在未修补固件的 iOS 26.x 与 iOS 27.0–27.2 设备，实时评估 **8 项 2026 高危系统漏洞**，并为 iOS 五大主流网络代理客户端提供开箱即用的**防 Brotli 溢出降级护盾**（防御 `CVE-2026-111497` / `HTTP2Shell` `libbrotli` 堆溢出远程代码执行，CVSS 9.2）：

- **双层零解压拦截**：请求层将 `Accept-Encoding` 强制降级为 `gzip, deflate`；响应层采用**零响应体解压**（`requires-body=false` / `script-response-header`）直接阻断恶意服务端强行回传的 `Content-Encoding: br` 畸形流，避免代理进程或系统 `WebKit`/`CFNetwork` 触发漏洞。
- **零耗电、零断网默认策略**：全部 5 款客户端规则统一内置 `-*.apple.com`、`-guzzoni.apple.com`（普通话 Siri）、`-*.siri.apple.com`、`-apple-relay.*`、`-*.openai.com`、`-*.alipay.com`、`-*.tenpay.com` 等 **16 项严苛负向排除规则**，默认仅针对 `*.xyz`、`*.top`、`*.icu`、`*.click`、`*.zip` 等 **20 类黑产钓鱼高频后缀**开启 MITM，日常挂机零额外耗电、绝不影响银行与主流 App 正常联网（切勿在日常将附加域名设为全局 `*`）。

#### 📥 五大代理客户端一键订阅列表（也可在 WQGuard App「固件雷达」内一键唤起导入）

| 客户端 | 规则格式 | 仓库文件 | 在线订阅直链（复制填入客户端即可） | 启用要点 |
|---|---|---|---|---|
| **Surge** | `.sgmodule` | [`WQGuard-Brotli-Shield.sgmodule`](Shields/Surge/WQGuard-Brotli-Shield.sgmodule) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Surge/WQGuard-Brotli-Shield.sgmodule` | 导入「模块」，开启 `MitM` 与 CA 证书信任 |
| **Shadowrocket (小火箭)** | `.module` | [`WQGuard-Brotli-Shield.module`](Shields/Shadowrocket/WQGuard-Brotli-Shield.module) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Shadowrocket/WQGuard-Brotli-Shield.module` | 导入「配置 → 模块」，开启「HTTPS 解密」与证书信任 |
| **Quantumult X (圈 X)** | `.conf` | [`WQGuard-Brotli-Shield.conf`](Shields/QuantumultX/WQGuard-Brotli-Shield.conf) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/QuantumultX/WQGuard-Brotli-Shield.conf` | 添加至「重写 → 资源引用」，开启「重写」与「MitM」开关 |
| **Loon** | `.plugin` | [`WQGuard-Brotli-Shield.plugin`](Shields/Loon/WQGuard-Brotli-Shield.plugin) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Loon/WQGuard-Brotli-Shield.plugin` | 导入「配置 → 插件」，开启「MITM」与证书信任 |
| **Stash** | `.stoverride` | [`WQGuard-Brotli-Shield.stoverride`](Shields/Stash/WQGuard-Brotli-Shield.stoverride) | `https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/Stash/WQGuard-Brotli-Shield.stoverride` | 导入「覆写 (Overrides)」，开启「MITM」与根证书信任 |

#### 📊 8 项 2026 固件高危漏洞评估矩阵

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

### 5. 🚀 快速上手指南

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

### 6. 💻 macOS 命令行工具 (`wqguard-cli`) 与源码构建

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

---

### 2. 🔒 Security & Privacy Policy (Three Core Invariants)

Because a security auditor inspects sensitive device metadata and untrusted third-party binaries, WQGuard enforces three non-negotiable engineering guarantees (see [SECURITY.md](SECURITY.md) for full specification):

1. **100% On-Device Execution · Zero Telemetry & Zero External Network Calls**
   - Built strictly on native Swift and Darwin frameworks with **zero third-party SDKs, zero analytics/crash reporters, and zero outbound internet requests**.
   - Imported `.mobiledevicepairing` records, `installed_apps.json` snapshots, and queued `.ipa` archives remain strictly inside WQGuard's private app sandbox and can be wiped with one tap at any time. Engine 1A communicates over `LocalDevVPN` exclusively with the device's own `lockdownd` daemon via local virtual loopback — no traffic ever leaves the device.
2. **Zero-Exploit Architecture**
   - Unlike utilities that weaponize `worse_query` or `fsgetpath` inode brute-forcing to inspect peer containers — risking `0x8badf00d` watchdog terminations, dangling escaping symlinks, or `containermanagerd` instability — WQGuard **embeds zero exploit primitives** and relies strictly on Apple's official `com.apple.mobile.installation_proxy` protocol and user-selected packages.
3. **100% Strict Physical Read-Only Invariant**
   - All direct file accesses enforce `open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)`, `lstat()` + `readlink()` non-recursive symlink inspection, read-only `.mappedIfSafe` (`PROT_READ`) memory mapping, RAII `ScopedSandboxToken` cleanup, and `defer`-guaranteed ephemeral `.ipa` scratch directory removal — continuously verified across **664 automated unit tests** via pre/post SHA-256 checksums, nanosecond `mtime` assertions, and `0444/0555` read-only filesystem stress suites.

---

### 3. 🎯 Scanning Strategy & 4-Tier Risk Grading

#### 3.1 3-Engine Complementary Collection & Automatic Correlation
- **Engine 1A · Wireless Pairing Direct (`LocalDevVPN` + Pairing Record)**: Queries iOS's official `installation_proxy` on-device for full `Entitlements`, `App Groups`, and signer identities, complete with a built-in **iOS 26.4+ / iOS 27 Same-Subnet IP Helper**.
- **Engine 1B · Offline Registry Snapshot (`pymobiledevice3` / `xcrun devicectl`)**: Zero-VPN Mac snapshot export (`installed_apps.json`), 100% compatible with iOS 27.
- **Engine 2 · Multi-Select `.ipa` / `.tipa` Binary Queue**: Batch-import local packages from the iOS Files picker (or exported from Feather) to decompile main Mach-O binaries, `Frameworks/*.dylib`, and `PlugIns/*.appex`.
- **Engine 3 · On-Device Environment Probe**: Inventory sideload signers and unsandboxed/bootstrap tools via standard `UIApplication.canOpenURL` checks.
- **Automatic `Bundle ID` Upgrade**: When an installed app in Engine 1 matches a queued `.ipa` in Engine 2, WQGuard automatically merges both into a **`🔬 Full Registry + Binary Audit`**.

#### 3.2 Two-Stage False-Positive Elimination
1. **Apple System Filtering & Accurate 4-Channel Attribution**: Dual-layer path (`/System/Library/`, `/Applications/`) and platform-binary filtering eliminates Apple OS daemon noise, while `BetaReportsActive`, `get-task-allow`, and provisioning profile inspection accurately separate **`🍏 App Store`**, **`✈️ TestFlight`**, **`🏢 Enterprise`**, and **`🛠️ Sideloaded`** apps.
2. **Cryptographic `App Groups` Gate ($O(1)$ Fast-Path)**: Parses both **Slot 5 (XML `0xfade7171`)** and **Slot 7 (ASN.1 DER `0xfade7172`)** in `LC_CODE_SIGNATURE` SuperBlobs (preventing dual-slot shadowing attacks). Because `containermanagerd` physically rejects requests from binaries lacking `com.apple.security.application-groups`, apps without App Groups or other threat indicators are fast-pathed as `Safe` in $O(1)$ time.

#### 3.3 Multi-Vector Detection & 4-Tier Verdict Matrix
WQGuard combines exact symbol/XPC matching (`libsystem_containermanager.dylib`, `container_query_*`, `fsgetpath`), **XOR-resistant behavioral tuples** (`cryptid == 0 ∧ AppGroups ∧ dlopen/dlsym ∧ symlink/sandbox_extension_consume`), wallet `Bundle ID` impersonation checks, injected `Frameworks/*.dylib` auditing, private Photos TCC bypass detection (`PhotoLibraryServices`), and rogue supervision plist checks:

| Risk Tier | Trigger Criteria | Recommended Action |
|---|---|---|
| **🔴 High Risk** | `containermanagerd` escape symbols/XPC, `fsgetpath` inode brute-forcing, escaping container symlinks, rogue MDM supervision plist, private Photos TCC bypass, or wallet/app impersonation | **Do NOT launch — delete immediately**, remove provisioning profile, and reboot device to invalidate kernel sandbox tokens |
| **🟡 Known Tool** | Matches user-enabled whitelist rules or recognized sideload signer utilities (e.g., WQGuard itself, Feather, SideStore, LocalDevVPN) | Verify the package was intentionally installed from its official source |
| **🟠 Caution** | Sideloaded/enterprise app declaring shared `App Groups`, dynamic-loading behavioral tuples, third-party injected `Frameworks/*.dylib`, or persistent background modes | Inspect the detailed dylib & entitlement evidence card; retain only trusted mods |
| **🟢 Safe** | Official App Store / TestFlight apps, or clean sideloaded apps free of sensitive entitlements, private symbols, and injected libraries | Complies with iOS sandbox boundaries |

> **⚖️ Minimal Default Whitelist Principle**: Out of the box, **only `WQGuard` itself is whitelisted**. Third-party exploit or container utilities are never silently exempted unless explicitly whitelisted by the user in Settings.

---

### 4. 🌐 Firmware CVE Exposure Radar & 5-Client Brotli Shield Matrix (`CVE-2026-111497`)

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

### 5. 🚀 Quick Start & Building from Source

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
