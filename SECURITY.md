# 安全策略与只读不变量规范 / Security Policy & Invariant Specification

**[🇨🇳 简体中文](#简体中文) · [🇺🇸 English](#english)**

---

<a name="简体中文"></a>
## 🇨🇳 简体中文

### 1. 安全设计总则

**WQGuard（容器守卫）** 是面向 iOS 26.2+ / iOS 27.x 与 macOS Darwin 主机的开源只读安全审计工具与多平台固件 CVE 防护系统。由于安全扫描器需要直接解析来历不明甚至高度恶意的第三方侧载包（`.ipa` / `.tipa`）、共享容器元数据以及本机应用注册表，WQGuard 在工程底层严格执行**三大零信任铁律**：

1. **100% 物理只读不变量（Strict Read-Only Invariant）**：在任何情况下，WQGuard **绝不修改、创建、覆写、截断或触碰**任何被检应用二进制、系统文件或容器元数据。
2. **零漏洞利用原则（Zero-Exploit Architecture）**：WQGuard **绝不内嵌任何内核或系统守护进程漏洞代码**（如 `worse_query`、`bad_query` 或 `fsgetpath` 暴力枚举），绝不充当混淆替身或破坏系统稳定性。
3. **100% 本机离线与隐私隔离（100% On-Device & Zero Telemetry）**：零第三方 SDK、零遥测上报、零公网传输。用户导入的配对证书与快照严格封闭在本机应用沙盒内。

---

### 2. 安全漏洞负责任披露流程

如果您在 WQGuard 引擎、客户端或代理护盾规则中发现了潜在安全漏洞、解析器越界风险或检测绕过手法，欢迎向我们提交负责任披露报告。

#### 2.1 适用范围
- **`WQGuardCore` 核心引擎**：Mach-O 二进制解析、双槽 `CSBlob`（XML + ASN.1 DER）权限解析、`CSStore2` 读取器、`LockdownInstallationProxyClient` 协议交互、静态签名与行为元组裁决管线。
- **`wqguard-cli` 命令行工具**：参数解析、文件流处理与报告生成器。
- **`WQGuard` iOS 客户端**：SwiftUI 视图层、沙盒文件导入队列与本地存储隔离。
- **`Shields/` 多平台代理护盾矩阵**：Surge (`.sgmodule`)、Shadowrocket (`.module`)、Quantumult X (`.conf`)、Loon (`.plugin`)、Stash (`.stoverride`) 规则及 `Shields/scripts/brotli-guard.js` 响应拦截脚本。

#### 2.2 提交通道与响应时效
- **首选私密通道**：通过 [GitHub Private Vulnerability Advisory](https://github.com/Kianuni/WQGuard/security/advisories/new) 提交私密安全报告（请附带复现环境、PoC 样本或最小复现步骤）。
- **响应承诺**：
  - **48 小时内**：确认收到报告并启动初步评估；
  - **5 个工作日内**：完成漏洞复现与严重度定级；
  - **14 个工作日内**：完成补丁开发与回归测试验证，并协调公开致谢与披露。

---

### 3. 核心安全工程实现细节

#### 3.1 POSIX 文件描述符硬锁死 (`O_RDONLY | O_NOFOLLOW | O_CLOEXEC`)
在通过底层系统调用直接读取容器或元数据文件时（如 `MCMReader.swift`），强制组合三项标志位：
```swift
let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
```
- **`O_RDONLY`**：以纯只读模式打开描述符，任何写入尝试都会被 Darwin 内核直接以 `EBADF` 拒绝。
- **`O_NOFOLLOW`**：若目标路径为符号链接，`open()` 立即报错 `ELOOP` 终止，彻底阻断恶意包利用软链接诱导扫描器越界读取宿主机敏感文件。
- **`O_CLOEXEC`**：防止文件描述符意外泄漏至任何子进程。

#### 3.2 只读零拷贝内存映射 (`.mappedIfSafe` / `PROT_READ`)
在 `MachOParser.swift`、`CSStore2Parser.swift` 与 `IPAPackageScanner.swift` 中，二进制结构解析均采用只读内存映射与严格整数溢出边界检查：
```swift
let data = try Data(contentsOf: url, options: [.mappedIfSafe])
```
底层对应 `mmap(..., PROT_READ, MAP_SHARED | MAP_RESILIENT_CODESIGN, ...)`，虚拟内存页仅授予 `PROT_READ` 只读权限，并且所有 Mach-O Load Command 偏移与切片范围均经过 64 位无溢出边界校验，防止畸形二进制引发越界崩溃。

#### 3.3 非递归软链接穿越防御 (`lstat` + `readlink`)
针对利用 `worse_query` 将 `<AppGroup>/Library/Caches` 替换为逃逸软链接的攻击场景，普通文件遍历 API（如 `stat()` 或默认目录枚举）会跟随软链接跨入受害者容器。WQGuard 在 `ContainerScanner.swift` 中严格执行：
1. **禁用 `stat()`，强制使用 `lstat()`** 识别节点本身的 `S_IFLNK` 属性；
2. **使用 `readlink()` 原位读取指向路径字符串** 作为取证证据；
3. **严禁递归进入软链接节点**：一旦检测到 `isSymlink == true`，立即记录告警并终止该分支向下遍历。

#### 3.4 作用域沙盒令牌自动回收 (`ScopedSandboxToken` / `SEC-M5-02`)
iOS 内核为单个进程分配的沙盒扩展槽位（Sandbox Extension Slots）数量有限。若扫描器连续校验数百个容器而未及时释放句柄，将触发内核表耗尽（错误码 `-6` / `EXFULL`）。WQGuard 通过线程安全的 RAII 封装类 `ScopedSandboxToken`，确保每次单点检查退出作用域或 `deinit` 时立即释放对应句柄。

#### 3.5 本地数据隔离与无痕临时拆包
- **`.ipa` 无痕拆包自毁**：未安装的 `.ipa` / `.tipa` 仅解压至随机 UUID 命名的隔离临时目录 `NSTemporaryDirectory()/WQGuard_IPA_<UUID>/`，并由 Swift `defer` 块保证无论解析成功或抛出异常均在函数返回前彻底删除临时目录。
- **配对记录与环回通信隔离**：用户导入的 `.mobiledevicepairing` 仅保存在本机沙盒 `Application Support/WQGuardRegistry/` 内，支持随时一键销毁；连接 `installation_proxy` 时仅与本机虚拟环回地址（如 `10.7.0.1` 或同网段本机隧道端）建立本地 TLS 握手，绝不向外部网络发送任何字节。

---

### 4. 自动化只读回归验证体系

WQGuard 的只读承诺由 **664 项自动化单元测试**（含 `ReadOnlyAssertions.swift` 对抗测试套件）在每次构建时强制校验：
1. **全目录逐字节 SHA-256 前后比对**：扫描前后对目标目录全部文件计算 SHA-256，任何 1 比特变化立即判定测试失败。
2. **纳秒级文件系统时间戳校验**：比对 `st_mtimespec.tv_sec` 与 `st_mtimespec.tv_nsec`，确保扫描绝不污染文件修改时间。
3. **描述符只读模式断言**：通过 `fcntl(fd, F_GETFL)` 校验 `flags & O_ACCMODE == O_RDONLY`。
4. **纯只读权限文件系统实战测试**：将测试文件设为 `0444` (`r--r--r--`)、目录设为 `0555` (`r-xr-xr-x`)，验证全链路扫描在零写权限环境下 100% 正常运行。

---

<a name="english"></a>
## 🇺🇸 English

### 1. Security Design Principles

**WQGuard** is an open-source, production-grade security scanner and multi-client firmware CVE guard for iOS 26.2+ / iOS 27.x and macOS Darwin hosts. Because WQGuard inspects potentially hostile third-party `.ipa` archives, shared containers, and installed-app registries, it enforces **three strict zero-trust invariants**:

1. **100% Physical Read-Only Invariant**: Under no circumstances does WQGuard modify, create, rewrite, truncate, or touch any inspected binary, container metadata, or system file.
2. **Zero-Exploit Architecture**: WQGuard embeds **zero sandbox escape or kernel exploit primitives** (no `worse_query`, no `bad_query`, no `fsgetpath` brute-forcing), preventing `containermanagerd` crashes, `0x8badf00d` watchdog kills, or dangling symlinks.
3. **100% On-Device & Zero Telemetry**: Zero third-party SDKs, zero analytics, and zero outbound internet connections. Pairing files and snapshots stay strictly within WQGuard's local app sandbox.

---

### 2. Responsible Vulnerability Disclosure

#### 2.1 Scope
- **`WQGuardCore` Framework**: Mach-O parser, dual-slot `CSBlob` (XML + ASN.1 DER) entitlement parser, `CSStore2` reader, `LockdownInstallationProxyClient`, and static/behavioral risk pipeline.
- **`wqguard-cli` Binary**: Argument parsing, stream purity, and report exporters.
- **`WQGuard` iOS App**: SwiftUI views, sandboxed package queue, and local storage isolation.
- **`Shields/` 5-Client Brotli Shield Matrix**: Configurations for Surge (`.sgmodule`), Shadowrocket (`.module`), Quantumult X (`.conf`), Loon (`.plugin`), Stash (`.stoverride`), and `Shields/scripts/brotli-guard.js`.

#### 2.2 Reporting & Timeline
- **Preferred Channel**: Submit via [GitHub Private Vulnerability Advisory](https://github.com/Kianuni/WQGuard/security/advisories/new) with reproduction steps or PoC samples.
- **Response Targets**: Initial acknowledgement within **48 hours**, triage within **5 business days**, and patch validation within **14 business days**.

---

### 3. Core Engineering Safeguards

1. **POSIX Descriptor Locking (`O_RDONLY | O_NOFOLLOW | O_CLOEXEC`)**: Direct file reads enforce read-only kernel descriptors and immediately fail with `ELOOP` on symbolic links rather than dereferencing untrusted targets.
2. **Read-Only Memory Mapping (`.mappedIfSafe` / `PROT_READ`)**: Binary parsers operate on read-only mapped pages guarded by overflow-checked 64-bit bounds validation.
3. **Non-Recursive Symlink Forensics (`lstat` + `readlink`)**: `ContainerScanner` never calls `stat()` or recurses into symbolic links, capturing escaping destinations safely without traversing outside container boundaries.
4. **Scoped RAII Sandbox Token Release (`ScopedSandboxToken`)**: Immediately releases Seatbelt extension handles upon scope exit to prevent kernel table exhaustion (`EXFULL`).
5. **Ephemeral Scratch Unpacking & Local Loopback Isolation**: Uninstalled `.ipa` archives unpack into randomized `NSTemporaryDirectory()/WQGuard_IPA_<UUID>/` directories guaranteed to be wiped via `defer`; `LocalDevVPN` pairing connections communicate strictly over local virtual loopback with the device's own `lockdownd` service.

---

### 4. Automated Read-Only Regression Verification

Continuously enforced across **664 automated unit tests** (`ReadOnlyAssertions.swift`):
- Pre/post bit-for-bit **SHA-256 checksum equality** across all scanned files;
- Pre/post **nanosecond `st_mtimespec` timestamp equality**;
- Descriptor access mode verification (`fcntl(fd, F_GETFL) & O_ACCMODE == O_RDONLY`);
- Full pipeline execution on **`0444` / `0555` read-only permissioned filesystems**.
