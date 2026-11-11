# Security Policy & Invariant Specification

## 1. Security Overview

**WQGuard** is an open-source, production-grade security scanner and firmware posture analysis tool for iOS 26.2+ / iOS 27.x and macOS Darwin hosts. WQGuard inspects installed applications, uninstalled `.ipa` archives, and App Group shared containers to detect cross-container sandbox escapes (`containermanagerd` / `worse_query` / `bad_query` exploits), 2026 firmware CVE exposures, trojanized cryptocurrency drainers, and malicious injected dylibs.

Because WQGuard operates as a security auditor that inspects potentially untrusted or hostile third-party software, WQGuard is engineered with a **zero-trust, 100% read-only invariant**:
> Under no circumstances does WQGuard modify, create, rewrite, truncate, or touch any inspected application binary, container metadata, system file, or directory.

---

## 2. Vulnerability Reporting & Disclosure Policy

We take the security of WQGuard and our users seriously. If you discover a security vulnerability within WQGuard or its scanning heuristics, we ask you to disclose it responsibly.

### 2.1 Scope
The following components are in scope:
- **`WQGuardCore` Framework**: Mach-O parsing, `CSBlob` entitlement parsing, `CSStore2` cache reader, static signature engine, and risk grading pipeline.
- **`wqguard-cli` Command-Line Tool**: CLI argument parsing, file handling, and export generators.
- **`WQGuard` iOS Application Target**: SwiftUI dashboard, document picker import, report viewers, and share sheet integration.
- **`Surge/WQGuard-Brotli-Shield.sgmodule`**: Brotli downgrade headers, regex patterns, script guards, and negative exclusion rules.

### 2.2 Reporting Process
- **Preferred Method**: Submit a report via [GitHub Private Vulnerability Advisory](https://github.com/Kianuni/WQGuard/security/advisories/new).
- **Alternative Method**: Open a minimal non-sensitive security contact issue in [Kianuni/WQGuard](https://github.com/Kianuni/WQGuard/issues) requesting a private channel.
- **Include**:
  1. Detailed description of the vulnerability, including attack vector and potential impact.
  2. Proof-of-concept (PoC) code or reproducer binary/IPA.
  3. Environment details (macOS version, iOS version, Xcode version, WQGuard commit hash).
  4. Suggested remediation if available.

### 2.3 Response Timeline & Embargo
- **Initial Acknowledgement**: Within 48 hours of receipt.
- **Triage & Reproduction**: Within 5 business days.
- **Fix & Patch Validation**: Within 14 business days.
- **Public Disclosure**: Coordinated release following patch publication, typically 30 days after initial report.

---

## 3. The 100% Read-Only Safety Invariant

The fundamental principle governing WQGuard's operation is the **Strict Read-Only Invariant**. When analyzing installed applications or container structures, WQGuard must never act as a confused deputy, nor alter file timestamps, nor trigger filesystem mutations that could interfere with system stability or forensic integrity.

### 3.1 POSIX Descriptor Flags (`O_RDONLY | O_NOFOLLOW | O_CLOEXEC`)
When reading files directly via Darwin POSIX system calls (such as in `MCMReader.swift`):
```swift
// MCMReader.swift:163
let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
```
- **`O_RDONLY`**: The file descriptor is opened strictly in read-only access mode. Any write operation attempted on this descriptor results in an immediate `EBADF` kernel error.
- **`O_NOFOLLOW`**: If the target path is a symbolic link, `open()` immediately fails with `ELOOP` rather than dereferencing the link. This prevents malicious symlinks from redirecting file descriptors outside container boundaries.
- **`O_CLOEXEC`**: Ensures the file descriptor is closed automatically upon any subsequent `execve()` call, preventing descriptor leakage into subprocesses.

### 3.2 Memory-Mapped Buffers (`.mappedIfSafe` / `PROT_READ`)
Binary parsing in `MachOParser.swift`, `CSStore2Parser.swift`, and `IPAPackageScanner.swift` relies on zero-copy memory mapping:
```swift
let data = try Data(contentsOf: url, options: [.mappedIfSafe])
```
- On Darwin, `.mappedIfSafe` utilizes `mmap(..., PROT_READ, MAP_SHARED | MAP_RESILIENT_CODESIGN, ...)`:
  - Memory pages are mapped as **read-only** (`PROT_READ`).
  - No write permissions are granted to the virtual memory pages.
  - Mach-O parsing traverses pointers into this mapped buffer without allocating mutable write buffers.

### 3.3 Safe Symbolic Link Traversal Defense (`lstat` & `readlink`)
Attackers using `worse_query` exploit `containermanagerd` by replacing `<AppGroup>/Library/Caches` with an escaping symlink. A naive scanner using `FileManager.contentsOfDirectory` or `stat()` would follow the link and traverse into sensitive targets (such as `/private/var/mobile/Containers/Data/Application/` or `/etc/`).

WQGuard defends against this in `ContainerScanner.swift`:
1. **Never use `stat()`**: WQGuard uses `lstat()` exclusively:
   ```swift
   var st = stat()
   guard lstat(targetURL.path, &st) == 0 else { return ... }
   let isSymlink = (st.st_mode & S_IFMT) == S_IFLNK
   ```
2. **Read Link Destination Without Dereferencing**:
   ```swift
   var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
   let len = readlink(targetURL.path, &buffer, buffer.count - 1)
   buffer[len] = 0
   let dest = String(cString: buffer)
   ```
3. **Strict Non-Recursion**: If `isSymlink` is `true`, WQGuard flags the escaping target and **strictly aborts recursive descent into that node**. Under no condition does WQGuard `opendir` or recurse into an untrusted symbolic link.

### 3.4 Scoped RAII Sandbox Token Cleanup (`SEC-M5-02`)
On iOS devices, consuming Seatbelt sandbox extensions (`sandbox_extension_consume`) populates entries in the kernel's per-process sandbox extension table. 
- As documented in security audit `SEC-M5-02`, Darwin assigns a finite number of sandbox extension slots per process.
- If a security scanner iterates over 200+ installed applications and App Group containers without releasing consumed handles, the kernel table exhausts mid-scan and fails with error code `-6` (`EXFULL`).
- **WQGuard Solution**: WQGuard implements `ScopedSandboxToken`:
  ```swift
  public final class ScopedSandboxToken: @unchecked Sendable {
      public let handle: Int64
      private var isReleased: Bool = false
      private let lock = NSLock()
      
      public init(handle: Int64) { self.handle = handle }
      
      public func release() {
          lock.lock()
          defer { lock.unlock() }
          guard !isReleased else { return }
          isReleased = true
          if handle > 0 {
              // Calls sandbox_extension_release(handle) immediately
          }
      }
      
      deinit { release() }
  }
  ```
  Every token acquired during App Group inspection is scoped to a single inspection pass and immediately closed upon block exit.

### 3.5 Ephemeral Scratch Sandbox for Local IPA Inspection
When inspecting uninstalled `.ipa` packages via `IPAPackageScanner.swift`:
1. The `.ipa` archive is unpacked into a cryptographically randomized, isolated scratch directory:
   `NSTemporaryDirectory()/WQGuard_IPA_<UUID>/`.
2. All inner bundle binaries (`Payload/*.app`, embedded `.dylib` files, and `.appex` extensions) are inspected strictly in read-only mode.
3. An automated Swift `defer` block guarantees complete removal of the temporary directory upon method return, regardless of whether inspection succeeds or throws an error:
   ```swift
   defer {
       try? FileManager.default.removeItem(at: tempDir)
   }
   ```
4. No artifacts or unzipped files ever persist on the user's filesystem.

---

## 4. Automated Read-Only Verification

WQGuard's read-only guarantees are not merely documented; they are continuously enforced and verified by automated regression test suites (`ReadOnlyAssertions.swift`):

1. **Bit-for-Bit SHA-256 Checksums**:
   Before and after each scanner pass, `ReadOnlyAssertions.captureSnapshot()` hashes all files in the target directories. The test suite asserts:
   ```swift
   XCTAssertEqual(initialSHA256, finalSHA256, "Binary SHA256 mutated during scanning!")
   ```
2. **Nanosecond Filesystem Timestamps**:
   `ReadOnlyAssertions` compares POSIX `st_mtimespec.tv_sec` and `st_mtimespec.tv_nsec`. Any timestamp mutation fails the test run immediately:
   ```swift
   XCTAssertEqual(before.mtimeNsec, after.mtimeNsec, "Modification timestamp mutated!")
   ```
3. **Read-Only Access Mode Checks**:
   Open descriptors are verified via `fcntl(fd, F_GETFL)`:
   ```swift
   let accessMode = flags & O_ACCMODE
   XCTAssertEqual(accessMode, O_RDONLY, "Descriptor not opened O_RDONLY!")
   ```
4. **Execution on Read-Only Filesystems**:
   Tests explicitly apply permission `0444` (`r--r--r--`) to files and `0555` (`r-xr-xr-x`) to directories, verifying that WQGuard operates flawlessly without write access.

---

## 5. Security Best Practices for Operators

1. **Verify Binary Signatures**: When installing WQGuard on iOS, ensure the package is signed with your own trusted ad-hoc identity or installed via TrollStore.
2. **Always Audit IPAs Before Installation**: Use `wqguard-cli --ipa <path>` or the iOS in-app document picker to inspect third-party sideloaded packages before signing or deploying them to devices.
3. **Maintain Surge Brotli Shield Exclusions**: Do not remove mandatory negative exclusions (`-*.apple.com`, `-guzzoni.apple.com`, `-*.binance.com`, etc.) from `WQGuard-Brotli-Shield.sgmodule`, as doing so may disrupt Apple Intelligence, Siri, and cert-pinned financial applications.
