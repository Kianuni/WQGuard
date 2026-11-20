//
//  ContainerScanner.swift
//  WQGuardCore
//
//  Layer 3 Shared Container Inspector.
//  Performs 100% read-only bounds checking on App Group containers,
//  inspecting `Library/Caches` with `lstat` to detect anomalous escaping symlinks
//  (`S_ISLNK`) pointing outside container boundaries without following untrusted symlinks (`O_NOFOLLOW`).
//  Includes scoped RAII token cleanup to prevent Darwin kernel handle exhaustion (SEC-M5-02).
//

import Foundation
import Darwin

/// Result of inspecting a container directory.
public struct ContainerScanResult: Sendable, Equatable {
    public let containerURL: URL
    public let metadata: MCMMetadata?
    public let escapingSymlinks: [String]
    public let indicators: [ThreatIndicator]
    public let isClean: Bool

    public init(
        containerURL: URL,
        metadata: MCMMetadata?,
        escapingSymlinks: [String],
        indicators: [ThreatIndicator]
    ) {
        self.containerURL = containerURL
        self.metadata = metadata
        self.escapingSymlinks = escapingSymlinks
        self.indicators = indicators
        self.isClean = indicators.isEmpty && escapingSymlinks.isEmpty
    }
}

/// Scoped RAII token guard releasing Darwin kernel sandbox extensions on deinit (SEC-M5-02).
public final class ScopedSandboxToken: @unchecked Sendable {
    public let handle: Int64
    private var isReleased: Bool = false
    private let lock = NSLock()

    public init(handle: Int64) {
        self.handle = handle
    }

    public func release() {
        lock.lock()
        defer { lock.unlock() }
        guard !isReleased else { return }
        isReleased = true
        if handle > 0 {
            #if os(iOS)
            typealias ReleaseFn = @convention(c) (Int64) -> Int32
            if let handlePtr = dlopen(nil, RTLD_NOW) {
                if let sym = IOCTokenArmor.tSbxRelease.withCString({ dlsym(handlePtr, $0) }) {
                    let releaseFn = unsafeBitCast(sym, to: ReleaseFn.self)
                    _ = releaseFn(handle)
                }
            }
            #endif
        }
    }

    deinit {
        release()
    }
}

public enum ContainerScannerError: Error, Sendable, Equatable, LocalizedError {
    case symlinkParentDirectory(String)
    case notADirectory(String)
    case unreadableDirectory(String, Int32)

    public var errorDescription: String? {
        switch self {
        case .symlinkParentDirectory(let path):
            return WQLocale.pick(
                en: "Refusing to scan symlinked container parent directory '\(path)'.",
                zh: "拒绝扫描符号链接容器父目录 '\(path)'。"
            )
        case .notADirectory(let path):
            return WQLocale.pick(
                en: "Container parent path '\(path)' is not a directory.",
                zh: "容器父路径 '\(path)' 不是目录。"
            )
        case .unreadableDirectory(let path, let err):
            return WQLocale.pick(
                en: "Unable to open container directory '\(path)' (errno=\(err)).",
                zh: "无法读取容器目录 '\(path)' (errno=\(err))。"
            )
        }
    }
}

/// Layer 3 Container Inspector.
public final class ContainerScanner: Sendable {
    public static let shared = ContainerScanner()

    public init() {}

    /// Inspects a single shared container directory for metadata and anomalous escaping symlinks.
    public func scanContainer(at containerURL: URL) throws -> ContainerScanResult {
        var indicators: [ThreatIndicator] = []
        var escapingSymlinks: [String] = []

        let cleanContainerPath = IPAPackageScanner.stripTrailingSlashes(containerURL.path)
        var rootSt = stat()
        if lstat(cleanContainerPath, &rootSt) == 0 && (rootSt.st_mode & S_IFMT) == S_IFLNK {
            escapingSymlinks.append(cleanContainerPath)
            indicators.append(ThreatIndicator(
                signature: "CONTAINER_ROOT_SYMLINK",
                description: WQLocale.pick(
                    en: "Container root path '\(cleanContainerPath)' is a symbolic link; refusing traversal.",
                    zh: "容器根目录路径 '\(cleanContainerPath)' 为符号链接，已拒绝遍历。"
                ),
                category: ThreatIndicator.Category.escapingSymlink,
                location: cleanContainerPath,
                severity: .highRisk
            ))
            return ContainerScanResult(
                containerURL: containerURL,
                metadata: nil,
                escapingSymlinks: escapingSymlinks,
                indicators: indicators
            )
        }

        // 1. Read container metadata read-only
        let metadata: MCMMetadata?
        do {
            metadata = try MCMReader.shared.readMetadata(inContainer: containerURL)
        } catch {
            metadata = nil
            // If metadata is corrupted or anomalous, note it as an informational indicator
            let metadataPath = containerURL.appendingPathComponent(MCMReader.metadataFilename).path
            switch error {
            case MCMReaderError.corruptedPlist:
                indicators.append(ThreatIndicator(
                    signature: "CONTAINER_METADATA_CORRUPTED",
                    description: "Container metadata plist is corrupted or malformed.",
                    category: ThreatIndicator.Category.escapingSymlink,
                    location: metadataPath,
                    severity: .caution
                ))
            case MCMReaderError.emptyData:
                indicators.append(ThreatIndicator(
                    signature: "CONTAINER_METADATA_EMPTY",
                    description: "Container metadata plist is empty (0 bytes).",
                    category: ThreatIndicator.Category.escapingSymlink,
                    location: metadataPath,
                    severity: .caution
                ))
            case MCMReaderError.invalidUUID(let uuid):
                indicators.append(ThreatIndicator(
                    signature: "CONTAINER_METADATA_INVALID_UUID",
                    description: "Container metadata UUID '\(uuid)' is malformed or invalid.",
                    category: ThreatIndicator.Category.escapingSymlink,
                    location: metadataPath,
                    severity: .caution
                ))
            case MCMReaderError.missingRequiredKey(let key):
                indicators.append(ThreatIndicator(
                    signature: "CONTAINER_METADATA_MISSING_KEY",
                    description: "Container metadata plist is missing required key '\(key)'.",
                    category: ThreatIndicator.Category.escapingSymlink,
                    location: metadataPath,
                    severity: .caution
                ))
            case MCMReaderError.fileTooLarge:
                indicators.append(ThreatIndicator(
                    signature: "CONTAINER_METADATA_FILE_TOO_LARGE",
                    description: "Container metadata plist size exceeds safe quota limit.",
                    category: ThreatIndicator.Category.escapingSymlink,
                    location: metadataPath,
                    severity: .caution
                ))
            case MCMReaderError.symlinkEncountered:
                indicators.append(ThreatIndicator(
                    signature: "CONTAINER_METADATA_SYMLINK",
                    description: "Container metadata plist is an untrusted symbolic link.",
                    category: ThreatIndicator.Category.escapingSymlink,
                    location: metadataPath,
                    severity: .caution
                ))
            default:
                break
            }
        }

        // 2. Inspect Library and Library/Caches (part = 3), traversing strictly verified in-container directories
        let libraryURL = containerURL.appendingPathComponent("Library")
        let libraryInspection = inspectPathForEscapingSymlink(targetURL: libraryURL, containerRootURL: containerURL)
        var effectiveLibraryURL: URL? = nil

        if libraryInspection.isSymlink {
            if libraryInspection.isEscaping {
                escapingSymlinks.append(libraryURL.path)
                indicators.append(ThreatIndicator(
                    signature: "CONTAINER_LIBRARY_SYMLINK",
                    description: WQLocale.pick(
                        en: "Container Library directory has been replaced by an escaping symbolic link pointing to '\(libraryInspection.destination ?? "unknown")' (sandbox container escape vector).",
                        zh: "容器 Library 目录已被替换为指向外部路径 '\(libraryInspection.destination ?? "unknown")' 的逃逸符号链接。"
                    ),
                    category: ThreatIndicator.Category.escapingSymlink,
                    location: libraryURL.path,
                    severity: .highRisk
                ))
            } else {
                effectiveLibraryURL = resolveInContainerDirectory(targetURL: libraryURL, containerRootURL: containerURL)
            }
        } else if libraryInspection.isDirectory {
            effectiveLibraryURL = libraryURL
        }

        if let resolvedLibraryURL = effectiveLibraryURL {
            let cachesURL = resolvedLibraryURL.appendingPathComponent("Caches")
            let cachesInspection = inspectPathForEscapingSymlink(targetURL: cachesURL, containerRootURL: containerURL)
            var effectiveCachesURL: URL? = nil

            if cachesInspection.isSymlink {
                if cachesInspection.isEscaping {
                    escapingSymlinks.append(cachesURL.path)
                    indicators.append(ThreatIndicator(
                        signature: "CONTAINER_CACHES_SYMLINK",
                        description: "Container Library/Caches has been replaced by an escaping symbolic link pointing to '\(cachesInspection.destination ?? "unknown")' (classic worse_query / containermanagerd exploit primitive).",
                        category: ThreatIndicator.Category.escapingSymlink,
                        location: cachesURL.path,
                        severity: .highRisk
                    ))
                } else {
                    effectiveCachesURL = resolveInContainerDirectory(targetURL: cachesURL, containerRootURL: containerURL)
                }
            } else if cachesInspection.isDirectory {
                effectiveCachesURL = cachesURL
            }

            if let resolvedCachesURL = effectiveCachesURL {
                // Safely inspect entries in Library/Caches, failing closed if entry/depth limits or unreadable subdirs occur
                let childScan = inspectDirectoryChildren(dirURL: resolvedCachesURL, containerRootURL: containerURL)
                for escape in childScan.escapes {
                    escapingSymlinks.append(escape.url.path)
                    indicators.append(ThreatIndicator(
                        signature: "CONTAINER_ESCAPING_SYMLINK",
                        description: "Symbolic link inside Library/Caches points outside container boundary to '\(escape.destination)' (unauthorized container escape vector).",
                        category: ThreatIndicator.Category.escapingSymlink,
                        location: escape.url.path,
                        severity: .highRisk
                    ))
                }
                if childScan.hitEntryLimit || childScan.hitDepthLimit {
                    let limitDetail = childScan.hitEntryLimit
                        ? WQLocale.pick(
                            en: "entry cap (\(childScan.inspectedEntries) items) exceeded",
                            zh: "超过目录条目扫描上限 (\(childScan.inspectedEntries) 项)"
                        )
                        : WQLocale.pick(
                            en: "directory nesting depth cap exceeded",
                            zh: "超过子目录嵌套深度上限"
                        )
                    indicators.append(ThreatIndicator(
                        signature: "CONTAINER_CACHES_SCAN_TRUNCATED",
                        description: WQLocale.pick(
                            en: "Container Library/Caches inspection was truncated (\(limitDetail)); excessive decoy files or deep nesting may conceal an escaping symbolic link.",
                            zh: "容器 Library/Caches 扫描因 \(limitDetail) 被截断，大量诱饵文件或超深嵌套目录可能被用于隐藏逃逸符号链接。"
                        ),
                        category: ThreatIndicator.Category.escapingSymlink,
                        location: cachesURL.path,
                        severity: .highRisk
                    ))
                }
                for unreadablePath in childScan.unreadableSubdirs.prefix(8) {
                    indicators.append(ThreatIndicator(
                        signature: "CONTAINER_CACHES_UNREADABLE_SUBDIR",
                        description: WQLocale.pick(
                            en: "Container Library/Caches contains an unreadable subdirectory ('\(unreadablePath)') that prevented complete symbolic link inspection.",
                            zh: "容器 Library/Caches 内存在无法读取的子目录 ('\(unreadablePath)')，阻碍了完整逃逸符号链接排查。"
                        ),
                        category: ThreatIndicator.Category.escapingSymlink,
                        location: unreadablePath,
                        severity: .highRisk
                    ))
                }
            }
        }

        // 3. Unconditional Fake Supervision Check (strict O_NOFOLLOW regular-file read)
        let supervisionTarget: (root: URL, components: [String], displayURL: URL)?
        if libraryInspection.isSymlink {
            if let resolvedLib = effectiveLibraryURL {
                supervisionTarget = (
                    root: resolvedLib,
                    components: ["ConfigurationProfiles", "CloudConfigurationDetails.plist"],
                    displayURL: resolvedLib.appendingPathComponent("ConfigurationProfiles/CloudConfigurationDetails.plist")
                )
            } else {
                supervisionTarget = nil
            }
        } else {
            supervisionTarget = (
                root: containerURL,
                components: ["Library", "ConfigurationProfiles", "CloudConfigurationDetails.plist"],
                displayURL: containerURL.appendingPathComponent("Library/ConfigurationProfiles/CloudConfigurationDetails.plist")
            )
        }

        if let target = supervisionTarget {
            let cloudConfigURL = target.displayURL
            switch Self.readBoundedRegularFileNoFollow(
                rootURL: target.root,
                relativeComponents: target.components
            ) {
            case .success(let maybeData):
                if let cloudConfig = maybeData,
                   let plist = try? PropertyListSerialization.propertyList(from: cloudConfig, options: [], format: nil) as? [String: Any] {
                    let isSupervised = (plist["IsSupervised"] as? Bool == true) ||
                        ((plist["IsSupervised"] as? NSNumber)?.int64Value ?? 0) != 0
                    if isSupervised {
                        indicators.append(ThreatIndicator(
                            signature: "SYSTEMGROUP_SUPERVISION_DETECTED",
                            description: "CloudConfigurationDetails.plist asserts IsSupervised=true without verified MDM enrollment.",
                            category: "container_configuration",
                            location: cloudConfigURL.path,
                            severity: .highRisk
                        ))
                    }
                }
            case .failure(let hazard):
                if case .symlinkDetected(let symPath) = hazard {
                    let symURL = URL(fileURLWithPath: symPath)
                    let symInsp = inspectPathForEscapingSymlink(targetURL: symURL, containerRootURL: containerURL)
                    if symInsp.isEscaping && !escapingSymlinks.contains(symPath) {
                        escapingSymlinks.append(symPath)
                    }
                    indicators.append(ThreatIndicator(
                        signature: "CONTAINER_SUPERVISION_SYMLINK",
                        description: WQLocale.pick(
                            en: "ConfigurationProfiles supervision path '\(symPath)' is a symbolic link (potential O_NOFOLLOW evasion or cross-container redirect).",
                            zh: "ConfigurationProfiles 监管配置路径 '\(symPath)' 为符号链接（疑似规避检测或跨容器重定向）。"
                        ),
                        category: ThreatIndicator.Category.escapingSymlink,
                        location: symPath,
                        severity: .highRisk
                    ))
                } else if case .specialFileDetected(let specPath) = hazard {
                    indicators.append(ThreatIndicator(
                        signature: "CONTAINER_SUPERVISION_SPECIAL_FILE",
                        description: WQLocale.pick(
                            en: "CloudConfigurationDetails.plist path '\(specPath)' is a non-regular special file (FIFO/device/oversized).",
                            zh: "CloudConfigurationDetails.plist 路径 '\(specPath)' 为非常规特殊文件（FIFO/设备节点或超大文件）。"
                        ),
                        category: "container_configuration",
                        location: specPath,
                        severity: .caution
                    ))
                }
            }
        }

        return ContainerScanResult(
            containerURL: containerURL,
            metadata: metadata,
            escapingSymlinks: escapingSymlinks,
            indicators: indicators
        )
    }

    /// Recursively inspects multiple App Group containers in a parent directory without following symlinks on the parent or child roots.
    public func scanAppGroupContainers(at parentDirectoryURL: URL, maxContainers: Int = 4096) throws -> [ContainerScanResult] {
        let cleanParentPath = IPAPackageScanner.stripTrailingSlashes(parentDirectoryURL.path)
        var parentSt = stat()
        guard lstat(cleanParentPath, &parentSt) == 0 else {
            if errno == ENOENT { return [] }
            throw ContainerScannerError.unreadableDirectory(cleanParentPath, errno)
        }
        let parentMode = parentSt.st_mode & S_IFMT
        if parentMode == S_IFLNK {
            throw ContainerScannerError.symlinkParentDirectory(cleanParentPath)
        }
        guard parentMode == S_IFDIR else {
            throw ContainerScannerError.notADirectory(cleanParentPath)
        }

        guard let dp = opendir(cleanParentPath) else {
            throw ContainerScannerError.unreadableDirectory(cleanParentPath, errno)
        }
        defer { closedir(dp) }

        var childNames: [String] = []
        let maxScanEntries = max(maxContainers * 4, 16_384)
        var entryCount = 0
        while let entry = readdir(dp) {
            let name = withUnsafeBytes(of: entry.pointee.d_name) { raw -> String in
                let ptr = raw.baseAddress!.assumingMemoryBound(to: CChar.self)
                return String(cString: ptr)
            }
            if name == "." || name == ".." { continue }
            entryCount += 1
            if entryCount > maxScanEntries { break }
            childNames.append(name)
        }
        childNames.sort()

        let baseDirURL = URL(fileURLWithPath: cleanParentPath, isDirectory: true)
        var results: [ContainerScanResult] = []
        for name in childNames {
            if results.count >= maxContainers { break }
            let containerURL = baseDirURL.appendingPathComponent(name)
            var st = stat()
            guard lstat(containerURL.path, &st) == 0 else { continue }
            if (st.st_mode & S_IFMT) == S_IFLNK { continue }
            if (st.st_mode & S_IFMT) == S_IFDIR {
                let result = try scanContainer(at: containerURL)
                results.append(result)
            }
        }

        return results
    }

    /// Evaluates if a given path is a symlink and whether its target escapes the container boundary.
    public func inspectPathForEscapingSymlink(
        targetURL: URL,
        containerRootURL: URL
    ) -> (isSymlink: Bool, isDirectory: Bool, isEscaping: Bool, destination: String?) {
        var st = stat()
        guard lstat(targetURL.path, &st) == 0 else {
            return (false, false, false, nil)
        }

        let isSymlink = (st.st_mode & S_IFMT) == S_IFLNK
        let isDirectory = (st.st_mode & S_IFMT) == S_IFDIR

        guard isSymlink else {
            return (false, isDirectory, false, nil)
        }

        // Read destination using readlink (fail-closed if symlink target is unreadable or truncated at PATH_MAX)
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let len = readlink(targetURL.path, &buffer, Int(PATH_MAX))
        guard len > 0 && len < Int(PATH_MAX) else {
            return (true, false, true, "<unreadable-or-oversized-symlink>")
        }
        buffer[len] = 0
        let dest = String(cString: buffer)

        let isEscaping = isDestinationEscaping(destination: dest, relativeTo: targetURL.deletingLastPathComponent(), containerRoot: containerRootURL)
        return (true, false, isEscaping, dest)
    }

    public enum NoFollowReadHazard: Error, Sendable, Equatable {
        case symlinkDetected(String)
        case specialFileDetected(String)
    }

    /// Reads a regular file under `rootURL` component-by-component using `lstat` and `open(O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)`,
    /// guaranteeing zero symlink traversal, zero FIFO/special-file hangs, and strict size capping.
    public static func readBoundedRegularFileNoFollow(
        rootURL: URL,
        relativeComponents: [String],
        maxBytes: Int = 1_048_576
    ) -> Result<Data?, NoFollowReadHazard> {
        guard !relativeComponents.isEmpty else { return .success(nil) }
        var curPath = rootURL.path
        var rootSt = stat()
        guard lstat(curPath, &rootSt) == 0 else { return .success(nil) }
        if (rootSt.st_mode & S_IFMT) == S_IFLNK {
            return .failure(.symlinkDetected(curPath))
        }
        guard (rootSt.st_mode & S_IFMT) == S_IFDIR else { return .success(nil) }

        for idx in 0..<relativeComponents.count {
            let comp = relativeComponents[idx]
            guard !comp.isEmpty, comp != ".", comp != "..", !comp.contains("/") else {
                return .failure(.specialFileDetected(curPath))
            }
            curPath = (curPath as NSString).appendingPathComponent(comp)
            var st = stat()
            guard lstat(curPath, &st) == 0 else {
                return .success(nil)
            }
            let mode = st.st_mode & S_IFMT
            if mode == S_IFLNK {
                return .failure(.symlinkDetected(curPath))
            }
            if idx < relativeComponents.count - 1 {
                guard mode == S_IFDIR else { return .success(nil) }
            } else {
                guard mode == S_IFREG else {
                    return .failure(.specialFileDetected(curPath))
                }
                guard st.st_size >= 0 && st.st_size <= off_t(maxBytes) else {
                    return .failure(.specialFileDetected(curPath))
                }
                let fd = Darwin.open(curPath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard fd >= 0 else {
                    if errno == ELOOP {
                        return .failure(.symlinkDetected(curPath))
                    }
                    return .success(nil)
                }
                defer { Darwin.close(fd) }
                var fst = stat()
                guard fstat(fd, &fst) == 0,
                      (fst.st_mode & S_IFMT) == S_IFREG,
                      fst.st_dev == st.st_dev,
                      fst.st_ino == st.st_ino,
                      fst.st_size >= 0,
                      fst.st_size <= off_t(maxBytes) else {
                    return .failure(.specialFileDetected(curPath))
                }
                let targetLen = Int(fst.st_size)
                if targetLen == 0 {
                    return .success(Data())
                }
                var out = Data()
                out.reserveCapacity(min(targetLen, 65_536))
                var buf = [UInt8](repeating: 0, count: min(targetLen, 16_384))
                while out.count < targetLen {
                    let n = buf.withUnsafeMutableBytes { ptr -> Int in
                        guard let base = ptr.baseAddress else { return -1 }
                        return Darwin.read(fd, base, ptr.count)
                    }
                    if n > 0 {
                        if out.count + n > maxBytes {
                            return .failure(.specialFileDetected(curPath))
                        }
                        out.append(contentsOf: buf[0..<n])
                    } else if n == 0 {
                        break
                    } else if errno == EINTR {
                        continue
                    } else {
                        return .success(nil)
                    }
                }
                return .success(out)
            }
        }
        return .success(nil)
    }

    /// Checks if a symlink destination (or any intermediate/chained in-container symlink hop) escapes container root,
    /// using a true POSIX `namei` token-by-token resolver (`lstat` + `readlink` before `..` collapse) without
    /// `NSString.standardizingPath` (`~` expansion / host filesystem assumptions) or kernel symlink traversal.
    /// Any relative, absolute, or chained-symlink `..` traversal that climbs above `containerRoot` at any intermediate step
    /// is immediately flagged as escaping, even if subsequent path components would lexically re-enter `containerRoot`.
    public func isDestinationEscaping(destination: String, relativeTo parentDir: URL, containerRoot: URL) -> Bool {
        guard !destination.isEmpty, !destination.contains("\0") else {
            return true
        }

        func normalizePrivateAlias(_ comps: [String]) -> [String] {
            if comps.count >= 2,
               comps[0] == "private",
               (comps[1] == "var" || comps[1] == "tmp" || comps[1] == "etc") {
                return Array(comps.dropFirst())
            }
            return comps
        }

        func resolveStaticAbsoluteComponents(_ rawPath: String) -> [String]? {
            guard rawPath.hasPrefix("/"), !rawPath.contains("\0") else { return nil }
            var stack: [String] = []
            for sub in rawPath.split(separator: "/", omittingEmptySubsequences: true) {
                if sub == "." {
                    continue
                } else if sub == ".." {
                    guard !stack.isEmpty else { return nil }
                    stack.removeLast()
                } else {
                    stack.append(String(sub))
                }
            }
            return normalizePrivateAlias(stack)
        }

        let diskRootPath = containerRoot.standardizedFileURL.path
        guard let rootComps = resolveStaticAbsoluteComponents(diskRootPath),
              let parentAbsComps = resolveStaticAbsoluteComponents(parentDir.standardizedFileURL.path),
              parentAbsComps.count >= rootComps.count,
              Array(parentAbsComps.prefix(rootComps.count)) == rootComps else {
            return true
        }

        var currentStack = Array(parentAbsComps.dropFirst(rootComps.count))
        var pendingTokens: [String] = []

        // Tokenizes a raw symlink target onto `(currentStack, pendingTokens)` without prematurely collapsing `..` across symlinks.
        func enqueueTarget(_ target: String) -> Bool {
            guard !target.isEmpty, !target.contains("\0") else { return false }
            if target == "~" || target.hasPrefix("~/") {
                return false
            }
            if target.hasPrefix("/") {
                var rawTokens = target.split(separator: "/", omittingEmptySubsequences: true)
                    .map(String.init)
                    .filter { $0 != "." }
                if rawTokens.count >= 2,
                   rawTokens[0] == "private",
                   (rawTokens[1] == "var" || rawTokens[1] == "tmp" || rawTokens[1] == "etc") {
                    rawTokens.removeFirst()
                }
                guard rawTokens.count >= rootComps.count else {
                    return false
                }
                for i in 0..<rootComps.count {
                    if rawTokens[i] == ".." || rawTokens[i] != rootComps[i] {
                        return false
                    }
                }
                let remainder = Array(rawTokens.dropFirst(rootComps.count))
                if remainder.first == ".." {
                    return false
                }
                currentStack = []
                pendingTokens.insert(contentsOf: remainder, at: 0)
                return pendingTokens.count <= 512
            } else {
                let relTokens = target.split(separator: "/", omittingEmptySubsequences: true)
                    .map(String.init)
                    .filter { $0 != "." }
                pendingTokens.insert(contentsOf: relTokens, at: 0)
                return pendingTokens.count <= 512
            }
        }

        guard enqueueTarget(destination) else {
            return true
        }

        var visitedStates: Set<String> = []
        var symlinkHops = 0

        while !pendingTokens.isEmpty {
            let tok = pendingTokens.removeFirst()
            if tok.isEmpty || tok == "." {
                continue
            }
            if tok == ".." {
                guard !currentStack.isEmpty else {
                    return true
                }
                currentStack.removeLast()
                continue
            }

            var candidateDiskPath = diskRootPath
            for seg in currentStack {
                candidateDiskPath = (candidateDiskPath as NSString).appendingPathComponent(seg)
            }
            candidateDiskPath = (candidateDiskPath as NSString).appendingPathComponent(tok)

            var st = stat()
            if lstat(candidateDiskPath, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK {
                let stateKey = (currentStack + [tok]).joined(separator: "/")
                    + "\u{0}"
                    + pendingTokens.joined(separator: "/")
                if !visitedStates.insert(stateKey).inserted {
                    // Purely internal finite symlink cycle verified to remain inside containerRoot on every step
                    return false
                }
                symlinkHops += 1
                guard symlinkHops <= 32 else {
                    return true
                }
                var linkBuf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
                let rLen = readlink(candidateDiskPath, &linkBuf, Int(PATH_MAX))
                guard rLen > 0 && rLen < Int(PATH_MAX) else {
                    return true
                }
                linkBuf[rLen] = 0
                let hopDest = String(cString: linkBuf)
                guard enqueueTarget(hopDest) else {
                    return true
                }
            } else {
                currentStack.append(tok)
            }
        }

        return false
    }

    /// Resolves a strictly non-escaping symlink target to an existing in-container `S_IFDIR` URL
    /// using token-by-token `lstat` + `readlink` traversal (never consulting OS symlink resolution).
    /// Returns `nil` for escaping, cyclic, dangling, or non-directory targets.
    internal func resolveInContainerDirectory(targetURL: URL, containerRootURL: URL) -> URL? {
        func normalizePrivateAlias(_ comps: [String]) -> [String] {
            if comps.count >= 2,
               comps[0] == "private",
               (comps[1] == "var" || comps[1] == "tmp" || comps[1] == "etc") {
                return Array(comps.dropFirst())
            }
            return comps
        }

        func resolveStaticAbsoluteComponents(_ rawPath: String) -> [String]? {
            guard rawPath.hasPrefix("/"), !rawPath.contains("\0") else { return nil }
            var stack: [String] = []
            for sub in rawPath.split(separator: "/", omittingEmptySubsequences: true) {
                if sub == "." {
                    continue
                } else if sub == ".." {
                    guard !stack.isEmpty else { return nil }
                    stack.removeLast()
                } else {
                    stack.append(String(sub))
                }
            }
            return normalizePrivateAlias(stack)
        }

        let diskRootPath = IPAPackageScanner.stripTrailingSlashes(containerRootURL.standardizedFileURL.path)
        let targetStdPath = IPAPackageScanner.stripTrailingSlashes(targetURL.standardizedFileURL.path)
        guard let rootComps = resolveStaticAbsoluteComponents(diskRootPath),
              let targetComps = resolveStaticAbsoluteComponents(targetStdPath),
              targetComps.count >= rootComps.count,
              Array(targetComps.prefix(rootComps.count)) == rootComps else {
            return nil
        }

        var currentStack: [String] = []
        var pendingTokens = Array(targetComps.dropFirst(rootComps.count))
        var visitedStates: Set<String> = []
        var symlinkHops = 0

        func enqueueTarget(_ rawTarget: String) -> Bool {
            guard !rawTarget.isEmpty, !rawTarget.contains("\0") else { return false }
            if rawTarget == "~" || rawTarget.hasPrefix("~/") { return false }
            if rawTarget.hasPrefix("/") {
                var rawTokens = rawTarget.split(separator: "/", omittingEmptySubsequences: true)
                    .map(String.init)
                    .filter { $0 != "." }
                if rawTokens.count >= 2,
                   rawTokens[0] == "private",
                   (rawTokens[1] == "var" || rawTokens[1] == "tmp" || rawTokens[1] == "etc") {
                    rawTokens.removeFirst()
                }
                guard rawTokens.count >= rootComps.count else { return false }
                for i in 0..<rootComps.count {
                    if rawTokens[i] == ".." || rawTokens[i] != rootComps[i] { return false }
                }
                let remainder = Array(rawTokens.dropFirst(rootComps.count))
                if remainder.first == ".." { return false }
                currentStack = []
                pendingTokens.insert(contentsOf: remainder, at: 0)
                return pendingTokens.count <= 512
            } else {
                let relTokens = rawTarget.split(separator: "/", omittingEmptySubsequences: true)
                    .map(String.init)
                    .filter { $0 != "." }
                pendingTokens.insert(contentsOf: relTokens, at: 0)
                return pendingTokens.count <= 512
            }
        }

        while !pendingTokens.isEmpty {
            let tok = pendingTokens.removeFirst()
            if tok.isEmpty || tok == "." { continue }
            if tok == ".." {
                guard !currentStack.isEmpty else { return nil }
                currentStack.removeLast()
                continue
            }

            var candidateDiskPath = diskRootPath
            for seg in currentStack {
                candidateDiskPath = (candidateDiskPath as NSString).appendingPathComponent(seg)
            }
            candidateDiskPath = (candidateDiskPath as NSString).appendingPathComponent(tok)

            var st = stat()
            guard lstat(candidateDiskPath, &st) == 0 else { return nil }
            let mode = st.st_mode & S_IFMT
            if mode == S_IFLNK {
                let stateKey = (currentStack + [tok]).joined(separator: "/")
                    + "\u{0}"
                    + pendingTokens.joined(separator: "/")
                guard visitedStates.insert(stateKey).inserted else { return nil }
                symlinkHops += 1
                guard symlinkHops <= 32 else { return nil }

                var linkBuf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
                let rLen = readlink(candidateDiskPath, &linkBuf, Int(PATH_MAX))
                guard rLen > 0 && rLen < Int(PATH_MAX) else { return nil }
                linkBuf[rLen] = 0
                let hopDest = String(cString: linkBuf)
                guard enqueueTarget(hopDest) else { return nil }
            } else {
                currentStack.append(tok)
            }
        }

        var resolvedDiskPath = diskRootPath
        for seg in currentStack {
            resolvedDiskPath = (resolvedDiskPath as NSString).appendingPathComponent(seg)
        }
        var finalSt = stat()
        guard lstat(resolvedDiskPath, &finalSt) == 0,
              (finalSt.st_mode & S_IFMT) == S_IFDIR else {
            return nil
        }
        return URL(fileURLWithPath: resolvedDiskPath, isDirectory: true)
    }

    internal struct DirectoryChildrenScanOutcome {
        let escapes: [(url: URL, destination: String)]
        let inspectedEntries: Int
        let hitEntryLimit: Bool
        let hitDepthLimit: Bool
        let unreadableSubdirs: [String]
    }

    /// Inspects `Library/Caches` entries (including nested real subdirectories up to bounded depth)
    /// using POSIX `lstat` + `readdir` with zero symlink traversal, reporting truncation or unreadable subdirs.
    internal func inspectDirectoryChildren(
        dirURL: URL,
        containerRootURL: URL,
        maxDepth: Int = 8,
        maxEntries: Int = 4096
    ) -> DirectoryChildrenScanOutcome {
        struct InodeKey: Hashable {
            let dev: dev_t
            let ino: ino_t
        }
        var escapes: [(url: URL, destination: String)] = []
        var visitedDirs: Set<InodeKey> = []
        var inspectedEntries = 0
        var hitEntryLimit = false
        var hitDepthLimit = false
        var unreadableSubdirs: [String] = []

        func directoryHasNonDotEntries(at path: String) -> Bool? {
            guard let subDir = opendir(path) else { return nil }
            defer { closedir(subDir) }
            while let entry = readdir(subDir) {
                let name = withUnsafeBytes(of: entry.pointee.d_name) { raw -> String in
                    let ptr = raw.baseAddress!.assumingMemoryBound(to: CChar.self)
                    return String(cString: ptr)
                }
                if name != "." && name != ".." {
                    return true
                }
            }
            return false
        }

        func walk(currentDirURL: URL, depth: Int) {
            var dirSt = stat()
            guard lstat(currentDirURL.path, &dirSt) == 0,
                  (dirSt.st_mode & S_IFMT) == S_IFDIR else {
                return
            }
            guard visitedDirs.insert(InodeKey(dev: dirSt.st_dev, ino: dirSt.st_ino)).inserted else {
                return
            }
            guard let dir = opendir(currentDirURL.path) else {
                unreadableSubdirs.append(currentDirURL.path)
                return
            }
            defer { closedir(dir) }

            while let entry = readdir(dir) {
                let name = withUnsafeBytes(of: entry.pointee.d_name) { raw -> String in
                    let ptr = raw.baseAddress!.assumingMemoryBound(to: CChar.self)
                    return String(cString: ptr)
                }
                if name == "." || name == ".." { continue }
                if inspectedEntries >= maxEntries {
                    hitEntryLimit = true
                    break
                }
                inspectedEntries += 1

                let childURL = currentDirURL.appendingPathComponent(name)
                let inspection = inspectPathForEscapingSymlink(targetURL: childURL, containerRootURL: containerRootURL)
                if inspection.isSymlink {
                    if inspection.isEscaping, let dest = inspection.destination {
                        escapes.append((url: childURL, destination: dest))
                    } else if let resolvedDirURL = resolveInContainerDirectory(targetURL: childURL, containerRootURL: containerRootURL) {
                        var rSt = stat()
                        if lstat(resolvedDirURL.path, &rSt) == 0 && (rSt.st_mode & S_IFMT) == S_IFDIR {
                            let rKey = InodeKey(dev: rSt.st_dev, ino: rSt.st_ino)
                            if !visitedDirs.contains(rKey) {
                                if depth < maxDepth {
                                    walk(currentDirURL: resolvedDirURL, depth: depth + 1)
                                } else {
                                    switch directoryHasNonDotEntries(at: resolvedDirURL.path) {
                                    case .some(true):
                                        hitDepthLimit = true
                                    case .some(false):
                                        break
                                    case .none:
                                        unreadableSubdirs.append(resolvedDirURL.path)
                                    }
                                }
                            }
                        }
                    }
                } else if inspection.isDirectory {
                    if depth < maxDepth {
                        walk(currentDirURL: childURL, depth: depth + 1)
                    } else {
                        switch directoryHasNonDotEntries(at: childURL.path) {
                        case .some(true):
                            hitDepthLimit = true
                        case .some(false):
                            break
                        case .none:
                            unreadableSubdirs.append(childURL.path)
                        }
                    }
                }
            }
        }

        walk(currentDirURL: dirURL, depth: 0)
        return DirectoryChildrenScanOutcome(
            escapes: escapes,
            inspectedEntries: inspectedEntries,
            hitEntryLimit: hitEntryLimit,
            hitDepthLimit: hitDepthLimit,
            unreadableSubdirs: unreadableSubdirs
        )
    }
}
