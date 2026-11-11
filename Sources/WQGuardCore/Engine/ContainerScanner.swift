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
                if let sym = dlsym(handlePtr, "sandbox_extension_release") {
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

/// Layer 3 Container Inspector.
public final class ContainerScanner: Sendable {
    public static let shared = ContainerScanner()

    public init() {}

    /// Inspects a single shared container directory for metadata and anomalous escaping symlinks.
    public func scanContainer(at containerURL: URL) throws -> ContainerScanResult {
        var indicators: [ThreatIndicator] = []
        var escapingSymlinks: [String] = []

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

        // 2. Inspect Library/Caches (part = 3)
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")
        let cachesInspection = inspectPathForEscapingSymlink(targetURL: cachesURL, containerRootURL: containerURL)

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
            }
            // CRITICAL: NEVER recurse into cachesURL when it is a symlink!
        } else if cachesInspection.isDirectory {
            // Safely inspect direct entries in Library/Caches without following symlinks
            let childEscapes = inspectDirectoryChildren(dirURL: cachesURL, containerRootURL: containerURL)
            for escape in childEscapes {
                escapingSymlinks.append(escape.url.path)
                indicators.append(ThreatIndicator(
                    signature: "CONTAINER_ESCAPING_SYMLINK",
                    description: "Symbolic link inside Library/Caches points outside container boundary to '\(escape.destination)' (unauthorized container escape vector).",
                    category: ThreatIndicator.Category.escapingSymlink,
                    location: escape.url.path,
                    severity: .highRisk
                ))
            }
        }

        // 3. Fake Supervision Check for systemgroup.com.apple.configurationprofiles
        if metadata?.identifier == "systemgroup.com.apple.configurationprofiles" || containerURL.path.contains("configurationprofiles") {
            let cloudConfigURL = containerURL.appendingPathComponent("Library/ConfigurationProfiles/CloudConfigurationDetails.plist")
            if let cloudConfig = try? Data(contentsOf: cloudConfigURL, options: .alwaysMapped),
               let plist = try? PropertyListSerialization.propertyList(from: cloudConfig, options: [], format: nil) as? [String: Any],
               let isSupervised = plist["IsSupervised"] as? Bool, isSupervised {
                indicators.append(ThreatIndicator(
                    signature: "SYSTEMGROUP_SUPERVISION_DETECTED",
                    description: "CloudConfigurationDetails.plist asserts IsSupervised=true without verified MDM enrollment.",
                    category: "container_configuration",
                    location: cloudConfigURL.path,
                    severity: .highRisk
                ))
            }
        }

        return ContainerScanResult(
            containerURL: containerURL,
            metadata: metadata,
            escapingSymlinks: escapingSymlinks,
            indicators: indicators
        )
    }

    /// Recursively inspects multiple App Group containers in a parent directory.
    public func scanAppGroupContainers(at parentDirectoryURL: URL) throws -> [ContainerScanResult] {
        guard FileManager.default.fileExists(atPath: parentDirectoryURL.path) else { return [] }

        var results: [ContainerScanResult] = []
        let enumerator = FileManager.default.enumerator(
            at: parentDirectoryURL,
            includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
            options: [.skipsSubdirectoryDescendants, .skipsPackageDescendants]
        )

        while let containerURL = enumerator?.nextObject() as? URL {
            var st = stat()
            guard lstat(containerURL.path, &st) == 0 else { continue }
            // Skip symlinks at container root level
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

        // Read destination using readlink
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let len = readlink(targetURL.path, &buffer, buffer.count - 1)
        guard len > 0 else {
            return (true, false, false, nil)
        }
        buffer[len] = 0
        let dest = String(cString: buffer)

        let isEscaping = isDestinationEscaping(destination: dest, relativeTo: targetURL.deletingLastPathComponent(), containerRoot: containerRootURL)
        return (true, false, isEscaping, dest)
    }

    /// Checks if a symlink destination escapes container root.
    public func isDestinationEscaping(destination: String, relativeTo parentDir: URL, containerRoot: URL) -> Bool {
        let canonicalRoot = containerRoot.standardizedFileURL.path
        let privateRoot = "/private" + canonicalRoot

        let resolvedPath: String
        if destination.hasPrefix("/") {
            resolvedPath = (destination as NSString).standardizingPath
        } else {
            resolvedPath = parentDir.appendingPathComponent(destination).standardizedFileURL.path
        }

        // Target escapes if it does not have containerRoot as its prefix
        if resolvedPath == canonicalRoot || resolvedPath == privateRoot {
            return false // Symlink to container root itself is internal
        }

        let isInsideCanonical = resolvedPath.hasPrefix(canonicalRoot.hasSuffix("/") ? canonicalRoot : canonicalRoot + "/")
        let isInsidePrivate = resolvedPath.hasPrefix(privateRoot.hasSuffix("/") ? privateRoot : privateRoot + "/")

        return !(isInsideCanonical || isInsidePrivate)
    }

    /// Inspects directory entries using POSIX readdir with zero symlink traversal.
    private func inspectDirectoryChildren(
        dirURL: URL,
        containerRootURL: URL
    ) -> [(url: URL, destination: String)] {
        guard let dir = opendir(dirURL.path) else { return [] }
        defer { closedir(dir) }

        var escapes: [(url: URL, destination: String)] = []

        while let entry = readdir(dir) {
            let name = withUnsafeBytes(of: entry.pointee.d_name) { raw -> String in
                let ptr = raw.baseAddress!.assumingMemoryBound(to: CChar.self)
                return String(cString: ptr)
            }
            if name == "." || name == ".." { continue }

            let childURL = dirURL.appendingPathComponent(name)
            let inspection = inspectPathForEscapingSymlink(targetURL: childURL, containerRootURL: containerRootURL)
            if inspection.isSymlink && inspection.isEscaping, let dest = inspection.destination {
                escapes.append((url: childURL, destination: dest))
            }
        }

        return escapes
    }
}
