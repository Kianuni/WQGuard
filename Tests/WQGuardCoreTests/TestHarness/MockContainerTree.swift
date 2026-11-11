import Foundation
import Darwin

/// MockContainerTree constructs temporary App Group container directory structures with
/// `.com.apple.mobile_container_manager.metadata.plist`, `Library/Caches/`, and controlled escaping symlinks.
public final class MockContainerTree: @unchecked Sendable {
    public struct ContainerConfig: Sendable {
        public var appGroupId: String
        public var containerUUID: String
        public var createMetadataPlist: Bool
        public var createCachesDirectory: Bool
        public var escapingSymlinks: [String: String] // relative name -> outside target (e.g. ["escape_passwd": "/etc/passwd"])
        public var benignSymlinks: [String: String]   // relative name -> inside target (e.g. ["local_cache": "SubCache"])
        public var regularFiles: [String: Data]
        public var restrictedPermissionsPaths: [String] // relative paths to set 0o000

        public init(
            appGroupId: String = "group.com.example.app",
            containerUUID: String = UUID().uuidString,
            createMetadataPlist: Bool = true,
            createCachesDirectory: Bool = true,
            escapingSymlinks: [String: String] = [:],
            benignSymlinks: [String: String] = [:],
            regularFiles: [String: Data] = [:],
            restrictedPermissionsPaths: [String] = []
        ) {
            self.appGroupId = appGroupId
            self.containerUUID = containerUUID
            self.createMetadataPlist = createMetadataPlist
            self.createCachesDirectory = createCachesDirectory
            self.escapingSymlinks = escapingSymlinks
            self.benignSymlinks = benignSymlinks
            self.regularFiles = regularFiles
            self.restrictedPermissionsPaths = restrictedPermissionsPaths
        }
    }

    public let rootDirectoryURL: URL
    private var createdContainers: [URL] = []

    public init(baseDirectory: URL? = nil) {
        let base = baseDirectory ?? FileManager.default.temporaryDirectory
        self.rootDirectoryURL = base.appendingPathComponent("mock_app_group_containers_\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: self.rootDirectoryURL, withIntermediateDirectories: true)
    }

    deinit {
        cleanUp()
    }

    public func cleanUp() {
        // Restore permissions if any were zeroed before deleting (skip symlinks so we don't chmod targets like /etc/passwd)
        for container in createdContainers {
            let enumerator = FileManager.default.enumerator(at: container, includingPropertiesForKeys: [.isSymbolicLinkKey])
            while let item = enumerator?.nextObject() as? URL {
                if let isSymlink = (try? item.resourceValues(forKeys: [.isSymbolicLinkKey]))?.isSymbolicLink, isSymlink {
                    continue
                }
                _ = try? FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: item.path)
            }
            _ = try? FileManager.default.removeItem(at: container)
        }
        _ = try? FileManager.default.removeItem(at: rootDirectoryURL)
    }

    /// Creates a mock App Group container directory tree matching the config.
    public func createContainer(config: ContainerConfig) throws -> URL {
        let containerURL = rootDirectoryURL.appendingPathComponent(config.containerUUID)
        try FileManager.default.createDirectory(at: containerURL, withIntermediateDirectories: true)
        createdContainers.append(containerURL)

        // 1. Metadata plist
        if config.createMetadataPlist {
            let plistURL = containerURL.appendingPathComponent(".com.apple.mobile_container_manager.metadata.plist")
            let plistDict: [String: Any] = [
                "MCMMetadataIdentifier": config.appGroupId,
                "MCMMetadataUUID": config.containerUUID,
                "MCMMetadataClass": 7, // App Group class
                "MCMMetadataVersion": 1
            ]
            let data = try PropertyListSerialization.data(fromPropertyList: plistDict, format: .xml, options: 0)
            try data.write(to: plistURL)
        }

        // 2. Library/Caches
        let cachesURL = containerURL.appendingPathComponent("Library/Caches")
        if config.createCachesDirectory {
            try FileManager.default.createDirectory(at: cachesURL, withIntermediateDirectories: true)
        }

        // 3. Regular files
        for (relPath, fileData) in config.regularFiles {
            let targetURL = containerURL.appendingPathComponent(relPath)
            try FileManager.default.createDirectory(at: targetURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try fileData.write(to: targetURL)
        }

        // 4. Benign symlinks
        for (symlinkName, target) in config.benignSymlinks {
            let symlinkURL = cachesURL.appendingPathComponent(symlinkName)
            try FileManager.default.createSymbolicLink(at: symlinkURL, withDestinationURL: URL(fileURLWithPath: target))
        }

        // 5. Escaping symlinks (pointing outside container, e.g. /etc/passwd or /var/mobile)
        for (symlinkName, target) in config.escapingSymlinks {
            let symlinkURL = cachesURL.appendingPathComponent(symlinkName)
            try? FileManager.default.removeItem(at: symlinkURL)
            let res = symlink(target, symlinkURL.path)
            guard res == 0 else {
                let err = errno
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(err), userInfo: [NSLocalizedDescriptionKey: "Failed to create symlink: \(String(cString: strerror(err)))"])
            }
        }

        // 6. Restricted permissions paths
        for relPath in config.restrictedPermissionsPaths {
            let pathURL = containerURL.appendingPathComponent(relPath)
            _ = try? FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: pathURL.path)
        }

        return containerURL
    }

    /// Verifies using POSIX `lstat` whether a given URL is a symbolic link without following it.
    public static func isSymbolicLink(at url: URL) -> Bool {
        var st = stat()
        if lstat(url.path, &st) == 0 {
            return (st.st_mode & S_IFMT) == S_IFLNK
        }
        return false
    }

    /// Reads destination of a symbolic link using `readlink`.
    public static func destinationOfSymbolicLink(at url: URL) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let len = readlink(url.path, &buffer, buffer.count - 1)
        if len > 0 {
            buffer[len] = 0
            return String(cString: buffer)
        }
        return nil
    }
}
