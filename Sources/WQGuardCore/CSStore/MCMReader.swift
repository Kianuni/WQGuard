//
//  MCMReader.swift
//  WQGuardCore
//
//  100% read-only parser for `.com.apple.mobile_container_manager.metadata.plist`.
//  Extracts container class, UUID, identifier, and schema version with bounds safety.
//

import Foundation
import Darwin

/// Enumeration of Apple MobileContainerManager container classes.
public enum MCMContainerClass: Int, Codable, Sendable, CustomStringConvertible {
    case appData = 1              // CONTAINER_CLASS_USER (/var/mobile/Containers/Data/Application)
    case vpn = 2                  // CONTAINER_CLASS_VPN
    case system = 3               // CONTAINER_CLASS_SYSTEM
    case temporary = 4            // CONTAINER_CLASS_TEMPORARY
    case bundle = 5               // CONTAINER_CLASS_BUNDLE
    case appGroup = 7             // CONTAINER_CLASS_GROUP_DATA (/var/mobile/Containers/Shared/AppGroup)
    case plugin = 10              // CONTAINER_CLASS_PLUGIN (/var/mobile/Containers/Data/PluginKitPlugin)
    case internalDaemon = 11      // CONTAINER_CLASS_INTERNAL_DAEMON
    case systemGroup = 12         // CONTAINER_CLASS_SYSTEM_GROUP (/var/mobile/Containers/Shared/SystemGroup)
    case unknown = -1

    public init(rawValue: Int) {
        switch rawValue {
        case 1: self = .appData
        case 2: self = .vpn
        case 3: self = .system
        case 4: self = .temporary
        case 5: self = .bundle
        case 7: self = .appGroup
        case 10: self = .plugin
        case 11: self = .internalDaemon
        case 12: self = .systemGroup
        default: self = .unknown
        }
    }

    public var description: String {
        switch self {
        case .appData: return "Application Data (Class 1)"
        case .vpn: return "VPN (Class 2)"
        case .system: return "System (Class 3)"
        case .temporary: return "Temporary (Class 4)"
        case .bundle: return "Bundle (Class 5)"
        case .appGroup: return "App Group (Class 7)"
        case .plugin: return "PluginKit Plugin (Class 10)"
        case .internalDaemon: return "Internal Daemon (Class 11)"
        case .systemGroup: return "System Group (Class 12)"
        case .unknown: return "Unknown"
        }
    }
}

/// Parsed container metadata extracted from `.com.apple.mobile_container_manager.metadata.plist`.
public struct MCMMetadata: Sendable, Equatable, Codable {
    public let identifier: String
    public let uuid: String
    public let containerClass: MCMContainerClass
    public let rawClass: Int
    public let version: Int
    public let user: String?
    public let schemaVersion: Int?
    public let containerURL: URL?

    public init(
        identifier: String,
        uuid: String,
        containerClass: MCMContainerClass,
        rawClass: Int,
        version: Int = 1,
        user: String? = nil,
        schemaVersion: Int? = nil,
        containerURL: URL? = nil
    ) {
        self.identifier = identifier
        self.uuid = uuid
        self.containerClass = containerClass
        self.rawClass = rawClass
        self.version = version
        self.user = user
        self.schemaVersion = schemaVersion
        self.containerURL = containerURL
    }
}

public enum MCMReaderError: Error, Sendable, Equatable, CustomStringConvertible {
    case metadataFileNotFound(path: String)
    case emptyData(path: String)
    case fileTooLarge(size: Int64, maxAllowed: Int64)
    case permissionDenied(path: String)
    case corruptedPlist(reason: String)
    case missingRequiredKey(key: String)
    case invalidUUID(uuid: String)
    case symlinkEncountered(path: String)

    public var description: String {
        switch self {
        case .metadataFileNotFound(let path):
            return "Container metadata plist not found at \(path)."
        case .emptyData(let path):
            return "Metadata plist at \(path) is empty (0 bytes)."
        case .fileTooLarge(let size, let max):
            return "Metadata plist size (\(size) bytes) exceeds safe maximum limit (\(max) bytes)."
        case .permissionDenied(let path):
            return "Permission denied reading container metadata at \(path)."
        case .corruptedPlist(let reason):
            return "Metadata plist is corrupted: \(reason)"
        case .missingRequiredKey(let key):
            return "Metadata plist is missing required key '\(key)'."
        case .invalidUUID(let uuid):
            return "MCMMetadataUUID '\(uuid)' is not a valid UUID string."
        case .symlinkEncountered(let path):
            return "Refusing to follow untrusted symlink for metadata plist at \(path)."
        }
    }
}

/// 100% read-only reader for container metadata files.
public final class MCMReader: Sendable {
    public static let shared = MCMReader()
    public static let metadataFilename = ".com.apple.mobile_container_manager.metadata.plist"
    public static let maxPlistBytes: Int64 = 1024 * 1024 // 1 MB cap

    public init() {}

    /// Reads and parses `.com.apple.mobile_container_manager.metadata.plist` from a container directory URL.
    public func readMetadata(inContainer containerURL: URL) throws -> MCMMetadata {
        let plistURL = containerURL.appendingPathComponent(Self.metadataFilename)
        return try readMetadata(at: plistURL, containerURL: containerURL)
    }

    /// Reads and parses metadata directly from a plist file URL.
    public func readMetadata(at plistURL: URL, containerURL: URL? = nil) throws -> MCMMetadata {
        let path = plistURL.path

        // Check if plist itself is a symlink using lstat
        var st = stat()
        guard lstat(path, &st) == 0 else {
            let err = errno
            if err == ENOENT {
                throw MCMReaderError.metadataFileNotFound(path: path)
            } else if err == EACCES || err == EPERM {
                throw MCMReaderError.permissionDenied(path: path)
            }
            throw MCMReaderError.metadataFileNotFound(path: path)
        }

        if (st.st_mode & S_IFMT) == S_IFLNK {
            throw MCMReaderError.symlinkEncountered(path: path)
        }

        guard st.st_size > 0 else {
            throw MCMReaderError.emptyData(path: path)
        }

        guard st.st_size <= Self.maxPlistBytes else {
            throw MCMReaderError.fileTooLarge(size: st.st_size, maxAllowed: Self.maxPlistBytes)
        }

        // Open strictly with O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            let err = errno
            if err == EACCES || err == EPERM {
                throw MCMReaderError.permissionDenied(path: path)
            } else if err == ELOOP {
                throw MCMReaderError.symlinkEncountered(path: path)
            }
            throw MCMReaderError.metadataFileNotFound(path: path)
        }
        defer { close(fd) }

        var buffer = [UInt8](repeating: 0, count: Int(st.st_size))
        let bytesRead = read(fd, &buffer, Int(st.st_size))
        guard bytesRead == Int(st.st_size) else {
            throw MCMReaderError.corruptedPlist(reason: "Incomplete file read from disk.")
        }

        let data = Data(buffer)
        return try parseMetadata(data: data, containerURL: containerURL ?? plistURL.deletingLastPathComponent())
    }

    /// Parses container metadata from raw Data buffer (supports XML and Binary plist formats).
    public func parseMetadata(data: Data, containerURL: URL? = nil) throws -> MCMMetadata {
        guard !data.isEmpty else {
            throw MCMReaderError.emptyData(path: containerURL?.path ?? "")
        }

        var format = PropertyListSerialization.PropertyListFormat.xml
        let rawObj: Any
        do {
            rawObj = try PropertyListSerialization.propertyList(from: data, options: [], format: &format)
        } catch {
            throw MCMReaderError.corruptedPlist(reason: error.localizedDescription)
        }

        guard let dict = rawObj as? [String: Any] else {
            throw MCMReaderError.corruptedPlist(reason: "Root element is not a dictionary.")
        }

        guard let identifier = dict["MCMMetadataIdentifier"] as? String, !identifier.isEmpty else {
            throw MCMReaderError.missingRequiredKey(key: "MCMMetadataIdentifier")
        }

        guard let uuid = dict["MCMMetadataUUID"] as? String, !uuid.isEmpty else {
            throw MCMReaderError.missingRequiredKey(key: "MCMMetadataUUID")
        }

        guard UUID(uuidString: uuid) != nil else {
            throw MCMReaderError.invalidUUID(uuid: uuid)
        }

        let rawClass = dict["MCMMetadataClass"] as? Int ?? -1
        let containerClass = MCMContainerClass(rawValue: rawClass)
        let version = dict["MCMMetadataVersion"] as? Int ?? 1
        let user = dict["MCMMetadataUser"] as? String
        let schemaVersion = dict["MCMMetadataSchemaVersion"] as? Int

        return MCMMetadata(
            identifier: identifier,
            uuid: uuid,
            containerClass: containerClass,
            rawClass: rawClass,
            version: version,
            user: user,
            schemaVersion: schemaVersion,
            containerURL: containerURL
        )
    }
}
