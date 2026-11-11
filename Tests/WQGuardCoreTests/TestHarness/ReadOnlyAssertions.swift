import Foundation
import XCTest
import Darwin
import CryptoKit

/// ReadOnlyAssertions provides automated verification that scanner operations maintain 100% read-only integrity,
/// guaranteeing that no filesystem mutations occur (bit-for-bit SHA256 checksums and POSIX st_mtimespec stay unchanged),
/// and that target file descriptors are opened strictly with O_RDONLY.
public final class ReadOnlyAssertions: @unchecked Sendable {
    public static let shared = ReadOnlyAssertions()

    public struct FileState: Equatable, Sendable {
        public let path: String
        public let sha256Hex: String?
        public let mtimeSec: Int
        public let mtimeNsec: Int
        public let size: Int64
        public let inode: UInt64
        public let isDirectory: Bool
        public let isSymlink: Bool

        public static func == (lhs: FileState, rhs: FileState) -> Bool {
            return lhs.path == rhs.path &&
                   lhs.sha256Hex == rhs.sha256Hex &&
                   lhs.mtimeSec == rhs.mtimeSec &&
                   lhs.mtimeNsec == rhs.mtimeNsec &&
                   lhs.size == rhs.size &&
                   lhs.inode == rhs.inode &&
                   lhs.isDirectory == rhs.isDirectory &&
                   lhs.isSymlink == rhs.isSymlink
        }
    }

    public struct FilesystemSnapshot: Equatable, Sendable {
        public let files: [String: FileState]

        public init(files: [String: FileState]) {
            self.files = files
        }
    }

    public init() {}

    // MARK: - Snapshot Capture

    /// Captures a point-in-time filesystem snapshot of target URLs (recursively traversing directories).
    public static func captureSnapshot(of urls: [URL]) throws -> FilesystemSnapshot {
        var states: [String: FileState] = [:]

        for url in urls {
            let standardized = url.standardizedFileURL
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: standardized.path, isDirectory: &isDir) else {
                continue
            }

            if isDir.boolValue {
                // Record directory itself
                if let dirState = captureSingleFileState(at: standardized) {
                    states[standardized.path] = dirState
                }
                // Traverse children
                if let enumerator = FileManager.default.enumerator(
                    at: standardized,
                    includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey],
                    options: []
                ) {
                    while let fileURL = enumerator.nextObject() as? URL {
                        let childPath = fileURL.standardizedFileURL.path
                        if let state = captureSingleFileState(at: fileURL) {
                            states[childPath] = state
                        }
                    }
                }
            } else {
                if let state = captureSingleFileState(at: standardized) {
                    states[standardized.path] = state
                }
            }
        }

        return FilesystemSnapshot(files: states)
    }

    private static func captureSingleFileState(at url: URL) -> FileState? {
        var st = stat()
        if lstat(url.path, &st) != 0 {
            return nil
        }

        let isSymlink = (st.st_mode & S_IFMT) == S_IFLNK
        let isDirectory = (st.st_mode & S_IFMT) == S_IFDIR

        var sha256Hex: String? = nil
        if !isSymlink && !isDirectory {
            if let data = try? Data(contentsOf: url, options: .alwaysMapped) {
                let digest = SHA256.hash(data: data)
                sha256Hex = digest.compactMap { String(format: "%02x", $0) }.joined()
            }
        }

        return FileState(
            path: url.standardizedFileURL.path,
            sha256Hex: sha256Hex,
            mtimeSec: Int(st.st_mtimespec.tv_sec),
            mtimeNsec: Int(st.st_mtimespec.tv_nsec),
            size: st.st_size,
            inode: UInt64(st.st_ino),
            isDirectory: isDirectory,
            isSymlink: isSymlink
        )
    }

    // MARK: - Assertions

    /// Asserts that a target directory or file remained bit-for-bit unchanged before and after an operation.
    public static func assertUnmodified(
        before: FilesystemSnapshot,
        after: FilesystemSnapshot,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        XCTAssertEqual(
            before.files.count,
            after.files.count,
            "File count mismatch: before had \(before.files.count) items, after has \(after.files.count)",
            file: file,
            line: line
        )

        for (path, beforeState) in before.files {
            guard let afterState = after.files[path] else {
                XCTFail("File was deleted during read-only operation: \(path)", file: file, line: line)
                continue
            }

            // Check SHA256 integrity
            if let beforeHash = beforeState.sha256Hex {
                XCTAssertEqual(
                    beforeHash,
                    afterState.sha256Hex,
                    "SHA256 checksum changed for \(path) — read-only violation!",
                    file: file,
                    line: line
                )
            }

            // Check modification timestamp
            XCTAssertEqual(
                beforeState.mtimeSec,
                afterState.mtimeSec,
                "Modification timestamp (sec) mutated for \(path) — read-only violation!",
                file: file,
                line: line
            )
            XCTAssertEqual(
                beforeState.mtimeNsec,
                afterState.mtimeNsec,
                "Modification timestamp (nsec) mutated for \(path) — read-only violation!",
                file: file,
                line: line
            )

            // Check file size and inode
            XCTAssertEqual(beforeState.size, afterState.size, "File size mutated for \(path)", file: file, line: line)
            XCTAssertEqual(beforeState.inode, afterState.inode, "Inode changed for \(path)", file: file, line: line)
        }

        // Check for any newly added files
        for path in after.files.keys {
            if before.files[path] == nil {
                XCTFail("New file was unexpectedly created in scanned target: \(path)", file: file, line: line)
            }
        }
    }

    /// Asserts that an open file descriptor was opened strictly in read-only mode (O_RDONLY).
    public static func assertReadOnlyDescriptor(
        fd: Int32,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        let flags = fcntl(fd, F_GETFL)
        XCTAssertGreaterThanOrEqual(flags, 0, "fcntl(F_GETFL) failed on fd \(fd)", file: file, line: line)
        let accessMode = flags & O_ACCMODE
        XCTAssertEqual(accessMode, O_RDONLY, "File descriptor \(fd) is NOT opened O_RDONLY (access mode: \(accessMode))", file: file, line: line)
    }

    /// Executes a scanning block while enforcing that the targets remain 100% bit-for-bit identical before and after.
    @discardableResult
    public static func verifyReadOnlyExecution<T>(
        targetURLs: [URL],
        file: StaticString = #file,
        line: UInt = #line,
        operation: () throws -> T
    ) rethrows -> T {
        let beforeSnapshot = (try? captureSnapshot(of: targetURLs)) ?? FilesystemSnapshot(files: [:])
        let result = try operation()
        let afterSnapshot = (try? captureSnapshot(of: targetURLs)) ?? FilesystemSnapshot(files: [:])
        assertUnmodified(before: beforeSnapshot, after: afterSnapshot, file: file, line: line)
        return result
    }
}
