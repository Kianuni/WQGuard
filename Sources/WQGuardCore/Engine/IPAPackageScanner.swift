//
//  IPAPackageScanner.swift
//  WQGuardCore
//
//  Feature 11: 100% read-only zero-dependency sandboxed IPA package inspector.
//  Parses ZIP archives natively using Darwin zlib (raw Deflate windowBits = -15),
//  safely handling unaligned arm64 memory accesses, zip slip, and zip bomb threats.
//  Extracts relevant bundle metadata and executables into temporary sandbox for
//  Layer 1, Layer 2, and Layer 4 inspection.
//

import Foundation
import zlib

public enum IPAPackageScannerError: Error, LocalizedError, Sendable, Equatable {
    case fileNotFound(String)
    case invalidArchive(String)
    case endOfCentralDirectoryNotFound
    case corruptHeader(String)
    case unsupportedCompressionMethod(UInt16)
    case encryptedArchiveNotSupported
    case decompressionFailed(Int32)
    case zipSlipDetected(String)
    case quotaExceeded(String)
    case missingPayload
    case missingAppBundle
    case invalidInfoPlist(String)
    case missingExecutable(String)
    
    public var errorDescription: String? {
        switch self {
        case .fileNotFound(let path):
            return "IPA 文件未找到: \(path)"
        case .invalidArchive(let msg):
            return "无效的 IPA/ZIP 压缩包: \(msg)"
        case .endOfCentralDirectoryNotFound:
            return "未找到 ZIP 核心目录结束标记 (EOCD)，文件可能损坏或已被截断。"
        case .corruptHeader(let msg):
            return "ZIP 头部数据损坏: \(msg)"
        case .unsupportedCompressionMethod(let method):
            return "不支持的 ZIP 压缩算法 (ID: \(method))，仅支持 Store(0) 与 Deflate(8)。"
        case .encryptedArchiveNotSupported:
            return "不支持带密码保护的加密 ZIP 压缩包。"
        case .decompressionFailed(let code):
            return "zlib 解压失败，错误码: \(code)"
        case .zipSlipDetected(let path):
            return "检测到 Zip Slip 目录穿越恶意路径: \(path)，已终止解压。"
        case .quotaExceeded(let msg):
            return "超出安全配额限制 (解压炸弹防御): \(msg)"
        case .missingPayload:
            return "IPA 压缩包中缺少 Payload 目录。"
        case .missingAppBundle:
            return "Payload 目录下未找到有效的 .app 应用程序包。"
        case .invalidInfoPlist(let msg):
            return "无法读取或解析 Info.plist: \(msg)"
        case .missingExecutable(let name):
            return "应用包中未找到主可执行文件: \(name)"
        }
    }
}

/// Lightweight, 100% read-only, zero-dependency ZIP archive entry descriptor.
public struct ZIPArchiveEntry: Sendable, Equatable {
    public let path: String
    public let compressionMethod: UInt16
    public let compressedSize: Int
    public let uncompressedSize: Int
    public let crc32: UInt32
    public let localHeaderOffset: Int
    public let isDirectory: Bool
    public let externalFileAttributes: UInt32

    public init(
        path: String,
        compressionMethod: UInt16,
        compressedSize: Int,
        uncompressedSize: Int,
        crc32: UInt32,
        localHeaderOffset: Int,
        isDirectory: Bool,
        externalFileAttributes: UInt32
    ) {
        self.path = path
        self.compressionMethod = compressionMethod
        self.compressedSize = compressedSize
        self.uncompressedSize = uncompressedSize
        self.crc32 = crc32
        self.localHeaderOffset = localHeaderOffset
        self.isDirectory = isDirectory
        self.externalFileAttributes = externalFileAttributes
    }
}

/// Zero-dependency ZIP archive reader using Darwin zlib.
public final class NativeZIPArchiveReader: @unchecked Sendable {
    private let data: Data
    private let maxEntries: Int
    private let maxTotalUncompressedBytes: Int
    
    public init(
        data: Data,
        maxEntries: Int = 20_000,
        maxTotalUncompressedBytes: Int = 1024 * 1024 * 1024 // 1 GB
    ) {
        self.data = data
        self.maxEntries = maxEntries
        self.maxTotalUncompressedBytes = maxTotalUncompressedBytes
    }
    
    /// Parses the Central Directory of the ZIP archive.
    public func readCentralDirectory() throws -> [ZIPArchiveEntry] {
        guard data.count >= 22 else {
            throw IPAPackageScannerError.invalidArchive("文件大小小于 22 字节")
        }
        
        // Scan backwards from end for End of Central Directory signature: 0x06054b50
        var eocdOffset: Int? = nil
        let maxCommentLength = min(data.count - 22, 65535)
        let searchFloor = data.count - 22 - maxCommentLength
        
        for offset in stride(from: data.count - 22, through: searchFloor, by: -1) {
            let sig = data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: offset, as: UInt32.self).littleEndian
            }
            if sig == 0x06054b50 {
                eocdOffset = offset
                break
            }
        }
        
        guard let eocd = eocdOffset else {
            throw IPAPackageScannerError.endOfCentralDirectoryNotFound
        }
        
        let totalEntries = Int(data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: eocd + 10, as: UInt16.self).littleEndian
        })
        guard totalEntries <= maxEntries else {
            throw IPAPackageScannerError.quotaExceeded("ZIP 条目总数 (\(totalEntries)) 超过上限 (\(maxEntries))")
        }
        
        let cdSize = Int(data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: eocd + 12, as: UInt32.self).littleEndian
        })
        let cdOffset = Int(data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: eocd + 16, as: UInt32.self).littleEndian
        })
        
        guard cdOffset >= 0, cdSize >= 0, cdOffset + cdSize <= data.count else {
            throw IPAPackageScannerError.corruptHeader("核心目录偏移或大小超出文件边界")
        }
        
        var entries: [ZIPArchiveEntry] = []
        entries.reserveCapacity(min(totalEntries, 1024))
        
        var cur = cdOffset
        var cumulativeUncompressedBytes = 0
        
        for _ in 0..<totalEntries {
            guard cur + 46 <= cdOffset + cdSize else { break }
            let sig = data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur, as: UInt32.self).littleEndian
            }
            guard sig == 0x02014b50 else {
                throw IPAPackageScannerError.corruptHeader("核心目录头部魔数不匹配")
            }
            
            let flags = data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur + 8, as: UInt16.self).littleEndian
            }
            if (flags & 1) != 0 {
                throw IPAPackageScannerError.encryptedArchiveNotSupported
            }
            
            let method = data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur + 10, as: UInt16.self).littleEndian
            }
            let crc = data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur + 16, as: UInt32.self).littleEndian
            }
            let compSize = Int(data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur + 20, as: UInt32.self).littleEndian
            })
            let uncompSize = Int(data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur + 24, as: UInt32.self).littleEndian
            })
            let nameLen = Int(data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur + 28, as: UInt16.self).littleEndian
            })
            let extraLen = Int(data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur + 30, as: UInt16.self).littleEndian
            })
            let commentLen = Int(data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur + 32, as: UInt16.self).littleEndian
            })
            let extAttrs = data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur + 38, as: UInt32.self).littleEndian
            }
            let localOffset = Int(data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: cur + 42, as: UInt32.self).littleEndian
            })
            
            guard cur + 46 + nameLen <= data.count else {
                throw IPAPackageScannerError.corruptHeader("文件名超出数据边界")
            }
            let nameData = data.subdata(in: (cur + 46)..<(cur + 46 + nameLen))
            let path = String(decoding: nameData, as: UTF8.self)
            
            // Zip Slip validation: block absolute paths, Windows backslashes, NUL bytes, and ".." path segments
            // without false-positively rejecting valid filenames containing consecutive dots (e.g. "icon..png").
            let hasParentTraversal = path
                .split(separator: "/", omittingEmptySubsequences: false)
                .contains("..")
            if hasParentTraversal || path.hasPrefix("/") || path.contains("\\") || path.contains("\0") {
                throw IPAPackageScannerError.zipSlipDetected(path)
            }
            guard compSize >= 0, uncompSize >= 0 else {
                throw IPAPackageScannerError.corruptHeader("ZIP 条目大小字段异常")
            }
            
            cumulativeUncompressedBytes += uncompSize
            if cumulativeUncompressedBytes > maxTotalUncompressedBytes {
                throw IPAPackageScannerError.quotaExceeded("解压总数据量超过上限 (\(maxTotalUncompressedBytes) 字节)")
            }
            
            let isDir = path.hasSuffix("/")
            entries.append(ZIPArchiveEntry(
                path: path,
                compressionMethod: method,
                compressedSize: compSize,
                uncompressedSize: uncompSize,
                crc32: crc,
                localHeaderOffset: localOffset,
                isDirectory: isDir,
                externalFileAttributes: extAttrs
            ))
            
            cur += 46 + nameLen + extraLen + commentLen
        }
        
        return entries
    }
    
    /// Extracts a single entry's uncompressed data.
    public func extract(entry: ZIPArchiveEntry) throws -> Data {
        if entry.isDirectory || entry.uncompressedSize == 0 {
            if entry.compressionMethod == 8 && entry.compressedSize > 64 {
                // Guard against spoofed 0-byte uncompressedSize header hiding a Deflate bomb
                var strm = z_stream()
                let initStatus = inflateInit2_(&strm, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
                if initStatus == Z_OK {
                    defer { inflateEnd(&strm) }
                    let localOffset = entry.localHeaderOffset
                    if localOffset + 30 <= data.count {
                        let nameLen = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: localOffset + 26, as: UInt16.self).littleEndian })
                        let extraLen = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: localOffset + 28, as: UInt16.self).littleEndian })
                        let dataStart = localOffset + 30 + nameLen + extraLen
                        let dataEnd = dataStart + entry.compressedSize
                        if dataEnd <= data.count {
                            let rawCompressed = data.subdata(in: dataStart..<dataEnd)
                            var probe = Data(count: 1)
                            let st = rawCompressed.withUnsafeBytes { inPtr in
                                probe.withUnsafeMutableBytes { outPtr in
                                    strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
                                    strm.avail_in = uInt(entry.compressedSize)
                                    strm.next_out = outPtr.bindMemory(to: Bytef.self).baseAddress
                                    strm.avail_out = 1
                                    return inflate(&strm, Z_FINISH)
                                }
                            }
                            if strm.total_out > 0 || (st == Z_OK && strm.avail_in > 0) {
                                throw IPAPackageScannerError.quotaExceeded("ZIP 条目实际解压体积超出声明大小 0 字节")
                            }
                        }
                    }
                }
            }
            return Data()
        }
        
        let localOffset = entry.localHeaderOffset
        guard localOffset + 30 <= data.count else {
            throw IPAPackageScannerError.corruptHeader("本地文件头超出数据边界")
        }
        
        let localSig = data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: localOffset, as: UInt32.self).littleEndian
        }
        guard localSig == 0x04034b50 else {
            throw IPAPackageScannerError.corruptHeader("本地文件头魔数无效: \(String(format: "0x%08x", localSig))")
        }
        
        let nameLen = Int(data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: localOffset + 26, as: UInt16.self).littleEndian
        })
        let extraLen = Int(data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: localOffset + 28, as: UInt16.self).littleEndian
        })
        
        let dataStart = localOffset + 30 + nameLen + extraLen
        let dataEnd = dataStart + entry.compressedSize
        guard dataEnd <= data.count else {
            throw IPAPackageScannerError.corruptHeader("压缩文件数据段截断")
        }
        
        let rawCompressed = data.subdata(in: dataStart..<dataEnd)
        
        switch entry.compressionMethod {
        case 0: // STORE
            return rawCompressed
        case 8: // DEFLATE
            var strm = z_stream()
            // windowBits = -15 denotes raw deflate without zlib header (RFC 1951 standard for ZIP)
            let initStatus = inflateInit2_(&strm, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
            guard initStatus == Z_OK else {
                throw IPAPackageScannerError.decompressionFailed(initStatus)
            }
            defer { inflateEnd(&strm) }
            
            // Allocate +1 sentinel byte so Z_FINISH reliably detects streams inflating past declared uncompressedSize
            var decompressed = Data(count: entry.uncompressedSize + 1)
            let status: Int32 = rawCompressed.withUnsafeBytes { inPtr in
                decompressed.withUnsafeMutableBytes { outPtr in
                    strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
                    strm.avail_in = uInt(entry.compressedSize)
                    strm.next_out = outPtr.bindMemory(to: Bytef.self).baseAddress
                    strm.avail_out = uInt(entry.uncompressedSize + 1)
                    return inflate(&strm, Z_FINISH)
                }
            }
            
            if Int(strm.total_out) > entry.uncompressedSize || (status == Z_OK && strm.avail_out == 0) {
                throw IPAPackageScannerError.quotaExceeded("ZIP 条目实际解压字节数超过声明上限 (\(entry.uncompressedSize) 字节)")
            }
            guard status == Z_STREAM_END || status == Z_OK else {
                throw IPAPackageScannerError.decompressionFailed(status)
            }
            decompressed.count = Int(strm.total_out)
            return decompressed
        default:
            throw IPAPackageScannerError.unsupportedCompressionMethod(entry.compressionMethod)
        }
    }
}

/// 100% read-only, sandboxed IPA package scanner with zero external dependencies.
public final class IPAPackageScanner: @unchecked Sendable {
    public static let shared = IPAPackageScanner()
    
    public init() {}
    
    /// Safely unpacks relevant inspection targets from an `.ipa` into a temporary sandbox.
    /// Uses deterministic RAII scoped execution with guaranteed deletion.
    public func withTemporarySandbox<T>(
        ipaURL: URL,
        block: (URL, [ZIPArchiveEntry]) throws -> T
    ) throws -> T {
        let ipaData = try Data(contentsOf: ipaURL, options: .mappedIfSafe)
        let reader = NativeZIPArchiveReader(data: ipaData)
        let entries = try reader.readCentralDirectory()
        
        // Find the primary Payload/*.app bundle prefix
        guard let appEntry = entries.first(where: {
            let p = $0.path
            return (p.hasPrefix("Payload/") || p.hasPrefix("payload/")) && p.contains(".app/")
        }) else {
            throw IPAPackageScannerError.missingPayload
        }
        
        let pathComponents = appEntry.path.split(separator: "/")
        guard pathComponents.count >= 2, pathComponents[1].hasSuffix(".app") else {
            throw IPAPackageScannerError.missingAppBundle
        }
        let appBundleName = String(pathComponents[1])
        let appBundlePrefix = "\(pathComponents[0])/\(appBundleName)/"
        
        // Allocate deterministic scoped sandbox directory
        let tempSandbox = FileManager.default.temporaryDirectory
            .appendingPathComponent("wqguard_ipa_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempSandbox, withIntermediateDirectories: true)
        
        defer {
            try? FileManager.default.removeItem(at: tempSandbox)
        }
        
        let sandboxCanonicalPath = tempSandbox.standardizedFileURL.path
        let bundleURL = tempSandbox.appendingPathComponent(appBundleName)
        try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)
        
        // Extract required security auditing files preserving relative path (stripping archive symlinks)
        for entry in entries where entry.path.hasPrefix(appBundlePrefix) {
            let relativePath = String(entry.path.dropFirst(appBundlePrefix.count))
            if relativePath.isEmpty { continue }

            // Strip POSIX symbolic link entries (S_IFLNK = 0o120000) so archive symlinks are never materialized on disk
            let unixMode = (entry.externalFileAttributes >> 16) & 0o170000
            if unixMode == 0o120000 {
                continue
            }
            
            let destURL = bundleURL.appendingPathComponent(relativePath)
            let destCanonical = destURL.standardizedFileURL.path
            guard destCanonical.hasPrefix(sandboxCanonicalPath + "/") || destCanonical == sandboxCanonicalPath else {
                throw IPAPackageScannerError.zipSlipDetected(entry.path)
            }
            
            if entry.isDirectory {
                try FileManager.default.createDirectory(at: destURL, withIntermediateDirectories: true)
            } else {
                // Filter: Skip bulky UI/media/localization assets while preserving all Mach-O executables, dylibs, plists, mobileprovision, and receipts
                let ext = destURL.pathExtension.lowercased()
                let skippedAssetExtensions: Set<String> = [
                    "png", "jpg", "jpeg", "gif", "webp", "heic", "ico", "bmp", "tiff",
                    "car", "nib", "storyboardc", "strings", "stringsdict", "xcprivacy",
                    "mp3", "mp4", "m4a", "wav", "caf", "aac", "mov",
                    "ttf", "otf", "ttc", "woff", "woff2",
                    "html", "css", "js", "svg", "pdf", "txt", "md",
                    "mom", "omo", "metallib", "usdz", "scn"
                ]
                let isRelevant = !skippedAssetExtensions.contains(ext) ||
                                 entry.path.contains("/_MASReceipt/") ||
                                 entry.path.contains("/StoreKit/")
                
                if isRelevant {
                    let parentDir = destURL.deletingLastPathComponent()
                    try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
                    let fileData = try reader.extract(entry: entry)
                    try fileData.write(to: destURL, options: .atomic)
                    
                    // Restore executable permissions if indicated
                    if (entry.externalFileAttributes >> 16) & 0o111 != 0 {
                        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: destURL.path)
                    }
                }
            }
        }
        
        return try block(bundleURL, entries)
    }
    
    /// Complete scan of a local `.ipa` package conforming to Layers 1, 2, and 4.
    public func scan(ipaURL: URL) throws -> ScanFinding {
        guard FileManager.default.fileExists(atPath: ipaURL.path) else {
            throw IPAPackageScannerError.fileNotFound(ipaURL.path)
        }
        
        return try withTemporarySandbox(ipaURL: ipaURL) { (bundleURL, _) in
            // 1. Parse Info.plist
            let infoPlistURL = bundleURL.appendingPathComponent("Info.plist")
            guard FileManager.default.fileExists(atPath: infoPlistURL.path),
                  let plistData = try? Data(contentsOf: infoPlistURL),
                  let infoDict = (try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil)) as? [String: Any] else {
                throw IPAPackageScannerError.invalidInfoPlist("找不到或无法解析 Info.plist")
            }
            
            let bundleId = infoDict["CFBundleIdentifier"] as? String ?? "unknown.bundle"
            let appName = infoDict["CFBundleDisplayName"] as? String ?? infoDict["CFBundleName"] as? String ?? ipaURL.deletingPathExtension().lastPathComponent
            let version = infoDict["CFBundleShortVersionString"] as? String ?? infoDict["CFBundleVersion"] as? String ?? "1.0"
            let execName = infoDict["CFBundleExecutable"] as? String ?? appName
            
            let mainExecURL = bundleURL.appendingPathComponent(execName)
            guard FileManager.default.fileExists(atPath: mainExecURL.path) else {
                throw IPAPackageScannerError.missingExecutable(execName)
            }
            
            let mainExecData = try Data(contentsOf: mainExecURL, options: .mappedIfSafe)
            let mainSlices = try MachOParser.shared.parseAllSlices(data: mainExecData)
            let mainDetails = MachOScanner.shared.parseMachO(files: mainSlices, rawData: mainExecData)
            
            // 2. Layer 1: Install Channel & Entitlement Gating (merging XML Slot 5 + DER Slot 7 across all slices)
            let channelResult = ChannelClassifier.classifyBundle(at: bundleURL, cryptid: mainDetails.cryptid)
            var mainAppGroups: [String] = []
            var entitlementsDict: [String: Any] = [:]
            for slice in mainSlices {
                let (_, sliceGroups) = CSBlobParser.shared.extractAppGroups(from: slice.codeSignatureData)
                for g in sliceGroups where !mainAppGroups.contains(g) {
                    mainAppGroups.append(g)
                }
                let sliceEnts = CSBlobParser.shared.parseMergedEntitlements(from: slice.codeSignatureData)
                for (k, v) in sliceEnts where entitlementsDict[k] == nil {
                    entitlementsDict[k] = v
                }
            }
            let gating = EntitlementGating.evaluate(hasAppGroups: !mainAppGroups.isEmpty, appGroups: mainAppGroups)
            var combinedAppGroups = gating.appGroups
            let backgroundModes = infoDict["UIBackgroundModes"] as? [String] ?? []
            
            // 3. Layer 2: Main Executable Scan
            let scanContext = MachOScanner.ScanContext(
                bundleId: bundleId,
                displayName: appName,
                version: version,
                teamId: channelResult.teamIdentifier,
                bundlePath: ipaURL.path,
                executablePath: mainExecURL.path,
                installChannel: channelResult.channel,
                appGroups: gating.appGroups
            )
            
            var allIndicators: [ThreatIndicator] = []
            var allMatchedSymbols: Set<String> = []
            var allLinkedDylibs: Set<String> = Set(mainDetails.linkedDylibs)
            var allSymbols: Set<String> = Set(mainDetails.symbols)
            var dynamicLoadingFound = false
            var pathEnumerationFound = false
            
            // Scan main executable
            let mainFinding = MachOScanner.shared.scan(details: mainDetails, context: scanContext)
            allIndicators.append(contentsOf: mainFinding.indicators)
            allMatchedSymbols.formUnion(mainFinding.evidence.matchedSymbols)
            if mainFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
            if mainFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
            
            // 4. Scan Embedded Frameworks & Dynamic Libraries across the entire .app (Frameworks/, Dylibs/, DynamicLibraries/, root *.dylib)
            let mainExecCanonical = mainExecURL.standardizedFileURL.path
            let pluginsPrefix = bundleURL.appendingPathComponent("PlugIns").standardizedFileURL.path + "/"
            if let bundleEnum = FileManager.default.enumerator(at: bundleURL, includingPropertiesForKeys: [.isRegularFileKey]) {
                while let itemURL = bundleEnum.nextObject() as? URL {
                    let itemCanonical = itemURL.standardizedFileURL.path
                    if itemCanonical == mainExecCanonical || itemCanonical.hasPrefix(pluginsPrefix) {
                        continue
                    }
                    let isDylib = itemURL.pathExtension.lowercased() == "dylib"
                    let isFrameworkBinary = itemURL.deletingLastPathComponent().pathExtension.lowercased() == "framework" && itemURL.pathExtension.isEmpty
                    
                    if isDylib || isFrameworkBinary {
                        let relPath = itemURL.path.replacingOccurrences(of: bundleURL.path + "/", with: "")
                        if isDylib {
                            allLinkedDylibs.insert("@executable_path/\(relPath)")
                        }
                        if let dylibData = try? Data(contentsOf: itemURL, options: .mappedIfSafe),
                           let fwSlices = try? MachOParser.shared.parseAllSlices(data: dylibData),
                           !fwSlices.isEmpty {
                            let fwDetails = MachOScanner.shared.parseMachO(files: fwSlices, rawData: dylibData)
                            var fwGroups = gating.appGroups
                            for s in fwSlices {
                                let (_, sg) = CSBlobParser.shared.extractAppGroups(from: s.codeSignatureData)
                                for g in sg where !fwGroups.contains(g) { fwGroups.append(g) }
                            }
                            let fwContext = MachOScanner.ScanContext(
                                bundleId: bundleId,
                                displayName: appName,
                                version: version,
                                teamId: channelResult.teamIdentifier,
                                bundlePath: ipaURL.path,
                                executablePath: itemURL.path,
                                installChannel: channelResult.channel,
                                appGroups: fwGroups
                            )
                            let fwFinding = MachOScanner.shared.scan(details: fwDetails, context: fwContext)
                            
                            for ind in fwFinding.indicators {
                                allIndicators.append(ThreatIndicator(
                                    signature: ind.signature,
                                    description: "\(ind.description) [\(relPath)]",
                                    category: ind.category,
                                    location: "\(relPath): \(ind.location)",
                                    severity: ind.severity
                                ))
                            }
                            allMatchedSymbols.formUnion(fwFinding.evidence.matchedSymbols)
                            allLinkedDylibs.formUnion(fwDetails.linkedDylibs)
                            allSymbols.formUnion(fwDetails.symbols)
                            if fwFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
                            if fwFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
                        }
                    }
                }
            }
            
            // 5. Scan Embedded App Extensions (PlugIns/*.appex) with each extension's OWN independent CSBlob entitlements
            let pluginsURL = bundleURL.appendingPathComponent("PlugIns")
            if FileManager.default.fileExists(atPath: pluginsURL.path) {
                let plugEnumerator = FileManager.default.enumerator(at: pluginsURL, includingPropertiesForKeys: [.isDirectoryKey])
                while let itemURL = plugEnumerator?.nextObject() as? URL {
                    if itemURL.pathExtension.lowercased() == "appex" {
                        let plugInfoPlistURL = itemURL.appendingPathComponent("Info.plist")
                        if let pData = try? Data(contentsOf: plugInfoPlistURL),
                           let pDict = (try? PropertyListSerialization.propertyList(from: pData, options: [], format: nil)) as? [String: Any],
                           let plugExec = pDict["CFBundleExecutable"] as? String {
                            let plugBundleId = pDict["CFBundleIdentifier"] as? String ?? "\(bundleId).appex"
                            let plugName = pDict["CFBundleDisplayName"] as? String ?? pDict["CFBundleName"] as? String ?? plugExec
                            let plugBgModes = pDict["UIBackgroundModes"] as? [String] ?? []
                            let plugBinURL = itemURL.appendingPathComponent(plugExec)
                            if let binData = try? Data(contentsOf: plugBinURL, options: .mappedIfSafe),
                               let plugSlices = try? MachOParser.shared.parseAllSlices(data: binData),
                               !plugSlices.isEmpty {
                                let plugDetails = MachOScanner.shared.parseMachO(files: plugSlices, rawData: binData)
                                var plugGroups: [String] = []
                                for s in plugSlices {
                                    let (_, sg) = CSBlobParser.shared.extractAppGroups(from: s.codeSignatureData)
                                    for g in sg where !plugGroups.contains(g) { plugGroups.append(g) }
                                    let sEnts = CSBlobParser.shared.parseMergedEntitlements(from: s.codeSignatureData)
                                    for (k, v) in sEnts where entitlementsDict[k] == nil {
                                        entitlementsDict[k] = v
                                    }
                                }
                                let plugGating = EntitlementGating.evaluate(hasAppGroups: !plugGroups.isEmpty, appGroups: plugGroups)
                                for g in plugGating.appGroups where !combinedAppGroups.contains(g) {
                                    combinedAppGroups.append(g)
                                }
                                let plugContext = MachOScanner.ScanContext(
                                    bundleId: plugBundleId,
                                    displayName: plugName,
                                    version: version,
                                    teamId: channelResult.teamIdentifier,
                                    bundlePath: itemURL.path,
                                    executablePath: plugBinURL.path,
                                    installChannel: channelResult.channel,
                                    appGroups: plugGating.appGroups
                                )
                                let plugFinding = MachOScanner.shared.scan(details: plugDetails, context: plugContext)
                                
                                let relPath = plugBinURL.path.replacingOccurrences(of: bundleURL.path + "/", with: "")
                                for ind in plugFinding.indicators {
                                    allIndicators.append(ThreatIndicator(
                                        signature: ind.signature,
                                        description: "\(ind.description) [\(relPath)]",
                                        category: ind.category,
                                        location: "\(relPath): \(ind.location)",
                                        severity: ind.severity
                                    ))
                                }
                                allMatchedSymbols.formUnion(plugFinding.evidence.matchedSymbols)
                                allLinkedDylibs.formUnion(plugDetails.linkedDylibs)
                                allSymbols.formUnion(plugDetails.symbols)
                                if plugFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
                                if plugFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }

                                if !plugDetails.isFairPlayEncrypted,
                                   let extClip = ExpandedThreatCatalog.evaluateClipboardSnooping(
                                       backgroundModes: plugBgModes,
                                       symbols: plugDetails.symbols,
                                       cryptid: plugDetails.cryptid
                                   ) {
                                    allIndicators.append(extClip)
                                }

                                // Also scan any dylibs/frameworks nested inside this .appex
                                let plugBinCanonical = plugBinURL.standardizedFileURL.path
                                if let extEnum = FileManager.default.enumerator(at: itemURL, includingPropertiesForKeys: [.isRegularFileKey]) {
                                    while let subURL = extEnum.nextObject() as? URL {
                                        if subURL.standardizedFileURL.path == plugBinCanonical { continue }
                                        let subIsDylib = subURL.pathExtension.lowercased() == "dylib"
                                        let subIsFw = subURL.deletingLastPathComponent().pathExtension.lowercased() == "framework" && subURL.pathExtension.isEmpty
                                        if subIsDylib || subIsFw,
                                           let subData = try? Data(contentsOf: subURL, options: .mappedIfSafe),
                                           let subSlices = try? MachOParser.shared.parseAllSlices(data: subData),
                                           !subSlices.isEmpty {
                                            let subRel = subURL.path.replacingOccurrences(of: bundleURL.path + "/", with: "")
                                            if subIsDylib {
                                                allLinkedDylibs.insert("@executable_path/\(subRel)")
                                            }
                                            let subDetails = MachOScanner.shared.parseMachO(files: subSlices, rawData: subData)
                                            let subFinding = MachOScanner.shared.scan(details: subDetails, context: plugContext)
                                            for ind in subFinding.indicators {
                                                allIndicators.append(ThreatIndicator(
                                                    signature: ind.signature,
                                                    description: "\(ind.description) [\(subRel)]",
                                                    category: ind.category,
                                                    location: "\(subRel): \(ind.location)",
                                                    severity: ind.severity
                                                ))
                                            }
                                            allMatchedSymbols.formUnion(subFinding.evidence.matchedSymbols)
                                            allLinkedDylibs.formUnion(subDetails.linkedDylibs)
                                            allSymbols.formUnion(subDetails.symbols)
                                            if subFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
                                            if subFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // 5b. Expanded Local Threat Signatures (Impersonation, Photos Bypass, Brotli, Tweaks, Clipboard)
            allIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateImpersonation(
                bundleId: bundleId,
                displayName: appName,
                installChannel: channelResult.channel,
                cryptid: mainDetails.cryptid
            ))
            
            if !mainDetails.isFairPlayEncrypted {
                let dylibList = Array(allLinkedDylibs)
                let symbolList = Array(allSymbols)
                allIndicators.append(contentsOf: ExpandedThreatCatalog.evaluatePhotosBypass(
                    linkedDylibs: dylibList,
                    symbols: symbolList,
                    entitlements: entitlementsDict,
                    cryptid: mainDetails.cryptid
                ))
                allIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateBrotliSupplyChain(
                    linkedDylibs: dylibList,
                    symbols: symbolList
                ))
                allIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateInjectedDylibs(
                    linkedDylibs: dylibList
                ))
                if let clipboardInd = ExpandedThreatCatalog.evaluateClipboardSnooping(
                    backgroundModes: backgroundModes,
                    symbols: symbolList,
                    cryptid: mainDetails.cryptid
                ) {
                    allIndicators.append(clipboardInd)
                }
            }
            
            // 6. Layer 4: Final Risk Grading & Whitelist Evaluation
            var provisionalRisk: RiskTier = .safe
            if allIndicators.contains(where: { $0.severity == .highRisk }) {
                provisionalRisk = .highRisk
            } else if allIndicators.contains(where: { $0.severity == .caution }) {
                provisionalRisk = .caution
            }
            
            var isWhitelisted = false
            var whitelistedToolName: String? = nil
            var finalRisk = provisionalRisk
            
            if provisionalRisk == .highRisk || provisionalRisk == .caution {
                let wlResult = WhitelistEngine.shared.isWhitelisted(
                    bundleId: bundleId,
                    appGroups: combinedAppGroups,
                    matchedSignatures: Array(allMatchedSymbols),
                    teamId: channelResult.teamIdentifier
                )
                if wlResult.isWhitelisted {
                    isWhitelisted = true
                    whitelistedToolName = wlResult.toolName
                    finalRisk = .knownTool
                }
            }
            
            var remediation = ""
            if finalRisk == .highRisk {
                remediation = "该 IPA 包检测到未经授权的 containermanagerd 跨沙盒利用特征或私有越权 API 引用，严禁在未修补的设备上安装。"
            } else if finalRisk == .knownTool {
                remediation = "该 IPA 匹配已知开源安全审计工具白名单（\(whitelistedToolName ?? "Known Tool")），由授权开发者签署。"
            } else if finalRisk == .caution {
                remediation = "该 IPA 声明了 App Group 容器共享权限并包含动态符号解析能力，安装前建议复核来源。"
            } else {
                remediation = "该 IPA 包未发现任何跨沙盒越权或恶意利用特征，状态安全。"
            }
            
            let evidence = AuditEvidence(
                matchedSymbols: Array(allMatchedSymbols).sorted(),
                linkedDylibs: Array(allLinkedDylibs).sorted(),
                hasAppGroups: !combinedAppGroups.isEmpty,
                appGroups: combinedAppGroups,
                installChannel: channelResult.channel,
                cryptid: mainDetails.cryptid,
                isFairPlayEncrypted: mainDetails.isFairPlayEncrypted,
                escapingSymlinks: [],
                dynamicLoadingPresent: dynamicLoadingFound,
                pathEnumerationPresent: pathEnumerationFound,
                remediationGuidance: remediation
            )
            
            return ScanFinding(
                bundleId: bundleId,
                displayName: appName,
                version: version,
                teamId: channelResult.teamIdentifier,
                executablePath: "\(appName).app/\(execName)",
                bundlePath: ipaURL.path,
                installChannel: channelResult.channel,
                riskTier: finalRisk,
                isWhitelisted: isWhitelisted,
                whitelistedToolName: whitelistedToolName,
                indicators: allIndicators,
                evidence: evidence,
                scanTimestamp: Date()
            )
        }
    }
}
