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
            return WQLocale.pick(en: "IPA file not found: \(path)", zh: "IPA 文件未找到: \(path)")
        case .invalidArchive(let msg):
            return WQLocale.pick(en: "Invalid IPA/ZIP archive: \(msg)", zh: "无效的 IPA/ZIP 压缩包: \(msg)")
        case .endOfCentralDirectoryNotFound:
            return WQLocale.pick(en: "ZIP End of Central Directory (EOCD) signature not found; archive may be corrupted or truncated.", zh: "未找到 ZIP 核心目录结束标记 (EOCD)，文件可能损坏或已被截断。")
        case .corruptHeader(let msg):
            return WQLocale.pick(en: "Corrupt ZIP header: \(msg)", zh: "ZIP 头部数据损坏: \(msg)")
        case .unsupportedCompressionMethod(let method):
            return WQLocale.pick(en: "Unsupported ZIP compression method (ID: \(method)); only Store (0) and Deflate (8) are supported.", zh: "不支持的 ZIP 压缩算法 (ID: \(method))，仅支持 Store(0) 与 Deflate(8)。")
        case .encryptedArchiveNotSupported:
            return WQLocale.pick(en: "Password-protected encrypted ZIP archives are not supported.", zh: "不支持带密码保护的加密 ZIP 压缩包。")
        case .decompressionFailed(let code):
            return WQLocale.pick(en: "zlib decompression failed (error code: \(code))", zh: "zlib 解压失败，错误码: \(code)")
        case .zipSlipDetected(let path):
            return WQLocale.pick(en: "Zip Slip path traversal detected at '\(path)'; extraction aborted.", zh: "检测到 Zip Slip 目录穿越恶意路径: \(path)，已终止解压。")
        case .quotaExceeded(let msg):
            return WQLocale.pick(en: "Safety quota exceeded (Zip Bomb defense): \(msg)", zh: "超出安全配额限制 (解压炸弹防御): \(msg)")
        case .missingPayload:
            return WQLocale.pick(en: "Missing Payload directory in IPA archive.", zh: "IPA 压缩包中缺少 Payload 目录。")
        case .missingAppBundle:
            return WQLocale.pick(en: "No valid .app bundle found inside Payload directory.", zh: "Payload 目录下未找到有效的 .app 应用程序包。")
        case .invalidInfoPlist(let msg):
            return WQLocale.pick(en: "Unable to read or parse Info.plist: \(msg)", zh: "无法读取或解析 Info.plist: \(msg)")
        case .missingExecutable(let name):
            return WQLocale.pick(en: "Main executable '\(name)' not found in .app bundle.", zh: "应用包中未找到主可执行文件: \(name)")
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
    private let quotaLock = NSLock()
    private var cumulativeExtractedBytes: Int = 0
    
    public init(
        data: Data,
        maxEntries: Int = 20_000,
        maxTotalUncompressedBytes: Int = 1024 * 1024 * 1024 // 1 GB
    ) {
        // Rebase non-zero startIndex Data slices (zero-copy when startIndex == 0, e.g. mmap)
        self.data = data.startIndex == 0 ? data : Data(data)
        self.maxEntries = maxEntries
        self.maxTotalUncompressedBytes = maxTotalUncompressedBytes
    }

    @inline(__always)
    private func loadU16LE(_ offset: Int) -> UInt16 {
        data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt16.self).littleEndian }
    }

    @inline(__always)
    private func loadU32LE(_ offset: Int) -> UInt32 {
        data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self).littleEndian }
    }

    @inline(__always)
    private func loadU64LE(_ offset: Int) -> UInt64 {
        data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self).littleEndian }
    }

    internal static func canonicalArchivePathKey(_ rawPath: String) -> String {
        let cleaned = rawPath
            .split(separator: "/", omittingEmptySubsequences: true)
            .filter { $0 != "." }
            .joined(separator: "/")
        return cleaned.lowercased()
    }

    internal static func computeCRC32(_ buffer: Data) -> UInt32 {
        var crc: uLong = zlib.crc32(0, nil, 0)
        buffer.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: Bytef.self).baseAddress else { return }
            var remaining = raw.count
            var offset = 0
            let maxChunk = 1 << 30
            while remaining > 0 {
                let step = min(remaining, maxChunk)
                crc = zlib.crc32(crc, base.advanced(by: offset), uInt(step))
                offset += step
                remaining -= step
            }
        }
        return UInt32(truncatingIfNeeded: crc)
    }
    
    /// Parses the Central Directory of the ZIP archive and validates full local-header coverage.
    public func readCentralDirectory() throws -> [ZIPArchiveEntry] {
        guard data.count >= 22 else {
            throw IPAPackageScannerError.invalidArchive(WQLocale.pick(en: "File is smaller than 22 bytes", zh: "文件大小小于 22 字节"))
        }
        
        // Scan forward from searchFloor to EOF-22 and take the FIRST valid EOCD satisfying eocd + 22 + commentLen == data.count
        // so fake EOCD records embedded inside the archive comment can never shadow the real Central Directory.
        var eocdOffset: Int? = nil
        var sawAnyEOCDSig = false
        let maxCommentLength = min(data.count - 22, 65535)
        let searchFloor = data.count - 22 - maxCommentLength
        
        for offset in searchFloor...(data.count - 22) {
            if loadU32LE(offset) == 0x06054b50 {
                sawAnyEOCDSig = true
                let trailingCommentLen = Int(loadU16LE(offset + 20))
                if offset + 22 + trailingCommentLen == data.count {
                    eocdOffset = offset
                    break
                }
            }
        }
        
        guard let eocd = eocdOffset else {
            if sawAnyEOCDSig {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "ZIP EOCD comment length does not match archive EOF",
                    zh: "ZIP 结束标记 (EOCD) 注释长度与文件末尾不匹配"
                ))
            }
            throw IPAPackageScannerError.endOfCentralDirectoryNotFound
        }
        
        let totalEntries = Int(loadU16LE(eocd + 10))
        guard totalEntries <= maxEntries else {
            throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                en: "Total ZIP entries (\(totalEntries)) exceed limit (\(maxEntries))",
                zh: "ZIP 条目总数 (\(totalEntries)) 超过上限 (\(maxEntries))"
            ))
        }

        let diskNumber = loadU16LE(eocd + 4)
        let cdDiskNumber = loadU16LE(eocd + 6)
        let entriesOnDisk = Int(loadU16LE(eocd + 8))
        guard diskNumber == 0, cdDiskNumber == 0, entriesOnDisk == totalEntries else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Multi-disk ZIP archives or mismatched disk entry counts are invalid",
                zh: "不支持分卷 ZIP 压缩包或磁盘条目计数不一致"
            ))
        }
        
        let cdSize = Int(loadU32LE(eocd + 12))
        let cdOffset = Int(loadU32LE(eocd + 16))
        
        guard cdOffset >= 0, cdSize >= 0, cdOffset <= eocd, cdSize <= eocd - cdOffset else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Central Directory offset or size exceeds archive bounds",
                zh: "核心目录偏移或大小超出文件边界"
            ))
        }

        let cdEnd = cdOffset + cdSize
        let hasZip64EOCDAtEnd = (cdEnd <= eocd - 4) && (loadU32LE(cdEnd) == 0x06064b50)
        guard cdEnd == eocd || hasZip64EOCDAtEnd else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Unreferenced trailing bytes between Central Directory and EOCD",
                zh: "核心目录与 EOCD 结束标记之间存在未引用字节"
            ))
        }
        
        var entries: [ZIPArchiveEntry] = []
        entries.reserveCapacity(min(totalEntries, 1024))
        var seenMetadataKeys: Set<String> = []
        var seenLocalOffsets: Set<Int> = []
        seenLocalOffsets.reserveCapacity(min(totalEntries, 1024))
        
        var cur = cdOffset
        var cumulativeUncompressedBytes = 0
        var isMonotonicOffsets = true
        var lastLocalOffset = -1
        
        for _ in 0..<totalEntries {
            guard cur <= cdEnd - 46 else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Central Directory truncated before declared entry count (\(totalEntries))",
                    zh: "核心目录在达到声明条目数 (\(totalEntries)) 前被截断"
                ))
            }
            let sig = loadU32LE(cur)
            guard sig == 0x02014b50 else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Central Directory header magic mismatch",
                    zh: "核心目录头部魔数不匹配"
                ))
            }
            
            let flags = loadU16LE(cur + 8)
            if (flags & 1) != 0 {
                throw IPAPackageScannerError.encryptedArchiveNotSupported
            }
            
            let method = loadU16LE(cur + 10)
            let crc = loadU32LE(cur + 16)
            let compSizeRaw = loadU32LE(cur + 20)
            let uncompSizeRaw = loadU32LE(cur + 24)
            let nameLen = Int(loadU16LE(cur + 28))
            let extraLen = Int(loadU16LE(cur + 30))
            let commentLen = Int(loadU16LE(cur + 32))
            let extAttrs = loadU32LE(cur + 38)
            let localOffsetRaw = loadU32LE(cur + 42)
            
            let recordLen = 46 + nameLen + extraLen + commentLen
            guard recordLen <= cdEnd - cur else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Filename, extra field, or comment exceeds Central Directory bounds",
                    zh: "文件名、扩展头或注释超出核心目录边界"
                ))
            }
            let nameData = data.subdata(in: (cur + 46)..<(cur + 46 + nameLen))
            let path = String(decoding: nameData, as: UTF8.self)
            
            var compSize64 = UInt64(compSizeRaw)
            var uncompSize64 = UInt64(uncompSizeRaw)
            var localOffset64 = UInt64(localOffsetRaw)
            var resolvedUncomp64 = (uncompSizeRaw != 0xFFFF_FFFF)
            var resolvedComp64 = (compSizeRaw != 0xFFFF_FFFF)
            var resolvedOffset64 = (localOffsetRaw != 0xFFFF_FFFF)
            
            // Parse ZIP64 Extended Information Extra Field (0x0001) when 32-bit sentinels (0xFFFFFFFF) are used
            if !resolvedUncomp64 || !resolvedComp64 || !resolvedOffset64 {
                let extraStart = cur + 46 + nameLen
                let extraEnd = extraStart + extraLen
                var eCur = extraStart
                while eCur + 4 <= extraEnd {
                    let headerId = loadU16LE(eCur)
                    let dataSize = Int(loadU16LE(eCur + 2))
                    eCur += 4
                    guard eCur + dataSize <= extraEnd else { break }
                    if headerId == 0x0001 {
                        var zCur = eCur
                        let zEnd = eCur + dataSize
                        if uncompSizeRaw == 0xFFFF_FFFF, zCur + 8 <= zEnd {
                            uncompSize64 = loadU64LE(zCur)
                            resolvedUncomp64 = true
                            zCur += 8
                        }
                        if compSizeRaw == 0xFFFF_FFFF, zCur + 8 <= zEnd {
                            compSize64 = loadU64LE(zCur)
                            resolvedComp64 = true
                            zCur += 8
                        }
                        if localOffsetRaw == 0xFFFF_FFFF, zCur + 8 <= zEnd {
                            localOffset64 = loadU64LE(zCur)
                            resolvedOffset64 = true
                            zCur += 8
                        }
                        break
                    }
                    eCur += dataSize
                }
            }
            
            // Zip Slip validation: block absolute paths, Windows backslashes, NUL bytes, and ".." path segments
            // without false-positively rejecting valid filenames containing consecutive dots (e.g. "icon..png").
            // Also reject non-normalized empty ("//") or "." path segments (stripping a single trailing "/" for directory entries).
            if path.hasPrefix("/") || path.contains("\\") || path.contains("\0") {
                throw IPAPackageScannerError.zipSlipDetected(path)
            }
            let trimmedForSegments = path.hasSuffix("/") ? String(path.dropLast()) : path
            let rawSegments = trimmedForSegments.split(separator: "/", omittingEmptySubsequences: false)
            if rawSegments.contains("..") {
                throw IPAPackageScannerError.zipSlipDetected(path)
            }
            if trimmedForSegments.isEmpty || rawSegments.contains("") || rawSegments.contains(".") {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Non-normalized ZIP entry path contains empty or '.' segments: \(path)",
                    zh: "非规范化 ZIP 条目路径包含空段或 '.' 路径段: \(path)"
                ))
            }
            if uncompSize64 > UInt64(maxTotalUncompressedBytes) {
                throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                    en: "ZIP entry declared size (\(uncompSize64)) exceeds limit (\(maxTotalUncompressedBytes) bytes)",
                    zh: "ZIP 条目声明解压体积 (\(uncompSize64)) 超过安全上限 (\(maxTotalUncompressedBytes) 字节)"
                ))
            }
            guard resolvedUncomp64, resolvedComp64, resolvedOffset64,
                  compSize64 <= UInt64(cdOffset), localOffset64 <= UInt64(cdOffset) else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "ZIP entry offset or compressed size exceeds file bounds",
                    zh: "ZIP 条目偏移或压缩大小超出文件边界"
                ))
            }
            let compSize = Int(compSize64)
            let uncompSize = Int(uncompSize64)
            let localOffset = Int(localOffset64)

            // Reject duplicate or case-colliding bundle metadata files (Info.plist / embedded.mobileprovision);
            // duplicate executable/library entries are extracted side-by-side in withTemporarySandbox so EVERY copy is audited.
            let canonicalKey = Self.canonicalArchivePathKey(path)
            if canonicalKey.hasSuffix("/info.plist") || canonicalKey == "info.plist" ||
               canonicalKey.hasSuffix("/embedded.mobileprovision") || canonicalKey == "embedded.mobileprovision" {
                if !seenMetadataKeys.insert(canonicalKey).inserted {
                    throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                        en: "Duplicate or case-colliding bundle metadata entry: \(path)",
                        zh: "检测到重复或大小写冲突的包元数据条目: \(path)"
                    ))
                }
            }

            guard seenLocalOffsets.insert(localOffset).inserted else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Multiple Central Directory entries reference the same local header offset (\(localOffset))",
                    zh: "多个核心目录条目指向相同的本地文件头偏移 (\(localOffset))"
                ))
            }
            if localOffset < lastLocalOffset {
                isMonotonicOffsets = false
            }
            lastLocalOffset = localOffset
            
            let (nextCumulative, overflow) = cumulativeUncompressedBytes.addingReportingOverflow(uncompSize)
            if overflow || nextCumulative > maxTotalUncompressedBytes {
                throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                    en: "Total declared uncompressed size exceeds limit (\(maxTotalUncompressedBytes) bytes)",
                    zh: "解压总数据量超过上限 (\(maxTotalUncompressedBytes) 字节)"
                ))
            }
            cumulativeUncompressedBytes = nextCumulative
            
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
            
            cur += recordLen
        }

        // Post-loop integrity check: Central Directory must match declared entry count and exact byte length
        guard entries.count == totalEntries, cur == cdEnd else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Central Directory entry count or byte length mismatch",
                zh: "核心目录条目数量或总字节长度不匹配"
            ))
        }

        // Verify every local file header matches its Central Directory record and zero orphan local headers exist in [0..<cdOffset]
        if entries.isEmpty {
            guard cdOffset == 0 else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Empty Central Directory with non-zero archive prefix (\(cdOffset) bytes)",
                    zh: "核心目录为空但文件头部存在未引用数据 (\(cdOffset) 字节)"
                ))
            }
        } else {
            let ordered = isMonotonicOffsets ? entries : entries.sorted { $0.localHeaderOffset < $1.localHeaderOffset }
            guard ordered[0].localHeaderOffset == 0 else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Unreferenced leading data or orphan local header before offset \(ordered[0].localHeaderOffset)",
                    zh: "偏移 \(ordered[0].localHeaderOffset) 之前存在未引用数据或孤立本地文件头"
                ))
            }
            for idx in 0..<ordered.count {
                let validated = try validateLocalHeader(for: ordered[idx], upperBound: cdOffset)
                let nextStart = (idx + 1 < ordered.count) ? ordered[idx + 1].localHeaderOffset : cdOffset
                if (validated.flags & 0x0008) == 0 {
                    guard validated.dataEnd == nextStart else {
                        throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                            en: "Orphan local file header or unreferenced bytes detected after '\(ordered[idx].path)'",
                            zh: "条目 '\(ordered[idx].path)' 之后检测到孤立本地文件头或未引用数据"
                        ))
                    }
                } else {
                    let descLen = nextStart - validated.dataEnd
                    guard descLen == 12 || descLen == 16 || descLen == 20 || descLen == 24 else {
                        throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                            en: "Malformed data descriptor or orphan local header after '\(ordered[idx].path)'",
                            zh: "条目 '\(ordered[idx].path)' 的数据描述符异常或存在孤立本地文件头"
                        ))
                    }
                    if descLen == 16 || descLen == 24 {
                        guard loadU32LE(validated.dataEnd) == 0x08074b50 else {
                            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                                en: "Invalid data descriptor signature after '\(ordered[idx].path)'",
                                zh: "条目 '\(ordered[idx].path)' 的数据描述符签名无效"
                            ))
                        }
                    }
                }
            }
        }
        
        return entries
    }

    /// Validates that a local file header agrees with its Central Directory entry on magic, encryption flag,
    /// compression method, filename, and (when bit 3 data-descriptor flag is clear) CRC32 and sizes.
    private func validateLocalHeader(
        for entry: ZIPArchiveEntry,
        upperBound: Int
    ) throws -> (dataStart: Int, dataEnd: Int, flags: UInt16) {
        let localOffset = entry.localHeaderOffset
        guard upperBound >= 0, upperBound <= data.count, localOffset >= 0, localOffset <= upperBound - 30 else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Local file header exceeds data bounds",
                zh: "本地文件头超出数据边界"
            ))
        }

        let localSig = loadU32LE(localOffset)
        guard localSig == 0x04034b50 else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Invalid local file header magic: \(String(format: "0x%08x", localSig))",
                zh: "本地文件头魔数无效: \(String(format: "0x%08x", localSig))"
            ))
        }

        let localFlags = loadU16LE(localOffset + 6)
        if (localFlags & 1) != 0 {
            throw IPAPackageScannerError.encryptedArchiveNotSupported
        }

        let localMethod = loadU16LE(localOffset + 8)
        guard localMethod == entry.compressionMethod else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Local file header compression method (\(localMethod)) disagrees with Central Directory (\(entry.compressionMethod))",
                zh: "本地文件头压缩算法 (\(localMethod)) 与核心目录 (\(entry.compressionMethod)) 不一致"
            ))
        }

        let localCRC = loadU32LE(localOffset + 14)
        let localCompRaw = loadU32LE(localOffset + 18)
        let localUncompRaw = loadU32LE(localOffset + 22)
        let nameLen = Int(loadU16LE(localOffset + 26))
        let extraLen = Int(loadU16LE(localOffset + 28))

        let headerLen = 30 + nameLen + extraLen
        guard headerLen <= upperBound - localOffset else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Local file header filename or extra field is truncated",
                zh: "本地文件头文件名或扩展字段被截断"
            ))
        }

        let nameMatches = data.withUnsafeBytes { raw -> Bool in
            let nameSlice = UnsafeRawBufferPointer(rebasing: raw[(localOffset + 30)..<(localOffset + 30 + nameLen)])
            return nameSlice.elementsEqual(entry.path.utf8)
        }
        guard nameMatches else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Local file header filename disagrees with Central Directory entry '\(entry.path)'",
                zh: "本地文件头文件名与核心目录条目 '\(entry.path)' 不一致"
            ))
        }

        let dataStart = localOffset + headerLen
        guard entry.compressedSize >= 0, entry.uncompressedSize >= 0, entry.compressedSize <= upperBound - dataStart else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Compressed payload is truncated",
                zh: "压缩文件数据段截断"
            ))
        }
        let dataEnd = dataStart + entry.compressedSize

        if (localFlags & 0x0008) == 0 {
            var localComp64 = UInt64(localCompRaw)
            var localUncomp64 = UInt64(localUncompRaw)
            if localCompRaw == 0xFFFF_FFFF || localUncompRaw == 0xFFFF_FFFF {
                let extraStart = localOffset + 30 + nameLen
                var eCur = extraStart
                while eCur + 4 <= dataStart {
                    let hId = loadU16LE(eCur)
                    let dSz = Int(loadU16LE(eCur + 2))
                    eCur += 4
                    guard eCur + dSz <= dataStart else { break }
                    if hId == 0x0001 {
                        var zCur = eCur
                        let zEnd = eCur + dSz
                        if localUncompRaw == 0xFFFF_FFFF, zCur + 8 <= zEnd {
                            localUncomp64 = loadU64LE(zCur)
                            zCur += 8
                        }
                        if localCompRaw == 0xFFFF_FFFF, zCur + 8 <= zEnd {
                            localComp64 = loadU64LE(zCur)
                            zCur += 8
                        }
                        break
                    }
                    eCur += dSz
                }
            }
            guard localCRC == entry.crc32,
                  localComp64 == UInt64(entry.compressedSize),
                  localUncomp64 == UInt64(entry.uncompressedSize) else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Local file header CRC32 or sizes disagree with Central Directory for '\(entry.path)'",
                    zh: "本地文件头 CRC32 或长度与核心目录不一致: \(entry.path)"
                ))
            }
        }

        return (dataStart, dataEnd, localFlags)
    }

    /// Peeks up to `maxBytes` uncompressed prefix bytes without inflating the remainder of a large asset.
    internal func peekPrefix(entry: ZIPArchiveEntry, maxBytes: Int = 16) throws -> Data {
        if entry.isDirectory || maxBytes <= 0 {
            return Data()
        }
        let validated = try validateLocalHeader(for: entry, upperBound: data.count)
        let compLen = validated.dataEnd - validated.dataStart
        if compLen == 0 {
            return Data()
        }
        switch entry.compressionMethod {
        case 0:
            let count = min(maxBytes, compLen)
            return data.subdata(in: validated.dataStart..<(validated.dataStart + count))
        case 8:
            let feedLen = min(compLen, max(512, maxBytes * 8))
            let feedSlice = data.subdata(in: validated.dataStart..<(validated.dataStart + feedLen))
            var strm = z_stream()
            let initStatus = inflateInit2_(&strm, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
            guard initStatus == Z_OK else {
                throw IPAPackageScannerError.decompressionFailed(initStatus)
            }
            defer { inflateEnd(&strm) }
            var outBuf = [UInt8](repeating: 0, count: max(64, maxBytes))
            let outCap = outBuf.count
            var producedTotal = 0
            try feedSlice.withUnsafeBytes { inPtr in
                strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
                strm.avail_in = uInt(feedSlice.count)
                let status: Int32 = outBuf.withUnsafeMutableBufferPointer { buf in
                    strm.next_out = buf.baseAddress
                    strm.avail_out = uInt(outCap)
                    return inflate(&strm, Z_SYNC_FLUSH)
                }
                if status != Z_OK && status != Z_STREAM_END && status != Z_BUF_ERROR {
                    throw IPAPackageScannerError.decompressionFailed(status)
                }
                producedTotal = outCap - Int(strm.avail_out)
            }
            return Data(outBuf.prefix(min(producedTotal, maxBytes)))
        default:
            throw IPAPackageScannerError.unsupportedCompressionMethod(entry.compressionMethod)
        }
    }
    
    /// Extracts a single entry's uncompressed data using bounded chunked streaming inflation and CRC32 verification.
    public func extract(entry: ZIPArchiveEntry) throws -> Data {
        let validated = try validateLocalHeader(for: entry, upperBound: data.count)
        if entry.isDirectory {
            return Data()
        }
        
        let rawCompressed = data.subdata(in: validated.dataStart..<validated.dataEnd)
        
        switch entry.compressionMethod {
        case 0: // STORE
            if rawCompressed.count > entry.uncompressedSize {
                throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                    en: "STORE entry payload (\(rawCompressed.count)) exceeds declared size (\(entry.uncompressedSize) bytes)",
                    zh: "STORE 条目实际长度 (\(rawCompressed.count)) 超出声明大小 (\(entry.uncompressedSize) 字节)"
                ))
            }
            guard rawCompressed.count == entry.uncompressedSize else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "STORE entry payload (\(rawCompressed.count)) does not match declared uncompressed size (\(entry.uncompressedSize))",
                    zh: "STORE 条目长度 (\(rawCompressed.count)) 与声明解压大小 (\(entry.uncompressedSize)) 不一致"
                ))
            }
            if entry.crc32 != 0 && Self.computeCRC32(rawCompressed) != entry.crc32 {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "CRC32 checksum mismatch for '\(entry.path)'",
                    zh: "条目 '\(entry.path)' CRC32 校验和不匹配"
                ))
            }
            try recordExtractedBytes(rawCompressed.count)
            return rawCompressed

        case 8: // DEFLATE
            if rawCompressed.isEmpty {
                guard entry.uncompressedSize == 0, entry.crc32 == 0 else {
                    throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                        en: "Empty DEFLATE stream for non-empty entry '\(entry.path)'",
                        zh: "非空条目 '\(entry.path)' 的 DEFLATE 数据流为空"
                    ))
                }
                return Data()
            }
            var strm = z_stream()
            // windowBits = -15 denotes raw deflate without zlib header (RFC 1951 standard for ZIP)
            let initStatus = inflateInit2_(&strm, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
            guard initStatus == Z_OK else {
                throw IPAPackageScannerError.decompressionFailed(initStatus)
            }
            defer { inflateEnd(&strm) }

            let chunkSize = 65_536
            var chunk = [UInt8](repeating: 0, count: chunkSize)
            var decompressed = Data()
            decompressed.reserveCapacity(min(max(entry.uncompressedSize, 0), 262_144))

            var sawStreamEnd = false
            try rawCompressed.withUnsafeBytes { inPtr in
                strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
                strm.avail_in = uInt(rawCompressed.count)

                var reachedEnd = false
                while !reachedEnd {
                    let status: Int32 = chunk.withUnsafeMutableBufferPointer { outBuf in
                        strm.next_out = outBuf.baseAddress
                        strm.avail_out = uInt(chunkSize)
                        return inflate(&strm, Z_NO_FLUSH)
                    }

                    let produced = chunkSize - Int(strm.avail_out)
                    if produced > 0 {
                        let (nextLen, lenOverflow) = decompressed.count.addingReportingOverflow(produced)
                        if lenOverflow || nextLen > entry.uncompressedSize {
                            throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                                en: "Inflated entry size exceeds declared limit (\(entry.uncompressedSize) bytes)",
                                zh: "ZIP 条目实际解压字节数超过声明上限 (\(entry.uncompressedSize) 字节)"
                            ))
                        }
                        try recordExtractedBytes(produced)
                        decompressed.append(contentsOf: chunk[0..<produced])
                    }

                    if status == Z_STREAM_END {
                        sawStreamEnd = true
                        reachedEnd = true
                    } else if status == Z_OK {
                        if strm.avail_in == 0 && produced == 0 {
                            reachedEnd = true
                        }
                    } else if status == Z_BUF_ERROR && strm.avail_in == 0 {
                        reachedEnd = true
                    } else {
                        throw IPAPackageScannerError.decompressionFailed(status)
                    }
                }
            }
            guard sawStreamEnd, decompressed.count == entry.uncompressedSize else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Truncated DEFLATE stream or size mismatch for '\(entry.path)'",
                    zh: "条目 '\(entry.path)' DEFLATE 数据流截断或大小不匹配"
                ))
            }
            if entry.crc32 != 0 && Self.computeCRC32(decompressed) != entry.crc32 {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "CRC32 checksum mismatch for '\(entry.path)'",
                    zh: "条目 '\(entry.path)' CRC32 校验和不匹配"
                ))
            }
            return decompressed

        default:
            throw IPAPackageScannerError.unsupportedCompressionMethod(entry.compressionMethod)
        }
    }

    internal func recordExtractedBytes(_ delta: Int) throws {
        guard delta > 0 else { return }
        quotaLock.lock()
        defer { quotaLock.unlock() }
        let (updated, overflow) = cumulativeExtractedBytes.addingReportingOverflow(delta)
        if overflow || updated > maxTotalUncompressedBytes {
            throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                en: "Cumulative inflated archive size exceeds limit (\(maxTotalUncompressedBytes) bytes)",
                zh: "累计实际解压数据量超过上限 (\(maxTotalUncompressedBytes) 字节)"
            ))
        }
        cumulativeExtractedBytes = updated
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
        
        // Discover all top-level Payload/*.app (or payload/*.app) bundles and reject archives smuggling multiple .app roots
        var distinctLowerAppRoots: Set<String> = []
        var distinctExactAppRoots: Set<String> = []
        var primaryAppBundle: (bundleName: String, bundlePrefix: String)? = nil
        for e in entries {
            let p = e.path
            guard p.hasPrefix("Payload/") || p.hasPrefix("payload/") else { continue }
            let comps = p.split(separator: "/")
            guard comps.count >= 2 else { continue }
            let second = String(comps[1])
            // Ignore macOS AppleDouble sidecar files (e.g. Payload/._MyApp.app created by ditto/Finder)
            guard !second.hasPrefix("._"), second.lowercased().hasSuffix(".app") else { continue }
            let isBundleEntry = (comps.count >= 3) || e.isDirectory
            guard isBundleEntry else { continue }
            distinctLowerAppRoots.insert("\(comps[0].lowercased())/\(second.lowercased())")
            distinctExactAppRoots.insert("\(comps[0])/\(second)")
            if primaryAppBundle == nil && p.contains(".app/") {
                primaryAppBundle = (second, "\(comps[0])/\(second)/")
            }
        }

        guard let resolvedPrimary = primaryAppBundle else {
            throw IPAPackageScannerError.missingPayload
        }
        if distinctLowerAppRoots.count > 1 || distinctExactAppRoots.count > 1 {
            throw IPAPackageScannerError.invalidArchive(WQLocale.pick(
                en: "IPA archive contains multiple top-level .app bundles inside Payload/",
                zh: "IPA 压缩包 Payload 目录下包含多个顶层 .app 应用包"
            ))
        }
        let appBundleName = resolvedPrimary.bundleName
        let appBundlePrefix = resolvedPrimary.bundlePrefix
        
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
        let bundleCanonicalPath = bundleURL.standardizedFileURL.path

        // Pass 1: Collect archive POSIX symlink entries (S_IFLNK = 0o120000) in memory without materializing OS symlinks on disk
        var archiveSymlinks: [String: (target: String, isExec: Bool)] = [:]
        for entry in entries where entry.path.hasPrefix(appBundlePrefix) {
            let rawRelative = String(entry.path.dropFirst(appBundlePrefix.count))
            let cleanComps = rawRelative.split(separator: "/").filter { !$0.isEmpty && $0 != "." }
            guard !cleanComps.isEmpty else { continue }
            let cleanRel = cleanComps.joined(separator: "/")
            let unixMode = (entry.externalFileAttributes >> 16) & 0o170000
            if unixMode == 0o120000 {
                if entry.uncompressedSize <= 4096 {
                    let linkBytes = try reader.extract(entry: entry)
                    let targetStr = String(decoding: linkBytes, as: UTF8.self)
                    let isExec = ((entry.externalFileAttributes >> 16) & 0o111) != 0
                    archiveSymlinks[cleanRel] = (targetStr, isExec)
                }
            }
        }

        let symlinkTargetMap = archiveSymlinks.mapValues(\.target)
        var resolvedInBundleSymlinks: [(linkRel: String, targetRel: String, isExec: Bool)] = []
        var referencedSymlinkTargets: Set<String> = []
        for (linkRel, meta) in archiveSymlinks {
            if let resolvedRel = Self.resolveInBundleArchivePath(from: linkRel, symlinks: symlinkTargetMap) {
                resolvedInBundleSymlinks.append((linkRel, resolvedRel, meta.isExec))
                referencedSymlinkTargets.insert(resolvedRel)
            }
        }

        let skippedAssetExtensions: Set<String> = [
            "png", "jpg", "jpeg", "gif", "webp", "heic", "ico", "bmp", "tiff",
            "car", "nib", "storyboardc", "strings", "stringsdict", "xcprivacy",
            "mp3", "mp4", "m4a", "wav", "caf", "aac", "mov",
            "ttf", "otf", "ttc", "woff", "woff2",
            "html", "css", "js", "svg", "pdf", "txt", "md",
            "mom", "omo", "metallib", "usdz", "scn"
        ]
        
        // Pass 2: Extract regular files and directories (peeking magic on skipped extensions so disguised Mach-Os are always extracted,
        // and preserving ALL copies of duplicate or case-colliding entries under disambiguated sibling filenames so neither first-wins nor last-wins can hide a payload)
        var duplicateCounter = 0
        for entry in entries where entry.path.hasPrefix(appBundlePrefix) {
            let rawRelative = String(entry.path.dropFirst(appBundlePrefix.count))
            let cleanComps = rawRelative.split(separator: "/").filter { !$0.isEmpty && $0 != "." }
            guard !cleanComps.isEmpty else { continue }
            let cleanRel = cleanComps.joined(separator: "/")

            let unixMode = (entry.externalFileAttributes >> 16) & 0o170000
            if unixMode == 0o120000 {
                continue
            }
            
            let destURL = bundleURL.appendingPathComponent(cleanRel)
            let destCanonical = destURL.standardizedFileURL.path
            guard destCanonical.hasPrefix(sandboxCanonicalPath + "/") || destCanonical == sandboxCanonicalPath,
                  destCanonical.hasPrefix(bundleCanonicalPath + "/") || destCanonical == bundleCanonicalPath else {
                throw IPAPackageScannerError.zipSlipDetected(entry.path)
            }
            
            if entry.isDirectory {
                var existingIsDir: ObjCBool = false
                if FileManager.default.fileExists(atPath: destURL.path, isDirectory: &existingIsDir), !existingIsDir.boolValue {
                    throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                        en: "Directory entry collides with existing regular file at '\(entry.path)'",
                        zh: "目录条目与已存在的文件路径冲突: \(entry.path)"
                    ))
                }
                try FileManager.default.createDirectory(at: destURL, withIntermediateDirectories: true)
            } else {
                let ext = destURL.pathExtension.lowercased()
                var isRelevant = !skippedAssetExtensions.contains(ext) ||
                                 entry.path.contains("/_MASReceipt/") ||
                                 entry.path.contains("/StoreKit/") ||
                                 referencedSymlinkTargets.contains(cleanRel)
                if !isRelevant {
                    let prefix = try reader.peekPrefix(entry: entry, maxBytes: 16)
                    if Self.isMachOOrFatMagic(prefix) {
                        isRelevant = true
                    }
                }
                
                if isRelevant {
                    let parentDir = destURL.deletingLastPathComponent()
                    try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
                    let fileData = try reader.extract(entry: entry)

                    let writeURL: URL
                    if FileManager.default.fileExists(atPath: destURL.path) {
                        duplicateCounter += 1
                        let baseName = destURL.deletingPathExtension().lastPathComponent
                        let disambiguatedName = ext.isEmpty
                            ? "\(baseName).__wqg_dup_\(duplicateCounter)__"
                            : "\(baseName).__wqg_dup_\(duplicateCounter)__.\(ext)"
                        writeURL = parentDir.appendingPathComponent(disambiguatedName)
                    } else {
                        writeURL = destURL
                    }

                    try fileData.write(to: writeURL, options: .atomic)
                    
                    if (entry.externalFileAttributes >> 16) & 0o111 != 0 {
                        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: writeURL.path)
                    }
                }
            }
        }

        // Pass 3: Materialize strictly in-bundle symlinks pointing to extracted regular files as bounded regular-file copies
        // (zero OS S_IFLNK symlinks are ever created on disk; escaping symlinks remain stripped)
        for resolvedLink in resolvedInBundleSymlinks.sorted(by: { $0.linkRel < $1.linkRel }) {
            let srcURL = bundleURL.appendingPathComponent(resolvedLink.targetRel)
            let dstURL = bundleURL.appendingPathComponent(resolvedLink.linkRel)
            let srcCanonical = srcURL.standardizedFileURL.path
            let dstCanonical = dstURL.standardizedFileURL.path
            guard srcCanonical.hasPrefix(bundleCanonicalPath + "/"),
                  dstCanonical.hasPrefix(bundleCanonicalPath + "/") else {
                continue
            }
            var srcIsDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: srcURL.path, isDirectory: &srcIsDir),
                  !srcIsDir.boolValue,
                  !FileManager.default.fileExists(atPath: dstURL.path) else {
                continue
            }
            let targetData = try Data(contentsOf: srcURL)
            try reader.recordExtractedBytes(targetData.count)
            try FileManager.default.createDirectory(at: dstURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try targetData.write(to: dstURL, options: .atomic)
            if resolvedLink.isExec {
                try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dstURL.path)
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
                throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                    en: "Missing or unparseable Info.plist",
                    zh: "找不到或无法解析 Info.plist"
                ))
            }
            
            let bundleId = infoDict["CFBundleIdentifier"] as? String ?? "unknown.bundle"
            let appName = infoDict["CFBundleDisplayName"] as? String ?? infoDict["CFBundleName"] as? String ?? ipaURL.deletingPathExtension().lastPathComponent
            let version = infoDict["CFBundleShortVersionString"] as? String ?? infoDict["CFBundleVersion"] as? String ?? "1.0"
            let (execName, mainExecURL) = try Self.resolveSafeBundleExecutableURL(
                infoDict: infoDict,
                bundleURL: bundleURL,
                fallbackName: appName
            )
            
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
                entitlementsDict = CSBlobParser.mergeEntitlementDictionaries(entitlementsDict, sliceEnts)
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
            var unencryptedSymbols: Set<String> = mainDetails.isFairPlayEncrypted ? [] : Set(mainDetails.symbols)
            var unencryptedTextStrings: Set<String> = mainDetails.isFairPlayEncrypted ? [] : Set(mainDetails.textStrings)
            var hasUnencryptedBinary = !mainDetails.isFairPlayEncrypted
            var appLinkedDylibs: Set<String> = Set(mainDetails.linkedDylibs)
            var appUnencryptedSymbols: Set<String> = mainDetails.isFairPlayEncrypted ? [] : Set(mainDetails.symbols)
            var appHasUnencryptedBinary = !mainDetails.isFairPlayEncrypted
            var dynamicLoadingFound = false
            var pathEnumerationFound = false
            var escapingSymlinks: [String] = []
            
            // Scan main executable
            let mainFinding = MachOScanner.shared.scan(details: mainDetails, context: scanContext)
            allIndicators.append(contentsOf: mainFinding.indicators)
            allMatchedSymbols.formUnion(mainFinding.evidence.matchedSymbols)
            if mainFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
            if mainFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
            
            // 4. Discover and scan all embedded *.appex bundles FIRST so combinedAppGroups includes extension App Groups
            // before evaluating shared Frameworks/* across the .app (R5 D3)
            let bundleResolvedPath = bundleURL.resolvingSymlinksInPath().standardizedFileURL.path
            let bundleResolvedPrefix = bundleResolvedPath.hasSuffix("/") ? bundleResolvedPath : bundleResolvedPath + "/"

            var appexURLs: [URL] = []
            if let dirEnum = FileManager.default.enumerator(at: bundleURL, includingPropertiesForKeys: [.isDirectoryKey]) {
                while let candidateURL = dirEnum.nextObject() as? URL {
                    if candidateURL.pathExtension.lowercased() == "appex" {
                        appexURLs.append(candidateURL)
                    }
                }
            }
            let appexPrefixes = appexURLs.map { $0.standardizedFileURL.path + "/" }

            for itemURL in appexURLs {
                Self.scanEmbeddedAppex(
                    appexURL: itemURL,
                    rootBundleURL: bundleURL,
                    bundleResolvedPrefix: bundleResolvedPrefix,
                    parentBundleId: bundleId,
                    version: version,
                    teamId: channelResult.teamIdentifier,
                    installChannel: channelResult.channel,
                    machoScanner: MachOScanner.shared,
                    combinedAppGroups: &combinedAppGroups,
                    entitlementsDict: &entitlementsDict,
                    allIndicators: &allIndicators,
                    allMatchedSymbols: &allMatchedSymbols,
                    allLinkedDylibs: &allLinkedDylibs,
                    unencryptedSymbols: &unencryptedSymbols,
                    unencryptedTextStrings: &unencryptedTextStrings,
                    hasUnencryptedBinary: &hasUnencryptedBinary,
                    dynamicLoadingFound: &dynamicLoadingFound,
                    pathEnumerationFound: &pathEnumerationFound,
                    escapingSymlinks: &escapingSymlinks
                )
            }
            
            // 5. Scan all remaining Mach-O binaries across the .app (identified by magic or binary role, excluding mainExec and *.appex subtrees)
            // using combinedAppGroups so frameworks shared with grouped .appex extensions are properly gated
            let mainExecCanonical = mainExecURL.standardizedFileURL.path
            let mainExecResolved = mainExecURL.resolvingSymlinksInPath().standardizedFileURL.path
            let appCandidates = Self.enumerateCandidateFiles(
                in: bundleURL,
                bundleRootResolvedPrefix: bundleResolvedPrefix,
                escapingSymlinks: &escapingSymlinks,
                bundleRootURL: bundleURL
            )
            for candidate in appCandidates {
                let itemURL = candidate.logicalURL
                let readURL = candidate.readURL
                let itemCanonical = itemURL.standardizedFileURL.path
                if itemCanonical == mainExecCanonical ||
                   itemCanonical == mainExecResolved ||
                   appexPrefixes.contains(where: { itemCanonical.hasPrefix($0) }) {
                    continue
                }
                let isDylib = itemURL.pathExtension.lowercased() == "dylib"
                let isExpectedRole = Self.isExpectedEmbeddedBinaryRole(itemURL: itemURL)
                let prefixBytes = Self.readPrefixBytes(of: readURL, maxBytes: 16) ?? Data()
                let hasMachOMagic = Self.isMachOOrFatMagic(prefixBytes)
                guard isExpectedRole || hasMachOMagic else { continue }

                let relPath = Self.bundleRelativePath(of: itemURL, in: bundleURL)
                if isDylib {
                    allLinkedDylibs.insert("@executable_path/\(relPath)")
                    appLinkedDylibs.insert("@executable_path/\(relPath)")
                }

                guard let dylibData = try? Data(contentsOf: readURL, options: .mappedIfSafe),
                      let fwSlices = try? MachOParser.shared.parseAllSlices(data: dylibData),
                      !fwSlices.isEmpty else {
                    let corruptInd = Self.makeCorruptMachOIndicator(relPath: relPath)
                    allIndicators.append(corruptInd)
                    allMatchedSymbols.insert(corruptInd.signature)
                    continue
                }

                let fwDetails = MachOScanner.shared.parseMachO(files: fwSlices, rawData: dylibData)
                var fwGroups = combinedAppGroups
                for s in fwSlices {
                    let (_, sg) = CSBlobParser.shared.extractAppGroups(from: s.codeSignatureData)
                    for g in sg where !fwGroups.contains(g) { fwGroups.append(g) }
                    let fwEnts = CSBlobParser.shared.parseMergedEntitlements(from: s.codeSignatureData)
                    entitlementsDict = CSBlobParser.mergeEntitlementDictionaries(entitlementsDict, fwEnts)
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
                appLinkedDylibs.formUnion(fwDetails.linkedDylibs)
                if !fwDetails.isFairPlayEncrypted {
                    hasUnencryptedBinary = true
                    appHasUnencryptedBinary = true
                    unencryptedSymbols.formUnion(fwDetails.symbols)
                    appUnencryptedSymbols.formUnion(fwDetails.symbols)
                    unencryptedTextStrings.formUnion(fwDetails.textStrings)
                }
                if fwFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
                if fwFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
            }
            
            // 5b. Expanded Local Threat Signatures (propagate all matched threat signatures into allMatchedSymbols so Trojanized bundles can never spoof WhitelistEngine)
            Self.appendExpandedThreatIndicators(
                bundleId: bundleId,
                displayName: appName,
                installChannel: channelResult.channel,
                mainCryptid: mainDetails.cryptid,
                mainIsFairPlayEncrypted: mainDetails.isFairPlayEncrypted,
                mainBackgroundModes: backgroundModes,
                infoDict: infoDict,
                entitlementsDict: entitlementsDict,
                allLinkedDylibs: allLinkedDylibs,
                appLinkedDylibs: appLinkedDylibs,
                unencryptedSymbols: unencryptedSymbols,
                appUnencryptedSymbols: appUnencryptedSymbols,
                unencryptedTextStrings: unencryptedTextStrings,
                hasUnencryptedBinary: hasUnencryptedBinary,
                appHasUnencryptedBinary: appHasUnencryptedBinary,
                allIndicators: &allIndicators,
                allMatchedSymbols: &allMatchedSymbols
            )
            
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
                remediation = WQLocale.pick(
                    en: "Unauthorized containermanagerd sandbox escape primitives, inline svc #0x80 direct syscalls, local exploit primitives, privacy bypass APIs, or impersonation traits detected. Do NOT install on unpatched devices.",
                    zh: "该 IPA 包检测到未经授权的 containermanagerd 跨沙盒利用特征、内联 svc #0x80 直接系统调用、本地越权原语、私有隐私绕过 API 或仿冒特征，严禁在未修补的设备上安装。"
                )
            } else if finalRisk == .knownTool {
                remediation = WQLocale.pick(
                    en: "Matched trusted whitelist rule (\(whitelistedToolName ?? "Known Tool")) signed by an authorized developer.",
                    zh: "该 IPA 匹配已知开源安全审计工具白名单（\(whitelistedToolName ?? "Known Tool")），由授权开发者签署。"
                )
            } else if finalRisk == .caution {
                remediation = WQLocale.pick(
                    en: "This IPA declares App Group shared containers or dynamic symbol resolution / embedded libraries. Verify source before installing.",
                    zh: "该 IPA 声明了 App Group 容器共享权限并包含动态符号解析能力，安装前建议复核来源。"
                )
            } else {
                remediation = WQLocale.pick(
                    en: "No cross-container sandbox escape or malicious exploit indicators found in this IPA; safe.",
                    zh: "该 IPA 包未发现任何跨沙盒越权或恶意利用特征，状态安全。"
                )
            }
            
            let evidence = AuditEvidence(
                matchedSymbols: Array(allMatchedSymbols).sorted(),
                linkedDylibs: Array(allLinkedDylibs).sorted(),
                hasAppGroups: !combinedAppGroups.isEmpty,
                appGroups: combinedAppGroups,
                installChannel: channelResult.channel,
                cryptid: mainDetails.cryptid,
                isFairPlayEncrypted: mainDetails.isFairPlayEncrypted,
                escapingSymlinks: escapingSymlinks,
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

    // MARK: - Shared Bundle Security Helpers (used by IPAPackageScanner & SecurityPipeline)

    internal static func resolveInBundleArchivePath(from linkRel: String, symlinks: [String: String]) -> String? {
        var currentRel = linkRel
        for _ in 0..<16 {
            let comps = currentRel.split(separator: "/").map(String.init)
            guard !comps.isEmpty else { return nil }
            var prefixStack: [String] = []
            var expanded = false
            for idx in 0..<comps.count {
                let seg = comps[idx]
                let candidate = (prefixStack + [seg]).joined(separator: "/")
                if let target = symlinks[candidate] {
                    if target.isEmpty || target.hasPrefix("/") || target.contains("\\") || target.contains("\0") {
                        return nil
                    }
                    var resolvedStack = prefixStack
                    for tSegSub in target.split(separator: "/", omittingEmptySubsequences: false) {
                        let tSeg = String(tSegSub)
                        if tSeg.isEmpty || tSeg == "." {
                            continue
                        } else if tSeg == ".." {
                            guard !resolvedStack.isEmpty else {
                                return nil
                            }
                            resolvedStack.removeLast()
                        } else {
                            resolvedStack.append(tSeg)
                        }
                    }
                    if idx + 1 < comps.count {
                        resolvedStack.append(contentsOf: comps[(idx + 1)...])
                    }
                    guard !resolvedStack.isEmpty else { return nil }
                    currentRel = resolvedStack.joined(separator: "/")
                    expanded = true
                    break
                } else {
                    prefixStack.append(seg)
                }
            }
            if !expanded {
                return currentRel
            }
        }
        return nil
    }

    internal static func resolveSafeBundleExecutableURL(
        infoDict: [String: Any],
        bundleURL: URL,
        fallbackName: String
    ) throws -> (execName: String, execURL: URL) {
        let execName: String
        if let rawExec = infoDict["CFBundleExecutable"] {
            guard let strExec = rawExec as? String else {
                throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                    en: "CFBundleExecutable must be a non-empty string",
                    zh: "CFBundleExecutable 必须为非空字符串"
                ))
            }
            execName = strExec
        } else {
            execName = fallbackName
        }

        if execName.isEmpty || execName == "." {
            throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                en: "CFBundleExecutable is empty or invalid",
                zh: "CFBundleExecutable 为空或无效"
            ))
        }
        if execName.contains("/") || execName.contains("\\") || execName.contains("..") || execName.contains("\0") {
            throw IPAPackageScannerError.zipSlipDetected(execName)
        }

        let bundleStd = bundleURL.standardizedFileURL.path
        let bundleStdPrefix = bundleStd.hasSuffix("/") ? bundleStd : bundleStd + "/"
        let bundleResolved = bundleURL.resolvingSymlinksInPath().standardizedFileURL.path
        let bundleResolvedPrefix = bundleResolved.hasSuffix("/") ? bundleResolved : bundleResolved + "/"

        let candidateURL = bundleURL.appendingPathComponent(execName)
        guard candidateURL.standardizedFileURL.path.hasPrefix(bundleStdPrefix) else {
            throw IPAPackageScannerError.zipSlipDetected(execName)
        }

        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: candidateURL.path, isDirectory: &isDir) else {
            throw IPAPackageScannerError.missingExecutable(execName)
        }
        guard !isDir.boolValue else {
            throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                en: "CFBundleExecutable '\(execName)' resolves to a directory instead of a regular file",
                zh: "CFBundleExecutable '\(execName)' 指向目录而非可执行文件"
            ))
        }
        let resolvedExecPath = candidateURL.resolvingSymlinksInPath().standardizedFileURL.path
        guard resolvedExecPath.hasPrefix(bundleResolvedPrefix) else {
            throw IPAPackageScannerError.zipSlipDetected(execName)
        }

        return (execName, candidateURL)
    }

    internal static func isMachOOrFatMagic(_ data: Data) -> Bool {
        guard data.count >= 4 else { return false }
        let rawBE = data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: 0, as: UInt32.self).bigEndian
        }
        switch rawBE {
        case 0xFEED_FACE, 0xCEFA_EDFE, 0xFEED_FACF, 0xCFFA_EDFE:
            return true
        case 0xCAFE_BABE, 0xCAFE_BABF:
            guard data.count >= 8 else { return false }
            let nfat = data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self).bigEndian
            }
            return nfat >= 1 && nfat <= 32
        case 0xBEBA_FECA, 0xBFBA_FECA:
            guard data.count >= 8 else { return false }
            let nfat = data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self).littleEndian
            }
            return nfat >= 1 && nfat <= 32
        default:
            return false
        }
    }

    internal static func readPrefixBytes(of fileURL: URL, maxBytes: Int = 16) -> Data? {
        guard let fh = try? FileHandle(forReadingFrom: fileURL) else { return nil }
        defer { try? fh.close() }
        return try? fh.read(upToCount: maxBytes)
    }

    internal static func isExpectedEmbeddedBinaryRole(itemURL: URL) -> Bool {
        if itemURL.pathExtension.lowercased() == "dylib" {
            return true
        }
        let rawName = itemURL.lastPathComponent
        let cleanName: String
        if let dupRange = rawName.range(of: ".__wqg_dup_") {
            let prefix = String(rawName[..<dupRange.lowerBound])
            let ext = itemURL.pathExtension
            cleanName = ext.isEmpty ? prefix : "\(prefix).\(ext)"
        } else {
            cleanName = rawName
        }
        let parentURL = itemURL.deletingLastPathComponent()
        if parentURL.pathExtension.lowercased() == "framework" {
            let fwPlistURL = parentURL.appendingPathComponent("Info.plist")
            if let pData = try? Data(contentsOf: fwPlistURL),
               let pDict = (try? PropertyListSerialization.propertyList(from: pData, options: [], format: nil)) as? [String: Any],
               let fwExec = pDict["CFBundleExecutable"] as? String,
               !fwExec.isEmpty {
                return cleanName == fwExec
            }
            let fwStem = parentURL.deletingPathExtension().lastPathComponent
            return !fwStem.isEmpty && cleanName == fwStem
        }
        return false
    }

    internal static func makeCorruptMachOIndicator(relPath: String) -> ThreatIndicator {
        ThreatIndicator(
            signature: "CorruptMachO:UnparseableBinary",
            description: WQLocale.pick(
                en: "Embedded binary or Mach-O image has malformed or truncated headers and could not be statically parsed [\(relPath)].",
                zh: "内嵌二进制或 Mach-O 镜像头部损坏或被截断，无法完成静态解析 [\(relPath)]。"
            ),
            category: "Malformed Mach-O Binary",
            location: "\(relPath): Mach-O Header",
            severity: .highRisk
        )
    }

    internal static func enumerateCandidateFiles(
        in rootURL: URL,
        bundleRootResolvedPrefix: String,
        escapingSymlinks: inout [String],
        bundleRootURL: URL
    ) -> [(logicalURL: URL, readURL: URL)] {
        var results: [(logicalURL: URL, readURL: URL)] = []
        guard let enumerator = FileManager.default.enumerator(
            at: rootURL,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey]
        ) else {
            return results
        }
        while let itemURL = enumerator.nextObject() as? URL {
            let values = try? itemURL.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            if values?.isSymbolicLink == true {
                let resolved = itemURL.resolvingSymlinksInPath().standardizedFileURL
                if !resolved.path.hasPrefix(bundleRootResolvedPrefix) {
                    let rel = bundleRelativePath(of: itemURL, in: bundleRootURL)
                    if !escapingSymlinks.contains(rel) {
                        escapingSymlinks.append(rel)
                    }
                    continue
                }
                if (try? resolved.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true {
                    results.append((logicalURL: itemURL, readURL: resolved))
                }
            } else if values?.isRegularFile == true {
                let resolved = itemURL.resolvingSymlinksInPath().standardizedFileURL
                guard resolved.path.hasPrefix(bundleRootResolvedPrefix) else {
                    let rel = bundleRelativePath(of: itemURL, in: bundleRootURL)
                    if !escapingSymlinks.contains(rel) {
                        escapingSymlinks.append(rel)
                    }
                    continue
                }
                results.append((logicalURL: itemURL, readURL: resolved))
            }
        }
        return results
    }

    internal static func scanEmbeddedAppex(
        appexURL: URL,
        rootBundleURL: URL,
        bundleResolvedPrefix: String,
        parentBundleId: String,
        version: String,
        teamId: String?,
        installChannel: InstallChannel,
        machoScanner: MachOScanner,
        combinedAppGroups: inout [String],
        entitlementsDict: inout [String: Any],
        allIndicators: inout [ThreatIndicator],
        allMatchedSymbols: inout Set<String>,
        allLinkedDylibs: inout Set<String>,
        unencryptedSymbols: inout Set<String>,
        unencryptedTextStrings: inout Set<String>,
        hasUnencryptedBinary: inout Bool,
        dynamicLoadingFound: inout Bool,
        pathEnumerationFound: inout Bool,
        escapingSymlinks: inout [String]
    ) {
        let plugInfoPlistURL = appexURL.appendingPathComponent("Info.plist")
        let pDict = (try? Data(contentsOf: plugInfoPlistURL)).flatMap {
            (try? PropertyListSerialization.propertyList(from: $0, options: [], format: nil)) as? [String: Any]
        }
        let fallbackExecName = appexURL.deletingPathExtension().lastPathComponent
        let plugBundleId = pDict?["CFBundleIdentifier"] as? String ?? "\(parentBundleId).appex"
        let plugName = pDict?["CFBundleDisplayName"] as? String ?? pDict?["CFBundleName"] as? String ?? fallbackExecName
        let plugBgModes = pDict?["UIBackgroundModes"] as? [String] ?? []

        var plugGroups: [String] = []
        var plugEntitlementsDict: [String: Any] = [:]
        var plugLinkedDylibs: Set<String> = []
        var plugUnencryptedSymbols: Set<String> = []
        var plugHasUnencryptedBinary = false
        var fallbackCryptid: UInt32 = 0
        var scannedPrimaryCanonical: String? = nil
        var scannedPrimaryResolved: String? = nil
        let appexRelPath = bundleRelativePath(of: appexURL, in: rootBundleURL)

        if let validDict = pDict {
            do {
                let (_, plugBinURL) = try resolveSafeBundleExecutableURL(
                    infoDict: validDict,
                    bundleURL: appexURL,
                    fallbackName: fallbackExecName
                )
                let plugReadURL = plugBinURL.resolvingSymlinksInPath().standardizedFileURL
                scannedPrimaryCanonical = plugBinURL.standardizedFileURL.path
                scannedPrimaryResolved = plugReadURL.path
                let relPath = bundleRelativePath(of: plugBinURL, in: rootBundleURL)

                guard let binData = try? Data(contentsOf: plugReadURL, options: .mappedIfSafe),
                      let plugSlices = try? MachOParser.shared.parseAllSlices(data: binData),
                      !plugSlices.isEmpty else {
                    let corruptInd = makeCorruptMachOIndicator(relPath: relPath)
                    allIndicators.append(corruptInd)
                    allMatchedSymbols.insert(corruptInd.signature)
                    return
                }

                let plugDetails = machoScanner.parseMachO(files: plugSlices, rawData: binData)
                fallbackCryptid = plugDetails.cryptid
                for s in plugSlices {
                    let (_, sg) = CSBlobParser.shared.extractAppGroups(from: s.codeSignatureData)
                    for g in sg where !plugGroups.contains(g) { plugGroups.append(g) }
                    let sEnts = CSBlobParser.shared.parseMergedEntitlements(from: s.codeSignatureData)
                    plugEntitlementsDict = CSBlobParser.mergeEntitlementDictionaries(plugEntitlementsDict, sEnts)
                    entitlementsDict = CSBlobParser.mergeEntitlementDictionaries(entitlementsDict, sEnts)
                }
                let plugGating = EntitlementGating.evaluate(hasAppGroups: !plugGroups.isEmpty, appGroups: plugGroups)
                for g in plugGating.appGroups where !combinedAppGroups.contains(g) {
                    combinedAppGroups.append(g)
                }
                let plugContext = MachOScanner.ScanContext(
                    bundleId: plugBundleId,
                    displayName: plugName,
                    version: version,
                    teamId: teamId,
                    bundlePath: appexURL.path,
                    executablePath: plugBinURL.path,
                    installChannel: installChannel,
                    appGroups: plugGating.appGroups
                )
                let plugFinding = machoScanner.scan(details: plugDetails, context: plugContext)
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
                plugLinkedDylibs.formUnion(plugDetails.linkedDylibs)
                if !plugDetails.isFairPlayEncrypted {
                    hasUnencryptedBinary = true
                    plugHasUnencryptedBinary = true
                    unencryptedSymbols.formUnion(plugDetails.symbols)
                    plugUnencryptedSymbols.formUnion(plugDetails.symbols)
                    unencryptedTextStrings.formUnion(plugDetails.textStrings)
                    if let extClip = ExpandedThreatCatalog.evaluateClipboardSnooping(
                        backgroundModes: plugBgModes,
                        symbols: plugDetails.symbols,
                        cryptid: plugDetails.cryptid
                    ) {
                        allIndicators.append(extClip)
                        allMatchedSymbols.insert(extClip.signature)
                    }
                }
                if plugFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
                if plugFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
            } catch let IPAPackageScannerError.zipSlipDetected(badExec) {
                let travInd = ThreatIndicator(
                    signature: "AppexExecutableTraversal",
                    description: WQLocale.pick(
                        en: "App extension declares unsafe path-traversal CFBundleExecutable '\(badExec)' [\(appexRelPath)].",
                        zh: "应用扩展声明了包含目录穿越风险的 CFBundleExecutable '\(badExec)' [\(appexRelPath)]。"
                    ),
                    category: "Malformed Bundle Metadata",
                    location: "\(appexRelPath)/Info.plist",
                    severity: .highRisk
                )
                allIndicators.append(travInd)
                allMatchedSymbols.insert(travInd.signature)
            } catch {
                // Fall through to magic-based scanning of all files inside this .appex so hidden Mach-Os cannot evade audit
            }
        }

        let plugGating = EntitlementGating.evaluate(hasAppGroups: !plugGroups.isEmpty, appGroups: plugGroups)
        let extCandidates = enumerateCandidateFiles(
            in: appexURL,
            bundleRootResolvedPrefix: bundleResolvedPrefix,
            escapingSymlinks: &escapingSymlinks,
            bundleRootURL: rootBundleURL
        )
        for candidate in extCandidates {
            let subURL = candidate.logicalURL
            let subReadURL = candidate.readURL
            let subCanonical = subURL.standardizedFileURL.path
            if subCanonical == scannedPrimaryCanonical || subCanonical == scannedPrimaryResolved {
                continue
            }
            let subIsDylib = subURL.pathExtension.lowercased() == "dylib"
            let subIsExpectedRole = isExpectedEmbeddedBinaryRole(itemURL: subURL)
            let prefix = readPrefixBytes(of: subReadURL, maxBytes: 16) ?? Data()
            let subHasMagic = isMachOOrFatMagic(prefix)
            guard subIsExpectedRole || subHasMagic else { continue }

            let subRel = bundleRelativePath(of: subURL, in: rootBundleURL)
            if subIsDylib {
                allLinkedDylibs.insert("@executable_path/\(subRel)")
                plugLinkedDylibs.insert("@executable_path/\(subRel)")
            }

            guard let subData = try? Data(contentsOf: subReadURL, options: .mappedIfSafe),
                  let subSlices = try? MachOParser.shared.parseAllSlices(data: subData),
                  !subSlices.isEmpty else {
                let corruptInd = makeCorruptMachOIndicator(relPath: subRel)
                allIndicators.append(corruptInd)
                allMatchedSymbols.insert(corruptInd.signature)
                continue
            }

            var subGroups = plugGating.appGroups
            for s in subSlices {
                let (_, sg) = CSBlobParser.shared.extractAppGroups(from: s.codeSignatureData)
                for g in sg where !subGroups.contains(g) { subGroups.append(g) }
                for g in sg where !combinedAppGroups.contains(g) { combinedAppGroups.append(g) }
                let sEnts = CSBlobParser.shared.parseMergedEntitlements(from: s.codeSignatureData)
                plugEntitlementsDict = CSBlobParser.mergeEntitlementDictionaries(plugEntitlementsDict, sEnts)
                entitlementsDict = CSBlobParser.mergeEntitlementDictionaries(entitlementsDict, sEnts)
            }
            let subContext = MachOScanner.ScanContext(
                bundleId: plugBundleId,
                displayName: plugName,
                version: version,
                teamId: teamId,
                bundlePath: appexURL.path,
                executablePath: subURL.path,
                installChannel: installChannel,
                appGroups: subGroups
            )
            let subDetails = machoScanner.parseMachO(files: subSlices, rawData: subData)
            let subFinding = machoScanner.scan(details: subDetails, context: subContext)
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
            plugLinkedDylibs.formUnion(subDetails.linkedDylibs)
            if !subDetails.isFairPlayEncrypted {
                hasUnencryptedBinary = true
                plugHasUnencryptedBinary = true
                unencryptedSymbols.formUnion(subDetails.symbols)
                plugUnencryptedSymbols.formUnion(subDetails.symbols)
                unencryptedTextStrings.formUnion(subDetails.textStrings)
            }
            if subFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
            if subFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
        }

        if let validDict = pDict {
            let primaryRel: String
            if let prim = scannedPrimaryCanonical {
                primaryRel = bundleRelativePath(of: URL(fileURLWithPath: prim), in: rootBundleURL)
            } else {
                primaryRel = appexRelPath
            }
            appendAppexAccessorySetupIndicators(
                linkedDylibs: plugLinkedDylibs,
                unencryptedSymbols: plugUnencryptedSymbols,
                hasUnencryptedBinary: plugHasUnencryptedBinary,
                fallbackCryptid: fallbackCryptid,
                infoPlist: validDict,
                entitlements: plugEntitlementsDict,
                installChannel: installChannel,
                relPath: primaryRel,
                allIndicators: &allIndicators,
                allMatchedSymbols: &allMatchedSymbols
            )
        }
    }

    internal static func bundleRelativePath(of itemURL: URL, in bundleURL: URL) -> String {
        let itemStd = itemURL.standardizedFileURL.path
        for root in [bundleURL.standardizedFileURL.path, bundleURL.resolvingSymlinksInPath().standardizedFileURL.path] {
            let prefix = root.hasSuffix("/") ? root : root + "/"
            if itemStd.hasPrefix(prefix) {
                return String(itemStd.dropFirst(prefix.count))
            }
        }
        let itemResolved = itemURL.resolvingSymlinksInPath().standardizedFileURL.path
        let rootResolved = bundleURL.resolvingSymlinksInPath().standardizedFileURL.path
        let resolvedPrefix = rootResolved.hasSuffix("/") ? rootResolved : rootResolved + "/"
        if itemResolved.hasPrefix(resolvedPrefix) {
            return String(itemResolved.dropFirst(resolvedPrefix.count))
        }
        return itemURL.lastPathComponent
    }

    internal static func appendAppexAccessorySetupIndicators(
        linkedDylibs: Set<String>,
        unencryptedSymbols: Set<String>,
        hasUnencryptedBinary: Bool,
        fallbackCryptid: UInt32,
        infoPlist: [String: Any],
        entitlements: [String: Any],
        installChannel: InstallChannel,
        relPath: String,
        allIndicators: inout [ThreatIndicator],
        allMatchedSymbols: inout Set<String>
    ) {
        let appexAccessoryInds = ExpandedThreatCatalog.evaluateAccessorySetupBypass(
            linkedDylibs: Array(linkedDylibs),
            symbols: Array(unencryptedSymbols),
            infoPlist: infoPlist,
            entitlements: entitlements,
            installChannel: installChannel,
            cryptid: hasUnencryptedBinary ? 0 : fallbackCryptid
        )
        for accInd in appexAccessoryInds {
            let annotated = ThreatIndicator(
                signature: accInd.signature,
                description: "\(accInd.description) [\(relPath)]",
                category: accInd.category,
                location: "\(relPath): \(accInd.location)",
                severity: accInd.severity
            )
            allIndicators.append(annotated)
            allMatchedSymbols.insert(annotated.signature)
        }
    }

    internal static func appendExpandedThreatIndicators(
        bundleId: String,
        displayName: String,
        installChannel: InstallChannel,
        mainCryptid: UInt32,
        mainIsFairPlayEncrypted: Bool,
        mainBackgroundModes: [String],
        infoDict: [String: Any],
        entitlementsDict: [String: Any],
        allLinkedDylibs: Set<String>,
        appLinkedDylibs: Set<String>,
        unencryptedSymbols: Set<String>,
        appUnencryptedSymbols: Set<String>,
        unencryptedTextStrings: Set<String>,
        hasUnencryptedBinary: Bool,
        appHasUnencryptedBinary: Bool,
        allIndicators: inout [ThreatIndicator],
        allMatchedSymbols: inout Set<String>
    ) {
        var expandedIndicators: [ThreatIndicator] = []
        expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateDangerousEntitlements(
            bundleId: bundleId,
            installChannel: installChannel,
            entitlements: entitlementsDict,
            hasUnencryptedBinary: hasUnencryptedBinary
        ))
        let effectiveImpersonationChannel: InstallChannel = (hasUnencryptedBinary && installChannel == .appStore)
            ? .developerSideloaded
            : installChannel
        expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: bundleId,
            displayName: displayName,
            installChannel: effectiveImpersonationChannel,
            cryptid: hasUnencryptedBinary ? 0 : mainCryptid
        ))

        let dylibList = Array(allLinkedDylibs)
        let symbolList = Array(unencryptedSymbols)
        let textStringList = Array(unencryptedTextStrings)
        if hasUnencryptedBinary {
            expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluatePhotosBypass(
                linkedDylibs: dylibList,
                symbols: symbolList,
                entitlements: entitlementsDict,
                cryptid: 0
            ))
            expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateBrotliSupplyChain(
                linkedDylibs: dylibList,
                symbols: symbolList
            ))
            expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateInjectedDylibs(
                linkedDylibs: dylibList
            ))
            if !mainIsFairPlayEncrypted,
               let clipboardInd = ExpandedThreatCatalog.evaluateClipboardSnooping(
                   backgroundModes: mainBackgroundModes,
                   symbols: symbolList,
                   cryptid: mainCryptid
               ) {
                expandedIndicators.append(clipboardInd)
            }
        } else if installChannel != .appStore {
            expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateInjectedDylibs(
                linkedDylibs: dylibList
            ))
        }

        // Run 2026 local exploit & private-entitlement checks even when binaries are FairPlay-encrypted (passing appropriate cryptid)
        expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateAudioMxdBypass(
            linkedDylibs: hasUnencryptedBinary ? dylibList : [],
            symbols: hasUnencryptedBinary ? symbolList : [],
            entitlements: entitlementsDict,
            cryptid: hasUnencryptedBinary ? 0 : mainCryptid
        ))
        expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateBookRestoreAndGestalt(
            linkedDylibs: hasUnencryptedBinary ? dylibList : [],
            textStrings: hasUnencryptedBinary ? textStringList : [],
            entitlements: entitlementsDict,
            cryptid: hasUnencryptedBinary ? 0 : mainCryptid
        ))
        expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateAccessorySetupBypass(
            linkedDylibs: appHasUnencryptedBinary ? Array(appLinkedDylibs) : [],
            symbols: appHasUnencryptedBinary ? Array(appUnencryptedSymbols) : [],
            infoPlist: infoDict,
            entitlements: entitlementsDict,
            installChannel: installChannel,
            cryptid: appHasUnencryptedBinary ? 0 : mainCryptid
        ))

        let preExistingSignatures = Set(allIndicators.map(\.signature))
        var seenExpandedKeys: Set<String> = []
        for expInd in expandedIndicators {
            allMatchedSymbols.insert(expInd.signature)
            if expInd.signature != "CVE-2026-84493:AccessorySetupKitBypass" && preExistingSignatures.contains(expInd.signature) {
                continue
            }
            let key = "\(expInd.signature)\u{0}\(expInd.location)"
            if seenExpandedKeys.insert(key).inserted {
                allIndicators.append(expInd)
            }
        }
    }
}
