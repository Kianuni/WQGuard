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

import Darwin
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
        
        let rawDiskNumber = loadU16LE(eocd + 4)
        let rawCdDiskNumber = loadU16LE(eocd + 6)
        let rawEntriesOnDisk = loadU16LE(eocd + 8)
        let rawTotalEntries = loadU16LE(eocd + 10)
        let rawCdSize = loadU32LE(eocd + 12)
        let rawCdOffset = loadU32LE(eocd + 16)

        let hasZip64Locator = (eocd >= 20) && (loadU32LE(eocd - 20) == 0x0706_4b50)
        let totalEntries: Int
        let cdSize: Int
        let cdOffset: Int
        let expectedTrailerStart: Int

        if hasZip64Locator {
            guard eocd >= 76 else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Truncated ZIP64 End of Central Directory record before locator",
                    zh: "ZIP64 核心目录结束记录在定位头之前被截断"
                ))
            }
            let locDisk = loadU32LE(eocd - 16)
            let z64Off64 = loadU64LE(eocd - 12)
            let locTotalDisks = loadU32LE(eocd - 4)
            guard locDisk == 0, locTotalDisks <= 1, z64Off64 <= UInt64(eocd - 76) else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Invalid ZIP64 EOCD locator offset or multi-disk fields",
                    zh: "ZIP64 定位记录偏移或分卷字段无效"
                ))
            }
            let z64Off = Int(z64Off64)
            guard loadU32LE(z64Off) == 0x0606_4b50 else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "ZIP64 EOCD signature (0x06064b50) missing at locator offset",
                    zh: "定位偏移处缺少 ZIP64 核心目录结束签名 (0x06064b50)"
                ))
            }
            let z64Remaining = loadU64LE(z64Off + 4)
            let (z64End64, z64Ov) = z64Off64.addingReportingOverflow(12)
            let (z64FullEnd64, z64FullOv) = z64End64.addingReportingOverflow(z64Remaining)
            guard !z64Ov, !z64FullOv, z64Remaining >= 44, z64FullEnd64 == UInt64(eocd - 20) else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "ZIP64 EOCD record size does not align with ZIP64 locator (unreferenced gap bytes)",
                    zh: "ZIP64 结束记录长度与定位头不对齐（存在未引用间隙字节）"
                ))
            }
            let z64Disk = loadU32LE(z64Off + 16)
            let z64CdDisk = loadU32LE(z64Off + 20)
            let z64EntriesOnDisk = loadU64LE(z64Off + 24)
            let z64TotalEntries = loadU64LE(z64Off + 32)
            let z64CdSize = loadU64LE(z64Off + 40)
            let z64CdOffset = loadU64LE(z64Off + 48)

            guard z64TotalEntries <= UInt64(maxEntries) else {
                throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                    en: "Total ZIP64 entries (\(z64TotalEntries)) exceed limit (\(maxEntries))",
                    zh: "ZIP64 条目总数 (\(z64TotalEntries)) 超过上限 (\(maxEntries))"
                ))
            }
            guard z64Disk == 0, z64CdDisk == 0, z64EntriesOnDisk == z64TotalEntries else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Multi-disk ZIP64 archives or mismatched disk entry counts are invalid",
                    zh: "不支持分卷 ZIP64 压缩包或磁盘条目计数不一致"
                ))
            }
            // Enforce strict agreement between Classic EOCD non-sentinel fields and ZIP64 EOCD fields (defeats dual-CD polyglots)
            let diskOk = (rawDiskNumber == 0xFFFF || UInt32(rawDiskNumber) == z64Disk)
            let cdDiskOk = (rawCdDiskNumber == 0xFFFF || UInt32(rawCdDiskNumber) == z64CdDisk)
            let onDiskOk = (rawEntriesOnDisk == 0xFFFF || UInt64(rawEntriesOnDisk) == z64EntriesOnDisk)
            let totalOk = (rawTotalEntries == 0xFFFF || UInt64(rawTotalEntries) == z64TotalEntries)
            let sizeOk = (rawCdSize == 0xFFFF_FFFF || UInt64(rawCdSize) == z64CdSize)
            let offOk = (rawCdOffset == 0xFFFF_FFFF || UInt64(rawCdOffset) == z64CdOffset)
            guard diskOk, cdDiskOk, onDiskOk, totalOk, sizeOk, offOk else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Classic EOCD fields disagree with ZIP64 EOCD record (polyglot archive rejected)",
                    zh: "传统 EOCD 字段与 ZIP64 EOCD 记录冲突（拒绝双目录多态压缩包）"
                ))
            }
            guard z64CdOffset <= z64Off64, z64CdSize <= z64Off64 - z64CdOffset else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "ZIP64 Central Directory offset or size exceeds archive bounds",
                    zh: "ZIP64 核心目录偏移或大小超出文件边界"
                ))
            }
            totalEntries = Int(z64TotalEntries)
            cdSize = Int(z64CdSize)
            cdOffset = Int(z64CdOffset)
            expectedTrailerStart = z64Off
        } else {
            totalEntries = Int(rawTotalEntries)
            guard totalEntries <= maxEntries else {
                throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                    en: "Total ZIP entries (\(totalEntries)) exceed limit (\(maxEntries))",
                    zh: "ZIP 条目总数 (\(totalEntries)) 超过上限 (\(maxEntries))"
                ))
            }
            guard rawDiskNumber == 0, rawCdDiskNumber == 0, Int(rawEntriesOnDisk) == totalEntries else {
                throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                    en: "Multi-disk ZIP archives or mismatched disk entry counts are invalid",
                    zh: "不支持分卷 ZIP 压缩包或磁盘条目计数不一致"
                ))
            }
            cdSize = Int(rawCdSize)
            cdOffset = Int(rawCdOffset)
            expectedTrailerStart = eocd
        }

        guard cdOffset >= 0, cdSize >= 0, cdOffset <= expectedTrailerStart, cdSize <= expectedTrailerStart - cdOffset else {
            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                en: "Central Directory offset or size exceeds archive bounds",
                zh: "核心目录偏移或大小超出文件边界"
            ))
        }

        let cdEnd = cdOffset + cdSize
        guard cdEnd == expectedTrailerStart else {
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
                    let ddStart = validated.dataEnd
                    let ddCRC: UInt32
                    let ddComp: UInt64
                    let ddUncomp: UInt64
                    if descLen == 16 || descLen == 24 {
                        guard loadU32LE(ddStart) == 0x08074b50 else {
                            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                                en: "Invalid data descriptor signature after '\(ordered[idx].path)'",
                                zh: "条目 '\(ordered[idx].path)' 的数据描述符签名无效"
                            ))
                        }
                        ddCRC = loadU32LE(ddStart + 4)
                        if descLen == 16 {
                            ddComp = UInt64(loadU32LE(ddStart + 8))
                            ddUncomp = UInt64(loadU32LE(ddStart + 12))
                        } else {
                            ddComp = loadU64LE(ddStart + 8)
                            ddUncomp = loadU64LE(ddStart + 16)
                        }
                    } else {
                        let firstWord = loadU32LE(ddStart)
                        guard firstWord != 0x04034b50 else {
                            throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                                en: "Orphan local header disguised as signatureless data descriptor after '\(ordered[idx].path)'",
                                zh: "条目 '\(ordered[idx].path)' 之后检测到伪装成无签名数据描述符的孤立本地文件头"
                            ))
                        }
                        ddCRC = firstWord
                        if descLen == 12 {
                            ddComp = UInt64(loadU32LE(ddStart + 4))
                            ddUncomp = UInt64(loadU32LE(ddStart + 8))
                        } else {
                            ddComp = loadU64LE(ddStart + 4)
                            ddUncomp = loadU64LE(ddStart + 12)
                        }
                    }
                    let entry = ordered[idx]
                    let crcMatches = (entry.crc32 == 0) || (ddCRC == entry.crc32)
                    guard crcMatches,
                          ddComp == UInt64(entry.compressedSize),
                          ddUncomp == UInt64(entry.uncompressedSize) else {
                        throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                            en: "Data descriptor CRC32 or sizes disagree with Central Directory for '\(entry.path)'",
                            zh: "条目 '\(entry.path)' 数据描述符 CRC32 或长度与核心目录不一致"
                        ))
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

    /// Peeks sufficient uncompressed header bytes (`64` bytes for Thin/2-slice Mach-Os, or up to `8 + nfat * 20`
    /// for 3..1024-slice Universal FAT binaries) so disguised multi-slice Mach-O payloads cannot hide behind perturbed early `fat_arch` entries.
    internal func peekMachOHeaderPrefix(entry: ZIPArchiveEntry) throws -> Data {
        let initial = try peekPrefix(entry: entry, maxBytes: 64)
        guard initial.count >= 8 else { return initial }
        let rawBE = initial.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self).bigEndian }
        if rawBE == 0xCAFE_BABE || rawBE == 0xBEBA_FECA {
            let nfat: UInt32 = initial.withUnsafeBytes { ptr in
                rawBE == 0xCAFE_BABE
                    ? ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self).bigEndian
                    : ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self).littleEndian
            }
            if nfat > 2 && nfat <= 1024 {
                let needed = min(20_488, 8 + Int(nfat) * 20)
                if needed > initial.count && entry.uncompressedSize > initial.count {
                    return try peekPrefix(entry: entry, maxBytes: needed)
                }
            }
        }
        return initial
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
            var strm = z_stream()
            let initStatus = inflateInit2_(&strm, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
            guard initStatus == Z_OK else {
                throw IPAPackageScannerError.decompressionFailed(initStatus)
            }
            defer { inflateEnd(&strm) }

            let targetBytes = min(maxBytes, max(0, entry.uncompressedSize))
            var outData = Data()
            outData.reserveCapacity(max(64, maxBytes))
            var outChunk = [UInt8](repeating: 0, count: max(64, maxBytes))
            let maxCompressedScanBudget = 65_536
            var compressedCursor = 0

            while outData.count < maxBytes && compressedCursor < compLen {
                if compressedCursor >= maxCompressedScanBudget && outData.count < targetBytes {
                    throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                        en: "Suspicious empty DEFLATE block padding before prefix of '\(entry.path)'",
                        zh: "条目 '\(entry.path)' 头部存在异常空 DEFLATE 块填充"
                    ))
                }
                let step = min(4096, compLen - compressedCursor)
                let sliceStart = validated.dataStart + compressedCursor
                let feedSlice = data.subdata(in: sliceStart..<(sliceStart + step))
                compressedCursor += step

                var streamEnded = false
                try feedSlice.withUnsafeBytes { inPtr in
                    strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
                    strm.avail_in = uInt(feedSlice.count)
                    while outData.count < maxBytes {
                        let outCap = outChunk.count
                        let status: Int32 = outChunk.withUnsafeMutableBufferPointer { buf in
                            strm.next_out = buf.baseAddress
                            strm.avail_out = uInt(outCap)
                            return inflate(&strm, Z_SYNC_FLUSH)
                        }
                        let produced = outCap - Int(strm.avail_out)
                        if produced > 0 {
                            let take = min(produced, maxBytes - outData.count)
                            outData.append(contentsOf: outChunk[0..<take])
                        }
                        if status == Z_STREAM_END {
                            streamEnded = true
                            break
                        } else if status == Z_OK {
                            if strm.avail_in == 0 && produced == 0 {
                                break
                            }
                        } else if status == Z_BUF_ERROR && strm.avail_in == 0 {
                            break
                        } else {
                            throw IPAPackageScannerError.decompressionFailed(status)
                        }
                    }
                }
                if streamEnded {
                    break
                }
            }
            return outData
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
        try withTemporarySandboxAndSymlinks(ipaURL: ipaURL) { bundleURL, entries, _ in
            try block(bundleURL, entries)
        }
    }

    internal func withTemporarySandboxAndSymlinks<T>(
        ipaURL: URL,
        block: (URL, [ZIPArchiveEntry], [String]) throws -> T
    ) throws -> T {
        let ipaData = try Self.readBoundedRegularFileDirectNoFollow(at: ipaURL, maxBytes: 1024 * 1024 * 1024)
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
        var seenSymlinkLowerKeys: Set<String> = []
        for entry in entries where entry.path.hasPrefix(appBundlePrefix) {
            let rawRelative = String(entry.path.dropFirst(appBundlePrefix.count))
            let cleanComps = rawRelative.split(separator: "/").filter { !$0.isEmpty && $0 != "." }
            guard !cleanComps.isEmpty else { continue }
            let cleanRel = cleanComps.joined(separator: "/")
            let unixMode = (entry.externalFileAttributes >> 16) & 0o170000
            if unixMode == 0o120000 {
                guard entry.uncompressedSize <= 4096 else {
                    throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                        en: "Oversized symbolic link entry in IPA archive: '\(entry.path)' (\(entry.uncompressedSize) bytes)",
                        zh: "IPA 压缩包中存在超大符号链接条目: '\(entry.path)' (\(entry.uncompressedSize) 字节)"
                    ))
                }
                guard seenSymlinkLowerKeys.insert(cleanRel.lowercased()).inserted else {
                    throw IPAPackageScannerError.corruptHeader(WQLocale.pick(
                        en: "Duplicate or case-colliding symbolic link entry in IPA archive: '\(entry.path)'",
                        zh: "IPA 压缩包中存在重复或大小写冲突的符号链接条目: '\(entry.path)'"
                    ))
                }
                let linkBytes = try reader.extract(entry: entry)
                let targetStr = String(decoding: linkBytes, as: UTF8.self)
                let isExec = ((entry.externalFileAttributes >> 16) & 0o111) != 0
                archiveSymlinks[cleanRel] = (targetStr, isExec)
            }
        }

        let symlinkTargetMap = archiveSymlinks.mapValues(\.target)
        var resolvedInBundleSymlinks: [(linkRel: String, targetRel: String, isExec: Bool)] = []
        var referencedSymlinkTargets: Set<String> = []
        var archiveEscapingSymlinks: [String] = []
        for (linkRel, meta) in archiveSymlinks.sorted(by: { $0.key < $1.key }) {
            if let resolvedRel = Self.resolveInBundleArchivePath(from: linkRel, symlinks: symlinkTargetMap) {
                resolvedInBundleSymlinks.append((linkRel, resolvedRel, meta.isExec))
                referencedSymlinkTargets.insert(resolvedRel)
            } else {
                archiveEscapingSymlinks.append("\(linkRel) -> \(meta.target)")
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
                    let prefix = try reader.peekMachOHeaderPrefix(entry: entry)
                    if Self.isMachOOrFatMagic(prefix, fileSize: entry.uncompressedSize) {
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

        // Pass 3: Materialize strictly in-bundle symlinks pointing to extracted regular files or directories as bounded copies
        // (zero OS S_IFLNK symlinks are ever created on disk; escaping symlinks remain stripped and reported).
        // Materialize regular-file symlinks before directory symlinks across two passes so file symlinks inside a symlinked
        // directory source (e.g. `ZStore/RealExtDir/ExtExec -> ../../Assets/Bin` inside `PlugIns/Hidden.appex -> ../ZStore/RealExtDir`)
        // and symlinks referencing a materialized directory are both populated completely.
        let sortedBundleLinks = resolvedInBundleSymlinks.sorted { lhs, rhs in
            if lhs.linkRel != rhs.linkRel { return lhs.linkRel < rhs.linkRel }
            return lhs.targetRel < rhs.targetRel
        }
        var materializedLinkIndices: Set<Int> = []
        for _ in 0..<2 {
            for wantDirectories in [false, true] {
                for (linkIdx, resolvedLink) in sortedBundleLinks.enumerated() where !materializedLinkIndices.contains(linkIdx) {
                    let srcURL = bundleURL.appendingPathComponent(resolvedLink.targetRel)
                    let dstURL = bundleURL.appendingPathComponent(resolvedLink.linkRel)
                    let srcCanonical = srcURL.standardizedFileURL.path
                    let dstCanonical = dstURL.standardizedFileURL.path
                    guard srcCanonical.hasPrefix(bundleCanonicalPath + "/"),
                          dstCanonical.hasPrefix(bundleCanonicalPath + "/"),
                          srcCanonical != dstCanonical,
                          !dstCanonical.hasPrefix(srcCanonical + "/") else {
                        materializedLinkIndices.insert(linkIdx)
                        continue
                    }
                    var srcIsDir: ObjCBool = false
                    guard FileManager.default.fileExists(atPath: srcURL.path, isDirectory: &srcIsDir) else {
                        continue
                    }
                    guard srcIsDir.boolValue == wantDirectories else {
                        continue
                    }
                    materializedLinkIndices.insert(linkIdx)
                    if srcIsDir.boolValue {
                        guard !FileManager.default.fileExists(atPath: dstURL.path),
                              let subEnum = FileManager.default.enumerator(
                                  at: srcURL,
                                  includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey]
                              ) else {
                            continue
                        }
                        try FileManager.default.createDirectory(at: dstURL, withIntermediateDirectories: true)
                        let srcPrefix = srcCanonical + "/"
                        var copiedEntries = 0
                        while let subItem = subEnum.nextObject() as? URL, copiedEntries < 2048 {
                            let subItemStd = subItem.standardizedFileURL.path
                            guard subItemStd.hasPrefix(srcPrefix) else { continue }
                            let subRel = String(subItemStd.dropFirst(srcPrefix.count))
                            let subDst = dstURL.appendingPathComponent(subRel)
                            let vals = try? subItem.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey])
                            if vals?.isDirectory == true {
                                try FileManager.default.createDirectory(at: subDst, withIntermediateDirectories: true)
                            } else if vals?.isRegularFile == true {
                                let data = try Self.readBoundedRegularFileDirectNoFollow(at: subItem)
                                try reader.recordExtractedBytes(data.count)
                                try FileManager.default.createDirectory(at: subDst.deletingLastPathComponent(), withIntermediateDirectories: true)
                                try data.write(to: subDst, options: .atomic)
                                copiedEntries += 1
                            }
                        }
                        continue
                    }
                    let writeDstURL: URL
                    if FileManager.default.fileExists(atPath: dstURL.path) {
                        duplicateCounter += 1
                        let dstExt = dstURL.pathExtension
                        let dstBase = dstURL.deletingPathExtension().lastPathComponent
                        let disambig = dstExt.isEmpty
                            ? "\(dstBase).__wqg_dup_\(duplicateCounter)__"
                            : "\(dstBase).__wqg_dup_\(duplicateCounter)__.\(dstExt)"
                        writeDstURL = dstURL.deletingLastPathComponent().appendingPathComponent(disambig)
                    } else {
                        writeDstURL = dstURL
                    }
                    let targetData = try Self.readBoundedRegularFileDirectNoFollow(at: srcURL)
                    try reader.recordExtractedBytes(targetData.count)
                    try FileManager.default.createDirectory(at: writeDstURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                    try targetData.write(to: writeDstURL, options: .atomic)
                    if resolvedLink.isExec {
                        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: writeDstURL.path)
                    }
                }
            }
        }
        
        return try block(bundleURL, entries, archiveEscapingSymlinks)
    }
    
    /// Complete scan of a local `.ipa` package conforming to Layers 1, 2, and 4.
    public func scan(ipaURL: URL) throws -> ScanFinding {
        return try withTemporarySandboxAndSymlinks(ipaURL: ipaURL) { (bundleURL, archiveEntries, archiveEscapingSymlinks) in
            // 1. Parse Info.plist
            let infoPlistURL = bundleURL.appendingPathComponent("Info.plist")
            guard let plistData = try? Self.readBoundedRegularFileDirectNoFollow(at: infoPlistURL, maxBytes: 8 * 1024 * 1024),
                  let infoDict = (try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil)) as? [String: Any] else {
                throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                    en: "Missing or unparseable Info.plist",
                    zh: "找不到或无法解析 Info.plist"
                ))
            }
            
            let rawPlistBundleId = (infoDict["CFBundleIdentifier"] as? String)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let hasExplicitPlistBundleId = (rawPlistBundleId != nil && !rawPlistBundleId!.isEmpty)
            let bundleId = (hasExplicitPlistBundleId ? rawPlistBundleId! : nil) ?? "unknown.bundle"
            let appName = infoDict["CFBundleDisplayName"] as? String ?? infoDict["CFBundleName"] as? String ?? ipaURL.deletingPathExtension().lastPathComponent
            let version = infoDict["CFBundleShortVersionString"] as? String ?? infoDict["CFBundleVersion"] as? String ?? "1.0"
            let (execName, mainExecURL) = try Self.resolveSafeBundleExecutableURL(
                infoDict: infoDict,
                bundleURL: bundleURL,
                fallbackName: appName
            )
            
            let mainExecData = try Self.readBoundedRegularFileDirectNoFollow(at: mainExecURL)
            let mainSlices = try MachOParser.shared.parseAllSlices(data: mainExecData)
            let mainDetails = MachOScanner.shared.parseMachO(
                files: mainSlices,
                rawData: mainExecData,
                expectedContainerSliceCount: mainSlices.first?.slicesInContainer.count
            )
            
            // 2. Layer 1: Install Channel & Entitlement Gating (merging XML Slot 5 + DER Slot 7 across all selected audit slices & signature blobs)
            var codeSigTrust = CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: mainSlices)
            if let plistBindingFailure = CSBlobParser.shared.verifyBundleInfoPlistBinding(
                fromSlices: mainSlices,
                infoPlistData: plistData,
                plistBundleId: hasExplicitPlistBundleId ? bundleId : nil
            ) {
                codeSigTrust = plistBindingFailure
            } else if let crSealFailure = CSBlobParser.shared.verifyBundleCodeResourcesSeal(
                fromSlices: mainSlices,
                bundleURL: bundleURL
            ) {
                codeSigTrust = crSealFailure
            }
            let mainHasMissingCS = CSBlobParser.hasMissingCodeSignature(inSlices: mainSlices)
            var bundleSigTrust = codeSigTrust
            var bundleHasMissingCS = mainHasMissingCS
            var appHasMissingCS = mainHasMissingCS
            let hasArchiveMobileProvision = archiveEntries.contains { e in
                let lower = e.path.lowercased()
                return lower.hasSuffix(".app/embedded.mobileprovision")
                    && !lower.contains("/appclips/")
                    && !lower.contains("/watch/")
            }
            var channelResult = ChannelClassifier.classifyBundle(
                at: bundleURL,
                cryptid: mainDetails.cryptid,
                codeSignatureTrust: codeSigTrust
            )
            if hasArchiveMobileProvision && channelResult.channel == .appStore {
                channelResult = ChannelClassifier.classify(
                    cryptid: mainDetails.cryptid,
                    mobileprovisionData: nil,
                    hasMobileProvisionArtifact: true,
                    codeSignatureTrust: codeSigTrust
                )
            }
            var mainAppGroups: [String] = []
            var mainEntitlementsDict: [String: Any] = [:]
            var entitlementsDict: [String: Any] = [:]
            for slice in MachOParser.selectAuditSlices(from: mainSlices) {
                let (_, sliceGroups) = CSBlobParser.shared.extractAppGroups(fromSlice: slice)
                for g in sliceGroups where !mainAppGroups.contains(g) {
                    mainAppGroups.append(g)
                }
                let sliceEnts = CSBlobParser.shared.parseMergedEntitlements(fromSlice: slice)
                mainEntitlementsDict = CSBlobParser.mergeEntitlementDictionaries(mainEntitlementsDict, sliceEnts)
                entitlementsDict = CSBlobParser.mergeEntitlementDictionaries(entitlementsDict, sliceEnts)
            }
            let identityResolution = Self.resolveDistinctEntitlementIdentities(
                fromSlices: mainSlices,
                explicitTeamId: channelResult.teamIdentifier
            )
            let mainEntBundleId = identityResolution.primaryBundleId
            let effectiveTeamId = channelResult.teamIdentifier ?? identityResolution.inferredTeamId
            let hasConflictingBundleIdentity = identityResolution.hasMultipleBundleIds
                || identityResolution.hasMultipleTeamIds
                || identityResolution.hasProvisionTeamConflict
                || (hasExplicitPlistBundleId && identityResolution.distinctBundleIds.contains {
                    Self.doesEntitlementBundleIdConflict(entBundleId: $0, withPlistBundleId: bundleId)
                })
            let hasVerifiedBundleIdentity = (hasExplicitPlistBundleId || mainEntBundleId != nil) && !hasConflictingBundleIdentity
            let gating = EntitlementGating.evaluate(hasAppGroups: !mainAppGroups.isEmpty, appGroups: mainAppGroups)
            var combinedAppGroups = gating.appGroups
            let backgroundModes = Self.extractFlexibleStringList(infoDict["UIBackgroundModes"])
            
            // 3. Layer 2: Main Executable Scan
            let scanContext = MachOScanner.ScanContext(
                bundleId: bundleId,
                displayName: appName,
                version: version,
                teamId: effectiveTeamId,
                bundlePath: ipaURL.path,
                executablePath: mainExecURL.path,
                installChannel: channelResult.channel,
                appGroups: gating.appGroups,
                disqualifyAppStoreExemption: mainDetails.cryptid != 0 && (mainHasMissingCS || codeSigTrust != .appleAppStoreVerified)
            )
            
            var allIndicators: [ThreatIndicator] = []
            var allMatchedSymbols: Set<String> = []
            var allLinkedDylibs: Set<String> = Set(mainDetails.linkedDylibs)
            let mainInspectable = !mainDetails.isFairPlayEncrypted || mainDetails.hasUnencryptedSegments || codeSigTrust.isDisqualifiedFromAppStore || mainHasMissingCS
            let mainSymbolsInspectable = mainInspectable || codeSigTrust != .appleAppStoreVerified
            var unencryptedSymbols: Set<String> = mainSymbolsInspectable ? Set(mainDetails.symbols) : []
            var unencryptedTextStrings: Set<String> = mainInspectable ? Set(mainDetails.textStrings) : []
            var hasUnencryptedBinary = mainInspectable
            var appLinkedDylibs: Set<String> = Set(mainDetails.linkedDylibs)
            var appUnencryptedSymbols: Set<String> = mainSymbolsInspectable ? Set(mainDetails.symbols) : []
            var appHasUnencryptedBinary = mainInspectable
            var dynamicLoadingFound = false
            var pathEnumerationFound = false
            var escapingSymlinks: [String] = archiveEscapingSymlinks
            
            // Scan main executable
            let mainFinding = MachOScanner.shared.scan(details: mainDetails, context: scanContext)
            allIndicators.append(contentsOf: mainFinding.indicators)
            allMatchedSymbols.formUnion(mainFinding.evidence.matchedSymbols)
            if mainFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
            if mainFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
            
            // 4. Discover and scan all embedded *.appex and *.xpc bundles FIRST so combinedAppGroups includes extension App Groups
            // before evaluating shared Frameworks/* across the .app (R5 D3)
            let bundleResolvedPath = bundleURL.resolvingSymlinksInPath().standardizedFileURL.path
            let bundleResolvedPrefix = bundleResolvedPath.hasSuffix("/") ? bundleResolvedPath : bundleResolvedPath + "/"

            let appexURLs = Self.discoverEmbeddedExtensions(
                in: bundleURL,
                bundleRootResolvedPrefix: bundleResolvedPrefix,
                escapingSymlinks: &escapingSymlinks,
                bundleRootURL: bundleURL
            )
            let appexPrefixes = Self.computeEmbeddedExtensionPrefixes(
                appexURLs: appexURLs,
                bundleRootResolvedPrefix: bundleResolvedPrefix
            )
            let hasAnyArchiveAppexProvision = archiveEntries.contains { e in
                let lower = e.path.lowercased()
                return lower.hasSuffix(".appex/embedded.mobileprovision")
                    || lower.hasSuffix(".xpc/embedded.mobileprovision")
                    || lower.contains("/appclips/") && lower.hasSuffix(".app/embedded.mobileprovision")
                    || lower.contains("/watch/") && lower.hasSuffix(".app/embedded.mobileprovision")
                    || lower.hasSuffix("/embedded.mobileprovision")
            }

            for itemURL in appexURLs {
                let itemRelLower = Self.bundleRelativePath(of: itemURL, in: bundleURL).lowercased()
                let itemHasArchiveProvision = hasAnyArchiveAppexProvision && archiveEntries.contains { e in
                    e.path.lowercased().hasSuffix("/\(itemRelLower)/embedded.mobileprovision")
                }
                Self.scanEmbeddedAppex(
                    appexURL: itemURL,
                    rootBundleURL: bundleURL,
                    bundleResolvedPrefix: bundleResolvedPrefix,
                    allEmbeddedExtensionPrefixes: appexPrefixes,
                    parentBundleId: bundleId,
                    version: version,
                    teamId: effectiveTeamId,
                    installChannel: channelResult.channel,
                    hasArchiveMobileProvision: itemHasArchiveProvision,
                    machoScanner: MachOScanner.shared,
                    combinedAppGroups: &combinedAppGroups,
                    entitlementsDict: &entitlementsDict,
                    allIndicators: &allIndicators,
                    allMatchedSymbols: &allMatchedSymbols,
                    allLinkedDylibs: &allLinkedDylibs,
                    unencryptedSymbols: &unencryptedSymbols,
                    unencryptedTextStrings: &unencryptedTextStrings,
                    hasUnencryptedBinary: &hasUnencryptedBinary,
                    bundleCodeSignatureTrust: &bundleSigTrust,
                    bundleHasMissingCodeSignature: &bundleHasMissingCS,
                    dynamicLoadingFound: &dynamicLoadingFound,
                    pathEnumerationFound: &pathEnumerationFound,
                    escapingSymlinks: &escapingSymlinks
                )
            }
            if bundleSigTrust.isDisqualifiedFromAppStore && channelResult.channel == .appStore {
                channelResult = ChannelClassifier.classify(
                    cryptid: mainDetails.cryptid,
                    mobileprovisionData: nil,
                    hasMobileProvisionArtifact: false,
                    codeSignatureTrust: bundleSigTrust
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
                let isExpectedRole = Self.isExpectedEmbeddedBinaryRole(
                    itemURL: itemURL,
                    bundleRootResolvedPrefix: bundleResolvedPrefix
                )
                let (prefixBytes, readFileSize) = Self.readMachOHeaderPrefix(of: readURL)
                let hasMachOMagic = Self.isMachOOrFatMagic(prefixBytes, fileSize: readFileSize)
                guard isExpectedRole || hasMachOMagic else { continue }

                let relPath = Self.bundleRelativePath(of: itemURL, in: bundleURL)
                if isDylib {
                    allLinkedDylibs.insert("@executable_path/\(relPath)")
                    appLinkedDylibs.insert("@executable_path/\(relPath)")
                }

                guard let dylibData = try? Self.readBoundedRegularFileDirectNoFollow(at: readURL),
                      let fwSlices = try? MachOParser.shared.parseAllSlices(data: dylibData),
                      !fwSlices.isEmpty else {
                    let corruptInd = Self.makeCorruptMachOIndicator(relPath: relPath)
                    allIndicators.append(corruptInd)
                    allMatchedSymbols.insert(corruptInd.signature)
                    continue
                }

                let fwSigTrust = CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: fwSlices)
                let fwHasMissingCS = CSBlobParser.hasMissingCodeSignature(inSlices: fwSlices)
                if fwHasMissingCS {
                    bundleHasMissingCS = true
                    appHasMissingCS = true
                }
                if fwSigTrust != .appleAppStoreVerified {
                    if bundleSigTrust == .appleAppStoreVerified || fwSigTrust.isDisqualifiedFromAppStore {
                        bundleSigTrust = fwSigTrust
                    }
                }
                if fwSigTrust.isDisqualifiedFromAppStore && channelResult.channel == .appStore {
                    channelResult = ChannelClassifier.classify(
                        cryptid: mainDetails.cryptid,
                        mobileprovisionData: nil,
                        hasMobileProvisionArtifact: false,
                        codeSignatureTrust: fwSigTrust
                    )
                }

                let fwDetails = MachOScanner.shared.parseMachO(
                    files: fwSlices,
                    rawData: dylibData,
                    expectedContainerSliceCount: fwSlices.first?.slicesInContainer.count
                )
                var fwGroups = combinedAppGroups
                for s in MachOParser.selectAuditSlices(from: fwSlices) {
                    let (_, sg) = CSBlobParser.shared.extractAppGroups(fromSlice: s)
                    for g in sg where !fwGroups.contains(g) { fwGroups.append(g) }
                    for g in sg where !combinedAppGroups.contains(g) { combinedAppGroups.append(g) }
                    let fwEnts = CSBlobParser.shared.parseMergedEntitlements(fromSlice: s)
                    entitlementsDict = CSBlobParser.mergeEntitlementDictionaries(entitlementsDict, fwEnts)
                }
                let fwContext = MachOScanner.ScanContext(
                    bundleId: bundleId,
                    displayName: appName,
                    version: version,
                    teamId: effectiveTeamId,
                    bundlePath: ipaURL.path,
                    executablePath: itemURL.path,
                    installChannel: channelResult.channel,
                    appGroups: fwGroups,
                    disqualifyAppStoreExemption: fwDetails.cryptid != 0 && (fwHasMissingCS || fwSigTrust != .appleAppStoreVerified)
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
                if !fwDetails.isFairPlayEncrypted || fwDetails.hasUnencryptedSegments || fwSigTrust.isDisqualifiedFromAppStore || fwHasMissingCS {
                    hasUnencryptedBinary = true
                    appHasUnencryptedBinary = true
                    unencryptedSymbols.formUnion(fwDetails.symbols)
                    appUnencryptedSymbols.formUnion(fwDetails.symbols)
                    unencryptedTextStrings.formUnion(fwDetails.textStrings)
                } else if fwSigTrust != .appleAppStoreVerified {
                    unencryptedSymbols.formUnion(fwDetails.symbols)
                    appUnencryptedSymbols.formUnion(fwDetails.symbols)
                }
                if fwFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
                if fwFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
            }
            
            // 5b. Escaping Bundle Symlinks & Expanded Local Threat Signatures (propagate all matched threat signatures into allMatchedSymbols so Trojanized bundles can never spoof WhitelistEngine)
            Self.appendEscapingSymlinkIndicators(
                escapingSymlinks: escapingSymlinks,
                allIndicators: &allIndicators,
                allMatchedSymbols: &allMatchedSymbols
            )
            Self.appendExpandedThreatIndicators(
                bundleId: bundleId,
                displayName: appName,
                installChannel: channelResult.channel,
                mainCryptid: mainDetails.cryptid,
                mainIsFairPlayEncrypted: mainDetails.isFairPlayEncrypted,
                mainHasUnencryptedSegments: mainDetails.hasUnencryptedSegments,
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
                codeSignatureTrust: bundleSigTrust,
                hasMissingCodeSignature: bundleHasMissingCS,
                appHasMissingCodeSignature: appHasMissingCS,
                allIndicators: &allIndicators,
                allMatchedSymbols: &allMatchedSymbols
            )
            for candidateEntBid in identityResolution.distinctBundleIds where candidateEntBid.caseInsensitiveCompare(bundleId) != .orderedSame {
                Self.appendConflictingIdentityIndicators(
                    conflictingBundleId: candidateEntBid,
                    displayName: appName,
                    installChannel: channelResult.channel,
                    mainCryptid: mainDetails.cryptid,
                    mainIsFairPlayEncrypted: mainDetails.isFairPlayEncrypted,
                    mainHasUnencryptedSegments: mainDetails.hasUnencryptedSegments,
                    hasUnencryptedBinary: hasUnencryptedBinary,
                    codeSignatureTrust: bundleSigTrust,
                    hasMissingCodeSignature: bundleHasMissingCS,
                    entitlementsDict: entitlementsDict,
                    allIndicators: &allIndicators,
                    allMatchedSymbols: &allMatchedSymbols
                )
            }
            
            // 6. Layer 4: Final Risk Grading & Whitelist Evaluation
            var provisionalRisk: RiskTier = .safe
            if allIndicators.contains(where: { $0.severity == .highRisk }) {
                provisionalRisk = .highRisk
            } else if allIndicators.contains(where: { $0.severity == .caution }) {
                provisionalRisk = .caution
            }

            let isTeamVerifiedForWhitelist: Bool
            if let effTeam = effectiveTeamId, !effTeam.isEmpty {
                isTeamVerifiedForWhitelist = (channelResult.teamIdentifier != nil)
                    && !identityResolution.hasMultipleTeamIds
                    && !identityResolution.hasProvisionTeamConflict
                    && !bundleHasMissingCS
                    && (bundleSigTrust != .adHocOrUnsigned)
            } else {
                isTeamVerifiedForWhitelist = true
            }
            let whitelistTeamId: String? = isTeamVerifiedForWhitelist ? effectiveTeamId : nil
            
            var isWhitelisted = false
            var whitelistedToolName: String? = nil
            var finalRisk = provisionalRisk
            
            if hasVerifiedBundleIdentity && (provisionalRisk == .highRisk || provisionalRisk == .caution) {
                let wlResult = WhitelistEngine.shared.isWhitelisted(
                    bundleId: hasExplicitPlistBundleId ? bundleId : (mainEntBundleId ?? bundleId),
                    appGroups: combinedAppGroups,
                    matchedSignatures: Array(allMatchedSymbols),
                    teamId: whitelistTeamId
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
                remediationGuidance: remediation,
                isWhitelistEligible: hasVerifiedBundleIdentity,
                isTeamIdWhitelistVerified: isTeamVerifiedForWhitelist
            )
            
            return ScanFinding(
                bundleId: bundleId,
                displayName: appName,
                version: version,
                teamId: effectiveTeamId,
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
        var currentStack: [String] = []
        var pendingTokens = linkRel.split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
            .filter { $0 != "." }
        guard !pendingTokens.isEmpty else { return nil }

        var symlinkHops = 0
        var visitedStates: Set<String> = []

        while !pendingTokens.isEmpty {
            let tok = pendingTokens.removeFirst()
            if tok.isEmpty || tok == "." {
                continue
            }
            if tok == ".." {
                guard !currentStack.isEmpty else {
                    return nil
                }
                currentStack.removeLast()
                continue
            }

            let candidate = (currentStack + [tok]).joined(separator: "/")
            if let target = symlinks[candidate] {
                if target.isEmpty || target.hasPrefix("/") || target.contains("\\") || target.contains("\0")
                    || target == "~" || target.hasPrefix("~/") {
                    return nil
                }
                let stateKey = candidate + "\u{0}" + pendingTokens.joined(separator: "/")
                guard visitedStates.insert(stateKey).inserted else {
                    return nil
                }
                symlinkHops += 1
                guard symlinkHops <= 16 else {
                    return nil
                }
                let hopTokens = target.split(separator: "/", omittingEmptySubsequences: true)
                    .map(String.init)
                    .filter { $0 != "." }
                pendingTokens.insert(contentsOf: hopTokens, at: 0)
                guard pendingTokens.count <= 256 else {
                    return nil
                }
            } else {
                currentStack.append(tok)
            }
        }

        guard !currentStack.isEmpty else { return nil }
        let finalRel = currentStack.joined(separator: "/")
        // Reject cyclic self-ancestor symlinks (`PlugIns/Loop.appex -> ..` or `PlugIns/Loop.appex -> ../PlugIns`)
        if linkRel == finalRel || linkRel.hasPrefix(finalRel + "/") {
            return nil
        }
        return finalRel
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

        var candLst = stat()
        guard lstat(candidateURL.path, &candLst) == 0 else {
            throw IPAPackageScannerError.missingExecutable(execName)
        }
        let candMode = candLst.st_mode & S_IFMT
        if candMode == S_IFDIR {
            throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                en: "CFBundleExecutable '\(execName)' resolves to a directory instead of a regular file",
                zh: "CFBundleExecutable '\(execName)' 指向目录而非可执行文件"
            ))
        }
        if candMode == S_IFLNK {
            var linkBuf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let linkLen = readlink(candidateURL.path, &linkBuf, Int(PATH_MAX))
            guard linkLen > 0 else {
                throw IPAPackageScannerError.zipSlipDetected(execName)
            }
            let linkTarget = String(cString: linkBuf)
            if linkTarget.hasPrefix("/") || linkTarget.contains("\\") || linkTarget.contains("\0") {
                throw IPAPackageScannerError.zipSlipDetected(execName)
            }
            let lexicalTarget = candidateURL.deletingLastPathComponent().appendingPathComponent(linkTarget).standardizedFileURL.path
            guard lexicalTarget.hasPrefix(bundleStdPrefix) || lexicalTarget.hasPrefix(bundleResolvedPrefix) else {
                throw IPAPackageScannerError.zipSlipDetected(execName)
            }
            let resolvedExecPath = candidateURL.resolvingSymlinksInPath().standardizedFileURL.path
            guard resolvedExecPath.hasPrefix(bundleResolvedPrefix) else {
                throw IPAPackageScannerError.zipSlipDetected(execName)
            }
            var targetLst = stat()
            guard lstat(resolvedExecPath, &targetLst) == 0 else {
                throw IPAPackageScannerError.zipSlipDetected(execName)
            }
            if (targetLst.st_mode & S_IFMT) == S_IFDIR {
                throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                    en: "CFBundleExecutable '\(execName)' resolves to a directory instead of a regular file",
                    zh: "CFBundleExecutable '\(execName)' 指向目录而非可执行文件"
                ))
            }
            guard (targetLst.st_mode & S_IFMT) == S_IFREG else {
                throw IPAPackageScannerError.zipSlipDetected(execName)
            }
            return (execName, candidateURL)
        }
        guard candMode == S_IFREG else {
            throw IPAPackageScannerError.invalidInfoPlist(WQLocale.pick(
                en: "CFBundleExecutable '\(execName)' is not a regular file",
                zh: "CFBundleExecutable '\(execName)' 不是普通可执行文件"
            ))
        }
        let resolvedExecPath = candidateURL.resolvingSymlinksInPath().standardizedFileURL.path
        guard resolvedExecPath.hasPrefix(bundleResolvedPrefix) else {
            throw IPAPackageScannerError.zipSlipDetected(execName)
        }

        return (execName, candidateURL)
    }

    internal static func isMachOOrFatMagic(_ rawInput: Data, fileSize: Int? = nil) -> Bool {
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
        guard data.count >= 4 else { return false }
        let rawBE = data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: 0, as: UInt32.self).bigEndian
        }
        func isPlausibleMachOCpuType(_ cpu: UInt32) -> Bool {
            let middleZero = (cpu & 0x00FF_FF00) == 0
            let baseArch = cpu & 0x0000_00FF
            let abiBits = cpu & 0xFF00_0000
            return middleZero && baseArch >= 1
                && (abiBits == 0x0000_0000 || abiBits == 0x0100_0000 || abiBits == 0x0200_0000)
        }
        switch rawBE {
        case 0xFEED_FACE, 0xCEFA_EDFE, 0xFEED_FACF, 0xCFFA_EDFE:
            return true
        case 0xCAFE_BABE, 0xCAFE_BABF:
            guard data.count >= 8 else { return false }
            let nfat = data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self).bigEndian
            }
            guard nfat >= 1 && nfat <= 1024 else { return false }
            if rawBE == 0xCAFE_BABF {
                return true
            }
            if data.count >= 12 {
                // Distinguish Universal FAT32 (0xCAFEBABE) from Java .class (0xCAFEBABE):
                // In every valid Java .class file, byte 10 is constant_pool[1].tag (1..20, never 0),
                // so firstCpu & 0x00FF_FF00 != 0. If fat_arch[0..k].cputype was deliberately perturbed,
                // inspect ALL available fat_arch[1..<available] entries (not just fat_arch[0..1]).
                let firstCpu = data.withUnsafeBytes { ptr in
                    ptr.loadUnaligned(fromByteOffset: 8, as: UInt32.self).bigEndian
                }
                if isPlausibleMachOCpuType(firstCpu) {
                    return true
                }
                if nfat >= 2 && data.count >= 28 {
                    let headerEnd = UInt64(8) + UInt64(nfat) * 20
                    if let fsz = fileSize, fsz >= 0, headerEnd > UInt64(fsz) {
                        return false
                    }
                    let availableSlices = min(Int(nfat), (data.count - 8) / 20)
                    for i in 1..<availableSlices {
                        let entryOff = 8 + i * 20
                        let cpuI = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entryOff, as: UInt32.self).bigEndian }
                        let offI = UInt64(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entryOff + 8, as: UInt32.self).bigEndian })
                        let szI = UInt64(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entryOff + 12, as: UInt32.self).bigEndian })
                        let alignI = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entryOff + 16, as: UInt32.self).bigEndian }
                        let sliceFitsFile: Bool
                        if let fsz = fileSize, fsz >= 0 {
                            sliceFitsFile = offI <= UInt64(fsz) && szI <= UInt64(fsz) - offI
                        } else {
                            sliceFitsFile = true
                        }
                        if isPlausibleMachOCpuType(cpuI) && alignI <= 32 && offI >= 8 && szI >= 28 && sliceFitsFile {
                            return true
                        }
                    }
                }
                return false
            }
            return nfat <= 32
        case 0xBEBA_FECA, 0xBFBA_FECA:
            guard data.count >= 8 else { return false }
            let nfat = data.withUnsafeBytes { ptr in
                ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self).littleEndian
            }
            return nfat >= 1 && nfat <= 1024
        default:
            return false
        }
    }

    /// Reads up to `maxBytes` from a regular file using `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`
    /// and `lstat`/`fstat` verification so symlinks, FIFOs, and device nodes are never followed or blocked on.
    internal static func readPrefixBytes(of fileURL: URL, maxBytes: Int = 64) -> Data? {
        readPrefixBytesAndSize(of: fileURL, maxBytes: maxBytes)?.prefix
    }

    internal static func readPrefixBytesAndSize(of fileURL: URL, maxBytes: Int = 64) -> (prefix: Data, fileSize: Int)? {
        guard maxBytes > 0 else { return (Data(), 0) }
        var lst = stat()
        guard lstat(fileURL.path, &lst) == 0,
              (lst.st_mode & S_IFMT) == S_IFREG else {
            return nil
        }
        let fd = Darwin.open(fileURL.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { Darwin.close(fd) }

        var fst = stat()
        guard fstat(fd, &fst) == 0,
              (fst.st_mode & S_IFMT) == S_IFREG,
              fst.st_dev == lst.st_dev,
              fst.st_ino == lst.st_ino else {
            return nil
        }
        let totalSize = Int(clamping: max(0, fst.st_size))
        let toRead = min(maxBytes, totalSize)
        guard toRead > 0 else { return (Data(), totalSize) }
        var buf = [UInt8](repeating: 0, count: toRead)
        var offset = 0
        while offset < toRead {
            let n: Int = buf.withUnsafeMutableBytes { raw in
                guard let ptr = raw.baseAddress?.advanced(by: offset) else { return -1 }
                return Darwin.read(fd, ptr, toRead - offset)
            }
            if n > 0 {
                offset += n
            } else if n == 0 {
                break
            } else if errno == EINTR {
                continue
            } else {
                return nil
            }
        }
        return (Data(buf[0..<offset]), totalSize)
    }

    /// Reads 64 bytes (or up to `8 + nfat * 20` bytes for 3..1024-slice FAT headers) without following symlinks.
    internal static func readMachOHeaderPrefix(of fileURL: URL) -> (prefix: Data, fileSize: Int?) {
        guard let initial = readPrefixBytesAndSize(of: fileURL, maxBytes: 64) else {
            return (Data(), nil)
        }
        let data = initial.prefix
        guard data.count >= 8 else {
            return (data, initial.fileSize)
        }
        let rawBE = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self).bigEndian }
        if rawBE == 0xCAFE_BABE || rawBE == 0xBEBA_FECA {
            let nfat: UInt32 = data.withUnsafeBytes { ptr in
                rawBE == 0xCAFE_BABE
                    ? ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self).bigEndian
                    : ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self).littleEndian
            }
            if nfat > 2 && nfat <= 1024 {
                let needed = min(20_488, 8 + Int(nfat) * 20)
                if needed > data.count && initial.fileSize > data.count,
                   let expanded = readPrefixBytesAndSize(of: fileURL, maxBytes: needed) {
                    return (expanded.prefix, expanded.fileSize)
                }
            }
        }
        return (data, initial.fileSize)
    }

    public static func stripTrailingSlashes(_ rawPath: String) -> String {
        var s = rawPath
        while s.count > 1 && s.hasSuffix("/") {
            s.removeLast()
        }
        return s
    }

    public static func isNonSymlinkDirectory(at dirURL: URL) -> Bool {
        let cleanPath = stripTrailingSlashes(dirURL.path)
        var lst = stat()
        guard lstat(cleanPath, &lst) == 0 else { return false }
        return (lst.st_mode & S_IFMT) == S_IFDIR
    }

    /// Returns `true` ONLY when `fileURL` is a genuine macOS AppleDouble (`._*`) metadata file starting with magic `0x00051607`,
    /// preventing attackers from hiding real PKZIP `.ipa` or Mach-O payloads under `._*` filenames.
    public static func isGenuineAppleDoubleMetadataFile(at fileURL: URL) -> Bool {
        guard fileURL.lastPathComponent.hasPrefix("._") else { return false }
        guard let prefix = readPrefixBytes(of: fileURL, maxBytes: 4), prefix.count == 4 else {
            return false
        }
        return prefix[0] == 0x00 && prefix[1] == 0x05 && prefix[2] == 0x16 && prefix[3] == 0x07
    }

    /// Safely reads a regular file strictly using `lstat` + `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` bounded to `maxBytes`.
    public static func readBoundedRegularFileDirectNoFollow(at fileURL: URL, maxBytes: Int = 512 * 1024 * 1024) throws -> Data {
        let cleanPath = stripTrailingSlashes(fileURL.path)
        var lst = stat()
        guard lstat(cleanPath, &lst) == 0 else {
            throw IPAPackageScannerError.fileNotFound(cleanPath)
        }
        let mode = lst.st_mode & S_IFMT
        if mode == S_IFLNK {
            throw IPAPackageScannerError.zipSlipDetected((cleanPath as NSString).lastPathComponent)
        }
        guard mode == S_IFREG else {
            throw IPAPackageScannerError.invalidArchive(WQLocale.pick(
                en: "Target is not a regular file: '\(cleanPath)'",
                zh: "目标不是普通文件: '\(cleanPath)'"
            ))
        }
        let fd = Darwin.open(cleanPath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ELOOP {
                throw IPAPackageScannerError.zipSlipDetected((cleanPath as NSString).lastPathComponent)
            }
            throw IPAPackageScannerError.fileNotFound(cleanPath)
        }
        defer { Darwin.close(fd) }

        var fst = stat()
        guard fstat(fd, &fst) == 0,
              (fst.st_mode & S_IFMT) == S_IFREG,
              fst.st_dev == lst.st_dev,
              fst.st_ino == lst.st_ino else {
            throw IPAPackageScannerError.invalidArchive(WQLocale.pick(
                en: "Target file changed type or inode during open: '\(cleanPath)'",
                zh: "目标文件在读取时发生类型或 inode 变更: '\(cleanPath)'"
            ))
        }
        guard fst.st_size >= 0, fst.st_size <= off_t(maxBytes) else {
            throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                en: "File size (\(fst.st_size) bytes) exceeds safety limit (\(maxBytes) bytes)",
                zh: "文件大小 (\(fst.st_size) 字节) 超过安全上限 (\(maxBytes) 字节)"
            ))
        }
        let expected = Int(fst.st_size)
        if expected == 0 { return Data() }
        var out = Data(count: expected)
        var total = 0
        try out.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            while total < expected {
                let n = Darwin.read(fd, base.advanced(by: total), expected - total)
                if n > 0 {
                    total += n
                } else if n == 0 {
                    break
                } else if errno == EINTR {
                    continue
                } else {
                    throw IPAPackageScannerError.invalidArchive("Read failed for '\(cleanPath)'")
                }
            }
        }
        return total < expected ? Data(out.prefix(total)) : out
    }

    /// Streams a bounded regular file to `destinationURL` using `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` on read
    /// and an `O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC` sibling staging file + atomic `rename` on write.
    @discardableResult
    public static func copyBoundedRegularFileNoFollow(
        from sourceURL: URL,
        to destinationURL: URL,
        maxBytes: Int = 1024 * 1024 * 1024
    ) throws -> Int {
        let srcPath = stripTrailingSlashes(sourceURL.path)
        let dstPath = stripTrailingSlashes(destinationURL.path)
        let dstParentPath = stripTrailingSlashes(destinationURL.deletingLastPathComponent().path)

        var parentLst = stat()
        guard lstat(dstParentPath, &parentLst) == 0,
              (parentLst.st_mode & S_IFMT) == S_IFDIR else {
            throw IPAPackageScannerError.invalidArchive(WQLocale.pick(
                en: "Destination directory is invalid or a symbolic link: '\(dstParentPath)'",
                zh: "目标目录无效或为符号链接: '\(dstParentPath)'"
            ))
        }

        var existingDstLst = stat()
        if lstat(dstPath, &existingDstLst) == 0 {
            let dstMode = existingDstLst.st_mode & S_IFMT
            if dstMode == S_IFLNK {
                throw IPAPackageScannerError.zipSlipDetected((dstPath as NSString).lastPathComponent)
            }
            guard dstMode == S_IFREG else {
                throw IPAPackageScannerError.invalidArchive("Refusing to overwrite non-regular destination '\(dstPath)'")
            }
        }

        var srcLst = stat()
        guard lstat(srcPath, &srcLst) == 0 else {
            throw IPAPackageScannerError.fileNotFound(srcPath)
        }
        let srcMode = srcLst.st_mode & S_IFMT
        if srcMode == S_IFLNK {
            throw IPAPackageScannerError.zipSlipDetected((srcPath as NSString).lastPathComponent)
        }
        guard srcMode == S_IFREG else {
            throw IPAPackageScannerError.invalidArchive(WQLocale.pick(
                en: "Source is not a regular file: '\(srcPath)'",
                zh: "源文件不是普通文件: '\(srcPath)'"
            ))
        }

        let inFD = Darwin.open(srcPath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard inFD >= 0 else {
            if errno == ELOOP {
                throw IPAPackageScannerError.zipSlipDetected((srcPath as NSString).lastPathComponent)
            }
            throw IPAPackageScannerError.fileNotFound(srcPath)
        }
        defer { Darwin.close(inFD) }

        var srcFst = stat()
        guard fstat(inFD, &srcFst) == 0,
              (srcFst.st_mode & S_IFMT) == S_IFREG,
              srcFst.st_dev == srcLst.st_dev,
              srcFst.st_ino == srcLst.st_ino else {
            throw IPAPackageScannerError.invalidArchive("Source file changed type or inode during open: '\(srcPath)'")
        }
        guard srcFst.st_size >= 0, srcFst.st_size <= off_t(maxBytes) else {
            throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                en: "File size (\(srcFst.st_size) bytes) exceeds safety limit (\(maxBytes) bytes)",
                zh: "文件大小 (\(srcFst.st_size) 字节) 超过安全上限 (\(maxBytes) 字节)"
            ))
        }

        let tmpPath = "\(dstParentPath)/.wqguard_stage_\(UUID().uuidString).tmp"
        let outFD = Darwin.open(tmpPath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard outFD >= 0 else {
            throw IPAPackageScannerError.invalidArchive("Unable to create staging file at '\(dstParentPath)'")
        }
        var closedOutFD = false
        var renamedStage = false
        defer {
            if !closedOutFD { Darwin.close(outFD) }
            if !renamedStage { _ = Darwin.unlink(tmpPath) }
        }

        let chunkSize = 256 * 1024
        var chunk = [UInt8](repeating: 0, count: chunkSize)
        var totalCopied = 0

        while true {
            let n = Darwin.read(inFD, &chunk, chunkSize)
            if n > 0 {
                totalCopied += n
                if totalCopied > maxBytes {
                    throw IPAPackageScannerError.quotaExceeded(WQLocale.pick(
                        en: "Streamed file exceeded safety limit (\(maxBytes) bytes)",
                        zh: "复制文件过程中大小超出安全上限 (\(maxBytes) 字节)"
                    ))
                }
                var written = 0
                while written < n {
                    let w = chunk.withUnsafeBytes { raw in
                        Darwin.write(outFD, raw.baseAddress!.advanced(by: written), n - written)
                    }
                    if w > 0 {
                        written += w
                    } else if w < 0 && errno == EINTR {
                        continue
                    } else {
                        throw IPAPackageScannerError.invalidArchive("Write failed while staging '\(dstPath)'")
                    }
                }
            } else if n == 0 {
                break
            } else if errno == EINTR {
                continue
            } else {
                throw IPAPackageScannerError.invalidArchive("Read failed while copying '\(srcPath)'")
            }
        }

        Darwin.close(outFD)
        closedOutFD = true

        // Re-check destination is not a symlink right before rename
        if lstat(dstPath, &existingDstLst) == 0 && (existingDstLst.st_mode & S_IFMT) == S_IFLNK {
            throw IPAPackageScannerError.zipSlipDetected((dstPath as NSString).lastPathComponent)
        }
        guard Darwin.rename(tmpPath, dstPath) == 0 else {
            throw IPAPackageScannerError.invalidArchive("Atomic rename failed for '\(dstPath)'")
        }
        renamedStage = true
        return totalCopied
    }

    /// Atomically writes bounded in-memory `Data` to `destinationURL`, rejecting symbolic links on both parent directory and destination file.
    public static func writeBoundedRegularFileAtomicNoFollow(_ data: Data, to destinationURL: URL) throws {
        let dstPath = stripTrailingSlashes(destinationURL.path)
        let dstParentPath = stripTrailingSlashes(destinationURL.deletingLastPathComponent().path)

        var parentLst = stat()
        guard lstat(dstParentPath, &parentLst) == 0,
              (parentLst.st_mode & S_IFMT) == S_IFDIR else {
            throw IPAPackageScannerError.invalidArchive("Destination directory is invalid or a symbolic link: '\(dstParentPath)'")
        }

        var existingDstLst = stat()
        if lstat(dstPath, &existingDstLst) == 0 {
            let dstMode = existingDstLst.st_mode & S_IFMT
            if dstMode == S_IFLNK {
                throw IPAPackageScannerError.zipSlipDetected((dstPath as NSString).lastPathComponent)
            }
            guard dstMode == S_IFREG else {
                throw IPAPackageScannerError.invalidArchive("Refusing to overwrite non-regular destination '\(dstPath)'")
            }
        }

        let tmpPath = "\(dstParentPath)/.wqguard_write_\(UUID().uuidString).tmp"
        let outFD = Darwin.open(tmpPath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard outFD >= 0 else {
            throw IPAPackageScannerError.invalidArchive("Unable to create atomic write file at '\(dstParentPath)'")
        }
        var closedOutFD = false
        var renamedStage = false
        defer {
            if !closedOutFD { Darwin.close(outFD) }
            if !renamedStage { _ = Darwin.unlink(tmpPath) }
        }

        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress, raw.count > 0 else { return }
            var written = 0
            while written < raw.count {
                let w = Darwin.write(outFD, base.advanced(by: written), raw.count - written)
                if w > 0 {
                    written += w
                } else if w < 0 && errno == EINTR {
                    continue
                } else {
                    throw IPAPackageScannerError.invalidArchive("Atomic write failed for '\(dstPath)'")
                }
            }
        }

        Darwin.close(outFD)
        closedOutFD = true

        if lstat(dstPath, &existingDstLst) == 0 && (existingDstLst.st_mode & S_IFMT) == S_IFLNK {
            throw IPAPackageScannerError.zipSlipDetected((dstPath as NSString).lastPathComponent)
        }
        guard Darwin.rename(tmpPath, dstPath) == 0 else {
            throw IPAPackageScannerError.invalidArchive("Atomic rename failed for '\(dstPath)'")
        }
        renamedStage = true
    }

    internal static func extractFlexibleStringList(_ raw: Any?) -> [String] {
        guard let raw else { return [] }
        if let arr = raw as? [String] {
            return arr
        }
        if let anyArr = raw as? [Any] {
            return anyArr.compactMap { $0 as? String }
        }
        if let single = raw as? String {
            return [single]
        }
        return []
    }

    internal static func appendEscapingSymlinkIndicators(
        escapingSymlinks: [String],
        allIndicators: inout [ThreatIndicator],
        allMatchedSymbols: inout Set<String>
    ) {
        guard !escapingSymlinks.isEmpty else { return }
        allMatchedSymbols.insert("BUNDLE_ESCAPING_SYMLINK")
        for symPath in escapingSymlinks {
            allIndicators.append(ThreatIndicator(
                signature: "BUNDLE_ESCAPING_SYMLINK",
                description: WQLocale.pick(
                    en: "Application bundle contains an escaping or cyclic symbolic link (\(symPath)) pointing outside bundle boundaries.",
                    zh: "应用包内包含越界或循环符号链接 (\(symPath))，指向应用包边界之外。"
                ),
                category: ThreatIndicator.Category.escapingSymlink,
                location: symPath,
                severity: .highRisk
            ))
        }
    }

    internal static func isExpectedEmbeddedBinaryRole(
        itemURL: URL,
        bundleRootResolvedPrefix: String? = nil
    ) -> Bool {
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
        let grandParentURL = parentURL.deletingLastPathComponent()
        let frameworkRootURL: URL?
        if parentURL.pathExtension.lowercased() == "framework" {
            frameworkRootURL = parentURL
        } else if grandParentURL.lastPathComponent.lowercased() == "versions" &&
                  grandParentURL.deletingLastPathComponent().pathExtension.lowercased() == "framework" {
            frameworkRootURL = grandParentURL.deletingLastPathComponent()
        } else {
            frameworkRootURL = nil
        }

        if let fwURL = frameworkRootURL {
            let plistCandidates = [
                fwURL.appendingPathComponent("Info.plist"),
                fwURL.appendingPathComponent("Resources/Info.plist"),
                parentURL.appendingPathComponent("Resources/Info.plist")
            ]
            for fwPlistURL in plistCandidates {
                let resolvedPlist = fwPlistURL.resolvingSymlinksInPath().standardizedFileURL
                if let rootPrefix = bundleRootResolvedPrefix, !resolvedPlist.path.hasPrefix(rootPrefix) {
                    continue
                }
                if let pData = try? readBoundedRegularFileDirectNoFollow(at: resolvedPlist, maxBytes: 4 * 1024 * 1024),
                   let pDict = (try? PropertyListSerialization.propertyList(from: pData, options: [], format: nil)) as? [String: Any],
                   let fwExec = pDict["CFBundleExecutable"] as? String,
                   !fwExec.isEmpty {
                    return cleanName == fwExec
                }
            }
            let fwStem = fwURL.deletingPathExtension().lastPathComponent
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

    private struct BundleInodeKey: Hashable {
        let dev: dev_t
        let ino: ino_t
    }

    /// Discovers all embedded `.appex` and `.xpc` bundles inside `rootURL`, safely descending through strictly
    /// in-bundle directory symlinks (e.g. `PlugIns -> Resources/ExtStore`) with inode cycle protection while recording escaping/cyclic symlinks.
    internal static func discoverEmbeddedExtensions(
        in rootURL: URL,
        bundleRootResolvedPrefix: String,
        escapingSymlinks: inout [String],
        bundleRootURL: URL
    ) -> [URL] {
        var found: [URL] = []
        var seenLogicalPaths: Set<String> = []
        let rootResolved = rootURL.resolvingSymlinksInPath().standardizedFileURL
        let rootNoSlash = bundleRootResolvedPrefix.hasSuffix("/")
            ? String(bundleRootResolvedPrefix.dropLast())
            : bundleRootResolvedPrefix
        var visitedCount = 0

        func walk(logicalDir: URL, physicalDir: URL, ancestorInodes: Set<BundleInodeKey>, depth: Int) {
            guard depth <= 16, visitedCount < 20_000 else { return }
            var dirSt = stat()
            guard lstat(physicalDir.path, &dirSt) == 0,
                  (dirSt.st_mode & S_IFMT) == S_IFDIR else { return }
            let dirInode = BundleInodeKey(dev: dirSt.st_dev, ino: dirSt.st_ino)
            guard !ancestorInodes.contains(dirInode) else { return }
            var nextAncestors = ancestorInodes
            nextAncestors.insert(dirInode)

            guard let dp = opendir(physicalDir.path) else { return }
            defer { closedir(dp) }

            var names: [String] = []
            while let ent = readdir(dp) {
                let name = withUnsafeBytes(of: ent.pointee.d_name) { raw -> String in
                    String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                }
                if name != "." && name != ".." && !name.hasPrefix("._") {
                    names.append(name)
                }
            }
            names.sort()

            for name in names {
                if visitedCount >= 20_000 { break }
                visitedCount += 1
                let childLogical = logicalDir.appendingPathComponent(name)
                let childPhysical = physicalDir.appendingPathComponent(name)
                var cst = stat()
                guard lstat(childPhysical.path, &cst) == 0 else { continue }
                let mode = cst.st_mode & S_IFMT
                let ext = childLogical.pathExtension.lowercased()

                if mode == S_IFLNK {
                    let resolved = childPhysical.resolvingSymlinksInPath().standardizedFileURL
                    guard resolved.path.hasPrefix(bundleRootResolvedPrefix),
                          resolved.path != rootNoSlash,
                          !rootNoSlash.hasPrefix(resolved.path + "/") else {
                        let rel = bundleRelativePath(of: childLogical, in: bundleRootURL)
                        if !escapingSymlinks.contains(rel) {
                            escapingSymlinks.append(rel)
                        }
                        continue
                    }
                    var rst = stat()
                    guard lstat(resolved.path, &rst) == 0 else { continue }
                    if (rst.st_mode & S_IFMT) == S_IFDIR {
                        let rInode = BundleInodeKey(dev: rst.st_dev, ino: rst.st_ino)
                        if nextAncestors.contains(rInode) {
                            let rel = bundleRelativePath(of: childLogical, in: bundleRootURL)
                            if !escapingSymlinks.contains(rel) {
                                escapingSymlinks.append(rel)
                            }
                            continue
                        }
                        if ext == "appex" || ext == "xpc" || ext == "app" {
                            let key = childLogical.standardizedFileURL.path
                            if seenLogicalPaths.insert(key).inserted {
                                found.append(childLogical)
                            }
                        }
                        walk(logicalDir: childLogical, physicalDir: resolved, ancestorInodes: nextAncestors, depth: depth + 1)
                    }
                } else if mode == S_IFDIR {
                    if ext == "appex" || ext == "xpc" || ext == "app" {
                        let key = childLogical.standardizedFileURL.path
                        if seenLogicalPaths.insert(key).inserted {
                            found.append(childLogical)
                        }
                    }
                    walk(logicalDir: childLogical, physicalDir: childPhysical, ancestorInodes: nextAncestors, depth: depth + 1)
                }
            }
        }

        walk(logicalDir: rootURL, physicalDir: rootResolved, ancestorInodes: [], depth: 0)
        return found
    }

    internal static func computeEmbeddedExtensionPrefixes(
        appexURLs: [URL],
        bundleRootResolvedPrefix: String
    ) -> [String] {
        let rootNoSlash = bundleRootResolvedPrefix.hasSuffix("/")
            ? String(bundleRootResolvedPrefix.dropLast())
            : bundleRootResolvedPrefix
        var prefixes: [String] = []
        var seen: Set<String> = []
        for u in appexURLs {
            let logicalPfx = u.standardizedFileURL.path + "/"
            if seen.insert(logicalPfx).inserted {
                prefixes.append(logicalPfx)
            }
            let resolved = u.resolvingSymlinksInPath().standardizedFileURL.path
            if resolved.hasPrefix(bundleRootResolvedPrefix) && resolved != rootNoSlash && !rootNoSlash.hasPrefix(resolved + "/") {
                let resolvedPfx = resolved + "/"
                if seen.insert(resolvedPfx).inserted {
                    prefixes.append(resolvedPfx)
                }
            }
        }
        return prefixes
    }

    internal static func enumerateCandidateFiles(
        in rootURL: URL,
        bundleRootResolvedPrefix: String,
        escapingSymlinks: inout [String],
        bundleRootURL: URL
    ) -> [(logicalURL: URL, readURL: URL)] {
        var results: [(logicalURL: URL, readURL: URL)] = []
        let rootResolved = rootURL.resolvingSymlinksInPath().standardizedFileURL
        let rootNoSlash = bundleRootResolvedPrefix.hasSuffix("/")
            ? String(bundleRootResolvedPrefix.dropLast())
            : bundleRootResolvedPrefix
        var visitedCount = 0

        func walk(logicalDir: URL, physicalDir: URL, ancestorInodes: Set<BundleInodeKey>, depth: Int) {
            guard depth <= 16, visitedCount < 20_000 else { return }
            var dirSt = stat()
            guard lstat(physicalDir.path, &dirSt) == 0,
                  (dirSt.st_mode & S_IFMT) == S_IFDIR else { return }
            let dirInode = BundleInodeKey(dev: dirSt.st_dev, ino: dirSt.st_ino)
            guard !ancestorInodes.contains(dirInode) else { return }
            var nextAncestors = ancestorInodes
            nextAncestors.insert(dirInode)

            guard let dp = opendir(physicalDir.path) else { return }
            defer { closedir(dp) }

            var names: [String] = []
            while let ent = readdir(dp) {
                let name = withUnsafeBytes(of: ent.pointee.d_name) { raw -> String in
                    String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                }
                if name != "." && name != ".." {
                    names.append(name)
                }
            }
            names.sort()

            for name in names {
                if visitedCount >= 20_000 { break }
                visitedCount += 1
                let childLogical = logicalDir.appendingPathComponent(name)
                let childPhysical = physicalDir.appendingPathComponent(name)
                var cst = stat()
                guard lstat(childPhysical.path, &cst) == 0 else { continue }
                let mode = cst.st_mode & S_IFMT

                if mode == S_IFLNK {
                    let resolved = childPhysical.resolvingSymlinksInPath().standardizedFileURL
                    guard resolved.path.hasPrefix(bundleRootResolvedPrefix),
                          resolved.path != rootNoSlash,
                          !rootNoSlash.hasPrefix(resolved.path + "/") else {
                        let rel = bundleRelativePath(of: childLogical, in: bundleRootURL)
                        if !escapingSymlinks.contains(rel) {
                            escapingSymlinks.append(rel)
                        }
                        continue
                    }
                    var rst = stat()
                    guard lstat(resolved.path, &rst) == 0 else { continue }
                    let rMode = rst.st_mode & S_IFMT
                    if rMode == S_IFREG {
                        results.append((logicalURL: childLogical, readURL: resolved))
                    } else if rMode == S_IFDIR {
                        let rInode = BundleInodeKey(dev: rst.st_dev, ino: rst.st_ino)
                        if nextAncestors.contains(rInode) {
                            let rel = bundleRelativePath(of: childLogical, in: bundleRootURL)
                            if !escapingSymlinks.contains(rel) {
                                escapingSymlinks.append(rel)
                            }
                            continue
                        }
                        walk(logicalDir: childLogical, physicalDir: resolved, ancestorInodes: nextAncestors, depth: depth + 1)
                    }
                } else if mode == S_IFREG {
                    let resolved = childPhysical.resolvingSymlinksInPath().standardizedFileURL
                    guard resolved.path.hasPrefix(bundleRootResolvedPrefix) else {
                        let rel = bundleRelativePath(of: childLogical, in: bundleRootURL)
                        if !escapingSymlinks.contains(rel) {
                            escapingSymlinks.append(rel)
                        }
                        continue
                    }
                    results.append((logicalURL: childLogical, readURL: resolved))
                } else if mode == S_IFDIR {
                    walk(logicalDir: childLogical, physicalDir: childPhysical, ancestorInodes: nextAncestors, depth: depth + 1)
                }
            }
        }

        walk(logicalDir: rootURL, physicalDir: rootResolved, ancestorInodes: [], depth: 0)
        return results
    }

    internal static func extractEntitlementBundleIdentity(
        entitlements: [String: Any],
        explicitTeamId: String?
    ) -> (bundleId: String?, resolvedTeamId: String?) {
        guard let rawAppId = (entitlements["application-identifier"] as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              !rawAppId.isEmpty else {
            return (nil, explicitTeamId)
        }
        var teamOut = explicitTeamId
        if let explicitTeam = explicitTeamId, !explicitTeam.isEmpty, rawAppId.hasPrefix(explicitTeam + ".") {
            let stripped = String(rawAppId.dropFirst(explicitTeam.count + 1))
            return (stripped.isEmpty ? rawAppId : stripped, teamOut)
        }
        if let dotIdx = rawAppId.firstIndex(of: ".") {
            let prefix = String(rawAppId[..<dotIdx])
            let rest = String(rawAppId[rawAppId.index(after: dotIdx)...])
            let isTenCharTeam = prefix.count == 10 && prefix.utf8.allSatisfy {
                ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x30 && $0 <= 0x39)
            }
            if isTenCharTeam && !rest.isEmpty {
                if teamOut == nil { teamOut = prefix }
                return (rest, teamOut)
            }
        }
        return (rawAppId, teamOut)
    }

    internal static func doesEntitlementBundleIdConflict(
        entBundleId: String?,
        withPlistBundleId plistBundleId: String
    ) -> Bool {
        guard let ent = entBundleId?.trimmingCharacters(in: .whitespacesAndNewlines),
              !ent.isEmpty else {
            return false
        }
        let plist = plistBundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !plist.isEmpty else { return false }
        if ent == "*" || ent.caseInsensitiveCompare(plist) == .orderedSame {
            return false
        }
        if ent.hasSuffix(".*") {
            let prefix = String(ent.dropLast())
            return !plist.lowercased().hasPrefix(prefix.lowercased())
        }
        return true
    }

    internal struct EntitlementIdentityResolution: Sendable {
        let distinctBundleIds: [String]
        let distinctTeamIds: [String]
        let primaryBundleId: String?
        let inferredTeamId: String?
        let hasMultipleBundleIds: Bool
        let hasMultipleTeamIds: Bool
        let hasProvisionTeamConflict: Bool
    }

    internal static func resolveDistinctEntitlementIdentities(
        fromSlices slices: [MachOFile],
        explicitTeamId: String?
    ) -> EntitlementIdentityResolution {
        let (rawAppIds, rawTeamIds) = CSBlobParser.shared.extractDistinctEntitlementIdentities(fromSlices: slices)
        var bundleIds: [String] = []
        var seenBidsLower: Set<String> = []
        var teamIds: [String] = []
        var seenTeamLower: Set<String> = []

        func appendUniqueTeam(_ tid: String?) {
            guard let t = tid?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else { return }
            if seenTeamLower.insert(t.lowercased()).inserted {
                teamIds.append(t)
            }
        }

        for tid in rawTeamIds {
            appendUniqueTeam(tid)
        }

        for rawAppId in rawAppIds {
            let (parsedBid, inferredTid) = extractEntitlementBundleIdentity(
                entitlements: ["application-identifier": rawAppId],
                explicitTeamId: explicitTeamId
            )
            if inferredTid?.caseInsensitiveCompare(explicitTeamId ?? "") != .orderedSame {
                appendUniqueTeam(inferredTid)
            } else if explicitTeamId != nil, let dotIdx = rawAppId.firstIndex(of: ".") {
                let prefix = String(rawAppId[..<dotIdx])
                let rest = rawAppId[rawAppId.index(after: dotIdx)...]
                let isTenCharTeam = prefix.count == 10 && !rest.isEmpty && prefix.utf8.allSatisfy {
                    ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x30 && $0 <= 0x39)
                }
                if isTenCharTeam {
                    appendUniqueTeam(prefix)
                }
            }
            if let bid = parsedBid?.trimmingCharacters(in: .whitespacesAndNewlines), !bid.isEmpty {
                if seenBidsLower.insert(bid.lowercased()).inserted {
                    bundleIds.append(bid)
                }
            }
        }

        let trimmedExplicitTeam = explicitTeamId?.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasProvConflict: Bool
        if let provTeam = trimmedExplicitTeam, !provTeam.isEmpty {
            hasProvConflict = teamIds.contains { $0.caseInsensitiveCompare(provTeam) != .orderedSame }
        } else {
            hasProvConflict = false
        }

        return EntitlementIdentityResolution(
            distinctBundleIds: bundleIds,
            distinctTeamIds: teamIds,
            primaryBundleId: bundleIds.first,
            inferredTeamId: teamIds.first,
            hasMultipleBundleIds: bundleIds.count > 1,
            hasMultipleTeamIds: teamIds.count > 1,
            hasProvisionTeamConflict: hasProvConflict
        )
    }

    internal static func appendConflictingIdentityIndicators(
        conflictingBundleId: String,
        displayName: String,
        installChannel: InstallChannel,
        mainCryptid: UInt32,
        mainIsFairPlayEncrypted: Bool = false,
        mainHasUnencryptedSegments: Bool = false,
        hasUnencryptedBinary: Bool,
        codeSignatureTrust: CodeSignatureTrustDisposition = .absentOrSynthetic,
        hasMissingCodeSignature: Bool = false,
        entitlementsDict: [String: Any],
        allIndicators: inout [ThreatIndicator],
        allMatchedSymbols: inout Set<String>
    ) {
        let isVerifiedAppStore = (codeSignatureTrust == .appleAppStoreVerified
            && !hasMissingCodeSignature
            && mainIsFairPlayEncrypted
            && !mainHasUnencryptedSegments)
        let effectiveImpChannel: InstallChannel = (!isVerifiedAppStore && (installChannel == .appStore || installChannel == .testFlight))
            ? .developerSideloaded
            : installChannel
        let effectiveCryptid: UInt32 = (!isVerifiedAppStore || effectiveImpChannel.isSideloadedOrEnterprise)
            ? 0
            : mainCryptid
        let effectiveEntChannel: InstallChannel = (!isVerifiedAppStore && installChannel == .appStore)
            ? .developerSideloaded
            : installChannel
        let extraInds = ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: conflictingBundleId,
            displayName: displayName,
            installChannel: effectiveImpChannel,
            cryptid: effectiveCryptid
        ) + ExpandedThreatCatalog.evaluateDangerousEntitlements(
            bundleId: conflictingBundleId,
            installChannel: effectiveEntChannel,
            entitlements: entitlementsDict,
            hasUnencryptedBinary: hasUnencryptedBinary || !isVerifiedAppStore
        )
        let existingKeys = Set(allIndicators.map { "\($0.signature)\u{0}\($0.location)" })
        for ind in extraInds {
            allMatchedSymbols.insert(ind.signature)
            if !existingKeys.contains("\(ind.signature)\u{0}\(ind.location)") {
                allIndicators.append(ind)
            }
        }
    }

    internal static func scanEmbeddedAppex(
        appexURL: URL,
        rootBundleURL: URL,
        bundleResolvedPrefix: String,
        allEmbeddedExtensionPrefixes: [String] = [],
        parentBundleId: String,
        version: String,
        teamId: String?,
        installChannel: InstallChannel,
        hasArchiveMobileProvision: Bool = false,
        machoScanner: MachOScanner,
        combinedAppGroups: inout [String],
        entitlementsDict: inout [String: Any],
        allIndicators: inout [ThreatIndicator],
        allMatchedSymbols: inout Set<String>,
        allLinkedDylibs: inout Set<String>,
        unencryptedSymbols: inout Set<String>,
        unencryptedTextStrings: inout Set<String>,
        hasUnencryptedBinary: inout Bool,
        bundleCodeSignatureTrust: inout CodeSignatureTrustDisposition,
        bundleHasMissingCodeSignature: inout Bool,
        dynamicLoadingFound: inout Bool,
        pathEnumerationFound: inout Bool,
        escapingSymlinks: inout [String]
    ) {
        let appexRelPath = bundleRelativePath(of: appexURL, in: rootBundleURL)
        let resolvedAppexURL = appexURL.resolvingSymlinksInPath().standardizedFileURL
        let rootNoSlash = bundleResolvedPrefix.hasSuffix("/") ? String(bundleResolvedPrefix.dropLast()) : bundleResolvedPrefix

        // Validate `.appex`/`.xpc`/nested `.app` containment BEFORE reading Info.plist or traversing children:
        // rejects external symlinks and cyclic ancestor symlinks (`PlugIns/Loop.appex -> ..`).
        guard resolvedAppexURL.path.hasPrefix(bundleResolvedPrefix),
              resolvedAppexURL.path != rootNoSlash,
              !rootNoSlash.hasPrefix(resolvedAppexURL.path + "/") else {
            if !escapingSymlinks.contains(appexRelPath) {
                escapingSymlinks.append(appexRelPath)
            }
            return
        }

        var appexIsDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: resolvedAppexURL.path, isDirectory: &appexIsDir),
              appexIsDir.boolValue else {
            return
        }

        let ownLogicalPrefix = appexURL.standardizedFileURL.path + "/"
        let ownResolvedPrefix = resolvedAppexURL.path + "/"
        let strictChildExtensionPrefixes = allEmbeddedExtensionPrefixes.filter { pfx in
            pfx != ownLogicalPrefix && pfx != ownResolvedPrefix && (pfx.hasPrefix(ownLogicalPrefix) || pfx.hasPrefix(ownResolvedPrefix))
        }

        var pDict: [String: Any]? = nil
        var plugPlistData: Data? = nil
        let flatPlugPlistURL = resolvedAppexURL.appendingPathComponent("Info.plist")
        let contentsPlugPlistURL = resolvedAppexURL.appendingPathComponent("Contents/Info.plist")
        for candidatePlistURL in [flatPlugPlistURL, contentsPlugPlistURL] {
            var plistStat = stat()
            guard lstat(candidatePlistURL.path, &plistStat) == 0 else { continue }
            let resolvedPlistURL = candidatePlistURL.resolvingSymlinksInPath().standardizedFileURL
            guard resolvedPlistURL.path.hasPrefix(bundleResolvedPrefix) else {
                let plistRel = bundleRelativePath(of: candidatePlistURL, in: rootBundleURL)
                if !escapingSymlinks.contains(plistRel) {
                    escapingSymlinks.append(plistRel)
                }
                break
            }
            if let pData = try? readBoundedRegularFileDirectNoFollow(at: resolvedPlistURL, maxBytes: 8 * 1024 * 1024),
               let parsed = (try? PropertyListSerialization.propertyList(from: pData, options: [], format: nil)) as? [String: Any] {
                plugPlistData = pData
                pDict = parsed
            }
            break
        }

        let fallbackExecName = appexURL.deletingPathExtension().lastPathComponent
        let extKind = appexURL.pathExtension.lowercased().isEmpty ? "appex" : appexURL.pathExtension.lowercased()
        let rawPlugPlistBid = (pDict?["CFBundleIdentifier"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasExplicitPlugPlistBid = (rawPlugPlistBid != nil && !rawPlugPlistBid!.isEmpty)
        let plugBundleId = (hasExplicitPlugPlistBid ? rawPlugPlistBid! : nil) ?? "\(parentBundleId).\(extKind)"
        let plugName = pDict?["CFBundleDisplayName"] as? String ?? pDict?["CFBundleName"] as? String ?? fallbackExecName
        let plugBgModes = extractFlexibleStringList(pDict?["UIBackgroundModes"])

        var plugGroups: [String] = []
        var plugEntitlementsDict: [String: Any] = [:]
        var plugDistinctEntBundleIds: [String] = []
        var plugLinkedDylibs: Set<String> = []
        var plugUnencryptedSymbols: Set<String> = []
        var plugHasUnencryptedBinary = false
        var plugPrimaryFairPlayClean = false
        var plugAggregateSigTrust: CodeSignatureTrustDisposition = .appleAppStoreVerified
        var plugSawAnyBinary = false
        var plugAnyMissingCS = false
        var fallbackCryptid: UInt32 = 0
        var scannedPrimaryCanonical: String? = nil
        var scannedPrimaryResolved: String? = nil
        var effectiveExtChannel: InstallChannel = installChannel
        var appexProvisionInspect = ChannelClassifier.classifyBundle(at: resolvedAppexURL, cryptid: 1)
        if hasArchiveMobileProvision && appexProvisionInspect.channel == .appStore {
            appexProvisionInspect = ChannelClassifier.classify(
                cryptid: 1,
                mobileprovisionData: nil,
                hasMobileProvisionArtifact: true
            )
        }
        if effectiveExtChannel == .appStore && appexProvisionInspect.channel != .appStore {
            effectiveExtChannel = appexProvisionInspect.channel
        }

        if let validDict = pDict {
            do {
                let effectiveExtRoot = (!FileManager.default.fileExists(atPath: flatPlugPlistURL.path)
                    && FileManager.default.fileExists(atPath: resolvedAppexURL.appendingPathComponent("Contents/MacOS").path))
                    ? resolvedAppexURL.appendingPathComponent("Contents/MacOS")
                    : resolvedAppexURL
                let (_, plugBinURL) = try resolveSafeBundleExecutableURL(
                    infoDict: validDict,
                    bundleURL: effectiveExtRoot,
                    fallbackName: fallbackExecName
                )
                let plugReadURL = plugBinURL.resolvingSymlinksInPath().standardizedFileURL
                scannedPrimaryCanonical = plugBinURL.standardizedFileURL.path
                scannedPrimaryResolved = plugReadURL.path
                let relPath: String
                if resolvedAppexURL.path != appexURL.standardizedFileURL.path {
                    let innerRel = bundleRelativePath(of: plugBinURL, in: resolvedAppexURL)
                    relPath = "\(appexRelPath)/\(innerRel)"
                } else {
                    relPath = bundleRelativePath(of: plugBinURL, in: rootBundleURL)
                }

                if let binData = try? readBoundedRegularFileDirectNoFollow(at: plugReadURL),
                   let plugSlices = try? MachOParser.shared.parseAllSlices(data: binData),
                   !plugSlices.isEmpty {
                    let plugDetails = machoScanner.parseMachO(
                        files: plugSlices,
                        rawData: binData,
                        expectedContainerSliceCount: plugSlices.first?.slicesInContainer.count
                    )
                    fallbackCryptid = plugDetails.cryptid
                    plugPrimaryFairPlayClean = plugDetails.isFairPlayEncrypted && !plugDetails.hasUnencryptedSegments
                    var plugSigTrust = CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: plugSlices)
                    if let bindFailure = CSBlobParser.shared.verifyBundleInfoPlistBinding(
                        fromSlices: plugSlices,
                        infoPlistData: plugPlistData,
                        plistBundleId: hasExplicitPlugPlistBid ? plugBundleId : nil
                    ) {
                        plugSigTrust = bindFailure
                    } else if let crFailure = CSBlobParser.shared.verifyBundleCodeResourcesSeal(
                        fromSlices: plugSlices,
                        bundleURL: resolvedAppexURL
                    ) {
                        plugSigTrust = crFailure
                    }
                    let plugHasMissingCS = CSBlobParser.hasMissingCodeSignature(inSlices: plugSlices)
                    plugSawAnyBinary = true
                    if plugHasMissingCS {
                        plugAnyMissingCS = true
                        bundleHasMissingCodeSignature = true
                    }
                    if plugSigTrust != .appleAppStoreVerified {
                        plugAggregateSigTrust = plugSigTrust
                        if bundleCodeSignatureTrust == .appleAppStoreVerified || plugSigTrust.isDisqualifiedFromAppStore {
                            bundleCodeSignatureTrust = plugSigTrust
                        }
                    }
                    if effectiveExtChannel == .appStore && plugSigTrust.isDisqualifiedFromAppStore {
                        effectiveExtChannel = .developerSideloaded
                    }
                    let plugIdRes = resolveDistinctEntitlementIdentities(
                        fromSlices: plugSlices,
                        explicitTeamId: teamId ?? appexProvisionInspect.teamIdentifier
                    )
                    plugDistinctEntBundleIds = plugIdRes.distinctBundleIds
                    for s in MachOParser.selectAuditSlices(from: plugSlices) {
                        let (_, sg) = CSBlobParser.shared.extractAppGroups(fromSlice: s)
                        for g in sg where !plugGroups.contains(g) { plugGroups.append(g) }
                        let sEnts = CSBlobParser.shared.parseMergedEntitlements(fromSlice: s)
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
                        teamId: teamId ?? appexProvisionInspect.teamIdentifier,
                        bundlePath: appexURL.path,
                        executablePath: plugBinURL.path,
                        installChannel: effectiveExtChannel,
                        appGroups: plugGating.appGroups,
                        disqualifyAppStoreExemption: plugDetails.cryptid != 0 && (plugHasMissingCS || plugSigTrust != .appleAppStoreVerified)
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
                    if !plugDetails.isFairPlayEncrypted || plugDetails.hasUnencryptedSegments || plugSigTrust.isDisqualifiedFromAppStore || plugHasMissingCS {
                        hasUnencryptedBinary = true
                        plugHasUnencryptedBinary = true
                        unencryptedSymbols.formUnion(plugDetails.symbols)
                        plugUnencryptedSymbols.formUnion(plugDetails.symbols)
                        unencryptedTextStrings.formUnion(plugDetails.textStrings)
                    } else if plugSigTrust != .appleAppStoreVerified {
                        unencryptedSymbols.formUnion(plugDetails.symbols)
                        plugUnencryptedSymbols.formUnion(plugDetails.symbols)
                    }
                    if plugFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
                    if plugFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
                } else {
                    // Record corrupt primary executable indicator AND continue scanning sibling dylibs/symlinks inside this .appex
                    let corruptInd = makeCorruptMachOIndicator(relPath: relPath)
                    allIndicators.append(corruptInd)
                    allMatchedSymbols.insert(corruptInd.signature)
                }
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
            in: resolvedAppexURL,
            bundleRootResolvedPrefix: bundleResolvedPrefix,
            escapingSymlinks: &escapingSymlinks,
            bundleRootURL: rootBundleURL
        )
        for candidate in extCandidates {
            let subURL = candidate.logicalURL
            let subReadURL = candidate.readURL
            let subCanonical = subURL.standardizedFileURL.path
            if subCanonical == scannedPrimaryCanonical
                || subCanonical == scannedPrimaryResolved
                || subReadURL.path == scannedPrimaryResolved
                || strictChildExtensionPrefixes.contains(where: { subCanonical.hasPrefix($0) || subReadURL.path.hasPrefix($0) }) {
                continue
            }
            let subIsDylib = subURL.pathExtension.lowercased() == "dylib"
            let subIsExpectedRole = isExpectedEmbeddedBinaryRole(
                itemURL: subURL,
                bundleRootResolvedPrefix: bundleResolvedPrefix
            )
            let (prefix, subFileSize) = readMachOHeaderPrefix(of: subReadURL)
            let subHasMagic = isMachOOrFatMagic(prefix, fileSize: subFileSize)
            guard subIsExpectedRole || subHasMagic else { continue }

            let subRel: String
            if resolvedAppexURL.path != appexURL.standardizedFileURL.path {
                let innerRel = bundleRelativePath(of: subURL, in: resolvedAppexURL)
                subRel = "\(appexRelPath)/\(innerRel)"
            } else {
                subRel = bundleRelativePath(of: subURL, in: rootBundleURL)
            }
            if subIsDylib {
                allLinkedDylibs.insert("@executable_path/\(subRel)")
                plugLinkedDylibs.insert("@executable_path/\(subRel)")
            }

            guard let subData = try? readBoundedRegularFileDirectNoFollow(at: subReadURL),
                  let subSlices = try? MachOParser.shared.parseAllSlices(data: subData),
                  !subSlices.isEmpty else {
                let corruptInd = makeCorruptMachOIndicator(relPath: subRel)
                allIndicators.append(corruptInd)
                allMatchedSymbols.insert(corruptInd.signature)
                continue
            }

            var subGroups = plugGating.appGroups
            for s in MachOParser.selectAuditSlices(from: subSlices) {
                let (_, sg) = CSBlobParser.shared.extractAppGroups(fromSlice: s)
                for g in sg where !subGroups.contains(g) { subGroups.append(g) }
                for g in sg where !combinedAppGroups.contains(g) { combinedAppGroups.append(g) }
                let sEnts = CSBlobParser.shared.parseMergedEntitlements(fromSlice: s)
                plugEntitlementsDict = CSBlobParser.mergeEntitlementDictionaries(plugEntitlementsDict, sEnts)
                entitlementsDict = CSBlobParser.mergeEntitlementDictionaries(entitlementsDict, sEnts)
            }
            let subSigTrust = CSBlobParser.shared.inspectCodeSignatureTrust(fromSlices: subSlices)
            let subHasMissingCS = CSBlobParser.hasMissingCodeSignature(inSlices: subSlices)
            plugSawAnyBinary = true
            if subHasMissingCS {
                plugAnyMissingCS = true
                bundleHasMissingCodeSignature = true
            }
            if subSigTrust != .appleAppStoreVerified {
                if plugAggregateSigTrust == .appleAppStoreVerified || subSigTrust.isDisqualifiedFromAppStore {
                    plugAggregateSigTrust = subSigTrust
                }
                if bundleCodeSignatureTrust == .appleAppStoreVerified || subSigTrust.isDisqualifiedFromAppStore {
                    bundleCodeSignatureTrust = subSigTrust
                }
            }
            if effectiveExtChannel == .appStore && subSigTrust.isDisqualifiedFromAppStore {
                effectiveExtChannel = .developerSideloaded
            }
            let subDetails = machoScanner.parseMachO(
                files: subSlices,
                rawData: subData,
                expectedContainerSliceCount: subSlices.first?.slicesInContainer.count
            )
            let subContext = MachOScanner.ScanContext(
                bundleId: plugBundleId,
                displayName: plugName,
                version: version,
                teamId: teamId ?? appexProvisionInspect.teamIdentifier,
                bundlePath: appexURL.path,
                executablePath: subURL.path,
                installChannel: effectiveExtChannel,
                appGroups: subGroups,
                disqualifyAppStoreExemption: subDetails.cryptid != 0 && (subHasMissingCS || subSigTrust != .appleAppStoreVerified)
            )
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
            if !subDetails.isFairPlayEncrypted || subDetails.hasUnencryptedSegments || subSigTrust.isDisqualifiedFromAppStore || subHasMissingCS {
                hasUnencryptedBinary = true
                plugHasUnencryptedBinary = true
                unencryptedSymbols.formUnion(subDetails.symbols)
                plugUnencryptedSymbols.formUnion(subDetails.symbols)
                unencryptedTextStrings.formUnion(subDetails.textStrings)
            } else if subSigTrust != .appleAppStoreVerified {
                unencryptedSymbols.formUnion(subDetails.symbols)
                plugUnencryptedSymbols.formUnion(subDetails.symbols)
            }
            if subFinding.evidence.dynamicLoadingPresent { dynamicLoadingFound = true }
            if subFinding.evidence.pathEnumerationPresent { pathEnumerationFound = true }
        }

        if let validDict = pDict {
            let effectivePlugTrust = plugSawAnyBinary ? plugAggregateSigTrust : bundleCodeSignatureTrust
            let isPlugVerifiedAppStore = (effectivePlugTrust == .appleAppStoreVerified
                && !plugAnyMissingCS
                && plugPrimaryFairPlayClean)

            // Evaluate background clipboard snooping across ALL symbols inside this embedded extension/AppClip (primary + sibling Frameworks/*)
            if (plugHasUnencryptedBinary || !isPlugVerifiedAppStore),
               let extClip = ExpandedThreatCatalog.evaluateClipboardSnooping(
                   backgroundModes: plugBgModes,
                   symbols: Array(plugUnencryptedSymbols),
                   cryptid: 0
               ) {
                let annotatedClip = ThreatIndicator(
                    signature: extClip.signature,
                    description: "\(extClip.description) [\(appexRelPath)]",
                    category: extClip.category,
                    location: "\(appexRelPath): \(extClip.location)",
                    severity: extClip.severity
                )
                allIndicators.append(annotatedClip)
                allMatchedSymbols.insert(annotatedClip.signature)
            }

            // Evaluate wallet/messenger brand impersonation on embedded `.appex`, `.xpc`, and nested `AppClips/*.app` / `Watch/*.app`
            if !isPlugVerifiedAppStore {
                let impChannel: InstallChannel = (effectiveExtChannel == .appStore || effectiveExtChannel == .testFlight)
                    ? .developerSideloaded
                    : effectiveExtChannel
                var candidatePlugBids: [String] = []
                if hasExplicitPlugPlistBid {
                    candidatePlugBids.append(plugBundleId)
                }
                for entBid in plugDistinctEntBundleIds where !candidatePlugBids.contains(where: { $0.caseInsensitiveCompare(entBid) == .orderedSame }) {
                    candidatePlugBids.append(entBid)
                }
                if candidatePlugBids.isEmpty {
                    candidatePlugBids.append("")
                }
                var seenImpSigs: Set<String> = []
                for candBid in candidatePlugBids {
                    let impInds = ExpandedThreatCatalog.evaluateImpersonation(
                        bundleId: candBid.isEmpty ? nil : candBid,
                        displayName: (validDict["CFBundleDisplayName"] as? String) ?? (validDict["CFBundleName"] as? String),
                        installChannel: impChannel,
                        cryptid: 0
                    )
                    for imp in impInds where seenImpSigs.insert(imp.signature).inserted {
                        let annotatedImp = ThreatIndicator(
                            signature: imp.signature,
                            description: "\(imp.description) [\(appexRelPath)]",
                            category: imp.category,
                            location: "\(appexRelPath): \(imp.location)",
                            severity: imp.severity
                        )
                        allIndicators.append(annotatedImp)
                        allMatchedSymbols.insert(annotatedImp.signature)
                    }
                }
            }

            let primaryRel: String
            if let prim = scannedPrimaryCanonical {
                if resolvedAppexURL.path != appexURL.standardizedFileURL.path {
                    let innerRel = bundleRelativePath(of: URL(fileURLWithPath: prim), in: resolvedAppexURL)
                    primaryRel = "\(appexRelPath)/\(innerRel)"
                } else {
                    primaryRel = bundleRelativePath(of: URL(fileURLWithPath: prim), in: rootBundleURL)
                }
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
                installChannel: effectiveExtChannel,
                codeSignatureTrust: effectivePlugTrust,
                hasMissingCodeSignature: plugAnyMissingCS,
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
        codeSignatureTrust: CodeSignatureTrustDisposition = .appleAppStoreVerified,
        hasMissingCodeSignature: Bool = false,
        relPath: String,
        allIndicators: inout [ThreatIndicator],
        allMatchedSymbols: inout Set<String>
    ) {
        let effectiveChannel: InstallChannel = ((hasUnencryptedBinary || hasMissingCodeSignature) && installChannel == .appStore)
            ? .developerSideloaded
            : installChannel
        let appexAccessoryInds = ExpandedThreatCatalog.evaluateAccessorySetupBypass(
            linkedDylibs: Array(linkedDylibs),
            symbols: Array(unencryptedSymbols),
            infoPlist: infoPlist,
            entitlements: entitlements,
            installChannel: effectiveChannel,
            cryptid: (hasUnencryptedBinary || hasMissingCodeSignature) ? 0 : fallbackCryptid,
            codeSignatureTrust: codeSignatureTrust,
            hasMissingCodeSignature: hasMissingCodeSignature
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
        mainHasUnencryptedSegments: Bool = false,
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
        codeSignatureTrust: CodeSignatureTrustDisposition = .absentOrSynthetic,
        hasMissingCodeSignature: Bool = false,
        appHasMissingCodeSignature: Bool = false,
        allIndicators: inout [ThreatIndicator],
        allMatchedSymbols: inout Set<String>
    ) {
        let unverifiedAppStoreSig = (codeSignatureTrust != .appleAppStoreVerified || hasMissingCodeSignature)
        let isVerifiedAppStore = !unverifiedAppStoreSig && mainIsFairPlayEncrypted && !mainHasUnencryptedSegments
        let effectiveDangerousEntChannel: InstallChannel = (!isVerifiedAppStore && installChannel == .appStore)
            ? .developerSideloaded
            : installChannel

        var expandedIndicators: [ThreatIndicator] = []
        expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateDangerousEntitlements(
            bundleId: bundleId,
            installChannel: effectiveDangerousEntChannel,
            entitlements: entitlementsDict,
            hasUnencryptedBinary: hasUnencryptedBinary || !isVerifiedAppStore
        ))
        let effectiveImpersonationChannel: InstallChannel = (!isVerifiedAppStore && (installChannel == .appStore || installChannel == .testFlight))
            ? .developerSideloaded
            : installChannel
        let effectiveImpersonationCryptid: UInt32 = (!isVerifiedAppStore || effectiveImpersonationChannel.isSideloadedOrEnterprise)
            ? 0
            : mainCryptid
        expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateImpersonation(
            bundleId: bundleId,
            displayName: displayName,
            installChannel: effectiveImpersonationChannel,
            cryptid: effectiveImpersonationCryptid
        ))

        let dylibList = Array(allLinkedDylibs)
        let symbolList = Array(unencryptedSymbols)
        let textStringList = Array(unencryptedTextStrings)

        // Always evaluate restricted private Photos entitlements (`com.apple.private.photos.*`, `com.apple.photos.bourgeoisie`)
        // even when `cryptid != 0`, and check private Photos frameworks/symbols whenever unencrypted, non-App-Store, or lacking verified App Store CMS.
        expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluatePhotosBypass(
            linkedDylibs: (hasUnencryptedBinary || installChannel != .appStore || unverifiedAppStoreSig) ? dylibList : [],
            symbols: (hasUnencryptedBinary || unverifiedAppStoreSig) ? symbolList : [],
            entitlements: entitlementsDict,
            cryptid: (hasUnencryptedBinary || unverifiedAppStoreSig) ? 0 : mainCryptid
        ))

        if hasUnencryptedBinary || unverifiedAppStoreSig {
            expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateBrotliSupplyChain(
                linkedDylibs: dylibList,
                symbols: symbolList
            ))
            expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateInjectedDylibs(
                linkedDylibs: dylibList
            ))
            if !mainIsFairPlayEncrypted || appHasUnencryptedBinary || unverifiedAppStoreSig,
               let clipboardInd = ExpandedThreatCatalog.evaluateClipboardSnooping(
                   backgroundModes: mainBackgroundModes,
                   symbols: symbolList,
                   cryptid: 0
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
            linkedDylibs: (hasUnencryptedBinary || unverifiedAppStoreSig) ? dylibList : [],
            symbols: (hasUnencryptedBinary || unverifiedAppStoreSig) ? symbolList : [],
            entitlements: entitlementsDict,
            cryptid: (hasUnencryptedBinary || unverifiedAppStoreSig) ? 0 : mainCryptid
        ))
        expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateBookRestoreAndGestalt(
            linkedDylibs: (hasUnencryptedBinary || unverifiedAppStoreSig) ? dylibList : [],
            textStrings: hasUnencryptedBinary ? textStringList : [],
            entitlements: entitlementsDict,
            cryptid: (hasUnencryptedBinary || unverifiedAppStoreSig) ? 0 : mainCryptid
        ))
        let anyMissingCS = appHasMissingCodeSignature || hasMissingCodeSignature
        let effectiveAccessoryChannel: InstallChannel = ((appHasUnencryptedBinary || hasUnencryptedBinary || anyMissingCS) && installChannel == .appStore)
            ? .developerSideloaded
            : installChannel
        let effectiveAccessoryCryptid: UInt32 = (appHasUnencryptedBinary || anyMissingCS || effectiveAccessoryChannel.isSideloadedOrEnterprise)
            ? 0
            : mainCryptid
        expandedIndicators.append(contentsOf: ExpandedThreatCatalog.evaluateAccessorySetupBypass(
            linkedDylibs: (appHasUnencryptedBinary || effectiveAccessoryChannel != .appStore || unverifiedAppStoreSig) ? Array(appLinkedDylibs) : [],
            symbols: (appHasUnencryptedBinary || unverifiedAppStoreSig) ? Array(appUnencryptedSymbols) : [],
            infoPlist: infoDict,
            entitlements: entitlementsDict,
            installChannel: effectiveAccessoryChannel,
            cryptid: effectiveAccessoryCryptid,
            codeSignatureTrust: codeSignatureTrust,
            hasMissingCodeSignature: anyMissingCS
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
