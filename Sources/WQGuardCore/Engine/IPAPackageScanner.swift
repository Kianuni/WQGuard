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
            
            // Zip Slip validation
            if path.contains("..") || path.hasPrefix("/") || path.contains("\\") {
                throw IPAPackageScannerError.zipSlipDetected(path)
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
            
            var decompressed = Data(count: entry.uncompressedSize)
            let status: Int32 = rawCompressed.withUnsafeBytes { inPtr in
                decompressed.withUnsafeMutableBytes { outPtr in
                    strm.next_in = UnsafeMutablePointer(mutating: inPtr.bindMemory(to: Bytef.self).baseAddress)
                    strm.avail_in = uInt(entry.compressedSize)
                    strm.next_out = outPtr.bindMemory(to: Bytef.self).baseAddress
                    strm.avail_out = uInt(entry.uncompressedSize)
                    return inflate(&strm, Z_FINISH)
                }
            }
            
            guard status == Z_STREAM_END || status == Z_OK else {
                throw IPAPackageScannerError.decompressionFailed(status)
            }
            if Int(strm.total_out) < decompressed.count {
                decompressed.count = Int(strm.total_out)
            }
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
        
        // Extract required security auditing files preserving relative path
        for entry in entries where entry.path.hasPrefix(appBundlePrefix) {
            let relativePath = String(entry.path.dropFirst(appBundlePrefix.count))
            if relativePath.isEmpty { continue }
            
            let destURL = bundleURL.appendingPathComponent(relativePath)
            let destCanonical = destURL.standardizedFileURL.path
            guard destCanonical.hasPrefix(sandboxCanonicalPath + "/") || destCanonical == sandboxCanonicalPath else {
                throw IPAPackageScannerError.zipSlipDetected(entry.path)
            }
            
            if entry.isDirectory {
                try FileManager.default.createDirectory(at: destURL, withIntermediateDirectories: true)
            } else {
                // Filter: Skip bulky UI/media/localization assets while preserving all Mach-O executables (even if executable name contains dots), dylibs, plists, mobileprovision, and receipts
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
        
        return try withTemporarySandbox(ipaURL: ipaURL) { (bundleURL, entries) in
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
            let mainMachO = try MachOParser.shared.parse(data: mainExecData)
            let mainDetails = MachOScanner.shared.parseMachO(file: mainMachO, rawData: mainExecData)
            
            // 2. Layer 1: Install Channel & Entitlement Gating
            let channelResult = ChannelClassifier.classifyBundle(at: bundleURL, cryptid: mainDetails.cryptid)
            let (hasGroups, appGroups) = CSBlobParser.shared.extractAppGroups(from: mainMachO.codeSignatureData)
            let gating = EntitlementGating.evaluate(hasAppGroups: hasGroups, appGroups: appGroups)
            let backgroundModes = infoDict["UIBackgroundModes"] as? [String] ?? []
            var entitlementsDict: [String: Any] = [:]
            if let csData = mainMachO.codeSignatureData,
               let parsed = try? CSBlobParser.shared.parseSuperBlob(csData),
               let rawXml = parsed.rawXML,
               let dict = try? CSBlobParser.shared.parseXMLPlist(Data(rawXml.utf8)) {
                entitlementsDict = dict
            }
            
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
            
            // 4. Scan Embedded Frameworks & Dynamic Libraries
            let frameworksURL = bundleURL.appendingPathComponent("Frameworks")
            if FileManager.default.fileExists(atPath: frameworksURL.path) {
                let fwEnumerator = FileManager.default.enumerator(at: frameworksURL, includingPropertiesForKeys: [.isRegularFileKey])
                while let itemURL = fwEnumerator?.nextObject() as? URL {
                    let isDylib = itemURL.pathExtension.lowercased() == "dylib"
                    let isFrameworkBinary = itemURL.deletingLastPathComponent().pathExtension.lowercased() == "framework" && itemURL.pathExtension.isEmpty
                    
                    if isDylib || isFrameworkBinary {
                        if let dylibData = try? Data(contentsOf: itemURL, options: .mappedIfSafe),
                           let fwMachO = try? MachOParser.shared.parse(data: dylibData) {
                            let fwDetails = MachOScanner.shared.parseMachO(file: fwMachO, rawData: dylibData)
                            let fwFinding = MachOScanner.shared.scan(details: fwDetails, context: scanContext)
                            
                            // Prefix indicator locations with framework subpath
                            let relPath = itemURL.path.replacingOccurrences(of: bundleURL.path + "/", with: "")
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
            
            // 5. Scan Embedded App Extensions (PlugIns)
            let pluginsURL = bundleURL.appendingPathComponent("PlugIns")
            if FileManager.default.fileExists(atPath: pluginsURL.path) {
                let plugEnumerator = FileManager.default.enumerator(at: pluginsURL, includingPropertiesForKeys: [.isDirectoryKey])
                while let itemURL = plugEnumerator?.nextObject() as? URL {
                    if itemURL.pathExtension.lowercased() == "appex" {
                        let plugInfoPlistURL = itemURL.appendingPathComponent("Info.plist")
                        if let pData = try? Data(contentsOf: plugInfoPlistURL),
                           let pDict = (try? PropertyListSerialization.propertyList(from: pData, options: [], format: nil)) as? [String: Any],
                           let plugExec = pDict["CFBundleExecutable"] as? String {
                            let plugBinURL = itemURL.appendingPathComponent(plugExec)
                            if let binData = try? Data(contentsOf: plugBinURL, options: .mappedIfSafe),
                               let plugMachO = try? MachOParser.shared.parse(data: binData) {
                                let plugDetails = MachOScanner.shared.parseMachO(file: plugMachO, rawData: binData)
                                let plugFinding = MachOScanner.shared.scan(details: plugDetails, context: scanContext)
                                
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
                    appGroups: gating.appGroups,
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
                hasAppGroups: !gating.appGroups.isEmpty,
                appGroups: gating.appGroups,
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
