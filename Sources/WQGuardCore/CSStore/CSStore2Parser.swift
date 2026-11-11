//
//  CSStore2Parser.swift
//  WQGuardCore
//
//  Production-grade, memory-safe parser for Apple LaunchServices CSStore2 ("bdsl") database.
//  Supports iOS 26 (0x23c), iOS 27.0 (0x250), iOS 27.2+ (0x25c) unit tables,
//  Unicode sanitization, container UUID mapping, and localized app name resolution.
//

import Foundation

/// Snapshot representing parsed LaunchServices application, plugin, and App Group mappings.
public struct CSStoreSnapshot: Sendable, Equatable {
    public let storePath: String?
    public let layoutLabel: String
    public let appContainers: [String: String]      // "/var/mobile/Containers/Data/Application/<UUID>" -> bundleID
    public let pluginContainers: [String: String]   // "/var/mobile/Containers/Data/PluginKitPlugin/<UUID>" -> bundleID
    public let appGroups: [String]                  // "/var/mobile/Containers/Shared/AppGroup/<UUID>"
    public let displayNames: [String: String]       // bundleID -> displayName
    public let bundleNames: [String: String]        // bundleID -> bundleName
    public let loadedAt: Date

    public init(
        storePath: String? = nil,
        layoutLabel: String,
        appContainers: [String: String],
        pluginContainers: [String: String],
        appGroups: [String],
        displayNames: [String: String],
        bundleNames: [String: String],
        loadedAt: Date = Date()
    ) {
        self.storePath = storePath
        self.layoutLabel = layoutLabel
        self.appContainers = appContainers
        self.pluginContainers = pluginContainers
        self.appGroups = appGroups
        self.displayNames = displayNames
        self.bundleNames = bundleNames
        self.loadedAt = loadedAt
    }
}

/// Layout specification for a LaunchServices CSStore2 database schema version.
public struct CSLayoutSpec: Sendable, Equatable {
    public let label: String
    public let bundleSize: UInt32
    public let bundleIDOffset: UInt32
    public let containerOffset: UInt32
    public let nameOffset: UInt32
    public let displayNameOffset: UInt32
    public let pluginSize: UInt32
    public let pluginBundleIDOffset: UInt32
    public let pluginContainerOffset: UInt32

    public init(
        label: String,
        bundleSize: UInt32,
        bundleIDOffset: UInt32,
        containerOffset: UInt32,
        nameOffset: UInt32,
        displayNameOffset: UInt32,
        pluginSize: UInt32,
        pluginBundleIDOffset: UInt32,
        pluginContainerOffset: UInt32
    ) {
        self.label = label
        self.bundleSize = bundleSize
        self.bundleIDOffset = bundleIDOffset
        self.containerOffset = containerOffset
        self.nameOffset = nameOffset
        self.displayNameOffset = displayNameOffset
        self.pluginSize = pluginSize
        self.pluginBundleIDOffset = pluginBundleIDOffset
        self.pluginContainerOffset = pluginContainerOffset
    }
}

public enum CSStore2ParserError: Error, Sendable, Equatable, CustomStringConvertible {
    case dataTooSmall(size: Int, minRequired: Int)
    case dataTooLarge(size: Int, maxAllowed: Int)
    case invalidMagic(found: String)
    case memoryAllocationFailed
    case noValidLayoutMatched
    case fileReadFailed(String)

    public var description: String {
        switch self {
        case .dataTooSmall(let size, let min):
            return "CSStore data size (\(size) bytes) is below minimum valid size (\(min) bytes)."
        case .dataTooLarge(let size, let max):
            return "CSStore data size (\(size) bytes) exceeds safe maximum limit (\(max) bytes)."
        case .invalidMagic(let found):
            return "CSStore magic header mismatch: expected 'bdsl', found '\(found)'."
        case .memoryAllocationFailed:
            return "Failed to allocate memory for string ID index bitmap."
        case .noValidLayoutMatched:
            return "No supported CSStore2 layout matched database structure (0x23c, 0x250, 0x25c)."
        case .fileReadFailed(let reason):
            return "Failed to read CSStore file: \(reason)"
        }
    }
}

/// 100% read-only parser for Apple LaunchServices CSStore2 databases.
public final class CSStore2Parser: Sendable {
    public static let shared = CSStore2Parser()

    public static let minStoreBytes: Int = 0x1000            // 4 KB
    public static let maxStoreBytes: Int = 64 * 1024 * 1024  // 64 MB
    public static let maxStringID: UInt32 = 0x01000000       // 16M IDs max
    public static let maxBundleRecords: Int = 100_000
    public static let maxDecodedStrings: Int = 200_000
    public static let maxDecodedStringBytes: Int = 8 * 1024 * 1024

    /// Supported CSStore2 layout specifications covering iOS 26, 27.0, and 27.2+.
    public static let supportedLayouts: [CSLayoutSpec] = [
        CSLayoutSpec(label: "27.0",  bundleSize: 0x250, bundleIDOffset: 0x0c, containerOffset: 0x68, nameOffset: 0x6c, displayNameOffset: 0x74, pluginSize: 0x118, pluginBundleIDOffset: 0x00, pluginContainerOffset: 0x54),
        CSLayoutSpec(label: "26",    bundleSize: 0x23c, bundleIDOffset: 0x0c, containerOffset: 0x64, nameOffset: 0x68, displayNameOffset: 0x70, pluginSize: 0x104, pluginBundleIDOffset: 0x00, pluginContainerOffset: 0x50),
        CSLayoutSpec(label: "27.2",  bundleSize: 0x25c, bundleIDOffset: 0x0c, containerOffset: 0x6c, nameOffset: 0x70, displayNameOffset: 0x78, pluginSize: 0x120, pluginBundleIDOffset: 0x00, pluginContainerOffset: 0x58),
        CSLayoutSpec(label: "27.2b", bundleSize: 0x25c, bundleIDOffset: 0x10, containerOffset: 0x6c, nameOffset: 0x70, displayNameOffset: 0x78, pluginSize: 0x120, pluginBundleIDOffset: 0x04, pluginContainerOffset: 0x58),
        CSLayoutSpec(label: "27.2c", bundleSize: 0x25c, bundleIDOffset: 0x0c, containerOffset: 0x6c, nameOffset: 0x70, displayNameOffset: 0x78, pluginSize: 0x120, pluginBundleIDOffset: 0x04, pluginContainerOffset: 0x58),
        CSLayoutSpec(label: "27.2d", bundleSize: 0x25c, bundleIDOffset: 0x10, containerOffset: 0x6c, nameOffset: 0x70, displayNameOffset: 0x78, pluginSize: 0x120, pluginBundleIDOffset: 0x00, pluginContainerOffset: 0x58),
    ]

    /// Built-in localized Chinese display names for system and popular third-party applications.
    public static let builtInChineseNames: [String: String] = [
        "com.apple.AppStore": "App Store",
        "com.apple.mobilesafari": "Safari 浏览器",
        "com.apple.weather": "天气",
        "com.apple.news": "Apple News",
        "com.apple.stocks": "股市",
        "com.apple.mobilemail": "邮件",
        "com.apple.MobileSMS": "信息",
        "com.apple.mobilephone": "电话",
        "com.apple.mobileslideshow": "照片",
        "com.apple.Photos": "照片",
        "com.apple.camera": "相机",
        "com.apple.mobilecal": "日历",
        "com.apple.mobilenotes": "备忘录",
        "com.apple.reminders": "提醒事项",
        "com.apple.Maps": "地图",
        "com.apple.Music": "Apple 音乐",
        "com.apple.tv": "Apple TV",
        "com.apple.podcasts": "播客",
        "com.apple.iBooks": "图书",
        "com.apple.Health": "健康",
        "com.apple.Passbook": "钱包",
        "com.apple.Preferences": "设置",
        "com.apple.mobiletimer": "时钟",
        "com.apple.calculator": "计算器",
        "com.apple.compass": "指南针",
        "com.apple.VoiceMemos": "语音备忘录",
        "com.apple.facetime": "FaceTime 通话",
        "com.apple.MobileAddressBook": "通讯录",
        "com.apple.DocumentsApp": "文件",
        "com.apple.findmy": "查找",
        "com.apple.Home": "家庭",
        "com.apple.shortcuts": "快捷指令",
        "com.apple.Translate": "翻译",
        "com.apple.Fitness": "健身",
        "com.apple.Bridge": "Watch",
        "com.apple.freeform": "无边记",
        "com.apple.journal": "手记",
        "com.apple.Passwords": "密码",
        "com.apple.measure": "测距仪",
        "com.apple.tips": "提示",
        "com.apple.siri": "Siri",
        "com.tencent.xin": "微信",
        "com.tencent.mqq": "QQ",
        "com.ss.iphone.ugc.Aweme": "抖音",
        "tv.danmaku.bilianime": "哔哩哔哩",
        "com.xingin.discover": "小红书",
        "com.taobao.taobao4iphone": "淘宝",
        "com.alipay.iphoneclient": "支付宝",
        "com.jingdong.app.mall": "京东",
        "com.meituan.imeituan": "美团",
        "com.netease.cloudmusic": "网易云音乐",
        "com.tencent.QQMusic": "QQ音乐",
        "com.zhihu.ios": "知乎",
        "com.sina.weibo": "微博",
        "com.autonavi.amap": "高德地图",
        "org.telegram.Telegram-iOS": "Telegram",
        "com.openai.chat": "ChatGPT",
        "com.NSSurge.inc.surge-ios": "Surge",
        "com.nssurge.inc.surge-ios": "Surge",
        "com.luo.quantumult-x": "Quantumult X",
        "com.liguangming.Shadowrocket": "Shadowrocket",
        "com.loon.loon": "Loon",
        "ws.stash.app": "Stash"
    ]

    public init() {}

    /// Parses CSStore2 data directly from a file URL.
    public func parse(at fileURL: URL) throws -> CSStoreSnapshot {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            throw CSStore2ParserError.fileReadFailed("File not found at \(fileURL.path)")
        }
        let data = try Data(contentsOf: fileURL, options: .mappedIfSafe)
        return try parse(data: data, storePath: fileURL.path)
    }

    /// Parses CSStore2 data directly from memory.
    public func parse(data: Data, storePath: String? = nil) throws -> CSStoreSnapshot {
        guard data.count >= Self.minStoreBytes else {
            throw CSStore2ParserError.dataTooSmall(size: data.count, minRequired: Self.minStoreBytes)
        }
        guard data.count <= Self.maxStoreBytes else {
            throw CSStore2ParserError.dataTooLarge(size: data.count, maxAllowed: Self.maxStoreBytes)
        }

        // Check magic bytes "bdsl" (0x62 0x64 0x73 0x6c)
        let magicData = data.prefix(4)
        guard magicData.elementsEqual([0x62, 0x64, 0x73, 0x6c]) else {
            let found = String(decoding: magicData, as: UTF8.self)
            throw CSStore2ParserError.invalidMagic(found: found)
        }

        // Find string heap anchor ("<string>")
        let heapMarker = Data([0x3c, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3e])
        let heapOffset = data.range(of: heapMarker)?.lowerBound ?? 0

        let bitsetBytes = Int(Self.maxStringID / 8)
        var need = [UInt8](repeating: 0, count: bitsetBytes)
        var inHeap = [UInt8](repeating: 0, count: bitsetBytes)

        let layouts = Self.supportedLayouts
        var layoutRecs = [[UInt32]](repeating: [], count: layouts.count)
        var layoutPlugins = [[UInt32]](repeating: [], count: layouts.count)

        // Read unit records across all layouts
        let totalCount = data.count
        data.withUnsafeBytes { rawBuffer in
            let bytes = rawBuffer.bindMemory(to: UInt8.self).baseAddress!
            let maxRecordSize = 0x25c

            var o = 0
            while o + 8 + maxRecordSize <= totalCount {
                let size = readUInt32(from: bytes + o + 4)
                let u = bytes + o + 8

                for (lIdx, layout) in layouts.enumerated() {
                    // Check plugin record
                    if size == layout.pluginSize {
                        let p0 = readUInt32(from: u + Int(layout.pluginBundleIDOffset))
                        let p1 = readUInt32(from: u + Int(layout.pluginContainerOffset))
                        if p0 != 0 && (p0 & 3) == 0 && (p0 >> 2) < Self.maxStringID &&
                           p1 != 0 && (p1 & 3) == 0 && (p1 >> 2) < Self.maxStringID &&
                           layoutPlugins[lIdx].count / 2 < Self.maxBundleRecords {
                            layoutPlugins[lIdx].append(p0)
                            layoutPlugins[lIdx].append(p1)
                            let sid0 = Int(p0 >> 2)
                            let sid1 = Int(p1 >> 2)
                            need[sid0 / 8] |= UInt8(1 << (sid0 % 8))
                            need[sid1 / 8] |= UInt8(1 << (sid1 % 8))
                        }
                    }

                    // Check bundle record
                    if size == layout.bundleSize {
                        if layoutRecs[lIdx].count / 4 < Self.maxBundleRecords {
                            let bid = readUInt32(from: u + Int(layout.bundleIDOffset))
                            let name = readUInt32(from: u + Int(layout.nameOffset))
                            let disp = readUInt32(from: u + Int(layout.displayNameOffset))
                            let cont = readUInt32(from: u + Int(layout.containerOffset))

                            if bid != 0 && (bid & 3) == 0 && (bid >> 2) < Self.maxStringID {
                                layoutRecs[lIdx].append(contentsOf: [bid, name, disp, cont])
                                for r in [bid, name, disp, cont] {
                                    if r != 0 && (r & 3) == 0 && (r >> 2) < Self.maxStringID {
                                        let sid = Int(r >> 2)
                                        need[sid / 8] |= UInt8(1 << (sid % 8))
                                    }
                                }
                            }
                        }
                    }
                }
                o += 4
            }
        }

        // Decode string table
        var strings: [UInt32: String] = [:]
        var pathStrings: [UInt32: String?] = [:]
        var decodedStringBytes = 0

        data.withUnsafeBytes { rawBuffer in
            let bytes = rawBuffer.bindMemory(to: UInt8.self).baseAddress!
            var o = 0
            while o <= totalCount - 8 {
                let sid = readUInt32(from: bytes + o)
                if sid != 0 && sid < Self.maxStringID {
                    let sidInt = Int(sid)
                    if (need[sidInt / 8] & UInt8(1 << (sidInt % 8))) != 0 {
                        let isHereInHeap = o >= heapOffset
                        let hasExisting = strings[sid] != nil
                        let keepGeneral = !hasExisting || (isHereInHeap && (inHeap[sidInt / 8] & UInt8(1 << (sidInt % 8))) == 0)

                        let peekLen = (o + 8 <= totalCount) ? readUInt32(from: bytes + o + 4) : 0
                        let maybePath = peekLen >= 6 && peekLen < 0x400 && o + 8 < totalCount && bytes[o + 8] == 0x2f // '/'

                        if keepGeneral || maybePath {
                            if let s = readString(bytes: bytes, totalLength: totalCount, offset: o) {
                                if maybePath && s.contains("/mobile/Containers/Data/") {
                                    let prev = pathStrings[sid]
                                    if prev == nil {
                                        pathStrings[sid] = s
                                    } else if prev! != s {
                                        pathStrings[sid] = Optional<String>.none // Ambiguous path collision
                                    }
                                }
                                if keepGeneral && (!hasExisting && strings.count < Self.maxDecodedStrings && (decodedStringBytes + s.utf8.count) < Self.maxDecodedStringBytes) {
                                    strings[sid] = s
                                    if !hasExisting { decodedStringBytes += s.utf8.count }
                                    if isHereInHeap { inHeap[sidInt / 8] |= UInt8(1 << (sidInt % 8)) }
                                }
                            }
                        }
                    }
                }
                o += 4
            }
        }

        func pathFor(ref: UInt32) -> String? {
            let sid = ref >> 2
            if let p = pathStrings[sid] {
                return p
            }
            return strings[sid]
        }

        // Score and select best layout
        var bestApps: [String: String]?
        var bestPlugins: [String: String]?
        var bestDisplay: [String: String]?
        var bestBundle: [String: String]?
        var bestLayoutLabel = ""
        var bestTotalMapped = 0

        for (lIdx, layout) in layouts.enumerated() {
            var appMap: [String: String] = [:]
            var pluginMap: [String: String] = [:]
            var dispMap: [String: String] = [:]
            var bnMap: [String: String] = [:]

            let plugins = layoutPlugins[lIdx]
            var pi = 0
            while pi + 1 < plugins.count {
                let bidRef = plugins[pi]
                let contRef = plugins[pi + 1]
                pi += 2

                if let bid = strings[bidRef >> 2], looksLikeBundleID(bid),
                   let rawPath = pathFor(ref: contRef),
                   let varPath = normalizeVarPath(rawPath),
                   isValidUUIDContainer(varPath, prefix: "/var/mobile/Containers/Data/PluginKitPlugin/") {
                    pluginMap[varPath] = bid
                }
            }

            let recs = layoutRecs[lIdx]
            var ri = 0
            while ri + 3 < recs.count {
                let bidRef = recs[ri]
                let nameRef = recs[ri + 1]
                let dispRef = recs[ri + 2]
                let contRef = recs[ri + 3]
                ri += 4

                guard let bid = strings[bidRef >> 2], looksLikeBundleID(bid) else { continue }

                if contRef != 0 && (contRef & 3) == 0 {
                    if let rawPath = pathFor(ref: contRef),
                       let varPath = normalizeVarPath(rawPath),
                       isValidUUIDContainer(varPath, prefix: "/var/mobile/Containers/Data/Application/") {
                        appMap[varPath] = bid
                    }
                }

                if (nameRef & 3) == 0, let rawName = strings[nameRef >> 2], let nm = sanitizeUnicodeName(rawName) {
                    if bnMap[bid] == nil { bnMap[bid] = nm }
                }
                if (dispRef & 3) == 0, let rawDisp = strings[dispRef >> 2], let dn = sanitizeUnicodeName(rawDisp) {
                    if dispMap[bid] == nil { dispMap[bid] = dn }
                }
            }

            let totalMapped = appMap.count + pluginMap.count
            if bestApps == nil || totalMapped > bestTotalMapped || (totalMapped == bestTotalMapped && dispMap.count > (bestDisplay?.count ?? 0)) {
                bestApps = appMap
                bestPlugins = pluginMap
                bestDisplay = dispMap
                bestBundle = bnMap
                bestTotalMapped = totalMapped
                bestLayoutLabel = layout.label
            }
        }

        guard bestTotalMapped > 0, let finalApps = bestApps, let finalPlugins = bestPlugins else {
            throw CSStore2ParserError.noValidLayoutMatched
        }

        // AppGroup UUID scanning
        var appGroupSet: Set<String> = []
        let groupNeedle = Data("/mobile/Containers/Shared/AppGroup/".utf8)
        var searchRange = 0..<data.count
        while let match = data.range(of: groupNeedle, options: [], in: searchRange) {
            let uuidStart = match.upperBound
            let uuidEnd = uuidStart + 36
            if uuidEnd <= data.count {
                let uuidSubdata = data.subdata(in: uuidStart..<uuidEnd)
                if let uuidStr = String(data: uuidSubdata, encoding: .ascii), UUID(uuidString: uuidStr) != nil {
                    appGroupSet.insert("/var/mobile/Containers/Shared/AppGroup/" + uuidStr.uppercased())
                }
            }
            searchRange = uuidStart..<data.count
        }

        return CSStoreSnapshot(
            storePath: storePath,
            layoutLabel: bestLayoutLabel,
            appContainers: finalApps,
            pluginContainers: finalPlugins,
            appGroups: Array(appGroupSet).sorted(),
            displayNames: bestDisplay ?? [:],
            bundleNames: bestBundle ?? [:],
            loadedAt: Date()
        )
    }

    /// Reads string from memory buffer checking length, null-termination, and UTF-8 validity.
    private func readString(bytes: UnsafePointer<UInt8>, totalLength: Int, offset: Int) -> String? {
        guard offset + 8 <= totalLength else { return nil }
        let len = Int(readUInt32(from: bytes + offset + 4))
        guard len > 0, len < 0x800, offset + 8 + len <= totalLength else { return nil }
        if (len % 4) != 0 && bytes[offset + 8 + len] != 0 { return nil }
        // Verify no internal null byte
        for i in 0..<len {
            if bytes[offset + 8 + i] == 0 { return nil }
        }
        let data = Data(bytes: bytes + offset + 8, count: len)
        return String(data: data, encoding: .utf8)
    }

    /// Read little-endian 32-bit unsigned integer.
    @inline(__always)
    private func readUInt32(from ptr: UnsafePointer<UInt8>) -> UInt32 {
        var v: UInt32 = 0
        memcpy(&v, ptr, 4)
        return v
    }

    /// Validates if string follows standard reverse-DNS bundle identifier rules.
    public func looksLikeBundleID(_ s: String) -> Bool {
        guard s.count > 2, s.contains("."), !s.hasPrefix(".") else { return false }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
        return s.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    /// Normalizes path removing `/private/var` symlink prefix and standardizing path separators.
    public func normalizeVarPath(_ raw: String) -> String? {
        guard !raw.isEmpty else { return nil }
        var p = (raw as NSString).standardizingPath
        if p.hasPrefix("/private/var/") {
            p = String(p.dropFirst(8))
        }
        return p
    }

    /// Validates if path matches the expected container prefix followed by a valid 36-character UUID.
    public func isValidUUIDContainer(_ path: String, prefix: String) -> Bool {
        guard path.hasPrefix(prefix), path.count == prefix.count + 36 else { return false }
        let uuidStr = String(path.dropFirst(prefix.count))
        return UUID(uuidString: uuidStr) != nil
    }

    /// Sanitizes display names to eliminate format scalars, BiDi overrides, and invisible characters.
    public func sanitizeUnicodeName(_ raw: String) -> String? {
        guard !raw.isEmpty else { return nil }
        var result = ""
        result.reserveCapacity(raw.count)

        for scalar in raw.unicodeScalars {
            let val = scalar.value
            if isFormatScalar(val) || val == 0x2028 || val == 0x2029 {
                result.append("\u{FFFD}")
            } else if val >= 0x00 && val <= 0x1F || val == 0x7F {
                return nil // Rejects ASCII control characters
            } else {
                result.append(String(scalar))
            }
        }

        let normalized = result.precomposedStringWithCanonicalMapping
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard !normalized.isEmpty, !normalized.hasPrefix("/"), !normalized.contains(".app/") else {
            return nil
        }
        return normalized
    }

    /// Identifies format and BiDi control scalars that could disguise malicious binaries.
    private func isFormatScalar(_ c: UInt32) -> Bool {
        return c == 0x00ad ||
               (c >= 0x0600 && c <= 0x0605) || c == 0x061c || c == 0x06dd ||
               c == 0x070f ||
               (c >= 0x0890 && c <= 0x0891) || c == 0x08e2 ||
               c == 0x180e ||
               (c >= 0x200b && c <= 0x200f) ||
               (c >= 0x202a && c <= 0x202e) ||
               (c >= 0x2060 && c <= 0x206f) ||
               c == 0xfeff
    }
}
