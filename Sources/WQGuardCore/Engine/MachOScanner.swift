//
//  MachOScanner.swift
//  WQGuardCore
//
//  Layer 2 Mach-O binary, load command, symbol table, and string scanner.
//  100% read-only bounds checking with FairPlay DRM handling and whitelist integration.
//

import Foundation
import MachO

/// Static Mach-O binary, symbol table, and string scanner (Layer 2 of WQGuard pipeline).
public final class MachOScanner: @unchecked Sendable {
    public static let shared = MachOScanner()
    
    /// Scan context parameters providing application identity and entitlement information.
    public struct ScanContext: Sendable {
        public let bundleId: String?
        public let displayName: String
        public let version: String
        public let teamId: String?
        public let bundlePath: String
        public let executablePath: String?
        public let installChannel: InstallChannel
        public let appGroups: [String]
        public let disqualifyAppStoreExemption: Bool
        
        public init(
            bundleId: String? = nil,
            displayName: String = "App",
            version: String = "1.0",
            teamId: String? = nil,
            bundlePath: String = "",
            executablePath: String? = nil,
            installChannel: InstallChannel = .developerSideloaded,
            appGroups: [String] = [],
            disqualifyAppStoreExemption: Bool = false
        ) {
            self.bundleId = bundleId
            self.displayName = displayName
            self.version = version
            self.teamId = teamId
            self.bundlePath = bundlePath
            self.executablePath = executablePath
            self.installChannel = installChannel
            self.appGroups = appGroups
            self.disqualifyAppStoreExemption = disqualifyAppStoreExemption
        }
    }
    
    /// Low-level details parsed directly from a Mach-O slice.
    public struct ParsedBinaryDetails: Sendable {
        public let cryptid: UInt32
        public let linkedDylibs: [String]
        public let symbols: [String]
        public let textStrings: [String]
        public let isFairPlayEncrypted: Bool
        public let directSyscallSites: [DirectSyscallSite]
        public let directSyscallCount: Int
        public let corruptedSliceCount: Int
        public let hasUnencryptedSegments: Bool
        
        public init(
            cryptid: UInt32,
            linkedDylibs: [String],
            symbols: [String],
            textStrings: [String],
            isFairPlayEncrypted: Bool,
            directSyscallSites: [DirectSyscallSite] = [],
            directSyscallCount: Int = 0,
            corruptedSliceCount: Int = 0,
            hasUnencryptedSegments: Bool = false
        ) {
            self.cryptid = cryptid
            self.linkedDylibs = linkedDylibs
            self.symbols = symbols
            self.textStrings = textStrings
            self.isFairPlayEncrypted = isFairPlayEncrypted
            self.directSyscallSites = directSyscallSites
            self.directSyscallCount = directSyscallCount
            self.corruptedSliceCount = corruptedSliceCount
            self.hasUnencryptedSegments = hasUnencryptedSegments
        }
    }
    
    public init() {}
    // MARK: - Mach-O Parsing (Delegated to MachOParser)
    
    /// Parses load commands, symbols, Objective-C selectors, and string tables across all slices in raw Mach-O data.
    public func parseMachO(data rawInput: Data) throws -> ParsedBinaryDetails {
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
        let slices = try MachOParser.shared.parseAllSlices(data: data)
        let declaredCount = slices.first?.slicesInContainer.count
        return parseMachO(files: slices, rawData: data, expectedContainerSliceCount: declaredCount)
    }
    
    /// Extracts `ParsedBinaryDetails` from a single parsed `MachOFile`.
    public func parseMachO(file: MachOFile, rawData: Data? = nil) -> ParsedBinaryDetails {
        parseMachO(files: [file], rawData: rawData, expectedContainerSliceCount: nil)
    }

    /// Extracts and unions `ParsedBinaryDetails` across one or more Mach-O architecture slices.
    public func parseMachO(
        files: [MachOFile],
        rawData: Data? = nil,
        expectedContainerSliceCount: Int? = nil
    ) -> ParsedBinaryDetails {
        let targetFiles = MachOParser.selectAuditSlices(from: files)
        guard let primary = targetFiles.first else {
            return ParsedBinaryDetails(cryptid: 0, linkedDylibs: [], symbols: [], textStrings: [], isFairPlayEncrypted: false)
        }

        let corruptedSliceCount: Int
        if let expected = expectedContainerSliceCount, expected > files.count {
            corruptedSliceCount = expected - files.count
        } else {
            corruptedSliceCount = 0
        }

        let allEncrypted = targetFiles.allSatisfy { $0.isFairPlayEncrypted }
        let cryptid: UInt32 = allEncrypted ? primary.cryptid : 0
        let isFairPlayEncrypted = allEncrypted

        var linkedDylibs: [String] = []
        var dylibSet: Set<String> = []
        var symbols: [String] = []
        var symbolSet: Set<String> = []
        var directSyscallSites: [DirectSyscallSite] = []
        var directSyscallCount = 0
        let maxSyscallSamples = 16

        for f in targetFiles {
            for dylib in f.linkedDylibPaths where dylibSet.insert(dylib).inserted {
                linkedDylibs.append(dylib)
            }
            for sym in f.symbols where symbolSet.insert(sym).inserted {
                symbols.append(sym)
            }
            for sel in f.objcMethodNames where symbolSet.insert(sel).inserted {
                symbols.append(sel)
            }
            let remainingSampleCapacity = max(0, maxSyscallSamples - directSyscallSites.count)
            let syscallScan = f.scanDirectSyscalls(maxSampleSites: remainingSampleCapacity)
            directSyscallCount += syscallScan.totalCount
            if remainingSampleCapacity > 0 && !syscallScan.sampleSites.isEmpty {
                directSyscallSites.append(contentsOf: syscallScan.sampleSites.prefix(remainingSampleCapacity))
            }
        }

        // Build unencrypted byte buffers per slice (redacting genuine FairPlay encryptedRange bytes to NUL so partial
        // LC_ENCRYPTION_INFO_64 headers cannot hide unencrypted __cstring/__TEXT payloads while ciphertext never false-positives).
        var inspectableBuffers: [Data] = []
        var sawPartialUnencryptedContent = false
        for f in targetFiles {
            if !f.isFairPlayEncrypted || f.hasForgedPlaintextFairPlayRange {
                inspectableBuffers.append(f.sliceData)
                sawPartialUnencryptedContent = true
            } else if let er = f.encryptionInfo?.encryptedRange {
                let headerSize = f.is64Bit ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
                let postHeaderStart = min(f.sliceData.count, headerSize + Int(f.sizeofcmds))
                let hasExposedSectionOrText = f.segments.contains { seg in
                    guard seg.name == "__TEXT" || (seg.initialProtection & 0x04) != 0 else { return false }
                    for sect in seg.sections where sect.size > 0 {
                        if let sOff = Int(exactly: sect.offset), let sSz = Int(exactly: sect.size),
                           sOff >= 0, sOff + sSz <= f.sliceData.count {
                            if sOff < er.lowerBound || (sOff + sSz) > er.upperBound {
                                return true
                            }
                        }
                    }
                    if let segRange = seg.fileRange {
                        let bodyStart = max(segRange.lowerBound, postHeaderStart)
                        let bodyEnd = min(segRange.upperBound, f.sliceData.count)
                        if bodyEnd > bodyStart && (bodyStart < er.lowerBound || bodyEnd > er.upperBound) {
                            return true
                        }
                    }
                    return false
                }
                if hasExposedSectionOrText {
                    var masked = f.sliceData
                    let clampLo = max(0, min(er.lowerBound, masked.count))
                    let clampHi = max(clampLo, min(er.upperBound, masked.count))
                    if clampHi > clampLo {
                        masked.resetBytes(in: clampLo..<clampHi)
                    }
                    inspectableBuffers.append(masked)
                    sawPartialUnencryptedContent = true
                }
            }
        }
        
        var textStrings: [String] = []
        if !inspectableBuffers.isEmpty {
            var candidateStrings: [String] = [
                "com.apple.containermanagerd.system",
                "com.apple.containermanagerd",
                "/Containers/Data/",
                "/Containers/Shared/",
                "/var/mobile/Containers/",
                "/private/var/mobile/Containers/",
                ".com.apple.mobile_container_manager.metadata.plist",
                ".csstore",
                "com.apple.LaunchServices-",
                SignatureCatalog.targetDylibName
            ]
            for extra in SignatureCatalog.standaloneExploitCandidateStrings where !candidateStrings.contains(extra) {
                candidateStrings.append(extra)
            }
            let caseInsensitiveFwKeys = Set(SignatureCatalog.standaloneExploitDylibRules.keys).union([SignatureCatalog.targetDylibName])
            for extra in SignatureCatalog.standaloneExploitDylibRules.keys.sorted() where !candidateStrings.contains(extra) {
                candidateStrings.append(extra)
            }
            for extra in SignatureCatalog.standaloneExploitSymbolRules.keys.sorted() where !candidateStrings.contains(extra) {
                candidateStrings.append(extra)
            }
            for extra in SignatureCatalog.privateContainerSymbols.keys.sorted() where !candidateStrings.contains(extra) {
                candidateStrings.append(extra)
            }
            let pathEnumKeys = Set(SignatureCatalog.pathEnumerationSymbols.keys)
            for extra in pathEnumKeys.sorted() where !candidateStrings.contains(extra) {
                candidateStrings.append(extra)
            }
            
            let checkRawToo = (!isFairPlayEncrypted && files.count == 1 && rawData != nil && rawData!.count != primary.sliceData.count)

            for target in candidateStrings {
                let needle = Data(target.utf8)
                if pathEnumKeys.contains(target) {
                    let inSliceExact = inspectableBuffers.contains { Self.containsExactCStringSymbol(in: $0, symbolUTF8: needle) }
                    let inRawExact = checkRawToo && rawData != nil && Self.containsExactCStringSymbol(in: rawData!, symbolUTF8: needle)
                    if inSliceExact || inRawExact || symbolSet.contains(target) {
                        textStrings.append(target)
                    }
                } else {
                    var inSlice = inspectableBuffers.contains { $0.range(of: needle) != nil }
                    if !inSlice && caseInsensitiveFwKeys.contains(target) {
                        let lowerTarget = target.lowercased()
                        inSlice = inspectableBuffers.contains { String(decoding: $0, as: UTF8.self).lowercased().contains(lowerTarget) }
                    }
                    if inSlice ||
                       (checkRawToo && rawData?.range(of: needle) != nil) ||
                       symbolSet.contains(target) {
                        textStrings.append(target)
                    }
                }
            }

            // Surface dynamically loaded framework paths (`dlopen` / `CFBundleLoadExecutable` / `NSBundle`) and
            // Objective-C runtime class/selector resolution (`NSClassFromString`, `objc_getClass`, `NSSelectorFromString`, `sel_registerName`)
            // so `ExpandedThreatCatalog` evaluators cannot be bypassed by avoiding static `LC_LOAD_DYLIB` / `LC_SYMTAB` imports.
            let hasDynamicLibraryLoader = symbols.contains { sym in
                let clean = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
                return clean == "dlopen"
                    || clean == "CFBundleLoadExecutable"
                    || clean == "CFBundleLoadExecutableAndReturnError"
                    || sym == "bundleWithPath:" || sym == "bundleWithURL:"
                    || sym.contains("bundleWithPath:") || sym.contains("bundleWithURL:")
            }
            if hasDynamicLibraryLoader {
                let dynamicFrameworks = [
                    IOCTokenArmor.tPhotoLibFw,
                    IOCTokenArmor.tAssetsLibFw,
                    IOCTokenArmor.tAccSetupFw
                ]
                for fw in dynamicFrameworks {
                    let matchedInSlice = inspectableBuffers.contains { Self.containsFrameworkPathCString(in: $0, frameworkName: fw) }
                    let matchedInRaw = checkRawToo && rawData != nil && Self.containsFrameworkPathCString(in: rawData!, frameworkName: fw)
                    if (matchedInSlice || matchedInRaw), dylibSet.insert(fw).inserted {
                        linkedDylibs.append(fw)
                    }
                }
            }

            let hasObjCClassResolver = symbols.contains { sym in
                let clean = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
                return clean == "NSClassFromString"
                    || clean == "objc_getClass"
                    || clean == "objc_lookUpClass"
                    || clean == "objc_getRequiredClass"
                    || clean == "objc_getMetaClass"
                    || sym == "classNamed:" || sym.contains("classNamed:")
            }
            if hasObjCClassResolver {
                let dynamicClasses = [
                    IOCTokenArmor.tPLPhotoLib,
                    IOCTokenArmor.tASAccSess,
                    IOCTokenArmor.tUIPasteboard
                ]
                for cls in dynamicClasses {
                    let needle = Data(cls.utf8)
                    let matchedInSlice = inspectableBuffers.contains { Self.containsExactCStringSymbol(in: $0, symbolUTF8: needle) }
                    let matchedInRaw = checkRawToo && rawData != nil && Self.containsExactCStringSymbol(in: rawData!, symbolUTF8: needle)
                    if (matchedInSlice || matchedInRaw), symbolSet.insert(cls).inserted {
                        symbols.append(cls)
                    }
                }
            }

            let hasObjCSelectorResolver = symbols.contains { sym in
                let clean = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
                return clean == "NSSelectorFromString"
                    || clean == "sel_registerName"
                    || clean == "sel_getUid"
            }
            if hasObjCSelectorResolver {
                let dynamicSelectors = [
                    IOCTokenArmor.tSysPhotoLib,
                    IOCTokenArmor.tGenPasteboard
                ]
                for sel in dynamicSelectors {
                    let needle = Data(sel.utf8)
                    let matchedInSlice = inspectableBuffers.contains { Self.containsExactCStringSymbol(in: $0, symbolUTF8: needle) }
                    let matchedInRaw = checkRawToo && rawData != nil && Self.containsExactCStringSymbol(in: rawData!, symbolUTF8: needle)
                    if (matchedInSlice || matchedInRaw), symbolSet.insert(sel).inserted {
                        symbols.append(sel)
                    }
                }
            }
        }
        
        return ParsedBinaryDetails(
            cryptid: cryptid,
            linkedDylibs: linkedDylibs,
            symbols: symbols,
            textStrings: textStrings,
            isFairPlayEncrypted: isFairPlayEncrypted,
            directSyscallSites: directSyscallSites,
            directSyscallCount: directSyscallCount,
            corruptedSliceCount: corruptedSliceCount,
            hasUnencryptedSegments: sawPartialUnencryptedContent
        )
    }
    
    /// Executes Layer 2 scan against binary details and context.
    public func scan(
        details: ParsedBinaryDetails,
        context: ScanContext
    ) -> ScanFinding {
        let hasAppGroups = !context.appGroups.isEmpty

        // Pre-gating checks for App-Group-independent primitives:
        // - APFS inode enumeration (`bad_query` / CM-05 `fsgetpath`, `container_object_get_path`)
        // - Inline ARM64 `svc #0x80` direct syscalls
        // - Corrupted / unparseable Universal FAT sibling slices
        // - Standalone 2026 exploit dylibs, symbols, and strings (audiomxd, BookRestore, MobileGestalt)
        let standalonePathEnumMatches: [SignatureCatalog.Rule] = details.symbols.compactMap { sym in
            let cleanSym = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
            return SignatureCatalog.pathEnumerationSymbols[cleanSym] ?? SignatureCatalog.pathEnumerationSymbols[sym]
        }
        let hasDirectSyscalls = details.directSyscallCount > 0
        let hasCorruptedSlices = details.corruptedSliceCount > 0
        let hasDlopenImport = details.symbols.contains { sym in
            let clean = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
            return clean == "dlopen" || sym.contains("dlopen")
        }
        let hasDlsymImport = details.symbols.contains { sym in
            let clean = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
            return clean == "dlsym" || sym.contains("dlsym")
        }
        let hasObjCBundleInit = details.symbols.contains { sym in
            sym == "bundleWithPath:" || sym == "bundleWithURL:" || sym == "initWithPath:" || sym == "initWithURL:"
                || sym.contains("bundleWithPath:") || sym.contains("bundleWithURL:")
        }
        let hasObjCBundleLoad = details.symbols.contains { sym in
            sym == "load" || sym == "loadAndReturnError:" || sym == "classNamed:" || sym == "principalClass"
        }
        let hasLibraryLoaderImport = hasDlopenImport || (hasObjCBundleInit && hasObjCBundleLoad) || details.symbols.contains { sym in
            let clean = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
            return clean == "CFBundleLoadExecutable" || clean == "CFBundleLoadExecutableAndReturnError"
        }
        let hasSymbolResolverImport = hasDlsymImport || details.symbols.contains { sym in
            let clean = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
            return clean == "CFBundleGetFunctionPointerForName"
                || clean == "CFBundleGetFunctionPointersForNames"
                || clean == "CFBundleGetDataPointerForName"
        }

        let hasInspectableCodeOrStrings = !details.isFairPlayEncrypted || details.hasUnencryptedSegments || !details.textStrings.isEmpty || context.installChannel != .appStore || context.disqualifyAppStoreExemption

        var standaloneDylibMatches: [(rule: SignatureCatalog.Rule, dylib: String)] = []
        let sortedDylibRules = SignatureCatalog.standaloneExploitDylibRules.sorted { $0.key < $1.key }
        if !details.isFairPlayEncrypted || details.hasUnencryptedSegments || context.installChannel != .appStore || context.disqualifyAppStoreExemption {
            for dylib in details.linkedDylibs {
                let lowerDylib = dylib.lowercased()
                for (pattern, rule) in sortedDylibRules {
                    let lowerPat = pattern.lowercased()
                    if lowerDylib.contains(lowerPat) || lowerDylib.hasSuffix(lowerPat) {
                        standaloneDylibMatches.append((rule: rule, dylib: dylib))
                    }
                }
            }
        }

        var standaloneSymbolMatches: [(rule: SignatureCatalog.Rule, symbol: String)] = []
        var standaloneStringMatches: [(rule: SignatureCatalog.Rule, pattern: String)] = []
        var standaloneCStringMatches: [(rule: SignatureCatalog.Rule, pattern: String)] = []
        var dynamicPathEnumMatches: [String] = []
        if hasInspectableCodeOrStrings {
            for sym in details.symbols {
                let cleanSym = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
                if let rule = SignatureCatalog.standaloneExploitSymbolRules[cleanSym] ?? SignatureCatalog.standaloneExploitSymbolRules[sym] {
                    standaloneSymbolMatches.append((rule: rule, symbol: sym))
                }
            }

            let sortedStringRules = SignatureCatalog.standaloneExploitStringRules.sorted { $0.key < $1.key }
            for str in details.textStrings {
                for (pattern, rule) in sortedStringRules {
                    if str.contains(pattern) {
                        standaloneStringMatches.append((rule: rule, pattern: pattern))
                    }
                }
            }

            // Detect private frameworks resolved via dlopen/CFBundleLoadExecutable/NSBundle C-strings,
            // and private symbols resolved via dlsym(RTLD_DEFAULT, name) / CFBundleGetFunctionPointerForName C-strings.
            if hasLibraryLoaderImport {
                for str in details.textStrings {
                    let lowerStr = str.lowercased()
                    for (pattern, rule) in sortedDylibRules {
                        if lowerStr.contains(pattern.lowercased()),
                           !standaloneDylibMatches.contains(where: { $0.rule.pattern == rule.pattern }),
                           !standaloneCStringMatches.contains(where: { $0.rule.pattern == rule.pattern }) {
                            standaloneCStringMatches.append((rule: rule, pattern: pattern))
                        }
                    }
                }
            }
            if hasSymbolResolverImport {
                let sortedSymbolRules = SignatureCatalog.standaloneExploitSymbolRules.sorted { $0.key < $1.key }
                let sortedPathEnumRules = SignatureCatalog.pathEnumerationSymbols.sorted { $0.key < $1.key }
                for str in details.textStrings {
                    for (symKey, rule) in sortedSymbolRules {
                        if str.contains(symKey),
                           !standaloneSymbolMatches.contains(where: { $0.rule.pattern == rule.pattern }),
                           !standaloneCStringMatches.contains(where: { $0.rule.pattern == rule.pattern }) {
                            standaloneCStringMatches.append((rule: rule, pattern: symKey))
                        }
                    }
                    for (symKey, rule) in sortedPathEnumRules {
                        if str.contains(symKey), !dynamicPathEnumMatches.contains(rule.pattern) {
                            dynamicPathEnumMatches.append(rule.pattern)
                        }
                    }
                }
            }
        }

        let hasStandaloneExploits = !standalonePathEnumMatches.isEmpty
            || !dynamicPathEnumMatches.isEmpty
            || hasDirectSyscalls
            || hasCorruptedSlices
            || !standaloneDylibMatches.isEmpty
            || !standaloneSymbolMatches.isEmpty
            || !standaloneStringMatches.isEmpty
            || !standaloneCStringMatches.isEmpty
        
        // 1. Layer 1 Gating Check (only fast-paths when both App Groups AND all App-Group-independent exploits are absent)
        let gating = EntitlementGating.evaluate(hasAppGroups: hasAppGroups, appGroups: context.appGroups)
        if gating.isGatedOut && !hasStandaloneExploits {
            let emptyEvidence = AuditEvidence(
                matchedSymbols: [],
                linkedDylibs: details.linkedDylibs,
                hasAppGroups: false,
                appGroups: [],
                installChannel: context.installChannel,
                cryptid: details.cryptid,
                isFairPlayEncrypted: details.isFairPlayEncrypted,
                escapingSymlinks: [],
                dynamicLoadingPresent: false,
                pathEnumerationPresent: false,
                remediationGuidance: gating.reason
            )
            return ScanFinding(
                bundleId: context.bundleId ?? "unknown",
                displayName: context.displayName,
                version: context.version,
                teamId: context.teamId,
                executablePath: context.executablePath,
                bundlePath: context.bundlePath,
                installChannel: context.installChannel,
                riskTier: .safe,
                isWhitelisted: false,
                whitelistedToolName: nil,
                indicators: [],
                evidence: emptyEvidence,
                scanTimestamp: Date()
            )
        }
        
        var indicators: [ThreatIndicator] = []
        var seenIndicatorKeys: Set<String> = []
        func appendUniqueIndicator(_ indicator: ThreatIndicator) {
            let key = "\(indicator.signature)\u{0}\(indicator.location)"
            if seenIndicatorKeys.insert(key).inserted {
                indicators.append(indicator)
            }
        }
        var matchedSymbols: [String] = []
        var pathEnumerationDetected = false
        var dynamicLoadingDetected = false
        var symlinkDetected = false

        // 1b. App-Group-Independent Direct Syscalls (`svc #0x80`), Corrupted Slices & Standalone 2026 Exploit Indicators
        if hasCorruptedSlices {
            appendUniqueIndicator(ThreatIndicator(
                signature: "CorruptMachO:UnparseableSlice",
                description: WQLocale.pick(
                    en: "Universal FAT binary contains \(details.corruptedSliceCount) corrupted or header-mismatched architecture slice(s) concealing uninspected bytes",
                    zh: "Universal FAT 二进制包含 \(details.corruptedSliceCount) 个损坏或架构头伪造的切片，可能隐藏未受检载荷"
                ),
                category: "Binary Integrity Anomaly",
                location: "FAT Header (\(details.corruptedSliceCount)x unparseable slice)",
                severity: .highRisk
            ))
            matchedSymbols.append("CorruptMachO:UnparseableSlice")
        }

        for dynPathSym in dynamicPathEnumMatches {
            if !matchedSymbols.contains(dynPathSym) {
                matchedSymbols.append(dynPathSym)
            }
            pathEnumerationDetected = true
        }

        if hasDirectSyscalls {
            let syscallLocation: String
            if let site = details.directSyscallSites.first {
                syscallLocation = "\(site.segmentName),\(site.sectionName) @ \(String(format: "0x%llx", site.virtualAddress)) (\(details.directSyscallCount)x svc #0x80)"
            } else {
                syscallLocation = "__TEXT,__text (\(details.directSyscallCount)x svc #0x80)"
            }
            appendUniqueIndicator(SignatureCatalog.directSyscallRule.toIndicator(at: syscallLocation))
            matchedSymbols.append(SignatureCatalog.directSyscallRule.pattern)
        }

        for match in standaloneDylibMatches {
            appendUniqueIndicator(match.rule.toIndicator(at: "LC_LOAD_DYLIB: \(match.dylib)"))
            matchedSymbols.append(match.rule.pattern)
        }

        for match in standaloneSymbolMatches {
            appendUniqueIndicator(match.rule.toIndicator(at: "LC_SYMTAB: \(match.symbol)"))
            matchedSymbols.append(match.rule.pattern)
        }

        for match in standaloneStringMatches {
            appendUniqueIndicator(match.rule.toIndicator(at: "__TEXT: \(match.pattern)"))
            matchedSymbols.append(match.rule.pattern)
        }

        for match in standaloneCStringMatches {
            appendUniqueIndicator(match.rule.toIndicator(at: "__TEXT,__cstring: \(match.pattern)"))
            matchedSymbols.append(match.rule.pattern)
        }
        
        // 2. Scan Linked Dylibs (requires App Group precondition)
        if !gating.isGatedOut {
            for dylib in details.linkedDylibs {
                let lowerDylib = dylib.lowercased()
                for (pattern, rule) in SignatureCatalog.dylibRules {
                    let lowerPat = pattern.lowercased()
                    if lowerDylib.contains(lowerPat) || lowerDylib.hasSuffix(lowerPat) {
                        appendUniqueIndicator(rule.toIndicator(at: "LC_LOAD_DYLIB: \(dylib)"))
                        matchedSymbols.append(pattern)
                    }
                }
            }
        }
        
        // 3. Scan Symbol Table
        for sym in details.symbols {
            let cleanSym = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
            
            // Check Private containermanager APIs (requires App Group precondition)
            if !gating.isGatedOut,
               let rule = SignatureCatalog.privateContainerSymbols[cleanSym] ?? SignatureCatalog.privateContainerSymbols[sym] {
                appendUniqueIndicator(rule.toIndicator(at: "LC_SYMTAB: \(sym)"))
                matchedSymbols.append(rule.pattern)
            }
            
            // Check Path Enumeration Symbols (fsgetpath / container_object_get_path - independent of App Groups)
            if let rule = SignatureCatalog.pathEnumerationSymbols[cleanSym] ?? SignatureCatalog.pathEnumerationSymbols[sym] {
                matchedSymbols.append(rule.pattern)
                pathEnumerationDetected = true
            }
            
            // Check Dynamic Loading (dlopen/dlsym)
            if !gating.isGatedOut,
               SignatureCatalog.dynamicLoadingSymbols.contains(cleanSym) || SignatureCatalog.dynamicLoadingSymbols.contains(sym) {
                matchedSymbols.append(cleanSym)
            }
            
            // Check Symlink APIs
            if !gating.isGatedOut,
               SignatureCatalog.symlinkPrimitives.contains(cleanSym) || SignatureCatalog.symlinkPrimitives.contains(sym) {
                symlinkDetected = true
                matchedSymbols.append(cleanSym)
            }
        }
        
        if !gating.isGatedOut {
            let hasDlopen = matchedSymbols.contains("dlopen") || details.symbols.contains { $0.contains("dlopen") }
            let hasDlsym = matchedSymbols.contains("dlsym") || details.symbols.contains { $0.contains("dlsym") }
            if hasDlopen && hasDlsym {
                dynamicLoadingDetected = true
            }
            
            // 4. Scan String Signatures (Direct XPC, MCM Metadata)
            for str in details.textStrings {
                // Direct XPC
                for (pattern, rule) in SignatureCatalog.directXPCRules {
                    if str.contains(pattern) {
                        appendUniqueIndicator(rule.toIndicator(at: "__TEXT: \(pattern)"))
                        matchedSymbols.append(pattern)
                    }
                }
                
                // Container metadata files
                for (pattern, rule) in SignatureCatalog.metadataFileRules {
                    if str.contains(pattern) {
                        appendUniqueIndicator(rule.toIndicator(at: "__TEXT: \(pattern)"))
                        matchedSymbols.append(pattern)
                    }
                }
            }

            // Dynamic C-string resolution of containermanager dylib / symbols via dlopen/CFBundleLoadExecutable/NSBundle or dlsym(RTLD_DEFAULT, ...)
            if hasInspectableCodeOrStrings && (hasLibraryLoaderImport || hasSymbolResolverImport) {
                let sortedContainerDylibRules = SignatureCatalog.dylibRules.sorted { $0.key < $1.key }
                let sortedContainerSymRules = SignatureCatalog.privateContainerSymbols.sorted { $0.key < $1.key }
                for str in details.textStrings {
                    if hasLibraryLoaderImport {
                        let lowerStr = str.lowercased()
                        for (pattern, rule) in sortedContainerDylibRules {
                            if lowerStr.contains(pattern.lowercased()) && !matchedSymbols.contains(pattern) {
                                appendUniqueIndicator(rule.toIndicator(at: "__TEXT,__cstring: \(pattern)"))
                                matchedSymbols.append(pattern)
                            }
                        }
                    }
                    if hasSymbolResolverImport {
                        for (symKey, rule) in sortedContainerSymRules {
                            if str.contains(symKey) && !matchedSymbols.contains(rule.pattern) {
                                appendUniqueIndicator(rule.toIndicator(at: "__TEXT,__cstring: \(symKey)"))
                                matchedSymbols.append(rule.pattern)
                            }
                        }
                    }
                }
            }
        }
        
        // Check Path Leak Combination: fsgetpath / container_object_get_path + /Containers/Data/ or /Containers/Shared/
        let hasContainerPathStr = details.textStrings.contains { str in
            SignatureCatalog.containerPathSubstrings.contains { str.contains($0) }
        }
        if pathEnumerationDetected {
            let fsgetpathSym = IOCTokenArmor.tFsgetpath
            let containerObjPathSym = IOCTokenArmor.tContainerObjGetPath
            let hasFsgetpath = matchedSymbols.contains(fsgetpathSym)
            let hasContainerObjGetPath = matchedSymbols.contains(containerObjPathSym)
            let primarySym = hasFsgetpath ? fsgetpathSym : containerObjPathSym
            if hasContainerPathStr {
                let targetSub = details.textStrings.first { s in SignatureCatalog.containerPathSubstrings.contains { s.contains($0) } } ?? "/Containers/Data/"
                let sig = "\(primarySym):\(targetSub)"
                appendUniqueIndicator(ThreatIndicator(
                    signature: sig,
                    description: WQLocale.pick(
                        en: "Path leak brute-force targeting application containers (\(primarySym) combined with container prefix)",
                        zh: "针对应用容器的路径枚举暴力探测（\(primarySym) 配合容器路径前缀）"
                    ),
                    category: "Sandbox Enumeration",
                    location: "Mach-O (Symbol + String)",
                    severity: .highRisk
                ))
            } else {
                if hasFsgetpath {
                    appendUniqueIndicator(ThreatIndicator(
                        signature: fsgetpathSym,
                        description: WQLocale.pick(
                            en: "APFS file system inode brute-force primitive",
                            zh: "底层 APFS 文件系统 inode 路径枚举遍历原语 (\(fsgetpathSym))"
                        ),
                        category: "Sandbox Enumeration",
                        location: "LC_SYMTAB",
                        severity: .highRisk
                    ))
                }
                if hasContainerObjGetPath, let objRule = SignatureCatalog.pathEnumerationSymbols[containerObjPathSym] {
                    appendUniqueIndicator(objRule.toIndicator(at: "LC_SYMTAB"))
                }
            }
        }
        
        // 5. Evaluate Behavioral Tuple:
        // (cryptid == 0 || hasUnencryptedSegments || non-App-Store / unverified App Store sig) + application-groups + (dlopen && dlsym, or dlsym/CFBundle symbol resolver) + (symlink || sandbox_extension_consume || fsgetpath)
        let sbxConsumeSym = IOCTokenArmor.tSbxConsume
        let hasSandboxConsume = matchedSymbols.contains(sbxConsumeSym) || details.symbols.contains { $0.contains(sbxConsumeSym) }
        let canEvaluateBehavioralTuple = details.cryptid == 0
            || details.hasUnencryptedSegments
            || context.installChannel.isSideloadedOrEnterprise
            || context.disqualifyAppStoreExemption
        if canEvaluateBehavioralTuple && !gating.isGatedOut && (dynamicLoadingDetected || hasSymbolResolverImport) && (symlinkDetected || hasSandboxConsume || pathEnumerationDetected) {
            let alreadyHasExplicitExploit = indicators.contains { $0.severity == .highRisk && $0.category == "Private API Symbol" }
            if !alreadyHasExplicitExploit {
                appendUniqueIndicator(SignatureCatalog.behavioralTupleRule.toIndicator())
                matchedSymbols.append(SignatureCatalog.behavioralTupleRule.pattern)
            }
        }
        
        // 6. Evaluate Dynamic Loading Alone Heuristic:
        // App Groups + dlopen + dlsym without high risk exploit APIs -> Caution
        let hasHighRisk = indicators.contains { $0.severity == .highRisk }
        if !hasHighRisk && dynamicLoadingDetected && !gating.isGatedOut {
            appendUniqueIndicator(SignatureCatalog.dynamicLoadingCautionRule.toIndicator())
        }
        
        // 7. Determine Final Risk Tier and Whitelist Status
        var provisionalRisk: RiskTier = .safe
        if indicators.contains(where: { $0.severity == .highRisk }) {
            provisionalRisk = .highRisk
        } else if indicators.contains(where: { $0.severity == .caution }) {
            provisionalRisk = .caution
        }
        
        var isWhitelisted = false
        var whitelistedToolName: String? = nil
        var finalRisk = provisionalRisk
        
        if provisionalRisk == .highRisk || provisionalRisk == .caution {
            let whitelistResult = WhitelistEngine.shared.isWhitelisted(
                bundleId: context.bundleId ?? "",
                appGroups: context.appGroups,
                matchedSignatures: matchedSymbols,
                teamId: context.teamId
            )
            if whitelistResult.isWhitelisted {
                isWhitelisted = true
                whitelistedToolName = whitelistResult.toolName
                finalRisk = .knownTool
            }
        }
        
        var remediation = ""
        if finalRisk == .highRisk {
            remediation = WQLocale.pick(
                en: "Unauthorized high-risk exploit indicators detected (containermanagerd sandbox escape, inline svc #0x80 direct syscalls, or local privacy/system bypass primitives). Immediately uninstall or isolate this application.",
                zh: "检测到未经授权的高危利用特征（containermanagerd 跨沙盒逃逸、内联 svc #0x80 直接系统调用或本地隐私/系统绕过原语），建议立即卸载或隔离该应用。"
            )
        } else if finalRisk == .knownTool {
            remediation = WQLocale.pick(
                en: "Matched trusted whitelist rule (\(whitelistedToolName ?? "Known Tool")) signed by an authorized developer.",
                zh: "该应用匹配已知开源安全审计工具白名单（\(whitelistedToolName ?? "Known Tool")），由授权开发者签署。"
            )
        } else if finalRisk == .caution {
            remediation = WQLocale.pick(
                en: "The application declares App Group shared containers alongside dynamic symbol resolution capabilities. Review source before trusting.",
                zh: "应用声明了 App Group 共享容器权限并包含动态符号解析能力，建议持续关注。"
            )
        } else {
            if details.isFairPlayEncrypted {
                remediation = WQLocale.pick(
                    en: "Official App Store / TestFlight package protected by FairPlay DRM. No escape indicators found across unencrypted segments; safe.",
                    zh: "App Store / TestFlight 官方发布应用，FairPlay DRM 加密。未在非加密段发现越权特征，状态安全。"
                )
            } else {
                remediation = WQLocale.pick(
                    en: "No cross-container sandbox escape indicators detected; safe.",
                    zh: "未发现任何跨容器越权特征，状态安全。"
                )
            }
        }
        
        let evidence = AuditEvidence(
            matchedSymbols: Array(Set(matchedSymbols)).sorted(),
            linkedDylibs: details.linkedDylibs,
            hasAppGroups: hasAppGroups,
            appGroups: context.appGroups,
            installChannel: context.installChannel,
            cryptid: details.cryptid,
            isFairPlayEncrypted: details.isFairPlayEncrypted,
            escapingSymlinks: [],
            dynamicLoadingPresent: dynamicLoadingDetected,
            pathEnumerationPresent: pathEnumerationDetected,
            remediationGuidance: remediation
        )
        
        return ScanFinding(
            bundleId: context.bundleId ?? "unknown",
            displayName: context.displayName,
            version: context.version,
            teamId: context.teamId,
            executablePath: context.executablePath,
            bundlePath: context.bundlePath,
            installChannel: context.installChannel,
            riskTier: finalRisk,
            isWhitelisted: isWhitelisted,
            whitelistedToolName: whitelistedToolName,
            indicators: indicators,
            evidence: evidence,
            scanTimestamp: Date()
        )
    }
    
    /// Complete scan from binary data (100% read-only).
    public func scan(binaryData: Data, context: ScanContext) throws -> ScanFinding {
        let details = try parseMachO(data: binaryData)
        return scan(details: details, context: context)
    }
    
    /// Complete scan from binary URL (100% read-only, `O_NOFOLLOW` regular-file guarded).
    public func scan(binaryURL: URL, context: ScanContext) throws -> ScanFinding {
        let data = try IPAPackageScanner.readBoundedRegularFileDirectNoFollow(at: binaryURL)
        return try scan(binaryData: data, context: context)
    }

    /// Checks whether `data` contains a NUL-terminated filesystem/bundle path C-string (`<= 260` bytes, no spaces/newlines)
    /// referencing `frameworkName` case-insensitively (e.g. `/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/PhotoLibraryServices`),
    /// avoiding false positives on human-readable prose sentences.
    private static func containsFrameworkPathCString(in rawInput: Data, frameworkName: String) -> Bool {
        let lowerFw = frameworkName.lowercased()
        guard !lowerFw.isEmpty, rawInput.count >= lowerFw.utf8.count else { return false }
        return rawInput.withUnsafeBytes { raw in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return false }
            let n = raw.count
            var i = 0
            while i < n {
                while i < n && base[i] == 0 { i += 1 }
                if i >= n { break }
                let start = i
                var hasSpaceOrCtrl = false
                while i < n && base[i] != 0 {
                    let b = base[i]
                    if b <= 0x20 || b == 0x7F {
                        hasSpaceOrCtrl = true
                    }
                    i += 1
                }
                let len = i - start
                if !hasSpaceOrCtrl && len >= lowerFw.utf8.count && len <= 260 {
                    let s = String(decoding: UnsafeBufferPointer(start: base.advanced(by: start), count: len), as: UTF8.self)
                    if s.lowercased().contains(lowerFw) {
                        return true
                    }
                }
            }
            return false
        }
    }

    /// Checks whether `data` contains `symbolUTF8` as a NUL-terminated C-string (`(^|\0)_?<symbol>\0`),
    /// avoiding false positives on prose sentences mentioning a symbol name in parentheses or messages.
    private static func containsExactCStringSymbol(in rawInput: Data, symbolUTF8: Data) -> Bool {
        guard !symbolUTF8.isEmpty, rawInput.count >= symbolUTF8.count else { return false }
        let data = rawInput.startIndex == 0 ? rawInput : Data(rawInput)
        var searchStart = 0
        while searchStart <= data.count - symbolUTF8.count {
            guard let found = data.range(of: symbolUTF8, options: [], in: searchStart..<data.count) else {
                return false
            }
            let idx = found.lowerBound
            let endIdx = found.upperBound
            let validEnd = (endIdx == data.count) || (data[endIdx] == 0x00)
            let validStart: Bool
            if idx == 0 || data[idx - 1] == 0x00 {
                validStart = true
            } else if data[idx - 1] == 0x5F && (idx - 1 == 0 || data[idx - 2] == 0x00) {
                validStart = true
            } else {
                validStart = false
            }
            if validStart && validEnd {
                return true
            }
            searchStart = idx + 1
        }
        return false
    }
}
