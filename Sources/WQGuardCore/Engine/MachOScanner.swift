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
        
        public init(
            bundleId: String? = nil,
            displayName: String = "App",
            version: String = "1.0",
            teamId: String? = nil,
            bundlePath: String = "",
            executablePath: String? = nil,
            installChannel: InstallChannel = .developerSideloaded,
            appGroups: [String] = []
        ) {
            self.bundleId = bundleId
            self.displayName = displayName
            self.version = version
            self.teamId = teamId
            self.bundlePath = bundlePath
            self.executablePath = executablePath
            self.installChannel = installChannel
            self.appGroups = appGroups
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
        
        public init(
            cryptid: UInt32,
            linkedDylibs: [String],
            symbols: [String],
            textStrings: [String],
            isFairPlayEncrypted: Bool,
            directSyscallSites: [DirectSyscallSite] = [],
            directSyscallCount: Int = 0
        ) {
            self.cryptid = cryptid
            self.linkedDylibs = linkedDylibs
            self.symbols = symbols
            self.textStrings = textStrings
            self.isFairPlayEncrypted = isFairPlayEncrypted
            self.directSyscallSites = directSyscallSites
            self.directSyscallCount = directSyscallCount
        }
    }
    
    public init() {}
    // MARK: - Mach-O Parsing (Delegated to MachOParser)
    
    /// Parses load commands, symbols, Objective-C selectors, and string tables across all slices in raw Mach-O data.
    public func parseMachO(data: Data) throws -> ParsedBinaryDetails {
        let slices = try MachOParser.shared.parseAllSlices(data: data)
        return parseMachO(files: slices, rawData: data)
    }
    
    /// Extracts `ParsedBinaryDetails` from a single parsed `MachOFile`.
    public func parseMachO(file: MachOFile, rawData: Data? = nil) -> ParsedBinaryDetails {
        parseMachO(files: [file], rawData: rawData)
    }

    /// Extracts and unions `ParsedBinaryDetails` across one or more Mach-O architecture slices.
    public func parseMachO(files: [MachOFile], rawData: Data? = nil) -> ParsedBinaryDetails {
        let targetFiles = MachOParser.selectAuditSlices(from: files)
        guard let primary = targetFiles.first else {
            return ParsedBinaryDetails(cryptid: 0, linkedDylibs: [], symbols: [], textStrings: [], isFairPlayEncrypted: false)
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
            if !f.isFairPlayEncrypted {
                for sel in f.objcMethodNames where symbolSet.insert(sel).inserted {
                    symbols.append(sel)
                }
            }
            let remainingSampleCapacity = max(0, maxSyscallSamples - directSyscallSites.count)
            let syscallScan = f.scanDirectSyscalls(maxSampleSites: remainingSampleCapacity)
            directSyscallCount += syscallScan.totalCount
            if remainingSampleCapacity > 0 && !syscallScan.sampleSites.isEmpty {
                directSyscallSites.append(contentsOf: syscallScan.sampleSites.prefix(remainingSampleCapacity))
            }
        }
        
        var textStrings: [String] = []
        if !isFairPlayEncrypted {
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
                "libsystem_containermanager.dylib"
            ]
            for extra in SignatureCatalog.standaloneExploitCandidateStrings where !candidateStrings.contains(extra) {
                candidateStrings.append(extra)
            }
            
            let unencryptedSlices = targetFiles.filter { !$0.isFairPlayEncrypted }
            let checkRawToo = (files.count == 1 && rawData != nil && rawData!.count != primary.sliceData.count)

            for target in candidateStrings {
                let needle = Data(target.utf8)
                let inSlice = unencryptedSlices.contains { $0.sliceData.range(of: needle) != nil }
                if inSlice ||
                   (checkRawToo && rawData?.range(of: needle) != nil) ||
                   symbolSet.contains(target) {
                    textStrings.append(target)
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
            directSyscallCount: directSyscallCount
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
        // - Standalone 2026 exploit dylibs, symbols, and strings (audiomxd, BookRestore, MobileGestalt)
        let standalonePathEnumMatches: [SignatureCatalog.Rule] = details.symbols.compactMap { sym in
            let cleanSym = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
            return SignatureCatalog.pathEnumerationSymbols[cleanSym] ?? SignatureCatalog.pathEnumerationSymbols[sym]
        }
        let hasDirectSyscalls = details.directSyscallCount > 0

        var standaloneDylibMatches: [(rule: SignatureCatalog.Rule, dylib: String)] = []
        if !details.isFairPlayEncrypted || context.installChannel != .appStore {
            let sortedDylibRules = SignatureCatalog.standaloneExploitDylibRules.sorted { $0.key < $1.key }
            for dylib in details.linkedDylibs {
                for (pattern, rule) in sortedDylibRules {
                    if dylib.contains(pattern) || dylib.hasSuffix(pattern) {
                        standaloneDylibMatches.append((rule: rule, dylib: dylib))
                    }
                }
            }
        }

        var standaloneSymbolMatches: [(rule: SignatureCatalog.Rule, symbol: String)] = []
        var standaloneStringMatches: [(rule: SignatureCatalog.Rule, pattern: String)] = []
        if !details.isFairPlayEncrypted {
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
        }

        let hasStandaloneExploits = !standalonePathEnumMatches.isEmpty
            || hasDirectSyscalls
            || !standaloneDylibMatches.isEmpty
            || !standaloneSymbolMatches.isEmpty
            || !standaloneStringMatches.isEmpty
        
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

        // 1b. App-Group-Independent Direct Syscalls (`svc #0x80`) & Standalone 2026 Exploit Indicators
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
        
        // 2. Scan Linked Dylibs (requires App Group precondition)
        if !gating.isGatedOut {
            for dylib in details.linkedDylibs {
                for (pattern, rule) in SignatureCatalog.dylibRules {
                    if dylib.contains(pattern) || dylib.hasSuffix(pattern) {
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
        }
        
        // Check Path Leak Combination: fsgetpath / container_object_get_path + /Containers/Data/ or /Containers/Shared/
        let hasContainerPathStr = details.textStrings.contains { str in
            SignatureCatalog.containerPathSubstrings.contains { str.contains($0) }
        }
        if pathEnumerationDetected {
            let hasFsgetpath = matchedSymbols.contains("fsgetpath")
            let hasContainerObjGetPath = matchedSymbols.contains("container_object_get_path")
            let primarySym = hasFsgetpath ? "fsgetpath" : "container_object_get_path"
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
                        signature: "fsgetpath",
                        description: WQLocale.pick(
                            en: "APFS file system inode brute-force primitive",
                            zh: "底层 APFS 文件系统 inode 路径枚举遍历原语 (fsgetpath)"
                        ),
                        category: "Sandbox Enumeration",
                        location: "LC_SYMTAB",
                        severity: .highRisk
                    ))
                }
                if hasContainerObjGetPath, let objRule = SignatureCatalog.pathEnumerationSymbols["container_object_get_path"] {
                    appendUniqueIndicator(objRule.toIndicator(at: "LC_SYMTAB"))
                }
            }
        }
        
        // 5. Evaluate Behavioral Tuple:
        // cryptid == 0 + application-groups + (dlopen && dlsym) + (symlink || sandbox_extension_consume || fsgetpath)
        let hasSandboxConsume = matchedSymbols.contains("sandbox_extension_consume") || details.symbols.contains { $0.contains("sandbox_extension_consume") }
        if details.cryptid == 0 && !gating.isGatedOut && dynamicLoadingDetected && (symlinkDetected || hasSandboxConsume || pathEnumerationDetected) {
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
    
    /// Complete scan from binary URL (100% read-only).
    public func scan(binaryURL: URL, context: ScanContext) throws -> ScanFinding {
        let data = try Data(contentsOf: binaryURL, options: .mappedIfSafe)
        return try scan(binaryData: data, context: context)
    }
}
