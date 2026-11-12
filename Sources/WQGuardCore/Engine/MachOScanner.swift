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
        
        public init(
            cryptid: UInt32,
            linkedDylibs: [String],
            symbols: [String],
            textStrings: [String],
            isFairPlayEncrypted: Bool
        ) {
            self.cryptid = cryptid
            self.linkedDylibs = linkedDylibs
            self.symbols = symbols
            self.textStrings = textStrings
            self.isFairPlayEncrypted = isFairPlayEncrypted
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
        }
        
        var textStrings: [String] = []
        if !isFairPlayEncrypted {
            let candidateStrings: [String] = [
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
            isFairPlayEncrypted: isFairPlayEncrypted
        )
    }
    
    /// Executes Layer 2 scan against binary details and context.
    public func scan(
        details: ParsedBinaryDetails,
        context: ScanContext
    ) -> ScanFinding {
        let hasAppGroups = !context.appGroups.isEmpty

        // Pre-gating check for App-Group-independent APFS inode enumeration primitives (`bad_query` / CM-05 `fsgetpath`).
        let standalonePathEnumMatches: [SignatureCatalog.Rule] = details.symbols.compactMap { sym in
            let cleanSym = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
            return SignatureCatalog.pathEnumerationSymbols[cleanSym] ?? SignatureCatalog.pathEnumerationSymbols[sym]
        }
        
        // 1. Layer 1 Gating Check (only fast-paths when both App Groups AND standalone fsgetpath are absent)
        let gating = EntitlementGating.evaluate(hasAppGroups: hasAppGroups, appGroups: context.appGroups)
        if gating.isGatedOut && standalonePathEnumMatches.isEmpty {
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
        var matchedSymbols: [String] = []
        var pathEnumerationDetected = false
        var dynamicLoadingDetected = false
        var symlinkDetected = false
        
        // 2. Scan Linked Dylibs (requires App Group precondition)
        if !gating.isGatedOut {
            for dylib in details.linkedDylibs {
                for (pattern, rule) in SignatureCatalog.dylibRules {
                    if dylib.contains(pattern) || dylib.hasSuffix(pattern) {
                        indicators.append(rule.toIndicator(at: "LC_LOAD_DYLIB: \(dylib)"))
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
                indicators.append(rule.toIndicator(at: "LC_SYMTAB: \(sym)"))
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
                        indicators.append(rule.toIndicator(at: "__TEXT: \(pattern)"))
                        matchedSymbols.append(pattern)
                    }
                }
                
                // Container metadata files
                for (pattern, rule) in SignatureCatalog.metadataFileRules {
                    if str.contains(pattern) {
                        indicators.append(rule.toIndicator(at: "__TEXT: \(pattern)"))
                        matchedSymbols.append(pattern)
                    }
                }
            }
        }
        
        // Check Path Leak Combination: fsgetpath + /Containers/Data/ or /Containers/Shared/
        let hasContainerPathStr = details.textStrings.contains { str in
            SignatureCatalog.containerPathSubstrings.contains { str.contains($0) }
        }
        if pathEnumerationDetected {
            if hasContainerPathStr {
                let targetSub = details.textStrings.first { s in SignatureCatalog.containerPathSubstrings.contains { s.contains($0) } } ?? "/Containers/Data/"
                let sig = "fsgetpath:\(targetSub)"
                indicators.append(ThreatIndicator(
                    signature: sig,
                    description: "Path leak brute-force targeting application containers (fsgetpath combined with container prefix)",
                    category: "Sandbox Enumeration",
                    location: "Mach-O (Symbol + String)",
                    severity: .highRisk
                ))
            } else {
                indicators.append(ThreatIndicator(
                    signature: "fsgetpath",
                    description: "APFS file system inode brute-force primitive",
                    category: "Sandbox Enumeration",
                    location: "LC_SYMTAB",
                    severity: .highRisk
                ))
            }
        }
        
        // 5. Evaluate Behavioral Tuple:
        // cryptid == 0 + application-groups + (dlopen && dlsym) + (symlink || sandbox_extension_consume || fsgetpath)
        let hasSandboxConsume = matchedSymbols.contains("sandbox_extension_consume") || details.symbols.contains { $0.contains("sandbox_extension_consume") }
        if details.cryptid == 0 && !gating.isGatedOut && dynamicLoadingDetected && (symlinkDetected || hasSandboxConsume || pathEnumerationDetected) {
            let alreadyHasExplicitExploit = indicators.contains { $0.severity == .highRisk && $0.category == "Private API Symbol" }
            if !alreadyHasExplicitExploit {
                indicators.append(SignatureCatalog.behavioralTupleRule.toIndicator())
            }
        }
        
        // 6. Evaluate Dynamic Loading Alone Heuristic:
        // App Groups + dlopen + dlsym without high risk exploit APIs -> Caution
        let hasHighRisk = indicators.contains { $0.severity == .highRisk }
        if !hasHighRisk && dynamicLoadingDetected && !gating.isGatedOut {
            indicators.append(SignatureCatalog.dynamicLoadingCautionRule.toIndicator())
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
            remediation = "检测到未经授权的 containermanagerd 跨沙盒利用特征，建议立即卸载或隔离该应用。"
        } else if finalRisk == .knownTool {
            remediation = "该应用匹配已知开源安全审计工具白名单（\(whitelistedToolName ?? "Known Tool")），由授权开发者签署。"
        } else if finalRisk == .caution {
            remediation = "应用声明了 App Group 共享容器权限并包含动态符号解析能力，建议持续关注。"
        } else {
            if details.isFairPlayEncrypted {
                remediation = "App Store / TestFlight 官方发布应用，FairPlay DRM 加密。未在非加密段发现越权特征，状态安全。"
            } else {
                remediation = "未发现任何跨容器越权特征，状态安全。"
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
