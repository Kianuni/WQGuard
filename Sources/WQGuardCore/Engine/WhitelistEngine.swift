//
//  WhitelistEngine.swift
//  WQGuardCore
//
//  Thread-safe known-tool whitelist engine with multi-criteria matching,
//  dynamic user configuration, and transparent rule toggling.
//

import Foundation

/// Represents a known or user-configured tool rule in the whitelist.
public struct WhitelistedTool: Identifiable, Codable, Sendable, Equatable {
    public var id: String { name }
    
    /// Display name of the known tool.
    public let name: String
    
    /// User-facing description explaining the purpose and origin of the tool.
    public var description: String
    
    /// Patterns for allowed bundle identifiers (supports exact, prefix "prefix*", or glob "com.*.name").
    public var allowedBundleIds: [String]
    
    /// Patterns for allowed App Groups (supports exact, prefix "group.prefix*", or glob "group.*.name").
    public var allowedAppGroups: [String]
    
    /// Optional developer Team IDs allowed to sign this tool. If nil or empty, team ID check is skipped.
    public var allowedTeamIds: [String]?
    
    /// Exploit symbols/signatures expected for this tool (e.g. libsystem_containermanager.dylib).
    public var expectedSignatures: [String]
    
    /// Whether this whitelist rule is active.
    public var isEnabled: Bool
    
    /// Indicates whether this rule is one of the built-in defaults or user-added.
    public var isBuiltIn: Bool

    /// Primary initializer with Array parameters.
    public init(
        name: String,
        allowedBundleIds: [String] = [],
        allowedAppGroups: [String] = [],
        allowedTeamIds: [String]? = nil,
        expectedSignatures: [String] = [],
        description: String = "",
        isEnabled: Bool = true,
        isBuiltIn: Bool = false
    ) {
        self.name = name
        self.allowedBundleIds = allowedBundleIds
        self.allowedAppGroups = allowedAppGroups
        self.allowedTeamIds = allowedTeamIds
        self.expectedSignatures = expectedSignatures
        self.description = description
        self.isEnabled = isEnabled
        self.isBuiltIn = isBuiltIn
    }

    /// Convenience initializer supporting Set parameters for PROJECT.md contract compatibility.
    public init(
        name: String,
        allowedBundleIds: Set<String>,
        allowedAppGroups: Set<String> = [],
        expectedSignatures: Set<String> = [],
        description: String = "",
        allowedTeamIds: Set<String>? = nil,
        isEnabled: Bool = true,
        isBuiltIn: Bool = false
    ) {
        self.init(
            name: name,
            allowedBundleIds: Array(allowedBundleIds).sorted(),
            allowedAppGroups: Array(allowedAppGroups).sorted(),
            allowedTeamIds: allowedTeamIds.map { Array($0).sorted() },
            expectedSignatures: Array(expectedSignatures).sorted(),
            description: description,
            isEnabled: isEnabled,
            isBuiltIn: isBuiltIn
        )
    }
}

/// Pattern matching utility supporting exact matches, prefix matches, and glob wildcards.
public enum PatternMatcher {
    internal static let asciiWhitespace = CharacterSet(charactersIn: " \t\r\n")

    /// Returns true if the string contains any control, format, zero-width, soft-hyphen, variation-selector, or non-printable scalar.
    internal static func containsForbiddenScalar(_ s: String) -> Bool {
        for scalar in s.unicodeScalars {
            let v = scalar.value
            if v <= 0x1F || (v >= 0x7F && v <= 0x9F) || v == 0x00AD
                || (v >= 0x200B && v <= 0x200F)
                || (v >= 0x2028 && v <= 0x202F)
                || (v >= 0x2060 && v <= 0x206F)
                || (v >= 0xFE00 && v <= 0xFE0F)
                || v == 0xFEFF
                || (v >= 0xE0100 && v <= 0xE01EF) {
                return true
            }
            let cat = scalar.properties.generalCategory
            if cat == .control || cat == .format {
                return true
            }
        }
        return false
    }

    /// Strict RFC-1034 / Apple CFBundleIdentifier ASCII character check: non-empty and every byte in `[A-Za-z0-9.-]`.
    internal static func isStrictIdentifierASCII(_ s: String) -> Bool {
        guard !s.isEmpty else { return false }
        return s.utf8.allSatisfy { b in
            (b >= 0x41 && b <= 0x5A)
                || (b >= 0x61 && b <= 0x7A)
                || (b >= 0x30 && b <= 0x39)
                || b == 0x2E
                || b == 0x2D
        }
    }

    /// Evaluates whether a value matches a pattern.
    /// Supports exact matching, prefix with `*` suffix, and general glob matching (`*` and `?`).
    public static func matches(pattern: String, value: String) -> Bool {
        let trimmedPattern = pattern.trimmingCharacters(in: asciiWhitespace)
        let trimmedValue = value.trimmingCharacters(in: asciiWhitespace)

        guard !containsForbiddenScalar(trimmedPattern), !containsForbiddenScalar(trimmedValue) else {
            return false
        }

        let patternIsASCII = trimmedPattern.utf8.allSatisfy { $0 < 0x80 }
        let valueIsASCII = trimmedValue.utf8.allSatisfy { $0 < 0x80 }

        // 1. Exact match (strict ASCII byte fold when pattern is ASCII; canonical compare only for explicit non-ASCII custom patterns)
        if !trimmedPattern.contains("*") && !trimmedPattern.contains("?") {
            if patternIsASCII {
                return valueIsASCII && trimmedPattern.lowercased() == trimmedValue.lowercased()
            }
            return trimmedPattern.caseInsensitiveCompare(trimmedValue) == .orderedSame
        }
        
        // 2. Simple prefix fast path (e.g., "prefix*")
        if trimmedPattern.hasSuffix("*") && !trimmedPattern.dropLast().contains("*") && !trimmedPattern.contains("?") {
            let prefix = String(trimmedPattern.dropLast())
            if prefix.isEmpty { return true }
            if patternIsASCII && valueIsASCII {
                return trimmedValue.lowercased().hasPrefix(prefix.lowercased())
            }
            return trimmedValue.range(of: prefix, options: [.anchored, .caseInsensitive]) != nil
        }
        
        // 3. Simple suffix fast path (e.g., "*suffix")
        if trimmedPattern.hasPrefix("*") && !trimmedPattern.dropFirst().contains("*") && !trimmedPattern.contains("?") {
            let suffix = String(trimmedPattern.dropFirst())
            if suffix.isEmpty { return true }
            if patternIsASCII && valueIsASCII {
                return trimmedValue.lowercased().hasSuffix(suffix.lowercased())
            }
            return trimmedValue.range(of: suffix, options: [.backwards, .anchored, .caseInsensitive]) != nil
        }
        
        // 4. General glob wildcard matching (e.g. "com.*.gestaltx")
        let escaped = NSRegularExpression.escapedPattern(for: trimmedPattern)
        let regexPattern = "^" + escaped
            .replacingOccurrences(of: "\\*", with: ".*")
            .replacingOccurrences(of: "\\?", with: ".") + "$"
        
        guard let regex = try? NSRegularExpression(pattern: regexPattern, options: [.caseInsensitive]) else {
            return false
        }
        let range = NSRange(trimmedValue.startIndex..<trimmedValue.endIndex, in: trimmedValue)
        return regex.firstMatch(in: trimmedValue, range: range) != nil
    }
}

/// Thread-safe whitelist evaluation engine conforming to `Sendable`.
public final class WhitelistEngine: @unchecked Sendable {
    /// Shared singleton instance.
    public static let shared = WhitelistEngine()

    private let lock = NSLock()
    private var tools: [WhitelistedTool]

    /// Built-in default whitelist containing only WQGuard's own self-identity rule.
    /// Third-party sideloading tools and research utilities are strictly zero-trust and NEVER built-in.
    public static var defaultTools: [WhitelistedTool] {
        [
            WhitelistedTool(
                name: "WQGuard",
                allowedBundleIds: [
                    "com.wqguard.app",
                    "com.wqguard.app.debug",
                    "com.antigravity.wqguard"
                ],
                allowedAppGroups: [
                    "group.com.wqguard.app",
                    "group.com.wqguard.scanner"
                ],
                expectedSignatures: [
                    IOCTokenArmor.tCqCreate,
                    "com.apple.containermanagerd",
                    "com.apple.containermanagerd.system",
                    ".com.apple.mobile_container_manager.metadata.plist",
                    ".csstore",
                    "com.apple.LaunchServices-",
                    "dlopen",
                    "dlsym"
                ],
                description: WQLocale.pick(
                    en: "Self-identity whitelist for WQGuard security scanner",
                    zh: "WQGuard 安全审计器自身身份白名单规则"
                ),
                isEnabled: true,
                isBuiltIn: true
            )
        ]
    }

    /// Initializes a WhitelistEngine instance with specified initial rules (defaults to built-in WQGuard rule).
    public init(tools: [WhitelistedTool] = WhitelistEngine.defaultTools) {
        self.tools = tools
    }

    /// Returns a copy of all current whitelist rules.
    public var allTools: [WhitelistedTool] {
        lock.lock()
        defer { lock.unlock() }
        return tools
    }

    /// Looks up a specific tool by name (case-insensitive).
    public func tool(named name: String) -> WhitelistedTool? {
        lock.lock()
        defer { lock.unlock() }
        return tools.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }
    }

    /// Registers a custom tool rule or updates an existing non-built-in rule with the same name.
    /// Built-in default rules (`WQGuard`) can never be overwritten or forged via custom registration.
    public func registerCustomTool(_ tool: WhitelistedTool) {
        lock.lock()
        defer { lock.unlock() }
        var customTool = tool
        customTool.isBuiltIn = false
        if let idx = tools.firstIndex(where: { $0.name.caseInsensitiveCompare(customTool.name) == .orderedSame }) {
            guard !tools[idx].isBuiltIn else { return }
            tools[idx] = customTool
        } else {
            tools.append(customTool)
        }
    }

    /// Enables or disables a whitelist rule by name.
    public func toggleTool(named name: String, isEnabled: Bool) {
        lock.lock()
        defer { lock.unlock() }
        if let idx = tools.firstIndex(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) {
            tools[idx].isEnabled = isEnabled
        }
    }

    /// Removes a non-built-in tool rule by name.
    public func removeTool(named name: String) {
        lock.lock()
        defer { lock.unlock() }
        tools.removeAll { !$0.isBuiltIn && $0.name.caseInsensitiveCompare(name) == .orderedSame }
    }

    /// Resets all rules to the built-in default WQGuard rule.
    public func resetToDefaults() {
        lock.lock()
        defer { lock.unlock() }
        tools = WhitelistEngine.defaultTools
    }

    /// Queries whether the target application identity and entitlement profile matches an active whitelist rule.
    ///
    /// - Parameters:
    ///   - bundleId: Candidate bundle identifier.
    ///   - appGroups: Array of App Group identifiers declared in candidate's entitlements.
    ///   - matchedSignatures: Array of detected exploit symbols or indicators.
    ///   - teamId: Optional candidate code signing Team ID.
    /// - Returns: A tuple containing whether the application is whitelisted and the matching tool's name.
    public func isWhitelisted(
        bundleId: String,
        appGroups: [String] = [],
        matchedSignatures: [String] = [],
        teamId: String? = nil
    ) -> (isWhitelisted: Bool, toolName: String?) {
        evaluateCandidateBundleIds(
            [bundleId],
            appGroups: appGroups,
            matchedSignatures: matchedSignatures,
            teamId: teamId
        )
    }

    /// Queries whether a single active whitelist rule simultaneously covers both `primaryBundleId` and `secondaryBundleId`
    /// (used when correlating an installed registry record with a suffix-modified sideloaded package).
    public func isWhitelistedForBoth(
        primaryBundleId: String,
        secondaryBundleId: String,
        appGroups: [String] = [],
        matchedSignatures: [String] = [],
        teamId: String? = nil
    ) -> (isWhitelisted: Bool, toolName: String?) {
        if primaryBundleId.trimmingCharacters(in: PatternMatcher.asciiWhitespace)
            .caseInsensitiveCompare(secondaryBundleId.trimmingCharacters(in: PatternMatcher.asciiWhitespace)) == .orderedSame {
            return evaluateCandidateBundleIds(
                [primaryBundleId],
                appGroups: appGroups,
                matchedSignatures: matchedSignatures,
                teamId: teamId
            )
        }
        return evaluateCandidateBundleIds(
            [primaryBundleId, secondaryBundleId],
            appGroups: appGroups,
            matchedSignatures: matchedSignatures,
            teamId: teamId
        )
    }

    /// Evaluates whether an existing `ScanFinding` qualifies for whitelist downgrade, enforcing
    /// `isWhitelistEligible`, `correlatedPackageBundleId` dual-bundle matching, `isTeamIdWhitelistVerified`,
    /// and complete threat-indicator signature coverage.
    public func evaluateFindingWhitelist(_ finding: ScanFinding) -> (isWhitelisted: Bool, toolName: String?) {
        #if os(iOS)
        let runningSelfBid = Bundle.main.bundleIdentifier ?? "com.wqguard.app"
        #else
        let runningSelfBid = ""
        #endif
        return evaluateFindingWhitelist(finding, runningSelfBundleId: runningSelfBid)
    }

    public static func isNonWhitelistableStructuralSignature(_ sig: String) -> Bool {
        sig.hasPrefix("SymlinkEscape:")
            || sig.hasPrefix("MalformedPackage:")
            || sig.hasPrefix("CorruptMachO:")
            || sig == "AppexExecutableTraversal"
            || sig == "CODE_SIGNATURE_SEAL_MISMATCH"
            || sig == "BUNDLE_ESCAPING_SYMLINK"
            || sig == "ArchiveSymlinkCollision"
            || sig == "ArchiveSymlinkQuotaExceeded"
            || sig.hasPrefix("CONTAINER_")
            || sig == "SYSTEMGROUP_SUPERVISION_DETECTED"
            || sig.hasPrefix("CloudConfigurationDetails.")
            || sig == "AppleSystemAppGroup"
            || sig.hasPrefix("AppleSystemAppGroup(")
    }

    private static func isHighRiskImpersonationSignature(_ sig: String) -> Bool {
        guard sig.hasPrefix("IMPERSONATION:") else { return false }
        let brandName = String(sig.dropFirst("IMPERSONATION:".count))
        return ExpandedThreatCatalog.targetBrands.contains(where: { $0.name == brandName })
            || brandName.contains("Alipay")
    }

    private static func isNonResearchHighRiskThreatSignature(_ sig: String) -> Bool {
        if sig == "com.apple.private.security.no-container"
            || sig == "com.apple.private.security.no-sandbox"
            || sig == "com.apple.private.security.container-required"
            || sig == "com.apple.private.MobileContainerManager.allowed"
            || sig == "com.apple.private.security.storage.AppDataContainers"
            || sig == "platform-application"
            || sig == "com.apple.private.tcc.allow"
            || sig == "com.apple.private.tcc.allow-prompting"
            || sig == "keychain-access-groups(*)"
            || sig == "arm64:svc_0x80"
            || sig.contains(IOCTokenArmor.tPhotoLibFw)
            || sig.contains(IOCTokenArmor.tAssetsLibFw)
            || sig == IOCTokenArmor.tPLPhotoLib
            || sig == "_OBJC_CLASS_$_\(IOCTokenArmor.tPLPhotoLib)"
            || sig.hasPrefix("-[\(IOCTokenArmor.tPLPhotoLib)")
            || sig.hasPrefix("+[\(IOCTokenArmor.tPLPhotoLib)")
            || sig.contains(IOCTokenArmor.tPLPhotoLib)
            || sig == IOCTokenArmor.tPhotoLibSvc
            || sig.contains(IOCTokenArmor.tSysPhotoLib)
            || sig == "com.apple.photos.bourgeoisie" {
            return true
        }
        if sig.hasPrefix("MobileGestaltTamper:")
            || sig.hasPrefix("BookRestore:")
            || sig.hasPrefix("CVE-2026-")
            || sig.hasPrefix("com.apple.private.photos.")
            || (sig.hasPrefix("UIBackgroundModes(") && sig.hasSuffix("+\(IOCTokenArmor.tUIPasteboard)")) {
            return true
        }
        return isHighRiskImpersonationSignature(sig)
    }

    internal func evaluateFindingWhitelist(
        _ finding: ScanFinding,
        runningSelfBundleId: String
    ) -> (isWhitelisted: Bool, toolName: String?) {
        guard finding.evidence.escapingSymlinks.isEmpty,
              !finding.indicators.contains(where: {
                  Self.isNonWhitelistableStructuralSignature($0.signature)
                      || ($0.severity == .highRisk && $0.signature.hasPrefix("IMPERSONATION:"))
              }),
              !finding.evidence.matchedSymbols.contains(where: {
                  Self.isNonWhitelistableStructuralSignature($0) || Self.isHighRiskImpersonationSignature($0)
              }) else {
            return (false, nil)
        }

        var sigSet = Set(finding.evidence.matchedSymbols)
        for ind in finding.indicators {
            if ind.signature != "com.apple.security.application-groups"
                && ind.signature != SignatureCatalog.dynamicLoadingCautionRule.pattern {
                sigSet.insert(ind.signature)
            }
        }
        let allSignatures = Array(sigSet)

        if finding.evidence.isWhitelistEligible {
            let candidateTeam = finding.evidence.isTeamIdWhitelistVerified ? finding.teamId : nil

            let standardResult: (isWhitelisted: Bool, toolName: String?)
            if let secondaryBid = finding.evidence.correlatedPackageBundleId, !secondaryBid.isEmpty {
                standardResult = isWhitelistedForBoth(
                    primaryBundleId: finding.bundleId,
                    secondaryBundleId: secondaryBid,
                    appGroups: finding.evidence.appGroups,
                    matchedSignatures: allSignatures,
                    teamId: candidateTeam
                )
            } else {
                standardResult = isWhitelisted(
                    bundleId: finding.bundleId,
                    appGroups: finding.evidence.appGroups,
                    matchedSignatures: allSignatures,
                    teamId: candidateTeam
                )
            }
            if standardResult.isWhitelisted {
                return standardResult
            }
        }

        // Running iOS host self-whitelist fallback for enterprise/sideload-resigned WQGuard
        let cleanSelfBid = runningSelfBundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanRecBid = finding.bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanCorrelatedBid = finding.evidence.correlatedPackageBundleId?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let hasDistinctCorrelatedBid = !cleanCorrelatedBid.isEmpty
            && cleanCorrelatedBid.caseInsensitiveCompare(cleanRecBid) != .orderedSame
        let allowSelfFallbackForDepth: Bool
        switch finding.evidence.auditDepth {
        case .registryEntitlements:
            allowSelfFallbackForDepth = true
        case .fullBinaryAndRegistry:
            allowSelfFallbackForDepth = finding.evidence.isWhitelistEligible
        case .onDeviceProbe:
            allowSelfFallbackForDepth = false
        }
        if !cleanSelfBid.isEmpty,
           allowSelfFallbackForDepth,
           !hasDistinctCorrelatedBid,
           !finding.indicators.contains(where: { $0.severity == .highRisk }),
           (cleanRecBid.caseInsensitiveCompare(cleanSelfBid) == .orderedSame
               || (cleanRecBid.caseInsensitiveCompare("com.wqguard.app") == .orderedSame
                   && finding.displayName.trimmingCharacters(in: .whitespacesAndNewlines) == "WQGuard")),
           let wqTool = tool(named: "WQGuard"), wqTool.isEnabled {
            let hasDisallowedGroup = finding.evidence.appGroups.contains {
                !PatternMatcher.isStrictIdentifierASCII($0)
                    || ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup($0)
            }
            if !hasDisallowedGroup {
                let allExpected = allSignatures.allSatisfy { sig in
                    let cleanSig = sig.hasPrefix("_") ? String(sig.dropFirst()) : sig
                    return wqTool.expectedSignatures.contains { pattern in
                        let cleanPat = pattern.hasPrefix("_") ? String(pattern.dropFirst()) : pattern
                        return PatternMatcher.matches(pattern: pattern, value: sig)
                            || PatternMatcher.matches(pattern: cleanPat, value: cleanSig)
                    }
                }
                if allExpected {
                    return (true, wqTool.name)
                }
            }
        }

        return (false, nil)
    }

    private func evaluateCandidateBundleIds(
        _ requiredBundleIds: [String],
        appGroups: [String],
        matchedSignatures: [String],
        teamId: String?
    ) -> (isWhitelisted: Bool, toolName: String?) {
        guard !requiredBundleIds.isEmpty else {
            return (false, nil)
        }

        // Structurally hostile archive/package/Mach-O anomalies and high-risk impersonation drainers can never be downgraded by any whitelist rule
        if matchedSignatures.contains(where: {
            Self.isNonWhitelistableStructuralSignature($0) || Self.isHighRiskImpersonationSignature($0)
        }) {
            return (false, nil)
        }

        lock.lock()
        let currentTools = tools
        lock.unlock()

        let requiresMultipleDistinctBundles = requiredBundleIds.count > 1

        for tool in currentTools where tool.isEnabled {
            let cleanBundlePatterns = tool.allowedBundleIds
                .map { $0.trimmingCharacters(in: PatternMatcher.asciiWhitespace) }
                .filter { !$0.isEmpty }
            let cleanGroupPatterns = tool.allowedAppGroups
                .map { $0.trimmingCharacters(in: PatternMatcher.asciiWhitespace) }
                .filter { !$0.isEmpty }
            let cleanTeamIds = (tool.allowedTeamIds ?? [])
                .map { $0.trimmingCharacters(in: PatternMatcher.asciiWhitespace) }
                .filter { !$0.isEmpty }

            // Fail-closed: reject degenerate or wildcard-only rules (e.g. "*", "?") that lack any concrete identity anchor
            let hasConcretePattern: ([String]) -> Bool = { patterns in
                patterns.contains { pat in
                    let stripped = pat.filter { $0 != "*" && $0 != "?" && $0 != "." }
                    return !stripped.isEmpty
                }
            }
            let hasConcreteTeam = cleanTeamIds.contains { tid in
                let stripped = tid.filter { $0 != "*" && $0 != "?" }
                return !stripped.isEmpty
            }
            guard hasConcretePattern(cleanBundlePatterns) || hasConcretePattern(cleanGroupPatterns) || hasConcreteTeam else {
                continue
            }
            // Reject rules where allowedBundleIds contains a pure wildcard ("*" / "?") without a concrete Team ID anchor
            if cleanBundlePatterns.contains(where: { $0.allSatisfy { $0 == "*" || $0 == "?" || $0 == "." } }) && !hasConcreteTeam {
                continue
            }
            // Bridging two distinct correlated bundle IDs requires an explicit allowedBundleIds pattern covering both
            if requiresMultipleDistinctBundles && cleanBundlePatterns.isEmpty {
                continue
            }

            if tool.isBuiltIn {
                guard requiredBundleIds.allSatisfy({ PatternMatcher.isStrictIdentifierASCII($0) }),
                      appGroups.allSatisfy({ PatternMatcher.isStrictIdentifierASCII($0) }) else {
                    continue
                }
            }

            // 1. Bundle ID match check across ALL required candidate bundle IDs
            if !cleanBundlePatterns.isEmpty {
                let allBundlesMatch = requiredBundleIds.allSatisfy { candidateBid in
                    cleanBundlePatterns.contains { pattern in
                        if pattern.utf8.allSatisfy({ $0 < 0x80 }) {
                            let candidate = candidateBid.trimmingCharacters(in: PatternMatcher.asciiWhitespace)
                            let patternHasUnderscore = pattern.utf8.contains(0x5F)
                            let allowedCharsOk = candidate.utf8.allSatisfy { b in
                                (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39)
                                    || b == 0x2E || b == 0x2D || (patternHasUnderscore && b == 0x5F)
                            }
                            guard !candidate.isEmpty && allowedCharsOk else { return false }
                        }
                        return PatternMatcher.matches(pattern: pattern, value: candidateBid)
                    }
                }
                guard allBundlesMatch else { continue }
            }

            // 2. App Group match check:
            // - Reject unauthorized Apple internal system App Groups (`group.com.apple.*` / `systemgroup.com.apple.*`) on non-Apple bundle IDs
            //   unless explicitly matched by a concrete group pattern.
            // - Enforce `allSatisfy` across ALL rules (both built-in and custom) whenever `allowedAppGroups` is non-empty so a re-signed
            //   whitelisted tool can never piggyback third-party victim App Groups (e.g. `group.io.metamask`, `group.org.telegram`).
            let concreteGroupPatterns = cleanGroupPatterns.filter { pat in
                !pat.filter { $0 != "*" && $0 != "?" && $0 != "." }.isEmpty
            }
            let matchesGroupPattern: (String, String) -> Bool = { pattern, group in
                if pattern.utf8.allSatisfy({ $0 < 0x80 }) {
                    let candidate = group.trimmingCharacters(in: PatternMatcher.asciiWhitespace)
                    let patternHasUnderscore = pattern.utf8.contains(0x5F)
                    let allowedCharsOk = candidate.utf8.allSatisfy { b in
                        (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39)
                            || b == 0x2E || b == 0x2D || (patternHasUnderscore && b == 0x5F)
                    }
                    guard !candidate.isEmpty && allowedCharsOk else { return false }
                }
                return PatternMatcher.matches(pattern: pattern, value: group)
            }

            if !tool.isBuiltIn && appGroups.contains(where: { ExpandedThreatCatalog.isProtectedVictimOrAppleSystemAppGroup($0) }) {
                continue
            }

            let allCandidateBidsAreApple = requiredBundleIds.allSatisfy {
                $0.trimmingCharacters(in: PatternMatcher.asciiWhitespace).lowercased().hasPrefix("com.apple.")
            }
            let requiresExplicitAppleGroupPattern = !tool.isBuiltIn || !allCandidateBidsAreApple
            let hasUnauthorizedAppleSystemGroup = requiresExplicitAppleGroupPattern && appGroups.contains { grp in
                let lowerGrp = ExpandedThreatCatalog.foldConfusablesToASCII(grp)
                    .trimmingCharacters(in: PatternMatcher.asciiWhitespace)
                    .lowercased()
                guard lowerGrp.hasPrefix("group.com.apple.")
                    || lowerGrp.hasPrefix("systemgroup.com.apple.")
                    || InstalledAppRegistryScanner.isAppleOwnedAppGroup(lowerGrp) else {
                    return false
                }
                return !concreteGroupPatterns.contains { pattern in matchesGroupPattern(pattern, grp) }
            }
            guard !hasUnauthorizedAppleSystemGroup else { continue }

            if !cleanGroupPatterns.isEmpty {
                guard !concreteGroupPatterns.isEmpty,
                      !appGroups.isEmpty,
                      appGroups.allSatisfy({ group in
                          concreteGroupPatterns.contains { pattern in
                              matchesGroupPattern(pattern, group)
                          }
                      }) else {
                    continue
                }
            }

            // 3. Team ID match check (if rule explicitly restricts Team IDs)
            if !cleanTeamIds.isEmpty {
                let trimmedCandidateTeam = teamId?.trimmingCharacters(in: PatternMatcher.asciiWhitespace) ?? ""
                guard !trimmedCandidateTeam.isEmpty,
                      !PatternMatcher.containsForbiddenScalar(trimmedCandidateTeam),
                      cleanTeamIds.contains(where: { $0.caseInsensitiveCompare(trimmedCandidateTeam) == .orderedSame }) else {
                    continue
                }
            }

            // 4. Matched signatures subset check (prevents Trojanized builds carrying unexpected exploit primitives from spoofing a whitelist rule)
            if tool.expectedSignatures.isEmpty {
                if matchedSignatures.contains(where: Self.isNonResearchHighRiskThreatSignature) {
                    continue
                }
            } else if !matchedSignatures.isEmpty {
                let allExpected = matchedSignatures.allSatisfy { sig in
                    let cleanSig = sig.hasPrefix("_") ? String(sig.dropFirst()) : sig
                    return tool.expectedSignatures.contains { pattern in
                        let cleanPattern = pattern.hasPrefix("_") ? String(pattern.dropFirst()) : pattern
                        return PatternMatcher.matches(pattern: pattern, value: sig)
                            || PatternMatcher.matches(pattern: cleanPattern, value: cleanSig)
                    }
                }
                guard allExpected else { continue }
            }

            // Successfully matched all criteria
            return (true, tool.name)
        }

        return (false, nil)
    }
}
