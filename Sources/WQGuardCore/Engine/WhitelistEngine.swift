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

    /// Returns true if the string contains any control, format, zero-width, soft-hyphen, or non-printable scalar.
    internal static func containsForbiddenScalar(_ s: String) -> Bool {
        for scalar in s.unicodeScalars {
            let v = scalar.value
            if v <= 0x1F || (v >= 0x7F && v <= 0x9F) || v == 0x00AD
                || (v >= 0x200B && v <= 0x200F)
                || (v >= 0x2028 && v <= 0x202F)
                || (v >= 0x2060 && v <= 0x206F)
                || v == 0xFEFF {
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

    /// Registers a custom tool rule or updates an existing rule with the same name.
    public func registerCustomTool(_ tool: WhitelistedTool) {
        lock.lock()
        defer { lock.unlock() }
        if let idx = tools.firstIndex(where: { $0.name.caseInsensitiveCompare(tool.name) == .orderedSame }) {
            tools[idx] = tool
        } else {
            tools.append(tool)
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

    /// Removes a tool rule by name.
    public func removeTool(named name: String) {
        lock.lock()
        defer { lock.unlock() }
        tools.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
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
        lock.lock()
        let currentTools = tools
        lock.unlock()

        for tool in currentTools where tool.isEnabled {
            if tool.isBuiltIn {
                guard PatternMatcher.isStrictIdentifierASCII(bundleId),
                      appGroups.allSatisfy({ PatternMatcher.isStrictIdentifierASCII($0) }) else {
                    continue
                }
            }

            // 1. Bundle ID match check
            if !tool.allowedBundleIds.isEmpty {
                let matchesBundle = tool.allowedBundleIds.contains { pattern in
                    if pattern.utf8.allSatisfy({ $0 < 0x80 }) {
                        let candidate = bundleId.trimmingCharacters(in: PatternMatcher.asciiWhitespace)
                        let patternHasUnderscore = pattern.utf8.contains(0x5F)
                        let allowedCharsOk = candidate.utf8.allSatisfy { b in
                            (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39)
                                || b == 0x2E || b == 0x2D || (patternHasUnderscore && b == 0x5F)
                        }
                        guard !candidate.isEmpty && allowedCharsOk else { return false }
                    }
                    return PatternMatcher.matches(pattern: pattern, value: bundleId)
                }
                guard matchesBundle else { continue }
            }

            // 2. App Group match check (Crucial for preventing bundle ID spoofing & piggybacked victim App Groups)
            if !tool.allowedAppGroups.isEmpty {
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
                let matchesAppGroup: Bool
                if tool.isBuiltIn {
                    matchesAppGroup = !appGroups.isEmpty && appGroups.allSatisfy { group in
                        tool.allowedAppGroups.contains { pattern in
                            matchesGroupPattern(pattern, group)
                        }
                    }
                } else {
                    matchesAppGroup = appGroups.contains { group in
                        tool.allowedAppGroups.contains { pattern in
                            matchesGroupPattern(pattern, group)
                        }
                    }
                }
                guard matchesAppGroup else { continue }
            }

            // 3. Team ID match check (if rule explicitly restricts Team IDs)
            if let allowedTeams = tool.allowedTeamIds, !allowedTeams.isEmpty {
                guard let candidateTeam = teamId, allowedTeams.contains(candidateTeam) else {
                    continue
                }
            }

            // 4. Matched signatures subset check (prevents Trojanized builds carrying unexpected exploit primitives from spoofing a whitelist rule)
            if !tool.expectedSignatures.isEmpty && !matchedSignatures.isEmpty {
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
