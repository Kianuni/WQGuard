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
    /// Evaluates whether a value matches a pattern.
    /// Supports exact matching, prefix with `*` suffix, and general glob matching (`*` and `?`).
    public static func matches(pattern: String, value: String) -> Bool {
        let trimmedPattern = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedValue = value.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // 1. Exact match (case-insensitive)
        if trimmedPattern.caseInsensitiveCompare(trimmedValue) == .orderedSame {
            return true
        }
        
        // 2. Simple prefix fast path (e.g., "prefix*")
        if trimmedPattern.hasSuffix("*") && !trimmedPattern.dropLast().contains("*") && !trimmedPattern.contains("?") {
            let prefix = String(trimmedPattern.dropLast())
            if prefix.isEmpty { return true }
            return trimmedValue.range(of: prefix, options: [.anchored, .caseInsensitive]) != nil
        }
        
        // 3. Simple suffix fast path (e.g., "*suffix")
        if trimmedPattern.hasPrefix("*") && !trimmedPattern.dropFirst().contains("*") && !trimmedPattern.contains("?") {
            let suffix = String(trimmedPattern.dropFirst())
            if suffix.isEmpty { return true }
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

    /// The 6 built-in transparent known tools.
    public static let defaultTools: [WhitelistedTool] = [
        WhitelistedTool(
            name: "Erosion",
            allowedBundleIds: ["com.jbdotparty.Erosion"],
            allowedAppGroups: ["group.com.jbdotparty.Erosion.WQ"],
            expectedSignatures: [
                "libsystem_containermanager.dylib",
                "container_query_create",
                "container_query_set_group_identifiers",
                "container_query_operation_set_part",
                "container_query_operation_set_flags",
                "container_copy_sandbox_token",
                "sandbox_extension_consume",
                "container_query_get_single_result"
            ],
            description: "Known open-source containermanagerd research utility by jbdotparty",
            isEnabled: true,
            isBuiltIn: true
        ),
        WhitelistedTool(
            name: "Erosion-CN",
            allowedBundleIds: ["com.jbdotparty.Erosion-*", "com.jbdotparty.Erosion.*", "com.jbdotparty.ErosionCN*"],
            allowedAppGroups: ["group.com.jbdotparty.Erosion*"],
            expectedSignatures: [
                "libsystem_containermanager.dylib",
                "container_query_create",
                "container_query_set_group_identifiers",
                "container_query_operation_set_part",
                "container_query_operation_set_flags",
                "container_copy_sandbox_token",
                "sandbox_extension_consume",
                "container_query_get_single_result"
            ],
            description: "Localized Erosion open-source utility distribution",
            isEnabled: true,
            isBuiltIn: true
        ),
        WhitelistedTool(
            name: "GestaltX",
            allowedBundleIds: ["com.*.gestaltx", "com.*gestaltx", "*.gestaltx", "com.straight-tamago.gestaltx"],
            allowedAppGroups: ["group.*.gestaltx", "group.*gestaltx", "*.gestaltx"],
            expectedSignatures: [
                "libsystem_containermanager.dylib",
                "container_query_create",
                "container_query_set_group_identifiers"
            ],
            description: "Known open-source MobileGestalt property inspection tool",
            isEnabled: true,
            isBuiltIn: true
        ),
        WhitelistedTool(
            name: "WQFiles",
            allowedBundleIds: ["cz.kolbi.wqfiles"],
            allowedAppGroups: ["group.cz.kolbi.wqfiles"],
            expectedSignatures: [
                "libsystem_containermanager.dylib",
                "container_query_create",
                "container_query_set_group_identifiers",
                "container_query_operation_set_part",
                "container_query_operation_set_flags",
                "container_copy_sandbox_token",
                "sandbox_extension_consume",
                "container_query_get_single_result"
            ],
            description: "Known open-source file manager utility by Kolbi using App Group container access",
            isEnabled: true,
            isBuiltIn: true
        ),
        WhitelistedTool(
            name: "WQFiles-CN",
            allowedBundleIds: ["cz.kolbi.wqfiles-*", "cz.kolbi.wqfiles.*", "cz.kolbi.wqfilesCN*", "cz.kolbi.wqfiles-cn*"],
            allowedAppGroups: ["group.cz.kolbi.wqfiles*"],
            expectedSignatures: [
                "libsystem_containermanager.dylib",
                "container_query_create",
                "container_query_set_group_identifiers",
                "container_query_operation_set_part",
                "container_query_operation_set_flags",
                "container_copy_sandbox_token",
                "sandbox_extension_consume",
                "container_query_get_single_result"
            ],
            description: "Localized WQFiles open-source utility distribution",
            isEnabled: true,
            isBuiltIn: true
        ),
        WhitelistedTool(
            name: "WQGuard",
            allowedBundleIds: [
                "com.wqguard.app",
                "com.wqguard.app.*",
                "com.antigravity.wqguard*"
            ],
            allowedAppGroups: [
                "group.com.wqguard.app",
                "group.com.wqguard.scanner"
            ],
            expectedSignatures: [
                "container_query_create",
                "container_query_get_single_result"
            ],
            description: "Self-identity whitelist for WQGuard security scanner",
            isEnabled: true,
            isBuiltIn: true
        )
    ]

    /// Initializes a WhitelistEngine instance with specified initial rules (defaults to the 6 built-ins).
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

    /// Resets all rules to the 6 default built-in tools.
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
            // 1. Bundle ID match check
            if !tool.allowedBundleIds.isEmpty {
                let matchesBundle = tool.allowedBundleIds.contains { pattern in
                    PatternMatcher.matches(pattern: pattern, value: bundleId)
                }
                guard matchesBundle else { continue }
            }

            // 2. App Group match check (Crucial for preventing bundle ID spoofing)
            if !tool.allowedAppGroups.isEmpty {
                let matchesAppGroup = appGroups.contains { group in
                    tool.allowedAppGroups.contains { pattern in
                        PatternMatcher.matches(pattern: pattern, value: group)
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

            // Successfully matched all criteria
            return (true, tool.name)
        }

        return (false, nil)
    }
}
