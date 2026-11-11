//
//  CLIConfig.swift
//  WQGuardCore
//
//  Configuration model, error types, and format enums for wqguard-cli.
//

import Foundation

// MARK: - 1. Metadata Constants
public enum WQGuardCLIMetadata: Sendable {
    public static let version = "1.0.0"

    public static var platformArchitecture: String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return "unknown"
        #endif
    }

    public static var versionString: String {
        "WQGuard v\(version) (Darwin \(platformArchitecture))"
    }
}

// MARK: - 2. CLI Errors
public enum CLIError: Error, LocalizedError, Equatable, Sendable {
    case unrecognizedOption(String)
    case missingArgument(option: String, expected: String)
    case invalidFormat(String)
    case invalidOSVersion(String)
    case fileNotFound(String)
    case missingAction
    case writeFailed(path: String, reason: String)
    case generic(String)

    public var errorDescription: String? {
        switch self {
        case .unrecognizedOption(let opt):
            return "wqguard-cli error: unrecognized option '\(opt)'"
        case .missingArgument(let opt, let exp):
            return "wqguard-cli error: option '\(opt)' requires an argument \(exp)"
        case .invalidFormat(let fmt):
            return "wqguard-cli error: invalid format '\(fmt)'. Supported formats: text, json, markdown"
        case .invalidOSVersion(let ver):
            return "wqguard-cli error: invalid OS version string '\(ver)'"
        case .fileNotFound(let path):
            return "wqguard-cli error: target file or directory not found: \(path)"
        case .missingAction:
            return "wqguard-cli error: no action specified. Use --scan-system, --ipa, --container, --firmware-radar, --export-surge, --version, or --help."
        case .writeFailed(let path, let reason):
            return "wqguard-cli error: failed to write output to '\(path)': \(reason)"
        case .generic(let msg):
            return "wqguard-cli error: \(msg)"
        }
    }
}

// MARK: - 3. Output Format Enum
public enum OutputFormat: String, CaseIterable, Sendable {
    case text
    case json
    case markdown

    public init?(rawValueCaseInsensitive: String) {
        let lower = rawValueCaseInsensitive.lowercased()
        if lower == "text" || lower == "txt" {
            self = .text
        } else if lower == "json" {
            self = .json
        } else if lower == "markdown" || lower == "md" {
            self = .markdown
        } else {
            return nil
        }
    }
}

// MARK: - 4. Parsed Configuration Model
public struct CLIConfig: Equatable, Sendable {
    public var scanSystem: Bool = false
    public var ipaPath: String? = nil
    public var containerPath: String? = nil
    public var firmwareRadar: Bool = false
    public var firmwareVersion: String? = nil
    public var exportSurgePath: String? = nil
    public var format: OutputFormat = .text
    public var outPath: String? = nil
    public var whitelistedBundleIDs: [String] = []
    public var showVersion: Bool = false
    public var showHelp: Bool = false

    public init(
        scanSystem: Bool = false,
        ipaPath: String? = nil,
        containerPath: String? = nil,
        firmwareRadar: Bool = false,
        firmwareVersion: String? = nil,
        exportSurgePath: String? = nil,
        format: OutputFormat = .text,
        outPath: String? = nil,
        whitelistedBundleIDs: [String] = [],
        showVersion: Bool = false,
        showHelp: Bool = false
    ) {
        self.scanSystem = scanSystem
        self.ipaPath = ipaPath
        self.containerPath = containerPath
        self.firmwareRadar = firmwareRadar
        self.firmwareVersion = firmwareVersion
        self.exportSurgePath = exportSurgePath
        self.format = format
        self.outPath = outPath
        self.whitelistedBundleIDs = whitelistedBundleIDs
        self.showVersion = showVersion
        self.showHelp = showHelp
    }

    public var hasAction: Bool {
        scanSystem || ipaPath != nil || containerPath != nil ||
        firmwareRadar || exportSurgePath != nil || showVersion || showHelp
    }
}
