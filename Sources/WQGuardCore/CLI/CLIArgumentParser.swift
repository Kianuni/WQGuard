//
//  CLIArgumentParser.swift
//  WQGuardCore
//
//  Zero-dependency native Darwin argument parser, ANSI styler, and manual for wqguard-cli.
//

import Foundation
import Darwin

// MARK: - 1. Zero-Dependency Native Argument Parser
public struct CLIArgumentParser: Sendable {
    public static func parse(arguments: [String]) throws -> CLIConfig {
        var config = CLIConfig()
        let args = Array(arguments.dropFirst()) // drop executable path
        var idx = 0

        while idx < args.count {
            let arg = args[idx]

            if arg == "-h" || arg == "--help" {
                config.showHelp = true
                idx += 1
            } else if arg == "-v" || arg == "--version" {
                config.showVersion = true
                idx += 1
            } else if arg == "scan" {
                if idx + 1 < args.count && !args[idx + 1].hasPrefix("-") {
                    let target = args[idx + 1]
                    if target.lowercased().hasSuffix(".ipa") {
                        config.ipaPath = target
                    } else {
                        config.containerPath = target
                    }
                    idx += 2
                } else {
                    config.scanSystem = true
                    idx += 1
                }
            } else if arg == "-s" || arg == "--scan-system" {
                config.scanSystem = true
                idx += 1
            } else if arg == "-i" || arg == "--ipa" {
                idx += 1
                guard idx < args.count, !args[idx].hasPrefix("-") else {
                    throw CLIError.missingArgument(option: arg, expected: "<path>")
                }
                config.ipaPath = args[idx]
                idx += 1
            } else if arg.hasPrefix("--ipa=") {
                let val = String(arg.dropFirst("--ipa=".count))
                guard !val.isEmpty else { throw CLIError.missingArgument(option: "--ipa", expected: "<path>") }
                config.ipaPath = val
                idx += 1
            } else if arg.hasPrefix("-i=") {
                let val = String(arg.dropFirst("-i=".count))
                guard !val.isEmpty else { throw CLIError.missingArgument(option: "-i", expected: "<path>") }
                config.ipaPath = val
                idx += 1
            } else if arg == "-c" || arg == "--container" {
                idx += 1
                guard idx < args.count, !args[idx].hasPrefix("-") else {
                    throw CLIError.missingArgument(option: arg, expected: "<path>")
                }
                config.containerPath = args[idx]
                idx += 1
            } else if arg.hasPrefix("--container=") {
                let val = String(arg.dropFirst("--container=".count))
                guard !val.isEmpty else { throw CLIError.missingArgument(option: "--container", expected: "<path>") }
                config.containerPath = val
                idx += 1
            } else if arg.hasPrefix("-c=") {
                let val = String(arg.dropFirst("-c=".count))
                guard !val.isEmpty else { throw CLIError.missingArgument(option: "-c", expected: "<path>") }
                config.containerPath = val
                idx += 1
            } else if arg == "-r" || arg == "--firmware-radar" {
                config.firmwareRadar = true
                idx += 1
                // Optional argument: check if next token exists and is not a flag
                if idx < args.count && !args[idx].hasPrefix("-") {
                    config.firmwareVersion = args[idx]
                    idx += 1
                }
            } else if arg.hasPrefix("--firmware-radar=") {
                config.firmwareRadar = true
                let val = String(arg.dropFirst("--firmware-radar=".count))
                config.firmwareVersion = val.isEmpty ? nil : val
                idx += 1
            } else if arg.hasPrefix("-r=") {
                config.firmwareRadar = true
                let val = String(arg.dropFirst("-r=".count))
                config.firmwareVersion = val.isEmpty ? nil : val
                idx += 1
            } else if arg == "--export-surge" {
                idx += 1
                guard idx < args.count, !args[idx].hasPrefix("-") else {
                    throw CLIError.missingArgument(option: "--export-surge", expected: "<path>")
                }
                config.exportSurgePath = args[idx]
                idx += 1
            } else if arg.hasPrefix("--export-surge=") {
                let val = String(arg.dropFirst("--export-surge=".count))
                guard !val.isEmpty else { throw CLIError.missingArgument(option: "--export-surge", expected: "<path>") }
                config.exportSurgePath = val
                idx += 1
            } else if arg == "--export-shield" {
                idx += 1
                guard idx < args.count, !args[idx].hasPrefix("-") else {
                    throw CLIError.missingArgument(option: "--export-shield", expected: "<path>")
                }
                config.exportShieldPath = args[idx]
                idx += 1
            } else if arg.hasPrefix("--export-shield=") {
                let val = String(arg.dropFirst("--export-shield=".count))
                guard !val.isEmpty else { throw CLIError.missingArgument(option: "--export-shield", expected: "<path>") }
                config.exportShieldPath = val
                idx += 1
            } else if arg == "--format" {
                idx += 1
                guard idx < args.count, !args[idx].hasPrefix("-") else {
                    throw CLIError.missingArgument(option: "--format", expected: "<json|markdown|text>")
                }
                guard let fmt = OutputFormat(rawValueCaseInsensitive: args[idx]) else {
                    throw CLIError.invalidFormat(args[idx])
                }
                config.format = fmt
                idx += 1
            } else if arg.hasPrefix("--format=") {
                let val = String(arg.dropFirst("--format=".count))
                guard let fmt = OutputFormat(rawValueCaseInsensitive: val) else {
                    throw CLIError.invalidFormat(val)
                }
                config.format = fmt
                idx += 1
            } else if arg == "-o" || arg == "--out" {
                idx += 1
                guard idx < args.count, !args[idx].hasPrefix("-") else {
                    throw CLIError.missingArgument(option: arg, expected: "<path>")
                }
                config.outPath = args[idx]
                idx += 1
            } else if arg.hasPrefix("--out=") {
                let val = String(arg.dropFirst("--out=".count))
                guard !val.isEmpty else { throw CLIError.missingArgument(option: "--out", expected: "<path>") }
                config.outPath = val
                idx += 1
            } else if arg.hasPrefix("-o=") {
                let val = String(arg.dropFirst("-o=".count))
                guard !val.isEmpty else { throw CLIError.missingArgument(option: "-o", expected: "<path>") }
                config.outPath = val
                idx += 1
            } else if arg == "--whitelist" {
                idx += 1
                guard idx < args.count, !args[idx].hasPrefix("-") else {
                    throw CLIError.missingArgument(option: "--whitelist", expected: "<bundleID>")
                }
                config.whitelistedBundleIDs.append(args[idx])
                idx += 1
            } else if arg.hasPrefix("--whitelist=") {
                let val = String(arg.dropFirst("--whitelist=".count))
                guard !val.isEmpty else { throw CLIError.missingArgument(option: "--whitelist", expected: "<bundleID>") }
                config.whitelistedBundleIDs.append(val)
                idx += 1
            } else {
                throw CLIError.unrecognizedOption(arg)
            }
        }

        guard config.hasAction else {
            throw CLIError.missingAction
        }

        return config
    }
}

// MARK: - 2. Terminal ANSI Styler & Progress Tracker
public final class TerminalStyler: Sendable {
    public let isTTY: Bool
    public let supportsColor: Bool

    public init(fileDescriptor: Int32 = STDOUT_FILENO) {
        self.isTTY = isatty(fileDescriptor) != 0
        let env = ProcessInfo.processInfo.environment
        let noColor = env["NO_COLOR"] != nil
        let termDumb = env["TERM"] == "dumb"
        self.supportsColor = self.isTTY && !noColor && !termDumb
    }

    public func red(_ text: String) -> String { supportsColor ? "\u{001B}[31m\(text)\u{001B}[0m" : text }
    public func green(_ text: String) -> String { supportsColor ? "\u{001B}[32m\(text)\u{001B}[0m" : text }
    public func yellow(_ text: String) -> String { supportsColor ? "\u{001B}[33m\(text)\u{001B}[0m" : text }
    public func cyan(_ text: String) -> String { supportsColor ? "\u{001B}[36m\(text)\u{001B}[0m" : text }
    public func bold(_ text: String) -> String { supportsColor ? "\u{001B}[1m\(text)\u{001B}[0m" : text }
    public func dim(_ text: String) -> String { supportsColor ? "\u{001B}[2m\(text)\u{001B}[0m" : text }

    public func printProgress(_ progress: ScanProgress, to handle: FileHandle = .standardError) {
        guard isatty(handle.fileDescriptor) != 0 else { return }
        let width = 20
        let clampedFraction = min(max(progress.fractionCompleted, 0.0), 1.0)
        let filled = Int(Double(width) * clampedFraction)
        let bar = String(repeating: "=", count: filled) + (filled < width ? ">" : "") + String(repeating: " ", count: max(0, width - filled - (filled < width ? 1 : 0)))
        let line = String(format: "\r\u{001B}[2K[%@] %5.1f%% (%d/%d) %@", bar, clampedFraction * 100.0, progress.completedCount, progress.totalCount, progress.currentTarget)
        handle.write(Data(line.utf8))
    }

    public func clearProgress(to handle: FileHandle = .standardError) {
        guard isatty(handle.fileDescriptor) != 0 else { return }
        handle.write(Data("\r\u{001B}[2K\r".utf8))
    }
}

// MARK: - 3. Usage Manual
public enum CLIManual: Sendable {
    public static func manualString(styler: TerminalStyler = TerminalStyler()) -> String {
        """
        \(styler.bold("OVERVIEW")): WQGuard CLI - 100% Read-Only iOS Security Scanner
        Detects containermanagerd sandbox escape (worse_query / bad_query), evaluates
        2026 firmware CVE exposures, and audits iOS application bundles & containers.

        \(styler.bold("USAGE")): wqguard-cli [options]

        \(styler.bold("OPTIONS")):
          \(styler.cyan("-s, --scan-system"))
                Scan installed applications on current machine/target using
                SecurityPipeline and LaunchServices CSStore2 caches.

          \(styler.cyan("-i, --ipa <path>"))
                Inspect local uninstalled .ipa archive using IPAPackageScanner.

          \(styler.cyan("-c, --container <path>"))
                Inspect AppGroup container directory using ContainerScanner.

          \(styler.cyan("-r, --firmware-radar [os_version]"))
                Evaluate OS version against 8 2026 CVEs (e.g., Photos bypass,
                Brotli OOB RCE, worse_query 0day) using FirmwarePostureEngine.
                If os_version is omitted, current device OS version is used.

          \(styler.cyan("--export-surge <path>"))
                Export WQGuard-Brotli-Shield.sgmodule with 16 negative exclusions
                (protecting Apple Intelligence, Siri, and banking) via SurgeBrotliShieldHelper.

          \(styler.cyan("--export-shield <path>"))
                Export Brotli shield auto-inferring client format from extension:
                .sgmodule (Surge), .module (Shadowrocket), .conf (Quantumult X),
                .plugin (Loon), or .stoverride (Stash).

          \(styler.cyan("--format <text|json|markdown>"))
                Report format output (default: text).

          \(styler.cyan("-o, --out <path>"))
                Write report to file path instead of standard output.

          \(styler.cyan("--whitelist <bundleID>"))
                Temporarily whitelist specific bundle ID for this scan run (repeatable).

          \(styler.cyan("-v, --version"))
                Print CLI engine version information.

          \(styler.cyan("-h, --help"))
                Show this help manual.

        \(styler.bold("EXIT CODES")):
          0     Scan completed with no High Risk findings (clean, safe, or whitelisted).
          1     High Risk findings detected (RiskTier.highRisk).
          2     Usage error, invalid arguments, or missing target file.

        \(styler.bold("EXAMPLES")):
          # Scan an uninstalled IPA file and save JSON report
          wqguard-cli --ipa /path/to/app.ipa --format json -o report.json

          # Scan local applications with temporary whitelist
          wqguard-cli -s --whitelist com.example.internal --format text

          # Evaluate iOS 26.2 firmware exposure against 2026 CVEs
          wqguard-cli --firmware-radar 26.2

          # Export Surge Brotli shield module
          wqguard-cli --export-surge /path/to/WQGuard-Brotli-Shield.sgmodule
        """
    }

    public static func printUsage(styler: TerminalStyler = TerminalStyler()) {
        print(manualString(styler: styler))
    }
}
