//
//  CLICommandRunner.swift
//  WQGuardCore
//
//  Command execution engine for wqguard-cli dispatching scans, evaluations, and reports.
//

import Foundation
import Darwin

public enum CLICommandRunner: Sendable {
    public static func run(
        arguments: [String],
        stdout: FileHandle = .standardOutput,
        stderr: FileHandle = .standardError
    ) async -> Int32 {
        let styler = TerminalStyler(fileDescriptor: stdout.fileDescriptor)

        // 1. Argument Parsing
        let config: CLIConfig
        do {
            config = try CLIArgumentParser.parse(arguments: arguments)
        } catch let error as CLIError {
            let msg = "\(error.localizedDescription)\n"
            stderr.write(Data(msg.utf8))
            return 2
        } catch {
            let msg = "wqguard-cli error: \(error.localizedDescription)\n"
            stderr.write(Data(msg.utf8))
            return 2
        }

        // 2. Help and Version Early Exit
        if config.showHelp {
            let man = CLIManual.manualString(styler: styler) + "\n"
            stdout.write(Data(man.utf8))
            return 0
        }

        if config.showVersion {
            let ver = "\(WQGuardCLIMetadata.versionString)\n"
            stdout.write(Data(ver.utf8))
            return 0
        }

        // 3. Whitelist Registration
        for bundleId in config.whitelistedBundleIDs {
            let tool = WhitelistedTool(
                name: "CLI-Whitelist-\(bundleId)",
                allowedBundleIds: [bundleId],
                allowedAppGroups: [],
                expectedSignatures: [],
                description: "Whitelisted via CLI --whitelist flag",
                isEnabled: true,
                isBuiltIn: false
            )
            WhitelistEngine.shared.registerCustomTool(tool)
        }

        let startTime = Date()

        // 4. Surge Shield Module Export
        if let surgePath = config.exportSurgePath {
            do {
                let content = SurgeBrotliShieldHelper.shared.generateModuleContent()
                let validation = SurgeBrotliShieldHelper.shared.validateModule(content: content)
                guard validation.isCompliant else {
                    let msg = "wqguard-cli error: Surge module validation failed: \(validation.errors.joined(separator: ", "))\n"
                    stderr.write(Data(msg.utf8))
                    return 2
                }
                let destURL = URL(fileURLWithPath: surgePath)
                let dir = destURL.deletingLastPathComponent()
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                try content.write(to: destURL, atomically: true, encoding: .utf8)
                let confirm = "[+] Exported Surge shield to \(destURL.path)\n"
                stderr.write(Data(confirm.utf8))
            } catch {
                let msg = "wqguard-cli error: failed to export Surge shield: \(error.localizedDescription)\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
        }

        // 5. Firmware Radar Evaluation
        var firmwareReport: FirmwarePostureReport? = nil
        if config.firmwareRadar {
            let osVersion: SystemOSVersion
            if let vStr = config.firmwareVersion {
                guard let parsed = SystemOSVersion(string: vStr) else {
                    let msg = "\(CLIError.invalidOSVersion(vStr).localizedDescription)\n"
                    stderr.write(Data(msg.utf8))
                    return 2
                }
                osVersion = parsed
            } else {
                osVersion = SystemOSVersion.currentDevice
            }
            firmwareReport = FirmwarePostureEngine.shared.evaluate(osVersion: osVersion)
        }

        // 6. Target Scanning
        var findings: [ScanFinding] = []

        // 6.1 IPA Scanning
        if let ipaPath = config.ipaPath {
            let url = URL(fileURLWithPath: ipaPath)
            guard FileManager.default.fileExists(atPath: url.path) else {
                let msg = "\(CLIError.fileNotFound(ipaPath).localizedDescription)\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
            styler.printProgress(ScanProgress(currentTarget: url.lastPathComponent, completedCount: 0, totalCount: 1), to: stderr)
            do {
                let finding = try IPAPackageScanner.shared.scan(ipaURL: url)
                findings.append(finding)
                styler.printProgress(ScanProgress(currentTarget: url.lastPathComponent, completedCount: 1, totalCount: 1), to: stderr)
                styler.clearProgress(to: stderr)
            } catch {
                styler.clearProgress(to: stderr)
                let msg = "wqguard-cli error: failed to scan IPA '\(ipaPath)': \(error.localizedDescription)\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
        }

        // 6.2 Container Scanning
        if let containerPath = config.containerPath {
            let url = URL(fileURLWithPath: containerPath)
            guard FileManager.default.fileExists(atPath: url.path) else {
                let msg = "\(CLIError.fileNotFound(containerPath).localizedDescription)\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
            var containerResults: [ContainerScanResult] = []

            // Disambiguate single container vs App Group parent directory:
            // A single container directly contains `Library`, `Library/Caches`, or `.com.apple.mobile_container_manager.metadata.plist`.
            // Use POSIX lstat to avoid following escaping symlinks or failing on broken link targets.
            var st = stat()
            let hasLibrary = lstat(url.appendingPathComponent("Library").path, &st) == 0
            let hasCaches = lstat(url.appendingPathComponent("Library/Caches").path, &st) == 0
            let hasMetadata = lstat(url.appendingPathComponent(MCMReader.metadataFilename).path, &st) == 0
            let isSingleContainer = hasLibrary || hasCaches || hasMetadata

            if isSingleContainer {
                if let single = try? ContainerScanner.shared.scanContainer(at: url) {
                    containerResults = [single]
                }
            } else if let results = try? ContainerScanner.shared.scanAppGroupContainers(at: url), !results.isEmpty {
                containerResults = results
            } else if let single = try? ContainerScanner.shared.scanContainer(at: url) {
                containerResults = [single]
            }
            for res in containerResults {
                let bundleId = res.metadata?.identifier ?? res.containerURL.lastPathComponent
                let appGroups = res.metadata?.identifier != nil ? [res.metadata!.identifier] : []
                let riskTier: RiskTier = res.indicators.contains(where: { $0.severity == .highRisk }) ? .highRisk :
                    (res.indicators.contains(where: { $0.severity == .caution }) ? .caution : .safe)
                let finding = ScanFinding(
                    bundleId: bundleId,
                    displayName: res.containerURL.lastPathComponent,
                    version: "1.0",
                    teamId: nil,
                    executablePath: nil,
                    bundlePath: res.containerURL.path,
                    installChannel: .developerSideloaded,
                    riskTier: riskTier,
                    isWhitelisted: false,
                    indicators: res.indicators,
                    evidence: AuditEvidence(
                        matchedSymbols: [],
                        linkedDylibs: [],
                        hasAppGroups: !appGroups.isEmpty,
                        appGroups: appGroups,
                        installChannel: .developerSideloaded,
                        cryptid: 0,
                        isFairPlayEncrypted: false,
                        escapingSymlinks: res.escapingSymlinks,
                        dynamicLoadingPresent: false,
                        pathEnumerationPresent: false,
                        remediationGuidance: res.isClean ? "Container clean." : "Investigate escaping symlinks or malformed metadata."
                    )
                )
                findings.append(finding)
            }
        }

        // 6.3 System Scanning
        if config.scanSystem {
            findAndParseCSStore()
            do {
                let sysFindings = try await SecurityPipeline.shared.scanInstalledAppsAsync { progress in
                    styler.printProgress(progress, to: stderr)
                }
                findings.append(contentsOf: sysFindings)
                styler.clearProgress(to: stderr)
            } catch {
                styler.clearProgress(to: stderr)
                let msg = "wqguard-cli error: system scan failed: \(error.localizedDescription)\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
        }

        // 7. Report Generation & Output Delivery
        var outputString = ""

        if !findings.isEmpty || config.scanSystem {
            let session = ScanSession(
                targetPath: config.ipaPath ?? config.containerPath ?? (config.scanSystem ? "System" : nil),
                findings: findings,
                systemVersion: firmwareReport?.osVersion.displayString ?? FirmwarePostureEngine.shared.evaluate().osVersion.displayString,
                scanDuration: Date().timeIntervalSince(startTime)
            )

            do {
                switch config.format {
                case .json:
                    outputString = try ReportGenerator.shared.generateJSONReportString(session: session)
                case .markdown:
                    outputString = ReportGenerator.shared.generateMarkdownReport(session: session)
                case .text:
                    outputString = ReportGenerator.shared.generatePlainTextReport(session: session)
                }
            } catch {
                let msg = "wqguard-cli error: failed to serialize report: \(error.localizedDescription)\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
        } else if let fr = firmwareReport {
            // Standalone firmware radar report
            switch config.format {
            case .json:
                do {
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                    let data = try encoder.encode(fr)
                    outputString = String(decoding: data, as: UTF8.self)
                } catch {
                    let msg = "wqguard-cli error: failed to encode firmware report JSON: \(error.localizedDescription)\n"
                    stderr.write(Data(msg.utf8))
                    return 2
                }
            case .text:
                outputString = formatFirmwareReportText(report: fr, styler: styler)
            case .markdown:
                outputString = formatFirmwareReportMarkdown(report: fr)
            }
        }

        // Deliver Output
        if !outputString.isEmpty {
            if let outPath = config.outPath {
                let outURL = URL(fileURLWithPath: outPath)
                do {
                    try FileManager.default.createDirectory(at: outURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                    try outputString.write(to: outURL, atomically: true, encoding: .utf8)
                    let confirm = "[+] Report written to \(outURL.path)\n"
                    stderr.write(Data(confirm.utf8))
                } catch {
                    let msg = "wqguard-cli error: failed to write output file '\(outPath)': \(error.localizedDescription)\n"
                    stderr.write(Data(msg.utf8))
                    return 2
                }
            } else {
                let outData = outputString.hasSuffix("\n") ? Data(outputString.utf8) : Data((outputString + "\n").utf8)
                stdout.write(outData)
            }
        }

        // 8. Exit Code Evaluation
        var hasHighRisk = false
        if !findings.isEmpty {
            let session = ScanSession(findings: findings)
            if session.riskBreakdown[.highRisk, default: 0] > 0 {
                hasHighRisk = true
            }
        }
        if let fr = firmwareReport, fr.overallRiskTier == .highRisk {
            hasHighRisk = true
        }

        return hasHighRisk ? 1 : 0
    }

    private static func findAndParseCSStore() {
        #if os(macOS)
        let homeCaches = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Caches").path
        #else
        let homeCaches = (NSHomeDirectory() as NSString).appendingPathComponent("Library/Caches")
        #endif
        let candidates = [
            homeCaches,
            "/private/var/mobile/Library/Caches"
        ]
        for dir in candidates {
            guard FileManager.default.fileExists(atPath: dir) else { continue }
            if let files = try? FileManager.default.contentsOfDirectory(atPath: dir) {
                for f in files where f.hasPrefix("com.apple.LaunchServices-") && f.hasSuffix(".csstore") {
                    let csURL = URL(fileURLWithPath: (dir as NSString).appendingPathComponent(f))
                    if let _ = try? CSStore2Parser.shared.parse(at: csURL) {
                        return
                    }
                }
            }
        }
    }

    private static func formatFirmwareReportText(report: FirmwarePostureReport, styler: TerminalStyler) -> String {
        var lines: [String] = []
        lines.append("================================================================================")
        lines.append("           WQGuard Firmware CVE Exposure Radar")
        lines.append("================================================================================")
        lines.append("Target OS: \(report.osVersion.displayString)")
        lines.append("Overall Posture: \(report.overallRiskTier.rawValue) (\(report.overallRiskTier.localizedNameZh))")
        lines.append("Evaluated CVEs: \(report.totalEvaluated)")
        lines.append("Exposed Vulnerabilities: \(report.exposedCount)")
        lines.append("Patched Vulnerabilities: \(report.patchedVulnerabilities.count)")
        lines.append("--------------------------------------------------------------------------------")
        if !report.exposedVulnerabilities.isEmpty {
            lines.append("EXPOSED VULNERABILITIES:")
            for vuln in report.exposedVulnerabilities {
                let scoreStr = vuln.cvssScore.map { String(format: "%.1f", $0) } ?? "N/A"
                lines.append("• [\(vuln.cveId.rawValue)] \(vuln.name) (CVSS \(scoreStr) - \(vuln.severity.rawValue))")
                lines.append("  Subsystem: \(vuln.subsystem)")
                lines.append("  Details: \(vuln.details)")
            }
            lines.append("--------------------------------------------------------------------------------")
        }
        if !report.actionableMitigations.isEmpty {
            lines.append("ACTIONABLE MITIGATIONS (Non-Upgrade):")
            for (idx, mit) in report.actionableMitigations.enumerated() {
                lines.append("\(idx + 1). [\(mit.category.rawValue)] \(mit.title)")
                lines.append("   Instructions: \(mit.instructions)")
            }
        }
        lines.append("================================================================================")
        return lines.joined(separator: "\n")
    }

    private static func formatFirmwareReportMarkdown(report: FirmwarePostureReport) -> String {
        var lines: [String] = []
        lines.append("# WQGuard Firmware CVE Exposure Radar Report")
        lines.append("")
        lines.append("- **Target OS**: `\(report.osVersion.displayString)`")
        lines.append("- **Overall Posture**: `\(report.overallRiskTier.rawValue)` (\(report.overallRiskTier.localizedNameZh))")
        lines.append("- **Exposed Vulnerabilities**: `\(report.exposedCount)` / `\(report.totalEvaluated)`")
        lines.append("")
        lines.append("## Vulnerability Status")
        lines.append("")
        lines.append("| CVE ID | Name | Subsystem | Severity | Status |")
        lines.append("|---|---|---|---|---|")
        for vuln in FirmwarePostureEngine.allVulnerabilities {
            let isExposed = report.exposedVulnerabilities.contains(where: { $0.id == vuln.id })
            let status = isExposed ? "⚠️ EXPOSED" : "✅ PATCHED"
            lines.append("| `\(vuln.cveId.rawValue)` | \(vuln.name) | \(vuln.subsystem) | \(vuln.severity.rawValue) | \(status) |")
        }
        if !report.actionableMitigations.isEmpty {
            lines.append("")
            lines.append("## Actionable Mitigations")
            lines.append("")
            for mit in report.actionableMitigations {
                lines.append("### \(mit.title) (`\(mit.category.rawValue)`)")
                lines.append(mit.instructions)
                lines.append("")
            }
        }
        return lines.joined(separator: "\n")
    }
}
