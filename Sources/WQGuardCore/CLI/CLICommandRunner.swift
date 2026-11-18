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

        // 3. Scoped Whitelist Registration (restored via defer so CLI invocations never pollute WhitelistEngine.shared)
        var priorToolsByName: [String: WhitelistedTool?] = [:]
        for bundleId in config.whitelistedBundleIDs {
            let ruleName = "CLI-Whitelist-\(bundleId)"
            if priorToolsByName[ruleName] == nil {
                priorToolsByName[ruleName] = WhitelistEngine.shared.tool(named: ruleName)
            }
            let tool = WhitelistedTool(
                name: ruleName,
                allowedBundleIds: [bundleId],
                allowedAppGroups: [],
                expectedSignatures: [],
                description: "Whitelisted via CLI --whitelist flag",
                isEnabled: true,
                isBuiltIn: false
            )
            WhitelistEngine.shared.registerCustomTool(tool)
        }
        defer {
            for (ruleName, prior) in priorToolsByName {
                if let saved = prior {
                    WhitelistEngine.shared.registerCustomTool(saved)
                } else {
                    WhitelistEngine.shared.removeTool(named: ruleName)
                }
            }
        }

        let startTime = Date()

        func stripTrailingSlashes(_ rawPath: String) -> String {
            guard rawPath.count > 1 else { return rawPath }
            var s = rawPath
            while s.count > 1 && s.hasSuffix("/") {
                s.removeLast()
            }
            return s
        }

        func verifySafeOutputDestination(_ destURL: URL) -> String? {
            let cleanPath = stripTrailingSlashes(destURL.path)
            var st = stat()
            if lstat(cleanPath, &st) == 0 {
                let mode = st.st_mode & S_IFMT
                if mode == S_IFLNK {
                    return "refusing to overwrite symbolic link at '\(cleanPath)'"
                }
                if mode != S_IFREG {
                    return "output path '\(cleanPath)' exists and is not a regular file"
                }
            }
            return nil
        }

        func writeSafeCLIOutput(_ content: String, to rawPath: String) throws -> URL {
            let rawDestURL = URL(fileURLWithPath: rawPath)
            let rawParent = stripTrailingSlashes(rawDestURL.deletingLastPathComponent().path)
            let effectiveDestURL: URL
            if rawParent == "/tmp" {
                effectiveDestURL = URL(fileURLWithPath: "/private/tmp").appendingPathComponent(rawDestURL.lastPathComponent)
            } else if rawParent == "/var" {
                effectiveDestURL = URL(fileURLWithPath: "/private/var").appendingPathComponent(rawDestURL.lastPathComponent)
            } else {
                effectiveDestURL = rawDestURL
            }
            if let unsafeReason = verifySafeOutputDestination(effectiveDestURL) {
                throw NSError(domain: "WQGuardCLI", code: 2, userInfo: [NSLocalizedDescriptionKey: unsafeReason])
            }
            let parentURL = effectiveDestURL.deletingLastPathComponent()
            let cleanParent = stripTrailingSlashes(parentURL.path)
            var pSt = stat()
            if lstat(cleanParent, &pSt) == 0 && (pSt.st_mode & S_IFMT) == S_IFLNK {
                throw NSError(domain: "WQGuardCLI", code: 2, userInfo: [NSLocalizedDescriptionKey: "refusing to write through symbolic link directory '\(cleanParent)'"])
            }
            try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: true)
            try IPAPackageScanner.writeBoundedRegularFileAtomicNoFollow(Data(content.utf8), to: effectiveDestURL)
            return URL(fileURLWithPath: stripTrailingSlashes(rawDestURL.path))
        }

        // 4. Surge & Multi-Client Shield Export
        if let surgePath = config.exportSurgePath {
            do {
                let content = SurgeBrotliShieldHelper.shared.generateModuleContent()
                let validation = SurgeBrotliShieldHelper.shared.validateModule(content: content)
                guard validation.isCompliant else {
                    let msg = "wqguard-cli error: Surge module validation failed: \(validation.errors.joined(separator: ", "))\n"
                    stderr.write(Data(msg.utf8))
                    return 2
                }
                let destURL = try writeSafeCLIOutput(content, to: surgePath)
                let confirm = "[+] Exported Surge shield to \(destURL.path)\n"
                stderr.write(Data(confirm.utf8))
            } catch {
                let msg = "wqguard-cli error: failed to export Surge shield: \(error.localizedDescription)\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
        }

        if let shieldPath = config.exportShieldPath {
            let platform = ProxyShieldPlatform(identifierOrPath: shieldPath) ?? .surge
            do {
                let content = SurgeBrotliShieldHelper.shared.generateShieldContent(for: platform)
                let validation = SurgeBrotliShieldHelper.shared.validateShield(content: content, for: platform)
                guard validation.isCompliant else {
                    let msg = "wqguard-cli error: \(platform.shortTitleEn) shield validation failed: \(validation.errors.joined(separator: ", "))\n"
                    stderr.write(Data(msg.utf8))
                    return 2
                }
                let destURL = try writeSafeCLIOutput(content, to: shieldPath)
                let confirm = "[+] Exported \(platform.shortTitleEn) shield to \(destURL.path)\n"
                stderr.write(Data(confirm.utf8))
            } catch {
                let msg = "wqguard-cli error: failed to export \(platform.shortTitleEn) shield: \(error.localizedDescription)\n"
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
            let cleanIpaPath = stripTrailingSlashes(ipaPath)
            let url = URL(fileURLWithPath: cleanIpaPath)
            var ipaStat = stat()
            guard lstat(cleanIpaPath, &ipaStat) == 0 else {
                let msg = "\(CLIError.fileNotFound(ipaPath).localizedDescription)\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
            let ipaMode = ipaStat.st_mode & S_IFMT
            if ipaMode == S_IFLNK {
                let msg = "wqguard-cli error: refusing to follow symbolic link target '\(ipaPath)'\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
            guard ipaMode == S_IFREG else {
                let msg = "wqguard-cli error: IPA target '\(ipaPath)' is not a regular file\n"
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

        // 6.2 Container / Bundle / Framework / Binary / Extensionless-IPA / Unpacked-Payload Target Scanning (handles `wqguard-cli scan <target>` and `-c <path>`)
        if let containerPath = config.containerPath {
            let cleanContainerPath = stripTrailingSlashes(containerPath)
            let url = URL(fileURLWithPath: cleanContainerPath)
            var targetStat = stat()
            guard lstat(cleanContainerPath, &targetStat) == 0 else {
                let msg = "\(CLIError.fileNotFound(containerPath).localizedDescription)\n"
                stderr.write(Data(msg.utf8))
                return 2
            }

            let targetMode = targetStat.st_mode & S_IFMT
            if targetMode == S_IFLNK {
                let msg = "wqguard-cli error: refusing to follow symbolic link target '\(containerPath)'\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
            let isDirectoryTarget = (targetMode == S_IFDIR)
            let isRegularTarget = (targetMode == S_IFREG)
            guard isDirectoryTarget || isRegularTarget else {
                let msg = "wqguard-cli error: target '\(containerPath)' is a special non-regular file (mode=\(targetStat.st_mode))\n"
                stderr.write(Data(msg.utf8))
                return 2
            }

            let ext = url.pathExtension.lowercased()
            var probeStat = stat()
            let hasBundlePlist: Bool = isDirectoryTarget && (
                lstat(url.appendingPathComponent("Info.plist").path, &probeStat) == 0 ||
                lstat(url.appendingPathComponent("Contents/Info.plist").path, &probeStat) == 0 ||
                lstat(url.appendingPathComponent("Resources/Info.plist").path, &probeStat) == 0 ||
                lstat(url.appendingPathComponent("Versions/Current/Resources/Info.plist").path, &probeStat) == 0 ||
                lstat(url.appendingPathComponent("Versions/A/Resources/Info.plist").path, &probeStat) == 0
            )
            let isBundleDirectoryTarget = isDirectoryTarget && (
                ext == "app" || ext == "appex" || ext == "xpc" || ext == "framework" || ext == "xcframework" || ext == "bundle" ||
                (hasBundlePlist &&
                 lstat(url.appendingPathComponent(MCMReader.metadataFilename).path, &probeStat) != 0 &&
                 lstat(url.appendingPathComponent("Library").path, &probeStat) != 0)
            )

            if isRegularTarget && (ext == "ipa" || ext == "tipa") {
                do {
                    findings.append(try IPAPackageScanner.shared.scan(ipaURL: url))
                } catch {
                    let msg = "wqguard-cli error: failed to scan IPA '\(containerPath)': \(error.localizedDescription)\n"
                    stderr.write(Data(msg.utf8))
                    return 2
                }
            } else if isBundleDirectoryTarget {
                do {
                    findings.append(try SecurityPipeline.shared.scanBundle(at: url))
                } catch {
                    let msg = "wqguard-cli error: failed to scan bundle '\(containerPath)': \(error.localizedDescription)\n"
                    stderr.write(Data(msg.utf8))
                    return 2
                }
            } else if isRegularTarget {
                let (prefix, fileSize) = IPAPackageScanner.readMachOHeaderPrefix(of: url)
                let isZipMagic = prefix.count >= 4 && (
                    (prefix[0] == 0x50 && prefix[1] == 0x4B && prefix[2] == 0x03 && prefix[3] == 0x04) ||
                    (prefix[0] == 0x50 && prefix[1] == 0x4B && prefix[2] == 0x05 && prefix[3] == 0x06)
                )
                if isZipMagic {
                    do {
                        findings.append(try IPAPackageScanner.shared.scan(ipaURL: url))
                    } catch {
                        let msg = "wqguard-cli error: failed to scan ZIP/IPA archive '\(containerPath)': \(error.localizedDescription)\n"
                        stderr.write(Data(msg.utf8))
                        return 2
                    }
                } else if IPAPackageScanner.isMachOOrFatMagic(prefix, fileSize: fileSize) {
                    do {
                        findings.append(try SecurityPipeline.shared.scanBinary(at: url))
                    } catch {
                        let msg = "wqguard-cli error: failed to scan Mach-O binary '\(containerPath)': \(error.localizedDescription)\n"
                        stderr.write(Data(msg.utf8))
                        return 2
                    }
                } else {
                    let msg = "wqguard-cli error: target '\(containerPath)' is not a container directory, app bundle, IPA archive, or Mach-O binary (mode=\(targetStat.st_mode))\n"
                    stderr.write(Data(msg.utf8))
                    return 2
                }
            } else {
                var st = stat()
                let hasLibrary = lstat(url.appendingPathComponent("Library").path, &st) == 0
                let hasCaches = lstat(url.appendingPathComponent("Library/Caches").path, &st) == 0
                let hasMetadata = lstat(url.appendingPathComponent(MCMReader.metadataFilename).path, &st) == 0
                let isSingleContainer = hasLibrary || hasCaches || hasMetadata || url.path.contains("configurationprofiles")

                let hasChildContainerMarkers: Bool = {
                    guard !isSingleContainer, let dp = opendir(url.path) else { return false }
                    defer { closedir(dp) }
                    while let ent = readdir(dp) {
                        let name = withUnsafeBytes(of: ent.pointee.d_name) { raw -> String in
                            String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                        }
                        if name == "." || name == ".." { continue }
                        let childURL = url.appendingPathComponent(name)
                        var cst = stat()
                        guard lstat(childURL.path, &cst) == 0, (cst.st_mode & S_IFMT) == S_IFDIR else { continue }
                        var mst = stat()
                        if lstat(childURL.appendingPathComponent("Library").path, &mst) == 0 ||
                           lstat(childURL.appendingPathComponent(MCMReader.metadataFilename).path, &mst) == 0 ||
                           name.contains("configurationprofiles") {
                            return true
                        }
                    }
                    return false
                }()

                // If the directory is neither a single container nor an App Group parent directory (e.g. unpacked `Payload/` or
                // batch audit directory containing `.app`/`.appex`/`.xpc`/`.framework`/`.xcframework`/`.ipa` targets), scan all packages inside it.
                let nestedPackageTargets: [URL] = (!isSingleContainer && !hasChildContainerMarkers)
                    ? Self.discoverNestedPackageTargetsNoFollow(in: url)
                    : []

                if !nestedPackageTargets.isEmpty {
                    for pkgURL in nestedPackageTargets {
                        let pkgExt = pkgURL.pathExtension.lowercased()
                        do {
                            if pkgExt == "ipa" || pkgExt == "tipa" {
                                findings.append(try IPAPackageScanner.shared.scan(ipaURL: pkgURL))
                            } else {
                                findings.append(try SecurityPipeline.shared.scanBundle(at: pkgURL))
                            }
                        } catch {
                            let msg = "wqguard-cli error: failed to scan '\(pkgURL.path)': \(error.localizedDescription)\n"
                            stderr.write(Data(msg.utf8))
                            return 2
                        }
                    }
                } else {
                    var containerResults: [ContainerScanResult] = []
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
            }
        }

        // 6.3 System Scanning (host backup / unsandboxed CLI forensics)
        if config.scanSystem {
            let csSnapshot = findAndParseCSStore()
            var extraBundleURLs: [URL] = []
            if let snap = csSnapshot {
                let candidatePaths = Set(snap.discoveredAppBundles).union(snap.bundlePaths.values)
                for path in candidatePaths.sorted() {
                    var cst = stat()
                    if lstat(stripTrailingSlashes(path), &cst) == 0, (cst.st_mode & S_IFMT) == S_IFDIR {
                        extraBundleURLs.append(URL(fileURLWithPath: path))
                    }
                }
            }
            do {
                let sysFindings = try await SecurityPipeline.shared.scanInstalledAppsAsync(additionalLocations: extraBundleURLs) { progress in
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
                do {
                    let outData = outputString.hasSuffix("\n") ? outputString : (outputString + "\n")
                    let outURL = try writeSafeCLIOutput(outData, to: outPath)
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

    private static func discoverNestedPackageTargetsNoFollow(in rootURL: URL, maxDepth: Int = 4, maxEntries: Int = 4096) -> [URL] {
        let bundleExts: Set<String> = ["app", "appex", "xpc", "framework", "xcframework", "bundle"]
        let archiveExts: Set<String> = ["ipa", "tipa"]
        var discovered: [URL] = []
        var visitedEntries = 0

        func walk(dirURL: URL, depth: Int) {
            guard depth <= maxDepth, visitedEntries < maxEntries, let dp = opendir(dirURL.path) else { return }
            defer { closedir(dp) }
            var names: [String] = []
            while let ent = readdir(dp) {
                let name = withUnsafeBytes(of: ent.pointee.d_name) { raw -> String in
                    String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                }
                if name != "." && name != ".." && name != ".DS_Store" {
                    names.append(name)
                }
            }
            names.sort()
            for name in names {
                if visitedEntries >= maxEntries { break }
                visitedEntries += 1
                let childURL = dirURL.appendingPathComponent(name)
                var cst = stat()
                guard lstat(childURL.path, &cst) == 0 else { continue }
                let mode = cst.st_mode & S_IFMT
                if name == ".git" && mode == S_IFDIR {
                    var gitHeadLst = stat()
                    if lstat(childURL.appendingPathComponent("HEAD").path, &gitHeadLst) == 0 {
                        continue
                    }
                }
                if name.hasPrefix("._") && mode == S_IFREG && IPAPackageScanner.isGenuineAppleDoubleMetadataFile(at: childURL) {
                    continue
                }
                let ext = childURL.pathExtension.lowercased()
                if mode == S_IFREG && archiveExts.contains(ext) {
                    discovered.append(childURL)
                } else if mode == S_IFLNK && (archiveExts.contains(ext) || bundleExts.contains(ext)) {
                    discovered.append(childURL)
                } else if mode == S_IFDIR {
                    if bundleExts.contains(ext) {
                        discovered.append(childURL)
                    } else {
                        walk(dirURL: childURL, depth: depth + 1)
                    }
                }
            }
        }

        walk(dirURL: rootURL, depth: 0)
        return discovered
    }

    private static func findAndParseCSStore() -> CSStoreSnapshot? {
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
            guard IPAPackageScanner.isNonSymlinkDirectory(at: URL(fileURLWithPath: dir, isDirectory: true)) else { continue }
            if let files = try? FileManager.default.contentsOfDirectory(atPath: dir) {
                for f in files where f.hasPrefix("com.apple.LaunchServices-") && f.hasSuffix(".csstore") {
                    let csURL = URL(fileURLWithPath: (dir as NSString).appendingPathComponent(f))
                    if let snap = try? CSStore2Parser.shared.parse(at: csURL) {
                        return snap
                    }
                }
            }
        }
        return nil
    }

    private static func formatFirmwareReportText(report: FirmwarePostureReport, styler: TerminalStyler) -> String {
        var lines: [String] = []
        let safeDisplayOS = ReportGenerator.shared.plain(report.osVersion.displayString)
        lines.append("================================================================================")
        lines.append("           WQGuard Firmware CVE Exposure Radar")
        lines.append("================================================================================")
        lines.append("Target OS: \(safeDisplayOS)")
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
        lines.append("- **Target OS**: \(ReportGenerator.shared.codeSpan(report.osVersion.displayString))")
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
