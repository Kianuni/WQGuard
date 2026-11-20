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

        // 3. Isolated Per-Run Whitelist Engine (never mutates WhitelistEngine.shared)
        let cliWhitelistEngine = WhitelistEngine(tools: WhitelistEngine.shared.allTools)
        var hasCustomCLIWhitelist = false
        for bundleId in config.whitelistedBundleIDs {
            let cleanBid = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !cleanBid.isEmpty,
                  !cleanBid.contains("\0"),
                  !cleanBid.allSatisfy({ $0 == "*" || $0 == "?" || $0 == "." }) else {
                continue
            }
            hasCustomCLIWhitelist = true
            let ruleName = "CLI-Whitelist-\(cleanBid)"
            let tool = WhitelistedTool(
                name: ruleName,
                allowedBundleIds: [cleanBid],
                allowedAppGroups: [],
                expectedSignatures: [],
                description: "Whitelisted via CLI --whitelist flag",
                isEnabled: true,
                isBuiltIn: false
            )
            cliWhitelistEngine.registerCustomTool(tool)
        }
        let cliPipeline = SecurityPipeline(whitelistEngine: cliWhitelistEngine)

        let startTime = Date()

        func stripTrailingSlashes(_ rawPath: String) -> String {
            guard rawPath.count > 1 else { return rawPath }
            var s = rawPath
            while s.count > 1 && s.hasSuffix("/") {
                s.removeLast()
            }
            return s
        }

        func isDarwinPrivateRootAlias(_ linkPath: String, expectedTarget: String) -> Bool {
            var st = stat()
            guard lstat(linkPath, &st) == 0, (st.st_mode & S_IFMT) == S_IFLNK else { return false }
            var buf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let n = readlink(linkPath, &buf, Int(PATH_MAX))
            guard n > 0 && n < Int(PATH_MAX) else { return false }
            buf[n] = 0
            return String(cString: buf) == expectedTarget
        }

        func writeSafeCLIOutput(_ content: String, to rawPath: String) throws -> URL {
            func cliIOError(_ message: String) -> NSError {
                NSError(domain: "WQGuardCLI", code: 2, userInfo: [NSLocalizedDescriptionKey: message])
            }

            guard !rawPath.isEmpty, !rawPath.contains("\0"), !rawPath.hasSuffix("/") else {
                throw cliIOError("invalid output path '\(rawPath)'")
            }

            let absPath: String
            if rawPath.hasPrefix("/") {
                absPath = rawPath
            } else {
                let cwd = FileManager.default.currentDirectoryPath
                absPath = (cwd as NSString).appendingPathComponent(rawPath)
            }

            let rawComps = absPath.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
            guard let rawFileName = rawComps.last,
                  !rawFileName.isEmpty,
                  rawFileName != ".",
                  rawFileName != ".." else {
                throw cliIOError("invalid output file name in path '\(rawPath)'")
            }

            var canonicalPath = absPath
            if (canonicalPath == "/tmp" || canonicalPath.hasPrefix("/tmp/")) &&
                isDarwinPrivateRootAlias("/tmp", expectedTarget: "private/tmp") {
                canonicalPath = "/private/tmp" + canonicalPath.dropFirst(4)
            } else if (canonicalPath == "/var" || canonicalPath.hasPrefix("/var/")) &&
                isDarwinPrivateRootAlias("/var", expectedTarget: "private/var") {
                canonicalPath = "/private/var" + canonicalPath.dropFirst(4)
            }

            let comps = canonicalPath.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
            guard let fileName = comps.last,
                  !fileName.isEmpty,
                  fileName != ".",
                  fileName != ".." else {
                throw cliIOError("invalid output file name in path '\(rawPath)'")
            }
            let parentComps = Array(comps.dropLast())

            var curFD = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            guard curFD >= 0 else {
                throw cliIOError("unable to open root directory (errno=\(errno))")
            }
            defer {
                if curFD >= 0 { Darwin.close(curFD) }
            }

            for comp in parentComps {
                if comp == "." { continue }
                if comp == ".." {
                    let nextFD = Darwin.openat(curFD, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                    guard nextFD >= 0 else {
                        throw cliIOError("unable to traverse parent directory '..' (errno=\(errno))")
                    }
                    Darwin.close(curFD)
                    curFD = nextFD
                    continue
                }

                var nextFD = Darwin.openat(curFD, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                if nextFD < 0 {
                    let err = errno
                    if err == ELOOP {
                        throw cliIOError("refusing to write through symbolic link directory '\(comp)'")
                    } else if err == ENOTDIR {
                        throw cliIOError("path component '\(comp)' is not a directory")
                    } else if err == ENOENT {
                        if Darwin.mkdirat(curFD, comp, 0o755) != 0 && errno != EEXIST {
                            throw cliIOError("unable to create directory '\(comp)' (errno=\(errno))")
                        }
                        nextFD = Darwin.openat(curFD, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                        if nextFD < 0 {
                            if errno == ELOOP {
                                throw cliIOError("refusing to write through symbolic link directory '\(comp)'")
                            }
                            throw cliIOError("unable to open directory '\(comp)' (errno=\(errno))")
                        }
                    } else {
                        throw cliIOError("unable to open directory '\(comp)' (errno=\(err))")
                    }
                }
                Darwin.close(curFD)
                curFD = nextFD
            }

            var st = stat()
            if fstatat(curFD, fileName, &st, AT_SYMLINK_NOFOLLOW) == 0 {
                let mode = st.st_mode & S_IFMT
                if mode == S_IFLNK {
                    throw cliIOError("refusing to overwrite symbolic link at '\(rawPath)'")
                }
                if mode != S_IFREG {
                    throw cliIOError("output path '\(rawPath)' exists and is not a regular file")
                }
            } else if errno != ENOENT {
                throw cliIOError("unable to inspect output destination '\(rawPath)' (errno=\(errno))")
            }

            let tmpName = ".wqguard_write_\(UUID().uuidString).tmp"
            let outFD = Darwin.openat(curFD, tmpName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard outFD >= 0 else {
                throw cliIOError("unable to create atomic temporary file for '\(rawPath)' (errno=\(errno))")
            }
            var closedOutFD = false
            var renamedStage = false
            defer {
                if !closedOutFD { Darwin.close(outFD) }
                if !renamedStage { _ = Darwin.unlinkat(curFD, tmpName, 0) }
            }

            let data = Data(content.utf8)
            try data.withUnsafeBytes { raw in
                guard let base = raw.baseAddress, raw.count > 0 else { return }
                var written = 0
                while written < raw.count {
                    let w = Darwin.write(outFD, base.advanced(by: written), raw.count - written)
                    if w > 0 {
                        written += w
                    } else if w < 0 && errno == EINTR {
                        continue
                    } else {
                        throw cliIOError("atomic write failed for '\(rawPath)' (errno=\(errno))")
                    }
                }
            }

            Darwin.close(outFD)
            closedOutFD = true

            if fstatat(curFD, fileName, &st, AT_SYMLINK_NOFOLLOW) == 0 {
                let mode = st.st_mode & S_IFMT
                if mode == S_IFLNK {
                    throw cliIOError("refusing to overwrite symbolic link at '\(rawPath)'")
                }
                if mode != S_IFREG {
                    throw cliIOError("output path '\(rawPath)' exists and is not a regular file")
                }
            }
            guard Darwin.renameat(curFD, tmpName, curFD, fileName) == 0 else {
                throw cliIOError("atomic rename failed for '\(rawPath)' (errno=\(errno))")
            }
            renamedStage = true

            return URL(fileURLWithPath: stripTrailingSlashes(URL(fileURLWithPath: rawPath).path))
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
            guard !ipaPath.isEmpty, !ipaPath.contains("\0") else {
                let msg = "wqguard-cli error: invalid IPA path\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
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
                let rawFinding = try cliPipeline.scanIPA(at: url)
                let finding = Self.applyCLIWhitelistIfNeeded(
                    to: rawFinding,
                    using: cliWhitelistEngine,
                    hasCustomCLIWhitelist: hasCustomCLIWhitelist
                )
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
            guard !containerPath.isEmpty, !containerPath.contains("\0") else {
                let msg = "wqguard-cli error: invalid target path\n"
                stderr.write(Data(msg.utf8))
                return 2
            }
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
                    let rawFinding = try cliPipeline.scanIPA(at: url)
                    findings.append(Self.applyCLIWhitelistIfNeeded(
                        to: rawFinding,
                        using: cliWhitelistEngine,
                        hasCustomCLIWhitelist: hasCustomCLIWhitelist
                    ))
                } catch {
                    let msg = "wqguard-cli error: failed to scan IPA '\(containerPath)': \(error.localizedDescription)\n"
                    stderr.write(Data(msg.utf8))
                    return 2
                }
            } else if isBundleDirectoryTarget {
                do {
                    findings.append(try cliPipeline.scanBundle(at: url))
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
                        let rawFinding = try cliPipeline.scanIPA(at: url)
                        findings.append(Self.applyCLIWhitelistIfNeeded(
                            to: rawFinding,
                            using: cliWhitelistEngine,
                            hasCustomCLIWhitelist: hasCustomCLIWhitelist
                        ))
                    } catch {
                        let msg = "wqguard-cli error: failed to scan ZIP/IPA archive '\(containerPath)': \(error.localizedDescription)\n"
                        stderr.write(Data(msg.utf8))
                        return 2
                    }
                } else if IPAPackageScanner.isMachOOrFatMagic(prefix, fileSize: fileSize) {
                    do {
                        findings.append(try cliPipeline.scanBinary(at: url))
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
                                let rawFinding = try cliPipeline.scanIPA(at: pkgURL)
                                findings.append(Self.applyCLIWhitelistIfNeeded(
                                    to: rawFinding,
                                    using: cliWhitelistEngine,
                                    hasCustomCLIWhitelist: hasCustomCLIWhitelist
                                ))
                            } else {
                                findings.append(try cliPipeline.scanBundle(at: pkgURL))
                            }
                        } catch {
                            let msg = "wqguard-cli error: failed to scan '\(pkgURL.path)': \(error.localizedDescription)\n"
                            stderr.write(Data(msg.utf8))
                            return 2
                        }
                    }
                } else {
                    var containerResults: [ContainerScanResult] = []
                    do {
                        if isSingleContainer {
                            containerResults = [try ContainerScanner.shared.scanContainer(at: url)]
                        } else {
                            let results = try ContainerScanner.shared.scanAppGroupContainers(at: url)
                            if !results.isEmpty {
                                containerResults = results
                            } else {
                                containerResults = [try ContainerScanner.shared.scanContainer(at: url)]
                            }
                        }
                    } catch {
                        let msg = "wqguard-cli error: failed to scan container '\(containerPath)': \(error.localizedDescription)\n"
                        stderr.write(Data(msg.utf8))
                        return 2
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
                                remediationGuidance: res.isClean ? "Container clean." : "Investigate escaping symlinks or malformed metadata.",
                                isWhitelistEligible: false,
                                isTeamIdWhitelistVerified: false
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
                    guard path.hasPrefix("/"), !path.contains("\0") else { continue }
                    var cst = stat()
                    if lstat(stripTrailingSlashes(path), &cst) == 0, (cst.st_mode & S_IFMT) == S_IFDIR {
                        extraBundleURLs.append(URL(fileURLWithPath: path))
                    }
                }
            }
            do {
                let sysFindings = try await cliPipeline.scanInstalledAppsAsync(additionalLocations: extraBundleURLs) { progress in
                    styler.printProgress(progress, to: stderr)
                }
                findings.append(contentsOf: sysFindings.map {
                    Self.applyCLIWhitelistIfNeeded(
                        to: $0,
                        using: cliWhitelistEngine,
                        hasCustomCLIWhitelist: hasCustomCLIWhitelist
                    )
                })
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
                    let csPath = (dir as NSString).appendingPathComponent(f)
                    var csStat = stat()
                    guard lstat(csPath, &csStat) == 0, (csStat.st_mode & S_IFMT) == S_IFREG else { continue }
                    let csURL = URL(fileURLWithPath: csPath)
                    if let snap = try? CSStore2Parser.shared.parse(at: csURL) {
                        return snap
                    }
                }
            }
        }
        return nil
    }

    private static func applyCLIWhitelistIfNeeded(
        to finding: ScanFinding,
        using engine: WhitelistEngine,
        hasCustomCLIWhitelist: Bool
    ) -> ScanFinding {
        guard hasCustomCLIWhitelist,
              !finding.isWhitelisted,
              finding.riskTier == .highRisk || finding.riskTier == .caution else {
            return finding
        }
        let eval = engine.evaluateFindingWhitelist(finding)
        guard eval.isWhitelisted else {
            return finding
        }
        let toolName = eval.toolName ?? "Known Tool"
        let updatedGuidance = WQLocale.pick(
            en: "Matched CLI whitelist rule (\(toolName)).",
            zh: "匹配 CLI 白名单规则（\(toolName)）。"
        )
        let updatedEvidence = AuditEvidence(
            matchedSymbols: finding.evidence.matchedSymbols,
            linkedDylibs: finding.evidence.linkedDylibs,
            hasAppGroups: finding.evidence.hasAppGroups,
            appGroups: finding.evidence.appGroups,
            installChannel: finding.evidence.installChannel,
            cryptid: finding.evidence.cryptid,
            isFairPlayEncrypted: finding.evidence.isFairPlayEncrypted,
            escapingSymlinks: finding.evidence.escapingSymlinks,
            dynamicLoadingPresent: finding.evidence.dynamicLoadingPresent,
            pathEnumerationPresent: finding.evidence.pathEnumerationPresent,
            remediationGuidance: updatedGuidance,
            auditDepth: finding.evidence.auditDepth,
            signerIdentity: finding.evidence.signerIdentity,
            correlatedPackageBundleId: finding.evidence.correlatedPackageBundleId,
            isWhitelistEligible: finding.evidence.isWhitelistEligible,
            isTeamIdWhitelistVerified: finding.evidence.isTeamIdWhitelistVerified
        )
        return ScanFinding(
            bundleId: finding.bundleId,
            displayName: finding.displayName,
            version: finding.version,
            teamId: finding.teamId,
            executablePath: finding.executablePath,
            bundlePath: finding.bundlePath,
            installChannel: finding.installChannel,
            riskTier: .knownTool,
            isWhitelisted: true,
            whitelistedToolName: toolName,
            indicators: finding.indicators,
            evidence: updatedEvidence,
            scanTimestamp: finding.scanTimestamp
        )
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
