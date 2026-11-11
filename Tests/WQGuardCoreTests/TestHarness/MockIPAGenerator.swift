import Foundation

/// MockIPAGenerator constructs valid `.ipa` ZIP archives with `Payload/AppName.app`, `Info.plist`,
/// `embedded.mobileprovision`, Mach-O executables, embedded frameworks, and app extensions.
public final class MockIPAGenerator: @unchecked Sendable {
    public static let shared = MockIPAGenerator()

    public enum ProvisioningProfileType: Sendable {
        case none
        case developerSideloaded(teamId: String, devices: [String])
        case enterpriseInHouse(teamId: String)
        case custom(Data)
    }

    public struct IPAPackageConfig: Sendable {
        public var appName: String
        public var bundleIdentifier: String
        public var version: String
        public var teamIdentifier: String?
        public var executableBinary: Data
        public var provisioningProfile: ProvisioningProfileType
        public var embeddedFrameworks: [String: Data] // relative path inside Frameworks/ -> data
        public var appExtensions: [String: (bundleId: String, binary: Data)] // appex name -> (bundleId, binary)
        public var additionalFiles: [String: Data]
        public var includePayloadDirectory: Bool
        public var corruptArchive: Bool
        public var corruptInfoPlist: Bool

        public init(
            appName: String = "TestApp",
            bundleIdentifier: String = "com.example.TestApp",
            version: String = "1.0.0",
            teamIdentifier: String? = "TEAM123456",
            executableBinary: Data,
            provisioningProfile: ProvisioningProfileType = .none,
            embeddedFrameworks: [String: Data] = [:],
            appExtensions: [String: (bundleId: String, binary: Data)] = [:],
            additionalFiles: [String: Data] = [:],
            includePayloadDirectory: Bool = true,
            corruptArchive: Bool = false,
            corruptInfoPlist: Bool = false
        ) {
            self.appName = appName
            self.bundleIdentifier = bundleIdentifier
            self.version = version
            self.teamIdentifier = teamIdentifier
            self.executableBinary = executableBinary
            self.provisioningProfile = provisioningProfile
            self.embeddedFrameworks = embeddedFrameworks
            self.appExtensions = appExtensions
            self.additionalFiles = additionalFiles
            self.includePayloadDirectory = includePayloadDirectory
            self.corruptArchive = corruptArchive
            self.corruptInfoPlist = corruptInfoPlist
        }
    }

    public init() {}

    /// Builds a valid `.ipa` file on disk and returns its URL.
    public func createIPA(config: IPAPackageConfig) throws -> URL {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("ipa_build_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        defer {
            try? FileManager.default.removeItem(at: tempDir)
        }

        // Determine App bundle directory
        let appDir: URL
        if config.includePayloadDirectory {
            let payloadDir = tempDir.appendingPathComponent("Payload")
            appDir = payloadDir.appendingPathComponent("\(config.appName).app")
        } else {
            appDir = tempDir.appendingPathComponent("\(config.appName).app")
        }
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)

        // 1. Executable binary
        let execURL = appDir.appendingPathComponent(config.appName)
        try config.executableBinary.write(to: execURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: execURL.path)

        // 2. Info.plist
        let infoPlistURL = appDir.appendingPathComponent("Info.plist")
        if config.corruptInfoPlist {
            try "MALFORMED_PLIST_NOT_XML".write(to: infoPlistURL, atomically: true, encoding: .utf8)
        } else {
            let infoDict: [String: Any] = [
                "CFBundleIdentifier": config.bundleIdentifier,
                "CFBundleExecutable": config.appName,
                "CFBundleName": config.appName,
                "CFBundleDisplayName": config.appName,
                "CFBundleShortVersionString": config.version,
                "CFBundleVersion": config.version,
                "CFBundlePackageType": "APPL"
            ]
            let plistData = try PropertyListSerialization.data(fromPropertyList: infoDict, format: .xml, options: 0)
            try plistData.write(to: infoPlistURL)
        }

        // 3. embedded.mobileprovision
        switch config.provisioningProfile {
        case .none:
            break
        case .developerSideloaded(let teamId, let devices):
            let provData = generateMobileProvision(teamId: teamId, isEnterprise: false, devices: devices)
            try provData.write(to: appDir.appendingPathComponent("embedded.mobileprovision"))
        case .enterpriseInHouse(let teamId):
            let provData = generateMobileProvision(teamId: teamId, isEnterprise: true, devices: [])
            try provData.write(to: appDir.appendingPathComponent("embedded.mobileprovision"))
        case .custom(let data):
            try data.write(to: appDir.appendingPathComponent("embedded.mobileprovision"))
        }

        // 4. Embedded Frameworks
        if !config.embeddedFrameworks.isEmpty {
            let frameworksDir = appDir.appendingPathComponent("Frameworks")
            try FileManager.default.createDirectory(at: frameworksDir, withIntermediateDirectories: true)
            for (relPath, data) in config.embeddedFrameworks {
                let fwURL = frameworksDir.appendingPathComponent(relPath)
                try FileManager.default.createDirectory(at: fwURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                try data.write(to: fwURL)
            }
        }

        // 5. App Extensions (PlugIns)
        if !config.appExtensions.isEmpty {
            let pluginsDir = appDir.appendingPathComponent("PlugIns")
            try FileManager.default.createDirectory(at: pluginsDir, withIntermediateDirectories: true)
            for (extName, extData) in config.appExtensions {
                let appexDir = pluginsDir.appendingPathComponent("\(extName).appex")
                try FileManager.default.createDirectory(at: appexDir, withIntermediateDirectories: true)
                let extExec = appexDir.appendingPathComponent(extName)
                try extData.binary.write(to: extExec)

                let extInfoPlist: [String: Any] = [
                    "CFBundleIdentifier": extData.bundleId,
                    "CFBundleExecutable": extName,
                    "CFBundlePackageType": "XPC!",
                    "NSExtension": ["NSExtensionPointIdentifier": "com.apple.widgetkit-extension"]
                ]
                let extPlistData = try PropertyListSerialization.data(fromPropertyList: extInfoPlist, format: .xml, options: 0)
                try extPlistData.write(to: appexDir.appendingPathComponent("Info.plist"))
            }
        }

        // 6. Additional Files
        for (relPath, data) in config.additionalFiles {
            let fileURL = appDir.appendingPathComponent(relPath)
            try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: fileURL)
        }

        // 7. Zip into .ipa
        let outputIPA = FileManager.default.temporaryDirectory.appendingPathComponent("\(config.appName)_\(UUID().uuidString).ipa")

        if config.corruptArchive {
            // Write corrupt non-zip bytes
            let corruptBytes = Data([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00, 0xff, 0xff])
            try corruptBytes.write(to: outputIPA)
            return outputIPA
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        process.currentDirectoryURL = tempDir
        process.arguments = ["-q", "-r", outputIPA.path, "."]
        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            throw NSError(domain: "MockIPAGenerator", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: "Failed to zip IPA archive"])
        }

        return outputIPA
    }

    /// Generates mock embedded.mobileprovision plist XML wrapped in simulated CMS/DER payload.
    private func generateMobileProvision(teamId: String, isEnterprise: Bool, devices: [String]) -> Data {
        var dict: [String: Any] = [
            "AppIDName": "TestApp",
            "ApplicationIdentifierPrefix": [teamId],
            "TeamIdentifier": [teamId],
            "TeamName": "Test Security Team",
            "Name": isEnterprise ? "Enterprise In-House Profile" : "iOS Developer Provisioning Profile",
            "Entitlements": [
                "application-identifier": "\(teamId).com.example.TestApp",
                "com.apple.developer.team-identifier": teamId
            ],
            "TimeToLive": 365
        ]

        if isEnterprise {
            dict["ProvisionsAllDevices"] = true
        } else {
            dict["ProvisionedDevices"] = devices.isEmpty ? ["00008030-001234567890002E"] : devices
        }

        let plistData = (try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)) ?? Data()
        // Wrap in a mock CMS container (or raw plist)
        return plistData
    }
}
