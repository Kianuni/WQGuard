//
//  ChannelClassifier.swift
//  WQGuardCore
//
//  100% read-only installation channel classifier for iOS applications.
//  Distinguishes between Developer Sideloaded, Enterprise In-House, TestFlight, and App Store.
//

import Foundation

/// Classifies application installation channels based on FairPlay DRM encryption (cryptid),
/// embedded mobileprovision profiles, and receipt metadata.
public enum ChannelClassifier {
    
    /// Structured result of install channel classification.
    public struct ClassificationResult: Sendable, Equatable {
        public let channel: InstallChannel
        public let teamIdentifier: String?
        public let teamName: String?
        public let profileName: String?
        public let isEnterprise: Bool
        public let hasMobileProvision: Bool
        public let hasReceipt: Bool
        public let isFairPlayEncrypted: Bool
        public let details: String
        
        public init(
            channel: InstallChannel,
            teamIdentifier: String? = nil,
            teamName: String? = nil,
            profileName: String? = nil,
            isEnterprise: Bool = false,
            hasMobileProvision: Bool = false,
            hasReceipt: Bool = false,
            isFairPlayEncrypted: Bool = false,
            details: String = ""
        ) {
            self.channel = channel
            self.teamIdentifier = teamIdentifier
            self.teamName = teamName
            self.profileName = profileName
            self.isEnterprise = isEnterprise
            self.hasMobileProvision = hasMobileProvision
            self.hasReceipt = hasReceipt
            self.isFairPlayEncrypted = isFairPlayEncrypted
            self.details = details
        }
    }
    
    /// Extracts an embedded XML property list from an Apple `.mobileprovision` CMS signedData blob.
    ///
    /// Real `.mobileprovision` files are DER-encoded CMS containers wrapping an XML property list.
    /// This method locates the XML plist payload between `<?xml`/`<plist` and `</plist>` and deserializes it.
    public static func extractPlist(from mobileprovisionData: Data) -> [String: Any]? {
        // 1. Direct plist deserialization if already XML/binary plist
        if let plist = try? PropertyListSerialization.propertyList(from: mobileprovisionData, options: [], format: nil) as? [String: Any] {
            return plist
        }
        
        // 2. Scan for XML plist tags inside CMS wrapper
        let startTokens = ["<?xml", "<plist"].compactMap { $0.data(using: .utf8) }
        guard let endToken = "</plist>".data(using: .utf8) else { return nil }
        
        var startOffset: Int? = nil
        for token in startTokens {
            if let range = mobileprovisionData.range(of: token) {
                if startOffset == nil || range.lowerBound < startOffset! {
                    startOffset = range.lowerBound
                }
            }
        }
        
        guard let start = startOffset else { return nil }
        guard let endRange = mobileprovisionData.range(of: endToken, in: start..<mobileprovisionData.count) else {
            return nil
        }
        
        let xmlData = mobileprovisionData.subdata(in: start..<endRange.upperBound)
        return (try? PropertyListSerialization.propertyList(from: xmlData, options: [], format: nil)) as? [String: Any]
    }
    
    /// Classifies an application based on memory metadata.
    ///
    /// - Parameters:
    ///   - cryptid: The encryption identifier from Mach-O LC_ENCRYPTION_INFO_64 (0 = unencrypted, 1 = FairPlay encrypted).
    ///   - mobileprovisionData: Optional raw bytes of `embedded.mobileprovision`.
    ///   - receiptData: Optional raw bytes of `_MASReceipt/receipt` or `StoreKit/receipt`.
    ///   - hasSandboxReceipt: True if `StoreKit/sandboxReceipt` exists in the bundle.
    /// - Returns: A `ClassificationResult` containing the detected channel and signing metadata.
    public static func classify(
        cryptid: UInt32,
        mobileprovisionData: Data? = nil,
        receiptData: Data? = nil,
        hasSandboxReceipt: Bool = false
    ) -> ClassificationResult {
        let isEncrypted = (cryptid != 0)
        let hasProvision = (mobileprovisionData != nil && !mobileprovisionData!.isEmpty)
        let hasReceipt = (receiptData != nil && !receiptData!.isEmpty) || hasSandboxReceipt
        
        var parsedPlist: [String: Any]? = nil
        if let data = mobileprovisionData {
            parsedPlist = extractPlist(from: data)
        }
        
        var isEnterprise = false
        var teamId: String? = nil
        var teamName: String? = nil
        var profileName: String? = nil
        var hasBetaReportsActive = false
        
        if let plist = parsedPlist {
            if let allDevices = plist["ProvisionsAllDevices"] as? Bool, allDevices {
                isEnterprise = true
            }
            if let teamIds = plist["TeamIdentifier"] as? [String], let first = teamIds.first {
                teamId = first
            } else if let appPrefixes = plist["ApplicationIdentifierPrefix"] as? [String], let first = appPrefixes.first {
                teamId = first
            }
            teamName = plist["TeamName"] as? String
            profileName = plist["Name"] as? String
            if let beta = plist["BetaReportsActive"] as? Bool, beta {
                hasBetaReportsActive = true
            }
            if let entDict = plist["Entitlements"] as? [String: Any],
               let betaEnt = entDict["beta-reports-active"] as? Bool, betaEnt {
                hasBetaReportsActive = true
            }
        }
        
        // FairPlay Encrypted Binaries (App Store or TestFlight)
        if isEncrypted {
            var isTestFlight = hasSandboxReceipt || hasBetaReportsActive
            if !isTestFlight, let rData = receiptData {
                let receiptStr = String(decoding: rData, as: UTF8.self).lowercased()
                if receiptStr.contains("sandbox") || receiptStr.contains("betareportsactive") || receiptStr.contains("testflight") {
                    isTestFlight = true
                }
            }
            
            if isTestFlight {
                return ClassificationResult(
                    channel: .testFlight,
                    teamIdentifier: teamId,
                    teamName: teamName,
                    profileName: profileName,
                    isEnterprise: false,
                    hasMobileProvision: hasProvision,
                    hasReceipt: true,
                    isFairPlayEncrypted: true,
                    details: "TestFlight Beta: FairPlay DRM encrypted binary (cryptid=1) with sandbox or beta receipt markers."
                )
            } else {
                return ClassificationResult(
                    channel: .appStore,
                    teamIdentifier: teamId,
                    teamName: teamName,
                    profileName: profileName,
                    isEnterprise: false,
                    hasMobileProvision: hasProvision,
                    hasReceipt: hasReceipt,
                    isFairPlayEncrypted: true,
                    details: "App Store: FairPlay DRM encrypted production binary (cryptid=1) released through Apple App Store."
                )
            }
        }
        
        // Unencrypted Binaries (Sideloaded or Enterprise)
        if isEnterprise {
            return ClassificationResult(
                channel: .enterpriseInHouse,
                teamIdentifier: teamId,
                teamName: teamName,
                profileName: profileName,
                isEnterprise: true,
                hasMobileProvision: true,
                hasReceipt: hasReceipt,
                isFairPlayEncrypted: false,
                details: "Enterprise In-House: Unencrypted binary signed with enterprise provisioning profile (ProvisionsAllDevices: true)."
            )
        } else {
            let note = hasProvision ?
                "Unencrypted binary signed with developer/personal provisioning profile (ProvisionedDevices list)." :
                "Unencrypted binary without embedded provisioning profile (Ad-Hoc / TrollStore / ldid signed)."
            return ClassificationResult(
                channel: .developerSideloaded,
                teamIdentifier: teamId,
                teamName: teamName,
                profileName: profileName,
                isEnterprise: false,
                hasMobileProvision: hasProvision,
                hasReceipt: hasReceipt,
                isFairPlayEncrypted: false,
                details: "Developer Sideloaded: \(note)"
            )
        }
    }
    
    /// Classifies an installed or extracted bundle URL (100% read-only).
    ///
    /// - Parameters:
    ///   - bundleURL: The URL of the `.app` bundle directory.
    ///   - cryptid: The encryption identifier parsed from the main executable Mach-O header.
    /// - Returns: A `ClassificationResult`.
    public static func classifyBundle(
        at bundleURL: URL,
        cryptid: UInt32
    ) -> ClassificationResult {
        let provURL = bundleURL.appendingPathComponent("embedded.mobileprovision")
        let provData = try? Data(contentsOf: provURL, options: .mappedIfSafe)
        
        let sandboxReceiptURL = bundleURL.appendingPathComponent("StoreKit/sandboxReceipt")
        let hasSandboxReceipt = FileManager.default.fileExists(atPath: sandboxReceiptURL.path)
        
        var receiptData: Data? = nil
        let masReceiptURL = bundleURL.appendingPathComponent("_MASReceipt/receipt")
        let storeKitReceiptURL = bundleURL.appendingPathComponent("StoreKit/receipt")
        if let data = try? Data(contentsOf: masReceiptURL, options: .mappedIfSafe) {
            receiptData = data
        } else if let data = try? Data(contentsOf: storeKitReceiptURL, options: .mappedIfSafe) {
            receiptData = data
        }
        
        return classify(
            cryptid: cryptid,
            mobileprovisionData: provData,
            receiptData: receiptData,
            hasSandboxReceipt: hasSandboxReceipt
        )
    }
}
