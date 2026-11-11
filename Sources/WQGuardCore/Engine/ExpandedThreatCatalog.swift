//
//  ExpandedThreatCatalog.swift
//  WQGuardCore
//
//  Feature 27: Expanded Local Binary & Bundle Threat Signatures.
//  Detects Private Photos bypass, libbrotli CVE-2026-111497 supply chain notice,
//  repackaged crypto wallet/messenger impersonation, injected dylib/tweak enumeration,
//  background clipboard snooping tuples, and fake supervision inspection.
//

import Foundation

public enum ExpandedThreatCatalog {

    // MARK: - 1. Repackaged Crypto Wallet & Messenger Impersonation
    public struct ImpersonatedBrand: Sendable, Equatable {
        public let name: String
        public let bundleIdPatterns: [String]
        public let displayNames: [String]
        public let description: String

        public init(name: String, bundleIdPatterns: [String], displayNames: [String], description: String) {
            self.name = name
            self.bundleIdPatterns = bundleIdPatterns
            self.displayNames = displayNames
            self.description = description
        }
    }

    public static let targetBrands: [ImpersonatedBrand] = [
        ImpersonatedBrand(
            name: "MetaMask",
            bundleIdPatterns: ["io.metamask", "metamask"],
            displayNames: ["metamask", "小狐狸"],
            description: "主流 Web3 以太坊钱包，常见伪造版本用于窃取助记词与私钥"
        ),
        ImpersonatedBrand(
            name: "Trust Wallet",
            bundleIdPatterns: ["com.sixdays.trust", "trustwallet"],
            displayNames: ["trust wallet", "trust"],
            description: "多链加密货币钱包，常见侧载重打包用于注入资产划转后门"
        ),
        ImpersonatedBrand(
            name: "Phantom",
            bundleIdPatterns: ["app.phantom", "phantom"],
            displayNames: ["phantom"],
            description: "Solana / 多链钱包，钓鱼重打包高发目标"
        ),
        ImpersonatedBrand(
            name: "OKX",
            bundleIdPatterns: ["com.okex.ios", "com.okinc.okx", "com.okx.ios"],
            displayNames: ["okx", "欧易"],
            description: "加密货币交易所，钓鱼包通常伪装为企业版以盗取登录令牌与资金"
        ),
        ImpersonatedBrand(
            name: "Binance",
            bundleIdPatterns: ["com.binance.binance", "com.binance.ios"],
            displayNames: ["binance", "币安"],
            description: "全球最大加密资产平台，非法分发包极高概率为账户凭证嗅探木马"
        ),
        ImpersonatedBrand(
            name: "TokenPocket",
            bundleIdPatterns: ["vip.mytokenpocket", "tokenpocket"],
            displayNames: ["tokenpocket", "tp钱包"],
            description: "多链移动钱包，侧载伪装常用于自动签名恶意合约"
        ),
        ImpersonatedBrand(
            name: "imToken",
            bundleIdPatterns: ["im.token.app", "org.consenlabs.token"],
            displayNames: ["imtoken"],
            description: "去中心化钱包，二次打包常见后门"
        ),
        ImpersonatedBrand(
            name: "Bitget",
            bundleIdPatterns: ["com.bitkeep.wallet", "com.bitget.ios"],
            displayNames: ["bitget", "bitkeep"],
            description: "Web3 钱包与交易所应用"
        ),
        ImpersonatedBrand(
            name: "Telegram",
            bundleIdPatterns: ["org.telegram.messenger", "org.telegram.telegram-ios"],
            displayNames: ["telegram", "纸飞机", "tg"],
            description: "加密通讯软件，非官方重打包包常内嵌会话历史记录上传后门"
        )
    ]

    // MARK: - 2. Private Photos Bypass Signatures
    public static let photosFrameworks: Set<String> = [
        "PhotoLibraryServices.framework",
        "AssetsLibraryServices.framework"
    ]

    public static let photosSymbols: Set<String> = [
        "PLPhotoLibrary",
        "_OBJC_CLASS_$_PLPhotoLibrary",
        "-[PLPhotoLibrary",
        "+[PLPhotoLibrary",
        "PhotoLibraryServices"
    ]

    public static let photosEntitlementPrefix = "com.apple.private.photos."
    public static let photosBourgeoisieEntitlement = "com.apple.photos.bourgeoisie"

    // MARK: - 3. Bundled libbrotli Signatures
    public static let brotliDylibPatterns: [String] = [
        "libbrotli",
        "brotli.framework",
        "libbrotlidec"
    ]

    public static let brotliSymbols: Set<String> = [
        "BrotliDecoderDecompressStream",
        "BrotliDecoderCreateInstance",
        "BrotliDecoderDecompress"
    ]

    // MARK: - 4. Injected Hooking Frameworks & Tweaks
    public static let knownHookingFrameworks: [String] = [
        "CydiaSubstrate",
        "libsubstitute",
        "ElleKit",
        "libhooker",
        "Shadow",
        "Choicy"
    ]

    public static let suspiciousTweakPatterns: [String] = [
        "inject",
        "hook",
        "tweak",
        "patch",
        "crack",
        "substitute"
    ]

    // MARK: - 5. Clipboard Snooping Signatures
    public static let backgroundModesRequiringInspection: Set<String> = [
        "audio",
        "location",
        "voip"
    ]

    public static let pasteboardSymbols: Set<String> = [
        "UIPasteboard",
        "generalPasteboard",
        "UIPasteboardNameGeneral",
        "_OBJC_CLASS_$_UIPasteboard",
        "-[UIPasteboard string]",
        "-[UIPasteboard strings]"
    ]

    // MARK: - Evaluators

    /// 1. Evaluates Private Photos Bypass indicators.
    public static func evaluatePhotosBypass(
        linkedDylibs: [String],
        symbols: [String],
        entitlements: [String: Any],
        cryptid: UInt32
    ) -> [ThreatIndicator] {
        var indicators: [ThreatIndicator] = []

        // Framework checks
        for dylib in linkedDylibs {
            for fw in photosFrameworks {
                if dylib.contains(fw) {
                    indicators.append(ThreatIndicator(
                        signature: fw,
                        description: "应用非法链接了 Apple 内部相册私有框架 \(fw)。可在未经 TCC 提示下直接读取用户相册 (CVE-2026-112676 攻击向量)。",
                        category: "Private Photos Bypass",
                        location: "LC_LOAD_DYLIB: \(dylib)",
                        severity: .highRisk
                    ))
                }
            }
        }

        // Symbol checks
        for sym in symbols {
            for targetSym in photosSymbols {
                if sym.contains(targetSym) {
                    indicators.append(ThreatIndicator(
                        signature: targetSym,
                        description: "二进制包含私有相册调用符号 \(sym)，疑似利用私有接口窃取系统照片。",
                        category: "Private Photos Bypass",
                        location: "LC_SYMTAB: \(sym)",
                        severity: .highRisk
                    ))
                    break
                }
            }
        }

        // Entitlement checks
        for (key, _) in entitlements {
            if key.hasPrefix(photosEntitlementPrefix) || key == photosBourgeoisieEntitlement {
                indicators.append(ThreatIndicator(
                    signature: key,
                    description: "声明了 Apple 内部相册私有 Entitlement (\(key))，可规避相册隐私受控保护。",
                    category: "Private Photos Bypass",
                    location: "CSBlob Entitlements",
                    severity: .highRisk
                ))
            }
        }

        return indicators
    }

    /// 2. Evaluates bundled libbrotli supply chain risk.
    public static func evaluateBrotliSupplyChain(
        linkedDylibs: [String],
        symbols: [String]
    ) -> [ThreatIndicator] {
        var indicators: [ThreatIndicator] = []

        for dylib in linkedDylibs {
            let lower = dylib.lowercased()
            for pattern in brotliDylibPatterns {
                if lower.contains(pattern) {
                    indicators.append(ThreatIndicator(
                        signature: pattern,
                        description: "应用内嵌打包了 libbrotli 动态库 (\(dylib))。请核验版本是否 >= 1.2.1，早期版本存在 CVSS 9.2 堆溢出远程代码执行高危漏洞 (CVE-2026-111497 / HTTP2Shell)。",
                        category: "Supply Chain Notice (libbrotli)",
                        location: "LC_LOAD_DYLIB: \(dylib)",
                        severity: .caution
                    ))
                    break
                }
            }
        }

        for sym in symbols {
            let cleanSym = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
            if brotliSymbols.contains(cleanSym) || brotliSymbols.contains(sym) {
                indicators.append(ThreatIndicator(
                    signature: cleanSym,
                    description: "二进制包含 libbrotli 解码符号 \(sym)。若内嵌库未打补丁，可能受 CVE-2026-111497 漏洞威胁。",
                    category: "Supply Chain Notice (libbrotli)",
                    location: "LC_SYMTAB: \(sym)",
                    severity: .caution
                ))
                break
            }
        }

        return indicators
    }

    /// 3. Evaluates repackaged crypto wallet and messenger impersonation.
    public static func evaluateImpersonation(
        bundleId: String?,
        displayName: String?,
        installChannel: InstallChannel,
        cryptid: UInt32
    ) -> [ThreatIndicator] {
        // Only sideloaded or enterprise packages (cryptid == 0) can be unauthorized repackages
        guard cryptid == 0, installChannel == .developerSideloaded || installChannel == .enterpriseInHouse else {
            return []
        }

        var indicators: [ThreatIndicator] = []
        let rawBid = (bundleId ?? "").lowercased()
        let rawName = (displayName ?? "").lowercased()

        for brand in targetBrands {
            let matchBid = brand.bundleIdPatterns.contains { rawBid.contains($0) }
            let matchName = brand.displayNames.contains { rawName.contains($0) }

            if matchBid || matchName {
                indicators.append(ThreatIndicator(
                    signature: "IMPERSONATION:\(brand.name)",
                    description: "高危告警：侧载未加密软件包冒充知名应用 '\(brand.name)'。官方应用仅通过 App Store 发行，非官方重打包版本为高危助记词/资金窃取木马（Drainer）！\(brand.description)。",
                    category: "Wallet/Messenger Impersonation",
                    location: "BundleID: \(bundleId ?? "nil"), Name: \(displayName ?? "nil")",
                    severity: .highRisk
                ))
            }
        }

        return indicators
    }

    /// 4. Enumerates injected dylibs and modded tweak frameworks.
    public static func evaluateInjectedDylibs(
        linkedDylibs: [String]
    ) -> [ThreatIndicator] {
        var indicators: [ThreatIndicator] = []

        for dylib in linkedDylibs {
            var matchedKnownHooker = false
            // Check for explicit hooking frameworks
            for hooker in knownHookingFrameworks {
                if dylib.contains(hooker) {
                    indicators.append(ThreatIndicator(
                        signature: hooker,
                        description: "二进制加载了越狱挂钩与注入框架 \(hooker)，表明该软件包已被第三方二次篡改并具备动态方法挂钩能力。",
                        category: "Injected Tweak / Modded IPA",
                        location: "LC_LOAD_DYLIB: \(dylib)",
                        severity: .caution
                    ))
                    matchedKnownHooker = true
                }
            }
            if matchedKnownHooker {
                continue
            }

            // Check non-system @executable_path/Frameworks/ tweaks
            if dylib.hasPrefix("@executable_path/Frameworks/") || dylib.hasPrefix("@rpath/") {
                let filename = (dylib as NSString).lastPathComponent.lowercased()
                for pattern in suspiciousTweakPatterns {
                    if filename.contains(pattern) {
                        indicators.append(ThreatIndicator(
                            signature: filename,
                            description: "检测到内嵌可疑注入插件或外挂动态库: \(filename)",
                            category: "Injected Tweak / Modded IPA",
                            location: "LC_LOAD_DYLIB: \(dylib)",
                            severity: .caution
                        ))
                        break
                    }
                }
            }
        }

        return indicators
    }

    /// 5. Evaluates background clipboard snooping behavioral tuple.
    public static func evaluateClipboardSnooping(
        backgroundModes: [String],
        symbols: [String],
        cryptid: UInt32
    ) -> ThreatIndicator? {
        // App must have persistent background mode and be unencrypted
        guard cryptid == 0 else { return nil }
        let hasPersistentMode = backgroundModes.contains { backgroundModesRequiringInspection.contains($0) }
        guard hasPersistentMode else { return nil }

        // Binary references UIPasteboard
        let hasPasteboard = symbols.contains { sym in
            pasteboardSymbols.contains { sym.contains($0) }
        }

        if hasPasteboard {
            let modesStr = backgroundModes.filter { backgroundModesRequiringInspection.contains($0) }.joined(separator: ", ")
            return ThreatIndicator(
                signature: "UIBackgroundModes(\(modesStr))+UIPasteboard",
                description: "检测到后台剪贴板监听特征元组：应用声明了常驻后台模式 (\(modesStr)) 且二进制引用了 UIPasteboard 读取接口。极高概率用于在后台持续轮询窃取用户复制的助记词或密码凭证。",
                category: "Background Clipboard Snooping",
                location: "Info.plist + LC_SYMTAB",
                severity: .highRisk
            )
        }

        return nil
    }

    /// 6. Inspects system configuration profiles for fake supervision in 100% read-only mode.
    public static func evaluateSupervision(
        containerRoot: URL
    ) -> [ThreatIndicator] {
        var indicators: [ThreatIndicator] = []
        let cloudConfigURL = containerRoot
            .appendingPathComponent("systemgroup.com.apple.configurationprofiles")
            .appendingPathComponent("Library")
            .appendingPathComponent("ConfigurationProfiles")
            .appendingPathComponent("CloudConfigurationDetails.plist")

        guard FileManager.default.fileExists(atPath: cloudConfigURL.path) else {
            return []
        }

        // 100% read-only inspection
        guard let data = try? Data(contentsOf: cloudConfigURL, options: .mappedIfSafe),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            return []
        }

        if let isSupervised = plist["IsSupervised"] as? Bool, isSupervised {
            indicators.append(ThreatIndicator(
                signature: "CloudConfigurationDetails.IsSupervised=true",
                description: "高危告警：检测到当前设备处于伪装企业受监管状态 (IsSupervised == true)。零售设备若未授权注册 Apple Business Manager，将引发无限设置向导死锁（Infinite Setup Assistant Loop）或被第三方 MDM 远程下发恶意策略。",
                category: "Fake Supervision / Rogue Profile",
                location: cloudConfigURL.path,
                severity: .highRisk
            ))
        } else {
            indicators.append(ThreatIndicator(
                signature: "CloudConfigurationDetails.plist (Residual)",
                description: "检测到系统残留的非标准 CloudConfigurationDetails.plist 文件。可能导致后续系统配置文件校验报错。",
                category: "Fake Supervision / Rogue Profile",
                location: cloudConfigURL.path,
                severity: .caution
            ))
        }

        return indicators
    }
}
