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
        public let descriptionEn: String

        public init(
            name: String,
            bundleIdPatterns: [String],
            displayNames: [String],
            description: String,
            descriptionEn: String = ""
        ) {
            self.name = name
            self.bundleIdPatterns = bundleIdPatterns
            self.displayNames = displayNames
            self.description = description
            self.descriptionEn = descriptionEn.isEmpty ? description : descriptionEn
        }

        public var localizedDescription: String {
            WQLocale.pick(en: descriptionEn, zh: description)
        }
    }

    public static let targetBrands: [ImpersonatedBrand] = [
        ImpersonatedBrand(
            name: "MetaMask",
            bundleIdPatterns: ["io.metamask", "metamask"],
            displayNames: ["metamask", "小狐狸"],
            description: "主流 Web3 以太坊钱包，常见伪造版本用于窃取助记词与私钥",
            descriptionEn: "Major Web3 Ethereum wallet; fake builds commonly harvest seed phrases and private keys"
        ),
        ImpersonatedBrand(
            name: "Trust Wallet",
            bundleIdPatterns: ["com.sixdays.trust", "trustwallet"],
            displayNames: ["trust wallet", "trustwallet"],
            description: "多链加密货币钱包，常见侧载重打包用于注入资产划转后门",
            descriptionEn: "Multi-chain crypto wallet; sideloaded clones frequently embed asset-draining backdoors"
        ),
        ImpersonatedBrand(
            name: "Phantom",
            bundleIdPatterns: ["app.phantom", "phantom"],
            displayNames: ["phantom"],
            description: "Solana / 多链钱包，钓鱼重打包高发目标",
            descriptionEn: "Solana / multi-chain wallet; frequent target of phishing repackages"
        ),
        ImpersonatedBrand(
            name: "OKX",
            bundleIdPatterns: ["com.okex.ios", "com.okinc.okx", "com.okx.ios"],
            displayNames: ["okx", "欧易"],
            description: "加密货币交易所，钓鱼包通常伪装为企业版以盗取登录令牌与资金",
            descriptionEn: "Crypto exchange app; phishing builds pose as enterprise apps to steal login tokens and funds"
        ),
        ImpersonatedBrand(
            name: "Binance",
            bundleIdPatterns: ["com.binance.binance", "com.binance.ios"],
            displayNames: ["binance", "币安"],
            description: "全球最大加密资产平台，非法分发包极高概率为账户凭证嗅探木马",
            descriptionEn: "Global crypto exchange; unofficial sideload builds are very likely credential-stealing trojans"
        ),
        ImpersonatedBrand(
            name: "TokenPocket",
            bundleIdPatterns: ["vip.mytokenpocket", "tokenpocket"],
            displayNames: ["tokenpocket", "tp钱包"],
            description: "多链移动钱包，侧载伪装常用于自动签名恶意合约",
            descriptionEn: "Multi-chain mobile wallet; sideloaded clones are often used to auto-sign malicious contracts"
        ),
        ImpersonatedBrand(
            name: "imToken",
            bundleIdPatterns: ["im.token.app", "org.consenlabs.token"],
            displayNames: ["imtoken"],
            description: "去中心化钱包，二次打包常见后门",
            descriptionEn: "Decentralized crypto wallet; repackaged builds frequently carry backdoors"
        ),
        ImpersonatedBrand(
            name: "Bitget",
            bundleIdPatterns: ["com.bitkeep.wallet", "com.bitget.ios"],
            displayNames: ["bitget", "bitkeep"],
            description: "Web3 钱包与交易所应用",
            descriptionEn: "Web3 wallet and exchange app"
        ),
        ImpersonatedBrand(
            name: "Telegram",
            bundleIdPatterns: ["org.telegram.messenger", "org.telegram.telegram-ios"],
            displayNames: ["telegram", "纸飞机", "tg"],
            description: "加密通讯软件，非官方重打包包常内嵌会话历史记录上传后门",
            descriptionEn: "Encrypted messenger; unofficial repackages often embed session token and chat exfiltration backdoors"
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
        "PhotoLibraryServices",
        "systemPhotoLibrary",
        "sharedPhotoLibrary"
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
                        description: WQLocale.pick(
                            en: "Unauthorized linkage to private Apple Photos framework \(fw), enabling silent photo library access without TCC consent (CVE-2026-112676 vector).",
                            zh: "应用非法链接了 Apple 内部相册私有框架 \(fw)。可在未经 TCC 提示下直接读取用户相册 (CVE-2026-112676 攻击向量)。"
                        ),
                        category: "Private Photos Bypass",
                        location: "LC_LOAD_DYLIB: \(dylib)",
                        severity: .highRisk
                    ))
                }
            }
        }

        // Symbol checks
        let privateSelectorsOnly: Set<String> = ["systemPhotoLibrary"]
        for sym in symbols {
            for targetSym in photosSymbols where targetSym != "sharedPhotoLibrary" {
                let matched = privateSelectorsOnly.contains(targetSym) ? (sym == targetSym || sym.contains(" \(targetSym)]")) : sym.contains(targetSym)
                if matched {
                    indicators.append(ThreatIndicator(
                        signature: targetSym,
                        description: WQLocale.pick(
                            en: "Binary imports private Apple Photos symbol \(sym), indicating potential unauthorized photo exfiltration.",
                            zh: "二进制包含私有相册调用符号 \(sym)，疑似利用私有接口窃取系统照片。"
                        ),
                        category: "Private Photos Bypass",
                        location: "LC_SYMTAB: \(sym)",
                        severity: .highRisk
                    ))
                    break
                }
            }
        }

        // Entitlement checks (ignore explicit boolean `false` / integer `0` placeholders)
        for (key, val) in entitlements {
            if isExplicitFalseOrZeroEntitlementValue(val) {
                continue
            }
            if key.hasPrefix(photosEntitlementPrefix) || key == photosBourgeoisieEntitlement {
                indicators.append(ThreatIndicator(
                    signature: key,
                    description: WQLocale.pick(
                        en: "Declares restricted Apple private Photos entitlement (\(key)), bypassing TCC privacy protections.",
                        zh: "声明了 Apple 内部相册私有 Entitlement (\(key))，可规避相册隐私受控保护。"
                    ),
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
                        description: WQLocale.pick(
                            en: "Bundles embedded libbrotli library (\(dylib)). Verify bundled version is >= 1.2.1; earlier versions suffer from a CVSS 9.2 heap OOB write RCE (CVE-2026-111497 / HTTP2Shell).",
                            zh: "应用内嵌打包了 libbrotli 动态库 (\(dylib))。请核验版本是否 >= 1.2.1，早期版本存在 CVSS 9.2 堆溢出远程代码执行高危漏洞 (CVE-2026-111497 / HTTP2Shell)。"
                        ),
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
                    description: WQLocale.pick(
                        en: "Binary contains libbrotli decoder symbol \(sym). Unpatched static builds may be exposed to CVE-2026-111497.",
                        zh: "二进制包含 libbrotli 解码符号 \(sym)。若内嵌库未打补丁，可能受 CVE-2026-111497 漏洞威胁。"
                    ),
                    category: "Supply Chain Notice (libbrotli)",
                    location: "LC_SYMTAB: \(sym)",
                    severity: .caution
                ))
                break
            }
        }

        return indicators
    }

    /// Extracts lowercase ASCII brand tokens from an original-case display name, splitting on:
    /// - Non-ASCII boundaries (e.g. `"WeChat多开"` -> `"WeChat"`),
    /// - Punctuation / whitespace,
    /// - CamelCase transitions (`"TelegramX"` -> `"telegram"`, `"x"`; `"MetaMaskWallet"` -> `"meta"`, `"mask"`, `"wallet"`, `"metamask"`),
    /// - Acronym-to-word transitions (`"OKXWallet"` -> `"okx"`, `"wallet"`; `"TGPro"` -> `"tg"`, `"pro"`).
    public static func extractBrandTokens(from rawDisplayName: String) -> Set<String> {
        var tokens: Set<String> = []
        let asciiWords = rawDisplayName.split { !$0.isASCII || (!$0.isLetter && !$0.isNumber) }

        for wordSub in asciiWords {
            let chars = Array(wordSub)
            guard !chars.isEmpty else { continue }
            tokens.insert(String(chars).lowercased())

            var subTokens: [String] = []
            var current: [Character] = [chars[0]]
            for i in 1..<chars.count {
                let prev = chars[i - 1]
                let cur = chars[i]
                let lowerToUpper = prev.isLowercase && cur.isUppercase
                let acronymToWord = prev.isUppercase && cur.isUppercase && (i + 1 < chars.count && chars[i + 1].isLowercase)
                let letterDigitSplit = (prev.isLetter && cur.isNumber) || (prev.isNumber && cur.isLetter)

                if lowerToUpper || acronymToWord || letterDigitSplit {
                    subTokens.append(String(current).lowercased())
                    current = [cur]
                } else {
                    current.append(cur)
                }
            }
            subTokens.append(String(current).lowercased())

            for t in subTokens where !t.isEmpty {
                tokens.insert(t)
            }
            // Include contiguous camel-pair bigrams (e.g. Meta+Mask -> metamask, Trust+Wallet -> trustwallet, We+Chat -> wechat)
            if subTokens.count >= 2 {
                for i in 0..<(subTokens.count - 1) {
                    tokens.insert(subTokens[i] + subTokens[i + 1])
                }
            }
        }

        return tokens
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
        let rawBid = (bundleId ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let trimmedOrigName = (displayName ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let rawName = trimmedOrigName.lowercased()
        let asciiTokens = extractBrandTokens(from: trimmedOrigName)

        for brand in targetBrands {
            let matchBid = !rawBid.isEmpty && brand.bundleIdPatterns.contains { pat in
                rawBid == pat
                    || rawBid.hasPrefix(pat + ".")
                    || rawBid.contains("." + pat + ".")
                    || rawBid.hasSuffix("." + pat)
            }
            let matchName = !rawName.isEmpty && brand.displayNames.contains { pat in
                let isASCII = pat.unicodeScalars.allSatisfy { $0.isASCII }
                if isASCII && !pat.contains(" ") {
                    // Single-word ASCII brand/alias (e.g., "tg", "okx", "telegram", "metamask"): require exact word/camel token boundary
                    // so substrings inside unrelated words ("NetGuard", "PostgREST", "GitGraph", "ZeroTrust") never false-positive.
                    return rawName == pat || asciiTokens.contains(pat)
                }
                return rawName == pat || rawName.contains(pat)
            }

            if matchBid || matchName {
                indicators.append(ThreatIndicator(
                    signature: "IMPERSONATION:\(brand.name)",
                    description: WQLocale.pick(
                        en: "HIGH RISK: Sideloaded unencrypted package impersonates '\(brand.name)'. Official releases ship exclusively via the App Store; unofficial repackages are prime vectors for seed-phrase/fund drainers. \(brand.localizedDescription).",
                        zh: "高危告警：侧载未加密软件包冒充知名应用 '\(brand.name)'。官方应用仅通过 App Store 发行，非官方重打包版本为高危助记词/资金窃取木马（Drainer）！\(brand.description)。"
                    ),
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
        var flaggedFiles: Set<String> = []

        for dylib in linkedDylibs {
            var matchedKnownHooker = false
            // Check for explicit hooking frameworks
            for hooker in knownHookingFrameworks {
                if dylib.contains(hooker) {
                    indicators.append(ThreatIndicator(
                        signature: hooker,
                        description: WQLocale.pick(
                            en: "Binary links hooking/injection framework \(hooker), indicating third-party tampering and runtime method-swizzling capabilities.",
                            zh: "二进制加载了越狱挂钩与注入框架 \(hooker)，表明该软件包已被第三方二次篡改并具备动态方法挂钩能力。"
                        ),
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

            let lowerDylib = dylib.lowercased()
            let filename = (dylib as NSString).lastPathComponent.lowercased()
            guard !filename.isEmpty else { continue }

            // Dedicated sideload tweak injection folders (.app/Dylibs/* or .app/DynamicLibraries/*)
            let isInSideloadTweakFolder =
                lowerDylib.hasPrefix("@executable_path/dylibs/") ||
                lowerDylib.hasPrefix("@executable_path/dynamiclibraries/") ||
                lowerDylib.contains("/dylibs/") ||
                lowerDylib.contains("/dynamiclibraries/")

            if isInSideloadTweakFolder && filename.hasSuffix(".dylib") {
                if flaggedFiles.insert(filename).inserted {
                    indicators.append(ThreatIndicator(
                        signature: filename,
                        description: WQLocale.pick(
                            en: "Detected dynamic library in sideload tweak folder: \(filename) (commonly injected by Feather / Cyan / Azule). Verify origin before installing.",
                            zh: "检测到侧载注入目录动态库: \(filename)（常见于 Feather / Cyan / Azule 第三方插件注入），请核实注入组件来源。"
                        ),
                        category: "Injected Tweak / Modded IPA",
                        location: "Embedded Dylib: \(dylib)",
                        severity: .caution
                    ))
                }
                continue
            }

            // Check non-system @executable_path/ or @rpath/ tweaks
            if dylib.hasPrefix("@executable_path/") || dylib.hasPrefix("@rpath/") {
                for pattern in suspiciousTweakPatterns {
                    if filename.contains(pattern) {
                        if flaggedFiles.insert(filename).inserted {
                            indicators.append(ThreatIndicator(
                                signature: filename,
                                description: WQLocale.pick(
                                    en: "Detected embedded tweak or suspicious injected dynamic library: \(filename)",
                                    zh: "检测到内嵌可疑注入插件或外挂动态库: \(filename)"
                                ),
                                category: "Injected Tweak / Modded IPA",
                                location: "LC_LOAD_DYLIB: \(dylib)",
                                severity: .caution
                            ))
                        }
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
                description: WQLocale.pick(
                    en: "Background clipboard snooping tuple detected: persistent background modes (\(modesStr)) combined with UIPasteboard symbols. High probability of silently harvesting copied seed phrases or passwords.",
                    zh: "检测到后台剪贴板监听特征元组：应用声明了常驻后台模式 (\(modesStr)) 且二进制引用了 UIPasteboard 读取接口。极高概率用于在后台持续轮询窃取用户复制的助记词或密码凭证。"
                ),
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
                description: WQLocale.pick(
                    en: "HIGH RISK: Spoofed corporate supervision state (IsSupervised == true) detected. On un-enrolled retail devices this can cause an Infinite Setup Assistant Loop or unauthorized MDM policy enforcement.",
                    zh: "高危告警：检测到当前设备处于伪装企业受监管状态 (IsSupervised == true)。零售设备若未授权注册 Apple Business Manager，将引发无限设置向导死锁（Infinite Setup Assistant Loop）或被第三方 MDM 远程下发恶意策略。"
                ),
                category: "Fake Supervision / Rogue Profile",
                location: cloudConfigURL.path,
                severity: .highRisk
            ))
        } else {
            indicators.append(ThreatIndicator(
                signature: "CloudConfigurationDetails.plist (Residual)",
                description: WQLocale.pick(
                    en: "Residual non-standard CloudConfigurationDetails.plist file detected, which may trigger configuration validation errors.",
                    zh: "检测到系统残留的非标准 CloudConfigurationDetails.plist 文件。可能导致后续系统配置文件校验报错。"
                ),
                category: "Fake Supervision / Rogue Profile",
                location: cloudConfigURL.path,
                severity: .caution
            ))
        }

        return indicators
    }

    /// Returns `true` when an entitlement value is an explicit boolean `false` or numeric integer `0` placeholder
    /// (e.g. `Bool(false)`, `Int(0)`, `Int64(0)`, `UInt64(0)`, or non-CFBoolean `NSNumber(value: 0)` from XML/DER blobs).
    private static func isExplicitFalseOrZeroEntitlementValue(_ val: Any?) -> Bool {
        guard let val else { return false }
        if let boolVal = val as? Bool {
            return !boolVal
        }
        if let intVal = val as? Int {
            return intVal == 0
        }
        if let int64Val = val as? Int64 {
            return int64Val == 0
        }
        if let uint64Val = val as? UInt64 {
            return uint64Val == 0
        }
        if let int32Val = val as? Int32 {
            return int32Val == 0
        }
        if let numVal = val as? NSNumber {
            return numVal.int64Value == 0 && numVal.doubleValue == 0.0
        }
        return false
    }

    /// 7. Evaluates AudioMxd Microphone TCC Bypass (CVE-2026-65339) indicators.
    public static func evaluateAudioMxdBypass(
        linkedDylibs: [String],
        symbols: [String],
        entitlements: [String: Any],
        cryptid: UInt32
    ) -> [ThreatIndicator] {
        var indicators: [ThreatIndicator] = []
        var emittedSignatures: Set<String> = []

        // Entitlement checks (ignore explicit boolean `false` / integer `0` placeholders)
        for key in entitlements.keys.sorted() {
            if isExplicitFalseOrZeroEntitlementValue(entitlements[key]) {
                continue
            }
            if key.hasPrefix("com.apple.private.mediaexperience") || key.hasPrefix("com.apple.private.cmsession") {
                let sig = "CVE-2026-65339:\(key)"
                if emittedSignatures.insert(sig).inserted {
                    indicators.append(ThreatIndicator(
                        signature: sig,
                        description: WQLocale.pick(
                            en: "Declares restricted Apple private AudioMxd / MediaExperience entitlement (\(key)), enabling microphone TCC privacy bypass (CVE-2026-65339).",
                            zh: "声明了 Apple 私有 AudioMxd / MediaExperience 权限 (\(key))，可绕过系统麦克风 TCC 隐私授权保护 (CVE-2026-65339)。"
                        ),
                        category: "AudioMxd Mic TCC Bypass (CVE-2026-65339)",
                        location: "CSBlob Entitlements",
                        severity: .highRisk
                    ))
                }
            }
        }

        // Binary checks on unencrypted images (never flag AudioToolbox/AVFAudio/AURemoteIO)
        if cryptid == 0 {
            let mediaFwToken = IOCTokenArmor.tMediaExpFw
            if let mediaRule = SignatureCatalog.standaloneExploitDylibRules[mediaFwToken] {
                for dylib in linkedDylibs where dylib.contains(mediaFwToken) {
                    if emittedSignatures.insert(mediaRule.pattern).inserted {
                        indicators.append(mediaRule.toIndicator(at: "LC_LOAD_DYLIB: \(dylib)"))
                    }
                }
            }

            let targetSymbolKeys = [IOCTokenArmor.tCMSessionSetProp, IOCTokenArmor.tAudioSessionSetCMProp]
            for targetKey in targetSymbolKeys {
                guard let rule = SignatureCatalog.standaloneExploitSymbolRules[targetKey] else { continue }
                for sym in symbols {
                    let cleanSym = sym.hasPrefix("_") ? String(sym.dropFirst()) : sym
                    if cleanSym == targetKey || sym.contains(targetKey) {
                        if emittedSignatures.insert(rule.pattern).inserted {
                            indicators.append(rule.toIndicator(at: "LC_SYMTAB: \(sym)"))
                        }
                        break
                    }
                }
            }
        }

        return indicators
    }

    /// 8. Evaluates BookRestore / bl_sbx escape and MobileGestalt system tampering indicators.
    public static func evaluateBookRestoreAndGestalt(
        linkedDylibs: [String],
        textStrings: [String],
        entitlements: [String: Any],
        cryptid: UInt32
    ) -> [ThreatIndicator] {
        var indicators: [ThreatIndicator] = []
        var emittedSignatures: Set<String> = []

        // Entitlement checks (ignore explicit boolean `false` / integer `0` placeholders)
        for key in entitlements.keys.sorted() {
            if isExplicitFalseOrZeroEntitlementValue(entitlements[key]) {
                continue
            }
            if key.hasPrefix("com.apple.private.bookassetd") || key.hasPrefix(IOCTokenArmor.tStorePrivPrefix) {
                let sig = "BookRestore:\(key)"
                if emittedSignatures.insert(sig).inserted {
                    indicators.append(ThreatIndicator(
                        signature: sig,
                        description: WQLocale.pick(
                            en: "Declares restricted Apple private bookstore/asset daemon entitlement (\(key)), associated with BookRestore / bl_sbx sandbox escape primitives.",
                            zh: "声明了 Apple 私有图书资源守护进程权限 (\(key))，与 BookRestore / bl_sbx 沙盒逃逸利用特征关联。"
                        ),
                        category: "BookRestore / bl_sbx Escape",
                        location: "CSBlob Entitlements",
                        severity: .highRisk
                    ))
                }
            } else if key.hasPrefix("com.apple.private.MobileGestalt") {
                let sig = "MobileGestaltTamper:\(key)"
                if emittedSignatures.insert(sig).inserted {
                    indicators.append(ThreatIndicator(
                        signature: sig,
                        description: WQLocale.pick(
                            en: "Declares restricted Apple private MobileGestalt entitlement (\(key)), enabling system device-capability plist tampering.",
                            zh: "声明了 Apple 私有 MobileGestalt 特权 (\(key))，可用于篡改系统设备配置属性列表。"
                        ),
                        category: "MobileGestalt System Tampering",
                        location: "CSBlob Entitlements",
                        severity: .highRisk
                    ))
                }
            }
        }

        // Binary dylib & string checks on unencrypted images
        if cryptid == 0 {
            let bookFwToken = IOCTokenArmor.tBookPrivFw
            if let bookRule = SignatureCatalog.standaloneExploitDylibRules[bookFwToken] {
                for dylib in linkedDylibs where dylib.contains(bookFwToken) {
                    if emittedSignatures.insert(bookRule.pattern).inserted {
                        indicators.append(bookRule.toIndicator(at: "LC_LOAD_DYLIB: \(dylib)"))
                    }
                }
            }

            for key in SignatureCatalog.standaloneExploitStringRules.keys.sorted() {
                guard let rule = SignatureCatalog.standaloneExploitStringRules[key] else { continue }
                for str in textStrings where str.contains(key) {
                    if emittedSignatures.insert(rule.pattern).inserted {
                        indicators.append(rule.toIndicator(at: "__TEXT: \(str)"))
                    }
                    break
                }
            }
        }

        return indicators
    }

    /// 9. Evaluates AccessorySetupKit Bluetooth TCC Bypass (CVE-2026-84493) indicators.
    public static func evaluateAccessorySetupBypass(
        linkedDylibs: [String],
        symbols: [String],
        infoPlist: [String: Any],
        entitlements: [String: Any],
        installChannel: InstallChannel,
        cryptid: UInt32
    ) -> [ThreatIndicator] {
        guard installChannel != .appStore else {
            return []
        }

        var indicators: [ThreatIndicator] = []

        // 1. Private AccessorySetupKit entitlements on non-App Store builds
        let matchedAccessoryEntKeys = entitlements.keys.sorted().filter { key in
            if isExplicitFalseOrZeroEntitlementValue(entitlements[key]) {
                return false
            }
            return key.hasPrefix("com.apple.private.accessorysetupkit")
        }
        if !matchedAccessoryEntKeys.isEmpty {
            let joined = matchedAccessoryEntKeys.joined(separator: ", ")
            indicators.append(ThreatIndicator(
                signature: "CVE-2026-84493:PrivateAccessoryEntitlement",
                description: WQLocale.pick(
                    en: "Declares restricted Apple private AccessorySetupKit entitlement (\(joined)) on non-App Store build, enabling Bluetooth pairing TCC bypass (CVE-2026-84493).",
                    zh: "非 App Store 应用声明了 Apple 私有 AccessorySetupKit 特权 (\(joined))，可绕过蓝牙配对 TCC 隐私授权检查 (CVE-2026-84493)。"
                ),
                category: "AccessorySetupKit Bluetooth TCC Bypass (CVE-2026-84493)",
                location: "CSBlob Entitlements",
                severity: .highRisk
            ))
        }

        // 2. Unencrypted non-App Store binaries invoking AccessorySetupKit without required Info.plist keys
        if cryptid == 0 {
            let linksAccessorySetup = linkedDylibs.contains { $0.contains("AccessorySetupKit.framework") }
            let usesAccessorySession = symbols.contains { $0.contains("ASAccessorySession") }

            if linksAccessorySetup || usesAccessorySession {
                let btUsageDesc = (infoPlist["NSBluetoothAlwaysUsageDescription"] as? String)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let hasValidBluetoothDesc = !btUsageDesc.isEmpty

                let supportsList = (infoPlist["NSAccessorySetupKitSupports"] as? [Any] ?? [])
                    .compactMap { $0 as? String }
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
                let hasValidSupports = !supportsList.isEmpty

                if !hasValidBluetoothDesc || !hasValidSupports {
                    indicators.append(ThreatIndicator(
                        signature: "CVE-2026-84493:AccessorySetupKitBypass",
                        description: WQLocale.pick(
                            en: "Uses AccessorySetupKit / ASAccessorySession while omitting required Info.plist declarations (NSBluetoothAlwaysUsageDescription and non-empty NSAccessorySetupKitSupports), matching CVE-2026-84493 silent Bluetooth TCC bypass.",
                            zh: "应用调用了 AccessorySetupKit / ASAccessorySession 但缺失必须的 Info.plist 声明（NSBluetoothAlwaysUsageDescription 或非空 NSAccessorySetupKitSupports），符合 CVE-2026-84493 静默蓝牙 TCC 隐私绕过特征。"
                        ),
                        category: "AccessorySetupKit Bluetooth TCC Bypass (CVE-2026-84493)",
                        location: "Info.plist + Mach-O",
                        severity: .highRisk
                    ))
                }
            }
        }

        return indicators
    }

    /// Parses boolean or numeric (0/1) entitlement scalars from XML Slot 5 / DER Slot 7 dictionaries.
    /// Returns `nil` for non-boolean values (e.g., container identifier strings).
    private static func parseEntitlementBool(_ val: Any?) -> Bool? {
        guard let val else { return nil }
        if let boolVal = val as? Bool {
            return boolVal
        }
        if let intVal = val as? Int {
            return intVal != 0
        }
        if let int64Val = val as? Int64 {
            return int64Val != 0
        }
        if let uint64Val = val as? UInt64 {
            return uint64Val != 0
        }
        if let int32Val = val as? Int32 {
            return int32Val != 0
        }
        if let numVal = val as? NSNumber {
            return numVal.int64Value != 0 || numVal.doubleValue != 0.0
        }
        return nil
    }

    private static func extractNonEmptyEntitlementStrings(_ val: Any?) -> [String] {
        guard let val else { return [] }
        if let strArr = val as? [String] {
            return strArr
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        }
        if let anyArr = val as? [Any] {
            return anyArr
                .compactMap { $0 as? String }
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        }
        if let single = val as? String {
            let trimmed = single.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? [] : [trimmed]
        }
        return []
    }

    /// 10. Shared evaluator for sandbox-escape, platform-privilege, TCC bypass, and wildcard keychain entitlements
    /// across `.ipa` archives (`IPAPackageScanner`) and `.app` bundles (`SecurityPipeline`).
    public static func evaluateDangerousEntitlements(
        bundleId: String,
        installChannel: InstallChannel,
        entitlements: [String: Any],
        hasUnencryptedBinary: Bool = false,
        location: String = "CSBlob Entitlements"
    ) -> [ThreatIndicator] {
        var indicators: [ThreatIndicator] = []
        let trimmedBundleId = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        let isTrustedAppleApp = trimmedBundleId.hasPrefix("com.apple.") && installChannel == .appStore && !hasUnencryptedBinary
        guard !isTrustedAppleApp else {
            return []
        }

        let sandboxEscapeRules: [(key: String, expectedBool: Bool, allowNonEmptyCollection: Bool, descEn: String, descZh: String)] = [
            (
                "com.apple.private.security.no-container",
                true,
                false,
                "Declares no-container entitlement, permitting direct cross-sandbox read/write access to other applications' data.",
                "声明了无容器隔离私有权限 (no-container)，可直接跨沙盒读写全机应用数据。"
            ),
            (
                "com.apple.private.security.no-sandbox",
                true,
                false,
                "Declares no-sandbox entitlement, bypassing iOS Seatbelt sandbox confinement completely.",
                "声明了关闭 Seatbelt 沙盒私有权限 (no-sandbox)，完全脱离 iOS 沙盒隔离控制。"
            ),
            (
                "com.apple.private.security.container-required",
                false,
                false,
                "Explicitly disables container enforcement (container-required=false), enabling unsandboxed execution.",
                "显式关闭了容器强制约束 (container-required=false)，具备沙盒逃逸执行能力。"
            ),
            (
                "com.apple.private.MobileContainerManager.allowed",
                true,
                true,
                "Declares direct private MobileContainerManager daemon privilege for querying or manipulating containers across applications.",
                "声明了 MobileContainerManager 私有守护进程直连特权，可跨应用查询或操作容器。"
            ),
            (
                "com.apple.private.security.storage.AppDataContainers",
                true,
                true,
                "Declares internal Apple AppDataContainers cross-application filesystem access entitlement.",
                "声明了 Apple 内部跨应用数据容器直接访问权限 (AppDataContainers)。"
            )
        ]

        for rule in sandboxEscapeRules {
            guard let rawVal = entitlements[rule.key] else { continue }
            let matchedBool = (parseEntitlementBool(rawVal) == rule.expectedBool)
            let matchedCollection = rule.allowNonEmptyCollection && !extractNonEmptyEntitlementStrings(rawVal).isEmpty
            if matchedBool || matchedCollection {
                indicators.append(ThreatIndicator(
                    signature: rule.key,
                    description: WQLocale.pick(en: rule.descEn, zh: rule.descZh),
                    category: "Sandbox Escape Entitlement",
                    location: location,
                    severity: .highRisk
                ))
            }
        }

        if parseEntitlementBool(entitlements["platform-application"]) == true && !trimmedBundleId.hasPrefix("com.apple.") {
            indicators.append(ThreatIndicator(
                signature: "platform-application",
                description: WQLocale.pick(
                    en: "Third-party application declares Apple system platform privilege (platform-application=true).",
                    zh: "第三方应用声明了 Apple 平台级系统应用特权 (platform-application=true)。"
                ),
                category: "Privilege Escalation Entitlement",
                location: location,
                severity: .highRisk
            ))
        } else if parseEntitlementBool(entitlements["platform-application"]) == true && (installChannel != .appStore || hasUnencryptedBinary) {
            indicators.append(ThreatIndicator(
                signature: "platform-application",
                description: WQLocale.pick(
                    en: "Sideloaded or unencrypted package declares Apple system platform privilege (platform-application=true).",
                    zh: "侧载或未加密软件包声明了 Apple 平台级系统应用特权 (platform-application=true)。"
                ),
                category: "Privilege Escalation Entitlement",
                location: location,
                severity: .highRisk
            ))
        }

        let tccKeys = ["com.apple.private.tcc.allow", "com.apple.private.tcc.allow-prompting"]
        for tccKey in tccKeys {
            guard let rawVal = entitlements[tccKey] else { continue }
            let services = extractNonEmptyEntitlementStrings(rawVal)
            let boolActive = (parseEntitlementBool(rawVal) == true)
            if !services.isEmpty || boolActive {
                let detail = services.isEmpty ? tccKey : services.joined(separator: ", ")
                indicators.append(ThreatIndicator(
                    signature: tccKey,
                    description: WQLocale.pick(
                        en: "Declares private TCC privacy bypass entitlement \(tccKey) (\(detail)), enabling access to protected user data without standard TCC consent.",
                        zh: "声明了私有 TCC 隐私免授权特权 \(tccKey) (\(detail))，可绕过标准系统授权弹窗访问受保护隐私数据。"
                    ),
                    category: "TCC Privacy Bypass",
                    location: location,
                    severity: .highRisk
                ))
            }
        }

        let keychainGroups = extractNonEmptyEntitlementStrings(entitlements["keychain-access-groups"])
        if keychainGroups.contains("*") || keychainGroups.contains(where: { $0.hasSuffix(".*") }) {
            let joined = keychainGroups.joined(separator: ", ")
            indicators.append(ThreatIndicator(
                signature: "keychain-access-groups(*)",
                description: WQLocale.pick(
                    en: "Declares wildcard keychain access groups (\(joined)), exposing cross-application credentials and private keys.",
                    zh: "声明了通配符钥匙串访问组 (\(joined))，可跨应用读取 Keychain 敏感登录凭证与私钥。"
                ),
                category: "Keychain Credential Exposure",
                location: location,
                severity: .highRisk
            ))
        }

        return indicators
    }
}
