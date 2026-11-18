//
//  SignatureCatalog.swift
//  WQGuardCore
//
//  Centralized catalog of target signatures, private symbols, dylibs,
//  path leak patterns, and behavioral heuristics.
//

import Foundation

/// Runtime XOR-0x5A IOC token armor preventing scanner binary self-triggering on `__TEXT,__cstring`.
internal enum IOCTokenArmor {
    // Dynamic Foundation call prevents LLVM -O WMO IPSCCP from constant-folding back into __cstring,
    // while remaining 100% Sendable and deterministic (PID is always > 0).
    private static let xorKey: UInt8 = ProcessInfo.processInfo.processIdentifier > -1 ? 0x5A : 0x00

    @inline(never)
    internal static func decode(_ encoded: [UInt8]) -> String {
        var out = [UInt8]()
        out.reserveCapacity(encoded.count)
        for b in encoded {
            out.append(b ^ xorKey)
        }
        return String(decoding: out, as: UTF8.self)
    }

    // Short identifier names ensure __swift5_reflstr / symbol tables never contain IOC substrings:
    internal static var tAudioDaemon: String { decode([0x39, 0x35, 0x37, 0x74, 0x3B, 0x2A, 0x2A, 0x36, 0x3F, 0x74, 0x3B, 0x2F, 0x3E, 0x33, 0x35, 0x74, 0x3B, 0x2F, 0x3E, 0x33, 0x35, 0x37, 0x22, 0x3E]) }
    internal static var tCoreMediaDaemon: String { decode([0x39, 0x35, 0x37, 0x74, 0x3B, 0x2A, 0x2A, 0x36, 0x3F, 0x74, 0x39, 0x35, 0x28, 0x3F, 0x37, 0x3F, 0x3E, 0x33, 0x3B, 0x74, 0x3B, 0x2F, 0x3E, 0x33, 0x35, 0x37, 0x22, 0x3E]) }
    internal static var tBookDaemon: String { decode([0x39, 0x35, 0x37, 0x74, 0x3B, 0x2A, 0x2A, 0x36, 0x3F, 0x74, 0x38, 0x35, 0x35, 0x31, 0x3B, 0x29, 0x29, 0x3F, 0x2E, 0x3E]) }
    internal static var tStoreDaemon: String { decode([0x39, 0x35, 0x37, 0x74, 0x3B, 0x2A, 0x2A, 0x36, 0x3F, 0x74, 0x33, 0x2E, 0x2F, 0x34, 0x3F, 0x29, 0x29, 0x2E, 0x35, 0x28, 0x3F, 0x3E]) }
    internal static var tStorePrivPrefix: String { decode([0x39, 0x35, 0x37, 0x74, 0x3B, 0x2A, 0x2A, 0x36, 0x3F, 0x74, 0x33, 0x2E, 0x2F, 0x34, 0x3F, 0x29, 0x29, 0x2E, 0x35, 0x28, 0x3F, 0x3E, 0x74, 0x2A, 0x28, 0x33, 0x2C, 0x3B, 0x2E, 0x3F]) }
    internal static var tBookSQLite: String { decode([0x18, 0x16, 0x1E, 0x3B, 0x2E, 0x3B, 0x38, 0x3B, 0x29, 0x3F, 0x17, 0x3B, 0x34, 0x3B, 0x3D, 0x3F, 0x28, 0x74, 0x29, 0x2B, 0x36, 0x33, 0x2E, 0x3F]) }
    internal static var tDownloadsSQLite: String { decode([0x3E, 0x35, 0x2D, 0x34, 0x36, 0x35, 0x3B, 0x3E, 0x29, 0x74, 0x68, 0x62, 0x74, 0x29, 0x2B, 0x36, 0x33, 0x2E, 0x3F, 0x3E, 0x38]) }
    internal static var tGestaltPlist: String { decode([0x39, 0x35, 0x37, 0x74, 0x3B, 0x2A, 0x2A, 0x36, 0x3F, 0x74, 0x17, 0x35, 0x38, 0x33, 0x36, 0x3F, 0x1D, 0x3F, 0x29, 0x2E, 0x3B, 0x36, 0x2E, 0x74, 0x2A, 0x36, 0x33, 0x29, 0x2E]) }
    internal static var tGestaltGroup: String { decode([0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x3D, 0x28, 0x35, 0x2F, 0x2A, 0x74, 0x39, 0x35, 0x37, 0x74, 0x3B, 0x2A, 0x2A, 0x36, 0x3F, 0x74, 0x37, 0x35, 0x38, 0x33, 0x36, 0x3F, 0x3D, 0x3F, 0x29, 0x2E, 0x3B, 0x36, 0x2E, 0x39, 0x3B, 0x39, 0x32, 0x3F]) }
}

/// Centralized catalog of exploit signatures, dylibs, symbols, strings, and behavioral rules.
public enum SignatureCatalog {
    
    /// Rule definition for a static signature.
    public struct Rule: Sendable, Equatable {
        public let id: String
        public let pattern: String
        public let category: String
        public let description: String
        public let descriptionZh: String?
        public let severity: RiskTier
        public let defaultLocation: String
        
        public init(
            id: String,
            pattern: String,
            category: String,
            description: String,
            descriptionZh: String? = nil,
            severity: RiskTier,
            defaultLocation: String
        ) {
            self.id = id
            self.pattern = pattern
            self.category = category
            self.description = description
            self.descriptionZh = descriptionZh
            self.severity = severity
            self.defaultLocation = defaultLocation
        }
        
        public func toIndicator(at location: String? = nil) -> ThreatIndicator {
            ThreatIndicator(
                signature: pattern,
                description: WQLocale.pick(en: description, zh: descriptionZh ?? description),
                category: category,
                location: location ?? defaultLocation,
                severity: severity
            )
        }
    }
    
    // MARK: - 1. Dynamic Libraries
    public static let targetDylibName = "libsystem_containermanager.dylib"
    public static let dylibRules: [String: Rule] = [
        "libsystem_containermanager.dylib": Rule(
            id: "DYLIB_CONTAINERMANAGER",
            pattern: "libsystem_containermanager.dylib",
            category: "Dylib Reference",
            description: "Direct linkage to private libsystem_containermanager.dylib, used for containermanagerd IPC/token acquisition",
            descriptionZh: "直接链接私有容器管理器动态库 libsystem_containermanager.dylib，用于向 containermanagerd 发起跨沙盒查询与令牌获取",
            severity: .highRisk,
            defaultLocation: "LC_LOAD_DYLIB"
        )
    ]
    
    // MARK: - 2. Private containermanager APIs
    public static let privateContainerSymbols: [String: Rule] = [
        "container_query_create": Rule(
            id: "SYM_QUERY_CREATE",
            pattern: "container_query_create",
            category: "Private API Symbol",
            description: "Private containermanager API used to allocate container query objects",
            descriptionZh: "引用私有 containermanager 接口 container_query_create，用于构造跨容器查询对象",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "container_query_set_group_identifiers": Rule(
            id: "SYM_SET_GROUP_IDENTIFIERS",
            pattern: "container_query_set_group_identifiers",
            category: "Private API Symbol",
            description: "Private API setting target App Group identifier in container query",
            descriptionZh: "引用私有接口 container_query_set_group_identifiers 设置目标共享容器群组标识",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "container_query_operation_set_part": Rule(
            id: "SYM_SET_PART",
            pattern: "container_query_operation_set_part",
            category: "Private API Symbol",
            description: "Private API setting container part (e.g. part=3 for Library/Caches)",
            descriptionZh: "引用私有接口 container_query_operation_set_part 指定容器子路径（例如 part=3 指向 Library/Caches）",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "container_query_operation_set_flags": Rule(
            id: "SYM_SET_FLAGS",
            pattern: "container_query_operation_set_flags",
            category: "Private API Symbol",
            description: "Private API setting query operation flags (0x0000008000000000ULL / 0x0000000800000000ULL)",
            descriptionZh: "引用私有接口 container_query_operation_set_flags 配置底层容器查询标志位",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "container_copy_sandbox_token": Rule(
            id: "SYM_COPY_SANDBOX_TOKEN",
            pattern: "container_copy_sandbox_token",
            category: "Private API Symbol",
            description: "Private API retrieving issued Seatbelt sandbox token from containermanagerd result",
            descriptionZh: "引用私有接口 container_copy_sandbox_token 提取 containermanagerd 签发的跨沙盒访问令牌",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "sandbox_extension_consume": Rule(
            id: "SYM_SANDBOX_EXTENSION_CONSUME",
            pattern: "sandbox_extension_consume",
            category: "Private API Symbol",
            description: "Darwin Seatbelt API consuming sandbox extension token to acquire kernel path privileges",
            descriptionZh: "调用 Darwin Seatbelt 消费接口 sandbox_extension_consume 激活内核路径读写特权",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "container_query_get_single_result": Rule(
            id: "SYM_GET_SINGLE_RESULT",
            pattern: "container_query_get_single_result",
            category: "Private API Symbol",
            description: "Private API dispatching sync query to containermanagerd and returning container result",
            descriptionZh: "引用私有接口 container_query_get_single_result 向 containermanagerd 发起同步容器查询",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "container_query_iterate_results_sync": Rule(
            id: "SYM_ITERATE_RESULTS_SYNC",
            pattern: "container_query_iterate_results_sync",
            category: "Private API Symbol",
            description: "Private API synchronously iterating results from containermanagerd",
            descriptionZh: "引用私有接口 container_query_iterate_results_sync 同步遍历容器查询结果",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "container_query_set_class": Rule(
            id: "SYM_SET_CLASS",
            pattern: "container_query_set_class",
            category: "Private API Symbol",
            description: "Private API setting container class (e.g. class=7 for group data)",
            descriptionZh: "引用私有接口 container_query_set_class 指定目标容器类别（如 class=7）",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "container_query_free": Rule(
            id: "SYM_QUERY_FREE",
            pattern: "container_query_free",
            category: "Private API Symbol",
            description: "Private API freeing container query resources",
            descriptionZh: "引用私有接口 container_query_free 释放容器查询句柄",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "sandbox_extension_release": Rule(
            id: "SYM_SANDBOX_EXTENSION_RELEASE",
            pattern: "sandbox_extension_release",
            category: "Private API Symbol",
            description: "Darwin Seatbelt API releasing sandbox extension handle",
            descriptionZh: "调用 Darwin Seatbelt 接口 sandbox_extension_release 释放沙盒扩展令牌句柄",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        )
    ]
    
    // MARK: - 3. Direct XPC Service
    public static let directXPCRules: [String: Rule] = [
        "com.apple.containermanagerd": Rule(
            id: "XPC_CONTAINERMANAGERD",
            pattern: "com.apple.containermanagerd",
            category: "Direct XPC Bypass",
            description: "Direct XPC Mach service reference to containermanagerd, bypassing libsystem C wrappers",
            descriptionZh: "直接包含 com.apple.containermanagerd XPC Mach 服务名，可绕过 libsystem C 包装层与容器守护进程通信",
            severity: .highRisk,
            defaultLocation: "__TEXT,__cstring"
        ),
        "com.apple.containermanagerd.system": Rule(
            id: "XPC_CONTAINERMANAGERD_SYSTEM",
            pattern: "com.apple.containermanagerd.system",
            category: "Direct XPC Bypass",
            description: "Direct XPC Mach service reference to system containermanagerd daemon",
            descriptionZh: "直接包含系统级容器管理守护进程 XPC 服务名 com.apple.containermanagerd.system",
            severity: .highRisk,
            defaultLocation: "__TEXT,__cstring"
        )
    ]
    
    // MARK: - 4. Path Enumeration Primitives
    public static let pathEnumerationSymbols: [String: Rule] = [
        "fsgetpath": Rule(
            id: "SYM_FSGETPATH",
            pattern: "fsgetpath",
            category: "Sandbox Enumeration",
            description: "APFS file system inode brute-force primitive, used to enumerate container UUID paths without directory listing permissions",
            descriptionZh: "底层 APFS 文件系统 inode 遍历系统调用 fsgetpath，常用于无列目录权限下还原全机容器 UUID 路径",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "container_object_get_path": Rule(
            id: "SYM_CONTAINER_OBJECT_GET_PATH",
            pattern: "container_object_get_path",
            category: "Sandbox Enumeration",
            description: "Private container path resolution primitive",
            descriptionZh: "引用私有容器路径解析接口 container_object_get_path",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        )
    ]
    
    public static let containerPathSubstrings: [String] = [
        "/Containers/Data/",
        "/Containers/Shared/",
        "/var/mobile/Containers/",
        "/private/var/mobile/Containers/"
    ]
    
    // MARK: - 5. Container Metadata Artifacts
    public static let metadataFileRules: [String: Rule] = [
        ".com.apple.mobile_container_manager.metadata.plist": Rule(
            id: "META_MCM_PLIST",
            pattern: ".com.apple.mobile_container_manager.metadata.plist",
            category: "Container Metadata",
            description: "Direct reference to containermanagerd container metadata plist",
            descriptionZh: "直接引用 containermanagerd 容器元数据索引文件 (.com.apple.mobile_container_manager.metadata.plist)",
            severity: .caution,
            defaultLocation: "__TEXT,__cstring"
        ),
        ".csstore": Rule(
            id: "META_CSSTORE",
            pattern: ".csstore",
            category: "Container Metadata",
            description: "LaunchServices CSStore database file pattern for application bundle enumeration",
            descriptionZh: "引用 LaunchServices CSStore 二进制缓存匹配串，可能用于枚举已安装应用路径",
            severity: .caution,
            defaultLocation: "__TEXT,__cstring"
        ),
        "com.apple.LaunchServices-": Rule(
            id: "META_LAUNCHSERVICES_PREFIX",
            pattern: "com.apple.LaunchServices-",
            category: "Container Metadata",
            description: "LaunchServices database shared prefix reference",
            descriptionZh: "引用 LaunchServices 数据库文件前缀 com.apple.LaunchServices-",
            severity: .caution,
            defaultLocation: "__TEXT,__cstring"
        )
    ]
    
    // MARK: - 6. Dynamic Loading Primitives
    public static let dynamicLoadingSymbols: Set<String> = ["dlopen", "dlsym"]
    
    // MARK: - 7. Symlink Primitives
    public static let symlinkPrimitives: Set<String> = [
        "symlink",
        "symlinkat",
        "createSymbolicLinkAtPath:withDestinationPath:",
        "createSymbolicLinkAtPath:withDestinationPath:error:",
        "createSymbolicLinkAtURL:withDestinationURL:error:",
        "createSymbolicLinkAtPath"
    ]
    
    // MARK: - 8. Obfuscated Behavioral Tuple Rule
    public static let behavioralTupleRule = Rule(
        id: "TUPLE_OBFUSCATED_EXPLOIT",
        pattern: "cryptid0+AppGroups+dlopen/dlsym+Symlink/SandboxAPI",
        category: "Heuristic / Behavioral Tuple",
        description: "Obfuscation-resistant behavioral tuple: unencrypted binary possessing App Group, dynamic loading (dlopen/dlsym), and symlink traversal/sandbox token APIs.",
        descriptionZh: "抗混淆行为特征元组：未加密二进制同时具备 App Group、动态符号加载 (dlopen/dlsym) 与符号链接/沙盒令牌接口组合",
        severity: .highRisk,
        defaultLocation: "Behavioral Heuristic"
    )
    
    public static let dynamicLoadingCautionRule = Rule(
        id: "HEURISTIC_DYNAMIC_LOADING",
        pattern: "dlopen+dlsym",
        category: "Heuristic",
        description: "Application possesses App Group entitlement and imports dynamic symbol resolution primitives (dlopen/dlsym).",
        descriptionZh: "应用声明了 App Group 共享容器权限并导入动态符号解析原语 (dlopen/dlsym)",
        severity: .caution,
        defaultLocation: "LC_SYMTAB"
    )

    // MARK: - 9. Direct Syscall Evasion
    public static let directSyscallRule = Rule(
        id: "INSN_ARM64_SVC_0X80",
        pattern: "arm64:svc_0x80",
        category: "Direct Syscall Evasion",
        description: "Inline ARM64 svc #0x80 kernel syscall instruction (0xD4001001) detected in executable code, bypassing libsystem_kernel.dylib import tables and static symbol auditing.",
        descriptionZh: "在可执行代码段检测到内联 ARM64 svc #0x80 系统调用指令 (0xD4001001)，可绕过 libsystem_kernel.dylib 导入表与静态符号审计直接向内核发起调用。",
        severity: .highRisk,
        defaultLocation: "__TEXT,__text"
    )

    // MARK: - 10. App-Group-Independent 2026 Exploit Rulesets
    // NOTE: Never add AudioToolbox.framework, AVFAudio.framework, AudioOutputUnitStart, or AURemoteIO
    // to prevent false positives on legitimate sideloaded emulators/games (Delta, RetroArch, PPSSPP).
    public static let standaloneExploitDylibRules: [String: Rule] = [
        "MediaExperience.framework": Rule(
            id: "DYLIB_AUDIOMXD_MEDIAEXPERIENCE",
            pattern: "CVE-2026-65339:MediaExperience.framework",
            category: "AudioMxd Mic TCC Bypass (CVE-2026-65339)",
            description: "Direct linkage to private MediaExperience.framework, used to communicate with audiomxd and bypass microphone TCC privacy controls (CVE-2026-65339).",
            descriptionZh: "直接链接私有框架 MediaExperience.framework，可用于与 audiomxd 通信并绕过麦克风 TCC 隐私授权保护 (CVE-2026-65339)。",
            severity: .highRisk,
            defaultLocation: "LC_LOAD_DYLIB"
        ),
        "BookLibraryPrivate.framework": Rule(
            id: "DYLIB_BOOKRESTORE_PRIVATE",
            pattern: "BookRestore:BookLibraryPrivate.framework",
            category: "BookRestore / bl_sbx Escape",
            description: "Direct linkage to private BookLibraryPrivate.framework, associated with BookRestore / bl_sbx bookassetd sandbox escape chains.",
            descriptionZh: "直接链接私有框架 BookLibraryPrivate.framework，常见于 BookRestore / bl_sbx 图书守护进程沙盒逃逸利用链。",
            severity: .highRisk,
            defaultLocation: "LC_LOAD_DYLIB"
        )
    ]

    public static let standaloneExploitSymbolRules: [String: Rule] = [
        "CMSessionSetProperty": Rule(
            id: "SYM_CMSESSION_SET_PROPERTY",
            pattern: "CVE-2026-65339:CMSessionSetProperty",
            category: "AudioMxd Mic TCC Bypass (CVE-2026-65339)",
            description: "Imports private MediaExperience API CMSessionSetProperty, associated with CVE-2026-65339 audiomxd microphone TCC bypass.",
            descriptionZh: "导入私有 MediaExperience 接口 CMSessionSetProperty，涉及 CVE-2026-65339 audiomxd 麦克风隐私绕过攻击向量。",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        ),
        "AudioSessionSetCMProperty": Rule(
            id: "SYM_AUDIOSESSION_SET_CM_PROPERTY",
            pattern: "CVE-2026-65339:AudioSessionSetCMProperty",
            category: "AudioMxd Mic TCC Bypass (CVE-2026-65339)",
            description: "Imports private MediaExperience API AudioSessionSetCMProperty, associated with CVE-2026-65339 audiomxd microphone TCC bypass.",
            descriptionZh: "导入私有 MediaExperience 接口 AudioSessionSetCMProperty，涉及 CVE-2026-65339 audiomxd 麦克风隐私绕过攻击向量。",
            severity: .highRisk,
            defaultLocation: "LC_SYMTAB"
        )
    ]

    public static let standaloneExploitStringRules: [String: Rule] = [
        IOCTokenArmor.tAudioDaemon: Rule(
            id: "XPC_AUDIOMXD_AUDIO",
            pattern: "CVE-2026-65339:\(IOCTokenArmor.tAudioDaemon)",
            category: "AudioMxd Mic TCC Bypass (CVE-2026-65339)",
            description: "Direct XPC service reference to \(IOCTokenArmor.tAudioDaemon), enabling CVE-2026-65339 microphone TCC privacy bypass.",
            descriptionZh: "直接引用 XPC 服务名 \(IOCTokenArmor.tAudioDaemon)，可用于触发 CVE-2026-65339 麦克风 TCC 隐私绕过。",
            severity: .highRisk,
            defaultLocation: "__TEXT,__cstring"
        ),
        IOCTokenArmor.tCoreMediaDaemon: Rule(
            id: "XPC_AUDIOMXD_COREMEDIA",
            pattern: "CVE-2026-65339:\(IOCTokenArmor.tCoreMediaDaemon)",
            category: "AudioMxd Mic TCC Bypass (CVE-2026-65339)",
            description: "Direct XPC service reference to \(IOCTokenArmor.tCoreMediaDaemon), enabling CVE-2026-65339 microphone TCC privacy bypass.",
            descriptionZh: "直接引用 XPC 服务名 \(IOCTokenArmor.tCoreMediaDaemon)，可用于触发 CVE-2026-65339 麦克风 TCC 隐私绕过。",
            severity: .highRisk,
            defaultLocation: "__TEXT,__cstring"
        ),
        IOCTokenArmor.tBookDaemon: Rule(
            id: "XPC_BOOKASSETD",
            pattern: "BookRestore:\(IOCTokenArmor.tBookDaemon)",
            category: "BookRestore / bl_sbx Escape",
            description: "Direct XPC service reference to \(IOCTokenArmor.tBookDaemon), characteristic of BookRestore / bl_sbx arbitrary system file overwrite exploits.",
            descriptionZh: "直接引用 XPC 服务名 \(IOCTokenArmor.tBookDaemon)，为 BookRestore / bl_sbx 任意系统文件覆盖漏洞典型特征。",
            severity: .highRisk,
            defaultLocation: "__TEXT,__cstring"
        ),
        IOCTokenArmor.tStoreDaemon: Rule(
            id: "XPC_ITUNESSTORED",
            pattern: "BookRestore:\(IOCTokenArmor.tStoreDaemon)",
            category: "BookRestore / bl_sbx Escape",
            description: "Direct XPC service reference to \(IOCTokenArmor.tStoreDaemon), associated with BookRestore / downloads.28 SQLite restore sandbox escapes.",
            descriptionZh: "直接引用 XPC 服务名 \(IOCTokenArmor.tStoreDaemon)，与 BookRestore / downloads.28 数据库恢复沙盒逃逸链关联。",
            severity: .highRisk,
            defaultLocation: "__TEXT,__cstring"
        ),
        IOCTokenArmor.tBookSQLite: Rule(
            id: "STR_BLDATABASEMANAGER_SQLITE",
            pattern: "BookRestore:\(IOCTokenArmor.tBookSQLite)",
            category: "BookRestore / bl_sbx Escape",
            description: "References \(IOCTokenArmor.tBookSQLite) restore database target used by BookRestore / bl_sbx to hijack bookassetd file writes.",
            descriptionZh: "引用 \(IOCTokenArmor.tBookSQLite) 数据库目标，常用于 BookRestore / bl_sbx 劫持 bookassetd 写入系统受保护路径。",
            severity: .highRisk,
            defaultLocation: "__TEXT,__cstring"
        ),
        IOCTokenArmor.tDownloadsSQLite: Rule(
            id: "STR_DOWNLOADS28_SQLITEDB",
            pattern: "BookRestore:\(IOCTokenArmor.tDownloadsSQLite)",
            category: "BookRestore / bl_sbx Escape",
            description: "References \(IOCTokenArmor.tDownloadsSQLite) download database target used by BookRestore / bl_sbx to stage arbitrary system writes.",
            descriptionZh: "引用 \(IOCTokenArmor.tDownloadsSQLite) 下载数据库路径，常用于 BookRestore / bl_sbx 诱导系统守护进程实施越权写入。",
            severity: .highRisk,
            defaultLocation: "__TEXT,__cstring"
        ),
        IOCTokenArmor.tGestaltPlist: Rule(
            id: "STR_MOBILEGESTALT_PLIST",
            pattern: "MobileGestaltTamper:\(IOCTokenArmor.tGestaltPlist)",
            category: "MobileGestalt System Tampering",
            description: "References protected system file \(IOCTokenArmor.tGestaltPlist), indicating device capability cache spoofing or system tampering.",
            descriptionZh: "引用系统受保护配置文件 \(IOCTokenArmor.tGestaltPlist)，疑似用于篡改设备硬件能力缓存与系统配置。",
            severity: .highRisk,
            defaultLocation: "__TEXT,__cstring"
        ),
        IOCTokenArmor.tGestaltGroup: Rule(
            id: "STR_MOBILEGESTALT_CACHE",
            pattern: "MobileGestaltTamper:mobilegestaltcache",
            category: "MobileGestalt System Tampering",
            description: "References Apple system group container \(IOCTokenArmor.tGestaltGroup), indicating MobileGestalt cache tampering attempts.",
            descriptionZh: "引用系统共享容器标识 \(IOCTokenArmor.tGestaltGroup)，表明存在篡改 MobileGestalt 缓存风险。",
            severity: .highRisk,
            defaultLocation: "__TEXT,__cstring"
        )
    ]

    public static let standaloneExploitCandidateStrings: [String] = Array(standaloneExploitStringRules.keys).sorted()
}
