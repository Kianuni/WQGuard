//
//  SignatureCatalog.swift
//  WQGuardCore
//
//  Centralized catalog of target signatures, private symbols, dylibs,
//  path leak patterns, and behavioral heuristics.
//

import Foundation

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
}
