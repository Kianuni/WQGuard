//
//  WQLocale.swift
//  WQGuardCore
//
//  Runtime bilingual localization helper (English & Simplified Chinese)
//  across WQGuardCore engines, threat indicators, errors, and firmware advisories.
//

import Foundation

public enum WQLocale {
    private final class OverrideStorage: @unchecked Sendable {
        let lock = NSLock()
        var languageCode: String?
    }

    private static let storage = OverrideStorage()

    /// Optional runtime language override (e.g. `"en"` or `"zh-Hans"`) primarily for deterministic testing.
    /// Set to `nil` in production to follow `Locale.preferredLanguages`.
    public static var overrideLanguageCode: String? {
        get {
            storage.lock.lock()
            defer { storage.lock.unlock() }
            return storage.languageCode
        }
        set {
            storage.lock.lock()
            storage.languageCode = newValue
            storage.lock.unlock()
        }
    }

    /// Returns `true` when the active user language prefers English (any non-Chinese language),
    /// and `false` when Simplified/Traditional Chinese (`zh*`) is preferred.
    public static var isEnglish: Bool {
        let pref: String
        if let override = overrideLanguageCode?.trimmingCharacters(in: .whitespacesAndNewlines), !override.isEmpty {
            pref = override.lowercased()
        } else {
            pref = Locale.preferredLanguages.first?.lowercased() ?? "en"
        }
        return !pref.hasPrefix("zh")
    }

    @inline(__always)
    public static func pick(en: String, zh: String) -> String {
        return isEnglish ? en : zh
    }
}
