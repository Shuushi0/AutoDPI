import Foundation

/// The app's language, picked the way the command line picks it
/// (internal/i18n): the AUTODPI_LANG environment variable, the "language" key
/// of the service's config.json, then the first of the user's preferred
/// languages. Turkish when that is Turkish, English for every other.
enum L10n {
    static let turkish: Bool = {
        if let v = norm(ProcessInfo.processInfo.environment["AUTODPI_LANG"]) { return v == "tr" }
        var cfg = "/Library/Application Support/AutoDPI/config.json"
        if let home = ProcessInfo.processInfo.environment["AUTODPI_HOME"], !home.isEmpty {
            cfg = home + "/config.json"
        }
        if let d = FileManager.default.contents(atPath: cfg),
           let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
           let v = norm(o["language"] as? String) {
            return v == "tr"
        }
        return norm(Locale.preferredLanguages.first) == "tr"
    }()

    /// Dates and numbers follow the language.
    static let locale = Locale(identifier: turkish ? "tr_TR" : "en_GB")

    /// "tr", "en", or nil for tr_TR.UTF-8, en-US and the like.
    static func norm(_ tag: String?) -> String? {
        guard let t = tag?.lowercased().trimmingCharacters(in: .whitespaces), !t.isEmpty else { return nil }
        for l in ["tr", "en"] where t == l || t.hasPrefix(l + "_") || t.hasPrefix(l + "-") || t.hasPrefix(l + ".") {
            return l
        }
        return nil
    }
}

/// loc returns the Turkish text when the app is in Turkish, the English one otherwise.
func loc(_ tr: String, _ en: String) -> String { L10n.turkish ? tr : en }
