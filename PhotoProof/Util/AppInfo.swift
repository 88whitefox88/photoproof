import Foundation

enum AppInfoProvider {
    static let displayName = "ФотоДоказ"

    static var bundleId: String { Bundle.main.bundleIdentifier ?? "unknown" }

    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
    }

    static var build: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
    }

    /// "ABCDE12345." — подставляется Xcode при подписи. Нужен эксперту для проверки App Attest.
    static var appIdentifierPrefix: String? {
        guard let prefix = Bundle.main.object(forInfoDictionaryKey: "AppIdentifierPrefix") as? String,
              !prefix.isEmpty, !prefix.contains("$") else { return nil }
        return prefix
    }

    /// TEAMID.bundle.id
    static var appId: String? {
        guard let prefix = appIdentifierPrefix else { return nil }
        return prefix.hasSuffix(".") ? prefix + bundleId : prefix + "." + bundleId
    }
}

enum DeviceInfo {
    /// Аппаратный идентификатор модели, например iPhone15,2.
    static var modelIdentifier: String {
        var info = utsname()
        uname(&info)
        return withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
    }
}
