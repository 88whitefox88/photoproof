import CoreLocation
import CryptoKit
import Foundation

/// Форматирование дат, координат и чисел. Все форматы фиксированные (не зависят от настроек телефона).
enum Fmt {
    private static let posix = Locale(identifier: "en_US_POSIX")

    /// 2026-11-17T11:32:05.123Z
    static func isoUTC(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        f.timeZone = TimeZone(identifier: "UTC")
        return f.string(from: date)
    }

    /// 2026-11-17T14:32:05.123+03:00
    static func isoLocal(_ date: Date, timeZone: TimeZone) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        f.timeZone = timeZone
        return f.string(from: date)
    }

    static func parseISO(_ string: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = f.date(from: string) { return date }
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: string)
    }

    static func pattern(_ format: String, _ date: Date, _ timeZone: TimeZone) -> String {
        let f = DateFormatter()
        f.locale = posix
        f.timeZone = timeZone
        f.dateFormat = format
        return f.string(from: date)
    }

    /// 17.11.2026 14:32:05
    static func dateTime(_ date: Date, timeZone: TimeZone = .current) -> String {
        pattern("dd.MM.yyyy HH:mm:ss", date, timeZone)
    }

    /// UTC+03:00
    static func utcOffset(_ timeZone: TimeZone, at date: Date) -> String {
        "UTC" + offsetHHMM(timeZone.secondsFromGMT(for: date))
    }

    /// +03:00
    static func offsetHHMM(_ seconds: Int) -> String {
        let sign = seconds < 0 ? "-" : "+"
        let value = abs(seconds)
        return sign + String(format: "%02d:%02d", value / 3600, (value % 3600) / 60)
    }

    /// 55.755800° с.ш., 37.617300° в.д.
    static func coordinate(latitude: Double, longitude: Double) -> String {
        let lat = String(format: "%.6f°", abs(latitude)) + (latitude >= 0 ? " с.ш." : " ю.ш.")
        let lon = String(format: "%.6f°", abs(longitude)) + (longitude >= 0 ? " в.д." : " з.д.")
        return lat + ", " + lon
    }

    static func meters(_ value: Double) -> String {
        value < 10 ? String(format: "%.1f м", value) : String(format: "%.0f м", value)
    }

    static func bytes(_ count: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(count), countStyle: .file)
    }

    /// +1.5 с / −3 мин 12 с
    static func signedSeconds(_ value: Double) -> String {
        let sign = value < 0 ? "−" : "+"
        let a = abs(value)
        if a < 120 { return sign + String(format: "%.1f с", a) }
        let total = Int(a.rounded())
        if total < 7200 { return sign + "\(total / 60) мин \(total % 60) с" }
        return sign + "\(total / 3600) ч \((total % 3600) / 60) мин"
    }

    /// 3F9A 12C4 88B0 …
    static func groupedHex(_ hex: String) -> String {
        var groups: [String] = []
        var current = ""
        for ch in hex.uppercased() {
            current.append(ch)
            if current.count == 4 { groups.append(current); current = "" }
        }
        if !current.isEmpty { groups.append(current) }
        return groups.joined(separator: " ")
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    init?(hex: String) {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let byte = UInt8(String(decoding: chars[i..<(i + 2)], as: UTF8.self), radix: 16) else { return nil }
            bytes.append(byte)
            i += 2
        }
        self.init(bytes)
    }
}

enum Hashing {
    static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
    static func sha256Hex(_ data: Data) -> String { sha256(data).hex }
}

/// Монотонные часы: идут с момента загрузки устройства (включая сон) и не меняются,
/// если пользователь переводит часы. Позволяют доказать интервал между съемкой и меткой времени.
enum MonotonicClock {
    static func now() -> Double {
        Double(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1_000_000_000
    }
}

/// Номер доказательства — первые 12 hex-символов SHA-256 оригинала: 3F9A-12C4-88B0.
/// Любой может проверить, что штамп относится именно к этому файлу.
enum EvidenceID {
    static func make(fromSHA256Hex hex: String) -> String {
        let s = Array(hex.uppercased().prefix(12))
        return String(s[0..<4]) + "-" + String(s[4..<8]) + "-" + String(s[8..<12])
    }
}

/// Обертка для передачи не-Sendable значений из фоновой задачи.
struct UncheckedBox<T>: @unchecked Sendable {
    let value: T
}
