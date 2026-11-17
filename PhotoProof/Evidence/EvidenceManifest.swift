import Foundation

/// «Паспорт» снимка (manifest.json). Подписывается ключом устройства, аттестованным ключом App Attest
/// и заверяется метками доверенного времени. Содержит SHA-256 всех файлов пакета.
struct EvidenceManifest: Codable {
    var schema: String = "photoproof.evidence-manifest"
    var schemaVersion: Int = 1
    var evidenceId: String
    var application: Application
    var hardware: Hardware
    var capture: Capture
    var place: Place?
    var files: [FileEntry]
    var timestamps: [TimestampEntry]
    var timestampErrors: [String]?
    var clockCheck: ClockCheck?
    var signing: Signing
    var journal: JournalLink
    var stamp: [String]

    struct Application: Codable {
        var name: String
        var bundleId: String
        var appId: String?
        var version: String
        var build: String
    }

    struct Hardware: Codable {
        var model: String
        var systemName: String
        var systemVersion: String
        var identifierForVendor: String?
        var locale: String
    }

    struct Capture: Codable {
        var deviceTimeLocal: String
        var deviceTimeUTC: String
        var unixTime: Double
        var timeZone: String
        var utcOffsetSeconds: Int
        var monotonicSeconds: Double
        var camera: String
        var flash: String
        var imageWidth: Int
        var imageHeight: Int
        /// Всегда "live-camera": приложение не умеет импортировать готовые изображения.
        var source: String
    }

    struct Place: Codable {
        var latitude: Double
        var longitude: Double
        var horizontalAccuracyMeters: Double
        var altitudeMeters: Double?
        var verticalAccuracyMeters: Double?
        var speedMps: Double?
        var courseDegrees: Double?
        var fixTimeUTC: String
        var fixAgeSeconds: Double
        var isSimulatedBySoftware: Bool?
        var isProducedByAccessory: Bool?
        var preciseLocationAuthorized: Bool
        var address: String?
    }

    struct FileEntry: Codable {
        var role: String
        var name: String
        var mediaType: String
        var size: Int
        var sha256: String
    }

    struct TimestampEntry: Codable {
        var subject: String
        var subjectSha256: String
        var tsaName: String
        var tsaURL: String
        var file: String
        var genTimeUTC: String
        var serialNumber: String
        var policy: String
        var requestMonotonicSeconds: Double
        var responseMonotonicSeconds: Double
    }

    /// Сверка часов телефона с эталонным временем службы штампов времени.
    struct ClockCheck: Codable {
        var reference: String
        var referenceGenTimeUTC: String
        var secondsFromCaptureToRequest: Double
        var secondsFromCaptureToResponse: Double
        /// Интервал, в котором лежит расхождение «часы телефона − эталон» в момент съемки.
        var deviceOffsetMinSeconds: Double
        var deviceOffsetMaxSeconds: Double
        var toleranceSeconds: Double
        var deviceClockWithinTolerance: Bool
        /// Момент съемки по эталонной шкале времени.
        var estimatedCaptureTimeUTC: String
    }

    struct Signing: Codable {
        var algorithm: String
        var keyStorage: String
        var publicKeyFile: String
        var publicKeySpkiSha256: String
        var signatureFile: String
        var appAttest: AppAttest?
    }

    struct AppAttest: Codable {
        var keyId: String
        var attestationFile: String
        var challengeFile: String
        var assertionFile: String
    }

    /// Звено журнала устройства: удаление или подмена снимков задним числом обнаруживается.
    struct JournalLink: Codable {
        var sequence: Int
        var previousEntrySha256: String
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    static func decode(_ data: Data) throws -> EvidenceManifest {
        try JSONDecoder().decode(EvidenceManifest.self, from: data)
    }
}

extension EvidenceManifest.Application {
    static var current: Self {
        .init(name: AppInfoProvider.displayName,
              bundleId: AppInfoProvider.bundleId,
              appId: AppInfoProvider.appId,
              version: AppInfoProvider.version,
              build: AppInfoProvider.build)
    }
}

extension EvidenceManifest.Place {
    init(_ s: LocationSnapshot, captureDate: Date, address: String?) {
        self.init(latitude: s.latitude,
                  longitude: s.longitude,
                  horizontalAccuracyMeters: s.horizontalAccuracy,
                  altitudeMeters: s.altitude,
                  verticalAccuracyMeters: s.verticalAccuracy,
                  speedMps: s.speed,
                  courseDegrees: s.course,
                  fixTimeUTC: Fmt.isoUTC(s.timestamp),
                  fixAgeSeconds: captureDate.timeIntervalSince(s.timestamp),
                  isSimulatedBySoftware: s.isSimulated,
                  isProducedByAccessory: s.isFromAccessory,
                  preciseLocationAuthorized: s.precise,
                  address: address)
    }
}

extension EvidenceManifest.TimestampEntry {
    init(token: TimestampToken, subject: String, subjectSha256: String, file: String) {
        self.init(subject: subject,
                  subjectSha256: subjectSha256,
                  tsaName: token.server.name,
                  tsaURL: token.server.url.absoluteString,
                  file: file,
                  genTimeUTC: Fmt.isoUTC(token.info.genTime),
                  serialNumber: token.info.serialNumberHex,
                  policy: token.info.policy,
                  requestMonotonicSeconds: token.requestMonotonic,
                  responseMonotonicSeconds: token.responseMonotonic)
    }
}

extension EvidenceManifest.ClockCheck {
    static let tolerance: Double = 10

    /// Метка времени выдана между отправкой запроса и получением ответа. Зная по монотонным часам,
    /// сколько секунд прошло от съемки до запроса и до ответа, получаем момент съемки по эталону.
    /// Время в метке может быть усечено до секунды — это учтено (+1 с).
    static func evaluate(captureDate: Date, captureMonotonic: Double, tokens: [TimestampToken]) -> Self? {
        guard let best = tokens.min(by: {
            ($0.responseMonotonic - $0.requestMonotonic) < ($1.responseMonotonic - $1.requestMonotonic)
        }) else { return nil }
        let reference = best.info.genTime.timeIntervalSince1970
        let device = captureDate.timeIntervalSince1970
        let toRequest = best.requestMonotonic - captureMonotonic
        let toResponse = best.responseMonotonic - captureMonotonic
        let offsetMin = device - reference - 1 + toRequest
        let offsetMax = device - reference + toResponse
        let within = offsetMin <= tolerance && offsetMax >= -tolerance
        let estimated = reference + 0.5 - (toRequest + toResponse) / 2
        return .init(reference: best.server.name,
                     referenceGenTimeUTC: Fmt.isoUTC(best.info.genTime),
                     secondsFromCaptureToRequest: toRequest,
                     secondsFromCaptureToResponse: toResponse,
                     deviceOffsetMinSeconds: offsetMin,
                     deviceOffsetMaxSeconds: offsetMax,
                     toleranceSeconds: tolerance,
                     deviceClockWithinTolerance: within,
                     estimatedCaptureTimeUTC: Fmt.isoUTC(Date(timeIntervalSince1970: estimated)))
    }

    var estimatedCaptureDate: Date? { Fmt.parseISO(estimatedCaptureTimeUTC) }
    var typicalOffset: Double { (deviceOffsetMinSeconds + deviceOffsetMaxSeconds) / 2 }
}
