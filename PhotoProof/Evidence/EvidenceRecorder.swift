import Foundation
import UIKit

extension EvidenceManifest.Hardware {
    @MainActor static var current: Self {
        let device = UIDevice.current
        return .init(model: DeviceInfo.modelIdentifier,
                     systemName: device.systemName,
                     systemVersion: device.systemVersion,
                     identifierForVendor: device.identifierForVendor?.uuidString,
                     locale: Locale.current.identifier)
    }
}

/// Конвейер фотофиксации:
///  1. снимок с камеры → SHA-256 оригинала;
///  2. метки доверенного времени (RFC 3161) на хеш оригинала + сверка часов телефона;
///  3. копия со штампом (дата, время, координаты, номер, QR);
///  4. паспорт manifest.json с хешами всех файлов → подпись ключом Secure Enclave → запись в журнал;
///  5. подпись паспорта аттестованным ключом App Attest;
///  6. метки доверенного времени на паспорт;
///  7. акт (PDF) и инструкция для эксперта (README.txt).
@MainActor
final class EvidenceRecorder: ObservableObject {
    enum Phase: Equatable {
        case idle, capturing, timestamping, sealing

        var title: String {
            switch self {
            case .idle: return ""
            case .capturing: return "Съемка…"
            case .timestamping: return "Получение метки доверенного времени…"
            case .sealing: return "Подпись и сохранение…"
            }
        }
    }

    @Published private(set) var phase: Phase = .idle
    @Published var errorMessage: String?

    private let camera: CameraController
    private let location: LocationProvider
    private let store: EvidenceStore

    init(camera: CameraController, location: LocationProvider, store: EvidenceStore) {
        self.camera = camera
        self.location = location
        self.store = store
    }

    func capture() async {
        guard phase == .idle else { return }
        phase = .capturing
        defer { phase = .idle }
        do {
            _ = try await record()
            store.reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func record() async throws -> String {
        // 1. Момент съемки
        let timeZone = TimeZone.current
        let captureDate = Date()
        let captureMonotonic = MonotonicClock.now()
        let precise = !location.isReducedAccuracy
        let place = location.freshLocation(maxAge: 120).map { LocationSnapshot($0, precise: precise) }
        let address = place == nil ? nil : location.address
        let flash = camera.flashOn && camera.hasFlash
        let orientation = CameraController.currentOrientation()

        let originalData = try await camera.capturePhoto(flash: flash, orientation: orientation,
                                                         gps: place.map { ImageMetadata.gps($0) })
        let originalHash = Hashing.sha256(originalData)
        let originalHex = originalHash.hex
        let evidenceId = EvidenceID.make(fromSHA256Hex: originalHex)

        // 2. Доверенное время на оригинал
        phase = .timestamping
        let originalStamps = await TimestampClient.timestampAll(digest: originalHash)
        let clock = EvidenceManifest.ClockCheck.evaluate(captureDate: captureDate,
                                                         captureMonotonic: captureMonotonic,
                                                         tokens: originalStamps.tokens)

        // 3. Копия со штампом (в фоне — это тяжелая операция)
        phase = .sealing
        let lines = StampComposer.lines(evidenceId: evidenceId, captureDate: captureDate, timeZone: timeZone,
                                        clock: clock, tokens: originalStamps.tokens, place: place,
                                        address: address, originalSHA256: originalHex)
        let qrPayload = "PHOTOPROOF;\(evidenceId);SHA256=\(originalHex)"
        let metadata = StampedImageMetadata(captureDate: captureDate, timeZone: timeZone, place: place,
                                            evidenceId: evidenceId, originalSHA256: originalHex)
        let rendered = try await Task.detached(priority: .userInitiated) {
            try StampRenderer.renderPackageImages(originalData: originalData, lines: lines,
                                                  qrPayload: qrPayload, metadata: metadata)
        }.value

        // 4. Файлы пакета
        let folder = AppPaths.evidenceRoot.appendingPathComponent(
            EvidenceFiles.folderName(evidenceId: evidenceId, captureDate: captureDate, timeZone: timeZone),
            isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)

        var fileEntries: [EvidenceManifest.FileEntry] = []
        func put(_ data: Data, _ name: String, role: String, mediaType: String) throws {
            let url = folder.appendingPathComponent(name)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            fileEntries.append(.init(role: role, name: name, mediaType: mediaType,
                                     size: data.count, sha256: Hashing.sha256Hex(data)))
        }

        try put(originalData, EvidenceFiles.original, role: "original", mediaType: "image/jpeg")
        try put(rendered.stampedJPEG, EvidenceFiles.stamped, role: "stamped-copy", mediaType: "image/jpeg")

        var timestampEntries: [EvidenceManifest.TimestampEntry] = []
        for token in originalStamps.tokens {
            let name = EvidenceFiles.tokenPath(subject: "original", server: token.server)
            try put(token.response, name, role: "rfc3161-token-original", mediaType: "application/timestamp-reply")
            timestampEntries.append(.init(token: token, subject: "original", subjectSha256: originalHex, file: name))
        }

        let signer = DeviceSigner.shared
        try put(Data(try signer.publicKeyPEM().utf8), EvidenceFiles.publicKey,
                role: "device-public-key", mediaType: "application/x-pem-file")

        var appAttest: EvidenceManifest.AppAttest?
        if case .ready(let keyId) = await AppAttestManager.shared.status(),
           let attestation = try? Data(contentsOf: AppAttestManager.attestationURL),
           let challenge = try? Data(contentsOf: AppAttestManager.challengeURL) {
            try put(attestation, EvidenceFiles.attestation, role: "appattest-attestation", mediaType: "application/cbor")
            try put(challenge, EvidenceFiles.attestationChallenge, role: "appattest-challenge", mediaType: "text/plain")
            appAttest = .init(keyId: keyId,
                              attestationFile: EvidenceFiles.attestation,
                              challengeFile: EvidenceFiles.attestationChallenge,
                              assertionFile: EvidenceFiles.assertion)
        }

        // 5. Паспорт → подпись → журнал (без await между чтением и записью журнала)
        let journalHead = Journal.head()
        let manifest = EvidenceManifest(
            evidenceId: evidenceId,
            application: .current,
            hardware: .current,
            capture: .init(deviceTimeLocal: Fmt.isoLocal(captureDate, timeZone: timeZone),
                           deviceTimeUTC: Fmt.isoUTC(captureDate),
                           unixTime: captureDate.timeIntervalSince1970,
                           timeZone: timeZone.identifier,
                           utcOffsetSeconds: timeZone.secondsFromGMT(for: captureDate),
                           monotonicSeconds: captureMonotonic,
                           camera: "back-wide",
                           flash: flash ? "on" : "off",
                           imageWidth: rendered.originalWidth,
                           imageHeight: rendered.originalHeight,
                           source: "live-camera"),
            place: place.map { EvidenceManifest.Place($0, captureDate: captureDate, address: address) },
            files: fileEntries,
            timestamps: timestampEntries,
            timestampErrors: originalStamps.failures.isEmpty ? nil : originalStamps.failures,
            clockCheck: clock,
            signing: .init(algorithm: "ECDSA P-256 / SHA-256 (DER)",
                           keyStorage: try signer.storage().rawValue,
                           publicKeyFile: EvidenceFiles.publicKey,
                           publicKeySpkiSha256: try signer.fingerprint(),
                           signatureFile: EvidenceFiles.signature,
                           appAttest: appAttest),
            journal: .init(sequence: journalHead.seq + 1, previousEntrySha256: journalHead.hash),
            stamp: lines.map(\.text))

        let manifestData = try manifest.encoded()
        try manifestData.write(to: folder.appendingPathComponent(EvidenceFiles.manifest),
                               options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        let signature = try signer.sign(manifestData)
        try signature.write(to: folder.appendingPathComponent(EvidenceFiles.signature), options: .atomic)
        try Journal.append(.captured, evidenceId: evidenceId, manifestSha256: Hashing.sha256Hex(manifestData))

        // 6. App Attest — подпись паспорта ключом, который Apple подтвердила как принадлежащий приложению
        if appAttest != nil, let assertion = try? await AppAttestManager.shared.assertion(for: manifestData) {
            try? assertion.write(to: folder.appendingPathComponent(EvidenceFiles.assertion), options: .atomic)
        }

        // 7. Доверенное время на паспорт (если нет сети — дозапросится позже)
        let manifestStamps = await TimestampClient.timestampAll(digest: Hashing.sha256(manifestData))
        for token in manifestStamps.tokens {
            let url = folder.appendingPathComponent(EvidenceFiles.tokenPath(subject: "manifest", server: token.server))
            try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? token.response.write(to: url, options: .atomic)
        }

        // 8. Миниатюра, акт, README
        if let thumbnail = rendered.thumbnailJPEG {
            try? thumbnail.write(to: AppPaths.thumbnail(for: evidenceId), options: .atomic)
        }
        if let item = EvidenceLoader.load(folder: folder) {
            await PackageDocuments.write(for: item)
        }
        return evidenceId
    }
}
