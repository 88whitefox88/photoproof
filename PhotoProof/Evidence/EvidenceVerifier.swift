import CryptoKit
import Foundation

struct VerificationCheck: Identifiable {
    enum Outcome { case passed, failed, info }
    let id = UUID()
    let title: String
    let outcome: Outcome
    let detail: String
}

/// Проверка пакета на телефоне: контрольные суммы, подпись паспорта, соответствие меток времени.
/// Подпись самих служб времени и цепочку App Attest проверяет эксперт (OpenSSL / verify.py).
enum EvidenceVerifier {
    static func verify(folder: URL) -> [VerificationCheck] {
        var checks: [VerificationCheck] = []
        guard let manifestData = try? Data(contentsOf: folder.appendingPathComponent(EvidenceFiles.manifest)),
              let manifest = try? EvidenceManifest.decode(manifestData) else {
            return [VerificationCheck(title: "Паспорт снимка", outcome: .failed, detail: "manifest.json отсутствует или поврежден")]
        }
        let timeZone = TimeZone(identifier: manifest.capture.timeZone) ?? .current

        for file in manifest.files {
            guard let data = try? Data(contentsOf: folder.appendingPathComponent(file.name)) else {
                checks.append(.init(title: file.name, outcome: .failed, detail: "файл отсутствует"))
                continue
            }
            let matches = Hashing.sha256Hex(data) == file.sha256
            checks.append(.init(title: file.name, outcome: matches ? .passed : .failed,
                                detail: matches ? "SHA-256 совпадает с паспортом" : "SHA-256 НЕ совпадает — файл изменен"))
        }

        do {
            let pem = try String(contentsOf: folder.appendingPathComponent(manifest.signing.publicKeyFile), encoding: .utf8)
            let key = try P256.Signing.PublicKey(pemRepresentation: pem)
            let signatureData = try Data(contentsOf: folder.appendingPathComponent(manifest.signing.signatureFile))
            let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
            let valid = key.isValidSignature(signature, for: manifestData)
            checks.append(.init(title: "Подпись паспорта", outcome: valid ? .passed : .failed,
                                detail: valid ? "ECDSA P-256: подпись верна" : "подпись не соответствует manifest.json"))
            let fingerprint = Hashing.sha256Hex(key.derRepresentation)
            if fingerprint != manifest.signing.publicKeySpkiSha256 {
                checks.append(.init(title: "Ключ подписи", outcome: .failed, detail: "отпечаток ключа не совпадает с паспортом"))
            } else if let current = try? DeviceSigner.shared.fingerprint() {
                checks.append(.init(title: "Ключ подписи", outcome: .info,
                                    detail: current == fingerprint
                                        ? "снимок подписан ключом этого iPhone"
                                        : "снимок подписан ключом другого устройства или прежней установки"))
            }
        } catch {
            checks.append(.init(title: "Подпись паспорта", outcome: .failed, detail: "не удалось проверить: \(error.localizedDescription)"))
        }

        let originalDigest = manifest.files.first { $0.role == "original" }
            .flatMap { Data(hex: $0.sha256) }
            .map { [UInt8]($0) }
        for entry in manifest.timestamps {
            checks.append(checkToken(at: folder.appendingPathComponent(entry.file), expected: originalDigest,
                                     title: "Метка \(entry.tsaName) на снимок", timeZone: timeZone))
        }
        let manifestDigest = [UInt8](Hashing.sha256(manifestData))
        let manifestTokens = EvidenceLoader.tokens(in: folder, subject: "manifest")
        for token in manifestTokens {
            checks.append(checkToken(at: folder.appendingPathComponent(token.file), expected: manifestDigest,
                                     title: "Метка \(token.tsaName) на паспорт", timeZone: timeZone))
        }
        if manifest.timestamps.isEmpty && manifestTokens.isEmpty {
            checks.append(.init(title: "Метки времени", outcome: .info,
                                detail: "пока нет — будут запрошены автоматически при появлении сети"))
        }

        if manifest.signing.appAttest != nil {
            let exists = FileManager.default.fileExists(atPath: folder.appendingPathComponent(EvidenceFiles.assertion).path)
            checks.append(.init(title: "Apple App Attest", outcome: exists ? .info : .failed,
                                detail: exists ? "аттестация и подпись присутствуют (цепочку Apple проверяет verify.py)"
                                               : "файл подписи App Attest отсутствует"))
        }
        return checks
    }

    private static func checkToken(at url: URL, expected: [UInt8]?, title: String, timeZone: TimeZone) -> VerificationCheck {
        guard let data = try? Data(contentsOf: url) else {
            return .init(title: title, outcome: .failed, detail: "файл метки отсутствует")
        }
        do {
            let info = try TimestampClient.parseResponse(data, expectedDigest: expected)
            return .init(title: title, outcome: .passed,
                         detail: "\(Fmt.dateTime(info.genTime, timeZone: timeZone)) — выдана именно на этот файл")
        } catch {
            return .init(title: title, outcome: .failed, detail: error.localizedDescription)
        }
    }
}
