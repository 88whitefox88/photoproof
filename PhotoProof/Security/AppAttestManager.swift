import DeviceCheck
import Foundation
import Security

/// Apple App Attest: Apple подтверждает, что ключ создан в Secure Enclave настоящего iPhone
/// и принадлежит оригинальному приложению (не модифицированному, не эмулятору).
/// Каждый паспорт снимка дополнительно подписывается этим аттестованным ключом.
actor AppAttestManager {
    enum Status: Equatable {
        case unsupported
        case notReady
        case ready(keyId: String)
        case failed(String)
    }

    static let shared = AppAttestManager()

    static var attestationURL: URL { AppPaths.support.appendingPathComponent("appattest_attestation.cbor") }
    static var challengeURL: URL { AppPaths.support.appendingPathComponent("appattest_challenge.txt") }

    private let keyIdDefaultsKey = "appattest.keyId.v1"
    private var lastError: String?
    private var preparing = false

    private var storedKeyId: String? { UserDefaults.standard.string(forKey: keyIdDefaultsKey) }

    func status() -> Status {
        guard DCAppAttestService.shared.isSupported else { return .unsupported }
        if let keyId = storedKeyId, FileManager.default.fileExists(atPath: Self.attestationURL.path) {
            return .ready(keyId: keyId)
        }
        if let lastError { return .failed(lastError) }
        return .notReady
    }

    /// Создает и аттестует ключ один раз на установку. Нужен интернет (запрос к серверам Apple).
    func prepare() async {
        guard DCAppAttestService.shared.isSupported, !preparing else { return }
        if case .ready = status() { return }
        preparing = true
        defer { preparing = false }
        do {
            let service = DCAppAttestService.shared
            let keyId = try await service.generateKey()
            var random = [UInt8](repeating: 0, count: 16)
            _ = SecRandomCopyBytes(kSecRandomDefault, random.count, &random)
            let challenge = """
            PhotoProof App Attest
            keyId: \(keyId)
            created: \(Fmt.isoUTC(Date()))
            random: \(Data(random).hex)
            """
            let challengeData = Data(challenge.utf8)
            let attestation = try await service.attestKey(keyId, clientDataHash: Hashing.sha256(challengeData))
            try challengeData.write(to: Self.challengeURL, options: .atomic)
            try attestation.write(to: Self.attestationURL, options: .atomic)
            UserDefaults.standard.set(keyId, forKey: keyIdDefaultsKey)
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Утверждение (assertion) App Attest над произвольными данными — здесь над manifest.json.
    func assertion(for data: Data) async throws -> Data {
        guard case .ready(let keyId) = status() else { throw CocoaError(.featureUnsupported) }
        return try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: Hashing.sha256(data))
    }
}
