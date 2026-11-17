import CryptoKit
import Foundation
import Security

/// Хранение служебных данных в связке ключей (только на этом устройстве, без переноса в бэкапы).
enum KeychainStore {
    static let service = "photoproof.keys"

    static func read(_ account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    static func save(_ data: Data, account: String) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(base as CFDictionary)
        var attributes = base
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }
}

/// Ключ подписи устройства (ECDSA P-256).
/// На iPhone закрытый ключ создается внутри Secure Enclave и физически не может быть извлечен —
/// подписать паспорт снимка можно только на этом телефоне и только этим приложением.
final class DeviceSigner {
    enum Storage: String {
        case secureEnclave = "secure-enclave"
        case keychain = "keychain-software"
    }

    static let shared = DeviceSigner()

    private enum Key {
        case enclave(SecureEnclave.P256.Signing.PrivateKey)
        case software(P256.Signing.PrivateKey)
    }

    private let lock = NSLock()
    private var cached: Key?
    private let enclaveAccount = "device-signing-key.secure-enclave.v1"
    private let softwareAccount = "device-signing-key.software.v1"

    private init() {}

    private func key() throws -> Key {
        lock.lock()
        defer { lock.unlock() }
        if let cached { return cached }
        let loaded = try loadOrCreate()
        cached = loaded
        return loaded
    }

    private func loadOrCreate() throws -> Key {
        if SecureEnclave.isAvailable {
            if let blob = KeychainStore.read(enclaveAccount),
               let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob) {
                return .enclave(key)
            }
            let key = try SecureEnclave.P256.Signing.PrivateKey()
            try KeychainStore.save(key.dataRepresentation, account: enclaveAccount)
            return .enclave(key)
        }
        // Симулятор или устройство без Secure Enclave — программный ключ (отмечается в паспорте).
        if let raw = KeychainStore.read(softwareAccount),
           let key = try? P256.Signing.PrivateKey(rawRepresentation: raw) {
            return .software(key)
        }
        let key = P256.Signing.PrivateKey()
        try KeychainStore.save(key.rawRepresentation, account: softwareAccount)
        return .software(key)
    }

    func storage() throws -> Storage {
        if case .enclave = try key() { return .secureEnclave }
        return .keychain
    }

    func publicKey() throws -> P256.Signing.PublicKey {
        switch try key() {
        case .enclave(let key): return key.publicKey
        case .software(let key): return key.publicKey
        }
    }

    func publicKeyPEM() throws -> String { try publicKey().pemRepresentation }

    /// SHA-256 открытого ключа (SubjectPublicKeyInfo DER) — «отпечаток» устройства.
    func fingerprint() throws -> String { Hashing.sha256Hex(try publicKey().derRepresentation) }

    /// Подпись ECDSA P-256 / SHA-256 в формате DER (совместима с `openssl dgst -verify`).
    func sign(_ data: Data) throws -> Data {
        switch try key() {
        case .enclave(let key): return try key.signature(for: data).derRepresentation
        case .software(let key): return try key.signature(for: data).derRepresentation
        }
    }
}
