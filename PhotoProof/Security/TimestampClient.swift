import Foundation
import Security

/// Служба штампов времени (Time-Stamp Authority, RFC 3161).
/// Независимая организация подписывает хеш файла вместе с точным временем — так доказывается,
/// что файл существовал в неизменном виде не позднее этого момента. Часы телефона на это не влияют.
struct TSAServer: Hashable, Sendable {
    let name: String
    let url: URL

    /// Несколько независимых служб: если одна недоступна — работают остальные,
    /// а несколько меток от разных организаций сильнее одной.
    static let defaults: [TSAServer] = [
        TSAServer(name: "FreeTSA", url: URL(string: "https://freetsa.org/tsr")!),
        TSAServer(name: "DigiCert", url: URL(string: "http://timestamp.digicert.com")!),
        TSAServer(name: "Sectigo", url: URL(string: "http://timestamp.sectigo.com")!),
    ]
}

struct TSTInfo: Sendable {
    let genTime: Date
    let serialNumberHex: String
    let policy: String
    let hashAlgorithm: String
    let hashedMessage: [UInt8]
    let nonce: [UInt8]?
}

struct TimestampToken: Sendable {
    let server: TSAServer
    /// Полный ответ TimeStampResp (файл .tsr) — проверяется `openssl ts -verify`.
    let response: Data
    let info: TSTInfo
    let requestMonotonic: Double
    let responseMonotonic: Double
}

struct TimestampBatch: Sendable {
    var tokens: [TimestampToken] = []
    var failures: [String] = []
}

enum TimestampError: LocalizedError {
    case http(Int)
    case rejected(Int)
    case malformed(String)
    case imprintMismatch
    case nonceMismatch

    var errorDescription: String? {
        switch self {
        case .http(let code): return "сервер ответил HTTP \(code)"
        case .rejected(let status): return "запрос отклонен службой (статус \(status))"
        case .malformed(let what): return "некорректный ответ: \(what)"
        case .imprintMismatch: return "метка выдана на другой хеш"
        case .nonceMismatch: return "nonce в ответе не совпадает с запросом"
        }
    }
}

enum TimestampClient {
    static let sha256OID = "2.16.840.1.101.3.4.2.1"
    static let tstInfoOID = "1.2.840.113549.1.9.16.1.4"

    private enum Outcome: Sendable {
        case success(Int, TimestampToken)
        case failure(Int, String)
        case graceExpired
    }

    /// Запрашивает метки у всех служб параллельно. После первой успешной метки ждет остальные
    /// не дольше `grace` секунд, чтобы медленная служба не задерживала съемку.
    static func timestampAll(digest: Data,
                             servers: [TSAServer] = TSAServer.defaults,
                             timeout: TimeInterval = 12,
                             grace: TimeInterval = 2.5) async -> TimestampBatch {
        let outcomes = await withTaskGroup(of: Outcome.self) { group -> [Outcome] in
            for (index, server) in servers.enumerated() {
                group.addTask {
                    do {
                        return .success(index, try await request(digest: digest, server: server, timeout: timeout))
                    } catch {
                        return .failure(index, error.localizedDescription)
                    }
                }
            }
            var collected: [Outcome] = []
            var graceStarted = false
            while let outcome = await group.next() {
                if case .graceExpired = outcome {
                    group.cancelAll()
                    break
                }
                collected.append(outcome)
                if case .success = outcome, !graceStarted {
                    graceStarted = true
                    group.addTask {
                        try? await Task.sleep(nanoseconds: UInt64(grace * 1_000_000_000))
                        return .graceExpired
                    }
                }
                let answered = collected.count
                if answered == servers.count {
                    group.cancelAll()
                    break
                }
            }
            return collected
        }

        var tokens: [Int: TimestampToken] = [:]
        var failures: [Int: String] = [:]
        for outcome in outcomes {
            switch outcome {
            case .success(let index, let token): tokens[index] = token
            case .failure(let index, let message): failures[index] = message
            case .graceExpired: break
            }
        }
        var batch = TimestampBatch()
        for (index, server) in servers.enumerated() {
            if let token = tokens[index] {
                batch.tokens.append(token)
            } else {
                batch.failures.append("\(server.name): \(failures[index] ?? "не ответила вовремя")")
            }
        }
        return batch
    }

    static func request(digest: Data, server: TSAServer, timeout: TimeInterval) async throws -> TimestampToken {
        var nonce = [UInt8](repeating: 0, count: 8)
        guard SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce) == errSecSuccess else {
            throw TimestampError.malformed("нет источника случайных чисел")
        }
        nonce[0] = (nonce[0] & 0x7F) | 0x01 // положительное число без ведущего нуля

        var request = URLRequest(url: server.url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        request.httpMethod = "POST"
        request.setValue("application/timestamp-query", forHTTPHeaderField: "Content-Type")
        request.setValue("application/timestamp-reply", forHTTPHeaderField: "Accept")
        request.httpBody = Data(makeRequest(digest: [UInt8](digest), nonce: nonce))

        let started = MonotonicClock.now()
        let (data, response) = try await URLSession.shared.data(for: request)
        let finished = MonotonicClock.now()

        guard let http = response as? HTTPURLResponse else { throw TimestampError.malformed("не HTTP-ответ") }
        guard http.statusCode == 200 else { throw TimestampError.http(http.statusCode) }
        let info = try parseResponse(data, expectedDigest: [UInt8](digest), expectedNonce: nonce)
        return TimestampToken(server: server, response: data, info: info,
                              requestMonotonic: started, responseMonotonic: finished)
    }

    /// TimeStampReq ::= SEQUENCE { version 1, messageImprint, nonce, certReq TRUE }
    static func makeRequest(digest: [UInt8], nonce: [UInt8]) -> [UInt8] {
        let algorithm = DER.sequence(DER.oid(sha256OID), DER.null())
        let imprint = DER.sequence(algorithm, DER.octetString(digest))
        return DER.sequence(DER.integer(1), imprint, DER.integer(unsignedBytes: nonce), DER.boolean(true))
    }

    /// Разбирает TimeStampResp и проверяет, что метка выдана именно на наш хеш.
    /// Криптографическую подпись самой службы проверяет эксперт (OpenSSL / verify.py).
    static func parseResponse(_ data: Data, expectedDigest: [UInt8]? = nil, expectedNonce: [UInt8]? = nil) throws -> TSTInfo {
        guard let response = try DER.parseAll([UInt8](data)).first, response.tag == DER.sequenceTag else {
            throw TimestampError.malformed("нет TimeStampResp")
        }
        let parts = try response.children()
        guard let statusInfo = parts.first, statusInfo.tag == DER.sequenceTag else {
            throw TimestampError.malformed("нет PKIStatusInfo")
        }
        let status = DER.intValue(try statusInfo.child(0).content)
        guard status == 0 || status == 1 else { throw TimestampError.rejected(status) }
        guard parts.count >= 2 else { throw TimestampError.malformed("нет токена") }

        let info = try parseToken(parts[1])
        if let expectedDigest, info.hashedMessage != expectedDigest { throw TimestampError.imprintMismatch }
        if let expectedNonce {
            guard let nonce = info.nonce,
                  DER.stripLeadingZeros(nonce) == DER.stripLeadingZeros(expectedNonce) else {
                throw TimestampError.nonceMismatch
            }
        }
        return info
    }

    /// ContentInfo → SignedData → encapContentInfo → TSTInfo
    static func parseToken(_ contentInfo: DERNode) throws -> TSTInfo {
        let ci = try contentInfo.children()
        guard ci.count >= 2, ci[1].tag == DER.context0 else { throw TimestampError.malformed("ContentInfo") }
        let signedData = try ci[1].child(0)

        var tstBytes: [UInt8]?
        for node in try signedData.children() where node.tag == DER.sequenceTag {
            guard let kids = try? node.children(), kids.count >= 2, kids[0].tag == DER.oidTag,
                  DER.oidString(kids[0].content) == tstInfoOID, kids[1].tag == DER.context0 else { continue }
            let octets = try kids[1].child(0)
            guard octets.tag == DER.octetStringTag else { throw TimestampError.malformed("eContent") }
            tstBytes = octets.content
            break
        }
        guard let tstBytes, let tst = try DER.parseAll(tstBytes).first else {
            throw TimestampError.malformed("нет TSTInfo")
        }

        // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, accuracy?, ordering?, nonce?, ... }
        let f = try tst.children()
        guard f.count >= 5, f[1].tag == DER.oidTag, f[2].tag == DER.sequenceTag,
              f[3].tag == DER.integerTag, f[4].tag == DER.generalizedTimeTag else {
            throw TimestampError.malformed("поля TSTInfo")
        }
        let imprint = try f[2].children()
        guard imprint.count == 2 else { throw TimestampError.malformed("messageImprint") }
        let algorithm = try imprint[0].child(0)
        guard let genTime = DER.generalizedTime(f[4].content) else { throw TimestampError.malformed("genTime") }
        let nonce = f.dropFirst(5).first { $0.tag == DER.integerTag }?.content

        return TSTInfo(genTime: genTime,
                       serialNumberHex: Data(f[3].content).hex,
                       policy: DER.oidString(f[1].content),
                       hashAlgorithm: DER.oidString(algorithm.content),
                       hashedMessage: imprint[1].content,
                       nonce: nonce)
    }
}
