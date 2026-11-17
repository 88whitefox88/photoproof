import Foundation

/// Журнал устройства (append-only). Каждая запись содержит SHA-256 предыдущей записи,
/// а паспорт каждого снимка — ссылку на текущий конец журнала. Поэтому удаление,
/// подмена или «досъемка задним числом» обнаруживаются при осмотре телефона.
enum Journal {
    enum Event: String, Codable {
        case captured
        case timestamped
        case deleted
    }

    struct Entry: Codable {
        let seq: Int
        let event: Event
        let evidenceId: String
        let manifestSha256: String?
        let deviceTimeUTC: String
        let prev: String
    }

    static var url: URL { AppPaths.support.appendingPathComponent("journal.jsonl") }
    static let genesis = String(repeating: "0", count: 64)

    /// Номер и SHA-256 последней записи.
    static func head() -> (seq: Int, hash: String) {
        guard let data = try? Data(contentsOf: url), !data.isEmpty else { return (0, genesis) }
        let lines = data.split(separator: UInt8(ascii: "\n"))
        guard let last = lines.last,
              let entry = try? JSONDecoder().decode(Entry.self, from: Data(last)) else { return (0, genesis) }
        return (entry.seq, Hashing.sha256Hex(Data(last)))
    }

    @discardableResult
    static func append(_ event: Event, evidenceId: String, manifestSha256: String?) throws -> Entry {
        let current = head()
        let entry = Entry(seq: current.seq + 1,
                          event: event,
                          evidenceId: evidenceId,
                          manifestSha256: manifestSha256,
                          deviceTimeUTC: Fmt.isoUTC(Date()),
                          prev: current.hash)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var line = try encoder.encode(entry)
        line.append(UInt8(ascii: "\n"))
        if FileManager.default.fileExists(atPath: url.path) {
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: line)
        } else {
            try line.write(to: url, options: .atomic)
        }
        return entry
    }
}
