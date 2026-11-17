import Foundation

/// Минимальный кодер/декодер ASN.1 DER — ровно столько, сколько нужно для RFC 3161.

enum DERError: LocalizedError {
    case truncated
    case unsupported(String)
    case unexpected(String)

    var errorDescription: String? {
        switch self {
        case .truncated: return "структура ASN.1 обрезана"
        case .unsupported(let what): return "неподдерживаемая структура ASN.1: \(what)"
        case .unexpected(let what): return "неожиданная структура ASN.1: \(what)"
        }
    }
}

struct DERNode {
    let tag: UInt8
    let content: [UInt8]

    func children() throws -> [DERNode] { try DER.parseAll(content) }

    func child(_ index: Int) throws -> DERNode {
        let all = try children()
        guard index < all.count else {
            throw DERError.unexpected("нет элемента #\(index) в теге 0x\(String(tag, radix: 16))")
        }
        return all[index]
    }
}

enum DER {
    static let integerTag: UInt8 = 0x02
    static let octetStringTag: UInt8 = 0x04
    static let oidTag: UInt8 = 0x06
    static let generalizedTimeTag: UInt8 = 0x18
    static let sequenceTag: UInt8 = 0x30
    static let context0: UInt8 = 0xA0

    // MARK: - Разбор

    static func parseAll(_ bytes: [UInt8]) throws -> [DERNode] {
        var nodes: [DERNode] = []
        var offset = 0
        while offset < bytes.count {
            let (node, next) = try parseOne(bytes, at: offset)
            nodes.append(node)
            offset = next
        }
        return nodes
    }

    static func parseOne(_ b: [UInt8], at start: Int) throws -> (DERNode, Int) {
        var i = start
        guard i + 2 <= b.count else { throw DERError.truncated }
        let tag = b[i]
        i += 1
        guard tag & 0x1F != 0x1F else { throw DERError.unsupported("многобайтовый тег") }
        var length = Int(b[i])
        i += 1
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard count > 0 else { throw DERError.unsupported("неопределенная длина (BER)") }
            guard count <= 4, i + count <= b.count else { throw DERError.truncated }
            length = 0
            for _ in 0..<count {
                length = (length << 8) | Int(b[i])
                i += 1
            }
        }
        guard length >= 0, i + length <= b.count else { throw DERError.truncated }
        return (DERNode(tag: tag, content: Array(b[i..<(i + length)])), i + length)
    }

    // MARK: - Кодирование

    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + encodeLength(content.count) + content
    }

    static func encodeLength(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    static func sequence(_ items: [UInt8]...) -> [UInt8] {
        tlv(sequenceTag, items.flatMap { $0 })
    }

    static func integer(_ value: Int) -> [UInt8] {
        precondition(value >= 0)
        var bytes: [UInt8] = []
        var v = value
        repeat {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        } while v > 0
        return integer(unsignedBytes: bytes)
    }

    static func integer(unsignedBytes: [UInt8]) -> [UInt8] {
        var bytes = Array(unsignedBytes.drop { $0 == 0 })
        if bytes.isEmpty { bytes = [0] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        return tlv(integerTag, bytes)
    }

    static func octetString(_ bytes: [UInt8]) -> [UInt8] { tlv(octetStringTag, bytes) }

    static func null() -> [UInt8] { [0x05, 0x00] }

    static func boolean(_ value: Bool) -> [UInt8] { [0x01, 0x01, value ? 0xFF : 0x00] }

    static func oid(_ dotted: String) -> [UInt8] {
        let arcs = dotted.split(separator: ".").compactMap { UInt64($0) }
        precondition(arcs.count >= 2)
        var body = base128(arcs[0] * 40 + arcs[1])
        for arc in arcs.dropFirst(2) { body += base128(arc) }
        return tlv(oidTag, body)
    }

    private static func base128(_ value: UInt64) -> [UInt8] {
        var v = value >> 7
        var out: [UInt8] = [UInt8(value & 0x7F)]
        while v > 0 {
            out.insert(UInt8(v & 0x7F) | 0x80, at: 0)
            v >>= 7
        }
        return out
    }

    // MARK: - Значения

    static func oidString(_ content: [UInt8]) -> String {
        var arcs: [UInt64] = []
        var value: UInt64 = 0
        for byte in content {
            value = (value << 7) | UInt64(byte & 0x7F)
            if byte & 0x80 == 0 {
                arcs.append(value)
                value = 0
            }
        }
        guard let first = arcs.first else { return "" }
        let head: [UInt64] = first < 40 ? [0, first] : (first < 80 ? [1, first - 40] : [2, first - 80])
        return (head + arcs.dropFirst()).map { String($0) }.joined(separator: ".")
    }

    /// Небольшие неотрицательные INTEGER (статус и т.п.).
    static func intValue(_ content: [UInt8]) -> Int {
        content.prefix(8).reduce(0) { ($0 << 8) | Int($1) }
    }

    static func stripLeadingZeros(_ bytes: [UInt8]) -> [UInt8] {
        let stripped = Array(bytes.drop { $0 == 0 })
        return stripped.isEmpty ? [0] : stripped
    }

    /// GeneralizedTime в формате RFC 3161: YYYYMMDDHHMMSS[.fff]Z
    static func generalizedTime(_ content: [UInt8]) -> Date? {
        let string = String(decoding: content, as: UTF8.self)
        guard string.hasSuffix("Z"), string.count >= 15 else { return nil }
        let chars = Array(string.dropLast())
        func number(_ from: Int, _ length: Int) -> Int? {
            Int(String(chars[from..<(from + length)]))
        }
        guard let year = number(0, 4), let month = number(4, 2), let day = number(6, 2),
              let hour = number(8, 2), let minute = number(10, 2), let second = number(12, 2) else { return nil }
        var fraction = 0.0
        if chars.count > 14 {
            guard chars[14] == "." || chars[14] == "," else { return nil }
            fraction = Double("0." + String(chars[15...])) ?? 0
        }
        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.hour = hour
        components.minute = minute
        components.second = second
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        guard let date = calendar.date(from: components) else { return nil }
        return date.addingTimeInterval(fraction)
    }
}
