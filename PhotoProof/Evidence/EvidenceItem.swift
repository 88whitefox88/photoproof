import Foundation

enum AppPaths {
    static var documents: URL { FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0] }
    static var evidenceRoot: URL { documents.appendingPathComponent("Evidence", isDirectory: true) }
    static var support: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("PhotoProof", isDirectory: true)
    }
    static var thumbnails: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Thumbnails", isDirectory: true)
    }

    static func thumbnail(for id: String) -> URL { thumbnails.appendingPathComponent("\(id).jpg") }

    static func prepare() {
        for directory in [evidenceRoot, support, thumbnails] {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }
}

/// Имена файлов пакета — только латиница, чтобы ZIP корректно открывался в Windows.
enum EvidenceFiles {
    static let original = "1_original.jpg"
    static let stamped = "2_stamped.jpg"
    static let manifest = "manifest.json"
    static let signature = "manifest.sig"
    static let assertion = "manifest.appattest-assertion.cbor"
    static let publicKey = "device_public_key.pem"
    static let attestation = "appattest_attestation.cbor"
    static let attestationChallenge = "appattest_challenge.txt"
    static let tsaDirectory = "tsa"
    static let report = "report.pdf"
    static let readme = "README.txt"

    static func tokenPath(subject: String, server: TSAServer) -> String {
        "\(tsaDirectory)/\(subject)_\(server.name).tsr"
    }

    static func folderName(evidenceId: String, captureDate: Date, timeZone: TimeZone) -> String {
        Fmt.pattern("yyyy-MM-dd_HH-mm-ss", captureDate, timeZone) + "_" + evidenceId
    }
}

struct TokenSummary: Hashable, Sendable {
    let tsaName: String
    let genTime: Date
    let file: String
}

struct EvidenceItem: Identifiable, Hashable, Sendable {
    let id: String
    let folder: URL
    let manifest: EvidenceManifest
    let manifestSha256: String
    /// Метки времени на manifest.json (могут быть получены позже, если съемка была без сети).
    let manifestTimestamps: [TokenSummary]
    let captureDate: Date
    let hasAssertion: Bool

    var originalURL: URL { folder.appendingPathComponent(EvidenceFiles.original) }
    var stampedURL: URL { folder.appendingPathComponent(EvidenceFiles.stamped) }
    var manifestURL: URL { folder.appendingPathComponent(EvidenceFiles.manifest) }
    var reportURL: URL { folder.appendingPathComponent(EvidenceFiles.report) }
    var timeZone: TimeZone { TimeZone(identifier: manifest.capture.timeZone) ?? .current }
    var originalSha256: String { manifest.files.first { $0.role == "original" }?.sha256 ?? "" }

    var isTimeConfirmed: Bool { !manifest.timestamps.isEmpty || !manifestTimestamps.isEmpty }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id && lhs.manifestTimestamps == rhs.manifestTimestamps && lhs.hasAssertion == rhs.hasAssertion
    }

    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

enum EvidenceLoader {
    static func load(folder: URL) -> EvidenceItem? {
        guard let data = try? Data(contentsOf: folder.appendingPathComponent(EvidenceFiles.manifest)),
              let manifest = try? EvidenceManifest.decode(data) else { return nil }
        let assertionURL = folder.appendingPathComponent(EvidenceFiles.assertion)
        return EvidenceItem(id: manifest.evidenceId,
                            folder: folder,
                            manifest: manifest,
                            manifestSha256: Hashing.sha256Hex(data),
                            manifestTimestamps: tokens(in: folder, subject: "manifest"),
                            captureDate: Date(timeIntervalSince1970: manifest.capture.unixTime),
                            hasAssertion: FileManager.default.fileExists(atPath: assertionURL.path))
    }

    static func tokens(in folder: URL, subject: String) -> [TokenSummary] {
        let directory = folder.appendingPathComponent(EvidenceFiles.tsaDirectory)
        let prefix = subject + "_"
        let urls = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return urls
            .filter { $0.lastPathComponent.hasPrefix(prefix) && $0.pathExtension == "tsr" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .compactMap { url -> TokenSummary? in
                guard let data = try? Data(contentsOf: url),
                      let info = try? TimestampClient.parseResponse(data) else { return nil }
                let name = String(url.deletingPathExtension().lastPathComponent.dropFirst(prefix.count))
                return TokenSummary(tsaName: name, genTime: info.genTime,
                                    file: EvidenceFiles.tsaDirectory + "/" + url.lastPathComponent)
            }
    }
}
