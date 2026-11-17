import Foundation

@MainActor
final class EvidenceStore: ObservableObject {
    @Published private(set) var items: [EvidenceItem] = []
    private var isCompleting = false

    init() {
        AppPaths.prepare()
        reload()
    }

    func reload() {
        let folders = (try? FileManager.default.contentsOfDirectory(
            at: AppPaths.evidenceRoot, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles])) ?? []
        items = folders
            .compactMap { EvidenceLoader.load(folder: $0) }
            .sorted { $0.captureDate > $1.captureDate }
    }

    func item(id: String) -> EvidenceItem? { items.first { $0.id == id } }

    func delete(_ item: EvidenceItem) {
        try? FileManager.default.removeItem(at: item.folder)
        try? FileManager.default.removeItem(at: AppPaths.thumbnail(for: item.id))
        try? Journal.append(.deleted, evidenceId: item.id, manifestSha256: item.manifestSha256)
        reload()
    }

    /// Дозапрашивает метки времени на паспорта снимков, сделанных без сети.
    /// Метка, полученная позже, честно показывает свое время — оно отражается в акте.
    func completePendingTimestamps() async {
        guard !isCompleting else { return }
        isCompleting = true
        defer { isCompleting = false }

        let pending = items.filter { $0.manifestTimestamps.isEmpty }
        guard !pending.isEmpty else { return }
        var changed = false
        for item in pending {
            guard let manifestData = try? Data(contentsOf: item.manifestURL) else { continue }
            let batch = await TimestampClient.timestampAll(digest: Hashing.sha256(manifestData))
            if batch.tokens.isEmpty { break } // сети нет — попробуем в следующий раз
            let tsaFolder = item.folder.appendingPathComponent(EvidenceFiles.tsaDirectory)
            try? FileManager.default.createDirectory(at: tsaFolder, withIntermediateDirectories: true)
            for token in batch.tokens {
                let url = item.folder.appendingPathComponent(EvidenceFiles.tokenPath(subject: "manifest", server: token.server))
                try? token.response.write(to: url, options: .atomic)
            }
            try? Journal.append(.timestamped, evidenceId: item.id, manifestSha256: item.manifestSha256)
            if let updated = EvidenceLoader.load(folder: item.folder) {
                await PackageDocuments.write(for: updated)
            }
            changed = true
        }
        if changed { reload() }
    }
}
