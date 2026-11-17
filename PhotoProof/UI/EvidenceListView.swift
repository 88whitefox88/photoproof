import SwiftUI

struct EvidenceListView: View {
    @EnvironmentObject private var store: EvidenceStore
    @State private var pendingDeletion: EvidenceItem?

    var body: some View {
        List {
            if store.items.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "photo.on.rectangle.angled")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("Снимков пока нет").font(.headline)
                    Text("Здесь хранятся все снимки, сделанные в приложении, вместе с подписями и метками времени.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 40)
                .listRowBackground(Color.clear)
            }
            ForEach(store.items) { item in
                NavigationLink(value: Route.evidence(item.id)) {
                    EvidenceRow(item: item)
                }
                .swipeActions {
                    Button { pendingDeletion = item } label: {
                        Label("Удалить", systemImage: "trash")
                    }
                    .tint(.red)
                }
            }
        }
        .navigationTitle("Архив")
        .refreshable { await store.completePendingTimestamps() }
        .confirmationDialog("Удалить снимок?",
                            isPresented: Binding(get: { pendingDeletion != nil },
                                                 set: { if !$0 { pendingDeletion = nil } }),
                            titleVisibility: .visible,
                            presenting: pendingDeletion) { item in
            Button("Удалить безвозвратно", role: .destructive) { store.delete(item) }
        } message: { _ in
            Text("Оригинал, подписи и метки времени будут удалены. Факт удаления останется в журнале. Если снимок может понадобиться в суде — сначала экспортируйте пакет.")
        }
    }
}

struct EvidenceRow: View {
    let item: EvidenceItem

    var body: some View {
        HStack(spacing: 12) {
            ThumbnailView(id: item.id)
                .frame(width: 64, height: 64)
                .clipShape(RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 4) {
                Text(Fmt.dateTime(item.captureDate, timeZone: item.timeZone))
                    .font(.headline.monospacedDigit())
                Text(placeText)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                HStack(spacing: 6) {
                    Image(systemName: item.isTimeConfirmed ? "checkmark.seal.fill" : "clock.badge.exclamationmark")
                        .foregroundStyle(item.isTimeConfirmed ? .green : .orange)
                    Text("№ \(item.id)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                .font(.caption)
            }
        }
        .padding(.vertical, 2)
    }

    private var placeText: String {
        guard let place = item.manifest.place else { return "Без геопозиции" }
        if let address = place.address, !address.isEmpty { return address }
        return Fmt.coordinate(latitude: place.latitude, longitude: place.longitude)
    }
}
