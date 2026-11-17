import Photos
import SwiftUI

struct EvidenceDetailView: View {
    let evidenceId: String
    @EnvironmentObject private var store: EvidenceStore
    @State private var shareItem: ShareItem?
    @State private var checks: [VerificationCheck]?
    @State private var busy = false
    @State private var notice: String?
    @State private var showFullImage = false

    var body: some View {
        Group {
            if let item = store.item(id: evidenceId) {
                content(item)
            } else {
                Text("Запись не найдена").foregroundStyle(.secondary)
            }
        }
        .navigationTitle("№ \(evidenceId)")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $shareItem) { ActivityView(items: $0.urls) }
        .alert("ФотоДоказ",
               isPresented: Binding(get: { notice != nil }, set: { if !$0 { notice = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(notice ?? "")
        }
    }

    private func content(_ item: EvidenceItem) -> some View {
        let m = item.manifest
        return List {
            Section {
                StampedImageView(url: item.stampedURL)
                    .contentShape(Rectangle())
                    .onTapGesture { showFullImage = true }
            } footer: {
                Text("Нажмите, чтобы увеличить. Штамп нанесен под кадром и не закрывает изображение.")
            }
            .listRowInsets(EdgeInsets())

            Section("Статус") {
                StatusRow(state: item.isTimeConfirmed ? .ok : .warning,
                          title: item.isTimeConfirmed ? "Время подтверждено" : "Метка времени ожидается",
                          detail: timeStatusDetail(item))
                StatusRow(state: m.place == nil ? .warning : (m.place?.isSimulatedBySoftware == true ? .bad : .ok),
                          title: m.place == nil ? "Без геопозиции" : "Место зафиксировано",
                          detail: m.place.map { "±\(Fmt.meters($0.horizontalAccuracyMeters))" + ($0.isSimulatedBySoftware == true ? " · ПОДМЕНА КООРДИНАТ" : "") })
                StatusRow(state: .ok,
                          title: "Подписано ключом устройства",
                          detail: m.signing.keyStorage == "secure-enclave" ? "Ключ в Secure Enclave" : "Программный ключ")
                StatusRow(state: item.hasAssertion ? .ok : .neutral,
                          title: item.hasAssertion ? "Аттестовано Apple App Attest" : "Без App Attest",
                          detail: item.hasAssertion ? "Оригинальное приложение на настоящем iPhone" : "Аттестация недоступна на этом устройстве или не была готова")
            }

            Section {
                Button { export(item) } label: {
                    Label("Пакет доказательств (ZIP)", systemImage: "doc.zipper")
                }
                Button { shareItem = ShareItem(urls: [item.reportURL]) } label: {
                    Label("Акт фотофиксации (PDF)", systemImage: "doc.richtext")
                }
                Button { shareItem = ShareItem(urls: [item.stampedURL]) } label: {
                    Label("Фото со штампом", systemImage: "photo")
                }
                Button { saveToPhotos(item) } label: {
                    Label("Сохранить копию в «Фото»", systemImage: "square.and.arrow.down")
                }
            } header: {
                Text("Передать")
            } footer: {
                Text("Для суда передавайте ZIP-пакет целиком: доказательством служат оригинал, паспорт, подписи и метки времени. Отправьте пакет себе на почту сразу после съемки — это дополнительная независимая фиксация.")
            }
            .disabled(busy)

            Section {
                Button { checks = EvidenceVerifier.verify(folder: item.folder) } label: {
                    Label("Проверить целостность", systemImage: "checkmark.shield")
                }
                if let checks {
                    ForEach(checks) { CheckRow(check: $0) }
                }
            } header: {
                Text("Проверка")
            } footer: {
                Text("Проверяются контрольные суммы, подпись паспорта и соответствие меток времени. Подписи служб времени и цепочку Apple проверяет эксперт по инструкции README.txt.")
            }

            Section("Сведения") {
                InfoRow(title: "Время съемки (часы устройства)",
                        value: "\(Fmt.dateTime(item.captureDate, timeZone: item.timeZone)) \(Fmt.utcOffset(item.timeZone, at: item.captureDate))")
                ForEach(Array(m.timestamps.enumerated()), id: \.offset) { _, t in
                    InfoRow(title: "Метка \(t.tsaName) на снимок",
                            value: Fmt.parseISO(t.genTimeUTC).map { Fmt.dateTime($0, timeZone: item.timeZone) } ?? t.genTimeUTC)
                }
                ForEach(item.manifestTimestamps, id: \.self) { t in
                    InfoRow(title: "Метка \(t.tsaName) на паспорт", value: Fmt.dateTime(t.genTime, timeZone: item.timeZone))
                }
                if let p = m.place {
                    InfoRow(title: "Координаты", value: Fmt.coordinate(latitude: p.latitude, longitude: p.longitude))
                    InfoRow(title: "Точность", value: "±\(Fmt.meters(p.horizontalAccuracyMeters))")
                    if let address = p.address { InfoRow(title: "Адрес (справочно)", value: address) }
                }
                InfoRow(title: "Устройство", value: "\(m.hardware.model), \(m.hardware.systemName) \(m.hardware.systemVersion)")
                InfoRow(title: "SHA-256 оригинала", value: item.originalSha256, monospaced: true)
                InfoRow(title: "SHA-256 паспорта", value: item.manifestSha256, monospaced: true)
                InfoRow(title: "Запись журнала", value: "№ \(m.journal.sequence)")
            }
        }
        .fullScreenCover(isPresented: $showFullImage) {
            FullImageView(url: item.stampedURL)
        }
    }

    private func timeStatusDetail(_ item: EvidenceItem) -> String {
        let names = Array(Set(item.manifest.timestamps.map(\.tsaName) + item.manifestTimestamps.map(\.tsaName))).sorted()
        if names.isEmpty { return "Нет связи со службами времени — метка будет запрошена автоматически" }
        var text = names.joined(separator: ", ")
        if let clock = item.manifest.clockCheck, !clock.deviceClockWithinTolerance {
            text += " · часы телефона расходились на \(Fmt.signedSeconds(clock.typicalOffset))"
        }
        return text
    }

    private func export(_ item: EvidenceItem) {
        busy = true
        let folder = item.folder
        Task { @MainActor in
            defer { busy = false }
            do {
                let url = try await Task.detached(priority: .userInitiated) {
                    try PackageExporter.zip(folder: folder)
                }.value
                shareItem = ShareItem(urls: [url])
            } catch {
                notice = "Не удалось создать архив: \(error.localizedDescription)"
            }
        }
    }

    private func saveToPhotos(_ item: EvidenceItem) {
        let url = item.stampedURL
        PHPhotoLibrary.requestAuthorization(for: .addOnly) { status in
            guard status == .authorized || status == .limited else {
                Task { @MainActor in notice = "Нет разрешения на добавление в «Фото»." }
                return
            }
            PHPhotoLibrary.shared().performChanges({
                let request = PHAssetCreationRequest.forAsset()
                request.addResource(with: .photo, fileURL: url, options: nil)
            }, completionHandler: { success, error in
                Task { @MainActor in
                    notice = success
                        ? "Копия со штампом сохранена в «Фото». Для суда используйте пакет из приложения — в «Фото» хранится лишь копия."
                        : "Ошибка: \(error?.localizedDescription ?? "неизвестно")"
                }
            })
        }
    }
}

struct StampedImageView: View {
    let url: URL
    @State private var image: UIImage?

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image).resizable().scaledToFit()
            } else {
                Rectangle()
                    .fill(Color.gray.opacity(0.2))
                    .aspectRatio(3.0 / 4.0, contentMode: .fit)
                    .overlay(ProgressView())
            }
        }
        .task(id: url) {
            let url = self.url
            let box = await Task.detached(priority: .userInitiated) {
                UncheckedBox(value: ImageLoader.downsampled(url, maxPixel: 1800))
            }.value
            image = box.value
        }
    }
}

struct FullImageView: View {
    let url: URL
    @Environment(\.dismiss) private var dismiss
    @State private var image: UIImage?

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.black.ignoresSafeArea()
            if let image {
                ZoomableImageView(image: image).ignoresSafeArea()
            } else {
                ProgressView().tint(.white).frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            Button { dismiss() } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.largeTitle)
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.white)
                    .padding()
            }
            .accessibilityLabel("Закрыть")
        }
        .task {
            let url = self.url
            let box = await Task.detached(priority: .userInitiated) {
                UncheckedBox(value: ImageLoader.downsampled(url, maxPixel: 4096))
            }.value
            image = box.value
        }
    }
}
