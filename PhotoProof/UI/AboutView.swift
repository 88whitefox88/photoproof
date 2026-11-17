import SwiftUI

struct AboutView: View {
    @State private var fingerprint = "…"
    @State private var storage = "…"
    @State private var attestStatus: AppAttestManager.Status = .notReady
    @State private var shareItem: ShareItem?
    @State private var attesting = false

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Text(AppInfoProvider.displayName).font(.title2.bold())
                    Text("Камера для фотофиксации. Каждый снимок получает штамп даты, времени и места, электронную подпись устройства и метки доверенного времени от независимых служб (RFC 3161).")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Text("Версия \(AppInfoProvider.version) (\(AppInfoProvider.build))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }

            Section {
                InfoRow(title: "Хранилище ключа", value: storage)
                InfoRow(title: "Отпечаток ключа (SHA-256)", value: fingerprint, monospaced: true)
                Button { exportPublicKey() } label: {
                    Label("Экспортировать открытый ключ", systemImage: "key")
                }
            } header: {
                Text("Ключ подписи этого iPhone")
            } footer: {
                Text("Закрытый ключ создан в защищенном чипе Secure Enclave и не может быть извлечен или скопирован. Отпечаток ключа можно заранее зафиксировать у нотариуса — тогда принадлежность всех снимков с этого телефона подтверждается проще.")
            }

            Section {
                StatusRow(state: attestState, title: attestTitle, detail: attestDetail)
                if canAttest {
                    Button {
                        attesting = true
                        Task { @MainActor in
                            await AppAttestManager.shared.prepare()
                            await refresh()
                            attesting = false
                        }
                    } label: {
                        Label(attesting ? "Аттестация…" : "Выполнить аттестацию", systemImage: "checkmark.seal")
                    }
                    .disabled(attesting)
                }
            } header: {
                Text("Apple App Attest")
            } footer: {
                Text("Подтверждение Apple, что снимки подписывает оригинальное приложение на настоящем iPhone. Выполняется один раз, нужен интернет.")
            }

            Section("Службы доверенного времени") {
                ForEach(TSAServer.defaults, id: \.self) { server in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(server.name)
                        Text(server.url.absoluteString).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            Section {
                GuideItem(number: 1, text: "Снимайте только в этом приложении. Не редактируйте и не пересохраняйте файлы.")
                GuideItem(number: 2, text: "Сразу после съемки отправьте ZIP-пакет себе на почту или юристу — это еще одна независимая фиксация времени.")
                GuideItem(number: 3, text: "Для суда: распечатайте акт (PDF) и фото со штампом, подпишите акт. ZIP-пакет передайте на флешке или диске вместе с ходатайством о приобщении. Укажите, когда, кем, где и каким устройством сделаны снимки.")
                GuideItem(number: 4, text: "Если другая сторона заявит о подделке — ходатайствуйте о компьютерно-технической экспертизе. Эксперт проверит пакет по инструкции README.txt.")
                GuideItem(number: 5, text: "Максимальная надежность — нотариальное обеспечение доказательств: нотариус осматривает телефон и файлы и фиксирует их контрольные суммы в протоколе.")
                GuideItem(number: 6, text: "Не удаляйте приложение и снимки и сохраняйте телефон до окончания дела.")
            } header: {
                Text("Как использовать в суде")
            } footer: {
                Text("Приложение повышает достоверность снимков, но не гарантирует их принятие: доказательства оценивает суд. Это не юридическая консультация.")
            }
        }
        .navigationTitle("О приложении")
        .task { await refresh() }
        .sheet(item: $shareItem) { ActivityView(items: $0.urls) }
    }

    private var canAttest: Bool {
        switch attestStatus {
        case .ready, .unsupported: return false
        case .notReady, .failed: return true
        }
    }

    private var attestState: StatusRow.State {
        switch attestStatus {
        case .ready: return .ok
        case .unsupported: return .neutral
        case .notReady: return .warning
        case .failed: return .bad
        }
    }

    private var attestTitle: String {
        switch attestStatus {
        case .ready: return "Ключ аттестован Apple"
        case .unsupported: return "Не поддерживается на этом устройстве"
        case .notReady: return "Аттестация еще не выполнена"
        case .failed: return "Аттестация не удалась"
        }
    }

    private var attestDetail: String? {
        switch attestStatus {
        case .ready(let keyId): return "Ключ: \(keyId.prefix(16))…"
        case .failed(let message): return message
        default: return nil
        }
    }

    @MainActor
    private func refresh() async {
        if let value = try? DeviceSigner.shared.fingerprint() {
            fingerprint = Fmt.groupedHex(value)
        } else {
            fingerprint = "ошибка чтения ключа"
        }
        storage = (try? DeviceSigner.shared.storage()) == .secureEnclave
            ? "Secure Enclave (аппаратный, неизвлекаемый)"
            : "Связка ключей (программный)"
        attestStatus = await AppAttestManager.shared.status()
    }

    private func exportPublicKey() {
        guard let pem = try? DeviceSigner.shared.publicKeyPEM(),
              let fingerprint = try? DeviceSigner.shared.fingerprint() else { return }
        let text = """
        Открытый ключ подписи устройства (приложение \(AppInfoProvider.displayName))
        Отпечаток SHA-256 (SubjectPublicKeyInfo): \(fingerprint)
        Выгружен: \(Fmt.isoUTC(Date()))

        \(pem)

        """
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("photoproof_device_public_key.pem")
        do {
            try Data(text.utf8).write(to: url, options: .atomic)
            shareItem = ShareItem(urls: [url])
        } catch {}
    }
}

private struct GuideItem: View {
    let number: Int
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text("\(number)")
                .font(.footnote.bold())
                .frame(width: 20, height: 20)
                .background(Circle().fill(Color.accentColor.opacity(0.25)))
            Text(text).font(.subheadline)
        }
        .padding(.vertical, 2)
    }
}
