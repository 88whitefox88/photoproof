import UIKit

/// Акт фотофиксации (PDF A4) — удобочитаемое отображение подписанного паспорта для печати и подачи в суд.
enum ReportBuilder {
    static func build(for item: EvidenceItem) -> Data {
        let m = item.manifest
        let tz = item.timeZone
        let pageRect = CGRect(x: 0, y: 0, width: 595.28, height: 841.89)
        let format = UIGraphicsPDFRendererFormat()
        format.documentInfo = [
            kCGPDFContextTitle as String: "Акт фотофиксации № \(item.id)",
            kCGPDFContextCreator as String: "\(AppInfoProvider.displayName) \(m.application.version)",
        ]
        let photo = reportImage(item.stampedURL)
        let renderer = UIGraphicsPDFRenderer(bounds: pageRect, format: format)

        return renderer.pdfData { context in
            var page = PDFPageWriter(context: context, bounds: pageRect)
            page.begin()
            page.title("АКТ ФОТОФИКСАЦИИ № \(item.id)")
            page.paragraph("Сформирован автоматически приложением «\(m.application.name)» \(m.application.version) на основании подписанного паспорта снимка (manifest.json). Доказательственное значение имеют файлы электронного пакета; настоящий акт — их удобочитаемое отображение.",
                           size: 8.5, color: .darkGray)

            page.section("1. Время съемки")
            page.row("По часам устройства",
                     "\(Fmt.dateTime(item.captureDate, timeZone: tz)) (\(Fmt.utcOffset(tz, at: item.captureDate)), \(m.capture.timeZone))")
            page.row("То же, UTC", m.capture.deviceTimeUTC)
            if m.timestamps.isEmpty {
                page.row("Метка времени на снимок", "не получена в момент съемки (нет связи со службами времени)")
            }
            for t in m.timestamps {
                let local = Fmt.parseISO(t.genTimeUTC).map { Fmt.dateTime($0, timeZone: tz) } ?? t.genTimeUTC
                page.row("Метка времени на снимок", "\(t.tsaName): \(local) (\(t.genTimeUTC)); служба \(t.tsaURL); серийный № \(t.serialNumber)")
            }
            for t in item.manifestTimestamps {
                page.row("Метка времени на паспорт", "\(t.tsaName): \(Fmt.dateTime(t.genTime, timeZone: tz)) (\(Fmt.isoUTC(t.genTime)))")
            }
            if let c = m.clockCheck {
                page.row("Сверка часов",
                         c.deviceClockWithinTolerance
                            ? "Расхождение часов устройства с эталоном (\(c.reference)) — в пределах ±\(Int(c.toleranceSeconds)) с. Метка запрошена через \(String(format: "%.1f", c.secondsFromCaptureToRequest)) с после съемки."
                            : "Часы устройства отличались от эталона (\(c.reference)) на \(Fmt.signedSeconds(c.typicalOffset)). В штампе указано время по эталону.")
            }

            page.section("2. Место съемки")
            if let p = m.place {
                page.row("Координаты (WGS-84)", String(format: "%.6f, %.6f", p.latitude, p.longitude)
                         + " — " + Fmt.coordinate(latitude: p.latitude, longitude: p.longitude))
                page.row("Точность", "±\(Fmt.meters(p.horizontalAccuracyMeters))"
                         + (p.preciseLocationAuthorized ? "" : " (точная геопозиция была запрещена в настройках)"))
                if let altitude = p.altitudeMeters {
                    page.row("Высота", String(format: "%.0f м", altitude))
                }
                let fixLocal = Fmt.parseISO(p.fixTimeUTC).map { Fmt.dateTime($0, timeZone: tz) } ?? p.fixTimeUTC
                page.row("Координаты получены", "\(fixLocal), за \(String(format: "%.0f", max(0, p.fixAgeSeconds))) с до съемки")
                if let address = p.address { page.row("Адрес (справочно)", address) }
                page.row("Программная подмена координат", p.isSimulatedBySoftware == true ? "ОБНАРУЖЕНА" : "не обнаружена")
            } else {
                page.row("Координаты", "не определены")
            }

            page.section("3. Устройство и приложение")
            page.row("Устройство", "\(m.hardware.model), \(m.hardware.systemName) \(m.hardware.systemVersion)")
            page.row("Приложение", "\(m.application.name) \(m.application.version) (сборка \(m.application.build)), \(m.application.appId ?? m.application.bundleId)")
            page.row("Источник снимка", "камера устройства в момент съемки; загрузка готовых изображений в приложение невозможна")
            page.row("Разрешение снимка", "\(m.capture.imageWidth) × \(m.capture.imageHeight), вспышка: \(m.capture.flash == "on" ? "вкл." : "выкл.")")

            page.section("4. Файлы и контрольные суммы SHA-256")
            for f in m.files {
                page.row(f.name, "\(f.sha256)  (\(Fmt.bytes(f.size)))", mono: true)
            }
            page.row(EvidenceFiles.manifest, item.manifestSha256, mono: true)

            page.section("5. Электронная подпись и аттестация")
            page.row("Подпись паспорта", "\(m.signing.algorithm); ключ: \(m.signing.keyStorage == "secure-enclave" ? "Secure Enclave (аппаратный, неизвлекаемый)" : "программный")")
            page.row("Отпечаток ключа устройства", m.signing.publicKeySpkiSha256, mono: true)
            page.row("Apple App Attest", item.hasAssertion ? "есть; ключ \(m.signing.appAttest?.keyId ?? "")" : "нет")
            page.row("Журнал устройства", "запись № \(m.journal.sequence); хеш предыдущей записи \(m.journal.previousEntrySha256)", mono: false)

            page.section("6. Порядок проверки")
            page.paragraph("Порядок проверки целостности файлов, подписи и меток доверенного времени приведен в файле README.txt пакета. Для проверки достаточно общедоступных инструментов (certutil, OpenSSL) либо скрипта verify.py из исходного кода приложения.",
                           size: 9)

            page.spacer(22)
            page.paragraph("Фотофиксацию произвел(а): _______________________________________________ (Ф.И.О.)", size: 10)
            page.spacer(14)
            page.paragraph("Подпись: ________________________          Дата: «____» ____________ 20____ г.", size: 10)

            if let photo {
                page.begin()
                page.section("Приложение: снимок со штампом (№ \(item.id))")
                page.image(photo)
            }
        }
    }

    /// Уменьшенная копия, перекодированная в JPEG, — чтобы PDF не разрастался.
    private static func reportImage(_ url: URL) -> UIImage? {
        guard let image = ImageLoader.downsampled(url, maxPixel: 1800),
              let jpeg = image.jpegData(compressionQuality: 0.8) else { return nil }
        return UIImage(data: jpeg)
    }
}

private struct PDFPageWriter {
    let context: UIGraphicsPDFRendererContext
    let bounds: CGRect
    let margin: CGFloat = 42
    var y: CGFloat = 0

    init(context: UIGraphicsPDFRendererContext, bounds: CGRect) {
        self.context = context
        self.bounds = bounds
    }

    private var contentWidth: CGFloat { bounds.width - margin * 2 }
    private var bottom: CGFloat { bounds.height - margin }
    private let drawOptions: NSStringDrawingOptions = [.usesLineFragmentOrigin, .usesFontLeading]

    mutating func begin() {
        context.beginPage()
        y = margin
    }

    private mutating func ensureSpace(_ height: CGFloat) {
        if y + height > bottom { begin() }
    }

    private func attributed(_ text: String, font: UIFont, color: UIColor = .black, charWrap: Bool = false) -> NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineBreakMode = charWrap ? .byCharWrapping : .byWordWrapping
        return NSAttributedString(string: text, attributes: [.font: font, .foregroundColor: color, .paragraphStyle: paragraph])
    }

    private func height(_ text: NSAttributedString, width: CGFloat) -> CGFloat {
        ceil(text.boundingRect(with: CGSize(width: width, height: .greatestFiniteMagnitude), options: drawOptions, context: nil).height)
    }

    mutating func title(_ text: String) {
        let s = attributed(text, font: .boldSystemFont(ofSize: 16))
        let h = height(s, width: contentWidth)
        ensureSpace(h)
        s.draw(with: CGRect(x: margin, y: y, width: contentWidth, height: h), options: drawOptions, context: nil)
        y += h + 8
    }

    mutating func paragraph(_ text: String, size: CGFloat = 10, color: UIColor = .black) {
        let s = attributed(text, font: .systemFont(ofSize: size), color: color)
        let h = height(s, width: contentWidth)
        ensureSpace(h)
        s.draw(with: CGRect(x: margin, y: y, width: contentWidth, height: h), options: drawOptions, context: nil)
        y += h + 6
    }

    mutating func section(_ text: String) {
        ensureSpace(48)
        y += 8
        let s = attributed(text, font: .boldSystemFont(ofSize: 11))
        let h = height(s, width: contentWidth)
        s.draw(with: CGRect(x: margin, y: y, width: contentWidth, height: h), options: drawOptions, context: nil)
        y += h + 3
        let line = UIBezierPath()
        line.move(to: CGPoint(x: margin, y: y))
        line.addLine(to: CGPoint(x: margin + contentWidth, y: y))
        line.lineWidth = 0.5
        UIColor.lightGray.setStroke()
        line.stroke()
        y += 5
    }

    mutating func row(_ label: String, _ value: String, mono: Bool = false) {
        let labelWidth: CGFloat = 150
        let gap: CGFloat = 8
        let valueWidth = contentWidth - labelWidth - gap
        let l = attributed(label, font: .systemFont(ofSize: 8.5, weight: .semibold), color: .darkGray)
        let v = attributed(value,
                           font: mono ? .monospacedSystemFont(ofSize: 7.5, weight: .regular) : .systemFont(ofSize: 9),
                           charWrap: mono)
        let h = max(height(l, width: labelWidth), height(v, width: valueWidth))
        ensureSpace(h + 4)
        l.draw(with: CGRect(x: margin, y: y, width: labelWidth, height: h), options: drawOptions, context: nil)
        v.draw(with: CGRect(x: margin + labelWidth + gap, y: y, width: valueWidth, height: h), options: drawOptions, context: nil)
        y += h + 5
    }

    mutating func spacer(_ height: CGFloat) { y += height }

    mutating func image(_ image: UIImage) {
        let available = bottom - y
        let scale = min(contentWidth / image.size.width, available / image.size.height)
        let size = CGSize(width: image.size.width * scale, height: image.size.height * scale)
        image.draw(in: CGRect(x: margin + (contentWidth - size.width) / 2, y: y, width: size.width, height: size.height))
        y += size.height + 8
    }
}
