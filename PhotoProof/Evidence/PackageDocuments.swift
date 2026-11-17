import Foundation

/// README.txt и report.pdf — производные документы; их можно перегенерировать в любой момент.
enum PackageDocuments {
    static func write(for item: EvidenceItem) async {
        var readme = Data([0xEF, 0xBB, 0xBF]) // BOM — чтобы Блокнот Windows открыл кириллицу правильно
        readme.append(Data(ReadmeBuilder.text(for: item).replacingOccurrences(of: "\n", with: "\r\n").utf8))
        try? readme.write(to: item.folder.appendingPathComponent(EvidenceFiles.readme), options: .atomic)

        let pdf = await Task.detached(priority: .utility) { ReportBuilder.build(for: item) }.value
        try? pdf.write(to: item.reportURL, options: .atomic)
    }
}

enum PackageExporter {
    /// ZIP средствами iOS (NSFileCoordinator .forUploading) — без сторонних библиотек.
    static func zip(folder: URL) throws -> URL {
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("PhotoProof_" + folder.lastPathComponent + ".zip")
        try? FileManager.default.removeItem(at: destination)
        var coordinatorError: NSError?
        var copyError: Error?
        NSFileCoordinator().coordinate(readingItemAt: folder, options: [.forUploading], error: &coordinatorError) { zipURL in
            do {
                try FileManager.default.copyItem(at: zipURL, to: destination)
            } catch {
                copyError = error
            }
        }
        if let coordinatorError { throw coordinatorError }
        if let copyError { throw copyError }
        return destination
    }
}

enum ReadmeBuilder {
    static func text(for item: EvidenceItem) -> String {
        let m = item.manifest
        let tz = item.timeZone
        var s = ""
        s += "ПАКЕТ ФОТОФИКСАЦИИ № \(item.id)\n"
        s += "Сформирован приложением «\(m.application.name)» \(m.application.version) (iPhone).\n\n"

        s += "Снимок сделан: \(Fmt.dateTime(item.captureDate, timeZone: tz)) (\(Fmt.utcOffset(tz, at: item.captureDate)), \(m.capture.timeZone)) по часам устройства.\n"
        for t in m.timestamps {
            s += "Метка доверенного времени на снимок: \(t.tsaName) — \(t.genTimeUTC)\n"
        }
        for t in item.manifestTimestamps {
            s += "Метка доверенного времени на паспорт: \(t.tsaName) — \(Fmt.isoUTC(t.genTime))\n"
        }
        if let c = m.clockCheck {
            s += c.deviceClockWithinTolerance
                ? "Часы устройства сверены с эталоном (\(c.reference)): расхождение в пределах ±\(Int(c.toleranceSeconds)) с.\n"
                : "Часы устройства отличались от эталона (\(c.reference)) на \(Fmt.signedSeconds(c.typicalOffset)); в штампе указано эталонное время.\n"
        }
        if let p = m.place {
            s += "Место: \(Fmt.coordinate(latitude: p.latitude, longitude: p.longitude)), точность ±\(Fmt.meters(p.horizontalAccuracyMeters))"
            if let a = p.address { s += "; адрес (справочно): \(a)" }
            s += "\n"
        } else {
            s += "Место: геопозиция не определена.\n"
        }
        s += "Устройство: \(m.hardware.model), \(m.hardware.systemName) \(m.hardware.systemVersion).\n\n"

        s += """
        СОСТАВ ПАКЕТА
          1_original.jpg ............. исходный снимок в том виде, в каком его выдала камера (не изменялся)
          2_stamped.jpg .............. копия снимка со штампом даты, времени и места (штамп под кадром)
          manifest.json .............. «паспорт» снимка: время, координаты, устройство, SHA-256 всех файлов
          manifest.sig ............... электронная подпись паспорта (ECDSA P-256 / SHA-256)
          device_public_key.pem ...... открытый ключ устройства для проверки подписи
          tsa/original_*.tsr ......... метки доверенного времени RFC 3161 на исходный снимок
          tsa/manifest_*.tsr ......... метки доверенного времени RFC 3161 на паспорт
          appattest_attestation.cbor   аттестация ключа сервисом Apple App Attest (если есть)
          appattest_challenge.txt .... данные, на которые выдана аттестация
          manifest.appattest-assertion.cbor  подпись паспорта аттестованным ключом App Attest
          report.pdf ................. акт фотофиксации для печати (производный документ)
          README.txt ................. этот файл


        """

        s += "КОНТРОЛЬНЫЕ СУММЫ SHA-256\n"
        for f in m.files {
            s += "  \(f.name)\n    \(f.sha256)\n"
        }
        s += "  manifest.json\n    \(item.manifestSha256)\n\n"

        let manifestToken = item.manifestTimestamps.first?.file ?? "tsa/manifest_FreeTSA.tsr"
        let originalToken = m.timestamps.first?.file ?? "tsa/original_FreeTSA.tsr"

        s += """
        ЧТО ДОКАЗЫВАЕТ ПАКЕТ
          1. Целостность. SHA-256 каждого файла записан в manifest.json, а паспорт подписан ключом,
             созданным в защищенном чипе Secure Enclave этого iPhone (ключ не может быть извлечен).
             Любое изменение снимка или паспорта обнаруживается.
          2. Время. Независимые службы штампов времени (RFC 3161) подписали хеш исходного снимка
             и хеш паспорта. Это доказывает, что файлы существовали в неизменном виде не позднее
             указанного в метке момента. Часы телефона сверены с эталоном (clockCheck в manifest.json).
          3. Происхождение. Приложение не умеет загружать готовые изображения — только снимать
             камерой. Аттестация Apple App Attest подтверждает, что паспорт подписан оригинальным
             приложением на настоящем устройстве Apple.
          4. Последовательность. Каждая съемка записывается в журнал устройства с цепочкой хешей
             (journal в manifest.json); удаление или подмена снимков задним числом обнаруживаются
             при осмотре телефона.

        КАК ПРОВЕРИТЬ (ДЛЯ ЭКСПЕРТА)
          Шаг 1. Контрольные суммы
            Windows:      certutil -hashfile 1_original.jpg SHA256
            macOS/Linux:  shasum -a 256 1_original.jpg
            Результат должен совпасть со значением в manifest.json (files -> sha256).

          Шаг 2. Подпись паспорта
            openssl dgst -sha256 -verify device_public_key.pem -signature manifest.sig manifest.json
            Ожидаемый результат: Verified OK

          Шаг 3. Метки доверенного времени
            openssl ts -reply -in \(manifestToken) -text
            openssl ts -verify -data manifest.json -in \(manifestToken) -CAfile <корневой сертификат службы>
            openssl ts -verify -data 1_original.jpg -in \(originalToken) -CAfile <корневой сертификат службы>
            Ожидаемый результат: Verification: OK
            Корневые сертификаты:
              FreeTSA — https://freetsa.org/files/cacert.pem
              DigiCert, Sectigo — стандартный набор корневых сертификатов, например
                "C:\\Program Files\\Git\\mingw64\\etc\\ssl\\certs\\ca-bundle.crt" (Windows, Git for Windows),
                /etc/ssl/certs/ca-certificates.crt (Linux), /etc/ssl/cert.pem (macOS).
            OpenSSL для Windows входит в состав Git for Windows: "C:\\Program Files\\Git\\usr\\bin\\openssl.exe".

          Шаг 4. Аттестация App Attest и комплексная проверка всего пакета
            python verify.py <этот ZIP или папка> --tsa-ca cacert.pem --apple-root Apple_App_Attestation_Root_CA.pem
            (cacert.pem — корневой сертификат FreeTSA; корни DigiCert и Sectigo скрипт находит сам)
            Скрипт verify.py поставляется с исходным кодом приложения.
            Корневой сертификат Apple: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem

        ВАЖНО
          Не открывайте файлы в редакторах и не пересохраняйте их — это изменит контрольные суммы.
          Для просмотра делайте копию. Доказательственное значение имеют файлы пакета;
          report.pdf — их удобочитаемое отображение.

        """
        return s
    }
}
