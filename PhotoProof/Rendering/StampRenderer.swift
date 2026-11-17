import CoreImage
import CoreImage.CIFilterBuiltins
import ImageIO
import UIKit

struct StampLine: Sendable {
    enum Style: Sendable { case headline, normal, warning, small }
    let text: String
    let style: Style
}

/// Текст штампа. Если часы телефона расходятся с эталоном — в штамп идет эталонное время
/// с пометкой; если эталон недоступен — время телефона с явным предупреждением.
enum StampComposer {
    static func lines(evidenceId: String,
                      captureDate: Date,
                      timeZone: TimeZone,
                      clock: EvidenceManifest.ClockCheck?,
                      tokens: [TimestampToken],
                      place: LocationSnapshot?,
                      address: String?,
                      originalSHA256: String) -> [StampLine] {
        var lines: [StampLine] = []
        let offset = Fmt.utcOffset(timeZone, at: captureDate)

        if let clock, !tokens.isEmpty {
            let names = tokens.map(\.server.name).joined(separator: ", ")
            if clock.deviceClockWithinTolerance {
                lines.append(.init(text: "\(Fmt.dateTime(captureDate, timeZone: timeZone))  \(offset)", style: .headline))
                lines.append(.init(text: "Время подтверждено: \(names) (RFC 3161)", style: .normal))
            } else {
                let reference = clock.estimatedCaptureDate ?? captureDate
                lines.append(.init(text: "\(Fmt.dateTime(reference, timeZone: timeZone))  \(offset)", style: .headline))
                lines.append(.init(text: "Время по эталону \(names); часы телефона: \(Fmt.signedSeconds(clock.typicalOffset))",
                                   style: .warning))
            }
        } else {
            lines.append(.init(text: "\(Fmt.dateTime(captureDate, timeZone: timeZone))  \(offset)", style: .headline))
            lines.append(.init(text: "Время по часам телефона — эталон недоступен (нет сети)", style: .warning))
        }

        if let place {
            lines.append(.init(text: "\(Fmt.coordinate(latitude: place.latitude, longitude: place.longitude))  ±\(Fmt.meters(place.horizontalAccuracy))",
                               style: .normal))
            if place.isSimulated == true {
                lines.append(.init(text: "ВНИМАНИЕ: координаты подменены программно", style: .warning))
            } else if !place.precise {
                lines.append(.init(text: "Приблизительная геопозиция (точная запрещена в настройках)", style: .warning))
            }
            if let address, !address.isEmpty {
                lines.append(.init(text: address, style: .normal))
            }
        } else {
            lines.append(.init(text: "Геопозиция не определена", style: .warning))
        }

        lines.append(.init(text: "№ \(evidenceId) · SHA-256 \(originalSHA256.prefix(16))… · \(AppInfoProvider.displayName)",
                           style: .small))
        return lines
    }
}

/// EXIF/TIFF/GPS для копии со штампом. Только ASCII — так поля читаются любыми программами.
struct StampedImageMetadata: Sendable {
    let captureDate: Date
    let timeZone: TimeZone
    let place: LocationSnapshot?
    let evidenceId: String
    let originalSHA256: String

    func properties() -> [String: Any] {
        let exifDate = Fmt.pattern("yyyy:MM:dd HH:mm:ss", captureDate, timeZone)
        let exif: [String: Any] = [
            kCGImagePropertyExifDateTimeOriginal as String: exifDate,
            kCGImagePropertyExifDateTimeDigitized as String: exifDate,
            kCGImagePropertyExifOffsetTimeOriginal as String: Fmt.offsetHHMM(timeZone.secondsFromGMT(for: captureDate)),
            kCGImagePropertyExifUserComment as String: "PhotoProof evidence \(evidenceId); original SHA-256 \(originalSHA256)",
        ]
        let tiff: [String: Any] = [
            kCGImagePropertyTIFFMake as String: "Apple",
            kCGImagePropertyTIFFModel as String: DeviceInfo.modelIdentifier,
            kCGImagePropertyTIFFSoftware as String: "PhotoProof \(AppInfoProvider.version)",
            kCGImagePropertyTIFFDateTime as String: exifDate,
            kCGImagePropertyTIFFImageDescription as String: "Stamped copy of evidence \(evidenceId). Original SHA-256: \(originalSHA256)",
        ]
        var properties: [String: Any] = [
            kCGImagePropertyExifDictionary as String: exif,
            kCGImagePropertyTIFFDictionary as String: tiff,
        ]
        if let place { properties[kCGImagePropertyGPSDictionary as String] = ImageMetadata.gps(place) }
        return properties
    }
}

enum ImageMetadata {
    static func gps(_ place: LocationSnapshot) -> [String: Any] {
        let utc = TimeZone(identifier: "UTC")!
        var gps: [String: Any] = [
            kCGImagePropertyGPSLatitude as String: abs(place.latitude),
            kCGImagePropertyGPSLatitudeRef as String: place.latitude >= 0 ? "N" : "S",
            kCGImagePropertyGPSLongitude as String: abs(place.longitude),
            kCGImagePropertyGPSLongitudeRef as String: place.longitude >= 0 ? "E" : "W",
            kCGImagePropertyGPSHPositioningError as String: place.horizontalAccuracy,
            kCGImagePropertyGPSTimeStamp as String: Fmt.pattern("HH:mm:ss.SS", place.timestamp, utc),
            kCGImagePropertyGPSDateStamp as String: Fmt.pattern("yyyy:MM:dd", place.timestamp, utc),
        ]
        if let altitude = place.altitude {
            gps[kCGImagePropertyGPSAltitude as String] = abs(altitude)
            gps[kCGImagePropertyGPSAltitudeRef as String] = altitude < 0 ? 1 : 0
        }
        return gps
    }
}

struct RenderedImages: Sendable {
    let stampedJPEG: Data
    let thumbnailJPEG: Data?
    let originalWidth: Int
    let originalHeight: Int
}

enum StampError: LocalizedError {
    case decode, encode
    var errorDescription: String? {
        switch self {
        case .decode: return "Не удалось прочитать снимок."
        case .encode: return "Не удалось сохранить копию со штампом."
        }
    }
}

enum StampRenderer {
    static func renderPackageImages(originalData: Data,
                                    lines: [StampLine],
                                    qrPayload: String,
                                    metadata: StampedImageMetadata) throws -> RenderedImages {
        guard let original = UIImage(data: originalData) else { throw StampError.decode }
        let stamped = render(original, lines: lines, qrPayload: qrPayload)
        guard let jpeg = jpegData(stamped, properties: metadata.properties()) else { throw StampError.encode }
        let thumbWidth: CGFloat = 360
        let thumbSize = CGSize(width: thumbWidth,
                               height: (thumbWidth * stamped.size.height / max(stamped.size.width, 1)).rounded())
        let thumbnail = stamped.preparingThumbnail(of: thumbSize)?.jpegData(compressionQuality: 0.75)
        return RenderedImages(stampedJPEG: jpeg,
                              thumbnailJPEG: thumbnail,
                              originalWidth: Int(original.size.width * original.scale),
                              originalHeight: Int(original.size.height * original.scale))
    }

    /// Холст = снимок целиком + полоса штампа ПОД ним. Ни один пиксель сцены не перекрывается.
    static func render(_ image: UIImage, lines: [StampLine], qrPayload: String) -> UIImage {
        let photoSize = CGSize(width: image.size.width * image.scale, height: image.size.height * image.scale)
        let unit = min(photoSize.width, photoSize.height) / 100
        let padding = unit * 2
        let headlineFont = UIFont.monospacedDigitSystemFont(ofSize: unit * 3.0, weight: .bold)
        let bodyFont = UIFont.monospacedDigitSystemFont(ofSize: unit * 2.2, weight: .medium)
        let smallFont = UIFont.monospacedSystemFont(ofSize: unit * 1.7, weight: .regular)

        let qrSide = (unit * 13).rounded()
        let textWidth = photoSize.width - qrSide - padding * 3
        let text = attributed(lines, headline: headlineFont, body: bodyFont, small: smallFont)
        let textHeight = ceil(text.boundingRect(with: CGSize(width: textWidth, height: .greatestFiniteMagnitude),
                                                options: [.usesLineFragmentOrigin, .usesFontLeading],
                                                context: nil).height)
        let bandHeight = (max(textHeight, qrSide) + padding * 2).rounded()
        let canvas = CGSize(width: photoSize.width, height: photoSize.height + bandHeight)

        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        format.opaque = true
        format.preferredRange = .standard
        let renderer = UIGraphicsImageRenderer(size: canvas, format: format)
        return renderer.image { context in
            image.draw(in: CGRect(origin: .zero, size: photoSize))

            let band = CGRect(x: 0, y: photoSize.height, width: canvas.width, height: bandHeight)
            UIColor(red: 0.07, green: 0.08, blue: 0.10, alpha: 1).setFill()
            context.fill(band)

            text.draw(with: CGRect(x: padding, y: band.minY + (bandHeight - textHeight) / 2,
                                   width: textWidth, height: textHeight),
                      options: [.usesLineFragmentOrigin, .usesFontLeading], context: nil)

            if let qr = qrImage(qrPayload, side: qrSide) {
                let qrRect = CGRect(x: canvas.width - padding - qrSide,
                                    y: band.minY + (bandHeight - qrSide) / 2,
                                    width: qrSide, height: qrSide)
                UIColor.white.setFill()
                context.fill(qrRect.insetBy(dx: -unit * 0.6, dy: -unit * 0.6))
                context.cgContext.interpolationQuality = .none
                qr.draw(in: qrRect)
            }
        }
    }

    private static func attributed(_ lines: [StampLine], headline: UIFont, body: UIFont, small: UIFont) -> NSAttributedString {
        let result = NSMutableAttributedString()
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineBreakMode = .byWordWrapping
        paragraph.paragraphSpacing = body.pointSize * 0.3
        let warning = UIColor(red: 1.0, green: 0.84, blue: 0.04, alpha: 1)
        for (index, line) in lines.enumerated() {
            let font: UIFont
            let color: UIColor
            switch line.style {
            case .headline: font = headline; color = .white
            case .normal: font = body; color = .white
            case .warning: font = body; color = warning
            case .small: font = small; color = UIColor(white: 0.75, alpha: 1)
            }
            let text = index == lines.count - 1 ? line.text : line.text + "\n"
            result.append(NSAttributedString(string: text, attributes: [
                .font: font, .foregroundColor: color, .paragraphStyle: paragraph,
            ]))
        }
        return result
    }

    private static func qrImage(_ payload: String, side: CGFloat) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scale = max(1, floor(side / output.extent.width))
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        guard let cgImage = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }

    static func jpegData(_ image: UIImage, properties: [String: Any], quality: CGFloat = 0.9) -> Data? {
        guard let cgImage = image.cgImage else { return nil }
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(data as CFMutableData, "public.jpeg" as CFString, 1, nil) else {
            return nil
        }
        var props = properties
        props[kCGImageDestinationLossyCompressionQuality as String] = quality
        props[kCGImagePropertyOrientation as String] = 1
        CGImageDestinationAddImage(destination, cgImage, props as CFDictionary)
        guard CGImageDestinationFinalize(destination) else { return nil }
        return data as Data
    }
}

enum ImageLoader {
    /// Уменьшенная копия для экрана/акта — не декодирует 12-мегапиксельный снимок целиком.
    static func downsampled(_ url: URL, maxPixel: Int) -> UIImage? {
        guard let source = CGImageSourceCreateWithURL(url as CFURL, [kCGImageSourceShouldCache: false] as CFDictionary) else {
            return nil
        }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
            kCGImageSourceThumbnailMaxPixelSize: maxPixel,
        ]
        guard let cgImage = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}
