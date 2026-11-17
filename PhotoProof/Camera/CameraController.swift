import AVFoundation
import ImageIO
import UIKit

enum CameraError: LocalizedError {
    case notRunning
    case noData

    var errorDescription: String? {
        switch self {
        case .notRunning: return "Камера не запущена."
        case .noData: return "Камера не вернула изображение."
        }
    }
}

/// Съемка только с живой камеры. Импорт готовых изображений в приложении отсутствует намеренно.
final class CameraController: NSObject, ObservableObject {
    enum Status: Equatable {
        case starting
        case running
        case denied
        case failed(String)
    }

    @Published private(set) var status: Status = .starting
    @Published private(set) var hasFlash = false
    @Published var flashOn = false

    let session = AVCaptureSession()
    private let output = AVCapturePhotoOutput()
    private let queue = DispatchQueue(label: "photoproof.camera.session")
    private var isConfigured = false
    private var inFlight: [Int64: PhotoCaptureDelegate] = [:]

    func start() {
        Task {
            guard await Self.requestAccess() else {
                await MainActor.run { self.status = .denied }
                return
            }
            queue.async { [weak self] in self?.startOnQueue() }
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self, self.session.isRunning else { return }
            self.session.stopRunning()
            DispatchQueue.main.async {
                if self.status == .running { self.status = .starting }
            }
        }
    }

    static func requestAccess() async -> Bool {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: return true
        case .notDetermined: return await AVCaptureDevice.requestAccess(for: .video)
        default: return false
        }
    }

    private func startOnQueue() {
        if !isConfigured { configure() }
        guard isConfigured else { return }
        if !session.isRunning { session.startRunning() }
        let running = session.isRunning
        DispatchQueue.main.async {
            self.status = running ? .running : .failed("Не удалось запустить камеру.")
        }
    }

    private func configure() {
        session.beginConfiguration()
        session.sessionPreset = .photo
        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input),
              session.canAddOutput(output) else {
            session.commitConfiguration()
            DispatchQueue.main.async { self.status = .failed("Не удалось подключиться к основной камере.") }
            return
        }
        session.addInput(input)
        session.addOutput(output)
        output.maxPhotoQualityPrioritization = .quality
        session.commitConfiguration()
        isConfigured = true
        let flash = device.hasFlash
        DispatchQueue.main.async { self.hasFlash = flash }
    }

    /// Возвращает JPEG ровно в том виде, в каком его выдал конвейер камеры (это и есть «оригинал»).
    func capturePhoto(flash: Bool, orientation: AVCaptureVideoOrientation, gps: [String: Any]?) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            queue.async { [self] in
                guard isConfigured, session.isRunning else {
                    continuation.resume(throwing: CameraError.notRunning)
                    return
                }
                let settings: AVCapturePhotoSettings
                if output.availablePhotoCodecTypes.contains(.jpeg) {
                    settings = AVCapturePhotoSettings(format: [AVVideoCodecKey: AVVideoCodecType.jpeg])
                } else {
                    settings = AVCapturePhotoSettings()
                }
                let mode: AVCaptureDevice.FlashMode = flash ? .on : .off
                if output.supportedFlashModes.contains(mode) { settings.flashMode = mode }
                settings.photoQualityPrioritization = .quality
                if let gps { settings.metadata = [kCGImagePropertyGPSDictionary as String: gps] }
                if let connection = output.connection(with: .video), connection.isVideoOrientationSupported {
                    connection.videoOrientation = orientation
                }
                let id = settings.uniqueID
                let delegate = PhotoCaptureDelegate { [weak self] result in
                    self?.queue.async { self?.inFlight[id] = nil }
                    continuation.resume(with: result)
                }
                inFlight[id] = delegate
                output.capturePhoto(with: settings, delegate: delegate)
            }
        }
    }

    @MainActor private static var lastOrientation: AVCaptureVideoOrientation = .portrait

    /// Ориентация снимка по положению телефона (интерфейс зафиксирован в портретной ориентации).
    @MainActor static func currentOrientation() -> AVCaptureVideoOrientation {
        switch UIDevice.current.orientation {
        case .portrait: lastOrientation = .portrait
        case .portraitUpsideDown: lastOrientation = .portraitUpsideDown
        case .landscapeLeft: lastOrientation = .landscapeRight
        case .landscapeRight: lastOrientation = .landscapeLeft
        default: break
        }
        return lastOrientation
    }
}

private final class PhotoCaptureDelegate: NSObject, AVCapturePhotoCaptureDelegate {
    private let completion: (Result<Data, Error>) -> Void
    private var result: Result<Data, Error>?

    init(completion: @escaping (Result<Data, Error>) -> Void) {
        self.completion = completion
    }

    func photoOutput(_ output: AVCapturePhotoOutput, didFinishProcessingPhoto photo: AVCapturePhoto, error: Error?) {
        if let error {
            result = .failure(error)
        } else if let data = photo.fileDataRepresentation() {
            result = .success(data)
        } else {
            result = .failure(CameraError.noData)
        }
    }

    func photoOutput(_ output: AVCapturePhotoOutput,
                     didFinishCaptureFor resolvedSettings: AVCaptureResolvedPhotoSettings,
                     error: Error?) {
        if let error, result == nil { result = .failure(error) }
        completion(result ?? .failure(CameraError.noData))
    }
}
