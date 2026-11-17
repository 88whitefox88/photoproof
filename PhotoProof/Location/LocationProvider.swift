import CoreLocation
import Foundation

/// Снимок геопозиции в момент съемки (значимый тип — безопасно передается между потоками).
struct LocationSnapshot: Sendable {
    let latitude: Double
    let longitude: Double
    let horizontalAccuracy: Double
    let altitude: Double?
    let verticalAccuracy: Double?
    let speed: Double?
    let course: Double?
    let timestamp: Date
    /// iOS сообщает, если координаты подменены программно (эмулятор GPS, отладчик).
    let isSimulated: Bool?
    let isFromAccessory: Bool?
    let precise: Bool

    init(_ location: CLLocation, precise: Bool) {
        latitude = location.coordinate.latitude
        longitude = location.coordinate.longitude
        horizontalAccuracy = location.horizontalAccuracy
        altitude = location.verticalAccuracy >= 0 ? location.altitude : nil
        verticalAccuracy = location.verticalAccuracy >= 0 ? location.verticalAccuracy : nil
        speed = location.speed >= 0 ? location.speed : nil
        course = location.course >= 0 ? location.course : nil
        timestamp = location.timestamp
        isSimulated = location.sourceInformation?.isSimulatedBySoftware
        isFromAccessory = location.sourceInformation?.isProducedByAccessory
        self.precise = precise
    }
}

@MainActor
final class LocationProvider: NSObject, ObservableObject {
    @Published private(set) var location: CLLocation?
    @Published private(set) var address: String?
    @Published private(set) var authorization: CLAuthorizationStatus = .notDetermined
    @Published private(set) var isReducedAccuracy = false

    private let manager = CLLocationManager()
    private let geocoder = CLGeocoder()
    private var lastGeocoded: CLLocation?
    private var requestedFullAccuracy = false

    override init() {
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyBest
        manager.distanceFilter = kCLDistanceFilterNone
        authorization = manager.authorizationStatus
    }

    func start() {
        switch manager.authorizationStatus {
        case .notDetermined:
            manager.requestWhenInUseAuthorization()
        case .authorizedWhenInUse, .authorizedAlways:
            beginUpdates()
        default:
            break
        }
        authorization = manager.authorizationStatus
    }

    func stop() {
        manager.stopUpdatingLocation()
    }

    /// Геопозиция, полученная не раньше чем `maxAge` секунд назад.
    func freshLocation(maxAge: TimeInterval) -> CLLocation? {
        guard let location, location.horizontalAccuracy >= 0,
              -location.timestamp.timeIntervalSinceNow <= maxAge else { return nil }
        return location
    }

    private func beginUpdates() {
        isReducedAccuracy = manager.accuracyAuthorization == .reducedAccuracy
        if isReducedAccuracy && !requestedFullAccuracy {
            requestedFullAccuracy = true
            manager.requestTemporaryFullAccuracyAuthorization(withPurposeKey: "EvidenceCapture")
        }
        manager.startUpdatingLocation()
    }

    fileprivate func handle(_ newLocation: CLLocation) {
        location = newLocation
        isReducedAccuracy = manager.accuracyAuthorization == .reducedAccuracy
        geocodeIfNeeded(newLocation)
    }

    fileprivate func handleAuthorizationChange() {
        authorization = manager.authorizationStatus
        if authorization == .authorizedWhenInUse || authorization == .authorizedAlways {
            beginUpdates()
        }
    }

    private func geocodeIfNeeded(_ location: CLLocation) {
        if let last = lastGeocoded, last.distance(from: location) < 25 { return }
        guard !geocoder.isGeocoding, location.horizontalAccuracy >= 0, location.horizontalAccuracy < 200 else { return }
        lastGeocoded = location
        geocoder.reverseGeocodeLocation(location, preferredLocale: Locale(identifier: "ru_RU")) { [weak self] placemarks, _ in
            let text = placemarks?.first.map { LocationProvider.describe($0) }
            Task { @MainActor in self?.address = text }
        }
    }

    nonisolated static func describe(_ placemark: CLPlacemark) -> String {
        var parts: [String] = []
        if let city = placemark.locality ?? placemark.subAdministrativeArea ?? placemark.administrativeArea {
            parts.append(city)
        }
        if let street = placemark.thoroughfare {
            parts.append(placemark.subThoroughfare.map { "\(street), \($0)" } ?? street)
        } else if let name = placemark.name {
            parts.append(name)
        }
        return parts.joined(separator: ", ")
    }
}

extension LocationProvider: CLLocationManagerDelegate {
    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let last = locations.last else { return }
        Task { @MainActor in self.handle(last) }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor in self.handleAuthorizationChange() }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {}
}
