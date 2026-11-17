import SwiftUI
import UIKit

@main
struct PhotoProofApp: App {
    @StateObject private var camera: CameraController
    @StateObject private var location: LocationProvider
    @StateObject private var store: EvidenceStore
    @StateObject private var recorder: EvidenceRecorder
    @Environment(\.scenePhase) private var scenePhase

    init() {
        AppPaths.prepare()
        let camera = CameraController()
        let location = LocationProvider()
        let store = EvidenceStore()
        let recorder = EvidenceRecorder(camera: camera, location: location, store: store)
        _camera = StateObject(wrappedValue: camera)
        _location = StateObject(wrappedValue: location)
        _store = StateObject(wrappedValue: store)
        _recorder = StateObject(wrappedValue: recorder)
        UIDevice.current.beginGeneratingDeviceOrientationNotifications()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(camera)
                .environmentObject(location)
                .environmentObject(store)
                .environmentObject(recorder)
                .preferredColorScheme(.dark)
        }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .active:
                camera.start()
                location.start()
                Task {
                    await AppAttestManager.shared.prepare()
                    await store.completePendingTimestamps()
                }
            case .background:
                camera.stop()
                location.stop()
            default:
                break
            }
        }
    }
}
