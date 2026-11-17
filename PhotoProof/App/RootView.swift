import SwiftUI

enum Route: Hashable {
    case archive
    case about
    case evidence(String)
}

struct RootView: View {
    @EnvironmentObject private var camera: CameraController
    @EnvironmentObject private var location: LocationProvider
    @State private var path = NavigationPath()

    var body: some View {
        NavigationStack(path: $path) {
            CameraScreen(path: $path)
                .navigationDestination(for: Route.self) { route in
                    switch route {
                    case .archive: EvidenceListView()
                    case .about: AboutView()
                    case .evidence(let id): EvidenceDetailView(evidenceId: id)
                    }
                }
        }
        .onAppear {
            camera.start()
            location.start()
        }
    }
}
