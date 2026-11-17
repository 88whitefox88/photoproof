import SwiftUI
import UIKit

struct CameraScreen: View {
    @Binding var path: NavigationPath
    @EnvironmentObject private var camera: CameraController
    @EnvironmentObject private var store: EvidenceStore
    @EnvironmentObject private var recorder: EvidenceRecorder
    @State private var shutterFlash = false

    private var canShoot: Bool { recorder.phase == .idle && camera.status == .running }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            preview
            VStack(spacing: 0) {
                topBar
                Spacer(minLength: 0)
                bottomBar
            }
            if shutterFlash {
                Color.white.opacity(0.85).ignoresSafeArea().allowsHitTesting(false)
            }
            if recorder.phase != .idle {
                ProcessingOverlay(title: recorder.phase.title)
            }
        }
        .toolbar(.hidden, for: .navigationBar)
        .alert("Фотофиксация не выполнена",
               isPresented: Binding(get: { recorder.errorMessage != nil },
                                    set: { if !$0 { recorder.errorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(recorder.errorMessage ?? "")
        }
        .onAppear { camera.start() }
    }

    @ViewBuilder
    private var preview: some View {
        switch camera.status {
        case .denied:
            PermissionMessage(systemImage: "camera.fill",
                              title: "Нет доступа к камере",
                              message: "Разрешите доступ: Настройки → ФотоДоказ → Камера.",
                              showsSettingsButton: true)
        case .failed(let message):
            PermissionMessage(systemImage: "exclamationmark.triangle.fill",
                              title: "Камера недоступна",
                              message: message,
                              showsSettingsButton: false)
        case .starting, .running:
            CameraPreview(session: camera.session)
        }
    }

    private var topBar: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    Text(Fmt.dateTime(context.date))
                        .font(.system(.headline, design: .monospaced))
                }
                LocationBadge()
            }
            Spacer()
            Button { path.append(Route.about) } label: {
                Image(systemName: "info.circle").font(.title2)
            }
            .accessibilityLabel("О приложении")
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(
            LinearGradient(colors: [.black.opacity(0.75), .clear], startPoint: .top, endPoint: .bottom)
                .ignoresSafeArea(edges: .top)
        )
    }

    private var bottomBar: some View {
        HStack(alignment: .center) {
            lastCaptureButton
                .frame(width: 60, height: 60)
            Spacer()
            shutterButton
            Spacer()
            VStack(spacing: 18) {
                if camera.hasFlash {
                    Button { camera.flashOn.toggle() } label: {
                        Image(systemName: camera.flashOn ? "bolt.fill" : "bolt.slash.fill")
                    }
                    .accessibilityLabel(camera.flashOn ? "Вспышка включена" : "Вспышка выключена")
                }
                Button { path.append(Route.archive) } label: {
                    Image(systemName: "folder.fill")
                }
                .accessibilityLabel("Архив снимков")
            }
            .font(.title2)
            .frame(width: 60)
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 24)
        .padding(.top, 20)
        .padding(.bottom, 12)
        .background(
            LinearGradient(colors: [.clear, .black.opacity(0.8)], startPoint: .top, endPoint: .bottom)
                .ignoresSafeArea(edges: .bottom)
        )
    }

    @ViewBuilder
    private var lastCaptureButton: some View {
        if let item = store.items.first {
            Button { path.append(Route.evidence(item.id)) } label: {
                ThumbnailView(id: item.id)
                    .frame(width: 60, height: 60)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(.white.opacity(0.8), lineWidth: 1.5))
            }
            .accessibilityLabel("Последний снимок")
        } else {
            Color.clear
        }
    }

    private var shutterButton: some View {
        Button(action: shoot) {
            ZStack {
                Circle().strokeBorder(.white, lineWidth: 5).frame(width: 82, height: 82)
                Circle().fill(.white).frame(width: 66, height: 66)
            }
        }
        .disabled(!canShoot)
        .opacity(canShoot ? 1 : 0.45)
        .accessibilityLabel("Сфотографировать")
    }

    private func shoot() {
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        withAnimation(.easeOut(duration: 0.05)) { shutterFlash = true }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.12) {
            withAnimation(.easeIn(duration: 0.2)) { shutterFlash = false }
        }
        Task { await recorder.capture() }
    }
}

struct LocationBadge: View {
    @EnvironmentObject private var location: LocationProvider

    var body: some View {
        let state = badgeState
        Label(state.text, systemImage: state.icon)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(state.color.opacity(0.85), in: Capsule())
    }

    private var badgeState: (text: String, icon: String, color: Color) {
        switch location.authorization {
        case .denied, .restricted:
            return ("Геопозиция запрещена", "location.slash.fill", .red)
        case .notDetermined:
            return ("Нет разрешения на геопозицию", "location", .gray)
        default:
            break
        }
        guard let current = location.location else { return ("Поиск GPS…", "location", .orange) }
        if current.sourceInformation?.isSimulatedBySoftware == true {
            return ("Подмена координат!", "exclamationmark.triangle.fill", .red)
        }
        if location.isReducedAccuracy { return ("Приблизительная геопозиция", "location.circle", .orange) }
        let accuracy = current.horizontalAccuracy
        return ("GPS ±\(Int(accuracy.rounded())) м", "location.fill", accuracy <= 25 ? Color(red: 0.1, green: 0.55, blue: 0.25) : .orange)
    }
}
