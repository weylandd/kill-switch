import SwiftUI
import AppKit
import KillSwitchShared

/// Identifiers for the app's auxiliary windows (opened via `openWindow`).
enum AppWindow {
    static let requests = "permission-requests"
}

/// Compact entry in the control panel: opens the connection-requests window and shows how many
/// requests are waiting, so the list no longer crowds the main panel.
struct PermissionRequestsButton: View {
    @ObservedObject var controller: MenuBarController
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button {
            openWindow(id: AppWindow.requests)
            // This is an LSUIElement (menu-bar-only) app, so a freshly opened window does not come
            // forward on its own — activate the app to bring it to the front.
            NSApp.activate(ignoringOtherApps: true)
        } label: {
            HStack {
                Label("Запросы на подключение", systemImage: "bell.badge")
                Spacer()
                if !controller.candidates.isEmpty {
                    Text("\(controller.candidates.count)")
                        .font(.caption2).bold()
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Capsule().fill(Color.accentColor))
                        .foregroundStyle(.white)
                }
            }
        }
    }
}

/// The connection-requests list shown in its own window (separate from the control panel).
struct PermissionRequestsWindow: View {
    @ObservedObject var controller: MenuBarController

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Запросы на подключение").font(.title3).bold()
            Text("Когда VPN-клиент пытается выйти на новый сервер напрямую, он появляется здесь. Разрешите свой сервер — остальное останется заблокированным.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Divider()
            PermissionRequestsView(candidates: controller.candidates, onAllow: controller.allow)
            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(width: 380, height: 340)
    }
}

/// "Запрос на разрешение" — the candidate servers a VPN client tried to reach directly. One tap
/// allows an IPv4 candidate (R22, R23); IPv6 candidates are shown but can't be allowed.
struct PermissionRequestsView: View {
    let candidates: [Candidate]
    let onAllow: (Candidate) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Запрос на разрешение").font(.subheadline).bold()

            if candidates.isEmpty {
                // Never a blank area — explain why it's empty (R-UX).
                Text("Новых подключений нет. Когда VPN-клиент попробует выйти на новый сервер, он появится здесь.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(candidates) { candidate in
                    HStack(alignment: .firstTextBaseline) {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(candidate.displayLabel).font(.callout)
                            if let note = candidate.diagnosticNote {
                                Text(note).font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        if candidate.canAllow {
                            Button("Разрешить") { onAllow(candidate) }
                        } else {
                            Text("IPv6").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }
}
