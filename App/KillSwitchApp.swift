import SwiftUI
import AppKit
import KillSwitchShared

/// The menu-bar app: a thin remote control over the privileged daemon. The icon reflects the
/// protection state (and a pending approval request); the window holds the controls.
@main
struct KillSwitchApp: App {
    @StateObject private var controller = MenuBarController()

    var body: some Scene {
        MenuBarExtra {
            ControlPanelView(controller: controller)
        } label: {
            Image(systemName: controller.menuBarSymbol)
        }
        .menuBarExtraStyle(.window)
    }
}

/// The popover content. Routes between first-run setup, the unreachable state, and the normal
/// controls, but always shows the status header so the user is never left guessing.
struct ControlPanelView: View {
    @ObservedObject var controller: MenuBarController

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("KillSwitch").font(.title3).bold()
            StatusHeader(state: controller.state)

            Divider()

            switch controller.state {
            case .needsApproval:
                setupSection
            case .daemonUnreachable:
                unreachableSection
            default:
                controlsSection
            }

            Divider()
            Button("Выйти") { NSApplication.shared.terminate(nil) }
        }
        .padding(14)
        .frame(width: 360)
    }

    // First run: the daemon isn't approved yet.
    private var setupSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Чтобы защита заработала, включите KillSwitch в Системных настройках → «Объекты входа и расширения».")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Button("Установить / проверить защиту") { controller.register() }
            Button("Открыть Системные настройки") { controller.openSettings() }
        }
    }

    // Daemon approved but not answering.
    private var unreachableSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Не удаётся связаться со службой защиты. Защита может ещё работать, но управлять ей сейчас нельзя.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Button("Повторить") { Task { await controller.refresh() } }
            Button("Открыть Системные настройки") { controller.openSettings() }
        }
    }

    // Normal controls.
    private var controlsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Toggle("Защита включена", isOn: Binding(
                get: { controller.status?.protectionEnabled ?? false },
                set: { controller.setProtection($0) }))
                .toggleStyle(.switch)

            Toggle("Доступ к локальной сети", isOn: Binding(
                get: { controller.status?.lanAllowed ?? false },
                set: { controller.setLAN($0) }))
                .toggleStyle(.switch)

            Divider()
            PermissionRequestsView(candidates: controller.candidates, onAllow: controller.allow)

            Divider()
            ServersListView(servers: controller.servers,
                            manualAddress: $controller.manualAddress,
                            manualError: controller.manualError,
                            onAdd: controller.addManual,
                            onRemove: controller.remove)

            if let lastError = controller.lastError {
                Text(lastError).font(.caption).foregroundStyle(.red)
            }
        }
    }
}
