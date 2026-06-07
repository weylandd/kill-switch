import SwiftUI
import AppKit
import KillSwitchShared

/// Приложение в строке меню. Этап A / U4 — минимальный пульт: установка/проверка
/// демона через SMAppService и путь к Системным настройкам. Полный пульт (статус,
/// переключатели, «Запрос на разрешение») — в U7–U8.
@main
struct KillSwitchApp: App {
    var body: some Scene {
        MenuBarExtra("KillSwitch", systemImage: "shield") {
            MenuContentView()
        }
        .menuBarExtraStyle(.window)
    }
}

struct MenuContentView: View {
    @State private var statusText = "Проверяется…"

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("KillSwitch").font(.headline)
            Text("Статус защиты: \(statusText)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Divider()

            Button("Установить / проверить защиту", action: install)
            Button("Открыть «Объекты входа» в Системных настройках", action: openSettings)

            Divider()

            Button("Выйти") { NSApplication.shared.terminate(nil) }
        }
        .padding(12)
        .frame(width: 340)
        .onAppear(perform: refreshStatus)
    }

    private func refreshStatus() {
        if #available(macOS 13.0, *) {
            statusText = DaemonRegistration.statusDescription
        } else {
            statusText = "требуется macOS 13 или новее"
        }
    }

    private func install() {
        guard #available(macOS 13.0, *) else { return }
        switch DaemonRegistration.register() {
        case .registered:
            statusText = "установлена и активна"
        case .requiresApproval:
            statusText = "требуется одобрение → Системные настройки → «Объекты входа и расширения»"
        case .failed(let message):
            statusText = "не удалось установить: \(message)"
        }
    }

    private func openSettings() {
        if #available(macOS 13.0, *) {
            DaemonRegistration.openLoginItemsSettings()
        }
    }
}
