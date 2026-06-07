import SwiftUI
import AppKit
import KillSwitchShared

/// Приложение в строке меню. Этап A / U1 — пока только каркас:
/// иконка-щит и заглушка-меню. Реальный пульт (статус, переключатели,
/// «Запрос на разрешение») приходит в U7–U8.
@main
struct KillSwitchApp: App {
    var body: some Scene {
        MenuBarExtra("KillSwitch", systemImage: "shield") {
            Text("KillSwitch — каркас (этап A)")
            Text("Демон: \(KillSwitchConfig.daemonLabel)")
                .font(.caption)
                .foregroundStyle(.secondary)
            Divider()
            Button("Выйти") { NSApplication.shared.terminate(nil) }
        }
        .menuBarExtraStyle(.window)
    }
}
