import SwiftUI
import KillSwitchShared

/// The allowed-servers whitelist with per-row removal, plus the manual-address fallback (R12).
struct ServersListView: View {
    let servers: [ServerRule]
    @Binding var manualAddress: String
    let manualError: String?
    let onAdd: () -> Void
    let onRemove: (ServerRule) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Разрешённые серверы").font(.subheadline).bold()

            if servers.isEmpty {
                Text("Пока нет разрешённых серверов.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                ForEach(servers) { server in
                    HStack {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(server.label).font(.callout)
                            Text(server.effectiveOrigin == .auto ? "\(server.address) · добавлен автоматически"
                                                                 : server.address)
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(role: .destructive) { onRemove(server) } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                        .help("Удалить сервер")
                    }
                }
            }

            HStack {
                TextField("Адрес сервера (например 89.106.86.61)", text: $manualAddress)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(onAdd)
                Button("Добавить", action: onAdd)
            }
            if let manualError {
                Text(manualError).font(.caption).foregroundStyle(.red)
            }
        }
    }
}
