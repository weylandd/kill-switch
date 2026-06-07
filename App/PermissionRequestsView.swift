import SwiftUI
import KillSwitchShared

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
