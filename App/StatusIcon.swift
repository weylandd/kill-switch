import SwiftUI
import KillSwitchShared

/// Panel header: the state icon, title, and one-line explanation. The exposed state is shown in
/// red with an alert shape so "real IP is open" can't be missed (R14).
struct StatusHeader: View {
    let state: ProtectionState

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: state.iconSymbolName)
                .font(.system(size: 24))
                .foregroundStyle(state.tintColor)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(state.title)
                    .font(.headline)
                    .foregroundStyle(state.isExposed ? Color.red : Color.primary)
                Text(state.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
    }
}

extension ProtectionState {
    /// Icon tint per state. Shape already distinguishes states; color reinforces it (R14/R24).
    var tintColor: Color {
        switch self {
        case .protectedTunnelUp:   return .green
        case .protectedTunnelDown: return .blue
        case .disarmed:            return .red
        case .needsApproval:       return .orange
        case .daemonUnreachable:   return .gray
        }
    }
}
