import Foundation
import SwiftUI
import ServiceManagement
import KillSwitchShared

/// The menu-bar view model. Polls the daemon over XPC for status, candidates, and the server
/// list, and forwards the user's actions back. All UI state lives here so the views stay thin.
@MainActor
final class MenuBarController: ObservableObject {
    @Published var status: DaemonStatus?
    @Published var candidates: [Candidate] = []
    @Published var servers: [ServerRule] = []
    @Published var manualAddress: String = ""
    @Published var manualError: String?
    @Published var lastError: String?

    private let client = XPCClient()
    private var pollTask: Task<Void, Never>?

    // MARK: - Derived presentation

    /// Whether SMAppService reports the daemon as approved and active.
    var registrationApproved: Bool { DaemonRegistration.status == .enabled }

    var state: ProtectionState {
        AppState.resolve(status: status, registrationApproved: registrationApproved)
    }

    var menuBarSymbol: String {
        StatusPresentation.menuBarSymbol(state: state, hasNewCandidate: status?.hasNewCandidate ?? false)
    }

    // MARK: - Polling

    func startPolling() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 2_000_000_000)   // 2s
            }
        }
    }

    func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    func refresh() async {
        let s = await client.fetchStatus()
        status = s
        // Only pull lists when the daemon answered; otherwise keep the last-known view.
        if s != nil {
            candidates = await client.fetchCandidates()
            servers = await client.fetchServers()
        }
    }

    // MARK: - Actions

    /// Turn protection on, or emergency-disarm it. Disarm takes effect immediately (no modal), so
    /// it always works even with the network fully blocked (R13).
    func setProtection(_ on: Bool) {
        Task {
            let (ok, err) = await client.setProtection(enabled: on)
            if !ok { lastError = err }
            await refresh()
        }
    }

    func setLAN(_ on: Bool) {
        Task {
            _ = await client.setLANAccess(allowed: on)
            await refresh()
        }
    }

    func allow(_ candidate: Candidate) {
        guard candidate.canAllow else { return }   // IPv6 can't be allowed
        Task {
            let (ok, err) = await client.allowServer(address: candidate.address,
                                                     label: candidate.processName, port: candidate.port)
            if !ok { lastError = err }
            await refresh()
        }
    }

    func remove(_ server: ServerRule) {
        Task {
            _ = await client.removeServer(address: server.address)
            await refresh()
        }
    }

    /// Manual address entry (R12) — the advanced fallback when auto-detect can't help.
    func addManual() {
        let address = manualAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard IPv4.isValid(address) else {
            manualError = "Неверный адрес. Пример: 89.106.86.61"
            return
        }
        manualError = nil
        Task {
            let (ok, err) = await client.allowServer(address: address, label: "Добавлено вручную", port: 0)
            if ok { manualAddress = "" } else { lastError = err }
            await refresh()
        }
    }

    func register() {
        _ = DaemonRegistration.register()
        Task { await refresh() }
    }

    func openSettings() {
        DaemonRegistration.openLoginItemsSettings()
    }
}
