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
    /// True while the privileged emergency OFF is running (its admin-password dialog is up).
    @Published var isEmergencyRunning = false

    private let client = XPCClient()
    private var pollTask: Task<Void, Never>?

    init() {
        // Start polling at construction (the controller lives for the whole app), so the menu-bar
        // icon reflects state immediately — not only after the user first opens the window.
        startPolling()
    }

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

    private func startPolling() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }   // controller gone → stop the loop (don't spin)
                await self.refresh()
                try? await Task.sleep(nanoseconds: 2_000_000_000)   // 2s
            }
        }
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

    /// Break-glass emergency OFF (KTD7). Bypasses the daemon entirely and restores the internet by
    /// driving PF directly with root (one admin-password prompt). This is the guaranteed escape when
    /// the daemon is hung/dead and the normal switch above can't reach it.
    func emergencyOff() {
        guard !isEmergencyRunning else { return }
        Task {
            isEmergencyRunning = true
            // run() blocks on the system auth dialog — keep it off the main actor.
            let outcome = await Task.detached { EmergencyOff.run() }.value
            isEmergencyRunning = false
            switch outcome {
            case .restored:  lastError = nil
            case .cancelled: break                        // user dismissed the prompt; nothing changed
            case .failed(let msg): lastError = "Аварийный сброс: \(msg)"
            }
            await refresh()
        }
    }

    func setLAN(_ on: Bool) {
        Task {
            let (ok, err) = await client.setLANAccess(allowed: on)
            if !ok { lastError = err }
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
            let (ok, err) = await client.removeServer(address: server.address)
            if !ok { lastError = err }
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
