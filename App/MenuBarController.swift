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
    @Published var trustedClients: [TrustedClient] = []
    @Published var manualAddress: String = ""
    @Published var manualError: String?
    @Published var lastError: String?
    /// Transient success banner shown right after a disarm or break-glass, so OFF is never a silent
    /// no-op (R33). Distinct from the steady disarmed icon/toggle: it confirms the action just worked
    /// and the internet should be back. Auto-clears after a few seconds.
    @Published var offConfirmation: String?
    /// Transient notice when the daemon auto-allowed one or more servers for a trusted client, so the
    /// automation is never silent (R8). Coalesced across a rotation burst. Auto-clears.
    @Published var autoAllowNotice: String?
    /// A candidate awaiting trust confirmation — drives the "Доверять приложению X?" dialog so the
    /// scope of the action (auto-approve this app's future servers) is explicit (DL-001).
    @Published var pendingTrustCandidate: Candidate?
    /// True while the privileged emergency OFF is running (its admin-password dialog is up).
    @Published var isEmergencyRunning = false
    /// True while a manual "retry connection" is in flight, so the button can show feedback.
    @Published var isCheckingConnection = false

    /// Auto-approval is paused on the rate cap (R6) — surfaced from the status poll (KTD10).
    var isAutoApprovalPaused: Bool { status?.isAutoApprovalPaused ?? false }
    /// A trusted app's signature changed and its trust is suspended (R13) — from the status poll.
    var hasSuspendedClient: Bool { status?.hasSuspendedClient ?? false }

    private let client = XPCClient()
    private var pollTask: Task<Void, Never>?
    private var confirmationTask: Task<Void, Never>?
    private var autoAllowNoticeTask: Task<Void, Never>?
    /// True once the server list has been fetched at least once, so the initial load (which fills the
    /// list from the daemon's persisted state) doesn't fire "auto-approved" notices for pre-existing
    /// servers — while a genuinely-empty first list still lets the first post-trust batch be announced.
    private var hasLoadedServersOnce = false

    init() {
        // Start polling at construction (the controller lives for the whole app), so the menu-bar
        // icon reflects state immediately — not only after the user first opens the window.
        startPolling()
        ensureLoginItemIfProtectionInstalled()
    }

    /// If protection is installed (the daemon is approved), make sure THIS control app also launches
    /// at login. Without it the user can reboot into a fully-blocked network with the daemon running
    /// but no on-screen way to disarm or run the break-glass — the 2026-06-08 lockout. Self-healing
    /// on launch covers installs made before this existed and re-adds the app if it was removed.
    private func ensureLoginItemIfProtectionInstalled() {
        guard DaemonRegistration.status == .enabled, !AppLoginItem.isEnabled else { return }
        AppLoginItem.enable()
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
        if s != status { status = s }
        // Only pull lists when the daemon answered; otherwise keep the last-known view. Each list is
        // reassigned only when it actually changed, so a steady 2s poll doesn't republish identical
        // data and needlessly invalidate the UI (e.g. disturb focus in the manual-address field).
        if s != nil {
            let freshCandidates = await client.fetchCandidates()
            if freshCandidates != candidates { candidates = freshCandidates }
            let fresh = await client.fetchServers()
            announceAutoApprovals(old: servers, new: fresh)
            if fresh != servers { servers = fresh }
            let freshTrusted = await client.fetchTrustedClients()
            if freshTrusted != trustedClients { trustedClients = freshTrusted }
        }
    }

    /// Show a transient, coalesced notice when auto-approved servers appear between polls — automation
    /// must be noticeable, not silent (R8/DL-004). A rotation burst that adds several servers in one
    /// poll window produces ONE "added N" notice rather than a flurry of banners.
    private func announceAutoApprovals(old: [ServerRule], new: [ServerRule]) {
        // Suppress only the very first fetch of the app's lifetime (it loads pre-existing servers);
        // after that, an empty `old` is a real state we want to diff against — that's exactly the
        // fresh-install "trust → first auto-approval" case the notice must not miss (review finding).
        guard hasLoadedServersOnce else { hasLoadedServersOnce = true; return }
        let known = Set(old.map(\.address))
        let added = new.filter { $0.effectiveOrigin == .auto && !known.contains($0.address) }
        guard !added.isEmpty else { return }
        autoAllowNotice = added.count == 1
            ? "Авто-разрешён новый сервер VPN: \(added[0].address)"
            : "Авто-разрешено новых серверов VPN: \(added.count)"
        autoAllowNoticeTask?.cancel()
        autoAllowNoticeTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 8_000_000_000)
            guard !Task.isCancelled else { return }
            self?.autoAllowNotice = nil
        }
    }

    /// Manual "Повторить" on the unreachable screen: force a brand-new connection (the cached one is
    /// dead if it was built while the daemon was down) and re-check, with on-screen feedback so the
    /// button is never a silent no-op. The 2s poll also recovers on its own now, but an explicit
    /// retry should feel responsive.
    func retryConnection() {
        guard !isCheckingConnection else { return }
        Task {
            isCheckingConnection = true
            client.reset()
            await refresh()
            isCheckingConnection = false
        }
    }

    // MARK: - Actions

    /// Turn protection on, or emergency-disarm it. Disarm takes effect immediately (no modal), so
    /// it always works even with the network fully blocked (R13).
    func setProtection(_ on: Bool) {
        Task {
            let (ok, err) = await client.setProtection(enabled: on)
            if !ok {
                lastError = err
            } else if on {
                clearOffConfirmation()       // re-armed — drop any lingering "off" banner
            } else {
                lastError = nil
                flashOffConfirmation()       // disarm succeeded — confirm visibly (R33)
            }
            await refresh()
        }
    }

    /// Show the transient "protection off, internet should work" banner and auto-clear it after a few
    /// seconds. Cancels any prior timer so repeated actions don't leave a stale banner.
    private func flashOffConfirmation() {
        offConfirmation = "Защита выключена — интернет должен работать."
        confirmationTask?.cancel()
        confirmationTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 6_000_000_000)
            guard !Task.isCancelled else { return }
            self?.offConfirmation = nil
        }
    }

    private func clearOffConfirmation() {
        confirmationTask?.cancel()
        offConfirmation = nil
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
            case .restored:  lastError = nil; flashOffConfirmation()   // confirm visibly (R33)
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

    /// Step 1 of trusting an app: stash the candidate so the view can show a confirmation dialog
    /// naming the scope ("its future servers will be allowed automatically") before we commit.
    func requestTrust(_ candidate: Candidate) {
        guard candidate.pid != nil else { return }   // no pid → can't verify the process
        pendingTrustCandidate = candidate
    }

    func cancelTrust() { pendingTrustCandidate = nil }

    /// Step 2: the user confirmed. The daemon verifies the LIVE process signature and enrols its
    /// Team ID; from then on its new servers are auto-approved.
    func confirmTrust() {
        guard let candidate = pendingTrustCandidate, let pid = candidate.pid else { return }
        pendingTrustCandidate = nil
        Task {
            let (ok, err) = await client.trustClient(pid: pid, label: candidate.processName)
            if !ok { lastError = err }
            await refresh()
        }
    }

    func untrust(_ trusted: TrustedClient) {
        Task {
            let (ok, err) = await client.untrustClient(teamID: trusted.teamID)
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
        // Installing protection also makes this control app launch at login, so the disarm toggle
        // and break-glass are present after a reboot (best-effort — never blocks daemon setup).
        AppLoginItem.enable()
        Task { await refresh() }
    }

    func openSettings() {
        DaemonRegistration.openLoginItemsSettings()
    }
}
