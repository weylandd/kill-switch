import Foundation
import KillSwitchShared
import KillSwitchDaemonCore

// The privileged daemon. At startup it raises protection from the persisted state (U4):
// load state -> build the default-deny ruleset -> enable the firewall. It then keeps that
// protection up (watchdog, U5), watches for new servers (observer, U6), and serves the app
// over XPC (U7).

// Shared collaborators — one StateStore (its lock serializes writes) and one PF engine across
// bootstrap, watchdog and the command handler.
let store = StateStore()
let pf = PFRulesetManager()
let observer = ConnectionObserver()

// Local-only event journal (U9, R21). Routed as the `log:` sink for the components below so key
// actions (startup, protection on/off, server add/remove, watchdog reinstalls) are recorded.
let eventLog = EventLog()
let journal: (String) -> Void = { eventLog.record($0) }

let bootstrap = DaemonBootstrap(store: store, pf: pf, log: journal)
do {
    try bootstrap.start()
} catch {
    // Exit so launchd (KeepAlive) restarts the daemon and retries full startup.
    // We deliberately do NOT force a block-all here: the user must never end up with no
    // internet and no way to turn protection off without Terminal. A failed start leaves
    // PF in its prior state (off on a cold first boot), which is recoverable; an automatic
    // lockdown could strand the user (see docs/review-followups-stage-a.md).
    FileHandle.standardError.write(
        Data("[\(KillSwitchConfig.daemonLabel)] startup failed, exiting for restart: \(error)\n".utf8))
    exit(EXIT_FAILURE)
}

// Keep protection from silently staying down if PF is disabled or the rules are flushed (U5).
// It reads the persisted state on every check, so it never fights an explicit disarm.
let watchdog = Watchdog(pf: pf, stateProvider: { store.load() }, log: journal)
watchdog.start()

// Watch for direct outbound attempts so the app can offer new servers for approval (U6).
observer.start()

// Serve the menu-bar app: status, allow/remove server, protection on/off, LAN toggle (U7).
let handler = CommandHandler(store: store, pf: pf, candidates: observer, log: journal)
let xpc = XPCService(handler: handler)
xpc.resume()

// Guaranteed escape hatch (KTD7): when the daemon is told to stop — e.g. the user toggles it off
// in System Settings → Login Items, or the system unloads it — drop the firewall so the internet
// is restored. Otherwise the PF rules would persist in the kernel with no daemon left to disarm
// them, stranding the user. We accept the small fail-open window this opens on a restart; the
// user explicitly prefers fail-open over any lockout risk.
let sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
sigterm.setEventHandler {
    // Restore the system default ruleset (not just `pfctl -d`): otherwise our block-all rules stay
    // loaded in the kernel after we exit and re-block everything the next time PF is enabled (on
    // wake, or by a VPN client), with no daemon left to undo it.
    try? pf.restoreSystemDefault()
    FileHandle.standardError.write(Data("[\(KillSwitchConfig.daemonLabel)] SIGTERM — restored default ruleset, exiting\n".utf8))
    exit(EXIT_SUCCESS)
}
sigterm.resume()
signal(SIGTERM, SIG_IGN)   // let the dispatch source handle it instead of the default action

// The daemon is a long-lived process under launchd. Keep the runloop alive.
RunLoop.main.run()
