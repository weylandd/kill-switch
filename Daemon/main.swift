import Foundation
import KillSwitchShared
import KillSwitchDaemonCore

// The privileged daemon. At startup it raises protection from the persisted state (U4):
// load state -> build the default-deny ruleset -> enable the firewall.
// The XPC service for talking to the app is wired up in U7.

let bootstrap = DaemonBootstrap()
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
let watchdog = Watchdog(pf: PFRulesetManager(), stateProvider: { StateStore().load() })
watchdog.start()

// The daemon is a long-lived process under launchd. Keep the runloop alive.
RunLoop.main.run()
