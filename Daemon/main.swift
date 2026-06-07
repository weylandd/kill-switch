import Foundation
import KillSwitchShared
import KillSwitchDaemonCore

// The privileged daemon. At startup it raises protection from the persisted state (U4):
// load state -> build the default-deny ruleset -> enable the firewall.
// The XPC service for talking to the app is wired up in U7; the watchdog is U5.

let bootstrap = DaemonBootstrap()
do {
    try bootstrap.start()
} catch {
    // Fail-closed: if protection could not be raised, do NOT keep running without rules.
    // First try an emergency block-all lockdown so the machine is closed (no internet)
    // rather than left open during the restart window. Then exit so launchd (KeepAlive)
    // restarts the daemon and retries full startup (launchd throttles restarts).
    FileHandle.standardError.write(
        Data("[\(KillSwitchConfig.daemonLabel)] startup failed, locking down then exiting for restart: \(error)\n".utf8))
    bootstrap.emergencyLockdown()
    exit(EXIT_FAILURE)
}

// The daemon is a long-lived process under launchd. Keep the runloop alive.
RunLoop.main.run()
