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
    // Exit with an error so launchd (KeepAlive) restarts the daemon and retries
    // (launchd throttles restarts, so there is no tight loop).
    FileHandle.standardError.write(
        Data("[\(KillSwitchConfig.daemonLabel)] startup failed, exiting for restart: \(error)\n".utf8))
    exit(EXIT_FAILURE)
}

// The daemon is a long-lived process under launchd. Keep the runloop alive.
RunLoop.main.run()
