import Foundation
@testable import KillSwitchDaemonCore

/// Test double for `SignatureVerifying`: a fixed pid → Team ID map, nil for everyone else, and a
/// record of which pids were checked (so tests can assert the verifier was/was not consulted).
final class FakeSignatureVerifier: SignatureVerifying {
    var teamIDsByPid: [Int32: String] = [:]
    private(set) var checkedPids: [Int32] = []

    func verifiedTeamID(forPid pid: Int32) -> String? {
        checkedPids.append(pid)
        return teamIDsByPid[pid]
    }
}
