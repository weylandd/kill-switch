import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

final class AutoApproverTests: XCTestCase {
    private var tempDir: URL!
    private var store: StateStore!
    private var pf: FakePF!
    private var candidates: FakeCandidates!
    private var verifier: FakeSignatureVerifier!
    private var sessionDisarm: SessionDisarm!
    private var signals: AutoApprovalSignals!

    private let trustedTeamID = "2XZUN9L63Z"
    private let dialer = "packet-extension-mac"

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("AutoApproverTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        store = StateStore(directory: tempDir)
        pf = FakePF()
        candidates = FakeCandidates()
        verifier = FakeSignatureVerifier()
        sessionDisarm = SessionDisarm(markerURL: tempDir.appendingPathComponent("session-disarm"),
                                      bootID: { "boot-test" }, log: { _ in })
        signals = AutoApprovalSignals()
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    private func makeApprover(maxPerHour: Int = 10) -> AutoApprover {
        AutoApprover(store: store, pf: pf, candidates: candidates, verifier: verifier,
                     sessionDisarm: sessionDisarm, signals: signals,
                     maxApprovalsPerHour: maxPerHour, log: { _ in })
    }

    private func saveState(trusted: [TrustedClient], protectionEnabled: Bool = true,
                           servers: [ServerRule] = [], excluded: [String] = []) throws {
        try store.save(PersistedState(servers: servers, protectionEnabled: protectionEnabled,
                                      trustedClients: trusted, excludedAddresses: excluded))
    }

    private func trusted() -> TrustedClient {
        TrustedClient(teamID: trustedTeamID, label: "v2RayTun", processNames: [dialer])
    }

    /// Covers AE1: a trusted client's blocked dial to a new server is auto-approved — persisted
    /// first (origin .auto, labelled), then added to the kernel table.
    func testTrustedClientCandidateIsAutoApproved() throws {
        try saveState(trusted: [trusted()])
        verifier.teamIDsByPid = [555: trustedTeamID]
        candidates.list = [Candidate(processName: dialer, address: "91.240.86.16", port: 443, pid: 555)]

        let approved = makeApprover().tick()

        XCTAssertEqual(approved, ["91.240.86.16"])
        let saved = store.load()
        XCTAssertEqual(saved.servers.map(\.address), ["91.240.86.16"], "persisted")
        XCTAssertEqual(saved.servers.first?.effectiveOrigin, .auto, "marked auto for the UI")
        XCTAssertEqual(saved.servers.first?.label, "v2RayTun")
        XCTAssertTrue(pf.ops.contains(.add("91.240.86.16")), "reaches the kernel table")
        XCTAssertFalse(signals.paused)
    }

    /// Covers AE2: a process whose signature does NOT match a trusted Team ID is left alone — name
    /// imitation is not enough.
    func testUntrustedSignatureIsNotApproved() throws {
        try saveState(trusted: [trusted()])
        verifier.teamIDsByPid = [777: "EVIL000000"]    // signed, but a different team
        candidates.list = [Candidate(processName: dialer, address: "6.6.6.6", port: 443, pid: 777)]

        XCTAssertTrue(makeApprover().tick().isEmpty)
        XCTAssertTrue(store.load().servers.isEmpty)
        XCTAssertFalse(pf.ops.contains(.add("6.6.6.6")))
    }

    /// An unsigned/unverifiable process (verifier returns nil) is never auto-approved (fail closed).
    func testUnverifiableProcessIsNotApproved() throws {
        try saveState(trusted: [trusted()])
        candidates.list = [Candidate(processName: dialer, address: "7.7.7.7", port: 443, pid: 888)]
        XCTAssertTrue(makeApprover().tick().isEmpty)
        XCTAssertTrue(store.load().servers.isEmpty)
    }

    /// Covers AE5/R5: IPv6 and pid-less candidates are skipped (IPv6 fully blocked; no pid = no
    /// signature to verify).
    func testIPv6AndPidlessCandidatesSkipped() throws {
        try saveState(trusted: [trusted()])
        verifier.teamIDsByPid = [555: trustedTeamID]
        candidates.list = [
            Candidate(processName: dialer, address: "2606:4700::1111", port: 443, isIPv6: true, pid: 555),
            Candidate(processName: dialer, address: "8.8.8.8", port: 443, pid: nil),
        ]
        XCTAssertTrue(makeApprover().tick().isEmpty)
        XCTAssertTrue(store.load().servers.isEmpty)
    }

    /// Covers AE6: while disarmed (persisted flag OR boot-session marker) nothing is approved or
    /// persisted — the auto-approver never fights an explicit OFF.
    func testDisarmedStateIsLeftAlone() throws {
        try saveState(trusted: [trusted()], protectionEnabled: false)
        verifier.teamIDsByPid = [555: trustedTeamID]
        candidates.list = [Candidate(processName: dialer, address: "91.240.86.16", port: 443, pid: 555)]
        XCTAssertTrue(makeApprover().tick().isEmpty, "persisted disarm → no action")

        try saveState(trusted: [trusted()])
        try sessionDisarm.setDisarmed()
        XCTAssertTrue(makeApprover().tick().isEmpty, "session-disarm marker → no action")
    }

    /// Covers AE3: an address on the exclusion list (a prior user removal) is never re-added.
    func testExcludedAddressIsNotApproved() throws {
        try saveState(trusted: [trusted()], excluded: ["91.240.86.16"])
        verifier.teamIDsByPid = [555: trustedTeamID]
        candidates.list = [Candidate(processName: dialer, address: "91.240.86.16", port: 443, pid: 555)]
        XCTAssertTrue(makeApprover().tick().isEmpty)
        XCTAssertTrue(store.load().servers.isEmpty)
    }

    /// ADV-2: a connection from a vendor process NOT in the trust record's dialing-process list
    /// (e.g. the GUI app, same Team ID) is not auto-approved and doesn't consume the relay cap.
    func testWrongDialingProcessIsNotApproved() throws {
        try saveState(trusted: [trusted()])     // processNames = ["packet-extension-mac"]
        verifier.teamIDsByPid = [555: trustedTeamID]
        candidates.list = [Candidate(processName: "v2RayTun-GUI", address: "9.9.9.9", port: 443, pid: 555)]
        XCTAssertTrue(makeApprover().tick().isEmpty, "GUI noise (same team, different process) ignored")
        XCTAssertTrue(store.load().servers.isEmpty)
    }

    /// R6: the hourly cap bounds approvals and raises the visible pause signal.
    func testRateCapStopsApprovalsAndSignalsPause() throws {
        try saveState(trusted: [trusted()])
        verifier.teamIDsByPid = [555: trustedTeamID]
        candidates.list = (1...5).map {
            Candidate(processName: dialer, address: "91.240.86.\($0)", port: 443, pid: 555)
        }
        let approved = makeApprover(maxPerHour: 2).tick()
        XCTAssertEqual(approved.count, 2, "stops at the cap")
        XCTAssertEqual(store.load().servers.count, 2)
        XCTAssertTrue(signals.paused, "pause signal raised for the UI")
    }

    /// No trusted clients → no work and no signature checks at all.
    func testNoTrustedClientsMeansNoWork() throws {
        try saveState(trusted: [])
        candidates.list = [Candidate(processName: dialer, address: "91.240.86.16", port: 443, pid: 555)]
        XCTAssertTrue(makeApprover().tick().isEmpty)
        XCTAssertTrue(verifier.checkedPids.isEmpty, "no trust list → no signature checks")
    }
}
