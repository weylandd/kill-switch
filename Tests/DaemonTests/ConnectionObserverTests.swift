import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

/// Scanner that returns a fixed set of samples — lets us exercise the observer without libproc.
final class FakeScanner: SocketScanning {
    var samples: [ConnectionSample] = []
    func scan() -> [ConnectionSample] { samples }
}

/// Inspector with a fixed set of tunnel-local addresses.
final class FakeInspector: InterfaceInspecting {
    var addresses: Set<String> = []
    func tunnelLocalAddresses() -> Set<String> { addresses }
}

final class ConnectionObserverTests: XCTestCase {

    // MARK: - AddressRules (pure)

    func testPublicUnicastClassification() {
        XCTAssertTrue(AddressRules.isPublicUnicastIPv4("89.106.86.61"), "a real server is public")
        XCTAssertTrue(AddressRules.isPublicUnicastIPv4("1.1.1.1"))
        XCTAssertFalse(AddressRules.isPublicUnicastIPv4("10.0.0.1"), "10/8 private")
        XCTAssertFalse(AddressRules.isPublicUnicastIPv4("192.168.1.5"), "192.168/16 private")
        XCTAssertFalse(AddressRules.isPublicUnicastIPv4("172.20.1.1"), "172.16/12 private")
        XCTAssertFalse(AddressRules.isPublicUnicastIPv4("169.254.1.1"), "link-local")
        XCTAssertFalse(AddressRules.isPublicUnicastIPv4("100.96.0.1"), "CGNAT 100.64/10")
        XCTAssertFalse(AddressRules.isPublicUnicastIPv4("127.0.0.1"), "loopback")
        XCTAssertFalse(AddressRules.isPublicUnicastIPv4("198.18.0.1"), "tunnel-internal benchmarking range")
        XCTAssertFalse(AddressRules.isPublicUnicastIPv4("224.0.0.1"), "multicast")
        XCTAssertFalse(AddressRules.isPublicUnicastIPv4("not-an-ip"))
    }

    func testInTunnelDetection() {
        XCTAssertTrue(AddressRules.isInTunnel(localAddress: "198.18.0.1", tunnelLocalAddresses: ["198.18.0.1"]))
        XCTAssertFalse(AddressRules.isInTunnel(localAddress: "192.168.1.10", tunnelLocalAddresses: ["198.18.0.1"]))
        XCTAssertFalse(AddressRules.isInTunnel(localAddress: nil, tunnelLocalAddresses: ["198.18.0.1"]),
                       "unknown source -> treated as direct, so it is still surfaced")
    }

    /// R12/KTD8: loopback (::1, 127/8) and link-local (fe80::/10) are never candidates.
    func testLoopbackAndLinkLocalClassification() {
        XCTAssertTrue(AddressRules.isLoopbackOrLinkLocal("::1"), "IPv6 loopback")
        XCTAssertTrue(AddressRules.isLoopbackOrLinkLocal("127.0.0.1"), "IPv4 loopback")
        XCTAssertTrue(AddressRules.isLoopbackOrLinkLocal("127.255.0.7"), "whole 127/8 is loopback")
        XCTAssertTrue(AddressRules.isLoopbackOrLinkLocal("fe80::1c2d"), "IPv6 link-local")
        XCTAssertTrue(AddressRules.isLoopbackOrLinkLocal("FE80::ABCD"), "case-insensitive")
        XCTAssertFalse(AddressRules.isLoopbackOrLinkLocal("89.106.86.61"), "a real server is not loopback")
        XCTAssertFalse(AddressRules.isLoopbackOrLinkLocal("2606:4700::1111"), "public IPv6 is not loopback")
        XCTAssertFalse(AddressRules.isLoopbackOrLinkLocal("169.254.1.1"), "IPv4 link-local is not in this set (handled by isPublicUnicastIPv4)")
    }

    // MARK: - Observer filtering (refresh + keep rules)

    private func makeObserver(scanner: FakeScanner, inspector: FakeInspector) -> ConnectionObserver {
        ConnectionObserver(scanner: scanner, inspector: inspector, log: { _ in })
    }

    /// Covers AE3: a SYN_SENT attempt to a public address surfaces with the right process + address.
    func testDirectPublicAttemptBecomesCandidate() {
        let scanner = FakeScanner()
        scanner.samples = [ConnectionSample(processName: "v2RayTun", address: "89.106.86.61", port: 443,
                                            localAddress: "192.168.1.10")]
        let obs = makeObserver(scanner: scanner, inspector: FakeInspector())

        obs.refresh()
        let candidates = obs.candidates(allowedServers: [], vpnClientHints: ["v2ray"])
        XCTAssertEqual(candidates.count, 1)
        XCTAssertEqual(candidates.first?.processName, "v2RayTun")
        XCTAssertEqual(candidates.first?.address, "89.106.86.61")
        XCTAssertEqual(candidates.first?.port, 443)
    }

    /// Covers AE4: an address already approved (in <servers>) is excluded from candidates.
    func testApprovedServerIsExcluded() {
        let scanner = FakeScanner()
        scanner.samples = [ConnectionSample(processName: "v2RayTun", address: "89.106.86.61", port: 443,
                                            localAddress: "192.168.1.10")]
        let obs = makeObserver(scanner: scanner, inspector: FakeInspector())

        obs.refresh()
        XCTAssertTrue(obs.candidates(allowedServers: ["89.106.86.61"], vpnClientHints: ["v2ray"]).isEmpty,
                      "an approved server is no longer a candidate")
    }

    /// Noise filter: private/in-tunnel destinations and traffic from a utun source are dropped.
    func testPrivateAndInTunnelTrafficFilteredOut() {
        let scanner = FakeScanner()
        scanner.samples = [
            ConnectionSample(processName: "Safari", address: "142.250.1.1", port: 443, localAddress: "198.18.0.2"), // through tunnel
            ConnectionSample(processName: "mDNS", address: "192.168.1.1", port: 53, localAddress: "192.168.1.10"),  // private dest
            ConnectionSample(processName: "v2RayTun", address: "89.106.86.61", port: 443, localAddress: "192.168.1.10"), // direct public
        ]
        let inspector = FakeInspector(); inspector.addresses = ["198.18.0.2"]
        let obs = makeObserver(scanner: scanner, inspector: inspector)

        obs.refresh()
        let candidates = obs.candidates(allowedServers: [], vpnClientHints: ["v2ray"])
        XCTAssertEqual(candidates.map(\.address), ["89.106.86.61"], "only the direct public attempt survives")
    }

    /// Covers AE5: loopback self-talk (the ::1 flood) never becomes a candidate, while a real
    /// direct public attempt in the same scan survives.
    func testLoopbackTrafficNeverBecomesCandidate() {
        let scanner = FakeScanner()
        scanner.samples = [
            ConnectionSample(processName: "packet-extension-mac", address: "::1", port: 49813,
                             localAddress: "::1", isIPv6: true),
            ConnectionSample(processName: "packet-extension-mac", address: "::1", port: 51200,
                             localAddress: "::1", isIPv6: true),   // different ephemeral port = used to be a new row
            ConnectionSample(processName: "127.0.0.1-talker", address: "127.0.0.1", port: 1080,
                             localAddress: "127.0.0.1"),
            ConnectionSample(processName: "PacketTunnel", address: "91.240.86.16", port: 443,
                             localAddress: "192.168.1.10"),
        ]
        let obs = makeObserver(scanner: scanner, inspector: FakeInspector())

        obs.refresh()
        let candidates = obs.candidates(allowedServers: [], vpnClientHints: [])
        XCTAssertEqual(candidates.map(\.address), ["91.240.86.16"],
                       "loopback self-talk dropped; only the real direct attempt survives")
    }

    /// A blocked IPv6 attempt is surfaced as a diagnostic candidate (can't be allowed, but visible
    /// so an IPv6-only server doesn't just look dead).
    func testIPv6AttemptSurfacedAsDiagnostic() {
        let scanner = FakeScanner()
        scanner.samples = [ConnectionSample(processName: "v2RayTun", address: "2606:4700::1111", port: 443,
                                            localAddress: nil, isIPv6: true)]
        let obs = makeObserver(scanner: scanner, inspector: FakeInspector())

        obs.refresh()
        let candidates = obs.candidates(allowedServers: [], vpnClientHints: ["v2ray"])
        XCTAssertEqual(candidates.count, 1)
        XCTAssertTrue(candidates.first?.isIPv6 == true, "marked as IPv6 so the UI can flag it as un-allowable")
    }

    /// Several direct destinations from one process produce several candidate rows.
    func testMultipleDestinationsFromOneProcess() {
        let scanner = FakeScanner()
        scanner.samples = [
            ConnectionSample(processName: "v2RayTun", address: "89.106.86.61", port: 443, localAddress: "192.168.1.10"),
            ConnectionSample(processName: "v2RayTun", address: "5.6.7.8", port: 8443, localAddress: "192.168.1.10"),
        ]
        let obs = makeObserver(scanner: scanner, inspector: FakeInspector())

        obs.refresh()
        XCTAssertEqual(Set(obs.candidates(allowedServers: [], vpnClientHints: ["v2ray"]).map(\.address)),
                       ["89.106.86.61", "5.6.7.8"])
    }

    /// Re-scanning the same connection refreshes its timestamp instead of duplicating the row.
    func testRescanDeduplicates() {
        let scanner = FakeScanner()
        scanner.samples = [ConnectionSample(processName: "v2RayTun", address: "89.106.86.61", port: 443,
                                            localAddress: "192.168.1.10")]
        let obs = makeObserver(scanner: scanner, inspector: FakeInspector())

        obs.refresh(now: Date(timeIntervalSince1970: 1000))
        obs.refresh(now: Date(timeIntervalSince1970: 1003))
        XCTAssertEqual(obs.candidates(allowedServers: [], vpnClientHints: ["v2ray"],
                                      now: Date(timeIntervalSince1970: 1003)).count, 1,
                       "the same socket seen twice stays one candidate")
    }

    // MARK: - selectCandidates (pure union rule)

    /// "(5 most recent processes) ∪ (all within window)" — an old attempt from a non-top process
    /// outside the window drops; recent ones stay.
    func testWindowAndRecentProcessUnion() {
        let now = Date(timeIntervalSince1970: 10_000)
        let recent = ConnectionSample(processName: "fresh", address: "1.1.1.1", port: 443,
                                      seenAt: now.addingTimeInterval(-60))       // within 5 min
        let stale = ConnectionSample(processName: "old", address: "2.2.2.2", port: 443,
                                     seenAt: now.addingTimeInterval(-600))       // 10 min ago
        let result = ConnectionObserver.selectCandidates(
            samples: [recent, stale], allowedServers: [], vpnClientHints: [], now: now,
            recentProcessLimit: 1, window: 300)
        // "fresh" is both within window and the single most-recent process; "old" is neither.
        XCTAssertEqual(result.map(\.address), ["1.1.1.1"])
    }

    /// Candidates are returned newest-first for a stable display order.
    func testCandidatesSortedNewestFirst() {
        let now = Date(timeIntervalSince1970: 10_000)
        let older = ConnectionSample(processName: "a", address: "1.1.1.1", port: 1, seenAt: now.addingTimeInterval(-10))
        let newer = ConnectionSample(processName: "b", address: "2.2.2.2", port: 2, seenAt: now.addingTimeInterval(-1))
        let result = ConnectionObserver.selectCandidates(
            samples: [older, newer], allowedServers: [], vpnClientHints: [], now: now,
            recentProcessLimit: 5, window: 300)
        XCTAssertEqual(result.map(\.address), ["2.2.2.2", "1.1.1.1"])
    }

    // MARK: - VPN-client filtering (the 693-candidate flood fix)

    /// Only connections from VPN-client processes become candidates; other apps' blocked attempts
    /// (which flood the list when default-deny is active) are dropped.
    func testOnlyVPNClientProcessesBecomeCandidates() {
        let now = Date(timeIntervalSince1970: 10_000)
        let samples = [
            ConnectionSample(processName: "Google Chrome H", address: "142.250.1.1", port: 443, seenAt: now),
            ConnectionSample(processName: "v2RayTun", address: "89.106.86.61", port: 443, seenAt: now),
            ConnectionSample(processName: "Spotify", address: "35.186.1.1", port: 443, seenAt: now),
        ]
        let result = ConnectionObserver.selectCandidates(
            samples: samples, allowedServers: [], vpnClientHints: ["v2ray"], now: now,
            recentProcessLimit: 5, window: 300)
        XCTAssertEqual(result.map(\.address), ["89.106.86.61"],
                       "only the VPN client's attempt survives; Chrome/Spotify noise is dropped")
    }

    /// The list is capped so a pathological flood can never make it unreviewable.
    func testCandidateListIsCapped() {
        let now = Date(timeIntervalSince1970: 10_000)
        let many = (0..<100).map {
            ConnectionSample(processName: "v2RayTun", address: "8.8.\($0 / 256).\($0 % 256)", port: 443, seenAt: now)
        }
        let result = ConnectionObserver.selectCandidates(
            samples: many, allowedServers: [], vpnClientHints: ["v2ray"], now: now,
            recentProcessLimit: 5, window: 300, maxCount: 25)
        XCTAssertEqual(result.count, 25, "the candidate list is capped")
    }

    /// The matcher: case-insensitive substring; empty hints disable the filter.
    func testVPNClientMatching() {
        XCTAssertTrue(ConnectionObserver.matchesVPNClient("v2RayTun", hints: ["v2ray"]))
        XCTAssertTrue(ConnectionObserver.matchesVPNClient("Happ", hints: ["happ"]))
        XCTAssertFalse(ConnectionObserver.matchesVPNClient("Google Chrome H", hints: ["v2ray", "happ"]))
        XCTAssertTrue(ConnectionObserver.matchesVPNClient("anything", hints: []), "empty hints disable the filter")
    }
}
