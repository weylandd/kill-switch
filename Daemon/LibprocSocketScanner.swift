import Foundation
import Darwin

/// Enumerates every process's sockets via libproc (the technique `lsof` uses) and reports direct
/// outbound attempts. Runs as root in the daemon, so it sees all processes' sockets — including
/// blocked/pending ones (TCP SYN_SENT), which is how a new, still-blocked server becomes visible.
///
/// This is pure system access and cannot run in the test sandbox; it is verified on a real
/// machine (see docs/review-followups-stage-a.md). The classification logic that consumes its
/// output lives in `AddressRules`/`ConnectionObserver` and is unit-tested separately.
public final class LibprocSocketScanner: SocketScanning {

    public init() {}

    public func scan() -> [ConnectionSample] {
        let now = Date()
        var samples: [ConnectionSample] = []

        // Generously sized pid buffer; macOS bounds the process count well below this.
        let maxPids = 8192
        var pids = [pid_t](repeating: 0, count: maxPids)
        let returnedBytes = proc_listallpids(&pids, Int32(maxPids * MemoryLayout<pid_t>.size))
        guard returnedBytes > 0 else { return [] }
        let pidCount = Int(returnedBytes) / MemoryLayout<pid_t>.size

        for i in 0..<pidCount where pids[i] > 0 {
            samples.append(contentsOf: sockets(of: pids[i], now: now))
        }
        return samples
    }

    // MARK: - Per-process socket walk

    private func sockets(of pid: pid_t, now: Date) -> [ConnectionSample] {
        let bufSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bufSize > 0 else { return [] }

        let capacity = Int(bufSize) / MemoryLayout<proc_fdinfo>.size
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: capacity)
        let got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, bufSize)
        guard got > 0 else { return [] }
        let count = Int(got) / MemoryLayout<proc_fdinfo>.size

        let name = Self.processName(pid)
        var result: [ConnectionSample] = []
        for i in 0..<count where fds[i].proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
            if let sample = sample(pid: pid, name: name, fd: fds[i].proc_fd, now: now) {
                result.append(sample)
            }
        }
        return result
    }

    private func sample(pid: pid_t, name: String, fd: Int32, now: Date) -> ConnectionSample? {
        var info = socket_fdinfo()
        let size = Int32(MemoryLayout<socket_fdinfo>.size)
        guard proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, size) == size else { return nil }

        let kind = info.psi.soi_kind
        guard kind == Int32(SOCKINFO_TCP) || kind == Int32(SOCKINFO_IN) else { return nil }

        let inSock: in_sockinfo
        if kind == Int32(SOCKINFO_TCP) {
            let tcp = info.psi.soi_proto.pri_tcp
            // Only outbound attempts/active connections: a pending SYN (the new-server case) or an
            // established one. Listening/closed sockets are not attempts.
            guard tcp.tcpsi_state == Int32(TSI_S_SYN_SENT) || tcp.tcpsi_state == Int32(TSI_S_ESTABLISHED) else {
                return nil
            }
            inSock = tcp.tcpsi_ini
        } else {
            inSock = info.psi.soi_proto.pri_in
        }

        // Ports are stored in network byte order in the low 16 bits.
        let port = Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: inSock.insi_fport)))
        guard port > 0 else { return nil }   // no foreign endpoint -> not an outbound connection

        let isIPv6 = (inSock.insi_vflag & UInt8(INI_IPV6)) != 0
        let remote: String?
        let local: String?
        if isIPv6 {
            remote = Self.ipv6String(inSock.insi_faddr.ina_6)
            local = Self.ipv6String(inSock.insi_laddr.ina_6)
        } else {
            remote = Self.ipv4String(inSock.insi_faddr.ina_46.i46a_addr4)
            local = Self.ipv4String(inSock.insi_laddr.ina_46.i46a_addr4)
        }
        guard let remoteAddr = remote, !Self.isUnspecified(remoteAddr) else { return nil }

        return ConnectionSample(processName: name, address: remoteAddr, port: port,
                                localAddress: local, isIPv6: isIPv6, seenAt: now)
    }

    // MARK: - Helpers

    static func processName(_ pid: pid_t) -> String {
        var buf = [CChar](repeating: 0, count: 256)
        let n = proc_name(pid, &buf, UInt32(buf.count))
        let name = n > 0 ? String(cString: buf) : ""
        return name.isEmpty ? "pid \(pid)" : name
    }

    static func ipv4String(_ addr: in_addr) -> String? {
        var a = addr
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
        return String(cString: buf)
    }

    static func ipv6String(_ addr: in6_addr) -> String? {
        var a = addr
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &a, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
        return String(cString: buf)
    }

    private static func isUnspecified(_ addr: String) -> Bool {
        addr == "0.0.0.0" || addr == "::" || addr.isEmpty
    }
}

/// Reports the addresses bound to `utun*` interfaces via getifaddrs, so the observer can drop
/// traffic that is already inside a tunnel.
public final class GetifaddrsInspector: InterfaceInspecting {

    public init() {}

    public func tunnelLocalAddresses() -> Set<String> {
        var result = Set<String>()
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return result }
        defer { freeifaddrs(head) }

        var ptr = head
        while let cur = ptr {
            defer { ptr = cur.pointee.ifa_next }
            let name = String(cString: cur.pointee.ifa_name)
            guard name.hasPrefix("utun"), let sa = cur.pointee.ifa_addr else { continue }
            if let addr = Self.addressString(sa) { result.insert(addr) }
        }
        return result
    }

    private static func addressString(_ sa: UnsafeMutablePointer<sockaddr>) -> String? {
        let family = sa.pointee.sa_family
        guard family == UInt8(AF_INET) || family == UInt8(AF_INET6) else { return nil }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let len = socklen_t(sa.pointee.sa_len)
        guard getnameinfo(sa, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else {
            return nil
        }
        return String(cString: host)
    }
}
