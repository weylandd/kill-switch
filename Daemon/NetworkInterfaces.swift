import Foundation
import Darwin

/// Enumerates the current tunnel (`utun*`) interfaces.
///
/// macOS pf does NOT treat `utun` as an interface group (unlike OpenBSD), so a rule like
/// `pass on utun` matches nothing and all decrypted tunnel traffic gets blocked. The ruleset must
/// therefore name each active interface explicitly (`pass on utun7 ...`). Names shift across
/// reconnects/reboots, so this is read live whenever the ruleset is (re)built.
public enum NetworkInterfaces {
    public static func utunNames() -> [String] {
        var names = Set<String>()
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return [] }
        defer { freeifaddrs(head) }

        var ptr = head
        while let cur = ptr {
            defer { ptr = cur.pointee.ifa_next }
            let name = String(cString: cur.pointee.ifa_name)
            if name.hasPrefix("utun") { names.insert(name) }
        }
        return names.sorted()
    }
}
