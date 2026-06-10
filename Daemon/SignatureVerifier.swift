import Foundation
import Security
import Darwin

/// Verifies the code signature of a LIVE process and reports its signing Team ID. Behind a protocol
/// so the trusted-client logic can be unit-tested with a fake (no real processes needed).
public protocol SignatureVerifying {
    /// The code-signing Team ID of the running process named by `pid`, or nil when the process is
    /// unsigned, ad-hoc, a platform binary, tampered, gone, or otherwise not Developer-ID-verifiable.
    /// "nil" always means "do not trust" — the auto-approval and trust paths fail closed on it.
    func verifiedTeamID(forPid pid: Int32) -> String?
}

/// Real implementation on top of the Security framework. This is what makes "trust this app"
/// trustworthy: a malicious process can copy a NAME like "PacketTunnel", but it cannot carry another
/// developer's Developer-ID signature — the signature is checked against the LIVE code object, so a
/// tampered or impostor binary fails `SecCodeCheckValidity` and returns nil.
///
/// Identity is bound via the audit token (not the bare PID): the token includes the `pidversion`, so
/// it names exactly one incarnation of one process and closes the PID-reuse / exec-replacement race
/// (KTD1). Verdicts are cached by `(pid, pidversion)` so a process isn't re-validated every scan.
public final class SecCodeSignatureVerifier: SignatureVerifying {

    private let lock = NSLock()
    private var cache: [String: String?] = [:]   // "(pid).(pidversion)" -> Team ID, or nil = untrusted

    /// Validity requirement: signed by a chain rooted at an Apple CA (`anchor apple generic`). We do
    /// NOT pin a cert TYPE or a Team ID here — this verifier READS the team id of whatever is validly
    /// Apple-anchored, and the caller decides which team to trust. `anchor apple generic` deliberately
    /// accepts ALL legitimate third-party signing types — Developer ID, Mac App Store, AND
    /// "Apple iPhone OS Application Signing" (iOS apps run on Apple Silicon Macs, which is how the
    /// real VPN client on the test machine is signed — a strict Developer-ID requirement rejected it,
    /// caught in live verification 2026-06-10). Security is unaffected: ad-hoc/unsigned binaries fail
    /// `anchor apple generic`, Apple's own platform binaries carry no Team ID (rejected by the
    /// non-empty-team check below), and a Team ID cannot be forged — so auto-approval still requires a
    /// match to a team the user explicitly trusted.
    private static let appleAnchoredRequirement = "anchor apple generic"

    public init() {}

    public func verifiedTeamID(forPid pid: Int32) -> String? {
        guard let token = Self.auditToken(forPid: pid) else { return nil }
        let key = "\(pid).\(token.val.7)"   // val.7 = pidversion

        lock.lock()
        if let cached = cache[key] { lock.unlock(); return cached }
        lock.unlock()

        let teamID = Self.computeTeamID(token: token)

        lock.lock()
        if cache.count > 512 { cache.removeAll() }   // pids recycle slowly; a coarse reset is enough
        cache[key] = teamID
        lock.unlock()
        return teamID
    }

    // MARK: - Internals

    /// Convert a pid to its audit token via the task NAME port (root needs no entitlement for the
    /// name port). Returns nil if the process is gone or the lookup fails.
    private static func auditToken(forPid pid: Int32) -> audit_token_t? {
        var task: task_name_t = 0
        guard task_name_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, task) }

        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &token) { tokenPtr -> kern_return_t in
            tokenPtr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), intPtr, &count)
            }
        }
        return kr == KERN_SUCCESS ? token : nil
    }

    /// Resolve the live SecCode for the audit token, validate it against the Developer-ID
    /// requirement, and read its Team ID. Any failure → nil (fail closed).
    private static func computeTeamID(token: audit_token_t) -> String? {
        var tokenVar = token
        let tokenData = Data(bytes: &tokenVar, count: MemoryLayout<audit_token_t>.size)
        let attrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary

        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let liveCode = code else { return nil }

        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(appleAnchoredRequirement as CFString, [], &requirement) == errSecSuccess,
              let req = requirement else { return nil }

        // Validate the LIVE signature against the requirement. No network revocation checks on the
        // decision path (they can stall); default flags use trustd's cached trust state.
        guard SecCodeCheckValidity(liveCode, [], req) == errSecSuccess else { return nil }

        // Signing info lives on the static code object.
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(liveCode, [], &staticCode) == errSecSuccess,
              let sc = staticCode else { return nil }

        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(sc, flags, &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }

        let teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
        return (teamID?.isEmpty == false) ? teamID : nil
    }
}
