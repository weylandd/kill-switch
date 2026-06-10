---
date: 2026-06-10
topic: trusted-client-auto-approval
---

# Trusted-Client Auto-Approval — Requirements

## Summary

Let the user trust a VPN client APP once (anchored to its verified developer code signature), after which the daemon automatically whitelists new servers that app dials — so a subscription client's silent server rotation no longer breaks the internet. The firewall itself stays default-deny and untouched; only whitelist maintenance becomes automatic, gated by signature verification. Includes the loopback-noise filter for the candidate list.

---

## Problem Frame

The 2026-06-10 incident (`docs/solutions/integration-issues/vpn-endpoint-rotation-pf-whitelist-blocks-new-connections.md`): v2RayTun draws from a pool of relay servers and rotates them without notice. The whitelist held one IP, so after a self-reconnect every NEW connection on the machine silently died while established ones survived — the user spent a morning toggling protection to keep the internet alive. Manual per-server approval cannot keep up with a client that changes endpoints on its own schedule; each rotation is another silent outage. Separately, the candidate list floods with the client's loopback self-connections (`::1:<ephemeral>`), which once produced ~1700 meaningless approval requests.

---

## Key Decisions

- **Trust the app, enforce by signature.** PF cannot filter by application, so per-app permission is implemented above the firewall: the daemon verifies the LIVE process's developer code signature (Team ID) and translates app-level trust into address-level whitelist entries. A rogue process can imitate a name but not carry another developer's signature.
- **The firewall posture does not change.** Default-deny, full IPv6 block, and the R19 backstop stay exactly as they are. Automation only maintains the `<servers>` list; nothing gets a broader pass.
- **This deliberately revises the 2026-06-07 decision** "approve each new server manually — not auto-trust-app" (`docs/brainstorms/2026-06-07-vpn-kill-switch-macos-requirements.md`). That decision predated the discovery that the client rotates a server pool; the incident showed manual-only approval turns every rotation into a silent outage. It also closes R35/AE5 of `docs/brainstorms/2026-06-08-vpn-kill-switch-reliable-off-requirements.md` beyond what manual approval could.
- **Rejected alternatives (considered with the user, 2026-06-10):** a reactive kill-switch (open while tunnel is up, slam on drop) — trades the zero-leak guarantee for a leak window at the most dangerous moment; a NetworkExtension rewrite — previously rejected, stays rejected; parsing the client's subscription/config — fragile coupling to a third-party format.

---

## Requirements

**Trust model**

- R1. Trust is granted per app by an explicit user action (one tap on a candidate row: "trust this app"). Trust is never established automatically.
- R2. Trust is anchored to the verified developer code signature (Team ID) of the live process, checked by the daemon at grant time and on every auto-approval. A process with a matching name but a missing, invalid, or different signature must not pass.
- R3. When a signature cannot be verified, there is no automation for that process — the manual flow applies. A failed trust attempt tells the user why; blocked attempts from unverifiable processes just remain ordinary candidates.

**Automation behavior**

- R4. While protection is armed, a blocked direct attempt by a trusted app to a plausible server (public unicast IPv4) is whitelisted automatically within a few seconds, so the client's own retry succeeds without user action.
- R5. IPv6 stays fully blocked; automation never approves IPv6 destinations (existing posture unchanged).
- R6. Auto-approvals are rate-capped. At the cap, automation pauses with a visible signal; manual approval keeps working. (Cap value: planning.)
- R7. Automation is hands-off while protection is disarmed — including the boot-session disarm marker — the same "never fight an explicit OFF" rule the watchdog follows.

**Visibility and control**

- R8. Every auto-approval is noticeable, not silent: a transient in-app notice, a journal entry, and a visible "added automatically" marker on the server row.
- R9. Auto-added servers are removable like any others. Removing one excludes that address from future auto-approval (the user's removal is respected); manual approval can still re-add it. *(Default to confirm at plan review.)*
- R10. Revoking trust ("don't trust") stops automation for that app immediately. Servers already approved remain until removed individually.
- R11. The existing manual flow (per-server "allow", manual IP entry) remains unchanged as the universal fallback.

**Candidate-list hygiene**

- R12. Loopback destinations (`::1`, `127.0.0.0/8`) never appear as approval candidates — they are a process talking to itself and were the root cause of the ~1700-request flood. This filter ships regardless of the trust feature.

---

## Acceptance Examples

- AE1. **Rotation survives.** Given v2RayTun is trusted and protection is armed, when the client switches to a pool server never seen before, then new connections work within a few seconds with no user action, and the approval is visible (notice + journal + marked row). Covers R2, R4, R8.
- AE2. **Impostor stays blocked.** Given an app is trusted, when a process with a similar name but a different or missing signature dials a new address, then nothing is auto-approved and the attempt appears as an ordinary manual candidate. Covers R2, R3.
- AE3. **Removal is respected.** Given an auto-added server was removed by the user, when the trusted client dials it again, then it is not auto re-added (manual approval still possible). Covers R9.
- AE4. **Untrust restores manual mode.** Given trust was revoked, when the client rotates to a new server, then the attempt is blocked and surfaces as a manual candidate — today's behavior. Covers R10, R11.
- AE5. **No loopback noise.** Given the VPN client makes loopback self-connections on changing ephemeral ports, then none of them ever appear in the candidate list. Covers R12.
- AE6. **OFF means off.** Given protection is disarmed (toggle or break-glass marker), when a trusted client dials new servers, then nothing is added or persisted until protection is re-armed. Covers R7.

---

## Scope Boundaries

**Deferred for later**

- macOS system notifications for auto-approvals (v1: in-app notice + journal).
- Any auto-revocation heuristics (e.g., distrust after N suspicious approvals).

**Outside this product's identity**

- NetworkExtension rewrite (decided earlier, unchanged).
- Reactive kill-switch (allow-while-up / block-on-drop) — weakens the core zero-leak guarantee.
- Parsing or importing the VPN client's subscription/config to learn servers.
- Any weakening of default-deny for processes that are not signature-verified trusted.

---

## Dependencies / Assumptions

- v2RayTun and its tunnel extension are Developer-ID signed with a stable Team ID — verified live 2026-06-10 (`codesign`: app and `packet-extension-mac.appex` both `2XZUN9L63Z`).
- The root daemon can verify a live process's code signature via the Security framework; API specifics are a planning concern.
- The daemon's observer already attributes blocked direct attempts to the owning process (proved during the incident — it surfaced `PacketTunnel → <ip>:<port>` rows); attributing a pid for signature checks is an extension of existing capability, not new ground.

---

## Outstanding Questions

**Resolve at plan review**

- Confirm the R9 default (removed address ⇒ excluded from auto-approval) — the alternative readings are "removal is temporary, automation may re-add with a notice" and "removal revokes the app's trust entirely".

**Deferred to planning**

- Rate-cap value and window (R6).
- Whether granting trust also immediately approves that app's currently-pending candidates (recommended: yes).
- Exact notice presentation (reuse of the existing transient banner pattern vs a dedicated surface).

---

## Sources / Research

- Incident root-cause and diagnostics: `docs/solutions/integration-issues/vpn-endpoint-rotation-pf-whitelist-blocks-new-connections.md`.
- Decision being revised: `docs/brainstorms/2026-06-07-vpn-kill-switch-macos-requirements.md` (manual per-server approval); related deferred items R35/AE5: `docs/brainstorms/2026-06-08-vpn-kill-switch-reliable-off-requirements.md`.
- PF/anchor architecture the feature builds on: `docs/solutions/tooling-decisions/macos-privileged-daemon-pf-killswitch-setup.md`.
