# Focused stable-MVP security review

Review date: 2026-07-27

Scope: the Linux daemon, source-profile handling, OpenVPN management channel,
namespace/firewall lifecycle, SOCKS5 data path, local control/metrics surfaces,
systemd deployment, dependencies, and the disposable Ubuntu 24.04 acceptance
environment. This is an internal engineering review, not an independent
penetration test or security audit.

## Threat boundaries and conclusions

The principal invariant is fail-closed egress: namespace application traffic
must never fall back through the host WAN. Each worker has a separate network
namespace and default-drop nftables policy. Bootstrap and strict modes permit
only validated OpenVPN recovery endpoint tuples; the worker proxy is started
only after the tunnel and route are verified. Any VPN, tunnel, route, proxy, or
egress-verification failure removes the worker from dispatch, applies strict
mode, and terminates its active sessions.

The daemon itself is privileged and is inside the trusted computing base.
Configuration, profiles, credential files, users files, challenge helpers,
OpenVPN, `ip`, and `nft` must be controlled by the administrator. A party able
to replace the daemon or these root-controlled inputs already has an equivalent
privilege boundary.

## Review findings closed

- Source `.ovpn` files are private, regular, non-symlink files in a directory
  that group and other users cannot modify. Open uses before/opened/after
  identity checks to resist replacement races.
- Profiles are parsed before privileged mutation. Script, plugin,
  alternate-route-program, logging, status, daemonization, and other
  profile-controlled execution/file-output directives are rejected. Derived
  profiles set OpenVPN script security level 1 and replace daemon-owned
  management and route directives without changing source files.
- OpenVPN and configured challenge-helper paths must be absolute, regular,
  executable, and not writable by group or other users. Child processes receive
  an explicit minimal environment and are launched directly, never through a
  shell.
- Credential and bcrypt users files require private permissions, non-symlink
  identity, bounded reads, and non-writable immediate parent directories.
- Management username/password and encrypted-key secrets are loaded only on
  demand. Static, dynamic, and `CR_TEXT` challenges use bounded JSON input,
  bounded one-line output, a deadline, and errors that exclude helper output,
  raw management lines, paths, and secret values.
- The public SOCKS listener defaults to loopback. A non-loopback listener
  requires bcrypt authentication or a conspicuous insecure override.
- Control uses a mode-`0600` Unix socket with bounded JSON messages. Worker
  identifiers and actions are validated. Disable/restart immediately remove a
  worker and terminate its sessions; reload retains or restores a complete old
  generation until the candidate is active.
- Metrics require an IP-literal loopback listener and expose only bounded,
  configured worker labels. They exclude clients, destinations, public IPs,
  profile paths, and credentials.
- The systemd unit limits capabilities to network administration/raw access
  and named-network-namespace mount creation, restricts writable paths and
  address families, blocks broad syscall classes, applies kernel/proc
  protections, and creates volatile namespace directories through tmpfiles.

## Verification evidence

- `go test ./...`, `go test -race ./...`, `go vet ./...`, format checks, script
  syntax checks, and release builds are CI gates.
- `govulncheck ./...` reports no reachable or imported-package vulnerability.
  Its verbose module inventory notes `GO-2026-5932` in
  `golang.org/x/crypto/openpgp`; vpnpoold imports `bcrypt`, not `openpgp`, so
  there is no scanned call path. The direct `x/crypto` dependency is current
  at review time.
- `systemd-analyze verify` passes. `systemd-analyze security` scores the
  installed unit 3.1 (`OK`) on the Ubuntu 24.04 guest. This heuristic score is
  evidence of hardening, not proof of isolation.
- The root integration test verifies default-drop namespace rules and blocked
  direct fallback.
- The four-worker acceptance test verifies unique exits; management
  authentication and OTP; enable/disable and reload rollback; live
  least-connections; authenticated rendezvous stability/minimal remapping;
  held-session termination; immediate proxy/VPN withdrawal; strict
  no-fallback rules; verified recovery; soak; crash/stale recovery; and zero
  residual processes/namespaces.
- A packaged binary passed fresh install, in-place restart upgrade with
  rollback machinery enabled, hardened service startup, and VM reboot recovery
  to exactly four workers without duplicates.

## Residual risks and release gates

- Named network namespaces require `CAP_SYS_ADMIN` on the reviewed target.
  Systemd reduces the surrounding surface, but compromise of the root daemon
  remains high impact. Removing this capability would require a different
  namespace ownership/deployment design.
- Go strings and subprocess pipes can transiently hold secrets. Buffers are
  bounded and mutable byte slices are cleared where practical, but the runtime
  cannot guarantee `mlock`, non-copying, or complete memory erasure.
- Challenge helpers are administrator-trusted code executed by the privileged
  daemon. Keep them small, root-owned, non-writable, secret-safe, and free of
  network/file behaviors not required for the provider.
- The source-profile denylist deliberately rejects advanced provider hooks.
  Every exception needs a separate threat review; silently permitting scripts
  or plugins is not acceptable.
- Only SOCKS5 TCP `CONNECT` is supported. UDP, HTTP CONNECT at the public
  listener, transparent routing, and session migration are outside the MVP.
  The namespace worker embeds microproxy, whose HTTP/HTTPS frontend is not
  opened by vpnpoold. Privoxy or another HTTP-to-SOCKS adapter can still be
  deployed separately, but it becomes an additional authentication, DNS,
  logging, and exposure boundary.
- The principal live target was Ubuntu 24.04 with the project test OpenVPN
  server, plus a real-provider path. Before production, repeat host validation,
  privileged tests, systemd startup/reboot, provider authentication, DNS,
  upstream-proxy, leak, and failure tests on the exact kernel, nftables,
  iproute2, systemd, OpenVPN, and VPN-provider combination.

Relevant upstream behavior is documented in the
[OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html).
The vulnerability scan uses the Go team's
[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), which
reports vulnerabilities affecting call paths in Go binaries rather than merely
matching module versions.
