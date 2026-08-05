# Architecture

## Process and network model

`vpnpoold daemon` runs on the Linux host. Each configured OpenVPN profile
is assigned a deterministic network namespace, veth pair, and private `/30`.
OpenVPN and `vpnpoold worker-proxy` are separate processes launched inside that
namespace. The worker process embeds microproxy v0.0.1 and enables its SOCKS5
frontend only. The daemon never changes a Go runtime thread's namespace.

The host-side SOCKS5 dispatcher selects only workers whose state snapshot is
both `HEALTHY` and fully verified. A selected TCP connection remains pinned to
one worker for its lifetime.

## Worker startup order

The implemented fail-closed sequence is:

1. allocate deterministic names and addresses;
2. resolve all OpenVPN remote hostnames and create private derived profiles
   with credential-file references and enforced full-tunnel IPv4 routes;
3. clean exact deterministic stale worker resources when configured;
4. enable narrowly limited host forwarding/NAT for resolved OpenVPN endpoints;
5. open the host dispatcher and optional loopback metrics endpoint with an
   empty/unhealthy worker pool;
6. create each namespace, veth, and namespace-specific resolver file;
7. install its bootstrap nftables policy;
8. start OpenVPN on management hold, subscribe to its private Unix management
   socket, release the hold, and require both `CONNECTED,SUCCESS` and a verified
   tunnel route;
9. install active rules, start the namespace worker proxy, and wait until its
   listener accepts TCP;
10. verify consecutive real requests and public IP through the worker;
11. transition to `HEALTHY` and publish it to the dispatcher.

All endpoint resolution and derived-profile preparation complete before a
privileged networking mutation. A dispatcher opened before workers are healthy
fails closed with no selectable backend.

If `health.host_public_ips` is empty, preparation also makes a direct request
to the configured IP-check endpoint with environment proxies disabled. The
observed host address becomes forbidden egress evidence for every worker. The
runtime refreshes this value at `health.interval`; failures retain the last
valid policy.

Before cleanup or networking mutation, the host daemon acquires a Linux
abstract Unix-socket singleton lock. Because the lock belongs to the host
network namespace rather than `runtime.run_dir`, separate configurations cannot
race over the global `vpnpoold_host` nftables table.

The controller treats OpenVPN/tunnel failures, proxy exits, and egress failures
differently:

- OpenVPN or tunnel failure withdraws the worker, installs strict mode, stops
  the proxy, terminates sessions, and waits for the supervisor's next verified
  tunnel generation.
- Proxy failure performs the same withdrawal and strict transition but
  preserves the OpenVPN recovery/control plane and restarts only the proxy with
  bounded backoff.
- Egress verification failure withdraws and blocks the worker, then requests a
  fresh OpenVPN generation before proxy recovery.

Health results carry the proxy activation generation. Results from an older
generation are ignored and cannot republish a failed worker.

Daemon-owned management directives are removed only from private derived
profiles, preventing source-profile TCP management listeners or conflicting
hold settings from taking effect. Source `.ovpn` files remain unchanged.
Potentially executable source directives—scripts, plugins, alternate route
programs, and file-logging hooks—are rejected. The management client can answer
configured username/password, private-key password, static challenge, dynamic
challenge, and `CR_TEXT` prompts. Challenge helpers are trusted executables
invoked directly with bounded JSON, output, timeout, and a minimal environment.
Raw protocol lines and secret values are never included in logs or errors.
Any unconfigured or malformed prompt fails closed.

## Namespace firewall states

- `bootstrap`: loopback, veth-side established traffic, and new OpenVPN control
  traffic to pre-resolved endpoint IP/port tuples.
- `active`: bootstrap allowances plus tunnel egress/replies and host access to
  the worker proxy port.
- `strict`: bootstrap control-plane allowances only; no tunnel egress and no
  new proxy connections.

Every base chain has a drop policy. Connection-tracking allowances are scoped
to an interface; strict mode does not contain a generic established-flow rule.
Rule replacement is sent as one nftables transaction.

Configured `network.dns_servers` are written to
`/etc/netns/${namespace}/resolv.conf`. `ip netns exec` exposes that file only
inside the matching namespace. Bootstrap and strict firewall states block
resolver traffic; it can leave only through the tunnel in active mode.

## Selection

The selection package filters unhealthy and draining workers before every
choice. It implements weighted round robin, weighted least-connections, and
weighted rendezvous hashing for source, username, and session keys. Removing a
worker from a rendezvous set only remaps keys that selected that worker.

The dispatcher terminates the client-side SOCKS5 handshake and optional
username/password authentication. For `session_hash`, `alice/session-123`
authenticates as `alice` and hashes `session-123`. It then opens the destination
through one namespace worker. Backend retries are permitted only before the
dispatcher returns SOCKS5 CONNECT success; afterward the connection remains
pinned. Transport or protocol failure marks the matching worker generation
unhealthy immediately, while an ordinary destination refusal does not.

When a worker configures `upstream_http_proxy`, microproxy routes its namespace
SOCKS connection through a bounded, unauthenticated HTTP `CONNECT` tunnel to
that explicit in-tunnel IP and port instead of dialing the destination
directly. Destination hostnames are then resolved by the in-tunnel proxy,
never by the host. Ambient `HTTP_PROXY` variables are ignored, the listener
allows only the host-side veth address, and the configured handshake, connect,
and per-I/O timeouts remain enforced by the vpnpoold adapter.

## Local control plane

The daemon owns a mode-`0600` Unix socket inside the mode-`0700`
`${runtime.run_dir}`. It also verifies same-UID Unix peer credentials before
processing a request. The current bounded, newline-delimited JSON
protocol exposes worker status, transactional reload, and
enable/disable/drain/undrain/restart actions. `vpnpoold status` reports state,
transition and last-healthy times, reason,
availability, draining, verified public IP, recovery counters, health-check
counters, active/total connections, selections, and byte counts. Draining
stops new assignments without terminating established sessions. Restart
immediately withdraws the worker, closes its sessions, installs strict mode,
and requests a new VPN generation. Disable persists as an operator override
across reloads and performs fail-closed teardown; enable permits a fresh,
fully verified startup. A non-socket filesystem entry is never removed to make
way for the listener.

The optional Prometheus endpoint binds only to an IP-literal loopback address.
It exposes the same bounded operational counters but deliberately excludes
public IPs and all client/session/destination values.

## Transactional reload

`SIGHUP` prepares a complete candidate runtime without privileged networking
mutation while the current generation remains live. Cutover stops the old
generation fail-closed, activates the candidate's host firewall, SOCKS,
control, and metrics listeners, and only then retires the old derived profiles.
Activation failure restarts the exact retained old runtime. Invalid candidates
never interrupt current traffic.
