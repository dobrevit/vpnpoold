# Troubleshooting

## Configuration validation fails

Run `vpnpoold validate --config PATH`. Validation intentionally checks that the
OpenVPN binary is executable, the profiles directory exists, and each `.ovpn`
base filename names a private regular file. Profile, credential, and users
files may not be symlinks; their immediate directories may not be writable by
group or other users. The OpenVPN binary and configured challenge helpers must
also be non-writable regular executables. The daemon never rewrites profiles.

Profiles containing executable OpenVPN hooks are deliberately rejected. This
includes script/plugin directives, alternate route executables, and
profile-controlled logging/status paths. Remove such hooks or place the
required behavior under daemon control; do not weaken source-profile
inspection to make an untrusted profile run.

A non-loopback `proxy.listen` is rejected unless authentication is enabled with
an existing users file, or `allow_insecure_public_listener` is explicitly set.
The latter creates an open-proxy risk.

When authentication is enabled, the users file must be a regular file with no
group or other permissions, normally mode `0600`. It accepts only bcrypt hashes
with cost 10 or greater. For `session_hash`, clients use the
`username/session-id` convention.

An OpenVPN `credentials_file` must be absolute, regular, not a symlink, and
inaccessible to group and other users. OpenVPN expects exactly two raw lines:
username followed by password. The daemon places only its path in the private
derived profile and never modifies the source `.ovpn`.

OpenVPN management settings in a source profile are omitted from the private
derived copy. The daemon owns one Unix management socket per worker, holds
startup until it has subscribed to state events, and still verifies the kernel
tunnel and routes after `CONNECTED,SUCCESS`.

Set `workers[].management.username_password` when OpenVPN should request the
two-line `credentials_file` through management. An encrypted client key can
use a private one-line `private_key_password_file`. OTP and challenge providers
use an absolute `challenge_response_command`; the executable receives one
bounded JSON object on stdin and must return exactly one response line before
`challenge_timeout`. Run the helper manually with representative JSON if
OpenVPN repeatedly returns to authentication. Its stderr and response are
intentionally absent from daemon errors, so helper-side diagnostics must also
avoid secrets.

## Worker reaches the VPN but not destinations

The derived profile enforces both IPv4 `/1` routes through the tunnel. If the
VPN does not provide DNS, configure reachable `network.dns_servers`; public
resolvers may be intentionally blocked by private VPNs.

If the VPN requires an in-tunnel HTTP proxy, set the worker's
`upstream_http_proxy` to an explicit address such as `192.168.1.1:3128`.
Authentication is not currently supported. A TCP timeout at that address
indicates VPN routing, firewall, or proxy-listener reachability rather than a
SOCKS dispatcher failure.

## Privileged tests are skipped

The namespace suite requires Linux, root, `ip`, `nft`, the `integration` build
tag, and `VPNPOOLD_INTEGRATION=1`. A normal `go test ./...` does not run it.

## Namespace creation fails

Check that network namespaces are enabled, `/run/netns` is usable, and the
calling process has `CAP_NET_ADMIN`. Run `ip netns list` and remove only stale
resources whose names were produced by the configured vpnpoold prefix.

## nftables application fails

Confirm the host kernel provides nftables and that `nft` works inside a newly
created network namespace. `vpnpoold` does not fall back to permissive iptables
rules.

## Status cannot connect

Run `vpnpoold status --config PATH` as root. It reads
`${runtime.run_dir}/control.sock`. The directory must be mode `0700`, the
socket is mode `0600`, and the daemon accepts only same-UID peers. If the
daemon is not running, no socket should remain after clean shutdown. The daemon
refuses to replace a regular file or symlink at that path; inspect such an entry
before removing it manually.

## A reload was rejected

Use `vpnpoold reload --config PATH` and inspect the journal. Decode,
filesystem, profile, remote-resolution, and derived-profile checks occur before
the live generation is interrupted. An invalid candidate therefore leaves the
current workers running. Activation failures trigger restoration of the exact
retained generation; status shows the active generation after recovery.
