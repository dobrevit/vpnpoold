# Security policy

`vpnpoold` runs as root, creates network namespaces, rewrites host and namespace
firewall rules, and supervises OpenVPN processes. Its worst failure is not a
crash — it is application traffic leaving through the host's ordinary WAN route
while the daemon still reports the exit as healthy. Reports about that class of
defect are the most valuable ones this project can receive.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository. Do not open
a public issue, and do not describe the defect in a pull request before a fix
exists.

A useful report states which invariant is broken, the conditions that trigger
it, and what an attacker or a failure gains. A proof of concept is welcome but
not required; a precise description of the ordering or state that breaks the
invariant is usually enough.

Expect an acknowledgement, then a fix developed privately and released together
with the disclosure. Reporters are credited unless they ask otherwise.

## Supported versions

This project has not yet reached a stable release. Only the current `main`
branch and the most recent tagged release receive fixes. There is no backport
policy for older tags.

## What is in scope

Anything that breaks one of the documented invariants, in particular:

- worker traffic reaching the internet through the host WAN route rather than
  its tunnel, under any failure, restart, reload or race;
- a worker becoming selectable by the dispatcher before namespace, veth,
  tunnel, route, proxy reachability and public-IP verification have all
  succeeded — or staying selectable after any of them fails;
- an established TCP session being migrated to a different exit;
- credentials, private keys, auth-file contents, raw management-protocol lines
  or whole profile bodies appearing in logs, error messages, metrics or the
  control socket;
- a source `.ovpn` file being modified, or a profile-supplied directive
  achieving code execution;
- argument or nftables injection through a worker ID, interface name,
  namespace name, or any other identifier that reaches a command;
- the public SOCKS listener being reachable without authentication when the
  configuration did not explicitly opt into that;
- privilege escalation through the control socket, the runtime directory, the
  derived-profile directory, or a helper executable the daemon invokes.

## What is not a vulnerability

The daemon is privileged and sits inside the trusted computing base. The
configuration file, OpenVPN profiles, credential files, users file, challenge
helpers, and the `ip`, `nft` and `openvpn` binaries are all administrator-
controlled inputs. An attacker who can already replace any of those has root, so
reports that assume such control describe a compromised host rather than a
defect here.

Also not defects:

- **Rejected profiles.** Source profiles carrying script, plugin, alternate
  route, or file-logging directives are refused deliberately. That is the
  feature, not a bug.
- **Refusal to start on permissive file modes.** Validation rejects profiles,
  credential files and users files whose directories are group- or
  other-writable. This is intentional and is not a usability defect.
- **A non-loopback listener requiring authentication.** Overriding it requires an
  explicit configuration key precisely so it cannot happen by accident.
- **Container escape from a `vpnpoold` image.** Any container running this daemon
  needs `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` and `/dev/net/tun`; such a container is
  not a security boundary and is not documented as one.

## Scope of existing review

`docs/security-review.md` records an internal engineering review with its date,
scope and residual risks. It is not an independent audit or a penetration test,
and it should not be read as one. `docs/security-model.md` documents the threat
model and the implemented mitigations.

The privileged paths — namespace and veth lifecycle, the nftables kill switch,
and OpenVPN supervision — are exercised by a disposable-VM acceptance suite
rather than by CI. Operators must validate a release on their own distribution
and VPN provider before production use.
