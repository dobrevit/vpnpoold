# Deployment notes

The included systemd unit launches the composed daemon and is a reviewed
starting point. Do not treat it as production-validated until the privileged
integration suite and the unit itself pass on the target distribution.

The MVP runs as root with a capability bounding set containing:

- `CAP_NET_ADMIN` for veths, routes, interfaces, and nftables;
- `CAP_NET_RAW` for common tunnel/network diagnostics;
- `CAP_SYS_ADMIN` because `ip netns add` manages named namespace mounts.

The unit creates the runtime directory with mode `0700` and permits writes only
to the daemon state directory, runtime directory,
`/run/netns`, and `/etc/netns`. The latter contains the namespace-specific
`resolv.conf` files consumed by `ip netns exec`; create it during installation:

```sh
sudo install -d -m 0755 /etc/netns
```

`/run/netns` is volatile. The installer installs
`deploy/tmpfiles/vpnpoold.conf`, and the unit starts after
`systemd-tmpfiles-setup.service`, so the path exists before systemd constructs
the service sandbox on a clean boot.

The unit restricts address families to Unix, IPv4, IPv6, and netlink. These
assumptions must be tested under the target systemd and OpenVPN versions;
capability behavior can differ by distribution.

`KillMode=mixed` is intentional. During an ordinary service stop, systemd
signals only the main daemon so it can withdraw workers, apply strict
firewalls, and gracefully terminate OpenVPN and proxy children in order. If
that sequence exceeds `TimeoutStopSec`, systemd force-kills any remaining
processes in the service cgroup.

Before installation:

```sh
make check
make check-host
sudo -E env VPNPOOLD_INTEGRATION=1 go test -tags=integration ./test/integration -v
```

The last command is intentionally opt-in and creates network resources.

After editing the configuration, reload with:

```sh
sudo systemctl reload vpnpoold
```

The unit sends `SIGHUP`. A rejected candidate leaves the current generation
running; inspect the journal for the validation or activation error.

## Packages

Releases ship `.deb`, `.rpm` and `.apk` packages for `amd64` and `arm64`
alongside the tarballs. Packages install the binary to `/usr/sbin/vpnpoold` and
the unit to `/usr/lib/systemd/system/`, where the manual `deploy/install.sh`
path uses `/usr/local/sbin`. Both are rendered from one unit template,
`deploy/systemd/vpnpoold.service.in`.

A package never enables, starts, or restarts the service. Restarting drops
every tunnel and terminates every established session, so activating an
upgraded binary stays an explicit operator action:

```sh
sudo systemctl restart vpnpoold
```

Packages create `/etc/vpnpoold` as `0750` and `profiles`/`credentials` as
`0700`. Those modes are required, not stylistic: configuration validation
refuses a profile or credential file whose directory is group- or
other-writable, so a permissive directory produces a daemon that will not
start. Only `*.example` configurations are shipped, and the unit's
`ConditionPathExists` keeps the service inert until an operator writes a real
`/etc/vpnpoold/vpnpoold.yaml`.

## Containers

Running `vpnpoold` in a container is possible but provides no security benefit,
and it is not a supported production path. systemd remains the supported
deployment.

`test/container/spike.sh` measures what a container actually requires. On a
Debian 12 image with `--device /dev/net/tun` and
`--sysctl net.ipv4.ip_forward=1`:

| Capabilities | Result |
|---|---|
| `NET_ADMIN`, `SYS_ADMIN` | `ip netns add` **fails** — the host's container AppArmor profile denies the bind mount |
| the same, plus `--security-opt apparmor=unconfined` | every check passes: namespace creation, `ip netns exec`, veth into the namespace, `nft -f -`, and the forwarding sysctl |

So a container that can run this daemon needs `CAP_SYS_ADMIN`, `/dev/net/tun`,
and AppArmor confinement lifted. `CAP_SYS_ADMIN` together with the ability to
mount is a realistic escape path, which means such a container isolates nothing
that the daemon's own network namespaces do not already isolate. Do not present
it as a security boundary.

If an image is ever built, prefer `--network host`. The daemon's singleton lock
is an abstract Unix socket scoped to the *network* namespace and its
`vpnpoold_host` nftables table is global to that namespace, so under
`--network host` both behave exactly as designed and as tested. With a private
container network namespace, two instances each believe they are the sole
firewall owner and worker egress is NATed twice — a topology no existing test
covers.

The one genuine argument for an image is testing, not deployment: if these
checks also hold on a GitHub-hosted runner, part of the acceptance matrix that
`docs/testing.md` records as a manual disposable-VM gate could become a CI gate.
Run the `container-spike` workflow manually to gather that evidence.
