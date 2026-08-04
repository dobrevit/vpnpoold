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
