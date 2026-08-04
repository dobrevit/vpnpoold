# Testing

Run the unprivileged suite and static checks:

```sh
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
```

The integration suite is excluded from ordinary test runs. On a disposable
Linux test host with `iproute2` and `nftables`, run:

```sh
sudo -E env VPNPOOLD_INTEGRATION=1 go test -tags=integration ./test/integration -v
```

The current integration test creates a deterministic namespace and veth pair,
installs strict default-drop nftables rules, verifies an attempted direct TCP
connection from the namespace to its host-side veth address is blocked, and
then deletes the resources. Cleanup is registered before firewall setup.

For a reproducible local target, `test/vm/README.md` describes the disposable
Ubuntu 24.04 libvirt guest. Inside a fresh copy of the repository, provision
and run all checks with:

```sh
sudo ./test/vm/provision.sh
sudo ./test/vm/run-privileged.sh
```

Never run privileged integration tests on a production gateway without first
reviewing the exact resource names and rules.

## Local OpenVPN failure acceptance test

The companion server documented in `test/vm/openvpn-server/README.md` removes
the dependency on a commercial provider. Its four profiles can exercise the
complete daemon, including disruptive recovery scenarios, from the disposable
integration VM:

```sh
sudo ./test/vm/run-local-server-e2e.sh \
  /path/to/vpnpoold \
  ./test/vm/vpnpoold-local-server.yaml \
  /path/to/vpnpoold-clients
```

This opt-in test verifies four unique healthy exits, human and JSON status,
enable/disable controls, valid reload, invalid-reload rollback, management
username/password and static OTP, least-connections under held sessions,
authenticated username/session rendezvous hashing and minimal remapping,
bad-password rejection, held-session termination, proxy-process failure,
OpenVPN failure with the server route deliberately blocked, strict
default-drop firewall rules, absence of namespace fallback, re-verification
before recovery, ungraceful daemon termination, stale namespace cleanup, and
final process/namespace cleanup.

Set `VPNPOOLD_SOAK_SECONDS` to run repeated dispatcher, status, and metrics
checks for the requested duration. The release acceptance run uses 30 seconds;
operators can use a longer value on their target host:

```sh
sudo VPNPOOLD_SOAK_SECONDS=1800 ./test/vm/run-local-server-e2e.sh \
  /path/to/vpnpoold \
  ./test/vm/vpnpoold-local-server.yaml \
  /path/to/vpnpoold-clients
```

The systemd fixture is separately installed and exercised across an in-place
restart upgrade and a VM reboot. After boot, wait for all four workers to be
healthy, assert exactly four OpenVPN processes and namespaces, then stop the
service and assert both counts return to zero. These are manual privileged
release gates because CI runners do not provide the companion libvirt VMs.
