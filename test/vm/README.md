# Disposable libvirt test VM

The privileged integration suite should run in a disposable VM, not on a
production gateway or a developer workstation. The current development guest
is named `vpnpoold-integration` and uses:

- Ubuntu Server 24.04 LTS;
- 2 vCPUs and 2 GiB RAM;
- a 16 GiB qcow2 volume in libvirt's `default` pool;
- one virtio NIC on libvirt's NAT-only `default` network;
- SSH key authentication for the `ubuntu` user;
- no libvirt autostart.

The guest provisioner installs the exact networking tools exercised by the
daemon, enables the daemon's required IPv4 forwarding sysctl, and installs Go
1.26.5. Run it after copying the repository into the guest:

```sh
sudo ./test/vm/provision.sh
sudo ./test/vm/run-privileged.sh
```

`vpnpoold-e2e.yaml` is a VM-specific one-worker configuration for a temporary
real profile. Install profile and credential copies under
`/run/vpnpoold-e2e` as root-owned mode-`0600` files. Never copy them with the
general source archive. Standard OpenVPN credential files contain the raw
username and password on separate lines; the normalization helper converts a
temporary `username=...` / `password=...` copy without printing either value.

Always stop the daemon after a live test and verify cleanup:

```sh
pgrep -x openvpn
sudo ip netns list
```

Both commands should report no test process or `vpne2e-*` namespace. The live
test configuration binds the host SOCKS listener to loopback and has no
libvirt autostart.

For repeatable multi-worker tests without a commercial VPN dependency,
`openvpn-server/README.md` describes the companion
`vpnpoold-openvpn-server` VM. `vpnpoold-local-server.yaml` connects four
workers to that server and verifies four distinct deterministic test addresses.
The root-only `run-local-server-e2e.sh` test covers control and reload,
management authentication/OTP, all MVP balancing modes, held sessions,
failure withdrawal/recovery, strict firewall/no-fallback behavior, soak, hard
daemon termination, stale-resource recovery, and final cleanup:

```sh
sudo ./test/vm/run-local-server-e2e.sh \
  /path/to/vpnpoold \
  ./test/vm/vpnpoold-local-server.yaml \
  /path/to/vpnpoold-clients
```

Run it only in the disposable integration VM. The client bundle contains
private keys and credentials and must be copied separately from the source
tree with mode-private permissions. Set `VPNPOOLD_SOAK_SECONDS` for a longer
repeated request/status/metrics phase.

`vpnpoold-systemd-local-server.yaml` is the equivalent fixture for validating
the installed `deploy/systemd/vpnpoold.service` unit. It uses the unit's
standard `/etc/vpnpoold`, `/run/vpnpoold`, and `/var/lib/vpnpoold` paths and a
separate namespace/subnet prefix from the transient acceptance test.
It is also the clean-boot and in-place upgrade release fixture. Always stop and
disable the service after those checks and verify that OpenVPN and the
`vpnsys-*` namespaces are gone.

Find the guest address and connect from the host with:

```sh
virsh --connect qemu:///system domifaddr vpnpoold-integration --source lease
ssh ubuntu@GUEST_ADDRESS
```

Lifecycle commands:

```sh
virsh --connect qemu:///system shutdown vpnpoold-integration
virsh --connect qemu:///system start vpnpoold-integration
```

The VM is deliberately not configured to start with the host. Removing it is a
separate, destructive operation and should include both the domain and its
`default/vpnpoold-integration.qcow2` storage volume.
