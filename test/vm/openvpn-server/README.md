# Disposable local OpenVPN server

This VM provides four independent, test-only OpenVPN client identities for
repeatable `vpnpoold` acceptance tests. It is named
`vpnpoold-openvpn-server`, uses `192.168.122.50` on libvirt's `default`
network, and has no libvirt autostart.

The provisioner creates a private CA, separate client certificates, and random
username/password credentials. Authentication uses OpenVPN's `via-file` mode
with temporary files in `/dev/shm`; passwords are not placed in process
environment variables. The disposable server also accepts the fixed test OTP
`246810` when a client uses the static-challenge profile variant; it must never
be reused outside this isolated fixture.

The VPN network is `10.250.0.0/24`. Each identity receives a fixed tunnel
address. A VPN-side HTTP endpoint at `http://10.250.0.1:8080/ip` maps those
addresses to distinct RFC 5737 documentation addresses:

| Identity | Tunnel address | Reported test address |
| --- | --- | --- |
| `user1` | `10.250.0.10` | `198.51.100.10` |
| `user2` | `10.250.0.11` | `198.51.100.11` |
| `user3` | `10.250.0.12` | `198.51.100.12` |
| `user4` | `10.250.0.13` | `198.51.100.13` |

These are intentionally not real public addresses. They are accepted as
global-unicast evidence by the application while remaining non-routable on the
Internet. The server also NATs client traffic to its libvirt uplink for general
test destinations, but all such traffic shares the VM's real external egress.

Create the VM from an Ubuntu 24.04 cloud image:

```sh
./test/vm/openvpn-server/create-vm.sh \
  ~/Downloads/vpnpoold-vm/ubuntu-24.04-server-cloudimg-amd64.img
```

After SSH becomes available, copy this directory and provision:

```sh
scp -r test/vm/openvpn-server ubuntu@192.168.122.50:/tmp/
ssh ubuntu@192.168.122.50 \
  'sudo /tmp/openvpn-server/provision.sh /tmp/openvpn-server'
```

Export the generated profiles and credentials to the ignored, mode-private
local directory:

```sh
./test/vm/openvpn-server/export-clients.sh
```

Never commit `.local/openvpn-test-server`; every profile contains a private
client key. Credential files contain the raw username and generated password
on separate lines, ready for `workers[].credentials_file`.

After a test, stop `vpnpoold` and verify that the client VM has no remaining
OpenVPN process or namespace. UDP has no connection teardown handshake that a
server can rely on, so an abruptly stopped client can remain in
`server.status` until the configured keepalive expires (at most about 30
seconds on this test server).

The local `vpnpoold` health URL for these profiles is:

```yaml
health:
  ip_check_url: http://10.250.0.1:8080/ip
```

The test HTTP service also exposes `/hold`. It keeps connections open so the
acceptance test can observe live least-connections accounting and prove that
worker failure terminates already-established sessions.

Lifecycle:

```sh
virsh --connect qemu:///system shutdown vpnpoold-openvpn-server
virsh --connect qemu:///system start vpnpoold-openvpn-server
```

Removing the VM is intentionally separate and destructive. Remove the domain,
`default/vpnpoold-openvpn-server.qcow2`, and the matching DHCP reservation from
the `default` libvirt network only when the test server is no longer wanted.
