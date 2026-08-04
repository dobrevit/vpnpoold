#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	echo "usage: create-vm.sh UBUNTU_CLOUD_IMAGE [SSH_PUBLIC_KEY]" >&2
	exit 2
fi

cloud_image=$1
ssh_public_key=${2:-"$HOME/.ssh/id_rsa.pub"}
connection=qemu:///system
domain=vpnpoold-openvpn-server
volume_name=vpnpoold-openvpn-server.qcow2
volume=/var/lib/libvirt/images/$volume_name
server_mac=52:54:00:76:70:6e
server_ip=192.168.122.50

if [ ! -f "$cloud_image" ] || [ ! -f "$ssh_public_key" ]; then
	echo "cloud image and SSH public key must be regular files" >&2
	exit 1
fi
if virsh --connect "$connection" dominfo "$domain" >/dev/null 2>&1; then
	echo "domain already exists: $domain" >&2
	exit 1
fi
if [ -e "$volume" ]; then
	echo "storage volume already exists: $volume" >&2
	exit 1
fi
if virsh --connect "$connection" net-dumpxml default |
	grep -Eq "$server_mac|$server_ip"; then
	echo "the requested DHCP reservation already exists" >&2
	exit 1
fi

reservation="<host mac='$server_mac' name='$domain' ip='$server_ip'/>"
reservation_added=0
volume_created=0
cleanup() {
	if virsh --connect "$connection" dominfo "$domain" >/dev/null 2>&1; then
		virsh --connect "$connection" destroy "$domain" >/dev/null 2>&1 || true
		virsh --connect "$connection" undefine "$domain" --nvram >/dev/null 2>&1 || true
	fi
	if [ "$volume_created" -eq 1 ]; then
		virsh --connect "$connection" vol-delete "$volume_name" \
			--pool default >/dev/null 2>&1 || true
	fi
	if [ "$reservation_added" -eq 1 ]; then
		virsh --connect "$connection" net-update default delete ip-dhcp-host \
			"$reservation" --live --config >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT HUP INT TERM

virsh --connect "$connection" net-update default add ip-dhcp-host \
	"$reservation" --live --config
reservation_added=1

virsh --connect "$connection" vol-create-as default "$volume_name" 4G \
	--format qcow2
volume_created=1
virsh --connect "$connection" vol-upload "$volume_name" "$cloud_image" \
	--pool default --sparse
virsh --connect "$connection" vol-resize "$volume_name" 12G --pool default

virt-install \
	--connect "$connection" \
	--name "$domain" \
	--memory 1536 \
	--vcpus 2 \
	--cpu host-passthrough \
	--import \
	--os-variant ubuntu24.04 \
	--disk "path=$volume,format=qcow2,bus=virtio" \
	--network "network=default,model=virtio,mac=$server_mac" \
	--graphics none \
	--console pty,target_type=serial \
	--channel unix,target_type=virtio,name=org.qemu.guest_agent.0 \
	--cloud-init "clouduser-ssh-key=$ssh_public_key,disable=on" \
	--noautoconsole

trap - EXIT HUP INT TERM
echo "$domain created at $server_ip without libvirt autostart"
