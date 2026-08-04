#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "provision.sh must run as root" >&2
	exit 1
fi
if [ "$#" -ne 1 ]; then
	echo "usage: provision.sh ASSET_DIRECTORY" >&2
	exit 2
fi

asset_directory=$1
for asset in server.conf check-auth.py ip-echo.py \
	vpnpoold-test-ip-echo.service nftables.conf; do
	if [ ! -f "$asset_directory/$asset" ]; then
		echo "missing server asset: $asset" >&2
		exit 1
	fi
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
	ca-certificates \
	easy-rsa \
	nftables \
	openvpn \
	openssl \
	python3

install -d -m 0700 /etc/openvpn/server /etc/openvpn/server/ccd
install -d -m 0700 /var/lib/openvpn/server
install -d -m 0755 /usr/local/libexec
install -m 0600 "$asset_directory/server.conf" /etc/openvpn/server/server.conf
install -m 0700 "$asset_directory/check-auth.py" /etc/openvpn/server/check-auth.py
install -m 0755 "$asset_directory/ip-echo.py" /usr/local/libexec/vpnpoold-test-ip-echo
install -m 0644 "$asset_directory/vpnpoold-test-ip-echo.service" \
	/etc/systemd/system/vpnpoold-test-ip-echo.service

uplink=$(ip -4 route show default | awk 'NR == 1 {print $5}')
case "$uplink" in
	""|*[!A-Za-z0-9_.-]*)
		echo "could not determine a safe uplink interface" >&2
		exit 1
		;;
esac
sed "s/@UPLINK@/$uplink/g" "$asset_directory/nftables.conf" >/etc/nftables.conf
chmod 0644 /etc/nftables.conf

printf '%s\n' 'net.ipv4.ip_forward=1' >/etc/sysctl.d/90-vpnpoold-test-server.conf
sysctl --system >/dev/null

easy_rsa_directory=/etc/openvpn/server/easy-rsa
if [ ! -f /etc/openvpn/server/pki/ca.crt ]; then
	install -d -m 0700 "$easy_rsa_directory"
	cp -a /usr/share/easy-rsa/. "$easy_rsa_directory/"
	(
		cd "$easy_rsa_directory"
		EASYRSA_BATCH=1 EASYRSA_REQ_CN=vpnpoold-test-ca ./easyrsa init-pki
		EASYRSA_BATCH=1 EASYRSA_REQ_CN=vpnpoold-test-ca ./easyrsa build-ca nopass
		EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass
		for user in user1 user2 user3 user4; do
			EASYRSA_BATCH=1 ./easyrsa build-client-full "$user" nopass
		done
		EASYRSA_BATCH=1 ./easyrsa gen-dh
	)
	mv "$easy_rsa_directory/pki" /etc/openvpn/server/pki
	openvpn --genkey secret /etc/openvpn/server/tls-crypt.key
	chmod 0600 /etc/openvpn/server/tls-crypt.key
fi

users_file=/etc/openvpn/server/users
if [ ! -f "$users_file" ]; then
	umask 077
	: >"$users_file"
	for user in user1 user2 user3 user4; do
		password=$(openssl rand -hex 18)
		printf '%s:%s\n' "$user" "$password" >>"$users_file"
	done
fi
chmod 0600 "$users_file"

client_number=10
for user in user1 user2 user3 user4; do
	printf 'ifconfig-push 10.250.0.%d 255.255.255.0\n' "$client_number" \
		>"/etc/openvpn/server/ccd/$user"
	chmod 0600 "/etc/openvpn/server/ccd/$user"
	client_number=$((client_number + 1))
done

bundle_directory=/home/ubuntu/vpnpoold-clients
install -d -o ubuntu -g ubuntu -m 0700 "$bundle_directory"
for user in user1 user2 user3 user4; do
	password=$(awk -F: -v user="$user" '$1 == user {print $2}' "$users_file")
	profile="$bundle_directory/$user.ovpn"
	credentials="$bundle_directory/$user.credentials"
	{
		printf '%s\n' \
			'client' \
			'dev tun' \
			'proto udp' \
			'remote 192.168.122.50 1194' \
			'resolv-retry infinite' \
			'nobind' \
			'persist-key' \
			'persist-tun' \
			'remote-cert-tls server' \
			'verify-x509-name server name' \
			'data-ciphers AES-256-GCM:AES-128-GCM' \
			'auth SHA256' \
			'auth-user-pass' \
			'verb 3' \
			'<ca>'
		sed -n '/BEGIN CERTIFICATE/,$p' /etc/openvpn/server/pki/ca.crt
		printf '%s\n' '</ca>' '<cert>'
		sed -n '/BEGIN CERTIFICATE/,$p' "/etc/openvpn/server/pki/issued/$user.crt"
		printf '%s\n' '</cert>' '<key>'
		cat "/etc/openvpn/server/pki/private/$user.key"
		printf '%s\n' '</key>' '<tls-crypt>'
		cat /etc/openvpn/server/tls-crypt.key
		printf '%s\n' '</tls-crypt>'
	} >"$profile"
	printf '%s\n%s\n' "$user" "$password" >"$credentials"
	chown ubuntu:ubuntu "$profile" "$credentials"
	chmod 0600 "$profile" "$credentials"
done

systemctl daemon-reload
systemctl enable nftables.service openvpn-server@server.service vpnpoold-test-ip-echo.service
systemctl restart nftables.service
systemctl restart openvpn-server@server.service
systemctl restart vpnpoold-test-ip-echo.service

systemctl is-active --quiet openvpn-server@server.service
systemctl is-active --quiet vpnpoold-test-ip-echo.service
test "$(sysctl -n net.ipv4.ip_forward)" = 1
test -c /dev/net/tun
echo "vpnpoold OpenVPN test server is ready with four client identities"
