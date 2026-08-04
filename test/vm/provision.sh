#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "provision.sh must run as root" >&2
	exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
	ca-certificates \
	curl \
	gcc \
	git \
	iproute2 \
	jq \
	make \
	nftables \
	openvpn

printf '%s\n' 'net.ipv4.ip_forward=1' >/etc/sysctl.d/90-vpnpoold-integration.conf
sysctl --system >/dev/null

go_version=1.26.5
go_archive="go${go_version}.linux-amd64.tar.gz"
go_sha256=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053

if [ ! -x /usr/local/go/bin/go ] ||
	[ "$(/usr/local/go/bin/go version | awk '{print $3}')" != "go${go_version}" ]; then
	temp_dir=$(mktemp -d)
	trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM

	curl --fail --location --retry 3 \
		--output "$temp_dir/$go_archive" \
		"https://go.dev/dl/$go_archive"
	printf '%s  %s\n' "$go_sha256" "$temp_dir/$go_archive" |
		sha256sum --check -

	rm -rf /usr/local/go
	tar -C /usr/local -xzf "$temp_dir/$go_archive"
fi

ln -sfn /usr/local/go/bin/go /usr/local/bin/go
ln -sfn /usr/local/go/bin/gofmt /usr/local/bin/gofmt

go version
ip -Version
nft --version
openvpn --version | sed -n '1p'
