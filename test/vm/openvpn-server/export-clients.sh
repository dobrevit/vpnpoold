#!/bin/sh
set -eu

if [ "$#" -gt 1 ]; then
	echo "usage: export-clients.sh [OUTPUT_DIRECTORY]" >&2
	exit 2
fi

output_directory=${1:-.local/openvpn-test-server}
server_ip=192.168.122.50
if [ -e "$output_directory" ]; then
	echo "refusing to overwrite existing client export: $output_directory" >&2
	exit 1
fi

umask 077
temporary_directory=$(mktemp -d)
cleanup() {
	rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

scp -q -r "ubuntu@$server_ip:vpnpoold-clients" "$temporary_directory/"
mkdir -p "$(dirname "$output_directory")"
mv "$temporary_directory/vpnpoold-clients" "$output_directory"
chmod 0700 "$output_directory"
find "$output_directory" -type f -exec chmod 0600 {} +
echo "private client profiles exported to $output_directory"
