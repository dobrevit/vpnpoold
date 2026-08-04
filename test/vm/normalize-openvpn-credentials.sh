#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "normalize-openvpn-credentials.sh must run as root" >&2
	exit 1
fi
if [ "$#" -ne 2 ]; then
	echo "usage: normalize-openvpn-credentials.sh INPUT OUTPUT" >&2
	exit 2
fi

input=$1
output=$2
temporary=$(mktemp "${output}.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
umask 077

awk '
NR == 1 && /^username=./ {
	sub(/^username=/, "")
	print
	next
}
NR == 2 && /^password=./ {
	sub(/^password=/, "")
	print
	next
}
{ exit 1 }
END {
	if (NR != 2) exit 1
}
' "$input" >"$temporary"

chown root:root "$temporary"
chmod 600 "$temporary"
mv "$temporary" "$output"
trap - EXIT HUP INT TERM
