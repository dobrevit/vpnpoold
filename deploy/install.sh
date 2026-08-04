#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: install.sh VPNPOOLD_BINARY" >&2
	exit 2
fi

binary=$1
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_directory=$(CDPATH= cd -- "$script_directory/.." && pwd)
destination_root=${DESTDIR:-}

case "$destination_root" in
""|/*) ;;
*)
	echo "DESTDIR must be empty or absolute" >&2
	exit 2
	;;
esac
if [ -z "$destination_root" ] && [ "$(id -u)" -ne 0 ]; then
	echo "install.sh must run as root unless DESTDIR is set" >&2
	exit 1
fi
if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
	echo "VPNPOOLD_BINARY must be an executable regular file" >&2
	exit 1
fi

"$binary" version >/dev/null
config=$destination_root/etc/vpnpoold/vpnpoold.yaml
if [ -f "$config" ]; then
	"$binary" validate -config "$config"
fi

sbindir=$destination_root/usr/local/sbin
docdir=$destination_root/usr/local/share/doc/vpnpoold
unitdir=$destination_root/etc/systemd/system
tmpfilesdir=$destination_root/usr/lib/tmpfiles.d
configdir=$destination_root/etc/vpnpoold
target=$sbindir/vpnpoold
previous=$sbindir/vpnpoold.previous
stage=$sbindir/.vpnpoold.install.$$

install -d -m 0755 "$sbindir" "$docdir" "$unitdir" "$tmpfilesdir"
install -d -m 0750 "$configdir"
install -d -m 0700 "$configdir/profiles" "$configdir/credentials"
install -d -m 0755 "$destination_root/etc/netns"
install -m 0755 "$binary" "$stage"
trap 'rm -f "$stage"' EXIT HUP INT TERM

if [ -f "$target" ]; then
	mv -f "$target" "$previous"
fi
mv "$stage" "$target"
trap - EXIT HUP INT TERM

install -m 0644 "$project_directory/deploy/systemd/vpnpoold.service" \
	"$unitdir/vpnpoold.service"
install -m 0644 "$project_directory/deploy/tmpfiles/vpnpoold.conf" \
	"$tmpfilesdir/vpnpoold.conf"
install -m 0644 "$project_directory/configs/vpnpoold.example.yaml" \
	"$configdir/vpnpoold.yaml.example"
install -m 0644 "$project_directory/configs/users.example.yaml" \
	"$configdir/users.yaml.example"
install -m 0644 \
	"$project_directory/README.md" \
	"$project_directory/LICENSE" \
	"$docdir/"
for document in "$project_directory"/docs/*.md; do
	install -m 0644 "$document" "$docdir/"
done

if [ -z "$destination_root" ]; then
	systemd-tmpfiles --create vpnpoold.conf
	systemctl daemon-reload
	if [ "${VPNPOOLD_RESTART:-0}" = 1 ] &&
		systemctl is-active --quiet vpnpoold.service; then
		if ! systemctl restart vpnpoold.service; then
			if [ -f "$previous" ]; then
				mv -f "$previous" "$target"
				systemctl restart vpnpoold.service || true
			fi
			echo "upgrade failed; the previous binary was restored" >&2
			exit 1
		fi
	fi
fi

"$target" version
echo "installed vpnpoold; configuration and service enablement remain operator-controlled"
