#!/bin/sh
# Runs after install and after upgrade, on deb, rpm and apk.
#
# This script deliberately does NOT enable, start, or restart the service.
#
# Restarting vpnpoold tears down every tunnel and terminates every established
# client session, so activating a new binary is an operator decision with a
# visible cost, not a side effect of `apt upgrade`. deploy/install.sh takes the
# same position and only restarts when VPNPOOLD_RESTART=1 is set explicitly.
set -eu

upgrade=0
case "${1:-}" in
configure)
	# deb: $2 holds the previously configured version on upgrade.
	[ -n "${2:-}" ] && upgrade=1
	;;
2)
	# rpm: $1 is 2 when upgrading.
	upgrade=1
	;;
esac

if command -v systemd-tmpfiles >/dev/null 2>&1; then
	# /run/netns must exist before systemd builds the service sandbox.
	systemd-tmpfiles --create vpnpoold.conf >/dev/null 2>&1 || true
fi

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [ "$upgrade" -eq 1 ]; then
	echo "vpnpoold: the new binary is installed but the running daemon still" >&2
	echo "vpnpoold: uses the previous one. Restart to activate it:" >&2
	echo "vpnpoold:     systemctl restart vpnpoold" >&2
	echo "vpnpoold: this drops every tunnel and every established session." >&2
else
	echo "vpnpoold: installed. Write /etc/vpnpoold/vpnpoold.yaml (see the" >&2
	echo "vpnpoold: .example files), then: vpnpoold validate --config PATH" >&2
	echo "vpnpoold: The service stays inert until that file exists." >&2
fi

exit 0
