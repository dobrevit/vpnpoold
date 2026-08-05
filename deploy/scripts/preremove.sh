#!/bin/sh
# Runs before removal on deb, rpm and apk.
#
# Stops the service on a real removal, but not during an upgrade: the upgrade
# path leaves the running daemon alone so that replacing the package does not
# silently drop every tunnel. Operator-supplied material under /etc/vpnpoold —
# OpenVPN profiles and credentials — is never touched here or on purge.
set -eu

upgrade=0
case "${1:-}" in
upgrade | failed-upgrade)
	# deb passes the action name.
	upgrade=1
	;;
1)
	# rpm passes 1 when the package is being upgraded, 0 on removal.
	upgrade=1
	;;
esac

if [ "$upgrade" -eq 1 ]; then
	exit 0
fi

if command -v systemctl >/dev/null 2>&1; then
	if systemctl is-active --quiet vpnpoold.service 2>/dev/null; then
		systemctl stop vpnpoold.service >/dev/null 2>&1 || true
	fi
	systemctl disable vpnpoold.service >/dev/null 2>&1 || true
fi

exit 0
