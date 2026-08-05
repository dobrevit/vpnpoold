#!/bin/sh
# Render the systemd unit for a specific install prefix.
#
# There is exactly one unit source, deploy/systemd/vpnpoold.service.in. A manual
# install puts the binary in /usr/local/sbin; a distribution package puts it in
# /usr/sbin. Keeping two copies of the unit would let the hardening directives
# drift apart, and this repository has already paid for duplicated sources once.
set -eu

if [ "$#" -ne 2 ] && [ "$#" -ne 3 ]; then
	echo "usage: render-unit.sh SBINDIR DOCDIR [OUTPUT]" >&2
	exit 2
fi

sbindir=$1
docdir=$2
output=${3:-}

for value in "$sbindir" "$docdir"; do
	case "$value" in
	/*) ;;
	*)
		echo "render-unit.sh paths must be absolute" >&2
		exit 2
		;;
	esac
	# The substituted values land in an executed unit file; refuse anything
	# that is not a plain path.
	case "$value" in
	*[!A-Za-z0-9/._-]*)
		echo "render-unit.sh paths contain unsupported characters" >&2
		exit 2
		;;
	esac
done

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
template=$script_directory/systemd/vpnpoold.service.in
if [ ! -f "$template" ]; then
	echo "missing unit template $template" >&2
	exit 1
fi

render() {
	sed -e "s|@SBINDIR@|$sbindir|g" -e "s|@DOCDIR@|$docdir|g" "$template"
}

if [ -z "$output" ]; then
	render
	exit 0
fi

temporary=$output.tmp.$$
trap 'rm -f "$temporary"' EXIT HUP INT TERM
render >"$temporary"
chmod 0644 "$temporary"
mv "$temporary" "$output"
trap - EXIT HUP INT TERM
