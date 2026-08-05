#!/bin/sh
# Container feasibility spike.
#
# Answers one question: can a container host vpnpoold's privileged operations,
# and if so at what cost in capabilities? The point is NOT to ship a production
# image — a container running this daemon needs CAP_SYS_ADMIN and is therefore
# not a security boundary. The point is that if these checks pass on a
# GitHub-hosted runner, a large part of the acceptance matrix that is currently
# a manual disposable-VM gate could become a CI gate.
#
# Run on the host you are evaluating:
#   ./test/container/spike.sh
#
# Exit status is 0 when every required check passes.
set -eu

image=${SPIKE_IMAGE:-debian:12}
runtime=${SPIKE_RUNTIME:-docker}
failures=0
results=""

record() {
	status=$1
	name=$2
	detail=${3:-}
	results="$results
$status	$name	$detail"
	if [ "$status" = FAIL ]; then
		failures=$((failures + 1))
	fi
}

if ! command -v "$runtime" >/dev/null 2>&1; then
	echo "container runtime $runtime is not installed" >&2
	exit 2
fi

# Check 0: does the host expose /dev/net/tun at all? Without it nothing else
# matters, and the answer differs between hosted runners and workstations.
if [ -c /dev/net/tun ]; then
	record PASS "host /dev/net/tun present"
else
	record FAIL "host /dev/net/tun present" "load the tun module"
fi

inner=$(cat <<'INNER'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq --no-install-recommends iproute2 nftables >/dev/null 2>&1

status=0

# 1. tun device usable inside the container.
if [ -c /dev/net/tun ]; then
	echo "PASS	tun device visible in container"
else
	echo "FAIL	tun device visible in container"
	status=1
fi

# 2. Named network namespace creation. This is the check most likely to fail:
# `ip netns add` bind-mounts /proc/self/ns/net under /run/netns, which needs
# CAP_SYS_ADMIN and a mount namespace that permits it. Ubuntu's docker-default
# AppArmor profile denies mount outright.
if ip netns add spike0 >/dev/null 2>&1; then
	echo "PASS	ip netns add"
	if ip netns exec spike0 ip link set lo up >/dev/null 2>&1; then
		echo "PASS	ip netns exec"
	else
		echo "FAIL	ip netns exec"
		status=1
	fi
	# 3. veth pair into the namespace, as the daemon does per worker.
	if ip link add spikehost type veth peer name spikens >/dev/null 2>&1 &&
		ip link set spikens netns spike0 >/dev/null 2>&1; then
		echo "PASS	veth pair into namespace"
		ip link del spikehost >/dev/null 2>&1 || true
	else
		echo "FAIL	veth pair into namespace"
		status=1
	fi
	ip netns del spike0 >/dev/null 2>&1 || true
else
	echo "FAIL	ip netns add"
	echo "SKIP	ip netns exec"
	echo "SKIP	veth pair into namespace"
	status=1
fi

# 4. nftables in the container's own network namespace, applied the way the
# daemon applies it: one transaction on stdin.
if printf 'add table inet spike\nadd chain inet spike input { type filter hook input priority -100; policy drop; }\n' |
	nft -f - >/dev/null 2>&1; then
	echo "PASS	nft -f - transaction"
	nft delete table inet spike >/dev/null 2>&1 || true
else
	echo "FAIL	nft -f - transaction"
	status=1
fi

# 5. The forwarding sysctl the daemon requires.
forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo unavailable)
if [ "$forward" = 1 ]; then
	echo "PASS	net.ipv4.ip_forward=1"
else
	echo "FAIL	net.ipv4.ip_forward=1 (is $forward)"
	status=1
fi

exit $status
INNER
)

run_variant() {
	label=$1
	shift
	output=$("$runtime" run --rm \
		--device /dev/net/tun \
		--sysctl net.ipv4.ip_forward=1 \
		"$@" \
		"$image" sh -c "$inner" 2>&1) || true
	echo "--- $label ---"
	echo "$output" | grep -E '^(PASS|FAIL|SKIP)' || echo "$output" | tail -5
	if echo "$output" | grep -q '^FAIL'; then
		record FAIL "$label" "see output above"
	else
		record PASS "$label"
	fi
}

echo "spike image: $image"
echo

# The capability set the daemon actually needs. CAP_SYS_ADMIN is required for
# named namespaces; granting it makes the container a weak boundary at best.
run_variant "caps only (NET_ADMIN, SYS_ADMIN)" \
	--cap-add NET_ADMIN --cap-add SYS_ADMIN

# Same, with AppArmor confinement lifted. If the previous variant failed on
# `ip netns add` and this one passes, the host's container AppArmor profile is
# what blocks the mount.
run_variant "caps + apparmor unconfined" \
	--cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined

echo
echo "=== summary ==="
printf '%s\n' "$results" | sed '/^$/d'
echo
if [ "$failures" -eq 0 ]; then
	echo "VERDICT: a container can host the privileged operations."
	echo "It still requires CAP_SYS_ADMIN and is not a security boundary."
	exit 0
fi
echo "VERDICT: $failures variant(s) failed; see above for which check blocked."
echo "If every variant failed at 'ip netns add', containerisation is not viable"
echo "on this host and the disposable VM remains the only option."
exit 1
