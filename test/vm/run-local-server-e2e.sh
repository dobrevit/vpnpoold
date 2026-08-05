#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "run-local-server-e2e.sh must run as root" >&2
	exit 1
fi
if [ "$#" -ne 3 ]; then
	echo "usage: run-local-server-e2e.sh DAEMON_BINARY CONFIG CLIENT_BUNDLE" >&2
	exit 2
fi

source_binary=$1
source_config=$2
client_bundle=$3
fixture_directory=$(dirname "$source_config")
runtime=/run/vpnpoold-local
daemon=$source_binary
config=$runtime/config.yaml
challenge_helper=/usr/local/libexec/vpnpoold-test-challenge-helper
primary_unit=vpnpoold-local-e2e.service
restart_unit=vpnpoold-local-e2e-restarted.service
active_unit=$primary_unit
held_pids=
soak_seconds=${VPNPOOLD_SOAK_SECONDS:-0}

case "$soak_seconds" in
""|*[!0-9]*)
	echo "VPNPOOLD_SOAK_SECONDS must be a non-negative integer" >&2
	exit 2
	;;
esac

for required in \
	"$source_binary" \
	"$source_config" \
	"$fixture_directory/dispatcher-users.yaml" \
	"$fixture_directory/management-challenge-helper.sh"; do
	if [ ! -f "$required" ]; then
		echo "required test input is missing: $required" >&2
		exit 1
	fi
done
case "$daemon" in
/*) ;;
*)
	echo "DAEMON_BINARY must be an absolute path" >&2
	exit 1
	;;
esac
if [ ! -x "$daemon" ]; then
	echo "DAEMON_BINARY must be executable" >&2
	exit 1
fi
for command in curl ip jq nft sha256sum systemctl systemd-run; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "required test command is missing: $command" >&2
		exit 1
	fi
done
for user in user1 user2 user3 user4; do
	for suffix in ovpn credentials; do
		if [ ! -f "$client_bundle/$user.$suffix" ]; then
			echo "client bundle is incomplete" >&2
			exit 1
		fi
	done
done
if [ "$(sysctl -n net.ipv4.ip_forward)" != 1 ]; then
	echo "net.ipv4.ip_forward must be enabled" >&2
	exit 1
fi

cleanup() {
	result=$?
	trap - EXIT HUP INT TERM
	set +e
	if [ -n "$held_pids" ]; then
		kill $held_pids >/dev/null 2>&1
	fi
	systemctl stop "$primary_unit" "$restart_unit" >/dev/null 2>&1
	for attempt in $(seq 1 50); do
		openvpn_count=$(pgrep -x openvpn 2>/dev/null | wc -l)
		namespace_count=$(ip netns list |
			awk '$1 ~ /^vpnlocal-/ {count++} END {print count+0}')
		if [ "$openvpn_count" -eq 0 ] && [ "$namespace_count" -eq 0 ]; then
			break
		fi
		sleep 0.1
	done
	if [ "$openvpn_count" -eq 0 ] && [ "$namespace_count" -ne 0 ]; then
		# A deliberate SIGKILL can leave named namespaces behind before the
		# restart phase runs. Remove only this fixture's validated prefix.
		for namespace in $(ip netns list |
			awk '$1 ~ /^vpnlocal-[0-9a-f]+$/ && length($1) == 19 {print $1}'); do
			ip netns delete "$namespace"
		done
		namespace_count=$(ip netns list |
			awk '$1 ~ /^vpnlocal-/ {count++} END {print count+0}')
	fi
	if nft list table inet vpnpoold_host >/dev/null 2>&1; then
		nft delete table inet vpnpoold_host
	fi
	if [ "$openvpn_count" -ne 0 ] || [ "$namespace_count" -ne 0 ]; then
		echo "cleanup failed: openvpn=$openvpn_count namespaces=$namespace_count" >&2
		result=1
	else
		echo "cleanup: no OpenVPN processes or vpnlocal namespaces remain"
	fi
	rm -rf "$runtime"
	rm -f "$challenge_helper"
	exit "$result"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

rm -rf "$runtime"
install -d -m 0700 "$runtime" "$runtime/profiles" "$runtime/credentials"
install -m 0600 "$source_config" "$config"
install -m 0600 "$fixture_directory/dispatcher-users.yaml" "$runtime/users.yaml"
install -d -m 0755 /usr/local/libexec
install -m 0700 "$fixture_directory/management-challenge-helper.sh" \
	"$challenge_helper"
for user in user1 user2 user3 user4; do
	install -m 0600 "$client_bundle/$user.ovpn" "$runtime/profiles/$user.ovpn"
	install -m 0600 "$client_bundle/$user.credentials" \
		"$runtime/credentials/$user"
done
printf '%s\n' 'static-challenge "vpnpoold fixture OTP" 0' \
	>>"$runtime/profiles/user1.ovpn"

start_daemon() {
	unit=$1
	systemd-run --quiet --unit="$unit" --collect \
		--property=KillMode=mixed \
		--property=TimeoutStopSec=30s \
		"$daemon" daemon --config "$config"
}

status_json() {
	"$daemon" status --config "$config" --format json 2>/dev/null
}

wait_for_healthy_count() {
	expected=$1
	attempts=$2
	for attempt in $(seq 1 "$attempts"); do
		response=$(status_json || true)
		count=$(printf '%s' "$response" |
			jq -r '[.workers[]? | select(.available == true)] | length' \
				2>/dev/null || printf 0)
		if [ "$count" = "$expected" ]; then
			return 0
		fi
		sleep 0.2
	done
	echo "timed out waiting for $expected healthy workers" >&2
	printf '%s\n' "$response" >&2
	return 1
}

wait_for_worker_availability() {
	worker_id=$1
	expected=$2
	attempts=$3
	for attempt in $(seq 1 "$attempts"); do
		response=$(status_json || true)
		available=$(printf '%s' "$response" |
			jq -r --arg id "$worker_id" \
				'.workers[]? | select(.id == $id) | .available' \
				2>/dev/null || true)
		if [ "$available" = "$expected" ]; then
			return 0
		fi
		sleep 0.1
	done
	echo "timed out waiting for $worker_id available=$expected" >&2
	printf '%s\n' "$response" >&2
	return 1
}

wait_for_worker_enabled_state() {
	worker_id=$1
	expected_enabled=$2
	expected_state=$3
	attempts=$4
	for attempt in $(seq 1 "$attempts"); do
		response=$(status_json || true)
		enabled=$(printf '%s' "$response" |
			jq -r --arg id "$worker_id" \
				'.workers[]? | select(.id == $id) | .enabled' \
				2>/dev/null || true)
		state=$(printf '%s' "$response" |
			jq -r --arg id "$worker_id" \
				'.workers[]? | select(.id == $id) | .state' \
				2>/dev/null || true)
		if [ "$enabled" = "$expected_enabled" ] &&
			[ "$state" = "$expected_state" ]; then
			return 0
		fi
		sleep 0.1
	done
	echo "timed out waiting for $worker_id enabled=$expected_enabled state=$expected_state" >&2
	printf '%s\n' "$response" >&2
	return 1
}

wait_for_control_socket_change() {
	previous_inode=$1
	attempts=$2
	for attempt in $(seq 1 "$attempts"); do
		current_inode=$(stat -c %i "$runtime/runtime/control.sock" 2>/dev/null || true)
		if [ -n "$current_inode" ] && [ "$current_inode" != "$previous_inode" ]; then
			return 0
		fi
		sleep 0.1
	done
	echo "control socket did not change after reload" >&2
	return 1
}

namespace_for_worker() {
	worker_id=$1
	suffix=$(printf '%s' "$worker_id" | sha256sum | cut -c1-10)
	printf 'vpnlocal-%s\n' "$suffix"
}

pid_in_namespace() {
	namespace=$1
	process_marker=$2
	for pid in $(ip netns pids "$namespace"); do
		if [ ! -r "/proc/$pid/cmdline" ]; then
			continue
		fi
		command_line=$(tr '\000' ' ' <"/proc/$pid/cmdline")
		case " $command_line " in
		*" $process_marker "*)
			printf '%s\n' "$pid"
			return 0
			;;
		esac
	done
	return 1
}

request_egress() {
	curl --silent --show-error --fail --max-time 5 \
		--socks5-hostname 127.0.0.1:1080 \
		http://10.250.0.1:8080/ip
}

request_authenticated_egress() {
	username=$1
	curl --silent --show-error --fail --max-time 5 \
		--proxy-user "$username:vpnpoold-test-password" \
		--socks5-hostname 127.0.0.1:1080 \
		http://10.250.0.1:8080/ip
}

reload_and_wait() {
	control_inode=$(stat -c %i "$runtime/runtime/control.sock")
	"$daemon" reload --config "$config"
	wait_for_control_socket_change "$control_inode" 450
	wait_for_healthy_count 4 450
}

set_authenticated_dispatcher_mode() {
	mode=$1
	sed \
		-e 's/enabled: false/enabled: true/' \
		-e "s|users_file: \"\"|users_file: $runtime/users.yaml|" \
		-e "s/mode: round_robin/mode: $mode/" \
		"$source_config" >"$runtime/config.next"
	install -m 0600 "$runtime/config.next" "$config"
	reload_and_wait
}

restore_default_dispatcher() {
	install -m 0600 "$source_config" "$config"
	reload_and_wait
}

wait_for_output() {
	path=$1
	attempts=$2
	for attempt in $(seq 1 "$attempts"); do
		if [ -s "$path" ]; then
			return 0
		fi
		sleep 0.1
	done
	echo "timed out waiting for held request output" >&2
	return 1
}

wait_for_pid_exit() {
	pid=$1
	attempts=$2
	for attempt in $(seq 1 "$attempts"); do
		if ! kill -0 "$pid" 2>/dev/null; then
			wait "$pid" 2>/dev/null || true
			return 0
		fi
		sleep 0.1
	done
	echo "held client session did not terminate after worker failure" >&2
	return 1
}

start_held_request() {
	output=$1
	curl --no-buffer --silent --show-error --max-time 55 \
		--socks5-hostname 127.0.0.1:1080 \
		http://10.250.0.1:8080/hold >"$output" &
	held_request_pid=$!
	held_pids=$held_request_pid
	wait_for_output "$output" 50
}

assert_live_balancing_modes() {
	set_authenticated_dispatcher_mode least_connections
	for request in $(seq 1 5); do
		output="$runtime/held-$request"
		curl --no-buffer --silent --show-error --max-time 55 \
			--proxy-user "alice:vpnpoold-test-password" \
			--socks5-hostname 127.0.0.1:1080 \
			http://10.250.0.1:8080/hold >"$output" &
		held_pids="$held_pids $!"
		wait_for_output "$output" 50
	done
	held_results=$runtime/held-results
	: >"$held_results"
	for request in $(seq 1 5); do
		cat "$runtime/held-$request" >>"$held_results"
	done
	for address in \
		198.51.100.10 \
		198.51.100.11 \
		198.51.100.12 \
		198.51.100.13; do
		count=$(grep -c "^$address$" "$held_results")
		if [ "$address" = 198.51.100.10 ]; then
			expected=2
		else
			expected=1
		fi
		if [ "$count" -ne "$expected" ]; then
			echo "least-connections count for $address was $count, expected $expected" >&2
			return 1
		fi
	done
	active=$(status_json | jq -r '.dispatcher.active_connections')
	if [ "$active" -ne 5 ]; then
		echo "least-connections active count was $active, expected 5" >&2
		return 1
	fi
	for held_pid in $held_pids; do
		kill "$held_pid" >/dev/null 2>&1 || true
		wait "$held_pid" 2>/dev/null || true
	done
	held_pids=

	set_authenticated_dispatcher_mode username_hash
	first=$(request_authenticated_egress alice)
	for request in $(seq 1 5); do
		if [ "$(request_authenticated_egress alice)" != "$first" ]; then
			echo "username_hash moved a stable username" >&2
			return 1
		fi
	done
	if curl --silent --fail --max-time 3 \
		--proxy-user "alice:wrong-password" \
		--socks5-hostname 127.0.0.1:1080 \
		http://10.250.0.1:8080/ip >/dev/null 2>&1; then
		echo "dispatcher accepted an invalid password" >&2
		return 1
	fi

	set_authenticated_dispatcher_mode session_hash
	before=$runtime/session-before
	after=$runtime/session-after
	: >"$before"
	for session in $(seq 1 20); do
		address=$(request_authenticated_egress "alice/session-$session")
		printf '%s %s\n' "$session" "$address" >>"$before"
	done
	removed_address=$(awk '$1 == 1 {print $2}' "$before")
	case "$removed_address" in
	198.51.100.10) removed_worker=local-1 ;;
	198.51.100.11) removed_worker=local-2 ;;
	198.51.100.12) removed_worker=local-3 ;;
	198.51.100.13) removed_worker=local-4 ;;
	*)
		echo "session hash returned an unexpected address" >&2
		return 1
		;;
	esac
	"$daemon" worker disable --config "$config" "$removed_worker"
	wait_for_worker_enabled_state "$removed_worker" false DISABLED 150
	: >"$after"
	for session in $(seq 1 20); do
		address=$(request_authenticated_egress "alice/session-$session")
		printf '%s %s\n' "$session" "$address" >>"$after"
	done
	for session in $(seq 1 20); do
		old=$(awk -v session="$session" '$1 == session {print $2}' "$before")
		new=$(awk -v session="$session" '$1 == session {print $2}' "$after")
		if [ "$old" != "$removed_address" ] && [ "$new" != "$old" ]; then
			echo "rendezvous hashing unnecessarily moved session $session" >&2
			return 1
		fi
		if [ "$old" = "$removed_address" ] && [ "$new" = "$old" ]; then
			echo "removed session_hash worker remained selectable" >&2
			return 1
		fi
	done
	"$daemon" worker enable --config "$config" "$removed_worker"
	wait_for_worker_availability "$removed_worker" true 450
	restore_default_dispatcher
	echo "balancing: live least-connections, username_hash, session_hash, and authentication verified"
}

run_soak_cycle() {
	if [ "$soak_seconds" -eq 0 ]; then
		return
	fi
	deadline=$(($(date +%s) + soak_seconds))
	requests=0
	while [ "$(date +%s)" -lt "$deadline" ]; do
		request_egress >/dev/null
		response=$(status_json)
		if [ "$(printf '%s' "$response" |
			jq -r '[.workers[] | select(.available == true)] | length')" -ne 4 ]; then
			echo "soak cycle observed fewer than four available workers" >&2
			return 1
		fi
		curl --silent --show-error --fail --max-time 5 \
			http://127.0.0.1:9090/metrics >/dev/null
		requests=$((requests + 1))
		sleep 1
	done
	if [ "$requests" -eq 0 ]; then
		echo "soak cycle completed no requests" >&2
		return 1
	fi
	echo "soak: $requests verified request/status/metrics cycles over ${soak_seconds}s"
}

assert_worker_not_selected() {
	rejected_ip=$1
	observed=$(request_egress)
	if [ "$observed" = "$rejected_ip" ]; then
		echo "unavailable worker remained selectable: $rejected_ip" >&2
		return 1
	fi
}

assert_strict_firewall() {
	namespace=$1
	rules=$(ip netns exec "$namespace" nft list table inet vpnpoold)
	if printf '%s' "$rules" | grep -F 'oifname "tun0" accept' >/dev/null; then
		echo "namespace $namespace retained active tunnel egress rules" >&2
		return 1
	fi
	for chain in input output forward; do
		if ! printf '%s' "$rules" |
			grep -E "chain $chain \\{" >/dev/null; then
			echo "namespace $namespace is missing the $chain chain" >&2
			return 1
		fi
	done
	policy_count=$(printf '%s' "$rules" | grep -c 'policy drop;')
	if [ "$policy_count" -ne 3 ]; then
		echo "namespace $namespace is not default-drop in all directions" >&2
		return 1
	fi
}

assert_round_robin() {
	output=$runtime/egress-results
	: >"$output"
	for request in $(seq 1 12); do
		request_egress >>"$output"
	done
	for address in \
		198.51.100.10 \
		198.51.100.11 \
		198.51.100.12 \
		198.51.100.13; do
		count=$(grep -c "^$address$" "$output")
		if [ "$count" -ne 3 ]; then
			echo "round-robin count for $address was $count, expected 3" >&2
			return 1
		fi
	done
	echo "baseline: four healthy workers and balanced dispatcher egress"
}

assert_observability() {
	metrics_output=$runtime/metrics
	curl --silent --show-error --fail --max-time 5 \
		http://127.0.0.1:9090/metrics >"$metrics_output"
	for sample in \
		'vpnpool_worker_healthy{worker="local-1"} 1' \
		'vpnpool_worker_connections_total{worker="local-1"} 3' \
		'vpnpool_dispatcher_connections_total 12'; do
		if ! grep -F "$sample" "$metrics_output" >/dev/null; then
			echo "missing Prometheus sample: $sample" >&2
			return 1
		fi
	done
	if grep -E '198\\.51\\.100\\.|(public_ip|username|destination)="' \
		"$metrics_output" >/dev/null; then
		echo "Prometheus output contains a prohibited high-cardinality value" >&2
		return 1
	fi
	response=$(status_json)
	if [ "$(printf '%s' "$response" |
		jq -r '.dispatcher.connections_total')" -ne 12 ]; then
		echo "status dispatcher counters do not match observed traffic" >&2
		return 1
	fi
	if [ "$(printf '%s' "$response" |
		jq -r '[.workers[] | select(.connections_total == 3)] | length')" -ne 4 ]; then
		echo "status worker counters do not match balanced traffic" >&2
		return 1
	fi
	echo "observability: bounded metrics and status counters verified"
}

start_daemon "$primary_unit"
wait_for_healthy_count 4 450
assert_round_robin
assert_observability

table_status=$("$daemon" status --config "$config")
if ! printf '%s' "$table_status" | grep -F 'WORKER' >/dev/null ||
	! printf '%s' "$table_status" | grep -F 'local-1' >/dev/null; then
	echo "human-readable status table is incomplete" >&2
	exit 1
fi
"$daemon" worker disable --config "$config" local-4
wait_for_worker_enabled_state local-4 false DISABLED 150
disabled_namespace=$(namespace_for_worker local-4)
if ip netns list | awk '{print $1}' | grep -Fx "$disabled_namespace" >/dev/null; then
	echo "disabled worker namespace was not cleaned up" >&2
	exit 1
fi
for request in $(seq 1 6); do
	assert_worker_not_selected 198.51.100.13
done
"$daemon" worker enable --config "$config" local-4
wait_for_worker_availability local-4 true 450
control_inode=$(stat -c %i "$runtime/runtime/control.sock")
"$daemon" reload --config "$config"
wait_for_control_socket_change "$control_inode" 450
wait_for_healthy_count 4 450
assert_round_robin
assert_observability
echo "control plane: table status, disable, enable, and transactional reload verified"

cp "$config" "$runtime/config.valid"
printf '\nunknown_reload_field: true\n' >>"$config"
control_inode=$(stat -c %i "$runtime/runtime/control.sock")
systemctl kill --kill-whom=main --signal=HUP "$active_unit"
sleep 1
if [ "$(stat -c %i "$runtime/runtime/control.sock")" != "$control_inode" ]; then
	echo "invalid reload replaced the active generation" >&2
	exit 1
fi
install -m 0600 "$runtime/config.valid" "$config"
wait_for_healthy_count 4 20
echo "reload rollback: invalid configuration retained the healthy generation"

assert_live_balancing_modes

proxy_namespace=$(namespace_for_worker local-1)
start_held_request "$runtime/proxy-failure-held"
if [ "$(cat "$runtime/proxy-failure-held")" != "198.51.100.10" ]; then
	echo "proxy failure held session was not pinned to local-1" >&2
	exit 1
fi
proxy_pid=$(pid_in_namespace "$proxy_namespace" worker-proxy)
kill -KILL "$proxy_pid"
wait_for_worker_availability local-1 false 30
wait_for_pid_exit "$held_request_pid" 30
held_pids=
assert_worker_not_selected 198.51.100.10
assert_strict_firewall "$proxy_namespace"
wait_for_worker_availability local-1 true 450
if [ "$(status_json | jq -r \
	'.workers[] | select(.id == "local-1") | .proxy_restarts_total')" -lt 1 ]; then
	echo "proxy restart counter was not incremented" >&2
	exit 1
fi
echo "proxy failure: immediate withdrawal, strict firewall, verified recovery"

start_held_request "$runtime/openvpn-failure-held"
vpn_address=$(cat "$runtime/openvpn-failure-held")
case "$vpn_address" in
198.51.100.10) vpn_worker=local-1 ;;
198.51.100.11) vpn_worker=local-2 ;;
198.51.100.12) vpn_worker=local-3 ;;
198.51.100.13) vpn_worker=local-4 ;;
*)
	echo "OpenVPN failure held session returned an unexpected address" >&2
	exit 1
	;;
esac
vpn_namespace=$(namespace_for_worker "$vpn_worker")
server_route=192.168.122.50/32
ip -n "$vpn_namespace" route replace unreachable "$server_route"
vpn_pid=$(pid_in_namespace "$vpn_namespace" /usr/sbin/openvpn)
kill -KILL "$vpn_pid"
wait_for_worker_availability "$vpn_worker" false 30
wait_for_pid_exit "$held_request_pid" 30
held_pids=
assert_worker_not_selected "$vpn_address"
assert_strict_firewall "$vpn_namespace"
if ip netns exec "$vpn_namespace" curl --silent --fail --max-time 1 \
	http://10.250.0.1:8080/ip >/dev/null 2>&1; then
	echo "failed namespace reached the VPN-side endpoint directly" >&2
	exit 1
fi
ip -n "$vpn_namespace" route del unreachable "$server_route"
wait_for_worker_availability "$vpn_worker" true 450
if [ "$(status_json | jq -r \
	--arg id "$vpn_worker" \
	'.workers[] | select(.id == $id) | .openvpn_restarts_total')" -lt 1 ]; then
	echo "OpenVPN restart counter was not incremented" >&2
	exit 1
fi
echo "OpenVPN failure: immediate withdrawal, no fallback, verified recovery"

run_soak_cycle

# Some systemd versions return a failure after successfully killing the main
# process when the remaining cgroup is already empty. The state checks below
# determine whether the deliberate crash actually completed.
systemctl kill --kill-whom=all --signal=KILL "$active_unit" \
	>/dev/null 2>&1 || true
for attempt in $(seq 1 50); do
	if ! systemctl is-active --quiet "$active_unit"; then
		break
	fi
	sleep 0.1
done
if systemctl is-active --quiet "$active_unit"; then
	echo "failed to terminate the daemon test unit" >&2
	exit 1
fi
stale_count=$(ip netns list |
	awk '$1 ~ /^vpnlocal-/ {count++} END {print count+0}')
if [ "$stale_count" -ne 4 ]; then
	echo "hard crash did not leave the expected four stale namespaces" >&2
	exit 1
fi
active_unit=$restart_unit
start_daemon "$restart_unit"
wait_for_healthy_count 4 450
assert_round_robin
assert_observability
echo "daemon crash: stale resources cleaned and all workers re-verified"

echo "local OpenVPN server acceptance test passed"
