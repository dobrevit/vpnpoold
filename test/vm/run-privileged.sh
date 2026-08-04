#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "run-privileged.sh must run as root" >&2
	exit 1
fi

repo_dir=${1:-/home/ubuntu/vpnpoold}

if [ ! -f "$repo_dir/go.mod" ]; then
	echo "repository not found at $repo_dir" >&2
	exit 1
fi

cd "$repo_dir"

go test ./...
go test -race ./...
go vet ./...
VPNPOOLD_INTEGRATION=1 go test -tags=integration ./test/integration -v
