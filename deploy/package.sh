#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
	echo "usage: package.sh VERSION OUTPUT_DIRECTORY" >&2
	exit 2
fi

version=$1
output_directory=$2
case "$version" in
""|*[!0-9A-Za-z.+_-]*)
	echo "VERSION contains unsupported characters" >&2
	exit 2
	;;
esac
case "$output_directory" in
/*) ;;
*) output_directory=$(pwd)/$output_directory ;;
esac

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_directory=$(CDPATH= cd -- "$script_directory/.." && pwd)
commit=$(git -C "$project_directory" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
source_epoch=${SOURCE_DATE_EPOCH:-$(date +%s)}
build_date=$(date -u -d "@$source_epoch" +%Y-%m-%dT%H:%M:%SZ)
ldflags="-s -w"
ldflags="$ldflags -X github.com/dobrevit/vpnpoold/internal/buildinfo.Version=$version"
ldflags="$ldflags -X github.com/dobrevit/vpnpoold/internal/buildinfo.Commit=$commit"
ldflags="$ldflags -X github.com/dobrevit/vpnpoold/internal/buildinfo.Date=$build_date"

install -d -m 0755 "$output_directory"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

for architecture in amd64 arm64; do
	name=vpnpoold_${version}_linux_${architecture}
	stage=$temporary/$name
	install -d -m 0755 "$stage"
	(
		cd "$project_directory"
		CGO_ENABLED=0 GOOS=linux GOARCH=$architecture \
			go build -buildvcs=false -trimpath -ldflags "$ldflags" \
			-o "$stage/vpnpoold" ./cmd/vpnpoold
	)
	install -m 0644 \
		"$project_directory/README.md" \
		"$project_directory/LICENSE" \
		"$stage/"
	cp -a \
		"$project_directory/configs" \
		"$project_directory/deploy" \
		"$project_directory/docs" \
		"$stage/"
	tar \
		-I 'gzip -n' \
		--sort=name \
		--mtime="@$source_epoch" \
		--owner=0 \
		--group=0 \
		--numeric-owner \
		-C "$temporary" \
		-cf "$output_directory/$name.tar.gz" \
		"$name"
done

(
	cd "$output_directory"
	sha256sum vpnpoold_"$version"_linux_*.tar.gz >SHA256SUMS
)
echo "release archives written to $output_directory"
