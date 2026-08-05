#!/bin/sh
# Build deb, rpm and apk packages for linux/amd64 and linux/arm64.
#
# Mirrors deploy/package.sh: same build flags, same SOURCE_DATE_EPOCH handling,
# so two runs at the same epoch and commit produce byte-identical packages.
set -eu

if [ "$#" -ne 2 ]; then
	echo "usage: package-native.sh VERSION OUTPUT_DIRECTORY" >&2
	exit 2
fi

version=$1
output_directory=$2
case "$version" in
"" | *[!0-9A-Za-z.+_-]*)
	echo "VERSION contains unsupported characters" >&2
	exit 2
	;;
esac
case "$output_directory" in
/*) ;;
*) output_directory=$(pwd)/$output_directory ;;
esac

nfpm_version=${NFPM_VERSION:-v2.43.0}
nfpm="go run github.com/goreleaser/nfpm/v2/cmd/nfpm@$nfpm_version"

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

# Packages install to /usr/sbin, unlike the /usr/local/sbin manual install.
# Both come from the same unit template.
"$script_directory/render-unit.sh" \
	/usr/sbin \
	/usr/share/doc/vpnpoold \
	"$temporary/vpnpoold.service"

# Completion scripts are architecture independent, so generate them once with a
# host-native build rather than trying to execute a cross-compiled binary.
(
	cd "$project_directory"
	go build -buildvcs=false -trimpath -ldflags "$ldflags" -o "$temporary/vpnpoold.host" ./cmd/vpnpoold
)
for shell in bash zsh fish; do
	"$temporary/vpnpoold.host" completion "$shell" >"$temporary/completion.$shell"
done

for architecture in amd64 arm64; do
	stage=$temporary/$architecture
	install -d -m 0755 "$stage"
	(
		cd "$project_directory"
		CGO_ENABLED=0 GOOS=linux GOARCH=$architecture \
			go build -buildvcs=false -trimpath -ldflags "$ldflags" \
			-o "$stage/vpnpoold" ./cmd/vpnpoold
	)
	cp "$temporary/vpnpoold.service" "$stage/vpnpoold.service"
	for shell in bash zsh fish; do
		cp "$temporary/completion.$shell" "$stage/completion.$shell"
	done

	for format in deb rpm apk; do
		rendered=$temporary/nfpm-$architecture-$format.yaml
		# nfpm's per-packager overrides replace a field rather than extending
		# it, so deb-only contents are spliced in here instead.
		if [ "$format" = deb ]; then
			splice="/@DEB_ONLY_CONTENTS@/r $script_directory/nfpm-deb-contents.yaml"
		else
			splice=
		fi
		sed \
			${splice:+-e "$splice"} \
			-e "/@DEB_ONLY_CONTENTS@/d" \
			-e "s|@VERSION@|$version|g" \
			-e "s|@ARCH@|$architecture|g" \
			-e "s|@STAGE@|$stage|g" \
			"$script_directory/nfpm.yaml" >"$rendered"

		(
			cd "$project_directory"
			SOURCE_DATE_EPOCH=$source_epoch \
				$nfpm package \
				--config "$rendered" \
				--packager "$format" \
				--target "$output_directory"
		)
	done
done

(
	cd "$output_directory"
	sha256sum vpnpoold*.deb vpnpoold*.rpm vpnpoold*.apk >SHA256SUMS.packages
)
echo "packages written to $output_directory"
