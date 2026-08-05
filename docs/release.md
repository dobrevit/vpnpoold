# Release and upgrade policy

`vpnpoold version` reports the release version, source commit, UTC build time,
and Go toolchain. Official archives are Linux-only, contain a statically linked
binary for `amd64` or `arm64`, and are accompanied by `SHA256SUMS`.

Configuration has an explicit integer schema version. This release supports
only schema version `1`. A binary refuses both older and newer schemas instead
of guessing at a migration. No schema migration is currently necessary.
Before a future release changes the schema, it must add a documented,
separately testable migration from every supported prior version.

## Artifacts

Each release publishes, for `amd64` and `arm64`:

- a `.tar.gz` archive containing the binary, configuration examples, deploy
  scripts and documentation;
- native `.deb`, `.rpm` and `.apk` packages;
- `SHA256SUMS` covering every artifact;
- a `.cosign.bundle` for every artifact and for `SHA256SUMS`.

Packages install the binary to `/usr/sbin`, the unit to
`/usr/lib/systemd/system`, and shell completion for bash, zsh and fish. They
ship only `*.example` configurations, never enable or start the service, and
never restart it on upgrade — activating a new binary drops every tunnel and
every established session, so it stays an operator decision.

Build release archives and packages with a stable source epoch:

```sh
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  ./deploy/package.sh 0.1.0 ./dist
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  ./deploy/package-native.sh 0.1.0 ./dist
sha256sum -c ./dist/SHA256SUMS
```

Both scripts work offline and need no signing capability. Signing happens only
in the release workflow.

## Verifying a release

Artifacts are signed with Sigstore keyless signing. There is no long-lived
signing key: the identity is the release workflow itself, attested by a GitHub
OIDC token and recorded in the public transparency log. Verification therefore
checks *which workflow, in which repository, at which tag* produced the file —
a stronger statement than "someone with the private key signed it".

Verify the checksum manifest, then the checksums:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity \
    'https://github.com/dobrevit/vpnpoold/.github/workflows/release.yml@refs/tags/v0.1.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

sha256sum -c SHA256SUMS
```

Substitute the tag you downloaded. To verify a single artifact directly:

```sh
cosign verify-blob \
  --bundle vpnpoold_0.1.0_linux_amd64.tar.gz.cosign.bundle \
  --certificate-identity \
    'https://github.com/dobrevit/vpnpoold/.github/workflows/release.yml@refs/tags/v0.1.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vpnpoold_0.1.0_linux_amd64.tar.gz
```

Both flags matter. Without `--certificate-identity` any Sigstore signature from
any project verifies, and without `--certificate-oidc-issuer` an identity from a
different issuer would be accepted. Omitting either reduces the check to
"this was signed by somebody".

The release workflow verifies every artifact against the same identity before
uploading, so a broken signature fails the release rather than an operator's
install.

Distribution-native signatures — `rpm --addsign`, `debsigs`, an apk signing key —
are deliberately not implemented. They are what `apt`, `dnf` and `apk` check
when installing from a *repository*, and this project does not publish one yet.
Adding them means holding a long-lived private key in Actions secrets, which is
a custody problem worth taking on only when there is a repository to serve.

Install a freshly built or extracted binary:

```sh
sudo ./deploy/install.sh ./vpnpoold
sudoedit /etc/vpnpoold/vpnpoold.yaml
sudo /usr/local/sbin/vpnpoold validate \
  --config /etc/vpnpoold/vpnpoold.yaml
sudo systemctl enable --now vpnpoold
```

For an upgrade, first back up `/etc/vpnpoold` and verify the new binary against
the live configuration. The installer performs that validation before
replacing an existing binary, retains one copy as
`/usr/local/sbin/vpnpoold.previous`, and does not restart a running service
unless explicitly requested:

```sh
sudo ./vpnpoold-new validate --config /etc/vpnpoold/vpnpoold.yaml
sudo env VPNPOOLD_RESTART=1 ./deploy/install.sh ./vpnpoold-new
```

If the restart fails, the installer restores the previous binary and attempts
to restart it. Configuration is never overwritten by the installer.
