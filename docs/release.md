# Release and upgrade policy

`vpnpoold version` reports the release version, source commit, UTC build time,
and Go toolchain. Official archives are Linux-only, contain a statically linked
binary for `amd64` or `arm64`, and are accompanied by `SHA256SUMS`.

Configuration has an explicit integer schema version. This release supports
only schema version `1`. A binary refuses both older and newer schemas instead
of guessing at a migration. No schema migration is currently necessary.
Before a future release changes the schema, it must add a documented,
separately testable migration from every supported prior version.

Build release archives with a stable source epoch:

```sh
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  ./deploy/package.sh 0.1.0 ./dist
sha256sum -c ./dist/SHA256SUMS
```

Install a freshly built or extracted binary:

```sh
sudo ./deploy/install.sh ./vpnpoold
sudoedit /etc/vpnpoold/vpnpoold.yaml
sudo /usr/local/sbin/vpnpoold validate \
  -config /etc/vpnpoold/vpnpoold.yaml
sudo systemctl enable --now vpnpoold
```

For an upgrade, first back up `/etc/vpnpoold` and verify the new binary against
the live configuration. The installer performs that validation before
replacing an existing binary, retains one copy as
`/usr/local/sbin/vpnpoold.previous`, and does not restart a running service
unless explicitly requested:

```sh
sudo ./vpnpoold-new validate -config /etc/vpnpoold/vpnpoold.yaml
sudo env VPNPOOLD_RESTART=1 ./deploy/install.sh ./vpnpoold-new
```

If the restart fails, the installer restores the previous binary and attempts
to restart it. Configuration is never overwritten by the installer.
