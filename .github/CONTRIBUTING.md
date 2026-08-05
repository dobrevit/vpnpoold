# Contributing to vpnpoold

`vpnpoold` is a Linux-only daemon that runs as root, creates network
namespaces, rewrites host and namespace firewall rules, and supervises OpenVPN
processes. A defect here does not produce a bad response — it produces traffic
leaving through the wrong network interface. Contributions are welcome, but the
bar below is not negotiable, and most of it exists because of that difference.

## The security invariants

Every change is measured against these. If your change touches one, say which
one in the pull request and explain why it still holds.

1. **Fail closed.** Any uncertainty must resolve to "no traffic", never "traffic
   through an unverified path".
2. **Worker traffic never falls back to the host WAN route.** This is the
   primary threat the whole design exists to prevent.
3. **Restrictive namespace firewall rules are installed before the worker proxy
   is exposed** — ordering here is a security property, not a style choice.
4. **A worker is unavailable until tunnel, route, proxy and public-IP checks all
   succeed.** Process liveness and an open port are not evidence of health.
5. **A failing worker leaves selection immediately**, and its established
   sessions are terminated before anything is stopped or restarted.
6. **An established TCP session is never migrated to another exit.**
7. **Credentials, private keys, auth files and whole profile bodies are never
   logged** — including inside error messages, which must not echo subprocess
   output or argument vectors.
8. **Original `.ovpn` files are never modified.** Derived profiles are written
   mode `0600` under the runtime directory instead.
9. **The public listener defaults to loopback**, and a non-loopback listener is
   refused without authentication unless explicitly overridden.
10. **No shell, ever.** `ip`, `nft` and `openvpn` are executed through
    `exec.CommandContext` with argument vectors, behind the `process.Runner` and
    `process.Starter` interfaces. Every identifier reaching a command or an
    nftables document is validated first.
11. **Cleanup is idempotent** and **configuration reload is transactional** — an
    invalid candidate configuration must leave the running one untouched.

Source profiles carrying executable directives (script, plugin, alternate route
programs, file logging) are rejected by design. Do not loosen that check to make
a particular provider's profile work.

## Getting set up

Go 1.26 or newer. There is no build tooling beyond the Makefile:

```sh
make check        # gofmt + go test ./... + go vet ./...
make test-race    # what CI runs
make build
```

Before opening a pull request, `make check`, `make test-race`, and
`go run golang.org/x/vuln/cmd/govulncheck@v1.3.0 ./...` should all be clean.
CI runs all three plus a build, an install-layout smoke test, and a release
archive build.

## Tests

Unit tests are table-driven and use in-package fakes that record the exact
argument vectors passed to `ip`, `nft` and `openvpn`. Assert on those vectors
rather than shelling out — see `internal/namespace/manager_test.go` and
`internal/controller/worker_test.go` for the pattern.

The privileged suite is build-tagged and opt-in:

```sh
sudo -E env VPNPOOLD_INTEGRATION=1 go test -tags=integration ./test/integration -v
```

**Run it only in a disposable virtual machine.** It creates namespaces, veth
pairs and default-drop firewall rules on the host it runs on. `test/vm/`
provisions a suitable Ubuntu guest and a companion OpenVPN server, so no
commercial VPN provider is needed; `docs/testing.md` has the full procedure.

**Never report privileged results as passing unless you actually ran them.** If
you could not run them, say so in the pull request. A reviewer needs to know
which claims were verified and which were reasoned.

## Commits and pull requests

Commit subjects follow the conventional-commit form, because release notes are
drafted from pull request titles:

```
feat: add UDP ASSOCIATE support
fix: close the session-tracking window during dispatcher handshake
docs: record the kill-switch ordering rationale
build: package deb and rpm artifacts
test: cover stale-generation health results
```

A `!` after the type (`feat!:`) marks a breaking change. Pull requests are
labelled automatically from the title, and those labels decide both the release
note section and the next version number, so the title matters more than usual.

Keep changes to the smallest coherent increment, add or update tests with the
change, and report the actual test results — not the ones you expect.

## Changing the configuration schema

The configuration carries an explicit integer `version: 1`, and the binary
refuses both older and newer schemas rather than guessing. Changing it requires
a documented, separately testable migration from every supported prior version.
See `docs/release.md` before starting.

## Reporting a vulnerability

Do not open a public issue for a security defect. Use GitHub's private
vulnerability reporting on this repository so a fix can be prepared before the
problem is public.

## Where things live

`docs/architecture.md` for the fail-closed startup order, `docs/security-model.md`
for the threat model, `docs/controller.md` for worker lifecycle and failure
classes, `docs/testing.md` for the test matrix, and `docs/troubleshooting.md`
for what validation rejects and why.
