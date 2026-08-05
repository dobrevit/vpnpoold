.PHONY: all build test test-race vet format-check check check-host integration install dist clean

VERSION ?= 0.1.0-dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/dobrevit/vpnpoold/internal/buildinfo.Version=$(VERSION)
LDFLAGS += -X github.com/dobrevit/vpnpoold/internal/buildinfo.Commit=$(COMMIT)
LDFLAGS += -X github.com/dobrevit/vpnpoold/internal/buildinfo.Date=$(BUILD_DATE)

all: check

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o vpnpoold ./cmd/vpnpoold

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

format-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

check: format-check test vet

check-host:
	go run ./cmd/vpnpoold validate-host

integration:
	@test "$$VPNPOOLD_INTEGRATION" = "1" || { echo "set VPNPOOLD_INTEGRATION=1 explicitly"; exit 2; }
	go test -tags=integration ./test/integration -v

install: build
	./deploy/install.sh ./vpnpoold

dist:
	./deploy/package.sh "$(VERSION)" ./dist

clean:
	rm -f ./vpnpoold
