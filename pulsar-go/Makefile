# pulsar-go — Go bindings for the Pulsar HTTP engine.
#
# Self-contained flow: lib/libsolidc.a and lib/libpulsar.a are prebuilt
# musl static archives checked into this repo (see lib/.version), and
# third_party/ holds only the minimal C header snapshots cgo needs to
# compile bridge.c against them (pulsar public headers + the solidc
# headers they include). No system libpulsar/libsolidc required, and no
# C sources are shipped — `go build` works straight after `go get`.
#
#   make libs          # verify the checked-in archives + headers are present
#   make libs-rebuild  # maintainer-only: rebuild lib/*.a from live sources
#                      # (needs the monorepo checkout, musl-gcc, x86_64 Linux)
#   make build         # go build ./...
#   make static        # fully static musl binary at bin/server
#   make test          # go vet + go test
#   make smoke         # run bin/server, exercise endpoints, shut down
#   make install       # install static binary to $(PREFIX)/bin (PREFIX=/usr/local)
#
# Overrides: CC=musl-gcc (default, must match the prebuilt archives),
# OPT=-O2, NUM_WORKERS=8, PREFIX=..., VERSION=x.y.z (for `make tag`).
#
# Linux x86_64 only. The checked-in archives are built with musl-gcc;
# building the Go module with any other CC (e.g. glibc gcc) mixes libcs
# and is unsupported.

CC          ?= musl-gcc
OPT         ?= -O3
NUM_WORKERS ?= 4
PREFIX      ?= /usr/local
BINDIR      := bin
LIBDIR      := lib
STATIC_BIN  := $(BINDIR)/server

export CC
export CGO_ENABLED := 1

LIBS := $(LIBDIR)/libsolidc.a $(LIBDIR)/libpulsar.a

.PHONY: help libs libs-rebuild build static test vet smoke install deploy clean tag

help:
	@echo "Targets:"
	@echo "  libs         Verify checked-in prebuilt musl archives + headers"
	@echo "  libs-rebuild Rebuild lib/*.a from live sources (maintainer, x86_64 Linux + musl-gcc)"
	@echo "  build        go build ./..."
	@echo "  static       Fully static musl binary at $(STATIC_BIN)"
	@echo "  test         go vet + go test ./..."
	@echo "  vet          go vet ./..."
	@echo "  smoke        Boot $(STATIC_BIN), curl endpoints, shut down"
	@echo "  install      Install binary to \$$(PREFIX)/bin [$(PREFIX)]"
	@echo "  tag          Create go-gettable tag pulsar-go/v\$$(VERSION)"
	@echo "  clean        Remove bin/ (lib/*.a are checked in, use libs-rebuild to refresh)"

# The archives are checked in; this only verifies they (and the header
# snapshots cgo compiles against) are present. It never recompiles.
libs:
	@test -f "$(LIBDIR)/libsolidc.a" -a -f "$(LIBDIR)/libpulsar.a" || \
		{ echo "error: $(LIBDIR)/*.a missing. This is a full checkout issue — run 'make libs-rebuild' (x86_64 Linux + musl-gcc)."; \
		  echo "If you arrived via 'go get', re-fetch the module: the archives are checked in upstream."; exit 1; }
	@test -d third_party/pulsar/include -a -d third_party/solidc/include/solidc || \
		{ echo "error: third_party/ header snapshots missing. Run 'make libs-rebuild'."; exit 1; }
	@echo "libs ok (prebuilt musl, see $(LIBDIR)/.version):"
	@cat $(LIBDIR)/.version 2>/dev/null || true

# Maintainer-only: refresh the header snapshots and rebuild the archives
# from the live monorepo sources. Not part of the normal `go get` flow.
libs-rebuild:
	OPT="$(OPT)" NUM_WORKERS="$(NUM_WORKERS)" ./scripts/build-libs.sh

build: libs
	go build ./...

static: libs
	mkdir -p $(BINDIR)
	CC="$(CC)" CGO_ENABLED=1 go build -trimpath \
		-ldflags '-linkmode external -extldflags "-static" -s -w' \
		-o $(STATIC_BIN) ./cmd/server
	file $(STATIC_BIN) || true

vet: libs
	go vet ./...

test: vet
	CC="$(CC)" CGO_ENABLED=1 go test ./...

smoke: static
	./scripts/smoke.sh ./$(STATIC_BIN)

install: static
	./scripts/deploy.sh --prefix "$(PREFIX)" --binary ./$(STATIC_BIN)

deploy: install

clean:
	rm -rf $(BINDIR)

# Usage: make tag VERSION=0.1.0  ->  pulsar-go/v0.1.0 (module-aware tag so
# `go get github.com/abiiranathan/pulsar/pulsar-go@v0.1.0` resolves).
tag:
	@if [ -z "$(VERSION)" ]; then echo "usage: make tag VERSION=x.y.z" >&2; exit 1; fi
	git tag -a "pulsar-go/v$(VERSION)" -m "pulsar-go v$(VERSION)"
	@echo "Created tag pulsar-go/v$(VERSION). Push with: git push origin pulsar-go/v$(VERSION)"
