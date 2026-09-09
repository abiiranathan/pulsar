# pulsar-go — Go bindings for the Pulsar HTTP engine.
#
# Self-contained flow: solidc is vendored under third_party/, compiled with
# $(CC) (default musl-gcc) into lib/*.a, and linked by cgo. No system
# libpulsar/libsolidc required.
#
#   make vendor   # fetch + prune solidc at the pinned commit
#   make libs     # build lib/libsolidc.a lib/libpulsar.a with $(CC)
#   make build    # go build ./...
#   make static   # fully static musl binary at bin/server
#   make test     # go vet + go test
#   make smoke    # run bin/server, exercise endpoints, shut down
#   make install  # install static binary to $(PREFIX)/bin (PREFIX=/usr/local)
#
# Overrides: CC=gcc (glibc dev loop), OPT=-O2, NUM_WORKERS=8, PREFIX=...,
# VERSION=x.y.z (for `make tag`).

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
LIB_CC_STAMP := $(LIBDIR)/.cc

.PHONY: help vendor libs build static test vet smoke install deploy clean tag

help:
	@echo "Targets:"
	@echo "  vendor   Vendor solidc at the pinned commit (third_party/)"
	@echo "  libs     Build static C archives with \$$(CC) [$(CC)]"
	@echo "  build    go build ./..."
	@echo "  static   Fully static musl binary at $(STATIC_BIN)"
	@echo "  test     go vet + go test ./..."
	@echo "  vet      go vet ./..."
	@echo "  smoke    Boot $(STATIC_BIN), curl endpoints, shut down"
	@echo "  install  Install binary to \$$(PREFIX)/bin [$(PREFIX)]"
	@echo "  tag      Create go-gettable tag pulsar-go/v\$$(VERSION)"
	@echo "  clean    Remove bin/, lib/*.a"

vendor:
	./scripts/vendor.sh

# Archives must always match the current $(CC): musl-built objects linked by
# glibc gcc (or vice versa) mix libcs. The stamp forces a rebuild on switch.
libs: scripts/build-libs.sh third_party/solidc/.pin third_party/pulsar/.sync
	@if [ ! -f "$(LIBDIR)/libsolidc.a" ] || [ ! -f "$(LIBDIR)/libpulsar.a" ] || \
	    [ "$$(cat $(LIB_CC_STAMP) 2>/dev/null)" != "$(CC)" ]; then \
		OPT="$(OPT)" NUM_WORKERS="$(NUM_WORKERS)" ./scripts/build-libs.sh && \
		echo "$(CC)" > $(LIB_CC_STAMP); \
	else \
		echo "libs up to date (built with $$(cat $(LIB_CC_STAMP)))"; \
	fi

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
	rm -rf $(BINDIR) $(LIBDIR)/*.a

# Usage: make tag VERSION=0.1.0  ->  pulsar-go/v0.1.0 (module-aware tag so
# `go get github.com/abiiranathan/pulsar/pulsar-go@v0.1.0` resolves).
tag:
	@if [ -z "$(VERSION)" ]; then echo "usage: make tag VERSION=x.y.z" >&2; exit 1; fi
	git tag -a "pulsar-go/v$(VERSION)" -m "pulsar-go v$(VERSION)"
	@echo "Created tag pulsar-go/v$(VERSION). Push with: git push origin pulsar-go/v$(VERSION)"
