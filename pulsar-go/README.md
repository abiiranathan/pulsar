# pulsar-go — Go bindings for Pulsar Web Server

Go bindings for [Pulsar](../README.md), the HTTP server engine written in C.
The event loop, HTTP parser, router, and response assembler all live in C
(linked from the checked-in `lib/` archives); this package wraps that in an
idiomatic Go API for routing, middleware, and request handling.

Start with `doc.go` for the full architecture, threading, and memory model.

## Layout

| File         | Contents                                                      |
| ------------ | ------------------------------------------------------------- |
| `doc.go`     | Package documentation (start here)                            |
| `pulsar.go`  | Engine, routing, `Context` request/response API               |
| `form.go`    | Form parsing: URL-encoded + multipart, zero-copy file uploads |
| `bridge.h/c` | cgo glue compiled into the Go package (not into `libpulsar`)  |
| `exports.go` | C→Go dispatcher trampoline                                    |
| `cmd/server` | Example server                                                |

## Requests

```go
app.Get("/users/:id", func(c *pulsar.Context) error {
    return c.JSON(200, map[string]string{"id": c.Param("id")})
})
```

- `c.Param` / `c.Query` / `c.Header` return owned copies, safe to retain.
- `c.ParamView` / `c.QueryView` / `c.HeaderView` are zero-copy views into C
  memory, valid only for the current request. Faster, but clone them
  (`strings.Clone`) if you need to keep them around.
- `c.Body()` is always zero-copy. `c.Queries()` and `c.Headers()` enumerate
  everything as views. `c.RoutePattern()` and `c.ContentLength()` expose
  metadata without extra parsing.

## Forms

URL-encoded bodies are parsed in pure Go, directly over the zero-copy body:

```go
name := c.PostFormValue("name")
all := c.PostForm() // map[string][]string, percent-decoded
```

Multipart uploads (`multipart/form-data`, RFC 7578) are parsed by the C
engine (linked from `lib/`) into a private arena. File bytes are never
copied — `UploadedFile.Data` windows the request body directly.

```go
app.Post("/upload", func(c *pulsar.Context) error {
    file, err := c.FormFile("avatar")
    if err != nil {
        return err // 400
    }
    // file.Filename / file.MimeType are zero-copy, request-scoped.
    return c.SaveUploadedFile(file, "/tmp/"+file.Filename)
})
```

`c.FormValue(name)` checks multipart fields first, then the URL-encoded
body, then the query string. The parsed form is cached per request and
freed automatically once the request completes (`Form.Close` is
idempotent, so you don't need to guard against calling it twice).

## Responses

Bodies buffer in Go and flush once via a single cgo call, so repeated
`c.Write` calls don't cost extra transitions. The single-shot helpers
(`String`, `JSON`, `HTML`, `Blob`, `Send`, `NoContent`, `Redirect`) commit
once and return `ErrResponseAlreadyWritten` if you call a second one.

## Install

The module path is `github.com/abiiranathan/pulsar/pulsar-go` — note the
`/pulsar-go` suffix, since it lives inside the `pulsar/` monorepo. No
system libpulsar or libsolidc is required and no C compilation is needed:
musl static archives (`lib/libpulsar.a`, `lib/libsolidc.a`, see
`lib/.version`) are checked in, and `third_party/` holds only the minimal
header snapshots cgo compiles `bridge.c` against:

```bash
go get github.com/abiiranathan/pulsar/pulsar-go@latest
go build ./...
```

Linux x86_64 only: the archives are built with `musl-gcc`, so the Go
module must also be built with `CC=musl-gcc` (the Makefile default).
Mixing a glibc-built module with the musl archives (or vice versa) is
unsupported.

Releases are cut as module-aware tags (`pulsar-go/v0.1.0`), so any tagged
version resolves normally: `go get github.com/abiiranathan/pulsar/pulsar-go@v0.1.0`.

## Build

```bash
make libs         # verify the checked-in archives + headers are present
make libs-rebuild # maintainer-only: rebuild lib/*.a from live sources (x86_64 Linux + musl-gcc)
make build    # go build ./...
make vet      # go vet ./...
make test     # vet + go test ./...
make static   # fully static musl binary at bin/server
make smoke    # boot bin/server, exercise endpoints, shut down
./build.sh    # shortcut for local dev: verify libs + go run ./cmd/server
```

`CC` must stay `musl-gcc` to match the checked-in archives.
`OPT` (`-O3`) and `NUM_WORKERS` (`4`) tune `make libs-rebuild` only.

`src/regex.c` is excluded from `libsolidc.a` because it needs libpcre2 and
nothing in pulsar uses it. Set `SOLIDC_WITH_REGEX=1` (and point `CFLAGS_EXTRA`
at your pcre2 headers) when running `make libs-rebuild` if you need it
anyway (the final Go link then also needs `-lpcre2-8`).

## Refreshing the prebuilt archives (maintainers)

`lib/*.a` are built from the live monorepo C sources plus solidc at the
pinned commit (`third_party/solidc/.pin`). `make libs-rebuild` fetches
solidc to a temp dir (its sources are never vendored), recompiles both
archives, refreshes the `third_party/` header snapshots and `lib/.version`,
and must be committed as one unit. The pulsar header snapshot records its
source commit in `third_party/pulsar/.sync` — if it drifts from the live
`../include`, the bindings are linking against stale declarations, so
always rebuild (never hand-edit `third_party/`).

## Deploy

```bash
make static
sudo make install            # PREFIX=/usr/local -> /usr/local/bin/pulsar-server
sudo ./scripts/deploy.sh --prefix /usr/local
PORT=8080 ./bin/server       # run directly
```

The binary reads `PORT` (default `8080`).

The old CMake flow (`cmake -S .. -B ../build && cmake --build ../build`)
still builds the C library on its own, but the Go bindings don't consume
it — everything needed for `pulsar-go` is the checked-in `lib/*.a`
plus the `third_party/` header snapshots.
