# pulsar-go — Go bindings for Pulsar Web Server

Go bindings for [Pulsar](../README.md), the HTTP server engine written in C.
The event loop, HTTP parser, router, and response assembler all live in C
(`../src/pulsar.c`, `../src/routing.c`); this package wraps that in an
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
engine (`../src/forms.c`) into a private arena. File bytes are never
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
system libpulsar or libsolidc is required; solidc is vendored under
`third_party/` and built into static archives by `make`:

```bash
go get github.com/abiiranathan/pulsar/pulsar-go@latest
cd $(go env GOMODCACHE)/github.com/abiiranathan/pulsar*/pulsar-go*  # or inside your own module
make libs     # CC=musl-gcc by default; builds lib/libsolidc.a and lib/libpulsar.a
make build
```

Releases are cut as module-aware tags (`pulsar-go/v0.1.0`), so any tagged
version resolves normally: `go get github.com/abiiranathan/pulsar/pulsar-go@v0.1.0`.

## Build

```bash
make vendor   # (re-)vendor solidc at the pinned commit, see third_party/solidc/.pin
make libs     # static C archives with musl-gcc (override: CC=gcc for a glibc dev loop)
make build    # go build ./...
make vet      # go vet ./...
make test     # vet + go test ./...
make static   # fully static musl binary at bin/server
make smoke    # boot bin/server, exercise endpoints, shut down
./build.sh    # shortcut for local dev: make libs + go run ./cmd/server
```

`CC` has to match between `libs` and every Go step. The Makefile enforces
this with a stamp file (`lib/.cc`) and rebuilds the archives automatically
when it changes, so you can't accidentally link a musl archive against a
glibc build or vice versa. `OPT` (`-O3`) and `NUM_WORKERS` (`4`) tune the
C archives.

`src/regex.c` is excluded from `libsolidc.a` because it needs libpcre2 and
nothing in pulsar uses it. Set `SOLIDC_WITH_REGEX=1` (and point `CFLAGS_EXTRA`
at your pcre2 headers) if you need it anyway.

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
it anymore — everything needed for `pulsar-go` comes from `make libs`.
