# pulsar-go — Go bindings for the Pulsar HTTP engine

Go bindings for [Pulsar](../README.md), a high-performance HTTP server
engine written in C. The event loop, HTTP parser, router, and response
assembler run in C (`../src/pulsar.c`, `../src/routing.c`); this package
provides idiomatic Go routing, middleware, and request handling on top.

See `doc.go` for the full architecture, threading, and memory model.

## Layout

| File        | Contents                                                        |
|-------------|-----------------------------------------------------------------|
| `doc.go`    | Package documentation (start here)                              |
| `pulsar.go` | Engine, routing, `Context` request/response API                 |
| `form.go`   | Form parsing: URL-encoded + multipart, zero-copy file uploads   |
| `bridge.h/c`| cgo glue compiled into the Go package (not into `libpulsar`)    |
| `exports.go`| C→Go dispatcher trampoline                                     |
| `cmd/server`| Example server                                                 |

## Requests

```go
app.Get("/users/:id", func(c *pulsar.Context) error {
    return c.JSON(200, map[string]string{"id": c.Param("id")})
})
```

- `c.Param / c.Query / c.Header` return **owned copies**, safe to retain.
- `c.ParamView / c.QueryView / c.HeaderView` are **zero-copy views** into
  C memory, valid only for the current request — faster, but copy them
  (e.g. `strings.Clone`) to keep them.
- `c.Body()` is always zero-copy; `c.Queries()` / `c.Headers()` enumerate
  everything as views; `c.RoutePattern()` and `c.ContentLength()` expose
  metadata without extra parsing.

## Forms

URL-encoded bodies are parsed in pure Go over the zero-copy body:

```go
name := c.PostFormValue("name")
all := c.PostForm() // map[string][]string, percent-decoded
```

Multipart uploads (`multipart/form-data`, RFC 7578) are parsed by the C
engine (`../src/forms.c`) into a private arena. **File bytes are never
copied** — `UploadedFile.Data` windows the request body, with the
boundary CRLF already stripped:

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

`c.FormValue(name)` checks multipart fields, then the URL-encoded body,
then the query string. The parsed form is cached per request and freed
automatically when the request completes (`Form.Close` is idempotent).

## Responses

Bodies buffer in Go and flush once via a single cgo call, so repeated
`c.Write` costs no extra transitions. Single-shot helpers (`String`,
`JSON`, `HTML`, `Blob`, `Send`, `NoContent`, `Redirect`) commit once and
return `ErrResponseAlreadyWritten` on reuse.

## Build

```bash
./build.sh            # rebuild C engine via CMake, run the example
go vet ./... && go test ./...
```

The `//cgo` directives in `pulsar.go` expect `../build/lib/libpulsar`
(`cmake -S .. -B ../build && cmake --build ../build`).
