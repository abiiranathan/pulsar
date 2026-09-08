// Package pulsar provides Go bindings for the Pulsar high-performance
// HTTP server engine written in C.
//
// # Architecture
//
// Pulsar runs its event loop, HTTP parser, router, and response assembler
// in C (see ../src/pulsar.c, ../src/routing.c). Routes registered from Go
// are installed in the C router with a small integer route ID; when a
// request matches, C calls back into Go through goPulsarDispatcher with
// only that ID (O(1), no string lookup on the hot path). The Go Engine
// then runs the middleware/handler chain for the ID and flushes the
// buffered response with a single cgo call.
//
// # Threading
//
// C worker threads invoke Go handlers. A Context is created fresh per
// request and is only ever touched by the goroutine running its chain;
// it must not be retained or used after the handler returns, and it is
// not safe for concurrent use.
//
// Pulsar supports exactly one running Engine per process (see
// activeEngine); Listen blocks in the C event loop.
//
// # Memory and zero-copy rules
//
// Request data lives in C memory owned by the server:
//
//   - Body bytes live in the connection's arena-backed receive buffer.
//     Context.Body returns a zero-copy slice aliasing that buffer — no
//     copy is made. The slice is valid only for the current request;
//     copy it if it must outlive the handler.
//   - Param, Query, and Header return owned Go strings (copied), which
//     are safe to retain. Their zero-copy counterparts ParamView,
//     QueryView, and HeaderView alias C memory without copying and are
//     valid only for the current request.
//   - Field and file metadata from multipart forms (names, filenames,
//     MIME types, field values) alias the form's C arena and are valid
//     until the request ends. Uploaded file payloads alias the request
//     body itself: no file bytes are ever copied by the parser.
//   - Response bodies are buffered in Go (Context.buf) and flushed once
//     after the chain completes, so repeated Write calls cost no extra
//     cgo transitions.
//
// # Forms
//
// Two content types are supported (see form.go):
//
//   - application/x-www-form-urlencoded is parsed in pure Go over the
//     zero-copy body; percent-decoding necessarily allocates the decoded
//     output while the scan itself borrows the body.
//   - multipart/form-data (RFC 7578, see ../include/forms.h and
//     ../src/forms.c) is parsed by the C engine into a private arena.
//     File contents are exposed as offset/size windows into the body and
//     are never copied; use UploadedFile.Data for the zero-copy payload
//     or SaveUploadedFile to persist it.
//
// # Example
//
//	app := pulsar.New()
//	app.Use(pulsar.Recover())
//	app.Get("/hello/:name", func(c *pulsar.Context) error {
//		return c.String(200, "hello "+c.Param("name"))
//	})
//	app.Post("/upload", func(c *pulsar.Context) error {
//		f, err := c.FormFile("avatar")
//		if err != nil {
//			return err
//		}
//		return c.SaveUploadedFile(f, "/tmp/"+f.Filename)
//	})
//	app.Listen("0.0.0.0", 8080)
package pulsar
