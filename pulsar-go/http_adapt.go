package pulsar

/*
#include "bridge.h"
*/
import "C"

import (
	"bytes"
	"context"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// This file adapts Pulsar handlers to and from the standard library's
// net/http world.
//
// Two directions are supported:
//
//   - net/http inside Pulsar: WrapHandler / WrapHandlerFunc wrap an
//     http.Handler (or func) as a Pulsar HandlerFunc, so existing stdlib
//     handlers and middleware (prometheus, pprof, chi sub-routers, …) run
//     inside a Pulsar route.
//   - Pulsar inside net/http: ToHTTPHandler converts a Pulsar HandlerFunc
//     chain into an http.Handler, so Pulsar handlers run under net/http
//     (net/http.Server, httptest, stdlib middleware) with no C engine.
//
// The Pulsar -> net/http direction runs the chain against a Context
// detached from C (conn == nil; see NewTestContext). Every Context
// accessor falls back to Go-owned fields in that mode, and multipart
// forms are parsed with mime/multipart instead of the C engine, so the
// converted handler supports params, queries, headers, bodies, forms,
// files, redirects and file responses without a live server.

// pulsarParamsKey carries Pulsar path params into the *http.Request built
// for a wrapped stdlib handler. Retrieve them with ParamsFromRequest.
type pulsarParamsKey struct{}

// ParamsFromRequest returns the Pulsar path params captured for r by
// WrapHandler, or nil if r did not originate from a Pulsar request.
func ParamsFromRequest(r *http.Request) map[string]string {
	if r == nil {
		return nil
	}
	if v := r.Context().Value(pulsarParamsKey{}); v != nil {
		if m, ok := v.(map[string]string); ok {
			return m
		}
	}
	return nil
}

// ----------------------------------------------------------------
// net/http inside Pulsar
// ----------------------------------------------------------------

// pulsarResponseWriter captures an stdlib handler's output so it can be
// replayed onto a Pulsar Context. It implements http.ResponseWriter.
type pulsarResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
	wrote  bool
}

var rwPool = sync.Pool{
	New: func() any {
		return &pulsarResponseWriter{
			header: make(http.Header, 32),
		}
	},
}

func acquireResponseWriter() *pulsarResponseWriter {
	rw := rwPool.Get().(*pulsarResponseWriter)
	rw.status = 0
	rw.wrote = false
	rw.body.Reset()
	clear(rw.header)
	return rw
}

func releaseResponseWriter(rw *pulsarResponseWriter) {
	// Don't retain huge buffers in pool
	if rw.body.Cap() > 64*1024 {
		return
	}
	rwPool.Put(rw)
}

func (w *pulsarResponseWriter) Header() http.Header { return w.header }

func (w *pulsarResponseWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.status = status
	w.wrote = true
}

func (w *pulsarResponseWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}

// buildHTTPRequest translates the current Pulsar request into an
// *http.Request for a wrapped stdlib handler.
//
// The body aliases the Pulsar body buffer via bytes.NewReader — no copy —
// which is safe because the wrapped handler runs synchronously inside the
// Pulsar handler. Path parameters are populated both via Go 1.22+ req.SetPathValue
// (for r.PathValue) and request context (for ParamsFromRequest).
func (c *Context) buildHTTPRequest() *http.Request {
	method := c.Method()
	if method == "" {
		method = http.MethodGet
	}
	path := c.Path()
	if path == "" {
		path = "/"
	}

	// 1. Build query string without intermediate map allocations.
	var rawQuery string
	if c.conn != nil {
		if count := int(C.bridge_query_count(c.conn)); count > 0 {
			var b strings.Builder
			for i := range count {
				var cName, cVal *C.char
				var nLen, vLen C.size_t
				if C.bridge_query_at(c.conn, C.size_t(i), &cName, &nLen, &cVal, &vLen) == 0 {
					continue
				}
				if b.Len() > 0 {
					b.WriteByte('&')
				}
				b.WriteString(url.QueryEscape(unsafeView(cName, nLen)))
				b.WriteByte('=')
				b.WriteString(url.QueryEscape(unsafeView(cVal, vLen)))
			}
			rawQuery = b.String()
		}
	} else if len(c.queryVals) > 0 {
		rawQuery = url.Values(c.queryVals).Encode()
	}

	// 2. Populate headers directly without allocating an intermediate map.
	header := make(http.Header)
	var host string
	if c.conn != nil {
		if count := int(C.bridge_req_headers_count(c.conn)); count > 0 {
			header = make(http.Header, count)
			for i := range count {
				var cName, cVal *C.char
				var nLen, vLen C.size_t
				if C.bridge_req_header_at(c.conn, C.size_t(i), &cName, &nLen, &cVal, &vLen) != 0 {
					name := unsafeView(cName, nLen)
					val := C.GoStringN(cVal, C.int(vLen))
					header.Add(name, val)
					if host == "" && strings.EqualFold(name, "Host") {
						host = val
					}
				}
			}
		}
	} else if len(c.reqHeaders) > 0 {
		header = c.reqHeaders.Clone()
		host = header.Get("Host")
	}

	// 3. Body: use http.NoBody for empty payloads, bytes.NewReader alias otherwise.
	var body io.ReadCloser = http.NoBody
	var getBody func() (io.ReadCloser, error)

	contentLength := int64(0)
	if b := c.Body(); len(b) > 0 {
		contentLength = int64(len(b))
		body = io.NopCloser(bytes.NewReader(b))
		getBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(b)), nil
		}
	} else if cl := c.ContentLength(); cl > 0 {
		contentLength = int64(cl)
	}

	u := &url.URL{
		Path:     path,
		RawQuery: rawQuery,
		Host:     host,
	}

	// 4. Context & Path parameters.
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	params := c.Params()
	if len(params) > 0 {
		ctx = context.WithValue(ctx, pulsarParamsKey{}, params)
	}

	// 5. Assemble http.Request directly without url.Parse overhead.
	req := (&http.Request{
		Method:        method,
		URL:           u,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          body,
		GetBody:       getBody,
		ContentLength: contentLength,
		Host:          host,
		RequestURI:    u.RequestURI(),
	}).WithContext(ctx)

	// 6. Set Go 1.22+ path parameters for r.PathValue(name).
	for k, v := range params {
		req.SetPathValue(k, v)
	}

	return req
}

// replayToContext copies a captured stdlib response onto c. Headers set by
// the stdlib handler are staged via SetHeader; the status and body commit
// through the normal buffered path. A handler that wrote nothing leaves c
// untouched so the Pulsar chain can still produce its own response.
func (c *Context) replayToContext(w *pulsarResponseWriter) {
	if len(w.header) == 0 && !w.wrote && w.body.Len() == 0 {
		return
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	for k := range w.header {
		c.SetHeader(k, w.header.Get(k))
	}
	c.status = status
	c.written = true
	if w.body.Len() > 0 {
		c.buf = append(c.buf, w.body.Bytes()...)
	}
}

// WrapHandler adapts an http.Handler as a Pulsar HandlerFunc.
//
// The current Pulsar request (method, path, query, headers, body) is
// translated to an *http.Request, h serves it into a buffer, and the
// captured status/headers/body are replayed onto the Pulsar Context.
//
// If a Pulsar response was already committed, the wrapped handler is not
// invoked and ErrResponseAlreadyWritten is returned. A wrapped handler
// that writes nothing leaves the Context untouched.
func WrapHandler(h http.Handler) HandlerFunc {
	if h == nil {
		panic("pulsar: WrapHandler called with nil http.Handler")
	}
	return func(c *Context) error {
		if c.ResponseWritten() {
			return ErrResponseAlreadyWritten
		}
		rw := acquireResponseWriter()
		defer releaseResponseWriter(rw)

		h.ServeHTTP(rw, c.buildHTTPRequest())
		c.replayToContext(rw)
		return nil
	}
}

// WrapHandlerFunc adapts an http.HandlerFunc as a Pulsar HandlerFunc.
// It is shorthand for WrapHandler(http.HandlerFunc(f)).
func WrapHandlerFunc(f http.HandlerFunc) HandlerFunc {
	return WrapHandler(http.HandlerFunc(f))
}

// WrapH is an alias for WrapHandler.
func WrapH(h http.Handler) HandlerFunc { return WrapHandler(h) }

// WrapF is an alias for WrapHandlerFunc.
func WrapF(f http.HandlerFunc) HandlerFunc { return WrapHandlerFunc(f) }

// WrapMiddleware adapts stdlib middleware of the form
// func(http.Handler) http.Handler as Pulsar middleware.
//
// The remainder of the Pulsar chain runs as the "next" http.Handler: when
// the middleware invokes it, pending Pulsar handlers execute with Next and
// their response is captured back into the middleware's ResponseWriter, so
// the middleware can observe or mutate status, headers and body as usual.
// Call it like any Pulsar middleware:
//
//	app.Use(pulsar.WrapMiddleware(func(next http.Handler) http.Handler {
//		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//			w.Header().Set("X-From-Std", "1")
//			next.ServeHTTP(w, r)
//		})
//	}))
//
// WrapMiddleware adapts stdlib middleware of the form
// func(http.Handler) http.Handler as Pulsar middleware.
//
// The remainder of the Pulsar chain runs as the "next" http.Handler: when
// the middleware invokes it, pending Pulsar handlers execute with Next and
// their response is captured back into the middleware's ResponseWriter, so
// the middleware can observe or mutate status, headers and body as usual.
// Call it like any Pulsar middleware:
//
//	app.Use(pulsar.WrapMiddleware(func(next http.Handler) http.Handler {
//		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//			w.Header().Set("X-From-Std", "1")
//			next.ServeHTTP(w, r)
//		})
//	}))
func WrapMiddleware(mw func(http.Handler) http.Handler) HandlerFunc {
	if mw == nil {
		panic("pulsar: WrapMiddleware called with nil middleware")
	}
	return func(c *Context) error {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			// Run the rest of the Pulsar chain, capturing whatever it
			// writes so the stdlib middleware sees a normal response.
			// Chain errors are routed to the Engine's ErrorHandler (or the
			// default) exactly as Engine.dispatch would, so the middleware
			// observes the rendered error response.
			runChain := func() {
				if err := c.Next(); err != nil {
					if c.engine != nil && c.engine.errorHandler != nil {
						c.engine.errorHandler(err, c)
					} else {
						DefaultErrorHandler(err, c)
					}
				}
			}

			rw, ok := w.(*pulsarResponseWriter)
			if !ok {
				// Middleware replaced the writer (e.g. gzip): run the chain
				// into a fresh pooled buffer, then copy it out.
				tmp := acquireResponseWriter()
				defer releaseResponseWriter(tmp)

				runChain()

				// Capture the chain's committed status before
				// copyContextToWriter drains and zeroes it from c.
				fallbackStatus := responseStatus(c)
				copyContextToWriter(c, tmp)
				for k := range tmp.header {
					w.Header().Set(k, tmp.header.Get(k))
				}
				status := tmp.status
				if status == 0 {
					status = fallbackStatus
				}
				w.WriteHeader(status)
				_, _ = w.Write(tmp.body.Bytes())
				return
			}

			runChain()
			copyContextToWriter(c, rw)
		})

		rw := acquireResponseWriter()
		defer releaseResponseWriter(rw)

		mw(next).ServeHTTP(rw, c.buildHTTPRequest())

		if !nextCalled {
			// The stdlib middleware short-circuited without invoking
			// next: abort the Pulsar chain so handlers after this
			// middleware do not run, mirroring c.Abort semantics.
			c.Abort()
		}

		// Reconcile the middleware's final buffer back onto c.
		// copyContextToWriter moved the chain's status/body into rw (the
		// Go header mirror is retained), so rw is now authoritative.
		if len(rw.header) == 0 && !rw.wrote && rw.body.Len() == 0 {
			return nil
		}

		for k := range rw.header {
			if c.respHeaders.Get(k) != rw.header.Get(k) {
				c.SetHeader(k, rw.header.Get(k))
			}
		}

		status := rw.status
		if status == 0 {
			status = http.StatusOK
		}
		c.status = status
		c.written = true
		if rw.body.Len() > 0 {
			c.buf = append(c.buf, rw.body.Bytes()...)
		}
		return nil
	}
}

// copyContextToWriter drains the Pulsar Context's staged response into w
// without flushing to C, for handoff to stdlib middleware writers.
// Staged headers are mirrored into respHeaders in both live and detached
// modes (see SetHeader), so the middleware observes the full header set.
func copyContextToWriter(c *Context, w *pulsarResponseWriter) {
	for k := range c.respHeaders {
		w.header.Set(k, c.respHeaders.Get(k))
	}
	if c.written {
		status := c.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if len(c.buf) > 0 {
			_, _ = w.Write(c.buf)
		}
		// Mark the chain output consumed: the outer reconcile will replay
		// the middleware's final buffer, so clear staged state to avoid a
		// double commit.
		c.buf = c.buf[:0]
		c.written = false
		c.status = 0
	}
}

// responseStatus returns the committed status, defaulting to 200.
func responseStatus(c *Context) int {
	if c.status != 0 {
		return c.status
	}
	return http.StatusOK
}

// ----------------------------------------------------------------
// Pulsar inside net/http
// ----------------------------------------------------------------

// NewTestContext builds a Context detached from the C engine for unit
// testing Pulsar handlers with plain Go (no server, no cgo traffic).
// r supplies method, path, query, headers and body; params supplies path
// parameters as the router would have parsed them.
//
// The returned Context supports the full response API (String, JSON,
// Write, SetHeader, Redirect, ServeFile, …) buffered in Go. Drive it by
// calling the handler directly, or convert it with ToHTTPHandler and use
// httptest:
//
//	req := httptest.NewRequest("GET", "/users/42?q=x", nil)
//	rec := httptest.NewRecorder()
//	ToHTTPHandler(myHandler).ServeHTTP(rec, req)
func NewTestContext(r *http.Request, params map[string]string) *Context {
	c := &Context{index: -1}
	if r == nil {
		c.method = http.MethodGet
		c.path = "/"
		return c
	}
	c.method = r.Method
	if c.method == "" {
		c.method = http.MethodGet
	}
	c.path = r.URL.Path
	if c.path == "" {
		c.path = "/"
	}
	c.reqHeaders = make(http.Header)
	for k, vs := range r.Header {
		for _, v := range vs {
			c.reqHeaders.Add(k, v)
		}
	}
	if r.Host != "" && c.reqHeaders.Get("Host") == "" {
		c.reqHeaders.Set("Host", r.Host)
	}
	if r.URL != nil && len(r.URL.Query()) > 0 {
		c.queryVals = make(map[string][]string, len(r.URL.Query()))
		for k, vs := range r.URL.Query() {
			cp := make([]string, len(vs))
			copy(cp, vs)
			c.queryVals[k] = cp
		}
	}
	if r.Body != nil {
		if b, err := io.ReadAll(r.Body); err == nil {
			c.body = b
		}
	}
	if len(params) > 0 {
		c.params = make(map[string]string, len(params))
		maps.Copy(c.params, params)
	}
	if r.URL != nil {
		c.routePat = r.URL.Path
	}
	if r.Context() != nil {
		c.ctx = r.Context()
	}
	return c
}

// writeTestContextToHTTP renders a detached Context's staged response onto
// w: headers first, then status (default 200 when a body or headers were
// staged, 200 empty otherwise), then body.
func writeTestContextToHTTP(c *Context, w http.ResponseWriter) {
	for k := range c.respHeaders {
		w.Header().Set(k, c.respHeaders.Get(k))
	}
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if len(c.buf) > 0 {
		_, _ = w.Write(c.buf)
	}
}

// ToHTTPHandler converts a Pulsar HandlerFunc chain into an http.Handler,
// running handlers against a detached Context built from each incoming
// *http.Request. Route params use Express-style ":name" segments of
// pattern when pattern is non-empty:
//
//	h := pulsar.ToHTTPHandler(myHandler, authMw, pulsar.WithPattern("/users/:id"))
//	http.Handle("/users/", h)
//
// Errors returned from the chain go to DefaultErrorHandler (or the custom
// handler set via WithErrorHandler), mirroring Engine.dispatch. The
// response is rendered with net/http semantics.
// ToHTTPHandler converts a Pulsar HandlerFunc chain into an http.Handler,
// running handlers against a detached Context built from each incoming
// *http.Request.
func ToHTTPHandler(h HandlerFunc, opts ...ToHTTPOption) http.Handler {
	if h == nil {
		panic("pulsar: ToHTTPHandler called with nil handler")
	}
	cfg := toHTTPConfig{errorHandler: DefaultErrorHandler}
	for _, o := range opts {
		o(&cfg)
	}
	chain := append([]HandlerFunc{}, cfg.middleware...)
	chain = append(chain, h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var path string
		if r != nil && r.URL != nil {
			path = r.URL.Path
		}
		c := NewTestContext(r, matchPatternParams(cfg.patternSegments, path))
		if cfg.pattern != "" {
			c.routePat = cfg.pattern
		}
		c.chain = chain
		c.index = -1
		if err := c.Next(); err != nil {
			cfg.errorHandler(err, c)
		}
		writeTestContextToHTTP(c, w)
	})
}

type patternSegment struct {
	name    string
	isParam bool
}

// toHTTPConfig carries ToHTTPHandler options.
type toHTTPConfig struct {
	pattern         string
	patternSegments []patternSegment
	middleware      []HandlerFunc
	errorHandler    ErrorHandler
}

// ToHTTPOption customizes ToHTTPHandler.
type ToHTTPOption func(*toHTTPConfig)

// WithPattern sets the route pattern used to extract path params.
// It supports both Express style (:id) and standard/Go 1.22 style ({id}).
func WithPattern(pattern string) ToHTTPOption {
	return func(cfg *toHTTPConfig) {
		cfg.pattern = cleanPath(pattern)
		segs := splitPath(cfg.pattern)
		cfg.patternSegments = make([]patternSegment, len(segs))
		for i, s := range segs {
			if strings.HasPrefix(s, ":") && len(s) > 1 {
				// Express-style: :id or :id([0-9]+)
				name := s[1:]
				if idx := strings.IndexByte(name, '('); idx >= 0 {
					name = name[:idx]
				}
				cfg.patternSegments[i] = patternSegment{name: name, isParam: true}
			} else if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") && len(s) > 2 {
				// OpenAPI / Go 1.22 style: {id} or {id:[0-9]+}
				name := s[1 : len(s)-1]
				if idx := strings.IndexByte(name, ':'); idx >= 0 {
					name = name[:idx]
				}
				cfg.patternSegments[i] = patternSegment{name: name, isParam: true}
			} else {
				cfg.patternSegments[i] = patternSegment{name: s, isParam: false}
			}
		}
	}
}

// WithMiddleware appends Pulsar middleware run before the handler.
func WithMiddleware(mws ...HandlerFunc) ToHTTPOption {
	return func(cfg *toHTTPConfig) {
		cfg.middleware = append(cfg.middleware, mws...)
	}
}

// WithErrorHandler overrides the ErrorHandler invoked when the chain
// returns an error (default DefaultErrorHandler).
func WithErrorHandler(eh ErrorHandler) ToHTTPOption {
	return func(cfg *toHTTPConfig) {
		if eh != nil {
			cfg.errorHandler = eh
		}
	}
}

// matchPatternParams aligns the pre-parsed pattern segments against the incoming path.
// It uses a single-pass index scan with zero intermediate slice or string allocations.
func matchPatternParams(segs []patternSegment, path string) map[string]string {
	if len(segs) == 0 {
		return nil
	}
	p := strings.Trim(path, "/")
	if p == "" {
		return nil
	}

	var out map[string]string
	segIdx := 0
	start := 0

	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			if i > start {
				if segIdx >= len(segs) {
					return nil // Path contains more segments than pattern
				}
				seg := p[start:i]
				ps := segs[segIdx]
				if ps.isParam {
					if out == nil {
						out = make(map[string]string, len(segs))
					}
					out[ps.name] = seg
				} else if ps.name != seg {
					return nil // Static segment mismatch
				}
				segIdx++
			}
			start = i + 1
		}
	}

	if segIdx != len(segs) {
		return nil // Path contains fewer segments than pattern
	}
	return out
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// multipartFormStandalone parses the detached Context's body as
// multipart/form-data using the stdlib mime/multipart reader. Field
// names/values allocate as Go strings; file payloads are fully buffered
// (unlike the C engine's zero-copy windows) since there is no request
// arena to window into. Called by Context.MultipartForm when conn == nil.
func (c *Context) multipartFormStandalone() (*Form, error) {
	ct := c.Header("Content-Type")
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.HasPrefix(mt, "multipart/") {
		fErr := NewHTTPError(http.StatusBadRequest, "invalid multipart form")
		c.formErr = fErr
		return nil, fErr
	}
	boundary, ok := params["boundary"]
	if !ok || boundary == "" {
		fErr := NewHTTPError(http.StatusBadRequest, "invalid multipart form")
		c.formErr = fErr
		return nil, fErr
	}
	body := c.Body()
	if len(body) == 0 {
		fErr := NewHTTPError(http.StatusBadRequest, "invalid multipart form")
		c.formErr = fErr
		return nil, fErr
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	f := &Form{ctx: c, body: body}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			fErr := NewHTTPError(http.StatusBadRequest, "invalid multipart form")
			c.formErr = fErr
			return nil, fErr
		}
		name := part.FormName()
		if name == "" {
			_, _ = io.Copy(io.Discard, part)
			continue
		}
		if filename := part.FileName(); filename != "" {
			data, err := io.ReadAll(part)
			if err != nil {
				fErr := NewHTTPError(http.StatusBadRequest, "invalid multipart form")
				c.formErr = fErr
				return nil, fErr
			}
			f.files = append(f.files, &UploadedFile{
				FieldName: name,
				Filename:  filename,
				MimeType:  part.Header.Get("Content-Type"),
				Data:      data,
				Size:      len(data),
			})
			continue
		}
		data, err := io.ReadAll(part)
		if err != nil {
			fErr := NewHTTPError(http.StatusBadRequest, "invalid multipart form")
			c.formErr = fErr
			return nil, fErr
		}
		f.fields = append(f.fields, formField{name: name, value: string(data)})
	}
	c.form = f
	return f, nil
}
