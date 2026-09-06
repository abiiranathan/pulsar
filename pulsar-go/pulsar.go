package pulsar

/*
#cgo CFLAGS: -I${SRCDIR}/../include -D_GNU_SOURCE -O3
#cgo LDFLAGS: -L${SRCDIR}/../build/lib -L${SRCDIR}/../build/bin -lpulsar -lsolidc -lpthread -lm
#cgo LDFLAGS: -Wl,--disable-new-dtags -Wl,-rpath,${SRCDIR}/../build/lib
#include <stdlib.h>
#include "bridge.h"
#include "../include/pulsar.h"
#include "../include/status.h"
#include "../include/method.h"
*/
import "C"
import (
	"context" // for context.Context
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"unsafe"
)

var (
	// ErrResponseAlreadyWritten is returned when a handler attempts to set the
	// status code or dispatch a terminal response (String, JSON, Redirect, etc.)
	// after the response has already been committed via a prior terminal call.
	//
	// It is NOT returned by Write itself: Write may be called any number of
	// times to append to the buffered response body. It is returned by the
	// single-shot convenience methods (String, JSON, HTML, Redirect, NoContent)
	// when called a second time, since those represent "commit this exact body
	// now" rather than "append to the body".
	ErrResponseAlreadyWritten = errors.New("pulsar: response already committed")

	// activeEngineMu guards activeEngine.
	activeEngineMu sync.Mutex

	// activeEngine is the process-wide Engine instance reachable from the cgo
	// dispatch trampoline. Pulsar supports exactly one running Engine per
	// process; Listen sets this before entering the C event loop.
	activeEngine *Engine

	// zeroByte backs zero-length buffers passed across cgo. Taking the address
	// of a zero-length Go slice's data pointer is not guaranteed safe to pass
	// to C, so empty writes are pointed at this shared byte instead, with a
	// length of 0 so it is never actually dereferenced on the C side.
	zeroByte byte
)

// HandlerFunc is the signature for Pulsar handlers and middleware. Returning
// a non-nil error aborts the remaining chain and invokes the Engine's
// ErrorHandler.
type HandlerFunc func(c *Context) error

// ErrorHandler processes an error returned from a handler or middleware. It
// is responsible for producing a response on c if one has not already been
// written.
type ErrorHandler func(err error, c *Context)

// HTTPError pairs an HTTP status code with a response message and an
// optional wrapped internal error for logging or debugging. Handlers should
// return an *HTTPError (or wrap one) to control the status code sent to the
// client; returning a plain error results in a 500 via DefaultErrorHandler.
type HTTPError struct {
	Code     int   `json:"code"`    // HTTP status code to send to the client.
	Message  any   `json:"message"` // Response body payload: a string is sent as text, anything else as JSON.
	Internal error `json:"-"`       // Wrapped cause, not exposed to the client. Retrieved via Unwrap.
}

// Error implements the error interface, including the internal cause when
// present so that logs capture the underlying failure alongside the status
// code presented to the client.
func (e *HTTPError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("code=%d, message=%v, internal=%v", e.Code, e.Message, e.Internal)
	}
	return fmt.Sprintf("code=%d, message=%v", e.Code, e.Message)
}

// Unwrap exposes the internal cause to errors.Is, errors.As, and
// errors.AsType, so callers can inspect the underlying error without
// reaching into the Internal field directly.
func (e *HTTPError) Unwrap() error {
	return e.Internal
}

// NewHTTPError creates an *HTTPError for status code. If message is
// provided, its first element becomes the response payload; otherwise the
// standard library's text for code is used (e.g. "Not Found" for 404).
func NewHTTPError(code int, message ...any) *HTTPError {
	he := &HTTPError{Code: code, Message: http.StatusText(code)}
	if len(message) > 0 {
		he.Message = message[0]
	}
	return he
}

// WithInternal attaches an underlying cause for logging and returns e for
// chaining. The cause is never sent to the client.
func (e *HTTPError) WithInternal(err error) *HTTPError {
	e.Internal = err
	return e
}

// Context carries per-request state through a handler chain: path and query
// parameters, the request body, response buffering, and a request-scoped
// key/value store. A Context is created fresh for each request and must not
// be retained or used after the handler chain returns.
//
// Not safe for concurrent use: a single Context is only ever accessed by the
// goroutine executing its handler chain.
type Context struct {
	conn   *C.PulsarConn // Underlying C connection; valid only for the lifetime of the request.
	engine *Engine       // Owning Engine, for access to shared configuration.
	chain  []HandlerFunc // Middleware + handler chain for the matched route.
	index  int           // Index of the currently executing handler in chain.

	status  int  // Pending response status code; 0 until WriteHeader or a terminal method sets it.
	written bool // True once a status code or body byte has been committed to buf.

	// buf accumulates the response body across one or more Write calls. It is
	// flushed to the connection exactly once, after the handler chain
	// completes, via a single writev-backed C call. Buffering here (rather
	// than issuing a cgo call per Write) lets handlers call Write as many
	// times as they like — e.g. to stream a response incrementally from Go's
	// point of view — without paying a cgo transition per chunk and without
	// the C side needing to support partial/chunked writes itself.
	buf []byte

	// Cached request metadata, populated lazily to avoid a cgo call for
	// fields a given handler never reads.
	method string
	path   string
	body   []byte
	params map[string]string
	store  map[string]any
	ctx    context.Context

	// Lazily parsed request bodies. form caches the multipart parse
	// (freed automatically when the request completes); formErr caches
	// a parse failure so it is not retried. postForm caches the
	// URL-encoded body parse, guarded by postFormParsed.
	form           *Form
	formErr        error
	postForm       map[string][]string
	postFormParsed bool
}

// DefaultErrorHandler writes a response for an error returned from a
// handler. *HTTPError values are rendered using their Code and Message
// (JSON unless Message is a string); any other error becomes a generic 500.
// If a response has already been written, DefaultErrorHandler does nothing,
// since the client has already received a status code that cannot be
// changed.
func DefaultErrorHandler(err error, c *Context) {
	if c.ResponseWritten() {
		return
	}

	if httpErr, ok := errors.AsType[*HTTPError](err); ok {
		switch msg := httpErr.Message.(type) {
		case string:
			_ = c.String(httpErr.Code, msg)
		default:
			_ = c.JSON(httpErr.Code, msg)
		}
		return
	}
	_ = c.String(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
}

// Next invokes the remaining handlers in the chain in order, stopping early
// if a handler returns an error or the request is aborted. Middleware calls
// Next to yield control to the next handler; the return value should
// generally be propagated to the caller unchanged.
func (c *Context) Next() error {
	c.index++
	for c.index < len(c.chain) {
		if c.Aborted() {
			return nil
		}
		if err := c.chain[c.index](c); err != nil {
			return err
		}
		c.index++
	}
	return nil
}

// Abort marks the request as aborted, preventing any remaining handlers in
// the chain from running. It does not itself write a response or stop the
// currently executing handler; callers should return promptly after calling
// Abort.
func (c *Context) Abort() {
	C.conn_abort(c.conn)
}

// Aborted reports whether Abort has been called for this request.
func (c *Context) Aborted() bool {
	return C.bridge_is_aborted(c.conn) != 0
}

// ResponseWritten reports whether a status code or response body has been
// committed for this request.
func (c *Context) ResponseWritten() bool {
	return c.written
}

// Method returns the request's HTTP method, e.g. "GET".
func (c *Context) Method() string {
	if c.method == "" {
		c.method = C.GoString(C.req_method(c.conn))
	}
	return c.method
}

// Path returns the request's URL path.
func (c *Context) Path() string {
	if c.path == "" {
		c.path = C.GoString(C.req_path(c.conn))
	}
	return c.path
}

// Param returns the named path parameter, or "" if it is not present. Each
// call after the first is served from a cached map, so repeated lookups for
// different names do not repeatedly cross into C.
//
// The returned string is an owned copy and is safe to retain beyond the
// request. For a zero-copy view valid only for the current request, use
// ParamView.
func (c *Context) Param(name string) string {
	if name == "" {
		return ""
	}
	if c.params != nil {
		return c.params[name]
	}
	var cData *C.char
	var cLen C.size_t
	if C.bridge_get_path_param(
		c.conn,
		(*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		C.size_t(len(name)),
		&cData,
		&cLen,
	) == 0 {
		return ""
	}
	return C.GoStringN(cData, C.int(cLen))
}

// Params returns all parsed path parameters as a map, keyed by parameter
// name. The returned map is owned by the Context and must not be mutated by
// the caller. Returns nil if the route has no path parameters.
func (c *Context) Params() map[string]string {
	if c.params != nil {
		return c.params
	}
	count := int(C.bridge_get_path_params_count(c.conn))
	if count == 0 {
		return nil
	}
	c.params = make(map[string]string, count)
	for i := range count {
		var cName, cVal *C.char
		var nameLen, valLen C.size_t
		C.bridge_get_path_param_at(c.conn, C.size_t(i), &cName, &nameLen, &cVal, &valLen)
		if cName != nil && cVal != nil {
			c.params[C.GoStringN(cName, C.int(nameLen))] = C.GoStringN(cVal, C.int(valLen))
		}
	}
	return c.params
}

// Query returns the named query-string parameter, or "" if it is not
// present.
//
// Values are already percent-decoded by the C engine (with '+' as space).
// The returned string is an owned copy safe to retain; QueryView is the
// zero-copy variant valid only for the current request.
func (c *Context) Query(name string) string {
	if name == "" {
		return ""
	}
	var cData *C.char
	var cLen C.size_t
	if C.bridge_query_get(
		c.conn,
		(*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		C.size_t(len(name)),
		&cData,
		&cLen,
	) == 0 {
		return ""
	}
	return C.GoStringN(cData, C.int(cLen))
}

// Header returns the named request header, or "" if it is not present.
//
// Lookup is case-insensitive. The returned string is an owned copy safe
// to retain; HeaderView is the zero-copy variant valid only for the
// current request.
func (c *Context) Header(name string) string {
	if name == "" {
		return ""
	}
	var cData *C.char
	var cLen C.size_t
	if C.bridge_req_header_get(
		c.conn,
		(*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		C.size_t(len(name)),
		&cData,
		&cLen,
	) == 0 {
		return ""
	}
	return C.GoStringN(cData, C.int(cLen))
}

// unsafeView aliases C memory (data, len) as a Go string without copying.
// The result is valid only while the underlying C storage lives — for
// request, query, header, route, and form views that means the current
// request. Callers that need the value afterwards must copy it (e.g. via
// strings.Clone).
func unsafeView(data *C.char, n C.size_t) string {
	if data == nil || n == 0 {
		return ""
	}
	return unsafe.String((*byte)(unsafe.Pointer(data)), int(n))
}

// ParamView returns the named path parameter as a zero-copy view into C
// memory, valid only for the current request. It returns "" if absent.
// Prefer Param when the value must outlive the handler.
func (c *Context) ParamView(name string) string {
	if name == "" {
		return ""
	}
	var cData *C.char
	var cLen C.size_t
	if C.bridge_get_path_param(
		c.conn,
		(*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		C.size_t(len(name)),
		&cData,
		&cLen,
	) == 0 {
		return ""
	}
	return unsafeView(cData, cLen)
}

// QueryView returns the named query-string parameter as a zero-copy view
// into C memory, valid only for the current request. Values are already
// percent-decoded by the engine. Prefer Query when the value must
// outlive the handler.
func (c *Context) QueryView(name string) string {
	if name == "" {
		return ""
	}
	var cData *C.char
	var cLen C.size_t
	if C.bridge_query_get(
		c.conn,
		(*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		C.size_t(len(name)),
		&cData,
		&cLen,
	) == 0 {
		return ""
	}
	return unsafeView(cData, cLen)
}

// HeaderView returns the named request header as a zero-copy view into C
// memory, valid only for the current request. Prefer Header when the
// value must outlive the handler.
func (c *Context) HeaderView(name string) string {
	if name == "" {
		return ""
	}
	var cData *C.char
	var cLen C.size_t
	if C.bridge_req_header_get(
		c.conn,
		(*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		C.size_t(len(name)),
		&cData,
		&cLen,
	) == 0 {
		return ""
	}
	return unsafeView(cData, cLen)
}

// Queries returns all query-string parameters. Values alias C memory
// (zero-copy) and are valid only for the current request; copy them to
// retain. Returns nil when the URL carries no query string.
func (c *Context) Queries() map[string]string {
	count := int(C.bridge_query_count(c.conn))
	if count == 0 {
		return nil
	}
	out := make(map[string]string, count)
	for i := 0; i < count; i++ {
		var cName, cVal *C.char
		var nameLen, valLen C.size_t
		if C.bridge_query_at(c.conn, C.size_t(i), &cName, &nameLen, &cVal, &valLen) == 0 {
			continue
		}
		out[unsafeView(cName, nameLen)] = unsafeView(cVal, valLen)
	}
	return out
}

// Headers returns all request headers. Names and values alias C memory
// (zero-copy) and are valid only for the current request; copy them to
// retain. Returns nil when the request carries no headers.
func (c *Context) Headers() map[string]string {
	count := int(C.bridge_req_headers_count(c.conn))
	if count == 0 {
		return nil
	}
	out := make(map[string]string, count)
	for i := 0; i < count; i++ {
		var cName, cVal *C.char
		var nameLen, valLen C.size_t
		if C.bridge_req_header_at(c.conn, C.size_t(i), &cName, &nameLen, &cVal, &valLen) == 0 {
			continue
		}
		out[unsafeView(cName, nameLen)] = unsafeView(cVal, valLen)
	}
	return out
}

// ContentType returns the request's Content-Type header, or "" if absent.
// The returned string is an owned copy safe to retain.
func (c *Context) ContentType() string {
	return c.Header("Content-Type")
}

// ContentTypeView is the zero-copy variant of ContentType, valid only
// for the current request.
func (c *Context) ContentTypeView() string {
	return c.HeaderView("Content-Type")
}

// ContentLength returns the request's Content-Length in bytes, or 0 when
// the request has no body.
func (c *Context) ContentLength() int {
	return int(C.bridge_content_length(c.conn))
}

// RoutePattern returns the matched route's pattern (e.g. "/users/:id"),
// or "" if the connection has no matched route. The pattern has static
// lifetime on the C side, so the returned view stays valid beyond the
// request; it is returned as a zero-copy view regardless.
func (c *Context) RoutePattern() string {
	var cData *C.char
	var cLen C.size_t
	if C.bridge_route_pattern(c.conn, &cData, &cLen) == 0 {
		return ""
	}
	return unsafeView(cData, cLen)
}

// Body returns the raw request body as a zero-copy slice into the
// connection's receive buffer. The returned slice is only valid for the
// duration of the current request; callers that need the data to outlive
// the handler must copy it. Returns nil if the request has no body.
func (c *Context) Body() []byte {
	if c.body != nil {
		return c.body
	}
	slice := C.req_body_slice(c.conn)
	if slice.data == nil || slice.len == 0 {
		return nil
	}
	c.body = unsafe.Slice((*byte)(unsafe.Pointer(slice.data)), int(slice.len))
	return c.body
}

// BindJSON decodes the request body as JSON into v, which must be a
// pointer. Returns an *HTTPError with status 400 if the body is empty or is
// not valid JSON for v.
func (c *Context) BindJSON[T any](v *T) error {
	body := c.Body()
	if len(body) == 0 {
		return NewHTTPError(http.StatusBadRequest, "request body cannot be empty")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return NewHTTPError(http.StatusBadRequest, "invalid json payload: "+err.Error()).WithInternal(err)
	}
	return nil
}

// Context returns the request-scoped context.Context, defaulting to
// context.Background if SetContext has not been called.
func (c *Context) Context() context.Context {
	if c.ctx == nil {
		c.ctx = context.Background()
	}
	return c.ctx
}

// SetContext replaces the request-scoped context.Context, e.g. to attach a
// deadline or values for downstream handlers.
func (c *Context) SetContext(ctx context.Context) {
	c.ctx = ctx
}

// Set stores a key/value pair scoped to the current request, for handing
// data from one middleware to the next handler in the chain.
func (c *Context) Set(key string, val any) {
	if c.store == nil {
		c.store = make(map[string]any)
	}
	c.store[key] = val
}

// Get retrieves a value previously stored with Set. The second return value
// reports whether key was present.
func (c *Context) Get(key string) (any, bool) {
	if c.store == nil {
		return nil, false
	}
	v, ok := c.store[key]
	return v, ok
}

// SetHeader sets a response header. It may be called at any point before
// the response is flushed, including after Write has begun accumulating a
// body. Returns c to allow chaining.
func (c *Context) SetHeader(key, value string) *Context {
	if key == "" {
		return c
	}
	kSlice := C.StrSlice{data: (*C.char)(strPtr(key)), len: C.size_t(len(key))}
	vSlice := C.StrSlice{data: (*C.char)(strPtr(value)), len: C.size_t(len(value))}
	C.conn_writeheader(c.conn, kSlice, vSlice)
	return c
}

// WriteHeader sets the response status code. It is a no-op returning
// ErrResponseAlreadyWritten if a status code has already been set, either
// explicitly or implicitly via Write, String, JSON, or a similar method.
//
// Calling WriteHeader is optional: if omitted, the response is sent with
// status 200 once the handler chain completes and the buffered body (if
// any) is flushed.
func (c *Context) WriteHeader(status int) error {
	if c.written {
		return ErrResponseAlreadyWritten
	}
	c.status = status
	c.written = true
	return nil
}

// Write appends p to the response body buffer and returns len(p), nil.
// Unlike String, JSON, and the other single-shot response methods, Write
// may be called any number of times per request; each call appends to the
// same buffer. The buffer is only sent to the client once, via a single
// writev-backed flush after the handler chain finishes, so calling Write
// repeatedly does not incur a cgo transition per call.
//
// The first call to Write implicitly commits status 200 if WriteHeader has
// not already been called. Write never itself returns
// ErrResponseAlreadyWritten; that error is reserved for the single-shot
// methods, which conflict with a body already in progress.
//
// Write implements io.Writer.
func (c *Context) Write(p []byte) (int, error) {
	if !c.written {
		c.status = http.StatusOK
		c.written = true
	}
	c.buf = append(c.buf, p...)
	return len(p), nil
}

// String sends a plain text response with the given status code and body.
// Returns ErrResponseAlreadyWritten if a response has already been
// committed for this request.
func (c *Context) String(status int, text string) error {
	if c.written {
		return ErrResponseAlreadyWritten
	}
	c.status = status
	c.written = true
	c.buf = append(c.buf, text...)
	return nil
}

// JSON marshals v and sends it as the response body with Content-Type
// application/json. Returns ErrResponseAlreadyWritten if a response has
// already been committed for this request, or any error from json.Marshal.
func (c *Context) JSON(status int, v any) error {
	if c.written {
		return ErrResponseAlreadyWritten
	}
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("pulsar: marshal json response: %w", err)
	}
	c.SetHeader("Content-Type", "application/json")
	c.status = status
	c.written = true
	c.buf = append(c.buf, data...)
	return nil
}

// ServeFile sends the contents of filename as the response body, using
// the underlying C sendfile(2) implementation.
// ServeFile fully supports HTTP range requests, so clients can request partial content and resume downloads.
//
// Returns ErrResponseAlreadyWritten if a response has already been
// committed for this request, or an error if the file could not be opened.
// Note that the file is not yet sent even if this call succeeds.
// The file is sent when the handler chain completes and the response is flushed.
// This only reads file meta-data, parses the range header, and sets up the sendfile operation.
func (c *Context) ServeFile(filename string) error {
	if c.written {
		return ErrResponseAlreadyWritten
	}

	c.status = http.StatusOK
	c.written = true
	cFile := C.CString(filename)
	defer C.free(unsafe.Pointer(cFile))

	if !C.conn_servefile(c.conn, cFile) {
		return fmt.Errorf("pulsar: serve file: could not open %s", filename)
	}
	return nil

}

// HTML sends an HTML response with the given status code and body. Returns
// ErrResponseAlreadyWritten if a response has already been committed for
// this request.
func (c *Context) HTML(status int, html string) error {
	if c.written {
		return ErrResponseAlreadyWritten
	}
	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	c.status = status
	c.written = true
	c.buf = append(c.buf, html...)
	return nil
}

// Send writes raw bytes as the response body with the given status code.
// Returns ErrResponseAlreadyWritten if a response has already been
// committed for this request.
func (c *Context) Send(status int, data []byte) error {
	if c.written {
		return ErrResponseAlreadyWritten
	}
	c.status = status
	c.written = true
	c.buf = append(c.buf, data...)
	return nil
}

// NoContent sends an empty response with the given status code. Returns
// ErrResponseAlreadyWritten if a response has already been committed for
// this request.
func (c *Context) NoContent(status int) error {
	if c.written {
		return ErrResponseAlreadyWritten
	}
	c.status = status
	c.written = true
	return nil
}

// Redirect sends an HTTP redirect to location. status must be a 3xx code;
// StatusMovedPermanently and StatusPermanentRedirect are sent as permanent
// redirects. Redirect bypasses the buffered body path and is dispatched to
// C immediately, since a redirect carries no body of its own. Returns
// ErrResponseAlreadyWritten if a response has already been committed for
// this request.
func (c *Context) Redirect(status int, location string) error {
	if c.written {
		return ErrResponseAlreadyWritten
	}
	c.written = true
	cLoc := C.CString(location)
	defer C.free(unsafe.Pointer(cLoc))
	permanent := status == http.StatusMovedPermanently || status == http.StatusPermanentRedirect
	C.conn_send_redirect(c.conn, cLoc, C.bool(permanent))
	return nil
}

// flush sends the accumulated response buffer to the client in a single
// call, using whatever status was committed via WriteHeader, Write, or one
// of the single-shot response methods. It is invoked once by the Engine
// after the handler chain completes; handlers must not call it directly.
//
// flush is a no-op if no response was committed (c.written is false) or if
// Redirect already dispatched its own response, since Redirect sets
// c.written without populating c.buf or c.status via the buffered path.
func (c *Context) flush() {
	if !c.written {
		return
	}
	C.conn_send(c.conn, C.http_status(c.status), bytesPtr(c.buf), C.size_t(len(c.buf)))
}

// ----------------------------------------------------------------
// Engine, Groups and Router
// ----------------------------------------------------------------

// Router is implemented by both Engine and Group, letting middleware and
// route-registration code work uniformly against either a top-level engine
// or a prefixed sub-router.
type Router interface {
	Use(mws ...HandlerFunc)
	Get(pattern string, h HandlerFunc, mws ...HandlerFunc)
	Post(pattern string, h HandlerFunc, mws ...HandlerFunc)
	Put(pattern string, h HandlerFunc, mws ...HandlerFunc)
	Delete(pattern string, h HandlerFunc, mws ...HandlerFunc)
	Patch(pattern string, h HandlerFunc, mws ...HandlerFunc)
	Head(pattern string, h HandlerFunc, mws ...HandlerFunc)
	Options(pattern string, h HandlerFunc, mws ...HandlerFunc)
	Handle(method, pattern string, h HandlerFunc, mws ...HandlerFunc)
	Group(prefix string, mws ...HandlerFunc) *Group
	Static(prefix, dir string)
}

// Engine is the central Pulsar server instance: it owns the registered
// routes, global middleware, and the error handler, and drives the
// underlying C event loop once Listen is called.
type Engine struct {
	middleware   []HandlerFunc   // Global middleware, applied to every route registered from this point on.
	chains       [][]HandlerFunc // Per-route handler chains, indexed by routeID.
	errorHandler ErrorHandler    // Invoked when a handler in the chain returns an error.
}

// New creates an Engine with DefaultErrorHandler installed.
func New() *Engine {
	return &Engine{
		errorHandler: DefaultErrorHandler,
	}
}

// SetErrorHandler installs a custom ErrorHandler, replacing
// DefaultErrorHandler. Calling it with nil is a no-op, leaving the
// previously installed handler in place.
func (e *Engine) SetErrorHandler(h ErrorHandler) {
	if h != nil {
		e.errorHandler = h
	}
}

// Group returns a new Group rooted at prefix, inheriting no middleware from
// the Engine beyond what is passed in mws. Middleware registered on the
// Engine via Use after Group is called still applies, since every route's
// chain is built from e.middleware at registration time.
func (e *Engine) Group(prefix string, mws ...HandlerFunc) *Group {
	return &Group{
		prefix:     cleanPath(prefix),
		middleware: mws,
		engine:     e,
	}
}

// Use appends global middleware, applied to every route registered after
// this call.
func (e *Engine) Use(mws ...HandlerFunc) {
	e.middleware = append(e.middleware, mws...)
}

// addRoute builds the full handler chain for a route and registers it with
// the underlying C router. It panics if handler is nil or if the C layer
// rejects the pattern (duplicate route, malformed pattern, or a full route
// table), since these represent programmer error at startup rather than
// conditions a caller can recover from at request time.
func (e *Engine) addRoute(method int, pattern string, handler HandlerFunc, routeMws []HandlerFunc) {
	if handler == nil {
		panic("pulsar: nil handler for route " + pattern)
	}

	chain := make([]HandlerFunc, 0, len(e.middleware)+len(routeMws)+1)
	chain = append(chain, e.middleware...)
	chain = append(chain, routeMws...)
	chain = append(chain, handler)

	routeID := len(e.chains)
	e.chains = append(e.chains, chain)

	cPattern := C.CString(pattern)
	defer C.free(unsafe.Pointer(cPattern))

	if ret := C.pulsar_bridge_add_route(C.int(method), cPattern, C.int(routeID)); ret != 0 {
		e.chains = e.chains[:len(e.chains)-1]
		panic(fmt.Sprintf("pulsar: failed to register route %s (duplicate, invalid pattern, or table full)", pattern))
	}
}

// Handle registers a handler for method and pattern. method is matched
// case-insensitively; an unrecognized method panics.
func (e *Engine) Handle(method, pattern string, h HandlerFunc, mws ...HandlerFunc) {
	e.addRoute(methodStringToInt(method), cleanPath(pattern), h, mws)
}

// Get registers h to handle GET requests to pattern.
func (e *Engine) Get(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	e.addRoute(int(C.HTTP_GET), cleanPath(pattern), h, mws)
}

// Post registers h to handle POST requests to pattern.
func (e *Engine) Post(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	e.addRoute(int(C.HTTP_POST), cleanPath(pattern), h, mws)
}

// Put registers h to handle PUT requests to pattern.
func (e *Engine) Put(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	e.addRoute(int(C.HTTP_PUT), cleanPath(pattern), h, mws)
}

// Delete registers h to handle DELETE requests to pattern.
func (e *Engine) Delete(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	e.addRoute(int(C.HTTP_DELETE), cleanPath(pattern), h, mws)
}

// Patch registers h to handle PATCH requests to pattern.
func (e *Engine) Patch(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	e.addRoute(int(C.HTTP_PATCH), cleanPath(pattern), h, mws)
}

// Head registers h to handle HEAD requests to pattern.
func (e *Engine) Head(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	e.addRoute(int(C.HTTP_HEAD), cleanPath(pattern), h, mws)
}

// Options registers h to handle OPTIONS requests to pattern.
func (e *Engine) Options(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	e.addRoute(int(C.HTTP_OPTIONS), cleanPath(pattern), h, mws)
}

// Static serves the directory tree rooted at dir under prefix. File serving
// is handled entirely on the C side via sendfile(2) and does not invoke any
// Go handler chain.
func (e *Engine) Static(prefix, dir string) {
	cPrefix := C.CString(prefix)
	cDir := C.CString(dir)
	defer C.free(unsafe.Pointer(cPrefix))
	defer C.free(unsafe.Pointer(cDir))
	if ret := C.pulsar_bridge_add_static(cPrefix, cDir); ret != 0 {
		panic(fmt.Sprintf("pulsar: failed to register static route %s -> %s", prefix, dir))
	}
}

// dispatch is the cgo-visible entry point invoked by the C event loop for
// each matched request. It builds a Context for routeID, runs its handler
// chain to completion, routes any returned error to the ErrorHandler, and
// finally flushes the accumulated response body to the connection exactly
// once, regardless of how many times the handler called Write.
//
// A cached multipart form (see MultipartForm) is freed after the flush;
// form metadata views must not be used once dispatch returns.
func (e *Engine) dispatch(connPtr unsafe.Pointer, routeID int) {
	if routeID < 0 || routeID >= len(e.chains) {
		C.conn_notfound((*C.PulsarConn)(connPtr))
		return
	}

	ctx := Context{
		conn:   (*C.PulsarConn)(connPtr),
		engine: e,
		chain:  e.chains[routeID],
		index:  -1,
	}
	defer ctx.closeForm()

	if err := ctx.Next(); err != nil {
		e.errorHandler(err, &ctx)
	}

	ctx.flush()
}

// Group is a Router rooted at a URL prefix, with its own middleware stack
// layered on top of any middleware inherited from a parent Group or Engine.
type Group struct {
	prefix     string        // URL prefix prepended to every route registered on this Group.
	middleware []HandlerFunc // Middleware applied to every route registered on this Group, in addition to Engine-level middleware.
	engine     *Engine       // Root Engine that ultimately owns every registered route.
}

// Use appends middleware to this Group, applied to every route registered
// on it after this call.
func (g *Group) Use(mws ...HandlerFunc) {
	g.middleware = append(g.middleware, mws...)
}

// Group returns a new Group nested under this one, at prefix relative to
// the parent, inheriting the parent's middleware followed by mws.
func (g *Group) Group(prefix string, mws ...HandlerFunc) *Group {
	combined := make([]HandlerFunc, 0, len(g.middleware)+len(mws))
	combined = append(combined, g.middleware...)
	combined = append(combined, mws...)
	return &Group{
		prefix:     joinPaths(g.prefix, prefix),
		middleware: combined,
		engine:     g.engine,
	}
}

// Handle registers h for method and pattern under this Group's prefix. The
// per-call route middleware mws is combined with the Group's own middleware
// into a fresh slice so that registering one route can never alias, and
// later corrupt, another route's middleware chain sharing this Group.
func (g *Group) Handle(method, pattern string, h HandlerFunc, mws ...HandlerFunc) {
	chain := make([]HandlerFunc, 0, len(g.middleware)+len(mws))
	chain = append(chain, g.middleware...)
	chain = append(chain, mws...)
	g.engine.Handle(method, joinPaths(g.prefix, pattern), h, chain...)
}

// Get registers h to handle GET requests to pattern under this Group.
func (g *Group) Get(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	g.Handle(http.MethodGet, pattern, h, mws...)
}

// Post registers h to handle POST requests to pattern under this Group.
func (g *Group) Post(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	g.Handle(http.MethodPost, pattern, h, mws...)
}

// Put registers h to handle PUT requests to pattern under this Group.
func (g *Group) Put(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	g.Handle(http.MethodPut, pattern, h, mws...)
}

// Delete registers h to handle DELETE requests to pattern under this Group.
func (g *Group) Delete(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	g.Handle(http.MethodDelete, pattern, h, mws...)
}

// Patch registers h to handle PATCH requests to pattern under this Group.
func (g *Group) Patch(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	g.Handle(http.MethodPatch, pattern, h, mws...)
}

// Head registers h to handle HEAD requests to pattern under this Group.
func (g *Group) Head(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	g.Handle(http.MethodHead, pattern, h, mws...)
}

// Options registers h to handle OPTIONS requests to pattern under this
// Group.
func (g *Group) Options(pattern string, h HandlerFunc, mws ...HandlerFunc) {
	g.Handle(http.MethodOptions, pattern, h, mws...)
}

// Static serves the directory tree rooted at dir under prefix, relative to
// this Group's prefix.
func (g *Group) Static(prefix, dir string) {
	g.engine.Static(joinPaths(g.prefix, prefix), dir)
}

// ----------------------------------------------------------------
// Built-in Middleware
// ----------------------------------------------------------------

// Recover returns middleware that recovers a panic from any downstream
// handler, converts it into an error, and aborts the request. Install it
// early in the global middleware stack so it wraps all other handlers.
func Recover() HandlerFunc {
	return func(c *Context) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic recovered: %v", r)
				c.Abort()
			}
		}()
		return c.Next()
	}
}

// ----------------------------------------------------------------
// Logging & Execution
// ----------------------------------------------------------------

// SetLogger installs Pulsar's background logging engine to write to fd. It
// panics if fd is negative or if a logger is already installed, since both
// indicate programmer error at startup rather than a runtime condition.
func SetLogger(fd int) {
	if fd < 0 {
		panic("pulsar: invalid log fd")
	}
	if ret := C.pulsar_bridge_set_logger(C.int(fd)); ret != 0 {
		panic("pulsar: failed to install logger (bad fd or logger already installed)")
	}
}

// Listen registers e as the active engine and starts the C event loop,
// blocking until the server stops. Returns an error if the event loop exits
// with a non-zero status.
func (e *Engine) Listen(addr string, port int) error {
	activeEngineMu.Lock()
	activeEngine = e
	activeEngineMu.Unlock()

	cAddr := C.CString(addr)
	defer C.free(unsafe.Pointer(cAddr))

	if ret := C.pulsar_run(cAddr, C.int(port)); ret != 0 {
		return fmt.Errorf("pulsar: server exited with code %d", ret)
	}
	return nil
}

// ----------------------------------------------------------------
// Utilities
// ----------------------------------------------------------------

// strPtr returns a pointer suitable for passing s's bytes to C without a
// copy. For an empty string it returns a pointer to a shared zero byte
// rather than a nil or dangling pointer, since C call sites pass the
// corresponding length (0) alongside it and never dereference it.
func strPtr(s string) unsafe.Pointer {
	if len(s) == 0 {
		return unsafe.Pointer(&zeroByte)
	}
	return unsafe.Pointer(unsafe.StringData(s))
}

// bytesPtr is strPtr for []byte.
func bytesPtr(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return unsafe.Pointer(&zeroByte)
	}
	return unsafe.Pointer(&b[0])
}

// methodStringToInt maps an HTTP method name to its C-side HTTP_* constant.
// Matching is case-insensitive. Panics on an unrecognized method, since
// this is only ever called with a route registration string supplied at
// startup.
func methodStringToInt(method string) int {
	switch strings.ToUpper(method) {
	case http.MethodGet:
		return int(C.HTTP_GET)
	case http.MethodPost:
		return int(C.HTTP_POST)
	case http.MethodPut:
		return int(C.HTTP_PUT)
	case http.MethodPatch:
		return int(C.HTTP_PATCH)
	case http.MethodDelete:
		return int(C.HTTP_DELETE)
	case http.MethodHead:
		return int(C.HTTP_HEAD)
	case http.MethodOptions:
		return int(C.HTTP_OPTIONS)
	default:
		panic("pulsar: unknown HTTP method: " + method)
	}
}

// cleanPath normalizes p to start with exactly one leading slash and have
// no trailing slash, except that the root path is always returned as "/".
func cleanPath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

// joinPaths joins a cleaned base path and a cleaned element, e.g.
// joinPaths("/api", "/users") returns "/api/users".
func joinPaths(base, elem string) string {
	b := cleanPath(base)
	e := cleanPath(elem)
	if b == "/" {
		return e
	}
	if e == "/" {
		return b
	}
	return b + e
}
