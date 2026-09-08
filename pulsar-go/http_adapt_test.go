package pulsar

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runPulsar executes h (plus optional middleware) against req as Engine
// dispatch would: chain -> error handler. Returns the detached Context so
// tests can inspect staged status/headers/body.
func runPulsar(t *testing.T, req *http.Request, h HandlerFunc, mws ...HandlerFunc) *Context {
	t.Helper()
	c := NewTestContext(req, nil)
	chain := append(append([]HandlerFunc{}, mws...), h)
	c.chain = chain
	c.index = -1
	if err := c.Next(); err != nil {
		DefaultErrorHandler(err, c)
	}
	return c
}

func TestWrapHandlerFuncBasic(t *testing.T) {
	std := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.URL.Query().Get("q"); got != "x" {
			t.Errorf("query q = %q, want x", got)
		}
		if got := r.Header.Get("X-In"); got != "1" {
			t.Errorf("header X-In = %q, want 1", got)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "ping" {
			t.Errorf("body = %q, want ping", body)
		}
		w.Header().Set("X-Out", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello std"))
	})

	pulsarH := WrapHandlerFunc(std)

	req := httptest.NewRequest(http.MethodPost, "/wrap?q=x", strings.NewReader("ping"))
	req.Header.Set("X-In", "1")
	c := runPulsar(t, req, pulsarH)

	if c.status != http.StatusCreated {
		t.Fatalf("status = %d, want 201", c.status)
	}
	if string(c.buf) != "hello std" {
		t.Fatalf("body = %q, want %q", c.buf, "hello std")
	}
	if got := c.respHeaders.Get("X-Out"); got != "yes" {
		t.Fatalf("X-Out = %q, want yes", got)
	}
}

func TestWrapHandlerNoWriteLeavesContextUntouched(t *testing.T) {
	pulsarH := WrapH(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := runPulsar(t, req, pulsarH)
	if c.ResponseWritten() {
		t.Fatal("empty stdlib handler should leave Context unwritten")
	}
}

func TestWrapHandlerAlreadyWritten(t *testing.T) {
	inner := WrapHandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("late"))
	}))

	h := func(c *Context) error {
		if err := c.String(http.StatusOK, "first"); err != nil {
			t.Fatalf("String: %v", err)
		}
		if err := inner(c); !errors.Is(err, ErrResponseAlreadyWritten) {
			t.Fatalf("inner err = %v, want ErrResponseAlreadyWritten", err)
		}
		return nil
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := runPulsar(t, req, h)
	if string(c.buf) != "first" {
		t.Fatalf("body = %q, want first", c.buf)
	}
}

func TestWrapHandlerExposesPulsarParams(t *testing.T) {
	var got map[string]string
	var pathVal string
	std := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ParamsFromRequest(r)
		pathVal = r.PathValue("id")
		_, _ = w.Write([]byte("ok"))
	})
	req := httptest.NewRequest(http.MethodGet, "/users/42", nil)
	c := NewTestContext(req, map[string]string{"id": "42"})
	c.chain = []HandlerFunc{WrapHandler(std)}
	c.index = -1
	if err := c.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if got["id"] != "42" {
		t.Fatalf("params = %#v, want id=42", got)
	}
	if pathVal != "42" {
		t.Fatalf("r.PathValue(id) = %q, want 42", pathVal)
	}
}

func TestWrapMiddlewareAddsHeaderAndSeesChain(t *testing.T) {
	var sawBody string
	mw := WrapMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Mw", "1")
			next.ServeHTTP(w, r)
			if prw, ok := w.(*pulsarResponseWriter); ok {
				sawBody = prw.body.String()
			}
		})
	})
	final := func(c *Context) error { return c.String(http.StatusOK, "chain-body") }

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := runPulsar(t, req, final, mw)

	if string(c.buf) != "chain-body" {
		t.Fatalf("body = %q, want chain-body", c.buf)
	}
	if got := c.respHeaders.Get("X-Mw"); got != "1" {
		t.Fatalf("X-Mw = %q, want 1", got)
	}
	if sawBody != "chain-body" {
		t.Fatalf("middleware saw body %q, want chain-body", sawBody)
	}
}

func TestWrapMiddlewareShortCircuit(t *testing.T) {
	mw := WrapMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked"))
		})
	})
	called := false
	final := func(c *Context) error {
		called = true
		return c.String(http.StatusOK, "should not run")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := runPulsar(t, req, final, mw)
	if called {
		t.Fatal("chain should not run when middleware short-circuits")
	}
	if c.status != http.StatusForbidden || string(c.buf) != "blocked" {
		t.Fatalf("got %d %q, want 403 blocked", c.status, c.buf)
	}
}

func TestWrapMiddlewareChainError(t *testing.T) {
	mw := WrapMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Mw", "seen")
			next.ServeHTTP(w, r)
		})
	})
	boom := func(c *Context) error { return NewHTTPError(http.StatusTeapot, "teapot") }
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := runPulsar(t, req, boom, mw)
	if c.status != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", c.status)
	}
	if got := c.respHeaders.Get("X-Mw"); got != "seen" {
		t.Fatalf("X-Mw = %q, want seen", got)
	}
}

func TestToHTTPHandlerBasic(t *testing.T) {
	pulsarH := func(c *Context) error {
		return c.JSON(http.StatusOK, map[string]string{"id": c.Param("id")})
	}
	h := ToHTTPHandler(pulsarH, WithPattern("/users/:id"))

	req := httptest.NewRequest(http.MethodGet, "/users/42", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "42") {
		t.Fatalf("body = %q, want id 42", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestToHTTPHandlerMiddlewareAndError(t *testing.T) {
	auth := func(c *Context) error {
		if c.Header("Authorization") == "" {
			return NewHTTPError(http.StatusUnauthorized, "nope")
		}
		return c.Next()
	}
	ok := func(c *Context) error { return c.String(http.StatusOK, "secret") }
	h := ToHTTPHandler(ok, WithMiddleware(auth))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth code = %d, want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer x")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "secret" {
		t.Fatalf("auth got %d %q", rec.Code, rec.Body.String())
	}
}

func TestToHTTPHandlerRedirectAndHeaders(t *testing.T) {
	h := ToHTTPHandler(func(c *Context) error {
		c.SetHeader("X-Keep", "me")
		return c.Redirect(http.StatusSeeOther, "/elsewhere")
	})
	req := httptest.NewRequest(http.MethodGet, "/old", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/elsewhere" {
		t.Fatalf("location = %q", loc)
	}
	if got := rec.Header().Get("X-Keep"); got != "me" {
		t.Fatalf("X-Keep = %q", got)
	}
}

func TestRoundTripPulsarWrappingHTTPUnderNetHTTP(t *testing.T) {
	// Pulsar handler that delegates to stdlib, served via net/http.
	inner := WrapHandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("round-" + r.URL.Query().Get("q")))
	}))
	pulsarH := func(c *Context) error { return inner(c) }

	req := httptest.NewRequest(http.MethodGet, "/r?q=trip", nil)
	rec := httptest.NewRecorder()
	ToHTTPHandler(pulsarH).ServeHTTP(rec, req)
	if rec.Body.String() != "round-trip" {
		t.Fatalf("body = %q, want round-trip", rec.Body.String())
	}
}

func TestStandaloneMultipartForm(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("note", "hi")
	fw, _ := mw.CreateFormFile("file", "a.txt")
	_, _ = fw.Write([]byte("file-bytes"))
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	c := NewTestContext(req, nil)

	f, err := c.FormFile("file")
	if err != nil {
		t.Fatalf("FormFile: %v", err)
	}
	if string(f.Data) != "file-bytes" || f.Filename != "a.txt" {
		t.Fatalf("file = %+v", f)
	}
	if got := c.FormValue("note"); got != "hi" {
		t.Fatalf("note = %q", got)
	}
}

func TestStandaloneServeFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(p, []byte("file-content"), 0600); err != nil {
		t.Fatal(err)
	}
	h := ToHTTPHandler(func(c *Context) error { return c.ServeFile(p) })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "file-content" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestNewTestContextDefaults(t *testing.T) {
	c := NewTestContext(nil, nil)
	if c.Method() != http.MethodGet || c.Path() != "/" {
		t.Fatalf("defaults = %q %q", c.Method(), c.Path())
	}
	if c.ContentLength() != 0 {
		t.Fatalf("content-length = %d", c.ContentLength())
	}
	c.Abort()
	if !c.Aborted() {
		t.Fatal("Abort/Aborted round-trip failed in test mode")
	}
}
