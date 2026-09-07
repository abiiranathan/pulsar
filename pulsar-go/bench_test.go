package pulsar

// This file benchmarks four representative workloads (hello world, JSON
// response, URL-encoded form processing, and file serving) side by side on
// two stacks:
//
//   - Pulsar, driven through NewTestContext/ToHTTPHandler's underlying
//     handler-chain execution (Context.Next), i.e. conn == nil "detached"
//     mode. This is the only way to drive Pulsar handlers from testing.B
//     without a live C event loop and real sockets, and it is the same
//     execution path ToHTTPHandler uses in production for the
//     Pulsar-inside-net/http direction.
//   - Plain net/http, using httptest.NewRecorder as the ResponseWriter.
//
// Both sides therefore measure handler/framework overhead for an
// in-process call, not real socket I/O, DNS, or TCP handshake cost. This
// is the standard way HTTP framework benchmarks are written (it is what
// net/http/httptest-based benchmarks measure for the stdlib side too), and
// it isolates exactly the thing this comparison cares about: how much
// overhead each framework adds around an otherwise identical handler body.
//
// Caveat specific to Pulsar: ServeFile's benchmark exercises the detached
// code path (os.ReadFile followed by a buffered write), not the live C
// engine's sendfile(2) fast path used when conn != nil. A conn != nil
// benchmark would require a running C event loop and real sockets, which
// testing.B cannot drive per-op at a meaningful rate; treat the file
// benchmark here as measuring Go-side dispatch overhead only, not an
// end-to-end comparison of sendfile vs. an http.ServeContent-style read.
//
// Run with:
//
//	go test -bench=. -benchmem -run=^$ .
//
// Use -benchtime=2s (or higher) for more stable numbers, and
// -cpu=1,2,4,8 to see how each stack behaves under GOMAXPROCS scaling for
// the -Parallel variants.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// benchUser is the fixed payload encoded by the JSON benchmarks. Kept
// small and realistic (a handful of scalar fields) rather than a
// microscopic {"a":1} or a large nested document, since neither extreme
// is representative of typical handler payloads.
type benchUser struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Active   bool     `json:"active"`
	Tags     []string `json:"tags"`
	LoginCnt int      `json:"login_count"`
}

// benchUserPayload is the value every JSON benchmark encodes. A package
// var (rather than a fresh literal per call) keeps allocation attributable
// to the encode step itself, not to building the source value.
var benchUserPayload = benchUser{
	ID:       42,
	Name:     "Ada Lovelace",
	Email:    "ada@example.com",
	Active:   true,
	Tags:     []string{"admin", "beta", "staff"},
	LoginCnt: 1287,
}

// benchFormBody is the url-encoded body every form benchmark parses. It
// mirrors a small, realistic form: a handful of fields, one repeated key.
var benchFormBody = url.Values{
	"name":  {"Grace Hopper"},
	"email": {"grace@example.com"},
	"role":  {"engineer"},
	"tag":   {"go", "systems", "compilers"},
}.Encode()

// benchFilePath is the temp file served by the file benchmarks, created
// once in TestMain and sized to resemble a small static asset (e.g. a
// favicon or a small JSON/HTML fragment) rather than a trivial few bytes,
// since per-byte copy cost is part of what's being measured.
var benchFilePath string

// TestMain provisions the shared temp file used by BenchmarkPulsarFile
// and BenchmarkNetHTTPFile, then cleans it up after the full test/bench
// binary finishes.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pulsar-bench")
	if err != nil {
		panic("bench setup: " + err.Error())
	}
	defer os.RemoveAll(dir)

	benchFilePath = filepath.Join(dir, "asset.txt")
	// ~8KB of content: large enough that copy cost is measurable, small
	// enough that a benchmark loop stays fast.
	content := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog\n"), 180)
	if err := os.WriteFile(benchFilePath, content, 0600); err != nil {
		panic("bench setup: " + err.Error())
	}

	os.Exit(m.Run())
}

// ----------------------------------------------------------------
// Hello world
// ----------------------------------------------------------------

// BenchmarkPulsarHelloWorld measures Context.String for a trivial
// fixed-text response, run through the same detached-Context path
// ToHTTPHandler uses in production.
func BenchmarkPulsarHelloWorld(b *testing.B) {
	h := func(c *Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ReportAllocs()
	for b.Loop() {
		c := NewTestContext(req, nil)
		c.chain = []HandlerFunc{h}
		c.index = -1
		if err := c.Next(); err != nil {
			b.Fatalf("handler chain: %v", err)
		}
	}
}

// BenchmarkNetHTTPHelloWorld is the stdlib equivalent of
// BenchmarkPulsarHelloWorld: an http.HandlerFunc writing the same fixed
// text into an httptest.ResponseRecorder.
func BenchmarkNetHTTPHelloWorld(b *testing.B) {
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, World!"))
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		h(rec, req)
	}
}

// ----------------------------------------------------------------
// JSON response
// ----------------------------------------------------------------

// BenchmarkPulsarJSON measures Context.JSON, which marshals v with
// encoding/json, sets Content-Type, and buffers the result.
func BenchmarkPulsarJSON(b *testing.B) {
	h := func(c *Context) error {
		return c.JSON(http.StatusOK, benchUserPayload)
	}
	req := httptest.NewRequest(http.MethodGet, "/user", nil)

	b.ReportAllocs()
	for b.Loop() {
		c := NewTestContext(req, nil)
		c.chain = []HandlerFunc{h}
		c.index = -1
		if err := c.Next(); err != nil {
			b.Fatalf("handler chain: %v", err)
		}
	}
}

// BenchmarkNetHTTPJSON is the stdlib equivalent: json.NewEncoder writing
// directly to the ResponseWriter, the idiomatic net/http JSON pattern.
func BenchmarkNetHTTPJSON(b *testing.B) {
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(benchUserPayload)
	}
	req := httptest.NewRequest(http.MethodGet, "/user", nil)

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		h(rec, req)
	}
}

// ----------------------------------------------------------------
// Form processing (application/x-www-form-urlencoded)
// ----------------------------------------------------------------

// newFormRequest builds a fresh POST request with benchFormBody, since
// the body reader is consumed by each parse and cannot be reused across
// b.Loop iterations.
func newFormRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/form", bytes.NewBufferString(benchFormBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// BenchmarkPulsarForm measures PostFormValue/PostForm: parsing the
// url-encoded body and reading back several fields, including the
// repeated "tag" key via the multi-value map.
func BenchmarkPulsarForm(b *testing.B) {
	h := func(c *Context) error {
		name := c.PostFormValue("name")
		email := c.PostFormValue("email")
		role := c.PostFormValue("role")
		tags := c.PostForm()["tag"]
		if name == "" || email == "" || role == "" || len(tags) != 3 {
			b.Fatalf("unexpected form values: name=%q email=%q role=%q tags=%v", name, email, role, tags)
		}
		return c.NoContent(http.StatusOK)
	}

	b.ReportAllocs()
	for b.Loop() {
		c := NewTestContext(newFormRequest(), nil)
		c.chain = []HandlerFunc{h}
		c.index = -1
		if err := c.Next(); err != nil {
			b.Fatalf("handler chain: %v", err)
		}
	}
}

// BenchmarkNetHTTPForm is the stdlib equivalent: r.ParseForm followed by
// r.FormValue/r.Form lookups for the same fields.
func BenchmarkNetHTTPForm(b *testing.B) {
	h := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		name := r.FormValue("name")
		email := r.FormValue("email")
		role := r.FormValue("role")
		tags := r.Form["tag"]
		if name == "" || email == "" || role == "" || len(tags) != 3 {
			http.Error(w, "unexpected form values", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		h(rec, newFormRequest())
	}
}

// ----------------------------------------------------------------
// File serving
// ----------------------------------------------------------------

// BenchmarkPulsarFile measures Context.ServeFile in detached mode
// (conn == nil): os.ReadFile plus a Content-Type sniff/lookup, buffered
// into c.buf. See the file-level doc comment for why this does not
// exercise the live C sendfile(2) path.
func BenchmarkPulsarFile(b *testing.B) {
	h := func(c *Context) error {
		return c.ServeFile(benchFilePath)
	}
	req := httptest.NewRequest(http.MethodGet, "/asset.txt", nil)

	b.ReportAllocs()
	for b.Loop() {
		c := NewTestContext(req, nil)
		c.chain = []HandlerFunc{h}
		c.index = -1
		if err := c.Next(); err != nil {
			b.Fatalf("handler chain: %v", err)
		}
	}
}

// BenchmarkNetHTTPFile is the stdlib equivalent: http.ServeFile, which
// internally opens the file, stats it, and streams via io.Copy (with
// range-request support neither side is exercising here).
func BenchmarkNetHTTPFile(b *testing.B) {
	h := func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, benchFilePath)
	}
	req := httptest.NewRequest(http.MethodGet, "/asset.txt", nil)

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		h(rec, req)
	}
}

// ----------------------------------------------------------------
// Parallel variants
// ----------------------------------------------------------------
//
// The sequential benchmarks above measure per-call overhead on a single
// goroutine. The -Parallel variants below run the same handler bodies
// under b.RunParallel to surface contention that only appears under
// concurrent load (e.g. shared-map access, lock contention, or allocator
// pressure across P's) — relevant since a real server handles many
// requests concurrently across goroutines. Each parallel worker builds
// its own Context/Request per iteration, matching one goroutine per
// in-flight request in the live engine.

// BenchmarkPulsarHelloWorldParallel is the concurrent counterpart to
// BenchmarkPulsarHelloWorld.
func BenchmarkPulsarHelloWorldParallel(b *testing.B) {
	h := func(c *Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c := NewTestContext(req, nil)
			c.chain = []HandlerFunc{h}
			c.index = -1
			if err := c.Next(); err != nil {
				b.Fatalf("handler chain: %v", err)
			}
		}
	})
}

// BenchmarkNetHTTPHelloWorldParallel is the concurrent counterpart to
// BenchmarkNetHTTPHelloWorld.
func BenchmarkNetHTTPHelloWorldParallel(b *testing.B) {
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, World!"))
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			h(rec, req)
		}
	})
}

// BenchmarkPulsarJSONParallel is the concurrent counterpart to
// BenchmarkPulsarJSON.
func BenchmarkPulsarJSONParallel(b *testing.B) {
	h := func(c *Context) error {
		return c.JSON(http.StatusOK, benchUserPayload)
	}
	req := httptest.NewRequest(http.MethodGet, "/user", nil)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c := NewTestContext(req, nil)
			c.chain = []HandlerFunc{h}
			c.index = -1
			if err := c.Next(); err != nil {
				b.Fatalf("handler chain: %v", err)
			}
		}
	})
}

// BenchmarkNetHTTPJSONParallel is the concurrent counterpart to
// BenchmarkNetHTTPJSON.
func BenchmarkNetHTTPJSONParallel(b *testing.B) {
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(benchUserPayload)
	}
	req := httptest.NewRequest(http.MethodGet, "/user", nil)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			h(rec, req)
		}
	})
}

// BenchmarkPulsarFormParallel is the concurrent counterpart to
// BenchmarkPulsarForm.
func BenchmarkPulsarFormParallel(b *testing.B) {
	h := func(c *Context) error {
		name := c.PostFormValue("name")
		email := c.PostFormValue("email")
		role := c.PostFormValue("role")
		tags := c.PostForm()["tag"]
		if name == "" || email == "" || role == "" || len(tags) != 3 {
			return NewHTTPError(http.StatusInternalServerError, "unexpected form values")
		}
		return c.NoContent(http.StatusOK)
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c := NewTestContext(newFormRequest(), nil)
			c.chain = []HandlerFunc{h}
			c.index = -1
			if err := c.Next(); err != nil {
				b.Fatalf("handler chain: %v", err)
			}
		}
	})
}

// BenchmarkNetHTTPFormParallel is the concurrent counterpart to
// BenchmarkNetHTTPForm.
func BenchmarkNetHTTPFormParallel(b *testing.B) {
	h := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		name := r.FormValue("name")
		email := r.FormValue("email")
		role := r.FormValue("role")
		tags := r.Form["tag"]
		if name == "" || email == "" || role == "" || len(tags) != 3 {
			http.Error(w, "unexpected form values", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			h(rec, newFormRequest())
		}
	})
}

// BenchmarkPulsarFileParallel is the concurrent counterpart to
// BenchmarkPulsarFile.
func BenchmarkPulsarFileParallel(b *testing.B) {
	h := func(c *Context) error {
		return c.ServeFile(benchFilePath)
	}
	req := httptest.NewRequest(http.MethodGet, "/asset.txt", nil)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c := NewTestContext(req, nil)
			c.chain = []HandlerFunc{h}
			c.index = -1
			if err := c.Next(); err != nil {
				b.Fatalf("handler chain: %v", err)
			}
		}
	})
}

// BenchmarkNetHTTPFileParallel is the concurrent counterpart to
// BenchmarkNetHTTPFile.
func BenchmarkNetHTTPFileParallel(b *testing.B) {
	h := func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, benchFilePath)
	}
	req := httptest.NewRequest(http.MethodGet, "/asset.txt", nil)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			h(rec, req)
		}
	})
}
