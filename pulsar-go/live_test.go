package pulsar

// Live end-to-end tests: a real C event loop serves HTTP while Go handlers
// exercise the cgo hot path (snapshot metadata, deferred header commit,
// abort flag, multipart lens, sendfile + range). Detached-mode tests cover
// pure-Go behavior; these prove the live conn != nil path.
//
// The server is stopped by clearing the C server_running flag (the same
// mechanism SIGTERM uses); workers observe it within ~500ms.

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// freeTestPort returns an available localhost port. There is an inherent
// bind race; callers treat bind failure as fatal since the suite owns no
// other listener.
func freeTestPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// waitForServer polls until the listener accepts or the deadline passes.
func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", addr)
}

func TestLiveInvalidPatternsPanic(t *testing.T) {
	bad := []string{
		"/live-bad-unclosed/{id",
		"/live-bad-stray/id}",
		"/live-bad-nested/{{id}}",
		"/live-bad-bare/:",
		"/live-bad-constraint/:id([0-9+",
	}
	for _, p := range bad {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("pattern %q: expected panic, got none", p)
				}
			}()
			app := New()
			app.Get(p, func(c *Context) error { return c.NoContent(http.StatusOK) })
		}()
	}
}

func TestLiveServer(t *testing.T) {
	// Static file served over the live sendfile path.
	dir := t.TempDir()
	fileContent := "0123456789abcdef"
	assetPath := filepath.Join(dir, "asset.txt")
	if err := os.WriteFile(assetPath, []byte(fileContent), 0600); err != nil {
		t.Fatal(err)
	}

	app := New()
	app.Get("/live/hello/:name", func(c *Context) error {
		// Single-lookup Param path + snapshot-backed scalars.
		return c.String(http.StatusOK, "hi "+c.Param("name"))
	})
	app.Get("/live/users/{id}", func(c *Context) error {
		return c.JSON(http.StatusOK, map[string]string{"id": c.Param("id")})
	})
	app.Get("/live/constrained/:id([0-9]+)", func(c *Context) error {
		// Constraint stripped at registration: plain wildcard named "id".
		return c.String(http.StatusOK, "id="+c.Param("id"))
	})
	app.Get("/live/meta/:a", func(c *Context) error {
		// Touch every snapshot-backed accessor, twice to prove caching.
		_ = c.Method()
		_ = c.Path()
		_ = c.ContentLength()
		_ = c.RoutePattern()
		_ = c.Queries()
		_ = c.Headers()
		body := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d",
			c.Method(), c.Path(), c.Param("a"),
			c.Query("q"), c.Header("X-Echo"), c.RoutePattern(), c.ContentLength())
		return c.String(http.StatusOK, body)
	})
	app.Post("/live/echo", func(c *Context) error {
		var v struct {
			Msg string `json:"msg"`
		}
		if err := c.BindJSON(&v); err != nil {
			return err
		}
		return c.JSON(http.StatusOK, map[string]string{"got": v.Msg})
	})
	app.Get("/live/redir", func(c *Context) error {
		return c.Redirect(http.StatusTemporaryRedirect, "/live/hello/there")
	})
	app.Get("/live/file", func(c *Context) error {
		// Staged before ServeFile: must reach the client exactly once,
		// and must suppress servefile's own Content-Type guess.
		c.SetHeader("X-Custom", "yes")
		c.SetHeader("Content-Type", "text/custom")
		return c.ServeFile(assetPath)
	})
	app.Get("/live/aborted", func(c *Context) error {
		return c.String(http.StatusOK, "unreached")
	}, func(c *Context) error {
		c.Abort()
		return c.String(http.StatusUnauthorized, "blocked")
	})
	app.Post("/live/form", func(c *Context) error {
		// FormValue twice: Content-Type must cross cgo at most once.
		_ = c.FormValue("a")
		b := c.FormValue("b")
		f, err := c.FormFile("f")
		if err != nil {
			return err
		}
		return c.String(http.StatusOK, b+"|"+f.Filename+"|"+string(f.Data))
	})
	app.Get("/live/ts/", func(c *Context) error {
		// Trailing slash stripped at registration: reachable as /live/ts.
		return c.String(http.StatusOK, "ts")
	})

	port := freeTestPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	setServerRunning(true)
	listenDone := make(chan error, 1)
	go func() { listenDone <- app.Listen("127.0.0.1", port) }()
	t.Cleanup(func() {
		setServerRunning(false)
		select {
		case <-listenDone:
		case <-time.After(15 * time.Second):
			t.Errorf("server did not shut down")
		}
		setServerRunning(true)
	})
	waitForServer(t, addr)
	base := "http://" + addr

	plain := &http.Client{Timeout: 5 * time.Second}
	noredir := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	get := func(t *testing.T, client *http.Client, path string, hdr map[string]string) (int, http.Header, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}

	t.Run("colon-param", func(t *testing.T) {
		code, _, body := get(t, plain, "/live/hello/bob", nil)
		if code != 200 || body != "hi bob" {
			t.Fatalf("got %d %q", code, body)
		}
	})
	t.Run("brace-param", func(t *testing.T) {
		code, h, body := get(t, plain, "/live/users/42", nil)
		if code != 200 || !strings.Contains(body, "42") {
			t.Fatalf("got %d %q", code, body)
		}
		if ct := h.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content-type = %q", ct)
		}
	})
	t.Run("constraint-stripped", func(t *testing.T) {
		code, _, body := get(t, plain, "/live/constrained/77", nil)
		if code != 200 || body != "id=77" {
			t.Fatalf("got %d %q", code, body)
		}
	})
	t.Run("snapshot-meta", func(t *testing.T) {
		code, _, body := get(t, plain, "/live/meta/x?q=Q", map[string]string{"X-Echo": "E"})
		want := "GET|/live/meta/x|x|Q|E|/live/meta/{a}|0"
		if code != 200 || body != want {
			t.Fatalf("got %d %q, want %q", code, body, want)
		}
	})
	t.Run("json-echo", func(t *testing.T) {
		resp, err := plain.Post(base+"/live/echo", "application/json", strings.NewReader(`{"msg":"hey"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || !strings.Contains(string(b), "hey") {
			t.Fatalf("got %d %q", resp.StatusCode, b)
		}
	})
	t.Run("redirect-verbatim", func(t *testing.T) {
		code, h, _ := get(t, noredir, "/live/redir", nil)
		if code != http.StatusTemporaryRedirect {
			t.Fatalf("code = %d, want 307", code)
		}
		if loc := h.Get("Location"); loc != "/live/hello/there" {
			t.Fatalf("location = %q", loc)
		}
	})
	t.Run("servefile-headers", func(t *testing.T) {
		code, h, body := get(t, plain, "/live/file", nil)
		if code != 200 || body != fileContent {
			t.Fatalf("got %d %q", code, body)
		}
		if got := h.Values("X-Custom"); len(got) != 1 || got[0] != "yes" {
			t.Fatalf("X-Custom = %q, want exactly one", got)
		}
		if got := h.Values("Content-Type"); len(got) != 1 || got[0] != "text/custom" {
			t.Fatalf("Content-Type = %q, want single text/custom", got)
		}
	})
	t.Run("servefile-range", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, base+"/live/file", nil)
		req.Header.Set("Range", "bytes=0-3")
		resp, err := plain.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusPartialContent {
			t.Fatalf("code = %d, want 206", resp.StatusCode)
		}
		if string(b) != fileContent[:4] {
			t.Fatalf("body = %q", b)
		}
	})
	t.Run("abort-middleware", func(t *testing.T) {
		code, _, body := get(t, plain, "/live/aborted", nil)
		if code != 401 || body != "blocked" {
			t.Fatalf("got %d %q", code, body)
		}
	})
	t.Run("multipart", func(t *testing.T) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("a", "1")
		_ = mw.WriteField("b", "2")
		fw, _ := mw.CreateFormFile("f", "n.txt")
		_, _ = fw.Write([]byte("payload"))
		_ = mw.Close()
		req, _ := http.NewRequest(http.MethodPost, base+"/live/form", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := plain.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || string(b) != "2|n.txt|payload" {
			t.Fatalf("got %d %q", resp.StatusCode, b)
		}
	})
	t.Run("trailing-slash", func(t *testing.T) {
		code, _, body := get(t, plain, "/live/ts", nil)
		if code != 200 || body != "ts" {
			t.Fatalf("got %d %q", code, body)
		}
	})
}
