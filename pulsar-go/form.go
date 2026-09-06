package pulsar

/*
#include <stdlib.h>
#include "bridge.h"
#include "../include/forms.h"
#include "../include/pulsar.h"
*/
import "C"
import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"unsafe"
)

// This file implements form parsing for the Go binding.
//
// Two content types are supported:
//
//   - application/x-www-form-urlencoded is parsed in pure Go directly
//     over the zero-copy request body (see PostForm). Scanning borrows
//     the body; only percent-decoded outputs allocate.
//   - multipart/form-data (RFC 7578) is parsed by the C engine
//     (src/forms.c) into a private arena (see MultipartForm). Regular
//     field names/values and file metadata alias that arena (zero-copy,
//     request-scoped). File payloads are offset/size windows into the
//     request body itself and are never copied; UploadedFile.Data is a
//     zero-copy subslice of Context.Body.
//
// Lifetime: every value returned here aliases C memory owned by the
// server. Nothing may be used after the handler chain returns. Copy
// anything that must outlive the current request.

// UploadedFile describes a single uploaded file in a multipart form.
//
// FieldName, Filename, and MimeType are zero-copy views into the form's
// C arena: they are valid only until the request ends (or Close is
// called) and must be copied (e.g. via strings.Clone) to retain them.
//
// Data is a zero-copy view into the request body (body[offset:offset+size]);
// no file bytes are copied by the parser. It stays valid until the
// request ends, independent of Close, but must likewise be copied to
// outlive the handler.
//
// The CRLF delimiter preceding the boundary marker is stripped, so Data
// holds exactly the bytes the client sent (matching mime/multipart).
type UploadedFile struct {
	FieldName string // Form field name, e.g. "avatar".
	Filename  string // Original client filename, e.g. "photo.png".
	MimeType  string // Part Content-Type, e.g. "image/png".
	Data      []byte // File payload, zero-copy view into the request body.
	Size      int    // len(Data); kept for convenience without re-slicing.
}

// Form is a parsed multipart/form-data request.
//
// Obtain it via Context.MultipartForm, which parses at most once per
// request and caches the result. The Engine frees the underlying C arena
// automatically when the request completes; calling Close early is
// optional but idempotent. After Close, field/file metadata views must
// no longer be used.
type Form struct {
	ctx    *Context         // Owning request; keeps handler-scoped refs together.
	raw    *C.MultipartForm // C arena owner; nil after Close.
	body   []byte           // Zero-copy request body; file Data subslices this.
	fields []formField      // Regular fields in arrival order.
	files  []*UploadedFile  // Uploaded files in arrival order.
	closed bool
}

// formField is one regular (non-file) multipart field.
type formField struct {
	name  string // Zero-copy view into the form arena.
	value string // Zero-copy view into the form arena.
}

// Field returns the first value for name, or "" if absent.
func (f *Form) Field(name string) string {
	for i := range f.fields {
		if f.fields[i].name == name {
			return f.fields[i].value
		}
	}
	return ""
}

// Fields returns every value for name in arrival order, or nil if absent.
func (f *Form) Fields(name string) []string {
	var out []string
	for i := range f.fields {
		if f.fields[i].name == name {
			out = append(out, f.fields[i].value)
		}
	}
	return out
}

// FieldMap returns all regular fields grouped by name. Values alias C
// memory; copy them to retain beyond the request.
func (f *Form) FieldMap() map[string][]string {
	out := make(map[string][]string, len(f.fields))
	for i := range f.fields {
		n := f.fields[i].name
		out[n] = append(out[n], f.fields[i].value)
	}
	return out
}

// File returns the first uploaded file for field name, or an *HTTPError
// with status 400 if none exists.
func (f *Form) File(name string) (*UploadedFile, error) {
	for _, uf := range f.files {
		if uf.FieldName == name {
			return uf, nil
		}
	}
	return nil, NewHTTPError(http.StatusBadRequest, "missing file: "+name)
}

// Files returns every uploaded file for field name in arrival order.
func (f *Form) Files(name string) []*UploadedFile {
	var out []*UploadedFile
	for _, uf := range f.files {
		if uf.FieldName == name {
			out = append(out, uf)
		}
	}
	return out
}

// Close releases the C arena backing this form's metadata. Field/file
// metadata strings must not be used afterwards; file Data views (which
// point into the request body, not the form arena) stay valid until the
// request ends. Close is idempotent and is called automatically when the
// request completes.
func (f *Form) Close() {
	if f == nil || f.closed {
		return
	}
	f.closed = true
	if f.raw != nil {
		C.bridge_free_multipart(f.raw)
		f.raw = nil
	}
	f.fields = nil
	f.files = nil
}

// closeForm frees a cached multipart form, if any. It is called by the
// Engine after each request's response is flushed.
func (c *Context) closeForm() {
	if c.form != nil {
		c.form.Close()
		c.form = nil
	}
}

// MultipartForm parses the request as multipart/form-data (RFC 7578) and
// returns the cached result. A second call returns the same *Form
// without re-parsing. Parsing fails with an *HTTPError (status 400) when
// the Content-Type is missing or has no boundary, the body is empty, or
// the payload is malformed (see src/forms.c limits such as MAX_FILE_SIZE).
func (c *Context) MultipartForm() (*Form, error) {
	if c.form != nil {
		return c.form, nil
	}
	if c.formErr != nil {
		return nil, c.formErr
	}
	var raw *C.MultipartForm
	var code C.int
	var cmsg *C.char
	if C.bridge_parse_multipart(c.conn, &raw, &code, &cmsg) != 0 || raw == nil {
		msg := "invalid multipart form"
		if cmsg != nil {
			msg = C.GoString(cmsg)
		}
		err := NewHTTPError(http.StatusBadRequest, msg)
		c.formErr = err
		return nil, err
	}

	body := c.Body() // Zero-copy; file payloads subslice this buffer.
	f := &Form{ctx: c, raw: raw, body: body}

	if n := int(C.bridge_form_num_fields(raw)); n > 0 {
		f.fields = make([]formField, 0, n)
		for i := range n {
			var cn, cv *C.char
			var nl, vl C.size_t
			if C.bridge_form_field_at(raw, C.size_t(i), &cn, &nl, &cv, &vl) == 0 {
				continue
			}
			f.fields = append(f.fields, formField{
				name:  unsafeView(cn, nl),
				value: unsafeView(cv, vl),
			})
		}
	}

	if n := int(C.bridge_form_num_files(raw)); n > 0 {
		f.files = make([]*UploadedFile, 0, n)
		for i := range n {
			var cField, cName, cType *C.char
			var fieldLen, nameLen, typeLen C.size_t
			var off, sz C.size_t
			if C.bridge_form_file_at(raw, C.size_t(i),
				&cField, &fieldLen, &cName, &nameLen, &cType, &typeLen,
				&off, &sz) == 0 {
				continue
			}
			o, s := int(off), int(sz)
			var data []byte
			// Guard against a body that changed under us; on mismatch
			// expose an empty payload rather than slicing out of bounds.
			if o >= 0 && s >= 0 && o+s <= len(body) {
				data = body[o : o+s : o+s]
				// The C parser (src/forms.c) windows the payload up to
				// the boundary marker, which includes the CRLF
				// delimiter preceding it. Strip exactly one trailing
				// CRLF so Data holds the file bytes the client sent,
				// matching mime/multipart semantics. Trimming only
				// shortens the view — it stays zero-copy.
				if len(data) >= 2 && data[len(data)-2] == '\r' && data[len(data)-1] == '\n' {
					data = data[:len(data)-2]
				}
			}
			f.files = append(f.files, &UploadedFile{
				FieldName: unsafeView(cField, fieldLen),
				Filename:  unsafeView(cName, nameLen),
				MimeType:  unsafeView(cType, typeLen),
				Data:      data,
				Size:      len(data),
			})
		}
	}

	c.form = f
	return f, nil
}

// FormFile returns the first uploaded file for field name, parsing the
// multipart form on first use. It is shorthand for
// MultipartForm followed by Form.File.
func (c *Context) FormFile(name string) (*UploadedFile, error) {
	f, err := c.MultipartForm()
	if err != nil {
		return nil, err
	}
	return f.File(name)
}

// FormValue returns the first value for name, checking multipart fields,
// then the URL-encoded body, then the query string. It returns "" when
// the name is absent everywhere. Use FormValueView for the zero-copy
// variant where available, or Field/Query/PostFormValue to target one
// source explicitly.
func (c *Context) FormValue(name string) string {
	if name == "" {
		return ""
	}
	if ct := c.Header("Content-Type"); strings.HasPrefix(ct, "multipart/form-data") {
		if f, err := c.MultipartForm(); err == nil {
			if v := f.Field(name); v != "" {
				return v
			}
		}
	} else if v := c.PostFormValue(name); v != "" {
		return v
	}
	return c.Query(name)
}

// SaveUploadedFile writes file's zero-copy payload to dst with mode 0600,
// creating or truncating the destination. Parent directories are not
// created; create them beforehand if needed.
func (c *Context) SaveUploadedFile(file *UploadedFile, dst string) error {
	if file == nil {
		return NewHTTPError(http.StatusBadRequest, "no file to save")
	}
	if err := os.WriteFile(dst, file.Data, 0600); err != nil {
		return NewHTTPError(http.StatusInternalServerError, "cannot save upload").WithInternal(err)
	}
	return nil
}

// PostForm parses an application/x-www-form-urlencoded body into a map of
// name to all its values, caching the result. It returns nil when the
// body is empty or is not URL-encoded. Percent-decoded outputs allocate;
// the scan itself borrows the zero-copy body. Malformed pairs are
// skipped. Values are already percent-decoded (with '+' as space).
func (c *Context) PostForm() map[string][]string {
	if c.postFormParsed {
		return c.postForm
	}
	c.postFormParsed = true
	body := c.Body()
	if len(body) == 0 {
		return nil
	}
	ct := c.Header("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct != "" && ct != "application/x-www-form-urlencoded" {
		return nil
	}
	out := parseURLEncoded(body)
	c.postForm = out
	return out
}

// PostFormValue returns the first URL-encoded body value for name, or ""
// if absent. It parses (and caches) via PostForm.
func (c *Context) PostFormValue(name string) string {
	if name == "" {
		return ""
	}
	pf := c.PostForm()
	if pf == nil {
		return ""
	}
	vals := pf[name]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// parseURLEncoded parses a URL-encoded body (k=v&k2=v2) into a map.
// Decoding allocates; the scan borrows b without copying it first.
func parseURLEncoded(b []byte) map[string][]string {
	var out map[string][]string
	start := 0
	for i := 0; i <= len(b); i++ {
		if i < len(b) && b[i] != '&' && b[i] != ';' {
			continue
		}
		pair := b[start:i]
		start = i + 1
		if len(pair) == 0 {
			continue
		}
		var key, val []byte
		if j := indexByte(pair, '='); j >= 0 {
			key, val = pair[:j], pair[j+1:]
		} else {
			key = pair
		}
		k, err := url.QueryUnescape(bytesView(key))
		if err != nil {
			continue
		}
		v, err := url.QueryUnescape(bytesView(val))
		if err != nil {
			continue
		}
		if out == nil {
			out = make(map[string][]string)
		}
		out[k] = append(out[k], v)
	}
	return out
}

// bytesView aliases b as a string without copying. The result must not
// outlive b.
func bytesView(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// indexByte is bytes.IndexByte inlined to keep this file dependency-light.
func indexByte(b []byte, v byte) int {
	for i := range b {
		if b[i] == v {
			return i
		}
	}
	return -1
}
