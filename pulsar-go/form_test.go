package pulsar

import (
	"reflect"
	"testing"
)

func TestParseURLEncoded(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string][]string
	}{
		{"empty", "", nil},
		{"single", "name=john", map[string][]string{"name": {"john"}}},
		{"plus-is-space", "name=john+doe", map[string][]string{"name": {"john doe"}}},
		{"percent", "city=New%20York", map[string][]string{"city": {"New York"}}},
		{"multi-value", "a=1&a=2&a=3", map[string][]string{"a": {"1", "2", "3"}}},
		{"empty-value", "flag=", map[string][]string{"flag": {""}}},
		{"bare-key", "flag", map[string][]string{"flag": {""}}},
		{"skips-empty-pairs", "a=1&&b=2&", map[string][]string{"a": {"1"}, "b": {"2"}}},
		{"semicolon-sep", "a=1;b=2", map[string][]string{"a": {"1"}, "b": {"2"}}},
		{"skips-malformed-escape", "a=%zz&b=ok", map[string][]string{"b": {"ok"}}},
		{"key-decoded", "a%20b=c", map[string][]string{"a b": {"c"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseURLEncoded([]byte(tt.input)); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseURLEncoded(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormFieldAccessors(t *testing.T) {
	f := &Form{
		fields: []formField{
			{name: "color", value: "red"},
			{name: "color", value: "blue"},
			{name: "size", value: "L"},
		},
		files: []*UploadedFile{
			{FieldName: "avatar", Filename: "a.png", MimeType: "image/png", Data: []byte("123")},
			{FieldName: "avatar", Filename: "b.png", MimeType: "image/png", Data: []byte("4567")},
		},
	}
	for _, uf := range f.files {
		uf.Size = len(uf.Data)
	}

	if got := f.Field("color"); got != "red" {
		t.Fatalf("Field(color) = %q, want red", got)
	}
	if got := f.Field("missing"); got != "" {
		t.Fatalf("Field(missing) = %q, want empty", got)
	}
	if got := f.Fields("color"); !reflect.DeepEqual(got, []string{"red", "blue"}) {
		t.Fatalf("Fields(color) = %#v", got)
	}
	if got := f.FieldMap(); !reflect.DeepEqual(got, map[string][]string{
		"color": {"red", "blue"},
		"size":  {"L"},
	}) {
		t.Fatalf("FieldMap() = %#v", got)
	}

	first, err := f.File("avatar")
	if err != nil {
		t.Fatalf("File(avatar) error: %v", err)
	}
	if first.Filename != "a.png" || first.Size != 3 {
		t.Fatalf("File(avatar) = %+v", first)
	}
	if got := f.Files("avatar"); len(got) != 2 {
		t.Fatalf("Files(avatar) count = %d, want 2", len(got))
	}
	if _, err := f.File("missing"); err == nil {
		t.Fatal("File(missing) expected error, got nil")
	}
}

func TestFormCloseIdempotent(t *testing.T) {
	f := &Form{}
	f.Close() // Must not panic on a form with no C arena.
	f.Close()
	if !f.closed {
		t.Fatal("Close did not mark form closed")
	}
}
