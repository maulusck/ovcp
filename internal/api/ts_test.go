package api

import (
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestTypeScript: a type reads in TypeScript exactly as encoding/json writes it.
func TestTypeScript(t *testing.T) {
	type Inner struct{ A int }
	type Fixture struct {
		Inner
		Tagged string    `json:"tagged"`
		Opt    int       `json:"opt,omitempty"`
		When   time.Time `json:"when,omitzero"`
		Skip   string    `json:"-"`
		P      *Inner
		L      []string
		M      map[string]bool
		B      []byte
		hidden int
	}
	g := tsGen{decls: map[string]string{}, types: map[string]reflect.Type{}}
	if got := g.ts(reflect.TypeFor[Fixture]()); got != "Fixture" {
		t.Fatalf("ts = %q, want the named reference", got)
	}
	want := "{ A: number; tagged: string; opt?: number; when?: string; P: Inner | null; L: string[]; M: Record<string, boolean>; B: string; }"
	if got := g.decls["Fixture"]; got != want {
		t.Fatalf("Fixture =\n%s\nwant\n%s", got, want)
	}
	if got := g.ts(reflect.TypeFor[Patch[Inner]]()); got != "Inner" {
		t.Fatalf("Patch[Inner] = %q, want Inner", got)
	}
	if !strings.Contains(TypeScript(), `"GET /api/status": { in: Partial<Record<string, never>>; out: Status }`) {
		t.Fatal("TypeScript() lacks GET /api/status")
	}
}

// TestWildcardMustBeInput: a {wildcard} the handler's input doesn't name, by
// its exact JSON name, can't be registered.
func TestWildcardMustBeInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic for {id} against field ID")
		}
	}()
	wildcards("DELETE /api/x/{id}", reflect.TypeFor[struct{ ID string }]())
}

// TestPathBeatsBody: a path value wins over the same field in the body.
func TestPathBeatsBody(t *testing.T) {
	e := setup(t)
	e.login("admin")
	r := e.req("DELETE", "/api/users/admin", `{"name":"nobody"}`, true)
	if b, _ := io.ReadAll(r.Body); !strings.Contains(string(b), "your own account") {
		t.Fatalf("%d %s, want the own-account refusal: the path names admin", r.StatusCode, b)
	}
}
