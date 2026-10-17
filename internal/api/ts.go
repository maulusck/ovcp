package api

import (
	"encoding"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"
)

// TypeScript is the web API as TypeScript declarations, read off routes: each
// pattern's input (every field optional, as a JSON body may omit any) and output.
func TypeScript() string {
	g := tsGen{decls: map[string]string{}, types: map[string]reflect.Type{}}
	var b strings.Builder
	b.WriteString("// Generated from internal/api's routes by `go run ./cmd/apits`; do not edit.\n\n")
	b.WriteString("export interface Routes {\n")
	for _, rt := range (&Server{}).routes() {
		fmt.Fprintf(&b, "  %q: { in: Partial<%s>; out: %s }\n", rt.pattern, g.ts(rt.in), g.ts(rt.out))
	}
	b.WriteString("}\n\nexport interface Download { blob: Blob; filename: string }\n")
	for _, name := range slices.Sorted(maps.Keys(g.decls)) {
		fmt.Fprintf(&b, "export interface %s %s\n", name, g.decls[name])
	}
	return b.String()
}

// tsGen collects one declaration per named Go struct, refusing two that share a name.
type tsGen struct {
	decls map[string]string
	types map[string]reflect.Type
}

var (
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
)

// ts is t as encoding/json writes it.
// ponytail: a nil slice or map encodes null but is typed []/Record; producers
// return empty ones. Upgrade: encoding/json/v2 (nil encodes empty) everywhere.
func (g *tsGen) ts(t reflect.Type) string {
	switch {
	case t == reflect.TypeFor[time.Time]():
		return "string"
	case t == reflect.TypeFor[Download]():
		return "Download"
	case t.Implements(reflect.TypeFor[interface{ patched() reflect.Type }]()):
		return g.ts(reflect.Zero(t).Interface().(interface{ patched() reflect.Type }).patched())
	case t.Implements(jsonMarshaler) || reflect.PointerTo(t).Implements(jsonMarshaler):
		panic("ts: " + t.String() + " has its own MarshalJSON")
	case t.Implements(textMarshaler) || reflect.PointerTo(t).Implements(textMarshaler):
		return "string"
	}
	switch t.Kind() {
	case reflect.Pointer:
		return g.ts(t.Elem()) + " | null"
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return "string" // base64
		}
		if e := g.ts(t.Elem()); !strings.ContainsAny(e, " |") {
			return e + "[]"
		}
		return "(" + g.ts(t.Elem()) + ")[]"
	case reflect.Map:
		return "Record<" + g.ts(t.Key()) + ", " + g.ts(t.Elem()) + ">"
	case reflect.Struct:
		if t.Name() == "" || len(jsonFields(t)) == 0 {
			return g.fields(t)
		}
		if seen, ok := g.types[t.Name()]; ok {
			if seen != t {
				panic("ts: " + t.String() + " and " + seen.String() + " share a name")
			}
			return t.Name()
		}
		g.types[t.Name()] = t
		g.decls[t.Name()] = g.fields(t)
		return t.Name()
	}
	panic("ts: unsupported " + t.String())
}

func (g *tsGen) fields(t reflect.Type) string {
	fs := jsonFields(t)
	if len(fs) == 0 {
		return "Record<string, never>"
	}
	var b strings.Builder
	b.WriteString("{")
	for _, f := range fs {
		opt := ""
		if f.optional {
			opt = "?"
		}
		fmt.Fprintf(&b, " %s%s: %s;", f.name, opt, g.ts(f.Type))
	}
	b.WriteString(" }")
	return b.String()
}

// jsonFieldOf is a struct field as encoding/json names it.
type jsonFieldOf struct {
	reflect.StructField
	name     string
	optional bool // omitempty or omitzero
}

// jsonFields are t's fields as encoding/json writes them, untagged embedded
// structs flattened.
// ponytail: no shadowing between embedded and outer names; add it when a type needs it.
func jsonFields(t reflect.Type) []jsonFieldOf {
	var out []jsonFieldOf
	for i := range t.NumField() {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch {
		case name == "-":
		case f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct:
			out = append(out, jsonFields(f.Type)...)
		case f.IsExported():
			if name == "" {
				name = f.Name
			}
			opt := strings.Contains(opts, "omitempty") || strings.Contains(opts, "omitzero")
			out = append(out, jsonFieldOf{f, name, opt})
		}
	}
	return out
}

// jsonField is t's field named name in JSON.
func jsonField(t reflect.Type, name string) (jsonFieldOf, bool) {
	for _, f := range jsonFields(t) {
		if f.name == name {
			return f, true
		}
	}
	return jsonFieldOf{}, false
}
