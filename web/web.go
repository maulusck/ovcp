// Package web embeds the built admin UI.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the UI rooted at its index.
func Dist() fs.FS {
	f, _ := fs.Sub(dist, "dist")
	return f
}
