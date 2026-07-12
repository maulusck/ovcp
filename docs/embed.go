// Package docs embeds ovcp.8, pre-rendered to plain text by `make build`,
// for `ovcp --help` (no runtime man/mandoc dependency).
package docs

import _ "embed"

//go:embed ovcp.txt
var Text string
