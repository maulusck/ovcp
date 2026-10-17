// Command apits prints the web API's TypeScript declarations, which the web
// UI's type check (make check) reads.
package main

import (
	"os"

	"github.com/ovcp/ovcp/internal/api"
)

func main() { os.Stdout.WriteString(api.TypeScript()) }
