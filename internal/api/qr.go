package api

import (
	"encoding/base64"
	"fmt"
	"strings"

	"rsc.io/qr"
)

// qrDataURI renders text as a QR code SVG data URI, for inline <img> use.
// Reuses the qr encoder already vendored for `ovcp user totp`'s terminal
// output instead of pulling in a JS QR library.
func qrDataURI(text string) (string, error) {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return "", err
	}
	const scale = 4
	dim := (code.Size + 2) * scale
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">`, dim, dim, dim, dim)
	b.WriteString(`<rect width="100%" height="100%" fill="#fff"/>`)
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d"/>`, (x+1)*scale, (y+1)*scale, scale, scale)
			}
		}
	}
	b.WriteString(`</svg>`)
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(b.String())), nil
}
