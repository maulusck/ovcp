module github.com/ovcp/ovcp

go 1.22

require (
	github.com/mattn/go-sqlite3 v1.14.22
	golang.org/x/crypto v0.31.0
	golang.org/x/term v0.27.0
)

require (
	github.com/mdp/qrterminal/v3 v3.2.0
	golang.org/x/sys v0.28.0
)

require rsc.io/qr v0.2.0 // indirect

replace golang.org/x/crypto => github.com/golang/crypto v0.31.0

replace golang.org/x/sys => github.com/golang/sys v0.28.0

replace golang.org/x/term => github.com/golang/term v0.27.0

replace rsc.io/qr => github.com/rsc/qr v0.2.0
