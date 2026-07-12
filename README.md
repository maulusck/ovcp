# OVCP — OpenVPN Control Plane

Self-hosted management for one OpenVPN server: web UI, native PKI (no
easy-rsa), client `.ovpn` export, audit log. One static Go binary with the
Svelte UI embedded. OpenVPN itself is an external dependency, controlled
only via its management unix socket.

Runtime needs `openvpn` on `PATH`. Building needs Go 1.22+, a C compiler,
Node/npm, and `mandoc` — run `make deps` to check, or see `man ovcp` for
the full list.

Prefer a distro package over building from source? `make deb` / `make rpm`
(needs `nfpm`) — see `man ovcp`'s **packages** section.

## Quick start (dev)

```sh
make release              # builds UI + bin/ovcp
export OVCP_DATA=$PWD/data

# one-shot setup: CA, server cert, tls-crypt key, server.conf, admin user
bin/ovcp init -server-cn vpn.example.com
# → prompts for a new CA passphrase (needed for every issue/revoke)
# → prompts for the admin user's password

bin/ovcp serve
# → starts openvpn from data/server.conf (ovcp owns the process)
# → admin UI: https://127.0.0.1:8443  (self-signed cert)

bin/ovcp export -cn alice -remote vpn.example.com > alice.ovpn
```

If `serve` says `not initialized, missing: ...` — run `ovcp init` first;
it is idempotent and fills in whatever is missing.

## Full reference

`man ovcp` (`make man` to preview before installing) is the complete,
maintained reference: every command and flag, the security model, the
privilege model (and why it's *not* privilege-separated), every environment
variable, every file ovcp reads or writes, and deployment recipes for
systemd, containers, SELinux, and distro packages. This README stays a
pitch and a quick start; nothing below duplicates it, so it can't drift out
of sync with it.

The same page is also in the web UI's **Docs** tab (`mandoc` renders
`docs/ovcp.8` at build time into `web/dist/docs.html`, embedded in the
binary like the rest of the UI) — no terminal needed to read it, one source
either way.

## Layout

```
cmd/ovcp             CLI + serve entrypoint
internal/pki         CA, issue/revoke, CRL, .ovpn bundles, tls-crypt
internal/store       SQLite (metadata only — never private keys)
internal/backup      encrypted export/import (CA, CRL, tls-crypt, config, database)
internal/controller  openvpn Supervisor (reaped child) + control socket; mgmt client
internal/ovpnconf    validated server.conf generation
internal/auth        argon2id, sessions, TOTP, rate-limit, RBAC
internal/api         REST/JSON + embedded UI, HTTPS, CSRF
web/ui               Svelte 5 sources → web/dist (embedded)
deploy/              systemd units, nfpm packaging, selinux.sh
docs/ovcp.8          man page
```

## Development

```sh
make help
go test ./...
cd web/ui && npm run dev   # UI dev server (proxy API manually or run serve)
```

`mandoc` isn't packaged everywhere by default — `apk add mandoc` / `apt
install mandoc` (already in the container build stage).
