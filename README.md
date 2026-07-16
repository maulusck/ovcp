<h1 style="display:flex; align-items:center; gap:10px; margin:0">
  <img src="web/ui/public/favicon.svg" width="34" height="34" alt="">
  OVCP — self-hosted OpenVPN control plane
</h1>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Go 1.22+](https://img.shields.io/badge/go-1.22%2B-00ADD8)

Run and manage one [OpenVPN](https://openvpn.net/) server without easy-rsa,
docker-compose spaghetti, or a separate PKI toolchain. OVCP is a single
static Go binary — a built-in certificate authority, a web admin UI, a
scriptable CLI, and OpenVPN process supervision, all in one process.

- **Native PKI** — issue, revoke, and renew client/server certificates; no
  `easy-rsa`, no shell scripts. CA private key stored encrypted
  (argon2id + AES-256-GCM); every sign/revoke needs the passphrase in memory,
  never on disk.
- **One binary** — the Svelte web UI is embedded in the Go binary. No
  Node.js, reverse proxy, or separate frontend deploy in production.
- **Full CLI** — every UI action has a CLI equivalent, with `-json` output
  on `list`/`status`/`audit`/`stats`/`user list` for scripting, and shell
  completion for bash/zsh/fish.
- **Client export** — generate ready-to-import `.ovpn` profiles (optionally
  key-encrypted) or a scannable QR code, from the CLI or the UI.
- **Live stats & audit log** — per-client traffic/connection history, a
  live top-like `stats -follow`, and an audit trail of every admin action.
- **Optional Telegram bot** — push notifications for revokes, user changes,
  and cert-expiry warnings, plus a narrow Start/Stop/Restart menu gated to
  one linked admin chat. Off by default; nothing else depends on it.
- **Encrypted backup/restore** — one command exports CA, CRL, tls-crypt key,
  config, and database into a single encrypted archive.
- **Prod-ready deployment** — systemd unit, `.deb`/`.rpm` packages, an
  all-in-one container image, and a SELinux policy, all included.

## Requirements

- **Runtime:** Linux with `/dev/net/tun`, and [`openvpn`](https://openvpn.net/)
  on `PATH`. OVCP runs as root — it owns the PKI and starts openvpn itself
  as a supervised child process.
- **Build:** Go 1.22+, a C compiler (CGO, for the SQLite driver), Node/npm
  (Svelte UI), and `mandoc` (renders the man page into the UI's Docs tab).
  Run `make deps` to check, or see `man ovcp`'s **REQUIREMENTS** section.

## Install

Pick one:

```sh
# Debian/Ubuntu or Fedora/RHEL — prebuilt package (needs nfpm to build it)
make deb   # or: make rpm
sudo apt install ./dist/ovcp_*.deb   # or: sudo rpm -i dist/ovcp-*.rpm

# Container (podman or docker) — OpenVPN included, nothing else to install
podman build -t ovcp -f Containerfile .

# From source
make deps && make release   # → bin/ovcp, dist/completion/*
```

## Quick start

Setup is two commands: `init` once, then `serve`.

```sh
export OVCP_DATA=$PWD/data   # or run as root against /var/lib/ovcp — see below

bin/ovcp init -server-cn vpn.example.com
# → CA, server cert, tls-crypt key, server.conf, admin user
# → prompts for a CA passphrase and the admin password

bin/ovcp serve
# → starts openvpn (ovcp owns the process) and the admin UI
# → https://127.0.0.1:8443 (self-signed cert on first run)
```

`init` is idempotent — safe to re-run any time, it only fills in what's
missing. If `serve` refuses with `not initialized, missing: ...`, that's
the fix.

Issue a client and hand them a ready-to-import profile:

```sh
bin/ovcp export -cn alice -remote vpn.example.com > alice.ovpn
```

**Production**, via the installed package:

```sh
sudo ovcp init -server-cn vpn.example.com
sudo systemctl enable --now ovcp
```

**Container**, same two steps:

```sh
podman run --rm -v ovcp:/var/lib/ovcp ovcp init -server-cn vpn.example.com
podman run -d --cap-add=NET_ADMIN --device /dev/net/tun \
  -p 1194:1194/udp -p 127.0.0.1:8443:8443 \
  -v ovcp:/var/lib/ovcp ovcp
```

Every client showing the same `RealAddress`? That's your container
runtime's userspace port proxy rewriting the source address, not an ovcp
bug — see `man ovcp`'s **DEPLOYMENT** → **container** section for the fix
(Docker, Podman, and Kubernetes each have a different one).

## CLI

`ovcp <command>` covers certs, users, backups, live status, and stats —
run `ovcp -h` for the full command table, or `man ovcp` for every flag,
the security/privilege model, environment variables, and deployment
recipes. Machine-readable output: pass `-json` to `list`/`status`/`audit`/
`stats`/`user list`.

## Full reference

`man ovcp` (`make man` to preview before installing) is the complete,
maintained reference: every command and flag, the security model, the
privilege model (and why it's *not* privilege-separated), every environment
variable, every file ovcp reads or writes, and deployment recipes for
systemd, containers, SELinux, and distro packages. This README stays a
pitch and a quick start; nothing above duplicates it, so it can't drift out
of sync.

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

## License

[MIT](LICENSE)
