<h1 style="display:flex; align-items:center; gap:10px; margin:0">
  <img src="web/ui/public/favicon.svg" width="34" height="34" alt="">
  OVCP — OpenVPN Control Plane
</h1>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Go 1.22+](https://img.shields.io/badge/go-1.22%2B-00ADD8)

One [OpenVPN](https://openvpn.net/) server, one static binary, one data
directory. No `easy-rsa`, no compose stack, no separate PKI toolchain
bolted on after the fact. `ovcp` owns the CA, the server config, and the
openvpn process itself, the same way on bare metal, under systemd, or in
a container. A CLI for scripts, a web UI for humans; neither is the
second-class citizen.

## Features

- **Native PKI** — issue, revoke, renew. No `easy-rsa`, no shell scripts
  wrapping `openssl`. CA private key encrypted at rest, passphrase never
  persisted.
- **One binary** — the web UI is embedded in it. No separate frontend to
  deploy, no reverse proxy required.
- **Full CLI** — every UI action has a CLI equivalent, not a subset.
  `-json` switches every command to machine-readable output, same fields
  either way. Shell completion for bash/zsh/fish.
- **Client export** — a complete, ready-to-import `.ovpn` profile on
  stdout, optionally key-encrypted, from the CLI or the UI.
- **Internal DNS** (optional) — dnsmasq resolves the server and each
  connected client by hostname over the tunnel, plus custom hosts-file
  entries. Switch it to answer only local names, no upstream forwarding.
- **Live stats & audit log** — per-client traffic history, a top-like
  `stats -follow`, and an audit trail of every admin action.
- **Telegram bot** (optional) — notifications for revokes, user changes,
  CA rotation, and cert expiry, plus a narrow Start/Stop/Restart/Reconnect
  menu gated to one linked chat. Off by default; nothing else depends on it.
- **Encrypted backup/restore** — one command, one encrypted archive:
  everything needed to restore the server, nothing that needs the
  original host.
- **Access control** — role-based (admin/operator/readonly), optional
  TOTP 2FA with QR-code enrollment, rate-limited logins, CSRF-protected
  HTTPS-only sessions.
- **Packaging** — systemd unit, `.deb`/`.rpm`/`.apk`/Arch/Void packages
  (amd64, ARM, RISC-V; glibc or musl), a multi-arch container image, and a
  SELinux policy. All included, none bolted on later.

## Requirements

Linux with `/dev/net/tun`, and [`openvpn`](https://openvpn.net/) on `PATH`.
OVCP runs as root — it owns the PKI and starts openvpn itself as a
supervised child process. [`dnsmasq`](https://thekelleys.org.uk/dnsmasq/doc.html)
on `PATH` is optional, for internal DNS — ovcp starts it itself when found.

This is sufficient to run ovcp. Building it from source has its own
toolchain requirements — see [`docs/BUILD.md`](docs/BUILD.md).

## Install

OVCP ships in three equivalent forms; choose based on your host:

- **Distro package** — `.deb`, `.rpm`, `.apk`, or Arch/Void — installs the
  binary, man page, shell completions, and a service file for your init
  system in one step.
- **Container image** — one image, OpenVPN included, nothing else to
  install.
- **Static binary** — drop `ovcp` on `PATH`; nothing else required at
  runtime beyond `openvpn` itself.

No tagged release exists yet, so none of these are published as
ready-to-download artifacts — build from source; see
[`docs/BUILD.md`](docs/BUILD.md) for your architecture and libc.

## Quick start

The examples below assume `ovcp` is on `PATH` — a distro package puts it
there; a from-source build needs `sudo make install` first, or run
`bin/ovcp` directly from the checkout (see [`docs/BUILD.md`](docs/BUILD.md)).

Setup is two commands: `init` once, then `serve`.

```sh
export OVCP_DATA=$PWD/data   # or run as root against /var/lib/ovcp — see below

ovcp init -server-cn vpn.example.com
# → CA, server cert, tls-crypt key, server.conf, admin user
# → prompts for a CA passphrase and the admin password

ovcp serve
# → starts openvpn (ovcp owns the process) and the admin UI
# → https://127.0.0.1:8443 (self-signed cert on first run)
```

`init` is idempotent — safe to re-run any time, it only fills in what's
missing. If `serve` refuses with `not initialized, missing: ...`, that's
the fix.

Issue a client and hand them a ready-to-import profile:

```sh
ovcp certificate issue -cn alice -export -remote vpn.example.com > alice.ovpn
```

**Production**, via an installed package:

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

Every client showing the same `RealAddress`? See `man ovcp`'s
**DEPLOYMENT** → **container** section.

## CLI

`ovcp <command>` covers certs, users, backups, live status, and stats —
run `ovcp -h` for the full command table, or `man ovcp` for every flag,
the security/privilege model, environment variables, and deployment
recipes. Every command is scriptable: `ovcp -json <command>` (flag comes
*before* the command, like `-data`/`-debug`) swaps its human text for JSON
on stdout — same fields, both directions, including errors
(`{"error": "..."}`, same shape the REST API uses). `stats -follow` and
`completion` are the only two exceptions, both because there's no single
result to encode.

```sh
ovcp -json certificate list | jq -r '.[] | select(.status == "expired") | .cn'
```

## Documentation

Four documents, four altitudes, nothing duplicated between them:

- **This README** — what OVCP is, why it exists, and the shortest path to
  a running server.
- **[`man ovcp`](docs/ovcp.8)** — the complete runtime reference: every
  command and flag, the security and privilege model, every environment
  variable, every file ovcp reads or writes, and deployment recipes for
  systemd, containers, and SELinux. The same page renders into the web
  UI's **Docs** tab at build time — no terminal needed to read it, one
  source either way.
- **[`docs/BUILD.md`](docs/BUILD.md)** — building the binary, cross-compiling
  for another arch/libc, the container image, and distro/Void packages.
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** — internal design:
  source layout, the process and IPC model, and the rationale behind
  decisions that affect more than one package.

## License

[MIT](LICENSE)
