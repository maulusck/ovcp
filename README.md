<h1 style="display:flex; align-items:center; gap:10px; margin:0">
  <img src="web/ui/public/favicon.svg" width="34" height="34" alt="">
  OVCP — OpenVPN Control Plane
</h1>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Go 1.22+](https://img.shields.io/badge/go-1.22%2B-00ADD8)

**OVCP runs an OpenVPN server end to end** — CA, server config, client
issuance, the `openvpn` process itself. One static binary. No `easy-rsa`.
No shell scripts hacked around `openssl`. No compose stack. No separate
database. `ovcp` owns the CA, the config, the worker process — bare
metal, systemd, container, no difference.

Beyond certs: internal DNS, policy-routed egress, per-client traffic
stats, operational notifications. Same binary. All optional. Zero extra
installs. CLI and web UI both do the full job — neither is a
stripped-down stand-in for the other.

## Features

### Core

Always on. No external tool required.

- **Native PKI** — issue, revoke, renew. No `easy-rsa`, no hand-rolled
  `openssl` wrappers. CA private key encrypted at rest. Passphrase never
  touches disk.
- **One binary** — web UI embedded. No separate frontend, no reverse
  proxy.
- **Full CLI** — every UI action has a CLI twin, not a crippled subset.
  `-json` flips any command to machine output, same fields either way.
  Completion for bash/zsh/fish.
- **Client export** — ready-to-import `.ovpn` on stdout, optionally
  key-encrypted, split-tunnel or full-tunnel, custom OpenVPN directives
  per client. Same output, CLI or UI.
- **Live stats & audit log** — per-client traffic history, a top(1)-style
  `stats -follow`, an audit trail of every admin action.
- **Log management** — rotation for `openvpn.log`/`ovcp.log`/
  `dnsmasq.log`, retention configurable. Copytruncate against each
  worker's already-open handle. No restart.
- **Access control** — role-based (admin/operator/readonly), optional
  TOTP 2FA with QR enrollment, rate-limited logins, CSRF-protected
  HTTPS-only sessions.
- **Encrypted backup/restore** — one command, one encrypted archive.
  Everything needed to rebuild the server. Nothing tied to the original
  host.
- **Packaging** — systemd unit, `.deb`/`.rpm`/`.apk`/Arch/Void
  (amd64, ARM, RISC-V; glibc or musl), multi-arch container image,
  SELinux policy. Shipped. Not bolted on after the fact.

### Optional modules

Gated on a tool being on `PATH`, or explicit opt-in. Core doesn't care
whether they're there or not.

- **Internal DNS** (needs [`dnsmasq`](https://thekelleys.org.uk/dnsmasq/doc.html))
  — resolve the server and every connected client by hostname over the
  tunnel, plus custom hosts-file entries. Restrict it to local names
  only, no upstream forwarding.
- **Upstreams** (needs [`nftables`](https://wiki.nftables.org/)) — pick
  the egress connected clients exit through instead of the box's own
  default route, switchable live in the common case: a local interface (a
  second NIC, a WireGuard peer — anything already up on the host, `ovcp`
  only steers and NATs) or a SOCKS5 backend (Tor, proxychains,
  self-hosted, relayed through a small in-process proxy). Per-client
  overrides on top of a server-wide default, kill-switched: a dead egress
  fails traffic closed, never leaks it out the host's own route.
- **Telegram bot** (needs a bot token) — notifications for revokes, user
  changes, CA rotation, cert expiry, plus a narrow Start/Stop/Restart/
  Reconnect menu gated to one linked chat. Off unless configured. Nothing
  else depends on it.

## Requirements

Linux with `/dev/net/tun`, [`openvpn`](https://openvpn.net/) on `PATH`.
OVCP runs as root — owns the PKI, starts openvpn itself as a supervised
child process. [`dnsmasq`](https://thekelleys.org.uk/dnsmasq/doc.html)
and [`nftables`](https://wiki.nftables.org/) are optional, gating DNS and
Upstreams above — `ovcp` starts/programs each itself when found, never
installs either.

That's what it takes to run ovcp. Building from source has its own
toolchain requirements — see [`docs/BUILD.md`](docs/BUILD.md).

## Install

Ships three ways. Pick one.

- **Distro package** — `.deb`, `.rpm`, `.apk`, or Arch/Void — binary, man
  page, shell completions, service file, one step. `openvpn` pulls in as
  a hard dependency; `dnsmasq`/`nftables` are suggested, not forced.
- **Container image** — one image, OpenVPN included, nothing else to
  install.
- **Static binary** — drop `ovcp` on `PATH`. Nothing else required at
  runtime beyond `openvpn` itself.

No tagged release yet. Nothing prebuilt. Build from source — see
[`docs/BUILD.md`](docs/BUILD.md) for your architecture and libc.

## Quick start

Examples assume `ovcp` is on `PATH` — a distro package puts it there; a
from-source build needs `sudo make install` first, or run `bin/ovcp`
straight from the checkout (see [`docs/BUILD.md`](docs/BUILD.md)).

Two commands: `init` once, `serve` forever after.

```sh
export OVCP_DATA=$PWD/data   # or run as root against /var/lib/ovcp — see below

ovcp init -server-cn vpn.example.com
# → CA, server cert, tls-crypt key, server.conf, admin user
# → prompts for a CA passphrase and the admin password

ovcp serve
# → starts openvpn (ovcp owns the process) and the admin UI
# → https://127.0.0.1:8443 (self-signed cert on first run)
```

`init` is idempotent. Re-run it whenever; it only fills gaps. `serve`
refusing with `not initialized, missing: ...` means run `init` first.

Issue a client, get a ready-to-import profile:

```sh
ovcp certificate issue -cn alice -export -remote vpn.example.com > alice.ovpn
```

**Production**, installed package:

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

Identical `RealAddress` on every client: `man ovcp`, **DEPLOYMENT** →
**container**.

## CLI

`ovcp <command>` covers certs, users, backups, live status, stats — `ovcp
-h` for the full command table, `man ovcp` for every flag, the security/
privilege model, environment variables, deployment recipes. Every command
scriptable: `ovcp -json <command>` (flag goes *before* the command, like
`-data`/`-debug`) swaps human text for JSON on stdout — same fields, both
directions, errors included (`{"error": "..."}`, same shape the REST API
uses). `stats -follow` and `completion` are the only exceptions — no
single result to encode.

```sh
ovcp -json certificate list | jq -r '.[] | select(.status == "expired") | .cn'
```

## Documentation

Four documents, four altitudes, nothing duplicated between them:

- **This README** — what OVCP is, why it exists, shortest path to a
  running server.
- **[`man ovcp`](docs/ovcp.8)** — the complete runtime reference: every
  command and flag, the security and privilege model, every environment
  variable, every file ovcp reads or writes, deployment recipes for
  systemd, containers, SELinux. Same page renders into the web UI's
  **Docs** tab at build time — no terminal needed, one source either way.
  From a checkout, before installing anything: `make man`.
- **[`docs/BUILD.md`](docs/BUILD.md)** — building the binary,
  cross-compiling for another arch/libc, the container image,
  distro/Void packages.
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** — internal design:
  source layout, the process and IPC model, the rationale behind
  decisions that affect more than one package.

## License

[MIT](LICENSE)
