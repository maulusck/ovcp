<h1 style="display:flex; align-items:center; gap:10px; margin:0">
  <img src="web/ui/public/favicon.svg" width="34" height="34" alt="OVCP logo">
  OVCP — OpenVPN Control Plane
</h1>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**OVCP runs an OpenVPN server end to end** from one static Go binary: its
own certificate authority, the server configuration, client certificate
issuance and the `openvpn` process itself. It needs no `easy-rsa`, no
`openssl` scripts, no separate database and no compose stack, and it
behaves the same on bare metal, under systemd and in a container.

Internal DNS, policy-routed egress, per-client traffic statistics and
notifications are built in and optional. The CLI covers every operation;
the web UI covers all but setup, the CA and restore, which stay on the host.

[Features](#features) · [Requirements](#requirements) ·
[Install](#install) · [Quick start](#quick-start) · [CLI](#cli) ·
[Documentation](#documentation) · [License](#license)

## Features

### Core

Always available, with no external tools.

- **Native PKI.** Issue, revoke and renew certificates. The CA private key
  is encrypted at rest and its passphrase is never written to disk.
- **One binary.** The web UI is embedded; no separate frontend or reverse
  proxy.
- **Full CLI.** Every UI action is a CLI command with the same
  implementation. `-json` switches any command to machine-readable output.
  Completion for bash, zsh and fish.
- **Client export.** Ready-to-import `.ovpn` profiles, optionally
  key-encrypted, split- or full-tunnel, with per-client OpenVPN directives.
- **Statistics and audit log.** Per-client traffic history, a live
  `stats -follow` view and an audit trail of every administrative action.
- **Log management.** Rotation and retention for `openvpn.log`, `ovcp.log`
  and `dnsmasq.log` without restarting any process.
- **Access control.** Admin, operator and read-only roles, optional TOTP
  two-factor authentication, rate-limited logins and CSRF-protected
  HTTPS-only sessions.
- **Encrypted backup and restore.** One command produces one encrypted
  archive containing everything needed to rebuild the server on any host.
- **Least privilege.** OVCP never runs as root; it and its workers hold
  only the network capabilities they need.
- **Packaging.** systemd unit, `.deb`/`.rpm`/`.apk`/Arch/Void packages
  (amd64, ARM, RISC-V; glibc or musl), a multi-arch container image and an
  SELinux policy.

### Optional modules

Each module is enabled by a tool on `PATH` or by explicit configuration.
The core does not depend on any of them.

- **Internal DNS** (requires [`dnsmasq`](https://thekelleys.org.uk/dnsmasq/doc.html)).
  Resolves the server and every connected client by hostname over the
  tunnel, plus custom host entries, optionally without upstream
  forwarding.
- **Upstreams** (requires [`nftables`](https://wiki.nftables.org/)).
  Routes client traffic through a chosen egress instead of the host's
  default route: a local interface such as a second NIC or a WireGuard
  peer, or a SOCKS5 backend such as Tor. A server-wide default can be
  overridden per client, and a failed egress blocks traffic rather than
  leaking it through the default route.
- **Telegram bot** (requires a bot token). Notifications for revocations,
  user changes, CA rotation and certificate expiry, plus a
  Start/Stop/Restart/Reconnect menu restricted to one linked chat.

## Requirements

Linux with `/dev/net/tun` and [`openvpn`](https://openvpn.net/) on `PATH`.
[`dnsmasq`](https://thekelleys.org.uk/dnsmasq/doc.html) and
[`nftables`](https://wiki.nftables.org/) are optional and enable the
modules above. OVCP starts and supervises these processes itself and never
installs them. Build requirements are in [`docs/BUILD.md`](docs/BUILD.md).

## Install

- **Distro package**: `.deb`, `.rpm`, `.apk`, Arch or Void. Installs the
  binary, man page, shell completions, service file and the `ovcp` system
  account. `openvpn` is a dependency; `dnsmasq` and `nftables` are
  suggested.
- **Container image**: one image with OpenVPN included.
- **Binary**: `ovcp` on `PATH` plus the `ovcp` system account.

There is no tagged release yet; build from source as described in
[`docs/BUILD.md`](docs/BUILD.md).

## Quick start

```sh
sudo ovcp init -server-cn vpn.example.com   # CA, server certificate, server.conf, admin user
sudo ovcp serve                             # openvpn and the admin UI on https://127.0.0.1:8443
sudo ovcp certificate issue -cn alice -export -remote vpn.example.com > alice.ovpn
```

`init` is idempotent and only creates what is missing. In production, run
`sudo systemctl enable --now ovcp` instead of `serve`. Container, systemd
and SELinux deployments are described in `man ovcp`, **DEPLOYMENT**.

## CLI

`ovcp -h` lists every command; `man ovcp` documents every flag, environment
variable and file. Any command produces JSON with `-json`:

```sh
sudo ovcp -json certificate list | jq -r '.[] | select(.status == "expired") | .cn'
```

## Documentation

- **This README**: what OVCP is and the shortest path to a running server.
- **[`man ovcp`](docs/ovcp.8)**: the runtime reference: commands, flags,
  environment, files, privileges and deployment. The same page is rendered
  into the web UI's **Docs** tab. From a checkout: `make man`.
- **[`docs/BUILD.md`](docs/BUILD.md)**: building, cross-compiling, the
  container image, packages, running from a checkout and tests.
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**: internal design and
  the rationale for cross-cutting decisions.

## License

[MIT](LICENSE)
