# OVCP — OpenVPN Control Plane

Self-hosted management for one OpenVPN server: web UI, native PKI (no
easy-rsa), client `.ovpn` export, audit log. One static Go binary with the
Svelte UI embedded. OpenVPN itself is an external dependency, controlled
only via its management unix socket.

## Quick start (standalone / dev)

```sh
make release              # builds UI + bin/ovcp
export OVCP_DATA=$PWD/data

# one-shot setup: CA, server cert, tls-crypt key, server.conf, admin user
bin/ovcp init -server-cn vpn.example.com
# → prompts for a new CA passphrase (needed for every issue/revoke)
# → prompts for the admin user's password

bin/ovcp serve
# → spawns openvpn from data/server.conf (standalone mode)
# → admin UI: https://127.0.0.1:8443  (self-signed cert)

bin/ovcp export -cn alice -remote vpn.example.com > alice.ovpn
```

If `serve` says `not initialized, missing: ...` — run `ovcp init` first;
it is idempotent and fills in whatever is missing.

Full reference: `make man` (or `man ovcp` once installed).

## Security model (tier 2 CA)

- CA key encrypted at rest (argon2id + AES-256-GCM); **every** sign/revoke
  requires the operator passphrase; it is never persisted.
- Client private keys are embedded in the exported profile once and never
  stored server-side (no escrow): lost profile = revoke + reissue.
  Certificates (public) are stored and downloadable anytime. Optionally
  protect the profile's key with a password (`-key-pass` / UI field);
  OpenVPN prompts for it on connect.
- Management socket is unix-only. Admin UI is HTTPS-only, loopback by
  default, with sessions, CSRF, RBAC (admin/operator/readonly), optional
  TOTP 2FA, login rate-limiting, and a full audit log.

## Privileges & exposure

**ovcp never runs elevated.** openvpn needs root (or CAP_NET_ADMIN) only to
start — it drops to `nobody` by itself. Who provides that start-up privilege
depends on how you run it:

| Mode | openvpn privileges | ovcp runs as |
|---|---|---|
| systemd | its own unit, as root, self-drops | `ovcp` system user (created by the package) |
| container | container root + `--cap-add NET_ADMIN` (the container is the sandbox) | root in the container |
| standalone (dev) | inherited from your `sudo` | drops after spawn: `$OVCP_USER` > `ovcp` user > sudo caller (nginx model) |

The management socket lives in `/run/ovcp`, root:ovcp `0750` under systemd —
directory permissions are the only guard needed.

**Interfaces:** `OVCP_LISTEN` (or `-listen`) takes a comma-separated list.
Every listener is the same HTTPS+auth+CSRF stack. Binding the VPN-side
address works even before tun0 exists (`IP_FREEBIND`), so this is all it
takes to reach the UI from connected clients:

```sh
OVCP_LISTEN=127.0.0.1:8443,10.8.0.1:8443   # host + inside the VPN
```

## Signing in with 2FA

Enroll from the CLI: `ovcp user totp -name alice` prints a QR code to scan
(plus the secret for manual entry); `-off` disables it. Login is two steps
in one form: submit username + password, and if the account has 2FA the
code field appears — resubmit with the current 6-digit code. Codes rotate
every 30 s (one step of clock skew is tolerated; check the server clock if
codes never work). Five failed attempts per user+IP lock login for 15
minutes.

## Deployment

Supervision belongs to the platform; ovcp auto-detects it (override with
`OVCP_PLATFORM`). openvpn and ovcp fail independently; the VPN stays up if
the panel dies.

### systemd
```sh
make release && sudo make install
sudo install -m644 deploy/systemd/*.service /usr/lib/systemd/system/
sudo OVCP_DATA=/var/lib/ovcp ovcp init -server-cn vpn.example.com
sudo systemctl enable --now openvpn-ovcp ovcp
```

### docker compose (one image, two roles)
```sh
docker compose -f deploy/compose.yaml build
docker compose -f deploy/compose.yaml run --rm -it app init -server-cn vpn.example.com
docker compose -f deploy/compose.yaml up -d
```

### kubernetes (1.29+)
Two containers in one pod (same image, ovcp as native sidecar), shared
volume for socket + config: `make image`, push, `kubectl apply -f
deploy/k8s/ovcp.yaml`, run `init` in the app container once.

### SELinux (RHEL/Fedora)
Confined openvpn can't read the non-standard data dir without labels — run
`sudo deploy/selinux.sh` once (respects `OVCP_DATA`). ovcp itself needs no policy.

### packages
`nfpm package -f deploy/nfpm.yaml -p deb` (or `-p rpm`) after `make release`.

## Layout

```
cmd/ovcp             CLI + serve entrypoint
internal/pki         CA, issue/revoke, CRL, .ovpn bundles, tls-crypt
internal/store       SQLite (metadata only — never private keys)
internal/controller  mgmt-socket client, Reloader (platform-specific)
internal/ovpnconf    validated server.conf generation
internal/auth        argon2id, sessions, TOTP, rate-limit, RBAC
internal/api         REST/JSON + embedded UI, HTTPS, CSRF
web/ui               Svelte 5 sources → web/dist (embedded)
deploy/              systemd, docker, compose, k8s, nfpm
docs/ovcp.8          man page
```

## Development

```sh
make help
go test ./...
cd web/ui && npm run dev   # UI dev server (proxy API manually or run serve)
```
