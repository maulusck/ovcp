# OVCP — OpenVPN Control Plane

Self-hosted management for one OpenVPN server: web UI, native PKI (no
easy-rsa), client `.ovpn` export, audit log. One static Go binary with the
Svelte UI embedded. OpenVPN itself is an external dependency, controlled
only via its management unix socket.

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

**ovcp runs as root.** It is the sole owner of the PKI and config
(`0600 root:root`), so those files are secure by default — no drop, no chown
dance, no per-mode privilege juggling. ovcp starts openvpn itself as a
foreground worker (reaped the instant it exits, so no zombies even when
ovcp is PID 1 in a container); openvpn drops to `nobody` on its own after
startup. (A
future unprivileged IPC worker will be a *separate* process, not a privilege
drop inside ovcp.)

The openvpn management socket and ovcp's control socket live in `/run/ovcp`
(`0750`, the control socket itself `0600`); directory permissions are the
only guard needed.

**Interfaces:** `OVCP_LISTEN` (or `-listen`) takes a comma-separated list.
Every listener is the same HTTPS+auth+CSRF stack. Binding the VPN-side
address works even before tun0 exists (`IP_FREEBIND`), so this is all it
takes to reach the UI from connected clients:

```sh
OVCP_LISTEN=127.0.0.1:8443,10.8.0.1:8443   # host + inside the VPN
```

## Deployment

One runtime, everywhere: ovcp runs as root and owns the openvpn worker
(fork/exec + signals — no SIGHUP, no in-place reload). openvpn is a plain
foreground child: a goroutine sits in `wait()` and reaps it on exit, so no
zombies accumulate across restarts, and `Pdeathsig` ties its lifetime to
ovcp's — it can never outlive the controller. If ovcp is restarted, its
`serve` process brings openvpn back up.

Lifecycle is driven the same way from the UI and the CLI:
`ovcp vpn start|stop|restart|reconnect`. The CLI reaches the running `serve`
over a root-only unix control socket (serve owns the process; the CLI is just
a remote for it). Restart is a full stop + fresh start (required for any
config, key, or CRL change); reconnect is a soft `SIGUSR1` session reset.

### systemd
A single unit runs ovcp as root; ovcp starts and stops openvpn itself.
```sh
make release && sudo make install
sudo install -m644 deploy/systemd/ovcp.service /usr/lib/systemd/system/
sudo OVCP_DATA=/var/lib/ovcp ovcp init -server-cn vpn.example.com
sudo systemctl enable --now ovcp
```

### container
One all-in-one image (`make image`): ovcp (as root) owns the PKI and starts
openvpn inside the container. Init once, then run:
```sh
podman run --rm -v ovcp:/var/lib/ovcp ovcp init -server-cn vpn.example.com
podman run -d --cap-add=NET_ADMIN --device /dev/net/tun \
  -p 1194:1194/udp -p 127.0.0.1:8443:8443 -v ovcp:/var/lib/ovcp ovcp
```
Image defaults `OVCP_CA_PASSPHRASE`/`OVCP_USER_PASSWORD` to `changeme` for
the one-shot init — override with `-e`. To split the UI and the VPN across
network interfaces, bind each published port to the right address:
```sh
-p 203.0.113.7:1194:1194/udp -p 192.168.1.10:8443:8443
```
(docker works the same; the Containerfile is plain OCI.)

### SELinux (RHEL/Fedora)
Confined openvpn can't read the non-standard data dir without labels — run
`sudo deploy/selinux.sh` once (respects `OVCP_DATA`). ovcp itself needs no policy.

### packages
`nfpm package -f deploy/nfpm.yaml -p deb` (or `-p rpm`) after `make release`.

## Backup & restore

```sh
bin/ovcp backup create              # prompts for a backup passphrase (twice)
# → ovcp-backup-<timestamp>.ovcpbak, an encrypted archive: CA, CRL, tls-crypt
#   key, server.conf, database. Unreadable without the passphrase — write it
#   down, it's never stored anywhere and can't be recovered.

bin/ovcp -data /var/lib/ovcp backup restore ovcp-backup-<timestamp>.ovcpbak
OVCP_SERVER_CN=vpn.example.com bin/ovcp renew-server   # issue a fresh server cert
bin/ovcp vpn start
```

Deliberately excludes the openvpn server certificate and private key: clients
trust the CA chain and a CN match, never a pinned server cert, so restore
just issues a fresh one from the restored CA instead of ever letting the
server's private key leave the machine. Client private keys were never
stored here either (no escrow) — nothing lost for existing clients across a
restore.

`backup create` is also in the web UI (Settings, admin role). `backup
restore` is CLI-only by design: it's an offline, disaster-recovery operation
against a data directory, not something to expose over HTTP on a possibly-
live server. Refuses to touch an already-initialized data directory unless
you pass `-force`.

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
