# Architecture

Internal design of ovcp: source layout, runtime composition, and the
rationale for decisions that span more than one package. Audience:
contributors and reviewers.

- Commands, flags, environment, files, privileges: `man ovcp`
  ([`docs/ovcp.8`](ovcp.8)).
- Building and packaging: [`docs/BUILD.md`](BUILD.md).

## Source layout

| Path | Responsibility |
|---|---|
| `cmd/ovcp` | CLI entrypoint: flag parsing, command dispatch, privilege drop, and the `serve` composition root. |
| `internal/pki` | Certificate authority: issue, revoke, renew, CRL generation, `.ovpn` bundle assembly, tls-crypt key generation. |
| `internal/store` | SQLite persistence for users, sessions, certificate metadata, audit log and connection statistics. Never stores private keys. |
| `internal/backup` | Encrypted export and import of the CA, CRL, tls-crypt key, TOTP key, server configuration and database. |
| `internal/controller` | Worker supervision (fork/exec, reap, restart backoff), the control-socket server, and the OpenVPN management-socket client. |
| `internal/ovpnconf` | Validated `server.conf` generation from stored configuration. |
| `internal/upstream` | Policy-routed egress: routing-table and nftables rules that steer client traffic out a chosen interface or into an in-process SOCKS5 relay. Per-client overrides are installed on OpenVPN's `>CLIENT:ESTABLISHED` management event (`internal/controller/mgmt.go`). |
| `internal/auth` | Password hashing (argon2id), sessions, TOTP, login rate limiting, RBAC. |
| `internal/telegram` | Optional notification bot: long-poller, command menu, expiry sweep. |
| `internal/api` | The mutation core the CLI and the handlers share (see CLI and web API), the web API handlers, the embedded web UI, HTTPS, CSRF, and the session and RBAC middleware. |
| `web/ui` | Svelte 5 sources for the admin UI, built to `web/dist`. |
| `web` | Embeds `web/dist` and exposes it to `internal/api` as an `fs.FS`. |

## Process model

`ovcp` is one binary with three roles: a CLI that performs one operation
and exits, an HTTPS server (`serve`) hosting the web API and the UI, and a
supervisor for the OpenVPN and dnsmasq workers. `serve` composes all three
in one process: it starts the workers through `internal/controller` and
wires the handlers in `internal/api` to `internal/pki`, `internal/store`,
`internal/auth`, `internal/backup` and `internal/telegram`.

There is no separate daemon, broker or database server. `ovcp.db` and the
PKI directory are the only persistent state, both accessed in-process.

### Sockets

A running `serve` uses two Unix sockets:

- The **management socket** (`OVCP_MGMT_SOCK`) speaks OpenVPN's management
  protocol. OpenVPN accepts one management client for its lifetime; `serve`
  holds that connection while the worker runs, and nothing else dials it.
- The **control socket** (`OVCP_CTRL_SOCK`, owner-only) carries ovcp's own
  protocol from separate `ovcp` invocations (`vpn`, `dns`, `telegram`,
  `debug`, `upstream`, `status`, `stats -follow`) to `serve`. `kill` and
  the connected-client list are proxied to the management connection.
  Every other operation is answered in-process: `vpn`/`dns`
  `start|stop|restart|status` drive their `Supervisor`, `vpn reconnect`
  sends `SIGUSR1` to the OpenVPN child, `telegram` drives the `Poller`,
  `debug` sets the log level, `upstream-assign` rewrites one connected
  client's nftables rule (the CLI and web API share `api.ApplyAssign`),
  and `upstream-reapply` re-applies the persisted upstream configuration.

### CLI and web API

Every mutation has one implementation, in `internal/api` or the package
that owns the data (`store`, `pki`, `upstream`, `ovpnconf`), and that
implementation enforces every rule: validation, ordering, what may change.
The CLI command and the HTTP handler are adapters over it. They parse input,
fill defaults, reach a running openvpn over their own transport (the
control socket, or the management connection `serve` holds), render the
result and name the audit actor. A rule enforced in only one adapter is a
bug, because the other path skips it. Routes, roles and CLI twins:
`man ovcp`, **WEB API**.

`dns block-internet` is a stored setting, not a control-socket operation,
and works without `serve`. Socket defaults and flags: `man ovcp`,
**ENVIRONMENT**.

## Supervisor

Workers run as foreground children of `serve` (fork/exec, reaped on exit,
bound to the parent by `Pdeathsig`). If `serve` restarts it brings them
back; if it exits they cannot outlive it.

An exit ovcp did not request is logged and the worker is restarted; a
crash loop trips a breaker, so a persistent misconfiguration yields one
error instead of endless restarts (thresholds: `man ovcp`, `serve`).

Reload is restart-only. A restart re-reads every file (certificates, CRL,
`server.conf`), which `SIGHUP` cannot guarantee. `SIGUSR1` remains
available as a soft session reset. Command semantics: `man ovcp`,
**COMMANDS**.

Lifecycle methods (`Start`, `Stop`, `Restart`, `Reconnect`) take a
per-worker mutex with `TryLock`. A call that overlaps one in flight fails
with `ErrBusy` (HTTP 409) instead of queueing, so repeated callers cannot
stack a series of disruptive restarts. The mutex is held for the real
duration of each operation, which paces callers without a cooldown timer.
`internal/telegram`'s `Poller` applies the same pattern to its own
lifecycle.

dnsmasq is a second worker of the same `Supervisor` type, addressed on the
control socket with a `dns-` prefix and without `reconnect`. Its arguments
are recomputed on every start (`Supervisor.PreStart`) from the persisted
subnet, and `--bind-dynamic` tolerates the listen address not existing
yet, so it never listens on a stale address.

`internal/upstream` identifies VPN traffic by the tunnel interface it
arrives on (`ovpnconf.TunDev`), never by a source address another host
could forge. A successful `vpn start` or `restart` re-applies the upstream
rules, as `upstream reconcile` does, and with per-client routing
reattaches the management connection openvpn holds new clients for;
`stop` and `reconnect` do neither.

Outbound NAT for the tunnel belongs to ovcp's own nft table (a catch-all
`masquerade` for unmarked `ovcp0` traffic), so it is reconciled and purged
with everything else. IPv4 forwarding stays the operator's.
`RoutingPrereqsWarning` (`internal/controller`) reports what ovcp does not
provide: forwarding, and NAT only when the upstream feature (nft) is off.
What is checked and reported: `man ovcp`, **NETWORKING**.

## Privilege model

ovcp runs as one process at one privilege level, and that level is not
root. `dropRoot` (`cmd/ovcp`) enforces two invariants on every
invocation:

- **No root process survives.** A root invocation switches to `OVCP_USER`
  in place: setuid, keep `dropCaps` as ambient capabilities, then exec
  itself under the same pid. The workers inherit exactly that set, so no
  configuration, including `server.conf`'s `Extra` directives, can raise a
  worker above the privileges the admin UI already has. The systemd unit
  applies the same drop natively (`User=`, `AmbientCapabilities=`).
- **Ownership is set only at creation.** ovcp chowns a directory only when
  it has just created it, and does so through file descriptors (`mkdirat`,
  `openat` with `O_NOFOLLOW`, `fchown`). It never changes the owner of an
  existing path, so no link or path substitution can redirect a chown
  performed as root. The layout of pre-existing directories belongs to the
  installer.

A root supervisor with a non-root web worker was rejected: the worker
would still need to rewrite routing and `server.conf`, so the IPC between
them would carry root-equivalent operations while adding a protocol to
secure. Containment beyond the drop is delegated to the OS; the systemd
unit sandboxes the whole process tree (`deploy/systemd/ovcp.service`).

The operational details (account, capabilities, modes, container flags)
are specified in `man ovcp`, **PRIVILEGES**.

`$OVCP_DATA`'s tree (the root, `pki/`, `logs/`, `dns/`) is created and its
modes repaired only by `ensureSkeleton` (`cmd/ovcp`); when started as root,
`dropRoot` creates the root directory first so it can set its owner.
`internal/store`, `internal/pki` and `internal/controller` assume the tree
exists, because every stateful command reaches it through
`cliContext.openStore`, which calls `ensureSkeleton` first. It is
idempotent and runs on every invocation; `ovcp init -skeleton` runs it
alone, for packaging and permission repair.

## Data boundaries

- **`internal/store` (SQLite)**: operational metadata only: users,
  sessions, certificate records, audit log, statistics. No private key
  material.
- **PKI directory**: the CA private key (argon2id + AES-256-GCM) and the
  server keypair. The CA passphrase exists only in memory during a signing
  operation.
- **Client private keys**: generated, embedded once into the exported
  `.ovpn`, and discarded. There is no escrow; a lost profile is revoked and
  reissued.

File paths and contents: `man ovcp`, **FILES**. Security properties:
`man ovcp`, **SECURITY**.
