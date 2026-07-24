# Architecture

Internal design of ovcp: how the source is organized, how the process is
composed at runtime, and the rationale behind decisions that affect more
than one package. Audience: contributors and reviewers working on the
codebase.

- Command and flag reference: `man ovcp` ([`docs/ovcp.8`](ovcp.8)).
- Build and packaging: [`docs/BUILD.md`](BUILD.md).

## Source layout

| Path | Responsibility |
|---|---|
| `cmd/ovcp` | CLI entrypoint: flag parsing, command dispatch, and the `serve` composition root. |
| `internal/pki` | Certificate authority: issue, revoke, renew, CRL generation, `.ovpn` bundle assembly, tls-crypt key generation. |
| `internal/store` | SQLite persistence for users, sessions, certificate metadata, audit log, and connection stats. Never stores private keys. |
| `internal/backup` | Encrypted export/import of the CA, CRL, tls-crypt key, TOTP key, server config, and database. |
| `internal/controller` | OpenVPN process supervision (fork/exec, reap, restart backoff), the control-socket server, and the management-socket client used to query and drive a running OpenVPN process. |
| `internal/ovpnconf` | Validated `server.conf` generation from stored configuration. |
| `internal/auth` | Password hashing (argon2id), sessions, TOTP, login rate-limiting, RBAC. |
| `internal/telegram` | Optional notification bot: long-poller, narrow command surface, expiry sweep. |
| `internal/api` | REST/JSON handlers, the embedded web UI, HTTPS, CSRF, and the session/RBAC middleware chain. |
| `web/ui` | Svelte 5 sources for the admin UI, built to `web/dist` and embedded in the binary. |
| `web` | `go:embed`s the built `web/dist` tree and exposes it as an `fs.FS` to `internal/api`. |

## Process model

`ovcp` is a single binary that plays three roles depending on the command
invoked: a CLI that runs one operation and exits, an HTTPS server (`serve`)
that hosts the REST API and embedded UI, and a supervisor for one OpenVPN
process. `serve` composes all of it in one process: it starts the OpenVPN
worker through `internal/controller`, and wires the HTTP handlers in
`internal/api` to `internal/pki`, `internal/store`, `internal/auth`,
`internal/backup`, and `internal/telegram`.

There is no separate daemon, message broker, or database server. The
`ovcp.db` SQLite file and the PKI directory are the only persistent state,
and both are read and written in-process.

### Two sockets, two protocols

A running `serve` process exposes two Unix sockets, each serving a
different purpose:

- The **management socket** (`OVCP_MGMT_SOCK`) speaks OpenVPN's own
  management protocol. OpenVPN's management interface accepts exactly one
  connected client for its entire lifetime; `serve` holds that connection
  for as long as the OpenVPN worker runs.
- The **control socket** (`OVCP_CTRL_SOCK`) is ovcp's own protocol,
  root-only, used by a separate `ovcp` invocation (`vpn`, `dns`,
  `telegram`, `debug`, `stats -follow`) to reach a running `serve`. Only
  `vpn`'s `status`/`kill`/`reconnect` and `stats -follow` actually proxy
  through to the management-socket connection above. Everything else
  answers from in-process state instead: `vpn`/`dns start|stop|restart`
  and `telegram start|stop|restart|status` drive their own `Supervisor`/
  `Poller` (see Supervisor design, below); `debug on`/`off` flips an
  in-process log-level variable. Nothing dials the management socket
  except `serve` itself. `dns block-internet` is not a control-socket op
  at all — it reads/writes a stored setting directly and works without
  `serve` running.

Exact defaults, flags, and environment variables for both sockets are
documented in `man ovcp`, `ENVIRONMENT`.

## Supervisor design

OpenVPN runs as a foreground child of `serve` (`fork`/`exec`, reaped on
exit, tied to the parent's lifetime via `Pdeathsig`) rather than as an
independently managed system service. This keeps process ownership
unambiguous: if `serve` restarts, it brings OpenVPN back up; if `serve`
exits, OpenVPN cannot outlive it.

An exit `ovcp` did not itself request is logged and the worker is
auto-restarted after a fixed delay. A configuration bad enough to make
OpenVPN exit repeatedly trips a breaker after 5 attempts within 60 seconds,
so a persistent misconfiguration produces one error instead of a restart
loop.

Reload is restart-only; in-place reload via `SIGHUP` is not supported. A
fresh restart re-reads every root-owned file (certificates, CRL,
`server.conf`); `SIGHUP` cannot guarantee the same. `SIGUSR1` remains
available for a soft session reset that does not replace the process.
Command-level behavior for `vpn start|stop|restart|reconnect|status` is
documented in `man ovcp`, `COMMANDS`.

`Supervisor`'s lifecycle methods (`Start`/`Stop`/`Restart`/`Reconnect`)
`TryLock` a single per-worker mutex instead of blocking on it: a call that
overlaps one already in flight is rejected (`ErrBusy`, surfaced as HTTP 409)
rather than queued behind it. Queuing would still be memory-safe — the
mutex was already held for each op's whole real duration — but it would
let a rapid-fire caller (a stuck client retrying, a scripted loop) stack up
a run of genuinely executed restarts, one after another, each disrupting
the service again. There is deliberately no cooldown timer on top of this:
the mutex is already held for exactly as long as the real stop+start cycle
takes, so pacing falls out of the worker's own actual speed instead of a
guessed constant. `internal/telegram`'s `Poller` mirrors the identical
`TryLock`/reject pattern for its own `Start`/`Stop`/`Restart`, independent
of `Supervisor` (different type, same shape) since its lifecycle is driven
through the same control socket.

dnsmasq (Records tab, optional — only if found on `PATH`) is a second
worker under the same `Supervisor`/`Lifecycle` type, reachable over the
same control socket via a `dns-` op prefix; no `reconnect`. Its `Args` are
recomputed fresh on every (re)start (`Supervisor.PreStart`) from the
persisted server config's subnet, not baked in once, so a subnet change
or OpenVPN restart never leaves it listening on a stale address
(`--bind-dynamic` also tolerates the address not existing yet).

## Privilege model

`ovcp` runs as a single root-owned process; the admin UI, the REST API, and
PKI operations all execute in the same process and the same privilege
level. A privilege-separated design — a root supervisor process plus a
non-root HTTP worker communicating over IPC — was evaluated and not
adopted.

The reasoning: reaching the admin UI at all already requires defeating the
VPN's own authentication, CSRF protection, RBAC, and optional TOTP. A
second process and an IPC protocol would add implementation and audit
surface without changing the effective trust boundary, since compromising
the HTTP worker still yields the same PKI and configuration access an
attacker would need to target the root process directly. Process
containment is instead delegated to the OS: the shipped systemd unit
sandboxes the whole process (`ProtectSystem=strict`, `NoNewPrivileges`,
`MemoryDenyWriteExecute`, and more — see `deploy/systemd/ovcp.service`).

File modes, capability requirements, and container privilege flags are
documented in `man ovcp`, `PRIVILEGES`.

`$OVCP_DATA`'s own directory tree (the root, `pki/`, `logs/`, `dns/`) has
exactly one owner: `cmd/ovcp`'s `ensureSkeleton`. `internal/store`,
`internal/pki`, and `internal/controller` no longer create or `chmod` their
own directories — they trust the tree already exists, because every
stateful entry point (`cliContext.openStore`, `runServe`) calls
`ensureSkeleton` first. It's idempotent and cheap, so it runs on every
invocation rather than once at install time; `ovcp init -skeleton` exposes
it directly, for packaging scripts and as a permissions-repair command.

## Data boundaries

Three storage locations, three different exposure levels:

- **`internal/store` (SQLite)** — operational metadata only: users,
  sessions, certificate records, audit log, connection stats. No private
  key material is ever written here.
- **PKI directory (filesystem)** — the CA private key (encrypted,
  argon2id + AES-256-GCM) and the server keypair. The CA passphrase exists
  only in process memory for the duration of a signing operation and is
  never persisted.
- **Client private keys** — generated, embedded once into the exported
  `.ovpn` profile, and discarded. There is no server-side escrow; a lost
  profile is a revoke-and-reissue, not a recovery.

Authoritative file paths and their contents are documented in `man ovcp`,
`FILES`; the security properties of each are documented in `man ovcp`,
`SECURITY`.
