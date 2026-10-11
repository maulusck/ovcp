# Building OVCP

Building the `ovcp` binary, distro packages, and the container image —
natively on any supported host, or cross-compiled from any other.

This document covers building and packaging only. Runtime commands,
configuration, and deployment are documented in `man ovcp`
([`docs/ovcp.8`](ovcp.8)); internal design in
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md).

`make help` lists every target and variable; this document explains what
they do and why.

## Requirements

`make deps` checks the base build requirements are on `PATH` and reports
what is missing:

- Go 1.22+
- a C compiler (`cc` or `gcc` — CGO, for the SQLite driver)
- npm (`web/ui`, the Svelte admin UI)
- mandoc (renders `docs/ovcp.8` into the UI's Docs tab)

Additional tools are required only for specific targets, and are checked
individually when that target runs — not by `make deps`:

- [zig](https://ziglang.org/) — cross-compiling (`TARGET=` set to anything
  other than `host`); checked by `build` and packaging targets via
  `check-cross`
- [nfpm](https://nfpm.goreleaser.com/) — `.deb`/`.rpm`/`.apk`/Arch
  packages; checked by `deb`/`rpm`/`apk`/`archlinux` via `check-nfpm`
- podman or docker — the container image; checked by `image` via
  `check-image`

## Build targets

Every build, packaging, and image target reads the `TARGET` variable
(default `host`).

- **`TARGET=host`** — a native build using the host's own `cc`/`gcc` and
  `go build`. No cross toolchain is required beyond the base requirements
  above.
- **Any other `TARGET`** — cross-compiles via
  [zig cc](https://ziglang.org/), which bundles clang and a libc/
  compiler-rt sysroot for each target below. One toolchain covers every
  supported architecture and libc combination. This is genuine
  cross-compilation, not emulation — QEMU is not involved for `build` or
  packaging targets; it is required only for cross-architecture container
  **images** (see Container image, below).

| TARGET | GOARCH | GOARM | libc | zig triple | nfpm arch |
|---|---|---|---|---|---|
| `arm64` | arm64 | — | glibc | `aarch64-linux-gnu` | `arm64` |
| `arm64-musl` | arm64 | — | musl | `aarch64-linux-musl` | `arm64` |
| `armv7` | arm | 7 | glibc | `arm-linux-gnueabihf` | `arm7` |
| `armv7-musl` | arm | 7 | musl | `arm-linux-musleabihf` | `arm7` |
| `armv6` | arm | 6 | glibc | `arm-linux-gnueabihf` | `arm6` |
| `armv6-musl` | arm | 6 | musl | `arm-linux-musleabihf` | `arm6` |
| `amd64` | amd64 | — | glibc | `x86_64-linux-gnu` | `amd64` |
| `amd64-musl` | amd64 | — | musl | `x86_64-linux-musl` | `amd64` |
| `riscv64` | riscv64 | — | glibc | `riscv64-linux-gnu` | `riscv64` |
| `riscv64-musl` | riscv64 | — | musl | `riscv64-linux-musl` | `riscv64` |

`TARGET=host` on an amd64 machine and `TARGET=amd64` produce the same
architecture but are not equivalent: `TARGET=host` never invokes zig;
`TARGET=amd64` always does. There is no auto-detection that routes a
matching `TARGET` through the native path — `host` is native, every other
value is cross-compiled, without exception.

```sh
make build                  # native, whatever this host is
make build TARGET=arm64     # cross, glibc arm64
```

`make help`'s `TARGET` line is generated from this table (`CROSS_TARGETS`
in the Makefile) and stays in sync with it automatically.

### Install

Install a native build directly, without packaging it — binary, man page,
and shell completions, `DESTDIR`/`prefix` honored (GNU Coding Standards):

```sh
sudo make install
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ovcp   # the account ovcp runs as; packages create it
```

This does not install the systemd unit or the SELinux policy; a distro
package includes the unit (see Packages, below), and a from-source
deployment adds it manually — see `man ovcp`, `DEPLOYMENT`.

## Container image

```sh
make image                    # this host's own arch
make image TARGET=arm64       # cross-build a specific arch
```

The image is Alpine-based (musl) regardless of which `TARGET` row is used
— `arm64` and `arm64-musl` produce an identical image, since the
Containerfile's build stage selects musl unconditionally. Both names are
accepted.

### Native vs. cross, and what `--platform` does

`make image` always passes an explicit `--platform`, derived from the same
`GOARCH`/`GOARM` as `build` and packaging (`TARGET=host` resolves to the
host's actual architecture via `go env GOARCH`).

Podman and Docker can auto-detect the target platform from the host when
`--platform` is omitted, but that auto-detection is version-dependent: on
an engine that does not implement it, `podman build`/`docker build` fails
on the first `FROM` line with `no value specified for --platform=`, before
any Containerfile logic runs. Passing `--platform` explicitly removes that
dependency; it is a long-standing, universally supported flag on both
tools.

### Cross-building an image needs QEMU/binfmt

The Containerfile's builder stage (`FROM --platform=$BUILDPLATFORM ...`) is
pinned to the build machine's own architecture: Go and npm never run
emulated, since zig cross-compiles the binary directly. The final stage
(`FROM alpine:latest`, `apk add openvpn`) is not pinned the same way — for
a genuine cross build it must run as the target architecture, because
`apk` itself has to execute. Without binfmt handlers registered for that
architecture, this step fails with `exec container process: Exec format
error`.

`make image TARGET=<cross-arch>` preflights this condition before starting
the build (`check-image`): it runs a trivial container for the target
platform and fails immediately, with the cause and the fix, if that does
not succeed:

```
error: this host can't run linux/arm64 containers (no working QEMU/binfmt for it) - see docs/BUILD.md, 'Cross-building an image needs QEMU/binfmt'
```

This is inherent to any cross-architecture image build whose final stage
performs real package-manager work. CI does not encounter it:
`docker/setup-qemu-action` registers emulation against a real root
`dockerd`. On a workstation, there are two independent causes; check in
order.

**1. Nothing registered.**

```sh
ls /proc/sys/fs/binfmt_misc/ | grep qemu   # empty = nothing registered
```

Fix (same command regardless of distro or engine; requires real root):

```sh
sudo docker run --privileged --rm docker.io/tonistiigi/binfmt --install all
```

Podman or Homebrew installations outside `sudo`'s restricted `PATH`
(`could not find a working conmon binary`) require the `PATH` to be
preserved explicitly:

```sh
sudo env PATH="$PATH" $(which podman) run --privileged --rm docker.io/tonistiigi/binfmt --install all
```

**2. Registered, but this engine still can't use it.**

Some distributions (Debian/Ubuntu's `qemu-user-binfmt`) register a wrapper
that re-execs the real interpreter dynamically instead of shipping a
static binary. The kernel's `F` flag caches only the wrapper's own file
descriptor; if the wrapper's further exec cannot resolve inside the target
container's near-empty root filesystem, the step still fails.
`tonistiigi/binfmt` avoids this with statically linked interpreters, which
is why the fix above uses it in preference to a distro package.

Rootless Podman or Docker can separately fail to use an emulator that is
correctly registered and statically linked; this is an unprivileged
user-namespace limitation, not specific to this project. Confirm the
registration first (`cat /proc/sys/fs/binfmt_misc/qemu-aarch64`; `flags:`
should include `F`). If it still fails under a normal user account, retry
as root:

```sh
sudo env PATH="$PATH" make image TARGET=arm64
```

(`sudo make ...` alone is not sufficient: Make resolves `$(CTR)` using
root's own `PATH`, which hits the same problem one layer up.)

Neither fix persists across a reboot: `/proc/sys/fs/binfmt_misc` is kernel
memory only and is rebuilt from installed packages on every boot. If a
distro package's boot hook re-registers its wrapper afterward, cause 2 can
recur and the fix must be re-applied.

### Unrecognized TARGET values

`build` and `image` share a `check-target` prerequisite: an unrecognized
`TARGET` is rejected immediately (`unknown TARGET=foo (see: make help)`)
rather than falling back to the host architecture. `check-cross` (used by
`build` and packaging only) additionally requires `zig` on the host
`PATH`; `image` does not have this requirement, since zig runs inside the
builder container rather than on the machine invoking `podman build`.

### The persistent build cache

The Containerfile's final `RUN` step (`zig cc` / `go build`) uses a
BuildKit/buildah cache mount:

```
RUN --mount=type=cache,id=ovcp-build-cache,target=/root/.cache ...
```

Without this mount, every image build recompiles from a cold cache: zig
rebuilds its target's libc/compiler-rt objects from scratch, and
`go build` has no prior object cache, because `~/.cache` lives inside the
ephemeral build container and is not preserved between `podman build`
invocations. The source `COPY` lines earlier in the same stage make this
step re-run on any source change, so the cold-cache cost is paid
repeatedly without the mount.

The mount persists the cache in the container engine's own build-cache
store — outside the checkout, shared across builds on the same host,
independent of Docker's normal layer cache. Measured on this project:
~6.5 minutes cold, ~2 minutes warm, for the same build. `make image`
reports that the cache is in use; `make clean` reports that the cache is
untouched (it removes only files this project writes into the checkout:
`bin/`, `web/dist/`, `dist/`). Reclaim the cache explicitly:

```sh
podman builder prune    # or: docker builder prune
```

## Packages

```sh
make deb                # native host arch
make deb TARGET=arm64   # cross-compile the binary first, then package it (glibc: Debian/Fedora/Arch bases)
make apk                # Alpine/OpenWrt are musl-only; apk forces TARGET to <hostarch>-musl on its own
make apk TARGET=riscv64-musl # cross-build for a different musl arch instead
```

`apk` always builds a musl binary, even bare with no `TARGET` at all and even
alongside other formats in one call (`make deb rpm apk`) — Alpine/OpenWrt
never get a glibc binary just because `TARGET` defaulted to `host` for the
others. An explicit `TARGET` is still honored as given, musl or not (with a
warning if it isn't musl).

`nfpm` builds `.deb`, `.rpm`, `.apk`, and Arch packages from a single
manifest ([`deploy/nfpm.yaml`](../deploy/nfpm.yaml)): the binary, man page,
shell completions, and `LICENSE` at their standard paths, plus a service
file — the systemd unit for `.deb`/`.rpm`/Arch, an OpenRC init script
([`deploy/openrc/ovcp.initd`](../deploy/openrc/ovcp.initd)) for `.apk`,
since Alpine has no systemd. On OpenWrt (also an `.apk` consumer),
[`deploy/postinstall.sh`](../deploy/postinstall.sh) replaces the OpenRC
script with [`deploy/openwrt/ovcp.init`](../deploy/openwrt/ovcp.init) (a
procd script), detected via the presence of `/etc/rc.common`. Neither init
script replicates the systemd unit's sandboxing (see
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md), Privilege model) — OpenRC and
procd have no short equivalent to `ProtectSystem`/`NoNewPrivileges`.

`ARCH` (the `nfpm.yaml` `arch:` field) is derived from the `TARGET` table
above; for `TARGET=host` it falls back to `go env GOARCH`, so a package
built natively on an arm64 host is labeled `arm64`, not a hardcoded
default.

The manifest declares `openvpn` as a hard package dependency (`.deb`/
`.rpm` pull it in automatically) and `dnsmasq`/`nftables` as suggested,
not required — both are optional at runtime (internal DNS, policy-routed
egress; see `man ovcp`, `REQUIREMENTS`), so the package manager offers
them without forcing the install. `apk`/Arch packages have no `Suggests:`
equivalent and drop the field entirely; install those two manually if you
want the features they gate.

Install a built package:

```sh
sudo apt install ./dist/ovcp_*.deb              # Debian/Ubuntu
sudo rpm -i dist/ovcp-*.rpm                      # Fedora/RHEL
sudo apk add --allow-untrusted dist/ovcp-*.apk   # Alpine/OpenWrt
```

### Void Linux

Void Linux packages (xbps) are built from a template contributed to
[void-packages](https://github.com/void-linux/void-packages), not shipped
by this repository — that is how Void distributes packages generally.
[`deploy/void/template`](../deploy/void/template) and
[`deploy/void/files/ovcp/run`](../deploy/void/files/ovcp/run) (a runit
service) are the starting point. `make install DESTDIR="$DESTDIR"
prefix=/usr`, invoked via `build_style=gnu-makefile`, is what the
template's `do_install` hook uses. Any packaging system that calls plain
`make install` already works; `DESTDIR` and `prefix` are honored per the
GNU Coding Standards.

## Development workflow

```sh
make help                  # every target and variable
make test                  # go test ./... (builds the UI first, see below)
make vet                   # go vet ./...
make man                   # preview docs/ovcp.8 with man(1)
cd web/ui && npm run dev   # UI dev server; proxy the API manually or run `ovcp serve` alongside
```

`web/web.go` does `//go:embed all:dist`, so anything that imports it —
`cmd/ovcp`, hence `go build`/`go test`/`go vet` on that package — fails on a
fresh checkout with `pattern all:dist: no matching files found` until
`web/dist` exists. `test` and `vet` depend on `ui` for this reason; running
`go test ./...`/`go vet ./...` directly only works once `make ui` (or any
target that pulls it in) has populated `web/dist` at least once.

### Running from the checkout

Started as root, `ovcp` switches to the `ovcp` account (`man ovcp`,
**PRIVILEGES**), which cannot reach a binary or data directory inside a
private `$HOME`. From a checkout, run it either unprivileged, where the UI,
CLI, PKI and database work but openvpn, dnsmasq and nft cannot start
without `CAP_NET_ADMIN`:

```sh
export PATH=/usr/sbin:$PATH OVCP_DATA=$PWD/data \
  OVCP_CTRL_SOCK=$PWD/run/control.sock OVCP_MGMT_SOCK=$PWD/run/mgmt.sock
bin/ovcp init -server-cn vpn.example.com
bin/ovcp serve
```

or as root without the privilege drop:

```sh
sudo OVCP_USER=root OVCP_DATA=$PWD/data bin/ovcp serve
```

`sudo bin/ovcp` with the `ovcp` account present fails with
`exec …/bin/ovcp as ovcp: permission denied` and leaves an empty `./data`
owned by `ovcp`; remove it with `sudo rmdir data`.

### Tests

`make test` runs every suite. Two suites exercise privileges rootless,
inside user namespaces, and skip when their tools are missing:

```sh
go test ./cmd/ovcp -run TestDropRoot -v   # needs unshare --map-auto (an /etc/subuid entry)
go test ./cmd/ovcp -run TestE2E -v        # needs unshare, nsenter, ip, nft, openvpn
go test ./... -skip TestE2E               # everything else
```

On Debian, `ip`, `nft` and `openvpn` live in `/usr/sbin`; prefix the
commands with `PATH=/usr/sbin:$PATH`.

## CI / the release pipeline

[`.github/workflows/release.yml`](../.github/workflows/release.yml) runs on
every `v*` tag push and has three stages:

1. **`build`** — every `TARGET` row above, as a separate matrix job:
   binary, shell completions, and (`.deb`/`.rpm`/`.zst` for glibc targets,
   `.apk` for musl targets) the matching package, uploaded as a build
   artifact.
2. **`release`** — downloads every matrix artifact, computes a combined
   `SHA256SUMS`, and publishes a GitHub Release with all binaries,
   packages, and the checksum file attached.
3. **`image`** — pushes a multi-arch container image manifest to
   `ghcr.io`, tagged with the release tag and `latest`:

   ```sh
   docker buildx build \
     --platform linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6,linux/riscv64 \
     --push -f Containerfile .
   ```

   This differs from `make image` in shape: one manifest list spanning
   every platform, pushed to a registry, with QEMU provisioned via
   `docker/setup-qemu-action` and GitHub Actions' own layer cache. It is
   not routed through the Makefile — `make image` builds one local image
   to run or inspect, not a release artifact.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `unknown TARGET=foo (see: make help)` | Typo, or `foo` is not in the table above | `make help` lists every valid name |
| `missing: zig (cross-compiler for TARGET=...)` | Cross build, zig not installed | Install zig, or use `TARGET=host` when already on that architecture |
| `error: this host can't run linux/X containers (no working QEMU/binfmt for it)` | Cross image build, no binfmt handlers | `sudo docker run --privileged --rm docker.io/tonistiigi/binfmt --install all` (one-time, host-wide) |
| `user: unknown user ovcp: create that system account ...` | Started as root, no `ovcp` account | **Install** above, or `OVCP_USER=root` |
| `exec …/ovcp as ovcp: permission denied` | Binary inside a private `$HOME` | **Install** above, or **Running from the checkout** |
| `no value specified for --platform=` | An old podman/docker invoked directly, bypassing `make image` | Use `make image`, which always passes `--platform` explicitly, or add `--platform=linux/$(uname -m)` manually |
| Image build takes 6+ minutes every time | Build cache was pruned, or this is the first build on this host | Expected once; subsequent builds reuse `id=ovcp-build-cache` and drop to ~2 minutes |
