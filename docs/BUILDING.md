# Building OVCP

How to build the binary, distro packages, and the container image — natively
on any supported host, or cross-compiled from any other. This is developer/
packager documentation; end-user CLI docs are `docs/ovcp.8` (`man ./docs/ovcp.8`
or `make man`).

`make help` is always the source of truth for targets and variables; this
document explains the *why* behind them.

## Requirements

`make deps` checks all of these are on `PATH` and explains what's missing:

- Go 1.22+
- a C compiler (`cc` or `gcc` — CGO, for the sqlite driver; only needed for
  `TARGET=host`, see below)
- npm (`web/ui`, the Svelte admin UI)
- mandoc (renders `docs/ovcp.8` into the UI's Docs tab)
- [zig](https://ziglang.org/) — only for cross-compiling (`TARGET=` set to
  anything other than `host`)
- [nfpm](https://nfpm.goreleaser.com/) — only for `.deb`/`.rpm`/`.apk`/Arch
  packages
- podman or docker — only for the container image

## TARGET: the one knob for every arch

Every build/package/image target reads `TARGET` (default `host`):

- **`TARGET=host`** — a plain native build. No cross toolchain, no zig, just
  the system's own `cc`/`gcc` and `go build` targeting whatever the go
  toolchain runs on. This is the fast path and requires nothing beyond the
  base `deps` list.
- **Any other `TARGET`** — cross-compiles via [zig cc](https://ziglang.org/),
  which bundles clang + a libc/compiler-rt sysroot for every target below.
  One tool covers every arch and both libcs, instead of a different
  cross-toolchain package per arch. Real (non-emulated) cross-compilation —
  no QEMU involved for `build`/packaging, only for cross container **images**
  (see below).

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

`TARGET=host` on an amd64 machine and `TARGET=amd64` are *not* the same
thing: the former never touches zig, the latter always does, even though the
result targets the same arch. There's no auto-detection that skips the cross
path when `TARGET`'s arch happens to match the host — one rule (`host` is
native, everything else is cross), applied uniformly, is simpler than a rule
plus an exception.

```sh
make build                  # native, whatever this host is
make build TARGET=arm64     # cross, glibc arm64
make deb TARGET=arm64-musl  # cross, musl arm64, packaged as a .apk-style deb (Alpine consumers use `make apk`)
```

`make help`'s `TARGET` line is generated from this same table (`CROSS_TARGETS`
in the Makefile), so it can't drift out of sync with it.

## Container image

```sh
make image                    # this host's own arch
make image TARGET=arm64       # cross-build a specific arch
```

The image is always Alpine-based (musl) regardless of which `TARGET` row you
name — `arm64` and `arm64-musl` produce the same image, since the
Containerfile's own build stage picks musl unconditionally. Use whichever
name you'd naturally reach for.

### Native vs. cross, and what `--platform` actually does

`make image` always passes an explicit `--platform`, derived from the same
`GOARCH`/`GOARM` as `build`/packaging (`TARGET=host` falls back to the host's
real arch via `go env GOARCH`). This is deliberate, not decorative: podman
and docker can auto-detect the target platform from the host when
`--platform` is *omitted*, but that auto-detection is a newer, tool-and-
version-dependent feature — on an engine or version that doesn't implement
it, `podman build`/`docker build` fails hard on the very first `FROM` line
with `no value specified for --platform=`, before any of the Containerfile's
own logic runs. Passing `--platform` explicitly removes that dependency
entirely; it's a long-standing, universally-supported flag on both tools.

### Cross-building an image needs QEMU/binfmt

The Containerfile's builder stage (`FROM --platform=$BUILDPLATFORM ...`) is
pinned to the *build* machine's own arch — Go and npm never run emulated,
zig cross-compiles the binary directly. But the **final** stage (`FROM
alpine:latest`, `apk add openvpn`) is not pinned that way: for a genuine
cross build it has to run *as* the target arch, because `apk` itself has to
execute. Without binfmt handlers registered for that arch, that step fails
with `exec container process: Exec format error`.

`make image TARGET=<cross-arch>` preflights this before starting the real
build (`check-image`): it runs a trivial container for the target platform
and fails immediately, with a clear message and the fix, if that doesn't
work:

```
error: this host can't run linux/arm64 containers (no binfmt/QEMU registered for it)
  see: docker run --privileged --rm tonistiigi/binfmt --install all
```

That one-time host setup (works for both podman and docker) is what CI's
release pipeline also relies on, via `docker/setup-qemu-action`. There is no
way around this requirement for this Containerfile's structure — it's
inherent to any cross-arch image build whose final stage does real
package-manager work, not a gap in the Makefile.

### Unknown TARGET fails clearly, not silently

Both `build` and `image` share a `check-target` prerequisite: an unrecognized
`TARGET` is rejected up front (`unknown TARGET=foo (see: make help)`) rather
than silently falling back to the host's own arch. `check-cross` (used only
by `build`/packaging) additionally requires `zig` on the host `PATH` — a
requirement `image` doesn't have, since zig runs *inside* the builder
container, not on the machine invoking `podman build`.

### The persistent build cache

The Containerfile's final `RUN` (the `zig cc`/`go build` step) uses a
BuildKit/buildah cache mount:

```
RUN --mount=type=cache,id=ovcp-build-cache,target=/root/.cache ...
```

Without it, every single image build recompiles from a cold cache: zig
rebuilds its target's libc/compiler-rt objects from scratch, and `go build`
has no prior object cache either, because `~/.cache` lives inside the
ephemeral build container and nothing preserves it between `podman build`
invocations. `COPY . .` earlier in the same stage means this step re-runs on
*any* source change, so paying that cold-cache cost every time compounds
fast.

The cache mount fixes this by living in the container engine's own
build-cache store instead — not this checkout, nothing to `.gitignore`,
shared across builds on the same host regardless of Docker's normal layer
cache. Measured on this project: **~6.5 minutes cold, ~2 minutes warm** for
the same build. `make image` prints a reminder that it's in use; `make
clean` prints a reminder that it *isn't* touched (it only removes files this
project writes into the checkout — `bin/`, `web/dist/`, `dist/`). Reclaim it
explicitly:

```sh
podman builder prune    # or: docker builder prune
```

## Packages (.deb/.rpm/.apk/Arch)

```sh
make deb                     # native host arch
make deb TARGET=arm64        # cross-compile the binary first, then package it (glibc, for Debian/Fedora/Arch bases)
make apk TARGET=riscv64-musl # musl, for Alpine/OpenWrt bases
```

`ARCH` (fed to `nfpm.yaml`'s `arch:` field) comes from the same `TARGET`
table (last column above); for `TARGET=host` it falls back to `go env
GOARCH` — never a hardcoded guess, so a package built natively on, say, an
arm64 host is correctly labeled `arm64`, not silently mislabeled `amd64`.

`apk` targets use OpenRC's init script by default; `postinstall.sh` swaps in
the procd one automatically when `/etc/rc.common` (OpenWrt's marker) is
present — see `deploy/nfpm.yaml`.

## CI / the release pipeline

`.github/workflows/release.yml` builds every `TARGET` row above as a
separate matrix job (binaries, shell completions, packages), and separately
pushes a real multi-arch container image manifest to `ghcr.io` via:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6,linux/riscv64 \
  --push -f Containerfile .
```

That's a fundamentally different shape than `make image` (one manifest list
spanning every platform, pushed to a registry, with QEMU set up via
`docker/setup-qemu-action` and GitHub Actions' own layer cache) and
deliberately isn't routed through the Makefile — `make image` is for
building *one* local image to run or inspect, not for cutting a release.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `unknown TARGET=foo (see: make help)` | Typo, or `foo` isn't in the table above | `make help` lists every valid name |
| `missing: zig (cross-compiler for TARGET=...)` | Cross build, zig not installed | Install zig, or use `TARGET=host` if you're already on that arch |
| `error: this host can't run linux/X containers (no binfmt/QEMU registered for it)` | Cross image build, no binfmt handlers | `docker run --privileged --rm tonistiigi/binfmt --install all` (one-time, host-wide) |
| `no value specified for --platform=` | Very old podman/docker invoked *without* going through `make image` (e.g. a hand-typed `podman build` from the Containerfile's header comment) | Use `make image`, which always passes `--platform` explicitly, or add `--platform=linux/$(uname -m)` yourself |
| Image build takes 6+ minutes every time | Build cache got pruned, or this is the first build on this host | Expected once; subsequent builds reuse `id=ovcp-build-cache` and drop to ~2 minutes |
| `.deb`/`.rpm` built on an arm64/riscv64 host is labeled `amd64` | Pre-existing bug, fixed — if you still see this, `ARCH` isn't picking up `go env GOARCH` | Check `go env GOARCH` returns the real arch, and that `make`'s `ARCH` variable reflects it (`make -n deb TARGET=host \| grep ARCH=`) |
