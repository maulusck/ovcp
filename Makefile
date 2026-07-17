# require(cmds,human-message): fail clearly if none of cmds (space-separated
# alternatives, e.g. "cc gcc") are on PATH. The one shape every tool-presence
# check in this file shares.
require = command -v $(firstword $(1)) >/dev/null 2>&1 $(patsubst %,|| command -v % >/dev/null 2>&1,$(wordlist 2,99,$(1))) || { echo "missing: $(2)"; exit 1; }

BINARY  := ovcp
# strip a leading v (v1.2.3 tags): deb's Version field must start with a
# digit, and this feeds nfpm.yaml's version: field for every package format.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
VERSION := $(if $(VERSION),$(VERSION),dev)
# GNU Coding Standards: lowercase prefix, uppercase DESTDIR (staged
# installs). Default /usr, not /usr/local, to match nfpm.yaml's own paths.
prefix  ?= /usr
DESTDIR ?=

# TARGET picks what build/release/packaging produce: "host" (default) is
# a plain native build, no cross toolchain involved at all. Every other
# TARGET cross-compiles via zig cc — one tool, real (non-emulated) native
# cross-compilation, glibc and musl alike, one mechanism for every arch
# instead of a different cross-toolchain per libc. One row per target:
# GOARCH, GOARM (- if native), zig's target triple, nfpm's arch spelling.
t-arm64        = arm64   - aarch64-linux-gnu     arm64
t-arm64-musl   = arm64   - aarch64-linux-musl    arm64
t-armv7        = arm     7 arm-linux-gnueabihf   arm7
t-armv7-musl   = arm     7 arm-linux-musleabihf  arm7
t-armv6        = arm     6 arm-linux-gnueabihf   arm6
t-armv6-musl   = arm     6 arm-linux-musleabihf  arm6
t-amd64        = amd64   - x86_64-linux-gnu      amd64
t-amd64-musl   = amd64   - x86_64-linux-musl     amd64
t-riscv64      = riscv64 - riscv64-linux-gnu     riscv64
t-riscv64-musl = riscv64 - riscv64-linux-musl    riscv64
# derived from the table above so `help` never drifts from it
CROSS_TARGETS := $(patsubst t-%,%,$(filter t-%,$(.VARIABLES)))

TARGET ?= host
GOARCH := $(word 1,$(t-$(TARGET)))
GOARM  := $(filter-out -,$(word 2,$(t-$(TARGET))))
CC     := $(if $(word 3,$(t-$(TARGET))),zig cc -target $(word 3,$(t-$(TARGET))))
# TARGET=host arch, from the go toolchain itself: single source of truth for
# "the arch of whatever machine this runs on" (nfpm's ARCH below, and the
# container --platform), instead of a hardcoded guess that's only ever right
# on amd64.
HOSTARCH := $(shell go env GOARCH)
ARCH     := $(or $(word 4,$(t-$(TARGET))),$(HOSTARCH))
# main.buildTarget mirrors main.version below: baked in at compile time so
# `ovcp version` can report exactly what it was built for, same TARGET name
# whether that's "host" or a cross target - never guessed at runtime.
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.buildTarget=$(TARGET)
# OCI platform string for the same TARGET: linux/<goarch>, or linux/arm/v<goarm>
# for the arm variants. Cross (TARGET != host) needs binfmt/QEMU registered on
# this host, same as any buildx cross build — the final stage's `apk add`
# really executes as the target arch.
PLATFORM := linux/$(or $(GOARCH),$(HOSTARCH))$(if $(GOARM),/v$(GOARM))

.PHONY: build test vet clean install help ui release man image deb rpm apk archlinux deps completions check-target check-cross check-nfpm check-image

release: build completions ## UI + binary + shell completions

deps: ## check build tools are on PATH (go, cc, npm, mandoc)
	@$(call require,go,go (1.22+))
	@$(call require,cc gcc,a C compiler (CGO, for the sqlite driver))
	@$(call require,npm,npm (web/ui))
	@$(call require,mandoc,mandoc (renders docs/ovcp.8 for the UI's Docs tab))
	@echo "build deps OK"

CTR := $(shell command -v podman || command -v docker)
# id=ovcp-build-cache in the Containerfile's zig/go RUN mount; reused by
# image (says it's using this) and clean (reminds it isn't touched by rm -rf).
CACHE_HINT := podman/docker builder prune reclaims the persistent build cache (id=ovcp-build-cache)

check-image: check-target
	@$(call require,podman docker,podman or docker (container image build))
	@test "$(TARGET)" = host || $(CTR) run --rm --platform $(PLATFORM) docker.io/library/alpine:latest true >/dev/null 2>&1 || \
	  { echo "error: this host can't run $(PLATFORM) containers (no working QEMU/binfmt for it) - see docs/BUILDING.md, 'Cross-building an image needs QEMU/binfmt'"; exit 1; }

image: check-image ## build all-in-one container image for TARGET's arch (default: this host's own); podman, else docker
	@echo "using persistent zig/go build cache - $(CACHE_HINT)"
	$(CTR) build --platform $(PLATFORM) -t ovcp -t ovcp:$(VERSION) --build-arg VERSION=$(VERSION) -f Containerfile .

check-nfpm:
	@$(call require,nfpm,nfpm (packaging))

deb rpm archlinux apk: check-nfpm release ## build package (needs nfpm; TARGET= to cross-build first, see build)
	VERSION=$(VERSION) ARCH=$(ARCH) nfpm package -f deploy/nfpm.yaml -p $@ -t dist/

help: ## show targets and variables
	@echo "targets:"
	@grep -E '^[a-z][a-z0-9_ -]*:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-20s %s\n", $$1, $$2}'
	@echo "variables:"
	@echo "  TARGET               host (default), or one of: $(CROSS_TARGETS)"
	@echo "                       cross-builds via zig cc; see build"
	@echo "  prefix, DESTDIR      install paths, GNU-standard (install target)"

web/ui/node_modules: web/ui/package.json web/ui/package-lock.json
	cd web/ui && npm ci
	@touch $@

ui: web/ui/node_modules ## build svelte UI into web/dist (needs mandoc, for the in-app Docs tab)
	cd web/ui && npm run build
	mandoc -T html -O fragment docs/ovcp.8 > web/dist/docs.html

check-target:
	@test "$(TARGET)" = host -o -n "$(t-$(TARGET))" || { echo "unknown TARGET=$(TARGET) (see: make help)"; exit 1; }

check-cross: check-target
	@test -z '$(CC)' || { $(call require,zig,zig (cross-compiler for TARGET=$(TARGET))); }

build: check-cross ui ## build bin/ovcp (CGO for sqlite; see help for TARGET= to cross-build via zig)
	GOOS=$(if $(GOARCH),linux) GOARCH=$(GOARCH) GOARM=$(GOARM) CC='$(CC)' \
		CGO_ENABLED=1 go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/ovcp

completions: ui ## generate shell completion scripts into dist/completion
	@mkdir -p dist/completion; \
	go build -ldflags '$(LDFLAGS)' -o bin/.completions-helper ./cmd/ovcp; \
	bin/.completions-helper completion bash > dist/completion/ovcp.bash; \
	bin/.completions-helper completion zsh  > dist/completion/ovcp.zsh; \
	bin/.completions-helper completion fish > dist/completion/ovcp.fish; \
	rm -f bin/.completions-helper

test: ui ## run all tests
	go test ./...

vet: ui ## go vet
	go vet ./...

clean: ## remove build output (bin/, web/dist/, dist/)
	rm -rf bin web/dist dist
	@echo "note: container build cache untouched - $(CACHE_HINT)"

install: release ## install binary + man page + shell completions (DESTDIR/prefix honored)
	install -D -m 0755 bin/$(BINARY) $(DESTDIR)$(prefix)/bin/$(BINARY)
	install -D -m 0644 docs/ovcp.8 $(DESTDIR)$(prefix)/share/man/man8/ovcp.8
	install -D -m 0644 dist/completion/ovcp.bash $(DESTDIR)$(prefix)/share/bash-completion/completions/ovcp
	install -D -m 0644 dist/completion/ovcp.zsh $(DESTDIR)$(prefix)/share/zsh/site-functions/_ovcp
	install -D -m 0644 dist/completion/ovcp.fish $(DESTDIR)$(prefix)/share/fish/vendor_completions.d/ovcp.fish

man: ## preview man page
	man ./docs/ovcp.8
