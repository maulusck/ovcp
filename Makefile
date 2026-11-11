# require(cmds,msg): fail if none of cmds (space-separated alternatives) are on PATH.
require = command -v $(firstword $(1)) >/dev/null 2>&1 $(patsubst %,|| command -v % >/dev/null 2>&1,$(wordlist 2,99,$(1))) || { echo "missing: $(2)"; exit 1; }

# Toolchain versions, one home each: Go in go.mod, Node in web/ui/.nvmrc, the
# rest here. `make versions` prints them; CI and the image build read that.
GO_VERSION     := $(shell sed -n 's/^go //p' go.mod)
NODE_VERSION   := $(shell cat web/ui/.nvmrc)
ZIG_VERSION    := 0.17.1
NFPM_VERSION   := 2.48.0
ALPINE_VERSION := 3.24
TOOLCHAIN      := GO_VERSION NODE_VERSION ZIG_VERSION NFPM_VERSION ALPINE_VERSION
IMAGE_ARGS     := $(foreach v,GO_VERSION NODE_VERSION ZIG_VERSION ALPINE_VERSION,--build-arg $(v)=$($(v)))
# want(cmd,version,name): fail unless cmd's output contains version.
want = v=$$($(1) 2>&1); case "$$v" in *$(2)*) ;; *) echo "$(3): want $(2), have: $$(echo "$$v" | head -1)"; exit 1;; esac

BINARY  := ovcp
# v1.2.3 tags give 1.2.3; an untagged tree gives 0.0.0-<hash>, which every
# package format accepts (deb needs a leading digit) and sorts below 1.0.0.
VERSION := $(shell v=$$(git describe --tags --dirty 2>/dev/null) && echo $${v#v} || echo 0.0.0-$$(git describe --always --dirty 2>/dev/null || echo dev))
# GNU Coding Standards: lowercase prefix, uppercase DESTDIR (staged
# installs). Default /usr, not /usr/local, to match nfpm.yaml's own paths.
prefix  ?= /usr
DESTDIR ?=

# TARGET rows: GOARCH, GOARM (- if none), zig triple, nfpm arch. "host" (default)
# builds natively; every row cross-compiles through zig cc, glibc and musl alike.
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
# This host's arch, from go env: nfpm's ARCH and the image platform for TARGET=host.
HOSTARCH := $(shell go env GOARCH)
ARCH     := $(or $(word 4,$(t-$(TARGET))),$(HOSTARCH))
# Go's linker flags; `ovcp version` reports main.version and main.buildTarget.
GO_LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTarget=$(TARGET)
# platform(target): its OCI platform (linux/arm/v<goarm> for arm). A cross
# image needs binfmt/QEMU registered on this host, like any buildx cross build.
platform = linux/$(or $(word 1,$(t-$(1))),$(HOSTARCH))$(if $(filter-out -,$(word 2,$(t-$(1)))),/v$(word 2,$(t-$(1))))
PLATFORM := $(call platform,$(TARGET))

# apk is musl-only: unless TARGET is given on the command line it builds
# <hostarch>-musl, so `make deb apk` never ships a glibc .apk.
ifeq ($(origin TARGET),command line)
APK_TARGET := $(TARGET)
else
APK_TARGET := $(HOSTARCH)-musl
endif

.PHONY: build bin docs check versions image-args platforms clean install help ui release man image deb rpm apk archlinux deps completions check-target check-cross check-nfpm check-image

release: build completions ## UI + binary + shell completions

deps: ## check build tools are on PATH at `make versions` (go, cc, node, mandoc)
	@$(call require,go,go)
	@$(call require,cc gcc,a C compiler (CGO, for the sqlite driver))
	@$(call require,npm,npm (web/ui))
	@$(call require,mandoc,mandoc (renders docs/ovcp.8 for the UI's Docs tab))
	@$(call want,go env GOVERSION,go$(GO_VERSION),go)
	@$(call want,node --version,v$(NODE_VERSION).,node)
	@echo "build deps OK"

versions: ## print the toolchain versions as KEY=value
	@$(foreach v,$(TOOLCHAIN),echo $(v)=$($(v));)

image-args: ## print the Containerfile's toolchain --build-arg flags
	@echo $(IMAGE_ARGS)

platforms: ## print the image's platforms, one per -musl TARGET (CI's multi-arch build)
	@echo $(foreach t,$(sort $(filter %-musl,$(CROSS_TARGETS))),$(call platform,$t)) | tr ' ' ,

CTR := $(shell command -v podman || command -v docker)
# id=ovcp-build-cache in the Containerfile's zig/go RUN mount, which clean leaves alone.
CACHE_HINT := podman/docker builder prune reclaims the persistent build cache (id=ovcp-build-cache)

check-image: check-target
	@$(call require,podman docker,podman or docker (container image build))
	@test "$(TARGET)" = host || $(CTR) run --rm --platform $(PLATFORM) docker.io/library/alpine:$(ALPINE_VERSION) true >/dev/null 2>&1 || \
	  { echo "error: this host can't run $(PLATFORM) containers (no working QEMU/binfmt for it) - see docs/BUILD.md, 'Cross-building an image needs QEMU/binfmt'"; exit 1; }

image: check-image ## build all-in-one container image for TARGET's arch (default: this host's own); podman, else docker
	$(CTR) build --platform $(PLATFORM) -t ovcp -t ovcp:$(VERSION) --build-arg VERSION=$(VERSION) $(IMAGE_ARGS) -f Containerfile .

check-nfpm:
	@$(call require,nfpm,nfpm (packaging))
	@$(call want,nfpm --version,$(NFPM_VERSION),nfpm)

# package(format,target): what `make install` stages in dist/root plus nfpm.yaml's
# own files, named by TARGET, which is unique, so no two packages share a name.
package = rm -rf dist/root && $(MAKE) --no-print-directory install DESTDIR=$(CURDIR)/dist/root prefix=/usr && \
	VERSION=$(VERSION) ARCH=$(ARCH) nfpm package -f deploy/nfpm.yaml -p $(1) -t dist/ovcp_$(VERSION)_$(2).$(subst archlinux,pkg.tar.zst,$(1))

deb rpm archlinux: check-nfpm release ## build package (needs nfpm; TARGET= to cross-build first, see build)
	$(call package,$@,$(TARGET))

apk: check-nfpm ## build Alpine/OpenWrt package (needs nfpm; forces TARGET to musl unless you set one yourself)
	@case "$(APK_TARGET)" in \
	  *-musl) test "$(APK_TARGET)" = "$(TARGET)" || echo "building apk for TARGET=$(APK_TARGET)" ;; \
	  *) echo "warning: TARGET=$(APK_TARGET) is not -musl; Alpine/OpenWrt are musl-only, this .apk likely won't run there" >&2 ;; \
	esac
	$(MAKE) TARGET=$(APK_TARGET) release
	$(call package,$@,$(APK_TARGET))

help: ## show targets and variables
	@echo "targets:"
	@grep -E '^[a-z][a-z0-9_ -]*:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-20s %s\n", $$1, $$2}'
	@echo "variables:"
	@echo "  TARGET               host (default), or one of: $(CROSS_TARGETS)"
	@echo "                       cross-builds via zig cc; see build"
	@echo "  prefix, DESTDIR      install paths, GNU-standard (install target)"

web/ui/node_modules: web/ui/package.json web/ui/package-lock.json
	cd web/ui && npm ci --no-fund
	@touch $@

# The UI's Docs tab; after the UI build, which empties web/dist.
render_docs = mandoc -T html -O fragment docs/ovcp.8 > web/dist/docs.html

ui: web/ui/node_modules ## build svelte UI into web/dist (needs mandoc, for the in-app Docs tab)
	cd web/ui && npm run build
	$(render_docs)

docs: ## render docs/ovcp.8 into a built web/dist (the image's UI comes from its own stage)
	$(render_docs)

check-target:
	@test "$(TARGET)" = host -o -n "$(t-$(TARGET))" || { echo "unknown TARGET=$(TARGET) (see: make help)"; exit 1; }

check-cross: check-target
	@test -z '$(CC)' || { $(call require,zig,zig (cross-compiler for TARGET=$(TARGET))); $(call want,zig version,$(ZIG_VERSION),zig); }

# The one link step (build, bin): a cgo PIE that elfcheck verifies. CFLAGS, CPPFLAGS and
# LDFLAGS (a distro's) reach cgo, never Go's linker; full RELRO is always appended.
define link
GOOS=$(if $(GOARCH),linux) GOARCH=$(GOARCH) GOARM=$(GOARM) CC='$(CC)' CGO_ENABLED=1 \
	CGO_CFLAGS='$(CFLAGS)' CGO_CPPFLAGS='$(CPPFLAGS)' CGO_LDFLAGS='$(LDFLAGS) -Wl,-z,relro,-z,now' \
	go build -buildmode=pie -trimpath -ldflags '$(GO_LDFLAGS)' -o bin/$(BINARY) ./cmd/ovcp
go run ./cmd/elfcheck bin/$(BINARY)
endef

build: check-cross ui ## build bin/ovcp, a hardened PIE (see help for TARGET= to cross-build via zig)
	$(link)

bin: check-cross ## build without the UI step, on web/dist as it is (the image builds its UI in its own stage)
	$(link)

# Generated by a host build (TARGET's CC and flags never apply to it).
completions: ui ## generate shell completion scripts into dist/completion
	@mkdir -p dist/completion
	go run ./cmd/ovcp completion bash > dist/completion/ovcp.bash
	go run ./cmd/ovcp completion zsh  > dist/completion/ovcp.zsh
	go run ./cmd/ovcp completion fish > dist/completion/ovcp.fish

# Every gate, run by CI and before each commit: a hardened build, an install that never compiles,
# unique package names, CI's matrix, vet, the UI against Go's API types, gofmt, mandoc, all tests.
check: SHELL := /bin/bash
check: .SHELLFLAGS := -eo pipefail -c
check: release ## run every gate: hardened build, vet, gofmt, UI types, mandoc lint, all tests, none skipped
	! $(MAKE) -n install | grep -E '^(go|cd web)'
	test $$({ $(foreach t,$(CROSS_TARGETS),$(MAKE) -n deb TARGET=$t;) } | grep -o 'dist/ovcp_[^ ]*' | sort -u | wc -l) = $(words $(CROSS_TARGETS))
	test "$$(sed -n 's/^ *target: \[\(.*\)\]$$/\1/p' .github/workflows/ci.yml | tr -d ' ' | tr , '\n' | sort | xargs)" = "$(sort $(CROSS_TARGETS))"
	go vet ./cmd/... ./internal/...
	go run ./cmd/apits > web/ui/src/api.gen.d.ts
	cd web/ui && npm run -s check
	test -z "$$(gofmt -l cmd internal web)" || { gofmt -l cmd internal web; exit 1; }
	mandoc -T lint -W warning docs/ovcp.8
	mkdir -p dist && go test -count=1 -v ./cmd/... ./internal/... 2>&1 | tee dist/check.log | grep -E -- '^(--- FAIL|--- SKIP|FAIL|ok)'
	! grep -- '--- SKIP' dist/check.log

clean: ## remove build output (bin/, web/dist/, dist/)
	rm -rf bin web/dist dist
	@echo "note: container build cache untouched - $(CACHE_HINT)"

# install only copies what `make` built (no rule makes these files): it never
# compiles, so a root install runs no toolchain and ships the build's binary.
install: bin/$(BINARY) dist/completion/ovcp.bash dist/completion/ovcp.zsh dist/completion/ovcp.fish ## install what `make` built: binary, man page, completions (DESTDIR/prefix honored)
	install -D -m 0755 bin/$(BINARY) $(DESTDIR)$(prefix)/bin/$(BINARY)
	install -D -m 0644 docs/ovcp.8 $(DESTDIR)$(prefix)/share/man/man8/ovcp.8
	install -D -m 0644 dist/completion/ovcp.bash $(DESTDIR)$(prefix)/share/bash-completion/completions/ovcp
	install -D -m 0644 dist/completion/ovcp.zsh $(DESTDIR)$(prefix)/share/zsh/site-functions/_ovcp
	install -D -m 0644 dist/completion/ovcp.fish $(DESTDIR)$(prefix)/share/fish/vendor_completions.d/ovcp.fish

man: ## preview man page
	man ./docs/ovcp.8
