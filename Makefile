BINARY  := ovcp
# strip a leading v (v1.2.3 tags): deb's Version field must start with a
# digit, and this feeds nfpm.yaml's version: field for every package format.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
VERSION := $(if $(VERSION),$(VERSION),dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
# GNU Coding Standards: lowercase prefix, uppercase DESTDIR (staged
# installs). Default /usr, not /usr/local, to match nfpm.yaml's own paths.
prefix  ?= /usr
DESTDIR ?=

.PHONY: build test vet clean install help ui release man image deb rpm apk archlinux deps completions

release: ui build completions ## UI + binary + shell completions

deps: ## check build tools are on PATH (go, cc, npm, mandoc)
	@command -v go     >/dev/null || { echo "missing: go (1.22+)"; exit 1; }
	@command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || { echo "missing: a C compiler (CGO, for the sqlite driver)"; exit 1; }
	@command -v npm    >/dev/null || { echo "missing: npm (web/ui)"; exit 1; }
	@command -v mandoc >/dev/null || { echo "missing: mandoc (renders docs/ovcp.8 for the UI's Docs tab)"; exit 1; }
	@echo "build deps OK"

CTR := $(shell command -v podman || command -v docker)

image: ## build all-in-one container image (podman, else docker)
	@test -n "$(CTR)" || { echo "error: neither podman nor docker found"; exit 1; }
	$(CTR) build -t ovcp -f Containerfile .

deb rpm archlinux: release ## build package (needs nfpm)
	@command -v nfpm >/dev/null || { echo "missing: nfpm (packaging)"; exit 1; }
	VERSION=$(VERSION) nfpm package -f deploy/nfpm.yaml -p $@

apk: ui completions ## build .apk (needs nfpm + podman/docker: cross-builds against musl)
	@command -v nfpm >/dev/null || { echo "missing: nfpm (packaging)"; exit 1; }
	@test -n "$(CTR)" || { echo "missing: podman or docker (musl build for apk)"; exit 1; }
	$(CTR) run --rm -v $(CURDIR):/src:Z -w /src docker.io/library/golang:alpine \
		sh -c 'apk add --no-cache gcc musl-dev >/dev/null && CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o bin/ovcp-musl ./cmd/ovcp'
	VERSION=$(VERSION) nfpm package -f deploy/nfpm.yaml -p apk

help: ## show targets
	@grep -E '^[a-z][a-z0-9_ -]*:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-20s %s\n", $$1, $$2}'

web/ui/node_modules: web/ui/package.json web/ui/package-lock.json
	cd web/ui && npm ci
	@touch $@

ui: web/ui/node_modules ## build svelte UI into web/dist (needs mandoc, for the in-app Docs tab)
	cd web/ui && npm run build
	mandoc -T html -O fragment docs/ovcp.8 > web/dist/docs.html

build: ## build bin/ovcp (CGO for sqlite)
	CGO_ENABLED=1 go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/ovcp

completions: build ## generate shell completion scripts into dist/completion
	mkdir -p dist/completion
	bin/$(BINARY) completion bash > dist/completion/ovcp.bash
	bin/$(BINARY) completion zsh  > dist/completion/ovcp.zsh
	bin/$(BINARY) completion fish > dist/completion/ovcp.fish

test: ## run all tests
	go test ./...

vet: ## go vet
	go vet ./...

clean: ## remove build output (bin/, web/dist/, dist/)
	rm -rf bin web/dist dist

install: release ## install binary + man page + shell completions (DESTDIR/prefix honored)
	install -D -m 0755 bin/$(BINARY) $(DESTDIR)$(prefix)/bin/$(BINARY)
	install -D -m 0644 docs/ovcp.8 $(DESTDIR)$(prefix)/share/man/man8/ovcp.8
	install -D -m 0644 dist/completion/ovcp.bash $(DESTDIR)$(prefix)/share/bash-completion/completions/ovcp
	install -D -m 0644 dist/completion/ovcp.zsh $(DESTDIR)$(prefix)/share/zsh/site-functions/_ovcp
	install -D -m 0644 dist/completion/ovcp.fish $(DESTDIR)$(prefix)/share/fish/vendor_completions.d/ovcp.fish

man: ## preview man page
	man ./docs/ovcp.8
