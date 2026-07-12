BINARY  := ovcp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet clean install help ui release man image deb rpm deps

release: ui build ## UI + binary

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

deb rpm: release ## build package (needs nfpm)
	VERSION=$(VERSION) nfpm package -f deploy/nfpm.yaml -p $@

help: ## show targets
	@grep -E '^[a-z][a-z0-9_ -]*:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

web/ui/node_modules: web/ui/package.json web/ui/package-lock.json
	cd web/ui && npm ci
	@touch $@

ui: web/ui/node_modules ## build svelte UI into web/dist (needs mandoc, for the in-app Docs tab)
	cd web/ui && npm run build
	mandoc -T html -O fragment docs/ovcp.8 > web/dist/docs.html

build: ## build bin/ovcp (CGO for sqlite)
	CGO_ENABLED=1 go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/ovcp

test: ## run all tests
	go test ./...

vet: ## go vet
	go vet ./...

clean: ## remove build output (bin/, web/dist/)
	rm -rf bin web/dist

install: build ## install binary + man page
	install -m 0755 bin/$(BINARY) /usr/bin/$(BINARY)
	install -D -m 0644 docs/ovcp.8 /usr/share/man/man8/ovcp.8

man: ## preview man page
	man ./docs/ovcp.8
