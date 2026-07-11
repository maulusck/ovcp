BINARY  := ovcp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet clean install help ui release man image deb rpm

release: ui build ## UI + binary

CTR := $(shell command -v podman || command -v docker)

image: ## build all-in-one container image (podman, else docker)
	@test -n "$(CTR)" || { echo "error: neither podman nor docker found"; exit 1; }
	$(CTR) build -t ovcp -f Containerfile .

deb rpm: release ## build package (needs nfpm)
	VERSION=$(VERSION) nfpm package -f deploy/nfpm.yaml -p $@

all: build

help: ## show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

ui: ## build svelte UI into web/dist
	cd web/ui && npm install && npm run build

build: ## build bin/ovcp (CGO for sqlite)
	CGO_ENABLED=1 go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/ovcp

test: ## run all tests
	go test ./...

vet: ## go vet
	go vet ./...

clean: ## remove bin/
	rm -rf bin

install: build ## install binary + man page
	install -m 0755 bin/$(BINARY) /usr/bin/$(BINARY)
	install -D -m 0644 docs/ovcp.8 /usr/share/man/man8/ovcp.8

man: ## preview man page
	man ./docs/ovcp.8
