# OVCP all-in-one image: ovcp runs as the image's ovcp account (man ovcp, PRIVILEGES). Run
# examples: README.md "Container"; TARGET=/cross-build/cache details: docs/BUILD.md.
FROM --platform=$BUILDPLATFORM docker.io/library/node:22-alpine AS ui
WORKDIR /src/web/ui
COPY web/ui/package*.json ./
RUN npm ci
COPY web/ui/index.html web/ui/jsconfig.json web/ui/svelte.config.js web/ui/vite.config.js ./
COPY web/ui/public ./public
COPY web/ui/src ./src
RUN npm run build

# Runs on the builder's own platform (not emulated), cross-compiling via zig — same mechanism the Makefile
# uses. Always musl (final stage is Alpine).
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.22-alpine AS build
ARG VERSION=dev
ARG TARGETARCH TARGETVARIANT
RUN apk add --no-cache zig mandoc
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web/web.go ./web/
COPY --from=ui /src/web/dist ./web/dist
COPY docs/ovcp.8 ./docs/
RUN mandoc -T html -O fragment docs/ovcp.8 > web/dist/docs.html
# cache mount, not a layer: without it, any source change forces a from-scratch zig/go rebuild.
# See docs/BUILD.md, "The persistent build cache".
RUN --mount=type=cache,id=ovcp-build-cache,target=/root/.cache \
    case "$TARGETARCH$TARGETVARIANT" in \
      amd64)   ZIG=x86_64-linux-musl ;; \
      arm64)   ZIG=aarch64-linux-musl ;; \
      armv7)   ZIG=arm-linux-musleabihf; GOARM=7 ;; \
      armv6)   ZIG=arm-linux-musleabihf; GOARM=6 ;; \
      riscv64) ZIG=riscv64-linux-musl ;; \
      *) echo "unsupported platform $TARGETARCH$TARGETVARIANT" >&2; exit 1 ;; \
    esac; \
    CC="zig cc -target $ZIG" CGO_ENABLED=1 GOOS=linux GOARCH=$TARGETARCH GOARM=$GOARM \
      go build -ldflags "-s -w -X main.version=${VERSION} -X main.buildTarget=${TARGETARCH}${TARGETVARIANT}-musl" -o /ovcp ./cmd/ovcp

FROM docker.io/library/alpine:latest
# refresh base packages at build time, not just whatever alpine:latest last
# baked in — this ships a VPN/PKI tool, worth the extra seconds.
RUN apk upgrade --no-cache && apk add --no-cache openvpn dnsmasq nftables \
    && adduser -S -D -H ovcp && install -d -o ovcp -m 0700 /var/lib/ovcp
COPY --from=build /ovcp /usr/bin/ovcp
# no secret defaults: init prompts (-it) or takes -e OVCP_CA_PASSPHRASE/OVCP_USER_PASSWORD
ENV OVCP_DATA=/var/lib/ovcp \
    OVCP_LISTEN=0.0.0.0:8443
# logrotate/log-shippers expect /var/log; symlink into the data volume
# instead of duplicating files.
RUN ln -s /var/lib/ovcp/logs /var/log/ovcp
VOLUME /var/lib/ovcp
EXPOSE 1194/udp 8443/tcp
ENTRYPOINT ["ovcp"]
CMD ["serve"]
