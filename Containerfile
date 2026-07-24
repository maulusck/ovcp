# OVCP all-in-one image: ovcp (as root) owns the PKI and starts openvpn. Run
# examples: README.md "Container"; TARGET=/cross-build/cache details: docs/BUILD.md.
FROM --platform=$BUILDPLATFORM docker.io/library/node:22-alpine AS ui
WORKDIR /src/web/ui
COPY web/ui/package*.json ./
RUN npm ci
COPY web/ui .
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
COPY . .
COPY --from=ui /src/web/dist ./web/dist
RUN mandoc -T html -O fragment docs/ovcp.8 > web/dist/docs.html
# cache mount, not a layer: without it, COPY . . above forces a from-scratch zig/go rebuild on every
# source change. See docs/BUILD.md, "The persistent build cache".
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
# baked in — this ships a root-owned VPN/PKI tool, worth the extra seconds.
RUN apk upgrade --no-cache && apk add --no-cache openvpn dnsmasq
COPY --from=build /ovcp /usr/bin/ovcp
ENV OVCP_DATA=/var/lib/ovcp \
    OVCP_LISTEN=0.0.0.0:8443 \
    OVCP_CA_PASSPHRASE=changeme! \
    OVCP_USER_PASSWORD=changeme! \
    OVCP_OPENVPN_GROUP=nobody \
    OVCP_DNSMASQ_GROUP=nobody
# logrotate/log-shippers expect /var/log; symlink into the data volume
# instead of duplicating files.
RUN ln -s /var/lib/ovcp/logs /var/log/ovcp
VOLUME /var/lib/ovcp
EXPOSE 1194/udp 8443/tcp
ENTRYPOINT ["ovcp"]
CMD ["serve"]
