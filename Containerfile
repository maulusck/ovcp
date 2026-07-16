# OVCP all-in-one image: ovcp (as root) owns the PKI and starts openvpn.
#
# First boot (one-shot init; passphrase/password default to "changeme",
# override with -e OVCP_CA_PASSPHRASE=... -e OVCP_USER_PASSWORD=...):
#   podman run --rm -v ovcp:/var/lib/ovcp ovcp init -server-cn vpn.example.com
#
# Run:
#   podman run -d --cap-add=NET_ADMIN --device /dev/net/tun \
#     -p 1194:1194/udp -p 127.0.0.1:8443:8443 \
#     -v ovcp:/var/lib/ovcp ovcp
#
# Split UI and VPN across interfaces with -p bind addresses, e.g. UI on the
# LAN interface, VPN on the WAN interface:
#   -p 203.0.113.7:1194:1194/udp -p 192.168.1.10:8443:8443
#
# Multi-arch (amd64/arm64/armv7/armv6/riscv64):
#   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6,linux/riscv64 -f Containerfile .
FROM --platform=$BUILDPLATFORM docker.io/library/node:22-alpine AS ui
WORKDIR /src/web/ui
COPY web/ui/package*.json ./
RUN npm ci
COPY web/ui .
RUN npm run build

# Runs on the builder's own platform (not emulated) and cross-compiles via
# zig — same mechanism the Makefile uses for every non-native TARGET, one
# tool for every arch instead of a cross-toolchain per arch. Always musl:
# this image's final stage is Alpine.
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
RUN case "$TARGETARCH$TARGETVARIANT" in \
      amd64)   ZIG=x86_64-linux-musl ;; \
      arm64)   ZIG=aarch64-linux-musl ;; \
      armv7)   ZIG=arm-linux-musleabihf; GOARM=7 ;; \
      armv6)   ZIG=arm-linux-musleabihf; GOARM=6 ;; \
      riscv64) ZIG=riscv64-linux-musl ;; \
      *) echo "unsupported platform $TARGETARCH$TARGETVARIANT" >&2; exit 1 ;; \
    esac; \
    CC="zig cc -target $ZIG" CGO_ENABLED=1 GOOS=linux GOARCH=$TARGETARCH GOARM=$GOARM \
      go build -ldflags "-s -w -X main.version=${VERSION}" -o /ovcp ./cmd/ovcp

FROM docker.io/library/alpine:latest
# refresh base packages at build time, not just whatever alpine:latest last
# baked in — this ships a root-owned VPN/PKI tool, worth the extra seconds.
RUN apk upgrade --no-cache && apk add --no-cache openvpn
COPY --from=build /ovcp /usr/bin/ovcp
ENV OVCP_DATA=/var/lib/ovcp \
    OVCP_LISTEN=0.0.0.0:8443 \
    OVCP_CA_PASSPHRASE=changeme \
    OVCP_USER_PASSWORD=changeme \
    OVCP_OPENVPN_GROUP=nobody
# logrotate/log-shippers expect /var/log; symlink into the data volume
# instead of duplicating files.
RUN ln -s /var/lib/ovcp/logs /var/log/ovcp
VOLUME /var/lib/ovcp
EXPOSE 1194/udp 8443/tcp
ENTRYPOINT ["ovcp"]
CMD ["serve"]
