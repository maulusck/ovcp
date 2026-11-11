# check=skip=InvalidDefaultArgInFrom
# OVCP all-in-one image: ovcp runs as the image's ovcp account (man ovcp, PRIVILEGES). Run
# examples: README.md "Container"; TARGET=/cross-build/cache details: docs/BUILD.md.
# Toolchain versions come from `make versions` (make image, CI's image job), never
# defaults: a missing one fails at FROM, so BuildKit's check for them is skipped.
ARG GO_VERSION NODE_VERSION ZIG_VERSION ALPINE_VERSION
FROM --platform=$BUILDPLATFORM docker.io/library/node:${NODE_VERSION}-alpine${ALPINE_VERSION} AS ui
WORKDIR /src/web/ui
COPY web/ui/package*.json ./
RUN npm ci --no-fund
COPY web/ui/index.html web/ui/jsconfig.json web/ui/svelte.config.js web/ui/vite.config.js ./
COPY web/ui/public ./public
COPY web/ui/src ./src
RUN npm run build

# Runs on the builder's own platform (not emulated), cross-compiling through the Makefile's own
# `bin` (zig, hardening, the TARGET table). Always musl (final stage is Alpine).
FROM --platform=$BUILDPLATFORM docker.io/library/golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build
ARG VERSION=dev
ARG TARGETARCH TARGETVARIANT ZIG_VERSION
# zig at ZIG_VERSION from ziglang.org, as CI: Alpine packages an older one.
# This stage runs natively, so uname -m is zig's arch name (x86_64, aarch64).
RUN apk add --no-cache make mandoc xz && z="zig-$(uname -m)-linux-$ZIG_VERSION" && \
    wget -qO- "https://ziglang.org/download/$ZIG_VERSION/$z.tar.xz" | tar -xJ -C /opt && \
    ln -s "/opt/$z/zig" /usr/local/bin/zig
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY Makefile ./
COPY web/ui/.nvmrc ./web/ui/
COPY cmd ./cmd
COPY internal ./internal
COPY web/web.go ./web/
COPY --from=ui /src/web/dist ./web/dist
COPY docs/ovcp.8 ./docs/
RUN mandoc -T html -O fragment docs/ovcp.8 > web/dist/docs.html
# cache mount, not a layer: without it, any source change forces a from-scratch zig/go rebuild.
# See docs/BUILD.md, "The persistent build cache". TARGET is e.g. armv7-musl (arm + v7).
RUN --mount=type=cache,id=ovcp-build-cache,target=/root/.cache \
    make bin TARGET="$TARGETARCH$TARGETVARIANT-musl" VERSION="$VERSION"

FROM docker.io/library/alpine:${ALPINE_VERSION}
# refresh base packages at build time, not just whatever the base image last
# baked in — this ships a VPN/PKI tool, worth the extra seconds.
RUN apk upgrade --no-cache && apk add --no-cache openvpn dnsmasq nftables \
    && adduser -S -D -H ovcp && install -d -o ovcp -m 0700 /var/lib/ovcp
COPY --from=build /src/bin/ovcp /usr/bin/ovcp
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
