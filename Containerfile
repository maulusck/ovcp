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
FROM docker.io/library/node:22-alpine AS ui
WORKDIR /src/web/ui
COPY web/ui/package*.json ./
RUN npm ci
COPY web/ui .
RUN npm run build

FROM docker.io/library/golang:1.22-alpine AS build
RUN apk add --no-cache gcc musl-dev mandoc
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
RUN mandoc -T html -O fragment docs/ovcp.8 > web/dist/docs.html
RUN CGO_ENABLED=1 go build -ldflags '-s -w' -o /ovcp ./cmd/ovcp

FROM docker.io/library/alpine:latest
RUN apk add --no-cache openvpn
COPY --from=build /ovcp /usr/bin/ovcp
ENV OVCP_DATA=/var/lib/ovcp \
    OVCP_LISTEN=0.0.0.0:8443 \
    OVCP_CA_PASSPHRASE=changeme \
    OVCP_USER_PASSWORD=changeme \
    OVCP_OPENVPN_GROUP=nobody
VOLUME /var/lib/ovcp
EXPOSE 1194/udp 8443/tcp
ENTRYPOINT ["ovcp"]
CMD ["serve"]
