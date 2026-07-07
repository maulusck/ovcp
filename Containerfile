# all-in-one image: ovcp + openvpn, supervised by ovcp (standalone mode).
# run:  docker run -d --cap-add=NET_ADMIN --device /dev/net/tun \
#         -e OVCP_SERVER_CN=vpn.example.com \
#         -e OVCP_CA_PASSPHRASE=... -e OVCP_USER_PASSWORD=... \
#         -p 1194:1194/udp -p 127.0.0.1:8443:8443 -v ovcp:/var/lib/ovcp ovcp
FROM node:22-alpine AS ui
WORKDIR /src/web/ui
COPY web/ui/package*.json ./
RUN npm ci
COPY web/ui .
RUN npm run build

FROM golang:1.22-alpine AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
RUN CGO_ENABLED=1 go build -ldflags '-s -w' -o /ovcp ./cmd/ovcp

FROM alpine:latest
RUN apk add --no-cache openvpn
COPY --from=build /ovcp /usr/local/bin/ovcp
COPY deploy/entrypoint.sh /entrypoint.sh
ENV OVCP_DATA=/var/lib/ovcp \
    OVCP_LISTEN=0.0.0.0:8443 \
    OVCP_PLATFORM=standalone \
    OVCP_OPENVPN_GROUP=nobody
VOLUME /var/lib/ovcp
EXPOSE 1194/udp 8443/tcp
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget -q --no-check-certificate -O /dev/null https://127.0.0.1:8443/ || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["serve"]
