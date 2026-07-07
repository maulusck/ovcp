#!/bin/sh
# serve: init on first run, then run. openvpn: sidecar mode (compose/k8s).
# anything else: pass through to the CLI.
set -e
case "${1:-serve}" in
serve)
	if [ ! -f "$OVCP_DATA/pki/ca.crt" ]; then
		: "${OVCP_SERVER_CN:?first run: set OVCP_SERVER_CN, OVCP_CA_PASSPHRASE, OVCP_USER_PASSWORD}"
		: "${OVCP_CA_PASSPHRASE:?}" "${OVCP_USER_PASSWORD:?}"
		ovcp init -server-cn "$OVCP_SERVER_CN"
	fi
	exec ovcp serve ;;
openvpn)
	exec openvpn --config "$OVCP_DATA/server.conf" ;;
*)
	exec ovcp "$@" ;;
esac
