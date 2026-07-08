#!/bin/sh
# Roles:
#   serve    (default) all-in-one: init on first boot, then run ovcp, which
#            supervises openvpn (standalone mode).
#   openvpn  VPN-only, for the split-interface compose setup. Waits for the
#            config the app container renders, then runs openvpn directly.
#   *        passed straight to the ovcp CLI.
set -e
: "${OVCP_DATA:=/var/lib/ovcp}"

case "${1:-serve}" in
serve)
	if [ ! -f "$OVCP_DATA/pki/ca.crt" ]; then
		: "${OVCP_SERVER_CN:?first run: set OVCP_SERVER_CN, OVCP_CA_PASSPHRASE, OVCP_USER_PASSWORD}"
		: "${OVCP_CA_PASSPHRASE:?}" "${OVCP_USER_PASSWORD:?}"
		ovcp init -server-cn "$OVCP_SERVER_CN"
	fi
	exec ovcp serve ;;
openvpn)
	while [ ! -f "$OVCP_DATA/server.conf" ]; do
		echo "waiting for $OVCP_DATA/server.conf …"; sleep 1
	done
	exec openvpn --config "$OVCP_DATA/server.conf" ;;
*)
	exec ovcp "$@" ;;
esac
