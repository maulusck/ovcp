#!/bin/sh
# Labels the data dir for confined openvpn and dnsmasq (RHEL/Fedora); ovcp runs
# unconfined and writes both workers' logs itself. Honors OVCP_DATA.
set -e
# no-op unless SELinux is enforcing/permissive and the tooling exists
command -v getenforce >/dev/null 2>&1 || exit 0
[ "$(getenforce)" = "Disabled" ] && exit 0
command -v semanage >/dev/null 2>&1 || { echo "install policycoreutils-python-utils"; exit 1; }
DATA="${OVCP_DATA:-/var/lib/ovcp}"
semanage fcontext -a -t openvpn_etc_t "${DATA}(/.*)?"
semanage fcontext -a -t openvpn_var_log_t "${DATA}/logs(/.*)?"
# more specific than the openvpn_etc_t catch-all above, so it wins for --hostsdir
semanage fcontext -a -t dnsmasq_etc_t "${DATA}/dns(/.*)?"
restorecon -R "$DATA"
