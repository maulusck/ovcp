#!/bin/sh
# SELinux (RHEL/Fedora): openvpn runs confined (openvpn_t) and cannot read
# the non-standard /var/lib/ovcp without labels. ovcp itself runs
# unconfined_service_t and needs nothing. Adjust OVCP_DATA if you moved it.
set -e
# no-op unless SELinux is enforcing/permissive and the tooling exists
command -v getenforce >/dev/null 2>&1 || exit 0
[ "$(getenforce)" = "Disabled" ] && exit 0
command -v semanage >/dev/null 2>&1 || { echo "install policycoreutils-python-utils"; exit 1; }
DATA="${OVCP_DATA:-/var/lib/ovcp}"
semanage fcontext -a -t openvpn_etc_t "${DATA}(/.*)?"
semanage fcontext -a -t openvpn_var_log_t "${DATA}/logs(/.*)?"
restorecon -R "$DATA"
# /run/ovcp is created by systemd (RuntimeDirectory) as var_run_t: fine.
