#!/bin/sh
# SELinux (RHEL/Fedora): openvpn runs confined (openvpn_t) and cannot read
# the non-standard /var/lib/ovcp without labels. ovcp itself runs
# unconfined_service_t and needs nothing. Adjust OVCP_DATA if you moved it.
set -e
DATA="${OVCP_DATA:-/var/lib/ovcp}"
semanage fcontext -a -t openvpn_etc_t "${DATA}(/.*)?"
semanage fcontext -a -t openvpn_var_log_t "${DATA}/status\.log"
semanage fcontext -a -t openvpn_var_log_t "${DATA}/openvpn\.log"
restorecon -R "$DATA"
# /run/ovcp is created by systemd (RuntimeDirectory) as var_run_t: fine.
