#!/bin/sh
# ovcp runs as root and owns the data dir outright (PKI keys are 0600 root:root).
# Honors OVCP_DATA if the installer set it; matches selinux.sh's fallback.
set -e
DATA="${OVCP_DATA:-/var/lib/ovcp}"
mkdir -p "$DATA/logs"
chown root:root "$DATA"
chmod 700 "$DATA"
chmod 700 "$DATA/logs"
# logrotate/log-shippers expect /var/log; symlink instead of duplicating files.
ln -sfn "$DATA/logs" /var/log/ovcp
