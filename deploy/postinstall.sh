#!/bin/sh
# ovcp runs as root and owns the data dir outright (PKI keys are 0600 root:root).
# Honors OVCP_DATA if the installer set it; matches selinux.sh's fallback.
set -e
DATA="${OVCP_DATA:-/var/lib/ovcp}"
mkdir -p "$DATA"
chown root:root "$DATA"
chmod 700 "$DATA"
