#!/bin/sh
# ovcp runs as root and owns the data dir outright (PKI keys are 0600 root:root).
set -e
mkdir -p /var/lib/ovcp
chown root:root /var/lib/ovcp
chmod 700 /var/lib/ovcp
