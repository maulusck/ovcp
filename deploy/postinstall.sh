#!/bin/sh
# create the unprivileged service user and hand it the data dir
set -e
getent passwd ovcp >/dev/null || useradd -r -s /usr/sbin/nologin -d /var/lib/ovcp ovcp
mkdir -p /var/lib/ovcp
chown ovcp:ovcp /var/lib/ovcp
chmod 750 /var/lib/ovcp
