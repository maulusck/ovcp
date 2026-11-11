#!/bin/sh
# Every package's install and upgrade, and the image build: idempotent; honors
# OVCP_DATA. init -skeleton is the one owner of the data tree's layout.
set -e
DATA="${OVCP_DATA:-/var/lib/ovcp}"
# the account ovcp drops to (see dropRoot): useradd (deb/rpm) or adduser (apk/OpenWrt).
if ! id ovcp >/dev/null 2>&1; then
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --no-create-home --shell /usr/sbin/nologin ovcp
	else
		addgroup -S ovcp # busybox -S alone puts the user in the shared nogroup
		adduser -S -D -H -G ovcp -s /sbin/nologin ovcp
	fi
fi
ovcp init -skeleton
# SELinux (RHEL/Fedora): auto-labels if the box is confined, safe no-op
# elsewhere; never fails the install (see the script's own guards).
/usr/lib/ovcp/selinux.sh || true
# logrotate/log-shippers expect /var/log; symlink instead of duplicating files.
ln -sfn "$DATA/logs" /var/log/ovcp
# One .apk serves Alpine (OpenRC) and OpenWrt, which runs procd (/etc/rc.common):
# there the procd script replaces the OpenRC one.
if [ -f /etc/rc.common ] && [ -f /usr/lib/ovcp/ovcp.procd-init ]; then
	mv /usr/lib/ovcp/ovcp.procd-init /etc/init.d/ovcp
fi
