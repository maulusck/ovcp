#!/bin/sh
# ovcp owns the data dir outright; `init -skeleton` is the one place that
# knows its layout/permissions. Honors OVCP_DATA if the installer set it.
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
OVCP_DATA="$DATA" ovcp init -skeleton
# SELinux (RHEL/Fedora): auto-labels if the box is confined, safe no-op
# elsewhere; never fails the install (see the script's own guards).
OVCP_DATA="$DATA" /usr/lib/ovcp/selinux.sh || true
# logrotate/log-shippers expect /var/log; symlink instead of duplicating files.
ln -sfn "$DATA/logs" /var/log/ovcp
# apk package is shared with Alpine (OpenRC) but OpenWrt runs procd — swap
# in the procd script when present (see deploy/nfpm.yaml's apk override).
if [ -f /etc/rc.common ] && [ -f /usr/lib/ovcp/ovcp.procd-init ]; then
	mv /usr/lib/ovcp/ovcp.procd-init /etc/init.d/ovcp
	chmod 755 /etc/init.d/ovcp
fi
