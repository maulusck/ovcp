#!/bin/bash
# Live acceptance: `scripts/vm-acceptance.sh purge` resets both machines (rebooting
# the client) and verifies the clean slate; `apk` installs the .apk on the client
# (OpenRC) and checks it; plain `scripts/vm-acceptance.sh` then
# builds a .deb, installs it here (systemd) and drives the Alpine client
# $OVCP_TEST_VM. Host uplink, address and gateway come from the default
# route. Needs passwordless sudo. Purge again afterwards.
set -u
T=$(mktemp -d)
export PATH=/usr/sbin:$PATH
SRC=$(cd "$(dirname "$0")/.." && pwd)
VM=${OVCP_TEST_VM:-root@10.254.254.3}               # Alpine client, key-auth root ssh
read -r GW UPLINK < <(ip route show default | awk '{print $3, $5; exit}')
SRV=$(ip -4 -br addr show "$UPLINK" | awk '{sub(/\/.*/, "", $3); print $3}')
CA='Test-CA-pass1' ADM='Test-admin-pass1'
FAILS=0 PASSES=0
pass() { echo "PASS  $1"; PASSES=$((PASSES+1)); }
fail() { echo "FAIL  $1"; FAILS=$((FAILS+1)); }
t() { local n=$1; shift; if eval "$*" >/dev/null 2>&1; then pass "$n"; else fail "$n"; fi; }
C() { ssh -o BatchMode=yes -o ConnectTimeout=5 $VM "$@"; }
O() { sudo -n ovcp "$@"; }
creds() { # serve and the workers it runs: ovcp, CapEff 0x1400, NoNewPrivs=$1
	local n=0 p serve
	serve=$(pgrep -f '^/usr/bin/ovcp serve') || return 1
	for p in $serve $(pgrep -P $serve); do
		[ "$(stat -c %U /proc/$p)" = ovcp ] || return 1
		grep -q '^CapEff:.*0000000000001400$' /proc/$p/status || return 1
		grep -q "^NoNewPrivs:.*$1\$" /proc/$p/status || return 1
		n=$((n+1))
	done
	[ $n -eq 3 ]
}
connect() { # $1 = extra openvpn args
	C "pkill openvpn; timeout 20 sh -c 'while pgrep openvpn >/dev/null; do sleep 0.5; done'; rm -f /tmp/ovpn.log;
	   openvpn --config vm3.ovpn $1 --daemon --log /tmp/ovpn.log;
	   timeout 40 sh -c 'until grep -q \"Initialization Sequence Completed\" /tmp/ovpn.log; do sleep 1; done'"
}
purge() { # clean slate on both machines, then verify it
	local i boot
	sudo -n systemctl disable --now ovcp >/dev/null 2>&1
	sudo -n apt-get purge -y ovcp >/dev/null 2>&1
	sudo -n rm -rf /var/lib/ovcp /run/ovcp /var/log/ovcp /etc/systemd/system/ovcp.service.d
	sudo -n systemctl daemon-reload
	sudo -n userdel ovcp 2>/dev/null; sudo -n groupdel ovcp 2>/dev/null
	sudo -n nft delete table inet ovcp-upstreams 2>/dev/null
	for i in $(seq 0 63); do # ovcp's band: tables 100-163, rule priorities 20000-20063
		sudo -n ip rule del priority $((20000+i)) 2>/dev/null
		sudo -n ip route flush table $((100+i)) 2>/dev/null
	done
	sudo -n ip link del ovcp0 2>/dev/null
	while sudo -n iptables -t nat -D POSTROUTING -o $UPLINK -j MASQUERADE 2>/dev/null; do :; done
	pgrep -f '^ssh -o BatchMode=yes -f -N -D' | xargs -r kill
	C 'apk del -q ovcp 2>/dev/null; deluser ovcp 2>/dev/null; delgroup ovcp 2>/dev/null; rm -rf /var/lib/ovcp /run/ovcp /var/log/ovcp /root/vm3.ovpn /tmp/ovpn.log' >/dev/null 2>&1
	boot=$(C cat /proc/sys/kernel/random/boot_id)
	C reboot >/dev/null 2>&1
	timeout 240 sh -c "until b=\$(ssh -o BatchMode=yes -o ConnectTimeout=3 $VM cat /proc/sys/kernel/random/boot_id 2>/dev/null) && [ -n \"\$b\" ] && [ \"\$b\" != '$boot' ]; do sleep 3; done"
	t "purged: no package" "! dpkg -s ovcp"
	t "purged: no account" "! id ovcp"
	t "purged: no data, runtime, log or unit override" "! ls -d /var/lib/ovcp /run/ovcp /var/log/ovcp /etc/systemd/system/ovcp.service.d"
	t "purged: no ovcp0, nft table or ovcp NAT rule" "! ip link show ovcp0 && ! sudo -n nft list table inet ovcp-upstreams && ! sudo -n iptables -t nat -S POSTROUTING | grep -q -- '-o $UPLINK -j MASQUERADE'"
	t "purged: no rule or route in ovcp's band" "! ip rule | grep -qE '^200[0-6][0-9]:' && [ -z \"\$(for i in \$(seq 100 163); do ip route show table \$i; done)\" ]"
	t "purged: client rebooted (new boot id)" "[ -n \"\$(C cat /proc/sys/kernel/random/boot_id)\" ] && [ \"\$(C cat /proc/sys/kernel/random/boot_id)\" != '$boot' ]"
	t "purged: client has no openvpn, ovcp package, account or data" "! C 'pgrep openvpn || apk info -e ovcp || id ovcp || ls -d /var/lib/ovcp'"
}
connected() { timeout 90 sh -c "until sudo -n ovcp status 2>/dev/null | grep -q ' vm3 '; do sleep 2; done"; }

if [ "${1:-}" = purge ]; then
	echo "== purge"; purge; echo "== RESULT: $PASSES passed, $FAILS failed"; rm -rf "$T"; [ $FAILS -eq 0 ]; exit
fi

if [ "${1:-}" = apk ]; then # the .apk on the Alpine client (OpenRC) instead of the .deb here; purge around it
	echo "== apk (OpenRC, on the client)"
	cd $SRC && rm -f dist/*.apk && make apk >$T/apk.log 2>&1 && scp -q dist/*.apk $VM:/root/ovcp.apk
	t "apk add: postinstall finds every file it calls" "C 'modprobe tun; apk add -q dnsmasq && apk add --allow-untrusted /root/ovcp.apk' >$T/add.log 2>&1 && ! grep -qi 'not found' $T/add.log"
	t "init, rc-service start" "C 'OVCP_CA_PASSPHRASE=$CA OVCP_USER_PASSWORD=$ADM ovcp init -server-cn vm3.example && rc-service ovcp start' && sleep 6"
	t "serve + workers: ovcp, CapEff 0x1400, NoNewPrivs 0 (OpenRC)" "C \"\$(declare -f creds); creds 0\""
	echo "== RESULT: $PASSES passed, $FAILS failed"; rm -rf "$T"; [ $FAILS -eq 0 ]; exit
fi

# forwarding is the operator's choice; neither ovcp nor this script sets it
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || { echo "enable forwarding first: sudo sysctl -w net.ipv4.ip_forward=1" >&2; exit 2; }

echo "== build"
cd $SRC && rm -f dist/*.deb && make deb >$T/deb.log 2>&1
DEB=$(ls dist/ovcp_*.deb 2>/dev/null)
t "deb built, untagged version 0.0.0~<hash>, not dirty" "echo '$DEB' | grep -qE 'ovcp_0\.0\.0~[0-9a-f]+_amd64\.deb$'"

echo "== install (.deb, systemd)"
t "apt install" "sudo -n apt-get install -y ./$DEB"
t "postinstall created system account ovcp (nologin)" "getent passwd ovcp | grep -q ':/usr/sbin/nologin$'"
t "/var/lib/ovcp owned by ovcp, 0700" "[ \"\$(sudo -n stat -c '%U %a' /var/lib/ovcp)\" = 'ovcp 700' ]"
t "/var/log/ovcp symlink" "[ -L /var/log/ovcp ]"

echo "== init as root"
t "init" "sudo -n env OVCP_CA_PASSPHRASE=$CA OVCP_USER_PASSWORD=$ADM ovcp init -server-cn $SRV"
t "nothing in data dir owned by anyone but ovcp" "[ -z \"\$(sudo -n find /var/lib/ovcp ! -user ovcp)\" ]"
t "pki/ca.key.enc 0600" "[ \"\$(sudo -n stat -c %a /var/lib/ovcp/pki/ca.key.enc)\" = 600 ]"

echo "== service (shipped unit + documented OVCP_LISTEN override)"
sudo -n mkdir -p /etc/systemd/system/ovcp.service.d
printf '[Service]\nEnvironment=OVCP_LISTEN=127.0.0.1:8443,10.8.0.1:8443\n' | sudo -n tee /etc/systemd/system/ovcp.service.d/listen.conf >/dev/null
sudo -n systemctl daemon-reload
t "systemctl enable --now" "sudo -n systemctl enable --now ovcp"
sleep 6
t "unit active" "systemctl is-active -q ovcp"
t "ovcp+openvpn+dnsmasq: user ovcp, CapEff 0x1400, NoNewPrivs 1" "creds 1"
t "tunnel interface ovcp0 10.8.0.1" "ip -br a show ovcp0 | grep -q 10.8.0.1/24"
t "dnsmasq bound 10.8.0.1:53 (NET_BIND_SERVICE)" "ss -lun | grep -q '10.8.0.1:53 '"
t "UI on loopback and tunnel" "ss -ltn | grep -q '127.0.0.1:8443' && ss -ltn | grep -q '10.8.0.1:8443'"
t "sudo ovcp status reaches serve (CLI drop)" "O status | grep -q '^OpenVPN: running'"
t "status warns: NAT missing" "O status 2>&1 | grep -q 'no outbound NAT'"
t "serve logged the routing warning at start" "sudo -n journalctl --no-pager _PID=\$(pgrep -f '^/usr/bin/ovcp serve') | grep -q 'no outbound NAT'"
sudo -n iptables -t nat -A POSTROUTING -o $UPLINK -j MASQUERADE
t "status: NAT warning gone" "! O status 2>&1 | grep -q 'no outbound NAT'"
t "IP server CN: no DOMAIN pushed" "! sudo -n grep -q DOMAIN /var/lib/ovcp/server.conf"

echo "== client profile"
sudo -n env OVCP_CA_PASSPHRASE=$CA ovcp certificate issue -cn vm3 -export > $T/vm3.ovpn 2>/dev/null
t "profile issued: remote $SRV, 4 PEM blocks" "grep -q '^remote $SRV 1194' $T/vm3.ovpn && [ \$(grep -c BEGIN $T/vm3.ovpn) -eq 4 ]"

echo "== vm3 (fresh boot)"
timeout 180 sh -c "until ssh -o BatchMode=yes -o ConnectTimeout=3 $VM true 2>/dev/null; do sleep 3; done"
t "vm3 reachable after reboot" "C true"
t "vm3 tools" "C 'apk add -q openvpn bind-tools curl iputils >/dev/null; which openvpn dig curl traceroute'"
scp -q $T/vm3.ovpn $VM:/root/vm3.ovpn
C 'modprobe tun; sysctl -qw net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2'

echo "== split tunnel"
t "connect (route-nopull, 1.1.1.1 only)" "connect '--route-nopull --route-gateway 10.8.0.1 --route 1.1.1.1 255.255.255.255'"
t "1.1.1.1 via tun0" "C 'ip route get 1.1.1.1 | grep -q tun0'"
t "8.8.8.8 not via tun0" "! C 'ip route get 8.8.8.8 | grep -q tun0'"
t "traceroute 1.1.1.1 hop1 = 10.8.0.1" "C 'traceroute -n -m 1 -w 2 1.1.1.1 | grep -q 10.8.0.1'"
t "traceroute 1.1.1.1 hop2 answers through tunnel" "C 'traceroute -n -m 2 -w 2 1.1.1.1 | grep -qE \"^ 2  [0-9]\"'"
t "HTTPS to 1.1.1.1 through tunnel" "C 'curl -s -m 8 -o /dev/null https://1.1.1.1/'"
t "internal DNS: vm3 -> its tunnel IP (within one status interval + tick)" "C 'timeout 15 sh -c \"until dig +short +time=1 +tries=1 @10.8.0.1 vm3 | grep -q ^10.8.0.; do sleep 1; done\"'"
t "no bogus domain alias" "[ -z \"\$(C 'dig +short @10.8.0.1 vm3.254.254.2')\" ]"
t "UI over tunnel /healthz 200" "[ \"\$(C 'curl -sk -o /dev/null -w %{http_code} https://10.8.0.1:8443/healthz')\" = 200 ]"

echo "== full tunnel"
t "connect (pushed redirect-gateway)" "connect ''"
t "8.8.8.8 via tun0" "C 'ip route get 8.8.8.8 | grep -q tun0'"
t "HTTPS egress through VPN NAT" "C 'curl -s -m 8 -o /dev/null https://1.1.1.1/'"
t "no DOMAIN in PUSH_REPLY" "! C 'grep PUSH_REPLY /tmp/ovpn.log | grep -q DOMAIN'"
t "client logs no persist-key deprecation" "! C 'grep -qi persist-key /tmp/ovpn.log'"

echo "== API"
J='Content-Type: application/json'
t "bad login 401" "[ \"\$(curl -sk -o /dev/null -w %{http_code} -H '$J' -d '{\"username\":\"admin\",\"password\":\"x\"}' https://127.0.0.1:8443/api/login)\" = 401 ]"
rm -f $T/cj
t "login 200, HttpOnly+Secure+SameSite=Strict" "curl -sk -c $T/cj -D - -o /dev/null -H '$J' -d '{\"username\":\"admin\",\"password\":\"$ADM\"}' https://127.0.0.1:8443/api/login | grep -qi 'ovcp_session=.*HttpOnly; Secure; SameSite=Strict'"
t "authenticated GET 200" "[ \"\$(curl -sk -b $T/cj -o /dev/null -w %{http_code} https://127.0.0.1:8443/api/certs)\" = 200 ]"
t "no session 401" "[ \"\$(curl -sk -o /dev/null -w %{http_code} https://127.0.0.1:8443/api/certs)\" = 401 ]"
t "POST without CSRF 403" "[ \"\$(curl -sk -b $T/cj -X POST -H '$J' -d '{}' -o /dev/null -w %{http_code} https://127.0.0.1:8443/api/vpn/restart)\" = 403 ]"

echo "== upstream: iface (default)"
t "add iface upstream" "O upstream add -id wan -iface $UPLINK -gateway $GW"
t "set-default" "O upstream set-default -id wan"
t "fwmark rule installed" "ip rule | grep -q 'fwmark 0x64 lookup 100'"
t "table 100: egress + kill-switch" "ip route show table 100 | grep -q 'default via $GW' && ip route show table 100 | grep -q 'unreachable default'"
t "client egress via upstream" "C 'curl -s -m 8 -o /dev/null https://1.1.1.1/'"
t "nft rules match iifname ovcp0, no source-address trust" "sudo -n nft list table inet ovcp-upstreams | grep -q 'iifname \"ovcp0\" meta mark set' && ! sudo -n nft list table inet ovcp-upstreams | grep -q 'ip saddr 10.8.0.0/24'"
sudo -n nft -f - <<NFT
table inet spoofcheck {
	chain c {
		type filter hook postrouting priority 100; policy accept;
		iifname "$UPLINK" ip saddr 10.8.0.99 counter
		iifname "$UPLINK" ip saddr 10.8.0.99 meta mark 0x64 counter
	}
}
NFT
C "ip addr add 10.8.0.99/32 dev eth0; ip route add 1.1.1.1/32 via $SRV dev eth0 src 10.8.0.99; for i in 1 2 3; do dig +tries=1 +time=1 -b 10.8.0.99 @1.1.1.1 example.com >/dev/null 2>&1; done; ip route del 1.1.1.1/32 via $SRV dev eth0; ip addr del 10.8.0.99/32 dev eth0"
SPOOF=$(sudo -n nft list chain inet spoofcheck c | grep -o 'packets [0-9]*' | awk '{print $2}' | tr '\n' ' ')
t "spoofed 10.8.0.99 from LAN arrived (control: $SPOOF)" "[ \$(echo $SPOOF | cut -d' ' -f1) -gt 0 ]"
t "spoofed packets NOT marked for the upstream" "[ \$(echo $SPOOF | cut -d' ' -f2) -eq 0 ]"
sudo -n nft delete table inet spoofcheck

echo "== upstream: socks, per-client"
ssh -o BatchMode=yes -f -N -D 127.0.0.1:1080 localhost
t "socks upstream add" "O upstream add -id sox -socks socks5://127.0.0.1:1080"
t "assign vm3 (asks for restart)" "O upstream assign -cn vm3 -id sox 2>&1 | grep -q 'vpn restart'"
t "vpn restart" "O vpn restart"
t "vm3 reconnects" "connected"
t "relay listener owned by ovcp" "sudo -n ss -ltnp | grep ':20001' | grep -q '\"ovcp\"'"
t "client HTTPS via socks relay" "C 'curl -s -m 8 -o /dev/null https://1.1.1.1/'"
pgrep -f '^ssh -o BatchMode=yes -f -N -D 127.0.0.1:1080' | xargs -r kill; sleep 1
t "backend down: fails closed (no leak)" "! C 'curl -s -m 8 -o /dev/null https://1.1.1.1/'"
ssh -o BatchMode=yes -f -N -D 127.0.0.1:1080 localhost; sleep 1
t "backend up: recovers" "C 'curl -s -m 8 -o /dev/null https://1.1.1.1/'"
t "direct LAN connection to relay dropped" "[ \"\$(C 'curl -s -m 5 -o /dev/null -w %{http_code} http://$SRV:20001/')\" = 000 ]"
O upstream assign -cn vm3 -clear >/dev/null; O upstream set-default -clear >/dev/null
O upstream del -id sox >/dev/null; O upstream del -id wan >/dev/null
pgrep -f '^ssh -o BatchMode=yes -f -N -D 127.0.0.1:1080' | xargs -r kill
t "cleanup: no fwmark rules, no relay, baseline nft" "! ip rule | grep -q fwmark && ! sudo -n ss -ltn | grep -q ':2000[0-9]' && [ \$(sudo -n nft list table inet ovcp-upstreams | grep -c 'mark set') -eq 0 ]"
t "client egress back to transparent" "C 'curl -s -m 8 -o /dev/null https://1.1.1.1/'"

echo "== CLI"
t "backup create > private file (umask 077, owned by me)" "(umask 077; sudo -n env OVCP_BACKUP_PASSPHRASE=Test-backup-1 ovcp backup create > $T/final.bak) && [ \"\$(stat -c '%U %a' $T/final.bak)\" = \"$(id -un) 600\" ]"
sudo -n rm -rf /tmp/ovcp-final-restore
t "backup restore < private file (shell opens it, not ovcp)" "sudo -n env OVCP_BACKUP_PASSPHRASE=Test-backup-1 ovcp -data /tmp/ovcp-final-restore backup restore < $T/final.bak"
t "restored data intact (vm3 cert)" "O -data /tmp/ovcp-final-restore certificate list | grep -q 'client vm3'"
t "restored dir owned by ovcp" "[ \"\$(sudo -n stat -c %U /tmp/ovcp-final-restore)\" = ovcp ]"
t "restore refuses a file argument" "! sudo -n env OVCP_BACKUP_PASSPHRASE=Test-backup-1 ovcp -data /tmp/ovcp-final-restore backup restore -force $T/final.bak < /dev/null"
sudo -n rm -rf /tmp/ovcp-final-restore $T/final.bak
t "certificate issue -out is gone" "! O certificate issue -cn x -out /tmp/x 2>&1 | grep -q serial"
t "duplicate active CN refused (schema index)" "! sudo -n env OVCP_CA_PASSPHRASE=$CA ovcp certificate issue -cn vm3 >/dev/null 2>&1"
t "logs rotate" "O logs rotate"
t "user add operator" "sudo -n env OVCP_USER_PASSWORD=Ops-pass-12 ovcp user add -name ops -role operator"
t "audit has login + issue" "O audit | grep -q login && O audit | grep -q issue"
t "stats has samples" "O stats | grep -q 'sample'"

echo "== kill"
t "vpn kill: client told to HALT, its openvpn exits" "O vpn kill -cn vm3 && C 'timeout 15 sh -c \"while pgrep openvpn >/dev/null; do sleep 1; done\"'"
t "vpn kill of a disconnected CN fails" "timeout 20 sh -c 'while sudo -n ovcp status | grep -q \" vm3 \"; do sleep 1; done' && ! O vpn kill -cn vm3"
t "reconnect for revoke" "connect ''"

echo "== revoke"
SER=$(O -json certificate list | python3 -c 'import sys,json;print([c["serial"] for c in json.load(sys.stdin) if c["cn"]=="vm3" and c["status"]!="revoked"][0])')
t "revoke vm3" "sudo -n env OVCP_CA_PASSPHRASE=$CA ovcp certificate revoke -serial $SER"
t "revoke restarts the session; reconnect refused (no manual kill)" "timeout 20 sh -c 'until sudo -n tail -n 300 /var/lib/ovcp/logs/openvpn.log | grep -q \"certificate revoked\"; do sleep 1; done'"
sudo -n env OVCP_CA_PASSPHRASE=$CA ovcp certificate issue -cn vm3 -export > $T/vm3.ovpn 2>/dev/null
scp -q $T/vm3.ovpn $VM:/root/vm3.ovpn
t "reissued profile connects" "connect ''"

echo "== service restart"
t "systemctl restart" "sudo -n systemctl restart ovcp"
t "vm3 reconnects after restart" "connected"
t "creds after restart" "creds 1"
t "data dir still all ovcp-owned" "[ -z \"\$(sudo -n find /var/lib/ovcp ! -user ovcp)\" ]"

C 'pkill openvpn' >/dev/null 2>&1
echo "== RESULT: $PASSES passed, $FAILS failed"
rm -rf "$T"
[ $FAILS -eq 0 ]
