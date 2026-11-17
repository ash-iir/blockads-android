#!/bin/sh
# Rootless check of the helper's routing plan against a real kernel + iproute2
# (no WireGuard needed): builds the plan, applies it in a throw-away network
# namespace with a veth standing in for bawg0, prints rules/table/lookups,
# then runs `down` twice. Usage: IP=/path/to/ip ./netns-test.sh
# uidrange must be a mapped uid inside the user namespace, so the first app
# range is rewritten to 0-0 (the shell's uid) and the others are dropped.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
IP="${IP:-ip}"
(cd "$here" && go build -o /tmp/wghelper-test .)
cat > /tmp/wghelper-test.json <<'J'
{"privateKey":"yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=","addresses":["10.66.66.2/24"],
"peers":[{"publicKey":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","endpoint":"203.0.113.5:51820","allowedIPs":["0.0.0.0/0","::/0"]}],
"uidRanges":[{"start":10000,"end":10684},{"start":10686,"end":19999}],"appUid":10682,"excludeLan":true,"killSwitch":true}
J
/tmp/wghelper-test plan -config /tmp/wghelper-test.json > /tmp/wghelper-plan.txt
unshare -rn sh -s "$IP" <<'S'
IP="$1"
$IP link set lo up
$IP link add wan0 type veth peer name wanp; $IP link set wan0 up; $IP link set wanp up
$IP addr add 192.0.2.10/24 dev wan0; $IP -6 addr add 2001:db8:1::10/64 dev wan0 nodad
$IP route add default via 192.0.2.1 dev wan0; $IP -6 route add default via 2001:db8:1::1 dev wan0
$IP link add bawg0 type veth peer name bawgp; $IP link set bawgp up
sed -n '1,/teardown/p' /tmp/wghelper-plan.txt | grep '^ip ' | grep -v 'link add' \
  | sed "s#uidrange 10000-10684 #uidrange 0-0 #" | grep -v 'uidrange 1' | sed "s#^ip #$IP #" | sh -e
$IP -4 rule show; $IP -6 rule show; $IP -4 route show table 980; $IP -6 route show table 980
for a in "8.8.8.8" "8.8.8.8 ipproto udp dport 53" "192.168.1.5" "10.66.66.7" "1.1.1.1 mark 0x40000000"; do
  printf '%-32s -> ' "$a"; $IP route get $a 2>&1 | head -1; done
for a in "2001:4860::8888" "2001:4860::8888 ipproto udp dport 53"; do
  printf '%-32s -> ' "$a"; $IP -6 route get $a 2>&1 | head -1; done
/tmp/wghelper-test down -ip "$IP"; /tmp/wghelper-test down -ip "$IP"
echo "after down:"; $IP -4 rule show; $IP -6 rule show; $IP link show bawg0 2>&1 | head -1
S
