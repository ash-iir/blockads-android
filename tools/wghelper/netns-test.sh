#!/bin/sh
# Check of the helper's netlink path against a real kernel, in a throw-away
# network namespace: `selftest`, then `apply` (addresses, routes and rules
# over netlink; a dummy/veth stands in for bawg0, no WireGuard needed), route
# lookups, foreign rules in our pref range survive `down`, `down` twice.
# The helper itself never runs `ip` here (it is only a fallback); `ip` is
# used for setup and inspection.
#
# As root (CI):            go build -o /tmp/wghelper-test . &&
#                          sudo WGHELPER_BIN=/tmp/wghelper-test ./netns-test.sh
# Rootless (user ns):      ./netns-test.sh   (uid ranges must be mapped:
#                          the script maps uid 10000 when not root)
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
IP="${IP:-ip}"
BIN="${WGHELPER_BIN:-}"
if [ -z "$BIN" ]; then BIN=/tmp/wghelper-test; (cd "$here" && go build -o "$BIN" .); fi
cat > /tmp/wghelper-test.json <<'J'
{"privateKey":"yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=","addresses":["10.66.66.2/24"],
"peers":[{"publicKey":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","endpoint":"203.0.113.5:51820","allowedIPs":["0.0.0.0/0","::/0"]}],
"uidRanges":[{"start":10000,"end":10000}],"excludeLan":true,"killSwitch":true}
J
"$BIN" plan -config /tmp/wghelper-test.json

if [ "$(id -u)" = 0 ]; then
  NS="unshare -n"
else
  NS="unshare -n --map-user=10000 --map-group=10000 --keep-caps"
fi
$NS sh -s "$IP" "$BIN" <<'S'
set -eu
IP="$1"; BIN="$2"
fail() { echo "FAIL: $*"; exit 1; }
$IP link set lo up
$IP link add wan0 type veth peer name wanp; $IP link set wan0 up; $IP link set wanp up
$IP addr add 192.0.2.10/24 dev wan0; $IP -6 addr add 2001:db8:1::10/64 dev wan0 nodad
$IP route add default via 192.0.2.1 dev wan0; $IP -6 route add default via 2001:db8:1::1 dev wan0

echo "== selftest"; "$BIN" selftest

# Foreign rules inside our pref range: down must leave them alone.
$IP -4 rule add pref 10050 uidrange 10000-19999 lookup 1050
$IP -4 rule add pref 10002 iif lo uidrange 19999-19999 lookup 980   # matches local traffic of uid 19999 only
$IP -6 rule add pref 10099 unreachable

echo "== apply"; "$BIN" apply -config /tmp/wghelper-test.json
"$BIN" rules
$IP -4 rule show; $IP -6 rule show
$IP -4 route show table 980; $IP -6 route show table 980
"$BIN" rules | grep -q 'pref 10003 ipproto udp dport 53 goto 10099  \[ours\]' || fail "v4 udp dns rule"
"$BIN" rules | grep -q 'ip -6 rule add pref 10004 ipproto tcp dport 53 goto 10099  \[ours\]' || fail "v6 tcp dns rule"
$IP -4 route show table 980 | grep -q '^default dev bawg0' || fail "v4 default route"
$IP -4 route show table 980 | grep -q 'throw 192.168.0.0/16' || fail "throw lan"
$IP -6 route show table 980 | grep -q 'unreachable default' || fail "v6 unreachable"

get() { $IP "$@" 2>&1 | head -1; }
r=$(get route get 8.8.8.8 uid 10000);                      echo "uid 10000 8.8.8.8          -> $r"; echo "$r" | grep -q 'dev bawg0' || fail "app not in tunnel"
r=$(get route get 8.8.8.8 uid 10000 ipproto udp dport 53); echo "uid 10000 8.8.8.8 udp/53   -> $r"; echo "$r" | grep -q 'dev wan0' || fail "dns must bypass tunnel"
r=$(get route get 8.8.8.8 uid 10000 ipproto tcp dport 53); echo "uid 10000 8.8.8.8 tcp/53   -> $r"; echo "$r" | grep -q 'dev wan0' || fail "tcp dns must bypass tunnel"
r=$(get route get 8.8.8.8 uid 10001);                      echo "uid 10001 8.8.8.8          -> $r"; echo "$r" | grep -q 'dev wan0' || fail "unrouted uid"
r=$(get route get 192.168.1.5 uid 10000);                  echo "uid 10000 192.168.1.5      -> $r"; echo "$r" | grep -q 'dev wan0' || fail "lan excluded"
r=$(get route get 10.66.66.7 uid 10000);                   echo "uid 10000 10.66.66.7       -> $r"; echo "$r" | grep -q 'dev bawg0' || fail "tunnel subnet"
r=$(get route get 1.1.1.1 mark 0x40000000);                echo "probe mark 1.1.1.1         -> $r"; echo "$r" | grep -q 'dev bawg0' || fail "probe rule"
r=$(get -6 route get 2001:4860::8888 uid 10000);           echo "uid 10000 v6               -> $r"; echo "$r" | grep -qi 'unreachable\|Network is unreachable' || fail "v6 must be blocked"
r=$(get -6 route get 2001:4860::8888 uid 10000 ipproto udp dport 53); echo "uid 10000 v6 udp/53         -> $r"
echo "$r" | grep -q 'dev wan0' || fail "v6 dns must bypass"

echo "== down x2"
"$BIN" down || fail "down"
"$BIN" down || fail "down (2nd)"
echo "after down:"; $IP -4 rule show; $IP -6 rule show
$IP -4 rule show | grep -q '^10050:.*lookup 1050' || fail "foreign 10050 removed"
$IP -4 rule show | grep -q '^10002:.*iif lo.*lookup 980' || fail "foreign 10002 (iif lo) removed"
$IP -6 rule show | grep -q '^10099:.*unreachable' || fail "foreign v6 10099 unreachable removed"
[ -z "$("$BIN" rules | grep '\[ours\]' || true)" ] || fail "rules left"
[ -z "$($IP -4 route show table 980 2>/dev/null)" ] || fail "v4 table left"
[ -z "$($IP -6 route show table 980 2>/dev/null)" ] || fail "v6 table left"
! $IP link show bawg0 >/dev/null 2>&1 || fail "bawg0 left"
echo "netns test OK"
S
