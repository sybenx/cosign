#!/bin/sh
# The Keykin dry-run stack on this machine, without Docker: two relays (nak, in memory), three Keykin servers, a push
# stub, all on 127.0.0.1, and one TLS front door on the tailnet address (proxy.mjs). Everything lives in this folder;
# stop.sh ends it all. Test servers only: no live host is named anywhere here.
#   ./start.sh <tailnet name, e.g. mini.example.ts.net> <tailnet IPv4>
set -eu
cd "$(dirname "$0")"
NAME="$1"; IP="$2"; HERE="$(pwd)"; KK="$HERE/keykin"
mkdir -p run logs
[ -f "run/$NAME.crt" ] || { echo "no certificate: run 'tailscale cert --cert-file run/$NAME.crt --key-file run/$NAME.key $NAME' first"; exit 2; }
start() { n="$1"; shift; nohup "$@" > "logs/$n.log" 2>&1 & echo $! > "run/$n.pid"; }
start relay1 ./bin/nak serve --hostname 127.0.0.1 --port 7781
start relay2 ./bin/nak serve --hostname 127.0.0.1 --port 7782
start pushstub node -e "require('http').createServer((q,s)=>{let n=0;q.on('data',c=>n+=c.length);q.on('end',()=>{console.log(JSON.stringify({push:q.url,bytes:n}));s.writeHead(201);s.end()})}).listen(8090,'127.0.0.1')"
start proxy node proxy.mjs "$IP" 443 "run/$NAME.crt" "run/$NAME.key"
sleep 2
for k in 1 2 3; do
  mkdir -p "data/s$k" "keys/s$k"
  ( cd "$KK" && KEYKIN_RELAYS="wss://$NAME/r1,wss://$NAME/r2" KEYKIN_DATA="$HERE/data/s$k" KEYKIN_KEYS="$HERE/keys/s$k" KEYKIN_PORT=871$k KEYKIN_BIND=127.0.0.1 \
    KEYKIN_HTTPS="https://$NAME/s$k" KEYKIN_NAME="s$k" KEYKIN_PUSH_HOSTS=127.0.0.1:8090 KEYKIN_PUSH_HTTP=1 KEYKIN_TRUST_PROXY=1 \
    nohup node server/main.ts > "$HERE/logs/s$k.log" 2>&1 & echo $! > "$HERE/run/s$k.pid" )
done
sleep 4
echo "front-door host keys (for the CLI's --fronts):"
for k in 1 2 3; do grep -o '"host":"[0-9a-f]*"' "logs/s$k.log" | head -1 | cut -d'"' -f4; done
