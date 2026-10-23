#!/bin/sh
# End to end over public relays: pairing, policy, the phone saying no, and each member going down.
cd "$(dirname "$0")/.."
B=$(cat logs/bunker.txt)
start() { (node server.ts data/$1 > logs/$1.log 2>&1 &) ; }
stop()  { pkill -f "server.ts data/$1"; }
phone() { pkill -f fake-phone.ts; sleep 0.5; (node test/fake-phone.ts $1 > logs/phone.log 2>&1 &) ; }
run()   { echo "\n=== $1"; node test/client.ts "$B" $2 | grep -E "sign kind|ERROR"; }

stop a; stop b; pkill -f fake-phone.ts; sleep 1
start a; start b; phone; sleep 6
run "all three up: note goes A+B, profile goes A+phone" "1 0"
phone --deny; sleep 3
run "phone says no: note still signs, profile refused" "1 0"
pkill -f fake-phone.ts; sleep 1
run "phone off: note still signs, profile refused" "1 0"
phone; stop a; echo "\n(server A stopped; B takes over the bunker after 30 s)"; sleep 36
run "server A down: B coordinates; note goes B+phone, profile B+phone" "1 0"
start a; sleep 6
run "A back: A answers again" "1"
echo "\n--- who did what ---"; grep -hE "signed|refused|could not" logs/a.log logs/b.log | tail -12; tail -6 logs/phone.log
