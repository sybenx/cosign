#!/bin/sh
# Ends everything start.sh began (by the pids it wrote), and nothing else.
cd "$(dirname "$0")"
for f in run/*.pid; do [ -f "$f" ] || continue; kill "$(cat "$f")" 2>/dev/null; rm -f "$f"; done
echo stopped
