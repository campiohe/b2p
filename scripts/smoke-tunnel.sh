#!/usr/bin/env bash
# Manual smoke test: real cloudflared quick tunnel, loopback transfer.
# Usage: ./scripts/smoke-tunnel.sh
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; kill 0 2>/dev/null || true' EXIT
mkdir -p "$WORK/out"
head -c 30000000 /dev/urandom > "$WORK/blob.bin"

BIN="$PWD/target/debug/b2p"
(cd "$WORK/out" && "$BIN" receive --yes > "$WORK/code.txt" 2> "$WORK/recv.log") &
RECV_PID=$!

echo "Waiting for tunnel..."
for _ in $(seq 1 60); do
  CODE=$(grep -oP "b2p send '\K[^']+" "$WORK/code.txt" 2>/dev/null || true)
  [ -n "${CODE:-}" ] && break
  sleep 1
done
[ -n "${CODE:-}" ] || { echo "FAIL: no code after 60s"; cat "$WORK/recv.log"; exit 1; }

echo "Sending through $CODE"
"$BIN" send "$CODE" "$WORK/blob.bin"
wait "$RECV_PID"

cmp "$WORK/blob.bin" "$WORK/out/blob.bin" && echo "SMOKE_OK"
