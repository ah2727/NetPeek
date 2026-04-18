#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./build/netpeek}"
TARGET="${2:-127.0.0.1}"
PORTS="${3:-1-65535}"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found or not executable: $BIN" >&2
  exit 1
fi

echo "[bench] connect backend scan: target=$TARGET ports=$PORTS"
START=$(date +%s)
"$BIN" scan "$TARGET" -p "$PORTS" --connect --threads 512 --min-rate 50000 --max-rate 500000 >/tmp/netpeek_bench_connect.out 2>/tmp/netpeek_bench_connect.err || true
END=$(date +%s)
ELAPSED=$((END-START))

echo "[bench] elapsed=${ELAPSED}s"
echo "[bench] stderr tail:"
tail -n 20 /tmp/netpeek_bench_connect.err || true
