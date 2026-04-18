#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./build/netpeek}"
CIDR="${2:-10.0.0.0/16}"
PORTS="${3:-80}"

if [[ $EUID -ne 0 ]]; then
  echo "run as root for raw SYN scan" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "binary not found or not executable: $BIN" >&2
  exit 1
fi

echo "[bench] SYN scan: cidr=$CIDR ports=$PORTS"
START=$(date +%s)
"$BIN" scan "$CIDR" -p "$PORTS" --syn --threads 1024 --min-rate 200000 --max-rate 1000000 >/tmp/netpeek_bench_syn.out 2>/tmp/netpeek_bench_syn.err || true
END=$(date +%s)
ELAPSED=$((END-START))

echo "[bench] elapsed=${ELAPSED}s"
echo "[bench] stderr tail:"
tail -n 20 /tmp/netpeek_bench_syn.err || true
