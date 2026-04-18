#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./build/netpeek}"
IFACE="${2:-eth0}"
TARGET="${3:-127.0.0.1}"
PORTS="${4:-1-10000}"

if [[ $EUID -ne 0 ]]; then
  echo "run as root to manage tc netem" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "binary not found or not executable: $BIN" >&2
  exit 1
fi

cleanup() {
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
}
trap cleanup EXIT

echo "[bench] applying netem 5% loss on $IFACE"
tc qdisc del dev "$IFACE" root 2>/dev/null || true
tc qdisc add dev "$IFACE" root netem loss 5%

START=$(date +%s)
"$BIN" scan "$TARGET" -p "$PORTS" --connect --threads 256 --min-rate 5000 --max-rate 200000 >/tmp/netpeek_bench_rate.out 2>/tmp/netpeek_bench_rate.err || true
END=$(date +%s)
ELAPSED=$((END-START))

echo "[bench] elapsed=${ELAPSED}s"
echo "[bench] stderr tail:"
tail -n 30 /tmp/netpeek_bench_rate.err || true
