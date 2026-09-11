#!/usr/bin/env bash
# One-command demo launcher for ASAA.
# Starts the benchmark target and the ASAA server, seeds a clean demo state,
# and opens the dashboard. Ctrl+C stops everything.
set -e
cd "$(dirname "$0")"

PORT_APP=${PORT_APP:-8080}
PORT_TARGET=${PORT_TARGET:-8000}

echo "[ASAA] starting benchmark target on :$PORT_TARGET"
python scripts/mock_target.py "$PORT_TARGET" &
TARGET_PID=$!

echo "[ASAA] starting ASAA server on :$PORT_APP"
python -m uvicorn asaa.main:app --host 127.0.0.1 --port "$PORT_APP" &
APP_PID=$!

cleanup() { echo; echo "[ASAA] stopping"; kill $TARGET_PID $APP_PID 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# wait for health
for i in $(seq 1 40); do
  if curl -s -o /dev/null "http://127.0.0.1:$PORT_APP/api/health"; then break; fi
  sleep 0.5
done

echo "[ASAA] seeding demo state"
python scripts/seed.py "http://127.0.0.1:$PORT_APP" "http://127.0.0.1:$PORT_TARGET/" || true

echo
echo "==================================================================="
echo " ASAA dashboard:  http://127.0.0.1:$PORT_APP"
echo " Benchmark target: http://127.0.0.1:$PORT_TARGET"
echo " Press Ctrl+C to stop."
echo "==================================================================="
wait
