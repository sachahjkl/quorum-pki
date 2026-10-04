#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GO:=go}"
export CGO_ENABLED=0
mkdir -p bin
"$GO" build -o bin/node ./cmd/node
"$GO" build -o bin/request ./cmd/request
"$GO" build -o bin/verifier ./cmd/verifier
run_dir=$(mktemp -d)
pids=()
cleanup() { for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM
bin/node -role init -data "$run_dir"
bin/node -role registry -data "$run_dir" -listen 127.0.0.1:8081 > "$run_dir/registry.log" 2>&1 & pids+=("$!")
for i in 1 2 3 4 5; do
  bin/node -role validator -id "ca-$i" -data "$run_dir" -listen "127.0.0.1:$((8100+i))" > "$run_dir/ca-$i.log" 2>&1 & pids+=("$!")
done
bin/node -role witness -id witness-1 -data "$run_dir" -listen 127.0.0.1:8082 > "$run_dir/witness.log" 2>&1 & pids+=("$!")
# Bounded readiness polling, no fixed startup ordering assumption.
for i in $(seq 1 50); do if curl -sf http://127.0.0.1:8081/v1/checkpoint > /dev/null; then break; fi; sleep .1; done
bin/node -role coordinator -data "$run_dir" -listen 127.0.0.1:8083 > "$run_dir/coordinator.log" 2>&1 & pids+=("$!")
for i in $(seq 1 50); do if curl -sf http://127.0.0.1:8083/v1/config > /dev/null; then break; fi; sleep .1; done
bin/request -data "$run_dir"
bin/verifier -config "$run_dir/config.json" -checkpoint "$run_dir/client.json"
python3 - "$run_dir/bundle.json" <<'PY' | curl -fsS -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8082/v1/observe
import sys,json
b=json.load(open(sys.argv[1]));print(json.dumps({'checkpoint':b['checkpoint'],'consistency':[]}))
PY
if [[ "${1:-}" == "--check" ]]; then exit 0; fi
printf '\nIndependent services ready. API/SSE: http://localhost:8083 · state: %s\n' "$run_dir"
wait
