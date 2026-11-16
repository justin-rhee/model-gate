#!/usr/bin/env bash
# Runs the gate against a fake model API in a throwaway folder. No real key, no network.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; gate="$here/../src/model_gate.py"
tmp="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$tmp"' EXIT
echo "only-the-gate-has-this" > "$tmp/key"
cat > "$tmp/gate.conf" <<CONF
UPSTREAM=http://127.0.0.1:8799
PORT=8798
TOKEN_FILE=$tmp/key
STATE_DIR=$tmp/state
LOG=$tmp/calls.jsonl
CAP=30
CONF
python3 "$here/fake_upstream.py" 8799 & python3 "$gate" serve --config "$tmp/gate.conf" >/dev/null &
sleep 1
agent_key="a-key-the-agent-found"   # the agent's own key, which should never get through
call() {
  curl -s -o /dev/null -w "agent call: %{http_code}\n" http://127.0.0.1:8798/v1/messages \
    -H "x-api-key: $agent_key" -H "content-type: application/json" \
    -d '{"model":"any","max_tokens":8,"messages":[]}'
}
echo '$ model-gate status'; python3 "$gate" status --config "$tmp/gate.conf"
call
echo; echo '$ model-gate open session-1'; python3 "$gate" open --config "$tmp/gate.conf" session-1
call; call; call
echo; echo '$ model-gate close'; python3 "$gate" close --config "$tmp/gate.conf"
call
echo; echo "log: $(wc -l < "$tmp/calls.jsonl" | tr -d ' ') lines, gate key in it: $(grep -c only-the-gate "$tmp/calls.jsonl" || true)"
