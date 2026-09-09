#!/usr/bin/env bash
# Boot a pulsar-go server binary, exercise its endpoints, shut it down.
# Usage: ./scripts/smoke.sh ./bin/server [port]
set -euo pipefail

BIN="${1:-./bin/server}"
PORT="${2:-8080}"
BASE="http://127.0.0.1:$PORT"

if [[ ! -x "$BIN" ]]; then
    echo "error: $BIN is not executable. Run 'make static' first." >&2
    exit 1
fi

"$BIN" &
SRV=$!
trap 'kill -INT $SRV 2>/dev/null || true; wait $SRV 2>/dev/null || true' EXIT

echo "==> Waiting for $BASE/ ..."
for i in $(seq 1 50); do
    if curl -sf -o /dev/null -m 1 "$BASE/"; then
        break
    fi
    if ! kill -0 $SRV 2>/dev/null; then
        echo "error: server exited before becoming ready" >&2
        exit 1
    fi
    sleep 0.1
    if [[ "$i" == 50 ]]; then
        echo "error: server never became ready" >&2
        exit 1
    fi
done

fail=0
check() { # check <desc> <curl-args...> -- <expected-substring>
    local desc="$1"; shift
    local expected="${*: -1}"
    local args=("${@:1:$#-1}")
    local out
    if ! out="$(curl -sf -m 5 "${args[@]}" 2>&1)"; then
        echo "FAIL: $desc (curl error): $out" >&2
        fail=1
        return
    fi
    if [[ "$out" != *"$expected"* ]]; then
        echo "FAIL: $desc: expected substring '$expected', got: $out" >&2
        fail=1
        return
    fi
    echo "ok: $desc"
}

check "GET /" "$BASE/" -- "Welcome to Pulsar Go!"
check "GET /user/123" "$BASE/user/123" -- '"id":"123"'
# The /user/0 route returns 404, so curl -f fails; assert status + body directly.
code="$(curl -s -o /tmp/pulsar-smoke-404.body -w '%{http_code}' -m 5 "$BASE/user/0" || true)"
body="$(cat /tmp/pulsar-smoke-404.body 2>/dev/null || true)"
[[ "$code" == "404" ]] && echo "ok: GET /user/0 -> 404" || { echo "FAIL: expected 404, got $code" >&2; fail=1; }
check "POST /api/v1/echo (auth)" -X POST "$BASE/api/v1/echo" \
    -H 'Content-Type: application/json' -H 'Authorization: Bearer x' \
    -d '{"message":"hi","from":"smoke"}' -- '"message":"hi"'
code="$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST "$BASE/api/v1/echo" \
    -H 'Content-Type: application/json' -d '{"message":"hi"}')"
[[ "$code" == "401" ]] && echo "ok: POST /api/v1/echo without auth -> 401" || { echo "FAIL: expected 401, got $code" >&2; fail=1; }
check "POST /form" -X POST "$BASE/form" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'name=john+doe' -- 'john doe'

if [[ "$fail" != 0 ]]; then
    echo "SMOKE FAILED" >&2
    exit 1
fi
echo "SMOKE PASSED"
