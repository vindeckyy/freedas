#!/usr/bin/env bash
# End-to-end parity scenarios (plan §33.2). Run against the fake provider:
#   cargo build && FREEDAS_TEST_PROVIDER=fake scripts/e2e.sh
set -u
BIN=${FREEDAS_BIN:-./target/debug/freedas}
export FREEDAS_TEST_PROVIDER=fake
export FREEDAS_DATA=$(mktemp -d)/data
export FREEDAS_CONFIG_DIR=$(mktemp -d)/config
export FREEDAS_STATE=$(mktemp -d)/state
export FREEDAS_CACHE=$(mktemp -d)/cache
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ok: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
check(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1 :: $2"; fi }

proj() { local d; d=$(mktemp -d); cd "$d"; git init -q; echo "$d"; }

echo "== 1. quickstart =="
D=$(proj)
check "version"        "$BIN --version | grep -q freedas"
check "help"           "$BIN --help | grep -q run"
check "debug paths"    "$BIN debug paths | grep -q data"

echo "== 2. headless CI =="
cd "$D"
OUT=$($BIN run "WRITE:hello.txt:world" --auto --format json 2>"$D/write.err")
check "jsonl result"        "echo '$OUT' | grep -q '\"completed\":true'"
check "session.started evt" "echo '$OUT' | grep -q 'session.started'"
check "tool.result emitted" "echo '$OUT' | grep -q '\"type\":\"tool.result\"'"
check "session.marker evt"  "echo '$OUT' | grep -q '\"type\":\"session.marker\"'"
check "file written"        "test -f hello.txt && grep -q world hello.txt"
[ -s "$D/write.err" ] && sed 's/^/  write stderr: /' "$D/write.err"

echo "== 3. permissions =="
cd "$D"
echo SECRET=1 > .env; echo SAFE=1 > .env.example
mkdir -p .freedas && printf '{"permission":{"read":{".env":"ask","*.env.example":"allow"},"bash":{"rm -rf /":"deny"}}}' > .freedas/freedas.jsonc
OUT=$($BIN run "READ:.env" --format json 2>/dev/null)
check "env ask blocked"     "echo '$OUT' | grep -q 'read.*env'"
check "blocked array"       "echo '$OUT' | grep -q '\"blocked\"'"
check "env.example allowed" "$BIN run 'READ:.env.example' --format json 2>/dev/null | grep -q 'completed.*true'"
$BIN run "READ:.env" --format json >/dev/null 2>"$D/blocked.err"; RC=$?
check "blocked exits 3"     "[ $RC -eq 3 ]"
check "auto-rejecting stderr" "grep -q 'auto-rejecting' '$D/blocked.err'"

echo "== 3b. no sandbox backend =="
cd "$D"
mkdir -p fakepath
for t in bash sh git env uname id cat mkdir touch; do
  command -v "$t" >/dev/null 2>&1 && ln -sf "$(command -v "$t")" "fakepath/$t"
done
OUT=$(PATH="$PWD/fakepath" $BIN run "RUN:touch unsandboxed-marker" --auto --format json 2>"$D/nosandbox.err")
check "refuses unsandboxed" "echo '$OUT' | grep -qi 'sandbox backend'"
check "marker not written"  "test ! -e unsandboxed-marker"
PATH="$PWD/fakepath" FREEDAS_EXPERIMENTAL_SANDBOX=false $BIN run "RUN:touch opted-out-marker" --auto --format json >/dev/null 2>&1
check "opt-out runs direct" "test -e opted-out-marker"

echo "== 4. plan mode =="
cd "$D"
OUT=$($BIN run "WRITE:plan-forbidden.txt:x" --agent plan --format json 2>/dev/null)
check "plan cannot edit" "echo '$OUT' | grep -qiE 'denied|blocked|read-only' || ! test -f plan-forbidden.txt"

echo "== 5. sync =="
cd "$D"; mkdir -p .claude/skills/release .cursor/rules
echo "claude rules" > CLAUDE.md
echo "api rules"   > .cursor/rules/api.mdc
cat > .claude/skills/release/SKILL.md <<'EOF'
---
name: release
description: Cut a release
---
Draft notes from the last tag.
EOF
OUT=$($BIN sync --json 2>/dev/null || $BIN sync 2>/dev/null)
check "sync plans claude"   "echo '$OUT' | grep -q CLAUDE.md"
check "sync plans cursor"   "echo '$OUT' | grep -q api.mdc"
check "sync plans skill"    "echo '$OUT' | grep -q release"
$BIN sync apply >/dev/null 2>&1
check "markers written"     "grep -q 'freedas:sync:begin' AGENTS.md 2>/dev/null"
check "skill copied"        "test -f .freedas/skills/release/SKILL.md"

echo "== 6. worktrees =="
cd "$D"; git add -A; git -c user.email=t@t -c user.name=t commit -qm init 2>/dev/null || true
$BIN run "ECHO:a" --worktree w1 --format json >/dev/null 2>&1 || true
check "worktree created"    "git worktree list | grep -q w1"

echo "== 7. sessions round trip =="
cd "$D"
SID=$($BIN run "ECHO:abc" --format json 2>/dev/null | grep -o 'ses_[A-Z0-9]*' | head -1)
$BIN export "$SID" > /tmp/fexp.json 2>/dev/null
check "export has messages" "grep -q '\"role\"' /tmp/fexp.json || grep -q role /tmp/fexp.json"
check "export has session"  "grep -q '$SID' /tmp/fexp.json"
check "import ok"           "$BIN import /tmp/fexp.json 2>/dev/null | grep -q 'imported session'"
check "session list"        "$BIN session list | grep -q '$SID'"
check "session rename"      "$BIN session rename '$SID' renamed-e2e >/dev/null 2>&1 && $BIN session list | grep -q renamed-e2e"
check "agent list"          "$BIN agent list | grep -q build"
check "skill list runs"     "$BIN skill list >/dev/null 2>&1"

echo "== 8. mcp (config only) =="
check "mcp list" "$BIN mcp list >/dev/null 2>&1"

echo "== 9. memory =="
cd "$D"
$BIN run "remember that the api uses graphql" --format json >/dev/null 2>&1 || true
check "memory list cmd" "$BIN memory list >/dev/null 2>&1"

echo "== 10. server =="
PORT=4188
$BIN serve --port $PORT --hostname 127.0.0.1 &
SRVPID=$!; sleep 2
check "health"       "curl -sf http://127.0.0.1:$PORT/global/health | grep -q healthy"
check "create sess"  "curl -sf -X POST http://127.0.0.1:$PORT/session -H 'content-type: application/json' -d '{}' | grep -q ses_"
kill $SRVPID 2>/dev/null

echo "== 11. rules block =="
check "rules prints" "$BIN rules | grep -q 'Freedas picks the model'"

echo "== 12. upgrade/uninstall flags exist =="
check "uninstall help" "$BIN uninstall --help | grep -q keep-data"

echo "== 13. debug =="
check "debug prints sandbox status" "$BIN debug | grep -qi 'sandbox'"

echo
echo "PASS=$PASS FAIL=$FAIL"
exit $FAIL
