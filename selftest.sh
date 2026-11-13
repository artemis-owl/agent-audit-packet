#!/usr/bin/env bash
# Runs the mapper and the verifier over a real session kept in fixtures/ and
# over broken packets. Each case names the exit code and the line it
# expects; the first mismatch exits 1.
# Usage: ./selftest.sh
set -uo pipefail
cd "$(dirname "$0")"
fail() { echo "FAIL selftest: $*" >&2; exit 1; }
T="$(mktemp -d "${TMPDIR:-/tmp}/aap-selftest.XXXXXX")" || fail "no temporary directory"
trap 'rm -rf "$T"' EXIT
expect() {  # expect <exit code> <line the output must contain> <command...>
  local code="$1" line="$2"; shift 2
  local out; out="$("$@" 2>&1)"; local got=$?
  [ "$got" = "$code" ] || fail "\`$*\` exited $got, expected $code"
  case "$out" in *"$line"*) ;; *) fail "\`$*\` did not print: $line" ;; esac
  case "$out" in *Traceback*) fail "\`$*\` printed a traceback" ;; esac
}

expect 0 "PASS: packet is internally consistent" ./verify.sh
echo "ok   the sample packet passes"

expect 0 "mapped   5 evidence record(s), one per commit the report lists" \
  ./map-session.sh fixtures/0070-cloud-run-audit "$T/out"
[ -d "$T/out/corr-f39865b445dc0115" ] || fail "the mapper did not write corr-f39865b445dc0115"
echo "ok   the mapper writes corr-f39865b445dc0115 from the fixture session"

expect 1 "FAIL every evidence record closes the loop on an allowed decision: 5 evidence record(s) of an executed action under decision 'deny'" \
  ./verify.sh "$T/out/corr-f39865b445dc0115"
echo "ok   a session the audit failed is a named FAIL, exit 1"

cp -R "$T/out/corr-f39865b445dc0115" "$T/allowed"
sed -i.bak 's/"decision": "deny"/"decision": "allow"/' "$T/allowed/decision_traces.jsonl" && rm "$T/allowed/decision_traces.jsonl.bak"
expect 2 "not evidenced by this export: every evidence record closes the loop on an allowed decision: 5 of 5 evidence record(s) carry no details.policy_decision" \
  ./verify.sh "$T/allowed"
echo "ok   evidence with no recorded decision is not evidenced, exit 2"

for r in skipped error done; do
  cp -R packet/corr-500bdcb7dacac332 "$T/$r"
  sed -i.bak "s/\"result\":\"ok\"/\"result\":\"$r\"/" "$T/$r/evidence.jsonl" && rm "$T/$r/evidence.jsonl.bak"
done
expect 1 "FAIL no allowed decision is missing its evidence: allowed decisions whose only evidence records result 'skipped': ['corr-500bdcb7dacac332']" \
  ./verify.sh "$T/skipped"
expect 0 "ok   no allowed decision is missing its evidence; the action ran and its result is not 'ok' for: ['corr-500bdcb7dacac332']" \
  ./verify.sh "$T/error"
expect 1 "evidence.jsonl:1 records result 'done', not one of ok, error, skipped" ./verify.sh "$T/done"
echo "ok   a skipped action is not evidence, an error is named, an unknown result is a FAIL"

cp -R "$T/out/corr-f39865b445dc0115" "$T/broken"
echo '{not json' >> "$T/broken/evidence.jsonl"
expect 1 "evidence.jsonl:6 is not JSON" ./verify.sh "$T/broken"
rm "$T/broken/decision_traces.jsonl"
expect 1 "decision_traces.jsonl is missing" ./verify.sh "$T/broken"
expect 1 "FAIL packet: no such packet directory" ./verify.sh "$T/nowhere"
echo "ok   a broken or missing packet is a named FAIL, never a traceback"

expect 1 "FAIL: the source directory has no audit.json" ./map-session.sh "$T" "$T/out2"
echo "ok   a source directory with no audit result is a named FAIL"

echo "PASS: selftest"
