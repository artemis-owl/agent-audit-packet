#!/usr/bin/env bash
# Verifies one audit packet: schema integrity, record shape, and that the
# evidence closes the loop on the decision that authorized it.
# Usage: ./verify.sh [packet/corr-<id>]   (default: the sample packet)
set -euo pipefail
P="${1:-packet/corr-500bdcb7dacac332}"
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "packet: $P"
[ -d "$P" ] || fail "no such packet directory"

# 1. Schema files match their recorded hashes.
( cd "$P/schemas" && shasum -a 256 -c SHA256SUMS --quiet ) || fail "schema checksum mismatch"
echo "ok   schemas match SHA256SUMS"

# 2–5. Records parse and agree with each other and with the policy bundle.
python3 - "$P" <<'PY'
import json, sys, pathlib
p = pathlib.Path(sys.argv[1])
def jsonl(name):
    rows = [json.loads(l) for l in (p / name).read_text().splitlines() if l.strip()]
    assert rows, f"{name} is empty"
    return rows
traces = jsonl("decision_traces.jsonl")
evidence = jsonl("evidence.jsonl")
print(f"ok   {len(traces)} decision trace(s), {len(evidence)} evidence record(s) parse")

meta = json.loads((p / "policy/metadata.json").read_text())
for t in traces:
    assert t["policy"]["bundle_hash"] == meta["bundle_hash"], "trace cites a policy bundle other than the one shipped"
print("ok   every trace cites the shipped policy bundle:", meta["bundle_hash"][:19] + "…")

by_corr = {t["correlation_id"]: t for t in traces}
for e in evidence:
    t = by_corr.get(e["correlation_id"])
    assert t, f"evidence {e['event_id']} has no decision trace for {e['correlation_id']}"
    assert e["trace_id"] == t["trace_id"], "evidence and trace disagree on trace_id"
    assert e["action"] == t["request"]["action"], "evidence records a different action than was decided"
    assert e["details"]["policy_decision"] == t["policy"]["decision"], "evidence records a different decision than the trace"
    assert t["policy"]["decision"] == "allow", "an executed action was not allowed by policy"
print("ok   every evidence record closes the loop on an allowed decision")

orphans = [t["correlation_id"] for t in traces if t["correlation_id"] not in {e["correlation_id"] for e in evidence}]
assert not orphans, f"allowed decisions with no evidence of execution: {orphans}"
print("ok   no allowed decision is missing its evidence")

ptr = json.loads((p / "observability/pointers.json").read_text())
assert ptr["trace_id"] == traces[0]["trace_id"], "observability pointer does not match the trace"
print("ok   observability pointer matches the trace")
PY
echo "PASS: packet is internally consistent"
