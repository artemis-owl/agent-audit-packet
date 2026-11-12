#!/usr/bin/env bash
# Maps one cloud agent session's source files into an audit packet.
# Usage: ./map-session.sh <source-dir> <out-dir> [--session ID] [--model NAME] [--target OWNER/REPO]
#
# <source-dir> holds what the commissioner kept of the session:
#   audit.json                               the commissioner's audit result (required)
#   RUN_REPORT.md | run_report.md            the agent's final report (required)
#   run-log.condensed.txt | run_log.txt      the run log (optional)
#   prepared.json                            the task's preparation record (optional)
# Writes <out-dir>/corr-<id>/ and prints what was mapped and what this export
# cannot evidence. Exit 0 when the packet is written, 1 on a named failure.
# Check the result with ./verify.sh <out-dir>/corr-<id>.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 -I - "$HERE" "$@" <<'PY'
import hashlib, json, pathlib, re, shutil, sys


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def first(directory, *names):
    for name in names:
        if (directory / name).is_file():
            return directory / name
    return None


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        fail(f"{path.name} is not JSON ({exc})")


def main():
    here, args = pathlib.Path(sys.argv[1]), sys.argv[2:]
    opts, pos = {}, []
    while args:
        a = args.pop(0)
        if a in ("--session", "--model", "--target"):
            if not args:
                fail(f"{a} needs a value")
            opts[a[2:]] = args.pop(0)
        else:
            pos.append(a)
    if len(pos) != 2:
        fail("usage: ./map-session.sh <source-dir> <out-dir> [--session ID] [--model NAME] [--target OWNER/REPO]")
    src, out = pathlib.Path(pos[0]), pathlib.Path(pos[1])
    if not src.is_dir():
        fail(f"no such source directory: {src}")

    audit_path = first(src, "audit.json")
    report_path = first(src, "RUN_REPORT.md", "run_report.md")
    log_path = first(src, "run-log.condensed.txt", "run_log.txt")
    prepared_path = first(src, "prepared.json")
    if audit_path is None:
        fail("the source directory has no audit.json (the commissioner's audit result)")
    if report_path is None:
        fail("the source directory has no RUN_REPORT.md or run_report.md (the agent's final report)")

    audit = read_json(audit_path)
    if not isinstance(audit, dict):
        fail("audit.json is not an object")
    need = ("item_id", "work_branch", "tip", "base_sha", "verdict", "audited_at", "gate", "checks")
    missing = [k for k in need if not audit.get(k)]
    if missing:
        fail(f"audit.json lacks {', '.join(missing)}")
    if not isinstance(audit["checks"], dict):
        fail("audit.json checks is not an object")
    prepared = read_json(prepared_path) if prepared_path else {}
    if not isinstance(prepared, dict):
        fail("prepared.json is not an object")
    report = report_path.read_text(encoding="utf-8", errors="replace")
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path else ""

    not_evidenced = []

    session = opts.get("session")
    if not session:
        m = re.search(r"\bcse_[A-Za-z0-9]+", report) or re.search(r"\bcse_[A-Za-z0-9]+", log)
        if not m:
            fail("no session id (cse_…) in the report or the run log; pass --session")
        session = m.group(0)

    model = opts.get("model") or prepared.get("model")
    if not model:
        not_evidenced.append("the model that ran the session (pass --model, or keep prepared.json)")

    target = opts.get("target")
    if not target:
        url = prepared.get("target_repo") or ""
        m = re.search(r"github\.com[/:]([\w.-]+/[\w.-]+?)(?:\.git)?(?:[\s/)]|$)", url + "\n" + report)
        if not m:
            fail("no target repository in prepared.json or the report; pass --target")
        target = m.group(1)

    # Commits: lines of the report that open with a short or full sha, read from the
    # section headed "Commits" when the report has one.
    lines = report.splitlines()
    starts = [i for i, l in enumerate(lines) if re.match(r"\s*(#+\s*)?\(?\d+\)?[.)]?\s*Commits\b", l)]
    if starts:
        end = next((i for i in range(starts[0] + 1, len(lines))
                    if re.match(r"\s*(#+\s*)?\(\d+\)\s", lines[i])), len(lines))
        lines = lines[starts[0] + 1:end]
    commits = []
    for l in lines:
        m = re.match(r"\s*(?:[-*]\s+)?`?([0-9a-f]{7,40})`?\s+(\S.*)$", l)
        if not m or m.group(2).startswith(".."):
            continue
        rest = m.group(2).strip()
        q = re.match(r'["“](.+?)["”]', rest)
        commits.append((m.group(1), q.group(1) if q else rest))
    if not commits:
        not_evidenced.append("any pushed commit (the report lists none on a line of its own)")

    corr = "corr-" + sha(session)[:16]
    trace_id = sha(session)[:32]
    span_id = sha(audit["tip"])[:16]
    when = audit["audited_at"]
    bundle_hash = "sha256:" + sha(audit["gate"] + "\n" + (audit.get("mutation") or ""))
    decision = "allow" if audit["verdict"] == "PASS" else "deny"

    evidence = [{
        "action": "push",
        "correlation_id": corr,
        "details": {"branch": audit["work_branch"], "sha": c, "subject": subject},
        "event_id": sha(corr + ":" + c)[:32],
        "event_time": when,
        "evidence_type": "commit.pushed",
        "result": "ok",
        "schema_version": "0.1.0",
        "span_id": span_id,
        "trace_id": trace_id,
        "workload": {"image_digest": None, "service_name": "claude-code-cloud", "version": model},
    } for c, subject in commits]

    rationale = []
    for name, check in audit["checks"].items():
        check = check if isinstance(check, dict) else {}
        rationale.append({"code": f"{name}:{check.get('status')}", "message": check.get("reason")})
    attributes = {"item": audit["item_id"], "target": target}
    if model:
        attributes["model"] = model
    trace = {
        "correlation_id": corr,
        "data_classification": "internal",
        "event_id": sha(corr + ":trace")[:32],
        "event_time": when,
        "evidence_refs": [e["event_id"] for e in evidence],
        "pii_flags": [],
        "policy": {"bundle_hash": bundle_hash, "bundle_version": None, "decision": decision,
                   "engine": "spawner cloud audit", "rationale": rationale},
        "request": {"action": "push", "attributes": {"base_sha": audit["base_sha"], "tip": audit["tip"]},
                    "environment": target, "resource": audit["work_branch"]},
        "schema_version": "0.1.0",
        "span_id": span_id,
        "subject": {"attributes": attributes, "id": session, "type": "agent"},
        "trace_id": trace_id,
    }

    schemas = sorted(here.glob("packet/*/schemas"))
    if not schemas:
        fail("no packet/*/schemas beside this script to copy the contracts from")
    dest = out / corr
    if dest.exists():
        fail(f"{dest} already exists; a packet is never overwritten")
    for sub in ("policy", "observability"):
        (dest / sub).mkdir(parents=True)
    shutil.copytree(schemas[0], dest / "schemas")

    def dump(obj):
        return json.dumps(obj, sort_keys=True)

    (dest / "decision_traces.jsonl").write_text(dump(trace) + "\n", encoding="utf-8")
    (dest / "evidence.jsonl").write_text("".join(dump(e) + "\n" for e in evidence), encoding="utf-8")
    (dest / "policy/metadata.json").write_text(
        json.dumps({"bundle_hash": bundle_hash, "bundle_version": None, "rego_file": None},
                   sort_keys=True, indent=2) + "\n", encoding="utf-8")
    (dest / "policy/README.md").write_text(
        "There is no rego: no policy engine decided this push before it happened.\n"
        "The policy is the five checks of `spawner cloud audit` (fetch_and_match, containment, "
        "host_gate, mutation, connector_scan; kestrel-team docs/cloud.md), and bundle_hash is sha256 "
        "over the audit's declared gate string, a newline, and its mutation string.\n", encoding="utf-8")
    (dest / "observability/pointers.json").write_text(
        json.dumps({"correlation_id": corr, "session_url": "https://claude.ai/code/session_" + session[4:],
                    "span_id": span_id, "trace_id": trace_id}, sort_keys=True, indent=2) + "\n",
        encoding="utf-8")

    print(f"session: {session}")
    print(f"mapped   1 decision trace: decision '{decision}' from audit verdict {audit['verdict']}, "
          f"{len(rationale)} rationale item(s)")
    print(f"mapped   {len(evidence)} evidence record(s), one per commit the report lists")
    print(f"mapped   policy bundle hash over the audit's declared gate and mutation: {bundle_hash[:19]}…")
    for what in not_evidenced + [
        "a policy decision before the action (the audit decided after the push)",
        "a time per push (every event_time is the audit's audited_at)",
        "an image digest or SBOM (no supplychain/)",
    ]:
        print(f"not evidenced by this export: {what}")
    print(f"wrote    {dest}")


try:
    main()
except SystemExit:
    raise
except Exception as exc:  # an input this script does not expect is a named failure
    fail(f"unexpected input ({type(exc).__name__}: {exc})")
PY
