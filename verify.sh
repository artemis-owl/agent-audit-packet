#!/usr/bin/env bash
# Verifies one audit packet: the schema files against their recorded hashes,
# every record against its shipped schema, the policy file against the bundle
# hash the traces cite, and that the evidence closes the loop on the decision
# that authorized it. It checks no signature and nothing under supplychain/.
# Usage: ./verify.sh [packet/corr-<id>]   (default: the sample packet)
#
# One line per check: `ok`, `FAIL` with its reason, or `not evidenced by this
# export` with what is absent. Exit 0 when every check is ok, 1 when a check
# failed, 2 when none failed but the packet cannot evidence one.
set -euo pipefail
P="${1:-packet/corr-500bdcb7dacac332}"
echo "packet: $P"
exec python3 -I - "$P" <<'PY'
import hashlib, json, pathlib, sys

p = pathlib.Path(sys.argv[1])
counts = {"FAIL": 0, "NE": 0}
RESULTS = ("ok", "error", "skipped")  # schemas/evidence.avsc, field `result`


def ok(text):
    print(f"ok   {text}")


def bad(text, why):
    counts["FAIL"] += 1
    print(f"FAIL {text}: {why}")


def absent(text, why):
    counts["NE"] += 1
    print(f"not evidenced by this export: {text}: {why}")


def at(obj, *keys):
    """obj[k1][k2]…, or None when any step is absent or not an object."""
    for k in keys:
        if not isinstance(obj, dict) or k not in obj:
            return None
        obj = obj[k]
    return obj


def jsonl(name):
    """Rows of a .jsonl file, or a reason it cannot be read."""
    f = p / name
    if not f.is_file():
        return None, f"{name} is missing"
    rows = []
    for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            return None, f"{name}:{n} is not JSON"
        if not isinstance(row, dict):
            return None, f"{name}:{n} is not an object"
        rows.append(row)
    return rows, None


def json_file(name):
    f = p / name
    if not f.is_file():
        return None, f"{name} is missing"
    try:
        obj = json.loads(f.read_text(encoding="utf-8", errors="replace"))
    except ValueError:
        return None, f"{name} is not JSON"
    return (obj, None) if isinstance(obj, dict) else (None, f"{name} is not an object")


PRIMITIVES = {"string": str, "boolean": bool, "int": int, "long": int,
              "float": (int, float), "double": (int, float)}


def mismatch(value, schema, named, path):
    """Why `value` does not match an Avro schema read as JSON, or None. A field
    with a default may be absent; a union is written as the bare value."""
    if isinstance(schema, str):
        if schema == "null":
            return None if value is None else f"{path} is not null"
        if schema in PRIMITIVES:
            fits = isinstance(value, PRIMITIVES[schema]) and not (isinstance(value, bool) and schema != "boolean")
            return None if fits else f"{path} is not a {schema}"
        if schema in named:
            return mismatch(value, named[schema], named, path)
        return f"{path} has a type this verifier does not know ({schema})"
    if isinstance(schema, list):
        if any(mismatch(value, s, named, path) is None for s in schema):
            return None
        return f"{path} matches none of its allowed types"
    kind = schema.get("type") if isinstance(schema, dict) else None
    if kind == "record":
        named[schema.get("name")] = schema
        if not isinstance(value, dict):
            return f"{path or 'the record'} is not an object"
        for field in schema.get("fields", []):
            name = field["name"]
            where = f"{path}.{name}" if path else name
            if name not in value:
                if "default" in field:
                    continue
                return f"{where} is missing"
            why = mismatch(value[name], field["type"], named, where)
            if why:
                return why
        return None
    if kind == "array":
        if not isinstance(value, list):
            return f"{path} is not a list"
        for n, item in enumerate(value):
            why = mismatch(item, schema.get("items"), named, f"{path}[{n}]")
            if why:
                return why
        return None
    if kind == "map":
        if not isinstance(value, dict):
            return f"{path} is not a map"
        for key, item in value.items():
            why = mismatch(item, schema.get("values"), named, f"{path}.{key}")
            if why:
                return why
        return None
    if kind == "enum":
        return None if value in schema.get("symbols", []) else f"{path} is not one of its symbols"
    if isinstance(kind, (str, list, dict)):
        return mismatch(value, kind, named, path)
    return f"{path} has a schema this verifier cannot read"


def shape(rows, name, schema_name):
    """The first record of `name` that does not match its shipped schema."""
    schema, err = json_file(f"schemas/{schema_name}")
    if err:
        return err
    for n, row in enumerate(rows, 1):
        why = mismatch(row, schema, {}, "")
        if why:
            return f"{name}:{n} does not match {schema_name}: {why}"
    return None


def check():
    if not p.is_dir():
        bad("packet", "no such packet directory")
        return

    # 1. Schema files match their recorded hashes.
    what = "schemas match SHA256SUMS"
    sums = p / "schemas/SHA256SUMS"
    if not sums.is_file():
        bad(what, "schemas/SHA256SUMS is missing")
    else:
        wrong = []
        entries = [l.split(None, 1) for l in sums.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        for entry in entries:
            if len(entry) != 2:
                wrong.append("a line is not '<sha256>  <file>'")
                continue
            digest, name = entry[0], entry[1].strip().lstrip("*")
            f = p / "schemas" / name
            if not f.is_file():
                wrong.append(f"{name} is missing")
            elif hashlib.sha256(f.read_bytes()).hexdigest() != digest:
                wrong.append(f"{name} does not match its recorded hash")
        if not entries:
            wrong.append("SHA256SUMS lists no file")
        listed = {e[1].strip().lstrip("*") for e in entries if len(e) == 2}
        for f in sorted((p / "schemas").glob("*.avsc")):
            if f.name not in listed:
                wrong.append(f"{f.name} is not listed")
        if wrong:
            bad(what, "; ".join(wrong))
        else:
            ok(what)

    # 2. Both record files parse, and every record matches its shipped schema.
    traces, t_err = jsonl("decision_traces.jsonl")
    evidence, e_err = jsonl("evidence.jsonl")
    what = "decision traces and evidence records parse"
    if t_err or e_err:
        bad(what, "; ".join(x for x in (t_err, e_err) if x))
    elif not traces:
        bad(what, "decision_traces.jsonl is empty")
    else:
        unfit = (shape(traces, "decision_traces.jsonl", "decision_trace.avsc")
                 or shape(evidence, "evidence.jsonl", "evidence.avsc"))
        if unfit:
            bad(what, unfit)
        else:
            ok(f"{len(traces)} decision trace(s), {len(evidence)} evidence record(s) parse")
    parsed = not (t_err or e_err) and bool(traces)

    # 3. Every trace cites the policy bundle shipped in the packet, and the
    #    shipped policy file hashes to it.
    what = "every trace cites the shipped policy bundle"
    meta, m_err = json_file("policy/metadata.json")
    if not parsed:
        bad(what, "the record files did not parse")
    elif m_err:
        bad(what, m_err)
    elif not isinstance(meta.get("bundle_hash"), str) or not meta["bundle_hash"]:
        absent(what, "policy/metadata.json names no bundle_hash")
    else:
        uncited = [n for n, t in enumerate(traces, 1) if at(t, "policy", "bundle_hash") is None]
        other = [n for n, t in enumerate(traces, 1)
                 if at(t, "policy", "bundle_hash") not in (None, meta["bundle_hash"])]
        if other:
            bad(what, f"decision_traces.jsonl:{other[0]} cites a policy bundle other than the one shipped")
        elif uncited:
            absent(what, f"decision_traces.jsonl:{uncited[0]} cites no policy.bundle_hash")
        elif not isinstance(meta.get("rego_file"), str) or not meta["rego_file"]:
            absent(what, "the packet ships no policy file to hash the cited bundle against")
        elif not (p / "policy" / meta["rego_file"]).is_file():
            bad(what, f"policy/{meta['rego_file']} is named and not shipped")
        elif "sha256:" + hashlib.sha256((p / "policy" / meta["rego_file"]).read_bytes()).hexdigest() != meta["bundle_hash"]:
            bad(what, f"policy/{meta['rego_file']} does not hash to the cited bundle_hash")
        else:
            ok(f"{what}: {meta['bundle_hash'][:19]}…")

    # 4. Every evidence record closes the loop on an allowed decision.
    what = "every evidence record closes the loop on an allowed decision"
    if not parsed:
        bad(what, "the record files did not parse")
    else:
        by_corr = {t.get("correlation_id"): t for t in traces}
        broken, undecided, unrecorded = [], {}, 0
        for n, e in enumerate(evidence, 1):
            where = f"evidence.jsonl:{n}"
            t = by_corr.get(e.get("correlation_id")) if e.get("correlation_id") else None
            if t is None:
                broken.append(f"{where} has no decision trace for correlation_id {e.get('correlation_id')!r}")
                continue
            if e.get("trace_id") != t.get("trace_id"):
                broken.append(f"{where} and its trace disagree on trace_id")
            if e.get("action") != at(t, "request", "action"):
                broken.append(f"{where} records a different action than was decided")
            if e.get("result") not in RESULTS:
                broken.append(f"{where} records result {e.get('result')!r}, not one of ok, error, skipped")
            decided = at(t, "policy", "decision")
            recorded = at(e, "details", "policy_decision")
            if recorded is None:
                unrecorded += 1
            elif recorded != decided:
                broken.append(f"{where} records decision {recorded!r}, the trace {decided!r}")
            if decided != "allow":
                undecided[decided] = undecided.get(decided, 0) + 1
        for decided, n in sorted(undecided.items(), key=lambda kv: str(kv[0])):
            broken.append(f"{n} evidence record(s) of an executed action under decision {decided!r}")
        note = (f"{unrecorded} of {len(evidence)} evidence record(s) carry no details.policy_decision"
                if unrecorded else "")
        if broken:
            bad(what, "; ".join(broken[:4] + ([f"and {len(broken) - 4} more"] if len(broken) > 4 else [])
                                 + ([note] if note else [])))
        elif note:
            absent(what, note)
        else:
            ok(what)

    # 5. No allowed decision is missing its evidence.
    what = "no allowed decision is missing its evidence"
    if not parsed:
        bad(what, "the record files did not parse")
    else:
        # Evidence is a record that the action ran. A record whose result is
        # `skipped` says it did not, so it is not evidence of execution; one
        # whose result is `error` says it ran and failed, and the line says so.
        results = {}
        for e in evidence:
            results.setdefault(e.get("correlation_id"), []).append(e.get("result"))
        allowed = [t.get("correlation_id") for t in traces if at(t, "policy", "decision") == "allow"]
        orphans = [c for c in allowed if c not in results]
        skipped = [c for c in allowed if c in results and all(r == "skipped" for r in results[c])]
        failed = [c for c in allowed if c in results and c not in skipped
                  and not any(r == "ok" for r in results[c])]
        if orphans or skipped:
            why = []
            if orphans:
                why.append(f"allowed decisions with no evidence of execution: {orphans}")
            if skipped:
                why.append(f"allowed decisions whose only evidence records result 'skipped': {skipped}")
            bad(what, "; ".join(why))
        elif failed:
            ok(f"{what}; the action ran and its result is not 'ok' for: {failed}")
        else:
            ok(what)

    # 6. The observability pointer matches the trace.
    what = "observability pointer matches the trace"
    ptr, p_err = json_file("observability/pointers.json")
    if not parsed:
        bad(what, "the record files did not parse")
    elif p_err and "missing" in p_err:
        absent(what, p_err)
    elif p_err:
        bad(what, p_err)
    elif ptr.get("trace_id") is None:
        absent(what, "observability/pointers.json names no trace_id")
    else:
        why = []
        if any(t.get("trace_id") != ptr["trace_id"] for t in traces):
            why.append("the pointer's trace_id is not the trace's")
        if ptr.get("correlation_id") is not None and any(t.get("correlation_id") != ptr["correlation_id"] for t in traces):
            why.append("the pointer's correlation_id is not the trace's")
        if ptr.get("span_id") is not None and ptr["span_id"] not in [t.get("span_id") for t in traces]:
            why.append("the pointer's span_id is no trace's")
        if why:
            bad(what, "; ".join(why))
        else:
            ok(what)


try:
    check()
except Exception as exc:  # an input this script does not expect is a named failure
    bad("verifier", f"unexpected input ({type(exc).__name__}: {exc})")

if counts["FAIL"]:
    tail = f", {counts['NE']} not evidenced" if counts["NE"] else ""
    print(f"FAIL: {counts['FAIL']} check(s) failed{tail}")
    sys.exit(1)
if counts["NE"]:
    print(f"INCOMPLETE: {counts['NE']} check(s) not evidenced by this export")
    sys.exit(2)
print("PASS: packet is internally consistent")
PY
