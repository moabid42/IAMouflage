"""
Parse the vendored Elastic GCP corpus (.toml) into DetectionRecords.

Elastic rules carry a `type`:
  query            KQL single-event signature      -> paradigm=event
  esql             ES|QL, aggregates over a window -> paradigm=correlation
  machine_learning ML anomaly job (no query ops)   -> paradigm=ueba
  new_terms        first-seen tuple per identity   -> paradigm=ueba

Operations live in the `query` block, in `event.action:` (KQL) or
`event.action == "..."` (ES|QL) clauses. We read ONLY the query block: the prose in
`note`/`description` is full of method names in English and must never be scraped.

`event.action:(A or B)` is a disjunction -> separate DNF groups. ML jobs contribute
no operation (they baseline every method), so they carry no groups; they remain as
nodes tagged paradigm=ueba and, per the model, create no DETECTED_BY edge.

Output: data/detections.elastic.json
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

from core.canonical import Canonicaliser, canonicaliser
from core.corpus import add_corpus_arg
from detection.record import (
    CORRELATION, EVENT, UEBA, DetectionRecord, dump_records, resolve_token_groups,
)
from detection.runner import collect, out_path, report

PARADIGM_BY_TYPE = {
    "query": EVENT,
    "eql": EVENT,
    "esql": CORRELATION,
    "machine_learning": UEBA,
    "new_terms": UEBA,
}

# An op token inside a query: dotted, may carry * wildcards and a version segment.
# Scoped to event.action / method_name values, so 2-segment legacy names like
# `storage.setIamPermissions` are valid here and must be captured (>=1 dot), not only
# the usual 3-segment service.resource.verb.
_OP_TOKEN = re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_*]+){1,}')

# `event.action` / `gcp.audit.method_name` clause, KQL `field:(...)` or `field:value`,
# and ES|QL `field == "value"`.
_KQL_CLAUSE = re.compile(
    r'(?:event\.action|gcp\.audit\.method_name)\s*:\s*(\([^)]*\)|"[^"]*"|[^\s]+)',
    re.IGNORECASE)
_ESQL_CLAUSE = re.compile(
    r'(?:event\.action|gcp\.audit\.method_name)\s*==\s*"([^"]*)"', re.IGNORECASE)


def op_tokens_from_query(query: str) -> list[list[str]]:
    """Return DNF token groups from a query block.

    Each `event.action` clause becomes one or more groups. A parenthesised
    `(A or B or C)` is a disjunction -> three single-op groups. Distinct clauses in
    the same query are ANDed conceptually, but in this corpus multiple op-bearing
    clauses in one rule are effectively alternatives, so we keep them as separate
    groups (the coverage-maximising reading, flagged approx by the caller if >1).
    """
    groups: list[list[str]] = []

    for m in _KQL_CLAUSE.finditer(query):
        blob = m.group(1)
        vals = _OP_TOKEN.findall(blob)
        for v in vals:
            groups.append([v])  # each alternative is its own group (OR)

    for m in _ESQL_CLAUSE.finditer(query):
        v = m.group(1)
        if _OP_TOKEN.fullmatch(v):
            groups.append([v])

    # de-dup groups preserving order
    seen, out = set(), []
    for g in groups:
        k = tuple(g)
        if k not in seen:
            seen.add(k)
            out.append(g)
    return out


def mitre_from_threat(threat) -> tuple[list[str], list[str]]:
    tactics, techniques = set(), set()
    for entry in (threat or []):
        tac = (entry.get("tactic") or {}).get("name")
        if tac:
            tactics.add(tac.lower().replace(" ", "_"))
        for tech in (entry.get("technique") or []):
            if tech.get("id"):
                techniques.add(tech["id"].upper())
            for sub in (tech.get("subtechnique") or []):
                if sub.get("id"):
                    techniques.add(sub["id"].upper())
    return sorted(tactics), sorted(techniques)


def parse_rule(path: Path, canon: Canonicaliser) -> DetectionRecord | None:
    try:
        doc = tomllib.loads(path.read_text())
    except Exception as e:  # pragma: no cover
        print(f"  !! toml error {path.name}: {e}", file=sys.stderr)
        return None
    rule = doc.get("rule", {})
    if not rule:
        return None

    rtype = rule.get("type", "query")
    paradigm = PARADIGM_BY_TYPE.get(rtype, EVENT)
    query = rule.get("query", "") or ""
    token_groups = op_tokens_from_query(query) if query else []

    tactics, techniques = mitre_from_threat(rule.get("threat"))

    # multiple op-bearing clauses are kept as separate groups (OR): faithful for the OR
    # clauses that dominate this corpus, a slight over-approximation for the rare true AND.
    req, unresolved = resolve_token_groups(token_groups, canon, confidence="exact")

    rid = rule.get("rule_id", path.stem)
    domain = "k8s" if any(k in path.stem for k in ("gke", "k8s")) else "gcp"

    return DetectionRecord(
        id=f"elastic:{rid}",
        source="elastic",
        native_id=str(rid),
        title=rule.get("name", path.stem),
        file=str(path.name),
        paradigm=paradigm,
        level=rule.get("severity", "unknown"),
        status=doc.get("metadata", {}).get("maturity", "unknown"),
        domain=domain,
        rule_type=rtype,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        logsource={"index": rule.get("index"), "language": rule.get("language")},
        requirement=req,
        unresolved_tokens=sorted(set(unresolved)),
        notes=([f"ML/behavioural rule ({rtype}); baselines activity, names no specific "
                f"operation"] if paradigm == UEBA and not token_groups else []),
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    add_corpus_arg(ap)
    args = ap.parse_args()

    canon = canonicaliser()
    records = collect("elastic", ".toml", lambda p: parse_rule(p, canon), args.corpus_root)
    dump_records(records, out_path("elastic"))
    report("elastic", records)


if __name__ == "__main__":
    main()
