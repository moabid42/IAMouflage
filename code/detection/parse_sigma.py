"""
Parse the vendored Sigma GCP corpus into DetectionRecords.

Sigma rules key on log *fields*. The ones that identify a cloud operation are:

    gcp.audit.method_name                            (Cloud Audit Logs methodName)
    data.protoPayload.methodName                     (same, verbose form)
    data.protoPayload.authorizationInfo.permission   (IAM permission checked)

A rule's `detection:` block holds named search-identifiers combined by a `condition:`.
We recover the boolean structure rather than flattening it:

  * `selection` with a list value          -> a disjunction of ops (any one fires)
  * two op-bearing fields in one identifier -> a conjunction (both required)
  * `sel_a and sel_b`                       -> conjunction across identifiers
  * `sel_a or sel_b`                        -> disjunction across identifiers
  * `... and not filter`                    -> filter recorded as `excluded`, not a group

Rules that key on Workspace/login event names target a different telemetry stream;
their event names are kept for reference but they cover no GCP-API operation.

Output: data/detections.sigma.json
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

from core.canonical import Canonicaliser, canonicaliser
from core.corpus import add_corpus_arg, corpus_root, source_dirs
from detection.record import (
    EVENT, DetectionRecord, Requirement, dump_records, resolve_token_groups,
)

OP_BEARING_FIELDS = {
    "gcp.audit.method_name",
    "data.protopayload.methodname",
    "data.protopayload.authorizationinfo.permission",
}
WORKSPACE_FIELDS = {"eventname", "protopayload.metadata.event.eventname"}

# A few rules express an operation through startswith/contains/endswith fragments
# (e.g. startswith `admissionregistration.k8s.io.v` AND contains
# `.mutatingwebhookconfigurations.` AND a bare verb) that cannot be reassembled by
# field matching alone. We resolve those to explicit k8s method tokens here, keyed by
# rule id, so they canonicalise through the normal k8s rung. Each disjunct is one
# group. (Ported from the original parser's RULE_OP_OVERRIDES.)
RULE_OP_OVERRIDES = {
    # GKE Admission Controller: mutating/validating webhook create|patch|replace
    "6ad91e31-53df-4826-bd27-0166171c8040": [
        ["io.k8s.admissionregistration.v1.mutatingwebhookconfigurations.create"],
        ["io.k8s.admissionregistration.v1.mutatingwebhookconfigurations.patch"],
        ["io.k8s.admissionregistration.v1.mutatingwebhookconfigurations.replace"],
        ["io.k8s.admissionregistration.v1.validatingwebhookconfigurations.create"],
        ["io.k8s.admissionregistration.v1.validatingwebhookconfigurations.patch"],
        ["io.k8s.admissionregistration.v1.validatingwebhookconfigurations.replace"],
    ],
    # GKE CronJob (batch Job / CronJob objects)
    "cd3a808c-c7b7-4c50-a2f3-f4cfcd436435": [
        ["io.k8s.batch.v1.jobs.create"], ["io.k8s.batch.v1.cronjobs.create"],
        ["io.k8s.batch.v1.jobs.update"], ["io.k8s.batch.v1.cronjobs.update"],
    ],
}

_MOD_RE = re.compile(r"\|[a-z]+", re.IGNORECASE)


def base_field(key: str) -> str:
    return _MOD_RE.sub("", key).strip().lower()


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def mitre_split(tags):
    tactics, techniques = [], []
    for t in tags or []:
        t = str(t)
        if not t.startswith("attack."):
            continue
        val = t[len("attack."):]
        (techniques if re.match(r"t\d", val) else tactics).append(
            val.upper() if re.match(r"t\d", val) else val)
    return sorted(set(tactics)), sorted(set(techniques))


# A search-identifier is "op-bearing" if it constrains an operation field. We collect
# its op tokens; the identifier contributes one AND-group (its fields ANDed) unless a
# single field carries a value list, which is an OR within the group.
def identifier_ops(block: dict):
    """Return (op_tokens_by_field, event_names, is_filter_only).

    op_tokens_by_field: list of lists -- each inner list is the disjunction of values
    for one op-bearing field in this identifier. The identifier fires when every
    field is satisfied, i.e. the AND across fields of the OR across values.
    """
    fields, events = [], set()
    for key, val in block.items():
        bf = base_field(key)
        values = [str(v) for v in as_list(val)]
        if bf in OP_BEARING_FIELDS:
            fields.append(values)
        elif bf in WORKSPACE_FIELDS:
            events.update(values)
    return fields, events


def parse_condition(cond: str) -> tuple[list[str], list[str]]:
    """Very small Sigma condition reader.

    Returns (positive_identifiers, negated_identifiers). Handles the shapes that
    actually occur in this corpus: `a`, `a and b`, `a or b`, `a and not b`,
    `selection` / `1 of sel*` / `all of sel*`. Anything unrecognised falls back to
    "every identifier is positive", which is the permissive (coverage-maximising)
    reading and is flagged by the caller via confidence=approx.
    """
    if not cond:
        return [], []
    toks = cond.replace("(", " ").replace(")", " ").split()
    pos, neg, negate = [], [], False
    i = 0
    while i < len(toks):
        t = toks[i]
        low = t.lower()
        if low == "not":
            negate = True
        elif low in ("and", "or"):
            pass
        elif low in ("1", "all", "of", "them"):
            # `1 of selection*` / `all of them` -> treat the wildcard as positive;
            # resolved to concrete identifiers by the caller.
            pass
        else:
            (neg if negate else pos).append(t.rstrip("*"))
            negate = False
        i += 1
    return pos, neg


def parse_rule(path: Path, canon: Canonicaliser) -> DetectionRecord | None:
    try:
        doc = yaml.safe_load(path.read_text())
    except Exception as e:  # pragma: no cover
        print(f"  !! yaml error {path.name}: {e}", file=sys.stderr)
        return None
    if not isinstance(doc, dict):
        return None

    tactics, techniques = mitre_split(doc.get("tags"))
    logsource = doc.get("logsource", {}) or {}
    detection = doc.get("detection", {}) or {}
    condition = detection.get("condition", "")

    identifiers = {name: b for name, b in detection.items()
                   if name != "condition" and isinstance(b, dict)}

    pos, neg = parse_condition(condition if isinstance(condition, str) else "")
    approx = False

    def match_names(selected):
        out = []
        for want in selected:
            if want in identifiers:
                out.append(want)
            else:  # wildcard like `selection*`
                out += [n for n in identifiers if n.startswith(want)]
        return out or list(identifiers)  # fallback: all

    if not pos and not neg:
        pos = list(identifiers)
        approx = True

    pos_names = match_names(pos)
    neg_names = match_names(neg) if neg else []

    # Build DNF. Each positive identifier is an AND-group of its op fields; multiple
    # positive identifiers ORed in the condition become separate groups; but two
    # identifiers ANDed become one merged group. We approximate: identifiers joined by
    # `and` -> merged; by `or` -> separate. Detecting which is which precisely needs a
    # real parser, so we use a heuristic: if the condition contains ` or ` at top level
    # we treat positives as separate groups, else as one merged group.
    cond_l = (condition if isinstance(condition, str) else "").lower()
    or_joined = " or " in cond_l and " and " not in cond_l
    event_names: set[str] = set()

    per_id_fields = {}
    for name in pos_names:
        flds, evs = identifier_ops(identifiers[name])
        event_names |= evs
        if flds:
            per_id_fields[name] = flds

    rid = str(doc.get("id", path.stem))
    token_groups: list[list[str]] = []
    if rid in RULE_OP_OVERRIDES:
        token_groups = [list(g) for g in RULE_OP_OVERRIDES[rid]]
    elif or_joined:
        for flds in per_id_fields.values():
            # one identifier: AND across its fields. If a field has multiple values it
            # is an OR -> expand into separate groups (distribute OR over AND).
            token_groups += _distribute(flds)
    else:
        # AND across all positive identifiers -> one merged conjunction.
        merged = [f for flds in per_id_fields.values() for f in flds]
        if merged:
            token_groups += _distribute(merged)
    if len(per_id_fields) > 1 and not or_joined and rid not in RULE_OP_OVERRIDES:
        approx = True  # merged conjunction is a heuristic

    excluded_tokens = []
    for name in neg_names:
        flds, _ = identifier_ops(identifiers[name])
        excluded_tokens += [v for f in flds for v in f]

    req, unresolved = resolve_token_groups(
        token_groups, canon,
        confidence="approx" if approx else "exact",
        excluded_tokens=excluded_tokens)

    domain = "gcp"
    fp = str(path).lower()
    if "gworkspace" in fp:
        domain = "workspace"
    elif any(k in path.stem for k in ("kubernetes", "k8s", "container")):
        domain = "k8s"

    return DetectionRecord(
        id=f"sigma:{rid}",
        source="sigma",
        native_id=rid,
        title=doc.get("title", path.stem),
        file=str(path.name),
        paradigm=EVENT,  # every Sigma GCP rule is single-event (see docs/detection.md)
        level=doc.get("level", "unknown"),
        status=doc.get("status", "unknown"),
        domain=domain,
        rule_type="sigma",
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        logsource={"product": logsource.get("product"),
                   "service": logsource.get("service")},
        requirement=req,
        event_names=sorted(event_names),
        unresolved_tokens=sorted(set(unresolved)),
    )


def _distribute(fields: list[list[str]]) -> list[list[str]]:
    """Distribute OR (value lists) over AND (fields) into DNF groups.

    fields = [[a, b], [c]] means (a OR b) AND c -> [[a, c], [b, c]].
    A single field [[a, b]] (one op, several notations) -> [[a], [b]] (a OR b).
    """
    if not fields:
        return []
    if len(fields) == 1:
        return [[v] for v in fields[0]]
    import itertools
    return [list(combo) for combo in itertools.product(*fields)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    add_corpus_arg(ap)
    args = ap.parse_args()

    canon = canonicaliser()
    root = corpus_root(args.corpus_root)
    out = Path(__file__).resolve().parents[1] / "data" / "detections.sigma.json"

    records = []
    for d in source_dirs("sigma", root):
        for path in sorted(d.rglob("*.yml")):
            r = parse_rule(path, canon)
            if r:
                records.append(r)

    dump_records(records, out)
    covered = {p for r in records for p in r.requirement.covered_permissions()}
    print(f"[sigma] {len(records)} rules -> {out.name}")
    print(f"[sigma] distinct permissions referenced: {len(covered)}")
    unres = {t for r in records for t in r.unresolved_tokens}
    if unres:
        print(f"[sigma] unresolved tokens ({len(unres)}): {sorted(unres)}")


if __name__ == "__main__":
    main()
