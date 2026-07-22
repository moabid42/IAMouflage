"""
Parse the vendored Panther GCP corpus (paired .py + .yml) into DetectionRecords.

Panther detection logic is Python: a `rule(event)` function returning True/False. We
extract operation tokens by AST-walking that function (and the module-level constants
it uses), collecting the string literals compared against the audit-log methodName or
IAM permission:

    method == "run.services.create"
    method.endswith("Services.CreateService")
    any(part in method for part in RULE_CREATED_PARTS)   # RULE_CREATED_PARTS = [...]
    auth.get("permission") == "iam.serviceAccountKeys.create"

These idioms (`==`, `in LIST`, `any(... in ...)`) are all disjunctions: any one match
fires the rule. So base-rule op tokens become separate DNF groups (an OR). This is
faithful -- Panther base rules do not AND two different operations.

Two conjunction sources are modelled explicitly:
  * `Threshold > 1` in the .yml -> a count rule -> paradigm=correlation (fires only
    after N events), threshold recorded. Still one operation, so still one op set.
  * `AnalysisType: correlation_rule` -> a multi-stage chain referencing other rules
    by id. These are a genuine conjunction: every referenced sub-rule must fire. We
    emit the referenced rule ids and stitch them into an AND-group in a second pass
    (see resolve_correlations), since the sub-rules are parsed from the same corpus.

Companion metadata (RuleID, Severity, LogTypes, MITRE, Threshold) comes from the .yml.

Output: data/detections.panther.json
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

import yaml

from core.canonical import Canonicaliser, canonicaliser
from core.corpus import add_corpus_arg, corpus_root, source_dirs
from detection.record import (
    CORRELATION, EVENT, DetectionRecord, OpRequirement, Requirement, dump_records,
    resolve_token_groups,
)

# op-shaped literal: dotted, >=2 dots, no space/slash/at; or a suffix fragment
# beginning with a dot (`.Services.CreateService`, `.setMetadata`).
_OP_SHAPE = re.compile(r'^\.?[A-Za-z*][A-Za-z0-9_*]*(?:\.[A-Za-z0-9_*]+){1,}$')
# things that are audit-log *field paths*, not operations
_FIELD_PATHS = {
    "protoPayload.methodName", "protoPayload.authorizationInfo",
    "protoPayload.serviceName", "protoPayload.resourceName",
    "resource.labels", "protoPayload.request", "protoPayload.metadata",
}
# helper-only method names that carry the field, used to gate which literals count
_METHOD_HINT = re.compile(r'method|permission|action|event_type|CreateService', re.I)


def _looks_like_op(s: str) -> bool:
    if not _OP_SHAPE.match(s) or s in _FIELD_PATHS:
        return False
    if s.startswith(("protoPayload.", "resource.", "data.")):
        return False
    if "googleapis.com" in s or "gserviceaccount" in s:
        return False
    return True


def _keep_camel(tok: str, canon: Canonicaliser) -> bool:
    """A bare CamelCase suffix fragment (`Services.CreateService`,
    `TagBindings.CreateTagBinding`) is kept only if the reference can resolve it.

    Most such fragments come from `.endswith(...)` guards whose rule ALSO matches the
    concrete IAM permission, so the fragment is redundant and resolves to nothing ->
    dropped as noise. But a few rules (the Resource Manager Tag rules) match ONLY on
    such a suffix; those DO resolve via the curated gRPC table and must be kept, or the
    rule watches nothing.
    """
    head = tok.lstrip(".").split(".", 1)[0]
    if not head[:1].isupper():
        return True  # normal lowercase-service op, always keep
    return bool(canon.resolve(tok).permissions)


class OpLiteralVisitor(ast.NodeVisitor):
    """Collect op-shaped string literals that gate a rule's firing.

    We scope to the `rule()` function plus module-level string constants (which the
    rule references, e.g. RULE_CREATED_PARTS). Literals inside title()/dedup()/
    alert_context() are ignored: they format alerts, they do not decide firing.
    """

    def __init__(self):
        self.tokens: list[str] = []

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str) and _looks_like_op(node.value):
            self.tokens.append(node.value)


def extract_py_tokens(src: str, canon: Canonicaliser) -> list[str]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []

    tokens: list[str] = []

    # module-level string constants (lists/tuples of op fragments)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            v = OpLiteralVisitor()
            v.visit(node.value)
            tokens += v.tokens

    # the rule() function body
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "rule":
            v = OpLiteralVisitor()
            for stmt in node.body:
                v.visit(stmt)
            tokens += v.tokens

    # keep CamelCase suffix fragments only when the reference resolves them
    tokens = [t for t in tokens if _keep_camel(t, canon)]
    # de-dup preserving order
    return list(dict.fromkeys(tokens))


def mitre_from_reports(reports: dict) -> tuple[list[str], list[str]]:
    tactics, techniques = set(), set()
    for entry in ((reports or {}).get("MITRE ATT&CK") or []):
        for m in re.findall(r'TA\d{4}', str(entry)):
            tactics.add(m)
        for m in re.findall(r'T\d{4}(?:\.\d{3})?', str(entry)):
            techniques.add(m.upper())
    return sorted(tactics), sorted(techniques)


def load_yml(path: Path) -> dict:
    try:
        return yaml.safe_load(path.read_text()) or {}
    except Exception as e:  # pragma: no cover
        print(f"  !! yaml error {path.name}: {e}", file=sys.stderr)
        return {}


def parse_event_rule(py_path: Path, canon: Canonicaliser) -> DetectionRecord | None:
    yml_path = py_path.with_suffix(".yml")
    meta = load_yml(yml_path) if yml_path.exists() else {}
    if not meta:
        return None

    tokens = extract_py_tokens(py_path.read_text(), canon)
    token_groups = [[t] for t in tokens]  # OR of literals -> separate groups

    threshold = meta.get("Threshold")
    threshold = int(threshold) if threshold not in (None, "", 1, "1") else None
    paradigm = CORRELATION if threshold and threshold > 1 else EVENT

    tactics, techniques = mitre_from_reports(meta.get("Reports"))
    req, unresolved = resolve_token_groups(token_groups, canon, confidence="flat")

    rid = meta.get("RuleID", py_path.stem)
    domain = "k8s" if "k8s" in str(py_path) else (
        "gcp_lb" if "http_lb" in str(py_path) else "gcp")

    return DetectionRecord(
        id=f"panther:{rid}",
        source="panther",
        native_id=str(rid),
        title=meta.get("DisplayName", rid),
        file=str(py_path.name),
        paradigm=paradigm,
        level=str(meta.get("Severity", "unknown")).lower(),
        status="enabled" if meta.get("Enabled", True) else "disabled",
        domain=domain,
        rule_type="python",
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        logsource={"log_types": meta.get("LogTypes")},
        requirement=req,
        threshold=threshold,
        unresolved_tokens=sorted(set(unresolved)),
        notes=([f"count rule: fires after >= {threshold} events"] if paradigm == CORRELATION else []),
    )


def parse_correlation_rule(yml_path: Path) -> dict | None:
    """Correlation rules are .yml-only and reference other rules by id.

    Returns a light dict describing the chain; stitched into a record in the second
    pass once the referenced base rules are known.
    """
    meta = load_yml(yml_path)
    if meta.get("AnalysisType") != "correlation_rule":
        return None
    refs = []
    for block in (meta.get("Detection") or []):
        for grp in (block.get("Group") or []):
            if grp.get("RuleID"):
                refs.append(grp["RuleID"])
    tactics, techniques = mitre_from_reports(meta.get("Reports"))
    window = None
    for block in (meta.get("Detection") or []):
        if block.get("LookbackWindowMinutes"):
            window = f"{block['LookbackWindowMinutes']}m"
    return {
        "rid": meta.get("RuleID", yml_path.stem),
        "title": meta.get("DisplayName", yml_path.stem),
        "file": yml_path.name,
        "refs": refs,
        "severity": str(meta.get("Severity", "unknown")).lower(),
        "enabled": bool(meta.get("Enabled", False)),
        "tactics": tactics,
        "techniques": techniques,
        "window": window,
    }


def resolve_correlations(chains: list[dict], by_native: dict[str, DetectionRecord],
                         canon: Canonicaliser) -> list[DetectionRecord]:
    """Stitch each chain's referenced base rules into one conjunctive AND-group.

    The chain fires only when every referenced sub-rule fires, so the union of one op
    per sub-rule forms a single DNF group (a conjunction). Where a sub-rule has several
    op alternatives we take the cartesian product, so each concrete way of satisfying
    the whole chain is its own group.
    """
    import itertools
    out = []
    for ch in chains:
        # The correlation_rules directory is multi-cloud. A chain is GCP-relevant only
        # if at least one referenced sub-rule is a GCP rule we parsed. Others (AWS,
        # Okta, ...) are skipped.
        if not any(ref in by_native for ref in ch["refs"]):
            continue
        sub_ops = []  # per referenced rule: list of its op-token alternatives
        missing = []
        for ref in ch["refs"]:
            sub = by_native.get(ref)
            if sub is None:
                missing.append(ref)
                continue
            alts = [op.token for g in sub.requirement.groups for op in g]
            if alts:
                sub_ops.append(alts)
        # cartesian product across sub-rules -> conjunctive groups
        token_groups = [list(combo) for combo in itertools.product(*sub_ops)] if sub_ops else []
        req, unresolved = resolve_token_groups(
            token_groups, canon,
            confidence="exact" if not missing else "approx")
        notes = [f"multi-stage correlation of {len(ch['refs'])} rules: "
                 f"{' -> '.join(ch['refs'])}"]
        if missing:
            notes.append(f"unresolved sub-rules (not in GCP corpus): {missing}")
        out.append(DetectionRecord(
            id=f"panther:{ch['rid']}",
            source="panther",
            native_id=str(ch["rid"]),
            title=ch["title"],
            file=ch["file"],
            paradigm=CORRELATION,
            level=ch["severity"],
            status="enabled" if ch["enabled"] else "disabled",
            domain="gcp",
            rule_type="correlation_rule",
            mitre_tactics=ch["tactics"],
            mitre_techniques=ch["techniques"],
            requirement=req,
            window=ch["window"],
            unresolved_tokens=sorted(set(unresolved)),
            notes=notes,
        ))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    add_corpus_arg(ap)
    args = ap.parse_args()

    canon = canonicaliser()
    root = corpus_root(args.corpus_root)
    out = Path(__file__).resolve().parents[1] / "data" / "detections.panther.json"

    records: list[DetectionRecord] = []
    chains: list[dict] = []
    for d in source_dirs("panther", root):
        if d.name == "correlation_rules":
            for yml in sorted(d.glob("*.yml")):
                ch = parse_correlation_rule(yml)
                if ch:
                    chains.append(ch)
        else:
            for py in sorted(d.glob("*.py")):
                r = parse_event_rule(py, canon)
                if r:
                    records.append(r)

    by_native = {r.native_id: r for r in records}
    records += resolve_correlations(chains, by_native, canon)

    dump_records(records, out)
    from collections import Counter
    para = Counter(r.paradigm for r in records)
    covered = {p for r in records for p in r.requirement.covered_permissions()}
    print(f"[panther] {len(records)} rules -> {out.name}  paradigms={dict(para)}")
    print(f"[panther] distinct permissions referenced: {len(covered)}")
    unres = {t for r in records for t in r.unresolved_tokens}
    if unres:
        print(f"[panther] unresolved tokens ({len(unres)}): {sorted(unres)}")


if __name__ == "__main__":
    main()
