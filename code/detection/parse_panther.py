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
import itertools
import re
import sys
from pathlib import Path

import yaml

from core.canonical import Canonicaliser, canonicaliser
from core.corpus import add_corpus_arg, corpus_root, source_dirs
from detection.record import (
    CORRELATION, EVENT, DetectionRecord, dump_records, resolve_token_groups,
)
from detection.runner import out_path, report

# op-shaped literal: dotted, >=2 dots, no space/slash/at; or a suffix fragment
# beginning with a dot (`.Services.CreateService`, `.setMetadata`).
_OP_SHAPE = re.compile(r'^\.?[A-Za-z*][A-Za-z0-9_*]*(?:\.[A-Za-z0-9_*]+){1,}$')
# things that are audit-log *field paths*, not operations
_FIELD_PATHS = {
    "protoPayload.methodName", "protoPayload.authorizationInfo",
    "protoPayload.serviceName", "protoPayload.resourceName",
    "resource.labels", "protoPayload.request", "protoPayload.metadata",
}


def _looks_like_op(s: str) -> bool:
    if not _OP_SHAPE.match(s) or s in _FIELD_PATHS:
        return False
    if s.startswith(("protoPayload.", "resource.", "data.")):
        return False
    if "googleapis.com" in s or "gserviceaccount" in s:
        return False
    return True


# A GCP service host in a `serviceName == "cloudkms.googleapis.com"` guard -> used to
# scope a generic/ambiguous method (bare SetIamPolicy) to its service, like Chronicle's
# target.application on the SecOps side.
_HOST_RE = re.compile(r'\b([a-z][a-z0-9-]*)\.googleapis\.com\b')
_HOST_SERVICE = {"cloudresourcemanager": "resourcemanager"}
# `cloudaudit.googleapis.com` is the audit-log path identifier, not a GCP service; it
# appears inside logName strings and must not be read as the rule's service.
_NON_SERVICE_HOSTS = {"cloudaudit"}
# org/folder IAM changes are scoped by logName, not serviceName -> Resource Manager.
_LOGNAME_SCOPE = re.compile(r'startswith\(\s*["\'](organizations|folder)', re.IGNORECASE)
# bare/CamelCase set-policy method names (SetIamPolicy / SetIAMPolicy / setIamPermissions)
_GENERIC_SETIAM = {"setiampolicy", "setiampermissions"}


def _methods_from_string(s: str) -> set[str]:
    """Pull bare CamelCase gRPC method names out of a string constant.

    Panther rules name the operation as a bare method, sometimes inside a regex:
      method == "CreateServiceAccount"
      re.search(r"...ConfigServiceV\\d\\.Delete(Bucket|Sink)", methodName)
    We expand simple `Verb(Alt1|Alt2)` alternations and collect plain CamelCase words;
    each is only kept later if the curated reference can resolve it, so non-methods
    (`SecurityPolicy`, `ConfigServiceV`) fall away harmlessly.
    """
    out: set[str] = set()
    for verb, alts in re.findall(r'([A-Z][a-z]+)\(([A-Za-z0-9|]+)\)', s):
        for a in alts.split("|"):
            if a[:1].isupper():
                out.add(verb + a)
    for m in re.findall(r'[A-Z][a-z]+[A-Za-z0-9]{2,}', s):
        out.add(m)
    return out


def _service_from_source(src: str) -> str | None:
    hosts = [_HOST_SERVICE.get(h, h) for h in _HOST_RE.findall(src)
             if h not in _NON_SERVICE_HOSTS]
    if hosts:
        return hosts[0]
    return "resourcemanager" if _LOGNAME_SCOPE.search(src) else None


def _normalise_panther_token(tok: str, service: str | None, canon: Canonicaliser) -> str:
    """Resolve a raw op token the way SecOps does: lift a bare gRPC method to its full
    name, and scope a generic SetIamPolicy to the rule's service."""
    full = canon.full_from_bare(tok)
    if full:
        return full
    if service and tok.replace(".", "").lower() in _GENERIC_SETIAM:
        return f"{service}.*.setIamPolicy"
    return tok


def _resolvable(tok: str, canon: Canonicaliser) -> bool:
    r = canon.resolve(tok)
    return bool(r.permissions) or r.pattern is not None


class StringVisitor(ast.NodeVisitor):
    """Collect every string constant that gates a rule's firing (rule() + module-level
    constants it references). title()/dedup()/alert_context() are not visited."""

    def __init__(self):
        self.strings: list[str] = []

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.strings.append(node.value)


def _is_conjunctive(tree: ast.Module) -> bool:
    """True if rule() requires ALL of a permission list (an AND), not any-of (an OR).

    The dominant conjunctive idiom is a module-level list consumed by::

        for permission in REQUIRED_PERMISSIONS:
            if not granted.get(permission):
                return False

    i.e. every listed permission must be granted or the rule bails. When present, the
    rule's op literals are ANDed together (one group), not ORed (separate groups).
    `any(... in LIST)` / membership tests remain disjunctions and do NOT trip this.
    """
    list_names = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.List, ast.Tuple)):
            elts = node.value.elts
            if elts and all(isinstance(e, ast.Constant) and isinstance(e.value, str)
                            and _looks_like_op(e.value) for e in elts):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        list_names.add(tgt.id)
    for node in ast.walk(tree):
        if (isinstance(node, ast.For) and isinstance(node.iter, ast.Name)
                and node.iter.id in list_names):
            # a `return False` inside the loop body means "all must hold"
            if any(isinstance(n, ast.Return)
                   and isinstance(n.value, ast.Constant) and n.value.value is False
                   for n in ast.walk(node)):
                return True
    return False


def extract_py_tokens(src: str, canon: Canonicaliser) -> tuple[list[str], bool]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return [], False

    strings: list[str] = []
    for node in tree.body:                       # module-level constants (op lists)
        if isinstance(node, ast.Assign):
            v = StringVisitor()
            v.visit(node.value)
            strings += v.strings
    for node in ast.walk(tree):                  # rule() body
        if isinstance(node, ast.FunctionDef) and node.name == "rule":
            v = StringVisitor()
            for stmt in node.body:
                v.visit(stmt)
            strings += v.strings

    # a serviceName == "<svc>.googleapis.com" guard scopes an ambiguous SetIamPolicy
    service = _service_from_source(src)

    # candidate op tokens: dotted permission/method literals + bare CamelCase methods
    # (incl. those inside regex patterns).
    candidates: set[str] = set()
    for s in strings:
        if _looks_like_op(s):
            candidates.add(s)
        candidates |= _methods_from_string(s)

    # lift bare methods / scope generic SetIamPolicy, then keep only what resolves.
    # sorted() so the output is deterministic (a set's iteration order is not).
    tokens = []
    for t in sorted(candidates):
        nt = _normalise_panther_token(t, service, canon)
        if _resolvable(nt, canon):
            tokens.append(nt)
    return list(dict.fromkeys(tokens)), _is_conjunctive(tree)


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

    tokens, conjunctive = extract_py_tokens(py_path.read_text(), canon)
    if conjunctive:
        # all listed ops must occur together -> one AND-group
        token_groups = [list(tokens)]
    else:
        token_groups = [[t] for t in tokens]  # OR of literals -> separate groups

    threshold = meta.get("Threshold")
    threshold = int(threshold) if threshold not in (None, "", 1, "1") else None
    paradigm = CORRELATION if threshold and threshold > 1 else EVENT

    tactics, techniques = mitre_from_reports(meta.get("Reports"))
    req, unresolved = resolve_token_groups(
        token_groups, canon, confidence="exact" if conjunctive else "flat")

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

    dump_records(records, out_path("panther"))
    report("panther", records)


if __name__ == "__main__":
    main()
