"""
Parse the vendored Google SecOps (Chronicle) YARA-L 2.0 GCP corpus into DetectionRecords.

YARA-L is not YAML; we read the relevant blocks with targeted regexes. The
operation-bearing field is `<var>.metadata.product_event_type`, whose value is the
Cloud Audit Log methodName. Values appear as string literals or `/regex/` patterns,
sometimes ORed across several lines inside parentheses.

Paradigm:
  a `match: $entity over <window>` block + a count `condition` (`#gcp >= N`) turns a
  rule from single-event into a correlation over an entity -> paradigm=correlation,
  with the window and threshold recorded. No match block -> paradigm=event.

Correlation rules require every product_event_type in the (ORed) set to occur N times
within the window. The set-of-alternatives is a disjunction, so each alternative is a
DNF group; the count threshold is metadata, not extra ops.

Output: data/detections.gsecops.json
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from core.canonical import Canonicaliser, canonicaliser
from core.corpus import add_corpus_arg, corpus_root, source_dirs
from detection.record import (
    CORRELATION, EVENT, DetectionRecord, dump_records, resolve_token_groups,
)

_RULE_NAME = re.compile(r'\brule\s+([A-Za-z0-9_]+)\s*\{')
_META = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
_EVENTS_BLOCK = re.compile(r'\bevents:\s*(.*?)\n\s*(?:match|outcome|condition|options):',
                           re.S)
_MATCH_BLOCK = re.compile(r'\bmatch:\s*(.*?)\n\s*(?:outcome|condition|options):', re.S)
_CONDITION = re.compile(r'\bcondition:\s*(.*?)\n\s*\}', re.S)

# product_event_type = "literal"  |  = /regex/
_PET_LITERAL = re.compile(r'product_event_type\s*=\s*"([^"]+)"', re.IGNORECASE)
_PET_REGEX = re.compile(r'product_event_type\s*=\s*/([^/]+)/', re.IGNORECASE)
_WINDOW = re.compile(r'\bover\s+([0-9]+[smhd])', re.IGNORECASE)
_THRESHOLD = re.compile(r'#\w+\s*>=?\s*(\d+)')


def _meta_dict(block: str) -> dict:
    m = re.search(r'\bmeta:\s*(.*?)\n\s*events:', block, re.S)
    return dict(_META.findall(m.group(1))) if m else {}


def mitre_from_meta(meta: dict) -> tuple[list[str], list[str]]:
    tactics, techniques = set(), set()
    for t in re.split(r'[;,]', meta.get("mitre_attack_tactic", "")):
        t = t.strip().lower().replace(" ", "_")
        if t:
            tactics.add(t)
    tid = meta.get("mitre_attack_technique_id", "")
    for m in re.findall(r'T\d{4}(?:\.\d{3})?', tid):
        techniques.add(m.upper())
    return sorted(tactics), sorted(techniques)


def regex_to_pattern_token(rx: str) -> str | None:
    """Turn a product_event_type regex into a token the canonicaliser can pattern-match.

    e.g. `compute.firewalls.insert$` -> `compute.firewalls.insert`;
         `google.cloud.securitycenter.settings.*.Settings.Update` -> keep the * form.
    We strip anchors and pass it through as a wildcard token.
    """
    body = rx.strip().lstrip("^").rstrip("$")
    body = body.replace(".*", "*").replace("\\.", ".")
    return body if "." in body else None


def parse_rule(text: str, path: Path, canon: Canonicaliser) -> DetectionRecord | None:
    name_m = _RULE_NAME.search(text)
    if not name_m:
        return None
    name = name_m.group(1)
    meta = _meta_dict(text)

    ev_m = _EVENTS_BLOCK.search(text)
    events = ev_m.group(1) if ev_m else ""

    tokens = list(_PET_LITERAL.findall(events))
    for rx in _PET_REGEX.findall(events):
        tok = regex_to_pattern_token(rx)
        if tok:
            tokens.append(tok)

    # Each product_event_type value is an alternative -> its own DNF group.
    token_groups = [[t] for t in dict.fromkeys(tokens)]

    has_match = bool(_MATCH_BLOCK.search(text))
    paradigm = CORRELATION if has_match else EVENT
    window = None
    threshold = None
    if has_match:
        w = _WINDOW.search(_MATCH_BLOCK.search(text).group(1))
        window = w.group(1) if w else None
        cond_m = _CONDITION.search(text)
        if cond_m:
            th = _THRESHOLD.search(cond_m.group(1))
            threshold = int(th.group(1)) if th else None

    tactics, techniques = mitre_from_meta(meta)
    req, unresolved = resolve_token_groups(token_groups, canon, confidence="exact")

    rid = meta.get("rule_id", name)
    return DetectionRecord(
        id=f"gsecops:{rid}",
        source="gsecops",
        native_id=str(rid),
        title=meta.get("rule_name", name),
        file=str(path.name),
        paradigm=paradigm,
        level=meta.get("severity", "unknown").lower(),
        status="production",
        domain="gcp",
        rule_type="yaral",
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        logsource={"data_source": meta.get("data_source"),
                   "platform": meta.get("platform")},
        requirement=req,
        threshold=threshold,
        window=window,
        unresolved_tokens=sorted(set(unresolved)),
        notes=([f"correlation over {window}, needs >= {threshold} events"]
               if paradigm == CORRELATION else []),
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    add_corpus_arg(ap)
    args = ap.parse_args()

    canon = canonicaliser()
    root = corpus_root(args.corpus_root)
    out = Path(__file__).resolve().parents[1] / "data" / "detections.gsecops.json"

    records = []
    for d in source_dirs("gsecops", root):
        for path in sorted(d.glob("*.yaral")):
            r = parse_rule(path.read_text(), path, canon)
            if r:
                records.append(r)

    dump_records(records, out)
    from collections import Counter
    para = Counter(r.paradigm for r in records)
    covered = {p for r in records for p in r.requirement.covered_permissions()}
    print(f"[gsecops] {len(records)} rules -> {out.name}  paradigms={dict(para)}")
    print(f"[gsecops] distinct permissions referenced: {len(covered)}")
    unres = {t for r in records for t in r.unresolved_tokens}
    if unres:
        print(f"[gsecops] unresolved tokens ({len(unres)}): {sorted(unres)}")


if __name__ == "__main__":
    main()
