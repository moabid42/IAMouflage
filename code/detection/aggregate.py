"""
Aggregate the four per-source detection corpora into one merged detections.json.

Runs each parser, loads the per-source records, then does the two things that can only
happen once every corpus is known:

  1. Pattern expansion. Wildcard ops (a bare `SetIamPolicy`, a Sigma
     `.serviceAccounts.disable` suffix) are resolved against the *universe* of
     permissions that actually matter -- every permission the technique corpus uses
     plus every permission concretely resolved by any rule. Expanding against the full
     10k vocabulary would let a generic matcher blow up the graph.

  2. A merged, namespaced file. IDs are already prefixed (`sigma:`, `elastic:`, ...),
     so the Sigma-only baseline stays reproducible by filtering `source == "sigma"`.

Output: data/detections.json (merged) alongside the per-source data/detections.<src>.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from core.canonical import canonicaliser
from core.corpus import add_corpus_arg
from detection.record import (
    DetectionRecord, OpRequirement, Requirement, dump_records,
)

HERE = Path(__file__).resolve().parents[1]
DATA = HERE / "data"
SOURCES = ["sigma", "elastic", "gsecops", "panther"]
PARSERS = {s: f"detection.parse_{s}" for s in SOURCES}


def run_parsers(corpus_root: str | None) -> None:
    for src, mod in PARSERS.items():
        cmd = [sys.executable, "-m", mod]
        if corpus_root:
            cmd += ["--corpus-root", corpus_root]
        print(f"--- {src} ---")
        subprocess.run(cmd, check=True, cwd=HERE.parent / "code")


def load_source(src: str) -> list[dict]:
    path = DATA / f"detections.{src}.json"
    return json.loads(path.read_text()) if path.exists() else []


def technique_permission_universe() -> set[str]:
    """Every permission the technique corpus references -- the set that matters for
    pattern expansion. Falls back to empty if techniques.json is absent."""
    tpath = DATA / "techniques.json"
    if not tpath.exists():
        return set()
    techs = json.loads(tpath.read_text())
    return {p for t in techs for p in t.get("required_perms", []) + t.get("optional_perms", [])}


def _rec_from_dict(d: dict) -> DetectionRecord:
    req_d = d.get("requirement", {})
    groups = [[OpRequirement(**op) for op in g] for g in req_d.get("groups", [])]
    excluded = [OpRequirement(**op) for op in req_d.get("excluded", [])]
    req = Requirement(groups=groups, excluded=excluded,
                      confidence=req_d.get("confidence", "flat"),
                      note=req_d.get("note", ""))
    d = {k: v for k, v in d.items()
         if k not in ("requirement", "covered_permissions")}
    return DetectionRecord(requirement=req, **d)


def aggregate(corpus_root: str | None, skip_parse: bool) -> dict:
    if not skip_parse:
        run_parsers(corpus_root)

    canon = canonicaliser()
    records: list[DetectionRecord] = []
    for src in SOURCES:
        records += [_rec_from_dict(d) for d in load_source(src)]

    # ---- build the pattern-expansion universe ----
    universe = technique_permission_universe()
    for r in records:
        for op in r.requirement.all_ops():
            universe.update(op.permissions)

    # ---- expand patterns in place ----
    n_expanded = 0
    for r in records:
        for group in r.requirement.groups:
            for op in group:
                if op.pattern and not op.permissions:
                    op.permissions = list(canon.expand_pattern(op.pattern, universe))
                    if op.permissions:
                        n_expanded += 1
                        op.provenance += f" -> {len(op.permissions)} permission(s)"
                    else:
                        op.note = (op.note + " ; pattern matched no permission in universe").strip(" ;")

    dump_records(records, DATA / "detections.json")

    stats = {
        "total_rules": len(records),
        "by_source": dict(Counter(r.source for r in records)),
        "by_paradigm": dict(Counter(r.paradigm for r in records)),
        "by_domain": dict(Counter(r.domain for r in records)),
        "patterns_expanded": n_expanded,
        "distinct_permissions": len({p for r in records
                                     for p in r.requirement.covered_permissions()}),
        "rules_with_ops": sum(1 for r in records if r.requirement.groups),
        "event_only_rules": sum(1 for r in records if r.paradigm == "event"),
        "universe_size": len(universe),
    }
    (DATA / "detections.stats.json").write_text(json.dumps(stats, indent=2))
    return stats


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    add_corpus_arg(ap)
    ap.add_argument("--skip-parse", action="store_true",
                    help="merge existing per-source json without re-running parsers")
    args = ap.parse_args()

    stats = aggregate(args.corpus_root, args.skip_parse)
    print("\n=== aggregate ===")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"\nwrote {DATA/'detections.json'}")


if __name__ == "__main__":
    main()
