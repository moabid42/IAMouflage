"""Shared plumbing for the per-corpus parsers: locate a corpus's rule files and print
a one-line-per-corpus stats summary. Keeps each parse_*.py focused on its own format."""

from collections import Counter
from pathlib import Path

from core.corpus import corpus_root, source_dirs

_DATA = Path(__file__).resolve().parents[1] / "data"


def out_path(source: str) -> Path:
    return _DATA / f"detections.{source}.json"


def collect(source: str, suffix: str, parse_fn, corpus=None) -> list:
    """Run parse_fn over every `*<suffix>` file of a corpus; keep the truthy results."""
    records = []
    for d in source_dirs(source, corpus_root(corpus)):
        for path in sorted(d.rglob(f"*{suffix}")):
            r = parse_fn(path)
            if r:
                records.append(r)
    return records


def report(source: str, records: list) -> None:
    para = Counter(r.paradigm for r in records)
    covered = {p for r in records for p in r.requirement.covered_permissions()}
    print(f"[{source}] {len(records)} rules -> {out_path(source).name}  paradigms={dict(para)}")
    print(f"[{source}] distinct permissions referenced: {len(covered)}")
    unres = sorted({t for r in records for t in r.unresolved_tokens})
    if unres:
        print(f"[{source}] unresolved tokens ({len(unres)}): {unres}")
