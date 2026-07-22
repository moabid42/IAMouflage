"""
Locating the vendored detection corpora.

The corpora are not part of this repository -- they are upstream rule sets
(Sigma, Elastic, Google SecOps, Panther) checked out alongside the thesis. The old
code hardcoded `Path(__file__).parents[2]`, which silently broke when the pipeline
moved into IAMouflage: the path resolved to the repo root, where no corpora exist.

Resolution order, first hit wins:
  1. explicit --corpus-root argument
  2. $IAMOUFLAGE_CORPUS
  3. the conventional checkout location relative to this repo
"""

from __future__ import annotations

import os
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]

# Bachelorarbeit/code/IAMouflage -> Bachelorarbeit/draft/data/detections
_DEFAULT = _REPO.parents[1] / "draft" / "data" / "detections"

ENV_VAR = "IAMOUFLAGE_CORPUS"
TECH_ENV_VAR = "IAMOUFLAGE_TECHNIQUES"

# The technique corpus (hacktricks-cloud) sits beside the detection corpora under
# draft/data. Same broken-path story as the detections: the old hardcoded
# parents[2] no longer resolves after the move into IAMouflage.
_TECH_DEFAULT = (_REPO.parents[1] / "draft" / "data" / "techniques" /
                 "hacktricks-cloud" / "src" / "pentesting-cloud" / "gcp-security")

# Where each corpus's GCP rules live, relative to the corpus root.
SUBDIRS = {
    "sigma": ["sigma-rules/gcp"],
    "elastic": ["elastic-detection-rules/gcp"],
    "gsecops": ["gsecops-detection-rules/gcp"],
    "panther": [
        "panther-analysis-rules/gcp_audit_rules",
        "panther-analysis-rules/gcp_k8s_rules",
        "panther-analysis-rules/gcp_http_lb_rules",
        "panther-analysis-rules/correlation_rules",
    ],
}


def corpus_root(explicit: str | os.PathLike | None = None) -> Path:
    for cand in (explicit, os.environ.get(ENV_VAR), _DEFAULT):
        if not cand:
            continue
        p = Path(cand).expanduser().resolve()
        if p.is_dir():
            return p
    raise FileNotFoundError(
        f"detection corpora not found. Tried --corpus-root, ${ENV_VAR}, and the "
        f"default {_DEFAULT}. Point one of them at the directory containing "
        f"sigma-rules/, elastic-detection-rules/, gsecops-detection-rules/ and "
        f"panther-analysis-rules/."
    )


def source_dirs(source: str, root: Path) -> list[Path]:
    return [root / s for s in SUBDIRS[source] if (root / s).is_dir()]


def techniques_root(explicit: str | os.PathLike | None = None) -> Path:
    """Locate the hacktricks-cloud GCP technique corpus (flag / env / default)."""
    for cand in (explicit, os.environ.get(TECH_ENV_VAR), _TECH_DEFAULT):
        if not cand:
            continue
        p = Path(cand).expanduser().resolve()
        if p.is_dir():
            return p
    raise FileNotFoundError(
        f"technique corpus not found. Tried --techniques-root, ${TECH_ENV_VAR}, and the "
        f"default {_TECH_DEFAULT}.")


def add_corpus_arg(parser) -> None:
    parser.add_argument(
        "--corpus-root", default=None,
        help=f"directory holding the vendored rule sets (default: ${ENV_VAR} or {_DEFAULT})")
