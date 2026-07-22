"""
Fetch and pin the GCP naming reference tables that let detections join techniques.

Why this exists
---------------
Google names "the same operation" three incompatible ways:

    IAM permission        compute.firewalls.create
    REST method id        compute.firewalls.insert        <- audit-log methodName
    gRPC method name      google.iam.admin.v1.CreateServiceAccount

Detection corpora speak the *method* dialects; the technique corpus speaks the
*permission* dialect. Note `insert` vs `create`: these are the same operation, so no
amount of string normalisation joins them. The join needs a real lookup table.

This script materialises three pinned reference files under data/reference/:

  method_permissions.json  REST method id -> [IAM permission]      (from iam-dataset)
  permissions.json         the canonical IAM permission vocabulary (from iam-dataset)
  PROVENANCE.md            pinned commit + fetch date + validation notes

The fourth table, rpc_methods.json (gRPC method -> permission), is *not* fetched:
it is hand-curated from Google's own per-service audit-logging pages and lives in
version control with a source URL per entry. See reference/rpc_methods.json.

Reproducibility: the upstream commit is pinned below. Re-running with the same SHA
reproduces the same tables byte-for-byte. Bump DATASET_SHA deliberately, never
silently -- the coverage numbers in the thesis depend on it.

Usage:  python -m reference.fetch_reference [--sha SHA] [--check]
"""

import argparse
import json
import sys
import urllib.request
from pathlib import Path

# Pinned upstream. https://github.com/iann0036/iam-dataset
# Community-maintained; cross-validated against Google's official audit-logging
# documentation -- see PROVENANCE.md and reference/validate_reference.py.
DATASET_SHA = "1e4bdde1ef15ee01534ac4ed23221436e8796ab1"
DATASET_DATE = "2026-07-21T15:20:29Z"
RAW = "https://raw.githubusercontent.com/iann0036/iam-dataset/{sha}/gcp/{name}"

OUT = Path(__file__).resolve().parents[1] / "data" / "reference"


def fetch_json(sha: str, name: str):
    url = RAW.format(sha=sha, name=name)
    print(f"  GET {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=120) as r:
        return json.load(r)


def build_method_permissions(raw_map: dict) -> dict:
    """Flatten map.json into {rest_method_id: [permission, ...]}.

    We keep only methods that actually declare a permission. Methods with no
    declared permission cannot participate in the join, and carrying them would
    bloat the table with ~4k dead entries.
    """
    out = {}
    for _service, body in (raw_map.get("api") or {}).items():
        for method_id, info in (body.get("methods") or {}).items():
            perms = sorted({
                p["name"] for p in (info.get("permissions") or []) if p.get("name")
            })
            if perms:
                out[method_id] = perms
    return dict(sorted(out.items()))


def build_permission_vocab(raw_perms: dict) -> list:
    """The canonical IAM permission vocabulary (names only).

    Upstream maps permission -> predefined roles; we only need the key set, to
    answer "is this token already a valid IAM permission?". Dropping the role
    lists takes the file from ~8.5 MB to ~300 KB.
    """
    return sorted(raw_perms.keys())


PROVENANCE = """# Provenance of the GCP naming reference tables

These tables are the join substrate between the detection corpora (which name
operations as API *methods*) and the technique corpus (which names them as IAM
*permissions*). They are pinned so coverage numbers are reproducible.

## Sources

| File | Source | Kind | Pinned at |
|---|---|---|---|
| `method_permissions.json` | [iann0036/iam-dataset](https://github.com/iann0036/iam-dataset) `gcp/map.json` | community, machine-readable | `{sha}` ({date}) |
| `permissions.json` | same repo, `gcp/permissions.json` (keys only) | community, machine-readable | `{sha}` ({date}) |
| `../../reference/rpc_methods.json` | Google Cloud per-service audit-logging docs | **official**, hand-transcribed | see per-entry `source` |

## Counts

- REST methods with >=1 permission: **{n_methods}**
- Canonical IAM permissions: **{n_perms}**

## Why a community dataset

Google publishes the method->permission mapping only as prose tables on ~180
per-service HTML pages (`cloud.google.com/<service>/docs/audit-logging`). There is
no official machine-readable export: the API Discovery service
(`discovery.googleapis.com`) gives canonical method ids but carries no IAM
permissions, and `permissions.queryTestablePermissions` requires authentication
and returns no method mapping.

`iam-dataset` derives its mapping by crawling those same official surfaces. It is
therefore a *convenience index over official data*, not an independent claim -- but
it is third-party, so it is cross-validated rather than trusted.

## Cross-validation

`python -m reference.validate_reference` samples entries from
`method_permissions.json` and checks them against the curated official
`rpc_methods.json` and against known-good pairs transcribed from Google docs.
Results are recorded in `validation_report.json`.

## Reproducing

    python -m reference.fetch_reference

Bump `DATASET_SHA` in `reference/fetch_reference.py` deliberately. The pinned SHA
is what the thesis coverage figures were computed against.
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sha", default=DATASET_SHA, help="upstream commit to pin")
    ap.add_argument("--check", action="store_true",
                    help="verify existing files instead of rewriting them")
    args = ap.parse_args()

    if args.check:
        missing = [f for f in ("method_permissions.json", "permissions.json")
                   if not (OUT / f).exists()]
        if missing:
            print(f"missing reference files: {missing}", file=sys.stderr)
            return 1
        mp = json.loads((OUT / "method_permissions.json").read_text())
        pv = json.loads((OUT / "permissions.json").read_text())
        print(f"ok: {len(mp)} methods, {len(pv)} permissions")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    print(f"pinning iam-dataset @ {args.sha}", file=sys.stderr)

    raw_map = fetch_json(args.sha, "map.json")
    method_perms = build_method_permissions(raw_map)
    (OUT / "method_permissions.json").write_text(
        json.dumps(method_perms, indent=1, sort_keys=True))

    raw_perms = fetch_json(args.sha, "permissions.json")
    vocab = build_permission_vocab(raw_perms)
    (OUT / "permissions.json").write_text(json.dumps(vocab, indent=1))

    (OUT / "PROVENANCE.md").write_text(PROVENANCE.format(
        sha=args.sha, date=DATASET_DATE,
        n_methods=len(method_perms), n_perms=len(vocab)))

    print(f"wrote {len(method_perms)} method->permission entries", file=sys.stderr)
    print(f"wrote {len(vocab)} canonical permissions", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
