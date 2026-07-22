# Provenance of the GCP naming reference tables

These tables are the join substrate between the detection corpora (which name
operations as API *methods*) and the technique corpus (which names them as IAM
*permissions*). They are pinned so coverage numbers are reproducible.

## Sources

| File | Source | Kind | Pinned at |
|---|---|---|---|
| `method_permissions.json` | [iann0036/iam-dataset](https://github.com/iann0036/iam-dataset) `gcp/map.json` | community, machine-readable | `1e4bdde1ef15ee01534ac4ed23221436e8796ab1` (2026-07-21T15:20:29Z) |
| `permissions.json` | same repo, `gcp/permissions.json` + `gcp/role_permissions.json` keys (union) | community, machine-readable | `1e4bdde1ef15ee01534ac4ed23221436e8796ab1` (2026-07-21T15:20:29Z) |
| `../../reference/rpc_methods.json` | Google Cloud per-service audit-logging docs | **official**, hand-transcribed | see per-entry `source` |

The permission vocabulary unions `permissions.json` with the (permission-keyed)
`role_permissions.json`, giving ~3.6k more permissions than `permissions.json` alone.
Read from the local clone `draft/iam-dataset` when it is checked out at the pinned SHA
(offline build), else fetched from GitHub -- identical either way.

## Counts

- REST methods with >=1 permission: **6072**
- Canonical IAM permissions: **13760**

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
