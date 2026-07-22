"""
LOG-TYPE CLASSIFIER: does an operation produce telemetry a signature can see?

GCP Cloud Audit Logs split into:
  * ADMIN_ACTIVITY : configuration / IAM / metadata writes. ALWAYS ON, cannot be
                     disabled. A signature rule can see these.
  * DATA_ACCESS    : reads and data-plane writes (object content, secret payloads,
                     token minting, KMS decrypt). OFF BY DEFAULT for every service
                     except BigQuery. A signature rule never receives the event
                     unless Data Access logging was explicitly enabled.

=> A technique whose only observable operation is DATA_ACCESS is a *telemetry* blind
   spot (Class B): no signature can help until logging is reconfigured. Distinct from
   a technique that IS logged but has no rule written (Class A).

Two sources of truth, authoritative first
-----------------------------------------
Google assigns every permission a *type*: ADMIN_WRITE -> Admin Activity; ADMIN_READ /
DATA_READ / DATA_WRITE -> Data Access. Where we have that type from official docs
(the curated gRPC table, reference/rpc_methods.json), we use it directly.

Elsewhere we fall back to a verb heuristic over the canonical permission
`service.resource.verb`. Because inputs are now canonical IAM permissions (not raw
method strings), the heuristic is far more reliable than when it ran on mixed
notation. It is intentionally conservative and documented in the README.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

ADMIN_ACTIVITY = "ADMIN_ACTIVITY"
DATA_ACCESS = "DATA_ACCESS"

# Read / data-plane / credential-minting / crypto verbs -> DATA_ACCESS (off by default).
DATA_ACCESS_VERBS = {
    "get", "list", "aggregatedlist", "batchget", "getiampolicy", "testiampermissions",
    "access", "view", "read", "export", "exportdata", "getdata", "getfilecontents",
    "downloadartifacts", "accessreadtoken", "accessreadwritetoken", "getkeystring",
    "fetchlinkablerepositories", "consume", "reidentify", "portforward", "exec",
    # credential / token minting (iamcredentials + friends)
    "getaccesstoken", "getopenidtoken", "getidtoken", "generateaccesstoken",
    "generateidtoken", "signblob", "signjwt", "createtoken", "implicitdelegation",
    # KMS crypto operations
    "usetodecrypt", "usetodecryptviadelegation", "usetoencrypt", "decrypt", "encrypt",
}

# Configuration / IAM / metadata writes -> ADMIN_ACTIVITY (always on).
ADMIN_VERBS = {
    "create", "delete", "update", "patch", "insert", "setiampolicy", "disable",
    "enable", "undelete", "set", "upload", "import", "run", "runwithoverrides",
    "bind", "escalate", "add", "remove", "attachsubscription", "sourcecodeset",
    "setmetadata", "setcommoninstancemetadata", "setserviceaccount", "enabledebug",
    "deploy", "oslogin", "osadminlogin", "useexternalip", "use", "updateprojectconfig",
    "replace", "destroy", "actas",
}

# (service, resource) pairs whose content operations are DATA_ACCESS regardless of verb
# (object/secret payload planes).
DATA_PLANE_RESOURCES = {
    ("storage", "objects"),
    ("secretmanager", "versions"),
}

_CURATED = Path(__file__).resolve().parents[1] / "reference" / "rpc_methods.json"


@lru_cache(maxsize=1)
def _authoritative() -> dict[str, str]:
    """permission -> audit_log, transcribed from official Google docs via the gRPC table."""
    out: dict[str, str] = {}
    if not _CURATED.exists():
        return out
    for key, entry in json.loads(_CURATED.read_text()).items():
        if key.startswith("_"):
            continue
        audit = entry.get("audit_log")
        for p in (entry.get("permissions") or []):
            if audit in (ADMIN_ACTIVITY, DATA_ACCESS):
                out[p] = audit
    return out


def classify_permission(perm: str) -> tuple[str, bool, str]:
    """Return (log_type, logged_by_default, source) for a canonical IAM permission.

    source is "official" when taken from the curated permission-type table, else
    "heuristic".
    """
    auth = _authoritative().get(perm)
    if auth:
        return auth, auth == ADMIN_ACTIVITY, "official"

    parts = perm.split(".")
    service, resource, verb = parts[0], parts[-2], parts[-1]
    vl = verb.lower()
    if vl in DATA_ACCESS_VERBS:
        lt = DATA_ACCESS
    elif (service, resource) in DATA_PLANE_RESOURCES:
        lt = DATA_ACCESS
    elif vl in ADMIN_VERBS:
        lt = ADMIN_ACTIVITY
    else:
        lt = ADMIN_ACTIVITY  # default: unknown writes behave like admin activity
    return lt, lt == ADMIN_ACTIVITY, "heuristic"


# Backwards-compatible shim for callers that pass an op signature and want the old
# 2-tuple. The op signature and a canonical permission share the service.resource.verb
# shape, so classification is identical.
def classify_method(op: str):
    lt, logged, _ = classify_permission(op)
    return lt, logged
