"""
Detection-side knowledge: the LOG-TYPE CLASSIFIER.

What telemetry does an operation produce? GCP Cloud Audit Logs split into:
  * ADMIN_ACTIVITY : configuration / IAM / metadata writes. ALWAYS ON, cannot be
                     disabled. A signature rule can see these.
  * DATA_ACCESS    : reads and data-plane writes (object content, secret payloads,
                     token minting, KMS decrypt). OFF BY DEFAULT for almost every
                     service. A signature rule literally never receives the event
                     unless the operator explicitly turned Data Access logging on.

=> A technique whose only observable operation is DATA_ACCESS is a *telemetry* blind
   spot (Class B): no signature can help until logging is reconfigured. This is
   distinct from a technique that IS logged but has no rule written (Class A).

Intentionally conservative; documented in the README.
"""

ADMIN_ACTIVITY = "ADMIN_ACTIVITY"
DATA_ACCESS = "DATA_ACCESS"

# Read / data-plane / credential-minting / crypto verbs -> DATA_ACCESS (off by default).
DATA_ACCESS_VERBS = {
    "get", "list", "aggregatedlist", "batchget", "getiampolicy", "testiampermissions",
    "access", "view", "read", "export", "exportdata", "getdata", "getfilecontents",
    "downloadartifacts", "accessreadtoken", "accessreadwritetoken",
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
    "replace", "destroy",
}

# (service, resource) pairs whose content operations are DATA_ACCESS regardless of verb
# (object/secret payload planes).
DATA_PLANE_RESOURCES = {
    ("storage", "objects"),
    ("secretmanager", "versions"),
}


def classify_method(op: str):
    """Return (log_type, logged_by_default) for an operation signature."""
    parts = op.split(".")
    service, resource, verb = parts[0], parts[-2], parts[-1]
    if verb in DATA_ACCESS_VERBS:
        lt = DATA_ACCESS
    elif (service, resource) in DATA_PLANE_RESOURCES:
        lt = DATA_ACCESS
    elif verb in ADMIN_VERBS:
        lt = ADMIN_ACTIVITY
    else:
        lt = ADMIN_ACTIVITY  # default: unknown writes behave like admin activity
    logged_by_default = lt == ADMIN_ACTIVITY
    return lt, logged_by_default
