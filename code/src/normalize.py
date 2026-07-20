"""
Shared normalization: turn a GCP IAM permission or an audit-log methodName into a
canonical *operation signature* `service.resource.verb` so techniques and detections
can be joined despite three incompatible notations.

Why a normalized signature is needed
------------------------------------
GCP names "the same operation" three ways:

  * IAM permission     storage.buckets.setIamPolicy
  * audit methodName   v*.Compute.Firewalls.Insert  /  io.k8s.core.v*.secrets.create
  * sigma rule string  .serviceAccounts.disable (endswith, service dropped)

They disagree on casing, version prefixes (`v1.`, `v*.`) and package prefixes
(`io.k8s.core.`, `google.iam.admin.v1.`). We reduce every string to

        <service>.<resource>.<verb>       (all lower-case)

Design choices that keep the join correct:

* 3 segments, not 2. `resource.verb` alone collides across services
  (`compute.instances.create` vs `cloudsql.instances.create`;
   `run.jobs.create` vs the GKE CronJob rule's `jobs.create`;
   `secretmanager.secrets.delete` vs the GKE `secrets.delete` rule).
  Keeping the service prevents a technique from looking "covered" by an
  unrelated rule.

* Kubernetes alias. GKE RBAC permissions use the `container.*` service while the
  k8s audit methodNames use the `io.k8s.*` package. Both are folded to `gke` so a
  `container.pods.create` technique joins the `io.k8s.core.v1.pods.create` rule.

* Unknown-service wildcard `?`. The service-account rules match via
  `endswith: .serviceAccounts.disable`, so the service is absent in the rule
  string -> service `?`. `?` matches any service at join time. This is safe because
  the affected `serviceaccounts.*` resource/verb pairs are unique to IAM.

Conservatism: when in doubt the normalizer produces *different* signatures, which can
only make a technique look *less* covered, never more. Blind-spot counts are lower bounds.
"""

import re

# API version segments to drop: v1, v1beta1, v2alpha, and the sigma wildcard v*.
# Must contain a digit (or be v*) so real words like "vpnTunnels"/"versions" survive.
_VERSION_RE = re.compile(r"^v\d+[a-z0-9]*$|^v\*$")

# Kubernetes / framework path segments that are never a GCP service name.
# NB: real GCP services (e.g. `batch`, Google Cloud Batch) must NOT appear here, or
# their operations would lose their service and false-match unrelated rules. The only
# k8s methodNames auto-derived (not handled by RULE_OP_OVERRIDES) are the secrets and
# rolebinding rules, so we only need their framework prefixes.
_PKG_SEGMENTS = {
    "io", "k8s", "core", "rbac", "authorization",
    "googleapis", "com", "type", "admissionregistration",
}

# Fold GKE's two naming worlds (RBAC perms vs k8s audit package) into one service.
_SERVICE_ALIASES = {"container": "gke", "k8s": "gke"}

UNKNOWN_SERVICE = "?"


def op_signature(token: str) -> str | None:
    """Return canonical 'service.resource.verb' (service may be '?'), else None."""
    if not token:
        return None
    raw = [s for s in token.strip().strip(".").split(".") if s]
    k8s_origin = any(s.lower() == "k8s" for s in raw)
    segs = [s for s in raw if not _VERSION_RE.match(s)]
    # strip leading package-noise segments (io, k8s, core, ...)
    while segs and segs[0].lower() in _PKG_SEGMENTS:
        segs.pop(0)
    if len(segs) < 2:
        return None
    resource, verb = segs[-2].lower(), segs[-1].lower()
    if len(segs) >= 3:
        service = segs[0].lower()
    elif k8s_origin:
        service = "gke"
    else:
        service = UNKNOWN_SERVICE
    service = _SERVICE_ALIASES.get(service, service)
    return f"{service}.{resource}.{verb}"


def op_matches(technique_op: str, rule_op: str) -> bool:
    """Does a rule's covered op cover a technique's op?

    Equal on resource+verb, and services agree OR the rule left service unknown ('?').
    """
    t = technique_op.split(".")
    r = rule_op.split(".")
    if t[-2:] != r[-2:]:
        return False
    return r[0] == UNKNOWN_SERVICE or t[0] == UNKNOWN_SERVICE or t[0] == r[0]


def op_service(op: str) -> str:
    return op.split(".")[0]


def op_resource(op: str) -> str:
    return op.split(".")[-2]


def op_verb(op: str) -> str:
    return op.split(".")[-1]


# --- permission shape detection (used by the technique parser) ---------------
# service.resource.verb with >=3 dotted segments, first segment lower-case.
PERM_RE = re.compile(r"[a-z][a-zA-Z0-9]+(?:\.[a-zA-Z][a-zA-Z0-9]+){2,}")


def find_permissions(text: str) -> list[str]:
    """All permission-shaped tokens in a string, in order, de-duplicated (stable)."""
    seen, out = set(), []
    for m in PERM_RE.finditer(text):
        p = m.group(0)
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def perm_service(perm: str) -> str:
    return perm.split(".", 1)[0].lower()
