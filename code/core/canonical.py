"""
Canonicalisation: resolve any operation token a detection rule mentions into the
IAM permission(s) it corresponds to.

The problem
-----------
Google names one operation three incompatible ways, and the two corpora we join
speak different dialects:

    IAM permission     compute.firewalls.create      <- technique corpus
    REST method id     compute.firewalls.insert      <- Sigma / Panther / Elastic
    gRPC method name   google.iam.admin.v1.CreateServiceAccount

`insert` vs `create` is the same operation. No string normalisation joins those
two, which is why the old `op_signature()` approach could not work: it produced a
syntactic signature and hoped both sides agreed. They do not.

So we resolve through real lookup tables instead (see data/reference/, pinned and
documented in PROVENANCE.md), and canonicalise everything to the **IAM permission**.
Permission is the right canonical form because it is the unit of authorisation --
what a technique actually needs -- and because the technique corpus already speaks it.

Resolution ladder
-----------------
Each token is tried against progressively weaker evidence, and the winning rung is
recorded on the result so downstream code (and the thesis) can distinguish a
table-backed fact from an inference:

  1. exact        token is already a canonical IAM permission
  2. exact        token is a known REST method id      -> its declared permissions
  3. normalized   version/case-folded REST method id   -> its declared permissions
  4. k8s          io.k8s.<group>.<v>.<res>.<verb>      -> container.<res>.<verb>
  5. official     curated gRPC table (Google audit-logging docs)
  6. pattern      wildcard/suffix matcher (`.serviceAccounts.disable`, `*.firewalls.insert`)
  7. unresolved   recorded with a reason; never silently dropped

Patterns are *not* expanded here. A bare `SetIamPolicy` legitimately matches
hundreds of permissions, and eagerly expanding it would swamp the graph. The
resolver returns the pattern and lets the caller expand it against the set of
permissions that actually matter (see `expand_pattern`).

Conservatism: an unresolved token yields nothing rather than a guess. That can only
make a technique look *less* covered, never more, so blind-spot counts stay a lower
bound -- the same guarantee the old normaliser claimed, now actually earned.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

REF = Path(__file__).resolve().parents[1] / "data" / "reference"
CURATED = Path(__file__).resolve().parents[1] / "reference"

# Version / channel segments to drop when folding a method id: v1, v1beta1, v2alpha,
# v*, and the bare `beta`/`alpha` channel prefixes rule authors put on method ids
# (e.g. `beta.compute.images.setIamPolicy`). No IAM resource is literally named
# "beta"/"alpha", so stripping them is safe.
_VERSION_RE = re.compile(r"^v\d+[a-z0-9]*$|^v\*$|^\*$|^beta$|^alpha$", re.IGNORECASE)

# Permission-level renames: a handful of corpora reference an operation by a service
# name Google has since retired, or by a legacy short audit methodName that has too few
# segments to resolve structurally. The permission *vocabulary* only carries the current
# name, so these would otherwise be honest-but-avoidable misses. Each maps to a permission
# verified present in the current vocabulary.
_PERMISSION_ALIASES = {
    "serviceusage.apiKeys.create": "apikeys.keys.create",
    "serviceusage.apiKeys.list": "apikeys.keys.list",
    # legacy 2-segment audit methodName for bucket IAM changes (storage.setIamPermissions
    # / storage.setIamPolicy). Used by Elastic/GSecOps/Panther bucket-permission rules.
    "storage.setIamPermissions": "storage.buckets.setIamPolicy",
    "storage.setIamPolicy": "storage.buckets.setIamPolicy",
}

# GKE audit methodNames use k8s HTTP verbs; GCP IAM collapses some of them. Notably
# there is no `container.<res>.patch` permission -- both PATCH and PUT map to the
# `update` permission. Applied only in the k8s rung, where the mapping is heuristic.
_K8S_VERB_ALIASES = {"patch": "update", "replace": "update"}

# Kubernetes audit method: io.k8s.<group...>.<version>.<resource>.<verb>
_K8S_RE = re.compile(r"^io\.k8s\.", re.IGNORECASE)

# Google Workspace / login event names are a different telemetry stream entirely
# (not Cloud Audit Logs), so they can never resolve to a GCP IAM permission.
_WORKSPACE_EVENT_RE = re.compile(r"^[A-Z0-9_]+$")

# Tokens that look dotted but are hostnames, emails or payload types, not operations.
_NOISE_RE = re.compile(
    r"(googleapis\.com$|gserviceaccount\.com$|\.iam\.gserviceaccount|"
    r"^www\.|\.AuditData$|^google\.protobuf|^type\.googleapis)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Resolution:
    """What a raw rule token turned out to mean."""

    token: str
    permissions: tuple[str, ...] = ()
    pattern: str | None = None          # regex, when the token is a wildcard matcher
    kind: str = "unresolved"            # permission|rest_method|k8s|grpc_method|
                                        # pattern|workspace_event|noise|unresolved
    confidence: str = "none"            # exact|normalized|official|inferred|pattern|none
    provenance: str = ""                # human-readable trace, kept for the thesis
    note: str = ""

    @property
    def resolved(self) -> bool:
        return bool(self.permissions) or self.pattern is not None


def _strip_versions(token: str) -> str:
    segs = [s for s in token.split(".") if s and not _VERSION_RE.match(s)]
    return ".".join(segs)


class Canonicaliser:
    """Loads the pinned reference tables once and resolves tokens against them."""

    def __init__(self, ref_dir: Path = REF, curated_dir: Path = CURATED):
        self.perm_vocab: set[str] = set(
            json.loads((ref_dir / "permissions.json").read_text()))
        self.method_perms: dict[str, list[str]] = json.loads(
            (ref_dir / "method_permissions.json").read_text())

        rpc_path = curated_dir / "rpc_methods.json"
        raw_rpc = json.loads(rpc_path.read_text()) if rpc_path.exists() else {}
        self.rpc: dict[str, dict] = {
            k: v for k, v in raw_rpc.items() if not k.startswith("_")}

        # Case/version-folded indexes. Rule authors write `v*.Compute.Firewalls.Insert`
        # where the API says `compute.firewalls.insert`, and `Dns.ManagedZones.Delete`
        # where the API says `dns.managedZones.delete` -- so fold on lowercase.
        self._perm_idx = {p.lower(): p for p in self.perm_vocab}
        self._method_idx: dict[str, str] = {}
        for m in self.method_perms:
            self._method_idx.setdefault(_strip_versions(m).lower(), m)
        self._rpc_idx = {_strip_versions(k).lower(): k for k in self.rpc}

        self.unresolved: list[str] = []

    # -- individual rungs ----------------------------------------------------

    def _as_permission(self, tok: str) -> Resolution | None:
        alias = _PERMISSION_ALIASES.get(tok)
        if alias:
            return Resolution(tok, (alias,), kind="permission", confidence="normalized",
                              provenance=f"permission alias {tok} -> {alias} (retired service name)")
        if tok in self.perm_vocab:
            return Resolution(tok, (tok,), kind="permission", confidence="exact",
                              provenance="permissions.json")
        hit = self._perm_idx.get(_strip_versions(tok).lower())
        if hit:
            return Resolution(tok, (hit,), kind="permission", confidence="normalized",
                              provenance=f"permissions.json (folded {tok} -> {hit})")
        return None

    def _as_rest_method(self, tok: str) -> Resolution | None:
        perms = self.method_perms.get(tok)
        if perms:
            return Resolution(tok, tuple(perms), kind="rest_method", confidence="exact",
                              provenance=f"method_permissions.json[{tok}]")
        hit = self._method_idx.get(_strip_versions(tok).lower())
        if hit:
            return Resolution(tok, tuple(self.method_perms[hit]), kind="rest_method",
                              confidence="normalized",
                              provenance=f"method_permissions.json[{hit}] (folded from {tok})")
        return None

    def _as_k8s(self, tok: str) -> Resolution | None:
        """io.k8s.core.v1.pods.create -> container.pods.create

        GKE RBAC permissions live under the `container.*` service while the k8s audit
        methodNames use the `io.k8s.*` package. Both name the same operation.
        """
        if not _K8S_RE.match(tok):
            return None
        segs = [s for s in tok.split(".") if s and not _VERSION_RE.match(s)]
        # drop the io.k8s framework prefix and any api-group segments
        segs = [s for s in segs if s.lower() not in
                {"io", "k8s", "core", "api", "apis", "rbac", "authorization",
                 "admissionregistration", "apps", "batch", "policy", "networking"}]
        if len(segs) < 2:
            return None
        # `pods.exec.create` -> resource `pods`, subresource `exec`; verb is last
        resource, verb = segs[0], segs[-1]
        for v in (verb, _K8S_VERB_ALIASES.get(verb)):
            if not v:
                continue
            cand = f"container.{resource}.{v}"
            hit = self._perm_idx.get(cand.lower())
            if hit:
                note = "" if v == verb else f"k8s verb {verb}->{v} (no container.*.{verb} permission)"
                return Resolution(tok, (hit,), kind="k8s", confidence="normalized",
                                  provenance=f"k8s->container alias ({tok} -> {hit})", note=note)
        return Resolution(tok, (), kind="k8s", confidence="none",
                          provenance=f"k8s alias container.{resource}.{verb} not in permission vocabulary",
                          note="GKE operation with no matching container.* permission")

    def _as_grpc(self, tok: str) -> Resolution | None:
        key = None
        folded = _strip_versions(tok).lower()
        if tok in self.rpc:
            key = tok
        elif folded in self._rpc_idx:
            key = self._rpc_idx[folded]
        elif "." in tok and tok.lstrip(".").split(".", 1)[0][:1].isupper():
            # A bare CamelCase method *suffix* -- rule authors match with
            # `.endswith("TagBindings.CreateTagBinding")`, dropping the service prefix.
            # Match it against the tail of the curated (folded) gRPC keys.
            suf = "." + folded
            hits = [orig for f, orig in self._rpc_idx.items() if ("." + f).endswith(suf)]
            if len(hits) == 1:
                key = hits[0]
            elif len(hits) > 1:
                perms = tuple(sorted({p for h in hits
                                      for p in (self.rpc[h].get("permissions") or ())}))
                return Resolution(tok, perms, kind="grpc_method", confidence="pattern",
                                  provenance=f"rpc_methods.json suffix, {len(hits)} matches",
                                  note=f"matched {', '.join(sorted(hits))}")
        elif "*" in tok:
            # Rule authors wildcard inside the method name too, e.g.
            # `google.appengine.*.Firewall.Create*Rule`. Match the folded token as a
            # regex against the folded curated keys.
            rx = re.compile("^" + re.escape(folded).replace(r"\*", "[^.]*") + "$")
            hits = [orig for f, orig in self._rpc_idx.items() if rx.match(f)]
            if len(hits) == 1:
                key = hits[0]
            elif len(hits) > 1:
                # ambiguous wildcard: union the permissions of every match
                perms = tuple(sorted({p for h in hits
                                      for p in (self.rpc[h].get("permissions") or ())}))
                return Resolution(tok, perms, kind="grpc_method", confidence="pattern",
                                  provenance=f"rpc_methods.json, {len(hits)} wildcard matches",
                                  note=f"matched {', '.join(sorted(hits))}")
        if key is None:
            return None

        entry = self.rpc[key]
        perms = tuple(entry.get("permissions") or ())
        return Resolution(
            tok, perms, pattern=entry.get("pattern"), kind="grpc_method",
            confidence=entry.get("confidence", "inferred"),
            provenance=f"rpc_methods.json[{key}] <- {entry.get('source') or 'curated'}",
            note=entry.get("note", ""))

    def _as_pattern(self, tok: str) -> Resolution | None:
        """Suffix / wildcard matchers used by rule authors.

        Sigma writes `endswith: .serviceAccounts.disable`; Elastic writes
        `*.compute.firewalls.insert`. Both denote a set of real operations, so we
        return a regex and let the caller expand it against the permissions that
        actually matter.
        """
        if "*" not in tok and not tok.startswith("."):
            return None
        # Build the regex from the raw token: `*` is a one-segment wildcard. Do NOT
        # version-strip here -- a mid-token `*` (e.g. `bigquery.*.setIamPolicy`, "any
        # bigquery resource") would otherwise be deleted as a version segment, collapsing
        # the pattern. (Version-wildcard method ids like `v*.Compute.Firewalls.Insert`
        # never reach this rung; they resolve as REST methods first.)
        body = re.escape(tok.strip()).replace(r"\*", "[^.]*")
        if tok.startswith("."):
            rx = f".*{body}$"
        elif tok.endswith("*"):
            rx = f"^{body}"
        else:
            rx = f"^{body}$" if not tok.startswith("*") else f".*{body}$"
        return Resolution(tok, (), pattern=rx, kind="pattern", confidence="pattern",
                          provenance=f"wildcard matcher {tok!r} -> /{rx}/")

    # -- public --------------------------------------------------------------

    def resolve(self, token: str) -> Resolution:
        tok = (token or "").strip().strip('"\'').strip()
        if not tok:
            return Resolution(token, note="empty token")
        if _NOISE_RE.search(tok):
            return Resolution(tok, kind="noise", provenance="hostname/payload-type, not an operation")
        if _WORKSPACE_EVENT_RE.match(tok):
            return Resolution(tok, kind="workspace_event", confidence="exact",
                              provenance="Workspace admin/login event name",
                              note="different telemetry stream; covers no GCP API operation")

        # A gRPC/k8s rung that matched but yielded no permission is still a *fact*
        # ("this method has no citable GCP permission"), not a miss -- keep it rather
        # than letting the token fall through to the weaker pattern rung.
        for rung in (self._as_permission, self._as_rest_method, self._as_k8s,
                     self._as_grpc, self._as_pattern):
            got = rung(tok)
            if got is not None and (got.resolved or got.kind in {"k8s", "grpc_method"}):
                return got

        self.unresolved.append(tok)
        return Resolution(tok, provenance="no rung matched",
                          note="not a permission, REST method, k8s op, known gRPC method or pattern")

    def expand_pattern(self, rx: str, universe: set[str]) -> tuple[str, ...]:
        """Concrete permissions in `universe` matched by a pattern resolution.

        `universe` is normally the permissions the technique corpus actually uses,
        plus every concretely-resolved permission. Expanding against the full 10k
        vocabulary would let a generic matcher like `.setIamPolicy` blow up the graph
        with permissions no technique ever needs.
        """
        pat = re.compile(rx, re.IGNORECASE)
        return tuple(sorted(p for p in universe if pat.search(p)))


@lru_cache(maxsize=1)
def canonicaliser() -> Canonicaliser:
    return Canonicaliser()
