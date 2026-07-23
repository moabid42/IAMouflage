"""
The shared detection-record contract that every corpus parser emits.

One record per rule, in one shape, regardless of whether the rule was written in
Sigma YAML, Elastic TOML, YARA-L or Panther Python.

Firing semantics (the important part)
-------------------------------------
A rule does not "cover a list of operations". It fires when a *boolean condition*
over operations holds. If a rule requires calls B, C and D together, a technique
that performs only B and C must NOT count as detected -- the rule never fires.

So each rule carries its firing condition in **disjunctive normal form**:

    requirement.groups = [ G1, G2, ... ]        rule fires if ANY group is satisfied
    Gi                 = [ op1, op2, ... ]      group satisfied if ALL its ops occur

and, because one API method may be reachable through several permissions, each op
is itself a *disjunction* of permissions:

    op = {"permissions": [p1, p2, ...]}         op occurred if the actor used ANY pi

Putting it together, rule R detects technique T iff::

    exists G in R.groups such that
        for every op in G:  set(op.permissions) & set(T.required_perms) != {}
        and every op in G is logged by default

The two quantifiers come from different places and must not be confused:
  * ANY over permissions -- a permission can be exercised by several API methods,
    and we optimistically assume the attacker may take the watched path. This keeps
    blind-spot counts a strict lower bound.
  * ALL over ops in a group -- a conjunctive rule genuinely needs every call.

Negative filters (Sigma's `condition: selection and not filter`) are recorded in
`excluded` rather than folded into groups: a filter is an *evasion surface*, not a
coverage requirement, and conflating the two would understate coverage.

`requirement.confidence`
  exact   the rule language was parsed and the boolean structure is faithful
  approx  structure was partially recovered (e.g. nested logic was flattened)
  flat    no structure recovered; every op treated as its own single-op group
          (i.e. a pure disjunction -- the old, permissive behaviour)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from core.canonical import Canonicaliser, Resolution

# Paradigms, per docs/detection.md. Only `event` rules name a specific operation;
# the other two describe behaviour over history and therefore cover no single op.
EVENT = "event"
UEBA = "ueba"
CORRELATION = "correlation"


@dataclass
class OpRequirement:
    """One operation a rule requires, as the disjunction of permissions realising it."""

    token: str                      # the raw string the rule author wrote
    permissions: list[str] = field(default_factory=list)
    kind: str = "unresolved"
    confidence: str = "none"
    provenance: str = ""
    pattern: str | None = None      # set when the token was a wildcard matcher
    note: str = ""

    @classmethod
    def from_resolution(cls, r: Resolution) -> "OpRequirement":
        return cls(token=r.token, permissions=list(r.permissions), kind=r.kind,
                   confidence=r.confidence, provenance=r.provenance,
                   pattern=r.pattern, note=r.note)

    @property
    def resolved(self) -> bool:
        return bool(self.permissions)


@dataclass
class Requirement:
    """A rule's firing condition in DNF."""

    groups: list[list[OpRequirement]] = field(default_factory=list)
    excluded: list[OpRequirement] = field(default_factory=list)
    confidence: str = "flat"
    note: str = ""

    def all_ops(self) -> list[OpRequirement]:
        return [op for g in self.groups for op in g]

    def covered_permissions(self) -> list[str]:
        """Flat union of every permission mentioned. Debug/reporting only --
        never use this for detection, it discards the conjunctive structure."""
        return sorted({p for op in self.all_ops() for p in op.permissions})

    def satisfiable_groups(self) -> list[list[OpRequirement]]:
        """Groups in which every op resolved to at least one permission.

        A group containing an unresolved op can never be evaluated, so it cannot
        support a detection claim. Dropping it is the conservative choice.
        """
        return [g for g in self.groups if g and all(op.resolved for op in g)]


@dataclass
class DetectionRecord:
    """One detection rule, normalised across corpora."""

    id: str                          # namespaced, e.g. "sigma:1234-..."
    source: str                      # sigma | elastic | gsecops | panther
    native_id: str                   # the rule's own id in its corpus
    title: str
    file: str
    paradigm: str = EVENT
    level: str = "unknown"
    status: str = "unknown"
    domain: str = "gcp"              # gcp | workspace | k8s
    rule_type: str = ""              # corpus-native type, e.g. query/esql/machine_learning
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)
    requirement: Requirement = field(default_factory=Requirement)
    event_names: list[str] = field(default_factory=list)
    unresolved_tokens: list[str] = field(default_factory=list)
    threshold: int | None = None     # correlation rules: events needed to fire
    window: str | None = None        # correlation rules: time window
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        # convenience projection; NOT the detection input (see Requirement docstring)
        d["covered_permissions"] = self.requirement.covered_permissions()
        return d


def resolve_token_groups(
    token_groups: list[list[str]],
    canon: Canonicaliser,
    confidence: str = "exact",
    excluded_tokens: list[str] | None = None,
) -> tuple[Requirement, list[str]]:
    """Turn raw token DNF into a resolved Requirement.

    Returns (requirement, unresolved_tokens). Empty groups are dropped: a group with
    no operations would be trivially satisfied and would make the rule match
    everything.
    """
    groups: list[list[OpRequirement]] = []
    unresolved: list[str] = []

    for tokens in token_groups:
        ops: list[OpRequirement] = []
        for tok in tokens:
            # A token with no dot cannot be an operation (bare verbs like "create"
            # leak from startswith/contains fragment rules). Skip silently.
            if "." not in tok:
                continue
            r = canon.resolve(tok)
            if r.kind in {"noise"}:
                continue
            op = OpRequirement.from_resolution(r)
            if not op.resolved and op.pattern is None:
                unresolved.append(tok)
            ops.append(op)
        if ops:
            groups.append(ops)

    excluded = []
    for tok in (excluded_tokens or []):
        r = canon.resolve(tok)
        if r.kind != "noise":
            excluded.append(OpRequirement.from_resolution(r))

    return Requirement(groups=groups, excluded=excluded, confidence=confidence), unresolved


def dump_records(records: list[DetectionRecord], path) -> None:
    payload = [r.to_dict() for r in records]
    path.write_text(json.dumps(payload, indent=1))
