"""
Build the Neo4j detection-gap graph, joining techniques to detections on the *IAM
permission* -- the unit of authorisation both sides ultimately speak.

Why permission-centric
-----------------------
The old graph joined on a synthetic `service.resource.verb` op-signature and hoped the
technique and rule dialects agreed. They do not (`compute.firewalls.insert` the method
vs `compute.firewalls.create` the permission are the same operation). So detections are
now *canonicalised to permissions* up front (see core.canonical, detection/*), and the
graph joins Technique.REQUIRES(Permission) against DetectionRule ops that also resolve
to Permissions.

Firing semantics (DNF)
----------------------
A rule fires on a boolean condition, not a flat op list. Each rule carries its
condition in disjunctive normal form: groups ORed, ops within a group ANDed, and each
op a disjunction of the permissions that realise it. Rule R detects technique T iff::

    exists group G in R such that for every op in G:
        (a) some permission of op is required by T          (coverage)
        (b) some such permission is logged by default        (visibility)

(a) uses ANY-permission (an operation may be reached via several permissions, and we
optimistically assume the watched path is taken -> blind-spot counts stay a lower
bound). (b) is the telemetry gate: a conjunct the logs never show cannot complete the
pattern. UEBA rules name no operation, so they have no groups and detect nothing; that
is intentional -- they are kept as nodes for "what only anomaly detection would catch".

Blind classification (per technique)
------------------------------------
  DETECTED         an event (single-shot) rule fires on it
  CORRELATION_ONLY only a threshold/multi-stage rule fires (needs repetition/a chain)
  RULE_GAP         at least one required permission is logged, but no rule fires
  TELEMETRY_GAP    no required permission is logged by default -- invisible until
                   Data Access logging is reconfigured

Schema
------
Nodes
  (:Tactic {name}) (:Service {name})
  (:Technique {id,title,tactic,service,requires_actas,num_required,num_optional,
               primary_perm,any_logged,detected,detected_event,blind_class,
               detected_by_sigma_event})
  (:Permission {name,service,resource,verb,log_type,logged_by_default,log_source})
  (:DetectionRule {id,source,native_id,title,paradigm,level,status,domain,rule_type,
                   threshold,window,num_groups,covers_ops})
  (:RuleGroup {id,rule_id,size})          only conjunctive groups (size>=2)
  (:Capability {name,kind})
Relationships
  (Technique)-[:IN_TACTIC]->(Tactic) (Technique)-[:FOR_SERVICE]->(Service)
  (Technique)-[:REQUIRES {optional}]->(Permission)
  (DetectionRule)-[:WATCHES {op_token}]->(Permission)
  (DetectionRule)-[:HAS_GROUP]->(RuleGroup)-[:NEEDS {op_token}]->(Permission)
  (Technique)-[:DETECTED_BY {paradigm,threshold,group_size,single_event}]->(DetectionRule)
  (Technique)-[:GRANTS]->(Capability) (Capability)-[:IMPLIES]->(Capability)
  (Capability)-[:UNLOCKS]->(Technique) (Technique)-[:ENABLES {via}]->(Technique)

Usage:  python -m graph.build_graph      (env: NEO4J_URI, NEO4J_USER, NEO4J_PASS)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from detection.logtype import classify_permission
from library.capabilities import (
    CAPABILITY_IMPLIES, CROWN_JEWELS, PIVOTS, capability_unlocks, technique_grants,
)

URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
USER = os.environ.get("NEO4J_USER", "neo4j")
PASS = os.environ.get("NEO4J_PASS", "detgap-thesis")

DATA = Path(__file__).resolve().parents[1] / "data"

EVENT = "event"


def load_json(name):
    return json.loads((DATA / name).read_text())


def perm_parts(perm):
    p = perm.split(".")
    return p[0], p[-2], p[-1]


def _op_perms(op):
    return set(op.get("permissions") or [])


def rule_detects(rule, req_perms: set[str], logged: dict[str, bool]):
    """Return the first satisfying (group, via) or (None, None).

    group: the DNF group that fired. via: per-op, the required+logged permissions that
    satisfied it. A group satisfies iff every op is both covered by T and logged.
    """
    for group in rule["requirement"]["groups"]:
        if not group:
            continue
        via, ok = [], True
        for op in group:
            inter = _op_perms(op) & req_perms
            if not inter or not any(logged.get(p, False) for p in inter):
                ok = False
                break
            via.append(sorted(inter))
        if ok:
            return group, via
    return None, None


def build_model():
    techs = load_json("techniques.json")
    rules = load_json("detections.json")

    # ---- Permission universe + per-permission log type -------------------------
    perms: dict[str, dict] = {}

    def ensure_perm(name, source_hint=""):
        if name not in perms:
            s, r, v = perm_parts(name)
            lt, logged, src = classify_permission(name)
            perms[name] = {"name": name, "service": s, "resource": r, "verb": v,
                           "log_type": lt, "logged_by_default": logged,
                           "log_source": src}
        return perms[name]

    for t in techs:
        for p in t["required_perms"] + t["optional_perms"]:
            ensure_perm(p)
    for r in rules:
        for op in (r["requirement"]["groups"] and
                   [op for g in r["requirement"]["groups"] for op in g] or []):
            for p in _op_perms(op):
                ensure_perm(p)

    logged = {name: pv["logged_by_default"] for name, pv in perms.items()}

    # ---- Detection join (DNF) --------------------------------------------------
    detected_by = []           # {tech_id, rule_id, paradigm, threshold, group_size, single_event}
    for t in techs:
        req = set(t["required_perms"])
        any_logged = any(logged.get(p, False) for p in req)
        fired_event = False
        fired_any = False
        for r in rules:
            group, via = rule_detects(r, req, logged)
            if group is None:
                continue
            single = r["paradigm"] == EVENT and len(group) == 1 and (r.get("threshold") in (None, 1))
            fired_any = True
            fired_event = fired_event or single
            detected_by.append({
                "tech_id": t["id"], "rule_id": r["id"], "paradigm": r["paradigm"],
                "threshold": r.get("threshold"), "group_size": len(group),
                "single_event": single, "source": r["source"],
                "via": json.dumps(via),
            })
        t["any_logged"] = any_logged
        t["detected"] = fired_any
        t["detected_event"] = fired_event
        t["blind_class"] = (
            "DETECTED" if fired_event else
            "CORRELATION_ONLY" if fired_any else
            "RULE_GAP" if any_logged else
            "TELEMETRY_GAP")
        t["num_required"] = len(t["required_perms"])
        t["num_optional"] = len(t["optional_perms"])
        # sigma-only single-event detection, for reproducing the pre-merge baseline
        t["detected_by_sigma_event"] = any(
            d["tech_id"] == t["id"] and d["source"] == "sigma" and d["single_event"]
            for d in detected_by)

    # ---- Rule projections (WATCHES flat + conjunctive RuleGroups) --------------
    watches = []       # {rule_id, perm, op_token}
    rule_groups = []   # {id, rule_id, size}
    group_needs = []   # {group_id, perm, op_token}
    for r in rules:
        seen = set()
        for gi, group in enumerate(r["requirement"]["groups"]):
            for op in group:
                for p in _op_perms(op):
                    key = (p, op["token"])
                    if key not in seen:
                        seen.add(key)
                        watches.append({"rule_id": r["id"], "perm": p, "op_token": op["token"]})
            if len(group) >= 2:  # materialise conjunctions only
                gid = f"{r['id']}#g{gi}"
                rule_groups.append({"id": gid, "rule_id": r["id"], "size": len(group)})
                for op in group:
                    for p in _op_perms(op):
                        group_needs.append({"group_id": gid, "perm": p, "op_token": op["token"]})
        r["num_groups"] = len(r["requirement"]["groups"])
        r["covers_ops"] = sorted({op["token"] for g in r["requirement"]["groups"] for op in g})

    # ---- Capabilities + ENABLES (unchanged model) ------------------------------
    cap_kind = {c: "crown_jewel" for c in CROWN_JEWELS}
    cap_kind.update({c: "pivot" for c in PIVOTS})
    grants = []
    for t in techs:
        for c in technique_grants(t):
            grants.append({"tech_id": t["id"], "cap": c})
            cap_kind.setdefault(c, "pivot")
    unlocks, unlocks_by_cap = [], {}
    for t in techs:
        for c in cap_kind:
            if capability_unlocks(c, t):
                unlocks.append({"cap": c, "tech_id": t["id"]})
                unlocks_by_cap.setdefault(c, []).append(t["id"])

    implies_adj = {}
    for a, b in CAPABILITY_IMPLIES:
        implies_adj.setdefault(a, []).append(b)

    def implies_closure(cap):
        seen, stack = set(), [cap]
        while stack:
            c = stack.pop()
            if c in seen:
                continue
            seen.add(c)
            stack.extend(implies_adj.get(c, []))
        return seen

    grants_by_tech = {}
    for g in grants:
        grants_by_tech.setdefault(g["tech_id"], set()).add(g["cap"])
    enables = []
    for t in techs:
        reachable = set()
        for c in grants_by_tech.get(t["id"], ()):
            reachable |= implies_closure(c)
        for cap in reachable:
            for tgt in unlocks_by_cap.get(cap, ()):
                if tgt != t["id"]:
                    enables.append({"src": t["id"], "dst": tgt, "via": cap})

    return {
        "techs": techs, "rules": rules, "perms": list(perms.values()),
        "watches": watches, "rule_groups": rule_groups, "group_needs": group_needs,
        "detected_by": detected_by,
        "capabilities": [{"name": k, "kind": v} for k, v in cap_kind.items()],
        "grants": grants, "unlocks": unlocks, "enables": enables,
        "implies": [{"a": a, "b": b} for a, b in CAPABILITY_IMPLIES],
        "req_edges": [
            {"tech_id": t["id"], "perm": p, "optional": opt}
            for t in techs
            for p, opt in ([(x, False) for x in t["required_perms"]]
                           + [(x, True) for x in t["optional_perms"]])
        ],
    }


CONSTRAINTS = [
    "CREATE CONSTRAINT tech_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
    "CREATE CONSTRAINT perm_name IF NOT EXISTS FOR (p:Permission) REQUIRE p.name IS UNIQUE",
    "CREATE CONSTRAINT rule_id IF NOT EXISTS FOR (r:DetectionRule) REQUIRE r.id IS UNIQUE",
    "CREATE CONSTRAINT group_id IF NOT EXISTS FOR (g:RuleGroup) REQUIRE g.id IS UNIQUE",
    "CREATE CONSTRAINT cap_name IF NOT EXISTS FOR (c:Capability) REQUIRE c.name IS UNIQUE",
    "CREATE CONSTRAINT tactic_name IF NOT EXISTS FOR (x:Tactic) REQUIRE x.name IS UNIQUE",
    "CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE",
]


def load(model):
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(URI, auth=(USER, PASS))
    driver.verify_connectivity()
    with driver.session() as s:
        s.run("MATCH (n) DETACH DELETE n")
        for c in CONSTRAINTS:
            s.run(c)

        s.run("""UNWIND $rows AS t
            MERGE (n:Technique {id:t.id}) SET n += {
              title:t.title, tactic:t.tactic, service:t.service,
              requires_actas:t.requires_actas, num_required:t.num_required,
              num_optional:t.num_optional, primary_perm:t.primary_perm,
              any_logged:t.any_logged, detected:t.detected,
              detected_event:t.detected_event, blind_class:t.blind_class,
              detected_by_sigma_event:t.detected_by_sigma_event }
            MERGE (ta:Tactic {name:t.tactic}) MERGE (n)-[:IN_TACTIC]->(ta)
            MERGE (sv:Service {name:t.service}) MERGE (n)-[:FOR_SERVICE]->(sv)
        """, rows=model["techs"])

        s.run("""UNWIND $rows AS p
            MERGE (n:Permission {name:p.name}) SET n += {
              service:p.service, resource:p.resource, verb:p.verb,
              log_type:p.log_type, logged_by_default:p.logged_by_default,
              log_source:p.log_source }
        """, rows=model["perms"])

        s.run("""UNWIND $rows AS r
            MERGE (n:DetectionRule {id:r.id}) SET n += {
              source:r.source, native_id:r.native_id, title:r.title,
              paradigm:r.paradigm, level:r.level, status:r.status, domain:r.domain,
              rule_type:r.rule_type, threshold:r.threshold, window:r.window,
              num_groups:r.num_groups, covers_ops:r.covers_ops }
        """, rows=model["rules"])

        s.run("""UNWIND $rows AS g MERGE (n:RuleGroup {id:g.id})
                 SET n.rule_id=g.rule_id, n.size=g.size""", rows=model["rule_groups"])
        s.run("""UNWIND $rows AS c MERGE (n:Capability {name:c.name})
                 SET n.kind=c.kind""", rows=model["capabilities"])

        s.run("""UNWIND $rows AS e
            MATCH (t:Technique {id:e.tech_id}), (p:Permission {name:e.perm})
            MERGE (t)-[r:REQUIRES]->(p) SET r.optional=e.optional""", rows=model["req_edges"])
        s.run("""UNWIND $rows AS e
            MATCH (r:DetectionRule {id:e.rule_id}), (p:Permission {name:e.perm})
            MERGE (r)-[w:WATCHES]->(p) SET w.op_token=e.op_token""", rows=model["watches"])
        s.run("""UNWIND $rows AS e
            MATCH (r:DetectionRule {id:e.rule_id}), (g:RuleGroup {id:e.id})
            MERGE (r)-[:HAS_GROUP]->(g)""", rows=model["rule_groups"])
        s.run("""UNWIND $rows AS e
            MATCH (g:RuleGroup {id:e.group_id}), (p:Permission {name:e.perm})
            MERGE (g)-[n:NEEDS]->(p) SET n.op_token=e.op_token""", rows=model["group_needs"])
        s.run("""UNWIND $rows AS e
            MATCH (t:Technique {id:e.tech_id}), (r:DetectionRule {id:e.rule_id})
            MERGE (t)-[d:DETECTED_BY]->(r) SET d += {
              paradigm:e.paradigm, threshold:e.threshold, group_size:e.group_size,
              single_event:e.single_event, via:e.via }""", rows=model["detected_by"])
        s.run("""UNWIND $rows AS e
            MATCH (t:Technique {id:e.tech_id}), (c:Capability {name:e.cap})
            MERGE (t)-[:GRANTS]->(c)""", rows=model["grants"])
        s.run("""UNWIND $rows AS e
            MATCH (a:Capability {name:e.a}), (b:Capability {name:e.b})
            MERGE (a)-[:IMPLIES]->(b)""", rows=model["implies"])
        s.run("""UNWIND $rows AS e
            MATCH (c:Capability {name:e.cap}), (t:Technique {id:e.tech_id})
            MERGE (c)-[:UNLOCKS]->(t)""", rows=model["unlocks"])
        s.run("""UNWIND $rows AS e
            MATCH (a:Technique {id:e.src}), (b:Technique {id:e.dst})
            MERGE (a)-[r:ENABLES]->(b) SET r.via=e.via""", rows=model["enables"])

        counts = {lbl: s.run(f"MATCH (n:{lbl}) RETURN count(n) AS c").single()["c"]
                  for lbl in ["Technique", "Permission", "DetectionRule", "RuleGroup",
                              "Capability", "Tactic", "Service"]}
        rels = {rel: s.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c").single()["c"]
                for rel in ["REQUIRES", "WATCHES", "HAS_GROUP", "NEEDS", "DETECTED_BY",
                            "GRANTS", "IMPLIES", "UNLOCKS", "ENABLES", "IN_TACTIC",
                            "FOR_SERVICE"]}
    driver.close()
    return counts, rels


def summarise(model):
    from collections import Counter
    techs = model["techs"]
    bc = Counter(t["blind_class"] for t in techs)
    n = len(techs)
    print(f"techniques: {n}")
    for cls in ("DETECTED", "CORRELATION_ONLY", "RULE_GAP", "TELEMETRY_GAP"):
        c = bc.get(cls, 0)
        print(f"  {cls:16s} {c:4d}  ({100*c/n:.1f}%)")
    sig = sum(1 for t in techs if t["detected_by_sigma_event"])
    print(f"  [baseline] sigma single-event DETECTED: {sig} ({100*sig/n:.1f}%)")
    print(f"rules: {len(model['rules'])}  permissions: {len(model['perms'])}  "
          f"detected_by edges: {len(model['detected_by'])}  "
          f"conjunctive groups: {len(model['rule_groups'])}")


def main():
    model = build_model()
    summarise(model)
    try:
        counts, rels = load(model)
        print("\nLoaded graph into", URI)
        print("nodes:", counts)
        print("edges:", rels)
    except Exception as e:
        print(f"\n[no DB load] {type(e).__name__}: {e}")
        print("model built in-memory; start Neo4j and re-run to persist.")


if __name__ == "__main__":
    main()
