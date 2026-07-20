"""
Build the Neo4j detection-gap graph from the parsed corpora + knowledge mappings.

Graph schema
------------
Nodes
  (:Tactic {name})
  (:Service {name})
  (:Technique {id,title,tactic,service,section,file,line,requires_actas,
               num_required,num_optional,primary_perm,
               invokes_logged,covered_by_rule,detected,blind_class})
  (:Permission {name,service,resource,verb})
  (:ApiMethod  {op,service,resource,verb,log_type,logged_by_default,has_technique})
  (:DetectionRule {id,title,level,status,domain,signal,mitre_tactics,event_names})
  (:Capability {name,kind})     kind in {pivot, crown_jewel}

Relationships
  (Technique)-[:IN_TACTIC]->(Tactic)
  (Technique)-[:FOR_SERVICE]->(Service)
  (Technique)-[:REQUIRES {optional}]->(Permission)
  (Permission)-[:MAPS_TO]->(ApiMethod)
  (Technique)-[:INVOKES]->(ApiMethod)
  (DetectionRule)-[:COVERS]->(ApiMethod)
  (Technique)-[:DETECTED_BY]->(DetectionRule)   # covered AND logged-by-default
  (Technique)-[:GRANTS]->(Capability)
  (Capability)-[:IMPLIES]->(Capability)
  (Capability)-[:UNLOCKS]->(Technique)

Usage:  python src/build_graph.py       (env: NEO4J_URI, NEO4J_USER, NEO4J_PASS)
"""

import json
import os
from pathlib import Path

from neo4j import GraphDatabase

from mappings import (
    CAPABILITY_IMPLIES, CROWN_JEWELS, PIVOTS,
    capability_unlocks, classify_method, technique_grants,
)
from normalize import op_matches, op_signature

URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
USER = os.environ.get("NEO4J_USER", "neo4j")
PASS = os.environ.get("NEO4J_PASS", "detgap-thesis")

DATA = Path(__file__).resolve().parents[1] / "data"


def load_json(name):
    return json.loads((DATA / name).read_text())


def perm_parts(perm):
    p = perm.split(".")
    return p[0].lower(), p[-2].lower(), p[-1].lower()


def build_model():
    """Assemble plain python dicts/lists for every node and edge, then return them."""
    techs = load_json("techniques.json")
    rules = load_json("detections.json")

    # all covered ops across rules (rule_id, covered_op)
    covered_pairs = [(r["id"], op) for r in rules for op in r["covered_ops"]]

    # ---- ApiMethod universe: technique ops (concrete) + rule ops with no technique --
    method_ops = {}  # op -> dict

    def ensure_method(op, has_technique):
        if op not in method_ops:
            lt, logged = classify_method(op)
            s, r, v = op.split(".")[0], op.split(".")[-2], op.split(".")[-1]
            method_ops[op] = {
                "op": op, "service": s, "resource": r, "verb": v,
                "log_type": lt, "logged_by_default": logged,
                "has_technique": has_technique,
            }
        elif has_technique:
            method_ops[op]["has_technique"] = True

    # concrete technique ops
    tech_ops = set()
    for t in techs:
        for p in t["required_perms"] + t["optional_perms"]:
            op = op_signature(p)
            if op:
                tech_ops.add(op)
    for op in tech_ops:
        ensure_method(op, True)
    # rule ops that match no technique op -> standalone nodes
    for _, cop in covered_pairs:
        if not any(op_matches(top, cop) for top in tech_ops):
            ensure_method(cop, False)

    # ---- COVERS: rule -> apimethod (op_matches) --------------------------------
    covers = []  # (rule_id, op)
    for rid, cop in covered_pairs:
        for op in method_ops:
            if op_matches(op, cop):
                covers.append({"rule_id": rid, "op": op})
    covers_by_op = {}
    for c in covers:
        covers_by_op.setdefault(c["op"], set()).add(c["rule_id"])

    # ---- Permissions -----------------------------------------------------------
    perms = {}
    for t in techs:
        for p in t["required_perms"] + t["optional_perms"]:
            if p not in perms:
                s, r, v = perm_parts(p)
                perms[p] = {"name": p, "service": s, "resource": r, "verb": v,
                            "op": op_signature(p)}

    # ---- Technique derived detection status ------------------------------------
    for t in techs:
        invoked = [op_signature(p) for p in t["required_perms"]]
        invoked = [o for o in invoked if o]
        logged = any(method_ops[o]["logged_by_default"] for o in invoked)
        covered = any(o in covers_by_op for o in invoked)
        detected = any(o in covers_by_op and method_ops[o]["logged_by_default"]
                       for o in invoked)
        t["invokes_logged"] = logged
        t["covered_by_rule"] = covered
        t["detected"] = detected
        t["blind_class"] = (
            "DETECTED" if detected else ("RULE_GAP" if logged else "TELEMETRY_GAP")
        )
        t["num_required"] = len(t["required_perms"])
        t["num_optional"] = len(t["optional_perms"])
        t["detected_by"] = sorted({
            rid for o in invoked if method_ops[o]["logged_by_default"]
            for rid in covers_by_op.get(o, ())
        })

    # ---- Capabilities ----------------------------------------------------------
    cap_kind = {}
    for c in CROWN_JEWELS:
        cap_kind[c] = "crown_jewel"
    for c in PIVOTS:
        cap_kind[c] = "pivot"
    grants = []   # (tech_id, cap)
    for t in techs:
        for c in technique_grants(t):
            grants.append({"tech_id": t["id"], "cap": c})
            cap_kind.setdefault(c, "pivot")
    unlocks = []  # (cap, tech_id)  -- IMPERSONATE_SA unlocks actAs techniques
    unlocks_by_cap = {}
    for t in techs:
        for c in cap_kind:
            if capability_unlocks(c, t):
                unlocks.append({"cap": c, "tech_id": t["id"]})
                unlocks_by_cap.setdefault(c, []).append(t["id"])

    # ---- ENABLES: materialised technique->technique pivot edges -----------------
    # t1 ENABLES t2 iff a capability t1 grants (or that capability implies, transitively)
    # unlocks t2. This is the per-event-invisible attack step signatures cannot correlate.
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
        reachable_caps = set()
        for c in grants_by_tech.get(t["id"], ()):
            reachable_caps |= implies_closure(c)
        for cap in reachable_caps:
            for tgt in unlocks_by_cap.get(cap, ()):
                if tgt != t["id"]:
                    enables.append({"src": t["id"], "dst": tgt, "via": cap})

    return {
        "techs": techs, "rules": rules, "perms": list(perms.values()),
        "methods": list(method_ops.values()), "covers": covers,
        "capabilities": [{"name": k, "kind": v} for k, v in cap_kind.items()],
        "grants": grants, "unlocks": unlocks, "enables": enables,
        "implies": [{"a": a, "b": b} for a, b in CAPABILITY_IMPLIES],
        "req_edges": [
            {"tech_id": t["id"], "perm": p, "optional": opt}
            for t in techs
            for p, opt in ([(x, False) for x in t["required_perms"]]
                           + [(x, True) for x in t["optional_perms"]])
        ],
        "invokes": [
            {"tech_id": t["id"], "op": op_signature(p)}
            for t in techs for p in t["required_perms"] if op_signature(p)
        ],
        "maps_to": [{"perm": p["name"], "op": p["op"]} for p in perms.values() if p["op"]],
        "detected_by": [
            {"tech_id": t["id"], "rule_id": rid}
            for t in techs for rid in t["detected_by"]
        ],
    }


CONSTRAINTS = [
    "CREATE CONSTRAINT tech_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
    "CREATE CONSTRAINT perm_name IF NOT EXISTS FOR (p:Permission) REQUIRE p.name IS UNIQUE",
    "CREATE CONSTRAINT method_op IF NOT EXISTS FOR (m:ApiMethod) REQUIRE m.op IS UNIQUE",
    "CREATE CONSTRAINT rule_id IF NOT EXISTS FOR (r:DetectionRule) REQUIRE r.id IS UNIQUE",
    "CREATE CONSTRAINT cap_name IF NOT EXISTS FOR (c:Capability) REQUIRE c.name IS UNIQUE",
    "CREATE CONSTRAINT tactic_name IF NOT EXISTS FOR (x:Tactic) REQUIRE x.name IS UNIQUE",
    "CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE",
]


def run(session, cypher, **params):
    return session.run(cypher, **params)


def load(model):
    driver = GraphDatabase.driver(URI, auth=(USER, PASS))
    driver.verify_connectivity()
    with driver.session() as s:
        s.run("MATCH (n) DETACH DELETE n")
        for c in CONSTRAINTS:
            s.run(c)

        # nodes
        s.run("""UNWIND $rows AS t
            MERGE (n:Technique {id:t.id}) SET n += {
              title:t.title, tactic:t.tactic, service:t.service, section:t.section,
              file:t.file, line:t.line, requires_actas:t.requires_actas,
              num_required:t.num_required, num_optional:t.num_optional,
              primary_perm:t.primary_perm, invokes_logged:t.invokes_logged,
              covered_by_rule:t.covered_by_rule, detected:t.detected,
              blind_class:t.blind_class, extraction:t.extraction }
            MERGE (ta:Tactic {name:t.tactic}) MERGE (n)-[:IN_TACTIC]->(ta)
            MERGE (sv:Service {name:t.service}) MERGE (n)-[:FOR_SERVICE]->(sv)
        """, rows=model["techs"])

        s.run("""UNWIND $rows AS p
            MERGE (n:Permission {name:p.name})
            SET n += {service:p.service, resource:p.resource, verb:p.verb}
        """, rows=model["perms"])

        s.run("""UNWIND $rows AS m
            MERGE (n:ApiMethod {op:m.op}) SET n += {
              service:m.service, resource:m.resource, verb:m.verb,
              log_type:m.log_type, logged_by_default:m.logged_by_default,
              has_technique:m.has_technique }
        """, rows=model["methods"])

        s.run("""UNWIND $rows AS r
            MERGE (n:DetectionRule {id:r.id}) SET n += {
              title:r.title, level:r.level, status:r.status, domain:r.domain,
              signal:r.signal, mitre_tactics:r.mitre_tactics,
              event_names:r.event_names, covered_ops:r.covered_ops }
        """, rows=model["rules"])

        s.run("""UNWIND $rows AS c
            MERGE (n:Capability {name:c.name}) SET n.kind = c.kind
        """, rows=model["capabilities"])

        # edges
        s.run("""UNWIND $rows AS e
            MATCH (t:Technique {id:e.tech_id}), (p:Permission {name:e.perm})
            MERGE (t)-[r:REQUIRES]->(p) SET r.optional = e.optional
        """, rows=model["req_edges"])

        s.run("""UNWIND $rows AS e
            MATCH (p:Permission {name:e.perm}), (m:ApiMethod {op:e.op})
            MERGE (p)-[:MAPS_TO]->(m)
        """, rows=model["maps_to"])

        s.run("""UNWIND $rows AS e
            MATCH (t:Technique {id:e.tech_id}), (m:ApiMethod {op:e.op})
            MERGE (t)-[:INVOKES]->(m)
        """, rows=model["invokes"])

        s.run("""UNWIND $rows AS e
            MATCH (r:DetectionRule {id:e.rule_id}), (m:ApiMethod {op:e.op})
            MERGE (r)-[:COVERS]->(m)
        """, rows=model["covers"])

        s.run("""UNWIND $rows AS e
            MATCH (t:Technique {id:e.tech_id}), (r:DetectionRule {id:e.rule_id})
            MERGE (t)-[:DETECTED_BY]->(r)
        """, rows=model["detected_by"])

        s.run("""UNWIND $rows AS e
            MATCH (t:Technique {id:e.tech_id}), (c:Capability {name:e.cap})
            MERGE (t)-[:GRANTS]->(c)
        """, rows=model["grants"])

        s.run("""UNWIND $rows AS e
            MATCH (a:Capability {name:e.a}), (b:Capability {name:e.b})
            MERGE (a)-[:IMPLIES]->(b)
        """, rows=model["implies"])

        s.run("""UNWIND $rows AS e
            MATCH (c:Capability {name:e.cap}), (t:Technique {id:e.tech_id})
            MERGE (c)-[:UNLOCKS]->(t)
        """, rows=model["unlocks"])

        s.run("""UNWIND $rows AS e
            MATCH (a:Technique {id:e.src}), (b:Technique {id:e.dst})
            MERGE (a)-[r:ENABLES]->(b) SET r.via = e.via
        """, rows=model["enables"])

        counts = {}
        for label in ["Technique", "Permission", "ApiMethod", "DetectionRule",
                      "Capability", "Tactic", "Service"]:
            counts[label] = s.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()["c"]
        rels = {}
        for rel in ["REQUIRES", "MAPS_TO", "INVOKES", "COVERS", "DETECTED_BY",
                    "GRANTS", "IMPLIES", "UNLOCKS", "ENABLES", "IN_TACTIC",
                    "FOR_SERVICE"]:
            rels[rel] = s.run(
                f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c").single()["c"]
    driver.close()
    return counts, rels


def main():
    model = build_model()
    counts, rels = load(model)
    print("Loaded graph into", URI)
    print("nodes:", {k: v for k, v in counts.items()})
    print("edges:", {k: v for k, v in rels.items()})


if __name__ == "__main__":
    main()
