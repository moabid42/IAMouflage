# Passdown — GCP Detection-Gap Graph

Handoff for continuing this work in a new session. Read this first, then `docs/README.md`.

---

## TL;DR — what this project is

A Neo4j graph that models **GCP attack techniques** (from hacktricks-cloud) against a
**signature-detection corpus** (Sigma GCP rules), to find — **by graph query alone, no ML
model** — the attack scenarios the detections cannot catch. It is the **graph baseline** for
the bachelor thesis: it quantifies what per-event signatures miss, which is the gap a model is
meant to fill.

Everything lives under `draft/implementation/code/`. Working branch: **`paper`**.

---

## The ONE idea (the whole thing in a sentence)

> A detection catches a technique **only if the exact API action the technique performs is the
> same action some rule is watching for in the logs**. The graph exists to line those up and
> find the actions nobody watches.

Detections and techniques are **never joined directly**. They meet on a shared **`ApiMethod`**
(operation) node:

```
Technique ──INVOKES──▶ ApiMethod ◀──COVERS── DetectionRule
"I act here"           (an operation)         "my rule watches here"
```

- Both sides describe the action in different notations (IAM permission vs Sigma methodName),
  so both are normalised to one canonical `service.resource.verb` = the `ApiMethod` key.
- If a technique's ApiMethod has an incoming `COVERS` edge **and** the op is logged by default
  → `DETECTED_BY` edge is drawn → detected. Otherwise → blind spot.

---

## Current authoritative numbers (regenerate to confirm: `./run.sh analyze`)

**254 techniques, 15 detected (5.9%).** Blind classes: 189 RULE_GAP (74.4%), 50 TELEMETRY_GAP (19.7%).

Techniques by tactic / extraction:

| Tactic | Techniques | Extraction |
| --- | --- | --- |
| privilege-escalation | 143 | heading |
| post-exploitation | 75 | heading |
| discovery (gcp-services) | 20 | inline |
| unauthenticated-access | 12 | inline |
| persistence | 2 | heading |
| workspace-pivoting | 2 | inline |

Graph size:
- Nodes: Technique 254 · Permission 282 · ApiMethod 327 · DetectionRule 26 · Capability 9 · Tactic 6 · Service 34
- Edges: REQUIRES 387 · MAPS_TO 282 · INVOKES 363 · COVERS 60 · DETECTED_BY 15 · GRANTS 71 · IMPLIES 7 · UNLOCKS 25 · ENABLES 1481
- ApiMethod: 261 invoked-by-a-technique · 60 covered-by-a-rule · **only 11 in both** (the entire correlation surface) · 249 ADMIN_ACTIVITY / 78 DATA_ACCESS
- 26 rules = 15 `gcp_audit` + 1 `gcp_iam_authinfo` + 10 `workspace_event` (Workspace rules cover 0 GCP-API ops by construction)

---

## Two blind-spot classes (the main analytical contribution)

A technique is `DETECTED` only if a matched op is **logged by default**. Otherwise:

| Class | Meaning | Remedy |
| --- | --- | --- |
| `RULE_GAP` (A) | op **is** logged (Admin Activity), but **no rule** matches it | write a Sigma rule — evidence already in logs |
| `TELEMETRY_GAP` (B) | op is **Data Access**, **off by default** — no signature can ever fire | enable logging / reason over the graph |

`logged` ≠ `detected`. An op can be logged (`logged_by_default=true`) yet have no rule → RULE_GAP.

---

## Two extraction modes (why 220 vs 34)

- **heading** (220): privesc/persistence/post-exploit pages write the required permissions
  literally in the `###` heading → clean preconditions. High fidelity.
- **inline** (34): services/unauth/workspace-pivoting pages have **0 permission headings**;
  permissions are scraped from prose/`gcloud` examples, then filtered to real GCP IAM service
  prefixes (self-calibrated from the heading corpus + allowlist `cloudasset,billing,apikeys`).
  Tagged `extraction:"inline"`. Lower fidelity — filterable with `WHERE t.extraction='heading'`.
- `gcp-basic-information` is excluded (pure reference).

---

## Repo layout (`code/`)

```
docker-compose.yml     Neo4j 5.26  (bolt://localhost:7687, neo4j/detgap-thesis)
run.sh                 one-shot pipeline;  ./run.sh analyze = queries only
requirements.txt       neo4j, pyyaml
src/
  normalize.py         perm/methodName -> service.resource.verb (the join key + op_matches)
  parse_sigma.py       detections/sigma-rules/gcp -> data/detections.json
  parse_techniques.py  techniques/hacktricks -> data/techniques.json  (heading + inline modes)
  mappings.py          log-type classifier + capability model (knowledge layer)
  build_graph.py       load nodes/edges into Neo4j; derives DETECTED_BY + ENABLES
  run_queries.py       run queries/*.cypher -> out/findings.{md,json}
queries/00..09.cypher  the 10 gap-analysis questions (documented // TITLE / // WHY headers)
data/*.json            extracted corpora (committed)
out/findings.{md,json} generated report (committed)
docs/00..08 + README   full documentation set (00 = system design w/ mermaid)
```

Inputs (siblings, read-only): `../detections/sigma-rules/gcp/`, `../techniques/hacktricks-cloud/src/pentesting-cloud/gcp-security/`.

---

## How to run

```bash
cd draft/implementation/code
./run.sh              # venv + docker neo4j + parse + build + query  (needs Docker running)
./run.sh analyze      # re-run queries only, against an already-built graph
```

Neo4j browser: http://localhost:7474  (neo4j / detgap-thesis). Env overrides: `NEO4J_URI/USER/PASS`.

Individual stages: `.venv/bin/python src/parse_sigma.py` → `parse_techniques.py` → `build_graph.py` → `run_queries.py`.

---

## Graph schema quick reference

Nodes: `Technique{id,primary_perm,tactic,service,blind_class,detected,covered_by_rule,invokes_logged,requires_actas,extraction}`,
`Permission{name}`, `ApiMethod{op,log_type,logged_by_default,has_technique}`,
`DetectionRule{id,title,signal,covered_ops}`, `Capability{name,kind}`, `Tactic`, `Service`.

Edges: `REQUIRES{optional}`, `MAPS_TO`, `INVOKES`, `COVERS`, `DETECTED_BY` (derived),
`GRANTS`, `IMPLIES`, `UNLOCKS`, `ENABLES` (derived), `IN_TACTIC`, `FOR_SERVICE`.

Capability chaining (for multi-step attack paths): technique `GRANTS` a capability,
capabilities `IMPLIES` others, a capability `UNLOCKS` actAs-gated techniques → materialised as
`Technique-[:ENABLES]->Technique`. Crown jewels = PROJECT_ADMIN, ORG_ADMIN, SA_KEY_PERSIST,
READ_SECRET, DECRYPT_KMS. See `docs/05-capability-model.md`.

---

## Where the user is / what they were doing

The user was exploring the graph in the **Neo4j Browser** and got confused by node captions.
Key teaching points (they hit all of these):

- **Nodes captioned `TRUE`/`FALSE` are ApiMethods** — the browser is printing a boolean
  property (`has_technique`) as the caption. Tell them to **set the ApiMethod caption to `op`**.
- **`logged` ≠ `detected`.** A RULE_GAP technique invokes a logged op that no rule covers.
- **`MAPS_TO`/`INVOKES` say nothing about detection** — every technique has them. Only a
  `COVERS` edge onto the same ApiMethod means coverage.
- **Clicking the ApiMethod label shows only 25 nodes (LIMIT 25)** and they're the
  `has_technique=true` ones (created first) → user thought all were TRUE. The FALSE ones
  (`has_technique=false` = ops a rule watches but no technique uses) are only reachable via
  `COVERS` because they have no `INVOKES` edge.
- Best "show me a real match" query (the only 11 places a rule and technique meet):
  `MATCH (t:Technique)-[:INVOKES]->(m:ApiMethod)<-[:COVERS]-(r:DetectionRule) RETURN t,m,r;`

The user learns best from the **camera analogy**: techniques = burglar actions, ApiMethod =
locations, DetectionRule = cameras, detected = a camera points at the location where the action
happens, blind spot = a location with no camera. (See the last few chat turns / `docs/01`.)

---

## Gotchas (things that bit me — avoid re-learning)

- **Neo4j 5 Cypher:** `RETURN count(*) c` fails — needs `AS c`. `all` is a reserved word (can't
  be a variable). Mixing an aggregation with a non-grouping var in one RETURN errors — group in
  a `WITH` first (see `queries/00`).
- **Mermaid:** `graph` is a reserved node id (breaks flowcharts). `mmdc` IS installed locally —
  validate diagrams with it before committing.
- **Normalisation:** join key is `service.resource.verb` (3 segments) with a `container`/`k8s`→`gke`
  alias and a `?` unknown-service wildcard for the endswith SA rules. Do NOT put real GCP
  services (e.g. `batch`) in the k8s package-strip set, and the version regex must require a
  digit (so `versions`/`vpnTunnels` survive). Both were real bugs, now fixed + commented.
- **Conservative by design:** unsure normalisation → different signatures → techniques look
  *less* covered. All blind-spot counts are lower bounds. Data Access = off by default applied
  uniformly (BigQuery exception ignored, conservative).
- Coverage %s in `queries/00` are computed from the live total (not hardcoded) — safe to grow
  the corpus.

---

## Conventions

- **Commits:** atomic, `code(infra|engine|docs): one-line lowercase summary`. **No** Claude
  co-author trailer. **Do NOT push** — commit locally only. (Memory: `commit-conventions.md`.)
- **Memory files** (`~/.claude/projects/.../memory/`): `MEMORY.md` index,
  `detection-gap-graph.md` (this project), `commit-conventions.md`, `detections-corpus-map.md`,
  `impl-architecture-decisions.md`. Update `detection-gap-graph.md` if numbers change.

---

## Possible next steps (not started)

- **Model the other detection corpora.** Repo also vendors `detections/elastic-detection-rules`,
  `gsecops-detection-rules`, `panther-analysis-rules`. Only Sigma is modelled. Adding a parser
  that emits the same `covered_ops` shape would raise the detected count and strengthen the
  baseline. This is the most natural extension.
- **Feed real per-SA permission data** (e.g. from `infra/GCP-Hound`, a BloodHound-style GCP
  collector, or the `infra/GCPdvi` vulnerable env) into the capability layer to turn the
  in-principle `ENABLES` graph into concrete, ranked attack paths for a specific project.
- **Author Sigma rules for the Class-A gaps** (`queries/02`) — every row is a signature that
  could be written today because the op is already logged. Good concrete thesis artifact.
- **Persistence corpus is thin** (2 techniques) — the vendored persistence pages are prose.
  If a richer source exists, extend.
- Optional: a short `docs/why-the-graph.md` capturing the camera analogy for the thesis text
  (offered to the user, not yet written).

---

## Sanity check before continuing

```bash
docker ps | grep gcp-detgap-neo4j          # container up?
cd draft/implementation/code && ./run.sh analyze   # regenerates out/findings.md deterministically
git -C .. log --oneline -8                  # recent code(...) commits, clean tree
```
