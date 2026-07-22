# GCP Detection-Gap Graph

Modelling GCP attack techniques and their preconditions against four production detection
corpora in **Neo4j**, then finding — *by graph query alone, with no ML model* — the attack
scenarios the detections cannot catch.

This is the graph-baseline for the thesis: it establishes precisely **what the deployed
detections miss**, which is the gap the model is meant to fill.

> **The design and the graph model live in [`../docs/architecture`](../docs/architecture).**
> This file is the operational README: what goes in, how to run it, and where the numbers land.
> One thing worth stating up front: detections and techniques are **not** joined by a direct
> edge; both are canonicalised to the **IAM permission** and meet on shared `Permission` nodes,
> because the same operation is written three incompatible ways (`compute.firewalls.insert` the
> audit method == `compute.firewalls.create` the permission).

---

## The question

> Given the GCP detection rules an organisation runs, and the full set of GCP attack
> techniques (each with its IAM preconditions), which situations can the detections **not**
> figure out — discoverable purely from the graph, without a model?

## Inputs

| Corpus | Path | What we extract |
| --- | --- | --- |
| **Detections** — 4 sets, 163 rules | `sigma-rules/`, `elastic-detection-rules/`, `gsecops-detection-rules/`, `panther-analysis-rules/` under the corpus root | each rule's firing condition in DNF (the ops it requires, ANDed within a group, ORed across groups), its paradigm (event/correlation/ueba) and MITRE tags |
| **Techniques** — hacktricks-cloud | `techniques/.../gcp-security/` | one technique per permission-bearing heading + inline-extracted perms, each with its **required IAM permissions = preconditions** |
| **Reference tables** (pinned) | `data/reference/` + `reference/rpc_methods.json` | method→permission maps that let a rule's audit `methodName` join a technique's permission |

The corpora are not vendored here — set `IAMOUFLAGE_CORPUS` / `--corpus-root`
(default `../../../draft/data/detections`). See [`core/corpus.py`](core/corpus.py).

## The core idea (short version)

A rule fires on a **boolean condition** over operations; a technique is **detected** only when
some rule *group* is fully satisfied — every op in the group (a) covered by a permission the
technique requires **and** (b) written to a log that is **on by default**. GCP Cloud Audit Logs
split into Admin Activity (config/IAM writes, always on) and Data Access (reads, token minting,
KMS decrypt — off by default). So each technique falls into one bucket:

| Class | Meaning | Fix |
| --- | --- | --- |
| `DETECTED` | a single-event rule fires on it | — |
| `CORRELATION_ONLY` | only a threshold / multi-stage rule fires (needs repetition or a chain) | tune thresholds / correlate |
| `RULE_GAP` (A) | operation **is** logged, but **no rule** fires | write a signature |
| `TELEMETRY_GAP` (B) | operation is Data Access, **off by default** — *no signature can ever fire* | reconfigure logging / reason over the graph |

Full firing semantics, the canonicalisation ladder, the schema and the capability/chaining
layer are in [`../docs/architecture`](../docs/architecture).

---

## Headline findings

Full report: [`out/findings.md`](out/findings.md) · machine-readable: `out/findings.json`.

**Of 254 techniques, 86 (33.9%) are caught by a single-event signature** across all four
corpora combined; 2 are `CORRELATION_ONLY`, 117 (46.1%) are Class-A rule gaps, 49 (19.3%) are
Class-B telemetry gaps. *(The Sigma-only single-event baseline is 18/7.1% — three more than the
pre-canonicalisation 15, because resolving `insert`→`create` recovers detections the old string
match missed.)*

| Query | Scenario the detections miss |
| --- | --- |
| `07_blind_privesc_to_crown_jewels` | undetected techniques that directly hand over a crown jewel — `resourcemanager.*.setIamPolicy` → **Owner**, `iam.roles.update/create` → self-granted admin, `secretmanager.versions.access` → secrets, `cloudkms…decrypt`, `iam.serviceAccountKeys.create` → a permanent exportable credential. One uncovered API call, no alert. |
| `09_invisible_impersonation` | service-account impersonation primitives (`getAccessToken`, `signBlob`, `signJwt`, `implicitDelegation`, …) that are Data-Access ops — stealing another identity produces **no log at all** in a default project. |
| `08_undetected_pivot_chains` | multi-hop pivot chains (up to 4 hops) where every step is a blind spot *and* no rule reasons across hops — structurally invisible to per-event signatures. |
| `10_correlation_only` | techniques a single-event signature cannot catch, tripped **only** by a threshold/correlation rule — silent under one careful execution. |
| `04_covered_but_unlogged` | **false comfort:** rules that exist but are blind by default because they match a Data-Access read (e.g. `storage.buckets.list`). |
| `03_telemetry_gap_classB` | the techniques for which **no signature can ever help** without turning on Data Access logging. |

The detections that *do* exist cluster in impact/destruction, not in the privilege-escalation,
impersonation and credential-access operations that dominate the attack corpus
(`05_rules_without_technique`, `06_coverage_by_tactic_service`).

---

## Run it

```bash
./run.sh            # venv + neo4j + aggregate + build + query  (needs Docker)
./run.sh analyze    # re-run queries only
./run.sh refresh    # re-pin the upstream reference tables (needs network)
```

Neo4j browser: <http://localhost:7474> (`neo4j` / `detgap-thesis`). Try a query from
`queries/` or:

```cypher
MATCH (t:Technique {blind_class:'TELEMETRY_GAP'})-[:GRANTS]->(c:Capability {kind:'crown_jewel'})
RETURN t.primary_perm, c.name;
```

### Layout

```
code/
  docker-compose.yml         Neo4j 5.26
  run.sh                     one-shot pipeline (invokes the packages via python -m)
  requirements.txt
  core/
    canonical.py             detection token -> canonical IAM permission (via reference tables)
    corpus.py                locate the vendored corpora (--corpus-root / IAMOUFLAGE_CORPUS)
    normalize.py             permission -> service.resource.verb (used by capabilities)
  reference/
    fetch_reference.py       pin iam-dataset method->permission tables -> data/reference/
    rpc_methods.json         curated gRPC method->permission table (official Google docs)
  detection/                 DETECTION side — rules and what telemetry they can see
    record.py                the DNF detection-record contract
    parse_sigma.py           \
    parse_elastic.py          | one parser per corpus -> data/detections.{source}.json
    parse_gsecops.py          |
    parse_panther.py         /
    aggregate.py             run all four + merge -> data/detections.json
    logtype.py               ADMIN_ACTIVITY vs DATA_ACCESS classifier (is an op even logged?)
  library/                   LIBRARY side — techniques and how they chain
    parse_techniques.py      techniques -> data/techniques.json
    capabilities.py          capability model: GRANTS / IMPLIES / UNLOCKS (attack chaining)
  graph/                     assembly + analysis
    build_graph.py           DNF join, load Neo4j (derives DETECTED_BY + ENABLES)
    run_queries.py           run queries/*.cypher -> out/findings.{md,json}
  queries/*.cypher           the 11 gap-analysis questions (documented headers)
  data/*.json                extracted corpora (+ data/reference/ pinned tables)
  out/findings.{md,json}     generated report
```

---

## Assumptions & limitations

- **Detectability is defined structurally** (a rule group satisfied ∧ logged-by-default), not
  by running rules against real logs. It answers "could this rule ever fire on this technique",
  which is the right question for a coverage gap.
- **Data Access = off by default** is applied uniformly (BigQuery is the real exception;
  treating it as off is conservative).
- **UEBA rules create no coverage** — they name no specific operation, so they are nodes without
  `DETECTED_BY` edges; correlation rules do detect, but only under repetition/a chain
  (`CORRELATION_ONLY`).
- **The method→permission mapping is a pinned third-party index** over official Google data,
  cross-checked against a curated official gRPC table; unresolved tokens are dropped, never
  guessed (see `data/reference/PROVENANCE.md`).
- **The capability layer is a deterministic model of attacker reasoning**, not ground truth
  about a specific environment.
- Coverage numbers are **lower bounds** by construction (conservative canonicalisation +
  "any covered+logged op ⇒ detected").
