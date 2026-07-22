# IAMouflage

Where cloud identity detections meet the techniques designed to evade them.

IAMouflage models GCP attack techniques (with their IAM preconditions) against four
production detection corpora (Sigma, Elastic, Google SecOps, Panther) as a **Neo4j** graph,
then finds — *by graph query alone, no ML model* — the attack scenarios the detections cannot
catch. Detections and techniques speak incompatible operation dialects (`compute.firewalls.insert`
the audit method vs `compute.firewalls.create` the permission), so both are canonicalised to
the **IAM permission** and joined on it. For the design and the model, see
[`docs/architecture`](docs/architecture).

## Requirements

- **Docker** (runs Neo4j `5.26-community` via `code/docker-compose.yml`)
- **Python ≥ 3.10** (a virtualenv is created automatically)
- Python deps (installed automatically): `neo4j>=6.0`, `pyyaml>=6.0`

## Install & run

Everything is driven by one script. From the repo root:

```bash
cd code
./run.sh            # create venv, start Neo4j, aggregate corpora, build graph, run queries
./run.sh analyze    # re-run the gap-analysis queries only (graph already built)
./run.sh refresh    # re-pin the upstream method->permission reference tables (needs network)
```

`run.sh` creates `code/.venv`, installs the requirements, brings up Neo4j with
`docker compose`, waits for the Bolt port, then runs the pipeline.

- **Neo4j browser:** <http://localhost:7474> — user `neo4j`, password `detgap-thesis`
- **Bolt:** `bolt://localhost:7687`
- Overridable via env: `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASS`

The detection corpora are not vendored; point the pipeline at them with
`--corpus-root` or `IAMOUFLAGE_CORPUS` (default `../../../draft/data/detections`).

Run a single stage directly (from `code/`, with the venv active):

```bash
python -m detection.aggregate        # 4 corpora -> data/detections.{source}.json + detections.json
python -m library.parse_techniques   # techniques -> data/techniques.json
python -m graph.build_graph          # DNF join, load Neo4j (derives DETECTED_BY + ENABLES)
python -m graph.run_queries          # queries/*.cypher -> out/findings.{md,json}
```

## Layout

```
code/
  core/         canonical.py · corpus.py · normalize.py   token -> IAM permission; locate corpora
  reference/    fetch_reference.py · rpc_methods.json      pinned method->permission tables
  detection/    record.py · parse_{sigma,elastic,gsecops,panther}.py · aggregate.py · logtype.py
  library/      parse_techniques.py · capabilities.py      techniques + attack chaining
  graph/        build_graph.py · run_queries.py            DNF join into Neo4j + gap-analysis
  queries/      00..10.cypher                               the eleven gap-analysis questions
  data/         detections.json (+ per-source) · techniques.json · reference/   parsed corpora + tables
  out/          findings.{md,json}                          generated report
docs/
  architecture                                              the design + graph model
```

## Results

The headline numbers and every query's output land in
[`code/out/findings.md`](code/out/findings.md) (human) and `code/out/findings.json` (machine).
