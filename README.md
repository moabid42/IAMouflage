# IAMouflage

Where cloud identity detections meet the techniques designed to evade them.

IAMouflage models GCP attack techniques (with their IAM preconditions) against a
signature-detection corpus as a **Neo4j** graph, then finds — *by graph query alone, no ML
model* — the attack scenarios the detections cannot catch. For the design and the model, see
[`docs/architecture`](docs/architecture).

## Requirements

- **Docker** (runs Neo4j `5.26-community` via `code/docker-compose.yml`)
- **Python ≥ 3.10** (a virtualenv is created automatically)
- Python deps (installed automatically): `neo4j>=6.0`, `pyyaml>=6.0`

## Install & run

Everything is driven by one script. From the repo root:

```bash
cd code
./run.sh            # create venv, start Neo4j, parse corpora, build graph, run queries
./run.sh analyze    # re-run the gap-analysis queries only (graph already built)
```

`run.sh` creates `code/.venv`, installs the requirements, brings up Neo4j with
`docker compose`, waits for the Bolt port, then runs the pipeline.

- **Neo4j browser:** <http://localhost:7474> — user `neo4j`, password `detgap-thesis`
- **Bolt:** `bolt://localhost:7687`
- Overridable via env: `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASS`

Run a single stage directly (from `code/`, with the venv active):

```bash
python -m detection.parse_sigma      # rules      -> data/detections.json
python -m library.parse_techniques   # techniques -> data/techniques.json
python -m graph.build_graph          # load Neo4j  (derives DETECTED_BY + ENABLES)
python -m graph.run_queries          # queries/*.cypher -> out/findings.{md,json}
```

## Layout

```
code/
  core/         normalize.py                       shared join key (service.resource.verb)
  detection/    parse_sigma.py · logtype.py        rules + Admin-Activity vs Data-Access
  library/      parse_techniques.py · capabilities.py   techniques + attack chaining
  graph/        build_graph.py · run_queries.py    load Neo4j + gap-analysis queries
  queries/      00..09.cypher                       the ten gap-analysis questions
  data/         detections.json · techniques.json   parsed corpora
  out/          findings.{md,json}                   generated report
docs/
  architecture                                       the design + graph model
```

## Results

The headline numbers and every query's output land in
[`code/out/findings.md`](code/out/findings.md) (human) and `code/out/findings.json` (machine).
