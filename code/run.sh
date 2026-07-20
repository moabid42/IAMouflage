#!/usr/bin/env bash
# One-shot pipeline: stand up Neo4j, parse both corpora, build the graph, run the
# gap-analysis queries, and write the findings report.
#
#   ./run.sh            full pipeline (assumes docker + venv)
#   ./run.sh analyze    skip parsing/build, just re-run the queries
set -euo pipefail
cd "$(dirname "$0")"

PY=".venv/bin/python"
export NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
export NEO4J_USER="${NEO4J_USER:-neo4j}"
export NEO4J_PASS="${NEO4J_PASS:-detgap-thesis}"

if [ ! -x "$PY" ]; then
  echo ">> creating virtualenv"
  python3 -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r requirements.txt
fi

if [ "${1:-all}" != "analyze" ]; then
  echo ">> starting neo4j (docker compose)"
  docker compose up -d
  echo ">> waiting for neo4j bolt..."
  until $PY - <<'EOF' 2>/dev/null
from neo4j import GraphDatabase
import os
GraphDatabase.driver(os.environ["NEO4J_URI"],
    auth=(os.environ["NEO4J_USER"], os.environ["NEO4J_PASS"])).verify_connectivity()
EOF
  do sleep 2; done

  echo ">> parsing sigma detections";   $PY src/parse_sigma.py
  echo ">> parsing hacktricks techniques"; $PY src/parse_techniques.py
  echo ">> building neo4j graph";        $PY src/build_graph.py
fi

echo ">> running gap-analysis queries";  $PY src/run_queries.py
echo ">> done. See out/findings.md   (Neo4j browser: http://localhost:7474)"
