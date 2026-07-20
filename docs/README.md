# Documentation — GCP Detection-Gap Graph

This folder is the full reference for the detection-gap graph built in `code/`. It explains
what was built, how the graph is constructed, **how detection coverage is calculated**, and
what the results mean.

If you looked at the graph in the Neo4j browser and wondered *"why aren't the detections
wired to the techniques?"* — read **[03 — Graph model](03-graph-model.md#how-detections-correlate-to-techniques)**
first. Short answer: detections and techniques are **not** joined by a direct edge; they meet
on shared **`ApiMethod`** (operation) nodes, and that overlap is deliberately tiny — the
smallness *is* the finding.

## Reading order

| # | Document | What it answers |
| --- | --- | --- |
| 00 | [System design](00-system-design.md) | Architecture, context, data model, runtime & decision diagrams (Mermaid) |
| 01 | [Overview & mental model](01-overview.md) | What this is, the research question, the key idea, glossary |
| 02 | [Build pipeline](02-pipeline.md) | How the graph is built, stage by stage, file by file |
| 03 | [Graph model](03-graph-model.md) | Node/edge/property reference **and how detections correlate to techniques** |
| 04 | [Coverage methodology](04-coverage-methodology.md) | **How we compute which detection works against which technique** (normalisation, matching, log-type gating) |
| 05 | [Capability model](05-capability-model.md) | The chaining layer (`GRANTS`/`IMPLIES`/`UNLOCKS`/`ENABLES`) that expresses multi-step attacks |
| 06 | [Findings explained](06-findings.md) | Every query, its numbers, and how to read them |
| 07 | [Usage & infrastructure](07-usage.md) | Running Neo4j, the pipeline, the browser, example Cypher, troubleshooting |
| 08 | [Assumptions & limitations](08-assumptions-limitations.md) | What is modelled, what is not, why the numbers are lower bounds |

## One-paragraph summary

We model **26 Sigma GCP detection rules** and **254 GCP attack techniques** (each with its IAM
preconditions) as a Neo4j graph. A technique and a rule are linked only when they touch the
same **operation** (`service.resource.verb`), and a technique is considered *detected* only
when that shared operation is also written to a log that is **on by default**. Querying the
graph — with no ML model — shows that **only 15 of 254 techniques (5.9%) are detected**, and
surfaces the specific privilege-escalation, impersonation and multi-step pivot scenarios the
signatures cannot see.
