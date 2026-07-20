"""
Parse the vendored Sigma GCP detection corpus into structured detection records.

Each Sigma rule keys on one or more *fields*. For our gap analysis we care about the
fields that identify a cloud operation:

    gcp.audit.method_name                            (Cloud Audit Logs methodName)
    data.protoPayload.methodName                     (same, verbose form)
    data.protoPayload.authorizationInfo.permission   (IAM permission that was checked)

Rules that instead key on Google Workspace / login event names
(`eventName`, `protoPayload.metadata.event.eventName`) target a *different* telemetry
stream than the GCP-API techniques in the hacktricks corpus, so we tag them as
`workspace_event` and keep them as nodes, but they legitimately cover 0 GCP-API ops.

Output: data/detections.json
"""

import json
import re
import sys
from pathlib import Path

import yaml

from normalize import op_signature

OP_BEARING_FIELDS = {
    "gcp.audit.method_name",
    "data.protopayload.methodname",
    "data.protopayload.authorizationinfo.permission",
}
WORKSPACE_FIELDS = {"eventname", "protopayload.metadata.event.eventname"}

# Field modifiers we strip to get the base field name (endswith/startswith/contains...)
_MOD_RE = re.compile(r"\|[a-z]+", re.IGNORECASE)


def base_field(key: str) -> str:
    return _MOD_RE.sub("", key).strip().lower()


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# A few rules express an operation through startswith/contains/endswith combinations
# rather than a plain value list. We resolve those to explicit operation signatures
# here so they join cleanly to the technique corpus. Keyed by sigma rule id.
RULE_OP_OVERRIDES = {
    # Kubernetes Admission Controller (mutating/validating webhook create|patch|replace)
    "6ad91e31-53df-4826-bd27-0166171c8040": [
        "gke.mutatingwebhookconfigurations.create",
        "gke.mutatingwebhookconfigurations.patch",
        "gke.mutatingwebhookconfigurations.replace",
        "gke.validatingwebhookconfigurations.create",
        "gke.validatingwebhookconfigurations.patch",
        "gke.validatingwebhookconfigurations.replace",
    ],
    # Kubernetes CronJob (batch Job / CronJob objects) -> align to container.* verbs
    "cd3a808c-c7b7-4c50-a2f3-f4cfcd436435": [
        "gke.jobs.create", "gke.cronjobs.create",
        "gke.jobs.update", "gke.cronjobs.update",
    ],
}


def mitre_split(tags):
    tactics, techniques = [], []
    for t in tags or []:
        t = str(t)
        if not t.startswith("attack."):
            continue
        val = t[len("attack."):]
        if re.match(r"t\d", val):
            techniques.append(val.upper())
        else:
            tactics.append(val)
    return tactics, techniques


def parse_rule(path: Path):
    try:
        doc = yaml.safe_load(path.read_text())
    except Exception as e:  # pragma: no cover
        print(f"  !! yaml error {path.name}: {e}", file=sys.stderr)
        return None
    if not isinstance(doc, dict):
        return None

    tactics, techniques = mitre_split(doc.get("tags"))
    logsource = doc.get("logsource", {}) or {}
    detection = doc.get("detection", {}) or {}

    covered_ops, raw_matchers, event_names = set(), [], set()
    signal = "gcp_audit"

    for block_name, block in detection.items():
        if block_name == "condition" or not isinstance(block, dict):
            continue
        for key, val in block.items():
            bf = base_field(key)
            values = as_list(val)
            if bf in OP_BEARING_FIELDS:
                for v in values:
                    raw_matchers.append({"field": key, "value": v})
                    op = op_signature(str(v))
                    if op:
                        covered_ops.add(op)
                if bf == "data.protopayload.authorizationinfo.permission":
                    signal = "gcp_iam_authinfo"
            elif bf in WORKSPACE_FIELDS:
                signal = "workspace_event"
                for v in values:
                    event_names.add(str(v))
                    raw_matchers.append({"field": key, "value": v})

    rid = str(doc.get("id", path.stem))
    if rid in RULE_OP_OVERRIDES:
        covered_ops = set(RULE_OP_OVERRIDES[rid])

    # crude domain tag for grouping in the report
    domain = "gcp"
    fp = str(path).lower()
    if "gworkspace" in fp:
        domain = "workspace"
    elif "kubernetes" in path.stem or "k8s" in path.stem or "container" in path.stem:
        domain = "k8s"

    return {
        "id": rid,
        "title": doc.get("title", path.stem),
        "level": doc.get("level", "unknown"),
        "status": doc.get("status", "unknown"),
        "file": str(path.name),
        "domain": domain,
        "mitre_tactics": sorted(set(tactics)),
        "mitre_techniques": sorted(set(techniques)),
        "logsource_product": logsource.get("product"),
        "logsource_service": logsource.get("service"),
        "signal": signal,
        "covered_ops": sorted(covered_ops),
        "event_names": sorted(event_names),
        "raw_matchers": raw_matchers,
    }


def main():
    here = Path(__file__).resolve()
    root = here.parents[2]  # .../draft/implementation
    sigma_dir = root / "detections" / "sigma-rules" / "gcp"
    out = here.parents[1] / "data" / "detections.json"

    rules = []
    for path in sorted(sigma_dir.rglob("*.yml")):
        r = parse_rule(path)
        if r:
            rules.append(r)

    out.write_text(json.dumps(rules, indent=2))
    covered = sorted({op for r in rules for op in r["covered_ops"]})
    print(f"parsed {len(rules)} detection rules -> {out}")
    print(f"distinct covered operation signatures: {len(covered)}")
    for op in covered:
        print(f"   {op}")


if __name__ == "__main__":
    main()
