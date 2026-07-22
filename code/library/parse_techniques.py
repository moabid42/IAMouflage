"""
Parse the vendored hacktricks-cloud GCP corpus into structured Technique records.

Modelling rule
--------------
Every markdown heading (`###` / `####`) whose text contains permission-shaped tokens
`service.resource.verb` is one abusable technique. The heading *is* the precondition:
hacktricks writes the required IAM permissions directly in the heading, e.g.

    ### `cloudfunctions.functions.create` , `cloudfunctions.functions.sourceCodeSet` , `iam.serviceAccounts.actAs`
    ### `iam.roles.update` (`iam.roles.get`)
    ### `container.roles.escalate` | `container.clusterRoles.escalate`

Separator semantics (observed consistently across the corpus):

    ,  &        AND  -> all required together
    |           OR   -> independent alternatives (split into technique variants)
    ( ... )     optional / helper permissions (read perms that assist the abuse)

Service is taken from the primary permission's own prefix (most reliable), falling
back to the filename. Tactic comes from the directory
(privilege-escalation / persistence / post-exploitation).

Output: data/techniques.json
"""

import json
import re
from pathlib import Path

from core.canonical import canonicaliser
from core.corpus import techniques_root
from core.normalize import PERM_RE, find_permissions, op_signature, perm_service

_ACTAS_SIG = op_signature("iam.serviceAccounts.actAs")


def _canon_perm(p: str, canon) -> str:
    """Normalise a technique permission to its canonical IAM spelling.

    The hacktricks corpus carries casing drift (`iam.serviceaccounts.actAs`,
    `iam.ServiceAccounts.actAs`) and retired service names
    (`serviceusage.apiKeys.create` -> `apikeys.keys.create`). Left raw, these fail to
    join the (canonicalised) detection side by exact string, silently under-counting
    coverage. We normalise ONLY when the token resolves as a single real permission;
    anything else (a genuinely off-vocab perm like storage.buckets.setIpFilter) is kept
    untouched so we never corrupt a valid precondition.
    """
    r = canon.resolve(p)
    if r.kind == "permission" and len(r.permissions) == 1:
        return r.permissions[0]
    return p

# Each directory maps to (tactic, extraction_mode).
#
#   "heading" — a technique is a permission-bearing heading; the permissions in the
#               heading ARE its preconditions. This is how the three post-compromise
#               tactic dirs are written and it is the high-fidelity path.
#   "inline"  — the reference/enumeration dirs have NO permission-bearing headings
#               (verified: 0). Permissions appear inline in prose / gcloud examples.
#               We extract one technique per distinct inline permission, tagged
#               extraction="inline" so the lower fidelity is explicit and filterable.
#               `gcp-basic-information` is deliberately excluded (pure reference text).
TACTIC_DIRS = {
    "gcp-privilege-escalation": ("privilege-escalation", "heading"),
    "gcp-persistence": ("persistence", "heading"),
    "gcp-post-exploitation": ("post-exploitation", "heading"),
    "gcp-services": ("discovery", "inline"),
    "gcp-to-workspace-pivoting": ("workspace-pivoting", "inline"),
    "gcp-unauthenticated-enum-and-access": ("unauthenticated-access", "inline"),
}

ACTAS = "iam.serviceaccounts.actas"

# Inline extraction (prose / gcloud examples) is noisy: many dot-separated tokens are
# permission-shaped but are NOT IAM permissions — URLs (book.hacktricks.wiki), protobuf
# types (google.rpc.ErrorInfo), CLI paths (gcloud.projects.add), Python modules
# (xml.etree.ElementTree), OAuth scopes (admin.directory.user), resource paths. We reject
# them two ways: (a) obvious shape rejects here, and (b) the first segment must be a real
# GCP IAM service — see `valid_services` in main(), which is self-calibrated from the
# reliable heading corpus plus this short curated allowlist of services that appear only
# in the enum/unauth pages.
_SHAPE_REJECT_TAIL = {"com", "org", "io", "net", "dev", "wiki", "is", "gz", "internal",
                      "googleapis", "google", "html", "json"}
EXTRA_GCP_SERVICES = {"cloudasset", "billing", "apikeys"}


def is_real_permission(tok: str) -> bool:
    if "googleapis" in tok:
        return False
    parts = tok.split(".")
    if parts[-1].lower() in _SHAPE_REJECT_TAIL:
        return False
    return True

_HEADING_RE = re.compile(r"^(#{2,4})\s+(.*)$")
# Some headings carry a GitBook HTML anchor, e.g.
#   ### `iam.serviceAccounts.setIamPolicy` <a href="#..." id="iam.serviceaccounts.setiampolicy"></a>
# whose href/id hold a dotted token that permission extraction would scrape as a bogus
# duplicate permission. Strip HTML tags from a heading before extracting.
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_PAREN_RE = re.compile(r"\(([^()]*)\)")
_CLEAN_TITLE_RE = re.compile(r"<a\s+href=.*?</a>|[*_`]|\s+#.*$")


def paren_spans(text: str):
    return [(m.start(1), m.end(1)) for m in _PAREN_RE.finditer(text)]


def in_any_span(pos: int, spans) -> bool:
    return any(a <= pos < b for a, b in spans)


def clean_title(text: str) -> str:
    t = re.sub(r"<a\s+href=[^>]*>.*?</a>", "", text)
    t = t.replace("*", "").replace("_", "").replace("`", "")
    t = re.sub(r"\s+", " ", t).strip()
    return t


def service_from_filename(stem: str) -> str:
    s = stem
    for suf in ("-privesc", "-persistence", "-post-exploitation"):
        if s.endswith(suf):
            s = s[: -len(suf)]
    if s.startswith("gcp-"):
        s = s[4:]
    return s.replace("-", "")


def split_or_variants(heading: str):
    """Split a heading on top-level '|' (OR). Returns list of variant substrings."""
    # '|' only ever separates alternatives in this corpus; parentheses never contain '|'.
    if "|" not in heading:
        return [heading]
    return [part.strip() for part in heading.split("|") if part.strip()]


def extract_perms(text: str):
    """Return (required, optional) permission lists for a heading/variant substring."""
    spans = paren_spans(text)
    required, optional = [], []
    seen = set()
    for m in PERM_RE.finditer(text):
        p = m.group(0)
        if p in seen:
            continue
        seen.add(p)
        (optional if in_any_span(m.start(), spans) else required).append(p)
    return required, optional


def parse_file_headings(path: Path, tactic: str):
    """High-fidelity path: one technique per permission-bearing heading."""
    lines = path.read_text().splitlines()
    stem = path.stem
    if stem == "README":
        # e.g. gcp-compute-privesc/README.md -> use parent dir name
        stem = path.parent.name
    file_service = service_from_filename(stem)

    section = None
    techniques = []
    seq = 0
    for i, line in enumerate(lines, start=1):
        m = _HEADING_RE.match(line)
        if not m:
            continue
        hashes, htext = m.group(1), _HTML_TAG_RE.sub("", m.group(2)).strip()
        if len(hashes) == 2:
            # top-level section header; remember for context, not a technique itself
            if not PERM_RE.search(htext):
                section = clean_title(htext)
            continue
        if not PERM_RE.search(htext):
            continue  # heading without permission tokens is not a technique

        for variant in split_or_variants(htext):
            required, optional = extract_perms(variant)
            required = [p for p in required if is_real_permission(p)]
            optional = [p for p in optional if is_real_permission(p)]
            if not required and not optional:
                continue
            all_perms = required + optional
            # primary = first required perm that is not actAs, else first perm
            primary = next(
                (p for p in required if op_signature(p) != ACTAS),
                required[0] if required else all_perms[0],
            )
            service = perm_service(primary) or file_service
            requires_actas = any(op_signature(p) == ACTAS for p in all_perms)
            seq += 1
            techniques.append({
                "id": f"{tactic}:{stem}:{seq}",
                "title": clean_title(variant) if "|" in htext else clean_title(htext),
                "tactic": tactic,
                "service": service,
                "file_service": file_service,
                "section": section,
                "file": path.name,
                "rel_path": str(path),
                "line": i,
                "heading_level": len(hashes),
                "required_perms": required,
                "optional_perms": optional,
                "requires_actas": requires_actas,
                "primary_perm": primary,
                "extraction": "heading",
            })
    return techniques


def parse_file_inline(path: Path, tactic: str, valid_services: set[str]):
    """Lower-fidelity path for the reference/enumeration dirs: one technique per
    distinct inline permission token (these files have no permission headings).
    A token is kept only if its shape is plausible AND its service prefix is a real
    GCP IAM service (`valid_services`), which removes URLs/scopes/modules/paths."""
    lines = path.read_text().splitlines()
    stem = path.stem if path.stem != "README" else path.parent.name
    file_service = service_from_filename(stem)

    section = None
    techniques = []
    seen = set()
    seq = 0
    for i, line in enumerate(lines, start=1):
        hm = _HEADING_RE.match(line)
        if hm:
            if len(hm.group(1)) <= 2 and not PERM_RE.search(hm.group(2)):
                section = clean_title(hm.group(2))
            continue
        for p in find_permissions(line):
            if (p in seen or not is_real_permission(p)
                    or perm_service(p) not in valid_services):
                continue
            seen.add(p)
            seq += 1
            techniques.append({
                "id": f"{tactic}:{stem}:{seq}",
                "title": p,
                "tactic": tactic,
                "service": perm_service(p) or file_service,
                "file_service": file_service,
                "section": section,
                "file": path.name,
                "rel_path": str(path),
                "line": i,
                "heading_level": None,
                "required_perms": [p],
                "optional_perms": [],
                "requires_actas": op_signature(p) == ACTAS,
                "primary_perm": p,
                "extraction": "inline",
            })
    return techniques


def parse_file(path: Path, tactic: str, mode: str, valid_services: set[str]):
    if mode == "inline":
        return parse_file_inline(path, tactic, valid_services)
    return parse_file_headings(path, tactic)


def main():
    here = Path(__file__).resolve()
    base = techniques_root()  # draft/data/techniques/hacktricks-cloud/.../gcp-security
    out = here.parents[1] / "data" / "techniques.json"

    # Pass 1 — heading dirs (high fidelity). These also DEFINE the set of real GCP IAM
    # service prefixes used to filter the noisy inline extraction in pass 2.
    heading_tech = []
    for dirname, (tactic, mode) in TACTIC_DIRS.items():
        if mode != "heading":
            continue
        for path in sorted((base / dirname).rglob("*.md")):
            heading_tech.extend(parse_file(path, tactic, mode, set()))

    valid_services = {
        perm_service(p)
        for t in heading_tech
        for p in t["required_perms"] + t["optional_perms"]
    } | EXTRA_GCP_SERVICES

    # Pass 2 — inline dirs (enumeration / unauth / pivoting), filtered by valid_services.
    inline_tech = []
    for dirname, (tactic, mode) in TACTIC_DIRS.items():
        if mode != "inline":
            continue
        for path in sorted((base / dirname).rglob("*.md")):
            inline_tech.extend(parse_file(path, tactic, mode, valid_services))

    all_tech = heading_tech + inline_tech

    # Canonicalise permissions to their real IAM spelling so techniques join the
    # (already-canonical) detection side. Done as a final pass, AFTER the inline filter
    # in pass 2 has used the original service prefixes.
    canon = canonicaliser()
    for t in all_tech:
        t["required_perms"] = list(dict.fromkeys(_canon_perm(p, canon) for p in t["required_perms"]))
        t["optional_perms"] = [p for p in dict.fromkeys(_canon_perm(p, canon) for p in t["optional_perms"])
                               if p not in t["required_perms"]]
        t["primary_perm"] = _canon_perm(t["primary_perm"], canon)
        t["service"] = perm_service(t["primary_perm"]) or t["service"]
        t["requires_actas"] = any(
            op_signature(p) == _ACTAS_SIG for p in t["required_perms"] + t["optional_perms"])

    # Store rel_path relative to the corpus base so the output is reproducible across
    # checkouts (it was an absolute path, which changed per machine/location).
    for t in all_tech:
        try:
            t["rel_path"] = str(Path(t["rel_path"]).resolve().relative_to(base))
        except ValueError:
            pass
    out.write_text(json.dumps(all_tech, indent=2))

    by_tactic = {}
    services = set()
    for t in all_tech:
        by_tactic[t["tactic"]] = by_tactic.get(t["tactic"], 0) + 1
        services.add(t["service"])
    print(f"parsed {len(all_tech)} techniques -> {out}")
    for k, v in sorted(by_tactic.items()):
        print(f"   {k}: {v}")
    print(f"distinct services: {len(services)}")
    n_heading = sum(1 for t in all_tech if t["extraction"] == "heading")
    n_inline = sum(1 for t in all_tech if t["extraction"] == "inline")
    print(f"extraction: heading={n_heading}  inline={n_inline}")
    # how many involve actAs (identity-pivot preconditions)
    n_actas = sum(1 for t in all_tech if t["requires_actas"])
    print(f"techniques requiring iam.serviceAccounts.actAs: {n_actas}")


if __name__ == "__main__":
    main()
