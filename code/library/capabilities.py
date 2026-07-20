"""
Library-side knowledge: the CAPABILITY MODEL.

How do techniques chain into multi-step attack paths? Per-event signatures never
reason about chains. We attach to each technique the capabilities it GRANTS and let
capabilities UNLOCK further techniques, so the graph can express
"foothold -> ... -> project owner" without any ML model, purely by traversal. The
rules below are deterministic and auditable, and are documented in the README.
"""

from core.normalize import op_signature

IMPERSONATE_SA = "IMPERSONATE_SA"      # pivot: obtain a service account identity
CODE_EXEC_AS_SA = "CODE_EXEC_AS_SA"    # pivot: run attacker code as an attached SA
RESOURCE_IAM_WRITE = "RESOURCE_IAM_WRITE"  # pivot: setIamPolicy on a resource
CUSTOM_ROLE = "CUSTOM_ROLE"            # pivot: define/expand a custom role
PROJECT_ADMIN = "PROJECT_ADMIN"        # crown jewel: owner of a project/folder
ORG_ADMIN = "ORG_ADMIN"                # crown jewel: owner of the organization
SA_KEY_PERSIST = "SA_KEY_PERSIST"      # crown jewel: long-lived exportable credential
READ_SECRET = "READ_SECRET"            # crown jewel: read secret material
DECRYPT_KMS = "DECRYPT_KMS"            # crown jewel: decrypt with a KMS key

CROWN_JEWELS = {PROJECT_ADMIN, ORG_ADMIN, SA_KEY_PERSIST, READ_SECRET, DECRYPT_KMS}
PIVOTS = {IMPERSONATE_SA, CODE_EXEC_AS_SA, RESOURCE_IAM_WRITE, CUSTOM_ROLE}

_IMPERSONATION_VERBS = {
    "getaccesstoken", "getopenidtoken", "getidtoken", "generateaccesstoken",
    "generateidtoken", "signblob", "signjwt", "implicitdelegation", "createtoken",
}
_DEPLOY_VERBS = {"create", "update", "deploy", "run", "insert", "exec"}
_RM_ADMIN_RESOURCES = {"projects", "folders", "organizations"}


def technique_grants(tech: dict) -> set[str]:
    """Capabilities a technique yields once executed (deterministic, documented rules)."""
    caps: set[str] = set()
    ops = [op_signature(p) for p in tech["required_perms"]]
    ops = [o for o in ops if o]
    for op in ops:
        service, resource, verb = op.split(".")[0], op.split(".")[-2], op.split(".")[-1]

        # service-account impersonation / token minting
        if resource == "serviceaccounts" and verb in _IMPERSONATION_VERBS:
            caps.add(IMPERSONATE_SA)
        # exportable user-managed key
        if resource == "serviceaccountkeys" and verb == "create":
            caps.add(IMPERSONATE_SA)
            caps.add(SA_KEY_PERSIST)

        # setIamPolicy: escalate via policy binding
        if verb == "setiampolicy":
            if service == "resourcemanager" and resource in _RM_ADMIN_RESOURCES:
                caps.add(ORG_ADMIN if resource == "organizations" else PROJECT_ADMIN)
            else:
                caps.add(RESOURCE_IAM_WRITE)
            if resource == "serviceaccounts":
                caps.add(IMPERSONATE_SA)  # bind self serviceAccountTokenCreator

        # custom role creation / expansion
        if service == "iam" and resource == "roles" and verb in {"create", "update"}:
            caps.add(CUSTOM_ROLE)

        # secret material
        if service == "secretmanager" and resource == "versions" and verb == "access":
            caps.add(READ_SECRET)
        if resource == "secrets" and verb in {"get", "list"}:
            caps.add(READ_SECRET)

        # KMS decrypt
        if "usetodecrypt" in verb or verb == "decrypt":
            caps.add(DECRYPT_KMS)

    # deploy-with-actAs => run code as the attached (often higher-priv) service account
    if tech.get("requires_actas"):
        primary = op_signature(tech.get("primary_perm", "")) or ""
        pverb = primary.split(".")[-1] if primary else ""
        if pverb in _DEPLOY_VERBS:
            caps.add(CODE_EXEC_AS_SA)

    return caps


# Capability -> Capability implications (why each holds is in the README).
CAPABILITY_IMPLIES = [
    (CODE_EXEC_AS_SA, IMPERSONATE_SA),     # code running as the SA == holding its identity
    (RESOURCE_IAM_WRITE, IMPERSONATE_SA),  # grant self tokenCreator on a SA
    (CUSTOM_ROLE, PROJECT_ADMIN),          # add any permission to a role you already hold
    (ORG_ADMIN, PROJECT_ADMIN),            # org owner is project owner
    (PROJECT_ADMIN, IMPERSONATE_SA),       # owner may impersonate any SA
    (PROJECT_ADMIN, READ_SECRET),          # owner reads every secret
    (PROJECT_ADMIN, DECRYPT_KMS),          # owner uses every key
]


def capability_unlocks(cap: str, tech: dict) -> bool:
    """Does holding `cap` satisfy an unmet precondition of `tech`?

    The modelled unlock: once you can impersonate / act as a service account
    (IMPERSONATE_SA), every technique gated behind `iam.serviceAccounts.actAs`
    becomes usable, because you now control an SA identity to hand to actAs.
    """
    return cap == IMPERSONATE_SA and tech.get("requires_actas", False)
