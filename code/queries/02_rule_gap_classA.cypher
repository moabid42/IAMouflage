// TITLE: Class A blind spots — logged by default, but no rule (write-a-signature gaps)
// WHY: These are the "cheap wins". The operation lands in ADMIN_ACTIVITY logs (always on),
//      so the evidence exists in the customer's logs today — there simply is no sigma rule
//      matching it. Each row is a signature that could be authored immediately.
MATCH (t:Technique {blind_class:'RULE_GAP'})-[:INVOKES]->(m:ApiMethod)
WHERE m.logged_by_default = true AND NOT (:DetectionRule)-[:COVERS]->(m)
RETURN t.service      AS service,
       m.op           AS logged_but_unwatched_operation,
       t.tactic       AS tactic,
       t.primary_perm AS primary_permission,
       t.title        AS technique
ORDER BY service, logged_but_unwatched_operation;
