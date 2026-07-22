// TITLE: Class A blind spots — logged by default, but no rule (write-a-signature gaps)
// WHY: The "cheap wins". The permission lands in ADMIN_ACTIVITY logs (always on), so the
//      evidence exists in the customer's logs today — there is simply no rule watching it.
//      Each row is a permission a signature could be authored against immediately.
MATCH (t:Technique {blind_class:'RULE_GAP'})-[:REQUIRES]->(p:Permission)
WHERE p.logged_by_default = true AND NOT (:DetectionRule)-[:WATCHES]->(p)
RETURN t.service       AS service,
       p.name          AS logged_but_unwatched_permission,
       t.tactic        AS tactic,
       t.primary_perm  AS primary_permission,
       t.title         AS technique
ORDER BY service, logged_but_unwatched_permission;
