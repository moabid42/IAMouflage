// TITLE: Invisible service-account impersonation primitives
// WHY: The sharpest instance of a Class B telemetry gap. Every technique here GRANTS the
//      IMPERSONATE_SA capability (the attacker becomes another service account) while its
//      only operations are DATA_ACCESS events that are off by default. So the single most
//      valuable move in a GCP attack — stealing another identity — produces no log at all
//      in a default project, let alone an alert. These are also the entry points of the
//      pivot chains in query 08.
MATCH (t:Technique)-[:GRANTS]->(:Capability {name:'IMPERSONATE_SA'})
WHERE t.blind_class = 'TELEMETRY_GAP'
OPTIONAL MATCH (t)-[:REQUIRES {optional:false}]->(p:Permission)
WITH t, p ORDER BY p.name
WITH t, collect(DISTINCT p.name) AS permissions
RETURN t.service      AS service,
       t.primary_perm AS primary_permission,
       permissions,
       t.tactic       AS tactic,
       t.title        AS technique
ORDER BY service, primary_permission;
