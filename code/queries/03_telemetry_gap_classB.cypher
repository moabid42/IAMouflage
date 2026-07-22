// TITLE: Class B blind spots — Data Access logs OFF by default (signatures cannot help)
// WHY: The most important scenario for the thesis. Every observable operation this
//      technique performs is a DATA_ACCESS event, which GCP does NOT record unless the
//      operator explicitly enables Data Access audit logging. No signature can fire on an
//      event that was never logged. This is where impersonation, token minting, secret
//      reads and KMS decryption live: the classic "invisible privilege escalation".
MATCH (t:Technique {blind_class:'TELEMETRY_GAP'})
OPTIONAL MATCH (t)-[:REQUIRES {optional:false}]->(p:Permission)
WITH t, p ORDER BY p.name
WITH t, collect(DISTINCT p.name) AS permissions
RETURN t.tactic       AS tactic,
       t.service      AS service,
       t.primary_perm AS primary_permission,
       permissions    AS data_access_permissions,
       t.title        AS technique
ORDER BY service, primary_permission;
