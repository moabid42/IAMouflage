// TITLE: Class B blind spots — Data Access logs OFF by default (signatures cannot help)
// WHY: The most important scenario for the thesis. Every operation this technique performs
//      is a DATA_ACCESS event, which GCP does NOT record unless the operator explicitly
//      enables Data Access audit logging. No signature — however well written — can fire on
//      an event that was never logged. This is where impersonation, token minting, secret
//      reads and KMS decryption live: the classic "invisible privilege escalation".
MATCH (t:Technique {blind_class:'TELEMETRY_GAP'})
OPTIONAL MATCH (t)-[:INVOKES]->(m:ApiMethod)
WITH t, m ORDER BY m.op
WITH t, collect(DISTINCT m.op) AS operations
RETURN t.tactic       AS tactic,
       t.service      AS service,
       t.primary_perm AS primary_permission,
       operations     AS data_access_operations,
       t.title        AS technique
ORDER BY service, primary_permission;
