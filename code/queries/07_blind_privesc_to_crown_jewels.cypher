// TITLE: Undetected techniques that hand over a crown jewel
// WHY: The high-impact scenarios. Each technique here is a blind spot (no DETECTED_BY) yet
//      it grants — directly, or through a documented capability implication — a crown-jewel
//      capability: project/org ownership, an exportable SA key, secret material, or KMS
//      decryption. An attacker performs one uncovered API call and owns the asset, with no
//      alert. Pure graph traversal; no model involved.
MATCH (t:Technique)-[:GRANTS]->(:Capability)-[:IMPLIES*0..3]->(cj:Capability {kind:'crown_jewel'})
WHERE t.detected = false
WITH t, cj ORDER BY cj.name
WITH t, collect(DISTINCT cj.name) AS crown_jewels
RETURN t.tactic       AS tactic,
       t.service      AS service,
       t.primary_perm AS primary_permission,
       t.blind_class  AS blind_class,
       crown_jewels,
       t.title        AS technique
ORDER BY size(crown_jewels) DESC, tactic, service, primary_permission;
