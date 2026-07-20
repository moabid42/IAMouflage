// TITLE: Where the detection effort lands vs. where the attacks are
// WHY: Complements the blind-spot view. These rules cover operations that NO technique in
//      the offensive corpus uses (has_technique=false) — often destruction/impact verbs
//      (delete/patch of firewalls, DNS zones, VPN tunnels, packet mirrors). Useful, but it
//      shows the sigma set is weighted toward "impact/destruction" and away from the
//      "privilege-escalation / credential-access" operations that dominate the corpus.
MATCH (r:DetectionRule)-[:COVERS]->(m:ApiMethod {has_technique:false})
WITH r, m ORDER BY m.op
RETURN r.title    AS rule,
       collect(DISTINCT m.op) AS operations_no_technique_uses,
       r.mitre_tactics AS mitre_tactics
ORDER BY rule;
