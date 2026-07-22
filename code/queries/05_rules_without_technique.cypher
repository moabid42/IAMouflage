// TITLE: Where the detection effort lands vs. where the attacks are
// WHY: Complements the blind-spot view. These rules watch permissions that NO technique in
//      the offensive corpus uses — often destruction/impact verbs (delete/patch of
//      firewalls, DNS zones, VPN tunnels, packet mirrors). Useful, but it shows the
//      detection sets are weighted toward "impact/destruction" and away from the
//      privilege-escalation / credential-access operations that dominate the corpus.
MATCH (r:DetectionRule)-[:WATCHES]->(p:Permission)
WHERE NOT exists { (:Technique)-[:REQUIRES]->(p) }
WITH r, p ORDER BY p.name
RETURN r.source   AS source,
       r.title    AS rule,
       collect(DISTINCT p.name) AS permissions_no_technique_uses,
       r.mitre_tactics AS mitre_tactics
ORDER BY source, rule;
