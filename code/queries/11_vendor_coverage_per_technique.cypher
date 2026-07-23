// TITLE: Which vendors detect each technique (source diff)
// WHY: The per-technique view of the four-corpus merge. For every technique some rule
//      catches, which vendors (Sigma / Elastic / Google SecOps / Panther) catch it, and
//      how many agree. A high vendor_count = redundantly covered; 1 = only one vendor
//      would catch it, so dropping that vendor blinds you to it.
MATCH (t:Technique)-[:DETECTED_BY]->(r:DetectionRule)
WITH t, r ORDER BY r.source
WITH t, collect(DISTINCT r.source) AS vendors
RETURN t.tactic        AS tactic,
       t.service       AS service,
       t.primary_perm  AS primary_permission,
       size(vendors)   AS vendor_count,
       vendors,
       t.title         AS technique
ORDER BY vendor_count DESC, tactic, service;
