// TITLE: Each vendor's UNIQUE operations (what only they watch)
// WHY: The value-add of each corpus. Operations that exactly one vendor watches — remove
//      that vendor and these go uncovered. Shows how much unique surface each detection
//      stack contributes versus how much is redundant with the others.
MATCH (r:DetectionRule)-[:WATCHES]->(p:Permission)
WITH p, collect(DISTINCT r.source) AS vendors
WHERE size(vendors) = 1
WITH vendors[0] AS only_vendor, p ORDER BY p.name
RETURN only_vendor,
       count(p)                         AS unique_operations,
       collect(p.name)[..15]            AS sample
ORDER BY unique_operations DESC;
