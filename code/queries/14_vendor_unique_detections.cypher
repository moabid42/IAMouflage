// TITLE: Techniques only ONE vendor catches (incremental coverage)
// WHY: The incremental-coverage diff. Techniques that a single vendor detects and no
//      other does — the concrete answer to "what does adding this vendor buy me over the
//      others?". These flip to blind spots if that vendor is removed.
MATCH (t:Technique)-[:DETECTED_BY]->(r:DetectionRule)
WITH t, collect(DISTINCT r.source) AS vendors
WHERE size(vendors) = 1
WITH vendors[0] AS only_vendor, t ORDER BY t.tactic, t.service
RETURN only_vendor,
       count(t)                    AS techniques_only_this_vendor_catches,
       collect(t.primary_perm)[..12] AS sample
ORDER BY techniques_only_this_vendor_catches DESC;
