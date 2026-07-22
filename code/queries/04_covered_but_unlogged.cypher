// TITLE: Rules that look like coverage but are blind by default
// WHY: A subtle, dangerous scenario: a rule EXISTS and matches a permission, but that
//      permission is a Data Access operation that is off by default — so the rule silently
//      never fires in a stock project. The SOC believes it has coverage; the graph shows it
//      does not. Example: a "Storage Buckets Enumeration" rule on storage.buckets.list, a
//      DATA_ACCESS read.
MATCH (r:DetectionRule)-[:WATCHES]->(p:Permission)
WHERE p.logged_by_default = false
RETURN r.source      AS source,
       r.title       AS rule,
       r.level       AS level,
       p.name        AS permission_matched,
       p.log_type    AS log_type,
       exists { (:Technique)-[:REQUIRES]->(p) } AS used_by_a_technique
ORDER BY source, rule, permission_matched;
