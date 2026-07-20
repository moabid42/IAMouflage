// TITLE: Rules that look like coverage but are blind by default
// WHY: A subtle, dangerous scenario: a rule EXISTS and matches an operation, but that
//      operation is a Data Access event that is off by default — so the rule silently never
//      fires in a stock project. The SOC believes it has coverage; the graph shows it does
//      not. Example: "Storage Buckets Enumeration" keys on storage.buckets.list, a
//      DATA_ACCESS read.
MATCH (r:DetectionRule)-[:COVERS]->(m:ApiMethod)
WHERE m.logged_by_default = false
RETURN r.title       AS rule,
       r.level       AS level,
       m.op          AS operation_matched,
       m.log_type    AS log_type,
       m.has_technique AS used_by_a_technique
ORDER BY rule, operation_matched;
