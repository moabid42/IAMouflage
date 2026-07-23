// TITLE: Which vendors watch each operation (overlap matrix)
// WHY: The per-operation overlap. For every permission any rule watches, the set of
//      vendors watching it. Operations watched by all four are heavily redundant; those
//      watched by one are a single point of coverage. This is the raw diff between the
//      detection stacks at the operation level.
MATCH (r:DetectionRule)-[:WATCHES]->(p:Permission)
WITH p, r ORDER BY r.source
WITH p, collect(DISTINCT r.source) AS vendors
RETURN p.name        AS operation,
       p.log_type    AS log_type,
       size(vendors) AS vendor_count,
       vendors
ORDER BY vendor_count DESC, operation;
