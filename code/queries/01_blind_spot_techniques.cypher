// TITLE: Every technique with zero detection coverage
// WHY: The direct answer to "which situations can my detections not figure out?". These
//      techniques have NO rule whose firing condition they satisfy on an on-by-default
//      log, so executing them raises no alert (not even a correlation/threshold rule).
MATCH (t:Technique)
WHERE NOT (t)-[:DETECTED_BY]->(:DetectionRule)
RETURN t.tactic         AS tactic,
       t.service        AS service,
       t.primary_perm   AS primary_permission,
       t.blind_class    AS blind_class,
       t.requires_actas AS needs_actAs,
       t.title          AS technique
ORDER BY tactic, service, primary_permission;
