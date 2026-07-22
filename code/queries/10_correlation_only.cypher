// TITLE: Techniques only a correlation or threshold rule can catch
// WHY: New with the multi-corpus merge. These techniques are invisible to every
//      single-event signature (detected_event = false) yet DO trip a stateful rule — a
//      Google SecOps `match ... over <window>` count, a Panther Threshold, or a
//      multi-stage correlation chain. They are caught only if the operation repeats enough
//      times or the whole chain completes, so one careful execution still evades them. This
//      is exactly the ground a per-event detector cannot hold and the POMDP planner must
//      price against history, not a single action.
MATCH (t:Technique {blind_class:'CORRELATION_ONLY'})-[d:DETECTED_BY]->(r:DetectionRule)
WITH t, r, d ORDER BY r.source, r.title
RETURN t.tactic  AS tactic,
       t.service AS service,
       t.primary_perm AS primary_permission,
       collect(DISTINCT r.source + ':' + r.paradigm +
               CASE WHEN d.threshold IS NOT NULL THEN ' x' + toString(d.threshold) ELSE '' END) AS caught_only_by,
       t.title   AS technique
ORDER BY tactic, service, primary_permission;
