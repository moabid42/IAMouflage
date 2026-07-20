// TITLE: Blind-spot concentration by tactic and service
// WHY: Shows the shape of the gap. Privilege-escalation and post-exploitation are almost
//      entirely blind; the handful of detections cluster in GKE/container, storage and SQL.
//      Per service you can see exactly where you have 0% coverage.
MATCH (t:Technique)
WITH t.tactic AS tactic, t.service AS service,
     sum(CASE WHEN t.detected THEN 1 ELSE 0 END) AS detected,
     count(*) AS total
RETURN tactic,
       service,
       detected,
       total,
       total - detected AS blind,
       round(100.0 * detected / total, 1) AS pct_detected
ORDER BY blind DESC, tactic, service;
