// TITLE: Blind-spot concentration by tactic and service
// WHY: Shows the shape of the gap. Per tactic+service you see exactly where coverage is
//      0%. detected here means "a single-event signature fires" (detected_event); a
//      technique caught only by a correlation rule is not counted as covered.
MATCH (t:Technique)
WITH t.tactic AS tactic, t.service AS service,
     sum(CASE WHEN t.detected_event THEN 1 ELSE 0 END) AS detected,
     count(*) AS total
RETURN tactic,
       service,
       detected,
       total,
       total - detected AS blind,
       round(100.0 * detected / total, 1) AS pct_detected
ORDER BY blind DESC, tactic, service;
