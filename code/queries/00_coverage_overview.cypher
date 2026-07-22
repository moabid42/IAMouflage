// TITLE: Detection coverage overview
// WHY: Baseline — of every abusable GCP technique in the corpus, how does the merged
//      detection set (Sigma + Elastic + Google SecOps + Panther) classify each? A
//      technique is DETECTED only if one operation it must perform is (a) matched by a
//      rule group on a required permission AND (b) written to a log on by default. The
//      rest split into:
//        CORRELATION_ONLY only a threshold / multi-stage rule fires (needs repetition or
//                         a full chain); a single execution stays silent
//        RULE_GAP    (Class A) an operation IS logged by default, but no rule matches it
//        TELEMETRY_GAP (Class B) every observable operation is a Data Access log, OFF by
//                         default -> no signature can fire until logging is reconfigured
MATCH (tt:Technique)
WITH toFloat(count(tt)) AS total
MATCH (t:Technique)
WITH total, t.blind_class AS status, count(*) AS techniques
RETURN status,
       techniques,
       round(100.0 * techniques / total, 1) AS pct
ORDER BY techniques DESC;
