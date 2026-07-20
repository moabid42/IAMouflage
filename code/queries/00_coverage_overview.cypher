// TITLE: Detection coverage overview
// WHY: Baseline — of every abusable GCP technique in the corpus, how many does the
//      sigma signature set actually detect? A technique is DETECTED only if one of the
//      operations it must perform is (a) matched by a rule AND (b) written to a log that
//      is on by default. Everything else is a blind spot, split into:
//        RULE_GAP      (Class A) operation IS logged by default, but no rule matches it
//                                -> fixable by writing a signature
//        TELEMETRY_GAP (Class B) operation is a Data Access log, OFF by default
//                                -> no signature can ever fire until logging is reconfigured
MATCH (tt:Technique)
WITH toFloat(count(tt)) AS total
MATCH (t:Technique)
WITH total, t.blind_class AS status, count(*) AS techniques
RETURN status,
       techniques,
       round(100.0 * techniques / total, 1) AS pct
ORDER BY techniques DESC;
