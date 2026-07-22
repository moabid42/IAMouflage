// TITLE: Multi-step pivot chains that no per-event rule can correlate
// WHY: The scenario a signature engine structurally cannot see, and the graph can. Each
//      ENABLES edge is "technique A yields a capability that unlocks technique B" (mint an
//      SA token -> satisfy iam.serviceAccounts.actAs -> deploy code as a new SA -> mint the
//      next token...). Every hop is individually a blind spot AND the whole chain is
//      invisible: no rule fires on any hop, and no per-event rule reasons across hops.
//      entry = standalone foothold (<=2 perms, no actAs); each hop is a deploy-as-SA
//      technique reached purely by impersonation.
MATCH path = (entry:Technique)-[:ENABLES*2..4]->(goal:Technique)
WHERE ALL(n IN nodes(path) WHERE n.detected = false)
  AND entry.requires_actas = false
  AND entry.num_required <= 2
  AND goal.requires_actas = true
WITH entry, path,
     [n IN nodes(path) | n.service + '.' + split(n.primary_perm, '.')[-1]] AS steps,
     length(path) AS hops
RETURN entry.service      AS foothold_service,
       entry.primary_perm AS foothold_permission,
       hops,
       steps              AS chain
ORDER BY hops DESC, foothold_service, foothold_permission, steps
LIMIT 20;
