# Proposed governance extension (not executable in version 1)

This design addresses the requested evolving congregation of existing authorities. It is deliberately separate from the implemented static-epoch protocol. An epoch number in a signed message does not itself implement membership evolution.

A root program admits a federation by distributing an authenticated genesis configuration to clients. Governance is a quorum of independent operator keys, not one shared wallet secret. Each configuration fixes operator identities, signing/issuer keys, approval/finality thresholds and the tolerated fault budget.

A transition would contain old epoch/config hash, exact finalized predecessor checkpoint, new epoch/config, activation barrier and a unique transition nonce. It MUST receive a finality quorum from the old configuration and a readiness quorum from the new configuration, each signing the same complete transition with distinct contexts. Old and new quorums MUST satisfy their respective honest-intersection conditions. New voters MUST first acquire and verify the finalized state and durable locks. A joint-consensus barrier MUST finalize the transition in the old log before the new epoch processes subject changes. A second transition at the same old epoch MUST be locked out. Merely signing a new member list without tying it to the finalized state is insufficient.

Clients would verify the chain from their pinned configuration, reject skipped/rollback epochs, verify both authorization sets and carry their subject state and checkpoint watermark across the barrier. The same-root multiple-vote issue remains an operator admission policy. A removed operator's old signature remains valid as historical evidence, but cannot count for new-epoch decisions.

Automatic governance can replace membership only while the old authorizing quorum remains trustworthy. If it is compromised, an external root-program trust update and incident-reviewed recovery point are necessary. A threshold key scheme would add share refresh/DKG and require careful treatment of removed operators' old shares; independent multi-signatures avoid that lifecycle in this PoC.

Implementing this requires a full epoch-aware state replay format, durable transition locking, partition/restart tests and an expanded TLA+ model. Those are not present in v1. Changing `config.json` or deleting state is not a valid governance transition.
