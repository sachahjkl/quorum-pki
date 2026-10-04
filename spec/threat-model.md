# Threat model and security contract

This is an experimental, permissioned Web PKI overlay. It is not trustless and is not a browser implementation.

## Actors and roots of trust

The client pins one configuration containing the log identifier, epoch, operator signing keys, X.509 roots, approval threshold `a`, finality threshold `q` and tolerated finality fault budget `f`. These values MUST NOT be accepted from the same unauthenticated server that presents a binding. One member represents one independently governed operator, not one root certificate. Independent private keys and unique member identifiers are necessary but do not demonstrate organizational independence.

The bootstrap command is a trusted local ceremony. It generates five random independent identities. The simulator instead uses explicitly insecure, reproducible seeds. Neither procedure claims to be a production admission protocol. A real root program must vet ownership, control, shared infrastructure and incident response before admitting operators.

The honest domain-validation oracle in this PoC is a preconfigured owner public key per subject. A signed owner request is checked independently by each honest operator. Recovery uses a separately preconfigured recovery key. This is an emulator of independent checks, not ACME, DNSSEC or an Internet domain-control test. Every emulator shares this fixture: its compromise is a common-mode failure outside the independent-operator fault model.

## Adversary

The adversary can control the coordinator and registry, reorder or omit traffic, partition operators, present stale responses, tamper with messages, possess some validator keys, issue arbitrary certificates from those compromised roots and sign conflicting histories. It cannot forge an uncompromised Ed25519 signature, find a SHA-256 collision, change pinned client policy, restore an honest validator's durable state to an earlier snapshot or change a client's trusted clock/checkpoint storage.

HTTP carries signed application artifacts locally. Production transport authentication, confidentiality, DoS protection and endpoint access controls are not implemented. The network launcher binds localhost; Docker's published ports may bind all interfaces and require an explicitly isolated environment. Demonstration private keys share a volume; containers are separate processes, not separate administrative trust domains.

## Two separate quorum statements

1. **Binding authorization:** if strictly fewer than `a` operators are compromised and honest domain checks never approve unauthorized keys, compromised operators alone cannot authorize a false binding. For `a=3,m=5`, two compromised operators are insufficient. Three are sufficient; the scenario demonstrates the loss of this assumption.
2. **Finality uniqueness:** two finality quorums intersect in at least `2q-m` operators. With at most `f` Byzantine operators, `2q > m+f` ensures at least one honest common voter. Honest voters durably lock one checkpoint per size and extend their locked prefix. Thus incompatible checkpoints cannot both receive finality certificates under the assumptions.

For `(m,a,q,f)=(5,3,4,1)` both claims hold. `(7,5,5,2)` is also safe and can progress with two silent operators. `(5,3,3,2)` fails the finality-intersection condition. `4-of-5` can provide safety with two Byzantine operators, but cannot ensure availability if both withhold votes. The default chooses the more conservative combined operating assumption `f=1`.

## Availability and finality scope

The registry is a single sequencer and availability dependency. It is not trusted to invent a binding or a finalized checkpoint. Finality is a quorum notarization certificate, not a full BFT protocol with rounds and leader changes. Honest locks persist before signatures leave the process. Losing them violates the security model.

Partial signatures on an abandoned proposal can permanently split honest locks. No automatic unlocking is permitted. Safe recovery requires reproducing the exact signed candidate and completing its certificate, or an out-of-band trust reset. A network partition with fewer than `q` reachable operators blocks finalization. Eventual recovery of messages does not imply eventual progress after conflicting partial votes. No unconditional or partial-synchrony liveness theorem is claimed.

## What a lightweight client proves

It verifies the operator approval quorum and real X.509 chains for the latest binding event; a finality certificate; inclusion in the ordered event log; inclusion of the subject's current state in the signed state root; consistency with a locally retained checkpoint; and a bounded checkpoint age. It then accepts only a key in the state's deterministic validity/rotation window. The current-state root avoids the error of treating historical log inclusion as proof of current authorization.

No proof authenticates real-world organizational independence or domain ownership beyond the oracle assumptions. A fresh checkpoint can still hide a new revocation for up to the configured freshness bound. A first-use client without a trusted recent checkpoint can receive an older view within that bound. An indefinitely partitioned witness cannot expose a view it never receives. No compact absence proof for an unknown subject is implemented; missing subjects fail closed.

## Invariants and implementation evidence

| Contract | Enforcement / evidence |
|---|---|
| Commit requires approval and finality quorums | `VerifyApprovals`, `VerifyCheckpoint`, registry compare-and-append; adversarial and HTTP tests |
| Operator cannot be counted twice | Unique member IDs and keys, signature `kid`, duplicate rejection |
| Signatures bind epoch, config and previous subject version | Entire canonical Proposal; Head also binds roots, size and previous Head hash |
| Historical entries cannot be edited unnoticed | Previous entry hashes, domain-separated Merkle hashes, proofs and signed Head |
| State is current at the presented checkpoint | Validator replays state transitions and signs StateRoot; client verifies state inclusion |
| Local client watermark cannot move backward | `VerifyBundle` size/time monotonicity, same-size full Head comparison, consistency proof |
| Honest voter cannot fork after restart | Atomic lock write/fsync before signature; restart test |
| Rotation preserves the prior key until overlap ends | Schedule checks against prior expiry and retirement, no replacement of pending/grace rotation; boundary tests |
| Revoked keys are not accepted | Revoked state included in signed StateRoot; client fails if no active key |

TLC verifies a bounded abstraction of these rules. It does not model hashing, concrete serialization, X.509 parsing, actual disks, HTTP or Go memory. Its results are not a proof that the implementation is free of bugs.
