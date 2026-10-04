# Security considerations and comparisons

## Improvement and unchanged trust

A browser policy that actually enforces this overlay prevents one admitted CA from independently authorizing a false domain/key binding. The registry cannot replace missing operator approvals. Signed current-state proofs improve clients' ability to verify rotation and revocation without downloading the log. Durable checkpoints reject previously observed history rollback; independent witnesses expose contradictory signed histories when their views meet.

This does not remove trust. It replaces unilateral CA trust with trust in a pinned federation, the independence of enough members, common domain-validation dependencies, durable state and clock bounds. A corrupted approval quorum can authorize the wrong key. A corrupted finality quorum can authenticate arbitrary state. A hostile sequencer can censor and block progress. An authorized owner can still choose a compromised key. DNS/BGP, operator software, cloud providers and root-program governance can create correlated failures.

## Root programs and realistic extension

Existing CA operators could retain X.509 issuance and ACME machinery. A browser would require an external binding package for the same DNS name and SPKI, count independent operators, verify their certificates and enforce authenticated current state. Several roots owned by one operator count once. The target endpoint must still prove possession of the accepted private key during TLS.

This repo does not modify Chrome or Firefox and does not register TLS extensions or certificate OIDs. Native package verification models a new browser acceptance rule. Negotiation, stapling and cache design require separate interoperability work. A practical roll-out would first observe, then enforce for an explicitly announced population, then broaden. Once enforcement applies, silently falling back to one CA defeats the security goal. Observation mode alone does not prevent abuse.

Real domain checks should be geographically/network-diverse and assess correlated dependencies. Multiple copies of the same HTTP challenge from the same cloud resolver are not five independent trust sources. The PoC's owner key fixture is explicit common trust, suitable for exercising quorum mechanics only.

## Comparison

| Architecture | Root of trust | Prevention / evidence | Availability and scaling |
|---|---|---|---|
| Classical Web PKI | Browser root program and accepted CA chains | One authorized issuer can produce a valid chain; CT/other controls improve evidence and constraints | Mature issuance, one issuer generally sufficient |
| Certificate Transparency | Accepted CA plus logged SCTs and monitored logs | Detects misissuance and inconsistent histories; does not itself require several independent issuers to authorize the same SPKI | Mature ecosystem; inclusion is historical, not proof of current subject authorization |
| DNSSEC / DANE | DNS trust chain and domain administrative delegation | TLSA can bind server credentials without relying solely on public CA issuance; DNS hierarchy compromises remain material | Different deployment/client support and DNS availability assumptions |
| This overlay | Pinned independent operators, approval/finality thresholds, client checkpoints | Prevents unilateral binding under assumptions; authenticates current key state; gossip can expose signed forks | O(m) signatures/certs; fixed sequencer; blocking locks and full replay limit availability/scaling |
| Public blockchain | Consensus/sybil mechanism, economic/network assumptions and initial software/checkpoint trust | Replicated ordering and public audit; does not determine true domain ownership by itself | Fees/resources, latency, privacy, probabilistic or protocol-specific finality; not required for this PoC |
| Permissioned BFT ledger | Admission governance, fault bound, consensus protocol | Quorum ordering with protocol-specific safety and liveness under network assumptions | More operational complexity; mature rounds/view changes can recover where this notarizer stalls |

The append-only Merkle log resembles a ledger but has one storage/sequencing process. Its replicas are not a state machine replication consensus. Validators independently check the full candidate and sign checkpoint state; witnesses monitor. There are no coins, mining, PoW, staking, transaction fees or economic Sybil defenses.

## Multi-signatures versus threshold signatures

Independent signatures retain attribution and integrate naturally with independent X.509 issuer roots. They need O(m) verification and package size, especially when certificates accompany approvals. A cryptographic aggregate/threshold signature may reduce the finality certificate, but requires separately designed membership, share distribution, refresh, participant authentication and nonce handling. FROST does not automatically stop an honest participant signing two conflicting checkpoints. Both approaches require consensus/voting rules and durable state.

The current package is intentionally not small enough for ubiquitous browser deployment: it includes several leaf certificates, a signature set and two proof paths. Merkle paths remain O(log N); authority data remains O(m). A cache of operator roots/configuration avoids downloading those with every response.

## Capture, Sybil resistance and recovery

One independent operator per member plus vetted admission provides permissioned Sybil resistance, only as strong as governance vetting. Ten independently keyed subsidiaries under one controlling entity remain a potential single actor. Rotating signing keys without independent incident remediation does not remove a compromised operator.

A compromised old governance quorum can sign a malicious new federation. Joint old/new authorization does not cure that; clients need root-program emergency override anchored outside that quorum. Recovery after erased client checkpoints cannot reconstruct the fact that the client saw a later view. Recovery from lost validator lock state needs external authenticated history, not automatic empty-state restart.

Version 1 has separate owner recovery keys but static federation configuration. `governance.md` defines the intended transition design and explicitly identifies it as unimplemented. Production safety would additionally require HSM/key isolation, audited validation adapters, transport security, replay/rate controls, robust persistence, monitoring, privacy review and complete BFT recovery.

## Concrete implementation limitations

- Native HTTP is for a local laboratory. Body bounds exist; there is no production access control or traffic confidentiality.
- The JSON canonicalizer is an intentionally narrow JCS subset. Typed decoding is not full runtime JSON Schema validation; strict required-field conformance is checked on fixtures offline.
- Durable writes use file fsync, rename and directory fsync. The executable cross-compiles; crash durability and replacement semantics are only exercised on Linux. Windows/macOS runtime persistence is not certified.
- Validator `mode=malicious` bypasses the domain oracle and lock policy while retaining cryptographic message checks. The four-stolen-key split-view scenario deliberately bypasses honest voter logic to show detectable evidence after assumptions fail.
- The simulator has seeded static per-actor delay/failure choice, not a packet-level Internet emulator. Real-time goroutine arrival order can vary. Seeds reproduce keys, fault selections and roots; the exported normalized trace sorts events but is not an exact scheduling replay engine.
- Partition configuration is a list of unreachable actors from the coordinator, not arbitrary changing graph cuts. Refusal, malformed signatures and crashes are selectable; crash/restart durable-lock behavior is covered separately.
- Freshness expires on an idle log unless an explicit quorum heartbeat is submitted; automatic heartbeat scheduling is not supplied. No automatic witness polling, witness cosignature or TLS/browser plugin is supplied.
- The sequencer sends full history to voters and recomputes state trees. Storage is atomic JSON snapshots, not a scalable log database. Missing subject proofs fail closed.
- No hot membership transitions, automatic epoch migration, view changes, automatic quorum-compromise recovery, private domain logging, wildcard bindings or public CA enrollment are implemented.

These gaps are in the delivery status, not hidden behind successful HTTP responses or model checking.
