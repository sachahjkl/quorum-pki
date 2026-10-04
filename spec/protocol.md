# Quorum PKI Overlay Protocol, version 1

Experimental specification · implementation revision 0.1 · 2026-10-04

## 1. Status and conventions

This document defines the implemented research protocol. It is not an IETF RFC, Internet-Draft, registered TLS extension, ACME extension or Certificate Transparency log profile. The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT and MAY are interpreted according to BCP 14 (RFC 2119 and RFC 8174), only when capitalized.

Version 1 is an overlay: existing X.509 certificates are retained, but acceptance additionally requires independent operator approvals and authenticated registry state. The native verifier implements the additional acceptance policy. Existing browsers are unchanged and will not apply it.

## 2. Terminology

**Operator:** one independently governed authority, with one voting identity and an associated CA root in the pinned configuration. **Subject:** normalized ASCII DNS name without a trailing dot or wildcard. Internationalized names MUST be converted to an agreed A-label representation outside this PoC; Unicode input is rejected. **Proposal:** a subject state transition. **Approval:** an operator's proposal signature and, for key-bearing events, its X.509 server certificate for the same subject/SPKI. **Coordinator:** collects approvals and checkpoint votes. **Registry:** sequences and persists finalized entries. **Checkpoint:** a signed Head with a finality quorum. **State tree:** sorted subject-state leaves describing the current key schedule. **Witness:** persists and compares verified checkpoint views. **Epoch:** one immutable membership/policy configuration. **Finalized:** accepted with a verified finality certificate; receipt of a local signature alone is insufficient.

## 3. Cryptographic profile and serialization

Implementations MUST use SHA-256 and Ed25519 in version 1. Go's standard library implements the primitives. Algorithm negotiation and user-supplied algorithm identifiers are intentionally absent.

Signed values MUST use the restricted RFC 8785 JCS profile: ASCII strings, booleans, null, arrays, objects and integer values within `[-(2^53-1),2^53-1]`. Floats, exponent-form input, Unicode strings, unpaired surrogates, duplicate members and unknown members MUST be rejected. ASCII property sorting is identical to JCS UTF-16 ordering for this profile. Escaping uses ECMAScript-compatible JSON string escaping; HTML escaping MUST NOT be applied. No Unicode normalization is performed. Input may contain whitespace; it is parsed and canonically reserialized before signing. This is not a general JCS library.

The normative structural formats are the files in `schemas/` (JSON Schema Draft 2020-12). Every fixed object forbids additional properties. Required fields MUST be present for schema conformance. The Go decoder rejects duplicate/unknown members and the numeric/string profile; semantic validators enforce security constraints. It is not a general JSON Schema evaluator, and some omitted fields can be normalized to zero values. Interoperable producers MUST still emit all required fields; offline schema checks verify generated artifacts.

Hashes are lowercase 64-character hexadecimal strings. Public keys, certificates and signatures use unpadded base64url. X.509 certificates are DER. Numeric times are Unix seconds (UTC), not JSON date strings. Sequences are 1-based; Merkle indices are 0-based.

### 3.1 Structured signatures

A Signature is a detached JWS-style flattened object containing `protected` and `signature`. The protected header is canonical JSON `{"alg":"EdDSA","kid":"operator-id","typ":"context"}` encoded in base64url. The signing input is:

`BASE64URL(protected-header) || "." || BASE64URL(canonical-payload)`.

This reuses the signing-input construction and protected metadata of RFC 7515 and Ed25519 use from RFC 8037. The payload is conveyed by the surrounding protocol object; its omission corresponds to detached content, not to a new signing primitive. The wire wrapper is a protocol profile, not a complete JOSE implementation. `alg`, `kid` and `typ` MUST be protected, recognized and verified; unprotected headers and `none` are unsupported. Contexts are `qpk-owner-v1`, `qpk-approval-v1`, and `qpk-checkpoint-v1`. Cross-context signatures MUST NOT be accepted.

### 3.2 Configuration

Config contains protocol version, positive epoch, log ID, approval quorum `a`, finality quorum `q`, fault budget `f`, and member records `(id,key,root,url)`. ConfigHash is SHA-256 of its canonical bytes, including URLs. IDs and public keys MUST be unique. Clients MUST pin Config independently. The implementation requires `a>f`, `1<=a<=m`, `q<=m`, `f>=0`, and `2q>m+f`. Operators MUST be counted by independent operator identity rather than by certificates or root count. Admission independence is a governance assertion, not something this cryptographic rule establishes.

## 4. Proposal and approval

Proposal binds version, epoch, ConfigHash, event, subject, new public key, subject generation, previous subject Entry hash, activation, retirement, expiration and a nonce. A first `issue` has generation 1 and empty previous reference. Later key/revocation transitions MUST increment generation exactly once and name the current subject Entry hash. Sequence is assigned by the registry, not chosen by the owner. The nonce provides request distinction; version checks and reference checks prevent duplicate issuance. Identical retry after finalization is rejected as stale rather than implemented as an idempotent replay.

A validator MUST check proposal version/epoch/config, DNS syntax, key encoding and schedule, then its domain-validation policy. In this emulator, the owner request signature MUST verify against the subject fixture key. `recover` MUST instead use the independently pinned recovery key. `recovery=true` is required but is not itself authorization. A malicious emulator MAY bypass the owner check for attack demonstrations; it still uses real signatures and certificates.

A key-bearing approval MUST contain a valid server certificate chaining to that operator's pinned root, with SAN matching the subject, SPKI matching the proposal key and certificate validity covering activation through expiration. Certificate verification is performed at the entry timestamp. Only Ed25519 subject keys are implemented. `revoke` and `heartbeat` approvals carry an empty certificate. Duplicate or unrecognized operator signatures MUST be rejected.

The coordinator SHOULD contact all operators concurrently. It MUST verify each response before counting it. A timeout, refusal, invalid signature or invalid certificate contributes no vote. It collects responses over bounded context timeouts; no coordinator signature can substitute for a missing operator signature. A quorum failure MUST return an error and MUST NOT append a finalized entry. Receiving an error does not imply validators have not persisted partial finality locks.

## 5. Entry ordering and state transitions

Entry binds version, sequential index, timestamp, previous global Entry hash, Proposal and sorted approvals. Approval order is lexicographic operator ID. The first global entry has an empty previous hash. Each later global entry MUST hash-reference its immediate predecessor. Entries MUST NOT contain their own root or inclusion proof: these would make self-referential hashes. Proofs and checkpoints are separate artifacts.

Subject states are derived by replay. `issue` creates a state. `rotate` creates a next generation preserving the prior key as OldKey. `revoke` increments generation, retains the key schedule for audit and sets Revoked. `recover` replaces a prior or revoked state with an authorized new key; it does not preserve a compromised key in grace. Nonexistent subjects cannot rotate, revoke or recover. A `heartbeat` MUST reference an existing current subject state, retain its generation and previous subject Entry hash, and carry an empty key; it appends a new ordered event without changing subject state. It requires the normal signed owner request, approval quorum and finality quorum.

For rotation, Activate MUST precede Retire; Retire MUST NOT exceed the prior state's Expires; a new rotation MUST NOT replace a pending or still-overlapping rotation. Expires MUST exceed Activate. A retired old key cannot be resurrected by a routine rotation. Prior revoked/expired keys cannot authorize routine rotation. Emergency recovery bypasses overlap and can interrupt service; that tradeoff is intentional.

The conceptual lifecycle is PROPOSED → APPROVED → FINALIZED, followed by time-derived SCHEDULED → GRACE → ACTIVE → RETIRED, or explicit REVOKED. GRACE denotes the interval in which both keys are accepted. ACTIVE denotes the interval in which only the new key is accepted. Time-derived labels are not separate journal writes. There is no certificate expiration every few minutes; demo certificates cover one day by default, and the protocol permits longer explicit schedules.

## 6. Authenticated trees

Log hashing and proofs reuse RFC 9162 §2.1:

- empty tree root: `SHA256("")`;
- leaf: `SHA256(0x00 || canonical(Entry))`;
- parent: `SHA256(0x01 || left || right)`;
- non-power-of-two trees split at the greatest power of two strictly smaller than the leaf count.

Inclusion paths are bottom-up sibling hashes. Consistency proofs implement RFC 9162 SUBPROOF and verify that the old log is a prefix of the new log. Proofs MUST bind both sizes and independently authenticated roots. Extra proof nodes MUST be rejected. An old empty root has only an empty consistency proof. Equal-sized checkpoints require identical root and full Head.

The State tree uses the same hashing on canonical State objects sorted lexicographically by subject. Each State binds subject, generation, latest Entry hash, Key, OldKey, Activate, Retire, Expires and Revoked. StateRoot is signed in the same Head as the ordered log Root. Validators replay all entries to verify both roots. The client receives only its current State and Merkle path. This is a sorted vector tree, not a sparse Merkle map; unknown-subject non-membership proofs are unsupported. A new subject can change many state-tree positions. Log and state construction/replay are intentionally unoptimized.

## 7. Finality and durable locks

Head binds version, epoch, ConfigHash, LogID, tree Size, log Root, StateRoot, timestamp and previous Head hash. The first finalized Head names the deterministic unsigned genesis Head. Genesis has size/time zero and both empty-tree roots. Genesis MUST NOT be used to accept a binding.

A candidate includes the full log prefix, its finalized parent Checkpoint and proposed Head. An honest voter MUST validate all approvals and state transitions, the parent's quorum certificate, exact parent size, monotonic time, previous Head hash, parent prefix roots and proposed roots. It MUST persist its latest locked Head before releasing its signature. It MUST reject a lower size, a different Head at its locked size, a changed locked log prefix, or a contradictory immediate parent. Restart MUST reload the durable lock and MUST NOT silently discard a corrupt lock file.

A finality certificate requires `q` independent valid Head signatures. The registry MUST independently verify candidate and finality certificate, compare the complete stored prefix, and append atomically. Finality is the existence of this quorum certificate, even if a registry crash delays serving it. There is no global wall-clock instant at which all parties learn it.

This implementation is a fixed-sequencer, permanently locked notarization protocol. It MUST NOT be described as PBFT, Tendermint or a complete view-changing BFT consensus. Lost or conflicting partial votes can block progress indefinitely. The automatic demos reset an entire isolated universe; that is not an in-protocol recovery of a production federation.

## 8. Client acceptance

Given a trusted Config, requested subject, local time, maximum age and optional durable prior Checkpoint, the client MUST:

1. Verify epoch, ConfigHash, LogID and finality quorum of the presented Checkpoint.
2. Reject a timestamp more than 5 seconds in the future or older than configured maximum age (CLI default: 300 seconds).
3. Verify approvals and operator X.509 chains of the latest subject Entry.
4. Verify Entry inclusion against signed log Root and Size.
5. Verify current State inclusion against signed StateRoot.
6. Match requested subject, Entry hash and generation to the State.
7. Reject size/time rollback, same-size different Head, or an invalid consistency proof against its prior checkpoint.
8. Reject Revoked or expired state. Before Activate, accept only OldKey if present; during `[Activate,Retire)`, accept both Key and OldKey; thereafter accept only Key until Expires.
9. Persist the accepted Checkpoint before treating it as a future rollback watermark.

The caller MUST additionally prove possession of the selected subject private key, e.g. by normal TLS, and match its SPKI to an accepted key. The CLI verifies authorization artifacts; it does not perform a live TLS handshake with the subject. Browser-level certificate stapling and TLS integration are not implemented.

The state root is an authenticated assertion by the finality quorum that this state follows the full log. A compact client does not replay the log itself. The approved public key list is bounded to two per subject.

Freshness assumes a trustworthy local clock. An idle log eventually exceeds the configured age unless refreshed. An authenticated `heartbeat` appends through the same approval/finality path and refreshes the checkpoint timestamp without extending any certificate or key lifetime. The CLI and UI expose heartbeats; automatic scheduling is not implemented. A deployment MUST arrange periodic quorum heartbeats and MUST NOT silently disable freshness to fix unavailable refreshes.

## 9. Witnesses and gossip

A witness MUST verify quorum signatures, refuse local rollback or a conflicting same-size Head, require consistency for extensions, and persist its accepted view. `POST /v1/gossip` compares two verified checkpoints. Different roots or state roots at the same size constitute signed equivocation evidence (the complete Head comparison detects either). Different-sized views require a consistency proof through `observe`; mere size difference is not evidence of fraud.

Witnesses in version 1 are monitors, not an extra client trust threshold. They do not cosign and do not poll peers automatically. The HTTP endpoints permit explicit observation/gossip, and scenarios directly exercise these operations. Detection requires contradictory views to reach an honest comparing witness. No finite detection bound under arbitrary partitions is claimed.

## 10. API, errors and resource bounds

`api/openapi.yaml` documents native endpoints. Issue, rotation, revocation and recovery share `POST /v1/subjects`; the signed event distinguishes them. Simulator control endpoints are separate demo conveniences and do not accept production signed requests. Message bodies are limited to 16 MiB. The HTTP helper times out after 5 seconds; coordinator requests time out after 6 seconds. A validator's CPU/disk work already begun may persist a vote even after the caller times out.

Errors are JSON `{error:string}` with HTTP 409 in this PoC, covering malformed input, signature/certificate failure, quorum failure, stale generation, scheduling violation, invalid proof, rollback, equivocation and persistence failure. Production clients need stable machine-readable error codes and authentication. SSE is advisory only, with bounded replay and no durable resume cursor. UI events MUST NOT be treated as cryptographic evidence.

## 11. Versioning, membership and recovery

Unknown protocol versions and mismatched epochs MUST be rejected. The executable configuration is static for its entire log. Changing a Config changes its hash and invalidates acceptance under the old Config. There is no implemented hot membership transition. The designed extension is specified separately in `governance.md`; it MUST NOT be assumed available in version 1.

Subject recovery requires a separately pinned recovery credential and the ordinary operator quorum; a revoked state has no active key until a successful recovery. Federation recovery after quorum-key compromise cannot be authorized safely by those same compromised keys alone. Version 1 requires an out-of-band, authenticated new trust configuration and explicit log/checkpoint reset. It MUST NOT call a newly initialized database a continuation of the old finalized log.

## 12. Security and deployment

See `threat-model.md`, `security-considerations.md` and `references.md`. The repo's tests and captured results are the evidence of implemented behavior. This PoC is not suitable as a replacement browser root program. Its conditional safety relies on pinned independent members, correct domain checks, uncompromised signatures, durable locks/checkpoints and reliable time.
