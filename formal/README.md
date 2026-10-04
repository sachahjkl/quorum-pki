# Formal model and captured checking

`DistributedPKI.tla` abstracts signatures as sets of authenticated operator approvals/votes. Honest approvals reject a forged binding; Byzantine operators may approve it and vote twice. Honest finality voters lock one proposal per subject version. Commit requires approval and finality quorums. The append-only sequence, subject generations, client watermark, rotation/grace keys, revocation, rollback attempt and simplified partition are explicit variables/actions.

The model abstracts checkpoint slots by subject generation. It does not model the global Merkle index, concrete cross-subject scheduling or actual parent-certificate hashes. Quorum safety transfers only under the stated durable one-vote-per-slot assumption. The Go implementation locks checkpoint sizes and validates full prefixes; tests cover this distinct implementation obligation.

## Invariants

- `TypeOK`: finite model domains are preserved.
- `CommittedHasQuorum`: every finalized proposal has both quorums.
- `MinorityCannotForge`: the forged proposal cannot finalize when Byzantine cardinality is below ApprovalQuorum.
- `UniqueFinality`: no two distinct proposals of one generation can finalize.
- `AppendOnly`: the saved previous sequence remains a prefix after commits.
- `NoRollback`: an attempted rollback does not lower the already-observed version.
- `RotationContinuity`: both old and next keys remain accepted during the modeled overlap, unless explicitly revoked.

`Rollback` is a client rejection action; NoRollback checks that abstraction, not whether all network paths in Go invoke it. Go rollback tests independently exercise the real verifier. Rotation intervals are abstract ticks, not a timed TLA+ model. Heartbeat refresh and governance transitions are not modeled. The model has no cryptographic proof of real-world domain validity and no liveness/fairness theorem.

## Executed configurations

| Model/config | Result | Coverage |
|---|---|---|
| DistributedPKI / DistributedPKI.cfg | PASS; 673,206 distinct states, 5,478,850 generated, depth 37 | 3 operators, approval 2, finality 3, one Byzantine; five proposals; all listed invariants |
| DistributedPKI / Unsafe.cfg | Expected FAIL of UniqueFinality | 3 operators, approval 2, finality 2, one Byzantine; signed fork counterexample |
| QuorumIntersection / IntersectionFive.cfg | PASS | Exhaustively enumerates pairs of 4-of-5 quorums, one Byzantine |
| QuorumIntersection / IntersectionSeven.cfg | PASS; 841 pairs | Exhaustively enumerates pairs of 5-of-7 quorums, two Byzantine |

`Five.cfg` is provided for the full 5-operator behavioral model but was not exhaustively run. The 5/7-operator intersection models verify the quorum combinatorics, not the full protocol. Finite-state checking is not a theorem over unbounded histories. Captured outputs in `results/tlc-*.txt` include TLC version, assumptions and state counts. Unsafe failure is evidence against the weaker configuration, not a test to be made green by hiding the invariant.

## Reproduction

Install Java 17+ and obtain an official [TLA+ tools release](https://github.com/tlaplus/tlaplus/releases). Pass the jar path:

```sh
make formal TLC_JAR=/absolute/path/tla2tools.jar
java -cp /absolute/path/tla2tools.jar tlc2.TLC -workers 2 \
  -config formal/Unsafe.cfg formal/DistributedPKI.tla
```

The second command MUST exit nonzero with a UniqueFinality counterexample. The captured run used the environment's already-installed TLC jar. No jar is bundled. `CHECK_DEADLOCK FALSE` is intentional: lack of availability under insufficient quorum is not a safety failure; no progress guarantee is claimed.
