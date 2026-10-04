# Validation summary

The repository is v0.1 with the explicit unfinished scope in README.md. Successful checks do not assert the missing features.

| Check | Executed result |
|---|---|
| Go unit and integration tests, vet | PASS |
| Concurrent Go race-detector tests (development tool uses cgo; deliverable builds do not) | PASS |
| Standalone native multi-process launch | PASS: randomized keys, issuance, client authorization verification, witness observation |
| Native attack scenarios | 13 PASS |
| Go WASM in actual Node Worker | Same 13 scenarios PASS |
| Linux amd64 production build | PASS with CGO_ENABLED=0 |
| Windows amd64, macOS arm64, Linux arm64 demo cross-builds | PASS with CGO_ENABLED=0; not run on those OSes |
| JSON Schema 2020-12 metaschemas, signed bundle/config fixtures, unknown property rejection | PASS using optional Python jsonschema dev tool |
| TLA+ bounded behavioral model | PASS: 673,206 distinct states, 7 invariants |
| Unsafe finality model | Expected UniqueFinality counterexample |
| 4-of-5 and 5-of-7 honest quorum intersection | PASS by exhaustive quorum-pair enumeration |
| Docker image / Compose execution | NOT RUN: no Docker executable in environment |
| Browser visual interaction | BLOCKED: control browser refused local URL with ERR_BLOCKED_BY_CLIENT; no visual QA assertion |
| ACME, live domain TLS handshake, public browser integration | NOT IMPLEMENTED |
| Hot membership transitions / full BFT view changes | NOT IMPLEMENTED |

Captured benchmark run: Go 1.25.1, Linux amd64, AMD EPYC 9V74 virtual environment, 8 exposed runtime CPUs. Three samples per case; approximate end-to-end first write/verification times: 5 actors 8.1 ms, 10 actors 18.7 ms, 50 actors 240 ms, 100 actors 638 ms. Light client verification approximately 1.36 ms; one-subject/one-entry response 5,574 canonical bytes. Verification of a 1,024-leaf inclusion uses ten sibling hashes (320 raw bytes). Sequential writes in this short, tiny-log, in-memory run: about 70/s. These numbers include repeated JSON/X.509 checking and are not a scalable database or network throughput claim.

No safety theorem for the Go binary is claimed. TLC checks the abstraction described in formal/README.md; runtime tests separately exercise cryptography, proofs, durable locks, HTTP, lifecycle and client rejection paths.
