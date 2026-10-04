# Quorum PKI laboratory

Executable research PoC of a quorum-based X.509 acceptance overlay. Go standard library only, no cgo or Go modules downloaded. The same cryptographic/state engine runs as independent native HTTP services and as a Go WebAssembly browser Worker.

**Delivery status: runnable v0.1, not the complete target federation.** Quorum authorization, notarized current-state/log proofs, rotation, revocation, recovery, adversarial scenarios, native processes, WASM, strict schemas, OpenAPI and a checked bounded TLA+ model are implemented. Hot governance transitions and a full leader-changing BFT consensus are not. The gaps below are substantive; the specification distinguishes implemented behavior from proposed extensions.

## Run the interactive lab

Requires Go 1.25+ (or Docker Compose).

```sh
make wasm
make demo
# Open http://localhost:8080
```

Or:

```sh
docker compose up --build
```

Compose's default launches the interactive simulator. Open `http://localhost:8080`, issue `example.com`, rotate, advance the virtual clock, revoke or trigger forged requests. The native mode uses goroutines/SSE; the browser mode uses Go WASM in a Worker. Select the mode in the first control. Both modes simulate independent actors in one machine; they do not establish independent organizational trust.

To see forged authorization blocked, reset with `ca-1` or `ca-1,ca-2` in the malicious field, then propose a fake key. Reset with `ca-1,ca-2,ca-3` to demonstrate authorization-threshold compromise. The UI distinguishes 3 approvals from 4 finality signatures. Run “Run attack scenarios” to exercise all thirteen isolated cases. It includes fork evidence after sufficient finality keys are stolen, rather than pretending a signed fork is possible within the honest-intersection assumptions.

The included WASM binary was executed in Node's Worker runtime against all scenarios. The interface is in English, with a protocol walkthrough and an unrounded, monochrome layout. Browser visual verification was blocked by the control browser refusing localhost (`ERR_BLOCKED_BY_CLIENT`); no visual QA success is claimed.

## Run genuinely separate processes

```sh
make build
GO=go scripts/network-demo.sh --check
# omit --check to leave the processes running
```

This starts five independent CA processes (ports 8101–8105), registry (8081), witness (8082) and coordinator (8083). It creates random local keys, submits a signed request, verifies a compact bundle and has the witness observe the checkpoint. The script reports its temporary state directory. The independent-service coordinator exposes the signed API/SSE; the simulator's unsigned UI convenience buttons are not its signed request client.

For persistent container processes:

```sh
docker compose -f docker-compose.network.yml up --build
# Copy fixture state for the local CLI if desired:
docker compose -f docker-compose.network.yml cp coordinator:/data ./data
make build
bin/request -data data -url http://localhost:8083
bin/verifier -config data/config.json -url http://localhost:8081
bin/request -data data -url http://localhost:8083 -event rotate
```

Bootstrap preserves and verifies an existing matching configuration, and refuses to overwrite inconsistent keys or URLs. It is not a key-reset tool. The local script always creates a fresh isolated universe. No Docker executable was available in the execution environment, so Compose/image construction is supplied but not executed; native HTTP launch was actually tested. The containers share a development state volume, which is not production key isolation.

## Verify and reproduce

```sh
make test
make vet
make scenarios
make wasm-test
node scripts/ui-review.cjs
make cross
make bench
make formal TLC_JAR=/absolute/path/tla2tools.jar
python3 scripts/validate-schemas.py
```

Go application builds use `CGO_ENABLED=0`. `make cross` targets Windows amd64, macOS arm64 and Linux arm64; builds are cross-checked, not runtime-certified on those OSes. The race detector itself requires cgo/toolchain support and is a separate development check.

`cmd/request` is a signed CLI proposer using the owner/recovery fixture keys; `cmd/verifier` pins local Config and retains a durable checkpoint. An advertised `/v1/config` is not itself a trusted bootstrap channel. The verifier demonstrates authorization checking, not a browser TLS handshake. Checkpoint maximum age defaults to five minutes; use `bin/request -event heartbeat` or the UI refresh action to obtain a quorum-authenticated new checkpoint without extending key validity. Automatic heartbeat scheduling is not supplied.

## Architecture

- `internal/protocol`: typed formats, restricted JCS, detached JWS-style Ed25519 signatures, pinned member/policy checks.
- `internal/merkle`: RFC 9162 domain-separated tree hashes, O(log N) inclusion and consistency paths.
- `internal/engine`: X.509 verification, subject state replay, bounded two-key rotation, current-state root, durable finality locks, light client and witnesses.
- `internal/service`: HTTP transport, separate validator/registry/witness handlers, signed compare-and-append, SSE.
- `internal/simulation`: deterministic keys/fault selection, optional wall-clock delay, goroutine transport, virtual lifecycle clock and scenarios.
- `cmd/demo`, `cmd/wasm`: shared engine with native/SSE or Worker adapters.
- `cmd/node`: independent roles selected by `-role`; no artificial duplicate executables for the same launcher.
- `cmd/request`, `cmd/verifier`: signed native request and lightweight client.
- `schemas`, `api`, `spec`, `formal`, `results`: wire contracts, API, normative experimental specification, formal models and captured verification.

## Security contract

The default is approval **3-of-5** and finality **4-of-5**, with at most one Byzantine operator for the combined contract. A false binding requires compromising the approval threshold or the honest validation oracle. Unique finality requires `2q > m+f` and persistent honest locks. With seven validators, approval/finality 5-of-7 and `f=2` is supported. Merely collecting 3-of-5 signatures cannot by itself prevent signed conflicting histories.

The client verifies genuine independent-operator Ed25519 approvals and X.509 chains, a finality quorum, log inclusion, current-state inclusion, consistency, freshness and its own rollback watermark. The state proof is essential: historical inclusion alone does not establish that a key remains authorized.

The implementation is a fixed-sequencer notarization protocol. It preserves conditional safety but may permanently stall after incompatible partial locks. It has no PBFT-style rounds/view changes or availability theorem. A false-binding scenario with three malicious approval operators violates the approval assumption even if honest notarizers can still enforce log consistency.

## Captured results

- Unit/integration/scenario tests pass; native process launch produces a finalized and client-verified binding and witness observation.
- 13 native adversarial scenarios and 13 actual Go WASM scenarios pass.
- TLA+ bounded behavioral model: 673,206 distinct states, all seven invariants pass. Unsafe 2-of-3 finality produces the expected UniqueFinality counterexample.
- Exhaustive quorum-intersection checks pass for 4-of-5 with one Byzantine and 5-of-7 with two.
- Merkle proofs are tested across every index and old size for tree sizes 1–128, including tamper/extra-node rejection.
- Benchmarks and environment facts are in `results/benchmarks.txt`; short runs are measurements, not capacity guarantees.

## Important unfinished scope

1. Dynamic epoch/member admission/removal is designed in `spec/governance.md`, not executable.
2. Complete BFT leader recovery and safe resolution of conflicting partial votes are not implemented.
3. Domain control is a signed owner-key fixture, not an ACME deployment or independent Internet-vantage validation.
4. No browser extension/TLS stapling, live domain TLS test, automatic witness gossip/cosigning or sparse non-membership proof.
5. Heartbeat refresh is explicit, not automatically scheduled; freshness fails closed if refresh cannot finalize. Full-history validator replay and JSON snapshot persistence are deliberately unoptimized.
6. Reproducible seeds/fault choices/roots are implemented; exact deterministic concurrent scheduling replay is not.

See `spec/protocol.md` for the implemented normative behavior, `spec/threat-model.md` for assumptions, `formal/README.md` for exact abstraction limits and `spec/security-considerations.md` for comparisons and bootstrapping/governance risks. This is not trustless and is not production-ready.

## Interface review / English edition

The page now explains the two quorums, key lifecycle, authenticated state and trust assumptions in English. Styling is monochrome with square controls and rule-separated sections. Review fixes isolate scenario streams from the active registry, deduplicate SSE replay, clear counters/proofs on reset and runtime changes, reject unavailable WASM without silently using the native backend, and unlock controls after errors. Node DOM behavior checks and Go/WASM tests pass; this does not replace browser visual QA.
