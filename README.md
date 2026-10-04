<img src=".project/image.png" alt="Quorum PKI logo" width="96" height="96">

# Quorum PKI

**An experimental quorum-based acceptance overlay for X.509 certificates.**

[![CI and GitHub Pages](https://github.com/sachahjkl/quorum-pki/actions/workflows/pages.yml/badge.svg)](https://github.com/sachahjkl/quorum-pki/actions/workflows/pages.yml)

[Interactive laboratory](https://sachahjkl.github.io/quorum-pki/) · [Protocol specification](spec/protocol.md) · [Threat model](spec/threat-model.md) · [OpenAPI](api/openapi.yaml) · [Formal model](formal/README.md)

## Abstract

Quorum PKI explores a client-enforced policy in which a domain–public-key binding requires approval from several independently governed certificate authorities. An approval quorum authorizes a binding; a separate finality quorum notarizes an ordered log and its derived current state. A client verifies operator signatures, X.509 chains, Merkle proofs, checkpoint freshness and consistency with its previously accepted checkpoint before accepting a key.

The repository provides an executable Go reference implementation, a browser WebAssembly laboratory, strict wire schemas and bounded TLA+ models. The goal is to make the protocol's assumptions and failure modes reviewable through both specification and reproducible experiments.

## Status and scope

| Item | Status |
|---|---|
| Protocol | Experimental version 1 |
| Implementation | Research proof of concept, revision 0.1 |
| Standards status | Not an IETF RFC or Internet-Draft |
| Dependencies | Go standard library; no cgo or third-party Go modules |
| License | [MIT](LICENSE) |

Implemented features include quorum authorization, signed checkpoints, log and current-state proofs, key rotation, revocation, subject recovery, native HTTP services and a Go WASM worker. The implementation uses a fixed sequencer and durable notarization locks. It does not provide complete view-changing BFT consensus or hot membership transitions.

Existing browsers do not enforce this overlay. The CLI verifies authorization artifacts; TLS integration and proof of possession remain the caller's responsibility. This is a research implementation, not a production PKI deployment.

## Protocol overview

1. **Propose.** An owner submits a signed state transition for a domain and public key. Recovery uses a separately pinned credential.
2. **Approve.** Operators validate the request independently and sign the same proposal. Key-bearing approvals include X.509 certificates for the same subject and SPKI.
3. **Finalize.** Validators verify the ordered history and derived state, persist voting locks, and sign a checkpoint committing to both Merkle roots.
4. **Verify.** A client checks the finality certificate, approvals, certificate chains, log inclusion, current-state inclusion, freshness and consistency with its saved checkpoint.

The log proves that an event occurred. The state commitment identifies the currently authorized key schedule. Historical inclusion alone does not establish that a key remains valid after rotation or revocation.

### Two quorums, two guarantees

Let `m` be the number of operators, `a` the approval threshold, `q` the finality threshold and `f` the assumed Byzantine fault budget. The configuration requires `a > f` and `2q > m + f`.

| Configuration | Approval | Finality | Combined fault budget |
|---|---:|---:|---:|
| Default: 5 operators | 3-of-5 | 4-of-5 | At most 1 Byzantine operator |
| Alternative: 7 operators | 5-of-7 | 5-of-7 | At most 2 Byzantine operators |

Approval protects against unauthorized bindings under honest validation assumptions. Finality relies on honest quorum intersection and persistent locks to prevent conflicting finalized histories. Three approval signatures in the default configuration do not, by themselves, establish finality.

These guarantees assume an independently authenticated, pinned configuration; genuinely independent operators; correct domain validation; uncompromised cryptographic keys; durable locks and client checkpoints; and a trustworthy local clock. Organizational independence is a governance assumption, not a cryptographic result.

### Lifecycle and availability

Rotation permits a bounded overlap during which the old and new keys are accepted. Revocation disables the binding. Recovery replaces it through a separate credential and the ordinary quorums. Explicit heartbeats refresh checkpoint freshness without extending certificate or key validity.

The CLI's default maximum checkpoint age is five minutes. If refresh cannot finalize, acceptance eventually fails closed. Conflicting or lost partial finality votes can stall the protocol indefinitely; no leader-change mechanism or availability theorem is supplied.

## Try the laboratory

Open the [hosted laboratory](https://sachahjkl.github.io/quorum-pki/). It runs the Go engine locally in a WebAssembly worker and requires no native API server.

For a local instance, install **Go 1.25+** and `make`:

```sh
make wasm
make demo
# Open http://localhost:8080
```

Alternatively, use Docker Compose:

```sh
docker compose up --build
```

The local interface supports native Go/SSE and WASM worker modes. Both simulate multiple actors on one machine; they do not establish independent organizational trust.

Suggested walkthrough:

1. Issue `example.com` and inspect approvals, finality signatures and the client proof.
2. Schedule rotation and advance the virtual clock through activation, overlap and retirement.
3. Revoke the binding, then recover it.
4. Reset with `ca-1` or `ca-1,ca-2` marked malicious and propose a false key: authorization is blocked.
5. Reset with `ca-1,ca-2,ca-3` marked malicious: the approval threshold is compromised.
6. Run the thirteen isolated attack scenarios. A passing scenario means the observed outcome matches its stated assumptions, including expected success after threshold compromise.

Reset creates a fresh simulation. It is not an in-protocol federation recovery procedure.

## Run independent services

On a POSIX shell:

```sh
make build
GO=go scripts/network-demo.sh --check
# Omit --check to leave the processes running.
```

The script starts five CA processes on ports 8101–8105, a registry on 8081, a witness on 8082 and a coordinator on 8083. It creates fresh local keys, submits a signed request, verifies a compact bundle and records a witness observation. It reports its temporary state directory.

For persistent container processes:

```sh
docker compose -f docker-compose.network.yml up --build
docker compose -f docker-compose.network.yml cp coordinator:/data ./data
make build
bin/request -data data -url http://localhost:8083
bin/verifier -config data/config.json -url http://localhost:8081
bin/request -data data -url http://localhost:8083 -event rotate
```

Bootstrap preserves and verifies an existing matching configuration and refuses inconsistent keys or URLs. The containers share a development state volume; this is not production key isolation. The independent coordinator accepts signed requests, while simulator UI endpoints are demonstration conveniences.

## Specification and repository map

| Path | Purpose |
|---|---|
| [spec/protocol.md](spec/protocol.md) | Implemented protocol, serialization, acceptance rules and normative requirements |
| [spec/threat-model.md](spec/threat-model.md) | Adversary capabilities, trust assumptions and claimed properties |
| [spec/security-considerations.md](spec/security-considerations.md) | Deployment risks, bootstrapping and comparisons |
| [spec/governance.md](spec/governance.md) | Proposed membership and epoch transitions; not implemented |
| [spec/references.md](spec/references.md) | Standards provenance, exact reuse and deliberate exclusions |
| [schemas/](schemas/) | JSON Schema Draft 2020-12 wire contracts |
| [api/openapi.yaml](api/openapi.yaml) | Native HTTP API |
| [internal/protocol/](internal/protocol/) | Types, restricted JCS profile, detached signatures and policy checks |
| [internal/merkle/](internal/merkle/) | RFC 9162-style log hashing, inclusion and consistency proofs |
| [internal/engine/](internal/engine/) | X.509 validation, state replay, finality locks, clients and witnesses |
| [internal/service/](internal/service/) | Independent HTTP services and signed compare-and-append |
| [internal/simulation/](internal/simulation/) | Fault injection, virtual clock and adversarial scenarios |
| [cmd/](cmd/) | Demo, WASM adapter, service launcher, proposer and verifier |
| [web/](web/) | Browser laboratory and worker assets |
| [formal/](formal/) | Bounded TLA+ models and reproduction instructions |
| [results/](results/) | Captured verification outputs, fixtures and benchmarks |

The protocol uses SHA-256, Ed25519, a restricted RFC 8785 canonical JSON profile and detached JWS-style signatures. Merkle algorithms reuse RFC 9162 §2.1. These choices do not imply full JOSE, Certificate Transparency, ACME or browser-policy compatibility; [references](spec/references.md) describe the exact scope.

## Verification and evidence

Go and Node.js are required for the core checks:

```sh
make test
make vet
make scenarios
make wasm-test
node scripts/ui-review.cjs
```

Additional reproduction commands:

```sh
make cross
make bench
make formal TLC_JAR=/absolute/path/tla2tools.jar
python3 scripts/validate-schemas.py
```

Formal checking requires Java 17+ and the TLA+ tools jar; see [formal/README.md](formal/README.md) for configurations and the expected unsafe counterexample. Schema-validation requirements are documented in the [validation script](scripts/validate-schemas.py). Go application builds use `CGO_ENABLED=0`; race detection requires separate cgo/toolchain support.

Captured evidence includes:

- Thirteen native and thirteen actual Go WASM adversarial scenarios.
- Native independent-service execution with a finalized, client-verified binding and witness observation.
- Merkle proof checks across every index and prior size for trees of size 1–128, including tampered and extra-node rejection.
- A bounded behavioral TLA+ run with 673,206 distinct states and all seven modeled invariants satisfied. Unsafe 2-of-3 finality produces the expected `UniqueFinality` counterexample.
- Exhaustive quorum-intersection checks for 4-of-5 with one Byzantine and 5-of-7 with two.
- Cross-build outputs and environment-specific benchmarks in [results/](results/).

The behavioral model abstracts checkpoint slots by subject generation; it does not prove the concrete implementation or unbounded histories. It supplies no liveness theorem. Cross-builds are not runtime certification, benchmarks are not capacity guarantees, and Node DOM checks do not replace browser visual testing. Docker construction was not exercised in the original captured verification environment.

Native persistence tests currently encounter directory-sync access errors on Windows. The CI verification environment is Ubuntu; application cross-build support is distinct from native test coverage.

## Open issues for protocol review

The following questions define the next research work:

1. **Finality recovery:** how should a federation safely resolve incompatible partial locks and replace a failed sequencer without weakening finalized-history safety?
2. **Membership governance:** how should independent operators be admitted, removed and replaced across authenticated epochs? A proposed design exists, but hot transitions are not executable.
3. **Domain validation:** how should independent Internet-vantage checks or ACME adapters replace the signed owner-key fixture?
4. **Client integration:** how should TLS possession checks, proof delivery, configuration distribution and durable client checkpoints fit browser and service deployments?
5. **Witness operation:** what gossip, observation and cosigning policy would provide useful detection guarantees under partitions?
6. **Freshness and scale:** how should automatic heartbeats, incremental replay, storage and authenticated non-membership proofs be designed and evaluated?

Other current limits include full-history validator replay, JSON snapshot persistence, static membership and no exact deterministic replay of concurrent scheduling. Recovery after federation quorum-key compromise requires an authenticated out-of-band trust reset, not authorization by the compromised quorum.

## GitHub Pages deployment

Select **Settings → Pages → Source → GitHub Actions**. The [CI and GitHub Pages workflow](.github/workflows/pages.yml) verifies Go tests, static checks, WASM scenarios and UI behavior, then builds the static site. Pushes to `master` or `main` trigger the workflow; only the repository's default branch deploys. Pull requests run verification and build the artifact. Manual execution is available from the Actions tab.

The deployed copy exposes only the WASM runtime. Relative asset URLs support hosting under `/quorum-pki/`. The deployment URL is recorded in the `github-pages` environment.

## Contributing to the review

Use [issues](https://github.com/sachahjkl/quorum-pki/issues) for protocol questions, counterexamples and reproducible implementation defects. Cite the relevant specification section, state the assumed fault model, and distinguish safety, availability and deployment concerns. For a counterexample, include the configuration, action sequence and observed verification result.

Pull requests should identify whether they change the implemented protocol, its documentation or a proposed extension, and provide verification appropriate to the affected guarantee.
