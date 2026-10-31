# HIA: independently proved finite optimization with native NDU

This document describes the candidate-ranking bridge. The integrated tree also
retains a separate recursive-utility bridge; see [the two bridge contracts](HIA_NDU_BRIDGES.md)
for their distinct builders, environments, receipts and source pins.

This increment connects the existing HIA Core to the original Rust NDU
evaluator. It does not make NDU a verifier or turn the six research goals into
closed production claims. The executable authority remains `verify_program`;
frontends, interpretation and direct LLVM emission continue to consume that
same canonical program.

The branch starts from Hepta `3db07aa877ab1a5fc00560d7037e6efbc884fc1f`
(the convergence candidate in #323). The NDU bridge uses exact source bytes
from `hepta-private-ci` commit
`d3c2d760eca5065fc966820379c35c6e8d56e855`, without changing that repository
or its production authority. Historical qualification on another Hepta SHA
does not qualify these new files.

## Admission and authority

1. A frontend produces canonical HIA. The normal verifier checks closed SSA,
   types, ownership, loans and effects. An optimizer cannot replace this step
   with a `safe`, `proved` or `ok` input field.
2. `hia_finite_actions.propose_candidates` produces a bounded deterministic
   list. It offers wrapping identities, constant folding, reassociation and
   removal of dead **total** scalar operations. Checked operations cannot be
   discarded merely because their values are unused: their traps are observable.
3. `hia_ndu_optimizer.rank_candidates` rechecks each candidate and preserves
   every unselected function and the rest of the module byte-for-byte after
   canonicalization. The selected public function needs a fresh
   `hia_translation_validation` proof of return values and first trap code for
   every scalar input. Calls, loops, resources and unsupported operations produce
   `unknown`; a syntactically legal proposal with a counterexample is rejected.
4. The original native
   `codex_hepta_ndu::evaluate_candidates_with_policy` sees finite alternatives,
   hard violations, conservative costs and a mandatory `abstain` incumbent.
   Its recommendation is advisory. Neither a score nor a serialized SMT receipt
   authorizes execution.
5. A selected proposal needs another fresh proof on the same immutable program
   pair, and must still pass the measured-cost gate after the native evaluator
   and that proof finish. Failure retains the incumbent.
6. Native publication independently rechecks all exports, the entire supported
   ABI, proofs, exact LLVM/artifact identities, actual ELF metadata and finite
   interpreter/native probes. Linux sealed descriptors retain executable bytes
   across leases. Background publication also checks generation and selection
   epoch to prevent stale work and rollback ABA.

The proof encoder, canonical verifier, solver, assembler/compiler, loader,
trusted Python process and host are part of the trusted computing base. There
is no whole-compiler refinement theorem. In particular, an SMT proof of an HIA
transformation is not a proof that every native compiler instruction is correct.

## Cost, uncertainty and abstention

An observation identifies the exact canonical program and supplies integer
nanoseconds per call, an absolute uncertainty radius, and already incurred
search cost. Search cost includes generation, compilation, proof and measurement
performed by the producer. The adapter charges every observation's search cost
once, including losing proposals and baseline measurement, then adds its own
actual wall time. CLI proposal regeneration is also measured and explicitly
charged. There is no free search or free rejected candidate.

For expected reuse count `N`, the comparison is:

```text
incumbent lower cost = N * max(0, incumbent runtime - incumbent uncertainty)
candidate upper cost = N * (candidate runtime + candidate uncertainty)
                       + all already incurred search cost
                       + actual adapter time
```

Only a strict positive difference can be admitted. Background native proof,
compilation, loading and preparation must fit the remaining margin **before**
the generation pointer changes. This is an explicit finite horizon, not an
infinite amortization assumption. Queue delay and post-publication reporting are
reported separately; a pre-publication gate cannot know future reporting time.

The original NDU uncertainty axis is digest-bound but does not itself adjust
Pareto ranking. This adapter therefore applies uncertainty in the costs before
calling NDU. Conversion from integer ns to signed Q32.32 milliseconds uses exact
integer arithmetic, round-to-nearest/ties-to-even and overflow rejection; it
never clips a costly proposal into feasibility.

`resource_cap_ns` is an **admission threshold for recorded search expenditure**,
not a preemptive operating-system CPU quota. Solver and child-process deadlines
bound their respective operations, but a decision may discover that its budget
has already been exceeded. Such a result cannot publish a candidate. These
search limits do not prove heap or execution bounds for arbitrary HIA programs.

The ranker now checks the remaining budget before starting the native evaluator
as well as before each proof. A zero or exhausted allowance returns an explicit
incumbent decision with `native_response: null` and a false
`native_rank_admission.invoked` flag. That response is not represented as a
native evaluation. When there is budget, executable identity admission and
sealing reduce the allowance passed to the bounded process runner. Its execution
timer starts after ownership checks and `Popen`, so startup and OS scheduling
can still overrun that allowance. They remain charged by the final cost gate;
this is not a hard whole-call wall-clock deadline. The subsequent fresh proof
and final cost gate remain required.
Background cancellation and preparation failures keep their paid-work records
as described in [HIA_BACKGROUND_OPTIMIZER.md](HIA_BACKGROUND_OPTIMIZER.md).

Measurements are trusted-host observations. Program hashes prevent accidental
cross-program reuse; they do not attest that a supplied measurement is truthful.
The actual native experiment retains raw samples, artifacts, costs, protocol
and source hashes. Its maximum-deviation radius describes the observed sample
envelope; it is not a confidence interval for future workloads.

## Build the actual NDU evaluator

Install the repository's pinned Rust toolchain and the optional verification
dependency (`python -m pip install '.[verification]'`). Native qualification
requires actual Clang 20+, Linux x86-64 and the documented C/C++ toolchains.

Keep an upstream Git checkout containing the pinned commit, then run:

```sh
python tools/build_hia_ndu_bridge.py \
  --upstream /path/to/hepta-private-ci \
  --output /new/path/to/isolated-ndu-build
```

The output directory must be new. The builder uses `git archive` of the exact
object; it does not use mutable upstream working-tree bytes. Original Rust
sources and embedded fixtures from `hepta-ndu`, `hepta-contracts` and
`hepta-types` are preserved. Only production dependency manifests are adapted
into a small workspace; upstream tests, development-only dependencies and
unrelated Codex crates are not represented as qualified.

The isolated `Cargo.lock` is committed under `rust/hia-ndu-bridge/`, and every
qualified build requires `--locked`. The receipt inventories all original
non-manifest bytes, adapter files, generated manifests, the lock, actual binary,
builder, selected Rust/Cargo versions and relevant build flags. These inputs
are read again after compilation. This includes fixtures referenced by
`include_str!`, not only `src/` files.

The Python consumer rejects a receipt for another upstream pin, adapter, lock,
builder or binary. The bridge additionally hashes the exact raw request. NDU's
semantic evaluation digest is preserved separately; semantic digests can remain
unchanged when irrelevant/rejected raw payloads differ.

## Agent-facing entrypoints

Both commands join the existing `hepta hia` command tree and bounded input
loaders:

```sh
python -m hepta hia verify-translation before.json after.json \
  --function calculate --timeout-ms 2000 --json

python -m hepta hia optimize before.json --function calculate \
  --bridge /path/to/hia-ndu-bridge \
  --bridge-build-receipt /path/to/build-receipt.json \
  --observations observations.json --objective objective.json \
  --max-candidates 8 --json
```

Translation validation returns nonzero for `disproved` or `unknown`. An
optimization decision that safely abstains returns zero; malformed inputs or
an unbound bridge fail. The optimize command returns a decision and canonical
selected program. It does not publish native code.

Programmatic input shapes are intentionally small:

```python
objective = {
    "expected_calls": 1_000_000,
    "resource_cap_ns": 5_000_000_000,
    "target": "x86_64-unknown-linux-gnu",
    "measurement_profile": "name-of-frozen-native-protocol",
}
observations = {
    "abstain": {
        "program_sha256": "exact-canonical-program-sha256",
        "runtime_ns": 12,
        "uncertainty_ns": 2,
        "search_ns": 123456,
    },
    # Every generated candidate id has the same four fields.
}
```

The numbers above illustrate the schema and are not measurements. Booleans are
not accepted as integer counts. Candidate generation is bounded to eight recipe
proposals; the ranking API permits at most 32 explicitly provided proposals.
All selected program/input hashes, objective, generation, exact observations,
request, native response, proof results and cost accounting are retained.

## Resource and migration increment

The Rust `--owned-run` oracle now accepts the declared byte-owner CFG profile:
branches, loops, internal scalar/resource calls, Owner transfers/returns and
call-scoped loans. All frames share allocation-failure injection and the same
step/live-byte ledger, with at most 32 live call frames. Public entrypoints and
returns remain scalar. Escaping/returned loans, chain/bulk operations and nominal
composite input are not silently accepted.

Actual C and C++ project migration qualification retains separate denominators
for original native execution, translated HIA native execution and the bounded
Python/Rust interpreter comparison. The latter consumes the exact canonical
Core produced by the real translators. No hand-reconstructed replacement
program stands in for a frontend. These profiles do not establish arbitrary
C++ template/library rewriting, a stable universal C++ ABI or external lifetime
correctness across every FFI boundary.

## Experiments and closure

`tools/qualify_hia_ndu_search.py` freezes workloads, candidate limits, seeds,
training/holdout trial counts, budget and reuse horizon before compiling or
measuring. A native C loop driver executes the actual shared libraries. Fixed,
seeded-random, simple measured enumeration and NDU policies receive the same
candidate/observation table, with their actual policy overhead retained. This is
a paired replay experiment; it does not claim online learning.

The initial real campaign is a useful negative control: LLVM may canonicalize
all proposed HIA rewrites to identical machine code. Equal code and noisy timing
must not be reported as an exclusive NDU speedup. All samples and all failed
criteria remain in the evidence. Improving the experiment's uncertainty
definition creates a newly versioned protocol and a fresh run; it does not
rewrite the earlier result.

| Workstream | Executable increment | Gate still open |
| --- | --- | --- |
| Shared semantics | Existing canonical Core, actual producer/CLI/native consumers, optimization commands | Whole-language and backend refinement |
| Resources/Rust | Bounded CFG byte-owner oracle, call/return ownership, failure and budget parity | Escaping loans, general composite/async resource runtime |
| Behavioral validation | All-input scalar acyclic bitvector/trap translation checks; unknown rejects | Calls, loops, heap transformations, concurrency |
| NDU | Actual pinned Rust evaluator, bounded recipes, robust cost/abstain gate, equal-budget experiment | Reproducible incremental value over strong simple policies |
| C/C++ and ABI | Exact migrated Core through Python/Rust/native, actual local native executions | Arbitrary projects/libraries, other actual OS/CPU targets |
| Reoptimization | Sealed generations, leases, stale/cancel/preparation gates, finite background worker and offline x86 search | Measured net gain, stateful migration, broad instruction search |

The integrated collector runs against one committed source inventory and keeps
every gate outcome. A passing **bounded mechanism** result never changes the
six-stage closure or scientific-advantage flags to true.

```sh
python tools/qualify_hia_ndu_pipeline.py \
  --output-directory /new/path/to/evidence --clang /path/to/clang \
  --bridge /path/to/hia-ndu-bridge \
  --bridge-build-receipt /path/to/build-receipt.json \
  --upstream /path/to/hepta-private-ci
```

The upstream checkout is needed to independently compare the archived Git bytes
with the actual build inputs. `--full-regression` additionally runs the complete
existing Python suite; skipped or empty test runs do not qualify.

See `HIA_TRANSLATION_VALIDATION.md`, `HIA_NDU_SEARCH.md`, `HIA_MULTIVERSION.md`,
`HIA_BACKGROUND_OPTIMIZER.md`, `HIA_X86_SEARCH.md` and the retained qualification
record for their exact profiles and source identities.
