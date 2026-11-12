# Native lifecycle convergence and measured no-change profile

This finite integration uses the existing `ScalarMultiversionRuntime` and
`ScalarStateSession`. There is one native publication state machine. Python
Canonical Core remains the execution authority; timing evidence grants no Core
authority and does not qualify a new language version.

## Admission boundary

The live scalar lifecycle and guarded-specialization proposal entry points now
explicitly admit primitive HIA v1–v7 only, matching their independent translation
validator. Even a pure scalar v8 program is refused by those two entry points.
Canonical Core and direct LLVM retain v8 support. A v8 scalar add still executes
to 12 for inputs 7 and 5, while the independent scalar translation validator
reports `unknown`. Before this change, that v8 program could start a native
scalar baseline and produce a specialization proposal, although publication
already failed because its independent proof was unknown. This was an
inconsistent finite-profile boundary, not a demonstrated semantic miscompile or
proof bypass.

A version allowlist alone is insufficient. The lifecycle checks every function
for its closed total scalar operation, type, export, effect and acyclic control
flow profile. Byte owners, recursive chains, internal calls, checked traps and
resource effects remain outside this live in-process profile, including in v7.
The specialization proposer checks the selected scalar function and may preserve
an unrelated resource helper unchanged; that does not qualify the whole module
for native lifecycle publication. Tests cover both boundaries independently.

`ScalarStateSession` carries one host-owned scalar across code publication and
rollback, with revision comparison, one-use cancellation and generation leases.
This is not heap, loan or stack migration, persistence, crash recovery or a
resource-program runtime. Public native wrappers remain scalar C functions.

## Measurement at the existing publication point

`publish_if_current(..., measurement=...)` adds an optional finite measurement
profile to the existing conditional publication method. Omitting it retains the
previous explicit host-observation/manual lifecycle contract; existing NDU jobs
are not silently upgraded to measured eligibility. A caller using the new
profile supplies the exact `hepta.hia.native-publication-measurement.v1` envelope:

| Field | Meaning and finite bound |
| --- | --- |
| `before_sha256`, `after_sha256` | Canonical Core SHA-256 values |
| `before_artifact_sha256`, `after_artifact_sha256` | SHA-256 of the actual native bytes being compared |
| `workload_sha256` | Digest of the declared fixed workload; the host supplies its meaning |
| `function` | One existing exported scalar function, at most 256 characters |
| `calls_per_sample` | Exact integer, 1–64,000,000 |
| `horizon_calls` | Exact integer, 1–1,000,000,000,000; a workload assumption |
| `search_cost_ns` | Observed pre-entry experiment cost, 0–3,600,000,000,000 ns |
| `maximum_search_ns` | Predeclared total policy budget, 1–3,600,000,000,000 ns |
| `samples` | Odd 15–63 pairs, each exactly `baseline_ns` and `candidate_ns`, positive integer ns up to 60,000,000,000 |

The schema field is mandatory. Unknown keys, booleans/floats in integer fields,
malformed digests, missing fields and out-of-range values are refused. The
envelope is copied into detached ordinary Python containers. This capture is not
an independently attested measurement or a transactional snapshot of a
concurrently mutated caller object.

The fixed `paired-native-artifact-cost-v1` policy refuses identical native
artifacts; either side's median absolute deviation above 5% of its median;
paired median savings below 2% of baseline median; or paired savings at or below
three times the median absolute deviation of paired savings. Every supplied pair
is retained, with no trimming or adaptive retries. These rules are conservative
admission rules, not a statistical confidence proof.

The projected candidate cost includes the declared experiment cost, actual
preparation time at the existing gate, and a separately labelled fixed
2,000,000,000 ns decision reserve. The reserve is not reported as observed
spending. Publication also requires the projected horizon to recover all of
that charged cost and remain within the declared search budget. Projected totals
are bounded at 10^18 ns. The horizon is a host workload assumption, not a promise
of future demand. Earlier preparation handoff timestamps cannot be combined
with this envelope, avoiding ambiguous accounting of pre-entry cost.

The new policy can only add refusal. The gate still checks current generation
and epoch, ABI, cancellation and live-generation budget; independently proves
the exact candidate against the immutable baseline; performs a fresh actual
native build and probes; and rechecks both native artifact identities and the
cost policy immediately before the existing selection assignment. A forged
candidate artifact digest is refused after actual preparation, and its
unselected native generation is disposed. Wrong behavior remains rejected by
the proof even if supplied timing samples appear advantageous.

This selectively integrates the identity/noise policy from PR #333 into the
current lifecycle. Its separate resource-program child dispatcher and third
NDU transport are not introduced. Existing ranking and recursive NDU bridge
pins and authority limits remain unchanged. Historical abstain/no-change or
negative performance results are not converted into success on a new source
commit.

## Reproducible finite experiment

After committing a clean combined source tree:

```sh
python tools/qualify_hia_native_lifecycle_convergence.py \
  --expected-head EXACT_CLEAN_COMMIT \
  --output-directory NEW_OUTPUT_DIRECTORY \
  --clang /absolute/path/to/clang \
  --rustc /absolute/path/to/rustc
```

The CLI requires the exact clean commit before and after execution. The Python
`run` entry also permits an explicitly unqualified development replay with no
expected commit; its report retains the dirty status and cannot be presented as
a clean release result. The output directory must be new.

Before compiling, the qualifier writes `protocol.json`, declaring all state
inputs, code transitions, workload, sample order, costs, horizon and controls.
Actual C, Rust and direct-LLVM native functions each process the same 12 state
transitions, including u64 wrapping edges. There are two independently proved
native publications, code rollback, cancellation-before-call, stale revision,
and one call through a retained retired-generation lease. The runtime is closed
and the retained lease released; the final generation inventory must be empty.

The measurement driver makes 31 alternating pairs of 50,000 calls per side:
3,100,000 actual native timing calls. A fixed eight-input workload and an
independent arithmetic checksum validate every pair. Automatic preparation probe
calls, the 36 cross-language state calls and the one retired-lease call have
separate denominators. Actual completed preparations include the candidate
later refused for a forged artifact identity.

The selected equivalent transformation commutes an integer addition. The
qualifier requires its actual compiled bytes to be identical to the baseline.
Its intended real outcome is therefore **no change**, regardless of timing
noise. No retry seeks a faster result. Additional noisy, no-net-gain, stale
source, forged artifact and wrong-semantics cases are explicit synthetic policy
controls, not measured performance evidence. A separate test exercises actual
proof, compilation, publication and calls for a byte-distinct specialization
with deliberately synthetic eligible timing samples; that is a publication
path test, not a speed claim.

Retained evidence includes source/tool digests, exact C/Rust and LLVM inputs,
actual compiler command arguments and outputs, fresh artifact hashes, copied
executed native bytes, state traces, all raw timing pairs, refusals and final
generation inventory. Observers call the existing compiler/preparation methods
and preserve their actual results; they do not supply fake receipts or compiled
outputs. The ordinary compiler receipt remains `native_compiled_not_executed`;
execution evidence belongs to this separate qualifier.

## Limits and failure history

This profile runs on the current Linux x86-64 host. Existing AArch64/RV64 v8
qualifiers execute through QEMU; they are not physical-device evidence and this
scalar lifecycle experiment does not extend their ABI. Resource accounting in
other native qualifiers remains distinct from interpreter-only loan counters.

The first development run of the new eight-method test module had seven passes
and one error: the qualifier passed a mutable document to the LLVM emitter,
which requires a verified immutable program. The qualifier now obtains that
program through `verify_program`; the emitter's guard was preserved. Subsequent
results must be reported with their actual source identity and retained logs.
No complete Rust safety equivalence, general performance superiority, physical
device qualification or complete P0–P7 closure follows from this finite profile.
