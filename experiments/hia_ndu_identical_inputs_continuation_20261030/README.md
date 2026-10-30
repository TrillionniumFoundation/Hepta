# Prospective identical-input native NDU study

This is a new study. It does not replace the earlier registered NDU result or
the earlier negative application-level optimization studies.

The original NDU implementation remains pinned to
`c4a1bbed3a39beba43a6abf1a18b6f75c5725c21`. Two separate Rust controls implement
exact linear suffix DP and a first-batch myopic score. They are deliberately
identified as controls, with different identity/response schemas. Their
scalar recurrence receipts are not labelled as original NDU recursive
evidence. All three use the pinned Rust 1.90.0 toolchain, the same locked serde
and serde_json versions, the same bounded stream framing, and sealed process
admission. No original NDU source or production admission rule is modified.

## Question and scope

For this finite supplied-path profile, how do the original NDU framework,
a strong exact native DP and a native myopic strategy compare in recommendation
quality and instrumented process/host cost when they receive identical
information?

This is not a real-application speed study. Cost matrices are synthetic supplied
inputs. Their verification labels and digests are scenario data, not proofs of
candidate code. The original NDU and DP receive the same complete paths,
costs, budgets and labels. A recommendation cannot authorize execution.

The exact DP is a linear table of suffix values for each supplied path. Unit
discounts make each step checked signed-Q32 addition. It retains every best
feasible root-value tie. There is no unnecessary hash-map or cloned-suffix
overhead in this control. The myopic arm receives the same complete input and
returns the same complete path-value table, but ranks feasible paths by the
first batch's two events. Unresolved ties remain null recommendations; no
hidden lexical choice is made. Report the full-path regret range of those
frontiers separately from regret for unique recommendations.

The original framework performs recursive evidence work that these controls do
not reproduce. Native transport/parse/envelope time is therefore not pure
algorithm time. The study reports this distinction and cannot isolate an
algorithm-only causal contribution from total process latency.

## Registration and preserved constraints

`PROTOCOL.json` fixes 2,048 decisions per arm, a new session at every
256-decision boundary, zero cross-request decision/result caches, the three
regimes, seeds, ten-second request timeout, 1,200-second overall run budget and
96 MiB retained-evidence budget. Formal inputs cannot be relabelled as
development inputs. The formal generator requires an explicit formal permit.

The runner adds stronger operational gates:

1. Before registration, real native tiny controls must pass exact Q32,
   ties, explicit abstention and one-unit-over-budget cases in all three arms.
2. Every real native arm must process exactly 256 development replies and
   reject request 257 while closing the session. These are separate lifecycle
   controls, not extra formal observations.
3. A complete development matrix run must pass and bind the current exact
   study sources. Changing a runner, test or protocol invalidates an older
   development receipt.
4. Freeze creation checks each bound file against its actual Git blob.
5. Formal invocation requires the precise FREEZE blob at a complete published
   registration commit, the source commit as its ancestor, unchanged bound
   sources, and an absent one-shot execution claim. The root/operator verifies
   remote publication before invocation; a local Git object is not itself
   proof that a remote ref was published.
6. Formal cold builds happen after that claim. Original NDU and each control
   get separate empty compilation targets, one compiler job, the existing
   dependency cache and measured cleanup. No earlier build time is reused.

The final native study must wait until other planned native timing has ended.
The retained host affinity records the actual process context; no shared-host
exclusivity is claimed.

## Complete byte evidence within the fixed budget

Development showed that four separate gzip streams could exceed 96 MiB at the
registered denominator. The limit was kept. The runner now stores one
lossless interleaved archive with a channel, arm and decision index on every
record. Each decision is an independently checksummed XZ member.

The original canonical request is retained once. Every actual response frame
is retained as its original UTF-8 byte string; failed partial frames use
lossless hexadecimal bytes. This is not serialization of the parsed response
object. Lengths and SHA-256 digests are checked again after decoding the
archive, together with sequence numbers, request linkage, started/completed
denominators and member checksums.

Each record first reaches a flushed pending journal before the next native
call. The pending file is cleared only after its compressed member is flushed.
Failure paths retain starts, partial frames, quality disagreements and
cleanup diagnostics. Detailed accounting rows are in the same archive;
the summary report does not duplicate all of them as large plain JSON.
Compression/write times that cannot appear inside their own timed record
are retained in the member index.

The complete measured archive-writing, compression, finalization and byte
audit are common assay overhead, charged equally once to each standalone arm.
This prevents a shared compression dictionary from becoming a supposed native
algorithm advantage. Request construction is also charged once per arm.
Each arm additionally carries its actual source build, startup, complete
request/admission, quality-check and cleanup costs.

## Cost interpretation

The runner reports measured prefix accounting at 1, 32, 256 and 2,048
decisions. For a prefix ending inside a session, the accounting uses the
actual close cost later observed at that declared session boundary. These
are accounting prefixes of one study, not separately executed short trials.

Reports distinguish native transport/parse/envelope wall time from host work.
The control adapter's extra structural-normalization copy is explicitly
measured and retained. Native request hashes are checked at the actual
transport call before sending. All arm-specific responses retain their
distinct identity and scope.

Toolchain/dependency acquisition, human engineering/review and Python
interpreter bootstrap before the instrumented entry remain unknown costs;
they are not converted to zero. The result is an instrumented accounting
subtotal. It is not a complete global economic guarantee, a machine-code
proof, real-application net gain, or unlimited-lifetime extrapolation.

## Terminal accounting and interrupted builds

`RESULT.json` is provisional. The runner writes it before taking the terminal
wall and directory-size observation, so its actual encoding and write are in
the observed budget. It reconciles all disjoint native/session/common timing
regions to that measured wall. Every remaining coordination, prefix-analysis,
source-inventory, hash and normal-report cost is a common charge, once to each
standalone arm. The full-run residual is conservatively charged at every
prefix; it is not an observed one-request or 32-request stopped trial.

`FINAL_GATE.json` binds the actual result bytes/hash. Its exact encoded bytes
and a fixed 2,048-byte positive `FINAL_COMPLETE.json` are included in the same
96 MiB limit. Only after an actual post-gate directory/stat and monotonic check
does the runner write the completion receipt. That receipt binds both hashes
and records the additional observed gate-tail time, which is another equal
common addend to every prefix arm. Admission requires that positive complete
receipt; absence of a failure marker alone never proves a run finished.
A final post-completion check also rejects time/byte overrun and preserves
`FINAL_GATE_FAILURE.json`. The CLI returns failure in these cases. A stopped
process with only a provisional result or gate cannot be frozen.

The completion receipt cannot recursively measure its own preparation/write
and process exit. These last operations remain an explicit unmeasured tail,
not a zero-cost assumption. The CLI exposes a later observed wall/byte receipt
for the external process record. This boundary limits total-economic claims;
it does not remove any fixed budget or accept a known overrun.

Build interruption also preserves evidence. The bounded runner retains the
owned group leader without reaping it until it has terminated the group,
drained the pipes and reaped the leader. Timeout, `KeyboardInterrupt` and other
caught exceptions retain original observed stdout/stderr, EOF completeness,
argv, elapsed time and cleanup status before propagation. A compiler target is
removed only after cleanup is confirmed. The runner does not claim to contain
a deliberately escaped process group. Tests exercise real child and descendant
processes; no mocked process counts as a native planning observation.

## Commands

Development uses already built native manifests and only the fixed
development seed:

```sh
python3 -B -m experiments.hia_ndu_identical_inputs_continuation_20261030.study \
  development \
  --ndu-manifest /path/to/original-c4-stream/identity.json \
  --control-directory /path/to/separate-development-controls \
  --output /path/to/new-development-output \
  --count 32
python3 -B -m unittest tests.test_hia_ndu_identical_inputs -v
```

After committing the exact reviewed sources, create a freeze from current
successful native development evidence:

```sh
python3 -B -m experiments.hia_ndu_identical_inputs_continuation_20261030.study \
  freeze \
  --controls-result /path/to/development/controls/RESULT.json \
  --development-result /path/to/development/matrix/RESULT.json
```

The root/operator publishes and independently reviews that registration before
using the `formal` command. Formal input generation and cold builds are not
part of freeze creation. Every started formal run is retained; a timeout,
identity drift, semantic mismatch or resource-limit failure stops the run.
There is no success-seeking retry or seed replacement.
