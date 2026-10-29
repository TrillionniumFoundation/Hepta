# Heterogeneous NDU activation and exact-cost follow-up

This prospective study follows the negative six-outcome experiment at
`96bc1b4598a8469b0d44b09e7e97d4705cac2cc5`. It changes neither that protocol nor
its result. The original NDU application arm built **zero** candidates. A warm
wall-time difference consequently could not be attributed to useful candidate
selection.

The old model multiplied every size's baseline forecast by a ratio from one
small-input observation. In the retained group-0 stable NDU episode, the
31-byte baseline probe took 7,103,714 ns against the calibration median
35,040,151 ns. That ratio repriced all other baseline sizes. This is a disclosed
model assumption, not evidence that the workload changed proportionally at
every size. Candidate-wise contiguous calibration also allowed startup and
host-load trends to correlate with candidate identity.

## Concrete changes

- Calibration now rotates and alternates all six module/target pairs at every
  registered size and repetition. All samples remain in the dataset.
- Completed observations update only their exact module, target and input-size
  cell. No cross-size or cross-module speedup is inferred from one observation.
- Forecasts include mandatory per-delivery fresh proof as well as execution.
  Calibration performs that same proof. One-time candidate construction is
  separately priced; it is not counted again as recurrent delivery cost.
- `byte_sum.hepta` performs one allocation and a byte reduction;
  `packet_xor.hepta` performs two allocations, a transform/XOR pass and a byte
  reduction. They produce distinct canonical Core hashes and have independent
  mathematical checksum oracles. Both are small kernels from the existing
  optimizer workload, not representative migrated applications.
- Each application episode owns one real compilation-attempt credit shared
  across its semantic modules. The credit is consumed before compilation and
  is never refunded. Every chosen native image is independently reproved and
  executed through the existing receipt-matched sealed-image path.
- Post-run analysis compares each NDU selected plan to complete DP on the
  **same** model, reports actual candidate builds and correct outputs, and
  separately checks whether two predicted-profitable modules competed for the
  single credit. A timing difference does not imply activation or useful choice.

`PROTOCOL_20261028.json` specifies three groups, 8 epochs, 65,539 calls per
native execution and stable, changing-load and heterogeneous shared-budget
profiles. The fixed control commits its complete-DP allocation after the
identical initial probe; DP and NDU receive the same candidate bank, legal
allocations, registered input schedule and the same observation interface. Each
arm receives its own completed observations; the post-run audit passes NDU's
exact model to complete DP. None receives future observed timing. NDU remains
the pinned native recursive evaluator;
the research driver does not replace it with an imitation.

Activation and shared-budget competition have their own gates. The economic
gate still requires complete cold NDU cost to beat both fixed and complete DP
in **every** registered profile. A fresh empty-target native build is charged
once per applicable standalone interpretation. Per-profile tables are separate
deployment interpretations and must not be summed; the combined table charges
common setup once. Warm results omit only the native build.

The protocol permits negative activation, competition and net-benefit results.
It does not establish that a native evaluator should beat exact DP on a fully
known additive finite problem. It does not claim global instruction optimality,
universal Rust superiority, an indefinitely amortized gain, or a dot-host run.

## Reproduce

Use a clean committed checkout, the pinned native source `c4a1bbed...`, Rust
1.90.0 and the selected actual Clang installation. Keep build and raw results
outside the checkout. First run `tools/measure_hia_ndu_build.py` with a fresh
empty target directory, then pass its identity and outer cost envelope to:

```sh
python tools/qualify_hia_ndu_activation.py \
  --output /tmp/hia-ndu-activation-run \
  --identity /tmp/hia-ndu-activation-build/build/identity.json \
  --build-envelope /tmp/hia-ndu-activation-build/BUILD_ENVELOPE.json \
  --clang /absolute/path/to/clang
```

The runner refuses an uncommitted source/protocol or mismatched build envelope.
`REGISTRATION.json` is created before calibration or application observations.
It preserves the source identity, source hashes, protocol and native image.
Native I/O, proposals, proofs, actual command output, artifacts and all failure
costs are retained. The post-run audit has no execution authority.

The local tests in `tests/test_hia_ndu_activation.py` cover oracle boundaries,
invalid protocol fields, exact-cell forecasting, distinct resource structures
and all-arm execution of both semantic modules. Native tests require
`HEPTA_NDU_STREAM_IDENTITY` and real host `/proc` visibility. A namespace error
must be corrected by using an authorized compatible executor, never by
disabling actual process-image identity checks.

Authority remains `DENY_ALL`; `safety_certificate` remains `false`.
