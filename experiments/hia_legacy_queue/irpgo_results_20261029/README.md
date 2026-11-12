# Actual IR PGO follow-up: completed, composite advantage gate false

This separately registered follow-up executed clean source
`6191eca3e896473707306fb8fb98d9b7b6f187bb`. It retains the first negative legacy
trial and the failed IR PGO preparation. No arm or sample was replaced after
measurement. The measured source is preserved in the raw source bundle; later
integration commits do not inherit its execution identity.

## What was run

The unchanged upstream implementation and authored integration code produced
the same verified Core SHA-256:
`1044e28ea68a18d6a0681cff9cd5f835e26e91c9a669dab01256b9592f64ca51`.

All 11 registered arms were built and run: default HIA, native HIA LTO, native
HIA IR PGO; C and C++ LTO, frontend PGO and IR PGO; safe Rust LTO and PGO.
The selected candidate was **`hia_native_irpgo`** before any performance data.
LLVM IR PGO used actual `-fprofile-generate` training and `-fprofile-use`, with
both algorithms on the same 65,537 training bytes. Every entry-function block
counter vector is retained and individually checked for positive execution.
The flag `entry_first = 0` means those vectors are not reported as entry-call
counts. Original and candidate Core/LLVM bytes were checked against fresh
emission around every HIA research compilation and at measurement boundaries.

The held-out seed was 29102026 and its length 2,097,189 bytes, fixed in the new
protocol. This is different from the old trial, so ratios must be computed
within each trial rather than across the two sample sets.

## Functional and resource result

- 96 cases across 11 native routes: **1,056** correct ABI/differential calls.
- **96** allocation/refusal rows: VM, C, default HIA and HIA IR PGO agree.
  The PGO resource observer uses O3, full LTO and native CPU optimization. It
  is a separate observed binary made from the same IR/profile, with allocator
  refusal wrappers, not direct failure injection into the timed DSO.
- **12** maintenance cases pass after an explicitly named IEEE/Castagnoli API
  update. Original upstream source files remain unchanged.
- **154** measured applications and both switch/recovery observations finish
  correctly. No samples are excluded.

## Fixed performance gate

| Algorithm | Arm | Median whole process ms | Batch P99 ns | Median child wait4 peak KiB |
|---|---|---:|---:|---:|
| Castagnoli | HIA native IR PGO | 38.715538 | 300052 | 1696 |
| Castagnoli | Fastest strong reference: C native LTO | 41.916362 | 272406 | 1636 |
| IEEE | HIA native IR PGO | 41.845892 | 308714 | 1732 |
| IEEE | Fastest strong reference: C native IR PGO | 38.572544 | 235596 | 1616 |

The candidate's time ratios are 0.923638 and 1.084862, respectively. Both
P99 ratios exceed one (1.101488 and 1.310353), as do both RSS ratios (1.036675
and 1.071782). Therefore **`performance_advantage_gate=false`** and
**`performance_and_rss_gate=false`**. A positive Castagnoli median observation
does not satisfy the compound two-algorithm gate.

All samples were collected on the available shared Linux host. Team model
inference and other native benchmark runs were paused during this interval;
that does not make the host exclusive or identify it as the user's physical
workstation. No statistical significance or universal speed claim is made.
Batch tails refer to up to 4096 input bytes, not a service request SLA.

## Costs and limitations

Initialization was 0.049134493 s, `run()` was 83.032088636 s, and their recorded
sum was **83.081223129 s**. HIA IR PGO preparation was **1.003022127 s**,
including its actual training and required bindings; HIA LTO was 0.508871301 s.
Rust PGO preparation was 7.188470515 s. All other build, monitor, switch,
recovery and complete process records remain in the qualification dataset.
Outer Python startup/imports, toolchain acquisition, archival and human
engineering are outside these timers. No person-hour saving was measured.

The earlier failed preparation is retained separately: the binaries agreed,
but the maintenance oracle incorrectly used JSON key order to choose its CRC
polynomial. The named algorithm fix and a 12-case native diagnostic preceded
this frozen formal run. The earlier O2 resource observations were not relabeled
as this run's O3 resource evidence.

## Inspection

`SUMMARY.json` gives all arm metrics and the direct gate result. `INDEX.json`
binds lossless datasets for the entire qualification, actual process ledger and
319-file raw inventory (14,336,512 bytes). The differential ledger and actual
HIA/C/C++ IR counter texts are included directly. Native artifacts, raw compiler
output, earlier failures and original source commits are retained separately.

```sh
python experiments/hia_legacy_queue/irpgo_results_20261029/inspect_evidence.py
```

All three datasets reconstructed successfully. Inspection does not execute or
requalify the experiment, and it grants no production authority.
