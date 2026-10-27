# First integrated resource candidate: retained failed attempt

Code commit: `9ce4bc1dc3f831401af5a2736b319d61bfd7c0f2`. Tree: `629b85b18e97d77b5a5f3022d8cc830786e3dfc9`.
All **46 planned gates completed**; **44 passed** and **2 failed**.
The complete unit/native integration suite passed **1369 tests with zero skips**.
The source snapshot was unchanged: `ef24464829b85b4757ec0ccf6147229775a10d0a0b069e5d36fcd33afba19b39`.
The [original aggregate](release-validation.json) remains `failed`.
[Attempt summary](attempt-summary.json) preserves the exact nonpassing rows.

## Status-contract integration defect

`cpp_owned_migration` actually returned zero and emitted the precise status
`native_owned_implementation_and_cleanup_qualified`. The collector incorrectly
expected generic `passed`, so it correctly did not credit the incompatible
report. The producer's complete actual-source/native report was independently
validated after the run; see [integration-diagnosis.json](integration-diagnosis.json).
The later collector fix accepts this exact scoped status and still invokes the
original strict current-source validator. It does not edit this report or
change migration semantics.

## Owned-resource performance remains inconclusive

All **63 samples** are retained in [llvm_owned.json](llvm_owned.json).
The speed thresholds were satisfied, but **five implementation/kernel series**
exceeded the fixed 5% relative-MAD quality limit. The maximum was approximately
12.60%, for LLVM constructor-error execution. The measured geometric ratios
were **0.807324** against same-source Rust and
**0.770825** against handwritten Rust.
Those favorable ratios do not turn this attempt into a pass.
The [artifact comparison](performance-consistency-review.json) confirms that
all five noisy series use the same LLVM/handwritten-Rust and driver binary
bytes as the earlier passing attempt. No specific host scheduling cause is
established by these records.

| Kernel | LLVM / same-source Rust | LLVM / handwritten Rust |
| --- | ---: | ---: |
| constructor_error | 0.917480 | 0.894528 |
| full_lifecycle | 0.564375 | 0.946856 |
| two_stage | 1.016197 | 0.540742 |

The original quality rejection is preserved. Its complete report passes only
the explicit audit mode `require_pass=False`; the ordinary release validator
rejects it. The source, driver, ordering, sample count and thresholds were not
changed. A subsequent integration run is a separate complete attempt and must
retain this one.

## Other actual observations

The C++ migration-to-LLVM end-to-end gate, two Rust allocator-refusal observers,
local stored-loan qualification, two-version JSON upgrade, scalar LLVM
performance, strict namespace/workspace/crash fixtures, Lean and QEMU gates
passed their documented scopes. Foreign JSON destructor termination remains
unqualified recovery. Scripted evaluator fixtures are not live model trials.
The Windows job **121235596135**, run **40215485226**, actually executed ABI
qualification at this code commit. Its original [receipt](platform/windows-x86_64.json)
and [strict CRLF-source replay](platform/windows-receipt-replay.json) are retained.

## Archive and reproduction

Original JSON, logs and generated text are archived without normalizing their
contents. [archive-manifest.json](archive-manifest.json) records their hashes
and identifies native products that remain local instead of being added to Git.
Copied generated work-directory text is under `retained_workdirs/`. Native
validators require the original retained files; another checkout should rerun
the recorded commands into fresh directories. This is not closure of the full
seven-stage production-language roadmap.
