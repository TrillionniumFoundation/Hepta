# Finite native adaptation: retained execution evidence

This final run passed after the compiler implementation was frozen. It exercises two distinct native implementations of u64 wrapping addition: `x+y` and `(x^y) + 2*(x&y)`. Both immutable Core programs pass internal verification. Their sealed executable snapshots have different SHA-256 values. Retained objdump observations show `lea; ret` for the baseline and `mov; xor; and; lea; ret` for the candidate.

## Observed result

- 131 inputs execute on both original and explicitly selected native versions and agree with an independent u64 oracle, including wrap boundaries.
- Four concurrent threads each execute 65,536 native calls, totaling 262,144. Selection and close are refused while dispatch leases remain active; a quiescent explicit return to baseline succeeds.
- Changed artifact bytes before load reject. An actual write to the sealed descriptor fails with EPERM. Replacing the published pathname does not change subsequent native execution.
- Inequivalent Core, fabricated receipt and modified public telemetry cannot authorize a version. Expired internal measurement retains the baseline.
- The raw archive contains both exact native images read from their sealed descriptors before tamper controls, their Core JSON inputs, internal proof/build receipts, native values, measured costs and decision events.

`automatic_profitable_selection_supported=false`: profitable autonomous adaptation is not implemented. Measured shadows use `conservative_shadow_only`; their fully charged finite experiment cannot amortize its own execution/preparation cost. Only explicitly requested, verified empty-state switching is established. Live owner/loan/heap/stack migration remains unsupported. No candidate speedup or global optimality is claimed.

## Retention and scope of evidence

`qualification.json` is the complete observation report. `command.json` retains the actual argv, exit code, stdout, stderr and elapsed time. `source-identity.json` pins all included implementation, driver and fixture bytes. `raw-evidence.tar.xz` contains the complete successful output tree, the earlier ENOSPC attempt, and a source snapshot. `archive-members.json` records every retained member size and SHA-256; packaging re-read and checked every archive member.

The first attempt failed during host storage exhaustion; its files are retained under `enospc-attempt/`. The successful retry ran after archived temporary output was removed. It did not overlap the registered benchmark timing. These source hashes and local reports are reproducibility evidence, not authentication of arbitrary third-party receipts.
