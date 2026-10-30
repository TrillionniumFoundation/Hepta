# Native startup and linker fixture repair

This package retains two real failures, the minimal two-file repair, local
controlled validation, and new executions on its exact public commit. It
preserves the original failed outcomes and keeps every source identity
separate.

| Role | Commit | Tree |
| --- | --- | --- |
| Original public convergence | `e0b9012a249167b5bc5b0f3bd243899344621080` | `7adcc2a0333b48374b4add2d8132d1998c5cc48c` |
| Local frozen two-file repair | `40ae7fa8c8d8c82cec0861e4f946e264329a984a` | `8e39b41544b5fde725a6ed57cc104bfa2f3fa257` |
| Public repair on the existing PR410 branch | `b121c9b4a57a8a58e53360d1d67387d953348f57` | `8e39b41544b5fde725a6ed57cc104bfa2f3fa257` |

Both repair commits have public e0 as parent and the same tree. The two source
files, their Git modes and blobs, the full-index patch, and an independent
tree reconstruction are included. After local validation, the clean repair
checkout was explicitly moved to the same-tree public commit to avoid another
large checkout; the original local branch, commit, source export and execution
records remain unchanged. The readback receipt records that transition.

## Native child startup budget

Original official e0 source/application run `41055139018`, job
`124060656375`, ran 340 selected methods with 339 ordinary passes and one
failed subtest. `fork_and_stall` timed out under its 0.2-second total budget
before the test observed its required SIGSYS result. The original CI record
does not isolate exactly how that elapsed time was divided among startup,
scheduling, loading and evaluation.

A separate real controlled experiment added a 0.35-second startup delay only
to the two fork worker paths, before the original worker and syscall filter.
It did not replace process status, native execution, filtering or assertions.
On the unchanged e0 source, the actual child exit codes were
`[-9, -31, -9]`: the first fork test failed by timing out before reaching the
original worker; the second fork test reached the forbidden syscall and died
with SIGSYS; the ordinary stall still timed out. This expected reproduction
remains a failed test, not a passing qualification.

The repair gives both fork cases the existing 3-second startup allowance.
The non-forking stall retains its 0.2-second deadline. Both fork assertions
still require SIGSYS(-31), and the actual marker/cleanup assertions remain.
With the same controlled delay, the local repair and the public repair each
actually produced `[-31, -31, -9]`, three absent-marker observations, and an
unchanged empty cleanup state. All original/delayed worker source, native C
and ELF bytes, child argv/exit codes, timings, marker observations and logs
are retained.

## Generic linker fixture

A different selected test on unchanged e0 failed with the actual pinned
generic Rust LLD because its fixture passed the generic executable spelling
directly to the production ELF-driver guard. This is distinct from the
official timeout failure.

The repair makes that fixture enter the existing `elf_linker_driver` context
through a test-lifetime `ExitStack`, using the admitted ELF driver until all
fixture work finishes. Cleanup closes the contexts before removing the
temporary directory. Production selected-executable/alias identity checks,
exception cleanup, current dispatcher behavior, and bound-IR/profile/compiler
guards remain unchanged. The original generic-linker error is retained.

## Actual new validation

| Source | Selection | Actual result |
| --- | --- | --- |
| Original e0 | Controlled startup-delay method | One expected failed test; actual child codes `[-9, -31, -9]` |
| Original e0 | Selected generic LLD fixture | One actual error, retained separately from the timeout |
| Local 40ae | Same controlled startup-delay method | One ordinary pass; `[-31, -31, -9]` |
| Local 40ae | Related native/linker guards with actual generic LLD | 13 ordinary passes |
| Public b121 | Same controlled startup-delay method | One ordinary pass; `[-31, -31, -9]` |
| Public b121 | Related native/linker guards with actual generic LLD | 13 ordinary passes, exact-once method events |
| Public b121 | Existing canonical safety qualifier | 340 ordinary passes, exact-once method events |

The 13-method selection contains four native child-limit methods, five
same-Core build-input methods, two restored selected-linker identity/cleanup
methods, and the two current dispatcher methods. It overlaps canonical340;
the counts are not additional independent coverage. The original public e0
local340 pass and official339+1 failure remain separate in the convergence
package.

The canonical public b121 run has no skipped tests, failures, errors, expected
failures or unexpected successes. Source, tools, original NDU/Z3 inputs and the
target Rust executable are stable before/after. The selected Rust tests use
their existing Cargo setup paths and existing target; there is no new
standalone Rust crate qualification. The actual executable bytes match the
retained public e0 Machine. Its original build provenance is not relabeled.

The new canonical run delegates to the unchanged original qualifier producer
with explicit public head/tree/output/environment parameters. Both producer
files and the parameterization receipt are included. Native evidence output
paths are unique to the new run, so no old corpus was overwritten.

## Independent review and limits

The frozen independent repair review is included as its exact archive, with
its publication map and readback. It checked the two-file change, original
worker bytes, strict signal/marker/stall assertions, linker lifetime,
actual red/green records and related 13-method log without new native calls.
A reviewer identity precondition exited after the authorized checkout moved
from local40ae to same-tree publicb121; that exit is retained, and the old
executions were not renamed as public executions. Any later review of the new
public execution has its own identity and does not alter this original review.

Only test fixtures changed. Production runtime, Core, Machine, syscall filter,
canonical340 selector set and all authority settings remain unchanged. This
package does not claim official hosted CI has passed without original hosted
content evidence. It does not qualify later P0 changes, Rust production
authority, global soundness or all P0–P7 blockers.

The NDU runtime artifacts remain the original public147 builds. Their denied
authority, compiler/source/build-cost records and exact bytes remain original;
only transport paths were relocated. The package retains restoration and
identity receipts plus immutable original-ZIP reconstruction references,
without duplicating a huge toolchain installation.
