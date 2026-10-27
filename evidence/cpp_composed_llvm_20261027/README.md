# Composed C++ migration: independent LLVM execution and publication audit

This directory retains the actual source-bound LLVM qualification on frozen
code `53ffaa3fe3843993ad71783dba462c9334781796`. It also preserves the earlier
three-route migration run and LLVM development run separately. None of these
records substitutes for the final integrated candidate's own complete run.

## Actual LLVM results

| Migrated source | Actual calls | Allocations / frees | Actual allocator refusals | Result/event digest |
| --- | ---: | ---: | ---: | --- |
| Pair | 437 | 401 / 401 | 196 | `79fca1db8d2f0865` |
| Triple | 613 | 796 / 796 | 307 | `857e18f53bf7b178` |
| Quad | 833 | 1,409 / 1,409 | 423 | `6d4d805955152153` |

The total is **1,883 calls, 2,606 successful allocations and frees, and 926
real refusals**. Each call finished with zero live tracked byte storage.
The direct LLVM objects export only `composed_case`; their link commands
contain no original C++ object and no Hepta Rust/C implementation object.
A C harness observes the actual LLVM implementation. Rust remains a separate
mandatory type/borrow reference validation, and does not emit the tested
implementation machine code.

All three programs also have two actual compiled and executed LLVM controls:
omitting `free` leaves respectively 2, 3 and 4 allocations live; reversing the
composite destructor's field selections releases all storage but changes the
event order. All six controls exit 3 at the first lifecycle case. Their exact
observed traces match an independently computed event oracle. They are clearly
marked unqualified negative-control LLVM, not source-accepted output.

The frozen compiler SHA-256 is
`871913722878bf26987932afe660e22d1f9d774e29c6299eb1dcbff1ce2367b1`.
The current-source validator passed on the frozen tree. It freshly translates
the C++ AST and regenerates the typed/resource/LLVM projection, checks the
retained native products and exact commands, and recompiles the finite target
layout assertions. It does not execute the retained target observations again
or authenticate arbitrary reports from another party.

`frozen-report.json` is copied byte-for-byte from the actual producer output.
Absolute execution paths remain as recorded. They are not rewritten to make
the report look freshly replayable in another directory or compiler tree.

## Independent publication audit and correction

The review reproduced a source/publication race in `3b16d1d`: the test's
actual hard-link hook changed the original C++ after the last source check.
The original migrator still returned `ok=true` and left the published file.
The original source SHA was
`688d09988166354438730d9d62835bdc54e2632cb57659bed3dbc89fa179baa2`;
after appending a new global declaration it was
`ad1f649deb0ce99b34a898f5f4cda2d6420850a8d524a0a810193ad94738532e`.

Commit `1cf9f40` replaces the bare link with exact byte/inode publication,
rechecks source and compiler identities after linking, and verifies the final
published file. On failure it withdraws only its own link. Three regressions
perform actual source writes, staged-byte writes and competing replacement
writes. The corrected migrator rejects the first two and preserves the third
writer's independent file. This is point-in-time consistency, not immunity
from later writes by another process with the same filesystem permissions.

The migration suite passed **15 tests** after this correction, including its
real C++/Rust/C execution. The new LLVM suite passed **8 tests**, with actual
native executions and 19 report mutation cases, rehashed IR/native-product
tampering, a resealed false negative trace, failed-link evidence retention,
output preservation and report-controlled executable rejection. Test cases
which inject timeouts or race hooks are explicit simulations of those trigger
conditions; they are not counted as additional real crash or timing trials.

## Preserved development records

The archive includes the original `composed-bdb-001` three-route run, the first
complete `composed-llvm-review-001` run, the final frozen run, exact source/IR,
objects/executables, raw native receipts, and associated test logs. The first
LLVM run preceded the stricter exact negative-trace oracle and caller-selected
layout tool guard; its original report remains unchanged and its exact
qualifier source is retained next to it. It is historical evidence, not a
report validated by the final tool.

An earlier exploratory script attempted to read the LLVM dataclass's nonexistent
`.llvm` attribute and stopped before native compilation. Correcting the script
to read `.text` produced the separate pair object probe. That script failure
is not counted as a completed qualification or a native program failure.

The source bundle contains the exact three commits from public base
`bdb8690317e96e1cd4a6f140e96376faa9dba522` through frozen source `53ffaa3`.
It permits recovery of the locally recorded source commits even when later
integration uses different commit identities with the same files.

## Archive integrity

The base64 file contains an XZ-compressed tar archive. `MANIFEST.json` records
the compressed archive digest and every member's size and SHA-256. Verify
without extracting or executing any artifact:

```
python evidence/cpp_composed_llvm_20261027/verify_archive.py
```

The archived three-route run contains Rust executables; the LLVM runs contain
native executables, objects and deliberate wrong-code controls. The verifier
only reads their bytes. Running them is a separate authorized qualification
action. The finite cases do not prove arbitrary C++/RAII safety, whole-compiler
refinement, physical-device behavior, or a performance advantage. No timing
benchmark was run by this increment.
