# Independent local-view review and receipt correction

The independent review examined implementation `d3d0927` and its unchanged
original receipt in `../llvm-local-views-20261027/d3d0927.json`. This review
did not identify an accepted source program that violates local-view aliasing
or a demonstrated LLVM/C resource-lowering miscompilation. That limited
finding is not a soundness proof.

## Reproduced receipt-validation defects

The original validator accepted eight independently modified reports. The
inputs were deep JSON copies of the actual successful report; the unmodified
report first passed the original validator. `before.json` preserves the
observed outcomes. Each accepted mutation changed only the named field:

| Mutation | Change accepted by the old validator |
| --- | --- |
| `rejection_claim_proof` | Rejected `escaping_view` build claims whole-language safety proved |
| `rejection_claim_execution` | The same rejected build claims native execution qualified |
| `rejection_claim_general_cross_target` | The same rejected build claims cross-target execution qualified |
| `unsupported_reference_target` | Its successful Rust reference target changed to AArch64 |
| `unsupported_reference_compiler` | Its reference compiler digest changed to 64 zeroes |
| `unsupported_reference_borrow_scope` | Its reference reports native lifetimes unchecked |
| `positive_c_target` | The successful C library target changed to AArch64 |
| `positive_llvm_tool_version` | The successful LLVM tool version changed to `rustc 1.0` |

A ninth control changed a native artifact size to Boolean `true` and was
already correctly rejected. These are report-consistency defects. They do
not show that the producer ran an unqualified compiler or emitted unsafe
machine code.

## Correction and actual rerun

Implementation commit **`68980d9eefc61fcae38e353eeb88a141cbda7b49`** changes
only the qualifier and its tests. Rejected builds now have an exact field
inventory and closed claim set. Their full source project is reconstructed
from retained fixture bytes using source overrides at its original path.
The verifier binds successful unsupported-shape references and genuine Rust
rejections to the same pinned compiler, host target, flags and precise borrow
checking state. It also checks the C host ABI and the admitted Clang version
family. It does not execute native tools during report replay or authenticate
arbitrary third-party claims of execution.

The fresh **11-test** run passed with zero skips, errors or failures; its raw
output is in `tests.log`. The mutation test now rejects **38** independent
changes, including the eight reproduced defects and additional source-graph,
profile, flags and negative-reference changes. The new native qualification
was also executed after the implementation commit and is retained unchanged
as `68980d9.json`:

- LLVM, C/UBSan and Rust each execute all **140** fixed cases.
- Each backend observes **110 allocations, 110 releases, 30 allocator
  refusals**, and zero remaining live allocations after every call.
- Each backend's bounds-error child exits with SIGABRT.
- The actually compiled owner-release omission exits **86** with two live
  allocations, no releases, at the first allocating case.
- All fourteen invalid/unsupported sources still publish no object; three
  LLVM/source-identity mutants still fail before native compilation.

`manifest.json` binds the exact preserved report/log bytes and their source
commits. The earlier passing report is kept unchanged; changing qualifier
input bytes means it cannot substitute for the corrected qualifier's receipt.

## Audited boundary

The source lowerer still rejects interprocedural/named regions, nested
stored-view records and view-field reborrows. The native layout helper still
admits only one inferred local u8-slice descriptor, and rejects labelled v5
records even when declarations are unused. Shared descriptors copy;
exclusive descriptors move and end without freeing their owner. Ordinary
owner destruction continues through its separately verified Drop plan.
Source regeneration, semantic/resource identities, target-layout checks and
publication guards remain in the execution path.

No performance workload or threshold was changed or measured. The final
integrated compiler requires a new source-bound receipt on its own snapshot.
