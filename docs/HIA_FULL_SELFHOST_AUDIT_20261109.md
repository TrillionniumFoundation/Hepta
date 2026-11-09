# Whole-stack HIA selfhosting audit — 2026-11-09

## Decision and source authority

**Whole-stack rewrite is OPEN, not complete.** The successful native fixed point
is real, but does not establish that the rest of the project is implemented in
HIA. The current implementation contains a live `hepta/` package with 212 Python
files, 76,121 lines and 4,125,246 bytes. These are source inventory figures, not a
percentage-completion estimate. Archived copies and example source files are
not counted as production replacements.

The project is `TrillionniumFoundation/Hepta`; there is no separate organization
repository named `HIA`. `main` is the public metadata/entry branch, not the full
compiler source. The selected public v9 source lock is `2598f430`; the separately
named v16 source lock is `6ecd8023`. Neither automatically selects an unmerged
selfhost candidate. Development continues here from PR #834 source commit
`ffbf0b89ddb468a056561543bce3e1fcab6b8da3`, which contains the v16 baseline and
v17 internal scalar result work. Do not copy a full compiler into metadata-only
`main`, silently advance release locks, or promote unrelated candidate branches.

The open-PR inventory observed during this audit contains 465 entries. Many
are stacked historical/research branches; their titles or isolated success
receipts do not establish integration into the selected source. Current adjacent
work includes #829 information pricing, #830 copied-image proof/adoption, #831
paired cost reading, #832 public minimum-image entry, #833 artifact-chain replay
and #835 paid-observation/deadline retention. These have distinct source and
acceptance identities; they are not blanket qualifications of this branch.

## Current development and qualification

On exact PR #834 head `ffbf0b89`, the observed workflows include:

| Gate | Observed state |
| --- | --- |
| Selfhost source / cold / native / language (`42642459675`) | success |
| Unified candidate (`42642459577`) | success |
| Six-outcome source/application (`42642459646`) | success |
| Agent native tools, finite CRC, intelligent assembly | success |
| Verified optimization/NDU, direct x86 backend, round4 runtime | success |
| Actual-host ABI (`42642459832`) | failure; macOS job cancelled |
| Real upstream C++ (`42642459828`) | failure; macOS job cancelled |

A cancelled required platform is **not** an executed pass. Prior green runs
cannot replace fresh execution after source changes. Proof and optimization
experiments also retain their own boundaries: finite scalar/leaf proofs are not
whole compiler refinement, and no general NDU economic benefit is established.
Hardware-required GPU/MCU claims cannot be closed by host emulation or renaming.

## Implementation boundary, component by component

| Component | Implemented in HIA now | Still needed for whole-stack closure |
| --- | --- | --- |
| Scanner / assembly parser | Fixed canonical `hia-asm.v1` bytes | General identifiers, full grammar and diagnostics |
| Core validation / ownership | Fixed scalar and resource profile, CFG/call checks | Signed/unit types, composites, returned owners/loans, full signatures |
| Code generator / ELF writer | Linux x86-64 flat and bounded ELF | General linker, multiple exports, other targets |
| Execution / standard library | Explicit bounded compiled primitives | General runtime, tasks/I/O, production library |
| Modules / packages / build | No full HIA replacement | Module graph, package/build/install orchestration |
| Agent tools / persistence | Compiled leaf programs, not service rewrite | Worker/service/store/protocol implementations |
| Optimizer / proof tools | Selected compiled kernels only | Planner, optimizer, validators and proof construction |
| CLI / release | Public checked entry exists, host orchestrated | Standalone HIA toolchain entry and release path |

`tools/audit_hia_selfhost_closure.py --output <new.json>` inventories every live
Python package file with AST imports and SHA-256, maps implementation authorities,
and emits these open boundaries. It is static audit evidence, not runtime or
formal evidence; dynamic imports and semantic equivalence require separate checks.

## Implemented follow-through: v18 empty result tuples

The compiler now accepts internal `fn fN(...) -> ()`, `_ = call(...)`, and `ret()`.
The public borrowed-buffer `f0 -> u32` ABI and the 1 MiB source/output/workspace
limits remain unchanged. Scalar-result discarding, missing effects, leaked
owners and live child loans remain rejected. The exact structural node count no
longer underflows for an empty signature. Empty direct self-tail calls preserve
the same-frame jump and immediate-return requirement.

The source-only cold replay passed all 11 ownership/isolation checks and its
nested native qualification passed **1,917 / 1,917** checks. Both original and
modified-source compiler chains reached their respective machine-byte fixed
points. The `multi` family preserves 43 original scalar cases and 17 original
refusals, adding 20 observations across seven void programs and seven refusals.
The source/reference/discovery regression passed 43 tests. Machine-readable
receipts remain bound to their actual source file manifests, not to this prose.

Historical recovery bundles/manifests remain immutable. CI now validates those
bytes against the original/recovered commits, then independently regenerates and
qualifies the current source; intentionally improved source must not be required
to equal an old snapshot, nor should the old snapshot be rewritten to match it.

## Ordered remaining work and acceptance

1. Preserve the admitted source grammar and capacity accounting while making the
   compiler large enough to implement missing language features within explicit
   resource bounds; do not silently raise a ceiling to hide a layout conflict.
2. Implement all Core scalar types and result/resource transfers, then composite
   type elaboration and complete ownership/loan behavior. Retain independent VM,
   negative-control, native and modified-self bootstrap observations.
3. Implement arbitrary identifiers, module graphs and a general linker/export
   interface in HIA. Compile multi-module programs from source bytes without a
   Python parser or verifier after B0.
4. Replace the interpreter/runtime/library and CLI/build/package authorities,
   then the worker/persistence/optimization/proof-tool implementations according
   to explicit component conformance contracts. Calling the Python implementation
   through an FFI or copying its output is not a rewrite.
5. Rebuild the **entire toolchain** from a source-only clean environment through
   B0/B1/B2/B3 and an actual changed-source fixed point; build real projects,
   install on clean machines and execute all applicable platform/resource gates.

Until those gates execute successfully, `whole_stack_rewritten_in_hia` and
`whole_HIA_language_self_hosted` must remain false. This ledger is the continuation
of implementation, not a declaration that planning or a subset closes the goal.
