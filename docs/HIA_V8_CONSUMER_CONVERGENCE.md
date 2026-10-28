# Converging the existing v8 resource consumers

This document records the scope of checkpoint
`f882b4bb02d39bc1dbe0d2237aac69a51469ae0a`. Its tests and limitations belong to
that source identity. The subsequent chain/original-type/native lifecycle
convergence is documented in
[HIA_BLOCKER_CONVERGENCE_20261028.md](HIA_BLOCKER_CONVERGENCE_20261028.md);
the earlier chain-execution refusal below is not the current v5 profile.

This increment starts at recovered checkpoint
`0f0f78fa1aa2360c901385de0fc70275b8db4954`, itself descended from public
PR #329 `817713b163b6812a6516179951412b4a6c93ae2b`. It keeps the same v8
language semantics, canonical Python `verify_core` authority, direct LLVM
backend and Agent return-origin contracts. It does not create a new IR or
promote a shadow/proof/analysis receipt into executable admission authority.

## Independent Rust execution

The existing Rust ownership checker and resource Machine independently check
and execute finite parameter-bound returned loans. Original input origins
survive CFG renaming. Calls instantiate returned capabilities from their
declared actual arguments. Forwarding makes a new child; transferring a direct
child does not count a second loan. Errors and budget stops retain actual
resource state. Versioned owned-v8 receipts and execution profiles coexist
with unchanged v1–v7 wire contracts.

See [HIA_RUST_RETURNED_LOANS_V8.md](HIA_RUST_RETURNED_LOANS_V8.md). Chain
checking is static only, chain execution rejects, scalar-only Rust remains
v1–v7, and the Python Core remains mandatory for production admission.

## Separate resource quantities

The existing call-graph and interval/CFG engines now expose separate v8
contracts for root-inclusive synchronous frames, acyclic byte-owner VM events,
and public-scalar-entry requested live payload. Private borrowed helpers retain
unknown external roots and summarize only their additional local payload.
The caller still accounts for its live owners; returned-view lengths map back
to their verified actual roots. Unknown extents, recursive calls and unsupported
resource flow reject instead of acquiring a sample-based bound.

See [HIA_V8_RESOURCE_BUDGETS.md](HIA_V8_RESOURCE_BUDGETS.md). The old
all-function heap API and source-facing native consumer keep their original
version boundaries. None of these quantities proves RSS, native-stack size,
CPU time, termination or cleanup after a stopped execution.

## Direct LLVM on two emulated architectures

The finite cross-target qualifier uses the existing LLVM emitter, object/ELF
inspectors and bounded runtime. It actually links and executes returned-loan,
recursive, chain-head, allocation-failure and trap cases under AArch64 and RV64
QEMU. It retains compiler/linker/emulator commands, original result/resource
lines, target identities and compiled wrong-result/free-removal controls.

See [HIA_RETURNED_LOAN_CROSS_EXECUTION.md](HIA_RETURNED_LOAN_CROSS_EXECUTION.md).
The public ABI still exposes only scalar wrappers. Emulation does not qualify
physical hardware, callbacks, external borrowed lifetimes or device timing.

## C parameter entry effects

PR #331 `3c2e647ee459ca073c58d1ad03be0622b3877436` is selectively integrated;
its initial two-path source-end guard and tests are retained in the commit
history. Its previously unexecuted project test used an unsupported capture
flag, `-Werror=vla`, so it initially failed at driver admission. The test now
uses an admitted capture configuration; the separate native warning-suppression
control remains. The capture flag allowlist was not expanded.

Actual earlier-source native comparisons found that both ordinary and
record-view array parameters could lose entry effects: with input `n=7`, the
original C returned `8` while the generated native function returned `7`.
An identifier-end check alone also misses `typeof`-wrapped VLA parameters.
The current finite spelling gate is applied before parameter type
decomposition and binds the declaration to captured physical source bytes.
It refuses unsupported adjusted/computed declarators, rather than rewriting
them as pointer contracts. The responsible declaration retains its diagnostic
code separately from later unattempted declarations.

See [C_MIGRATION.md](C_MIGRATION.md). This is a finite admission repair, not
a universal C declarator analysis, source-equivalence proof or arbitrary C++
migration qualification. Native counterexamples retain the exact earlier
source identity that produced them.

## Combined qualification and remaining work

Freeze a clean combined commit before invoking `tools/qualify_hia_integrated.py`.
The new mandatory coverage groups must occur in its one complete Python run;
do not add selected suites, qualifier replays or auditor checks to that test
denominator. Cargo has a separate denominator. Re-run the v8 Rust, budget and
cross-target collectors on that same combined commit to retain detailed raw
observations and compiler/runtime identities. Failed development attempts
remain identified and do not become successful evidence after a fix.

The P0–P7 goal remains broader: general memory/provenance, arbitrary recursive
ADTs, complete partial initialization, asynchronous cancellation and external
lifetimes still need their own semantics and counterexamples. Cross-platform
ABI, real-project migration costs, held-out Agent/model benefits, service
throughput/tail latency, physical devices and end-to-end soundness/refinement
require actual qualification. Existing scalar/compositional optimization
proof profiles still return unknown for v8. Remote publication and source
identity must be checked separately from local test success.
