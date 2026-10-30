# Composite v4: public source and finite execution evidence

Public commit: `99cf106586509b08bb2b9890ed29cf042336d69e`.
Public parent: `adbe4a1168a84d0696749ef54f933994b5dc554c`.
Exact tree: `c2afb20ce0eb14ff3a7750ff123d8f9bfa8842e2`.
Local component: `e21d672eb1bc588e248f72b0217b922671a869a5`.
Local parent: `bf143a7ebf12e4a7013c0dd41fe23d14ad3e5ec7`.
Both parent trees: `04b70dccc157af470aa2b5bdeb74e6f88dbff5bf`.

## Included evidence

- `public/`: fresh exact-public source comparison of all 14 changed raw blobs,
  modes and SHA256 values; per-command argv, environment whitelist, UTC time,
  elapsed time, stdout/stderr; actual public composition 13/13, Rust API v4
  8/8, legacy regression 98/98 and the CLI example returning 37.
- `local/`: original exact-local composition 13/13 and legacy 98/98 receipts.
  Local source identities are unchanged and are not relabeled as public runs.
- Both composition receipts have 153 actual Rust comparisons, four raw Rust
  refusals and 31 native calls. The public stacked API receipt independently
  retains 155 comparisons, 37 raw refusals and eight legacy-version sets.
  Method and observation counts describe separate overlapping scopes.
- `peer-review/`: the immutable independent review archive plus readable review
  and public-tree mapping. Independent executions remain bound to local e21:
  two Python/two Rust/two LLVM mixed-result/mutual-recursion cases, four Python
  refusals, one raw Rust refusal, and four actual allocator calls on two
  distinct failure indices (two initial observations plus two identity-bound
  replays). This is a finite review, not a second full release.
- `source-export/`: 14 changed raw UTF-8 files, exact modes and old/new Git blob
  IDs, SHA256 identities, full-index patch and an independently reconstructed
  final tree. Original PR draft and public-rerun script are retained unchanged.
- `source-publication/`: original public-source receipt. Its false execution
  flag is explicitly a historical snapshot taken before the new public runs.
- `development/`: preliminary test records and the seven-byte observer
  investigation. The original diagnostic is a labeled copy from the tool
  transcript; reproduction.json contains new actual process observations.
  The observer classifies only 1-byte payloads and 24-byte nodes. Size7 caused
  unknown_sizes=1 while every result/allocation/free/live/peak counter matched
  Python. The allocator case now uses the declared size1 fixture; nine-module
  native scalar calls retain sizes1,7,19. No backend change hid a discrepancy.
- `executables/`: actual Rust executable bytes, bound by the original local and
  public receipts. Identical executable bytes are stored once; run identities
  and compilation source identities remain separate in the manifest.
- `review-support/PR_BODY_PUBLIC_VERIFIED.md`: ready public PR description with
  the new execution observations. It does not mutate the earlier export.

The reviewed safety registry selects 116 unique methods, retaining all previous
103 and adding 13. This package does not claim that the full 116-method safety
gate or integrated release was executed. Current LLVM20 execution used the
isolated Ubuntu20.1.2 package build on a Debian13/GCC14 host, distinct from prior
Ubuntu-host qualification. Raw reports retain compiler, Rust and source hashes.

This increment closes the finite nominal partial-record/primitive returned-loan
composition gap. Python remains production admission authority; optimization
policy is no_change. All historical routes, general memory/provenance, arbitrary
recursive ADTs, complete partial initialization, escaping stored loans,
external lifetimes, full cancellation/error cleanup, callback/reentrant/thread
ABI, process-memory/performance/device and refinement/soundness claims remain
outside this finite qualification. Whole P0/P1/P2 and P0–P7 closure is false.
