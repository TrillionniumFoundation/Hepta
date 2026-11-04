# Guarded entry outlining: opt-in native layout

## Problem and change

The existing checked-reduction pipeline places the complete fast and checked
fallback CFGs in one native function. Actual Clang 20.1.2 assembly on desktop
shows callee-saved register saves before both the length-range guard and the
empty test. An earlier thin wrapper fixes the empty entry but still calls that
combined body for nonempty inputs.

The new `guarded-outline-v1` layout partitions only an effect-free unsigned
entry guard whose two complete successor CFGs are disjoint. Each component is
emitted by the existing function emitter. The public function retains an actual
range guard and tail-dispatches to the relevant complete component. The empty
edge calls the same fast component with zero only after testing the actual
argument for equality with zero; it does not synthesize a constant result.

The layout is explicit opt-in in `emit_program_llvm` and
`build_program_native`. The default is still `canonical`.
Compilation regenerates the exact IR with the same layout before admitting
bytes. Both object inventory checks and transactional publication remain active.
Only Linux x86_64 is admitted for this first layout.

## Correspondence argument and its limits

The recognizer requires two nontrapping entry operations: an actual usize
constant and an unsigned less-or-equal comparison against a real parameter.
Both edges must pass all original parameters unchanged. The successor sets
must be disjoint, cover every remaining original block, never re-enter the
guard, and never have a backedge into either new function entry.

For nonzero input, the same guard selects the same complete component with the
same values. For zero input, unsigned zero is at most the bound, and substituting
literal zero preserves the selected argument. No other argument changes.
A Z3 obligation checks these two scalar properties for all 64-bit lengths and
bounds. Block/operation correspondence is checked structurally, with rejection
tests for missing/shared CFGs, wrong argument transport and backedges.

Every allocation/refusal, load/store, checked operation, trap and release
remains in its original component. Crucially, both helpers inherit the original
whole-function initialization decision; a component's narrower view cannot
authorize malloc or zero-initialization removal by itself. Core bytes do not
change, so this layout does not add interpreter quota steps.

This is not a machine-checked proof of Python-to-LLVM refinement. The existing
compiler, linker, libc and hardware assumptions still apply. Native tests
include a zero input that must abort on checked division, demonstrating that
the empty edge cannot silently replace every function result with zero.

## Performance protocol

`benchmarks/hia_outlined_aot/PROTOCOL.json` and
`tools/qualify_hia_outlined_aot.py` freeze six arms:

- canonical checked HIA;
- canonical verified reduction HIA;
- Rust 1.95.0 O3, fat LTO, one codegen unit;
- the same Rust configuration with explicit byte arithmetic;
- the previous empty-entry wrapper;
- the new outlined entry.

Both original v2 workload/length groups and the previous wrapper's prospective
lengths remain. Eight further lengths and three seeds are registered before
execution. Three separate loads (1, 16, 64 calls), 21 samples per request and all
median/p95/p99 thresholds remain: 1.10 / 1.20 / 1.20 against each Rust arm.
There are 3,348 requests, 70,308 measured batches and 1,898,316 kernel calls.
No sample is excluded or selected by retry.

Current frontend/proof/compiler/load costs, actual memory allocation peaks,
loader segment mappings, process RSS, actual first calls, all raw timing rows
and full build streams are retained. The observer records CPU affinity and
load before/after and for each workload/group/seed. The host remains shared;
affinity does not reserve a CPU. Human engineering, historical acquisition and
energy costs are unknown. The amortization calculation is a warm-median model,
with real cold-first-call observations reported separately.

Before timing, actual Clang 20.1.2 compilation produced a frame-free empty
dispatcher for both workloads. Object sizes increased from 2,400 to 2,800 bytes
(linear) and from 2,888 to 3,456 bytes (affine). These are compile-only
observations and an explicit resource cost, not a speedup claim.
The full prospective timing verdict must be read from the exact-source
campaign result; this document does not pre-authorize performance adoption.

## Commands

```sh
PYTHONDONTWRITEBYTECODE=1 HIA_TEST_CLANG20=/absolute/clang-20 \
  /absolute/python -m unittest tests.test_hia_entry_layout \
  tests.test_hia_outlined_aot_protocol -v

PYTHONDONTWRITEBYTECODE=1 /absolute/python tools/qualify_hia_outlined_aot.py \
  --output /absolute/new-evidence-directory \
  --clang /absolute/clang-20 --rustc /absolute/rustc-1.95.0 --cpu 0
```

Use a CPU in the process's inherited affinity. Output must be a fresh directory
outside the source checkout. Historical negative results and any new failures
remain evidence; they do not change the frozen thresholds.
