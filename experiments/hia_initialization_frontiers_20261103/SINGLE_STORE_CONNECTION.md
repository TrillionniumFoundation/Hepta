# Proposed single successful store connection

Design only. This is a narrow next obligation after the read-only ledger, not a
proof implementation or authorization. All twelve connection obligations remain
unproved. DENY_ALL, actual_core_bridge_proved=false, zero initialization unchanged.
No Lean/native execution or new memory model is introduced.

## One proposed commuting step

Use the existing HiaInitializationPrefix.Memory and write, write_at_index and
write_at_other. The operational side is one actual `buffer.store` in reverified
Core executed by `hepta/hia_program_runtime.py`, not a synthetic replacement.
Bind the exact operation ordinal and ordered operands to the runtime environment.

A concrete owner has bytearray data D of length L. Introduce a specification-only
set W of indices explicitly written by successful program stores to this live
allocation instance. Allocation starts with W empty, even though production D
is zeroed. The set is a ghost observation, not a reason to skip zeroing. Define
the projection into the EXISTING Memory type as:

- address a in W and a<L: some (BitVec.ofNat 8 D[a]);
- every other address: none.

This projection deliberately tracks explicit-store provenance. Projecting every
zero-filled runtime byte as some byte would make initialization coverage vacuous.
The model's none does not claim that an actual production byte is undefined.
Require W to be a subset of [0,L). Track allocation identity by a retained live
owner reference/epoch, not reusable Python id alone or the static SSA root name.

For actual successful `buffer.store(view, i, v)`, require all of:

1. Verified operand types usize/u8 and their runtime interpretation: 0<=i<2^64,
   0<=v<256. Python's negative indices and bool/int subtyping must not become an
   alternate Core semantics through direct helper calls.
2. The ordered environment lookup denotes the specified i,v and view. Every
   active view-parent link resolves without cycles to this exact live owner.
3. The immediate view is mutable, as checked by the real operation; legality of
   creating that view and exclusive borrow discipline come from separate trusted
   Core/resource validation, not from this projection.
4. i<L and the real assignment returns normally. A budget stop before operation,
   stale owner/view, invalid borrow or bounds trap is not a successful store.
5. The bytearray assignment modifies only D[i], preserves length and other owner
   data; Python/bytearray execution semantics remain a declared trust boundary.

The proposed post-state has D'[i]=v and D'[a]=D[a] for a!=i, W'=W union {i}.
The desired equality is projection(D',W') = write(projection(D,W),i,ofNat8(v)).
This splits exactly into write_at_index and write_at_other. It does not require
the store value to be independent of previous loads: that stronger condition is
needed later to reuse completed_fill_independent_of_initial, not for one write.
An overwrite is valid for this local relation but need not extend a contiguous
prefix; write_extends_prefix additionally needs the prefix and schedule premises.

## Falsifiable controls before proposing a theorem

Future tests should instrument the existing successful operation boundary without
changing its implementation or initial data. Compare pre/post snapshots for every
byte of small bounded owners, every valid index and representative u8 values,
including same-value overwrites and repeated writes. Check the specification-only
W event is added only after success. Include another live owner with different
contents to detect wrong-root projection; preserve strong references across both.

Required negative/control cases:

- zero-length owner and i=L reject without a W update;
- explicit store of zero still adds W, while an allocator-provided zero does not;
- a second owner's equal-sized buffer cannot reuse the first owner's W;
- owner drop plus new allocation cannot inherit W, even if an identifier repeats;
- immutable/expired/nested-expired views and cyclic parent links reject;
- invalid negative index or out-of-range byte is rejected by Core/type boundary,
  not used as an unverified call into the private VM helper;
- wrong operand order, stale operation locator, changed stored value and phi
  transport mismatch invalidate the connection receipt;
- budget interruption before the store cannot appear as a normal post-state;
- a second write outside i, a changed length or incorrectly recorded root must
  falsify the proposed frame equation.

Some adversarial runtime-object cases cannot arise from verified Core. Label
those as boundary unit probes, not valid program counterexamples. Finite tests
would only test the projection implementation and specified cases, never prove
all Python states. Reuse the existing observer where appropriate but do not let
its recorded success substitute for the actual pre/post bytearray comparison.

## Explicit exclusions

This single-step relation does not establish allocation success coupling,
all-path loop completion, graph-to-trace refinement, initial-byte-independent
value schedules, post-completion resource frames, output equivalence or LLVM
memory semantics. It does not prove caller-side well-typed runtime invariants;
those must be separately derived or explicitly trusted. It cannot preserve quota
merely by relating memory: the known reference20/deferred17 counterexample stays.
The executable Python VM, parser/Core verifier and resource checker are not
machine-checked by referencing existing Lean lemmas. A future theorem needs a
precisely stated operational projection and proof, not a ledger status upgrade.

## Isolated observation implementation

`tools/observe_single_store_projection.py` now wraps the real ordinary-VM
operation in a temporary single-process patch. It binds the actual operation
object to its function/block/ordinal, snapshots every live owner's actual bytes
and resource counters before/after each store, and retains owner objects for
invocation-local epochs. W changes only after a store returns successfully.
The finite checker compares the exact changed byte/W union and frames all other
live owners, then checks the finite projected-memory equation. It is not a Lean
proof or an authenticated certificate verifier. Snapshots/JSON are research data,
not evidence accepted by any production entry point.

Observation bounds are at most 65,536 live byte entries per snapshot, 4,096 store
events, 262,144 total pre/post byte entries, 16,384 total pre/post owner
rows (including zero-sized owners), and 4,096 retained owner epochs.
Crossing a bound disables further observation, lets ordinary VM execution
continue, and forces observation_complete/finite_frame_matches=false. Explicit VM
step/heap limits remain separate and unchanged. Before/after source identities
bind the observer, relevant Core/runtime/ledger code and model descriptions; they
are not atomic execution snapshots against a hostile concurrent host.

A run with zero stores can have no local frame counterexample but proves no
coverage; observed store and successful-store counts are explicit, and
all_program_loads_covered_claim is always false. The observer's dynamic monkeypatch
is unsuitable for concurrent VM use. Tests remain finite and retain all twelve
unproved obligations and DENY_ALL regardless of a matched local frame.

The 20 permanent tests include real deferred-Core fixture runs, every index of
small buffers with representative bytes and overwrites, bounds/budget/refusal
outcome preservation, two live owners, repeated allocation sites and drops,
changed-source/observation-bound refusal, actual instruction locators and tampered
frame data. Invalid private view graphs are clearly labelled boundary unit probes,
not verified-Core counterexamples. A negative control explicitly shows that
altering only the locator does not invalidate the local byte-frame equation:
`audit_store_event` is not a transport authenticator. The existing Python-only CI
adds these controls to its exact 82-test zero-skip inventory, without artifact
upload or native/Lean execution.

An additional bounded local matrix used the two exact deferred fixtures with
n=0..16 and seed=0,1,255: 102 runs and 816 successful store events. Every observed
local frame matched, and VM outcomes/resources equalled unobserved execution.
This exercises only the original small-input fast path and remains finite
observation, not a proof or slow-path/native/performance result.
