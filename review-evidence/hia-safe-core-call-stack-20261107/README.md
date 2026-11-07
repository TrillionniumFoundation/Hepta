# Nonreturning CALL still has a stack effect

This record corrects a concrete unsoundness in the selected Safe Core machine
model. It does not establish a kernel-checked ISA proof or whole-language
soundness and does not authorize production adoption.

## Counterexample

The old x86 model checked call-site alignment, then treated `call abort` as a
terminal outcome without modelling the calling instruction's return-address
store. A controlled faulty producer inserted `MOV RSP, 0` immediately before
that call. The selected Core computes checked `u32` addition, so overflow reaches
the call. The old checker accepted its exact final ELF image with the expected
`sat, unsat, unsat, unsat, unsat` answers.

An x86 CALL first decrements RSP by eight and stores its return address. In this
counterexample that write is outside the caller's admitted stack. A nonreturning
callee does not remove the caller instruction's memory effect. No unsafe
candidate in this record was executed.

## Fix and verification

Source commit `097b0d831ace40f7b7c9b30ac66479961fa92a22` moves the existing CALL
stack update and checked return-address store ahead of the external `abort`
branch. Internal and external calls now use the same checked stack semantics.

The exact scalar candidate previously accepted, SHA256
`78e423c2edf4285e7a214e1598566b31a5c91e71b504499895cc7ee40f0d9066`, is rejected by
the updated model with a `machine_memory_access_bounds` SAT counterexample.
Its witness has `a=2608092046`, `b=3261911607`; their sum exceeds `u32` and reaches
the corrupted abort call. The same object and final image bytes were reused.
The five pre-fix queries and two post-fix queries were replayed in fresh solver
contexts and retained with their original hashes.

The full qualification on the source commit passed **27 tests, zero skips,
three positive images, five semantic SAT mutants, and 29 raw-query replays**.
Regression coverage includes both scalar and borrowed entrypoints with zero
RSP, plus an abort call whose stack decrement exhausts the declared 16 KiB
budget. Rejected safe builds publish no `program.so`/requested output image.
The qualification's explicitly named `candidate.rejected.*` files are retained
static negative controls, not approved execution artifacts.

`raw-evidence.tar.gz` contains the original `before`, `after` and `qualification`
directories. Each retains its own file manifest. `SUMMARY.json` binds the old
and fixed source identity, exact candidate, result counts and archive digest.

## Reproduce

Use the pinned Z3 4.15.4 Python environment, GNU ld and Linux x86-64. Run the
script from this directory in fresh processes and use new output directories:

```sh
python reproduce.py --checkout /path/to/d0635e7-checkout \
  --output /tmp/hia-call-before --expect accepted
python reproduce.py --checkout /path/to/097b0d8-checkout \
  --output /tmp/hia-call-after --expect rejected
python /path/to/097b0d8-checkout/tools/qualify_hia_safe_core.py \
  --output /tmp/hia-call-qualification
```

An `accepted` result here is the reproduction of the old model defect. The
script builds and symbolically inspects the image; it never loads or invokes it.
Existing trust assumptions remain: the Python models, canonical verifier,
identified solver, loader and libc abort contract are trusted. This correction
covers the calling instruction's stack access; it does not prove the internals
of libc, the OS or the hardware ISA.
