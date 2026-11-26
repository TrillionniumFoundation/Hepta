# Native verifier explicit retirement

This component is qualified with the exact eleven-role native Value product
`6aa48162de9636fd9a3a4552efce0cfa789e007db36aa261a1f3291134ea27b4`.
The final resource-capable Value and complete public BackgroundOptimizer still
require their own integrated qualification.

## Runtime interfaces

| Owner | New request | Captured context | Reply |
| --- | --- | --- | --- |
| verify_program | HIABVFY3 / HIABVFY4 | HIABVYC2 | HIABVFR2 |
| Typed structure | HIABTC03; cleanup HIABTC04 | HIABVC02 | HIABTV02 |
| Lossless transport | HIABIQ02 | HIABIC02 | HIABIO02 |
| Checked value freeze | HIABFZQ2 | HIABFZC2 | HIABFZR2 |

The old private profiles and their input bounds remain supported. New verifier
requests preserve the original canonical/structured input, error ordering,
8 MiB budget, depth 64, 262144-node budget, integer policies, and live native
dependency calls. Context extents remain 4096, 128, 256, and 2048 bytes.

The verifier reply uses retained at 56, quarantine kind at 64, and pending at
72. Kind 1 permits known cleanup only. Kind 2 preserves custody and refuses
effect replay. Nonretained replies have both additional fields zero.
The nested structure reply uses kind/pending at 112/120; transport uses
retained/kind/pending at 48/56/64; freeze uses 56/104/112, preserving its original
Unicode error fields.

## Ownership

The new owners execute HIABVQ02 release 29 and validate its explicit
known/consumed/pending response. A consumed ticket is cleared from its actual
stored slot before a result can be quarantined. Transport writes its changed
heap frame back before returning. Confirmed pending retirement uses the
original Value retry operation 31 and never resends an already consumed cap.

Known preconsumption failures preserve the exact ticket. Unknown or
inconsistent results preserve the whole relevant continuation and use kind 2.
An explicit cleanup request cannot turn kind 2 into another release attempt.
Immutable payload release has its own preconsumption status domain.

New file-descriptor cleanup uses the actual single-descriptor close_range
operation and clears custody only after success. Actual munmap failures retain
both address and extent. Caller, snapshot, frozen payload, process output,
normalizer duplicate, and nested continuation custody remain distinct.

## Actual qualification

All seven HIA policy/packer modules compiled twice with the original compiler
and produced identical bytes. The three native packers produced objects equal
to independent relocation references. Mechanical assembly matched the retained
bridge bytes. Host linked shared objects were used only as external QA loaders;
they are not native production build inputs.

Both old and new verifier profiles passed the unchanged 423 original cases:
846 comparisons in total. Each profile passed 103 private controls.
The original 14 verifier ownership/failure/concurrency groups passed.
The typed structure's original 272 comparisons, original 16 integer groups,
private guards, and original three cleanup groups passed.

Both transport profiles passed the original 30 smoke groups and 266
transport/capture/freezer groups. Both freezer profiles passed the original 226
whole-component groups. Original transport and freezer controls passed 22 and
16 groups respectively, with the retained malloc/free qualification hook.
All three original native packer gates passed 24 controls each.

Three actual kernel policy failures passed on unchanged native instructions:
close_range refusal, verifier munmap refusal, and last-cap Value arena munmap
refusal after the actual caller anchor was released. All used the same retained
native context for successful cleanup. The final Value case observed
consumed-with-pending, then actual retry 31 cleared and unmapped the arena.
All checked caps, payload owners, descriptors, and mappings were recovered.

Nine separately labeled dependency-response controls covered structure,
transport, and verifier release: known unconsumed refusal, unknown reply, and
known consumed but otherwise inconsistent result. Known refusals drained;
unknown outcomes remained isolated without duplicate effects. These controls
are not claimed as kernel fault tests.

The exact evidence and preserved unsuccessful development-runner attempts are
recorded in HIA_NATIVE_VERIFIER_RETIREMENT_QUALIFICATION.json. Existing native
source, original assertions, compiler limits, and original test domains were
not changed to accommodate those runner failures.

## Release boundary

This receipt qualifies these verifier components with the pinned Value image.
It does not qualify the resource-capable Value revision, full public
BackgroundOptimizer, unified dispatcher, final cold build, installation, or
production activation. Those gates remain explicit in the final assembly.
