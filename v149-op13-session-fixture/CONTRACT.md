# Native05 session fixture successor

This is one unapplied helper change. All production files and all existing test
bodies, IDs, assertions, limits, and observer implementations remain byte exact.
The original R2 Native05 failure remains an actual failure.

## Concrete cause

The failing observation is late-public-alias-False. It uses the original op13
effect through the reference selected CLI, before the new Patch policy executes.
CliSession.__init__ prepares arguments and an initial packet but does not assign
consume_mask. The existing helper called _effect(35) directly, which imports
providers but does not perform the original step initialization. Native05 then
calls _effect(13) directly and reaches argument(b, 1), which reads the absent
consume_mask. This is a fixture lifecycle defect; it is not evidence that the
new op13 policy altered captured-alias semantics.

## Exact correction and boundary

Only the helper's imports=True branch now calls the original session.step(),
requires the exact real first import command and its zero consume mask, then
calls the original session.observe(). The original step supplies the field from
the actual HIA command; observe performs the real claim and the original import
effect. It produces the normal ACK packet. No fixture field, result, claim, or
ACK is invented and no production constructor or continuation is modified.

The imports=False path is unchanged, including no step and no provider import.
Native04 still controls both original imports and the update commit/failure in
its original observation scope. Existing explicit consume_request controls keep
their original code and do not become a claim about full CLI execution.

The additional real step registers the fixture session in the original active
session table. Direct-effect fixtures remain partial continuations: close does
not synthesize a terminal plan, release, or ACK. No all-sessions-retired or whole
CLI claim follows. Native12's direct prepare/weak-reference path does not use
this helper and is unchanged. New setup control-image calls are preserved by the
existing real journal; observation deltas use the original per-observation
baseline. Only the existing full CLI cases complete their original lifecycle.

## Required future binding

A successor must create an independent 3210-file source view, change exactly
tests/hia_patch_cli_support.py, and update its corresponding projected-map and
origin descriptor. Source8 and Native12 tests retain their full original bytes.
All 16 owners and eight actual builds must run anew under the original limits
after independent review and authorization. No earlier passing stage is carried
over as this successor's result. This authoring does not authorize a binder,
source copy, compilation, project import, product, or test execution.
