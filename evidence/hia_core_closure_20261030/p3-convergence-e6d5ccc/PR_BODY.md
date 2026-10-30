## Why

PR405 already contains the stronger structural IR, capture, frozen-input and artifact-directory protections from the older P3 audit chain. Its C importer still admits one canonical source path while both bounded reads follow the caller's mutable alias. A parent-alias rebind can therefore compile decoy bytes under the admitted source name, or conceal a persistent change to the admitted source during the final recheck.

## Change

Use the admitted canonical source path for both bounded reads. Restore direct source leaf-symlink rejection and non-following terminal opens where supported. Preserve stable parent-directory aliases, existing source-byte limits, real frozen-stdin Clang capture, shared process cleanup, and pinned artifact-directory publication. Add six real-Clang provenance regression methods and include the module in the existing strict migration workflow. No IR/Core/Rust implementation or general migration domain changes are included.

## Validation

- Exact405 implementation: corrected six-method red harness exposes five semantic failures; the normal-path method passes both regular-file and parent-directory-alias conversions.
- Fixed focused bytes: all six methods pass, with seven migration invocations and20 retained actual Clang calls; two admission-stage refusals launch no compiler.
- Frozen local e6d5ccc2c5d1bfc8479f92b0385428ac578c358a: all177 required migration/workflow methods across27 modules pass with zero failures, errors or skips. Existing real original-C/generated-Rust comparisons and deliberately wrong compiled-target control execute within this selection.
- All1087 materialized source blobs/modes match the frozen Git tree before/after; recorded tool executables are stable. Original failing runs, the initial JSON tuple/list harness mistake, corrected red run, green run and source export remain separately identified.

## Limits

This pins the admitted canonical source pathname, not every ancestor directory or source inode. It does not establish general filesystem race freedom, qualify the non-POSIX fallback against hostile directory renames, close general ABI/lifetime migration obligations, switch production authority or change optimization policy. This validation is bound to local e6d5ccc; a later integration/public head requires its own relevant rerun. The implementation preserves405's existing broader256-parameter/256-token IR limits and newer negative-payload/parser guards instead of importing the old branch wholesale.
