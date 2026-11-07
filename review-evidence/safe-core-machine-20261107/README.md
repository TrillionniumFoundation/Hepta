# Safe Core retained validation — 2026-11-07

Source commit: `1837d3ba8a542bd4d7c008e7c8c65085a061afbf`, based on
`894d2dfce54ff25271b8de2c18c902394484d5cc`. These are opt-in candidate results.
The deployed v4 cohort and its production task are not changed by this evidence.

- 25 targeted tests passed, zero skips.
- Three positive Core/object/final ELF examples each passed one nonvacuity SAT
  check and four UNSAT obligations.
- Four wrong-backend candidates yielded semantic SAT counterexamples.
- 27/27 original SMT queries replayed in fresh contexts: 11 SAT / 16 UNSAT.
  SAT includes nonvacuity and required negative counterexamples.
- The actual build CLI also completed and retained its attempt receipt.

`originals.tar.gz` contains the original source, object, text, final ELF, query,
query-result, rejection and test-log files. Verify its SHA-256 against
`evidence.json`, then verify extracted files against `original-files.json`.
Files named `candidate.rejected.*` are wrong-code evidence and must not be loaded.

`all_input_refinement_in_independent_model` is the scoped SMT claim.
`machine_checked_isa_refinement_proved`, `whole_language_soundness_proved` and
`default_release_or_production_admission_changed` remain false. The caller's
allocation liveness/exclusivity, available stack, genuine libc abort, loader,
Python models and identified Z3 remain explicit assumptions.

Re-run `python tools/qualify_hia_safe_core.py --output <new-directory>` for the
current checkout. Do not substitute these old source-bound receipts for a new
combined candidate's own run.
