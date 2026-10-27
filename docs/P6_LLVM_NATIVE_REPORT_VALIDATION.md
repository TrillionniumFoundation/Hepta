# Native scalar32 performance report validation

The release gate imports tools.qualify_llvm_native.validate_report(report).
It returns None only for a complete successful report for the current compiler
and qualifier source; all rejections raise ValueError. A caller that knows the
release candidate commit can additionally supply expected_git_commit=full_SHA.

The validator performs no native compilation, native loading, or measurement.
It binds the retained report to:

- The unchanged frozen v2 protocol and exact Hepta and C driver source hashes.
- The current qualifier file and compiler source hashes, plus a recorded Git
  commit (an exact candidate commit when the optional argument is provided).
- A fresh frontend, CFG, SSA, verifier and LLVM replay of the fixed Hepta source.
  The Rust metadata check and actual Rust library/object receipts must identify
  the pinned Rust toolchain, checked overflow, abort-on-panic and optimization
  settings. LLVM library/object receipts must identify the same fresh SSA and
  LLVM, native Clang and source-origin recheck.
- All six library, object and driver artifact hashes and sizes, with compiler
  receipt identities cross-checked against the artifact inventory. The driver
  compile/link arguments and artifact/source paths are bound as well.
- All 186 independent Python oracle cases and 372 recorded native invocations.
- All 42 raw samples in their frozen interleaved order, with exact field types,
  stable per-kernel checksums, clock data and a fresh evaluate_samples result.
  Sample deletion, reordering, edited summary statistics, a changed threshold,
  or an outer success flag on an inconclusive result cannot satisfy the gate.
- Host affinity, load observations, finite compilation timings and the narrow
  claims: only finite scalar correctness and this host scalar32 performance gate
  may be true. Whole-language performance, owned/borrowed lowering, refinement,
  universal superiority, heap costs and cross-target execution remain false.

This is a consistency validator for retained execution evidence. A JSON report
is not a signed execution attestation: the validator does not authenticate an
arbitrary third party or reconstruct removed native binaries from their
digests. The release runner must execute the qualifier on the candidate source
and retain the resulting report.

The two archived first-run reports remain unchanged. Neither passed the frozen
measurement-quality gate, and neither is retroactively qualified by this
validator. Unit tests use explicitly synthetic constant sample durations to
exercise the acceptance path; those fixtures are never published as measured
results.

Validation performed without collecting any new timings:

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_llvm_native_qualification_policy -v

The 10 tests cover the five original threshold rules and successful synthetic
validation, candidate binding, source/build/claim tampering, incomplete or
modified oracle/sample inventories, retained noise failures, and performance
regressions.
