# Unified candidate: executed checkpoint, 2026-10-25

This is an executed checkpoint, not closure of the entire language roadmap.
The code candidate is `776f005d0f709c5033d513f113b4e4175e5be035`
(tree `f811842173ae41e23c52ee46bbe8d5df3b5e78d0`).
All **40 planned gates passed**, including **1,287 tests with zero skips**.
The source snapshot before and after qualification is identical:
`940d204d11807b774e53b2c3e4f8ffe362c4071b541c8b87477771cd700ceead`.
The full raw result is [release-validation.json](release-validation.json).
The current seven-stage account is [stage-ledger.json](stage-ledger.json).
An evidence-only child commit does not change the qualified code bytes.

## Native evidence

- Complete selected C++ scalar class implementation: 1,777 differential cases
  for each of the Rust and independent C paths, 3,554 comparisons total.
  No original C++ class implementation is linked by either Hepta path.
- C++ automatic scoped object lifetime: real standard-library use and actual
  success, constructor failure, method failure and allocation refusal paths.
  These objects still execute in C++; they are not rewritten resource classes.
- Resource graphs: independent checks plus a fresh source/import replay and
  native Rust reference validation. These establish the documented profile,
  not a whole-language refinement theorem.
- Pinned Lean: real binary identity, actual process results and mutation
  controls, rather than trusting arbitrary printed theorem names.
- Strict namespace workspace and crash/recovery fixtures executed; these are
  scripted evaluator qualifications, not real model productivity experiments.
- [Windows original receipt](platform/windows-x86_64.json) comes from real
  GitHub Actions Windows runner job 121219223339, run 40210077217. It observes
  181 Rust/C ABI calls at each of O0/O2 and an actually rejected wrong C echo.
  [Receipt replay](platform/windows-receipt-replay.json) accounts for the
  runner's CRLF checkout using exact reconstructed source bytes. It does not
  repeat Windows execution on Linux or qualify the LLVM backend on Windows.

## Frozen scalar LLVM performance

Protocol `hepta.llvm-native-scalar32-perf.v2` was fixed before this run.
All 42 samples and previous inconclusive runs are retained. There is no
outlier removal, result selection, or threshold relaxation.

| Workload | Median paired LLVM / Rust elapsed ratio |
| --- | ---: |
| signed_walk | 1.0048292512 |
| unsigned_walk | 0.9862790145 |
| branch_accumulate | 0.8189559446 |
| Geometric mean | 0.9327906849 |

Every per-implementation relative MAD is below the predefined 5% maximum;
all samples exceed 50 ms; the geometric mean is below 1.10 and each workload
below 1.20. These are three scalar workloads on this host, not proof of
universal superiority or resource-owning-program performance.
See [llvm_native.json](llvm_native.json) for all measurements and identities.
Earlier v1 and v2 first-run inconclusive reports remain in the parent
`evidence/` directory; the current result does not replace them.

## Remaining work

The stored-loan independent verifier, true nontrivial C++ resource-owner
migration and independent LLVM owned-memory path are the next implementation
vertical. General lifetime/type generics, global resource accounting, real
upstream upgrade costs, controlled live-model tasks, production services and
physical hardware qualification remain separate obligations. Unsupported
features, missing observations and unproved general claims are not converted
into a passing checkbox by this checkpoint.

## Archive and reproduction

Original JSON and text logs are retained without editing. Generated source
files are also retained. Native executables stay in the local run directory;
[archive-manifest.json](archive-manifest.json) records their content digests
and explicitly marks them as not Git archived. They can be rebuilt by the
commands in the raw release report and the locked toolchain bootstrap.
No platform-dependent executable is added to Git.

The preintegration failure log and baseline count are preserved to show the
issues actually repaired. [execution-prerequisites.json](execution-prerequisites.json)
records absent live-model credentials and network/device observations without
reading or exposing credential values.
