# Closure CI retry on bd450

Source: `bd450cb0ebee40db175011f54d8b34c260d13c49`.

[Workflow run 41258514699](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41258514699), attempt 2, job 124712953325: **success**. The job ran from 2026-11-01T01:19:42Z to 2026-11-01T01:29:21Z, 9 minutes 39 seconds.

- Unit suite: **175 tests in 335.036 seconds, OK**, zero failures, errors, skips or expected failures. The planned-versus-executed count gate passed.
- Lean register safety: 14 theorems, 3 negative controls and 272 VM cases.
- Optimization resource contract: 4 exit cases, 2 budget-difference cases, 3 rejections and 13 tests.
- Actual C++ callback migration: two variants with 1,185 cases each, 2,370 cases per implementation. Automatic migration wall was 82.919145986 seconds and qualification wall was 99.848403817 seconds. Human engineering time remains unobserved. C++ timing is descriptive, without a relative speed pass gate.
- Migrated Core call expansion: 5 profiles, 1,784 native observations, stable sources and captured component. The report expressly leaves backend refinement, global safety theorem and performance qualification false.
- The separate optional original-native NDU job was **skipped by its workflow condition**. This is distinct from the zero skipped unit tests and provides no additional native NDU result.

## First attempt and recovery

Attempt 1 is retained in `../closure-attempt-1/`. It was cancelled while `apt-get update` ceased progress during dependency setup, before source tests started. The timing matches the configured 25-minute job limit. LLVM key and repository metadata downloads had succeeded. There was no explicit HTTP error in the available log.

The retry used the same source commit. Root received a successful single-job retry response; a prior child request had been interrupted without a response, so exact request attribution is not asserted. No attempt above 2 was observed. Successful fixed-composition and native-performance workflows were not rerun.

## Artifact identity

- Artifact ID: 13065366749; 2,193,221 bytes.
- SHA256 reported both by GitHub API and upload log: `2de9f828f1417a8a43a6ac2c39283fce5c32651f4dd80e4a600009e571bf378c`.
- The archive was not downloaded in this closeout, so no local byte-digest recomputation is claimed. Primary fixed-composition evidence was already downloaded and separately verified.

All **8/8 workflows on this exact head have latest conclusion success**. This does not change the negative performance/NDU findings or close all seven research goals.
