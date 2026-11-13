# HIA v85: first real combined source materialization

This is an additive development checkpoint, not whole-native qualification.

## Actual execution

- Fixed inputs: main f33d8da316de8fdf27b504371f1a5310997ff548 and development a733926a2786a3d4a37304bd2d18ebb2eac57ac9, with both original merge bases retained.
- Harness commit: 97b869129993f450f17bc632ab6da21c9a504a75.
- GitHub Actions run 43379129114, job 131732539209.
- The real merge resolved all 122 conflicts using 285 authored files, 36 exact-retained files, and 185 regeneration seeds.
- All 1,439 Python files parsed and compiled under Python 3.14.4.
- The first checker inventory generation returned 1. None of the 109 owner generators or complete Source test bodies ran in this attempt.
- The exact exception was: ValueError: unreviewed dynamic import mechanism: hia_proof_contract.py:_safe_core_method_reference.
- The terminal snapshot records all 3,039 non-.git files. New or changed content is captured completely; unchanged original bytes still depend on the four fixed Git commits explicitly named by the manifest.

## Complete failure custody

The first-real-source-run directory contains the original result, full job log, exact command record and stderr, manifest, and all 49 ordered gzip chunks. Concatenating the chunks produces 25,597,017 bytes with SHA256 51788472830bf7e983ee220e6e5a3ea2c33be7bf81b08b6ed97b6bf88db0c173. The archive is not falsely described as self-contained: fixed original Git dependencies remain required.

The original Actions ZIP (artifact 14015512106) was also downloaded locally. Its complete 78,366,629 bytes matched SHA256 e09710a316997174899e56ab1b2272d16d6eb7ff7c83da1c6114dfb380762d25. All 1,433 outer member CRCs and SHA256 values were checked; all 1,178 inner tar members were checked against both the Git manifest and corresponding outer raw members. Every ordered gzip chunk was independently checked against its size, SHA256, and Git blob identity. The complete readback inventory is included.

## Source provenance and later drafts

The executed harness and new authoring packets are retained verbatim. The main f33d incremental packet had a stale test preimage; it was not applied directly. The corrected packet retains the final Surface test outside the single native-step-order method and preserves BytePolicy registration.

The rust-artifact fix adds only the 61-byte upload-path line for hia-rust-caller-inputs.sha256. It is authored, not executed in the first run. The normalized wrapper changes metadata layout only, retaining exact source bytes.

The materializer r6 draft adds bounded failure diagnostics to the job log while keeping complete original streams in evidence. It passed local Python 3.12 AST/compile only and was not the materializer executed in this run.

No existing qualification is transferred to this composition. Whole-native remains false. Product refs, defaults, and legacy production implementations have not been changed or removed. Original test and execution budgets remain intact. Work continues with the exact checker counterexample, then complete generation, Source, and Native/cold qualification.
