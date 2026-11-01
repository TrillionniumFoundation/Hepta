# bd450 fixed-composition CI audit

Source: `bd450cb0ebee40db175011f54d8b34c260d13c49`; tree: `f12a62b33be4b36e2ad5761189c68220552e4501`.

Run: https://github.com/TrillionniumFoundation/Hepta/actions/runs/41258510021 — **SUCCESS**. Job: `124706687202`, 2026-11-01T00:50:33Z to 2026-11-01T00:55:19Z (4m 46s).

Artifact `13064600611`: 1,884,227 bytes. Verified GitHub SHA-256: `a03a5e3ed1b3ccabf6e4b70ef84279f5d368977f6778ca7ffb1620a99679beb2`. Safe extraction retained 360 regular files (9,114,504 uncompressed bytes).

## Fixed combination and tests

All 14 registered qualification stages passed, including GSL upstream upgrade. Source/tool identities remained unchanged; same-combination build/execute/reject/recover is true. All 130 planned tests started and finished: zero failures, zero errors, zero skips.

This is successful execution of the registered checks. The report retains all_seven_research_targets_closed=false, safety_certificate=false and authority=DENY_ALL.

## GSL upgrade requalification

GSL 3.1.0 and 4.0.0 passed: 416 rows per original/migrated pair, six positive pairs, 4,992 observation rows and 14,976 scalar C ABI calls. Actual qualification wall: 2.916384s. Wrong-but-linear control: 325 mismatches detected. Narrowed return/signed argument and duplicate/lost owner negatives were detected.

This rechecks the inherited closed final_action<GslCallback>/finally translator; authored clients and explicit exception-status paths are not counted as automatically translated. No whole-GSL, general C++ exception-ABI, full semantic-equivalence or labor-cost claim.

## New performance result

Valid measurement; Rust gate **failed**, 47/60 Rust comparisons passed. Independent holdout gate and broad Rust parity remain false. Gates are median ratio <= 1.10 and p95 ratio <= 1.20.

| Baseline | Passing comparisons | Passing holdouts | Range of HIA/baseline median latency ratios |
|---|---:|---:|---:|
| hia_checked | 30/30 | 16/16 | 0.3543–1.0891 |
| rust_byte_release | 21/30 | 12/16 | 0.9914–1.2510 |
| rust_release | 26/30 | 16/16 | 0.6380–1.2284 |

Ratios are HIA reduction / baseline; smaller is faster. The 30 cohorts comprise two arithmetic workloads, seven registered and eight held-out lengths each. Quantiles describe 64-call batches on one shared Linux x86_64 runner; neither application-wide parity nor a general performance theorem follows.

## New NDU result

Finite correctness, same-information controls, exact-model agreement and complete cost accounting passed. Native net benefit remains **not established**; 0/3 scenarios beat every control. Nine actual native invocations and three skip-only episodes without native start were retained.

| Scenario | Native / best control service median | Native beats all controls |
|---|---:|---|
| tiny | 1.059984 | False |
| amortized | 1.305119 | False |
| invalidate-recover | 1.411348 | False |

Outer-completed conservative solo campaign allocations (not independently executed solo campaigns):

| Policy | Cost (seconds) |
|---|---:|
| exact_dp | 5.094874042 |
| fixed | 5.057261130 |
| lightweight | 5.069928890 |
| native_ndu | 24.034514145 |

Every policy is charged the common campaign remainder once; native additionally receives the outer-minus-inner bridge-build overhead. The original nested NDU report was preserved unchanged. Three repetitions are exploratory and do not establish a statistical or application-wide benefit.

## Retained files

- ../archives/archive-manifest.json — reconstructs the container whose ci-bd450/ prefix preserves every original ZIP payload file; original ZIP digest remains in ARTIFACT-METADATA.json
- ARTIFACT-METADATA.json — GitHub metadata and digest
- EXTRACTION.json — safe extraction checks and every extracted file hash
- WORKFLOW.json, JOBS.json — API identity and timing; registered command streams remain under the reconstructed ci-bd450/ prefix
- reconstructed ci-bd450/ payload — unchanged uploaded evidence
- SUMMARY.json — machine-readable summary, failed Rust comparisons and stage timings

No local heavy tests, source/ref changes or model calls were made by this audit. Earlier d170 results are not substituted here.
