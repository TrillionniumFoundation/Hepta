# B full NDU artifact: independent read-only review

## Decision

**The original artifact contains a complete, positive bounded kernel performance result. It does not establish stable incremental NDU benefit or complete economic benefit.** These are separate conclusions, and the earlier scalar/controller negative observations must not erase this kernel result.

The independently recomputed `narrowed-reduction-parity` experiment passes all **9 training comparisons and 21 independent holdout comparisons** against its registered C, C++, and Rust controls. The distinct-code guarded opportunity experiment completes all **84 registered samples**, but neither of its two modules passes the opportunity gate after the measured search cost. The three native-policy experiments each retain a complete 12-row policy cohort, with **zero native NDU policy invocations** and all net-benefit claims false.

This review grants `PASS_READONLY_EVIDENCE_RECONCILIATION` for the checks stated below. It grants no new compiler, solver, loader, machine-code, whole-language, deployment, or economic qualification.

## Exact original identity

| Item | Exact identity |
| --- | --- |
| Source commit | `6ecd8023615a6e0b2dc269379fb059c656b38b6f` |
| Source tree | `4c51962e030e9ea39c6498224c99eb40fbdd2f35` |
| Original CI run | [42565815059](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815059), attempt 1, success |
| Original job | `128991965937`, `verified-native`, success |
| Original artifact | `13653895483`, `hia-verified-optimization-6ecd8023615a6e0b2dc269379fb059c656b38b6f` |
| ZIP bytes / members | 19,759,307 bytes; 1,796 members; 227,392,009 uncompressed member bytes |
| ZIP SHA-256 | `d8ad94fe9ab18679c1475de2e490c03620081e58bad52654031c73253e2d1dff` |

The ZIP was hashed independently and matches the saved official GitHub artifact digest. Its source files, original run metadata, and actual job checkout log identify B itself. This job explicitly checked out the head commit; it is not being described as a default merge-ref job. No result from an earlier head is transferred to B.

The reviewer read 117 selected original ZIP members without extracting the entire artifact and compared **238 distinct source blobs** with the exact Git tree, checking both Git blob SHA-1 and file SHA-256. These include the 214-path opportunity map, 231-path parity maps, 226-path native-policy maps, 216-path loop map, frozen opportunity protocol, workflow, and checker dependencies. Overlapping maps are not counted as additional distinct sources. The opportunity report also contains an unchanged 9,833-entry tracked-file snapshot before and after its run; this review checked its equality and commit/tree identity, but does **not** claim to have independently read all 9,833 Git blobs.

Original API metadata, job log, protocol bytes, and selected proof receipts are preserved in `originals/`. Every analyzed original member has its own hash and byte count in `analyzed-original-members.json`. The complete source ZIP and complete retained-member collection remain separate evidence, including members outside this review's scope.

## 1. Complete kernel performance samples

The registered workload allocates an owned byte buffer, fills and sums it, returns the checksum, and releases it. All four backends use allocator instrumentation. The finite domain uses three training sizes, seven distinct holdout sizes, three seeds per size and phase, and four backends. Each native request records 21 timing batches of 64 calls, with the registered warmup policy.

For **each** of the three parity profiles, this review reconciled all 24 raw JSONL transcripts with all 120 result rows, including request identity, all timing values, checksum, allocator metrics, load/mapping acknowledgments, clean close, and exit. It independently recomputed the statistics from all 2,520 timing batches per profile. Across the three profiles, that is **72 transcripts, 360 requests, and 7,560 timing batches**, with no trimming, rerun selection, or missing registered request.

| Original profile | Training comparisons passing | Holdout comparisons passing | Entire registered performance gate |
| --- | ---: | ---: | --- |
| `release-parity` | 0 / 9 | 3 / 21 | FAIL |
| `verified-reduction-parity` | 9 / 9 | 18 / 21 | FAIL |
| `narrowed-reduction-parity` | **9 / 9** | **21 / 21** | **PASS** |

Each comparison requires the HIA median to be at most 1.1 times its named control, and both p95 and p99 to be at most 1.2 times the control. All baselines and sizes are required. The independent recomputation exactly matches the original cohort statistics, comparison rows, and gate flags.

For the narrowed profile, all 21 holdout median ratios are also below 1, ranging from **0.3750794211 to 0.9325095057**: the recorded medians are approximately **6.75% to 62.49% lower** than the paired controls. The p95 and p99 ratios also remain below 1 in these recorded cohorts. These are empirical batch measurements from 63 timing samples per backend/size cohort; p99 is the maximum of those 63 observations. They are not a statistical confidence interval or a guarantee about individual-call production tails.

This positive result remains limited to one instrumented kernel on one shared Linux host. Clang 20.1.8 and Rust 1.90.0 have different compiler implementations and LLVM versions; C/C++ thin LTO, Rust fat LTO, and HIA's checked-IR object path are disclosed. The original result expressly leaves `broad_rust_performance_parity_established=false`. Its campaign cost is 17,573,777,597 ns, but total human time, earlier tool acquisition, energy, and a deployed application demand horizon remain unknown. A program-speed improvement therefore does not establish a complete economic return or an NDU-controller contribution.

The 192 original correctness/probe rows per profile are retained in the source artifact and their counts are reported; this review did not rerun that correctness suite or independently reconcile each of those separate correctness transcripts. It did independently check the scalar and batch checksum formula for every timing row reconciled above.

## 2. Preregistered distinct-code opportunity

The original frozen protocol SHA-256 is:

`1b4d1818d7fa9aff079bf7b27220d9f4df2bc0668a52b827e8a0adbd1b8cebbf`.

It specifies a checked two-argument u32 division/remainder kernel, baseline and two denominator-specialized actions, two hot-denominator modules, seven training seeds and seven independent validation seeds, and 200,000 calls per measured batch. The denominator-zero trap and declared Core/LLVM scope remain part of its qualification. A prospective 100,000,000-call horizon per module is explicitly synthetic, not a production trace.

The reviewer checked all **2 × 3 × (7 + 7) = 84** original samples, including raw stdout/base64 equality, empty stderr, successful exit, recorded checksum versus expected checksum, work count, driver identity, and selected library identity. The checksum oracle for this workload was **not** independently reimplemented in this review; the check binds the original observed and expected values without claiming a new differential qualification.

The three actual retained ELF `calculate` exports were independently located and read as inert bytes: baseline **19 bytes**, denominator-8 **39 bytes**, and denominator-10 **54 bytes**, with three distinct hashes. This verifies a genuine distinct-code contrast in the original artifacts, rather than relying only on different candidate names. It does not prove the machine instructions' semantics.

The gate uses the observed envelope `minimum(baseline outer wall) − maximum(candidate outer wall)` and charges the **entire measured search cost of 7,823,661,243 ns** to each proposed module opportunity. It does not treat that observed envelope as a statistical confidence bound. Independent arithmetic reproduces all four rows:

| Module / phase | Saved ns per observed batch envelope | Prospective saving over 500 batches | Net after full search cost |
| --- | ---: | ---: | ---: |
| hot8 / training | −374,521 | −187,260,500 | −8,010,921,743 ns |
| hot8 / validation | −374,140 | −187,070,000 | −8,010,731,243 ns |
| hot10 / training | −331,196 | −165,598,000 | −7,989,259,243 ns |
| hot10 / validation | −288,803 | −144,401,500 | −7,968,062,743 ns |

Both modules have distinct exported code, but neither has positive net savings. The original result is correctly **qualified as an observation** with `status=no-economic-opportunity`; `opportunity_gate_passed`, `ndu_comparison_authorized_by_this_evidence`, `NDU_gain_established`, and statistical superiority are all false. The registered gate therefore does not authorize claiming an NDU-versus-enumeration win from this experiment. Tool installation, outer interpreter startup/imports, and final report decoration/encoding/write remain explicitly excluded.

## 3. Native-policy contrasts and retained negative results

The three native-policy profiles are separate from the independent holdout parity runs above. Each has 36 training requests and a complete policy denominator of three episodes × four arms: fixed, exact DP, greedy, and native NDU. The review checked exact cohort coverage, status, and `service_total_ns = actual_total_ns − independent_audit_ns`, then independently recomputed all nine service-cost comparisons per profile from its 12 original result rows.

| Native-policy profile | Training performance comparisons passing | Native NDU policy calls | NDU-labelled arm wins over fixed | Complete policy / NDU / lifecycle net benefit |
| --- | ---: | ---: | ---: | --- |
| `native-release-ndu` | 0 / 9 | **0** | 0 / 3 | All false |
| `verified-reduction-ndu` | 6 / 9 | **0** | 0 / 3 | All false |
| `narrowed-reduction-ndu` | **9 / 9** | **0** | 0 / 3 | All false |

The 36-row training statistics for each profile were also recomputed from the complete original result rows. This review did not independently reconcile their separate raw training JSONL or every nested policy-step transcript; that boundary is recorded in `audit.json`. Some service comparisons against exact DP or greedy are lower, but the arm skipped native NDU invocation and lost to fixed in every episode. Such differences do not establish a native-controller contribution. All three original reports keep complete lifecycle cost unknown and net-benefit flags false.

The older native loop is also preserved separately: its 30 episodes completed, but its original amortized NDU cost is not lower than the selected fixed or light controls. Its calibration candidates have identical native bytes, so it is not substituted for the distinct-code opportunity test. Its original timeout, snapshot-drift rejection, and verifier-timeout controls are preserved in `originals/ndu-loop-original-fault-controls.json`. The costed finite-model and background lifecycle controls record actual native calls and limited functional successes; their original flags do not establish application speedup. Their nested histories were summarized, not independently replayed here. Synthetic lifecycle costs are not benchmark measurements.

## 4. Proof and checker boundaries

The opportunity's three Core translation reports have all six required fields: subject, property, profile, assumptions, checker, and unproved obligations. Their 12-path checker source identities match B's exact Git blobs, and their canonical identity hashes were independently recomputed. These fields are preserved without widening them in `six-field-translation-scopes.json`.

The reviewed guarded and narrowed optimization receipts use older, different schemas. This review does **not** relabel them as six-field machine proofs. It independently recomputed the optimization, guarded, narrowing, and chained checker identities from B's source bytes and checked the original/final Core and receipt binding hashes. The guarded proof binds **`hia.o`**; a retained successful trusted-linker command links it with instrumentation into the separately hashed **`hia.so`** used by the finite experiment. Conflating those two artifacts would overstate the proof. Both identities and the link record are retained in `native-image-bindings.json`.

The original receipts expressly leave backend refinement, whole-language soundness, deployment authority, and performance qualification false. The native compiler, linker, loader, libc, and hardware remain trusted. This audit adds no general machine, ABI, resource, FFI, concurrency, or loading correctness theorem.

## Audit execution and reproducibility

`audit_full_ndu.py` imports only Python standard-library modules and invokes only read-only Git object commands. It reads existing artifact bytes, parses inert JSON/ELF metadata, hashes source objects, and recomputes finite numeric summaries. It does not import or execute Hepta, run a checker or solver, compile anything, execute a native artifact, run tests, or call the live service.

Example replay into a **new** review directory, with the saved original metadata/log paths under the evidence root:

```bash
python -B audit_full_ndu.py \
  --zip ORIGINAL_CI_ARTIFACT.zip \
  --repo EXACT_GIT_OBJECT_REPOSITORY \
  --evidence-root SAVED_EVIDENCE_ROOT \
  --output NEW_AUDIT_DIRECTORY
```

The successful review run is `audit-attempt-05`, exit 0. Four earlier reviewer attempts failed on explicit schema assumptions: raw metrics vector versus named derived map; a nonzero library identifier; object-file proof versus linked shared library; and `proved` versus `verified` status vocabulary. Their original logs and auditor snapshots are retained. These were reviewer schema-adaptation failures, **not CI, compiler, or benchmark failures**, and none was silently relabelled as a successful run.

`audit.json` is the full structured finding; `parity-comparisons.json`, `native-policy-rows.json`, `guarded-opportunity-samples.json`, and source/image binding files make the numerical and identity conclusions reviewable. `files.json` freezes this package's exact files. The raw complete CI artifact remains the authority for observations outside the explicitly reconciled subset.
