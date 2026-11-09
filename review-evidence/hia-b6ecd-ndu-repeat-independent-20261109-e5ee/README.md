# Same-source post-integration NDU repeat: independent read-only review

## Conclusion

**The complete narrowed release-parity result repeats in this second CI run: 9/9 training and 21/21 holdout comparisons pass again. This is a bounded repeat observation, not proof of statistical stability or a general performance guarantee.** A separate narrowed policy-training campaign has a new p99 failure and passes only 8/9 comparisons, versus 9/9 previously. Both facts must remain visible.

The complete 84-sample distinct-code opportunity study again finds no economic opportunity. All three native-policy cohorts again have zero native NDU policy invocations and false incremental/gated/whole-lifecycle benefit flags. Stable NDU value and complete economic benefit therefore remain unestablished.

## Original identities and method

| Item | First source qualification | Post-integration repeat |
| --- | --- | --- |
| CI run | [42565815059](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815059) | [42572528877](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42572528877) |
| Job | `128991965937` | `129012916174` |
| Artifact | `13653895483` | `13654707994` |
| ZIP bytes | 19,759,307 | 19,758,336 |
| ZIP SHA-256 | `d8ad94fe9ab18679c1475de2e490c03620081e58bad52654031c73253e2d1dff` | `8b791d08e2f3543b1ec5f9c0447233da6f75a3b68fd5bc7c59d909d0aed572c2` |

Both bind source `6ecd8023615a6e0b2dc269379fb059c656b38b6f`, tree `4c51962e030e9ea39c6498224c99eb40fbdd2f35`. The second run is a separate successful attempt-1 run. Its official API artifact collection, run and job metadata, and decoded original job log were retrieved independently. The actual log explicitly checks out B; the recorded source/tree members agree. The ZIP digest matches the official metadata. It contains 1,796 members and 227,409,926 uncompressed member bytes.

The previously reviewed standard-library auditor was reused with only the new immutable run/artifact/size identities and local metadata paths substituted. `auditor-adaptation.json` records every substitution and both auditor hashes. No original audit package was modified.

The second audit independently matches 238 source blobs to exact Git bytes and reconciles the same 117 selected original members as the first review. Its source bindings are identical to the earlier review. Across its three parity profiles it reconciles all 72 raw JSONL transcripts, 360 requests and 7,560 timing batches, then exactly recomputes original cohort statistics and comparisons.

The supplemental `compare_runs.py` also reconciles **all raw policy-training responses in both artifacts**: an additional 72 transcripts, 216 requests and 4,536 timing batches. Each profile in each run has the complete 36-request denominator. Request IDs/work counts, native response fields, allocator-vector conversion, timing sum, and original result-row equality are checked without executing the producer. This supplements the inherited auditor's narrower `training_raw_jsonl_independently_reconciled=false` statement; the completed additional checks are explicitly recorded in `comparison.json`. Nested policy-step histories and correctness-only transcript suites were not newly replayed.

All 17 retained parity image labels, including drivers and proof-bound objects, have identical hashes between runs. The opportunity's three exported-code and library identities also match. The metadata for both parity hosts reports nonexclusive Linux x86-64, the same kernel string and selected CPU 0; it does not establish the same physical host or exclusive CPU ownership. No causal diagnosis of the timing differences is made.

## Complete parity denominators

Each profile in each run contains 120 native requests: four backends, three training and seven distinct holdout sizes, three seeds per size/phase. Each request has 21 timed batches of 64 calls. Each backend/size cohort therefore has 63 recorded timing samples. No sample was dropped or rerun to improve a result.

| Profile | First training | Repeat training | First holdout | Repeat holdout | Whole gate in repeat |
| --- | ---: | ---: | ---: | ---: | --- |
| `release-parity` | 0/9 | 0/9 | 3/21 | 4/21 | FAIL |
| `verified-reduction-parity` | 9/9 | 9/9 | 18/21 | 18/21 | FAIL |
| `narrowed-reduction-parity` | **9/9** | **9/9** | **21/21** | **21/21** | **PASS** |

The threshold remains median ratio ≤ 1.1, p95 and p99 ratios ≤ 1.2, requiring every registered control and size. The narrowed repeat's 21 holdout median ratios range from **0.3732886997 to 0.9239543726**, about **7.60%–62.67% lower** than the corresponding controls. The earlier range was 0.3750794211–0.9325095057. Both sets of finite observations are preserved; the numbers are not described as identical reproductions.

An unchanged pass count can hide changed failures. In `verified-reduction-parity`, the repeat's three failures are now the size-2 comparison against each of C, C++ and Rust. Those three comparisons previously passed. Conversely, size-63 against C++/Rust and size-1025 against C++ now pass after previously failing. Thus “18/21 in both runs” does not mean that the same 18 comparisons reproduced. The ordinary release profile gains one pass, size-63 against C. `comparison.json` preserves all 90 matched comparison pairs, including every flip.

These measurements concern one allocator-instrumented owned-buffer kernel and finite inputs. Compiler implementations/LLVM versions and LTO settings differ by backend. The two observed successes strengthen the evidence for that specific narrowed profile, but do not establish universal Rust parity, a production-tail bound, general compiler superiority, or statistical reproducibility. With 63 observations, reported p99 is the observed maximum; it is not a population-tail confidence bound.

## New negative policy-training sample

Policy-training experiments are separate campaigns from the independent release-parity holdout above. Their results must not be exchanged or pooled to hide a failure.

| Native-policy training profile | First | Repeat | Change |
| --- | ---: | ---: | --- |
| `native-release-ndu` | 0/9 | 0/9 | Still fails |
| `verified-reduction-ndu` | 6/9 | 9/9 | The three size-64 comparisons now pass |
| `narrowed-reduction-ndu` | 9/9 | **8/9** | New size-64 versus Rust p99 failure |

The new narrowed failure is directly reconciled to all three seeds' raw native timing responses, retaining all 63 samples per side:

| Size-64 narrowed vs Rust | First HIA / Rust ns | Repeat HIA / Rust ns | Repeat ratio |
| --- | ---: | ---: | ---: |
| Median | 1,092 / 1,832 | 1,142 / 1,752 | 0.6518264840 |
| p95 | 1,893 / 1,923 | 1,272 / 1,833 | 0.6939443535 |
| p99 | 1,963 / 1,993 | **2,343 / 1,923** | **1.2184087363** |

The p99 ratio exceeds the original 1.2 gate. It remains a failure even though the median is favorable and the separate release-parity holdout succeeds. No gate, denominator or outlier policy was relaxed.

Each of the three actual policy cohorts still completes all three episodes × four arms = 12 rows. Service accounting and all nine cost comparisons per profile reproduce the original result arithmetic. **Native NDU policy invocation count is zero in all three cohorts in both runs**, every NDU-labelled arm loses to fixed in all three episodes, and incremental/gated/whole-lifecycle benefit flags remain false. Differences against exact DP or greedy cannot be claimed as a native NDU contribution when the policy never invoked it. Other finite-model/background parts of the original artifact may contain native calls; this zero count is not generalized to the entire artifact.

## Distinct-code opportunity repeat

The frozen protocol and all 84 registered samples are retained again. The baseline, denominator-8 and denominator-10 actual ELF exports remain distinct at 19, 39 and 54 bytes. The raw stdout/base64, recorded checksum/expected-checksum equality, exits, work counts and image/driver bindings are reconciled as in the first audit; the expected-checksum generator is not a newly executed or independently proved oracle.

The repeat's full measured search cost is **7,699,759,469 ns**, versus 7,823,661,243 ns previously. The registered synthetic 100,000,000-call horizon remains 500 measured-size batches per module. Both modules remain negative under the registered minimum-baseline minus maximum-candidate outer-wall envelope:

| Module / phase | First net ns | Repeat net ns |
| --- | ---: | ---: |
| hot8 / training | −8,010,921,743 | −7,830,573,469 |
| hot8 / validation | −8,010,731,243 | −7,806,997,969 |
| hot10 / training | −7,989,259,243 | −7,796,031,969 |
| hot10 / validation | −7,968,062,743 | −7,808,765,969 |

Both runs report `qualified=true` and `status=no-economic-opportunity`: the observations are qualified, but the economic opportunity gate, permission to claim an NDU comparison from it, NDU gain, and statistical-superiority flags remain false. Cost exclusions and synthetic-demand provenance are unchanged. Qualification success is not an economic win.

## Proof and execution boundaries

The second artifact's three six-field translation scopes and exact checker source identities are checked anew. The original guarded/narrowed optimization receipts retain their own limited schemas. Their object proof binds `hia.o`; the recorded trusted-linker step and separately hashed `hia.so` preserve the finite execution chain without proving machine-level refinement, general loader behavior or whole-compiler correctness.

`audit-attempt-01` and the supplemental comparison both exit 0 on this new artifact. Their original stdout/stderr and exact source hashes are retained. Only inert JSON/ELF metadata, hashes, read-only Git objects and arithmetic are used. There are **zero local project imports, compiler/solver/native/test executions or live-service calls**. A new successful GitHub run is never used as a substitute for reconciling its actual numbers.

`audit.json` is the independent new-artifact finding. `comparison.json` contains all matched rows and the additional raw policy-training checks. `files.json` freezes the package. The previous package and all its positive and negative results remain untouched. This repeat does not close stable incremental NDU value or complete economic return.
