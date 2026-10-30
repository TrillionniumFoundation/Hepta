# Finite oracle reference reuse: retained execution and adverse findings

The bounded reference-reuse implementation and its negative controls pass.
Two separately frozen local studies each completed all 60 observations and 240
actual native contexts. **Neither passed the finite-job cold economic gate.**
There is no NDU arm, cache-disabled end-to-end comparison, global-optimality
proof or production-demand evidence.

## Source and validation identity

| Cohort | Frozen source | Scope |
| --- | --- | --- |
| Original reference implementation and v2 protocol | `2cd000135b5a252cf3b0f31d1c2b04649cd5a12e` | 43/43 scoped methods; 60 actual observations |
| Adaptive diverse-input follow-up | `31574dc5387af54d0dd8e2336b9f69e3113c96ba` | 44/44 scoped methods; 60 actual observations |

Both scoped suites include actual Clang 20.1.8 builds, sealed images, independent
child executions and the existing finite-context ownership/failure controls.
There were no skipped methods in either retained log. Python was 3.13.5 and
Z3 was 4.15.4. The initial development attempt with Clang 19 was correctly
rejected by the existing Clang 20+ gate: 29 unit methods passed and the two native
methods errored before execution. That tool output was observed during
development but was not retained as a raw log; no native pass is attributed to
that attempt. The compiler gate was not lowered.

Each source and protocol was committed before its own single local study.
This is **local frozen-before-run**, without a public preregistration claim.
The later evidence-only commit is not relabeled as the tested source.

## Complete observations

| Item | v2 | v3 |
| --- | ---: | ---: |
| Completed observations | 60 | 60 |
| Actual child contexts | 240 | 240 |
| Actual CRC step calls | 245,760 | 245,760 |
| Cold setup including release | 7.989701033 s | 8.101166973 s |
| Complete study wall, with recorded exclusions | 11.962453478 s | 12.093415514 s |
| Oracle reference misses | 2 | 64 |
| Oracle reference hits | 1,022 | 960 |
| Peak canonical retained bytes | 1,391 | 70,188 |
| Peak retained entries | 2 | 64 |
| Economic gate | false | false |

Every selected candidate completed its original source/kernel proof, selected
LLVM check, finite VM/native differential and sealed publication. All three
exported candidate code identities are distinct in both runs. Every actual
context completed and its input/output identities and lifecycle were retained.
All source-before/source-after observations match. Final close released native
resources and cleared the reference storage. No failed sample was removed,
and no context or study was automatically retried.

The reference cache reuses only immutable independently computed expectations.
V3 measured 106.181934 ms of miss computation, 23.170921 ms of canonical-key
construction/lookup and 0.286715 ms of storing references. These are component
observations; the economic gate uses the complete host arm cost, which includes
all preparation and evidence work. Canonical byte counts and byte-nanoseconds
are not Python RSS, physical energy or money. This study has no cache-off
end-to-end arm, so no measured end-to-end cache speedup is asserted.

### V2 input defect is preserved

The inherited generator emits zeros over its first 4096 bytes. Choosing a
4096-byte study in v2 therefore made both phases identical and all 32 request
chunks zero. The complete v2 record is retained in `RESULT-v2.json` and
`raw-v2.tar.gz`. It does not establish diverse-input behavior or an independent
training/validation comparison. Its two cache entries are explained by its
two polynomial parameters, not by hidden sample filtering.

V3 was explicitly designed **after** discovering this defect. Its separate
SHAKE256 domain/phase/seed construction was frozen at the second source before
execution. Input admission verified two distinct phases, 32 pairwise-distinct
256-byte chunks and zero all-zero chunks. Arms, budgets, sample counts, stopping
rules and the economic criterion stayed unchanged. This is an adaptive
engineering repair, not an independent statistical confirmation.

### V3 adverse economic result

The primary comparison uses each complete `arm_host_wall_ns`, including trace
preparation, cache lookup, evidence serialization, native execution and result
validation. The strongest static control is the minimum complete cost across
all three coalesced static arms. Dispatch is charged its maximum observation,
then the complete cold setup and release cost is subtracted.

| Phase / workload | Dispatch increment before cold setup | Cold net |
| --- | ---: | ---: |
| training / IEEE | −9.778182 ms | −8.110945155 s |
| training / Castagnoli | −1.671533 ms | −8.102838506 s |
| training / mixed | −0.821189 ms | −8.101988162 s |
| validation / IEEE | −2.480859 ms | −8.103647832 s |
| validation / Castagnoli | −0.299133 ms | −8.101466106 s |
| validation / mixed | −1.623850 ms | −8.102790823 s |

The observed fresh-child to coalesced-baseline batching envelope was positive
in each v3 row, approximately 187–205 ms. That concerns batching an already
prepared finite workload; it is not a specialization, NDU or cold deployment
gain. Dispatch did not beat the strongest static envelope even before cold
setup. These minima/maxima are not statistical confidence intervals.

## Shared host and timing limitation

`RUN_CONTEXT.json` and `RUN_CONTEXT_V3.json` record the relevant explicit
environment and concurrent work. V2 overlapped native NDU bridge compilation and
other focused tests. Root performance work was paused for v3, but other native
test work may still have been active. Both runs used a shared development host.
**`performance_timing_qualified=false` applies to both.** All cost values remain
descriptive observations of these actual attempts; no dedicated-host timing or
portable performance qualification follows. The raw results were not altered
to remove interference or manufacture a positive outcome.

## Preservation and audit

`AUDIT.json` records an independent read-only arithmetic/count review of every
context and direct input-diversity recomputation. The reviewer did not rerun
workloads or call the study's economic analyzer for the arithmetic checks.

The two archives each retain 320 original files, including every plan, actual
context, source capture, original C execution evidence, compiled images and
protocol. `RAW_MANIFEST.json` lists all 640 raw members with their exact SHA256,
size and mode. Both archives were reopened and every decompressed member was
verified against that manifest. `ARCHIVES.json` records the archive identities.
The convenient result JSON files are byte-for-byte copies of the original
results, not edited summaries. No original source-C or machine-code proof is
claimed from these finite observations.
