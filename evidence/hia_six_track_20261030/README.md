# HIA six-track execution evidence — 2026-10-30

[Full report in Chinese](../../docs/HIA_SIX_TRACK_EXECUTION_20261030.md) · [Machine-readable outcomes](RESULTS.json) · [Implementation PR #389](https://github.com/TrillionniumFoundation/Hepta/pull/389)

## Result boundaries

The implementation at `865a4626910efbc882cad47a7816e9aa276a9600` passed its complete 3,937-method Python CI, 88 Rust tests, 158-entry safety matrix and all eight integrated gates. Overlapping CI and local test scopes must not be added into one denominator. The later candidate-reuse runner has five separate accounting tests; those are not part of the 3,937 methods.

The real legacy component application passed its bounded functional/resource checks. Its preselected HIA IRPGO candidate was slower than the fastest strong Rust PGO reference by 8.30% and 19.01%; its performance gates failed. No human labor saving was measured.

The native NDU four-arm study passed functional/resource checks but failed warm and build-inclusive net-cost gates. Its 32 recorded choices agreed with exact same-model DP. The failed first sandbox observation and its costs are retained.

The separately registered adaptive byte_sum reuse experiment completed 2,304 deliveries. Guarded passed all three complete-cost pairs (5.009502% lower standalone observed cost); guarded+narrowed failed one pair. The predeclared combined two-candidate gate therefore failed. This is not an unbiased confirmation, legacy-application win, statistical superiority or NDU incremental value.

The pinned actual model completed its single qualification run with 0/3 tasks, nine requests/responses and 25,336 tokens. The observation is valid but eligibility failed. Only the registered three attempts per task occurred; no additional qualification run or 16-cell main was started. Reference-capacity controls are not model successes.

Python remains production admission authority. Whole-language soundness, general asynchronous recovery, full native backend refinement, unrestricted C++ migration, universal Rust performance parity, physical-dot execution and agent productivity superiority remain unestablished.

The readable [NDU summary](NDU_SUMMARY.json) and [reuse summary](CANDIDATE_AMORTIZATION_SUMMARY.json) bind the original complete RESULT hashes. Their large per-delivery aggregates remain unmodified in the raw archives; summary files are explicitly labeled derived.

## Raw archives

| File | Bytes | Retained scope |
| --- | ---: | --- |
| [ndu-receipts.tar.gz](ndu-receipts.tar.gz) | 817,490 | Both NDU studies, failure diagnostics, original stream frames, source/build identities, cost/release receipts and public kernel text. Private NDU source and native executables are explicitly excluded. |
| [legacy-irpgo-raw.tar.gz](legacy-irpgo-raw.tar.gz) | 3,348,420 | All 319 original application files: captures, generated source/Core/LLVM, public native binaries, fixed inputs, profiles, sample ledgers, commands and output. |
| [integration-and-ci-receipts.tar.gz](integration-and-ci-receipts.tar.gz) | 1,194,733 | Explicit 11-file allowlist: local selected-scope records, complete CI job logs, one fully verified integrated artifact ZIP, and rejected-transfer metadata. |
| [agent-v9-raw.tar.xz](agent-v9-raw.tar.xz) | 2,562,872 | All 1,091 retained capacity/qualification/log files, including every request, SSE response, token receipt and generated candidate source/binary. Model weights and official runtime executables are referenced by exact pins/hashes. |
| [source-history.bundle](source-history.bundle) | 73,481 | Six original public Hepta source refs, including local experimental commits. Requires the declared base commit; private NDU Git objects are not included. |
| [candidate-amortization-evidence.tar.xz](candidate-amortization-evidence.tar.xz) | 582,060 | All 2,403 original reuse-run files, plus prereview, source mapping, independent audit, source subset and post-study test logs; 2,418 archive members including inventory. Public native products retained. |

The published NDU and candidate-reuse archive filenames are shorter than the original collector filenames in their inventories; their byte lengths and SHA-256 digests are identical. Every archived member was checked against its per-file size/hash inventory. See the archive-specific `*.inventory.json` / manifest files and the repository-relative [MANIFEST.json](MANIFEST.json).

Run hash verification from the repository root after retrieving the listed payloads:

```sh
sha256sum -c evidence/hia_six_track_20261030/SHA256SUMS
```

`MANIFEST.json` inventories every payload except itself and `SHA256SUMS`, avoiding recursive self-hashes. `SHA256SUMS` also verifies the manifest. The Git tree binds the checksum file itself.

## Source identities and reproduction

[SOURCE_PUBLICATION.json](SOURCE_PUBLICATION.json) preserves both local experiment identities and equivalent public Git trees. NDU/application runs used local `c9954b70afbe03d23b682aeef28c41057d8d52b1`; CI/model/final local tests used published `865a4626910efbc882cad47a7816e9aa276a9600`. Both trees are `998a90d473749d14274cb8adaf253a30f0185798`.

The reuse run used local `9598f3332b6916b55940bf9c77314bf04e38710b`. Before native samples, its identical tree `428629c489284830bb852b6c85f671afcb8e0f0c` was published as [registration c0c77cd3](https://github.com/TrillionniumFoundation/Hepta/commit/c0c77cd382d16953c66e1e8eba206ff11f4da45d). Publication metadata does not rewrite historical experiment SHAs.

The history bundle was verified with Git and requires base `9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b`:

```sh
git fetch origin 9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b
git bundle verify evidence/hia_six_track_20261030/source-history.bundle
git bundle list-heads evidence/hia_six_track_20261030/source-history.bundle
```

Use the corresponding pinned source and tool identities, the recorded argv and a fresh output directory outside the source checkout. The original NDU implementation requires authorized access to its private source pin; no private source or binary is republished here. The agent run uses the exact downloadable model/runtime revisions and hashes in admission/acquisition records. The completed model eligibility failure must not be silently rerun or relabeled as an eligible main study.

## Independent checks and failures retained

- [Application arithmetic audit](legacy-irpgo-arithmetic-audit.json), including its preserved initial review and explanation of two audit-only corrections. Original experimental data and thresholds were unchanged.
- [NDU arithmetic/finite-enumeration audit](NDU_ARITHMETIC_AUDIT.json).
- [Reuse prereview](candidate-amortization-prerun-review.json) and [independent post-run audit](candidate-amortization-independent-audit.json).
- [Actual-model audit](agent-v9-independent-audit.json), with the [operator stop](AGENT_STOP.json). Its qualification-only zero hidden count is separate from the 19 capacity reference controls that actually exercised hidden evaluation.
- [CI review](CI_REVIEW.json). Two large artifact downloads were truncated and rejected, never counted as complete evidence; full job logs are retained. Official complete artifacts remain available at [integrated](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40985902483/artifacts/12948390584), [verified-native](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40985952977/artifacts/12946874292), and [source/application](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40985952981/artifacts/12946853428).

Timing scopes are explicit. The 199.343918199-second prior NDU/candidate chain plus the 339.344308616-second reuse study gives 538.688226815 tracked seconds for that chain; this is not total engineering, application, model, download or human effort. The first Python seal-API preflight had zero model requests but unknown outer duration, recorded as null. No missing cost is invented as zero.

The host is nonexclusive x86-64 Linux. These observations establish neither statistical superiority nor universal performance. Review/audit success and `valid_observation=true` are not safety certificates or positive performance/eligibility verdicts.
