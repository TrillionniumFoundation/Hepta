# Completed Agent reproduction: new source snapshot, disclosed tasks

The original strict Agent-advantage gates **did not pass**. Both fixed model families finished all 12 scheduled cells, for **24 cells and 47 actual completion requests/responses**. The original cohort reader reports `complete_valid_coverage: true`; every request has complete token usage. No inference timeout, generation infrastructure failure, identity drift, or new cgroup OOM/kill occurred.

This is a reproduction of the already disclosed v4 tasks on a new implementation snapshot. It is **not a new blind task cohort**, and no old response was repaired or rescored. Repeated greedy runs of the same disclosed tasks must not be pooled as independent population samples.

## Observed results

| Model | Representation | Correct tasks | Submissions | Input tokens | Output tokens | Total tokens |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Qwen2.5-Coder 1.5B | JSON HIA | 0/4 | 8 | 11,880 | 8,340 | 20,220 |
| Qwen2.5-Coder 1.5B | Compact HIA | 0/4 | 8 | 8,477 | 2,634 | 11,111 |
| Qwen2.5-Coder 1.5B | Rust | 0/4 | 8 | 6,523 | 1,018 | 7,541 |
| Granite 3.3 2B | JSON HIA | 0/4 | 8 | 12,089 | 7,155 | 19,244 |
| Granite 3.3 2B | Compact HIA | 0/4 | 8 | 9,835 | 3,008 | 12,843 |
| Granite 3.3 2B | Rust | 2/4 | 7 | 5,983 | 938 | 6,921 |

Granite solved `clamped_delta_bias` in Rust on its second submission and `floor_multiple_v2` in Rust on its first submission. These passed all 254 and 256 hidden input cases respectively, their independent provider contracts, original-argument/single-call obligations, and sealed native artifact checks. No HIA or compact-HIA cell passed its public examples, so its hidden tests were not run. Unrun hidden tests are not counted as observed hidden failures.

Compact HIA consumed fewer tokens than JSON HIA in each family, but produced no correct task and consumed more total tokens than Rust. The correctness-first gates against both Rust and JSON HIA remain false for maintenance and upgrade. Syntax compression therefore does not establish an Agent development advantage in this experiment.

| Model | Representation | Submission outcomes |
| --- | --- | --- |
| Qwen2.5-Coder 1.5B | JSON HIA | observable_wrong=2, response_rejected=6 |
| Qwen2.5-Coder 1.5B | Compact HIA | observable_wrong=2, response_rejected=6 |
| Qwen2.5-Coder 1.5B | Rust | compile_rejected=4, observable_wrong=4 |
| Granite 3.3 2B | JSON HIA | observable_wrong=4, response_rejected=4 |
| Granite 3.3 2B | Compact HIA | observable_wrong=4, response_rejected=4 |
| Granite 3.3 2B | Rust | compile_rejected=3, observable_wrong=2, public_passed=2 |

`response_rejected` covers the existing output/source admission gate; `compile_rejected` is an actual native compile refusal; `observable_wrong` is an admitted native candidate that violates the value or provider observations. Rust remains subject to the original documented finite source scanner, not the full Rust language. Positive and hostile controls demonstrate that the evaluator can admit correct implementations and detect bypassed/wrong providers; these controls are not scored as model answers.

## Controls, process ownership, and source identity

All 20 original orchestration tests passed with no failures, errors, or skips. All 36 reference/partial-migration controls passed: 24 actual native builds/executions, eight expected response refusals, and four expected compile refusals. All nine hostile-provider controls built natively and were rejected as observably wrong. The same native compiler identities were used in the model runs.

The first non-generative capacity attempt could not bind its owned private Unix socket in the restricted executor. It made zero completion requests and is retained in `capacity-01/`. The separately retained `capacity-02/` used the authorized local execution path and passed both models, 12 tokenizer-only rows each, with zero completion requests. The original private-socket peer ownership, actual `/proc` executable/environment, no-repack condition, file hashes, and process shutdown checks were preserved. Registration occurred only after all controls and passing capacity checks.

- Baseline repository commit: `a32ad51250b905bb4729168f4d8f9328880b44db`. This identifies the retrieved parent, not the new uncommitted source tree.
- Measured 543-file source content hash: `6f0a253461da398c32d311b9c16825a86de0c70c231bc560a4baa156b00c3440`.
- Registration SHA-256: `aa2a599db942a9d9cd5675e2de7264639b0808d1be1e6014e184a924ae98a33a`.
- All 543 frozen files matched their initial manifest at collection. The 31 registered study sources also passed the original repeated cell-boundary identity checks.
- Final source rebind: **31/31 registered study sources match** the current tree: 22 materialized files and nine Git-marked sparse files read from the recorded HEAD commit. The original registration was not edited.
- The complete frozen source inventory is **not** identical to later development: 8 changed files and 5 new Python files are listed in `SOURCE_CLOSURE_REBIND_TRANSPORT.json`. New call-expansion, planning, C++ qualification, and other paths outside the registered study closure are not qualified by this model comparison.

## Costs and retained artifacts

The Qwen run took 704.709094 seconds and the Granite run 1166.038060 seconds: 1870.747155 seconds in sequential model runs. These run scopes already include their own reference controls, hash/start/stop, inference, native validation, and cell-boundary identity checks. Nested costs must not be added again.

Preparation separately records 9.472832 seconds for initial controls, 5.053536 seconds for the failed capacity attempt, 8.013969 seconds for successful capacity, source freezing/archiving, registration, and registration validation. Some preparation stages overlapped, and the source archive was created while Qwen ran; these durations are not disjoint wall time. Cached pinned models/runtime were reused; incremental downloads were zero. Human engineering time, unrelated shared-host work, and total economic costs remain unknown.

The complete input/output total is 77,880 tokens, including every failed submission. There are 45 unsuccessful submissions and two successful final submissions. The small model families and finite arithmetic workspaces do not establish general language productivity, large-project migration, or statistical superiority.

- `READOUT.json`: concise machine-readable outcomes, costs, controls, and scope.
- `COHORT_RESULT.json`: unchanged output of the original v4 cohort reader.
- `source.tar.xz` and `SOURCE_SNAPSHOT.json`: measured source and exact identities; all 543 archive members were checked.
- `artifacts.tar.xz` and `ARTIFACT_MANIFEST.json`: all 996 raw control/capacity/suite files, including requests, responses, candidate sources, native artifacts, outputs, identity checks, and server logs; every archive member hash was checked.
- `ARTIFACT_ARCHIVE_CHECK.json` and `SOURCE_ARCHIVE_CHECK.json`: actual archive verification results.
- `SOURCE_CLOSURE_REBIND_TRANSPORT.json`: final current-tree applicability after the collector packaging change; earlier source-rebind records remain retained.
- `COMMANDS.json`, `ENVIRONMENT.json`, and `PREPARATION_COSTS.json`: execution scope and preparation provenance.

Raw artifact archive SHA-256: `dfa029e8ac45c0143c392bb501089f1780a1476c94eee4d10322fc5576e2775e` (1467212 bytes). Source archive SHA-256: `8de2b31a6d03575574dbafcf6fc1b9f7fa4f9bdff296cddb16e9c566ee421c5f` (1428640 bytes). The artifact archive check took 0.910504 seconds and passed all 996 files.

## Transport-only recompression after the study

The published container uses a 64 MiB XZ dictionary and is 1,467,212 bytes, replacing the original 28,678,468-byte container. The complete 166,000,640-byte decompressed tar stream is byte-for-byte identical: `5136bbc014dffbc910532f13dfa02cee9cc2cda5dddbea996e436f59c5454b2f`. All 996 file bytes, hashes, names, tar metadata, and member order are unchanged. Model records, scores, gates, and registration are unchanged.

`ARCHIVE_TRANSPORT.json` preserves the original container identity and original collector/archive-check costs, and records 42.987537 seconds for the additional single-threaded recompression and 0.910504 seconds for the new exact-stream/member check. The former container remains at `/tmp/hepta-agent-recompression-64m/artifacts-original-dict4m.tar.xz`. The collector default now uses the same 64 MiB dictionary for future packaging; the original study code and protocol have not changed.

A targeted check of 866 UTF-8 artifact/sidecar text, JSON, and log records found zero credential-signature or complete-environment-dump flags. Every observed environment field contained only the `LLAMA_ARG_REPACK` whitelist. No potential secret values were printed. This is a targeted content check, not a general proof about arbitrary strings.
