# HIA eight-delivery evidence, 2026-10-30

Start with the [Chinese delivery report](../../docs/HIA_EIGHT_DELIVERY_20261030.md) and [machine-readable results](RESULTS.json). The implementation and observed outcomes are reviewable in [Draft PR #399](https://github.com/TrillionniumFoundation/Hepta/pull/399). All eight user acceptance criteria are **not** closed; `release_qualified=false`.

## Identity and admission

The actual qualification source is local commit `60dfedc626b7ce3feaaa87ac16d711fe0cc8e9d3`. The published source commit is `37d3a317b77aeac8f42b8a727f0f123b4a46e49f`. Both have Git tree `6add0d477bf92c3980110b50a6b1675306175c99` and parent `2cc9fb3b92a7306d2f5aae316c99e8364be700f9`; they are different commit identities. [SOURCE_PUBLICATION.json](SOURCE_PUBLICATION.json) explains the metadata difference, and [qualified-source.bundle](qualified-source.bundle) retains the original qualification commit.

The Agent protocol and pre-generation reviews were published in commit `5e4ad121e5721e6d82fe071b6a1e3f805cbe2674` before benchmark requests began. The [registration directory](frontier-registration/) retains the committed protocol, runner, freeze and reviews. Later evidence commits do not change the tested production implementation.

## Result index

| Evidence | Meaning |
| --- | --- |
| [CODE_REVIEW.json](CODE_REVIEW.json) | Limited reviewed integration and explicit limits; not a soundness proof |
| [DOCUMENT_REVIEW.json](DOCUMENT_REVIEW.json) | Final read-only consistency review bound to the exact delivery report and RESULTS bytes; no new experiment |
| [SAFETY_ATTEMPTS.json](SAFETY_ATTEMPTS.json) | First 273-pass/4-skip failure retained; subsequent canonical 277/277 pass on unchanged frozen source |
| [MIGRATION_SUMMARY.json](MIGRATION_SUMMARY.json) | C finite migration and actual C++ release upgrade; full human costs unknown, three foreign allocation-abort sites per version unrecovered |
| [NDU_SUMMARY.json](NDU_SUMMARY.json) | Actual four-arm replication and failed first environment attempt; functional controls passed, economic gates failed |
| [FRONTIER_SUMMARY.json](FRONTIER_SUMMARY.json) / [description](FRONTIER_SUMMARY.md) | Actual new model qualification 3/3 and main 14/16; all 23 requests and both failed cells included |
| [FRONTIER_ACTUAL_AUDIT.json](FRONTIER_ACTUAL_AUDIT.json) | Independent raw-event, cost, sequencing, public/hidden and resource-observation recalculation |
| [FRONTIER_LIFECYCLE_AUDIT.json](FRONTIER_LIFECYCLE_AUDIT.json) | Read-only audit of 23 model transports and 23 validation worker receipts |
| [FRONTIER_OPCODE_DIAGNOSIS.json](FRONTIER_OPCODE_DIAGNOSIS.json) | Actual comparison opcode names, frozen disclosure gap, existing discovery mechanisms and causal limits |

The 277 canonical and 43 host-control cohorts overlap and are not additive. Model task costs are complete as reported fields, but one prior bootstrap request lacks exact usage, and complete human/service lifecycle costs remain unknown. Conservative charge is not an independently verified exact token total.

## Raw archives

| Archive | Files | Uncompressed bytes | Compressed bytes | SHA-256 |
| --- | ---: | ---: | ---: | --- |
| [raw-core-evidence.tar.xz](raw-core-evidence.tar.xz) | 1,669 | 69,633,747 | 10,117,320 | `d5e729c094e573783b6e0e0872092bccc01da963c7011b7b93906c358413e99e` |
| [raw-frontier-evidence.tar.xz](raw-frontier-evidence.tar.xz) | 1,648 | 136,018,220 | 2,138,660 | `ffd834085400c29f02fd2f052e62793b1a96328fd1fc9930fb2972f8e3397d5b` |

[ARCHIVE_MANIFEST.json](ARCHIVE_MANIFEST.json) and [FRONTIER_ARCHIVE_MANIFEST.json](FRONTIER_ARCHIVE_MANIFEST.json) give original absolute paths, archive paths, sizes and SHA-256 for every file. Each archive was reopened and every member was independently read and hash-checked after creation. Archive verification concerns retained bytes, not the truth of every claim in those bytes.

The first archive contains actual safety/host/finite-build/migration/NDU results, failed attempts, historical V9 raw calibration and V10 source-labelled audit materials. The second adds all regular non-pycache new pilot files, superseded pre-generation controls and runner drafts, every actual request/response/validation result, final independent audits and later observation records absent from the first archive. Any later counterpart to a first-archive record is listed explicitly; earlier bytes remain retained. Extract into separate directories to preserve both snapshots.

No model weight file or complete external toolchain installation is included. Native executables and captured source inputs needed to inspect the particular observations are included where listed in the manifests. Original commands, allowlisted environment settings and tool hashes remain in launch, registration and build receipts. Paths describe the actual run environment and may need explicit relocation when reproducing.

Both failed HIA cells, all six rejected repair attempts, the initial safety skips, the first NDU identity refusal, C++ `noexcept` aborts, older Agent qualification failures, and corrected pre-generation/audit drafts remain part of the evidence. They are not overwritten by the final summary.
