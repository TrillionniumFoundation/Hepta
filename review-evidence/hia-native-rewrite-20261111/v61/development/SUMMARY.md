# v61 development evidence

This directory retains development observations and failed, incomplete, or abandoned attempts without reclassifying them as qualification. The coordinator owns the parent v61 README, final custody, and separate c80 qualification records.

## Contents and byte custody

Eight archives retain **127 original files / 12,446,110 original bytes** in **774,556 compressed bytes**. Every archive member was read back, compared byte-for-byte with a second real read of its unchanged original, and checked against its captured SHA-256. Original file identity and metadata were checked before and after reads. Tar paths and permission bits are retained; tar timestamps, uid, and gid are normalized. No raw phase directory or whole repository is included.

| Package | Original members | Original bytes | Packed bytes |
|---|---:|---:|---:|
| [hia-archive-stored-experiment.tar.xz](hia-archive-stored-experiment.tar.xz) | 47 | 159,068 | 19,892 |
| [hia-ci-c80eb2.tar.xz](hia-ci-c80eb2.tar.xz) | 18 | 352,732 | 61,668 |
| [hia-json-independent-audit.tar.xz](hia-json-independent-audit.tar.xz) | 8 | 59,826 | 12,392 |
| [hia-origins-independent-audit.tar.xz](hia-origins-independent-audit.tar.xz) | 12 | 9,183,267 | 378,936 |
| [hia-structure-performance.tar.xz](hia-structure-performance.tar.xz) | 22 | 744,156 | 176,880 |
| [native-origins-development.tar.xz](native-origins-development.tar.xz) | 11 | 1,895,467 | 115,572 |
| [root-integration.tar.xz](root-integration.tar.xz) | 7 | 41,147 | 6,000 |
| [structure-independent-review.tar.xz](structure-independent-review.tar.xz) | 2 | 10,447 | 3,216 |

[CUSTODY.json](CUSTODY.json) records each archive SHA-256, every original member's size/SHA-256/source identity, excluded originals, and each readable copy. [pack_evidence.py](pack_evidence.py) is the actual packaging script. Historical absolute paths inside original observations are preserved verbatim; tar member paths are listed in custody. `readable/` contains exact copies of selected summaries and the initial assertion-failure transcript; `integration/` contains the seven requested root observations as exact copies.

## Preserved observations

- **Structure performance:** the entire earlier and `guarded/` directories are retained. Both sets of complete reference timing rows, source hashes, raw compressed reference results, tests, final interleaved component timing samples, and the final summary remain available. The earlier candidate SHA is `1458ef7dfcaabec1963c8d6cfe0bca5127fe4a65d73cf4968714a1673cbf473f`; the guarded candidate SHA is `76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92`; both compare against c80 program SHA `cf26805792737e15969ec17220810290cf74df9387151cb8521e8096daa68df3`. The guarded 105-test run passed. All three complete reference outputs matched their baseline bytes. The final whole-reference wall-time observation saved only 0.279 seconds in aggregate, so the earlier larger timing difference is not presented as a full-cold improvement.
- **Independent structure review:** the review script and all 14 targeted outcomes are retained, including alias mutation, newly formed nested cycles, sibling scope/error priority, and large-string pre-hash bounds. Its recorded comparisons all match c80; this is a finite development review.
- **Native origins development:** the actual HIA image, input/output, manifest, request/receipt, stdout/stderr, source bindings, scope, and review record are retained. The initial tool-output transcript preserves **both decimal-ID assertion failures** (`param` and `return`, value `14.0`): the native JSON gate returned `0xffffffff`, while the initial assertion expected command error `0xfffffff1`. That transcript is explicitly a retained final tool-output chunk, not a recreated passing run. Subsequent corrected observations remain separate. This image used an existing B3 development compiler and does not establish current-source cold qualification.
- **Independent native origins audit:** all 64 generated DAGs, native entries, 1,536 exact outcomes, bindings before/after, full source inventories before/after, audit script/log, findings, and summary are retained. The recorded actual native-image run reports all case checks true and zero findings, with unchanged command bytes and source bindings. No full-language claim follows from this finite audit.
- **Independent JSON audit:** scanner snapshots, audit/count scripts, log, summary, evidence manifest, and actual double-preflight counts are retained. The recorded 281,836 outcomes match baseline; the large gzip containing their raw rows is excluded here only because it is separately retained. Native-selector controls in this audit use an inert stub to check routing; they do not qualify a native image.
- **GitHub c80 attempt:** the native/source job logs, cold report, phase index, observed/final CI metadata, analysis script/results, and original evidence manifest are retained. This is the recorded GitHub 180-second cold timeout, including its source-byte and cleanup evidence. It does not replace or characterize the coordinator's separately retained ROG c80 run.
- **64 KiB archive experiment:** its baseline, independent patch, profiles, both real timing observations, 13-test log, and rejection disposition are retained inside `hia-ci-c80eb2.tar.xz`. It was **not integrated**: the measured wall benefit was small and unstable.
- **ZIP_STORED experiment:** scripts, baseline/experimental snapshots, raw benchmark metadata/log, disposition, and 38 small ROG phase receipts are retained. It was **abandoned and not integrated**: the recorded sample regressed CPU and wall time while increasing container size about 34-fold. Neither archive experiment changes the production archiver; packaging independently checked that the integrated archiver bytes still equal c80.
- **Root integration:** `v61-focused-source.{json,log}`, `v61-integration-incomplete-first.{json,log}`, `v61-integration-custody.json`, `v61-regeneration.log`, and `json-span-regressions.log` are retained both inside `root-integration.tar.xz` and directly under `integration/`. The incomplete first run remains `INCOMPLETE_NOT_QUALIFICATION`: its terminal test report was not observed. The subsequent focused source/adapter report records 71 tests, zero failures/errors/skips, and does not claim cold qualification.

## Large originals retained separately

The coordinator confirmed durable retention with matching size and SHA-256. No signed URL or private access identifier is included here.

| Original filename | Bytes | SHA-256 | Public source identity |
|---|---:|---|---|
| `outcomes.jsonl.gz` | 14,779,166 | `4bab6b4732699fcd09610b95c2d9e8d1b85d95fb412a4439be126a970fcd1585` | Independent JSON audit raw outcomes |
| `c80eb2-native-attempt1.zip` | 41,214,916 | `c1d137bf8f54afaff613e725c152e84ecb19cab20fd03f94531e8392ffef11ec` | Original GitHub artifact `13824752138` |

The package is evidence only. It does not assert that the whole language is self-hosted or the entire stack is HIA native.
