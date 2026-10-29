# b1fc unified-source CI artifact review

Both recorded CI jobs passed on public source
`b1fc801320c1ea8d0bca4708721cad49fd591c58`. Its Git tree and the tree of local
source `ed7958626ef213b6e9445954402e7e7ab65f3ebf` were directly checked as
`9c638e9506eaa08ee59c8901ebb2a44378f93af4`.

This package reviews retained evidence from that exact implementation. It does
not retag earlier local experiments as b1fc experiments and does not qualify
later code changes.

## Artifact identities and actual runs

| Job | Run ID | Artifact ID | ZIP bytes | ZIP SHA-256 |
|---|---:|---:|---:|---|
| Source/application | 40861350818 | 12892241108 | 75,465,013 | `82dd8adfac01454f4d267d6e83a67d11fdde701e288d3c7a0f0a39b89f5c37ae` |
| Broad verified/native | 40861350834 | 12891724659 | 4,942,215 | `130b40196ee1091ed8757ee02c351f6b7c2e697d69e89cdfe32739c5a467d359` |

Actual local ZIP bytes match the original GitHub metadata's digest, size and
workflow head, as well as the separate downloader receipt. Both original
metadata objects and download receipts are retained. No temporary signed
download URL is recorded by the reviewer. `CI_RUNS.json` also preserves the
successful push-triggered source job; that duplicate run is not counted as an
additional sample.

## Test identity accounting

| Suite or intersection | Different test IDs |
|---|---:|
| Source regression | **262** |
| Broad regression | **774** |
| Safety contract | **37** |
| Source and broad | 242 |
| Source and safety | 7 |
| Broad and safety | 24 |
| All three | 5 |
| Union of all three | **805** |

The counts are derived from the actual logs and artifact results, not assumed
from a prior release. The source and broad suites each have zero failed, errored
or skipped tests; broad lists 81 distinct modules. The 805-ID union is a set of
different identifiers, not 805 statistically independent experiments.

## Three separately bound native reference profiles

| Study profile | Ordered reference rows | Source snapshot files | Public cases | Hidden cases |
|---|---:|---:|---:|---:|
| V8 | 19/19 | 170 | 54 | 472 |
| V9 | 19/19 | 176 | 54 | 472 |
| V10 | 19/19 | 189 | 54 | 472 |

Each profile has its own protocol path, schema, protocol digest and source
bindings. Registry order, original reference response, query digest, immutable
source snapshots, persistent per-row files, compiler records and identity
boundaries agree. All recorded public/native/resource/applicable HIA VM and
terminal-hidden gates pass.

For **each profile**, the reviewer read and hashed 19 ELF executables, 8 HIA
native objects and 8 HIA Core artifacts. Native stdout agrees with retained
observations and expected values; resource accounting is checked against the
declared task contract. Each profile has 15 distinct executable hashes across
its 19 rows. No artifact is executed during this audit.

The profiles share the same 19 registry IDs. There are **57 profile-tagged
reference records**, not 57 different tasks or Agent successes. For every
profile, `model_requests`, `tokenizer_invocations` and `agent_successes` are zero;
`capacity_qualified` and `model_qualified` are false. These CI controls do not
override the separately recorded negative V10 model qualification.

## Scalar and source-byte checks

The source phase reads all **449** selected scalar obligations, their actual
Core and LLVM bytes, and retained SMT query hashes. Their recorded results are
449 verified, zero unknown/refuted, with the five original negative controls
recorded as four refutations and one profile rejection. This is an independent
check of retained solver evidence, not a new solver run or a proof covering the
whole language, native optimizer, memory or concurrency semantics.

The source stage checks **942** distinct Git blob paths. After adding the broad
inventory, the union is **4,330** distinct paths, all read directly from the
immutable local commit with lazy fetching and network protocols disabled.
Overlap is reconciled by exact path/blob/size/SHA identity; source-stage paths
are included in the final union rather than added a second time.

The broad job log separately reports **36 native NDU observations** with a
successful result. This audit reads that job-log record; it does not reexecute
those observations or establish NDU profitability or a performance advantage.

## Staged review and reproducibility

The unchanged `review_ci_artifacts.py` check functions from the previous audit
are reused. The small `review_ci_b1fc.py` driver performs source/common/scalar
checks **once**, then calls the reference checks separately for V9 and V10 while
retaining all three source-binding groups. The later broad stage consumes the
hash-bound successful source review and reads only its own artifact; it does
not repeat the source/scalar checks. Both complete stage runs pass.

Original source review SHA-256:
`e307838b2db86a7b4022453ea8389f59705edb3565b0cb7fd59b25fb4d8c5221`.

Original broad review SHA-256:
`cdbfefe327379dfe04266e22fff969c20a520acb17dc8979c6bd97384e7eaa4e`.

The four large JSON review/read inventories are stored as lossless compact
JSON. `RECONSTRUCTION.json` specifies the original byte counts, digests and
`json.dumps` settings. Each reconstructed original was checked byte-for-byte
before packaging. `COMMANDS.json` retains both actual invocations and original
absolute paths. The base and stage-driver source bytes are included.

An initial metadata-display probe assumed the older nested metadata wrapper
and stopped with `KeyError: artifact` before reading ZIP members. The new raw
GitHub metadata and separate downloader record are handled directly; no
producer metadata or scientific gate was changed. `PREPARATION_NOTE.json`
preserves this preparation issue separately from the two successful audits.

All reviewer model, tokenizer, native, compiler, solver, test and network-fetch
execution counts are **zero**. Remote tool identities and source-stability flags
remain producer records; the review is not hardware attestation or a guarantee
against a compromised compiler or host. No scientific acceptance gate is
upgraded by this audit.
