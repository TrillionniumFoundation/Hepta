# Preserved scalar v2 CI originals — e632886e

This directory preserves the **original successful CI evidence** for
`e632886e3ae63365b509aa29529d0968a228346d`, tree
`3fc34baf1710a99093e181a7d6c87bb373c4204f`. It is an evidence-only addition:
the receipts remain bound to that qualified implementation, not to the later
commit that stores this archive. PR #833's source head is not advanced by this
preservation branch.

## Provenance

- [Exact-source run 42629363155](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42629363155)
- [Successful source job 129201346180](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42629363155/job/129201346180)
- Original artifact ID: `13682147300`
- Original artifact name: `hia-exact-source-e632886e3ae63365b509aa29529d0968a228346d`
- Original ZIP: **38,898,072 bytes**
- Original ZIP SHA-256: `321d17dab979ceb0378d7b078446432c77e408d13b82821175ca1715a9e5c421`
- Original GitHub artifact expiry: `2026-12-09T14:17:25Z`

The original ZIP was downloaded through the connected GitHub artifact API and
its byte length and SHA-256 were checked before opening it. The source ZIP
contains 29,554 members, with 1,932,191,336 total uncompressed bytes. It was not
fully extracted.

## Exactly what is retained

The archive keeps these **complete prefixes and exact files**, without renaming
members or changing their uncompressed bytes:

| Original ZIP paths | Members |
| --- | ---: |
| `scalar-adoption-chain/**` | 250: all 249 manifest-listed originals plus the original manifest |
| `scalar-adoption-replay.json.recomputed/**` | 116: the original CI-created model queries, results and validation records |
| `scalar-adoption-replay.json` | 1 |
| `scalar-adoption-tests.log`, `scalar-adoption-chain.log`, `scalar-adoption-replay.log` | 3 |
| `source.txt`, `dependencies.txt` | 2 |
| **Total** | **372 files, 7,003,366 original bytes** |

This includes all four types' canonical and planned object/final images,
canonical Core and source, complete profiles, context, workload, objectives,
cost records, proof receipts and dependencies, original 52 SMT queries, native
measurements, owner observations, adoption and rollback receipts, and full
domain-call journals. Nothing required by the original 249-member packet
manifest is omitted.

The 116 `recomputed` members were generated **during the original CI run** and
copied from that ZIP. Preservation did not regenerate any query, receipt, proof,
native image or observation. Original absolute paths and timing fields inside
receipts are deliberately unchanged.

The remaining 29,182 original ZIP members are outside this scalar selection.
They cover the other source-closure campaigns. Their top-level counts are
recorded in `preservation.json`; no claim is made that this smaller archive
retains the full original source-closure ZIP.

## Archived identity

- Archive: [scalar-adoption-v2-e632886e.tar.gz](scalar-adoption-v2-e632886e.tar.gz)
- Archive length: **544,166 bytes**
- Archive SHA-256: `fd680ab666a4a06940e02906a819f8a8785eee81a6be0f1b441beae0263bc77a`
- Archive Git blob SHA-1: `b98a8587c3728a5bfbaff83e0f9e4c39a1c02849`
- Original packet manifest SHA-256: `7c4280010655083bd2e05ae84cbb03a3762ef4368fcb942c9046fe9ddb434115`

The tar/gzip container normalizes timestamps, ownership and file modes for
reproducibility. **Member paths and data bytes match the original ZIP exactly.**
`selected-files.json` retains each member's path, length, SHA-256, original ZIP
CRC, compressed length, header offset, timestamp and external attributes.

## Offline verification performed

The preservation tool uses only Python's standard library. It checked the
selected bytes against the source ZIP, wrote the archive, then read the archive
back and checked:

- Every original packet manifest entry: 249 members.
- Every exported artifact digest: 208 full artifact references across four types.
- All 52 original query digests and their recorded CI outcomes.
- Byte-for-byte equality of each original query and its original CI-created
  recomputed counterpart.
- The original strict replay's manifest/report digests, full type matrix,
  complete chain results and original source identities.
- The original sixteen-test completion log: **16 tests in 18.092 seconds, OK**.
- The original qualification's recorded **1,000 native workload calls and
  40 owner calls**, including retained/new leases across rollback.

These are checks of retained records and bytes. **No native program, compiler,
linker, service owner, solver or proof generator was executed during
preservation.** The verification does not create another native observation or
another solver result.

To repeat the offline archive verification from this directory:

```sh
python3 preserve_scalar_ci.py verify --directory .
```

To reproduce the selected archive from the original GitHub ZIP, use a new output
directory:

```sh
python3 preserve_scalar_ci.py preserve --source-zip /path/to/original-ci.zip --output /path/to/new-evidence
```

## Accompanying records

- `preservation.json`: pinned source/ZIP/archive identities, exact selection,
  excluded-prefix counts and the offline checks.
- `selected-files.json`: per-member custody index.
- `preserve_scalar_ci.py`: standard-library packager and offline verifier.
- `artifact-metadata.json`: the GitHub connector's artifact metadata, serialized
  as a provenance record.
- `github-job-129201346180.decoded.log`: the complete decoded job log returned by
  the GitHub connector, encoded as UTF-8. This supplemental file is not claimed
  to be an original ZIP member.

The original qualification flags remain false for kernel-checked Core/hardware
soundness, full compiler-buffer refinement, foreign-resource liveness, formal
online-endpoint qualification, production acceptance, execution authority and
economic benefit. Hash consistency and preserved executable-model results do
not promote those scope boundaries.
