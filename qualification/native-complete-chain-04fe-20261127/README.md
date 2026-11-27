# Exact 04fe native cold, release, installation and installed-source rebuild

This evidence records the actual completed native construction chain for Hepta
`04feaffc29bd77ae4ab3695eb08602726a01ba1c`, tree
`94757793dee4e46b80db5586c9f2dfc2db39ed82`. All 1,289 production source
inputs were frozen before execution and re-read unchanged at the end.

## Actual result

The original 60-phase, 479,882-node cold qualification passed all 14 checks.
Its native nested execution took 120.528958803 seconds within the unchanged
180-second budget and 3-second cleanup allowance. The traced cold entry
completed in 134.786016751 seconds. The original scheduler bounds remained
two phase workers, one archive worker, two pending archives and four unsealed phases.

The subsequent eight-role source bootstrap completed in 29.320753255 seconds.
Ordinary native release completed in 650.744223207 seconds. Native depot
installation completed in 21.353478234 seconds and installed native verification
in 18.596833448 seconds. Finally, the installed native tool rebuilt the complete
source in 682.706468874 seconds, within the original 1,800-second release budget.

Both complete release packages are byte-identical: 194,753,597 bytes,
SHA-256 `201fd124d0c6fc80cb9ad97816e4f69cbc1ea669462b3f86d168566f57817f7e`.
The installed depot contains all 301 actual package members. Every descendant
observed by the original process tracing was native. The process counts, original
commands, all terminal return codes, resource observations, receipts and full
execution traces are retained without replacing any failed attempt.

## Preserved attempts and custody

The first chain output failed with real ENOSPC after 1.419 seconds: the native
CLI returned 74 and the supervising Python process returned 120. It did not
reach a cold semantic or 180-second timeout failure. The original truncated
report, trace and resource record remain in this archive.

An earlier supervisor observation requested a nonexistent export/report.json
after all four preconstruction commands had already returned zero. The actual
export/qualification.json was read back; no successful product command was
replayed. That original observation failure is also preserved.

The successful full chain used a separate chain-v2 output. Its supervisor
returned zero after 1,541.645939828 seconds. The source, cold report, three
original compiler generations and installed tools were all re-read unchanged.

## Files

- complete-core-logs.tar.gz: all 306 retained core manifest, report, receipt,
  source-provenance, log and full trace members, SHA-256
  `4e06a5d671fb61f1e279a010eca19a19d05ddc33acdd2dec0ab4815397196301`.
- complete-manifest.json.gz: the exact complete 5,186-path inventory. Its
  uncompressed JSON is 1,227,241 bytes, SHA-256
  `0183d6572f8d4d8844af85716c2fc26151be06e6a741057d9e0b3079dceed67d`.
- qualification.json: the original completed readback and all stage timings.
- replica-verification.json: the independent Mac verification of every retained
  path, all 1,973 unique blobs and the complete core archive.

The complete retained evidence represents 4,142,316,741 regular-file bytes
before deduplication. Its content-addressed archive is 522,821,757 bytes,
SHA-256 `511eb539bb0cbb330bc0d42122a3046692eac0a06378d40aa464f22cb1b90b99`.
Every blob was checked on both hosts. The two complete physical copies are:

- ROG: /run/media/qian-qi/TOSHIBA_DEV_1TB/hia-closed-evidence-20261127-2ac5/native-complete-04fe-v1/complete-evidence-cas.tar.gz
- Mac: /Users/qianqi/work/hia-native-complete-04fe-evidence-20261127-2ac5/complete-evidence-cas.tar.gz

The complete Git-backed authoring worktree is identified by its exact commit
and tree; the actual native source export, construction products, both chain
attempts and installed files are included in the retained inventory. The
original live source, packages, three generation files and depot were not
removed or changed during archiving.

## Completed scratch relocation

After the complete evidence had been verified on both hosts, the two completed
chain-v2/.hia-build-* scratch directories were checked against the same full
manifest again. All 1,208 files (1,557,968,928 logical bytes) and their original
file modes matched the retained archive, and no active process used those paths.
The first cleanup stopped explicitly at a read-only verified-package directory
after removing 303 already archived files. A separate reconciled attempt verified
the remaining 905 files and made only the owned scratch directories writable
before removing them. Shared file permissions were not changed. The original
failure and the terminal successful readback are in scratch-relocation-readback.json.

The source worktree and Git objects, original cold report and three generations,
source-bootstrap tools, installed depot, both complete release packages and the
separate public Worker installation failure remain in place. All relocated
scratch bytes and modes remain in both verified content-addressed archives.

## Scope

This is a real native cold, ordinary release, depot installation, verification
and installed-source rebuild PASS. Worker installation and its public
START/STATUS/read/witness qualification, final host-caller integration and
legacy retirement are separate gates. No success is transferred to another
Git HEAD, no generation index is relabelled, and this record does not assert
that whole Worker/public delivery or legacy retirement has passed.
