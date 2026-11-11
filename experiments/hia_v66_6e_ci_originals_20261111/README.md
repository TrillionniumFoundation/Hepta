# Exact 6e failed CI artifact: original bytes and independent audit

The original GitHub workflow remains **FAILURE**. This checkpoint preserves its complete original ZIP and records a read-only audit. It executes no product tests and makes no whole-native or full-retained qualification claim.

## Identity

| Item | Exact identity |
| --- | --- |
| Repository commit | `6e048234e19e4dbf02d1cf5040831fba07748f02` |
| Canonical tree | `440f3fcb9014b2af6c788f78b993af6b25730d46` |
| Workflow | [43038321007](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43038321007), original push, failure |
| Original artifact | `13865519334`, 122,628,168 bytes |
| Original ZIP SHA256 | `7ff3905907ac8a02e0b5366ce4bbc3c24e5794c9dde94a0f87149c9ed9cc5137` |
| Lossless zstd | 63,568,818 bytes, SHA256 `b7e36d63bbbad93bfadc95c0b429db34bb8b8996d9ce7041c021b6836b057bc6` |

## What was actually verified

All 6,176 outer ZIP members were read completely, checking CRC, exact length and SHA256; they contain 578,435,037 decoded bytes. Every one of the 38 cold phase archives was then independently verified with the exact source-bound archive utility, including all 42,623 inner files, 2,397,876,480 decoded bytes, member SHA256 values and modes, and the original phase retention receipts.

All 669 exported source files match the canonical 6e Git tree by path, exact bytes, size and Git blob identity. The support contract declares 668 files; the support contract itself completes the 669-file cold closure. Canonical Git modes and actual exported modes are recorded separately: the canonical replay deliberately writes each exported source file with mode 0400. No current mutable checkout supplies old-source authority.

The actual B3 is 668,608 bytes with SHA256 `0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`. All 23 discovered native manifests bind that compiler and a source hash from the exact closure. Both strict machine-plan and machine-encoding caller builds additionally bind the original cold report, request, actual compiler input/output bytes, compilation receipt and final native image.

## Original results, unchanged

| Original gate | Observed result |
| --- | --- |
| Cold | PASS, 132.140118786 seconds against the original 180-second limit; 11 outer and 5,051 nested checks |
| Cold ownership | Natural exit 0, complete cleanup, ECHILD, no remaining children, forced child kill, overflow or interrupted signal |
| Language | 1,242 checks and 10 report assertion tests passed |
| Native components | 67 exact loaded/executed tests passed |
| Machine-plan callers | 44 exact loaded/executed tests passed |
| Selected journal callers | 94 exact loaded/chosen/executed tests passed |
| Machine-encoding component | 9 executed; one retained-reference AST comparison failure; 374 actual native entries across 37 commands |
| Machine-encoding original callers | Expected 51; not executed after the component failure |
| Ordinary wire callers | Expected 89; original GitHub step skipped |
| Overall workflow and both jobs | Original failure |

The encoding failure is `MachineEncodingSourceTests.test_retained_reference_methods_are_unchanged`; the original component report and traceback are preserved verbatim. The 51 expected IDs are derived statically from the exact five canonical test files, including inherited methods. The 89 expected wire IDs come from the prior d2 loaded set, with every relevant test module's Git blob, size and mode verified identical between canonical d2 and 6e. These expected counts do not represent new executions or successes.

## Retained audit attempts

The complete original ZIP was never modified. Three preliminary audit attempts completed the underlying integrity checks but stopped while computing auxiliary expected denominators: the first assumed retained test files belonged to the smaller cold export, the second rejected known method-preserving `unittest.skipUnless` decorators, and the third made the same cold-export assumption for wire test modules. The final audit reads the exact canonical Git sources and records the known inheritance/decorators. All four auditor revisions, original stdout/stderr, process records and three `AUDIT-HOLD.json` files remain in `audit-originals.tar.xz`. These are audit implementation attempts, not product reruns or replacements of the failed CI result.

## Recover the complete original ZIP

The 16 files under `original-zip-parts/` are concatenated in their manifest order and decoded as one zstd stream. `ORIGINAL-ZIP-PRESERVATION.json` binds every part's size, SHA256 and Git blob SHA1. The original compression was fully decoded and compared byte-for-byte with the unchanged original ZIP; the separate restoration script also independently reconstructed and re-read the exact original bytes.

With Python and `zstandard` available, run from this directory:

```sh
python -B restore_original_zip.py /absolute/path/to/a/new/output-directory
```

The output directory must not exist. The script verifies every part, the combined zstd size/hash, the decoded ZIP size/hash, and an independent final file readback. It retains partial output if verification fails and never overwrites an existing directory. Its `RESTORATION.json` states the original workflow failure and that no product tests ran.

`AUDIT-ORIGINALS.json` lists every exact small audit input, original report, log and script retained in the adjacent archive. `CUSTODY.json` binds the final reports, archive and full-ZIP pieces. The original workflow's separate full job logs and first AST diagnosis are also retained in root's checkpoint `f70d936256b08acb3e0e0d32e2b8684dbd716cbe`; this audit does not substitute a new result for those originals.
