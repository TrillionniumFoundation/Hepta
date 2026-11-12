# Exact ba714f original run and corrected read-only audit

The original GitHub Actions run **43191718592 remains failed**, and its original `FINAL.json` remains `HOLD`. The independent verifier used `argument_count == 3`, although `NativeHiaJsonImage` declares three pointer/length pairs, and the bounded-read adapter passes their six flat C ABI parameters. All 210 original completion records contain six arguments.

## Original bytes preserved

The official 17,443,242-byte artifact (13930698085, SHA-256 `bec5a2317ee9a1590dcd2ab2ac642df78012b7b32bebe5bcd6269bdbc563a506`) is stored completely, losslessly, in the 34 binary parts named in `../ORIGINAL-ZIP-RESTORATION.json`. Concatenate those parts in their listed order and verify the full seal before opening the ZIP. No archive member must be extracted or executed to verify this restoration. All 15 outer members and all 897 typed tar members were independently read. Regular originals total 103,811,800 bytes; symlink and FIFO entries were checked as metadata without opening their targets.

The first immutable custody checkpoint is `f76e1e1fcbe118519aa70f8ff13f6ab8b9419aad`. Its receiver archive also preserves the original job log, provider responses, all receiver scripts, five finite archive-reader controls, the initial 182-join audit, and the actual original failure.

## Corrected observation, without a product rerun

Pre-execution checkpoint `cbcab02f6467ae0ff1321318db0780e81bb8b497` changes just `3` to `6` in copies of the frozen verifier and independent record reader. Both original files remain preserved. The new driver imports no Hepta product module and does not invoke an image, compiler or installer. It reads the same closed ZIP, exact canonical source bytes and the original recorded identities.

The single corrected read-only audit exited zero after 4.045538650 seconds, with **262 checks passed** and no errors. The original predicate evaluates false on the original record population; the corrected predicate evaluates true. Four controls replace the argument count with 3 or 5 in all 210 records or one actual record; all four are rejected. The previously unreached original verification tail checks all seven complete fixtures, continuation records, negative-manifest bytes, module origins, restored installed bytes and modes, and the descriptor's non-runtime role.

## What the original run actually recorded

- All 55 finite controls and the original eight methods completed, including seven real CLI child processes under their unchanged 20-second timeouts. The caller observers recorded 12 read attempts and 11 returns.
- All nine installation cases completed. Seven public reads produced 210 normal native entry returns: 203 continuation statuses and seven terminal statuses. One fixture contains the full 8 MiB input.
- Fresh B0/B1/B2, original compilation request/receipt/stdout/full-output bytes and actual images were independently joined. The B2 image is 668,608 bytes with SHA-256 `0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`. The bounded-read image is 73,701 bytes with SHA-256 `fb9763ad12e967b5543ea514e84012470dd86a8999e7e51277a5c5235badc533`.
- The actual source distribution has 286 regular members, the wheel has 282, and the restored installed tree has 286. Their complete bytes and member metadata were read. They contain 170 Python sources and all 105 resource paths.
- The outer original owner observed a natural exit after 46.318889354 seconds within its unchanged 180-second limit; it and all 14 inner owners reached natural ECHILD cleanup. Original compiler 20-second/10-CPU-second limits and the installed child five-second limit are unchanged.

## Scope

This is a corrected review of a failed workflow's original evidence. It does not replace the original failed status, constitute a successful CI rerun, or qualify a different source revision. Exact ba714f source is the only bound product. The hosted filesystem/context effects, broader foreign-object/finalizer/GC/async semantics, default activation and formal cold/full qualification remain outside the result. The ABI descriptor is retained source-owned metadata and is not read by the runtime adapter. External Python/git/linker binaries are bound by their original identity reports, but their byte files were outside the owned archive and were not independently recovered here.

`REPORT.json` contains all 262 exact checks. `HANDOFF.json` provides machine-readable identities and limitations. The peer's original static review and its correction are both preserved unchanged.
