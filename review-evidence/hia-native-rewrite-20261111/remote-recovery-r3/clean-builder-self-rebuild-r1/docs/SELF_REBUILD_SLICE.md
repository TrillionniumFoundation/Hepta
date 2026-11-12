# Native clean-builder self-source reconstruction

## Current state

This is an inactive, source-only slice. The two new reader inputs and this inventory have full Git text readback. There has been no Python AST, source import, generation, B3, VM, native run, archive replay, installation or activation in this revision.

The exact R13 handoff says its seven source recipes and two packing operations completed, but the resulting package retains the bootstrap `hia-build` executable. This slice removes that specific self-copy after exact original recovery. It does not replace the public C/build transaction owned by native_checker, and it does not claim the full 15-action CLI, 11-tool Worker or namespace migration.

The source inventory in `evidence/INITIAL_SOURCE_INVENTORY.json` binds the audited entry and installation files and the original custody. Historical results remain historical: the new reader does not rerun or borrow those results.

## First executable step: complete original recovery

The standalone standard-library reader reconstructs the original 57,162,628-byte archive from all 19 exact repository parts. It binds every part's path, size, mode and original Git SHA-1, records each computed SHA256 in the new custody, then verifies the whole original archive SHA256 `721d89da963f863e3760d9577f3585b0cd9d6f3c71a36ee597d975baf12e388b` and both original custody/handoff files.

It materializes every one of the 814 members: 661 regular files, 153 directories and 171,212,656 raw file bytes. No symlink, hard link or sparse payload is accepted. All original file bytes and modes and directory modes are checked again unconditionally. Original archive and stored compressed CAS bytes stay in the output; logical CAS expansion and historical target replay are deliberately not part of source recovery.

Exactly 21 pinned original text files are exported after complete member validation. They include all clean gate/driver/package/packer/executor authors, their development compile/build code, original design, bundle and installed-chain summaries. Each console export has original path, bytes, mode, full SHA256, computed Git SHA-1 and complete base64 bytes. Source text is decoded only as UTF-8; it is not imported, parsed or executed.

Run from a verified repository checkout, with a new output directory outside it:

```sh
python /absolute/checkout/review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/clean-builder-self-rebuild-r1/ci/read_original_clean_build_r1.py --repo /absolute/checkout --out /absolute/new-original-output
```

The config defaults to the sibling `original-inputs.json`; the reader pins its exact Git SHA-1 and SHA256. There are no external package, common.prepare, network, Git-subprocess or historical-host dependencies. The checkout supplies the 19 original parts and two original JSON files listed in the config. No source checkout is mutated.

The reader retains the original limits: aggregate self plus child CPU strictly below 90 seconds, full elapsed time strictly below 180 seconds, 1 GiB address space and zero core limit. There are no target children. Final gates run after complete stdout and after final receipt readback. Initial failures are preserved; later receipt failures are appended, with independent best-effort FAIL rewrites. `complete_original_archive_and_814_members_retained_and_afterchecked` can become true only after full reconstruction, all-member validation and successful after-checks with no pending output.

The workflow should always retain the complete output directory and full stdout/stderr/process record. A reader PASS means exact source recovery only. It is not a build or installation PASS.

## Implementation after the original authors are available

First reproduce the exact old authoring-to-HIA bindings and fixed carrier/prefix before changing any recipe. Preserve the original seven recipes, their order, errors, limits and the complete old bundle/package/source-kit identities. The original clean-builder compiler is 669,556 bytes with SHA256 `35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b`; it must not be silently substituted with the Worker 0e09 compiler.

Then add a source-bound self recipe that compiles the complete clean builder's own HIA control/policy/packing sources through the actual compiler and feeds the resulting images to the actual HIA ELF packer. The old complete builder executable may serve as an identified bootstrap input, but it cannot be copied as the claimed newly rebuilt executable. A retained fixed mechanical ELF prefix must remain explicitly source-bound; it does not substitute for HIA business compilation. Exact input/slot/recipe changes will be derived from the recovered original sources, not invented from the handoff summary.

The qualification must retain the complete source-kit and recipe receipts, compare all output bytes, run the rebuilt builder on the same immutable kit, and prove the next generation reaches the same builder/package fixed point. A separate real mutation of a reachable self-owned HIA source must affect the actual compiled self image and final executable, then reach its own second-generation fixed point. Only a manifest change or a copied old executable is insufficient.

Installation and installed rebuild use an isolated destination and original empty-PATH/HOME constraints. No default selector or production entry is activated by this slice. Native regeneration of the broad support contract is still a separate open task; its current Python source inventory is explicitly retained in the initial audit.

## Ownership and unresolved gates

Root alone commits and changes refs. This owner changes only the isolated clean-builder slice after recovery. native_checker continues the public C/build file-custody, Core/Graph, backend and publication transaction; audit_runtime continues the physical Store owner. All old failures and original test budgets remain unchanged.

At this delivery the original archive has not been read by this new reader, the full old author text has not been restored, and no new self recipe is qualified. The reader is the concrete next executable dependency, not a claim that self-rebuilding is complete.
