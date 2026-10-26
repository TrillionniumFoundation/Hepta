# Hepta direct P3/P5 integration: target object symbols + Owned LLVM publication

## Exact immutable basis (2026-10-25)

- Parent integrated owned candidate: PR #137 `8ae80897fa08adfa3608ad65b505387ac2dba997`.
- Sibling five-target symbol gate donor: PR #136 `54ee112ff842131f4a54cb6648a9f640a1a7d22a`.
- Shared common ancestor: PR #135 `c483b4cedcc03a8bfcbe02d3c6b3f644f8c8af59`.
- First combined eight-file Git object commit: `531c14f27613fc8bd1e98a95613095c5eb20c74a`; tree `9e7177f2c5c101fbe5f4a896e17e1fca4ae8ca35`.
- The eight paths were selected only after verifying that each donor path's **base blob SHA matched the parent PR #137 blob SHA** (or both paths were absent). The three symbol scanner, negative test and documentation files are exact donor blobs.
- Two overlapping paths, `hepta/llvm_owned_pipeline.py` and `tests/test_llvm_owned_backend.py`, were intentionally **not** replaced by PR #136 versions. PR #137's checked resource clauses, verified ELF dynamic imports, source identity revalidation, exact output publisher and new tests remain the integration owner.

## New functional P5 reconciliation

The native-owned source-facing output is a second publication after the backend's staged object. A successful call to `publish_verified` no longer suffices by itself for source compiler success. The integration adds an independent `recheck_verified_publication(stage, destination, expected_bytes)` invocation before minting the outer receipt. It checks that both paths still resolve to the same regular hard-linked inode, that full bytes match the already validated object and that the file identity remains stable. A rejected output is unlinked only if its inode is still the compiler's own stage; replacements from other writers must not be deleted. The original current-source-graph and compiler identity recheck remains mandatory *after* publication.

The source-facing Owned LLVM injected test now corrupts the destination **after the first publisher returns**. This is a different trust-boundary test from corrupting inside `os.link`, because PR #137 no longer uses a direct source-level `os.link`; it uses the shared `publish_verified` helper. The test expects `E_LLVM_OWNED_PUBLICATION`, no successful receipt and no own output left behind. The existing source-edit-after-publication test remains.

## Direct local execution and limits (no CI)

- Exact Git source for `hepta/artifact_publication.py` reconstructed in an isolated Linux host directory. `git hash-object` matched remote blob `242fe8d5b7693fa8eb1954c5b51c9af9a1449816` byte-for-byte.
- Actual Python **3.13.5**, Clang **17**, GCC **14**: **7 / 7** standalone tests passed without skips. Tested verified first+second hardlink, mutation after first receipt, replacement with different inode, symlink, FIFO refusal, competing-writer preservation, and **real Clang LLVM-IR to ELF object -> exact-file verified publication -> GCC C executable that returns zero for hepta_native_check(41)==42**.
- This validates the exact self-contained publication helper, **not** the full Hepta source-facing owned pipeline. No Rust 1.90/Clang20 repo checkout is available on this execution host, so the new native Hepta source tests have **not run**. Do not inherit #115's previous 44/46 from its earlier code snapshot.

## Remaining P0–P7 blockers

Canonical checked HSIR is inherited, not a whole-language proof. General stored lifetime generics and machine pointer provenance remain open (P1); broad C/C++ migration and real foreign ABI/exception safety remain open (P2–P4); owned LLVM full-type/backend equivalence and the frozen scalar and owned performance **stability** failures remain open (P5). Real controlled provider Agent 2x2 trials remain **zero** (P6). Physical boards, DMA, GPU/NPU and multi-host production service execution remain open (P7). QEMU/Windows receipts are pinned to their own historical code identities.

`whole_project_blockers_closed=false`. This branch is reviewable source progress, not production release qualification.
