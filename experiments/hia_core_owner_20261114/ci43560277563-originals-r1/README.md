# Core owner CI43560277563: verified original failure and preserved originals

## Current result

The original standard CI run 43560277563, attempt 1, failed at native step 40. Its admitted original process owner records a 180-second qualification timeout, return code -9, and completed cleanup in 0.051362859 seconds within the original additional 3 seconds. No product qualification was rerun to obtain these originals.

The original groups show 15/15 component tests and 51/51 machine tests complete; the final Core group has 35 starts and 34 completed OK outcomes. Therefore 100 of the original 116 methods completed, 101 started, and the final callers report is missing. The last started method is `ByteABIAdmissionTests.test_direct_byte_object_emission_needs_no_llvm_or_subprocess`. This frontier does not establish its performance cause.

Both independent Core builds returned all 39 units, 78 total. Their per-unit timing sums are not full build wall times. The component group's 47.991 seconds already includes its own build. Preserve both builds and the original 15 + 51 + 50 population.

The installation control passed its current gate but still installed 176 Python files and 111 resource files. It does not establish whole native installation.

## Provenance and complete byte transport

- Fixed original head: `4597913bd67d1b1d84a378bf82327c96f344bc81`; product tree: `bbf636708811f3a8297b3a9dba86720df08fdb79`.
- Diagnostics-only collector: run 43569181054, attempt 1, job 132369583798, head `59ecea13b79a1f771c5c850167034610e620df14`.
- Original source artifact 14101986435: 613570248 bytes, SHA256 `a1d1a0a1d580f9ffafb20f5400aef515becf7ac47d48e2850ef4c7ffe08b64f3`.
- Complete small artifact 14104345269: 14627724 bytes, SHA256 `8d939283e347be007ef85d0d4595385685f6c145ecaa2d25c1b6ecea6c0fd787`.

Root independently read all 39 complete small ZIP members and checked their headers, descriptors, CRCs, and hashes. Root independently read both complete large-archive metadata JSONL files, joined all 19542 records, and verified all 23 selected original bodies. The reviewed collector read every body in the large original archive; Root did not independently repeat the complete 613570248-byte download and body decompression.

`small/` contains 37 direct, byte-exact members. The two larger metadata JSONL members remain inside the complete original small ZIP. That complete ZIP is preserved as a deterministic gzip stream carried by the nine base64 texts in `transport/`. Follow `transport/RECONSTRUCT.json`: independently decode each carrier, concatenate the decoded chunks in order, check the full gzip hash, then decompress exactly one stream and check the complete ZIP hash. The full original ZIP and every original member can be reconstructed without inventing missing data. These carriers do not partition or substitute for the 613570248-byte source artifact.

Root independently decoded that gzip with a separate bounded V8 decoder, checked single EOF, CRC and ISIZE, and obtained the exact original ZIP hash. `GZIP-REPORT.original.json` is a passive byte-transport result, not a product qualification. Signed URLs and their private request were excluded.

`small/originals/INDEX.json` maps the preserved opaque member names to their exact original product paths. The only missing selected original is `hia-core-lowering-callers-evidence/report.json`. No replacement report is fabricated.

## Static optimization candidate

`candidate/` preserves an unexecuted balanced-dispatch generator draft and its textual/numeric review. Only the full `unit_source` author function changes. Instruction bodies, effects, entry rules, ABI, sequence, and all original gates remain unchanged. Static routing comparison covers all 2428 PCs and boundary rejection; it does not establish timing equivalence.

The worst comparison count changes from 16 to 7, but 570 PCs have more comparisons, 228 have the same count, and 1630 have fewer. The existing exact fixture rejects this new generator revision. A precise successor fixture, real generation, all 40 actual output identities, original nine capacity checks, matching cold replay and the complete original qualification remain necessary. No candidate Python execution, generation, HIA compilation, VM, native, test or CI result is claimed here.

The remaining-project matrix in `closure/` is preserved at its original review time. Its earlier Core-raw UNKNOWN wording is superseded specifically by `ROOT-ORIGINAL-CLOSURE.json`; its remaining whole-project blockers still apply.

## Whole-project boundary

Whole-stack closure remains HOLD. Default CLI/runtime, production SQLite/store integration and recovery, solver/proof, Rust/build replacement, whole native install/activation/upgrade/recovery, original Full32 at the final exact source, and explicit dependency/retirement checks remain open. The earlier content-review-blocked CLI CPython runtime port remains blocked and has not been resumed; FOR_ITER remains unwritten.

No default branch or PR head is changed by this evidence archive. No merge, activation or legacy deletion is performed. All 4154 parent-tree leaves are preserved in the archive commit. The evidence branch may advance by one fast-forward evidence-only commit marked `[skip ci]`; no collector or product qualification is intentionally retriggered.

See `ROOT-ORIGINAL-CLOSURE.json` for the admitted owner, unchanged budgets, actual frontiers, full provenance and practical limits.
