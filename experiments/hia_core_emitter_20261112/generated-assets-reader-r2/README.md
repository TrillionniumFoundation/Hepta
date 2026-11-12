# Independent Core generated-source receiver r2

This new read-only custody control is independent of original receiver run 43138417048. That original run, workflow commit 0753cae7150e2c8d01b0d5cbec41264e831b5d3e, branch reference and queued observations are preserved. It is neither cancelled nor relabelled nor rerun.

The original receiver remained queued with no started step in the 2026-11-12 03:58:11 UTC observation. The new workflow uses ubuntu-latest, a runner label that has recently started a separate reviewed operation. This does not establish why the original job is queued. Runtime, operation and filesystem identities are freshly observed; no old identity is substituted.

The worker, controller, original receiver helper, guardian, process owner and asset inventory are copied byte-for-byte from reviewed control A 8b10b000a43e57cdaa27f60d425b6625e4b2209a. Only four policy identity fields change: control prefix, trigger branch, private work-root name and public custody-root name. The workflow also binds its new exact control commit and policy hash and uses its new independent identity.

The source remains artifact 13907470026: 12,049,642 bytes, SHA-256 e6d54cec5c3788221827bf25a3189838dbc884211d89c3ef86afa129117319d8. All 103 members still require full bytes/SHA/Git-blob/CRC verification, with the same 54 selected originals totalling 7,251,108 bytes. The original 900-second owner, 3-second cleanup, 8 MiB raw-frame budget, 12 MiB stdout budget, 24 KiB frames, transport limits, token separation and bounded partial-HOLD custody are unchanged.

No generation, project execution, native compilation, product test, cold qualification or old product replay occurs. The original 39 HIA assets and ABI are recovered as historical bytes, not regenerated. The unrelated UNKNOWN TimSort operation is untouched. The new execution branch has not been created by this checkpoint; root review and one unique trigger remain required.
