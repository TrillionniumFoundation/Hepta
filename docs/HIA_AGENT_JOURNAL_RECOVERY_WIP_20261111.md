# Request-journal owner recovery checkpoint

Status: **DEVELOPMENT / WIP; reconstructed after executor loss.**

This branch starts from exact commit `93d66bcc3acb88212c9b153d7852ba22eeab24c8`, tree `0a67bf07951505a50e9aeb888f1c2c448d1eb816`. It does not modify the published v63 qualification, running service, or existing data.

## Custody

The original isolated worktree was `/tmp/hia-e26e-native-state-owner` on branch `codex/hia-native-state-owner-20261111-e26e`. Its executor became unavailable before a source commit. The new generator, adapter and generated HIA bytes were not retained outside that executor. The record below is a context-derived historical record, not recovered byte custody or a qualification receipt.

Historical development compiler SHA-256: `0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
Historical v2 HIA source SHA-256: `eb45d7af71edeca5cc6cd44304361e81052e41b5232270e3cc89bd6af0e64bae` (311586 bytes).
Historical v2 image SHA-256: `3b1382211a0bf52ffa23f37560adcf8c295507e523fde10cb00e775984343edf`.

The historical v1 compilation was rejected by the native compiler's per-function CFG bound. Chunked literal comparison removed that excessive CFG growth in v2. A v2 native smoke observed request/key hashes matching independent SHA-256, reserve/ACK/effect/final instructions, and one real SQLite artifact call plus exact replay with the retained call owner forbidden. Complete tests and installed qualification had not run. The final Core VM smoke result was not recovered. None of those observations qualifies reconstructed source.

Reconstructed files must receive fresh generation, compilation, source/ABI tests, ordinary selected-owner regressions, and independent cold qualification. They must not be assigned the historical source/image hashes.

## Proposed ownership boundary

HIA owns original canonical request identity, known-tool admission, top-level request-key admission, journal key binding, reserve/replay/conflict/unknown decisions, successful verification replay routing, terminal canonical response and cost detail bytes, and instructions controlling journal/cost writes. Python remains a mechanical SQLite and foreign-object bridge. SQLite still owns locking, transactions, durability, recovery and concurrency. Business methods, schemas, installation/context/budget checks, retained proof verification and alias authority remain separately hosted or existing native owners. This change does not make the full AgentStore/service native.

Explicit selection is planned through `HEPTA_HIA_AGENT_JOURNAL_MANIFEST`, bound to the exact checked-in HIA source and installed catalog. No fallback to retained journal decisions is allowed after selection.

## Required compatibility

- Compute the original request digest before resource alias expansion.
- Claim a known tool's nonempty string key of at most 192 Unicode codepoints before full schema admission. Preserve the legacy order of unknown-tool, key, schema, installation and context errors.
- Compare digest before journal state. A completed entry returns its cached response without effect, cost or update. Any other existing state is unknown, never a retry of the effect.
- Route a completed successful `hia_verify` replay through retained evidence verification before returning it.
- Insert running intent, then acknowledge reservation to HIA after observed SQL INSERT success and before transaction COMMIT.
- For adopt/rollback, keep slot mutation, completed response UPDATE and the HIA response ACK inside the same SQLite transaction. ACK follows successful SQL UPDATE and precedes COMMIT. A later COMMIT exception must preserve the old reserved-flag behavior, including running intent after rollback and rejected first response.
- Permit no repeated, fabricated or out-of-order ACK.
- Preserve trusted arbitrary-precision clock observations as TEXT; do not narrow them to u64.
- Malformed cached response must refuse; it must not silently invoke the effect.
- Preserve separate 8 MiB canonical response and cost-details channels, all finite binary64 values, original JSON budgets and source-order foreign materialization.

## Validation still required

Source regeneration and Core VM transitions; actual native ABI/canaries and independent canonical/hash comparisons; all ordinary tools with retained call owner forbidden; restart/replay/conflict, real process crash, proof replay, lease/CAS, costs and COMMIT fault controls; installed wheel source/catalog/resource binding; selected-owner existing suites separately from unselected whole regression; independent current-source cold build. No suite result is asserted by this checkpoint.
