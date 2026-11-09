# Selective scalar-control integration onto #817

This integration starts at #817 source
`6a8c297b3f8f21506d11c2cb093c1c58d84ffe55`. It imports exactly fourteen
existing files from `afe3fafe95a9523872249ca9ba5a3929df03b0cf`:

- The scalar-control harness, fifteen-test suite and independent workflow.
- The protocol and original-results documents.
- The five original 64-pair evidence files, including the complete archive.
- The four stop-order and outer-cost accounting review files.

`import-manifest.json` records every selected path, source commit, Git blob
identity, complete SHA-256 and byte count. All fourteen imports are byte-for-byte
identical to their selected source blobs. The source inherits the #812/#814
integration `75e9a462465d94541d1706c2cebb5e30e623af27` and accounting fix
`0fed397e276505910e125eb54cbdfb902ee3e50c`.

The copied-byte ABI branch is not merged. The #817 versions of
`hia_agent_service.py`, `hia_agent_runner.py` and `hia_agent_contract.py` remain
unchanged; no separate copied-byte ABI implementation or lifecycle qualifier
is imported. The #817 Core support declaration and existing source workflow
also remain unchanged. `tools/hia_release.py` is unchanged so that the final
integrator can make one complete source-closure update.

## Validation on the integrated source

Source commit: `b85868550ff064eb9cbced3256a3d45c16109902`.
The source was clean before and after validation.

- All **15 evidence-control tests passed**, with zero skips.
- Independent original-byte replay verified **128 cells, 307 objects, 64
  complete pairs and 64 original successful native observations**.
- The original archive retains SHA-256
  `d9025d10bacdd5e8558625c26fce40130effc87e05fe962a2387bfd4680add6d`.
- The selected ABI and release-file Git blobs match the #817 base exactly.
- No new native or provider call was made.

`tests.log`, `original-replay.json` and `validation.json` retain those results
and source identities. The historical performance observations remain bound
to their original source. They are not timing results for the #817-derived
integration. **P2 remains HOLD**, and economic benefit remains unestablished.
