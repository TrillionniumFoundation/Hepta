# Real legacy Core: checked allocation/payload bound

Frozen analyzer source: `d246aecf3cd1b96e818bd4e53ffe0408fb1fbd93`, tree
`e9288f21ad676a7084a78da03d780518d75f1a12`. Both recorded commands ran with a
clean source checkout and matching before/after dependency snapshots.

The exact preexisting migration Core is retained at
`tests/fixtures/hia_payload_bound/legacy_core.hia.json`, SHA-256
`1044e28ea68a18d6a0681cff9cd5f835e26e91c9a669dab01256b9592f64ca51` (143,935
bytes). This is a fresh analysis of those Core bytes, not a rerun or relabeling
of their earlier C/C++ migration qualification.

## Outcome

For a fresh `legacy_checksum_chunk` invocation, over all correctly typed scalar
inputs and all allocation outcomes, the checked profile gives at most **3
allocation requests**, **32 bytes of cumulative requested payload**, and **32
bytes of simultaneously live byte-owner payload**. This includes finite trace
prefixes ending in traps or execution-budget stops; it promises no cleanup
after those stops.

The analyzer checked all 16 definitions, 162 blocks, 26 static call sites and
6 cyclic SCCs containing 24 blocks. None of the cyclic blocks or their call
closures contains an allocator. The only three allocation sites are:

| Function | Block | Opcode index | Const index | Operand | Bytes |
| --- | --- | ---: | ---: | --- | ---: |
| `legacy_checksum_chunk` | `b128` | 1 | 0 | `v1528` | 16 |
| `legacy_checksum_chunk` | `b129` | 2 | 1 | `v1552` | 8 |
| `legacy_checksum_chunk` | `b131` | 2 | 1 | `v1582` | 8 |

All positions are zero based. Every complete CFG/call dependency and callee
summary is in `legacy-analysis.json`. The deterministic analysis digest is
`6c0c089d9ca3576af82f809bbd3209bc5e9c4fbf9d3e813a2461ae53b0726ca6`.

The 19 regression tests passed with zero skips in 0.207 seconds (0.425 seconds
including the process wrapper). They check rejecting direct/indirect loop
allocation, recursion, dynamic/cross-block sizes, forged Core and unknown
operations; owner returns, branch overestimates and stopped prefixes are also
checked against the existing Core interpreter. No native build, model request
or performance experiment was run. Test durations are provenance, not a
comparative performance claim.

## Authority and limits

The implementation extends the existing `hia_heap_bound` analysis and still
uses `verify_program` as the sole canonical Core check. No historical
admission was widened. Only the reviewed primitive v1 profile with same-block
constant sizes, an acyclic call graph and allocation-free CFG cycles can
receive this result. Unknown cases are refused.

The readable induction and TCB are in
`docs/hia-next-payload-bound/PROFILE.md`. This is executable structural
evidence conditional on that checker/semantics, not a machine-checked
whole-language proof. It does not bound termination, stack, owner/view
metadata, allocator overhead, RSS or concurrent instances; it does not prove
C/C++ source or native refinement or grant runtime/optimizer authority.
The environment is shared cloud scratch, not verified physical user dot.

`manifest.json` retains exact commands, working directory, both exit codes,
Core identity and raw-file digests. The original raw records remain at their
recorded `/tmp` paths. The full source revision is kept distinct from this
later evidence-only commit.
