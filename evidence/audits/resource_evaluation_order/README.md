# Assignment and projection evaluation-order audit

An independent source review found that sequential resource lowering evaluated an
assignment target before its right-hand side. Both native backends evaluate the
right-hand side first. A right-hand side could therefore consume the owner used
by a later target index or a returned-target argument, while the old resource
graph described those uses as preceding the consumption.

`before-afc900b.json` preserves the actual comparison against the separately
checked out C-owned backend. All three invalid candidates passed its frontend,
resource verifier and C-emission check; all three were rejected by native Rust
checking. **The invalid C candidates were never built or executed.** There is no
ASan crash claim. The evidence is the wrong acceptance and the source-order
mismatch, followed by rejection after correction.

`after.json` preserves the fixed compiler comparison: all three candidates are
rejected by the independent resource verifier before C generation. All four
valid neighbouring programs execute successfully through both native backends
(eight executions; C uses UBSan). One of those valid cases was conservatively
rejected by the old lowering because it borrowed a mutable target before copying
the right-hand side. The change also traverses nested projection indices from
the base outward, matching execution order.

The manifest binds the exact before/after lowering files, compiler report hashes,
case corpus and replay script. These are historical audit snapshots, not the
final integrated compiler qualification. `tests/test_resource_evaluation_order.py`
reruns the rejection and valid-neighbour checks on the current compiler. To replay
against any checkout, run the absolute path of `replay.py` from that checkout with
`PYTHONPATH=.` and a fresh `--output` path.

This closes these observed ordering defects. It does not establish a general
source-to-IR or IR-to-C refinement proof.
