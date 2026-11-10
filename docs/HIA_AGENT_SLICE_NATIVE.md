# HIA-native Agent editing-view graph

The explicitly selected `HEPTA_HIA_AGENT_SLICE_MANIFEST` route replaces the
production edit-query SSA/CFG slice computation with `agent_slice.hiaasm`.
Both single edits and batch edits use the existing `prepare_edit` callers.
It does not change the query schema, grants, whole-Core verification or patch
publication. No high-level Hepta source/AST/checker port is involved.

The HIA application owns same-block transitive consumers, all displayed input
producers, FIFO cross-block argument propagation to a monotone fixed point,
both reachable regions of an affected branch (including no-result operations
and reconvergence), successor-loop convergence, rejection of a backedge to the
selected block, and the existing **256 visible operations / 64 visible blocks**
budgets. This conservative view does not prove precise control dependence,
aliasing or functional equivalence.

Python still verifies and materializes Core objects, serializes immutable graph
facts, binds names and presentation order, hashes snapshots, reconstructs
queries, applies patches and publishes/persists results. The current default
still uses the reference slicer. Explicit selection never falls back on an
invalid manifest, malformed packet, out-of-profile input or native refusal.
This component is not a native-only Agent or entire native product.

## Bounded byte interface

The read-only fact packet is at most 8 MiB. Its eight little-endian u64 header
words are magic `HIASLC01`, block/operation/value/edge/link counts, source block
and selected global operation. Fixed-width rows follow: 64-byte blocks,
40-byte operations, 16-byte value owners/producers, 32-byte CFG edges and
8-byte value links. Parameters and output values partition the value table;
operations partition blocks. The HIA validator checks all ranges, partitions,
local owners, preceding definitions, terminator conditions, edge arities and
argument agreement before using graph facts. It is not a second Core verifier.

Output is `64 + 8*(blocks + values + operations)` bytes: `HIASLR01`, the three
counts, source block, selected operation, total displayed operations, zero,
then block flags, value-flow flags and operation roles in declaration order.
Private workspace requires output size plus `8*blocks` queue bytes and is
initialized by HIA, including when supplied dirty. Result codes `0xffffffff`
and `0xfffffffe` reject malformed input and insufficient buffers. Codes
`0xfffffffc`, `0xfffffffb`, `0xfffffffa` retain the original cycle, block-budget
and operation-budget diagnostics. No output byte is published on a refusal.
The local native image is trusted executable code, not an untrusted-code sandbox.

## Development build and selection

```sh
python -B tools/build_hia_agent_slice.py --compiler /qualified/B3.image.bin \
  --cold-report /qualified/cold.json --output /new/agent-slice
HEPTA_HIA_AGENT_SLICE_MANIFEST=/new/agent-slice/manifest.json hia edit-query ...
```

The build also emits `hia-agent-slice`, a syscall-only normalized-graph filter
packed by the existing HIA native filter packer. It reads one packet from stdin
and writes the result packet to stdout; no host parser, dynamic loader or child
compiler runs. Exit statuses are 0/success, 2/invalid graph or refused view,
3/capacity, 4/I/O, 64/arguments; a write failure may leave partial stdout, not
a complete result. This graph-filter entry is not the entire Agent stdio entry.

The build admits the original eleven completed cold checks and all three exact
compiler hashes. Filesystem/build orchestration remains Python. Tests execute
hand-authored complete result-byte witnesses in the independent Core VM before
building B0, then actual B0→B1=B2 compilation, existing real edit callers with
both reference graph functions disabled, randomized declaration orders,
unchanged view-budget boundaries, malformed-packet/output canaries and parallel
private-buffer calls. These finite observations are not all-input refinement,
platform/clean-machine qualification or whole-product closure.

Installed adapters resolve their HIA app source from package-owned `_data`,
never cwd/HOME/a different checkout. Both identity and graph app sources are
bound into worker identity and exact source-distribution/wheel resources.
The high-level language is removed, not retained as a runtime prerequisite.
