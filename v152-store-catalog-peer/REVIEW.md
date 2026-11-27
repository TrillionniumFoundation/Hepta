# Independent Store catalogue root R1 static review

**No determinate blocker found within the declared codec ABI.** No generator,
project module, Core checker, Native/VM or filesystem transaction was executed.
The physical owners must be distinct, as CONTRACT.md explicitly requires.
This conclusion is not execution qualification or a complete Store replacement.

## ABI and complete ranges

`catalog_root_policy.py.txt::catalog_root` checks source >=128, output >=1152,
workspace ==2048 before any data access. The initial reads end at source byte
127; the complete header and operation-specific shape checks precede the
workspace clear. Operation 0 requires source704, operation1 source1104, and
operations2/3 source128. Their last possible source reads are respectively
703,1103,127,127. The three u32 refusal values and 576/96 success extents match
the contract. Generation-max refusal precedes old-root validation and clear,
also matching `catalog_codec_oracle.py::transition` ordering.

The ten 48-byte records occupy workspace64..543. Last record starts496; its
digest ends543. The complete old catalogue copy is source128..703 to
workspace0..575. Ten transition slots occupy source704..1103, last start1064.
All index arithmetic is bounded by ten records or fixed byte extents; there
is no reachable u64 offset wrap in these loops. The mask flag becomes1024
only after the tenth iteration and is unused then.

## SHA scratch and alias precondition

I read the full retained `tools/generate_hia_sha256.py` and new
`generate_hia_store_catalog_root.py::hash_program`. Its explicit reversible
projection changes entry/range/digest destination and identifier names; the
retained compression and padding algebra is left intact. Actual generation,
whole executed inverse, Core verification and SHA correspondence remain gates.

| Owner | Range | Purpose |
|---|---|---|
| workspace | 0..543 | Catalogue checksum prefix |
| workspace | 544..575 | Stored checksum |
| workspace | 576..639 | Empty-page scratch |
| workspace | 640..2047 | Cleared remainder |
| output | 0..511 | SHA round constants |
| output | 512..1023 | SHA schedule |
| output | 1024..1087 | SHA chaining state |
| output | 1088..1119 | Serialized digest |
| output | 1120..1151 | Unwritten minimum-ABI tail |

The projected SHA checks n in {64,544}, start<=length(s), n<=length(s)-start,
and scratch>=1120. Hash input is workspace; scratch/digest is output. Empty
page construction cannot overwrite the catalogue under the declared physical
owner precondition. Each SHA call initializes its constants and chaining state.
`finish_catalog` hashes before copying digest into workspace and all576 bytes
to output. Validation copies output only after all root/empty-page comparisons.
Operation3 copies workspace576..639 to output0..63, then nonoverlapping
output1088..1119 to output64..95; no later hash uses overwritten scratch.

There is **no physical alias check in this kernel**. A future admitted wrapper
must prove all three owners/extents are distinct. Without it, clear_work could
overwrite source and SHA stores could overwrite hash input. Syntactic buffer
names or a future Core check alone are not measured physical admission. This
is an open integration obligation, not an alias-safe-ABI claim. Error returns
after clear/hash may leave partial output/workspace; all full six buffers and
canaries must be retained, not only the logical return extent.

## Ten-family semantics

I read actual `hia_agent_store.py` DDL: artifacts, profiles, contexts, requests,
costs, cursors, slots, versions, leases, execution_budgets. The oracle tuple and
record IDs1..10 match this exact order.

`valid_catalog` binds magic/version, UUID, expected generation, table count10,
reserved zeros, the complete544-byte prefix checksum, all ordered IDs and all
nonzero digests. Every zero count is bound to the canonical64-byte empty page
for that same UUID/table. `empty_page` clears its entire region before writes,
so reserved bytes remain zero.

Transition accepts only a nonzero ten-bit mask. Selected count/digest pairs
must differ; digest must be nonzero; zero count requires canonical empty hash.
Each unselected40-byte proposal must be zero. UUID, IDs, reserved fields and
unselected records remain byte-identical. All changes share one generation
increment and checksum; max-u64 refuses before addition. Oracle layout,
canonical-empty rules and pair/generation rules correspond statically.
Malformed request controls must mutate bytes; oracle request-builder rejection
is not HIA execution evidence.

## Remaining scope and gates

A nonempty count/digest is encoded metadata. No page graph, count truth,
uniqueness/index constraint, cross-table authorization, request replay,
slot/version/budget transaction, locking, rename/fsync, recovery or default
selection is implemented here. The original DDL has primary/unique constraints
which this root codec does not implement. Contract and generation result fields
state these limits accurately. A checksummed root does not establish durability.

`bound_read` is a selected-input generator guard, not a complete3210-source or
2496-runtime scan. Future owner must perform the promised full fresh guards.
The plan retains two generation owners plus check, each180+3, compilation at
20s/10CPU/1MiB, VM10M/8MiB/depth128, and all13 control families. None ran here;
no prior Store test or cold qualification transfers to this new codec.

`INPUT-PINS.json` binds all nine fully read source/contract files, current mode
and seven stats. `capture_review.py` only reads those files and performs inert
AST/table-order checks; it never imports or invokes their implementation.
