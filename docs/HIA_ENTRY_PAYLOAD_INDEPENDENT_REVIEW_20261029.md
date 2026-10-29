# Independent review of the primitive-v1 entry payload analysis

**No blocking soundness issue was found in the examined profile at
`d246aecf3cd1b96e818bd4e53ffe0408fb1fbd93`.** This is a scoped static review,
conditional on the canonical Core checker, reviewed operational semantics and
Python implementation. It is not a proof-assistant theorem, native admission,
or a new performance result.

## Independently checked evidence

The review compared eleven source/fixture/document files with their exact Git
blobs, and compared the producer's dependency digests and regression-log hash.
The reviewed worktree was clean and unchanged throughout snapshot capture.
The actual migration input bytes matched the retained fixture:

```text
1044e28ea68a18d6a0681cff9cd5f835e26e91c9a669dab01256b9592f64ca51
```

The input is 143,935 bytes. Its complete graph contains 16 functions, 162 blocks
and 26 syntactic call sites. Independent transitive-reachability checks
reconstructed the SCC relation without calling the new analyzer: six cyclic
components containing 24 blocks agree with the producer's report. The complete
call graph is acyclic, and every reported callee precedes its callers in the
summary order. Each call site was charged independently.

The three allocation sites in `legacy_checksum_chunk` are `b128`, `b129` and
`b131`. Their earlier local literal `usize` definitions request 16, 8 and 8
bytes. Independent static accounting gives three allocation opcodes, three
nonzero requests and 32 cumulative requested payload bytes. A fresh scalar
entry starts without external owned payload, so 32 is also a conservative
upper bound on simultaneous live byte-owner payload.

The producer's deterministic report digest was recomputed and matched. Its
19-test regression log records 19 passes and zero skips; **the reviewer did not
rerun that suite**. No original analyzer invocation, VM execution, native build,
native execution, model request or performance experiment was performed by this
review. The independent checks inspected data and graph structure only.

The complete review receipt and the producer regression evidence are retained
under
[`payload_review_20261029`](../experiments/hia_next_safety/payload_review_20261029/REVIEW.json).

## Soundness-sensitive cases examined

The accepted domain is explicitly closed: primitive Core v1, a separately
enumerated scalar/resource type inventory, exact opcode inventory and four
terminator forms. Canonical verification runs before the analysis. Future
schemas, composite normalization, unknown allocators, chains and foreign calls
cannot silently inherit a payload bound. The selected public entry has only
scalar parameters and results; a resource-returning or resource-taking
function cannot be mistaken for a fresh entry with zero incoming payload.

Allocation sizes come only from an earlier literal `const usize` in the same
block. The sequential scan and verified SSA identity prevent a later, shadowed,
block-parameter or caller-provided value from supplying the bound. Arithmetic
and cross-block constant propagation are deliberately refused. The admitted
range is nonnegative and no greater than the operational allocator's
`2^63 - 1` object-size limit.

Every block containing an allocation opcode must be outside all CFG cycles.
The same prohibition applies to a cyclic call site whose transitive callee
closure contains any allocation opcode, including a zero-size allocator.
This preserves a finite allocation-opcode count as well as a byte count.
Allocation-free cyclic calls contribute zero newly requested payload even when
their invocation count is unbounded. An acyclic allocating exit from a loop is
not mistaken for a cyclic allocation site.

Private summaries count newly requested payload only. Passing, returning or
moving an owner transfers its existing payload; borrowing a view does not
create another byte buffer. The canonical checker supplies linear ownership
and typed call/return flow. A scalar root cannot obtain an externally owned
buffer through a cast or foreign primitive in this closed opcode inventory.
All payload reachable from that root therefore originates at a counted
allocation site. A private caller's unknown incoming extent is not separately
claimed to be bounded.

Summing mutually exclusive branch sites overestimates possible work. It does
not require a branch-feasibility proof. Each noncyclic allocating block occurs
at most once per invocation; otherwise the path between two occurrences would
put the block in a cycle. Callee-first induction over the acyclic call graph
then supports the per-call-site cumulative bound.

Allocation failure, arithmetic/explicit traps and execution-budget stops
shorten the executed prefix. A successful request creates at most the charged
payload; an optional failure creates an empty owner, and a required failure
aborts. The zero-size operational branch creates an empty owner without a
nonzero allocation attempt. No failure case needs a destructor-completion
assumption to maintain the cumulative upper bound. Retained owners after abort
remain covered by the sum of payload already created.

## Boundaries that remain explicit

The reviewed implementation adds a read-only analysis and leaves the previous
heap/static-budget/native admission domains unchanged. A supplied report or
digest grants no optimization or installation authority; a consumer must
analyze the actual Core again. This review does not broaden that rule.

The bound is per fresh sequential Core invocation and counts requested logical
byte-owner payload. It does not establish termination, cleanup after abort,
free-call count, VM ticks, owner/view metadata, allocator overhead, native stack,
process RSS, foreign-resource behavior or concurrent invocation totals. It also
does not prove C/C++-source or Core-to-machine-code refinement, or the soundness
of the entire language.

The resulting review remains `authority = DENY_ALL` and
`safety_certificate = false`. Source changes or a broader accepted profile
require a new review and appropriately scoped evidence.
