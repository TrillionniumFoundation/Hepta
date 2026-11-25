# Typed structure cleanup ownership

The final typed structure component preserves the HIABTC01 operations 0 and 1 and their original private rejection domain. The independent HIABTC02 operation 2 resumes only a completed HIABTV01 status-3 cleanup. It never repeats the original snapshot, structural traversal, integer conversion, or detached-tree construction.

The original 96 MiB output, threshold-bearing source, fixed value context, and all owned rows must remain alive. For operation 2, source words 16, 24, and 32 are zero; word 40 retains the same captured integer conversion policy, word 48 is 10100891, and the exact threshold tail remains present. The continuation still returns 4 for an actual value call, 10 for another pure step, or 0 for a terminal HIABTV01 reply. Success restores the original semantic result and transfers its owned root only once.

Every successful overflow-reference drop now clears its actual slot. A failed overflow reference preserves the enumeration extent until it is released. Ordinary rows already retained failed references; both paths now retry only the still-owned references. Invalid retry frames leave the public reply untouched. A caller must not free, reuse, or treat a status-3 continuation as an ordinary error with no retained resources.

## Actual qualification

The final component passed 272 comparisons with the original implementation, covering snapshots, scalar domains, depth, aliases, cycles, Unicode and byte-budget priority, integer conversion, random values, and exact admitted fanout. Those cases made 1,603,491 actual value-owner calls. Sixteen additional exact huge-integer threshold cases and 26 original private guards passed.

Three cleanup groups temporarily invalidated the real value-context lifecycle marker for exactly one native drop, restored it, and resumed through the new profile. Both ordinary traversal modes and a real list-growth overflow of 262144 captured references passed. Each retry made exactly one successful drop; already-freed references were not freed again. All value contexts were empty after final release. No provider return was mocked.

The companion qualification JSON contains current source, compiler output, complete reports, and their hashes. This closes the typed snapshot/structure cleanup component; complete BackgroundOptimizer integration is tracked separately.
