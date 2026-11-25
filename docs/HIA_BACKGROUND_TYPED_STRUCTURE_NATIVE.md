# Native typed structure and detached snapshot

This component observes the captured native mutable-value owner through actual capabilities. It does not accept caller assertions about types, lengths, object identities or children. It implements the original HIA program structure checks, and an optional detached-snapshot pass, before the BackgroundOptimizer's JSON freezer.

This is a qualified component. The complete BackgroundOptimizer controller, runtime provider, Future carrier and installation remain separate obligations.

## Contract

The six-word continuation consumes `HIABTC01`: a 128-byte header followed by the exact 10,100,891-byte decimal representation of 2^33554432. Fields are mode at 8 (0 structure, 1 snapshot then structure), actual root value capability at 16/24/32, captured `int_max_str_digits` at 40, and threshold length at 48. Bytes 56..127 are zero. The surrounding owner captures the conversion policy; callers cannot silently select unlimited conversion.

The 128-byte private context begins `HIABVC01`, followed by the captured native value entry at 8, its live context address at 16 and extent at 24. The input, output and context views must not overlap. The output continuation storage is 96 MiB, derived from the original 262144-node traversal ceiling and held references; this is not a new public value size limit.

The enclosing mechanical caller initializes output offset 128 (phase) to zero. Return 4 requests the fixed six-word value-owner call: function at output 0, two-bit bank mask at 8, and six arguments at 16..56. Bank 0 is absolute, 1 context, 2 input, 3 output. The current mask is 51. Write the actual callback return code at output 136, then resume. Return 10 continues without an effect; return 0 is terminal. No output zeroing is required before each actual value call: the captured complete value entry owns initialization, and qualification poisons its output before every callback.

Terminal `HIABTV01` has status at 8: 0 success, 1 original rejection, 2 provider failure, 3 failed cleanup. Error ID is at 16; owned detached root is at 24/32/40. Visited count, exact serialized byte count and retained-node count are at 48/56/64; mode/pass/digit policy at 72/80/88; provider status and failed cleanup count at 96/104. Private malformed calls return 0xfffffffd and preserve the public 128-byte output. A cleanup failure retains the relevant live references in continuation storage; the enclosing owner must quarantine or explicitly finish cleanup, never discard that state as success.

## Semantics and ownership

Both modes keep the original 8 MiB byte, 262144-node and depth-64 bounds. Direct structure checks count queued nodes before child kinds, examine keys in insertion order, then values in reverse traversal order. Detached snapshot checks walk values in original left-to-right order before the structure pass. Native container observations occur under the actual value mutex through operation 23; keys and values return independent retained capabilities.

Integer admission checks bit length before decimal conversion policy and byte budget. The exact threshold data is source-bound. Tests cover positive and negative threshold minus one, threshold, and threshold plus one, with both captured default 4300 and unlimited 0. Unlimited conversion is a separately qualified policy, not the production default.

Container clones are created bottom-up. Scalar leaves retain their original immutable value identity. Repeated container aliases become separate detached containers, and cyclic inputs are rejected. Successful output remains unchanged when the original container is mutated. Every held key, value and temporary container is released after success or ordinary rejection. Public value references are not naked pointers.

The component covers native null, bool, arbitrary integer, binary64, WTF-8 string, list, dict and bytes values, preserving their original supported/unsupported classification. It does not claim equivalence for arbitrary foreign Python classes or custom iterators. Concurrent foreign mutation diagnostics are not inferred from finite native graph tests.

## Actual qualification

- Two independent native source compilations produced identical 115521-byte policy.
- Original/native semantic and ownership matrix: 238 cases and 5900 actual value calls against value owner v1.
- Final policy v4 against value owner v2: 272 cases and 1603491 actual native calls, including complete admitted 262143-child lists in both modes, exact byte/Unicode limits, aliases, cycles, decimal-policy ordering and poisoned callback buffers.
- Final policy against value owner v3: 16 threshold cases, 84 actual native calls, and 26 private framing/capability guards. Context-token operations were not used by this component; these tests do not substitute for v3's own lifetime qualification.
- All test contexts released every temporary and output reference and successfully destroyed the native value context.

The two full admitted fanout cases took approximately 54.20 s and 51.00 s in their external differential observer. No original semantic, compiler or transport budget was increased. The complete BackgroundOptimizer integration must account for its actual submit work.

Exact source, binary and external report digests are recorded in the adjacent qualification JSON. Runtime source is `background_optimizer_value_structure.hepta` plus the existing exact threshold data; Python authors and observers are development tools only.
