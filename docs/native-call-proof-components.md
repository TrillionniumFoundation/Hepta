# Native direct-call proof components

This checkpoint qualifies three native HIA components: closure and graph
extraction from freshly admitted canonical Core, final graph linking using
fresh summaries, and summary/CNF projection with a Boolean solver.

The complete public call-proof owner, public receipt integration, installed
release, and production activation remain open. External Python in these
checks orchestrates component calls and supplies independent original Core,
Z3, and byte-level oracles. It is not a product runtime.

## Original profile retained

The closure permits at most 16 functions, 32 blocks, 512 original operations,
32 inputs, and 16 returns. It visits unique callees in sorted order, rejects
active recursion before a cached graph can hide it, and preserves original
per-function profile refusal ordering. A multi-result call contributes one
placeholder per result to the original shaped profile; a zero-result call
contributes none. Actual emitted graphs retain the original call operations.

The expansion count is recorded and capped at 33. The owner must reject a
value above 32 only after both closures and the original signature comparison.
Closure extraction does not move that refusal ahead of the original checks.

The linker validates private input extents, the selected graph, callee fixups,
summary inventory, signature identity, and output capacity before writing
output. It binds call arguments and actual summaries into the HIABVP02 graph.
Every tested solver invocation consumes the actual native output. Python
packet construction is only an independent exact-byte oracle.

## Artifacts

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| General call summary and CNF | 506208 | 9881f2e28de2500899fc7a14b084f4744267cb38cfff826d3ddfc9ab18b1ffce |
| Closure and graph | 354949 | 7cbd688f224827b9a82adb2e6d63d6996803f8af470e4a4e654f7eb5f0649fc4 |
| Graph linker | 100835 | 7843033d79824032e44b6ea22e8fd57b02ea10e15a32a95ecb4540fa7964e4ca |

All three were built using the existing 49483399 source compiler, once
captured and sealed, under the unchanged native source profile. The final
linker has at most 14 block parameters, within the existing limit of 16.
Earlier attempts exceeding the compiler profile were rejected, not admitted
by increasing limits.

## Completed checks

- Fifteen direct-call semantic cases, 34 summary/solver invocations, and 60
  native links pass with original Z3 decisions and independent Core VM replay
  for actual native SAT witnesses. Cases include signed checked arithmetic,
  two independent calls, nested summaries, zero-result traps, bool and unit,
  16 return values, 32 arguments, callee mutation, and first-trap order.
- Twenty-one freshly admitted closure/profile boundaries agree with the
  original implementation, including exact function, block, operation,
  signature and return limits, recursion, loops, effects, and expansion
  count ordering.
- Seventy-two linker protocol, extent, summary and capacity refusals preserve
  the entire output allocation checked by the observer.
- The original general domain remains intact: 95 distinct graphs map to 113
  original calls, all 69 protocol gates pass, all 10 wide-domain checks pass,
  and all six bounded-marker checks pass.

The call component uses conflict activity and phase saving only for Boolean
search decisions. Clause construction, watched propagation, conflict
analysis, backtracking and the final witness retain their original
semantics. An earlier call case reached its test deadline without this
heuristic; the corrected case passes. Original general source and image are
unchanged and remain separately qualified.

## Private protocols

HIACGC01 retains the general component's 128 byte request and introduces
HIACGR01 status 5 for a completed summary. Summary mode 3 uses HIABVP02;
ordinary totality and equivalence remain modes 1 and 2. The full-word
SCALAR/TUPLE summary representation is validated and cloned with checked
32 bit node identities. All live state remains private to one invocation.

HIACCL01 is a closure bundle with a 128 byte header, sixteen fixed 640 byte
function records, up to 512 fixed 32 byte call fixups, and graph bytes from
offset 26752. HIACSU01 holds the contiguous fresh summary inventory.
HIACGL01 is the 128 byte linker request, followed by left/right bundles and
left/right inventories. These are private artifacts, not caller authority.

The adjacent JSON binds source files and the exact evidence reports.
The final owner still needs end-to-end deadline, cancellation, identity,
replay fault, public error-order and receipt qualification before release.
