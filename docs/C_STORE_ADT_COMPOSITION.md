# Ordinary raw-store order with concrete Copy ADTs

This P11/P01 increment integrates an existing capability, rather than inventing
another raw-store implementation. The destination is final PR #707 exact
`5e88f0daba0a860411bde76c1d4351194d51bfa5`; the ordinary-store source is PR #610
exact `b3ed67874af8f6fcc5b9cd7756e6800edf047ed1`. No broad runtime/resource branch
is merged. Both old sources need fresh joint qualification.

## Exact source composition

The Rust emitter receives #610's ordered tuple binding byte for byte. In the C
emitter, operand values already materialize into separate statements. Remove
only the extra ordinary-store rejection of effectful operands, preserving the
original explanatory fragment and index-only diagnostic from #610. The pointer,
offset and value therefore evaluate once in that order, before the write.
Ordinary assignment remains unchanged.

The original 13-method test corpus and documentation are preserved byte for
byte, with verified published Git blob identities. The fixture filename
`tests/raw_store_order_origin.py` is intentionally not default-discoverable.
The original documentation describes its broader source, including volatile
operations, not this destination's supported language.

`tools/verify_store_adt_sources.py` checks both original files and restores both
production files to the exact #707 hashes by reversing only this increment.
It binds 136 unchanged inherited inputs. Two tiny qualification adapters also
reverse to their exact parent hashes: the array verifier accepts an explicit
source string, and its runner uses the verified parent projection for provenance.
The array test suite still imports and executes the current production source.
The parent's original array inverse and numeric-origin checks both still run.
No source mismatch is treated as acceptable or silently ignored.

## New joint consumers

- Generic records, enums and builtin Result containing internal Unit values.
- Numerical casts and returned temporary-array projections as store payloads.
- Pointer selection before a later value changes that selection, and a plain
  offset snapshotted before the payload changes the offset variable.
- Nested stores, aggregate copies retained across writes, Unit store results
  embedded in arrays/records/Result, loops and all short-circuit directions.
- Module aliases with concrete private generic layouts.
- Pointer/index/value abort prefixes with no subsequent effect.
- The actual public CLI example `examples/c_store_adt.hepta`.

Every raw access in these consumers uses valid, live, aligned storage, and a
proven in-bounds offset. Changing evaluation order changes defined observable
behavior rather than deliberately accessing invalid memory.

## Reproduction and frozen inventories

```
python tools/validate_c_store_adt_composition.py
python tools/qualify_c_store_adt_oracle.py
python tools/validate_c_array_adt_composition.py
```

The strict C-only inventory contains **349 unique methods**, with all 333
inherited identities in order, eleven joint controls and five unchanged
applicable origin methods. It requires identical planned/started/finished/passed
identities, no skipped tests or expected/unexpected failures, and stable hashes
of the materialized source, tests, examples, documentation and qualification
inputs. It is a bounded compiler gate, not the repository release gate.

Required-Rust mode freezes **357 unique methods**. Its eight additional methods
are the three inherited Rust references and five ordinary-store origin Rust
controls. Joint helpers also run actual Rust O0/O3 in that mode. Missing or
incorrectly selected pinned Rust 1.90.0 fails closed.

Three unchanged origin methods are explicitly inapplicable because they include
volatile operations absent from this destination. A new joint method executes
the ordinary-store half of the original combined control, including exact
pointer/index/value traces and foreign aborts. New and inherited tests retain
the relevant unsafe, read-only and effectful-index refusals. Inapplicable methods
are not counted as passes. The parent's separate generic-resource origin
exclusion remains unchanged.

The independently authored oracle derives expected values and order in Python.
It checks 64 seeded aggregate cases in two success fixtures, plus a separate
aligned-pointer trace and three operand-failure fixtures, at native C O0/O3 with
nonrecovering UBSan: twelve native executions and three separately compiled
wrong-output controls per Python version. The two aggregate fixtures each
observe 96 values per execution. Original source, generated code, compiler,
executable, flags, outputs and status are recorded. The parser/checker is shared;
this is not an independent language interpreter.

Local qualification uses Python 3.12.14 and 3.13.5, GCC 14.2.0, Linux x86-64.
Native Rust and ARM are unavailable locally and are not claimed as executed.
The new read-only exact-head workflow requires Rust 1.90.0, the 357-method gate,
the new oracle and all three inherited numeric/array oracles on Linux
x86-64/AArch64 with Python 3.11/3.13. Old-source hosted successes do not qualify
this head, and queued workflows are not passes.

Initial missing type/effect annotations and an example match-arm separator
failure are retained separately; they are not part of the final passing runs.

## Retained limits

Only ordinary store is integrated. Volatile operations, raw Unit dereference,
array-pointer lowering, generic functions, resource payloads, recursive layout
execution and new aggregate C ABI remain outside this change. No signatures,
source literals, output paths or C-import publication are changed.

Raw-pointer validity, alignment, bounds, lifetime and allowed access throughout
operand evaluation remain unsafe caller obligations. Ordered evaluation is not
a memory-safety, ownership, MMIO, concurrency or durability guarantee. No
performance advantage, full language/refinement proof or production qualification
is established. P11/P01 remain PARTIAL. Draft only; no merge or deployment.
