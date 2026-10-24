# Bounded adjacent-run compaction

Replace the placeholder with adjacent-run compaction. Keep the first element of each maximal run of equal u32 values, preserving run order. Return the TOTAL required run count even when output capacity is smaller. Write only the first min(required,capacity) run representatives; never change the remaining output storage. Input and output may be exactly the same pointer (in-place compaction), or disjoint. Other overlaps are out of scope. Capacity zero permits a null output pointer; n zero permits a null input pointer. Do not dereference either empty region. Apart from the supported in-place case, input is immutable.

Replace only the marked function body. Keep all signatures, types, exported names, and declared effects unchanged. Return one complete replacement block including braces. Standard library only; no external packages. Tests call the native C ABI with valid regions satisfying the contract.
