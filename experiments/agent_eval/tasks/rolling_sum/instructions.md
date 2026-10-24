# Bounded wrapping rolling sums

Implement fixed-width rolling-window sums of signed i64 values. A window of zero or larger than n produces zero results. Otherwise return n-window+1 regardless of output capacity, and write only the first min(required,capacity) sums. Each sum uses two's-complement wrapping i64 arithmetic (modulo 2^64), including overflow and underflow. Preserve input and all unwritten output elements. Input/output are disjoint. Capacity zero permits null output; n zero permits null input. Prefer an O(n) rolling update; the functional score does not claim to prove asymptotic complexity.

Replace only the marked function body. Keep all signatures, types, exported names, and declared effects unchanged. Return one complete replacement block including braces. Standard library only; no external packages. Tests call the native C ABI with valid regions satisfying the contract.
