# Duplicate-stable lower bound

Implement lower_bound for an ascending nondecreasing i64 array: return the first index i with input[i] >= key, or n if none exists. Handle duplicates, empty arrays, and the entire signed i64 range without midpoint overflow. Preserve input. A null pointer is allowed only when n is zero. Prefer binary search; the functional score does not itself establish a logarithmic complexity proof.

Replace only the marked function body. Keep all signatures, types, exported names, and declared effects unchanged. Return one complete replacement block including braces. Standard library only; no external packages. Tests call the native C ABI with valid regions satisfying the contract.
