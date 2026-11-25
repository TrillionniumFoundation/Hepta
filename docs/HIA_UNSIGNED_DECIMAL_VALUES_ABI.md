# Exact unsigned decimal counter values

This pure HIA role represents nonnegative public generation, epoch, lease, and accounting integers as canonical ASCII decimal spans. It has no fixed 64-bit or 128-bit integer-value bound. Physical allocation remains the caller's responsibility. Runtime publication, locks, reference ownership, Python type classification, and error ordering are separate responsibilities.

## Six-word entry

The entry receives the immutable input pointer and length, disjoint output pointer and capacity, and work pointer and length. Work is unused and unchanged. Source and output must not overlap; the runtime supplies borrowed immutable operands and a newly owned output allocation.

The u32 return is an action code, never the result byte count:

- 0: a complete HIAVLR01 frame was written, including a structured format or underflow result.
- 0xfffffffd: invalid private header, opcode, reserved words, or inconsistent input extents. No output bytes change.
- 0xfffffffe: output capacity is short. No output bytes change.

The output extent is 32 plus the u64 result length in its header. This avoids truncating a large value length to a u32.

## Input

HIAUVL01 has eight little-endian words in its 64-byte header: magic, opcode, A length, B length, and four zero reserved words. The exact tail is A then B.

| Opcode | Operation | B |
|---|---|---|
| 0 | Validate and copy A | Must have zero length |
| 1 | Increment A | Must have zero length |
| 2 | Add A and B | Required canonical decimal |
| 3 | Compare A and B | Required canonical decimal |
| 4 | Subtract B from A | Required canonical decimal |

Canonical decimal is 0, or a nonzero ASCII digit followed by zero or more ASCII digits. Empty operands, signs, leading zeroes, whitespace, decimal points, exponents, non-ASCII digits, and embedded NUL bytes are format errors. Header extents are checked before operand reads.

## Output

HIAVLR01 has four little-endian words: magic, status, comparison, result length. The tail contains exactly the canonical result digits.

Status 0 means success; 1 is an operand format error; 2 is subtraction underflow. A comparison has no digit tail and reports 0 for A < B, 1 for equality, or 2 for A > B. Other successful operations use comparison 1. Format errors use comparison 1; underflow uses comparison 0. Both errors have a zero-length tail.

All operands and the exact output length are checked before the first write. Addition, increment, and subtraction use linear passes and constant auxiliary space. The source, work view, and bytes beyond the returned output extent remain unchanged.

## Runtime integration

Public exact-integer and nonnegative checks happen before converting values to spans. Booleans, floating-point values, strings, and negative expected generations or epochs must retain the original Python API rejection and precedence. Measurement values keep their original bounded integer domain.

The runtime owns immutable value objects, separately from finite private live-row slots. Under the original writer and selection locks, it allocates and computes a complete new value before replacing the owning reference. Allocation or computation failure preserves the old value. Lease records, events, and snapshots retain the referenced value; reusing a private row must never change an already published generation number.

The counter does not reset on close or when no generation is current. Reservation, rollback, publication, cancellation, and handoff ordering remain in the runtime coordinator.
