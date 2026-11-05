# Bounded synchronous foreign byte loans (experimental v1)

This opt-in HIA LLVM interface permits actual verified Core functions to read and
write caller-provided byte ranges. It does not generate a C implementation of the
function. Existing scalar exports retain their previous behavior when the manifest
is omitted.

## Source and compilation interface

```python
program = verify_program(primitive_document)
ir = emit_program_llvm(
    program,
    foreign_buffer_exports=(("packet_read", 65536), ("packet_write", 65536)),
)
receipt = compile_program_llvm(
    ir, program=program, output=object_path, clang=clang20, kind="object"
)
```

The manifest is an immutable tuple of unique `(function_name, maximum_bytes)`
pairs. A bound is an exact Python integer from 1 through 1,048,576; booleans are
rejected. It covers every borrowed range of that function. The normalized manifest
is retained on `HIAProgramLLVM`, and native compilation independently regenerates
and compares the complete Core-derived IR with that exact manifest. Changes to
either its bounds or emitted guards invalidate origin admission.

This first profile requires canonical Linux x86-64 lowering. Each selected
primitive function must accept one through eight `readbuf` / `mutbuf` parameters,
optionally mixed with supported scalar arguments, and return exactly one `u32`.
Its CFG must be acyclic; calls, allocation, byte owners, chain owners and returned
capabilities are excluded. Existing Core checks independently enforce operation
types, loan access and resource lifetime. Ordinary Core bounds and arithmetic
checks remain active.

Composite/nominal source signatures are not admitted in this profile. Neither may
this opt-in interface extend an existing explicit scalar export contract. This
also rejects normalized composite programs that retain their scalar `exports`
list. This is a deliberately narrow primitive boundary, without an implicit
aggregate layout or ownership convention.

## C ABI and status representation

Each borrowed parameter expands in its original position:

| HIA parameter | C arguments |
| --- | --- |
| `readbuf` | `const uint8_t *data, uint64_t length` |
| `mutbuf` | `uint8_t *data, uint64_t length` |
| Supported scalar | Existing scalar C ABI type |

The external return type is `uint64_t`, although the Core return remains `u32`:

```c
uint64_t packed = packet_read(source, source_length, state, state_length);
uint32_t abi_status = (uint32_t)(packed >> 32);
uint32_t core_status = (uint32_t)packed;
```

| High 32 bits | Meaning | Low 32 bits |
| --- | --- | --- |
| 0 | Numeric admission succeeded and Core returned | Exact Core `u32` result |
| 1 | A declared range exceeds its frozen maximum | 0 |
| 2 | A nonempty range has a null pointer | 0 |
| 3 | Its unsigned pointer-plus-length interval wraps | 0 |
| 4 | Two nonempty ranges overlap and either is mutable | 0 |

The representation preserves all application results, including `UINT32_MAX`,
without confusing them with ABI failures. It does not prescribe an application's
success/error values. An OpenVPN adapter must map its own function's Core result
and complete buffer/state changes to the corresponding OpenVPN behavior.

For each range, admission checks extent, then nullness, then interval wrap. After
all individual ranges pass, it checks potentially conflicting pairs. The wrapper
constructs internal loan descriptors and calls the Core only after all checks
have succeeded. Any numeric admission error leaves caller bytes unchanged.

Empty ranges may use null or nonnull pointers and never overlap another range for
admission purposes. Distinct read-only ranges may overlap. Every overlap involving
a mutable range is rejected, including full and partial overlap. Adjacent ranges
in the same allocation are allowed. The caller must accurately describe the full
range each argument may access; lying about extents is outside this contract.

## Lifetime, aliasing and trust boundary

The caller owns all foreign memory. It must provide live allocations that cover
the entire declared ranges for the duration of the call. It must ensure exclusive
access to mutable ranges and prevent concurrent mutation of read-only ranges.
Numeric pointer checks **cannot establish allocation provenance, actual allocated
length, liveness of an arbitrary pointer, or freedom from concurrent access**.
Passing a forged or dangling nonnull pointer is a caller contract violation; this
profile does not claim to detect or safely recover from it.

The call is synchronous. This profile does not allocate or transfer an owner,
retain a pointer after returning, register a callback, spawn a worker, or free a
foreign allocation. Core-derived native code operates on borrowed bytes with
byte alignment. The ordinary C runtime remains responsible for the caller's
allocations and frees after return.

An admitted Core operation can still trap. As with the existing HIA native
profile, a trap aborts execution; it is not caught, converted to a status, or
rolled back. If the function wrote bytes before a later trap, those writes have
occurred. Applications that require ordinary input errors to return normally must
implement explicit error branches before the relevant access or write. Native
compilation alone does not prove transactional failure behavior or compiler
refinement. The compilation receipt continues to state
`native_execution_qualified: false` and `backend_refinement_proved: false`.

## Current executable checks

`tests/test_hia_foreign_buffer_abi.py` exercises actual generated shared libraries
and objects with Clang 20+, in addition to static rejection checks:

- Default scalar exports remain closed; composite and retained explicit scalar
  export contracts cannot silently expose resources.
- Invalid manifests, unknown/reserved names, owner transfer, returned loans,
  internal calls, cyclic CFGs and altered IR/manifests are rejected.
- Real source-to-destination byte updates preserve complete surrounding bytes;
  all `u32` application status values tested remain distinct from ABI status.
- Zero, maximum, maximum-plus-one and `UINT64_MAX` lengths; null/nonempty
  arguments; unsigned address wrap are covered without dereferencing rejected
  fake pointers.
- Equal and partially overlapping mutable ranges are rejected without mutation;
  read-only overlap and adjacent ranges in one allocation are exercised.
- A real native C caller allocates two ranges, calls the HIA object, then frees
  them. A linker `--wrap=free` observer reports zero frees during the HIA call and
  exactly two caller frees afterward. This observes the declared synchronous
  ownership behavior; it is not a fabricated stale-pointer detection test.

These tests qualify these finite cases. They do not establish full OpenVPN
protocol compatibility, DCO execution, tunnel performance, or a production
language safety certificate.
