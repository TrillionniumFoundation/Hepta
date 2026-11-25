# Closed native allocation for rank ownership

This component replaces the two libc allocation imports of the already qualified immutable byte owner with a fixed mechanical Linux adapter. Its HIA ownership policy is unchanged. It is a dependency of the rank context and result-value owner; it does not claim complete rank, background optimizer or context qualification.

## Allocation ABI

The selected allocator flat is 175 bytes, SHA-256 `ee46f528f5da439aec944c400b3e5aa0e54cf7a1f9e915fca3acfe324ecb45c9`. It has no undefined imports.

| Entry offset | System V signature |
| --- | --- |
| 0 | malloc(size: u64) -> pointer or NULL |
| 93 | free(owned_pointer) -> void |

Allocation checks unsigned size-plus-32 overflow, then calls anonymous private mmap with read/write permission. No fixed aggregate byte limit is introduced. The returned address is 16-byte aligned. The private preceding 32 bytes contain the HIANKAL1 marker, exact requested mapping extent, requested allocation size and its complement. Anonymous memory is initially zero.

Free accepts NULL. Every non-NULL argument must be an actual live allocation owned by the HIA registry. It checks the private alignment/header/extent relation and performs munmap on the exact captured base and extent. Invalid private invariants or an unexpected munmap failure trap; this is not a public arbitrary-pointer deallocator. The unchanged HIA registry searches live nodes and checks their nonces before dereferencing a caller capability, so stale or foreign public capabilities never become free arguments.

The adapter preserves the System V callee-saved registers. It contains allocation mechanics only: no rank policy, resource identity, hashing or caller-selected callback address.

## Native construction

The readable adapter is `tools/hia_ndu_rank_context_allocator.S`. Development assembly independently checks its complete template and absence of relocations. Runtime construction uses the HIA source `examples/hia_bootstrap/ndu_rank_context_allocator_packer.hepta`.

That packer accepts exactly 16 bytes: HIANKAL1 followed by the unsigned version word 1. It emits the exact 175-byte allocator. It refuses malformed input with 0xffffffff and short output with 0xfffffffe without partial output.

The closed payload packer accepts HIANKPL1/32: policy length at 8, zero words at 16 and 24, followed by the actual unchanged HIA payload policy flat. Policy length is 16 through 1048576 bytes. It emits a fixed six-word view guard, the existing mechanical payload bridge, the supplied policy and the fixed allocator, resolving the three relative call sites itself in HIA. It accepts no allocator callback or caller-selected function address.

The selected closed payload is 85040 bytes, SHA-256 `dad77cae63da52f7944f283a0f487575b112cea4e51f8e8aef2701e9ef13752d`. Entry zero implements the existing HIABPY01/HIABPYR1 protocol. Its initial guard rejects NULL, short, wrapping and overlapping input/output/context views before the old bridge stores continuation state. The unchanged payload policy requires output at least 512 bytes and its private context at least 256 bytes. Full ownership/copy/borrow semantics remain documented in HIA_BACKGROUND_OWNED_PAYLOAD.md.

Both packer tools were compiled from HIA and actually executed to produce the selected flat outputs. The generic HIAFLT01 filter supplies only their executable wrapper. No assembler, linker, libc allocator or development author executes in the product allocation path.

## Actual qualification

The unchanged original byte-owner test suite ran against the closed native flat: 13022 actual operations, 900 independently generated segment comparisons, a complete 67108865-byte object, 1001 live references, 1000 stale-reference reuse controls, 1600 retain/copy/drop cycles on 16 actual threads, private framing/refusal controls and an actual fork identity check. All passed.

Five additional actual allocation failures target the native allocator's mmap syscall. External ptrace instrumentation changes only that syscall's length, causing the kernel to return ENOMEM. It does not replace the allocator with a model or modify product instructions. Empty/nonempty creation and retain failures unwind unpublished allocations, preserve every prior live object, and allow a same-owner retry. A sixth traced case observes 1002 new allocations and exactly 1002 corresponding frees, plus two separately counted allocations that existed before tracing.

Direct allocation checks cover zero, alignment boundaries, pages, one MiB plus one, 64 MiB plus one, unsigned overflow and actual address-space exhaustion. Successful mappings are checked for alignment and private headers, then mincore confirms the first page is unmapped after exact free. The private ABI and native packer tests check complete refusal atomicity and pre-store view guards.

The JSON ledger contains actual source/image/report pins and individual counts. These qualification groups overlap and are not summed into an invented independent-case total. Earlier 89-byte-guard evidence remains separate; the selected guard is 104 bytes and includes explicit NULL checks. Context qualification is recorded separately when its constructor, active tickets and retained results have been fully exercised.
