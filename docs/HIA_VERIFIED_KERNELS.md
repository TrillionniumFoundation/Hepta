# Verified register and SSE2 kernels

The opt-in kernel builder exports small x86-64 functions directly, then checks
the **linked ELF bytes** before publishing the library. Scalar hot paths stay
in registers. Three borrowed-byte loops perform one complete-range admission
before processing sixty-four bytes per main-loop iteration, sixteen bytes per
cleanup iteration and one byte per tail iteration. The solver runs during the build; the native call contains no proof
engine, interpreter or entry wrapper.

## Build and independent checking

Use Linux x86-64, GNU ld and `z3-solver==4.15.4.0`:

```sh
python tools/build_hia_verified_kernel.py \
  --source examples/hia_verified_kernels/multiply_add.hepta \
  --output /tmp/hia-multiply-add-build
python tools/build_hia_verified_kernel.py \
  --source examples/hia_verified_kernels/sum_u8.hepta \
  --output /tmp/hia-sum-build
```

Each output directory must be new and its parent must exist. An attempt retains
the original source, checked Core, selection, exact object and text bytes, SMT
queries and final report. `program.so` appears only after completed validation.
A proof failure or timeout leaves the attempt rejected and publishes no final
library. Selection refusals occur before proof: `auto` can use the existing
checked Safe Core lowering when the source is outside the register profile.
`scalar`, `simd` and `checked` request a specific path.

`hepta.hia_verified_kernel.build_verified_kernel` provides the same API in
Python. Its optional `artifact_directory` retains the single selected object;
the scalar builder consumes that immutable object without reemitting it.
The default SIMD path uses `simd_unroll=4`; `simd_unroll=1` retains the original
sixteen-byte loop for independently checked comparisons. Both use SSE2 and
the same Core recurrence and borrowed-byte ABI.
Production language defaults are unchanged, so programs outside these narrow
profiles continue to use their existing checks and compiler entry points.

Independent consumers accept caller-supplied Core, object and final ELF bytes:

```python
from hepta.hia_safe_core import validate_safe_core_artifact
from hepta.hia_verified_simd_check import validate_verified_simd_artifact

scalar = validate_safe_core_artifact(core, object_bytes, final_bytes, profile_version=2)
simd = validate_verified_simd_artifact(core, object_bytes, final_bytes)
```

These consumer paths do not import the producers. They inspect the final code,
symbol ranges, relocations, dynamic symbol lookup, load mappings and protection
flags. The closed direct-entry ELF shape extends the existing two-function
wrapper shape; both retain immediate binding of the sole libc `abort` import.

The SIMD build records and rechecks the producer, native encoder and exact GNU
linker identities around emission and publication. Linker output is bounded,
and the candidate is read through a non-following, non-blocking descriptor that
accepts only a stable ordinary file of at most 8 MiB. An output overflow,
changed tool or producer, FIFO, symlink or oversized candidate is a build
failure. Publication-time failures withdraw only this build's own link.

## Scalar register ABI

One straight-line Core function may use `bool`, `u8`, `u16`, `u32`, `u64` and
`usize`, wrapping arithmetic, bitwise and Boolean operations, unsigned
comparisons, `select`, wrapping casts and constants. The emitter uses only
SysV caller-saved registers. Unsupported control flow, checked operations and
excess register pressure produce explicit selection refusals.

The example `a * b + c` on `u64` emits this eleven-byte hot path:

```asm
imul rdi, rsi
add  rdi, rdx
mov  rax, rdi
ret
```

The existing all-input Safe Core model checks return/abort behavior, memory
bounds, termination within its acyclic model, stack and saved-register
preservation. Dirty high argument bits at narrower unsigned widths are
normalized and included in the proof domain. An unreachable abort suffix
retains the closed loader contract and adds no hot-path work.

## Borrowed-byte ABI and one-time range admission

| Kernel | SysV C signature | Result |
| --- | --- | --- |
| `sum_u8` | `uint64_t f(const uint8_t *src, uint64_t extent, uint64_t count)` | Byte sum modulo 2^64 |
| `all_zero_u8` | same arguments | 1 if every requested byte is zero, otherwise 0; empty result is 1 |
| `copy_u8` | `uint64_t f(uint8_t *dst, uint64_t dst_extent, const uint8_t *src, uint64_t src_extent, uint64_t count)` | Requested count, after exact forward copy |

These are direct borrowed-u64 entry points. The existing packed-u32 foreign
wrapper is a different ABI. An empty call accepts null pointers and accesses
no caller bytes. Before any nonempty access, the emitted guards check count
against each extent, nonnull pointers, address addition without wrap and,
for copying, disjoint requested ranges. Invalid inputs abort before any byte
effect. Copy remains a nonoverlapping operation; it is not `memmove`.

Once admitted, the loop carries current pointers and a decreasing remaining
count in registers. A `remaining >= 64` test admits four unaligned sixteen-byte
chunks at offsets 0, 16, 32 and 48. A single pointer/count update and backedge
advance the complete group. A `remaining >= 16` cleanup loop handles the next
zero to three chunks, and the tail consumes individual bytes. None repeats the full
extent/null/overflow/overlap checks, and no load crosses the requested end.
The zero scan carries four independent accumulators in its main loop, one for
each chunk position, then combines them once before the cleanup loop. This
removes the serial dependency across all four OR operations in each group.
The Core specification itself performs complete extent admission before its
first byte operation, preserving early-trap memory effects.

The scalar API from `simd_kernel_program(kind)` specifies the complete
five-block recurrence. The first profile recognizes those blocks and their
local SSA names exactly; module and export names may differ. It does not
recognize arbitrary source loops merely because they resemble a reduction.

## What the independent SIMD model proves

The checker separately decodes every text byte and closes the control-flow
graph. It checks prefix guards against all 64-bit ABI argument words, then
proves initiation, 64-byte, 16-byte and one-byte step bounds, a strictly decreasing
remaining count, exact exit coverage, vector/tail data semantics and saved
state. Copy includes a disjointness obligation ensuring earlier destination
writes cannot change a later source byte. Sum includes preservation of the
zero vector across iterations, not just the value of one isolated chunk. Each
chunk in the 64-byte step has independent symbolic bytes; the proof must
preserve the accumulator and the zero register through all four chunks before
it can connect to the cleanup loop. The independently decoded signed
displacements must match all four guarded offsets, with no extra reads or stores.

The original loop profile retains its ten solver obligations. The 64-byte
sum/copy profile adds range/termination and complete four-chunk data obligations
for a total of twelve. The parallel zero scan adds a thirteenth obligation for
the four-accumulator merge and preserved register state. Its induction retains
four arbitrary partial accumulators across iterations; it never resets their
symbolic prior states to zero. Reports record three backedges,
`vector_unroll=4`, `superblock_width=64` and the reduction-accumulator count.
The consumer also accepts the original sixteen-byte and single-accumulator
sixty-four-byte objects and final images without invoking either producer.

The induction connects the decoded backedges with the scalar Core recurrence.
Its trust base is the stated Python Core/ISA/loop/ELF models, GNU/Linux loader
contract and pinned Z3 implementation. A caller supplies live initialized
ranges, exclusive destination ownership, a valid return address and the
declared disjoint nonwrapping stack. The model does not establish those
external lifetimes or a complete hardware ISA theorem. It does not cover
concurrency, asynchronous faults or side channels.

Instruction semantics follow the documented SSE2 operations: `PSADBW` sums
two groups of eight unsigned-byte absolute differences, `PADDQ` adds the two
64-bit lanes modulo 2^64, and `MOVDQU` permits unaligned sixteen-byte accesses.
Primary references: [Rust's PSADBW intrinsic documentation](https://doc.rust-lang.org/stable/core/arch/x86_64/fn._mm_sad_epu8.html)
and [Intel's architecture manual](https://cdrdv2-public.intel.com/843827/253665-sdm-vol-1-dec-24.pdf).

## Regression and performance protocol

`HIA verified kernels` runs the new tests together with the original Safe Core,
artifact, loader, conditional-move and unsigned-cast tests. Its strict runner
rejects skips and incomplete test inventories. Negative cases mutate arithmetic,
register state, range conditions, branches, addresses and ELF metadata.
The four-chunk controls also corrupt later chunks, duplicate or negate their
displacements, change the 64-byte guard/stride/backedge, and poison the
persistent zero register in the last chunk. Linker failure controls exercise
bounded output, file types, candidate sizes and identity changes.
Native subprocess controls exercise invalid-range aborts. Guard-page tests
place buffers at exact protected-page boundaries and cover vector/tail sizes.

The fixed benchmark is:

```sh
python tools/benchmark_hia_verified_kernels.py \
  --output /tmp/hia-kernel-benchmark --cpu 15 \
  --rustc rustc
```

The v2 protocol records 64 cases, including simultaneous sixteen-byte and
sixty-four-byte SSE2 arms with identical Core and ABI. It records 21 batches
after three warmups, all raw samples, checksums,
disassemblies, final libraries and their proof inputs. Every arm uses the
same indirect-call driver and CPU affinity. Workloads include scalar multiply
add and 256/4096/4097/65536-byte spans with sixteen unaligned offsets. C and
Rust use their native-target release optimizers; SSE2 remains the HIA baseline
ISA. The ordinary HIA span baseline retains its checked packed-u32 wrapper;
all measured counts and sums fit u32, so these valid-input results agree with
the new u64 API. Invalid-input ABI behavior is not equated.

These measurements describe the declared hot-cache kernels on a shared host.
Affinity does not make a core exclusive, and the raw samples remain available
for assessing interference. Build/proof time is reported separately from
native call latency.

## Recorded campaigns

The [initial AI395 campaign](../benchmarks/hia_verified_kernels/results/ai395-20261119-initial.json)
retains all 64 cases and 1,344 samples from source commit
`8aa5a7959955b9191709fd650761d65d4be6ef46`. Its single-accumulator sixty-four-byte
zero scan took 1,591.221 ns at 64 KiB, compared with 1,202.520 ns for the
sixteen-byte control. This negative observation motivated the four independent
accumulators above; it remains part of the record. The candidate with that
change requires its own complete campaign with all comparison arms.
