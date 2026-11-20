# Verified register and native SIMD kernels

The kernel builder exports small x86-64 functions directly, then checks
the **linked ELF bytes** before publishing the library. Scalar hot paths stay
in registers. Three borrowed-byte loops perform one complete-range admission
before processing 64, 128 or 256 bytes per main-loop iteration for SSE2, AVX2
or AVX-512, respectively. Cleanup covers the requested range exactly; the wide
copy profile uses bounded first/last transfers for its final short suffix.
Wide reductions use a sixteen-byte cleanup and nonoverlapping word tails.
The solver runs during the build; the native call contains no proof
engine, interpreter or entry wrapper.

## Build and independent checking

Use Linux x86-64, GNU ld and `z3-solver==4.15.4.0`:

```sh
hia build examples/hia_verified_kernels/sum_u8.hepta \
  --kind shared -o /tmp/hia-sum.so
hia build examples/hia_verified_kernels/sum_u8.hepta \
  --kind shared --target-isa sse2 -o /tmp/hia-sum-portable.so
```

The standard shared-library build defaults to `--backend auto`. Its scalar,
SIMD or checked Safe Core selection is fixed before proof; a failed proof,
timeout or unsupported source publishes no library. `--target-isa native`
selects the widest supported profile after fresh CPU/OS observations.
`sse2`, `avx2` and `avx512` request explicit targets. The ordinary object build
retains its existing ABI and external-tool requirements. Explicit
`--backend native --kind shared` retains the ordinary module ABI. The native
HIA CLI control and formatter own the same choices and cross-field errors as
the reference CLI, including the installed entry-point continuation.

For an attempt directory retaining all proof inputs and queries:

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
The Python API preserves `simd_isa="sse2"` and `simd_unroll=4` as its compatible
defaults. `simd_unroll=1` retains the original sixteen-byte loop. Explicit
`simd_isa="avx2"` and `"avx512"` use four chunks and independent accumulators;
`"native"` selects from fresh host observations. All profiles use the same
Core recurrence and borrowed-byte ABI. The standard verified shared command
and retained-attempt tool default to the host-native selection.

Wide copy defaults to `simd_copy_tail="endpoints-fast"`; explicit `"endpoints"`
and `"byte"` retain the two previous complete machine profiles. Wide sum and
zero scan default to `simd_reduce_tail="bounded"`; explicit `"byte"` retains
the previous wide-reduction objects. These Python selectors preserve the old
profiles for simultaneous controls. They do not change the SSE2 defaults.

Explicit `simd_reduce_tail="bounded-one"` adds a single-byte entry to wide
sum and zero scan. The default remains `"bounded"` while the complete extended
benchmark matrix is evaluated. The new selection is separate from the old
profiles and does not apply to SSE2 or copy.

Independent consumers accept caller-supplied Core, object and final ELF bytes:

```python
from hepta.hia_safe_core import validate_safe_core_artifact
from hepta.hia_verified_simd_check import validate_verified_simd_artifact

scalar = validate_safe_core_artifact(core, object_bytes, final_bytes, profile_version=2)
simd = validate_verified_simd_artifact(core, object_bytes, final_bytes)
```

Unsigned checked negation and variable shifts require the explicit scalar
`profile_version=3`; unsigned checked multiplication requires
`profile_version=4`; checked unsigned division/remainder require
`profile_version=5`; signed values and mixed-sign casts require
`profile_version=6`. Each old profile keeps its operation and decoder domain.

These consumer paths do not import the producers. They inspect the final code,
symbol ranges, relocations, dynamic symbol lookup, load mappings and protection
flags. The closed direct-entry ELF shape extends the existing two-function
wrapper shape; both retain immediate binding of the sole libc `abort` import.

The SIMD and register builds record and recheck the producer, native encoder
and exact GNU linker identities around emission and publication. Linker output is bounded,
and the final candidate for all three verified build paths is captured by the
same bounded reader through a non-following, non-blocking descriptor that
accepts only a stable ordinary file of at most 8 MiB. An output overflow,
changed tool or producer, FIFO, symlink or oversized candidate is a build
failure. Publication-time failures withdraw only this build's own link.
The ordinary checked compiler's earlier artifact capture has its separate
64 MiB limit; the 8 MiB bound here describes the final validation capture.

## Checked scalars and source names

The register producer's v2 profile includes unsigned checked add, checked
subtract and checked casts at u8/u16/u32/u64/usize widths, using the existing
independent Safe Core v2 semantics. Add guards check carry at 64 bits and
the complete untruncated result at narrower widths. Subtract guards inspect
borrow before normalization. Narrowing casts check the source value before
discarding high bits. Guard scratch registers follow the same liveness
allocator; exhausting the caller-saved register budget is a selection refusal.
The auto selector can then choose the ordinary checked lowering before proof.

Successful register paths still use no stack memory. A reachable failure path
aligns the stack and calls `abort`; the model accounts for both its alignment
slot and CALL's return-address write, for 16 bytes in the current checked
arithmetic kernels. Reports keep this maximum separate from
`hot_stack_bytes=0`. The wrapping u64 multiply-add retains its original
four-instruction, 11-byte hot path. Final-byte negative controls remove guards,
truncate before checking, invert carry, clobber a live scratch value and break
abort alignment; each is rejected with a counterexample before publication.

The register v3 profile adds unsigned checked negation and checked left/right
shifts at u8/u16/u32/u64/usize widths. Negation returns zero only for a normalized
zero input; every other unsigned value aborts. Shifts check the complete
normalized count against the Core type width before x86 applies `CL & 63`.
Left-shift result bits may wrap at the declared width; result-bit loss is not
an additional shift trap. Dirty high ABI bits are normalized first: raw count
256 becomes zero for u8, but is an invalid count for the larger widths.

CL is an implicit machine operand. The allocator moves a still-live RCX value
to a free caller-saved register before installing a different count, including
when that value is the shift's own left operand. It does not overwrite RCX
with the shift result while the count remains live. If no safe register is
available, selection refuses before proof and auto may use checked Safe Core
v3. Dead shift/negation results still perform their observable trap checks.

The independent v3 decoder admits only the reviewed 64-bit register D3 /4 and
/5 forms. Its model reads the original CL even when the destination is RCX,
preserves the destination and CF/ZF when the effective count is zero, and
models the final shifted-out bit and zero flag otherwise. The Core model
checks the full type-width count separately. Final-byte controls remove or
mask the count guard, change direction, add an incorrect result-overflow trap,
omit result narrowing, corrupt live RCX and remove the negation guard. These
produce SMT counterexamples. Fifteen ordinary backend wrappers and the direct
register entries are covered, including a prior borrowed write followed by a
shift abort. The v3 profile still excludes signed values and checked mul/div/rem.

The register v4 profile adds checked unsigned multiplication at all five
unsigned widths. Its independent Core model uses a full 128-bit product.
The machine producer uses unsigned `MUL`, checks the high-half carry before
any flag-clobbering instruction, then checks the complete low word against
the declared width before narrowing. Dirty upper ABI bits are normalized
before multiplication. A discarded checked result still retains its abort
behavior, including products whose low 64 bits are zero.

RAX and RDX are implicit outputs. Every still-live value in either register
is moved to a free caller-saved register first; dying operands can remain in
place because both operands are read before either output changes. This
includes constants, repeated SSA operands and all six live ABI arguments.
Exhausting the register budget refuses selection before proof, allowing auto
to choose the ordinary checked v4 wrapper. Successful register paths retain
zero hot stack use. A reachable overflow calls the existing aligned abort
stub with 16 bytes of modeled maximum stack use; a constant multiplication
that can never overflow has no reachable abort stack use.

The v4 instruction model follows the
[Intel SDM's unsigned MUL result and flag rules](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf)
(Volume 2B, order 253667-080US, pp. 4-146–4-147). The complete RDX:RAX product
and CF are modeled independently of the emitter; undefined ZF becomes a fresh
arbitrary Boolean. Old v1/v2/v3 decoders reject the new MUL form. The v4 decoder
also retains v3 variable shifts, and the source chooses the lowest applicable
profile. Existing wrapping multiply-add stays v2 with its original 11 bytes.

Adversarial final-byte tests remove, invert or clobber the carry guard, truncate
before the narrow range check, corrupt live RAX/RDX saves and break abort-stack
alignment; these are refuted by counterexamples. Signed and wrong-operand
MUL substitutions have separate constant-source counterexamples. Their full
64-bit symbolic variants can reach the unchanged solver deadline; these
attempts must reject as incomplete and publish no library, and are not counted
as counterexample results. GNU assembler encodings, ordinary wrappers, native
boundary execution and sealed-loader revalidation cover the additional form.
The v4 profile still excludes checked division/remainder and signed arithmetic. This
extension introduces no new measured Rust performance claim.

The register v5 profile adds checked unsigned division and remainder at the
same five widths. The producer checks the normalized divisor for zero, moves
the dividend into RAX, explicitly clears RDX and executes unsigned `DIV`.
Remainder uses the instruction's RDX output. It preserves live RAX/RDX values
and also moves a dying divisor away from either implicit register before
preparing the dividend. Constants, repeated operands and register pressure
follow the same checked selection/fallback rules as multiplication.

The independent model reads the actual 128-bit dividend and both preinstruction
operands. A machine divide error is excluded from admitted terminal outcomes;
the Core requires the existing aligned libc abort on a zero divisor. For a
nonzero divisor D and words H/L, the quotient of `H*2**64+L` fits in one word
exactly when `H < D`. When independently executed bytes establish H as the
constant zero, exact 64-bit division/remainder expressions avoid an unnecessary
128-bit SMT circuit. Every other state retains the full dividend. Missing or
poisoned RDX clearing therefore yields a fault or a different proved result.
The instruction's undefined CF and ZF are separate arbitrary Booleans, following
the [Intel SDM DIV specification](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
(Volume 2A, order 253666-060US, pp. 3-285–3-287).

Ten ordinary div/rem wrappers and the direct register entries pass the same
five obligations. Negative controls target missing/inverted zero guards,
the complete high dividend word, wrong divisors, wrong quotient/remainder
outputs, live implicit registers and abort alignment. Separate native tests
distinguish `SIGFPE` from the required `SIGABRT`; a machine fault never becomes
a successful checked trap. GNU assembler encoding checks and all-integer
division identities supplement the independent model. The unsigned integer
operation names in the current primitive Core now have scalar semantics in
v5. The separately versioned v6 model adds signed integer types, while general
calls/loops and wider language families retain separate validation obligations.
New arithmetic has no inherited Rust timing result.

The signed v6 producer emits direct register code for `i8/i16/i32/i64/isize`,
including checked and wrapping arithmetic, signed comparisons, arithmetic
right shifts, and conversions between signed and unsigned types. The
independent consumer checks actual sign extension, SF/OF, CQO and IDIV from
the final linked image. Zero divisors, `MIN/-1`, arithmetic overflow and
invalid shift counts preserve Core abort behavior. All v6 proofs retain the
existing 15-second default deadline. Its complete, separately measured Rust
matrix is specified in `benchmarks/hia_verified_kernels/SIGNED_PROTOCOL.md`.

Both consumers also bind the executing primitive input closure before
decoding, record selected native helpers' actual RX mappings and source
bindings, and recheck those identities after final report hashing. This
rejects timestamp-valid stale decoder or hasher bytecode that could otherwise
change the proved program or its reported hash. The helper receipt describes
operator-selected trusted code; it explicitly does not claim independent
semantic refinement of those input helpers.

The three recognized Core recurrences also accept legal SSA and block
renaming, and block declaration reordering. Recognition first validates the
original typed Core, constructs bijections by CFG role and declaration
position, validates the renamed view, then requires exact inverse roundtrip
equality. It changes only identifier fields. The strict recurrence comparison
still checks operations, operand order, types, constants, attributes, effects
and traps. The `core_recognition` receipt records the original Core hash,
normal-form hash and complete mapping separately; the artifact subject stays
bound to the original Core. Renaming does not change machine bytes or any
machine proof obligation.

## Loaded checker and producer source identities

Proof-source hashes now bind the modules that actually executed. Previously,
a process could import a checker, replace its source file, then successfully
validate with the old in-memory function while reporting the replacement
file's hash. A retained local counterexample inserted an unconditional raise
in the on-disk checker; the already imported checker still returned a complete
successful proof attributed to those new bytes.

`hia_loaded_source` closes that attribution gap for registered package
modules. Ordinary module initialization passively captures the executing
code object and a stable source snapshot using only the standard library.
A proof's first identity request compares that code with an independent
compilation of the snapshot, including nested code, constants, instruction
bytes, flags and exception tables. The
comparison uses the interpreter's actual optimization level and disables
inheritance of the caller's compiler flags. Later identity requests bind the
same module object and re-read its source through a bounded ordinary-file
descriptor. Source drift, a replacement `sys.modules` object, missing source
or a reload rejects validation, publication or loading. Reload attempts taint
the old registration; installing changed verification code requires a fresh
process. Every producer/consumer identity map also identifies this binding
implementation. The native kernel hot path is unchanged.

The regressions preserve timestamps and source sizes while changing both
top-level constants and nested function bodies in valid timestamp caches.
They also exercise actual scalar/SIMD proof calls, replaced decoder modules,
and refusal before linker, CPU-probe or memfd effects. This package-loading
contract trusts the running interpreter and bootstrap; it does not promise
resistance to arbitrary in-process monkeypatches or authenticate an older
process that predates the binding mechanism.

Python's [module-cache contract](https://docs.python.org/3.12/reference/import.html#the-module-cache)
explains why existing aliases can retain an older module.
Its [bytecode-cache rules](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation)
and [timestamp mode](https://docs.python.org/3.12/library/py_compile.html#py_compile.PycInvalidationMode.TIMESTAMP)
compare modification time and size, so those metadata alone cannot establish
executed-source equality. The independent compilation follows the documented
[`compile` flags and optimization semantics](https://docs.python.org/3.12/library/functions.html#compile).

The scalar and SIMD solver identities additionally bind a controlled first
import of the complete Z3 Python package and the actual mapped native library.
Pre-load descriptors, executed code comparison and repeated mapping/file checks
reject source or library replacements even before the first proof. A process
that imported Z3 before admission must start a new process. See
[Loaded solver identity](HIA_LOADED_SOLVER_IDENTITY.md) for the receipt profile,
loading contract, negative controls and explicit Python/OS trust boundary.

## CPU admission and immutable loading

The independent decoder reports the features used by the actual final
instructions. A 256-bit copy needs AVX; its integer reductions also need AVX2.
The 512-bit copy needs AVX-512F; its sum additionally uses AVX-512BW, and the
wide reductions' horizontal stage uses AVX2. Features absent from an image are
not imposed merely because its target profile is named AVX2 or AVX-512.

`hia_verified_cpu` uses a fixed baseline-instruction CPUID/XGETBV probe in an
isolated subprocess. It checks hardware XSAVE/OSXSAVE/AVX, the enabled XCR0
state, and the precise extension bits on every CPU in the caller's allowed
affinity. XGETBV is reached only when OSXSAVE permits it. A probe fault,
missing feature, incomplete CPU inventory or changed affinity rejects the
build. The parent thread's affinity is never modified. The probe uses a
write-then-execute mapping; no writable/executable mapping is requested.

The public loader accepts original inputs and rechecks both the final image
and current CPU state:

```python
from hepta.hia_verified_kernel_load import load_verified_simd_kernel

kernel = load_verified_simd_kernel(core, object_bytes, final_bytes)
native_function = kernel.function
```

`load_verified_scalar_kernel(core, object_bytes, final_bytes)` supplies the
same immutable-mapping admission for Safe Core v2/v3/v4/v5/v6 scalar direct
entries. It reruns the independent scalar consumer, rejects borrowed arguments
and wrappers, and exposes zero to six raw uint64 SysV argument words with a
canonical uint64 return. The proved machine body performs narrow-width input
normalization; signed values are sign-extended and negative results use raw
64-bit two's-complement words. Scalar and SIMD cache identities remain distinct, and every
load constructs a fresh callable with the admitted argument types.

It copies the exact validated bytes into a Linux sealed memfd, verifies the
sealed byte readback, and rejects a pre-existing dynamic-loader pathname
cache before immediate binding. It then uses the GNU loader's link-map
information and `/proc/self/maps` to bind the actual RX mapping to the sealed
device/inode, entry file offset and every machine text byte. Only that verified
address becomes a callable. It does not resolve a target symbol before
binding the image, so a stale GNU IFUNC cannot execute during lookup.

Mappings remain in a bounded process-lifetime registry (64 images and 64 MiB).
Every load repeats validation and CPU admission and returns its own function
ABI object; mutable old reports or ctypes attributes do not authorize another
load. The scalar profile version is chosen anew from verified Core and is part
of the cache identity; a previous receipt cannot grant a later version admission. The native
call itself has no solver, CPUID or dispatch wrapper. Callers
retain live borrowed ranges and an ISA-compatible execution environment,
including after any later thread migration or affinity change.

## Scalar register ABI

One straight-line Core function may use `bool`, all primitive signed and
unsigned integer types, wrapping arithmetic, bitwise and Boolean operations,
comparisons, `select`, casts and constants. The emitter uses only SysV
caller-saved registers. The v2 through v6 additions above admit their explicit
checked operations. Unsupported control flow and excess register pressure
produce explicit selection refusals.

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
five-block recurrence. The recognizer accepts reversible SSA and block
renaming while preserving the original Core subject. Operations, effects,
edge arguments and the complete recurrence still have to match the reviewed
profile; module and export names may differ.

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

The wide profiles separately decode VEX and EVEX prefix fields, reserved bits,
unmasked full-vector memory forms and signed displacements. In particular,
EVEX disp8 is multiplied by the 64-byte tuple width; disp32 is not scaled.
Sum uses folded-memory VPSADBW plus VPADDQ, zero scan uses folded-memory
VPOR/VPORQ, and copy uses unaligned VMOVDQU/VMOVDQU64. Four arbitrary prior
accumulators are retained in the induction and merged before cleanup.
Narrow VEX writes zero their upper destination bits in the independent model.
The wide sum and zero scan each have fourteen obligations, including explicit
accumulator initialization. The original wide copy has twelve and remains
available as `simd_copy_tail="byte"` in the Python builder for complete
simultaneous controls. Those v1 paths retain their exact object/text bytes.

The wide copy's v2 endpoint profile has a bulk block that
loads four vectors before storing them, and its guarded single-vector cleanup
leaves fewer than 32/64 bytes. A descending width dispatch selects 16/32,
8, 4, 2 or 1 bytes. For `w <= remaining < 2*w`, the first and last `w`-byte
blocks cover exactly the suffix. Both loads precede the two stores; repeated
bytes receive the same source byte under the full-range disjointness contract.
The independent model uses one symbolic source byte array, actual decoded
offsets and an arbitrary destination-byte index to prove every byte inside and
outside the suffix. It also proves the dispatch partition and nonwrapping
bounds. AVX2 requires 21 total obligations and AVX-512 requires 23.
Changing the last store to reuse first-block data produces an SMT
counterexample in the overlapping case. A one-byte suffix has one load/store.
Every nonempty endpoint return passes through VZEROUPPER. The default v3
`copy-endpoints-fast` profile additionally sends `remaining == 1` directly
to its exact one-byte transfer. The closed branch shape and the endpoint
partition preserve the same 21/23 obligations. Both older copy profiles
retain their original complete object and text bytes.

The new `reduce-bounded` profiles use a short-input branch before wide
accumulator initialization. Short inputs initialize only the two required
128-bit registers. Long inputs use the existing wide bulk/vector loops and
fold the complete wide accumulator into 128 bits. Both paths join at the
same sixteen-byte cleanup loop and horizontal reduction. The final suffix
uses at most one exact load of each size 8, 4, 2 and 1, advancing after every
accepted word. Sum uses PSADBW against a preserved zero vector; zero scan
combines the loaded words. No endpoint-overlap trick is used for summation.

Each bounded reduction has 22 independent obligations. These include the
actual short-entry partition, both accumulator initializations, wide-to-narrow
and horizontal composition, the persistent zero register, and the complete
GPR/vector frame. A symbolic suffix length and arbitrary byte index prove
the word partition covers every requested byte exactly once and reads no
outside byte. Each word's data operation is checked separately against its
decoded operands. Negative controls preserve a stage's immediate result while
polluting the zero register needed by the next stage; they produce concrete
SMT counterexamples. All fourteen historical SSE2, wide-byte and endpoint
objects retain their exact byte hashes.

The explicit `reduce-bounded-one` profiles retain those 22 obligations and
add three, for 25 per image: the decoded single-byte entry partition, its
access bounds, and its result plus register frame. Only after the original
extent, nonnull and nonwrapping-address checks does `count == 1` branch to
one exact byte load and the common return. Zero scan retains the common
Boolean result normalization. This path needs no vector initialization or
horizontal reduction. Every other nonempty length follows the existing bounded
reduction after the extra entry test; its performance must therefore be
assessed across the whole matrix. The independent checker decodes the actual
load address and destination, and changed destinations produce functional
and register-frame counterexamples. The original `"bounded"` default and
all previous wide object/text bytes remain unchanged.

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

The v4 protocol records 533 cases, including simultaneous sixteen-byte and
sixty-four-byte SSE2, 128-byte AVX2 and 256-byte AVX-512 arms with identical
Core and ABI. It retains the complete 487-case v3 matrix and adds 46
simultaneous original wide-copy byte-tail controls, covering both ISAs at all
23 lengths. It records 21 batches
after three warmups, all raw samples, checksums,
disassemblies, final libraries and their proof inputs. Every arm uses the
same indirect-call driver and CPU affinity. Workloads include scalar multiply
add and 23 span lengths from zero to 65536, covering both sides of the 16-,
32-, 64-, 128-, 256- and page boundaries, with sixteen unaligned offsets. C and
Rust use their native-target release optimizers; SSE2 remains the HIA baseline
ISA. The ordinary HIA span baseline retains its checked packed-u32 wrapper;
all measured counts and sums fit u32, so these valid-input results agree with
the new u64 API. Invalid-input ABI behavior is not equated.

The v5 protocol preserves every v4 arm and its exact machine profile,
including both copy byte-tail controls. Six additional profiles cover the
default bounded sum/zero tails and fast one-byte endpoint-copy dispatch at
both wide ISAs. Their 138 additional cases produce 671 total cases and
14,091 measured samples. The v4 `verified-avx2-128`/`verified-avx512-256`
labels remain fixed to their old reduction byte tails and old copy endpoints;
the new defaults have explicit `bounded-tail` and `copy-endpoints-fast` arm
names. The driver, reference code, lengths, iteration counts and compiler
flags are unchanged.

The current v6 protocol preserves all 671 v5 case bindings and adds 92 cases:
wide sum and zero scan with `bounded-one`, at both ISAs and all 23 lengths.
It contains 763 cases and 16,023 measured samples. The two new arms are named
`verified-avx2-bounded-one` and `verified-avx512-bounded-one`; all fourteen
previous wide objects are constructed with explicit original tail selections,
including `"bounded"` and `"endpoints-fast"`. The full wide inventory is
18 builds with 356 solver obligations. Driver, reference sources, lengths,
iteration counts and compiler flags stay fixed. This protocol extension
adds no completed-campaign or performance conclusion by itself.

These measurements describe the declared hot-cache kernels on a shared host.
Affinity does not make a core exclusive, and the raw samples remain available
for assessing interference. Build/proof time is reported separately from
native call latency.

The current protocol also binds the actual glibc binary, its version and
the resolved memcpy IFUNC offset with a baseline-ISA helper under the same
affinity and environment. This dependency observation applies to new runs;
the historical campaigns below retain their original identity inventories.

The broader language and product work is tracked in
[HIA_RUST_COMPARISON.md](HIA_RUST_COMPARISON.md), with independent closure
criteria for each feature family and each performance workload.

## Recorded campaigns

The [initial AI395 campaign](../benchmarks/hia_verified_kernels/results/ai395-20261119-initial.json)
retains all 64 cases and 1,344 samples from source commit
`8aa5a7959955b9191709fd650761d65d4be6ef46`. Its single-accumulator sixty-four-byte
zero scan took 1,591.221 ns at 64 KiB, compared with 1,202.520 ns for the
sixteen-byte control. This negative observation motivated the four independent
accumulators above; it remains part of the record.

The [complete second campaign](../benchmarks/hia_verified_kernels/results/ai395-20261119-parallel-zero.json)
binds the changed implementation to
`b5de6a98467e8c51198a3335d97c0bc5536af8d5`. Both campaigns use the same AMD
Ryzen AI MAX+ 395 host, CPU 15, GCC 15.2, Rust 1.99.1 and pinned Z3 4.15.4.
Compiler executable hashes and the protocol are unchanged. Each campaign
retains all 64 cases, 21 samples per case, source/binary hashes and independently
checked checksums. Host sharing and the hot-cache protocol remain explicit.

Second-campaign median native-call latency, in nanoseconds:

| Workload | Original HIA direct | Verified SSE2 16 B | Current verified kernel | Rust native |
| --- | ---: | ---: | ---: | ---: |
| Scalar multiply-add | 2.042 | n/a | 0.998 | 0.999 |
| Byte sum, 4 KiB | 11990.799 | 84.550 | 69.331 | 67.712 |
| All-zero scan, 4 KiB | 11993.636 | 73.733 | 31.755 | 12.728 |
| Copy, 4 KiB | 13667.865 | 67.297 | 39.043 | 18.007 |
| All-zero scan, 64 KiB | 192192.476 | 1189.961 | 602.570 | 288.950 |

The current scalar entry is the register kernel; the span entries use the
64-byte main loop. In the second campaign the zero scan improves over the
simultaneous sixteen-byte control at all four measured lengths, including
1.975x at 64 KiB. The 4 KiB sum is within 2.4% of the Rust reference, while
zero scan and copy take 2.495x and 2.168x its time. The 64 KiB sum is effectively
flat against the sixteen-byte control: 1624.601 versus 1620.231 ns. These are
specific measurements, not a whole-language or universal speed claim.

The changed implementation passes the complete strict **139-test** kernel
inventory locally and in [hosted CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/44655567208),
including the frozen old object, all negative controls, and exact-end guard
pages. Its full-tree source-contract check covers 919 source identities.

### Complete wide-ISA campaign

The [third campaign summary](../benchmarks/hia_verified_kernels/results/ai395-20261119-wide-summary.json)
binds **487 cases and 10,227 samples** to source
`93bccb96c0ccb30f5e1fbe876a56e05953e5c83f`, tree
`41a31011db48f9971c68594dc583098f25361db4`. All cases completed in one
106.28-second campaign, with no selected-cell reruns or discarded samples.
The [complete public record](../benchmarks/hia_verified_kernels/results/ai395-20261119-wide.json.gz)
is gzip-compressed JSON and includes every sample, all six wide proofs and
fresh CPU observations, source/binary identities, and the actual libc
dependency. Its decompressed SHA256 is
`b7bf4c02b828da64c51ce2fcc5852c889301e3611f8e1757c62202da605332f9`;
the original remote RESULT SHA256 is
`06df05fee18efa5b16b728e028ca43facc02fd08068032ed05a437dd6a51d095`.

Independent readback checked the exact case inventory, all sample checksums
and timing divisions, every median, 519 command receipts, 21 binaries, 80
wide SMT query hashes and the before/after libc identity. This run used the
same AI395 host and CPU 15, GCC 15.2, Rust 1.99.1 and Z3 4.15.4. The observed
glibc 2.43 binary has SHA256
`9941dc28e68bc5fd788d9cd024c69e68c791d63799e7538a97b6040dd9f50fb6`;
its resolved memcpy offset is `0x1b0a40`.

Third-campaign median latency, in nanoseconds per call:

| Workload | Verified AVX2 | Verified AVX-512 | Rust native |
| --- | ---: | ---: | ---: |
| Byte sum, 4 KiB | 19.337 | 12.825 | 68.120 |
| All-zero scan, 4 KiB | 19.243 | 12.511 | 12.576 |
| Copy, 4 KiB | 33.200 | 29.953 | 17.555 |
| Byte sum, 64 KiB | 317.540 | 298.120 | 1137.411 |
| All-zero scan, 64 KiB | 319.360 | 336.430 | 287.560 |
| Copy, 64 KiB | 638.570 | 593.241 | 759.571 |
| Copy, 127 bytes | 9.052 | 14.980 | 1.818 |

Register multiply-add was 0.996479 ns versus Rust's 0.996097 ns. This tiny
difference is unresolved timing noise, not a demonstrated advantage. Wide
sum is faster on the listed large inputs, but AVX-512 has a lower median in
only 24 of the 69 span workload/length pairs and a higher one in 45. AVX2
has 22 lower and 47 higher medians. The [complete 69-row comparison](../benchmarks/hia_verified_kernels/results/ai395-20261119-wide-comparison.json)
retains the short-tail regressions. Even the descriptive minimum of both
wide arms has 41 higher medians; that minimum is not an implemented dispatch
policy. Short tails, 4 KiB copy and 64 KiB zero scan remain concrete work.

### CLI and cold-source qualification for the wide implementation

The [qualification receipt](../benchmarks/hia_verified_kernels/results/cli-current-qualification-633feee.json)
and its [exact source manifest](../benchmarks/hia_verified_kernels/results/cli-current-source-manifest-633feee.json)
bind the complete 923-file source closure plus its generated contract.
The matching-source cold replay passed 11/11 checks in 172.748 seconds under
the original deadline, including its B0/B1/B2/B3 and modified-source checks.
The native CLI gate passed 22 tests with no skips, and the actual installed
wheel passed isolated `-I -S`, empty-PATH, no-retained-parser controls. These
receipts distinguish CLI argument transport from actual shared-kernel execution.

Hosted strict gates on `633feee656f000e2a9b683b366e391b5eefe3ce1` passed
201 tests in both [PR CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/44661846561)
and [push CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/44661839320),
with no skips. This commit changes only the workflow's Python pin from the
measured `93bccb9` source. The earlier 168 failures on floating Python
3.12.16 are retained; the gate now uses already-supported Python 3.12.14.
These results qualify their recorded source identities. Later language or
checker extensions require their own applicable gates.

The broader `633feee` native workflow subsequently reached a separate
[retained failure](../benchmarks/hia_verified_kernels/results/native-633feee-failure-summary.json):
its original Core caller group ran all 50 tests and failed only the route
inventory assertion that still required every build to be "fixed native".
The original failure report and full group log are retained beside that
summary. The current test keeps its original ID and group membership, and
asserts the actual object/native and shared/verified routes, including proof
before publication and refusal after proof failure. It is also in the fast
kernel gate. Fixing that assertion does not retroactively make the old native
workflow successful; the changed source requires a complete rerun.

### Complete endpoint-copy campaign

The [fourth campaign summary](../benchmarks/hia_verified_kernels/results/ai395-20261120-endpoints-summary.json)
and [complete compressed record](../benchmarks/hia_verified_kernels/results/ai395-20261120-endpoints.json.gz)
bind **533 cases and 11,193 samples** to source
`60409eacc6cda870d2be1d090f2c66b682c9466b`, tree
`7bf431d26fe55e56082af92dd634aa515fa75ef7`. The original RESULT SHA256 is
`7c7a3c20508f5823fdecf0c9fe9240e1ba8093de7420fea4f7a66d6bc9be0885`;
the decompressed public record SHA256 is
`fe6660ae4b288294f5aaffd4df84041617019431f0a90a530dfcfed409860e99`.
The same CPU 15, tool binaries, runtime, driver and input protocol were used.
One complete campaign retained all samples without selected-cell reruns.

Remote readback checked 567 command-output receipts, 23 binaries, eight wide
builds and 124 SMT query hashes against their original files. A separate
local readback reconstructed all 533 cases and their deterministic order,
recomputed 11,193 timing divisions and checksums, all medians and Rust ratios,
matched the gzip content exactly, and checked 26 source hashes against the
frozen `60409ea` tree. Its scalar checksum used the direct ten-million-step
recurrence, independently of the remote projection's matrix implementation.

Fourth-campaign median latency, in nanoseconds per call:

| Workload | Verified AVX2 | Verified AVX-512 | Rust native |
| --- | ---: | ---: | ---: |
| Byte sum, 4 KiB | 19.329 | 12.972 | 67.451 |
| All-zero scan, 4 KiB | 19.565 | 12.685 | 12.660 |
| Copy, 4 KiB | 28.610 | 21.995 | 18.741 |
| Byte sum, 64 KiB | 317.170 | 296.790 | 1135.661 |
| All-zero scan, 64 KiB | 319.581 | 325.410 | 287.820 |
| Copy, 64 KiB | 561.740 | 577.811 | 766.400 |

The simultaneous old/new AVX-512 copy control is 14.871/1.420 ns at
63 bytes and 14.890/1.688 ns at 127 bytes. AVX2's 31-byte control is
8.448/1.461 ns. These endpoint improvements do not erase the slower one-byte
suffixes: at length 1, AVX-512 is 1.877 ns versus its old byte-tail control's
1.613 ns. At 65, 129 and 257 bytes, the one-byte suffix also regresses.

AVX-512 has 32 lower and 37 higher medians across the complete 69 span
workload/length pairs; AVX2 has 29 lower and 40 higher. The descriptive
minimum of both has 35 lower and 34 higher; this is not an implemented
dispatcher. Register multiply-add is 0.995402 ns versus Rust's 0.999111 ns,
an unresolved small difference. Short reduction tails still dominate some
losses: the AVX-512 32-byte sum is 7.574 ns versus Rust's 1.477 ns. The next
candidate must be measured separately before any of these results change.

The frozen `60409ea` implementation passes the full strict 272-test inventory
locally and in both [PR CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/44665015777)
and [push CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/44665008906),
with no skips. New source changes require a new contract and applicable gates.

### Complete bounded-tail campaign

The [fifth campaign summary](../benchmarks/hia_verified_kernels/results/ai395-20261120-bounded-summary.json)
and [complete record](../benchmarks/hia_verified_kernels/results/ai395-20261120-bounded.json.gz)
bind **671 cases and 14,091 samples** to source
`e9de97cee2a44cfbe044b245f2cf344c2cc3ef47`, tree
`0cc7dafab1cf665d9df410cc14136e3f7374d6d3`. The complete run took 112.454
seconds, with no selected-cell reruns. Its original RESULT SHA256 is
`445bb5040ee83ba09f531f4fcf1bea065b9b5cd95f471b9fa0789a4be9adfc29`;
the decompressed public SHA256 is
`968dbe823b86968c21fbec3e218a55b8597a1fd6f0759b7dd77ac357f2623e30`.
The independent readback checked all samples, 711 command receipts,
29 binaries, fourteen wide builds and 256 SMT query identities. All previous
533 library/symbol bindings and eight old wide object/text/final-image hashes
match their fourth-campaign controls. A separate local readback recomputed
the complete case order, checksums, timings, medians and Rust ratios.

New-default median latency, in nanoseconds per call:

| Workload | Verified AVX2 | Verified AVX-512 | Rust native |
| --- | ---: | ---: | ---: |
| Byte sum, 4 KiB | 18.913 | 12.930 | 67.402 |
| All-zero scan, 4 KiB | 19.121 | 13.095 | 12.669 |
| Copy, 4 KiB | 35.775 | 20.516 | 17.585 |
| Byte sum, 64 KiB | 314.380 | 290.150 | 1139.131 |
| All-zero scan, 64 KiB | 318.800 | 321.060 | 285.600 |
| Copy, 64 KiB | 545.920 | 578.600 | 768.850 |

AVX-512's new defaults have 42 lower and 27 higher medians across the 69
span pairs; AVX2 has 40 lower and 29 higher. The descriptive minimum of both
has 44 lower and 25 higher, without implying an implemented per-length
dispatcher. The one-byte copy median improves from the simultaneous original
endpoint control's 1.879 ns to 1.418 ns for AVX-512. Its 32-byte sum improves
from the old byte-tail control's 7.422 ns to 2.004 ns. Remaining empty and
one-byte paths, exact-vector boundaries, 4 KiB copy and 64 KiB zero scan remain
visible. AVX2 4 KiB copy regresses from the old endpoint control's 28.597 ns
to 35.775 ns; every sample is retained. Scalar multiply-add is 0.998354 ns
versus Rust's 0.996595 ns, an unresolved small difference.

**Allocation limitation in campaigns one through five:** the driver allocates
buffers after loading each DSO, then varies offsets 1–16 relative to those
allocations. It does not record or equalize the absolute cache-line/page
phases or source/destination distance. The fifth-campaign AVX2 copy regression
has separated sample ranges even though the long-copy bulk bytes did not
change. Different allocator/loader layouts are a plausible confound; the old
evidence cannot establish that cause. The observed timings remain intact,
but do not isolate the effect of the code change. A later protocol must bind
controlled address phases, distance and both copy address orders explicitly.

The frozen `e9de97c` source also passes all 298 strict tests in both
[PR CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/44667378159)
(84.516 seconds) and [push CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/44667371850)
(83.131 seconds), with no skips. These results do not qualify later source
changes or the new scalar v3/v4/v5 extensions.

### Complete matching-source caller qualification

The [60409 qualification receipt](../benchmarks/hia_verified_kernels/results/qualification-60409-20261120.json),
[exact source manifest](../benchmarks/hia_verified_kernels/results/source-manifest-60409-20261120.json)
and [original evidence archive](../benchmarks/hia_verified_kernels/results/qualification-evidence-60409-20261120.zip)
retain the new cold 11/11, native CLI 22, installed-wheel controls and the
complete original selected-caller inventory: component 11, original-machine
51 and original-Core 50, all passing with zero skips. The three caller groups
took 49.624, 33.630 and 41.597 seconds, respectively. Their full ID lists,
report/log hashes and source-stability checks are in the receipt. The route
test that failed on `633feee` passes inside the unchanged original 50-test group.

Two preceding local attempts exposed missing checkout files outside the cold
source closure. Both failures and their original reports/logs are retained.
The successful attempt followed complete tests/examples and recursive tool
dependency staging from exact `60409ea` Git blobs; no gate or product code was
changed to obtain the pass. The cold-source manifest stayed byte-identical.
These receipts bind `60409ea`, not a later source revision.
