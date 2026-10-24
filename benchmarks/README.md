# Native validation and benchmark scope

Run from the project root:

```sh
python tools/validate.py --bench --output artifacts/native-validation.json
python -m unittest discover -s tests -p test_native.py -v
```

The validator uses `RUSTC`, a `rustc` on `PATH`, or the locally installed pinned
Rust 1.90.0 toolchain. GCC and GNU `nm` are needed for the Linux native tests;
`objcopy`, `file`, and `taskset` provide additional inspection and CPU affinity.

## What is measured

`kernels.hepta`, `baseline.rs`, and `baseline.c` independently implement the same
two functions: wrapping `u64` sum and non-overlapping copy. The Rust reference is
handwritten, not the compiler's generated Rust. Inputs include non-vector tail
lengths and values whose sum wraps modulo 2^64. The C driver checks correctness
before timing, consumes results, warms the functions, and calls separate object
files without LTO. All input/output allocation is outside the timed region.

Hepta and Rust use the same rustc, optimization level 3, enabled overflow checks,
one codegen unit, panic-abort, and default target CPU. C uses GCC `-O3`; it is a
supplementary comparison using a different optimizer. The primary language-cost
comparison is Hepta against independent Rust. Seven trials use randomized
implementation order at each size and pin child processes to one permitted CPU
when `taskset` is available. This does not eliminate shared-host noise, thermal
effects, or frequency changes. Medians and ranges are reported, not a universal
performance guarantee or a statistical superiority claim.

The function text sections of the two Hepta kernels are also compared with the
independent Rust sections. Equal bytes are stronger evidence of no additional
instructions for these particular functions than small timing differences.
The complete objects may differ; for example, the generated no_std crate can
contain a panic handler which is outside the measured function sections.

## What is separately validated

- `examples/ffi/abi.hepta` is compiled by the real CLI to a native static library.
  A C executable calls it, and those functions call real C definitions. Three
  aggregate shapes cross the ABI by value in both input and result positions.
- A supplementary test appends read-only `size_of`, `align_of`, and `offset_of`
  probes to the emitted Rust and compares them with the generated C header.
  Those probes are harness code, not a source-language escape hatch. The
  unmodified CLI-built library is also tested independently.
- `borrowed.hepta` runs safe read/mut slice kernels, stack arrays, checked
  indexing, and no-allocation resource clauses. An independent handwritten
  `borrowed.rs` supplies the matching native correctness reference. This path
  is not included in the raw-pointer timing figures.
- `--no-std` object generation is checked for host, AArch64 Linux, Cortex-M, and Windows x64 MSVC
  when the matching Rust core components are installed. Undefined symbols are
  inspected for allocator or scheduler dependencies. Cross-target success is
  object-compilation evidence only; no cross-platform ABI or device execution
  result is implied.

## Broader finite ABI matrix

```sh
python tools/abi_fuzz.py --seed 20261024 --cases 36 --output artifacts/abi-matrix.json
python -m unittest discover -s tests -p test_abi_matrix.py -v
```

This complementary matrix generates 36 ordinary `repr(C)` aggregates from a
fixed seed, with nested records and nonempty array fields, plus 12 scalar and
12 raw-pointer shapes. Independent C typedef composition checks nested pointer
qualifiers and pointer-to-array declarations without reusing the production
declarator renderer. Every scalar field is initialized and compared, while
padding bytes are deliberately ignored. Real C functions count invocations to
confirm C-to-Hepta-to-C execution; C harnesses run at `-O0` and `-O2`. A separate
probe checks size, alignment, and every field offset. Twenty mixed scalar
arguments also exercise host register exhaustion and stack argument passing.

The matrix uses a C11 validation harness for C99-compatible ordinary types.
It remains a finite host-only test set. It provides no evidence for bitfields,
packed records, varargs, foreign exceptions, or Windows ABI execution.

The raw C kernels require valid, initialized, sufficiently long buffers and a
writable, non-overlapping copy destination. Their callers retain those
obligations. These tests do not qualify packed layouts, C bitfields, varargs,
unwinding, retained callbacks, MMIO, DMA, interrupts, GPU kernels, or AI-agent
productivity.
